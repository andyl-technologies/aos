//! K3s runtime-configuration materialization through the selected provider protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, AccessMode, LocalKey, MethodSemantics, ResourceReference,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest, AdmissionResult, AdmissionRevision,
    Invocation, InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA,
    SupportedPurposes,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    KubernetesProviderError, ability_value, atomic_write, bound_target_context, decode, invalid,
    read_bounded, require_resource,
};

const OBSERVATION_SCHEMA: &str = "aos.ability.k3s-configuration-observation/v1";
const CONTEXT_SCHEMA: &str = "aos.k3s.configuration-context/v1";
const REALIZATION_SCHEMA: &str = "aos.k3s.configuration-realization/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct K3sConfiguration {
    base: K3sConfigurationBase,
    contributions: BTreeMap<String, K3sIntegration>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct K3sConfigurationBase {
    flannel_backend: String,
    disable_network_policy: bool,
    disable_kube_proxy: bool,
    node_labels: BTreeMap<String, String>,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct K3sIntegration {
    disable_flannel: bool,
    disable_network_policy: bool,
    disable_kube_proxy: bool,
    node_labels: BTreeMap<String, String>,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct K3sConfigurationRealization {
    schema: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct K3sConfigurationContext {
    schema: String,
    path: String,
}

#[derive(Clone, Debug, Serialize)]
struct K3sConfigurationObservation<'a> {
    schema: &'static str,
    expected: &'a K3sConfiguration,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_digest: Option<Sha256Digest>,
}

pub(super) fn admit(request: AdmissionRequest) -> Result<AdmissionResult, KubernetesProviderError> {
    validate_configuration_method(request.method.method.as_str(), &request.semantics)?;
    let desired: K3sConfiguration = decode(&request.resource_spec.value)?;
    let realization: K3sConfigurationRealization = decode(&request.resource_spec.realization)?;
    validate_configuration(&desired)?;
    validate_configuration_prerequisites(&request.resources, &desired)?;
    validate_configuration_realization(&realization)?;
    let content = render_configuration(&desired)?;
    let current = configuration_matches(
        Path::new(&realization.path),
        &content,
        &request.resource_spec.revision.0.to_string(),
    )?;
    let observation = configuration_observation(&desired, &realization.path, &content, current);

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision: if current {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: None,
        observation: ability_value(serde_json::to_value(observation)?)?,
        native_context: ability_value(serde_json::to_value(K3sConfigurationContext {
            schema: CONTEXT_SCHEMA.into(),
            path: realization.path,
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .ok_or_else(|| invalid("K3s configuration purpose support is not canonical"))?,
    })
}

pub(super) fn invoke(invocation: Invocation) -> Result<InvocationResult, KubernetesProviderError> {
    validate_configuration_method(invocation.method.method.as_str(), &invocation.semantics)?;
    let context = bound_target_context(&invocation)?;
    let desired: K3sConfiguration = decode(&context.resource_spec.value)?;
    let realization: K3sConfigurationRealization = decode(&context.resource_spec.realization)?;
    let provider_context: K3sConfigurationContext = decode(&context.provider_context)?;
    validate_configuration(&desired)?;
    validate_configuration_prerequisites(&invocation.request.resources, &desired)?;
    validate_selected_inputs(&invocation.request.inputs, &desired)?;
    validate_configuration_realization(&realization)?;
    if provider_context.schema != CONTEXT_SCHEMA || provider_context.path != realization.path {
        return Err(invalid(
            "K3s configuration context differs from its checked realization",
        ));
    }
    let content = render_configuration(&desired)?;
    let revision = context.resource_spec.revision.0.to_string();

    if invocation.control.cancelled {
        return configuration_result(
            &invocation,
            &desired,
            &realization.path,
            &content,
            false,
            InvocationDisposition::RejectedBeforeEffect,
            false,
        );
    }
    match invocation.purpose {
        InvocationPurpose::Effect if invocation.method.method.as_str() == "apply" => {
            materialize_configuration(Path::new(&realization.path), &content, &revision)?;
            configuration_result(
                &invocation,
                &desired,
                &realization.path,
                &content,
                true,
                InvocationDisposition::Completed,
                true,
            )
        }
        InvocationPurpose::Effect if invocation.method.method.as_str() == "release" => {
            release_configuration(Path::new(&realization.path), &revision)?;
            configuration_result(
                &invocation,
                &desired,
                &realization.path,
                &content,
                false,
                InvocationDisposition::Completed,
                false,
            )
        }
        InvocationPurpose::Effect => {
            let current = configuration_matches(Path::new(&realization.path), &content, &revision)?;
            configuration_result(
                &invocation,
                &desired,
                &realization.path,
                &content,
                current,
                InvocationDisposition::Completed,
                false,
            )
        }
        InvocationPurpose::Reconcile => {
            let current = configuration_matches(Path::new(&realization.path), &content, &revision)?;
            let released = invocation.request.method.method.as_str() == "release" && !current;
            configuration_result(
                &invocation,
                &desired,
                &realization.path,
                &content,
                current,
                if current || released {
                    InvocationDisposition::Completed
                } else {
                    InvocationDisposition::SafeToRetry
                },
                current && invocation.request.method.method.as_str() == "apply",
            )
        }
        InvocationPurpose::Cancel => configuration_result(
            &invocation,
            &desired,
            &realization.path,
            &content,
            false,
            InvocationDisposition::RejectedBeforeEffect,
            false,
        ),
        InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => Err(invalid(
            "K3s configuration provider has no compensation operation",
        )),
    }
}

fn validate_configuration_method(
    method: &str,
    semantics: &MethodSemantics,
) -> Result<(), KubernetesProviderError> {
    let method_allowed = matches!(method, "apply" | "observe" | "release");
    if !method_allowed {
        return Err(invalid("method does not belong to K3s configuration"));
    }
    let expected = match method {
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "release" => MethodSemantics {
            required_target_access: AccessMode::ExclusiveWrite,
            stops_provider: true,
        },
        _ => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
    };
    if *semantics != expected {
        return Err(invalid("method semantics differ from K3s configuration"));
    }
    Ok(())
}

fn validate_configuration(desired: &K3sConfiguration) -> Result<(), KubernetesProviderError> {
    let mut labels = desired.base.node_labels.keys().collect::<BTreeSet<_>>();
    for contribution in desired.contributions.values() {
        for label in contribution.node_labels.keys() {
            if !labels.insert(label) {
                return Err(invalid("K3s configuration repeats a node label"));
            }
        }
    }
    Ok(())
}

fn validate_configuration_prerequisites(
    contexts: &[aos_provider_protocol::ResourceContext],
    desired: &K3sConfiguration,
) -> Result<(), KubernetesProviderError> {
    for reference in &desired.base.prerequisites {
        require_resource(contexts, reference)?;
    }
    for contribution in desired.contributions.values() {
        for reference in &contribution.prerequisites {
            require_resource(contexts, reference)?;
        }
    }
    Ok(())
}

fn validate_selected_inputs(
    inputs: &AbilityValue,
    desired: &K3sConfiguration,
) -> Result<(), KubernetesProviderError> {
    let selected: K3sConfiguration = decode(inputs)?;
    if selected != *desired {
        return Err(invalid(
            "configuration terminal inputs differ from the retained aggregate resource",
        ));
    }
    Ok(())
}

fn validate_configuration_realization(
    realization: &K3sConfigurationRealization,
) -> Result<(), KubernetesProviderError> {
    let path = Path::new(&realization.path);
    if realization.schema != REALIZATION_SCHEMA
        || path.parent() != Some(Path::new("/run/aos/k3s"))
        || path.extension().and_then(|value| value.to_str()) != Some("json")
    {
        return Err(invalid(
            "K3s configuration realization is outside its package-owned runtime root",
        ));
    }
    Ok(())
}

fn render_configuration(desired: &K3sConfiguration) -> Result<Vec<u8>, KubernetesProviderError> {
    let integrations = desired.contributions.values().collect::<Vec<_>>();
    let mut labels = desired.base.node_labels.clone();
    for integration in &integrations {
        labels.extend(integration.node_labels.clone());
    }
    let node_labels = labels
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>();
    aos_contract::canonical::to_vec(&serde_json::json!({
        "flannel-backend": if integrations.iter().any(|entry| entry.disable_flannel) {
            "none"
        } else {
            desired.base.flannel_backend.as_str()
        },
        "disable-network-policy": desired.base.disable_network_policy
            || integrations.iter().any(|entry| entry.disable_network_policy),
        "disable-kube-proxy": desired.base.disable_kube_proxy
            || integrations.iter().any(|entry| entry.disable_kube_proxy),
        "node-label": node_labels,
    }))
    .map_err(|error| invalid(error.to_string()))
}

fn configuration_marker(path: &Path) -> PathBuf {
    path.with_extension("state.json")
}

fn materialize_configuration(
    path: &Path,
    content: &[u8],
    revision: &str,
) -> Result<(), KubernetesProviderError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("K3s configuration path has no parent"))?;
    fs::create_dir_all(parent)?;
    atomic_write(path, content)?;
    atomic_write(
        &configuration_marker(path),
        &aos_contract::canonical::to_vec(&serde_json::json!({
            "schema": "aos.k3s.configuration-state/v1",
            "revision": revision,
            "content_digest": Sha256Digest::of_bytes(content),
        }))
        .map_err(|error| invalid(error.to_string()))?,
    )
}

fn configuration_matches(
    path: &Path,
    content: &[u8],
    revision: &str,
) -> Result<bool, KubernetesProviderError> {
    let actual = match read_bounded(path, ABILITY_LIMITS_V1.max_document_bytes) {
        Ok(actual) => actual,
        Err(KubernetesProviderError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let marker = match read_bounded(
        &configuration_marker(path),
        ABILITY_LIMITS_V1.max_document_bytes,
    ) {
        Ok(marker) => marker,
        Err(KubernetesProviderError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let marker: Value = serde_json::from_slice(&marker)?;
    Ok(actual == content
        && marker.get("schema").and_then(Value::as_str) == Some("aos.k3s.configuration-state/v1")
        && marker.get("revision").and_then(Value::as_str) == Some(revision)
        && marker.get("content_digest")
            == Some(&Value::String(Sha256Digest::of_bytes(content).to_string())))
}

fn release_configuration(path: &Path, revision: &str) -> Result<(), KubernetesProviderError> {
    let marker = configuration_marker(path);
    let marker_bytes = match read_bounded(&marker, ABILITY_LIMITS_V1.max_document_bytes) {
        Ok(bytes) => bytes,
        Err(KubernetesProviderError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let marker_value: Value = serde_json::from_slice(&marker_bytes)?;
    if marker_value.get("revision").and_then(Value::as_str) != Some(revision) {
        return Err(invalid(
            "refusing to release a K3s configuration owned by another revision",
        ));
    }
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::remove_file(marker) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn configuration_observation<'a>(
    desired: &'a K3sConfiguration,
    path: &str,
    content: &[u8],
    current: bool,
) -> K3sConfigurationObservation<'a> {
    K3sConfigurationObservation {
        schema: OBSERVATION_SCHEMA,
        expected: desired,
        state: if current { "current" } else { "absent" },
        path: current.then(|| path.to_owned()),
        content_digest: current.then(|| Sha256Digest::of_bytes(content)),
    }
}

fn configuration_result(
    invocation: &Invocation,
    desired: &K3sConfiguration,
    path: &str,
    content: &[u8],
    current: bool,
    disposition: InvocationDisposition,
    retained: bool,
) -> Result<InvocationResult, KubernetesProviderError> {
    let mut outputs = BTreeMap::new();
    if retained {
        outputs.insert(
            LocalKey::new("retained-resource").map_err(|error| invalid(error.to_string()))?,
            ability_value(serde_json::to_value(&invocation.request.target)?)?,
        );
    }
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition,
        evidence: ability_value(serde_json::to_value(configuration_observation(
            desired, path, content, current,
        ))?)?,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_accepts_only_configuration_methods_with_exact_semantics() {
        let apply = MethodSemantics::ordinary(AccessMode::ExclusiveWrite);

        assert!(validate_configuration_method("apply", &apply).is_ok());
        assert!(validate_configuration_method("unknown", &apply).is_err());
    }

    #[test]
    fn configuration_composes_flags_and_labels_canonically() {
        let desired = K3sConfiguration {
            base: K3sConfigurationBase {
                flannel_backend: "vxlan".into(),
                disable_network_policy: false,
                disable_kube_proxy: false,
                node_labels: BTreeMap::from([("region".into(), "west".into())]),
                prerequisites: vec![],
            },
            contributions: BTreeMap::from([(
                "cilium".into(),
                K3sIntegration {
                    disable_flannel: true,
                    disable_network_policy: true,
                    disable_kube_proxy: true,
                    node_labels: BTreeMap::from([("storage".into(), "longhorn".into())]),
                    prerequisites: vec![],
                },
            )]),
        };

        let rendered = render_configuration(&desired).expect("configuration renders");
        let rendered: Value = serde_json::from_slice(&rendered).expect("configuration parses");

        assert_eq!(rendered["flannel-backend"], "none");
        assert_eq!(rendered["disable-network-policy"], true);
        assert_eq!(rendered["disable-kube-proxy"], true);
        assert_eq!(rendered["node-label"][0], "region=west");
        assert_eq!(rendered["node-label"][1], "storage=longhorn");
    }
}
