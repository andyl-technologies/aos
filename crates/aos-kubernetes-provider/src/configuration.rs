//! Native K3s configuration materialization and ownership-safe teardown.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{KubernetesProviderError, MAX_DOCUMENT_BYTES, atomic_write, invalid, read_bounded};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct K3sConfiguration {
    path: String,
    base: K3sConfigurationBase,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    integrations: BTreeMap<String, K3sIntegration>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct K3sConfigurationBase {
    flannel_backend: String,
    disable_network_policy: bool,
    disable_kube_proxy: bool,
    node_labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct K3sIntegration {
    disable_flannel: bool,
    disable_network_policy: bool,
    disable_kube_proxy: bool,
    node_labels: BTreeMap<String, String>,
}

pub(super) fn invoke(
    invocation: &Invocation,
    operation: &str,
) -> Result<Value, KubernetesProviderError> {
    let desired: K3sConfiguration = serde_json::from_value(invocation.input.clone())?;
    validate_configuration(&desired)?;
    let path = Path::new(&desired.path);
    if path.parent() != Some(Path::new("/run/aos/k3s"))
        || path.extension().and_then(|value| value.to_str()) != Some("json")
    {
        return Err(invalid(
            "configuration path is outside the K3s runtime root",
        ));
    }
    let content = render_configuration(&desired)?;
    let current = configuration_matches(path, &content, &invocation.revision)?;
    let outputs = serde_json::json!({"path":desired.path});
    let previous = invocation
        .previous
        .as_ref()
        .map(|previous| {
            serde_json::from_value::<K3sConfiguration>(previous.input.clone())
                .map(|input| (input, previous.revision.as_str()))
        })
        .transpose()?;
    let retired = previous
        .as_ref()
        .filter(|(input, _)| input.path != desired.path);
    let retired_present = match retired {
        Some((input, _)) => {
            Path::new(&input.path).try_exists()?
                || configuration_marker(Path::new(&input.path)).try_exists()?
        }
        None => false,
    };

    if operation == "observe" {
        if current && !retired_present && invocation.action == Action::Apply {
            return Ok(serde_json::json!({"status":"current", "outputs":outputs}));
        }
        let status = if !path.try_exists()? && !configuration_marker(path).try_exists()? {
            "absent"
        } else if current
            || invocation.action == Action::Apply
            || (!path.try_exists()?
                && configuration_intent_matches(path, &content, &invocation.revision)?)
        {
            "retry-safe"
        } else {
            "indeterminate"
        };
        return Ok(serde_json::json!({"status":status}));
    }
    if operation == "apply" {
        if !current
            && path.try_exists()?
            && !configuration_intent_matches(path, &content, &invocation.revision)?
        {
            let previous = invocation
                .previous
                .as_ref()
                .ok_or_else(|| invalid("refusing to overwrite unowned K3s configuration"))?;
            let old: K3sConfiguration = serde_json::from_value(previous.input.clone())?;
            if old.path != desired.path
                || !configuration_matches(path, &render_configuration(&old)?, &previous.revision)?
            {
                return Err(invalid("K3s previous configuration ownership differs"));
            }
        }
        if let Some((input, revision)) = retired {
            let old_path = Path::new(&input.path);
            if old_path.parent() != Some(Path::new("/run/aos/k3s"))
                || old_path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                return Err(invalid(
                    "previous configuration path is outside the K3s runtime root",
                ));
            }
            if old_path.try_exists()?
                && !configuration_matches(old_path, &render_configuration(input)?, revision)?
            {
                return Err(invalid("retired K3s configuration has external edits"));
            }
        }
        materialize_configuration(path, &content, &invocation.revision)?;
        if let Some((input, revision)) = retired {
            release_configuration(Path::new(&input.path), revision)?;
        }
        return Ok(outputs);
    }
    release_configuration(path, &invocation.revision)?;
    Ok(serde_json::json!({}))
}

fn validate_configuration(desired: &K3sConfiguration) -> Result<(), KubernetesProviderError> {
    let mut labels = desired.base.node_labels.keys().collect::<BTreeSet<_>>();
    for integration in desired.integrations.values() {
        for label in integration.node_labels.keys() {
            if !labels.insert(label) {
                return Err(invalid("K3s configuration repeats a node label"));
            }
        }
    }
    Ok(())
}

fn render_configuration(desired: &K3sConfiguration) -> Result<Vec<u8>, KubernetesProviderError> {
    let integrations = desired.integrations.values().collect::<Vec<_>>();
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
    // Publish the owned intent first so interruption before content rename is retryable.
    atomic_write(
        &configuration_marker(path),
        &aos_contract::canonical::to_vec(&serde_json::json!({
            "schema": "aos.k3s.configuration-state/v1",
            "revision": revision,
            "content_digest": Sha256Digest::of_bytes(content),
        }))
        .map_err(|error| invalid(error.to_string()))?,
    )?;
    atomic_write(path, content)
}

fn configuration_intent_matches(
    path: &Path,
    content: &[u8],
    revision: &str,
) -> Result<bool, KubernetesProviderError> {
    let bytes = match read_bounded(&configuration_marker(path), MAX_DOCUMENT_BYTES) {
        Ok(bytes) => bytes,
        Err(KubernetesProviderError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let marker: Value = serde_json::from_slice(&bytes)?;
    Ok(
        marker.get("schema").and_then(Value::as_str) == Some("aos.k3s.configuration-state/v1")
            && marker.get("revision").and_then(Value::as_str) == Some(revision)
            && marker.get("content_digest")
                == Some(&Value::String(Sha256Digest::of_bytes(content).to_string())),
    )
}

fn configuration_matches(
    path: &Path,
    content: &[u8],
    revision: &str,
) -> Result<bool, KubernetesProviderError> {
    let actual = match read_bounded(path, MAX_DOCUMENT_BYTES) {
        Ok(actual) => actual,
        Err(KubernetesProviderError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let marker = match read_bounded(&configuration_marker(path), MAX_DOCUMENT_BYTES) {
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
    let marker_bytes = match read_bounded(&marker, MAX_DOCUMENT_BYTES) {
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
    if path.try_exists()? {
        let content = read_bounded(path, MAX_DOCUMENT_BYTES)?;
        if marker_value.get("content_digest")
            != Some(&Value::String(Sha256Digest::of_bytes(content).to_string()))
        {
            return Err(invalid(
                "refusing to delete externally modified K3s configuration",
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_configuration_needs_no_empty_integration_map() {
        let value = serde_json::json!({
            "path":"/run/aos/k3s/config.json",
            "base": {
                "flannel_backend": "vxlan",
                "disable_network_policy": false,
                "disable_kube_proxy": false,
                "node_labels": {}
            }
        });
        let desired: K3sConfiguration = serde_json::from_value(value.clone())
            .expect("base configuration without integrations decodes");

        assert!(desired.integrations.is_empty());
        assert_eq!(
            serde_json::to_value(desired).expect("configuration encodes"),
            value
        );
    }

    #[test]
    fn configuration_composes_flags_and_labels_canonically() {
        let desired = K3sConfiguration {
            path: "/run/aos/k3s/config.json".into(),
            base: K3sConfigurationBase {
                flannel_backend: "vxlan".into(),
                disable_network_policy: false,
                disable_kube_proxy: false,
                node_labels: BTreeMap::from([("region".into(), "west".into())]),
            },
            integrations: BTreeMap::from([(
                "cilium".into(),
                K3sIntegration {
                    disable_flannel: true,
                    disable_network_policy: true,
                    disable_kube_proxy: true,
                    node_labels: BTreeMap::from([("storage".into(), "longhorn".into())]),
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

    #[test]
    fn interrupted_configuration_intent_can_finish_and_rejects_other_revisions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let content = br#"{"flannel-backend":"vxlan"}"#;
        let marker = serde_json::json!({
            "schema":"aos.k3s.configuration-state/v1",
            "revision":"revision-one",
            "content_digest":Sha256Digest::of_bytes(content),
        });
        atomic_write(
            &configuration_marker(&path),
            &serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();

        assert!(configuration_intent_matches(&path, content, "revision-one").unwrap());
        assert!(!configuration_intent_matches(&path, content, "revision-two").unwrap());
        assert!(!configuration_matches(&path, content, "revision-one").unwrap());

        materialize_configuration(&path, content, "revision-one").unwrap();
        assert!(configuration_matches(&path, content, "revision-one").unwrap());
    }

    #[test]
    fn release_preserves_foreign_edits_and_removes_owned_configuration_idempotently() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let content = br#"{"owned":true}"#;
        materialize_configuration(&path, content, "revision-one").unwrap();

        assert!(release_configuration(&path, "revision-two").is_err());
        fs::write(&path, br#"{"foreign":true}"#).unwrap();
        assert!(release_configuration(&path, "revision-one").is_err());
        assert!(path.exists());

        fs::write(&path, content).unwrap();
        release_configuration(&path, "revision-one").unwrap();
        release_configuration(&path, "revision-one").unwrap();
        assert!(!path.exists());
        assert!(!configuration_marker(&path).exists());
    }
}
