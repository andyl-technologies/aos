//! K3s-owned convergence for typed Kubernetes object sets.
//!
//! The generic ability runtime authenticates and invokes this executable but
//! does not interpret Kubernetes objects. This provider validates the complete
//! checked resource context, binds it to one observed cluster incarnation and
//! kubeconfig digest, and applies or releases only objects bearing its exact
//! ownership annotation.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, AccessMode, IncarnationId, LocalKey, MethodSemantics,
    ResourceReference,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, BoundNativeContext, HANDLER_ABI_ARGUMENT,
    INVOCATION_SCHEMA, Invocation, InvocationDisposition, InvocationPurpose, InvocationResult,
    REQUEST_SCHEMA, RESULT_SCHEMA, ResourceContext, SupportedPurposes, resource_set_digest,
    validate_admission_resource, validate_resource_context, validate_resource_contexts,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

mod configuration;

const OBSERVATION_SCHEMA: &str = "aos.ability.kubernetes-object-set-observation/v1";
const PROVIDER_CONTEXT_SCHEMA: &str = "aos.kubernetes.object-set-context/v1";
const REALIZATION_SCHEMA: &str = "aos.kubernetes.object-set-realization/v1";
const RECEIPT_SCHEMA: &str = "aos.kubernetes.object-set-receipt/v1";
const OWNER_ANNOTATION: &str = "aos.andyl.com/object-set-owner";
const REVISION_ANNOTATION: &str = "aos.andyl.com/object-revision";
const STATE_ROOT: &str = "/var/lib/aos/ability-runtime/kubernetes-object-set";
const MAX_KUBECONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandlerRole {
    Configuration,
    ObjectSet,
}

impl HandlerRole {
    fn from_process() -> Result<Self, KubernetesProviderError> {
        let executable = std::env::args_os()
            .next()
            .ok_or_else(|| invalid("provider process has no executable name"))?;
        Self::from_entry_point(&executable)
    }

    fn from_entry_point(executable: &OsStr) -> Result<Self, KubernetesProviderError> {
        let name = Path::new(executable)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("provider executable name is not valid UTF-8"))?;
        match name {
            "aos-k3s-configuration-effects" => Ok(Self::Configuration),
            "aos-kubernetes-object-effects" => Ok(Self::ObjectSet),
            _ => Err(invalid(
                "provider entry point does not select a checked role",
            )),
        }
    }
}

/// Reports invalid contracts, unavailable Kubernetes operations, and state I/O failures.
#[derive(Debug, Error)]
pub enum KubernetesProviderError {
    /// The checked request differs from the package-owned contract.
    #[error("invalid Kubernetes object-set request: {0}")]
    Invalid(String),
    /// A filesystem or child-process operation failed.
    #[error("Kubernetes object-set operation failed: {0}")]
    Io(#[from] io::Error),
    /// A protocol or Kubernetes document could not be decoded.
    #[error("Kubernetes object-set document error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AggregateRequest {
    cluster: ClusterRequest,
    contributions: BTreeMap<String, ContributionRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ClusterRequest {
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContributionRequest {
    objects: Vec<KubernetesObject>,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct KubernetesObject {
    key: String,
    api_version: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    content: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Realization {
    schema: String,
    kubeconfig: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    cluster_incarnation: String,
    kubeconfig_digest: Sha256Digest,
    owner: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    revision: String,
    cluster_incarnation: String,
    kubeconfig_digest: Sha256Digest,
    objects: BTreeMap<String, ObjectReceipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectReceipt {
    api_version: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: String,
    resource_version: String,
    revision: String,
}

#[derive(Clone, Debug, Deserialize)]
struct LiveObject {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: LiveMetadata,
}

#[derive(Clone, Debug, Deserialize)]
struct LiveMetadata {
    name: String,
    namespace: Option<String>,
    uid: String,
    #[serde(rename = "resourceVersion")]
    resource_version: String,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
struct Observation<'a> {
    schema: &'static str,
    expected: &'a AggregateRequest,
    cluster: ClusterObservation,
    objects: BTreeMap<String, ObjectObservation>,
    state: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ClusterObservation {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    incarnation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kubeconfig_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Serialize)]
struct ObjectObservation {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_version: Option<String>,
}

/// Runs one selected command-handler operation from process arguments and streams.
///
/// # Errors
///
/// Returns an error when the command ABI, checked resource context, Kubernetes
/// response, or provider receipt is invalid.
pub fn run_from_process() -> Result<(), KubernetesProviderError> {
    let role = HandlerRole::from_process()?;
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[0] != HANDLER_ABI_ARGUMENT {
        return Err(invalid("expected --aos-primitive-v1 and one purpose"));
    }

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
        return Err(invalid(
            "protocol input exceeds the canonical document bound",
        ));
    }

    let output = match arguments[1].as_str() {
        "admit" => serde_json::to_vec(&admit(role, serde_json::from_slice(&input)?)?)?,
        "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation" => {
            let invocation = serde_json::from_slice(&input)?;
            serde_json::to_vec(&invoke(role, invocation, &arguments[1])?)?
        }
        _ => return Err(invalid("unsupported provider purpose")),
    };
    io::stdout().write_all(&output)?;
    Ok(())
}

fn admit(
    role: HandlerRole,
    request: AdmissionRequest,
) -> Result<AdmissionResult, KubernetesProviderError> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        return Err(invalid("admission schema differs from the selected ABI"));
    }
    validate_admission_resource(&request).map_err(|error| invalid(error.to_string()))?;
    validate_contexts(&request.resources)?;
    if role == HandlerRole::Configuration {
        return configuration::admit(request);
    }
    validate_method(request.method.method.as_str(), &request.semantics)?;
    let desired: AggregateRequest = decode(&request.resource_spec.value)?;
    let realization: Realization = decode(&request.resource_spec.realization)?;
    validate_desired(&desired)?;
    validate_object_prerequisites(&request.resources, &desired)?;
    validate_realization(&realization)?;
    let capability = Capability::acquire(&realization, request.control.attempt_remaining_millis)?;
    let owner = canonical_owner(&request.target)?;
    let observation = observe(&capability, &desired, &owner)?;
    let current = observation.state == "current";

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
        incarnation: Some(
            IncarnationId::new(capability.cluster_incarnation.clone())
                .map_err(|error| invalid(error.to_string()))?,
        ),
        observation: ability_value(serde_json::to_value(observation)?)?,
        native_context: ability_value(serde_json::to_value(ProviderContext {
            schema: PROVIDER_CONTEXT_SCHEMA.into(),
            cluster_incarnation: capability.cluster_incarnation,
            kubeconfig_digest: capability.kubeconfig_digest,
            owner,
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .ok_or_else(|| invalid("Kubernetes purpose support is not canonical"))?,
    })
}

fn invoke(
    role: HandlerRole,
    invocation: Invocation,
    selected_purpose: &str,
) -> Result<InvocationResult, KubernetesProviderError> {
    if invocation.schema != INVOCATION_SCHEMA
        || invocation.request.schema != REQUEST_SCHEMA
        || selected_purpose != purpose_name(invocation.purpose)
        || !invocation.method_is_bound()
        || invocation.method.interface != invocation.request.target.interface
        || !invocation
            .request
            .target
            .operations
            .contains(&invocation.method.method)
    {
        return Err(invalid(
            "invocation differs from its selected durable operation",
        ));
    }
    validate_contexts(&invocation.request.resources)?;
    if resource_set_digest(&invocation.request.resources)
        .map_err(|error| invalid(error.to_string()))?
        != invocation.request.native_context_digest
    {
        return Err(invalid(
            "resource contexts differ from their authenticated digest",
        ));
    }
    if role == HandlerRole::Configuration {
        return configuration::invoke(invocation);
    }
    validate_method(invocation.method.method.as_str(), &invocation.semantics)?;
    let (desired, realization, provider_context) = target_context(&invocation)?;
    validate_desired(&desired)?;
    validate_object_prerequisites(&invocation.request.resources, &desired)?;
    validate_realization(&realization)?;
    validate_selected_inputs(&invocation.request.inputs, &desired)?;
    if provider_context.schema != PROVIDER_CONTEXT_SCHEMA
        || provider_context.owner != canonical_owner(&invocation.request.target)?
    {
        return Err(invalid(
            "Kubernetes provider context differs from the selected target",
        ));
    }
    let capability =
        Capability::acquire(&realization, invocation.control.attempt_remaining_millis)?;
    if capability.cluster_incarnation != provider_context.cluster_incarnation
        || capability.kubeconfig_digest != provider_context.kubeconfig_digest
    {
        return Err(invalid(
            "Kubernetes cluster context changed after admission",
        ));
    }

    if invocation.control.cancelled {
        return result(
            &invocation,
            &desired,
            &capability,
            &provider_context.owner,
            InvocationDisposition::RejectedBeforeEffect,
            false,
        );
    }

    match invocation.purpose {
        InvocationPurpose::Effect if invocation.method.method.as_str() == "apply" => {
            let prior_receipt = read_retained_receipt(&invocation, &capability)?;
            apply(
                &capability,
                &desired,
                &provider_context.owner,
                prior_receipt.as_ref(),
            )?;
            write_receipt(&invocation, &capability, &desired, &provider_context.owner)?;
            result(
                &invocation,
                &desired,
                &capability,
                &provider_context.owner,
                InvocationDisposition::Completed,
                true,
            )
        }
        InvocationPurpose::Effect if invocation.method.method.as_str() == "release" => {
            if observe(&capability, &desired, &provider_context.owner)?.state == "absent" {
                remove_receipt(&invocation)?;
                return result(
                    &invocation,
                    &desired,
                    &capability,
                    &provider_context.owner,
                    InvocationDisposition::Completed,
                    false,
                );
            }
            let receipt = read_receipt(&invocation, &capability, &desired)?;
            release(&capability, &desired, &provider_context.owner, &receipt)?;
            remove_receipt(&invocation)?;
            result(
                &invocation,
                &desired,
                &capability,
                &provider_context.owner,
                InvocationDisposition::Completed,
                false,
            )
        }
        InvocationPurpose::Effect => result(
            &invocation,
            &desired,
            &capability,
            &provider_context.owner,
            InvocationDisposition::Completed,
            false,
        ),
        InvocationPurpose::Reconcile => {
            let observation = observe(&capability, &desired, &provider_context.owner)?;
            let disposition = if invocation.request.method.method.as_str() == "release" {
                if observation.state == "absent" {
                    remove_receipt(&invocation)?;
                    InvocationDisposition::Completed
                } else {
                    InvocationDisposition::SafeToRetry
                }
            } else if observation.state == "current" {
                InvocationDisposition::Completed
            } else {
                InvocationDisposition::SafeToRetry
            };
            result_with_observation(&invocation, observation, disposition, false)
        }
        InvocationPurpose::Cancel => result(
            &invocation,
            &desired,
            &capability,
            &provider_context.owner,
            InvocationDisposition::RejectedBeforeEffect,
            false,
        ),
        InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => Err(invalid(
            "Kubernetes object-set provider has no compensation operation",
        )),
    }
}

struct Capability {
    executable: PathBuf,
    kubeconfig: PathBuf,
    kubeconfig_digest: Sha256Digest,
    cluster_incarnation: String,
    timeout_millis: u64,
}

impl Capability {
    fn acquire(
        realization: &Realization,
        timeout_millis: u64,
    ) -> Result<Self, KubernetesProviderError> {
        let executable = sibling_executable()?;
        let kubeconfig = PathBuf::from(&realization.kubeconfig);
        let metadata = fs::symlink_metadata(&kubeconfig)?;
        if !metadata.file_type().is_file() {
            return Err(invalid("kubeconfig is not a regular file"));
        }
        let bytes = read_bounded(&kubeconfig, MAX_KUBECONFIG_BYTES)?;
        let kubeconfig_digest = Sha256Digest::of_bytes(bytes);
        let mut capability = Self {
            executable,
            kubeconfig,
            kubeconfig_digest,
            cluster_incarnation: String::new(),
            timeout_millis,
        };
        let namespace =
            capability.run(&["get", "namespace", "kube-system", "--output=json"], None)?;
        let value: Value = serde_json::from_slice(&namespace)?;
        capability.cluster_incarnation = required_string(&value, &["metadata", "uid"])?;
        Ok(capability)
    }

    fn run(
        &self,
        arguments: &[&str],
        input: Option<&[u8]>,
    ) -> Result<Vec<u8>, KubernetesProviderError> {
        let timeout = self.timeout_millis.clamp(1, 30_000);
        let mut command = Command::new(&self.executable);
        command
            .env_clear()
            .arg("kubectl")
            .arg("--kubeconfig")
            .arg(&self.kubeconfig)
            .arg(format!("--request-timeout={timeout}ms"))
            .args(arguments)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        if let Some(input) = input {
            child
                .stdin
                .take()
                .ok_or_else(|| invalid("kubectl stdin was not created"))?
                .write_all(input)?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(invalid(format!(
                "k3s kubectl failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        if output.stdout.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
            return Err(invalid(
                "kubectl response exceeds the canonical document bound",
            ));
        }
        Ok(output.stdout)
    }
}

fn sibling_executable() -> Result<PathBuf, KubernetesProviderError> {
    let executable = std::env::current_exe()?;
    let sibling = executable
        .parent()
        .ok_or_else(|| invalid("handler executable has no parent"))?
        .join("k3s");
    if !fs::symlink_metadata(&sibling)?.file_type().is_symlink() {
        return Err(invalid(
            "package-owned k3s executable is not an authenticated sibling link",
        ));
    }
    Ok(sibling)
}

fn validate_desired(desired: &AggregateRequest) -> Result<(), KubernetesProviderError> {
    let mut keys = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for contribution in desired.contributions.values() {
        for object in &contribution.objects {
            if !keys.insert(object.key.clone()) {
                return Err(invalid("Kubernetes object keys are not globally unique"));
            }
            let identity = (
                &object.api_version,
                &object.kind,
                &object.namespace,
                &object.name,
            );
            if !identities.insert(identity) {
                return Err(invalid("Kubernetes API object identities are not unique"));
            }
            let value: Value = serde_json::from_str(&object.content)?;
            if aos_contract::canonical::to_vec(&value)
                .map_err(|error| invalid(error.to_string()))?
                != object.content.as_bytes()
            {
                return Err(invalid("Kubernetes object content is not canonical JSON"));
            }
            validate_object_identity(object, &value)?;
        }
    }
    Ok(())
}

fn validate_selected_inputs(
    inputs: &AbilityValue,
    desired: &AggregateRequest,
) -> Result<(), KubernetesProviderError> {
    let selected: AggregateRequest = decode(inputs)?;
    if selected != *desired {
        return Err(invalid(
            "terminal inputs differ from the retained aggregate resource",
        ));
    }
    Ok(())
}

fn validate_object_identity(
    object: &KubernetesObject,
    value: &Value,
) -> Result<(), KubernetesProviderError> {
    let metadata = value
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Kubernetes object has no metadata object"))?;
    let namespace = metadata
        .get("namespace")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let reserved_annotation = metadata
        .get("annotations")
        .and_then(Value::as_object)
        .is_some_and(|annotations| {
            annotations.contains_key(OWNER_ANNOTATION)
                || annotations.contains_key(REVISION_ANNOTATION)
        });
    if value.get("apiVersion").and_then(Value::as_str) != Some(&object.api_version)
        || value.get("kind").and_then(Value::as_str) != Some(&object.kind)
        || metadata.get("name").and_then(Value::as_str) != Some(&object.name)
        || namespace != object.namespace
        || metadata.contains_key("uid")
        || metadata.contains_key("resourceVersion")
        || reserved_annotation
    {
        return Err(invalid(
            "Kubernetes object content differs from its declared identity",
        ));
    }
    Ok(())
}

fn validate_realization(realization: &Realization) -> Result<(), KubernetesProviderError> {
    if realization.schema != REALIZATION_SCHEMA || !Path::new(&realization.kubeconfig).is_absolute()
    {
        return Err(invalid(
            "Kubernetes realization is outside the package-owned schema",
        ));
    }
    Ok(())
}

fn validate_method(
    method: &str,
    semantics: &MethodSemantics,
) -> Result<(), KubernetesProviderError> {
    let method_allowed = matches!(method, "apply" | "observe" | "release");
    if !method_allowed {
        return Err(invalid(
            "method does not belong to Kubernetes object-set management",
        ));
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
        return Err(invalid(
            "method semantics differ from Kubernetes object-set management",
        ));
    }
    Ok(())
}

pub(crate) fn validate_contexts(
    contexts: &[ResourceContext],
) -> Result<(), KubernetesProviderError> {
    validate_resource_contexts(contexts).map_err(|error| invalid(error.to_string()))
}

pub(crate) fn require_resource(
    contexts: &[ResourceContext],
    reference: &ResourceReference,
) -> Result<(), KubernetesProviderError> {
    let index = contexts
        .binary_search_by(|context| context.reference.resource.cmp(&reference.resource))
        .map_err(|_| invalid("required resource has no runtime context"))?;
    if contexts[index].reference != *reference {
        return Err(invalid(
            "required resource context differs from the exact desired reference",
        ));
    }
    Ok(())
}

fn validate_object_prerequisites(
    contexts: &[ResourceContext],
    desired: &AggregateRequest,
) -> Result<(), KubernetesProviderError> {
    for reference in &desired.cluster.prerequisites {
        require_resource(contexts, reference)?;
    }
    for contribution in desired.contributions.values() {
        for reference in &contribution.prerequisites {
            require_resource(contexts, reference)?;
        }
    }
    Ok(())
}

fn target_context(
    invocation: &Invocation,
) -> Result<(AggregateRequest, Realization, ProviderContext), KubernetesProviderError> {
    let native = bound_target_context(invocation)?;
    Ok((
        decode(&native.resource_spec.value)?,
        decode(&native.resource_spec.realization)?,
        decode(&native.provider_context)?,
    ))
}

pub(crate) fn bound_target_context(
    invocation: &Invocation,
) -> Result<BoundNativeContext, KubernetesProviderError> {
    let contexts = invocation
        .request
        .resources
        .iter()
        .filter(|context| context.reference == invocation.request.target)
        .collect::<Vec<_>>();
    let [context] = contexts.as_slice() else {
        return Err(invalid(
            "target resource must have exactly one runtime context",
        ));
    };
    let native = validate_resource_context(context).map_err(|error| invalid(error.to_string()))?;
    if native.resource_spec.value != invocation.request.inputs {
        return Err(invalid(
            "controller inputs differ from the retained aggregate resource",
        ));
    }
    Ok(native)
}

fn all_objects(desired: &AggregateRequest) -> impl Iterator<Item = &KubernetesObject> {
    desired
        .contributions
        .values()
        .flat_map(|contribution| contribution.objects.iter())
}

fn desired_revision(object: &KubernetesObject) -> Sha256Digest {
    Sha256Digest::separated("aos.kubernetes.object/v1", object.content.as_bytes())
}

fn desired_document(
    object: &KubernetesObject,
    owner: &str,
) -> Result<Vec<u8>, KubernetesProviderError> {
    let mut document: Value = serde_json::from_str(&object.content)?;
    let metadata = document
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("Kubernetes object has no mutable metadata"))?;
    let annotations = metadata
        .entry("annotations")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| invalid("Kubernetes metadata annotations is not an object"))?;
    annotations.insert(OWNER_ANNOTATION.into(), Value::String(owner.into()));
    annotations.insert(
        REVISION_ANNOTATION.into(),
        Value::String(desired_revision(object).to_string()),
    );
    aos_contract::canonical::to_vec(&document).map_err(|error| invalid(error.to_string()))
}

fn observe<'a>(
    capability: &Capability,
    desired: &'a AggregateRequest,
    owner: &str,
) -> Result<Observation<'a>, KubernetesProviderError> {
    let mut objects = BTreeMap::new();
    let mut all_absent = true;
    let mut all_current = true;
    for object in all_objects(desired) {
        let live = get_object(capability, object)?;
        let observation = match live {
            None => {
                all_current = false;
                ObjectObservation {
                    state: "absent",
                    revision: None,
                    uid: None,
                    resource_version: None,
                }
            }
            Some(live) => {
                all_absent = false;
                let owned = live
                    .metadata
                    .annotations
                    .get(OWNER_ANNOTATION)
                    .map(String::as_str)
                    == Some(owner);
                let revision = live
                    .metadata
                    .annotations
                    .get(REVISION_ANNOTATION)
                    .and_then(|value| Sha256Digest::parse(value).ok());
                let current = owned && revision == Some(desired_revision(object));
                all_current &= current;
                ObjectObservation {
                    state: if !owned {
                        "foreign"
                    } else if current {
                        "current"
                    } else {
                        "drifted"
                    },
                    revision,
                    uid: Some(live.metadata.uid),
                    resource_version: Some(live.metadata.resource_version),
                }
            }
        };
        objects.insert(object.key.clone(), observation);
    }
    let state = if all_current {
        "current"
    } else if all_absent {
        "absent"
    } else {
        "drifted"
    };
    Ok(Observation {
        schema: OBSERVATION_SCHEMA,
        expected: desired,
        cluster: ClusterObservation {
            available: true,
            incarnation: Some(capability.cluster_incarnation.clone()),
            kubeconfig_digest: Some(capability.kubeconfig_digest),
        },
        objects,
        state,
    })
}

fn get_object(
    capability: &Capability,
    object: &KubernetesObject,
) -> Result<Option<LiveObject>, KubernetesProviderError> {
    let mut arguments = vec![
        "get",
        object.kind.as_str(),
        object.name.as_str(),
        "--ignore-not-found",
        "--output=json",
    ];
    if let Some(namespace) = &object.namespace {
        arguments.extend(["--namespace", namespace.as_str()]);
    }
    let bytes = capability.run(&arguments, None)?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }

    let live: LiveObject = serde_json::from_slice(&bytes)?;
    if live.api_version != object.api_version
        || live.kind != object.kind
        || live.metadata.name != object.name
        || live.metadata.namespace != object.namespace
    {
        return Err(invalid("Kubernetes API returned another object identity"));
    }
    Ok(Some(live))
}

fn apply(
    capability: &Capability,
    desired: &AggregateRequest,
    owner: &str,
    prior_receipt: Option<&Receipt>,
) -> Result<(), KubernetesProviderError> {
    for object in all_objects(desired) {
        if let Some(live) = get_object(capability, object)?
            && live
                .metadata
                .annotations
                .get(OWNER_ANNOTATION)
                .map(String::as_str)
                != Some(owner)
        {
            return Err(invalid("refusing to replace a foreign Kubernetes object"));
        }
    }
    for object in all_objects(desired) {
        let document = desired_document(object, owner)?;
        capability.run(
            &[
                "apply",
                "--server-side",
                "--field-manager=aos",
                "--filename=-",
                "--output=json",
            ],
            Some(&document),
        )?;
    }
    if let Some(receipt) = prior_receipt {
        prune_retired_objects(capability, desired, owner, receipt)?;
    }
    if observe(capability, desired, owner)?.state != "current" {
        return Err(invalid(
            "Kubernetes object set did not converge after apply",
        ));
    }
    Ok(())
}

fn prune_retired_objects(
    capability: &Capability,
    desired: &AggregateRequest,
    owner: &str,
    receipt: &Receipt,
) -> Result<(), KubernetesProviderError> {
    let mut retired = Vec::new();
    for (key, retained) in &receipt.objects {
        if all_objects(desired).any(|object| retained.matches(object)) {
            continue;
        }
        let object = retained.as_object(key);
        let Some(live) = get_object(capability, &object)? else {
            continue;
        };
        if live
            .metadata
            .annotations
            .get(OWNER_ANNOTATION)
            .map(String::as_str)
            != Some(owner)
            || live
                .metadata
                .annotations
                .get(REVISION_ANNOTATION)
                .map(String::as_str)
                != Some(retained.revision.as_str())
        {
            return Err(invalid(
                "refusing to prune a retired Kubernetes object with changed ownership",
            ));
        }
        if retained.uid != live.metadata.uid {
            return Err(invalid("refusing to prune a replacement Kubernetes object"));
        }
        retired.push((object, live));
    }
    for (object, live) in retired {
        delete_with_preconditions(capability, &object, &live)?;
    }
    Ok(())
}

fn release(
    capability: &Capability,
    desired: &AggregateRequest,
    owner: &str,
    receipt: &Receipt,
) -> Result<(), KubernetesProviderError> {
    let mut retained_objects = Vec::new();
    for object in all_objects(desired) {
        let Some(live) = get_object(capability, object)? else {
            continue;
        };
        if live
            .metadata
            .annotations
            .get(OWNER_ANNOTATION)
            .map(String::as_str)
            != Some(owner)
        {
            return Err(invalid("refusing to delete a foreign Kubernetes object"));
        }
        if live
            .metadata
            .annotations
            .get(REVISION_ANNOTATION)
            .map(String::as_str)
            != Some(desired_revision(object).to_string().as_str())
        {
            return Err(invalid(
                "refusing to delete a Kubernetes object at another revision",
            ));
        }
        let retained = receipt
            .objects
            .get(&object.key)
            .ok_or_else(|| invalid("Kubernetes receipt omitted a desired object"))?;
        if retained.uid != live.metadata.uid {
            return Err(invalid(
                "refusing to delete a replacement Kubernetes object",
            ));
        }
        retained_objects.push((object, live));
    }
    for (object, live) in retained_objects {
        delete_with_preconditions(capability, object, &live)?;
    }
    if observe(capability, desired, owner)?.state != "absent" {
        return Err(invalid(
            "Kubernetes object set remained present after release",
        ));
    }
    Ok(())
}

fn delete_with_preconditions(
    capability: &Capability,
    object: &KubernetesObject,
    live: &LiveObject,
) -> Result<(), KubernetesProviderError> {
    if live.metadata.uid.is_empty() || live.metadata.resource_version.is_empty() {
        return Err(invalid(
            "Kubernetes delete requires UID and resource-version preconditions",
        ));
    }
    let resource_url = discover_resource_url(capability, object)?;
    let options = delete_options(live)?;
    capability.run(
        &["delete", "--raw", &resource_url, "-f", "-"],
        Some(&options),
    )?;
    Ok(())
}

fn delete_options(live: &LiveObject) -> Result<Vec<u8>, KubernetesProviderError> {
    aos_contract::canonical::to_vec(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {
            "resourceVersion": live.metadata.resource_version,
            "uid": live.metadata.uid,
        },
        "propagationPolicy": "Foreground",
    }))
    .map_err(|error| invalid(error.to_string()))
}

fn discover_resource_url(
    capability: &Capability,
    object: &KubernetesObject,
) -> Result<String, KubernetesProviderError> {
    let (prefix, expected_group_version) =
        if let Some((group, version)) = object.api_version.split_once('/') {
            (
                format!("/apis/{group}/{version}"),
                object.api_version.as_str(),
            )
        } else {
            (
                format!("/api/{}", object.api_version),
                object.api_version.as_str(),
            )
        };
    let output = capability.run(&["get", "--raw", &prefix], None)?;
    let discovery: Value = serde_json::from_slice(&output)?;
    if discovery.get("groupVersion").and_then(Value::as_str) != Some(expected_group_version) {
        return Err(invalid(
            "Kubernetes discovery returned another API group version",
        ));
    }
    let resources = discovery
        .get("resources")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Kubernetes discovery has no resource list"))?;
    let namespaced = object.namespace.is_some();
    let matches = resources
        .iter()
        .filter(|candidate| {
            candidate.get("kind").and_then(Value::as_str) == Some(object.kind.as_str())
                && candidate.get("namespaced").and_then(Value::as_bool) == Some(namespaced)
                && candidate
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !name.contains('/'))
        })
        .collect::<Vec<_>>();
    let [mapping] = matches.as_slice() else {
        return Err(invalid(
            "Kubernetes kind does not resolve to one exact API resource",
        ));
    };
    let plural = mapping
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Kubernetes API resource has no name"))?;
    Ok(match &object.namespace {
        Some(namespace) => format!("{prefix}/namespaces/{namespace}/{plural}/{}", object.name),
        None => format!("{prefix}/{plural}/{}", object.name),
    })
}

fn result(
    invocation: &Invocation,
    desired: &AggregateRequest,
    capability: &Capability,
    owner: &str,
    disposition: InvocationDisposition,
    retained: bool,
) -> Result<InvocationResult, KubernetesProviderError> {
    let observation = observe(capability, desired, owner)?;
    result_with_observation(invocation, observation, disposition, retained)
}

fn result_with_observation(
    invocation: &Invocation,
    observation: Observation<'_>,
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
        evidence: ability_value(serde_json::to_value(observation)?)?,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn receipt_path(invocation: &Invocation) -> Result<PathBuf, KubernetesProviderError> {
    let digest = Sha256Digest::of_canonical(
        "aos.kubernetes.object-set-receipt-path/v1",
        &invocation.request.target.resource,
    )
    .map_err(|error| invalid(error.to_string()))?;
    Ok(Path::new(STATE_ROOT).join(format!("{}.json", digest.hex())))
}

fn write_receipt(
    invocation: &Invocation,
    capability: &Capability,
    desired: &AggregateRequest,
    owner: &str,
) -> Result<(), KubernetesProviderError> {
    let observation = observe(capability, desired, owner)?;
    if observation.state != "current" {
        return Err(invalid(
            "cannot publish a receipt for a noncurrent object set",
        ));
    }
    let mut objects = BTreeMap::new();
    for (key, observed) in observation.objects {
        let object = all_objects(desired)
            .find(|object| object.key == key)
            .ok_or_else(|| invalid("current observation has an unknown object key"))?;
        objects.insert(
            key,
            ObjectReceipt {
                api_version: object.api_version.clone(),
                kind: object.kind.clone(),
                namespace: object.namespace.clone(),
                name: object.name.clone(),
                uid: observed
                    .uid
                    .ok_or_else(|| invalid("current object has no UID"))?,
                resource_version: observed
                    .resource_version
                    .ok_or_else(|| invalid("current object has no resource version"))?,
                revision: observed
                    .revision
                    .ok_or_else(|| invalid("current object has no revision"))?
                    .to_string(),
            },
        );
    }
    let receipt = Receipt {
        schema: RECEIPT_SCHEMA.into(),
        revision: invocation
            .request
            .resources
            .iter()
            .find(|context| context.reference == invocation.request.target)
            .ok_or_else(|| invalid("target context is absent"))?
            .revision
            .0
            .to_string(),
        cluster_incarnation: capability.cluster_incarnation.clone(),
        kubeconfig_digest: capability.kubeconfig_digest,
        objects,
    };
    atomic_write(
        &receipt_path(invocation)?,
        &aos_contract::canonical::to_vec(&receipt).map_err(|error| invalid(error.to_string()))?,
    )
}

fn read_receipt(
    invocation: &Invocation,
    capability: &Capability,
    desired: &AggregateRequest,
) -> Result<Receipt, KubernetesProviderError> {
    let receipt = read_retained_receipt(invocation, capability)?
        .ok_or_else(|| invalid("Kubernetes object-set receipt is absent"))?;
    let expected_revision = invocation
        .request
        .resources
        .iter()
        .find(|context| context.reference == invocation.request.target)
        .ok_or_else(|| invalid("target context is absent"))?
        .revision
        .0
        .to_string();
    let desired_keys = all_objects(desired)
        .map(|object| object.key.as_str())
        .collect::<BTreeSet<_>>();
    let retained_keys = receipt
        .objects
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if receipt.revision != expected_revision || retained_keys != desired_keys {
        return Err(invalid(
            "Kubernetes receipt differs from the exact retained object set",
        ));
    }
    for object in all_objects(desired) {
        let retained = receipt
            .objects
            .get(&object.key)
            .ok_or_else(|| invalid("Kubernetes receipt omitted a desired object"))?;
        if !retained.matches(object)
            || retained.revision != desired_revision(object).to_string()
            || retained.uid.is_empty()
            || retained.resource_version.is_empty()
        {
            return Err(invalid(
                "Kubernetes receipt object identity or revision is invalid",
            ));
        }
    }
    Ok(receipt)
}

fn read_retained_receipt(
    invocation: &Invocation,
    capability: &Capability,
) -> Result<Option<Receipt>, KubernetesProviderError> {
    let bytes = match read_bounded(
        &receipt_path(invocation)?,
        ABILITY_LIMITS_V1.max_document_bytes,
    ) {
        Ok(bytes) => bytes,
        Err(KubernetesProviderError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let receipt: Receipt = serde_json::from_slice(&bytes)?;
    let identities = receipt
        .objects
        .values()
        .map(ObjectReceipt::identity)
        .collect::<BTreeSet<_>>();
    let valid_objects = receipt.objects.values().all(|object| {
        !object.api_version.is_empty()
            && !object.kind.is_empty()
            && !object.name.is_empty()
            && !object.uid.is_empty()
            && !object.resource_version.is_empty()
            && Sha256Digest::parse(&object.revision).is_ok()
    });
    if receipt.schema != RECEIPT_SCHEMA
        || Sha256Digest::parse(&receipt.revision).is_err()
        || receipt.cluster_incarnation != capability.cluster_incarnation
        || receipt.kubeconfig_digest != capability.kubeconfig_digest
        || identities.len() != receipt.objects.len()
        || !valid_objects
    {
        return Err(invalid(
            "Kubernetes receipt differs from the retained provider context",
        ));
    }
    Ok(Some(receipt))
}

impl ObjectReceipt {
    fn identity(&self) -> (&str, &str, Option<&str>, &str) {
        (
            self.api_version.as_str(),
            self.kind.as_str(),
            self.namespace.as_deref(),
            self.name.as_str(),
        )
    }

    fn matches(&self, object: &KubernetesObject) -> bool {
        self.identity()
            == (
                object.api_version.as_str(),
                object.kind.as_str(),
                object.namespace.as_deref(),
                object.name.as_str(),
            )
    }

    fn as_object(&self, key: &str) -> KubernetesObject {
        KubernetesObject {
            key: key.to_owned(),
            api_version: self.api_version.clone(),
            kind: self.kind.clone(),
            namespace: self.namespace.clone(),
            name: self.name.clone(),
            content: String::new(),
        }
    }
}

fn remove_receipt(invocation: &Invocation) -> Result<(), KubernetesProviderError> {
    match fs::remove_file(receipt_path(invocation)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), KubernetesProviderError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("receipt path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn canonical_owner(reference: &ResourceReference) -> Result<String, KubernetesProviderError> {
    Sha256Digest::of_canonical("aos.kubernetes.object-set-owner/v1", &reference.resource)
        .map(|digest| digest.to_string())
        .map_err(|error| invalid(error.to_string()))
}

pub(crate) fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, KubernetesProviderError> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("file exceeds its declared byte bound"));
    }
    Ok(bytes)
}

fn required_string(value: &Value, path: &[&str]) -> Result<String, KubernetesProviderError> {
    let mut current = value;
    for component in path {
        current = current
            .get(*component)
            .ok_or_else(|| invalid("Kubernetes response omitted a required field"))?;
    }
    current
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid("Kubernetes response field is not a nonempty string"))
}

pub(crate) fn decode<T: for<'de> Deserialize<'de>>(
    value: &AbilityValue,
) -> Result<T, KubernetesProviderError> {
    Ok(serde_json::from_value(value.as_json().clone())?)
}

pub(crate) fn ability_value(value: Value) -> Result<AbilityValue, KubernetesProviderError> {
    AbilityValue::new(value).map_err(|error| invalid(error.to_string()))
}

pub(crate) fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> KubernetesProviderError {
    KubernetesProviderError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> KubernetesObject {
        KubernetesObject {
            key: "gateway".into(),
            api_version: "v1".into(),
            kind: "ConfigMap".into(),
            namespace: Some("default".into()),
            name: "gateway".into(),
            content: r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"gateway","namespace":"default"},"spec":{}}"#.into(),
        }
    }

    #[test]
    fn handler_accepts_only_object_methods_with_exact_semantics() {
        let apply = MethodSemantics::ordinary(AccessMode::ExclusiveWrite);

        assert!(validate_method("apply", &apply).is_ok());
        assert!(validate_method("unknown", &apply).is_err());
        assert_eq!(
            HandlerRole::from_entry_point(OsStr::new("aos-kubernetes-object-effects"))
                .expect("object role parses"),
            HandlerRole::ObjectSet,
        );
        assert_eq!(
            HandlerRole::from_entry_point(OsStr::new("aos-k3s-configuration-effects"))
                .expect("configuration role parses"),
            HandlerRole::Configuration,
        );
        assert!(HandlerRole::from_entry_point(OsStr::new("aos-kubernetes-provider")).is_err());
    }

    #[test]
    fn object_identity_and_canonical_content_are_checked_together() {
        let desired = AggregateRequest {
            cluster: ClusterRequest {
                prerequisites: vec![],
            },
            contributions: BTreeMap::from([(
                "gateway".into(),
                ContributionRequest {
                    objects: vec![object()],
                    prerequisites: vec![],
                },
            )]),
        };

        assert!(validate_desired(&desired).is_ok());

        let mut reserved = desired.clone();
        reserved.contributions.get_mut("gateway").unwrap().objects[0].content = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"annotations":{"aos.andyl.com/object-set-owner":"forged"},"name":"gateway","namespace":"default"},"spec":{}}"#.into();
        assert!(validate_desired(&reserved).is_err());

        let mut changed = desired;
        changed.contributions.get_mut("gateway").unwrap().objects[0].name = "other".into();
        assert!(validate_desired(&changed).is_err());
    }

    #[test]
    fn desired_document_adds_only_provider_annotations() {
        let document = desired_document(&object(), "owner").expect("object renders");
        let parsed: Value = serde_json::from_slice(&document).expect("object parses");

        assert_eq!(parsed["metadata"]["annotations"][OWNER_ANNOTATION], "owner");
        assert_eq!(
            parsed["metadata"]["annotations"][REVISION_ANNOTATION],
            desired_revision(&object()).to_string()
        );
    }

    #[test]
    fn delete_options_bind_uid_and_resource_version() {
        let live = LiveObject {
            api_version: "v1".into(),
            kind: "ConfigMap".into(),
            metadata: LiveMetadata {
                name: "gateway".into(),
                namespace: Some("default".into()),
                uid: "uid-123".into(),
                resource_version: "456".into(),
                annotations: BTreeMap::new(),
            },
        };

        let options = delete_options(&live).expect("delete options render");
        let options: Value = serde_json::from_slice(&options).expect("delete options parse");

        assert_eq!(options["preconditions"]["uid"], "uid-123");
        assert_eq!(options["preconditions"]["resourceVersion"], "456");
        assert_eq!(options["propagationPolicy"], "Foreground");
    }

    #[test]
    fn retained_identity_distinguishes_removed_objects_from_updated_content() {
        let object = object();
        let retained = ObjectReceipt {
            api_version: object.api_version.clone(),
            kind: object.kind.clone(),
            namespace: object.namespace.clone(),
            name: object.name.clone(),
            uid: "uid-123".into(),
            resource_version: "456".into(),
            revision: desired_revision(&object).to_string(),
        };

        assert!(retained.matches(&object));

        let mut updated_content = object.clone();
        updated_content.content = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"gateway","namespace":"default"},"spec":{"updated":true}}"#.into();
        assert!(retained.matches(&updated_content));

        let mut replacement = object;
        replacement.name = "replacement".into();
        assert!(!retained.matches(&replacement));
    }
}
