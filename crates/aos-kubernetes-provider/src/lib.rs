//! Native module handlers for K3s configuration and Kubernetes object sets.
//!
//! The module runtime supplies fully resolved inputs and retained previous state.
//! Kubernetes mutations retain exact cluster identity and object UID receipts;
//! teardown uses ownership annotations and API preconditions to reject replacements.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

mod configuration;

const MAX_DOCUMENT_BYTES: u64 = 256 * 1024;
const RECEIPT_SCHEMA: &str = "aos.kubernetes.object-set-receipt/v1";
const OWNER_ANNOTATION: &str = "aos.andyl.com/object-set-owner";
const REVISION_ANNOTATION: &str = "aos.andyl.com/object-revision";
const STATE_ROOT: &str = "/var/lib/aos/ability-runtime/kubernetes-object-set";
const MAX_KUBECONFIG_BYTES: u64 = 1024 * 1024;

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
    kubeconfig: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    object_sets: BTreeMap<String, ObjectSetRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectSetRequest {
    objects: Vec<KubernetesObject>,
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
    #[serde(skip)]
    document: Value,
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
    schema: &'a str,
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

/// Executes one native `apply`, `remove`, or `observe` invocation.
///
/// # Errors
/// Returns an error for invalid input, ownership conflicts, unavailable cluster
/// operations, or failed durable receipt writes.
pub fn run_from_process() -> Result<(), KubernetesProviderError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [operation] = arguments.as_slice() else {
        return Err(invalid("expected one apply, remove, or observe argument"));
    };
    if !matches!(operation.as_str(), "apply" | "remove" | "observe") {
        return Err(invalid("unsupported module handler operation"));
    }

    let mut input = Vec::new();
    io::stdin()
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(invalid("module invocation exceeds its byte bound"));
    }
    let invocation: Invocation = serde_json::from_slice(&input)?;
    let output = match invocation
        .effect
        .identity
        .iter()
        .rev()
        .nth(2)
        .map(String::as_str)
        .unwrap_or("")
    {
        "kubernetes" => invoke(&invocation, operation)?,
        "k3sConfiguration" => configuration::invoke(&invocation, operation)?,
        _ => return Err(invalid("unknown Kubernetes operation ability")),
    };
    io::stdout().write_all(&serde_json::to_vec(&output)?)?;
    Ok(())
}

fn invoke(invocation: &Invocation, operation: &str) -> Result<Value, KubernetesProviderError> {
    let desired: AggregateRequest = serde_json::from_value(invocation.input.clone())?;
    validate_desired(&desired)?;
    if !Path::new(&desired.kubeconfig).is_absolute() {
        return Err(invalid("kubeconfig must have an absolute path"));
    }
    let capability = Capability::acquire(&desired.kubeconfig, invocation.effect.timeout_ms)?;
    let owner = Sha256Digest::of_bytes(invocation.id.as_bytes()).to_string();
    validate_intent(invocation, &capability)?;
    let receipt = read_retained_receipt(invocation, &capability)?;
    let observation = observe("aos.kubernetes.objects/v1", &capability, &desired, &owner)?;

    if operation == "observe" {
        let status = if observation
            .objects
            .values()
            .any(|object| object.state == "foreign")
        {
            "indeterminate"
        } else if invocation.action == Action::Remove
            && (observation.state == "absent" || observation.objects.is_empty())
        {
            "absent"
        } else if invocation.action == Action::Apply
            && observation.state == "current"
            && receipt
                .as_ref()
                .is_some_and(|receipt| receipt.revision == invocation.revision)
        {
            return Ok(serde_json::json!({"status":"current", "outputs": outputs(&capability)}));
        } else {
            "retry-safe"
        };
        return Ok(serde_json::json!({"status":status}));
    }

    if operation == "apply" {
        // Establish writable durable state before changing the remote cluster.
        let intent_path = receipt_path(invocation)?.with_extension("intent.json");
        atomic_write(
            &intent_path,
            &aos_contract::canonical::to_vec(&serde_json::json!({
                "revision":invocation.revision,
                "cluster":capability.cluster_incarnation,
                "kubeconfig_digest":capability.kubeconfig_digest,
            }))
            .map_err(|error| invalid(error.to_string()))?,
        )?;
        apply(
            "aos.kubernetes.objects/v1",
            &capability,
            &desired,
            &owner,
            receipt.as_ref(),
        )?;
        write_receipt(
            "aos.kubernetes.objects/v1",
            invocation,
            &capability,
            &desired,
            &owner,
        )?;
        return Ok(outputs(&capability));
    }
    if observation.state != "absent" && !observation.objects.is_empty() {
        let receipt = read_receipt(invocation, &capability, &desired)?;
        release(
            "aos.kubernetes.objects/v1",
            &capability,
            &desired,
            &owner,
            &receipt,
        )?;
    }
    remove_receipt(invocation)?;
    let intent_path = receipt_path(invocation)?.with_extension("intent.json");
    match fs::remove_file(intent_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(serde_json::json!({}))
}

fn validate_intent(
    invocation: &Invocation,
    capability: &Capability,
) -> Result<(), KubernetesProviderError> {
    let path = receipt_path(invocation)?.with_extension("intent.json");
    let bytes = match read_bounded(&path, MAX_DOCUMENT_BYTES) {
        Ok(bytes) => bytes,
        Err(KubernetesProviderError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let intent: Value = serde_json::from_slice(&bytes)?;
    if intent.get("cluster").and_then(Value::as_str)
        != Some(capability.cluster_incarnation.as_str())
        || intent.get("kubeconfig_digest")
            != Some(&Value::String(capability.kubeconfig_digest.to_string()))
    {
        return Err(invalid(
            "interrupted Kubernetes mutation belongs to another cluster capability",
        ));
    }
    Ok(())
}

fn outputs(capability: &Capability) -> Value {
    serde_json::json!({"cluster": capability.cluster_incarnation})
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
        kubeconfig_path: &str,
        timeout_millis: u64,
    ) -> Result<Self, KubernetesProviderError> {
        let executable = sibling_executable()?;
        let kubeconfig = PathBuf::from(kubeconfig_path);
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
        if output.stdout.len() as u64 > MAX_DOCUMENT_BYTES {
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
    for object_set in desired.object_sets.values() {
        for object in &object_set.objects {
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

fn all_objects(desired: &AggregateRequest) -> impl Iterator<Item = &KubernetesObject> {
    desired
        .object_sets
        .values()
        .flat_map(|object_set| object_set.objects.iter())
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
    observation_schema: &'a str,
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
                let expected: Value = serde_json::from_str(&object.content)?;
                let current = owned
                    && revision == Some(desired_revision(object))
                    && contains_desired(&live.document, &expected);
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
        schema: observation_schema,
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

// Server defaulting may add fields; every explicitly desired field must still match.
fn contains_desired(observed: &Value, desired: &Value) -> bool {
    match (observed, desired) {
        (Value::Object(observed), Value::Object(desired)) => desired.iter().all(|(name, value)| {
            observed
                .get(name)
                .is_some_and(|observed| contains_desired(observed, value))
        }),
        _ => observed == desired,
    }
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

    let mut live: LiveObject = serde_json::from_slice(&bytes)?;
    live.document = serde_json::from_slice(&bytes)?;
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
    observation_schema: &str,
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
    if observe(observation_schema, capability, desired, owner)?.state != "current" {
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
    observation_schema: &str,
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
    if observe(observation_schema, capability, desired, owner)?.state != "absent" {
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

fn receipt_path(invocation: &Invocation) -> Result<PathBuf, KubernetesProviderError> {
    let digest =
        Sha256Digest::of_canonical("aos.kubernetes.object-set-receipt-path/v1", &invocation.id)
            .map_err(|error| invalid(error.to_string()))?;
    Ok(Path::new(STATE_ROOT).join(format!("{}.json", digest.hex())))
}

fn write_receipt(
    observation_schema: &str,
    invocation: &Invocation,
    capability: &Capability,
    desired: &AggregateRequest,
    owner: &str,
) -> Result<(), KubernetesProviderError> {
    let observation = observe(observation_schema, capability, desired, owner)?;
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
        revision: invocation.revision.clone(),
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
    let expected_revision = invocation.revision.clone();
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
    let bytes = match read_bounded(&receipt_path(invocation)?, MAX_DOCUMENT_BYTES) {
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
    fn object_identity_and_canonical_content_are_checked_together() {
        let desired = AggregateRequest {
            kubeconfig: "/etc/rancher/k3s/k3s.yaml".into(),
            object_sets: BTreeMap::from([(
                "gateway".into(),
                ObjectSetRequest {
                    objects: vec![object()],
                },
            )]),
        };

        assert!(validate_desired(&desired).is_ok());

        let mut reserved = desired.clone();
        let reserved_gateway = reserved.object_sets.get_mut("gateway").unwrap();
        reserved_gateway.objects[0].content = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"annotations":{"aos.andyl.com/object-set-owner":"forged"},"name":"gateway","namespace":"default"},"spec":{}}"#.into();
        assert!(validate_desired(&reserved).is_err());

        let mut changed = desired;
        let changed_gateway = changed.object_sets.get_mut("gateway").unwrap();
        changed_gateway.objects[0].name = "other".into();
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
            document: Value::Null,
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

    #[test]
    fn observation_checks_owned_fields_while_allowing_server_defaults() {
        let desired = serde_json::json!({"spec":{"replicas":2}});
        let observed = serde_json::json!({"spec":{"replicas":2,"defaulted":true},"status":{}});
        assert!(contains_desired(&observed, &desired));

        let drifted = serde_json::json!({"spec":{"replicas":3,"defaulted":true}});
        assert!(!contains_desired(&drifted, &desired));
    }
}
