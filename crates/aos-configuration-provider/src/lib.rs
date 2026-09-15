//! Provider-owned runtime for typed configuration materialization.
//!
//! The provider writes one resource-owned file from checked inline, artifact,
//! structured, or interpolated input. Credential fragments are accepted only
//! when their reference and path match one acquired resource context. Secret
//! bytes never enter observations, outputs, or durable provider state.

#![forbid(unsafe_code)]

pub mod structured;

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, AccessMode, ArtifactReference, LocalKey, MethodSemantics,
    ResourceId, ResourceReference, RevisionId,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, native_context_digest, resource_set_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::structured::{DocumentNode, StructuredFormat, encode_structured_document};

const INTERFACE_NAME: &str = "aos.configuration.materialization";
const OBSERVATION_SCHEMA: &str = "aos.ability.configuration-materialization-observation/v1";
const PROVIDER_CONTEXT_SCHEMA: &str = "aos.configuration.materializer-context/v1";
const REALIZATION_SCHEMA: &str = "aos.configuration.materializer-realization/v1";
const MARKER_SCHEMA: &str = "aos.configuration.materializer-state/v1";
const MATERIALIZER_VERSION: &str = "aos-configuration-provider/1";
const CONFIGURATION_ROOT: &str = "/run/aos/configurations";

/// Reports malformed requests, unauthorized inputs, and materialization failures.
#[derive(Debug, Error)]
pub enum ConfigurationProviderError {
    /// The checked request does not match the provider's closed contract.
    #[error("invalid configuration materialization request: {0}")]
    Invalid(String),
    /// The requested filesystem operation failed.
    #[error("configuration materialization failed: {0}")]
    Io(#[from] io::Error),
    /// A structured source could not be encoded.
    #[error(transparent)]
    Structured(#[from] structured::StructuredDocumentError),
    /// A protocol document could not be decoded or encoded.
    #[error("configuration provider protocol error: {0}")]
    Protocol(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationRequest {
    name: String,
    source: ConfigurationSource,
    mode: String,
    owner: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ConfigurationSource {
    ArtifactFile {
        reference: ArtifactFileReference,
    },
    InlineText {
        content: String,
    },
    InterpolatedText {
        fragments: Vec<InterpolatedFragment>,
        maximum_size_bytes: u64,
    },
    StructuredValue {
        format: StructuredFormat,
        document: Vec<DocumentNode>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFileReference {
    artifact: ArtifactReference,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum InterpolatedFragment {
    Literal {
        text: String,
    },
    ArtifactPath {
        reference: ArtifactFileReference,
    },
    ExecutionPath {
        value: String,
    },
    CredentialContent {
        resource: ResourceReference,
        path: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationRealization {
    schema: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterializationMarker {
    schema: String,
    provider_version: String,
    input_digest: Sha256Digest,
    resource_revisions: Vec<ResourceRevisionBinding>,
    content_digest: Sha256Digest,
    mode: u32,
    owner: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceRevisionBinding {
    resource: ResourceId,
    revision: RevisionId,
}

/// Runs one selected handler invocation from the process arguments and streams.
///
/// # Errors
///
/// Returns an error when the ABI selector, purpose, input, or provider result is
/// invalid, or when the requested filesystem operation fails.
pub fn run_from_process() -> Result<(), ConfigurationProviderError> {
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
        "admit" => serde_json::to_vec(&admit(serde_json::from_slice(&input)?)?)?,
        "effect" | "reconcile" | "cancel" => {
            let invocation = serde_json::from_slice(&input)?;
            serde_json::to_vec(&invoke(invocation, &arguments[1])?)?
        }
        _ => return Err(invalid("unsupported provider purpose")),
    };
    io::stdout().write_all(&output)?;
    Ok(())
}

fn admit(request: AdmissionRequest) -> Result<AdmissionResult, ConfigurationProviderError> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        return Err(invalid("admission schema differs from the selected ABI"));
    }
    validate_method(
        request.method.interface.name.as_str(),
        request.method.method.as_str(),
        &request.semantics,
    )?;
    validate_resource_contexts(&request.resources)?;

    let desired: ConfigurationRequest = decode_value(&request.resource_spec.value)?;
    let realization: ConfigurationRealization = decode_value(&request.resource_spec.realization)?;
    validate_request(&desired)?;
    validate_realization(&request.resource_spec.resource, &realization)?;

    let marker = read_marker(&marker_path(Path::new(&realization.path)))?;
    let expected_digest = input_digest(&desired)?;
    let expected_mode = parse_mode(&desired.mode)?;
    let present = match marker.as_ref() {
        Some(marker)
            if marker.schema == MARKER_SCHEMA
                && marker.provider_version == MATERIALIZER_VERSION
                && marker.input_digest == expected_digest
                && marker.mode == expected_mode =>
        {
            file_matches(Path::new(&realization.path), marker)?
        }
        _ => false,
    };
    let observation = observation(
        &desired,
        present.then(|| realization.path.clone()),
        if present { "materialized" } else { "absent" },
    )?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision: if present {
            AdmissionRevision::Present {
                revision: request.resource_spec.revision,
            }
        } else {
            AdmissionRevision::Absent
        },
        incarnation: None,
        observation,
        native_context: ability_value(serde_json::json!({
            "schema": PROVIDER_CONTEXT_SCHEMA,
            "path": realization.path,
        }))?,
        supported_purposes: SupportedPurposes::from_ordered(vec![
            InvocationPurpose::Effect,
            InvocationPurpose::Reconcile,
            InvocationPurpose::Cancel,
        ])
        .ok_or_else(|| invalid("configuration purpose support is not canonical"))?,
    })
}

fn invoke(
    invocation: Invocation,
    purpose: &str,
) -> Result<InvocationResult, ConfigurationProviderError> {
    if invocation.schema != INVOCATION_SCHEMA || purpose != purpose_name(invocation.purpose) {
        return Err(invalid("invocation envelope differs from the selected ABI"));
    }
    if !invocation.method_is_bound() {
        return Err(invalid(
            "invocation method is not bound to the durable recovery contract",
        ));
    }
    validate_resource_contexts(&invocation.request.resources)?;
    let resources_digest = resource_set_digest(&invocation.request.resources)
        .map_err(|error| invalid(error.to_string()))?;
    if resources_digest != invocation.request.native_context_digest {
        return Err(invalid(
            "resource contexts differ from their authenticated set digest",
        ));
    }
    validate_method(
        invocation.method.interface.name.as_str(),
        invocation.method.method.as_str(),
        &invocation.semantics,
    )?;
    let desired: ConfigurationRequest = decode_value(&invocation.request.inputs)?;
    validate_request(&desired)?;
    if invocation.control.cancelled {
        return result(
            &invocation,
            &desired,
            None,
            InvocationDisposition::RejectedBeforeEffect,
            false,
        );
    }

    let output_path = materialized_path(&invocation.request.target.resource)?;
    match invocation.purpose {
        InvocationPurpose::Effect if invocation.method.method.as_str() == "materialize" => {
            let (content, resource_revisions) = render(&desired, &invocation.request.resources)?;
            materialize(&output_path, &desired, &content, resource_revisions)?;
            result(
                &invocation,
                &desired,
                Some(&output_path),
                InvocationDisposition::Completed,
                true,
            )
        }
        InvocationPurpose::Effect => {
            let present = observed_current(&output_path, &desired)?;
            result(
                &invocation,
                &desired,
                present.then_some(output_path.as_path()),
                InvocationDisposition::Completed,
                false,
            )
        }
        InvocationPurpose::Reconcile => {
            let present = observed_current(&output_path, &desired)?;
            result(
                &invocation,
                &desired,
                present.then_some(output_path.as_path()),
                if present {
                    InvocationDisposition::Completed
                } else {
                    InvocationDisposition::SafeToRetry
                },
                present && invocation.request.method.method.as_str() == "materialize",
            )
        }
        InvocationPurpose::Cancel => result(
            &invocation,
            &desired,
            None,
            InvocationDisposition::RejectedBeforeEffect,
            false,
        ),
        InvocationPurpose::Compensate | InvocationPurpose::ReconcileCompensation => Err(invalid(
            "configuration materialization has no compensation method",
        )),
    }
}

fn validate_method(
    interface: &str,
    method: &str,
    semantics: &MethodSemantics,
) -> Result<(), ConfigurationProviderError> {
    if interface != INTERFACE_NAME || !matches!(method, "materialize" | "observe") {
        return Err(invalid(
            "method does not belong to configuration materialization",
        ));
    }
    let access = if method == "materialize" {
        AccessMode::ExclusiveWrite
    } else {
        AccessMode::Read
    };
    if *semantics != MethodSemantics::ordinary(access) {
        return Err(invalid(
            "method semantics differ from configuration materialization",
        ));
    }
    Ok(())
}

fn validate_resource_contexts(
    resources: &[ResourceContext],
) -> Result<(), ConfigurationProviderError> {
    for context in resources {
        let digest = native_context_digest(&context.native_context)
            .map_err(|error| invalid(error.to_string()))?;
        if digest != context.native_context_digest {
            return Err(invalid(
                "resource native context differs from its authenticated digest",
            ));
        }
    }
    Ok(())
}

fn validate_request(request: &ConfigurationRequest) -> Result<(), ConfigurationProviderError> {
    if request.name.is_empty()
        || request.name.len() > 128
        || !request
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid(
            "configuration name is outside the local-key contract",
        ));
    }

    let mode = parse_mode(&request.mode)?;
    if let ConfigurationSource::InterpolatedText {
        fragments,
        maximum_size_bytes,
    } = &request.source
    {
        if *maximum_size_bytes == 0
            || *maximum_size_bytes > ABILITY_LIMITS_V1.max_document_bytes
            || fragments.len() as u64 > ABILITY_LIMITS_V1.max_collection_items
        {
            return Err(invalid("interpolated source exceeds the canonical bounds"));
        }
        let contains_credential = fragments
            .iter()
            .any(|fragment| matches!(fragment, InterpolatedFragment::CredentialContent { .. }));
        if contains_credential && !matches!(mode, 0o400 | 0o600) {
            return Err(invalid(
                "credential content requires owner-only output mode",
            ));
        }
    }
    Ok(())
}

fn validate_realization(
    resource: &ResourceId,
    realization: &ConfigurationRealization,
) -> Result<(), ConfigurationProviderError> {
    if realization.schema != REALIZATION_SCHEMA
        || realization.path != path_text(&materialized_path(resource)?)?
    {
        return Err(invalid(
            "provider realization differs from the resource identity",
        ));
    }
    Ok(())
}

fn render(
    request: &ConfigurationRequest,
    contexts: &[ResourceContext],
) -> Result<(Vec<u8>, BTreeMap<ResourceId, RevisionId>), ConfigurationProviderError> {
    let mut revisions = BTreeMap::new();
    let bytes = match &request.source {
        ConfigurationSource::InlineText { content } => content.as_bytes().to_vec(),
        ConfigurationSource::ArtifactFile { reference } => read_artifact_file(reference)?,
        ConfigurationSource::StructuredValue { format, document } => {
            encode_structured_document(*format, document.clone())?
        }
        ConfigurationSource::InterpolatedText {
            fragments,
            maximum_size_bytes,
        } => render_fragments(fragments, *maximum_size_bytes, contexts, &mut revisions)?,
    };
    if bytes.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
        return Err(invalid(
            "materialized content exceeds the canonical document bound",
        ));
    }
    Ok((bytes, revisions))
}

fn render_fragments(
    fragments: &[InterpolatedFragment],
    maximum_size_bytes: u64,
    contexts: &[ResourceContext],
    revisions: &mut BTreeMap<ResourceId, RevisionId>,
) -> Result<Vec<u8>, ConfigurationProviderError> {
    let mut output = Vec::new();
    for fragment in fragments {
        match fragment {
            InterpolatedFragment::Literal { text } => {
                append_bounded(&mut output, text.as_bytes(), maximum_size_bytes)?;
            }
            InterpolatedFragment::ArtifactPath { reference } => {
                let path = validated_artifact_file_path(reference)?;
                append_bounded(
                    &mut output,
                    path_text(&path)?.as_bytes(),
                    maximum_size_bytes,
                )?;
            }
            InterpolatedFragment::ExecutionPath { value } => {
                append_bounded(&mut output, value.as_bytes(), maximum_size_bytes)?;
            }
            InterpolatedFragment::CredentialContent { resource, path } => {
                if !resource
                    .operations
                    .iter()
                    .any(|operation| operation.as_str() == "observe")
                {
                    return Err(invalid(
                        "credential reference does not grant read observation",
                    ));
                }
                let context = contexts
                    .iter()
                    .find(|context| context.reference == *resource)
                    .ok_or_else(|| invalid("credential reference has no exact runtime context"))?;
                let observed_path = context
                    .observation
                    .as_json()
                    .get("realized")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| invalid("credential context has no realized path"))?;
                if observed_path != path {
                    return Err(invalid("credential path differs from its resource context"));
                }

                let bytes = read_protected(Path::new(path))?;
                append_bounded(&mut output, &bytes, maximum_size_bytes)?;
                revisions.insert(resource.resource.clone(), context.revision);
            }
        }
    }
    Ok(output)
}

fn append_bounded(
    output: &mut Vec<u8>,
    bytes: &[u8],
    maximum_size_bytes: u64,
) -> Result<(), ConfigurationProviderError> {
    let size = output
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| invalid("interpolated output size overflow"))?;
    if size as u64 > maximum_size_bytes {
        return Err(invalid(
            "interpolated output exceeds its declared byte bound",
        ));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_artifact_file(
    reference: &ArtifactFileReference,
) -> Result<Vec<u8>, ConfigurationProviderError> {
    let path = validated_artifact_file_path(reference)?;
    read_bounded(&path, ABILITY_LIMITS_V1.max_document_bytes)
}

fn validated_artifact_file_path(
    reference: &ArtifactFileReference,
) -> Result<PathBuf, ConfigurationProviderError> {
    let relative = Path::new(&reference.path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid("artifact file path is not a strict relative path"));
    }
    let root = fs::canonicalize(&reference.artifact.store_path)?;
    let path = fs::canonicalize(root.join(relative))?;
    if !path.starts_with(&root) || !fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err(invalid("artifact file escapes its authenticated artifact"));
    }
    Ok(path)
}

fn read_protected(path: &Path) -> Result<Vec<u8>, ConfigurationProviderError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid("credential path is not an owner-only regular file"));
    }
    read_bounded(path, ABILITY_LIMITS_V1.max_document_bytes)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, ConfigurationProviderError> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("source file exceeds its declared byte bound"));
    }
    Ok(bytes)
}

fn materialize(
    path: &Path,
    request: &ConfigurationRequest,
    content: &[u8],
    resource_revisions: BTreeMap<ResourceId, RevisionId>,
) -> Result<(), ConfigurationProviderError> {
    let mode = parse_mode(&request.mode)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("configuration path has no parent"))?;
    fs::create_dir_all(parent)?;
    atomic_write(path, content, mode, request.owner.as_deref())?;

    let marker = MaterializationMarker {
        schema: MARKER_SCHEMA.into(),
        provider_version: MATERIALIZER_VERSION.into(),
        input_digest: input_digest(request)?,
        resource_revisions: resource_revisions
            .into_iter()
            .map(|(resource, revision)| ResourceRevisionBinding { resource, revision })
            .collect(),
        content_digest: Sha256Digest::of_bytes(content),
        mode,
        owner: request.owner.clone(),
    };
    let marker_bytes =
        aos_contract::canonical::to_vec(&marker).map_err(|error| invalid(error.to_string()))?;
    atomic_write(&marker_path(path), &marker_bytes, 0o600, None)?;
    Ok(())
}

fn atomic_write(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<&str>,
) -> Result<(), ConfigurationProviderError> {
    let temporary = path.with_extension("aos-new");
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(&temporary)?,
        Ok(_) => {
            return Err(invalid(
                "temporary materialization path is not a regular file",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
    if let Some(owner) = owner {
        rustix::fs::chown(&temporary, Some(resolve_uid(owner)?), None).map_err(io::Error::from)?;
    }
    fs::rename(&temporary, path)?;
    Ok(())
}

fn observed_current(
    path: &Path,
    request: &ConfigurationRequest,
) -> Result<bool, ConfigurationProviderError> {
    let Some(marker) = read_marker(&marker_path(path))? else {
        return Ok(false);
    };
    Ok(marker.schema == MARKER_SCHEMA
        && marker.provider_version == MATERIALIZER_VERSION
        && marker.input_digest == input_digest(request)?
        && marker.mode == parse_mode(&request.mode)?
        && file_matches(path, &marker)?)
}

fn file_matches(
    path: &Path,
    marker: &MaterializationMarker,
) -> Result<bool, ConfigurationProviderError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o7777 != marker.mode {
        return Ok(false);
    }
    if let Some(owner) = &marker.owner
        && metadata.uid() != resolve_uid(owner)?.as_raw()
    {
        return Ok(false);
    }
    let bytes = read_bounded(path, ABILITY_LIMITS_V1.max_document_bytes)?;
    Ok(Sha256Digest::of_bytes(&bytes) == marker.content_digest)
}

fn read_marker(path: &Path) -> Result<Option<MaterializationMarker>, ConfigurationProviderError> {
    let bytes = match read_bounded(path, ABILITY_LIMITS_V1.max_document_bytes) {
        Ok(bytes) => bytes,
        Err(ConfigurationProviderError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn materialized_path(resource: &ResourceId) -> Result<PathBuf, ConfigurationProviderError> {
    let encoded =
        aos_contract::canonical::to_vec(resource).map_err(|error| invalid(error.to_string()))?;
    let digest = Sha256::digest(encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(Path::new(CONFIGURATION_ROOT).join(format!("{}-{digest}", resource.key)))
}

fn marker_path(path: &Path) -> PathBuf {
    path.with_extension("aos-state.json")
}

fn input_digest(
    request: &ConfigurationRequest,
) -> Result<Sha256Digest, ConfigurationProviderError> {
    Sha256Digest::of_canonical("aos.configuration.materializer-input/v1", request)
        .map_err(|error| invalid(error.to_string()))
}

fn parse_mode(value: &str) -> Result<u32, ConfigurationProviderError> {
    let mode =
        u32::from_str_radix(value, 8).map_err(|_| invalid("configuration mode is not octal"))?;
    if value.len() != 4 || mode > 0o7777 {
        return Err(invalid(
            "configuration mode is outside the file-mode contract",
        ));
    }
    Ok(mode)
}

fn resolve_uid(owner: &str) -> Result<rustix::process::Uid, ConfigurationProviderError> {
    let passwd = read_bounded(Path::new("/etc/passwd"), 1024 * 1024)?;
    let passwd =
        std::str::from_utf8(&passwd).map_err(|_| invalid("passwd database is not UTF-8"))?;
    for line in passwd.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() == 7 && fields[0] == owner {
            let uid = fields[2]
                .parse::<u32>()
                .map_err(|_| invalid("principal has an invalid numeric identity"))?;
            return Ok(rustix::process::Uid::from_raw(uid));
        }
    }
    Err(invalid(
        "declared principal is absent from the identity database",
    ))
}

fn observation(
    expected: &ConfigurationRequest,
    materialized: Option<String>,
    state: &str,
) -> Result<AbilityValue, ConfigurationProviderError> {
    let mut value = serde_json::json!({
        "schema": OBSERVATION_SCHEMA,
        "expected": expected,
        "state": state,
    });
    if let Some(path) = materialized {
        value
            .as_object_mut()
            .ok_or_else(|| invalid("observation is not an object"))?
            .insert("materialized".into(), serde_json::Value::String(path));
    }
    ability_value(value)
}

fn result(
    invocation: &Invocation,
    desired: &ConfigurationRequest,
    path: Option<&Path>,
    disposition: InvocationDisposition,
    include_outputs: bool,
) -> Result<InvocationResult, ConfigurationProviderError> {
    let path = path.map(path_text).transpose()?;
    let state = if path.is_some() {
        "materialized"
    } else {
        "absent"
    };
    let mut outputs = BTreeMap::new();
    if include_outputs {
        let execution_path = path
            .clone()
            .ok_or_else(|| invalid("completed materialization has no output path"))?;
        outputs.insert(
            LocalKey::new("execution-path").map_err(|error| invalid(error.to_string()))?,
            ability_value(serde_json::Value::String(execution_path))?,
        );
        outputs.insert(
            LocalKey::new("retained-resource").map_err(|error| invalid(error.to_string()))?,
            ability_value(serde_json::to_value(&invocation.request.target)?)?,
        );
    }
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition,
        evidence: observation(desired, path, state)?,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn decode_value<T: for<'de> Deserialize<'de>>(
    value: &AbilityValue,
) -> Result<T, ConfigurationProviderError> {
    Ok(serde_json::from_value(value.as_json().clone())?)
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue, ConfigurationProviderError> {
    AbilityValue::new(value).map_err(|error| invalid(error.to_string()))
}

fn path_text(path: &Path) -> Result<String, ConfigurationProviderError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("provider path is not UTF-8"))
}

fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}

fn invalid(message: impl Into<String>) -> ConfigurationProviderError {
    ConfigurationProviderError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Sha256Digest {
        serde_json::from_value(serde_json::json!(format!(
            "sha256:{}",
            byte.to_string().repeat(64)
        )))
        .expect("digest fixture is valid")
    }

    fn resource_reference() -> ResourceReference {
        serde_json::from_value(serde_json::json!({
            "interface": {
                "name": "aos.credential.delivery",
                "abi": 1,
                "descriptor": format!("sha256:{}", "1".repeat(64)),
            },
            "resource": {
                "provider": {
                    "environment": {
                        "authority": "test",
                        "key": "host",
                        "stage": "host",
                    },
                    "key": "credentials",
                },
                "key": "root-password",
            },
            "operations": ["observe"],
            "lifetime": "instance",
        }))
        .expect("resource-reference fixture is valid")
    }

    fn context(reference: ResourceReference, path: &Path) -> ResourceContext {
        ResourceContext {
            reference,
            revision: RevisionId(digest('2')),
            observation: ability_value(serde_json::json!({
                "schema": "aos.ability.credential-delivery-observation/v1",
                "expected": {
                    "name": "root-password",
                    "source": null,
                    "encrypted": false,
                },
                "realized": path,
                "state": "ready",
            }))
            .expect("observation fixture is bounded"),
            native_context: ability_value(serde_json::json!({"fixture": true}))
                .expect("native context fixture is bounded"),
            native_context_digest: digest('3'),
        }
    }

    #[test]
    fn artifact_path_fragment_emits_only_a_contained_regular_file() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let schemas = directory.path().join("schemas");
        fs::create_dir(&schemas).expect("schema directory is created");
        let schema = schemas.join("core.schema");
        fs::write(&schema, "objectclass ( 1.2.3 )\n").expect("schema file is written");
        let reference = ArtifactReference {
            content: digest('4'),
            store_path: path_text(directory.path()).expect("artifact path is UTF-8"),
            nar_hash: digest('5'),
            closure: digest('6'),
        };
        let fragments = vec![InterpolatedFragment::ArtifactPath {
            reference: ArtifactFileReference {
                artifact: reference.clone(),
                path: "schemas/core.schema".into(),
            },
        }];

        let rendered = render_fragments(&fragments, 4096, &[], &mut BTreeMap::new())
            .expect("contained artifact file path renders");
        assert_eq!(
            rendered,
            fs::canonicalize(&schema)
                .expect("schema path canonicalizes")
                .as_os_str()
                .as_encoded_bytes()
        );

        let escaping = vec![InterpolatedFragment::ArtifactPath {
            reference: ArtifactFileReference {
                artifact: reference,
                path: "../outside".into(),
            },
        }];
        assert!(render_fragments(&escaping, 4096, &[], &mut BTreeMap::new()).is_err());
    }

    #[test]
    fn credential_fragment_requires_the_exact_context_path_and_read_operation() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let credential = directory.path().join("credential");
        atomic_write(&credential, b"correct horse", 0o400, None).expect("credential is written");
        let reference = resource_reference();
        let fragments = vec![InterpolatedFragment::CredentialContent {
            resource: reference.clone(),
            path: path_text(&credential).expect("credential path is UTF-8"),
        }];
        let mut revisions = BTreeMap::new();

        assert_eq!(
            render_fragments(
                &fragments,
                1024,
                &[context(reference.clone(), &credential)],
                &mut revisions,
            )
            .expect("matching credential context renders"),
            b"correct horse"
        );
        assert_eq!(
            revisions.get(&reference.resource),
            Some(&RevisionId(digest('2')))
        );

        let other = directory.path().join("other");
        let error = render_fragments(
            &fragments,
            1024,
            &[context(reference.clone(), &other)],
            &mut BTreeMap::new(),
        )
        .expect_err("mismatched context path is rejected");
        assert!(error.to_string().contains("path differs"));

        let mut without_read = reference;
        without_read.operations.clear();
        let error = render_fragments(
            &[InterpolatedFragment::CredentialContent {
                resource: without_read,
                path: path_text(&credential).expect("credential path is UTF-8"),
            }],
            1024,
            &[],
            &mut BTreeMap::new(),
        )
        .expect_err("reference without read observation is rejected");
        assert!(error.to_string().contains("read observation"));
    }

    #[test]
    fn marker_commits_to_secret_content_without_recording_it() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let output = directory.path().join("slapd.conf");
        let request = ConfigurationRequest {
            name: "slapd".into(),
            source: ConfigurationSource::InlineText {
                content: "public template".into(),
            },
            mode: "0600".into(),
            owner: None,
        };
        let reference = resource_reference();
        let revisions = BTreeMap::from([(reference.resource, RevisionId(digest('4')))]);

        materialize(&output, &request, b"rootpw private-value\n", revisions)
            .expect("configuration is materialized");
        assert!(observed_current(&output, &request).expect("configuration can be observed"));

        let marker = fs::read(marker_path(&output)).expect("marker is readable");
        let marker_text = String::from_utf8(marker).expect("marker is UTF-8 JSON");
        assert!(!marker_text.contains("private-value"));
        assert!(marker_text.contains(MATERIALIZER_VERSION));
    }

    #[test]
    fn credential_sources_require_owner_only_modes() {
        let request = ConfigurationRequest {
            name: "protected".into(),
            source: ConfigurationSource::InterpolatedText {
                fragments: vec![InterpolatedFragment::CredentialContent {
                    resource: resource_reference(),
                    path: "/run/credentials/root-password".into(),
                }],
                maximum_size_bytes: 1024,
            },
            mode: "0640".into(),
            owner: None,
        };

        assert!(validate_request(&request).is_err());
    }
}
