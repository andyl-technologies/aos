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
    Operation, ResourceId, ResourceReference, RevisionId,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    RootObservationRequest, RootObservationResult, SupportedPurposes, boot_scoped_handler_root,
    resource_set_digest, validate_admission_resource, validate_resource_contexts,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::structured::{DocumentNode, StructuredFormat, encode_structured_document};

const PROVIDER_CONTEXT_SCHEMA: &str = "aos.configuration.materializer-context/v1";
const MARKER_SCHEMA: &str = "aos.configuration.materializer-state/v1";
const MATERIALIZER_VERSION: &str = "aos-configuration-provider/1";
const CONFIGURATION_ROOT: &str = "/run/aos/configurations";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const TERMINAL_HANDLER: &str = "configuration-materialization-terminal";
const TERMINAL_INTERFACE: &str = "aos.configuration.materialization-terminal";
const QUALIFICATION_ADAPTER: &str = "configuration-materialization";
const QUALIFICATION_OBSERVATION_KIND: &str = "filesystem";
const QUALIFICATION_SCOPE: &str = "host-resource";

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
        reference: ArtifactPathReference,
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
struct ArtifactPathReference {
    artifact: ArtifactReference,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum InterpolatedFragment {
    Literal {
        text: String,
    },
    ArtifactFilePath {
        reference: ArtifactPathReference,
    },
    ArtifactDirectoryPath {
        reference: ArtifactPathReference,
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
    #[serde(rename = "schema")]
    _schema: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterializationMarker {
    schema: String,
    provider_version: String,
    resource: ResourceId,
    revision: RevisionId,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationObserverArguments {
    request_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationObserverRequest {
    adapter: LocalKey,
    scope: LocalKey,
    operation: Operation,
}

#[derive(Debug, Serialize)]
struct QualificationObserverResult {
    provider: LocalKey,
    kind: LocalKey,
    scope: LocalKey,
    observation: String,
}

#[derive(Debug, Serialize)]
struct QualificationFilesystemObservation {
    kind: LocalKey,
    resource: ResourceId,
    entries: Vec<QualificationFilesystemEntry>,
}

#[derive(Debug, Serialize)]
struct QualificationFilesystemEntry {
    path: String,
    marker: MaterializationMarker,
    content_digest: Option<Sha256Digest>,
    mode: Option<u32>,
    owner: Option<u32>,
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
        "observe-root" => serde_json::to_vec(&observe_root(&input)?)?,
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

fn observe_root(input: &[u8]) -> Result<RootObservationResult, ConfigurationProviderError> {
    let request: RootObservationRequest =
        aos_contract::canonical::from_slice(input, "configuration root observation request")
            .map_err(|error| invalid(error.to_string()))?;
    let native_boot_id = fs::read_to_string(BOOT_ID_PATH)?;
    observe_root_for_boot(request, native_boot_id.trim())
}

fn observe_root_for_boot(
    request: RootObservationRequest,
    native_boot_id: &str,
) -> Result<RootObservationResult, ConfigurationProviderError> {
    if !request
        .implementation
        .handler
        .as_ref()
        .is_some_and(|handler| handler.as_str() == TERMINAL_HANDLER)
        || request.interface.name.as_str() != TERMINAL_INTERFACE
    {
        return Err(invalid(
            "selected configuration terminal does not match this executable",
        ));
    }
    boot_scoped_handler_root(request, native_boot_id).map_err(|error| invalid(error.to_string()))
}

/// Runs the package-owned, read-only qualification observer.
///
/// The observer reads the exact resource named by a checked operation from the
/// configuration provider's authoritative marker directory. It does not read
/// execution journals and never returns materialized content.
///
/// # Errors
///
/// Returns an error when the request is malformed, addresses another provider,
/// or the provider state cannot be read within the configured bounds.
pub fn run_observer_from_process() -> Result<(), ConfigurationProviderError> {
    let arguments: QualificationObserverArguments = read_bounded_json(io::stdin())?;
    let request_path = Path::new(&arguments.request_path);
    if !request_path.is_absolute()
        || request_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(invalid(
            "qualification observer request path is not absolute and normalized",
        ));
    }

    let request: QualificationObserverRequest = serde_json::from_slice(&read_bounded(
        request_path,
        ABILITY_LIMITS_V1.max_document_bytes,
    )?)?;
    validate_qualification_request(&request)?;
    let observation = qualification_observation(
        Path::new(CONFIGURATION_ROOT),
        &request.operation.target.resource,
    )?;
    let observation = String::from_utf8(
        aos_contract::canonical::to_vec(&observation)
            .map_err(|error| invalid(error.to_string()))?,
    )
    .map_err(|_| invalid("qualification observation is not UTF-8"))?;
    let result = QualificationObserverResult {
        provider: request.adapter,
        kind: local_key(QUALIFICATION_OBSERVATION_KIND)?,
        scope: request.scope,
        observation,
    };
    let bytes =
        aos_contract::canonical::to_vec(&result).map_err(|error| invalid(error.to_string()))?;
    io::stdout().write_all(&bytes)?;
    Ok(())
}

fn read_bounded_json(
    input: impl Read,
) -> Result<QualificationObserverArguments, ConfigurationProviderError> {
    let mut bytes = Vec::new();
    input
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
        return Err(invalid(
            "qualification observer input exceeds the document bound",
        ));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn validate_qualification_request(
    request: &QualificationObserverRequest,
) -> Result<(), ConfigurationProviderError> {
    if request.adapter.as_str() != QUALIFICATION_ADAPTER
        || request.scope.as_str() != QUALIFICATION_SCOPE
        || request.operation.target.interface != request.operation.interface
    {
        return Err(invalid(
            "qualification observer request does not address this provider",
        ));
    }
    Ok(())
}

fn qualification_observation(
    root: &Path,
    resource: &ResourceId,
) -> Result<QualificationFilesystemObservation, ConfigurationProviderError> {
    let mut entries = Vec::new();
    match fs::read_dir(root) {
        Ok(directory) => {
            for (index, entry) in directory
                .take(ABILITY_LIMITS_V1.max_collection_items as usize + 1)
                .enumerate()
            {
                if index as u64 >= ABILITY_LIMITS_V1.max_collection_items {
                    return Err(invalid("configuration marker inventory exceeds its bound"));
                }
                let entry = entry?;
                let path = entry.path();
                if !entry.file_type()?.is_file()
                    || !path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.ends_with(".aos-state.json"))
                {
                    continue;
                }
                let Some(marker) = read_marker(&path)? else {
                    continue;
                };
                if marker.resource != *resource {
                    continue;
                }
                let materialized = materialized_path(&path)?;
                let metadata = fs::symlink_metadata(&materialized).ok();
                let content_digest = match metadata.as_ref() {
                    Some(metadata) if metadata.file_type().is_file() => {
                        Some(Sha256Digest::of_bytes(&read_bounded(
                            &materialized,
                            ABILITY_LIMITS_V1.max_document_bytes,
                        )?))
                    }
                    _ => None,
                };
                entries.push(QualificationFilesystemEntry {
                    path: path_text(&materialized)?,
                    marker,
                    content_digest,
                    mode: metadata
                        .as_ref()
                        .map(|value| value.permissions().mode() & 0o7777),
                    owner: metadata.as_ref().map(MetadataExt::uid),
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if entries.len() > 1 {
        return Err(invalid(
            "configuration resource has multiple authoritative markers",
        ));
    }
    Ok(QualificationFilesystemObservation {
        kind: local_key(QUALIFICATION_OBSERVATION_KIND)?,
        resource: resource.clone(),
        entries,
    })
}

fn materialized_path(marker_path: &Path) -> Result<PathBuf, ConfigurationProviderError> {
    let file_name = marker_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("configuration marker name is not UTF-8"))?;
    let suffix = ".aos-state.json";
    let name = file_name
        .strip_suffix(suffix)
        .ok_or_else(|| invalid("configuration marker has another suffix"))?;
    Ok(marker_path.with_file_name(name))
}

fn local_key(value: &str) -> Result<LocalKey, ConfigurationProviderError> {
    LocalKey::new(value).map_err(|error| invalid(error.to_string()))
}

fn admit(request: AdmissionRequest) -> Result<AdmissionResult, ConfigurationProviderError> {
    if request.schema != ADMISSION_REQUEST_SCHEMA {
        return Err(invalid("admission schema differs from the selected ABI"));
    }
    validate_admission_resource(&request).map_err(|error| invalid(error.to_string()))?;
    validate_method(request.method.method.as_str(), &request.semantics)?;
    validate_resource_contexts(&request.resources).map_err(|error| invalid(error.to_string()))?;
    let observation_schema = request
        .contract
        .observation_discriminator()
        .ok_or_else(|| {
            invalid("selected configuration method has no exact observation discriminator")
        })?;

    let desired: ConfigurationRequest = decode_value(&request.resource_spec.value)?;
    let realization: ConfigurationRealization = decode_value(&request.resource_spec.realization)?;
    validate_request(&desired)?;
    validate_realization(&realization)?;

    let marker = read_marker(&marker_path(Path::new(&realization.path)))?;
    let expected_digest = input_digest(&desired)?;
    let expected_mode = parse_mode(&desired.mode)?;
    let present = match marker.as_ref() {
        Some(marker)
            if marker.schema == MARKER_SCHEMA
                && marker.provider_version == MATERIALIZER_VERSION
                && marker.resource == request.resource_spec.resource
                && marker.revision == request.resource_spec.revision
                && marker.input_digest == expected_digest
                && marker.mode == expected_mode =>
        {
            file_matches(Path::new(&realization.path), marker)?
        }
        _ => false,
    };
    let path_exists = match fs::symlink_metadata(&realization.path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !present && (marker.is_some() || path_exists) {
        return Ok(AdmissionResult {
            schema: ADMISSION_SCHEMA.into(),
            disposition: AdmissionDisposition::Rejected,
            revision: AdmissionRevision::Unknown,
            incarnation: None,
            observation: observation(observation_schema, &desired, None, "unknown")?,
            native_context: ability_value(serde_json::json!({"rejected": true}))?,
            supported_purposes: SupportedPurposes::from_ordered(Vec::new())
                .ok_or_else(|| invalid("empty configuration purpose set is not canonical"))?,
        });
    }
    let observation = observation(
        observation_schema,
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
    validate_resource_contexts(&invocation.request.resources)
        .map_err(|error| invalid(error.to_string()))?;
    let resources_digest = resource_set_digest(&invocation.request.resources)
        .map_err(|error| invalid(error.to_string()))?;
    if resources_digest != invocation.request.native_context_digest {
        return Err(invalid(
            "resource contexts differ from their authenticated set digest",
        ));
    }
    validate_method(invocation.method.method.as_str(), &invocation.semantics)?;
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

    let target = invocation
        .request
        .resources
        .iter()
        .find(|context| context.reference == invocation.request.target)
        .ok_or_else(|| invalid("target resource has no exact runtime context"))?;
    let bound = aos_provider_protocol::validate_resource_context(target)
        .map_err(|error| invalid(error.to_string()))?;
    let realization = target_realization(&invocation)?;
    let output_path = PathBuf::from(&realization.path);
    match invocation.purpose {
        InvocationPurpose::Effect if invocation.method.method.as_str() == "release" => {
            release_materialization(
                &output_path,
                &desired,
                &bound.resource_spec.resource,
                bound.resource_spec.revision,
            )?;
            result(
                &invocation,
                &desired,
                None,
                InvocationDisposition::Completed,
                false,
            )
        }
        InvocationPurpose::Effect if invocation.method.method.as_str() == "materialize" => {
            let (content, resource_revisions) = render(&desired, &invocation.request.resources)?;
            materialize(
                &output_path,
                &desired,
                &content,
                resource_revisions,
                bound.resource_spec.resource.clone(),
                bound.resource_spec.revision,
            )?;
            result(
                &invocation,
                &desired,
                Some(&output_path),
                InvocationDisposition::Completed,
                true,
            )
        }
        InvocationPurpose::Effect => {
            let present = observed_current(
                &output_path,
                &desired,
                &bound.resource_spec.resource,
                bound.resource_spec.revision,
            )?;
            result(
                &invocation,
                &desired,
                present.then_some(output_path.as_path()),
                InvocationDisposition::Completed,
                false,
            )
        }
        InvocationPurpose::Reconcile => {
            let present = observed_current(
                &output_path,
                &desired,
                &bound.resource_spec.resource,
                bound.resource_spec.revision,
            )?;
            if invocation.method.method.as_str() == "release" && present {
                release_materialization(
                    &output_path,
                    &desired,
                    &bound.resource_spec.resource,
                    bound.resource_spec.revision,
                )?;
                return result(
                    &invocation,
                    &desired,
                    None,
                    InvocationDisposition::Completed,
                    false,
                );
            }
            result(
                &invocation,
                &desired,
                present.then_some(output_path.as_path()),
                if invocation.method.method.as_str() == "release" || present {
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
    method: &str,
    semantics: &MethodSemantics,
) -> Result<(), ConfigurationProviderError> {
    if !matches!(method, "materialize" | "observe" | "release") {
        return Err(invalid(
            "method does not belong to configuration materialization",
        ));
    }
    let expected = match method {
        "materialize" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "release" => MethodSemantics::provider_stop(),
        _ => return Err(invalid("unsupported configuration method")),
    };
    if *semantics != expected {
        return Err(invalid(
            "method semantics differ from configuration materialization",
        ));
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
    realization: &ConfigurationRealization,
) -> Result<(), ConfigurationProviderError> {
    let path = Path::new(&realization.path);
    if path.parent() != Some(Path::new(CONFIGURATION_ROOT))
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "provider realization is not a direct configuration-root child",
        ));
    }
    Ok(())
}

fn target_realization(
    invocation: &Invocation,
) -> Result<ConfigurationRealization, ConfigurationProviderError> {
    target_realization_from_contexts(
        &invocation.request.target,
        &invocation.request.inputs,
        &invocation.request.resources,
    )
}

fn target_realization_from_contexts(
    target: &ResourceReference,
    inputs: &AbilityValue,
    resources: &[ResourceContext],
) -> Result<ConfigurationRealization, ConfigurationProviderError> {
    let mut matches = resources
        .iter()
        .filter(|context| context.reference == *target);
    let context = matches
        .next()
        .ok_or_else(|| invalid("target resource has no exact runtime context"))?;
    if matches.next().is_some() {
        return Err(invalid(
            "target resource has multiple exact runtime contexts",
        ));
    }
    let native: aos_provider_protocol::BoundNativeContext = decode_value(&context.native_context)?;
    if native.schema != aos_provider_protocol::RESOURCE_CONTEXT_SCHEMA
        || native.resource_spec.resource != target.resource
        || native.resource_spec.value != *inputs
        || native.resource_spec.revision != context.revision
    {
        return Err(invalid(
            "target context differs from the durable checked request",
        ));
    }
    let realization = decode_value(&native.resource_spec.realization)?;
    validate_realization(&realization)?;
    Ok(realization)
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
            InterpolatedFragment::ArtifactFilePath { reference } => {
                let path = validated_artifact_path(reference, ArtifactPathKind::RegularFile)?;
                append_bounded(
                    &mut output,
                    path_text(&path)?.as_bytes(),
                    maximum_size_bytes,
                )?;
            }
            InterpolatedFragment::ArtifactDirectoryPath { reference } => {
                let path = validated_artifact_path(reference, ArtifactPathKind::Directory)?;
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
    reference: &ArtifactPathReference,
) -> Result<Vec<u8>, ConfigurationProviderError> {
    let path = validated_artifact_path(reference, ArtifactPathKind::RegularFile)?;
    read_bounded(&path, ABILITY_LIMITS_V1.max_document_bytes)
}

#[derive(Clone, Copy)]
enum ArtifactPathKind {
    Directory,
    RegularFile,
}

fn validated_artifact_path(
    reference: &ArtifactPathReference,
    expected_kind: ArtifactPathKind,
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
    let file_type = fs::symlink_metadata(&path)?.file_type();
    let kind_matches = match expected_kind {
        ArtifactPathKind::Directory => file_type.is_dir(),
        ArtifactPathKind::RegularFile => file_type.is_file(),
    };
    if !path.starts_with(&root) || !kind_matches {
        return Err(invalid(
            "artifact path escapes its authenticated artifact or has the wrong kind",
        ));
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
    resource: ResourceId,
    revision: RevisionId,
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
        resource,
        revision,
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

fn release_materialization(
    path: &Path,
    request: &ConfigurationRequest,
    resource: &ResourceId,
    revision: RevisionId,
) -> Result<(), ConfigurationProviderError> {
    let marker_path = marker_path(path);
    let Some(marker) = read_marker(&marker_path)? else {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(invalid(
                    "configuration release found an unclaimed materialized path",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    };
    if marker.schema != MARKER_SCHEMA
        || marker.provider_version != MATERIALIZER_VERSION
        || marker.resource != *resource
        || marker.revision != revision
        || marker.input_digest != input_digest(request)?
    {
        return Err(invalid(
            "configuration release claim differs from the checked resource revision",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            if !file_matches(path, &marker)? {
                return Err(invalid(
                    "configuration release content differs from its durable claim",
                ));
            }
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(&marker_path)?;
    sync_parent(path)
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
    sync_parent(path)?;
    Ok(())
}

fn observed_current(
    path: &Path,
    request: &ConfigurationRequest,
    resource: &ResourceId,
    revision: RevisionId,
) -> Result<bool, ConfigurationProviderError> {
    let Some(marker) = read_marker(&marker_path(path))? else {
        return Ok(false);
    };
    Ok(marker.schema == MARKER_SCHEMA
        && marker.provider_version == MATERIALIZER_VERSION
        && marker.resource == *resource
        && marker.revision == revision
        && marker.input_digest == input_digest(request)?
        && marker.mode == parse_mode(&request.mode)?
        && file_matches(path, &marker)?)
}

fn sync_parent(path: &Path) -> Result<(), ConfigurationProviderError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("configuration path has no parent"))?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
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
    observation_schema: &str,
    expected: &ConfigurationRequest,
    materialized: Option<String>,
    state: &str,
) -> Result<AbilityValue, ConfigurationProviderError> {
    let mut value = serde_json::json!({
        "schema": observation_schema,
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
    let observation_schema = invocation
        .contract
        .observation_discriminator()
        .ok_or_else(|| {
            invalid("selected configuration method has no exact observation discriminator")
        })?;
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
        evidence: observation(observation_schema, desired, path, state)?,
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

    #[test]
    fn root_probe_requires_the_configuration_terminal_and_current_boot() {
        let boot_id = "01234567-89ab-cdef-0123-456789abcdef";
        let request: RootObservationRequest = serde_json::from_value(serde_json::json!({
            "schema": aos_provider_protocol::ROOT_OBSERVATION_REQUEST_SCHEMA,
            "provider": {
                "environment": {"authority":"system-image","key":"test","stage":"host"},
                "key": TERMINAL_HANDLER
            },
            "interface": {"name": TERMINAL_INTERFACE,"abi":1,"descriptor":digest('a')},
            "implementation": {
                "descriptor": digest('b'),
                "artifact": {
                    "content": digest('c'),
                    "store_path": "/nix/store/00000000000000000000000000000000-aos",
                    "nar_hash": digest('d'),
                    "closure": digest('e')
                },
                "handler": TERMINAL_HANDLER
            },
            "policy_revision": digest('f'),
            "boot_id": boot_id,
            "challenge": digest('0'),
            "maximum_age_millis": 1000,
            "control": {
                "attempt_remaining_millis": 1000,
                "recovery_remaining_millis": 1000,
                "cancelled": false
            }
        }))
        .expect("configuration terminal root request");

        let observed = observe_root_for_boot(request.clone(), boot_id)
            .expect("selected configuration terminal");
        assert_eq!(observed.boot_id, boot_id);
        assert!(
            observe_root_for_boot(request.clone(), "11234567-89ab-cdef-0123-456789abcdef").is_err()
        );

        let mut wrong_role = request;
        wrong_role.interface.name = aos_ability_model::InterfaceName::new("aos.other-interface")
            .expect("valid interface fixture");
        assert!(observe_root_for_boot(wrong_role, boot_id).is_err());
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

    fn assignment(reference: &ResourceReference) -> aos_ability_model::ProviderAssignment {
        serde_json::from_value(serde_json::json!({
            "provider": reference.resource.provider,
            "interface": reference.interface,
            "implementation": {
                "descriptor": format!("sha256:{}", "4".repeat(64)),
                "artifact": {
                    "content": format!("sha256:{}", "5".repeat(64)),
                    "store_path": "/nix/store/00000000000000000000000000000000-fixture",
                    "nar_hash": format!("sha256:{}", "6".repeat(64)),
                    "closure": format!("sha256:{}", "7".repeat(64)),
                },
                "handler": "fixture",
            },
            "incarnation": "fixture-incarnation",
        }))
        .expect("provider assignment fixture is valid")
    }

    fn context(reference: ResourceReference, path: &Path) -> ResourceContext {
        let revision = RevisionId(digest('2'));
        let native_context = ability_value(
            serde_json::to_value(aos_provider_protocol::BoundNativeContext {
                schema: aos_provider_protocol::RESOURCE_CONTEXT_SCHEMA.into(),
                resource_spec: aos_provider_protocol::ResourceSpec {
                    resource: reference.resource.clone(),
                    kind: reference.interface.name.clone(),
                    lifetime: reference.lifetime,
                    value: ability_value(serde_json::json!({"name":"root-password"}))
                        .expect("desired value fixture is bounded"),
                    realization: ability_value(serde_json::json!({"path":path}))
                        .expect("realization fixture is bounded"),
                    revision,
                },
                provider_context: ability_value(serde_json::json!({"fixture":true}))
                    .expect("provider context fixture is bounded"),
            })
            .expect("bound context fixture serializes"),
        )
        .expect("bound context fixture is bounded");
        ResourceContext {
            assignment: assignment(&reference),
            reference,
            revision,
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
            native_context_digest: aos_provider_protocol::native_context_digest(&native_context)
                .expect("native context digest computes"),
            native_context,
        }
    }

    fn target_context(
        reference: ResourceReference,
        inputs: AbilityValue,
        revision: RevisionId,
        path: &str,
    ) -> ResourceContext {
        let native_context = ability_value(serde_json::json!({
            "schema": aos_provider_protocol::RESOURCE_CONTEXT_SCHEMA,
            "resource_spec": {
                "resource": reference.resource,
                "kind": reference.interface.name,
                "lifetime": reference.lifetime,
                "value": inputs,
                "realization": {
                    "schema": "validated-by-runtime",
                    "path": path,
                },
                "revision": revision,
            },
            "provider_context": {
                "schema": PROVIDER_CONTEXT_SCHEMA,
                "path": path,
            },
        }))
        .expect("target native context is bounded");
        let native_context_digest = aos_provider_protocol::native_context_digest(&native_context)
            .expect("target native context digest is canonical");

        ResourceContext {
            assignment: assignment(&reference),
            reference,
            revision,
            observation: ability_value(serde_json::json!({
                "schema": "aos.test.configuration-observation/v1",
                "expected": inputs,
                "materialized": path,
                "state": "materialized",
            }))
            .expect("target observation is bounded"),
            native_context,
            native_context_digest,
        }
    }

    #[test]
    fn target_realization_requires_one_full_authority_and_matching_revision() {
        let target = resource_reference();
        let inputs = ability_value(serde_json::json!({
            "name": "server",
            "source": {"kind": "inline-text", "content": "ready=true\n"},
            "mode": "0444",
            "owner": null,
        }))
        .expect("target inputs are bounded");
        let revision = RevisionId(digest('7'));
        let path = "/run/aos/configurations/server-deadbeef";
        let context = target_context(target.clone(), inputs.clone(), revision, path);

        let realization =
            target_realization_from_contexts(&target, &inputs, std::slice::from_ref(&context))
                .expect("one exact target context is accepted");
        assert_eq!(realization.path, path);

        let mut weaker_target = target.clone();
        weaker_target.operations.clear();
        assert!(
            target_realization_from_contexts(
                &weaker_target,
                &inputs,
                std::slice::from_ref(&context),
            )
            .is_err()
        );
        assert!(
            target_realization_from_contexts(&target, &inputs, &[context.clone(), context.clone()])
                .is_err()
        );

        let mut mismatched_revision = context;
        mismatched_revision.revision = RevisionId(digest('8'));
        assert!(
            target_realization_from_contexts(&target, &inputs, &[mismatched_revision]).is_err()
        );
    }

    #[test]
    fn artifact_file_path_fragment_emits_only_a_contained_regular_file() {
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
        let fragments = vec![InterpolatedFragment::ArtifactFilePath {
            reference: ArtifactPathReference {
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

        let escaping = vec![InterpolatedFragment::ArtifactFilePath {
            reference: ArtifactPathReference {
                artifact: reference,
                path: "../outside".into(),
            },
        }];
        assert!(render_fragments(&escaping, 4096, &[], &mut BTreeMap::new()).is_err());
    }

    #[test]
    fn artifact_directory_fragment_emits_only_a_contained_directory() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let modules = directory.path().join("libexec/openldap");
        fs::create_dir_all(&modules).expect("module directory is created");
        let reference = ArtifactReference {
            content: digest('4'),
            store_path: path_text(directory.path()).expect("artifact path is UTF-8"),
            nar_hash: digest('5'),
            closure: digest('6'),
        };
        let fragments = vec![InterpolatedFragment::ArtifactDirectoryPath {
            reference: ArtifactPathReference {
                artifact: reference.clone(),
                path: "libexec/openldap".into(),
            },
        }];

        let rendered = render_fragments(&fragments, 4096, &[], &mut BTreeMap::new())
            .expect("contained artifact directory path renders");
        assert_eq!(
            rendered,
            fs::canonicalize(&modules)
                .expect("module directory canonicalizes")
                .as_os_str()
                .as_encoded_bytes()
        );

        let file = directory.path().join("not-a-directory");
        fs::write(&file, b"content").expect("regular file is written");
        let wrong_kind = vec![InterpolatedFragment::ArtifactDirectoryPath {
            reference: ArtifactPathReference {
                artifact: reference,
                path: "not-a-directory".into(),
            },
        }];
        assert!(render_fragments(&wrong_kind, 4096, &[], &mut BTreeMap::new()).is_err());
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

        let resource = resource_reference().resource;
        let revision = RevisionId(digest('8'));
        materialize(
            &output,
            &request,
            b"rootpw private-value\n",
            revisions,
            resource.clone(),
            revision,
        )
        .expect("configuration is materialized");
        assert!(
            observed_current(&output, &request, &resource, revision)
                .expect("configuration can be observed")
        );

        let marker = fs::read(marker_path(&output)).expect("marker is readable");
        let marker_text = String::from_utf8(marker).expect("marker is UTF-8 JSON");
        assert!(!marker_text.contains("private-value"));
        assert!(marker_text.contains(MATERIALIZER_VERSION));
    }

    #[test]
    fn qualification_observer_reads_only_the_exact_materialized_resource() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let output = directory.path().join("service");
        let request = ConfigurationRequest {
            name: "service".into(),
            source: ConfigurationSource::InlineText {
                content: "enabled=true\n".into(),
            },
            mode: "0644".into(),
            owner: None,
        };
        let resource = resource_reference().resource;
        materialize(
            &output,
            &request,
            b"enabled=true\n",
            BTreeMap::new(),
            resource.clone(),
            RevisionId(digest('8')),
        )
        .expect("configuration is materialized");

        let observation = qualification_observation(directory.path(), &resource)
            .expect("exact provider state is observable");

        assert_eq!(observation.resource, resource);
        assert_eq!(observation.entries.len(), 1);
        assert_eq!(observation.entries[0].path, path_text(&output).unwrap());
        assert_eq!(
            observation.entries[0].content_digest,
            Some(Sha256Digest::of_bytes(b"enabled=true\n"))
        );
        assert_eq!(observation.entries[0].mode, Some(0o644));
    }

    #[test]
    fn release_removes_only_the_exact_claimed_revision_and_reconciles_partial_cleanup() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let output = directory.path().join("service.conf");
        let request = ConfigurationRequest {
            name: "service".into(),
            source: ConfigurationSource::InlineText {
                content: "enabled=true\n".into(),
            },
            mode: "0600".into(),
            owner: None,
        };
        let resource = resource_reference().resource;
        let revision = RevisionId(digest('8'));
        materialize(
            &output,
            &request,
            b"enabled=true\n",
            BTreeMap::new(),
            resource.clone(),
            revision,
        )
        .expect("configuration is materialized");

        let error = release_materialization(&output, &request, &resource, RevisionId(digest('9')))
            .expect_err("a foreign revision must not release the configuration");
        assert!(error.to_string().contains("checked resource revision"));
        assert!(output.is_file());

        fs::remove_file(&output).expect("fixture simulates a crash after content cleanup");
        release_materialization(&output, &request, &resource, revision)
            .expect("release finishes exact partial cleanup");
        assert!(!output.exists());
        assert!(!marker_path(&output).exists());
        release_materialization(&output, &request, &resource, revision)
            .expect("released absence is idempotent");
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
