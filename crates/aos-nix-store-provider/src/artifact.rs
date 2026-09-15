//! Persistent content-addressed objects backed by the local Nix store.
//!
//! A checked runtime blob is copied into the immutable store, then retained by
//! a GC root owned by the logical ability resource. Provider metadata records
//! the provider-neutral request beside that root so admission can distinguish
//! a converged resource from an older semantic revision.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, AccessMode, ArtifactClosureMemberInput, ArtifactReference, LocalKey,
    MethodSemantics, ResourceId, ResourceReference, RevisionId, artifact_closure_identity,
    artifact_content_identity,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest, AdmissionResult, AdmissionRevision,
    BoundNativeContext, INVOCATION_SCHEMA, Invocation, InvocationDisposition, InvocationPurpose,
    InvocationResult, MAX_TRANSACTION_BLOB_BYTES, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, TRANSACTION_BLOB_INPUT_DIRECTORY_ENV, TRANSACTION_BLOB_REFERENCE_TYPE,
    TransactionBlobReference, resource_set_digest, validate_admission_resource,
    validate_resource_context, validate_resource_contexts,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::handler::{ability_value, decode_value, remaining};
use crate::process::ProcessStoreCommands;

const RESOURCE_INTERFACE_NAME: &str = "aos.artifact.content-addressed-object";
const REALIZATION_SCHEMA: &str = "aos.artifact.content-addressed-object-realization/v1";
const OBSERVATION_SCHEMA: &str = "aos.artifact.content-addressed-object-observation/v1";
const PROVIDER_CONTEXT_SCHEMA: &str = "aos.artifact.content-addressed-object-context/v1";
const METADATA_SCHEMA: &str = "aos.artifact.content-addressed-object-metadata/v1";
const ROOT_DIRECTORY: &str = "/nix/var/nix/gcroots/aos/content-addressed-objects";
const NIX_STORE_RELATIVE: &str = "../libexec/nix-store";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Handles persistent content-addressed object methods for the Nix store.
pub(super) struct ContentArtifactProvider {
    root_directory: PathBuf,
    store_directory: PathBuf,
    executable: Option<PathBuf>,
    commands: Box<dyn ArtifactStoreCommands>,
    validate_executable_file: bool,
}

impl ContentArtifactProvider {
    /// Constructs the production provider rooted in Nix's permanent GC roots.
    pub(super) fn production() -> Self {
        Self {
            root_directory: ROOT_DIRECTORY.into(),
            store_directory: "/nix/store".into(),
            executable: None,
            commands: Box::new(ProcessStoreCommands),
            validate_executable_file: true,
        }
    }

    /// Admits one effect-free object operation.
    pub(super) fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_method(request.method.method.as_str(), &request.semantics)?;
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;

        let desired: ContentObjectRequest = decode_value(&request.resource_spec.value)?;
        validate_request(&desired)?;
        validate_prerequisites(&desired.prerequisites, &request.resources)?;
        validate_target(&request.target, request.method.method.as_str())?;
        let realization: ContentObjectRealization =
            decode_value(&request.resource_spec.realization)?;
        validate_realization(&realization)?;
        let executable = self.executable()?;
        let inspection = self.inspect(
            &request.resource_spec.resource,
            &desired,
            &executable,
            request.control.attempt_remaining_millis,
        );
        let observation = observation(&desired, &inspection)?;
        let revision = admission_revision(&inspection, &observation)?;
        let native_context = ability_value(json!({
            "schema": PROVIDER_CONTEXT_SCHEMA,
            "executable": executable,
            "owner": request.resource_spec.resource,
        }))?;
        let purposes = if request.method.method.as_str() == "observe" {
            vec![InvocationPurpose::Effect]
        } else {
            vec![
                InvocationPurpose::Effect,
                InvocationPurpose::Reconcile,
                InvocationPurpose::Cancel,
            ]
        };

        Ok(AdmissionResult {
            schema: ADMISSION_SCHEMA.into(),
            disposition: AdmissionDisposition::Admitted,
            revision,
            incarnation: Some(request.assignment.incarnation),
            observation,
            native_context,
            supported_purposes: SupportedPurposes::from_ordered(purposes)
                .context("constructing content object supported purposes")?,
        })
    }

    /// Executes or reconciles one checked persistent object operation.
    pub(super) fn invoke(&self, invocation: Invocation) -> Result<InvocationResult> {
        ensure!(
            invocation.schema == INVOCATION_SCHEMA,
            "unsupported invocation schema"
        );
        ensure!(
            invocation.method_is_bound(),
            "invocation method differs from durable recovery authority"
        );
        validate_method(invocation.method.method.as_str(), &invocation.semantics)?;
        validate_method(
            invocation.request.method.method.as_str(),
            &invocation.request.semantics,
        )?;
        validate_resource_contexts(&invocation.request.resources)?;
        ensure!(
            resource_set_digest(&invocation.request.resources)?
                == invocation.request.native_context_digest,
            "resource contexts differ from their authenticated set digest"
        );

        let target = require_resource(&invocation.request.resources, &invocation.request.target)?;
        let bound: BoundNativeContext = validate_resource_context(target)?;
        validate_target(
            &invocation.request.target,
            invocation.method.method.as_str(),
        )?;

        let desired: ContentObjectRequest = decode_value(&bound.resource_spec.value)?;
        validate_request(&desired)?;
        validate_prerequisites(&desired.prerequisites, &invocation.request.resources)?;
        let parameters: ContentObjectParameters = decode_value(&invocation.request.inputs)?;
        ensure!(
            parameters.request == desired,
            "content object method request differs from the checked resource"
        );
        validate_parameters(invocation.request.method.method.as_str(), &parameters)?;
        let realization: ContentObjectRealization = decode_value(&bound.resource_spec.realization)?;
        validate_realization(&realization)?;
        let provider: ProviderContext = decode_value(&bound.provider_context)?;
        ensure!(
            provider.schema == PROVIDER_CONTEXT_SCHEMA
                && provider.owner == bound.resource_spec.resource,
            "content object provider context differs from the bound resource"
        );
        let executable = self.executable()?;
        ensure!(
            provider.executable == executable,
            "selected Nix store executable changed after admission"
        );

        let primary_method = invocation.request.method.method.as_str();
        let observation_before = self.inspect(
            &bound.resource_spec.resource,
            &desired,
            &executable,
            invocation.control.attempt_remaining_millis,
        );
        let (disposition, inspection) = match invocation.purpose {
            InvocationPurpose::Effect if invocation.control.cancelled => (
                InvocationDisposition::RejectedBeforeEffect,
                observation_before,
            ),
            InvocationPurpose::Effect => {
                match primary_method {
                    "commit" => self.commit(
                        &bound.resource_spec.resource,
                        &desired,
                        parameters.blob.as_ref().context(
                            "content object commit is missing its checked transaction blob",
                        )?,
                        &executable,
                        invocation.control.attempt_remaining_millis,
                    )?,
                    "observe" => {}
                    "remove" => self.remove(&bound.resource_spec.resource)?,
                    _ => bail!("unsupported content object effect method"),
                }
                let current = self.inspect(
                    &bound.resource_spec.resource,
                    &desired,
                    &executable,
                    invocation.control.attempt_remaining_millis,
                );
                (completion_disposition(primary_method, &current), current)
            }
            InvocationPurpose::Reconcile => (
                reconciliation_disposition(
                    primary_method,
                    &observation_before,
                    parameters.blob.as_ref(),
                ),
                observation_before,
            ),
            InvocationPurpose::Cancel => (
                cancellation_disposition(
                    primary_method,
                    &observation_before,
                    parameters.blob.as_ref(),
                ),
                observation_before,
            ),
            InvocationPurpose::Compensate => (
                InvocationDisposition::RejectedBeforeEffect,
                observation_before,
            ),
            InvocationPurpose::ReconcileCompensation => (
                InvocationDisposition::InterventionRequired,
                observation_before,
            ),
        };
        let evidence = observation(&desired, &inspection)?;
        let outputs = if disposition == InvocationDisposition::Completed
            && matches!(primary_method, "commit" | "observe")
        {
            successful_outputs(
                &invocation.request.target,
                &inspection,
                primary_method == "commit",
            )?
        } else {
            BTreeMap::new()
        };

        Ok(InvocationResult {
            schema: RESULT_SCHEMA.into(),
            disposition,
            evidence,
            outputs,
            native_context_digest: invocation.request.native_context_digest,
        })
    }

    fn executable(&self) -> Result<PathBuf> {
        let executable = if let Some(executable) = &self.executable {
            executable.clone()
        } else {
            let current = std::env::current_exe().context("resolving provider executable")?;
            current
                .parent()
                .context("provider executable has no parent")?
                .join(NIX_STORE_RELATIVE)
        };
        let resolved = fs::canonicalize(&executable).context("resolving bundled nix-store")?;
        ensure!(
            resolved.starts_with("/nix/store") || !self.validate_executable_file,
            "bundled nix-store resolves outside the immutable store"
        );
        if self.validate_executable_file {
            let metadata = fs::metadata(&resolved).context("inspecting bundled nix-store")?;
            ensure!(
                metadata.is_file(),
                "bundled nix-store is not a regular file"
            );
            ensure!(
                metadata.permissions().mode() & 0o111 != 0,
                "bundled nix-store is not executable"
            );
        }
        Ok(resolved)
    }

    fn inspect(
        &self,
        resource: &ResourceId,
        desired: &ContentObjectRequest,
        executable: &Path,
        remaining_millis: u64,
    ) -> Inspection {
        match self.inspect_checked(resource, desired, executable, remaining_millis) {
            Ok(inspection) => inspection,
            Err(_) => Inspection::Unknown,
        }
    }

    fn inspect_checked(
        &self,
        resource: &ResourceId,
        desired: &ContentObjectRequest,
        executable: &Path,
        remaining_millis: u64,
    ) -> Result<Inspection> {
        let paths = self.paths(resource)?;
        let root_metadata = fs::symlink_metadata(&paths.root);
        let state_metadata = fs::symlink_metadata(&paths.metadata);
        match (&root_metadata, &state_metadata) {
            (Err(root), Err(state))
                if root.kind() == io::ErrorKind::NotFound
                    && state.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(Inspection::Absent);
            }
            _ => {}
        }
        let Ok(root_metadata) = root_metadata else {
            return Ok(Inspection::Drifted);
        };
        let Ok(state_metadata) = state_metadata else {
            return Ok(Inspection::Drifted);
        };
        if !root_metadata.file_type().is_symlink() || !state_metadata.is_file() {
            return Ok(Inspection::Drifted);
        }

        let metadata = match read_metadata(&paths.metadata) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(Inspection::Drifted),
        };
        if metadata.schema != METADATA_SCHEMA || metadata.expected != *desired {
            return Ok(Inspection::Drifted);
        }
        let target = match fs::read_link(&paths.root) {
            Ok(target) if target == Path::new(&metadata.artifact.store_path) => target,
            _ => return Ok(Inspection::Drifted),
        };
        if !self
            .commands
            .is_valid(executable, &target, remaining_millis)?
        {
            return Ok(Inspection::Drifted);
        }
        let observed = self.describe_artifact(executable, &target, remaining_millis)?;
        if observed.artifact != metadata.artifact
            || observed.content_sha256 != metadata.content_sha256
        {
            return Ok(Inspection::Drifted);
        }
        Ok(Inspection::Ready(observed))
    }

    fn commit(
        &self,
        resource: &ResourceId,
        desired: &ContentObjectRequest,
        blob: &TransactionBlobReference,
        executable: &Path,
        remaining_millis: u64,
    ) -> Result<()> {
        let source = checked_blob_path(blob)?;
        let deadline = crate::handler::deadline(remaining_millis)?;
        let store_path = self
            .commands
            .add_fixed(executable, &source, remaining(deadline)?)?;
        let stored = self.describe_artifact(executable, &store_path, remaining(deadline)?)?;
        ensure!(
            stored.content_sha256 == blob.content_sha256,
            "stored object differs from its checked transaction blob"
        );
        let metadata = ObjectMetadata {
            schema: METADATA_SCHEMA.into(),
            expected: desired.clone(),
            artifact: stored.artifact,
            content_sha256: stored.content_sha256,
        };
        self.publish_root(resource, &store_path, &metadata)
    }

    fn describe_artifact(
        &self,
        executable: &Path,
        store_path: &Path,
        remaining_millis: u64,
    ) -> Result<StoredArtifact> {
        validate_store_path(store_path, &self.store_directory)?;
        let deadline = crate::handler::deadline(remaining_millis)?;
        let references = self
            .commands
            .references(executable, store_path, remaining(deadline)?)?;
        ensure!(
            references.is_empty(),
            "content-addressed flat object unexpectedly carries store references"
        );
        let bytes = read_bounded_regular(store_path)?;
        let nar = self
            .commands
            .dump(executable, store_path, remaining(deadline)?)?;
        let nar_hash = Sha256Digest::of_bytes(&nar);
        let store_path_text = store_path
            .to_str()
            .context("content-addressed store path is not UTF-8")?
            .to_string();
        let store_key = store_path_key(&store_path_text)?;
        let closure = artifact_closure_identity(
            store_key,
            &[ArtifactClosureMemberInput {
                key: store_key.into(),
                nar_hash,
                references: Vec::new(),
            }],
        )?;
        Ok(StoredArtifact {
            artifact: ArtifactReference {
                content: artifact_content_identity(&nar_hash),
                store_path: store_path_text,
                nar_hash,
                closure,
            },
            content_sha256: Sha256Digest::of_bytes(bytes),
        })
    }

    fn publish_root(
        &self,
        resource: &ResourceId,
        store_path: &Path,
        metadata: &ObjectMetadata,
    ) -> Result<()> {
        let paths = self.paths(resource)?;
        create_real_directory(&self.root_directory)?;
        create_real_directory(&paths.directory)?;
        let suffix = temporary_suffix();
        let root_temporary = paths.directory.join(format!("root.{suffix}.tmp"));
        let metadata_temporary = paths.directory.join(format!("metadata.{suffix}.tmp"));
        remove_if_present(&root_temporary)?;
        remove_if_present(&metadata_temporary)?;

        symlink(store_path, &root_temporary).context("creating temporary Nix GC root")?;
        fs::rename(&root_temporary, &paths.root).context("publishing Nix GC root")?;
        sync_directory(&paths.directory)?;

        let encoded = aos_contract::canonical::to_vec(metadata)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&metadata_temporary)
            .context("creating content object metadata")?;
        file.write_all(&encoded)
            .context("writing content object metadata")?;
        file.sync_all().context("syncing content object metadata")?;
        drop(file);
        fs::rename(&metadata_temporary, &paths.metadata)
            .context("publishing content object metadata")?;
        sync_directory(&paths.directory)
    }

    fn remove(&self, resource: &ResourceId) -> Result<()> {
        let paths = self.paths(resource)?;
        remove_symlink_if_present(&paths.root)?;
        remove_regular_if_present(&paths.metadata)?;
        match fs::remove_dir(&paths.directory) {
            Ok(()) => sync_directory(&self.root_directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing content object owner directory"),
        }
    }

    fn paths(&self, resource: &ResourceId) -> Result<ObjectPaths> {
        let digest =
            Sha256Digest::of_canonical("aos.artifact.content-addressed-object-owner/v1", resource)?;
        let directory = self.root_directory.join(digest.hex());
        Ok(ObjectPaths {
            root: directory.join("root"),
            metadata: directory.join("metadata.json"),
            directory,
        })
    }

    #[cfg(test)]
    fn test(
        root_directory: PathBuf,
        store_directory: PathBuf,
        commands: Box<dyn ArtifactStoreCommands>,
    ) -> Self {
        Self {
            root_directory,
            store_directory,
            executable: Some(PathBuf::from("/test/nix-store")),
            commands,
            validate_executable_file: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentObjectRequest {
    name: LocalKey,
    media_type: String,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentObjectParameters {
    request: ContentObjectRequest,
    blob: Option<TransactionBlobReference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentObjectRealization {
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    executable: PathBuf,
    owner: ResourceId,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectMetadata {
    schema: String,
    expected: ContentObjectRequest,
    artifact: ArtifactReference,
    content_sha256: Sha256Digest,
}

#[derive(Clone, Debug)]
struct StoredArtifact {
    artifact: ArtifactReference,
    content_sha256: Sha256Digest,
}

#[derive(Debug)]
enum Inspection {
    Absent,
    Ready(StoredArtifact),
    Drifted,
    Unknown,
}

struct ObjectPaths {
    directory: PathBuf,
    root: PathBuf,
    metadata: PathBuf,
}

pub(super) trait ArtifactStoreCommands: Send + Sync {
    fn add_fixed(&self, executable: &Path, source: &Path, remaining_millis: u64)
    -> Result<PathBuf>;

    fn dump(&self, executable: &Path, store_path: &Path, remaining_millis: u64) -> Result<Vec<u8>>;

    fn references(
        &self,
        executable: &Path,
        store_path: &Path,
        remaining_millis: u64,
    ) -> Result<Vec<PathBuf>>;

    fn is_valid(&self, executable: &Path, store_path: &Path, remaining_millis: u64)
    -> Result<bool>;
}

fn validate_request(request: &ContentObjectRequest) -> Result<()> {
    validate_media_type(&request.media_type)?;
    ensure!(
        request.prerequisites.len() <= 64,
        "too many content object prerequisites"
    );
    let encoded = request
        .prerequisites
        .iter()
        .map(serde_json::to_vec)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        encoded.windows(2).all(|pair| pair[0] < pair[1]),
        "content object prerequisites are not canonical and unique"
    );
    Ok(())
}

fn validate_media_type(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 255,
        "content object media type is empty or oversized"
    );
    let mut parts = value.split('/');
    let type_name = parts.next().unwrap_or_default();
    let subtype = parts.next().unwrap_or_default();
    ensure!(
        !type_name.is_empty()
            && !subtype.is_empty()
            && parts.next().is_none()
            && type_name.bytes().all(media_token_byte)
            && subtype.bytes().all(media_token_byte),
        "content object media type is not canonical"
    );
    Ok(())
}

fn media_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
        )
}

fn validate_parameters(method: &str, parameters: &ContentObjectParameters) -> Result<()> {
    match method {
        "commit" => {
            ensure!(
                parameters.blob.is_some(),
                "content object commit requires a transaction blob"
            );
        }
        "observe" | "remove" => {
            ensure!(
                parameters.blob.is_none(),
                "content object observation and deletion reject blob inputs"
            );
        }
        _ => bail!("unsupported content object method"),
    }
    Ok(())
}

fn validate_realization(realization: &ContentObjectRealization) -> Result<()> {
    ensure!(
        realization.schema == REALIZATION_SCHEMA,
        "unsupported content object realization"
    );
    Ok(())
}

fn validate_method(method: &str, semantics: &MethodSemantics) -> Result<()> {
    let expected = match method {
        "commit" => MethodSemantics::ordinary(AccessMode::ExclusiveWrite),
        "observe" => MethodSemantics::ordinary(AccessMode::Read),
        "remove" => MethodSemantics::provider_stop(),
        _ => bail!("selected content object method is unsupported"),
    };
    ensure!(
        *semantics == expected,
        "selected content object method semantics differ"
    );
    Ok(())
}

fn validate_target(target: &ResourceReference, method: &str) -> Result<()> {
    ensure!(
        target.interface.name.as_str() == RESOURCE_INTERFACE_NAME,
        "content object operation does not target the public resource interface"
    );
    ensure!(
        target
            .operations
            .binary_search_by_key(&method, LocalKey::as_str)
            .is_ok(),
        "content object method is outside the target resource authority"
    );
    ensure!(
        target.lifetime == aos_ability_model::ResourceLifetime::Persistent,
        "content object target is not persistent"
    );
    Ok(())
}

fn validate_prerequisites(
    prerequisites: &[ResourceReference],
    resources: &[ResourceContext],
) -> Result<()> {
    for prerequisite in prerequisites {
        let context = require_resource(resources, prerequisite)?;
        validate_resource_context(context)?;
    }
    Ok(())
}

fn require_resource<'a>(
    resources: &'a [ResourceContext],
    reference: &ResourceReference,
) -> Result<&'a ResourceContext> {
    let matches = resources
        .iter()
        .filter(|context| &context.reference == reference)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "request does not contain one exact resource context"
    );
    Ok(matches[0])
}

fn checked_blob_path(reference: &TransactionBlobReference) -> Result<PathBuf> {
    ensure!(
        reference.kind == TRANSACTION_BLOB_REFERENCE_TYPE,
        "transaction blob reference has an unsupported type"
    );
    ensure!(
        reference.size_bytes <= MAX_TRANSACTION_BLOB_BYTES,
        "transaction blob exceeds its bound"
    );
    let input = std::env::var_os(TRANSACTION_BLOB_INPUT_DIRECTORY_ENV)
        .context("runtime did not expose checked transaction blob inputs")?;
    let input = PathBuf::from(input);
    ensure!(
        input.is_absolute(),
        "transaction blob input root is not absolute"
    );
    checked_blob_at(&input, reference)
}

fn checked_blob_at(input: &Path, reference: &TransactionBlobReference) -> Result<PathBuf> {
    let path = input.join(reference.handle.as_str());
    let bytes = read_bounded_regular(&path)?;
    ensure!(
        bytes.len() as u64 == reference.size_bytes
            && Sha256Digest::of_bytes(&bytes) == reference.content_sha256,
        "transaction blob bytes differ from their checked reference"
    );
    Ok(path)
}

fn read_bounded_regular(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening regular file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting regular file {}", path.display()))?;
    ensure!(metadata.is_file(), "checked object is not a regular file");
    ensure!(
        metadata.len() <= MAX_TRANSACTION_BLOB_BYTES,
        "checked object exceeds the transaction blob bound"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_TRANSACTION_BLOB_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading regular file {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_TRANSACTION_BLOB_BYTES,
        "checked object grew beyond the transaction blob bound"
    );
    let after = file
        .metadata()
        .with_context(|| format!("reinspecting regular file {}", path.display()))?;
    ensure!(
        after.len() == metadata.len(),
        "checked object changed while it was read"
    );
    Ok(bytes)
}

fn read_metadata(path: &Path) -> Result<ObjectMetadata> {
    let bytes = read_bounded_regular(path)?;
    aos_contract::canonical::from_slice(&bytes, "content object metadata")
}

fn observation(desired: &ContentObjectRequest, inspection: &Inspection) -> Result<AbilityValue> {
    let (state, content_sha256, artifact) = match inspection {
        Inspection::Absent => ("absent", None, None),
        Inspection::Ready(stored) => (
            "ready",
            Some(stored.content_sha256),
            Some(stored.artifact.clone()),
        ),
        Inspection::Drifted => ("drifted", None, None),
        Inspection::Unknown => ("unknown", None, None),
    };
    ability_value(json!({
        "schema": OBSERVATION_SCHEMA,
        "expected": desired,
        "state": state,
        "content_sha256": content_sha256,
        "artifact": artifact,
    }))
}

fn admission_revision(
    inspection: &Inspection,
    observation: &AbilityValue,
) -> Result<AdmissionRevision> {
    match inspection {
        Inspection::Ready(_) | Inspection::Drifted => Ok(AdmissionRevision::Present {
            revision: RevisionId(Sha256Digest::of_canonical(
                "aos.artifact.content-addressed-object-observed/v1",
                observation,
            )?),
        }),
        Inspection::Absent => Ok(AdmissionRevision::Absent),
        Inspection::Unknown => Ok(AdmissionRevision::Unknown),
    }
}

fn completion_disposition(method: &str, inspection: &Inspection) -> InvocationDisposition {
    match (method, inspection) {
        ("commit" | "observe", Inspection::Ready(_)) | ("remove", Inspection::Absent) => {
            InvocationDisposition::Completed
        }
        (_, Inspection::Unknown) => InvocationDisposition::Indeterminate,
        _ => InvocationDisposition::Indeterminate,
    }
}

fn reconciliation_disposition(
    method: &str,
    inspection: &Inspection,
    blob: Option<&TransactionBlobReference>,
) -> InvocationDisposition {
    match (method, inspection) {
        ("commit", Inspection::Ready(stored))
            if blob.is_some_and(|blob| blob.content_sha256 == stored.content_sha256) =>
        {
            InvocationDisposition::Completed
        }
        ("observe", Inspection::Ready(_)) => InvocationDisposition::Completed,
        ("remove", Inspection::Absent) => InvocationDisposition::Completed,
        ("commit", Inspection::Absent | Inspection::Ready(_) | Inspection::Drifted)
        | ("remove", Inspection::Ready(_) | Inspection::Drifted) => {
            InvocationDisposition::SafeToRetry
        }
        _ => InvocationDisposition::StillIndeterminate,
    }
}

fn cancellation_disposition(
    method: &str,
    inspection: &Inspection,
    blob: Option<&TransactionBlobReference>,
) -> InvocationDisposition {
    match (method, inspection) {
        ("commit", Inspection::Ready(stored))
            if blob.is_some_and(|blob| blob.content_sha256 == stored.content_sha256) =>
        {
            InvocationDisposition::Completed
        }
        ("observe", Inspection::Ready(_)) => InvocationDisposition::Completed,
        ("remove", Inspection::Absent) => InvocationDisposition::Completed,
        ("commit", Inspection::Absent | Inspection::Ready(_))
        | ("remove", Inspection::Ready(_)) => InvocationDisposition::RejectedBeforeEffect,
        _ => InvocationDisposition::Indeterminate,
    }
}

fn successful_outputs(
    target: &ResourceReference,
    inspection: &Inspection,
    include_resource: bool,
) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    let Inspection::Ready(stored) = inspection else {
        bail!("completed content object operation lacks a ready observation");
    };
    let mut outputs = BTreeMap::new();
    outputs.insert(
        LocalKey::new("artifact-reference")?,
        ability_value(serde_json::to_value(&stored.artifact)?)?,
    );
    if include_resource {
        let mut retained = target.clone();
        retained.operations = ["observe", "remove"]
            .into_iter()
            .map(LocalKey::new)
            .collect::<Result<Vec<_>, _>>()?;
        outputs.insert(
            LocalKey::new("artifact-resource")?,
            ability_value(serde_json::to_value(retained)?)?,
        );
    }
    outputs.insert(
        LocalKey::new("content-sha256")?,
        ability_value(serde_json::to_value(stored.content_sha256)?)?,
    );
    Ok(outputs)
}

fn validate_store_path(path: &Path, store_directory: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.parent() == Some(store_directory)
            && path.file_name().is_some_and(|name| !name.is_empty()),
        "content-addressed object has an invalid store path"
    );
    Ok(())
}

fn store_path_key(path: &str) -> Result<&str> {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("content-addressed store path has no UTF-8 name")?;
    let (key, _) = name
        .split_once('-')
        .context("content-addressed store path has no store key")?;
    ensure!(
        key.len() == 32
            && key
                .bytes()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
        "content-addressed store path has an invalid store key"
    );
    Ok(key)
}

fn create_real_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            File::open(path)
                .context("opening new content object directory")?
                .sync_all()
                .context("syncing new content object directory")?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .context("content object directory has no parent")?;
            create_real_directory(parent)?;
            fs::create_dir(path).context("creating content object directory")?;
            sync_directory(parent)?;
        }
        Err(error) => return Err(error).context("creating content object directory"),
    }
    let metadata = fs::symlink_metadata(path).context("inspecting content object directory")?;
    ensure!(
        metadata.is_dir(),
        "content object directory is not a real directory"
    );
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(path).context("removing stale content object temporary")
        }
        Ok(_) => bail!("content object temporary path has an unexpected type"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting content object temporary"),
    }
}

fn remove_symlink_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fs::remove_file(path).context("removing content object GC root")
        }
        Ok(_) => bail!("content object GC root is not a symlink"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting content object GC root"),
    }
}

fn remove_regular_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(path).context("removing content object metadata")
        }
        Ok(_) => bail!("content object metadata is not a regular file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting content object metadata"),
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn temporary_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests;
