//! Native command handler for transaction-scoped boot preparations.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, AccessMode, ArtifactReference, LocalKey, MethodSemantics, ResourceReference,
    RevisionId,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, BoundNativeContext, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, RESULT_SCHEMA, ResourceContext,
    SupportedPurposes, resource_set_digest, validate_admission_resource, validate_resource_context,
    validate_resource_contexts,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::process::{CommandRunner, ProcessCommandRunner};

const INTERFACE_NAME: &str = "aos.boot.preparation";
const REALIZATION_SCHEMA: &str = "aos.boot.preparation-realization/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.boot-preparation-observation/v1";
const CONTEXT_SCHEMA: &str = "aos.boot.preparation-context/v1";
const MARKER_SCHEMA: &str = "aos.boot.preparation-marker/v1";
const MARKER_ROOT: &str = "/run/aos/boot-preparations";
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

/// Executes exact boot preparations and retains transaction-scoped evidence.
pub struct BootPreparationProvider {
    marker_root: PathBuf,
    runner: Box<dyn CommandRunner>,
    validate_executable_file: bool,
}

impl BootPreparationProvider {
    /// Constructs the production provider.
    #[must_use]
    pub fn production() -> Self {
        Self {
            marker_root: MARKER_ROOT.into(),
            runner: Box::new(ProcessCommandRunner),
            validate_executable_file: true,
        }
    }

    /// Handles one bounded provider-protocol document.
    ///
    /// # Errors
    ///
    /// Returns an error when the request, selected resource context, executable,
    /// retained marker, or subprocess result is invalid.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        let result = match purpose {
            "admit" => {
                let request: AdmissionRequest = aos_contract::canonical::from_slice(
                    input,
                    "boot preparation admission request",
                )?;
                ensure!(
                    request.schema == ADMISSION_REQUEST_SCHEMA,
                    "unsupported admission schema"
                );
                serde_json::to_value(self.admit(request)?)?
            }
            "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation" => {
                let invocation: Invocation =
                    aos_contract::canonical::from_slice(input, "boot preparation invocation")?;
                ensure!(
                    invocation.schema == INVOCATION_SCHEMA,
                    "unsupported invocation schema"
                );
                ensure!(
                    purpose == purpose_name(invocation.purpose),
                    "invocation purpose differs from argv"
                );
                serde_json::to_value(self.invoke(invocation)?)?
            }
            _ => bail!("unsupported command-handler purpose {purpose:?}"),
        };

        aos_contract::canonical::canonical_json(&result)
            .context("encoding canonical boot preparation response")
    }

    fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_method(
            &request.method.interface.name.to_string(),
            request.method.method.as_str(),
            &request.semantics,
        )?;
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;

        let desired: PreparationRequest = decode_value(&request.resource_spec.value)?;
        validate_request(&desired)?;
        validate_prerequisites(&desired.prerequisites, &request.resources)?;
        let realization: PreparationRealization = decode_value(&request.resource_spec.realization)?;
        ensure!(
            realization.schema == REALIZATION_SCHEMA,
            "unsupported boot preparation realization"
        );
        let executable = Executable::from_reference(desired.execution.clone());
        executable.validate(self.validate_executable_file)?;

        let observation = self.observe(
            &request.resource_spec.value,
            &request.target,
            request.resource_spec.revision,
        )?;
        let revision = admission_revision(&observation, request.resource_spec.revision);
        let native_context = ability_value(json!({
            "schema": CONTEXT_SCHEMA,
            "executable": executable,
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
                .context("constructing canonical supported purposes")?,
        })
    }

    fn invoke(&self, invocation: Invocation) -> Result<InvocationResult> {
        ensure!(
            invocation.method_is_bound(),
            "invocation method differs from durable recovery authority"
        );
        validate_method(
            &invocation.method.interface.name.to_string(),
            invocation.method.method.as_str(),
            &invocation.semantics,
        )?;

        let request = &invocation.request;
        validate_resource_contexts(&request.resources)?;
        ensure!(
            resource_set_digest(&request.resources)? == request.native_context_digest,
            "resource contexts differ from their authenticated set digest"
        );
        let target = require_resource(&request.resources, &request.target)?;
        let bound: BoundNativeContext = validate_resource_context(target)?;
        ensure!(
            invocation.method.interface == request.target.interface
                && request
                    .target
                    .operations
                    .binary_search(&invocation.method.method)
                    .is_ok(),
            "invocation method is outside target resource authority"
        );
        ensure!(
            bound.resource_spec.value == request.inputs,
            "durable inputs differ from bound desired request"
        );

        let desired: PreparationRequest = decode_value(&bound.resource_spec.value)?;
        validate_request(&desired)?;
        validate_prerequisites(&desired.prerequisites, &request.resources)?;
        let realization: PreparationRealization = decode_value(&bound.resource_spec.realization)?;
        ensure!(
            realization.schema == REALIZATION_SCHEMA,
            "unsupported boot preparation realization"
        );
        let executable = Executable::from_reference(desired.execution.clone());
        executable.validate(self.validate_executable_file)?;
        let context: ProviderContext = decode_value(&bound.provider_context)?;
        ensure!(
            context.schema == CONTEXT_SCHEMA,
            "unsupported boot preparation provider context"
        );
        ensure!(
            context.executable == executable,
            "selected executable differs from admitted context"
        );

        let before = self.observe(
            &bound.resource_spec.value,
            &request.target,
            bound.resource_spec.revision,
        )?;
        let method = invocation.method.method.as_str();
        let (disposition, evidence, mut outputs) = match invocation.purpose {
            InvocationPurpose::Effect if method == "observe" => {
                (InvocationDisposition::Completed, before, BTreeMap::new())
            }
            InvocationPurpose::Effect if invocation.control.cancelled => (
                InvocationDisposition::RejectedBeforeEffect,
                before,
                BTreeMap::new(),
            ),
            InvocationPurpose::Effect => match observation_state(&before) {
                Some(PreparationState::Completed) => (
                    InvocationDisposition::Completed,
                    before,
                    successful_outputs(&request.target)?,
                ),
                Some(PreparationState::Absent | PreparationState::Failed) => {
                    self.runner
                        .run(&executable, invocation.control.attempt_remaining_millis)?;
                    self.record_completion(&request.target, bound.resource_spec.revision)?;
                    let evidence = self.observe(
                        &bound.resource_spec.value,
                        &request.target,
                        bound.resource_spec.revision,
                    )?;
                    (
                        InvocationDisposition::Completed,
                        evidence,
                        successful_outputs(&request.target)?,
                    )
                }
                Some(PreparationState::Unknown) | None => (
                    InvocationDisposition::Indeterminate,
                    before,
                    BTreeMap::new(),
                ),
            },
            InvocationPurpose::Reconcile => match observation_state(&before) {
                Some(PreparationState::Completed) => (
                    InvocationDisposition::Completed,
                    before,
                    successful_outputs(&request.target)?,
                ),
                Some(PreparationState::Absent | PreparationState::Failed) => {
                    (InvocationDisposition::SafeToRetry, before, BTreeMap::new())
                }
                Some(PreparationState::Unknown) | None => (
                    InvocationDisposition::StillIndeterminate,
                    before,
                    BTreeMap::new(),
                ),
            },
            InvocationPurpose::Cancel => match observation_state(&before) {
                Some(PreparationState::Completed) => (
                    InvocationDisposition::Completed,
                    before,
                    successful_outputs(&request.target)?,
                ),
                Some(PreparationState::Absent) => (
                    InvocationDisposition::RejectedBeforeEffect,
                    before,
                    BTreeMap::new(),
                ),
                _ => (
                    InvocationDisposition::Indeterminate,
                    before,
                    BTreeMap::new(),
                ),
            },
            InvocationPurpose::Compensate => (
                InvocationDisposition::RejectedBeforeEffect,
                before,
                BTreeMap::new(),
            ),
            InvocationPurpose::ReconcileCompensation => (
                InvocationDisposition::InterventionRequired,
                before,
                BTreeMap::new(),
            ),
        };
        if disposition == InvocationDisposition::Completed {
            outputs.insert(LocalKey::new("observation")?, evidence.clone());
        }

        Ok(InvocationResult {
            schema: RESULT_SCHEMA.into(),
            disposition,
            evidence,
            outputs,
            native_context_digest: request.native_context_digest,
        })
    }

    fn observe(
        &self,
        expected: &AbilityValue,
        target: &ResourceReference,
        revision: RevisionId,
    ) -> Result<AbilityValue> {
        let state = match self.read_marker(target)? {
            MarkerRead::Missing => PreparationState::Absent,
            MarkerRead::Invalid => PreparationState::Unknown,
            MarkerRead::Valid(marker)
                if marker.resource == *target && marker.revision == revision =>
            {
                PreparationState::Completed
            }
            MarkerRead::Valid(_) => PreparationState::Failed,
        };
        ability_value(json!({
            "schema": OBSERVATION_SCHEMA,
            "expected": expected.as_json(),
            "state": state,
        }))
    }

    fn read_marker(&self, target: &ResourceReference) -> Result<MarkerRead> {
        let path = self.marker_path(target)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(MarkerRead::Missing);
            }
            Err(error) => return Err(error).context("reading boot preparation marker"),
        };
        let marker = match aos_contract::canonical::from_slice::<CompletionMarker>(
            &bytes,
            "boot preparation marker",
        ) {
            Ok(marker) if marker.schema == MARKER_SCHEMA => marker,
            Ok(_) | Err(_) => return Ok(MarkerRead::Invalid),
        };
        Ok(MarkerRead::Valid(marker))
    }

    fn record_completion(&self, target: &ResourceReference, revision: RevisionId) -> Result<()> {
        ensure!(
            !matches!(self.read_marker(target)?, MarkerRead::Invalid),
            "refusing to replace an invalid boot preparation marker"
        );
        ensure_marker_root(&self.marker_root)?;
        let path = self.marker_path(target)?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let marker = CompletionMarker {
            schema: MARKER_SCHEMA.into(),
            resource: target.clone(),
            revision,
        };
        let bytes = aos_contract::canonical::canonical_json(&serde_json::to_value(marker)?)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context("creating boot preparation marker")?;
        file.write_all(&bytes)
            .context("writing boot preparation marker")?;
        file.sync_all().context("syncing boot preparation marker")?;
        drop(file);
        fs::rename(&temporary, &path).context("publishing boot preparation marker")?;
        File::open(&self.marker_root)
            .context("opening boot preparation marker directory")?
            .sync_all()
            .context("syncing boot preparation marker directory")
    }

    fn marker_path(&self, target: &ResourceReference) -> Result<PathBuf> {
        let digest = Sha256Digest::of_canonical("aos.boot.preparation-marker-key/v1", target)?;
        Ok(self
            .marker_root
            .join(digest.to_string().trim_start_matches("sha256:")))
    }

    #[cfg(test)]
    fn test(marker_root: PathBuf, runner: Box<dyn CommandRunner>) -> Self {
        Self {
            marker_root,
            runner,
            validate_executable_file: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PreparationRequest {
    execution: ExecutableReference,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparationRealization {
    schema: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutableReference {
    artifact: ArtifactReference,
    entry_point: String,
    arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Executable {
    artifact: ArtifactReference,
    entry_point: String,
    pub(super) arguments: Vec<String>,
}

impl Executable {
    fn from_reference(reference: ExecutableReference) -> Self {
        Self {
            artifact: reference.artifact,
            entry_point: reference.entry_point,
            arguments: reference.arguments,
        }
    }

    pub(super) fn path(&self) -> PathBuf {
        Path::new(&self.artifact.store_path).join(&self.entry_point)
    }

    fn validate(&self, inspect_file: bool) -> Result<()> {
        let root = Path::new(&self.artifact.store_path);
        ensure!(
            root.is_absolute() && root.starts_with("/nix/store"),
            "preparation artifact is outside the immutable store"
        );
        let relative = Path::new(&self.entry_point);
        ensure!(
            !self.entry_point.is_empty()
                && !relative.is_absolute()
                && relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_))),
            "preparation entry point is not a normalized relative path"
        );
        ensure!(
            self.arguments.len() <= MAX_ARGUMENTS,
            "too many preparation arguments"
        );
        ensure!(
            self.arguments.iter().map(String::len).sum::<usize>() <= MAX_ARGUMENT_BYTES
                && self
                    .arguments
                    .iter()
                    .all(|argument| !argument.contains('\0')),
            "preparation arguments exceed their bound or contain NUL"
        );
        if inspect_file {
            let root = fs::canonicalize(root).context("resolving preparation artifact root")?;
            let resolved =
                fs::canonicalize(self.path()).context("resolving preparation executable")?;
            ensure!(
                resolved.starts_with(&root),
                "preparation executable resolves outside its artifact"
            );
            let metadata = fs::metadata(&resolved).context("inspecting preparation executable")?;
            ensure!(
                metadata.is_file(),
                "preparation executable is not a regular file"
            );
            ensure!(
                metadata.permissions().mode() & 0o111 != 0,
                "preparation executable is not executable"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    executable: Executable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionMarker {
    schema: String,
    resource: ResourceReference,
    revision: RevisionId,
}

enum MarkerRead {
    Missing,
    Invalid,
    Valid(CompletionMarker),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PreparationState {
    Absent,
    Completed,
    Failed,
    Unknown,
}

fn ensure_marker_root(root: &Path) -> Result<()> {
    fs::create_dir_all(root).context("creating boot preparation marker root")?;
    let metadata = fs::symlink_metadata(root).context("inspecting boot preparation marker root")?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "boot preparation marker root is not a directory"
    );
    Ok(())
}

fn validate_method(interface: &str, method: &str, semantics: &MethodSemantics) -> Result<()> {
    ensure!(
        interface == INTERFACE_NAME,
        "selected interface is not boot preparation"
    );
    let access = match method {
        "prepare" => AccessMode::ExclusiveWrite,
        "observe" => AccessMode::Read,
        _ => bail!("selected boot preparation method is unsupported"),
    };
    ensure!(
        *semantics == MethodSemantics::ordinary(access),
        "selected method semantics differ"
    );
    Ok(())
}

fn validate_request(request: &PreparationRequest) -> Result<()> {
    ensure!(
        request.prerequisites.len() <= 64,
        "too many boot preparation prerequisites"
    );
    let encoded = request
        .prerequisites
        .iter()
        .map(serde_json::to_vec)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        encoded.windows(2).all(|pair| pair[0] < pair[1]),
        "boot preparation prerequisites are not canonical and unique"
    );
    Ok(())
}

fn validate_prerequisites(
    prerequisites: &[ResourceReference],
    resources: &[ResourceContext],
) -> Result<()> {
    for prerequisite in prerequisites {
        validate_resource_context(require_resource(resources, prerequisite)?)?;
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

fn admission_revision(observation: &AbilityValue, desired: RevisionId) -> AdmissionRevision {
    match observation_state(observation) {
        Some(PreparationState::Completed) => AdmissionRevision::Present { revision: desired },
        Some(PreparationState::Absent) => AdmissionRevision::Absent,
        Some(PreparationState::Failed) => {
            match Sha256Digest::of_canonical("aos.boot.preparation-observed/v1", observation) {
                Ok(digest) => AdmissionRevision::Present {
                    revision: RevisionId(digest),
                },
                Err(_) => AdmissionRevision::Unknown,
            }
        }
        Some(PreparationState::Unknown) | None => AdmissionRevision::Unknown,
    }
}

fn observation_state(observation: &AbilityValue) -> Option<PreparationState> {
    serde_json::from_value(observation.as_json().get("state")?.clone()).ok()
}

fn successful_outputs(target: &ResourceReference) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    let mut outputs = BTreeMap::new();
    outputs.insert(
        LocalKey::new("retained-resource")?,
        ability_value(serde_json::to_value(target)?)?,
    );
    Ok(outputs)
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).context("constructing canonical ability value")
}

fn decode_value<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding checked ability value")
}

const fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    struct NoopRunner;

    impl CommandRunner for NoopRunner {
        fn run(&self, _: &Executable, _: u64) -> Result<()> {
            Ok(())
        }
    }

    fn target() -> ResourceReference {
        serde_json::from_value(json!({
            "interface": {
                "name": INTERFACE_NAME,
                "abi": 1,
                "descriptor": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "resource": {
                "provider": {
                    "environment": {"authority": "test", "key": "initrd", "stage": "initrd"},
                    "key": "provider"
                },
                "key": "seed"
            },
            "operations": ["observe", "prepare"],
            "lifetime": "transaction"
        }))
        .expect("target reference")
    }

    #[test]
    fn rejects_non_store_executable() {
        let executable = Executable {
            artifact: serde_json::from_value(json!({
                "closure": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "content": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "nar_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "store_path": "/tmp/not-store"
            })).expect("artifact"),
            entry_point: "bin/prepare".into(),
            arguments: vec![],
        };

        assert!(executable.validate(false).is_err());
    }

    #[test]
    fn completion_is_bound_to_the_exact_revision() {
        let directory = tempdir().expect("marker directory");
        let provider = BootPreparationProvider::test(directory.path().into(), Box::new(NoopRunner));
        let target = target();
        let first = RevisionId(Sha256Digest::of_bytes(b"first"));
        let second = RevisionId(Sha256Digest::of_bytes(b"second"));
        let expected = ability_value(json!({"execution": {"artifact": {"content": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "store_path": "/nix/store/00000000000000000000000000000000-preparation", "nar_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "closure": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}, "entry_point": "bin/prepare", "arguments": []}, "prerequisites": []})).expect("expected request");

        provider
            .record_completion(&target, first)
            .expect("record completion");
        let completed = provider
            .observe(&expected, &target, first)
            .expect("observe completion");
        let drifted = provider
            .observe(&expected, &target, second)
            .expect("observe other revision");

        assert_eq!(
            observation_state(&completed),
            Some(PreparationState::Completed)
        );
        assert_eq!(observation_state(&drifted), Some(PreparationState::Failed));
    }

    #[test]
    fn invalid_marker_is_never_replaced() {
        let directory = tempdir().expect("marker directory");
        let provider = BootPreparationProvider::test(directory.path().into(), Box::new(NoopRunner));
        let target = target();
        let revision = RevisionId(Sha256Digest::of_bytes(b"revision"));
        let path = provider.marker_path(&target).expect("marker path");
        fs::write(&path, b"not-json").expect("corrupt marker");

        assert!(matches!(
            provider.read_marker(&target).expect("read marker"),
            MarkerRead::Invalid
        ));
        assert!(provider.record_completion(&target, revision).is_err());
        assert_eq!(
            fs::read(path).expect("retained corrupt marker"),
            b"not-json"
        );
    }
}
