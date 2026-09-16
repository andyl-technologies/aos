//! Command dispatch and local Nix store database realization.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, AccessMode, ArtifactReference, LocalKey, MethodReference, MethodSemantics,
    ResourceReference, RevisionId,
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

use crate::artifact::ContentArtifactProvider;
use crate::process::ProcessStoreCommands;
#[cfg(test)]
use crate::process::argument_batches;

const REALIZATION_SCHEMA: &str = "aos.nix.store-database-realization/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.nix-store-database-observation/v1";
const PROVIDER_CONTEXT_SCHEMA: &str = "aos.nix.store-database-context/v1";
const DATABASE_PATH: &str = "/nix/var/nix/db/db.sqlite";
const MAX_REGISTRATION_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REGISTRATION_RECORDS: usize = 1_000_000;
const DATABASE_INTERFACE: &str = "aos.nix.store-database-effects";
const CONTENT_OBJECT_INTERFACE: &str = "aos.artifact.content-addressed-object-operations";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NixStoreRole {
    Database,
    ContentAddressedObject,
}

impl NixStoreRole {
    fn from_method(method: &MethodReference) -> Result<Self> {
        match method.interface.name.as_str() {
            DATABASE_INTERFACE => Ok(Self::Database),
            CONTENT_OBJECT_INTERFACE => Ok(Self::ContentAddressedObject),
            _ => bail!("selected interface does not belong to the Nix store provider"),
        }
    }
}

/// Handles package-owned local Nix store abilities.
pub struct NixStoreProvider {
    artifacts: ContentArtifactProvider,
    database_path: PathBuf,
    commands: Box<dyn StoreCommands>,
    validate_executable_file: bool,
}

impl NixStoreProvider {
    /// Constructs the production provider for the local Nix database.
    #[must_use]
    pub fn production() -> Self {
        Self {
            artifacts: ContentArtifactProvider::production(),
            database_path: DATABASE_PATH.into(),
            commands: Box::new(ProcessStoreCommands),
            validate_executable_file: true,
        }
    }

    /// Handles one bounded command invocation and returns canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the wire schema, authority, provider context, or
    /// selected executable is invalid, or when a requested database command
    /// cannot complete within its supplied deadline.
    pub fn handle(&self, purpose: &str, input: &[u8]) -> Result<Vec<u8>> {
        let result = match purpose {
            "admit" => {
                let request: AdmissionRequest = aos_contract::canonical::from_slice(
                    input,
                    "Nix store database admission request",
                )
                .context("decoding Nix store database admission request")?;
                ensure!(
                    request.schema == ADMISSION_REQUEST_SCHEMA,
                    "unsupported admission schema"
                );
                let role = NixStoreRole::from_method(&request.method)?;
                match role {
                    NixStoreRole::Database => serde_json::to_value(self.admit(request)?)?,
                    NixStoreRole::ContentAddressedObject => {
                        serde_json::to_value(self.artifacts.admit(request)?)?
                    }
                }
            }
            "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation" => {
                let invocation: Invocation =
                    aos_contract::canonical::from_slice(input, "Nix store database invocation")
                        .context("decoding Nix store database invocation")?;
                ensure!(
                    invocation.schema == INVOCATION_SCHEMA,
                    "unsupported invocation schema"
                );
                ensure!(
                    purpose == purpose_name(invocation.purpose),
                    "invocation purpose differs from argv"
                );
                ensure!(
                    invocation.method_is_bound(),
                    "invocation method differs from durable recovery authority"
                );
                let role = NixStoreRole::from_method(&invocation.method)?;
                match role {
                    NixStoreRole::Database => serde_json::to_value(self.invoke(invocation)?)?,
                    NixStoreRole::ContentAddressedObject => {
                        serde_json::to_value(self.artifacts.invoke(invocation)?)?
                    }
                }
            }
            _ => bail!("unsupported command-handler purpose {purpose:?}"),
        };

        aos_contract::canonical::canonical_json(&result)
            .context("encoding canonical Nix store database response")
    }

    fn admit(&self, request: AdmissionRequest) -> Result<AdmissionResult> {
        validate_method(request.method.method.as_str(), &request.semantics)?;
        validate_admission_resource(&request)?;
        validate_resource_contexts(&request.resources)?;

        let desired: DatabaseRequest = decode_value(&request.resource_spec.value)?;
        validate_request(&desired)?;
        validate_prerequisites(&desired.prerequisites, &request.resources)?;
        let realization: DatabaseRealization = decode_value(&request.resource_spec.realization)?;
        let executable = self.validate_realization(&realization)?;
        let registration = read_registration(desired.registration.as_ref())?;
        let observation = self.observe(
            &request.resource_spec.value,
            &desired,
            &executable,
            registration.as_ref(),
            request.control.attempt_remaining_millis,
        )?;
        let revision = observation_revision(&observation, request.resource_spec.revision)?;
        let native_context = ability_value(json!({
            "schema": PROVIDER_CONTEXT_SCHEMA,
            "executable": executable,
            "registration": registration.as_ref().map(Registration::context),
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
        let supported_purposes = SupportedPurposes::from_ordered(purposes)
            .context("constructing canonical supported purposes")?;

        Ok(AdmissionResult {
            schema: ADMISSION_SCHEMA.into(),
            disposition: AdmissionDisposition::Admitted,
            revision,
            incarnation: Some(request.assignment.incarnation),
            observation,
            native_context,
            supported_purposes,
        })
    }

    fn invoke(&self, invocation: Invocation) -> Result<InvocationResult> {
        ensure!(
            invocation.method_is_bound(),
            "invocation method differs from durable recovery authority"
        );
        validate_method(invocation.method.method.as_str(), &invocation.semantics)?;

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
            "invocation method is outside the target resource authority"
        );
        ensure!(
            bound.resource_spec.value == request.inputs,
            "durable inputs differ from the bound desired request"
        );

        let desired: DatabaseRequest = decode_value(&bound.resource_spec.value)?;
        validate_request(&desired)?;
        validate_prerequisites(&desired.prerequisites, &request.resources)?;
        let realization: DatabaseRealization = decode_value(&bound.resource_spec.realization)?;
        let executable = self.validate_realization(&realization)?;
        let context: ProviderContext = decode_value(&bound.provider_context)?;
        ensure!(
            context.schema == PROVIDER_CONTEXT_SCHEMA,
            "unsupported Nix store provider context"
        );
        ensure!(
            context.executable == executable,
            "selected Nix executable differs from admitted context"
        );
        let registration = read_registration(desired.registration.as_ref())?;
        ensure!(
            registration.as_ref().map(Registration::context) == context.registration,
            "registration stream differs from admitted context"
        );

        let observation_before = self.observe(
            &bound.resource_spec.value,
            &desired,
            &executable,
            registration.as_ref(),
            invocation.control.attempt_remaining_millis,
        )?;
        let (disposition, evidence, mut outputs) = match invocation.purpose {
            InvocationPurpose::Effect if invocation.method.method.as_str() == "observe" => (
                InvocationDisposition::Completed,
                observation_before,
                BTreeMap::new(),
            ),
            InvocationPurpose::Effect if invocation.control.cancelled => (
                InvocationDisposition::RejectedBeforeEffect,
                observation_before,
                BTreeMap::new(),
            ),
            InvocationPurpose::Effect => {
                self.apply(
                    &executable,
                    registration.as_ref(),
                    invocation.control.attempt_remaining_millis,
                )?;
                let evidence = self.observe(
                    &bound.resource_spec.value,
                    &desired,
                    &executable,
                    registration.as_ref(),
                    invocation.control.attempt_remaining_millis,
                )?;
                if observation_state(&evidence) == Some(DatabaseState::Ready) {
                    (
                        InvocationDisposition::Completed,
                        evidence,
                        successful_outputs(&request.target)?,
                    )
                } else {
                    (
                        InvocationDisposition::Indeterminate,
                        evidence,
                        BTreeMap::new(),
                    )
                }
            }
            InvocationPurpose::Reconcile => match observation_state(&observation_before) {
                Some(DatabaseState::Ready) => (
                    InvocationDisposition::Completed,
                    observation_before,
                    successful_outputs(&request.target)?,
                ),
                Some(DatabaseState::Absent | DatabaseState::Degraded) => (
                    InvocationDisposition::SafeToRetry,
                    observation_before,
                    BTreeMap::new(),
                ),
                Some(DatabaseState::Unknown) | None => (
                    InvocationDisposition::StillIndeterminate,
                    observation_before,
                    BTreeMap::new(),
                ),
            },
            InvocationPurpose::Cancel => match observation_state(&observation_before) {
                Some(DatabaseState::Ready) => (
                    InvocationDisposition::Completed,
                    observation_before,
                    successful_outputs(&request.target)?,
                ),
                Some(DatabaseState::Absent) => (
                    InvocationDisposition::RejectedBeforeEffect,
                    observation_before,
                    BTreeMap::new(),
                ),
                Some(DatabaseState::Degraded | DatabaseState::Unknown) | None => (
                    InvocationDisposition::Indeterminate,
                    observation_before,
                    BTreeMap::new(),
                ),
            },
            InvocationPurpose::Compensate => (
                InvocationDisposition::RejectedBeforeEffect,
                observation_before,
                BTreeMap::new(),
            ),
            InvocationPurpose::ReconcileCompensation => (
                InvocationDisposition::InterventionRequired,
                observation_before,
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

    fn validate_realization(&self, realization: &DatabaseRealization) -> Result<Executable> {
        ensure!(
            realization.schema == REALIZATION_SCHEMA,
            "unsupported Nix store database realization"
        );
        ensure!(
            realization.nix_store.arguments.is_empty(),
            "the Nix store executable must not carry undeclared arguments"
        );
        let executable = Executable {
            artifact: realization.nix_store.artifact.clone(),
            entry_point: realization.nix_store.entry_point.clone(),
        };
        executable.validate(self.validate_executable_file)?;
        Ok(executable)
    }

    fn observe(
        &self,
        expected: &AbilityValue,
        desired: &DatabaseRequest,
        executable: &Executable,
        registration: Option<&Registration>,
        remaining_millis: u64,
    ) -> Result<AbilityValue> {
        let initialized = database_is_regular(&self.database_path)?;
        let registration_digest = registration.map(|value| value.digest.to_string());
        let (registration_state, state) = if !initialized {
            (
                registration_missing_state(desired, registration),
                DatabaseState::Absent,
            )
        } else if let Some(registration) = registration {
            match self
                .commands
                .records_match(executable, &registration.records, remaining_millis)
            {
                Ok(true) => (RegistrationState::Loaded, DatabaseState::Ready),
                Ok(false) => (RegistrationState::Partial, DatabaseState::Degraded),
                Err(_) => (RegistrationState::Unknown, DatabaseState::Unknown),
            }
        } else if desired
            .registration
            .as_ref()
            .is_some_and(|value| value.required)
        {
            (RegistrationState::Absent, DatabaseState::Degraded)
        } else {
            match self.commands.probe(executable, remaining_millis) {
                Ok(()) => (
                    registration_missing_state(desired, None),
                    DatabaseState::Ready,
                ),
                Err(_) => (RegistrationState::Unknown, DatabaseState::Unknown),
            }
        };

        ability_value(json!({
            "schema": OBSERVATION_SCHEMA,
            "expected": expected.as_json(),
            "initialized": initialized,
            "registration_digest": registration_digest,
            "registration_state": registration_state,
            "state": state,
        }))
    }

    fn apply(
        &self,
        executable: &Executable,
        registration: Option<&Registration>,
        remaining_millis: u64,
    ) -> Result<()> {
        let deadline = deadline(remaining_millis)?;
        self.commands
            .initialize(executable, remaining(deadline)?)
            .context("initializing the local Nix store database")?;
        if let Some(registration) = registration {
            self.commands
                .load(executable, &registration.bytes, remaining(deadline)?)
                .context("loading the admitted Nix registration stream")?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn test(database_path: PathBuf, commands: Box<dyn StoreCommands>) -> Self {
        Self {
            artifacts: ContentArtifactProvider::production(),
            database_path,
            commands,
            validate_executable_file: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum DatabaseScope {
    Local,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct DatabaseRequest {
    scope: DatabaseScope,
    #[serde(default)]
    registration: Option<RegistrationInput>,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RegistrationInput {
    path: String,
    required: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseRealization {
    schema: String,
    nix_store: ExecutableReference,
}

#[derive(Clone, Debug, Deserialize)]
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
}

impl Executable {
    pub(super) fn path(&self) -> PathBuf {
        Path::new(&self.artifact.store_path).join(&self.entry_point)
    }

    fn validate(&self, inspect_file: bool) -> Result<()> {
        let root = Path::new(&self.artifact.store_path);
        ensure!(
            root.is_absolute() && root.starts_with("/nix/store"),
            "Nix executable artifact is outside the immutable store"
        );
        let relative = Path::new(&self.entry_point);
        ensure!(
            !self.entry_point.is_empty()
                && !relative.is_absolute()
                && relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "Nix executable entry point is not a normalized relative path"
        );
        if !inspect_file {
            return Ok(());
        }

        let expected = self.path();
        let root = fs::canonicalize(root).context("resolving Nix artifact root")?;
        let resolved = fs::canonicalize(&expected).context("resolving Nix executable")?;
        ensure!(
            resolved.starts_with(&root),
            "Nix executable resolves outside its authenticated artifact"
        );
        let metadata = fs::metadata(&resolved).context("inspecting Nix executable")?;
        ensure!(metadata.is_file(), "Nix executable is not a regular file");
        ensure!(
            metadata.permissions().mode() & 0o111 != 0,
            "Nix executable is not executable"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    schema: String,
    executable: Executable,
    registration: Option<RegistrationContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistrationContext {
    path: String,
    digest: Sha256Digest,
    records: u64,
}

struct Registration {
    path: String,
    bytes: Vec<u8>,
    digest: Sha256Digest,
    records: BTreeMap<String, RegistrationRecord>,
}

impl Registration {
    fn context(&self) -> RegistrationContext {
        RegistrationContext {
            path: self.path.clone(),
            digest: self.digest,
            records: self.records.len() as u64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RegistrationRecord {
    path: String,
    nar_hash: String,
    nar_size: u64,
    deriver: String,
    references: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RegistrationState {
    Absent,
    Loaded,
    NotRequested,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DatabaseState {
    Absent,
    Degraded,
    Ready,
    Unknown,
}

pub(super) trait StoreCommands: Send + Sync {
    fn probe(&self, executable: &Executable, remaining_millis: u64) -> Result<()>;

    fn records_match(
        &self,
        executable: &Executable,
        expected: &BTreeMap<String, RegistrationRecord>,
        remaining_millis: u64,
    ) -> Result<bool>;

    fn initialize(&self, executable: &Executable, remaining_millis: u64) -> Result<()>;

    fn load(
        &self,
        executable: &Executable,
        registration: &[u8],
        remaining_millis: u64,
    ) -> Result<()>;
}

fn read_registration(input: Option<&RegistrationInput>) -> Result<Option<Registration>> {
    let Some(input) = input else {
        return Ok(None);
    };
    let path = Path::new(&input.path);
    ensure!(path.is_absolute(), "registration path is not absolute");
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !input.required => {
            return Ok(None);
        }
        Err(error) => return Err(error).context("inspecting Nix registration stream"),
    };
    ensure!(
        metadata.is_file(),
        "Nix registration stream is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_REGISTRATION_BYTES,
        "Nix registration stream exceeds its bound"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .context("opening Nix registration stream")?
        .take(MAX_REGISTRATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("reading Nix registration stream")?;
    ensure!(
        bytes.len() as u64 <= MAX_REGISTRATION_BYTES,
        "Nix registration stream grew beyond its bound"
    );
    let records = parse_registration(&bytes)?;
    Ok(Some(Registration {
        path: input.path.clone(),
        digest: Sha256Digest::of_bytes(&bytes),
        bytes,
        records,
    }))
}

pub(super) fn parse_registration(bytes: &[u8]) -> Result<BTreeMap<String, RegistrationRecord>> {
    let text = std::str::from_utf8(bytes).context("registration stream is not UTF-8")?;
    ensure!(
        text.is_empty() || text.ends_with('\n'),
        "registration stream has a truncated final line"
    );
    let mut lines = text.lines();
    let mut records = BTreeMap::new();
    while let Some(path) = lines.next() {
        ensure!(
            records.len() < MAX_REGISTRATION_RECORDS,
            "registration stream contains too many records"
        );
        validate_store_path(path)?;
        let nar_hash = next_line(&mut lines, "NAR hash")?;
        ensure!(
            !nar_hash.is_empty() && nar_hash.bytes().all(|byte| byte.is_ascii_graphic()),
            "registration NAR hash is invalid"
        );
        let nar_size = next_line(&mut lines, "NAR size")?
            .parse::<u64>()
            .context("registration NAR size is invalid")?;
        let deriver = next_line(&mut lines, "deriver")?;
        if !deriver.is_empty() {
            validate_store_path(deriver)?;
        }
        let reference_count = next_line(&mut lines, "reference count")?
            .parse::<usize>()
            .context("registration reference count is invalid")?;
        ensure!(
            reference_count <= MAX_REGISTRATION_RECORDS,
            "registration record contains too many references"
        );
        let mut references = Vec::with_capacity(reference_count);
        for _ in 0..reference_count {
            let reference = next_line(&mut lines, "reference")?;
            validate_store_path(reference)?;
            references.push(reference.to_string());
        }
        let record = RegistrationRecord {
            path: path.to_string(),
            nar_hash: nar_hash.to_string(),
            nar_size,
            deriver: deriver.to_string(),
            references,
        };
        ensure!(
            records.insert(path.to_string(), record).is_none(),
            "registration stream repeats a store path"
        );
    }
    Ok(records)
}

fn next_line<'a>(lines: &mut impl Iterator<Item = &'a str>, field: &str) -> Result<&'a str> {
    lines
        .next()
        .with_context(|| format!("registration stream ends before {field}"))
}

fn validate_store_path(path: &str) -> Result<()> {
    let parsed = Path::new(path);
    ensure!(
        parsed.is_absolute()
            && parsed.parent() == Some(Path::new("/nix/store"))
            && parsed.file_name().is_some_and(|name| !name.is_empty()),
        "registration contains an invalid store path"
    );
    Ok(())
}

fn validate_request(request: &DatabaseRequest) -> Result<()> {
    ensure!(
        request.scope == DatabaseScope::Local,
        "the Nix store database provider only supports the local store"
    );
    ensure!(
        request.prerequisites.len() <= 64,
        "too many Nix store database prerequisites"
    );
    let encoded = request
        .prerequisites
        .iter()
        .map(serde_json::to_vec)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        encoded.windows(2).all(|pair| pair[0] < pair[1]),
        "Nix store database prerequisites are not canonical and unique"
    );
    Ok(())
}

fn validate_method(method: &str, semantics: &MethodSemantics) -> Result<()> {
    let access = match method {
        "converge" => AccessMode::ExclusiveWrite,
        "observe" => AccessMode::Read,
        _ => bail!("selected Nix store database method is unsupported"),
    };
    ensure!(
        *semantics == MethodSemantics::ordinary(access),
        "selected Nix store database method semantics differ"
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

fn observation_revision(
    observation: &AbilityValue,
    desired: RevisionId,
) -> Result<AdmissionRevision> {
    match observation_state(observation) {
        Some(DatabaseState::Ready) => Ok(AdmissionRevision::Present { revision: desired }),
        Some(DatabaseState::Absent) => Ok(AdmissionRevision::Absent),
        Some(DatabaseState::Degraded) => {
            let digest =
                Sha256Digest::of_canonical("aos.nix.store-database-observed/v1", observation)?;
            Ok(AdmissionRevision::Present {
                revision: RevisionId(digest),
            })
        }
        Some(DatabaseState::Unknown) | None => Ok(AdmissionRevision::Unknown),
    }
}

fn observation_state(observation: &AbilityValue) -> Option<DatabaseState> {
    serde_json::from_value(observation.as_json().get("state")?.clone()).ok()
}

fn registration_missing_state(
    desired: &DatabaseRequest,
    registration: Option<&Registration>,
) -> RegistrationState {
    if desired.registration.is_none() {
        RegistrationState::NotRequested
    } else if registration.is_none() {
        RegistrationState::Absent
    } else {
        RegistrationState::Unknown
    }
}

fn database_is_regular(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspecting local Nix store database"),
    }
}

fn successful_outputs(target: &ResourceReference) -> Result<BTreeMap<LocalKey, AbilityValue>> {
    let mut outputs = BTreeMap::new();
    outputs.insert(
        LocalKey::new("retained-resource")?,
        ability_value(serde_json::to_value(target)?)?,
    );
    Ok(outputs)
}

pub(super) fn deadline(remaining_millis: u64) -> Result<Instant> {
    ensure!(remaining_millis > 0, "operation deadline expired");
    monotonic_now()
        .checked_add(Duration::from_millis(remaining_millis))
        .context("operation deadline overflow")
}

pub(super) fn remaining(deadline: Instant) -> Result<u64> {
    let millis = deadline
        .checked_duration_since(monotonic_now())
        .context("operation deadline expired")?
        .as_millis();
    u64::try_from(millis.max(1)).context("operation deadline is too large")
}

// Monotonic time bounds a live subprocess only; it never enters provider state.
#[allow(clippy::disallowed_methods)]
pub(super) fn monotonic_now() -> Instant {
    Instant::now()
}

pub(super) fn ability_value(value: serde_json::Value) -> Result<AbilityValue> {
    AbilityValue::new(value).context("constructing canonical ability value")
}

pub(super) fn decode_value<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding checked ability value")
}

pub(super) const fn purpose_name(purpose: InvocationPurpose) -> &'static str {
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
    use std::sync::Mutex;

    use tempfile::tempdir;

    use super::*;

    const SAMPLE: &str = concat!(
        "/nix/store/00000000000000000000000000000000-root\n",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        "42\n",
        "\n",
        "1\n",
        "/nix/store/11111111111111111111111111111111-child\n",
        "/nix/store/11111111111111111111111111111111-child\n",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n",
        "21\n",
        "\n",
        "0\n",
    );

    #[derive(Default)]
    struct FakeCommands {
        records: Mutex<BTreeMap<String, RegistrationRecord>>,
        initialized: Mutex<bool>,
    }

    impl StoreCommands for FakeCommands {
        fn probe(&self, _: &Executable, _: u64) -> Result<()> {
            ensure!(
                *self.initialized.lock().map_err(lock_error)?,
                "not initialized"
            );
            Ok(())
        }

        fn records_match(
            &self,
            _: &Executable,
            expected: &BTreeMap<String, RegistrationRecord>,
            _: u64,
        ) -> Result<bool> {
            Ok(*self.records.lock().map_err(lock_error)? == *expected)
        }

        fn initialize(&self, _: &Executable, _: u64) -> Result<()> {
            *self.initialized.lock().map_err(lock_error)? = true;
            Ok(())
        }

        fn load(&self, _: &Executable, registration: &[u8], _: u64) -> Result<()> {
            *self.records.lock().map_err(lock_error)? = parse_registration(registration)?;
            Ok(())
        }
    }

    fn lock_error<T>(_: std::sync::PoisonError<T>) -> anyhow::Error {
        anyhow::anyhow!("test lock is poisoned")
    }

    fn method(interface: &str) -> MethodReference {
        serde_json::from_value(json!({
            "interface": {
                "name": interface,
                "abi": 1,
                "descriptor": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "method": "observe"
        }))
        .expect("method fixture is valid")
    }

    #[test]
    fn authenticated_interfaces_select_only_package_declared_roles() {
        assert_eq!(
            NixStoreRole::from_method(&method(DATABASE_INTERFACE))
                .expect("database interface selects its role"),
            NixStoreRole::Database
        );
        assert_eq!(
            NixStoreRole::from_method(&method(CONTENT_OBJECT_INTERFACE))
                .expect("content interface selects its role"),
            NixStoreRole::ContentAddressedObject
        );
        assert!(
            NixStoreRole::from_method(&method("aos.artifact.content-addressed-object")).is_err(),
            "the public resource interface must not select a terminal role"
        );
        assert!(
            NixStoreRole::from_method(&method("aos.example.unowned-effects")).is_err(),
            "an unowned interface must not select a role"
        );
    }

    #[test]
    fn registration_parser_retains_exact_database_records() {
        let records = parse_registration(SAMPLE.as_bytes()).expect("registration parses");

        assert_eq!(records.len(), 2);
        assert_eq!(records.values().next().expect("root exists").nar_size, 42);
        assert_eq!(
            records.values().next().expect("root exists").references,
            ["/nix/store/11111111111111111111111111111111-child"]
        );
    }

    #[test]
    fn registration_parser_rejects_truncation_and_duplicate_paths() {
        let truncated = SAMPLE.trim_end_matches('\n').as_bytes();
        assert!(parse_registration(truncated).is_err());

        let duplicate = format!("{SAMPLE}{SAMPLE}");
        assert!(parse_registration(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn apply_loads_the_exact_registration_before_reporting_ready() {
        let temporary = tempdir().expect("temporary directory exists");
        let registration_path = temporary.path().join("registration");
        fs::write(&registration_path, SAMPLE).expect("registration is written");
        let database_path = temporary.path().join("db.sqlite");
        fs::write(&database_path, []).expect("database marker is written");
        let desired = DatabaseRequest {
            scope: DatabaseScope::Local,
            registration: Some(RegistrationInput {
                path: registration_path.display().to_string(),
                required: true,
            }),
            prerequisites: Vec::new(),
        };
        let registration = read_registration(desired.registration.as_ref())
            .expect("registration can be read")
            .expect("registration exists");
        let expected = ability_value(
            serde_json::to_value(json!({
                "scope": "local",
                "registration": {
                    "path": registration_path,
                    "required": true,
                },
                "prerequisites": [],
            }))
            .expect("request serializes"),
        )
        .expect("request is bounded");
        let executable = Executable {
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes(b"content"),
                store_path: "/nix/store/00000000000000000000000000000000-nix".into(),
                nar_hash: Sha256Digest::of_bytes(b"nar"),
                closure: Sha256Digest::of_bytes(b"closure"),
            },
            entry_point: "bin/nix-store".into(),
        };
        let provider = NixStoreProvider::test(
            database_path,
            Box::new(FakeCommands {
                initialized: Mutex::new(true),
                ..FakeCommands::default()
            }),
        );

        let before = provider
            .observe(&expected, &desired, &executable, Some(&registration), 1_000)
            .expect("initial state observes");
        assert_eq!(observation_state(&before), Some(DatabaseState::Degraded));

        provider
            .apply(&executable, Some(&registration), 1_000)
            .expect("registration loads");
        let after = provider
            .observe(&expected, &desired, &executable, Some(&registration), 1_000)
            .expect("loaded state observes");
        assert_eq!(observation_state(&after), Some(DatabaseState::Ready));
    }

    #[test]
    fn argument_batches_bound_process_argv() {
        let paths = (0..1_100)
            .map(|index| format!("/nix/store/{index:032}-package"))
            .collect::<Vec<_>>();
        let batches = argument_batches(paths.iter().map(String::as_str));

        assert_eq!(batches.len(), 3);
        assert!(batches.iter().all(|batch| batch.len() <= 512));
        assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), paths.len());
    }
}
