//! Trusted nginx candidate validation and generation association.
//!
//! Native orchestration supplies the exact candidate bytes for each logical
//! resource. Its typed request also carries protected credential views from
//! exact checked producers. The adapter authenticates those views, binds them
//! to the candidate's TLS directives, executes the authenticated nginx artifact
//! by absolute path, bounds process lifetime, and records the candidate and
//! credential digests validated for an exact desired generation. Its durable
//! formats are:
//!
//! ```text
//! {"schema":"aos.ability.nginx-request/v2",...}
//! {"schema":"aos.ability.nginx-validation/v2",...}
//! {"schema":"aos.ability.nginx-generation-association/v2",...}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aos_ability_model::builtin::credential_view_schema;
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityActivationMode, AbilityValue, ArtifactReference, ExecutionStage,
    InterfaceKey, InterfaceName, LocalKey, MethodReference, Operation, OperationFamily,
    ProviderAssignment, ProviderImplementationReference, ResourceAccess, ResourceId, RevisionId,
    ValueSchema,
};
use aos_ability_plan::{RuntimeResourceHealth, RuntimeResourceState};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose, ReconcileDisposition, ReservationContext,
    ResourceAdmissionEvidence, ResourceHandle, ResourceRevisionObservation, RuntimeControl,
    TrustedAdapter, TrustedResourceCatalog,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::ability_package::VerifiedAbilityPackage;
use crate::config_eval::ability_store::inventory::require_machine_global_host_collision_domain;
use crate::config_eval::ability_store::{
    GenerationAbilityStoreError, NativeQualifiedResource, NativeResourceInventory,
    NativeResourceReservation,
};
use crate::config_eval::native_ability_fs::{RootedDirectory, RootedFile};
use crate::config_eval::native_host_resources::{
    CredentialEvidence, NativeDependencyBinding, authenticate_credential_dependency_view,
    authenticate_credential_view_evidence,
};

const INTERFACE_NAME: &str = "aos.nginx-validation";
pub(super) const INTERFACE_DESCRIPTOR: &str =
    "sha256:c781b7f06eabaa9386ab0438f150b028e98b6d07ad78a907a567d27ee14602a6";
const HANDLER_KEY: &str = "nginx-terminal";
const ENTRY_POINT: &str = "bin/nginx";
const REQUEST_SCHEMA: &str = "aos.ability.nginx-request/v2";
const VALIDATION_SCHEMA: &str = "aos.ability.nginx-validation/v2";
const ASSOCIATION_SCHEMA: &str = "aos.ability.nginx-generation-association/v2";
const MAX_ASSOCIATION_BYTES: u64 = ABILITY_LIMITS_V1.max_document_bytes;

/// Binds a logical nginx resource to exact candidate bytes and one generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxResourceSpec {
    /// Names the logical resource declared by the checked provider.
    pub resource: ResourceId,
    /// Names the terminal handler selected for this logical owner.
    pub handler_provider: aos_ability_model::InstanceId,
    /// Names the independently authorized validation working directory.
    pub validation_prefix: PathBuf,
    /// Carries the exact configuration bytes selected by native orchestration.
    pub candidate: Vec<u8>,
    /// Identifies the currently selected generation, when one exists.
    pub current_generation: Option<RevisionId>,
    /// Commits to the candidate associated with the current generation.
    pub current_candidate_digest: Option<Sha256Digest>,
    /// Identifies the desired generation, or is absent for release.
    pub desired_generation: Option<RevisionId>,
    /// Pins the credential producers authorized for candidate validation.
    pub(crate) credential_dependencies: Vec<NativeDependencyBinding>,
}

#[derive(Clone, Debug)]
struct QualifiedNginxResource {
    spec: NginxResourceSpec,
    candidate_path: RootedFile,
    validation_path: RootedFile,
    association_path: RootedFile,
    validation_prefix: RootedDirectory,
    candidate_digest: Sha256Digest,
    implementation: ProviderImplementationReference,
    qualified: NativeQualifiedResource,
}

/// A fresh lock-bound handle for one nginx generation association.
#[derive(Debug)]
pub struct NginxResourceHandle {
    resource: QualifiedNginxResource,
    action: NginxAction,
    reservation: NativeResourceReservation,
}

/// Resolves nginx logical resources to trusted candidates and association records.
pub struct NginxResourceCatalog {
    assignment: ProviderAssignment,
    inventory: NativeResourceInventory,
    resources: BTreeMap<ResourceId, QualifiedNginxResource>,
}

impl NginxResourceCatalog {
    /// Constructs a catalog under an existing canonical private-state root.
    ///
    /// The state root must contain canonical `candidates`, `validations`, and
    /// `associations` directories created by native orchestration. Each resource
    /// separately names its operator-authorized validation working directory.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe state paths, empty candidates, resources
    /// owned by another provider, duplicate logical or physical records, or a
    /// host execution domain outside the machine-global collision ledger.
    pub fn new(
        private_state_root: impl AsRef<Path>,
        assignment: ProviderAssignment,
        inventory: NativeResourceInventory,
        trusted_owner: u32,
        resources: impl IntoIterator<Item = NginxResourceSpec>,
    ) -> Result<Self, io::Error> {
        if trusted_owner != 0 || assignment.provider.environment.stage != ExecutionStage::Host {
            return Err(invalid_data(
                "nginx validation supports only the root-owned host execution view",
            ));
        }
        require_machine_global_host_collision_domain()?;
        let private_state_root = RootedDirectory::open(
            private_state_root.as_ref(),
            trusted_owner,
            "nginx state root",
        )?;
        let candidate_root = existing_private_directory(&private_state_root, "candidates")?;
        let validation_root = existing_private_directory(&private_state_root, "validations")?;
        let association_root = existing_private_directory(&private_state_root, "associations")?;

        let mut association_paths = BTreeSet::new();
        let mut validation_prefixes = BTreeSet::new();
        let mut indexed = BTreeMap::new();
        for spec in resources {
            if spec.handler_provider != assignment.provider {
                return Err(invalid_data("nginx resource belongs to another provider"));
            }
            if spec.current_generation.is_some() != spec.current_candidate_digest.is_some() {
                return Err(invalid_data(
                    "nginx current generation and candidate commitment must appear together",
                ));
            }
            if spec.desired_generation.is_some() && spec.candidate.is_empty() {
                return Err(invalid_data("nginx candidate is empty"));
            }
            let validation_prefix = RootedDirectory::open(
                &spec.validation_prefix,
                trusted_owner,
                "nginx validation prefix",
            )?;
            if !validation_prefixes.insert(validation_prefix.display().to_path_buf()) {
                return Err(invalid_data(
                    "distinct nginx resources share a validation prefix",
                ));
            }
            let candidate_digest = Sha256Digest::of_bytes(&spec.candidate);
            let candidate_path = candidate_root.child(candidate_digest.to_string())?;
            let resource_digest =
                Sha256Digest::of_canonical("aos.ability.nginx-resource/v1", &spec.resource)
                    .map_err(|error| invalid_data(error.to_string()))?;
            let association_path = association_root.child(resource_digest.to_string())?;
            let validation_path = validation_root.child(format!(
                "{}-{}",
                resource_digest,
                spec.desired_generation
                    .map(|revision| revision.0.to_string())
                    .unwrap_or_else(|| "release".to_string())
            ))?;
            if !association_paths.insert(association_path.display().to_path_buf()) {
                return Err(invalid_data(
                    "distinct nginx resources share an association record",
                ));
            }
            let object = validation_prefix
                .display()
                .to_str()
                .ok_or_else(|| invalid_data("nginx validation prefix is not UTF-8"))?;
            let qualified =
                NativeQualifiedResource::nginx_validation_prefix(spec.resource.clone(), object)
                    .map_err(store_error)?;
            let logical = spec.resource.clone();
            if indexed
                .insert(
                    logical,
                    QualifiedNginxResource {
                        spec,
                        candidate_path,
                        validation_path,
                        association_path,
                        validation_prefix: validation_prefix.clone(),
                        candidate_digest,
                        implementation: assignment.implementation.clone(),
                        qualified,
                    },
                )
                .is_some()
            {
                return Err(invalid_data("nginx catalog contains a duplicate resource"));
            }
        }
        Ok(Self {
            assignment,
            inventory,
            resources: indexed,
        })
    }

    /// Returns the exact logical-to-native qualification for a catalog member.
    #[must_use]
    pub fn qualified_resource(&self, resource: &ResourceId) -> Option<NativeQualifiedResource> {
        self.resources
            .get(resource)
            .map(|entry| entry.qualified.clone())
    }

    /// Returns the trusted candidate bytes and generation for a catalog member.
    #[must_use]
    pub fn resource_spec(&self, resource: &ResourceId) -> Option<&NginxResourceSpec> {
        self.resources.get(resource).map(|entry| &entry.spec)
    }

    /// Classifies an association only when its ownership is unambiguous.
    ///
    /// # Errors
    ///
    /// Returns an error when the resource is absent from the catalog, its
    /// association cannot be inspected, or its ownership evidence is foreign.
    pub(crate) fn classify_runtime_revision(
        &self,
        resource: &ResourceId,
    ) -> Result<(NativeQualifiedResource, RuntimeResourceState), io::Error> {
        let resource = self
            .resources
            .get(resource)
            .ok_or_else(|| invalid_data("nginx runtime resource is not cataloged"))?;
        let observation = observe_association(resource)?;
        let state = match observation {
            ResourceRevisionObservation::Absent => RuntimeResourceState::Absent,
            ResourceRevisionObservation::Present(revision) => RuntimeResourceState::Present {
                revision,
                health: RuntimeResourceHealth::Healthy,
            },
            ResourceRevisionObservation::Unknown => {
                return Err(invalid_data("nginx association evidence is foreign"));
            }
        };
        Ok((resource.qualified.clone(), state))
    }
}

impl TrustedResourceCatalog for NginxResourceCatalog {
    type Handle = NginxResourceHandle;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        if context
            .expected_provider
            .is_some_and(|assignment| assignment != &self.assignment)
        {
            return Err(invalid_data("nginx provider assignment is absent or stale"));
        }
        if operation.target.resource != access.resource {
            return Err(invalid_data(
                "nginx access does not target the operation resource",
            ));
        }
        let context = ReservationContext {
            expected_provider: Some(&self.assignment),
            ..context
        };
        let resource = self
            .resources
            .get(&access.resource)
            .ok_or_else(|| invalid_data("nginx resource is outside the authorized catalog"))?
            .clone();
        let action = action_for(operation)?;
        validate_action_spec(&action, &resource.spec)?;
        let reservation = self
            .inventory
            .reserve(&resource.qualified, context, operation, access)
            .map_err(store_error)?;
        let state = match observe_association(&resource)? {
            ResourceRevisionObservation::Absent => RuntimeResourceState::Absent,
            ResourceRevisionObservation::Present(revision) => RuntimeResourceState::Present {
                revision,
                health: RuntimeResourceHealth::Healthy,
            },
            ResourceRevisionObservation::Unknown => {
                return Err(invalid_data("nginx association evidence is foreign"));
            }
        };
        let revision = match state {
            RuntimeResourceState::Absent => ResourceRevisionObservation::Absent,
            RuntimeResourceState::Present { revision, .. } => {
                ResourceRevisionObservation::Present(revision)
            }
        };
        let evidence = ResourceAdmissionEvidence::new_with_revision_observation(
            access.resource.clone(),
            Some(self.assignment.incarnation.clone()),
            revision,
            boolean_value(revision == expected_current(&resource.spec))?,
        );
        Ok(CatalogReservation::new(
            NginxResourceHandle {
                resource,
                action,
                reservation,
            },
            evidence,
        ))
    }

    fn release(
        &mut self,
        resource: &ResourceId,
        handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        if handle.reservation.logical() != resource {
            return Err(invalid_data(
                "nginx release does not match its native reservation",
            ));
        }
        handle.reservation.release().map_err(store_error)
    }
}

/// Durable nginx request reconstructed with a fresh native resource handle.
#[derive(Clone, Debug)]
pub struct NginxRequest {
    durable: NginxDurableRequest,
    resource: QualifiedNginxResource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum NginxAction {
    Validate,
    Record,
    Release,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NginxDurableRequest {
    schema: String,
    action: NginxAction,
    resource: ResourceId,
    current_generation: Option<RevisionId>,
    current_candidate_digest: Option<Sha256Digest>,
    desired_generation: Option<RevisionId>,
    candidate_digest: Sha256Digest,
    implementation: ProviderImplementationReference,
    validation_prefix: String,
    credential_evidence: Vec<CredentialEvidence>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NginxValidationInput {
    candidate: bool,
    credential_views: Vec<CredentialViewInput>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialViewInput {
    path: String,
    version: String,
}

/// Boolean completion or observation evidence for an nginx terminal call.
#[derive(Clone, Debug)]
pub struct NginxRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for NginxRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for NginxRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

/// Executes authenticated nginx validation and association methods.
pub struct NativeNginxAdapter {
    assignment: ProviderAssignment,
    executable: PathBuf,
    success: NginxRecord,
    failure: NginxRecord,
}

impl NativeNginxAdapter {
    /// Constructs an adapter from one exact sealed nginx terminal assignment.
    ///
    /// # Errors
    ///
    /// Returns an error unless the package and assignment resolve the exact
    /// nginx validation interface, handler, artifact, and executable entry point.
    pub fn new(
        package: &VerifiedAbilityPackage,
        assignment: ProviderAssignment,
    ) -> Result<Self, io::Error> {
        let executable = authenticate(package, &assignment)?;
        Ok(Self {
            assignment,
            executable,
            success: record(true)?,
            failure: record(false)?,
        })
    }
}

impl TrustedAdapter for NativeNginxAdapter {
    type Request = NginxRequest;
    type Completion = NginxRecord;
    type Observation = NginxRecord;
    type Handle = NginxResourceHandle;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> bool {
        implementation == &self.assignment.implementation
            && method.interface == self.assignment.interface
            && matches!(
                purpose,
                InvocationPurpose::Effect
                    | InvocationPurpose::Reconcile
                    | InvocationPurpose::Cancel
            )
            && matches!(method.method.as_str(), "validate" | "record" | "release")
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        if operation.interface != self.assignment.interface {
            return Err(invalid_data("nginx operation uses another interface"));
        }
        let action = action_for(operation)?;
        let input = decode_validation_input(inputs, &action)?;
        let [resource] = resources else {
            return Err(invalid_data(
                "nginx operation requires exactly one resource",
            ));
        };
        if resource.resource() != &operation.target.resource {
            return Err(invalid_data(
                "nginx handle does not match the operation target",
            ));
        }
        if resource.native().action != action {
            return Err(invalid_data(
                "nginx handle was acquired for another operation family",
            ));
        }
        validate_action_spec(&action, &resource.native().resource.spec)?;
        let credential_evidence = match action {
            NginxAction::Validate => authenticate_credential_inputs(
                &input.credential_views,
                &resource.native().resource.spec.credential_dependencies,
            )?,
            NginxAction::Record | NginxAction::Release => Vec::new(),
        };
        if action == NginxAction::Validate {
            validate_candidate_credential_paths(
                &resource.native().resource.spec.candidate,
                &credential_evidence,
            )?;
        }
        encode_request(durable_request(
            action,
            &resource.native().resource,
            credential_evidence,
        )?)
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        let request: NginxDurableRequest = serde_json::from_value(durable.as_json().clone())
            .map_err(|error| invalid_data(format!("invalid durable nginx request: {error}")))?;
        if request.schema != REQUEST_SCHEMA {
            return Err(invalid_data("unsupported durable nginx request schema"));
        }
        let [resource] = resources else {
            return Err(invalid_data("nginx recovery requires exactly one resource"));
        };
        validate_recovered_request(
            &request,
            &resource.native().action,
            &resource.native().resource,
        )?;
        if request.action == NginxAction::Validate {
            authenticate_credential_evidence(
                &request.credential_evidence,
                &resource.native().resource.spec.credential_dependencies,
            )?;
            validate_candidate_credential_paths(
                &resource.native().resource.spec.candidate,
                &request.credential_evidence,
            )?;
        }
        Ok(NginxRequest {
            durable: request,
            resource: resource.native().resource.clone(),
        })
    }

    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        if control.is_cancelled() {
            return EffectDisposition::RejectedBeforeEffect(self.failure.clone());
        }
        match request.durable.action {
            NginxAction::Validate => {
                match authenticate_request_credentials(request).and_then(|()| {
                    validate_candidate(
                        &self.executable,
                        &request.resource,
                        &request.durable.credential_evidence,
                        control,
                    )
                }) {
                    Ok(()) => EffectDisposition::Completed(self.success.clone()),
                    Err(_) => EffectDisposition::Indeterminate(self.failure.clone()),
                }
            }
            NginxAction::Record => match record_association(&request.resource) {
                Ok(()) => EffectDisposition::Completed(self.success.clone()),
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    EffectDisposition::RejectedBeforeEffect(self.failure.clone())
                }
                Err(_) => EffectDisposition::Indeterminate(self.failure.clone()),
            },
            NginxAction::Release => match release_association(&request.resource) {
                Ok(()) => EffectDisposition::Completed(self.success.clone()),
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    EffectDisposition::RejectedBeforeEffect(self.failure.clone())
                }
                Err(_) => EffectDisposition::Indeterminate(self.failure.clone()),
            },
        }
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        match reconcile_request(request) {
            Ok(ReconcileState::Completed) => ReconcileDisposition::Completed(self.success.clone()),
            Ok(ReconcileState::SafeToRetry) => {
                ReconcileDisposition::SafeToRetry(self.failure.clone())
            }
            Ok(ReconcileState::Intervention) | Err(_) => {
                ReconcileDisposition::InterventionRequired(self.failure.clone())
            }
        }
    }

    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        match self.reconcile(request, control) {
            ReconcileDisposition::Completed(record) => CancellationDisposition::Completed(record),
            ReconcileDisposition::SafeToRetry(record)
            | ReconcileDisposition::RejectedBeforeEffect(record) => {
                CancellationDisposition::RejectedBeforeEffect(record)
            }
            ReconcileDisposition::StillIndeterminate(record)
            | ReconcileDisposition::InterventionRequired(record) => {
                CancellationDisposition::Indeterminate(record)
            }
        }
    }
}

fn validate_recovered_request(
    request: &NginxDurableRequest,
    acquired_action: &NginxAction,
    resource: &QualifiedNginxResource,
) -> Result<(), io::Error> {
    if &request.action != acquired_action {
        return Err(invalid_data(
            "durable nginx action disagrees with fresh acquisition",
        ));
    }
    validate_action_spec(&request.action, &resource.spec)?;
    let expected = durable_request(
        request.action.clone(),
        resource,
        request.credential_evidence.clone(),
    )?;
    if request != &expected {
        return Err(invalid_data(
            "durable nginx request disagrees with fresh acquisition",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconcileState {
    Completed,
    SafeToRetry,
    Intervention,
}

fn reconcile_request(request: &NginxRequest) -> Result<ReconcileState, io::Error> {
    let resource = &request.resource;
    match request.durable.action {
        NginxAction::Validate => {
            authenticate_request_credentials(request)?;
            if validation_matches(resource, &request.durable.credential_evidence)? {
                resource.validation_path.sync_parent()?;
                Ok(ReconcileState::Completed)
            } else {
                Ok(ReconcileState::SafeToRetry)
            }
        }
        NginxAction::Record => {
            if association_matches_desired(resource)? {
                resource.association_path.sync_parent()?;
                Ok(ReconcileState::Completed)
            } else if association_matches_current(resource)? {
                Ok(ReconcileState::SafeToRetry)
            } else {
                Ok(ReconcileState::Intervention)
            }
        }
        NginxAction::Release => {
            if matches!(
                observe_association(resource)?,
                ResourceRevisionObservation::Absent
            ) {
                resource.association_path.sync_parent()?;
                Ok(ReconcileState::Completed)
            } else if association_matches_current(resource)? {
                Ok(ReconcileState::SafeToRetry)
            } else {
                Ok(ReconcileState::Intervention)
            }
        }
    }
}

fn validate_candidate(
    executable: &Path,
    resource: &QualifiedNginxResource,
    credential_evidence: &[CredentialEvidence],
    control: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    execution_budget(control)?;
    stage_candidate(resource)?;
    verify_candidate(resource)?;
    let budget = execution_budget(control)?;
    let mut child = Command::new(executable)
        .env_clear()
        .current_dir(resource.validation_prefix.display())
        .arg("-t")
        .arg("-c")
        .arg(resource.candidate_path.display())
        .arg("-p")
        .arg(resource.validation_prefix.display())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let status = wait_bounded(&mut child, control, budget)?;
    verify_candidate(resource)?;
    if status.success() {
        write_validation(resource, credential_evidence)
    } else {
        // Configuration testing may open configured logs before reporting a
        // failure, so rejection is not proof that no external effect occurred.
        Err(io::Error::other("nginx rejected the candidate"))
    }
}

fn execution_budget(control: &dyn RuntimeControl) -> Result<u64, io::Error> {
    if control.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "nginx validation was cancelled before spawn",
        ));
    }
    let budget = control
        .attempt_remaining_millis()
        .min(control.recovery_remaining_millis());
    if budget == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "nginx validation has no remaining budget",
        ));
    }
    Ok(budget)
}

fn wait_bounded(
    child: &mut Child,
    control: &dyn RuntimeControl,
    budget: u64,
) -> Result<std::process::ExitStatus, io::Error> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                let _ = terminate(child);
                return Err(error);
            }
        }
        if control.is_cancelled() {
            terminate(child)?;
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "nginx validation was cancelled",
            ));
        }
        if started.elapsed() >= Duration::from_millis(budget) {
            terminate(child)?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "nginx validation timed out",
            ));
        }
        if control.attempt_remaining_millis() == 0 || control.recovery_remaining_millis() == 0 {
            terminate(child)?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "nginx validation exhausted its live runtime budget",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn terminate(child: &mut Child) -> Result<(), io::Error> {
    match child.kill() {
        Ok(()) => {
            let _ = child.wait()?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
            let _ = child.wait()?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidationRecord {
    schema: String,
    resource: ResourceId,
    generation: RevisionId,
    candidate_digest: Sha256Digest,
    implementation: ProviderImplementationReference,
    validation_prefix: String,
    credential_evidence: Vec<CredentialEvidence>,
}

fn write_validation(
    resource: &QualifiedNginxResource,
    credential_evidence: &[CredentialEvidence],
) -> Result<(), io::Error> {
    let generation = resource
        .spec
        .desired_generation
        .ok_or_else(|| invalid_data("nginx validation has no desired generation"))?;
    let validation = ValidationRecord {
        schema: VALIDATION_SCHEMA.to_string(),
        resource: resource.spec.resource.clone(),
        generation,
        candidate_digest: resource.candidate_digest,
        implementation: resource.implementation.clone(),
        validation_prefix: path_string(resource.validation_prefix.display())?,
        credential_evidence: credential_evidence.to_vec(),
    };
    let bytes = serde_json::to_vec(&validation)
        .map_err(|error| invalid_data(format!("encoding nginx validation: {error}")))?;
    resource.validation_path.atomic_write(&bytes, false)
}

fn validation_matches(
    resource: &QualifiedNginxResource,
    credential_evidence: &[CredentialEvidence],
) -> Result<bool, io::Error> {
    let Some(validation) = read_validation(resource)? else {
        return Ok(false);
    };

    validation_record_matches(resource, &validation, credential_evidence)
}

fn read_validation(
    resource: &QualifiedNginxResource,
) -> Result<Option<ValidationRecord>, io::Error> {
    let Some(bytes) = resource
        .validation_path
        .read_optional(MAX_ASSOCIATION_BYTES)?
    else {
        return Ok(None);
    };
    let validation = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid nginx validation record: {error}")))?;

    Ok(Some(validation))
}

fn validation_record_matches(
    resource: &QualifiedNginxResource,
    validation: &ValidationRecord,
    credential_evidence: &[CredentialEvidence],
) -> Result<bool, io::Error> {
    Ok(validation.schema == VALIDATION_SCHEMA
        && validation.resource == resource.spec.resource
        && Some(validation.generation) == resource.spec.desired_generation
        && validation.candidate_digest == resource.candidate_digest
        && validation.implementation == resource.implementation
        && validation.validation_prefix == path_string(resource.validation_prefix.display())?
        && validation.credential_evidence == credential_evidence)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssociationRecord {
    schema: String,
    resource: ResourceId,
    generation: RevisionId,
    candidate_digest: Sha256Digest,
    credential_evidence: Vec<CredentialEvidence>,
}

fn record_association(resource: &QualifiedNginxResource) -> Result<(), io::Error> {
    let validation = read_validation(resource)?.ok_or_else(|| {
        invalid_data("nginx candidate lacks exact successful validation evidence")
    })?;
    authenticate_credential_evidence(
        &validation.credential_evidence,
        &resource.spec.credential_dependencies,
    )?;
    if !validation_record_matches(resource, &validation, &validation.credential_evidence)? {
        return Err(invalid_data(
            "nginx candidate lacks exact successful validation evidence",
        ));
    }
    if !association_matches_current(resource)? {
        return Err(invalid_data("nginx generation association is stale"));
    }
    let generation = resource
        .spec
        .desired_generation
        .ok_or_else(|| invalid_data("nginx association has no desired generation"))?;
    let association = AssociationRecord {
        schema: ASSOCIATION_SCHEMA.to_string(),
        resource: resource.spec.resource.clone(),
        generation,
        candidate_digest: resource.candidate_digest,
        credential_evidence: validation.credential_evidence,
    };
    let bytes = serde_json::to_vec(&association)
        .map_err(|error| invalid_data(format!("encoding nginx association: {error}")))?;
    resource.association_path.atomic_write(&bytes, false)
}

fn remove_association(resource: &QualifiedNginxResource) -> Result<(), io::Error> {
    resource.association_path.remove()?;
    resource.association_path.sync_parent()
}

fn release_association(resource: &QualifiedNginxResource) -> Result<(), io::Error> {
    if !association_matches_current(resource)? {
        return Err(invalid_data("nginx release association is stale"));
    }
    remove_association(resource)
}

fn observe_association(
    resource: &QualifiedNginxResource,
) -> Result<ResourceRevisionObservation, io::Error> {
    let Some(bytes) = resource
        .association_path
        .read_optional(MAX_ASSOCIATION_BYTES)?
    else {
        return Ok(ResourceRevisionObservation::Absent);
    };
    let association: AssociationRecord = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid nginx association record: {error}")))?;
    if association.schema == ASSOCIATION_SCHEMA && association.resource == resource.spec.resource {
        Ok(ResourceRevisionObservation::Present(association.generation))
    } else {
        Ok(ResourceRevisionObservation::Unknown)
    }
}

fn association_matches_current(resource: &QualifiedNginxResource) -> Result<bool, io::Error> {
    association_matches(
        resource,
        resource.spec.current_generation,
        resource.spec.current_candidate_digest,
    )
}

fn association_matches_desired(resource: &QualifiedNginxResource) -> Result<bool, io::Error> {
    if !association_matches(
        resource,
        resource.spec.desired_generation,
        Some(resource.candidate_digest),
    )? {
        return Ok(false);
    }
    let Some(association) = read_association(resource)? else {
        return Ok(false);
    };
    let Some(validation) = read_validation(resource)? else {
        return Ok(false);
    };
    if !validation_record_matches(resource, &validation, &association.credential_evidence)? {
        return Ok(false);
    }
    authenticate_credential_evidence(
        &association.credential_evidence,
        &resource.spec.credential_dependencies,
    )?;

    Ok(association.credential_evidence == validation.credential_evidence)
}

fn association_matches(
    resource: &QualifiedNginxResource,
    generation: Option<RevisionId>,
    candidate_digest: Option<Sha256Digest>,
) -> Result<bool, io::Error> {
    let Some(association) = read_association(resource)? else {
        return Ok(generation.is_none() && candidate_digest.is_none());
    };
    Ok(association.schema == ASSOCIATION_SCHEMA
        && association.resource == resource.spec.resource
        && Some(association.generation) == generation
        && Some(association.candidate_digest) == candidate_digest)
}

fn read_association(
    resource: &QualifiedNginxResource,
) -> Result<Option<AssociationRecord>, io::Error> {
    let Some(bytes) = resource
        .association_path
        .read_optional(MAX_ASSOCIATION_BYTES)?
    else {
        return Ok(None);
    };
    let association = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid nginx association record: {error}")))?;

    Ok(Some(association))
}

fn expected_current(spec: &NginxResourceSpec) -> ResourceRevisionObservation {
    spec.current_generation.map_or(
        ResourceRevisionObservation::Absent,
        ResourceRevisionObservation::Present,
    )
}

fn stage_candidate(resource: &QualifiedNginxResource) -> Result<(), io::Error> {
    if resource.candidate_path.exists()? {
        verify_candidate(resource)?;
        return resource.candidate_path.sync_parent();
    }
    resource
        .candidate_path
        .atomic_write(&resource.spec.candidate, true)
}

fn verify_candidate(resource: &QualifiedNginxResource) -> Result<(), io::Error> {
    let bytes = resource
        .candidate_path
        .read(resource.spec.candidate.len().saturating_add(1) as u64)?;
    if bytes == resource.spec.candidate
        && Sha256Digest::of_bytes(&bytes) == resource.candidate_digest
    {
        Ok(())
    } else {
        Err(invalid_data("immutable nginx candidate changed"))
    }
}

fn action_for(operation: &Operation) -> Result<NginxAction, io::Error> {
    let action = match operation.family {
        OperationFamily::ValidateCandidate => NginxAction::Validate,
        OperationFamily::RecordGenerationAssociation => NginxAction::Record,
        OperationFamily::ReleaseResource => NginxAction::Release,
        _ => return Err(invalid_data("unsupported nginx operation family")),
    };
    let expected = match action {
        NginxAction::Validate => "validate",
        NginxAction::Record => "record",
        NginxAction::Release => "release",
    };
    if operation.method.as_str() != expected {
        return Err(invalid_data("nginx method disagrees with operation family"));
    }
    Ok(action)
}

fn validate_action_spec(action: &NginxAction, spec: &NginxResourceSpec) -> Result<(), io::Error> {
    match action {
        NginxAction::Validate | NginxAction::Record if spec.desired_generation.is_none() => {
            Err(invalid_data("nginx candidate has no desired generation"))
        }
        NginxAction::Release if spec.desired_generation.is_some() => Err(invalid_data(
            "nginx release unexpectedly carries a desired generation",
        )),
        _ => Ok(()),
    }
}

fn decode_validation_input(
    inputs: &AbilityValue,
    action: &NginxAction,
) -> Result<NginxValidationInput, io::Error> {
    let input: NginxValidationInput = serde_json::from_value(inputs.as_json().clone())
        .map_err(|error| invalid_data(format!("invalid nginx validation input: {error}")))?;
    let expected_candidate = !matches!(action, NginxAction::Release);
    if input.candidate != expected_candidate {
        return Err(invalid_data(
            "nginx candidate presence disagrees with the operation action",
        ));
    }
    if !matches!(action, NginxAction::Validate) && !input.credential_views.is_empty() {
        return Err(invalid_data(
            "only nginx validation may consume credential views",
        ));
    }

    Ok(input)
}

fn authenticate_credential_inputs(
    views: &[CredentialViewInput],
    dependencies: &[NativeDependencyBinding],
) -> Result<Vec<CredentialEvidence>, io::Error> {
    if views.len() != dependencies.len() {
        return Err(invalid_data(
            "nginx credential views differ from checked producer authority",
        ));
    }

    let mut remaining = dependencies.iter().collect::<Vec<_>>();
    let mut authenticated = Vec::with_capacity(views.len());
    for view in views {
        let evidence = authenticate_credential_view_evidence(Path::new(&view.path), &view.version)?;
        let position = remaining
            .iter()
            .position(|binding| binding.resource == evidence.resource)
            .ok_or_else(|| {
                invalid_data("nginx credential view has no checked producer authority")
            })?;
        let binding = remaining.remove(position);
        let producer_evidence =
            authenticate_credential_dependency_view(binding, Path::new(&view.path), &view.version)?;
        if producer_evidence != evidence {
            return Err(invalid_data(
                "nginx credential evidence changed during authentication",
            ));
        }
        authenticated.push(evidence);
    }
    authenticated.sort_by(|left, right| left.resource.cmp(&right.resource));

    Ok(authenticated)
}

fn authenticate_credential_evidence(
    expected: &[CredentialEvidence],
    dependencies: &[NativeDependencyBinding],
) -> Result<(), io::Error> {
    if expected.len() != dependencies.len() {
        return Err(invalid_data(
            "durable nginx credentials differ from checked producer authority",
        ));
    }

    let mut remaining = dependencies.iter().collect::<Vec<_>>();
    for expected_evidence in expected {
        let position = remaining
            .iter()
            .position(|binding| binding.resource == expected_evidence.resource)
            .ok_or_else(|| {
                invalid_data("durable nginx credential has no checked producer authority")
            })?;
        let binding = remaining.remove(position);
        let evidence = authenticate_credential_dependency_view(
            binding,
            Path::new(&expected_evidence.view_path),
            &expected_evidence.version,
        )?;
        if &evidence != expected_evidence {
            return Err(invalid_data(
                "durable nginx credential evidence is stale or changed",
            ));
        }
    }

    Ok(())
}

fn authenticate_request_credentials(request: &NginxRequest) -> Result<(), io::Error> {
    authenticate_credential_evidence(
        &request.durable.credential_evidence,
        &request.resource.spec.credential_dependencies,
    )?;
    validate_candidate_credential_paths(
        &request.resource.spec.candidate,
        &request.durable.credential_evidence,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NginxToken<'a> {
    Word(&'a str),
    Quoted,
    Semicolon,
    Boundary,
}

fn validate_candidate_credential_paths(
    candidate: &[u8],
    credential_evidence: &[CredentialEvidence],
) -> Result<(), io::Error> {
    let source =
        std::str::from_utf8(candidate).map_err(|_| invalid_data("nginx candidate is not UTF-8"))?;
    let tokens = tokenize_nginx(source)?;
    let certificates = directive_paths(&tokens, "ssl_certificate")?;
    let private_keys = directive_paths(&tokens, "ssl_certificate_key")?;
    let expected = credential_evidence
        .iter()
        .map(|evidence| evidence.view_path.as_str())
        .collect::<BTreeSet<_>>();

    if certificates != expected || private_keys != expected {
        return Err(invalid_data(
            "nginx TLS directives differ from authenticated credential views",
        ));
    }

    Ok(())
}

fn directive_paths<'a>(
    tokens: &[NginxToken<'a>],
    directive: &str,
) -> Result<BTreeSet<&'a str>, io::Error> {
    let mut paths = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if token != &NginxToken::Word(directive) {
            continue;
        }
        let Some(NginxToken::Word(path)) = tokens.get(index + 1) else {
            return Err(invalid_data(format!(
                "nginx {directive} must use one unquoted path"
            )));
        };
        if tokens.get(index + 2) != Some(&NginxToken::Semicolon) || !path.starts_with('/') {
            return Err(invalid_data(format!(
                "nginx {directive} must use one absolute path"
            )));
        }
        paths.insert(*path);
    }

    Ok(paths)
}

fn tokenize_nginx(source: &str) -> Result<Vec<NginxToken<'_>>, io::Error> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            byte if byte.is_ascii_whitespace() => cursor += 1,
            b'#' => {
                cursor += 1;
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    cursor += 1;
                }
            }
            b';' => {
                tokens.push(NginxToken::Semicolon);
                cursor += 1;
            }
            b'{' | b'}' => {
                tokens.push(NginxToken::Boundary);
                cursor += 1;
            }
            quote @ (b'\'' | b'"') => {
                cursor += 1;
                let mut closed = false;
                while cursor < bytes.len() {
                    match bytes[cursor] {
                        b'\\' => cursor = cursor.saturating_add(2),
                        byte if byte == quote => {
                            cursor += 1;
                            closed = true;
                            break;
                        }
                        _ => cursor += 1,
                    }
                }
                if !closed {
                    return Err(invalid_data("nginx candidate has an unterminated quote"));
                }
                tokens.push(NginxToken::Quoted);
            }
            _ => {
                let start = cursor;
                while cursor < bytes.len()
                    && !bytes[cursor].is_ascii_whitespace()
                    && !matches!(bytes[cursor], b'#' | b';' | b'{' | b'}' | b'\'' | b'"')
                {
                    cursor += 1;
                }
                let word = source
                    .get(start..cursor)
                    .ok_or_else(|| invalid_data("nginx candidate token is not UTF-8"))?;
                tokens.push(NginxToken::Word(word));
            }
        }
    }

    Ok(tokens)
}

fn durable_request(
    action: NginxAction,
    resource: &QualifiedNginxResource,
    credential_evidence: Vec<CredentialEvidence>,
) -> Result<NginxDurableRequest, io::Error> {
    Ok(NginxDurableRequest {
        schema: REQUEST_SCHEMA.to_string(),
        action,
        resource: resource.spec.resource.clone(),
        current_generation: resource.spec.current_generation,
        current_candidate_digest: resource.spec.current_candidate_digest,
        desired_generation: resource.spec.desired_generation,
        candidate_digest: resource.candidate_digest,
        implementation: resource.implementation.clone(),
        validation_prefix: path_string(resource.validation_prefix.display())?,
        credential_evidence,
    })
}

fn encode_request(request: NginxDurableRequest) -> Result<AbilityValue, io::Error> {
    let value = serde_json::to_value(request)
        .map_err(|error| invalid_data(format!("encoding nginx request: {error}")))?;
    AbilityValue::new(value)
        .map_err(|error| invalid_data(format!("nginx request exceeds limits: {error}")))
}

fn authenticate(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
) -> Result<PathBuf, io::Error> {
    preflight_native_nginx(package, assignment, &assignment.implementation.artifact)?;
    authenticate_executable(&assignment.implementation.artifact.store_path)
}

pub(crate) fn preflight_native_nginx(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
    executable: &ArtifactReference,
) -> Result<(), io::Error> {
    if package.activation_mode() != AbilityActivationMode::StructuredEffects
        || assignment.interface != expected_interface()?
    {
        return Err(invalid_data(
            "nginx adapter requires its exact structured-effects interface",
        ));
    }
    let handler_key =
        LocalKey::new(HANDLER_KEY).map_err(|error| invalid_data(error.to_string()))?;
    if assignment.implementation.handler.as_ref() != Some(&handler_key) {
        return Err(invalid_data("nginx assignment selects another handler"));
    }
    let verified = package
        .resolve_terminal_handler(assignment.implementation.descriptor, &handler_key)
        .ok_or_else(|| {
            invalid_data("authenticated package does not resolve the assigned nginx handler")
        })?;
    if verified.provider().interface != assignment.interface
        || verified.provider().artifact != assignment.implementation.artifact
        || verified
            .provider()
            .descriptor_digest()
            .map_err(|error| invalid_data(error.to_string()))?
            != assignment.implementation.descriptor
        || verified.handler().artifact != assignment.implementation.artifact
        || verified.handler().entry_point != ENTRY_POINT
        || verified.handler().arguments != nginx_validation_request_schema()?
        || verified.handler().result != ValueSchema::Boolean
    {
        return Err(invalid_data(
            "authenticated nginx provider linkage differs from the assignment",
        ));
    }
    if executable != &assignment.implementation.artifact {
        return Err(invalid_data(
            "nginx resource map selects an executable outside the assigned terminal artifact",
        ));
    }
    Ok(())
}

fn nginx_validation_request_schema() -> Result<ValueSchema, io::Error> {
    Ok(ValueSchema::Record {
        fields: BTreeMap::from([
            (
                LocalKey::new("candidate").map_err(|error| invalid_data(error.to_string()))?,
                ValueSchema::Boolean,
            ),
            (
                LocalKey::new("credential_views")
                    .map_err(|error| invalid_data(error.to_string()))?,
                ValueSchema::List {
                    element: Box::new(
                        credential_view_schema()
                            .map_err(|error| invalid_data(error.to_string()))?,
                    ),
                    max_items: 1024,
                },
            ),
        ]),
        optional_fields: Vec::new(),
    })
}

fn authenticate_executable(store_path: &str) -> Result<PathBuf, io::Error> {
    let root = PathBuf::from(store_path);
    if root.to_str() != Some(store_path) {
        return Err(invalid_data("nginx artifact store path is not canonical"));
    }
    let artifact = RootedDirectory::open(&root, 0, "nginx artifact root")?;
    let executable = artifact.resolve(Path::new(ENTRY_POINT))?;
    if executable.mode()? & 0o111 == 0 {
        return Err(invalid_data(
            "authenticated nginx entry point is not a regular executable",
        ));
    }
    Ok(executable.display().to_path_buf())
}

fn expected_interface() -> Result<InterfaceKey, io::Error> {
    Ok(InterfaceKey {
        name: InterfaceName::new(INTERFACE_NAME)
            .map_err(|error| invalid_data(error.to_string()))?,
        abi: NonZeroU32::new(1).ok_or_else(|| invalid_data("invalid interface ABI"))?,
        descriptor: Sha256Digest::parse(INTERFACE_DESCRIPTOR)
            .map_err(|error| invalid_data(error.to_string()))?,
    })
}

fn existing_private_directory(
    root: &RootedDirectory,
    name: &str,
) -> Result<RootedDirectory, io::Error> {
    root.child_directory(name)
}

fn boolean_value(value: bool) -> Result<AbilityValue, io::Error> {
    AbilityValue::new(serde_json::Value::Bool(value))
        .map_err(|error| invalid_data(error.to_string()))
}

fn path_string(path: &Path) -> Result<String, io::Error> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| invalid_data("nginx path is not UTF-8"))
}

fn record(value: bool) -> Result<NginxRecord, io::Error> {
    Ok(NginxRecord {
        durable: boolean_value(value)?,
        outputs: BTreeMap::new(),
    })
}

fn store_error(error: GenerationAbilityStoreError) -> io::Error {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_ability_model::{ArtifactReference, EnvironmentId, ExecutionStage, InstanceId};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn validation_input_uses_the_typed_credential_view_contract() {
        let typed = AbilityValue::new(serde_json::json!({
            "candidate": true,
            "credential_views": [{
                "path": "/var/lib/aos/ability-runtime/credentials/credential.view",
                "version": "certificate-v1"
            }]
        }))
        .expect("typed input is canonical");
        let parsed = decode_validation_input(&typed, &NginxAction::Validate)
            .expect("typed validation input is accepted");
        assert!(parsed.candidate);
        assert_eq!(parsed.credential_views.len(), 1);

        let legacy = boolean_value(true).expect("legacy Boolean is canonical");
        assert!(decode_validation_input(&legacy, &NginxAction::Validate).is_err());
        assert!(decode_validation_input(&typed, &NginxAction::Record).is_err());
    }

    #[test]
    fn validation_receipt_binds_every_credential_evidence_field() {
        let fixture = nginx_fixture("runtime");
        let evidence = test_credential_evidence("certificate-v1");
        write_validation(&fixture.resource, std::slice::from_ref(&evidence))
            .expect("validation receipt is written");
        assert!(
            validation_matches(&fixture.resource, std::slice::from_ref(&evidence))
                .expect("exact credential evidence matches")
        );

        let mut changed = evidence.clone();
        changed.version = "certificate-v2".to_string();
        assert!(!validation_matches(&fixture.resource, &[changed]).expect("version is checked"));

        let mut changed = evidence.clone();
        changed.view_path.push_str("-foreign");
        assert!(!validation_matches(&fixture.resource, &[changed]).expect("path is checked"));

        let mut changed = evidence.clone();
        changed.content_digest = Sha256Digest::of_bytes(b"changed-certificate");
        assert!(!validation_matches(&fixture.resource, &[changed]).expect("digest is checked"));

        let mut changed = evidence;
        changed.resource.key = LocalKey::new("foreign-credential").expect("key is valid");
        assert!(!validation_matches(&fixture.resource, &[changed]).expect("resource is checked"));
    }

    #[test]
    fn durable_request_contains_only_secret_free_credential_evidence() {
        let fixture = nginx_fixture("runtime");
        let evidence = test_credential_evidence("certificate-v1");
        let durable = durable_request(
            NginxAction::Validate,
            &fixture.resource,
            vec![evidence.clone()],
        )
        .expect("durable request is constructed");
        let encoded = encode_request(durable).expect("durable request encodes");
        let credential = encoded.as_json()["credential_evidence"][0]
            .as_object()
            .expect("credential evidence is a record");
        let fields = credential
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            fields,
            BTreeSet::from(["content_digest", "resource", "version", "view_path"])
        );
        assert_eq!(credential["resource"], serde_json::json!(evidence.resource));
        assert_eq!(credential["version"], evidence.version);
        assert_eq!(credential["view_path"], evidence.view_path);
        assert_eq!(
            credential["content_digest"],
            serde_json::json!(evidence.content_digest)
        );
    }

    #[test]
    fn candidate_tls_directives_exactly_match_authenticated_combined_pem_views() {
        let evidence = test_credential_evidence("certificate-v1");
        let path = &evidence.view_path;
        let valid = format!(
            "events {{}} http {{ server {{ ssl_certificate {path}; ssl_certificate_key {path}; }} }}"
        );
        assert!(
            validate_candidate_credential_paths(valid.as_bytes(), std::slice::from_ref(&evidence))
                .is_ok()
        );

        let missing_key = format!("ssl_certificate {path};");
        assert!(
            validate_candidate_credential_paths(
                missing_key.as_bytes(),
                std::slice::from_ref(&evidence)
            )
            .is_err()
        );

        let extra = format!(
            "ssl_certificate {path}; ssl_certificate_key {path}; ssl_certificate /foreign.pem;"
        );
        assert!(
            validate_candidate_credential_paths(extra.as_bytes(), std::slice::from_ref(&evidence))
                .is_err()
        );

        let quoted = format!("ssl_certificate \"{path}\"; ssl_certificate_key {path};");
        assert!(
            validate_candidate_credential_paths(quoted.as_bytes(), std::slice::from_ref(&evidence))
                .is_err()
        );

        let comments_only =
            format!("# ssl_certificate {path};\n# ssl_certificate_key {path};\nevents {{}}");
        assert!(validate_candidate_credential_paths(comments_only.as_bytes(), &[]).is_ok());
    }

    #[test]
    fn candidate_file_is_immutable_and_exact() {
        let root = tempfile::tempdir().expect("temporary root is created");
        let owner = fs::metadata(root.path())
            .expect("root metadata is read")
            .uid();
        let rooted = RootedDirectory::open(root.path(), owner, "nginx test root")
            .expect("test root is opened");
        let path = rooted
            .child("candidate".to_string())
            .expect("candidate resolves");
        path.atomic_write(b"events {}", true)
            .expect("candidate is written");
        assert_eq!(path.read(64).expect("candidate is readable"), b"events {}");
        assert_eq!(
            fs::metadata(path.display())
                .expect("candidate metadata is readable")
                .permissions()
                .mode()
                & 0o222,
            0
        );
    }

    #[test]
    fn validation_receipt_rejects_same_candidate_from_another_executable() {
        let fixture = nginx_fixture("first-runtime");
        stage_candidate(&fixture.resource).expect("candidate is staged");
        write_validation(&fixture.resource, &[]).expect("validation receipt is written");
        assert!(validation_matches(&fixture.resource, &[]).expect("receipt is valid"));

        let mut upgraded = fixture.resource.clone();
        upgraded.implementation = implementation("second-runtime");
        assert!(!validation_matches(&upgraded, &[]).expect("upgraded receipt is checked"));
    }

    #[test]
    fn recovery_rejects_a_mutated_durable_action() {
        let fixture = nginx_fixture("runtime");
        let mut durable = durable_request(NginxAction::Validate, &fixture.resource, Vec::new())
            .expect("durable request encodes");
        durable.action = NginxAction::Record;

        assert!(
            validate_recovered_request(&durable, &NginxAction::Validate, &fixture.resource,)
                .is_err()
        );
    }

    #[test]
    fn adapter_reconciles_validate_record_and_release_crash_boundaries() {
        let validate = nginx_fixture("runtime");
        let mut validate_adapter = test_adapter(&validate.resource);
        let validate_request = test_request(NginxAction::Validate, &validate.resource);
        assert!(matches!(
            validate_adapter.reconcile(&validate_request, &ZeroBudgetControl),
            ReconcileDisposition::SafeToRetry(_)
        ));
        stage_candidate(&validate.resource).expect("candidate is staged before validation");
        write_validation(&validate.resource, &[]).expect("validation effect is persisted");
        assert!(matches!(
            validate_adapter.reconcile(&validate_request, &ZeroBudgetControl),
            ReconcileDisposition::Completed(_)
        ));

        let record = nginx_fixture("runtime");
        let mut record_adapter = test_adapter(&record.resource);
        let record_request = test_request(NginxAction::Record, &record.resource);
        assert!(matches!(
            record_adapter.reconcile(&record_request, &ZeroBudgetControl),
            ReconcileDisposition::SafeToRetry(_)
        ));
        stage_candidate(&record.resource).expect("record candidate is staged");
        write_validation(&record.resource, &[]).expect("record validation is persisted");
        record_association(&record.resource).expect("association effect is persisted");
        assert!(matches!(
            record_adapter.cancel(&record_request, &ZeroBudgetControl),
            CancellationDisposition::Completed(_)
        ));

        let release = nginx_fixture_with_transition("runtime", Some(revision("current")), None);
        write_test_association(
            &release.resource,
            revision("current"),
            release.resource.candidate_digest,
        );
        let mut release_adapter = test_adapter(&release.resource);
        let release_request = test_request(NginxAction::Release, &release.resource);
        assert!(matches!(
            release_adapter.reconcile(&release_request, &ZeroBudgetControl),
            ReconcileDisposition::SafeToRetry(_)
        ));
        release
            .resource
            .association_path
            .remove()
            .expect("simulated release unlink succeeds before directory sync");
        assert!(matches!(
            release_adapter.reconcile(&release_request, &ZeroBudgetControl),
            ReconcileDisposition::Completed(_)
        ));
    }

    #[test]
    fn exhausted_budget_prevents_candidate_staging_and_process_spawn() {
        let fixture = nginx_fixture("runtime");
        let control = ZeroBudgetControl;
        assert!(
            validate_candidate(
                Path::new("/missing-nginx"),
                &fixture.resource,
                &[],
                &control,
            )
            .is_err()
        );
        assert!(
            !fixture
                .resource
                .candidate_path
                .exists()
                .expect("candidate absence is observed")
        );
    }

    struct NginxFixture {
        _root: tempfile::TempDir,
        resource: QualifiedNginxResource,
    }

    fn nginx_fixture(runtime: &str) -> NginxFixture {
        nginx_fixture_with_transition(runtime, None, Some(revision("desired")))
    }

    fn nginx_fixture_with_transition(
        runtime: &str,
        current_generation: Option<RevisionId>,
        desired_generation: Option<RevisionId>,
    ) -> NginxFixture {
        let root = tempfile::tempdir().expect("temporary root is created");
        let owner = fs::metadata(root.path())
            .expect("root metadata is read")
            .uid();
        for directory in ["candidates", "validations", "associations", "sandbox"] {
            fs::create_dir(root.path().join(directory)).expect("fixture directory is created");
        }
        let state =
            RootedDirectory::open(root.path(), owner, "nginx test root").expect("state root opens");
        let candidate_root = state
            .child_directory("candidates")
            .expect("candidate root opens");
        let validation_root = state
            .child_directory("validations")
            .expect("validation root opens");
        let association_root = state
            .child_directory("associations")
            .expect("association root opens");
        let validation_prefix = state
            .child_directory("sandbox")
            .expect("sandbox root opens");
        let resource_id = test_resource_id();
        let candidate = b"events {}".to_vec();
        let candidate_digest = Sha256Digest::of_bytes(&candidate);
        let identity = Sha256Digest::of_bytes(b"resource").to_string();
        let association_path = association_root
            .child(identity.clone())
            .expect("association resolves");
        let qualified = NativeQualifiedResource::nginx_validation_prefix(
            resource_id.clone(),
            validation_prefix
                .display()
                .to_str()
                .expect("validation prefix is UTF-8"),
        )
        .expect("physical resource qualifies");
        NginxFixture {
            _root: root,
            resource: QualifiedNginxResource {
                spec: NginxResourceSpec {
                    handler_provider: resource_id.provider.clone(),
                    resource: resource_id,
                    validation_prefix: validation_prefix.display().to_path_buf(),
                    candidate,
                    current_generation,
                    current_candidate_digest: current_generation.map(|_| candidate_digest),
                    desired_generation,
                    credential_dependencies: Vec::new(),
                },
                candidate_path: candidate_root
                    .child(candidate_digest.to_string())
                    .expect("candidate resolves"),
                validation_path: validation_root
                    .child(identity)
                    .expect("validation resolves"),
                association_path,
                validation_prefix,
                candidate_digest,
                implementation: implementation(runtime),
                qualified,
            },
        }
    }

    fn test_adapter(resource: &QualifiedNginxResource) -> NativeNginxAdapter {
        NativeNginxAdapter {
            assignment: ProviderAssignment {
                provider: resource.spec.resource.provider.clone(),
                interface: InterfaceKey {
                    name: InterfaceName::new(INTERFACE_NAME).expect("interface name is valid"),
                    abi: NonZeroU32::new(1).expect("interface ABI is nonzero"),
                    descriptor: Sha256Digest::parse(INTERFACE_DESCRIPTOR)
                        .expect("interface descriptor is valid"),
                },
                implementation: resource.implementation.clone(),
                incarnation: aos_ability_model::IncarnationId::new("test-nginx-runtime")
                    .expect("test incarnation is valid"),
            },
            executable: PathBuf::from("/missing-test-nginx"),
            success: record(true).expect("success record encodes"),
            failure: record(false).expect("failure record encodes"),
        }
    }

    fn test_request(action: NginxAction, resource: &QualifiedNginxResource) -> NginxRequest {
        NginxRequest {
            durable: durable_request(action, resource, Vec::new())
                .expect("durable request encodes"),
            resource: resource.clone(),
        }
    }

    fn write_test_association(
        resource: &QualifiedNginxResource,
        generation: RevisionId,
        candidate_digest: Sha256Digest,
    ) {
        let association = AssociationRecord {
            schema: ASSOCIATION_SCHEMA.to_string(),
            resource: resource.spec.resource.clone(),
            generation,
            candidate_digest,
            credential_evidence: Vec::new(),
        };
        resource
            .association_path
            .atomic_write(
                &serde_json::to_vec(&association).expect("association encodes"),
                false,
            )
            .expect("association is persisted");
    }

    fn implementation(runtime: &str) -> ProviderImplementationReference {
        ProviderImplementationReference {
            descriptor: Sha256Digest::of_bytes(format!("descriptor-{runtime}").as_bytes()),
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes(format!("content-{runtime}").as_bytes()),
                store_path: format!("/nix/store/{runtime}"),
                nar_hash: Sha256Digest::of_bytes(format!("nar-{runtime}").as_bytes()),
                closure: Sha256Digest::of_bytes(format!("closure-{runtime}").as_bytes()),
            },
            handler: Some(LocalKey::new(HANDLER_KEY).expect("handler key is valid")),
        }
    }

    fn test_credential_evidence(version: &str) -> CredentialEvidence {
        let mut resource = test_resource_id();
        resource.key = LocalKey::new("tls-credential").expect("credential key is valid");

        CredentialEvidence {
            resource,
            version: version.to_string(),
            view_path: format!(
                "/var/lib/aos/ability-runtime/credentials/{}.view",
                Sha256Digest::of_bytes(b"tls-credential-resource")
            ),
            content_digest: Sha256Digest::of_bytes(b"certificate-and-private-key"),
        }
    }

    fn test_resource_id() -> ResourceId {
        ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test").expect("authority is valid"),
                    key: LocalKey::new("host").expect("environment is valid"),
                    stage: ExecutionStage::Host,
                },
                key: LocalKey::new("nginx").expect("provider is valid"),
            },
            key: LocalKey::new("virtual-hosts").expect("resource is valid"),
        }
    }

    fn revision(label: &str) -> RevisionId {
        RevisionId(Sha256Digest::of_bytes(label.as_bytes()))
    }

    struct ZeroBudgetControl;

    impl RuntimeControl for ZeroBudgetControl {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn elapsed_millis(&self) -> u64 {
            0
        }
        fn attempt_remaining_millis(&self) -> u64 {
            0
        }
        fn recovery_remaining_millis(&self) -> u64 {
            0
        }
    }
}
