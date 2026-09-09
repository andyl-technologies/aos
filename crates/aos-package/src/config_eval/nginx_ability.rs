//! Trusted nginx candidate validation and generation association.
//!
//! Native orchestration supplies the exact candidate bytes for each logical
//! resource. The checked plan carries only Boolean terminal parameters. The
//! adapter executes the authenticated nginx artifact by absolute path, bounds
//! process lifetime, discards diagnostics without buffering, and records which
//! candidate digest was validated for an exact desired generation. Its durable
//! formats are:
//!
//! ```text
//! {"schema":"aos.ability.nginx-request/v1",...}
//! {"schema":"aos.ability.nginx-validation/v1",...}
//! {"schema":"aos.ability.nginx-generation-association/v1",...}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aos_ability_model::{
    AbilityActivationMode, AbilityValue, ExecutionStage, InterfaceKey, InterfaceName, LocalKey,
    MethodReference, Operation, OperationFamily, ProviderAssignment,
    ProviderImplementationReference, ResourceAccess, ResourceId, RevisionId, ValueSchema,
};
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

const INTERFACE_NAME: &str = "aos.nginx-validation";
const INTERFACE_DESCRIPTOR: &str =
    "sha256:cfe3335b1ff3082ffd17e38f098e804461daaa32db19a2aba9faa2e2acaddd1d";
const HANDLER_KEY: &str = "nginx-terminal";
const ENTRY_POINT: &str = "bin/nginx";
const REQUEST_SCHEMA: &str = "aos.ability.nginx-request/v1";
const VALIDATION_SCHEMA: &str = "aos.ability.nginx-validation/v1";
const ASSOCIATION_SCHEMA: &str = "aos.ability.nginx-generation-association/v1";
const MAX_ASSOCIATION_BYTES: u64 = 16 * 1024;

/// Binds a logical nginx resource to exact candidate bytes and one generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NginxResourceSpec {
    /// Names the logical resource declared by the checked provider.
    pub resource: ResourceId,
    /// Carries the exact configuration bytes selected by native orchestration.
    pub candidate: Vec<u8>,
    /// Identifies the currently selected generation, when one exists.
    pub current_generation: Option<RevisionId>,
    /// Commits to the candidate associated with the current generation.
    pub current_candidate_digest: Option<Sha256Digest>,
    /// Identifies the desired generation, or is absent for release.
    pub desired_generation: Option<RevisionId>,
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
    /// The root must contain canonical `candidates`, `validations`,
    /// `associations`, and `sandbox` directories created by native orchestration.
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
        let validation_prefix = existing_private_directory(&private_state_root, "sandbox")?;

        let mut association_paths = BTreeSet::new();
        let mut indexed = BTreeMap::new();
        for spec in resources {
            if spec.resource.provider != assignment.provider {
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
            let object = association_path
                .display()
                .to_str()
                .ok_or_else(|| invalid_data("nginx association path is not UTF-8"))?;
            let qualified =
                NativeQualifiedResource::nginx_generation(spec.resource.clone(), object)
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
        if context.expected_provider != Some(&self.assignment) {
            return Err(invalid_data("nginx provider assignment is absent or stale"));
        }
        if operation.target.resource != access.resource {
            return Err(invalid_data(
                "nginx access does not target the operation resource",
            ));
        }
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
        let revision = observe_association(&resource)?;
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
        if inputs.as_json() != &serde_json::Value::Bool(true) {
            return Err(invalid_data(
                "nginx terminal method requires the closed Boolean input true",
            ));
        }
        if operation.interface != self.assignment.interface {
            return Err(invalid_data("nginx operation uses another interface"));
        }
        let action = action_for(operation)?;
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
        encode_request(durable_request(action, &resource.native().resource)?)
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
                match validate_candidate(&self.executable, &request.resource, control) {
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
    if request != &durable_request(request.action.clone(), resource)? {
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
            if validation_matches(resource)? {
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
        write_validation(resource)
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
}

fn write_validation(resource: &QualifiedNginxResource) -> Result<(), io::Error> {
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
    };
    let bytes = serde_json::to_vec(&validation)
        .map_err(|error| invalid_data(format!("encoding nginx validation: {error}")))?;
    resource.validation_path.atomic_write(&bytes, false)
}

fn validation_matches(resource: &QualifiedNginxResource) -> Result<bool, io::Error> {
    let Some(bytes) = resource
        .validation_path
        .read_optional(MAX_ASSOCIATION_BYTES)?
    else {
        return Ok(false);
    };
    let validation: ValidationRecord = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid nginx validation record: {error}")))?;
    Ok(validation.schema == VALIDATION_SCHEMA
        && validation.resource == resource.spec.resource
        && Some(validation.generation) == resource.spec.desired_generation
        && validation.candidate_digest == resource.candidate_digest
        && validation.implementation == resource.implementation
        && validation.validation_prefix == path_string(resource.validation_prefix.display())?)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssociationRecord {
    schema: String,
    resource: ResourceId,
    generation: RevisionId,
    candidate_digest: Sha256Digest,
}

fn record_association(resource: &QualifiedNginxResource) -> Result<(), io::Error> {
    if !validation_matches(resource)? {
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
    association_matches(
        resource,
        resource.spec.desired_generation,
        Some(resource.candidate_digest),
    )
}

fn association_matches(
    resource: &QualifiedNginxResource,
    generation: Option<RevisionId>,
    candidate_digest: Option<Sha256Digest>,
) -> Result<bool, io::Error> {
    let Some(bytes) = resource
        .association_path
        .read_optional(MAX_ASSOCIATION_BYTES)?
    else {
        return Ok(generation.is_none() && candidate_digest.is_none());
    };
    let association: AssociationRecord = serde_json::from_slice(&bytes)
        .map_err(|error| invalid_data(format!("invalid nginx association record: {error}")))?;
    Ok(association.schema == ASSOCIATION_SCHEMA
        && association.resource == resource.spec.resource
        && Some(association.generation) == generation
        && Some(association.candidate_digest) == candidate_digest)
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

fn durable_request(
    action: NginxAction,
    resource: &QualifiedNginxResource,
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
        || verified.handler().arguments != ValueSchema::Boolean
        || verified.handler().result != ValueSchema::Boolean
    {
        return Err(invalid_data(
            "authenticated nginx provider linkage differs from the assignment",
        ));
    }
    authenticate_executable(&assignment.implementation.artifact.store_path)
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
        write_validation(&fixture.resource).expect("validation receipt is written");
        assert!(validation_matches(&fixture.resource).expect("receipt is valid"));

        let mut upgraded = fixture.resource.clone();
        upgraded.implementation = implementation("second-runtime");
        assert!(!validation_matches(&upgraded).expect("upgraded receipt is checked"));
    }

    #[test]
    fn recovery_rejects_a_mutated_durable_action() {
        let fixture = nginx_fixture("runtime");
        let mut durable = durable_request(NginxAction::Validate, &fixture.resource)
            .expect("durable request encodes");
        durable.action = NginxAction::Record;

        assert!(
            validate_recovered_request(&durable, &NginxAction::Validate, &fixture.resource,)
                .is_err()
        );
    }

    #[test]
    fn exhausted_budget_prevents_candidate_staging_and_process_spawn() {
        let fixture = nginx_fixture("runtime");
        let control = ZeroBudgetControl;
        assert!(
            validate_candidate(Path::new("/missing-nginx"), &fixture.resource, &control).is_err()
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
        let qualified = NativeQualifiedResource::nginx_generation(
            resource_id.clone(),
            association_path
                .display()
                .to_str()
                .expect("association path is UTF-8"),
        )
        .expect("physical resource qualifies");
        NginxFixture {
            _root: root,
            resource: QualifiedNginxResource {
                spec: NginxResourceSpec {
                    resource: resource_id,
                    candidate,
                    current_generation: None,
                    current_candidate_digest: None,
                    desired_generation: Some(revision("desired")),
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
