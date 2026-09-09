//! Trusted managed-configuration resource admission and atomic publication.
//!
//! The catalog receives destination authority, candidate bytes, and revisions
//! from the native orchestrator. Checked plans carry only Boolean method
//! parameters and cannot select filesystem paths. The adapter stages immutable
//! candidates, publishes with an expected-old check, and records the selected
//! revision after the destination directory is durable. Its durable formats are:
//!
//! ```text
//! {"schema":"aos.ability.managed-configuration-request/v1",...}
//! {"schema":"aos.ability.managed-configuration-revision/v1",...}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

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
use crate::config_eval::native_ability_fs::{
    RootedDirectory, RootedFile, authenticate_native_executor,
};

const INTERFACE_NAME: &str = "aos.managed-configuration-effects";
const INTERFACE_DESCRIPTOR: &str =
    "sha256:2b5e3051194f29f19bdf178c7e51f3bc4dbee7b67eafb04cba7953580dd990bf";
const HANDLER_KEY: &str = "managed-configuration-terminal";
const ENTRY_POINT: &str = "bin/.aos-package-runtime-unwrapped";
const REQUEST_SCHEMA: &str = "aos.ability.managed-configuration-request/v1";
const MARKER_SCHEMA: &str = "aos.ability.managed-configuration-revision/v1";
const MAX_MARKER_BYTES: u64 = 16 * 1024;

/// Binds one logical resource to native candidate and destination authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedConfigurationResourceSpec {
    /// Names the logical resource declared by the checked provider.
    pub resource: ResourceId,
    /// Names the destination relative to the catalog's trusted root.
    pub destination: PathBuf,
    /// Carries the exact candidate bytes selected by the native orchestrator.
    pub candidate: Vec<u8>,
    /// Gives the revision expected before publication or release.
    pub current_revision: Option<RevisionId>,
    /// Gives the revision assigned to the candidate, when one is being published.
    pub desired_revision: Option<RevisionId>,
}

#[derive(Clone, Debug)]
struct QualifiedManagedConfiguration {
    spec: ManagedConfigurationResourceSpec,
    destination: RootedFile,
    candidate_path: RootedFile,
    marker_path: RootedFile,
    candidate_digest: Sha256Digest,
    qualified: NativeQualifiedResource,
}

/// A fresh lock-bound handle for one managed configuration destination.
#[derive(Debug)]
pub struct ManagedConfigurationResourceHandle {
    resource: QualifiedManagedConfiguration,
    action: ManagedConfigurationAction,
    reservation: NativeResourceReservation,
}

/// Resolves logical resources to orchestrator-owned configuration paths and bytes.
pub struct ManagedConfigurationResourceCatalog {
    assignment: ProviderAssignment,
    inventory: NativeResourceInventory,
    resources: BTreeMap<ResourceId, QualifiedManagedConfiguration>,
}

impl ManagedConfigurationResourceCatalog {
    /// Constructs a catalog beneath exact trusted destination and private-state roots.
    ///
    /// Both roots and every destination parent must already exist as canonical
    /// directories. Every ancestor must prevent arbitrary rename, either by
    /// denying group/world writes or by enforcing sticky-directory ownership;
    /// the selected roots and descendants must additionally belong to
    /// `trusted_owner` and deny group/world writes. This keeps directory
    /// creation and path authority inside native orchestration.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical roots or destinations, duplicate logical
    /// or physical resources, resources owned by another provider, or invalid
    /// revision assignments. Host execution also rejects rooted or custom
    /// profile domains that do not share the machine-global collision ledger.
    pub fn new(
        destination_root: impl AsRef<Path>,
        private_state_root: impl AsRef<Path>,
        assignment: ProviderAssignment,
        inventory: NativeResourceInventory,
        trusted_owner: u32,
        resources: impl IntoIterator<Item = ManagedConfigurationResourceSpec>,
    ) -> Result<Self, io::Error> {
        if trusted_owner != 0 || assignment.provider.environment.stage != ExecutionStage::Host {
            return Err(invalid_data(
                "managed configuration supports only the root-owned host execution view",
            ));
        }
        require_machine_global_host_collision_domain()?;
        let destination_root =
            RootedDirectory::open(destination_root.as_ref(), trusted_owner, "destination root")?;
        let private_state_root = RootedDirectory::open(
            private_state_root.as_ref(),
            trusted_owner,
            "private state root",
        )?;
        let candidate_root = private_state_root.child_directory("candidates")?;
        let marker_root = private_state_root.child_directory("revisions")?;

        let mut destinations = BTreeSet::new();
        let mut indexed = BTreeMap::new();
        for spec in resources {
            if spec.resource.provider != assignment.provider {
                return Err(invalid_data(
                    "managed configuration resource belongs to another provider",
                ));
            }
            if spec.desired_revision.is_some() && spec.candidate.is_empty() {
                return Err(invalid_data("managed configuration candidate is empty"));
            }
            let destination = destination_root.resolve(&spec.destination)?;
            if !destinations.insert(destination.display().to_path_buf()) {
                return Err(invalid_data(
                    "distinct managed configuration resources share a destination",
                ));
            }
            let candidate_digest = Sha256Digest::of_bytes(&spec.candidate);
            let candidate_path = candidate_root.child(candidate_digest.to_string())?;
            let marker_name =
                Sha256Digest::of_bytes(destination.display().as_os_str().as_encoded_bytes());
            let marker_path = marker_root.child(marker_name.to_string())?;
            let object = destination
                .display()
                .to_str()
                .ok_or_else(|| invalid_data("managed configuration destination is not UTF-8"))?;
            let qualified =
                NativeQualifiedResource::managed_configuration(spec.resource.clone(), object)
                    .map_err(store_error)?;
            let resource = spec.resource.clone();
            if indexed
                .insert(
                    resource,
                    QualifiedManagedConfiguration {
                        spec,
                        destination,
                        candidate_path,
                        marker_path,
                        candidate_digest,
                        qualified,
                    },
                )
                .is_some()
            {
                return Err(invalid_data(
                    "managed configuration catalog contains a duplicate resource",
                ));
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

    /// Returns the trusted candidate bytes and revisions for a catalog member.
    #[must_use]
    pub fn resource_spec(
        &self,
        resource: &ResourceId,
    ) -> Option<&ManagedConfigurationResourceSpec> {
        self.resources.get(resource).map(|entry| &entry.spec)
    }
}

impl TrustedResourceCatalog for ManagedConfigurationResourceCatalog {
    type Handle = ManagedConfigurationResourceHandle;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        if context.expected_provider != Some(&self.assignment) {
            return Err(invalid_data(
                "managed configuration provider assignment is absent or stale",
            ));
        }
        if operation.target.resource != access.resource {
            return Err(invalid_data(
                "managed configuration access does not target the operation resource",
            ));
        }
        let resource = self
            .resources
            .get(&access.resource)
            .ok_or_else(|| {
                invalid_data("managed configuration resource is outside the authorized catalog")
            })?
            .clone();
        let action = action_for(operation)?;
        validate_action_spec(&action, &resource.spec)?;
        let reservation = self
            .inventory
            .reserve(&resource.qualified, context, operation, access)
            .map_err(store_error)?;
        let revision = observe_revision(&resource)?;
        let evidence = ResourceAdmissionEvidence::new_with_revision_observation(
            access.resource.clone(),
            Some(self.assignment.incarnation.clone()),
            revision,
            boolean_value(matches!(revision, ResourceRevisionObservation::Present(_)))?,
        );
        Ok(CatalogReservation::new(
            ManagedConfigurationResourceHandle {
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
                "managed configuration release does not match its reservation",
            ));
        }
        handle.reservation.release().map_err(store_error)
    }
}

/// Durable managed-configuration request reconstructed with a fresh native handle.
#[derive(Clone, Debug)]
pub struct ManagedConfigurationRequest {
    durable: ManagedConfigurationDurableRequest,
    resource: QualifiedManagedConfiguration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ManagedConfigurationAction {
    Prepare,
    Publish,
    Release,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedConfigurationDurableRequest {
    schema: String,
    action: ManagedConfigurationAction,
    resource: ResourceId,
    destination: String,
    candidate_digest: Sha256Digest,
    current_revision: Option<RevisionId>,
    desired_revision: Option<RevisionId>,
}

/// Boolean completion or observation evidence for a managed configuration call.
#[derive(Clone, Debug)]
pub struct ManagedConfigurationRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for ManagedConfigurationRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for ManagedConfigurationRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

/// Executes authenticated managed-configuration terminal methods.
pub struct NativeManagedConfigurationAdapter {
    assignment: ProviderAssignment,
    success: ManagedConfigurationRecord,
    failure: ManagedConfigurationRecord,
}

impl NativeManagedConfigurationAdapter {
    /// Constructs an adapter from one exact sealed terminal assignment.
    ///
    /// # Errors
    ///
    /// Returns an error unless the package uses structured effects and resolves
    /// the assignment to the exact managed-configuration interface, handler,
    /// artifact, native runtime entry point, and currently executing package
    /// runtime.
    pub fn new(
        package: &VerifiedAbilityPackage,
        assignment: ProviderAssignment,
    ) -> Result<Self, io::Error> {
        authenticate(package, &assignment)?;
        authenticate_native_executor(
            &assignment.implementation.artifact,
            ENTRY_POINT,
            "managed configuration",
        )?;
        Ok(Self {
            assignment,
            success: record(true)?,
            failure: record(false)?,
        })
    }
}

impl TrustedAdapter for NativeManagedConfigurationAdapter {
    type Request = ManagedConfigurationRequest;
    type Completion = ManagedConfigurationRecord;
    type Observation = ManagedConfigurationRecord;
    type Handle = ManagedConfigurationResourceHandle;
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
            && matches!(method.method.as_str(), "prepare" | "publish" | "release")
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        if inputs.as_json() != &serde_json::Value::Bool(true) {
            return Err(invalid_data(
                "managed configuration method requires the closed Boolean input true",
            ));
        }
        if operation.interface != self.assignment.interface {
            return Err(invalid_data(
                "managed configuration operation uses another interface",
            ));
        }
        let action = action_for(operation)?;
        let [resource] = resources else {
            return Err(invalid_data(
                "managed configuration operation requires exactly one resource",
            ));
        };
        if resource.resource() != &operation.target.resource {
            return Err(invalid_data(
                "managed configuration handle does not match the operation target",
            ));
        }
        if resource.native().action != action {
            return Err(invalid_data(
                "managed configuration handle was acquired for another operation family",
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
        let request: ManagedConfigurationDurableRequest =
            serde_json::from_value(durable.as_json().clone()).map_err(|error| {
                invalid_data(format!(
                    "invalid durable managed configuration request: {error}"
                ))
            })?;
        if request.schema != REQUEST_SCHEMA {
            return Err(invalid_data(
                "unsupported durable managed configuration request schema",
            ));
        }
        let [resource] = resources else {
            return Err(invalid_data(
                "managed configuration recovery requires exactly one resource",
            ));
        };
        validate_recovered_request(
            &request,
            &resource.native().action,
            &resource.native().resource,
        )?;
        Ok(ManagedConfigurationRequest {
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
        match execute_request(request) {
            Ok(()) => EffectDisposition::Completed(self.success.clone()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                EffectDisposition::RejectedBeforeEffect(self.failure.clone())
            }
            Err(_) => EffectDisposition::Indeterminate(self.failure.clone()),
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
    request: &ManagedConfigurationDurableRequest,
    acquired_action: &ManagedConfigurationAction,
    resource: &QualifiedManagedConfiguration,
) -> Result<(), io::Error> {
    if &request.action != acquired_action {
        return Err(invalid_data(
            "durable managed configuration action disagrees with fresh acquisition",
        ));
    }
    validate_action_spec(&request.action, &resource.spec)?;
    if request != &durable_request(request.action.clone(), resource)? {
        return Err(invalid_data(
            "durable managed configuration request disagrees with fresh acquisition",
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

fn execute_request(request: &ManagedConfigurationRequest) -> Result<(), io::Error> {
    match request.durable.action {
        ManagedConfigurationAction::Prepare => stage_candidate(&request.resource),
        ManagedConfigurationAction::Publish => publish_candidate(&request.resource),
        ManagedConfigurationAction::Release => release_destination(&request.resource),
    }
}

fn reconcile_request(request: &ManagedConfigurationRequest) -> Result<ReconcileState, io::Error> {
    let resource = &request.resource;
    match request.durable.action {
        ManagedConfigurationAction::Prepare => match verify_candidate(resource) {
            Ok(()) => {
                resource.candidate_path.sync_parent()?;
                Ok(ReconcileState::Completed)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Ok(ReconcileState::SafeToRetry)
            }
            Err(_) => Ok(ReconcileState::Intervention),
        },
        ManagedConfigurationAction::Publish => {
            let observation = observe_revision(resource)?;
            if destination_has_candidate(resource)? {
                if observation == expected_observation(resource.spec.desired_revision) {
                    resource.destination.sync_parent()?;
                    resource.marker_path.sync_parent()?;
                    return Ok(ReconcileState::Completed);
                }
                if !marker_matches_revision_association(resource, resource.spec.current_revision)? {
                    return Ok(ReconcileState::Intervention);
                }

                // A crash after rename but before directory fsync must not let
                // the later marker become the only durable object.
                resource.destination.sync_parent()?;
                write_marker(resource)?;
                return Ok(ReconcileState::Completed);
            }
            Ok(
                if observation == expected_observation(resource.spec.current_revision) {
                    ReconcileState::SafeToRetry
                } else {
                    ReconcileState::Intervention
                },
            )
        }
        ManagedConfigurationAction::Release => {
            let observation = observe_revision(resource)?;
            if matches!(observation, ResourceRevisionObservation::Absent) {
                resource.destination.sync_parent()?;
                resource.marker_path.sync_parent()?;
                Ok(ReconcileState::Completed)
            } else if observation == expected_observation(resource.spec.current_revision) {
                Ok(ReconcileState::SafeToRetry)
            } else if !resource.destination.exists()?
                && marker_matches_revision_association(resource, resource.spec.current_revision)?
            {
                resource.destination.sync_parent()?;
                remove_marker(resource)?;
                Ok(ReconcileState::Completed)
            } else {
                Ok(ReconcileState::Intervention)
            }
        }
    }
}

fn stage_candidate(resource: &QualifiedManagedConfiguration) -> Result<(), io::Error> {
    if resource.candidate_path.exists()? {
        verify_candidate(resource)?;
        return resource.candidate_path.sync_parent();
    }
    resource
        .candidate_path
        .atomic_write(&resource.spec.candidate, true)
}

fn publish_candidate(resource: &QualifiedManagedConfiguration) -> Result<(), io::Error> {
    verify_candidate(resource)?;
    if observe_revision(resource)? != expected_observation(resource.spec.current_revision) {
        return Err(invalid_data(
            "managed configuration expected revision is stale",
        ));
    }
    resource
        .destination
        .atomic_write(&resource.spec.candidate, false)?;
    write_marker(resource)
}

fn release_destination(resource: &QualifiedManagedConfiguration) -> Result<(), io::Error> {
    if observe_revision(resource)? != expected_observation(resource.spec.current_revision) {
        return Err(invalid_data(
            "managed configuration release revision is stale",
        ));
    }
    resource.destination.remove()?;
    resource.destination.sync_parent()?;
    remove_marker(resource)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevisionMarker {
    schema: String,
    destination: String,
    revision: RevisionId,
    content: Sha256Digest,
}

fn observe_revision(
    resource: &QualifiedManagedConfiguration,
) -> Result<ResourceRevisionObservation, io::Error> {
    let destination = resource.destination.read_optional(16 * 1024 * 1024)?;
    let marker = read_marker_optional(&resource.marker_path)?;
    match (destination, marker) {
        (None, None) => Ok(ResourceRevisionObservation::Absent),
        (Some(bytes), Some(marker))
            if marker.schema == MARKER_SCHEMA
                && marker.destination == path_string(resource.destination.display())?
                && marker.content == Sha256Digest::of_bytes(&bytes) =>
        {
            Ok(ResourceRevisionObservation::Present(marker.revision))
        }
        _ => Ok(ResourceRevisionObservation::Unknown),
    }
}

fn destination_has_candidate(resource: &QualifiedManagedConfiguration) -> Result<bool, io::Error> {
    Ok(resource
        .destination
        .read_optional(16 * 1024 * 1024)?
        .is_some_and(|bytes| Sha256Digest::of_bytes(&bytes) == resource.candidate_digest))
}

fn marker_matches_revision_association(
    resource: &QualifiedManagedConfiguration,
    expected_revision: Option<RevisionId>,
) -> Result<bool, io::Error> {
    let marker = read_marker_optional(&resource.marker_path)?;
    let Some(marker) = marker else {
        return Ok(expected_revision.is_none());
    };
    let Some(expected_revision) = expected_revision else {
        return Ok(false);
    };

    // A completed destination rename makes the old content association
    // unverifiable. The protected marker must still name the exact destination
    // and revision admitted before the interrupted operation.
    Ok(marker.schema == MARKER_SCHEMA
        && marker.destination == path_string(resource.destination.display())?
        && marker.revision == expected_revision)
}

fn write_marker(resource: &QualifiedManagedConfiguration) -> Result<(), io::Error> {
    let revision = resource
        .spec
        .desired_revision
        .ok_or_else(|| invalid_data("publish has no desired revision"))?;
    let marker = RevisionMarker {
        schema: MARKER_SCHEMA.to_string(),
        destination: path_string(resource.destination.display())?,
        revision,
        content: resource.candidate_digest,
    };
    let bytes = serde_json::to_vec(&marker)
        .map_err(|error| invalid_data(format!("encoding revision marker: {error}")))?;
    resource.marker_path.atomic_write(&bytes, false)
}

fn remove_marker(resource: &QualifiedManagedConfiguration) -> Result<(), io::Error> {
    resource.marker_path.remove()?;
    resource.marker_path.sync_parent()
}

fn verify_candidate(resource: &QualifiedManagedConfiguration) -> Result<(), io::Error> {
    let bytes = resource
        .candidate_path
        .read(resource.spec.candidate.len().saturating_add(1) as u64)?;
    if bytes == resource.spec.candidate
        && Sha256Digest::of_bytes(&bytes) == resource.candidate_digest
    {
        Ok(())
    } else {
        Err(invalid_data(
            "immutable managed configuration candidate changed",
        ))
    }
}

fn action_for(operation: &Operation) -> Result<ManagedConfigurationAction, io::Error> {
    let action = match operation.family {
        OperationFamily::PrepareManagedConfiguration => ManagedConfigurationAction::Prepare,
        OperationFamily::PublishConfiguration => ManagedConfigurationAction::Publish,
        OperationFamily::ReleaseResource => ManagedConfigurationAction::Release,
        _ => {
            return Err(invalid_data(
                "unsupported managed configuration operation family",
            ));
        }
    };
    let expected = match action {
        ManagedConfigurationAction::Prepare => "prepare",
        ManagedConfigurationAction::Publish => "publish",
        ManagedConfigurationAction::Release => "release",
    };
    if operation.method.as_str() != expected {
        return Err(invalid_data(
            "managed configuration method disagrees with operation family",
        ));
    }
    Ok(action)
}

fn validate_action_spec(
    action: &ManagedConfigurationAction,
    spec: &ManagedConfigurationResourceSpec,
) -> Result<(), io::Error> {
    match action {
        ManagedConfigurationAction::Prepare | ManagedConfigurationAction::Publish
            if spec.desired_revision.is_none() =>
        {
            Err(invalid_data(
                "managed configuration candidate has no desired revision",
            ))
        }
        ManagedConfigurationAction::Release if spec.desired_revision.is_some() => Err(
            invalid_data("managed configuration release unexpectedly carries a desired revision"),
        ),
        _ => Ok(()),
    }
}

fn durable_request(
    action: ManagedConfigurationAction,
    resource: &QualifiedManagedConfiguration,
) -> Result<ManagedConfigurationDurableRequest, io::Error> {
    Ok(ManagedConfigurationDurableRequest {
        schema: REQUEST_SCHEMA.to_string(),
        action,
        resource: resource.spec.resource.clone(),
        destination: path_string(resource.destination.display())?,
        candidate_digest: resource.candidate_digest,
        current_revision: resource.spec.current_revision,
        desired_revision: resource.spec.desired_revision,
    })
}

fn encode_request(request: ManagedConfigurationDurableRequest) -> Result<AbilityValue, io::Error> {
    let value = serde_json::to_value(request).map_err(|error| {
        invalid_data(format!("encoding managed configuration request: {error}"))
    })?;
    AbilityValue::new(value).map_err(|error| {
        invalid_data(format!(
            "managed configuration request exceeds limits: {error}"
        ))
    })
}

fn authenticate(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    if package.activation_mode() != AbilityActivationMode::StructuredEffects
        || assignment.interface != expected_interface()?
    {
        return Err(invalid_data(
            "managed configuration adapter requires its exact structured-effects interface",
        ));
    }
    let handler_key =
        LocalKey::new(HANDLER_KEY).map_err(|error| invalid_data(error.to_string()))?;
    if assignment.implementation.handler.as_ref() != Some(&handler_key) {
        return Err(invalid_data(
            "managed configuration assignment selects another handler",
        ));
    }
    let verified = package
        .resolve_terminal_handler(assignment.implementation.descriptor, &handler_key)
        .ok_or_else(|| {
            invalid_data(
                "authenticated package does not resolve the assigned managed configuration handler",
            )
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
            "authenticated managed configuration provider linkage differs from the assignment",
        ));
    }
    Ok(())
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

fn read_marker_optional(path: &RootedFile) -> Result<Option<RevisionMarker>, io::Error> {
    let Some(bytes) = path.read_optional(MAX_MARKER_BYTES)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        invalid_data(format!(
            "invalid managed configuration revision marker: {error}"
        ))
    })
}

fn expected_observation(revision: Option<RevisionId>) -> ResourceRevisionObservation {
    revision.map_or(
        ResourceRevisionObservation::Absent,
        ResourceRevisionObservation::Present,
    )
}

fn path_string(path: &Path) -> Result<String, io::Error> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| invalid_data("managed configuration path is not UTF-8"))
}

fn boolean_value(value: bool) -> Result<AbilityValue, io::Error> {
    AbilityValue::new(serde_json::Value::Bool(value))
        .map_err(|error| invalid_data(error.to_string()))
}

fn record(value: bool) -> Result<ManagedConfigurationRecord, io::Error> {
    Ok(ManagedConfigurationRecord {
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
    use aos_ability_model::{ArtifactReference, EnvironmentId, InstanceId};
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn destinations_reject_path_aliases() {
        let root = tempfile::tempdir().expect("temporary root is created");
        let owner = std::fs::metadata(root.path())
            .expect("root metadata is read")
            .uid();
        let rooted =
            RootedDirectory::open(root.path(), owner, "test root").expect("test root is opened");
        assert!(rooted.resolve(Path::new("etc/nginx.conf")).is_err());
        std::fs::create_dir(root.path().join("etc")).expect("destination parent is created");
        assert!(rooted.resolve(Path::new("etc/nginx.conf")).is_ok());
        for alias in ["../nginx.conf", "etc/../nginx.conf", "/etc/nginx.conf"] {
            assert!(rooted.resolve(Path::new(alias)).is_err(), "{alias}");
        }
    }

    #[test]
    fn descriptor_relative_write_replaces_only_the_named_symlink() {
        let root = tempfile::tempdir().expect("temporary root is created");
        let owner = std::fs::metadata(root.path())
            .expect("root metadata is read")
            .uid();
        let rooted =
            RootedDirectory::open(root.path(), owner, "test root").expect("test root is opened");
        let destination = rooted
            .child("nginx.conf".to_string())
            .expect("target resolves");
        std::os::unix::fs::symlink("elsewhere", root.path().join("nginx.conf"))
            .expect("attacker symlink is created");

        destination
            .atomic_write(b"candidate", false)
            .expect("rename replaces only the named link");
        assert_eq!(
            destination.read(64).expect("candidate is readable"),
            b"candidate"
        );
    }

    #[test]
    fn publish_reconcile_repairs_destination_before_marker_crash_window() {
        let fixture = managed_fixture(None, Some(revision("desired")), b"candidate");
        fixture
            .resource
            .destination
            .atomic_write(b"candidate", false)
            .expect("simulated destination rename succeeds");
        let request = ManagedConfigurationRequest {
            durable: durable_request(ManagedConfigurationAction::Publish, &fixture.resource)
                .expect("durable request encodes"),
            resource: fixture.resource.clone(),
        };

        assert_eq!(
            reconcile_request(&request).expect("crash window reconciles"),
            ReconcileState::Completed
        );
        assert_eq!(
            observe_revision(&fixture.resource).expect("repaired revision is observed"),
            ResourceRevisionObservation::Present(revision("desired"))
        );
    }

    #[test]
    fn publish_rejects_stale_revision_without_replacing_destination() {
        let fixture = managed_fixture(
            Some(revision("expected")),
            Some(revision("desired")),
            b"new candidate",
        );
        fixture
            .resource
            .destination
            .atomic_write(b"old candidate", false)
            .expect("old destination is installed");
        let stale_marker = RevisionMarker {
            schema: MARKER_SCHEMA.to_string(),
            destination: path_string(fixture.resource.destination.display())
                .expect("destination is UTF-8"),
            revision: revision("other"),
            content: Sha256Digest::of_bytes(b"old candidate"),
        };
        fixture
            .resource
            .marker_path
            .atomic_write(
                &serde_json::to_vec(&stale_marker).expect("marker encodes"),
                false,
            )
            .expect("stale marker is installed");
        stage_candidate(&fixture.resource).expect("new candidate is staged");

        assert!(publish_candidate(&fixture.resource).is_err());
        assert_eq!(
            fixture
                .resource
                .destination
                .read(64)
                .expect("old destination remains"),
            b"old candidate"
        );
    }

    #[test]
    fn publish_reconcile_rejects_a_foreign_revision_with_identical_content() {
        let fixture = managed_fixture(
            Some(revision("expected")),
            Some(revision("desired")),
            b"candidate",
        );
        fixture
            .resource
            .destination
            .atomic_write(b"candidate", false)
            .expect("candidate destination is installed");
        write_test_marker(&fixture.resource, revision("foreign"), b"candidate");
        let request = ManagedConfigurationRequest {
            durable: durable_request(ManagedConfigurationAction::Publish, &fixture.resource)
                .expect("durable request encodes"),
            resource: fixture.resource.clone(),
        };

        assert_eq!(
            reconcile_request(&request).expect("foreign marker is inspected"),
            ReconcileState::Intervention
        );
        assert_eq!(
            observe_revision(&fixture.resource).expect("foreign marker remains observable"),
            ResourceRevisionObservation::Present(revision("foreign"))
        );
    }

    #[test]
    fn release_reconcile_rejects_a_foreign_revision_after_destination_removal() {
        let fixture = managed_fixture(Some(revision("expected")), None, b"");
        write_test_marker(&fixture.resource, revision("foreign"), b"old candidate");
        let request = ManagedConfigurationRequest {
            durable: durable_request(ManagedConfigurationAction::Release, &fixture.resource)
                .expect("durable request encodes"),
            resource: fixture.resource.clone(),
        };

        assert_eq!(
            reconcile_request(&request).expect("foreign marker is inspected"),
            ReconcileState::Intervention
        );
        assert_eq!(
            read_marker_optional(&fixture.resource.marker_path)
                .expect("foreign marker is readable")
                .expect("foreign marker remains")
                .revision,
            revision("foreign")
        );
    }

    #[test]
    fn recovery_rejects_a_mutated_durable_action() {
        let fixture = managed_fixture(None, Some(revision("desired")), b"candidate");
        let mut durable = durable_request(ManagedConfigurationAction::Prepare, &fixture.resource)
            .expect("durable request encodes");
        durable.action = ManagedConfigurationAction::Publish;

        assert!(
            validate_recovered_request(
                &durable,
                &ManagedConfigurationAction::Prepare,
                &fixture.resource,
            )
            .is_err()
        );
    }

    #[test]
    fn rooted_directory_rejects_lexical_and_symlink_aliases() {
        let root = tempfile::tempdir().expect("temporary root is created");
        let owner = std::fs::metadata(root.path())
            .expect("root metadata is read")
            .uid();
        let alias = root.path().with_extension("alias");
        std::os::unix::fs::symlink(root.path(), &alias).expect("root alias is created");
        assert!(RootedDirectory::open(&alias, owner, "test root").is_err());

        let doubled = PathBuf::from(format!("//{}", &root.path().display().to_string()[1..]));
        assert!(RootedDirectory::open(&doubled, owner, "test root").is_err());
        std::fs::remove_file(alias).expect("root alias is removed");
    }

    #[test]
    fn assigned_runtime_rejects_a_different_current_executable() {
        let artifact = ArtifactReference {
            content: Sha256Digest::of_bytes(b"managed runtime content"),
            store_path: "/nix/store/00000000000000000000000000000000-managed-runtime".to_string(),
            nar_hash: Sha256Digest::of_bytes(b"managed runtime nar"),
            closure: Sha256Digest::of_bytes(b"managed runtime closure"),
        };
        let assigned = Path::new(&artifact.store_path).join(ENTRY_POINT);
        crate::config_eval::native_ability_fs::authenticate_native_executor_path(
            &artifact,
            ENTRY_POINT,
            "managed configuration",
            &assigned,
        )
        .expect("assigned native executor authenticates");

        let forged = Path::new(
            "/nix/store/11111111111111111111111111111111-forged-runtime/bin/.aos-package-runtime-unwrapped",
        );
        assert!(
            crate::config_eval::native_ability_fs::authenticate_native_executor_path(
                &artifact,
                ENTRY_POINT,
                "managed configuration",
                forged,
            )
            .is_err()
        );
    }

    struct ManagedFixture {
        _root: tempfile::TempDir,
        resource: QualifiedManagedConfiguration,
    }

    fn managed_fixture(
        current_revision: Option<RevisionId>,
        desired_revision: Option<RevisionId>,
        candidate: &[u8],
    ) -> ManagedFixture {
        let root = tempfile::tempdir().expect("temporary root is created");
        let owner = std::fs::metadata(root.path())
            .expect("root metadata is read")
            .uid();
        for directory in [
            "destinations",
            "state",
            "state/candidates",
            "state/revisions",
        ] {
            std::fs::create_dir(root.path().join(directory)).expect("fixture directory is created");
        }
        let destinations = RootedDirectory::open(
            &root.path().join("destinations"),
            owner,
            "test destinations",
        )
        .expect("destination root opens");
        let state = RootedDirectory::open(&root.path().join("state"), owner, "test state")
            .expect("state root opens");
        let candidates = state
            .child_directory("candidates")
            .expect("candidate root opens");
        let revisions = state
            .child_directory("revisions")
            .expect("revision root opens");
        let resource_id = test_resource_id();
        let destination = destinations
            .child("nginx.conf".to_string())
            .expect("destination resolves");
        let candidate_digest = Sha256Digest::of_bytes(candidate);
        let marker_name =
            Sha256Digest::of_bytes(destination.display().as_os_str().as_encoded_bytes());
        let qualified = NativeQualifiedResource::managed_configuration(
            resource_id.clone(),
            destination
                .display()
                .to_str()
                .expect("destination is UTF-8"),
        )
        .expect("physical resource qualifies");
        ManagedFixture {
            _root: root,
            resource: QualifiedManagedConfiguration {
                spec: ManagedConfigurationResourceSpec {
                    resource: resource_id,
                    destination: PathBuf::from("nginx.conf"),
                    candidate: candidate.to_vec(),
                    current_revision,
                    desired_revision,
                },
                destination,
                candidate_path: candidates
                    .child(candidate_digest.to_string())
                    .expect("candidate path resolves"),
                marker_path: revisions
                    .child(marker_name.to_string())
                    .expect("marker path resolves"),
                candidate_digest,
                qualified,
            },
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
                key: LocalKey::new("managed").expect("provider is valid"),
            },
            key: LocalKey::new("configuration").expect("resource is valid"),
        }
    }

    fn revision(label: &str) -> RevisionId {
        RevisionId(Sha256Digest::of_bytes(label.as_bytes()))
    }

    fn write_test_marker(
        resource: &QualifiedManagedConfiguration,
        marker_revision: RevisionId,
        content: &[u8],
    ) {
        let marker = RevisionMarker {
            schema: MARKER_SCHEMA.to_string(),
            destination: path_string(resource.destination.display()).expect("destination is UTF-8"),
            revision: marker_revision,
            content: Sha256Digest::of_bytes(content),
        };
        resource
            .marker_path
            .atomic_write(
                &serde_json::to_vec(&marker).expect("test marker encodes"),
                false,
            )
            .expect("test marker is installed");
    }
}
