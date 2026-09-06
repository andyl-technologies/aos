//! Drives signed destination-slot materialization and reaping from reconciliation.
//!
//! The controller derives every protocol field from protected logical state,
//! binds the resulting deadline-free body to a separately signed Mount 1.3
//! plan, and records the exact lease-bound packet before broker I/O:
//!
//! ```text
//! logical slot + authenticated inventory + current namespace authority
//!     -> exact portable slot body -> signed Mount plan
//!     -> durable attempt -> authenticated durable completion
//! ```
//!
//! Pending recovery retains the original request body, signed plan, and local
//! deadline. A renewed ownership lease may reconstruct only the envelope; it
//! cannot change operation identity, assignment, slot binding, specification,
//! resource fence, or effect semantics.

use aos_proto::aos::sandbox::local::v1::{
    ApplyDestinationSlotRequest, AssignmentFence, Audience, BrokerMethod, DestinationSlotAction,
    DestinationSlotLifecycle, RequestHeader,
};
use aos_sandbox_core::{
    ObjectDigest, OperationId, ProtocolVersion, RawPairedClockSample, Revision,
};
use aos_sandbox_protocol::semantics::canonical_destination_slot_semantics_v1;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedDestinationSlotInventoryRecord,
    ValidatedDestinationSlotRequest, decode_destination_slot_request,
};
use buffa::Message as _;

use crate::attachment_slot_state::{
    AttachmentSlotPresenceV1, DurableAttachmentSlotV1, get_revision_in_validated_namespace,
};
use crate::destination_slot_inventory::{
    CurrentDestinationSlotReconciliationV1, DestinationSlotReconciliationActionV1,
    matching_resource,
};
use crate::dispatch::{BrokerDispatchSemanticIdentityV1, BrokerDispatchTemplateV1};
use crate::mount_preparation::{self, MountCatalogPreparationError};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::CurrentNamespaceTarget;
use crate::{Journal, SignedBrokerPlan};

mod attempt;
mod completion;

pub use attempt::{
    DestinationSlotAttemptAdmissionOutcomeV1, DurableCurrentDestinationSlotAttemptV1,
};
pub use completion::{
    CompletedCurrentDestinationSlotAttemptV1, DestinationSlotCompletionOutcomeV1,
    DestinationSlotDispatchClient,
};

pub(crate) const CARRIER_VERSION: ProtocolVersion = ProtocolVersion::new(1, 3);
pub(crate) const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT;
pub(crate) const RESPONSE_BYTES: u32 = 16 * 1024;

/// Reports stale reconciliation, invalid authority, or durable effect failure.
#[derive(Debug, thiserror::Error)]
pub enum DestinationSlotEffectError {
    /// The authenticated inventory or current logical slot changed.
    #[error(transparent)]
    Reconciliation(#[from] crate::mount_attempt::MountAttemptError),
    /// Reconciliation did not select a new materialize or reap effect.
    #[error("destination-slot reconciliation did not select a new effect")]
    NotPreparable,
    /// Reconciliation did not identify an exact pending durable effect.
    #[error("destination-slot reconciliation did not select a resumable effect")]
    NotResumable,
    /// Current logical slot history is missing, changed, or malformed.
    #[error(transparent)]
    Slot(#[from] crate::AttachmentSlotStateError),
    /// The retained canonical sandbox specification is missing or malformed.
    #[error(transparent)]
    Specification(#[from] crate::SandboxSpecStateError),
    /// Current signed runtime or namespace authority changed or expired.
    #[error(transparent)]
    Current(#[from] crate::runtime_scope::NamespaceTargetError),
    /// The current runtime rejected the selected signed Mount plan or lease.
    #[error(transparent)]
    Runtime(#[from] crate::runtime_scope::CurrentRuntimeScopeError),
    /// The signed plan does not bind the exact destination-slot semantics.
    #[error(transparent)]
    Template(#[from] crate::BrokerDispatchTemplateError),
    /// The request deadline or local exchange window is invalid.
    #[error(transparent)]
    Preparation(#[from] MountCatalogPreparationError),
    /// Hostile protocol bytes or the broker result failed validation.
    #[error(transparent)]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    /// Kernel record-subject validation or packet transfer failed.
    #[error(transparent)]
    Transport(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
    /// Kernel service identity or retained cgroup validation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// Protected effect state or its cross-references are inconsistent.
    #[error("destination-slot effect state is corrupt")]
    CorruptState,
    /// One operation identity is already bound to different exact bytes.
    #[error("destination-slot effect operation conflicts with durable state")]
    Conflict,
    /// Retained effect state exceeds a fixed count or byte ceiling.
    #[error("destination-slot effect state capacity is exhausted")]
    Capacity,
    /// The selected attempt deadline exceeds retained live authority.
    #[error("destination-slot effect deadline exceeds current authority")]
    Deadline,
    /// Mount rejected or could not complete the request.
    #[error("Mount rejected the destination-slot request with {code:?} (retryable: {retryable})")]
    BrokerRejected {
        /// Closed broker error code.
        code: aos_proto::aos::sandbox::local::v1::BrokerErrorCode,
        /// Whether the same exact request may succeed later.
        retryable: bool,
    },
    /// Protected journal provenance, health, or durability failed.
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
}

/// Retains a reconciler-derived destination-slot operation before plan binding.
pub struct PreparedCurrentDestinationSlotV1 {
    operation: PreparedOperation,
}

/// Retains an exact pending operation before its original signed plan is rebound.
pub struct PreparedCurrentDestinationSlotResumeV1 {
    operation: PreparedOperation,
    record: attempt::Record,
}

/// Retains a new operation and its separately verified signed Mount plan.
pub struct PreparedCurrentDestinationSlotDispatchV1 {
    operation: PreparedOperation,
    template: BrokerDispatchTemplateV1,
}

/// Retains a pending operation and the exact original signed Mount plan.
pub struct PreparedCurrentDestinationSlotResumeDispatchV1 {
    operation: PreparedOperation,
    template: BrokerDispatchTemplateV1,
    record: attempt::Record,
}

struct PreparedOperation {
    reconciliation: CurrentDestinationSlotReconciliationV1,
    target: CurrentNamespaceTarget,
    body_without_deadline: Vec<u8>,
    semantics: BrokerDispatchSemanticIdentityV1,
    valid_until_boottime_nanoseconds: u64,
    ready: Option<ReadyResourceExpectation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadyResourceExpectation {
    pub(super) materialization_operation_id: [u8; 16],
    pub(super) materialization_request_digest: [u8; 32],
    pub(super) resource_kernel_boot_id: [u8; 16],
    pub(super) slot_device: u64,
    pub(super) slot_inode: u64,
    pub(super) anchor_unique_mount_id: u64,
    pub(super) ready_resource_digest: [u8; 32],
}

impl ReadyResourceExpectation {
    fn from_ready(
        resource: &ValidatedDestinationSlotInventoryRecord,
    ) -> Result<Self, DestinationSlotEffectError> {
        if resource.lifecycle() != DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY {
            return Err(DestinationSlotEffectError::Conflict);
        }
        Ok(Self {
            materialization_operation_id: *resource.materialization().operation_id(),
            materialization_request_digest: *resource.materialization().request_digest(),
            resource_kernel_boot_id: *resource.resource_kernel_boot_id(),
            slot_device: resource
                .slot_device()
                .ok_or(DestinationSlotEffectError::CorruptState)?,
            slot_inode: resource
                .slot_inode()
                .ok_or(DestinationSlotEffectError::CorruptState)?,
            anchor_unique_mount_id: resource
                .anchor_unique_mount_id()
                .ok_or(DestinationSlotEffectError::CorruptState)?,
            ready_resource_digest: *resource.resource_digest(),
        })
    }

    pub(super) fn matches_preserved(
        self,
        resource: &ValidatedDestinationSlotInventoryRecord,
    ) -> bool {
        resource.materialization().operation_id() == &self.materialization_operation_id
            && resource.materialization().request_digest() == &self.materialization_request_digest
            && resource.resource_kernel_boot_id() == &self.resource_kernel_boot_id
            && resource.slot_device() == Some(self.slot_device)
            && resource.slot_inode() == Some(self.slot_inode)
            && resource.anchor_unique_mount_id() == Some(self.anchor_unique_mount_id)
    }

    pub(super) fn is_valid(self) -> bool {
        self.materialization_operation_id != [0; 16]
            && self.materialization_request_digest != [0; 32]
            && self.resource_kernel_boot_id != [0; 16]
            && self.slot_device != 0
            && self.slot_inode != 0
            && self.anchor_unique_mount_id != 0
            && self.ready_resource_digest != [0; 32]
    }
}

impl PreparedCurrentDestinationSlotV1 {
    /// Returns the exact closed reconciliation action being prepared.
    #[must_use]
    pub const fn action(&self) -> DestinationSlotReconciliationActionV1 {
        self.operation.reconciliation.action()
    }

    /// Returns the portable semantics a separately signed plan must contain.
    #[must_use]
    pub const fn semantics(&self) -> BrokerDispatchSemanticIdentityV1 {
        self.operation.semantics
    }

    /// Borrows the exact deadline-free protocol 1.3 request body.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.operation.body_without_deadline
    }

    /// Returns the exclusive lifetime inherited from current namespace authority.
    #[must_use]
    pub const fn valid_until_boottime_nanoseconds(&self) -> u64 {
        self.operation.valid_until_boottime_nanoseconds
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.operation.recheck(journal, clock)
    }
}

impl PreparedCurrentDestinationSlotResumeV1 {
    /// Returns the exact pending action being resumed.
    #[must_use]
    pub const fn action(&self) -> DestinationSlotReconciliationActionV1 {
        self.operation.reconciliation.action()
    }

    /// Returns the stable operation identity retained by Mount and the controller.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.record.request_id()
    }

    /// Returns the original signed plan digest required for recovery.
    #[must_use]
    pub const fn required_plan_digest(&self) -> ObjectDigest {
        self.record.plan_digest()
    }

    /// Borrows the exact original deadline-free request body.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.operation.body_without_deadline
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.operation.recheck(journal, clock)?;
        attempt::recheck_resume_record(journal, &self.operation, &self.record)
    }
}

impl PreparedCurrentDestinationSlotDispatchV1 {
    /// Borrows the exact signed, deadline-free Mount dispatch template.
    #[must_use]
    pub const fn template(&self) -> &BrokerDispatchTemplateV1 {
        &self.template
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.operation.recheck(journal, clock)?;
        verify_template(journal, &self.operation, &self.template, clock)
    }
}

impl PreparedCurrentDestinationSlotResumeDispatchV1 {
    /// Borrows the exact original signed Mount dispatch template.
    #[must_use]
    pub const fn template(&self) -> &BrokerDispatchTemplateV1 {
        &self.template
    }

    pub(crate) fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.operation.recheck(journal, clock)?;
        attempt::recheck_resume_record(journal, &self.operation, &self.record)?;
        verify_template(journal, &self.operation, &self.template, clock)?;
        if !self.record.matches_resume_template(&self.template) {
            return Err(DestinationSlotEffectError::Conflict);
        }
        Ok(())
    }
}

impl PreparedOperation {
    fn recheck<T>(
        &self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<(), DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.reconciliation.recheck(journal)?;
        self.target.recheck(journal, clock)?;
        validate_target(self.reconciliation.slot(), &self.target)?;
        mount_preparation::check_mount_deadline(self.valid_until_boottime_nanoseconds)?;
        validate_operation_body(journal, self)?;
        self.reconciliation.recheck(journal)?;
        self.target.recheck(journal, clock)?;
        Ok(())
    }
}

pub(crate) fn prepare_current<T>(
    journal: &mut Journal,
    reconciliation: CurrentDestinationSlotReconciliationV1,
    target: CurrentNamespaceTarget,
    clock: &mut T,
) -> Result<PreparedCurrentDestinationSlotV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    reconciliation.recheck(journal)?;
    target.recheck(journal, clock)?;
    validate_target(reconciliation.slot(), &target)?;

    let action = reconciliation.action();
    if !matches!(
        action,
        DestinationSlotReconciliationActionV1::Materialize { .. }
            | DestinationSlotReconciliationActionV1::Reap { .. }
    ) {
        return Err(DestinationSlotEffectError::NotPreparable);
    }
    let operation = build_operation(journal, reconciliation, target, action)?;
    operation.recheck(journal, clock)?;
    Ok(PreparedCurrentDestinationSlotV1 { operation })
}

pub(crate) fn prepare_current_resume<T>(
    journal: &mut Journal,
    reconciliation: CurrentDestinationSlotReconciliationV1,
    target: CurrentNamespaceTarget,
    clock: &mut T,
) -> Result<PreparedCurrentDestinationSlotResumeV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    reconciliation.recheck(journal)?;
    target.recheck(journal, clock)?;
    validate_target(reconciliation.slot(), &target)?;
    let request_id = resume_request_id(reconciliation.action())?;
    let record = attempt::replay_record(journal, request_id)?;
    let operation = build_replay_operation(journal, reconciliation, target, &record)?;
    let prepared = PreparedCurrentDestinationSlotResumeV1 { operation, record };
    prepared.recheck(journal, clock)?;
    Ok(prepared)
}

pub(crate) fn bind_signed_plan<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentDestinationSlotV1,
    signed_plan: SignedBrokerPlan,
    clock: &mut T,
) -> Result<PreparedCurrentDestinationSlotDispatchV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    let template = bind_template(journal, &prepared.operation, signed_plan, clock)?;
    let result = PreparedCurrentDestinationSlotDispatchV1 {
        operation: prepared.operation,
        template,
    };
    result.recheck(journal, clock)?;
    Ok(result)
}

pub(crate) fn bind_resume_signed_plan<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentDestinationSlotResumeV1,
    signed_plan: SignedBrokerPlan,
    clock: &mut T,
) -> Result<PreparedCurrentDestinationSlotResumeDispatchV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    prepared.recheck(journal, clock)?;
    let template = bind_template(journal, &prepared.operation, signed_plan, clock)?;
    if !prepared.record.matches_resume_template(&template) {
        return Err(DestinationSlotEffectError::Conflict);
    }
    let result = PreparedCurrentDestinationSlotResumeDispatchV1 {
        operation: prepared.operation,
        template,
        record: prepared.record,
    };
    result.recheck(journal, clock)?;
    Ok(result)
}

pub(crate) fn admit_current<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentDestinationSlotDispatchV1,
    deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<DurableCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    attempt::admit_current(journal, prepared, deadline_boottime_nanoseconds, clock)
}

pub(crate) fn resume_current<T>(
    journal: &mut Journal,
    prepared: PreparedCurrentDestinationSlotResumeDispatchV1,
    clock: &mut T,
) -> Result<DurableCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    attempt::resume_current(journal, prepared, clock)
}

pub(crate) fn dispatch_current<T>(
    journal: &mut Journal,
    attempt: DurableCurrentDestinationSlotAttemptV1,
    client: DestinationSlotDispatchClient,
    clock: &mut T,
) -> Result<CompletedCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    completion::dispatch_current(journal, attempt, client, clock)
}

pub(crate) fn validate_attempt_namespace(
    journal: &mut Journal,
) -> Result<(), DestinationSlotEffectError> {
    attempt::validate_namespace(journal)
}

pub(crate) fn validate_completion_namespace(
    journal: &mut Journal,
) -> Result<(), DestinationSlotEffectError> {
    completion::validate_namespace(journal)
}

pub(crate) fn contains_attempt_request_id(journal: &Journal, request_id: &[u8; 16]) -> bool {
    attempt::contains_request_id(journal, request_id)
}

pub(crate) fn controller_state_records(
    journal: &mut Journal,
) -> Result<ControllerStateRecords, DestinationSlotEffectError> {
    Ok(ControllerStateRecords {
        attempts: attempt::state_records(journal)?,
        completions: completion::state_records(journal)?,
    })
}

pub(crate) struct ControllerStateRecords {
    pub(crate) attempts: Vec<ControllerStateRecord>,
    pub(crate) completions: Vec<ControllerStateRecord>,
}

type ControllerStateRecord = ([u8; 16], [u8; 32]);

fn build_operation(
    journal: &mut Journal,
    reconciliation: CurrentDestinationSlotReconciliationV1,
    target: CurrentNamespaceTarget,
    action: DestinationSlotReconciliationActionV1,
) -> Result<PreparedOperation, DestinationSlotEffectError> {
    let slot = reconciliation.slot();
    let spec = crate::sandbox_spec_state::get(journal, slot.sandbox_spec())?
        .ok_or(DestinationSlotEffectError::Conflict)?;
    let (request_id, wire_action, resource_fence, expected_digest, ready) = match action {
        DestinationSlotReconciliationActionV1::Materialize { operation_id } => (
            operation_id,
            DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE,
            None,
            Vec::new(),
            None,
        ),
        DestinationSlotReconciliationActionV1::Reap {
            operation_id,
            expected_resource_digest,
        } => {
            let resource = matching_resource(slot, reconciliation.snapshot().inventory())?
                .ok_or(DestinationSlotEffectError::Conflict)?;
            let ready = ReadyResourceExpectation::from_ready(resource)?;
            if expected_resource_digest.as_bytes() != &ready.ready_resource_digest {
                return Err(DestinationSlotEffectError::Conflict);
            }
            (
                operation_id,
                DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP,
                Some(proto_fence(resource.fence())),
                expected_resource_digest.as_bytes().to_vec(),
                Some(ready),
            )
        }
        _ => return Err(DestinationSlotEffectError::NotPreparable),
    };
    let deadline = target
        .runtime_generation()
        .scope()
        .deadline_boottime_nanoseconds();
    let mut request = ApplyDestinationSlotRequest {
        header: Some(request_header(request_id, deadline)).into(),
        fence: Some(mount_preparation::current_fence(&target)).into(),
        resource_fence: resource_fence.into(),
        action: wire_action.into(),
        namespace_generation: slot.namespace_generation(),
        destination_slot_id: slot.slot_id().as_bytes().to_vec(),
        sandbox_spec: Some(proto_descriptor(slot.sandbox_spec())).into(),
        sandbox_spec_bytes: spec.canonical_bytes().to_vec(),
        expected_resource_digest: expected_digest,
        ..Default::default()
    };
    let validated = decode_request(&request.encode_to_vec(), deadline)?;
    let canonical = canonical_destination_slot_semantics_v1(&validated)
        .map_err(|_| DestinationSlotEffectError::CorruptState)?;
    let semantics = BrokerDispatchSemanticIdentityV1::new(
        canonical.verb(),
        canonical.target(),
        canonical.commitment(),
    );
    request
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = 0;

    Ok(PreparedOperation {
        reconciliation,
        target,
        body_without_deadline: request.encode_to_vec(),
        semantics,
        valid_until_boottime_nanoseconds: deadline,
        ready,
    })
}

fn build_replay_operation(
    journal: &mut Journal,
    reconciliation: CurrentDestinationSlotReconciliationV1,
    target: CurrentNamespaceTarget,
    record: &attempt::Record,
) -> Result<PreparedOperation, DestinationSlotEffectError> {
    if record.namespace_target() != target.durable_reference() {
        return Err(DestinationSlotEffectError::Conflict);
    }
    let request_bytes = crate::dispatch::durable_attempt_body(
        record.body_without_deadline(),
        record.deadline_boottime_nanoseconds(),
    )
    .map_err(|_| DestinationSlotEffectError::CorruptState)?;
    let request = decode_request(&request_bytes, record.deadline_boottime_nanoseconds())?;
    let canonical = canonical_destination_slot_semantics_v1(&request)
        .map_err(|_| DestinationSlotEffectError::CorruptState)?;
    let operation = PreparedOperation {
        reconciliation,
        target,
        body_without_deadline: record.body_without_deadline().to_vec(),
        semantics: BrokerDispatchSemanticIdentityV1::new(
            canonical.verb(),
            canonical.target(),
            canonical.commitment(),
        ),
        valid_until_boottime_nanoseconds: record.deadline_boottime_nanoseconds(),
        ready: record.ready_expectation(),
    };
    validate_operation_body(journal, &operation)?;
    Ok(operation)
}

fn bind_template<T>(
    journal: &mut Journal,
    operation: &PreparedOperation,
    signed_plan: SignedBrokerPlan,
    clock: &mut T,
) -> Result<BrokerDispatchTemplateV1, DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    operation
        .target
        .runtime_generation()
        .scope()
        .verify_mount_plan_version(journal, &signed_plan, CARRIER_VERSION, clock)?;
    Ok(BrokerDispatchTemplateV1::new(
        signed_plan,
        METHOD,
        operation.body_without_deadline.clone(),
        Vec::new(),
        operation.semantics,
    )?)
}

fn verify_template<T>(
    journal: &mut Journal,
    operation: &PreparedOperation,
    template: &BrokerDispatchTemplateV1,
    clock: &mut T,
) -> Result<(), DestinationSlotEffectError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if template.method() != METHOD
        || template.body_without_deadline() != operation.body_without_deadline
        || template.semantics() != operation.semantics
        || template.signed_plan().plan().protocol_version() != CARRIER_VERSION
    {
        return Err(DestinationSlotEffectError::Conflict);
    }
    operation
        .target
        .runtime_generation()
        .scope()
        .verify_mount_plan_version(journal, template.signed_plan(), CARRIER_VERSION, clock)?;
    Ok(())
}

fn validate_operation_body(
    journal: &mut Journal,
    operation: &PreparedOperation,
) -> Result<(), DestinationSlotEffectError> {
    let body = crate::dispatch::durable_attempt_body(
        &operation.body_without_deadline,
        operation.valid_until_boottime_nanoseconds,
    )
    .map_err(|_| DestinationSlotEffectError::CorruptState)?;
    let request = decode_request(&body, operation.valid_until_boottime_nanoseconds)?;
    let slot = operation.reconciliation.slot();
    let spec = crate::sandbox_spec_state::get(journal, slot.sandbox_spec())?
        .ok_or(DestinationSlotEffectError::Conflict)?;
    let canonical = canonical_destination_slot_semantics_v1(&request)
        .map_err(|_| DestinationSlotEffectError::CorruptState)?;
    if request.namespace_generation() != slot.namespace_generation()
        || request.destination_slot_id() != slot.slot_id().as_bytes()
        || request.sandbox_spec() != slot.sandbox_spec()
        || request.sandbox_spec_bytes() != spec.canonical_bytes()
        || BrokerDispatchSemanticIdentityV1::new(
            canonical.verb(),
            canonical.target(),
            canonical.commitment(),
        ) != operation.semantics
        || !request_matches_action(&request, operation.reconciliation.action(), operation.ready)
    {
        return Err(DestinationSlotEffectError::Conflict);
    }
    validate_target(slot, &operation.target)
}

fn request_matches_action(
    request: &ValidatedDestinationSlotRequest,
    action: DestinationSlotReconciliationActionV1,
    ready: Option<ReadyResourceExpectation>,
) -> bool {
    let request_id = request.header().request_id();
    match action {
        DestinationSlotReconciliationActionV1::Materialize { operation_id }
        | DestinationSlotReconciliationActionV1::ResumeMaterialize { operation_id } => {
            request.action() == DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE
                && request_id == operation_id.as_bytes()
                && ready.is_none()
        }
        DestinationSlotReconciliationActionV1::ResumeMaterializeForReap {
            operation_id, ..
        } => {
            request.action() == DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE
                && request_id == operation_id.as_bytes()
                && ready.is_none()
        }
        DestinationSlotReconciliationActionV1::Reap {
            operation_id,
            expected_resource_digest,
        } => {
            let expected = ready.map(|value| value.ready_resource_digest);
            request.action() == DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP
                && request_id == operation_id.as_bytes()
                && request.expected_resource_digest() == expected.as_ref()
                && expected_resource_digest.as_bytes() == expected.as_ref().unwrap_or(&[0; 32])
        }
        DestinationSlotReconciliationActionV1::ResumeReap { operation_id } => {
            let expected = ready.map(|value| value.ready_resource_digest);
            request.action() == DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP
                && request_id == operation_id.as_bytes()
                && request.expected_resource_digest() == expected.as_ref()
        }
        _ => false,
    }
}

fn validate_target(
    slot: &DurableAttachmentSlotV1,
    target: &CurrentNamespaceTarget,
) -> Result<(), DestinationSlotEffectError> {
    let manifest = target
        .runtime_generation()
        .scope()
        .binding()
        .manifest()
        .manifest();
    if manifest.sandbox() != slot.sandbox()
        || manifest.incarnation() != slot.incarnation()
        || target.target_generation() != slot.namespace_generation()
    {
        return Err(DestinationSlotEffectError::Conflict);
    }
    Ok(())
}

fn resume_request_id(
    action: DestinationSlotReconciliationActionV1,
) -> Result<OperationId, DestinationSlotEffectError> {
    match action {
        DestinationSlotReconciliationActionV1::ResumeMaterialize { operation_id }
        | DestinationSlotReconciliationActionV1::ResumeMaterializeForReap {
            operation_id, ..
        }
        | DestinationSlotReconciliationActionV1::ResumeReap { operation_id } => Ok(operation_id),
        _ => Err(DestinationSlotEffectError::NotResumable),
    }
}

fn request_header(operation_id: OperationId, deadline: u64) -> RequestHeader {
    RequestHeader {
        protocol_major: u32::from(CARRIER_VERSION.major()),
        protocol_minor: u32::from(CARRIER_VERSION.minor()),
        request_id: operation_id.as_bytes().to_vec(),
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: deadline,
        maximum_response_bytes: RESPONSE_BYTES,
        ..Default::default()
    }
}

pub(super) fn decode_request(
    bytes: &[u8],
    deadline: u64,
) -> Result<ValidatedDestinationSlotRequest, DestinationSlotEffectError> {
    let now = deadline
        .checked_sub(1)
        .ok_or(DestinationSlotEffectError::CorruptState)?;
    let peer = synthetic_credentials();
    Ok(decode_destination_slot_request(
        bytes,
        peer,
        PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        now,
    )?)
}

pub(super) fn synthetic_credentials() -> PeerCredentials {
    PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    }
}

fn proto_fence(fence: &aos_sandbox_protocol::ValidatedAssignmentFence) -> AssignmentFence {
    AssignmentFence {
        sandbox_id: fence.sandbox_id().to_vec(),
        incarnation_id: fence.incarnation_id().to_vec(),
        assignment_epoch: fence.assignment_epoch(),
        desired_generation: fence.desired_generation(),
        assignment_digest: fence.assignment_digest().to_vec(),
        ..Default::default()
    }
}

fn proto_descriptor(
    value: &aos_sandbox_core::ObjectDescriptor,
) -> aos_proto::aos::sandbox::local::v1::Descriptor {
    aos_proto::aos::sandbox::local::v1::Descriptor {
        media_type: value.media_type().as_str().to_owned(),
        sha256: value.digest().as_bytes().to_vec(),
        encoded_size: value.encoded_size(),
        ..Default::default()
    }
}

pub(super) fn logical_slot_for_request(
    journal: &Journal,
    request: &ValidatedDestinationSlotRequest,
) -> Result<DurableAttachmentSlotV1, DestinationSlotEffectError> {
    let revision = match request.action() {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => Revision::new(1),
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => Revision::new(2),
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => {
            return Err(DestinationSlotEffectError::CorruptState);
        }
    };
    let slot = get_revision_in_validated_namespace(
        journal,
        aos_sandbox_core::AttachmentSlotId::from_bytes(*request.destination_slot_id()),
        revision,
    )?
    .ok_or(DestinationSlotEffectError::CorruptState)?;
    let expected_presence = match request.action() {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => {
            AttachmentSlotPresenceV1::Available
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => AttachmentSlotPresenceV1::Released,
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => {
            return Err(DestinationSlotEffectError::CorruptState);
        }
    };
    if slot.presence() != expected_presence
        || slot.sandbox().as_bytes() != request.binding_fence().sandbox_id()
        || slot.incarnation().as_bytes() != request.binding_fence().incarnation_id()
        || slot.namespace_generation() != request.namespace_generation()
        || slot.sandbox_spec() != request.sandbox_spec()
        || slot.operation_id().as_bytes() != request.header().request_id()
    {
        return Err(DestinationSlotEffectError::CorruptState);
    }
    Ok(slot)
}
