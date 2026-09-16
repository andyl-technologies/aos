//! Shared dormant authority and effect descriptions for lifecycle orchestration.
//!
//! Phase-six state machines emit typed work descriptions. Post-effect joins
//! consume authenticated protected-session readbacks and never accept raw
//! inventory callbacks, evidence rows, or effect authority.

use std::marker::PhantomData;

use aos_proto::aos::sandbox::local::v1::{
    ApplyDestinationSlotRequest, ApplyDestinationSlotResponse, ApplyMountRequest,
    ApplyNetworkRequest, ApplyRuntimeRequest, ApplyStorageRequest, BrokerMethod,
    DestinationSlotAction, DestinationSlotLifecycle, InventoryDestinationSlotsResponse,
    InventoryMountResourcesResponse, InventoryNetworkResourcesResponse, InventoryRuntimeResponse,
    InventoryStorageResourcesResponse, MountAction, MountLifecycle, MountResult, MountState,
    NetworkAction, NetworkResult, NetworkState, RuntimeAction, RuntimeObservation, RuntimeState,
    StorageAction, StorageResult,
};
use aos_sandbox_core::{
    AssignmentEpoch, NamespaceGeneration, ObjectDigest, OperationId, Revision, SandboxId,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerMethodResultV1, AuthenticatedBrokerOutcomeDirectionV1,
    AuthenticatedBrokerRequestDirectionV1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    LifecycleAttemptStateV1, LifecycleBootInventoryV1, LifecycleEffectDirectionV1,
    LifecycleMethodV1, LifecycleOperationV1, LifecyclePhaseV1, LifecycleProtectedCoordinationV1,
    LifecycleProtectedRetentionLedgerV1, LifecycleRecordDigestV1, LifecycleResourceV1,
    LifecycleStepBodyDigestV1, LifecycleStepStateV1, LifecycleSuspendObservationV1,
    LifecycleTerminalResultV1,
};

/// Reports a malformed or stale method-specific lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LifecyclePhase6ErrorV1 {
    /// The supplied operation, identity, ordering, or commitment is invalid.
    #[error("lifecycle orchestration input is invalid")]
    InvalidInput,
    /// A transition does not directly follow the retained state.
    #[error("lifecycle orchestration transition is stale or out of order")]
    InvalidTransition,
    /// A bounded collection would exceed its protocol ceiling.
    #[error("lifecycle orchestration capacity is exceeded")]
    Capacity,
    /// Current protected state no longer matches the authority boundary.
    #[error("lifecycle protected-current authority is stale")]
    StaleAuthority,
}

/// Authenticates one terminal method disposition from canonical operation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleMethodCompletionV1 {
    method: LifecycleMethodV1,
    plan: ObjectDigest,
    disposition: LifecycleTerminalResultV1,
    result: ObjectDigest,
    inventory: ObjectDigest,
}

impl LifecycleMethodCompletionV1 {
    /// Returns the completed lifecycle method.
    #[must_use]
    pub const fn method(self) -> LifecycleMethodV1 {
        self.method
    }

    /// Returns the persisted terminal disposition.
    #[must_use]
    pub const fn disposition(self) -> LifecycleTerminalResultV1 {
        self.disposition
    }

    /// Returns the canonical persisted method-plan commitment.
    #[must_use]
    pub const fn plan(self) -> ObjectDigest {
        self.plan
    }

    /// Returns the final persisted effect-result commitment.
    #[must_use]
    pub const fn result(self) -> ObjectDigest {
        self.result
    }

    /// Returns the final persisted inventory commitment.
    #[must_use]
    pub const fn inventory(self) -> ObjectDigest {
        self.inventory
    }

    /// Commits the complete method-specific terminal witness.
    #[must_use]
    pub fn commitment(self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.method-completion.v1\0")
                .chain_update([self.method as u8, self.disposition as u8])
                .chain_update(self.plan.as_bytes())
                .chain_update(self.result.as_bytes())
                .chain_update(self.inventory.as_bytes())
                .finalize()
                .into(),
        )
    }
}

/// Identifies the exact immutable action sequence persisted by an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleMethodPlanV1 {
    method: LifecycleMethodV1,
    steps: u32,
    commitment: ObjectDigest,
}

impl LifecycleMethodPlanV1 {
    pub(super) fn from_current(
        current: &CurrentLifecycleOperationV1<'_>,
        expected_steps: usize,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if expected_steps == 0 || current.operation().steps().len() != expected_steps {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            method: current.operation().intent().method(),
            steps: u32::try_from(expected_steps).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?,
            commitment: method_plan_commitment_for_operation(current.operation()),
        })
    }

    pub(super) fn cursor_index(
        self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<Option<usize>, LifecyclePhase6ErrorV1> {
        if current.operation().intent().method() != self.method
            || current.operation().steps().len() != self.steps as usize
            || method_plan_commitment_for_operation(current.operation()) != self.commitment
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        current
            .persisted_effect_cursor()?
            .map(|cursor| {
                usize::try_from(cursor.step())
                    .ok()
                    .filter(|index| *index < self.steps as usize)
                    .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)
            })
            .transpose()
    }

    pub(super) fn matches_current(self, current: &CurrentLifecycleOperationV1<'_>) -> bool {
        current.operation().intent().method() == self.method
            && current.operation().steps().len() == self.steps as usize
            && method_plan_commitment_for_operation(current.operation()) == self.commitment
    }

    /// Returns the method whose action sequence is committed.
    #[must_use]
    pub const fn method(self) -> LifecycleMethodV1 {
        self.method
    }

    /// Returns the exact number of persisted actions.
    #[must_use]
    pub const fn steps(self) -> u32 {
        self.steps
    }

    /// Returns the canonical full-plan commitment.
    #[must_use]
    pub const fn commitment(self) -> ObjectDigest {
        self.commitment
    }
}

/// Authenticates one exact durable Residual cursor and its admitted retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleDeferredEffectCursorV1 {
    operation: OperationId,
    operation_record: LifecycleRecordDigestV1,
    method_plan: ObjectDigest,
    step: u32,
    direction: LifecycleEffectDirectionV1,
    failed_attempt: u32,
    retry_attempt: u32,
    action: u32,
    reason: ObjectDigest,
    plan: ObjectDigest,
}

impl LifecycleDeferredEffectCursorV1 {
    pub(super) fn from_current_residual(
        current: &CurrentLifecycleOperationV1<'_>,
        method_plan: LifecycleMethodPlanV1,
        action: u32,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if action == 0 || !method_plan.matches_current(current) {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let residual = current
            .operation()
            .steps()
            .iter()
            .filter(|step| step.state() == LifecycleStepStateV1::Residual)
            .collect::<Vec<_>>();
        if residual.len() != 1 {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let step = residual[0];
        let attempt = step
            .compensation_attempts()
            .last()
            .or_else(|| step.forward_attempts().last())
            .filter(|attempt| attempt.state() == LifecycleAttemptStateV1::Failed)
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        let retry = attempt
            .retry()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
        let reason = attempt
            .failure()
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?
            .detail()
            .digest();
        Ok(Self {
            operation: current.operation().operation_id(),
            operation_record: current.record(),
            method_plan: method_plan.commitment(),
            step: step.index(),
            direction: attempt.direction(),
            failed_attempt: attempt.number(),
            retry_attempt: retry.attempt(),
            action,
            reason,
            plan: step.plan().digest(),
        })
    }

    /// Returns the operation containing the durable Residual cursor.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the exact current operation-record commitment.
    #[must_use]
    pub const fn operation_record(self) -> LifecycleRecordDigestV1 {
        self.operation_record
    }

    /// Returns the full canonical method-plan commitment.
    #[must_use]
    pub const fn method_plan(self) -> ObjectDigest {
        self.method_plan
    }

    /// Returns the persisted step index.
    #[must_use]
    pub const fn step(self) -> u32 {
        self.step
    }

    /// Returns the failed effect direction.
    #[must_use]
    pub const fn direction(self) -> LifecycleEffectDirectionV1 {
        self.direction
    }

    /// Returns the failed attempt number.
    #[must_use]
    pub const fn failed_attempt(self) -> u32 {
        self.failed_attempt
    }

    /// Returns the exact admitted retry attempt number.
    #[must_use]
    pub const fn retry_attempt(self) -> u32 {
        self.retry_attempt
    }

    /// Returns the method-specific action ordinal.
    #[must_use]
    pub const fn action(self) -> u32 {
        self.action
    }

    /// Returns the durable failure reason commitment.
    #[must_use]
    pub const fn reason(self) -> ObjectDigest {
        self.reason
    }

    /// Returns the exact persisted step-plan commitment.
    #[must_use]
    pub const fn plan(self) -> ObjectDigest {
        self.plan
    }
}

/// Describes the unique active Phase 6 cursor reconstructed from protected replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecyclePersistedEffectCursorV1 {
    step: u32,
    direction: LifecycleEffectDirectionV1,
    attempt: u32,
    state: LifecycleAttemptStateV1,
    admission: ObjectDigest,
    request: super::LifecycleStepRequestDigestV1,
    body: LifecycleStepBodyDigestV1,
    plan: ObjectDigest,
}

impl LifecyclePersistedEffectCursorV1 {
    /// Returns the persisted step index.
    #[must_use]
    pub const fn step(self) -> u32 {
        self.step
    }

    /// Returns the persisted effect direction.
    #[must_use]
    pub const fn direction(self) -> LifecycleEffectDirectionV1 {
        self.direction
    }

    /// Returns the one-based persisted attempt number.
    #[must_use]
    pub const fn attempt(self) -> u32 {
        self.attempt
    }

    /// Returns the replayed attempt state, including outcome ambiguity.
    #[must_use]
    pub const fn state(self) -> LifecycleAttemptStateV1 {
        self.state
    }

    /// Returns the exact durable admission commitment.
    #[must_use]
    pub const fn admission(self) -> ObjectDigest {
        self.admission
    }

    /// Returns the exact persisted logical effect request commitment.
    #[must_use]
    pub const fn request(self) -> super::LifecycleStepRequestDigestV1 {
        self.request
    }

    /// Returns the canonical persisted effect-body commitment.
    #[must_use]
    pub const fn body(self) -> LifecycleStepBodyDigestV1 {
        self.body
    }

    /// Returns the persisted method-plan commitment.
    #[must_use]
    pub const fn plan(self) -> ObjectDigest {
        self.plan
    }
}

/// Borrows one coordination record decoded from fixed protected auxiliary state.
#[must_use = "current lifecycle coordination must remain bound to its owner"]
pub struct CurrentLifecycleCoordinationV1<'current> {
    coordination: LifecycleProtectedCoordinationV1,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

impl<'current> CurrentLifecycleCoordinationV1<'current> {
    pub(crate) const fn from_protected_current(
        coordination: LifecycleProtectedCoordinationV1,
        projection_root: ObjectDigest,
    ) -> Self {
        Self {
            coordination,
            projection_root,
            current: PhantomData,
        }
    }

    /// Borrows the verifier-owned coordination transaction.
    #[must_use]
    pub const fn coordination(&self) -> &LifecycleProtectedCoordinationV1 {
        &self.coordination
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }
}

/// Borrows one retention ledger decoded from fixed protected auxiliary state.
#[must_use = "current lifecycle retention must remain bound to its owner"]
pub struct CurrentLifecycleRetentionLedgerV1<'current> {
    retention: LifecycleProtectedRetentionLedgerV1,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

impl<'current> CurrentLifecycleRetentionLedgerV1<'current> {
    pub(crate) const fn from_protected_current(
        retention: LifecycleProtectedRetentionLedgerV1,
        projection_root: ObjectDigest,
    ) -> Self {
        Self {
            retention,
            projection_root,
            current: PhantomData,
        }
    }

    /// Borrows the verifier-owned complete retention ledger.
    #[must_use]
    pub const fn retention(&self) -> &LifecycleProtectedRetentionLedgerV1 {
        &self.retention
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }
}

/// Borrows one suspend observation decoded from fixed protected auxiliary state.
#[must_use = "current lifecycle suspension evidence must remain bound to its owner"]
pub struct CurrentLifecycleSuspendObservationV1<'current> {
    observation: LifecycleSuspendObservationV1,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

impl<'current> CurrentLifecycleSuspendObservationV1<'current> {
    pub(crate) const fn from_protected_current(
        observation: LifecycleSuspendObservationV1,
        projection_root: ObjectDigest,
    ) -> Self {
        Self {
            observation,
            projection_root,
            current: PhantomData,
        }
    }

    /// Returns the exact verifier-owned suspension observation.
    #[must_use]
    pub const fn observation(&self) -> LifecycleSuspendObservationV1 {
        self.observation
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }
}

/// Borrows one boot inventory decoded from fixed protected auxiliary state.
#[must_use = "current lifecycle boot inventory must remain bound to its owner"]
pub struct CurrentLifecycleBootInventoryV1<'current> {
    inventory: LifecycleBootInventoryV1,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

/// Borrows the authoritative current target-assignment boundary.
#[must_use = "current target assignment must remain bound to its fixed owner"]
pub struct CurrentLifecycleTargetAssignmentV1<'current> {
    sandbox: SandboxId,
    assignment_epoch: AssignmentEpoch,
    namespace_generation: NamespaceGeneration,
    state: ObjectDigest,
    operation: OperationId,
    operation_record: LifecycleRecordDigestV1,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

impl<'current> CurrentLifecycleTargetAssignmentV1<'current> {
    pub(crate) const fn from_protected_current(
        sandbox: SandboxId,
        assignment_epoch: AssignmentEpoch,
        namespace_generation: NamespaceGeneration,
        state: ObjectDigest,
        operation: OperationId,
        operation_record: LifecycleRecordDigestV1,
        projection_root: ObjectDigest,
    ) -> Self {
        Self {
            sandbox,
            assignment_epoch,
            namespace_generation,
            state,
            operation,
            operation_record,
            projection_root,
            current: PhantomData,
        }
    }

    /// Returns the sandbox whose current assignment was authenticated.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the current authoritative assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the current authoritative namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the protected state commitment used for currentness.
    #[must_use]
    pub const fn state(&self) -> ObjectDigest {
        self.state
    }

    pub(super) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(super) const fn operation_record(&self) -> LifecycleRecordDigestV1 {
        self.operation_record
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }
}

/// Borrows current host-runtime liveness from a protected boot inventory.
#[must_use = "runtime liveness must remain bound to its fixed owner"]
pub struct CurrentLifecycleRuntimeLivenessV1<'current> {
    fence: super::LiveRuntimeFenceV1,
    host_boot: [u8; 16],
    inventory: ObjectDigest,
    operation: OperationId,
    operation_record: LifecycleRecordDigestV1,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

impl<'current> CurrentLifecycleRuntimeLivenessV1<'current> {
    pub(crate) const fn from_protected_current(
        fence: super::LiveRuntimeFenceV1,
        host_boot: [u8; 16],
        inventory: ObjectDigest,
        operation: OperationId,
        operation_record: LifecycleRecordDigestV1,
        projection_root: ObjectDigest,
    ) -> Self {
        Self {
            fence,
            host_boot,
            inventory,
            operation,
            operation_record,
            projection_root,
            current: PhantomData,
        }
    }

    /// Returns the exact still-live runtime fence.
    #[must_use]
    pub const fn fence(&self) -> super::LiveRuntimeFenceV1 {
        self.fence
    }

    /// Returns the protected host-boot generation commitment.
    #[must_use]
    pub const fn host_boot(&self) -> [u8; 16] {
        self.host_boot
    }

    /// Returns the complete protected runtime inventory commitment.
    #[must_use]
    pub const fn inventory(&self) -> ObjectDigest {
        self.inventory
    }

    pub(super) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(super) const fn operation_record(&self) -> LifecycleRecordDigestV1 {
        self.operation_record
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }
}

impl<'current> CurrentLifecycleBootInventoryV1<'current> {
    pub(crate) const fn from_protected_current(
        inventory: LifecycleBootInventoryV1,
        projection_root: ObjectDigest,
    ) -> Self {
        Self {
            inventory,
            projection_root,
            current: PhantomData,
        }
    }

    /// Borrows the exact verifier-owned six-domain boot inventory.
    #[must_use]
    pub const fn inventory(&self) -> &LifecycleBootInventoryV1 {
        &self.inventory
    }

    pub(super) const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }
}

/// Borrows one exact operation recovered from the fixed protected journal.
#[must_use = "current lifecycle authority must be consumed before its owner borrow ends"]
pub struct CurrentLifecycleOperationV1<'current> {
    operation: LifecycleOperationV1,
    record: LifecycleRecordDigestV1,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

impl<'current> CurrentLifecycleOperationV1<'current> {
    pub(crate) fn from_protected_current(
        operation: LifecycleOperationV1,
        record: LifecycleRecordDigestV1,
        projection_root: ObjectDigest,
    ) -> Self {
        Self {
            operation,
            record,
            projection_root,
            current: PhantomData,
        }
    }

    /// Borrows the fully decoded current operation.
    #[must_use]
    pub const fn operation(&self) -> &LifecycleOperationV1 {
        &self.operation
    }

    /// Returns the exact canonical operation-record commitment.
    #[must_use]
    pub const fn record(&self) -> LifecycleRecordDigestV1 {
        self.record
    }

    /// Returns the complete fixed-journal lifecycle projection root.
    #[must_use]
    pub const fn projection_root(&self) -> ObjectDigest {
        self.projection_root
    }

    pub(super) fn require_method(
        &self,
        methods: &[LifecycleMethodV1],
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        methods
            .contains(&self.operation.intent().method())
            .then_some(())
            .ok_or(LifecyclePhase6ErrorV1::InvalidInput)
    }

    /// Reissues the unique exact reserved Phase 6 attempt from protected state.
    ///
    /// Repeated calls for the same `Reserved` attempt return the same admission
    /// and dispatch commitment. An `Ambiguous` attempt fails closed until its
    /// durable operation record is resolved.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the current operation contains
    /// exactly one matching persisted plan/body and reserved attempt.
    pub fn recover_reserved_effect(
        &self,
        domain: LifecycleEffectDomainV1,
        ordinal: u32,
        target: [u8; 16],
        prerequisite: ObjectDigest,
        plan: ObjectDigest,
    ) -> Result<CurrentLifecycleEffectV1<'current>, LifecyclePhase6ErrorV1> {
        LifecycleEffectRequestV1::new(self, domain, ordinal, target, prerequisite, plan).map(
            |request| CurrentLifecycleEffectV1 {
                request,
                operation_record: self.record,
                projection_root: self.projection_root,
                current: PhantomData,
            },
        )
    }

    /// Reconstructs the unique active persisted cursor, including ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] if multiple steps claim concurrent
    /// effect authority or the operation's active attempt shape is incomplete.
    pub fn persisted_effect_cursor(
        &self,
    ) -> Result<Option<LifecyclePersistedEffectCursorV1>, LifecyclePhase6ErrorV1> {
        persisted_effect_cursor_for_operation(&self.operation)
    }

    /// Reconstructs the method-specific terminal witness from protected state.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] if persisted active-attempt state is
    /// ambiguous. Absence means the operation is not durably complete.
    pub fn persisted_completion(
        &self,
    ) -> Result<Option<LifecycleMethodCompletionV1>, LifecyclePhase6ErrorV1> {
        if self.persisted_effect_cursor()?.is_some() {
            return Ok(None);
        }
        Ok(persisted_completion_for_operation(&self.operation))
    }

    pub(super) fn require_persisted_completion(
        &self,
        methods: &[LifecycleMethodV1],
    ) -> Result<LifecycleMethodCompletionV1, LifecyclePhase6ErrorV1> {
        self.require_method(methods)?;
        self.persisted_completion()?
            .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)
    }
}

pub(super) fn persisted_completion_for_operation(
    operation: &LifecycleOperationV1,
) -> Option<LifecycleMethodCompletionV1> {
    if operation.phase() != LifecyclePhaseV1::Terminal
        || operation.finished_at().is_none()
        || !matches!(persisted_effect_cursor_for_operation(operation), Ok(None))
    {
        return None;
    }
    let disposition = operation.terminal_result()?;
    let (result, inventory) = match disposition {
        LifecycleTerminalResultV1::Succeeded => {
            if !operation
                .steps()
                .iter()
                .all(|step| step.state() == LifecycleStepStateV1::Applied)
            {
                return None;
            }
            let final_step = operation.steps().last()?;
            (
                final_step.result()?.digest(),
                final_step.inventory()?.digest(),
            )
        }
        LifecycleTerminalResultV1::FailedBeforeCommit
        | LifecycleTerminalResultV1::CanceledBeforeCommit => {
            if !operation.steps().iter().all(|step| {
                matches!(
                    step.state(),
                    LifecycleStepStateV1::Planned | LifecycleStepStateV1::Compensated
                )
            }) {
                return None;
            }
            let final_step = operation
                .steps()
                .iter()
                .find(|step| step.state() == LifecycleStepStateV1::Compensated)?;
            (
                final_step.compensation_result()?.digest(),
                final_step.inventory()?.digest(),
            )
        }
        LifecycleTerminalResultV1::BlockedBeforeCommit
        | LifecycleTerminalResultV1::BlockedAfterCommit => return None,
    };
    Some(LifecycleMethodCompletionV1 {
        method: operation.intent().method(),
        plan: method_plan_commitment_for_operation(operation),
        disposition,
        result,
        inventory,
    })
}

pub(super) fn method_plan_commitment_for_operation(
    operation: &LifecycleOperationV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.method-plan.v1\0")
        .chain_update([operation.intent().method() as u8])
        .chain_update((operation.steps().len() as u64).to_be_bytes());
    for step in operation.steps() {
        hasher = hasher
            .chain_update(step.index().to_be_bytes())
            .chain_update([step.class() as u8, step.domain() as u8])
            .chain_update(step.request().digest().as_bytes())
            .chain_update(step.request_body().digest().as_bytes())
            .chain_update(step.plan().digest().as_bytes())
            .chain_update(
                step.compensation_request()
                    .map_or([0; 32], |value| *value.digest().as_bytes()),
            )
            .chain_update(
                step.compensation_body()
                    .map_or([0; 32], |value| *value.digest().as_bytes()),
            )
            .chain_update(
                step.compensation_plan()
                    .map_or([0; 32], |value| *value.digest().as_bytes()),
            );
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

pub(super) fn persisted_effect_cursor_for_operation(
    operation: &LifecycleOperationV1,
) -> Result<Option<LifecyclePersistedEffectCursorV1>, LifecyclePhase6ErrorV1> {
    let mut active = operation.steps().iter().filter_map(active_step_attempt);
    let Some((step, direction, attempt, request, body, plan)) = active.next() else {
        return Ok(None);
    };
    if active.next().is_some() {
        return Err(LifecyclePhase6ErrorV1::InvalidTransition);
    }
    Ok(Some(LifecyclePersistedEffectCursorV1 {
        step,
        direction,
        attempt: attempt.number(),
        state: attempt.state(),
        admission: attempt.admission().digest(),
        request,
        body,
        plan: plan.digest(),
    }))
}

/// Selects the lower protected domain that must observe one inert effect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleEffectDomainV1 {
    /// Targets the runtime or payload cgroup owner.
    Runtime = 1,
    /// Targets mount and attachment custody.
    Mount = 2,
    /// Targets dataset, snapshot, hold, or clone custody.
    Storage = 3,
    /// Targets network namespace and endpoint custody.
    Network = 4,
    /// Targets cache pin and publication custody.
    Cache = 5,
    /// Targets resumable immutable transfer custody.
    Transfer = 6,
    /// Targets the protected controller transaction itself.
    Controller = 7,
}

/// Carries one non-executable, exact lower-domain effect handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleEffectRequestV1 {
    operation: OperationId,
    operation_revision: Revision,
    domain: LifecycleEffectDomainV1,
    ordinal: u32,
    step: u32,
    direction: LifecycleEffectDirectionV1,
    attempt: u32,
    admission: ObjectDigest,
    logical: super::LifecycleStepRequestDigestV1,
    target: [u8; 16],
    prerequisite: ObjectDigest,
    plan: ObjectDigest,
    payload: ObjectDigest,
}

/// Borrows one exact persisted and currently revalidated lower-domain handoff.
#[must_use = "a current lifecycle effect must be consumed at a protected effect boundary"]
pub struct CurrentLifecycleEffectV1<'current> {
    request: LifecycleEffectRequestV1,
    operation_record: super::LifecycleRecordDigestV1,
    projection_root: ObjectDigest,
    current: PhantomData<&'current ()>,
}

impl CurrentLifecycleEffectV1<'_> {
    pub(crate) const fn request(&self) -> LifecycleEffectRequestV1 {
        self.request
    }

    /// Returns the protected operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.request.operation()
    }

    /// Returns the exact operation revision used to derive the handoff.
    #[must_use]
    pub const fn operation_revision(&self) -> Revision {
        self.request.operation_revision()
    }

    /// Returns the lower protected domain.
    #[must_use]
    pub const fn domain(&self) -> LifecycleEffectDomainV1 {
        self.request.domain()
    }

    /// Returns the method-specific stable action ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.request.ordinal()
    }

    /// Returns the exact persisted step index.
    #[must_use]
    pub const fn step(&self) -> u32 {
        self.request.step()
    }

    /// Returns the persisted attempt direction.
    #[must_use]
    pub const fn direction(&self) -> LifecycleEffectDirectionV1 {
        self.request.direction()
    }

    /// Returns the one-based persisted attempt number.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.request.attempt()
    }

    /// Returns the durable attempt admission commitment.
    #[must_use]
    pub const fn admission(&self) -> ObjectDigest {
        self.request.admission()
    }

    /// Returns the exact persisted logical effect request commitment.
    #[must_use]
    pub const fn logical_request(&self) -> super::LifecycleStepRequestDigestV1 {
        self.request.logical_request()
    }

    /// Returns the exact target identity bytes.
    #[must_use]
    pub const fn target(&self) -> [u8; 16] {
        self.request.target()
    }

    /// Returns the state commitment that must still be current at dispatch.
    #[must_use]
    pub const fn prerequisite(&self) -> ObjectDigest {
        self.request.prerequisite()
    }

    /// Returns the exact persisted method plan commitment.
    #[must_use]
    pub const fn plan(&self) -> ObjectDigest {
        self.request.plan()
    }

    /// Returns the canonical typed lower-domain payload.
    #[must_use]
    pub fn canonical_body(&self) -> [u8; 122] {
        self.request.canonical_body()
    }

    /// Returns the attempt-bound dispatch commitment.
    #[must_use]
    pub const fn payload(&self) -> ObjectDigest {
        self.request.payload()
    }

    /// Validates an authenticated lower-domain request without minting evidence.
    ///
    /// This pure admission check is intended for the protected broker-session
    /// owner before it reserves or sends the request. Success grants no effect
    /// or observation authority.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the method and entire
    /// canonical method body equal the authoritative lifecycle compilation.
    pub fn validate_authenticated_broker_request(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        self.authenticated_broker_effect(request).map(drop)
    }

    /// Binds this handoff to the exact authenticated request sent to its owner.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the signed request has the
    /// matching domain method and exact lifecycle dispatch body.
    pub(crate) fn bind_authenticated_broker_request(
        self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<LifecycleAuthenticatedBrokerEffectV1, LifecyclePhase6ErrorV1> {
        self.authenticated_broker_effect(request)
    }

    pub(super) fn authenticated_broker_effect(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<LifecycleAuthenticatedBrokerEffectV1, LifecyclePhase6ErrorV1> {
        let compiled = LifecycleBrokerRequestCompilerV1::compile(self.request, request)?;
        let domain = compiled.domain();
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || request.session_binding() == [0; 32]
            || request.signed_request_digest() == [0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(LifecycleAuthenticatedBrokerEffectV1 {
            request: self.request,
            domain,
            broker_method: request.method(),
            compiled,
            signed_request: ObjectDigest::from_bytes(request.signed_request_digest()),
            request_semantic: ObjectDigest::from_bytes(request.semantic_commitment()),
            lifecycle_body: self.canonical_body(),
            request_body: ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into()),
            session_binding: ObjectDigest::from_bytes(request.session_binding()),
        })
    }

    /// Verifies a Storage, Mount, or Network result through its fixed endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the lifecycle challenge is
    /// current for this exact handoff and the fixed endpoint authenticates the
    /// exact request/result/immediate-inventory exchange.
    #[cfg(target_os = "linux")]
    pub fn observe_fixed_broker_effect(
        self,
        challenge: &super::LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: super::LifecycleBootBootstrapEndpointV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
        signature: [u8; 64],
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        if !matches!(
            endpoint,
            super::LifecycleBootBootstrapEndpointV1::Storage
                | super::LifecycleBootBootstrapEndpointV1::Mount
                | super::LifecycleBootBootstrapEndpointV1::Network
        ) || challenge.operation() != self.operation()
            || challenge.operation_record() != self.operation_record
            || challenge.projection_root() != self.projection_root
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let message =
            challenge.broker_effect_signing_message(endpoint, &self, outcome, inventory)?;
        super::boot_reconcile::verify_fixed_bootstrap_signature(endpoint, &message, signature)?;
        let authenticated = self.bind_authenticated_broker_request(outcome.request())?;
        if endpoint == super::LifecycleBootBootstrapEndpointV1::Storage {
            let readback =
                super::LifecycleAuthenticatedStorageReadbackV1::from_fixed_endpoint_attestation(
                    challenge,
                    &authenticated,
                    outcome,
                    inventory,
                    signature,
                )?;
            authenticated.observe_complete_storage(outcome, readback)
        } else {
            authenticated.observe(outcome, inventory)
        }
    }

    /// Joins a protected atomic Storage group to its complete successor inventory.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless this is the exact persisted
    /// Storage effect compiled into `plan` and Storage's adjacent authenticated
    /// inventory proves every member's committed group transition.
    pub fn observe_atomic_dataset_snapshot(
        self,
        plan: &super::LifecycleAtomicDatasetSnapshotPlanV1,
        successor: super::LifecycleAuthenticatedAtomicStorageSuccessorV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        if self.domain() != LifecycleEffectDomainV1::Storage
            || self.request != plan.lifecycle_effect()
            || self.operation() != plan.operation()
            || self.payload() != plan.effect_commitment()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let inventory = successor.current();
        LifecycleEffectObservationV1::from_authenticated_readback(
            self.request,
            successor.observation(),
            inventory.commitment(),
            inventory.generation(),
            inventory.source(),
            successor.program(),
        )
    }

    /// Joins an exact Cache pin release to its current fixed-owner readback.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the result and post-effect
    /// projection identify the exact same nonzero Cache owner generation.
    #[cfg(target_os = "linux")]
    pub fn observe_cache_pin_release(
        self,
        result: crate::cache_residency::CacheEffectObservationV1,
        owner: &crate::cache_residency::DormantCacheOwnerV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        let current = result.currentness();
        if self.domain() != LifecycleEffectDomainV1::Cache
            || result.effect()
                != crate::cache_residency::cache_owner_effect_commitment_v1(
                    b"unpin",
                    &self.target(),
                    current,
                )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        self.observe_cache_owner_result(result, owner)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn observe_cache_availability(
        self,
        result: crate::cache_residency::CacheEffectObservationV1,
        owner: &crate::cache_residency::DormantCacheOwnerV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        if self.domain() != LifecycleEffectDomainV1::Cache {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        self.observe_cache_owner_result(result, owner)
    }

    #[cfg(target_os = "linux")]
    fn observe_cache_owner_result(
        self,
        result: crate::cache_residency::CacheEffectObservationV1,
        owner: &crate::cache_residency::DormantCacheOwnerV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        let current = result.currentness();
        owner
            .validate_current(current)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let inventory = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.cache-effect-readback.v1\0")
                .chain_update(current.generation().to_be_bytes())
                .chain_update(current.digest().as_bytes())
                .finalize()
                .into(),
        );
        LifecycleEffectObservationV1::from_authenticated_readback(
            self.request,
            result.effect(),
            inventory,
            current.generation(),
            current.digest(),
            current.digest(),
        )
    }

    /// Joins a current protected transfer result to the complete transfer set.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless both values were issued by
    /// the Transfer owner for this exact lifecycle request and generation.
    pub fn observe_transfer_effect(
        self,
        owner: &mut crate::multi_node::ProtectedMultiNodeAuthorityOwnerV1,
        result: &crate::multi_node::ProtectedMultiNodeCurrentRecordV1,
        inventory: &super::LifecycleAuthenticatedTransferInventoryV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        let record = result.record().record();
        let state = record
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
        let identity = state.manifest().identity();
        let inventory_entry = inventory.entries().iter().find(|entry| {
            entry.resource()
                == LifecycleResourceV1::Other(aos_sandbox_core::ResourceId::from_bytes(
                    *record.operation().as_bytes(),
                ))
        });
        if self.domain() != LifecycleEffectDomainV1::Transfer
            || record.domain() != crate::multi_node::MultiNodeJournalDomainV1::SnapshotTransfer
            || record.operation() != self.operation()
            || self.target() != *record.operation().as_bytes()
            || identity.operation() != self.operation()
            || record.effect_state() != crate::multi_node::JournalEffectStateV1::Committed
            || inventory_entry.is_none_or(|entry| entry.identity() != record.digest())
            || inventory.generation() == 0
            || inventory.source().as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        owner
            .recheck_lifecycle_transfer_record(result)
            .and_then(|()| owner.recheck_lifecycle_transfer_inventory(inventory))
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let transition = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.transfer-transition-readback.v1\0")
                .chain_update(self.canonical_body())
                .chain_update(record.sequence().to_be_bytes())
                .chain_update(record.predecessor_digest().as_bytes())
                .chain_update(record.payload_digest().as_bytes())
                .chain_update([record.effect_state() as u8])
                .chain_update(record.effect_digest().as_bytes())
                .chain_update(record.digest().as_bytes())
                .finalize()
                .into(),
        );
        LifecycleEffectObservationV1::from_authenticated_readback(
            self.request,
            transition,
            inventory.commitment(),
            inventory.generation(),
            inventory.source(),
            inventory.source(),
        )
    }

    /// Joins an exact lifecycle-journal commit to a Controller-owned effect.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the effect is Controller-owned
    /// and the commit exposes nonzero durable transaction and projection state.
    pub fn observe_lifecycle_commit(
        self,
        applied: &super::AppliedLifecycleJournalTransactionV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        let snapshot = applied.snapshot();
        if self.domain() != LifecycleEffectDomainV1::Controller
            || snapshot.journal_sequence() == 0
            || applied.transaction_digest().as_bytes() == &[0; 32]
            || snapshot.projection_root().as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        LifecycleEffectObservationV1::from_authenticated_readback(
            self.request,
            applied.transaction_digest(),
            snapshot.projection_root(),
            snapshot.journal_sequence(),
            snapshot.projection_root(),
            applied.transaction_digest(),
        )
    }

    pub(crate) fn observe_controller_readback(
        self,
        result: ObjectDigest,
        inventory: ObjectDigest,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        if self.domain() != LifecycleEffectDomainV1::Controller {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        LifecycleEffectObservationV1::from_authenticated_readback(
            self.request,
            result,
            inventory,
            u64::from(self.operation_revision().get()),
            inventory,
            self.admission(),
        )
    }
}

/// Retains an exact signed effect request until its owner supplies readback.
#[derive(Clone, Debug, PartialEq)]
pub struct LifecycleAuthenticatedBrokerEffectV1 {
    request: LifecycleEffectRequestV1,
    domain: LifecycleEffectDomainV1,
    broker_method: BrokerMethod,
    compiled: LifecycleCompiledBrokerRequestV1,
    signed_request: ObjectDigest,
    request_semantic: ObjectDigest,
    lifecycle_body: [u8; 122],
    request_body: ObjectDigest,
    session_binding: ObjectDigest,
}

impl LifecycleAuthenticatedBrokerEffectV1 {
    pub(super) const fn lifecycle_request(&self) -> LifecycleEffectRequestV1 {
        self.request
    }

    pub(super) fn require_broker_readback_handoff(
        &self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let outcome_request = outcome.request();
        let inventory_request = inventory.request();
        let expected_client_sequence = outcome_request
            .client_sequence()
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_broker_sequence = outcome
            .broker_sequence()
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || inventory.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || outcome.method() != self.broker_method
            || broker_inventory_domain(inventory.method()) != Some(self.domain)
            || ObjectDigest::from_bytes(outcome_request.signed_request_digest())
                != self.signed_request
            || ObjectDigest::from_bytes(outcome_request.semantic_commitment())
                != self.request_semantic
            || ObjectDigest::from_bytes(Sha256::digest(outcome_request.exact_body()).into())
                != self.request_body
            || self.lifecycle_body != self.request.canonical_body()
            || &LifecycleBrokerRequestCompilerV1::compile(self.request, outcome_request)?
                != &self.compiled
            || ObjectDigest::from_bytes(outcome_request.session_binding()) != self.session_binding
            || ObjectDigest::from_bytes(inventory_request.session_binding()) != self.session_binding
            || inventory_request.client_sequence() != expected_client_sequence
            || inventory.broker_sequence() != expected_broker_sequence
            || !matches!(
                outcome.result(),
                AuthenticatedBrokerMethodResultV1::Success { .. }
            )
            || !matches!(
                inventory.result(),
                AuthenticatedBrokerMethodResultV1::Success { .. }
            )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        require_exact_post_effect_readback(self, outcome, inventory)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn require_storage_readback_handoff(
        &self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let request = outcome.request();
        let inventory_request = inventory.request();
        let expected_client_sequence = request
            .client_sequence()
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_broker_sequence = outcome
            .broker_sequence()
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if self.domain != LifecycleEffectDomainV1::Storage
            || self.broker_method != BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || outcome.method() != self.broker_method
            || inventory.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || inventory.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || ObjectDigest::from_bytes(request.signed_request_digest()) != self.signed_request
            || ObjectDigest::from_bytes(request.semantic_commitment()) != self.request_semantic
            || ObjectDigest::from_bytes(request.session_binding()) != self.session_binding
            || ObjectDigest::from_bytes(inventory_request.session_binding()) != self.session_binding
            || inventory_request.client_sequence() != expected_client_sequence
            || inventory.broker_sequence() != expected_broker_sequence
            || self.lifecycle_body != self.request.canonical_body()
            || &LifecycleBrokerRequestCompilerV1::compile(self.request, request)? != &self.compiled
            || !matches!(
                outcome.result(),
                AuthenticatedBrokerMethodResultV1::Success { .. }
            )
            || !matches!(
                inventory.result(),
                AuthenticatedBrokerMethodResultV1::Success { .. }
            )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(())
    }

    /// Joins the signed effect result to a later complete signed inventory.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless both outcomes are successful,
    /// authenticated by the same session, and the inventory is the matching
    /// domain's immediate successor readback generation.
    pub(crate) fn observe(
        self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        self.require_broker_readback_handoff(outcome, inventory)?;
        let result = ObjectDigest::from_bytes(outcome.semantic_commitment());
        let inventory_source =
            ObjectDigest::from_bytes(Sha256::digest(inventory.canonical_packet()).into());
        let inventory_digest = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.authenticated-inventory-readback.v1\0")
                .chain_update(self.session_binding.as_bytes())
                .chain_update(inventory.broker_sequence().to_be_bytes())
                .chain_update(inventory.semantic_commitment())
                .chain_update(inventory.canonical_packet())
                .finalize()
                .into(),
        );
        LifecycleEffectObservationV1::from_authenticated_readback(
            self.request,
            result,
            inventory_digest,
            inventory.broker_sequence(),
            inventory_source,
            self.session_binding,
        )
    }

    /// Joins a signed Storage result to a later signed complete Storage projection.
    ///
    /// This path is required for snapshot, clone, hold, and quota effects,
    /// because the broker's launch-only workspace inventory cannot establish
    /// those object families or their authenticated absence.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the signed request is the
    /// exact retained lifecycle binding and the immediate successor request in
    /// the same authenticated session proves the action-specific resulting
    /// object or absence.
    #[cfg(target_os = "linux")]
    pub fn observe_complete_storage(
        self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        readback: super::LifecycleAuthenticatedStorageReadbackV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        let request = outcome.request();
        if self.domain != LifecycleEffectDomainV1::Storage
            || self.broker_method != BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || outcome.method() != self.broker_method
            || ObjectDigest::from_bytes(request.signed_request_digest()) != self.signed_request
            || ObjectDigest::from_bytes(request.semantic_commitment()) != self.request_semantic
            || ObjectDigest::from_bytes(request.session_binding()) != self.session_binding
            || self.lifecycle_body != self.request.canonical_body()
            || &LifecycleBrokerRequestCompilerV1::compile(self.request, request)? != &self.compiled
            || readback.effect_request != self.signed_request
            || readback.effect_result != ObjectDigest::from_bytes(outcome.semantic_commitment())
            || readback.session != self.session_binding
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let LifecycleCompiledBrokerRequestV1::Storage(apply) = &self.compiled else {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        };
        let result = decode_canonical_success_body::<StorageResult>(successful_body(outcome)?)?;
        let inventory = readback.inventory();
        let expected_client_sequence = outcome
            .request()
            .client_sequence()
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        let expected_broker_sequence = outcome
            .broker_sequence()
            .checked_add(1)
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if inventory.client_generation() != expected_client_sequence
            || inventory.broker_generation() != expected_broker_sequence
            || inventory.session() != ObjectDigest::from_bytes(outcome.request().session_binding())
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        // The complete five-family body is an exact provider-signed successor
        // inventory. Callers cannot mint its session signature or substitute a
        // detached row vector for the post-effect readback.
        let action = apply
            .action
            .as_known()
            .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
        let (kind, transition_kind, handle, expected_present) = match action {
            StorageAction::STORAGE_ACTION_CREATE_WORKSPACE => (
                super::LifecycleStorageInventoryKindV1::Dataset,
                super::LifecycleStorageTransitionKindV1::CreateWorkspace,
                result.storage_handle.as_slice(),
                true,
            ),
            StorageAction::STORAGE_ACTION_SNAPSHOT => (
                super::LifecycleStorageInventoryKindV1::Snapshot,
                super::LifecycleStorageTransitionKindV1::Snapshot,
                result.immutable_version_handle.as_slice(),
                true,
            ),
            StorageAction::STORAGE_ACTION_HOLD_SNAPSHOT => (
                super::LifecycleStorageInventoryKindV1::Hold,
                super::LifecycleStorageTransitionKindV1::HoldSnapshot,
                apply.source_version_handle.as_slice(),
                true,
            ),
            StorageAction::STORAGE_ACTION_RELEASE_HOLD => (
                super::LifecycleStorageInventoryKindV1::Hold,
                super::LifecycleStorageTransitionKindV1::ReleaseHold,
                apply.source_version_handle.as_slice(),
                false,
            ),
            StorageAction::STORAGE_ACTION_CLONE => (
                super::LifecycleStorageInventoryKindV1::Clone,
                super::LifecycleStorageTransitionKindV1::Clone,
                result.storage_handle.as_slice(),
                true,
            ),
            StorageAction::STORAGE_ACTION_SET_QUOTA => (
                super::LifecycleStorageInventoryKindV1::Quota,
                super::LifecycleStorageTransitionKindV1::SetQuota,
                result.storage_handle.as_slice(),
                true,
            ),
            StorageAction::STORAGE_ACTION_DESTROY if apply.source_version_handle.is_empty() => (
                super::LifecycleStorageInventoryKindV1::Dataset,
                super::LifecycleStorageTransitionKindV1::DestroyDataset,
                apply.storage_handle.as_slice(),
                false,
            ),
            StorageAction::STORAGE_ACTION_DESTROY => (
                super::LifecycleStorageInventoryKindV1::Snapshot,
                super::LifecycleStorageTransitionKindV1::DestroySnapshot,
                apply.source_version_handle.as_slice(),
                false,
            ),
            StorageAction::STORAGE_ACTION_UNSPECIFIED => {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        };
        let identity = ObjectDigest::from_bytes(
            handle
                .try_into()
                .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?,
        );
        let matching = inventory
            .entries()
            .iter()
            .filter(|entry| entry.kind() == kind && entry.effect_subject() == identity)
            .collect::<Vec<_>>();
        let storage_request = ObjectDigest::from_bytes(Sha256::digest(request.exact_body()).into());
        let transitions = inventory
            .transitions()
            .iter()
            .filter(|transition| {
                transition.kind() == transition_kind
                    && transition.effect_subject() == identity
                    && transition.effect_request() == storage_request
            })
            .collect::<Vec<_>>();
        let exact_transition = transitions.len() == 1;
        let transition_hold = transitions
            .first()
            .and_then(|transition| transition.hold_id());
        let exact_present_rows = matching
            .iter()
            .filter(|entry| {
                entry.effect_request() == storage_request
                    && (action != StorageAction::STORAGE_ACTION_HOLD_SNAPSHOT
                        || entry.hold_id() == transition_hold)
            })
            .count();
        let exact_present = exact_present_rows == 1 && exact_transition;
        let exact_absence = if action == StorageAction::STORAGE_ACTION_RELEASE_HOLD {
            let Some(hold_id) = transition_hold else {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            };
            matching
                .iter()
                .all(|entry| entry.hold_id() != Some(hold_id))
        } else {
            matching.is_empty()
        };
        if identity.as_bytes() == &[0; 32]
            || (expected_present && !exact_present)
            || (!expected_present && (!exact_transition || !exact_absence))
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        LifecycleEffectObservationV1::from_authenticated_readback(
            self.request,
            ObjectDigest::from_bytes(outcome.semantic_commitment()),
            inventory.commitment(),
            inventory.generation(),
            inventory.source(),
            inventory.session(),
        )
    }
}

/// Carries exact protected readback for one inert lower-domain handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleEffectObservationV1 {
    request: LifecycleEffectRequestV1,
    result: ObjectDigest,
    inventory: ObjectDigest,
    inventory_generation: u64,
    inventory_source: ObjectDigest,
    inventory_session: ObjectDigest,
}

impl LifecycleEffectObservationV1 {
    fn from_authenticated_readback(
        request: LifecycleEffectRequestV1,
        result: ObjectDigest,
        inventory: ObjectDigest,
        inventory_generation: u64,
        inventory_source: ObjectDigest,
        inventory_session: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if result.as_bytes() == &[0; 32]
            || inventory.as_bytes() == &[0; 32]
            || inventory_generation == 0
            || inventory_source.as_bytes() == &[0; 32]
            || inventory_session.as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(Self {
            request,
            result,
            inventory,
            inventory_generation,
            inventory_source,
            inventory_session,
        })
    }

    pub(super) const fn request(self) -> LifecycleEffectRequestV1 {
        self.request
    }

    /// Returns the exact protected result commitment.
    #[must_use]
    pub const fn result(self) -> ObjectDigest {
        self.result
    }

    /// Returns the exact protected post-effect inventory commitment.
    #[must_use]
    pub const fn inventory(self) -> ObjectDigest {
        self.inventory
    }

    pub(super) const fn inventory_generation(self) -> u64 {
        self.inventory_generation
    }

    pub(super) const fn inventory_source(self) -> ObjectDigest {
        self.inventory_source
    }

    pub(super) const fn inventory_session(self) -> ObjectDigest {
        self.inventory_session
    }
}

#[derive(Clone, Debug, PartialEq)]
enum LifecycleCompiledBrokerRequestV1 {
    Runtime(ApplyRuntimeRequest),
    Mount(ApplyMountRequest),
    DestinationSlot(ApplyDestinationSlotRequest),
    Storage(ApplyStorageRequest),
    Network(ApplyNetworkRequest),
}

impl LifecycleCompiledBrokerRequestV1 {
    const fn domain(&self) -> LifecycleEffectDomainV1 {
        match self {
            Self::Runtime(_) => LifecycleEffectDomainV1::Runtime,
            Self::Mount(_) | Self::DestinationSlot(_) => LifecycleEffectDomainV1::Mount,
            Self::Storage(_) => LifecycleEffectDomainV1::Storage,
            Self::Network(_) => LifecycleEffectDomainV1::Network,
        }
    }
}

/// Owns the sole lifecycle-to-broker request conversion.
///
/// Every retained and replayed authenticated request is decoded through this
/// conversion. The resulting typed value binds the complete method body to the
/// persisted operation, ordinal, cursor, admission, prerequisite, and plan;
/// consumers never independently reinterpret a target or action.
struct LifecycleBrokerRequestCompilerV1;

impl LifecycleBrokerRequestCompilerV1 {
    fn compile(
        effect: LifecycleEffectRequestV1,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<LifecycleCompiledBrokerRequestV1, LifecyclePhase6ErrorV1> {
        if super::LifecycleStepRequestDigestV1::commit(request.exact_body())
            != effect.logical_request()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let target = effect.target();
        let compiled = match request.method() {
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
                let body = decode_canonical_broker_body::<ApplyRuntimeRequest>(request)?;
                if body.action.as_known() == Some(RuntimeAction::RUNTIME_ACTION_UNSPECIFIED)
                    || body.action.as_known().is_none()
                    || !body
                        .fence
                        .as_option()
                        .is_some_and(|fence| fence.sandbox_id.as_slice() == target.as_slice())
                {
                    return Err(LifecyclePhase6ErrorV1::InvalidInput);
                }
                LifecycleCompiledBrokerRequestV1::Runtime(body)
            }
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY => {
                let body = decode_canonical_broker_body::<ApplyMountRequest>(request)?;
                if body.action.as_known() == Some(MountAction::MOUNT_ACTION_UNSPECIFIED)
                    || body.action.as_known().is_none()
                    || body.attachment_id.as_slice() != target.as_slice()
                {
                    return Err(LifecyclePhase6ErrorV1::InvalidInput);
                }
                LifecycleCompiledBrokerRequestV1::Mount(body)
            }
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT => {
                let body = decode_canonical_broker_body::<ApplyDestinationSlotRequest>(request)?;
                if body.action.as_known()
                    == Some(DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED)
                    || body.action.as_known().is_none()
                    || body.destination_slot_id.as_slice() != target.as_slice()
                {
                    return Err(LifecyclePhase6ErrorV1::InvalidInput);
                }
                LifecycleCompiledBrokerRequestV1::DestinationSlot(body)
            }
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
                let body = decode_canonical_broker_body::<ApplyStorageRequest>(request)?;
                if body.action.as_known() == Some(StorageAction::STORAGE_ACTION_UNSPECIFIED)
                    || body.action.as_known().is_none()
                    || body.operation_id.as_slice() != effect.operation().as_bytes()
                    || !body
                        .fence
                        .as_option()
                        .is_some_and(|fence| fence.sandbox_id.as_slice() == target.as_slice())
                {
                    return Err(LifecyclePhase6ErrorV1::InvalidInput);
                }
                LifecycleCompiledBrokerRequestV1::Storage(body)
            }
            BrokerMethod::BROKER_METHOD_NETWORK_APPLY => {
                let body = decode_canonical_broker_body::<ApplyNetworkRequest>(request)?;
                if body.action.as_known() == Some(NetworkAction::NETWORK_ACTION_UNSPECIFIED)
                    || body.action.as_known().is_none()
                    || !(body
                        .fence
                        .as_option()
                        .is_some_and(|fence| fence.sandbox_id.as_slice() == target.as_slice())
                        || body
                            .endpoint_ids
                            .iter()
                            .any(|endpoint| endpoint.as_slice() == target.as_slice()))
                {
                    return Err(LifecyclePhase6ErrorV1::InvalidInput);
                }
                LifecycleCompiledBrokerRequestV1::Network(body)
            }
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        if compiled.domain() != effect.domain()
            || effect.ordinal() == 0
            || effect.step() == u32::MAX
            || effect.attempt() == 0
            || effect.admission().as_bytes() == &[0; 32]
            || effect.logical_request().digest().as_bytes() == &[0; 32]
            || effect.prerequisite().as_bytes() == &[0; 32]
            || effect.plan().as_bytes() == &[0; 32]
            || effect.payload().as_bytes() == &[0; 32]
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        Ok(compiled)
    }
}

fn decode_canonical_broker_body<M>(
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<M, LifecyclePhase6ErrorV1>
where
    M: buffa::Message + PartialEq,
{
    let body = M::decode_from_slice(request.exact_body())
        .map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
    if body.encode_to_vec().as_slice() != request.exact_body() {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    Ok(body)
}

fn require_exact_post_effect_readback(
    effect: &LifecycleAuthenticatedBrokerEffectV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    inventory: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(), LifecyclePhase6ErrorV1> {
    let outcome_body = successful_body(outcome)?;
    let inventory_body = successful_body(inventory)?;
    match effect.broker_method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => {
            let LifecycleCompiledBrokerRequestV1::Runtime(request) = &effect.compiled else {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            };
            let result = decode_canonical_success_body::<RuntimeObservation>(outcome_body)?;
            let complete =
                decode_canonical_success_body::<InventoryRuntimeResponse>(inventory_body)?;
            let target = effect.request.target();
            let targets = |row: &RuntimeObservation| {
                row.fence
                    .as_option()
                    .is_some_and(|fence| fence.sandbox_id.as_slice() == target)
            };
            let expected_state = match request.action.as_known() {
                Some(RuntimeAction::RUNTIME_ACTION_LAUNCH | RuntimeAction::RUNTIME_ACTION_THAW) => {
                    RuntimeState::RUNTIME_STATE_READY
                }
                Some(RuntimeAction::RUNTIME_ACTION_FREEZE) => RuntimeState::RUNTIME_STATE_FROZEN,
                Some(RuntimeAction::RUNTIME_ACTION_STOP | RuntimeAction::RUNTIME_ACTION_KILL) => {
                    RuntimeState::RUNTIME_STATE_ABSENT
                }
                _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
            };
            let absent = expected_state == RuntimeState::RUNTIME_STATE_ABSENT;
            if !targets(&result)
                || (absent
                    && !matches!(
                        result.state.as_known(),
                        Some(
                            RuntimeState::RUNTIME_STATE_ABSENT | RuntimeState::RUNTIME_STATE_EXITED
                        )
                    ))
                || (!absent && result.state.as_known() != Some(expected_state))
                || if absent {
                    complete.runtimes.iter().any(targets)
                } else {
                    !complete.runtimes.iter().any(|row| {
                        targets(row)
                            && row.runtime_handle == result.runtime_handle
                            && row.state == result.state
                            && row.observation_sequence >= result.observation_sequence
                    })
                }
            {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT => {
            let LifecycleCompiledBrokerRequestV1::DestinationSlot(request) = &effect.compiled
            else {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            };
            let result =
                decode_canonical_success_body::<ApplyDestinationSlotResponse>(outcome_body)?;
            let complete =
                decode_canonical_success_body::<InventoryDestinationSlotsResponse>(inventory_body)?;
            let target = effect.request.target();
            let result = result
                .resource
                .as_option()
                .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
            let expected_lifecycle = match request.action.as_known() {
                Some(DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP) => {
                    DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED
                }
                Some(
                    DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE
                    | DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE,
                ) => DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY,
                _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
            };
            if result.destination_slot_id.as_slice() != target
                || result.lifecycle.as_known() != Some(expected_lifecycle)
                || !complete.slots.iter().any(|row| row == result)
            {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => {
            let LifecycleCompiledBrokerRequestV1::Mount(request) = &effect.compiled else {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            };
            let result = decode_canonical_success_body::<MountResult>(outcome_body)?;
            let complete =
                decode_canonical_success_body::<InventoryMountResourcesResponse>(inventory_body)?;
            let target = effect.request.target();
            let rows = complete.mounts.iter().filter(|row| {
                row.recipe
                    .as_option()
                    .is_some_and(|recipe| recipe.attachment_id.as_slice() == target)
            });
            let (expected_state, expected_lifecycle) = match request.action.as_known() {
                Some(MountAction::MOUNT_ACTION_CREATE_DETACHED) => (
                    MountState::MOUNT_STATE_DETACHED,
                    MountLifecycle::MOUNT_LIFECYCLE_PREPARED,
                ),
                Some(MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE) => (
                    MountState::MOUNT_STATE_INSTALLED,
                    MountLifecycle::MOUNT_LIFECYCLE_INSTALLED,
                ),
                Some(MountAction::MOUNT_ACTION_DETACH) => (
                    MountState::MOUNT_STATE_REVOKED,
                    MountLifecycle::MOUNT_LIFECYCLE_PREPARED,
                ),
                Some(MountAction::MOUNT_ACTION_RELEASE) => (
                    MountState::MOUNT_STATE_ABSENT,
                    MountLifecycle::MOUNT_LIFECYCLE_RELEASED,
                ),
                _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
            };
            let exact = rows.into_iter().any(|row| {
                row.lifecycle.as_known() == Some(expected_lifecycle)
                    && (request.detached_mount_handle.is_empty()
                        || row.mount_handle == request.detached_mount_handle)
            });
            if result.attachment_id.as_slice() != target
                || result.state.as_known() != Some(expected_state)
                || !exact
            {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        }
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
            let LifecycleCompiledBrokerRequestV1::Storage(request) = &effect.compiled else {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            };
            let result = decode_canonical_success_body::<StorageResult>(outcome_body)?;
            let complete =
                decode_canonical_success_body::<InventoryStorageResourcesResponse>(inventory_body)?;
            let action = request
                .action
                .as_known()
                .ok_or(LifecyclePhase6ErrorV1::InvalidInput)?;
            let exact = complete
                .workspaces
                .iter()
                .any(|row| row.workspace_handle == result.storage_handle);
            let expected_present = matches!(
                action,
                StorageAction::STORAGE_ACTION_CREATE_WORKSPACE
                    | StorageAction::STORAGE_ACTION_CLONE
                    | StorageAction::STORAGE_ACTION_SET_QUOTA
            );
            let expected_absent = action == StorageAction::STORAGE_ACTION_DESTROY;
            // The v1 workspace inventory cannot prove Snapshot/Hold mutations.
            // Those effects must use the complete Storage-owner projection,
            // never reinterpret this launch-only list as success.
            if (!expected_present && !expected_absent)
                || (expected_present && !exact)
                || (expected_absent && exact)
            {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        }
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => {
            let LifecycleCompiledBrokerRequestV1::Network(request) = &effect.compiled else {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            };
            let result = decode_canonical_success_body::<NetworkResult>(outcome_body)?;
            let complete =
                decode_canonical_success_body::<InventoryNetworkResourcesResponse>(inventory_body)?;
            let expected_state = match request.action.as_known() {
                Some(NetworkAction::NETWORK_ACTION_PREPARE) => {
                    NetworkState::NETWORK_STATE_DEFAULT_DROP
                }
                Some(
                    NetworkAction::NETWORK_ACTION_ARM_LEASE
                    | NetworkAction::NETWORK_ACTION_RENEW_LEASE,
                ) => NetworkState::NETWORK_STATE_ARMED,
                Some(NetworkAction::NETWORK_ACTION_DISARM) => NetworkState::NETWORK_STATE_FENCED,
                Some(NetworkAction::NETWORK_ACTION_DESTROY) => NetworkState::NETWORK_STATE_ABSENT,
                _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
            };
            let absent = expected_state == NetworkState::NETWORK_STATE_ABSENT;
            let exact = complete.networks.iter().any(|row| {
                row.network_handle == result.network_handle
                    && row.state == result.state
                    && row.lease_generation == result.lease_generation
            });
            if result.state.as_known() != Some(expected_state) || absent == exact {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        }
        _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
    }
    Ok(())
}

fn successful_body(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<&[u8], LifecyclePhase6ErrorV1> {
    match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => Ok(exact_body),
        AuthenticatedBrokerMethodResultV1::Error(_) => Err(LifecyclePhase6ErrorV1::InvalidInput),
    }
}

fn decode_canonical_success_body<M>(bytes: &[u8]) -> Result<M, LifecyclePhase6ErrorV1>
where
    M: buffa::Message,
{
    let value = M::decode_from_slice(bytes).map_err(|_| LifecyclePhase6ErrorV1::InvalidInput)?;
    if value.encode_to_vec().as_slice() != bytes {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    Ok(value)
}

fn broker_inventory_domain(method: BrokerMethod) -> Option<LifecycleEffectDomainV1> {
    match method {
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME => {
            Some(LifecycleEffectDomainV1::Runtime)
        }
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => {
            Some(LifecycleEffectDomainV1::Mount)
        }
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => {
            Some(LifecycleEffectDomainV1::Storage)
        }
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => {
            Some(LifecycleEffectDomainV1::Network)
        }
        _ => None,
    }
}

impl LifecycleEffectRequestV1 {
    pub(super) fn new(
        current: &CurrentLifecycleOperationV1<'_>,
        domain: LifecycleEffectDomainV1,
        ordinal: u32,
        target: [u8; 16],
        prerequisite: ObjectDigest,
        plan: ObjectDigest,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if target == [0; 16] || prerequisite.as_bytes() == &[0; 32] || plan.as_bytes() == &[0; 32] {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }

        let Some(cursor) = current.persisted_effect_cursor()? else {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        };
        let persisted_plan = super::LifecycleStepPlanDigestV1::commit(plan.as_bytes());
        if cursor.state() != LifecycleAttemptStateV1::Reserved
            || cursor.plan() != persisted_plan.digest()
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }

        let body = lifecycle_effect_body_v1(
            current.operation().operation_id(),
            current.operation().record_revision(),
            domain,
            ordinal,
            cursor.step(),
            cursor.direction(),
            target,
            prerequisite,
            persisted_plan.digest(),
        );
        if LifecycleStepBodyDigestV1::commit(&body) != cursor.body() {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let admission = cursor.admission();
        let payload = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.phase6-dispatch.v1\0")
                .chain_update(body)
                .chain_update(cursor.attempt().to_be_bytes())
                .chain_update(admission.as_bytes())
                .finalize()
                .into(),
        );

        Ok(Self {
            operation: current.operation.operation_id(),
            operation_revision: current.operation.record_revision(),
            domain,
            ordinal,
            step: cursor.step(),
            direction: cursor.direction(),
            attempt: cursor.attempt(),
            admission,
            logical: cursor.request(),
            target,
            prerequisite,
            plan: persisted_plan.digest(),
            payload,
        })
    }

    /// Returns the protected operation identity.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the exact operation revision used to derive the handoff.
    #[must_use]
    pub const fn operation_revision(self) -> Revision {
        self.operation_revision
    }

    /// Returns the lower protected domain.
    #[must_use]
    pub const fn domain(self) -> LifecycleEffectDomainV1 {
        self.domain
    }

    /// Returns the method-specific stable effect ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }

    /// Returns the exact persisted lifecycle step index.
    #[must_use]
    pub const fn step(self) -> u32 {
        self.step
    }

    /// Returns whether this is the persisted forward or compensation attempt.
    #[must_use]
    pub const fn direction(self) -> LifecycleEffectDirectionV1 {
        self.direction
    }

    /// Returns the persisted one-based attempt number.
    #[must_use]
    pub const fn attempt(self) -> u32 {
        self.attempt
    }

    /// Returns the durable attempt admission commitment.
    #[must_use]
    pub const fn admission(self) -> ObjectDigest {
        self.admission
    }

    /// Returns the exact persisted logical request commitment.
    #[must_use]
    pub const fn logical_request(self) -> super::LifecycleStepRequestDigestV1 {
        self.logical
    }

    /// Returns the exact target identity bytes.
    #[must_use]
    pub const fn target(self) -> [u8; 16] {
        self.target
    }

    /// Returns the state commitment that must still be current at dispatch.
    #[must_use]
    pub const fn prerequisite(self) -> ObjectDigest {
        self.prerequisite
    }

    /// Returns the exact persisted method plan commitment.
    #[must_use]
    pub const fn plan(self) -> ObjectDigest {
        self.plan
    }

    pub(super) fn canonical_body(self) -> [u8; 122] {
        lifecycle_effect_body_v1(
            self.operation,
            self.operation_revision,
            self.domain,
            self.ordinal,
            self.step,
            self.direction,
            self.target,
            self.prerequisite,
            self.plan,
        )
    }

    /// Returns the canonical lower-domain request commitment.
    #[must_use]
    pub const fn payload(self) -> ObjectDigest {
        self.payload
    }
}

fn active_step_attempt(
    step: &super::LifecycleStepV1,
) -> Option<(
    u32,
    LifecycleEffectDirectionV1,
    super::LifecycleEffectAttemptV1,
    super::LifecycleStepRequestDigestV1,
    LifecycleStepBodyDigestV1,
    super::LifecycleStepPlanDigestV1,
)> {
    let (direction, attempt, request, body, plan) = match step.state() {
        LifecycleStepStateV1::Applying => (
            LifecycleEffectDirectionV1::Forward,
            step.forward_attempts().last().copied(),
            step.request(),
            step.request_body(),
            step.plan(),
        ),
        LifecycleStepStateV1::Compensating => (
            LifecycleEffectDirectionV1::Compensation,
            step.compensation_attempts().last().copied(),
            step.compensation_request()?,
            step.compensation_body()?,
            step.compensation_plan()?,
        ),
        _ => return None,
    };
    attempt.map(|attempt| (step.index(), direction, attempt, request, body, plan))
}

fn lifecycle_effect_body_v1(
    operation: OperationId,
    operation_revision: Revision,
    domain: LifecycleEffectDomainV1,
    ordinal: u32,
    step: u32,
    direction: LifecycleEffectDirectionV1,
    target: [u8; 16],
    prerequisite: ObjectDigest,
    plan: ObjectDigest,
) -> [u8; 122] {
    let mut body = [0; 122];
    body[..8].copy_from_slice(b"AOSLFX01");
    body[8..24].copy_from_slice(operation.as_bytes());
    body[24..32].copy_from_slice(&operation_revision.get().to_be_bytes());
    body[32] = domain as u8;
    body[33] = direction as u8;
    body[34..38].copy_from_slice(&ordinal.to_be_bytes());
    body[38..42].copy_from_slice(&step.to_be_bytes());
    body[42..58].copy_from_slice(&target);
    body[58..90].copy_from_slice(prerequisite.as_bytes());
    body[90..122].copy_from_slice(plan.as_bytes());
    body
}

/// Commits the canonical Phase 6 effect payload stored before dispatch.
///
/// # Errors
///
/// Returns [`LifecyclePhase6ErrorV1`] for sentinel target, prerequisite, or
/// plan fields. The returned digest is suitable for the selected lifecycle
/// step direction's persisted request body.
#[allow(clippy::too_many_arguments)]
pub fn lifecycle_phase6_effect_body_commitment_v1(
    operation: OperationId,
    operation_revision: Revision,
    domain: LifecycleEffectDomainV1,
    ordinal: u32,
    step: u32,
    direction: LifecycleEffectDirectionV1,
    target: [u8; 16],
    prerequisite: ObjectDigest,
    plan: ObjectDigest,
) -> Result<LifecycleStepBodyDigestV1, LifecyclePhase6ErrorV1> {
    if target == [0; 16] || prerequisite.as_bytes() == &[0; 32] || plan.as_bytes() == &[0; 32] {
        return Err(LifecyclePhase6ErrorV1::InvalidInput);
    }
    Ok(LifecycleStepBodyDigestV1::commit(
        &lifecycle_effect_body_v1(
            operation,
            operation_revision,
            domain,
            ordinal,
            step,
            direction,
            target,
            prerequisite,
            plan,
        ),
    ))
}

/// Commits one method-specific canonical Phase 6 plan description.
#[must_use]
pub fn lifecycle_phase6_plan_commitment_v1(
    canonical_description: ObjectDigest,
) -> super::LifecycleStepPlanDigestV1 {
    super::LifecycleStepPlanDigestV1::commit(canonical_description.as_bytes())
}
