//! Portable backend trait and closed effect outcomes.

use super::{
    BackendExecutionHandle, BackendExecutionInspectionRequestV1, BackendExecutionInspectionV1,
    BackendExecutionRequestV1, BackendFreezeObservationV1, BackendLifecycleRecoveryRecordV1,
    BackendOperationIdV1, BackendOperationSequenceV1, BackendProbeReportV1, BackendRetryClassV1,
    BackendRuntimeInspectionV1, BackendStartObservationV1, BackendStopDeadlineV1,
    BackendStopObservationV1, DestroyableRuntime, DestroyedRuntime, FrozenRuntime, PreparedRuntime,
    ResolvedRuntimePlanV1, RunningRuntime, RuntimeHandleCommitmentV1, RuntimeRecoveryToken,
    StoppableRuntime, StoppedRuntime,
};

/// Reports the result of a state-consuming backend effect.
#[must_use]
pub enum BackendEffectOutcome<S, T, R> {
    /// The effect and all required postcondition observations completed.
    Complete(S),
    /// The backend proved no effect began and returns state safe to retry.
    Rejected {
        /// Closed failure classification.
        error: RuntimeBackendError,
        /// Original state retained for an explicitly authorized retry.
        retry_state: T,
    },
    /// The effect may have begun and requires durable authenticated recovery.
    RecoveryRequired(RuntimeRecoveryToken<R>),
}

/// Reports the result of an execution handoff that borrows its runtime.
#[must_use]
pub enum BackendExecutionOutcome<H, R> {
    /// The agent accepted the exact admitted execution and returned a handle.
    Complete(BackendExecutionHandle<H>),
    /// The backend proved that no command was handed off.
    Rejected(RuntimeBackendError),
    /// Handoff status is ambiguous and must be reconciled before retry.
    RecoveryRequired(RuntimeRecoveryToken<R>),
}

/// Reports authenticated resolution of one ambiguous backend boundary.
#[must_use]
pub enum BackendRecoveryOutcome<O, R> {
    /// Protected inspection resolved the exact effect to one observation.
    Recovered(O),
    /// Inspection was temporarily unavailable and returns the intact token.
    Retryable {
        /// Closed diagnostic classification.
        error: RuntimeBackendError,
        /// Move-only recovery authority retained for another inspection.
        token: RuntimeRecoveryToken<R>,
    },
    /// Evidence conflicted; the intact token must remain quarantined.
    Quarantine {
        /// Closed integrity or currentness classification.
        error: RuntimeBackendError,
        /// Move-only token retained for operator-visible reconciliation.
        token: RuntimeRecoveryToken<R>,
    },
}

/// Defines the complete backend-neutral runtime lifecycle.
///
/// Implementations resolve plan commitments through protected local catalogs.
/// They must validate every currentness binding immediately before an effect
/// and verify postconditions before returning `Complete`. A failure after an
/// effect may have begun returns `RecoveryRequired`; it must never be relabeled
/// as a retryable pre-effect rejection.
pub trait RuntimeBackend {
    /// Opaque backend state produced by `prepare`.
    type PreparedHandle;
    /// Opaque backend state for a started runtime.
    type RuntimeHandle;
    /// Opaque backend state for one execution.
    type ExecutionHandle;
    /// Opaque backend state retained across ambiguous lifecycle effects.
    type LifecycleRecoveryHandle;
    /// Opaque backend state retained across ambiguous execution handoff.
    type ExecutionRecoveryHandle;

    /// Returns an authenticated, nonauthorizing capability observation.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] when protected platform inspection is
    /// unavailable, inconsistent, stale, or fails integrity validation.
    fn probe(&mut self) -> Result<BackendProbeReportV1, RuntimeBackendError>;

    /// Resolves protected resources and prepares a runtime without starting it.
    fn prepare(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        plan: ResolvedRuntimePlanV1,
    ) -> BackendEffectOutcome<
        PreparedRuntime<Self::PreparedHandle>,
        ResolvedRuntimePlanV1,
        Self::LifecycleRecoveryHandle,
    >;

    /// Starts a prepared runtime and verifies its exact payload generation.
    fn start(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        prepared: PreparedRuntime<Self::PreparedHandle>,
    ) -> BackendEffectOutcome<
        (
            RunningRuntime<Self::RuntimeHandle>,
            BackendStartObservationV1,
        ),
        PreparedRuntime<Self::PreparedHandle>,
        Self::LifecycleRecoveryHandle,
    >;

    /// Hands one durably admitted execution to the authenticated guest agent.
    fn exec(
        &mut self,
        runtime: &mut RunningRuntime<Self::RuntimeHandle>,
        request: BackendExecutionRequestV1,
    ) -> BackendExecutionOutcome<Self::ExecutionHandle, Self::ExecutionRecoveryHandle>;

    /// Freezes the complete payload cgroup and verifies the barrier.
    fn freeze(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: RunningRuntime<Self::RuntimeHandle>,
    ) -> BackendEffectOutcome<
        (
            FrozenRuntime<Self::RuntimeHandle>,
            BackendFreezeObservationV1,
        ),
        RunningRuntime<Self::RuntimeHandle>,
        Self::LifecycleRecoveryHandle,
    >;

    /// Thaws an exact frozen payload generation and verifies runnable state.
    fn thaw(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: FrozenRuntime<Self::RuntimeHandle>,
    ) -> BackendEffectOutcome<
        (
            RunningRuntime<Self::RuntimeHandle>,
            BackendRuntimeInspectionV1,
        ),
        FrozenRuntime<Self::RuntimeHandle>,
        Self::LifecycleRecoveryHandle,
    >;

    /// Stops a running or frozen payload before the caller's relative deadline.
    fn stop(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: StoppableRuntime<Self::RuntimeHandle>,
        deadline: BackendStopDeadlineV1,
    ) -> BackendEffectOutcome<
        (
            StoppedRuntime<Self::RuntimeHandle>,
            BackendStopObservationV1,
        ),
        StoppableRuntime<Self::RuntimeHandle>,
        Self::LifecycleRecoveryHandle,
    >;

    /// Inspects one exact runtime without mutating it.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] when the observation is unauthenticated,
    /// stale, incomplete, or not bound to the requested generation.
    fn inspect(
        &mut self,
        expected: &RuntimeHandleCommitmentV1,
    ) -> Result<BackendRuntimeInspectionV1, RuntimeBackendError>;

    /// Inspects one exact execution without mutating it.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for an unauthenticated, stale,
    /// incomplete, or cross-runtime observation.
    fn inspect_execution(
        &mut self,
        expected: &BackendExecutionInspectionRequestV1,
    ) -> Result<BackendExecutionInspectionV1, RuntimeBackendError>;

    /// Resolves an ambiguous lifecycle effect using protected backend state.
    ///
    /// The implementation must match operation, sequence, currentness, plan,
    /// and request commitment before inspecting the retained backend-private
    /// handle. Every nonterminal outcome returns the intact move-only token.
    fn recover_lifecycle(
        &mut self,
        token: RuntimeRecoveryToken<Self::LifecycleRecoveryHandle>,
    ) -> BackendRecoveryOutcome<BackendRuntimeInspectionV1, Self::LifecycleRecoveryHandle>;

    /// Resolves an Issued or Indeterminate lifecycle record after process loss.
    ///
    /// The backend must authenticate its own inventory and match operation,
    /// sequence, currentness, plan, runtime handle, request, and protected
    /// provenance. It must not reissue the recorded effect.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] when protected recovery evidence is
    /// unavailable, stale, incomplete, or conflicts with the durable record.
    fn recover_lifecycle_after_crash(
        &mut self,
        record: &BackendLifecycleRecoveryRecordV1,
    ) -> Result<BackendRuntimeInspectionV1, RuntimeBackendError>;

    /// Resolves an ambiguous execution handoff without reissuing the command.
    ///
    /// Exact absence is an authenticated recovery observation, never proof
    /// that command execution did not occur. The durable owner determines the
    /// terminal Lost transition through complete inventory reconciliation.
    fn recover_execution_handoff(
        &mut self,
        token: RuntimeRecoveryToken<Self::ExecutionRecoveryHandle>,
    ) -> BackendRecoveryOutcome<BackendExecutionInspectionV1, Self::ExecutionRecoveryHandle>;

    /// Destroys prepared resources only after the payload is proven absent.
    fn destroy(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: DestroyableRuntime<Self::PreparedHandle, Self::RuntimeHandle>,
    ) -> BackendEffectOutcome<
        DestroyedRuntime,
        DestroyableRuntime<Self::PreparedHandle, Self::RuntimeHandle>,
        Self::LifecycleRecoveryHandle,
    >;
}

/// Reports a closed backend failure without exposing host paths or commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeBackendError {
    /// The protected capability report is unavailable or stale.
    #[error("backend capability evidence is unavailable")]
    CapabilityEvidenceUnavailable,
    /// One hard semantic capability is absent.
    #[error("backend cannot satisfy the resolved runtime plan")]
    UnsupportedPlan,
    /// Durable currentness differs from the requested assignment or generation.
    #[error("backend request is stale")]
    StaleCurrentness,
    /// An operation sequence was replayed with different bytes.
    #[error("backend operation sequence equivocated")]
    Equivocation,
    /// An operation sequence has a gap, rollback, or exhausted value.
    #[error("backend operation sequence is invalid")]
    InvalidSequence,
    /// A protected catalog cannot resolve one exact opaque commitment.
    #[error("backend resource is unavailable")]
    UnknownResource,
    /// Runtime state is incompatible with the requested operation.
    #[error("backend runtime is in a conflicting state")]
    StateConflict,
    /// A bounded resource or response ceiling was exceeded.
    #[error("backend resource bound was exceeded")]
    ResourceExhausted,
    /// An authenticated guest-agent session is absent or superseded.
    #[error("backend guest-agent session is unavailable")]
    AgentUnavailable,
    /// Backend or agent evidence failed an integrity check.
    #[error("backend integrity verification failed")]
    IntegrityFailure,
    /// The backend proved no effect started and an exact retry may be admitted.
    #[error("backend rejected the request before effect")]
    RetryableBeforeEffect,
    /// This exact plan or operation failed permanently.
    #[error("backend operation failed permanently")]
    PermanentFailure,
}

impl RuntimeBackendError {
    /// Returns the only retry classification permitted for this failure.
    #[must_use]
    pub const fn retry_class(self) -> BackendRetryClassV1 {
        match self {
            Self::RetryableBeforeEffect => BackendRetryClassV1::SafeBeforeEffect,
            Self::CapabilityEvidenceUnavailable
            | Self::AgentUnavailable
            | Self::ResourceExhausted => BackendRetryClassV1::ExactIdempotentReplay,
            Self::UnsupportedPlan
            | Self::StaleCurrentness
            | Self::Equivocation
            | Self::InvalidSequence
            | Self::UnknownResource
            | Self::StateConflict
            | Self::IntegrityFailure
            | Self::PermanentFailure => BackendRetryClassV1::Permanent,
        }
    }
}
