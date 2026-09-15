//! Bounded single-host attempt admission and execution supervision.
//!
//! The supervisor implements the transport-neutral campaign
//! [`ExecutorService`] using a pluggable durable [`AssignmentLedger`]. It owns
//! only operational scheduling state: canonical attempt and observation
//! validation remains behind an injected read-only admission boundary, and no
//! campaign mutable-ref capability is accepted here.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use crucible_campaign::{
    AttemptExecutionScope, AttemptId, AttemptResourceLimits, AttemptStartMode, CampaignCodecError,
    CampaignLineageId, CancelAttemptExecutionDisposition, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse, DaemonEpoch,
    ExactCheckpointId, ExecutionId, ExecutorControlService, ExecutorRejection,
    ExecutorResumeService, ExecutorService, ExecutorStatusService, FindingCandidateBundleId,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    ObservationId, ResumeAttemptExecutionDisposition, ResumeAttemptExecutionRequest,
    ResumeAttemptExecutionResponse, SubmitAttemptDisposition, SubmitAttemptRequest,
    SubmitAttemptResponse,
};

use crate::{
    AssignmentLedger, AssignmentPublish, AssignmentRecord, AttemptExecutionKey,
    AttemptExecutionOrigin, AttemptResultStageOutcome, AttemptResultStagingError,
    AttemptRuntimeState, AttemptStateCas, AttemptWorkerReconcileOutcome, CapturedAttemptCheckpoint,
    CompletedFindingCandidate, ExactCheckpointResumeBasis, PreparedAttemptCheckpoint,
    PreparedAttemptResult, StagedAttemptResult,
};
use crucible::ContentHash;

/// Process-local authority for the exact root selected by durable admission.
///
/// Only post-CAS supervisor paths can construct this non-cloneable value. It
/// is consumed when the attempt process contract is born with the selected
/// exact root.
#[derive(Debug)]
pub(crate) struct SelectedExactCheckpointRoot {
    checkpoint: ExactCheckpointId,
}

impl SelectedExactCheckpointRoot {
    fn after_durable_admission(origin: AttemptExecutionOrigin) -> Option<Self> {
        origin.checkpoint().map(Self::after_durable_checkpoint)
    }

    fn after_durable_checkpoint(checkpoint: ExactCheckpointId) -> Self {
        Self { checkpoint }
    }

    /// Creates process-launch authority after a snapshot-bound finding proof.
    pub(crate) const fn after_authenticated_campaign_finding(
        checkpoint: ExactCheckpointId,
    ) -> Self {
        Self { checkpoint }
    }

    pub(crate) fn authorizes(&self, checkpoint: ExactCheckpointId) -> bool {
        self.checkpoint == checkpoint
    }

    pub(crate) fn process_contract_root(&self) -> ContentHash {
        ContentHash {
            bytes: self.checkpoint.content_id().digest(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn from_test_checkpoint(checkpoint: ExactCheckpointId) -> Self {
        Self { checkpoint }
    }
}

mod admission;
mod checkpoint;
mod checkpoint_promotion;
mod execution;
mod execution_control;
mod publication;
pub use publication::stage_prepared_attempt_result;

pub(crate) use execution_control::{
    AttemptCheckpointHandoff, ExecutionCancellationHook, ExecutionCancellationHookRegistration,
    ExecutionCheckpointHandoff,
};
pub use execution_control::{CheckpointHandoffFailure, ExecutionCancellation};
mod state;
mod submission;

pub use checkpoint_promotion::{
    CheckpointPromotionCompletionOutcome, CheckpointPromotionRecovery,
    CheckpointPromotionRestartWork, CheckpointPromotionStageOutcome,
    PausedCheckpointPromotionRecovery,
};

/// Read-only semantic and capability validation performed before guest work.
pub trait AttemptAdmissionValidator {
    /// Validates one complete immutable assignment basis.
    ///
    /// The implementation authenticates the attempt, lineage, referenced
    /// objects, and supported executor profile. Temporary input absence and
    /// stable incompatibility are protocol rejections, not transport errors.
    ///
    /// # Errors
    ///
    /// Returns the stable executor rejection when the immutable request basis
    /// is unavailable, unauthorized, or incompatible with this executor.
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection>;

    /// Validates the request's operational execution scope.
    ///
    /// The default accepts ordinary semantic execution only. Implementations
    /// that admit an operational scope must authenticate its immutable owner
    /// independently of the ordinary attempt and lineage validation performed
    /// by [`Self::validate`].
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorRejection::Incompatible`] for every non-semantic
    /// scope unless the implementation explicitly authenticates that scope.
    fn validate_execution_scope(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<(), ExecutorRejection> {
        if matches!(request.execution_scope(), AttemptExecutionScope::Semantic) {
            Ok(())
        } else {
            Err(ExecutorRejection::Incompatible)
        }
    }

    /// Resolves the immutable capture attempt for a selected-savepoint assignment.
    ///
    /// The default accepts ordinary assignments and fails closed for a selected
    /// source because only a repository-backed validator can authenticate that
    /// source's capture request.
    ///
    /// # Errors
    ///
    /// Returns a stable rejection when the selected source cannot be authenticated.
    fn selected_savepoint_source_attempt(
        &self,
        request: &SubmitAttemptRequest,
    ) -> Result<Option<AttemptId>, ExecutorRejection> {
        if matches!(
            request.start_mode(),
            AttemptStartMode::SelectedSavepoint { .. }
        ) {
            Err(ExecutorRejection::Incompatible)
        } else {
            Ok(None)
        }
    }

    /// Validates a published observation before durable completion admission.
    ///
    /// The default is deliberately fail-closed. Production validators
    /// authenticate the observation closure and exact attempt/lineage
    /// correspondence through the repository's read-only response validator.
    ///
    /// # Errors
    ///
    /// Returns the stable completion failure when the observation cannot be
    /// authenticated for the exact admitted request.
    fn validate_completion(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
    ) -> Result<(), CompletionValidationFailure> {
        Err(CompletionValidationFailure::Incompatible)
    }

    /// Validates every retained root before durable completion or replay.
    ///
    /// The default accepts observation-only completions through
    /// [`Self::validate_completion`] and fails closed when a candidate is
    /// present. Repository-backed implementations authenticate the candidate's
    /// complete immutable closure before returning success.
    ///
    /// # Errors
    ///
    /// Returns the stable completion failure when either retained root is
    /// unavailable, unauthorized, or incompatible with the admitted request.
    fn validate_completion_artifacts(
        &self,
        request: &SubmitAttemptRequest,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        self.validate_completion(request, observation)?;
        if finding_candidate.is_some() {
            return Err(CompletionValidationFailure::Incompatible);
        }
        Ok(())
    }

    /// Validates a durable completion projected through status or control.
    ///
    /// These requests preserve the semantic lineage and attempt but omit the
    /// original assignment-local resource fields. The default fails closed;
    /// repository-backed validators authenticate every reported root directly.
    ///
    /// # Errors
    ///
    /// Returns the stable completion failure when any retained artifact is
    /// unavailable, unauthorized, or incompatible.
    fn validate_retained_completion(
        &self,
        _lineage: CampaignLineageId,
        _attempt: AttemptId,
        _observation: ObservationId,
        _finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        Err(CompletionValidationFailure::Incompatible)
    }
}

/// Stable reason a durable operational completion cannot be reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionValidationFailure {
    /// Referenced immutable input is not currently available for authentication.
    UnavailableInput,
    /// The immutable observation tier denied this executor access.
    Unauthorized,
    /// The observation is present but does not match the exact execution basis.
    Incompatible,
}

impl<F> AttemptAdmissionValidator for F
where
    F: Fn(&SubmitAttemptRequest) -> Result<(), ExecutorRejection>,
{
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        self(request)
    }
}

/// Admission validator for supervisor tests that isolate execution behavior.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AllowAllAttemptAdmission;

#[cfg(test)]
impl AttemptAdmissionValidator for AllowAllAttemptAdmission {
    fn validate(&self, _request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        Ok(())
    }

    fn validate_completion(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
    ) -> Result<(), CompletionValidationFailure> {
        Ok(())
    }

    fn validate_completion_artifacts(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
        _finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        Ok(())
    }

    fn validate_retained_completion(
        &self,
        _lineage: CampaignLineageId,
        _attempt: AttemptId,
        _observation: ObservationId,
        _finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<(), CompletionValidationFailure> {
        Ok(())
    }
}

/// Hard single-host capacity advertised by one local executor incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorCapacity {
    maximum_concurrent_executions: u32,
    maximum_vcpus: u32,
    maximum_resident_bytes: u64,
    maximum_disk_bytes: u64,
    maximum_execution_quanta: u64,
}

impl ExecutorCapacity {
    /// Builds explicit bounded local execution capacity.
    ///
    /// A zero disk capacity is valid for read-only execution profiles.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorCapacityError`] when concurrency, CPU, resident
    /// memory, or execution-quanta capacity is zero.
    pub const fn new(
        maximum_concurrent_executions: u32,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_disk_bytes: u64,
        maximum_execution_quanta: u64,
    ) -> Result<Self, ExecutorCapacityError> {
        if maximum_concurrent_executions == 0 {
            return Err(ExecutorCapacityError::ZeroConcurrentExecutions);
        }
        if maximum_vcpus == 0 {
            return Err(ExecutorCapacityError::ZeroVcpus);
        }
        if maximum_resident_bytes == 0 {
            return Err(ExecutorCapacityError::ZeroResidentBytes);
        }
        if maximum_execution_quanta == 0 {
            return Err(ExecutorCapacityError::ZeroExecutionQuanta);
        }
        Ok(Self {
            maximum_concurrent_executions,
            maximum_vcpus,
            maximum_resident_bytes,
            maximum_disk_bytes,
            maximum_execution_quanta,
        })
    }

    /// Returns the maximum number of concurrent guest executions.
    #[must_use]
    pub const fn maximum_concurrent_executions(self) -> u32 {
        self.maximum_concurrent_executions
    }

    /// Returns the total virtual CPU capacity.
    #[must_use]
    pub const fn maximum_vcpus(self) -> u32 {
        self.maximum_vcpus
    }

    /// Returns the total resident-memory capacity in bytes.
    #[must_use]
    pub const fn maximum_resident_bytes(self) -> u64 {
        self.maximum_resident_bytes
    }

    /// Returns the total writable-materialization capacity in bytes.
    #[must_use]
    pub const fn maximum_disk_bytes(self) -> u64 {
        self.maximum_disk_bytes
    }

    /// Returns the per-execution deterministic work ceiling.
    #[must_use]
    pub const fn maximum_execution_quanta(self) -> u64 {
        self.maximum_execution_quanta
    }

    fn supports(self, resources: AttemptResourceLimits) -> bool {
        resources.maximum_vcpus() <= self.maximum_vcpus
            && resources.maximum_resident_bytes() <= self.maximum_resident_bytes
            && resources.maximum_disk_bytes() <= self.maximum_disk_bytes
            && resources.maximum_execution_quanta() <= self.maximum_execution_quanta
    }
}

/// Invalid local executor capacity configuration.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExecutorCapacityError {
    /// No execution could ever be admitted.
    #[error("executor capacity has zero concurrent executions")]
    ZeroConcurrentExecutions,
    /// No request can satisfy a zero virtual CPU capacity.
    #[error("executor capacity has zero virtual CPUs")]
    ZeroVcpus,
    /// No request can satisfy a zero resident-memory capacity.
    #[error("executor capacity has zero resident bytes")]
    ZeroResidentBytes,
    /// No request can satisfy a zero deterministic work ceiling.
    #[error("executor capacity has zero execution quanta")]
    ZeroExecutionQuanta,
}

/// Process-local aggregate capacity remaining after active reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorAvailability {
    slots: u32,
    vcpus: u32,
    resident_bytes: u64,
    disk_bytes: u64,
}

impl ExecutorAvailability {
    /// Returns available concurrent-attempt slots.
    #[must_use]
    pub const fn slots(self) -> u32 {
        self.slots
    }

    /// Returns available virtual CPUs.
    #[must_use]
    pub const fn vcpus(self) -> u32 {
        self.vcpus
    }

    /// Returns available resident-memory bytes.
    #[must_use]
    pub const fn resident_bytes(self) -> u64 {
        self.resident_bytes
    }

    /// Returns available writable-materialization bytes.
    #[must_use]
    pub const fn disk_bytes(self) -> u64 {
        self.disk_bytes
    }
}

/// One accepted assignment ready for the local execution worker.
#[derive(Debug)]
pub struct QueuedAttempt {
    execution: ExecutionId,
    request: SubmitAttemptRequest,
    origin: AttemptExecutionOrigin,
    cancellation: ExecutionCancellation,
    checkpoint_request: ExecutionCheckpointRequest,
    checkpoint_handoff: Option<ExecutionCheckpointHandoff>,
    selected_checkpoint: Mutex<Option<SelectedExactCheckpointRoot>>,
}

impl QueuedAttempt {
    #[cfg(test)]
    pub(crate) fn from_test_parts(execution: ExecutionId, request: SubmitAttemptRequest) -> Self {
        Self {
            execution,
            request,
            origin: AttemptExecutionOrigin::Initial,
            cancellation: ExecutionCancellation::default(),
            checkpoint_request: ExecutionCheckpointRequest::default(),
            checkpoint_handoff: None,
            selected_checkpoint: Mutex::new(None),
        }
    }

    /// Returns the local execution incarnation allocated by the supervisor.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact immutable assignment request.
    #[must_use]
    pub const fn request(&self) -> &SubmitAttemptRequest {
        &self.request
    }

    /// Returns whether execution starts initially or from an exact checkpoint.
    #[must_use]
    pub const fn origin(&self) -> AttemptExecutionOrigin {
        self.origin
    }

    /// Returns the process-local cancellation signal for the guest runner.
    #[must_use]
    pub const fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    /// Returns the process-local exact-checkpoint request signal.
    #[must_use]
    pub const fn checkpoint_request(&self) -> &ExecutionCheckpointRequest {
        &self.checkpoint_request
    }

    pub(crate) fn install_checkpoint_handoff(&mut self, handoff: ExecutionCheckpointHandoff) {
        self.checkpoint_handoff = Some(handoff);
    }

    pub(crate) fn take_selected_checkpoint(&self) -> Option<SelectedExactCheckpointRoot> {
        self.selected_checkpoint.lock().ok()?.take()
    }

    pub(crate) fn restore_selected_checkpoint(&self, selected: SelectedExactCheckpointRoot) {
        if let Ok(mut slot) = self.selected_checkpoint.lock() {
            *slot = Some(selected);
        }
    }

    pub(crate) const fn checkpoint_handoff(&self) -> Option<&ExecutionCheckpointHandoff> {
        self.checkpoint_handoff.as_ref()
    }

    pub(crate) fn reconciliation_copy(&self) -> Self {
        Self {
            execution: self.execution,
            request: self.request.clone(),
            origin: self.origin,
            cancellation: self.cancellation.clone(),
            checkpoint_request: self.checkpoint_request.clone(),
            checkpoint_handoff: None,
            selected_checkpoint: Mutex::new(None),
        }
    }
}

/// Cloneable process-local exact-checkpoint request for one execution.
#[derive(Clone, Debug, Default)]
pub struct ExecutionCheckpointRequest {
    requested: Arc<AtomicBool>,
}

impl ExecutionCheckpointRequest {
    /// Returns whether an exact checkpoint has been requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    /// Returns whether two handles name the same execution incarnation.
    #[must_use]
    pub fn same_incarnation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.requested, &other.requested)
    }

    fn request(&self) {
        self.requested.store(true, Ordering::Release);
    }

    /// Latches the request from a crate-internal regression fixture.
    #[cfg(test)]
    pub(crate) fn request_for_test(&self) {
        self.request();
    }
}

/// Durable outcome of requesting an exact checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointRequestOutcome {
    /// This call durably latched the request and signaled the worker.
    Requested,
    /// The same execution had already latched the request.
    AlreadyRequested,
    /// Publication is in progress under the returned retained root.
    Publishing {
        /// Exact root retained before immutable publication.
        checkpoint: ExactCheckpointId,
    },
    /// The execution is paused at a complete durable root.
    Paused {
        /// Complete exact-checkpoint root.
        checkpoint: ExactCheckpointId,
    },
    /// Canonical completion won before the request.
    AlreadyCompleted {
        /// Published immutable observation.
        observation: ObservationId,
    },
    /// Cancellation won before the request.
    AlreadyCanceled,
    /// The named execution is not current.
    NotCurrent,
}

/// Durable outcome of reserving an exact-checkpoint publication root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointPublicationOutcome {
    /// Requested state advanced to a retained publication root.
    Staged,
    /// The exact root was already staged.
    AlreadyStaged,
    /// The exact checkpoint was already complete and paused.
    AlreadyPaused,
    /// Completion or cancellation won before publication began.
    NotCurrent,
}

/// Idempotent result of publishing and stopping at an exact checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointCompletionOutcome {
    /// This call durably promoted the complete root and released capacity.
    Paused,
    /// The exact complete root was already durable.
    AlreadyPaused,
    /// The supplied execution or root is no longer current.
    NotCurrent,
}

/// Idempotent result of publishing one executor completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// This call durably published the completion state.
    Completed,
    /// The exact observation was already durable for this execution.
    AlreadyCompleted,
    /// Cancellation won the race; the observation is diagnostic only.
    Canceled,
    /// The supplied execution is not the attempt's current execution.
    NotCurrent,
}

/// Durable outcome of reserving an observation publication root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservationPublicationOutcome {
    /// Running state advanced to a durable publication root.
    Staged,
    /// The exact observation was already staged for this execution.
    AlreadyStaged,
    /// Cancellation won before publication began.
    Canceled,
    /// The exact observation was already durably completed.
    AlreadyCompleted,
    /// The supplied execution is no longer current.
    NotCurrent,
}

/// Idempotent result of canceling one local execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancellationOutcome {
    /// This call durably accepted cancellation.
    Canceled,
    /// The exact execution was already canceled.
    AlreadyCanceled,
    /// Completion won the race and remains eligible for validation.
    AlreadyCompleted {
        /// Immutable observation published before cancellation.
        observation: ObservationId,
    },
    /// The supplied execution is not the attempt's current execution.
    NotCurrent,
}

/// Idempotent result of durably stopping one non-retryable worker failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalFailureOutcome {
    /// This call durably recorded the terminal failure.
    Failed,
    /// The exact execution was already durably terminal.
    AlreadyFailed,
    /// The supplied execution is not the attempt's current execution.
    NotCurrent,
}

/// Failure from local executor ledger or internal state coordination.
#[derive(Debug, thiserror::Error)]
pub enum LocalExecutorError<E> {
    /// The operational ledger could not complete a safe read or publication.
    #[error("executor assignment ledger operation failed")]
    Ledger(E),
    /// A protocol response could not be constructed canonically.
    #[error(transparent)]
    Protocol(#[from] CampaignCodecError),
    /// The single-writer ledger contradicted the supervisor's validated basis.
    #[error("executor ledger invariant failed: {reason}")]
    LedgerInvariant {
        /// Stable invariant category.
        reason: &'static str,
    },
    /// One execution produced two different immutable observations.
    #[error("executor completion conflicts with the durable observation")]
    ConflictingCompletion,
    /// One execution produced two different exact-checkpoint roots.
    #[error("executor checkpoint conflicts with the durable exact root")]
    ConflictingCheckpoint,
    /// The semantic validator could not authenticate the completed observation.
    #[error("executor completion validation failed: {reason:?}")]
    CompletionValidation {
        /// Stable semantic failure category.
        reason: CompletionValidationFailure,
    },
    /// The daemon exhausted its process-local execution identity sequence.
    #[error("executor execution identity sequence is exhausted")]
    ExecutionIdentityExhausted,
}

#[derive(Debug)]
struct ActiveExecution {
    request: SubmitAttemptRequest,
    origin: AttemptExecutionOrigin,
    cancellation: ExecutionCancellation,
    checkpoint_request: ExecutionCheckpointRequest,
    worker_in_flight: bool,
    selected_checkpoint: Option<SelectedExactCheckpointRoot>,
}

/// One current process-owned execution observed under the supervisor actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalExecutionActivity {
    pub(crate) execution: ExecutionId,
    pub(crate) worker_in_flight: bool,
    pub(crate) cancellation_requested: bool,
    pub(crate) completion_pending: bool,
    pub(crate) cancellation_pending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingCompletion {
    key: AttemptExecutionKey,
    observation: ObservationId,
}

#[derive(Clone, Copy, Debug, Default)]
struct UsedCapacity {
    vcpus: u32,
    resident_bytes: u64,
    disk_bytes: u64,
}

enum AttemptAdvance<E> {
    Committed,
    CommittedAfterError(E),
}

/// Short actor decision made before repository-backed semantic validation.
// A resolved response deliberately remains inline: this short-lived internal
// decision crosses no persistence or wire boundary, and boxing every exact
// replay would introduce an allocation solely to shrink the empty variant.
// crucible-lint: allow rust-allow -- the large variant is bounded by the executor message limit.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SubmitPreflight {
    /// An exact replay, conflict, or stale epoch produced a complete response.
    Resolved(SubmitAttemptResponse),
    /// The caller must authenticate semantic input outside actor ownership.
    NeedsValidation,
}

/// Repository-authenticated operational data retained across actor reacquisition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ValidatedSubmitAdmission {
    selected_source_attempt: Option<AttemptId>,
}

impl ValidatedSubmitAdmission {
    pub(crate) fn validate<V: AttemptAdmissionValidator>(
        validator: &V,
        request: &SubmitAttemptRequest,
    ) -> Result<Self, ExecutorRejection> {
        validator.validate(request)?;
        validator.validate_execution_scope(request)?;
        let selected_source_attempt = validator.selected_savepoint_source_attempt(request)?;
        if selected_source_attempt.is_some()
            != matches!(
                request.start_mode(),
                AttemptStartMode::SelectedSavepoint { .. }
            )
        {
            return Err(ExecutorRejection::Incompatible);
        }
        Ok(Self {
            selected_source_attempt,
        })
    }
}

/// Sole-writer bounded local executor over one operational ledger.
pub struct LocalExecutorSupervisor<L, V> {
    ledger: L,
    validator: Arc<V>,
    daemon_epoch: DaemonEpoch,
    capacity: ExecutorCapacity,
    next_execution_ordinal: u64,
    active: BTreeMap<ExecutionId, ActiveExecution>,
    queued: VecDeque<ExecutionId>,
    pending_completions: BTreeMap<ExecutionId, PendingCompletion>,
    pending_cancellations: BTreeMap<ExecutionId, AttemptExecutionKey>,
    used: UsedCapacity,
}

impl<L, V> LocalExecutorSupervisor<L, V> {
    /// Creates an empty process-local supervisor over durable operational state.
    ///
    /// A restarted process supplies a fresh [`DaemonEpoch`]. Stale running
    /// records from older epochs are replaceable; completed observations remain
    /// durable and immediately replayable.
    #[must_use]
    pub fn new(
        ledger: L,
        validator: V,
        daemon_epoch: DaemonEpoch,
        capacity: ExecutorCapacity,
    ) -> Self {
        Self {
            ledger,
            validator: Arc::new(validator),
            daemon_epoch,
            capacity,
            next_execution_ordinal: 0,
            active: BTreeMap::new(),
            queued: VecDeque::new(),
            pending_completions: BTreeMap::new(),
            pending_cancellations: BTreeMap::new(),
            used: UsedCapacity::default(),
        }
    }

    /// Returns this process's daemon incarnation.
    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    /// Returns the configured hard local capacity.
    #[must_use]
    pub const fn capacity(&self) -> ExecutorCapacity {
        self.capacity
    }

    /// Returns the number of current execution reservations.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Copies the bounded process-owned activity needed by status projection.
    pub(crate) fn operational_activity_snapshot(&self) -> Vec<LocalExecutionActivity> {
        self.active
            .iter()
            .map(|(execution, active)| LocalExecutionActivity {
                execution: *execution,
                worker_in_flight: active.worker_in_flight,
                cancellation_requested: active.cancellation.is_canceled(),
                completion_pending: self.pending_completions.contains_key(execution),
                cancellation_pending: self.pending_cancellations.contains_key(execution),
            })
            .collect()
    }

    /// Returns aggregate capacity remaining after current reservations.
    #[must_use]
    pub fn availability(&self) -> ExecutorAvailability {
        let active = u32::try_from(self.active.len()).unwrap_or(u32::MAX);
        ExecutorAvailability {
            slots: self
                .capacity
                .maximum_concurrent_executions
                .saturating_sub(active),
            vcpus: self.capacity.maximum_vcpus.saturating_sub(self.used.vcpus),
            resident_bytes: self
                .capacity
                .maximum_resident_bytes
                .saturating_sub(self.used.resident_bytes),
            disk_bytes: self
                .capacity
                .maximum_disk_bytes
                .saturating_sub(self.used.disk_bytes),
        }
    }

    /// Returns the number of accepted executions not yet taken by a worker.
    #[must_use]
    pub fn queued_count(&self) -> usize {
        self.queued.len()
    }

    /// Returns the ledger for read-only diagnostics and tests.
    #[must_use]
    pub const fn ledger(&self) -> &L {
        &self.ledger
    }

    /// Returns the owned ledger after supervisor shutdown.
    #[must_use]
    pub fn into_ledger(self) -> L {
        self.ledger
    }

    /// Returns shared read-only admission authority for out-of-actor preflight.
    pub(crate) fn admission_validator(&self) -> Arc<V> {
        Arc::clone(&self.validator)
    }

    /// Takes the next accepted execution exactly once from the pending queue.
    #[must_use]
    pub fn next_queued(&mut self) -> Option<QueuedAttempt> {
        while let Some(execution) = self.queued.pop_front() {
            if let Some(active) = self.active.get_mut(&execution) {
                active.worker_in_flight = true;
                return Some(QueuedAttempt {
                    execution,
                    request: active.request.clone(),
                    origin: active.origin,
                    cancellation: active.cancellation.clone(),
                    checkpoint_request: active.checkpoint_request.clone(),
                    checkpoint_handoff: None,
                    selected_checkpoint: Mutex::new(active.selected_checkpoint.take()),
                });
            }
        }
        None
    }

    /// Requeues a still-current accepted execution after an operational worker failure.
    ///
    /// The queue remains bounded by active capacity. Stale work and duplicate
    /// queue entries are ignored.
    pub fn requeue(&mut self, queued: QueuedAttempt) {
        let execution = queued.execution;
        if self.active.get(&execution).is_some_and(|active| {
            active.request == queued.request && active.origin == queued.origin
        }) && !self.queued.contains(&execution)
        {
            if let Some(active) = self.active.get_mut(&execution) {
                active.selected_checkpoint = queued.selected_checkpoint.into_inner().ok().flatten();
                active.worker_in_flight = false;
            }
            self.queued.push_back(execution);
        }
    }

    /// Signals cancellation to every active worker without releasing capacity.
    ///
    /// The bounded worker-pool owner uses this during shutdown. Physical
    /// reservations remain charged until each worker returns and reconciles its
    /// exact linear token.
    pub(crate) fn signal_all_active_cancellation(&self) {
        for active in self.active.values() {
            active.cancellation.cancel();
        }
    }
}

impl<L, V> ExecutorService for LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    type Error = LocalExecutorError<L::Error>;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.submit(request)
    }
}

impl<L, V> ExecutorStatusService for LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        let key = AttemptExecutionKey::new_scoped(
            request.lineage(),
            request.attempt(),
            request.execution_scope(),
        );
        let state = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let (disposition, finding_candidate) = match state {
            Some(state)
                if state.daemon_epoch() == request.daemon_epoch()
                    && state.execution() == request.execution()
                    && state.execution_basis() == request.execution_basis() =>
            {
                match state {
                    AttemptRuntimeState::Running { .. }
                    | AttemptRuntimeState::Publishing { .. } => {
                        (GetAttemptExecutionDisposition::Running, None)
                    }
                    AttemptRuntimeState::CheckpointRequested { .. } => {
                        (GetAttemptExecutionDisposition::CheckpointRequested, None)
                    }
                    AttemptRuntimeState::CheckpointPublishing { checkpoint, .. } => (
                        GetAttemptExecutionDisposition::CheckpointPublishing { checkpoint },
                        None,
                    ),
                    AttemptRuntimeState::CheckpointPromoting {
                        promoted_checkpoint,
                        ..
                    } => (
                        GetAttemptExecutionDisposition::CheckpointPublishing {
                            checkpoint: promoted_checkpoint,
                        },
                        None,
                    ),
                    AttemptRuntimeState::Paused { checkpoint, .. } => {
                        (GetAttemptExecutionDisposition::Paused { checkpoint }, None)
                    }
                    AttemptRuntimeState::Completed {
                        observation,
                        finding_candidate,
                        ..
                    } => {
                        let finding_candidate = finding_candidate.candidate();
                        self.validator
                            .validate_retained_completion(
                                request.lineage(),
                                request.attempt(),
                                observation,
                                finding_candidate,
                            )
                            .map_err(|reason| LocalExecutorError::CompletionValidation {
                                reason,
                            })?;
                        (
                            GetAttemptExecutionDisposition::Completed { observation },
                            finding_candidate,
                        )
                    }
                    AttemptRuntimeState::Canceled { .. } => {
                        (GetAttemptExecutionDisposition::Canceled, None)
                    }
                    AttemptRuntimeState::TerminalFailure { .. } => {
                        (GetAttemptExecutionDisposition::TerminalFailure, None)
                    }
                }
            }
            Some(_) | None => (GetAttemptExecutionDisposition::NotCurrent, None),
        };
        match finding_candidate {
            Some(candidate) => GetAttemptExecutionResponse::new_with_finding_candidate(
                request,
                disposition,
                candidate,
            ),
            None => GetAttemptExecutionResponse::new(request, disposition),
        }
        .map_err(Into::into)
    }
}

impl<L, V> ExecutorControlService for LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        let key = AttemptExecutionKey::new_scoped(
            request.lineage(),
            request.attempt(),
            request.execution_scope(),
        );
        let state = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let exact = state.as_ref().is_some_and(|state| {
            state.daemon_epoch() == request.daemon_epoch()
                && state.execution() == request.execution()
                && state.execution_basis() == request.execution_basis()
        });
        if exact
            && let Some(AttemptRuntimeState::Completed {
                observation,
                finding_candidate,
                ..
            }) = state
        {
            let finding_candidate = finding_candidate.candidate();
            self.validator
                .validate_retained_completion(
                    request.lineage(),
                    request.attempt(),
                    observation,
                    finding_candidate,
                )
                .map_err(|reason| LocalExecutorError::CompletionValidation { reason })?;
        }
        let finding_candidate = state.and_then(AttemptRuntimeState::finding_candidate);
        let disposition = if exact {
            match self.request_checkpoint(key, request.execution())? {
                CheckpointRequestOutcome::Requested => {
                    CheckpointAttemptExecutionDisposition::Requested
                }
                CheckpointRequestOutcome::AlreadyRequested => {
                    CheckpointAttemptExecutionDisposition::AlreadyRequested
                }
                CheckpointRequestOutcome::Publishing { checkpoint } => {
                    CheckpointAttemptExecutionDisposition::Publishing { checkpoint }
                }
                CheckpointRequestOutcome::Paused { checkpoint } => {
                    CheckpointAttemptExecutionDisposition::Paused { checkpoint }
                }
                CheckpointRequestOutcome::AlreadyCompleted { observation } => {
                    CheckpointAttemptExecutionDisposition::AlreadyCompleted { observation }
                }
                CheckpointRequestOutcome::AlreadyCanceled => {
                    CheckpointAttemptExecutionDisposition::AlreadyCanceled
                }
                CheckpointRequestOutcome::NotCurrent => {
                    CheckpointAttemptExecutionDisposition::NotCurrent
                }
            }
        } else {
            CheckpointAttemptExecutionDisposition::NotCurrent
        };
        match (disposition, finding_candidate) {
            (CheckpointAttemptExecutionDisposition::AlreadyCompleted { .. }, Some(candidate)) => {
                CheckpointAttemptExecutionResponse::new_with_finding_candidate(
                    request,
                    disposition,
                    candidate,
                )
            }
            _ => CheckpointAttemptExecutionResponse::new(request, disposition),
        }
        .map_err(Into::into)
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        let key = AttemptExecutionKey::new_scoped(
            request.lineage(),
            request.attempt(),
            request.execution_scope(),
        );
        let state = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let exact = state.as_ref().is_some_and(|state| {
            state.daemon_epoch() == request.daemon_epoch()
                && state.execution() == request.execution()
                && state.execution_basis() == request.execution_basis()
        });
        if exact
            && let Some(AttemptRuntimeState::Completed {
                observation,
                finding_candidate,
                ..
            }) = state
        {
            let finding_candidate = finding_candidate.candidate();
            self.validator
                .validate_retained_completion(
                    request.lineage(),
                    request.attempt(),
                    observation,
                    finding_candidate,
                )
                .map_err(|reason| LocalExecutorError::CompletionValidation { reason })?;
        }
        let finding_candidate = state.and_then(AttemptRuntimeState::finding_candidate);
        let disposition = if exact {
            match self.cancel_execution(key, request.execution())? {
                CancellationOutcome::Canceled => CancelAttemptExecutionDisposition::Canceled,
                CancellationOutcome::AlreadyCanceled => {
                    CancelAttemptExecutionDisposition::AlreadyCanceled
                }
                CancellationOutcome::AlreadyCompleted { observation } => {
                    CancelAttemptExecutionDisposition::AlreadyCompleted { observation }
                }
                CancellationOutcome::NotCurrent => CancelAttemptExecutionDisposition::NotCurrent,
            }
        } else {
            CancelAttemptExecutionDisposition::NotCurrent
        };
        match (disposition, finding_candidate) {
            (CancelAttemptExecutionDisposition::AlreadyCompleted { .. }, Some(candidate)) => {
                CancelAttemptExecutionResponse::new_with_finding_candidate(
                    request,
                    disposition,
                    candidate,
                )
            }
            _ => CancelAttemptExecutionResponse::new(request, disposition),
        }
        .map_err(Into::into)
    }
}

impl<L, V> ExecutorResumeService for LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        self.resume(request)
    }
}

#[cfg(test)]
mod tests;
