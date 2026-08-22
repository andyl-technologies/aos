//! Bounded single-host attempt admission and execution supervision.
//!
//! The supervisor implements the transport-neutral campaign
//! [`ExecutorService`] using a pluggable durable [`AssignmentLedger`]. It owns
//! only operational scheduling state: canonical attempt and observation
//! validation remains behind an injected read-only admission boundary, and no
//! campaign mutable-ref capability is accepted here.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crucible_campaign::{
    AttemptResourceLimits, CampaignCodecError, CancelAttemptExecutionDisposition,
    CancelAttemptExecutionRequest, CancelAttemptExecutionResponse,
    CheckpointAttemptExecutionDisposition, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, DaemonEpoch, ExactCheckpointId, ExecutionId,
    ExecutorControlService, ExecutorRejection, ExecutorService, ExecutorStatusService,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    ObservationId, SubmitAttemptDisposition, SubmitAttemptRequest, SubmitAttemptResponse,
};

use crate::{
    AssignmentLedger, AssignmentPublish, AssignmentRecord, AttemptExecutionKey,
    AttemptRuntimeState, AttemptStateCas,
};

/// Read-only semantic and capability validation performed before guest work.
pub trait AttemptAdmissionValidator {
    /// Validates one complete immutable assignment basis.
    ///
    /// The implementation authenticates the attempt, lineage, referenced
    /// objects, and supported executor profile. Temporary input absence and
    /// stable incompatibility are protocol rejections, not transport errors.
    fn validate(&self, request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection>;

    /// Validates a published observation before durable completion admission.
    ///
    /// The default is deliberately fail-closed. Production validators
    /// authenticate the observation closure and exact attempt/lineage
    /// correspondence through the repository's read-only response validator.
    fn validate_completion(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
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

/// Admission validator used only by already-authenticated compositions/tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAllAttemptAdmission;

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
    cancellation: ExecutionCancellation,
    checkpoint_request: ExecutionCheckpointRequest,
}

impl QueuedAttempt {
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
}

/// Cloneable process-local cancellation signal for one execution incarnation.
#[derive(Clone, Debug, Default)]
pub struct ExecutionCancellation {
    canceled: Arc<AtomicBool>,
}

impl ExecutionCancellation {
    /// Returns whether cancellation has been requested for this execution.
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    /// Returns whether two handles name the same execution incarnation.
    #[must_use]
    pub fn same_incarnation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.canceled, &other.canceled)
    }

    fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
    }

    /// Requests cancellation from a crate-internal regression fixture.
    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self) {
        self.cancel();
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
pub enum ObservationPublicationOutcome {
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

#[derive(Clone, Debug)]
struct ActiveExecution {
    request: SubmitAttemptRequest,
    cancellation: ExecutionCancellation,
    checkpoint_request: ExecutionCheckpointRequest,
    worker_in_flight: bool,
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
pub(crate) enum SubmitPreflight {
    /// An exact replay, conflict, or stale epoch produced a complete response.
    Resolved(SubmitAttemptResponse),
    /// The caller must authenticate semantic input outside actor ownership.
    NeedsValidation,
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

    /// Returns the number of published observations awaiting ledger reconciliation.
    #[must_use]
    pub fn pending_completion_count(&self) -> usize {
        self.pending_completions.len()
    }

    /// Returns the number of terminal worker stops awaiting ledger reconciliation.
    #[must_use]
    pub fn pending_cancellation_count(&self) -> usize {
        self.pending_cancellations.len()
    }

    /// Returns one staged completion execution for bounded actor retry.
    #[must_use]
    pub fn next_pending_completion(&self) -> Option<ExecutionId> {
        self.pending_completions.keys().next().copied()
    }

    /// Returns one staged cancellation execution for bounded actor retry.
    #[must_use]
    pub fn next_pending_cancellation(&self) -> Option<ExecutionId> {
        self.pending_cancellations.keys().next().copied()
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
                    cancellation: active.cancellation.clone(),
                    checkpoint_request: active.checkpoint_request.clone(),
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
        if self
            .active
            .get(&execution)
            .is_some_and(|active| active.request == queued.request)
            && !self.queued.contains(&execution)
        {
            if let Some(active) = self.active.get_mut(&execution) {
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

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    /// Performs replay/conflict and epoch checks before semantic admission.
    ///
    /// A caller may release actor ownership while evaluating [`Self::admission_validator`]
    /// after this method returns [`SubmitPreflight::NeedsValidation`]. The final
    /// submit method rechecks assignment identity after reacquiring ownership.
    pub(crate) fn preflight_submit(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitPreflight, LocalExecutorError<L::Error>> {
        if let Some(response) = self.assignment_response(request)? {
            return Ok(SubmitPreflight::Resolved(response));
        }
        if request.daemon_epoch() != self.daemon_epoch {
            return self
                .persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Unauthorized,
                    },
                )
                .map(SubmitPreflight::Resolved);
        }
        Ok(SubmitPreflight::NeedsValidation)
    }

    /// Completes assignment admission after out-of-actor semantic validation.
    pub(crate) fn submit_after_validation(
        &mut self,
        request: &SubmitAttemptRequest,
        validation: Result<(), ExecutorRejection>,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        if let Some(response) = self.assignment_response(request)? {
            return Ok(response);
        }
        if request.daemon_epoch() != self.daemon_epoch {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Unauthorized,
                },
            );
        }
        if let Err(reason) = validation {
            return self.persist_response(request, SubmitAttemptDisposition::Rejected { reason });
        }
        self.submit_admitted(request)
    }

    /// Reconciles a caught worker panic after its linear token was unwound.
    ///
    /// Only the fixed worker owner calls this with the execution identity and
    /// attempt key captured before dispatch. The method marks physical worker
    /// ownership finished before durable cancellation so capacity cannot remain
    /// charged to an execution whose thread has already stopped.
    pub(crate) fn reconcile_panicked_worker(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
    ) -> Result<CancellationOutcome, LocalExecutorError<L::Error>> {
        if let Some(active) = self.active.get_mut(&execution) {
            if AttemptExecutionKey::new(active.request.lineage(), active.request.attempt()) != key {
                return Err(LocalExecutorError::LedgerInvariant {
                    reason: "panicked worker execution basis does not match active reservation",
                });
            }
            active.cancellation.cancel();
            active.worker_in_flight = false;
        }
        self.cancel_execution(key, execution)
    }

    /// Durably requests one exact checkpoint before signaling the worker.
    ///
    /// The operational state transition is committed first. A crash after the
    /// transition therefore preserves checkpoint intent for restart recovery;
    /// a live exact worker receives a sticky process-local signal afterward.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for ledger failures or contradictory
    /// process-local ownership.
    pub fn request_checkpoint(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
    ) -> Result<CheckpointRequestOutcome, LocalExecutorError<L::Error>> {
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CheckpointRequestOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::Running {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                let Some(active) = self.active.get(&execution) else {
                    return Ok(CheckpointRequestOutcome::NotCurrent);
                };
                if AttemptExecutionKey::new(active.request.lineage(), active.request.attempt())
                    != key
                {
                    return Err(LocalExecutorError::LedgerInvariant {
                        reason: "checkpoint request attempt does not match active reservation",
                    });
                }
                let next = AttemptRuntimeState::CheckpointRequested {
                    execution_basis,
                    daemon_epoch,
                    execution,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                if let Some(active) = self.active.get(&execution) {
                    active.checkpoint_request.request();
                }
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CheckpointRequestOutcome::Requested)
            }
            AttemptRuntimeState::CheckpointRequested {
                daemon_epoch,
                execution: current_execution,
                ..
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                if let Some(active) = self.active.get(&execution) {
                    active.checkpoint_request.request();
                }
                Ok(CheckpointRequestOutcome::AlreadyRequested)
            }
            AttemptRuntimeState::CheckpointPublishing {
                execution: current_execution,
                checkpoint,
                ..
            } if current_execution == execution => {
                Ok(CheckpointRequestOutcome::Publishing { checkpoint })
            }
            AttemptRuntimeState::Paused {
                execution: current_execution,
                checkpoint,
                ..
            } if current_execution == execution => {
                Ok(CheckpointRequestOutcome::Paused { checkpoint })
            }
            AttemptRuntimeState::Completed {
                execution: current_execution,
                observation,
                ..
            } if current_execution == execution => {
                Ok(CheckpointRequestOutcome::AlreadyCompleted { observation })
            }
            AttemptRuntimeState::Canceled {
                execution: current_execution,
                ..
            } if current_execution == execution => Ok(CheckpointRequestOutcome::AlreadyCanceled),
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => Ok(CheckpointRequestOutcome::NotCurrent),
        }
    }

    /// Durably reserves an exact-checkpoint root before immutable writes.
    ///
    /// This crate-private actor phase is called only after checkpoint metadata
    /// and VMState have been prepared without writes. It deliberately keeps
    /// the worker and resource reservation active until publication completes
    /// and the QEMU process is reaped.
    pub(crate) fn stage_checkpoint_publication(
        &mut self,
        queued: &QueuedAttempt,
        checkpoint: ExactCheckpointId,
    ) -> Result<CheckpointPublicationOutcome, LocalExecutorError<L::Error>> {
        self.validate_pending_basis(queued)?;
        let key = AttemptExecutionKey::new(queued.request.lineage(), queued.request.attempt());
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CheckpointPublicationOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                daemon_epoch,
                execution,
            } if daemon_epoch == self.daemon_epoch && execution == queued.execution => {
                let next = AttemptRuntimeState::CheckpointPublishing {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    checkpoint,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CheckpointPublicationOutcome::Staged)
            }
            AttemptRuntimeState::CheckpointPublishing {
                execution,
                checkpoint: current_checkpoint,
                ..
            } if execution == queued.execution && current_checkpoint == checkpoint => {
                Ok(CheckpointPublicationOutcome::AlreadyStaged)
            }
            AttemptRuntimeState::CheckpointPublishing { execution, .. }
                if execution == queued.execution =>
            {
                Err(LocalExecutorError::ConflictingCheckpoint)
            }
            AttemptRuntimeState::Paused {
                execution,
                checkpoint: current_checkpoint,
                ..
            } if execution == queued.execution && current_checkpoint == checkpoint => {
                self.mark_worker_finished(execution);
                self.release_active_if_present(execution)?;
                Ok(CheckpointPublicationOutcome::AlreadyPaused)
            }
            AttemptRuntimeState::Paused { execution, .. } if execution == queued.execution => {
                Err(LocalExecutorError::ConflictingCheckpoint)
            }
            AttemptRuntimeState::Completed { execution, .. }
            | AttemptRuntimeState::Canceled { execution, .. }
                if execution == queued.execution =>
            {
                self.mark_worker_finished(execution);
                self.release_active_if_present(execution)?;
                Ok(CheckpointPublicationOutcome::NotCurrent)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => Ok(CheckpointPublicationOutcome::NotCurrent),
        }
    }

    /// Promotes a fully published root and releases a physically stopped worker.
    pub(crate) fn complete_checkpoint(
        &mut self,
        queued: &QueuedAttempt,
        checkpoint: ExactCheckpointId,
    ) -> Result<CheckpointCompletionOutcome, LocalExecutorError<L::Error>> {
        self.validate_pending_basis(queued)?;
        let key = AttemptExecutionKey::new(queued.request.lineage(), queued.request.attempt());
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CheckpointCompletionOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::CheckpointPublishing {
                execution_basis,
                daemon_epoch,
                execution,
                checkpoint: current_checkpoint,
            } if execution == queued.execution => {
                if current_checkpoint != checkpoint {
                    return Err(LocalExecutorError::ConflictingCheckpoint);
                }
                let next = AttemptRuntimeState::Paused {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    checkpoint,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                self.mark_worker_finished(execution);
                self.release_active_if_present(execution)?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CheckpointCompletionOutcome::Paused)
            }
            AttemptRuntimeState::Paused {
                execution,
                checkpoint: current_checkpoint,
                ..
            } if execution == queued.execution && current_checkpoint == checkpoint => {
                self.mark_worker_finished(execution);
                self.release_active_if_present(execution)?;
                Ok(CheckpointCompletionOutcome::AlreadyPaused)
            }
            AttemptRuntimeState::Paused { execution, .. } if execution == queued.execution => {
                Err(LocalExecutorError::ConflictingCheckpoint)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => Ok(CheckpointCompletionOutcome::NotCurrent),
        }
    }

    /// Durably reserves the exact observation as an in-progress publication root.
    ///
    /// The operational ledger entry is established before immutable candidate
    /// bytes are written. GC therefore treats the observation closure as an
    /// in-progress root even across a daemon crash. The execution-model worker
    /// is considered physically stopped when this actor method is called.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for an invalid execution token, ledger
    /// failure, or a conflicting observation.
    pub fn stage_observation_publication(
        &mut self,
        queued: &QueuedAttempt,
        observation: ObservationId,
    ) -> Result<ObservationPublicationOutcome, LocalExecutorError<L::Error>> {
        self.validate_pending_basis(queued)?;
        self.mark_worker_finished(queued.execution);
        let key = AttemptExecutionKey::new(queued.request.lineage(), queued.request.attempt());
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(ObservationPublicationOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::Running {
                execution_basis,
                daemon_epoch,
                execution,
            }
            | AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                daemon_epoch,
                execution,
            } if execution_basis == queued.request.execution_basis_digest()
                && daemon_epoch == self.daemon_epoch
                && execution == queued.execution =>
            {
                let next = AttemptRuntimeState::Publishing {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    observation,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(ObservationPublicationOutcome::Staged)
            }
            AttemptRuntimeState::Publishing {
                execution: current_execution,
                observation: current_observation,
                ..
            } if current_execution == queued.execution && current_observation == observation => {
                Ok(ObservationPublicationOutcome::AlreadyStaged)
            }
            AttemptRuntimeState::Publishing {
                execution: current_execution,
                ..
            } if current_execution == queued.execution => {
                Err(LocalExecutorError::ConflictingCompletion)
            }
            AttemptRuntimeState::Completed {
                execution: current_execution,
                observation: current_observation,
                ..
            } if current_execution == queued.execution && current_observation == observation => {
                self.release_active_if_present(queued.execution)?;
                Ok(ObservationPublicationOutcome::AlreadyCompleted)
            }
            AttemptRuntimeState::Canceled {
                execution: current_execution,
                ..
            } if current_execution == queued.execution => {
                self.release_active_if_present(queued.execution)?;
                Ok(ObservationPublicationOutcome::Canceled)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => Ok(ObservationPublicationOutcome::NotCurrent),
        }
    }

    /// Stages an immutable observation and attempts durable completion reconciliation.
    ///
    /// A noncommitted ledger or validation failure retains the exact observation
    /// in bounded process-local state. The actor can retry it with
    /// [`Self::reconcile_pending_completion`] without re-running the guest.
    /// Commit-indeterminate ledger failures release capacity and clear the
    /// pending item after the ledger confirms the desired state.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for a conflicting staged observation,
    /// ledger failure, or semantic completion failure.
    pub fn stage_and_reconcile_completion(
        &mut self,
        queued: &QueuedAttempt,
        observation: ObservationId,
    ) -> Result<CompletionOutcome, LocalExecutorError<L::Error>> {
        let execution = queued.execution;
        let key = AttemptExecutionKey::new(queued.request.lineage(), queued.request.attempt());
        let pending = PendingCompletion { key, observation };
        if self
            .pending_completions
            .get(&execution)
            .is_some_and(|current| *current != pending)
        {
            return Err(LocalExecutorError::ConflictingCompletion);
        }
        if !self.pending_completions.contains_key(&execution) {
            self.validate_pending_basis(queued)?;
            self.require_pending_capacity()?;
        }
        self.mark_worker_finished(execution);
        self.pending_completions.insert(execution, pending);
        self.reconcile_pending_completion(execution)?
            .ok_or(LocalExecutorError::LedgerInvariant {
                reason: "staged completion disappeared before reconciliation",
            })
    }

    /// Retries one staged immutable observation without executing the guest again.
    ///
    /// Returns `Ok(None)` when no completion is staged for this execution.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] when durable or semantic completion
    /// reconciliation fails. A still-current failure leaves the item staged.
    pub fn reconcile_pending_completion(
        &mut self,
        execution: ExecutionId,
    ) -> Result<Option<CompletionOutcome>, LocalExecutorError<L::Error>> {
        let Some(pending) = self.pending_completions.get(&execution).copied() else {
            return Ok(None);
        };
        match self.complete_execution(pending.key, execution, pending.observation) {
            Ok(outcome) => {
                self.pending_completions.remove(&execution);
                Ok(Some(outcome))
            }
            Err(error) => {
                let retryable = matches!(
                    &error,
                    LocalExecutorError::Ledger(_)
                        | LocalExecutorError::CompletionValidation {
                            reason: CompletionValidationFailure::UnavailableInput,
                        }
                );
                if !retryable {
                    self.pending_completions.remove(&execution);
                    if self.active.contains_key(&execution) {
                        self.stage_cancellation(pending.key, execution)?;
                    }
                } else if !self.active.contains_key(&execution) {
                    // A compare-exchange error that nevertheless committed is
                    // confirmed by `complete_execution` releasing the active
                    // reservation; no retry remains necessary.
                    self.pending_completions.remove(&execution);
                }
                Err(error)
            }
        }
    }

    /// Stages a terminal worker stop and attempts durable cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for a conflicting stop basis or ledger
    /// failure. A noncommitted failure remains available to
    /// [`Self::reconcile_pending_cancellation`].
    pub fn stage_and_reconcile_cancellation(
        &mut self,
        queued: &QueuedAttempt,
    ) -> Result<CancellationOutcome, LocalExecutorError<L::Error>> {
        let execution = queued.execution;
        let key = AttemptExecutionKey::new(queued.request.lineage(), queued.request.attempt());
        if !self.pending_cancellations.contains_key(&execution) {
            self.validate_pending_basis(queued)?;
            self.require_pending_capacity()?;
        }
        self.mark_worker_finished(execution);
        self.stage_cancellation(key, execution)
    }

    fn stage_cancellation(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
    ) -> Result<CancellationOutcome, LocalExecutorError<L::Error>> {
        if self
            .pending_cancellations
            .get(&execution)
            .is_some_and(|current| *current != key)
        {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "execution has a conflicting staged cancellation basis",
            });
        }
        self.pending_cancellations.insert(execution, key);
        self.reconcile_pending_cancellation(execution)?
            .ok_or(LocalExecutorError::LedgerInvariant {
                reason: "staged cancellation disappeared before reconciliation",
            })
    }

    /// Retries one staged terminal worker stop without re-running the guest.
    ///
    /// Returns `Ok(None)` when no cancellation is staged for this execution.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] when ledger reconciliation fails. A
    /// still-current failure leaves the cancellation staged.
    pub fn reconcile_pending_cancellation(
        &mut self,
        execution: ExecutionId,
    ) -> Result<Option<CancellationOutcome>, LocalExecutorError<L::Error>> {
        let Some(key) = self.pending_cancellations.get(&execution).copied() else {
            return Ok(None);
        };
        match self.cancel_execution(key, execution) {
            Ok(outcome) => {
                self.pending_cancellations.remove(&execution);
                Ok(Some(outcome))
            }
            Err(error) => {
                if !self.active.contains_key(&execution) {
                    self.pending_cancellations.remove(&execution);
                }
                Err(error)
            }
        }
    }

    fn validate_pending_basis(
        &self,
        queued: &QueuedAttempt,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        let key = AttemptExecutionKey::new(queued.request.lineage(), queued.request.attempt());
        let basis = queued.request.execution_basis_digest();
        let active_matches = self.active.get(&queued.execution).is_some_and(|active| {
            active.request == queued.request
                && AttemptExecutionKey::new(active.request.lineage(), active.request.attempt())
                    == key
        });
        if active_matches {
            return Ok(());
        }
        let durable_matches = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?
            .is_some_and(|state| match state {
                AttemptRuntimeState::Running {
                    execution_basis,
                    daemon_epoch,
                    execution,
                }
                | AttemptRuntimeState::CheckpointRequested {
                    execution_basis,
                    daemon_epoch,
                    execution,
                }
                | AttemptRuntimeState::CheckpointPublishing {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    ..
                }
                | AttemptRuntimeState::Paused {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    ..
                }
                | AttemptRuntimeState::Publishing {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    ..
                }
                | AttemptRuntimeState::Completed {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    ..
                }
                | AttemptRuntimeState::Canceled {
                    execution_basis,
                    daemon_epoch,
                    execution,
                } => {
                    execution_basis == basis
                        && execution == queued.execution
                        && daemon_epoch == queued.request.daemon_epoch()
                        && daemon_epoch == self.daemon_epoch
                }
            });
        if !durable_matches {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "pending reconciliation has no exact execution reservation",
            });
        }
        Ok(())
    }

    fn require_pending_capacity(&self) -> Result<(), LocalExecutorError<L::Error>> {
        let pending = self
            .pending_completions
            .len()
            .checked_add(self.pending_cancellations.len())
            .ok_or(LocalExecutorError::LedgerInvariant {
                reason: "pending reconciliation count overflow",
            })?;
        let limit = usize::try_from(self.capacity.maximum_concurrent_executions).map_err(|_| {
            LocalExecutorError::LedgerInvariant {
                reason: "executor capacity does not fit process address space",
            }
        })?;
        if pending >= limit {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "pending reconciliation capacity exhausted",
            });
        }
        Ok(())
    }

    fn mark_worker_finished(&mut self, execution: ExecutionId) {
        if let Some(active) = self.active.get_mut(&execution) {
            active.worker_in_flight = false;
        }
    }

    /// Durably records a published observation and releases local capacity.
    ///
    /// The caller publishes and authenticates the immutable observation before
    /// invoking this method. If cancellation already won, the observation is
    /// not promoted to the attempt's completed runtime state.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for ledger failures, impossible
    /// single-writer state races, or a conflicting second observation.
    pub fn complete_execution(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        observation: ObservationId,
    ) -> Result<CompletionOutcome, LocalExecutorError<L::Error>> {
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CompletionOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::Completed {
                execution: current_execution,
                observation: current_observation,
                ..
            } if current_execution == execution && current_observation == observation => {
                self.release_active_if_present(execution)?;
                Ok(CompletionOutcome::AlreadyCompleted)
            }
            AttemptRuntimeState::Completed {
                execution: current_execution,
                ..
            } if current_execution == execution => Err(LocalExecutorError::ConflictingCompletion),
            AttemptRuntimeState::Canceled {
                execution: current_execution,
                ..
            } if current_execution == execution => {
                self.release_active_if_present(execution)?;
                Ok(CompletionOutcome::Canceled)
            }
            AttemptRuntimeState::Publishing {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
                observation: staged_observation,
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                if staged_observation != observation {
                    return Err(LocalExecutorError::ConflictingCompletion);
                }
                let Some(active) = self.active.get(&execution) else {
                    return Ok(CompletionOutcome::NotCurrent);
                };
                if AttemptExecutionKey::new(active.request.lineage(), active.request.attempt())
                    != key
                {
                    return Err(LocalExecutorError::LedgerInvariant {
                        reason: "active execution attempt mismatch",
                    });
                }
                self.validator
                    .validate_completion(&active.request, observation)
                    .map_err(|reason| LocalExecutorError::CompletionValidation { reason })?;
                let next = AttemptRuntimeState::Completed {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    observation,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                self.release_active_if_present(execution)?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CompletionOutcome::Completed)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => Ok(CompletionOutcome::NotCurrent),
        }
    }

    /// Durably accepts cancellation and releases local capacity.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for ledger failures or impossible
    /// single-writer state races.
    pub fn cancel_execution(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
    ) -> Result<CancellationOutcome, LocalExecutorError<L::Error>> {
        if let Some(active) = self.active.get(&execution)
            && AttemptExecutionKey::new(active.request.lineage(), active.request.attempt()) == key
        {
            active.cancellation.cancel();
        }
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CancellationOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::Completed {
                execution: current_execution,
                observation,
                ..
            } if current_execution == execution => {
                self.release_active_if_present(execution)?;
                Ok(CancellationOutcome::AlreadyCompleted { observation })
            }
            AttemptRuntimeState::Canceled {
                execution: current_execution,
                ..
            } if current_execution == execution => {
                self.release_active_if_idle(execution)?;
                Ok(CancellationOutcome::AlreadyCanceled)
            }
            AttemptRuntimeState::Running {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
            }
            | AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
            }
            | AttemptRuntimeState::CheckpointPublishing {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
                ..
            }
            | AttemptRuntimeState::Paused {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
                ..
            }
            | AttemptRuntimeState::Publishing {
                execution_basis,
                daemon_epoch,
                execution: current_execution,
                ..
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                let next = AttemptRuntimeState::Canceled {
                    execution_basis,
                    daemon_epoch,
                    execution,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                self.release_active_if_idle(execution)?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CancellationOutcome::Canceled)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => Ok(CancellationOutcome::NotCurrent),
        }
    }

    fn submit(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        match self.preflight_submit(request)? {
            SubmitPreflight::Resolved(response) => return Ok(response),
            SubmitPreflight::NeedsValidation => {}
        }
        let validation = self.validator.validate(request);
        self.submit_after_validation(request, validation)
    }

    fn assignment_response(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<Option<SubmitAttemptResponse>, LocalExecutorError<L::Error>> {
        let Some(record) = self
            .ledger
            .load_assignment(request.assignment())
            .map_err(LocalExecutorError::Ledger)?
        else {
            return Ok(None);
        };
        if record.request() == request {
            return Ok(Some(record.response().clone()));
        }
        self.response(
            request,
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::ConflictingAssignment,
            },
        )
        .map(Some)
    }

    fn submit_admitted(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        if !self.capacity.supports(request.resources()) {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                },
            );
        }

        let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
        let execution_basis = request.execution_basis_digest();
        let mut prior = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        match prior {
            Some(AttemptRuntimeState::CheckpointRequested {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
            })
            | Some(AttemptRuntimeState::CheckpointPublishing {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
                ..
            }) if current_basis == execution_basis
                && daemon_epoch == self.daemon_epoch
                && self.active.contains_key(&execution) =>
            {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyRunning { execution },
                );
            }
            Some(AttemptRuntimeState::Paused {
                execution_basis: current_basis,
                execution,
                checkpoint,
                ..
            }) if current_basis == execution_basis => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyPaused {
                        execution,
                        checkpoint,
                    },
                );
            }
            Some(
                requested @ AttemptRuntimeState::CheckpointRequested {
                    execution_basis: current_basis,
                    ..
                },
            ) if current_basis == execution_basis => {
                if !self.has_capacity(request.resources()) {
                    return self.persist_response(
                        request,
                        SubmitAttemptDisposition::Rejected {
                            reason: ExecutorRejection::Backpressure,
                        },
                    );
                }
                let recovery_execution = self.allocate_execution_id()?;
                let recovery = AttemptRuntimeState::CheckpointRequested {
                    execution_basis: current_basis,
                    daemon_epoch: self.daemon_epoch,
                    execution: recovery_execution,
                };
                let advance = self.advance_attempt(key, requested, Some(recovery))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    self.reserve_checkpoint_recovery(request, recovery_execution)?;
                    return Err(LocalExecutorError::Ledger(error));
                }
                let response = self.persist_response(
                    request,
                    SubmitAttemptDisposition::Accepted {
                        execution: recovery_execution,
                    },
                );
                self.reserve_checkpoint_recovery(request, recovery_execution)?;
                return response;
            }
            Some(
                publishing @ AttemptRuntimeState::CheckpointPublishing {
                    execution_basis: current_basis,
                    checkpoint,
                    ..
                },
            ) if current_basis == execution_basis => {
                if !self.has_capacity(request.resources()) {
                    return self.persist_response(
                        request,
                        SubmitAttemptDisposition::Rejected {
                            reason: ExecutorRejection::Backpressure,
                        },
                    );
                }
                let recovery_execution = self.allocate_execution_id()?;
                let recovery = AttemptRuntimeState::CheckpointPublishing {
                    execution_basis: current_basis,
                    daemon_epoch: self.daemon_epoch,
                    execution: recovery_execution,
                    checkpoint,
                };
                let advance = self.advance_attempt(key, publishing, Some(recovery))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    self.reserve_checkpoint_recovery(request, recovery_execution)?;
                    return Err(LocalExecutorError::Ledger(error));
                }
                let response = self.persist_response(
                    request,
                    SubmitAttemptDisposition::Accepted {
                        execution: recovery_execution,
                    },
                );
                self.reserve_checkpoint_recovery(request, recovery_execution)?;
                return response;
            }
            Some(AttemptRuntimeState::Publishing {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
                ..
            }) if current_basis == execution_basis
                && daemon_epoch == self.daemon_epoch
                && self.active.contains_key(&execution) =>
            {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyRunning { execution },
                );
            }
            Some(
                publishing @ AttemptRuntimeState::Publishing {
                    execution_basis: current_basis,
                    daemon_epoch,
                    execution,
                    observation,
                },
            ) if current_basis == execution_basis => {
                match self.validator.validate_completion(request, observation) {
                    Ok(()) => {
                        let completed = AttemptRuntimeState::Completed {
                            execution_basis: current_basis,
                            daemon_epoch,
                            execution,
                            observation,
                        };
                        let advance = self.advance_attempt(key, publishing, Some(completed))?;
                        if let AttemptAdvance::CommittedAfterError(error) = advance {
                            return Err(LocalExecutorError::Ledger(error));
                        }
                        self.release_active_if_present(execution)?;
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::AlreadyCompleted { observation },
                        );
                    }
                    Err(CompletionValidationFailure::UnavailableInput) => {
                        if !self.has_capacity(request.resources()) {
                            return self.persist_response(
                                request,
                                SubmitAttemptDisposition::Rejected {
                                    reason: ExecutorRejection::Backpressure,
                                },
                            );
                        }
                        let recovery_execution = self.allocate_execution_id()?;
                        let recovery = AttemptRuntimeState::Publishing {
                            execution_basis: current_basis,
                            daemon_epoch: self.daemon_epoch,
                            execution: recovery_execution,
                            observation,
                        };
                        let advance = self.advance_attempt(key, publishing, Some(recovery))?;
                        if let AttemptAdvance::CommittedAfterError(error) = advance {
                            self.reserve(request, recovery_execution)?;
                            return Err(LocalExecutorError::Ledger(error));
                        }
                        let response = self.persist_response(
                            request,
                            SubmitAttemptDisposition::Accepted {
                                execution: recovery_execution,
                            },
                        );
                        self.reserve(request, recovery_execution)?;
                        return response;
                    }
                    Err(CompletionValidationFailure::Unauthorized) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::Unauthorized,
                            },
                        );
                    }
                    Err(CompletionValidationFailure::Incompatible) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::Incompatible,
                            },
                        );
                    }
                }
            }
            Some(AttemptRuntimeState::Completed {
                execution_basis: current_basis,
                observation,
                ..
            }) if current_basis == execution_basis => {
                match self.validator.validate_completion(request, observation) {
                    Ok(()) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::AlreadyCompleted { observation },
                        );
                    }
                    Err(CompletionValidationFailure::UnavailableInput) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::UnavailableInput,
                            },
                        );
                    }
                    Err(CompletionValidationFailure::Unauthorized) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::Unauthorized,
                            },
                        );
                    }
                    Err(CompletionValidationFailure::Incompatible) => {
                        let advance = self.advance_attempt_optional(key, prior, None)?;
                        if let AttemptAdvance::CommittedAfterError(error) = advance {
                            return Err(LocalExecutorError::Ledger(error));
                        }
                        prior = None;
                    }
                }
            }
            Some(AttemptRuntimeState::Running {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
            })
            | Some(AttemptRuntimeState::Publishing {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
                ..
            }) if daemon_epoch == self.daemon_epoch
                && current_basis == execution_basis
                && self.active.contains_key(&execution) =>
            {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyRunning { execution },
                );
            }
            Some(AttemptRuntimeState::Running {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            })
            | Some(AttemptRuntimeState::Publishing {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            }) if daemon_epoch == self.daemon_epoch && current_basis != execution_basis => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Incompatible,
                    },
                );
            }
            Some(AttemptRuntimeState::CheckpointRequested {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            })
            | Some(AttemptRuntimeState::CheckpointPublishing {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            }) if daemon_epoch == self.daemon_epoch && current_basis != execution_basis => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Incompatible,
                    },
                );
            }
            Some(AttemptRuntimeState::CheckpointRequested { .. })
            | Some(AttemptRuntimeState::CheckpointPublishing { .. })
            | Some(AttemptRuntimeState::Paused { .. })
            | Some(AttemptRuntimeState::Completed { .. }) => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Incompatible,
                    },
                );
            }
            Some(AttemptRuntimeState::Running { .. })
            | Some(AttemptRuntimeState::Publishing { .. })
            | Some(AttemptRuntimeState::Canceled { .. })
            | None => {}
        }

        if !self.has_capacity(request.resources()) {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Backpressure,
                },
            );
        }

        let execution = self.allocate_execution_id()?;
        let running = AttemptRuntimeState::Running {
            execution_basis,
            daemon_epoch: self.daemon_epoch,
            execution,
        };
        let advance = self.advance_attempt_optional(key, prior, Some(running))?;
        if let AttemptAdvance::CommittedAfterError(error) = advance {
            self.reserve(request, execution)?;
            return Err(LocalExecutorError::Ledger(error));
        }
        let response =
            self.persist_response(request, SubmitAttemptDisposition::Accepted { execution });
        // State is durable before response publication. Even when publication
        // is indeterminate, retain and run the prepared work so a response that
        // did become visible can never name an execution the daemon abandoned.
        self.reserve(request, execution)?;
        response
    }

    fn persist_response(
        &mut self,
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        let response = self.response(request, disposition)?;
        let record = AssignmentRecord::new(request.clone(), response.clone())?;
        match self
            .ledger
            .publish_assignment(&record)
            .map_err(LocalExecutorError::Ledger)?
        {
            AssignmentPublish::Stored | AssignmentPublish::Existing => Ok(response),
            AssignmentPublish::Conflict => Err(LocalExecutorError::LedgerInvariant {
                reason: "assignment changed after absent lookup",
            }),
        }
    }

    fn response(
        &self,
        request: &SubmitAttemptRequest,
        disposition: SubmitAttemptDisposition,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        SubmitAttemptResponse::new(request, disposition).map_err(Into::into)
    }

    fn advance_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: AttemptRuntimeState,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptAdvance<L::Error>, LocalExecutorError<L::Error>> {
        self.advance_attempt_optional(key, Some(expected), next)
    }

    fn advance_attempt_optional(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptAdvance<L::Error>, LocalExecutorError<L::Error>> {
        let outcome = match self.ledger.compare_exchange_attempt(key, expected, next) {
            Ok(outcome) => outcome,
            Err(error) => {
                let observed = self
                    .ledger
                    .load_attempt(key)
                    .map_err(LocalExecutorError::Ledger)?;
                if observed == next {
                    return Ok(AttemptAdvance::CommittedAfterError(error));
                }
                if observed == expected {
                    return Err(LocalExecutorError::Ledger(error));
                }
                return Err(LocalExecutorError::LedgerInvariant {
                    reason: "attempt state changed while reconciling failed compare-exchange",
                });
            }
        };
        match outcome {
            AttemptStateCas::Advanced => Ok(AttemptAdvance::Committed),
            AttemptStateCas::Conflict { .. } => Err(LocalExecutorError::LedgerInvariant {
                reason: "attempt state changed under sole writer",
            }),
        }
    }

    fn has_capacity(&self, resources: AttemptResourceLimits) -> bool {
        u32::try_from(self.active.len()).is_ok_and(|active| {
            active < self.capacity.maximum_concurrent_executions
                && self
                    .used
                    .vcpus
                    .checked_add(resources.maximum_vcpus())
                    .is_some_and(|total| total <= self.capacity.maximum_vcpus)
                && self
                    .used
                    .resident_bytes
                    .checked_add(resources.maximum_resident_bytes())
                    .is_some_and(|total| total <= self.capacity.maximum_resident_bytes)
                && self
                    .used
                    .disk_bytes
                    .checked_add(resources.maximum_disk_bytes())
                    .is_some_and(|total| total <= self.capacity.maximum_disk_bytes)
        })
    }

    fn reserve(
        &mut self,
        request: &SubmitAttemptRequest,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        let resources = request.resources();
        let used = UsedCapacity {
            vcpus: self
                .used
                .vcpus
                .checked_add(resources.maximum_vcpus())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved vcpu accounting overflow",
                })?,
            resident_bytes: self
                .used
                .resident_bytes
                .checked_add(resources.maximum_resident_bytes())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved memory accounting overflow",
                })?,
            disk_bytes: self
                .used
                .disk_bytes
                .checked_add(resources.maximum_disk_bytes())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved disk accounting overflow",
                })?,
        };
        if self.active.contains_key(&execution) {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "execution identity was already active",
            });
        }
        self.active.insert(
            execution,
            ActiveExecution {
                request: request.clone(),
                cancellation: ExecutionCancellation::default(),
                checkpoint_request: ExecutionCheckpointRequest::default(),
                worker_in_flight: false,
            },
        );
        self.queued.push_back(execution);
        self.used = used;
        Ok(())
    }

    fn reserve_checkpoint_recovery(
        &mut self,
        request: &SubmitAttemptRequest,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        self.reserve(request, execution)?;
        let active = self
            .active
            .get(&execution)
            .ok_or(LocalExecutorError::LedgerInvariant {
                reason: "checkpoint recovery reservation disappeared",
            })?;
        active.checkpoint_request.request();
        Ok(())
    }

    fn release_active(
        &mut self,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        let Some(active) = self.active.get(&execution) else {
            return Ok(());
        };
        let resources = active.request.resources();
        let used = UsedCapacity {
            vcpus: self
                .used
                .vcpus
                .checked_sub(resources.maximum_vcpus())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved vcpu accounting underflow",
                })?,
            resident_bytes: self
                .used
                .resident_bytes
                .checked_sub(resources.maximum_resident_bytes())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved memory accounting underflow",
                })?,
            disk_bytes: self
                .used
                .disk_bytes
                .checked_sub(resources.maximum_disk_bytes())
                .ok_or(LocalExecutorError::LedgerInvariant {
                    reason: "reserved disk accounting underflow",
                })?,
        };
        if self.active.remove(&execution).is_none() {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "active execution disappeared during release",
            });
        }
        self.queued.retain(|queued| *queued != execution);
        self.used = used;
        Ok(())
    }

    fn release_active_if_present(
        &mut self,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        if self.active.contains_key(&execution) {
            self.release_active(execution)?;
        }
        Ok(())
    }

    fn release_active_if_idle(
        &mut self,
        execution: ExecutionId,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        if self
            .active
            .get(&execution)
            .is_some_and(|active| !active.worker_in_flight)
        {
            self.release_active(execution)?;
        }
        Ok(())
    }

    fn allocate_execution_id(&mut self) -> Result<ExecutionId, LocalExecutorError<L::Error>> {
        loop {
            self.next_execution_ordinal = self
                .next_execution_ordinal
                .checked_add(1)
                .ok_or(LocalExecutorError::ExecutionIdentityExhausted)?;
            let mut bytes = self.daemon_epoch.as_bytes();
            let suffix = u64::from_be_bytes(bytes[8..].try_into().map_err(|_| {
                LocalExecutorError::LedgerInvariant {
                    reason: "daemon epoch execution suffix width",
                }
            })?) ^ self.next_execution_ordinal;
            bytes[8..].copy_from_slice(&suffix.to_be_bytes());
            let Ok(execution) = ExecutionId::from_bytes(bytes) else {
                continue;
            };
            if !self.active.contains_key(&execution) {
                return Ok(execution);
            }
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
        let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
        let state = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let disposition = match state {
            Some(state)
                if state.daemon_epoch() == request.daemon_epoch()
                    && state.execution() == request.execution()
                    && state.execution_basis() == request.execution_basis() =>
            {
                match state {
                    AttemptRuntimeState::Running { .. }
                    | AttemptRuntimeState::Publishing { .. } => {
                        GetAttemptExecutionDisposition::Running
                    }
                    AttemptRuntimeState::CheckpointRequested { .. } => {
                        GetAttemptExecutionDisposition::CheckpointRequested
                    }
                    AttemptRuntimeState::CheckpointPublishing { checkpoint, .. } => {
                        GetAttemptExecutionDisposition::CheckpointPublishing { checkpoint }
                    }
                    AttemptRuntimeState::Paused { checkpoint, .. } => {
                        GetAttemptExecutionDisposition::Paused { checkpoint }
                    }
                    AttemptRuntimeState::Completed { observation, .. } => {
                        GetAttemptExecutionDisposition::Completed { observation }
                    }
                    AttemptRuntimeState::Canceled { .. } => {
                        GetAttemptExecutionDisposition::Canceled
                    }
                }
            }
            Some(_) | None => GetAttemptExecutionDisposition::NotCurrent,
        };
        GetAttemptExecutionResponse::new(request, disposition).map_err(Into::into)
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
        let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
        let state = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let exact = state.as_ref().is_some_and(|state| {
            state.daemon_epoch() == request.daemon_epoch()
                && state.execution() == request.execution()
                && state.execution_basis() == request.execution_basis()
        });
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
        CheckpointAttemptExecutionResponse::new(request, disposition).map_err(Into::into)
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
        let state = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let exact = state.as_ref().is_some_and(|state| {
            state.daemon_epoch() == request.daemon_epoch()
                && state.execution() == request.execution()
                && state.execution_basis() == request.execution_basis()
        });
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
        CancelAttemptExecutionResponse::new(request, disposition).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
