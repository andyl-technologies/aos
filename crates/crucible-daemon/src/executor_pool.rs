//! Fixed local attempt workers around the sole-writer executor supervisor.
//!
//! The pool shares only the short operational supervisor actor. Each linear
//! [`QueuedAttempt`] moves to exactly one worker thread; guest execution,
//! repository preflight, and immutable publication all happen after the actor
//! lock is released. Publication and ledger failures retain their phase token
//! and retry that phase without re-running modeled execution.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::executor_supervisor::LocalExecutionActivity;
use crucible_api::{
    ProductionExactCheckpointRetirement, retire_production_exact_checkpoint_catalog,
};
#[cfg(test)]
use crucible_campaign::CampaignExecutorPublicationGuard;
use crucible_campaign::{
    AttemptExecutionScope, CampaignExecutorStore, CampaignRepositoryGcExclusionGuard,
    CancelAttemptExecutionRequest, CancelAttemptExecutionResponse,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse, ExactCheckpointId,
    ExecutorCapabilityService, ExecutorCapacityReport, ExecutorControlService, ExecutorDescription,
    ExecutorRejection, ExecutorResumeService, ExecutorService, ExecutorStatusService,
    FindingExactPins, FindingExactRetention, FindingExactRetentionDisposition,
    FindingExactRetentionIncomplete, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, SubmitAttemptRequest,
    SubmitAttemptResponse, WatchExecutorCapacityRequest,
};

use crate::executor_supervisor::{AttemptCheckpointHandoff, ExecutionCheckpointHandoff};
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionDisposition, AttemptExecutionKey,
    AttemptExecutionReconciliationStep, AttemptResultPreparationError,
    AttemptResultRecoveryFailure, AttemptResultStageOutcome, AttemptRuntimeState,
    AttemptWorkerFailure, AttemptWorkerReconcileError, CapturedAttemptCheckpoint,
    CheckpointHandoffFailure, CheckpointPublicationOutcome, CheckpointResultAbortToken,
    CheckpointResultStageOutcome, CompletionValidationFailure, DirectoryPreparedResultJournal,
    ExactCheckpointStore, FindingReplayCaptureStore, HotCheckpointFallback, LocalAttemptWorker,
    LocalExecutorCapabilityService, LocalExecutorError, LocalExecutorSupervisor,
    PreparedAttemptCheckpoint, PreparedAttemptRecoveryOutcome, PreparedAttemptResult,
    PreparedAttemptWorkResult, PreparedCheckpointResult, PreparedFindingExactRetention,
    PreparedResultJournalError, PublishedAttemptResult, QueuedAttempt, StagedAttemptResult,
    abort_checkpoint_result, abort_prepared_attempt_result, abort_published_attempt_result,
    abort_staged_attempt_result, journal_prepared_attempt_result, prepare_attempt_result,
    publish_prepared_attempt_result, publish_staged_checkpoint_result, reconcile_attempt_failure,
    reconcile_published_attempt_result, reconcile_published_checkpoint_result,
    recover_prepared_attempt_result, retry_pending_attempt_result, retry_pending_checkpoint_result,
    stage_prepared_attempt_result, stage_prepared_checkpoint_result,
};

mod completion;
pub use completion::LocalExecutorPoolCompletion;
use completion::{PoolCompletionState, WorkerCompletion};

mod promotion;
pub use promotion::{
    LocalCheckpointPromotionWorker, MAX_LOCAL_CHECKPOINT_PROMOTION_QUEUE,
    MAX_LOCAL_CHECKPOINT_PROMOTION_WORKERS, ProductionCheckpointPromotionWorker,
};
use promotion::{PromotionQueue, promotion_worker_loop};

struct DisabledCheckpointPromotionWorker;

impl LocalCheckpointPromotionWorker for DisabledCheckpointPromotionWorker {
    type Error = ();

    fn prepare(
        &mut self,
        _work: crate::CheckpointPromotionRestartWork,
        _cancellation: crate::ExecutionCancellation,
    ) -> Result<crate::PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>>
    {
        Err(AttemptWorkerFailure::Terminal(()))
    }
}

/// Maximum execution threads accepted by one local executor pool.
pub const MAX_LOCAL_EXECUTOR_WORKERS: usize = 256;

const WORKER_RETRY_INTERVAL: Duration = Duration::from_millis(10);
pub(crate) const WORKER_SHUTDOWN_WAIT: Duration = Duration::from_secs(30);
const POOL_RUNNING: u8 = 0;
const POOL_SHUTTING_DOWN: u8 = 1;
const POOL_POISONED: u8 = 2;

/// Durable prepared-result location used by production semantic workers.
#[derive(Clone, Debug)]
pub(crate) struct PreparedResultJournalConfig {
    namespace: PathBuf,
    maximum_payload_bytes: usize,
    #[cfg(test)]
    before_journal: Option<Arc<PreparedResultJournalTestBarrier>>,
}

impl PreparedResultJournalConfig {
    pub(crate) fn new(namespace: PathBuf, maximum_payload_bytes: usize) -> Self {
        Self {
            namespace,
            maximum_payload_bytes,
            #[cfg(test)]
            before_journal: None,
        }
    }

    #[cfg(test)]
    fn with_before_journal_barrier(
        mut self,
        barrier: Arc<PreparedResultJournalTestBarrier>,
    ) -> Self {
        self.before_journal = Some(barrier);
        self
    }
}

#[cfg(test)]
#[derive(Debug)]
struct PreparedResultJournalTestBarrier {
    entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
impl PreparedResultJournalTestBarrier {
    fn wait(&self) {
        let Some(entered) = self.entered.lock().expect("journal barrier signal").take() else {
            return;
        };
        entered.send(()).expect("journal barrier observer");

        let (released, changed) = self.release.as_ref();
        let mut released = released.lock().expect("journal barrier release");
        while !*released {
            released = changed.wait(released).expect("journal barrier wake");
        }
    }
}

/// Receives exact roots only after the durable supervisor state is paused.
///
/// Implementations must provide bounded backpressure. Returning an error
/// poisons the pool because an exact checkpoint would otherwise become
/// invisible to its operational retention owner.
pub(crate) trait PausedCheckpointObserver: Send + Sync {
    fn checkpoint_paused(&self, checkpoint: ExactCheckpointId) -> Result<(), ()>;

    fn checkpoint_promoted(
        &self,
        _source: ExactCheckpointId,
        promoted: ExactCheckpointId,
    ) -> Result<(), ()> {
        self.checkpoint_paused(promoted)
    }
}

/// Cloneable checked component service backed by one fixed worker pool.
pub struct LocalExecutorPoolService<L, V> {
    shared: Arc<SharedExecutor<L, V>>,
}

/// Bounded process-owned executor activity captured under the actor mutex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalExecutorOperationalSnapshot {
    pub(crate) revision: u64,
    pub(crate) daemon_epoch: crucible_campaign::DaemonEpoch,
    pub(crate) activities: Vec<LocalExecutionActivity>,
}

impl<L, V> Clone for LocalExecutorPoolService<L, V> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<L, V> LocalExecutorPoolService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator + Send + Sync,
{
    /// Durably requests cancellation of one exact local execution.
    ///
    /// Capacity remains charged while its worker is physically in flight. The
    /// worker thread performs the matching exit acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool is poisoned, the supervisor lock is
    /// unavailable, or durable cancellation fails.
    pub fn cancel_execution(
        &self,
        key: AttemptExecutionKey,
        execution: crucible_campaign::ExecutionId,
    ) -> Result<crate::CancellationOutcome, LocalExecutorPoolServiceError<L::Error>> {
        let mut executor = self.shared.lock_executor()?;
        executor
            .supervisor_mut()
            .cancel_execution(key, execution)
            .map_err(LocalExecutorPoolServiceError::Supervisor)
    }

    /// Returns a fixed-size operational report without repository traversal.
    ///
    /// # Errors
    ///
    /// Returns an error when supervisor ownership is poisoned.
    pub fn report(
        &self,
    ) -> Result<LocalExecutorPoolReport, LocalExecutorPoolServiceError<L::Error>> {
        let executor = self.shared.lock_executor_read_only()?;
        Ok(self.shared.report(executor.supervisor()))
    }

    /// Copies process-owned execution activity under one short actor lock.
    pub(crate) fn operational_snapshot(
        &self,
    ) -> Result<LocalExecutorOperationalSnapshot, LocalExecutorPoolServiceError<L::Error>> {
        self.shared.require_running()?;
        let executor = self.shared.lock_executor_read_only()?;
        let revision = self.shared.ownership_revision.load(Ordering::Acquire);
        if revision == u64::MAX {
            return Err(LocalExecutorPoolServiceError::ObservationRevisionExhausted);
        }
        let supervisor = executor.supervisor();
        Ok(LocalExecutorOperationalSnapshot {
            revision,
            daemon_epoch: supervisor.daemon_epoch(),
            activities: supervisor.operational_activity_snapshot(),
        })
    }
}

impl<L, V> ExecutorService for LocalExecutorPoolService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator + Send + Sync,
{
    type Error = LocalExecutorPoolServiceError<L::Error>;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.shared.require_running()?;
        let preflight = {
            let mut executor = self.shared.lock_executor()?;
            executor
                .supervisor_mut()
                .preflight_submit(request)
                .map_err(LocalExecutorPoolServiceError::Supervisor)?
        };
        if let crate::executor_supervisor::SubmitPreflight::Resolved(response) = preflight {
            return Ok(response);
        }

        let validation = match catch_unwind(AssertUnwindSafe(|| {
            crate::executor_supervisor::ValidatedSubmitAdmission::validate(
                self.shared.validator.as_ref(),
                request,
            )
        })) {
            Ok(validation) => validation,
            Err(_) => {
                self.shared.poison();
                return Err(LocalExecutorPoolServiceError::WorkerPanicked);
            }
        };
        self.shared.require_running()?;
        let mut executor = self.shared.lock_executor()?;
        let response = executor
            .supervisor_mut()
            .submit_after_validation(request, validation)
            .map_err(LocalExecutorPoolServiceError::Supervisor)?;
        if executor.supervisor().queued_count() != 0 {
            self.shared.ready.notify_one();
        }
        Ok(response)
    }
}

impl<L, V> ExecutorCapabilityService for LocalExecutorPoolService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator + Send + Sync,
{
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
        self.shared.require_running()?;
        self.shared
            .lock_executor_read_only()?
            .describe_executor()
            .map_err(LocalExecutorPoolServiceError::Supervisor)
    }

    fn watch_capacity(
        &mut self,
        request: &WatchExecutorCapacityRequest,
    ) -> Result<ExecutorCapacityReport, Self::Error> {
        self.shared.require_running()?;
        self.shared
            .lock_executor()?
            .watch_capacity(request)
            .map_err(LocalExecutorPoolServiceError::Supervisor)
    }
}

impl<L, V> ExecutorStatusService for LocalExecutorPoolService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator + Send + Sync,
{
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.shared.require_running()?;
        self.shared
            .lock_executor_read_only()?
            .get_attempt_execution(request)
            .map_err(LocalExecutorPoolServiceError::Supervisor)
    }
}

impl<L, V> ExecutorControlService for LocalExecutorPoolService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator + Send + Sync,
{
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        self.shared.require_running()?;
        self.shared
            .lock_executor()?
            .checkpoint_attempt_execution(request)
            .map_err(LocalExecutorPoolServiceError::Supervisor)
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        self.shared.require_running()?;
        self.shared
            .lock_executor()?
            .cancel_attempt_execution(request)
            .map_err(LocalExecutorPoolServiceError::Supervisor)
    }
}

impl<L, V> ExecutorResumeService for LocalExecutorPoolService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator + Send + Sync,
{
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        self.shared.require_running()?;
        let assignment = request
            .assignment_request()
            .map_err(LocalExecutorError::from)
            .map_err(LocalExecutorPoolServiceError::Supervisor)?;
        let validation = match catch_unwind(AssertUnwindSafe(|| {
            self.shared
                .validator
                .validate(&assignment)
                .and_then(|()| self.shared.validator.validate_execution_scope(&assignment))
        })) {
            Ok(validation) => validation,
            Err(_) => {
                self.shared.poison();
                return Err(LocalExecutorPoolServiceError::WorkerPanicked);
            }
        };
        self.shared.require_running()?;
        let mut executor = self.shared.lock_executor()?;
        let response = executor
            .supervisor_mut()
            .resume_after_validation(request, validation)
            .map_err(LocalExecutorPoolServiceError::Supervisor)?;
        if executor.supervisor().queued_count() != 0 {
            self.shared.ready.notify_one();
        }
        Ok(response)
    }
}

/// Fixed owner of local execution threads and their shared supervisor actor.
pub struct LocalExecutorWorkerPool<L, V> {
    service: LocalExecutorPoolService<L, V>,
    workers: Vec<JoinHandle<()>>,
}

impl<L, V> LocalExecutorWorkerPool<L, V>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    /// Starts one fixed thread for every supplied worker implementation.
    ///
    /// The worker count is additionally bounded by the supervisor's configured
    /// execution-slot capacity. Exact captures are prepared and published
    /// through `checkpoints` after their worker session has reaped QEMU. No
    /// thread is created after the constructor returns.
    ///
    /// # Errors
    ///
    /// Returns an error for zero workers, more than 256 workers, more workers
    /// than execution slots, or an operating-system thread-spawn failure.
    pub fn start<W>(
        executor: LocalExecutorCapabilityService<L, V>,
        store: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        workers: Vec<W>,
    ) -> Result<Self, LocalExecutorPoolConfigError>
    where
        W: LocalAttemptWorker + Send + 'static,
    {
        Self::start_inner(
            executor,
            store,
            checkpoints,
            workers,
            Vec::<DisabledCheckpointPromotionWorker>::new(),
            None,
            None,
            None,
        )
    }

    /// Starts fixed semantic workers with one durable paused-root owner.
    pub(crate) fn start_with_checkpoint_observer<W>(
        executor: LocalExecutorCapabilityService<L, V>,
        store: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        workers: Vec<W>,
        checkpoint_observer: Arc<dyn PausedCheckpointObserver>,
        prepared_results: Option<PreparedResultJournalConfig>,
        hot_checkpoint_retention: Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>>,
    ) -> Result<Self, LocalExecutorPoolConfigError>
    where
        W: LocalAttemptWorker + Send + 'static,
    {
        Self::start_inner(
            executor,
            store,
            checkpoints,
            workers,
            Vec::<DisabledCheckpointPromotionWorker>::new(),
            Some(checkpoint_observer),
            prepared_results,
            hot_checkpoint_retention,
        )
    }

    /// Starts fixed semantic and paused-checkpoint promotion workers.
    ///
    /// Startup inventories compact raw/staged promotion records before any
    /// service handle is returned. Promotion workers run repository, QEMU, and
    /// immutable-store phases outside supervisor ownership and borrow the actor
    /// only for exact ledger transitions.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid semantic or promotion worker counts, more
    /// than 65,536 durable restart items, an unreadable restart inventory, or an
    /// operating-system thread-spawn failure.
    pub fn start_with_checkpoint_promotions<W, P>(
        executor: LocalExecutorCapabilityService<L, V>,
        store: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        workers: Vec<W>,
        promotion_workers: Vec<P>,
    ) -> Result<Self, LocalExecutorPoolConfigError>
    where
        W: LocalAttemptWorker + Send + 'static,
        P: LocalCheckpointPromotionWorker + Send + 'static,
    {
        if promotion_workers.is_empty() {
            return Err(LocalExecutorPoolConfigError::ZeroPromotionWorkers);
        }
        Self::start_inner(
            executor,
            store,
            checkpoints,
            workers,
            promotion_workers,
            None,
            None,
            None,
        )
    }

    /// Starts fixed semantic and promotion workers with one paused-root owner.
    // crucible-lint: allow rust-allow -- pool startup keeps each independently owned worker authority explicit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_with_checkpoint_promotions_and_observer<W, P>(
        executor: LocalExecutorCapabilityService<L, V>,
        store: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        workers: Vec<W>,
        promotion_workers: Vec<P>,
        checkpoint_observer: Arc<dyn PausedCheckpointObserver>,
        prepared_results: Option<PreparedResultJournalConfig>,
        hot_checkpoint_retention: Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>>,
    ) -> Result<Self, LocalExecutorPoolConfigError>
    where
        W: LocalAttemptWorker + Send + 'static,
        P: LocalCheckpointPromotionWorker + Send + 'static,
    {
        if promotion_workers.is_empty() {
            return Err(LocalExecutorPoolConfigError::ZeroPromotionWorkers);
        }
        Self::start_inner(
            executor,
            store,
            checkpoints,
            workers,
            promotion_workers,
            Some(checkpoint_observer),
            prepared_results,
            hot_checkpoint_retention,
        )
    }

    // crucible-lint: allow rust-allow -- the private constructor preserves the public startup boundaries without a second configuration model.
    #[allow(clippy::too_many_arguments)]
    fn start_inner<W, P>(
        executor: LocalExecutorCapabilityService<L, V>,
        store: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        workers: Vec<W>,
        promotion_workers: Vec<P>,
        checkpoint_observer: Option<Arc<dyn PausedCheckpointObserver>>,
        prepared_results: Option<PreparedResultJournalConfig>,
        hot_checkpoint_retention: Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>>,
    ) -> Result<Self, LocalExecutorPoolConfigError>
    where
        W: LocalAttemptWorker + Send + 'static,
        P: LocalCheckpointPromotionWorker + Send + 'static,
    {
        let worker_count = workers.len();
        if worker_count == 0 {
            return Err(LocalExecutorPoolConfigError::ZeroWorkers);
        }
        if worker_count > MAX_LOCAL_EXECUTOR_WORKERS {
            return Err(LocalExecutorPoolConfigError::TooManyWorkers);
        }
        let maximum_slots = usize::try_from(
            executor
                .supervisor()
                .capacity()
                .maximum_concurrent_executions(),
        )
        .map_err(|_| LocalExecutorPoolConfigError::WorkerCountExceedsSlots)?;
        if worker_count > maximum_slots {
            return Err(LocalExecutorPoolConfigError::WorkerCountExceedsSlots);
        }

        let promotion_worker_count = promotion_workers.len();
        if promotion_worker_count > MAX_LOCAL_CHECKPOINT_PROMOTION_WORKERS {
            return Err(LocalExecutorPoolConfigError::TooManyPromotionWorkers);
        }
        if promotion_worker_count > maximum_slots {
            return Err(LocalExecutorPoolConfigError::PromotionWorkerCountExceedsSlots);
        }

        let mut restart_work = Vec::new();
        let mut restart_overflow = false;
        if promotion_worker_count != 0 {
            executor
                .supervisor()
                .visit_checkpoint_promotion_restart_work(&mut |work| {
                    if restart_work.len() < MAX_LOCAL_CHECKPOINT_PROMOTION_QUEUE {
                        restart_work.push(work);
                    } else {
                        restart_overflow = true;
                    }
                })
                .map_err(|_| LocalExecutorPoolConfigError::PromotionRestartInventory)?;
            if restart_overflow {
                return Err(LocalExecutorPoolConfigError::TooManyPromotionRestarts);
            }
        }

        let shared = Arc::new(SharedExecutor::new(
            executor,
            checkpoints,
            worker_count,
            promotion_worker_count,
            restart_work,
            checkpoint_observer,
            prepared_results,
            hot_checkpoint_retention,
        ));
        let total_workers = worker_count
            .checked_add(promotion_worker_count)
            .ok_or(LocalExecutorPoolConfigError::TooManyPromotionWorkers)?;
        let mut joins: Vec<JoinHandle<()>> = Vec::with_capacity(total_workers);
        for (slot, worker) in workers.into_iter().enumerate() {
            let worker_shared = Arc::clone(&shared);
            let worker_store = store.clone();
            let join = match thread::Builder::new()
                .name(format!("crucible-executor-{slot}"))
                .spawn(move || {
                    let _completion = WorkerCompletion::new(&worker_shared.completion);
                    worker_loop(worker_shared, worker_store, worker);
                }) {
                Ok(join) => join,
                Err(source) => {
                    shared.request_shutdown();
                    // Already-started workers own their exact state. A spawn
                    // failure must not wait forever on their reconciliation.
                    drop(joins);
                    return Err(LocalExecutorPoolConfigError::Spawn { source });
                }
            };
            joins.push(join);
        }
        for (slot, worker) in promotion_workers.into_iter().enumerate() {
            let worker_shared = Arc::clone(&shared);
            let join = match thread::Builder::new()
                .name(format!("crucible-checkpoint-promotion-{slot}"))
                .spawn(move || {
                    let _completion = WorkerCompletion::new(&worker_shared.completion);
                    promotion_worker_loop(worker_shared, worker);
                }) {
                Ok(join) => join,
                Err(source) => {
                    shared.request_shutdown();
                    drop(joins);
                    return Err(LocalExecutorPoolConfigError::Spawn { source });
                }
            };
            joins.push(join);
        }

        Ok(Self {
            service: LocalExecutorPoolService { shared },
            workers: joins,
        })
    }

    /// Returns a cloneable direct/RPC-compatible executor component service.
    #[must_use]
    pub fn service(&self) -> LocalExecutorPoolService<L, V> {
        self.service.clone()
    }

    /// Returns a cloneable sticky shutdown authority for this pool incarnation.
    #[must_use]
    pub fn shutdown_handle(&self) -> LocalExecutorPoolShutdown<L, V> {
        LocalExecutorPoolShutdown {
            shared: Arc::clone(&self.service.shared),
        }
    }

    /// Returns a cloneable signal that completes after every worker exits.
    #[must_use]
    pub fn completion_handle(&self) -> LocalExecutorPoolCompletion {
        LocalExecutorPoolCompletion {
            state: Arc::clone(&self.service.shared.completion),
        }
    }

    /// Signals all active executions and prevents new assignment admission.
    pub fn request_shutdown(&self) {
        self.service.shared.request_shutdown();
    }

    /// Requests shutdown and waits up to thirty seconds for worker cleanup.
    ///
    /// A conforming execution model observes cancellation during every bounded
    /// operational quantum. Unfinished workers retain their supervisor, store,
    /// and exact reconciliation tokens after the wait expires. No reservation
    /// is released merely because the caller stopped waiting.
    ///
    /// # Errors
    ///
    /// Returns an error when a worker thread escaped the pool's panic boundary
    /// or a caught worker panic poisoned this executor incarnation. Returns
    /// [`LocalExecutorPoolShutdownError::CleanupPending`] when cleanup remains
    /// in flight or a worker has entered fail-closed quarantine.
    pub fn shutdown_and_join(
        self,
    ) -> Result<LocalExecutorPoolReport, LocalExecutorPoolShutdownError> {
        self.shutdown_and_join_with_timeout(WORKER_SHUTDOWN_WAIT)
    }

    pub(crate) fn shutdown_and_join_with_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<LocalExecutorPoolReport, LocalExecutorPoolShutdownError> {
        self.request_shutdown();
        if !self.service.shared.completion.wait_for_cleanup(timeout) {
            return Err(LocalExecutorPoolShutdownError::CleanupPending);
        }
        let mut outer_panic = false;
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                outer_panic = true;
            }
        }
        if outer_panic {
            return Err(LocalExecutorPoolShutdownError::ThreadPanicked);
        }
        let state = self.service.shared.state.load(Ordering::Acquire);
        if state == POOL_POISONED {
            return Err(LocalExecutorPoolShutdownError::WorkerPanicked);
        }
        let executor = self
            .service
            .shared
            .executor
            .lock()
            .map_err(|_| LocalExecutorPoolShutdownError::SupervisorPoisoned)?;
        Ok(self.service.shared.report(executor.supervisor()))
    }
}

/// Cloneable sticky shutdown authority for one local executor worker pool.
pub struct LocalExecutorPoolShutdown<L, V> {
    shared: Arc<SharedExecutor<L, V>>,
}

impl<L, V> Clone for LocalExecutorPoolShutdown<L, V> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<L, V> LocalExecutorPoolShutdown<L, V> {
    /// Signals every active execution and prevents new assignment admission.
    pub fn shutdown(&self) {
        self.shared.request_shutdown();
    }

    /// Returns whether this pool has entered a terminal lifecycle state.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) != POOL_RUNNING
    }
}

impl<L, V> Drop for LocalExecutorWorkerPool<L, V> {
    fn drop(&mut self) {
        self.service.shared.request_shutdown();
        // Dropping a JoinHandle detaches without dropping the shared supervisor.
        // Each thread retains the Arc and exact reconciliation token until its
        // cancellation-aware worker exits.
        self.workers.clear();
    }
}

/// Invalid fixed worker-pool construction.
#[derive(Debug, thiserror::Error)]
pub enum LocalExecutorPoolConfigError {
    /// No execution can make progress without a worker.
    #[error("local executor worker count must be nonzero")]
    ZeroWorkers,
    /// The fixed process-wide safety bound was exceeded.
    #[error("local executor worker count exceeds 256")]
    TooManyWorkers,
    /// More workers were supplied than the supervisor can admit.
    #[error("local executor worker count exceeds configured execution slots")]
    WorkerCountExceedsSlots,
    /// An explicit promotion-enabled pool supplied no promotion worker.
    #[error("local executor checkpoint-promotion worker count is zero")]
    ZeroPromotionWorkers,
    /// The fixed process-wide promotion-thread safety bound was exceeded.
    #[error("local executor checkpoint-promotion worker count exceeds 256")]
    TooManyPromotionWorkers,
    /// More promotion workers were supplied than execution slots.
    #[error("local executor checkpoint-promotion worker count exceeds configured execution slots")]
    PromotionWorkerCountExceedsSlots,
    /// Durable attempt-state enumeration failed during promotion startup.
    #[error("local executor checkpoint-promotion restart inventory is unavailable")]
    PromotionRestartInventory,
    /// Compact durable restart work exceeded the fixed process-local queue bound.
    #[error("local executor checkpoint-promotion restart inventory exceeds 65536 items")]
    TooManyPromotionRestarts,
    /// Durable attempt-state enumeration failed during prepared-result cleanup.
    #[error("local executor prepared-result restart inventory is unavailable")]
    PreparedResultRestartInventory,
    /// A stable prepared-result journal could not be authenticated or removed.
    #[error("local executor stable prepared-result cleanup failed")]
    PreparedResultCleanup {
        /// Exact durable journal failure.
        #[source]
        source: PreparedResultJournalError,
    },
    /// A completed ledger result does not match its prepared-result journal.
    #[error("local executor completed result differs from its prepared-result journal")]
    PreparedResultCompletionMismatch,
    /// A completed immutable closure could not be authenticated before journal removal.
    #[error(
        "local executor completed result is unavailable or incompatible during journal cleanup"
    )]
    PreparedResultCompletionValidation {
        /// Stable repository-backed validation reason.
        reason: CompletionValidationFailure,
    },
    /// The operating system refused to create one fixed worker.
    #[error("local executor worker thread could not be created")]
    Spawn {
        /// Operating-system thread creation failure.
        source: io::Error,
    },
}

/// Checked component-service failure from a local worker pool.
#[derive(Debug, thiserror::Error)]
pub enum LocalExecutorPoolServiceError<E> {
    /// The pool has begun terminal shutdown.
    #[error("local executor worker pool is shutting down")]
    ShuttingDown,
    /// A worker invariant panic poisoned this executor incarnation.
    #[error("local executor worker panicked")]
    WorkerPanicked,
    /// Shared supervisor ownership was poisoned.
    #[error("local executor supervisor lock was poisoned")]
    SupervisorPoisoned,
    /// The monotone status-observation revision can no longer advance.
    #[error("local executor status observation revision is exhausted")]
    ObservationRevisionExhausted,
    /// The sole-writer supervisor rejected or could not persist the operation.
    #[error("local executor supervisor operation failed")]
    Supervisor(LocalExecutorError<E>),
}

/// Terminal failure while joining a fixed worker pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LocalExecutorPoolShutdownError {
    /// Workers retain unresolved resources after the bounded cleanup wait.
    #[error(
        "local executor cleanup is pending; worker resources and endpoint ownership remain retained"
    )]
    CleanupPending,
    /// A worker panicked outside the pool's guarded model call.
    #[error("local executor worker thread panicked")]
    ThreadPanicked,
    /// A caught model/worker panic poisoned the executor incarnation.
    #[error("local executor worker panicked")]
    WorkerPanicked,
    /// Shared supervisor ownership was poisoned.
    #[error("local executor supervisor lock was poisoned")]
    SupervisorPoisoned,
}

/// Bounded operational counters for one local executor pool incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalExecutorPoolReport {
    workers: usize,
    promotion_workers: usize,
    active: usize,
    queued: usize,
    promotions_active: usize,
    promotions_queued: usize,
    executions: u64,
    retry_requeues: u64,
    publication_retries: u64,
    reconciled: u64,
    discarded: u64,
    checkpoints_paused: u64,
    checkpoints_discarded: u64,
    promotion_retries: u64,
    promotions_reconciled: u64,
    promotions_discarded: u64,
    promotion_failures: u64,
    terminal_stops: u64,
    worker_panics: u64,
}

impl LocalExecutorPoolReport {
    /// Returns the fixed number of worker threads created at startup.
    #[must_use]
    pub const fn workers(self) -> usize {
        self.workers
    }

    /// Returns the fixed number of checkpoint-promotion threads.
    #[must_use]
    pub const fn promotion_workers(self) -> usize {
        self.promotion_workers
    }

    /// Returns exact currently charged supervisor reservations.
    #[must_use]
    pub const fn active(self) -> usize {
        self.active
    }

    /// Returns accepted executions not yet taken by a worker.
    #[must_use]
    pub const fn queued(self) -> usize {
        self.queued
    }

    /// Returns replay-oracle comparisons currently owned by promotion workers.
    #[must_use]
    pub const fn promotions_active(self) -> usize {
        self.promotions_active
    }

    /// Returns compact raw/staged promotion phases awaiting a fixed worker.
    #[must_use]
    pub const fn promotions_queued(self) -> usize {
        self.promotions_queued
    }

    /// Returns worker executions begun by this pool incarnation.
    #[must_use]
    pub const fn executions(self) -> u64 {
        self.executions
    }

    /// Returns retryable worker failures requeued without capacity growth.
    #[must_use]
    pub const fn retry_requeues(self) -> u64 {
        self.retry_requeues
    }

    /// Returns storage or ledger phase retries that did not rerun the guest.
    #[must_use]
    pub const fn publication_retries(self) -> u64 {
        self.publication_retries
    }

    /// Returns published candidates reconciled as durable completions.
    #[must_use]
    pub const fn reconciled(self) -> u64 {
        self.reconciled
    }

    /// Returns candidates discarded because cancellation or staleness won.
    #[must_use]
    pub const fn discarded(self) -> u64 {
        self.discarded
    }

    /// Returns exact checkpoints reconciled as durable paused executions.
    #[must_use]
    pub const fn checkpoints_paused(self) -> u64 {
        self.checkpoints_paused
    }

    /// Returns captured checkpoints discarded because another outcome won.
    #[must_use]
    pub const fn checkpoints_discarded(self) -> u64 {
        self.checkpoints_discarded
    }

    /// Returns transient promotion phase retries that did not rerun an attempt.
    #[must_use]
    pub const fn promotion_retries(self) -> u64 {
        self.promotion_retries
    }

    /// Returns promoted paused roots committed by fixed promotion workers.
    #[must_use]
    pub const fn promotions_reconciled(self) -> u64 {
        self.promotions_reconciled
    }

    /// Returns stale or deliberately reverted promotion phases.
    #[must_use]
    pub const fn promotions_discarded(self) -> u64 {
        self.promotions_discarded
    }

    /// Returns stable promotion preparation, publication, or ledger failures.
    #[must_use]
    pub const fn promotion_failures(self) -> u64 {
        self.promotion_failures
    }

    /// Returns canceled or terminal worker results durably stopped.
    #[must_use]
    pub const fn terminal_stops(self) -> u64 {
        self.terminal_stops
    }

    /// Returns caught worker invariant panics.
    #[must_use]
    pub const fn worker_panics(self) -> u64 {
        self.worker_panics
    }
}

struct SharedExecutor<L, V> {
    executor: Mutex<LocalExecutorCapabilityService<L, V>>,
    validator: Arc<V>,
    checkpoints: Arc<ExactCheckpointStore>,
    ready: Condvar,
    promotions: PromotionQueue,
    state: AtomicU8,
    ownership_revision: AtomicU64,
    worker_count: usize,
    promotion_worker_count: usize,
    checkpoint_observer: Option<Arc<dyn PausedCheckpointObserver>>,
    prepared_results: Option<PreparedResultJournalConfig>,
    hot_checkpoint_retention: Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>>,
    completion: Arc<PoolCompletionState>,
    counters: PoolCounters,
}

impl<L, V> SharedExecutor<L, V> {
    // crucible-lint: allow rust-allow -- shared state construction keeps worker counts and optional publication authorities explicit.
    #[allow(clippy::too_many_arguments)]
    fn new(
        executor: LocalExecutorCapabilityService<L, V>,
        checkpoints: Arc<ExactCheckpointStore>,
        worker_count: usize,
        promotion_worker_count: usize,
        restart_work: Vec<crate::CheckpointPromotionRestartWork>,
        checkpoint_observer: Option<Arc<dyn PausedCheckpointObserver>>,
        prepared_results: Option<PreparedResultJournalConfig>,
        hot_checkpoint_retention: Option<Arc<dyn crate::HotCheckpointFallbackRetentionAdmin>>,
    ) -> Self {
        let validator = executor.supervisor().admission_validator();
        Self {
            executor: Mutex::new(executor),
            validator,
            checkpoints,
            ready: Condvar::new(),
            promotions: PromotionQueue::from_restart_work(restart_work),
            state: AtomicU8::new(POOL_RUNNING),
            ownership_revision: AtomicU64::new(0),
            worker_count,
            promotion_worker_count,
            checkpoint_observer,
            prepared_results,
            hot_checkpoint_retention,
            completion: Arc::new(PoolCompletionState::new(
                worker_count.saturating_add(promotion_worker_count),
            )),
            counters: PoolCounters::default(),
        }
    }

    fn require_running<E>(&self) -> Result<(), LocalExecutorPoolServiceError<E>> {
        match self.state.load(Ordering::Acquire) {
            POOL_RUNNING => Ok(()),
            POOL_SHUTTING_DOWN => Err(LocalExecutorPoolServiceError::ShuttingDown),
            POOL_POISONED => Err(LocalExecutorPoolServiceError::WorkerPanicked),
            _ => Err(LocalExecutorPoolServiceError::WorkerPanicked),
        }
    }

    fn lock_executor(
        &self,
    ) -> Result<
        MutexGuard<'_, LocalExecutorCapabilityService<L, V>>,
        LocalExecutorPoolServiceError<L::Error>,
    >
    where
        L: AssignmentLedger,
    {
        match self.executor.lock() {
            Ok(executor) => {
                self.bump_ownership_revision();
                Ok(executor)
            }
            Err(poisoned) => {
                drop(poisoned.into_inner());
                self.fail_closed();
                Err(LocalExecutorPoolServiceError::SupervisorPoisoned)
            }
        }
    }

    fn lock_executor_read_only(
        &self,
    ) -> Result<
        MutexGuard<'_, LocalExecutorCapabilityService<L, V>>,
        LocalExecutorPoolServiceError<L::Error>,
    >
    where
        L: AssignmentLedger,
    {
        match self.executor.lock() {
            Ok(executor) => Ok(executor),
            Err(poisoned) => {
                drop(poisoned.into_inner());
                self.fail_closed();
                Err(LocalExecutorPoolServiceError::SupervisorPoisoned)
            }
        }
    }

    fn bump_ownership_revision(&self) {
        let _ =
            self.ownership_revision
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |revision| {
                    revision.checked_add(1)
                });
    }

    fn request_shutdown(&self) {
        let _ = self.state.compare_exchange(
            POOL_RUNNING,
            POOL_SHUTTING_DOWN,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.completion.signal_stopping();
        match self.executor.lock() {
            Ok(executor) => {
                self.bump_ownership_revision();
                executor.supervisor().signal_all_active_cancellation();
            }
            Err(poisoned) => poisoned
                .into_inner()
                .supervisor()
                .signal_all_active_cancellation(),
        }
        self.ready.notify_all();
        self.promotions.shutdown();
    }

    fn poison(&self) {
        increment(&self.counters.worker_panics);
        self.fail_closed();
    }

    fn fail_closed(&self) {
        self.state.store(POOL_POISONED, Ordering::Release);
        self.completion.signal_stopping();
        match self.executor.lock() {
            Ok(executor) => {
                self.bump_ownership_revision();
                executor.supervisor().signal_all_active_cancellation();
            }
            Err(poisoned) => poisoned
                .into_inner()
                .supervisor()
                .signal_all_active_cancellation(),
        }
        self.ready.notify_all();
        self.promotions.shutdown();
    }

    fn report(&self, supervisor: &LocalExecutorSupervisor<L, V>) -> LocalExecutorPoolReport {
        LocalExecutorPoolReport {
            workers: self.worker_count,
            promotion_workers: self.promotion_worker_count,
            active: supervisor.active_count(),
            queued: supervisor.queued_count(),
            promotions_active: self.promotions.active_count(),
            promotions_queued: self.promotions.pending_count(),
            executions: self.counters.executions.load(Ordering::Relaxed),
            retry_requeues: self.counters.retry_requeues.load(Ordering::Relaxed),
            publication_retries: self.counters.publication_retries.load(Ordering::Relaxed),
            reconciled: self.counters.reconciled.load(Ordering::Relaxed),
            discarded: self.counters.discarded.load(Ordering::Relaxed),
            checkpoints_paused: self.counters.checkpoints_paused.load(Ordering::Relaxed),
            checkpoints_discarded: self.counters.checkpoints_discarded.load(Ordering::Relaxed),
            promotion_retries: self.counters.promotion_retries.load(Ordering::Relaxed),
            promotions_reconciled: self.counters.promotions_reconciled.load(Ordering::Relaxed),
            promotions_discarded: self.counters.promotions_discarded.load(Ordering::Relaxed),
            promotion_failures: self.counters.promotion_failures.load(Ordering::Relaxed),
            terminal_stops: self.counters.terminal_stops.load(Ordering::Relaxed),
            worker_panics: self.counters.worker_panics.load(Ordering::Relaxed),
        }
    }
}

struct PoolCheckpointHandoff<L, V> {
    shared: Weak<SharedExecutor<L, V>>,
    queued: QueuedAttempt,
}

impl<L, V> std::fmt::Debug for PoolCheckpointHandoff<L, V> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoolCheckpointHandoff")
            .field("execution", &self.queued.execution())
            .field("attempt", &self.queued.request().attempt())
            .finish_non_exhaustive()
    }
}

impl<L, V> AttemptCheckpointHandoff for PoolCheckpointHandoff<L, V>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    fn prepare_and_stage(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure> {
        let Some(shared) = self.shared.upgrade() else {
            return Err(CheckpointHandoffFailure::Terminal);
        };
        let prepared = loop {
            if self.queued.cancellation().is_canceled() {
                return Err(CheckpointHandoffFailure::Canceled);
            }
            match shared
                .checkpoints
                .prepare_attempt_checkpoint_with_cancellation(
                    capture.reopenable_copy(),
                    self.queued.cancellation(),
                ) {
                Ok(prepared) => break prepared,
                Err(crate::ExactCheckpointStoreError::Canceled) => {
                    return Err(CheckpointHandoffFailure::Canceled);
                }
                Err(source) if source.is_retryable() => {
                    increment(&shared.counters.publication_retries);
                    thread::sleep(WORKER_RETRY_INTERVAL);
                }
                Err(_) => return Err(CheckpointHandoffFailure::Terminal),
            }
        };

        loop {
            if self.queued.cancellation().is_canceled() {
                return Err(CheckpointHandoffFailure::Canceled);
            }
            let root = prepared.root();
            let mut executor = match shared.executor.lock() {
                Ok(executor) => executor,
                Err(poisoned) => {
                    drop(poisoned.into_inner());
                    shared.fail_closed();
                    return Err(CheckpointHandoffFailure::Terminal);
                }
            };
            shared.bump_ownership_revision();
            match executor
                .supervisor_mut()
                .stage_checkpoint_publication_before_teardown(&self.queued, root)
            {
                Ok(CheckpointPublicationOutcome::Staged)
                | Ok(CheckpointPublicationOutcome::AlreadyStaged)
                | Ok(CheckpointPublicationOutcome::AlreadyPaused) => return Ok(prepared),
                Ok(CheckpointPublicationOutcome::NotCurrent)
                    if self.queued.cancellation().is_canceled() =>
                {
                    return Err(CheckpointHandoffFailure::Canceled);
                }
                Ok(CheckpointPublicationOutcome::NotCurrent) => {
                    return Err(CheckpointHandoffFailure::Terminal);
                }
                Err(source) if supervisor_error_is_retryable(&source) => {
                    increment(&shared.counters.publication_retries);
                    drop(executor);
                    thread::sleep(WORKER_RETRY_INTERVAL);
                }
                Err(_) => return Err(CheckpointHandoffFailure::Terminal),
            }
        }
    }
}

#[derive(Default)]
struct PoolCounters {
    executions: AtomicU64,
    retry_requeues: AtomicU64,
    publication_retries: AtomicU64,
    reconciled: AtomicU64,
    discarded: AtomicU64,
    checkpoints_paused: AtomicU64,
    checkpoints_discarded: AtomicU64,
    promotion_retries: AtomicU64,
    promotions_reconciled: AtomicU64,
    promotions_discarded: AtomicU64,
    promotion_failures: AtomicU64,
    terminal_stops: AtomicU64,
    worker_panics: AtomicU64,
}

/// Removes restart journals whose durable ledger state is already terminal.
///
/// The caller supplies the repository GC guard acquired before the ledger's
/// lifetime writer fence. Packaged startup invokes this before any worker or
/// maintenance thread exists, so the order is repository GC exclusion, ledger
/// exclusion, then this module's nonblocking per-key journal lock.
pub(crate) fn reconcile_stable_prepared_result_journals<L, V>(
    ledger: &L,
    validator: &V,
    config: &PreparedResultJournalConfig,
    _gc_exclusion: &CampaignRepositoryGcExclusionGuard<'_>,
) -> Result<(), LocalExecutorPoolConfigError>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let mut cleanup_failure = None;
    ledger
        .visit_attempt_states(&mut |key, state| {
            if cleanup_failure.is_some()
                || key.scope() != AttemptExecutionScope::Semantic
                || !matches!(
                    state,
                    AttemptRuntimeState::Completed { .. }
                        | AttemptRuntimeState::Canceled { .. }
                        | AttemptRuntimeState::TerminalFailure { .. }
                )
            {
                return;
            }

            let present = DirectoryPreparedResultJournal::artifacts_present(&config.namespace, key);
            match present {
                Ok(false) => return,
                Ok(true) => {}
                Err(source) => {
                    cleanup_failure =
                        Some(LocalExecutorPoolConfigError::PreparedResultCleanup { source });
                    return;
                }
            }
            cleanup_failure =
                reconcile_one_stable_prepared_result(validator, config, key, state).err();
        })
        .map_err(|_| LocalExecutorPoolConfigError::PreparedResultRestartInventory)?;

    cleanup_failure.map_or(Ok(()), Err)
}

fn reconcile_one_stable_prepared_result<V>(
    validator: &V,
    config: &PreparedResultJournalConfig,
    key: AttemptExecutionKey,
    state: AttemptRuntimeState,
) -> Result<(), LocalExecutorPoolConfigError>
where
    V: AttemptAdmissionValidator,
{
    match DirectoryPreparedResultJournal::open_for_recovery(
        &config.namespace,
        key,
        config.maximum_payload_bytes,
    ) {
        Ok(Some(journal)) => {
            validate_completed_journal(validator, key, state, &journal)?;
            journal
                .remove()
                .map_err(|source| LocalExecutorPoolConfigError::PreparedResultCleanup { source })
        }
        Ok(None) => Ok(()),
        Err(PreparedResultJournalError::RecoveryRequired) => {
            validate_completed_ledger_result(validator, key, state)?;
            DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
                &config.namespace,
                key,
            )
            .map(|_| ())
            .map_err(|source| LocalExecutorPoolConfigError::PreparedResultCleanup { source })
        }
        Err(source) => Err(LocalExecutorPoolConfigError::PreparedResultCleanup { source }),
    }
}

fn validate_completed_journal<V>(
    validator: &V,
    key: AttemptExecutionKey,
    state: AttemptRuntimeState,
    journal: &DirectoryPreparedResultJournal,
) -> Result<(), LocalExecutorPoolConfigError>
where
    V: AttemptAdmissionValidator,
{
    let AttemptRuntimeState::Completed {
        observation,
        finding_candidate,
        ..
    } = state
    else {
        return Ok(());
    };
    let journal_observation = journal
        .result()
        .observation()
        .observation()
        .id()
        .map_err(|_| LocalExecutorPoolConfigError::PreparedResultCompletionMismatch)?;
    let journal_finding = journal
        .result()
        .finding()
        .map(crate::PreparedCrucibleFindingCandidate::id)
        .transpose()
        .map_err(|_| LocalExecutorPoolConfigError::PreparedResultCompletionMismatch)?;
    let completed_finding = finding_candidate.candidate();
    if journal_observation != observation || journal_finding != completed_finding {
        return Err(LocalExecutorPoolConfigError::PreparedResultCompletionMismatch);
    }

    validate_completed_ledger_result(validator, key, state)
}

fn validate_completed_ledger_result<V>(
    validator: &V,
    key: AttemptExecutionKey,
    state: AttemptRuntimeState,
) -> Result<(), LocalExecutorPoolConfigError>
where
    V: AttemptAdmissionValidator,
{
    let AttemptRuntimeState::Completed {
        observation,
        finding_candidate,
        ..
    } = state
    else {
        return Ok(());
    };
    validator
        .validate_retained_completion(
            key.lineage(),
            key.attempt(),
            observation,
            finding_candidate.candidate(),
        )
        .map_err(
            |reason| LocalExecutorPoolConfigError::PreparedResultCompletionValidation { reason },
        )
}

fn worker_loop<L, V, W>(
    shared: Arc<SharedExecutor<L, V>>,
    store: CampaignExecutorStore,
    mut worker: W,
) where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
    W: LocalAttemptWorker,
{
    loop {
        let Some(queued) = take_next_queued(&shared) else {
            complete_native_checkpoint_cleanup(&shared, worker.take_abandoned_native_checkpoint());
            return;
        };
        let queued = match recover_before_execution(&shared, &store, queued) {
            RecoveryDisposition::Runnable(queued) => *queued,
            RecoveryDisposition::Prepared(prepared) => {
                let _ = reconcile_prepared_result(&shared, &store, *prepared);
                continue;
            }
            RecoveryDisposition::Stopped => continue,
        };
        if queued.cancellation().is_canceled() {
            reconcile_worker_failure(&shared, queued, AttemptWorkerFailure::Canceled(()));
            continue;
        }
        increment(&shared.counters.executions);
        let execution = queued.execution();
        let key = AttemptExecutionKey::for_request(queued.request());
        let cancellation = queued.cancellation().clone();
        match catch_unwind(AssertUnwindSafe(|| worker.execute(queued))) {
            Ok(work) if cancellation.is_canceled() => {
                let (queued, result, abandoned_checkpoint) = work.into_parts();
                complete_native_checkpoint_cleanup(&shared, abandoned_checkpoint);
                let produced_result = match result {
                    Ok(product) => {
                        retire_native_checkpoint_source(
                            &shared,
                            product.into_abandoned_retirement(),
                        );
                        true
                    }
                    Err(_) => false,
                };
                reconcile_worker_failure(&shared, queued, AttemptWorkerFailure::Canceled(()));
                if produced_result {
                    reconcile_worker_execution(
                        &shared,
                        &mut worker,
                        AttemptExecutionDisposition::Canceled,
                    );
                }
            }
            Ok(work) => {
                if let Some(disposition) = reconcile_work_result(&shared, &store, work) {
                    reconcile_worker_execution(&shared, &mut worker, disposition);
                }
            }
            Err(_) => {
                shared.poison();
                reconcile_panicked_worker(&shared, key, execution);
                complete_native_checkpoint_cleanup(
                    &shared,
                    worker.take_abandoned_native_checkpoint(),
                );
            }
        }
    }
}

enum RecoveryDisposition {
    Runnable(Box<QueuedAttempt>),
    Prepared(Box<PreparedAttemptResult>),
    Stopped,
}

fn recover_before_execution<L, V>(
    shared: &SharedExecutor<L, V>,
    store: &CampaignExecutorStore,
    mut queued: QueuedAttempt,
) -> RecoveryDisposition
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    if queued.request().execution_scope() != AttemptExecutionScope::Semantic {
        return RecoveryDisposition::Runnable(Box::new(queued));
    }
    let Some(config) = &shared.prepared_results else {
        return RecoveryDisposition::Runnable(Box::new(queued));
    };
    loop {
        if queued.cancellation().is_canceled()
            || shared.state.load(Ordering::Acquire) != POOL_RUNNING
        {
            reconcile_worker_failure(shared, queued, AttemptWorkerFailure::Canceled(()));
            return RecoveryDisposition::Stopped;
        }
        if !recover_or_remove_staged_journal(shared, config, &queued) {
            return RecoveryDisposition::Stopped;
        }
        match recover_prepared_attempt_result(
            store,
            &config.namespace,
            config.maximum_payload_bytes,
            queued,
        ) {
            Ok(PreparedAttemptRecoveryOutcome::Missing(queued)) => {
                return RecoveryDisposition::Runnable(queued);
            }
            Ok(PreparedAttemptRecoveryOutcome::Prepared(prepared)) => {
                return RecoveryDisposition::Prepared(prepared);
            }
            Err(error) if recovery_failure_is_retryable(&error.source) => {
                queued = *error.queued;
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                reconcile_worker_failure(
                    shared,
                    *error.queued,
                    AttemptWorkerFailure::Terminal(error.source),
                );
                return RecoveryDisposition::Stopped;
            }
        }
    }
}

fn recover_or_remove_staged_journal<L, V>(
    shared: &SharedExecutor<L, V>,
    config: &PreparedResultJournalConfig,
    queued: &QueuedAttempt,
) -> bool
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let key = AttemptExecutionKey::for_request(queued.request());
    loop {
        let state = {
            let executor = match shared.executor.lock() {
                Ok(executor) => executor,
                Err(poisoned) => {
                    drop(poisoned.into_inner());
                    shared.poison();
                    return false;
                }
            };
            match executor.supervisor().ledger().load_attempt(key) {
                Ok(state) => state,
                Err(_) => {
                    increment(&shared.counters.publication_retries);
                    drop(executor);
                    thread::sleep(WORKER_RETRY_INTERVAL);
                    continue;
                }
            }
        };
        let staged = match DirectoryPreparedResultJournal::open_staged_for_recovery(
            &config.namespace,
            key,
            config.maximum_payload_bytes,
        ) {
            Ok(staged) => staged,
            Err(PreparedResultJournalError::Io { .. }) => {
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
                continue;
            }
            Err(_) => {
                shared.poison();
                return false;
            }
        };
        let Some(mut staged) = staged else {
            return true;
        };

        let Some(AttemptRuntimeState::Publishing {
            observation,
            finding_candidate,
            finding_replay_captures,
            finding_exact_retention_roots,
            prepared_result_digest,
            ..
        }) = state
        else {
            drop(staged);
            match DirectoryPreparedResultJournal::cleanup_orphans_after_ledger_check(
                &config.namespace,
                key,
            ) {
                Ok(_) => return true,
                Err(PreparedResultJournalError::Io { .. }) => {
                    increment(&shared.counters.publication_retries);
                    thread::sleep(WORKER_RETRY_INTERVAL);
                    continue;
                }
                Err(_) => {
                    shared.poison();
                    return false;
                }
            }
        };
        let Some((
            journal_observation,
            journal_candidate,
            journal_captures,
            journal_exact_roots,
            journal_digest,
        )) = prepared_journal_publication_identity(&staged)
        else {
            shared.poison();
            return false;
        };
        let common_identity_matches = journal_observation == observation
            && journal_candidate == finding_candidate
            && journal_captures == finding_replay_captures;
        let versioned_identity_matches = match prepared_result_digest {
            Some(digest) => {
                journal_exact_roots == finding_exact_retention_roots
                    && journal_digest == Some(digest)
            }
            None => finding_exact_retention_roots == [None; 3] && journal_exact_roots == [None; 3],
        };
        if !common_identity_matches || !versioned_identity_matches {
            shared.poison();
            return false;
        }
        match staged.commit_staged() {
            Ok(()) => return true,
            Err(PreparedResultJournalError::Io { .. }) => {
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => {
                shared.poison();
                return false;
            }
        }
    }
}

type PreparedJournalPublicationIdentity = (
    crucible_campaign::ObservationId,
    Option<crucible_campaign::FindingCandidateBundleId>,
    Option<crucible_campaign::FindingReplayCaptureSet>,
    [Option<ExactCheckpointId>; 3],
    Option<crucible_campaign::CampaignHash>,
);

fn prepared_journal_publication_identity(
    journal: &DirectoryPreparedResultJournal,
) -> Option<PreparedJournalPublicationIdentity> {
    let observation = journal.result().observation().observation().id().ok()?;
    let finding = journal.result().finding();
    let finding_candidate = finding
        .map(crate::PreparedCrucibleFindingCandidate::id)
        .transpose()
        .ok()?;
    let finding_replay_captures = finding.and_then(|finding| finding.bundle().replay_captures());
    let mut roots = [None; 3];
    if let Some(bundle) = finding.map(|finding| finding.bundle())
        && bundle.exact_retention().is_some_and(|retention| {
            retention.disposition() == FindingExactRetentionDisposition::Complete
        })
    {
        for (slot, root) in roots
            .iter_mut()
            .zip(bundle.exact_pins().all().iter().copied())
        {
            *slot = Some(root);
        }
        if bundle.exact_pins().all().len() > roots.len() {
            return None;
        }
    }
    let prepared_result_digest = journal.prepared_result_digest();
    Some((
        observation,
        finding_candidate,
        finding_replay_captures,
        roots,
        Some(prepared_result_digest),
    ))
}

fn recovery_failure_is_retryable(source: &AttemptResultRecoveryFailure) -> bool {
    match source {
        AttemptResultRecoveryFailure::Journal(PreparedResultJournalError::Io { .. }) => true,
        AttemptResultRecoveryFailure::Preparation(source) => {
            source.executor_rejection() == ExecutorRejection::UnavailableInput
        }
        AttemptResultRecoveryFailure::CaptureStore(source) => source.is_retryable(),
        AttemptResultRecoveryFailure::Journal(_)
        | AttemptResultRecoveryFailure::ProductionReplay(_) => false,
    }
}

fn take_next_queued<L, V>(shared: &Arc<SharedExecutor<L, V>>) -> Option<QueuedAttempt>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    let mut executor = match shared.executor.lock() {
        Ok(executor) => executor,
        Err(poisoned) => {
            drop(poisoned.into_inner());
            shared.fail_closed();
            return None;
        }
    };
    loop {
        if executor.supervisor().queued_count() != 0 {
            // `next_queued` transfers actor ownership to a worker and may also
            // discard stale queue entries. Stamp every post-wake mutation.
            shared.bump_ownership_revision();
        }
        if let Some(mut queued) = executor.supervisor_mut().next_queued() {
            let handoff = PoolCheckpointHandoff {
                shared: Arc::downgrade(shared),
                queued: queued.reconciliation_copy(),
            };
            queued.install_checkpoint_handoff(ExecutionCheckpointHandoff::new(Arc::new(handoff)));
            return Some(queued);
        }
        if shared.state.load(Ordering::Acquire) != POOL_RUNNING {
            return None;
        }
        executor = match shared.ready.wait_timeout(executor, WORKER_RETRY_INTERVAL) {
            Ok((executor, _)) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner().0);
                shared.fail_closed();
                return None;
            }
        };
    }
}

fn reconcile_work_result<L, V, W>(
    shared: &SharedExecutor<L, V>,
    store: &CampaignExecutorStore,
    work: crate::AttemptWorkResult<W>,
) -> Option<AttemptExecutionDisposition>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let (queued, result, abandoned_checkpoint) = work.into_parts();
    complete_native_checkpoint_cleanup(shared, abandoned_checkpoint);
    let work = crate::AttemptWorkResult::new(queued, result);
    let prepared = match prepare_attempt_result(store, &shared.checkpoints, work) {
        Ok(prepared) => prepared,
        Err(AttemptResultPreparationError::Worker {
            queued,
            failure,
            retirement,
        }) => {
            complete_native_checkpoint_cleanup(shared, retirement);
            reconcile_worker_failure(shared, *queued, failure);
            return None;
        }
        Err(AttemptResultPreparationError::Candidate {
            mut pending,
            mut source,
        }) => loop {
            if pending.queued().cancellation().is_canceled() {
                let queued = retire_pending_attempt_result(shared, *pending);
                reconcile_worker_failure(shared, queued, AttemptWorkerFailure::Canceled(()));
                return Some(AttemptExecutionDisposition::Canceled);
            }
            if source.executor_rejection() != ExecutorRejection::UnavailableInput {
                let queued = retire_pending_attempt_result(shared, *pending);
                reconcile_worker_failure(shared, queued, AttemptWorkerFailure::Terminal(source));
                return Some(AttemptExecutionDisposition::Failed);
            }
            increment(&shared.counters.publication_retries);
            thread::sleep(WORKER_RETRY_INTERVAL);
            match retry_pending_attempt_result::<W>(store, *pending) {
                Ok(prepared) => {
                    break PreparedAttemptWorkResult::Observation(Box::new(prepared));
                }
                Err(AttemptResultPreparationError::Candidate {
                    pending: next,
                    source: next_source,
                }) => {
                    pending = next;
                    source = next_source;
                }
                Err(AttemptResultPreparationError::Worker {
                    queued,
                    failure,
                    retirement,
                }) => {
                    complete_native_checkpoint_cleanup(shared, retirement);
                    reconcile_worker_failure(shared, *queued, failure);
                    return None;
                }
                Err(AttemptResultPreparationError::Checkpoint { pending, source }) => {
                    let queued = retire_pending_checkpoint_result(shared, *pending);
                    reconcile_worker_failure(
                        shared,
                        queued,
                        AttemptWorkerFailure::Terminal(source),
                    );
                    return Some(AttemptExecutionDisposition::Failed);
                }
            }
        },
        Err(AttemptResultPreparationError::Checkpoint {
            mut pending,
            mut source,
        }) => loop {
            if pending.queued().cancellation().is_canceled() {
                let queued = retire_pending_checkpoint_result(shared, *pending);
                reconcile_worker_failure(shared, queued, AttemptWorkerFailure::Canceled(()));
                return Some(AttemptExecutionDisposition::Canceled);
            }
            if !source.is_retryable() {
                let queued = retire_pending_checkpoint_result(shared, *pending);
                reconcile_worker_failure(shared, queued, AttemptWorkerFailure::Terminal(source));
                return Some(AttemptExecutionDisposition::Failed);
            }
            increment(&shared.counters.publication_retries);
            thread::sleep(WORKER_RETRY_INTERVAL);
            match retry_pending_checkpoint_result::<W>(&shared.checkpoints, *pending) {
                Ok(prepared) => {
                    break PreparedAttemptWorkResult::ExactCheckpoint(Box::new(prepared));
                }
                Err(AttemptResultPreparationError::Checkpoint {
                    pending: next,
                    source: next_source,
                }) => {
                    pending = next;
                    source = next_source;
                }
                Err(AttemptResultPreparationError::Worker {
                    queued,
                    failure,
                    retirement,
                }) => {
                    complete_native_checkpoint_cleanup(shared, retirement);
                    reconcile_worker_failure(shared, *queued, failure);
                    return None;
                }
                Err(AttemptResultPreparationError::Candidate { pending, source }) => {
                    let queued = retire_pending_attempt_result(shared, *pending);
                    reconcile_worker_failure(
                        shared,
                        queued,
                        AttemptWorkerFailure::Terminal(source),
                    );
                    return Some(AttemptExecutionDisposition::Failed);
                }
            }
        },
    };

    let prepared = match prepared {
        PreparedAttemptWorkResult::Observation(prepared) => *prepared,
        PreparedAttemptWorkResult::ExactCheckpoint(prepared) => {
            return Some(reconcile_checkpoint_result(shared, *prepared));
        }
    };

    let (prepared, journaled) =
        match stage_finding_replay_captures_before_journal(shared, store, prepared) {
            CaptureRootDisposition::Prepared {
                prepared,
                journaled,
            } => (*prepared, journaled),
            CaptureRootDisposition::Finished(disposition) => return Some(disposition),
        };

    let prepared = if journaled {
        prepared
    } else {
        match journal_before_stage(shared, prepared) {
            Some(prepared) => prepared,
            None => return Some(AttemptExecutionDisposition::Failed),
        }
    };

    Some(reconcile_prepared_result(shared, store, prepared))
}

fn retire_pending_attempt_result<L, V>(
    shared: &SharedExecutor<L, V>,
    pending: crate::PendingAttemptResult,
) -> QueuedAttempt
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let (queued, _candidate, retention) = pending.into_parts();
    let retirement = retention
        .as_ref()
        .and_then(PreparedFindingExactRetention::checkpoint)
        .and_then(CapturedAttemptCheckpoint::native_retirement);
    retire_native_checkpoint_source(shared, retirement);
    queued
}

fn retire_pending_checkpoint_result<L, V>(
    shared: &SharedExecutor<L, V>,
    pending: crate::PendingCheckpointResult,
) -> QueuedAttempt
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let (queued, checkpoint) = pending.into_parts();
    retire_native_checkpoint_source(shared, checkpoint.native_retirement());
    queued
}

enum CaptureRootDisposition {
    Prepared {
        prepared: Box<PreparedAttemptResult>,
        journaled: bool,
    },
    Finished(AttemptExecutionDisposition),
}

fn stage_finding_replay_captures_before_journal<L, V>(
    shared: &SharedExecutor<L, V>,
    store: &CampaignExecutorStore,
    mut prepared: PreparedAttemptResult,
) -> CaptureRootDisposition
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let capture_inputs = match prepared.production_replay_capture_inputs() {
        Ok(inputs) => inputs,
        Err(source) => return stop_capture_handoff(shared, prepared, source),
    };
    let captures = match capture_inputs.map(FindingReplayCaptureStore::prepare_set) {
        Some(Ok(captures)) => Some(captures),
        Some(Err(source)) => return stop_capture_handoff(shared, prepared, source),
        None => None,
    };
    let exact_retention = prepared
        .take_finding_exact_retention()
        .map(|retention| prepare_finding_exact_retention(shared, retention));
    if captures.is_none() && exact_retention.is_none() {
        return CaptureRootDisposition::Prepared {
            prepared: Box::new(prepared),
            journaled: false,
        };
    };

    let guard = loop {
        if prepared.queued().cancellation().is_canceled() {
            retire_prepared_finding_exact_retention(shared, exact_retention);
            abort_prepared(shared, prepared);
            return CaptureRootDisposition::Finished(AttemptExecutionDisposition::Canceled);
        }
        match store.acquire_finding_replay_publication_guard() {
            Ok(guard) => break guard,
            Err(source) if source.executor_rejection() == ExecutorRejection::UnavailableInput => {
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(source) => {
                retire_prepared_finding_exact_retention(shared, exact_retention);
                return stop_capture_handoff(shared, prepared, source);
            }
        }
    };

    if let Some(captures) = &captures {
        loop {
            if prepared.queued().cancellation().is_canceled() {
                drop(guard);
                retire_prepared_finding_exact_retention(shared, exact_retention);
                abort_prepared(shared, prepared);
                return CaptureRootDisposition::Finished(AttemptExecutionDisposition::Canceled);
            }
            match FindingReplayCaptureStore::publish_set(&guard, captures) {
                Ok(()) => break,
                Err(source) if source.is_retryable() => {
                    increment(&shared.counters.publication_retries);
                    thread::sleep(WORKER_RETRY_INTERVAL);
                }
                Err(source) => {
                    drop(guard);
                    retire_prepared_finding_exact_retention(shared, exact_retention);
                    return stop_capture_handoff(shared, prepared, source);
                }
            }
        }
    }

    if let Some(captures) = &captures
        && let Err(source) = prepared.bind_production_replay_captures(captures.references())
    {
        drop(guard);
        retire_prepared_finding_exact_retention(shared, exact_retention);
        return stop_capture_handoff(shared, prepared, source);
    }
    if let Some(exact_retention) = exact_retention
        && let Err(source) = bind_finding_exact_retention(shared, &mut prepared, exact_retention)
    {
        drop(guard);
        return stop_capture_handoff(shared, prepared, source);
    }

    if prepared.result().finding().is_some_and(|finding| {
        matches!(
            finding
                .bundle()
                .exact_retention()
                .map(|retention| retention.disposition()),
            Some(FindingExactRetentionDisposition::Complete)
        )
    }) {
        loop {
            if prepared.queued().cancellation().is_canceled() {
                drop(guard);
                abort_prepared(shared, prepared);
                return CaptureRootDisposition::Finished(AttemptExecutionDisposition::Canceled);
            }
            match crate::executor_worker::publish_prepared_semantic_attempt_result(
                store,
                prepared.result(),
            ) {
                Ok(_) => break,
                Err(source)
                    if source.executor_rejection() == ExecutorRejection::UnavailableInput =>
                {
                    increment(&shared.counters.publication_retries);
                    thread::sleep(WORKER_RETRY_INTERVAL);
                }
                Err(source) => {
                    drop(guard);
                    return stop_capture_handoff(shared, prepared, source);
                }
            }
        }
    }

    let Some(mut prepared) = stage_journal_before_publication_root(shared, prepared) else {
        drop(guard);
        return CaptureRootDisposition::Finished(AttemptExecutionDisposition::Failed);
    };

    loop {
        if prepared.queued().cancellation().is_canceled() {
            drop(guard);
            abort_prepared(shared, prepared);
            return CaptureRootDisposition::Finished(AttemptExecutionDisposition::Canceled);
        }
        let mut executor = lock_or_retain(shared, &prepared);
        match stage_prepared_attempt_result(executor.supervisor_mut(), prepared) {
            Ok(AttemptResultStageOutcome::Publish(staged)) => {
                drop(executor);
                let mut prepared = (*staged).into_prepared();
                loop {
                    match prepared.commit_staged_journal() {
                        Ok(journaled) => {
                            prepared = journaled;
                            break;
                        }
                        Err(error)
                            if matches!(error.source, PreparedResultJournalError::Io { .. }) =>
                        {
                            prepared = *error.prepared;
                            increment(&shared.counters.publication_retries);
                            thread::sleep(WORKER_RETRY_INTERVAL);
                        }
                        Err(error) => retain_forever(shared, (error.prepared, guard)),
                    }
                }
                drop(guard);
                return CaptureRootDisposition::Prepared {
                    prepared: Box::new(prepared),
                    journaled: true,
                };
            }
            Ok(AttemptResultStageOutcome::Finished { prepared, outcome }) => {
                drop(executor);
                drop(guard);
                cleanup_prepared_journal(shared, *prepared);
                record_outcome(shared, outcome);
                return CaptureRootDisposition::Finished(worker_reconcile_disposition(outcome));
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                prepared = *error.prepared;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                prepared = *error.prepared;
                drop(executor);
                drop(guard);
                abort_prepared(shared, prepared);
                return CaptureRootDisposition::Finished(AttemptExecutionDisposition::Failed);
            }
        }
    }
}

fn stage_journal_before_publication_root<L, V>(
    shared: &SharedExecutor<L, V>,
    mut prepared: PreparedAttemptResult,
) -> Option<PreparedAttemptResult>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let Some(config) = &shared.prepared_results else {
        return Some(prepared);
    };
    loop {
        if prepared.queued().cancellation().is_canceled() {
            abort_prepared(shared, prepared);
            return None;
        }
        #[cfg(test)]
        if let Some(barrier) = &config.before_journal {
            barrier.wait();
        }
        match crate::stage_prepared_attempt_result_journal(
            &config.namespace,
            config.maximum_payload_bytes,
            prepared,
        ) {
            Ok((journaled, _)) => return Some(journaled),
            Err(error) if matches!(error.source, PreparedResultJournalError::Io { .. }) => {
                prepared = *error.prepared;
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                let source = error.source;
                match (*error.prepared).into_queued_without_journal() {
                    Ok(queued) => reconcile_worker_failure(
                        shared,
                        queued,
                        AttemptWorkerFailure::Terminal(source),
                    ),
                    Err(prepared) => retain_forever(shared, prepared),
                }
                return None;
            }
        }
    }
}

#[cfg(test)]
fn journal_before_releasing_finding_guard<L, V>(
    shared: &SharedExecutor<L, V>,
    prepared: PreparedAttemptResult,
    guard: CampaignExecutorPublicationGuard<'_>,
) -> Option<PreparedAttemptResult>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let journaled = journal_before_stage(shared, prepared);
    drop(guard);
    journaled
}

enum PreparedFindingExactRetentionPhase {
    Disabled {
        basis: crucible_campaign::AttemptRetentionPolicyBasis,
    },
    Incomplete {
        basis: crucible_campaign::AttemptRetentionPolicyBasis,
        reason: FindingExactRetentionIncomplete,
        retirement: Option<ProductionExactCheckpointRetirement>,
    },
    Captured {
        basis: crucible_campaign::AttemptRetentionPolicyBasis,
        checkpoint: PreparedAttemptCheckpoint,
        retirement: Option<ProductionExactCheckpointRetirement>,
    },
}

fn prepare_finding_exact_retention<L, V>(
    shared: &SharedExecutor<L, V>,
    retention: PreparedFindingExactRetention,
) -> PreparedFindingExactRetentionPhase
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match retention {
        PreparedFindingExactRetention::Disabled { basis } => {
            PreparedFindingExactRetentionPhase::Disabled { basis }
        }
        PreparedFindingExactRetention::Incomplete {
            basis,
            reason,
            discarded_checkpoint,
        } => PreparedFindingExactRetentionPhase::Incomplete {
            basis,
            reason,
            retirement: discarded_checkpoint
                .as_ref()
                .and_then(CapturedAttemptCheckpoint::native_retirement),
        },
        PreparedFindingExactRetention::Captured { basis, checkpoint } => {
            let retirement = checkpoint.native_retirement();
            match shared.checkpoints.prepare_attempt_checkpoint(checkpoint) {
                Ok(checkpoint) => PreparedFindingExactRetentionPhase::Captured {
                    basis,
                    checkpoint,
                    retirement,
                },
                Err(_) => PreparedFindingExactRetentionPhase::Incomplete {
                    basis,
                    reason: FindingExactRetentionIncomplete::CandidateAuthenticationFailed,
                    retirement,
                },
            }
        }
    }
}

fn retire_prepared_finding_exact_retention<L, V>(
    shared: &SharedExecutor<L, V>,
    retention: Option<PreparedFindingExactRetentionPhase>,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let retirement = retention.and_then(|retention| match retention {
        PreparedFindingExactRetentionPhase::Disabled { .. } => None,
        PreparedFindingExactRetentionPhase::Incomplete { retirement, .. }
        | PreparedFindingExactRetentionPhase::Captured { retirement, .. } => retirement,
    });
    retire_native_checkpoint_source(shared, retirement);
}

fn bind_finding_exact_retention<L, V>(
    shared: &SharedExecutor<L, V>,
    prepared: &mut PreparedAttemptResult,
    retention: PreparedFindingExactRetentionPhase,
) -> Result<(), crate::PreparedSemanticResultCodecError>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let (basis, exact_pins, authenticated_candidates, disposition, retirement, evidence) =
        match retention {
            PreparedFindingExactRetentionPhase::Disabled { basis } => (
                basis,
                FindingExactPins::default(),
                0,
                FindingExactRetentionDisposition::Disabled,
                None,
                None,
            ),
            PreparedFindingExactRetentionPhase::Incomplete {
                basis,
                reason,
                retirement,
            } => (
                basis,
                FindingExactPins::default(),
                0,
                FindingExactRetentionDisposition::Incomplete(reason),
                retirement,
                None,
            ),
            PreparedFindingExactRetentionPhase::Captured {
                basis,
                checkpoint,
                retirement,
            } => {
                let publication = shared.checkpoints.publish_attempt_checkpoint(&checkpoint);
                let selected = match publication {
                    Ok(publication) => {
                        select_finding_exact_retention(shared, prepared, publication.root())
                    }
                    Err(_) => Err(FindingExactRetentionIncomplete::DurableStagingFailed),
                };
                match selected {
                    Ok((pins, candidates, evidence)) => (
                        basis,
                        pins,
                        candidates,
                        FindingExactRetentionDisposition::Complete,
                        retirement,
                        Some(evidence),
                    ),
                    Err(reason) => (
                        basis,
                        FindingExactPins::default(),
                        0,
                        FindingExactRetentionDisposition::Incomplete(reason),
                        retirement,
                        None,
                    ),
                }
            }
        };

    retire_native_checkpoint_source(shared, retirement);
    let exact_retention = FindingExactRetention::new(
        basis.snapshot(),
        basis.policy(),
        basis.admission(),
        authenticated_candidates,
        disposition,
    )
    .map_err(|_| crate::PreparedSemanticResultCodecError::Inconsistent {
        component: "finding exact retention evidence",
    })?;
    prepared.bind_finding_exact_retention(exact_pins, exact_retention, evidence)
}

fn select_finding_exact_retention<L, V>(
    shared: &SharedExecutor<L, V>,
    prepared: &PreparedAttemptResult,
    captured: ExactCheckpointId,
) -> Result<
    (
        FindingExactPins,
        u32,
        crucible_campaign::FindingExactRetentionEvidence,
    ),
    FindingExactRetentionIncomplete,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let finding = prepared
        .result()
        .finding()
        .ok_or(FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let scenario = crate::decode_crucible_scenario_artifact(finding.scenario())
        .map_err(|_| FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let configuration = finding.original_configuration().configuration();

    let candidates = collect_finding_exact_candidates(shared, &scenario, configuration, captured)?;

    let failure_events = candidates
        .get(&captured)
        .copied()
        .ok_or(FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let measurement_events = match prepared.result().observation().observation().stop() {
        crucible_campaign::StopOutcome::ObservationReached(proof) => {
            Some(proof.boundary().start_events())
        }
        _ => None,
    };
    let boundaries = crate::FindingExactPinBoundaries::new(failure_events, measurement_events)
        .map_err(|_| FindingExactRetentionIncomplete::SelectionFailed)?;
    let pins = crate::exact_pin_retention::select_finding_exact_pins_from_event_counts(
        boundaries,
        &candidates,
    )
    .map_err(|_| FindingExactRetentionIncomplete::SelectionFailed)?;
    let authenticated_candidates = u32::try_from(candidates.len())
        .map_err(|_| FindingExactRetentionIncomplete::CandidateLimitExceeded)?;
    let evidence = crucible_campaign::FindingExactRetentionEvidence::new(
        candidates
            .iter()
            .map(|(checkpoint, events)| {
                crucible_campaign::FindingExactRetentionCandidate::new(*checkpoint, *events)
            })
            .collect(),
        captured,
        failure_events,
        measurement_events,
        pins.clone(),
    )
    .map_err(|_| FindingExactRetentionIncomplete::SelectionFailed)?;
    Ok((pins, authenticated_candidates, evidence))
}

fn collect_finding_exact_candidates<L, V>(
    shared: &SharedExecutor<L, V>,
    scenario: &crucible::ScenarioDefForm,
    configuration: crucible_campaign::ConfigurationId,
    captured: ExactCheckpointId,
) -> Result<BTreeMap<ExactCheckpointId, u64>, FindingExactRetentionIncomplete>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let mut candidates =
        FindingExactCandidateAccumulator::new(&shared.checkpoints, scenario, configuration);
    candidates.consider(captured);

    let executor = shared
        .lock_executor()
        .map_err(|_| FindingExactRetentionIncomplete::CandidateInventoryUnavailable)?;
    executor
        .supervisor()
        .ledger()
        .visit_checkpoint_roots(&mut |checkpoint| {
            candidates.consider(checkpoint);
        })
        .map_err(|_| FindingExactRetentionIncomplete::CandidateInventoryUnavailable)?;

    // Destructive campaign GC fences the assignment ledger before the hot
    // fallback catalog. Keep that global order here, and retain the executor
    // lock until the hot inventory is complete so no coupled path can invert it.
    let hot_retention = shared.hot_checkpoint_retention.as_ref().map(Arc::clone);
    let mut hot_fence = hot_retention
        .as_ref()
        .map(|retention| retention.acquire_hot_checkpoint_retention_fence())
        .transpose()
        .map_err(|_| FindingExactRetentionIncomplete::CandidateInventoryUnavailable)?;
    if let Some(fence) = hot_fence.as_mut() {
        fence
            .visit_fallbacks(&mut |_slot, record| {
                if let HotCheckpointFallback::Exact(checkpoint) = record.fallback() {
                    candidates.consider(checkpoint);
                }
                Ok(())
            })
            .map_err(|_| FindingExactRetentionIncomplete::CandidateInventoryUnavailable)?;
    }

    drop(hot_fence);
    drop(executor);
    candidates.finish()
}

struct FindingExactCandidateAccumulator<'a> {
    checkpoints: &'a ExactCheckpointStore,
    scenario: &'a crucible::ScenarioDefForm,
    configuration: crucible_campaign::ConfigurationId,
    examined: BTreeSet<ExactCheckpointId>,
    examined_root_bytes: u64,
    candidates: BTreeMap<ExactCheckpointId, u64>,
    candidate_limit: bool,
    candidate_authentication_failed: bool,
}

impl<'a> FindingExactCandidateAccumulator<'a> {
    fn new(
        checkpoints: &'a ExactCheckpointStore,
        scenario: &'a crucible::ScenarioDefForm,
        configuration: crucible_campaign::ConfigurationId,
    ) -> Self {
        Self {
            checkpoints,
            scenario,
            configuration,
            examined: BTreeSet::new(),
            examined_root_bytes: 0,
            candidates: BTreeMap::new(),
            candidate_limit: false,
            candidate_authentication_failed: false,
        }
    }

    fn consider(&mut self, checkpoint: ExactCheckpointId) {
        // New finding evidence is independently verifiable only for the
        // manifest/index production representation.
        if checkpoint.content_id().schema_version() != crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION {
            return;
        }
        if self.examined.contains(&checkpoint) {
            return;
        }
        if self.examined.len() == crate::MAX_FINDING_EXACT_PIN_CANDIDATES {
            self.candidate_limit = true;
            return;
        }
        self.examined.insert(checkpoint);

        let remaining = crate::MAX_FINDING_EXACT_PIN_CANDIDATE_ROOT_BYTES
            .saturating_sub(self.examined_root_bytes);
        let metadata_bytes = match self
            .checkpoints
            .finding_authentication_metadata_bytes(checkpoint, remaining)
        {
            Ok(metadata_bytes) => metadata_bytes,
            Err(crate::ExactCheckpointStoreError::ArtifactLimit { .. }) => {
                self.candidate_limit = true;
                return;
            }
            Err(_) => {
                self.candidate_authentication_failed = true;
                return;
            }
        };
        let Some(examined_root_bytes) = self.examined_root_bytes.checked_add(metadata_bytes) else {
            self.candidate_limit = true;
            return;
        };
        if examined_root_bytes > crate::MAX_FINDING_EXACT_PIN_CANDIDATE_ROOT_BYTES {
            self.candidate_limit = true;
            return;
        }
        self.examined_root_bytes = examined_root_bytes;

        let events = match crate::exact_pin_retention::authenticate_finding_exact_checkpoint(
            self.checkpoints,
            self.scenario,
            self.configuration,
            checkpoint,
        ) {
            Ok(events) => events,
            Err(
                crate::ExactPinRetentionError::CheckpointConfigurationMismatch { .. }
                | crate::ExactPinRetentionError::CheckpointScenarioMismatch { .. },
            ) => return,
            Err(_) => {
                self.candidate_authentication_failed = true;
                return;
            }
        };
        self.candidates.insert(checkpoint, events);
    }

    fn finish(self) -> Result<BTreeMap<ExactCheckpointId, u64>, FindingExactRetentionIncomplete> {
        if self.candidate_limit {
            return Err(FindingExactRetentionIncomplete::CandidateLimitExceeded);
        }
        if self.candidate_authentication_failed {
            return Err(FindingExactRetentionIncomplete::CandidateAuthenticationFailed);
        }
        Ok(self.candidates)
    }
}

fn stop_capture_handoff<L, V, E>(
    shared: &SharedExecutor<L, V>,
    mut prepared: PreparedAttemptResult,
    source: E,
) -> CaptureRootDisposition
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let native_retirement = prepared
        .take_finding_exact_retention()
        .and_then(|retention| {
            retention
                .checkpoint()
                .and_then(CapturedAttemptCheckpoint::native_retirement)
        });
    retire_native_checkpoint_source(shared, native_retirement);
    match prepared.into_queued_without_journal() {
        Ok(queued) => {
            reconcile_worker_failure(shared, queued, AttemptWorkerFailure::Terminal(source))
        }
        Err(prepared) => retain_forever(shared, prepared),
    }
    CaptureRootDisposition::Finished(AttemptExecutionDisposition::Failed)
}

fn journal_before_stage<L, V>(
    shared: &SharedExecutor<L, V>,
    mut prepared: PreparedAttemptResult,
) -> Option<PreparedAttemptResult>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let Some(config) = &shared.prepared_results else {
        return Some(prepared);
    };
    loop {
        if prepared.queued().cancellation().is_canceled() {
            abort_prepared(shared, prepared);
            return None;
        }
        #[cfg(test)]
        if let Some(barrier) = &config.before_journal {
            barrier.wait();
        }
        match journal_prepared_attempt_result(
            &config.namespace,
            config.maximum_payload_bytes,
            prepared,
        ) {
            Ok((journaled, _)) => return Some(journaled),
            Err(error) if matches!(error.source, PreparedResultJournalError::Io { .. }) => {
                prepared = *error.prepared;
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                let source = error.source;
                match (*error.prepared).into_queued_without_journal() {
                    Ok(queued) => {
                        reconcile_worker_failure(
                            shared,
                            queued,
                            AttemptWorkerFailure::Terminal(source),
                        );
                    }
                    Err(prepared) => retain_forever(shared, prepared),
                }
                return None;
            }
        }
    }
}

fn reconcile_prepared_result<L, V>(
    shared: &SharedExecutor<L, V>,
    store: &CampaignExecutorStore,
    prepared: PreparedAttemptResult,
) -> AttemptExecutionDisposition
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let staged = match stage_prepared(shared, prepared) {
        StageDisposition::Publish(staged) => staged,
        StageDisposition::Finished(disposition) => return disposition,
    };
    let published = match publish_staged(shared, store, staged) {
        PublishDisposition::Published(published) => *published,
        PublishDisposition::Finished(disposition) => return disposition,
    };
    reconcile_published(shared, published)
}

fn reconcile_checkpoint_result<L, V>(
    shared: &SharedExecutor<L, V>,
    mut prepared: PreparedCheckpointResult,
) -> AttemptExecutionDisposition
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let mut staged = loop {
        if prepared.queued().cancellation().is_canceled() {
            abort_checkpoint(
                shared,
                CheckpointResultAbortToken::Prepared(Box::new(prepared)),
            );
            return AttemptExecutionDisposition::Canceled;
        }
        let mut executor = lock_or_retain(shared, &prepared);
        match stage_prepared_checkpoint_result(executor.supervisor_mut(), prepared) {
            Ok(CheckpointResultStageOutcome::Publish(staged)) => break staged,
            Ok(CheckpointResultStageOutcome::Finished {
                prepared,
                checkpoint,
                outcome,
            }) => {
                drop(executor);
                retire_native_checkpoint_source(shared, prepared.native_retirement());
                record_checkpoint_stage_outcome(shared, checkpoint, outcome);
                return checkpoint_stage_disposition(checkpoint, outcome);
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                prepared = *error.prepared;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                drop(executor);
                abort_checkpoint(shared, CheckpointResultAbortToken::Prepared(error.prepared));
                return AttemptExecutionDisposition::Failed;
            }
        }
    };

    let mut published = loop {
        if staged.queued().cancellation().is_canceled() {
            abort_checkpoint(shared, CheckpointResultAbortToken::Staged(staged));
            return AttemptExecutionDisposition::Canceled;
        }
        match publish_staged_checkpoint_result(&shared.checkpoints, *staged) {
            Ok(published) => break Box::new(published),
            Err(error) if error.source.is_retryable() => {
                staged = error.staged;
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                abort_checkpoint(shared, CheckpointResultAbortToken::Staged(error.staged));
                return AttemptExecutionDisposition::Failed;
            }
        }
    };

    loop {
        if published.queued().cancellation().is_canceled() {
            abort_checkpoint(shared, CheckpointResultAbortToken::Published(published));
            return AttemptExecutionDisposition::Canceled;
        }
        let key = AttemptExecutionKey::for_request(published.queued().request());
        let checkpoint = published.root();
        let mut executor = lock_or_retain(shared, &published);
        match reconcile_published_checkpoint_result(executor.supervisor_mut(), *published) {
            Ok(crate::CheckpointCompletionOutcome::Paused)
            | Ok(crate::CheckpointCompletionOutcome::AlreadyPaused) => {
                increment(&shared.counters.checkpoints_paused);
                drop(executor);
                if !observe_paused_checkpoint(shared, checkpoint) {
                    return AttemptExecutionDisposition::ExactCheckpoint(checkpoint);
                }
                enqueue_paused_checkpoint_promotion(shared, key);
                return AttemptExecutionDisposition::ExactCheckpoint(checkpoint);
            }
            Ok(crate::CheckpointCompletionOutcome::NotCurrent) => {
                increment(&shared.counters.checkpoints_discarded);
                return AttemptExecutionDisposition::Failed;
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                published = error.published;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                drop(executor);
                abort_checkpoint(
                    shared,
                    CheckpointResultAbortToken::Published(error.published),
                );
                return AttemptExecutionDisposition::Failed;
            }
        }
    }
}

fn checkpoint_stage_disposition(
    checkpoint: ExactCheckpointId,
    outcome: CheckpointPublicationOutcome,
) -> AttemptExecutionDisposition {
    match outcome {
        CheckpointPublicationOutcome::AlreadyPaused => {
            AttemptExecutionDisposition::ExactCheckpoint(checkpoint)
        }
        CheckpointPublicationOutcome::NotCurrent
        | CheckpointPublicationOutcome::Staged
        | CheckpointPublicationOutcome::AlreadyStaged => AttemptExecutionDisposition::Failed,
    }
}

fn enqueue_paused_checkpoint_promotion<L, V>(
    shared: &SharedExecutor<L, V>,
    key: AttemptExecutionKey,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    if shared.promotion_worker_count == 0 {
        return;
    }
    loop {
        if shared.state.load(Ordering::Acquire) != POOL_RUNNING {
            return;
        }
        let executor = match shared.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return;
            }
        };
        shared.bump_ownership_revision();
        match executor
            .supervisor()
            .paused_checkpoint_promotion_recovery(key)
        {
            Ok(Some(recovery)) => {
                drop(executor);
                shared.promotions.enqueue(
                    shared,
                    crate::CheckpointPromotionRestartWork::Paused(recovery),
                );
                return;
            }
            Ok(None) => return,
            Err(error) if supervisor_error_is_retryable(&error) => {
                increment(&shared.counters.promotion_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => {
                increment(&shared.counters.promotion_failures);
                return;
            }
        }
    }
}

fn abort_checkpoint<L, V>(shared: &SharedExecutor<L, V>, mut token: CheckpointResultAbortToken)
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let native_retirement = token.native_retirement();
    loop {
        let mut executor = lock_or_retain(shared, &token);
        match abort_checkpoint_result(executor.supervisor_mut(), token) {
            Ok(_) => {
                drop(executor);
                retire_native_checkpoint_source(shared, native_retirement);
                increment(&shared.counters.checkpoints_discarded);
                increment(&shared.counters.terminal_stops);
                return;
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                token = error.token;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                drop(executor);
                retain_forever(shared, error.token);
            }
        }
    }
}

fn retire_native_checkpoint_source<L, V>(
    shared: &SharedExecutor<L, V>,
    retirement: Option<ProductionExactCheckpointRetirement>,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    if let Some(retirement) = retire_native_checkpoint_source_until_terminal(shared, retirement) {
        retain_forever(shared, retirement);
    }
}

fn retire_native_checkpoint_source_until_terminal<L, V>(
    shared: &SharedExecutor<L, V>,
    retirement: Option<ProductionExactCheckpointRetirement>,
) -> Option<ProductionExactCheckpointRetirement>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let retirement = retirement?;
    loop {
        match retire_production_exact_checkpoint_catalog(&retirement) {
            Ok(_) => return None,
            Err(error) if error.is_retryable() => {
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => return Some(retirement),
        }
    }
}

fn complete_native_checkpoint_cleanup<L, V>(
    shared: &SharedExecutor<L, V>,
    cleanup: Option<crate::NativeCheckpointCleanup>,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let Some(cleanup) = cleanup else {
        return;
    };
    let (retirements, mut quarantines) = partition_native_checkpoint_cleanup(cleanup);
    for retirement in retirements {
        if let Some(retirement) =
            retire_native_checkpoint_source_until_terminal(shared, Some(retirement))
        {
            quarantines.push(retirement);
        }
    }
    if !quarantines.is_empty() {
        retain_forever(shared, quarantines);
    }
}

fn partition_native_checkpoint_cleanup(
    cleanup: crate::NativeCheckpointCleanup,
) -> (
    Vec<ProductionExactCheckpointRetirement>,
    Vec<ProductionExactCheckpointRetirement>,
) {
    let mut retirements = Vec::new();
    let mut quarantines = Vec::new();
    let mut pending = vec![cleanup];
    while let Some(cleanup) = pending.pop() {
        match cleanup {
            crate::NativeCheckpointCleanup::Retire(retirement) => retirements.push(retirement),
            crate::NativeCheckpointCleanup::Quarantine(retirement) => {
                quarantines.push(retirement);
            }
            crate::NativeCheckpointCleanup::Batch(cleanups) => pending.extend(cleanups),
        }
    }
    (retirements, quarantines)
}

fn record_checkpoint_stage_outcome<L, V>(
    shared: &SharedExecutor<L, V>,
    checkpoint: ExactCheckpointId,
    outcome: crate::CheckpointPublicationOutcome,
) {
    match outcome {
        crate::CheckpointPublicationOutcome::AlreadyPaused => {
            increment(&shared.counters.checkpoints_paused);
            let _ = observe_paused_checkpoint(shared, checkpoint);
        }
        crate::CheckpointPublicationOutcome::NotCurrent => {
            increment(&shared.counters.checkpoints_discarded);
        }
        crate::CheckpointPublicationOutcome::Staged
        | crate::CheckpointPublicationOutcome::AlreadyStaged => {
            shared.poison();
        }
    }
}

fn observe_paused_checkpoint<L, V>(
    shared: &SharedExecutor<L, V>,
    checkpoint: ExactCheckpointId,
) -> bool {
    let Some(observer) = shared.checkpoint_observer.as_ref() else {
        return true;
    };
    if observer.checkpoint_paused(checkpoint).is_err() {
        shared.poison();
        return false;
    }
    true
}

fn observe_promoted_checkpoint<L, V>(
    shared: &SharedExecutor<L, V>,
    source: ExactCheckpointId,
    promoted: ExactCheckpointId,
) -> bool {
    let Some(observer) = shared.checkpoint_observer.as_ref() else {
        return true;
    };
    if observer.checkpoint_promoted(source, promoted).is_err() {
        shared.poison();
        return false;
    }
    true
}

mod reconciliation;

use reconciliation::*;

#[cfg(test)]
mod tests;
