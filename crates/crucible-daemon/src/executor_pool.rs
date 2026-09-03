//! Fixed local attempt workers around the sole-writer executor supervisor.
//!
//! The pool shares only the short operational supervisor actor. Each linear
//! [`QueuedAttempt`] moves to exactly one worker thread; guest execution,
//! repository preflight, and immutable publication all happen after the actor
//! lock is released. Publication and ledger failures retain their phase token
//! and retry that phase without re-running modeled execution.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crucible_api::{
    ProductionExactCheckpointRetirement, retire_production_exact_checkpoint_catalog,
};
use crucible_campaign::{
    CampaignExecutorStore, CancelAttemptExecutionRequest, CancelAttemptExecutionResponse,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse, ExactCheckpointId,
    ExecutorCapabilityService, ExecutorCapacityReport, ExecutorControlService, ExecutorDescription,
    ExecutorRejection, ExecutorResumeService, ExecutorService, ExecutorStatusService,
    GetAttemptExecutionRequest, GetAttemptExecutionResponse, ResumeAttemptExecutionRequest,
    ResumeAttemptExecutionResponse, SubmitAttemptRequest, SubmitAttemptResponse,
    WatchExecutorCapacityRequest,
};

use crate::executor_supervisor::{AttemptCheckpointHandoff, ExecutionCheckpointHandoff};
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionDisposition, AttemptExecutionKey,
    AttemptExecutionReconciliationStep, AttemptResultPreparationError, AttemptResultStageOutcome,
    AttemptWorkerFailure, AttemptWorkerReconcileError, CapturedAttemptCheckpoint,
    CheckpointHandoffFailure, CheckpointPublicationOutcome, CheckpointResultAbortToken,
    CheckpointResultStageOutcome, CompletionValidationFailure, ExactCheckpointStore,
    LocalAttemptWorker, LocalExecutorCapabilityService, LocalExecutorError,
    LocalExecutorSupervisor, PreparedAttemptCheckpoint, PreparedAttemptResult,
    PreparedAttemptWorkResult, PreparedCheckpointResult, PublishedAttemptResult, QueuedAttempt,
    StagedAttemptResult, abort_checkpoint_result, abort_prepared_attempt_result,
    abort_published_attempt_result, abort_staged_attempt_result, prepare_attempt_result,
    publish_prepared_attempt_result, publish_staged_checkpoint_result, reconcile_attempt_failure,
    reconcile_published_attempt_result, reconcile_published_checkpoint_result,
    retry_pending_attempt_result, retry_pending_checkpoint_result, stage_prepared_attempt_result,
    stage_prepared_checkpoint_result,
};

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
const POOL_RUNNING: u8 = 0;
const POOL_SHUTTING_DOWN: u8 = 1;
const POOL_POISONED: u8 = 2;

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
        let executor = self.shared.lock_executor()?;
        Ok(self.shared.report(executor.supervisor()))
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

        let validation =
            match catch_unwind(AssertUnwindSafe(|| self.shared.validator.validate(request))) {
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
            .lock_executor()?
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
            .lock_executor()?
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
            self.shared.validator.validate(&assignment)
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
        )
    }

    /// Starts fixed semantic workers with one durable paused-root owner.
    pub(crate) fn start_with_checkpoint_observer<W>(
        executor: LocalExecutorCapabilityService<L, V>,
        store: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        workers: Vec<W>,
        checkpoint_observer: Arc<dyn PausedCheckpointObserver>,
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
        )
    }

    /// Starts fixed semantic and promotion workers with one paused-root owner.
    pub(crate) fn start_with_checkpoint_promotions_and_observer<W, P>(
        executor: LocalExecutorCapabilityService<L, V>,
        store: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        workers: Vec<W>,
        promotion_workers: Vec<P>,
        checkpoint_observer: Arc<dyn PausedCheckpointObserver>,
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
        )
    }

    fn start_inner<W, P>(
        executor: LocalExecutorCapabilityService<L, V>,
        store: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        workers: Vec<W>,
        promotion_workers: Vec<P>,
        checkpoint_observer: Option<Arc<dyn PausedCheckpointObserver>>,
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
                .spawn(move || worker_loop(worker_shared, worker_store, worker))
            {
                Ok(join) => join,
                Err(source) => {
                    shared.request_shutdown();
                    for join in joins {
                        let _ = join.join();
                    }
                    return Err(LocalExecutorPoolConfigError::Spawn { source });
                }
            };
            joins.push(join);
        }
        for (slot, worker) in promotion_workers.into_iter().enumerate() {
            let worker_shared = Arc::clone(&shared);
            let join = match thread::Builder::new()
                .name(format!("crucible-checkpoint-promotion-{slot}"))
                .spawn(move || promotion_worker_loop(worker_shared, worker))
            {
                Ok(join) => join,
                Err(source) => {
                    shared.request_shutdown();
                    for join in joins {
                        let _ = join.join();
                    }
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

    /// Requests shutdown, joins every worker, and returns final counters.
    ///
    /// A conforming execution model observes cancellation during every bounded
    /// operational quantum. This method waits until those workers return and
    /// their exact supervisor tokens are reconciled.
    ///
    /// # Errors
    ///
    /// Returns an error when a worker thread escaped the pool's panic boundary
    /// or a caught worker panic poisoned this executor incarnation.
    pub fn shutdown_and_join(
        mut self,
    ) -> Result<LocalExecutorPoolReport, LocalExecutorPoolShutdownError> {
        self.request_shutdown();
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

/// Cloneable completion signal for one local executor worker-pool incarnation.
#[derive(Clone)]
pub struct LocalExecutorPoolCompletion {
    state: Arc<PoolCompletionState>,
}

impl LocalExecutorPoolCompletion {
    /// Returns whether every fixed worker thread has exited.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state.is_finished()
    }

    /// Blocks until every fixed worker exits or synchronization is poisoned.
    ///
    /// Poison is treated as terminal completion so a containing service fails
    /// closed instead of retaining a listener for a broken executor owner.
    pub fn wait(&self) {
        let Ok(wait) = self.state.wait.lock() else {
            return;
        };
        drop(
            self.state
                .changed
                .wait_while(wait, |_| !self.state.is_finished()),
        );
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
    /// The sole-writer supervisor rejected or could not persist the operation.
    #[error("local executor supervisor operation failed")]
    Supervisor(LocalExecutorError<E>),
}

/// Terminal failure while joining a fixed worker pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LocalExecutorPoolShutdownError {
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
    worker_count: usize,
    promotion_worker_count: usize,
    checkpoint_observer: Option<Arc<dyn PausedCheckpointObserver>>,
    completion: Arc<PoolCompletionState>,
    counters: PoolCounters,
}

impl<L, V> SharedExecutor<L, V> {
    fn new(
        executor: LocalExecutorCapabilityService<L, V>,
        checkpoints: Arc<ExactCheckpointStore>,
        worker_count: usize,
        promotion_worker_count: usize,
        restart_work: Vec<crate::CheckpointPromotionRestartWork>,
        checkpoint_observer: Option<Arc<dyn PausedCheckpointObserver>>,
    ) -> Self {
        let validator = executor.supervisor().admission_validator();
        Self {
            executor: Mutex::new(executor),
            validator,
            checkpoints,
            ready: Condvar::new(),
            promotions: PromotionQueue::from_restart_work(restart_work),
            state: AtomicU8::new(POOL_RUNNING),
            worker_count,
            promotion_worker_count,
            checkpoint_observer,
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
            Ok(executor) => Ok(executor),
            Err(poisoned) => {
                drop(poisoned.into_inner());
                self.fail_closed();
                Err(LocalExecutorPoolServiceError::SupervisorPoisoned)
            }
        }
    }

    fn request_shutdown(&self) {
        let _ = self.state.compare_exchange(
            POOL_RUNNING,
            POOL_SHUTTING_DOWN,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        match self.executor.lock() {
            Ok(executor) => executor.supervisor().signal_all_active_cancellation(),
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
        match self.executor.lock() {
            Ok(executor) => executor.supervisor().signal_all_active_cancellation(),
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

struct PoolCompletionState {
    finished_workers: AtomicUsize,
    worker_count: usize,
    wait: Mutex<()>,
    changed: Condvar,
}

impl PoolCompletionState {
    fn new(worker_count: usize) -> Self {
        Self {
            finished_workers: AtomicUsize::new(0),
            worker_count,
            wait: Mutex::new(()),
            changed: Condvar::new(),
        }
    }

    fn is_finished(&self) -> bool {
        self.finished_workers.load(Ordering::Acquire) >= self.worker_count
    }

    fn worker_finished(&self) {
        let _wait = match self.wait.lock() {
            Ok(wait) => wait,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ =
            self.finished_workers
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |finished| {
                    Some(finished.saturating_add(1).min(self.worker_count))
                });
        self.changed.notify_all();
    }
}

struct WorkerCompletion {
    state: Arc<PoolCompletionState>,
}

impl WorkerCompletion {
    fn new(state: &Arc<PoolCompletionState>) -> Self {
        Self {
            state: Arc::clone(state),
        }
    }
}

impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        self.state.worker_finished();
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

fn worker_loop<L, V, W>(
    shared: Arc<SharedExecutor<L, V>>,
    store: CampaignExecutorStore,
    mut worker: W,
) where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
    W: LocalAttemptWorker,
{
    let _completion = WorkerCompletion::new(&shared.completion);
    loop {
        let Some(queued) = take_next_queued(&shared) else {
            return;
        };
        if queued.cancellation().is_canceled() {
            reconcile_worker_failure(&shared, queued, AttemptWorkerFailure::Canceled(()));
            continue;
        }
        increment(&shared.counters.executions);
        let execution = queued.execution();
        let key = AttemptExecutionKey::new(queued.request().lineage(), queued.request().attempt());
        let cancellation = queued.cancellation().clone();
        match catch_unwind(AssertUnwindSafe(|| worker.execute(queued))) {
            Ok(work) if cancellation.is_canceled() => {
                let (queued, result) = work.into_parts();
                let produced_result = result.is_ok();
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
            }
        }
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
    let prepared = match prepare_attempt_result(store, &shared.checkpoints, work) {
        Ok(prepared) => prepared,
        Err(AttemptResultPreparationError::Worker { queued, failure }) => {
            reconcile_worker_failure(shared, *queued, failure);
            return None;
        }
        Err(AttemptResultPreparationError::Candidate {
            mut pending,
            mut source,
        }) => loop {
            if pending.queued().cancellation().is_canceled() {
                let (queued, _) = pending.into_parts();
                reconcile_worker_failure(shared, queued, AttemptWorkerFailure::Canceled(()));
                return Some(AttemptExecutionDisposition::Canceled);
            }
            if source.executor_rejection() != ExecutorRejection::UnavailableInput {
                let (queued, _) = pending.into_parts();
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
                Err(AttemptResultPreparationError::Worker { queued, failure }) => {
                    reconcile_worker_failure(shared, *queued, failure);
                    return None;
                }
                Err(AttemptResultPreparationError::Checkpoint { pending, source }) => {
                    let (queued, _) = pending.into_parts();
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
                let (queued, _) = pending.into_parts();
                reconcile_worker_failure(shared, queued, AttemptWorkerFailure::Canceled(()));
                return Some(AttemptExecutionDisposition::Canceled);
            }
            if !source.is_retryable() {
                let (queued, _) = pending.into_parts();
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
                Err(AttemptResultPreparationError::Worker { queued, failure }) => {
                    reconcile_worker_failure(shared, *queued, failure);
                    return None;
                }
                Err(AttemptResultPreparationError::Candidate { pending, source }) => {
                    let (queued, _) = pending.into_parts();
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

    let staged = match stage_prepared(shared, prepared) {
        StageDisposition::Publish(staged) => staged,
        StageDisposition::Finished(disposition) => return Some(disposition),
    };
    let published = match publish_staged(shared, store, staged) {
        PublishDisposition::Published(published) => *published,
        PublishDisposition::Finished(disposition) => return Some(disposition),
    };
    Some(reconcile_published(shared, published))
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
        let key = AttemptExecutionKey::new(
            published.queued().request().lineage(),
            published.queued().request().attempt(),
        );
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
    let Some(retirement) = retirement else {
        return;
    };
    loop {
        match retire_production_exact_checkpoint_catalog(&retirement) {
            Ok(_) => return,
            Err(error) if error.is_retryable() => {
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => retain_forever(shared, retirement),
        }
    }
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

enum StageDisposition {
    Publish(Box<StagedAttemptResult>),
    Finished(AttemptExecutionDisposition),
}

enum PublishDisposition {
    Published(Box<PublishedAttemptResult>),
    Finished(AttemptExecutionDisposition),
}

fn stage_prepared<L, V>(
    shared: &SharedExecutor<L, V>,
    mut prepared: PreparedAttemptResult,
) -> StageDisposition
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        if prepared.queued().cancellation().is_canceled() {
            abort_prepared(shared, prepared);
            return StageDisposition::Finished(AttemptExecutionDisposition::Canceled);
        }
        let mut executor = lock_or_retain(shared, &prepared);
        match stage_prepared_attempt_result(executor.supervisor_mut(), prepared) {
            Ok(AttemptResultStageOutcome::Publish(staged)) => {
                return StageDisposition::Publish(staged);
            }
            Ok(AttemptResultStageOutcome::Finished(outcome)) => {
                record_outcome(shared, outcome);
                return StageDisposition::Finished(worker_reconcile_disposition(outcome));
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
                abort_prepared(shared, prepared);
                return StageDisposition::Finished(AttemptExecutionDisposition::Failed);
            }
        }
    }
}

fn publish_staged<L, V>(
    shared: &SharedExecutor<L, V>,
    store: &CampaignExecutorStore,
    mut staged: Box<StagedAttemptResult>,
) -> PublishDisposition
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        if staged.queued().cancellation().is_canceled() {
            abort_staged(shared, staged);
            return PublishDisposition::Finished(AttemptExecutionDisposition::Canceled);
        }
        match publish_prepared_attempt_result(store, staged) {
            Ok(published) => return PublishDisposition::Published(Box::new(published)),
            Err(error)
                if error.source.executor_rejection() == ExecutorRejection::UnavailableInput =>
            {
                staged = error.staged;
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                abort_staged(shared, error.staged);
                return PublishDisposition::Finished(AttemptExecutionDisposition::Failed);
            }
        }
    }
}

fn reconcile_published<L, V>(
    shared: &SharedExecutor<L, V>,
    mut published: PublishedAttemptResult,
) -> AttemptExecutionDisposition
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        if published.queued().cancellation().is_canceled() {
            abort_published(shared, published);
            return AttemptExecutionDisposition::Canceled;
        }
        let mut executor = lock_or_retain(shared, &published);
        match reconcile_published_attempt_result::<L, V, ()>(executor.supervisor_mut(), published) {
            Ok(outcome) => {
                record_outcome(shared, outcome);
                return worker_reconcile_disposition(outcome);
            }
            Err(AttemptWorkerReconcileError::CompletionPending {
                published: next,
                source,
            }) if supervisor_error_is_retryable(&source) => {
                published = *next;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(AttemptWorkerReconcileError::CompletionPending {
                published: next, ..
            }) => {
                published = *next;
                drop(executor);
                abort_published(shared, published);
                return AttemptExecutionDisposition::Failed;
            }
            Err(_) => {
                drop(executor);
                shared.poison();
                return AttemptExecutionDisposition::Failed;
            }
        }
    }
}

fn reconcile_worker_failure<L, V, W>(
    shared: &SharedExecutor<L, V>,
    mut queued: QueuedAttempt,
    mut failure: AttemptWorkerFailure<W>,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = lock_or_retain(shared, &queued);
        match reconcile_attempt_failure(executor.supervisor_mut(), queued, failure) {
            Err(AttemptWorkerReconcileError::Worker(_)) => {
                increment(&shared.counters.retry_requeues);
                shared.ready.notify_one();
                return;
            }
            Err(AttemptWorkerReconcileError::Stopped { .. }) | Ok(()) => {
                increment(&shared.counters.terminal_stops);
                return;
            }
            Err(AttemptWorkerReconcileError::FailurePending {
                queued: next,
                failure: next_failure,
                source,
            }) if supervisor_error_is_retryable(&source) => {
                queued = *next;
                failure = next_failure;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(AttemptWorkerReconcileError::FailurePending {
                queued: next,
                failure: next_failure,
                ..
            }) => {
                drop(executor);
                retain_forever(shared, (*next, next_failure));
            }
            Err(AttemptWorkerReconcileError::CompletionPending { published, .. }) => {
                drop(executor);
                retain_forever(shared, published);
            }
        }
    }
}

fn abort_prepared<L, V>(shared: &SharedExecutor<L, V>, mut prepared: PreparedAttemptResult)
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = lock_or_retain(shared, &prepared);
        match abort_prepared_attempt_result(executor.supervisor_mut(), prepared) {
            Ok(_) => {
                increment(&shared.counters.terminal_stops);
                return;
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                prepared = *error.prepared;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                drop(executor);
                retain_forever(shared, error.prepared);
            }
        }
    }
}

fn abort_staged<L, V>(shared: &SharedExecutor<L, V>, mut staged: Box<StagedAttemptResult>)
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = lock_or_retain(shared, &staged);
        match abort_staged_attempt_result(executor.supervisor_mut(), staged) {
            Ok(_) => {
                increment(&shared.counters.terminal_stops);
                return;
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                staged = error.staged;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                drop(executor);
                retain_forever(shared, error.staged);
            }
        }
    }
}

fn abort_published<L, V>(shared: &SharedExecutor<L, V>, mut published: PublishedAttemptResult)
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = lock_or_retain(shared, &published);
        match abort_published_attempt_result(executor.supervisor_mut(), published) {
            Ok(_) => {
                increment(&shared.counters.terminal_stops);
                return;
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                published = *error.published;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                drop(executor);
                retain_forever(shared, error.published);
            }
        }
    }
}

fn reconcile_panicked_worker<L, V>(
    shared: &SharedExecutor<L, V>,
    key: AttemptExecutionKey,
    execution: crucible_campaign::ExecutionId,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = match shared.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                retain_forever(shared, (key, execution));
            }
        };
        match executor
            .supervisor_mut()
            .reconcile_panicked_worker(key, execution)
        {
            Ok(_) => return,
            Err(error) if supervisor_error_is_retryable(&error) => {
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => {
                drop(executor);
                retain_forever(shared, (key, execution));
            }
        }
    }
}

fn lock_or_retain<'a, L, V, T>(
    shared: &'a SharedExecutor<L, V>,
    token: &T,
) -> MutexGuard<'a, LocalExecutorCapabilityService<L, V>> {
    match shared.executor.lock() {
        Ok(executor) => executor,
        Err(poisoned) => {
            drop(poisoned.into_inner());
            retain_forever(shared, token);
        }
    }
}

fn retain_forever<L, V, T>(shared: &SharedExecutor<L, V>, token: T) -> ! {
    shared.fail_closed();
    let _retained = token;
    loop {
        thread::park();
    }
}

fn supervisor_error_is_retryable<E>(error: &LocalExecutorError<E>) -> bool {
    matches!(
        error,
        LocalExecutorError::Ledger(_)
            | LocalExecutorError::CompletionValidation {
                reason: CompletionValidationFailure::UnavailableInput,
            }
    )
}

fn reconcile_worker_execution<L, V, W>(
    shared: &SharedExecutor<L, V>,
    worker: &mut W,
    disposition: AttemptExecutionDisposition,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
    W: LocalAttemptWorker,
{
    loop {
        match worker.reconcile_execution(disposition) {
            Ok(AttemptExecutionReconciliationStep::Complete) => return,
            Ok(AttemptExecutionReconciliationStep::Progressed) => thread::yield_now(),
            Err(AttemptWorkerFailure::Retryable(_)) => {
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(AttemptWorkerFailure::Canceled(_) | AttemptWorkerFailure::Terminal(_)) => {
                shared.poison();
                return;
            }
        }
    }
}

fn worker_reconcile_disposition(
    outcome: crate::AttemptWorkerReconcileOutcome,
) -> AttemptExecutionDisposition {
    match outcome {
        crate::AttemptWorkerReconcileOutcome::Reconciled {
            observation,
            completion:
                crate::CompletionOutcome::Completed | crate::CompletionOutcome::AlreadyCompleted,
        } => AttemptExecutionDisposition::Observation(observation),
        crate::AttemptWorkerReconcileOutcome::Discarded {
            completion: crate::CompletionOutcome::Canceled,
            ..
        } => AttemptExecutionDisposition::Canceled,
        crate::AttemptWorkerReconcileOutcome::Discarded {
            completion: crate::CompletionOutcome::NotCurrent,
            ..
        }
        | crate::AttemptWorkerReconcileOutcome::Reconciled { .. }
        | crate::AttemptWorkerReconcileOutcome::Discarded { .. } => {
            AttemptExecutionDisposition::Failed
        }
    }
}

fn record_outcome<L, V>(
    shared: &SharedExecutor<L, V>,
    outcome: crate::AttemptWorkerReconcileOutcome,
) {
    match outcome {
        crate::AttemptWorkerReconcileOutcome::Reconciled { .. } => {
            increment(&shared.counters.reconciled);
        }
        crate::AttemptWorkerReconcileOutcome::Discarded { .. } => {
            increment(&shared.counters.discarded);
        }
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

#[cfg(test)]
mod tests;
