//! Bounded paused-checkpoint promotion workers.
//!
//! Promotion work is compact and durable in the assignment ledger. Fixed
//! worker threads perform repository authentication, guarded QEMU comparison,
//! and immutable publication without holding supervisor ownership; only the
//! stage, reconcile, and revert transitions borrow the actor briefly.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::thread;

use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionKey, AttemptWorkerFailure,
    CheckpointPromotionCompletionOutcome, CheckpointPromotionRestartWork,
    CheckpointPromotionStageOutcome, ExactCheckpointStore, ExecutionCancellation,
    PausedCheckpointPromotionPreparationError, PausedCheckpointPromotionRecovery,
    PausedCheckpointPromotionRestartPreparationError, PausedCheckpointPromotionStageOutcome,
    PrepareReplayOraclePromotionError, PreparedPausedCheckpointPromotion,
    PreparedPausedCheckpointPromotionRestart, ProductionAttemptCheckpointRestoreError,
    ProductionPausedCheckpointReplayFactory, PublishedPausedCheckpointPromotion,
    StagedPausedCheckpointPromotion, prepare_production_paused_checkpoint_promotion_restart,
    publish_staged_paused_checkpoint_promotion, reconcile_published_paused_checkpoint_promotion,
    revert_recovered_paused_checkpoint_promotion, revert_staged_paused_checkpoint_promotion,
    stage_prepared_paused_checkpoint_promotion,
};
use crucible_campaign::{CampaignRepositoryError, CampaignStoreError, ExecutorRejection};
use crucible_cas::content_store::StoreError;
use crucible_qemu::QemuVmRealizationError;

use super::{
    POOL_RUNNING, SharedExecutor, WORKER_RETRY_INTERVAL, WorkerCompletion, increment,
    supervisor_error_is_retryable,
};

/// Maximum fixed promotion threads accepted by one local executor pool.
pub const MAX_LOCAL_CHECKPOINT_PROMOTION_WORKERS: usize = 256;

/// Maximum compact paused-root items retained in the process-local work queue.
pub const MAX_LOCAL_CHECKPOINT_PROMOTION_QUEUE: usize = 65_536;

/// No-actor preparation boundary for one durable paused-root promotion phase.
pub trait LocalCheckpointPromotionWorker {
    /// Operational or semantic preparation failure.
    type Error;

    /// Resolves and prepares one raw or staged durable promotion phase.
    ///
    /// Implementations perform repository reads and guarded replay comparison
    /// here. They must not borrow the local executor supervisor or mutate the
    /// operational ledger.
    ///
    /// # Errors
    ///
    /// Returns a classified transient, canceled, or terminal preparation
    /// failure. Retryable failures are retried without dropping `work`.
    fn prepare(
        &mut self,
        work: CheckpointPromotionRestartWork,
        cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>>;
}

/// Production restart worker around one guarded replay-oracle factory.
pub struct ProductionCheckpointPromotionWorker<F> {
    store: crucible_campaign::CampaignExecutorStore,
    checkpoints: std::sync::Arc<ExactCheckpointStore>,
    run_state_root: PathBuf,
    factory: F,
}

impl<F> ProductionCheckpointPromotionWorker<F> {
    /// Binds one fixed promotion worker to its immutable and process authorities.
    #[must_use]
    pub fn new(
        store: crucible_campaign::CampaignExecutorStore,
        checkpoints: std::sync::Arc<ExactCheckpointStore>,
        run_state_root: impl Into<PathBuf>,
        factory: F,
    ) -> Self {
        Self {
            store,
            checkpoints,
            run_state_root: run_state_root.into(),
            factory,
        }
    }

    /// Returns the stable run-state root for guarded comparison sessions.
    #[must_use]
    pub fn run_state_root(&self) -> &Path {
        &self.run_state_root
    }

    /// Returns the node-specific replay session factory.
    #[must_use]
    pub const fn factory(&self) -> &F {
        &self.factory
    }
}

impl<F> LocalCheckpointPromotionWorker for ProductionCheckpointPromotionWorker<F>
where
    F: ProductionPausedCheckpointReplayFactory,
{
    type Error = PausedCheckpointPromotionRestartPreparationError;

    fn prepare(
        &mut self,
        work: CheckpointPromotionRestartWork,
        cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>> {
        prepare_production_paused_checkpoint_promotion_restart(
            &self.store,
            &self.checkpoints,
            work,
            &self.run_state_root,
            cancellation,
            &mut self.factory,
        )
        .map_err(classify_production_promotion_failure)
    }
}

#[derive(Clone, Copy)]
enum PromotionFailureClass {
    Retryable,
    Canceled,
    Terminal,
}

fn classify_production_promotion_failure(
    error: PausedCheckpointPromotionRestartPreparationError,
) -> AttemptWorkerFailure<PausedCheckpointPromotionRestartPreparationError> {
    let class = match &error {
        PausedCheckpointPromotionRestartPreparationError::Resolution(resolution) => {
            match resolution {
                crate::PausedCheckpointPromotionRecoveryResolutionError::Repository(error) => {
                    classify_repository_failure(error)
                }
                crate::PausedCheckpointPromotionRecoveryResolutionError::Artifact(_)
                | crate::PausedCheckpointPromotionRecoveryResolutionError::ExecutionBasisMismatch => {
                    PromotionFailureClass::Terminal
                }
            }
        }
        PausedCheckpointPromotionRestartPreparationError::Repository(error) => {
            classify_repository_failure(error)
        }
        PausedCheckpointPromotionRestartPreparationError::Artifact(_) => {
            PromotionFailureClass::Terminal
        }
        PausedCheckpointPromotionRestartPreparationError::Preparation(error) => {
            classify_preparation_failure(error)
        }
        PausedCheckpointPromotionRestartPreparationError::Staged(error) => {
            classify_restore_failure(error)
        }
    };
    match class {
        PromotionFailureClass::Retryable => AttemptWorkerFailure::Retryable(error),
        PromotionFailureClass::Canceled => AttemptWorkerFailure::Canceled(error),
        PromotionFailureClass::Terminal => AttemptWorkerFailure::Terminal(error),
    }
}

fn classify_repository_failure(error: &CampaignRepositoryError) -> PromotionFailureClass {
    if matches!(
        error,
        CampaignRepositoryError::Poisoned
            | CampaignRepositoryError::Store(StoreError::Poisoned { .. })
            | CampaignRepositoryError::Merkle(CampaignStoreError::Store(
                StoreError::Poisoned { .. }
            ))
    ) {
        return PromotionFailureClass::Terminal;
    }
    if error.executor_rejection() == ExecutorRejection::UnavailableInput {
        PromotionFailureClass::Retryable
    } else {
        PromotionFailureClass::Terminal
    }
}

fn classify_preparation_failure(
    error: &PausedCheckpointPromotionPreparationError,
) -> PromotionFailureClass {
    match error {
        PausedCheckpointPromotionPreparationError::ProductionRestore(error) => {
            classify_restore_failure(error)
        }
        PausedCheckpointPromotionPreparationError::ProductionClosure(_) => {
            PromotionFailureClass::Terminal
        }
        PausedCheckpointPromotionPreparationError::Realization(error) => {
            classify_realization_failure(error)
        }
        PausedCheckpointPromotionPreparationError::Preparation(error) => match error {
            PrepareReplayOraclePromotionError::Checkpoint(error) if error.is_retryable() => {
                PromotionFailureClass::Retryable
            }
            PrepareReplayOraclePromotionError::Checkpoint(
                crate::ExactCheckpointStoreError::Canceled,
            ) => PromotionFailureClass::Canceled,
            PrepareReplayOraclePromotionError::ReplayOracle(error) => {
                classify_realization_failure(error)
            }
            PrepareReplayOraclePromotionError::Checkpoint(_) => PromotionFailureClass::Terminal,
        },
    }
}

fn classify_restore_failure(
    error: &ProductionAttemptCheckpointRestoreError,
) -> PromotionFailureClass {
    match error {
        ProductionAttemptCheckpointRestoreError::Canceled => PromotionFailureClass::Canceled,
        ProductionAttemptCheckpointRestoreError::Checkpoint(error) if error.is_retryable() => {
            PromotionFailureClass::Retryable
        }
        ProductionAttemptCheckpointRestoreError::AttemptScenarioMismatch
        | ProductionAttemptCheckpointRestoreError::AttemptSelectionMismatch
        | ProductionAttemptCheckpointRestoreError::CheckpointScenarioMismatch { .. }
        | ProductionAttemptCheckpointRestoreError::ClosureIdentityMismatch { .. }
        | ProductionAttemptCheckpointRestoreError::CheckpointConfigurationMismatch { .. }
        | ProductionAttemptCheckpointRestoreError::AttemptPrefixMismatch { .. }
        | ProductionAttemptCheckpointRestoreError::NestedCampaignBranch { .. }
        | ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady { .. }
        | ProductionAttemptCheckpointRestoreError::Checkpoint(_)
        | ProductionAttemptCheckpointRestoreError::Lifecycle(_) => PromotionFailureClass::Terminal,
    }
}

fn classify_realization_failure(error: &QemuVmRealizationError) -> PromotionFailureClass {
    match error {
        QemuVmRealizationError::StoreUnavailable { .. }
        | QemuVmRealizationError::ExecutorUnavailable { .. } => PromotionFailureClass::Retryable,
        QemuVmRealizationError::Canceled { .. } => PromotionFailureClass::Canceled,
        QemuVmRealizationError::ReapQuarantined { .. }
        | QemuVmRealizationError::Store { .. }
        | QemuVmRealizationError::Executor { .. }
        | QemuVmRealizationError::ForkPrefix(_)
        | QemuVmRealizationError::ForkPrefixOutOfRange { .. }
        | QemuVmRealizationError::AncestorPrefix(_)
        | QemuVmRealizationError::InvalidCheckpoint { .. }
        | QemuVmRealizationError::InvalidAncestor { .. }
        | QemuVmRealizationError::RuntimeContentMismatch { .. }
        | QemuVmRealizationError::SavevmPolicy { .. }
        | QemuVmRealizationError::InvalidLoadvmAuthorization { .. }
        | QemuVmRealizationError::ReadyPointPolicy { .. } => PromotionFailureClass::Terminal,
    }
}

#[derive(Default)]
pub(super) struct PromotionQueue {
    state: Mutex<PromotionQueueState>,
    ready: Condvar,
    space: Condvar,
}

#[derive(Default)]
struct PromotionQueueState {
    pending: VecDeque<CheckpointPromotionRestartWork>,
    indexed: BTreeSet<AttemptExecutionKey>,
    active: BTreeMap<AttemptExecutionKey, ExecutionCancellation>,
}

impl PromotionQueue {
    pub(super) fn from_restart_work(work: Vec<CheckpointPromotionRestartWork>) -> Self {
        let mut pending = VecDeque::with_capacity(work.len());
        let mut indexed = BTreeSet::new();
        for work in work {
            let key = work_key(work);
            if indexed.insert(key) {
                pending.push_back(work);
            }
        }
        Self {
            state: Mutex::new(PromotionQueueState {
                pending,
                indexed,
                active: BTreeMap::new(),
            }),
            ready: Condvar::new(),
            space: Condvar::new(),
        }
    }

    pub(super) fn pending_count(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.pending.len(),
            Err(poisoned) => poisoned.into_inner().pending.len(),
        }
    }

    pub(super) fn active_count(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.active.len(),
            Err(poisoned) => poisoned.into_inner().active.len(),
        }
    }

    pub(super) fn enqueue<L, V>(
        &self,
        shared: &SharedExecutor<L, V>,
        work: CheckpointPromotionRestartWork,
    ) where
        L: AssignmentLedger,
        V: AttemptAdmissionValidator,
    {
        let key = work_key(work);
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return;
            }
        };
        loop {
            if state.indexed.contains(&key) || state.active.contains_key(&key) {
                return;
            }
            if shared.state.load(std::sync::atomic::Ordering::Acquire) != POOL_RUNNING {
                return;
            }
            if state.pending.len() < MAX_LOCAL_CHECKPOINT_PROMOTION_QUEUE {
                state.pending.push_back(work);
                state.indexed.insert(key);
                self.ready.notify_one();
                return;
            }
            state = match self.space.wait(state) {
                Ok(state) => state,
                Err(poisoned) => {
                    drop(poisoned.into_inner());
                    shared.fail_closed();
                    return;
                }
            };
        }
    }

    fn take<L, V>(
        &self,
        shared: &SharedExecutor<L, V>,
    ) -> Option<(CheckpointPromotionRestartWork, ExecutionCancellation)>
    where
        L: AssignmentLedger,
        V: AttemptAdmissionValidator,
    {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return None;
            }
        };
        loop {
            if shared.state.load(std::sync::atomic::Ordering::Acquire) != POOL_RUNNING {
                return None;
            }
            if let Some(work) = state.pending.pop_front() {
                let key = work_key(work);
                state.indexed.remove(&key);
                let cancellation = ExecutionCancellation::default();
                state.active.insert(key, cancellation.clone());
                if shared.state.load(std::sync::atomic::Ordering::Acquire) != POOL_RUNNING {
                    cancellation.cancel();
                }
                self.space.notify_one();
                return Some((work, cancellation));
            }
            state = match self.ready.wait(state) {
                Ok(state) => state,
                Err(poisoned) => {
                    drop(poisoned.into_inner());
                    shared.fail_closed();
                    return None;
                }
            };
        }
    }

    fn finish(&self, work: CheckpointPromotionRestartWork) {
        let key = work_key(work);
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.active.remove(&key);
        self.space.notify_all();
    }

    pub(super) fn shutdown(&self) {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        for cancellation in state.active.values() {
            cancellation.cancel();
        }
        self.ready.notify_all();
        self.space.notify_all();
    }
}

pub(super) fn promotion_worker_loop<L, V, W>(
    shared: std::sync::Arc<SharedExecutor<L, V>>,
    mut worker: W,
) where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
    W: LocalCheckpointPromotionWorker,
{
    let _completion = WorkerCompletion::new(&shared.completion);
    loop {
        let Some((work, cancellation)) = shared.promotions.take(&shared) else {
            return;
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            process_promotion_work(&shared, &mut worker, work, cancellation)
        }));
        shared.promotions.finish(work);
        if result.is_err() {
            shared.poison();
            return;
        }
    }
}

fn process_promotion_work<L, V, W>(
    shared: &SharedExecutor<L, V>,
    worker: &mut W,
    mut work: CheckpointPromotionRestartWork,
    cancellation: ExecutionCancellation,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
    W: LocalCheckpointPromotionWorker,
{
    loop {
        if cancellation.is_canceled()
            || shared.state.load(std::sync::atomic::Ordering::Acquire) != POOL_RUNNING
        {
            return;
        }
        let prepared = match worker.prepare(work, cancellation.clone()) {
            Ok(prepared) => prepared,
            Err(AttemptWorkerFailure::Retryable(_)) => {
                increment(&shared.counters.promotion_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
                continue;
            }
            Err(AttemptWorkerFailure::Canceled(_)) => return,
            Err(AttemptWorkerFailure::Terminal(_)) => {
                if let CheckpointPromotionRestartWork::Staged(recovery) = work
                    && let Some(raw) = revert_recovered(shared, recovery)
                {
                    work = CheckpointPromotionRestartWork::Paused(raw);
                    continue;
                }
                increment(&shared.counters.promotion_failures);
                return;
            }
        };
        match prepared {
            PreparedPausedCheckpointPromotionRestart::Stage(prepared) => {
                process_prepared(shared, *prepared, &cancellation);
                return;
            }
            PreparedPausedCheckpointPromotionRestart::Reconcile(published) => {
                reconcile_published(shared, *published);
                return;
            }
        }
    }
}

fn process_prepared<L, V>(
    shared: &SharedExecutor<L, V>,
    mut prepared: PreparedPausedCheckpointPromotion,
    cancellation: &ExecutionCancellation,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let staged = loop {
        if cancellation.is_canceled() {
            return;
        }
        let mut executor = match shared.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return;
            }
        };
        match stage_prepared_paused_checkpoint_promotion(executor.supervisor_mut(), prepared) {
            Ok(PausedCheckpointPromotionStageOutcome::Publish(staged)) => break *staged,
            Ok(PausedCheckpointPromotionStageOutcome::Finished { outcome, .. }) => {
                record_stage_outcome(shared, outcome);
                return;
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                prepared = *error.prepared;
                increment(&shared.counters.promotion_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => {
                increment(&shared.counters.promotion_failures);
                return;
            }
        }
    };

    publish_staged(shared, staged, cancellation);
}

fn publish_staged<L, V>(
    shared: &SharedExecutor<L, V>,
    mut staged: StagedPausedCheckpointPromotion,
    cancellation: &ExecutionCancellation,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        if cancellation.is_canceled()
            || shared.state.load(std::sync::atomic::Ordering::Acquire) != POOL_RUNNING
        {
            revert_staged(shared, &staged);
            return;
        }
        match publish_staged_paused_checkpoint_promotion(&shared.checkpoints, staged) {
            Ok(published) => {
                reconcile_published(shared, published);
                return;
            }
            Err(error) if error.source.is_retryable() => {
                staged = *error.staged;
                increment(&shared.counters.promotion_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                staged = *error.staged;
                revert_staged(shared, &staged);
                increment(&shared.counters.promotion_failures);
                return;
            }
        }
    }
}

fn reconcile_published<L, V>(
    shared: &SharedExecutor<L, V>,
    mut published: PublishedPausedCheckpointPromotion,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        // The staged source/replacement pair and complete replacement are
        // already durable. Shutdown may leave the final CAS to the bounded
        // restart inventory instead of holding pool teardown on a sick ledger.
        if shared.state.load(std::sync::atomic::Ordering::Acquire) != POOL_RUNNING {
            return;
        }
        let mut executor = match shared.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return;
            }
        };
        match reconcile_published_paused_checkpoint_promotion(executor.supervisor_mut(), published)
        {
            Ok(CheckpointPromotionCompletionOutcome::Promoted)
            | Ok(CheckpointPromotionCompletionOutcome::AlreadyPromoted) => {
                increment(&shared.counters.promotions_reconciled);
                return;
            }
            Ok(CheckpointPromotionCompletionOutcome::NotCurrent)
            | Ok(CheckpointPromotionCompletionOutcome::Reverted) => {
                increment(&shared.counters.promotions_discarded);
                return;
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                published = *error.published;
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

fn revert_staged<L, V>(shared: &SharedExecutor<L, V>, staged: &StagedPausedCheckpointPromotion)
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = match shared.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return;
            }
        };
        match revert_staged_paused_checkpoint_promotion(executor.supervisor_mut(), staged) {
            Ok(_) => {
                increment(&shared.counters.promotions_discarded);
                return;
            }
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

fn revert_recovered<L, V>(
    shared: &SharedExecutor<L, V>,
    recovery: crate::CheckpointPromotionRecovery,
) -> Option<PausedCheckpointPromotionRecovery>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = match shared.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return None;
            }
        };
        match revert_recovered_paused_checkpoint_promotion(executor.supervisor_mut(), recovery) {
            Ok(CheckpointPromotionCompletionOutcome::Reverted) => {
                increment(&shared.counters.promotions_discarded);
                let raw = executor
                    .supervisor()
                    .paused_checkpoint_promotion_recovery(recovery.key());
                return match raw {
                    Ok(raw) => raw,
                    Err(_) => {
                        increment(&shared.counters.promotion_failures);
                        None
                    }
                };
            }
            Ok(CheckpointPromotionCompletionOutcome::NotCurrent)
            | Ok(CheckpointPromotionCompletionOutcome::Promoted)
            | Ok(CheckpointPromotionCompletionOutcome::AlreadyPromoted) => return None,
            Err(error) if supervisor_error_is_retryable(&error) => {
                increment(&shared.counters.promotion_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => return None,
        }
    }
}

fn record_stage_outcome<L, V>(
    shared: &SharedExecutor<L, V>,
    outcome: CheckpointPromotionStageOutcome,
) {
    match outcome {
        CheckpointPromotionStageOutcome::AlreadyPromoted => {
            increment(&shared.counters.promotions_reconciled);
        }
        CheckpointPromotionStageOutcome::NotCurrent => {
            increment(&shared.counters.promotions_discarded);
        }
        CheckpointPromotionStageOutcome::Staged
        | CheckpointPromotionStageOutcome::AlreadyStaged => {
            increment(&shared.counters.promotion_failures);
        }
    }
}

fn work_key(work: CheckpointPromotionRestartWork) -> AttemptExecutionKey {
    match work {
        CheckpointPromotionRestartWork::Paused(recovery) => recovery.key(),
        CheckpointPromotionRestartWork::Staged(recovery) => recovery.key(),
    }
}
