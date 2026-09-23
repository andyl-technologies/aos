//! Bounded paused-checkpoint promotion workers.
//!
//! Promotion work is compact and durable in the assignment ledger. Fixed
//! worker threads perform repository authentication, guarded QEMU comparison,
//! and immutable publication without holding supervisor ownership; only the
//! stage, reconcile, and revert transitions borrow the actor briefly.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::thread;

use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionKey, AttemptWorkerFailure,
    CheckpointPromotionCompletionOutcome, CheckpointPromotionRestartWork,
    CheckpointPromotionStageOutcome, ExactCheckpointStore, ExecutionCancellation,
    PausedCheckpointPromotionPreparationError, PausedCheckpointPromotionRecovery,
    PausedCheckpointPromotionRestartPreparationError, PausedCheckpointPromotionStageOutcome,
    PreparedPausedCheckpointPromotion, PreparedPausedCheckpointPromotionRestart,
    ProductionAttemptCheckpointRestoreError, ProductionPausedCheckpointReplayFactory,
    PublishedPausedCheckpointPromotion, StagedPausedCheckpointPromotion,
    prepare_production_paused_checkpoint_promotion_restart,
    publish_staged_paused_checkpoint_promotion, reconcile_published_paused_checkpoint_promotion,
    revert_recovered_paused_checkpoint_promotion, revert_staged_paused_checkpoint_promotion,
    stage_prepared_paused_checkpoint_promotion,
};
use crucible_campaign::{CampaignRepositoryError, CampaignStoreError, ExecutorRejection};
use crucible_cas::content_store::StoreError;
use crucible_qemu::QemuVmRealizationError;

use super::{
    LocalExecutorPromotionPhase, POOL_RUNNING, SharedExecutor, WORKER_RETRY_INTERVAL, increment,
    retain_forever, supervisor_error_is_retryable,
};

/// Maximum fixed promotion threads accepted by one local executor pool.
pub const MAX_LOCAL_CHECKPOINT_PROMOTION_WORKERS: usize = 256;

/// Maximum compact paused-root items retained in the process-local work queue.
pub const MAX_LOCAL_CHECKPOINT_PROMOTION_QUEUE: usize = 65_536;

/// No-actor preparation boundary for one durable paused-root promotion phase.
pub(crate) trait LocalCheckpointPromotionWorker {
    /// Operational or semantic preparation failure.
    type Error: std::fmt::Debug;

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
        work: &mut CheckpointPromotionRestartWork,
        cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>>;
}

pub(super) struct DisabledCheckpointPromotionWorker;

impl LocalCheckpointPromotionWorker for DisabledCheckpointPromotionWorker {
    type Error = ();

    fn prepare(
        &mut self,
        _work: &mut CheckpointPromotionRestartWork,
        _cancellation: ExecutionCancellation,
    ) -> Result<PreparedPausedCheckpointPromotionRestart, AttemptWorkerFailure<Self::Error>> {
        Err(AttemptWorkerFailure::Terminal(()))
    }
}

/// Production restart worker around one guarded replay-oracle factory.
pub(crate) struct ProductionCheckpointPromotionWorker<F> {
    store: crucible_campaign::CampaignExecutorStore,
    checkpoints: std::sync::Arc<ExactCheckpointStore>,
    run_state_root: PathBuf,
    factory: F,
}

impl<F> ProductionCheckpointPromotionWorker<F> {
    /// Binds one fixed promotion worker to its immutable and process authorities.
    #[must_use]
    pub(crate) fn new(
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
}

impl<F> LocalCheckpointPromotionWorker for ProductionCheckpointPromotionWorker<F>
where
    F: ProductionPausedCheckpointReplayFactory,
{
    type Error = PausedCheckpointPromotionRestartPreparationError;

    fn prepare(
        &mut self,
        work: &mut CheckpointPromotionRestartWork,
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
                | crate::PausedCheckpointPromotionRecoveryResolutionError::ExecutionBasisMismatch
                | crate::PausedCheckpointPromotionRecoveryResolutionError::CaptureStartMismatch => {
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
        PausedCheckpointPromotionPreparationError::SavepointReplayMismatch => {
            PromotionFailureClass::Terminal
        }
        PausedCheckpointPromotionPreparationError::Realization(error) => {
            classify_realization_failure(error)
        }
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
        | ProductionAttemptCheckpointRestoreError::MaterializedStartMismatch { .. }
        | ProductionAttemptCheckpointRestoreError::NestedCampaignBranch { .. }
        | ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady { .. }
        | ProductionAttemptCheckpointRestoreError::Checkpoint(_)
        | ProductionAttemptCheckpointRestoreError::Lifecycle(_) => PromotionFailureClass::Terminal,
    }
}

fn classify_realization_failure(error: &QemuVmRealizationError) -> PromotionFailureClass {
    match error {
        QemuVmRealizationError::ExecutorUnavailable { .. } => PromotionFailureClass::Retryable,
        QemuVmRealizationError::Canceled { .. } => PromotionFailureClass::Canceled,
        QemuVmRealizationError::ReapQuarantined { .. }
        | QemuVmRealizationError::Store { .. }
        | QemuVmRealizationError::Executor { .. }
        | QemuVmRealizationError::InvalidCheckpoint { .. }
        | QemuVmRealizationError::InvalidAncestor { .. }
        | QemuVmRealizationError::ReplayOracleMismatch { .. } => PromotionFailureClass::Terminal,
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
            let key = work_key(&work);
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

    pub(super) fn try_counts(&self) -> Result<(usize, usize), &'static str> {
        match self.state.try_lock() {
            Ok(state) => Ok((state.active.len(), state.pending.len())),
            Err(std::sync::TryLockError::WouldBlock) => Err("busy"),
            Err(std::sync::TryLockError::Poisoned(_)) => Err("poisoned"),
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
        let key = work_key(&work);
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
                let key = work_key(&work);
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

    fn finish(&self, key: AttemptExecutionKey) {
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

#[cfg(test)]
mod tests {
    use super::PromotionQueue;

    #[test]
    fn pending_cleanup_can_inspect_a_busy_promotion_queue() {
        let queue = PromotionQueue::default();
        let _held = queue.state.lock().expect("promotion queue lock");

        assert_eq!(queue.try_counts(), Err("busy"));
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
    loop {
        let Some((mut work, cancellation)) = shared.promotions.take(&shared) else {
            return;
        };
        let key = work_key(&work);
        let result = catch_unwind(AssertUnwindSafe(|| {
            process_promotion_work(&shared, &mut worker, &mut work, cancellation)
        }));
        shared.promotions.finish(key);
        if result.is_err() {
            shared.poison();
            return;
        }
    }
}

pub(super) fn process_promotion_work<L, V, W>(
    shared: &SharedExecutor<L, V>,
    worker: &mut W,
    work: &mut CheckpointPromotionRestartWork,
    cancellation: ExecutionCancellation,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
    W: LocalCheckpointPromotionWorker,
{
    let key = work_key(work);
    loop {
        if cancellation.is_canceled()
            || shared.state.load(std::sync::atomic::Ordering::Acquire) != POOL_RUNNING
        {
            return;
        }
        shared.record_promotion_phase(key, LocalExecutorPromotionPhase::Preflight);
        if !preflight_promotion_work(shared, work, &cancellation) {
            return;
        }
        shared.record_promotion_phase(key, LocalExecutorPromotionPhase::Preparation);
        let prepared = match worker.prepare(work, cancellation.clone()) {
            Ok(prepared) => prepared,
            Err(AttemptWorkerFailure::Retryable(_)) => {
                increment(&shared.counters.promotion_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
                continue;
            }
            Err(AttemptWorkerFailure::Canceled(_)) => return,
            Err(AttemptWorkerFailure::Terminal(error)) => {
                increment(&shared.counters.promotion_preparation_terminal);
                shared.record_promotion_failure(
                    key,
                    LocalExecutorPromotionPhase::Preparation,
                    &error,
                );
                if let CheckpointPromotionRestartWork::Staged(recovery) = work
                    && let Some(raw) = revert_recovered(shared, *recovery)
                {
                    *work = CheckpointPromotionRestartWork::Paused(raw);
                    continue;
                }
                increment(&shared.counters.promotion_failures);
                return;
            }
        };
        match prepared {
            PreparedPausedCheckpointPromotionRestart::Stage(prepared) => {
                process_prepared(shared, key, *prepared, &cancellation);
                return;
            }
            PreparedPausedCheckpointPromotionRestart::Reconcile(published) => {
                reconcile_published(shared, key, *published);
                return;
            }
        }
    }
}

fn preflight_promotion_work<L, V>(
    shared: &SharedExecutor<L, V>,
    work: &CheckpointPromotionRestartWork,
    cancellation: &ExecutionCancellation,
) -> bool
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        if cancellation.is_canceled()
            || shared.state.load(std::sync::atomic::Ordering::Acquire) != POOL_RUNNING
        {
            return false;
        }
        let executor = match shared.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return false;
            }
        };
        match executor
            .supervisor()
            .checkpoint_promotion_work_is_current(work)
        {
            Ok(true) => return true,
            Ok(false) => {
                increment(&shared.counters.promotions_discarded);
                return false;
            }
            Err(error) if supervisor_error_is_retryable(&error) => {
                increment(&shared.counters.promotion_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                shared.record_promotion_failure(
                    work_key(work),
                    LocalExecutorPromotionPhase::Preflight,
                    &error.to_string(),
                );
                increment(&shared.counters.promotion_failures);
                return false;
            }
        }
    }
}

fn process_prepared<L, V>(
    shared: &SharedExecutor<L, V>,
    key: AttemptExecutionKey,
    mut prepared: PreparedPausedCheckpointPromotion,
    cancellation: &ExecutionCancellation,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let staged = loop {
        if cancellation.is_canceled() {
            retire_prepared_native_source(shared, prepared);
            return;
        }
        shared.record_promotion_phase(key, LocalExecutorPromotionPhase::Stage);
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
            Ok(PausedCheckpointPromotionStageOutcome::Finished {
                prepared, outcome, ..
            }) => {
                drop(executor);
                retire_prepared_native_source(shared, *prepared);
                record_stage_outcome(shared, key, outcome);
                return;
            }
            Err(error) if supervisor_error_is_retryable(&error.source) => {
                prepared = *error.prepared;
                increment(&shared.counters.promotion_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                shared.record_promotion_failure(
                    key,
                    LocalExecutorPromotionPhase::Stage,
                    &error.source.to_string(),
                );
                drop(executor);
                retire_prepared_native_source(shared, *error.prepared);
                increment(&shared.counters.promotion_failures);
                return;
            }
        }
    };

    publish_staged(shared, key, staged, cancellation);
}

fn publish_staged<L, V>(
    shared: &SharedExecutor<L, V>,
    key: AttemptExecutionKey,
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
            revert_staged(shared, staged);
            return;
        }
        shared.record_promotion_phase(key, LocalExecutorPromotionPhase::Publication);
        match publish_staged_paused_checkpoint_promotion(&shared.checkpoints, staged) {
            Ok(published) => {
                reconcile_published(shared, key, published);
                return;
            }
            Err(error) if error.source.is_retryable() => {
                staged = *error.staged;
                increment(&shared.counters.promotion_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(error) => {
                shared.record_promotion_failure(
                    key,
                    LocalExecutorPromotionPhase::Publication,
                    &error.source,
                );
                increment(&shared.counters.promotion_publication_terminal_reverted);
                staged = *error.staged;
                revert_staged(shared, staged);
                increment(&shared.counters.promotion_failures);
                return;
            }
        }
    }
}

fn reconcile_published<L, V>(
    shared: &SharedExecutor<L, V>,
    key: AttemptExecutionKey,
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
        shared.record_promotion_phase(key, LocalExecutorPromotionPhase::Reconcile);
        let mut executor = match shared.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => {
                drop(poisoned.into_inner());
                shared.fail_closed();
                return;
            }
        };
        let source = published.source();
        let promoted = published.promoted();
        match reconcile_published_paused_checkpoint_promotion(
            &shared.checkpoints,
            executor.supervisor_mut(),
            published,
        ) {
            Ok(CheckpointPromotionCompletionOutcome::Promoted)
            | Ok(CheckpointPromotionCompletionOutcome::AlreadyPromoted) => {
                drop(executor);
                if !super::observe_promoted_checkpoint(shared, source, promoted) {
                    return;
                }
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
            Err(error) => {
                shared.record_promotion_failure(
                    key,
                    LocalExecutorPromotionPhase::Reconcile,
                    &error.source.to_string(),
                );
                increment(&shared.counters.promotion_failures);
                return;
            }
        }
    }
}

fn revert_staged<L, V>(shared: &SharedExecutor<L, V>, staged: StagedPausedCheckpointPromotion)
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
        match revert_staged_paused_checkpoint_promotion(executor.supervisor_mut(), &staged) {
            Ok(_) => {
                drop(executor);
                retire_staged_native_source(shared, staged);
                increment(&shared.counters.promotions_discarded);
                return;
            }
            Err(error) if supervisor_error_is_retryable(&error) => {
                increment(&shared.counters.promotion_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => {
                drop(executor);
                retain_forever(shared, staged);
            }
        }
    }
}

fn retire_prepared_native_source<L, V>(
    shared: &SharedExecutor<L, V>,
    prepared: PreparedPausedCheckpointPromotion,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        match prepared.retire_native_source() {
            Ok(()) => return,
            Err(error) if error.is_retryable() => {
                increment(&shared.counters.promotion_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => retain_forever(shared, prepared),
        }
    }
}

fn retire_staged_native_source<L, V>(
    shared: &SharedExecutor<L, V>,
    staged: StagedPausedCheckpointPromotion,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        match staged.retire_native_source() {
            Ok(()) => return,
            Err(error) if error.is_retryable() => {
                increment(&shared.counters.promotion_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => retain_forever(shared, staged),
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
    shared.record_promotion_phase(recovery.key(), LocalExecutorPromotionPhase::Revert);
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
                    Err(error) => {
                        shared.record_promotion_failure(
                            recovery.key(),
                            LocalExecutorPromotionPhase::Revert,
                            &error.to_string(),
                        );
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
    key: AttemptExecutionKey,
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
            shared.record_promotion_failure(key, LocalExecutorPromotionPhase::Stage, &outcome);
            increment(&shared.counters.promotion_failures);
        }
    }
}

fn work_key(work: &CheckpointPromotionRestartWork) -> AttemptExecutionKey {
    match work {
        CheckpointPromotionRestartWork::Paused(recovery) => recovery.key(),
        CheckpointPromotionRestartWork::Staged(recovery) => recovery.key(),
    }
}
