//! Final result publication, cleanup, and worker reconciliation.

use super::*;

pub(super) enum StageDisposition {
    Publish(Box<StagedAttemptResult>),
    Finished(AttemptExecutionDisposition),
}

pub(super) enum PublishDisposition {
    Published(Box<PublishedAttemptResult>),
    Finished(AttemptExecutionDisposition),
}

pub(super) fn stage_prepared<L, V>(
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
            Ok(AttemptResultStageOutcome::Finished { prepared, outcome }) => {
                drop(executor);
                cleanup_prepared_journal(shared, *prepared);
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

pub(super) fn publish_staged<L, V>(
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

pub(super) fn reconcile_published<L, V>(
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
            Err(AttemptWorkerReconcileError::JournalCleanupPending {
                published: next,
                source: PreparedResultJournalError::Io { .. },
            }) => {
                published = *next;
                increment(&shared.counters.publication_retries);
                drop(executor);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(AttemptWorkerReconcileError::JournalCleanupPending {
                published: next, ..
            }) => {
                drop(executor);
                retain_forever(shared, next);
            }
            Err(_) => {
                drop(executor);
                shared.poison();
                return AttemptExecutionDisposition::Failed;
            }
        }
    }
}

pub(super) fn reconcile_worker_failure<L, V, W>(
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
            Err(
                AttemptWorkerReconcileError::Stopped { .. }
                | AttemptWorkerReconcileError::TerminalStopped { .. },
            )
            | Ok(()) => {
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
            Err(
                AttemptWorkerReconcileError::CompletionPending { published, .. }
                | AttemptWorkerReconcileError::JournalCleanupPending { published, .. },
            ) => {
                drop(executor);
                retain_forever(shared, published);
            }
        }
    }
}

pub(super) fn abort_prepared<L, V>(
    shared: &SharedExecutor<L, V>,
    mut prepared: PreparedAttemptResult,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = lock_or_retain(shared, &prepared);
        match abort_prepared_attempt_result(executor.supervisor_mut(), prepared) {
            Ok((_, completed)) => {
                drop(executor);
                cleanup_prepared_journal(shared, completed);
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

pub(super) fn abort_staged<L, V>(
    shared: &SharedExecutor<L, V>,
    mut staged: Box<StagedAttemptResult>,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = lock_or_retain(shared, &staged);
        match abort_staged_attempt_result(executor.supervisor_mut(), staged) {
            Ok((_, completed)) => {
                drop(executor);
                cleanup_staged_journal(shared, completed);
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

pub(super) fn abort_published<L, V>(
    shared: &SharedExecutor<L, V>,
    mut published: PublishedAttemptResult,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    loop {
        let mut executor = lock_or_retain(shared, &published);
        match abort_published_attempt_result(executor.supervisor_mut(), published) {
            Ok((_, completed)) => {
                drop(executor);
                cleanup_published_journal(shared, completed);
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

pub(super) trait PreparedJournalCleanup {
    fn remove_prepared_journal(&self) -> Result<(), PreparedResultJournalError>;
}

impl PreparedJournalCleanup for PreparedAttemptResult {
    fn remove_prepared_journal(&self) -> Result<(), PreparedResultJournalError> {
        self.remove_journal()
    }
}

impl PreparedJournalCleanup for Box<StagedAttemptResult> {
    fn remove_prepared_journal(&self) -> Result<(), PreparedResultJournalError> {
        self.remove_journal()
    }
}

impl PreparedJournalCleanup for PublishedAttemptResult {
    fn remove_prepared_journal(&self) -> Result<(), PreparedResultJournalError> {
        self.remove_journal()
    }
}

pub(super) fn cleanup_prepared_journal<L, V>(
    shared: &SharedExecutor<L, V>,
    prepared: PreparedAttemptResult,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    cleanup_journal(shared, prepared);
}

pub(super) fn cleanup_staged_journal<L, V>(
    shared: &SharedExecutor<L, V>,
    staged: Box<StagedAttemptResult>,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    cleanup_journal(shared, staged);
}

pub(super) fn cleanup_published_journal<L, V>(
    shared: &SharedExecutor<L, V>,
    published: PublishedAttemptResult,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    cleanup_journal(shared, published);
}

pub(super) fn cleanup_journal<L, V, T>(shared: &SharedExecutor<L, V>, token: T)
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
    T: PreparedJournalCleanup,
{
    loop {
        match token.remove_prepared_journal() {
            Ok(()) => return,
            Err(PreparedResultJournalError::Io { .. }) => {
                increment(&shared.counters.publication_retries);
                thread::sleep(WORKER_RETRY_INTERVAL);
            }
            Err(_) => retain_forever(shared, token),
        }
    }
}

pub(super) fn reconcile_panicked_worker<L, V>(
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
        shared.bump_ownership_revision();
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

pub(super) fn lock_or_retain<'a, L, V, T>(
    shared: &'a SharedExecutor<L, V>,
    token: &T,
) -> MutexGuard<'a, LocalExecutorCapabilityService<L, V>> {
    match shared.executor.lock() {
        Ok(executor) => {
            shared.bump_ownership_revision();
            executor
        }
        Err(poisoned) => {
            drop(poisoned.into_inner());
            retain_forever(shared, token);
        }
    }
}

pub(super) fn retain_forever<L, V, T>(shared: &SharedExecutor<L, V>, token: T) -> ! {
    shared.fail_closed();
    shared.completion.signal_retained();
    let _retained = token;
    loop {
        thread::park();
    }
}

pub(super) fn supervisor_error_is_retryable<E>(error: &LocalExecutorError<E>) -> bool {
    matches!(
        error,
        LocalExecutorError::Ledger(_)
            | LocalExecutorError::CompletionValidation {
                reason: CompletionValidationFailure::UnavailableInput,
            }
    )
}

pub(super) fn reconcile_worker_execution<L, V, W>(
    shared: &SharedExecutor<L, V>,
    worker: &mut W,
    disposition: AttemptExecutionDisposition,
) where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
    W: LocalAttemptWorker,
{
    loop {
        let reconciliation = worker.reconcile_execution(disposition);
        complete_native_checkpoint_cleanup(shared, worker.take_abandoned_native_checkpoint());
        match reconciliation {
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

pub(super) fn worker_reconcile_disposition(
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

pub(super) fn record_outcome<L, V>(
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

pub(super) fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
