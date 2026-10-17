//! Checkpoint publication, native retirement, and promotion admission.

use super::*;

pub(super) fn reconcile_checkpoint_result<L, V>(
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
                let retirement = prepared.native_retirement();
                drop(prepared);
                retire_native_checkpoint_source(shared, retirement);
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

pub(super) fn observe_promoted_checkpoint<L, V>(
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
