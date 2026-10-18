//! Pre-teardown checkpoint publication through the original prepared actor.
//!
//! The handoff owns the same admission route and accepted queue identity used
//! by production execution. It stages native capture before teardown without
//! constructing another ledger or another resource reservation.

use super::*;

struct PreparedActorCheckpointHandoff<L, V> {
    admission: Arc<HostAdmission<L, V>>,
    checkpoints: Arc<ExactCheckpointStore>,
    queued: QueuedAttempt,
}

impl<L, V> std::fmt::Debug for PreparedActorCheckpointHandoff<L, V> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedActorCheckpointHandoff")
            .field("execution", &self.queued.execution())
            .finish_non_exhaustive()
    }
}

pub(super) fn install<L, V>(
    admission: Arc<HostAdmission<L, V>>,
    queued: &mut QueuedAttempt,
    checkpoints: Arc<ExactCheckpointStore>,
) where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    let handoff = PreparedActorCheckpointHandoff {
        admission,
        checkpoints,
        queued: queued.reconciliation_copy(),
    };
    queued.install_checkpoint_handoff(ExecutionCheckpointHandoff::new(Arc::new(handoff)));
}

impl<L, V> AttemptCheckpointHandoff for PreparedActorCheckpointHandoff<L, V>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    fn prepare_and_stage(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure> {
        let prepared = self
            .checkpoints
            .prepare_attempt_checkpoint_with_cancellation(capture, self.queued.cancellation())
            .map_err(|error| match error {
                crate::ExactCheckpointStoreError::Canceled => CheckpointHandoffFailure::Canceled,
                error if error.is_retryable() => CheckpointHandoffFailure::Retryable,
                _ => CheckpointHandoffFailure::Terminal,
            })?;

        let stage = self
            .admission
            .with_supervisor(|actor| {
                Ok(actor
                    .stage_checkpoint_publication_before_teardown(&self.queued, prepared.root()))
            })
            .map_err(|_| CheckpointHandoffFailure::Terminal)?
            .map_err(|error| {
                if supervisor_error_is_retryable(&error) {
                    CheckpointHandoffFailure::Retryable
                } else {
                    CheckpointHandoffFailure::Terminal
                }
            })?;
        match stage {
            CheckpointPublicationOutcome::Staged
            | CheckpointPublicationOutcome::AlreadyStaged
            | CheckpointPublicationOutcome::AlreadyPaused => Ok(prepared),
            CheckpointPublicationOutcome::NotCurrent
                if self.queued.cancellation().is_canceled() =>
            {
                Err(CheckpointHandoffFailure::Canceled)
            }
            CheckpointPublicationOutcome::NotCurrent => Err(CheckpointHandoffFailure::Terminal),
        }
    }
}
