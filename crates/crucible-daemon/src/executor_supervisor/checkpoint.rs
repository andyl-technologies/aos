//! Checkpoint requests, staging, and completion.

use super::*;

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
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
                origin,
                daemon_epoch,
                execution: current_execution,
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                let Some(active) = self.active.get(&execution) else {
                    return Ok(CheckpointRequestOutcome::NotCurrent);
                };
                if AttemptExecutionKey::for_request(&active.request) != key {
                    return Err(LocalExecutorError::LedgerInvariant {
                        reason: "checkpoint request attempt does not match active reservation",
                    });
                }
                let next = AttemptRuntimeState::CheckpointRequested {
                    execution_basis,
                    origin,
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
            AttemptRuntimeState::CheckpointPromoting {
                execution: current_execution,
                promoted_checkpoint,
                ..
            } if current_execution == execution => Ok(CheckpointRequestOutcome::Publishing {
                checkpoint: promoted_checkpoint,
            }),
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
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. }
            | AttemptRuntimeState::TerminalFailure { .. } => {
                Ok(CheckpointRequestOutcome::NotCurrent)
            }
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
        self.stage_checkpoint_publication_with_worker_state(queued, checkpoint, true)
    }

    /// Durably reserves an exact root while the guest worker is still live.
    ///
    /// Unlike [`Self::stage_checkpoint_publication`], idempotent terminal state
    /// does not release the active reservation. The modeled runner must first
    /// reap QEMU and return its linear token; the ordinary worker reconciliation
    /// phase then acknowledges physical exit and releases capacity.
    pub(crate) fn stage_checkpoint_publication_before_teardown(
        &mut self,
        queued: &QueuedAttempt,
        checkpoint: ExactCheckpointId,
    ) -> Result<CheckpointPublicationOutcome, LocalExecutorError<L::Error>> {
        self.stage_checkpoint_publication_with_worker_state(queued, checkpoint, false)
    }

    pub(super) fn stage_checkpoint_publication_with_worker_state(
        &mut self,
        queued: &QueuedAttempt,
        checkpoint: ExactCheckpointId,
        worker_finished: bool,
    ) -> Result<CheckpointPublicationOutcome, LocalExecutorError<L::Error>> {
        self.validate_pending_basis(queued)?;
        let key = AttemptExecutionKey::for_request(&queued.request);
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
                origin,
                daemon_epoch,
                execution,
            } if daemon_epoch == self.daemon_epoch && execution == queued.execution => {
                let next = AttemptRuntimeState::CheckpointPublishing {
                    execution_basis,
                    origin,
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
                if worker_finished {
                    self.mark_worker_finished(execution);
                    self.release_active_if_present(execution)?;
                }
                Ok(CheckpointPublicationOutcome::AlreadyPaused)
            }
            AttemptRuntimeState::Paused { execution, .. } if execution == queued.execution => {
                Err(LocalExecutorError::ConflictingCheckpoint)
            }
            AttemptRuntimeState::Completed { execution, .. }
            | AttemptRuntimeState::Canceled { execution, .. }
                if execution == queued.execution =>
            {
                if worker_finished {
                    self.mark_worker_finished(execution);
                    self.release_active_if_present(execution)?;
                }
                Ok(CheckpointPublicationOutcome::NotCurrent)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. }
            | AttemptRuntimeState::TerminalFailure { .. } => {
                Ok(CheckpointPublicationOutcome::NotCurrent)
            }
        }
    }

    /// Promotes a fully published root and releases a physically stopped worker.
    pub(crate) fn complete_checkpoint(
        &mut self,
        queued: &QueuedAttempt,
        checkpoint: ExactCheckpointId,
    ) -> Result<CheckpointCompletionOutcome, LocalExecutorError<L::Error>> {
        self.validate_pending_basis(queued)?;
        let key = AttemptExecutionKey::for_request(&queued.request);
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
                origin,
                daemon_epoch,
                execution,
                checkpoint: current_checkpoint,
            } if execution == queued.execution => {
                if current_checkpoint != checkpoint {
                    return Err(LocalExecutorError::ConflictingCheckpoint);
                }
                let next = AttemptRuntimeState::Paused {
                    execution_basis,
                    origin,
                    daemon_epoch,
                    execution,
                    checkpoint,
                    promotion_basis: Some(
                        crate::CheckpointPromotionExecutionBasis::new_for_start_mode(
                            queued.request.resources(),
                            queued.request.retention(),
                            queued.request.start_mode(),
                        ),
                    ),
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
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. }
            | AttemptRuntimeState::TerminalFailure { .. } => {
                Ok(CheckpointCompletionOutcome::NotCurrent)
            }
        }
    }
}
