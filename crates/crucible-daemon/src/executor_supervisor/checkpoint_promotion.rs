//! Durable supervisor phases for paused-root replay-oracle promotion.

use crucible_campaign::{ExactCheckpointId, ExecutionId};

use super::{AttemptAdvance, LocalExecutorError, LocalExecutorSupervisor};
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionKey, AttemptRuntimeState,
};

/// Durable outcome of reserving a replay-validated paused-root replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointPromotionStageOutcome {
    /// The paused source advanced to a retained source/replacement pair.
    Staged,
    /// The exact source/replacement pair was already staged.
    AlreadyStaged,
    /// The replacement was already the complete paused root.
    AlreadyPromoted,
    /// The supplied execution or source root is no longer current.
    NotCurrent,
}

/// Idempotent result of completing or abandoning paused-root promotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointPromotionCompletionOutcome {
    /// The complete replacement became the paused resume root.
    Promoted,
    /// The replacement was already the complete paused resume root.
    AlreadyPromoted,
    /// A staged replacement was abandoned and the raw source restored.
    Reverted,
    /// The supplied execution or root pair is no longer current.
    NotCurrent,
}

/// Restart-recoverable identity of one staged paused-root promotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointPromotionRecovery {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    source: ExactCheckpointId,
    promoted: ExactCheckpointId,
}

impl CheckpointPromotionRecovery {
    /// Returns the exact lineage-qualified attempt key.
    #[must_use]
    pub const fn key(self) -> AttemptExecutionKey {
        self.key
    }

    /// Returns the execution that produced the paused source.
    #[must_use]
    pub const fn execution(self) -> ExecutionId {
        self.execution
    }

    /// Returns the retained raw source root.
    #[must_use]
    pub const fn source(self) -> ExactCheckpointId {
        self.source
    }

    /// Returns the retained expected replacement root.
    #[must_use]
    pub const fn promoted(self) -> ExactCheckpointId {
        self.promoted
    }
}

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    /// Loads one staged paused-root promotion for restart recovery.
    ///
    /// This is a short operational-ledger read. Immutable-root authentication
    /// and any replay rerun occur after the caller releases actor ownership.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError::Ledger`] when the durable record cannot be
    /// read safely.
    pub fn checkpoint_promotion_recovery(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<CheckpointPromotionRecovery>, LocalExecutorError<L::Error>> {
        let state = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        Ok(match state {
            Some(AttemptRuntimeState::CheckpointPromoting {
                execution,
                source_checkpoint,
                promoted_checkpoint,
                ..
            }) => Some(CheckpointPromotionRecovery {
                key,
                execution,
                source: source_checkpoint,
                promoted: promoted_checkpoint,
            }),
            Some(_) | None => None,
        })
    }

    /// Retains a replay-validated paused-root replacement before publication.
    ///
    /// The source must still be the exact complete paused root produced by
    /// `execution`. Both source and replacement become GC roots in the same
    /// durable CAS. No active execution reservation is created or released.
    pub(crate) fn stage_checkpoint_promotion(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        source_checkpoint: ExactCheckpointId,
        promoted_checkpoint: ExactCheckpointId,
    ) -> Result<CheckpointPromotionStageOutcome, LocalExecutorError<L::Error>> {
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CheckpointPromotionStageOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::Paused {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                checkpoint,
            } if current_execution == execution && checkpoint == source_checkpoint => {
                let next = AttemptRuntimeState::CheckpointPromoting {
                    execution_basis,
                    origin,
                    daemon_epoch,
                    execution,
                    source_checkpoint,
                    promoted_checkpoint,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CheckpointPromotionStageOutcome::Staged)
            }
            AttemptRuntimeState::CheckpointPromoting {
                execution: current_execution,
                source_checkpoint: current_source,
                promoted_checkpoint: current_promoted,
                ..
            } if current_execution == execution
                && current_source == source_checkpoint
                && current_promoted == promoted_checkpoint =>
            {
                Ok(CheckpointPromotionStageOutcome::AlreadyStaged)
            }
            AttemptRuntimeState::CheckpointPromoting {
                execution: current_execution,
                ..
            } if current_execution == execution => Err(LocalExecutorError::ConflictingCheckpoint),
            AttemptRuntimeState::Paused {
                execution: current_execution,
                checkpoint,
                ..
            } if current_execution == execution && checkpoint == promoted_checkpoint => {
                Ok(CheckpointPromotionStageOutcome::AlreadyPromoted)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => {
                Ok(CheckpointPromotionStageOutcome::NotCurrent)
            }
        }
    }

    /// Replaces one staged raw paused root with its complete promoted root.
    pub(crate) fn complete_checkpoint_promotion(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        source_checkpoint: ExactCheckpointId,
        promoted_checkpoint: ExactCheckpointId,
    ) -> Result<CheckpointPromotionCompletionOutcome, LocalExecutorError<L::Error>> {
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CheckpointPromotionCompletionOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::CheckpointPromoting {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                source_checkpoint: current_source,
                promoted_checkpoint: current_promoted,
            } if current_execution == execution
                && current_source == source_checkpoint
                && current_promoted == promoted_checkpoint =>
            {
                let next = AttemptRuntimeState::Paused {
                    execution_basis,
                    origin,
                    daemon_epoch,
                    execution,
                    checkpoint: promoted_checkpoint,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CheckpointPromotionCompletionOutcome::Promoted)
            }
            AttemptRuntimeState::Paused {
                execution: current_execution,
                checkpoint,
                ..
            } if current_execution == execution && checkpoint == promoted_checkpoint => {
                Ok(CheckpointPromotionCompletionOutcome::AlreadyPromoted)
            }
            AttemptRuntimeState::CheckpointPromoting {
                execution: current_execution,
                ..
            } if current_execution == execution => Err(LocalExecutorError::ConflictingCheckpoint),
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => {
                Ok(CheckpointPromotionCompletionOutcome::NotCurrent)
            }
        }
    }

    /// Abandons an incomplete promotion while retaining the authenticated source.
    pub(crate) fn revert_checkpoint_promotion(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
        source_checkpoint: ExactCheckpointId,
        promoted_checkpoint: ExactCheckpointId,
    ) -> Result<CheckpointPromotionCompletionOutcome, LocalExecutorError<L::Error>> {
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(CheckpointPromotionCompletionOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::CheckpointPromoting {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                source_checkpoint: current_source,
                promoted_checkpoint: current_promoted,
            } if current_execution == execution
                && current_source == source_checkpoint
                && current_promoted == promoted_checkpoint =>
            {
                let next = AttemptRuntimeState::Paused {
                    execution_basis,
                    origin,
                    daemon_epoch,
                    execution,
                    checkpoint: source_checkpoint,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(CheckpointPromotionCompletionOutcome::Reverted)
            }
            AttemptRuntimeState::Paused {
                execution: current_execution,
                checkpoint,
                ..
            } if current_execution == execution && checkpoint == source_checkpoint => {
                Ok(CheckpointPromotionCompletionOutcome::Reverted)
            }
            AttemptRuntimeState::CheckpointPromoting {
                execution: current_execution,
                ..
            } if current_execution == execution => Err(LocalExecutorError::ConflictingCheckpoint),
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. } => {
                Ok(CheckpointPromotionCompletionOutcome::NotCurrent)
            }
        }
    }
}
