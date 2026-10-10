//! Active execution completion and cancellation.

use super::*;

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    pub(super) fn validate_pending_basis(
        &self,
        queued: &QueuedAttempt,
    ) -> Result<(), LocalExecutorError<L::Error>> {
        let key = AttemptExecutionKey::for_request(&queued.request);
        let basis = queued.request.execution_basis_digest();
        let active_matches = self.active.get(&queued.execution).is_some_and(|active| {
            active.request == queued.request
                && active.origin == queued.origin
                && AttemptExecutionKey::for_request(&active.request) == key
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
                    ..
                }
                | AttemptRuntimeState::CheckpointRequested {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    ..
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
                    ..
                }
                | AttemptRuntimeState::TerminalFailure {
                    execution_basis,
                    daemon_epoch,
                    execution,
                    ..
                } => {
                    execution_basis == basis
                        && execution == queued.execution
                        && daemon_epoch == queued.request.daemon_epoch()
                        && daemon_epoch == self.daemon_epoch
                        && state.origin() == queued.origin
                }
                AttemptRuntimeState::CheckpointPromoting { .. } => false,
            });
        if !durable_matches {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "pending reconciliation has no exact execution reservation",
            });
        }
        Ok(())
    }

    pub(super) fn require_pending_capacity(&self) -> Result<(), LocalExecutorError<L::Error>> {
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

    pub(super) fn mark_worker_finished(&mut self, execution: ExecutionId) {
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
                origin,
                daemon_epoch,
                execution: current_execution,
                observation: staged_observation,
                finding_candidate,
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                if staged_observation != observation {
                    return Err(LocalExecutorError::ConflictingCompletion);
                }
                let Some(active) = self.active.get(&execution) else {
                    return Ok(CompletionOutcome::NotCurrent);
                };
                if AttemptExecutionKey::for_request(&active.request) != key {
                    return Err(LocalExecutorError::LedgerInvariant {
                        reason: "active execution attempt mismatch",
                    });
                }
                self.validator
                    .validate_completion_artifacts(&active.request, observation, finding_candidate)
                    .map_err(|reason| LocalExecutorError::CompletionValidation { reason })?;
                let next = AttemptRuntimeState::Completed {
                    execution_basis,
                    origin,
                    daemon_epoch,
                    execution,
                    observation,
                    finding_candidate: CompletedFindingCandidate::pending(finding_candidate),
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
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. }
            | AttemptRuntimeState::TerminalFailure { .. } => Ok(CompletionOutcome::NotCurrent),
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
            && AttemptExecutionKey::for_request(&active.request) == key
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
                origin,
                daemon_epoch,
                execution: current_execution,
            }
            | AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
            }
            | AttemptRuntimeState::CheckpointPublishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                ..
            }
            | AttemptRuntimeState::Paused {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                ..
            }
            | AttemptRuntimeState::CheckpointPromoting {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                ..
            }
            | AttemptRuntimeState::Publishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                ..
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                let next = AttemptRuntimeState::Canceled {
                    execution_basis,
                    origin,
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
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. }
            | AttemptRuntimeState::TerminalFailure { .. } => Ok(CancellationOutcome::NotCurrent),
        }
    }

    pub(super) fn fail_execution_terminally(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
    ) -> Result<TerminalFailureOutcome, LocalExecutorError<L::Error>> {
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(TerminalFailureOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::TerminalFailure {
                execution: current_execution,
                ..
            } if current_execution == execution => {
                self.release_active_if_idle(execution)?;
                Ok(TerminalFailureOutcome::AlreadyFailed)
            }
            AttemptRuntimeState::Running {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
            }
            | AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
            }
            | AttemptRuntimeState::CheckpointPublishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                ..
            }
            | AttemptRuntimeState::Paused {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                ..
            }
            | AttemptRuntimeState::CheckpointPromoting {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                ..
            }
            | AttemptRuntimeState::Publishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                ..
            } if daemon_epoch == self.daemon_epoch && current_execution == execution => {
                let next = AttemptRuntimeState::TerminalFailure {
                    execution_basis,
                    origin,
                    daemon_epoch,
                    execution,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                self.release_active_if_idle(execution)?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(TerminalFailureOutcome::Failed)
            }
            AttemptRuntimeState::Running { .. }
            | AttemptRuntimeState::CheckpointRequested { .. }
            | AttemptRuntimeState::CheckpointPublishing { .. }
            | AttemptRuntimeState::Paused { .. }
            | AttemptRuntimeState::CheckpointPromoting { .. }
            | AttemptRuntimeState::Publishing { .. }
            | AttemptRuntimeState::Completed { .. }
            | AttemptRuntimeState::Canceled { .. }
            | AttemptRuntimeState::TerminalFailure { .. } => Ok(TerminalFailureOutcome::NotCurrent),
        }
    }
}
