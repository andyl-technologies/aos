//! Observation, finding, cancellation, and terminal publication.

use super::*;

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    /// Durably reserves the exact observation as an in-progress publication root.
    ///
    /// The operational ledger entry is established before immutable candidate
    /// bytes are written. GC therefore treats the observation closure as an
    /// in-progress root even across a daemon crash. The execution-model worker
    /// is considered physically stopped when this actor method is called.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for an invalid execution token, ledger
    /// failure, or a conflicting observation.
    pub fn stage_observation_publication(
        &mut self,
        queued: &QueuedAttempt,
        observation: ObservationId,
    ) -> Result<ObservationPublicationOutcome, LocalExecutorError<L::Error>> {
        self.stage_observation_publication_with_candidate(queued, observation, None)
    }

    /// Durably reserves an observation and finding candidate before publication.
    ///
    /// Both deterministic identities enter the same assignment-ledger state
    /// transition. The caller must compute and preflight them without writes,
    /// invoke this method, and only then publish either immutable closure. A
    /// crash therefore leaves the exact missing or complete candidate root for
    /// bounded restart recovery, while destructive GC fails closed on an
    /// incomplete closure.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for an invalid execution token, ledger
    /// failure, or a conflicting observation or finding candidate.
    pub fn stage_observation_and_finding_candidate_publication(
        &mut self,
        queued: &QueuedAttempt,
        observation: ObservationId,
        finding_candidate: crucible_campaign::FindingCandidateBundleId,
    ) -> Result<ObservationPublicationOutcome, LocalExecutorError<L::Error>> {
        self.stage_observation_publication_with_candidate(
            queued,
            observation,
            Some(finding_candidate),
        )
    }

    pub(super) fn stage_observation_publication_with_candidate(
        &mut self,
        queued: &QueuedAttempt,
        observation: ObservationId,
        finding_candidate: Option<crucible_campaign::FindingCandidateBundleId>,
    ) -> Result<ObservationPublicationOutcome, LocalExecutorError<L::Error>> {
        self.validate_pending_basis(queued)?;
        self.mark_worker_finished(queued.execution);
        let key = AttemptExecutionKey::for_request(&queued.request);
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        let Some(current) = current else {
            return Ok(ObservationPublicationOutcome::NotCurrent);
        };
        match current {
            AttemptRuntimeState::Running {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
            }
            | AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
            } if execution_basis == queued.request.execution_basis_digest()
                && daemon_epoch == self.daemon_epoch
                && execution == queued.execution =>
            {
                let next = AttemptRuntimeState::Publishing {
                    execution_basis,
                    origin,
                    daemon_epoch,
                    execution,
                    observation,
                    finding_candidate,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(ObservationPublicationOutcome::Staged)
            }
            AttemptRuntimeState::Publishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution: current_execution,
                observation: current_observation,
                finding_candidate: current_candidate,
                ..
            } if current_execution == queued.execution
                && current_observation == observation
                && current_candidate.is_none()
                && finding_candidate.is_some() =>
            {
                let next = AttemptRuntimeState::Publishing {
                    execution_basis,
                    origin,
                    daemon_epoch,
                    execution: current_execution,
                    observation,
                    finding_candidate,
                };
                let advance = self.advance_attempt(key, current, Some(next))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    return Err(LocalExecutorError::Ledger(error));
                }
                Ok(ObservationPublicationOutcome::Staged)
            }
            AttemptRuntimeState::Publishing {
                execution: current_execution,
                observation: current_observation,
                finding_candidate: current_candidate,
                ..
            } if current_execution == queued.execution
                && current_observation == observation
                && (finding_candidate.is_none() || current_candidate == finding_candidate) =>
            {
                Ok(ObservationPublicationOutcome::AlreadyStaged)
            }
            AttemptRuntimeState::Publishing {
                execution: current_execution,
                ..
            } if current_execution == queued.execution => {
                Err(LocalExecutorError::ConflictingCompletion)
            }
            AttemptRuntimeState::Completed {
                execution: current_execution,
                observation: current_observation,
                finding_candidate: current_candidate,
                ..
            } if current_execution == queued.execution
                && current_observation == observation
                && (finding_candidate.is_none()
                    || current_candidate.candidate() == finding_candidate) =>
            {
                self.release_active_if_present(queued.execution)?;
                Ok(ObservationPublicationOutcome::AlreadyCompleted)
            }
            AttemptRuntimeState::Canceled {
                execution: current_execution,
                ..
            } if current_execution == queued.execution => {
                self.release_active_if_present(queued.execution)?;
                Ok(ObservationPublicationOutcome::Canceled)
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
                Ok(ObservationPublicationOutcome::NotCurrent)
            }
        }
    }

    /// Stages an immutable observation and attempts durable completion reconciliation.
    ///
    /// A noncommitted ledger or validation failure retains the exact observation
    /// in bounded process-local state. The actor can retry it with
    /// [`Self::reconcile_pending_completion`] without re-running the guest.
    /// Commit-indeterminate ledger failures release capacity and clear the
    /// pending item after the ledger confirms the desired state.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for a conflicting staged observation,
    /// ledger failure, or semantic completion failure.
    pub fn stage_and_reconcile_completion(
        &mut self,
        queued: &QueuedAttempt,
        observation: ObservationId,
    ) -> Result<CompletionOutcome, LocalExecutorError<L::Error>> {
        let execution = queued.execution;
        let key = AttemptExecutionKey::for_request(&queued.request);
        let pending = PendingCompletion { key, observation };
        if self
            .pending_completions
            .get(&execution)
            .is_some_and(|current| *current != pending)
        {
            return Err(LocalExecutorError::ConflictingCompletion);
        }
        if !self.pending_completions.contains_key(&execution) {
            self.validate_pending_basis(queued)?;
            self.require_pending_capacity()?;
        }
        self.mark_worker_finished(execution);
        self.pending_completions.insert(execution, pending);
        self.reconcile_pending_completion(execution)?
            .ok_or(LocalExecutorError::LedgerInvariant {
                reason: "staged completion disappeared before reconciliation",
            })
    }

    /// Reconciles a published observation with its exact staged finding root.
    ///
    /// The worker calls this after publishing both immutable closures. The
    /// exact optional candidate is checked against the durable assignment
    /// state before the ordinary bounded completion operation is installed, so
    /// a recovered token cannot acknowledge a different staged root.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError::ConflictingCompletion`] when the current
    /// execution retains a different observation or finding candidate. Other
    /// ledger and semantic validation failures are returned unchanged.
    pub fn stage_and_reconcile_completion_with_finding_candidate(
        &mut self,
        queued: &QueuedAttempt,
        observation: ObservationId,
        finding_candidate: Option<FindingCandidateBundleId>,
    ) -> Result<CompletionOutcome, LocalExecutorError<L::Error>> {
        let key = AttemptExecutionKey::for_request(&queued.request);
        let current = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        match current {
            Some(AttemptRuntimeState::Publishing {
                execution,
                observation: current_observation,
                finding_candidate: current_candidate,
                ..
            }) if execution == queued.execution => {
                if current_observation != observation || current_candidate != finding_candidate {
                    return Err(LocalExecutorError::ConflictingCompletion);
                }
            }
            Some(AttemptRuntimeState::Completed {
                execution,
                observation: current_observation,
                finding_candidate: current_candidate,
                ..
            }) if execution == queued.execution => {
                if current_observation != observation
                    || current_candidate.candidate() != finding_candidate
                {
                    return Err(LocalExecutorError::ConflictingCompletion);
                }
            }
            Some(AttemptRuntimeState::Running { execution, .. })
            | Some(AttemptRuntimeState::CheckpointRequested { execution, .. })
                if execution == queued.execution =>
            {
                return Err(LocalExecutorError::LedgerInvariant {
                    reason: "exact completion was not staged before publication",
                });
            }
            Some(AttemptRuntimeState::CheckpointPublishing { .. })
            | Some(AttemptRuntimeState::Running { .. })
            | Some(AttemptRuntimeState::CheckpointRequested { .. })
            | Some(AttemptRuntimeState::Paused { .. })
            | Some(AttemptRuntimeState::CheckpointPromoting { .. })
            | Some(AttemptRuntimeState::Publishing { .. })
            | Some(AttemptRuntimeState::Completed { .. })
            | Some(AttemptRuntimeState::Canceled { .. })
            | Some(AttemptRuntimeState::TerminalFailure { .. })
            | None => {}
        }

        self.stage_and_reconcile_completion(queued, observation)
    }

    /// Retries one staged immutable observation without executing the guest again.
    ///
    /// Returns `Ok(None)` when no completion is staged for this execution.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] when durable or semantic completion
    /// reconciliation fails. A still-current failure leaves the item staged.
    pub fn reconcile_pending_completion(
        &mut self,
        execution: ExecutionId,
    ) -> Result<Option<CompletionOutcome>, LocalExecutorError<L::Error>> {
        let Some(pending) = self.pending_completions.get(&execution).copied() else {
            return Ok(None);
        };
        match self.complete_execution(pending.key, execution, pending.observation) {
            Ok(outcome) => {
                self.pending_completions.remove(&execution);
                Ok(Some(outcome))
            }
            Err(error) => {
                let retryable = matches!(
                    &error,
                    LocalExecutorError::Ledger(_)
                        | LocalExecutorError::CompletionValidation {
                            reason: CompletionValidationFailure::UnavailableInput,
                        }
                );
                if !retryable {
                    self.pending_completions.remove(&execution);
                    if self.active.contains_key(&execution) {
                        self.stage_cancellation(pending.key, execution)?;
                    }
                } else if !self.active.contains_key(&execution) {
                    // A compare-exchange error that nevertheless committed is
                    // confirmed by `complete_execution` releasing the active
                    // reservation; no retry remains necessary.
                    self.pending_completions.remove(&execution);
                }
                Err(error)
            }
        }
    }

    /// Stages a terminal worker stop and attempts durable cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] for a conflicting stop basis or ledger
    /// failure. A noncommitted failure remains available to
    /// [`Self::reconcile_pending_cancellation`].
    pub fn stage_and_reconcile_cancellation(
        &mut self,
        queued: &QueuedAttempt,
    ) -> Result<CancellationOutcome, LocalExecutorError<L::Error>> {
        let execution = queued.execution;
        let key = AttemptExecutionKey::for_request(&queued.request);
        if !self.pending_cancellations.contains_key(&execution) {
            self.validate_pending_basis(queued)?;
            self.require_pending_capacity()?;
        }
        self.mark_worker_finished(execution);
        self.stage_cancellation(key, execution)
    }

    /// Durably records a non-retryable worker failure and releases capacity.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] when the token does not match the current
    /// execution or the operational ledger cannot commit the terminal state.
    pub fn stage_and_reconcile_terminal_failure(
        &mut self,
        queued: &QueuedAttempt,
    ) -> Result<TerminalFailureOutcome, LocalExecutorError<L::Error>> {
        self.validate_pending_basis(queued)?;
        self.mark_worker_finished(queued.execution);

        let key = AttemptExecutionKey::for_request(&queued.request);
        self.fail_execution_terminally(key, queued.execution)
    }

    pub(super) fn stage_cancellation(
        &mut self,
        key: AttemptExecutionKey,
        execution: ExecutionId,
    ) -> Result<CancellationOutcome, LocalExecutorError<L::Error>> {
        if self
            .pending_cancellations
            .get(&execution)
            .is_some_and(|current| *current != key)
        {
            return Err(LocalExecutorError::LedgerInvariant {
                reason: "execution has a conflicting staged cancellation basis",
            });
        }
        self.pending_cancellations.insert(execution, key);
        self.reconcile_pending_cancellation(execution)?
            .ok_or(LocalExecutorError::LedgerInvariant {
                reason: "staged cancellation disappeared before reconciliation",
            })
    }

    /// Retries one staged terminal worker stop without re-running the guest.
    ///
    /// Returns `Ok(None)` when no cancellation is staged for this execution.
    ///
    /// # Errors
    ///
    /// Returns [`LocalExecutorError`] when ledger reconciliation fails. A
    /// still-current failure leaves the cancellation staged.
    pub fn reconcile_pending_cancellation(
        &mut self,
        execution: ExecutionId,
    ) -> Result<Option<CancellationOutcome>, LocalExecutorError<L::Error>> {
        let Some(key) = self.pending_cancellations.get(&execution).copied() else {
            return Ok(None);
        };
        match self.cancel_execution(key, execution) {
            Ok(outcome) => {
                self.pending_cancellations.remove(&execution);
                Ok(Some(outcome))
            }
            Err(error) => {
                if !self.active.contains_key(&execution) {
                    self.pending_cancellations.remove(&execution);
                }
                Err(error)
            }
        }
    }
}
