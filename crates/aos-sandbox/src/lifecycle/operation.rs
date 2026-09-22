//! Monotone lifecycle-operation and per-step transition checks.

use aos_sandbox_core::Revision;

use super::{
    LifecycleFailureV1, LifecycleMethodSemanticCommitV1, LifecycleModelError, LifecycleOperationV1,
    LifecyclePhaseV1, LifecycleRecordDigestV1, LifecycleRetryV1, LifecycleStepV1,
    LifecycleTerminalResultV1, LifecycleTimeV1,
};

pub(super) fn history_shape_is_valid(
    revision: Revision,
    phase: LifecyclePhaseV1,
    predecessor: Option<LifecycleRecordDigestV1>,
) -> bool {
    match (revision.get(), predecessor) {
        (1, None) => phase == LifecyclePhaseV1::Accepted,
        (value, Some(_)) => value > 1,
        _ => false,
    }
}

impl LifecycleOperationV1 {
    /// Constructs a validated successor without dispatching external work.
    ///
    /// Same-phase successors are permitted so attempts, inventory observations,
    /// retry schedules, and reverse compensation progress can be journaled. The
    /// semantic-commit witness may first appear only on `ReadyToCommit` to
    /// `Committed`; after that it must remain byte-for-byte identical.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError`] for a broken record chain, changed
    /// immutable intent, regressed step/progress state, invalid phase edge,
    /// removed/replaced semantic-commit witness, or failed bounded allocation.
    #[allow(clippy::too_many_arguments)]
    pub fn successor(
        &self,
        predecessor_digest: LifecycleRecordDigestV1,
        phase: LifecyclePhaseV1,
        forward_progress: u32,
        compensation_progress: u32,
        steps: Vec<LifecycleStepV1>,
        semantic_commit: Option<LifecycleMethodSemanticCommitV1>,
        failure: Option<LifecycleFailureV1>,
        retry: Option<LifecycleRetryV1>,
        terminal_result: Option<LifecycleTerminalResultV1>,
        finished_at: Option<LifecycleTimeV1>,
    ) -> Result<Self, LifecycleModelError> {
        let next_revision = self
            .record_revision()
            .checked_next()
            .map_err(|_| LifecycleModelError::InvalidTransition)?;
        let phase_edge = (!matches!(
            self.phase(),
            LifecyclePhaseV1::Terminal | LifecyclePhaseV1::PermanentlyBlocked
        ) && phase == self.phase())
            || matches!(
                (self.phase(), phase),
                (LifecyclePhaseV1::Accepted, LifecyclePhaseV1::Preparing)
                    | (LifecyclePhaseV1::Accepted, LifecyclePhaseV1::Compensating)
                    | (LifecyclePhaseV1::Accepted, LifecyclePhaseV1::Terminal)
                    | (LifecyclePhaseV1::Preparing, LifecyclePhaseV1::Prepared)
                    | (LifecyclePhaseV1::Preparing, LifecyclePhaseV1::Compensating)
                    | (LifecyclePhaseV1::Preparing, LifecyclePhaseV1::RetryWaiting)
                    | (
                        LifecyclePhaseV1::Preparing,
                        LifecyclePhaseV1::PermanentlyBlocked
                    )
                    | (LifecyclePhaseV1::Prepared, LifecyclePhaseV1::ReadyToCommit)
                    | (LifecyclePhaseV1::Prepared, LifecyclePhaseV1::Compensating)
                    | (LifecyclePhaseV1::ReadyToCommit, LifecyclePhaseV1::Committed)
                    | (
                        LifecyclePhaseV1::ReadyToCommit,
                        LifecyclePhaseV1::Compensating
                    )
                    | (LifecyclePhaseV1::Committed, LifecyclePhaseV1::Completing)
                    | (LifecyclePhaseV1::Committed, LifecyclePhaseV1::Terminal)
                    | (LifecyclePhaseV1::Committed, LifecyclePhaseV1::Residual)
                    | (
                        LifecyclePhaseV1::Committed,
                        LifecyclePhaseV1::PermanentlyBlocked
                    )
                    | (LifecyclePhaseV1::Completing, LifecyclePhaseV1::Terminal)
                    | (LifecyclePhaseV1::Completing, LifecyclePhaseV1::Residual)
                    | (
                        LifecyclePhaseV1::Completing,
                        LifecyclePhaseV1::PermanentlyBlocked
                    )
                    | (LifecyclePhaseV1::Compensating, LifecyclePhaseV1::Terminal)
                    | (
                        LifecyclePhaseV1::Compensating,
                        LifecyclePhaseV1::RetryWaiting
                    )
                    | (
                        LifecyclePhaseV1::Compensating,
                        LifecyclePhaseV1::PermanentlyBlocked
                    )
                    | (LifecyclePhaseV1::Residual, LifecyclePhaseV1::Completing)
                    | (LifecyclePhaseV1::Residual, LifecyclePhaseV1::Terminal)
                    | (
                        LifecyclePhaseV1::Residual,
                        LifecyclePhaseV1::PermanentlyBlocked
                    )
                    | (LifecyclePhaseV1::RetryWaiting, LifecyclePhaseV1::Preparing)
                    | (
                        LifecyclePhaseV1::RetryWaiting,
                        LifecyclePhaseV1::Compensating
                    )
                    | (
                        LifecyclePhaseV1::RetryWaiting,
                        LifecyclePhaseV1::PermanentlyBlocked
                    )
            );
        let commit_is_monotone = match (self.method_semantic_commit(), semantic_commit.as_ref()) {
            (Some(previous), Some(current)) => previous == current,
            (Some(_), None) => false,
            (None, Some(_)) => {
                self.phase() == LifecyclePhaseV1::ReadyToCommit
                    && phase == LifecyclePhaseV1::Committed
            }
            (None, None) => true,
        };
        let steps_are_monotone = steps.len() == self.steps().len()
            && steps
                .iter()
                .zip(self.steps())
                .all(|(current, previous)| current.can_follow(previous));
        let binds_unbound_plan = self.steps().iter().all(LifecycleStepV1::is_unbound);
        let binding_is_atomic = !binds_unbound_plan
            || (phase == LifecyclePhaseV1::Accepted
                && steps.iter().all(|step| !step.has_unbound_commitment())
                && forward_progress == self.forward_progress()
                && compensation_progress == self.compensation_progress()
                && semantic_commit.as_ref() == self.method_semantic_commit()
                && failure == self.failure()
                && retry == self.retry()
                && terminal_result == self.terminal_result()
                && finished_at == self.finished_at());
        let terminal_is_monotone = self
            .terminal_result()
            .is_none_or(|value| terminal_result == Some(value));
        let finish_is_monotone = self
            .finished_at()
            .is_none_or(|value| finished_at == Some(value));
        let makes_progress = phase != self.phase()
            || forward_progress != self.forward_progress()
            || compensation_progress != self.compensation_progress()
            || steps != self.steps()
            || semantic_commit.as_ref() != self.method_semantic_commit()
            || failure != self.failure()
            || retry != self.retry()
            || terminal_result != self.terminal_result()
            || finished_at != self.finished_at();
        if !phase_edge
            || !commit_is_monotone
            || !steps_are_monotone
            || !binding_is_atomic
            || !terminal_is_monotone
            || !finish_is_monotone
            || !makes_progress
            || forward_progress < self.forward_progress()
            || compensation_progress < self.compensation_progress()
        {
            return Err(LifecycleModelError::InvalidTransition);
        }

        let mut expectations = Vec::new();
        expectations
            .try_reserve_exact(self.expectations().len())
            .map_err(|_| LifecycleModelError::Allocation)?;
        expectations.extend_from_slice(self.expectations());
        Self::new(
            self.operation_id(),
            self.caller(),
            self.project(),
            self.idempotency(),
            self.intent().clone(),
            self.accepted_at(),
            Revision::new(next_revision.get()),
            expectations,
            steps,
            phase,
            forward_progress,
            compensation_progress,
            semantic_commit,
            failure,
            retry,
            terminal_result,
            finished_at,
            Some(predecessor_digest),
        )
        .map_err(|_| LifecycleModelError::InvalidTransition)
    }
}
