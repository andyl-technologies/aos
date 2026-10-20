//! Non-authorizing recovery classification for lifecycle operations.

use super::{
    LifecycleAmbiguousResumeV1, LifecycleMethodSemanticCommitV1, LifecycleOperationV1,
    LifecyclePhaseV1, LifecycleStepStateV1, resume_ambiguous_attempt_v1,
};

/// Classifies safe recovery work without carrying an executable request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleRecoveryActionV1 {
    /// No automatic work remains.
    None,
    /// Preparation may resume after fresh expectations and authority.
    ResumePreparation,
    /// An ambiguous forward step must be reconciled from fresh inventory.
    ResolveForwardAmbiguity {
        /// Stable step index.
        step: u32,
        /// Exact attempt-local request, body, plan, admission, and evidence.
        attempt: LifecycleAmbiguousResumeV1,
    },
    /// An ambiguous compensation must be reconciled from fresh inventory.
    ResolveCompensationAmbiguity {
        /// Stable step index.
        step: u32,
        /// Exact compensation attempt and its inventory classification.
        attempt: LifecycleAmbiguousResumeV1,
    },
    /// The exact desired-state CAS must be revalidated before commit.
    RevalidateSemanticCommit,
    /// Post-commit work may resume under fresh broker plans.
    ResumeCommittedForward {
        /// Complete irreversible witness and method-family facts.
        commit: LifecycleMethodSemanticCommitV1,
    },
    /// Reverse compensation may resume under fresh broker plans.
    ResumeReverseCompensation,
    /// A failed pre-commit attempt may be retried only after its durable deadline.
    ResumePreCommitRetry {
        /// Stable step index whose latest failed attempt governs retry.
        step: u32,
        /// Exact failed attempt, including retry timing and prior admission.
        attempt: super::LifecycleEffectAttemptV1,
    },
    /// A failed reverse attempt may resume only after forward ambiguity is resolved.
    ResumePreCommitCompensationRetry {
        /// Stable step index whose reverse attempt governs retry.
        step: u32,
        /// Exact failed compensation attempt and retry admission.
        attempt: super::LifecycleEffectAttemptV1,
    },
    /// Residual cleanup may retry without changing committed semantics.
    ResumeResidualCleanup {
        /// Complete irreversible witness and method-family facts.
        commit: LifecycleMethodSemanticCommitV1,
        /// Stable post-commit step whose exact failed attempt may resume.
        step: u32,
        /// Exact failed attempt including request, admission, inventory, and retry.
        attempt: super::LifecycleEffectAttemptV1,
    },
    /// An operator must inspect blocked state.
    RequireOperatorReview {
        /// Retained irreversible witness when the block occurred after commit.
        commit: Option<LifecycleMethodSemanticCommitV1>,
    },
}

/// Classifies one replayed operation without creating effect authority.
///
/// Step identifiers select durable records only. A caller must obtain fresh
/// ownership, inventory, and broker authorization before external work.
#[must_use]
pub fn classify_operation_recovery_v1(
    operation: &LifecycleOperationV1,
) -> LifecycleRecoveryActionV1 {
    if let Some((step, attempt)) = operation.steps().iter().find_map(|step| {
        (step.state() == LifecycleStepStateV1::Applying)
            .then(|| step.forward_attempts().last().copied())
            .flatten()
            .and_then(|attempt| resume_ambiguous_attempt_v1(attempt).ok())
            .map(|attempt| (step.index(), attempt))
    }) {
        return LifecycleRecoveryActionV1::ResolveForwardAmbiguity { step, attempt };
    }
    if operation.method_semantic_commit().is_none() {
        if let Some((step, attempt)) = operation.steps().iter().find_map(|step| {
            (step.state() == LifecycleStepStateV1::Residual)
                .then(|| step.forward_attempts().last().copied())
                .flatten()
                .filter(|attempt| {
                    attempt.state() == super::LifecycleAttemptStateV1::Failed
                        && attempt.retry().is_some()
                })
                .map(|attempt| (step.index(), attempt))
        }) {
            return LifecycleRecoveryActionV1::ResumePreCommitRetry { step, attempt };
        }
    }
    if let Some((step, attempt)) = operation.steps().iter().rev().find_map(|step| {
        (step.state() == LifecycleStepStateV1::Compensating)
            .then(|| step.compensation_attempts().last().copied())
            .flatten()
            .and_then(|attempt| resume_ambiguous_attempt_v1(attempt).ok())
            .map(|attempt| (step.index(), attempt))
    }) {
        return LifecycleRecoveryActionV1::ResolveCompensationAmbiguity { step, attempt };
    }
    if operation.method_semantic_commit().is_none() {
        if let Some((step, attempt)) = operation.steps().iter().rev().find_map(|step| {
            (step.state() == LifecycleStepStateV1::Residual)
                .then(|| step.compensation_attempts().last().copied())
                .flatten()
                .filter(|attempt| {
                    attempt.state() == super::LifecycleAttemptStateV1::Failed
                        && attempt.retry().is_some()
                })
                .map(|attempt| (step.index(), attempt))
        }) {
            return LifecycleRecoveryActionV1::ResumePreCommitCompensationRetry { step, attempt };
        }
    }
    match operation.phase() {
        LifecyclePhaseV1::Accepted | LifecyclePhaseV1::Preparing => {
            LifecycleRecoveryActionV1::ResumePreparation
        }
        LifecyclePhaseV1::Prepared | LifecyclePhaseV1::ReadyToCommit => {
            LifecycleRecoveryActionV1::RevalidateSemanticCommit
        }
        LifecyclePhaseV1::Committed | LifecyclePhaseV1::Completing => {
            operation.method_semantic_commit().cloned().map_or_else(
                || LifecycleRecoveryActionV1::RequireOperatorReview { commit: None },
                |commit| LifecycleRecoveryActionV1::ResumeCommittedForward { commit },
            )
        }
        LifecyclePhaseV1::Compensating => LifecycleRecoveryActionV1::ResumeReverseCompensation,
        LifecyclePhaseV1::RetryWaiting => operation
            .steps()
            .iter()
            .find_map(|step| {
                (step.state() == LifecycleStepStateV1::Residual)
                    .then(|| {
                        step.forward_attempts()
                            .last()
                            .into_iter()
                            .chain(step.compensation_attempts().last())
                            .find(|attempt| {
                                attempt.state() == super::LifecycleAttemptStateV1::Failed
                                    && attempt.retry().is_some()
                            })
                            .copied()
                    })
                    .flatten()
                    .map(|attempt| LifecycleRecoveryActionV1::ResumePreCommitRetry {
                        step: step.index(),
                        attempt,
                    })
            })
            .unwrap_or_else(|| LifecycleRecoveryActionV1::RequireOperatorReview {
                commit: operation.method_semantic_commit().cloned(),
            }),
        LifecyclePhaseV1::Residual => operation
            .method_semantic_commit()
            .cloned()
            .zip(operation.steps().iter().find_map(|step| {
                (step.state() == LifecycleStepStateV1::Residual)
                    .then(|| {
                        step.forward_attempts()
                            .last()
                            .into_iter()
                            .chain(step.compensation_attempts().last())
                            .find(|attempt| {
                                attempt.state() == super::LifecycleAttemptStateV1::Failed
                                    && attempt.retry().is_some()
                            })
                            .copied()
                    })
                    .flatten()
                    .map(|attempt| (step.index(), attempt))
            }))
            .map_or_else(
                || LifecycleRecoveryActionV1::RequireOperatorReview {
                    commit: operation.method_semantic_commit().cloned(),
                },
                |(commit, (step, attempt))| LifecycleRecoveryActionV1::ResumeResidualCleanup {
                    commit,
                    step,
                    attempt,
                },
            ),
        LifecyclePhaseV1::PermanentlyBlocked => LifecycleRecoveryActionV1::RequireOperatorReview {
            commit: operation.method_semantic_commit().cloned(),
        },
        LifecyclePhaseV1::Terminal => LifecycleRecoveryActionV1::None,
    }
}
