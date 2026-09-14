//! Closed, non-authorizing data model for lifecycle transactions.
//!
//! Lifecycle records separate immutable request intent, reversible preparation,
//! the atomic desired-state commit, and forward cleanup. A semantic commit is a
//! monotone witness: no successor may remove or replace it, even when the
//! operation later becomes residual or permanently blocked.

use super::attempt::{
    LifecycleAttemptHistoryV1, LifecycleAttemptStateV1, LifecycleEffectAttemptV1,
    LifecycleEffectDirectionV1, MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP,
};
pub use super::digest::{
    DesiredStateCasDigestV1, DesiredStateDocumentDigestV1, LifecycleFailureDigestV1,
    LifecycleIdempotencyDigestV1, LifecycleInventoryDigestV1, LifecycleJournalCommitDigestV1,
    LifecycleNormalizedRequestDigestV1, LifecycleRecordDigestV1, LifecycleResourceStateDigestV1,
    LifecycleSemanticCommitDigestV1, LifecycleStepAdmissionDigestV1, LifecycleStepBodyDigestV1,
    LifecycleStepPlanDigestV1, LifecycleStepRequestDigestV1, LifecycleStepResultDigestV1,
};
use super::intent::{
    DesiredStateCasV1, LifecycleFailureV1, LifecycleIntentV1, LifecycleMethodV1,
    LifecycleResourceV1, LifecycleRetryV1, LifecycleStepClassV1, LifecycleStepDomainV1,
    LifecycleStepStateV1, LifecycleTimeV1, ResourceExpectationV1, ResourceExpectedStateV1,
};
use super::projection::LifecycleModelError;
use super::semantic::LifecycleMethodSemanticCommitV1;
use aos_sandbox_core::{
    DesiredGeneration, ObjectDigest, OperationId, PrincipalId, ProjectId, Revision, SandboxId,
};

/// Maximum resources fenced by one lifecycle operation.
pub const MAXIMUM_LIFECYCLE_EXPECTATIONS: usize = 4_096;
/// Maximum steps retained by one lifecycle operation.
pub const MAXIMUM_LIFECYCLE_STEPS: usize = 4_096;
/// Retains immutable plan data and monotone progress for one step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleStepV1 {
    index: u32,
    class: LifecycleStepClassV1,
    domain: LifecycleStepDomainV1,
    request: LifecycleStepRequestDigestV1,
    request_body: LifecycleStepBodyDigestV1,
    plan: LifecycleStepPlanDigestV1,
    compensation_request: Option<LifecycleStepRequestDigestV1>,
    compensation_body: Option<LifecycleStepBodyDigestV1>,
    compensation_plan: Option<LifecycleStepPlanDigestV1>,
    state: LifecycleStepStateV1,
    forward_attempts: Vec<LifecycleEffectAttemptV1>,
    compensation_attempts: Vec<LifecycleEffectAttemptV1>,
    result: Option<LifecycleStepResultDigestV1>,
    compensation_result: Option<LifecycleStepResultDigestV1>,
    inventory: Option<LifecycleInventoryDigestV1>,
    failure: Option<LifecycleFailureV1>,
    retry: Option<LifecycleRetryV1>,
}

impl LifecycleStepV1 {
    /// Constructs a complete step snapshot under closed progress invariants.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for inconsistent fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: u32,
        class: LifecycleStepClassV1,
        domain: LifecycleStepDomainV1,
        request: LifecycleStepRequestDigestV1,
        request_body: LifecycleStepBodyDigestV1,
        plan: LifecycleStepPlanDigestV1,
        compensation_request: Option<LifecycleStepRequestDigestV1>,
        compensation_body: Option<LifecycleStepBodyDigestV1>,
        compensation_plan: Option<LifecycleStepPlanDigestV1>,
        state: LifecycleStepStateV1,
        forward_attempts: Vec<LifecycleEffectAttemptV1>,
        compensation_attempts: Vec<LifecycleEffectAttemptV1>,
        result: Option<LifecycleStepResultDigestV1>,
        compensation_result: Option<LifecycleStepResultDigestV1>,
        inventory: Option<LifecycleInventoryDigestV1>,
        failure: Option<LifecycleFailureV1>,
        retry: Option<LifecycleRetryV1>,
    ) -> Result<Self, LifecycleModelError> {
        let compensation_shape = match class {
            LifecycleStepClassV1::PreCommitReversible => {
                compensation_request.is_some()
                    && compensation_body.is_some()
                    && compensation_plan.is_some()
            }
            LifecycleStepClassV1::PostCommitForward => {
                compensation_request.is_none()
                    && compensation_body.is_none()
                    && compensation_plan.is_none()
            }
        };
        let bounded = forward_attempts.len() <= MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP
            && compensation_attempts.len() <= MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP;
        let forward_history = LifecycleAttemptHistoryV1::new(
            LifecycleEffectDirectionV1::Forward,
            request,
            request_body,
            plan,
            forward_attempts.clone(),
        );
        let compensation_history =
            match (compensation_request, compensation_body, compensation_plan) {
                (Some(request), Some(body), Some(plan)) => LifecycleAttemptHistoryV1::new(
                    LifecycleEffectDirectionV1::Compensation,
                    request,
                    body,
                    plan,
                    compensation_attempts.clone(),
                ),
                (None, None, None) if compensation_attempts.is_empty() => {
                    LifecycleAttemptHistoryV1::new(
                        LifecycleEffectDirectionV1::Compensation,
                        request,
                        request_body,
                        plan,
                        Vec::new(),
                    )
                }
                _ => Err(LifecycleModelError::InvalidModel),
            };
        let forward_latest = forward_attempts.last().copied();
        let compensation_latest = compensation_attempts.last().copied();
        let active_latest = compensation_latest.or(forward_latest);
        let aggregate_evidence_matches = result
            == forward_latest.and_then(|attempt| attempt.result())
            && compensation_result == compensation_latest.and_then(|attempt| attempt.result())
            && inventory == active_latest.and_then(|attempt| attempt.inventory())
            && failure == active_latest.and_then(|attempt| attempt.failure())
            && retry == active_latest.and_then(|attempt| attempt.retry());
        let progress = match state {
            LifecycleStepStateV1::Planned => {
                forward_attempts.is_empty()
                    && compensation_attempts.is_empty()
                    && result.is_none()
                    && compensation_result.is_none()
                    && inventory.is_none()
                    && failure.is_none()
                    && retry.is_none()
            }
            LifecycleStepStateV1::Applying => {
                forward_latest.is_some_and(|attempt| {
                    matches!(
                        attempt.state(),
                        LifecycleAttemptStateV1::Reserved | LifecycleAttemptStateV1::Ambiguous
                    )
                }) && compensation_attempts.is_empty()
                    && result.is_none()
                    && compensation_result.is_none()
            }
            LifecycleStepStateV1::Applied => {
                forward_latest
                    .is_some_and(|attempt| attempt.state() == LifecycleAttemptStateV1::Succeeded)
                    && compensation_attempts.is_empty()
                    && result.is_some()
                    && compensation_result.is_none()
                    && inventory.is_some()
            }
            LifecycleStepStateV1::Compensating => {
                class == LifecycleStepClassV1::PreCommitReversible
                    && forward_latest.is_some_and(|attempt| {
                        attempt.state() == LifecycleAttemptStateV1::Succeeded
                    })
                    && result.is_some()
                    && compensation_latest.is_some_and(|attempt| {
                        matches!(
                            attempt.state(),
                            LifecycleAttemptStateV1::Reserved | LifecycleAttemptStateV1::Ambiguous
                        )
                    })
                    && compensation_result.is_none()
            }
            LifecycleStepStateV1::Compensated => {
                class == LifecycleStepClassV1::PreCommitReversible
                    && forward_latest.is_some_and(|attempt| {
                        attempt.state() == LifecycleAttemptStateV1::Succeeded
                    })
                    && result.is_some()
                    && compensation_latest.is_some_and(|attempt| {
                        attempt.state() == LifecycleAttemptStateV1::Succeeded
                    })
                    && compensation_result.is_some()
                    && inventory.is_some()
            }
            LifecycleStepStateV1::Residual => active_latest
                .is_some_and(|attempt| attempt.state() == LifecycleAttemptStateV1::Failed),
            LifecycleStepStateV1::PermanentlyBlocked => active_latest.is_some_and(|attempt| {
                attempt.state() == LifecycleAttemptStateV1::PermanentlyBlocked
            }),
            LifecycleStepStateV1::Canceled => {
                class == LifecycleStepClassV1::PreCommitReversible
                    && compensation_attempts.is_empty()
                    && forward_latest.is_some_and(|attempt| {
                        attempt.state() == LifecycleAttemptStateV1::Failed
                            && attempt.retry().is_some()
                    })
            }
        };
        let retry_time_is_valid = match (failure, retry) {
            (_, None) => true,
            (Some(failure), Some(retry)) => retry.not_before() >= failure.observed_at(),
            (None, Some(_)) => false,
        };
        if !compensation_shape
            || !bounded
            || forward_history.is_err()
            || compensation_history.is_err()
            || !aggregate_evidence_matches
            || !progress
            || !retry_time_is_valid
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            index,
            class,
            domain,
            request,
            request_body,
            plan,
            compensation_request,
            compensation_body,
            compensation_plan,
            state,
            forward_attempts,
            compensation_attempts,
            result,
            compensation_result,
            inventory,
            failure,
            retry,
        })
    }

    /// Returns stable index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }
    /// Returns class.
    #[must_use]
    pub const fn class(&self) -> LifecycleStepClassV1 {
        self.class
    }
    /// Returns domain.
    #[must_use]
    pub const fn domain(&self) -> LifecycleStepDomainV1 {
        self.domain
    }
    /// Returns logical request commitment.
    #[must_use]
    pub const fn request(&self) -> LifecycleStepRequestDigestV1 {
        self.request
    }
    /// Returns exact request body commitment.
    #[must_use]
    pub const fn request_body(&self) -> LifecycleStepBodyDigestV1 {
        self.request_body
    }
    /// Returns selected plan commitment.
    #[must_use]
    pub const fn plan(&self) -> LifecycleStepPlanDigestV1 {
        self.plan
    }
    /// Returns compensation request commitment.
    #[must_use]
    pub const fn compensation_request(&self) -> Option<LifecycleStepRequestDigestV1> {
        self.compensation_request
    }
    /// Returns compensation body commitment.
    #[must_use]
    pub const fn compensation_body(&self) -> Option<LifecycleStepBodyDigestV1> {
        self.compensation_body
    }
    /// Returns compensation plan commitment.
    #[must_use]
    pub const fn compensation_plan(&self) -> Option<LifecycleStepPlanDigestV1> {
        self.compensation_plan
    }
    /// Returns durable state.
    #[must_use]
    pub const fn state(&self) -> LifecycleStepStateV1 {
        self.state
    }
    /// Returns forward attempts.
    #[must_use]
    pub fn forward_attempts(&self) -> &[LifecycleEffectAttemptV1] {
        &self.forward_attempts
    }
    /// Returns compensation attempts.
    #[must_use]
    pub fn compensation_attempts(&self) -> &[LifecycleEffectAttemptV1] {
        &self.compensation_attempts
    }
    /// Returns forward result commitment.
    #[must_use]
    pub const fn result(&self) -> Option<LifecycleStepResultDigestV1> {
        self.result
    }
    /// Returns compensation result commitment.
    #[must_use]
    pub const fn compensation_result(&self) -> Option<LifecycleStepResultDigestV1> {
        self.compensation_result
    }
    /// Returns inventory commitment.
    #[must_use]
    pub const fn inventory(&self) -> Option<LifecycleInventoryDigestV1> {
        self.inventory
    }
    /// Returns failure.
    #[must_use]
    pub const fn failure(&self) -> Option<LifecycleFailureV1> {
        self.failure
    }
    /// Returns retry schedule.
    #[must_use]
    pub const fn retry(&self) -> Option<LifecycleRetryV1> {
        self.retry
    }

    /// Marks one exact retryable failed forward attempt canceled.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidTransition`] unless this is a
    /// reversible forward residual with no compensation attempt.
    pub fn cancel_retryable_forward(&self) -> Result<Self, LifecycleModelError> {
        if self.state != LifecycleStepStateV1::Residual
            || self.class != LifecycleStepClassV1::PreCommitReversible
            || !self.compensation_attempts.is_empty()
            || self.forward_attempts.last().is_none_or(|attempt| {
                attempt.state() != LifecycleAttemptStateV1::Failed || attempt.retry().is_none()
            })
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        Self::new(
            self.index,
            self.class,
            self.domain,
            self.request,
            self.request_body,
            self.plan,
            self.compensation_request,
            self.compensation_body,
            self.compensation_plan,
            LifecycleStepStateV1::Canceled,
            self.forward_attempts.clone(),
            self.compensation_attempts.clone(),
            self.result,
            self.compensation_result,
            self.inventory,
            self.failure,
            self.retry,
        )
        .map_err(|_| LifecycleModelError::InvalidTransition)
    }

    pub(super) fn can_follow(&self, old: &Self) -> bool {
        let immutable = self.index == old.index
            && self.class == old.class
            && self.domain == old.domain
            && self.request == old.request
            && self.request_body == old.request_body
            && self.plan == old.plan
            && self.compensation_request == old.compensation_request
            && self.compensation_body == old.compensation_body
            && self.compensation_plan == old.compensation_plan;
        let forward_history = LifecycleAttemptHistoryV1::new(
            LifecycleEffectDirectionV1::Forward,
            self.request,
            self.request_body,
            self.plan,
            self.forward_attempts.clone(),
        );
        let old_forward_history = LifecycleAttemptHistoryV1::new(
            LifecycleEffectDirectionV1::Forward,
            old.request,
            old.request_body,
            old.plan,
            old.forward_attempts.clone(),
        );
        let compensation_history = self
            .compensation_request
            .zip(self.compensation_body)
            .zip(self.compensation_plan)
            .and_then(|((request, body), plan)| {
                LifecycleAttemptHistoryV1::new(
                    LifecycleEffectDirectionV1::Compensation,
                    request,
                    body,
                    plan,
                    self.compensation_attempts.clone(),
                )
                .ok()
            });
        let old_compensation_history = old
            .compensation_request
            .zip(old.compensation_body)
            .zip(old.compensation_plan)
            .and_then(|((request, body), plan)| {
                LifecycleAttemptHistoryV1::new(
                    LifecycleEffectDirectionV1::Compensation,
                    request,
                    body,
                    plan,
                    old.compensation_attempts.clone(),
                )
                .ok()
            });
        let attempts_are_monotone = matches!(
            (forward_history, old_forward_history),
            (Ok(current), Ok(previous)) if current.can_follow(&previous)
        ) && match (compensation_history, old_compensation_history) {
            (Some(current), Some(previous)) => current.can_follow(&previous),
            (None, None) => {
                self.compensation_attempts.is_empty() && old.compensation_attempts.is_empty()
            }
            _ => false,
        };
        let edge = self.state == old.state
            || matches!(
                (old.state, self.state),
                (
                    LifecycleStepStateV1::Planned,
                    LifecycleStepStateV1::Applying
                ) | (
                    LifecycleStepStateV1::Applying,
                    LifecycleStepStateV1::Applied
                        | LifecycleStepStateV1::Residual
                        | LifecycleStepStateV1::PermanentlyBlocked
                ) | (
                    LifecycleStepStateV1::Applied,
                    LifecycleStepStateV1::Compensating
                ) | (
                    LifecycleStepStateV1::Compensating,
                    LifecycleStepStateV1::Compensated
                        | LifecycleStepStateV1::Residual
                        | LifecycleStepStateV1::PermanentlyBlocked
                ) | (
                    LifecycleStepStateV1::Residual,
                    LifecycleStepStateV1::Applying
                        | LifecycleStepStateV1::Compensating
                        | LifecycleStepStateV1::PermanentlyBlocked
                        | LifecycleStepStateV1::Canceled
                )
            );
        immutable && attempts_are_monotone && edge
    }
}

fn option_is_monotone<T: Copy + Eq>(old: Option<T>, new: Option<T>) -> bool {
    old.is_none_or(|value| new == Some(value))
}

/// Describes coordinator phase independently of semantic commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecyclePhaseV1 {
    /// Request and expectations are durable.
    Accepted = 1,
    /// Reversible preparation is progressing.
    Preparing = 2,
    /// Reversible preparation is complete.
    Prepared = 3,
    /// The desired-state CAS is ready.
    ReadyToCommit = 4,
    /// The desired-state CAS committed.
    Committed = 5,
    /// Post-commit forward work is progressing.
    Completing = 6,
    /// Pre-commit work is compensating in reverse.
    Compensating = 7,
    /// No further work remains.
    Terminal = 8,
    /// A failed pre-commit attempt is waiting for retry admission.
    RetryWaiting = 9,
    /// Retryable cleanup remains.
    Residual = 10,
    /// Safe automatic progress is impossible.
    PermanentlyBlocked = 11,
}

/// Selects one narrow terminal outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleTerminalResultV1 {
    /// Commit and forward completion succeeded.
    Succeeded = 1,
    /// Failure compensated before commit.
    FailedBeforeCommit = 2,
    /// Cancellation compensated before commit.
    CanceledBeforeCommit = 3,
    /// Progress became blocked before commit.
    BlockedBeforeCommit = 4,
    /// Progress became blocked after commit.
    BlockedAfterCommit = 5,
}

/// Proves that one exact desired-state CAS crossed semantic commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleSemanticCommitV1 {
    sequence: u64,
    desired_state_cas: DesiredStateCasV1,
    journal_commit_digest: LifecycleJournalCommitDigestV1,
    committed_at: LifecycleTimeV1,
}

impl LifecycleSemanticCommitV1 {
    /// Constructs an irreversible semantic-commit witness.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel fields.
    pub fn new(
        sequence: u64,
        desired_state_cas: DesiredStateCasV1,
        journal_commit_digest: LifecycleJournalCommitDigestV1,
        committed_at: LifecycleTimeV1,
    ) -> Result<Self, LifecycleModelError> {
        if sequence == 0 || sequence == u64::MAX {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                sequence,
                desired_state_cas,
                journal_commit_digest,
                committed_at,
            })
        }
    }
    /// Returns commit sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Returns desired-state CAS commitment.
    #[must_use]
    pub const fn desired_state_cas(self) -> DesiredStateCasV1 {
        self.desired_state_cas
    }
    /// Returns containing atomic journal commitment.
    #[must_use]
    pub const fn journal_commit_digest(self) -> LifecycleJournalCommitDigestV1 {
        self.journal_commit_digest
    }
    /// Returns commit time.
    #[must_use]
    pub const fn committed_at(self) -> LifecycleTimeV1 {
        self.committed_at
    }
    /// Returns purpose-separated witness commitment.
    #[must_use]
    pub fn witness_digest(self) -> LifecycleSemanticCommitDigestV1 {
        let mut bytes = [0_u8; 178];
        bytes[..8].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[8] = self.desired_state_cas.resource().code();
        bytes[9..25].copy_from_slice(self.desired_state_cas.resource().as_bytes());
        bytes[25..33].copy_from_slice(
            &self
                .desired_state_cas
                .expected_generation()
                .get()
                .to_be_bytes(),
        );
        bytes[33] = u8::from(self.desired_state_cas.expected_state().is_some());
        bytes[34..66].copy_from_slice(
            self.desired_state_cas
                .expected_state()
                .map_or(ObjectDigest::from_bytes([0; 32]), |digest| digest.digest())
                .as_bytes(),
        );
        bytes[66..74].copy_from_slice(
            &self
                .desired_state_cas
                .successor_generation()
                .get()
                .to_be_bytes(),
        );
        bytes[74..106].copy_from_slice(self.desired_state_cas.desired_state().digest().as_bytes());
        bytes[106..138].copy_from_slice(self.desired_state_cas.digest().digest().as_bytes());
        bytes[138..170].copy_from_slice(self.journal_commit_digest.digest().as_bytes());
        bytes[170..178].copy_from_slice(&self.committed_at.get().to_be_bytes());
        LifecycleSemanticCommitDigestV1::commit(&bytes)
    }
}

/// Stores one complete immutable-intent and monotone-progress snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleOperationV1 {
    operation_id: OperationId,
    caller: PrincipalId,
    project: ProjectId,
    idempotency: LifecycleIdempotencyDigestV1,
    normalized_request: LifecycleNormalizedRequestDigestV1,
    intent: LifecycleIntentV1,
    accepted_at: LifecycleTimeV1,
    record_revision: Revision,
    expectations: Vec<ResourceExpectationV1>,
    steps: Vec<LifecycleStepV1>,
    phase: LifecyclePhaseV1,
    forward_progress: u32,
    compensation_progress: u32,
    semantic_commit: Option<LifecycleMethodSemanticCommitV1>,
    failure: Option<LifecycleFailureV1>,
    retry: Option<LifecycleRetryV1>,
    terminal_result: Option<LifecycleTerminalResultV1>,
    finished_at: Option<LifecycleTimeV1>,
    predecessor_digest: Option<LifecycleRecordDigestV1>,
}

impl LifecycleOperationV1 {
    /// Constructs a complete lifecycle record under all closed invariants.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for non-canonical or inconsistent state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: OperationId,
        caller: PrincipalId,
        project: ProjectId,
        idempotency: LifecycleIdempotencyDigestV1,
        intent: LifecycleIntentV1,
        accepted_at: LifecycleTimeV1,
        record_revision: Revision,
        expectations: Vec<ResourceExpectationV1>,
        steps: Vec<LifecycleStepV1>,
        phase: LifecyclePhaseV1,
        forward_progress: u32,
        compensation_progress: u32,
        semantic_commit: Option<LifecycleMethodSemanticCommitV1>,
        failure: Option<LifecycleFailureV1>,
        retry: Option<LifecycleRetryV1>,
        terminal_result: Option<LifecycleTerminalResultV1>,
        finished_at: Option<LifecycleTimeV1>,
        predecessor_digest: Option<LifecycleRecordDigestV1>,
    ) -> Result<Self, LifecycleModelError> {
        if operation_id.as_bytes() == &[0; 16]
            || caller.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || record_revision.get() == 0
            || record_revision.get() == u64::MAX
            || expectations.is_empty()
            || expectations.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || steps.is_empty()
            || steps.len() > MAXIMUM_LIFECYCLE_STEPS
            || !expectations
                .windows(2)
                .all(|p| p[0].resource() < p[1].resource())
            || !steps
                .iter()
                .enumerate()
                .all(|(i, s)| usize::try_from(s.index()).ok() == Some(i))
            || !steps_are_partitioned(&steps)
            || steps.iter().any(|step| {
                step.forward_attempts()
                    .iter()
                    .chain(step.compensation_attempts())
                    .any(|attempt| {
                        attempt.started_at() < accepted_at
                            || attempt
                                .observed_at()
                                .is_some_and(|value| value < accepted_at)
                            || attempt
                                .retry()
                                .is_some_and(|value| value.not_before() < accepted_at)
                    })
            })
            || !intent_expectations_are_valid(&intent, &expectations)
            || semantic_commit.as_ref().is_some_and(|commit| {
                LifecycleMethodSemanticCommitV1::new(
                    commit.witness(),
                    commit.facts().clone(),
                    commit.evidence().clone(),
                    &intent,
                    &expectations,
                )
                .is_err()
            })
            || !operation_times_are_valid(
                accepted_at,
                semantic_commit.as_ref().map(|commit| commit.witness()),
                failure,
                retry,
                finished_at,
            )
            || !operation_progress_is_valid(
                &steps,
                phase,
                forward_progress,
                compensation_progress,
                semantic_commit.as_ref().map(|commit| commit.witness()),
                failure,
                retry,
                terminal_result,
                finished_at,
            )
            || !operation_attempt_projection_is_valid(&steps, phase, failure, retry)
            || !super::operation::history_shape_is_valid(record_revision, phase, predecessor_digest)
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let normalized_request = super::format::normalized_request_digest_v1(&intent);
        Ok(Self {
            operation_id,
            caller,
            project,
            idempotency,
            normalized_request,
            intent,
            accepted_at,
            record_revision,
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
            predecessor_digest,
        })
    }
    /// Returns operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    /// Returns the authenticated caller identity captured at admission.
    #[must_use]
    pub const fn caller(&self) -> PrincipalId {
        self.caller
    }
    /// Returns the project authority scope captured at admission.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }
    /// Returns idempotency commitment.
    #[must_use]
    pub const fn idempotency(&self) -> LifecycleIdempotencyDigestV1 {
        self.idempotency
    }
    /// Returns normalized request commitment.
    #[must_use]
    pub const fn normalized_request(&self) -> LifecycleNormalizedRequestDigestV1 {
        self.normalized_request
    }
    /// Borrows method-specific intent.
    #[must_use]
    pub const fn intent(&self) -> &LifecycleIntentV1 {
        &self.intent
    }
    /// Returns admission time.
    #[must_use]
    pub const fn accepted_at(&self) -> LifecycleTimeV1 {
        self.accepted_at
    }
    /// Returns record revision.
    #[must_use]
    pub const fn record_revision(&self) -> Revision {
        self.record_revision
    }
    /// Returns canonical expectations.
    #[must_use]
    pub fn expectations(&self) -> &[ResourceExpectationV1] {
        &self.expectations
    }
    /// Returns ordered steps.
    #[must_use]
    pub fn steps(&self) -> &[LifecycleStepV1] {
        &self.steps
    }
    /// Returns coordinator phase.
    #[must_use]
    pub const fn phase(&self) -> LifecyclePhaseV1 {
        self.phase
    }
    /// Returns completed forward prefix.
    #[must_use]
    pub const fn forward_progress(&self) -> u32 {
        self.forward_progress
    }
    /// Returns compensated reverse suffix.
    #[must_use]
    pub const fn compensation_progress(&self) -> u32 {
        self.compensation_progress
    }
    /// Returns semantic commit witness.
    #[must_use]
    pub const fn semantic_commit(&self) -> Option<LifecycleSemanticCommitV1> {
        match &self.semantic_commit {
            Some(commit) => Some(commit.witness()),
            None => None,
        }
    }
    /// Borrows the complete retained method-family semantic commit.
    #[must_use]
    pub const fn method_semantic_commit(&self) -> Option<&LifecycleMethodSemanticCommitV1> {
        self.semantic_commit.as_ref()
    }
    /// Returns operation failure.
    #[must_use]
    pub const fn failure(&self) -> Option<LifecycleFailureV1> {
        self.failure
    }
    /// Returns retry scheduling.
    #[must_use]
    pub const fn retry(&self) -> Option<LifecycleRetryV1> {
        self.retry
    }
    /// Returns terminal result.
    #[must_use]
    pub const fn terminal_result(&self) -> Option<LifecycleTerminalResultV1> {
        self.terminal_result
    }
    /// Returns finish time.
    #[must_use]
    pub const fn finished_at(&self) -> Option<LifecycleTimeV1> {
        self.finished_at
    }
    /// Returns predecessor record digest.
    #[must_use]
    pub const fn predecessor_digest(&self) -> Option<LifecycleRecordDigestV1> {
        self.predecessor_digest
    }
}

fn operation_attempt_projection_is_valid(
    steps: &[LifecycleStepV1],
    phase: LifecyclePhaseV1,
    failure: Option<LifecycleFailureV1>,
    retry: Option<LifecycleRetryV1>,
) -> bool {
    let mut active = steps.iter().filter(|step| {
        matches!(
            step.state(),
            LifecycleStepStateV1::Applying
                | LifecycleStepStateV1::Compensating
                | LifecycleStepStateV1::Residual
                | LifecycleStepStateV1::PermanentlyBlocked
        )
    });
    let first = active.next();
    if active.next().is_some() {
        return false;
    }
    let expected = first.map_or((None, None), |step| (step.failure(), step.retry()));
    let phase_allows_active = match phase {
        LifecyclePhaseV1::Preparing
        | LifecyclePhaseV1::Completing
        | LifecyclePhaseV1::Compensating
        | LifecyclePhaseV1::RetryWaiting
        | LifecyclePhaseV1::Residual
        | LifecyclePhaseV1::PermanentlyBlocked => true,
        _ => first.is_none(),
    };
    phase_allows_active && (failure, retry) == expected
}

fn steps_are_partitioned(steps: &[LifecycleStepV1]) -> bool {
    let n = steps
        .iter()
        .take_while(|s| s.class() == LifecycleStepClassV1::PreCommitReversible)
        .count();
    steps[n..]
        .iter()
        .all(|s| s.class() == LifecycleStepClassV1::PostCommitForward)
}

fn expectation_matches(
    values: &[ResourceExpectationV1],
    resource: LifecycleResourceV1,
    absent: bool,
) -> bool {
    values.iter().any(|e| {
        e.resource() == resource
            && matches!(e.expected(), ResourceExpectedStateV1::Absent) == absent
    })
}

fn intent_expectations_are_valid(
    intent: &LifecycleIntentV1,
    values: &[ResourceExpectationV1],
) -> bool {
    let present_sandbox = |id| expectation_matches(values, LifecycleResourceV1::Sandbox(id), false);
    let absent_sandbox = |id| expectation_matches(values, LifecycleResourceV1::Sandbox(id), true);
    let present_snapshot =
        |id| expectation_matches(values, LifecycleResourceV1::Snapshot(id), false);
    let absent_snapshot = |id| expectation_matches(values, LifecycleResourceV1::Snapshot(id), true);
    let present_execution =
        |id| expectation_matches(values, LifecycleResourceV1::Execution(id), false);
    let absent_execution =
        |id| expectation_matches(values, LifecycleResourceV1::Execution(id), true);
    let present_view = |id| expectation_matches(values, LifecycleResourceV1::View(id), false);
    let absent_view = |id| expectation_matches(values, LifecycleResourceV1::View(id), true);
    let present_attachment =
        |id| expectation_matches(values, LifecycleResourceV1::Attachment(id), false);
    let absent_attachment =
        |id| expectation_matches(values, LifecycleResourceV1::Attachment(id), true);
    let present_capability =
        |id| expectation_matches(values, LifecycleResourceV1::Capability(id), false);
    let absent_capability =
        |id| expectation_matches(values, LifecycleResourceV1::Capability(id), true);
    let identities_are_valid = match intent {
        LifecycleIntentV1::Create { sandbox } => absent_sandbox(*sandbox),
        LifecycleIntentV1::Fork { source, target } => {
            present_snapshot(*source) && absent_sandbox(*target)
        }
        LifecycleIntentV1::Restore {
            snapshot, sandbox, ..
        } => present_snapshot(*snapshot) && absent_sandbox(*sandbox),
        LifecycleIntentV1::Hibernate {
            sandbox, snapshot, ..
        }
        | LifecycleIntentV1::Snapshot {
            sandbox, snapshot, ..
        } => present_sandbox(*sandbox) && absent_snapshot(*snapshot),
        LifecycleIntentV1::UpdateEnvironment {
            sandbox,
            environment_generation,
            ..
        } => {
            environment_generation.get() != 0
                && environment_generation.get() != u64::MAX
                && present_sandbox(*sandbox)
        }
        LifecycleIntentV1::UpdatePolicy { sandbox, .. } => present_sandbox(*sandbox),
        LifecycleIntentV1::Start { sandbox, .. }
        | LifecycleIntentV1::Stop { sandbox, .. }
        | LifecycleIntentV1::SuspendMemory { sandbox, .. }
        | LifecycleIntentV1::DeleteSandbox { sandbox, .. } => present_sandbox(*sandbox),
        LifecycleIntentV1::Resume { sandbox, source } => {
            present_sandbox(*sandbox)
                && match source {
                    LifecycleResumeSourceV1::Memory { .. } => true,
                    LifecycleResumeSourceV1::Hibernated { snapshot, .. } => {
                        present_snapshot(*snapshot)
                    }
                }
        }
        LifecycleIntentV1::DeleteSnapshot { snapshot, .. } => present_snapshot(*snapshot),
        LifecycleIntentV1::CreateExecution {
            sandbox, execution, ..
        } => present_sandbox(*sandbox) && absent_execution(*execution),
        LifecycleIntentV1::CancelExecution { execution, .. } => present_execution(*execution),
        LifecycleIntentV1::CreateView { view } => absent_view(*view),
        LifecycleIntentV1::AttachView {
            sandbox,
            view,
            attachment,
            ..
        } => present_sandbox(*sandbox) && present_view(*view) && absent_attachment(*attachment),
        LifecycleIntentV1::ReplaceAttachment {
            attachment, view, ..
        } => present_attachment(*attachment) && present_view(*view),
        LifecycleIntentV1::DetachView { attachment, .. } => present_attachment(*attachment),
        LifecycleIntentV1::ReleaseView { view, .. } => present_view(*view),
        LifecycleIntentV1::AttenuateCapability { parent, child } => {
            present_capability(*parent) && absent_capability(*child)
        }
        LifecycleIntentV1::RenewCapability { capability, .. }
        | LifecycleIntentV1::RevokeCapability { capability, .. } => present_capability(*capability),
    };
    identities_are_valid && intent_fences_are_coherent(intent, values)
}

fn fence_matches_expectation(
    fence: DesiredStateFenceV1,
    expected_resource: LifecycleResourceV1,
    values: &[ResourceExpectationV1],
) -> bool {
    fence.resource() == expected_resource
        && values.iter().any(|expectation| {
            expectation.resource() == expected_resource
                && expectation.expected()
                    == ResourceExpectedStateV1::Present {
                        revision: fence.resource_revision(),
                        state_digest: fence.resource_state(),
                    }
        })
}

fn runtime_fence_matches(
    fence: LiveRuntimeFenceV1,
    expected_sandbox: Option<SandboxId>,
    values: &[ResourceExpectationV1],
) -> bool {
    expected_sandbox.is_none_or(|sandbox| sandbox == fence.sandbox())
        && fence_matches_expectation(
            fence.desired(),
            LifecycleResourceV1::Sandbox(fence.sandbox()),
            values,
        )
}

fn target_fence_matches(
    fence: super::LifecycleTargetFenceV1,
    expected_resource: LifecycleResourceV1,
    values: &[ResourceExpectationV1],
) -> bool {
    fence.resource() == expected_resource
        && values.iter().any(|expectation| {
            expectation.resource() == expected_resource
                && expectation.expected() == fence.expected()
        })
}

fn intent_fences_are_coherent(
    intent: &LifecycleIntentV1,
    values: &[ResourceExpectationV1],
) -> bool {
    match intent {
        LifecycleIntentV1::Create { .. }
        | LifecycleIntentV1::Fork { .. }
        | LifecycleIntentV1::Restore { .. }
        | LifecycleIntentV1::CreateView { .. }
        | LifecycleIntentV1::AttenuateCapability { .. } => true,
        LifecycleIntentV1::UpdateEnvironment { sandbox, fence, .. }
        | LifecycleIntentV1::UpdatePolicy { sandbox, fence }
        | LifecycleIntentV1::Start { sandbox, fence }
        | LifecycleIntentV1::DeleteSandbox { sandbox, fence } => {
            fence_matches_expectation(*fence, LifecycleResourceV1::Sandbox(*sandbox), values)
        }
        LifecycleIntentV1::ReleaseView { view, fence } => {
            fence_matches_expectation(*fence, LifecycleResourceV1::View(*view), values)
        }
        LifecycleIntentV1::DeleteSnapshot { snapshot, fence } => {
            fence_matches_expectation(*fence, LifecycleResourceV1::Snapshot(*snapshot), values)
        }
        LifecycleIntentV1::RenewCapability { capability, fence }
        | LifecycleIntentV1::RevokeCapability { capability, fence } => {
            fence_matches_expectation(*fence, LifecycleResourceV1::Capability(*capability), values)
        }
        LifecycleIntentV1::Stop { sandbox, fence }
        | LifecycleIntentV1::SuspendMemory { sandbox, fence } => {
            runtime_fence_matches(*fence, Some(*sandbox), values)
        }
        LifecycleIntentV1::Hibernate {
            sandbox,
            snapshot,
            fence,
            target_fence,
        }
        | LifecycleIntentV1::Snapshot {
            sandbox,
            snapshot,
            fence,
            target_fence,
        } => {
            runtime_fence_matches(*fence, Some(*sandbox), values)
                && target_fence_matches(
                    *target_fence,
                    LifecycleResourceV1::Snapshot(*snapshot),
                    values,
                )
                && target_fence.expected() == ResourceExpectedStateV1::Absent
        }
        LifecycleIntentV1::CreateExecution {
            sandbox,
            execution,
            fence,
            target_fence,
        } => {
            runtime_fence_matches(*fence, Some(*sandbox), values)
                && target_fence_matches(
                    *target_fence,
                    LifecycleResourceV1::Execution(*execution),
                    values,
                )
                && target_fence.expected() == ResourceExpectedStateV1::Absent
        }
        LifecycleIntentV1::AttachView {
            sandbox,
            attachment,
            fence,
            target_fence,
            ..
        } => {
            runtime_fence_matches(*fence, Some(*sandbox), values)
                && target_fence_matches(
                    *target_fence,
                    LifecycleResourceV1::Attachment(*attachment),
                    values,
                )
                && target_fence.expected() == ResourceExpectedStateV1::Absent
        }
        LifecycleIntentV1::CancelExecution {
            execution,
            fence,
            target_fence,
        } => {
            runtime_fence_matches(*fence, None, values)
                && target_fence_matches(
                    *target_fence,
                    LifecycleResourceV1::Execution(*execution),
                    values,
                )
                && matches!(
                    target_fence.expected(),
                    ResourceExpectedStateV1::Present { .. }
                )
        }
        LifecycleIntentV1::ReplaceAttachment {
            attachment,
            fence,
            target_fence,
            ..
        }
        | LifecycleIntentV1::DetachView {
            attachment,
            fence,
            target_fence,
        } => {
            runtime_fence_matches(*fence, None, values)
                && target_fence_matches(
                    *target_fence,
                    LifecycleResourceV1::Attachment(*attachment),
                    values,
                )
                && matches!(
                    target_fence.expected(),
                    ResourceExpectedStateV1::Present { .. }
                )
        }
        LifecycleIntentV1::Resume { sandbox, source } => match source {
            LifecycleResumeSourceV1::Memory { fence } => {
                runtime_fence_matches(*fence, Some(*sandbox), values)
            }
            LifecycleResumeSourceV1::Hibernated { fence, .. } => {
                fence_matches_expectation(*fence, LifecycleResourceV1::Sandbox(*sandbox), values)
            }
        },
    }
}

pub(super) fn intent_semantic_cas_is_valid(
    intent: &LifecycleIntentV1,
    commit: LifecycleSemanticCommitV1,
) -> bool {
    let cas = commit.desired_state_cas();
    let (resource, expected) = match intent {
        LifecycleIntentV1::Create { sandbox } => (
            LifecycleResourceV1::Sandbox(*sandbox),
            Some(DesiredGeneration::new(0)),
        ),
        LifecycleIntentV1::Fork { target, .. } => (
            LifecycleResourceV1::Sandbox(*target),
            Some(DesiredGeneration::new(0)),
        ),
        LifecycleIntentV1::Restore { sandbox, .. } => (
            LifecycleResourceV1::Sandbox(*sandbox),
            Some(DesiredGeneration::new(0)),
        ),
        LifecycleIntentV1::Start { sandbox, fence }
        | LifecycleIntentV1::DeleteSandbox { sandbox, fence } => (
            LifecycleResourceV1::Sandbox(*sandbox),
            Some(fence.expected_generation()),
        ),
        LifecycleIntentV1::UpdateEnvironment { sandbox, fence, .. } => (
            LifecycleResourceV1::Sandbox(*sandbox),
            Some(fence.expected_generation()),
        ),
        LifecycleIntentV1::UpdatePolicy { sandbox, fence } => (
            LifecycleResourceV1::Sandbox(*sandbox),
            Some(fence.expected_generation()),
        ),
        LifecycleIntentV1::Stop { sandbox, fence }
        | LifecycleIntentV1::SuspendMemory { sandbox, fence }
        | LifecycleIntentV1::Hibernate { sandbox, fence, .. } => (
            LifecycleResourceV1::Sandbox(*sandbox),
            Some(fence.desired().expected_generation()),
        ),
        LifecycleIntentV1::Snapshot { snapshot, .. } => (
            LifecycleResourceV1::Snapshot(*snapshot),
            Some(DesiredGeneration::new(0)),
        ),
        LifecycleIntentV1::Resume { sandbox, source } => {
            let expected = match source {
                LifecycleResumeSourceV1::Memory { fence } => fence.desired().expected_generation(),
                LifecycleResumeSourceV1::Hibernated { fence, .. } => fence.expected_generation(),
            };
            (LifecycleResourceV1::Sandbox(*sandbox), Some(expected))
        }
        LifecycleIntentV1::DeleteSnapshot { snapshot, fence } => (
            LifecycleResourceV1::Snapshot(*snapshot),
            Some(fence.expected_generation()),
        ),
        LifecycleIntentV1::CreateExecution { execution, .. } => (
            LifecycleResourceV1::Execution(*execution),
            Some(DesiredGeneration::new(0)),
        ),
        LifecycleIntentV1::CancelExecution {
            execution,
            target_fence,
            ..
        } => (
            LifecycleResourceV1::Execution(*execution),
            Some(target_fence.expected_generation()),
        ),
        LifecycleIntentV1::CreateView { view } => (
            LifecycleResourceV1::View(*view),
            Some(DesiredGeneration::new(0)),
        ),
        LifecycleIntentV1::AttachView { attachment, .. } => (
            LifecycleResourceV1::Attachment(*attachment),
            Some(DesiredGeneration::new(0)),
        ),
        LifecycleIntentV1::ReplaceAttachment {
            attachment,
            target_fence,
            ..
        }
        | LifecycleIntentV1::DetachView {
            attachment,
            target_fence,
            ..
        } => (
            LifecycleResourceV1::Attachment(*attachment),
            Some(target_fence.expected_generation()),
        ),
        LifecycleIntentV1::ReleaseView { view, fence } => (
            LifecycleResourceV1::View(*view),
            Some(fence.expected_generation()),
        ),
        LifecycleIntentV1::AttenuateCapability { child, .. } => (
            LifecycleResourceV1::Capability(*child),
            Some(DesiredGeneration::new(0)),
        ),
        LifecycleIntentV1::RenewCapability { capability, fence }
        | LifecycleIntentV1::RevokeCapability { capability, fence } => (
            LifecycleResourceV1::Capability(*capability),
            Some(fence.expected_generation()),
        ),
    };
    cas.resource() == resource
        && expected.is_none_or(|generation| cas.expected_generation() == generation)
}

fn operation_times_are_valid(
    accepted: LifecycleTimeV1,
    commit: Option<LifecycleSemanticCommitV1>,
    failure: Option<LifecycleFailureV1>,
    retry: Option<LifecycleRetryV1>,
    finished: Option<LifecycleTimeV1>,
) -> bool {
    let commit_valid = commit.is_none_or(|value| value.committed_at() >= accepted);
    let failure_valid = failure.is_none_or(|value| value.observed_at() >= accepted);
    let retry_valid = match (failure, retry) {
        (_, None) => true,
        (Some(failure), Some(retry)) => retry.not_before() >= failure.observed_at(),
        (None, Some(_)) => false,
    };
    let finished_valid = finished.is_none_or(|value| {
        value >= accepted && commit.is_none_or(|semantic| value >= semantic.committed_at())
    });
    commit_valid && failure_valid && retry_valid && finished_valid
}

#[allow(clippy::too_many_arguments)]
fn operation_progress_is_valid(
    steps: &[LifecycleStepV1],
    phase: LifecyclePhaseV1,
    forward: u32,
    compensated: u32,
    commit: Option<LifecycleSemanticCommitV1>,
    failure: Option<LifecycleFailureV1>,
    retry: Option<LifecycleRetryV1>,
    result: Option<LifecycleTerminalResultV1>,
    finished: Option<LifecycleTimeV1>,
) -> bool {
    let (Ok(f), Ok(c)) = (usize::try_from(forward), usize::try_from(compensated)) else {
        return false;
    };
    let reversible = steps
        .iter()
        .take_while(|s| s.class() == LifecycleStepClassV1::PreCommitReversible)
        .count();
    if f > steps.len() || c > f.min(reversible) {
        return false;
    }
    let start = f - c;
    if steps.iter().enumerate().any(|(i, s)| {
        (s.state() == LifecycleStepStateV1::Compensated) != (i >= start && i < f && i < reversible)
    }) {
        return false;
    }
    if steps.iter().enumerate().any(|(index, step)| {
        if index < start {
            !matches!(
                step.state(),
                LifecycleStepStateV1::Applied
                    | LifecycleStepStateV1::Compensating
                    | LifecycleStepStateV1::Residual
                    | LifecycleStepStateV1::PermanentlyBlocked
            )
        } else if index < f {
            step.state() != LifecycleStepStateV1::Compensated
        } else if index == f {
            !matches!(
                step.state(),
                LifecycleStepStateV1::Planned
                    | LifecycleStepStateV1::Applying
                    | LifecycleStepStateV1::Residual
                    | LifecycleStepStateV1::PermanentlyBlocked
                    | LifecycleStepStateV1::Canceled
            )
        } else {
            step.state() != LifecycleStepStateV1::Planned
        }
    }) {
        return false;
    }
    let active_step_count = steps
        .iter()
        .filter(|step| {
            matches!(
                step.state(),
                LifecycleStepStateV1::Applying | LifecycleStepStateV1::Compensating
            )
        })
        .count();
    if active_step_count > 1 {
        return false;
    }
    let mut compensating_count = 0_usize;
    let mut compensating_index_is_valid = true;
    for (index, step) in steps.iter().enumerate() {
        if step.state() == LifecycleStepStateV1::Compensating {
            compensating_count += 1;
            compensating_index_is_valid &= index + c + 1 == f;
        }
    }
    if compensating_count > 1 || !compensating_index_is_valid {
        return false;
    }
    if steps.iter().any(|step| {
        (step.state() == LifecycleStepStateV1::Residual
            && !matches!(
                phase,
                LifecyclePhaseV1::RetryWaiting | LifecyclePhaseV1::Residual
            ))
            || (step.state() == LifecycleStepStateV1::PermanentlyBlocked
                && phase != LifecyclePhaseV1::PermanentlyBlocked)
    }) {
        return false;
    }
    let commit_shape = match phase {
        LifecyclePhaseV1::Accepted
        | LifecyclePhaseV1::Preparing
        | LifecyclePhaseV1::Prepared
        | LifecyclePhaseV1::ReadyToCommit
        | LifecyclePhaseV1::Compensating
        | LifecyclePhaseV1::RetryWaiting => commit.is_none(),
        LifecyclePhaseV1::Committed | LifecyclePhaseV1::Completing => commit.is_some(),
        _ => true,
    };
    let terminal_shape = match (phase, result, finished) {
        (LifecyclePhaseV1::Terminal, Some(LifecycleTerminalResultV1::Succeeded), Some(_)) => {
            commit.is_some()
        }
        (
            LifecyclePhaseV1::Terminal,
            Some(
                LifecycleTerminalResultV1::FailedBeforeCommit
                | LifecycleTerminalResultV1::CanceledBeforeCommit,
            ),
            Some(_),
        ) => commit.is_none(),
        (LifecyclePhaseV1::Residual, None, None) => commit.is_some(),
        (LifecyclePhaseV1::RetryWaiting, None, None) => commit.is_none(),
        (
            LifecyclePhaseV1::PermanentlyBlocked,
            Some(LifecycleTerminalResultV1::BlockedBeforeCommit),
            Some(_),
        ) => commit.is_none(),
        (
            LifecyclePhaseV1::PermanentlyBlocked,
            Some(LifecycleTerminalResultV1::BlockedAfterCommit),
            Some(_),
        ) => commit.is_some(),
        (
            LifecyclePhaseV1::Accepted
            | LifecyclePhaseV1::Preparing
            | LifecyclePhaseV1::Prepared
            | LifecyclePhaseV1::ReadyToCommit
            | LifecyclePhaseV1::Committed
            | LifecyclePhaseV1::Completing
            | LifecyclePhaseV1::Compensating
            | LifecyclePhaseV1::RetryWaiting,
            None,
            None,
        ) => true,
        _ => false,
    };
    let progress = match phase {
        LifecyclePhaseV1::Accepted => f == 0 && c == 0,
        LifecyclePhaseV1::Preparing => f <= reversible && c == 0,
        LifecyclePhaseV1::Prepared
        | LifecyclePhaseV1::ReadyToCommit
        | LifecyclePhaseV1::Committed => f == reversible && c == 0,
        LifecyclePhaseV1::Completing => f >= reversible && c == 0,
        LifecyclePhaseV1::Compensating => f <= reversible,
        LifecyclePhaseV1::RetryWaiting => f <= reversible,
        LifecyclePhaseV1::Terminal => match result {
            Some(LifecycleTerminalResultV1::Succeeded) => f == steps.len() && c == 0,
            Some(
                LifecycleTerminalResultV1::FailedBeforeCommit
                | LifecycleTerminalResultV1::CanceledBeforeCommit,
            ) => c == f,
            _ => true,
        },
        _ => true,
    };
    let phase_step_shape = match phase {
        LifecyclePhaseV1::Accepted => steps
            .iter()
            .all(|step| step.state() == LifecycleStepStateV1::Planned),
        LifecyclePhaseV1::Prepared
        | LifecyclePhaseV1::ReadyToCommit
        | LifecyclePhaseV1::Committed => steps.iter().enumerate().all(|(index, step)| {
            if index < reversible {
                step.state() == LifecycleStepStateV1::Applied
            } else {
                step.state() == LifecycleStepStateV1::Planned
            }
        }),
        LifecyclePhaseV1::Terminal if result == Some(LifecycleTerminalResultV1::Succeeded) => steps
            .iter()
            .all(|step| step.state() == LifecycleStepStateV1::Applied),
        _ => true,
    };
    let failure_shape = !matches!(
        phase,
        LifecyclePhaseV1::RetryWaiting
            | LifecyclePhaseV1::Residual
            | LifecyclePhaseV1::PermanentlyBlocked
    ) || failure.is_some();
    let retry_shape = retry.is_none()
        || matches!(
            phase,
            LifecyclePhaseV1::Preparing
                | LifecyclePhaseV1::Completing
                | LifecyclePhaseV1::Compensating
                | LifecyclePhaseV1::RetryWaiting
                | LifecyclePhaseV1::Residual
        );
    let residual_retry_shape = !matches!(
        phase,
        LifecyclePhaseV1::RetryWaiting | LifecyclePhaseV1::Residual
    ) || retry.is_some();
    commit_shape
        && terminal_shape
        && progress
        && phase_step_shape
        && failure_shape
        && retry_shape
        && residual_retry_shape
}
