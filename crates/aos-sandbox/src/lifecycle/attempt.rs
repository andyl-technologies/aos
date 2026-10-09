//! Bounded effect-attempt evidence and exact ambiguous recovery selectors.

use super::{
    LifecycleFailureClassV1, LifecycleFailureV1, LifecycleInventoryDigestV1, LifecycleModelError,
    LifecycleRetryV1, LifecycleStepAdmissionDigestV1, LifecycleStepBodyDigestV1,
    LifecycleStepPlanDigestV1, LifecycleStepRequestDigestV1, LifecycleStepResultDigestV1,
    LifecycleTimeV1,
};

/// Maximum attempts retained for one logical effect direction.
pub const MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP: usize = 64;
/// Maximum attempt number representable in retry scheduling.
pub const MAXIMUM_LIFECYCLE_ATTEMPTS: u32 = MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP as u32;

/// Selects the direction of an effect attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleEffectDirectionV1 {
    /// Applies the stable forward effect.
    Forward = 1,
    /// Applies its stable reverse compensation.
    Compensation = 2,
}

/// Describes durable evidence for one exact attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleAttemptStateV1 {
    /// Admission is durable but no observation is durable.
    Reserved = 1,
    /// Fresh inventory still cannot distinguish whether the effect occurred.
    Ambiguous = 2,
    /// Exact result and post-effect inventory are durable.
    Succeeded = 3,
    /// Failure, inventory, and a later retry schedule are durable.
    Failed = 4,
    /// Failure and inventory prove that automatic retry is unsafe.
    PermanentlyBlocked = 5,
}

/// Retains all commitments and observations for one exact effect attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleEffectAttemptV1 {
    number: u32,
    direction: LifecycleEffectDirectionV1,
    request: LifecycleStepRequestDigestV1,
    body: LifecycleStepBodyDigestV1,
    plan: LifecycleStepPlanDigestV1,
    admission: LifecycleStepAdmissionDigestV1,
    started_at: LifecycleTimeV1,
    state: LifecycleAttemptStateV1,
    result: Option<LifecycleStepResultDigestV1>,
    failure: Option<LifecycleFailureV1>,
    inventory: Option<LifecycleInventoryDigestV1>,
    retry: Option<LifecycleRetryV1>,
    observed_at: Option<LifecycleTimeV1>,
}

impl LifecycleEffectAttemptV1 {
    /// Constructs one closed, attempt-local evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] when evidence, retry, or
    /// timestamp shape does not match the selected state and attempt number.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        number: u32,
        direction: LifecycleEffectDirectionV1,
        request: LifecycleStepRequestDigestV1,
        body: LifecycleStepBodyDigestV1,
        plan: LifecycleStepPlanDigestV1,
        admission: LifecycleStepAdmissionDigestV1,
        started_at: LifecycleTimeV1,
        state: LifecycleAttemptStateV1,
        result: Option<LifecycleStepResultDigestV1>,
        failure: Option<LifecycleFailureV1>,
        inventory: Option<LifecycleInventoryDigestV1>,
        retry: Option<LifecycleRetryV1>,
        observed_at: Option<LifecycleTimeV1>,
    ) -> Result<Self, LifecycleModelError> {
        let number_is_valid = usize::try_from(number)
            .is_ok_and(|value| value > 0 && value <= MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP);
        let next_number = number.checked_add(1);
        let evidence_is_valid = match state {
            LifecycleAttemptStateV1::Reserved => {
                result.is_none()
                    && failure.is_none()
                    && inventory.is_none()
                    && retry.is_none()
                    && observed_at.is_none()
            }
            LifecycleAttemptStateV1::Ambiguous => {
                result.is_none()
                    && failure.is_some_and(|value| {
                        value.class() == LifecycleFailureClassV1::AmbiguousEffect
                    })
                    && inventory.is_some()
                    && retry.is_none()
                    && observed_at.is_some()
            }
            LifecycleAttemptStateV1::Succeeded => {
                result.is_some()
                    && failure.is_none()
                    && inventory.is_some()
                    && retry.is_none()
                    && observed_at.is_some()
            }
            LifecycleAttemptStateV1::Failed => {
                result.is_none()
                    && failure.is_some()
                    && inventory.is_some()
                    && retry.is_some_and(|value| Some(value.attempt()) == next_number)
                    && observed_at.is_some()
            }
            LifecycleAttemptStateV1::PermanentlyBlocked => {
                result.is_none()
                    && failure.is_some()
                    && inventory.is_some()
                    && retry.is_none()
                    && observed_at.is_some()
            }
        };
        let times_are_valid = observed_at.is_none_or(|value| value >= started_at)
            && failure.is_none_or(|value| {
                value.observed_at() >= started_at && observed_at == Some(value.observed_at())
            })
            && retry.is_none_or(|value| {
                failure.is_some_and(|failure| value.not_before() >= failure.observed_at())
            });
        if !number_is_valid || !evidence_is_valid || !times_are_valid {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            number,
            direction,
            request,
            body,
            plan,
            admission,
            started_at,
            state,
            result,
            failure,
            inventory,
            retry,
            observed_at,
        })
    }

    /// Returns the stable one-based attempt number.
    #[must_use]
    pub const fn number(self) -> u32 {
        self.number
    }
    /// Returns the effect direction.
    #[must_use]
    pub const fn direction(self) -> LifecycleEffectDirectionV1 {
        self.direction
    }
    /// Returns the stable logical request commitment.
    #[must_use]
    pub const fn request(self) -> LifecycleStepRequestDigestV1 {
        self.request
    }
    /// Returns the exact effect body commitment.
    #[must_use]
    pub const fn body(self) -> LifecycleStepBodyDigestV1 {
        self.body
    }
    /// Returns the stable plan commitment.
    #[must_use]
    pub const fn plan(self) -> LifecycleStepPlanDigestV1 {
        self.plan
    }
    /// Returns the fresh attempt-specific admission commitment.
    #[must_use]
    pub const fn admission(self) -> LifecycleStepAdmissionDigestV1 {
        self.admission
    }
    /// Returns the durable reservation time.
    #[must_use]
    pub const fn started_at(self) -> LifecycleTimeV1 {
        self.started_at
    }
    /// Returns the exact evidence state.
    #[must_use]
    pub const fn state(self) -> LifecycleAttemptStateV1 {
        self.state
    }
    /// Returns the attempt-local result commitment.
    #[must_use]
    pub const fn result(self) -> Option<LifecycleStepResultDigestV1> {
        self.result
    }
    /// Returns the attempt-local failure.
    #[must_use]
    pub const fn failure(self) -> Option<LifecycleFailureV1> {
        self.failure
    }
    /// Returns the attempt-local inventory commitment.
    #[must_use]
    pub const fn inventory(self) -> Option<LifecycleInventoryDigestV1> {
        self.inventory
    }
    /// Returns the schedule for the next attempt.
    #[must_use]
    pub const fn retry(self) -> Option<LifecycleRetryV1> {
        self.retry
    }
    /// Returns the exact observation time.
    #[must_use]
    pub const fn observed_at(self) -> Option<LifecycleTimeV1> {
        self.observed_at
    }

    fn can_refine(self, previous: Self) -> bool {
        self.number == previous.number
            && self.direction == previous.direction
            && self.request == previous.request
            && self.body == previous.body
            && self.plan == previous.plan
            && self.admission == previous.admission
            && self.started_at == previous.started_at
            && matches!(
                (previous.state, self.state),
                (
                    LifecycleAttemptStateV1::Reserved,
                    LifecycleAttemptStateV1::Reserved
                ) | (
                    LifecycleAttemptStateV1::Reserved,
                    LifecycleAttemptStateV1::Ambiguous
                ) | (
                    LifecycleAttemptStateV1::Reserved,
                    LifecycleAttemptStateV1::Succeeded
                ) | (
                    LifecycleAttemptStateV1::Reserved,
                    LifecycleAttemptStateV1::Failed
                ) | (
                    LifecycleAttemptStateV1::Reserved,
                    LifecycleAttemptStateV1::PermanentlyBlocked
                ) | (
                    LifecycleAttemptStateV1::Ambiguous,
                    LifecycleAttemptStateV1::Ambiguous
                ) | (
                    LifecycleAttemptStateV1::Ambiguous,
                    LifecycleAttemptStateV1::Succeeded
                ) | (
                    LifecycleAttemptStateV1::Ambiguous,
                    LifecycleAttemptStateV1::Failed
                ) | (
                    LifecycleAttemptStateV1::Ambiguous,
                    LifecycleAttemptStateV1::PermanentlyBlocked
                )
            )
    }
}

/// Retains append-only attempts for one stable logical effect direction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAttemptHistoryV1 {
    direction: LifecycleEffectDirectionV1,
    request: LifecycleStepRequestDigestV1,
    body: LifecycleStepBodyDigestV1,
    plan: LifecycleStepPlanDigestV1,
    attempts: Vec<LifecycleEffectAttemptV1>,
}

impl LifecycleAttemptHistoryV1 {
    /// Constructs a canonical bounded attempt history.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] unless attempt numbers are
    /// consecutive, commitments remain stable, and only failure starts a retry.
    pub fn new(
        direction: LifecycleEffectDirectionV1,
        request: LifecycleStepRequestDigestV1,
        body: LifecycleStepBodyDigestV1,
        plan: LifecycleStepPlanDigestV1,
        attempts: Vec<LifecycleEffectAttemptV1>,
    ) -> Result<Self, LifecycleModelError> {
        if attempts.len() > MAXIMUM_LIFECYCLE_ATTEMPTS_PER_STEP
            || attempts.iter().enumerate().any(|(index, attempt)| {
                usize::try_from(attempt.number()).ok() != index.checked_add(1)
                    || attempt.direction() != direction
                    || attempt.request() != request
                    || attempt.body() != body
                    || attempt.plan() != plan
            })
            || attempts.windows(2).any(|pair| {
                pair[0].state() != LifecycleAttemptStateV1::Failed
                    || pair[0]
                        .retry()
                        .is_none_or(|retry| retry.attempt() != pair[1].number())
                    || pair[1].state() != LifecycleAttemptStateV1::Reserved
                    || pair[0].admission() == pair[1].admission()
                    || pair[0]
                        .retry()
                        .is_none_or(|retry| pair[1].started_at() < retry.not_before())
            })
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            direction,
            request,
            body,
            plan,
            attempts,
        })
    }

    /// Borrows exact append-only attempts.
    #[must_use]
    pub fn attempts(&self) -> &[LifecycleEffectAttemptV1] {
        &self.attempts
    }

    /// Checks an append or exact same-attempt evidence refinement.
    #[must_use]
    pub fn can_follow(&self, previous: &Self) -> bool {
        let Some(maximum_length) = previous.attempts.len().checked_add(1) else {
            return false;
        };
        if self.direction != previous.direction
            || self.request != previous.request
            || self.body != previous.body
            || self.plan != previous.plan
            || self.attempts.len() < previous.attempts.len()
            || self.attempts.len() > maximum_length
        {
            return false;
        }
        if self.attempts.len() == previous.attempts.len() {
            let Some(shared_length) = previous.attempts.len().checked_sub(1) else {
                return self.attempts.is_empty();
            };
            return self.attempts.get(..shared_length) == previous.attempts.get(..shared_length)
                && self.attempts[shared_length].can_refine(previous.attempts[shared_length]);
        }
        let Some(previous_last_index) = previous.attempts.len().checked_sub(1) else {
            return false;
        };
        if self.attempts.get(..previous_last_index) != previous.attempts.get(..previous_last_index)
        {
            return false;
        }
        let Some(previous_last) = previous.attempts.last().copied() else {
            return false;
        };
        let Some(current_previous) = self.attempts.get(previous_last_index).copied() else {
            return false;
        };
        let Some(next) = self.attempts.last().copied() else {
            return false;
        };
        let previous_is_failed = if previous_last.state() == LifecycleAttemptStateV1::Failed {
            current_previous == previous_last
        } else {
            current_previous.can_refine(previous_last)
                && current_previous.state() == LifecycleAttemptStateV1::Failed
        };
        previous_is_failed
            && current_previous
                .retry()
                .is_some_and(|retry| retry.attempt() == next.number())
            && current_previous.number().checked_add(1) == Some(next.number())
            && next.state() == LifecycleAttemptStateV1::Reserved
            && next.admission() != current_previous.admission()
            && current_previous
                .retry()
                .is_some_and(|retry| next.started_at() >= retry.not_before())
    }
}

/// Selects exactly one durable ambiguous attempt for reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleAmbiguousResumeV1(LifecycleEffectAttemptV1);

impl LifecycleAmbiguousResumeV1 {
    /// Returns the exact attempt-local commitments and evidence.
    #[must_use]
    pub const fn attempt(self) -> LifecycleEffectAttemptV1 {
        self.0
    }
}

/// Classifies one exact reserved or ambiguous attempt for reconciliation.
///
/// # Errors
///
/// Returns [`LifecycleModelError::InvalidModel`] once the attempt is resolved.
pub fn resume_ambiguous_attempt_v1(
    attempt: LifecycleEffectAttemptV1,
) -> Result<LifecycleAmbiguousResumeV1, LifecycleModelError> {
    if matches!(
        attempt.state(),
        LifecycleAttemptStateV1::Reserved | LifecycleAttemptStateV1::Ambiguous
    ) {
        Ok(LifecycleAmbiguousResumeV1(attempt))
    } else {
        Err(LifecycleModelError::InvalidModel)
    }
}
