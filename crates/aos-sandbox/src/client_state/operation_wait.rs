//! Pure bounded reduction of established public operation resources.
//!
//! Transport deadline expiry ends only this observation loop. It never implies
//! operation cancellation. Resource versions cannot reappear after a newer
//! version, conditions and results cannot disappear, cancellation cannot reopen,
//! retry advice cannot become more permissive, and terminal state permits only
//! an exact replay.

use std::collections::BTreeSet;

use crate::controller_query::observation::{
    CheckedConditionObservationV1, CheckedOperationObservationV1,
};
use crate::controller_query::resource::{
    operation_phase_can_follow, operation_progress_stage, CheckedOperationPhaseV1,
    CheckedOperationResourceV1, CheckedResourceReferenceV1,
};

/// Maximum operation observations in one wait.
pub const MAXIMUM_WAIT_OBSERVATIONS: u32 = 100_000;
/// Maximum client-side wait duration in nanoseconds.
pub const MAXIMUM_WAIT_NANOSECONDS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;
/// Maximum opaque resource-version bytes retained for ABA detection.
pub const MAXIMUM_WAIT_VERSION_BYTES: usize = 8 * 1024 * 1024;

/// Reports invalid or contradictory operation-wait state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperationWaitError {
    /// A wait bound is zero or exceeds the compiled ceiling.
    #[error("operation wait bound is invalid")]
    InvalidWaitBound,
    /// An observation names another operation.
    #[error("operation observation identity does not match the wait")]
    OperationMismatch,
    /// One resource version was reused for different content.
    #[error("operation resource version equivocated")]
    ResourceVersionConflict,
    /// An earlier resource version reappeared after advancement.
    #[error("operation resource version regressed")]
    ResourceVersionRegression,
    /// A later resource reports a non-increasing observation sequence.
    #[error("operation observation sequence did not advance")]
    ObservationSequenceRegression,
    /// A later poll reports an impossible public phase regression.
    #[error("operation phase regressed or crossed its commit boundary")]
    InvalidPhaseAdvance,
    /// Immutable identity, acceptance, method, or audit fields changed.
    #[error("immutable operation fields changed")]
    ImmutableFieldConflict,
    /// Progress regressed or changed milestone without phase advancement.
    #[error("operation progress regressed")]
    ProgressRegression,
    /// A prior condition disappeared, regressed, or equivocated.
    #[error("operation conditions regressed")]
    ConditionRegression,
    /// A prior result disappeared or changed.
    #[error("operation results regressed")]
    ResultRegression,
    /// Retry or cancellation state became more permissive.
    #[error("operation retry or cancellation state regressed")]
    ControlStateRegression,
    /// Caller-provided elapsed monotonic time moved backward.
    #[error("operation wait elapsed time regressed")]
    ElapsedTimeRegression,
    /// A non-identical observation followed terminal state.
    #[error("terminal operation state permits only exact replay")]
    TerminalConflict,
    /// Elapsed time was supplied after a non-operation terminal wait outcome.
    #[error("operation wait is already terminal")]
    AlreadyTerminal,
    /// Retained resource versions exceeded the fixed byte budget.
    #[error("operation wait version-history byte budget exceeded")]
    VersionCapacityExceeded,
}

/// Defines caller-side bounds for a pure operation wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationWaitPolicyV1 {
    maximum_elapsed_nanos: u64,
    maximum_observations: u32,
}

impl OperationWaitPolicyV1 {
    /// Constructs a bounded wait policy.
    ///
    /// # Errors
    ///
    /// Returns [`OperationWaitError::InvalidWaitBound`] for zero or excessive
    /// values.
    pub const fn new(
        maximum_elapsed_nanos: u64,
        maximum_observations: u32,
    ) -> Result<Self, OperationWaitError> {
        if maximum_elapsed_nanos == 0
            || maximum_elapsed_nanos > MAXIMUM_WAIT_NANOSECONDS
            || maximum_observations == 0
            || maximum_observations > MAXIMUM_WAIT_OBSERVATIONS
        {
            Err(OperationWaitError::InvalidWaitBound)
        } else {
            Ok(Self {
                maximum_elapsed_nanos,
                maximum_observations,
            })
        }
    }
}

/// Identifies why an operation wait stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationWaitTerminationV1 {
    /// The operation reached this terminal public phase.
    OperationTerminal(CheckedOperationPhaseV1),
    /// Caller-side elapsed time reached the wait deadline.
    DeadlineReached,
    /// The maximum number of observations was consumed.
    ObservationLimitReached,
}

/// Reports the result of reducing one operation observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationWaitApplyOutcomeV1 {
    /// The operation remains nonterminal and polling may continue.
    Pending,
    /// The exact current resource was replayed.
    Replay,
    /// The wait reached a terminal condition.
    Terminal(OperationWaitTerminationV1),
}

/// Reduces checked observations for one accepted operation.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationWaitReducerV1 {
    operation_id: [u8; 16],
    policy: OperationWaitPolicyV1,
    current: Option<CheckedOperationObservationV1>,
    seen_versions: BTreeSet<Vec<u8>>,
    seen_version_bytes: usize,
    observations: u32,
    elapsed_nanos: u64,
    termination: Option<OperationWaitTerminationV1>,
}

impl OperationWaitReducerV1 {
    /// Creates an empty reducer for one nonzero operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`OperationWaitError::OperationMismatch`] for the zero identity.
    pub fn new(
        operation_id: [u8; 16],
        policy: OperationWaitPolicyV1,
    ) -> Result<Self, OperationWaitError> {
        if operation_id == [0; 16] {
            return Err(OperationWaitError::OperationMismatch);
        }
        Ok(Self {
            operation_id,
            policy,
            current: None,
            seen_versions: BTreeSet::new(),
            seen_version_bytes: 0,
            observations: 0,
            elapsed_nanos: 0,
            termination: None,
        })
    }

    /// Returns the latest accepted operation resource.
    #[must_use]
    pub const fn current(&self) -> Option<&CheckedOperationResourceV1> {
        match &self.current {
            Some(observation) => Some(observation.resource()),
            None => None,
        }
    }

    /// Returns why this wait stopped, if terminal.
    #[must_use]
    pub const fn termination(&self) -> Option<OperationWaitTerminationV1> {
        self.termination
    }

    /// Advances caller-side elapsed time without canceling the operation.
    ///
    /// # Errors
    ///
    /// Returns [`OperationWaitError::ElapsedTimeRegression`] for backward time
    /// or [`OperationWaitError::AlreadyTerminal`] after stop.
    pub fn advance_elapsed(
        &mut self,
        elapsed_nanos: u64,
    ) -> Result<Option<OperationWaitTerminationV1>, OperationWaitError> {
        if self.termination.is_some() {
            return Err(OperationWaitError::AlreadyTerminal);
        }
        if elapsed_nanos < self.elapsed_nanos {
            return Err(OperationWaitError::ElapsedTimeRegression);
        }
        self.elapsed_nanos = elapsed_nanos;
        if elapsed_nanos >= self.policy.maximum_elapsed_nanos {
            let termination = OperationWaitTerminationV1::DeadlineReached;
            self.termination = Some(termination);
            Ok(Some(termination))
        } else {
            Ok(None)
        }
    }

    /// Reduces one checked operation observation at a monotonic elapsed time.
    ///
    /// Conflict checks occur before aggregate bounds, and all checks complete
    /// before state mutation.
    ///
    /// # Errors
    ///
    /// Returns [`OperationWaitError`] for identity, version, phase, immutable
    /// field, progress, condition, result, control-state, time, or terminal
    /// conflicts.
    pub fn apply(
        &mut self,
        observation: CheckedOperationObservationV1,
        elapsed_nanos: u64,
    ) -> Result<OperationWaitApplyOutcomeV1, OperationWaitError> {
        let resource = observation.resource();
        if resource.operation_id() != self.operation_id {
            return Err(OperationWaitError::OperationMismatch);
        }
        if elapsed_nanos < self.elapsed_nanos {
            return Err(OperationWaitError::ElapsedTimeRegression);
        }
        if self.termination.is_some_and(|reason| {
            !matches!(reason, OperationWaitTerminationV1::OperationTerminal(_))
        }) {
            return Err(OperationWaitError::AlreadyTerminal);
        }
        if let Some(current) = &self.current {
            let current_resource = current.resource();
            if current_resource.phase().is_terminal() {
                if observation == *current {
                    return Ok(OperationWaitApplyOutcomeV1::Replay);
                }
                return Err(OperationWaitError::TerminalConflict);
            }
            if resource.resource_version() == current_resource.resource_version() {
                if observation == *current {
                    return self.finish_replay(elapsed_nanos);
                }
                return Err(OperationWaitError::ResourceVersionConflict);
            }
            if self
                .seen_versions
                .contains(resource.resource_version().as_bytes())
            {
                return Err(OperationWaitError::ResourceVersionRegression);
            }
            if observation.observation_sequence() <= current.observation_sequence() {
                return Err(OperationWaitError::ObservationSequenceRegression);
            }
            validate_immutable_fields(current_resource, resource)?;
            if !operation_phase_can_follow(current_resource.phase(), resource.phase()) {
                return Err(OperationWaitError::InvalidPhaseAdvance);
            }
            validate_progress(current_resource, resource)?;
            validate_conditions(current.conditions(), observation.conditions())?;
            validate_results(current_resource.results(), resource.results())?;
            if resource.retry() < current_resource.retry()
                || (!current_resource.cancelable() && resource.cancelable())
            {
                return Err(OperationWaitError::ControlStateRegression);
            }
        }

        let next_observations = self.observations + 1;
        let version = resource.resource_version().as_bytes().to_vec();
        let next_version_bytes = self
            .seen_version_bytes
            .checked_add(version.len())
            .filter(|bytes| *bytes <= MAXIMUM_WAIT_VERSION_BYTES)
            .ok_or(OperationWaitError::VersionCapacityExceeded)?;
        let phase = resource.phase();
        self.elapsed_nanos = elapsed_nanos;
        self.observations = next_observations;
        self.seen_version_bytes = next_version_bytes;
        self.seen_versions.insert(version);
        self.current = Some(observation);

        if phase.is_terminal() {
            let termination = OperationWaitTerminationV1::OperationTerminal(phase);
            self.termination = Some(termination);
            return Ok(OperationWaitApplyOutcomeV1::Terminal(termination));
        }
        Ok(self.finish_bounds(elapsed_nanos))
    }

    fn finish_replay(
        &mut self,
        elapsed_nanos: u64,
    ) -> Result<OperationWaitApplyOutcomeV1, OperationWaitError> {
        self.elapsed_nanos = elapsed_nanos;
        self.observations += 1;
        match self.finish_bounds(elapsed_nanos) {
            OperationWaitApplyOutcomeV1::Pending => Ok(OperationWaitApplyOutcomeV1::Replay),
            terminal => Ok(terminal),
        }
    }

    fn finish_bounds(&mut self, elapsed_nanos: u64) -> OperationWaitApplyOutcomeV1 {
        if self.observations >= self.policy.maximum_observations {
            let termination = OperationWaitTerminationV1::ObservationLimitReached;
            self.termination = Some(termination);
            OperationWaitApplyOutcomeV1::Terminal(termination)
        } else if elapsed_nanos >= self.policy.maximum_elapsed_nanos {
            let termination = OperationWaitTerminationV1::DeadlineReached;
            self.termination = Some(termination);
            OperationWaitApplyOutcomeV1::Terminal(termination)
        } else {
            OperationWaitApplyOutcomeV1::Pending
        }
    }
}

fn validate_immutable_fields(
    previous: &CheckedOperationResourceV1,
    next: &CheckedOperationResourceV1,
) -> Result<(), OperationWaitError> {
    let previous = previous.as_proto();
    let next = next.as_proto();
    if previous.operation_id != next.operation_id
        || previous.method != next.method
        || previous.accepted_generation != next.accepted_generation
        || previous.audit_id != next.audit_id
        || previous.accepted_at != next.accepted_at
    {
        Err(OperationWaitError::ImmutableFieldConflict)
    } else {
        Ok(())
    }
}

fn validate_progress(
    previous: &CheckedOperationResourceV1,
    next: &CheckedOperationResourceV1,
) -> Result<(), OperationWaitError> {
    let (previous_completed, previous_total) = previous.progress();
    let (next_completed, next_total) = next.progress();
    let previous_stage = operation_progress_stage(previous.phase(), previous.milestone());
    let next_stage = operation_progress_stage(next.phase(), next.milestone());
    if next_stage < previous_stage {
        return Err(OperationWaitError::ProgressRegression);
    }
    if previous_stage == next_stage {
        if previous_total != next_total || previous_completed > next_completed {
            return Err(OperationWaitError::ProgressRegression);
        }
    }
    Ok(())
}

fn validate_conditions(
    previous: &[CheckedConditionObservationV1],
    next: &[CheckedConditionObservationV1],
) -> Result<(), OperationWaitError> {
    let mut next_index = 0;
    for previous_condition in previous {
        while next_index < next.len()
            && next[next_index].condition().code() < previous_condition.condition().code()
        {
            next_index += 1;
        }
        let Some(next_condition) = next.get(next_index) else {
            return Err(OperationWaitError::ConditionRegression);
        };
        if next_condition.condition().code() != previous_condition.condition().code()
            || next_condition.observation_sequence() < previous_condition.observation_sequence()
            || (next_condition.observation_sequence() == previous_condition.observation_sequence()
                && next_condition != previous_condition)
        {
            return Err(OperationWaitError::ConditionRegression);
        }
        next_index += 1;
    }
    Ok(())
}

fn validate_results(
    previous: &[CheckedResourceReferenceV1],
    next: &[CheckedResourceReferenceV1],
) -> Result<(), OperationWaitError> {
    let mut next_index = 0;
    for previous_result in previous {
        while next_index < next.len()
            && (
                next[next_index].resource_type(),
                next[next_index].resource_id(),
            ) < (
                previous_result.resource_type(),
                previous_result.resource_id(),
            )
        {
            next_index += 1;
        }
        let Some(next_result) = next.get(next_index) else {
            return Err(OperationWaitError::ResultRegression);
        };
        if next_result.as_proto() != previous_result.as_proto() {
            return Err(OperationWaitError::ResultRegression);
        }
        next_index += 1;
    }
    Ok(())
}
