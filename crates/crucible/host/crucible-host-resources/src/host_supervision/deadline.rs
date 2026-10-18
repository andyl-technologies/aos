//! Computes allocation-free operation deadlines and renders owned provenance.
//!
//! The parent module owns synchronization, original clocks and sticky updates.
//! This module reads one borrowed operation and preserves tied-source order;
//! only the public report conversion constructs an owned source list.

use std::time::Duration;

use super::{
    HostDeadlineSource, HostEffectiveDeadline, HostOperationClass, HostOperationState,
    HostOperationStatus, HostSupervisionError, Operation, SupervisionState, progress_kind,
};

// Liveness checks need a deadline decision, while status callers also need an
// owned list of tied sources. Keeping that distinction avoids heap allocation
// on each poll without changing deadline provenance or terminal precedence.
#[derive(Clone, Copy, Debug)]
struct DeadlineLimits {
    progress: Option<Duration>,
    total: Option<Duration>,
    outer: Option<Duration>,
}

impl DeadlineLimits {
    fn for_operation(state: &SupervisionState, operation: &Operation, elapsed: Duration) -> Self {
        let budget = state.budgets.get(operation.class);
        Self {
            progress: budget.progress_timeout.map(|allowance| {
                allowance.saturating_sub(elapsed.saturating_sub(operation.last_progress))
            }),
            total: budget.total_timeout.map(|allowance| {
                allowance.saturating_sub(elapsed.saturating_sub(operation.started))
            }),
            outer: (operation.class != HostOperationClass::Cleanup)
                .then_some(state.cap_allowance)
                .flatten()
                .map(|allowance| allowance.saturating_sub(elapsed)),
        }
    }

    fn decision(self) -> Option<DeadlineDecision> {
        let remaining = [self.progress, self.total, self.outer]
            .into_iter()
            .flatten()
            .min()?;
        Some(DeadlineDecision {
            remaining,
            progress_limited: self.progress == Some(remaining),
            total_limited: self.total == Some(remaining),
            outer_limited: self.outer == Some(remaining),
        })
    }
}

#[derive(Clone, Copy, Debug)]
/// Stores the fixed deadline and its tied provenance without an owned list.
pub(super) struct DeadlineDecision {
    /// Minimum remaining allowance among applicable original deadlines.
    pub(super) remaining: Duration,
    progress_limited: bool,
    total_limited: bool,
    outer_limited: bool,
}

impl DeadlineDecision {
    fn into_status(self, state: &SupervisionState) -> HostEffectiveDeadline {
        #[cfg(test)]
        DEADLINE_STATUS_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));

        let mut sources = Vec::with_capacity(3);
        if self.progress_limited {
            sources.push(HostDeadlineSource::Progress(state.policy_revision));
        }
        if self.total_limited {
            sources.push(HostDeadlineSource::Total(state.policy_revision));
        }
        if self.outer_limited {
            sources.push(HostDeadlineSource::Outer {
                cap_id: state.cap_id,
                revision: state.cap_revision,
            });
        }
        HostEffectiveDeadline {
            remaining: self.remaining,
            sources,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Stores the disposition needed by polling and completion checks.
pub(super) struct OperationDecision {
    /// Original operation class whose policy supplied the deadline.
    pub(super) class: HostOperationClass,
    /// Sticky disposition after applying the original precedence rules.
    pub(super) state: HostOperationState,
    /// Applicable deadline, absent for explicitly unlimited execution.
    pub(super) deadline: Option<DeadlineDecision>,
}

impl OperationDecision {
    /// Requires continuation under the already computed sticky disposition.
    ///
    /// # Errors
    /// Reports the original operation identity and class on expiration, or the
    /// original sticky terminal disposition otherwise.
    pub(super) fn require_running(self, id: u64) -> Result<(), HostSupervisionError> {
        match self.state {
            HostOperationState::Running => Ok(()),
            HostOperationState::Expired => Err(HostSupervisionError::DeadlineExpired {
                operation_id: id,
                class: self.class,
            }),
            state => Err(HostSupervisionError::Terminal { state }),
        }
    }
}

/// Computes disposition and tied deadlines from one already borrowed operation.
pub(super) fn decide_operation(
    state: &SupervisionState,
    operation: &Operation,
    elapsed: Duration,
) -> OperationDecision {
    let deadline = DeadlineLimits::for_operation(state, operation, elapsed).decision();
    let disposition = if operation.state != HostOperationState::Running {
        operation.state
    } else if operation.class != HostOperationClass::Cleanup
        && state.cap_state != HostOperationState::Running
    {
        state.cap_state
    } else if deadline.is_some_and(|deadline| deadline.remaining.is_zero()) {
        HostOperationState::Expired
    } else {
        HostOperationState::Running
    };
    OperationDecision {
        class: operation.class,
        state: disposition,
        deadline,
    }
}

/// Renders an owned report from the same operation used for its decision.
pub(super) fn operation_status_from_decision(
    state: &SupervisionState,
    id: u64,
    operation: &Operation,
    decision: OperationDecision,
) -> HostOperationStatus {
    HostOperationStatus {
        operation_id: id,
        class: decision.class,
        started_policy_revision: operation.started_revision,
        applied_policy_revision: state.policy_revision,
        completed_work_units: operation.completed,
        outstanding_work_units: operation.required.saturating_sub(operation.completed),
        progress_kind: progress_kind(decision.class),
        state: decision.state,
        effective_deadline: decision
            .deadline
            .map(|deadline| deadline.into_status(state)),
    }
}

#[cfg(test)]
thread_local! {
    // Counts owned reporting conversions, rather than inferring allocator calls.
    static DEADLINE_STATUS_CONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
#[path = "decision_tests.rs"]
mod tests;
