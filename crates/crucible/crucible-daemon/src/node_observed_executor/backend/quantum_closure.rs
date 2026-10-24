//! Per-original operational close requests, independent of native settlement.
//!
//! Deadlines are established before round submission. Their clock never defines
//! a logical coordinate, native elapsed-time receipt or physical pause claim.

use std::time::Duration;

use crucible_engine::{
    node_contract::Submission,
    node_dispatch::{DispatchError, DispatchStartFailure},
};
use crucible_node_format::Id;

use crate::supervision::ProcessDeadline;

use super::NodeObservedError;

/// Keeps the selected close rows beside any original partial-start failure.
pub(super) struct PendingRoundStart {
    pub(super) closures: QuantizedClosures,
    pub(super) failure: Option<DispatchStartFailure>,
}

impl PendingRoundStart {
    /// Checks every original controller deadline before native submission.
    ///
    /// # Errors
    /// Refuses row allocation or an unrepresentable anchor/budget sum.
    pub(super) fn prepare(budgets: Vec<(Id, Duration)>) -> Result<Self, NodeObservedError> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(budgets.len()).map_err(|_| {
            NodeObservedError::Native("original close schedule allocation refused".into())
        })?;
        let anchor = ProcessDeadline::after(Duration::ZERO).ok_or_else(|| {
            NodeObservedError::Native("round host anchor cannot be represented".into())
        })?;
        for (operation, budget) in budgets {
            let deadline = anchor.checked_add(budget).ok_or_else(|| {
                NodeObservedError::Native("host budget overflows monotonic clock".into())
            })?;
            rows.push(CloseRow {
                operation,
                deadline,
                started: false,
                state: CloseState::Pending,
            });
        }
        Ok(Self {
            closures: QuantizedClosures { rows },
            failure: None,
        })
    }

    /// Retains real accepted tokens and unused grants without another start.
    pub(super) fn retain_failure(&mut self, failure: DispatchStartFailure) {
        for token in &failure.accepted {
            self.closures.mark_started(token.operation());
        }
        self.failure = Some(failure);
    }
}

/// Holds one sticky close-request state for each original quantized operation.
pub(super) struct QuantizedClosures {
    pub(super) rows: Vec<CloseRow>,
}

pub(super) struct CloseRow {
    pub(super) operation: Id,
    pub(super) deadline: ProcessDeadline,
    pub(super) started: bool,
    state: CloseState,
}

enum CloseState {
    Pending,
    Submitting,
    Submitted(Submission),
    Settled,
    Failed(String),
}

impl QuantizedClosures {
    /// Records membership only after observing the original dispatch token.
    pub(super) fn mark_started(&mut self, operation: &Id) {
        if let Some(row) = self.rows.iter_mut().find(|row| &row.operation == operation) {
            row.started = true;
        }
    }

    /// Retains each request's actual outcome before returning an error.
    ///
    /// # Errors
    /// Refuses absent actual start membership, a refused or uncertain close,
    /// or a retained native failure. None of these states permits a retry.
    pub(super) fn request_due(
        &mut self,
        mut close: impl FnMut(&Id) -> Result<Option<Submission>, DispatchError>,
    ) -> Result<(), NodeObservedError> {
        for row in &mut self.rows {
            if let Some(reason) = row.failure_reason() {
                return Err(NodeObservedError::Native(reason));
            }
            if !row.started {
                return Err(NodeObservedError::Native(
                    "original quantized operation has no actual started token".into(),
                ));
            }
            if !matches!(row.state, CloseState::Pending) || !row.deadline.expired() {
                continue;
            }
            // An adapter can unwind after an effect. Keep this original request
            // sticky before the callback so reuse cannot issue a second close.
            row.state = CloseState::Submitting;
            row.state = match close(&row.operation) {
                Ok(Some(submission)) => CloseState::Submitted(submission),
                Ok(None) => CloseState::Settled,
                Err(error) => CloseState::Failed(error.to_string()),
            };
            if let Some(reason) = row.failure_reason() {
                return Err(NodeObservedError::Native(reason));
            }
        }
        Ok(())
    }
}

impl CloseRow {
    fn failure_reason(&self) -> Option<String> {
        match &self.state {
            CloseState::Submitted(Submission::Accepted)
            | CloseState::Pending
            | CloseState::Settled => None,
            CloseState::Submitted(submission) => Some(format!(
                "original native window {} closure was not accepted: {submission:?}",
                self.operation
            )),
            CloseState::Failed(reason) => Some(reason.clone()),
            CloseState::Submitting => Some(format!(
                "original native window {} closure remains uncertain after submission",
                self.operation
            )),
        }
    }
}
