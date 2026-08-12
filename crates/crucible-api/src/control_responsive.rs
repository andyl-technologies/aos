//! Quantum-counted control responsiveness contracts.
//!
//! The control API is a thin wrapper over the session actor. This module keeps
//! the API-side gate contract equally thin: callers provide acknowledgement
//! records from an in-process client, RPC route, or daemon route, and validation
//! is expressed only in scheduler quanta. Wall-clock durations are deliberately
//! absent from the data model.

use std::collections::BTreeSet;
use std::sync::Arc;

use crucible_session::{LiveSnapshot, SessionCommand};
use thiserror::Error;
use tokio::sync::mpsc;

/// Maximum acknowledgement latency accepted by `gate:control-responsive`.
pub const CONTROL_RESPONSIVE_QUANTUM_BOUND: u64 = 1;

/// Running-session control operations that the responsiveness gate must observe.
pub const CONTROL_RESPONSIVE_REQUIRED_OPERATIONS: [ControlOperationKind; 2] =
    [ControlOperationKind::Pause, ControlOperationKind::Query];

/// A control operation class measured by `gate:control-responsive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlOperationKind {
    /// Pause a running session at the next quantum boundary.
    Pause,
    /// Fork a child session from a deterministic checkpoint or prefix boundary.
    Fork,
    /// Read the current session state without mutating the run.
    Query,
}

/// Run state observed when a control operation was issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlSessionState {
    /// The session is loaded but not instantiated.
    Loaded,
    /// The session is actively stepping bounded scheduler quanta.
    Running,
    /// The session is idle at a quantum boundary.
    Paused,
    /// The session has reached a terminal state.
    Stopped,
}

/// Terminal acknowledgement status for a control operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlAcknowledgementStatus {
    /// The operation was accepted and applied.
    Applied,
    /// The operation was acknowledged with a typed rejection.
    Rejected,
}

/// A quantum-counted acknowledgement record for one control operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlOperationAcknowledgement {
    /// Operation class that was issued.
    pub operation: ControlOperationKind,
    /// Session state at the issuing boundary.
    pub requested_state: ControlSessionState,
    /// Scheduler quantum count visible when the operation was issued.
    pub requested_at_quantum: u64,
    /// Scheduler quantum count visible when the operation was acknowledged.
    pub acknowledged_at_quantum: u64,
    /// Whether the operation applied or was rejected by typed control logic.
    pub status: ControlAcknowledgementStatus,
}

impl ControlOperationAcknowledgement {
    /// Builds a quantum-counted acknowledgement record.
    #[must_use]
    pub const fn new(
        operation: ControlOperationKind,
        requested_state: ControlSessionState,
        requested_at_quantum: u64,
        acknowledged_at_quantum: u64,
        status: ControlAcknowledgementStatus,
    ) -> Self {
        Self {
            operation,
            requested_state,
            requested_at_quantum,
            acknowledged_at_quantum,
            status,
        }
    }

    /// Returns the acknowledgement latency measured in scheduler quanta.
    #[must_use]
    pub fn acknowledgement_delta_quanta(&self) -> Option<u64> {
        self.acknowledged_at_quantum
            .checked_sub(self.requested_at_quantum)
    }
}

/// Successful validation evidence for `gate:control-responsive`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlResponsiveReport {
    /// Bound applied to each operation, measured in scheduler quanta.
    pub bound_quanta: u64,
    /// Number of acknowledgement records inspected.
    pub observations: usize,
    /// Number of required operation classes observed.
    pub required_operations_observed: usize,
    /// Largest acknowledgement latency observed, in scheduler quanta.
    pub max_acknowledgement_delta_quanta: u64,
}

/// Error returned when control responsiveness evidence does not satisfy the gate.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ControlResponsivenessError {
    /// The operation was not issued against a running session.
    #[error("control operation {operation:?} was issued against {requested_state:?}, not Running")]
    OperationNotAgainstRunningSession {
        /// Operation that was issued in the wrong state.
        operation: ControlOperationKind,
        /// State observed when the operation was issued.
        requested_state: ControlSessionState,
    },
    /// The acknowledgement quantum counter moved backward.
    #[error(
        "control operation {operation:?} acknowledged at quantum {acknowledged_at_quantum} before request quantum {requested_at_quantum}"
    )]
    AcknowledgementBeforeRequest {
        /// Operation whose acknowledgement counter moved backward.
        operation: ControlOperationKind,
        /// Quantum count visible at request time.
        requested_at_quantum: u64,
        /// Quantum count visible at acknowledgement time.
        acknowledged_at_quantum: u64,
    },
    /// The acknowledgement took more quanta than the configured bound.
    #[error(
        "control operation {operation:?} acknowledgement took {observed_delta_quanta} quanta, exceeding bound {bound_quanta}"
    )]
    AcknowledgementExceededBound {
        /// Operation that exceeded the quantum bound.
        operation: ControlOperationKind,
        /// Observed acknowledgement latency in scheduler quanta.
        observed_delta_quanta: u64,
        /// Accepted acknowledgement bound in scheduler quanta.
        bound_quanta: u64,
    },
    /// Required operation coverage was incomplete.
    #[error("control-responsive gate did not observe required operation {operation:?}")]
    MissingRequiredOperation {
        /// Required operation that was absent from the evidence set.
        operation: ControlOperationKind,
    },
    /// A required operation was acknowledged as a rejection rather than applied.
    #[error("control-responsive gate required operation {operation:?} to apply, got {status:?}")]
    RequiredOperationRejected {
        /// Required operation that was rejected.
        operation: ControlOperationKind,
        /// Rejected acknowledgement status.
        status: ControlAcknowledgementStatus,
    },
    /// The live session command channel closed before the command was accepted.
    #[error("control operation {operation:?} could not be sent because the session channel closed")]
    CommandChannelClosed {
        /// Operation whose session command could not be sent.
        operation: ControlOperationKind,
    },
    /// A live session did not acknowledge the operation within the actor-yield budget.
    #[error(
        "control operation {operation:?} was not acknowledged after {max_actor_yields} actor yields"
    )]
    AcknowledgementTimeout {
        /// Operation that was not acknowledged in time.
        operation: ControlOperationKind,
        /// Quantum count visible when the operation was requested.
        requested_at_quantum: u64,
        /// Acknowledgement counter visible before the operation was sent.
        acknowledgement_count_before: u64,
        /// Actor-yield budget used while waiting.
        max_actor_yields: u64,
    },
}

/// Live in-process probe for `gate:control-responsive`.
///
/// The probe is the API's thin in-process route over a same-process session
/// actor. It sends one [`SessionCommand`] through the actor mailbox and records
/// the acknowledgement using only lock-free live-snapshot counters.
#[derive(Clone)]
pub struct ControlResponsiveSessionProbe {
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    max_actor_yields: u64,
}

impl ControlResponsiveSessionProbe {
    /// Creates a probe over a running same-process session actor.
    #[must_use]
    pub fn new(sender: mpsc::Sender<SessionCommand>, live: Arc<LiveSnapshot>) -> Self {
        Self {
            sender,
            live,
            max_actor_yields: 128,
        }
    }

    /// Returns a copy of this probe with an explicit actor-yield wait budget.
    #[must_use]
    pub fn with_max_actor_yields(mut self, max_actor_yields: u64) -> Self {
        self.max_actor_yields = max_actor_yields;
        self
    }

    /// Issues one operation against a running session and records its ack delta.
    ///
    /// # Errors
    ///
    /// Returns [`ControlResponsivenessError`] when the operation is not issued
    /// against a running session, the command channel closes, or the actor does
    /// not publish an acknowledgement within the configured actor-yield budget.
    pub async fn issue_against_running_session(
        &self,
        operation: ControlOperationKind,
    ) -> Result<ControlOperationAcknowledgement, ControlResponsivenessError> {
        let before = self.live.read();
        if before.state_kind != crucible_session::LiveStateKind::Running {
            return Err(
                ControlResponsivenessError::OperationNotAgainstRunningSession {
                    operation,
                    requested_state: ControlSessionState::from(before.state_kind),
                },
            );
        }

        let command = session_command_for(operation);
        let acknowledgement_count_before = before.control_acknowledgements;
        self.sender
            .send(command)
            .await
            .map_err(|_| ControlResponsivenessError::CommandChannelClosed { operation })?;

        for _ in 0..self.max_actor_yields {
            tokio::task::yield_now().await;
            let after = self.live.read();
            if after.control_acknowledgements > acknowledgement_count_before {
                return Ok(ControlOperationAcknowledgement::new(
                    operation,
                    ControlSessionState::Running,
                    before.quanta_stepped,
                    after.quanta_stepped,
                    ControlAcknowledgementStatus::Applied,
                ));
            }
        }

        Err(ControlResponsivenessError::AcknowledgementTimeout {
            operation,
            requested_at_quantum: before.quanta_stepped,
            acknowledgement_count_before,
            max_actor_yields: self.max_actor_yields,
        })
    }
}

impl From<crucible_session::LiveStateKind> for ControlSessionState {
    fn from(value: crucible_session::LiveStateKind) -> Self {
        match value {
            crucible_session::LiveStateKind::Loaded => Self::Loaded,
            crucible_session::LiveStateKind::Running => Self::Running,
            crucible_session::LiveStateKind::Paused => Self::Paused,
            crucible_session::LiveStateKind::Stopped => Self::Stopped,
        }
    }
}

fn session_command_for(operation: ControlOperationKind) -> SessionCommand {
    match operation {
        ControlOperationKind::Pause => SessionCommand::Pause,
        ControlOperationKind::Fork => SessionCommand::fork_current(),
        ControlOperationKind::Query => SessionCommand::query_snapshot(),
    }
}

/// Validates that control acknowledgements satisfy the quantum-bound gate.
///
/// The validator requires each record to be issued while the session is running,
/// rejects backward quantum counters, enforces the supplied quantum bound, and
/// requires coverage of pause and query operations.
///
/// # Errors
///
/// Returns [`ControlResponsivenessError`] if any acknowledgement was not issued
/// from a running session, moves backward in quantum time, exceeds
/// `bound_quanta`, or omits a required operation class.
pub fn validate_control_responsiveness(
    acknowledgements: &[ControlOperationAcknowledgement],
    bound_quanta: u64,
) -> Result<ControlResponsiveReport, ControlResponsivenessError> {
    let mut observed_operations = BTreeSet::new();
    let mut max_acknowledgement_delta_quanta = 0_u64;

    for acknowledgement in acknowledgements {
        if acknowledgement.requested_state != ControlSessionState::Running {
            return Err(
                ControlResponsivenessError::OperationNotAgainstRunningSession {
                    operation: acknowledgement.operation,
                    requested_state: acknowledgement.requested_state,
                },
            );
        }

        let Some(delta) = acknowledgement.acknowledgement_delta_quanta() else {
            return Err(ControlResponsivenessError::AcknowledgementBeforeRequest {
                operation: acknowledgement.operation,
                requested_at_quantum: acknowledgement.requested_at_quantum,
                acknowledged_at_quantum: acknowledgement.acknowledged_at_quantum,
            });
        };

        if delta > bound_quanta {
            return Err(ControlResponsivenessError::AcknowledgementExceededBound {
                operation: acknowledgement.operation,
                observed_delta_quanta: delta,
                bound_quanta,
            });
        }

        max_acknowledgement_delta_quanta = max_acknowledgement_delta_quanta.max(delta);
        if CONTROL_RESPONSIVE_REQUIRED_OPERATIONS.contains(&acknowledgement.operation) {
            if acknowledgement.status != ControlAcknowledgementStatus::Applied {
                return Err(ControlResponsivenessError::RequiredOperationRejected {
                    operation: acknowledgement.operation,
                    status: acknowledgement.status,
                });
            }
            observed_operations.insert(acknowledgement.operation);
        }
    }

    for operation in CONTROL_RESPONSIVE_REQUIRED_OPERATIONS {
        if !observed_operations.contains(&operation) {
            return Err(ControlResponsivenessError::MissingRequiredOperation { operation });
        }
    }

    Ok(ControlResponsiveReport {
        bound_quanta,
        observations: acknowledgements.len(),
        required_operations_observed: observed_operations.len(),
        max_acknowledgement_delta_quanta,
    })
}
