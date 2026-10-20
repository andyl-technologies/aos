//! Same-process actor probe for quantum-counted control responsiveness.

use crucible_control_api::control_responsive::*;
use crucible_session::{LiveSnapshot, SessionCommand};
use std::sync::Arc;
use tokio::sync::mpsc;

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

fn session_command_for(operation: ControlOperationKind) -> SessionCommand {
    match operation {
        ControlOperationKind::Pause => SessionCommand::Pause,
        ControlOperationKind::Fork => SessionCommand::fork_current(),
        ControlOperationKind::Query => SessionCommand::query_snapshot(),
    }
}
