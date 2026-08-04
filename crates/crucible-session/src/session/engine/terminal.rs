//! Engine-owned terminal outcomes and terminal checkpoint capture.

use super::*;

/// Engine-owned reason for entering the terminal state.
pub(super) enum TerminalCause {
    /// The assertion/trigger layer produced one or more property violations.
    Failed(Vec<String>),
    /// The run reached quiescence without a property violation.
    Passed,
    /// A configured execution budget was exhausted.
    BudgetExhausted,
    /// A live backend failed while the scheduler was driving it.
    BackendCrash(String),
    /// The operator explicitly stopped the session.
    OperatorStop,
}

impl<L> Engine<L> {
    pub(crate) fn stop_after_budget_exhaustion(&mut self) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        self.shutdown_quantum_loop()?;
        self.pending_control.clear();
        self.active_step = None;
        self.enter_stopped(TerminalCause::BudgetExhausted)
    }

    pub(crate) fn stop_after_backend_crash(&mut self, detail: String) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        self.pending_control.clear();
        self.active_step = None;
        self.enter_stopped(TerminalCause::BackendCrash(detail))
    }

    /// Publishes an actor failure as a terminal crash even if checkpointing fails.
    pub(crate) fn stop_after_actor_crash(&mut self, mut detail: String) {
        self.pending_control.clear();
        self.active_step = None;
        match self.save_current_checkpoint() {
            Ok(checkpoint) => self.terminal_savepoint = Some(checkpoint),
            Err(error) => {
                detail.push_str("; terminal checkpoint failed: ");
                detail.push_str(&error.to_string());
                self.terminal_savepoint = None;
            }
        }
        self.state = EngineState::Stopped {
            outcome: Outcome::Crashed { detail },
        };
    }

    pub(super) fn enter_stopped(&mut self, cause: TerminalCause) -> Result<(), SessionError> {
        let outcome = match cause {
            TerminalCause::Failed(violations) => Outcome::Failed { violations },
            TerminalCause::Passed => Outcome::Passed,
            TerminalCause::BudgetExhausted => Outcome::Timeout,
            TerminalCause::BackendCrash(detail) => Outcome::Crashed { detail },
            TerminalCause::OperatorStop => Outcome::Stopped,
        };
        let checkpoint = self.save_current_checkpoint()?;
        self.terminal_savepoint = Some(checkpoint);
        self.state = EngineState::Stopped { outcome };
        Ok(())
    }

    pub(super) fn save_current_checkpoint(&mut self) -> Result<Checkpoint, SessionError> {
        let mut checkpoint = self.graph.save_checkpoint(&self.configuration)?;
        checkpoint.virtual_time = self.frontier;
        Ok(checkpoint)
    }
}

/// Projects terminal pass/fail actions from a possibly grouped breakpoint action.
pub(super) fn breakpoint_terminal_verdict(action: &Action) -> (bool, Vec<String>) {
    match action {
        Action::Pass => (true, Vec::new()),
        Action::Fail { reason } => (false, vec![reason.clone()]),
        Action::Group(actions) => {
            let mut passed = false;
            let mut violations = Vec::new();
            for action in actions {
                let (action_passed, mut action_violations) = breakpoint_terminal_verdict(action);
                passed |= action_passed;
                violations.append(&mut action_violations);
            }
            violations.sort();
            violations.dedup();
            (passed, violations)
        }
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Log { .. } => (false, Vec::new()),
    }
}
