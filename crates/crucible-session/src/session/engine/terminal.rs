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
    pub(crate) fn stop_after_actor_crash(&mut self, mut detail: String)
    where
        L: QuantumLoop,
    {
        self.pending_control.clear();
        self.active_step = None;
        self.resolve_guest_introspection_for_terminal();
        match self.save_current_checkpoint() {
            Ok(checkpoint) => self.terminal_savepoint = Some(checkpoint),
            Err(error) => {
                detail.push_str("; terminal checkpoint failed: ");
                detail.push_str(&error.to_string());
                self.terminal_savepoint = None;
            }
        }
        self.debug_attach = None;
        self.debug_branch_required = false;
        self.debug_coordinator.detached();
        self.state = EngineState::Stopped {
            outcome: Outcome::Crashed { detail },
        };
    }

    pub(super) fn enter_stopped(&mut self, cause: TerminalCause) -> Result<(), SessionError>
    where
        L: QuantumLoop,
    {
        self.resolve_guest_introspection_for_terminal();
        let outcome = match cause {
            TerminalCause::Failed(violations) => Outcome::Failed { violations },
            TerminalCause::Passed => Outcome::Passed,
            TerminalCause::BudgetExhausted => Outcome::Timeout,
            TerminalCause::BackendCrash(detail) => Outcome::Crashed { detail },
            TerminalCause::OperatorStop => Outcome::Stopped,
        };
        // A production checkpoint needs live, quiesced QEMU processes. Capture
        // the resumable boundary before teardown; shutdown observations belong
        // to the terminal session record, not to the resumable checkpoint.
        let checkpoint = self.save_current_checkpoint()?;
        self.shutdown_quantum_loop()?;
        self.terminal_savepoint = Some(checkpoint);
        self.debug_attach = None;
        self.debug_branch_required = false;
        self.debug_coordinator.detached();
        self.state = EngineState::Stopped { outcome };
        Ok(())
    }

    pub(super) fn save_current_checkpoint(&mut self) -> Result<Checkpoint, SessionError>
    where
        L: QuantumLoop,
    {
        let mut checkpoint = self.graph.save_checkpoint(&self.configuration)?;
        checkpoint.virtual_time = self.frontier;
        if let Some(closure) = self.quantum_loop.capture_checkpoint(&self.configuration)? {
            checkpoint = checkpoint.with_execution_closure(closure);
        }
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
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Log { .. } => (false, Vec::new()),
    }
}
