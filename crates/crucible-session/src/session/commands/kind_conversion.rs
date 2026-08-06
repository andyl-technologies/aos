//! Session-command to command-kind conversion.

use super::*;

impl From<&SessionCommand> for SessionCommandKind {
    fn from(command: &SessionCommand) -> Self {
        match command {
            SessionCommand::Start => Self::Start,
            SessionCommand::Continue => Self::Continue,
            SessionCommand::Pause => Self::Pause,
            SessionCommand::Step {
                mode: StepMode::Quantum,
            } => Self::StepQuantum,
            SessionCommand::Step {
                mode: StepMode::Event,
            } => Self::StepEvent,
            SessionCommand::Step {
                mode: StepMode::Assertion,
            } => Self::StepAssertion,
            SessionCommand::Step {
                mode: StepMode::Timer,
            } => Self::StepTimer,
            SessionCommand::Step {
                mode: StepMode::Duration(_),
            } => Self::StepDuration,
            SessionCommand::Snapshot => Self::Snapshot,
            SessionCommand::Fork { .. } => Self::Fork,
            SessionCommand::Inject => Self::Inject,
            SessionCommand::SetBreakpoint { .. } => Self::SetBreakpoint,
            SessionCommand::RemoveBreakpoint { .. } => Self::RemoveBreakpoint,
            SessionCommand::CreateSavepoint { .. } => Self::CreateSavepoint,
            SessionCommand::Stop => Self::Stop,
            SessionCommand::ExhaustBudget => Self::ExhaustBudget,
            SessionCommand::Query { .. } => Self::Query,
            SessionCommand::AttachGdb { .. } => Self::AttachGdb,
            SessionCommand::DebugGoto { .. } => Self::DebugGoto,
            SessionCommand::DebugReverseStep { .. } => Self::DebugReverseStep,
            SessionCommand::DebugReverseContinue { .. } => Self::DebugReverseContinue,
            SessionCommand::DebugForkNonCanonical { .. } => Self::DebugForkNonCanonical,
            SessionCommand::Acknowledge { command, .. } => Self::from(command.as_ref()),
        }
    }
}
