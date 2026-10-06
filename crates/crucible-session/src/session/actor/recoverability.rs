//! Classification of recoverable actor, engine, scheduler, and backend rejections.

use super::*;

/// Captures rejection policy without copying any command-owned history.
#[derive(Clone, Copy)]
pub(in super::super) struct CommandRejectionKind {
    reverse: bool,
    debugger: bool,
}

impl CommandRejectionKind {
    pub(in super::super) fn from_command(command: &SessionCommand) -> Self {
        Self {
            reverse: matches!(
                command,
                SessionCommand::DebugReverseStep { .. }
                    | SessionCommand::DebugReverseContinue { .. }
            ),
            debugger: matches!(
                command,
                SessionCommand::AttachGdb { .. }
                    | SessionCommand::DebugGoto { .. }
                    | SessionCommand::DebugReverseStep { .. }
                    | SessionCommand::DebugReverseContinue { .. }
                    | SessionCommand::DebugForkNonCanonical { .. }
                    | SessionCommand::GuestIntrospection { .. }
                    | SessionCommand::Acknowledge { .. }
            ),
        }
    }
}

pub(in super::super) fn is_recoverable_command_rejection(
    command: CommandRejectionKind,
    error: &SessionError,
) -> bool {
    if matches!(error, SessionError::DebugHistoryUnavailable { .. }) && command.reverse {
        return true;
    }
    if !command.debugger {
        return false;
    }
    match error {
        SessionError::InvalidTransition { .. }
        | SessionError::InvalidEngineState { .. }
        | SessionError::BreakpointConditionPrefix { .. }
        | SessionError::UnsupportedBreakpointAction { .. }
        | SessionError::UnsupportedBreakpointFault { .. }
        | SessionError::BreakpointNotFound { .. }
        | SessionError::DebugAttachRequired { .. }
        | SessionError::DebugNonCanonicalBranchRequired { .. }
        | SessionError::GuestIntrospectionNotAuthorized { .. }
        | SessionError::GuestIntrospectionActivation { .. }
        | SessionError::GuestIntrospectionCapabilityUnavailable { .. }
        | SessionError::GuestIntrospectionChannelLimit { .. }
        | SessionError::DebugHistoryUnavailable { .. } => true,
        SessionError::Engine(error) => is_recoverable_engine_rejection(error),
        SessionError::Scheduler(error) => is_recoverable_scheduler_rejection(error),
        SessionError::ChannelClosed
        | SessionError::EventLogOffsetRegression { .. }
        | SessionError::EventLogOffsetMismatch { .. }
        | SessionError::ControlReplayBoundaryMismatch { .. }
        | SessionError::ControlReplayFrontierMismatch { .. }
        | SessionError::ControlReplayBatchMismatch { .. }
        | SessionError::ControlReplayFinalSnapshotMismatch { .. }
        | SessionError::ControlReplayInitialConfigurationMismatch { .. }
        | SessionError::ControlReplayRecordInvalid { .. }
        | SessionError::ControlReplayTerminalSamplingCleanup { .. }
        | SessionError::DebugRuntimeRepositionMismatch(_) => false,
    }
}

/// Distinguishes engine-driven failures from rejected operator commands.
pub(in super::super) fn is_autonomous_actor_error(error: &SessionError) -> bool {
    matches!(
        error,
        SessionError::Scheduler(_)
            | SessionError::EventLogOffsetRegression { .. }
            | SessionError::EventLogOffsetMismatch { .. }
            | SessionError::BreakpointConditionPrefix { .. }
            | SessionError::UnsupportedBreakpointAction { .. }
            | SessionError::UnsupportedBreakpointFault { .. }
            | SessionError::DebugRuntimeRepositionMismatch(_)
    )
}

pub(in super::super) fn is_recoverable_engine_rejection(error: &EngineError) -> bool {
    matches!(
        error,
        EngineError::CheckpointNotRecorded { .. }
            | EngineError::MissingBakedGenesis { .. }
            | EngineError::PropertyPredicateUnknownNode { .. }
            | EngineError::PropertyPredicateUnknownAssertion { .. }
            | EngineError::DebugAttachUnknownNode { .. }
            | EngineError::DebugTargetResolverFailureNotFound { .. }
            | EngineError::DebugGotoAttachMismatch { .. }
            | EngineError::DebugGotoScenarioMismatch { .. }
            | EngineError::DebugTimeTravelNoEarlierCoordinate { .. }
            | EngineError::DebugTimeTravelMissingEventCoordinate { .. }
            | EngineError::DebugTimeTravelCoordinateNotFound { .. }
            | EngineError::DebugTimeTravelUnknownNode { .. }
            | EngineError::DebugReverseContinueInvalidPrefix { .. }
            | EngineError::WorldNodeUnsupportedWorkload { .. }
            | EngineError::WorldNodeUnsupportedWorkloadConfigTree { .. }
            | EngineError::WorldNodeUnsupportedWorkloadPattern { .. }
            | EngineError::WorldNodeUnsupportedWorkloadSpikeMode { .. }
            | EngineError::WorldNodeUnsupportedWorkloadTimeSource { .. }
            | EngineError::DebugBreakpointRequiresAllowMutate { .. }
            | EngineError::EventLogReplayUnsupported { .. }
            | EngineError::SchedulePrefix(_)
    )
}

pub(in super::super) const fn is_recoverable_scheduler_rejection(error: &SchedulerError) -> bool {
    match error {
        SchedulerError::BoundaryViolation { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => true,
        SchedulerError::ResourceLimit { .. }
        | SchedulerError::Evaluation { .. }
        | SchedulerError::AssertionCheckpoint { .. } => false,
        SchedulerError::Backend(error) => is_recoverable_backend_rejection(error),
        SchedulerError::OperationalBoundary { .. } => false,
    }
}

pub(in super::super) const fn is_recoverable_backend_rejection(error: &BackendError) -> bool {
    match error {
        BackendError::Unsupported { .. } | BackendError::Rejected { .. } => true,
        BackendError::ResourceLimit { .. }
        | BackendError::OperationalFailure { .. }
        | BackendError::RetainedOperationalFailure { .. } => false,
    }
}
