//! Classification of recoverable actor, engine, scheduler, and backend rejections.

use super::*;

pub(in super::super) fn is_recoverable_command_rejection(
    command: &SessionCommand,
    error: &SessionError,
) -> bool {
    if matches!(error, SessionError::DebugHistoryUnavailable { .. })
        && matches!(
            command,
            SessionCommand::DebugReverseStep { .. } | SessionCommand::DebugReverseContinue { .. }
        )
    {
        return true;
    }
    let debugger_command = matches!(
        command,
        SessionCommand::AttachGdb { .. }
            | SessionCommand::DebugGoto { .. }
            | SessionCommand::DebugReverseStep { .. }
            | SessionCommand::DebugReverseContinue { .. }
            | SessionCommand::DebugForkNonCanonical { .. }
            | SessionCommand::GuestIntrospection { .. }
            | SessionCommand::Acknowledge { .. }
    );
    if !debugger_command {
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
            | EngineError::NotImplemented { .. }
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
        SchedulerError::NotImplemented { .. }
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => true,
        SchedulerError::Backend(error) => is_recoverable_backend_rejection(error),
    }
}

pub(in super::super) const fn is_recoverable_backend_rejection(error: &BackendError) -> bool {
    match error {
        BackendError::NotImplemented { .. }
        | BackendError::Unsupported { .. }
        | BackendError::Rejected { .. } => true,
    }
}
