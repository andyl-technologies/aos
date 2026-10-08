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

pub(in super::super) fn is_recoverable_scheduler_rejection(error: &SchedulerError) -> bool {
    match error {
        SchedulerError::BoundaryViolation { .. }
        | SchedulerError::RamAdmission { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => true,
        SchedulerError::RamFailure { source, .. } => source
            .first_boundary()
            .map(is_recoverable_scheduler_rejection)
            .unwrap_or(true),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_cas::ram::{PreparedRamFailure, RamFailureAdmission, RamStoreError};

    #[test]
    fn typed_ram_failures_preserve_original_scheduler_recoverability() {
        // This established finite fixture models metadata loans only.
        let _scope = crucible::test_support::fixture_decode_scope(64 * 1024).unwrap();
        let original = crucible::owned_decode::current_budget().unwrap();
        for first in [
            SchedulerError::BoundaryViolation {
                message: String::from("original boundary rejection"),
            },
            SchedulerError::OperationalBoundary {
                class: crucible::SchedulerOperationalFailureClass::Canceled,
                message: String::from("original cancellation"),
            },
            SchedulerError::Backend(BackendError::Rejected {
                message: String::from("original backend rejection"),
            }),
        ] {
            let expected = is_recoverable_scheduler_rejection(&first);
            let prepared = PreparedRamFailure::<SchedulerError>::new(&original).unwrap();
            let error = SchedulerError::from_ram_failure(
                prepared.retain(Some(first), RamStoreError::Invalid("cleanup failure")),
            );
            assert_eq!(is_recoverable_scheduler_rejection(&error), expected);
            assert_eq!(is_recoverable_scheduler_rejection(&error.clone()), expected);
        }

        let prepared = PreparedRamFailure::<SchedulerError>::new(&original).unwrap();
        let storage = SchedulerError::from_ram_failure(
            prepared.retain(None, RamStoreError::Invalid("original RAM store rejection")),
        );
        assert!(is_recoverable_scheduler_rejection(&storage));
        let admission = SchedulerError::RamAdmission {
            source: RamFailureAdmission::Original(
                crucible::owned_decode::DecodeAdmissionError::new(
                    std::io::Error::from_raw_os_error(12),
                ),
            ),
            custody: original.custody(),
        };
        assert!(is_recoverable_scheduler_rejection(&admission));
    }
}
