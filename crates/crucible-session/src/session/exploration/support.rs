//! Conversion, handle-identity, and action-classification helpers.

use super::*;

pub(super) fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub(super) fn u64_to_usize(value: u64) -> usize {
    match usize::try_from(value) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}

pub(super) fn fork_session_handle_id(parent: ContentHash, checkpoint: ContentHash) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.session.fork-handle.v1",
        &format!(
            "parent={}\ncheckpoint={}\n",
            parent.to_hex(),
            checkpoint.to_hex()
        ),
    )
}

pub(super) fn breakpoint_action_kind(action: &Action) -> &'static str {
    match action {
        Action::InjectFault { .. } => "inject-fault",
        Action::HealFault { .. } => "heal-fault",
        Action::ArmTimer { .. } => "arm-timer",
        Action::CancelTimer { .. } => "cancel-timer",
        Action::StartNode { .. } => "start-node",
        Action::StopNode { .. } => "stop-node",
        Action::CreateSavepoint { .. } => "create-savepoint",
        Action::Fork { .. } => "fork",
        Action::Pass => "pass",
        Action::Fail { .. } => "fail",
        Action::Log { .. } => "log",
        Action::Group(_) => "group",
    }
}

pub(super) fn control_operation_command_kind(
    control: &ControlOperationKind,
) -> Option<SessionCommandKind> {
    match control {
        ControlOperationKind::InjectFault { .. } => Some(SessionCommandKind::InjectFault),
        ControlOperationKind::HealFault { .. } => Some(SessionCommandKind::HealFault),
        ControlOperationKind::Inject
        | ControlOperationKind::Pause
        | ControlOperationKind::Resume
        | ControlOperationKind::Step
        | ControlOperationKind::Snapshot
        | ControlOperationKind::Fork
        | ControlOperationKind::Query => None,
    }
}
