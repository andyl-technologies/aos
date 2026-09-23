//! Closed public execution-control lowering for protected effect dispatch.
//!
//! Attach requires a separately authorized OpenSSH data route. Resize and
//! signal become portable guest-agent effects with no raw public enum values
//! crossing the Host boundary.

use aos_proto::aos::sandbox::v1::{
    ExecutionControlAction, ExecutionControlRequest, ExecutionSignal,
};
use aos_sandbox_core::runtime_backend::EffectOperationV1;

use crate::OperationCompilationError;

/// Separates a data-route attach from a guest-agent execution effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicExecutionControlDispatchV1 {
    /// Requires an OpenSSH data route without a guest-agent control effect.
    Attach,
    /// Carries a checked, portable guest-agent control operation.
    Effect(EffectOperationV1),
}

/// Lowers one canonical public control action into its closed dispatch kind.
///
/// # Errors
///
/// Returns [`OperationCompilationError::Malformed`] for an unknown action,
/// incompatible fields, invalid PTY geometry, or an unknown signal.
pub fn lower_public_execution_control_v1(
    request: &ExecutionControlRequest,
) -> Result<PublicExecutionControlDispatchV1, OperationCompilationError> {
    use ExecutionControlAction as Action;
    use ExecutionSignal as Signal;

    let no_geometry = request.terminal_rows == 0 && request.terminal_columns == 0;
    match request.action.as_known() {
        Some(Action::EXECUTION_CONTROL_ACTION_ATTACH)
            if no_geometry && request.signal.to_i32() == 0 =>
        {
            Ok(PublicExecutionControlDispatchV1::Attach)
        }
        Some(Action::EXECUTION_CONTROL_ACTION_RESIZE) if request.signal.to_i32() == 0 => {
            let rows = u16::try_from(request.terminal_rows)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(OperationCompilationError::Malformed)?;
            let columns = u16::try_from(request.terminal_columns)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(OperationCompilationError::Malformed)?;
            Ok(PublicExecutionControlDispatchV1::Effect(
                EffectOperationV1::ResizeTerminal { rows, columns },
            ))
        }
        Some(Action::EXECUTION_CONTROL_ACTION_SIGNAL) if no_geometry => {
            let signal_code = match request.signal.as_known() {
                Some(Signal::EXECUTION_SIGNAL_HANGUP) => 1,
                Some(Signal::EXECUTION_SIGNAL_INTERRUPT) => 2,
                Some(Signal::EXECUTION_SIGNAL_QUIT) => 3,
                Some(Signal::EXECUTION_SIGNAL_TERMINATE) => 15,
                Some(Signal::EXECUTION_SIGNAL_KILL) => 9,
                Some(Signal::EXECUTION_SIGNAL_USER_1) => 10,
                Some(Signal::EXECUTION_SIGNAL_USER_2) => 12,
                _ => return Err(OperationCompilationError::Malformed),
            };
            Ok(PublicExecutionControlDispatchV1::Effect(
                EffectOperationV1::Signal { signal_code },
            ))
        }
        _ => Err(OperationCompilationError::Malformed),
    }
}
