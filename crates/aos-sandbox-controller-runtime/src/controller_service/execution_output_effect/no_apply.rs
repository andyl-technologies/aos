//! Runs active NoApply on the original Host Session and live Source/C18 loan.
//!
//! A failed output preparation only triggers an attempt. Actual39, held42/43,
//! independent Root floor, native Cprepare/CAS, authenticated ACK and causal Root
//! confirmation must all complete before the later real Source disposal.

use aos_sandbox::controller_execution_operation::{
    ControllerExecutionNoApplyOriginalV2, ControllerExecutionReadReceivingLoanV1,
};
use aos_sandbox_broker_session_security::{
    ExecutionAvailabilitySessionIoOriginalV2, HostExecutionNoApplySessionIoOriginalV2,
};

use super::*;

pub(super) fn run_active_once_v2(
    sessions: &super::super::SharedControllerBrokerSessions,
    controller: &mut Journal,
    bank: &aos_sandbox::ControllerResourceBankOpeningV1,
    profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
    availability: &ExecutionAvailabilitySessionIoOriginalV2,
    original: &mut HostExecutionNoApplySessionIoOriginalV2,
    native: &mut ControllerExecutionNoApplyOriginalV2,
) -> Result<(), EffectFailure> {
    let closed = || retryable("the original active NoApply programme retains an entered refusal");
    let mut sessions = sessions.lock().map_err(|_| closed())?;
    if sessions
        .storage
        .as_ref()
        .is_none_or(|storage| storage.has_capture_candidate())
    {
        return Err(closed());
    }
    let host = sessions.host.as_mut().ok_or_else(closed)?;
    let host = host.execution_no_apply_session_v2().map_err(|_| closed())?;
    let mut borrower = host
        .borrow_active_execution_no_apply_client_once_v2(
            availability,
            original,
            native,
            controller,
            bank,
            profile,
            receiving,
        )
        .map_err(|_| closed())?;

    borrower.terminal_no_apply_once_v2().map_err(|_| closed())?;
    borrower.preliminary_once_v2().map_err(|_| closed())?;
    borrower
        .prepare_controller_cut_once_v2()
        .map_err(|_| closed())?;
    borrower
        .begin_root_exchange_once_v2()
        .map_err(|_| closed())?;
    borrower.query_root_nonce_once_v2().map_err(|_| closed())?;
    borrower
        .receive_root_floor_once_v2()
        .map_err(|_| closed())?;
    borrower
        .prepare_controller_once_v2()
        .map_err(|_| closed())?;
    borrower.floor_seal_once_v2().map_err(|_| closed())?;
    borrower
        .commit_controller_cas_once_v2()
        .map_err(|_| closed())?;
    borrower.acknowledge_once_v2().map_err(|_| closed())?;
    borrower
        .finish_root_exchange_once_v2()
        .map_err(|_| closed())
}
