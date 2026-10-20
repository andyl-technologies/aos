//! Lends NoApply IO to the same concrete execution client forwarding engine.

use super::*;
use aos_sandbox::controller_execution_operation::ControllerExecutionNoApplyClientLoanV2;

super::execution_availability::execution_client_native_member_v2!(
    ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    execution_no_apply_client_journal_v2,
    execution_no_apply_client_stored_v2
);
