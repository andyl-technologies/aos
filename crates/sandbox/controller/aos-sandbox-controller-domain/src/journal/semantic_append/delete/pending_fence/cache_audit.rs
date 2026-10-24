//! Preserves the actual pending Source frontier before lending Cache funding.

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerCacheAuditIdentityDataV1, ControllerCacheDeleteAuditFundingLoanV1,
    ControllerDeletePreacceptTurnOriginalV1, ControllerOperationIntakeDemandDataV1,
};

impl SourceDeletePendingFenceV1<'_, '_, '_, '_> {
    pub(crate) fn borrow_preaccept_cache_audit_funding_v1<'funding, 'profile>(
        &'funding mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        turn: &'funding mut ControllerDeletePreacceptTurnOriginalV1<'profile>,
        identity: ControllerCacheAuditIdentityDataV1,
        additional: ResourceVector,
        complete: ResourceVector,
        semantic: ResourceVector,
    ) -> Result<ControllerCacheDeleteAuditFundingLoanV1<'funding, 'profile>, JournalError> {
        self.native_position_data_v1()?;
        self.scope.native.borrow_delete_cache_audit_funding_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            turn, identity, ControllerOperationIntakeDemandDataV1::from_demand_v1(additional),
            complete, semantic,
        ).map_err(JournalError::ControllerNative)
    }
}
