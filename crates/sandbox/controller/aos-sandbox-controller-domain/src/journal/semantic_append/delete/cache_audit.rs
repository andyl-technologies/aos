//! Lends actual Source/C17 custody across the fixed upper Cache boundary.

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerCacheAuditIdentityDataV1, ControllerCacheDeleteAuditFundingLoanV1,
    ControllerDeletePreacceptTurnOriginalV1, ControllerOperationIntakeDemandDataV1,
};

impl SourceDeleteSemanticScopeV1<'_, '_> {
    // Cache includes these upper carriers before its existing Source debit.
    pub(crate) fn cache_audit_forwarding_bytes_v1() -> Option<usize> {
        // The upper Source union and its selected semantic-scope or pending
        // fence branch each forward these exact arguments. All references
        // are thin borrows of sized originals, not copies of those originals.
        type Arguments<'a> = (
            &'a mut (), &'a mut Journal, &'a ControllerBankLaunchOriginalV1,
            &'a ControllerSelfProfileOriginalV1,
            &'a mut ControllerDeletePreacceptTurnOriginalV1<'a>,
            ControllerCacheAuditIdentityDataV1,
            ResourceVector, ResourceVector, ResourceVector,
        );
        std::mem::size_of::<Arguments<'_>>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Result<
                ControllerCacheDeleteAuditFundingLoanV1<'_, '_>, JournalError,
            >>().checked_mul(2)?)
    }

    // The controller projection stays at the original planning debit frontier.
    pub(crate) fn borrow_planning_cache_audit_funding_v1<'funding, 'profile>(
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
        self.native.borrow_delete_cache_audit_funding_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            turn, identity, ControllerOperationIntakeDemandDataV1::from_demand_v1(additional),
            complete, semantic,
        ).map_err(JournalError::ControllerNative)
    }
}
