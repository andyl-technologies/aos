//! Forwards fixed Cache audit funding through the actual held Source scope.

use super::*;
use crate::controller_receiving::bank_launch::{
    ControllerCacheAuditIdentityDataV1, ControllerCacheDeleteAuditFundingLoanV1,
    ControllerDeletePreacceptTurnOriginalV1, ControllerOperationIntakeDemandDataV1,
};

impl<P> SourceOperationScopeV1<'_, '_, P, DeleteSourcePurposeV1> {
    /// Lends the same Source-associated C17 debit to its entered Cache reader.
    ///
    /// This method retains the actual Source scope and native turn borrow. It
    /// creates no writer, account, capacity, authorization or completion proof.
    ///
    /// # Errors
    /// Preserves failed Source currentness or the actual C17 debit refusal
    /// before rejecting a changed turn, association or requested bound.
    pub fn borrow_delete_cache_audit_funding_v1<'funding, 'profile, C>(
        &'funding mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        turn: &'funding mut ControllerDeletePreacceptTurnOriginalV1<'profile>,
        identity: ControllerCacheAuditIdentityDataV1,
        additional: ControllerOperationIntakeDemandDataV1,
        complete: ResourceVector,
        semantic: ResourceVector,
    ) -> Result<ControllerCacheDeleteAuditFundingLoanV1<'funding, 'profile>, ControllerBankLaunchErrorV1> {
        self.historical_view_v1()?;
        if self.failure().is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.receiving.borrow_delete_cache_audit_funding_v1(
            controller, launch, profile, turn, identity, additional, complete, semantic,
        )
    }
}
