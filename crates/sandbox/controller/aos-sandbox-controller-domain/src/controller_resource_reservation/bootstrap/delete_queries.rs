//! Keeps Delete query projections on the Bank's private saved Launch.
//!
//! These named projections only lend the same intrinsic C17/Source originals
//! and existing Root client. They expose no Launch, writer, account or DATA
//! constructor and never substitute another purpose's slot.

use super::*;

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn capture_delete_planning_base_cuts_v2(
        &self,
        source: &mut crate::journal::SourceDeleteSemanticScopeV1<'_, '_>,
        authorization: &crate::public_mutation_compiler::delete_admission::DeleteAuthorizationBindingV1<'_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<crate::journal::DeletePlanningBaseCutsDataV2, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.capture_planning_base_cuts_v2(controller, launch, profile.lower_original_v1(), authorization)
            .map_err(Into::into)
    }

    pub(crate) fn delete_local_runtime_funding_data_v3(
        &self,
        source: &crate::journal::SourceDeleteSemanticScopeV1<'_, '_>,
        controller: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.local_runtime_funding_data_v3(controller, launch, profile.lower_original_v1())
            .map_err(Into::into)
    }

    pub(crate) fn reserve_delete_query_construction_v1(
        &self,
        source: &mut crate::journal::SourceDeleteSemanticScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        bytes: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.reserve_query_construction_v1(
            controller, launch, profile.lower_original_v1(), bytes,
        ).map_err(Into::into)
    }

    /// Lends the same Source semantic fields beside the exact authorized C17 loan.
    ///
    /// This keeps the retained Launch private on its actual Bank. It creates
    /// no second Journal, raw writer projection or capacity from caller DATA.
    pub(crate) fn borrow_delete_semantic_scope_v1<'scope, 'original>(
        &self,
        source: &'scope mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        loan: &'scope mut crate::controller_resource_reservation::operation_intake::ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<crate::journal::SourceDeleteSemanticScopeV1<'scope, 'original>, ResourceReservationErrorV1> {
        self.require_operation_intake_current_v1(loan, controller, profile)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.journal().borrow_delete_semantic_scope_v1(
            loan, controller, launch, profile.lower_original_v1(),
        ).map_err(Into::into)
    }

    /// Lends only the saved Launch to the actual authorized planning borrower.
    ///
    /// `upper_construction_bytes` is the actual reached Runtime frame layout.
    /// It only adds debt on this already genuine C17 loan and cannot declare a
    /// capacity, select a purpose or manufacture an authorization.
    ///
    /// # Errors
    /// Refuses same-C17/Source/currentness or construction/native admission
    /// before any Session move, extra Runtime construction or query IO.
    #[doc(hidden)]
    pub fn borrow_delete_planning_inventory_once_v1<'turn, 'scope, 'original, 'profile>(
        &'turn self,
        authorized: &'turn mut crate::public_mutation_compiler::delete_admission::ControllerDeleteSourceAuthorizedScopeV1<'scope, 'original>,
        controller: &'turn mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
        shape: crate::DeleteInventorySecurityShapeDataV1,
        upper_construction_bytes: usize,
    ) -> Result<crate::DeleteInventorySessionAppendOriginalV1<'turn, 'turn, 'scope, 'original, 'scope, 'profile>, ResourceReservationErrorV1> {
        authorized.reserve_query_construction_v1(controller, self, profile, upper_construction_bytes)?;
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        authorized.borrow_planning_inventory_once_v1(
            controller, launch, profile.lower_original_v1(), transcript, shape,
        ).map_err(Into::into)
    }

    /// Borrows a fresh Inventory turn from the actual ACK-gated Pending owner.
    ///
    /// The returned original owns the short intrinsic Source fence. It cannot
    /// outlive the same Pending borrow, substitute another payer, choose a
    /// nonce or renew the original horizon. The real Session stays resident
    /// until the complete fixed native/upper construction fee succeeds.
    ///
    /// # Errors
    /// Refuses an unavailable Pending/C17/Root association, native currentness,
    /// checked construction geometry or the same original's declared bound.
    #[doc(hidden)]
    pub fn borrow_delete_pending_inventory_once_v2<'turn, 'scope, 'original, 'profile>(
        &'turn self,
        pending: &'turn mut crate::ControllerDeletePendingOriginalV2<'scope, 'original>,
        controller: &'turn mut Journal,
        profile: &'profile crate::normal_root::ProductionControllerNormalRootProfileV1,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
        shape: crate::DeleteInventorySecurityShapeDataV1,
        challenge: &'turn ControllerDeletePendingRootChallengeLoanV2<'turn>,
        upper_construction_bytes: usize,
    ) -> Result<crate::DeleteInventorySessionAppendOriginalV1<
        'turn, 'turn, 'scope, 'original, 'scope, 'profile,
    >, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut fence = pending.borrow_fence_v2()?;
        fence.require_live_inventory_challenge_v1(controller, launch,
            profile.lower_original_v1(), challenge.actual_challenge_v2())?;
        let bytes = u64::try_from(upper_construction_bytes)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        fence.reserve_preaccept_additional_v1(controller, launch, profile.lower_original_v1(),
            aos_sandbox_model::ResourceVector::ZERO.with(
                aos_sandbox_model::ResourceDimension::MemoryBytes, bytes,
            ))?;
        fence.into_inventory_append_once_v2(controller, launch,
            profile.lower_original_v1(), transcript, shape, challenge.actual_challenge_v2())
            .map_err(Into::into)
    }

}

impl ControllerResourceBankOpeningV1 {
    /// Prepays the concrete whole-Six collection frame on its existing C17 cut.
    ///
    /// The amount only adds representation debt to the actual continuously
    /// borrowed authorized Source/C17 owner. It cannot declare a capacity or
    /// manufacture a query, role, nonce, profile or positive comparison.
    ///
    /// # Errors
    /// Refuses overflow, changed actual originals or exhausted declared capacity
    /// before any frame construction or further query materialization.
    #[doc(hidden)]
    pub fn reserve_delete_planning_collection_v2(
        &self,
        authorized: &mut crate::ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        bytes: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        authorized.reserve_query_construction_v1(controller, self, profile, bytes)
    }
}


impl ControllerResourceBankOpeningV1 {
    /// Adds the actual fresh collection's representation debt on the same C17.
    ///
    /// The original Pending fence and completed Root ACK are rejoined before
    /// admission. Bytes only increase debt; they cannot declare capacity,
    /// construct a Source owner or choose a nonce, method or purpose.
    ///
    /// # Errors
    /// Refuses changed originals, an expired challenge, arithmetic overflow or
    /// the existing original's immutable resource bound.
    #[doc(hidden)]
    pub fn reserve_delete_pending_collection_v2(
        &self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>,
        controller: &mut Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        challenge: &ControllerDeletePendingRootChallengeLoanV2<'_>,
        bytes: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let mut fence = pending.borrow_fence_v2()?;
        fence.require_live_inventory_challenge_v1(controller, launch,
            profile.lower_original_v1(), challenge.actual_challenge_v2())?;
        let bytes = u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        fence.reserve_preaccept_additional_v1(controller, launch, profile.lower_original_v1(),
            aos_sandbox_model::ResourceVector::ZERO.with(
                aos_sandbox_model::ResourceDimension::MemoryBytes, bytes,
            )).map_err(Into::into)
    }
}


impl ControllerResourceBankOpeningV1 {
    /// Rejoins the exact pending C17 claim for the retained local Runtime.
    ///
    /// This restrictive comparison uses the genuine Pending fence and actual
    /// ACK-gated Root challenge. The expected claim supplies no capacity, owner,
    /// nonce or accepted effect; every byte must match the real held original.
    ///
    /// # Errors
    /// Refuses expired/foreign Root or Pending custody, changed Launch/profile/C
    /// association, or any claim difference.
    #[doc(hidden)]
    pub fn require_delete_pending_local_funding_v3(&self,
        pending: &mut crate::ControllerDeletePendingOriginalV2<'_, '_>, controller: &Journal,
        profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
        challenge: &ControllerDeletePendingRootChallengeLoanV2<'_>,
        expected: &aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let fence = pending.borrow_fence_v2()?;
        fence.require_live_inventory_challenge_v1(controller, launch,
            profile.lower_original_v1(), challenge.actual_challenge_v2())?;
        let (actual, _, _) = fence.controller_funding_cut_data_v3(controller, launch, profile.lower_original_v1())?;
        if &actual != expected { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(())
    }
}
