//! Forwards the same genuine J to its closed lower financial provider.
//!
//! Upper Source/profile/parent/admission and native-post gates stay on the
//! actual intake. This module owns no second ledger, caller grant or native
//! original and cannot lend before the completed upper J append/readback.

use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerCreateContinuationFundingLoanV1 as Loan,
    ControllerCreateContinuationLedgerOriginalV1 as Original,
};

use super::{
    CreateContinuationCaptureOwnerV1 as Owner, ProductionControllerNormalRootProfileV1,
    Q04OriginalIntakeAttemptV1, ResourceReservationErrorV1, ResourceVector,
};

impl Q04OriginalIntakeAttemptV1 {
    /// Borrows the lower financial original retained by this same J attempt.
    ///
    /// # Errors
    /// Refuses absent or failed lower construction; returns no fallback owner.
    pub(super) fn continuation_original_v1(&self) -> Result<&Original, ResourceReservationErrorV1> {
        self.continuation
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Exclusively borrows the same retained lower financial original.
    ///
    /// # Errors
    /// Refuses absent or failed lower construction; creates no second ledger.
    pub(super) fn continuation_original_mut_v1(
        &mut self,
    ) -> Result<&mut Original, ResourceReservationErrorV1> {
        self.continuation
            .as_mut()
            .and_then(|value| value.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the actual lower construction, native or accounting cause.
    pub(super) fn continuation_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.continuation.as_ref()? {
            Ok(original) => original.failure_v1(),
            Err(cause) => Some(cause),
        }
    }

    /// Routes one existing closed capture owner to its same lower J highwater.
    ///
    /// # Errors
    /// Refuses missing original, native commitment or sticky receiving debt.
    pub(super) fn reserve_continuation_complete_v1(
        &mut self,
        owner: Owner,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let actual = self.continuation_original_mut_v1()?;
        let result = match owner {
            Owner::ControllerIntent => actual.reserve_controller_intent_complete_v1(complete),
            Owner::SourceHeld => actual.reserve_source_held_complete_v1(complete),
            Owner::CacheHeld => actual.reserve_cache_held_complete_v1(complete),
            Owner::Ownership => actual.reserve_ownership_complete_v1(complete),
            Owner::StorageInventory => actual.reserve_storage_inventory_complete_v1(complete),
            Owner::RootExchange => actual.reserve_root_exchange_complete_v1(complete),
            Owner::Observers => actual.reserve_observers_complete_v1(complete),
            Owner::HistoryNames => actual.reserve_history_names_complete_v1(complete),
            Owner::AssignmentPlanned => actual.reserve_assignment_planned_complete_v1(complete),
            Owner::StorageClientSession => {
                actual.reserve_storage_client_session_complete_v1(complete)
            }
            Owner::ReadyBundle => actual.reserve_ready_bundle_complete_v1(complete),
        };
        result.map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Lends only this same completed J's actual lower Cache financial port.
    ///
    /// # Errors
    /// Refuses incomplete upper append/posts, sticky debt or foreign profile.
    pub(in crate::controller_resource_reservation) fn borrow_cache_continuation_funding_v1<
        'funding,
        'profile,
    >(
        &'funding mut self,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Result<Loan<'funding, 'profile>, ResourceReservationErrorV1> {
        self.require_retained_capture()?;
        self.require_original(profile)?;
        self.continuation_original_mut_v1()?
            .borrow_cache_funding_v1(profile.lower_original_v1())
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}
