//! Borrows the same completed initial native anchors without extracting them.
//!
//! Construction joins the actual once-role receiver, endpoint aggregate and
//! final-taken protected Journal after the independent C/profile post. This is
//! mechanical residency, never semantic authentication or an effect permit.

use super::*;

/// Continuously borrows the same completed initial receiver and native owners.
///
/// Fields are private. This value cannot be constructed from a role, identity
/// Arc, count, transcript, success flag or replacement Journal.
#[doc(hidden)]
pub struct ControllerInitialSessionCompletedNativeBorrowV1<'held> {
    pub(super) owner: &'held ControllerInitialBrokerSessionReceivingV1,
    main: crate::journal::JournalProtectedNativeResidencyV1<'held>,
    endpoint: &'held Arc<aos_sandbox_broker::endpoint_native_files::ControllerEndpointNativeCustodyV1>,
}

impl ControllerInitialBrokerSessionReceivingV1 {
    /// Borrows actual completed main and endpoint custody under this same C.
    ///
    /// # Errors
    /// Refuses an unfinished/failed original, replaced owner or live probe.
    #[doc(hidden)]
    pub fn borrow_completed_native_v1<'held>(
        &'held self,
        main: &'held crate::Journal,
        endpoint: &'held Arc<aos_sandbox_broker::endpoint_native_files::ControllerEndpointNativeCustodyV1>,
    ) -> Result<ControllerInitialSessionCompletedNativeBorrowV1<'held>, ControllerInitialBrokerSessionClosedV1> {
        if self.first.is_some() || !self.take_entered
            || !matches!(self.after, Some(Ok(_)))
            || !matches!(self.after_binding, Some(Ok(())))
            || !self.opening.as_ref().is_some_and(|opening| opening.matches_journal_v1(main))
        {
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.receiving.as_ref().ok_or(ControllerInitialBrokerSessionClosedV1)?
            .require_completed_endpoint_native_v1(endpoint)
            .map_err(|_| ControllerInitialBrokerSessionClosedV1)?;
        let main = main.borrow_protected_native_residency_v1()
            .ok_or(ControllerInitialBrokerSessionClosedV1)?;
        Ok(ControllerInitialSessionCompletedNativeBorrowV1 { owner: self, main, endpoint })
    }
}

impl ControllerInitialSessionCompletedNativeBorrowV1<'_> {
    /// Rejoins this actual completed receiver to its recovered four-role owner.
    ///
    /// Construction already retains this same endpoint and main Journal. This
    /// additional comparison requires every new role's completed native after
    /// without reusing an old initial claim or a read-only inventory receiver.
    ///
    /// # Errors
    /// Refuses foreign C/Bank/profile/context or an unfinished four-role set.
    #[doc(hidden)]
    pub fn require_completed_recovered_ordinary_context_v2(
        &self,
        context: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2,
        bank: &crate::ControllerResourceBankOpeningV1,
        controller: &crate::Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let receiving = self.owner.receiving.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        bank.require_completed_recovered_ordinary_session_v2(
            context, receiving, controller, profile, self.owner.role,
        )
    }

    /// Rejoins this exact completed native Session to its new paid maintenance.
    ///
    /// Main and endpoint custody come from this actual opaque borrower. The
    /// lower purpose additionally rejects another generation, readonly Recover
    /// receiver, foreign role, unfinished native pair or replaced profile.
    /// This comparison grants no effect or operation authority.
    ///
    /// # Errors
    /// Refuses a foreign main Journal, role, C/Bank/profile or receiver origin.
    #[doc(hidden)]
    pub fn require_catalog_maintenance_current_v2(
        &self,
        maintenance: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceReceivingV2,
        bank: &crate::ControllerResourceBankOpeningV1,
        controller: &crate::Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        role: ControllerInitialBrokerSessionRoleV1,
        main: &crate::Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.owner.role != role || !self.matches_main_v1(main) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let receiving = self.owner.receiving.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        bank.require_completed_catalog_maintenance_session_v2(
            maintenance, receiving, controller, profile, role,
        )
    }

    /// Returns the same original's fixed role as comparison DATA.
    #[must_use]
    pub fn role_v1(&self) -> ControllerInitialBrokerSessionRoleV1 { self.owner.role }

    /// Counts the continuously borrowed endpoint6 and actual main3 anchors.
    ///
    /// Transport, floor/sidecar/helper and future observations are separate.
    #[must_use]
    pub fn retained_open_files_v1(&self) -> Option<usize> {
        self.endpoint.retained_open_file_count_v1()?.checked_add(self.main.open_files_v1())
    }

    pub(super) fn matches_main_v1(&self, actual: &crate::Journal) -> bool {
        self.main.matches_v1(actual)
    }
}


impl ControllerInitialBrokerSessionReceivingV1 {
    pub(crate) fn require_completed_catalog_maintenance_journal_v2(
        &self,
        maintenance: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerCatalogMaintenanceReceivingV2,
        bank: &crate::ControllerResourceBankOpeningV1,
        controller: &crate::Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        main: &crate::Journal,
        role: ControllerInitialBrokerSessionRoleV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.role != role || self.failure().is_some() || !self.take_entered
            || !matches!(self.after, Some(Ok(_)))
            || !matches!(self.after_binding, Some(Ok(())))
            || !self.opening.as_ref().is_some_and(|opening| opening.matches_journal_v1(main))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        bank.require_completed_catalog_maintenance_session_v2(
            maintenance, self.receiving.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?,
            controller, profile, role,
        )
    }
}
