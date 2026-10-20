//! Enters native P/I/Q observer origins through the same actual Bank and C.
//!
//! This bridge carries no imported lifetime or capacity. The actual native
//! factory checks the protected Reserved claim; upper CPU, clock, semantic
//! admission, archive exclusivity, append/readback and posts remain owed.

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1;
use aos_sandbox_model::ResourceVector;

use super::super::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};
use crate::{Journal, normal_root::ProductionControllerNormalRootProfileV1};

impl ControllerResourceBankOpeningV1 {
    /// Starts this same initial Bank's Reserved Q observer origin.
    ///
    /// # Errors
    /// Rejects an unentered Q, failed Bank, foreign C/profile or native claim.
    pub(in crate::controller_resource_reservation) fn begin_q04_observers_v1(
        &self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        fixed: ResourceVector,
    ) -> Result<ControllerReservedObserverOriginalV1, ResourceReservationErrorV1> {
        if !self.q04_intake_attempted
            || self.failure().is_some()
            || !self.native_opened()
            || !self.initial_first_use_owner()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = controller.controller_coordinator_for_bank_v1()?;
        writer.require_same_original_v1(&self.original)?;
        writer
            .begin_q04_reserved_observers_once_v1(launch, profile.lower_original_v1(), fixed)
            .map_err(Into::into)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Starts the same native Bank's FirstGlobal observer origin.
    ///
    /// # Errors
    /// Rejects failed/noninitial Bank, foreign C/profile or changed Reserved P.
    pub(in crate::controller_resource_reservation) fn begin_first_global_observers_v1(
        &self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        fixed: ResourceVector,
    ) -> Result<ControllerReservedObserverOriginalV1, ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.native_opened() || !self.initial_first_use_owner() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = controller.controller_coordinator_for_bank_v1()?;
        writer.require_same_original_v1(&self.original)?;
        writer
            .begin_first_global_reserved_observers_once_v1(
                launch,
                profile.lower_original_v1(),
                fixed,
            )
            .map_err(Into::into)
    }

    /// Starts the same native Bank's original Nix intake observer origin.
    ///
    /// # Errors
    /// Rejects an unentered I, failed/noninitial Bank, foreign C or changed claim.
    pub(in crate::controller_resource_reservation) fn begin_nix_observers_v1(
        &self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        fixed: ResourceVector,
    ) -> Result<ControllerReservedObserverOriginalV1, ResourceReservationErrorV1> {
        if !self.nix_intake_attempted
            || self.failure().is_some()
            || !self.native_opened()
            || !self.initial_first_use_owner()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let launch = self
            .launch
            .as_ref()
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let writer = controller.controller_coordinator_for_bank_v1()?;
        writer.require_same_original_v1(&self.original)?;
        writer
            .begin_nix_reserved_observers_once_v1(launch, profile.lower_original_v1(), fixed)
            .map_err(Into::into)
    }
}
