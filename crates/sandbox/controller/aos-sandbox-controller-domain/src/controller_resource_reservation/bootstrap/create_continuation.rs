//! Claims the original J ledger through the actual Bank/Controller producer.
//!
//! This private bridge supplies no imported ledger, native writer or paid
//! boolean. The same bank retains its once-entered Create intake and confirmed
//! original launch while the lower native factory checks its Reserved J claim.

use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateContinuationLedgerOriginalV1;
use aos_sandbox_model::ResourceVector;

use super::super::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};
use crate::{Journal, normal_root::ProductionControllerNormalRootProfileV1};

impl ControllerResourceBankOpeningV1 {
    /// Enters the sealed lower J factory through the same successful Bank.
    ///
    /// # Errors
    /// Refuses missing actual intake, closed Bank, foreign C or lower claim.
    pub(in crate::controller_resource_reservation) fn begin_create_continuation_ledger_v1(
        &self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        fixed: ResourceVector,
        observers: ResourceVector,
    ) -> Result<ControllerCreateContinuationLedgerOriginalV1, ResourceReservationErrorV1> {
        if !self.create_intake_attempted
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
            .begin_create_continuation_once_v1(
                launch,
                profile.lower_original_v1(),
                fixed,
                observers,
            )
            .map_err(Into::into)
    }

    /// Rejoins the lower J to the same actual post-append committed C claim.
    ///
    /// # Errors
    /// Refuses missing Bank/intake custody, native readback or lower commitment.
    pub(in crate::controller_resource_reservation) fn require_create_continuation_committed_v1(
        &self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        owner: &mut ControllerCreateContinuationLedgerOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.create_intake_attempted
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
        owner
            .require_committed_once_v1(writer, launch, profile.lower_original_v1())
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerResourceBankOpeningV1 {
    /// Starts the same Reserved J observer at the actual upper native frontier.
    ///
    /// This is no new Bank entry or native observation. Existing upper CPU,
    /// clock, exact admission and mutually exclusive archive checks remain owed.
    ///
    /// # Errors
    /// Refuses foreign/current C custody, closed original or lower once/bound failure.
    pub(in crate::controller_resource_reservation) fn begin_create_continuation_observers_v1(
        &self,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        owner: &mut ControllerCreateContinuationLedgerOriginalV1,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1, ResourceReservationErrorV1> {
        if !self.create_intake_attempted || self.failure().is_some()
            || !self.native_opened() || !self.initial_first_use_owner()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let writer = controller.controller_coordinator_for_bank_v1()?;
        writer.require_same_original_v1(&self.original)?;
        owner.begin_reserved_observers_once_v1(writer, profile.lower_original_v1())
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}
