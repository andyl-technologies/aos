//! Reborrows the same C and Source originals for the prepaid final destination.
//!
//! These private bridges are mechanical. The upper retained completion attempt
//! alone checks its real ACK, ordinal, clocks and exact semantic transaction.

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningCompletionDestinationV1;
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn prearm_provisioning_completion_native_v1(&self,
        original: &mut ControllerCreateProvisioningReceivingV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1, complete: ResourceVector,
    ) -> Result<ControllerCreateProvisioningCompletionDestinationV1, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(original.prearm_completion_destination_once_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile.lower_original_v1(), complete))
    }

    pub(crate) fn enter_provisioning_completion_native_v1(&self,
        destination: &mut ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1, controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        destination.enter_after_completed_original_once_v1(completed,
            controller.controller_coordinator_for_bank_v1()?, launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn require_provisioning_completion_native_v1(&self,
        destination: &ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        destination.require_current_v1(completed, controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn finish_provisioning_completion_native_v1(&self,
        destination: &mut ControllerCreateProvisioningCompletionDestinationV1,
        controller: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        destination.finish_native_once(controller.controller_coordinator_for_bank_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn require_completed_provisioning_completion_native_v1(&self,
        destination: &ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        destination.require_completed_original_v1(completed,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1()).map_err(Into::into)
    }
}


impl ControllerResourceBankOpeningV1 {
    pub(crate) fn prearm_provisioning_source_completion_v1(&self,
        original: &mut ControllerCreateProvisioningReceivingV1, controller: &Journal,
        source: &mut Journal, profile: &ProductionControllerNormalRootProfileV1, complete: ResourceVector,
    ) -> Result<SourceProvisioningCurrentnessOriginalV1, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.prearm_source_completion_native_v1(original, controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1(), complete)
    }

    pub(crate) fn enter_provisioning_source_completion_v1(&self,
        source_original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        source: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.enter_source_completion_native_v1(source_original, destination, completed,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1())
    }

    pub(crate) fn bind_provisioning_source_completion_v1(&self,
        source_original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        source: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        transaction: &crate::JournalTransaction,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.bind_source_completion_native_v1(source_original, destination, completed,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1(), transaction)
    }

    pub(crate) fn dispose_provisioning_source_completion_v1(&self,
        source_original: &mut SourceProvisioningCurrentnessOriginalV1,
        destination: &ControllerCreateProvisioningCompletionDestinationV1,
        completed: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        source: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.dispose_source_completion_native_v1(source_original, destination, completed,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile.lower_original_v1())
    }
}
