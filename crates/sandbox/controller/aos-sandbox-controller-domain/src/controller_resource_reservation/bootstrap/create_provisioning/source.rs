//! Rejoins actual C23 and Source originals for their staged native crossing.

use super::*;
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn begin_provisioning_source_native_v1(&self,
        original: &mut ControllerCreateProvisioningReceivingV1, controller: &Journal,
        source: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<SourceProvisioningCurrentnessOriginalV1, ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.begin_source_provisioning_native_v1(original,
            controller.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1(), complete)
    }

    pub(crate) fn require_provisioning_source_readonly_current_v1(&self,
        source_original: &mut SourceProvisioningCurrentnessOriginalV1,
        original: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        source: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.require_source_provisioning_readonly_current_v1(source_original, original,
            controller.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1())
    }

    pub(crate) fn bind_provisioning_source_native_v1(&self,
        source_original: &mut SourceProvisioningCurrentnessOriginalV1,
        original: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        source: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
        transaction: &crate::JournalTransaction,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.bind_source_provisioning_native_v1(source_original, original,
            controller.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1(), transaction)
    }

    pub(crate) fn dispose_provisioning_source_native_v1(&self,
        source_original: &mut SourceProvisioningCurrentnessOriginalV1,
        original: &ControllerCreateProvisioningReceivingV1, controller: &Journal,
        source: &mut Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        source.dispose_source_provisioning_native_v1(source_original, original,
            controller.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1())
    }
}
