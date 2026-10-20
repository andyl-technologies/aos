//! Forwards only genuine active Start native owners to fixed endpoint custody.

use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerCreateProvisioningReceivingV1, ControllerStartResourceEndpointOriginalV2,
};
use aos_sandbox_broker::endpoint_native_files::{ControllerEndpointExecutionOriginalV1,
    ControllerEndpointExecutionCaptureErrorV1, ControllerEndpointNativeCustodyCaptureV1,
    EndpointNativeFileOpenOriginalV1, EndpointNativeFileV1};
use aos_sandbox_core::ResourceVector;

use super::*;

impl ControllerResourceBankOpeningV1 {
    pub(crate) fn prepare_start_resource_endpoint_disposition_v2(&self,
        endpoint: &mut ControllerStartResourceEndpointOriginalV2,
        native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        endpoint.prepare_positive_disposition_v2(native,
            controller.controller_coordinator_for_bank_read_v1()?, launch,
            profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn start_resource_endpoint_expected_node_v2(&self,
        endpoint: &mut ControllerStartResourceEndpointOriginalV2,
        native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<[u8; 16], ResourceReservationErrorV1> {
        self.require_start_resource_endpoint_current_v2(endpoint, native, controller, profile)?;
        let observed = self.observed.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(observed.identity.native_fields().node)
    }

    pub(crate) fn prepare_start_resource_endpoint_once_v2(&self,
        endpoint: &mut ControllerStartResourceEndpointOriginalV2,
        native: &mut ControllerCreateProvisioningReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
        complete: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        endpoint.prepare_once_v2(native, controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1(), complete).map_err(Into::into)
    }

    pub(crate) fn require_start_resource_endpoint_current_v2(&self,
        endpoint: &mut ControllerStartResourceEndpointOriginalV2,
        native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        endpoint.require_current_v2(native, controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1()).map_err(Into::into)
    }

    pub(crate) fn capture_start_resource_execution_once_v2(&self,
        endpoint: &mut ControllerStartResourceEndpointOriginalV2,
        native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ControllerEndpointExecutionOriginalV1, ControllerEndpointExecutionCaptureErrorV1> {
        use ControllerEndpointExecutionCaptureErrorV1 as Error;
        let launch = self.launch.as_ref().ok_or(Error::Unavailable)?;
        let writer = controller.controller_coordinator_for_bank_read_v1().map_err(|_| Error::Unavailable)?;
        endpoint.capture_execution_once_v2(native, writer, launch, profile.lower_original_v1())
    }

    pub(crate) fn capture_start_resource_directory_once_v2(&self,
        endpoint: &mut ControllerStartResourceEndpointOriginalV2,
        native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
        destination: &mut EndpointNativeFileOpenOriginalV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        endpoint.capture_directory_once_v2(native, controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1(), destination).map_err(Into::into)
    }

    pub(crate) fn capture_start_resource_custody_once_v2(&self,
        endpoint: &mut ControllerStartResourceEndpointOriginalV2,
        native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, profile: &ProductionControllerNormalRootProfileV1,
        destination: &mut ControllerEndpointNativeCustodyCaptureV1,
        execution: &mut Option<ControllerEndpointExecutionOriginalV1>,
        post: &mut Option<aos_sandbox_linux::self_execution::SelfExecutionObservationV1>,
        files: [&EndpointNativeFileV1; 4],
    ) -> Result<(), ResourceReservationErrorV1> {
        let launch = self.launch.as_ref().ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        endpoint.capture_custody_once_v2(native, controller.controller_coordinator_for_bank_read_v1()?,
            launch, profile.lower_original_v1(), destination, execution, post, files).map_err(Into::into)
    }
}
