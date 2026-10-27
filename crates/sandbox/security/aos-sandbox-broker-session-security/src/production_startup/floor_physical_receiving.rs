//! Joins the actual Required launch profile to its persistent Controller owner.
//!
//! This comparison accepts only the same opaque admitted startup profile. It
//! creates no image, role, task slot, account or authority from caller DATA.

use aos_sandbox_controller_domain::ControllerStorageFloorPhysicalReceivingV1;

use super::{ControllerProfileDeliveryV1, Pid1LaunchImageV1};
use crate::{BrokerSessionSecurityError, ProtectedBrokerSessionFixedEndpointV1};

impl Pid1LaunchImageV1 {
    pub(crate) fn require_controller_physical_receiving_v1(
        &self,
        receiving: &mut ControllerStorageFloorPhysicalReceivingV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient)?;
        let ControllerProfileDeliveryV1::Admitted(binding) = &self.profile_delivery else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let profile = binding.profile().ok_or(BrokerSessionSecurityError::Currentness)?;
        receiving.require_controller_profile_v1(profile)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }
}

impl Pid1LaunchImageV1 {
    // The image already retains the actual Bank-admitted profile. This closed
    // selected projection shares that owner; it accepts no caller profile.
    pub(crate) fn controller_floor_profile_v1(
        &self,
    ) -> Result<Option<aos_sandbox_controller_domain::normal_root::ControllerSharedStartupProfileV1>, BrokerSessionSecurityError> {
        self.require_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient)?;
        let ControllerProfileDeliveryV1::Admitted(binding) = &self.profile_delivery else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        Ok(binding.floor_service_anchors_v1().map(|_| binding.clone()))
    }
}
