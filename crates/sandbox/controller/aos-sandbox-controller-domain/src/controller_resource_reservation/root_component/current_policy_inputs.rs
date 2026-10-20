//! Charges the existing signed-policy decoder to the same held Root original.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    pins::RootCurrentPinsStateV1, policy_inputs::RootCurrentPolicyInputsStateV1,
    root_open::RootCurrentOpenStateV1,
};

use super::RootReceivingOriginalV1;
use super::current_provision::{RootCurrentProvisionV1, RootCurrentStageV1};
use super::super::ResourceReservationErrorV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_policy_inputs_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root_open: &RootCurrentOpenStateV1,
        pins: &RootCurrentPinsStateV1,
    ) -> Result<(), Error> {
        if self.current_policy_inputs_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_policy_inputs_provision = Some(RootCurrentProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            pins.require_complete().map_err(|_| invalid())?;
            if root_open.completed_receiver().map_err(|_| invalid())?
                != self.current_root_open_original_pair().map_err(|_| invalid())?
            {
                return Err(invalid().into());
            }
            let base = self.current_pins_provision.as_ref()
                .and_then(|stage| stage.completed_prefix()).ok_or_else(invalid)?;
            let additional = RootCurrentPolicyInputsStateV1::dominant_demand()?;
            let demand = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(demand).map_err(|_| invalid())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_policy_inputs_provision.as_mut().ok_or(Error::Service)?.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::PolicyInputs)
    }
}
