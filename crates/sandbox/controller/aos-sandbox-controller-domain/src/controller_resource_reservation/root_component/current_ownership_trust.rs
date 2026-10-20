//! Admits fixed then actually observed typed Ownership trust under the same R.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    ownership_trust::RootCurrentOwnershipTrustStateV1,
    policy_inputs::RootCurrentPolicyInputsStateV1, root_open::RootCurrentOpenStateV1,
};
use super::RootReceivingOriginalV1;
use super::current_provision::{RootCurrentProvisionV1, RootCurrentStageV1};
use super::super::ResourceReservationErrorV1;

#[derive(Default)]
pub(super) struct RootCurrentOwnershipTrustProvisionV1 {
    pub(super) fixed: RootCurrentProvisionV1,
    pub(super) typed: RootCurrentProvisionV1,
}

impl RootCurrentOwnershipTrustProvisionV1 {
    pub(super) fn completed_prefix(&self) -> Option<aos_sandbox_model::ResourceVector> {
        self.fixed.completed_prefix()?;
        self.typed.completed_prefix()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed.failure().or_else(|| self.typed.failure())
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_ownership_trust_fixed_once(
        &mut self, startup: &ProductionNormalRootStartupV1,
        root_open: &RootCurrentOpenStateV1, policy_inputs: &RootCurrentPolicyInputsStateV1,
    ) -> Result<(), Error> {
        if self.current_ownership_trust_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_ownership_trust_provision = Some(RootCurrentOwnershipTrustProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            policy_inputs.require_complete().map_err(|_| invalid())?;
            if root_open.completed_receiver().map_err(|_| invalid())?
                != self.current_root_open_original_pair().map_err(|_| invalid())? {
                return Err(invalid().into());
            }
            let base = self.current_policy_inputs_provision.as_ref()
                .and_then(|stage| stage.completed_prefix()).ok_or_else(invalid)?;
            let additional = RootCurrentOwnershipTrustStateV1::fixed_demand_v1()?;
            let demand = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(demand).map_err(|_| invalid())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_ownership_trust_provision.as_mut().ok_or(Error::Service)?.fixed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::OwnershipTrustFixed)
    }

    pub(crate) fn require_current_ownership_trust_fixed_v1(
        &self, root_open: &RootCurrentOpenStateV1,
    ) -> Result<(), Error> {
        if self.failure().is_some()
            || root_open.completed_receiver().map_err(|_| Error::Service)?
                != self.current_root_open_original_pair().map_err(|_| Error::Service)?
            || self.current_ownership_trust_provision.as_ref()
                .and_then(|stage| stage.fixed.completed_prefix()).is_none()
        { return Err(Error::Service); }
        Ok(())
    }

    pub(crate) fn prepay_current_ownership_trust_typed_once(
        &mut self, startup: &ProductionNormalRootStartupV1,
        root_open: &RootCurrentOpenStateV1, trust: &RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), Error> {
        self.require_current_ownership_trust_fixed_v1(root_open)?;
        if self.current_ownership_trust_provision.as_ref()
            .is_none_or(|stage| stage.typed.permit.is_some())
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_ownership_trust_provision.as_ref()
                .and_then(|stage| stage.fixed.completed_prefix()).ok_or_else(invalid)?;
            let additional = trust.typed_demand_v1()?;
            let demand = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(demand).map_err(|_| invalid())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_ownership_trust_provision.as_mut().ok_or(Error::Service)?.typed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::OwnershipTrustTyped)
    }
}
