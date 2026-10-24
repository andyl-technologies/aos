//! Admits Root4's fixed owner and actual signed extent under the SAME R.

use aos_sandbox_model::ResourceVector;
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{root_open::RootCurrentOpenStateV1,
    use_admitted::RootCurrentUseAdmittedStateV1, use_reserved::RootCurrentUseReservedStateV1,
    signed_bound::{RootCurrentSignedBoundStateV1, input::RootSignedInputV1}};
use super::{RootReceivingOriginalV1, current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::ResourceReservationErrorV1;

mod controller_read;

#[derive(Default)]
pub(super) struct RootSignedProvisionV1 {
    pub(super) fixed: RootCurrentProvisionV1,
    pub(super) variable: RootCurrentProvisionV1,
    pub(super) read: super::current_controller_readonly::RootCurrentControllerReadonlyProvisionV1,
}

impl RootSignedProvisionV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed.failure().or_else(|| self.variable.failure()).or_else(|| self.read.failure())
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn current_signed_failure_v1(&self, bytes: bool)
        -> Option<&(dyn std::error::Error + 'static)> {
        let stages = self.current_signed_provision.as_ref()?;
        let stage = if bytes { &stages.variable } else { &stages.fixed };
        // A rejected permit precedes the service observation and every later
        // owed post. Resolve precisely this original source while its guard is held.
        stage.permit.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.activation.currentness_failure_v1()).or_else(|| stage.failure())
    }

    fn require_signed_original(&self, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1) -> Result<(), Error>
    {
        admitted.require_complete_v1().map_err(|_| Error::Service)?;
        if root.completed_receiver().map_err(|_| Error::Service)? != self.current_root_open_original_pair().map_err(|_| Error::Service)? {
            return Err(Error::Service);
        }
        Ok(())
    }

    pub(crate) fn prepay_current_signed_fixed_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1) -> Result<(), Error>
    {
        if self.current_signed_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_signed_provision = Some(RootSignedProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            self.require_signed_original(root, admitted).map_err(|_| invalid())?;
            let base = self.current_use_admitted_provision.as_ref()
                .and_then(|stage| stage.completed_prefix()).ok_or_else(invalid)?;
            let held = self.current_writers_receiving.as_ref()
                .and_then(|stage| stage.authority_extent()).ok_or_else(invalid)?;
            let demand = RootCurrentSignedBoundStateV1::fixed_receiving_demand_v1(held, admitted)?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_signed_provision.as_mut().ok_or(Error::Service)?.fixed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::SignedFixed)
    }

    pub(crate) fn prepay_current_signed_bytes_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, reserved: &RootCurrentUseReservedStateV1,
        input: &RootSignedInputV1) -> Result<(), Error>
    {
        if self.current_signed_provision.as_ref().is_none_or(|stage| stage.variable.permit.is_some())
            || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            self.require_signed_original(root, admitted).map_err(|_| invalid())?;
            let base = self.current_signed_provision.as_ref()
                .and_then(|stage| stage.fixed.completed_prefix()).ok_or_else(invalid)?;
            let demand = input.additional_received_demand_v1(reserved)?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_signed_provision.as_mut().ok_or(Error::Service)?.variable.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::SignedBytes)
    }

    pub(crate) fn completed_signed_bound_prefix_v1(&self, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, signed: &RootCurrentSignedBoundStateV1,
    ) -> Result<ResourceVector, Error> {
        self.require_signed_original(root, admitted)?;
        signed.require_complete_v1().map_err(|_| Error::Service)?;
        self.current_signed_provision.as_ref().and_then(|stage| stage.read.semantic.completed_prefix())
            .ok_or(Error::Service)
    }
}
