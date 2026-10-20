//! Charges fixed strict receipt and actual declared Ready byte DATA to RootR.

use aos_sandbox_core::ResourceVector;

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::OriginalRootCreateStorageCurrentAttemptV1;
use crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1;

use super::RootReceivingOriginalV1;
use super::current_provision::{RootCurrentProvisionV1, RootCurrentStageV1};
use super::super::ResourceReservationErrorV1;

#[derive(Default)]
pub(super) struct RootCurrentReadyProvisionV1 {
    pub(super) fixed: RootCurrentProvisionV1,
    pub(super) variable: RootCurrentProvisionV1,
}

impl RootCurrentReadyProvisionV1 {
    pub(super) fn completed_prefix(&self) -> Option<ResourceVector> {
        self.fixed.completed_prefix()?;
        self.variable.completed_prefix()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed.failure().or_else(|| self.variable.failure())
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_ready_fixed_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root_open: &RootCurrentOpenStateV1,
    ) -> Result<(), Error> {
        if self.current_ready_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_ready_provision = Some(RootCurrentReadyProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            if root_open.completed_receiver().map_err(|_| invalid())?
                != self.current_root_open_original_pair().map_err(|_| invalid())?
            {
                return Err(invalid().into());
            }
            let base = self.current_open_provision.as_ref()
                .and_then(|stage| stage.completed_prefix()).ok_or_else(invalid)?;
            let additional = OriginalRootCreateStorageCurrentAttemptV1::ready_fixed_demand()?;
            let demand = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(demand).map_err(|_| invalid())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_ready_provision.as_mut().ok_or(Error::Service)?.fixed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::ReadyFixed)
    }

    pub(crate) fn prepay_current_ready_bytes_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        index: aos_sandbox_protocol::domain_ledger::create_storage_history::transport::TransferIndexV1,
    ) -> Result<(), Error> {
        if self.failure().is_some() || !self.current_ready_provision.as_ref().is_some_and(|stage| {
            stage.fixed.completed_prefix().is_some() && stage.variable.permit.is_none()
        }) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_ready_provision.as_ref()
                .and_then(|stage| stage.fixed.completed_prefix()).ok_or_else(invalid)?;
            let additional = OriginalRootCreateStorageCurrentAttemptV1::ready_encoded_demand(index)?;
            let demand = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(demand).map_err(|_| invalid())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_ready_provision.as_mut().ok_or(Error::Service)?.variable.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::ReadyBytes)
    }
}
