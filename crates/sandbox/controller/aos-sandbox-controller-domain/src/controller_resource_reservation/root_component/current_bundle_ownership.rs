//! Admits actual B Ownership verification through the same completed Root R.
//!
//! The closed stages require the actual completed local trust and Source17
//! predecessor. Neither a supplied vector nor a parsed response constructs R.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    ownership_trust::RootCurrentOwnershipTrustStateV1,
    root_open::RootCurrentOpenStateV1,
    source_current::RootCurrentSourceExchangeStateV1,
};
use super::{RootReceivingOriginalV1, current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::ResourceReservationErrorV1;

#[derive(Default)]
pub(super) struct RootCurrentBundleOwnershipProvisionV1 {
    pub(super) fixed: RootCurrentProvisionV1,
    pub(super) typed: RootCurrentProvisionV1,
}

impl RootCurrentBundleOwnershipProvisionV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed.failure().or_else(|| self.typed.failure())
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_bundle_ownership_fixed_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        trust: &RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), Error> {
        if self.current_bundle_ownership_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_bundle_ownership_provision = Some(RootCurrentBundleOwnershipProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            source.require_complete_v1().map_err(|_| invalid())?;
            trust.require_complete().map_err(|_| invalid())?;
            if root.completed_receiver().map_err(|_| invalid())?
                != self.current_root_open_original_pair().map_err(|_| invalid())?
            {
                return Err(invalid().into());
            }
            let base = self.current_source_exchange_provision.as_ref()
                .and_then(|stage| stage.completed_prefix()).ok_or_else(invalid)?;
            let additional = RootCurrentBundleOwnershipStateV1::fixed_demand_v1()?;
            let complete = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete).map_err(|_| invalid())?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_bundle_ownership_provision.as_mut().ok_or(Error::Service)?.fixed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::BundleOwnershipFixed)
    }

    pub(crate) fn prepay_current_bundle_ownership_typed_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1,
        state: &RootCurrentBundleOwnershipStateV1,
    ) -> Result<(), Error> {
        if self.failure().is_some() || root.completed_receiver().map_err(|_| Error::Service)?
            != self.current_root_open_original_pair().map_err(|_| Error::Service)?
            || self.current_bundle_ownership_provision.as_ref().is_none_or(|stage|
                stage.fixed.completed_prefix().is_none() || stage.typed.permit.is_some())
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_bundle_ownership_provision.as_ref()
                .and_then(|stage| stage.fixed.completed_prefix()).ok_or_else(invalid)?;
            let complete = base.checked_add(state.additional_typed_demand_v1()?)
                .map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete).map_err(|_| invalid())?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_bundle_ownership_provision.as_mut().ok_or(Error::Service)?.typed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::BundleOwnershipTyped)
    }
}
