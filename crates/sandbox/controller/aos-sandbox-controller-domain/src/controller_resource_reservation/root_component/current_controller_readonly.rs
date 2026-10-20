//! Admits one independent Controller read under the same actual Root R.
//!
//! Fixed preparation, the held native prefix and its audited semantic maximum
//! are distinct closed stages. No path, caller vector, parsed receipt or other
//! owner's writer can construct a completed receiving stage.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    cache_current::RootCurrentCacheProofStateV1,
    controller_readonly::RootCurrentControllerReadonlyStateV1,
    root_open::RootCurrentOpenStateV1,
};
use super::{
    RootReceivingOriginalV1,
    current_provision::{RootCurrentProvisionV1, RootCurrentStageV1},
};
use super::super::ResourceReservationErrorV1;

#[derive(Default)]
pub(super) struct RootCurrentControllerReadonlyProvisionV1 {
    pub(super) fixed: RootCurrentProvisionV1,
    pub(super) native: RootCurrentProvisionV1,
    pub(super) semantic: RootCurrentProvisionV1,
}

impl RootCurrentControllerReadonlyProvisionV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed.failure()
            .or_else(|| self.native.failure())
            .or_else(|| self.semantic.failure())
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_controller_readonly_fixed_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1,
        cache: &RootCurrentCacheProofStateV1,
    ) -> Result<(), Error> {
        if self.current_controller_readonly_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_controller_readonly_provision = Some(Default::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            cache.require_complete_v1().map_err(|_| invalid())?;
            if root.completed_receiver().map_err(|_| invalid())?
                != self.current_root_open_original_pair().map_err(|_| invalid())?
            {
                return Err(invalid().into());
            }
            let base = self.current_cache_proof_provision.as_ref()
                .and_then(|stage| stage.completed_prefix()).ok_or_else(invalid)?;
            let complete = base.checked_add(RootCurrentControllerReadonlyStateV1::fixed_demand_v1()?)
                .map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete).map_err(|_| invalid())?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_controller_readonly_provision.as_mut().ok_or(Error::Service)?
            .fixed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::ControllerReadonlyFixed)
    }

    pub(crate) fn prepay_current_controller_readonly_native_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1,
        state: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        self.require_current_controller_readonly_stage(root, false)?;
        if self.current_controller_readonly_provision.as_ref()
            .is_none_or(|stage| stage.native.permit.is_some())
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_controller_readonly_provision.as_ref()
                .and_then(|stage| stage.fixed.completed_prefix()).ok_or_else(invalid)?;
            let complete = base.checked_add(state.additional_native_demand_v1()?)
                .map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete).map_err(|_| invalid())?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_controller_readonly_provision.as_mut().ok_or(Error::Service)?
            .native.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::ControllerReadonlyNative)
    }

    pub(crate) fn prepay_current_controller_readonly_semantic_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1,
        state: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        self.require_current_controller_readonly_stage(root, false)?;
        if self.current_controller_readonly_provision.as_ref().is_none_or(|stage|
            stage.native.completed_prefix().is_none() || stage.semantic.permit.is_some())
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_controller_readonly_provision.as_ref()
                .and_then(|stage| stage.native.completed_prefix()).ok_or_else(invalid)?;
            let complete = base.checked_add(state.additional_semantic_demand_v1()?)
                .map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete).map_err(|_| invalid())?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_controller_readonly_provision.as_mut().ok_or(Error::Service)?
            .semantic.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::ControllerReadonlySemantic)
    }

    // This private borrowed gate observes no native state and creates no token.
    // It can only require a completed stage on this same continuously held R.
    pub(crate) fn require_current_controller_readonly_stage(
        &self,
        root: &RootCurrentOpenStateV1,
        semantic: bool,
    ) -> Result<(), Error> {
        if self.failure().is_some()
            || root.completed_receiver().map_err(|_| Error::Service)?
                != self.current_root_open_original_pair().map_err(|_| Error::Service)?
        {
            return Err(Error::Service);
        }
        let stage = self.current_controller_readonly_provision.as_ref().ok_or(Error::Service)?;
        let complete = if semantic {
            stage.semantic.completed_prefix()
        } else {
            stage.fixed.completed_prefix()
        };
        complete.map(|_| ()).ok_or(Error::Service)
    }
}
