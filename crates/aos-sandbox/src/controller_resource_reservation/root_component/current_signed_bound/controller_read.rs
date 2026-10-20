//! Funds Root4's independent C6 read on the continuously held original R.

use aos_sandbox_core::ResourceVector;
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    controller_readonly::RootCurrentControllerReadonlyStateV1,
    root_open::RootCurrentOpenStateV1,
    signed_bound::{SignedControllerFinancialStageV1 as Stage, input::RootSignedInputV1},
    use_admitted::RootCurrentUseAdmittedStateV1,
};
use super::super::{RootReceivingOriginalV1,
    current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::super::ResourceReservationErrorV1;

impl RootReceivingOriginalV1 {
    fn signed_read_stage_v1(&self, stage: Stage) -> Option<&RootCurrentProvisionV1> {
        let read = &self.current_signed_provision.as_ref()?.read;
        Some(match stage { Stage::Fixed => &read.fixed, Stage::Native => &read.native,
            Stage::Semantic => &read.semantic })
    }

    fn signed_read_stage_mut_v1(&mut self, stage: Stage) -> Option<&mut RootCurrentProvisionV1> {
        let read = &mut self.current_signed_provision.as_mut()?.read;
        Some(match stage { Stage::Fixed => &mut read.fixed, Stage::Native => &mut read.native,
            Stage::Semantic => &mut read.semantic })
    }

    pub(crate) fn current_signed_controller_failure_v1(&self, stage: Stage)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        let stage = self.signed_read_stage_v1(stage)?;
        stage.permit.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.activation.currentness_failure_v1()).or_else(|| stage.failure())
    }

    pub(crate) fn prepay_current_signed_controller_fixed_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, input: &RootSignedInputV1,
    ) -> Result<(), Error> {
        let demand = RootCurrentControllerReadonlyStateV1::signed_fixed_demand_v1(input);
        self.prepay_signed_read_once(startup, root, admitted, Stage::Fixed, demand)
    }

    pub(crate) fn prepay_current_signed_controller_native_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, state: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        self.prepay_signed_read_once(startup, root, admitted, Stage::Native, state.additional_native_demand_v1())
    }

    pub(crate) fn prepay_current_signed_controller_semantic_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, state: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        self.prepay_signed_read_once(startup, root, admitted, Stage::Semantic, state.additional_semantic_demand_v1())
    }

    fn prepay_signed_read_once(&mut self, startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1, admitted: &RootCurrentUseAdmittedStateV1,
        stage: Stage, demand: Result<ResourceVector, crate::journal::JournalError>,
    ) -> Result<(), Error> {
        if self.failure().is_some()
            || self.signed_read_stage_v1(stage).is_none_or(|stage| stage.permit.is_some()) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            self.require_signed_original(root, admitted).map_err(|_| invalid())?;
            let prefix = match stage {
                Stage::Fixed => self.current_signed_provision.as_ref()
                    .and_then(|stage| stage.variable.completed_prefix()),
                Stage::Native => self.signed_read_stage_v1(Stage::Fixed)
                    .and_then(|stage| stage.completed_prefix()),
                Stage::Semantic => self.signed_read_stage_v1(Stage::Native)
                    .and_then(|stage| stage.completed_prefix()),
            }.ok_or_else(invalid)?;
            let complete = prefix.checked_add(demand?).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.signed_read_stage_mut_v1(stage).ok_or(Error::Service)?.permit, permit,
        );
        let selected = match stage {
            Stage::Fixed => RootCurrentStageV1::SignedControllerFixed,
            Stage::Native => RootCurrentStageV1::SignedControllerNative,
            Stage::Semantic => RootCurrentStageV1::SignedControllerSemantic,
        };
        self.finish_current_provision_once(startup, selected)
    }

    fn require_signed_read_stage_v1(&self, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, stage: Stage,
    ) -> Result<(), Error> {
        self.require_signed_original(root, admitted)?;
        self.signed_read_stage_v1(stage).and_then(|stage| stage.completed_prefix())
            .map(|_| ()).ok_or(Error::Service)
    }

    pub(crate) fn require_current_signed_controller_fixed(&self, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1,
    ) -> Result<(), Error> {
        self.require_signed_read_stage_v1(root, admitted, Stage::Fixed)
    }

    pub(crate) fn require_current_signed_controller_semantic(&self, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1,
    ) -> Result<(), Error> {
        self.require_signed_read_stage_v1(root, admitted, Stage::Semantic)
    }
}
