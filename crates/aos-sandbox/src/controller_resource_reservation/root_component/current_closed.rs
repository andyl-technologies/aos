//! Admits each actual terminal native/semantic frontier from the same whole R.
//!
//! A closed stage selects its concrete existing reader recipe. Caller vectors,
//! receipts and decoded models cannot create a role, account or IO grant.

use aos_sandbox_core::ResourceVector;
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    closed::{RootCurrentClosedStateV1, ClosedFinancialStageV1, read::RootCurrentClosedReadV1},
    root_open::RootCurrentOpenStateV1, signed_bound::RootCurrentSignedBoundStateV1,
    outcome::RootCurrentOutcomeStateV1, controller_readonly::RootCurrentControllerReadonlyStateV1};
use super::{RootReceivingOriginalV1, root_journal::RootJournalDemandErrorV1,
    current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::ResourceReservationErrorV1;

pub(super) struct RootClosedProvisionV1 { pub(super) stages: [RootCurrentProvisionV1; 7] }

impl Default for RootClosedProvisionV1 {
    fn default() -> Self { Self { stages: std::array::from_fn(|_| Default::default()) } }
}

impl RootClosedProvisionV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stages.iter().find_map(|stage| stage.failure())
    }
}

impl RootReceivingOriginalV1 {
    fn require_closed_original(&self, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1) -> Result<(), Error> {
        self.completed_outcome_prefix_v1(root, signed, outcome)?;
        if root.completed_receiver().map_err(|_| Error::Service)?
            != self.current_root_open_original_pair().map_err(|_| Error::Service)? { return Err(Error::Service); }
        Ok(())
    }

    pub(crate) fn prepay_current_closed_fixed_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1) -> Result<(), Error> {
        if self.current_closed_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1(); return Err(Error::Service);
        }
        self.current_closed_provision = Some(Default::default());
        let permit: Result<_, RootJournalDemandErrorV1> = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            self.require_closed_original(root, signed, outcome).map_err(|_| invalid())?;
            let base = self.completed_outcome_prefix_v1(root, signed, outcome).map_err(|_| invalid())?;
            let held = self.current_writers_receiving.as_ref()
                .and_then(|stage| stage.authority_extent()).ok_or_else(invalid)?;
            let demand = RootCurrentClosedStateV1::fixed_receiving_demand_v1(held, outcome)?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_closed_provision.as_mut().ok_or(Error::Service)?.stages[0].permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::Closed(ClosedFinancialStageV1::Fixed))
    }

    fn require_closed_previous(&self, stage: ClosedFinancialStageV1) -> Result<ResourceVector, Error> {
        let index = stage.index_v1();
        let stages = &self.current_closed_provision.as_ref().ok_or(Error::Service)?.stages;
        if index == 0 || stages[index].permit.is_some() { return Err(Error::Service); }
        stages[index - 1].completed_prefix().ok_or(Error::Service)
    }

    pub(crate) fn prepay_current_closed_controller_native_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1,
        read: &RootCurrentControllerReadonlyStateV1) -> Result<(), Error> {
        self.prepay_closed_controller(startup, root, signed, outcome, read, ClosedFinancialStageV1::ControllerNative)
    }

    pub(crate) fn prepay_current_closed_controller_semantic_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1,
        read: &RootCurrentControllerReadonlyStateV1) -> Result<(), Error> {
        self.prepay_closed_controller(startup, root, signed, outcome, read, ClosedFinancialStageV1::ControllerSemantic)
    }

    fn prepay_closed_controller(&mut self, startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1, signed: &RootCurrentSignedBoundStateV1,
        outcome: &RootCurrentOutcomeStateV1, read: &RootCurrentControllerReadonlyStateV1,
        stage: ClosedFinancialStageV1) -> Result<(), Error> {
        self.require_closed_original(root, signed, outcome)?;
        let base = self.require_closed_previous(stage)?;
        let permit: Result<_, RootJournalDemandErrorV1> = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let demand = match stage {
                ClosedFinancialStageV1::ControllerNative => read.additional_native_demand_v1()?,
                ClosedFinancialStageV1::ControllerSemantic => read.additional_semantic_demand_v1()?,
                _ => return Err(invalid().into()),
            };
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_closed_provision.as_mut().ok_or(Error::Service)?.stages[stage.index_v1()].permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::Closed(stage))
    }

    pub(crate) fn prepay_current_closed_release_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1,
        read: &RootCurrentClosedReadV1, stage: ClosedFinancialStageV1) -> Result<(), Error> {
        self.require_closed_original(root, signed, outcome)?;
        let base = self.require_closed_previous(stage)?;
        let permit: Result<_, RootJournalDemandErrorV1> = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let demand = read.additional_demand_v1(stage)?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_closed_provision.as_mut().ok_or(Error::Service)?.stages[stage.index_v1()].permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::Closed(stage))
    }

    pub(crate) fn require_current_closed_controller_fixed(&self, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1) -> Result<(), Error> {
        self.require_closed_original(root, signed, outcome)?;
        self.current_closed_provision.as_ref().and_then(|stage| stage.stages[0].completed_prefix())
            .ok_or(Error::Service).map(|_| ())
    }

    pub(crate) fn require_current_closed_controller_semantic(&self, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1) -> Result<(), Error> {
        self.require_closed_original(root, signed, outcome)?;
        self.current_closed_provision.as_ref().and_then(|stage| stage.stages[2].completed_prefix())
            .ok_or(Error::Service).map(|_| ())
    }

    pub(crate) fn current_closed_failure_v1(&self, selected: ClosedFinancialStageV1)
        -> Option<&(dyn std::error::Error + 'static)> {
        let stage = &self.current_closed_provision.as_ref()?.stages[selected.index_v1()];
        stage.permit.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.activation.currentness_failure_v1()).or_else(|| stage.failure())
    }
}
