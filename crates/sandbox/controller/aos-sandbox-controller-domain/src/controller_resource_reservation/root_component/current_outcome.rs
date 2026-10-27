//! Admits Root5's concrete staged readers and pair under the same actual R.
//!
//! Every amount comes from the actual fixed owner or captured extent. The
//! private stage roster preserves existing cumulative highwater, native debt
//! and reserved listener capacity; no receipt or caller vector creates a loan.

use aos_sandbox_model::ResourceVector;
use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{root_open::RootCurrentOpenStateV1,
    use_admitted::RootCurrentUseAdmittedStateV1, use_reserved::RootCurrentUseReservedStateV1,
    signed_bound::RootCurrentSignedBoundStateV1, controller_readonly::RootCurrentControllerReadonlyStateV1,
    outcome::{RootCurrentOutcomeStateV1, input::RootOutcomeInputV1, read::RootCurrentOutcomeReadV1}};
use super::{RootReceivingOriginalV1, root_journal::RootJournalDemandErrorV1,
    current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::ResourceReservationErrorV1;

#[derive(Default)]
pub(super) struct RootOutcomeProvisionV1 {
    pub(super) fixed: RootCurrentProvisionV1,
    pub(super) variable: RootCurrentProvisionV1,
    pub(super) controller_native: RootCurrentProvisionV1,
    pub(super) controller_semantic: RootCurrentProvisionV1,
    pub(super) session: RootCurrentProvisionV1,
}

impl RootOutcomeProvisionV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.fixed.failure().or_else(|| self.variable.failure())
            .or_else(|| self.controller_native.failure()).or_else(|| self.controller_semantic.failure())
            .or_else(|| self.session.failure())
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn current_outcome_failure_v1(&self,
        selected: crate::policy_compiler::create_storage_current::outcome::OutcomeFinancialStageV1,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        use crate::policy_compiler::create_storage_current::outcome::OutcomeFinancialStageV1 as Stage;
        let original = self.current_outcome_provision.as_ref()?;
        let stage = match selected {
            Stage::Fixed => &original.fixed, Stage::Bytes => &original.variable,
            Stage::ControllerNative => &original.controller_native,
            Stage::ControllerSemantic => &original.controller_semantic, Stage::Session => &original.session,
        };
        stage.permit.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.activation.currentness_failure_v1()).or_else(|| stage.failure())
    }

    fn require_outcome_original(&self, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1) -> Result<(), Error> {
        signed.require_complete_v1().map_err(|_| Error::Service)?;
        if self.failure().is_some() || root.completed_receiver().map_err(|_| Error::Service)?
            != self.current_root_open_original_pair().map_err(|_| Error::Service)?
        { return Err(Error::Service); }
        Ok(())
    }

    pub(crate) fn prepay_current_outcome_fixed_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, signed: &RootCurrentSignedBoundStateV1,
    ) -> Result<(), Error> {
        if self.current_outcome_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_outcome_provision = Some(Default::default());
        let permit: Result<_, RootJournalDemandErrorV1> = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            self.require_outcome_original(root, signed).map_err(|_| invalid())?;
            let base = self.completed_signed_bound_prefix_v1(root, admitted, signed).map_err(|_| invalid())?;
            let held = self.current_writers_receiving.as_ref()
                .and_then(|stage| stage.authority_extent()).ok_or_else(invalid)?;
            let demand = RootCurrentOutcomeStateV1::fixed_receiving_demand_v1(held, signed)?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_outcome_provision.as_mut().ok_or(Error::Service)?.fixed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::OutcomeFixed)
    }

    pub(crate) fn prepay_current_outcome_bytes_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, input: &RootOutcomeInputV1, reserved: &RootCurrentUseReservedStateV1,
    ) -> Result<(), Error> {
        self.require_outcome_original(root, signed)?;
        if self.current_outcome_provision.as_ref().is_none_or(|stage|
            stage.fixed.completed_prefix().is_none() || stage.variable.permit.is_some())
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit: Result<_, RootJournalDemandErrorV1> = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_outcome_provision.as_ref()
                .and_then(|stage| stage.fixed.completed_prefix()).ok_or_else(invalid)?;
            let demand = input.additional_received_demand_v1(reserved)?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_outcome_provision.as_mut().ok_or(Error::Service)?.variable.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::OutcomeBytes)
    }

    pub(crate) fn prepay_current_outcome_controller_native_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, state: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        self.require_outcome_original(root, signed)?;
        if self.current_outcome_provision.as_ref().is_none_or(|stage|
            stage.variable.completed_prefix().is_none() || stage.controller_native.permit.is_some())
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit: Result<_, RootJournalDemandErrorV1> = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_outcome_provision.as_ref()
                .and_then(|stage| stage.variable.completed_prefix()).ok_or_else(invalid)?;
            let demand = state.additional_native_demand_v1()?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_outcome_provision.as_mut().ok_or(Error::Service)?.controller_native.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::OutcomeControllerNative)
    }

    pub(crate) fn prepay_current_outcome_controller_semantic_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, state: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        self.require_outcome_original(root, signed)?;
        if self.current_outcome_provision.as_ref().is_none_or(|stage|
            stage.controller_native.completed_prefix().is_none() || stage.controller_semantic.permit.is_some())
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit: Result<_, RootJournalDemandErrorV1> = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_outcome_provision.as_ref()
                .and_then(|stage| stage.controller_native.completed_prefix()).ok_or_else(invalid)?;
            let demand = state.additional_semantic_demand_v1()?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_outcome_provision.as_mut().ok_or(Error::Service)?.controller_semantic.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::OutcomeControllerSemantic)
    }

    pub(crate) fn prepay_current_outcome_session_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, read: &RootCurrentOutcomeReadV1,
    ) -> Result<(), Error> {
        self.require_outcome_original(root, signed)?;
        if self.current_outcome_provision.as_ref().is_none_or(|stage|
            stage.controller_semantic.completed_prefix().is_none() || stage.session.permit.is_some())
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit: Result<_, RootJournalDemandErrorV1> = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.current_outcome_provision.as_ref()
                .and_then(|stage| stage.controller_semantic.completed_prefix()).ok_or_else(invalid)?;
            let demand = read.additional_session_demand_v1()?;
            let complete = base.checked_add(demand).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_outcome_provision.as_mut().ok_or(Error::Service)?.session.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::OutcomeSession)
    }

    pub(crate) fn require_current_outcome_controller_fixed(&self, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1) -> Result<(), Error> {
        self.require_outcome_original(root, signed)?;
        self.current_outcome_provision.as_ref().and_then(|stage| stage.variable.completed_prefix())
            .ok_or(Error::Service).map(|_| ())
    }

    pub(crate) fn require_current_outcome_controller_semantic(&self, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1) -> Result<(), Error> {
        self.require_outcome_original(root, signed)?;
        self.current_outcome_provision.as_ref().and_then(|stage| stage.controller_semantic.completed_prefix())
            .ok_or(Error::Service).map(|_| ())
    }

    pub(crate) fn completed_outcome_prefix_v1(&self, root: &RootCurrentOpenStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1,
    ) -> Result<ResourceVector, Error> {
        self.require_outcome_original(root, signed)?;
        outcome.require_complete_v1().map_err(|_| Error::Service)?;
        self.current_outcome_provision.as_ref().and_then(|stage| stage.session.completed_prefix()).ok_or(Error::Service)
    }
}
