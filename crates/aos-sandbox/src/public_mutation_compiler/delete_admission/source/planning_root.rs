//! Lends genuine authorized C17/Source planning cuts to the Root comparison.
//!
//! The private producer compares actual held owners. Its DATA is not a pending
//! native64, a Root floor, a Transfer absence or a completed six-domain grant.

use super::*;
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchOriginalV1, ControllerDeletePreacceptTurnOriginalV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1;

pub(crate) struct ControllerDeletePlanningRootCutDataV1 {
    pub(crate) project: [u8; 16],
    pub(crate) caller: [u8; 16],
    pub(crate) input_digest: [u8; 32],
    pub(crate) clock: RawPairedClockSample,
    pub(crate) expires: i64,
    pub(crate) funding: OperationIntakeFundingDataV1,
    pub(crate) controller_next: u64,
    pub(crate) controller_end: u64,
    pub(crate) source_next: u64,
    pub(crate) source_end: u64,
}

impl ControllerDeleteSourceAuthorizedScopeV1<'_, '_> {
    /// Borrows only this same C17's original refused planning admission.
    pub(crate) fn planning_root_intake_failure_view_v1<'cause>(
        &'cause self,
        profile: &'cause ControllerSelfProfileOriginalV1,
    ) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>> {
        self.source.planning_root_intake_failure_view_v1(profile)
    }

    pub(crate) fn planning_root_fixed_demand_v1() -> Result<ResourceVector, crate::JournalError> {
        let memory = std::mem::size_of::<ControllerDeletePlanningRootCutDataV1>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(2 * aos_sandbox_protocol::domain_ledger::resource_bank::OPERATION_INTAKE_FUNDING_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(crate::journal::SourceDeleteSemanticScopeV1::
                planning_read_view_construction_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(crate::JournalError::LimitExceeded("Delete planning Root cut"))?;
        ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .checked_add(super::super::PlanningNonce::demand_v1()?)
            .map_err(crate::JournalError::ReceivingAccounting)
    }

    pub(crate) fn reserve_planning_root_additional_v1(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: ResourceVector,
    ) -> Result<(), crate::JournalError> {
        self.source.reserve_planning_root_additional_v1(controller, launch, profile, additional)
    }

    pub(crate) fn planning_root_cut_data_v1(
        &self,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerDeletePlanningRootCutDataV1, crate::JournalError> {
        let funding = self.source.local_runtime_funding_data_v3(controller, launch, profile)?;
        let (source_next, source_end) = self.source.planning_source_boundary_data_v1()?;
        let coordinator = controller.controller_coordinator_for_bank_read_v1()?;
        let (clock, expires) = self.authorization.authorization_horizon_v1();
        let authorized = self.authorization.authorization();
        Ok(ControllerDeletePlanningRootCutDataV1 {
            project: authorized.project().into_bytes(),
            caller: authorized.caller().into_bytes(),
            input_digest: aos_sandbox_protocol::domain_ledger::delete_root::named_cuts::
                planning_authorized_input_cut_data_v2(self.authorization.input()),
            clock, expires, funding,
            controller_next: coordinator.next_sequence(),
            controller_end: coordinator.durable_prefix_end_data_v1(),
            source_next, source_end,
        })
    }

    pub(crate) fn prepare_planning_root_turn_v1<'profile>(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerDeletePreacceptTurnOriginalV1<'profile>, crate::JournalError> {
        self.source.prepare_planning_root_turn_v1(controller, launch, profile)
    }

    // Inert construction follows this purpose's actual fixed prepay. Only this
    // genuine pair can lend the retained decision to the shared nonce engine.
    pub(crate) fn new_planning_root_nonce_v1(&self) -> super::super::PlanningNonce {
        super::super::PlanningNonce::new(&self.authorization)
    }
}
