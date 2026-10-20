//! Recomputes V2 authorization, Source and Controller cuts on held originals.
//!
//! The Source preimage contains the native predecessor, the complete canonical
//! Tree encoding, both saved lineage heads, the canonical genesis seed, and
//! every validated policy-custody row in native namespace/key order. Each row
//! has fixed-width namespace and length prefixes. This is a saved predecessor
//! comparison under the genuine exclusive Source/C17 loan, never a new owner.

use super::*;
use sha2::{Digest as _, Sha256};
use aos_sandbox_protocol::domain_ledger::delete_batch::{
    DeleteBatchCommitmentsDataV2, LifecycleDeleteBatchV1,
};
use crate::public_mutation_compiler::delete_admission::DeleteAuthorizationBindingV1;

pub(crate) struct DeletePlanningBaseCutsDataV2 {
    pub(crate) authorization: [u8; 32],
    pub(crate) source: [u8; 32],
    pub(crate) controller: [u8; 32],
}

impl SourceDeleteSemanticScopeV1<'_, '_> {
    // A full historical prefix bounds Tree/Lineage reconstruction, including
    // superseded rows. Separate encoded lanes cover the current canonical Tree
    // while its validated model and original saved state remain resident.
    pub(super) fn planning_cuts_receiving_demand_v2(&self)
        -> Result<ResourceVector, JournalError>
    {
        let read = self.native.semantic_read_view_v1();
        let extent = protected_journal_preopen_replay_extent_for_prefix_v1(
            read.limits(), self.native.durable_end_data_v1(),
        )?;
        let fixed = std::mem::size_of::<DeletePlanningBaseCutsDataV2>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                aos_sandbox_protocol::domain_ledger::delete_root::named_cuts::DeleteAuthorizationCutDataV2<'_>
            >().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<aos_sandbox_ledger_replay::replay::tree_lineage::ClosedTreeLineageHeadV1>()
                    .checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(3 * aos_sandbox_protocol::domain_ledger::resource_bank::OPERATION_INTAKE_FUNDING_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Sha256>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(CanonicalWriterReadViewV1::<Selection>::receiving_construction_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("Delete V2 planning cuts"))?;
        let encoded = extent.native_bytes.checked_mul(4).and_then(|bytes| bytes.checked_add(fixed))
            .ok_or(JournalError::LimitExceeded("Delete V2 canonical Tree"))?;
        extent.dominant_semantic_receiving_demand_v1()?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, encoded),
        ).map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn capture_planning_base_cuts_v2(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        authorization: &DeleteAuthorizationBindingV1<'_>,
    ) -> Result<DeletePlanningBaseCutsDataV2, JournalError> {
        let demand = self.planning_cuts_receiving_demand_v2()?;
        self.native.reserve_delete_preaccept_additional_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(demand),
        ).map_err(JournalError::ControllerNative)?;
        self.planning_base_cuts_data_v2(controller, launch, profile, authorization)
    }

    /// Derives only the three cuts whose actual originals this scope owns.
    ///
    /// The caller must admit planning_cuts_receiving_demand_v2 before entry.
    /// No public constructor, caller digest or historical DTO substitutes a
    /// current claim, authorization, Source writer or complete six observation.
    fn planning_base_cuts_data_v2(
        &self,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        authorization: &DeleteAuthorizationBindingV1<'_>,
    ) -> Result<DeletePlanningBaseCutsDataV2, JournalError> {
        let funding = self.local_runtime_funding_data_v3(controller, launch, profile)?;
        let coordinator = controller.controller_coordinator_for_bank_read_v1()?;
        let controller_cut = funding.controller_funding_cut_data_v3(coordinator.next_sequence(),
            coordinator.durable_prefix_end_data_v1())
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let source_cut = aos_sandbox_ledger_replay::replay::tree_lineage::delete_cut::source_predecessor_cut_data_v2(
            self.historical_view_v1()?.materialized_state_v1(), authorization.authorization().project(),
            self.native.semantic_read_view_v1().next_sequence(), self.native.durable_end_data_v1(),
        )?;
        Ok(DeletePlanningBaseCutsDataV2 {
            authorization: authorization.authorization_cut_data_v2(),
            source: source_cut,
            controller: controller_cut,
        })
    }

    pub(super) fn require_planning_cuts_v2(
        &self,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        authorization: &DeleteAuthorizationBindingV1<'_>,
        batch: &LifecycleDeleteBatchV1,
    ) -> Result<(), JournalError> {
        let DeleteBatchCommitmentsDataV2 { authorization: saved_authorization,
            source: saved_source, controller: saved_controller, .. } = batch.view()
            .map_err(|_| JournalError::MalformedRecord("Delete V2 batch"))?
            .named_commitments_v2().ok_or(JournalError::ProtectedBoundary)?;
        let actual = self.planning_base_cuts_data_v2(controller, launch, profile, authorization)?;
        if actual.authorization != saved_authorization || actual.source != saved_source
            || actual.controller != saved_controller
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}
