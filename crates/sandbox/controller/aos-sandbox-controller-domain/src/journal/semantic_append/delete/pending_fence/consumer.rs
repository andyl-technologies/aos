//! Prepays the reached pending consumer beside all earlier held D originals.
//!
//! This adds actual representation and clock debt to the SAME consumed C17
//! frontier before constructing the owner or entering the existing planner.

use super::*;

impl SourceDeleteSemanticScopeV1<'_, '_> {
    pub(crate) fn reserve_pending_consumer_v2(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        operation: &crate::lifecycle::LifecycleOperationV1,
        batch: &aos_sandbox_protocol::domain_ledger::delete_batch::LifecycleDeleteBatchV1,
        fixed: ResourceVector,
    ) -> Result<ResourceVector, JournalError> {
        let prefix = usize::try_from(self.native.durable_end_data_v1())
            .map_err(|_| JournalError::JournalTooLarge)?;
        let bytes = crate::lifecycle::delete_pending::preparation_payload_bytes_v1(operation, batch, prefix)?;
        let own = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?)
            .with(D::MetadataEntries, 3);
        let cuts = self.planning_cuts_receiving_demand_v2()?;
        let additional = own.checked_add(cuts)
            .and_then(|demand| demand.checked_add(fixed))
            .map_err(JournalError::ReceivingAccounting)?;
        let receipt = self.native.reserve_delete_additional_demand_with_receipt_v2(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(additional),
        ).map_err(JournalError::ControllerNative)?;

        // The existing planner adds these SAME two terms once. Only the DATA
        // argument is normalized; the actual checked cumulative reservation
        // and consumed traffic are never subtracted, refunded or reset.
        receipt.checked_sub(own).and_then(|demand| demand.checked_sub(cuts))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn reserve_pending_append_v2(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        plan: &SourceDeletePendingPlanV1<'_>,
    ) -> Result<ResourceVector, JournalError> {
        self.reserve_exact_delete_append_v3(controller, launch, profile, plan.transaction())
    }

    pub(in crate::journal) fn reserve_exact_delete_append_v3(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction,
    ) -> Result<ResourceVector, JournalError> {
        let (stage, semantic, _) = source_semantic_append_geometry_v2(
            self.native.semantic_read_view_v1(), self.native.durable_end_data_v1(), transaction, &self.semantic,
        )?;
        let native = SourceDeleteAppendOriginalV1::<Selection>::receiving_demand_v1()
            .map_err(JournalError::ControllerNative)?;
        let additional = stage.checked_add(semantic).and_then(|demand| demand.checked_add(native))
            .map_err(JournalError::ReceivingAccounting)?;
        let receipt = self.native.reserve_delete_additional_demand_with_receipt_v2(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(additional),
        ).map_err(JournalError::ControllerNative)?;

        // Common upper/lower entry adds stage+semantic+native exactly once.
        // The SAME slot already retains and has paid the full receipt.
        receipt.checked_sub(additional).map_err(JournalError::ReceivingAccounting)
    }
}
