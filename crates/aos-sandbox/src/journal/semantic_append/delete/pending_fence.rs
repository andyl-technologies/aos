//! Keeps actual Source pending COMMIT provenance on its continuously held scope.
//!
//! The same native parser observes the exact prepared transaction. Only actual
//! local append/readback/post disposal can install its private completion on
//! the original scope. Returned position DATA is never accepted as an input.

use super::*;
use crate::lifecycle::delete_pending::SourceDeletePendingPlanV1;

mod inventory_append;
mod consumer;
pub use inventory_append::{DeleteInventorySessionAppendOriginalV1, DeleteInventorySessionAppendDisposalV1, DeleteInventoryIoDisposalV1, DeleteInventorySecurityShapeDataV1};

/// Observes the exact Source transaction after the sole parser validates COMMIT.
pub(in crate::journal) struct PendingNativeObserverV1<'transaction> {
    expected: &'transaction JournalTransaction,
    proof: Option<[u8; 64]>,
}

impl<'transaction> PendingNativeObserverV1<'transaction> {
    pub(super) const fn new(expected: &'transaction JournalTransaction) -> Self {
        Self { expected, proof: None }
    }

    pub(in crate::journal) fn observe(&mut self, transaction: &JournalTransaction,
        commit_sequence: u64, end_offset: u64, native_digest: &[u8],
    ) -> Result<(), JournalError> {
        if transaction.id() != self.expected.id() { return Ok(()); }
        if transaction != self.expected || self.proof.is_some() {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.proof = Some(crate::journal::delete_batch::native_commit_data_v1(
            *transaction.id(), commit_sequence, end_offset, native_digest,
        )?);
        Ok(())
    }

    pub(super) fn completed(&self) -> Option<&[u8; 64]> { self.proof.as_ref() }
}

// No caller-supplied DATA can install this marker. Construction stays next to
// the real same-scope native appender's completed local disposition.
pub(super) struct PendingSourceCompletionV1 {
    project: aos_sandbox_core::ProjectId,
    operation: aos_sandbox_core::OperationId,
    batch: aos_sandbox_core::ObjectDigest,
    committed: CommitResult,
    end: u64,
    native: [u8; 64],
}

impl PendingSourceCompletionV1 {
    pub(super) fn new(project: aos_sandbox_core::ProjectId,
        operation: aos_sandbox_core::OperationId, batch: aos_sandbox_core::ObjectDigest,
        committed: CommitResult, end: u64, native: [u8; 64],
    ) -> Self { Self { project, operation, batch, committed, end, native } }
}

/// Borrows the real C17/Source owner and the checked request behind its fence.
///
/// The owner grants no Controller acceptance, six-domain proof, fresh Root
/// floor or destruction authority. Those stages must join these held originals
/// and fund their own actual cumulative IO before entering their real engines.
#[must_use]
pub(crate) struct SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization> {
    pub(super) scope: &'fence mut SourceDeleteSemanticScopeV1<'journal, 'original>,
    pub(super) plan: &'fence SourceDeletePendingPlanV1<'authorization>,
}

impl<'journal, 'original> SourceDeleteSemanticScopeV1<'journal, 'original> {
    /// Borrows intrinsic pending provenance from this same actual Source scope.
    ///
    /// # Errors
    /// Refuses absent local completion, changed native position or saved rows,
    /// a different plan or native uncertainty. Supplied readback DATA is not an
    /// argument and cannot create this continuously held borrower.
    pub(crate) fn borrow_pending_fence_v1<'fence, 'authorization>(
        &'fence mut self,
        plan: &'fence SourceDeletePendingPlanV1<'authorization>,
    ) -> Result<SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>, JournalError> {
        if self.readiness.entered || self.readiness.next != 0 {
            return Err(JournalError::ProtectedBoundary);
        }
        let completion = self.pending_completion.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let read = self.native.historical_view_v1().map_err(JournalError::ControllerNative)?;
        let native = self.native.semantic_read_view_v1();
        if plan.coordinates() != (completion.project, completion.operation, completion.batch)
            || completion.committed.commit_sequence.checked_add(1) != Some(native.next_sequence())
            || completion.end != self.native.durable_end_data_v1()
            || completion.native[..16] != *plan.transaction().id()
            || completion.native[48..56] != completion.committed.commit_sequence.to_be_bytes()
            || completion.native[56..64] != completion.end.to_be_bytes()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        plan.require_saved_v1(read.materialized_state_v1())?;
        Ok(SourceDeletePendingFenceV1 { scope: self, plan })
    }
}

impl SourceDeletePendingFenceV1<'_, '_, '_, '_> {
    /// Borrows the actual checked public request while its native owner lives.
    pub(crate) fn authorization(&self)
        -> &crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1
    { self.plan.authorization() }

    /// Returns the actual authorization clock and exclusive earliest lease end.
    ///
    /// A later Root cutoff must preserve both original leases using this same
    /// paired clock. The held pending fence supplies no renewed authorization.
    pub(crate) fn authorization_horizon_v1(&self) -> (aos_sandbox_core::RawPairedClockSample, i64) {
        self.plan.authorization_horizon_v1()
    }

    // These DATA borrows stay downstream of the genuine intrinsic pending
    // scope; no supplied input or decision can replace the retained binding.
    pub(crate) fn original_public_request_data_v3(&self) -> &[u8] {
        self.plan.original_public_request_data_v3()
    }

    pub(crate) fn authorization_input_data_v2(&self) -> &[u8] {
        self.plan.authorization_input_data_v2()
    }

    pub(crate) fn authorization_witness_fields_v2(&self,
        open: aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootOpenDataV2,
        challenge: aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootChallengeDataV2,
    ) -> Result<aos_sandbox_protocol::domain_ledger::delete_root::authorization::DeleteRootAuthorizationFieldsV2,
        aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2> {
        self.plan.authorization_witness_fields_v2(open, challenge)
    }

    /// Borrows the canonical pending batch; these bytes alone grant nothing.
    pub(crate) fn batch_bytes(&self) -> Result<&[u8], JournalError> { self.plan.batch_bytes() }

    /// Borrows the actual parser-observed native COMMIT coordinates as DATA.
    ///
    /// # Errors
    /// Refuses missing same-scope provenance; no supplied bytes are adopted.
    pub(crate) fn native_position_data_v1(&self) -> Result<&[u8; 64], JournalError> {
        self.scope.pending_completion.as_ref().map(|completion| &completion.native)
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Borrows the same pending Source prefix for a prepaid historical comparison.
    ///
    /// # Errors
    /// Refuses missing intrinsic pending custody or actual native read failure.
    /// The outer C17/Source borrower still proves currentness and pays all posts.
    pub(crate) fn completed_stop_source_rows_v5(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>, JournalError> {
        self.native_position_data_v1()?;
        Ok(self.scope.native.historical_view_v1()
            .map_err(JournalError::ControllerNative)?.rows_data_v2())
    }

    /// Borrows the actual C17 funding and same held Controller position as DATA.
    ///
    /// Root must independently compare the complete canonical funding and current
    /// Controller cut under its genuine peer/read owner. Neither this tuple nor
    /// any field reconstructed from a wire can create this pending borrower.
    ///
    /// # Errors
    /// Refuses lost pending custody, a changed Source/C/profile/Launch, or any
    /// intervening Controller transaction since the exact pending plan.
    pub(crate) fn controller_funding_cut_data_v3(
        &self,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1, u64, u64), JournalError> {
        self.native_position_data_v1()?;
        let coordinator = controller.controller_coordinator_for_bank_read_v1()?;
        let funding = self.scope.native.current_delete_funding_data_v3(coordinator, launch, profile)
            .map_err(JournalError::ControllerNative)?;
        let next = controller.snapshot_sequence();
        if next != self.plan.controller_sequence_data_v1() {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok((funding, next, coordinator.durable_prefix_end_data_v1()))
    }

    /// Prepays fresh D-only native bookends while this exact pending cut lives.
    ///
    /// The returned native owner has no transport or six-domain grant. Its
    /// actual before/after destinations are distinct from the outer C17 posts;
    /// a real consumer must retain its upper IO until their positive disposal.
    /// The complete DATA includes all still-held models and cumulative upper
    /// traffic; the same native engine adds its own reached turn schedule.
    ///
    /// # Errors
    /// Refuses absent intrinsic pending provenance, native uncertainty, foreign
    /// C/profile/Launch or a requirement outside the same paid C17 declaration.
    pub(crate) fn prepare_preaccept_turn_v1<'profile>(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerDeletePreacceptTurnOriginalV1<'profile>, JournalError> {
        self.native_position_data_v1()?;
        self.scope.native.prepare_delete_preaccept_turn_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(
                complete.componentwise_max(self.plan.complete_demand()),
            ),
        ).map_err(JournalError::ControllerNative)
    }

    /// Borrows the same loan's retained cause for a precise C17 marker only.
    ///
    /// This lends neither a writer nor a new admission. The active consumer
    /// keeps its native/input originals and preserves their earlier causes.
    pub(crate) fn intake_failure_view_v1<'cause>(
        &'cause self,
        profile: &'cause ControllerSelfProfileOriginalV1,
    ) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>> {
        self.scope.native.delete_intake_failure_view_v1(profile)
    }

    /// Pays newly reached preaccept debt without replacing earlier stages.
    ///
    /// Root/Session clients derive this additional DATA from their actual
    /// finite recipe before growth. The same original retains the previous
    /// complete frontier, so interleaved clients cannot erase one another's
    /// entered traffic by passing an equal stage maximum. No capability or
    /// positive proof is created by this financial check.
    ///
    /// # Errors
    /// Retains same-C17 arithmetic/capacity refusal or changed native association.
    /// It never arms fresh work or pays additional debt after primary refusal.
    pub(crate) fn reserve_preaccept_additional_v1(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: ResourceVector,
    ) -> Result<(), JournalError> {
        self.native_position_data_v1()?;
        self.scope.native.reserve_delete_preaccept_additional_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(additional),
        ).map_err(JournalError::ControllerNative)
    }

    /// Prepays the next reached complete frontier on the SAME intrinsic C17.
    ///
    /// # Errors
    /// Retains actual C/profile/Launch/capacity refusal. Cumulative transport
    /// schedules, rather than equal per-stage maxima, must precede native IO.
    pub(crate) fn require_complete_v1(&mut self, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<(), JournalError> {
        self.scope.require_delete_plan_demand_v1(controller, launch, profile,
            complete.componentwise_max(self.plan.complete_demand()))
    }
}

impl SourceDeletePendingFenceV1<'_, '_, '_, '_> {
    pub(crate) fn finish_failed_outer_scope_once_v1(&mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        self.scope.finish_native_once_v1(controller, launch, profile)
    }
}

// A diagnostic borrow remains available on the same native owner after refusal.
// It cannot reenter a pending fence, admission or healthy currentness path.
impl SourceDeleteSemanticScopeV1<'_, '_> {
    pub(crate) fn pending_root_intake_failure_view_v2<'cause>(
        &'cause self,
        profile: &'cause ControllerSelfProfileOriginalV1,
    ) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>> {
        self.native.delete_intake_failure_view_v1(profile)
    }
}

impl SourceDeletePendingFenceV1<'_, '_, '_, '_> {
    pub(crate) fn metadata_graph_receiving_demand_v2(&self, controller: &Journal) -> Result<ResourceVector, JournalError> {
        self.scope.metadata_graph_receiving_demand_v2(controller)
    }

    pub(crate) fn metadata_graph_requests_v2(&self, controller: &Journal, project: aos_sandbox_core::ProjectId)
        -> Result<(aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2,
            Vec<SourceDeleteMetadataRequestDataV2>), SourceDeleteMetadataRequestErrorV2>
    {
        self.scope.metadata_graph_requests_v2(controller, project)
    }
}

impl SourceDeletePendingFenceV1<'_, '_, '_, '_> {
    pub(crate) fn dependency_graph_receiving_demand_v2(&self, controller: &Journal,
        metadata_links: usize,
    ) -> Result<ResourceVector, JournalError> {
        self.scope.dependency_graph_receiving_demand_v2(controller, metadata_links)
    }

    pub(crate) fn finish_dependency_graph_metadata_data_v2<'metadata>(&self,
        base: aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphBaseDataV2,
        controller: &Journal,
        metadata: &[aos_sandbox_ledger_replay::delete_graph::DeleteGraphMetadataDataV2<'metadata>],
    ) -> Result<DeleteDependencyGraphDataV2, SourceDeleteGraphErrorV2> {
        self.scope.finish_dependency_graph_metadata_data_v2(base, controller, metadata)
    }
}

impl SourceDeletePendingFenceV1<'_, '_, '_, '_> {
    pub(crate) fn require_prepaid_controller_admission_v3(
        &self,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        self.require_source_ready_v3()?;
        // The existing exact C17 cut validates the genuine funding union, complete
        // writer/enrollment/profile/Launch affinity and unchanged C before.
        self.controller_funding_cut_data_v3(controller, launch, profile)?;
        Ok(())
    }

    pub(crate) fn matches_cleared_create_identity_v3(
        &self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> bool {
        use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
        let DormantSandboxRequestKindV1::Delete(request) = self.plan.authorization().request().request()
        else { return false; };
        self.plan.coordinates().0 == identity.project()
            && request.sandbox_id.as_slice() == identity.sandbox().as_bytes()
    }
}

impl<'journal, 'original> SourceDeleteSemanticScopeV1<'journal, 'original> {
    /// Reborrows only the actual completed Ready successor for acceptance.
    ///
    /// The original scope and pending native64 have never left their retained
    /// owner. This entrance cannot reopen old inventory/planning loans: those
    /// remain refused once readiness started. Its caller keeps this fence live
    /// through C COMMIT readback, final clock and Source ControllerCommitted.
    pub(crate) fn borrow_ready_admission_fence_v3<'fence, 'authorization>(
        &'fence mut self,
        plan: &'fence crate::lifecycle::delete_pending::SourceDeletePendingPlanV1<'authorization>,
    ) -> Result<SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>, JournalError> {
        let original = self.pending_completion.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if plan.coordinates() != (original.project, original.operation, original.batch) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let fence = SourceDeletePendingFenceV1 { scope: self, plan };
        fence.require_source_ready_v3()?;
        Ok(fence)
    }
}

impl<'journal, 'original> SourceDeleteSemanticScopeV1<'journal, 'original> {
    pub(crate) fn borrow_controller_committed_fence_v3<'fence, 'authorization>(
        &'fence mut self,
        plan: &'fence crate::lifecycle::delete_pending::SourceDeletePendingPlanV1<'authorization>,
    ) -> Result<SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>, JournalError> {
        let original = self.pending_completion.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if plan.coordinates() != (original.project, original.operation, original.batch) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let fence = SourceDeletePendingFenceV1 { scope: self, plan };
        fence.require_source_controller_committed_v3()?;
        Ok(fence)
    }
}

impl SourceDeletePendingFenceV1<'_, '_, '_, '_> {
    pub(crate) fn controller_accepted_cut_v3<'cut>(
        &'cut self,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<(aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1, u64, u64), Box<dyn Error + Send + Sync>> {
        accepted.completed_native_v3(controller, self)?;
        let coordinator = controller.controller_coordinator_for_bank_read_v1()?;
        let funding = self.scope.native.current_delete_funding_data_v3(coordinator, launch, profile)
            .map_err(JournalError::ControllerNative)?;
        Ok((funding, controller.snapshot_sequence(), coordinator.durable_prefix_end_data_v1()))
    }
}
