//! Carries finite auxiliary readiness appends on the same native Source scope.
//!
//! All three transitions use the sole semantic/native append schedule and its
//! exact COMMIT observer. The original Planned COMMIT remains unchanged for
//! historical Root/handoff provenance; the current successor belongs to this
//! separate private state. No decoded position can install its completion.

use super::*;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use crate::public_mutation_compiler::delete_admission::PlanningClockError;

type Pair = RetainedKernelPairedClockAttemptV1<PlanningClockError>;

/// Keeps the real paid pair through each timed append frontier.
pub(crate) struct DeleteSourceFrontierClockV3 {
    native: Pair,
    sample: Option<Result<aos_sandbox_core::RawPairedClockSample, PlanningClockError>>,
    horizon: Option<Result<(), JournalError>>,
    bound: crate::normal_root::DeleteSourceClockBoundDataV3,
}

impl DeleteSourceFrontierClockV3 {
    pub(crate) fn receiving_demand_v3() -> Result<ResourceVector, JournalError> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(Pair::dominant_requested_bytes_v1()?.checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let names = Pair::receiving_metadata_cells_v1().and_then(|names| u64::try_from(names).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, Pair::MAXIMUM_RETAINED_FILES_V1 as u64)
            .with(D::MetadataEntries, names))
    }

    pub(crate) fn new(bound: crate::normal_root::DeleteSourceClockBoundDataV3) -> Self {
        Self { native: Default::default(), sample: None, horizon: None, bound }
    }

    pub(crate) fn observe_frontier_v3(&mut self) -> Result<(), JournalError> {
        if self.failure().is_some() { return Err(JournalError::ProtectedBoundary); }
        if let Some(Ok(sample)) = self.sample {
            // The canonical pair has already physically retired both positive
            // boot readers. Preserve its actual sample as the next lower bound.
            self.bound.after = sample;
            self.native = Default::default();
        }
        self.sample = Some(self.native.observe_once(None));
        self.horizon = Some((|| {
            let sample = *self.sample.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            self.bound.require_sample_v3(sample)
        })());
        if matches!(self.horizon, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn last_sample_v3(&self) -> Result<aos_sandbox_core::RawPairedClockSample, JournalError> {
        if self.failure().is_some() || !matches!(self.horizon, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.sample.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure().or_else(|| self.sample.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.horizon.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

use crate::lifecycle::delete_pending::{DeleteSourceReadinessPhaseV3, SourceDeleteReadinessPlanV3};

#[derive(Default)]
pub(super) struct SourceReadinessCurrentV3 {
    pub(super) next: u8,
    pub(super) entered: bool,
    funding_selected: [bool; 4],
    controller_join: [Option<Result<[u8; 64], Box<dyn Error + Send + Sync>>>; 2],
    native: Option<[u8; 64]>,
    transaction: Option<JournalTransaction>,
}

impl SourceReadinessCurrentV3 {
    fn require_next(&self, phase: DeleteSourceReadinessPhaseV3) -> Result<(), JournalError> {
        let expected = phase_index(phase);
        if self.entered || self.next != expected { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }
}

impl<'fence, 'journal, 'original, 'authorization>
    SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>
{
    /// Pays raw-schema/constructor backing before selecting or planning a row.
    pub(crate) fn prepare_source_readiness_plan_once_v3(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        phase: DeleteSourceReadinessPhaseV3,
        binding: &crate::normal_root::DeleteSourceBindingDataV3,
    ) -> Result<SourceDeleteReadinessPlanV3, crate::lifecycle::protected_journal::LifecycleProtectedJournalErrorV1> {
        self.reserve_source_readiness_models_v3(controller, launch, profile, phase, binding)?;
        let view = self.scope.native.semantic_read_view_v1();
        Ok(SourceDeleteReadinessPlanV3::prepare_v3(view.historical_view(), view.next_sequence(),
            controller.snapshot_sequence(), self.plan, phase, binding)?)
    }

    fn reserve_source_readiness_models_v3(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        phase: DeleteSourceReadinessPhaseV3,
        binding: &crate::normal_root::DeleteSourceBindingDataV3,
    ) -> Result<(), JournalError> {
        self.scope.readiness.require_next(phase)?;
        binding.require_pending_data_v3(self.plan)?;
        if binding.source_pending_data_v3() != self.native_position_data_v1()? {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let prefix = usize::try_from(self.scope.native.durable_end_data_v1())
            .map_err(|_| JournalError::JournalTooLarge)?;
        let view = self.scope.native.semantic_read_view_v1();
        let schema = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(view.historical_view().all_records())
            .ok_or(JournalError::JournalTooLarge)?;
        // ControllerCommitted can be reached only after four full original
        // operation/PlannedBatch COMMITs (initial, bound, Prepared and Ready).
        // Their retained physical prefix bounds the new semantic access sets:
        // one unchanged expectation plus one committed fact is smaller than
        // four old expectation encodings; the embedded state2 batch likewise
        // fits the four already retained batch members. Read-only expectations
        // remain unchanged. The same exact encoder counter prices all copies.
        let payload = crate::lifecycle::delete_pending::preparation_payload_for_operation_bound_v3(
            prefix, self.plan.batch_bytes()?.len(), prefix)?;
        let clock_bytes = Pair::dominant_requested_bytes_v1().ok_or(JournalError::JournalTooLarge)?;
        let clock_files = u64::try_from(Pair::MAXIMUM_RETAINED_FILES_V1)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let clock_names = Pair::receiving_metadata_cells_v1().and_then(|names| u64::try_from(names).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let headers = std::mem::size_of::<SourceDeleteReadinessPlanV3>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceReadinessCurrentV3>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(payload))
            .and_then(|bytes| bytes.checked_add(clock_bytes.checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let admission = self.reserve_preaccept_additional_v1(controller, launch, profile,
            schema.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, headers)
                .with(D::OpenFiles, clock_files)
                .with(D::MetadataEntries, clock_names.checked_add(2).ok_or(JournalError::JournalTooLarge)?))
                .map_err(JournalError::ReceivingAccounting)?);
        self.scope.readiness.funding_selected[usize::from(phase_index(phase))] = admission.is_err()
            && self.scope.native.delete_intake_failure_view_v1(profile).is_some();
        admission?;
        Ok(())
    }

    pub(crate) fn prepare_controller_committed_plan_once_v3(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        binding: &crate::normal_root::DeleteSourceBindingDataV3,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<SourceDeleteReadinessPlanV3, crate::lifecycle::protected_journal::LifecycleProtectedJournalErrorV1> {
        self.reserve_source_readiness_models_v3(controller, launch, profile,
            DeleteSourceReadinessPhaseV3::ControllerCommitted, binding)?;
        self.scope.readiness.controller_join[0] = Some(accepted.completed_native_v3(controller, self).copied());
        let native = self.scope.readiness.controller_join[0].as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        let view = self.scope.native.semantic_read_view_v1();
        Ok(SourceDeleteReadinessPlanV3::prepare_controller_committed_data_v3(view.historical_view(),
            view.next_sequence(), controller.snapshot_sequence(), self.plan, binding, native)?)
    }

    /// Enters the exact paid successor while retaining this original fence.
    pub(crate) fn enter_source_readiness_append_once_v3<'append>(
        &'append mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        plan: &'append SourceDeleteReadinessPlanV3,
    ) -> Result<SourceOperationSemanticAppendV1<'append, 'journal, 'original>, JournalError> {
        if plan.controller_commit_data_v3().is_some() { return Err(JournalError::ProtectedBoundary); }
        self.enter_readiness_append_inner_v3(controller, launch, profile, plan)
    }

    pub(crate) fn enter_controller_committed_append_once_v3<'append>(
        &'append mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        plan: &'append SourceDeleteReadinessPlanV3,
        accepted: &crate::journal::ControllerDeleteAdmissionOriginalV3,
    ) -> Result<SourceOperationSemanticAppendV1<'append, 'journal, 'original>, JournalError> {
        self.scope.readiness.controller_join[1] = Some(accepted.completed_native_v3(controller, self).copied());
        let native = self.scope.readiness.controller_join[1].as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if plan.phase_v3() != DeleteSourceReadinessPhaseV3::ControllerCommitted
            || plan.controller_commit_data_v3() != Some(native) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.enter_readiness_append_inner_v3(controller, launch, profile, plan)
    }

    fn enter_readiness_append_inner_v3<'append>(
        &'append mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        plan: &'append SourceDeleteReadinessPlanV3,
    ) -> Result<SourceOperationSemanticAppendV1<'append, 'journal, 'original>, JournalError> {
        self.scope.readiness.require_next(plan.phase_v3())?;
        plan.require_before_v3(self.scope.native.semantic_read_view_v1().next_sequence(),
            controller.snapshot_sequence())?;
        let admission = self.scope.reserve_exact_delete_append_v3(controller, launch, profile, plan.transaction_v3());
        self.scope.readiness.funding_selected[usize::from(phase_index(plan.phase_v3()))] = admission.is_err()
            && self.scope.native.delete_intake_failure_view_v1(profile).is_some();
        let complete = admission?;
        self.scope.readiness.entered = true;
        // Split the actual fields, not the owning Journal or writer. The shared
        // helper remains the only native/semantic construction implementation.
        let mut append = prepare_source_semantic_append_once_v1(
            SourceSemanticNativeScopeRefV1::Delete(&mut self.scope.native),
            &mut self.scope.semantic, &mut self.scope.pending_completion,
            controller, launch, profile, plan.transaction_v3(), complete,
        )?;
        append.readiness_clock = Some(DeleteSourceFrontierClockV3::new(plan.clock_bound_data_v3()));
        append.readiness_plan = Some(plan);
        append.readiness_current = Some(&mut self.scope.readiness);
        append.pending_native = Some(PendingNativeObserverV1::new(plan.transaction_v3()));
        Ok(append)
    }

    pub(crate) fn require_source_readiness_phase_complete_v3(
        &self,
        phase: DeleteSourceReadinessPhaseV3,
    ) -> Result<(), JournalError> {
        let state = &self.scope.readiness;
        if state.entered || state.next != phase_index(phase).checked_add(1).ok_or(JournalError::JournalTooLarge)?
            || state.native.is_none() || state.transaction.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Requires the intrinsic final Ready state beside the original handoff cut.
    pub(crate) fn require_source_ready_v3(&self) -> Result<(), JournalError> {
        self.require_current_readiness_phase_v3(3)
    }

    pub(crate) fn require_source_controller_committed_v3(&self) -> Result<(), JournalError> {
        self.require_current_readiness_phase_v3(4)
    }

    pub(crate) fn controller_committed_native_data_v3(&self) -> Result<&[u8;64], JournalError> {
        self.require_source_controller_committed_v3()?;
        self.scope.readiness.native.as_ref().ok_or(JournalError::ProtectedBoundary)
    }

    fn require_current_readiness_phase_v3(&self, next: u8) -> Result<(), JournalError> {
        let state = &self.scope.readiness;
        if state.entered || state.next != next || state.native.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        let view = self.scope.native.semantic_read_view_v1();
        let transaction = state.transaction.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let native = state.native.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let commit = u64::from_be_bytes(native[48..56].try_into()
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?);
        let end = u64::from_be_bytes(native[56..64].try_into()
            .map_err(|_| JournalError::StaleAuthoritySnapshot)?);
        if native[..16] != *transaction.id()
            || commit.checked_add(1) != Some(view.next_sequence())
            || end != self.scope.native.durable_end_data_v1()
            || transaction.records().iter().any(|record|
                view.state().get(&(record.namespace(), record.key().to_vec())).map(Vec::as_slice) != record.value())
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

impl SourceOperationSemanticAppendV1<'_, '_, '_> {
    /// Records progress only after actual same-client native posts and readback.
    pub(crate) fn complete_source_readiness_readback_v3(
        &mut self,
        root: &crate::normal_root::RootDeleteClientOriginalV1<'_>,
        controller: &Journal,
    ) -> Result<(), JournalError> {
        let plan = self.readiness_plan.ok_or(JournalError::ProtectedBoundary)?;
        root.require_source_readiness_after_v3(plan, controller)?;
        let latest = self.readiness_clock.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .last_sample_v3()?;
        root.require_source_readiness_post_clock_v3(latest)?;
        if self.failure().is_some() || !matches!(self.comparison, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        plan.require_saved_rows_v3(self.native.semantic_read_view_v1().state())?;
        let proof = self.pending_native.as_ref().and_then(PendingNativeObserverV1::completed)
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        let expected = phase_index(plan.phase_v3());
        let state = self.readiness_current.as_deref().ok_or(JournalError::ProtectedBoundary)?;
        if !state.entered || state.next != expected { return Err(JournalError::ProtectedBoundary); }
        // Own the already-paid exact transaction before any native disposition.
        let retained = plan.transaction_v3().clone();
        self.prepare_positive_disposal_v1()?.complete_after_disposal_v1();
        let state = self.readiness_current.as_deref_mut().ok_or(JournalError::ProtectedBoundary)?;
        state.transaction = Some(retained);
        state.native = Some(proof);
        state.next = expected.checked_add(1).ok_or(JournalError::JournalTooLarge)?;
        state.entered = false;
        Ok(())
    }
}

fn phase_index(phase: DeleteSourceReadinessPhaseV3) -> u8 {
    match phase {
        DeleteSourceReadinessPhaseV3::Binding => 0,
        DeleteSourceReadinessPhaseV3::Prepared => 1,
        DeleteSourceReadinessPhaseV3::Ready => 2,
        DeleteSourceReadinessPhaseV3::ControllerCommitted => 3,
    }
}

impl SourceDeleteSemanticScopeV1<'_, '_> {
    pub(crate) fn controller_committed_comparison_failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.readiness.controller_join.iter().find_map(|result| result.as_ref()?.as_ref().err()
            .map(|cause| cause.as_ref() as &(dyn Error + 'static)))
    }

    pub(crate) fn readiness_funding_failure_is_selected_v3(&self, index: usize) -> bool {
        self.readiness.funding_selected.get(index).copied().unwrap_or(false)
    }
}
