//! Carries final Operation successors on the original held Source writer.
//!
//! The accepted Batch2 frontier stays historical after the first successor.
//! A separate private frontier is installed only by actual native COMMIT,
//! complete readback, Source posts, Root/C posts and positive append disposal.

use super::*;
use crate::lifecycle::delete_pending::{
    DeleteSourceCompletionPhaseV4 as Phase, SourceDeleteCompletionPlanV4 as Plan,
};
use aos_sandbox_protocol::domain_ledger::delete_root::completion::DeleteRootPhysicalCompletionDataV4;

#[derive(Default)]
pub(super) struct SourceCompletionCurrentV4 {
    next: usize,
    entered: bool,
    funding: [Option<Result<(), JournalError>>; 2],
    append_funding: [Option<Result<ResourceVector, JournalError>>; 2],
    transaction: Option<JournalTransaction>,
    native: Option<[u8; 64]>,
    physical: Option<[u8; 32]>,
}

impl SourceCompletionCurrentV4 {
    fn require_next(&self, phase: Phase) -> Result<(), JournalError> {
        if self.entered || self.next != phase.index_v4() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl<'journal, 'original> SourceDeleteSemanticScopeV1<'journal, 'original> {
    pub(crate) fn prepare_completion_positive_disposal_v4<'disposal>(
        &'disposal mut self,
        controller: &'disposal Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        plan: &crate::lifecycle::delete_pending::SourceDeletePendingPlanV1<'_>,
        root: &crate::normal_root::RootDeleteClientOriginalV1<'_>,
    ) -> Result<SourceDeleteCompletionDisposalOriginalV4<'disposal>, JournalError> {
        if !self.pending_prepare_entered
            || self.completion_failure_v4().is_some()
            || self.failure().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        {
            let fence = self.borrow_source_completion_fence_v4(plan)?;
            // The genuine Root owns this actual C append/readback and its
            // completed native turn. A passive frame or obsolete cache flag
            // cannot satisfy this final same-Source/current-C conjunction.
            let source = fence.completion_native_data_v4()?;
            let terminal = root.borrow_terminal_controller_completed_v4(controller, source)?;
            terminal.require_current_readback_v4(controller, source)?;
        }
        let native = self
            .native
            .prepare_positive_disposal_v1(
                controller.controller_coordinator_for_bank_read_v1()?,
                launch,
                profile,
            )
            .map_err(JournalError::ControllerNative)?;
        Ok(SourceDeleteCompletionDisposalOriginalV4 {
            native,
            completion: &mut self.completion,
            readiness: &mut self.readiness,
            pending: &mut self.pending_completion,
        })
    }

    pub(crate) fn borrow_source_completion_fence_v4<'fence, 'authorization>(
        &'fence mut self,
        plan: &'fence crate::lifecycle::delete_pending::SourceDeletePendingPlanV1<'authorization>,
    ) -> Result<SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>, JournalError>
    {
        let fence = SourceDeletePendingFenceV1 { scope: self, plan };
        if fence.scope.completion.next == 0 {
            fence.require_source_controller_committed_v3()?;
        } else {
            fence.require_source_completion_current_v4()?;
        }
        Ok(fence)
    }

    pub(crate) fn completion_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.completion
            .funding
            .iter()
            .find_map(|slot| slot.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.completion
                    .append_funding
                    .iter()
                    .find_map(|slot| slot.as_ref()?.as_ref().err().map(|cause| cause as _))
            })
    }
}

/// Keeps the sole final native disposition while successful upper models retire.
pub(crate) struct SourceDeleteCompletionDisposalOriginalV4<'disposal> {
    native: aos_sandbox_broker::source_receiving::SourceDeleteScopeDisposalV1<'disposal, Selection>,
    completion: &'disposal mut SourceCompletionCurrentV4,
    readiness: &'disposal mut readiness::SourceReadinessCurrentV3,
    pending: &'disposal mut Option<PendingSourceCompletionV1>,
}

impl SourceDeleteCompletionDisposalOriginalV4<'_> {
    pub(crate) fn complete_after_upper_disposal_v4(self) {
        // These are successful comparison caches. Every failure path retains
        // them, and the native token still owns the unchanged financial debt.
        *self.completion = Default::default();
        *self.readiness = Default::default();
        drop(self.pending.take());
        self.native.complete_after_disposal_v1();
    }
}

impl<'fence, 'journal, 'original, 'authorization>
    SourceDeletePendingFenceV1<'fence, 'journal, 'original, 'authorization>
{
    pub(crate) fn prepare_source_completion_plan_once_v4(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        phase: Phase,
        physical: DeleteRootPhysicalCompletionDataV4,
        accepted_controller: &[u8; 64],
        bound: crate::normal_root::DeleteSourceClockBoundDataV3,
    ) -> Result<Plan, crate::lifecycle::protected_journal::LifecycleProtectedJournalErrorV1> {
        self.scope.completion.require_next(phase)?;
        if phase == Phase::Reserve {
            self.require_source_controller_committed_v3()?;
        } else {
            self.require_source_completion_current_v4()?;
        }
        let commitment = physical
            .commitment_v4()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if phase == Phase::Terminal && self.scope.completion.physical != Some(commitment) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let prefix = usize::try_from(self.scope.native.durable_end_data_v1())
            .map_err(|_| JournalError::JournalTooLarge)?;
        let view = self.scope.native.semantic_read_view_v1();
        let schema = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(
            view.historical_view().all_records(),
        )
        .ok_or(JournalError::JournalTooLarge)?;
        // The canonical Operation format reserves every attempt slot at fixed
        // width. Filling the one original anchor changes no encoded width.
        // Price the actual retained prefix and canonical model counter before
        // decoding, cloning or planning the successor.
        let payload = crate::lifecycle::delete_pending::preparation_payload_for_operation_bound_v3(
            prefix,
            self.plan.batch_bytes()?.len(),
            prefix,
        )?;
        let headers = std::mem::size_of::<Plan>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<SourceCompletionCurrentV4>().checked_mul(3)?)
            })
            .and_then(|bytes| bytes.checked_add(payload))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let clock = DeleteSourceFrontierClockV3::receiving_demand_v3()?;
        let demand = schema
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, headers))
            .and_then(|demand| demand.checked_add(clock))
            .map_err(JournalError::ReceivingAccounting)?;
        let index = phase.index_v4();
        if self.scope.completion.funding[index].is_some() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.scope.completion.funding[index] =
            Some(self.reserve_preaccept_additional_v1(controller, launch, profile, demand));
        if !matches!(self.scope.completion.funding[index], Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let view = self.scope.native.semantic_read_view_v1();
        Plan::prepare_v4(
            view.historical_view(),
            view.next_sequence(),
            controller.snapshot_sequence(),
            self.plan,
            phase,
            physical,
            accepted_controller,
            bound,
        )
    }

    pub(crate) fn enter_source_completion_append_once_v4<'append>(
        &'append mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        plan: &'append Plan,
    ) -> Result<SourceOperationSemanticAppendV1<'append, 'journal, 'original>, JournalError> {
        self.scope.completion.require_next(plan.phase_v4())?;
        if plan.phase_v4() == Phase::Reserve {
            self.require_source_controller_committed_v3()?;
        } else {
            self.require_source_completion_current_v4()?;
        }
        plan.require_before_v4(
            self.scope.native.semantic_read_view_v1().next_sequence(),
            controller.snapshot_sequence(),
        )?;
        let index = plan.phase_v4().index_v4();
        if self.scope.completion.append_funding[index].is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.scope.completion.append_funding[index] =
            Some(self.scope.reserve_exact_delete_append_v3(
                controller,
                launch,
                profile,
                plan.transaction_v4(),
            ));
        let complete = self.scope.completion.append_funding[index]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.scope.completion.entered = true;
        let mut append = prepare_source_semantic_append_once_v1(
            SourceSemanticNativeScopeRefV1::Delete(&mut self.scope.native),
            &mut self.scope.semantic,
            &mut self.scope.pending_completion,
            controller,
            launch,
            profile,
            plan.transaction_v4(),
            complete,
        )?;
        append.readiness_clock = Some(DeleteSourceFrontierClockV3::new(plan.clock_bound_v4()));
        append.completion_plan = Some(plan);
        append.completion_current = Some(&mut self.scope.completion);
        append.pending_native = Some(PendingNativeObserverV1::new(plan.transaction_v4()));
        Ok(append)
    }

    pub(crate) fn require_source_completion_current_v4(&self) -> Result<(), JournalError> {
        let state = &self.scope.completion;
        if state.entered || !(1..=2).contains(&state.next) {
            return Err(JournalError::ProtectedBoundary);
        }
        let transaction = state
            .transaction
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let native = state
            .native
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let sequence = u64::from_be_bytes(
            native[48..56]
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?,
        );
        let end = u64::from_be_bytes(
            native[56..64]
                .try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?,
        );
        let view = self.scope.native.semantic_read_view_v1();
        if native[..16] != *transaction.id()
            || sequence.checked_add(1) != Some(view.next_sequence())
            || end != self.scope.native.durable_end_data_v1()
            || transaction.records().iter().any(|record| {
                view.state()
                    .get(&(record.namespace(), record.key().to_vec()))
                    .map(Vec::as_slice)
                    != record.value()
            })
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(crate) fn require_source_completion_phase_v4(
        &self,
        phase: Phase,
    ) -> Result<(), JournalError> {
        self.require_source_completion_current_v4()?;
        if self.scope.completion.next != phase.index_v4() + 1 {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn completion_native_data_v4(&self) -> Result<&[u8; 64], JournalError> {
        self.require_source_completion_phase_v4(Phase::Terminal)?;
        self.scope
            .completion
            .native
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)
    }
}

impl SourceOperationSemanticAppendV1<'_, '_, '_> {
    pub(crate) fn complete_source_completion_readback_v4(
        &mut self,
        root: &crate::normal_root::RootDeleteClientOriginalV1<'_>,
        controller: &Journal,
    ) -> Result<(), JournalError> {
        let plan = self
            .completion_plan
            .ok_or(JournalError::ProtectedBoundary)?;
        root.require_source_completion_after_v4(plan, controller)?;
        let latest = self
            .readiness_clock
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .last_sample_v3()?;
        root.require_source_readiness_post_clock_v3(latest)?;
        if self.failure().is_some() || !matches!(self.comparison, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        plan.require_saved_v4(self.native.semantic_read_view_v1().state())?;
        let proof = self
            .pending_native
            .as_ref()
            .and_then(PendingNativeObserverV1::completed)
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let state = self
            .completion_current
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if !state.entered || state.next != plan.phase_v4().index_v4() {
            return Err(JournalError::ProtectedBoundary);
        }
        let retained = plan.transaction_v4().clone();
        self.prepare_positive_disposal_v1()?
            .complete_after_disposal_v1();
        let state = self
            .completion_current
            .as_deref_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        state.transaction = Some(retained);
        state.native = Some(proof);
        state.physical = Some(plan.physical_v4());
        state.next += 1;
        state.entered = false;
        Ok(())
    }
}
