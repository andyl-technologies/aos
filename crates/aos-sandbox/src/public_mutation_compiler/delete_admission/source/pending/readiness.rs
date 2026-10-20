//! Retains the finite Source readiness chain on the actual pending original.
//!
//! Root/C bookends and the sole Source append run independently. A failed
//! entered Source append retains the inherited unresolved-owner abort law,
//! after every already-owed Root/C/Source post has been attempted.

mod acceptance;
pub use acceptance::{OriginalDeleteStoragePreparationLoanV3, OriginalDeleteStorageApplyLoanV3, OriginalDeleteNetworkApplyLoanV4, OriginalDeleteMountReapLoanV4};

use super::*;
use crate::lifecycle::delete_pending::{DeleteSourceReadinessPhaseV3, SourceDeleteReadinessPlanV3};
use crate::normal_root::RootDeleteClientOriginalV1;

#[derive(Clone, Copy)]
enum First { Fence, Root, Plan(usize), Entry(usize), Run(usize), Readback(usize), Reentry }

/// Owns all reached pure models and native/semantic outcomes beside Source.
#[derive(Default)]
pub(super) struct ControllerDeleteSourceReadinessOriginalV3 {
    pub(super) started: bool,
    fence: Option<Result<(), JournalError>>,
    prepared: Option<Result<(), JournalError>>,
    plans: [Option<Result<SourceDeleteReadinessPlanV3, LifecycleProtectedJournalErrorV1>>; 3],
    root_entry: [Option<Result<(), JournalError>>; 3],
    before: [Option<Result<(), JournalError>>; 3],
    source_entry: [Option<Result<(), JournalError>>; 3],
    run: [Option<Result<(), JournalError>>; 3],
    root_after: [Option<Result<(), JournalError>>; 3],
    readback: [Option<Result<(), JournalError>>; 3],
    disposal: [Option<Result<(), JournalError>>; 3],
    complete: bool,
    acceptance: acceptance::ControllerDeleteAcceptanceOriginalV3,
    first: Option<First>,
}

impl ControllerDeleteSourceReadinessOriginalV3 {
    pub(super) fn selected_failure_v3<'cause>(&'cause self, source: &'cause SourceDeleteSemanticScopeV1<'_, '_>)
        -> Option<&'cause (dyn Error + 'static)> {
        if self.first.is_none() && self.acceptance.completion_funding_failure_is_selected_v4() {
            return source.completion_failure_v4().or_else(|| self.failure());
        }
        if self.first.is_none() && self.acceptance.comparison_failure_is_selected() {
            return source.controller_committed_comparison_failure_v3().or_else(|| self.failure());
        }
        self.failure()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.first.is_none() { return self.acceptance.failure(); }
        match self.first? {
            First::Fence => self.fence.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Root => self.prepared.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Plan(index) => self.plans[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Entry(index) => self.source_entry[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Run(index) => self.run[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Readback(index) => self.readback[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Reentry => None,
        }
    }
}

impl ControllerDeletePendingOriginalV2<'_, '_> {
    pub(crate) fn source_readiness_funding_failure_is_selected_v3(&self) -> bool {
        if self.readiness.first.is_none() {
            return self.readiness.acceptance.funding_failure_is_selected(&self.source)
                || self.readiness.acceptance.completion_final_funding_failure_is_selected_v4()
                || self.readiness.acceptance.completion_funding_failure_is_selected_v4()
                    && self.source.completion_failure_v4().is_some();
        }
        match self.readiness.first {
            Some(First::Plan(index) | First::Entry(index)) => self.source.readiness_funding_failure_is_selected_v3(index),
            _ => false,
        }
    }

    /// Reports the selected diagnostic owner, without granting a native phase.
    #[doc(hidden)]
    #[must_use]
    pub fn source_readiness_root_failure_is_selected_v3(&self) -> bool {
        self.readiness.acceptance.root_failure_is_selected()
            || matches!(self.readiness.first, Some(First::Root))
            || self.source_readiness_funding_failure_is_selected_v3()
    }

    pub(crate) fn prepare_source_readiness_once_v3(
        &mut self,
        root: &mut RootDeleteClientOriginalV1<'_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        if !self.complete || self.outer_after.is_some() || self.readiness.started {
            self.readiness.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.readiness.started = true;
        let state = &mut self.readiness;
        let plan = self.plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        // One original fence spans all three real Source successors. No new
        // old-purpose borrower can be issued after this attempt has started.
        let entered = self.source.borrow_pending_fence_v1(plan);
        if entered.is_err() {
            state.fence = Some(Err(match entered.err() {
                Some(cause) => cause,
                None => std::process::abort(),
            }));
            state.first = Some(First::Fence);
            return Err(JournalError::ProtectedBoundary);
        }
        let mut fence = match entered {
            Ok(fence) => { state.fence = Some(Ok(())); fence }
            Err(_) => std::process::abort(),
        };
        state.prepared = Some(root.prepare_source_admission_once_v3(&mut fence, controller, launch)
            .map_err(|_| JournalError::ProtectedBoundary));
        if !matches!(state.prepared, Some(Ok(()))) {
            state.first = Some(First::Root);
            return Err(JournalError::ProtectedBoundary);
        }
        for (index, phase) in [DeleteSourceReadinessPhaseV3::Binding,
            DeleteSourceReadinessPhaseV3::Prepared, DeleteSourceReadinessPhaseV3::Ready].into_iter().enumerate()
        {
            state.root_entry[index] = Some(root.begin_source_readiness_interval_once_v3(
                &mut fence, controller, launch, phase).map_err(|_| JournalError::ProtectedBoundary));
            if !matches!(state.root_entry[index], Some(Ok(()))) {
                state.first = Some(First::Root);
                return Err(JournalError::ProtectedBoundary);
            }
            state.before[index] = Some(root.require_source_readiness_before_v3(phase)
                .map_err(|_| JournalError::ProtectedBoundary));
            if matches!(state.before[index], Some(Ok(()))) {
                state.plans[index] = Some(match root.source_binding_data_v3() {
                    Ok(binding) => fence.prepare_source_readiness_plan_once_v3(
                        controller, launch, profile, phase, binding),
                    Err(_) => Err(JournalError::ProtectedBoundary.into()),
                });
                if !matches!(state.plans[index], Some(Ok(_))) {
                    state.first = Some(First::Plan(index));
                }
            } else {
                state.first = Some(First::Root);
            }
            if state.first.is_some() {
                root.refuse_source_readiness_primary_v3();
                state.root_after[index] = Some(root.finish_source_readiness_interval_once_v3(controller)
                    .map_err(|_| JournalError::ProtectedBoundary));
                return Err(JournalError::ProtectedBoundary);
            }
            let next = match state.plans[index].as_ref().and_then(|result| result.as_ref().ok()) {
                Some(next) => next,
                None => {
                    state.first = Some(First::Plan(index));
                    root.refuse_source_readiness_primary_v3();
                    state.root_after[index] = Some(root.finish_source_readiness_interval_once_v3(controller)
                        .map_err(|_| JournalError::ProtectedBoundary));
                    return Err(JournalError::ProtectedBoundary);
                }
            };
            // End both the borrowed entry Result and the actual append loan
            // before reborrowing this same fence for positive Root disposal.
            {
                let entered = fence.enter_source_readiness_append_once_v3(controller, launch, profile, next);
                if entered.is_err() {
                    state.source_entry[index] = Some(Err(match entered.err() {
                        Some(cause) => cause,
                        None => std::process::abort(),
                    }));
                    state.first = Some(First::Entry(index));
                    root.refuse_source_readiness_primary_v3();
                    state.root_after[index] = Some(root.finish_source_readiness_interval_once_v3(controller)
                        .map_err(|_| JournalError::ProtectedBoundary));
                    return Err(JournalError::ProtectedBoundary);
                }
                let mut append = match entered {
                    Ok(append) => { state.source_entry[index] = Some(Ok(())); append }
                    Err(_) => std::process::abort(),
                };
                state.run[index] = Some(append.run_once_v1());
                if !matches!(state.run[index], Some(Ok(()))) {
                    state.first = Some(First::Run(index));
                    root.refuse_source_readiness_primary_v3();
                }
                // Always precedes any inherited unresolved Source abandonment.
                state.root_after[index] = Some(root.finish_source_readiness_interval_once_v3(controller)
                    .map_err(|_| JournalError::ProtectedBoundary));
                if !matches!(state.root_after[index], Some(Ok(()))) {
                    state.first.get_or_insert(First::Root);
                }
                if state.first.is_none() {
                    state.readback[index] = Some(append.complete_source_readiness_readback_v3(root, controller));
                    if !matches!(state.readback[index], Some(Ok(()))) {
                        state.first = Some(First::Readback(index));
                    }
                }
                if state.first.is_some() {
                    self.outer_after = Some(append.finish_outer_scope_once_v1(controller, launch, profile));
                    std::process::abort();
                }
                drop(append);
            }
            state.disposal[index] = Some(root.retire_source_readiness_interval_once_v3(
                &fence, controller, phase).map_err(|_| JournalError::ProtectedBoundary));
            if !matches!(state.disposal[index], Some(Ok(()))) {
                state.first = Some(First::Root);
                return Err(JournalError::ProtectedBoundary);
            }
        }
        fence.require_source_ready_v3()?;
        state.complete = true;
        Ok(())
    }
}
