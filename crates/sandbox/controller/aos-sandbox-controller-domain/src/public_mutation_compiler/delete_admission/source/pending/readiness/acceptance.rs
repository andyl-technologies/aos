//! Accepts desired Delete state on the retained Source/C17/Root originals.
//!
//! The Controller COMMIT and state2 Source batch describe accepted cleanup
//! debt. Both originals remain occupied for the later physical effects.

use super::*;
mod preparation;
pub use preparation::{OriginalDeleteStoragePreparationLoanV3, OriginalDeleteStorageApplyLoanV3, OriginalDeleteNetworkApplyLoanV4};
pub use preparation::OriginalDeleteMountReapLoanV4;

#[derive(Clone, Copy)]
enum AcceptanceFirst {
    Fence,
    Controller,
    Root,
    Plan,
    Entry,
    Run,
    Readback,
    Complete,
    Reentry,
}

#[derive(Default)]
pub(super) struct ControllerDeleteAcceptanceOriginalV3 {
    started: bool,
    preparation: preparation::ControllerDeletePreparationOriginalV3,
    apply: preparation::ControllerDeleteApplyOriginalV3,
    network: preparation::ControllerDeleteNetworkOriginalV4,
    mount: preparation::ControllerDeleteMountOriginalV4,
    completion: preparation::ControllerDeleteCompletionOriginalV4,
    host_confirmation_contract: Option<Result<(), Box<dyn Error + Send + Sync>>>,
    fence: Option<Result<(), JournalError>>,
    controller: crate::journal::ControllerDeleteAdmissionOriginalV3,
    controller_result: Option<Result<(), JournalError>>,
    controller_disposal: Option<Result<(), JournalError>>,
    root_entry: Option<Result<(), JournalError>>,
    before: Option<Result<(), JournalError>>,
    plan: Option<Result<SourceDeleteReadinessPlanV3, LifecycleProtectedJournalErrorV1>>,
    entry: Option<Result<(), JournalError>>,
    run: Option<Result<(), JournalError>>,
    root_after: Option<Result<(), JournalError>>,
    readback: Option<Result<(), JournalError>>,
    disposal: Option<Result<(), JournalError>>,
    complete: Option<Result<(), JournalError>>,
    first: Option<AcceptanceFirst>,
}

impl ControllerDeleteAcceptanceOriginalV3 {
    pub(super) fn completion_funding_failure_is_selected_v4(&self) -> bool {
        self.completion.funding_failure_is_selected_v4()
    }

    pub(super) fn completion_final_funding_failure_is_selected_v4(&self) -> bool {
        self.first.is_none() && self.completion.final_funding_failure_is_selected_v4()
    }

    pub(super) fn comparison_failure_is_selected(&self) -> bool {
        matches!(
            self.first,
            Some(AcceptanceFirst::Plan | AcceptanceFirst::Entry)
        )
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.first.is_none() {
            return self.preparation.failure().or_else(|| self.network.failure())
                .or_else(|| self.host_confirmation_contract.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _))
                .or_else(|| self.mount.failure())
                .or_else(|| self.apply.failure())
                .or_else(|| self.completion.failure());
        }
        match self.first? {
            AcceptanceFirst::Fence => self.fence.as_ref()?.as_ref().err().map(|cause| cause as _),
            AcceptanceFirst::Controller => self.controller.failure(),
            AcceptanceFirst::Plan => self.plan.as_ref()?.as_ref().err().map(|cause| cause as _),
            AcceptanceFirst::Entry => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            AcceptanceFirst::Run => self.run.as_ref()?.as_ref().err().map(|cause| cause as _),
            AcceptanceFirst::Readback => self
                .readback
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            AcceptanceFirst::Complete => self
                .complete
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            AcceptanceFirst::Root | AcceptanceFirst::Reentry => None,
        }
    }

    pub(super) fn root_failure_is_selected(&self) -> bool {
        matches!(self.first, Some(AcceptanceFirst::Root))
            || self.first.is_none() && self.completion.root_failure_is_selected_v4()
            || (matches!(self.first, Some(AcceptanceFirst::Controller))
                && self.controller.root_failure_is_selected_v3())
    }

    pub(super) fn funding_failure_is_selected(
        &self,
        source: &SourceDeleteSemanticScopeV1<'_, '_>,
    ) -> bool {
        match self.first {
            Some(AcceptanceFirst::Controller) => self.controller.funding_failure_is_selected_v3(),
            Some(AcceptanceFirst::Plan | AcceptanceFirst::Entry) => {
                source.readiness_funding_failure_is_selected_v3(3)
            }
            _ => false,
        }
    }
}

impl ControllerDeletePendingOriginalV2<'_, '_> {
    pub(crate) fn accept_controller_once_v3(
        &mut self,
        root: &mut RootDeleteClientOriginalV1<'_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        let readiness = &mut self.readiness;
        let state = &mut readiness.acceptance;
        if !readiness.complete
            || readiness.first.is_some()
            || self.outer_after.is_some()
            || state.started
        {
            state.first.get_or_insert(AcceptanceFirst::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        state.started = true;
        let original = self
            .plan
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        // This is the same private Scope and Source writer. The fence remains
        // borrowed through C COMMIT, full readback and Source state2 COMMIT.
        let entered = self.source.borrow_ready_admission_fence_v3(original);
        let mut fence = match entered {
            Ok(fence) => {
                state.fence = Some(Ok(()));
                fence
            }
            Err(cause) => {
                state.fence = Some(Err(cause));
                state.first = Some(AcceptanceFirst::Fence);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        state.controller_result = Some(
            state
                .controller
                .record_once_v3(controller, &mut fence, root, launch, profile),
        );
        if !matches!(state.controller_result, Some(Ok(()))) {
            state.first = Some(AcceptanceFirst::Controller);
            return Err(JournalError::ProtectedBoundary);
        }
        state.controller_disposal = Some(
            root.retire_controller_admission_interval_once_v3(
                &fence,
                controller,
                &state.controller,
            )
            .map_err(|_| JournalError::ProtectedBoundary),
        );
        if !matches!(state.controller_disposal, Some(Ok(()))) {
            state.first = Some(AcceptanceFirst::Root);
            return Err(JournalError::ProtectedBoundary);
        }
        state.root_entry = Some(
            root.begin_source_controller_committed_interval_once_v3(
                &mut fence,
                controller,
                launch,
                &state.controller,
            )
            .map_err(|_| JournalError::ProtectedBoundary),
        );
        if !matches!(state.root_entry, Some(Ok(()))) {
            state.first = Some(AcceptanceFirst::Root);
            return Err(JournalError::ProtectedBoundary);
        }
        let phase = DeleteSourceReadinessPhaseV3::ControllerCommitted;
        state.before = Some(
            root.require_source_readiness_before_v3(phase)
                .map_err(|_| JournalError::ProtectedBoundary),
        );
        if matches!(state.before, Some(Ok(()))) {
            state.plan = Some(match root.source_binding_data_v3() {
                Ok(binding) => fence.prepare_controller_committed_plan_once_v3(
                    controller,
                    launch,
                    profile,
                    binding,
                    &state.controller,
                ),
                Err(_) => Err(JournalError::ProtectedBoundary.into()),
            });
            if !matches!(state.plan, Some(Ok(_))) {
                state.first = Some(AcceptanceFirst::Plan);
            }
        } else {
            state.first = Some(AcceptanceFirst::Root);
        }
        if state.first.is_some() {
            root.refuse_source_readiness_primary_v3();
            state.root_after = Some(
                root.finish_source_readiness_interval_once_v3(controller)
                    .map_err(|_| JournalError::ProtectedBoundary),
            );
            return Err(JournalError::ProtectedBoundary);
        }
        let next = state
            .plan
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        {
            let entered = fence.enter_controller_committed_append_once_v3(
                controller,
                launch,
                profile,
                next,
                &state.controller,
            );
            let mut append = match entered {
                Ok(append) => {
                    state.entry = Some(Ok(()));
                    append
                }
                Err(cause) => {
                    state.entry = Some(Err(cause));
                    state.first = Some(AcceptanceFirst::Entry);
                    root.refuse_source_readiness_primary_v3();
                    state.root_after = Some(
                        root.finish_source_readiness_interval_once_v3(controller)
                            .map_err(|_| JournalError::ProtectedBoundary),
                    );
                    return Err(JournalError::ProtectedBoundary);
                }
            };
            state.run = Some(append.run_once_v1());
            if !matches!(state.run, Some(Ok(()))) {
                state.first = Some(AcceptanceFirst::Run);
                root.refuse_source_readiness_primary_v3();
            }
            // Both afters remain owed before unresolved Source abandonment.
            state.root_after = Some(
                root.finish_source_readiness_interval_once_v3(controller)
                    .map_err(|_| JournalError::ProtectedBoundary),
            );
            if !matches!(state.root_after, Some(Ok(()))) {
                state.first.get_or_insert(AcceptanceFirst::Root);
            }
            if state.first.is_none() {
                state.readback =
                    Some(append.complete_source_readiness_readback_v3(root, controller));
                if !matches!(state.readback, Some(Ok(()))) {
                    state.first = Some(AcceptanceFirst::Readback);
                }
            }
            if state.first.is_some() {
                self.outer_after =
                    Some(append.finish_outer_scope_once_v1(controller, launch, profile));
                std::process::abort();
            }
            drop(append);
        }
        state.disposal = Some(
            root.retire_source_readiness_interval_once_v3(&fence, controller, phase)
                .map_err(|_| JournalError::ProtectedBoundary),
        );
        if !matches!(state.disposal, Some(Ok(()))) {
            state.first = Some(AcceptanceFirst::Root);
            return Err(JournalError::ProtectedBoundary);
        }
        state.complete = Some(fence.require_source_controller_committed_v3());
        if !matches!(state.complete, Some(Ok(()))) {
            state.first = Some(AcceptanceFirst::Complete);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}
