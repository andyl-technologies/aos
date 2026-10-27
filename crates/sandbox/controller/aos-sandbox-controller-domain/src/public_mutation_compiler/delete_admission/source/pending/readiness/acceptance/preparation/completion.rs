//! Settles the original Source anchor only after actual physical cleanup owners.
//!
//! Supplied SDK receipts are compared against the entered native originals.
//! The same Source writer stays held through both Operation-only successors;
//! every entered append runs Source and independent Root/C posts on refusal.

use super::*;
use crate::lifecycle::delete_pending::{
    DeleteSourceCompletionPhaseV4 as Phase, SourceDeleteCompletionPlanV4 as Plan,
};
use aos_sandbox_protocol::domain_ledger::delete_root::completion::{
    DeleteRootPhysicalCompletionDataV4, DeleteRootSourceCompletionDataV4,
};

#[derive(Clone, Copy)]
enum First {
    Funding,
    Physical,
    Fence,
    Root(usize),
    Controller(usize),
    Plan(usize),
    Entry(usize),
    Run(usize),
    Readback(usize),
    Frame,
    FinalFunding,
    FinalClock,
    Exchange,
    Outer,
    Reentry,
}

#[derive(Default)]
pub(in super::super) struct ControllerDeleteCompletionOriginalV4 {
    started: bool,
    physical_funding: Option<Result<(), JournalError>>,
    physical: Option<Result<DeleteRootPhysicalCompletionDataV4, Cause>>,
    fence: Option<Result<(), JournalError>>,
    plans: [Option<Result<Plan, LifecycleProtectedJournalErrorV1>>; 2],
    root_entry: [Option<Result<(), JournalError>>; 2],
    before: [Option<Result<(), JournalError>>; 2],
    controller_join: [Option<Result<[u8; 64], Cause>>; 2],
    entry: [Option<Result<(), JournalError>>; 2],
    run: [Option<Result<(), JournalError>>; 2],
    root_after: [Option<Result<(), JournalError>>; 2],
    readback: [Option<Result<(), JournalError>>; 2],
    disposal: [Option<Result<(), JournalError>>; 2],
    frame: Option<Result<DeleteRootSourceCompletionDataV4, JournalError>>,
    final_funding: Option<Result<(), JournalError>>,
    final_clock: Option<DeleteSourceFrontierClockV3>,
    final_clock_result: Option<Result<(), JournalError>>,
    exchange: Option<Result<(), JournalError>>,
    outer: Option<Result<(), JournalError>>,
    first: Option<First>,
}

impl ControllerDeleteCompletionOriginalV4 {
    pub(in super::super) fn root_failure_is_selected_v4(&self) -> bool {
        matches!(self.first, Some(First::Root(_) | First::Exchange))
            || self.final_funding_failure_is_selected_v4()
            || matches!(self.first, Some(First::Funding))
                && matches!(
                    self.physical_funding,
                    Some(Err(JournalError::ControllerNative(_)))
                )
    }

    pub(in super::super) fn funding_failure_is_selected_v4(&self) -> bool {
        matches!(
            self.first,
            Some(First::Plan(_) | First::Entry(_) | First::FinalFunding)
        )
    }

    pub(in super::super) fn final_funding_failure_is_selected_v4(&self) -> bool {
        matches!(self.first, Some(First::FinalFunding))
            && matches!(
                self.final_funding,
                Some(Err(JournalError::ControllerNative(_)))
            )
    }

    pub(in super::super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Funding => self
                .physical_funding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Physical => self
                .physical
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::Fence => self.fence.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Plan(index) => self.plans[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Entry(index) => self.entry[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Run(index) => self.run[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Readback(index) => self.readback[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Frame => self.frame.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::FinalFunding => self
                .final_funding
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::FinalClock => self
                .final_clock
                .as_ref()
                .and_then(|clock| clock.failure())
                .or_else(|| {
                    self.final_clock_result
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Exchange => self
                .exchange
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Outer => self.outer.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Controller(index) => self.controller_join[index]
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::Root(index) => self.root_entry[index]
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .or_else(|| self.before[index].as_ref()?.as_ref().err())
                .or_else(|| self.root_after[index].as_ref()?.as_ref().err())
                .or_else(|| self.disposal[index].as_ref()?.as_ref().err())
                .map(|cause| cause as _),
            First::Reentry => None,
        }
    }
}

impl ControllerDeletePendingOriginalV2<'_, '_> {
    pub(crate) fn finish_source_completion_root_once_v4(
        &mut self,
        root: &mut RootDeleteClientOriginalV1<'_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        let accepted = &mut self.readiness.acceptance;
        let state = &mut accepted.completion;
        if self.outer_after.is_some()
            || accepted.first.is_some()
            || state.first.is_some()
            || state.exchange.is_some()
            || state.final_funding.is_some()
        {
            state.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        let frame = state
            .frame
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        state.final_funding = Some((|| {
            self.source.reserve_planning_root_additional_v1(
                controller,
                launch,
                profile,
                DeleteSourceFrontierClockV3::receiving_demand_v3()?,
            )
        })());
        if !matches!(state.final_funding, Some(Ok(()))) {
            state.first = Some(First::FinalFunding);
            return Err(JournalError::ProtectedBoundary);
        }
        let bound = root.terminal_clock_bound_data_v4()?;
        state.final_clock = Some(DeleteSourceFrontierClockV3::new(bound));
        {
            let plan = self
                .plan
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let mut fence = self.source.borrow_source_completion_fence_v4(plan)?;
            state.exchange = Some(
                root.exchange_source_completion_once_v4(
                    &mut fence,
                    controller,
                    launch,
                    &accepted.controller,
                    frame,
                )
                .map_err(|_| JournalError::ProtectedBoundary),
            );
            if matches!(state.exchange, Some(Ok(()))) {
                state.exchange = Some(root.record_terminal_controller_once_v4(
                    &mut fence,
                    controller,
                    launch,
                    &accepted.controller,
                ));
            }
        }
        if !matches!(state.exchange, Some(Ok(()))) {
            state.first = Some(First::Exchange);
        }
        // The original Source/C17 afters and paired clock are independently
        // owed even when ACK, EOF, peer liveness or Root posts refused.
        self.outer_after = Some(
            self.source
                .finish_native_once_v1(controller, launch, profile),
        );
        state.outer = Some(if matches!(self.outer_after, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        });
        if !matches!(state.outer, Some(Ok(()))) {
            state.first.get_or_insert(First::Outer);
        }
        state.final_clock_result = Some(
            state
                .final_clock
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_frontier_v3(),
        );
        if !matches!(state.final_clock_result, Some(Ok(()))) {
            state.first.get_or_insert(First::FinalClock);
        }
        if state.first.is_some() {
            Err(JournalError::ProtectedBoundary)
        } else {
            Ok(())
        }
    }

    pub(crate) fn complete_source_cleanup_once_v4(
        &mut self,
        root: &mut RootDeleteClientOriginalV1<'_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        mount: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
        storage: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1),
    ) -> Result<DeleteRootSourceCompletionDataV4, JournalError> {
        let accepted = &mut self.readiness.acceptance;
        let state = &mut accepted.completion;
        if self.outer_after.is_some() || accepted.first.is_some() || state.started {
            state.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        state.started = true;
        state.physical_funding = Some((|| {
            let bytes = std::mem::size_of::<sha2::Sha256>()
                .checked_add(std::mem::size_of::<blake3::Hasher>())
                .and_then(|bytes| bytes.checked_add(544 + 416 + 192))
                .and_then(|bytes| bytes.checked_mul(3))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            self.source.reserve_planning_root_additional_v1(
                controller,
                launch,
                profile,
                ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes, bytes),
            )
        })());
        if !matches!(state.physical_funding, Some(Ok(()))) {
            state.first = Some(First::Funding);
            return Err(JournalError::ProtectedBoundary);
        }
        state.physical = Some((|| {
            if !matches!(accepted.complete, Some(Ok(())))
                || !matches!(accepted.host_confirmation_contract, Some(Ok(())))
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            for complete in [
                (
                    &accepted.network.first,
                    &accepted.network.after,
                    &accepted.network.retirement,
                    &accepted.network.complete,
                ),
                (
                    &accepted.mount.first,
                    &accepted.mount.after,
                    &accepted.mount.retirement,
                    &accepted.mount.complete,
                ),
                (
                    &accepted.apply.first,
                    &accepted.apply.after,
                    &accepted.apply.retirement,
                    &accepted.apply.complete,
                ),
            ] {
                if complete.0.is_some()
                    || !matches!(complete.1, Some(Ok(())))
                    || !matches!(complete.2, Some(Ok(())))
                    || !matches!(complete.3, Some(Ok(())))
                {
                    return Err(JournalError::ProtectedBoundary.into());
                }
            }
            root.require_completion_network_v4(
                accepted.network.io.completed_native_v3()?,
                accepted.network.io.completed_receipt_identity_data_v4()?,
            )?;
            let compare = |actual: &[u8; 64],
                           identity: ([u8; 32], [u8; 32]),
                           supplied: (&[u8; 64], &AuthenticatedBrokerMethodOutcomeV1)|
             -> Result<(), JournalError> {
                if actual != supplied.0
                    || identity
                        != (
                            supplied.1.request().signed_request_digest(),
                            *blake3::hash(supplied.1.canonical_packet()).as_bytes(),
                        )
                {
                    return Err(JournalError::StaleAuthoritySnapshot);
                }
                Ok(())
            };
            compare(
                accepted.mount.io.completed_native_v3()?,
                accepted.mount.io.completed_receipt_identity_data_v4()?,
                mount,
            )?;
            compare(
                accepted.apply.io.completed_native_v3()?,
                accepted.apply.io.completed_receipt_identity_data_v4()?,
                storage,
            )?;
            root.physical_completion_data_v4(mount, storage)
        })());
        let physical = match state
            .physical
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
        {
            Some(value) => value,
            None => {
                state.first = Some(First::Physical);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        let original = self
            .plan
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let entered = self.source.borrow_source_completion_fence_v4(original);
        let mut fence = match entered {
            Ok(fence) => {
                state.fence = Some(Ok(()));
                fence
            }
            Err(cause) => {
                state.fence = Some(Err(cause));
                state.first = Some(First::Fence);
                return Err(JournalError::ProtectedBoundary);
            }
        };
        for (index, phase) in [Phase::Reserve, Phase::Terminal].into_iter().enumerate() {
            state.root_entry[index] = Some(
                root.begin_source_completion_interval_once_v4(
                    &mut fence,
                    controller,
                    launch,
                    &accepted.controller,
                    phase,
                )
                .map_err(|_| JournalError::ProtectedBoundary),
            );
            if !matches!(state.root_entry[index], Some(Ok(()))) {
                state.first = Some(First::Root(index));
                return Err(JournalError::ProtectedBoundary);
            }
            state.before[index] = Some((|| {
                let bound = root.require_source_completion_before_v4(phase)?;
                state.controller_join[index] = Some(
                    accepted
                        .controller
                        .completed_native_v3(controller, &fence)
                        .copied(),
                );
                let native = match state.controller_join[index]
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                {
                    Some(native) => native,
                    None => {
                        state.first = Some(First::Controller(index));
                        return Err(JournalError::ProtectedBoundary);
                    }
                };
                state.plans[index] = Some(fence.prepare_source_completion_plan_once_v4(
                    controller, launch, profile, phase, physical, native, bound,
                ));
                Ok(())
            })());
            if !matches!(state.before[index], Some(Ok(()))) {
                state.first.get_or_insert(First::Root(index));
            } else if !matches!(state.plans[index], Some(Ok(_))) {
                state.first = Some(First::Plan(index));
            }
            if state.first.is_some() {
                root.refuse_source_readiness_primary_v3();
                state.root_after[index] = Some(
                    root.finish_source_readiness_interval_once_v3(controller)
                        .map_err(|_| JournalError::ProtectedBoundary),
                );
                return Err(JournalError::ProtectedBoundary);
            }
            let plan = state.plans[index]
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            {
                let entered =
                    fence.enter_source_completion_append_once_v4(controller, launch, profile, plan);
                let mut append = match entered {
                    Ok(append) => {
                        state.entry[index] = Some(Ok(()));
                        append
                    }
                    Err(cause) => {
                        state.entry[index] = Some(Err(cause));
                        state.first = Some(First::Entry(index));
                        root.refuse_source_readiness_primary_v3();
                        state.root_after[index] = Some(
                            root.finish_source_readiness_interval_once_v3(controller)
                                .map_err(|_| JournalError::ProtectedBoundary),
                        );
                        return Err(JournalError::ProtectedBoundary);
                    }
                };
                state.run[index] = Some(append.run_once_v1());
                if !matches!(state.run[index], Some(Ok(()))) {
                    state.first = Some(First::Run(index));
                    root.refuse_source_readiness_primary_v3();
                }
                state.root_after[index] = Some(
                    root.finish_source_readiness_interval_once_v3(controller)
                        .map_err(|_| JournalError::ProtectedBoundary),
                );
                if !matches!(state.root_after[index], Some(Ok(()))) {
                    state.first.get_or_insert(First::Root(index));
                }
                state.readback[index] =
                    Some(append.complete_source_completion_readback_v4(root, controller));
                if !matches!(state.readback[index], Some(Ok(()))) {
                    state.first.get_or_insert(First::Readback(index));
                }
                if state.first.is_some() {
                    self.outer_after =
                        Some(append.finish_outer_scope_once_v1(controller, launch, profile));
                    std::process::abort();
                }
            }
            state.disposal[index] = Some(
                root.retire_source_completion_interval_once_v4(&fence, controller, phase)
                    .map_err(|_| JournalError::ProtectedBoundary),
            );
            if !matches!(state.disposal[index], Some(Ok(()))) {
                state.first = Some(First::Root(index));
                return Err(JournalError::ProtectedBoundary);
            }
        }
        state.frame = Some((|| {
            let controller = *accepted
                .controller
                .completed_native_v3(controller, &fence)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            Ok(DeleteRootSourceCompletionDataV4 {
                physical,
                controller,
                source: *fence.completion_native_data_v4()?,
            })
        })());
        if !matches!(state.frame, Some(Ok(_))) {
            state.first = Some(First::Frame);
        }
        state
            .frame
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }
}

impl<'scope, 'original> ControllerDeletePendingOriginalV2<'scope, 'original> {
    pub(crate) fn prepare_terminal_positive_disposal_v4<'disposal>(
        &'disposal mut self,
        root: &RootDeleteClientOriginalV1<'_>,
        controller: &'disposal Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<crate::journal::SourceDeleteCompletionDisposalOriginalV4<'disposal>, JournalError>
    {
        let state = &self.readiness.acceptance.completion;
        if self.failure().is_some()
            || state.first.is_some()
            || !matches!(state.exchange, Some(Ok(())))
            || !matches!(self.outer_after, Some(Ok(())))
            || !matches!(state.final_clock_result, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let plan = self
            .plan
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let token = self
            .source
            .prepare_completion_positive_disposal_v4(controller, launch, profile, plan, root)?;
        // The genuine native token is prepared before any successful upper
        // owner is retired. All fallible checks are finished at this point.
        self.readiness = Default::default();
        drop(self.plan.take());
        Ok(token)
    }
}
