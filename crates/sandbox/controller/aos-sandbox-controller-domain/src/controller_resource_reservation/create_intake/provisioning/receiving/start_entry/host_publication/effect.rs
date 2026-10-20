//! Retains private Host Applying before send and Applied/Succeeded after fresh3.
//!
//! Both mutations use the same canonical Core row writer under closed IO2
//! scopes. Native Session terminal identities authorize the second transition;
//! an authenticated outcome alone cannot complete the private child.

use super::*;
use crate::normal_root::RootStartResourceCurrentTurnV2;
use crate::reconciler::start_admission::{StartAdmissionScopeV1, StartHostCoreScopePhaseV2 as Phase};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

#[derive(Default)]
struct EffectPhaseOriginalV2 {
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    context: Option<Result<(), ResourceReservationErrorV1>>,
    scope: Option<Result<(), ResourceReservationErrorV1>>,
    core: Option<Result<(), crate::ReconcilerError>>,
    turn: Option<u64>,
    selected: bool,
}

impl EffectPhaseOriginalV2 {
    fn failure_v2(&self) -> Option<(&(dyn Error + 'static), bool)> {
        if let Some(cause) = self.geometry.as_ref().and_then(|returned| returned.as_ref().err()) {
            return Some((cause, false));
        }
        for returned in [&self.funding, &self.context, &self.scope] {
            if let Some(cause) = returned.as_ref().and_then(|returned| returned.as_ref().err()) {
                return Some((cause, self.selected));
            }
        }
        self.core.as_ref().and_then(|returned| returned.as_ref().err())
            .map(|cause| (cause as &(dyn Error + 'static), self.selected))
    }
}

#[derive(Default)]
pub(super) struct StartHostEffectOriginalV2 {
    applying: EffectPhaseOriginalV2,
    applied: EffectPhaseOriginalV2,
    dispatch: Option<Result<crate::PreparedAuthorityEffectV1, Cause>>,
    dispatch_taken: bool,
    native_terminal: Option<Result<(), ResourceReservationErrorV1>>,
    receipt: Option<Result<Option<crate::ValidatedAuthorityEffectReceiptV1>, crate::ReconcilerError>>,
    receipt_taken: bool,
}

impl StartHostEffectOriginalV2 {
    pub(super) fn new() -> Self { Self::default() }

    fn phase_v2(&self, complete: bool) -> &EffectPhaseOriginalV2 {
        if complete { &self.applied } else { &self.applying }
    }

    fn phase_mut_v2(&mut self, complete: bool) -> &mut EffectPhaseOriginalV2 {
        if complete { &mut self.applied } else { &mut self.applying }
    }
}

impl StartHostPublicationActionOriginalV2 {
    pub(crate) fn effect_body_failure_v2(&self) -> Option<(&(dyn Error + 'static), bool)> {
        let original = &self.effect_original;
        original.applying.failure_v2()
            .or_else(|| original.dispatch.as_ref().and_then(|returned| returned.as_ref().err())
                .map(|cause| (cause.as_ref() as &(dyn Error + 'static), false)))
            .or_else(|| original.applied.failure_v2())
            .or_else(|| original.native_terminal.as_ref().and_then(|returned| returned.as_ref().err())
                .map(|cause| (cause as &(dyn Error + 'static), false)))
            .or_else(|| original.receipt.as_ref().and_then(|returned| returned.as_ref().err())
                .map(|cause| (cause as &(dyn Error + 'static), false)))
    }
}

impl StartNativeStateV1 {
    pub(crate) fn require_host_effect_scope_v2(&self, controller: &Journal,
        expected: &Arc<StartHostPublicationContractV2>, phase: Phase,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_active_host_publication_v2(controller, expected)?;
        let action = self.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = phase == Phase::Applied;
        let original = &action.effect_original;
        let entered = original.phase_v2(complete);
        let receipt_ready = match original.receipt.as_ref() {
            Some(Ok(Some(_))) => !original.receipt_taken,
            Some(Ok(None)) => original.receipt_taken,
            _ => false,
        };
        if !matches!(phase, Phase::Applying | Phase::Applied)
            || entered.turn != Some(self.native_turn)
            || !matches!(entered.geometry, Some(Ok(_)))
            || !matches!(entered.funding, Some(Ok(())))
            || !matches!(entered.context, Some(Ok(())))
            || entered.core.is_some()
            || !matches!(original.dispatch, Some(Ok(_)))
            || (complete && (!matches!(original.applying.core, Some(Ok(())))
                || !matches!(original.native_terminal, Some(Ok(())))
                || !receipt_ready))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn take_host_effect_inputs_v2(&mut self,
        expected: &Arc<StartHostPublicationContractV2>, complete: bool,
    ) -> Result<(crate::PreparedAuthorityEffectV1, Option<crate::ValidatedAuthorityEffectReceiptV1>), ResourceReservationErrorV1> {
        let action = self.host_publication_action.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !Arc::ptr_eq(expected, &action.contract) { return Err(ResourceReservationErrorV1::Conflict); }
        let original = &mut action.effect_original;
        let dispatch = original.dispatch.as_ref().and_then(|returned| returned.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.clone();
        if complete {
            if original.receipt_taken { return Err(ResourceReservationErrorV1::Conflict); }
            let receipt = original.receipt.as_mut().and_then(|returned| returned.as_mut().ok())
                .and_then(Option::take).ok_or(ResourceReservationErrorV1::Conflict)?;
            original.receipt_taken = true;
            Ok((dispatch, Some(receipt)))
        } else {
            if original.dispatch_taken { return Err(ResourceReservationErrorV1::Conflict); }
            original.dispatch_taken = true;
            Ok((dispatch, None))
        }
    }

    /// Rejoins the durable Applying boundary before the genuine Host1 IO loan.
    pub(crate) fn require_host_effect_applying_v2(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        let action = self.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        self.require_active_host_publication_v2(controller, &action.contract)?;
        if !matches!(action.effect_original.applying.core, Some(Ok(())))
            || action.effect_original.applying.turn != Some(self.native_turn)
            || action.effect_original.applied.core.is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Persists the exact private Applying attempt before any Host1 send.
    ///
    /// # Errors
    /// Retains currentness, pricing, canonical attempt or scoped Core refusal;
    /// the same C and Root2 posts remain independently owed.
    #[doc(hidden)]
    pub fn begin_host_effect_once_v2(&mut self,
        intake: &crate::CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        root: &RootStartResourceCurrentTurnV2<'_>, prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        let contract = self.prepare_host_effect_phase_once_v2(intake, controller, source, root, false)?;
        let dispatch = (|| -> Result<_, Cause> {
            let loan = self.borrow_host_root_v1(intake, controller, source)?;
            prepared.host_catalog_projection_v2(&loan, controller)?;
            if prepared.signed_plan_v2()? != &contract.host { return Err(Box::new(CLOSED)); }
            let effect = contract.plan.start_host_effect_plan_v2()?;
            let binding = effect.authority().ok_or(CLOSED)?;
            let sample = root.before_clock_data_v2()?;
            let (publication, attempt) = crate::publication::AuthorityPublicationStore::new(controller)
                .select_bound_current_attempt(contract.prepared.manifest().manifest().sandbox(),
                    contract.prepared.digest(), binding.source_draft_digest(), binding.audience(),
                    binding.template_digest(), Some(&contract.guardian),
                    prepared.request_header_v2()?.deadline_boottime_nanoseconds, sample)?;
            if attempt.history().body() != prepared.request_body_v2()? { return Err(Box::new(CLOSED)); }
            Ok(crate::PreparedAuthorityEffectV1::new(binding.digest(), publication, sample, attempt))
        })();
        let original = &mut self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
            .ok_or(ResourceReservationErrorV1::Conflict)?.effect_original;
        original.dispatch = Some(dispatch);
        if !matches!(original.dispatch, Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.run_host_effect_core_once_v2(controller, source, root, false)
    }

    /// Persists private Applied/Succeeded after the same native Host1 and fresh3.
    ///
    /// # Errors
    /// Retains another exchange, incomplete native terminal posts, invalid Host
    /// receipt, currentness, pricing or canonical Core mutation failure.
    #[doc(hidden)]
    pub fn finish_host_effect_once_v2(&mut self,
        intake: &crate::CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        root: &RootStartResourceCurrentTurnV2<'_>,
        host: &AuthenticatedBrokerMethodOutcomeV1, inventory: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.prepare_host_effect_phase_once_v2(intake, controller, source, root, true)?;
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let terminal = native.resources.host.io.require_completed_host_outcomes_v2(host, inventory);
        let original = &mut native.host_publication_action.as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?.effect_original;
        original.native_terminal = Some(terminal);
        if !matches!(original.native_terminal, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        original.receipt = Some((|| {
            let dispatch = original.dispatch.as_ref().and_then(|returned| returned.as_ref().ok())
                .ok_or(crate::ReconcilerError::InvalidExecutorOutput("private Host dispatch is absent"))?;
            dispatch.validate_authenticated_outcome(host).map(Some)
        })());
        if !matches!(original.receipt, Some(Ok(Some(_)))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.run_host_effect_core_once_v2(controller, source, root, true)
    }

    fn prepare_host_effect_phase_once_v2(&mut self,
        intake: &crate::CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        root: &RootStartResourceCurrentTurnV2<'_>, complete: bool,
    ) -> Result<Arc<StartHostPublicationContractV2>, ResourceReservationErrorV1> {
        let contract = {
            let loan = self.borrow_host_root_v1(intake, controller, source)?;
            loan.require_host_stage_v2(2, controller)?;
            root.require_host_io_owner_v2(loan.parent_operation_v1(), loan.native_turn_v1(), loan.native.profile.as_ref())?;
            let action = loan.native.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let original = &action.effect_original;
            if original.phase_v2(complete).geometry.is_some()
                || complete && !matches!(original.applying.core, Some(Ok(()))) {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Arc::clone(&action.contract)
        };
        let geometry = contract.plan.start_host_publication_phase_receiving_demand_v2(controller,
            &contract.draft, &contract.prepared,
            crate::cold_launch_publication::action::PublicationActionPhaseV1::ChildTransition)
            .and_then(|demand| demand.checked_add(StartAdmissionScopeV1::host_scope_receiving_demand_v2()
                .map_err(ResourceReservationErrorV1::Journal)?).map_err(Into::into));
        self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
            .ok_or(ResourceReservationErrorV1::Conflict)?.effect_original.phase_mut_v2(complete).geometry = Some(geometry);
        let demand = *self.native_state.as_ref().and_then(|native| native.host_publication_action.as_ref())
            .and_then(|action| action.effect_original.phase_v2(complete).geometry.as_ref())
            .and_then(|returned| returned.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut loan = self.borrow_host_root_v1(intake, controller, source)?;
        let resident = loan.native.resources.host_publication_resident.checked_add(demand)?;
        let funding = loan.require_complete_v1(controller, demand);
        let selected = funding.is_err() && loan.native.native_failure_v1().is_some();
        let turn = loan.native.native_turn;
        let context = if funding.is_ok() { loan.native.require_active_host_publication_v2(controller, &contract) }
            else { Err(ResourceReservationErrorV1::Conflict) };
        let phase = loan.native.host_publication_action.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
            .effect_original.phase_mut_v2(complete);
        phase.funding = Some(funding);
        phase.context = Some(context);
        phase.turn = Some(turn);
        phase.selected = selected;
        if !matches!(phase.funding, Some(Ok(()))) || !matches!(phase.context, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        loan.native.resources.host_publication_resident = resident;
        Ok(contract)
    }

    fn run_host_effect_core_once_v2(&mut self, controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        root: &RootStartResourceCurrentTurnV2<'_>, complete: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        let phase = if complete { Phase::Applied } else { Phase::Applying };
        let scope = match StartAdmissionScopeV1::from_host_entry_v2(self, controller, phase, root, source) {
            Ok(scope) => scope,
            Err(cause) => {
                self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
                    .ok_or(ResourceReservationErrorV1::Conflict)?.effect_original.phase_mut_v2(complete).scope = Some(Err(cause));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        if let Err(scope) = controller.install_start_admission_scope_v1(Box::new(scope)) {
            self.restore_native_state_v1(scope.into_native_v1());
            self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
                .ok_or(ResourceReservationErrorV1::Conflict)?.effect_original.phase_mut_v2(complete).scope = Some(Err(ResourceReservationErrorV1::Conflict));
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let returned = controller.advance_start_host_effect_v2(complete);
        let Some(scope) = controller.take_start_admission_scope_v1() else { std::process::abort(); };
        self.restore_native_state_v1(scope.into_native_v1());
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let selected = returned.is_err() && native.native_failure_v1().is_some();
        let original = native.host_publication_action.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
            .effect_original.phase_mut_v2(complete);
        original.scope = Some(Ok(()));
        original.selected = selected;
        original.core = Some(returned);
        if matches!(original.core, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Reports the actual retained private-effect body refusal before later posts.
    #[doc(hidden)]
    pub fn host_effect_body_failure_entered_v2(&self) -> bool {
        self.native_state.as_ref().and_then(|native| native.host_publication_action.as_ref())
            .and_then(StartHostPublicationActionOriginalV2::effect_body_failure_v2).is_some()
    }
}
