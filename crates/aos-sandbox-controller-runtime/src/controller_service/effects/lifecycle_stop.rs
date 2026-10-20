//! Keeps the accepted Stop and its actual Host outcome through terminal emission.
//!
//! One same-B Source interval surrounds the existing retained SDK exchange.
//! Every entered SDK and Source post runs independently after primary refusal;
//! neither a supplied receipt nor metadata readiness creates terminal authority.

use super::*;
use aos_sandbox::controller_lifecycle_stop::ControllerLifecycleStopOriginalV4;
use aos_sandbox::lifecycle::{LifecycleEffectObservationV1, LifecyclePhase6ErrorV1};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1;
use aos_sandbox_broker_session_security::{
    ExecutionClientPostOriginalV1, HostExecutionSessionReceivingOriginalV1,
};
use aos_sandbox_core::ResourceVector;
use std::error::Error;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1,
};
use crate::retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestPreparationV1, ProtectedBrokerOutcomeCurrentnessOwnerV1,
};

const CLOSED: aos_sandbox::ResourceReservationErrorV1 = aos_sandbox::ResourceReservationErrorV1::Conflict;
const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "Stop request custody is absent",
    retained: "Stop retains its original request and channel",
    unusable: "Stop channel requires genuine recovery",
};

#[derive(Clone, Copy)]
enum First {
    Accepted, Source, Entry, Host, Fixed, Arm, Quote, Funding, Bound, Authority,
    Preparation, Request, Dispatch, Exchange, CurrentBefore, Outcome, CurrentAfter,
    Post, Inventory, SourceAfter, Residual, Terminal, Reentry,
}

pub(super) struct LifecycleStopOriginalV4 {
    operation: OperationId,
    entered: bool,
    original: Box<ControllerLifecycleStopOriginalV4>,
    accepted: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    source: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    entry: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    host: Option<Result<(), EffectFailure>>,
    fixed: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    receiving: Box<HostExecutionSessionReceivingOriginalV1>,
    prepare_native: Box<aos_sandbox_broker_session_security::HostStopRequestPreparationOriginalV5>,
    quote: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    funding: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    bound: Option<Result<u64, BrokerSessionSecurityError>>,
    authority: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    preparation: Option<Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError>>,
    request: Option<Result<(), LifecyclePhase6ErrorV1>>,
    dispatch: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    exchange: Box<RetainedBrokerExchangeV1<()>>,
    outcome: Option<AuthenticatedBrokerMethodOutcomeV1>,
    currentness: Option<ProtectedBrokerOutcomeCurrentnessOwnerV1>,
    current_before: Option<Result<(), BrokerSessionSecurityError>>,
    observation: Option<Result<Option<LifecycleEffectObservationV1>, LifecyclePhase6ErrorV1>>,
    current_after: Option<Result<(), BrokerSessionSecurityError>>,
    post: Box<ExecutionClientPostOriginalV1>,
    post_arm: Option<Result<(), BrokerSessionSecurityError>>,
    post_finish: Option<Result<(), BrokerSessionSecurityError>>,
    source_finish: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    residual: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    terminal: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    inventory: Box<HealthyStopInventoryOriginalV5>,
    frontier: First,
    first: Option<First>,
    closed: aos_sandbox::ResourceReservationErrorV1,
}

impl LifecycleStopOriginalV4 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<ControllerLifecycleStopOriginalV4>(),
            boxed_bytes::<HostExecutionSessionReceivingOriginalV1>(),
            boxed_bytes::<aos_sandbox_broker_session_security::HostStopRequestPreparationOriginalV5>(),
            boxed_bytes::<RetainedBrokerExchangeV1<()>>(),
            boxed_bytes::<ExecutionClientPostOriginalV1>(),
            boxed_bytes::<HealthyStopInventoryOriginalV5>(),
            HealthyStopInventoryOriginalV5::inactive_receiving_bytes_v1(),
        ])
    }

    pub(super) fn new(operation: OperationId,
        bank: Arc<Mutex<aos_sandbox::ControllerResourceBankOpeningV1>>,
        profile: Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
    ) -> Self {
        Self {
            operation, entered: false,
            original: Box::new(ControllerLifecycleStopOriginalV4::new_v4(operation, bank, profile)),
            accepted: None, source: None, entry: None, host: None, fixed: None,
            receiving: Box::new(Default::default()), prepare_native: Box::new(Default::default()), quote: None, funding: None, bound: None,
            authority: None, preparation: None, request: None, dispatch: None, exchange: Box::new(Default::default()),
            outcome: None, currentness: None, current_before: None,
            observation: None, current_after: None, post: Box::new(Default::default()), post_arm: None,
            post_finish: None, source_finish: None, residual: None, terminal: None, inventory: Box::new(Default::default()), frontier: First::Accepted, first: None,
            closed: CLOSED,
        }
    }

    fn fixed_demand_v4() -> Option<ResourceVector> {
        HostExecutionSessionReceivingOriginalV1::fixed_demand_v1()?
            .checked_add(ExecutionClientPostOriginalV1::receiving_demand_v1()?).ok()?
            .checked_add(aos_sandbox_broker_session_security::HostStopRequestPreparationOriginalV5::receiving_demand_v5()?).ok()?
            .checked_add(HealthyStopInventoryOriginalV5::fixed_demand_v5()?).ok()?
            .checked_add(ControllerLifecycleStopOriginalV4::inventory_preparation_demand_v5().ok()?).ok()
    }

    pub(super) fn run_once_v4(&mut self, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        sessions: &SharedControllerBrokerSessions, node: NodeId,
        enrolled: &aos_sandbox::OperatorFirstLocalOrdinaryEnrollmentOriginalV2,
    ) -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.entered = true;
        // The actual compiled Runtime owner is a sizing input only. No second
        // owner or native resource is constructed to obtain its complete size.
        self.accepted = Some(self.original.prepare_accepted_with_recovered_enrollment_once_v6::<Self>(controller, source, enrolled));
        if !matches!(self.accepted, Some(Ok(()))) {
            self.first = Some(First::Accepted);
            return Err(CLOSED);
        }
        self.source = Some(self.original.prepare_source_metadata_once_v4(controller, source));
        if !matches!(self.source, Some(Ok(()))) {
            self.first = Some(First::Source);
            return Err(CLOSED);
        }
        self.entry = Some(self.original.begin_host_stop_once_v4(controller, source));
        if !matches!(self.entry, Some(Ok(()))) {
            self.first = Some(First::Entry);
        } else {
            let returned = (|| {
                self.frontier = First::Host;
                let mut held = sessions.lock().map_err(|_| EffectFailure::Retryable(
                    "Stop Session lock is poisoned".to_owned()))?;
                let host = held.host.as_mut().ok_or_else(closed)?;
                let session = host.lifecycle_stop_session_v4(&self.original, controller)?;
                self.run_exchange_once_v4(session, controller, source, node)
            })();
            if returned.is_err() { self.first.get_or_insert(self.frontier); }
            self.host = Some(returned);
        }
        // The Source before may have entered even when its entry or SDK body
        // refused. Its own entry bits decide the independently owed afters.
        self.source_finish = Some(self.original.finish_host_stop_once_v4(controller, source));
        if !matches!(self.source_finish, Some(Ok(()))) {
            self.first.get_or_insert(First::SourceAfter);
        }
        if self.first.is_some() { return Err(CLOSED); }
        StopHostPostsPositiveV4 { original: self }.commit_once_v4(controller, source)
    }

    fn run_exchange_once_v4(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1, node: NodeId,
    ) -> Result<(), EffectFailure> {
        let primary = (|| {
            self.frontier = First::Fixed;
            let fixed = Self::fixed_demand_v4().ok_or_else(closed)?;
            self.fixed = Some(self.original.admit_host_stop_fixed_receiving_once_v4(controller,
                ControllerOperationIntakeDemandDataV1::from_demand_v1(fixed)));
            if !matches!(self.fixed, Some(Ok(()))) { return Err(closed()); }
            self.frontier = First::Arm;
            self.post_arm = Some(session.arm_execution_client_post_v1(&mut self.post));
            if !matches!(self.post_arm, Some(Ok(()))) { return Err(closed()); }
            self.frontier = First::Quote;
            self.quote = Some(session.host_stop_demand_v4(&mut self.receiving));
            let demand = self.quote.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or_else(closed)?.checked_add(fixed).map_err(|_| closed())?;
            self.frontier = First::Funding;
            self.funding = Some(self.original.admit_host_stop_receiving_once_v4(controller,
                ControllerOperationIntakeDemandDataV1::from_demand_v1(demand)));
            if !matches!(self.funding, Some(Ok(()))) { return Err(closed()); }
            self.frontier = First::Bound;
            let sample = self.original.host_stop_clock_data_v4().map_err(|_| closed())?;
            self.bound = Some(session.host_stop_request_bound_data_v4(sample));
            let bound = self.bound.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or_else(closed)?;
            self.frontier = First::Authority;
            self.authority = Some(self.original.prepare_host_stop_authority_once_v4(controller, node, bound));
            if !matches!(self.authority, Some(Ok(()))) { return Err(closed()); }
            self.frontier = First::Preparation;
            let effect = self.original.prepared_host_stop_effect_v4(controller).map_err(|_| closed())?;
            let original = &self.original;
            let request = &mut self.request;
            self.preparation = Some(session.prepare_host_stop_retaining_v5(effect, sample,
                &mut self.prepare_native, |actual| {
                *request = Some(original.require_host_stop_request_v4(controller, actual));
                matches!(request, Some(Ok(())))
            }));
            if self.request.as_ref().is_some_and(Result::is_err) {
                self.frontier = First::Request;
                return Err(closed());
            }
            if !matches!(self.preparation, Some(Ok(DormantBrokerRequestPreparationV1::Prepared(_)))) {
                return Err(closed());
            }
            self.frontier = First::Dispatch;
            let Some(Ok(DormantBrokerRequestPreparationV1::Prepared(prepared))) = self.preparation.as_ref() else {
                return Err(closed());
            };
            let actual = prepared.host_stop_dispatch_request_data_v1().ok_or_else(closed)?;
            let replay = self.quote.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or_else(closed)?;
            self.dispatch = Some(self.original.bind_host_stop_dispatch_once_v1(controller, source, actual,
                ControllerOperationIntakeDemandDataV1::from_demand_v1(replay)));
            if !matches!(self.dispatch, Some(Ok(()))) { return Err(closed()); }
            if let Some(Ok(DormantBrokerRequestPreparationV1::Prepared(prepared))) = self.preparation.take() {
                self.exchange.start_generation((), prepared);
            }
            self.frontier = First::Exchange;
            let (_, outcome, currentness) = self.exchange.drive_execution_publication(session, &ERRORS)?;
            self.outcome = Some(outcome);
            self.currentness = Some(currentness);
            self.classify_once_v4(session, controller)
        })();
        if primary.is_err() { self.first.get_or_insert(self.frontier); }
        if self.post_arm.is_some() {
            self.post_finish = Some(session.finish_execution_client_post_v1(&mut self.post));
            if !matches!(self.post_finish, Some(Ok(()))) {
                self.first.get_or_insert(First::Post);
            }
        }
        if self.first.is_some() { return Err(closed()); }
        if matches!(self.observation, Some(Ok(None))) {
            self.frontier = First::Inventory;
            let returned = self.inventory.run_once_v5(session, controller, &mut self.original,
                self.outcome.as_ref().ok_or_else(closed)?);
            if returned.is_err() { self.first.get_or_insert(First::Inventory); }
            returned
        } else { primary }
    }

    fn require_positive_disposal_v5(&self, controller: &Journal)
        -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        if self.first.is_some() || !matches!(self.observation, Some(Ok(None)))
            || !matches!(self.residual, Some(Ok(()))) || !matches!(self.terminal, Some(Ok(())))
            || !matches!(self.current_before, Some(Ok(())))
            || !matches!(self.current_after, Some(Ok(())))
            || !matches!(self.post_finish, Some(Ok(())))
            || !matches!(self.source_finish, Some(Ok(())))
            || self.receiving.failure().is_some() || self.prepare_native.failure().is_some()
            || self.exchange.execution_failure().is_some() || self.post.failure().is_some()
            || self.inventory.completed_observation_v5().is_none()
        { return Err(CLOSED); }
        self.original.require_healthy_stop_disposal_v5(controller)
    }

    pub(super) fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        let selected: Option<&(dyn Error + 'static)> = match self.first? {
            First::Accepted | First::Source | First::Entry | First::Funding | First::Authority
                | First::SourceAfter | First::Residual | First::Terminal => self.original.failure_v4(),
            First::Host => cause(&self.host),
            First::Reentry => Some(&self.closed),
            First::Fixed => self.original.failure_v4().or_else(|| cause(&self.fixed)),
            First::Arm => self.post.failure().or_else(|| cause(&self.post_arm)),
            First::Quote => self.receiving.failure().or_else(|| cause(&self.quote)),
            First::Bound => cause(&self.bound),
            First::Preparation => self.prepare_native.failure().or_else(|| match self.preparation.as_ref() {
                Some(Err(cause))
                | Some(Ok(DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { error: cause, .. }))
                | Some(Ok(DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { error: cause, .. })) => Some(cause),
                _ => None,
            }),
            First::Request => cause(&self.request),
            First::Dispatch => self.original.failure_v4().or_else(|| cause(&self.dispatch)),
            First::Exchange => self.exchange.execution_failure().or_else(|| cause(&self.host)),
            First::CurrentBefore => self.post.terminal_before_failure_v1()
                .or_else(|| cause(&self.current_before)),
            First::Outcome => cause(&self.observation),
            First::Inventory => match self.inventory.first {
                Some(InventoryFirstV5::Funding | InventoryFirstV5::Challenge) =>
                    self.original.failure_v4().or_else(|| self.inventory.failure()),
                _ => self.inventory.failure(),
            },
            First::CurrentAfter => self.post.terminal_after_failure_v1()
                .or_else(|| cause(&self.current_after)),
            First::Post => self.post.failure().or_else(|| cause(&self.post_finish)),
        };
        selected.or(Some(&self.closed))
    }

    fn classify_once_v4(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        controller: &Journal,
    ) -> Result<(), EffectFailure> {
        self.frontier = First::CurrentBefore;
        let owner = self.currentness.take().ok_or_else(closed)?;
        let mut current = match session.retain_execution_outcome_current_with_post_v1(owner, &mut self.post) {
            Ok(current) => { self.current_before = Some(Ok(())); current }
            Err((owner, cause)) => {
                self.currentness = Some(owner);
                self.current_before = Some(Err(cause));
                return Err(closed());
            }
        };
        self.frontier = First::Outcome;
        self.observation = Some((|| {
            let outcome = self.outcome.as_ref().ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
            self.original.observe_host_stop_outcome_v4(controller, outcome)
        })());
        self.current_after = Some(current.revalidate_execution_with_post_v1(&mut self.post));
        self.currentness = Some(current.into_currentness_owner());
        if self.observation.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
        self.frontier = First::CurrentAfter;
        if !matches!(self.current_after, Some(Ok(()))) { return Err(closed()); }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum InventoryFirstV5 { Arm, Quote, Funding, Challenge, Preparation, Exchange, Attestation, Post }

#[derive(Default)]
struct HealthyStopInventoryOriginalV5 {
    entered: bool,
    receiving: Box<HostExecutionSessionReceivingOriginalV1>,
    quote: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    funding: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    challenge: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
    prepare_native: Box<aos_sandbox_broker_session_security::HostStopRequestPreparationOriginalV5>,
    preparation: Option<Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError>>,
    exchange: Box<RetainedBrokerExchangeV1<()>>,
    outcome: Option<AuthenticatedBrokerMethodOutcomeV1>,
    currentness: Option<ProtectedBrokerOutcomeCurrentnessOwnerV1>,
    post: Box<ExecutionClientPostOriginalV1>,
    arm: Option<Result<(), BrokerSessionSecurityError>>,
    finish: Option<Result<(), BrokerSessionSecurityError>>,
    attestation: aos_sandbox_broker_session_security::HostStopInventoryAttestationOriginalV5,
    observation: Option<Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1>>,
    first: Option<InventoryFirstV5>,
    closed: Option<aos_sandbox::ResourceReservationErrorV1>,
}

impl HealthyStopInventoryOriginalV5 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<HostExecutionSessionReceivingOriginalV1>(),
            boxed_bytes::<aos_sandbox_broker_session_security::HostStopRequestPreparationOriginalV5>(),
            boxed_bytes::<RetainedBrokerExchangeV1<()>>(),
            boxed_bytes::<ExecutionClientPostOriginalV1>(),
        ])
    }

    fn fixed_demand_v5() -> Option<ResourceVector> {
        HostExecutionSessionReceivingOriginalV1::fixed_demand_v1()?
            .checked_add(ExecutionClientPostOriginalV1::receiving_demand_v1()?).ok()?
            .checked_add(aos_sandbox_broker_session_security::HostStopRequestPreparationOriginalV5::receiving_demand_v5()?).ok()?
            .checked_add(aos_sandbox_broker_session_security::HostStopInventoryAttestationOriginalV5::receiving_demand_v5()?).ok()
    }

    fn run_once_v5(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        controller: &Journal, original: &mut ControllerLifecycleStopOriginalV4,
        effect_outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), EffectFailure> {
        if self.entered {
            self.closed.get_or_insert(CLOSED);
            return Err(closed());
        }
        self.entered = true;
        let mut frontier = InventoryFirstV5::Arm;
        let primary = (|| {
            self.arm = Some(session.arm_execution_client_post_v1(&mut self.post));
            if !matches!(self.arm, Some(Ok(()))) { return Err(closed()); }
            frontier = InventoryFirstV5::Quote;
            self.quote = Some(session.host_stop_inventory_demand_v5(&mut self.receiving));
            let quote = self.quote.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or_else(closed)?;
            frontier = InventoryFirstV5::Funding;
            self.funding = Some(original.admit_host_stop_inventory_receiving_once_v5(controller,
                ControllerOperationIntakeDemandDataV1::from_demand_v1(quote)));
            if !matches!(self.funding, Some(Ok(()))) { return Err(closed()); }
            frontier = InventoryFirstV5::Challenge;
            self.challenge = Some(original.prepare_inventory_challenge_once_v5(controller));
            if !matches!(self.challenge, Some(Ok(()))) { return Err(closed()); }
            frontier = InventoryFirstV5::Preparation;
            self.preparation = Some(session.prepare_host_stop_inventory_retaining_v5(
                original.prepared_host_stop_effect_v4(controller).map_err(|_| closed())?,
                &mut self.prepare_native,
                super::super::lifecycle_runtime_effect::inventory_envelope));
            if !matches!(self.preparation, Some(Ok(DormantBrokerRequestPreparationV1::Prepared(_)))) {
                return Err(closed());
            }
            if let Some(Ok(DormantBrokerRequestPreparationV1::Prepared(prepared))) = self.preparation.take() {
                self.exchange.start_generation((), prepared);
            }
            frontier = InventoryFirstV5::Exchange;
            let (_, outcome, currentness) = self.exchange.drive_execution_publication(session, &ERRORS)?;
            self.outcome = Some(outcome);
            self.currentness = Some(currentness);
            frontier = InventoryFirstV5::Attestation;
            let inventory = self.outcome.as_ref().ok_or_else(closed)?;
            let challenge = original.inventory_challenge_v5(controller).map_err(|_| closed())?;
            let currentness = &mut self.currentness;
            let returned = original.with_host_stop_effect_v5(controller, |effect| {
                // Keep the actual owner parked until every fallible Source
                // comparison has completed and the immediate SDK borrower enters.
                let owner = currentness.take()?;
                Some(session.complete_host_stop_inventory_retaining_v5(challenge, effect,
                    effect_outcome, inventory, owner, &mut self.post, &mut self.attestation))
            }).map_err(|_| closed())?.ok_or_else(closed)?;
            self.currentness = Some(returned.0);
            self.observation = Some(returned.1);
            if self.observation.as_ref().is_none_or(Result::is_err) { return Err(closed()); }
            Ok(())
        })();
        if primary.is_err() { self.first.get_or_insert(frontier); }
        if self.arm.is_some() {
            self.finish = Some(session.finish_execution_client_post_v1(&mut self.post));
            if !matches!(self.finish, Some(Ok(()))) { self.first.get_or_insert(InventoryFirstV5::Post); }
        }
        if self.first.is_some() { Err(closed()) } else { primary }
    }

    fn completed_observation_v5(&self) -> Option<LifecycleEffectObservationV1> {
        if self.first.is_some() || self.closed.is_some() || self.post.failure().is_some()
            || self.receiving.failure().is_some() || self.prepare_native.failure().is_some()
            || self.attestation.failure().is_some() || self.exchange.execution_failure().is_some()
            || !matches!(self.finish, Some(Ok(()))) { return None; }
        self.observation.as_ref()?.as_ref().ok().copied()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first? {
            InventoryFirstV5::Arm => self.post.failure().or_else(|| cause(&self.arm)),
            InventoryFirstV5::Quote => self.receiving.failure().or_else(|| cause(&self.quote)),
            InventoryFirstV5::Funding => cause(&self.funding),
            InventoryFirstV5::Challenge => cause(&self.challenge),
            InventoryFirstV5::Preparation => self.prepare_native.failure().or_else(|| match self.preparation.as_ref() {
                Some(Err(cause)) | Some(Ok(DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { error: cause, .. }))
                    | Some(Ok(DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { error: cause, .. })) => Some(cause as _),
                _ => None,
            }),
            InventoryFirstV5::Exchange => self.exchange.execution_failure(),
            InventoryFirstV5::Attestation => self.attestation.failure_with_post_v5(&self.post)
                .or_else(|| cause(&self.observation)),
            InventoryFirstV5::Post => self.post.failure().or_else(|| cause(&self.finish)),
        };
        selected.or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

// No bool or receipt constructor can form this borrower outside the actual
// immediate caller. The whole SDK/native outcome and all entered posts remain
// in this exact owner throughout Source residual and Controller terminal CAS.
struct StopHostPostsPositiveV4<'posts> {
    original: &'posts mut LifecycleStopOriginalV4,
}

impl StopHostPostsPositiveV4<'_> {
    fn commit_once_v4(self, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        let original = self.original;
        if original.first.is_some() || original.receiving.failure().is_some()
            || original.post.failure().is_some() || original.exchange.execution_failure().is_some()
            || !matches!(original.current_before, Some(Ok(())))
            || !matches!(original.current_after, Some(Ok(())))
            || !matches!(original.post_finish, Some(Ok(())))
            || !matches!(original.source_finish, Some(Ok(())))
            || match original.observation {
                Some(Ok(Some(_))) => false,
                Some(Ok(None)) => original.inventory.completed_observation_v5().is_none(),
                _ => true,
            }
        { return Err(CLOSED); }
        let outcome = original.outcome.as_ref().ok_or(CLOSED)?;
        original.residual = Some(match original.observation {
            Some(Ok(Some(_))) => original.original.commit_host_stop_residual_source_once_v4(controller, source, outcome),
            Some(Ok(None)) => original.original.commit_host_stop_success_source_once_v5(controller, source,
                original.inventory.completed_observation_v5().ok_or(CLOSED)?),
            _ => return Err(CLOSED),
        });
        if !matches!(original.residual, Some(Ok(()))) {
            original.first.get_or_insert(First::Residual);
            return Err(CLOSED);
        }
        original.terminal = Some(original.original.commit_stop_terminal_once_v5(controller, source));
        if !matches!(original.terminal, Some(Ok(()))) {
            original.first.get_or_insert(First::Terminal);
            return Err(CLOSED);
        }
        Ok(())
    }
}

impl ProductionEffectExecutor {
    pub(super) fn progress_lifecycle_stop_once_v4(&mut self, operation: OperationId,
        controller: &mut Journal,
    ) -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        if self.lifecycle_stop.is_none() {
            let bank = self.resource_bank.as_ref().cloned().ok_or(CLOSED)?;
            let profile = self.execution_profile.as_ref().cloned().ok_or(CLOSED)?;
            self.lifecycle_stop = Some(LifecycleStopOriginalV4::new(operation, bank, profile));
        }
        let original = self.lifecycle_stop.as_mut().ok_or(CLOSED)?;
        if !original.entered {
            if let Some(intake) = self.lifecycle_stop_intake.take() {
                if let Err(intake) = original.original.retain_recovered_stop_intake_once_v6(intake) {
                    self.lifecycle_stop_intake = Some(intake);
                    return Err(CLOSED);
                }
            }
        }
        if original.operation != operation { return Err(CLOSED); }
        original.run_once_v4(controller, &mut self.source_domains, &self.sessions, self.node,
            &self.first_local_enrollment)?;
        if matches!(original.observation, Some(Ok(None))) {
            original.require_positive_disposal_v5(controller)?;
            if self.lifecycle_stop_intake.is_some() { return Err(CLOSED); }
            self.lifecycle_stop_intake = original.original.take_healthy_recovered_stop_intake_once_v6(controller)?;
            // All native posts and the exact terminal C/Source commit are now
            // positive. Drop these actual request/model/native temporaries
            // before a later distinct operation can construct its new owner.
            // The permanent B ledger keeps all spent traffic and highwaters.
            drop(self.lifecycle_stop.take());
        }
        Ok(())
    }
}

fn closed() -> EffectFailure {
    EffectFailure::Retryable("Stop retains its exact native, Source and channel originals".to_owned())
}

fn cause<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}
