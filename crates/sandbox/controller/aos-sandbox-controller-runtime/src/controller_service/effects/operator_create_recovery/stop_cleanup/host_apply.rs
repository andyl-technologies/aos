//! Runs one fresh Host1 subturn while the genuine Root child interval is held.
//!
//! Request preparation, transport custody and currentness use the ordinary
//! retained SDK engines. The fresh Source22 pays their complete representation;
//! only the continuously held Root child can supply the new cleanup effect.
//! No old lifecycle attempt or authenticated success is rewritten here.

use super::*;
use crate::retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::{DormantBrokerRequestPreparationV1, ProtectedBrokerOutcomeCurrentnessOwnerV1};
use aos_sandbox_controller_domain::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1;
use aos_sandbox_controller_domain::normal_root::RootStopCleanupChildLoanV1;
use aos_sandbox_broker_session_security::{
    ExecutionClientPostOriginalV1, HostExecutionSessionReceivingOriginalV1,
    HostStopRequestPreparationOriginalV5,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};

const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "fresh Stop cleanup request custody is absent",
    retained: "fresh Stop cleanup retains its original request and channel",
    unusable: "fresh Stop cleanup channel requires genuine recovery",
};

type Source<'owner, 'source> = ControllerHostStopCleanupSourceLoanV1<'owner, 'source>;

#[derive(Clone, Copy)]
enum First { Fixed, Arm, Quote, Funding, Clock, Effect, Preparation, Request, Exchange,
    CurrentBefore, Outcome, CurrentAfter, Post, Reentry }

#[derive(Default)]
pub(super) struct StopCleanupHostApplyOriginalV1 {
    body: Body,
    post: Box<ExecutionClientPostOriginalV1>,
    arm: Option<Result<(), BrokerSessionSecurityError>>,
    after: Option<Result<(), BrokerSessionSecurityError>>,
}

#[derive(Default)]
struct Body {
    entered: bool,
    receiving: Box<HostExecutionSessionReceivingOriginalV1>,
    request_native: Box<HostStopRequestPreparationOriginalV5>,
    fixed: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    quote: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    funding: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    entry_clock: Option<Result<RawPairedClockSample, aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    clock: Option<Result<RawPairedClockSample, aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    preparation: Option<Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError>>,
    request: Option<Result<(), Closed>>,
    exchange: Box<RetainedBrokerExchangeV1<()>>,
    outcome: Option<AuthenticatedBrokerMethodOutcomeV1>,
    currentness: Option<ProtectedBrokerOutcomeCurrentnessOwnerV1>,
    before: Option<Result<(), BrokerSessionSecurityError>>,
    after: Option<Result<(), BrokerSessionSecurityError>>,
    result: Option<Result<(), Closed>>,
    first: Option<First>,
    closed: Option<Closed>,
}

// This owns only the independently prepaid Session after. Source/C/native
// posts remain owed by the actual outer Source22 owner on every result.
struct SessionPost<'turn> {
    session: &'turn mut DormantAuthenticatedBrokerSessionV1,
    original: &'turn mut ExecutionClientPostOriginalV1,
    result: &'turn mut Option<Result<(), BrokerSessionSecurityError>>,
}

impl SessionPost<'_> {
    fn finish(&mut self) {
        if self.result.is_none() {
            *self.result = Some(self.session.finish_execution_client_post_v1(self.original));
        }
    }
}

impl Drop for SessionPost<'_> {
    fn drop(&mut self) { self.finish(); }
}

impl StopCleanupHostApplyOriginalV1 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<ExecutionClientPostOriginalV1>(),
            Body::inactive_receiving_bytes_v1(),
        ])
    }

    fn fixed_demand() -> Option<ResourceVector> {
        HostExecutionSessionReceivingOriginalV1::fixed_demand_v1()?
            .checked_add(HostStopRequestPreparationOriginalV5::receiving_demand_v5()?).ok()?
            .checked_add(ExecutionClientPostOriginalV1::receiving_demand_v1()?).ok()
    }

    pub(super) fn run_once_v1(&mut self, source: &mut Source<'_, '_>, controller: &Journal,
        root: &RootStopCleanupChildLoanV1<'_>, session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<(), Closed> {
        if self.body.entered {
            self.body.first.get_or_insert(First::Reentry);
            self.body.closed.get_or_insert(Closed);
            return Err(Closed);
        }
        self.body.entered = true;
        self.body.fixed = Some(Self::fixed_demand().ok_or(aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict)
            .and_then(|demand| source.reserve_additional_v1(controller, demand)));
        if !matches!(self.body.fixed, Some(Ok(()))) {
            self.body.first = Some(First::Fixed);
            return Err(Closed);
        }

        self.body.entry_clock = Some(source.host_check_frontier_v1(controller));
        if !matches!(self.body.entry_clock, Some(Ok(_))) {
            self.body.first = Some(First::Clock);
            return Err(Closed);
        }

        self.arm = Some(session.arm_execution_client_post_v1(&mut self.post));
        // Even a refused arm owns its reached destinations. The same SDK
        // finisher determines which native afters are independently owed.
        let mut post = SessionPost { session, original: &mut self.post, result: &mut self.after };
        if !matches!(self.arm, Some(Ok(()))) {
            self.body.first = Some(First::Arm);
            self.body.result = Some(Err(Closed));
        } else {
            self.body.result = Some(self.body.run_primary(source, controller, root,
                post.session, post.original));
        }
        post.finish();
        drop(post);
        if !matches!(self.after, Some(Ok(()))) { self.body.first.get_or_insert(First::Post); }
        if self.body.first.is_some() || !matches!(self.body.result, Some(Ok(()))) {
            source.retain_cold_sdk_refusal_v1();
            return Err(Closed);
        }
        Ok(())
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let selected = match self.body.first? {
            First::Fixed => cause(&self.body.fixed),
            First::Arm => self.post.failure().or_else(|| cause(&self.arm)),
            First::Quote => self.body.receiving.failure().or_else(|| cause(&self.body.quote)),
            First::Funding => cause(&self.body.funding),
            First::Clock => cause(&self.body.entry_clock).or_else(|| cause(&self.body.clock)),
            First::Preparation => self.body.request_native.failure().or_else(||
                self.body.preparation.as_ref().and_then(|value| match value {
                    Err(cause) | Ok(DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { error: cause, .. })
                        | Ok(DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { error: cause, .. }) => Some(cause as _),
                    _ => None,
                })),
            First::Request => cause(&self.body.request),
            First::Exchange => self.body.exchange.execution_failure(),
            First::CurrentBefore => self.post.terminal_before_failure_v1().or_else(|| cause(&self.body.before)),
            First::CurrentAfter => self.post.terminal_after_failure_v1().or_else(|| cause(&self.body.after)),
            First::Post => self.post.failure().or_else(|| cause(&self.after)),
            First::Effect | First::Outcome | First::Reentry => None,
        };
        selected.or_else(|| self.body.closed.as_ref().map(|cause| cause as _))
    }
}

impl Body {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<HostExecutionSessionReceivingOriginalV1>(),
            boxed_bytes::<HostStopRequestPreparationOriginalV5>(),
            boxed_bytes::<RetainedBrokerExchangeV1<()>>(),
        ])
    }

    fn run_primary(&mut self, source: &mut Source<'_, '_>, controller: &Journal,
        root: &RootStopCleanupChildLoanV1<'_>, session: &mut DormantAuthenticatedBrokerSessionV1,
        post: &mut ExecutionClientPostOriginalV1,
    ) -> Result<(), Closed> {
        let mut frontier = First::Quote;
        let result = (|| {
            self.quote = Some(session.host_stop_demand_v4(&mut self.receiving));
            let demand = self.quote.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(Closed)?;
            frontier = First::Funding;
            self.funding = Some(source.reserve_additional_v1(controller, demand));
            if !matches!(self.funding, Some(Ok(()))) { return Err(Closed); }
            frontier = First::Clock;
            self.clock = Some(source.host_check_frontier_v1(controller));
            let sample = *self.clock.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Closed)?;
            frontier = First::Effect;
            let effect = root.effect_v1(source, controller).map_err(|_| Closed)?.ok_or(Closed)?;
            let subject = source.subject_data_v1(controller).map_err(|_| Closed)?;
            frontier = First::Preparation;
            let request = &mut self.request;
            self.preparation = Some(session.prepare_host_stop_retaining_v5(effect, sample,
                &mut self.request_native, |actual| {
                    let matches = actual.request_id() == *subject.cleanup_request_v1()
                        && aos_sandbox_protocol::decode_canonical_live_host_stop_cleanup_envelope_data_v1(
                            actual.exact_body()).is_ok_and(|body|
                                body.template_v1().host_stop_cleanup_v1() == Some(&subject));
                    *request = Some(if matches { Ok(()) } else { Err(Closed) });
                    matches
                }));
            if matches!(self.request, Some(Err(_))) { frontier = First::Request; return Err(Closed); }
            if !matches!(self.preparation, Some(Ok(DormantBrokerRequestPreparationV1::Prepared(_)))) {
                return Err(Closed);
            }
            let Some(Ok(DormantBrokerRequestPreparationV1::Prepared(prepared))) = self.preparation.take() else {
                return Err(Closed);
            };
            self.exchange.start_generation((), prepared);
            frontier = First::Exchange;
            let (_, outcome, currentness) = self.exchange.drive_execution_publication(session, &ERRORS)
                .map_err(|_| Closed)?;
            self.outcome = Some(outcome);
            self.currentness = Some(currentness);
            frontier = First::CurrentBefore;
            let currentness = self.currentness.take().ok_or(Closed)?;
            let mut current = match session.retain_execution_outcome_current_with_post_v1(currentness, post) {
                Ok(current) => { self.before = Some(Ok(())); current }
                Err((owner, cause)) => {
                    self.currentness = Some(owner);
                    self.before = Some(Err(cause));
                    return Err(Closed);
                }
            };
            frontier = First::Outcome;
            let outcome = self.outcome.as_ref().ok_or(Closed)?;
            let positive = outcome.request().request_id() == *subject.cleanup_request_v1()
                && matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. });
            // The sole authenticated SDK decoder has validated the method1
            // result. Final completion still requires an actual new Host3,
            // independent Root reread/48 and the sealed A8/native conjunction.
            self.after = Some(current.revalidate_execution_with_post_v1(post));
            self.currentness = Some(current.into_currentness_owner());
            if !positive { return Err(Closed); }
            frontier = First::CurrentAfter;
            if !matches!(self.after, Some(Ok(()))) { return Err(Closed); }
            source.require_current_v1(controller).map_err(|_| Closed)
        })();
        if result.is_err() {
            self.first.get_or_insert(frontier);
            self.closed.get_or_insert(Closed);
        }
        result
    }
}

fn cause<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
