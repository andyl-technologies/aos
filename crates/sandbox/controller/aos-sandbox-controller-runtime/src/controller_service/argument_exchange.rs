//! Retains Prepare and Accept on the same authenticated Host Session.
//!
//! Prepare does not consume AOSCIA02 or create a Guest challenge. Its exact
//! authenticated response and terminal-currentness owner remain beside the
//! separate Accept flight. Accept revalidates that actual predecessor before
//! invoking the one-shot signer. Every request uses the existing retained
//! transport engine; a failure blocks replacement and reconnect-based resend.

use aos_sandbox_api::aos::sandbox::local::v1::{BrokerMethod, BrokerRequestEnvelope};
use aos_sandbox_controller_domain::{EffectFailure, Journal};
use aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionReadReceivingLoanV1;
use aos_sandbox_controller_domain::ControllerResourceBankOpeningV1;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1;
use aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use std::mem::size_of;
use aos_sandbox_controller_domain::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::host_execution_argument::preparation::HostArgumentPreparationV2;

use crate::retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::controller_service::execution_argument_observe::{
    SignedExecutionArgumentRequestV2,
};
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestCoordinatesV1, DormantBrokerRequestPreparationV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1,
};

const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "Host argument request custody is absent",
    retained: "Host argument request retains protected recovery",
    unusable: "Host argument Session is closed; only original historical recovery is permitted",
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArgumentMethodV1 { Prepare, Accept }

impl ArgumentMethodV1 {
    const fn broker_method(self) -> BrokerMethod {
        match self {
            Self::Prepare => BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2,
            Self::Accept => BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArgumentExchangeContextV1 {
    method: ArgumentMethodV1,
    attempt: ControllerExecutionArgumentAttemptV1,
    exact_body: Vec<u8>,
}

/// Parks the real preparation return and transport owners before classification.
#[derive(Default)]
struct ArgumentFlightV2 {
    exchange: RetainedBrokerExchangeV1<ArgumentExchangeContextV1>,
    receiving: aos_sandbox_broker_session_security::HostExecutionSessionReceivingOriginalV1,
    post: super::execution_authorize::ExecutionClientPostSlotV1,
    post_arm: Option<Result<(), BrokerSessionSecurityError>>,
    post_finish: Option<Result<(), BrokerSessionSecurityError>>,
    receiving_demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    receiving_check: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    preparation: Option<Result<DormantBrokerRequestPreparationV1, BrokerSessionSecurityError>>,
    issuance: Option<Result<(), EffectFailure>>,
    context: Option<ArgumentExchangeContextV1>,
    outcome: Option<AuthenticatedBrokerMethodOutcomeV1>,
    currentness: Option<ProtectedBrokerOutcomeCurrentnessOwnerV1>,
    current_before: Option<Result<(), BrokerSessionSecurityError>>,
    classification: Option<Result<(), EffectFailure>>,
    current_after: Option<Result<(), BrokerSessionSecurityError>>,
    transport: Option<Result<(), EffectFailure>>,
    closed: Option<EffectFailure>,
}

impl ArgumentFlightV2 {
    fn entered(&self) -> bool {
        self.preparation.is_some() || self.context.is_some() || self.exchange.has_request()
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receiving.failure() { return Some(error); }
        if let Some(Err(error)) = &self.receiving_demand { return Some(error); }
        if let Some(Err(error)) = &self.receiving_check { return Some(error); }
        if let Some(Err(error)) = &self.issuance { return Some(error); }
        match &self.preparation {
            Some(Err(error))
            | Some(Ok(DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { error, .. }))
            | Some(Ok(DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        self.exchange.execution_failure()
            .or_else(|| self.transport.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.current_before.as_ref()?.as_ref().err().map(|error|
                self.post.terminal_before_failure_v1().unwrap_or(error)))
            .or_else(|| self.classification.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.current_after.as_ref()?.as_ref().err().map(|error|
                self.post.terminal_after_failure_v1().unwrap_or(error)))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
            .or_else(|| self.post.failure())
            .or_else(|| self.post_finish.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
    }

    fn finish_post(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> Result<(), EffectFailure> {
        if self.post_arm.is_some() {
            self.post_finish = Some(
                self.post
                    .native_mut_v1()
                    .and_then(|post| session.finish_execution_client_post_v1(post))
            );
            if !matches!(self.post_finish, Some(Ok(()))) {
                return Err(retryable("Host argument independently owed Session post failed"));
            }
        }
        Ok(())
    }

    fn admit_receiving(
        &mut self,
        session: &DormantAuthenticatedBrokerSessionV1,
        method: ArgumentMethodV1,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), EffectFailure> {
        let inline = u64::try_from(size_of::<Self>().checked_mul(2)
            .ok_or_else(|| retryable("Host argument capsule geometry overflows"))?)
            .map_err(|_| retryable("Host argument capsule geometry overflows"))?;
        let fixed = aos_sandbox_broker_session_security::HostExecutionSessionReceivingOriginalV1::fixed_demand_v1()
            .and_then(|fixed| fixed.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, inline)).ok())
            .and_then(|fixed| fixed.checked_add(
                super::execution_authorize::ExecutionClientPostSlotV1::receiving_demand_v1()?).ok())
            .ok_or_else(|| retryable("Host argument fixed geometry overflows"))?;
        self.receiving_check = Some(receiving.admit_stage_v1(bank, controller, profile,
            ControllerOperationIntakeDemandDataV1::from_demand_v1(fixed)));
        if !matches!(self.receiving_check, Some(Ok(()))) {
            return Err(retryable("Host argument fixed receiving is unavailable"));
        }
        self.post_arm = Some(
            self.post
                .initialize_once_v1()
                .and_then(|()| self.post.native_mut_v1())
                .and_then(|post| session.arm_execution_client_post_v1(post))
        );
        if !matches!(self.post_arm, Some(Ok(()))) {
            return Err(retryable("Host argument post could not bind its original Session"));
        }
        self.receiving_demand = Some(session.host_execution_argument_demand_v1(method.broker_method(), &mut self.receiving));
        let demand = self.receiving_demand.as_ref().and_then(|v| v.as_ref().ok()).copied()
            .ok_or_else(|| retryable("Host argument original receiving geometry failed"))?;
        self.receiving_check = Some(receiving.admit_stage_v1(bank, controller, profile,
            ControllerOperationIntakeDemandDataV1::from_demand_v1(demand)));
        if !matches!(self.receiving_check, Some(Ok(()))) {
            return Err(retryable("Host argument receiving declaration is insufficient"));
        }
        Ok(())
    }

    fn start(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        method: ArgumentMethodV1,
        prepared_source: Option<&HostArgumentPreparationV2>,
        issue: impl FnOnce(DormantBrokerRequestCoordinatesV1)
            -> Result<SignedExecutionArgumentRequestV2, EffectFailure>,
    ) -> Result<(), EffectFailure> {
        if self.entered() || self.failure().is_some() {
            self.closed.get_or_insert_with(|| retryable("Host argument flight already entered"));
            return Err(retryable(ERRORS.unusable));
        }
        let mut issued = None;
        let mut issuance = None;
        let build = |coordinates: DormantBrokerRequestCoordinatesV1| {
                let signed = match issue(coordinates) {
                    Ok(signed) => signed,
                    Err(error) => {
                        issuance = Some(Err(error));
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                };
                if signed.method() != method.broker_method()
                    || signed.attempt().request_id() != coordinates.request_id()
                {
                    issuance = Some(Err(retryable("Host argument signed request changed")));
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                let body = signed.body().to_vec();
                let envelope = BrokerRequestEnvelope {
                    method: method.broker_method().into(),
                    body: body.clone(),
                    authorization: Some(signed.authorization().clone()).into(),
                    ..Default::default()
                };
                issued = Some(ArgumentExchangeContextV1 {
                    method, attempt: signed.attempt().clone(), exact_body: body,
                });
                issuance = Some(Ok(()));
                Ok(envelope)
            };
        self.preparation = Some(match (method, prepared_source) {
            (ArgumentMethodV1::Prepare, None) => session.prepare_authenticated_request_checked_fallible(
                method.broker_method(), build, |_| true,
            ),
            (ArgumentMethodV1::Accept, Some(preparation)) => session.prepare_host_execution_argument_accept_v2(
                preparation, build,
                |request| request.session_binding() == preparation.controller_session(),
            ),
            _ => Err(BrokerSessionSecurityError::Currentness),
        });
        self.issuance = issuance;
        self.context = issued;
        if !matches!(self.preparation, Some(Ok(DormantBrokerRequestPreparationV1::Prepared(_)))) {
            self.exchange.mark_failed();
            return Err(retryable("Host argument preparation retains original failure"));
        }
        let Some(context) = self.context.take() else {
            self.closed = Some(retryable("Host argument context is absent"));
            return Err(retryable(ERRORS.unusable));
        };
        if let Some(Ok(DormantBrokerRequestPreparationV1::Prepared(prepared))) = self.preparation.take() {
            self.exchange.start_generation(context, prepared);
        }
        Ok(())
    }

    fn drive(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> Result<(), EffectFailure> {
        if self.failure().is_some() { return Err(retryable(ERRORS.unusable)); }
        match self.exchange.drive_execution_publication(session, &ERRORS) {
            Ok((context, outcome, currentness)) => {
                self.context = Some(context);
                self.outcome = Some(outcome);
                self.currentness = Some(currentness);
                self.transport = Some(Ok(()));
            }
            Err(error) => {
                self.transport = Some(Err(error));
                return Err(retryable(ERRORS.retained));
            }
        }
        let post = self.post.native_mut_v1()
            .map_err(|_| retryable(ERRORS.absent))?;
        let owner = self.currentness.take().ok_or_else(|| retryable(ERRORS.absent))?;
        let mut current = match session.retain_execution_outcome_current_with_post_v1(owner, post) {
            Ok(current) => { self.current_before = Some(Ok(())); current }
            Err((owner, error)) => {
                self.currentness = Some(owner);
                self.current_before = Some(Err(error));
                return Err(retryable("Host argument outcome is no longer current"));
            }
        };
        self.classification = Some(match (&self.context, &self.outcome) {
            (Some(context), Some(outcome)) => classify_outcome(context, outcome),
            _ => Err(retryable(ERRORS.absent)),
        });
        // The original live peer and terminal post is owed even if projection
        // rejects the returned authenticated body.
        self.current_after = Some(
            self.post
                .native_mut_v1()
                .and_then(|post| current.revalidate_execution_with_post_v1(post))
        );
        self.currentness = Some(current.into_currentness_owner());
        if self.failure().is_some() { return Err(retryable(ERRORS.unusable)); }
        Ok(())
    }

    fn completed(&self) -> bool {
        self.failure().is_none() && matches!(self.classification, Some(Ok(())))
            && matches!(self.current_after, Some(Ok(())))
    }
}

/// Retains the actual Prepare terminal alongside the independent Accept flight.
#[derive(Default)]
pub(crate) struct ControllerHostArgumentExchangeV1 {
    prepare: ArgumentFlightV2,
    accept: ArgumentFlightV2,
    preparation: Option<Result<HostArgumentPreparationV2, aos_sandbox_protocol::ProtocolValidationError>>,
    accept_predecessor: Option<Result<(), BrokerSessionSecurityError>>,
    closed: Option<EffectFailure>,
}

impl ControllerHostArgumentExchangeV1 {
    pub(crate) fn is_unentered_v2(&self) -> bool {
        !self.prepare.entered() && !self.accept.entered()
            && self.preparation.is_none() && self.accept_predecessor.is_none()
            && self.closed.is_none()
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.failure().is_some()
            || (self.prepare.entered() && !self.prepare.completed())
            || (self.accept.entered() && !self.accept.completed())
    }

    pub(crate) fn requires_reconnect(&self) -> bool { self.failure().is_some() }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.prepare.failure()
            .or_else(|| self.preparation.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| self.accept_predecessor.as_ref()?.as_ref().err().map(|error|
                self.accept.post.terminal_before_failure_v1().unwrap_or(error)))
            .or_else(|| self.accept.failure())
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }

    pub(crate) fn prepare(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        issue: impl FnOnce(DormantBrokerRequestCoordinatesV1, &mut Journal)
            -> Result<SignedExecutionArgumentRequestV2, EffectFailure>,
    ) -> Result<&HostArgumentPreparationV2, EffectFailure> {
        if self.prepare.entered() || self.failure().is_some() {
            return Err(retryable("Host preparation may only enter once"));
        }
        let primary = (|| {
            self.prepare.admit_receiving(session, ArgumentMethodV1::Prepare, receiving, bank, controller, profile)?;
            self.prepare.start(session, ArgumentMethodV1::Prepare, None, |coordinates| issue(coordinates, controller))?;
            self.prepare.drive(session)
        })();
        let after = self.prepare.finish_post(session);
        primary?;
        after?;
        let body = self.prepare.outcome.as_ref().and_then(|outcome| match outcome.result() {
            AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => Some(exact_body.as_slice()),
            _ => None,
        }).ok_or_else(|| retryable("Host preparation success is absent"))?;
        self.preparation = Some(HostArgumentPreparationV2::decode(body));
        self.preparation.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| retryable("Host preparation bytes are not canonical"))
    }

    pub(crate) fn accept(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
        issue: impl FnOnce(DormantBrokerRequestCoordinatesV1, &HostArgumentPreparationV2, &mut Journal)
            -> Result<SignedExecutionArgumentRequestV2, EffectFailure>,
    ) -> Result<(), EffectFailure> {
        if self.failure().is_some() || !self.prepare.completed() || self.accept.entered() {
            return Err(retryable("Host Accept has no completed original Prepare"));
        }
        let primary = (|| {
            self.accept.admit_receiving(session, ArgumentMethodV1::Accept, receiving, bank, controller, profile)?;
            let post = self.accept.post.native_mut_v1()
                .map_err(|_| retryable(ERRORS.absent))?;
            let owner = self.prepare.currentness.take().ok_or_else(|| retryable(ERRORS.absent))?;
            match session.retain_execution_outcome_current_with_post_v1(owner, post) {
                Ok(current) => {
                    // The same exclusive Session cannot advance between this
                    // terminal join and the immediately following preparation.
                    self.prepare.currentness = Some(current.into_currentness_owner());
                    self.accept_predecessor = Some(Ok(()));
                }
                Err((owner, error)) => {
                    self.prepare.currentness = Some(owner);
                    self.accept_predecessor = Some(Err(error));
                    return Err(retryable("Host Accept Session differs from Prepare"));
                }
            }
            let preparation = self.preparation.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| retryable("Host preparation is absent"))?;
            self.accept.start(session, ArgumentMethodV1::Accept, Some(preparation), |coordinates| issue(coordinates, preparation, controller))?;
            self.accept.drive(session)
        })();
        let after = self.accept.finish_post(session);
        primary?;
        after
    }

    /// Retires both positive terminals only while the original C/Source cut lives.
    pub(crate) fn retire_positive_v1(
        &mut self,
        disposal: &aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionPositiveDisposalV1<'_>,
        execution: aos_sandbox_model::ExecutionId,
    ) -> Result<(), EffectFailure> {
        if self.failure().is_some() || !self.prepare.completed() || !self.accept.completed() {
            return Err(retryable("Host argument positive disposal lacks its original terminals"));
        }
        for flight in [&self.prepare, &self.accept] {
            let context = flight.context.as_ref().ok_or_else(|| retryable(ERRORS.absent))?;
            if context.attempt.create_operation() != disposal.operation_v1()
                || context.attempt.execution() != execution
            {
                return Err(retryable("another execution owns the Host argument terminals"));
            }
        }
        *self = Self::default();
        Ok(())
    }

    pub(crate) fn accepted_outcome(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        if !self.accept.completed() { return None; }
        self.accept.outcome.as_ref()
    }
}

fn classify_outcome(
    context: &ArgumentExchangeContextV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(), EffectFailure> {
    let request = outcome.request();
    if outcome.method() != context.method.broker_method()
        || request.request_id() != context.attempt.request_id()
        || request.exact_body() != context.exact_body
    {
        return Err(EffectFailure::Permanent("Host argument outcome changed its original request".to_owned()));
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(retryable("Host argument flight has no successful terminal"));
    };
    if exact_body.is_empty() {
        return Err(EffectFailure::Permanent("Host argument signed body is empty".to_owned()));
    }
    Ok(())
}

fn retryable(message: &'static str) -> EffectFailure { EffectFailure::Retryable(message.to_owned()) }

/// Holds one actual output-stage forecast through the original caller's posts.
#[derive(Default)]
pub(crate) struct ExecutionSessionReceivingOriginalV1 {
    original: aos_sandbox_broker_session_security::HostExecutionSessionReceivingOriginalV1,
    demand: Option<Result<ResourceVector, BrokerSessionSecurityError>>,
    paid: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
}

impl ExecutionSessionReceivingOriginalV1 {
    pub(crate) fn admit_v1(
        &mut self,
        session: &DormantAuthenticatedBrokerSessionV1,
        method: BrokerMethod,
        receiving: &mut ControllerExecutionReadReceivingLoanV1<'_, '_>,
        bank: &ControllerResourceBankOpeningV1,
        controller: &mut Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), EffectFailure> {
        if self.demand.is_some() || self.paid.is_some() {
            return Err(retryable("original output receiving stage already entered"));
        }
        let fixed = aos_sandbox_broker_session_security::HostExecutionSessionReceivingOriginalV1::fixed_demand_v1()
            .ok_or_else(|| retryable("output receiving fixed geometry overflows"))?;
        self.paid = Some(receiving.admit_stage_v1(bank, controller, profile,
            ControllerOperationIntakeDemandDataV1::from_demand_v1(fixed)));
        if !matches!(self.paid, Some(Ok(()))) { return Err(retryable("output receiving fixed declaration refused")); }
        self.demand = Some(session.execution_output_demand_v1(method, &mut self.original));
        let demand = self.demand.as_ref().and_then(|v| v.as_ref().ok()).copied()
            .ok_or_else(|| retryable("output original geometry is unavailable"))?;
        self.paid = Some(receiving.admit_stage_v1(bank, controller, profile,
            ControllerOperationIntakeDemandDataV1::from_demand_v1(demand)));
        if matches!(self.paid, Some(Ok(()))) { Ok(()) }
        else { Err(retryable("output receiving exceeds the original declaration")) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
            .or_else(|| self.demand.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.paid.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}
