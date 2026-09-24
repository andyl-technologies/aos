//! Dormant retained exchange for the original Host ARG_MAX observation.
//!
//! Method 37 sends only the one signed request already bound to AOSCIA02.
//! The protected broker-session owner retains its exact packet through
//! ambiguity. This adapter checks request identity and returns an opaque
//! signed outcome; it does not interpret Guest evidence, admit an execution
//! specification, or issue a second observation after process restart.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, ObserveHostExecutionArgumentRequestV1,
};
use aos_sandbox::EffectFailure;
use aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use buffa::Message as _;

use crate::controller_retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::controller_service::execution_argument_observe::SignedExecutionArgumentObserveV1;
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestCoordinatesV1,
};

const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "Host argument observation request custody is absent",
    retained: "Host argument observation retains protected session recovery",
    unusable: "Host argument session is unusable; query original attempt after recovery",
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArgumentExchangeContextV1 {
    attempt: ControllerExecutionArgumentAttemptV1,
    exact_body: Vec<u8>,
}

/// Holds a signed outcome without granting ARG_MAX or specification authority.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ControllerHostArgumentOutcomeV1 {
    attempt: ControllerExecutionArgumentAttemptV1,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
}

impl ControllerHostArgumentOutcomeV1 {
    pub(crate) const fn attempt(&self) -> &ControllerExecutionArgumentAttemptV1 {
        &self.attempt
    }

    pub(crate) const fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.outcome
    }
}

/// Retains the exact original signed request until a terminal Host outcome.
#[derive(Default)]
pub(crate) struct ControllerHostArgumentExchangeV1 {
    exchange: RetainedBrokerExchangeV1<ArgumentExchangeContextV1>,
}

impl ControllerHostArgumentExchangeV1 {
    pub(crate) const fn has_pending(&self) -> bool {
        self.exchange.has_pending()
    }

    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.exchange.requires_reconnect()
    }

    /// Sends only the original signed and durably retained method-37 request.
    pub(crate) fn observe(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        issue: impl FnOnce(
            DormantBrokerRequestCoordinatesV1,
        ) -> Result<SignedExecutionArgumentObserveV1, EffectFailure>,
    ) -> Result<ControllerHostArgumentOutcomeV1, EffectFailure> {
        if self.exchange.has_pending() {
            return Err(retryable(
                "another Host argument request retains session custody",
            ));
        }
        let mut issued = None;
        let preparation = session
            .prepare_authenticated_request_checked_fallible(
                BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT,
                |coordinates| {
                    let signed = issue(coordinates).map_err(|_| {
                        BrokerSessionSecurityError::manifest("protected Host argument issuer")
                    })?;
                    let body = signed.body().to_vec();
                    let decoded = ObserveHostExecutionArgumentRequestV1::decode_from_slice(&body)
                        .map_err(|_| {
                        BrokerSessionSecurityError::manifest("canonical Host argument body")
                    })?;
                    if decoded.encode_to_vec() != body
                        || decoded.canonical_attempt != signed.attempt().canonical_bytes()
                        || signed.attempt().request_id() != coordinates.request_id()
                    {
                        return Err(BrokerSessionSecurityError::manifest(
                            "Host argument request changed after signing",
                        ));
                    }
                    let envelope = BrokerRequestEnvelope {
                        method: BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT.into(),
                        body: body.clone(),
                        authorization: Some(signed.authorization().clone()).into(),
                        ..Default::default()
                    };
                    issued = Some((signed, body));
                    Ok(envelope)
                },
                |_| true,
            )
            .map_err(|_| {
                self.exchange.mark_failed();
                retryable("original Host argument attempt needs cold Query38 recovery")
            })?;
        let (signed, body) = issued.ok_or_else(|| {
            self.exchange.mark_failed();
            retryable("Host argument issuer returned no protected attempt")
        })?;
        self.exchange.start(
            ArgumentExchangeContextV1 {
                attempt: signed.attempt().clone(),
                exact_body: body,
            },
            preparation,
        );
        self.drain(session)?.ok_or_else(|| retryable(ERRORS.absent))
    }

    /// Resumes the exact in-process send or authenticated response commitment.
    pub(crate) fn drain(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<Option<ControllerHostArgumentOutcomeV1>, EffectFailure> {
        if self.exchange.context().is_none() {
            return Ok(None);
        }
        let (context, outcome) = self.exchange.drive(session, &ERRORS)?;
        let observation = classify_outcome(&context, &outcome);
        if matches!(&observation, Err(EffectFailure::Permanent(_))) {
            self.exchange.mark_failed();
        }
        observation.map(Some)
    }
}

fn classify_outcome(
    context: &ArgumentExchangeContextV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<ControllerHostArgumentOutcomeV1, EffectFailure> {
    let request = outcome.request();
    if outcome.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
        || request.request_id() != context.attempt.request_id()
        || request.exact_body() != context.exact_body
    {
        return Err(EffectFailure::Permanent(
            "Host argument outcome has the wrong signed request".to_owned(),
        ));
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(retryable("Host argument observation was not committed"));
    };
    if exact_body.is_empty() {
        return Err(EffectFailure::Permanent(
            "Host argument observation returned an empty signed body".to_owned(),
        ));
    }
    Ok(ControllerHostArgumentOutcomeV1 {
        attempt: context.attempt.clone(),
        outcome: outcome.clone(),
    })
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}
