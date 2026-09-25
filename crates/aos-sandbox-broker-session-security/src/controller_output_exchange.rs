//! Retained Controller exchange for one provisional Host output reservation.
//!
//! Method 35 may be prepared once from the protected AOSCIA01 attempt. After
//! ambiguity, method 36 observes that same original request ID; ABSENT never
//! permits another reserve. Neither outcome admits an ExecutionSpec or makes
//! a public Create operation complete.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, ReserveHostExecutionOutputRequestV1,
};
use aos_sandbox::controller_execution_output_settlement::{
    ControllerExecutionOutputSettlementErrorV1, ProtectedControllerOutputSettlementV1,
    settle_authenticated_host_output_v1,
};
use aos_sandbox::controller_execution_preissue::ControllerExecutionOutputAttemptV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{EffectFailure, Journal};
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId, RawPairedClockSample};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::host_output::{
    HostOutputReservationStatusV1, ValidatedHostOutputReservationV1,
    decode_host_output_reservation_response_v1, host_output_locator_from_source_v1,
};
use buffa::Message as _;

use crate::controller_retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::controller_service::execution_output_reserve::{
    SignedExecutionOutputQueryV1, SignedExecutionOutputReserveV1,
};
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestCoordinatesV1,
};

const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "Host output request custody is absent",
    retained: "Host output request retains protected session recovery",
    unusable: "Host output session is unusable; query original attempt after recovery",
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMethodV1 {
    Reserve,
    Query,
}

impl OutputMethodV1 {
    const fn broker_method(self) -> BrokerMethod {
        match self {
            Self::Reserve => BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT,
            Self::Query => BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OutputExchangeContextV1 {
    method: OutputMethodV1,
    attempt: ControllerExecutionOutputAttemptV1,
    exact_body: Vec<u8>,
}

/// Retains an authenticated Host observation without granting Create authority.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ControllerHostOutputObservationV1 {
    receipt: ValidatedHostOutputReservationV1,
    attempt: ControllerExecutionOutputAttemptV1,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
}

impl ControllerHostOutputObservationV1 {
    /// Checks the operation selected by the reconciler before settlement.
    pub(crate) fn matches(&self, execution: ExecutionId, operation: OperationId) -> bool {
        self.attempt.execution() == execution && self.attempt.create_operation() == operation
    }

    /// Commits only a COMMITTED authenticated receipt under Controller custody.
    ///
    /// ABSENT stays a historical observation and never permits another reserve.
    /// The resulting AOSCIS01 proof still does not authorize Host execution.
    pub(crate) fn settle<T>(
        &self,
        controller: &mut Journal,
        assignment: &CurrentAssignmentTarget,
        clock: &mut T,
    ) -> Result<
        Option<ProtectedControllerOutputSettlementV1>,
        ControllerExecutionOutputSettlementErrorV1,
    >
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.receipt.status() == HostOutputReservationStatusV1::Absent {
            return Ok(None);
        }
        settle_authenticated_host_output_v1(
            controller,
            assignment,
            self.attempt.execution(),
            self.attempt.create_operation(),
            &self.outcome,
            clock,
        )
        .map(Some)
    }
}

/// Retains one method-35 or method-36 signed request through ambiguity.
#[derive(Default)]
pub(crate) struct ControllerHostOutputExchangeV1 {
    exchange: RetainedBrokerExchangeV1<OutputExchangeContextV1>,
}

impl ControllerHostOutputExchangeV1 {
    /// Reports outstanding request or poisoned-session custody.
    pub(crate) const fn has_pending(&self) -> bool {
        self.exchange.has_pending()
    }

    /// Reports whether the retained session must be replaced.
    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.exchange.requires_reconnect()
    }

    /// Prepares and sends the sole original method-35 attempt.
    ///
    /// `issue` must be the protected Controller signer: it receives the
    /// session-selected request ID, records AOSCIA01, and returns exact signed
    /// artifacts before the session can append or send a request. This method
    /// is intentionally not called from public Create admission.
    pub(crate) fn reserve(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        issue: impl FnOnce(
            DormantBrokerRequestCoordinatesV1,
        ) -> Result<SignedExecutionOutputReserveV1, EffectFailure>,
    ) -> Result<ControllerHostOutputObservationV1, EffectFailure> {
        if self.exchange.has_pending() {
            return Err(retryable(
                "another Host output request retains session custody",
            ));
        }
        let mut issued = None;
        let preparation = session
            .prepare_authenticated_request_checked_fallible(
                OutputMethodV1::Reserve.broker_method(),
                |coordinates| {
                    let signed = issue(coordinates).map_err(|_| {
                        BrokerSessionSecurityError::manifest("protected Host output reserve issuer")
                    })?;
                    let body = ReserveHostExecutionOutputRequestV1 {
                        header: Some(coordinates.request_header()).into(),
                        canonical_source: signed.source().canonical_bytes().to_vec(),
                        ..Default::default()
                    }
                    .encode_to_vec();
                    let envelope = BrokerRequestEnvelope {
                        method: OutputMethodV1::Reserve.broker_method().into(),
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
                retryable("original Host output attempt needs cold Query36 recovery")
            })?;
        let (signed, body) = issued.ok_or_else(|| {
            self.exchange.mark_failed();
            retryable("Host output reserve issuer returned no protected attempt")
        })?;
        let context = OutputExchangeContextV1 {
            method: OutputMethodV1::Reserve,
            attempt: signed.attempt().clone(),
            exact_body: body,
        };
        self.exchange.start(context, preparation);
        self.drain(session)?.ok_or_else(|| retryable(ERRORS.absent))
    }

    /// Sends a new read-only query for the original protected method-35 ID.
    ///
    /// The query issuer may mint a new method-36 request ID, but it must load
    /// the same AOSCIA01 record and sign the exact canonical query body.
    pub(crate) fn query(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        attempt: &ControllerExecutionOutputAttemptV1,
        issue: impl FnOnce(
            DormantBrokerRequestCoordinatesV1,
        ) -> Result<SignedExecutionOutputQueryV1, EffectFailure>,
    ) -> Result<ControllerHostOutputObservationV1, EffectFailure> {
        if self.exchange.has_pending() {
            return Err(retryable(
                "another Host output request retains session custody",
            ));
        }
        let mut issued = None;
        let preparation = session
            .prepare_authenticated_request_checked_fallible(
                OutputMethodV1::Query.broker_method(),
                |coordinates| {
                    let signed = issue(coordinates).map_err(|_| {
                        BrokerSessionSecurityError::manifest("protected Host output query issuer")
                    })?;
                    let envelope = BrokerRequestEnvelope {
                        method: OutputMethodV1::Query.broker_method().into(),
                        body: signed.body().to_vec(),
                        authorization: Some(signed.authorization().clone()).into(),
                        ..Default::default()
                    };
                    issued = Some(signed);
                    Ok(envelope)
                },
                |_| true,
            )
            .map_err(|_| {
                self.exchange.mark_failed();
                retryable("Host output query needs exact session recovery")
            })?;
        let signed = issued.ok_or_else(|| {
            self.exchange.mark_failed();
            retryable("Host output query issuer returned no signed request")
        })?;
        let context = OutputExchangeContextV1 {
            method: OutputMethodV1::Query,
            attempt: attempt.clone(),
            exact_body: signed.body().to_vec(),
        };
        self.exchange.start(context, preparation);
        self.drain(session)?.ok_or_else(|| retryable(ERRORS.absent))
    }

    /// Advances the exact retained send, response, or commit recovery stage.
    pub(crate) fn drain(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<Option<ControllerHostOutputObservationV1>, EffectFailure> {
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

    /// Advances custody only for the journal-loaded original attempt.
    pub(crate) fn drain_for(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        expected: &ControllerExecutionOutputAttemptV1,
    ) -> Result<Option<ControllerHostOutputObservationV1>, EffectFailure> {
        if self
            .exchange
            .context()
            .is_some_and(|context| &context.attempt != expected)
        {
            return Err(retryable(
                "another execution owns the retained Host output request",
            ));
        }

        self.drain(session)
    }
}

fn classify_outcome(
    context: &OutputExchangeContextV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<ControllerHostOutputObservationV1, EffectFailure> {
    let request = outcome.request();
    if outcome.method() != context.method.broker_method()
        || request.exact_body() != context.exact_body
        || (context.method == OutputMethodV1::Reserve
            && request.request_id() != context.attempt.original_request_id())
    {
        return Err(EffectFailure::Permanent(
            "Host output outcome has the wrong signed request".to_owned(),
        ));
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(retryable("Host output reserve or query was not committed"));
    };
    let source = context.attempt.source().canonical_bytes();
    let locator =
        host_output_locator_from_source_v1(&source, context.attempt.original_request_id())
            .map_err(|_| {
                EffectFailure::Permanent("protected output locator is invalid".to_owned())
            })?;
    let reservation = decode_host_output_reservation_response_v1(
        exact_body,
        locator,
        context.method == OutputMethodV1::Query,
    )
    .map_err(|_| EffectFailure::Permanent("signed Host output receipt is invalid".to_owned()))?;
    match reservation.status() {
        HostOutputReservationStatusV1::Absent => Ok(ControllerHostOutputObservationV1 {
            receipt: reservation,
            attempt: context.attempt.clone(),
            outcome: outcome.clone(),
        }),
        HostOutputReservationStatusV1::Committed
            if committed_digests_match_original(
                reservation.original_plan_digest(),
                reservation.original_semantic_request_digest(),
                context.attempt.plan_digest(),
                context.attempt.semantic_request_digest(),
            ) =>
        {
            Ok(ControllerHostOutputObservationV1 {
                receipt: reservation,
                attempt: context.attempt.clone(),
                outcome: outcome.clone(),
            })
        }
        HostOutputReservationStatusV1::Committed => Err(EffectFailure::Permanent(
            "Host output receipt differs from the original signed attempt".to_owned(),
        )),
    }
}

fn committed_digests_match_original(
    observed_plan: Option<ObjectDigest>,
    observed_semantics: Option<ObjectDigest>,
    original_plan: ObjectDigest,
    original_semantics: ObjectDigest,
) -> bool {
    observed_plan == Some(original_plan) && observed_semantics == Some(original_semantics)
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        HostExecutionOutputReservationStatusV1, HostExecutionOutputReservationV1,
    };
    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_protocol::host_output::{
        decode_host_output_reservation_response_v1, host_output_locator_from_source_v1,
    };
    use buffa::Message as _;

    use super::committed_digests_match_original;

    #[test]
    fn committed_receipt_requires_both_original_signed_digests() {
        let original_plan = ObjectDigest::from_bytes([1; 32]);
        let original_semantics = ObjectDigest::from_bytes([2; 32]);
        assert!(committed_digests_match_original(
            Some(original_plan),
            Some(original_semantics),
            original_plan,
            original_semantics,
        ));
        assert!(!committed_digests_match_original(
            Some(ObjectDigest::from_bytes([3; 32])),
            Some(original_semantics),
            original_plan,
            original_semantics,
        ));
        assert!(!committed_digests_match_original(
            Some(original_plan),
            Some(ObjectDigest::from_bytes([4; 32])),
            original_plan,
            original_semantics,
        ));
        assert!(!committed_digests_match_original(
            None,
            None,
            original_plan,
            original_semantics,
        ));
    }

    #[test]
    fn committed_receipt_rejects_every_foreign_original_locator_field() {
        let mut source = [0_u8; 688];
        source[..8].copy_from_slice(b"AOSCIR01");
        source[8..16].copy_from_slice(b"AOSCIP01");
        source[16..32].fill(1);
        source[32..48].fill(2);
        source[104..120].fill(3);
        source[160..192].fill(4);
        source[192..200].copy_from_slice(b"AOSEOR02");
        source[200..216].fill(1);
        source[216..232].fill(2);
        source[624..656].fill(5);
        source[656..688].fill(6);
        let locator = host_output_locator_from_source_v1(&source, [7; 16]).unwrap();
        let committed = HostExecutionOutputReservationV1 {
            status: HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_COMMITTED.into(),
            execution_id: locator.execution().as_bytes().to_vec(),
            create_operation_id: locator.create_operation().as_bytes().to_vec(),
            preissue_record_digest: locator.preissue_digest().as_bytes().to_vec(),
            output_claim_digest: locator.claim_digest().as_bytes().to_vec(),
            reserve_source_digest: locator.carrier_digest().as_bytes().to_vec(),
            original_reserve_request_id: locator.original_request_id().to_vec(),
            assignment_digest: locator.assignment_digest().as_bytes().to_vec(),
            host_boot_id: locator.host_boot_id().to_vec(),
            original_plan_digest: vec![8; 32],
            original_semantic_request_digest: vec![9; 32],
            host_correlation_record_digest: vec![10; 32],
            original_host_journal_sequence: 1,
            ..Default::default()
        };
        assert!(
            decode_host_output_reservation_response_v1(&committed.encode_to_vec(), locator, false,)
                .is_ok()
        );

        for field in 0..8 {
            let mut substituted = committed.clone();
            let bytes = match field {
                0 => &mut substituted.execution_id,
                1 => &mut substituted.create_operation_id,
                2 => &mut substituted.preissue_record_digest,
                3 => &mut substituted.output_claim_digest,
                4 => &mut substituted.reserve_source_digest,
                5 => &mut substituted.original_reserve_request_id,
                6 => &mut substituted.assignment_digest,
                _ => &mut substituted.host_boot_id,
            };
            bytes[0] ^= 0x40;
            assert!(
                decode_host_output_reservation_response_v1(
                    &substituted.encode_to_vec(),
                    locator,
                    false,
                )
                .is_err()
            );
        }
    }
}
