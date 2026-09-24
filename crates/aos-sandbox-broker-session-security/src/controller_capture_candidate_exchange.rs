//! Retained Controller exchange for a read-only Storage capture candidate.
//!
//! Method 41 uses a fresh authenticated Storage session and a signed grant
//! bound to that session's actual request ID. The original accepted Create
//! source may be inspected after its one-shot deadline, but each inspection
//! rechecks current Controller sources. This exchange retains an ambiguous
//! in-process request; after a process restart a new read-only inspection is
//! allowed. A candidate is not a physical backing or admission receipt.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, ReadStorageExecutionCaptureCandidateRequestV1,
    RequestHeader,
};
use aos_sandbox::EffectFailure;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::storage_capture_candidate::{
    StorageCaptureCandidateQueryV1, ValidatedStorageCaptureCandidateV1,
    decode_storage_capture_candidate_response_for_query_v1,
};
use buffa::Message as _;

use crate::controller_retained_exchange::{RetainedBrokerExchangeV1, RetainedExchangeErrorsV1};
use crate::controller_service::execution_capture_candidate::SignedStorageCaptureCandidateQueryV1;
use crate::dormant_handshake::ProtectedStorageSessionBindingV1;
use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerRequestCoordinatesV1,
};

const ERRORS: RetainedExchangeErrorsV1 = RetainedExchangeErrorsV1 {
    absent: "Storage candidate request custody is absent",
    retained: "Storage candidate request retains protected session recovery",
    unusable: "Storage candidate session is unusable; inspect again after recovery",
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct CandidateExchangeContextV1 {
    query: StorageCaptureCandidateQueryV1,
    exact_body: Vec<u8>,
    settlement_digest: ObjectDigest,
    maximum_response_bytes: u32,
    session_binding: [u8; 32],
}

/// Holds one signed, informational Storage candidate and its exact query.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ControllerStorageCaptureCandidateObservationV1 {
    candidate: ValidatedStorageCaptureCandidateV1,
    query: StorageCaptureCandidateQueryV1,
    settlement_digest: ObjectDigest,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
}

impl ControllerStorageCaptureCandidateObservationV1 {
    pub(crate) const fn candidate(&self) -> &ValidatedStorageCaptureCandidateV1 {
        &self.candidate
    }

    pub(crate) const fn query(&self) -> &StorageCaptureCandidateQueryV1 {
        &self.query
    }

    pub(crate) const fn settlement_digest(&self) -> ObjectDigest {
        self.settlement_digest
    }

    pub(crate) const fn outcome(&self) -> &AuthenticatedBrokerMethodOutcomeV1 {
        &self.outcome
    }
}

/// Retains one exact method-41 query through session recovery and ambiguity.
#[derive(Default)]
pub(crate) struct ControllerStorageCaptureCandidateExchangeV1 {
    exchange: RetainedBrokerExchangeV1<CandidateExchangeContextV1>,
}

impl ControllerStorageCaptureCandidateExchangeV1 {
    pub(crate) const fn has_pending(&self) -> bool {
        self.exchange.has_pending()
    }

    pub(crate) const fn requires_reconnect(&self) -> bool {
        self.exchange.requires_reconnect()
    }

    /// Sends only a protected-source query bound to this Storage session.
    ///
    /// The session-selected request ID and verified transcript binding are
    /// passed to the issuer before the broker request is durably reserved.
    /// Method 41 remains outside production negotiation until Storage's
    /// signed readback handler is qualified.
    pub(crate) fn query<T>(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        issue: impl FnOnce(
            ProtectedStorageSessionBindingV1,
            DormantBrokerRequestCoordinatesV1,
        ) -> Result<SignedStorageCaptureCandidateQueryV1, EffectFailure>,
        clock: &mut T,
    ) -> Result<ControllerStorageCaptureCandidateObservationV1, EffectFailure>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.exchange.has_pending() {
            return Err(retryable("another Storage candidate query retains custody"));
        }
        let binding = session
            .current_storage_session_binding()
            .map_err(|_| retryable("authenticated Storage session is unavailable"))?;
        let mut issued = None;
        let preparation = session
            .prepare_authenticated_request_checked_fallible(
                BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE,
                |coordinates| {
                    let signed = issue(binding, coordinates).map_err(|_| {
                        BrokerSessionSecurityError::manifest("protected Storage candidate issuer")
                    })?;
                    let body = signed.body().to_vec();
                    if !query_matches_body(
                        signed.query(),
                        &body,
                        binding.digest(),
                        &coordinates.request_header(),
                    ) {
                        return Err(BrokerSessionSecurityError::manifest(
                            "Storage candidate request changed after signing",
                        ));
                    }
                    let envelope = BrokerRequestEnvelope {
                        method:
                            BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
                                .into(),
                        body: body.clone(),
                        authorization: Some(signed.authorization().clone()).into(),
                        ..Default::default()
                    };
                    issued = Some((signed, body, coordinates.maximum_response_bytes()));
                    Ok(envelope)
                },
                |request| request.session_binding() == binding.digest(),
            )
            .map_err(|_| {
                self.exchange.mark_failed();
                retryable("Storage candidate query needs exact session recovery")
            })?;
        let (signed, body, maximum_response_bytes) = issued.ok_or_else(|| {
            self.exchange.mark_failed();
            retryable("Storage candidate issuer returned no signed request")
        })?;
        self.exchange.start(
            CandidateExchangeContextV1 {
                query: *signed.query(),
                exact_body: body,
                settlement_digest: signed.settlement_digest(),
                maximum_response_bytes,
                session_binding: binding.digest(),
            },
            preparation,
        );
        self.drain(session, clock)?
            .ok_or_else(|| retryable(ERRORS.absent))
    }

    /// Advances only the exact retained send and authenticated outcome.
    pub(crate) fn drain<T>(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        clock: &mut T,
    ) -> Result<Option<ControllerStorageCaptureCandidateObservationV1>, EffectFailure>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        if self.exchange.context().is_none() {
            return Ok(None);
        }
        let (context, outcome) = self.exchange.drive(session, &ERRORS)?;
        let observation = classify_outcome(&context, &outcome, clock);
        if matches!(&observation, Err(EffectFailure::Permanent(_))) {
            self.exchange.mark_failed();
        }
        observation.map(Some)
    }
}

fn query_matches_body(
    query: &StorageCaptureCandidateQueryV1,
    body: &[u8],
    session_binding: [u8; 32],
    header: &RequestHeader,
) -> bool {
    let Ok(decoded) = ReadStorageExecutionCaptureCandidateRequestV1::decode_from_slice(body) else {
        return false;
    };
    decoded.__buffa_unknown_fields.is_empty()
        && decoded.encode_to_vec() == body
        && decoded.canonical_query == query.canonical_bytes().as_slice()
        && query.request_id().as_slice() == header.request_id.as_slice()
        && query.deadline_boottime_nanoseconds() == header.deadline_boottime_nanoseconds
        && query.claimed_session_binding() == session_binding
        && decoded.header.as_option() == Some(header)
}

fn classify_outcome<T>(
    context: &CandidateExchangeContextV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    clock: &mut T,
) -> Result<ControllerStorageCaptureCandidateObservationV1, EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let request = outcome.request();
    if outcome.method() != BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
        || request.exact_body() != context.exact_body
        || request.request_id() != context.query.request_id()
        || request.session_binding() != context.session_binding
        || request.maximum_response_bytes() != context.maximum_response_bytes
    {
        return Err(EffectFailure::Permanent(
            "Storage candidate outcome differs from signed query".to_owned(),
        ));
    }
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(retryable(
            "Storage candidate query did not return a signed candidate",
        ));
    };
    let sample = clock().map_err(|_| retryable("protected Controller clock is unavailable"))?;
    if sample.host_boot_id() != context.query.host_boot_id() {
        return Err(retryable("Storage candidate Host boot changed"));
    }
    let candidate = decode_storage_capture_candidate_response_for_query_v1(
        exact_body,
        &context.query,
        context.maximum_response_bytes,
        sample.boottime_nanoseconds(),
    )
    .map_err(|_| EffectFailure::Permanent("signed Storage candidate is invalid".to_owned()))?;
    Ok(ControllerStorageCaptureCandidateObservationV1 {
        candidate,
        query: context.query,
        settlement_digest: context.settlement_digest,
        outcome: outcome.clone(),
    })
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        Audience, ReadStorageExecutionCaptureCandidateRequestV1, RequestHeader,
    };
    use aos_sandbox_protocol::storage_capture_candidate::{
        STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1, StorageCaptureCandidateQueryV1,
    };
    use buffa::Message as _;
    use sha2::{Digest as _, Sha256};

    use super::query_matches_body;

    fn query() -> StorageCaptureCandidateQueryV1 {
        let mut bytes = [0_u8; STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSSCQ01");
        let settlement = &mut bytes[8..216];
        settlement[..8].copy_from_slice(b"AOSCIS01");
        settlement[8..24].fill(1);
        settlement[24..40].fill(2);
        settlement[40..72].fill(3);
        settlement[72..104].fill(4);
        settlement[104..112].copy_from_slice(&5_u64.to_be_bytes());
        settlement[112..144].fill(6);
        settlement[144..176].fill(7);
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.controller-output-settlement.v1\0")
            .chain_update(&settlement[..176])
            .finalize();
        settlement[176..208].copy_from_slice(&checksum);

        bytes[216..248].fill(9);
        bytes[248..264].fill(10);
        bytes[264..280].fill(11);
        bytes[280..288].copy_from_slice(&1_u64.to_be_bytes());
        bytes[288..296].copy_from_slice(&2_u64.to_be_bytes());
        bytes[296..328].fill(13);
        bytes[328..344].fill(14);
        bytes[344..376].fill(15);
        bytes[376..392].fill(16);
        bytes[392..400].copy_from_slice(&1_000_u64.to_be_bytes());
        StorageCaptureCandidateQueryV1::from_canonical_bytes(&bytes).unwrap()
    }

    #[test]
    fn signed_query_body_requires_exact_session_request_and_deadline() {
        let query = query();
        let header = RequestHeader {
            protocol_major: 1,
            request_id: vec![16; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 1_000,
            maximum_response_bytes: 4_096,
            ..Default::default()
        };
        let request = ReadStorageExecutionCaptureCandidateRequestV1 {
            header: Some(header.clone()).into(),
            canonical_query: query.canonical_bytes().to_vec(),
            ..Default::default()
        };
        let body = request.encode_to_vec();
        assert!(query_matches_body(&query, &body, [15; 32], &header));
        assert!(!query_matches_body(&query, &body, [23; 32], &header));

        let mut foreign_header = header.clone();
        foreign_header.request_id[0] ^= 1;
        assert!(!query_matches_body(
            &query,
            &body,
            [15; 32],
            &foreign_header
        ));
        let mut foreign_header = header.clone();
        foreign_header.deadline_boottime_nanoseconds += 1;
        assert!(!query_matches_body(
            &query,
            &body,
            [15; 32],
            &foreign_header
        ));

        let mut altered = request;
        altered.canonical_query[216] ^= 1;
        assert!(!query_matches_body(
            &query,
            &altered.encode_to_vec(),
            [15; 32],
            &header
        ));
    }
}
