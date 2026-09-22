//! Canonical bounded records for an authenticated ownership session carrier.
//!
//! The records contain no local credentials, descriptors, or clock samples.
//! A carrier must authenticate its peer, enforce its record limit before
//! allocation, and negotiate a fresh session before decoding either record.
//!
//! ```text
//! request  = "AOSORQ01" | binding:32 | method:u8 | zero:3 |
//!            request-id:16 | claim-digest:32 | body-len:u32be | body
//! response = "AOSORS01" | binding:32 | method:u8 | outcome:u8 | zero:2 |
//!            request-id:16 | claim-digest:32 | body-len:u32be | body
//! body     = canonical claim (Begin), empty (Query/CompleteOrResume),
//!            four length-prefixed artifacts (Completed), or empty (other outcomes)
//! ```
//!
//! Methods use codes 1 (Begin), 2 (CompleteOrResume), and 3 (Query).
//! Response outcomes use 1 (Absent), 2 (Pending), 3 (Completed), and 4-18
//! for the fixed error-code mapping below. Unknown codes and reserved bytes
//! never select a compatibility fallback.

use aos_sandbox_core::ObjectDigest;

use crate::protocol::{
    MAXIMUM_OWNERSHIP_REQUEST_BYTES, MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
    NegotiatedOwnershipSessionV1, OwnershipMethodV1, OwnershipProtocolErrorCodeV1,
    OwnershipProtocolValidationError, OwnershipRequestBodyV1, OwnershipRequestEnvelopeV1,
    OwnershipResponseEnvelopeV1, OwnershipResponseOutcomeV1, OwnershipTransactionReferenceV1,
    OwnershipTransactionStatusV1,
};
use crate::{
    CLAIM_BYTES, MAXIMUM_LEASE_BYTES, MAXIMUM_RECEIPT_BYTES, MAXIMUM_SIGNATURE_BYTES,
    OwnershipClaimV1, UnverifiedOwnershipLeaseResponse,
};

const REQUEST_MAGIC: &[u8; 8] = b"AOSORQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSORS01";
const HEADER_BYTES: usize = 8 + 32 + 1 + 1 + 2 + 16 + 32 + 4;

enum RecordKind {
    Request,
    Response,
}

struct CarrierHeader<'a> {
    binding: [u8; 32],
    method: OwnershipMethodV1,
    outcome: u8,
    transaction: OwnershipTransactionReferenceV1,
    body: &'a [u8],
}

/// Reports malformed, oversized, or semantically substituted carrier records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipCarrierErrorV1 {
    /// A record exceeds its negotiated or fixed maximum before allocation.
    #[error("ownership carrier record exceeds its bound")]
    Oversized,
    /// A record has invalid framing, fields, lengths, or canonical bytes.
    #[error("ownership carrier record is malformed")]
    Malformed,
    /// A record does not belong to the negotiated session or request.
    #[error("ownership carrier record violates session semantics: {0}")]
    Protocol(#[from] OwnershipProtocolValidationError),
}

/// Encodes an exact request for the already-negotiated ownership session.
///
/// # Errors
///
/// Returns [`OwnershipCarrierErrorV1`] if the request belongs to another
/// session or its complete record exceeds the negotiated request limit.
pub fn encode_request_v1(
    session: &NegotiatedOwnershipSessionV1,
    request: &OwnershipRequestEnvelopeV1,
) -> Result<Vec<u8>, OwnershipCarrierErrorV1> {
    if request.session_binding() != session.binding() {
        return Err(OwnershipProtocolValidationError::SessionBindingMismatch.into());
    }
    let body = match request.body() {
        OwnershipRequestBodyV1::Begin(claim) => claim.canonical_bytes().as_slice(),
        OwnershipRequestBodyV1::CompleteOrResume(_) | OwnershipRequestBodyV1::Query(_) => &[],
    };
    let size = HEADER_BYTES + body.len();
    if size > session.maximum_request_bytes() as usize
        || size > MAXIMUM_OWNERSHIP_REQUEST_BYTES as usize
    {
        return Err(OwnershipCarrierErrorV1::Oversized);
    }

    let mut record = Vec::with_capacity(size);
    record.extend_from_slice(REQUEST_MAGIC);
    record.extend_from_slice(request.session_binding());
    record.push(method_code(request.method()));
    record.extend_from_slice(&[0; 3]);
    append_transaction(&mut record, request.transaction());
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(body);
    Ok(record)
}

/// Decodes one bounded request and validates it against the negotiated session.
///
/// The caller must reject an oversized socket record before allocating its
/// payload. This function repeats the bound for memory-backed callers.
///
/// # Errors
///
/// Returns [`OwnershipCarrierErrorV1`] for oversized, noncanonical, foreign,
/// or method/body-substituted records.
pub fn decode_request_v1(
    session: &NegotiatedOwnershipSessionV1,
    record: &[u8],
) -> Result<OwnershipRequestEnvelopeV1, OwnershipCarrierErrorV1> {
    if record.len() > session.maximum_request_bytes() as usize
        || record.len() > MAXIMUM_OWNERSHIP_REQUEST_BYTES as usize
    {
        return Err(OwnershipCarrierErrorV1::Oversized);
    }
    let header = decode_header(record, RecordKind::Request)?;
    if header.binding != *session.binding() {
        return Err(OwnershipProtocolValidationError::SessionBindingMismatch.into());
    }
    if !session.methods().contains(&header.method) {
        return Err(OwnershipProtocolValidationError::MethodUnavailable.into());
    }
    let decoded = match header.method {
        OwnershipMethodV1::Begin => {
            if header.body.len() != CLAIM_BYTES {
                return Err(OwnershipCarrierErrorV1::Malformed);
            }
            let claim = OwnershipClaimV1::from_canonical_bytes(header.body)
                .map_err(|_| OwnershipCarrierErrorV1::Malformed)?;
            OwnershipRequestBodyV1::Begin(Box::new(claim))
        }
        OwnershipMethodV1::CompleteOrResume => {
            if !header.body.is_empty() {
                return Err(OwnershipCarrierErrorV1::Malformed);
            }
            OwnershipRequestBodyV1::CompleteOrResume(header.transaction)
        }
        OwnershipMethodV1::Query => {
            if !header.body.is_empty() {
                return Err(OwnershipCarrierErrorV1::Malformed);
            }
            OwnershipRequestBodyV1::Query(header.transaction)
        }
    };
    let request = session.validate_request_parts(header.binding, header.method, decoded)?;
    if request.transaction() != header.transaction {
        return Err(OwnershipCarrierErrorV1::Malformed);
    }
    Ok(request)
}

/// Encodes a response validated for its exact originating request.
///
/// # Errors
///
/// Returns [`OwnershipCarrierErrorV1`] for a foreign response or one whose
/// complete record exceeds the negotiated response limit.
pub fn encode_response_v1(
    session: &NegotiatedOwnershipSessionV1,
    request: &OwnershipRequestEnvelopeV1,
    response: &OwnershipResponseEnvelopeV1,
) -> Result<Vec<u8>, OwnershipCarrierErrorV1> {
    crate::protocol::validate_response_binding(session, request, response)?;
    let (outcome_code, body) = encode_outcome(response.outcome())?;
    let size = HEADER_BYTES
        .checked_add(body.len())
        .ok_or(OwnershipCarrierErrorV1::Oversized)?;
    if size > session.maximum_response_bytes() as usize
        || size > MAXIMUM_OWNERSHIP_RESPONSE_BYTES as usize
    {
        return Err(OwnershipCarrierErrorV1::Oversized);
    }

    let mut record = Vec::with_capacity(size);
    record.extend_from_slice(RESPONSE_MAGIC);
    record.extend_from_slice(response.session_binding());
    record.push(method_code(response.method()));
    record.push(outcome_code);
    record.extend_from_slice(&[0; 2]);
    append_transaction(&mut record, response.transaction());
    record.extend_from_slice(&(body.len() as u32).to_be_bytes());
    record.extend_from_slice(&body);
    Ok(record)
}

/// Decodes one bounded response under the original request and session.
///
/// # Errors
///
/// Returns [`OwnershipCarrierErrorV1`] for oversized, noncanonical, foreign,
/// or method/transaction-substituted records.
pub fn decode_response_v1(
    session: &NegotiatedOwnershipSessionV1,
    request: &OwnershipRequestEnvelopeV1,
    record: &[u8],
) -> Result<OwnershipResponseEnvelopeV1, OwnershipCarrierErrorV1> {
    if record.len() > session.maximum_response_bytes() as usize
        || record.len() > MAXIMUM_OWNERSHIP_RESPONSE_BYTES as usize
    {
        return Err(OwnershipCarrierErrorV1::Oversized);
    }
    let header = decode_header(record, RecordKind::Response)?;
    if header.binding != *session.binding() || request.session_binding() != session.binding() {
        return Err(OwnershipProtocolValidationError::SessionBindingMismatch.into());
    }
    if !session.methods().contains(&header.method) {
        return Err(OwnershipProtocolValidationError::MethodUnavailable.into());
    }
    if header.method != request.method() || header.transaction != request.transaction() {
        return Err(OwnershipProtocolValidationError::ResponseBindingMismatch.into());
    }
    let outcome = decode_outcome(header.outcome, header.body)?;
    Ok(session.validate_response_parts(
        request,
        header.binding,
        header.method,
        header.transaction,
        outcome,
    )?)
}

fn append_transaction(record: &mut Vec<u8>, transaction: OwnershipTransactionReferenceV1) {
    record.extend_from_slice(transaction.request_id());
    record.extend_from_slice(transaction.claim_digest().as_bytes());
}

fn decode_header(
    record: &[u8],
    kind: RecordKind,
) -> Result<CarrierHeader<'_>, OwnershipCarrierErrorV1> {
    let magic = match kind {
        RecordKind::Request => REQUEST_MAGIC,
        RecordKind::Response => RESPONSE_MAGIC,
    };
    if record.len() < HEADER_BYTES || record.get(..8) != Some(magic.as_slice()) {
        return Err(OwnershipCarrierErrorV1::Malformed);
    }
    let binding: [u8; 32] = record[8..40]
        .try_into()
        .map_err(|_| OwnershipCarrierErrorV1::Malformed)?;
    let method = method_from_code(record[40])?;
    let outcome = record[41];
    if record[42..44] != [0; 2] || (matches!(kind, RecordKind::Request) && outcome != 0) {
        return Err(OwnershipCarrierErrorV1::Malformed);
    }
    let request_id: [u8; 16] = record[44..60]
        .try_into()
        .map_err(|_| OwnershipCarrierErrorV1::Malformed)?;
    let claim_digest: [u8; 32] = record[60..92]
        .try_into()
        .map_err(|_| OwnershipCarrierErrorV1::Malformed)?;
    let transaction =
        OwnershipTransactionReferenceV1::new(request_id, ObjectDigest::from_bytes(claim_digest))?;
    let body_length = u32::from_be_bytes(
        record[92..96]
            .try_into()
            .map_err(|_| OwnershipCarrierErrorV1::Malformed)?,
    ) as usize;
    if body_length != record.len() - HEADER_BYTES {
        return Err(OwnershipCarrierErrorV1::Malformed);
    }
    Ok(CarrierHeader {
        binding,
        method,
        outcome,
        transaction,
        body: &record[HEADER_BYTES..],
    })
}

const fn method_code(method: OwnershipMethodV1) -> u8 {
    match method {
        OwnershipMethodV1::Begin => 1,
        OwnershipMethodV1::CompleteOrResume => 2,
        OwnershipMethodV1::Query => 3,
    }
}

fn method_from_code(code: u8) -> Result<OwnershipMethodV1, OwnershipCarrierErrorV1> {
    match code {
        1 => Ok(OwnershipMethodV1::Begin),
        2 => Ok(OwnershipMethodV1::CompleteOrResume),
        3 => Ok(OwnershipMethodV1::Query),
        _ => Err(OwnershipCarrierErrorV1::Malformed),
    }
}

fn encode_outcome(
    outcome: &OwnershipResponseOutcomeV1,
) -> Result<(u8, Vec<u8>), OwnershipCarrierErrorV1> {
    match outcome {
        OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Absent) => {
            Ok((1, Vec::new()))
        }
        OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Pending) => {
            Ok((2, Vec::new()))
        }
        OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(artifacts)) => {
            let mut body = Vec::new();
            for bytes in [
                artifacts.lease(),
                artifacts.signature(),
                artifacts.receipt(),
                artifacts.receipt_signature(),
            ] {
                let length =
                    u32::try_from(bytes.len()).map_err(|_| OwnershipCarrierErrorV1::Oversized)?;
                body.extend_from_slice(&length.to_be_bytes());
                body.extend_from_slice(bytes);
            }
            Ok((3, body))
        }
        OwnershipResponseOutcomeV1::Error(error) => Ok((error_code(*error), Vec::new())),
    }
}

fn decode_outcome(
    code: u8,
    body: &[u8],
) -> Result<OwnershipResponseOutcomeV1, OwnershipCarrierErrorV1> {
    let status = match code {
        1 if body.is_empty() => OwnershipTransactionStatusV1::Absent,
        2 if body.is_empty() => OwnershipTransactionStatusV1::Pending,
        3 => OwnershipTransactionStatusV1::Completed(decode_artifacts(body)?),
        4..=18 if body.is_empty() => {
            return Ok(OwnershipResponseOutcomeV1::Error(error_from_code(code)?));
        }
        _ => return Err(OwnershipCarrierErrorV1::Malformed),
    };
    Ok(OwnershipResponseOutcomeV1::Status(status))
}

fn decode_artifacts(
    body: &[u8],
) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipCarrierErrorV1> {
    let mut offset = 0;
    let lease = take_artifact(body, &mut offset, MAXIMUM_LEASE_BYTES)?;
    let signature = take_artifact(body, &mut offset, MAXIMUM_SIGNATURE_BYTES)?;
    let receipt = take_artifact(body, &mut offset, MAXIMUM_RECEIPT_BYTES)?;
    let receipt_signature = take_artifact(body, &mut offset, MAXIMUM_SIGNATURE_BYTES)?;
    if offset != body.len() {
        return Err(OwnershipCarrierErrorV1::Malformed);
    }
    UnverifiedOwnershipLeaseResponse::from_transport(lease, signature, receipt, receipt_signature)
        .map_err(|_| OwnershipCarrierErrorV1::Malformed)
}

fn take_artifact(
    body: &[u8],
    offset: &mut usize,
    maximum: usize,
) -> Result<Vec<u8>, OwnershipCarrierErrorV1> {
    let length_bytes = body
        .get(*offset..*offset + 4)
        .ok_or(OwnershipCarrierErrorV1::Malformed)?;
    let length = u32::from_be_bytes(
        length_bytes
            .try_into()
            .map_err(|_| OwnershipCarrierErrorV1::Malformed)?,
    ) as usize;
    *offset += 4;
    if length == 0 || length > maximum {
        return Err(OwnershipCarrierErrorV1::Malformed);
    }
    let end = offset
        .checked_add(length)
        .ok_or(OwnershipCarrierErrorV1::Malformed)?;
    let artifact = body
        .get(*offset..end)
        .ok_or(OwnershipCarrierErrorV1::Malformed)?
        .to_vec();
    *offset = end;
    Ok(artifact)
}

const fn error_code(error: OwnershipProtocolErrorCodeV1) -> u8 {
    match error {
        OwnershipProtocolErrorCodeV1::InvalidRequest => 4,
        OwnershipProtocolErrorCodeV1::Unauthenticated => 5,
        OwnershipProtocolErrorCodeV1::PermissionDenied => 6,
        OwnershipProtocolErrorCodeV1::IncompatibleProtocol => 7,
        OwnershipProtocolErrorCodeV1::RequiredCapabilityUnavailable => 8,
        OwnershipProtocolErrorCodeV1::WrongAuthorityEpoch => 9,
        OwnershipProtocolErrorCodeV1::IdempotencyConflict => 10,
        OwnershipProtocolErrorCodeV1::AlreadyOwned => 11,
        OwnershipProtocolErrorCodeV1::StaleExpectedPrior => 12,
        OwnershipProtocolErrorCodeV1::NotFound => 13,
        OwnershipProtocolErrorCodeV1::ResourceExhausted => 14,
        OwnershipProtocolErrorCodeV1::DeadlineExceeded => 15,
        OwnershipProtocolErrorCodeV1::Unavailable => 16,
        OwnershipProtocolErrorCodeV1::IntegrityFailure => 17,
        OwnershipProtocolErrorCodeV1::Internal => 18,
    }
}

fn error_from_code(code: u8) -> Result<OwnershipProtocolErrorCodeV1, OwnershipCarrierErrorV1> {
    match code {
        4 => Ok(OwnershipProtocolErrorCodeV1::InvalidRequest),
        5 => Ok(OwnershipProtocolErrorCodeV1::Unauthenticated),
        6 => Ok(OwnershipProtocolErrorCodeV1::PermissionDenied),
        7 => Ok(OwnershipProtocolErrorCodeV1::IncompatibleProtocol),
        8 => Ok(OwnershipProtocolErrorCodeV1::RequiredCapabilityUnavailable),
        9 => Ok(OwnershipProtocolErrorCodeV1::WrongAuthorityEpoch),
        10 => Ok(OwnershipProtocolErrorCodeV1::IdempotencyConflict),
        11 => Ok(OwnershipProtocolErrorCodeV1::AlreadyOwned),
        12 => Ok(OwnershipProtocolErrorCodeV1::StaleExpectedPrior),
        13 => Ok(OwnershipProtocolErrorCodeV1::NotFound),
        14 => Ok(OwnershipProtocolErrorCodeV1::ResourceExhausted),
        15 => Ok(OwnershipProtocolErrorCodeV1::DeadlineExceeded),
        16 => Ok(OwnershipProtocolErrorCodeV1::Unavailable),
        17 => Ok(OwnershipProtocolErrorCodeV1::IntegrityFailure),
        18 => Ok(OwnershipProtocolErrorCodeV1::Internal),
        _ => Err(OwnershipCarrierErrorV1::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::model::{KeyReference, KeyUsage, StableKeyId};
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, IncarnationId, LeaseAssignment, NodeId,
        ProtocolVersion, SandboxId,
    };

    use super::*;
    use crate::protocol::OwnershipClientHelloV1;

    fn session() -> NegotiatedOwnershipSessionV1 {
        let authority = KeyReference::new(
            StableKeyId::new("ownership-carrier-test".to_owned()).unwrap(),
            7,
            ObjectDigest::from_bytes([8; 32]),
            KeyUsage::OwnershipLease,
        );
        let methods = vec![
            OwnershipMethodV1::Begin,
            OwnershipMethodV1::CompleteOrResume,
            OwnershipMethodV1::Query,
        ];
        let hello = OwnershipClientHelloV1::new(
            [9; 32],
            ProtocolVersion::new(1, 0),
            authority.clone(),
            methods.clone(),
            MAXIMUM_OWNERSHIP_RESPONSE_BYTES,
        )
        .unwrap();
        NegotiatedOwnershipSessionV1::negotiate(&hello, [10; 32], authority, methods).unwrap()
    }

    fn claim() -> OwnershipClaimV1 {
        let assignment = LeaseAssignment::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([4; 32]),
        )
        .unwrap();
        OwnershipClaimV1::acquire(
            [5; 16],
            assignment,
            DesiredGeneration::new(6),
            NodeId::from_bytes([7; 16]),
            60,
        )
        .unwrap()
    }

    #[test]
    fn canonical_request_round_trips_and_rejects_substitution() {
        let session = session();
        let request = session
            .request(OwnershipRequestBodyV1::Begin(Box::new(claim())))
            .unwrap();
        let encoded = encode_request_v1(&session, &request).unwrap();
        assert_eq!(decode_request_v1(&session, &encoded), Ok(request.clone()));

        let mut wrong_method = encoded.clone();
        wrong_method[40] = method_code(OwnershipMethodV1::Query);
        assert_eq!(
            decode_request_v1(&session, &wrong_method),
            Err(OwnershipCarrierErrorV1::Malformed)
        );

        let mut wrong_claim = encoded.clone();
        wrong_claim[60] ^= 1;
        assert_eq!(
            decode_request_v1(&session, &wrong_claim),
            Err(OwnershipCarrierErrorV1::Malformed)
        );

        let mut foreign_session = encoded;
        foreign_session[8] ^= 1;
        assert!(matches!(
            decode_request_v1(&session, &foreign_session),
            Err(OwnershipCarrierErrorV1::Protocol(
                OwnershipProtocolValidationError::SessionBindingMismatch
            ))
        ));
    }

    #[test]
    fn completed_response_round_trips_exact_artifacts() {
        let session = session();
        let request = session
            .request(OwnershipRequestBodyV1::Query(
                OwnershipTransactionReferenceV1::from_claim(&claim()),
            ))
            .unwrap();
        let artifacts = UnverifiedOwnershipLeaseResponse::from_transport(
            vec![1; 128],
            vec![2; 64],
            vec![3; 96],
            vec![4; 64],
        )
        .unwrap();
        let response = session
            .response(
                &request,
                OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(
                    artifacts,
                )),
            )
            .unwrap();
        let encoded = encode_response_v1(&session, &request, &response).unwrap();
        assert_eq!(
            decode_response_v1(&session, &request, &encoded),
            Ok(response)
        );

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(
            decode_response_v1(&session, &request, &truncated),
            Err(OwnershipCarrierErrorV1::Malformed)
        );

        let mut wrong_transaction = encoded;
        wrong_transaction[44] ^= 1;
        assert!(matches!(
            decode_response_v1(&session, &request, &wrong_transaction),
            Err(OwnershipCarrierErrorV1::Protocol(
                OwnershipProtocolValidationError::ResponseBindingMismatch
            ))
        ));
    }

    #[test]
    fn status_and_error_responses_keep_the_method_matrix() {
        let session = session();
        let reference = OwnershipTransactionReferenceV1::from_claim(&claim());
        let query = session
            .request(OwnershipRequestBodyV1::Query(reference))
            .unwrap();
        let begin = session
            .request(OwnershipRequestBodyV1::Begin(Box::new(claim())))
            .unwrap();

        for status in [
            OwnershipTransactionStatusV1::Absent,
            OwnershipTransactionStatusV1::Pending,
        ] {
            let response = session
                .response(&query, OwnershipResponseOutcomeV1::Status(status))
                .unwrap();
            let encoded = encode_response_v1(&session, &query, &response).unwrap();
            assert_eq!(decode_response_v1(&session, &query, &encoded), Ok(response));
        }

        let response = session
            .response(
                &begin,
                OwnershipResponseOutcomeV1::Error(OwnershipProtocolErrorCodeV1::AlreadyOwned),
            )
            .unwrap();
        let encoded = encode_response_v1(&session, &begin, &response).unwrap();
        assert_eq!(decode_response_v1(&session, &begin, &encoded), Ok(response));

        let mut invalid_begin_absent = encoded;
        invalid_begin_absent[41] = 1;
        assert!(matches!(
            decode_response_v1(&session, &begin, &invalid_begin_absent),
            Err(OwnershipCarrierErrorV1::Protocol(
                OwnershipProtocolValidationError::InvalidResponseStatus
            ))
        ));
    }

    #[test]
    fn oversized_records_fail_before_body_decode() {
        let session = session();
        let request = vec![0; MAXIMUM_OWNERSHIP_REQUEST_BYTES as usize + 1];
        let response = vec![0; MAXIMUM_OWNERSHIP_RESPONSE_BYTES as usize + 1];
        let query = session
            .request(OwnershipRequestBodyV1::Query(
                OwnershipTransactionReferenceV1::from_claim(&claim()),
            ))
            .unwrap();

        assert_eq!(
            decode_request_v1(&session, &request),
            Err(OwnershipCarrierErrorV1::Oversized)
        );
        assert_eq!(
            decode_response_v1(&session, &query, &response),
            Err(OwnershipCarrierErrorV1::Oversized)
        );
    }
}
