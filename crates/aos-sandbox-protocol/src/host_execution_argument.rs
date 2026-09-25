//! Strict, nonauthorizing method-37/38 AOSCIA02 request transport.
//!
//! A bounded protobuf carries the exact 336-byte Controller attempt inline.
//! Decoding checks canonical wire form, source checksum, and original versus
//! fresh session request IDs. Only a pinned signed plan plus current Host
//! protected owners can authorize a live Guest observation.

use aos_proto::aos::sandbox::local::v1::{
    ObserveHostExecutionArgumentRequestV1, ObserveHostExecutionArgumentResponseV1,
    QueryHostExecutionArgumentRequestV1, QueryHostExecutionArgumentResponseV1,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use crate::semantics::host_execution_argument::canonical_attempt_request_id_v1;
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, validate_request_header,
};

pub mod receipt;

use receipt::{HostExecutionArgumentFreshReceiptV1, HostExecutionArgumentHistoricalReceiptV1};

/// Exact canonical AOSCIA02 byte count.
pub const HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1: usize = 336;
const MAXIMUM_REQUEST_BODY_BYTES: usize = 2 * 1_024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 4 * 1_024;

/// Decodes one fresh Host-attested observation bound to the exact original attempt.
///
/// # Errors
///
/// Rejects an oversized/noncanonical wrapper, invalid AOSHAR01, or a source
/// that differs from the authenticated method-37 request.
pub fn decode_host_execution_argument_observe_response_v1(
    body: &[u8],
    canonical_attempt: &[u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
) -> Result<HostExecutionArgumentFreshReceiptV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = ObserveHostExecutionArgumentResponseV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let receipt =
        HostExecutionArgumentFreshReceiptV1::decode_canonical(&response.canonical_receipt)
            .map_err(|_| ProtocolValidationError::InvalidField("canonical_receipt"))?;
    if receipt.source() != canonical_attempt {
        return Err(ProtocolValidationError::InvalidField("canonical_receipt"));
    }
    Ok(receipt)
}

/// Decodes a historical, digest-only Host argument observation reply.
///
/// # Errors
///
/// Rejects an oversized/noncanonical wrapper, invalid AOSHQR01, or a source
/// that differs from the authenticated method-38 request.
pub fn decode_host_execution_argument_query_response_v1(
    body: &[u8],
    canonical_attempt: &[u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
) -> Result<HostExecutionArgumentHistoricalReceiptV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = QueryHostExecutionArgumentResponseV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let receipt = HostExecutionArgumentHistoricalReceiptV1::decode_canonical(
        &response.canonical_historical_receipt,
    )
    .map_err(|_| ProtocolValidationError::InvalidField("canonical_historical_receipt"))?;
    if receipt.source() != canonical_attempt {
        return Err(ProtocolValidationError::InvalidField(
            "canonical_historical_receipt",
        ));
    }
    Ok(receipt)
}

/// Retains structurally checked, still nonauthorizing Controller attempt bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostExecutionArgumentRequestV1 {
    header: ValidatedHeader,
    canonical_attempt: [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1],
    original_request_id: [u8; 16],
}

impl ValidatedHostExecutionArgumentRequestV1 {
    /// Returns the authenticated broker request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows the exact signed-plan source bytes for independent Host checks.
    #[must_use]
    pub const fn canonical_attempt(&self) -> &[u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] {
        &self.canonical_attempt
    }

    /// Returns the original one-shot method-37 broker request ID.
    #[must_use]
    pub const fn original_request_id(&self) -> [u8; 16] {
        self.original_request_id
    }
}

/// Decodes an original one-shot observe request without granting an effect.
///
/// # Errors
///
/// Rejects an oversized/noncanonical body, invalid header, malformed AOSCIA02,
/// or a source not bound to this method-37 session request ID.
pub fn decode_host_execution_argument_observe_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostExecutionArgumentRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ObserveHostExecutionArgumentRequestV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    validate_source(header, &request.canonical_attempt, false)
}

/// Decodes a read-only query of the original method-37 attempt.
///
/// # Errors
///
/// Rejects an oversized/noncanonical body, invalid header or AOSCIA02, or
/// reuse of the original request ID instead of a fresh query ID.
pub fn decode_host_execution_argument_query_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostExecutionArgumentRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryHostExecutionArgumentRequestV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    validate_source(header, &request.canonical_attempt, true)
}

fn validate_source(
    header: ValidatedHeader,
    source: &[u8],
    query: bool,
) -> Result<ValidatedHostExecutionArgumentRequestV1, ProtocolValidationError> {
    let canonical_attempt: [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] = source
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("canonical_attempt"))?;
    let original_request_id = canonical_attempt_request_id_v1(&canonical_attempt)
        .map_err(|_| ProtocolValidationError::InvalidField("canonical_attempt"))?;
    if (query && original_request_id == *header.request_id())
        || (!query && original_request_id != *header.request_id())
    {
        return Err(ProtocolValidationError::InvalidField("canonical_attempt"));
    }
    Ok(ValidatedHostExecutionArgumentRequestV1 {
        header,
        canonical_attempt,
        original_request_id,
    })
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        Audience, ObserveHostExecutionArgumentRequestV1, ObserveHostExecutionArgumentResponseV1,
        QueryHostExecutionArgumentRequestV1, QueryHostExecutionArgumentResponseV1, RequestHeader,
    };
    use aos_sandbox_core::ObjectDigest;
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn source() -> [u8; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1] {
        let mut source = [0; HOST_EXECUTION_ARGUMENT_ATTEMPT_BYTES_V1];
        source[..8].copy_from_slice(b"AOSCIA02");
        source[8..40].fill(1);
        source[40..56].copy_from_slice(&[7; 16]);
        source[56..184].fill(2);
        source[184..216].copy_from_slice(&[5; 32]);
        source[216..304].fill(3);
        let checksum: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&source[..304])
            .finalize()
            .into();
        source[304..].copy_from_slice(&checksum);
        source
    }

    fn header(request_id: [u8; 16]) -> RequestHeader {
        RequestHeader {
            protocol_major: 1,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 100,
            maximum_response_bytes: 8192,
            ..Default::default()
        }
    }

    fn peer_policy() -> (PeerCredentials, PeerPolicy) {
        (
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(9),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
        )
    }

    #[test]
    fn original_and_query_bind_distinct_session_request_ids() {
        let (peer, policy) = peer_policy();
        let original = ObserveHostExecutionArgumentRequestV1 {
            header: Some(header([7; 16])).into(),
            canonical_attempt: source().to_vec(),
            ..Default::default()
        };
        let observed = decode_host_execution_argument_observe_request_v1(
            &original.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap();
        assert_eq!(observed.original_request_id(), [7; 16]);

        let query = QueryHostExecutionArgumentRequestV1 {
            header: Some(header([8; 16])).into(),
            canonical_attempt: source().to_vec(),
            ..Default::default()
        };
        assert!(
            decode_host_execution_argument_query_request_v1(
                &query.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_ok()
        );
        let mut replayed_query = query;
        replayed_query.header = Some(header([7; 16])).into();
        assert!(
            decode_host_execution_argument_query_request_v1(
                &replayed_query.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );

        let mut changed_source = original;
        changed_source.canonical_attempt[120..152].fill(0);
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&changed_source.canonical_attempt[..304])
            .finalize();
        changed_source.canonical_attempt[304..].copy_from_slice(&checksum);
        assert!(
            decode_host_execution_argument_observe_request_v1(
                &changed_source.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );
        let changed_query = QueryHostExecutionArgumentRequestV1 {
            header: Some(header([8; 16])).into(),
            canonical_attempt: changed_source.canonical_attempt,
            ..Default::default()
        };
        assert!(
            decode_host_execution_argument_query_request_v1(
                &changed_query.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );
    }

    #[test]
    fn historical_response_echoes_exact_original_attempt() {
        assert!(
            receipt::MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1 + 8
                <= MAXIMUM_RESPONSE_BODY_BYTES
        );
        let receipt = HostExecutionArgumentHistoricalReceiptV1::new(
            source(),
            receipt::HistoricalHostArgumentStatusV1::Absent,
            ObjectDigest::from_bytes([0; 32]),
            ObjectDigest::from_bytes([0; 32]),
            ObjectDigest::from_bytes([0; 32]),
            0,
        )
        .unwrap();
        let response = QueryHostExecutionArgumentResponseV1 {
            canonical_historical_receipt: receipt.canonical_bytes().to_vec(),
            ..Default::default()
        };
        assert_eq!(
            decode_host_execution_argument_query_response_v1(&response.encode_to_vec(), &source())
                .unwrap(),
            receipt,
        );

        let mut foreign = source();
        foreign[120] ^= 1;
        assert!(
            decode_host_execution_argument_query_response_v1(&response.encode_to_vec(), &foreign)
                .is_err()
        );
        let invalid_fresh = ObserveHostExecutionArgumentResponseV1 {
            canonical_receipt: receipt.canonical_bytes().to_vec(),
            ..Default::default()
        };
        assert!(
            decode_host_execution_argument_observe_response_v1(
                &invalid_fresh.encode_to_vec(),
                &source(),
            )
            .is_err()
        );
    }
}
