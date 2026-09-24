//! Authenticated transport for provisional Host output reserve and readback.
//!
//! Method 35 carries the exact fixed AOSCIR01 source inline because it is
//! bounded to 688 bytes. Parsing a carrier does not authenticate accepted
//! Create; a matching Host-audience plan/lease and protected Host journal are
//! still required before AOSEOR02 can be reserved. Method 36 is read-only and
//! may resolve only the original method-35 attempt.

use aos_proto::aos::sandbox::local::v1::{
    HostExecutionOutputReservationStatusV1, HostExecutionOutputReservationV1,
    QueryHostExecutionOutputRequestV1, ReserveHostExecutionOutputRequestV1,
};
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId, ProtocolId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_request_header,
};

/// Exact canonical byte count of the AOSCIR01 reserve source.
pub const HOST_OUTPUT_RESERVE_SOURCE_BYTES_V1: usize = 688;
const MAXIMUM_REQUEST_BODY_BYTES: usize = 4 * 1_024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 1_024;

/// Names one original Host output reservation attempt and its signed source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostOutputReservationLocatorV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    original_request_id: [u8; 16],
    preissue_digest: ObjectDigest,
    claim_digest: ObjectDigest,
    carrier_digest: ObjectDigest,
    assignment_digest: ObjectDigest,
    host_boot_id: [u8; 16],
}

impl HostOutputReservationLocatorV1 {
    /// Returns the accepted execution identifier.
    #[must_use]
    pub const fn execution(self) -> ExecutionId {
        self.execution
    }

    /// Returns the accepted Create operation identifier.
    #[must_use]
    pub const fn create_operation(self) -> OperationId {
        self.create_operation
    }

    /// Returns the original method-35 broker request identifier.
    #[must_use]
    pub const fn original_request_id(self) -> [u8; 16] {
        self.original_request_id
    }

    /// Returns the protected AOSCIP01 record digest.
    #[must_use]
    pub const fn preissue_digest(self) -> ObjectDigest {
        self.preissue_digest
    }

    /// Returns raw SHA-256 of the exact AOSEOR02 claim bytes.
    #[must_use]
    pub const fn claim_digest(self) -> ObjectDigest {
        self.claim_digest
    }

    /// Returns the domain-separated AOSCIR01 carrier digest.
    #[must_use]
    pub const fn carrier_digest(self) -> ObjectDigest {
        self.carrier_digest
    }

    /// Returns the exact current assignment-manifest digest.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the original Host kernel boot identifier.
    #[must_use]
    pub const fn host_boot_id(self) -> [u8; 16] {
        self.host_boot_id
    }
}

/// Retains a canonical method-35 request pending independent Host authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostOutputReserveRequestV1 {
    header: ValidatedHeader,
    source: [u8; HOST_OUTPUT_RESERVE_SOURCE_BYTES_V1],
    locator: HostOutputReservationLocatorV1,
}

impl ValidatedHostOutputReserveRequestV1 {
    /// Returns the authenticated broker request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows exact inline AOSCIR01 bytes for structural and signed-grant checks.
    #[must_use]
    pub const fn source(&self) -> &[u8; HOST_OUTPUT_RESERVE_SOURCE_BYTES_V1] {
        &self.source
    }

    /// Returns the original attempt locator implied by the carrier.
    #[must_use]
    pub const fn locator(&self) -> HostOutputReservationLocatorV1 {
        self.locator
    }
}

/// Retains a canonical read-only method-36 query for one original attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostOutputQueryRequestV1 {
    header: ValidatedHeader,
    locator: HostOutputReservationLocatorV1,
}

impl ValidatedHostOutputQueryRequestV1 {
    /// Returns the authenticated readback request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact original attempt locator.
    #[must_use]
    pub const fn locator(&self) -> HostOutputReservationLocatorV1 {
        self.locator
    }
}

/// Distinguishes protected absence from one completed original reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOutputReservationStatusV1 {
    /// No matching Host claim or correlation exists under the current owner.
    Absent,
    /// The exact original Host claim/correlation pair committed.
    Committed,
}

/// Retains a cross-linked response after authenticated session verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostOutputReservationV1 {
    status: HostOutputReservationStatusV1,
    locator: HostOutputReservationLocatorV1,
    original_plan_digest: Option<ObjectDigest>,
    original_semantic_request_digest: Option<ObjectDigest>,
    correlation_digest: Option<ObjectDigest>,
    original_host_journal_sequence: Option<u64>,
}

impl ValidatedHostOutputReservationV1 {
    /// Returns whether the Host observed absence or a completed reservation.
    #[must_use]
    pub const fn status(self) -> HostOutputReservationStatusV1 {
        self.status
    }

    /// Returns the exact original attempt locator echoed in the response.
    #[must_use]
    pub const fn locator(self) -> HostOutputReservationLocatorV1 {
        self.locator
    }

    /// Returns the original signed broker-plan digest when committed.
    #[must_use]
    pub const fn original_plan_digest(self) -> Option<ObjectDigest> {
        self.original_plan_digest
    }

    /// Returns the original semantic request digest when committed.
    #[must_use]
    pub const fn original_semantic_request_digest(self) -> Option<ObjectDigest> {
        self.original_semantic_request_digest
    }

    /// Returns the protected AOSHOP01 record digest when committed.
    #[must_use]
    pub const fn correlation_digest(self) -> Option<ObjectDigest> {
        self.correlation_digest
    }

    /// Returns the original Host journal sequence when committed.
    #[must_use]
    pub const fn original_host_journal_sequence(self) -> Option<u64> {
        self.original_host_journal_sequence
    }
}

/// Decodes one canonical method-35 request without claiming Create authority.
///
/// # Errors
///
/// Rejects a malformed or oversized body, invalid broker header, or carrier
/// whose fixed locator/version fields cannot be cross-linked.
pub fn decode_host_output_reserve_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostOutputReserveRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ReserveHostExecutionOutputRequestV1::decode_from_slice(body)
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
    let source: [u8; HOST_OUTPUT_RESERVE_SOURCE_BYTES_V1] = request
        .canonical_source
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("canonical_source"))?;
    let locator = host_output_locator_from_source_v1(&source, *header.request_id())?;
    Ok(ValidatedHostOutputReserveRequestV1 {
        header,
        source,
        locator,
    })
}

/// Decodes one canonical method-36 query for a retained original attempt.
///
/// # Errors
///
/// Rejects a malformed or oversized body, invalid broker header, or missing
/// exact original attempt fields.
pub fn decode_host_output_query_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostOutputQueryRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryHostExecutionOutputRequestV1::decode_from_slice(body)
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
    let locator = HostOutputReservationLocatorV1 {
        execution: ExecutionId::from_bytes(exact_nonzero::<16>(
            &request.execution_id,
            "execution_id",
        )?),
        create_operation: OperationId::from_bytes(exact_nonzero::<16>(
            &request.create_operation_id,
            "create_operation_id",
        )?),
        original_request_id: exact_nonzero::<16>(
            &request.original_reserve_request_id,
            "original_reserve_request_id",
        )?,
        preissue_digest: digest(&request.preissue_record_digest, "preissue_record_digest")?,
        claim_digest: digest(&request.output_claim_digest, "output_claim_digest")?,
        carrier_digest: digest(&request.reserve_source_digest, "reserve_source_digest")?,
        assignment_digest: digest(&request.assignment_digest, "assignment_digest")?,
        host_boot_id: exact_nonzero::<16>(&request.host_boot_id, "host_boot_id")?,
    };
    Ok(ValidatedHostOutputQueryRequestV1 { header, locator })
}

/// Decodes and cross-links one signed-session Host reserve/query response.
///
/// The caller must first authenticate the session outcome. A successful
/// method-35 response must be committed; method 36 may observe absence.
///
/// # Errors
///
/// Rejects noncanonical, foreign-locator, or partial committed/absent bodies.
pub fn decode_host_output_reservation_response_v1(
    body: &[u8],
    locator: HostOutputReservationLocatorV1,
    allow_absent: bool,
) -> Result<ValidatedHostOutputReservationV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = HostExecutionOutputReservationV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let echoed = HostOutputReservationLocatorV1 {
        execution: ExecutionId::from_bytes(exact_nonzero::<16>(
            &response.execution_id,
            "execution_id",
        )?),
        create_operation: OperationId::from_bytes(exact_nonzero::<16>(
            &response.create_operation_id,
            "create_operation_id",
        )?),
        original_request_id: exact_nonzero::<16>(
            &response.original_reserve_request_id,
            "original_reserve_request_id",
        )?,
        preissue_digest: digest(&response.preissue_record_digest, "preissue_record_digest")?,
        claim_digest: digest(&response.output_claim_digest, "output_claim_digest")?,
        carrier_digest: digest(&response.reserve_source_digest, "reserve_source_digest")?,
        assignment_digest: digest(&response.assignment_digest, "assignment_digest")?,
        host_boot_id: exact_nonzero::<16>(&response.host_boot_id, "host_boot_id")?,
    };
    if echoed != locator {
        return Err(ProtocolValidationError::InvalidField("Host output locator"));
    }
    let status = match response.status.as_known() {
        Some(HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_ABSENT)
            if allow_absent
                && response.original_plan_digest.is_empty()
                && response.original_semantic_request_digest.is_empty()
                && response.host_correlation_record_digest.is_empty()
                && response.original_host_journal_sequence == 0 => HostOutputReservationStatusV1::Absent,
        Some(HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_COMMITTED)
            if response.original_host_journal_sequence != 0 => HostOutputReservationStatusV1::Committed,
        _ => return Err(ProtocolValidationError::InvalidField("Host output status")),
    };
    let (
        original_plan_digest,
        original_semantic_request_digest,
        correlation_digest,
        original_host_journal_sequence,
    ) = match status {
        HostOutputReservationStatusV1::Absent => (None, None, None, None),
        HostOutputReservationStatusV1::Committed => (
            Some(digest(
                &response.original_plan_digest,
                "original_plan_digest",
            )?),
            Some(digest(
                &response.original_semantic_request_digest,
                "original_semantic_request_digest",
            )?),
            Some(digest(
                &response.host_correlation_record_digest,
                "host_correlation_record_digest",
            )?),
            Some(response.original_host_journal_sequence),
        ),
    };
    Ok(ValidatedHostOutputReservationV1 {
        status,
        locator,
        original_plan_digest,
        original_semantic_request_digest,
        correlation_digest,
        original_host_journal_sequence,
    })
}

fn digest(bytes: &[u8], field: &'static str) -> Result<ObjectDigest, ProtocolValidationError> {
    Ok(ObjectDigest::from_bytes(exact_nonzero::<32>(bytes, field)?))
}

/// Extracts the original attempt locator from a fixed AOSCIR01 carrier.
///
/// This is a structural readback for authenticated-session correlation; it
/// does not validate the Controller's protected accepted-Create source or
/// authorize a Host reservation.
///
/// # Errors
///
/// Rejects a zero request identifier or malformed fixed carrier fields.
pub fn host_output_locator_from_source_v1(
    source: &[u8; HOST_OUTPUT_RESERVE_SOURCE_BYTES_V1],
    request_id: [u8; 16],
) -> Result<HostOutputReservationLocatorV1, ProtocolValidationError> {
    if request_id == [0; 16]
        || &source[..8] != b"AOSCIR01"
        || &source[8..16] != b"AOSCIP01"
        || &source[192..200] != b"AOSEOR02"
        || source[16..32] == [0; 16]
        || source[32..48] == [0; 16]
        || source[16..32] != source[200..216]
        || source[32..48] != source[216..232]
        || source[104..120] == [0; 16]
        || source[160..192] == [0; 32]
        || source[624..656] == [0; 32]
        || source[656..688] == [0; 32]
    {
        return Err(ProtocolValidationError::InvalidField("canonical_source"));
    }
    Ok(HostOutputReservationLocatorV1 {
        execution: ExecutionId::from_bytes(
            source[16..32]
                .try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("canonical_source"))?,
        ),
        create_operation: OperationId::from_bytes(
            source[32..48]
                .try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("canonical_source"))?,
        ),
        original_request_id: request_id,
        preissue_digest: ObjectDigest::from_bytes(
            source[160..192]
                .try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("canonical_source"))?,
        ),
        claim_digest: ObjectDigest::from_bytes(Sha256::digest(&source[192..520]).into()),
        carrier_digest: ObjectDigest::from_bytes(
            source[656..688]
                .try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("canonical_source"))?,
        ),
        assignment_digest: ObjectDigest::from_bytes(
            source[624..656]
                .try_into()
                .map_err(|_| ProtocolValidationError::InvalidField("canonical_source"))?,
        ),
        host_boot_id: source[104..120]
            .try_into()
            .map_err(|_| ProtocolValidationError::InvalidField("canonical_source"))?,
    })
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};

    use super::*;

    fn fixture() -> (
        ReserveHostExecutionOutputRequestV1,
        PeerCredentials,
        PeerPolicy,
    ) {
        let mut source = vec![0_u8; HOST_OUTPUT_RESERVE_SOURCE_BYTES_V1];
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
        let request = ReserveHostExecutionOutputRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![7; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            canonical_source: source,
            ..Default::default()
        };
        let peer = PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(9),
        };
        let policy = PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };
        (request, peer, policy)
    }

    fn response(locator: HostOutputReservationLocatorV1) -> HostExecutionOutputReservationV1 {
        HostExecutionOutputReservationV1 {
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
            original_host_journal_sequence: 11,
            ..Default::default()
        }
    }

    #[test]
    fn reserve_and_response_bind_original_attempt_and_source() {
        let (mut request, peer, policy) = fixture();
        let validated =
            decode_host_output_reserve_request_v1(&request.encode_to_vec(), peer, policy, 99)
                .unwrap();
        let locator = validated.locator();
        assert_eq!(locator.original_request_id(), [7; 16]);
        assert_eq!(locator.execution(), ExecutionId::from_bytes([1; 16]));

        let mut committed = response(locator);
        assert_eq!(
            decode_host_output_reservation_response_v1(&committed.encode_to_vec(), locator, false,)
                .unwrap()
                .status(),
            HostOutputReservationStatusV1::Committed
        );
        committed.original_reserve_request_id[0] ^= 1;
        assert!(
            decode_host_output_reservation_response_v1(&committed.encode_to_vec(), locator, false,)
                .is_err()
        );

        request.canonical_source[200] ^= 1;
        assert!(
            decode_host_output_reserve_request_v1(&request.encode_to_vec(), peer, policy, 99,)
                .is_err()
        );
    }

    #[test]
    fn query_can_observe_absence_but_reserve_cannot() {
        let (reserve, peer, policy) = fixture();
        let original =
            decode_host_output_reserve_request_v1(&reserve.encode_to_vec(), peer, policy, 99)
                .unwrap();
        let locator = original.locator();
        let query = QueryHostExecutionOutputRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![12; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            execution_id: locator.execution().as_bytes().to_vec(),
            create_operation_id: locator.create_operation().as_bytes().to_vec(),
            original_reserve_request_id: locator.original_request_id().to_vec(),
            preissue_record_digest: locator.preissue_digest().as_bytes().to_vec(),
            output_claim_digest: locator.claim_digest().as_bytes().to_vec(),
            reserve_source_digest: locator.carrier_digest().as_bytes().to_vec(),
            assignment_digest: locator.assignment_digest().as_bytes().to_vec(),
            host_boot_id: locator.host_boot_id().to_vec(),
            ..Default::default()
        };
        let validated =
            decode_host_output_query_request_v1(&query.encode_to_vec(), peer, policy, 99).unwrap();
        assert_eq!(validated.locator(), locator);

        let mut absent = response(locator);
        absent.status =
            HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_ABSENT
                .into();
        absent.original_plan_digest.clear();
        absent.original_semantic_request_digest.clear();
        absent.host_correlation_record_digest.clear();
        absent.original_host_journal_sequence = 0;
        assert!(
            decode_host_output_reservation_response_v1(&absent.encode_to_vec(), locator, true,)
                .is_ok()
        );
        assert!(
            decode_host_output_reservation_response_v1(&absent.encode_to_vec(), locator, false,)
                .is_err()
        );
    }
}
