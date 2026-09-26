//! Versioned, nonauthorizing Host failed-Create settlement wire admission.
//!
//! A signed broker session must bind these canonical request bodies and their
//! responses. Parsing one body alone supplies no live Host lease, Controller
//! CAS, or permission to retire the original argument archive.

use crate::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_proto::aos::sandbox::local::v1::{
    HostNoApplySettlementPhaseV2 as WirePhaseV2, HostNoApplySettlementStatusV2 as WireStatusV2,
    QueryHostExecutionNoApplySettlementRequestV2, QueryHostExecutionNoApplySettlementResponseV2,
    SettleHostExecutionNoApplyRequestV2, SettleHostExecutionNoApplyResponseV2,
};
use aos_sandbox_core::ObjectDigest;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::HostExecutionNoApplyRecordV1;
use super::transport::{ValidatedHostExecutionNoApplyRequestV1, decode_record, validate_request};
use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader};

const MAXIMUM_REQUEST_BODY_BYTES: usize = 2 * 1_024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 2 * 1_024;
const HOST_SETTLEMENT_RECORD_BYTES: usize = 396;
const HOST_SETTLEMENT_MAGIC: &[u8; 8] = b"AOSCHL01";
const HOST_SETTLEMENT_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.host-create-failure-lease.v1\0";
const CONTROLLER_ACK_BYTES: usize = 156;
const CONTROLLER_ACK_MAGIC: &[u8; 8] = b"AOSCFA01";
const CONTROLLER_ACK_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.create-failure-settlement-ack.v1\0";
const HOST_SETTLEMENT_HEAD_DOMAIN: &[u8] = b"aos.sandbox.host-create-failure-lease-head.v1\0";

/// Names one stage in the durable Host settlement chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostNoApplySettlementPhaseV2 {
    /// Commits the Host marker, handoff, challenge, and pre-lease cut.
    Preliminary,
    /// Retains the exact Controller prepare floor before its CAS.
    FloorSealed,
    /// Retains the Controller's exact post-CAS acknowledgment.
    AckRetained,
}

impl HostNoApplySettlementPhaseV2 {
    /// Returns the protected Host record stage byte.
    #[must_use]
    pub const fn record_stage(self) -> u8 {
        match self {
            Self::Preliminary => 1,
            Self::FloorSealed => 2,
            Self::AckRetained => 3,
        }
    }
}

/// Carries the stage-specific Controller coordinate without owner authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostNoApplyControllerCoordinateV2 {
    /// The preliminary stage has no Controller floor yet.
    Preliminary,
    /// The Controller's exact durable prepare-floor digest.
    Floor(ObjectDigest),
    /// The canonical Controller ACK body awaiting signed transport verification.
    Ack([u8; CONTROLLER_ACK_BYTES]),
}

/// Retains a canonical V2 settlement request for later signed admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostNoApplySettlementRequestV2 {
    original: ValidatedHostExecutionNoApplyRequestV1,
    archive_head: ObjectDigest,
    signed_terminal_outcome: ObjectDigest,
    phase: HostNoApplySettlementPhaseV2,
    coordinate: HostNoApplyControllerCoordinateV2,
    challenge: [u8; 16],
}

impl ValidatedHostNoApplySettlementRequestV2 {
    /// Returns the current request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        self.original.header()
    }

    /// Returns the original method-37 source and signed identity.
    #[must_use]
    pub const fn original(&self) -> &ValidatedHostExecutionNoApplyRequestV1 {
        &self.original
    }

    /// Returns the Controller's protected original H archive head.
    #[must_use]
    pub const fn archive_head(&self) -> ObjectDigest {
        self.archive_head
    }

    /// Returns the Controller's signed T outcome digest.
    #[must_use]
    pub const fn signed_terminal_outcome(&self) -> ObjectDigest {
        self.signed_terminal_outcome
    }

    /// Returns the requested Host stage.
    #[must_use]
    pub const fn phase(&self) -> HostNoApplySettlementPhaseV2 {
        self.phase
    }

    /// Returns the stage-specific Controller coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> HostNoApplyControllerCoordinateV2 {
        self.coordinate
    }

    /// Returns the challenge shared by all stages of this settlement.
    #[must_use]
    pub const fn challenge(&self) -> [u8; 16] {
        self.challenge
    }
}

/// Matches Controller's authenticated H/T archive to one V2 Host stage request.
///
/// The caller must obtain `outcome` and `original_archive_head` from the held,
/// protected Controller archive readback. This pure comparison cannot establish
/// archive currentness, a live Host lease, or permission to commit a stage.
/// The terminal digest is SHA-256 over the exact signed packet bytes.
///
/// # Errors
///
/// Rejects a foreign H head, signed terminal packet, original method-37
/// identity, method-39 request, or canonical Host marker.
pub fn match_archived_host_no_apply_outcome_v2(
    request: &ValidatedHostNoApplySettlementRequestV2,
    original_archive_head: ObjectDigest,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<HostExecutionNoApplyRecordV1, ProtocolValidationError> {
    if request.archive_head != original_archive_head
        || signed_host_no_apply_terminal_outcome_digest_v2(outcome)
            != request.signed_terminal_outcome
    {
        return Err(ProtocolValidationError::InvalidField("signed_archive"));
    }
    let readback = outcome
        .recorded_host_no_apply()
        .map_err(|_| ProtocolValidationError::InvalidField("signed_archive"))?
        .ok_or(ProtocolValidationError::InvalidField("signed_archive"))?;
    if outcome.method()
        != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
    {
        return Err(ProtocolValidationError::InvalidField("signed_archive"));
    }
    let terminal = aos_proto::aos::sandbox::local::v1::TerminalHostExecutionArgumentNoApplyRequestV1::decode_from_slice(
        outcome.request().exact_body(),
    )
    .map_err(|_| ProtocolValidationError::InvalidField("signed_archive"))?;
    let original = request.original();
    let fields = readback.record().fields();
    if terminal.encode_to_vec() != outcome.request().exact_body()
        || terminal.canonical_attempt.as_slice() != original.canonical_attempt()
        || terminal.original_session_binding.as_slice() != original.original_session_binding()
        || terminal.original_signed_request_digest.as_slice()
            != original.original_signed_request_digest()
        || fields.terminal_request_id != outcome.request().request_id()
        || fields.terminal_session_binding != outcome.request().session_binding()
        || fields.terminal_signed_request_digest != outcome.request().signed_request_digest()
        || decode_record(&readback.record().encode_canonical(), original).is_err()
    {
        return Err(ProtocolValidationError::InvalidField("signed_archive"));
    }
    Ok(*readback.record())
}

/// Hashes the exact authenticated signed terminal packet for a V2 H/T coordinate.
///
/// This is a packet identity, not proof that its Controller archive remains
/// current or that the Host still retains the matching marker.
#[must_use]
pub fn signed_host_no_apply_terminal_outcome_digest_v2(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(outcome.canonical_packet()).into())
}

/// Retains a distinct signed cold-query request for one original attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostNoApplySettlementQueryV2 {
    original: ValidatedHostExecutionNoApplyRequestV1,
}

impl ValidatedHostNoApplySettlementQueryV2 {
    /// Returns the current query header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        self.original.header()
    }

    /// Returns the original method-37 source and signed identity.
    #[must_use]
    pub const fn original(&self) -> &ValidatedHostExecutionNoApplyRequestV1 {
        &self.original
    }
}

/// Carries the exact Host stage history from a signed read-only response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostNoApplySettlementHistoryV2 {
    stages: [Option<[u8; HOST_SETTLEMENT_RECORD_BYTES]>; 3],
}

impl HostNoApplySettlementHistoryV2 {
    /// Returns the exact canonical records in preliminary, floor, ACK order.
    #[must_use]
    pub const fn stages(&self) -> &[Option<[u8; HOST_SETTLEMENT_RECORD_BYTES]>; 3] {
        &self.stages
    }
}

/// Parses one V2 stage request without granting a Host effect.
///
/// # Errors
///
/// Rejects noncanonical protobuf, a stale or malformed header/source, a zero
/// H/T identity or challenge, and a coordinate for the wrong stage.
pub fn decode_host_no_apply_settlement_request_v2(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostNoApplySettlementRequestV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = SettleHostExecutionNoApplyRequestV2::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let original = validate_request(
        request.header.as_option(),
        &request.canonical_attempt,
        &request.original_session_binding,
        &request.original_signed_request_digest,
        peer,
        policy,
        now_boottime_nanoseconds,
    )?;
    let archive_head = nonzero_digest(&request.archive_head, "archive_head")?;
    let signed_terminal_outcome =
        nonzero_digest(&request.signed_terminal_outcome, "signed_terminal_outcome")?;
    let challenge: [u8; 16] = request
        .challenge
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("challenge"))?;
    if challenge == [0; 16] {
        return Err(ProtocolValidationError::InvalidField("challenge"));
    }

    let (phase, coordinate) = match request.phase.as_known() {
        Some(WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_PRELIMINARY)
            if request.canonical_controller_coordinate.is_empty() =>
        {
            (
                HostNoApplySettlementPhaseV2::Preliminary,
                HostNoApplyControllerCoordinateV2::Preliminary,
            )
        }
        Some(WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_FLOOR_SEALED) => (
            HostNoApplySettlementPhaseV2::FloorSealed,
            HostNoApplyControllerCoordinateV2::Floor(nonzero_digest(
                &request.canonical_controller_coordinate,
                "canonical_controller_coordinate",
            )?),
        ),
        Some(WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_ACK_RETAINED) => {
            let ack: [u8; CONTROLLER_ACK_BYTES] = request
                .canonical_controller_coordinate
                .as_slice()
                .try_into()
                .map_err(|_| {
                    ProtocolValidationError::InvalidField("canonical_controller_coordinate")
                })?;
            validate_controller_ack_envelope(&ack, &original.canonical_attempt()[24..40])?;
            (
                HostNoApplySettlementPhaseV2::AckRetained,
                HostNoApplyControllerCoordinateV2::Ack(ack),
            )
        }
        _ => return Err(ProtocolValidationError::InvalidField("phase")),
    };

    Ok(ValidatedHostNoApplySettlementRequestV2 {
        original,
        archive_head,
        signed_terminal_outcome,
        phase,
        coordinate,
        challenge,
    })
}

/// Parses a distinct read-only V2 cold query without reviving a lease.
///
/// # Errors
///
/// Rejects noncanonical protobuf, a stale or malformed header/source, or an
/// original method-37 identity that differs from the signed query.
pub fn decode_host_no_apply_settlement_query_request_v2(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostNoApplySettlementQueryV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryHostExecutionNoApplySettlementRequestV2::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    Ok(ValidatedHostNoApplySettlementQueryV2 {
        original: validate_request(
            request.header.as_option(),
            &request.canonical_attempt,
            &request.original_session_binding,
            &request.original_signed_request_digest,
            peer,
            policy,
            now_boottime_nanoseconds,
        )?,
    })
}

/// Decodes one signed stage outcome against its original V2 request.
///
/// # Errors
///
/// Rejects malformed protobuf, a foreign stage, attempt, H/T identity,
/// challenge, Controller coordinate, or Host record envelope.
pub fn decode_host_no_apply_settlement_response_v2(
    body: &[u8],
    request: &ValidatedHostNoApplySettlementRequestV2,
    request_session_binding: [u8; 32],
) -> Result<[u8; HOST_SETTLEMENT_RECORD_BYTES], ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = SettleHostExecutionNoApplyResponseV2::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let record: [u8; HOST_SETTLEMENT_RECORD_BYTES] = response
        .canonical_record
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("canonical_record"))?;
    if validate_host_no_apply_settlement_record_envelope_v1(&record)?
        != request.phase.record_stage()
        || !record_matches_attempt(&record, request.original.canonical_attempt())
        || record[108..140] != *request.archive_head.as_bytes()
        || record[140..172] != *request.signed_terminal_outcome.as_bytes()
        || record[244..260] != request.challenge
    {
        return Err(ProtocolValidationError::InvalidField("canonical_record"));
    }
    match request.coordinate {
        HostNoApplyControllerCoordinateV2::Preliminary
            if record[212..244] == request_session_binding => {}
        HostNoApplyControllerCoordinateV2::Floor(floor)
            if record[300..332] == *floor.as_bytes() => {}
        HostNoApplyControllerCoordinateV2::Ack(ack)
            if record[300..332] == ack[60..92] && record[332..364] == ack[92..124] => {}
        _ => return Err(ProtocolValidationError::InvalidField("canonical_record")),
    }
    Ok(record)
}

/// Decodes all Host stages from a signed cold query without reviving a lease.
///
/// # Errors
///
/// Rejects malformed protobuf, incoherent status/presence, foreign execution
/// or operation, noncanonical records, or a broken phase predecessor chain.
pub fn decode_host_no_apply_settlement_query_response_v2(
    body: &[u8],
    request: &ValidatedHostNoApplySettlementQueryV2,
) -> Result<HostNoApplySettlementHistoryV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = QueryHostExecutionNoApplySettlementResponseV2::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let count = match response.status.as_known() {
        Some(WireStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_ABSENT) => 0,
        Some(WireStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_PRELIMINARY) => 1,
        Some(WireStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_FLOOR_SEALED) => 2,
        Some(WireStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_ACK_RETAINED) => 3,
        _ => return Err(ProtocolValidationError::InvalidField("status")),
    };
    let bodies = [
        &response.preliminary,
        &response.floor_sealed,
        &response.ack_retained,
    ];
    let mut stages = [None; 3];
    for (index, bytes) in bodies.into_iter().enumerate() {
        if index >= count {
            if !bytes.is_empty() {
                return Err(ProtocolValidationError::InvalidField("status"));
            }
            continue;
        }
        let record: [u8; HOST_SETTLEMENT_RECORD_BYTES] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolValidationError::InvalidField("canonical_record"))?;
        if validate_host_no_apply_settlement_record_envelope_v1(&record)? != index as u8 + 1
            || !record_matches_attempt(&record, request.original.canonical_attempt())
        {
            return Err(ProtocolValidationError::InvalidField("canonical_record"));
        }
        if index != 0 {
            let predecessor = stages[index - 1]
                .ok_or(ProtocolValidationError::InvalidField("canonical_record"))?;
            if !record_advances(&record, &predecessor) {
                return Err(ProtocolValidationError::InvalidField("canonical_record"));
            }
        }
        stages[index] = Some(record);
    }
    Ok(HostNoApplySettlementHistoryV2 { stages })
}

/// Checks the fixed Host record envelope before owner-specific replay joins.
///
/// # Errors
///
/// Rejects an unknown version, stage, reserved byte, length, or checksum.
pub fn validate_host_no_apply_settlement_record_envelope_v1(
    bytes: &[u8],
) -> Result<u8, ProtocolValidationError> {
    if bytes.len() != HOST_SETTLEMENT_RECORD_BYTES
        || bytes.get(..8) != Some(HOST_SETTLEMENT_MAGIC.as_slice())
        || bytes[8..10] != 1_u16.to_be_bytes()
        || !matches!(bytes[10], 1..=3)
        || bytes[11] != 0
        || Sha256::new()
            .chain_update(HOST_SETTLEMENT_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..HOST_SETTLEMENT_RECORD_BYTES - 32])
            .finalize()
            .as_slice()
            != &bytes[HOST_SETTLEMENT_RECORD_BYTES - 32..]
    {
        return Err(ProtocolValidationError::InvalidField("canonical_record"));
    }
    let required = [
        &bytes[12..28],
        &bytes[28..44],
        &bytes[44..76],
        &bytes[76..108],
        &bytes[108..140],
        &bytes[140..172],
        &bytes[172..180],
        &bytes[180..212],
        &bytes[212..244],
        &bytes[244..260],
        &bytes[260..268],
    ];
    if required
        .iter()
        .any(|field| field.iter().all(|byte| *byte == 0))
        || !match bytes[10] {
            1 => bytes[268..364].iter().all(|byte| *byte == 0),
            2 => {
                bytes[268..300].iter().any(|byte| *byte != 0)
                    && bytes[300..332].iter().any(|byte| *byte != 0)
                    && bytes[332..364].iter().all(|byte| *byte == 0)
            }
            3 => [268, 300, 332]
                .iter()
                .all(|start| bytes[*start..*start + 32].iter().any(|byte| *byte != 0)),
            _ => false,
        }
    {
        return Err(ProtocolValidationError::InvalidField("canonical_record"));
    }
    Ok(bytes[10])
}

fn record_matches_attempt(record: &[u8; HOST_SETTLEMENT_RECORD_BYTES], attempt: &[u8]) -> bool {
    record[12..28] == attempt[8..24] && record[28..44] == attempt[24..40]
}

fn record_advances(
    record: &[u8; HOST_SETTLEMENT_RECORD_BYTES],
    predecessor: &[u8; HOST_SETTLEMENT_RECORD_BYTES],
) -> bool {
    let mut sequence = [0; 8];
    let mut predecessor_sequence = [0; 8];
    sequence.copy_from_slice(&record[260..268]);
    predecessor_sequence.copy_from_slice(&predecessor[260..268]);
    let predecessor_digest = Sha256::new()
        .chain_update(HOST_SETTLEMENT_HEAD_DOMAIN)
        .chain_update(predecessor)
        .finalize();
    record[12..260] == predecessor[12..260]
        && u64::from_be_bytes(sequence) > u64::from_be_bytes(predecessor_sequence)
        && record[268..300] == predecessor_digest[..]
        && (record[10] != 3 || record[300..332] == predecessor[300..332])
}

fn nonzero_digest(
    bytes: &[u8],
    field: &'static str,
) -> Result<ObjectDigest, ProtocolValidationError> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField(field))?;
    if value == [0; 32] {
        return Err(ProtocolValidationError::InvalidField(field));
    }
    Ok(ObjectDigest::from_bytes(value))
}

/// Validates the canonical Controller settlement ACK envelope without signer authority.
///
/// # Errors
///
/// Returns an error if the version, identities, reserved bytes, or checksum are invalid.
pub fn validate_controller_create_failure_ack_envelope_v1(
    bytes: &[u8],
) -> Result<(), ProtocolValidationError> {
    if bytes.len() != CONTROLLER_ACK_BYTES
        || bytes[..8] != *CONTROLLER_ACK_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..12] != [0; 2]
        || bytes[12..28] == [0; 16]
        || [28, 60, 92]
            .iter()
            .any(|start| bytes[*start..*start + 32] == [0; 32])
        || Sha256::new()
            .chain_update(CONTROLLER_ACK_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..CONTROLLER_ACK_BYTES - 32])
            .finalize()
            .as_slice()
            != &bytes[CONTROLLER_ACK_BYTES - 32..]
    {
        return Err(ProtocolValidationError::InvalidField(
            "canonical_controller_coordinate",
        ));
    }
    Ok(())
}

fn validate_controller_ack_envelope(
    bytes: &[u8; CONTROLLER_ACK_BYTES],
    operation: &[u8],
) -> Result<(), ProtocolValidationError> {
    validate_controller_create_failure_ack_envelope_v1(bytes)?;
    if bytes[12..28] != *operation {
        return Err(ProtocolValidationError::InvalidField(
            "canonical_controller_coordinate",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        QueryHostExecutionNoApplySettlementResponseV2, SettleHostExecutionNoApplyResponseV2,
    };

    use super::*;
    use crate::host_execution_no_apply::transport::tests::{header, peer_policy, source};

    fn request(phase: WirePhaseV2, coordinate: Vec<u8>) -> SettleHostExecutionNoApplyRequestV2 {
        SettleHostExecutionNoApplyRequestV2 {
            header: Some(header([9; 16])).into(),
            canonical_attempt: source().to_vec(),
            original_session_binding: vec![12; 32],
            original_signed_request_digest: vec![13; 32],
            archive_head: vec![10; 32],
            signed_terminal_outcome: vec![11; 32],
            phase: phase.into(),
            canonical_controller_coordinate: coordinate,
            challenge: vec![9; 16],
            ..Default::default()
        }
    }

    fn record(
        stage: u8,
        predecessor: Option<[u8; HOST_SETTLEMENT_RECORD_BYTES]>,
    ) -> [u8; HOST_SETTLEMENT_RECORD_BYTES] {
        let mut bytes = [1; HOST_SETTLEMENT_RECORD_BYTES];
        bytes[..8].copy_from_slice(HOST_SETTLEMENT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = stage;
        bytes[11] = 0;
        bytes[12..28].fill(1);
        bytes[28..44].fill(2);
        bytes[108..140].fill(10);
        bytes[140..172].fill(11);
        bytes[172..180].copy_from_slice(&1_u64.to_be_bytes());
        bytes[212..244].fill(8);
        bytes[244..260].fill(9);
        bytes[260..268].copy_from_slice(&u64::from(stage).to_be_bytes());
        bytes[268..364].fill(0);
        if let Some(predecessor) = predecessor {
            bytes[268..300].copy_from_slice(
                &Sha256::new()
                    .chain_update(HOST_SETTLEMENT_HEAD_DOMAIN)
                    .chain_update(predecessor)
                    .finalize(),
            );
            bytes[300..332].fill(20);
            if stage == 3 {
                bytes[332..364].fill(21);
            }
        }
        let checksum = Sha256::new()
            .chain_update(HOST_SETTLEMENT_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..364])
            .finalize();
        bytes[364..].copy_from_slice(&checksum);
        bytes
    }

    #[test]
    fn stage_request_and_response_reject_foreign_coordinate() {
        let (peer, policy) = peer_policy();
        let preliminary_request = request(
            WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_PRELIMINARY,
            Vec::new(),
        );
        let preliminary = decode_host_no_apply_settlement_request_v2(
            &preliminary_request.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap();
        assert_eq!(
            preliminary.phase(),
            HostNoApplySettlementPhaseV2::Preliminary
        );

        let preliminary_record = record(1, None);
        let response = SettleHostExecutionNoApplyResponseV2 {
            canonical_record: preliminary_record.to_vec(),
            ..Default::default()
        };
        assert_eq!(
            decode_host_no_apply_settlement_response_v2(
                &response.encode_to_vec(),
                &preliminary,
                [8; 32],
            ),
            Ok(preliminary_record),
        );
        assert!(
            decode_host_no_apply_settlement_response_v2(
                &response.encode_to_vec(),
                &preliminary,
                [7; 32],
            )
            .is_err()
        );

        let invalid_floor = request(
            WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_FLOOR_SEALED,
            Vec::new(),
        );
        assert!(
            decode_host_no_apply_settlement_request_v2(
                &invalid_floor.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );
        let floor_request = request(
            WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_FLOOR_SEALED,
            vec![20; 32],
        );
        let floor = decode_host_no_apply_settlement_request_v2(
            &floor_request.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap();
        let floor_record = record(2, Some(preliminary_record));
        let response = SettleHostExecutionNoApplyResponseV2 {
            canonical_record: floor_record.to_vec(),
            ..Default::default()
        };
        assert!(
            decode_host_no_apply_settlement_response_v2(
                &response.encode_to_vec(), &floor, [7; 32],
            )
            .is_ok()
        );
        let foreign_floor = request(
            WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_FLOOR_SEALED,
            vec![22; 32],
        );
        let foreign_floor = decode_host_no_apply_settlement_request_v2(
            &foreign_floor.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap();
        assert!(
            decode_host_no_apply_settlement_response_v2(
                &response.encode_to_vec(),
                &foreign_floor,
                [7; 32],
            )
            .is_err()
        );

        let mut controller_ack = [0; CONTROLLER_ACK_BYTES];
        controller_ack[..8].copy_from_slice(CONTROLLER_ACK_MAGIC);
        controller_ack[8..10].copy_from_slice(&1_u16.to_be_bytes());
        controller_ack[12..28].fill(2);
        controller_ack[28..60].fill(3);
        controller_ack[60..92].fill(20);
        controller_ack[92..124].fill(21);
        let checksum = Sha256::new()
            .chain_update(CONTROLLER_ACK_CHECKSUM_DOMAIN)
            .chain_update(&controller_ack[..124])
            .finalize();
        controller_ack[124..].copy_from_slice(&checksum);
        let ack_request = request(
            WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_ACK_RETAINED,
            controller_ack.to_vec(),
        );
        let ack = decode_host_no_apply_settlement_request_v2(
            &ack_request.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap();
        let ack_record = record(3, Some(floor_record));
        let response = SettleHostExecutionNoApplyResponseV2 {
            canonical_record: ack_record.to_vec(),
            ..Default::default()
        };
        assert!(
            decode_host_no_apply_settlement_response_v2(&response.encode_to_vec(), &ack, [7; 32],)
                .is_ok()
        );
        let mut foreign_ack = ack_request;
        foreign_ack.canonical_controller_coordinate[92] ^= 1;
        assert!(
            decode_host_no_apply_settlement_request_v2(
                &foreign_ack.encode_to_vec(),
                peer,
                policy,
                99,
            )
            .is_err()
        );
    }

    #[test]
    fn cold_query_requires_exact_stage_presence_and_chain() {
        let (peer, policy) = peer_policy();
        let query = QueryHostExecutionNoApplySettlementRequestV2 {
            header: Some(header([10; 16])).into(),
            canonical_attempt: source().to_vec(),
            original_session_binding: vec![12; 32],
            original_signed_request_digest: vec![13; 32],
            ..Default::default()
        };
        let query = decode_host_no_apply_settlement_query_request_v2(
            &query.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap();
        let preliminary = record(1, None);
        let floor = record(2, Some(preliminary));
        let ack = record(3, Some(floor));
        let response = QueryHostExecutionNoApplySettlementResponseV2 {
            status: WireStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_ACK_RETAINED.into(),
            preliminary: preliminary.to_vec(),
            floor_sealed: floor.to_vec(),
            ack_retained: ack.to_vec(),
            ..Default::default()
        };
        assert_eq!(
            decode_host_no_apply_settlement_query_response_v2(&response.encode_to_vec(), &query)
                .unwrap()
                .stages(),
            &[Some(preliminary), Some(floor), Some(ack)],
        );
        let mut missing_floor = response.clone();
        missing_floor.floor_sealed.clear();
        assert!(
            decode_host_no_apply_settlement_query_response_v2(
                &missing_floor.encode_to_vec(),
                &query,
            )
            .is_err()
        );
        let mut altered_ack = response;
        altered_ack.ack_retained[268] ^= 1;
        assert!(
            decode_host_no_apply_settlement_query_response_v2(
                &altered_ack.encode_to_vec(), &query,
            )
            .is_err()
        );
    }
}
