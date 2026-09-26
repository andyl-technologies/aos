//! Closed signed-plan semantics for an original zero-byte Storage output reserve.
//!
//! The request carries the existing AOSCIA01 and AOSCIS01 records verbatim.
//! Their checksums establish structure only. A Storage effect additionally
//! requires a verified Controller signature, current assignment, a same-session
//! Host readback, and the exclusively held Storage output writer. No production
//! method advertises or dispatches this request yet.

use aos_proto::aos::sandbox::local::v1::{Audience, ReserveStorageExecutionOutputRequestV1};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment, BrokerGrant, BrokerGrantTarget,
    BrokerVerb, DesiredGeneration, IncarnationId, ObjectDigest, ProtocolId, SandboxId,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::host_output::{HostOutputReservationLocatorV1, host_output_locator_from_source_v1};
use crate::semantics::host_output_reserve_grant_v1;
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_request_header,
};

/// Exact protected Controller original Host attempt length.
pub const CONTROLLER_OUTPUT_ATTEMPT_BYTES_V1: usize = 816;
/// Exact protected Controller Host settlement length.
pub const CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1: usize = 208;

const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.controller-output-attempt.v1\0";
const PREISSUE_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-preissue.v1\0";
const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-reserve-source.v1\0";
const SETTLEMENT_DOMAIN: &[u8] = b"aos.sandbox.controller-output-settlement.v1\0";
const GRANT_DOMAIN: &[u8] = b"aos.sandbox.storage.output-reserve-grant.v1\0";
const MAXIMUM_BODY_BYTES: usize = 4 * 1_024;

/// Keeps structurally matched original Controller records under one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageOutputReserveRecordsV1 {
    attempt: [u8; CONTROLLER_OUTPUT_ATTEMPT_BYTES_V1],
    settlement: [u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1],
    locator: HostOutputReservationLocatorV1,
    deadline_boottime_nanoseconds: u64,
}

impl StorageOutputReserveRecordsV1 {
    /// Parses existing Controller records without claiming their provenance.
    ///
    /// # Errors
    ///
    /// Rejects malformed, mismatched, nonzero-output, or expired source fields.
    pub fn from_canonical_records(
        attempt: &[u8],
        settlement: &[u8],
    ) -> Result<Self, ProtocolValidationError> {
        let attempt: [u8; CONTROLLER_OUTPUT_ATTEMPT_BYTES_V1] =
            attempt.try_into().map_err(|_| invalid())?;
        let settlement: [u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1] =
            settlement.try_into().map_err(|_| invalid())?;
        let source: [u8; 688] = attempt[8..696].try_into().map_err(|_| invalid())?;
        let original_request_id: [u8; 16] = attempt[696..712].try_into().map_err(|_| invalid())?;
        let locator = host_output_locator_from_source_v1(&source, original_request_id)?;
        let deadline_boottime_nanoseconds = read_u64(&source[120..128])?;
        let original_host_deadline = read_u64(&attempt[776..784])?;
        let host_assignment = BrokerAssignment::new(
            SandboxId::from_bytes(exact_nonzero::<16>(&source[552..568], "sandbox")?),
            IncarnationId::from_bytes(exact_nonzero::<16>(&source[568..584], "incarnation")?),
            AssignmentEpoch::new(read_u64(&source[600..608])?),
            DesiredGeneration::new(read_u64(&source[608..616])?),
            ObjectDigest::from_bytes(exact_nonzero::<32>(&source[624..656], "assignment digest")?),
        )
        .map_err(|_| invalid())?;
        let host_semantic =
            host_output_reserve_grant_v1(host_assignment, original_request_id, &source)
                .map_err(|_| invalid())?;

        if &attempt[..8] != b"AOSCIA01"
            || &settlement[..8] != b"AOSCIS01"
            || &source[192..200] != b"AOSEOR02"
            || source[80..96] != [0; 16]
            || source[424..432] != [0; 8]
            || source[440..456] != [0; 16]
            || source[296..328] != source[624..656]
            || source[520..552] == [0; 32]
            || source[584..600] == [0; 16]
            || read_u64(&source[616..624])? == 0
            || attempt[712..744] == [0; 32]
            || attempt[744..776] != *host_semantic.commitment().digest().as_bytes()
            || original_host_deadline == 0
            || original_host_deadline > deadline_boottime_nanoseconds
            || deadline_boottime_nanoseconds == 0
            || read_u64(&settlement[104..112])? == 0
            || settlement[8..24] != *locator.execution().as_bytes()
            || settlement[24..40] != *locator.create_operation().as_bytes()
            || settlement[40..72] != attempt[784..816]
            || settlement[72..104] == [0; 32]
            || settlement[112..144] == [0; 32]
            || settlement[144..176] == [0; 32]
            || !matches_digest(PREISSUE_DOMAIN, &source[8..160], &source[160..192])
            || Sha256::digest(&source[192..488]).as_slice() != &source[488..520]
            || !matches_digest(SOURCE_DOMAIN, &source[..656], &source[656..688])
            || !matches_digest(ATTEMPT_DOMAIN, &attempt[..784], &attempt[784..816])
            || !matches_digest(SETTLEMENT_DOMAIN, &settlement[..176], &settlement[176..208])
        {
            return Err(invalid());
        }

        Ok(Self {
            attempt,
            settlement,
            locator,
            deadline_boottime_nanoseconds,
        })
    }

    /// Returns the original Host reserve locator that must be reread on Host.
    #[must_use]
    pub const fn host_locator(&self) -> HostOutputReservationLocatorV1 {
        self.locator
    }

    /// Returns the Controller preissue deadline shared by both owner records.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the exact original Controller attempt bytes.
    #[must_use]
    pub const fn attempt(&self) -> &[u8; CONTROLLER_OUTPUT_ATTEMPT_BYTES_V1] {
        &self.attempt
    }

    /// Returns the exact settled Controller Host receipt bytes.
    #[must_use]
    pub const fn settlement(&self) -> &[u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1] {
        &self.settlement
    }
}

/// Holds a canonical request pending independent signature and Host checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageOutputReserveRequestV1 {
    header: ValidatedHeader,
    records: StorageOutputReserveRecordsV1,
}

impl ValidatedStorageOutputReserveRequestV1 {
    /// Returns the authenticated request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows the structural Controller records; this is not an effect permit.
    #[must_use]
    pub const fn records(&self) -> &StorageOutputReserveRecordsV1 {
        &self.records
    }
}

/// Parses one closed Storage reserve request without authorizing mutation.
///
/// # Errors
///
/// Rejects noncanonical wire, stale header, changed Controller records, or a
/// deadline extending past the original protected preissue.
pub fn decode_storage_output_reserve_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageOutputReserveRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ReserveStorageExecutionOutputRequestV1::decode_from_slice(body)
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
        ProtocolId::StorageBroker,
        now_boottime_nanoseconds,
    )?;
    let records = StorageOutputReserveRecordsV1::from_canonical_records(
        &request.canonical_controller_attempt,
        &request.canonical_controller_settlement,
    )?;
    if header.deadline_boottime_nanoseconds() > records.deadline_boottime_nanoseconds() {
        return Err(invalid());
    }
    Ok(ValidatedStorageOutputReserveRequestV1 { header, records })
}

/// Compiles a Storage-only signed grant over the complete canonical request.
///
/// The signed plan still requires independent Storage admission and a current
/// authenticated Host proof. This function never publishes a broker method.
///
/// # Errors
///
/// Rejects a missing request ID or noncanonical, malformed, or oversized body.
pub fn storage_output_reserve_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    body: &[u8],
) -> Result<BrokerGrant, ProtocolValidationError> {
    if request_id == [0; 16] || body.is_empty() || body.len() > MAXIMUM_BODY_BYTES {
        return Err(invalid());
    }
    let request = ReserveStorageExecutionOutputRequestV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let header = request.header.as_option().ok_or_else(invalid)?;
    if !request.__buffa_unknown_fields.is_empty()
        || request.encode_to_vec() != body
        || header.request_id != request_id
        || header.protocol_major != 1
        || header.protocol_minor != 0
        || header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER)
    {
        return Err(invalid());
    }
    let records = StorageOutputReserveRecordsV1::from_canonical_records(
        &request.canonical_controller_attempt,
        &request.canonical_controller_settlement,
    )?;
    let source = &records.attempt[8..696];
    if records.host_locator().assignment_digest() != assignment.digest()
        || source[552..568] != *assignment.sandbox().as_bytes()
        || source[568..584] != *assignment.incarnation().as_bytes()
        || read_u64(&source[600..608])? != assignment.epoch().get()
        || read_u64(&source[608..616])? != assignment.desired_generation().get()
        || header.deadline_boottime_nanoseconds == 0
        || header.deadline_boottime_nanoseconds > records.deadline_boottime_nanoseconds()
    {
        return Err(invalid());
    }
    let mut statement = Vec::with_capacity(GRANT_DOMAIN.len() + 1 + 16 + body.len());
    statement.extend_from_slice(GRANT_DOMAIN);
    statement.push(1);
    statement.extend_from_slice(&request_id);
    statement.extend_from_slice(body);
    BrokerGrant::new(
        BrokerVerb::StorageReserveExecutionOutput,
        BrokerGrantTarget::Assignment,
        BrokerArgumentCommitment::for_canonical_bytes(&statement),
        MAXIMUM_BODY_BYTES as u32,
        0,
    )
    .map_err(|_| invalid())
}

fn read_u64(bytes: &[u8]) -> Result<u64, ProtocolValidationError> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| invalid())?))
}

fn matches_digest(domain: &[u8], body: &[u8], expected: &[u8]) -> bool {
    Sha256::new()
        .chain_update(domain)
        .chain_update(body)
        .finalize()
        .as_slice()
        == expected
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Storage output reserve source")
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};
    use aos_sandbox_core::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};

    use super::*;

    fn seal(domain: &[u8], bytes: &mut [u8], digest_start: usize) {
        let digest = Sha256::new()
            .chain_update(domain)
            .chain_update(&bytes[..digest_start])
            .finalize();
        bytes[digest_start..digest_start + 32].copy_from_slice(&digest);
    }

    fn fixture() -> (ReserveStorageExecutionOutputRequestV1, BrokerAssignment) {
        let mut source = [0_u8; 688];
        source[..8].copy_from_slice(b"AOSCIR01");
        source[8..16].copy_from_slice(b"AOSCIP01");
        source[16..32].fill(1);
        source[32..48].fill(2);
        source[48..80].fill(3);
        source[96..104].copy_from_slice(&1_u64.to_be_bytes());
        source[104..120].fill(4);
        source[120..128].copy_from_slice(&1_000_u64.to_be_bytes());
        source[128..160].fill(5);
        let preissue_digest = Sha256::new()
            .chain_update(PREISSUE_DOMAIN)
            .chain_update(&source[8..160])
            .finalize();
        source[160..192].copy_from_slice(&preissue_digest);

        source[192..200].copy_from_slice(b"AOSEOR02");
        source[200..216].fill(1);
        source[216..232].fill(2);
        for offset in [232, 264, 328, 360, 392, 456] {
            source[offset..offset + 32].fill(6);
        }
        source[296..328].fill(7);
        source[432..440].copy_from_slice(&100_u64.to_be_bytes());
        let claim_checksum = Sha256::digest(&source[192..488]);
        source[488..520].copy_from_slice(&claim_checksum);
        source[520..552].fill(8);
        source[552..568].fill(9);
        source[568..584].fill(10);
        source[584..600].fill(11);
        for offset in [600, 608, 616] {
            source[offset..offset + 8].copy_from_slice(&1_u64.to_be_bytes());
        }
        source[624..656].fill(7);
        seal(SOURCE_DOMAIN, &mut source, 656);

        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([9; 16]),
            IncarnationId::from_bytes([10; 16]),
            AssignmentEpoch::new(1),
            DesiredGeneration::new(1),
            ObjectDigest::from_bytes([7; 32]),
        )
        .unwrap();
        let semantic = host_output_reserve_grant_v1(assignment, [12; 16], &source).unwrap();

        let mut attempt = [0_u8; CONTROLLER_OUTPUT_ATTEMPT_BYTES_V1];
        attempt[..8].copy_from_slice(b"AOSCIA01");
        attempt[8..696].copy_from_slice(&source);
        attempt[696..712].fill(12);
        attempt[712..744].fill(13);
        attempt[744..776].copy_from_slice(semantic.commitment().digest().as_bytes());
        attempt[776..784].copy_from_slice(&900_u64.to_be_bytes());
        seal(ATTEMPT_DOMAIN, &mut attempt, 784);

        let mut settlement = [0_u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1];
        settlement[..8].copy_from_slice(b"AOSCIS01");
        settlement[8..24].fill(1);
        settlement[24..40].fill(2);
        settlement[40..72].copy_from_slice(&attempt[784..816]);
        settlement[72..104].fill(15);
        settlement[104..112].copy_from_slice(&1_u64.to_be_bytes());
        settlement[112..144].fill(16);
        settlement[144..176].fill(17);
        seal(SETTLEMENT_DOMAIN, &mut settlement, 176);

        let request = ReserveStorageExecutionOutputRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![18; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 950,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            canonical_controller_attempt: attempt.to_vec(),
            canonical_controller_settlement: settlement.to_vec(),
            ..Default::default()
        };
        (request, assignment)
    }

    #[test]
    fn zero_output_records_bind_exact_original_host_attempt_and_settlement() {
        let (request, assignment) = fixture();
        let records = StorageOutputReserveRecordsV1::from_canonical_records(
            &request.canonical_controller_attempt,
            &request.canonical_controller_settlement,
        )
        .unwrap();
        assert_eq!(records.host_locator().original_request_id(), [12; 16]);
        let body = request.encode_to_vec();
        let grant = storage_output_reserve_grant_v1(assignment, [18; 16], &body).unwrap();
        assert_eq!(grant.verb(), BrokerVerb::StorageReserveExecutionOutput);
        assert!(storage_output_reserve_grant_v1(assignment, [19; 16], &body).is_err());

        let peer = PeerCredentials {
            uid: 1,
            gid: 2,
            pid: None,
        };
        let policy = PeerPolicy {
            uid: 1,
            gid: Some(2),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };
        let decoded = decode_storage_output_reserve_request_v1(&body, peer, policy, 900).unwrap();
        assert_eq!(decoded.records(), &records);
    }

    #[test]
    fn zero_output_source_rejects_capture_and_substituted_original_receipts() {
        let (request, _) = fixture();
        let mut capture = request.canonical_controller_attempt.clone();
        capture[8 + 80] = 1;
        assert!(
            StorageOutputReserveRecordsV1::from_canonical_records(
                &capture,
                &request.canonical_controller_settlement,
            )
            .is_err()
        );

        let mut different_attempt = request.canonical_controller_attempt.clone();
        different_attempt[696] ^= 1;
        seal(ATTEMPT_DOMAIN, &mut different_attempt, 784);
        assert!(
            StorageOutputReserveRecordsV1::from_canonical_records(
                &different_attempt,
                &request.canonical_controller_settlement,
            )
            .is_err()
        );

        let mut different_settlement = request.canonical_controller_settlement.clone();
        different_settlement[72] ^= 1;
        assert!(
            StorageOutputReserveRecordsV1::from_canonical_records(
                &request.canonical_controller_attempt,
                &different_settlement,
            )
            .is_err()
        );
    }

    #[test]
    fn signed_semantics_reject_changed_storage_request_and_deadline_replay() {
        let (request, assignment) = fixture();
        let original =
            storage_output_reserve_grant_v1(assignment, [18; 16], &request.encode_to_vec())
                .unwrap();

        let mut changed = request.clone();
        let mut changed_header = changed.header.as_option().unwrap().clone();
        changed_header.request_id = vec![19; 16];
        changed.header = Some(changed_header).into();
        let replay =
            storage_output_reserve_grant_v1(assignment, [19; 16], &changed.encode_to_vec())
                .unwrap();
        assert_ne!(original.argument_commitment(), replay.argument_commitment());

        let mut substituted = request.clone();
        substituted.canonical_controller_attempt[712] ^= 1;
        seal(
            ATTEMPT_DOMAIN,
            &mut substituted.canonical_controller_attempt,
            784,
        );
        substituted.canonical_controller_settlement[40..72]
            .copy_from_slice(&substituted.canonical_controller_attempt[784..816]);
        seal(
            SETTLEMENT_DOMAIN,
            &mut substituted.canonical_controller_settlement,
            176,
        );
        let foreign =
            storage_output_reserve_grant_v1(assignment, [18; 16], &substituted.encode_to_vec())
                .unwrap();
        assert_ne!(
            original.argument_commitment(),
            foreign.argument_commitment()
        );

        let mut changed_header = changed.header.as_option().unwrap().clone();
        changed_header.deadline_boottime_nanoseconds = 1_001;
        changed.header = Some(changed_header).into();
        assert!(
            storage_output_reserve_grant_v1(assignment, [19; 16], &changed.encode_to_vec(),)
                .is_err()
        );
    }
}
