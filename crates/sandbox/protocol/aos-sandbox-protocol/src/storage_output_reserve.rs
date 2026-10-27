//! Closed signed-plan semantics for original Storage output registration.
//!
//! The request carries the existing AOSCIA01 and AOSCIS01 records verbatim.
//! Their checksums establish structure only. A Storage effect additionally
//! requires a verified Controller signature, current assignment, a same-session
//! Host readback, and the exclusively held Storage output writer. The legacy
//! profile keeps zero-output behavior. The captured profile also checks the
//! original accepted stdout/stderr quantities against their parent bound; its
//! parser alone never supplies admission or a physical output-capture permit.

pub mod authority_archive;
/// Defines closed pending-registration comparison and terminal DATA formats.
pub mod continuation;

#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) mod fixture;

use aos_sandbox_api::aos::sandbox::local::v1::{
    Audience, QueryStorageExecutionOutputRequestV1, ReserveStorageExecutionOutputRequestV1,
};
use aos_sandbox_model::{
    AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment, BrokerGrant, BrokerGrantTarget,
    BrokerVerb, DesiredGeneration, IncarnationId, ObjectDigest, ProtocolId, ProtocolVersion,
    SandboxId,
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
const QUERY_GRANT_DOMAIN: &[u8] = b"aos.sandbox.storage.output-query-grant.v1\0";
const MAXIMUM_BODY_BYTES: usize = 4 * 1_024;

/// Selects only the structural quantities accepted by the shared record decoder.
#[derive(Clone, Copy)]
pub(crate) enum OutputReserveProfileV1 {
    LegacyZero,
    Captured,
}

impl OutputReserveProfileV1 {
    fn rejects_quantities(self, source: &[u8; 688]) -> bool {
        match self {
            Self::LegacyZero => {
                source[80..96] != [0; 16]
                    || source[424..432] != [0; 8]
                    || source[440..456] != [0; 16]
            }
            Self::Captured => {
                let quantities = (|| {
                    let stdout = read_u64(&source[80..88])?;
                    let stderr = read_u64(&source[88..96])?;
                    let requested = read_u64(&source[424..432])?;
                    let parent_limit = read_u64(&source[432..440])?;
                    let claim_stdout = read_u64(&source[440..448])?;
                    let claim_stderr = read_u64(&source[448..456])?;

                    Ok::<_, ProtocolValidationError>(
                        stdout == claim_stdout
                            && stderr == claim_stderr
                            && stdout.checked_add(stderr) == Some(requested)
                            && requested <= parent_limit,
                    )
                })();
                !matches!(quantities, Ok(true))
            }
        }
    }
}

/// Keeps structurally matched original Controller records under one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageOutputReserveRecordsV1 {
    attempt: [u8; CONTROLLER_OUTPUT_ATTEMPT_BYTES_V1],
    settlement: [u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1],
    locator: HostOutputReservationLocatorV1,
    assignment: BrokerAssignment,
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
        Self::from_canonical_records_profile(attempt, settlement, OutputReserveProfileV1::LegacyZero)
    }

    /// Parses matched capture quantities without claiming protected provenance.
    ///
    /// # Errors
    ///
    /// Rejects different preissue and claim quantities, overflow, an exceeded
    /// parent bound, or any original record crosslink/checksum disagreement.
    pub fn from_canonical_captured_records(
        attempt: &[u8],
        settlement: &[u8],
    ) -> Result<Self, ProtocolValidationError> {
        Self::from_canonical_records_profile(attempt, settlement, OutputReserveProfileV1::Captured)
    }

    pub(crate) fn from_canonical_records_profile(
        attempt: &[u8],
        settlement: &[u8],
        profile: OutputReserveProfileV1,
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
            || profile.rejects_quantities(&source)
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
            assignment: host_assignment,
            deadline_boottime_nanoseconds,
        })
    }

    /// Returns the original Host reserve locator that must be reread on Host.
    #[must_use]
    pub const fn host_locator(&self) -> HostOutputReservationLocatorV1 {
        self.locator
    }

    /// Returns the assignment embedded in the original Controller source.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the accepted total, stdout and stderr limits from the original claim.
    #[must_use]
    pub fn output_limits_v2(&self) -> (u64, u64, u64) {
        let source = &self.attempt[8..696];
        let read = |offset| {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&source[offset..offset + 8]);
            u64::from_be_bytes(bytes)
        };

        (read(424), read(440), read(448))
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

/// Retains a fresh read-only query and its original reserve identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedStorageOutputQueryRequestV1 {
    header: ValidatedHeader,
    original_request_id: [u8; 16],
    original_body: Vec<u8>,
    original_plan_digest: ObjectDigest,
    original_semantic_digest: ObjectDigest,
    records: StorageOutputReserveRecordsV1,
}

impl ValidatedStorageOutputQueryRequestV1 {
    /// Returns the fresh authenticated query header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the immutable original method-46 request ID.
    #[must_use]
    pub const fn original_request_id(&self) -> [u8; 16] {
        self.original_request_id
    }

    /// Borrows the exact original method-46 body for protected lookup.
    #[must_use]
    pub fn original_body(&self) -> &[u8] {
        &self.original_body
    }

    /// Returns the original signed-plan digest for exact replay comparison.
    #[must_use]
    pub const fn original_plan_digest(&self) -> ObjectDigest {
        self.original_plan_digest
    }

    /// Returns the original signed semantic commitment digest.
    #[must_use]
    pub const fn original_semantic_digest(&self) -> ObjectDigest {
        self.original_semantic_digest
    }

    /// Borrows structural source records; these do not authorize mutation.
    #[must_use]
    pub const fn records(&self) -> &StorageOutputReserveRecordsV1 {
        &self.records
    }
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
    decode_reserve_profile(body, peer, policy, now_boottime_nanoseconds, OutputReserveProfileV1::LegacyZero)
}

/// Parses captured-output records without granting a Storage effect.
///
/// # Errors
///
/// Rejects noncanonical records, quantity mismatches, stale headers, or a widened deadline.
pub fn decode_captured_storage_output_reserve_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageOutputReserveRequestV1, ProtocolValidationError> {
    decode_reserve_profile(body, peer, policy, now_boottime_nanoseconds, OutputReserveProfileV1::Captured)
}

fn decode_reserve_profile(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
    profile: OutputReserveProfileV1,
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
    let records = StorageOutputReserveRecordsV1::from_canonical_records_profile(
        &request.canonical_controller_attempt,
        &request.canonical_controller_settlement,
        profile,
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
    reserve_grant_profile(assignment, request_id, body, OutputReserveProfileV1::LegacyZero)
}

/// Compiles the complete captured-output request commitment for independent admission.
///
/// # Errors
///
/// Rejects malformed records, inconsistent quantities, or a changed assignment.
pub fn captured_storage_output_reserve_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    body: &[u8],
) -> Result<BrokerGrant, ProtocolValidationError> {
    reserve_grant_profile(assignment, request_id, body, OutputReserveProfileV1::Captured)
}

pub(crate) fn reserve_grant_profile(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    body: &[u8],
    profile: OutputReserveProfileV1,
) -> Result<BrokerGrant, ProtocolValidationError> {
    if request_id == [0; 16] || body.is_empty() || body.len() > MAXIMUM_BODY_BYTES {
        return Err(invalid());
    }
    parse_reserve_records_profile(assignment, Some(request_id), body, profile)?;
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

/// Parses the historical registration body used by the closed Capture request.
///
/// Its original header is structural history; the Capture header and signed
/// request own fresh admission. This does not issue a physical effect permit.
pub(crate) fn capture_original_records_v2(
    body: &[u8],
    assignment: BrokerAssignment,
) -> Result<StorageOutputReserveRecordsV1, ProtocolValidationError> {
    if body.is_empty() || body.len() > MAXIMUM_BODY_BYTES {
        return Err(invalid());
    }
    parse_reserve_records_profile(assignment, None, body, OutputReserveProfileV1::Captured)
}

fn parse_reserve_records_profile(
    assignment: BrokerAssignment,
    expected_request_id: Option<[u8; 16]>,
    body: &[u8],
    profile: OutputReserveProfileV1,
) -> Result<StorageOutputReserveRecordsV1, ProtocolValidationError> {
    let request = ReserveStorageExecutionOutputRequestV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let header = request.header.as_option().ok_or_else(invalid)?;
    if !request.__buffa_unknown_fields.is_empty()
        || request.encode_to_vec() != body
        || (match expected_request_id {
            Some(request_id) => header.request_id != request_id,
            None => exact_nonzero::<16>(&header.request_id, "original Storage request").is_err(),
        })
        || header.protocol_major != 1
        || header.protocol_minor != 0
        || header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER)
    {
        return Err(invalid());
    }
    let records = StorageOutputReserveRecordsV1::from_canonical_records_profile(
        &request.canonical_controller_attempt,
        &request.canonical_controller_settlement,
        profile,
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
    Ok(records)
}

/// Parses a fresh historical query without admitting a Storage effect.
///
/// The original reserve deadline may have elapsed; only the query header must
/// still be live. Storage must compare every original field with its protected
/// attempt before returning a historical observation.
///
/// # Errors
///
/// Rejects a noncanonical query, reused reserve ID, stale query header, or
/// substituted original body, plan digest, or semantic commitment.
pub fn decode_storage_output_query_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageOutputQueryRequestV1, ProtocolValidationError> {
    decode_query_profile(body, peer, policy, now_boottime_nanoseconds, OutputReserveProfileV1::LegacyZero)
}

/// Parses a historical captured-output query without authorizing a new effect.
///
/// # Errors
///
/// Rejects changed original records, commitments, query identity, or current header.
pub fn decode_captured_storage_output_query_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageOutputQueryRequestV1, ProtocolValidationError> {
    decode_query_profile(body, peer, policy, now_boottime_nanoseconds, OutputReserveProfileV1::Captured)
}

fn decode_query_profile(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
    profile: OutputReserveProfileV1,
) -> Result<ValidatedStorageOutputQueryRequestV1, ProtocolValidationError> {
    let (query, original_id, records, original_semantic_digest) = parse_query_parts(body, profile)?;
    let header = validate_request_header(
        query
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::StorageBroker,
        now_boottime_nanoseconds,
    )?;
    if header.request_id() == &original_id
        || header.protocol_version() != ProtocolVersion::new(1, 0)
    {
        return Err(invalid());
    }
    let original_plan_digest = ObjectDigest::from_bytes(
        query.original_signed_plan_digest[..]
            .try_into()
            .map_err(|_| invalid())?,
    );
    Ok(ValidatedStorageOutputQueryRequestV1 {
        header,
        original_request_id: original_id,
        original_body: query.canonical_original_reserve_request,
        original_plan_digest,
        original_semantic_digest,
        records,
    })
}

/// Compiles a distinct read-only query grant over a fresh signed request.
///
/// # Errors
///
/// Rejects a query whose original reserve body, original plan digest, or
/// semantic commitment does not exactly match its embedded identity.
pub fn storage_output_query_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    body: &[u8],
) -> Result<BrokerGrant, ProtocolValidationError> {
    query_grant_profile(assignment, request_id, body, OutputReserveProfileV1::LegacyZero)
}

/// Compiles a fresh historical-query commitment for captured-output records.
///
/// # Errors
///
/// Rejects substituted original records, commitments, assignment, or request identity.
pub fn captured_storage_output_query_grant_v1(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    body: &[u8],
) -> Result<BrokerGrant, ProtocolValidationError> {
    query_grant_profile(assignment, request_id, body, OutputReserveProfileV1::Captured)
}

fn query_grant_profile(
    assignment: BrokerAssignment,
    request_id: [u8; 16],
    body: &[u8],
    profile: OutputReserveProfileV1,
) -> Result<BrokerGrant, ProtocolValidationError> {
    let (query, original_id, records, _) = parse_query_parts(body, profile)?;
    let header = query.header.as_option().ok_or_else(invalid)?;
    if request_id == [0; 16]
        || header.request_id != request_id
        || request_id == original_id
        || assignment != records.assignment()
    {
        return Err(invalid());
    }
    let mut statement = Vec::with_capacity(QUERY_GRANT_DOMAIN.len() + 1 + 16 + body.len());
    statement.extend_from_slice(QUERY_GRANT_DOMAIN);
    statement.push(1);
    statement.extend_from_slice(&request_id);
    statement.extend_from_slice(body);
    BrokerGrant::new(
        BrokerVerb::StorageQueryExecutionOutput,
        BrokerGrantTarget::Assignment,
        BrokerArgumentCommitment::for_canonical_bytes(&statement),
        MAXIMUM_BODY_BYTES as u32,
        0,
    )
    .map_err(|_| invalid())
}

fn parse_query_parts(
    body: &[u8],
    profile: OutputReserveProfileV1,
) -> Result<
    (
        QueryStorageExecutionOutputRequestV1,
        [u8; 16],
        StorageOutputReserveRecordsV1,
        ObjectDigest,
    ),
    ProtocolValidationError,
> {
    if body.is_empty() || body.len() > MAXIMUM_BODY_BYTES {
        return Err(invalid());
    }
    let query = QueryStorageExecutionOutputRequestV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !query.__buffa_unknown_fields.is_empty() || query.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = query.header.as_option().ok_or_else(invalid)?;
    if header.protocol_major != 1
        || header.protocol_minor != 0
        || header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER)
        || header.deadline_boottime_nanoseconds == 0
        || query.original_signed_plan_digest.len() != 32
        || query.original_signed_plan_digest == [0; 32]
        || query.original_semantic_request_digest.len() != 32
    {
        return Err(invalid());
    }
    let original = ReserveStorageExecutionOutputRequestV1::decode_from_slice(
        &query.canonical_original_reserve_request,
    )
    .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let original_header = original.header.as_option().ok_or_else(invalid)?;
    let original_id: [u8; 16] = original_header
        .request_id
        .as_slice()
        .try_into()
        .map_err(|_| invalid())?;
    let records = StorageOutputReserveRecordsV1::from_canonical_records_profile(
        &original.canonical_controller_attempt,
        &original.canonical_controller_settlement,
        profile,
    )?;
    let original_grant = reserve_grant_profile(
        records.assignment(),
        original_id,
        &query.canonical_original_reserve_request,
        profile,
    )?;
    let semantic_digest = original_grant.argument_commitment().digest();
    if query.original_semantic_request_digest != *semantic_digest.as_bytes() {
        return Err(invalid());
    }
    Ok((query, original_id, records, semantic_digest))
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
pub(crate) mod tests {
    use aos_sandbox_api::aos::sandbox::local::v1::{Audience, RequestHeader};
    use aos_sandbox_model::{AssignmentEpoch, DesiredGeneration, IncarnationId, SandboxId};

    use super::*;

    #[test]
    fn captured_quantities_require_the_same_preissue_claim_and_parent_bound() {
        let mut source = [0; 688];
        source[80..88].copy_from_slice(&7_u64.to_be_bytes());
        source[88..96].copy_from_slice(&3_u64.to_be_bytes());
        source[424..432].copy_from_slice(&10_u64.to_be_bytes());
        source[432..440].copy_from_slice(&10_u64.to_be_bytes());
        source[440..448].copy_from_slice(&7_u64.to_be_bytes());
        source[448..456].copy_from_slice(&3_u64.to_be_bytes());

        assert!(!OutputReserveProfileV1::Captured.rejects_quantities(&source));
        assert!(OutputReserveProfileV1::LegacyZero.rejects_quantities(&source));

        source[432..440].copy_from_slice(&9_u64.to_be_bytes());
        assert!(OutputReserveProfileV1::Captured.rejects_quantities(&source));
        source[432..440].copy_from_slice(&10_u64.to_be_bytes());
        source[440..448].copy_from_slice(&8_u64.to_be_bytes());
        assert!(OutputReserveProfileV1::Captured.rejects_quantities(&source));

        source[80..88].copy_from_slice(&u64::MAX.to_be_bytes());
        source[440..448].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(OutputReserveProfileV1::Captured.rejects_quantities(&source));
    }

    use super::fixture::{fixture, captured_fixture, seal};

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

    #[test]
    fn cold_query_has_distinct_grant_and_preserves_expired_original() {
        let (original, assignment) = fixture();
        let original_body = original.encode_to_vec();
        let reserve =
            storage_output_reserve_grant_v1(assignment, [18; 16], &original_body).unwrap();
        let query = QueryStorageExecutionOutputRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![19; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 1_100,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            canonical_original_reserve_request: original_body,
            original_signed_plan_digest: vec![20; 32],
            original_semantic_request_digest: reserve
                .argument_commitment()
                .digest()
                .as_bytes()
                .to_vec(),
            ..Default::default()
        };
        let body = query.encode_to_vec();
        let grant = storage_output_query_grant_v1(assignment, [19; 16], &body).unwrap();
        assert_eq!(grant.verb(), BrokerVerb::StorageQueryExecutionOutput);
        assert_ne!(grant.argument_commitment(), reserve.argument_commitment());

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
        let decoded = decode_storage_output_query_request_v1(&body, peer, policy, 1_000).unwrap();
        assert_eq!(decoded.original_request_id(), [18; 16]);
        assert_eq!(
            decoded.original_plan_digest(),
            ObjectDigest::from_bytes([20; 32])
        );
        assert!(decode_storage_output_query_request_v1(&body, peer, policy, 1_100).is_err());

        let mut reused_id = query.clone();
        let mut header = reused_id.header.as_option().unwrap().clone();
        header.request_id = vec![18; 16];
        reused_id.header = Some(header).into();
        assert!(
            storage_output_query_grant_v1(assignment, [18; 16], &reused_id.encode_to_vec())
                .is_err()
        );

        let mut substituted = query.clone();
        substituted.original_semantic_request_digest[0] ^= 1;
        assert!(
            storage_output_query_grant_v1(assignment, [19; 16], &substituted.encode_to_vec())
                .is_err()
        );

        let mut substituted = query;
        substituted.canonical_original_reserve_request[0] ^= 1;
        assert!(
            storage_output_query_grant_v1(assignment, [19; 16], &substituted.encode_to_vec())
                .is_err()
        );
    }
}

/// Bounds canonical logical-output inspection carriers before their allocation.
///
/// This geometry describes only the existing generated/validated records and
/// named encoding planes. It performs no parse, IO, admission or allocation.
///
/// # Errors
/// Returns an arithmetic refusal if the actual body width cannot be represented.
pub fn storage_output_inspection_receiving_bytes_v1(body_bytes: usize)
    -> Result<usize, aos_sandbox_model::AccountingError>
{
    use aos_sandbox_model::{AccountingError, ResourceDimension};
    let overflow = || AccountingError::ArithmeticOverflow { dimension: ResourceDimension::MemoryBytes };
    let statement = GRANT_DOMAIN.len().checked_add(1 + 16)
        .and_then(|prefix| prefix.checked_add(body_bytes)).ok_or_else(overflow)?;
    let typed = [
        std::mem::size_of::<ReserveStorageExecutionOutputRequestV1>(),
        std::mem::size_of::<ReserveStorageExecutionOutputRequestV1>(),
        std::mem::size_of::<aos_sandbox_api::aos::sandbox::local::v1::RequestHeader>(),
        std::mem::size_of::<StorageOutputReserveRecordsV1>(),
        std::mem::size_of::<StorageOutputReserveRecordsV1>(),
        std::mem::size_of::<BrokerGrant>(),
    ].into_iter().try_fold(0usize, |bytes, width| bytes.checked_add(width).ok_or_else(overflow))?;
    // The outer inspector remains live while the grant revalidates the body.
    // Each canonical generated field set is bounded by its actual wire bytes.
    [body_bytes, body_bytes, body_bytes, statement].into_iter()
        .try_fold(typed, |bytes, width| bytes.checked_add(width).ok_or_else(overflow))
}
