//! Closed, read-only Storage execution-capture candidate wire.
//!
//! The fixed query and candidate are structural packets. Their AOSCIS01
//! checksum is not a Controller signature, and their digest is not a Storage
//! outcome signature. A future method-41 issuer must verify the pinned BSA
//! Controller session, exact session binding, signed plan, protected AOSEOR03,
//! catalog head, and live ZFS before emitting a signed candidate response. It
//! must recompute `BrokerAssignment::digest()` from the current canonical
//! assignment manifest instead of trusting the query's assignment bytes.
//! No reserve, writer, or Host effect follows from parsing these bytes.
//!
//! ```text
//! AOSSCQ01 | AOSCIS01[208] | AOSEOR02-digest[32]
//!          | sandbox[16] | incarnation[16] | epoch:u64be
//!          | desired-generation:u64be | assignment-digest[32]
//!          | Host-boot[16] | authenticated-BSA-session-binding[32]
//!          | method41-request-id[16] | method41-deadline:u64be
//! AOSSCB01 | AOSSCQ01[400] | Storage-resolved-AOSEOR03-digest[32]
//!          | output-journal-sequence:u64be | catalog-generation:u64be
//!          | catalog-head-digest[32] | Storage-boot[16] | expiry:u64be
//!          | policy-digest[32] | Storage-create-operation[16]
//!          | admitted/stdout/stderr/allocation/metadata/floor:u64be each
//!          | pool/root-GUID:u64be each | pool/root-available:u64be each
//!          | preflight-digest[32] | candidate-checksum[32]
//! ```

use aos_proto::aos::sandbox::local::v1::{
    ReadStorageExecutionCaptureCandidateRequestV1, StorageExecutionCaptureCandidateV1,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment, BrokerGrant, BrokerGrantTarget,
    BrokerVerb, DesiredGeneration, IncarnationId, ObjectDigest, ProtocolId, ProtocolVersion,
    SandboxId,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::storage_capture_grant::ControllerOutputSettlementPreimageV1;
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, validate_request_header,
};

/// Exact fixed read-only candidate query length.
pub const STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1: usize = 400;
/// Exact fixed read-only candidate response length.
pub const STORAGE_CAPTURE_CANDIDATE_BYTES_V1: usize = 704;

const QUERY_MAGIC: &[u8; 8] = b"AOSSCQ01";
const CANDIDATE_MAGIC: &[u8; 8] = b"AOSSCB01";
const CANDIDATE_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-candidate.v1\0";
const ARGUMENT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-candidate-argument.v1\0";
const MAXIMUM_CANDIDATE_LIFETIME_NANOSECONDS: u64 = 5_000_000_000;
const MAXIMUM_REQUEST_BODY_BYTES: usize = 1_024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 1_024;
const STORAGE_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// Retains one canonical, structurally valid pre-grant query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCaptureCandidateQueryV1 {
    bytes: [u8; STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1],
    settlement: ControllerOutputSettlementPreimageV1,
    assignment: BrokerAssignment,
}

impl StorageCaptureCandidateQueryV1 {
    /// Assembles a structural query from sources already joined by its caller.
    ///
    /// This does not authenticate the Controller settlement, current
    /// assignment manifest, Host claim, or BSA transcript. A Controller issuer
    /// must prove those sources before signing the verb-50 plan.
    ///
    /// # Errors
    ///
    /// Rejects a zero or malformed source, identity, or request deadline.
    pub fn assemble_structural(
        settlement: &ControllerOutputSettlementPreimageV1,
        output_claim_digest: ObjectDigest,
        assignment: BrokerAssignment,
        host_boot_id: [u8; 16],
        session_binding: [u8; 32],
        request_id: [u8; 16],
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProtocolValidationError> {
        let mut bytes = [0; STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1];
        bytes[..8].copy_from_slice(QUERY_MAGIC);
        bytes[8..216].copy_from_slice(settlement.canonical_bytes());
        bytes[216..248].copy_from_slice(output_claim_digest.as_bytes());
        bytes[248..264].copy_from_slice(assignment.sandbox().as_bytes());
        bytes[264..280].copy_from_slice(assignment.incarnation().as_bytes());
        bytes[280..288].copy_from_slice(&assignment.epoch().get().to_be_bytes());
        bytes[288..296].copy_from_slice(&assignment.desired_generation().get().to_be_bytes());
        bytes[296..328].copy_from_slice(assignment.digest().as_bytes());
        bytes[328..344].copy_from_slice(&host_boot_id);
        bytes[344..376].copy_from_slice(&session_binding);
        bytes[376..392].copy_from_slice(&request_id);
        bytes[392..400].copy_from_slice(&deadline_boottime_nanoseconds.to_be_bytes());
        Self::from_canonical_bytes(&bytes)
    }

    /// Parses fixed query bytes without granting Controller or Storage authority.
    ///
    /// The session binding is only a claim until a pinned BSA verifier compares
    /// it with the transcript derived from both authenticated hello nonces.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical length, sentinel, assignment, or settlement.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        let bytes: [u8; STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1] = bytes
            .try_into()
            .map_err(|_| invalid("Storage capture candidate query"))?;
        if &bytes[..8] != QUERY_MAGIC
            || bytes[216..248] == [0; 32]
            || bytes[328..344] == [0; 16]
            || bytes[344..376] == [0; 32]
            || bytes[376..392] == [0; 16]
            || read_u64(&bytes[392..400]) == 0
        {
            return Err(invalid("Storage capture candidate query"));
        }
        let settlement =
            ControllerOutputSettlementPreimageV1::from_canonical_bytes(&bytes[8..216])?;
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes(field_16(&bytes[248..264])),
            IncarnationId::from_bytes(field_16(&bytes[264..280])),
            AssignmentEpoch::new(read_u64(&bytes[280..288])),
            DesiredGeneration::new(read_u64(&bytes[288..296])),
            ObjectDigest::from_bytes(field_32(&bytes[296..328])),
        )
        .map_err(|_| invalid("Storage capture candidate assignment"))?;
        Ok(Self {
            bytes,
            settlement,
            assignment,
        })
    }

    /// Returns the complete exact query preimage.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1] {
        &self.bytes
    }

    /// Returns the checksum-valid, not independently signed, Controller row.
    #[must_use]
    pub const fn settlement(&self) -> &ControllerOutputSettlementPreimageV1 {
        &self.settlement
    }

    /// Returns the full claimed assignment tuple.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the claimed Host AOSEOR02 record digest.
    #[must_use]
    pub fn output_claim_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(field_32(&self.bytes[216..248]))
    }

    /// Returns the exact Host kernel boot identity.
    #[must_use]
    pub fn host_boot_id(&self) -> [u8; 16] {
        field_16(&self.bytes[328..344])
    }

    /// Returns the claimed binding to compare with the verified BSA transcript.
    #[must_use]
    pub fn claimed_session_binding(&self) -> [u8; 32] {
        field_32(&self.bytes[344..376])
    }

    /// Returns the request identity embedded in the exact signed-plan source.
    #[must_use]
    pub fn request_id(&self) -> [u8; 16] {
        field_16(&self.bytes[376..392])
    }

    /// Returns the request deadline embedded in the exact signed-plan source.
    #[must_use]
    pub fn deadline_boottime_nanoseconds(&self) -> u64 {
        read_u64(&self.bytes[392..400])
    }

    /// Commits the exact query and authenticated request identity for a plan.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero request identifier.
    pub fn argument_commitment(
        &self,
        request_id: [u8; 16],
    ) -> Result<BrokerArgumentCommitment, ProtocolValidationError> {
        if request_id == [0; 16] || request_id != self.request_id() {
            return Err(invalid("Storage capture candidate request ID"));
        }
        let mut bytes = Vec::with_capacity(ARGUMENT_DOMAIN.len() + self.bytes.len());
        bytes.extend_from_slice(ARGUMENT_DOMAIN);
        bytes.extend_from_slice(&self.bytes);
        Ok(BrokerArgumentCommitment::for_canonical_bytes(&bytes))
    }

    /// Builds closed Storage-audience verb-50 plan semantics for this query.
    ///
    /// Structural bytes alone do not authorize a Controller signature or a
    /// Storage readback; the issuer must join its protected sources first.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request identity or broker-grant shape.
    pub fn broker_grant(
        &self,
        request_id: [u8; 16],
    ) -> Result<BrokerGrant, ProtocolValidationError> {
        BrokerGrant::new(
            BrokerVerb::StorageCaptureCandidateReadback,
            BrokerGrantTarget::Assignment,
            self.argument_commitment(request_id)?,
            MAXIMUM_REQUEST_BODY_BYTES as u32,
            0,
        )
        .map_err(|_| invalid("Storage capture candidate plan grant"))
    }
}

/// Carries one canonical method-41 request after ordinary header checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageCaptureCandidateRequestV1 {
    header: ValidatedHeader,
    query: StorageCaptureCandidateQueryV1,
}

impl ValidatedStorageCaptureCandidateRequestV1 {
    /// Returns the exact authenticated-request header to cross-check at BSA.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the structural query, not a grant or currentness proof.
    #[must_use]
    pub const fn query(&self) -> &StorageCaptureCandidateQueryV1 {
        &self.query
    }
}

/// Decodes a canonical method-41 request without admitting it for dispatch.
///
/// # Errors
///
/// Rejects oversized, unknown-field, noncanonical, stale-header, or malformed
/// fixed query bytes. A future issuer must additionally prove BSA session
/// binding, signed plan verb 50, Controller source, and Storage owner currentness.
pub fn decode_storage_capture_candidate_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageCaptureCandidateRequestV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ReadStorageExecutionCaptureCandidateRequestV1::decode_from_slice(body)
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
    if header.protocol_version() != STORAGE_VERSION {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    let query = StorageCaptureCandidateQueryV1::from_canonical_bytes(&request.canonical_query)?;
    if query.request_id() != *header.request_id()
        || query.deadline_boottime_nanoseconds() != header.deadline_boottime_nanoseconds()
    {
        return Err(invalid("Storage capture candidate request header"));
    }
    Ok(ValidatedStorageCaptureCandidateRequestV1 { header, query })
}

/// Retains a checksum-valid candidate only after signed-session verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageCaptureCandidateV1 {
    bytes: [u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1],
}

impl ValidatedStorageCaptureCandidateV1 {
    /// Returns the exact informational candidate bytes.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1] {
        &self.bytes
    }

    /// Returns the Storage-protected current AOSEOR03 record digest.
    #[must_use]
    pub fn output_record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(field_32(&self.bytes[408..440]))
    }

    /// Returns the bounded output-journal sequence observed by Storage.
    #[must_use]
    pub fn output_journal_sequence(&self) -> u64 {
        read_u64(&self.bytes[440..448])
    }

    /// Returns the separately observed catalog generation and head digest.
    #[must_use]
    pub fn catalog_head(&self) -> (u64, ObjectDigest) {
        (
            read_u64(&self.bytes[448..456]),
            ObjectDigest::from_bytes(field_32(&self.bytes[456..488])),
        )
    }

    /// Returns the exact aggregate byte ceiling retained by Storage.
    #[must_use]
    pub fn admitted_bytes(&self) -> u64 {
        read_u64(&self.bytes[560..568])
    }

    /// Returns the exact stdout byte ceiling retained by Storage.
    #[must_use]
    pub fn maximum_stdout_bytes(&self) -> u64 {
        read_u64(&self.bytes[568..576])
    }

    /// Returns the exact stderr byte ceiling retained by Storage.
    #[must_use]
    pub fn maximum_stderr_bytes(&self) -> u64 {
        read_u64(&self.bytes[576..584])
    }

    /// Returns the measured, not owner-pinned, pool GUID and root GUID.
    #[must_use]
    pub fn observed_guids(&self) -> (u64, u64) {
        (
            read_u64(&self.bytes[608..616]),
            read_u64(&self.bytes[616..624]),
        )
    }

    /// Returns the signed-outcome candidate checksum, not a standalone MAC.
    #[must_use]
    pub fn candidate_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(field_32(&self.bytes[672..704]))
    }
}

/// Decodes an exact candidate only after external signed-outcome validation.
///
/// # Errors
///
/// Rejects changed query/request echo, expired or overlong lifetime, invalid
/// split/capacity/GUID, unknown protobuf fields, or checksum substitution.
/// A valid candidate is informational; reserve must re-read both owner heads
/// and live ZFS, including an independently pinned expected pool GUID.
pub fn decode_storage_capture_candidate_response_v1(
    body: &[u8],
    original: &ValidatedStorageCaptureCandidateRequestV1,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageCaptureCandidateV1, ProtocolValidationError> {
    decode_storage_capture_candidate_response_for_query_v1(
        body,
        original.query(),
        original.header().maximum_response_bytes(),
        now_boottime_nanoseconds,
    )
}

/// Decodes a candidate against the Controller's exact authenticated query.
///
/// The caller must first validate the pinned Storage BSA signed outcome and
/// supply its original query, Header response ceiling, and current monotonic
/// clock. This pure comparison does not authenticate the outcome itself.
///
/// # Errors
///
/// Rejects changed query/request echo, expired or overlong lifetime, invalid
/// split/capacity/GUID, unknown protobuf fields, or checksum substitution.
pub fn decode_storage_capture_candidate_response_for_query_v1(
    body: &[u8],
    original_query: &StorageCaptureCandidateQueryV1,
    maximum_response_bytes: u32,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageCaptureCandidateV1, ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES || body.len() > maximum_response_bytes as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = StorageExecutionCaptureCandidateV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let bytes: [u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1] = response
        .canonical_candidate
        .as_slice()
        .try_into()
        .map_err(|_| invalid("Storage capture candidate"))?;
    let expiry = read_u64(&bytes[504..512]);
    let admitted = read_u64(&bytes[560..568]);
    let stdout = read_u64(&bytes[568..576]);
    let stderr = read_u64(&bytes[576..584]);
    let allocation = read_u64(&bytes[584..592]);
    let metadata = read_u64(&bytes[592..600]);
    let floor = read_u64(&bytes[600..608]);
    let minimum_available = allocation.checked_add(floor);
    let mut digest = Sha256::new();
    digest.update(CANDIDATE_DOMAIN);
    digest.update(&bytes[..672]);
    if &bytes[..8] != CANDIDATE_MAGIC
        || &bytes[8..408] != original_query.canonical_bytes().as_slice()
        || bytes[408..440] == [0; 32]
        || read_u64(&bytes[440..448]) == 0
        || read_u64(&bytes[448..456]) == 0
        || bytes[456..488] == [0; 32]
        || bytes[488..504] != original_query.host_boot_id()
        || expiry <= now_boottime_nanoseconds
        || expiry > original_query.deadline_boottime_nanoseconds()
        || expiry > now_boottime_nanoseconds.saturating_add(MAXIMUM_CANDIDATE_LIFETIME_NANOSECONDS)
        || bytes[512..544] == [0; 32]
        || bytes[544..560] == [0; 16]
        || &bytes[544..560] == original_query.settlement().create_operation().as_bytes()
        || admitted == 0
        || stdout.checked_add(stderr) != Some(admitted)
        || metadata == 0
        || floor == 0
        || admitted
            .checked_add(metadata)
            .is_none_or(|required| allocation < required)
        || minimum_available.is_none()
        || read_u64(&bytes[608..616]) == 0
        || read_u64(&bytes[616..624]) == 0
        || minimum_available.is_some_and(|required| {
            read_u64(&bytes[624..632]) < required || read_u64(&bytes[632..640]) < required
        })
        || bytes[640..672] == [0; 32]
        || digest.finalize().as_slice() != &bytes[672..704]
    {
        return Err(invalid("Storage capture candidate"));
    }
    Ok(ValidatedStorageCaptureCandidateV1 { bytes })
}

fn field_16(bytes: &[u8]) -> [u8; 16] {
    let mut field = [0; 16];
    field.copy_from_slice(bytes);
    field
}

fn field_32(bytes: &[u8]) -> [u8; 32] {
    let mut field = [0; 32];
    field.copy_from_slice(bytes);
    field
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap_or([0; 8]))
}

fn invalid(field: &'static str) -> ProtocolValidationError {
    ProtocolValidationError::InvalidField(field)
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};

    use super::*;

    fn query_bytes() -> [u8; STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1] {
        let mut bytes = [0; STORAGE_CAPTURE_CANDIDATE_QUERY_BYTES_V1];
        bytes[..8].copy_from_slice(QUERY_MAGIC);
        let settlement = &mut bytes[8..216];
        settlement[..8].copy_from_slice(b"AOSCIS01");
        settlement[8..24].fill(1);
        settlement[24..40].fill(2);
        settlement[40..72].fill(3);
        settlement[72..104].fill(4);
        settlement[104..112].copy_from_slice(&5_u64.to_be_bytes());
        settlement[112..144].fill(6);
        settlement[144..176].fill(7);
        let mut checksum = Sha256::new();
        checksum.update(b"aos.sandbox.controller-output-settlement.v1\0");
        checksum.update(&settlement[..176]);
        settlement[176..208].copy_from_slice(&checksum.finalize());

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
        bytes
    }

    fn request() -> ReadStorageExecutionCaptureCandidateRequestV1 {
        ReadStorageExecutionCaptureCandidateRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![16; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 1_000,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            canonical_query: query_bytes().to_vec(),
            ..Default::default()
        }
    }

    fn peer() -> (PeerCredentials, PeerPolicy) {
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

    fn candidate_bytes() -> [u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1] {
        let mut bytes = [0; STORAGE_CAPTURE_CANDIDATE_BYTES_V1];
        bytes[..8].copy_from_slice(CANDIDATE_MAGIC);
        bytes[8..408].copy_from_slice(&query_bytes());
        bytes[408..440].fill(8);
        bytes[440..448].copy_from_slice(&2_u64.to_be_bytes());
        bytes[448..456].copy_from_slice(&3_u64.to_be_bytes());
        bytes[456..488].fill(17);
        bytes[488..504].fill(14);
        bytes[504..512].copy_from_slice(&200_u64.to_be_bytes());
        bytes[512..544].fill(18);
        bytes[544..560].fill(19);
        for (range, value) in [
            (560..568, 100_u64),
            (568..576, 60),
            (576..584, 40),
            (584..592, 200),
            (592..600, 20),
            (600..608, 30),
            (608..616, 21),
            (616..624, 11),
            (624..632, 1_000),
            (632..640, 900),
        ] {
            bytes[range].copy_from_slice(&value.to_be_bytes());
        }
        bytes[640..672].fill(22);
        sign_checksum(&mut bytes);
        bytes
    }

    fn sign_checksum(bytes: &mut [u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1]) {
        let mut digest = Sha256::new();
        digest.update(CANDIDATE_DOMAIN);
        digest.update(&bytes[..672]);
        bytes[672..704].copy_from_slice(&digest.finalize());
    }

    fn decode_candidate(
        bytes: [u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1],
        original: &ValidatedStorageCaptureCandidateRequestV1,
    ) -> Result<ValidatedStorageCaptureCandidateV1, ProtocolValidationError> {
        let response = StorageExecutionCaptureCandidateV1 {
            canonical_candidate: bytes.to_vec(),
            ..Default::default()
        };
        decode_storage_capture_candidate_response_v1(&response.encode_to_vec(), original, 100)
    }

    #[test]
    fn query_commits_full_settlement_assignment_and_bsa_session_binding() {
        let (peer, policy) = peer();
        let request = request();
        let parsed = decode_storage_capture_candidate_request_v1(
            &request.encode_to_vec(),
            peer,
            policy,
            100,
        )
        .unwrap();
        assert_eq!(parsed.query().canonical_bytes(), &query_bytes());
        let assembled = StorageCaptureCandidateQueryV1::assemble_structural(
            parsed.query().settlement(),
            parsed.query().output_claim_digest(),
            parsed.query().assignment(),
            parsed.query().host_boot_id(),
            parsed.query().claimed_session_binding(),
            parsed.query().request_id(),
            parsed.query().deadline_boottime_nanoseconds(),
        )
        .unwrap();
        assert_eq!(assembled, *parsed.query());
        assert_eq!(
            parsed.query().settlement().original_host_journal_sequence(),
            5
        );
        assert_eq!(parsed.query().assignment().desired_generation().get(), 2);
        assert_eq!(parsed.query().claimed_session_binding(), [15; 32]);
        assert_eq!(parsed.query().output_claim_digest().as_bytes(), &[9; 32]);
        assert_eq!(
            parsed.query().broker_grant([16; 16]).unwrap().verb(),
            BrokerVerb::StorageCaptureCandidateReadback
        );
        let mut substituted = request.clone();
        substituted.canonical_query[348] ^= 1;
        let changed = decode_storage_capture_candidate_request_v1(
            &substituted.encode_to_vec(),
            peer,
            policy,
            100,
        )
        .unwrap();
        assert_ne!(
            changed
                .query()
                .argument_commitment([16; 16])
                .unwrap()
                .digest(),
            parsed
                .query()
                .argument_commitment([16; 16])
                .unwrap()
                .digest()
        );
        let mut wrong_header = request.clone();
        let mut header = wrong_header.header.as_option().unwrap().clone();
        header.deadline_boottime_nanoseconds = 999;
        wrong_header.header = Some(header).into();
        assert!(
            decode_storage_capture_candidate_request_v1(
                &wrong_header.encode_to_vec(),
                peer,
                policy,
                100,
            )
            .is_err()
        );
        let mut forged_settlement = request;
        forged_settlement.canonical_query[20] ^= 1;
        assert!(
            decode_storage_capture_candidate_request_v1(
                &forged_settlement.encode_to_vec(),
                peer,
                policy,
                100,
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_requires_exact_echo_owner_heads_space_and_checksum() {
        let (peer, policy) = peer();
        let original = decode_storage_capture_candidate_request_v1(
            &request().encode_to_vec(),
            peer,
            policy,
            100,
        )
        .unwrap();
        let valid = candidate_bytes();
        let parsed = decode_candidate(valid, &original).unwrap();
        let response = StorageExecutionCaptureCandidateV1 {
            canonical_candidate: valid.to_vec(),
            ..Default::default()
        };
        let controller_parsed = decode_storage_capture_candidate_response_for_query_v1(
            &response.encode_to_vec(),
            original.query(),
            original.header().maximum_response_bytes(),
            100,
        )
        .unwrap();
        assert_eq!(controller_parsed, parsed);
        assert_eq!(parsed.output_record_digest().as_bytes(), &[8; 32]);
        assert_eq!(parsed.output_journal_sequence(), 2);
        assert_eq!(parsed.catalog_head().0, 3);
        assert_eq!(parsed.observed_guids(), (21, 11));
        assert_ne!(parsed.candidate_digest().as_bytes(), &[0; 32]);

        for offset in [
            20, 216, 248, 344, 376, 392, 408, 440, 448, 456, 488, 512, 544, 608, 640, 672,
        ] {
            let mut changed = valid;
            changed[offset] ^= 1;
            assert!(
                decode_candidate(changed, &original).is_err(),
                "offset {offset}"
            );
        }
        let mut wrong_split = valid;
        wrong_split[568..576].copy_from_slice(&61_u64.to_be_bytes());
        sign_checksum(&mut wrong_split);
        assert!(decode_candidate(wrong_split, &original).is_err());

        let mut exhausted = valid;
        exhausted[624..632].copy_from_slice(&229_u64.to_be_bytes());
        sign_checksum(&mut exhausted);
        assert!(decode_candidate(exhausted, &original).is_err());

        let mut expired = valid;
        expired[504..512].copy_from_slice(&100_u64.to_be_bytes());
        sign_checksum(&mut expired);
        assert!(decode_candidate(expired, &original).is_err());

        let mut zero_pool_guid = valid;
        zero_pool_guid[608..616].fill(0);
        sign_checksum(&mut zero_pool_guid);
        assert!(decode_candidate(zero_pool_guid, &original).is_err());

        let mut absent_catalog_head = valid;
        absent_catalog_head[456..488].fill(0);
        sign_checksum(&mut absent_catalog_head);
        assert!(decode_candidate(absent_catalog_head, &original).is_err());

        let mut absent_output_record = valid;
        absent_output_record[408..440].fill(0);
        sign_checksum(&mut absent_output_record);
        assert!(decode_candidate(absent_output_record, &original).is_err());
    }
}
