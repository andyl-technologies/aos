//! Nonauthorizing wire and signed-plan meaning for retained capture admission.
//!
//! A Controller-signed Storage-audience plan must eventually commit the exact
//! source; this parser only fixes its bytes. Storage must independently cold-
//! read AOSCIS01/AOSCIA01, authenticated Host AOSEOR02/AOSHOP01, AOSEOR03, and
//! its own dataset policy before issuing a durable attempt. Reserve and Query
//! accept only full AOSSCG02; AOSSCG01 is an embedded comparison fragment.
//! Neither method is registered for broker dispatch by this module. Reserve also carries the
//! canonical historical method-46 body for a fresh independent Host readback.
//! The shared registration decoder crosslinks its records to AOSSCG01; those
//! bytes alone do not establish currentness, a signature, or a physical owner.
//!
//! ```text
//! AOSSCG01 | AOSCIS01[208] | AOSEOR03-digest[32] | AOSEOR02-digest[32]
//!          | original-Host-request[16] | sandbox[16] | incarnation[16]
//!          | epoch:u64be | desired-generation:u64be | assignment-digest[32]
//!          | Host-boot[16] | Storage-create-operation[16]
//!          | Storage-dataset-policy-digest[32]
//!          | admitted:u64be | stdout-max:u64be | stderr-max:u64be
//!          | allocation:u64be | metadata-headroom:u64be | pool-floor:u64be
//!          | original-deadline-boottime:u64be | original-reserve-request[16]
//! ```

use aos_sandbox_api::aos::sandbox::local::v1::{
    QueryStorageExecutionCaptureRequestV1, ReserveStorageExecutionCaptureRequestV1,
    StorageExecutionCaptureAttemptStatusV1, StorageExecutionCaptureAttemptV1,
};
use aos_sandbox_model::{
    AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment, BrokerGrant, BrokerGrantTarget,
    BrokerVerb, DesiredGeneration, ExecutionId, IncarnationId, ObjectDigest, OperationId,
    ProtocolId, ProtocolVersion, SandboxId,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_request_header,
};

mod ongoing;
pub use ongoing::{StorageCaptureGrantSourceV2, STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2};

/// Width of the embedded acquisition comparison fragment inside Source944.
pub const STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1: usize = 512;
/// Exact AOSCIS01 settlement preimage length committed by this source.
pub const CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1: usize = 208;

const SOURCE_MAGIC: &[u8; 8] = b"AOSSCG01";
const SETTLEMENT_MAGIC: &[u8; 8] = b"AOSCIS01";
const SETTLEMENT_DOMAIN: &[u8] = b"aos.sandbox.controller-output-settlement.v1\0";
const MAXIMUM_REQUEST_BODY_BYTES: usize = 4 * 1_024;
/// Bounds the canonical physical Capture attempt response accepted by its decoder.
pub const MAXIMUM_RESPONSE_BODY_BYTES: usize = 1_024;
const STORAGE_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// Distinguishes the two non-dispatchable Storage capture wire meanings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageCaptureGrantMethodV1 {
    /// The original one-shot reserve request, not an effect permit by itself.
    Reserve,
    /// A fresh read-only query of that original request.
    Query,
}

impl StorageCaptureGrantMethodV1 {
    /// Returns the exact Storage-audience signed-plan verb for this method.
    #[must_use]
    pub const fn broker_verb(self) -> BrokerVerb {
        match self {
            Self::Reserve => BrokerVerb::StorageReserveExecutionCapture,
            Self::Query => BrokerVerb::StorageQueryExecutionCapture,
        }
    }
}

/// Retains the checksum-verified, complete Controller settlement preimage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerOutputSettlementPreimageV1 {
    bytes: [u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1],
}

impl ControllerOutputSettlementPreimageV1 {
    /// Parses the complete fixed AOSCIS01 record and its internal checksum.
    ///
    /// This establishes structural integrity, not Controller journal custody
    /// or a signature. Storage must authenticate the corresponding grant and
    /// read back its AOSCIA01 source before accepting the record as current.
    ///
    /// # Errors
    ///
    /// Rejects a changed marker, length, required field, or checksum.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        let bytes: [u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1] = bytes
            .try_into()
            .map_err(|_| invalid("Controller output settlement"))?;
        let sequence = u64::from_be_bytes(
            bytes[104..112]
                .try_into()
                .map_err(|_| invalid("Controller output settlement"))?,
        );
        let mut digest = Sha256::new();
        digest.update(SETTLEMENT_DOMAIN);
        digest.update(&bytes[..176]);
        if &bytes[..8] != SETTLEMENT_MAGIC
            || bytes[8..24] == [0; 16]
            || bytes[24..40] == [0; 16]
            || bytes[40..72] == [0; 32]
            || bytes[72..104] == [0; 32]
            || sequence == 0
            || bytes[112..144] == [0; 32]
            || bytes[144..176] == [0; 32]
            || digest.finalize().as_slice() != &bytes[176..208]
        {
            return Err(invalid("Controller output settlement"));
        }
        Ok(Self { bytes })
    }

    /// Returns the exact 208-byte preimage a future Controller plan must bind.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1] {
        &self.bytes
    }

    /// Returns the accepted execution identifier.
    #[must_use]
    pub fn execution(&self) -> ExecutionId {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&self.bytes[8..24]);
        ExecutionId::from_bytes(bytes)
    }

    /// Returns the accepted Create operation identifier.
    #[must_use]
    pub fn create_operation(&self) -> OperationId {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&self.bytes[24..40]);
        OperationId::from_bytes(bytes)
    }

    /// Returns the protected AOSCIA01 original-attempt record digest.
    #[must_use]
    pub fn original_attempt_digest(&self) -> ObjectDigest {
        digest_field(&self.bytes[40..72])
    }

    /// Returns the protected Host AOSHOP01 correlation digest.
    #[must_use]
    pub fn host_correlation_digest(&self) -> ObjectDigest {
        digest_field(&self.bytes[72..104])
    }

    /// Returns the original protected Host journal sequence.
    #[must_use]
    pub fn original_host_journal_sequence(&self) -> u64 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.bytes[104..112]);
        u64::from_be_bytes(bytes)
    }

    /// Returns the protected AOSCIS01 record's domain-separated digest.
    #[must_use]
    pub fn record_digest(&self) -> ObjectDigest {
        digest_field(&self.bytes[176..208])
    }
}

/// Retains the embedded acquisition comparison fragment of full Source944.
///
/// This fragment is not accepted as a standalone request or signed grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCaptureGrantSourceV1 {
    bytes: [u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1],
    settlement: ControllerOutputSettlementPreimageV1,
    assignment: BrokerAssignment,
}

impl StorageCaptureGrantSourceV1 {
    fn from_candidate_data_v2(
        query: &crate::storage_capture_candidate::StorageCaptureCandidateQueryV1,
        candidate: &crate::storage_capture_candidate::ValidatedStorageCaptureCandidateV1,
        original: &crate::storage_output_reserve::StorageOutputReserveRecordsV1,
        request_id: [u8; 16], deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProtocolValidationError> {
        let bytes = candidate.canonical_bytes();
        let locator = original.host_locator();
        let (admitted, stdout, stderr) = original.output_limits_v2();
        if bytes[8..408] != *query.canonical_bytes()
            || original.settlement() != query.settlement().canonical_bytes()
            || original.assignment() != query.assignment()
            || locator.claim_digest() != query.output_claim_digest()
            || locator.execution() != query.settlement().execution()
            || locator.create_operation() != query.settlement().create_operation()
            || locator.host_boot_id() != query.host_boot_id()
            || candidate.admitted_bytes() != admitted
            || candidate.maximum_stdout_bytes() != stdout
            || candidate.maximum_stderr_bytes() != stderr
            || request_id == [0; 16] || request_id == query.request_id()
            || request_id == locator.original_request_id()
            || deadline_boottime_nanoseconds == 0
            || deadline_boottime_nanoseconds > read_u64_fixed(&bytes[504..512])
        {
            return Err(invalid("Storage capture candidate/original source"));
        }
        let mut source = [0; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1];
        source[..8].copy_from_slice(SOURCE_MAGIC);
        source[8..216].copy_from_slice(query.settlement().canonical_bytes());
        source[216..248].copy_from_slice(candidate.output_record_digest().as_bytes());
        source[248..280].copy_from_slice(query.output_claim_digest().as_bytes());
        source[280..296].copy_from_slice(&locator.original_request_id());
        source[296..376].copy_from_slice(&query.canonical_bytes()[248..328]);
        source[376..392].copy_from_slice(&query.host_boot_id());
        source[392..408].copy_from_slice(&bytes[544..560]);
        source[408..440].copy_from_slice(&bytes[512..544]);
        source[440..488].copy_from_slice(&bytes[560..608]);
        source[488..496].copy_from_slice(&deadline_boottime_nanoseconds.to_be_bytes());
        source[496..512].copy_from_slice(&request_id);
        Self::from_canonical_bytes(&source)
    }

    /// Parses one exact source without claiming it was signed or issued.
    ///
    /// # Errors
    ///
    /// Rejects malformed settlement, assignment, split, policy, boot,
    /// operation, deadline, or request identity fields.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        let bytes: [u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1] = bytes
            .try_into()
            .map_err(|_| invalid("Storage capture source"))?;
        if &bytes[..8] != SOURCE_MAGIC {
            return Err(invalid("Storage capture source"));
        }
        let settlement =
            ControllerOutputSettlementPreimageV1::from_canonical_bytes(&bytes[8..216])?;
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes(exact_nonzero::<16>(&bytes[296..312], "sandbox")?),
            IncarnationId::from_bytes(exact_nonzero::<16>(&bytes[312..328], "incarnation")?),
            AssignmentEpoch::new(read_u64(&bytes[328..336])?),
            DesiredGeneration::new(read_u64(&bytes[336..344])?),
            ObjectDigest::from_bytes(exact_nonzero::<32>(&bytes[344..376], "assignment digest")?),
        )
        .map_err(|_| invalid("Storage capture assignment"))?;
        let admitted = read_u64(&bytes[440..448])?;
        let stdout = read_u64(&bytes[448..456])?;
        let stderr = read_u64(&bytes[456..464])?;
        let allocation = read_u64(&bytes[464..472])?;
        let metadata = read_u64(&bytes[472..480])?;
        let floor = read_u64(&bytes[480..488])?;
        if bytes[216..248] == [0; 32]
            || bytes[248..280] == [0; 32]
            || bytes[280..296] == [0; 16]
            || bytes[376..392] == [0; 16]
            || bytes[392..408] == [0; 16]
            || bytes[392..408] == *settlement.create_operation().as_bytes()
            || bytes[408..440] == [0; 32]
            || stdout.checked_add(stderr) != Some(admitted)
            || metadata == 0
            || floor == 0
            || admitted
                .checked_add(metadata)
                .is_none_or(|needed| allocation < needed)
            || allocation.checked_add(floor).is_none()
            || read_u64(&bytes[488..496])? == 0
            || bytes[496..512] == [0; 16]
        {
            return Err(invalid("Storage capture source"));
        }
        Ok(Self {
            bytes,
            settlement,
            assignment,
        })
    }

    /// Returns the exact nonauthorizing source bytes.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1] {
        &self.bytes
    }

    /// Returns the complete checksum-verified AOSCIS01 preimage.
    #[must_use]
    pub const fn settlement(&self) -> &ControllerOutputSettlementPreimageV1 {
        &self.settlement
    }

    /// Returns the current assignment claimed by this source.
    #[must_use]
    pub const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }

    /// Returns the raw AOSEOR02 claim digest for later Host/currentness join.
    #[must_use]
    pub fn output_claim_digest(&self) -> ObjectDigest {
        digest_field(&self.bytes[248..280])
    }

    /// Returns the Storage-protected AOSEOR03 record digest.
    #[must_use]
    pub fn output_record_digest(&self) -> ObjectDigest {
        digest_field(&self.bytes[216..248])
    }

    /// Returns the Storage-selected dataset policy commitment to verify.
    #[must_use]
    pub fn dataset_policy_digest(&self) -> ObjectDigest {
        digest_field(&self.bytes[408..440])
    }

    /// Returns the exact original Host method-35 request identifier.
    #[must_use]
    pub fn original_host_request_id(&self) -> [u8; 16] {
        field_16(&self.bytes[280..296])
    }

    /// Returns the original physical Storage method-60 request identifier.
    ///
    /// This is distinct from the historical logical method-46 header ID in
    /// the canonical original body. The complete signed method-60 transport
    /// binds that body; this unchanged source commitment selects method60.
    #[must_use]
    pub fn original_reserve_request_id(&self) -> [u8; 16] {
        field_16(&self.bytes[496..512])
    }

    /// Returns the exact Storage dataset-create operation identifier.
    #[must_use]
    pub fn storage_create_operation(&self) -> OperationId {
        OperationId::from_bytes(field_16(&self.bytes[392..408]))
    }

    /// Returns the Host kernel boot identity committed by the source.
    #[must_use]
    pub fn host_boot_id(&self) -> [u8; 16] {
        field_16(&self.bytes[376..392])
    }

    /// Returns both per-stream ceilings and their exact admitted sum.
    #[must_use]
    pub fn output_limits(&self) -> (u64, u64, u64) {
        (
            read_u64_fixed(&self.bytes[440..448]),
            read_u64_fixed(&self.bytes[448..456]),
            read_u64_fixed(&self.bytes[456..464]),
        )
    }

    /// Returns Storage's allocation, metadata allowance, and protected floor.
    #[must_use]
    pub fn space_policy(&self) -> (u64, u64, u64) {
        (
            read_u64_fixed(&self.bytes[464..472]),
            read_u64_fixed(&self.bytes[472..480]),
            read_u64_fixed(&self.bytes[480..488]),
        )
    }

    /// Returns the original reserve deadline on the monotonic boot clock.
    #[must_use]
    pub fn original_deadline_boottime_nanoseconds(&self) -> u64 {
        read_u64_fixed(&self.bytes[488..496])
    }

}

fn capture_argument_commitment_data_v2(method: StorageCaptureGrantMethodV1,
    request_id: [u8; 16], original_request_id: [u8; 16], domain: &[u8], source: &[u8])
    -> Result<BrokerArgumentCommitment, ProtocolValidationError>
{
        if request_id == [0; 16]
            || (method == StorageCaptureGrantMethodV1::Reserve
                && request_id != original_request_id)
            || (method == StorageCaptureGrantMethodV1::Query
                && request_id == original_request_id)
        {
            return Err(invalid("Storage capture plan request ID"));
        }
        let mut bytes = Vec::with_capacity(domain.len() + 1 + 16 + source.len());
        bytes.extend_from_slice(domain);
        bytes.push(match method {
            StorageCaptureGrantMethodV1::Reserve => 1,
            StorageCaptureGrantMethodV1::Query => 2,
        });
        bytes.extend_from_slice(&request_id);
        bytes.extend_from_slice(source);
        Ok(BrokerArgumentCommitment::for_canonical_bytes(&bytes))
}

/// Names the one original reserve source and AOSEOR03 record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCaptureAttemptLocatorV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    original_reserve_request_id: [u8; 16],
    source_digest: ObjectDigest,
    output_record_digest: ObjectDigest,
    original_deadline_boottime_nanoseconds: u64,
}

impl StorageCaptureAttemptLocatorV1 {
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

    /// Returns the original Storage reserve request identifier.
    #[must_use]
    pub const fn original_reserve_request_id(self) -> [u8; 16] {
        self.original_reserve_request_id
    }

    /// Returns the complete source commitment.
    #[must_use]
    pub const fn source_digest(self) -> ObjectDigest {
        self.source_digest
    }

    /// Returns the protected AOSEOR03 record digest.
    #[must_use]
    pub const fn output_record_digest(self) -> ObjectDigest {
        self.output_record_digest
    }
}

/// Retains a strictly parsed reserve request pending signature verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedStorageCaptureReserveRequestV1 {
    header: ValidatedHeader,
    ongoing: StorageCaptureGrantSourceV2,
    original_body: Vec<u8>,
    original_records: crate::storage_output_reserve::StorageOutputReserveRecordsV1,
}

impl ValidatedStorageCaptureReserveRequestV1 {
    /// Returns the validated broker request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows the embedded acquisition coordinates as comparison DATA.
    #[must_use]
    pub const fn source(&self) -> &StorageCaptureGrantSourceV1 {
        self.ongoing.original_source_v1()
    }

    /// Borrows the full signed Source944 comparison DATA.
    #[must_use]
    pub const fn ongoing_source_v2(&self) -> Option<&StorageCaptureGrantSourceV2> { Some(&self.ongoing) }

    /// Builds canonical method-specific source semantics without admitting an effect.
    ///
    /// # Errors
    /// Rejects an absent/reused request ID under the selected source version.
    pub fn argument_commitment_data_v2(&self) -> Result<BrokerArgumentCommitment, ProtocolValidationError> {
        self.ongoing.argument_commitment_v2(StorageCaptureGrantMethodV1::Reserve, *self.header.request_id())
    }

    /// Borrows the canonical historical method-46 request crosslinked to this source.
    #[must_use]
    pub fn canonical_original_storage_output_request_v2(&self) -> &[u8] {
        &self.original_body
    }

    /// Borrows the original records decoded by the shared registration grammar.
    #[must_use]
    pub const fn original_output_records_v2(
        &self,
    ) -> &crate::storage_output_reserve::StorageOutputReserveRecordsV1 {
        &self.original_records
    }

}

/// Retains a strictly parsed cold query, never a fresh reserve permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageCaptureQueryRequestV1 {
    header: ValidatedHeader,
    ongoing: StorageCaptureGrantSourceV2,
}

impl ValidatedStorageCaptureQueryRequestV1 {
    /// Returns the validated fresh query header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows the full signed Source944 comparison DATA.
    #[must_use]
    pub const fn ongoing_source_v2(&self) -> Option<&StorageCaptureGrantSourceV2> { Some(&self.ongoing) }

    /// Builds canonical method-specific source semantics without admitting an effect.
    ///
    /// # Errors
    /// Rejects an absent/reused request ID under the selected source version.
    pub fn argument_commitment_data_v2(&self) -> Result<BrokerArgumentCommitment, ProtocolValidationError> {
        self.ongoing.argument_commitment_v2(StorageCaptureGrantMethodV1::Query, *self.header.request_id())
    }

    /// Borrows the embedded acquisition coordinates as comparison DATA.
    #[must_use]
    pub const fn source(&self) -> &StorageCaptureGrantSourceV1 {
        self.ongoing.original_source_v1()
    }
}

/// Parses the original reserve body without admitting an effect.
///
/// # Errors
///
/// Rejects oversized, noncanonical, stale-header, changed-source, or invalid
/// assignment/settlement/limit fields.
pub fn decode_storage_capture_reserve_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageCaptureReserveRequestV1, ProtocolValidationError> {
    let (header, ongoing, original_body) = decode_request(
        body,
        peer,
        policy,
        now_boottime_nanoseconds,
        StorageCaptureGrantMethodV1::Reserve,
    )?;
    let source = ongoing.original_source_v1();
    if source.original_reserve_request_id() != *header.request_id()
        || source.original_deadline_boottime_nanoseconds() != header.deadline_boottime_nanoseconds()
    {
        return Err(invalid("Storage capture original request"));
    }
    let original_body = original_body.ok_or_else(|| invalid("Storage capture original body"))?;
    let original_records = crate::storage_output_reserve::capture_original_records_v2(
        &original_body,
        source.assignment(),
    )?;
    let locator = original_records.host_locator();
    if original_records.settlement() != source.settlement().canonical_bytes()
        || original_records.assignment() != source.assignment()
        || locator.execution() != source.settlement().execution()
        || locator.create_operation() != source.settlement().create_operation()
        || locator.claim_digest() != source.output_claim_digest()
        || locator.original_request_id() != source.original_host_request_id()
        || locator.host_boot_id() != source.host_boot_id()
        || original_records.output_limits_v2() != source.output_limits()
    {
        return Err(invalid("Storage capture original records"));
    }
    Ok(ValidatedStorageCaptureReserveRequestV1 {
        header,
        ongoing,
        original_body,
        original_records,
    })
}

/// Parses a fresh read-only query of the original source.
///
/// # Errors
///
/// Rejects oversized, noncanonical, stale-header, changed-source, or reused
/// original request identity. Source expiry does not make historical query
/// impossible; the query header still needs its own fresh deadline.
pub fn decode_storage_capture_query_request_v1(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedStorageCaptureQueryRequestV1, ProtocolValidationError> {
    let (header, ongoing, _) = decode_request(
        body,
        peer,
        policy,
        now_boottime_nanoseconds,
        StorageCaptureGrantMethodV1::Query,
    )?;
    let source = ongoing.original_source_v1();
    if source.original_reserve_request_id() == *header.request_id() {
        return Err(invalid("Storage capture query request"));
    }
    Ok(ValidatedStorageCaptureQueryRequestV1 { header, ongoing })
}

fn decode_request(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
    method: StorageCaptureGrantMethodV1,
) -> Result<
    (ValidatedHeader, StorageCaptureGrantSourceV2, Option<Vec<u8>>),
    ProtocolValidationError,
> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let (header, source, original_body) = match method {
        StorageCaptureGrantMethodV1::Reserve => {
            let request = ReserveStorageExecutionCaptureRequestV1::decode_from_slice(body)
                .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
            if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
                return Err(ProtocolValidationError::UnknownFields);
            }
            (
                request.header,
                request.canonical_grant_source,
                Some(request.canonical_original_storage_output_request),
            )
        }
        StorageCaptureGrantMethodV1::Query => {
            let request = QueryStorageExecutionCaptureRequestV1::decode_from_slice(body)
                .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
            if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
                return Err(ProtocolValidationError::UnknownFields);
            }
            (request.header, request.canonical_grant_source, None)
        }
    };
    let header = validate_request_header(
        header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::StorageBroker,
        now,
    )?;
    if header.protocol_version() != STORAGE_VERSION {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    // No deployed standalone Source512 format exists. Refuse it before any
    // grant or outcome context can be formed; the full lifetime is mandatory.
    let source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&source)?;
    Ok((header, source, original_body))
}

/// Distinguishes historical absence from a durable possible-effect fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageCaptureAttemptStatusV1 {
    /// No matching protected Storage attempt exists.
    Absent,
    /// The exact protected attempt may have changed ZFS state.
    EffectPossible,
}

/// Retains a canonical response only after external signed-session validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageCaptureAttemptV1 {
    status: StorageCaptureAttemptStatusV1,
    locator: StorageCaptureAttemptLocatorV1,
    attempt: Option<[u8; 16]>,
    durable_attempt_digest: Option<ObjectDigest>,
    effective_deadline_boottime_nanoseconds: Option<u64>,
}

impl ValidatedStorageCaptureAttemptV1 {
    /// Returns the protected absence or possible-effect state.
    #[must_use]
    pub const fn status(self) -> StorageCaptureAttemptStatusV1 {
        self.status
    }

    /// Returns the exact original source locator.
    #[must_use]
    pub const fn locator(self) -> StorageCaptureAttemptLocatorV1 {
        self.locator
    }

    /// Returns the Storage attempt identity only after the effect fence exists.
    #[must_use]
    pub const fn attempt(self) -> Option<[u8; 16]> {
        self.attempt
    }

    /// Returns the original persisted native effect horizon, without renewal.
    ///
    /// The authenticated Storage producer derives it from the SAME admitted
    /// plan, ownership lease and original source request. Absence has no horizon.
    #[must_use]
    pub const fn effective_deadline_boottime_nanoseconds(self) -> Option<u64> {
        self.effective_deadline_boottime_nanoseconds
    }

    /// Returns the protected Storage attempt record digest when committed.
    #[must_use]
    pub const fn durable_attempt_digest(self) -> Option<ObjectDigest> {
        self.durable_attempt_digest
    }
}

/// Retains a historical attempt and optional full durable Complete comparison DATA.
///
/// Authentication, native currentness and actual Source/C ownership remain with
/// the caller. A cold completed record cannot authorize another Capture flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageCaptureQueryResponseV2 {
    attempt: ValidatedStorageCaptureAttemptV1,
    complete: Option<crate::storage_capture_result::CaptureCompleteRecordDataV2>,
}

impl ValidatedStorageCaptureQueryResponseV2 {
    /// Returns the original durable attempt association, never a retry permit.
    #[must_use]
    pub const fn attempt(&self) -> ValidatedStorageCaptureAttemptV1 { self.attempt }

    /// Borrows the full complete record only when the canonical response has one.
    #[must_use]
    pub const fn complete_record(&self) -> Option<&crate::storage_capture_result::CaptureCompleteRecordDataV2> {
        self.complete.as_ref()
    }
}

/// Decodes a versioned ongoing admission response against the whole signed source.
///
/// # Errors
/// Rejects foreign source/attempt coordinates, invalid status or a persisted
/// effect horizon beyond the original explicit execution lifetime.
pub fn decode_storage_capture_attempt_response_ongoing_v2(body: &[u8],
    source: &StorageCaptureGrantSourceV2, allow_absent: bool)
    -> Result<ValidatedStorageCaptureAttemptV1, ProtocolValidationError>
{
    decode_capture_response_inner_v2(body, source.locator_v2(), allow_absent, None)
        .map(|value| value.attempt)
}

/// Decodes the complete historical Query61 against its full ongoing source.
///
/// # Errors
/// Rejects incomplete/foreign result DATA or an altered original effect horizon.
pub fn decode_storage_capture_query_response_ongoing_v2(body: &[u8], source: &StorageCaptureGrantSourceV2)
    -> Result<ValidatedStorageCaptureQueryResponseV2, ProtocolValidationError>
{
    decode_capture_response_inner_v2(body, source.locator_v2(), true, Some(source))
}

fn decode_capture_response_inner_v2(body: &[u8], locator: StorageCaptureAttemptLocatorV1,
    allow_absent: bool, query_source: Option<&StorageCaptureGrantSourceV2>,
) -> Result<ValidatedStorageCaptureQueryResponseV2, ProtocolValidationError> {
    if body.len() > MAXIMUM_RESPONSE_BODY_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = StorageExecutionCaptureAttemptV1::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if response.execution_id != locator.execution.as_bytes()
        || response.create_operation_id != locator.create_operation.as_bytes()
        || response.original_reserve_request_id != locator.original_reserve_request_id
        || response.grant_source_digest != locator.source_digest.as_bytes()
        || response.output_record_digest != locator.output_record_digest.as_bytes()
    {
        return Err(invalid("Storage capture locator"));
    }
    let is_complete = response.status.as_known()
        == Some(StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_COMPLETE);
    if !is_complete && !response.canonical_complete_result.is_empty() {
        return Err(invalid("unexpected Storage capture complete result"));
    }
    let (status, attempt, durable_attempt_digest) = match response.status.as_known() {
        Some(StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_ABSENT)
            if allow_absent && response.attempt_id.is_empty() && response.durable_attempt_digest.is_empty()
                && response.effective_deadline_boottime_nanoseconds == 0 =>
        {
            (StorageCaptureAttemptStatusV1::Absent, None, None)
        }
        Some(StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_EFFECT_POSSIBLE)
        | Some(StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_COMPLETE)
            if !is_complete || query_source.is_some() => {
            (
                StorageCaptureAttemptStatusV1::EffectPossible,
                Some(exact_nonzero::<16>(&response.attempt_id, "attempt_id")?),
                Some(ObjectDigest::from_bytes(exact_nonzero::<32>(
                    &response.durable_attempt_digest,
                    "durable_attempt_digest",
                )?)),
            )
        }
        _ => return Err(invalid("Storage capture attempt status")),
    };
    let effective_deadline = match status {
        StorageCaptureAttemptStatusV1::Absent => None,
        StorageCaptureAttemptStatusV1::EffectPossible => {
            let deadline = response.effective_deadline_boottime_nanoseconds;
            if deadline == 0 || deadline > locator.original_deadline_boottime_nanoseconds {
                return Err(invalid("Storage capture original effect deadline"));
            }
            Some(deadline)
        }
    };
    let attempt = ValidatedStorageCaptureAttemptV1 { status, locator, attempt, durable_attempt_digest,
        effective_deadline_boottime_nanoseconds: effective_deadline };
    let complete = if is_complete {
        let record = crate::storage_capture_result::CaptureCompleteRecordDataV2::decode(
            &response.canonical_complete_result).map_err(|_| invalid("Storage capture complete result"))?;
        record.verify_source_ongoing_v2(query_source.ok_or_else(|| invalid("Storage capture query source"))?, attempt)
            .map_err(|_| invalid("Storage capture complete source"))?;
        Some(record)
    } else { None };
    Ok(ValidatedStorageCaptureQueryResponseV2 { attempt, complete })
}

fn field_16(bytes: &[u8]) -> [u8; 16] {
    let mut field = [0; 16];
    field.copy_from_slice(bytes);
    field
}

fn digest_field(bytes: &[u8]) -> ObjectDigest {
    let mut field = [0; 32];
    field.copy_from_slice(bytes);
    ObjectDigest::from_bytes(field)
}

fn read_u64(bytes: &[u8]) -> Result<u64, ProtocolValidationError> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| invalid("Storage capture integer"))?,
    ))
}

fn read_u64_fixed(bytes: &[u8]) -> u64 {
    let mut field = [0; 8];
    field.copy_from_slice(bytes);
    u64::from_be_bytes(field)
}

fn invalid(field: &'static str) -> ProtocolValidationError {
    ProtocolValidationError::InvalidField(field)
}

#[cfg(test)]
pub(crate) mod tests {
    use aos_sandbox_api::aos::sandbox::local::v1::{Audience, RequestHeader};

    use super::*;

    pub(crate) fn source_bytes() -> [u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1] {
        let (request, assignment) = crate::storage_output_reserve::fixture::captured_fixture();
        let records = crate::storage_output_reserve::StorageOutputReserveRecordsV1::from_canonical_captured_records(
            &request.canonical_controller_attempt,
            &request.canonical_controller_settlement,
        ).unwrap();
        let mut source = [0; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1];
        source[..8].copy_from_slice(SOURCE_MAGIC);
        source[8..216].copy_from_slice(records.settlement());
        source[216..248].fill(8);
        source[248..280].copy_from_slice(records.host_locator().claim_digest().as_bytes());
        source[280..296].copy_from_slice(&records.host_locator().original_request_id());
        source[296..312].copy_from_slice(assignment.sandbox().as_bytes());
        source[312..328].copy_from_slice(assignment.incarnation().as_bytes());
        source[328..336].copy_from_slice(&assignment.epoch().get().to_be_bytes());
        source[336..344].copy_from_slice(&assignment.desired_generation().get().to_be_bytes());
        source[344..376].copy_from_slice(assignment.digest().as_bytes());
        source[376..392].copy_from_slice(&records.host_locator().host_boot_id());
        source[392..408].fill(15);
        source[408..440].fill(16);
        for (offset, value) in [
            (440, 100_u64), (448, 60), (456, 40), (464, 200),
            (472, 20), (480, 30), (488, 100),
        ] {
            source[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        source[496..512].fill(17);
        source
    }

    pub(crate) fn original_body() -> Vec<u8> {
        crate::storage_output_reserve::fixture::captured_fixture().0.encode_to_vec()
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

    fn header(request_id: u8, deadline: u64) -> RequestHeader {
        RequestHeader {
            protocol_major: 1,
            request_id: vec![request_id; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes: 8192,
            ..Default::default()
        }
    }

    fn response(locator: StorageCaptureAttemptLocatorV1) -> StorageExecutionCaptureAttemptV1 {
        StorageExecutionCaptureAttemptV1 {
            status: StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_EFFECT_POSSIBLE.into(),
            execution_id: locator.execution().as_bytes().to_vec(),
            create_operation_id: locator.create_operation().as_bytes().to_vec(),
            original_reserve_request_id: locator.original_reserve_request_id().to_vec(),
            grant_source_digest: locator.source_digest().as_bytes().to_vec(),
            output_record_digest: locator.output_record_digest().as_bytes().to_vec(),
            attempt_id: vec![18; 16],
            durable_attempt_digest: vec![19; 32],
            effective_deadline_boottime_nanoseconds: locator.original_deadline_boottime_nanoseconds,
            ..Default::default()
        }
    }

    pub(crate) fn ongoing_source_data() -> StorageCaptureGrantSourceV2 {
        use crate::storage_capture_lifetime::StorageCaptureExecutionLifetimeDataV2;
        use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
        let original = StorageCaptureGrantSourceV1::from_canonical_bytes(&source_bytes()).unwrap();
        let assignment = original.assignment();
        let mut bytes = [1; 424];
        bytes[..8].copy_from_slice(b"AOSCLF02");
        bytes[8..24].copy_from_slice(original.settlement().execution().as_bytes());
        bytes[24..40].copy_from_slice(original.settlement().create_operation().as_bytes());
        bytes[40..56].copy_from_slice(original.settlement().create_operation().as_bytes());
        bytes[120..136].copy_from_slice(assignment.sandbox().as_bytes());
        bytes[136..152].copy_from_slice(assignment.incarnation().as_bytes());
        bytes[152..160].copy_from_slice(&assignment.epoch().get().to_be_bytes());
        bytes[160..168].copy_from_slice(&assignment.desired_generation().get().to_be_bytes());
        bytes[168..200].copy_from_slice(assignment.digest().as_bytes());
        bytes[232..240].copy_from_slice(&1_u64.to_be_bytes());
        let clock = |boot| RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            original.host_boot_id(), 100, boot).unwrap();
        let origin = clock(10);
        for (offset, sample) in [(240, origin), (320, clock(20))] {
            bytes[offset..offset+16].copy_from_slice(&sample.provenance().as_bytes());
            bytes[offset+16..offset+32].copy_from_slice(&sample.host_boot_id());
            bytes[offset+32..offset+40].copy_from_slice(&sample.wall_seconds().to_be_bytes());
            bytes[offset+40..offset+48].copy_from_slice(&sample.boottime_nanoseconds().to_be_bytes());
        }
        bytes[288..296].copy_from_slice(&900_i64.to_be_bytes());
        bytes[296..304].copy_from_slice(&1000_i64.to_be_bytes());
        bytes[304..312].copy_from_slice(&0_u64.to_be_bytes());
        let root = origin.conservative_lease_expiry_deadline_data_v2(1000, 0).unwrap()
            .min(origin.conservative_expiry_deadline_data_v1(900).unwrap());
        bytes[312..320].copy_from_slice(&root.to_be_bytes());
        bytes[368..376].copy_from_slice(&1000_u64.to_be_bytes());
        bytes[376..384].copy_from_slice(&800_i64.to_be_bytes());
        bytes[384..392].copy_from_slice(&1020_u64.to_be_bytes());
        let digest = Sha256::new().chain_update(b"aos.sandbox.storage.capture-execution-lifetime.v2\0")
            .chain_update(&bytes[..392]).finalize();
        bytes[392..].copy_from_slice(&digest);
        let lifetime = StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(&bytes).unwrap();
        StorageCaptureGrantSourceV2::from_original_data_v2(original, lifetime).unwrap()
    }

    #[test]
    fn ongoing_acquisition_keeps_expired_logical_delivery_historical() {
        let source = ongoing_source_data();
        let (peer, policy) = peer();
        let (mut original, _) = crate::storage_output_reserve::fixture::captured_fixture();
        original.header.get_or_insert_default().deadline_boottime_nanoseconds = 1;
        let mut request = ReserveStorageExecutionCaptureRequestV1 {
            header: Some(header(17, 100)).into(),
            canonical_grant_source: source.canonical_bytes_v2().to_vec(),
            canonical_original_storage_output_request: original.encode_to_vec(),
            ..Default::default()
        };
        let decoded = decode_storage_capture_reserve_request_v1(&request.encode_to_vec(), peer, policy, 99).unwrap();
        assert_eq!(decoded.ongoing_source_v2(), Some(&source));
        assert_eq!(decoded.source().original_deadline_boottime_nanoseconds(), 100);
        assert_eq!(source.effective_execution_deadline_v2(), 1020);

        request.canonical_grant_source = source.original_source_v1().canonical_bytes().to_vec();
        assert!(decode_storage_capture_reserve_request_v1(&request.encode_to_vec(), peer, policy, 99).is_err());
    }

    #[test]
    fn ongoing_response_preserves_immutable_execution_bound() {
        let source = ongoing_source_data();
        let mut body = response(source.locator_v2());
        body.effective_deadline_boottime_nanoseconds = 500;
        let encoded = body.encode_to_vec();
        let parsed = decode_storage_capture_attempt_response_ongoing_v2(&encoded, &source, false).unwrap();
        assert_eq!(parsed.effective_deadline_boottime_nanoseconds(), Some(500));
        assert_eq!(source.original_source_v1().original_deadline_boottime_nanoseconds(), 100);

        body.effective_deadline_boottime_nanoseconds = 1021;
        assert!(decode_storage_capture_attempt_response_ongoing_v2(&body.encode_to_vec(), &source, false).is_err());
        assert_eq!(source.effective_execution_deadline_v2(), 1020);
    }

    #[test]
    fn standalone_acquisition_source_is_refused_by_both_wire_methods() {
        let (peer, policy) = peer();
        let reserve = ReserveStorageExecutionCaptureRequestV1 {
            header: Some(header(17, 100)).into(),
            canonical_grant_source: source_bytes().to_vec(),
            canonical_original_storage_output_request: original_body(),
            ..Default::default()
        };
        let query = QueryStorageExecutionCaptureRequestV1 {
            header: Some(header(18, 200)).into(),
            canonical_grant_source: source_bytes().to_vec(),
            ..Default::default()
        };
        assert!(decode_storage_capture_reserve_request_v1(&reserve.encode_to_vec(), peer, policy, 99).is_err());
        assert!(decode_storage_capture_query_request_v1(&query.encode_to_vec(), peer, policy, 150).is_err());
    }

    #[test]
    fn complete_query_requires_full_matching_source_and_both_streams() {
        let source = ongoing_source_data();
        let original = source.original_source_v1();
        let mut complete = crate::storage_capture_result::tests::complete();
        complete.source_digest = source.source_digest_v2();
        complete.execution = *original.settlement().execution().as_bytes();
        complete.create_operation = *original.settlement().create_operation().as_bytes();
        complete.output_record_digest = original.output_record_digest();
        complete.claim_digest = original.output_claim_digest();
        complete.assignment_digest = original.assignment().digest();
        complete.stdout.maximum_bytes = original.output_limits().1;
        complete.stdout.truncated = false;
        complete.stderr.maximum_bytes = original.output_limits().2;
        let mut body = response(source.locator_v2());
        complete.attempt.copy_from_slice(&body.attempt_id);
        complete.durable_attempt_digest = ObjectDigest::from_bytes(body.durable_attempt_digest.as_slice().try_into().unwrap());
        body.status = StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_COMPLETE.into();
        body.canonical_complete_result = complete.encode().unwrap().to_vec();
        let encoded = body.encode_to_vec();
        assert_eq!(decode_storage_capture_query_response_ongoing_v2(&encoded, &source).unwrap().complete_record(), Some(&complete));
        assert!(decode_storage_capture_attempt_response_ongoing_v2(&encoded, &source, false).is_err());
        complete.claim_digest = ObjectDigest::from_bytes([99;32]);
        body.canonical_complete_result = complete.encode().unwrap().to_vec();
        assert!(decode_storage_capture_query_response_ongoing_v2(&body.encode_to_vec(), &source).is_err());
    }

    #[test]
    fn full_source_rejects_changed_acquisition_and_lifetime_coordinates() {
        let source = ongoing_source_data();
        for offset in [8 + 40, 8 + 344, 520 + 200] {
            let mut bytes = *source.canonical_bytes_v2();
            bytes[offset] ^= 1;
            assert!(StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&bytes).is_err());
        }
        let mut bytes = *source.canonical_bytes_v2();
        bytes[8 + 440..8 + 448].copy_from_slice(&101_u64.to_be_bytes());
        assert!(StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&bytes).is_err());
        bytes = *source.canonical_bytes_v2();
        bytes[8 + 464..8 + 472].copy_from_slice(&119_u64.to_be_bytes());
        assert!(StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&bytes).is_err());
        bytes = *source.canonical_bytes_v2();
        bytes[8 + 488..8 + 496].copy_from_slice(&20_u64.to_be_bytes());
        assert!(StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&bytes).is_err());
    }

}
