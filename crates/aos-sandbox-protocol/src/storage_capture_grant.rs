//! Nonauthorizing wire and signed-plan meaning for retained capture admission.
//!
//! A Controller-signed Storage-audience plan must eventually commit the exact
//! source; this parser only fixes its bytes. Storage must independently cold-
//! read AOSCIS01/AOSCIA01, authenticated Host AOSEOR02/AOSHOP01, AOSEOR03, and
//! its own dataset policy before issuing a durable attempt. Neither method is
//! registered for broker dispatch by this module.
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

use aos_proto::aos::sandbox::local::v1::{
    QueryStorageExecutionCaptureRequestV1, ReserveStorageExecutionCaptureRequestV1,
    StorageExecutionCaptureAttemptStatusV1, StorageExecutionCaptureAttemptV1,
};
use aos_sandbox_core::{
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

/// Exact versioned Storage capture source length.
pub const STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1: usize = 512;
/// Exact AOSCIS01 settlement preimage length committed by this source.
pub const CONTROLLER_OUTPUT_SETTLEMENT_BYTES_V1: usize = 208;

const SOURCE_MAGIC: &[u8; 8] = b"AOSSCG01";
const SETTLEMENT_MAGIC: &[u8; 8] = b"AOSCIS01";
const SETTLEMENT_DOMAIN: &[u8] = b"aos.sandbox.controller-output-settlement.v1\0";
const SOURCE_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-grant-source.v1\0";
const ARGUMENT_DOMAIN: &[u8] = b"aos.sandbox.storage.capture-grant-argument.v1\0";
const MAXIMUM_REQUEST_BODY_BYTES: usize = 4 * 1_024;
const MAXIMUM_RESPONSE_BODY_BYTES: usize = 1_024;
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

/// Fixes all bytes a future signed Storage-audience reserve plan must commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCaptureGrantSourceV1 {
    bytes: [u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1],
    settlement: ControllerOutputSettlementPreimageV1,
    assignment: BrokerAssignment,
}

impl StorageCaptureGrantSourceV1 {
    /// Parses one exact source without claiming it was signed or issued.
    ///
    /// # Errors
    ///
    /// Rejects malformed settlement, assignment, split, policy, boot,
    /// operation, deadline, or request identity fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
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

    /// Returns the original Storage reserve request identifier.
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

    /// Returns a domain-separated digest of every original source byte.
    #[must_use]
    pub fn source_digest(&self) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(SOURCE_DOMAIN);
        digest.update(self.bytes);
        ObjectDigest::from_bytes(digest.finalize().into())
    }

    /// Returns the future plan's method-separated full-source commitment.
    ///
    /// # Errors
    ///
    /// Rejects a missing, changed original reserve ID or reused query ID.
    pub fn argument_commitment(
        &self,
        method: StorageCaptureGrantMethodV1,
        request_id: [u8; 16],
    ) -> Result<BrokerArgumentCommitment, ProtocolValidationError> {
        if request_id == [0; 16]
            || (method == StorageCaptureGrantMethodV1::Reserve
                && request_id != self.original_reserve_request_id())
            || (method == StorageCaptureGrantMethodV1::Query
                && request_id == self.original_reserve_request_id())
        {
            return Err(invalid("Storage capture plan request ID"));
        }
        let mut bytes = Vec::with_capacity(ARGUMENT_DOMAIN.len() + 1 + 16 + self.bytes.len());
        bytes.extend_from_slice(ARGUMENT_DOMAIN);
        bytes.push(match method {
            StorageCaptureGrantMethodV1::Reserve => 1,
            StorageCaptureGrantMethodV1::Query => 2,
        });
        bytes.extend_from_slice(&request_id);
        bytes.extend_from_slice(&self.bytes);
        Ok(BrokerArgumentCommitment::for_canonical_bytes(&bytes))
    }

    /// Builds the exact nonauthorizing Storage grant semantics for one request.
    ///
    /// The Controller must still prove current protected and physical sources
    /// before signing a plan, and Storage must verify that plan separately.
    ///
    /// # Errors
    ///
    /// Rejects a missing or mismatched method-specific request identifier.
    pub fn broker_grant(
        &self,
        method: StorageCaptureGrantMethodV1,
        request_id: [u8; 16],
    ) -> Result<BrokerGrant, ProtocolValidationError> {
        let commitment = self.argument_commitment(method, request_id)?;
        BrokerGrant::new(
            method.broker_verb(),
            BrokerGrantTarget::Assignment,
            commitment,
            MAXIMUM_REQUEST_BODY_BYTES as u32,
            0,
        )
        .map_err(|_| invalid("Storage capture plan grant"))
    }

    /// Returns the exact response locator for the original source.
    #[must_use]
    pub fn locator(&self) -> StorageCaptureAttemptLocatorV1 {
        StorageCaptureAttemptLocatorV1 {
            execution: self.settlement.execution(),
            create_operation: self.settlement.create_operation(),
            original_reserve_request_id: self.original_reserve_request_id(),
            source_digest: self.source_digest(),
            output_record_digest: self.output_record_digest(),
        }
    }
}

/// Names the one original reserve source and AOSEOR03 record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCaptureAttemptLocatorV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    original_reserve_request_id: [u8; 16],
    source_digest: ObjectDigest,
    output_record_digest: ObjectDigest,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageCaptureReserveRequestV1 {
    header: ValidatedHeader,
    source: StorageCaptureGrantSourceV1,
}

impl ValidatedStorageCaptureReserveRequestV1 {
    /// Returns the validated broker request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the complete source whose signed plan must be verified.
    #[must_use]
    pub const fn source(&self) -> &StorageCaptureGrantSourceV1 {
        &self.source
    }
}

/// Retains a strictly parsed cold query, never a fresh reserve permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedStorageCaptureQueryRequestV1 {
    header: ValidatedHeader,
    source: StorageCaptureGrantSourceV1,
}

impl ValidatedStorageCaptureQueryRequestV1 {
    /// Returns the validated fresh query header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact original reserve source.
    #[must_use]
    pub const fn source(&self) -> &StorageCaptureGrantSourceV1 {
        &self.source
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
    let (header, source) = decode_request(
        body,
        peer,
        policy,
        now_boottime_nanoseconds,
        StorageCaptureGrantMethodV1::Reserve,
    )?;
    if source.original_reserve_request_id() != *header.request_id()
        || source.original_deadline_boottime_nanoseconds() != header.deadline_boottime_nanoseconds()
    {
        return Err(invalid("Storage capture original request"));
    }
    Ok(ValidatedStorageCaptureReserveRequestV1 { header, source })
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
    let (header, source) = decode_request(
        body,
        peer,
        policy,
        now_boottime_nanoseconds,
        StorageCaptureGrantMethodV1::Query,
    )?;
    if source.original_reserve_request_id() == *header.request_id() {
        return Err(invalid("Storage capture query request"));
    }
    Ok(ValidatedStorageCaptureQueryRequestV1 { header, source })
}

fn decode_request(
    body: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now: u64,
    method: StorageCaptureGrantMethodV1,
) -> Result<(ValidatedHeader, StorageCaptureGrantSourceV1), ProtocolValidationError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let (header, source) = match method {
        StorageCaptureGrantMethodV1::Reserve => {
            let request = ReserveStorageExecutionCaptureRequestV1::decode_from_slice(body)
                .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
            if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
                return Err(ProtocolValidationError::UnknownFields);
            }
            (request.header, request.canonical_grant_source)
        }
        StorageCaptureGrantMethodV1::Query => {
            let request = QueryStorageExecutionCaptureRequestV1::decode_from_slice(body)
                .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
            if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
                return Err(ProtocolValidationError::UnknownFields);
            }
            (request.header, request.canonical_grant_source)
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
    let source = StorageCaptureGrantSourceV1::from_canonical_bytes(&source)?;
    Ok((header, source))
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

    /// Returns the protected Storage attempt record digest when committed.
    #[must_use]
    pub const fn durable_attempt_digest(self) -> Option<ObjectDigest> {
        self.durable_attempt_digest
    }
}

/// Decodes a structurally exact response after signed-session authentication.
///
/// # Errors
///
/// Rejects malformed, unknown, foreign-locator, or partially present status
/// fields. A committed fence never implies a physical output result.
pub fn decode_storage_capture_attempt_response_v1(
    body: &[u8],
    locator: StorageCaptureAttemptLocatorV1,
    allow_absent: bool,
) -> Result<ValidatedStorageCaptureAttemptV1, ProtocolValidationError> {
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
    let (status, attempt, durable_attempt_digest) = match response.status.as_known() {
        Some(StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_ABSENT)
            if allow_absent && response.attempt_id.is_empty() && response.durable_attempt_digest.is_empty() =>
        {
            (StorageCaptureAttemptStatusV1::Absent, None, None)
        }
        Some(StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_EFFECT_POSSIBLE) => {
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
    Ok(ValidatedStorageCaptureAttemptV1 {
        status,
        locator,
        attempt,
        durable_attempt_digest,
    })
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
mod tests {
    use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod, RequestHeader};
    use buffa::Enumeration as _;

    use super::*;

    fn source_bytes() -> [u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1] {
        let mut source = [0; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V1];
        source[..8].copy_from_slice(SOURCE_MAGIC);
        let settlement = &mut source[8..216];
        settlement[..8].copy_from_slice(SETTLEMENT_MAGIC);
        settlement[8..24].fill(1);
        settlement[24..40].fill(2);
        settlement[40..72].fill(3);
        settlement[72..104].fill(4);
        settlement[104..112].copy_from_slice(&5_u64.to_be_bytes());
        settlement[112..144].fill(6);
        settlement[144..176].fill(7);
        let mut checksum = Sha256::new();
        checksum.update(SETTLEMENT_DOMAIN);
        checksum.update(&settlement[..176]);
        settlement[176..208].copy_from_slice(&checksum.finalize());

        source[216..248].fill(8);
        source[248..280].fill(9);
        source[280..296].fill(10);
        source[296..312].fill(11);
        source[312..328].fill(12);
        source[328..336].copy_from_slice(&1_u64.to_be_bytes());
        source[336..344].copy_from_slice(&2_u64.to_be_bytes());
        source[344..376].fill(13);
        source[376..392].fill(14);
        source[392..408].fill(15);
        source[408..440].fill(16);
        source[440..448].copy_from_slice(&100_u64.to_be_bytes());
        source[448..456].copy_from_slice(&60_u64.to_be_bytes());
        source[456..464].copy_from_slice(&40_u64.to_be_bytes());
        source[464..472].copy_from_slice(&200_u64.to_be_bytes());
        source[472..480].copy_from_slice(&20_u64.to_be_bytes());
        source[480..488].copy_from_slice(&30_u64.to_be_bytes());
        source[488..496].copy_from_slice(&100_u64.to_be_bytes());
        source[496..512].fill(17);
        source
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
            ..Default::default()
        }
    }

    #[test]
    fn source_commits_complete_settlement_split_policy_and_method() {
        let bytes = source_bytes();
        let source = StorageCaptureGrantSourceV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            StorageCaptureGrantMethodV1::Reserve.broker_verb(),
            BrokerVerb::StorageReserveExecutionCapture
        );
        assert_eq!(
            StorageCaptureGrantMethodV1::Query.broker_verb(),
            BrokerVerb::StorageQueryExecutionCapture
        );
        assert_eq!(
            source.settlement().execution(),
            ExecutionId::from_bytes([1; 16])
        );
        assert_eq!(source.settlement().original_host_journal_sequence(), 5);
        assert_eq!(source.output_limits(), (100, 60, 40));
        assert_eq!(source.space_policy(), (200, 20, 30));
        assert_eq!(source.original_host_request_id(), [10; 16]);
        let reserve_grant = source
            .broker_grant(StorageCaptureGrantMethodV1::Reserve, [17; 16])
            .unwrap();
        let query_grant = source
            .broker_grant(StorageCaptureGrantMethodV1::Query, [18; 16])
            .unwrap();
        assert_eq!(
            reserve_grant.verb(),
            BrokerVerb::StorageReserveExecutionCapture
        );
        assert_eq!(query_grant.verb(), BrokerVerb::StorageQueryExecutionCapture);
        assert_eq!(reserve_grant.target(), BrokerGrantTarget::Assignment);
        assert_eq!(reserve_grant.maximum_request_bytes(), 4 * 1_024);
        assert_eq!(reserve_grant.maximum_descriptors(), 0);
        assert_ne!(
            reserve_grant.argument_commitment(),
            query_grant.argument_commitment()
        );
        assert_eq!(
            source.settlement().record_digest().as_bytes(),
            &bytes[184..216]
        );
        assert_ne!(
            source
                .argument_commitment(StorageCaptureGrantMethodV1::Reserve, [17; 16])
                .unwrap(),
            source
                .argument_commitment(StorageCaptureGrantMethodV1::Query, [18; 16])
                .unwrap()
        );
        assert!(
            source
                .argument_commitment(StorageCaptureGrantMethodV1::Query, [17; 16])
                .is_err()
        );

        let mut tampered = bytes;
        tampered[8 + 72] ^= 1;
        assert!(StorageCaptureGrantSourceV1::from_canonical_bytes(&tampered).is_err());
        let mut split = bytes;
        split[455] ^= 1;
        assert!(StorageCaptureGrantSourceV1::from_canonical_bytes(&split).is_err());
        let mut floor = bytes;
        floor[480..488].fill(0);
        assert!(StorageCaptureGrantSourceV1::from_canonical_bytes(&floor).is_err());
        let mut zero_capture = bytes;
        zero_capture[440..464].fill(0);
        assert_eq!(
            StorageCaptureGrantSourceV1::from_canonical_bytes(&zero_capture)
                .unwrap()
                .output_limits(),
            (0, 0, 0)
        );
        assert!(StorageCaptureGrantSourceV1::from_canonical_bytes(&bytes[..511]).is_err());
    }

    #[test]
    fn caller_supplied_settlement_cannot_open_storage_capture_dispatch() {
        let (peer, policy) = peer();
        let request = ReserveStorageExecutionCaptureRequestV1 {
            header: Some(header(17, 100)).into(),
            canonical_grant_source: source_bytes().to_vec(),
            ..Default::default()
        };

        // AOSCIS01 has a reproducible checksum, not a Controller signature.
        let parsed =
            decode_storage_capture_reserve_request_v1(&request.encode_to_vec(), peer, policy, 99)
                .unwrap();
        assert_eq!(
            parsed.source().settlement().canonical_bytes()[..8],
            *SETTLEMENT_MAGIC
        );

        // No Storage capture method/profile or production handler is registered
        // for this wire. A caller's well-formed source is not an effect permit.
        for method_number in 0..=u16::MAX {
            let Some(method) = BrokerMethod::from_i32(i32::from(method_number)) else {
                continue;
            };
            let name = method.proto_name();
            assert!(
                !(name.starts_with("BROKER_METHOD_STORAGE_")
                    && (name.contains("CAPTURE") || name.contains("EXECUTION_OUTPUT"))),
                "unexpected Storage capture method: {name}"
            );
        }
    }

    #[test]
    fn reserve_and_fresh_query_reject_noncanonical_or_reused_headers() {
        let (peer, policy) = peer();
        let reserve = ReserveStorageExecutionCaptureRequestV1 {
            header: Some(header(17, 100)).into(),
            canonical_grant_source: source_bytes().to_vec(),
            ..Default::default()
        };
        let validated =
            decode_storage_capture_reserve_request_v1(&reserve.encode_to_vec(), peer, policy, 99)
                .unwrap();
        assert_eq!(validated.source().original_reserve_request_id(), [17; 16]);

        let mut changed = reserve.clone();
        changed.header.get_or_insert_default().request_id = vec![21; 16];
        assert!(
            decode_storage_capture_reserve_request_v1(&changed.encode_to_vec(), peer, policy, 99)
                .is_err()
        );
        changed = reserve.clone();
        changed
            .header
            .get_or_insert_default()
            .deadline_boottime_nanoseconds = 101;
        assert!(
            decode_storage_capture_reserve_request_v1(&changed.encode_to_vec(), peer, policy, 99)
                .is_err()
        );
        let mut unknown = reserve.encode_to_vec();
        unknown.extend_from_slice(&[0xa0, 0x06, 0x01]);
        assert!(decode_storage_capture_reserve_request_v1(&unknown, peer, policy, 99).is_err());

        let query = QueryStorageExecutionCaptureRequestV1 {
            header: Some(header(22, 201)).into(),
            canonical_grant_source: source_bytes().to_vec(),
            ..Default::default()
        };
        let validated =
            decode_storage_capture_query_request_v1(&query.encode_to_vec(), peer, policy, 200)
                .unwrap();
        assert_eq!(
            validated.source().original_deadline_boottime_nanoseconds(),
            100
        );
        let mut replayed = query;
        replayed.header.get_or_insert_default().request_id = vec![17; 16];
        assert!(
            decode_storage_capture_query_request_v1(&replayed.encode_to_vec(), peer, policy, 200)
                .is_err()
        );
    }

    #[test]
    fn attempt_response_is_exact_and_never_physical_success() {
        let source = StorageCaptureGrantSourceV1::from_canonical_bytes(&source_bytes()).unwrap();
        let locator = source.locator();
        let mut committed = response(locator);
        let validated =
            decode_storage_capture_attempt_response_v1(&committed.encode_to_vec(), locator, false)
                .unwrap();
        assert_eq!(
            validated.status(),
            StorageCaptureAttemptStatusV1::EffectPossible
        );
        assert_eq!(validated.attempt(), Some([18; 16]));

        committed.attempt_id.clear();
        assert!(
            decode_storage_capture_attempt_response_v1(&committed.encode_to_vec(), locator, false)
                .is_err()
        );
        committed = response(locator);
        committed.grant_source_digest[0] ^= 1;
        assert!(
            decode_storage_capture_attempt_response_v1(&committed.encode_to_vec(), locator, false)
                .is_err()
        );
        let mut absent = response(locator);
        absent.status =
            StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_ABSENT
                .into();
        absent.attempt_id.clear();
        absent.durable_attempt_digest.clear();
        assert_eq!(
            decode_storage_capture_attempt_response_v1(&absent.encode_to_vec(), locator, true)
                .unwrap()
                .status(),
            StorageCaptureAttemptStatusV1::Absent
        );
        assert!(
            decode_storage_capture_attempt_response_v1(&absent.encode_to_vec(), locator, false)
                .is_err()
        );
    }
}
