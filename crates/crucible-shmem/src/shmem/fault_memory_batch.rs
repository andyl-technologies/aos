//! Atomic ordered memory-mutation batch payloads and evidence.
//!
//! One batch is the QEMU-visible transaction unit. Its actions are evaluated in
//! wire order against a private overlay, and QEMU publishes their final bytes
//! only after every action and the complete prepared-boundary digest validate.

use core::fmt::Write as _;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    HARD_FAULT_PAYLOAD_BYTES, HARD_MEMORY_MUTATION_BYTES, MemoryMutationEvidenceError,
    MemoryMutationEvidenceV1, MemoryMutationPayloadError, MemoryMutationPayloadV1,
    memory_mutation_precondition_sha256,
};

/// Eight-byte magic for a version-1 atomic memory batch payload.
pub const MEMORY_MUTATION_BATCH_MAGIC_V1: [u8; 8] = *b"CRUMBAT1";
/// Semantic version of the atomic memory batch payload.
pub const MEMORY_MUTATION_BATCH_VERSION_V1: u16 = 1;
/// Fixed batch header bytes before ordered records.
pub const MEMORY_MUTATION_BATCH_HEADER_V1_BYTES: usize = 80;
/// Fixed bytes before each nested memory action payload.
pub const MEMORY_MUTATION_BATCH_RECORD_V1_BYTES: usize = 40;
/// Batch semantic-version field offset.
pub const MEMORY_MUTATION_BATCH_VERSION_OFFSET: usize = 8;
/// Batch action-count field offset.
pub const MEMORY_MUTATION_BATCH_COUNT_OFFSET: usize = 12;
/// Batch expected-precondition field offset.
pub const MEMORY_MUTATION_BATCH_PRECONDITION_OFFSET: usize = 16;
/// Batch record-byte-length field offset.
pub const MEMORY_MUTATION_BATCH_RECORDS_LENGTH_OFFSET: usize = 48;
/// Batch reserved-byte field offset.
pub const MEMORY_MUTATION_BATCH_RESERVED_OFFSET: usize = 52;
/// Batch first-record offset.
pub const MEMORY_MUTATION_BATCH_BODY_OFFSET: usize = MEMORY_MUTATION_BATCH_HEADER_V1_BYTES;
/// Action identity offset within one batch record.
pub const MEMORY_MUTATION_BATCH_RECORD_ACTION_HASH_OFFSET: usize = 0;
/// Nested payload length offset within one batch record.
pub const MEMORY_MUTATION_BATCH_RECORD_LENGTH_OFFSET: usize = 32;
/// Reserved-byte offset within one batch record.
pub const MEMORY_MUTATION_BATCH_RECORD_RESERVED_OFFSET: usize = 36;
/// Nested payload offset within one batch record.
pub const MEMORY_MUTATION_BATCH_RECORD_BODY_OFFSET: usize = MEMORY_MUTATION_BATCH_RECORD_V1_BYTES;
/// Maximum actions in one atomic memory batch.
pub const MEMORY_MUTATION_BATCH_MAX_ACTIONS: u32 = 64;
/// Maximum sum of addressed bytes across one batch.
pub const MEMORY_MUTATION_BATCH_MAX_CHANGED_BYTES: u64 = HARD_MEMORY_MUTATION_BYTES as u64;
/// SHA-256 domain prefix for an ordered prepared batch authorization.
pub const MEMORY_MUTATION_BATCH_PRECONDITION_SHA256_DOMAIN_V1: &[u8] =
    b"crucible.memory-mutation-batch-precondition.v1\0";
/// SHA-256 domain prefix for ordered batch before-state aggregation.
pub const MEMORY_MUTATION_BATCH_BEFORE_SHA256_DOMAIN_V1: &[u8] =
    b"crucible.memory-mutation-batch-before.v1\0";
/// SHA-256 domain prefix for ordered batch after-state aggregation.
pub const MEMORY_MUTATION_BATCH_AFTER_SHA256_DOMAIN_V1: &[u8] =
    b"crucible.memory-mutation-batch-after.v1\0";
/// Eight-byte magic for version-1 atomic memory batch evidence.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_MAGIC_V1: [u8; 8] = *b"CRUMBAV1";
/// Semantic version of atomic memory batch evidence.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_V1: u16 = 1;
/// Fixed evidence header bytes before ordered evidence records.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES: usize = 80;
/// Fixed bytes before each nested memory evidence payload.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_V1_BYTES: usize = 40;
/// Evidence semantic-version field offset.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_OFFSET: usize = 8;
/// Evidence action-count field offset.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_COUNT_OFFSET: usize = 12;
/// Evidence prepared-precondition field offset.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET: usize = 16;
/// Evidence record-byte-length field offset.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_RECORDS_LENGTH_OFFSET: usize = 48;
/// Evidence reserved-byte field offset.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_RESERVED_OFFSET: usize = 52;
/// Evidence first-record offset.
pub const MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET: usize =
    MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES;

/// One content-addressed action inside an atomic memory batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryMutationBatchActionV1 {
    /// Runtime action identity used to correlate ordered evidence.
    pub action_hash: [u8; 32],
    /// Canonical preparation-form mutation payload.
    pub mutation: MemoryMutationPayloadV1,
}

/// One atomic, ordered set of memory mutations for a single QEMU node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryMutationBatchV1 {
    /// Ordered actions, evaluated from first to last.
    pub actions: Vec<MemoryMutationBatchActionV1>,
    /// Prepared-boundary authorization digest, or zero during preparation.
    pub expected_precondition_sha256: [u8; 32],
}

impl MemoryMutationBatchV1 {
    /// Encodes a canonical non-mutating preparation request.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationBatchError`] when the batch is empty, exceeds a
    /// deterministic action/byte/transport bound, repeats an action identity,
    /// carries a commit digest, or contains a noncanonical preparation action.
    pub fn encode_preparation(&self) -> Result<Vec<u8>, MemoryMutationBatchError> {
        if self.expected_precondition_sha256 != [0; 32] {
            return Err(MemoryMutationBatchError::Precondition);
        }
        self.encode_with_mode(true)
    }

    /// Encodes a canonical commit request authorized by prior preparation.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationBatchError`] for an absent authorization digest
    /// or any invalid action, identity, cumulative resource, or framing bound.
    pub fn encode(&self) -> Result<Vec<u8>, MemoryMutationBatchError> {
        if self.expected_precondition_sha256 == [0; 32] {
            return Err(MemoryMutationBatchError::Precondition);
        }
        self.encode_with_mode(false)
    }

    fn encode_with_mode(&self, preparation: bool) -> Result<Vec<u8>, MemoryMutationBatchError> {
        validate_action_set(&self.actions)?;
        let mut nested = Vec::with_capacity(self.actions.len());
        let mut encoded_len = MEMORY_MUTATION_BATCH_HEADER_V1_BYTES;
        for action in &self.actions {
            let payload = action.mutation.encode_preparation()?;
            encoded_len = encoded_len
                .checked_add(MEMORY_MUTATION_BATCH_RECORD_V1_BYTES)
                .and_then(|value| value.checked_add(payload.len()))
                .ok_or(MemoryMutationBatchError::Length)?;
            nested.push(payload);
        }
        if encoded_len > HARD_FAULT_PAYLOAD_BYTES as usize {
            return Err(MemoryMutationBatchError::Length);
        }
        let count =
            u32::try_from(self.actions.len()).map_err(|_source| MemoryMutationBatchError::Count)?;
        let records_len = u32::try_from(encoded_len - MEMORY_MUTATION_BATCH_HEADER_V1_BYTES)
            .map_err(|_source| MemoryMutationBatchError::Length)?;
        let mut bytes = vec![0; MEMORY_MUTATION_BATCH_HEADER_V1_BYTES];
        bytes[..8].copy_from_slice(&MEMORY_MUTATION_BATCH_MAGIC_V1);
        put_u16(&mut bytes, 8, MEMORY_MUTATION_BATCH_VERSION_V1);
        put_u32(&mut bytes, 12, count);
        if !preparation {
            bytes[16..48].copy_from_slice(&self.expected_precondition_sha256);
        }
        put_u32(&mut bytes, 48, records_len);
        for (action, payload) in self.actions.iter().zip(nested) {
            bytes.extend_from_slice(&action.action_hash);
            bytes.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_source| MemoryMutationBatchError::Length)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&[0; 4]);
            bytes.extend_from_slice(&payload);
        }
        Ok(bytes)
    }

    /// Decodes a canonical preparation or commit batch.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationBatchError`] for invalid framing, mode,
    /// identities, nested actions, cumulative bounds, or trailing bytes.
    pub fn decode(bytes: &[u8], preparation: bool) -> Result<Self, MemoryMutationBatchError> {
        if bytes.len() < MEMORY_MUTATION_BATCH_HEADER_V1_BYTES
            || bytes[..8] != MEMORY_MUTATION_BATCH_MAGIC_V1
            || read_u16(bytes, 8) != MEMORY_MUTATION_BATCH_VERSION_V1
            || read_u16(bytes, 10) != 0
            || bytes[52..80].iter().any(|byte| *byte != 0)
        {
            return Err(MemoryMutationBatchError::Framing);
        }
        let count = read_u32(bytes, 12) as usize;
        let expected_precondition_sha256 = read_array32(bytes, 16);
        if (preparation && expected_precondition_sha256 != [0; 32])
            || (!preparation && expected_precondition_sha256 == [0; 32])
        {
            return Err(MemoryMutationBatchError::Precondition);
        }
        let records_len = read_u32(bytes, 48) as usize;
        if count == 0
            || count > MEMORY_MUTATION_BATCH_MAX_ACTIONS as usize
            || MEMORY_MUTATION_BATCH_HEADER_V1_BYTES.checked_add(records_len) != Some(bytes.len())
            || bytes.len() > HARD_FAULT_PAYLOAD_BYTES as usize
        {
            return Err(MemoryMutationBatchError::Length);
        }
        let mut offset = MEMORY_MUTATION_BATCH_HEADER_V1_BYTES;
        let mut actions = Vec::with_capacity(count);
        for _ in 0..count {
            let header_end = offset
                .checked_add(MEMORY_MUTATION_BATCH_RECORD_V1_BYTES)
                .filter(|end| *end <= bytes.len())
                .ok_or(MemoryMutationBatchError::Length)?;
            let action_hash = read_array32(bytes, offset);
            let payload_len = read_u32(bytes, offset + 32) as usize;
            if bytes[offset + 36..header_end].iter().any(|byte| *byte != 0) {
                return Err(MemoryMutationBatchError::Framing);
            }
            let payload_end = header_end
                .checked_add(payload_len)
                .filter(|end| *end <= bytes.len())
                .ok_or(MemoryMutationBatchError::Length)?;
            let mutation =
                MemoryMutationPayloadV1::decode_preparation(&bytes[header_end..payload_end])?;
            actions.push(MemoryMutationBatchActionV1 {
                action_hash,
                mutation,
            });
            offset = payload_end;
        }
        if offset != bytes.len() {
            return Err(MemoryMutationBatchError::Length);
        }
        validate_action_set(&actions)?;
        Ok(Self {
            actions,
            expected_precondition_sha256,
        })
    }
}

/// One action and its independently decoded QEMU evidence inside a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryMutationBatchEvidenceActionV1 {
    /// Runtime action identity from the corresponding request record.
    pub action_hash: [u8; 32],
    /// Canonical evidence for this action's ordered before/after state.
    pub evidence: MemoryMutationEvidenceV1,
}

/// Canonical evidence for a completely prepared or applied atomic batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryMutationBatchEvidenceV1 {
    /// Ordered per-action evidence.
    pub actions: Vec<MemoryMutationBatchEvidenceActionV1>,
    /// Digest that authorizes commit of this exact prepared boundary.
    pub precondition_sha256: [u8; 32],
}

impl MemoryMutationBatchEvidenceV1 {
    /// Returns the ordered aggregate of all per-action before-state digests.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationBatchError`] for invalid action identities or
    /// deterministic action/byte-count bounds.
    pub fn before_sha256(&self) -> Result<[u8; 32], MemoryMutationBatchError> {
        self.state_sha256(false)
    }

    /// Returns the ordered aggregate of all per-action after-state digests.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationBatchError`] for invalid action identities or
    /// deterministic action/byte-count bounds.
    pub fn after_sha256(&self) -> Result<[u8; 32], MemoryMutationBatchError> {
        self.state_sha256(true)
    }

    fn state_sha256(&self, after: bool) -> Result<[u8; 32], MemoryMutationBatchError> {
        validate_evidence_set(&self.actions)?;
        let mut hasher = Sha256::new();
        hasher.update(if after {
            MEMORY_MUTATION_BATCH_AFTER_SHA256_DOMAIN_V1
        } else {
            MEMORY_MUTATION_BATCH_BEFORE_SHA256_DOMAIN_V1
        });
        hasher.update(
            u32::try_from(self.actions.len())
                .map_err(|_source| MemoryMutationBatchError::Count)?
                .to_le_bytes(),
        );
        for action in &self.actions {
            hasher.update(action.action_hash);
            hasher.update(if after {
                action.evidence.after_sha256
            } else {
                action.evidence.before_sha256
            });
        }
        Ok(hasher.finalize().into())
    }

    /// Computes the authorization digest from all ordered evidence records.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationBatchError`] for an empty, duplicate, or
    /// over-capacity action set or invalid translation evidence.
    pub fn expected_precondition_sha256(&self) -> Result<[u8; 32], MemoryMutationBatchError> {
        validate_evidence_set(&self.actions)?;
        let mut hasher = Sha256::new();
        hasher.update(MEMORY_MUTATION_BATCH_PRECONDITION_SHA256_DOMAIN_V1);
        hasher.update(
            u32::try_from(self.actions.len())
                .map_err(|_source| MemoryMutationBatchError::Count)?
                .to_le_bytes(),
        );
        for action in &self.actions {
            let translation = action.evidence.translation_sha256()?;
            let precondition = memory_mutation_precondition_sha256(
                action.evidence.before_sha256,
                action.evidence.after_sha256,
                translation,
                action.evidence.mapping_generation_sha256,
            );
            hasher.update(action.action_hash);
            hasher.update(precondition);
        }
        Ok(hasher.finalize().into())
    }

    /// Encodes ordered batch evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationBatchError`] for invalid action evidence,
    /// digest mismatch, duplicate identities, or transport overflow.
    pub fn encode(&self) -> Result<Vec<u8>, MemoryMutationBatchError> {
        let expected = self.expected_precondition_sha256()?;
        if self.precondition_sha256 != expected {
            return Err(MemoryMutationBatchError::Precondition);
        }
        let mut nested = Vec::with_capacity(self.actions.len());
        let mut encoded_len = MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES;
        for action in &self.actions {
            let evidence = action.evidence.encode()?;
            encoded_len = encoded_len
                .checked_add(MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_V1_BYTES)
                .and_then(|value| value.checked_add(evidence.len()))
                .ok_or(MemoryMutationBatchError::Length)?;
            nested.push(evidence);
        }
        if encoded_len > HARD_FAULT_PAYLOAD_BYTES as usize {
            return Err(MemoryMutationBatchError::Length);
        }
        let mut bytes = vec![0; MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES];
        bytes[..8].copy_from_slice(&MEMORY_MUTATION_BATCH_EVIDENCE_MAGIC_V1);
        put_u16(&mut bytes, 8, MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_V1);
        put_u32(
            &mut bytes,
            12,
            u32::try_from(self.actions.len()).map_err(|_source| MemoryMutationBatchError::Count)?,
        );
        bytes[16..48].copy_from_slice(&self.precondition_sha256);
        put_u32(
            &mut bytes,
            48,
            u32::try_from(encoded_len - MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES)
                .map_err(|_source| MemoryMutationBatchError::Length)?,
        );
        for (action, evidence) in self.actions.iter().zip(nested) {
            bytes.extend_from_slice(&action.action_hash);
            bytes.extend_from_slice(
                &u32::try_from(evidence.len())
                    .map_err(|_source| MemoryMutationBatchError::Length)?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&[0; 4]);
            bytes.extend_from_slice(&evidence);
        }
        Ok(bytes)
    }

    /// Decodes and verifies ordered batch evidence.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryMutationBatchError`] for malformed framing, invalid
    /// nested evidence, identity errors, digest mismatch, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, MemoryMutationBatchError> {
        if bytes.len() < MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES
            || bytes[..8] != MEMORY_MUTATION_BATCH_EVIDENCE_MAGIC_V1
            || read_u16(bytes, 8) != MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_V1
            || read_u16(bytes, 10) != 0
            || bytes[52..80].iter().any(|byte| *byte != 0)
        {
            return Err(MemoryMutationBatchError::Framing);
        }
        let count = read_u32(bytes, 12) as usize;
        let records_len = read_u32(bytes, 48) as usize;
        if count == 0
            || count > MEMORY_MUTATION_BATCH_MAX_ACTIONS as usize
            || MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES.checked_add(records_len)
                != Some(bytes.len())
            || bytes.len() > HARD_FAULT_PAYLOAD_BYTES as usize
        {
            return Err(MemoryMutationBatchError::Length);
        }
        let mut offset = MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES;
        let mut actions = Vec::with_capacity(count);
        for _ in 0..count {
            let header_end = offset
                .checked_add(MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_V1_BYTES)
                .filter(|end| *end <= bytes.len())
                .ok_or(MemoryMutationBatchError::Length)?;
            let action_hash = read_array32(bytes, offset);
            let evidence_len = read_u32(bytes, offset + 32) as usize;
            if bytes[offset + 36..header_end].iter().any(|byte| *byte != 0) {
                return Err(MemoryMutationBatchError::Framing);
            }
            let evidence_end = header_end
                .checked_add(evidence_len)
                .filter(|end| *end <= bytes.len())
                .ok_or(MemoryMutationBatchError::Length)?;
            let evidence = MemoryMutationEvidenceV1::decode(&bytes[header_end..evidence_end])?;
            actions.push(MemoryMutationBatchEvidenceActionV1 {
                action_hash,
                evidence,
            });
            offset = evidence_end;
        }
        if offset != bytes.len() {
            return Err(MemoryMutationBatchError::Length);
        }
        let value = Self {
            actions,
            precondition_sha256: read_array32(bytes, 16),
        };
        if value.precondition_sha256 == [0; 32]
            || value.expected_precondition_sha256()? != value.precondition_sha256
        {
            return Err(MemoryMutationBatchError::Precondition);
        }
        Ok(value)
    }
}

/// Failure to encode or decode an atomic memory-mutation batch.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MemoryMutationBatchError {
    /// Batch framing, reserved bytes, or magic are invalid.
    #[error("memory mutation batch framing is invalid")]
    Framing,
    /// The action count is empty or above the deterministic limit.
    #[error("memory mutation batch action count is invalid")]
    Count,
    /// A nested or cumulative byte length is invalid.
    #[error("memory mutation batch length is invalid")]
    Length,
    /// An action identity is zero or repeated.
    #[error("memory mutation batch action identity is invalid")]
    ActionIdentity,
    /// Preparation/commit authorization is absent, unexpected, or mismatched.
    #[error("memory mutation batch precondition is invalid")]
    Precondition,
    /// A nested mutation payload is invalid.
    #[error(transparent)]
    Payload(#[from] MemoryMutationPayloadError),
    /// A nested evidence payload is invalid.
    #[error(transparent)]
    Evidence(#[from] MemoryMutationEvidenceError),
}

fn validate_action_set(
    actions: &[MemoryMutationBatchActionV1],
) -> Result<(), MemoryMutationBatchError> {
    if actions.is_empty() || actions.len() > MEMORY_MUTATION_BATCH_MAX_ACTIONS as usize {
        return Err(MemoryMutationBatchError::Count);
    }
    let mut total = 0_u64;
    for (index, action) in actions.iter().enumerate() {
        if action.action_hash == [0; 32]
            || actions[..index]
                .iter()
                .any(|earlier| earlier.action_hash == action.action_hash)
        {
            return Err(MemoryMutationBatchError::ActionIdentity);
        }
        total = total
            .checked_add(
                u64::try_from(action.mutation.mask.len())
                    .map_err(|_source| MemoryMutationBatchError::Length)?,
            )
            .ok_or(MemoryMutationBatchError::Length)?;
    }
    if total > MEMORY_MUTATION_BATCH_MAX_CHANGED_BYTES {
        return Err(MemoryMutationBatchError::Length);
    }
    Ok(())
}

fn validate_evidence_set(
    actions: &[MemoryMutationBatchEvidenceActionV1],
) -> Result<(), MemoryMutationBatchError> {
    if actions.is_empty() || actions.len() > MEMORY_MUTATION_BATCH_MAX_ACTIONS as usize {
        return Err(MemoryMutationBatchError::Count);
    }
    let mut total = 0_u64;
    for (index, action) in actions.iter().enumerate() {
        if action.action_hash == [0; 32]
            || actions[..index]
                .iter()
                .any(|earlier| earlier.action_hash == action.action_hash)
        {
            return Err(MemoryMutationBatchError::ActionIdentity);
        }
        total = total
            .checked_add(u64::from(action.evidence.length))
            .ok_or(MemoryMutationBatchError::Length)?;
    }
    if total > MEMORY_MUTATION_BATCH_MAX_CHANGED_BYTES {
        return Err(MemoryMutationBatchError::Length);
    }
    Ok(())
}

pub(crate) fn emit_memory_batch_c_header(out: &mut String) {
    macro_rules! define {
        ($name:literal, $value:expr) => {
            let _ = writeln!(out, "#define {} {}", $name, $value);
        };
    }
    out.push_str("\n/* Atomic ordered QEMU memory-mutation batch ABI. */\n");
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_BATCH_MAGIC_V1 \"CRUMBAT1\"\n");
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_BATCH_PRECONDITION_SHA256_DOMAIN_V1 \"crucible.memory-mutation-batch-precondition.v1\\0\"\n");
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_PRECONDITION_SHA256_DOMAIN_V1_BYTES",
        MEMORY_MUTATION_BATCH_PRECONDITION_SHA256_DOMAIN_V1.len()
    );
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_BATCH_BEFORE_SHA256_DOMAIN_V1 \"crucible.memory-mutation-batch-before.v1\\0\"\n");
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_BEFORE_SHA256_DOMAIN_V1_BYTES",
        MEMORY_MUTATION_BATCH_BEFORE_SHA256_DOMAIN_V1.len()
    );
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_BATCH_AFTER_SHA256_DOMAIN_V1 \"crucible.memory-mutation-batch-after.v1\\0\"\n");
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_AFTER_SHA256_DOMAIN_V1_BYTES",
        MEMORY_MUTATION_BATCH_AFTER_SHA256_DOMAIN_V1.len()
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_VERSION_V1",
        MEMORY_MUTATION_BATCH_VERSION_V1
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_HEADER_V1_BYTES",
        MEMORY_MUTATION_BATCH_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_RECORD_V1_BYTES",
        MEMORY_MUTATION_BATCH_RECORD_V1_BYTES
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_MAX_ACTIONS",
        MEMORY_MUTATION_BATCH_MAX_ACTIONS
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_MAX_CHANGED_BYTES",
        MEMORY_MUTATION_BATCH_MAX_CHANGED_BYTES
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_VERSION_OFFSET",
        MEMORY_MUTATION_BATCH_VERSION_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_COUNT_OFFSET",
        MEMORY_MUTATION_BATCH_COUNT_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_PRECONDITION_OFFSET",
        MEMORY_MUTATION_BATCH_PRECONDITION_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_RECORDS_LENGTH_OFFSET",
        MEMORY_MUTATION_BATCH_RECORDS_LENGTH_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_RESERVED_OFFSET",
        MEMORY_MUTATION_BATCH_RESERVED_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_BODY_OFFSET",
        MEMORY_MUTATION_BATCH_BODY_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_RECORD_ACTION_HASH_OFFSET",
        MEMORY_MUTATION_BATCH_RECORD_ACTION_HASH_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_RECORD_LENGTH_OFFSET",
        MEMORY_MUTATION_BATCH_RECORD_LENGTH_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_RECORD_RESERVED_OFFSET",
        MEMORY_MUTATION_BATCH_RECORD_RESERVED_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_RECORD_BODY_OFFSET",
        MEMORY_MUTATION_BATCH_RECORD_BODY_OFFSET
    );
    out.push_str("#define CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_MAGIC_V1 \"CRUMBAV1\"\n");
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_V1",
        MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_V1
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES",
        MEMORY_MUTATION_BATCH_EVIDENCE_HEADER_V1_BYTES
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_V1_BYTES",
        MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_V1_BYTES
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_OFFSET",
        MEMORY_MUTATION_BATCH_EVIDENCE_VERSION_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_COUNT_OFFSET",
        MEMORY_MUTATION_BATCH_EVIDENCE_COUNT_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET",
        MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_RECORDS_LENGTH_OFFSET",
        MEMORY_MUTATION_BATCH_EVIDENCE_RECORDS_LENGTH_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_RESERVED_OFFSET",
        MEMORY_MUTATION_BATCH_EVIDENCE_RESERVED_OFFSET
    );
    define!(
        "CRUCIBLE_MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET",
        MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET
    );
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_array32(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&bytes[offset..offset + 32]);
    value
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MEMORY_MUTATION_NO_VCPU, MemoryMutationAddressSpace, MemoryMutationAtomicity,
        MemoryMutationTransformKind,
    };

    fn action(id: u8, address: u64) -> MemoryMutationBatchActionV1 {
        MemoryMutationBatchActionV1 {
            action_hash: [id; 32],
            mutation: MemoryMutationPayloadV1 {
                address_space: MemoryMutationAddressSpace::GuestPhysical,
                transform: MemoryMutationTransformKind::BitFlip,
                atomicity: MemoryMutationAtomicity::AllOrNothing,
                vcpu_index: MEMORY_MUTATION_NO_VCPU,
                address,
                mask: vec![0xff],
                values: Vec::new(),
                expected_translation_sha256: [0; 32],
            },
        }
    }

    #[test]
    fn preparation_and_commit_batches_are_canonical_and_ordered() {
        let mut batch = MemoryMutationBatchV1 {
            actions: vec![action(1, 0x1000), action(2, 0x1000)],
            expected_precondition_sha256: [0; 32],
        };
        let preparation = batch
            .encode_preparation()
            .unwrap_or_else(|error| panic!("encode batch preparation: {error}"));
        assert_eq!(
            MemoryMutationBatchV1::decode(&preparation, true),
            Ok(batch.clone())
        );
        assert_eq!(
            MemoryMutationBatchV1::decode(&preparation, false),
            Err(MemoryMutationBatchError::Precondition)
        );

        batch.expected_precondition_sha256 = [9; 32];
        let commit = batch
            .encode()
            .unwrap_or_else(|error| panic!("encode batch commit: {error}"));
        assert_eq!(MemoryMutationBatchV1::decode(&commit, false), Ok(batch));
    }

    #[test]
    fn batch_rejects_duplicate_identity_and_cumulative_overflow() {
        let duplicate = MemoryMutationBatchV1 {
            actions: vec![action(1, 0), action(1, 1)],
            expected_precondition_sha256: [0; 32],
        };
        assert_eq!(
            duplicate.encode_preparation(),
            Err(MemoryMutationBatchError::ActionIdentity)
        );
    }

    #[test]
    fn transport_envelopes_include_worst_case_batch_overhead() {
        let per_action_overhead = MEMORY_MUTATION_BATCH_RECORD_V1_BYTES
            + crate::MEMORY_MUTATION_PAYLOAD_HEADER_V1_BYTES;
        let hard = MEMORY_MUTATION_BATCH_HEADER_V1_BYTES
            + MEMORY_MUTATION_BATCH_MAX_ACTIONS as usize * per_action_overhead
            + 2 * HARD_MEMORY_MUTATION_BYTES as usize;
        let default = MEMORY_MUTATION_BATCH_HEADER_V1_BYTES
            + MEMORY_MUTATION_BATCH_MAX_ACTIONS as usize * per_action_overhead
            + 2 * crate::DEFAULT_MEMORY_MUTATION_BYTES as usize;

        assert_eq!(hard, HARD_FAULT_PAYLOAD_BYTES as usize);
        assert_eq!(default, crate::DEFAULT_FAULT_PAYLOAD_BYTES as usize);
    }
}
