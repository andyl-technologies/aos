//! Canonical nonauthorizing Controller execution specification attempt DATA.
//!
//! The same byte engine serves Controller historical custody and Host's sealed
//! content comparison. Decoding identifies historical fields only; it cannot
//! establish live owner holds, argument freshness, Storage backing or a grant.
//!
//! ```text
//! AOSCSI01 | execution[16] | Create[16] | accepted-request[32] |
//! source-heads[344] | Controller-sequence:u64be | spec-length:u32be |
//! spec-digest[32] | canonical-spec | domain-separated-SHA256[32]
//! ```

use aos_sandbox_model::{DecodeLimits, ExecutionId, ExecutionSpecV1, ObjectDigest,
    OperationId, decode_execution_spec_v1, encode_execution_spec_v1,
    execution_spec_digest_v1};
use sha2::{Digest as _, Sha256};
use crate::host_execution::MAXIMUM_HOST_EXECUTION_SPEC_BYTES;

/// Rejects malformed or inconsistent canonical historical attempt DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecutionSpecAttemptDataErrorV1 {
    /// A field, canonical encoding or exact content digest disagrees.
    #[error("execution specification attempt differs from its historical DATA")]
    Mismatch,
}

const MAGIC: &[u8; 8] = b"AOSCSI01";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.controller-execution-spec-attempt.v1\0";
const SPEC_DOMAIN: &[u8] = b"aos-sandbox-execution-spec-v1\0";
/// Defines the complete historical source-head width.
pub const HEAD_BYTES: usize = 10 * 32 + 3 * 8;
/// Defines the fixed AOSCSI01 prefix before canonical spec bytes.
pub const PREFIX_BYTES: usize = 8 + 16 + 16 + 32 + HEAD_BYTES + 8 + 4 + 32;
/// Defines the minimum nonempty canonical attempt width.
pub const MINIMUM_RECORD_BYTES: usize = PREFIX_BYTES + 1 + 32;
/// Includes the complete maximum-size canonical specification.
pub const MAXIMUM_RECORD_BYTES: usize = PREFIX_BYTES + MAXIMUM_HOST_EXECUTION_SPEC_BYTES + 32;


/// Hashes the accepted Create request as recorded by an AOSCSI01 attempt.
///
/// The Controller's accepted operation separately binds caller and project.
/// The AOSCER01 reserve source uses a different domain-separated digest.
#[must_use]
pub fn execution_spec_attempt_request_digest_v1(canonical_request: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(canonical_request).into())
}

/// Records the independent protected heads observed while deriving one spec.
///
/// These values identify a Controller source cut for later audit. They do not
/// prove a Host/Storage cross-owner hold or confer effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerExecutionSpecSourceHeadsV1 {
    /// Exact signed assignment commitment.
    pub assignment_digest: ObjectDigest,
    /// Epoch of the signed assignment.
    pub assignment_epoch: u64,
    /// Current parent resource binding commitment.
    pub parent_binding: ObjectDigest,
    /// Current parent projection revision.
    pub parent_projection: ObjectDigest,
    /// Exact v2 Sandbox specification record.
    pub sandbox_spec_record: ObjectDigest,
    /// Current Environment activation record.
    pub environment_activation: ObjectDigest,
    /// Canonical Environment manifest commitment.
    pub environment_manifest: ObjectDigest,
    /// Current Environment generation.
    pub environment_generation: u64,
    /// Exact accepted v2 output claim commitment.
    pub output_claim: ObjectDigest,
    /// Exact Host output settlement commitment.
    pub output_settlement: ObjectDigest,
    /// Exact authenticated fresh argument receipt.
    pub argument_receipt: ObjectDigest,
    /// Exact Host one-shot argument custody commitment.
    pub host_argument_custody: ObjectDigest,
    /// Native Host sequence after argument custody.
    pub host_argument_sequence: u64,
}

/// Borrows all canonical AOSCSI01 fields without native or issuance authority.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionSpecAttemptFieldsV1<'bytes> {
    /// Exact execution identity.
    pub execution: ExecutionId,
    /// Original accepted Create operation.
    pub create_operation: OperationId,
    /// Exact accepted public request commitment.
    pub accepted_request_digest: ObjectDigest,
    /// Complete historical source coordinates.
    pub source_heads: ControllerExecutionSpecSourceHeadsV1,
    /// Controller sequence before the record append.
    pub controller_sequence: u64,
    /// Domain-separated canonical specification digest.
    pub specification_digest: ObjectDigest,
    /// Complete bounded canonical specification.
    pub specification_bytes: &'bytes [u8],
    /// Commitment of the complete AOSCSI01 prefix.
    pub record_digest: ObjectDigest,
}

impl<'bytes> ExecutionSpecAttemptFieldsV1<'bytes> {
    /// Decodes the exact canonical specification and its historical joins.
    ///
    /// # Errors
    /// Rejects malformed canonical bytes or changed execution/source fields.
    pub fn decoded_specification(
        &self,
    ) -> Result<ExecutionSpecV1, ExecutionSpecAttemptDataErrorV1> {
        let limits = DecodeLimits {
            maximum_bytes: MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
            ..DecodeLimits::default()
        };
        let specification = decode_execution_spec_v1(self.specification_bytes, limits)
            .map_err(|_| ExecutionSpecAttemptDataErrorV1::Mismatch)?;
        if specification.execution() != self.execution
            || specification.audit().as_bytes() != self.create_operation.as_bytes()
            || specification.target().assignment_digest() != self.source_heads.assignment_digest
            || specification.target().assignment_epoch().get() != self.source_heads.assignment_epoch
            || specification.environment_generation().get()
                != self.source_heads.environment_generation
            || encode_execution_spec_v1(&specification) != self.specification_bytes
            || execution_spec_digest_v1(&specification) != self.specification_digest
        {
            return Err(ExecutionSpecAttemptDataErrorV1::Mismatch);
        }
        Ok(specification)
    }

    /// Encodes the supplied historical prefix without its final commitment.
    ///
    /// This does not validate the fields or authorize any native operation.
    pub fn encode_without_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PREFIX_BYTES + self.specification_bytes.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.create_operation.as_bytes());
        bytes.extend_from_slice(self.accepted_request_digest.as_bytes());
        self.source_heads.encode_into(&mut bytes);
        bytes.extend_from_slice(&self.controller_sequence.to_be_bytes());
        bytes.extend_from_slice(&(self.specification_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.specification_digest.as_bytes());
        bytes.extend_from_slice(self.specification_bytes);
        bytes
    }

    /// Encodes the supplied fields and their supplied historical commitment.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.encode_without_digest();
        bytes.extend_from_slice(self.record_digest.as_bytes());
        bytes
    }

    /// Borrows canonical historical fields after the complete existing checks.
    ///
    /// # Errors
    /// Rejects malformed framing, sentinel fields, changed digest or spec joins.
    pub fn decode(bytes: &'bytes [u8]) -> Result<Self, ExecutionSpecAttemptDataErrorV1> {
        let record = Self::decode_framing_v4(bytes)?;
        record.decoded_specification()?;
        Ok(record)
    }

    fn decode_framing_v4(bytes: &'bytes [u8]) -> Result<Self, ExecutionSpecAttemptDataErrorV1> {
        if bytes.len() < MINIMUM_RECORD_BYTES
            || bytes.len() > MAXIMUM_RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(ExecutionSpecAttemptDataErrorV1::Mismatch);
        }
        let mut cursor = 8;
        let execution = ExecutionId::from_bytes(read_array::<16>(bytes, &mut cursor)?);
        let create_operation = OperationId::from_bytes(read_array::<16>(bytes, &mut cursor)?);
        let accepted_request_digest = ObjectDigest::from_bytes(read_array(bytes, &mut cursor)?);
        let source_heads = ControllerExecutionSpecSourceHeadsV1::decode_from(bytes, &mut cursor)?;
        let controller_sequence = u64::from_be_bytes(read_array(bytes, &mut cursor)?);
        let specification_length =
            u32::from_be_bytes(read_array::<4>(bytes, &mut cursor)?) as usize;
        let specification_digest = ObjectDigest::from_bytes(read_array(bytes, &mut cursor)?);
        if !valid_spec_size(specification_length)
            || bytes.len() != PREFIX_BYTES + specification_length + 32
        {
            return Err(ExecutionSpecAttemptDataErrorV1::Mismatch);
        }
        let specification_bytes = &bytes[cursor..cursor + specification_length];
        cursor += specification_length;
        let record_digest = ObjectDigest::from_bytes(read_array(bytes, &mut cursor)?);
        let record = Self {
            execution,
            create_operation,
            accepted_request_digest,
            source_heads,
            controller_sequence,
            specification_digest,
            specification_bytes,
            record_digest,
        };
        if cursor != bytes.len()
            || record.execution.as_bytes() == &[0; 16]
            || record.create_operation.as_bytes() == &[0; 16]
            || record.accepted_request_digest.as_bytes() == &[0; 32]
            || record.controller_sequence == 0
            || digest_spec(&record.specification_bytes) != record.specification_digest
            || digest_record(&bytes[..bytes.len() - 32]) != record.record_digest
        {
            return Err(ExecutionSpecAttemptDataErrorV1::Mismatch);
        }
        Ok(record)
    }
}

/// Selects historical identity DATA without allocating a specification model.
///
/// The sole framing and full-record hash checks run here. Callers must still
/// pay and run the complete semantic decoder under their genuine native owner;
/// these borrowed identifiers grant no read interval or execution authority.
///
/// # Errors
/// Rejects malformed framing, invalid identities or changed content digests.
pub fn execution_spec_attempt_identity_data_v4(
    bytes: &[u8],
) -> Result<(ExecutionId, OperationId), ExecutionSpecAttemptDataErrorV1> {
    let record = ExecutionSpecAttemptFieldsV1::decode_framing_v4(bytes)?;
    Ok((record.execution, record.create_operation))
}

impl ControllerExecutionSpecSourceHeadsV1 {
    /// Encodes the independently named source heads in AOSCSI01 field order.
    ///
    /// These bytes are historical identifiers, not a cross-owner barrier.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEAD_BYTES);
        self.encode_into(&mut bytes);
        bytes
    }

    /// Appends historical source coordinates in canonical field order.
    pub fn encode_into(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.assignment_digest.as_bytes());
        bytes.extend_from_slice(&self.assignment_epoch.to_be_bytes());
        bytes.extend_from_slice(self.parent_binding.as_bytes());
        bytes.extend_from_slice(self.parent_projection.as_bytes());
        bytes.extend_from_slice(self.sandbox_spec_record.as_bytes());
        bytes.extend_from_slice(self.environment_activation.as_bytes());
        bytes.extend_from_slice(self.environment_manifest.as_bytes());
        bytes.extend_from_slice(&self.environment_generation.to_be_bytes());
        bytes.extend_from_slice(self.output_claim.as_bytes());
        bytes.extend_from_slice(self.output_settlement.as_bytes());
        bytes.extend_from_slice(self.argument_receipt.as_bytes());
        bytes.extend_from_slice(self.host_argument_custody.as_bytes());
        bytes.extend_from_slice(&self.host_argument_sequence.to_be_bytes());
    }

    /// Decodes exact historical source coordinates at the supplied cursor.
    ///
    /// # Errors
    /// Rejects a short input or a sentinel digest, generation or sequence.
    pub fn decode_from(
        bytes: &[u8],
        cursor: &mut usize,
    ) -> Result<Self, ExecutionSpecAttemptDataErrorV1> {
        let read_digest =
            |cursor: &mut usize| read_array(bytes, cursor).map(ObjectDigest::from_bytes);
        let assignment_digest = read_digest(cursor)?;
        let assignment_epoch = u64::from_be_bytes(read_array(bytes, cursor)?);
        let parent_binding = read_digest(cursor)?;
        let parent_projection = read_digest(cursor)?;
        let sandbox_spec_record = read_digest(cursor)?;
        let environment_activation = read_digest(cursor)?;
        let environment_manifest = read_digest(cursor)?;
        let environment_generation = u64::from_be_bytes(read_array(bytes, cursor)?);
        let output_claim = read_digest(cursor)?;
        let output_settlement = read_digest(cursor)?;
        let argument_receipt = read_digest(cursor)?;
        let host_argument_custody = read_digest(cursor)?;
        let host_argument_sequence = u64::from_be_bytes(read_array(bytes, cursor)?);
        let heads = Self {
            assignment_digest,
            assignment_epoch,
            parent_binding,
            parent_projection,
            sandbox_spec_record,
            environment_activation,
            environment_manifest,
            environment_generation,
            output_claim,
            output_settlement,
            argument_receipt,
            host_argument_custody,
            host_argument_sequence,
        };
        if heads.assignment_epoch == 0
            || heads.environment_generation == 0
            || heads.host_argument_sequence == 0
            || [
                assignment_digest,
                parent_binding,
                parent_projection,
                sandbox_spec_record,
                environment_activation,
                environment_manifest,
                output_claim,
                output_settlement,
                argument_receipt,
                host_argument_custody,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(ExecutionSpecAttemptDataErrorV1::Mismatch);
        }
        Ok(heads)
    }
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ExecutionSpecAttemptDataErrorV1> {
    let end = cursor
        .checked_add(N)
        .ok_or(ExecutionSpecAttemptDataErrorV1::Mismatch)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ExecutionSpecAttemptDataErrorV1::Mismatch)?
        .try_into()
        .map_err(|_| ExecutionSpecAttemptDataErrorV1::Mismatch)?;
    *cursor = end;
    Ok(value)
}

/// Reports whether a historical spec fits the existing descriptor bound.
pub fn valid_spec_size(size: usize) -> bool {
    size != 0 && size <= MAXIMUM_HOST_EXECUTION_SPEC_BYTES
}

/// Hashes exact canonical spec bytes under the existing spec domain.
pub fn digest_spec(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(SPEC_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

/// Hashes exact attempt-prefix bytes under the existing record domain.
pub fn digest_record(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}


/// Prices the existing four-model canonical execution validation peak.
///
/// The selected caller lends an already validated opaque canonical spec width.
/// Every CBOR item occupies at least one actual byte; the sole decoder's item
/// limit bounds the compiled String/Vec/spec carriers. Actual encoded byte
/// copies, descriptors and native IO have their own separate suppliers. This
/// returns only requirement DATA and grants no capacity, parser or authority.
#[must_use]
pub fn execution_spec_validation_model_memory_bytes_v2(canonical_specification_bytes: usize) -> Option<usize> {
    if canonical_specification_bytes == 0 { return None; }
    let items = canonical_specification_bytes.min(aos_sandbox_model::DecodeLimits::default().maximum_total_items);
    items.checked_mul(8 * std::mem::size_of::<String>()
        + 4 * std::mem::size_of::<Vec<u8>>()
        + std::mem::size_of::<aos_sandbox_model::ExecutionSpecV1>())?.checked_mul(4)
}
