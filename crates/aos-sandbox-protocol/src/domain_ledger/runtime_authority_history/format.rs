//! Canonical binary codecs for pending intents, immutable bindings, and heads.
//!
//! Every integer is network-byte-order and every optional identity uses its
//! all-zero fixed-width value as the absent encoding. The three families evolve
//! independently even though their first versions share these layouts:
//!
//! ```text
//! pending = magic:8 || version:u16 || state:u8
//!         || expected-present:u8 || expected-revision:u64 || revision:u64
//!         || operation:16 || request-digest:32 || predecessor-digest:32
//!         || holder:16 || source-draft-digest:32 || assignment-digest:32
//!         || manifest-length:u32 || canonical-manifest
//!
//! binding = magic:8 || version:u16 || state:u8 || revision:u64
//!         || operation:16 || request-digest:32 || predecessor-digest:32
//!         || holder:16 || source-draft-digest:32 || publication-digest:32
//!         || lease-generation:u64 || lease-digest:32 || assignment-digest:32
//!         || manifest-length:u32 || canonical-manifest
//!
//! head    = magic:8 || version:u16 || sandbox:16 || revision:u64
//!         || binding-digest:32
//! ```

use aos_sandbox_core::bounded_codec::BoundedReader;
use aos_sandbox_core::{
    CanonicalAssignmentManifestV1, DecodeLimits, ObjectDigest, OperationId, PrincipalId, SandboxId,
};
use sha2::{Digest as _, Sha256};

use super::{
    BINDING_DIGEST_DOMAIN, BINDING_MAGIC, BINDING_VERSION, HEAD_MAGIC, HEAD_VERSION,
    MAXIMUM_RECORD_BYTES, PENDING_MAGIC, PENDING_VERSION, RuntimeAuthorityBindingV1,
    RuntimeAuthorityDataErrorV1, RuntimeAuthorityHeadV1, RuntimeAuthorityPendingV1,
    RuntimeAuthorityStateV1,
};

const OPTIONAL_ABSENT: u8 = 0;
const OPTIONAL_PRESENT: u8 = 1;
const FIXED_PENDING_BYTES: usize = 192;
const FIXED_BINDING_BYTES: usize = 255;
const HEAD_BYTES: usize = 66;

/// Returns the exact pending-record width for an announced manifest.
///
/// # Errors
/// Rejects the same record ceiling or overflow as the pending encoder.
pub fn runtime_pending_encoded_bytes_v1(manifest_bytes: usize)
    -> Result<usize, RuntimeAuthorityDataErrorV1>
{
    checked_record_length(FIXED_PENDING_BYTES, manifest_bytes)
}

/// Returns the exact binding-record width for an announced manifest.
///
/// # Errors
/// Rejects the same record ceiling or overflow as the binding encoder.
pub fn runtime_binding_encoded_bytes_v1(manifest_bytes: usize)
    -> Result<usize, RuntimeAuthorityDataErrorV1>
{
    checked_record_length(FIXED_BINDING_BYTES, manifest_bytes)
}

/// Returns the unchanged fixed current-head record width.
#[must_use]
pub const fn runtime_head_encoded_bytes_v1() -> usize { HEAD_BYTES }

/// Encodes one pending-intent record in its established canonical layout.
///
/// # Errors
///
/// Rejects a length that exceeds the fixed record-byte ceiling or wire width.
pub fn encode_pending(
    pending: &RuntimeAuthorityPendingV1,
) -> Result<Vec<u8>, RuntimeAuthorityDataErrorV1> {
    let manifest = pending.manifest.canonical_bytes();
    let mut bytes = Vec::with_capacity(runtime_pending_encoded_bytes_v1(manifest.len())?);
    bytes.extend_from_slice(PENDING_MAGIC);
    bytes.extend_from_slice(&PENDING_VERSION.to_be_bytes());
    bytes.push(pending.state.code());
    encode_optional_revision(&mut bytes, pending.expected_revision);
    bytes.extend_from_slice(&pending.revision.to_be_bytes());
    bytes.extend_from_slice(pending.operation.as_bytes());
    bytes.extend_from_slice(&pending.request_digest);
    encode_optional_digest(&mut bytes, pending.predecessor_digest);
    encode_holder(&mut bytes, pending.holder);
    bytes.extend_from_slice(pending.source_draft_digest.as_bytes());
    bytes.extend_from_slice(pending.manifest.digest().as_bytes());
    encode_bytes(&mut bytes, manifest)?;
    Ok(bytes)
}

/// Decodes and validates one canonical pending-intent record.
///
/// # Errors
///
/// Rejects an invalid field, version, length or record-byte constraint.
pub fn decode_pending(
    bytes: &[u8],
) -> Result<RuntimeAuthorityPendingV1, RuntimeAuthorityDataErrorV1> {
    validate_header(bytes, PENDING_MAGIC, PENDING_VERSION, FIXED_PENDING_BYTES)?;
    let mut reader = BoundedReader::new(&bytes[10..], |_| RuntimeAuthorityDataErrorV1::CorruptState);
    let state = RuntimeAuthorityStateV1::from_code(reader.u8()?)?;
    let expected_revision = decode_optional_revision(&mut reader)?;
    let revision = reader.u64()?;
    let operation = OperationId::from_bytes(reader.array()?);
    let request_digest = reader.array()?;
    let predecessor_digest = decode_optional_digest(&mut reader)?;
    let holder = decode_holder(&mut reader)?;
    let source_draft_digest = ObjectDigest::from_bytes(reader.array()?);
    let assignment_digest = ObjectDigest::from_bytes(reader.array()?);
    let manifest = decode_manifest(read_manifest_bytes(&mut reader)?)?;
    if !reader.is_empty()
        || operation.as_bytes() == &[0; 16]
        || request_digest == [0; 32]
        || source_draft_digest.as_bytes() == &[0; 32]
        || manifest.digest() != assignment_digest
        || !valid_state_holder(state, holder)
        || !valid_revision_link(expected_revision, revision, predecessor_digest)
    {
        return Err(RuntimeAuthorityDataErrorV1::CorruptState);
    }
    let pending = RuntimeAuthorityPendingV1 {
        operation,
        request_digest,
        state,
        holder,
        expected_revision,
        revision,
        predecessor_digest,
        manifest,
        source_draft_digest,
    };
    if encode_pending(&pending)? != bytes {
        return Err(RuntimeAuthorityDataErrorV1::CorruptState);
    }
    Ok(pending)
}

/// Encodes one immutable binding in its established canonical layout.
///
/// # Errors
///
/// Rejects a length that exceeds the fixed record-byte ceiling or wire width.
pub fn encode_binding(
    binding: &RuntimeAuthorityBindingV1,
) -> Result<Vec<u8>, RuntimeAuthorityDataErrorV1> {
    let manifest = binding.manifest.canonical_bytes();
    let mut bytes = Vec::with_capacity(runtime_binding_encoded_bytes_v1(manifest.len())?);
    bytes.extend_from_slice(BINDING_MAGIC);
    bytes.extend_from_slice(&BINDING_VERSION.to_be_bytes());
    bytes.push(binding.state.code());
    bytes.extend_from_slice(&binding.revision.to_be_bytes());
    bytes.extend_from_slice(binding.operation.as_bytes());
    bytes.extend_from_slice(&binding.request_digest);
    encode_optional_digest(&mut bytes, binding.predecessor_digest);
    encode_holder(&mut bytes, binding.holder);
    bytes.extend_from_slice(binding.source_draft_digest.as_bytes());
    bytes.extend_from_slice(binding.publication_digest.as_bytes());
    bytes.extend_from_slice(&binding.lease_generation.to_be_bytes());
    bytes.extend_from_slice(binding.lease_digest.as_bytes());
    bytes.extend_from_slice(binding.manifest.digest().as_bytes());
    encode_bytes(&mut bytes, manifest)?;
    Ok(bytes)
}

/// Decodes and validates one canonical immutable binding.
///
/// # Errors
///
/// Rejects an invalid field, version, length or record-byte constraint.
pub fn decode_binding(
    bytes: &[u8],
) -> Result<RuntimeAuthorityBindingV1, RuntimeAuthorityDataErrorV1> {
    validate_header(bytes, BINDING_MAGIC, BINDING_VERSION, FIXED_BINDING_BYTES)?;
    let mut reader = BoundedReader::new(&bytes[10..], |_| RuntimeAuthorityDataErrorV1::CorruptState);
    let state = RuntimeAuthorityStateV1::from_code(reader.u8()?)?;
    let revision = reader.u64()?;
    let operation = OperationId::from_bytes(reader.array()?);
    let request_digest = reader.array()?;
    let predecessor_digest = decode_optional_digest(&mut reader)?;
    let holder = decode_holder(&mut reader)?;
    let source_draft_digest = ObjectDigest::from_bytes(reader.array()?);
    let publication_digest = ObjectDigest::from_bytes(reader.array()?);
    let lease_generation = reader.u64()?;
    let lease_digest = ObjectDigest::from_bytes(reader.array()?);
    let assignment_digest = ObjectDigest::from_bytes(reader.array()?);
    let manifest = decode_manifest(read_manifest_bytes(&mut reader)?)?;
    if !reader.is_empty()
        || operation.as_bytes() == &[0; 16]
        || request_digest == [0; 32]
        || source_draft_digest.as_bytes() == &[0; 32]
        || publication_digest.as_bytes() == &[0; 32]
        || lease_generation == 0
        || lease_digest.as_bytes() == &[0; 32]
        || manifest.digest() != assignment_digest
        || !valid_state_holder(state, holder)
        || !valid_binding_link(revision, predecessor_digest)
    {
        return Err(RuntimeAuthorityDataErrorV1::CorruptState);
    }
    let mut binding = RuntimeAuthorityBindingV1 {
        operation,
        request_digest,
        state,
        holder,
        revision,
        predecessor_digest,
        manifest,
        source_draft_digest,
        publication_digest,
        lease_generation,
        lease_digest,
        digest: ObjectDigest::from_bytes([0; 32]),
    };
    let canonical = encode_binding(&binding)?;
    if canonical != bytes {
        return Err(RuntimeAuthorityDataErrorV1::CorruptState);
    }
    binding.digest = binding_digest(&canonical);
    Ok(binding)
}

/// Encodes one current-head reference in its established fixed-width layout.
pub fn encode_head(head: RuntimeAuthorityHeadV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEAD_BYTES);
    bytes.extend_from_slice(HEAD_MAGIC);
    bytes.extend_from_slice(&HEAD_VERSION.to_be_bytes());
    bytes.extend_from_slice(head.sandbox.as_bytes());
    bytes.extend_from_slice(&head.revision.to_be_bytes());
    bytes.extend_from_slice(head.binding_digest.as_bytes());
    bytes
}

/// Decodes and validates one canonical current-head reference.
///
/// # Errors
///
/// Rejects an invalid field, version, length or record-byte constraint.
pub fn decode_head(bytes: &[u8]) -> Result<RuntimeAuthorityHeadV1, RuntimeAuthorityDataErrorV1> {
    validate_header(bytes, HEAD_MAGIC, HEAD_VERSION, HEAD_BYTES)?;
    if bytes.len() != HEAD_BYTES {
        return Err(RuntimeAuthorityDataErrorV1::CorruptState);
    }
    let mut reader = BoundedReader::new(&bytes[10..], |_| RuntimeAuthorityDataErrorV1::CorruptState);
    let sandbox = SandboxId::from_bytes(reader.array()?);
    let revision = reader.u64()?;
    let binding_digest = ObjectDigest::from_bytes(reader.array()?);
    if !reader.is_empty()
        || sandbox.as_bytes() == &[0; 16]
        || revision == 0
        || binding_digest.as_bytes() == &[0; 32]
    {
        return Err(RuntimeAuthorityDataErrorV1::CorruptState);
    }
    let head = RuntimeAuthorityHeadV1 {
        sandbox,
        revision,
        binding_digest,
    };
    if encode_head(head) != bytes {
        return Err(RuntimeAuthorityDataErrorV1::CorruptState);
    }
    Ok(head)
}

/// Computes the established domain-separated binding commitment.
pub fn binding_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(BINDING_DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn checked_record_length(fixed: usize, variable: usize) -> Result<usize, RuntimeAuthorityDataErrorV1> {
    let length = fixed
        .checked_add(variable)
        .ok_or(RuntimeAuthorityDataErrorV1::LimitExceeded("record bytes"))?;
    if length > MAXIMUM_RECORD_BYTES {
        return Err(RuntimeAuthorityDataErrorV1::LimitExceeded("record bytes"));
    }
    Ok(length)
}

fn validate_header(
    bytes: &[u8],
    magic: &[u8; 8],
    version: u16,
    minimum: usize,
) -> Result<(), RuntimeAuthorityDataErrorV1> {
    if bytes.len() < minimum
        || bytes.len() > MAXIMUM_RECORD_BYTES
        || &bytes[..8] != magic
        || bytes[8..10] != version.to_be_bytes()
    {
        return Err(RuntimeAuthorityDataErrorV1::CorruptState);
    }
    Ok(())
}

fn encode_optional_revision(bytes: &mut Vec<u8>, revision: Option<u64>) {
    bytes.push(if revision.is_some() {
        OPTIONAL_PRESENT
    } else {
        OPTIONAL_ABSENT
    });
    bytes.extend_from_slice(&revision.unwrap_or(0).to_be_bytes());
}

fn decode_optional_revision(
    reader: &mut BoundedReader<'_, RuntimeAuthorityDataErrorV1>,
) -> Result<Option<u64>, RuntimeAuthorityDataErrorV1> {
    let present = reader.u8()?;
    let revision = reader.u64()?;
    match (present, revision) {
        (OPTIONAL_ABSENT, 0) => Ok(None),
        (OPTIONAL_PRESENT, 1..) => Ok(Some(revision)),
        _ => Err(RuntimeAuthorityDataErrorV1::CorruptState),
    }
}

fn encode_optional_digest(bytes: &mut Vec<u8>, digest: Option<ObjectDigest>) {
    bytes.extend_from_slice(
        digest
            .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
}

fn decode_optional_digest(
    reader: &mut BoundedReader<'_, RuntimeAuthorityDataErrorV1>,
) -> Result<Option<ObjectDigest>, RuntimeAuthorityDataErrorV1> {
    let digest = ObjectDigest::from_bytes(reader.array()?);
    Ok((digest.as_bytes() != &[0; 32]).then_some(digest))
}

fn encode_holder(bytes: &mut Vec<u8>, holder: Option<PrincipalId>) {
    bytes.extend_from_slice(
        holder
            .unwrap_or_else(|| PrincipalId::from_bytes([0; 16]))
            .as_bytes(),
    );
}

fn decode_holder(
    reader: &mut BoundedReader<'_, RuntimeAuthorityDataErrorV1>,
) -> Result<Option<PrincipalId>, RuntimeAuthorityDataErrorV1> {
    let holder = PrincipalId::from_bytes(reader.array()?);
    Ok((holder.as_bytes() != &[0; 16]).then_some(holder))
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RuntimeAuthorityDataErrorV1> {
    let length = u32::try_from(value.len())
        .map_err(|_| RuntimeAuthorityDataErrorV1::LimitExceeded("manifest bytes"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_manifest(bytes: &[u8]) -> Result<CanonicalAssignmentManifestV1, RuntimeAuthorityDataErrorV1> {
    CanonicalAssignmentManifestV1::from_canonical_bytes(bytes, DecodeLimits::default())
        .map_err(|_| RuntimeAuthorityDataErrorV1::CorruptState)
}

fn read_manifest_bytes<'a>(
    reader: &mut BoundedReader<'a, RuntimeAuthorityDataErrorV1>,
) -> Result<&'a [u8], RuntimeAuthorityDataErrorV1> {
    let length = usize::try_from(reader.u32()?).map_err(|_| RuntimeAuthorityDataErrorV1::CorruptState)?;
    reader.bytes(length)
}

fn valid_state_holder(state: RuntimeAuthorityStateV1, holder: Option<PrincipalId>) -> bool {
    matches!(
        (state, holder),
        (RuntimeAuthorityStateV1::Bound, Some(_)) | (RuntimeAuthorityStateV1::Revoked, None)
    )
}

fn valid_revision_link(
    expected: Option<u64>,
    revision: u64,
    predecessor: Option<ObjectDigest>,
) -> bool {
    match (expected, predecessor) {
        (None, None) => revision == 1,
        (Some(expected), Some(_)) => expected.checked_add(1) == Some(revision),
        _ => false,
    }
}

fn valid_binding_link(revision: u64, predecessor: Option<ObjectDigest>) -> bool {
    (revision == 1 && predecessor.is_none()) || (revision > 1 && predecessor.is_some())
}

#[cfg(test)]
mod width_tests {
    use super::*;

    #[test]
    fn pending_width_does_not_require_the_larger_binding_to_fit() {
        let manifest = MAXIMUM_RECORD_BYTES - FIXED_PENDING_BYTES;

        assert_eq!(runtime_pending_encoded_bytes_v1(manifest).unwrap(), MAXIMUM_RECORD_BYTES);
        assert!(runtime_binding_encoded_bytes_v1(manifest).is_err());
        assert!(runtime_pending_encoded_bytes_v1(usize::MAX).is_err());
        assert!(runtime_binding_encoded_bytes_v1(usize::MAX).is_err());
    }
}
