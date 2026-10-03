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

use aos_sandbox_core::{
    CanonicalAssignmentManifestV1, DecodeLimits, ObjectDigest, OperationId, PrincipalId, SandboxId,
};
use sha2::{Digest as _, Sha256};

use super::{
    BINDING_DIGEST_DOMAIN, BINDING_MAGIC, BINDING_VERSION, HEAD_MAGIC, HEAD_VERSION,
    MAXIMUM_RECORD_BYTES, PENDING_MAGIC, PENDING_VERSION, RuntimeAuthorityBindingV1,
    RuntimeAuthorityError, RuntimeAuthorityHeadV1, RuntimeAuthorityPendingV1,
    RuntimeAuthorityStateV1,
};

const OPTIONAL_ABSENT: u8 = 0;
const OPTIONAL_PRESENT: u8 = 1;
const FIXED_PENDING_BYTES: usize = 192;
const FIXED_BINDING_BYTES: usize = 255;
const HEAD_BYTES: usize = 66;

pub(super) fn encode_pending(
    pending: &RuntimeAuthorityPendingV1,
) -> Result<Vec<u8>, RuntimeAuthorityError> {
    let manifest = pending.manifest.canonical_bytes();
    let mut bytes = Vec::with_capacity(checked_record_length(FIXED_PENDING_BYTES, manifest.len())?);
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

pub(super) fn decode_pending(
    bytes: &[u8],
) -> Result<RuntimeAuthorityPendingV1, RuntimeAuthorityError> {
    validate_header(bytes, PENDING_MAGIC, PENDING_VERSION, FIXED_PENDING_BYTES)?;
    let mut cursor = 10;
    let state = RuntimeAuthorityStateV1::from_code(take_u8(bytes, &mut cursor)?)?;
    let expected_revision = decode_optional_revision(bytes, &mut cursor)?;
    let revision = take_u64(bytes, &mut cursor)?;
    let operation = OperationId::from_bytes(take_array(bytes, &mut cursor)?);
    let request_digest = take_array(bytes, &mut cursor)?;
    let predecessor_digest = decode_optional_digest(bytes, &mut cursor)?;
    let holder = decode_holder(bytes, &mut cursor)?;
    let source_draft_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let assignment_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let manifest = decode_manifest(take_length_prefixed(bytes, &mut cursor)?)?;
    if cursor != bytes.len()
        || operation.as_bytes() == &[0; 16]
        || request_digest == [0; 32]
        || source_draft_digest.as_bytes() == &[0; 32]
        || manifest.digest() != assignment_digest
        || !valid_state_holder(state, holder)
        || !valid_revision_link(expected_revision, revision, predecessor_digest)
    {
        return Err(RuntimeAuthorityError::CorruptState);
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
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(pending)
}

pub(super) fn encode_binding(
    binding: &RuntimeAuthorityBindingV1,
) -> Result<Vec<u8>, RuntimeAuthorityError> {
    let manifest = binding.manifest.canonical_bytes();
    let mut bytes = Vec::with_capacity(checked_record_length(FIXED_BINDING_BYTES, manifest.len())?);
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

pub(super) fn decode_binding(
    bytes: &[u8],
) -> Result<RuntimeAuthorityBindingV1, RuntimeAuthorityError> {
    validate_header(bytes, BINDING_MAGIC, BINDING_VERSION, FIXED_BINDING_BYTES)?;
    let mut cursor = 10;
    let state = RuntimeAuthorityStateV1::from_code(take_u8(bytes, &mut cursor)?)?;
    let revision = take_u64(bytes, &mut cursor)?;
    let operation = OperationId::from_bytes(take_array(bytes, &mut cursor)?);
    let request_digest = take_array(bytes, &mut cursor)?;
    let predecessor_digest = decode_optional_digest(bytes, &mut cursor)?;
    let holder = decode_holder(bytes, &mut cursor)?;
    let source_draft_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let publication_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let lease_generation = take_u64(bytes, &mut cursor)?;
    let lease_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let assignment_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    let manifest = decode_manifest(take_length_prefixed(bytes, &mut cursor)?)?;
    if cursor != bytes.len()
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
        return Err(RuntimeAuthorityError::CorruptState);
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
        return Err(RuntimeAuthorityError::CorruptState);
    }
    binding.digest = binding_digest(&canonical);
    Ok(binding)
}

pub(super) fn encode_head(head: RuntimeAuthorityHeadV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEAD_BYTES);
    bytes.extend_from_slice(HEAD_MAGIC);
    bytes.extend_from_slice(&HEAD_VERSION.to_be_bytes());
    bytes.extend_from_slice(head.sandbox.as_bytes());
    bytes.extend_from_slice(&head.revision.to_be_bytes());
    bytes.extend_from_slice(head.binding_digest.as_bytes());
    bytes
}

pub(super) fn decode_head(bytes: &[u8]) -> Result<RuntimeAuthorityHeadV1, RuntimeAuthorityError> {
    validate_header(bytes, HEAD_MAGIC, HEAD_VERSION, HEAD_BYTES)?;
    if bytes.len() != HEAD_BYTES {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    let mut cursor = 10;
    let sandbox = SandboxId::from_bytes(take_array(bytes, &mut cursor)?);
    let revision = take_u64(bytes, &mut cursor)?;
    let binding_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
    if cursor != bytes.len()
        || sandbox.as_bytes() == &[0; 16]
        || revision == 0
        || binding_digest.as_bytes() == &[0; 32]
    {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    let head = RuntimeAuthorityHeadV1 {
        sandbox,
        revision,
        binding_digest,
    };
    if encode_head(head) != bytes {
        return Err(RuntimeAuthorityError::CorruptState);
    }
    Ok(head)
}

pub(super) fn binding_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(BINDING_DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn checked_record_length(fixed: usize, variable: usize) -> Result<usize, RuntimeAuthorityError> {
    let length = fixed
        .checked_add(variable)
        .ok_or(RuntimeAuthorityError::LimitExceeded("record bytes"))?;
    if length > MAXIMUM_RECORD_BYTES {
        return Err(RuntimeAuthorityError::LimitExceeded("record bytes"));
    }
    Ok(length)
}

fn validate_header(
    bytes: &[u8],
    magic: &[u8; 8],
    version: u16,
    minimum: usize,
) -> Result<(), RuntimeAuthorityError> {
    if bytes.len() < minimum
        || bytes.len() > MAXIMUM_RECORD_BYTES
        || &bytes[..8] != magic
        || bytes[8..10] != version.to_be_bytes()
    {
        return Err(RuntimeAuthorityError::CorruptState);
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
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Option<u64>, RuntimeAuthorityError> {
    let present = take_u8(bytes, cursor)?;
    let revision = take_u64(bytes, cursor)?;
    match (present, revision) {
        (OPTIONAL_ABSENT, 0) => Ok(None),
        (OPTIONAL_PRESENT, 1..) => Ok(Some(revision)),
        _ => Err(RuntimeAuthorityError::CorruptState),
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
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Option<ObjectDigest>, RuntimeAuthorityError> {
    let digest = ObjectDigest::from_bytes(take_array(bytes, cursor)?);
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
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Option<PrincipalId>, RuntimeAuthorityError> {
    let holder = PrincipalId::from_bytes(take_array(bytes, cursor)?);
    Ok((holder.as_bytes() != &[0; 16]).then_some(holder))
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), RuntimeAuthorityError> {
    let length = u32::try_from(value.len())
        .map_err(|_| RuntimeAuthorityError::LimitExceeded("manifest bytes"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_manifest(bytes: &[u8]) -> Result<CanonicalAssignmentManifestV1, RuntimeAuthorityError> {
    CanonicalAssignmentManifestV1::from_canonical_bytes(bytes, DecodeLimits::default())
        .map_err(|_| RuntimeAuthorityError::CorruptState)
}

fn take_length_prefixed<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], RuntimeAuthorityError> {
    let length = usize::try_from(u32::from_be_bytes(take_array(bytes, cursor)?))
        .map_err(|_| RuntimeAuthorityError::CorruptState)?;
    take(bytes, cursor, length)
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, RuntimeAuthorityError> {
    Ok(*take(bytes, cursor, 1)?
        .first()
        .ok_or(RuntimeAuthorityError::CorruptState)?)
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, RuntimeAuthorityError> {
    Ok(u64::from_be_bytes(take_array(bytes, cursor)?))
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], RuntimeAuthorityError> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| RuntimeAuthorityError::CorruptState)
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], RuntimeAuthorityError> {
    let end = cursor
        .checked_add(length)
        .ok_or(RuntimeAuthorityError::CorruptState)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(RuntimeAuthorityError::CorruptState)?;
    *cursor = end;
    Ok(value)
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
