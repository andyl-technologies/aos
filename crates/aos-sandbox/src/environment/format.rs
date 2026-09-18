//! Canonical codec for exact environment-generation manifests.
//!
//! ```text
//! AOSENVG1 | version:1 | disclosure-kind:1 | predecessor-present:1 |
//! reserved:4 | project:16 | sandbox:16 | generation:8 |
//! predecessor-generation:8 | predecessor-manifest:32 |
//! facade-view:16 | facade-revision:8 | disclosure-id:16 |
//! environment-descriptor | environment-length:4 | canonical-environment |
//! output-length:4 | output | target-length:2 | target |
//! facade-descriptor | policy-descriptor | input-count:4 |
//! (role:1 | reserved:3 | descriptor)* | manifest-digest:32
//! ```
//!
//! A descriptor is `media-length:2 | media | digest:32 | encoded-size:8`.
//! Integers are big endian. Decode preflights every count, length, and remaining
//! byte before any allocation.

use aos_sandbox_core::format::{decode_environment, try_encode_environment};
use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{
    CacheDomainId, DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest, ProjectId, Revision,
    SandboxId, ViewId,
};

use super::model::{
    EnvironmentDescriptorRoleV1, EnvironmentFacadeV1, EnvironmentGenerationManifestV1,
    EnvironmentInputCommitmentV1, EnvironmentManifestDigestV1, EnvironmentModelError,
    EnvironmentPredecessorV1, EnvironmentTargetSystemV1, MAXIMUM_ENVIRONMENT_INPUTS,
    MAXIMUM_INLINE_ENVIRONMENT_BYTES, MAXIMUM_SELECTED_OUTPUT_BYTES, MAXIMUM_TARGET_SYSTEM_BYTES,
    SelectedEnvironmentOutputV1,
};

const MAGIC: &[u8; 8] = b"AOSENVG1";
const VERSION: u16 = 1;
const FIXED_PREFIX_BYTES: usize = 136;
const DIGEST_BYTES: usize = 32;
const MAXIMUM_RECORD_BYTES: usize = 96 * 1024 * 1024;

/// Encodes one validated manifest in exact v1 form.
///
/// # Errors
///
/// Returns [`EnvironmentModelError`] if the exact length exceeds the format
/// ceiling, cannot be represented, or checked allocation fails.
pub fn encode_environment_generation_v1(
    value: &EnvironmentGenerationManifestV1,
) -> Result<Vec<u8>, EnvironmentModelError> {
    let environment_length = usize::try_from(value.environment_descriptor().encoded_size())
        .map_err(|_| EnvironmentModelError::InvalidModel)?;
    let expected_length = encoded_length(value, environment_length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    let environment_bytes = try_encode_environment(value.environment())
        .map_err(|_| EnvironmentModelError::Allocation)?;
    if environment_bytes.len() != environment_length {
        return Err(EnvironmentModelError::InvalidModel);
    }
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(disclosure_code(value.disclosure().kind()));
    bytes.push(u8::from(value.predecessor().is_some()));
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(value.project().as_bytes());
    bytes.extend_from_slice(value.sandbox().as_bytes());
    bytes.extend_from_slice(&value.generation().get().to_be_bytes());
    bytes.extend_from_slice(
        &value
            .predecessor()
            .map_or(0, |predecessor| predecessor.generation().get())
            .to_be_bytes(),
    );
    bytes.extend_from_slice(
        value
            .predecessor()
            .map_or(ObjectDigest::from_bytes([0; 32]), |value| {
                value.manifest().digest()
            })
            .as_bytes(),
    );
    bytes.extend_from_slice(value.facade().view().as_bytes());
    bytes.extend_from_slice(&value.facade().revision().get().to_be_bytes());
    bytes.extend_from_slice(value.disclosure().domain_id().as_bytes());
    encode_descriptor(&mut bytes, value.environment_descriptor())?;
    push_u32_length(&mut bytes, environment_bytes.len())?;
    bytes.extend_from_slice(&environment_bytes);
    push_u32_length(&mut bytes, value.selected_output().as_str().len())?;
    bytes.extend_from_slice(value.selected_output().as_str().as_bytes());
    push_u16_length(&mut bytes, value.target_system().as_str().len())?;
    bytes.extend_from_slice(value.target_system().as_str().as_bytes());
    encode_descriptor(&mut bytes, value.facade().descriptor())?;
    encode_descriptor(&mut bytes, value.effective_policy())?;
    push_u32_length(&mut bytes, value.inputs().len())?;
    for input in value.inputs() {
        bytes.push(input.role() as u8);
        bytes.extend_from_slice(&[0; 3]);
        encode_descriptor(&mut bytes, input.descriptor())?;
    }
    let digest = EnvironmentManifestDigestV1::commit(&bytes);
    bytes.extend_from_slice(digest.digest().as_bytes());
    if bytes.len() != expected_length {
        return Err(EnvironmentModelError::InvalidModel);
    }
    Ok(bytes)
}

/// Decodes one exact, bounded environment-generation manifest.
///
/// # Errors
///
/// Returns [`EnvironmentModelError`] for preflight failure, allocation failure,
/// malformed portable Environment bytes, descriptor mismatch, or bad digest.
pub fn decode_environment_generation_v1(
    encoded: &[u8],
) -> Result<EnvironmentGenerationManifestV1, EnvironmentModelError> {
    let input_count = preflight(encoded)?;
    let (body, stored_digest) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    if EnvironmentManifestDigestV1::commit(body)
        .digest()
        .as_bytes()
        != stored_digest
    {
        return Err(EnvironmentModelError::CorruptEncoding);
    }

    let mut bytes = body;
    if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let disclosure_kind = decode_disclosure(take::<1>(&mut bytes)?[0])?;
    let predecessor_present = take::<1>(&mut bytes)?[0];
    if take::<4>(&mut bytes)? != [0; 4] {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let project = ProjectId::from_bytes(take(&mut bytes)?);
    let sandbox = SandboxId::from_bytes(take(&mut bytes)?);
    let generation = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let predecessor_generation = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let predecessor_raw = ObjectDigest::from_bytes(take(&mut bytes)?);
    let predecessor = match predecessor_present {
        0 if predecessor_generation.get() == 0 && predecessor_raw.as_bytes() == &[0; 32] => None,
        1 => Some(
            EnvironmentPredecessorV1::new(
                predecessor_generation,
                EnvironmentManifestDigestV1::from_stored(predecessor_raw)?,
            )
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?,
        ),
        _ => return Err(EnvironmentModelError::CorruptEncoding),
    };
    let facade_view = ViewId::from_bytes(take(&mut bytes)?);
    let facade_revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let disclosure_id = CacheDomainId::from_bytes(take(&mut bytes)?);
    let environment_descriptor = decode_descriptor(&mut bytes)?;
    let environment_length = read_u32_length(&mut bytes, MAXIMUM_INLINE_ENVIRONMENT_BYTES)?;
    let environment = decode_environment(
        take_slice(&mut bytes, environment_length)?,
        DecodeLimits::default(),
    )
    .map_err(|_| EnvironmentModelError::InvalidInlineEnvironment)?;
    let output_length = read_u32_length(&mut bytes, MAXIMUM_SELECTED_OUTPUT_BYTES)?;
    let selected_output =
        SelectedEnvironmentOutputV1::new(decode_text(take_slice(&mut bytes, output_length)?)?)
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    let target_length = usize::from(u16::from_be_bytes(take(&mut bytes)?));
    let target_system =
        EnvironmentTargetSystemV1::new(decode_text(take_slice(&mut bytes, target_length)?)?)
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    let facade_descriptor = decode_descriptor(&mut bytes)?;
    let effective_policy = decode_descriptor(&mut bytes)?;
    if read_u32_length(&mut bytes, MAXIMUM_ENVIRONMENT_INPUTS)? != input_count {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(input_count)
        .map_err(|_| EnvironmentModelError::Allocation)?;
    for _ in 0..input_count {
        let role = decode_role(take::<1>(&mut bytes)?[0])?;
        if take::<3>(&mut bytes)? != [0; 3] {
            return Err(EnvironmentModelError::CorruptEncoding);
        }
        inputs.push(
            EnvironmentInputCommitmentV1::new(role, decode_descriptor(&mut bytes)?)
                .map_err(|_| EnvironmentModelError::CorruptEncoding)?,
        );
    }
    if !bytes.is_empty() {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    EnvironmentGenerationManifestV1::new(
        project,
        sandbox,
        generation,
        predecessor,
        environment,
        environment_descriptor,
        selected_output,
        target_system,
        EnvironmentFacadeV1::new(facade_view, facade_revision, facade_descriptor)
            .map_err(|_| EnvironmentModelError::CorruptEncoding)?,
        effective_policy,
        CacheDomain::new(disclosure_kind, disclosure_id),
        inputs,
    )
    .map_err(|_| EnvironmentModelError::CorruptEncoding)
}

/// Returns the canonical purpose-separated digest of one validated manifest.
///
/// # Errors
///
/// Returns [`EnvironmentModelError`] if canonical encoding cannot be allocated
/// within the fixed record ceiling.
pub fn environment_manifest_digest_v1(
    value: &EnvironmentGenerationManifestV1,
) -> Result<EnvironmentManifestDigestV1, EnvironmentModelError> {
    let encoded = encode_environment_generation_v1(value)?;
    let body_length = encoded.len() - DIGEST_BYTES;
    Ok(EnvironmentManifestDigestV1::commit(&encoded[..body_length]))
}

fn encoded_length(
    value: &EnvironmentGenerationManifestV1,
    environment_length: usize,
) -> Result<usize, EnvironmentModelError> {
    let descriptor_length = |descriptor: &ObjectDescriptor| {
        42_usize.checked_add(descriptor.media_type().as_str().len())
    };
    let mut length = FIXED_PREFIX_BYTES
        .checked_add(
            descriptor_length(value.environment_descriptor())
                .ok_or(EnvironmentModelError::InvalidModel)?,
        )
        .and_then(|total| total.checked_add(4)?.checked_add(environment_length))
        .and_then(|total| {
            total
                .checked_add(4)?
                .checked_add(value.selected_output().as_str().len())
        })
        .and_then(|total| {
            total
                .checked_add(2)?
                .checked_add(value.target_system().as_str().len())
        })
        .and_then(|total| total.checked_add(descriptor_length(value.facade().descriptor())?))
        .and_then(|total| total.checked_add(descriptor_length(value.effective_policy())?))
        .and_then(|total| total.checked_add(4))
        .ok_or(EnvironmentModelError::InvalidModel)?;
    for input in value.inputs() {
        length = length
            .checked_add(4)
            .and_then(|total| total.checked_add(descriptor_length(input.descriptor())?))
            .ok_or(EnvironmentModelError::InvalidModel)?;
    }
    length = length
        .checked_add(DIGEST_BYTES)
        .filter(|length| *length <= MAXIMUM_RECORD_BYTES)
        .ok_or(EnvironmentModelError::InvalidModel)?;
    Ok(length)
}

fn preflight(encoded: &[u8]) -> Result<usize, EnvironmentModelError> {
    if encoded.len() < FIXED_PREFIX_BYTES + DIGEST_BYTES || encoded.len() > MAXIMUM_RECORD_BYTES {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    let body_length = encoded.len() - DIGEST_BYTES;
    let mut bytes = &encoded[..body_length];
    take_slice(&mut bytes, FIXED_PREFIX_BYTES)?;
    preflight_descriptor(&mut bytes)?;
    let environment = read_u32_length(&mut bytes, MAXIMUM_INLINE_ENVIRONMENT_BYTES)?;
    if environment == 0 {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    take_slice(&mut bytes, environment)?;
    let output = read_u32_length(&mut bytes, MAXIMUM_SELECTED_OUTPUT_BYTES)?;
    if output == 0 {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    take_slice(&mut bytes, output)?;
    let target = usize::from(u16::from_be_bytes(take(&mut bytes)?));
    if target == 0 || target > MAXIMUM_TARGET_SYSTEM_BYTES {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    take_slice(&mut bytes, target)?;
    preflight_descriptor(&mut bytes)?;
    preflight_descriptor(&mut bytes)?;
    let count = read_u32_length(&mut bytes, MAXIMUM_ENVIRONMENT_INPUTS)?;
    if count == 0 {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    for _ in 0..count {
        take_slice(&mut bytes, 4)?;
        preflight_descriptor(&mut bytes)?;
    }
    if !bytes.is_empty() {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    Ok(count)
}

fn encode_descriptor(
    bytes: &mut Vec<u8>,
    value: &ObjectDescriptor,
) -> Result<(), EnvironmentModelError> {
    push_u16_length(bytes, value.media_type().as_str().len())?;
    bytes.extend_from_slice(value.media_type().as_str().as_bytes());
    bytes.extend_from_slice(value.digest().as_bytes());
    bytes.extend_from_slice(&value.encoded_size().to_be_bytes());
    Ok(())
}

fn decode_descriptor(bytes: &mut &[u8]) -> Result<ObjectDescriptor, EnvironmentModelError> {
    let length = usize::from(u16::from_be_bytes(take(bytes)?));
    let media = decode_text(take_slice(bytes, length)?)?;
    let media_type = MediaType::new(media).map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    let digest = ObjectDigest::from_bytes(take(bytes)?);
    let size = u64::from_be_bytes(take(bytes)?);
    Ok(ObjectDescriptor::new(media_type, digest, size))
}

fn preflight_descriptor(bytes: &mut &[u8]) -> Result<(), EnvironmentModelError> {
    let length = usize::from(u16::from_be_bytes(take(bytes)?));
    if length == 0 || length > 255 {
        return Err(EnvironmentModelError::CorruptEncoding);
    }
    take_slice(
        bytes,
        length
            .checked_add(40)
            .ok_or(EnvironmentModelError::CorruptEncoding)?,
    )?;
    Ok(())
}

fn disclosure_code(value: CacheDomainKind) -> u8 {
    match value {
        CacheDomainKind::Private => 1,
        CacheDomainKind::Project => 2,
        CacheDomainKind::TrustDomain => 3,
        CacheDomainKind::Public => 4,
    }
}
fn decode_disclosure(value: u8) -> Result<CacheDomainKind, EnvironmentModelError> {
    match value {
        1 => Ok(CacheDomainKind::Private),
        2 => Ok(CacheDomainKind::Project),
        3 => Ok(CacheDomainKind::TrustDomain),
        4 => Ok(CacheDomainKind::Public),
        _ => Err(EnvironmentModelError::CorruptEncoding),
    }
}
fn decode_role(value: u8) -> Result<EnvironmentDescriptorRoleV1, EnvironmentModelError> {
    match value {
        1 => Ok(EnvironmentDescriptorRoleV1::ProjectSource),
        2 => Ok(EnvironmentDescriptorRoleV1::LockFile),
        3 => Ok(EnvironmentDescriptorRoleV1::EvaluationInput),
        4 => Ok(EnvironmentDescriptorRoleV1::Toolchain),
        5 => Ok(EnvironmentDescriptorRoleV1::Dependency),
        _ => Err(EnvironmentModelError::CorruptEncoding),
    }
}
fn decode_text(bytes: &[u8]) -> Result<String, EnvironmentModelError> {
    let text = std::str::from_utf8(bytes).map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    let mut value = String::new();
    value
        .try_reserve_exact(text.len())
        .map_err(|_| EnvironmentModelError::Allocation)?;
    value.push_str(text);
    Ok(value)
}
fn push_u16_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), EnvironmentModelError> {
    bytes.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| EnvironmentModelError::InvalidModel)?
            .to_be_bytes(),
    );
    Ok(())
}
fn push_u32_length(bytes: &mut Vec<u8>, length: usize) -> Result<(), EnvironmentModelError> {
    bytes.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| EnvironmentModelError::InvalidModel)?
            .to_be_bytes(),
    );
    Ok(())
}
fn read_u32_length(bytes: &mut &[u8], maximum: usize) -> Result<usize, EnvironmentModelError> {
    let value = usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| EnvironmentModelError::CorruptEncoding)?;
    if value > maximum {
        Err(EnvironmentModelError::CorruptEncoding)
    } else {
        Ok(value)
    }
}
fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], EnvironmentModelError> {
    let (value, remaining) = bytes
        .split_at_checked(length)
        .ok_or(EnvironmentModelError::CorruptEncoding)?;
    *bytes = remaining;
    Ok(value)
}
fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], EnvironmentModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| EnvironmentModelError::CorruptEncoding)
}
