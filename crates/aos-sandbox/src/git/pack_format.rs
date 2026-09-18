//! Canonical immutable-pack generation records.
//!
//! ```text
//! AOSGPK01 | body-len:u32 | format:u8 | reserved:3 | identity:16 |
//! generation:u64 | predecessor-present:u8 | reserved:7 |
//! predecessor-generation:u64 | predecessor-digest:32 | project:16 |
//! repository:16 | export:16 |
//! export-generation:u64 | export-digest:32 | generation-digest:32 |
//! pack-descriptor | index-descriptor | multi-present:u8 | reserved:7 |
//! [multi-pack-index-descriptor] | whole-ODB
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId, Revision};

use super::format::{
    decode_descriptor, decode_whole_database, encode_descriptor, encode_whole_database,
    preflight_descriptor, preflight_whole_database,
};
use super::{
    GitExportGenerationDigestV1, GitExportGenerationV1, GitModelError, GitObjectFormatV1,
    GitPackGenerationDigestV1, GitPackGenerationPredecessorV1, GitTrustedValidatorV1,
    ImmutablePackGenerationV1,
};

const MAGIC: &[u8; 8] = b"AOSGPK01";
const MAXIMUM_PACK_RECORD_BYTES: usize = 160 * 1024 * 1024;

/// Encodes one immutable pack generation in exact canonical form.
///
/// # Errors
///
/// Returns [`GitModelError`] if the derived body exceeds the record ceiling,
/// cannot be represented by the format's `u32` length, or allocation fails.
pub fn encode_pack_generation_v1(
    value: &ImmutablePackGenerationV1,
) -> Result<Vec<u8>, GitModelError> {
    let encoded_length = pack_encoded_length(value)?;
    let body_capacity = encoded_length
        .checked_sub(12)
        .ok_or(GitModelError::InvalidModel)?;
    let mut body = Vec::new();
    body.try_reserve_exact(body_capacity)
        .map_err(|_| GitModelError::Allocation)?;
    body.push(value.database().graph().format() as u8);
    body.extend_from_slice(&[0; 3]);
    body.extend_from_slice(value.pack_generation().as_bytes());
    body.extend_from_slice(&value.generation().get().to_be_bytes());
    match value.predecessor() {
        Some(predecessor) => {
            body.push(1);
            body.extend_from_slice(&[0; 7]);
            body.extend_from_slice(&predecessor.generation().get().to_be_bytes());
            body.extend_from_slice(predecessor.digest().digest().as_bytes());
        }
        None => body.extend_from_slice(&[0; 48]),
    }
    body.extend_from_slice(value.project().as_bytes());
    body.extend_from_slice(value.repository().as_bytes());
    body.extend_from_slice(value.export().as_bytes());
    body.extend_from_slice(&value.export_generation().get().to_be_bytes());
    body.extend_from_slice(value.export_digest().digest().as_bytes());
    body.extend_from_slice(value.generation_digest().digest().as_bytes());
    encode_descriptor(&mut body, value.pack());
    encode_descriptor(&mut body, value.index());
    match value.multi_pack_index() {
        Some(descriptor) => {
            body.push(1);
            body.extend_from_slice(&[0; 7]);
            encode_descriptor(&mut body, descriptor);
        }
        None => body.extend_from_slice(&[0; 8]),
    }
    encode_whole_database(&mut body, value.database());

    let body_length = u32::try_from(body.len()).map_err(|_| GitModelError::InvalidModel)?;
    if body.len() != body_capacity {
        return Err(GitModelError::InvalidModel);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_length)
        .map_err(|_| GitModelError::Allocation)?;
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&body_length.to_be_bytes());
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

pub(super) fn validate_pack_record_size(
    value: &ImmutablePackGenerationV1,
) -> Result<(), GitModelError> {
    pack_encoded_length(value).map(|_| ())
}

fn pack_encoded_length(value: &ImmutablePackGenerationV1) -> Result<usize, GitModelError> {
    let descriptor_length = |descriptor: &super::GitDescriptorV1| {
        44_usize.checked_add(descriptor.descriptor().media_type().as_str().len())
    };
    let database = value.database();
    let whole_database = 336_usize
        .checked_add(
            database
                .graph()
                .roots()
                .len()
                .checked_mul(32)
                .ok_or(GitModelError::InvalidModel)?,
        )
        .and_then(|length| {
            length.checked_add(
                database
                    .validator()
                    .report()
                    .descriptor()
                    .media_type()
                    .as_str()
                    .len(),
            )
        })
        .ok_or(GitModelError::InvalidModel)?;
    let pack = descriptor_length(value.pack()).ok_or(GitModelError::InvalidModel)?;
    let index = descriptor_length(value.index()).ok_or(GitModelError::InvalidModel)?;
    let multi = match value.multi_pack_index() {
        Some(descriptor) => descriptor_length(descriptor).ok_or(GitModelError::InvalidModel)?,
        None => 0,
    };
    let body = 196_usize
        .checked_add(pack)
        .and_then(|length| length.checked_add(index))
        .and_then(|length| length.checked_add(8))
        .and_then(|length| length.checked_add(multi))
        .and_then(|length| length.checked_add(whole_database))
        .ok_or(GitModelError::InvalidModel)?;
    let encoded = body.checked_add(12).ok_or(GitModelError::InvalidModel)?;
    if encoded > MAXIMUM_PACK_RECORD_BYTES || u32::try_from(body).is_err() {
        Err(GitModelError::InvalidModel)
    } else {
        Ok(encoded)
    }
}

/// Decodes one allocation-bounded immutable pack generation record.
///
/// # Errors
///
/// Returns [`GitModelError::CorruptEncoding`] for length, schema, lineage,
/// descriptor, trusted whole-ODB, expected export, or derived-generation
/// commitment mismatch.
pub fn decode_pack_generation_v1(
    encoded: &[u8],
    trusted_validator: &GitTrustedValidatorV1,
    expected_export: &GitExportGenerationV1,
) -> Result<ImmutablePackGenerationV1, GitModelError> {
    let value = decode_pack_generation_payload_v1(encoded, trusted_validator)?;
    if value.project() != expected_export.project()
        || value.repository() != expected_export.repository()
        || value.export() != expected_export.export()
        || value.export_generation() != expected_export.generation()
        || value.export_digest() != expected_export.generation_digest()
        || value.database() != expected_export.database()
    {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(value)
}

/// Decodes a self-contained pack payload before history rebinds its export.
pub(super) fn decode_pack_generation_payload_v1(
    encoded: &[u8],
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<ImmutablePackGenerationV1, GitModelError> {
    if encoded.len() < 12 || encoded.len() > MAXIMUM_PACK_RECORD_BYTES {
        return Err(GitModelError::CorruptEncoding);
    }
    let mut bytes = encoded;
    if take::<8>(&mut bytes)? != *MAGIC {
        return Err(GitModelError::CorruptEncoding);
    }
    let body_length = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if body_length != bytes.len() {
        return Err(GitModelError::CorruptEncoding);
    }
    preflight_body(bytes)?;
    let format = match take::<1>(&mut bytes)?[0] {
        1 => GitObjectFormatV1::Sha1,
        2 => GitObjectFormatV1::Sha256,
        _ => return Err(GitModelError::CorruptEncoding),
    };
    if take::<3>(&mut bytes)? != [0; 3] {
        return Err(GitModelError::CorruptEncoding);
    }
    let identity = ResourceId::from_bytes(take(&mut bytes)?);
    let generation = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let predecessor_slot = take_slice(&mut bytes, 48)?;
    let predecessor = decode_predecessor(predecessor_slot)?;
    let project = ProjectId::from_bytes(take(&mut bytes)?);
    let repository = ResourceId::from_bytes(take(&mut bytes)?);
    let export = ResourceId::from_bytes(take(&mut bytes)?);
    let export_generation = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let export_digest =
        GitExportGenerationDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
    let stored_digest =
        GitPackGenerationDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
    let pack = decode_descriptor(&mut bytes)?;
    let index = decode_descriptor(&mut bytes)?;
    let multi_present = take::<1>(&mut bytes)?[0];
    if take::<7>(&mut bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    let multi_pack_index = match multi_present {
        0 => None,
        1 => Some(decode_descriptor(&mut bytes)?),
        _ => return Err(GitModelError::CorruptEncoding),
    };
    let database = decode_whole_database(&mut bytes, format, trusted_validator)?;
    if !bytes.is_empty() {
        return Err(GitModelError::CorruptEncoding);
    }
    let value = ImmutablePackGenerationV1::from_parts(
        identity,
        generation,
        predecessor,
        project,
        repository,
        export,
        export_generation,
        export_digest,
        pack,
        index,
        multi_pack_index,
        database,
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    if value.generation_digest() != stored_digest {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(value)
}

fn preflight_body(mut bytes: &[u8]) -> Result<(), GitModelError> {
    take_slice(&mut bytes, 4 + 16 + 8 + 48 + 16 + 16 + 16 + 8 + 32 + 32)?;
    preflight_descriptor(&mut bytes)?;
    preflight_descriptor(&mut bytes)?;
    let present = take::<1>(&mut bytes)?[0];
    if take::<7>(&mut bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    match present {
        0 => {}
        1 => preflight_descriptor(&mut bytes)?,
        _ => return Err(GitModelError::CorruptEncoding),
    }
    preflight_whole_database(&mut bytes)?;
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(GitModelError::CorruptEncoding)
    }
}

fn decode_predecessor(
    mut bytes: &[u8],
) -> Result<Option<GitPackGenerationPredecessorV1>, GitModelError> {
    let present = take::<1>(&mut bytes)?[0];
    if take::<7>(&mut bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    let generation = u64::from_be_bytes(take(&mut bytes)?);
    let digest = ObjectDigest::from_bytes(take(&mut bytes)?);
    match (present, generation, digest.as_bytes() == &[0; 32]) {
        (0, 0, true) => Ok(None),
        (1, value, false) => GitPackGenerationPredecessorV1::new(
            Revision::new(value),
            GitPackGenerationDigestV1::from_stored(digest)?,
        )
        .map(Some)
        .map_err(|_| GitModelError::CorruptEncoding),
        _ => Err(GitModelError::CorruptEncoding),
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], GitModelError> {
    let prefix = bytes.get(..N).ok_or(GitModelError::CorruptEncoding)?;
    let value = <[u8; N]>::try_from(prefix).map_err(|_| GitModelError::CorruptEncoding)?;
    *bytes = bytes.get(N..).ok_or(GitModelError::CorruptEncoding)?;
    Ok(value)
}

fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], GitModelError> {
    let value = bytes.get(..length).ok_or(GitModelError::CorruptEncoding)?;
    *bytes = bytes.get(length..).ok_or(GitModelError::CorruptEncoding)?;
    Ok(value)
}
