//! Names the full distinct activation contract without constructing permissions.

use super::*;
use crucible_node_format::{SchemaRef, canonical};
use std::mem::size_of;

const CONTRACT: &[u8] = include_bytes!("contract.json");

/// Returns the complete immutable activation contract bytes.
pub fn restoration_activation_upload_contract_data() -> &'static [u8] {
    // The checked-in canonical JSON has one source-file newline outside its
    // canonical body; that byte is deliberately excluded from the definition.
    CONTRACT.strip_suffix(b"\n").unwrap_or(CONTRACT)
}

/// Names the complete selected definition without granting activation rights.
///
/// # Errors
/// Reports invalid static identifiers or content-reference construction failure.
pub fn restoration_activation_upload_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)?,
        version: 1,
        definition: canonical::content_ref(
            restoration_activation_upload_contract_data(),
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

/// Compares the full selected schema allocation-free, without projecting fields.
///
/// # Errors
/// Refuses another ID/version, any schema extension or changed full definition
/// algorithm/domain/digest/length/media. A match grants no native or Source right.
pub fn authenticate_restoration_activation_upload_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let bytes = restoration_activation_upload_contract_data();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(
        &u64::try_from(bytes.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    let digest = hasher.finalize().to_hex();
    if schema.id.as_str() != PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE
        || schema.version != 1
        || !schema.extensions.is_empty()
        || schema.definition.hash.algorithm != "blake3-256"
        || schema.definition.hash.domain != "cnp.blob.v1"
        || schema.definition.hash.digest != digest.as_str()
        || schema.definition.length.get() != bytes.len() as u64
        || schema.definition.media_type != "application/json"
    {
        return Err(invalid());
    }
    Ok(())
}

/// Names the full-reference comparison's fixed hash and borrowed result views.
pub fn restoration_activation_upload_schema_counter_scratch_data() -> usize {
    size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<&SchemaRef>()
        + size_of::<&[u8]>()
        + size_of::<Option<&[u8]>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<[u8; 64]>()
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
}
