//! Names the full independently selected suffix startup and allocation contract.

use super::*;
use crucible_node_format::{Id, SchemaRef, canonical};

const DEFINITION: &[u8] = include_bytes!("contract.json");

/// Borrows the immutable canonical definition, excluding its source-file newline.
pub fn restoration_suffix_contract_data() -> &'static [u8] {
    DEFINITION.strip_suffix(b"\n").unwrap_or(DEFINITION)
}

/// Names the full suffix definition without installing or issuing anything.
///
/// # Errors
/// Reports invalid compiled identifiers or full ContentRef construction failure.
pub fn restoration_suffix_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(PACKET_RESTORATION_SUFFIX_FEATURE)?,
        version: 1,
        definition: canonical::content_ref(restoration_suffix_contract_data(), "application/json")?,
        extensions: Default::default(),
    })
}

/// Compares every full definition field using an allocation-free hash view.
///
/// # Errors
/// Refuses another ID, version, definition, media type or schema extension.
pub fn authenticate_restoration_suffix_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let bytes = restoration_suffix_contract_data();
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
    if schema.id.as_str() != PACKET_RESTORATION_SUFFIX_FEATURE
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

/// Names all fixed views of the allocation-free full schema comparison.
pub fn restoration_suffix_schema_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<&SchemaRef>()
        + size_of::<&[u8]>()
        + size_of::<Option<&[u8]>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + std::mem::size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
}
