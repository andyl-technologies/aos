//! Names the single compiled genuine coordinator commitment checkpoint contract.
//!
//! The real append-only coordinator issuer is Core-owned. This immutable format
//! identity never creates a safe point from requested coordinates, equal native
//! timestamps, map order or a decoded witness. Old15 bodies are unchanged.
//!
//! ```text
//! definition = coordinator_checkpoint17.json
//! checkpoint media = application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17
//! ```

use super::*;

/// Names the separate actual coordinator prefix witness definition.
pub const COORDINATOR_CHECKPOINT17_SCHEMA: &str =
    "source-owned.coordinator-commitment-checkpoint/17";
/// Names the complete witness object media independently of Runtime7.
pub const COORDINATOR_CHECKPOINT17_MEDIA: &str =
    "application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17";
const CONTRACT: &[u8] = include_bytes!("coordinator_checkpoint17.json");

/// Borrows the one complete immutable definition consumed by Core and declarations.
pub const fn coordinator_checkpoint17_contract_data() -> &'static [u8] {
    CONTRACT
}

/// Returns full schema identity without issuing a coordinator checkpoint.
///
/// # Errors
/// Reports invalid compiled identifiers or content-reference construction failure.
pub fn coordinator_checkpoint17_schema_data() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(COORDINATOR_CHECKPOINT17_SCHEMA)?,
        version: 17,
        definition: canonical::content_ref(CONTRACT, "application/json")?,
        extensions: Default::default(),
    })
}

/// Compares the complete compiled coordinator witness definition without allocation.
///
/// # Errors
/// Refuses another identity/version, schema extensions or changed full definition.
pub fn authenticate_coordinator_checkpoint17_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let length = u64::try_from(CONTRACT.len()).map_err(|_| invalid())?;
    let reference = &schema.definition;
    if schema.id.as_str() != COORDINATOR_CHECKPOINT17_SCHEMA
        || schema.version != 17
        || !schema.extensions.is_empty()
        || reference.media_type != "application/json"
        || reference.length.get() != length
        || reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
    {
        return Err(invalid());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&length.to_be_bytes());
    hasher.update(CONTRACT);
    if hasher.finalize().to_hex().as_str() != reference.hash.digest.as_str() {
        return Err(invalid());
    }
    Ok(())
}

/// Names the exact fixed schema/ref/hash/result/formatter views before comparison.
pub fn coordinator_checkpoint17_schema_counter_scratch_data() -> usize {
    use std::mem::{size_of, size_of_val};
    size_of::<&SchemaRef>()
        + size_of::<&crucible_node_format::ContentRef>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of_val(&blake3::Hash::from_bytes([0; 32]).to_hex())
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    // These static immutable-format controls deliberately panic on invalid DATA.
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn full_checkpoint_definition_is_canonical_and_changed_axes_refuse() {
        let original = coordinator_checkpoint17_schema_data().unwrap();
        authenticate_coordinator_checkpoint17_schema_data(&original).unwrap();
        let value = canonical::parse_json(CONTRACT, CONTRACT.len()).unwrap();
        assert_eq!(canonical::canonical_json(&value).unwrap(), CONTRACT);
        for axis in 0..8 {
            let mut changed = original.clone();
            match axis {
                0 => changed.id = Id::new("foreign-checkpoint").unwrap(),
                1 => changed.version = 16,
                2 => changed.definition.hash.algorithm = "sha256".into(),
                3 => changed.definition.hash.domain = "other".into(),
                4 => changed.definition.hash.digest = "0".repeat(64),
                5 => {
                    changed.definition.length =
                        crucible_node_format::U64::new(changed.definition.length.get() + 1)
                }
                6 => changed.definition.media_type = COORDINATOR_CHECKPOINT17_MEDIA.into(),
                _ => {
                    changed
                        .extensions
                        .insert("extra".into(), serde_json::Value::Bool(true));
                }
            }
            assert!(authenticate_coordinator_checkpoint17_schema_data(&changed).is_err());
        }
    }
}
