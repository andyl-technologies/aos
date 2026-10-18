//! Quotes the actual retained World manifest without invoking its validators.
//!
//! Historical World authentication separately validates this typed manifest and
//! canonicalizes it against the request's full reference. That object is not an
//! activation artifact or an Envelope body. The closed projection visits its
//! actual fields without formatting U64 or cloning any owner, string or Value.

use crate::ProviderError;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
    original_serialization_counter_scratch_data,
};
use crucible_node_contract::{ActivationManifest, ContentRef, HashRef, Id, PreparedOwner, U64};
use std::mem::size_of;

/// Describes the independent canonical and validation-clone work for one World.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalWorldManifestWindow17 {
    /// Bounds transient canonical backing and adjacent validation-key clones.
    pub(crate) requested_storage_bytes: usize,
    /// Names fixed projection and borrowed validation-control layouts.
    pub(crate) declared_counter_scratch_bytes: usize,
}

/// Projects the exact retained manifest before any native-private validation.
///
/// The real validator clones two adjacent owner IDs or two adjacent hash keys
/// at a time. Those clones do not overlap between comparisons. The canonical
/// window is added conservatively, so no early-drop assumption supplies credit.
/// No typed manifest reparse or Vec<PreparedOwner> allocation happens here or in
/// that validator: the completed native cache already owns the actual manifest.
///
/// # Errors
/// Refuses checked overflow or geometry beyond the independently supplied bound.
pub(crate) fn world_manifest_window_data(
    manifest: &ActivationManifest,
    maximum: usize,
) -> Result<HistoricalWorldManifestWindow17, ProviderError> {
    let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
    project_manifest_data(&mut projection, manifest)?;
    let row = projection.finish(maximum)?;
    let clone_peak = validation_clone_peak_data(manifest)?;
    let requested_storage_bytes = sum(&[
        row.dom_and_canonical_scratch_bytes,
        row.projected_parser_requested_bytes,
        row.canonical_output_requested_bytes,
        row.serializer_temporary_requested_bytes,
        clone_peak,
    ])?;
    let declared_counter_scratch_bytes = counter_scratch_data();
    if sum(&[requested_storage_bytes, declared_counter_scratch_bytes])? > maximum {
        return Err(exhausted());
    }
    Ok(HistoricalWorldManifestWindow17 {
        requested_storage_bytes,
        declared_counter_scratch_bytes,
    })
}

fn project_manifest_data(
    projection: &mut OriginalSerializationStorageProjection,
    manifest: &ActivationManifest,
) -> Result<(), ProviderError> {
    let ActivationManifest {
        schema_version,
        transaction_id,
        activation_id,
        world_generation,
        gate_id,
        world_binding_hash,
        owners,
        coordinator_state_ref,
        extensions,
    } = manifest;
    projection.add_object()?;
    projection.add_field("schema_version")?;
    projection.add_value(schema_version)?;
    projection.add_field("transaction_id")?;
    projection.add_value(transaction_id)?;
    projection.add_field("activation_id")?;
    projection.add_value(activation_id)?;
    projection.add_field("world_generation")?;
    project_u64_data(projection, *world_generation)?;
    projection.add_field("gate_id")?;
    projection.add_value(gate_id)?;
    projection.add_field("world_binding_hash")?;
    project_hash_data(projection, world_binding_hash)?;

    projection.add_field("owners")?;
    projection.add_array_extent(owners.len())?;
    for owner in owners {
        project_owner_data(projection, owner)?;
    }

    projection.add_field("coordinator_state_ref")?;
    project_content_data(projection, coordinator_state_ref)?;
    projection.add_field("extensions")?;
    // These are already-owned JSON children, not typed U64/Bytes formatters.
    projection.add_value(extensions)
}

fn project_owner_data(
    projection: &mut OriginalSerializationStorageProjection,
    owner: &PreparedOwner,
) -> Result<(), ProviderError> {
    let PreparedOwner {
        owner_id,
        incarnation_id,
        owner_generation,
        prepared_token,
        binding_hashes,
        ready_receipt,
        extensions,
    } = owner;
    projection.add_object()?;
    projection.add_field("owner_id")?;
    projection.add_value(owner_id)?;
    projection.add_field("incarnation_id")?;
    projection.add_value(incarnation_id)?;
    projection.add_field("owner_generation")?;
    project_u64_data(projection, *owner_generation)?;
    projection.add_field("prepared_token")?;
    projection.add_value(prepared_token)?;

    projection.add_field("binding_hashes")?;
    projection.add_array_extent(binding_hashes.len())?;
    for hash in binding_hashes {
        project_hash_data(projection, hash)?;
    }

    projection.add_field("ready_receipt")?;
    project_content_data(projection, ready_receipt)?;
    projection.add_field("extensions")?;
    projection.add_value(extensions)
}

fn project_hash_data(
    projection: &mut OriginalSerializationStorageProjection,
    hash: &HashRef,
) -> Result<(), ProviderError> {
    let HashRef {
        algorithm,
        domain,
        digest,
    } = hash;
    projection.add_object()?;
    projection.add_field("algorithm")?;
    projection.add_string(algorithm)?;
    projection.add_field("domain")?;
    projection.add_string(domain)?;
    projection.add_field("digest")?;
    projection.add_string(digest)
}

fn project_content_data(
    projection: &mut OriginalSerializationStorageProjection,
    reference: &ContentRef,
) -> Result<(), ProviderError> {
    let ContentRef {
        hash,
        length,
        media_type,
    } = reference;
    projection.add_object()?;
    projection.add_field("hash")?;
    project_hash_data(projection, hash)?;
    projection.add_field("length")?;
    project_u64_data(projection, *length)?;
    projection.add_field("media_type")?;
    projection.add_string(media_type)
}

fn project_u64_data(
    projection: &mut OriginalSerializationStorageProjection,
    value: U64,
) -> Result<(), ProviderError> {
    let digits = value
        .get()
        .checked_ilog10()
        .map_or(1, |digits| digits as usize + 1);
    projection.add_unescaped_ascii_extent(digits)
}

fn validation_clone_peak_data(manifest: &ActivationManifest) -> Result<usize, ProviderError> {
    let mut maximum = 0;
    for pair in manifest.owners.windows(2) {
        maximum = maximum.max(sum(&[
            pair[0].owner_id.as_str().len(),
            pair[1].owner_id.as_str().len(),
        ])?);
    }
    for owner in &manifest.owners {
        for pair in owner.binding_hashes.windows(2) {
            maximum = maximum.max(sum(&[
                pair[0].domain.len(),
                pair[0].digest.len(),
                pair[1].domain.len(),
                pair[1].digest.len(),
            ])?);
        }
    }
    Ok(maximum)
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<HistoricalWorldManifestWindow17>()
        + size_of::<Result<HistoricalWorldManifestWindow17, ProviderError>>()
        + size_of::<OriginalSerializationStorageProjection>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<&ActivationManifest>()
        + size_of::<&PreparedOwner>()
        + size_of::<&ContentRef>()
        + size_of::<&HashRef>()
        + size_of::<std::slice::Iter<'static, PreparedOwner>>()
        + size_of::<std::slice::Iter<'static, HashRef>>()
        + size_of::<std::slice::Windows<'static, PreparedOwner>>()
        + size_of::<std::slice::Windows<'static, HashRef>>()
        + size_of::<Id>() * 2
        + size_of::<(String, String)>() * 2
        + size_of::<[usize; 5]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<U64>()
        + size_of::<usize>() * 5
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + original_serialization_counter_scratch_data()
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, term| {
        total.checked_add(*term).ok_or_else(exhausted)
    })
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native17 historical World manifest construction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::canonical;
    use serde_json::json;

    fn fixture() -> ActivationManifest {
        let hash = json!({
            "algorithm":"blake3-256", "domain":"cnp.node-binding.v1",
            "digest":"0".repeat(64)
        });
        let mut blob_hash = hash.clone();
        blob_hash["domain"] = json!("cnp.blob.v1");
        let mut world_hash = hash.clone();
        world_hash["domain"] = json!("cnp.world-binding.v1");
        let reference = json!({
            "hash":blob_hash, "length":"18446744073709551615",
            "media_type":"application/json"
        });
        serde_json::from_value(json!({
            "schema_version":1, "transaction_id":"transaction", "activation_id":"activation",
            "world_generation":"18446744073709551615", "gate_id":"gate",
            "world_binding_hash":world_hash,
            "owners":[{
                "owner_id":"owner", "incarnation_id":"incarnation",
                "owner_generation":"18446744073709551615", "prepared_token":"prepared",
                "binding_hashes":[hash], "ready_receipt":reference.clone(),
                "extensions":{}
            }],
            "coordinator_state_ref":reference, "extensions":{}
        }))
        .unwrap()
    }

    #[test]
    fn actual_canonical_bytes_fit_the_closed_manifest_projection() {
        let manifest = fixture();
        let mut projection = OriginalSerializationStorageProjection::new(usize::MAX).unwrap();
        project_manifest_data(&mut projection, &manifest).unwrap();
        let projected = projection.finish(usize::MAX).unwrap();

        let value = serde_json::to_value(&manifest).unwrap();
        let canonical = canonical::canonical_json(&value).unwrap();
        assert!(canonical.len() <= projected.maximum_encoded_bytes);
        assert_eq!(projected.serializer_temporary_requested_bytes, 20);
    }

    #[test]
    fn exact_manifest_window_passes_and_one_byte_short_refuses() {
        let manifest = fixture();
        let row = world_manifest_window_data(&manifest, usize::MAX).unwrap();
        let exact = row.requested_storage_bytes + row.declared_counter_scratch_bytes;

        assert_eq!(world_manifest_window_data(&manifest, exact).unwrap(), row);
        assert!(world_manifest_window_data(&manifest, exact - 1).is_err());
    }

    #[test]
    fn retained_manifest_extensions_are_independent_of_small_world_envelopes() {
        let mut manifest = fixture();
        let before = world_manifest_window_data(&manifest, usize::MAX).unwrap();
        manifest.owners[0]
            .extensions
            .insert("retained".to_owned(), json!(["x".repeat(20_000)]));
        let after = world_manifest_window_data(&manifest, usize::MAX).unwrap();

        assert!(after.requested_storage_bytes > before.requested_storage_bytes);
        assert!(after.requested_storage_bytes > 20_000);
    }
}
