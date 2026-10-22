//! Prices the actual strict Value parser without DTO reparses or native effects.

use super::*;
use crate::reference_packet::continuation_models::serde_partials;
use crate::reference_packet::service::native_startup::{
    raw_json_extent_counter_scratch_data, raw_json_extent_data,
};
use crate::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_data,
    original_json_value_storage_population_data,
};
use crate::retained_metadata::{BootstrapBodyMetadataProfileData, MetadataObserver};
use crucible_node_format::canonical;

/// Derives one actual strict-body row from its immutable lexical populations.
///
/// # Errors
/// Refuses unsupported layouts, invalid populations, overflow or short restriction.
pub(in super::super) fn actual_data(
    raw: &[u8],
    maximum: usize,
) -> Result<([usize; 3], BootstrapBodyMetadataProfileData), ProviderError> {
    let raw = raw_json_extent_data(raw)?;
    // Use the same population-to-layout function as the prospective producer.
    // Empty strict maps allocate no BTree root. Malformed grammar still leaves
    // its independently counted prefix within these lexical populations.
    let extent = original_json_value_storage_population_data(
        raw.maximum_value_nodes,
        raw.maximum_object_members,
        raw.maximum_decoded_string_bytes,
    )?;
    population_data(extent, maximum)
}

/// Bounds the same parser before any original Hello body exists.
///
/// # Errors
/// Refuses zero/unsupported extents, overflow or short independent restriction.
pub(super) fn maximum_data(bytes: usize, maximum: usize) -> Result<[usize; 3], ProviderError> {
    population_data(original_json_value_storage_extent_data(bytes)?, maximum).map(|(row, _)| row)
}

/// Prices strict parser populations independently of their original role.
///
/// # Errors
/// Refuses unsupported layouts, arithmetic overflow or a short restriction.
pub(in super::super) fn population_data(
    extent: OriginalJsonValueStorageExtentData,
    maximum: usize,
) -> Result<([usize; 3], BootstrapBodyMetadataProfileData), ProviderError> {
    let lookup = canonical::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.ok_or_else(exhausted)?;
    let profile = BootstrapBodyMetadataProfileData::from_strict_value_populations_data(
        extent.maximum_value_nodes,
        extent.maximum_object_members,
    )?;
    // Strict Invalid errors own only their closed reason plus one usize cursor.
    // The actual formatted String may grow; reserve its cumulative requests.
    let diagnostic = canonical::STRICT_JSON_DIAGNOSTIC_TEXT_BYTES_DATA
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(8))
        .ok_or_else(exhausted)?;
    let retained = extent
        .value_dom_requested_bytes
        .checked_add(diagnostic)
        .ok_or_else(exhausted)?;
    // serde only decodes exact quoted tokens into String here. Its errors are
    // converted to fixed category/line/column DATA before the ErrorImpl drops.
    // The actual pinned ErrorImpl allocation is temporary, separately priced.
    let transient = retained
        .checked_add(serde_partials::diagnostic_error_impl_allocation_upper_bytes_data())
        .and_then(|bytes| bytes.checked_add(lookup[1]))
        .and_then(|bytes| {
            bytes.checked_add(size_of::<Value>() + size_of::<Result<Value, ContractError>>())
        })
        .ok_or_else(exhausted)?;
    let scratch = profile
        .walk_scratch_data()?
        .checked_add(counter_scratch_data())
        .and_then(|bytes| bytes.checked_add(lookup[2]))
        .and_then(|bytes| bytes.checked_add(canonical::json_parse_counter_scratch_bytes_data()))
        .ok_or_else(exhausted)?;
    let row = [retained, transient, scratch];
    let peak = row.into_iter().try_fold(0usize, |sum, value| {
        sum.checked_add(value).ok_or_else(exhausted)
    })?;
    if peak > maximum {
        return Err(exhausted());
    }
    Ok((row, profile))
}

/// Names actual lexical, parser, profile and checked-layout controls.
pub(super) fn counter_scratch_data() -> usize {
    raw_json_extent_counter_scratch_data()
        + crate::protocol_snapshot::serde_decode_layout::text_counter_scratch_data()
        + size_of::<OriginalJsonValueStorageExtentData>() * 2
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + size_of::<BootstrapBodyMetadataProfileData>() * 2
        + size_of::<Result<BootstrapBodyMetadataProfileData, ProviderError>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<[usize; 3]>() * 3
        + size_of::<Option<[usize; 3]>>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Result<([usize; 3], BootstrapBodyMetadataProfileData), ProviderError>>()
        + size_of::<[u8; 20]>()
        + size_of::<[usize; 8]>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<std::array::IntoIter<usize, 3>>()
}
