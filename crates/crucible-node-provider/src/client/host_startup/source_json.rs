//! Exposes the existing closed raw-JSON storage counters as Source data only.
//!
//! The occurrence counter deliberately retains its selected-Control layout
//! ceiling. Its result bounds only the raw Value parser/clone/canonical phase;
//! it is not an arbitrary Source typed-decoder quote or an allocation grant.

use crate::retained_metadata::serialization_storage::{
    original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use crate::{
    ProviderError,
    reference_packet::service::complete_restore::transfer::{
        selected_issuer_decode_counter_scratch_data, selected_issuer_decode_storage_data,
    },
};

/// Counts the actual raw Value parse, clone and canonical occurrence phases.
///
/// The selected-Control typed-layout ceiling is conservatively included. Source
/// callers add their own typed DTOs, custom serializers and retained roots.
///
/// # Errors
/// Refuses malformed/deep JSON, a raw input beyond its actual encoded bound or
/// checked layout arithmetic overflow. This function performs no allocation.
pub fn original_host_source_json_occurrence_storage_data(
    bytes: &[u8],
    maximum_encoded_bytes: usize,
) -> Result<usize, ProviderError> {
    let raw = selected_issuer_decode_storage_data(
        bytes,
        std::mem::size_of::<serde_json::Value>(),
        maximum_encoded_bytes,
    )?;
    // The legacy occurrence scanner does not name these canonical numeric and
    // stable-sort workspaces itself. Add the exact separately audited layouts;
    // no credit is inferred from its unused selected-Control typed pool.
    raw.checked_add(132)
        .and_then(|bytes| bytes.checked_add(4096))
        .ok_or(ProviderError::ResourceExhausted(
            "original Source JSON workspace overflow",
        ))
}

/// Counts a closed future raw Value/parser/canonical phase from its encoded cap.
///
/// This is the audited lexical/layout bound, not a byte-to-heap multiplier.
/// Source typed DTO and custom-formatter construction remain independent.
///
/// # Errors
/// Refuses zero/unsupported encoded bounds or checked layout overflow.
pub fn original_host_source_json_extent_storage_data(
    maximum_encoded_bytes: usize,
) -> Result<usize, ProviderError> {
    let data = original_json_value_storage_extent_data(maximum_encoded_bytes)?;
    [
        data.value_dom_requested_bytes,
        data.canonical_work_requested_bytes,
        data.canonical_output_requested_bytes,
    ]
    .into_iter()
    .try_fold(0usize, |sum, value| {
        sum.checked_add(value).ok_or_else(|| {
            ProviderError::ResourceExhausted("original Source JSON storage extent overflow")
        })
    })
}

/// Counts the fixed raw occurrence and future-extent counter layouts.
pub fn original_host_source_json_counter_scratch_data() -> usize {
    selected_issuer_decode_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + std::mem::size_of::<[usize; 3]>()
}
