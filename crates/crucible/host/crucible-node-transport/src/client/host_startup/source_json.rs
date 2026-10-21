//! Exposes the existing closed raw-JSON storage counters as Source data only.
//!
//! The occurrence counter follows the actual raw Value parser/clone/canonical
//! owners. No Control snapshot DTO is constructed by that path. Typed Source
//! decoders keep their independent quotes; this data grants no allocation right.

use crate::retained_metadata::serialization_storage::{
    original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use crate::{
    ProviderError,
    reference_packet::service::complete_restore::transfer::{
        selected_issuer_decode_counter_scratch_data, selected_value_decode_storage_data,
    },
};

/// Counts the actual raw Value parse, clone and canonical occurrence phases.
///
/// Two independently owned Value trees cover parsing and cloned container
/// rebuilding, including empty object roots. Source callers independently add
/// their actual typed DTOs, custom serializers and retained enclosing roots.
///
/// # Errors
/// Refuses unbalanced or excessive nesting, a raw input beyond its actual
/// encoded bound or checked layout overflow. Strict JSON validation remains
/// independent. This function performs no allocation.
pub fn original_host_source_json_occurrence_storage_data(
    bytes: &[u8],
    maximum_encoded_bytes: usize,
) -> Result<usize, ProviderError> {
    if bytes.len() > maximum_encoded_bytes {
        return Err(ProviderError::ResourceExhausted(
            "original Source JSON encoded bound",
        ));
    }
    // This API's input ceiling is encoded bytes, not a decoded-allocation cap.
    // The caller admits the returned complete Value occurrence row separately.
    let raw = selected_value_decode_storage_data(bytes, usize::MAX)?;
    // The occurrence scanner does not name these canonical numeric and
    // stable-sort workspaces itself. Keep their independent audited layouts.
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
        sum.checked_add(value)
            .ok_or(ProviderError::ResourceExhausted(
                "original Source JSON storage extent overflow",
            ))
    })
}

/// Counts the fixed raw occurrence and future-extent counter layouts.
pub fn original_host_source_json_counter_scratch_data() -> usize {
    selected_issuer_decode_counter_scratch_data()
        + original_json_value_storage_extent_counter_scratch_data()
        + std::mem::size_of::<[usize; 3]>()
        + std::mem::size_of::<Result<usize, ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::MetadataObserver;
    use crate::retained_metadata::requested_storage::requested_metadata_backing_storage_data;
    use crucible_node_format::canonical;
    use serde_json::Value;
    use std::mem::size_of;

    #[test]
    fn occurrence_quote_covers_actual_parsed_and_cloned_value_owners()
    -> Result<(), Box<dyn std::error::Error>> {
        for raw in [
            b"{}".as_slice(),
            br#"{"empty":{},"array":[{},[],"x",1,2],"escaped":"\uD834\uDD1E"}"#,
            br#"["first","second",{},[],{"nested":{"leaf":true}}]"#,
        ] {
            let value: Value = serde_json::from_slice(raw)?;
            let cloned = value.clone();
            let canonical = canonical::canonical_json(&value)?;
            let mut owners = MetadataObserver::new();
            owners.observe(&value)?;
            owners.observe(&cloned)?;
            let actual = requested_metadata_backing_storage_data(&owners.finish())?
                + 2 * size_of::<Value>()
                + canonical.capacity();
            let quote = original_host_source_json_occurrence_storage_data(raw, raw.len())?;

            assert!(quote >= actual);
            assert_eq!(value, cloned);
            assert!(original_host_source_json_occurrence_storage_data(raw, raw.len() - 1).is_err());
        }
        assert!(original_host_source_json_occurrence_storage_data(b"{", 1).is_err());
        let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        assert!(
            original_host_source_json_occurrence_storage_data(deep.as_bytes(), deep.len()).is_err()
        );
        Ok(())
    }
}
