//! Bounds raw JSON Value ownership using lexical event counts and real layouts.
//!
//! The byte extent bounds JSON lexical occurrences, decoded UTF-8 source bytes
//! and punctuation independently. Requested storage then follows the compiled
//! String/Value/Vec/BTree layouts used by the actual parser and canonical writer.
//! This is deliberately conservative data, not a raw-byte-to-heap conversion or
//! an allocation/source permit. Typed DTOs, custom Serialize formatters, original
//! literal banks, error custody and caller-owned roots are separate terms.

use super::*;

/// Reports named upper bounds for one bounded raw JSON Value family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalJsonValueStorageExtentData {
    /// Counts JSON values and independently owned object-key strings.
    pub maximum_value_nodes: usize,
    /// Counts original object entries across all nested maps.
    pub maximum_object_members: usize,
    /// Bounds the sum of decoded UTF-8 lengths, including object keys.
    pub maximum_decoded_string_bytes: usize,
    /// Covers one fresh parser/clone Value tree with growable child banks.
    pub value_dom_requested_bytes: usize,
    /// Covers canonical key sorting, quoted string work and numeric formatting.
    pub canonical_work_requested_bytes: usize,
    /// Covers cumulative requested growth of the final canonical output bank.
    pub canonical_output_requested_bytes: usize,
    /// Bounds actual JCS output independently of its bank-growth requests.
    pub maximum_canonical_encoded_bytes: usize,
    /// Names only explicit counter/layout result headers, not compiler frames.
    pub declared_counter_scratch_bytes: usize,
}

impl OriginalJsonValueStorageExtentData {
    /// Sums one independent Value, canonical-work, output and fixed-view pass.
    ///
    /// # Errors
    /// Refuses checked requested-storage overflow.
    pub fn canonical_pass_requested_bytes(self) -> Result<usize, ProviderError> {
        sum(&[
            self.value_dom_requested_bytes,
            self.canonical_work_requested_bytes,
            self.canonical_output_requested_bytes,
            self.declared_counter_scratch_bytes,
        ])
    }
}

/// Bounds arbitrary Value fields under a genuinely selected raw JSON ceiling.
///
/// A completed nonempty array needs one delimiter per additional child; object
/// key/value pairs need at least `"":0,` (five bytes). This bounds logical events
/// before applying any private layout. Escapes cannot increase decoded UTF-8
/// length. The existing CNP parser independently enforces strict grammar/depth.
/// Malformed input may build a prefix, which has no larger occurrence budget.
///
/// No typed request/response validation, callback or custom formatter is run.
/// Caller limits are DATA until the actual original source/grant authenticates
/// their use; this function creates no Connection, DTO or native owner.
///
/// # Errors
/// Refuses zero extent, unsupported compiled tree layout, or checked arithmetic
/// overflow while bounding JSON values, strings, containers and canonical work.
pub fn original_json_value_storage_extent_data(
    maximum_encoded_bytes: usize,
) -> Result<OriginalJsonValueStorageExtentData, ProviderError> {
    if maximum_encoded_bytes == 0 {
        return Err(exhausted());
    }
    let bytes = maximum_encoded_bytes;
    let values = add(add(bytes, 1)? / 2, 1)?;
    let members = add(bytes / 5, 1)?;
    original_json_value_storage_population_data(values, members, bytes)
}

/// Applies the same defining layouts to separately established JSON events.
///
/// `values` includes object-key strings and every value/container, `members`
/// counts object entries, and `text` bounds total decoded key/string UTF8 bytes.
/// Callers must derive these occurrence bounds before allocating; these scalar
/// facts do not authenticate a body, actual parser profile or constructor grant.
/// The arithmetic and requested layouts match the encoded-extent producer.
///
/// # Errors
/// Refuses an empty population, unsupported compiled tree layout or overflow.
pub(crate) fn original_json_value_storage_population_data(
    values: usize,
    members: usize,
    text: usize,
) -> Result<OriginalJsonValueStorageExtentData, ProviderError> {
    if values == 0 || members > values {
        return Err(exhausted());
    }
    let value_node =
        super::map_node_bytes_for::<String, serde_json::Value>().map_err(|_| exhausted())?;
    let sort_node = super::map_node_bytes_for::<Vec<u16>, (&str, &serde_json::Value)>()
        .map_err(|_| exhausted())?;

    // The pinned parser uses Vec::new/push for arrays and serde's owned String
    // decoder. Sum geometric requests (not just final lengths), including the
    // nonzero minimum per bank. Empty decoded maps allocate no fresh BTree root;
    // at most one leaf/internal requested node per entry is needed, doubled here
    // to cover roots and conservative insertion growth independently.
    let strings = add(mul(8, text)?, mul(32, values)?)?;
    let arrays = mul(mul(8, values)?, std::mem::size_of::<serde_json::Value>())?;
    let maps = mul(mul(2, members)?, value_node)?;
    let dom = sum(&[
        strings,
        arrays,
        maps,
        std::mem::size_of::<serde_json::Value>(),
    ])?;

    // The pinned ryu-js finite binary64 output fits 32 ASCII bytes; integer
    // output fits 20. Its formatter owns a distinct 132-byte workspace, charged
    // below independently of output width. Strings expand by at most six bytes
    // per decoded UTF-8 byte.
    let encoded = add(mul(6, text)?, mul(36, values)?)?;
    let quoted_strings = add(mul(24, text)?, mul(264, values)?)?;
    let utf16 = add(mul(8, text)?, mul(16, members)?)?;
    // On the selected 64-bit std layout, one full B=6 sort node is wider
    // than five input entries. One node per member covers the final BTree;
    // the second covers cumulative input-Vec growth (four entries/member)
    // plus stable-sort heap scratch (at most one entry/member). The pinned
    // stable sort also has an explicit 4 KiB workspace, separate from heap.
    // Collection finishes sorting before recursively encoding child values,
    // so these fixed sort workspaces do not overlap across nested objects.
    let sort_entry = std::mem::size_of::<(Vec<u16>, (&str, &serde_json::Value))>();
    if std::mem::size_of::<usize>() != 8 || mul(5, sort_entry)? > sort_node {
        return Err(exhausted());
    }
    let sort_nodes = mul(mul(2, members)?, sort_node)?;
    let numbers = mul(std::mem::size_of::<[u8; 132]>(), values)?;
    let sort_workspace = std::mem::size_of::<[u8; 4096]>();
    let canonical_work = sum(&[quoted_strings, utf16, sort_nodes, numbers, sort_workspace])?;
    let output = add(mul(4, encoded)?, 256)?;
    let result = OriginalJsonValueStorageExtentData {
        maximum_value_nodes: values,
        maximum_object_members: members,
        maximum_decoded_string_bytes: text,
        value_dom_requested_bytes: dom,
        canonical_work_requested_bytes: canonical_work,
        canonical_output_requested_bytes: output,
        maximum_canonical_encoded_bytes: encoded,
        declared_counter_scratch_bytes: original_json_value_storage_extent_counter_scratch_data(),
    };
    result.canonical_pass_requested_bytes()?;
    Ok(result)
}

/// Names the actual fixed lexical-bound, layout and result views.
pub const fn original_json_value_storage_extent_counter_scratch_data() -> usize {
    // Includes result/copy, direct counters, nested node-layout counters and
    // the largest explicit sum array/iterator. This is not a compiler frame bound.
    2 * std::mem::size_of::<OriginalJsonValueStorageExtentData>()
        + 26 * std::mem::size_of::<usize>()
        + std::mem::size_of::<std::alloc::Layout>()
        + std::mem::size_of::<[usize; 5]>()
        + std::mem::size_of::<&[usize]>()
        + std::mem::size_of::<std::slice::Iter<'static, usize>>()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, term| add(sum, *term))
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("closed raw JSON Value storage")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::{
        MetadataObserver, requested_storage::requested_metadata_backing_storage_data,
    };
    use crucible_node_format::canonical;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn logical_values(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Array(values) => {
                1 + values.iter().map(logical_values).sum::<usize>()
            }
            serde_json::Value::Object(values) => {
                1 + values.len() + values.values().map(logical_values).sum::<usize>()
            }
            _ => 1,
        }
    }

    fn verify(bytes: &[u8]) -> TestResult {
        let value = canonical::parse_json(bytes, bytes.len())?;
        let mut observer = MetadataObserver::new();
        observer.observe(&value)?;
        let facts = observer.finish();
        let bound = original_json_value_storage_extent_data(bytes.len())?;
        let backing = requested_metadata_backing_storage_data(&facts)?;
        let encoded = canonical::canonical_json(&value)?;

        assert!(backing <= bound.value_dom_requested_bytes);
        assert!(encoded.len() <= bound.maximum_canonical_encoded_bytes);
        assert!(logical_values(&value) <= bound.maximum_value_nodes);
        assert!(facts.tree_entries <= bound.maximum_object_members);
        assert!(facts.string_capacity_bytes <= bound.value_dom_requested_bytes);
        Ok(())
    }

    #[test]
    fn real_dense_arrays_maps_escapes_numbers_and_empty_containers_fit() -> TestResult {
        for input in [
            b"0".as_slice(),
            b"[]",
            b"{}",
            b"[0,0,0,0,0,0,0,0]",
            br#"{"":0,"a":[],"b":{},"c":["",0],"d":1.0}"#,
            br#"{"quoted":"\u0000\n\"\\\uD834\uDD1E","number":1e+308}"#,
            br#"[[[[[[[[]]]]]]]]"#,
        ] {
            verify(input)?;
        }
        Ok(())
    }

    #[test]
    fn zero_and_checked_overflow_refuse_without_allocating_a_shape() {
        assert!(original_json_value_storage_extent_data(0).is_err());
        assert!(original_json_value_storage_extent_data(usize::MAX).is_err());
        assert!(original_json_value_storage_extent_data(usize::MAX / 32).is_err());
    }
}
