//! Bounds actual immutable raw JSON occurrences before the strict Value parser.
//!
//! This lexical census grants no parse or native authority. If it cannot price
//! a malformed prefix, its caller keeps the original whole-byte worst case.
//! The unchanged strict parser remains responsible for complete JSON validity.

use super::*;
use crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData;

#[derive(Default)]
struct Occurrences {
    values: usize,
    object_roots: usize,
    members: usize,
    string_bytes: usize,
}

fn occurrences(bytes: &[u8]) -> Option<Occurrences> {
    let mut counts = Occurrences::default();
    let mut stack = [0u8; 64];
    let mut depth = 0usize;
    let mut cursor = 0usize;
    while let Some(&byte) = bytes.get(cursor) {
        if b" \t\r\n,:".contains(&byte) {
            cursor += 1;
            continue;
        }
        match byte {
            b'{' | b'[' => {
                *stack.get_mut(depth)? = byte;
                depth += 1;
                counts.values = counts.values.checked_add(1)?;
                if byte == b'{' {
                    counts.object_roots = counts.object_roots.checked_add(1)?;
                }
                cursor += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if stack[depth] != if byte == b'}' { b'{' } else { b'[' } {
                    return None;
                }
                cursor += 1;
            }
            b'"' => {
                cursor += 1;
                let start = cursor;
                loop {
                    let next = *bytes.get(cursor)?;
                    cursor += 1;
                    if next == b'\\' {
                        bytes.get(cursor)?;
                        cursor += 1;
                    } else if next == b'"' {
                        break;
                    }
                }
                counts.string_bytes = counts.string_bytes.checked_add(cursor - start - 1)?;
                counts.values = counts.values.checked_add(1)?;
                let mut next = cursor;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) == Some(&b':') {
                    counts.members = counts.members.checked_add(1)?;
                }
            }
            _ => {
                let start = cursor;
                while bytes
                    .get(cursor)
                    .is_some_and(|b| !b" \t\r\n,:]}{[\"".contains(b))
                {
                    cursor += 1;
                }
                if cursor == start {
                    return None;
                }
                counts.values = counts.values.checked_add(1)?;
            }
        }
    }
    (depth == 0 && counts.values > 0).then_some(counts)
}

pub(super) fn extent(bytes: &[u8]) -> Result<OriginalJsonValueStorageExtentData, ProviderError> {
    let Some(counts) = occurrences(bytes) else {
        // No prefix is treated as zero. Preserve the generic bound, and let the
        // original strict parser produce its original error when funded.
        return crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(bytes.len());
    };
    let values = counts.values;
    let members = counts.members;
    let maps = sum(&[members, counts.object_roots])?;
    let strings = sum(&[mul(8, counts.string_bytes)?, mul(32, values)?])?;
    // Each container and each possible array child gets an independent growth
    // budget. Object entries/empty roots are additionally named tree owners.
    let arrays = mul(mul(8, values)?, std::mem::size_of::<serde_json::Value>())?;
    let value_node = crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data::<String, serde_json::Value>()?;
    let sort_node = crate::retained_metadata::serialization_storage::original_serialization_tree_node_requested_bytes_data::<Vec<u16>, (&str, &serde_json::Value)>()?;
    let sort_slot = std::mem::size_of::<(Vec<u16>, (&str, &serde_json::Value))>();
    if std::mem::size_of::<usize>() != 8 || mul(5, sort_slot)? > sort_node {
        return Err(exhausted());
    }
    let dom = sum(&[
        strings,
        arrays,
        mul(mul(2, maps)?, value_node)?,
        std::mem::size_of::<serde_json::Value>(),
    ])?;
    let encoded = sum(&[mul(6, counts.string_bytes)?, mul(36, values)?])?;
    let work = sum(&[
        mul(24, counts.string_bytes)?,
        mul(264, values)?,
        mul(8, counts.string_bytes)?,
        mul(16, members)?,
        mul(mul(2, members)?, sort_node)?,
        mul(std::mem::size_of::<[u8; 132]>(), values)?,
        std::mem::size_of::<[u8; 4096]>(),
    ])?;
    Ok(OriginalJsonValueStorageExtentData {
        maximum_value_nodes: values,
        maximum_object_members: members,
        maximum_decoded_string_bytes: counts.string_bytes,
        value_dom_requested_bytes: dom,
        canonical_work_requested_bytes: work,
        canonical_output_requested_bytes: sum(&[mul(4, encoded)?, 256])?,
        maximum_canonical_encoded_bytes: encoded,
        declared_counter_scratch_bytes: counter_scratch_data(),
    })
}

pub(super) fn counter_scratch_data() -> usize {
    std::mem::size_of::<[u8; 64]>()
        + 2 * std::mem::size_of::<Occurrences>()
        + std::mem::size_of::<Option<Occurrences>>()
        + 2 * std::mem::size_of::<OriginalJsonValueStorageExtentData>()
        + 16 * std::mem::size_of::<usize>()
        + std::mem::size_of::<[usize; 8]>()
        + std::mem::size_of::<std::slice::Iter<'static, usize>>()
        + std::mem::size_of::<&'static [usize]>()
        + std::mem::size_of::<Option<&'static u8>>()
        + std::mem::size_of::<Option<usize>>()
        + std::mem::size_of::<Result<usize, ProviderError>>()
        + std::mem::size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + std::mem::size_of::<std::alloc::Layout>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
}
