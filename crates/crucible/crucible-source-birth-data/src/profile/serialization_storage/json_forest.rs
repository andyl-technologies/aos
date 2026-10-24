//! Bounds separately owned JSON documents under one aggregate byte ceiling.
//!
//! A journal is a forest of independent roots, rather than one enclosing array.
//! Each root has its own parser and canonical output minimum. These quotes are
//! inert DATA; typed envelopes, journals, literal banks and Source admission
//! remain separate, independently priced owners.

use super::{
    OriginalJsonValueStorageExtentData, ProviderError,
    original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_population_data,
};
use std::mem::size_of;

/// Bounds independent JSON roots sharing one complete encoded-byte ceiling.
///
/// Each nonempty document contributes its own lexical rounding, root header
/// and canonical workspace/output minimum. The quote sums those independent
/// requests using the same defining layouts as the single-document producer.
/// It never multiplies the aggregate byte ceiling by the document population.
///
/// The byte ceiling must cover the actual input representation of every retained
/// root. A literal archive alone does not cover an unsent local request, an
/// unarchived response or separately retained copies. Callers price those owners
/// and typed DTOs independently and authenticate their real Source funding.
///
/// # Errors
/// Refuses an empty byte or document ceiling, unsupported compiled layouts or
/// checked arithmetic overflow. No document, output bank or permit is allocated.
pub fn original_json_value_storage_forest_data(
    maximum_encoded_bytes: usize,
    maximum_documents: usize,
) -> Result<OriginalJsonValueStorageExtentData, ProviderError> {
    if maximum_encoded_bytes == 0 || maximum_documents == 0 {
        return Err(exhausted());
    }

    // A nonempty JSON document consumes at least one byte. Summing the defining
    // per-document ceil(bytes / 2) + 1 bound retains each root's rounding term.
    let documents = maximum_documents.min(maximum_encoded_bytes);
    let values = add(add(maximum_encoded_bytes, documents)? / 2, documents)?;
    let members = add(maximum_encoded_bytes / 5, documents)?;
    let mut result =
        original_json_value_storage_population_data(values, members, maximum_encoded_bytes)?;

    // The population quote includes one root's fixed costs. A separate defining
    // one-value quote conservatively pays every additional root's minimum; its
    // positive value terms also remain charged, without changing event bounds.
    let root = original_json_value_storage_population_data(1, 0, 0)?;
    let additional_roots = documents - 1;
    result.value_dom_requested_bytes = add(
        result.value_dom_requested_bytes,
        mul(additional_roots, root.value_dom_requested_bytes)?,
    )?;
    result.canonical_work_requested_bytes = add(
        result.canonical_work_requested_bytes,
        mul(additional_roots, root.canonical_work_requested_bytes)?,
    )?;
    result.canonical_output_requested_bytes = add(
        result.canonical_output_requested_bytes,
        mul(additional_roots, root.canonical_output_requested_bytes)?,
    )?;
    result.maximum_canonical_encoded_bytes = add(
        result.maximum_canonical_encoded_bytes,
        mul(additional_roots, root.maximum_canonical_encoded_bytes)?,
    )?;
    result.declared_counter_scratch_bytes =
        original_json_value_storage_forest_counter_scratch_data();

    result.canonical_pass_requested_bytes()?;
    Ok(result)
}

/// Names simultaneous forest/population result headers and checked counters.
pub const fn original_json_value_storage_forest_counter_scratch_data() -> usize {
    original_json_value_storage_extent_counter_scratch_data()
        + 2 * size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + 8 * size_of::<usize>()
        + size_of::<Result<usize, ProviderError>>()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("closed raw JSON forest storage")
}
