//! Defines the original requested tree layout arithmetic as immutable DATA.

use crate::ProviderError;
use crate::profile::serialization_storage::RetainedProtocolMetadataFacts;
use std::mem::{align_of, size_of};

/// Counts pinned maximum internal-node layouts, including possible empty roots.
pub fn tree_storage_data(
    containers: usize,
    entries: usize,
    key_value_bytes: usize,
    entry_alignment: usize,
) -> Result<usize, ProviderError> {
    std::alloc::Layout::from_size_align(0, entry_alignment).map_err(|_| refused())?;
    let alignment = entry_alignment.max(align_of::<usize>());
    let node = sum(&[
        size_of::<usize>(),
        2 * size_of::<u16>(),
        12 * size_of::<usize>(),
        multiply(11, key_value_bytes)?,
        multiply(8, alignment - 1)?,
    ])?;
    multiply(add(containers, entries)?, node)
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("metadata requested backing storage")
}

/// Sums original metadata facts with the same tree/shared requested layouts.
///
/// This arithmetic authenticates no observation, Source or allocation grant.
///
/// # Errors
/// Refuses invalid layouts or the original checked backing-storage overflow.
pub fn requested_metadata_backing_storage_data(
    facts: &RetainedProtocolMetadataFacts,
) -> Result<usize, ProviderError> {
    sum(&[
        facts.string_capacity_bytes,
        facts.vector_capacity_bytes,
        facts.boxed_value_bytes,
        facts.shared_value_bytes,
        tree_storage_data(
            facts.tree_containers,
            facts.tree_entries,
            facts.maximum_tree_key_value_bytes,
            facts.maximum_tree_entry_alignment.max(1),
        )?,
        shared_header_storage_data(
            facts.shared_backing_views,
            facts.maximum_shared_value_alignment.max(1),
        )?,
    ])
}

/// Counts the original aligned shared header for each actual backing view.
///
/// # Errors
/// Refuses invalid alignment or checked requested-layout overflow.
pub fn shared_header_storage_data(
    views: usize,
    payload_alignment: usize,
) -> Result<usize, ProviderError> {
    std::alloc::Layout::from_size_align(0, payload_alignment).map_err(|_| refused())?;
    let alignment = payload_alignment.max(align_of::<usize>());
    let padded = add(2 * size_of::<usize>(), alignment - 1)? & !(alignment - 1);
    multiply(views, add(padded, alignment - 1)?)
}
