//! Defines the original requested tree layout arithmetic as immutable DATA.

use crate::ProviderError;
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
