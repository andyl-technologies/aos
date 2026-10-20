//! Combines actual metadata facts with checked source-pinned requested layouts.
//!
//! The BTree bound follows Rust 1.98.1's B=6 node (11 entries, 12 edges).
//! Shared headers follow the two-usize Rc/Arc counts and actual payload
//! alignment. These are requested-layout data, not an allocator measurement,
//! Source allowance, physical peak, or permission to clone or decode anything.
//! Equal values and independent views receive no alias discount here; a genuine
//! unique-root walker must establish any earlier deduplication locally.

use super::RetainedProtocolMetadataFacts;
use crate::ProviderError;
use std::mem::{align_of, size_of};

/// Sums actual backing facts with separate tree-node and shared-header layouts.
///
/// Facts originate in the caller's guarded exhaustive typed walk. The helper
/// itself authenticates no source or live actor. It excludes outer inline
/// headers, parser/canonical copies, traversal/compiler stack, and physical
/// allocator overhead; those remain independent simultaneous terms.
pub(crate) fn requested_metadata_backing_storage_data(
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

pub(crate) use crucible_source_birth_data::profile::requested_storage::tree_storage_data;

/// Counts one actual aligned Rc/Arc header per admitted shared backing view.
pub(crate) fn shared_header_storage_data(
    views: usize,
    payload_alignment: usize,
) -> Result<usize, ProviderError> {
    std::alloc::Layout::from_size_align(0, payload_alignment).map_err(|_| refused())?;
    let alignment = payload_alignment.max(align_of::<usize>());
    let padded = add(2 * size_of::<usize>(), alignment - 1)? & !(alignment - 1);
    multiply(views, add(padded, alignment - 1)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_zero_sized_aligned_tree_keys_and_shared_payloads_keep_alignment() -> TestResult {
        #[repr(align(64))]
        struct Aligned;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.tree::<Aligned, Aligned>(0)?;
        observer.shared_value(&Aligned)?;
        let facts = observer.finish();
        assert_eq!(facts.maximum_tree_entry_alignment, align_of::<Aligned>());
        assert_eq!(facts.maximum_shared_value_alignment, align_of::<Aligned>());
        assert_eq!(facts.maximum_tree_key_value_bytes, 0);
        assert_eq!(facts.shared_value_bytes, 0);
        assert!(
            requested_metadata_backing_storage_data(&facts)?
                > 2 * size_of::<usize>() + size_of::<usize>()
        );
        Ok(())
    }

    #[test]
    fn independent_views_are_added_and_invalid_or_overflowing_layouts_refuse() -> TestResult {
        let facts = RetainedProtocolMetadataFacts {
            string_capacity_bytes: 19,
            vector_capacity_bytes: 37,
            shared_value_bytes: 64,
            shared_backing_views: 2,
            maximum_shared_value_alignment: 64,
            ..Default::default()
        };
        let headers = shared_header_storage_data(2, 64)?;
        assert_eq!(
            requested_metadata_backing_storage_data(&facts)?,
            19 + 37 + 64 + headers
        );
        assert_eq!(
            requested_metadata_backing_storage_data(&Default::default())?,
            0
        );
        assert!(tree_storage_data(1, 1, 8, 3).is_err());
        assert!(tree_storage_data(usize::MAX, 1, 8, 8).is_err());
        assert!(shared_header_storage_data(usize::MAX, 64).is_err());
        Ok(())
    }
}
