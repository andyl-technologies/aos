//! Combines actual metadata facts with checked source-pinned requested layouts.
//!
//! The BTree bound follows Rust 1.98.1's B=6 node (11 entries, 12 edges).
//! Shared headers follow the two-usize Rc/Arc counts and actual payload
//! alignment. These are requested-layout data, not an allocator measurement,
//! Source allowance, physical peak, or permission to clone or decode anything.
//! Equal values and independent views receive no alias discount here; a genuine
//! unique-root walker must establish any earlier deduplication locally.

#[cfg(test)]
use super::RetainedProtocolMetadataFacts;
#[cfg(test)]
use crate::ProviderError;
#[cfg(test)]
use std::mem::{align_of, size_of};

pub(crate) use crucible_source_birth_data::profile::requested_storage::{
    requested_metadata_backing_storage_data, shared_header_storage_data, tree_storage_data,
};

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
