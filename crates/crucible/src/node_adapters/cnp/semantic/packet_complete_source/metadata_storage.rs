//! Converts actual borrowed protocol metadata facts into requested storage.
//!
//! Payload capacities remain distinct from tree nodes and shared headers. The
//! pinned Core layout helpers own those layout rules; this adapter adds the
//! terms under one checked ceiling without inferring any installed authority.

use super::storage_error::StorageError;
use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_provider::retained_metadata::RetainedProtocolMetadataFacts;

impl PacketCompleteSemanticSource {
    /// Bounds requested storage described by actual typed metadata facts.
    ///
    /// The caller obtains facts from the same borrowed SDK owner, then includes
    /// this result alongside all independently retained owners, byte banks,
    /// inline allocation headers and transient storage in its whole admission.
    /// Shared payloads and headers are charged per reported view, without an
    /// alias discount. This data conversion authenticates no source or capture
    /// capability and makes no allocator rounding or stack-storage claim.
    ///
    /// # Errors
    /// Refuses inconsistent tree facts, unsupported alignments, arithmetic
    /// overflow or a combined requested-storage term above `maximum`.
    pub fn complete_retained_metadata_storage_data(
        facts: &RetainedProtocolMetadataFacts,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        Self::complete_retained_metadata_storage_with_error::<OperationFailure>(facts, maximum)
    }

    /// Converts actual metadata facts without allocating a failure diagnostic.
    ///
    /// # Errors
    /// Refuses unsupported facts, checked layout overflow or the supplied bound.
    pub fn complete_retained_metadata_storage_precredit_data(
        facts: &RetainedProtocolMetadataFacts,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        Self::complete_retained_metadata_storage_with_error::<RuntimeError>(facts, maximum)
    }

    pub(super) fn complete_retained_metadata_storage_with_error<E: StorageError>(
        facts: &RetainedProtocolMetadataFacts,
        maximum: usize,
    ) -> Result<usize, E> {
        let payload = [
            facts.string_capacity_bytes,
            facts.vector_capacity_bytes,
            facts.boxed_value_bytes,
            facts.shared_value_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes)
                .filter(|total| *total <= maximum)
                .ok_or_else(|| E::limit("complete metadata payload storage exhausted"))
        })?;

        let trees = NodeRuntime::capture_protocol_tree_storage(
            facts.tree_containers,
            facts.tree_entries,
            facts.maximum_tree_key_value_bytes,
            facts.maximum_tree_entry_alignment,
            maximum - payload,
        )
        .map_err(E::runtime)?;
        let retained = payload
            .checked_add(trees)
            .ok_or_else(|| E::limit("complete metadata tree storage overflow"))?;
        let headers = NodeRuntime::capture_protocol_shared_header_storage(
            facts.shared_backing_views,
            facts.maximum_shared_value_alignment,
            maximum - retained,
        )
        .map_err(E::runtime)?;

        retained
            .checked_add(headers)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| E::limit("complete metadata combined storage exhausted"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn actual_spare_payload_capacity_is_admitted_at_exact_total() {
        let mut text = String::with_capacity(4096);
        text.push('x');
        let values = Vec::<u64>::with_capacity(23);
        let facts = RetainedProtocolMetadataFacts {
            string_capacity_bytes: text.capacity(),
            vector_capacity_bytes: values.capacity() * size_of::<u64>(),
            ..RetainedProtocolMetadataFacts::default()
        };
        let expected = text.capacity() + values.capacity() * size_of::<u64>();

        assert_eq!(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_data(&facts, expected)
                .unwrap(),
            expected
        );
        assert!(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                &facts,
                expected - 1,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_tree_and_shared_views_require_separate_aligned_storage() {
        #[repr(align(256))]
        struct AlignedZero;

        let facts = RetainedProtocolMetadataFacts {
            tree_containers: 1,
            maximum_tree_key_value_bytes: size_of::<AlignedZero>(),
            maximum_tree_entry_alignment: align_of::<AlignedZero>(),
            shared_backing_views: 2,
            maximum_shared_value_alignment: align_of::<AlignedZero>(),
            ..RetainedProtocolMetadataFacts::default()
        };
        let total = PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
            &facts,
            usize::MAX,
        )
        .unwrap();

        assert!(total >= 2 * align_of::<AlignedZero>());
        assert_eq!(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_data(&facts, total)
                .unwrap(),
            total
        );
        assert!(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                &facts,
                total - 1
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_metadata_facts_and_combined_overflow_refuse() {
        let invalid = [
            RetainedProtocolMetadataFacts {
                tree_entries: 1,
                ..RetainedProtocolMetadataFacts::default()
            },
            RetainedProtocolMetadataFacts {
                tree_containers: 1,
                maximum_tree_entry_alignment: 3,
                ..RetainedProtocolMetadataFacts::default()
            },
            RetainedProtocolMetadataFacts {
                string_capacity_bytes: usize::MAX,
                vector_capacity_bytes: 1,
                ..RetainedProtocolMetadataFacts::default()
            },
        ];

        for facts in invalid {
            assert!(
                PacketCompleteSemanticSource::complete_retained_metadata_storage_data(
                    &facts,
                    usize::MAX,
                )
                .is_err()
            );
        }
    }
}
