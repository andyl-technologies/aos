//! Checks failed native graph backing and conservative shared-view geometry.

use super::*;
use crate::retained_metadata::records::{
    MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind,
};
use crucible_node_format::{Id, SemanticVersion, canonical};

fn observe(
    owner: &NativeCurrentGraph17DecodeAttempt,
) -> crate::retained_metadata::RetainedProtocolMetadataFacts {
    let mut observer = MetadataObserver::new();
    owner.observe_capacity_data(&mut observer).unwrap();
    observer.finish()
}

fn failed_graph() -> Vec<Option<NativeCurrentGraph17DecodeAttempt>> {
    // The production cache retains this large header in its real heap slot.
    // Install that slot before invoking the reader; an inline test Option would
    // keep several copies of the large decoder on the ordinary thread stack.
    let mut slots = Vec::with_capacity(1);
    slots.resize_with(1, || None);
    assert!(read_native_current_graph17_into_data(b"[false]", &mut slots[0], 4096).is_err());
    slots
}

fn selection() -> ExtensionSelection {
    let mut declaration = canonical::content_ref(b"declaration DATA", "application/json").unwrap();
    declaration.hash.domain.reserve(191);
    let mut identifier = String::with_capacity(193);
    identifier.push_str("retained/extension");
    let mut build = String::with_capacity(197);
    build.push_str("capacity");
    let schema_digest = canonical::content_ref(b"schema DATA", "application/json")
        .unwrap()
        .hash;
    ExtensionSelection {
        declaration,
        identifier: Id::new(identifier).unwrap(),
        semantic_version: SemanticVersion {
            major: U64::new(1),
            minor: U64::new(0),
            patch: U64::new(0),
            prerelease: None,
            build: Some(build),
        },
        schema_digest,
    }
}

#[test]
fn capture_native_capacity_failed_graph_keeps_actual_raw_and_spare_banks() {
    let mut slots = failed_graph();
    let input = b"[false]";
    let owner = slots[0].as_mut().unwrap();
    owner.summaries.reserve(3);
    owner.target_groups.reserve(5);
    owner.selected_groups.reserve(7);
    let pointer = owner.raw.as_ptr();
    let expected_vectors = owner.raw.capacity()
        + owner.summaries.capacity() * size_of::<RestoredSettledNative17AliasSummary>()
        + owner.target_groups.capacity() * size_of::<bool>()
        + owner.selected_groups.capacity() * size_of::<Option<Arc<[ExtensionSelection]>>>();

    let facts = observe(owner);

    assert_eq!(facts.vector_capacity_bytes, expected_vectors);
    assert_eq!(
        requested_metadata_backing_storage_data(&facts).unwrap(),
        owner.retained_requested_storage_data(usize::MAX).unwrap()
    );
    assert_eq!(owner.raw, input);
    assert_eq!(owner.raw.as_ptr(), pointer);
    assert!(owner.failed);
    assert!(owner.completed_data().is_none());
    assert!(owner.validate_data().is_err());
    assert!(NativeCurrentGraph17DecodeAttempt::capacity_counter_scratch_data() > 0);
}

#[test]
fn capture_native_capacity_shared_selections_keep_each_actual_view_and_children() {
    let mut slots = failed_graph();
    let owner = slots[0].as_mut().unwrap();
    let baseline = observe(owner);
    let shared: Arc<[ExtensionSelection]> = Arc::from([selection()]);
    let equal_distinct: Arc<[ExtensionSelection]> = Arc::from([selection()]);
    let mut child_observer = MetadataObserver::new();
    ExtensionSelection::observe_output_data(&shared[0], &mut child_observer).unwrap();
    let child = child_observer.finish();
    owner.selected_groups.reserve(7);
    owner.selected_groups.extend([
        Some(Arc::clone(&shared)),
        Some(Arc::clone(&shared)),
        Some(equal_distinct),
    ]);
    let pointer = owner.selected_groups.as_ptr();
    let strong = Arc::strong_count(&shared);

    let facts = observe(owner);

    assert_eq!(
        facts.shared_backing_views - baseline.shared_backing_views,
        3
    );
    assert_eq!(
        facts.shared_value_bytes - baseline.shared_value_bytes,
        3 * size_of::<ExtensionSelection>()
    );
    assert_eq!(
        facts.maximum_shared_value_alignment,
        std::mem::align_of::<ExtensionSelection>()
    );
    assert_eq!(
        facts.string_capacity_bytes - baseline.string_capacity_bytes,
        3 * child.string_capacity_bytes
    );
    assert_eq!(
        facts.vector_capacity_bytes - baseline.vector_capacity_bytes,
        owner.selected_groups.capacity() * size_of::<Option<Arc<[ExtensionSelection]>>>()
            + 3 * child.vector_capacity_bytes
    );
    assert_eq!(owner.selected_groups.as_ptr(), pointer);
    assert_eq!(Arc::strong_count(&shared), strong);
    assert!(owner.validate_data().is_err());
}

#[test]
fn capture_native_capacity_short_graph_bank_keeps_actual_raw_prefix() {
    let slots = failed_graph();
    let owner = slots[0].as_ref().unwrap();
    let prefix = MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 199,
        element_bytes: 1,
        alignment: 1,
    };
    let mut records = MetadataRecordBank::reserve(2).unwrap();
    records.append(prefix).unwrap();
    let backing = records.allocated_bytes();
    let pointer = owner.raw.as_ptr();
    let mut observer = MetadataObserver::appending(&mut records);

    assert!(owner.observe_capacity_data(&mut observer).is_err());
    let _partial = observer.finish();

    assert_eq!(records.rows().len(), 2);
    assert_eq!(records.rows()[0], prefix);
    assert_eq!(records.rows()[1].kind, MetadataRecordKind::Vector);
    assert_eq!(records.rows()[1].extent, owner.raw.capacity());
    assert_eq!(records.rows()[1].element_bytes, size_of::<u8>());
    assert_eq!(records.allocated_bytes(), backing);
    assert_eq!(owner.raw.as_ptr(), pointer);
    assert!(owner.validate_data().is_err());
}
