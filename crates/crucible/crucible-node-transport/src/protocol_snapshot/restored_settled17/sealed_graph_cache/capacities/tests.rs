//! Checks real failed decoder children and every retained lazy-slot allocation.

use super::*;
use crate::retained_metadata::{
    records::{MetadataCapacityRecord, MetadataRecordBank, MetadataRecordKind},
    requested_metadata_backing_storage_data,
};

fn failed_cache() -> NativeGraph17DecodeCache {
    let mut cache = NativeGraph17DecodeCache::new();
    assert!(
        cache
            .read_into_data(
                b"{}",
                NativeCurrentGraph17ReadLimits {
                    maximum_requested: size_of::<Option<NativeCurrentGraph17DecodeAttempt>>()
                        + 4096,
                    maximum_target_requested: size_of::<Option<NativeCurrentGraph17DecodeAttempt>>(
                    ) + 4096,
                    maximum_nodes: 64,
                    maximum_depth: 64,
                }
            )
            .is_err()
    );
    cache
}

#[test]
fn capture_native_capacity_cache_keeps_real_failed_child_and_slot_spares() {
    let mut cache = failed_cache();
    cache.slots.reserve(3);
    cache.slots.push(None);
    let pointer = cache.slots.as_ptr();
    let child = cache.as_ref().unwrap();
    let child_bytes = child.retained_requested_storage_data(usize::MAX).unwrap();
    let expected = cache.slots.capacity() * size_of::<Option<NativeCurrentGraph17DecodeAttempt>>()
        + child_bytes;
    let mut observer = MetadataObserver::new();

    cache.observe_capacity_data(&mut observer).unwrap();
    let facts = observer.finish();

    assert_eq!(
        requested_metadata_backing_storage_data(&facts).unwrap(),
        expected
    );
    assert_eq!(
        cache.retained_requested_storage_data(usize::MAX).unwrap(),
        expected
    );
    assert_eq!(cache.slots.as_ptr(), pointer);
    assert!(cache.started);
    assert!(cache.as_ref().unwrap().validate_data().is_err());
    assert!(NativeGraph17DecodeCache::capacity_counter_scratch_data() > 0);
}

#[test]
fn capture_native_capacity_short_cache_bank_preserves_actual_slot_row() {
    let cache = failed_cache();
    let prefix = MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: 211,
        element_bytes: 1,
        alignment: 1,
    };
    let mut records = MetadataRecordBank::reserve(2).unwrap();
    records.append(prefix).unwrap();
    let backing = records.allocated_bytes();
    let mut observer = MetadataObserver::appending(&mut records);

    assert!(cache.observe_capacity_data(&mut observer).is_err());
    let _partial = observer.finish();

    assert_eq!(records.rows().len(), 2);
    assert_eq!(records.rows()[0], prefix);
    assert_eq!(records.rows()[1].kind, MetadataRecordKind::Vector);
    assert_eq!(records.rows()[1].extent, cache.slots.capacity());
    assert_eq!(
        records.rows()[1].element_bytes,
        size_of::<Option<NativeCurrentGraph17DecodeAttempt>>()
    );
    assert_eq!(
        records.rows()[1].alignment,
        std::mem::align_of::<Option<NativeCurrentGraph17DecodeAttempt>>()
    );
    assert_eq!(records.allocated_bytes(), backing);
    assert!(cache.as_ref().unwrap().validate_data().is_err());
}
