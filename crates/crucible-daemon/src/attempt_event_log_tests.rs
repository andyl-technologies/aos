//! Tests sealing, chaining, and authenticated read-back of attempt logs.

use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use crucible::{
    EventAttributeValue, EventLevel, EventLogTime, EventPayload, EventSource,
    SchedulerEventLogClass, VirtualTime,
};

use super::store::{AttemptLogDirectory, DirectorySegmentStore};
use super::*;

/// Builds one observational entry carrying `text_bytes` of payload text.
fn entry(sequence: u64, text_bytes: usize) -> SchedulerEventLogEntry {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("text"),
        EventAttributeValue::String("x".repeat(text_bytes)),
    );
    SchedulerEventLogEntry::from_retained_open_event(
        sequence,
        EventLogTime::from_virtual_time(VirtualTime {
            ticks: 1_000 * sequence,
        }),
        EventSource::Engine,
        EventLevel::Info,
        SchedulerEventLogClass::Observational,
        EventPayload::new("console_output", attributes),
    )
    .unwrap_or_else(|error| panic!("fixture entry should build: {error}"))
}

fn entries(count: u64, text_bytes: usize) -> Vec<SchedulerEventLogEntry> {
    (0..count)
        .map(|sequence| entry(sequence, text_bytes))
        .collect()
}

fn collected(log: &AttemptEventLog<MemorySegmentStore>) -> Vec<SchedulerEventLogEntry> {
    let mut visited = Vec::new();
    log.try_for_each_entry(|entry| {
        visited.push(entry.clone());
        Ok::<(), ()>(())
    })
    .unwrap_or_else(|error| panic!("log should read back: {error}"));
    visited
}

#[test]
fn seals_before_the_tail_crosses_its_target_and_reads_back_in_order() {
    let appended = entries(20, 1024 * 1024);
    let mut log = AttemptEventLog::new(MemorySegmentStore::default(), u64::MAX, 0);

    log.append(appended.clone())
        .unwrap_or_else(|error| panic!("append should succeed: {error}"));

    assert!(log.sealed_segments().len() >= 2);
    assert!(log.tail().len() < 8);
    for segment in log.sealed_segments() {
        assert!(segment.encoded_bytes as usize <= MAX_ATTEMPT_LOG_SEGMENT_BYTES);
    }
    assert_eq!(log.len(), 20);
    assert_eq!(collected(&log), appended);
}

#[test]
fn equal_entries_and_seal_points_produce_equal_segments_and_chains() {
    let appended = entries(12, 512);
    let mut first = AttemptEventLog::new(MemorySegmentStore::default(), u64::MAX, 0);
    let mut second = AttemptEventLog::new(MemorySegmentStore::default(), u64::MAX, 0);

    for log in [&mut first, &mut second] {
        log.append(appended[..5].to_vec())
            .unwrap_or_else(|error| panic!("append: {error}"));
        log.seal().unwrap_or_else(|error| panic!("seal: {error}"));
        log.append(appended[5..].to_vec())
            .unwrap_or_else(|error| panic!("append: {error}"));
        log.seal().unwrap_or_else(|error| panic!("seal: {error}"));
    }

    assert_eq!(first.sealed_segments(), second.sealed_segments());
    assert_eq!(first.chain(), second.chain());
    assert_ne!(first.chain(), empty_chain());
    assert!(first.tail().is_empty());
}

#[test]
fn refuses_non_dense_appends_and_the_storage_limit() {
    let mut log = AttemptEventLog::new(MemorySegmentStore::default(), 4096, 0);

    let gap = log.append([entry(1, 8)]);
    log.append([entry(0, 8)])
        .unwrap_or_else(|error| panic!("first entry: {error}"));
    let over_limit = log.append([entry(1, 8192)]);

    assert!(matches!(
        gap,
        Err(AttemptEventLogError::NonDense {
            expected: 0,
            actual: 1
        })
    ));
    assert!(matches!(
        over_limit,
        Err(AttemptEventLogError::StorageLimit { limit: 4096, .. })
    ));
    assert_eq!(log.len(), 1);
}

#[test]
fn decoding_rejects_segments_that_do_not_match_their_reference() {
    let mut log = AttemptEventLog::new(MemorySegmentStore::default(), u64::MAX, 7);
    log.append((7..10).map(|sequence| entry(sequence, 16)))
        .unwrap_or_else(|error| panic!("append: {error}"));
    log.seal().unwrap_or_else(|error| panic!("seal: {error}"));
    let segment = log.sealed_segments()[0];
    let bytes = log
        .store()
        .segment(segment.id)
        .unwrap_or_else(|error| panic!("stored segment: {error}"));

    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let shifted = AttemptLogSegmentRef {
        first_sequence: 6,
        ..segment
    };

    assert_eq!(
        decode_segment(&segment, &bytes)
            .unwrap_or_else(|error| panic!("valid segment: {error}"))
            .len(),
        3
    );
    assert!(decode_segment(&segment, &tampered).is_err());
    assert!(decode_segment(&shifted, &bytes).is_err());
}

/// Creates a fresh segment directory inside a temporary parent.
fn segment_directory() -> (tempfile::TempDir, Arc<AttemptLogDirectory>) {
    let parent = tempfile::tempdir().unwrap_or_else(|error| panic!("temporary parent: {error}"));
    let directory = AttemptLogDirectory::create(parent.path().join("event-log"))
        .unwrap_or_else(|error| panic!("segment directory: {error}"));
    (parent, directory)
}

#[test]
fn directory_store_round_trips_sealed_segments() {
    let (_parent, directory) = segment_directory();
    let appended = entries(4, 64);
    let mut log = AttemptEventLog::new(DirectorySegmentStore::new(directory), u64::MAX, 0);

    log.append(appended.clone())
        .unwrap_or_else(|error| panic!("append: {error}"));
    log.seal().unwrap_or_else(|error| panic!("seal: {error}"));
    let mut visited = Vec::new();
    let read_back = log.try_for_each_entry(|entry| {
        visited.push(entry.clone());
        Ok::<(), ()>(())
    });

    assert!(read_back.is_ok());
    assert_eq!(visited, appended);
}

#[test]
fn memory_and_directory_stores_yield_equal_refs_and_chain() {
    let (_parent, directory) = segment_directory();
    let appended = entries(20, 1024 * 1024);
    let mut memory = AttemptEventLog::new(MemorySegmentStore::default(), u64::MAX, 0);
    let mut on_disk = AttemptEventLog::new(DirectorySegmentStore::new(directory), u64::MAX, 0);

    memory
        .append(appended.clone())
        .unwrap_or_else(|error| panic!("memory append: {error}"));
    on_disk
        .append(appended)
        .unwrap_or_else(|error| panic!("directory append: {error}"));
    let memory_manifest = memory
        .seal_manifest()
        .unwrap_or_else(|error| panic!("memory manifest: {error}"));
    let on_disk_manifest = on_disk
        .seal_manifest()
        .unwrap_or_else(|error| panic!("directory manifest: {error}"));

    assert!(memory_manifest.segments().len() >= 2);
    assert_eq!(memory_manifest, on_disk_manifest);
}

#[test]
fn directory_removed_when_last_clone_drops() {
    let (_parent, directory) = segment_directory();
    let path = directory.path().to_path_buf();
    let mut log = AttemptEventLog::new(DirectorySegmentStore::new(directory), u64::MAX, 0);
    log.append(entries(3, 64))
        .unwrap_or_else(|error| panic!("append: {error}"));
    log.seal().unwrap_or_else(|error| panic!("seal: {error}"));
    let snapshot = log.clone();

    drop(log);
    let kept_by_snapshot = path.is_dir();
    drop(snapshot);

    assert!(kept_by_snapshot);
    assert!(!path.exists());
}

#[test]
fn directory_store_concurrent_identical_puts_never_expose_partial_bytes() {
    let (_parent, directory) = segment_directory();
    let bytes = vec![0x5a_u8; 4 * 1024 * 1024];
    let id = ContentId::for_bytes(ObjectKind::Trace, ATTEMPT_LOG_SEGMENT_SCHEMA, &bytes);
    let store = DirectorySegmentStore::new(directory);

    std::thread::scope(|scope| {
        for _ in 0..4 {
            let mut writer = store.clone();
            let bytes = &bytes;
            scope.spawn(move || {
                for _ in 0..8 {
                    writer
                        .put(id, bytes)
                        .unwrap_or_else(|error| panic!("concurrent put: {error}"));
                }
            });
        }
        let reader = store.clone();
        let bytes = &bytes;
        scope.spawn(move || {
            for _ in 0..64 {
                match reader.segment(id) {
                    Ok(read) => assert!(read == *bytes, "a reader saw partial segment bytes"),
                    Err(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
                }
            }
        });
    });

    let names = fs::read_dir(store.directory().path())
        .unwrap_or_else(|error| panic!("list segment directory: {error}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("directory entry: {error}"))
                .file_name()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names.len(),
        1,
        "only the complete segment remains: {names:?}"
    );
    assert_eq!(
        store
            .segment(id)
            .unwrap_or_else(|error| panic!("stored segment: {error}")),
        bytes
    );
}

#[test]
fn seal_refuses_segment_beyond_manifest_ceiling() {
    let mut log = AttemptEventLog::new(MemorySegmentStore::default(), u64::MAX, 0);
    for sequence in 0..MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS as u64 {
        log.append([entry(sequence, 1)])
            .unwrap_or_else(|error| panic!("append {sequence}: {error}"));
        log.seal()
            .unwrap_or_else(|error| panic!("seal {sequence}: {error}"));
    }

    log.append([entry(MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS as u64, 1)])
        .unwrap_or_else(|error| panic!("tail append: {error}"));
    let refused = log.seal();

    assert!(matches!(
        refused,
        Err(AttemptEventLogError::SegmentLimit {
            limit: MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS
        })
    ));
    assert_eq!(
        log.sealed_segments().len(),
        MAX_ATTEMPT_LOG_MANIFEST_SEGMENTS
    );
    assert_eq!(log.tail().len(), 1);
}
