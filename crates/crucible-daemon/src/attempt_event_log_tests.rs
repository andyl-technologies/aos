//! Tests sealing, chaining, and authenticated read-back of attempt logs.

use std::collections::BTreeMap;

use crucible::{
    EventAttributeValue, EventLevel, EventLogTime, EventPayload, EventSource,
    SchedulerEventLogClass, VirtualTime,
};

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

#[test]
fn directory_store_round_trips_sealed_segments() {
    let directory = std::env::temp_dir().join(format!(
        "crucible-attempt-log-segments-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap_or_else(|error| panic!("segment directory: {error}"));
    let appended = entries(4, 64);
    let mut log = AttemptEventLog::new(DirectorySegmentStore::new(&directory), u64::MAX, 0);

    log.append(appended.clone())
        .unwrap_or_else(|error| panic!("append: {error}"));
    log.seal().unwrap_or_else(|error| panic!("seal: {error}"));
    let mut visited = Vec::new();
    let read_back = log.try_for_each_entry(|entry| {
        visited.push(entry.clone());
        Ok::<(), ()>(())
    });

    let _ = fs::remove_dir_all(&directory);
    assert!(read_back.is_ok());
    assert_eq!(visited, appended);
}
