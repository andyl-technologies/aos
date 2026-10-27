//! Sealed scheduler event-log segment tests: seal points, authentication,
//! condition batching, and reference validation.

use super::*;
use crate::attempt_log::seal_attempt_log;
use crate::segment_store::SharedSegmentStore;

/// Builds a console entry whose encoding is about twice `bytes`, because the
/// entry carries its bytes as an event attribute and as the observable payload.
fn console_entry(sequence: u64, at: u64, bytes: usize) -> SchedulerEventLogEntry {
    SchedulerEventLogEntry::observable(
        sequence,
        VirtualTime { ticks: at },
        ObservableEventPayload::ConsoleOutput {
            node: NodeId {
                name: String::from("a"),
            },
            bytes: vec![0; bytes],
        },
    )
}

fn sealed_log(entries: &[SchedulerEventLogEntry]) -> (Arc<MemoryDagStore>, EventLog) {
    let store = Arc::new(MemoryDagStore::new());
    let shared: Arc<dyn DagStore> = store.clone();
    let mut log = EventLog::with_segment_store(shared);
    for entry in entries {
        log.append_entries(vec![entry.clone()])
            .unwrap_or_else(|error| panic!("entry should append: {error}"));
    }
    (store, log)
}

#[test]
fn seal_points_match_the_attempt_log_writer_for_equal_entries() {
    let chunk = EVENT_LOG_SEAL_TARGET_BYTES / 6;
    let entries = (0..7)
        .map(|sequence| console_entry(sequence, 5, chunk))
        .collect::<Vec<_>>();
    let (store, log) = sealed_log(&entries);

    let attempt_store = SharedSegmentStore::default();
    let attempt = seal_attempt_log(&entries, &attempt_store)
        .unwrap_or_else(|error| panic!("attempt log should seal: {error}"));

    // The attempt writer also seals its final open segment; the event log
    // keeps it as the tail.
    let sealed = log.sealed_segments().to_vec();
    assert_eq!(sealed.len() + 1, attempt.segments().len());
    for (segment, attempt_segment) in sealed.iter().zip(attempt.segments()) {
        assert_eq!(segment.first_sequence, attempt_segment.first_sequence);
        assert_eq!(segment.entry_count, attempt_segment.entry_count);
        assert_eq!(segment.encoded_bytes, attempt_segment.encoded_bytes);
        let bytes = store
            .get(&segment.object)
            .unwrap_or_else(|error| panic!("sealed segment should be stored: {error}"));
        assert_eq!(
            segment
                .decode(&bytes)
                .unwrap_or_else(|error| panic!("sealed segment should decode: {error}")),
            entries[segment.first_sequence as usize..][..segment.entry_count as usize]
        );
    }
    let tail_start = sealed.last().and_then(EventLogSegmentRef::end_sequence);
    assert_eq!(
        log.tail_entries()
            .first()
            .map(SchedulerEventLogEntry::sequence),
        tail_start
    );
}

#[test]
fn decode_refuses_bytes_that_do_not_match_the_reference() {
    let chunk = EVENT_LOG_SEAL_TARGET_BYTES / 4;
    let entries = (0..3)
        .map(|sequence| console_entry(sequence, 5, chunk))
        .collect::<Vec<_>>();
    let (store, log) = sealed_log(&entries);
    let segment = log.sealed_segments()[0];
    let bytes = store
        .get(&segment.object)
        .unwrap_or_else(|error| panic!("sealed segment should be stored: {error}"));

    let mut substituted = bytes.clone();
    if let Some(last) = substituted.last_mut() {
        *last ^= 1;
    }
    assert!(segment.decode(&substituted).is_err());

    let shifted = EventLogSegmentRef {
        first_sequence: segment.first_sequence + 1,
        ..segment
    };
    assert!(shifted.decode(&bytes).is_err());
    assert!(segment.decode(&bytes).is_ok());
}

#[test]
fn oversized_entry_fails_the_append_closed() {
    let mut log = EventLog::new();
    let oversized = console_entry(0, 5, EVENT_LOG_SEAL_TARGET_BYTES / 2 + 1);
    assert!(log.append_entries(vec![oversized]).is_err());
    assert_eq!(log.offset().events, 0);
    assert!(log.tail_entries().is_empty());
}

#[test]
fn condition_batches_end_at_running_time_maxima() {
    let mut batcher = ConditionBatcher::default();
    let times = [5, 3, 7, 7, 6, 9];
    let batches = (0_u64..)
        .zip(times)
        .filter_map(|(sequence, at)| batcher.push(console_entry(sequence, at, 1)))
        .map(|batch| {
            batch
                .iter()
                .map(|entry| entry.at().ticks)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    assert_eq!(batches, vec![vec![5], vec![3, 7], vec![7], vec![6, 9]]);
    assert!(batcher.finish().is_empty());
}

#[test]
fn segment_references_must_be_dense_nonempty_and_bounded() {
    let segment = |first_sequence, entry_count, encoded_bytes| EventLogSegmentRef {
        object: ContentHash::from_bytes(b"segment"),
        first_sequence,
        entry_count,
        encoded_bytes,
    };

    assert_eq!(validate_segment_refs(&[], 4), Some(4));
    assert_eq!(
        validate_segment_refs(&[segment(4, 2, 10), segment(6, 1, 10)], 4),
        Some(7)
    );
    assert_eq!(validate_segment_refs(&[segment(5, 2, 10)], 4), None);
    assert_eq!(validate_segment_refs(&[segment(4, 0, 10)], 4), None);
    assert_eq!(
        validate_segment_refs(
            &[segment(4, 1, MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64 + 1)],
            4
        ),
        None
    );
}
