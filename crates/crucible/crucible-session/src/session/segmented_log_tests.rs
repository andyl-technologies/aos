//! Sealed-segment session log tests: sealing, reading, counting, truncation,
//! and hub replay across segment boundaries.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use super::*;
use crate::{EventLogCursor, SessionEventLog};
use crucible_engine::{AssertionId, AssertionPhase, MemoryDagStore};

// Small enough that a few dozen entries span several multi-entry segments.
const TEST_SEAL_TARGET: u64 = 2_048;

/// Alternates causal boundaries and observational assertion updates.
fn entry(sequence: u64) -> SchedulerEventLogEntry {
    let at = VirtualTime { ticks: sequence };
    if sequence.is_multiple_of(3) {
        SchedulerEventLogEntry::assertion_state_observation(
            sequence,
            at,
            AssertionId::from_name("segmented-log"),
            AssertionPhase::Satisfied,
        )
    } else {
        crucible_engine::test_support::condition_boundary_entry_for_test(
            sequence,
            at,
            SchedulerEvaluationBoundaryKind::Quantum,
        )
    }
}

fn entries(range: std::ops::Range<u64>) -> Vec<SchedulerEventLogEntry> {
    range.map(entry).collect()
}

fn sealed_log(store: &Arc<MemoryDagStore>, count: u64) -> SegmentedEntryLog {
    let shared: Arc<dyn DagStore> = store.clone();
    let mut log = SegmentedEntryLog::with_seal_target(shared, TEST_SEAL_TARGET);
    log.append(&entries(0..count))
        .expect("dense entries should append");
    log
}

#[test]
fn appends_seal_full_tails_into_the_store_and_read_back_in_order() {
    let store = Arc::new(MemoryDagStore::new());
    let log = sealed_log(&store, 60);

    assert!(
        log.sealed.len() >= 3,
        "fixture should span several segments"
    );
    assert!(log.tail_bytes <= TEST_SEAL_TARGET);
    for segment in &log.sealed {
        assert!(
            store
                .exists(&segment.reference.object)
                .expect("store query")
        );
    }
    assert_eq!(log.len(), 60);
    assert_eq!(log.end(), 60);
    assert_eq!(log.last_sequence(), Some(59));
    assert_eq!(
        log.collect_through(u64::MAX).expect("log should read back"),
        entries(0..60)
    );
    assert_eq!(
        log.collect_through(17).expect("prefix should read back"),
        entries(0..17)
    );
}

#[test]
fn class_counts_match_a_direct_count_at_every_cut() {
    let store = Arc::new(MemoryDagStore::new());
    let log = sealed_log(&store, 40);
    let all = entries(0..40);

    for through in 0..=41_u64 {
        let (counts, last) = log.counts_through(through).expect("counts should read");
        let expected = ClassCounts::over(all.iter().take_while(|entry| entry.sequence() < through));
        assert_eq!(counts, expected, "counts through {through}");
        assert_eq!(
            last,
            through.min(40).checked_sub(1),
            "last through {through}"
        );
    }
}

#[test]
fn chunks_return_one_decoded_segment_or_a_bounded_tail_slice() {
    let store = Arc::new(MemoryDagStore::new());
    let log = sealed_log(&store, 60);
    let first = log
        .sealed
        .first()
        .copied()
        .expect("fixture has a sealed segment");
    assert!(
        first.reference.entry_count >= 2,
        "fixture segments hold several entries"
    );

    let sealed = log
        .chunk_from(1, 4)
        .expect("sealed chunk should read")
        .expect("sequence 1 is retained");
    assert_eq!(sealed.first_sequence, 0);
    assert_eq!(sealed.end(), first.end());
    assert_eq!(sealed.get(1), Some(&entry(1)));

    let tail = log
        .chunk_from(58, 4)
        .expect("tail chunk should read")
        .expect("sequence 58 is retained");
    assert_eq!(tail.first_sequence, 58);
    assert_eq!(tail.entries.as_slice(), entries(58..60).as_slice());
    assert!(log.chunk_from(60, 4).expect("end probe").is_none());
}

#[test]
fn truncation_inside_a_sealed_segment_keeps_its_prefix_as_the_tail() {
    let store = Arc::new(MemoryDagStore::new());
    let mut log = sealed_log(&store, 60);
    let second = log
        .sealed
        .get(1)
        .copied()
        .expect("fixture has two segments");
    assert!(
        second.reference.entry_count >= 2,
        "fixture segments hold several entries"
    );
    let cut = second.reference.first_sequence + 1;

    log.truncate(cut).expect("cut inside a sealed segment");
    assert_eq!(log.end(), cut);
    assert_eq!(log.sealed.len(), 1);
    assert_eq!(
        log.collect_through(u64::MAX).expect("truncated log"),
        entries(0..cut)
    );
    let (counts, _) = log.counts_through(u64::MAX).expect("totals");
    assert_eq!(counts, ClassCounts::over(&entries(0..cut)));

    log.append(&entries(cut..cut + 30))
        .expect("appends continue after the cut");
    assert_eq!(
        log.collect_through(u64::MAX).expect("extended log"),
        entries(0..cut + 30)
    );

    log.truncate(0).expect("truncate everything");
    assert!(log.is_empty());
    assert_eq!(log.end(), 0);
}

#[test]
fn appends_must_stay_dense() {
    let store = Arc::new(MemoryDagStore::new());
    let mut log = sealed_log(&store, 5);

    let error = log.append(&[entry(7)]).expect_err("a gap must fail closed");
    assert!(error.to_string().contains("not dense"));
    assert_eq!(log.end(), 5);
}

#[test]
fn hub_replays_and_summarizes_across_sealed_segments() {
    let store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let hub = SessionEventLog::with_seal_target_for_test(store, TEST_SEAL_TARGET);
    let all = entries(0..80);
    hub.append_entries(&all).expect("hub append");
    let mut stream = hub.subscribe(EventLogCursor::new(0));

    let mut replayed = Vec::new();
    while let Some(frame) = stream.try_recv().expect("replay should read segments") {
        replayed.push(frame.entry);
    }
    assert_eq!(replayed, all);

    let snapshot = hub
        .snapshot_through(EventLogCursor::new(33))
        .expect("snapshot inside a segment");
    let expected = ClassCounts::over(all.iter().take(33));
    assert_eq!(snapshot.event_count, 33);
    assert_eq!(snapshot.causal_count, expected.causal);
    assert_eq!(snapshot.observational_count, expected.observational);
    assert_eq!(snapshot.last_sequence, Some(32));

    hub.truncate_to_len(20).expect("hub truncation");
    let mut rewound = hub.subscribe(EventLogCursor::new(10));
    let mut after = Vec::new();
    while let Some(frame) = rewound.try_recv().expect("rewound replay") {
        after.push(frame.entry.sequence());
    }
    assert_eq!(after, (10..20).collect::<Vec<_>>());
}

#[test]
fn debug_history_extends_its_breakpoint_prefix_like_a_whole_rebuild() {
    let store: Arc<dyn DagStore> = Arc::new(MemoryDagStore::new());
    let mut history = crate::SessionDebugHistory::new(store);
    let configuration =
        Configuration::genesis(crucible_engine::ScenarioDef::from_canonical_material(
            "crucible.test.session.debug-history",
            "debug history",
        ));
    let no_patterns = BTreeSet::new();

    history
        .append(&entries(0..10), &configuration, &configuration)
        .expect("first batch");
    history
        .condition_prefix(&no_patterns, 0)
        .expect("prefix builds from the history");
    for batch in [10..25, 25..40] {
        history
            .append(&entries(batch), &configuration, &configuration)
            .expect("later batch");
    }

    let whole = ConditionEventLogPrefix::from_scheduler_event_log_entries(entries(0..40))
        .expect("whole prefix");
    let extended = history
        .condition_prefix(&no_patterns, 0)
        .expect("extended prefix")
        .clone();
    assert_eq!(extended, whole);

    history.truncate(20).expect("rewind the history");
    let rebuilt = history
        .condition_prefix(&no_patterns, 0)
        .expect("rebuilt prefix")
        .clone();
    let expected = ConditionEventLogPrefix::from_scheduler_event_log_entries(entries(0..20))
        .expect("rewound prefix");
    assert_eq!(rebuilt, expected);
    assert_eq!(history.coordinate(19), Some(&configuration));
    assert_eq!(history.coordinate(20), None);
}
