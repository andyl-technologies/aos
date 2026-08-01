//! Deterministic behavior of the session event-log subscriber stream.
//!
//! These tests exercise the public [`SessionEventLog`] subscriber surface —
//! `recv`, the wall-clock-free `try_recv` probe, and generation-reset replay —
//! without any real-time timeout. Emptiness is asserted through `try_recv`
//! returning `Ok(None)`, keeping the checks fully deterministic.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible_session::{EventLogCursor, SessionEventLog};

/// Builds a deterministic condition-boundary event-log entry for a sequence.
fn test_event_log_entry(sequence: u64) -> crucible::SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        crucible::VirtualTime {
            ticks: sequence.saturating_add(1),
        },
        crucible::SchedulerEvaluationBoundaryKind::Quantum,
    )
}

#[tokio::test]
async fn event_log_stream_does_not_duplicate_replayed_live_frame() {
    let hub = SessionEventLog::new();
    let mut stream = hub.subscribe(EventLogCursor::new(0));
    let entry = test_event_log_entry(0);

    crucible_session::test_support::append_event_log_entries_for_test(
        &hub,
        std::slice::from_ref(&entry),
    );
    let frame = stream
        .recv()
        .await
        .expect("event-log stream should not lag")
        .expect("appended entry should be visible");

    assert_eq!(frame.entry, entry);
    assert_eq!(stream.cursor(), EventLogCursor::new(1));
    assert_eq!(
        stream
            .try_recv()
            .expect("empty stream probe should not lag"),
        None
    );
}

#[tokio::test]
async fn event_log_generation_reset_preserves_retained_prefix_for_lagging_stream() {
    let hub = SessionEventLog::new();
    let entries = (0..10).map(test_event_log_entry).collect::<Vec<_>>();
    crucible_session::test_support::append_event_log_entries_for_test(&hub, &entries);
    let mut stream = hub.subscribe(EventLogCursor::new(0));

    for expected in entries.iter().take(2) {
        let frame = stream
            .recv()
            .await
            .expect("event-log stream should not lag")
            .expect("retained prefix entry should be visible before truncation");
        assert_eq!(frame.generation, 0);
        assert_eq!(&frame.entry, expected);
    }
    assert_eq!(stream.cursor(), EventLogCursor::new(2));

    let replacement = test_event_log_entry(5);
    crucible_session::test_support::truncate_event_log_for_test(&hub, 5);
    crucible_session::test_support::append_event_log_entries_for_test(
        &hub,
        std::slice::from_ref(&replacement),
    );

    for expected in entries[2..5].iter().chain(std::iter::once(&replacement)) {
        let frame = stream
            .recv()
            .await
            .expect("lagging stream should not lag")
            .expect("lagging stream should receive retained prefix after truncation");
        assert!(frame.generation > 0);
        assert_eq!(&frame.entry, expected);
    }
    assert_eq!(stream.cursor(), EventLogCursor::new(6));
    assert_eq!(
        stream
            .try_recv()
            .expect("drained stream probe should not lag"),
        None
    );
}
