//! Checks the T-OBS-1 unified event-log append owner.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    EventEvaluationKind, EventLog, SchedulerError, SchedulerEvaluationBoundaryKind, VirtualTime,
};

#[test]
fn event_log_append_path_feeds_offsets_and_condition_projection() {
    let mut log = EventLog::new();
    assert_eq!(log.offset().events, 0);

    let first = crucible::test_support::condition_boundary_entry_for_test(
        0,
        VirtualTime { ticks: 4 },
        SchedulerEvaluationBoundaryKind::Quantum,
    );
    let first_append = log
        .append_entries(vec![first.clone()])
        .expect("first entry should append");

    assert_eq!(first_append.entries, vec![first]);
    assert_eq!(first_append.offset.events, 1);
    assert!(first_append.offset.appended_segment.is_some());
    assert_eq!(log.offset().events, 1);
    assert_eq!(
        log.condition_prefix().point().kind(),
        EventEvaluationKind::QuantumBoundary
    );
    assert_eq!(
        log.condition_prefix().point().at(),
        VirtualTime { ticks: 4 }
    );

    let second = crucible::test_support::condition_boundary_entry_for_test(
        1,
        VirtualTime { ticks: 9 },
        SchedulerEvaluationBoundaryKind::Rendezvous,
    );
    let second_append = log
        .append_entries(vec![second.clone()])
        .expect("second entry should append");

    assert_eq!(second_append.entries, vec![second]);
    assert_eq!(second_append.offset.events, 2);
    assert!(second_append.offset.bytes > first_append.offset.bytes);
    assert_ne!(second_append.offset.prefix, first_append.offset.prefix);
    assert_eq!(log.offset().events, 2);
    assert_eq!(
        log.condition_prefix().point().kind(),
        EventEvaluationKind::RendezvousBoundary
    );
    assert_eq!(
        log.condition_prefix().point().at(),
        VirtualTime { ticks: 9 }
    );
}

#[test]
fn event_log_rejects_non_dense_append_sequence() {
    let mut log = EventLog::new();
    let entry = crucible::test_support::condition_boundary_entry_for_test(
        7,
        VirtualTime { ticks: 4 },
        SchedulerEvaluationBoundaryKind::Quantum,
    );

    let error = log
        .append_entries(vec![entry])
        .expect_err("non-dense sequence should be rejected");

    assert!(matches!(
        error,
        SchedulerError::BoundaryViolation { message }
            if message.contains("does not match expected dense sequence 0")
    ));
    assert_eq!(log.offset().events, 0);
}
