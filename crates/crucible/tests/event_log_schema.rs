//! Checks the T-OBS-2 event-log entry schema.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    EventClass, EventLevel, EventLog, EventSource, Icount, MarkerId, NodeId, ObservableEvent,
    VirtualTime,
};

#[test]
fn event_log_entries_carry_source_level_class_and_icount_stamp() {
    let node = NodeId {
        name: String::from("guest-a"),
    };
    let marker = ObservableEvent::guest_marker(
        Icount { retired: 99 },
        node.clone(),
        MarkerId::from_name("ready"),
    );
    let entry = crucible::test_support::condition_observation_entry_for_test(0, &marker);

    assert_eq!(entry.sequence(), 0);
    assert_eq!(entry.at(), VirtualTime { ticks: 99 });
    assert_eq!(entry.source(), &EventSource::Guest { node: node.clone() });
    assert_eq!(entry.level(), EventLevel::Info);
    assert_eq!(entry.class(), EventClass::Observational);

    let stamp = &entry.time().icount;
    assert_eq!(stamp.node, Some(node));
    assert_eq!(stamp.icount, Icount { retired: 99 });

    let mut log = EventLog::new();
    let append = log
        .append_entries(vec![entry])
        .expect("schema-complete guest entry should append");
    let segment = append.segment_text;

    assert!(segment.contains("entry.at_virtual_time_ticks=99"));
    assert!(segment.contains("entry.at_icount_retired=99"));
    assert!(segment.contains("entry.at_icount_node=some"));
    assert!(segment.contains("entry.at_icount_node_name=guest-a"));
    assert!(segment.contains("entry.source=guest"));
    assert!(segment.contains("entry.level=info"));
    assert!(segment.contains("entry.class=observational"));
}
