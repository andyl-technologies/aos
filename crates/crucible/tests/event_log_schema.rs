//! Checks the T-OBS-2 event-log entry schema.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ControlOperation, ControlOperationKind, EventLevel, EventLog, EventSource, Icount, MarkerId,
    NodeId, ObservableEvent, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerEventLogClass, SchedulerEventLogPayload, SchedulerNodeId, SchedulingNodeKind,
    SharedTimelineKey, SimInstant, VirtualTime,
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
    assert_eq!(entry.class(), SchedulerEventLogClass::Observational);

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

#[test]
fn command_caused_entries_preserve_command_correlation_source() {
    let command_id = 12;
    let control_node = SchedulerNodeId {
        node: NodeId {
            name: String::from("control-plane"),
        },
        kind: SchedulingNodeKind::ControlPlane,
    };
    let event = ScheduledEvent {
        key: ScheduledEventKey::new(
            SharedTimelineKey {
                virtual_time: SimInstant { ticks: 12 },
                node: control_node.clone(),
                sequence: command_id,
            },
            control_node,
        ),
        payload: ScheduledEventPayload::Control(ControlOperation {
            sequence: command_id,
            kind: ControlOperationKind::Query,
        }),
    };

    let entry = crucible::test_support::condition_payload_entry_for_test(
        0,
        VirtualTime { ticks: 12 },
        SchedulerEventLogPayload::ResolvedHappening(event),
    );

    assert_eq!(entry.source(), &EventSource::Command { command_id });
    assert_eq!(entry.time().icount.icount, Icount { retired: 12 });
}
