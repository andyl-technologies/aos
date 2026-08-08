//! Checks the T-OBS-3 open-set event-log payload projection.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    Decision, EventAttributeValue, EventClass, EventDiagnosticPayload, EventLevel, EventLog,
    Icount, MarkerId, NodeId, ObservableEvent, RngDecision, RngStreamId, SchedulerEventLogPayload,
    VirtualTime,
};

#[test]
fn payload_attributes_are_read_by_name_and_type() {
    let node = NodeId {
        name: String::from("guest-a"),
    };
    let marker = ObservableEvent::guest_marker(
        Icount { retired: 21 },
        node.clone(),
        MarkerId::from_name("phase-ready"),
    );
    let entry = crucible::test_support::condition_observation_entry_for_test(0, &marker);
    let payload = entry.event_payload();

    assert_eq!(payload.kind(), "guest_marker");
    assert_eq!(payload.node("node"), Some(&node));
    assert_eq!(payload.string("marker"), Some("phase-ready"));
    assert_eq!(
        payload.icount("retired_icount"),
        Some(Icount { retired: 21 })
    );
    assert_eq!(payload.u64("retired_icount"), None);
    assert!(payload.attribute("missing").is_none());

    let draw_entry = crucible::test_support::condition_payload_entry_for_test(
        1,
        VirtualTime { ticks: 21 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_link("network.partition"),
            value: 17,
        })),
    );
    let draw_payload = draw_entry.event_payload();

    assert_eq!(draw_payload.kind(), "rng_draw");
    assert_eq!(
        draw_payload.string("stream_domain"),
        Some("crucible.decision-rng.link-stream.v1")
    );
    assert_eq!(draw_payload.u64("value"), Some(17));
    assert_eq!(draw_payload.bool("value"), None);
}

#[test]
fn diagnostic_payload_is_typed_observational_escape_hatch() {
    let mut details = BTreeMap::new();
    details.insert(String::from("poll_count"), EventAttributeValue::U64(37));
    details.insert(
        String::from("executor"),
        EventAttributeValue::String(String::from("session")),
    );
    details.insert(
        String::from("severity"),
        EventAttributeValue::Level(EventLevel::Warn),
    );
    let entry = crucible::test_support::condition_payload_entry_for_test(
        0,
        VirtualTime { ticks: 11 },
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            "executor.poll",
            EventLevel::Warn,
            details,
        )),
    );

    let payload = entry.event_payload();
    assert_eq!(payload.kind(), "diagnostic");
    assert_eq!(payload.string("name"), Some("executor.poll"));
    assert_eq!(payload.u64("poll_count"), Some(37));
    assert_eq!(payload.string("executor"), Some("session"));
    assert_eq!(payload.level("severity"), Some(EventLevel::Warn));
    assert_eq!(entry.level(), EventLevel::Warn);
    assert_eq!(entry.class(), EventClass::Observational);
    assert!(entry.has_valid_content_hash());

    let mut log = EventLog::new();
    let append = log
        .append_entries(vec![entry])
        .expect("diagnostic payload should append");
    let segment = append.segment_text;

    assert!(segment.contains("entry.payload.kind=diagnostic"));
    assert!(segment.contains("event_payload.attribute.poll_count.value.type=u64"));
    assert!(segment.contains("event_payload.attribute.executor.value.type=string"));
}

#[test]
fn level_is_orthogonal_to_event_class() {
    let causal_trace = crucible::test_support::condition_payload_entry_for_test(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("orthogonal-level"),
            value: 7,
        })),
    );

    let diagnostic_error = crucible::test_support::condition_payload_entry_for_test(
        1,
        VirtualTime { ticks: 1 },
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            "host.failure",
            EventLevel::Error,
            BTreeMap::new(),
        )),
    );

    assert_eq!(causal_trace.level(), EventLevel::Trace);
    assert_eq!(causal_trace.class(), EventClass::Causal);
    assert_eq!(diagnostic_error.level(), EventLevel::Error);
    assert_eq!(diagnostic_error.class(), EventClass::Observational);
}
