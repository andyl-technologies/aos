//! Event-log catalog admission and canonical segment regressions.

use super::*;

#[test]
fn event_log_append_rejects_class_catalog_mismatch() {
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("class-catalog-mismatch"),
            value: 17,
        })),
    );
    entry.class = SchedulerEventLogClass::Observational;

    let error = EventLog::new()
        .append_entries(vec![entry])
        .expect_err("append must reject class/catalog mismatches");

    assert!(matches!(
        error,
        SchedulerError::BoundaryViolation { message }
            if message.contains("class observational does not match catalog class causal")
                && message.contains("payload kind rng_draw")
    ));
}

#[test]
fn event_log_append_rejects_typed_kind_catalog_drift() {
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("typed-kind-catalog-drift"),
            value: 23,
        })),
    );
    entry.event_payload = EventPayload::new("diagnostic", entry.event_payload.attributes().clone());

    let error = EventLog::new()
        .append_entries(vec![entry])
        .expect_err("append must reject typed payload kind/catalog drift");

    assert!(matches!(
        error,
        SchedulerError::BoundaryViolation { message }
            if message.contains("class causal does not match catalog class observational")
                && message.contains("payload kind diagnostic")
    ));
}

#[test]
fn event_log_append_rejects_unknown_typed_kind() {
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("unknown-typed-kind"),
            value: 31,
        })),
    );
    entry.event_payload = EventPayload::new(
        "unregistered_kind",
        entry.event_payload.attributes().clone(),
    );

    let error = EventLog::new()
        .append_entries(vec![entry])
        .expect_err("append must reject unknown typed payload kinds");

    assert!(matches!(
        error,
        SchedulerError::BoundaryViolation { message }
            if message.contains("payload kind unregistered_kind is not in the event-kind catalog")
    ));
}

#[test]
fn event_log_segment_binary_round_trips_to_same_bytes() {
    let previous_prefix = scheduler_event_log_empty_prefix();
    let entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 9 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("segment-round-trip"),
            value: 41,
        })),
    );
    let entries = vec![entry];
    let segment = scheduler_event_log_segment_material(previous_prefix, &entries);
    let bytes = segment.encode();

    let decoded = decode_scheduler_event_log_segment(&bytes)
        .unwrap_or_else(|error| panic!("segment should decode: {error:?}"));

    assert_eq!(decoded, segment);
    assert_eq!(decoded.encode(), bytes);
    assert_eq!(decoded.text_view(), segment.text_view());
    assert!(decoded.text_view().contains("entry.payload.kind=rng_draw"));
}
