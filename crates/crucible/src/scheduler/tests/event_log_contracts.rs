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

#[test]
fn event_log_v2_rejects_v1_and_missing_or_wrong_backend_input_stamp() {
    let consumer = SchedulerNodeId {
        node: NodeId {
            name: String::from("consumer"),
        },
        kind: SchedulingNodeKind::Vm,
    };
    let producer = SchedulerNodeId {
        node: NodeId {
            name: String::from("producer"),
        },
        kind: SchedulingNodeKind::Vm,
    };
    let event = ScheduledEvent {
        key: ScheduledEventKey::new(
            SharedTimelineKey {
                virtual_time: SimInstant { nanos: 7 },
                node: consumer.clone(),
                sequence: 1,
            },
            producer,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: vec![1, 2, 3],
        }),
    };
    let entry = scheduler_event_log_entry_with_physical_icount(
        0,
        VirtualTime { ticks: 7 },
        SchedulerEventLogPayload::ResolvedHappening(event.clone()),
        consumer.node.clone(),
        Icount { retired: 107 },
    );
    let different_counter = scheduler_event_log_entry_with_physical_icount(
        0,
        VirtualTime { ticks: 7 },
        SchedulerEventLogPayload::ResolvedHappening(event),
        consumer.node,
        Icount { retired: 108 },
    );
    assert!(entry.has_valid_content_hash());
    assert!(different_counter.has_valid_content_hash());
    assert_ne!(entry.content_hash(), different_counter.content_hash());

    let material =
        scheduler_event_log_segment_material(scheduler_event_log_empty_prefix(), &[entry]);

    let mut old_version = material.encode();
    old_version[16..20].copy_from_slice(&1_u32.to_le_bytes());
    assert!(matches!(
        decode_scheduler_event_log_segment(&old_version),
        Err(SchedulerEventLogSegmentDecodeError::UnsupportedVersion { version: 1 })
    ));

    for stamp_node in [None, Some(String::from("wrong-node"))] {
        let mut malformed = material.clone();
        malformed.entries[0].at_icount_node = stamp_node;
        assert!(matches!(
            decode_scheduler_event_log_segment(&malformed.encode()),
            Err(SchedulerEventLogSegmentDecodeError::InvalidBackendInputStamp { sequence: 0 })
        ));
    }
}
