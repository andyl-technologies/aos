//! Event-log catalog admission and canonical segment regressions.

use super::*;

#[test]
fn cloned_event_logs_share_history_until_admitted_mutation() {
    let fixture = crate::test_support::fixture_decode_scope(64 * 1024 * 1024).unwrap();
    let first = SchedulerEventLogEntry::evaluation_boundary(
        0,
        VirtualTime { ticks: 1 },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
    .unwrap();
    let mut original = EventLog::new();
    original.append_entries(vec![first]).unwrap();
    let original_offset = original.offset();
    let retained_bytes = fixture.retained_bytes();

    for _ in 0..1024 {
        let copied = original.clone();
        assert_eq!(
            copied.retained_entries().as_ptr(),
            original.retained_entries().as_ptr()
        );
        assert_eq!(copied.offset(), original_offset);
        assert_eq!(fixture.retained_bytes(), retained_bytes);
    }

    let mut branch = original.clone();
    let second = SchedulerEventLogEntry::evaluation_boundary(
        1,
        VirtualTime { ticks: 2 },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
    .unwrap();
    branch.append_entries(vec![second]).unwrap();

    assert_eq!(original.offset(), original_offset);
    assert_eq!(original.retained_entries().len(), 1);
    assert_eq!(branch.retained_entries().len(), 2);
    assert_ne!(
        branch.retained_entries().as_ptr(),
        original.retained_entries().as_ptr()
    );
    assert_eq!(branch.retained_entries()[0], original.retained_entries()[0]);
    assert!(fixture.retained_bytes() > retained_bytes);

    drop(original);
    assert!(
        branch
            .retained_entries()
            .iter()
            .all(|entry| entry.has_valid_content_hash().unwrap())
    );
    fixture.check().unwrap();
}

#[test]
fn event_log_append_rejects_class_catalog_mismatch() {
    let _origin = crate::test_support::fixture_decode_scope(64 * 1024 * 1024).unwrap();
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("class-catalog-mismatch"),
            value: 17,
        })),
    )
    .unwrap();
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
    let _origin = crate::test_support::fixture_decode_scope(64 * 1024 * 1024).unwrap();
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("typed-kind-catalog-drift"),
            value: 23,
        })),
    )
    .unwrap();
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
    let _origin = crate::test_support::fixture_decode_scope(64 * 1024 * 1024).unwrap();
    let mut entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 0 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("unknown-typed-kind"),
            value: 31,
        })),
    )
    .unwrap();
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
    let _origin = crate::test_support::fixture_decode_scope(64 * 1024 * 1024).unwrap();
    let previous_prefix = scheduler_event_log_empty_prefix();
    let entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: 9 },
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("segment-round-trip"),
            value: 41,
        })),
    )
    .unwrap();
    let entries = vec![entry];
    let segment = scheduler_event_log_segment_material(previous_prefix, &entries).unwrap();
    let bytes = segment.encode().unwrap();

    let decoded = decode_scheduler_event_log_segment(&bytes)
        .unwrap_or_else(|error| panic!("segment should decode: {error:?}"));

    assert_eq!(decoded, segment);
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(decoded.text_view().unwrap(), segment.text_view().unwrap());
    assert!(
        decoded
            .text_view()
            .unwrap()
            .contains("entry.payload.kind=rng_draw")
    );
}

#[test]
fn event_log_rejects_predecessor_versions_and_invalid_backend_input_stamp() {
    let _origin = crate::test_support::fixture_decode_scope(64 * 1024 * 1024).unwrap();
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
                virtual_time: SimInstant { ticks: 7 },
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
    )
    .unwrap();
    let different_counter = scheduler_event_log_entry_with_physical_icount(
        0,
        VirtualTime { ticks: 7 },
        SchedulerEventLogPayload::ResolvedHappening(event),
        consumer.node,
        Icount { retired: 108 },
    )
    .unwrap();
    assert!(entry.has_valid_content_hash().unwrap());
    assert!(different_counter.has_valid_content_hash().unwrap());
    assert_ne!(entry.content_hash(), different_counter.content_hash());

    let material =
        scheduler_event_log_segment_material(scheduler_event_log_empty_prefix(), &[entry]).unwrap();

    for version in [3_u32, 4] {
        let mut old_version = material.encode().unwrap();
        old_version[16..20].copy_from_slice(&version.to_le_bytes());
        assert!(matches!(
            decode_scheduler_event_log_segment(&old_version),
            Err(SchedulerEventLogSegmentDecodeError::UnsupportedVersion { version: actual })
                if actual == version
        ));
    }

    for stamp_node in [None, Some(String::from("wrong-node"))] {
        let mut malformed = material.clone();
        malformed.entries[0].at_node = stamp_node;
        assert!(matches!(
            decode_scheduler_event_log_segment(&malformed.encode().unwrap()),
            Err(SchedulerEventLogSegmentDecodeError::InvalidBackendInputStamp { sequence: 0 })
        ));
    }
}

#[test]
fn idle_jump_preserves_exact_tick_and_unchanged_raw_retirement_in_event_stamp() {
    let _origin = crate::test_support::fixture_decode_scope(64 * 1024 * 1024).unwrap();
    let node = NodeId {
        name: String::from("idle-vm"),
    };
    let scheduler_node = SchedulerNodeId {
        node: node.clone(),
        kind: SchedulingNodeKind::Vm,
    };
    let event = ScheduledEvent {
        key: ScheduledEventKey::new(
            SharedTimelineKey {
                virtual_time: SimInstant { ticks: 1001 },
                node: scheduler_node.clone(),
                sequence: 0,
            },
            scheduler_node,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: node.clone(),
            payload: vec![1],
        }),
    };
    let entry = scheduler_event_log_entry_with_physical_icount(
        0,
        VirtualTime { ticks: 1001 },
        SchedulerEventLogPayload::ResolvedHappening(event),
        node.clone(),
        Icount { retired: 0 },
    )
    .unwrap();

    assert_eq!(entry.time().stamp.tick, SimInstant { ticks: 1001 });
    assert_eq!(entry.time().stamp.retired, Some(Icount { retired: 0 }));
    assert_eq!(entry.time().stamp.node, Some(node));

    let material =
        scheduler_event_log_segment_material(scheduler_event_log_empty_prefix(), &[entry]).unwrap();
    assert_eq!(material.entries[0].at_tick, 1001);
    assert_eq!(material.entries[0].at_raw_retired, Some(0));
    assert_eq!(
        decode_scheduler_event_log_segment(&material.encode().unwrap()),
        Ok(material)
    );
}
