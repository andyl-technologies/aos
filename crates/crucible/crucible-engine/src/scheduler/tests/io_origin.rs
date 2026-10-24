//! Persisted I/O source-key ownership through actual device queue resolution.

use super::*;

fn source() -> SingleScheduler {
    test_scheduler(
        vec![test_scenario_node(
            "a",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    )
    .with_device_sub_node(disk_with_reads("a", "disk", &[(1, 8), (1, 8)]))
}

#[test]
fn resolution_retains_original_computed_key_instead_of_scheduler_ordinal() {
    let mut scheduler = source();
    let consumer = scheduler_node("a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("disk", SchedulingNodeKind::Disk);
    scheduler
        .event_sequences
        .set_next_sequence(producer.clone(), consumer.clone(), 100);
    let at = scheduler.device_sub_nodes[&consumer.node][0]
        .next_exact_local_event()
        .expect("actual computed block queue has a deadline");

    let (events, _) = scheduler
        .resolve_device_completions(&consumer, at)
        .expect("actual queue resolution");

    assert_eq!(events.len(), 2);
    for (index, event) in events.iter().enumerate() {
        let ScheduledEventPayload::IoCompletion(completion) = &event.payload else {
            panic!("block completion missing");
        };
        assert_eq!(completion.source_delivery.delivery_icount, at);
        assert_eq!(completion.source_delivery.src_node, 1);
        assert_eq!(completion.source_delivery.seq, index as u32);
        assert_ne!(completion.source_delivery.seq as u64, event.key.sequence());
        assert_eq!(event.key.producer(), &producer);
    }
}

#[test]
fn encoded_pending_completion_and_fork_clone_retain_the_actual_source_key() {
    let template = source();
    let mut scheduler = template.clone();
    let consumer = scheduler_node("a", SchedulingNodeKind::Vm);
    let at = scheduler.device_sub_nodes[&consumer.node][0]
        .next_exact_local_event()
        .expect("actual computed deadline");
    let (events, _) = scheduler
        .resolve_device_completions(&consumer, at)
        .expect("actual block resolution");
    scheduler.pending_events.extend(events);
    let encoded = scheduler
        .checkpoint()
        .and_then(|checkpoint| checkpoint.canonical_bytes())
        .expect("pending origin checkpoint");
    assert!(encoded.starts_with(b"crucible.single-scheduler-continuation.v6\0"));

    for _ in 0..2 {
        let decoded = SingleSchedulerCheckpoint::from_canonical_bytes(&encoded)
            .expect("current pending origin decode");
        let mut restored = template.clone();
        decoded
            .restore_into(&mut restored)
            .expect("authenticated matching device restore");
        assert_eq!(restored.pending_events, scheduler.pending_events);
        assert_eq!(restored.clone().pending_events, scheduler.pending_events);
    }
    let mut retired = encoded;
    retired[b"crucible.single-scheduler-continuation.v".len()] = b'3';
    assert!(matches!(
        SingleSchedulerCheckpoint::from_canonical_bytes(&retired),
        Err(SingleSchedulerCheckpointError::Version)
    ));
}

#[test]
fn missing_origin_and_mismatched_persisted_tick_are_refused() {
    let mut scheduler = source();
    let consumer = scheduler_node("a", SchedulingNodeKind::Vm);
    let at = scheduler.device_sub_nodes[&consumer.node][0]
        .next_exact_local_event()
        .expect("actual device deadline");
    let (mut events, _) = scheduler
        .resolve_device_completions(&consumer, at)
        .expect("actual queue resolution");
    let ScheduledEventPayload::IoCompletion(completion) = &mut events[0].payload else {
        panic!("computed completion missing");
    };
    let mut bare = serde_json::to_value(&*completion).expect("current completion encoding");
    bare.as_object_mut()
        .expect("completion object")
        .remove("source_delivery");
    assert!(serde_json::from_value::<IoCompletion>(bare).is_err());

    completion.source_delivery.delivery_icount += 1;
    scheduler.pending_events.extend(events);
    let encoded = scheduler
        .checkpoint()
        .and_then(|checkpoint| checkpoint.canonical_bytes())
        .expect("encode independently invalid origin fixture");
    assert!(matches!(
        SingleSchedulerCheckpoint::from_canonical_bytes(&encoded),
        Err(SingleSchedulerCheckpointError::State)
    ));
}

#[test]
fn event5_binds_original_queue_keys_and_refuses_event4_bytes() {
    let mut scheduler = source();
    let consumer = scheduler_node("a", SchedulingNodeKind::Vm);
    let at = scheduler.device_sub_nodes[&consumer.node][0]
        .next_exact_local_event()
        .expect("actual computed deadline");
    let (events, _) = scheduler
        .resolve_device_completions(&consumer, at)
        .expect("actual queue resolution");
    let original = &events[0];
    let ScheduledEventPayload::IoCompletion(completion) = &original.payload else {
        panic!("actual computed reply");
    };
    let payload = resolved_happening_event_payload(original);
    assert_eq!(
        payload.attributes.get("source_delivery_tick"),
        Some(&EventAttributeValue::U64(
            completion.source_delivery.delivery_icount
        )),
    );
    assert_eq!(
        payload.attributes.get("source_node"),
        Some(&EventAttributeValue::U64(u64::from(
            completion.source_delivery.src_node
        ))),
    );
    assert_eq!(
        payload.attributes.get("source_sequence"),
        Some(&EventAttributeValue::U64(u64::from(
            completion.source_delivery.seq
        ))),
    );

    // The canonical ordinal remains unchanged when the independently retained
    // queue identity is corrupted; the event hash must still distinguish it.
    let mut changed = original.clone();
    let ScheduledEventPayload::IoCompletion(changed_completion) = &mut changed.payload else {
        panic!("cloned reply");
    };
    changed_completion.source_delivery.seq += 1;
    let entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: at },
        SchedulerEventLogPayload::ResolvedHappening(original.clone()),
    );
    let changed_entry = scheduler_event_log_entry(
        0,
        VirtualTime { ticks: at },
        SchedulerEventLogPayload::ResolvedHappening(changed),
    );
    assert_ne!(entry.content_hash, changed_entry.content_hash);

    let mut encoded =
        scheduler_event_log_segment_bytes(scheduler_event_log_empty_prefix(), &[entry]);
    assert!(decode_scheduler_event_log_segment(&encoded).is_ok());
    encoded[16..20].copy_from_slice(&4_u32.to_le_bytes());
    assert!(matches!(
        decode_scheduler_event_log_segment(&encoded),
        Err(SchedulerEventLogSegmentDecodeError::UnsupportedVersion { version: 4 }),
    ));
}
