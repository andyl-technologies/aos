//! Checks the T-SCHED-8 deterministic event-order key.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    BackendInput, ControlOperation, ControlOperationKind, DecisionRngState, EventSequenceKey,
    EventSequenceState, ExactLocalEvent, MaterializedState, NetworkLookahead, NodeCounter, NodeId,
    QuantumLoop, QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerError, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulerState, SchedulingNodeKind, Shift, SimInstant, SingleScheduler,
    VirtualTime, next_scheduled_event_key, ordered_scheduled_events,
};

#[test]
fn scheduled_event_keys_order_by_virtual_consumer_producer_sequence() {
    let consumer_a = scheduler_node("consumer-a");
    let consumer_b = scheduler_node("consumer-b");
    let producer_a = scheduler_node("producer-a");
    let producer_b = scheduler_node("producer-b");
    let mut events = vec![
        backend_event(4, &consumer_a, &producer_b, 0, b"later-producer"),
        backend_event(5, &consumer_a, &producer_a, 0, b"later-time"),
        backend_event(4, &consumer_b, &producer_a, 0, b"later-consumer"),
        backend_event(4, &consumer_a, &producer_a, 1, b"later-sequence"),
        backend_event(4, &consumer_a, &producer_a, 0, b"first"),
    ];

    let ordered_payloads = ordered_scheduled_events(&events)
        .iter()
        .map(|event| backend_payload(event))
        .collect::<Vec<_>>();

    assert_eq!(
        ordered_payloads,
        vec![
            b"first".to_vec(),
            b"later-sequence".to_vec(),
            b"later-producer".to_vec(),
            b"later-consumer".to_vec(),
            b"later-time".to_vec(),
        ]
    );

    events.reverse();

    let reversed_payloads = ordered_scheduled_events(&events)
        .iter()
        .map(|event| backend_payload(event))
        .collect::<Vec<_>>();

    assert_eq!(reversed_payloads, ordered_payloads);
}

#[test]
fn next_scheduled_event_key_allocates_per_producer_consumer_sequence() {
    let consumer_a = scheduler_node("consumer-a");
    let consumer_b = scheduler_node("consumer-b");
    let producer_a = scheduler_node("producer-a");
    let producer_b = scheduler_node("producer-b");
    let mut sequences = EventSequenceState::empty();

    let first = next_scheduled_event_key(
        &mut sequences,
        VirtualTime { ticks: 7 },
        consumer_a.clone(),
        producer_a.clone(),
    )
    .expect("first sequence should allocate");
    let second = next_scheduled_event_key(
        &mut sequences,
        VirtualTime { ticks: 8 },
        consumer_a.clone(),
        producer_a.clone(),
    )
    .expect("second sequence should allocate");
    let different_consumer = next_scheduled_event_key(
        &mut sequences,
        VirtualTime { ticks: 8 },
        consumer_b.clone(),
        producer_a.clone(),
    )
    .expect("different consumer sequence should allocate");
    let different_producer = next_scheduled_event_key(
        &mut sequences,
        VirtualTime { ticks: 8 },
        consumer_a.clone(),
        producer_b.clone(),
    )
    .expect("different producer sequence should allocate");

    assert_eq!(first.sequence(), 0);
    assert_eq!(second.sequence(), 1);
    assert_eq!(different_consumer.sequence(), 0);
    assert_eq!(different_producer.sequence(), 0);
    assert_eq!(sequences.next_sequence(&producer_a, &consumer_a), 2);
    assert_eq!(sequences.next_sequence(&producer_a, &consumer_b), 1);
    assert_eq!(sequences.next_sequence(&producer_b, &consumer_a), 1);
}

#[test]
fn next_scheduled_event_key_keeps_scheduler_node_kinds_independent() {
    let consumer_vm = scheduler_node("node-a");
    let producer_vm = scheduler_node("node-b");
    let producer_disk = SchedulerNodeId {
        node: producer_vm.node.clone(),
        kind: SchedulingNodeKind::Disk,
    };
    let mut sequences = EventSequenceState::empty();

    let vm_event = next_scheduled_event_key(
        &mut sequences,
        VirtualTime { ticks: 3 },
        consumer_vm.clone(),
        producer_vm.clone(),
    )
    .expect("VM producer sequence should allocate");
    let disk_event = next_scheduled_event_key(
        &mut sequences,
        VirtualTime { ticks: 3 },
        consumer_vm.clone(),
        producer_disk.clone(),
    )
    .expect("disk producer sequence should allocate independently");

    assert_eq!(vm_event.sequence(), 0);
    assert_eq!(disk_event.sequence(), 0);
    assert_eq!(sequences.next_sequence(&producer_vm, &consumer_vm), 1);
    assert_eq!(sequences.next_sequence(&producer_disk, &consumer_vm), 1);
}

#[test]
fn next_scheduled_event_key_rejects_sequence_overflow() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let mut sequences = EventSequenceState {
        next: BTreeMap::from([(
            EventSequenceKey::new(producer.clone(), consumer.clone()),
            u64::MAX,
        )]),
    };

    let error =
        next_scheduled_event_key(&mut sequences, VirtualTime { ticks: 7 }, consumer, producer)
            .expect_err("sequence overflow must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("sequence overflow"));
}

#[test]
fn event_sequence_state_is_carried_in_materialized_scheduler_state_hash() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let mut scheduler = SchedulerState::empty();
    scheduler
        .event_sequences
        .set_next_sequence(producer.clone(), consumer.clone(), 7);
    let with_sequence = materialized_state(scheduler);
    let without_sequence = materialized_state(SchedulerState::empty());

    assert_ne!(with_sequence.id, without_sequence.id);
    assert_eq!(
        with_sequence
            .scheduler
            .event_sequences
            .next_sequence(&producer, &consumer),
        7
    );
}

#[test]
fn single_scheduler_allocates_control_event_keys_from_saved_sequence_state() {
    let control_node = SchedulerNodeId {
        node: node("control-plane"),
        kind: SchedulingNodeKind::ControlPlane,
    };
    let mut scenario = SchedulerLivenessScenario::from_canonical_material(
        "event-sequence-state",
        Shift::new(0).expect("zero shift should be valid"),
        2,
        SimInstant { nanos: 10 },
        vec![SchedulerScenarioNode {
            id: scheduler_node("vm-a"),
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    );
    scenario
        .event_sequences
        .set_next_sequence(control_node.clone(), control_node.clone(), 5);
    let mut scheduler = SingleScheduler::new(scenario).expect("scheduler should build");
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: vec![ControlOperation {
            sequence: 99,
            kind: ControlOperationKind::Query,
        }],
    };

    let outcome = scheduler
        .drive_quantum(request)
        .expect("scheduler should drive one quantum");

    let control_event = outcome
        .resolved_events
        .first()
        .expect("control event should resolve at the boundary");
    assert_eq!(control_event.key.consumer(), &control_node);
    assert_eq!(control_event.key.producer(), &control_node);
    assert_eq!(control_event.key.sequence(), 5);
}

fn materialized_state(scheduler: SchedulerState) -> MaterializedState {
    MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        scheduler,
        DecisionRngState::empty(),
        crucible::EventLogOffset::default(),
    )
}

fn backend_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            sequence,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn backend_payload(event: &ScheduledEvent) -> Vec<u8> {
    match &event.payload {
        ScheduledEventPayload::BackendInput(input) => input.payload.clone(),
        _ => panic!("test event should carry backend input"),
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}
