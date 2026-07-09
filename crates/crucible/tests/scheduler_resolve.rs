//! Checks the T-SCHED-16 RESOLVE phase.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, Decision, EventKey, ExactLocalEvent, FaultId, Icount, IoCompletion,
    NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest, ScheduledEvent,
    ScheduledEventKey, ScheduledEventPayload, ScheduledEventResolveClass, SchedulerError,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler, VirtualTime,
    ordered_scheduled_events, resolve_due_scheduled_events, scheduled_event_delivery_time,
    scheduled_event_resolve_class,
};

#[test]
fn resolve_quantum_processes_frame_io_and_fault_at_exact_delivery_icount_in_total_order() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let frame_producer = scheduler_node("alpha-frame", SchedulingNodeKind::Vm);
    let disk = scheduler_node("beta-disk", SchedulingNodeKind::Disk);
    let fault_source = scheduler_node("gamma-fault", SchedulingNodeKind::Vm);
    let frame = backend_event(5, &consumer, &frame_producer, 2, b"frame");
    let io = io_event(5, &consumer, &disk, 1, b"io");
    let fault = fault_event(5, &consumer, &fault_source, 0, "fault");
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "resolve-mixed-payloads",
        shift(0),
        8,
        SimInstant { nanos: 30 },
        vec![scenario_node("consumer", 0, finite_lookahead(10))],
        vec![fault.clone(), frame.clone(), io.clone()],
    ))
    .expect("scenario should build");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should resolve the mixed due set");

    assert_eq!(outcome.advanced_node, Some(consumer));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 5 });
    assert_eq!(
        outcome.resolved_events,
        vec![frame.clone(), io.clone(), fault.clone()]
    );
    assert_eq!(
        resolve_classes(&outcome.resolved_events),
        vec![
            ScheduledEventResolveClass::FrameDelivery,
            ScheduledEventResolveClass::IoCompletion,
            ScheduledEventResolveClass::FaultActivation,
        ]
    );
    assert_eq!(
        delivery_times(&outcome.resolved_events),
        vec![
            SimInstant { nanos: 5 },
            SimInstant { nanos: 5 },
            SimInstant { nanos: 5 },
        ]
    );
    assert_eq!(
        delivery_order(&outcome.decisions),
        outcome
            .resolved_events
            .iter()
            .map(event_key)
            .collect::<Vec<_>>()
    );
}

#[test]
fn resolve_due_events_are_independent_of_pending_transport_order() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let other = scheduler_node("other", SchedulingNodeKind::Vm);
    let producer_a = scheduler_node("producer-a", SchedulingNodeKind::Vm);
    let producer_b = scheduler_node("producer-b", SchedulingNodeKind::Vm);
    let due_first = backend_event(4, &consumer, &producer_a, 0, b"due-first");
    let due_second = backend_event(4, &consumer, &producer_b, 0, b"due-second");
    let future = backend_event(7, &consumer, &producer_a, 1, b"future");
    let other_consumer = backend_event(3, &other, &producer_a, 0, b"other");
    let mut first_pending = vec![
        future.clone(),
        due_second.clone(),
        other_consumer.clone(),
        due_first.clone(),
    ];
    let mut second_pending = vec![
        due_first.clone(),
        other_consumer.clone(),
        due_second.clone(),
        future.clone(),
    ];

    let first = resolve_due_scheduled_events(
        &mut first_pending,
        &consumer,
        SimInstant { nanos: 4 },
        shift(0),
    )
    .expect("first pending order should resolve");
    let second = resolve_due_scheduled_events(
        &mut second_pending,
        &consumer,
        SimInstant { nanos: 4 },
        shift(0),
    )
    .expect("second pending order should resolve");

    assert_eq!(first, vec![due_first, due_second]);
    assert_eq!(second, first);
    assert_eq!(
        ordered_event_keys(&first_pending),
        vec![event_key(&other_consumer), event_key(&future)]
    );
    assert_eq!(
        ordered_event_keys(&second_pending),
        ordered_event_keys(&first_pending)
    );
}

#[test]
fn resolve_rejects_backend_input_with_mismatched_payload_target() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let producer = scheduler_node("producer", SchedulingNodeKind::Vm);
    let mut event = backend_event(4, &consumer, &producer, 0, b"wrong-target");
    if let ScheduledEventPayload::BackendInput(input) = &mut event.payload {
        input.node = node("wrong-target");
    }
    let mut pending = vec![event];

    let error =
        resolve_due_scheduled_events(&mut pending, &consumer, SimInstant { nanos: 4 }, shift(0))
            .expect_err("backend input target mismatch must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("backend input key consumer"));
    assert_eq!(pending.len(), 1);
}

#[test]
fn resolve_rejects_late_event_before_advanced_frontier() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let producer = scheduler_node("producer", SchedulingNodeKind::Vm);
    let event = backend_event(3, &consumer, &producer, 0, b"late");
    let mut pending = vec![event];

    let error =
        resolve_due_scheduled_events(&mut pending, &consumer, SimInstant { nanos: 4 }, shift(0))
            .expect_err("late delivery must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("late scheduled event"));
    assert!(error.to_string().contains("delivery=3"));
    assert!(error.to_string().contains("advanced_to=4"));
    assert_eq!(pending.len(), 1);
}

#[test]
fn single_scheduler_rejects_self_delivery_that_would_be_late() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "resolve-late-self-delivery",
        shift(0),
        8,
        SimInstant { nanos: 30 },
        vec![scenario_node("consumer", 5, finite_lookahead(10))],
        vec![backend_event(4, &consumer, &consumer, 0, b"late-self")],
    ))
    .expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("late self-delivery must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("late scheduled event"));
    assert!(error.to_string().contains("delivery=4"));
}

#[test]
fn resolve_leaves_future_backend_input_unvalidated_until_due() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let producer = scheduler_node("producer", SchedulingNodeKind::Vm);
    let mut event = backend_event(9, &consumer, &producer, 0, b"future-wrong-target");
    if let ScheduledEventPayload::BackendInput(input) = &mut event.payload {
        input.node = node("wrong-target");
    }
    let mut pending = vec![event.clone()];

    let resolved =
        resolve_due_scheduled_events(&mut pending, &consumer, SimInstant { nanos: 4 }, shift(0))
            .expect("future events should not be validated by this RESOLVE quantum");

    assert!(resolved.is_empty());
    assert_eq!(pending, vec![event]);
}

#[test]
fn resolve_rejects_io_completion_with_non_exact_delivery_icount() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let disk = scheduler_node("disk", SchedulingNodeKind::Disk);
    let mut pending = vec![io_event_at_virtual_time(
        6, 5, &consumer, &disk, 0, b"bad-io",
    )];

    let error =
        resolve_due_scheduled_events(&mut pending, &consumer, SimInstant { nanos: 6 }, shift(0))
            .expect_err("I/O visibility mismatch must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("does not match delivery icount"));
    assert_eq!(pending.len(), 1);
}

fn delivery_order(decisions: &[Decision]) -> Vec<EventKey> {
    decisions
        .iter()
        .flat_map(|decision| match decision {
            Decision::DeliveryOrder(order) => order.order.clone(),
            Decision::FaultFires(_)
            | Decision::RngDraw(_)
            | Decision::Override(_)
            | Decision::Preemption(_)
            | Decision::AppRandom(_)
            | Decision::ControlFault(_) => Vec::new(),
        })
        .collect()
}

fn resolve_classes(events: &[ScheduledEvent]) -> Vec<ScheduledEventResolveClass> {
    events.iter().map(scheduled_event_resolve_class).collect()
}

fn delivery_times(events: &[ScheduledEvent]) -> Vec<SimInstant> {
    events
        .iter()
        .map(|event| {
            scheduled_event_delivery_time(event, shift(0))
                .expect("test event should have an exact visibility time")
        })
        .collect()
}

fn ordered_event_keys(events: &[ScheduledEvent]) -> Vec<EventKey> {
    ordered_scheduled_events(events)
        .into_iter()
        .map(event_key)
        .collect()
}

fn event_key(event: &ScheduledEvent) -> EventKey {
    EventKey::new(
        event.key.virtual_time(),
        event.key.consumer().clone(),
        event.key.producer().clone(),
        event.key.sequence(),
    )
}

fn scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: NetworkLookahead,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
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

fn io_event(
    delivery_icount: u64,
    consumer: &SchedulerNodeId,
    sub_node: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    io_event_at_virtual_time(
        delivery_icount,
        delivery_icount,
        consumer,
        sub_node,
        sequence,
        payload,
    )
}

fn io_event_at_virtual_time(
    virtual_time: u64,
    delivery_icount: u64,
    consumer: &SchedulerNodeId,
    sub_node: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            sub_node.clone(),
            sequence,
        ),
        payload: ScheduledEventPayload::IoCompletion(IoCompletion {
            sub_node: sub_node.clone(),
            target: consumer.node.clone(),
            delivery_icount: Icount {
                retired: delivery_icount,
            },
            payload: payload.to_vec(),
        }),
    }
}

fn fault_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    fault_name: &str,
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
        payload: ScheduledEventPayload::FaultActivation(FaultId {
            name: fault_name.to_owned(),
        }),
    }
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind,
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
