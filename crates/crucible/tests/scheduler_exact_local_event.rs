//! Checks the T-SCHED-6 exact-local event reducer.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ExactLocalEvent, FaultId, Icount, IoCompletion, NetworkLookahead, NodeCounter,
    NodeId, QuantumLoop, QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerError, SchedulerHorizon, SchedulerHorizonLimit, SchedulerHorizonSource,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler, VirtualTime,
    horizon_from_network_lookahead, next_exact_local_event,
};

#[test]
fn next_exact_local_event_selects_earliest_timer_io_or_fault() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
    let events = vec![
        fault_event(20, &node, "fault-later"),
        io_event(12, &node, &disk, b"io-earliest"),
    ];

    let exact = next_exact_local_event(
        &node,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos: 30 },
        },
        &events,
        shift(0),
    )
    .expect("exact local event should reduce");

    assert_eq!(
        exact,
        ExactLocalEvent::IoCompletion {
            virtual_time: SimInstant { nanos: 12 },
            sub_node: disk,
        }
    );
}

#[test]
fn next_exact_local_event_uses_fault_when_it_is_earliest() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
    let events = vec![
        io_event(20, &node, &disk, b"io-later"),
        fault_event(9, &node, "fault-earliest"),
    ];

    let exact = next_exact_local_event(
        &node,
        ExactLocalEvent::TimerDeadline {
            virtual_time: SimInstant { nanos: 12 },
        },
        &events,
        shift(0),
    )
    .expect("exact local event should reduce");

    assert_eq!(
        exact,
        ExactLocalEvent::FaultActivation {
            virtual_time: SimInstant { nanos: 9 },
            fault: FaultId {
                name: String::from("fault-earliest"),
            },
        }
    );
}

#[test]
fn next_exact_local_event_converts_io_delivery_icount_with_shift() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let ninep = scheduler_node("node-a", SchedulingNodeKind::NineP);
    let events = vec![io_event_at_virtual_time(14, 7, &node, &ninep, b"ninep")];

    let exact = next_exact_local_event(&node, ExactLocalEvent::NoArmedTimer, &events, shift(1))
        .expect("exact local event should reduce");

    assert_eq!(
        exact,
        ExactLocalEvent::IoCompletion {
            virtual_time: SimInstant { nanos: 14 },
            sub_node: ninep,
        }
    );
}

#[test]
fn next_exact_local_event_rejects_inconsistent_io_delivery_time() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
    let events = vec![io_event_at_virtual_time(9, 7, &node, &disk, b"stale-key")];

    let error = next_exact_local_event(&node, ExactLocalEvent::NoArmedTimer, &events, shift(1))
        .expect_err("inconsistent I/O timing must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("does not match delivery icount"));
}

#[test]
fn next_exact_local_event_rejects_io_target_mismatch() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let other = scheduler_node("node-b", SchedulingNodeKind::Vm);
    let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
    let mut event = io_event_at_virtual_time(7, 7, &node, &disk, b"wrong-target");
    if let ScheduledEventPayload::IoCompletion(completion) = &mut event.payload {
        completion.target = other.node;
    }
    let events = vec![event];

    let error = next_exact_local_event(&node, ExactLocalEvent::NoArmedTimer, &events, shift(0))
        .expect_err("I/O target mismatch must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("does not match payload target"));
}

#[test]
fn next_exact_local_event_ignores_network_input_and_other_nodes() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let peer = scheduler_node("node-b", SchedulingNodeKind::Vm);
    let peer_disk = scheduler_node("node-b", SchedulingNodeKind::Disk);
    let events = vec![
        backend_event(3, &node, &peer, b"network"),
        io_event(4, &peer, &peer_disk, b"other-io"),
        fault_event(5, &peer, "other-fault"),
    ];

    let exact = next_exact_local_event(&node, ExactLocalEvent::NoArmedTimer, &events, shift(0))
        .expect("exact local event should reduce");

    assert_eq!(exact, ExactLocalEvent::NoArmedTimer);
}

#[test]
fn single_scheduler_uses_pending_io_completion_as_exact_local_horizon() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "exact-local-io-horizon",
        shift(1),
        8,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "node-a",
            0,
            NetworkLookahead::Finite(SimDuration { nanos: 30 }),
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![io_event_at_virtual_time(14, 7, &node, &disk, b"ready")],
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should be valid");
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };

    let outcome = scheduler
        .drive_quantum(request)
        .expect("scheduler should drive to the I/O completion");

    assert_eq!(outcome.advanced_node, Some(node));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 14 });
    assert_eq!(outcome.resolved_events.len(), 1);
    assert_eq!(
        outcome.resolved_events[0].key.virtual_time(),
        VirtualTime { ticks: 14 }
    );
}

#[test]
fn single_scheduler_uses_pending_fault_as_exact_local_horizon() {
    let node = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "exact-local-fault-horizon",
        shift(0),
        8,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "node-a",
            0,
            NetworkLookahead::Finite(SimDuration { nanos: 30 }),
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![fault_event(11, &node, "fault-ready")],
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should be valid");
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };

    let outcome = scheduler
        .drive_quantum(request)
        .expect("scheduler should drive to the fault activation");

    assert_eq!(outcome.advanced_node, Some(node));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 11 });
    assert_eq!(outcome.resolved_events.len(), 1);
    assert!(matches!(
        outcome.resolved_events[0].payload,
        ScheduledEventPayload::FaultActivation(_)
    ));
}

#[test]
fn horizon_uses_io_completion_as_exact_local_source() {
    let disk = scheduler_node("node-a", SchedulingNodeKind::Disk);
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 10 },
        NetworkLookahead::Finite(SimDuration { nanos: 20 }),
        ExactLocalEvent::IoCompletion {
            virtual_time: SimInstant { nanos: 14 },
            sub_node: disk,
        },
        shift(0),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 14 },
                ceiling: Icount { retired: 14 },
            },
            source: SchedulerHorizonSource::ExactLocalIoCompletion,
        })
    );
}

#[test]
fn horizon_uses_fault_activation_as_exact_local_source() {
    let horizon = horizon_from_network_lookahead(
        SimInstant { nanos: 10 },
        NetworkLookahead::Finite(SimDuration { nanos: 20 }),
        ExactLocalEvent::FaultActivation {
            virtual_time: SimInstant { nanos: 16 },
            fault: FaultId {
                name: String::from("local-fault"),
            },
        },
        shift(0),
    );

    assert_eq!(
        horizon,
        Ok(SchedulerHorizon {
            limit: SchedulerHorizonLimit::Finite {
                virtual_time: SimInstant { nanos: 16 },
                ceiling: Icount { retired: 16 },
            },
            source: SchedulerHorizonSource::ExactLocalFault,
        })
    );
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}

fn io_event(
    delivery_icount: u64,
    consumer: &SchedulerNodeId,
    sub_node: &SchedulerNodeId,
    payload: &[u8],
) -> ScheduledEvent {
    io_event_at_virtual_time(
        delivery_icount,
        delivery_icount,
        consumer,
        sub_node,
        payload,
    )
}

fn io_event_at_virtual_time(
    virtual_time: u64,
    delivery_icount: u64,
    consumer: &SchedulerNodeId,
    sub_node: &SchedulerNodeId,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            sub_node.clone(),
            delivery_icount,
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

fn fault_event(virtual_time: u64, consumer: &SchedulerNodeId, fault_name: &str) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            consumer.clone(),
            virtual_time,
        ),
        payload: ScheduledEventPayload::FaultActivation(FaultId {
            name: fault_name.to_owned(),
        }),
    }
}

fn backend_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            virtual_time,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead,
        exact_local_event,
    }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
