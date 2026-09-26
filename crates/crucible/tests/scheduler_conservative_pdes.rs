//! Checks the T-SCHED-3 conservative-PDES advance rule.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerError,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, SimDuration, SimInstant, SingleScheduler, VirtualTime,
    authorize_conservative_advance, unresolved_cross_node_dependencies,
};

#[test]
fn conservative_pdes_authorization_clamps_at_unresolved_cross_node_dependency() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let event = backend_event(5, &consumer, &producer, 7, b"frame");

    let authorization = authorize_conservative_advance(
        &consumer,
        SimInstant { ticks: 0 },
        SimInstant { ticks: 10 },
        &[event],
    )
    .expect("future cross-node dependency should clamp, not fail");

    assert_eq!(authorization.authorized_target, SimInstant { ticks: 5 });
    assert_eq!(
        authorization
            .blocking_dependency
            .as_ref()
            .map(|dependency| dependency.virtual_time),
        Some(SimInstant { ticks: 5 })
    );
}

#[test]
fn conservative_pdes_authorization_allows_target_before_dependency() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let event = backend_event(8, &consumer, &producer, 1, b"later");

    let authorization = authorize_conservative_advance(
        &consumer,
        SimInstant { ticks: 2 },
        SimInstant { ticks: 6 },
        &[event],
    )
    .expect("target before dependency should be safe");

    assert_eq!(authorization.authorized_target, SimInstant { ticks: 6 });
    assert!(authorization.blocking_dependency.is_none());
}

#[test]
fn conservative_pdes_authorization_rejects_rollback() {
    let node = scheduler_node("node-a");
    let error = authorize_conservative_advance(
        &node,
        SimInstant { ticks: 8 },
        SimInstant { ticks: 4 },
        &[],
    )
    .expect_err("rollback must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("rejected rollback"));
}

#[test]
fn conservative_pdes_dependencies_only_include_cross_node_backend_input() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let local_event = backend_event(3, &consumer, &consumer, 1, b"local");
    let peer_event = backend_event(4, &consumer, &producer, 2, b"peer");
    let control_plane = scheduler_node("control-plane");
    let control_event = ScheduledEvent {
        key: ScheduledEventKey::new(
            crucible::SharedTimelineKey {
                virtual_time: crucible::SimInstant {
                    ticks: (VirtualTime { ticks: 2 }).ticks,
                },
                node: consumer.clone(),
                sequence: 3,
            },
            control_plane.clone(),
        ),
        payload: ScheduledEventPayload::Control(crucible::ControlOperation {
            sequence: 3,
            kind: crucible::ControlOperationKind::Query,
        }),
    };

    let dependencies =
        unresolved_cross_node_dependencies(&consumer, &[local_event, peer_event, control_event]);

    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].producer, producer);
    assert_eq!(dependencies[0].consumer, consumer);
    assert_eq!(dependencies[0].virtual_time, SimInstant { ticks: 4 });
}

#[test]
fn single_scheduler_stops_at_future_cross_node_dependency_before_horizon() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "conservative-pdes-clamp",
        8,
        SimInstant { ticks: 16 },
        vec![scenario_node(
            "consumer",
            0,
            10,
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![backend_event(4, &consumer, &producer, 9, b"frame")],
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should be valid");
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };

    let outcome = scheduler
        .drive_quantum(request)
        .expect("scheduler should advance to dependency");

    assert_eq!(outcome.advanced_node, Some(consumer));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 4 });
    assert_eq!(outcome.resolved_events.len(), 1);
    assert_eq!(
        outcome.resolved_events[0].key.virtual_time(),
        VirtualTime { ticks: 4 }
    );
}

#[test]
fn single_scheduler_delivers_non_instruction_aligned_dependency_exactly() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "conservative-pdes-exact-dependency",
        8,
        SimInstant { ticks: 16 },
        vec![scenario_node(
            "consumer",
            0,
            10,
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![backend_event(5, &consumer, &producer, 9, b"frame")],
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should be valid");
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };

    let outcome = scheduler
        .drive_quantum(request)
        .expect("the scheduler should preserve the exact event tick");

    assert_eq!(outcome.frontier, VirtualTime { ticks: 5 });
    assert_eq!(outcome.resolved_events.len(), 1);
    assert_eq!(
        outcome.resolved_events[0].key.virtual_time(),
        VirtualTime { ticks: 5 }
    );
}

#[test]
fn single_scheduler_rejects_due_cross_node_dependency_before_advance() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "conservative-pdes-due",
        8,
        SimInstant { ticks: 16 },
        vec![scenario_node(
            "consumer",
            0,
            10,
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![backend_event(0, &consumer, &producer, 9, b"due")],
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should be valid");
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };

    let error = scheduler
        .drive_quantum(request)
        .expect_err("already-due cross-node dependency must fail loudly");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(
        error
            .to_string()
            .contains("unresolved cross-node dependency is due")
    );
}

fn scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: u64,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead: finite_lookahead(network_lookahead),
        exact_local_event,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
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
        key: ScheduledEventKey::new(
            crucible::SharedTimelineKey {
                virtual_time: crucible::SimInstant {
                    ticks: (VirtualTime {
                        ticks: virtual_time,
                    })
                    .ticks,
                },
                node: consumer.clone(),
                sequence,
            },
            producer.clone(),
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { ticks: nanos })
}
