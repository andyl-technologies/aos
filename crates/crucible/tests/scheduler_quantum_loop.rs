//! Checks the T-SCHED-12 quantum loop as the atomic scheduler step.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, Configuration, ControlOperation, ControlOperationKind, Decision, EventKey,
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerError,
    SchedulerLivenessReport, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulerTerminal, SchedulingNodeKind, Shift, SimDuration, SimInstant,
    SingleScheduler, VirtualTime, check_scheduler_liveness, step,
};

#[test]
fn quantum_loop_pick_run_resolve_and_step_are_one_atomic_boundary() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let due = backend_event(4, &consumer, &producer, 7, b"first");
    let later = backend_event(7, &consumer, &producer, 8, b"later");
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "quantum-loop-atomic-boundary",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "consumer",
            0,
            finite_lookahead(10),
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![later.clone(), due.clone()],
    ))
    .expect("scenario should build");
    let input = scheduler.configuration().clone();

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: input.clone(),
            control: Vec::new(),
        })
        .expect("scheduler should drive one quantum");

    assert_eq!(outcome.advanced_node, Some(consumer.clone()));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 4 });
    assert_eq!(outcome.resolved_events, vec![due]);
    assert_eq!(
        delivery_order(&outcome.decisions),
        vec![EventKey::new(
            VirtualTime { ticks: 4 },
            consumer,
            producer,
            7,
        )]
    );
    assert_eq!(
        outcome.configuration,
        apply_decisions(&input, &outcome.decisions)
    );
    assert_eq!(scheduler.configuration(), &outcome.configuration);
}

#[test]
fn quantum_loop_sequence_is_pure_for_identical_scenario_inputs() {
    let first = check_scheduler_liveness(pure_sequence_scenario())
        .expect("first scheduler run should terminate");
    let second = check_scheduler_liveness(pure_sequence_scenario())
        .expect("second scheduler run should terminate");

    assert_eq!(first.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(first, second);
    assert_eq!(
        delivery_order_from_report(&first),
        vec![
            EventKey::new(
                VirtualTime { ticks: 3 },
                scheduler_node("node-a"),
                scheduler_node("node-b"),
                1,
            ),
            EventKey::new(
                VirtualTime { ticks: 6 },
                scheduler_node("node-b"),
                scheduler_node("node-a"),
                2,
            ),
        ]
    );
}

#[test]
fn quantum_loop_scheduler_state_contributes_to_effective_scenario_def() {
    let node_a = scheduler_node("node-a");
    let node_b = scheduler_node("node-b");
    let first = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "same-authored-material",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "node-a",
            0,
            finite_lookahead(10),
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![backend_event(3, &node_a, &node_b, 1, b"a")],
    ))
    .expect("first scenario should build");
    let second = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "same-authored-material",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "node-b",
            0,
            finite_lookahead(10),
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![backend_event(3, &node_b, &node_a, 1, b"b")],
    ))
    .expect("second scenario should build");

    assert_ne!(
        first.configuration().def.id(),
        second.configuration().def.id()
    );
}

#[test]
fn quantum_loop_steps_boundary_control_when_no_node_advances() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "control-only-boundary",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![SchedulerScenarioNode {
            id: scheduler_node("idle"),
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Idle,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    ))
    .expect("scenario should build");
    let input = scheduler.configuration().clone();

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: input.clone(),
            control: vec![ControlOperation {
                sequence: 1,
                kind: ControlOperationKind::Query,
            }],
        })
        .expect("control-only quantum should drive");

    assert_eq!(outcome.advanced_node, None);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 0 });
    assert_eq!(outcome.resolved_events.len(), 1);
    assert_eq!(
        delivery_order(&outcome.decisions),
        vec![EventKey::new(
            VirtualTime { ticks: 0 },
            control_node(),
            control_node(),
            0,
        )]
    );
    assert_eq!(
        outcome.configuration,
        apply_decisions(&input, &outcome.decisions)
    );
    assert_eq!(scheduler.configuration(), &outcome.configuration);
}

#[test]
fn quantum_loop_rejects_non_frontier_configuration_request() {
    let mut scheduler =
        SingleScheduler::new(pure_sequence_scenario()).expect("scenario should build");
    let stale = Configuration::genesis(crucible::ScenarioDef::from_canonical_material(
        "crucible.test.scheduler-quantum-loop.stale",
        "scenario=stale",
    ));

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: stale,
            control: Vec::new(),
        })
        .expect_err("non-frontier configuration must fail");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("scheduler frontier"));
}

fn pure_sequence_scenario() -> SchedulerLivenessScenario {
    let node_a = scheduler_node("node-a");
    let node_b = scheduler_node("node-b");
    SchedulerLivenessScenario::from_canonical_material(
        "quantum-loop-pure-sequence",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![
            scenario_node(
                "node-a",
                0,
                finite_lookahead(10),
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "node-b",
                0,
                finite_lookahead(10),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        vec![
            backend_event(6, &node_b, &node_a, 2, b"b"),
            backend_event(3, &node_a, &node_b, 1, b"a"),
        ],
    )
}

fn apply_decisions(configuration: &Configuration, decisions: &[Decision]) -> Configuration {
    let mut next = configuration.clone();
    for decision in decisions {
        next = step(&next, decision.clone());
    }
    next
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
            | Decision::AppRandom(_) => Vec::new(),
        })
        .collect()
}

fn delivery_order_from_report(report: &SchedulerLivenessReport) -> Vec<EventKey> {
    delivery_order(report.final_configuration.schedule.decisions())
}

fn scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead,
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

fn control_node() -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: String::from("control-plane"),
        },
        kind: SchedulingNodeKind::ControlPlane,
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

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
