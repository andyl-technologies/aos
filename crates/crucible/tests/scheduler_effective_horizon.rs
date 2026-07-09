//! Checks the T-SCHED-13 effective-horizon PICK/RUN projection.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulerTerminal, SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler,
    VirtualTime, check_scheduler_liveness,
};

#[test]
fn effective_horizon_pick_uses_running_idle_halted_done_projection() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "effective-horizon-mixed-states",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![
            scenario_node(
                "running-high",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(10),
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "idle-wake",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 3 },
                },
            ),
            scenario_node(
                "halted-low",
                0,
                SchedulerNodeActivity::Halted,
                finite_lookahead(1),
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 1 },
                },
            ),
            scenario_node(
                "done-low",
                0,
                SchedulerNodeActivity::Done,
                finite_lookahead(1),
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 2 },
                },
            ),
        ],
        Vec::new(),
    );

    let outcome = drive_one_quantum(scenario);

    assert_eq!(
        outcome.advanced_node,
        Some(scheduler_node("idle-wake", SchedulingNodeKind::Vm))
    );
}

#[test]
fn effective_horizon_ties_by_node_id_after_state_projection() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "effective-horizon-node-id-tie",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![
            scenario_node(
                "node-b",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(5),
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "node-a",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 5 },
                },
            ),
        ],
        Vec::new(),
    );

    let outcome = drive_one_quantum(scenario);

    assert_eq!(
        outcome.advanced_node,
        Some(scheduler_node("node-a", SchedulingNodeKind::Vm))
    );
}

#[test]
fn halted_and_done_nodes_do_not_block_quiescence_with_empty_queues() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "effective-horizon-all-terminal",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![
            scenario_node(
                "halted",
                0,
                SchedulerNodeActivity::Halted,
                finite_lookahead(1),
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 1 },
                },
            ),
            scenario_node(
                "done",
                0,
                SchedulerNodeActivity::Done,
                finite_lookahead(1),
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 2 },
                },
            ),
        ],
        Vec::new(),
    );

    let report = check_scheduler_liveness(scenario).expect("terminal nodes should quiesce");

    assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(report.quanta, 0);
}

#[test]
fn all_infinite_effective_horizons_yield_no_advance_when_queues_are_empty() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "effective-horizon-all-infinite",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![
            scenario_node(
                "idle",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "done",
                0,
                SchedulerNodeActivity::Done,
                finite_lookahead(1),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    ))
    .expect("scenario should build");
    let configuration = scheduler.configuration().clone();

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .expect("all-infinite projection should produce an empty quantum");

    assert_eq!(outcome.advanced_node, None);
    assert!(outcome.resolved_events.is_empty());
    assert!(outcome.decisions.is_empty());
    assert_eq!(outcome.frontier, VirtualTime { ticks: 0 });
}

#[test]
fn run_reaches_horizon_and_never_advances_past_it() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "effective-horizon-run-stops-at-horizon",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(10),
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 4 },
            },
        )],
        Vec::new(),
    );

    let outcome = drive_one_quantum(scenario);

    assert_eq!(
        outcome.advanced_node,
        Some(scheduler_node("runner", SchedulingNodeKind::Vm))
    );
    assert_eq!(outcome.frontier, VirtualTime { ticks: 4 });
    assert!(outcome.resolved_events.is_empty());
}

#[test]
fn run_stops_at_pending_delivery_before_network_horizon() {
    let consumer = scheduler_node("runner", SchedulingNodeKind::Vm);
    let producer = scheduler_node("peer", SchedulingNodeKind::Vm);
    let due = backend_event(5, &consumer, &producer, 1, b"frame");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "effective-horizon-run-stops-at-pending-delivery",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(10),
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![due.clone()],
    );

    let outcome = drive_one_quantum(scenario);

    assert_eq!(outcome.advanced_node, Some(consumer));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 5 });
    assert_eq!(outcome.resolved_events, vec![due]);
}

fn drive_one_quantum(scenario: SchedulerLivenessScenario) -> crucible::QuantumOutcome {
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should be valid");
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    scheduler
        .drive_quantum(request)
        .expect("scheduler should drive one quantum")
}

fn scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event,
    }
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
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
