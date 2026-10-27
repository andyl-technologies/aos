//! Checks exact scheduler wakeups requested by signal-driven fault bindings.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup.
#![allow(clippy::expect_used)]

use crucible_engine::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, SimInstant, SingleScheduler, VirtualTime,
};

#[test]
fn signal_fault_wakeup_advances_idle_shared_frontier_exactly() {
    let mut scheduler = SingleScheduler::new(scenario(vec![idle_node("b"), idle_node("a")]))
        .expect("scenario should build");
    scheduler
        .set_signal_fault_wakeup(Some(40))
        .expect("future wakeup should arm");

    assert_eq!(
        scheduler.signal_fault_wakeup(),
        Some(SimInstant { ticks: 40 })
    );
    assert!(
        !scheduler
            .quiescence()
            .expect("quiescence should compute")
            .is_quiescent()
    );

    for _ in 0..2 {
        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        };
        scheduler
            .drive_quantum(request)
            .expect("idle node should fast-forward to signal wakeup");
    }

    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 40 });
    assert_eq!(
        scheduler.signal_fault_wakeup(),
        Some(SimInstant { ticks: 40 })
    );
}

#[test]
fn signal_fault_wakeup_rejects_current_or_past_coordinates() {
    let mut scheduler =
        SingleScheduler::new(scenario(vec![idle_node("a")])).expect("scenario should build");

    assert!(scheduler.set_signal_fault_wakeup(Some(0)).is_err());
    assert_eq!(scheduler.signal_fault_wakeup(), None);
}

#[test]
fn signal_fault_wakeup_preserves_fractional_tick_coordinate() {
    let mut scheduler =
        SingleScheduler::new(scenario(vec![idle_node("a")])).expect("scenario should build");

    scheduler
        .set_signal_fault_wakeup(Some(6))
        .expect("exact wakeup should arm");
    assert_eq!(
        scheduler.signal_fault_wakeup(),
        Some(SimInstant { ticks: 6 })
    );
}

#[test]
fn signal_fault_wakeup_refuses_a_coordinate_a_skewed_live_node_passed() {
    // Nodes keep their own clocks: `z` already settled through 50 while the
    // shared frontier is still 0.
    let mut scheduler = SingleScheduler::new(scenario(vec![
        node_at("a", 0, SchedulerNodeActivity::Idle),
        node_at("z", 50, SchedulerNodeActivity::Idle),
    ]))
    .expect("scenario should build");

    let error = scheduler
        .set_signal_fault_wakeup(Some(20))
        .expect_err("an evaluation behind a live node must fail closed");

    assert!(
        error.to_string().contains("behind live node z"),
        "unexpected refusal: {error}"
    );
    assert_eq!(scheduler.signal_fault_wakeup(), None);
    scheduler
        .set_signal_fault_wakeup(Some(50))
        .expect("a node exactly at the coordinate has not passed it");
    scheduler
        .set_signal_fault_wakeup(Some(60))
        .expect("a coordinate ahead of every node arms");
}

#[test]
fn signal_fault_wakeup_ignores_halted_nodes_beyond_it() {
    // A halted node acts only on an input, which the evaluation precedes.
    let mut scheduler = SingleScheduler::new(scenario(vec![
        node_at("a", 0, SchedulerNodeActivity::Idle),
        node_at("z", 50, SchedulerNodeActivity::Halted),
    ]))
    .expect("scenario should build");

    scheduler
        .set_signal_fault_wakeup(Some(20))
        .expect("a halted node does not block an earlier evaluation");
}

#[test]
fn an_armed_signal_fault_wakeup_bounds_every_skewed_node() {
    let mut scheduler = SingleScheduler::new(scenario(vec![
        node_at("a", 0, SchedulerNodeActivity::Idle),
        node_at("z", 10, SchedulerNodeActivity::Idle),
    ]))
    .expect("scenario should build");
    scheduler
        .set_signal_fault_wakeup(Some(40))
        .expect("future wakeup should arm");

    for _ in 0..4 {
        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        };
        scheduler
            .drive_quantum(request)
            .expect("idle nodes should fast-forward to the wakeup");
    }

    // Neither the lagging nor the leading node passes the evaluation point.
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 40 });
    for name in ["a", "z"] {
        let node = NodeId {
            name: name.to_owned(),
        };
        let counter = scheduler
            .scheduler_counter_for_node(&node)
            .expect("node counter should project");
        assert_eq!(counter, NodeCounter { ticks: 40 }, "{name} left the wakeup");
    }
}

fn scenario(nodes: Vec<SchedulerScenarioNode>) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        "signal-fault-wakeup",
        8,
        SimInstant { ticks: 100 },
        nodes,
        Vec::new(),
    )
}

fn idle_node(name: &str) -> SchedulerScenarioNode {
    node_at(name, 0, SchedulerNodeActivity::Idle)
}

fn node_at(name: &str, counter: u64, activity: SchedulerNodeActivity) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: SchedulerNodeId {
            node: NodeId {
                name: name.to_owned(),
            },
            kind: SchedulingNodeKind::Vm,
        },
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead: NetworkLookahead::Infinite,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}
