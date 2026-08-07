//! Checks exact scheduler wakeups requested by signal-driven fault bindings.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup.
#![allow(clippy::expect_used)]

use crucible::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, Shift, SimInstant, SingleScheduler, VirtualTime,
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
        Some(SimInstant { nanos: 40 })
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
        Some(SimInstant { nanos: 40 })
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
fn signal_fault_wakeup_rounds_unrepresentable_virtual_coordinates_upward() {
    let mut scenario = scenario(vec![idle_node("a")]);
    scenario.shift = Shift::new(2).expect("shift should be valid");
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    scheduler
        .set_signal_fault_wakeup(Some(6))
        .expect("unaligned wakeup should round upward");
    assert_eq!(
        scheduler.signal_fault_wakeup(),
        Some(SimInstant { nanos: 8 })
    );
}

fn scenario(nodes: Vec<SchedulerScenarioNode>) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        "signal-fault-wakeup",
        Shift::new(0).expect("zero shift should be valid"),
        8,
        SimInstant { nanos: 100 },
        nodes,
        Vec::new(),
    )
}

fn idle_node(name: &str) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: SchedulerNodeId {
            node: NodeId {
                name: name.to_owned(),
            },
            kind: SchedulingNodeKind::Vm,
        },
        counter: NodeCounter { ticks: 0 },
        activity: SchedulerNodeActivity::Idle,
        network_lookahead: NetworkLookahead::Infinite,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}
