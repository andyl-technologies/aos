//! Ready-point and replacement-backend counter-origin regressions.

use crucible::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, RestartPolicy,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    Shift, SimDuration, SimInstant, SingleScheduler, VirtualTime,
};

fn scheduler_at_ready_counter(material: &str) -> (SingleScheduler, SchedulerNodeId, NodeCounter) {
    scheduler_at_ready_counter_with_lookahead(
        material,
        NetworkLookahead::Finite(SimDuration { nanos: 1 }),
    )
}

fn scheduler_at_ready_counter_with_lookahead(
    material: &str,
    network_lookahead: NetworkLookahead,
) -> (SingleScheduler, SchedulerNodeId, NodeCounter) {
    let node = SchedulerNodeId {
        node: NodeId {
            name: String::from("vm-a"),
        },
        kind: crucible::SchedulingNodeKind::Vm,
    };
    let ready_counter = NodeCounter { ticks: 4_096 };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        material,
        Shift::new(0).unwrap_or_else(|error| panic!("shift should be valid: {error}")),
        32,
        SimInstant { nanos: 32_000 },
        vec![SchedulerScenarioNode {
            id: node.clone(),
            counter: ready_counter,
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
    .with_ready_point_counter(node.clone(), ready_counter);
    let scheduler = SingleScheduler::new(scenario)
        .unwrap_or_else(|error| panic!("scheduler should build: {error}"));
    (scheduler, node, ready_counter)
}

#[test]
fn ready_point_restart_restores_the_admitted_backend_counter() {
    let (mut scheduler, node, ready_counter) =
        scheduler_at_ready_counter("ready-point-backend-counter");

    scheduler
        .apply_node_crash(1, &node.node, RestartPolicy::FromReadyPoint)
        .unwrap_or_else(|error| panic!("ready-point crash should apply: {error}"));
    let restart = scheduler
        .heal_node_crash(2, &node.node)
        .unwrap_or_else(|error| panic!("ready-point heal should restart: {error}"));

    assert!(restart.restarted);
    assert_eq!(restart.counter, ready_counter);
}

#[test]
fn backend_effect_time_restores_the_ready_point_counter_origin() {
    let (mut scheduler, node, _ready_counter) =
        scheduler_at_ready_counter("ready-point-backend-effect");

    assert_eq!(
        scheduler
            .backend_effect_time(&node.node, VirtualTime { ticks: 7 })
            .unwrap_or_else(|error| panic!("backend effect time should project: {error}")),
        VirtualTime { ticks: 4_103 }
    );
    scheduler
        .rebase_restarted_backend_counter(&node.node, NodeCounter { ticks: 8_192 })
        .unwrap_or_else(|error| panic!("replacement backend should rebase: {error}"));
    assert_eq!(
        scheduler
            .backend_effect_time(&node.node, VirtualTime { ticks: 7 })
            .unwrap_or_else(|error| panic!("rebased backend effect time should project: {error}")),
        VirtualTime { ticks: 8_199 }
    );
}

#[test]
fn replay_time_limit_targets_logical_time_from_the_ready_origin() {
    let (mut scheduler, node, ready_counter) = scheduler_at_ready_counter_with_lookahead(
        "ready-point-replay-limit",
        NetworkLookahead::Infinite,
    );
    scheduler
        .set_replay_time_limit(VirtualTime { ticks: 7 })
        .unwrap_or_else(|error| panic!("replay limit should be accepted: {error}"));
    let configuration = scheduler.configuration().clone();
    let outcome = scheduler
        .drive_quantum(crucible::QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("replay-limited quantum should advance: {error}"));
    let ceiling = scheduler
        .backend_step_ceiling(&outcome)
        .unwrap_or_else(|error| panic!("replay ceiling should project: {error}"));

    assert_eq!(
        ceiling,
        VirtualTime {
            ticks: ready_counter.ticks + 7
        }
    );
    assert_eq!(outcome.frontier, VirtualTime { ticks: 7 });
    assert_eq!(outcome.advanced_node, Some(node));
    assert_eq!(
        scheduler
            .scheduler_time_for_node(&NodeId {
                name: String::from("vm-a")
            })
            .unwrap_or_else(|error| panic!("scheduler-owned time should project: {error}")),
        VirtualTime { ticks: 7 }
    );
}

#[test]
fn runtime_branch_cap_stops_without_changing_the_canonical_schedule() {
    let (mut scheduler, _node, _ready_counter) = scheduler_at_ready_counter_with_lookahead(
        "runtime-branch-frontier-cap",
        NetworkLookahead::Infinite,
    );
    let configuration = scheduler.configuration().clone();
    scheduler
        .set_branch_frontier_cap(VirtualTime { ticks: 7 })
        .unwrap_or_else(|error| panic!("branch frontier should be accepted: {error}"));

    let capped = scheduler
        .drive_quantum(crucible::QuantumRequest {
            configuration: configuration.clone(),
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("branch-capped quantum should advance: {error}"));

    assert_eq!(capped.frontier, VirtualTime { ticks: 7 });
    assert!(capped.decisions.is_empty());
    assert_eq!(capped.configuration, configuration);

    scheduler.clear_branch_frontier_cap();
    let uncapped = scheduler
        .drive_quantum(crucible::QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("cleared branch cap should permit progress: {error}"));
    assert!(uncapped.frontier.ticks > capped.frontier.ticks);
}
