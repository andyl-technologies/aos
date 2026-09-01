//! Checks T-SCHED-23 partition/heal effective-edge mutations.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    SchedulerError, SchedulerLivenessScenario, SchedulerLookaheadEdge,
    SchedulerLookaheadEdgeEndpoint, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulerTopologyChange, SchedulerTopologyChangeTrigger, SchedulingNodeKind, Shift,
    SimDuration, SimInstant, SingleScheduler, VirtualTime,
};

#[test]
fn partition_removes_one_inbound_edge_and_recomputes_next_minimum() {
    let fast = scheduler_node("fast-producer");
    let slow = scheduler_node("slow-producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "partition-removes-one-inbound-edge",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(5),
        )],
    )
    .with_effective_topology_edges(vec![edge(&fast, &consumer, 5), edge(&slow, &consumer, 17)])
    .with_topology_change(SchedulerTopologyChange::partition(
        1,
        vec![endpoint(&fast, &consumer)],
    ));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer.clone()));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 17 });
    let application = only_topology_application(&scheduler);
    assert_eq!(
        application.trigger,
        SchedulerTopologyChangeTrigger::EdgeRemoval
    );
    assert_eq!(
        application.updates[0].previous_lookahead,
        finite_lookahead(5)
    );
    assert_eq!(
        application.updates[0].recomputed_lookahead,
        finite_lookahead(17)
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&fast, &consumer)
            .is_err()
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&slow, &consumer)
            .is_ok()
    );
}

#[test]
fn partition_last_inbound_edge_recomputes_infinite_lookahead() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "partition-last-inbound-edge",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(9),
        )],
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 9)])
    .with_topology_change(SchedulerTopologyChange::partition(
        2,
        vec![endpoint(&producer, &consumer)],
    ));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer.clone()));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 40 });
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        SimInstant { nanos: 40 }
    );
    let application = only_topology_application(&scheduler);
    assert_eq!(
        application.updates[0].previous_lookahead,
        finite_lookahead(9)
    );
    assert_eq!(
        application.updates[0].recomputed_lookahead,
        NetworkLookahead::Infinite
    );
}

#[test]
fn heal_restores_edge_over_current_partitioned_graph() {
    let fast = scheduler_node("fast-producer");
    let slow = scheduler_node("slow-producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "heal-restores-over-current-partitioned-graph",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(5),
        )],
    )
    .with_effective_topology_edges(vec![edge(&fast, &consumer, 5), edge(&slow, &consumer, 30)])
    .with_topology_change(SchedulerTopologyChange::partition(
        1,
        vec![endpoint(&fast, &consumer)],
    ))
    .with_topology_change(SchedulerTopologyChange::heal(
        2,
        vec![edge(&fast, &consumer, 6)],
    ));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer.clone()));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 6 });
    assert_eq!(scheduler.topology_change_applications().len(), 2);
    let partition = &scheduler.topology_change_applications()[0];
    assert_eq!(
        partition.trigger,
        SchedulerTopologyChangeTrigger::EdgeRemoval
    );
    assert_eq!(
        partition.updates[0].recomputed_lookahead,
        finite_lookahead(30)
    );
    let heal = &scheduler.topology_change_applications()[1];
    assert_eq!(heal.trigger, SchedulerTopologyChangeTrigger::EdgeRestore);
    assert_eq!(heal.updates[0].previous_lookahead, finite_lookahead(30));
    assert_eq!(heal.updates[0].recomputed_lookahead, finite_lookahead(6));
    assert!(
        scheduler
            .authorize_cross_node_send(&fast, &consumer)
            .is_ok()
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&slow, &consumer)
            .is_ok()
    );
}

#[test]
fn partition_removed_edge_blocks_send_until_heal_restores_it() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "partition-blocks-send-before-heal",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(8),
        )],
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 8)])
    .with_topology_change(SchedulerTopologyChange::partition(
        1,
        vec![endpoint(&producer, &consumer)],
    ));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    drive_one_quantum(&mut scheduler);
    let error = scheduler
        .authorize_cross_node_send(&producer, &consumer)
        .expect_err("partitioned edge must block sends");
    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));

    scheduler.queue_topology_change(SchedulerTopologyChange::heal(
        2,
        vec![edge(&producer, &consumer, 8)],
    ));
    drive_one_quantum(&mut scheduler);

    let authorization = scheduler
        .authorize_cross_node_send(&producer, &consumer)
        .expect("healed edge should authorize sends");
    assert_eq!(authorization.topology_epoch, 2);
}

fn base_scenario(material: &str, nodes: Vec<SchedulerScenarioNode>) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        material,
        shift(0),
        8,
        SimInstant { nanos: 40 },
        nodes,
        Vec::new(),
    )
}

fn drive_one_quantum(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should drive one quantum")
}

fn only_topology_application(
    scheduler: &SingleScheduler,
) -> &crucible::SchedulerTopologyChangeApplication {
    assert_eq!(scheduler.topology_change_applications().len(), 1);
    &scheduler.topology_change_applications()[0]
}

fn scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
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

fn edge(from: &SchedulerNodeId, to: &SchedulerNodeId, latency_ns: u64) -> SchedulerLookaheadEdge {
    SchedulerLookaheadEdge::new(from.clone(), to.clone(), duration(latency_ns))
}

fn endpoint(from: &SchedulerNodeId, to: &SchedulerNodeId) -> SchedulerLookaheadEdgeEndpoint {
    SchedulerLookaheadEdgeEndpoint::new(from.clone(), to.clone())
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(duration(nanos))
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
