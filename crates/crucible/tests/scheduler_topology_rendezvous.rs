//! Checks T-SCHED-24 topology swaps at exact activation rendezvous times.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    SchedulerLivenessScenario, SchedulerLookaheadEdge, SchedulerLookaheadEdgeEndpoint,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulerTopologyChange,
    SchedulerTopologyChangeTrigger, SchedulingNodeKind, Shift, SimDuration, SimInstant,
    SingleScheduler, VirtualTime,
};

#[test]
fn activation_rendezvous_caps_at_fault_time_not_fixed_tick() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let activation_time = instant(7);
    let scenario = base_scenario(
        "activation-rendezvous-caps-at-fault-time",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
        )],
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_rendezvous_interval(duration(100))
    .expect("rendezvous interval should be valid")
    .with_topology_change(
        SchedulerTopologyChange::new(
            1,
            SchedulerTopologyChangeTrigger::LatencyChange,
            vec![edge(&producer, &consumer, 3)],
        )
        .with_activation_time(activation_time),
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 7 });
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        activation_time
    );
    assert!(scheduler.topology_change_applications().is_empty());
}

#[test]
fn timed_topology_change_applies_after_activation_before_next_pick() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let activation_time = instant(7);
    let scenario = base_scenario(
        "timed-topology-applies-after-activation-before-pick",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
        )],
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_topology_change(
        SchedulerTopologyChange::new(
            2,
            SchedulerTopologyChangeTrigger::EdgeRemoval,
            vec![edge(&producer, &consumer, 3)],
        )
        .with_activation_time(activation_time),
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    drive_one_quantum(&mut scheduler);
    assert!(scheduler.topology_change_applications().is_empty());

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer.clone()));
    assert_eq!(
        scheduler.run_ceiling_publications()[1].target_time,
        instant(10)
    );
    let application = only_topology_application(&scheduler);
    assert_eq!(application.activation_time, Some(activation_time));
    assert_eq!(
        application.trigger,
        SchedulerTopologyChangeTrigger::EdgeRemoval
    );
    assert_eq!(application.updates[0].node, consumer);
    assert_eq!(
        application.updates[0].previous_lookahead,
        finite_lookahead(20)
    );
    assert_eq!(
        application.updates[0].recomputed_lookahead,
        finite_lookahead(3)
    );
}

#[test]
fn timed_topology_change_continues_after_old_horizon_before_activation() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let activation_time = instant(7);
    let scenario = base_scenario(
        "timed-topology-continues-after-old-horizon",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
        )],
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 5)])
    .with_topology_change(
        SchedulerTopologyChange::new(
            4,
            SchedulerTopologyChangeTrigger::EdgeRemoval,
            vec![edge(&producer, &consumer, 3)],
        )
        .with_activation_time(activation_time),
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let first = drive_one_quantum(&mut scheduler);
    assert_eq!(first.frontier, VirtualTime { ticks: 5 });
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        instant(5)
    );
    assert!(scheduler.topology_change_applications().is_empty());

    let second = drive_one_quantum(&mut scheduler);
    assert_eq!(second.frontier, VirtualTime { ticks: 7 });
    assert_eq!(
        scheduler.run_ceiling_publications()[1].target_time,
        activation_time
    );
    assert!(scheduler.topology_change_applications().is_empty());

    drive_one_quantum(&mut scheduler);
    assert_eq!(
        scheduler.run_ceiling_publications()[2].target_time,
        instant(10)
    );
    assert_eq!(
        only_topology_application(&scheduler).activation_time,
        Some(activation_time)
    );
}

#[test]
fn timed_topology_change_advances_idle_no_wake_node_to_activation() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let activation_time = instant(7);
    let scenario = base_scenario(
        "timed-topology-advances-idle-no-wake-node",
        vec![scenario_node("consumer", 0, SchedulerNodeActivity::Idle)],
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_topology_change(
        SchedulerTopologyChange::partition(5, vec![endpoint(&producer, &consumer)])
            .with_activation_time(activation_time),
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let first = drive_one_quantum(&mut scheduler);
    assert_eq!(first.advanced_node, Some(consumer));
    assert_eq!(first.frontier, VirtualTime { ticks: 7 });
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        activation_time
    );
    assert!(scheduler.topology_change_applications().is_empty());

    let second = drive_one_quantum(&mut scheduler);
    assert_eq!(second.advanced_node, None);
    assert_eq!(
        only_topology_application(&scheduler).activation_time,
        Some(activation_time)
    );
}

#[test]
fn ready_timed_change_keeps_sequence_order_with_immediate_change() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let activation_time = instant(7);
    let scenario = base_scenario(
        "ready-timed-change-keeps-sequence-order",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
        )],
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_topology_change(
        SchedulerTopologyChange::partition(1, vec![endpoint(&producer, &consumer)])
            .with_activation_time(activation_time),
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    drive_one_quantum(&mut scheduler);
    scheduler.queue_topology_change(SchedulerTopologyChange::heal(
        2,
        vec![edge(&producer, &consumer, 6)],
    ));

    drive_one_quantum(&mut scheduler);

    assert_eq!(scheduler.topology_change_applications().len(), 2);
    assert_eq!(scheduler.topology_change_applications()[0].sequence, 1);
    assert_eq!(scheduler.topology_change_applications()[1].sequence, 2);
    assert_eq!(
        scheduler.run_ceiling_publications()[1].target_time,
        instant(13)
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&producer, &consumer)
            .is_ok()
    );
}

#[test]
fn timed_topology_change_waits_until_all_nodes_reach_activation() {
    let producer = scheduler_node("producer");
    let alpha = scheduler_node("alpha");
    let beta = scheduler_node("beta");
    let activation_time = instant(7);
    let scenario = base_scenario(
        "timed-topology-waits-for-all-nodes",
        vec![
            scenario_node("alpha", 0, SchedulerNodeActivity::Runnable),
            scenario_node("beta", 4, SchedulerNodeActivity::Runnable),
        ],
    )
    .with_effective_topology_edges(vec![edge(&producer, &alpha, 20)])
    .with_rendezvous_interval(duration(100))
    .expect("rendezvous interval should be valid")
    .with_topology_change(
        SchedulerTopologyChange::partition(3, vec![endpoint(&producer, &alpha)])
            .with_activation_time(activation_time),
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let first = drive_one_quantum(&mut scheduler);
    assert_eq!(first.advanced_node, Some(alpha.clone()));
    assert_eq!(first.frontier, VirtualTime { ticks: 4 });
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        activation_time
    );
    assert!(scheduler.topology_change_applications().is_empty());

    let second = drive_one_quantum(&mut scheduler);
    assert_eq!(second.advanced_node, Some(beta));
    assert_eq!(second.frontier, VirtualTime { ticks: 7 });
    assert_eq!(
        scheduler.run_ceiling_publications()[1].target_time,
        activation_time
    );
    assert!(scheduler.topology_change_applications().is_empty());

    let third = drive_one_quantum(&mut scheduler);
    assert_eq!(third.advanced_node, Some(alpha.clone()));
    let application = only_topology_application(&scheduler);
    assert_eq!(application.activation_time, Some(activation_time));
    assert_eq!(
        application.trigger,
        SchedulerTopologyChangeTrigger::EdgeRemoval
    );
    assert_eq!(
        application.updates[0].previous_lookahead,
        finite_lookahead(20)
    );
    assert_eq!(
        application.updates[0].recomputed_lookahead,
        NetworkLookahead::Infinite
    );
    assert_eq!(
        scheduler.run_ceiling_publications()[2].target_time,
        instant(40)
    );
}

fn base_scenario(material: &str, nodes: Vec<SchedulerScenarioNode>) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        material,
        shift(0),
        8,
        instant(40),
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
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead: NetworkLookahead::Infinite,
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

fn instant(nanos: u64) -> SimInstant {
    SimInstant { nanos }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
