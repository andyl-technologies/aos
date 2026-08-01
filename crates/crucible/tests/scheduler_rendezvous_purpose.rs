//! Checks T-SCHED-26 rendezvous purpose restrictions and zero-skew swaps.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerLivenessScenario, SchedulerLookaheadEdge, SchedulerLookaheadEdgeEndpoint,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerRendezvousPurpose, SchedulerScenarioNode,
    SchedulerTopologyChange, SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler,
    VirtualTime,
};

#[test]
fn fixed_rendezvous_caps_do_not_deliver_future_event() {
    let consumer = scheduler_node("consumer");
    let producer = scheduler_node("producer");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "fixed-rendezvous-not-event-delivery",
        shift(0),
        8,
        instant(20),
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        vec![backend_event(12, &consumer, &producer, 77, b"frame")],
    )
    .with_rendezvous_interval(duration(5))
    .expect("rendezvous interval should be valid");
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let first = drive_one_quantum(&mut scheduler);
    assert_eq!(first.advanced_node, Some(consumer.clone()));
    assert_eq!(first.frontier, VirtualTime { ticks: 5 });
    assert!(first.resolved_events.is_empty());
    assert!(scheduler.rendezvous_records().is_empty());

    let second = drive_one_quantum(&mut scheduler);
    assert_eq!(second.advanced_node, Some(consumer.clone()));
    assert_eq!(second.frontier, VirtualTime { ticks: 10 });
    assert!(second.resolved_events.is_empty());
    assert!(scheduler.rendezvous_records().is_empty());

    let third = drive_one_quantum(&mut scheduler);
    assert_eq!(third.advanced_node, Some(consumer));
    assert_eq!(third.frontier, VirtualTime { ticks: 12 });
    assert_eq!(third.resolved_events.len(), 1);
    assert_eq!(
        third.resolved_events[0].key.virtual_time(),
        VirtualTime { ticks: 12 }
    );
    assert!(scheduler.rendezvous_records().is_empty());
}

#[test]
fn topology_swap_rendezvous_records_zero_skew_and_resumes_independently() {
    let producer = scheduler_node("producer");
    let alpha = scheduler_node("alpha");
    let beta = scheduler_node("beta");
    let activation_time = instant(7);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "topology-rendezvous-purpose-zero-skew",
        shift(0),
        8,
        instant(40),
        vec![
            scenario_node(
                "alpha",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
            ),
            scenario_node(
                "beta",
                4,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
            ),
        ],
        Vec::new(),
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
    assert!(scheduler.rendezvous_records().is_empty());

    let second = drive_one_quantum(&mut scheduler);
    assert_eq!(second.advanced_node, Some(beta.clone()));
    assert_eq!(second.frontier, VirtualTime { ticks: 7 });
    assert!(scheduler.rendezvous_records().is_empty());

    let third = drive_one_quantum(&mut scheduler);
    assert_eq!(third.advanced_node, Some(alpha.clone()));
    assert_eq!(third.frontier, VirtualTime { ticks: 7 });
    let post_rendezvous_alpha_run = &scheduler.run_ceiling_publications()[2];
    assert_eq!(post_rendezvous_alpha_run.node, alpha.clone());
    assert_eq!(
        post_rendezvous_alpha_run.current_icount,
        NodeCounter { ticks: 7 }
    );
    assert_eq!(post_rendezvous_alpha_run.max_advance_icount, 40);
    assert_eq!(post_rendezvous_alpha_run.target_time, instant(40));

    let records = scheduler.rendezvous_records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.sequence, 0);
    assert_eq!(record.purpose, SchedulerRendezvousPurpose::TopologySwap);
    assert_eq!(record.virtual_time, activation_time);
    assert_eq!(
        record
            .nodes
            .iter()
            .map(|node| node.node.clone())
            .collect::<Vec<_>>(),
        vec![alpha, beta.clone()]
    );
    assert!(
        record
            .nodes
            .iter()
            .all(|node| node.virtual_time == activation_time)
    );

    let fourth = drive_one_quantum(&mut scheduler);
    assert_eq!(fourth.advanced_node, Some(beta));
    assert_eq!(fourth.frontier, VirtualTime { ticks: 40 });
    assert_eq!(scheduler.rendezvous_records().len(), 1);
}

#[test]
fn topology_swap_rendezvous_membership_excludes_terminal_nodes() {
    let producer = scheduler_node("producer");
    let alpha = scheduler_node("alpha");
    let beta = scheduler_node("beta");
    let halted = scheduler_node("halted");
    let activation_time = instant(7);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "topology-rendezvous-terminal-membership",
        shift(0),
        8,
        instant(40),
        vec![
            scenario_node(
                "alpha",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
            ),
            scenario_node(
                "beta",
                4,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
            ),
            scenario_node(
                "halted",
                0,
                SchedulerNodeActivity::Halted,
                NetworkLookahead::Infinite,
            ),
        ],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &alpha, 20)])
    .with_topology_change(
        SchedulerTopologyChange::partition(3, vec![endpoint(&producer, &alpha)])
            .with_activation_time(activation_time),
    );
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    drive_one_quantum(&mut scheduler);
    drive_one_quantum(&mut scheduler);
    drive_one_quantum(&mut scheduler);

    let record = &scheduler.rendezvous_records()[0];
    assert_eq!(record.purpose, SchedulerRendezvousPurpose::TopologySwap);
    assert_eq!(
        record
            .nodes
            .iter()
            .map(|node| node.node.clone())
            .collect::<Vec<_>>(),
        vec![alpha, beta]
    );
    assert!(!record.nodes.iter().any(|node| node.node == halted));
    assert!(
        record
            .nodes
            .iter()
            .all(|node| node.virtual_time == activation_time)
    );
}

fn drive_one_quantum(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should drive one quantum")
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
