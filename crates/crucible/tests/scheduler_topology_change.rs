//! Checks T-SCHED-22 topology-change lookahead recompute.

#![forbid(unsafe_code)]

use crucible::{
    BackendInput, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerActor,
    SchedulerActorHandle, SchedulerError, SchedulerLivenessScenario, SchedulerLookaheadEdge,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulerTerminal,
    SchedulerTopologyChange, SchedulerTopologyChangeTrigger, SchedulingNodeKind, Shift,
    SimDuration, SimInstant, SingleScheduler, VirtualTime, check_scheduler_liveness,
};

#[test]
fn topology_change_recomputes_lowered_lookahead_before_pick() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "topology-change-lowered-lookahead-before-pick",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_topology_change(SchedulerTopologyChange::new(
        1,
        SchedulerTopologyChangeTrigger::LatencyChange,
        vec![edge(&producer, &consumer, 5)],
    ));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer.clone()));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 5 });
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        SimInstant { nanos: 5 }
    );
    let application = only_topology_application(&scheduler);
    assert_eq!(application.topology_epoch, 1);
    assert_eq!(application.sequence, 1);
    assert_eq!(
        application.trigger,
        SchedulerTopologyChangeTrigger::LatencyChange
    );
    assert_eq!(application.updates.len(), 1);
    assert_eq!(application.updates[0].node, consumer);
    assert_eq!(
        application.updates[0].previous_lookahead,
        finite_lookahead(20)
    );
    assert_eq!(
        application.updates[0].recomputed_lookahead,
        finite_lookahead(5)
    );
}

#[test]
fn runtime_topology_change_queue_recomputes_before_next_pick() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "topology-change-runtime-queue",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)]);
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    scheduler.queue_topology_change(SchedulerTopologyChange::new(
        2,
        SchedulerTopologyChangeTrigger::LatencyChange,
        vec![edge(&producer, &consumer, 6)],
    ));
    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 6 });
    assert_eq!(
        scheduler.topology_change_applications()[0].updates[0].recomputed_lookahead,
        finite_lookahead(6)
    );
}

#[test]
fn actor_topology_change_message_recomputes_before_next_pick() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "topology-change-actor-queue",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)]);
    let (handle, mut actor) = SchedulerActor::new(scenario).expect("scenario should build");

    handle
        .queue_topology_change(SchedulerTopologyChange::new(
            4,
            SchedulerTopologyChangeTrigger::LatencyChange,
            vec![edge(&producer, &consumer, 7)],
        ))
        .expect("topology change message should enqueue");
    actor
        .run_once()
        .expect("actor should accept topology change");
    let outcome = actor_drive_one_quantum(&handle, &mut actor);

    assert_eq!(outcome.advanced_node, Some(consumer));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 7 });
}

#[test]
fn pending_topology_change_freezes_cross_node_sends_until_boundary() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "topology-change-send-freeze",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_topology_change(SchedulerTopologyChange::new(
        7,
        SchedulerTopologyChangeTrigger::FaultActivation,
        vec![edge(&producer, &consumer, 5)],
    ));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let error = scheduler
        .authorize_cross_node_send(&producer, &consumer)
        .expect_err("pending topology change must freeze cross-node sends");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("cross-node sends frozen"));

    drive_one_quantum(&mut scheduler);
    let authorization = scheduler
        .authorize_cross_node_send(&producer, &consumer)
        .expect("send should be authorized after boundary recompute");

    assert_eq!(authorization.producer, producer);
    assert_eq!(authorization.consumer, consumer);
    assert_eq!(authorization.topology_epoch, 1);
}

#[test]
fn lowered_lookahead_prevents_inflight_frame_delivery_under_stale_horizon() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let inflight = backend_event(12, &consumer, &producer, 0, b"in-flight");
    let scenario = base_scenario(
        "topology-change-inflight-not-stale",
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        vec![inflight],
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_topology_change(SchedulerTopologyChange::new(
        3,
        SchedulerTopologyChangeTrigger::LatencyChange,
        vec![edge(&producer, &consumer, 5)],
    ));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 5 });
    assert!(outcome.resolved_events.is_empty());
}

#[test]
fn topology_only_boundary_progress_does_not_deadlock_liveness() {
    let producer = scheduler_node("producer");
    let done = scheduler_node("done");
    let scenario = base_scenario(
        "topology-change-only-liveness",
        vec![scenario_node(
            "done",
            0,
            SchedulerNodeActivity::Done,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &done, 20)])
    .with_topology_change(SchedulerTopologyChange::new(
        11,
        SchedulerTopologyChangeTrigger::Heal,
        vec![edge(&producer, &done, 9)],
    ));

    let report = check_scheduler_liveness(scenario).expect("topology-only boundary should settle");

    assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(report.quanta, 1);
    assert!(report.advanced_nodes.is_empty());
}

fn base_scenario(
    material: &str,
    nodes: Vec<SchedulerScenarioNode>,
    pending_events: Vec<ScheduledEvent>,
) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        material,
        shift(0),
        8,
        SimInstant { nanos: 40 },
        nodes,
        pending_events,
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

fn actor_drive_one_quantum(
    handle: &SchedulerActorHandle,
    actor: &mut SchedulerActor,
) -> crucible::QuantumOutcome {
    let snapshot = handle.snapshot().expect("snapshot should enqueue");
    actor.run_once().expect("actor should process snapshot");
    let configuration = snapshot
        .recv()
        .expect("actor should reply with snapshot")
        .configuration;
    let reply = handle
        .drive_quantum(QuantumRequest {
            configuration,
            control: Vec::new(),
        })
        .expect("drive quantum should enqueue");
    actor.run_once().expect("actor should drive quantum");
    reply
        .recv()
        .expect("actor should reply")
        .expect("scheduler should drive quantum")
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
    NetworkLookahead::Finite(duration(nanos))
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
