//! Checks T-FAULT-8 node crash and restart application on VM scheduler nodes.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, CombinedNodeFaults, Configuration, ExactLocalEvent, Icount, NetworkLookahead,
    NodeCounter, NodeId, QuantumLoop, QuantumRequest, RestartPolicy, ScheduledEvent,
    ScheduledEventKey, ScheduledEventPayload, ScheduledEventResolveClass, SchedulerDiscardedEvent,
    SchedulerDiscardedIoCompletion, SchedulerLivenessScenario, SchedulerLookaheadEdge,
    SchedulerNodeActivity, SchedulerNodeCrashApplication, SchedulerNodeId,
    SchedulerNodeRestartApplication, SchedulerScenarioNode, SchedulerTopologyChange,
    SchedulerTopologyChangeTrigger, SchedulingNodeKind, Shift, SimDuration, SimInstant,
    SingleScheduler, VirtualTime, apply_combined_node_crash_to_scheduler,
};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, IoCore, LinkFaults, NetLink,
};

#[test]
fn crash_discards_events_io_and_edges_without_constraining_peer() {
    let crashed = node_id("vm-a");
    let peer = node_id("vm-b");
    let crashed_node = scheduler_node(&crashed);
    let peer_node = scheduler_node(&peer);
    let edges = bidirectional_edges(&crashed_node, &peer_node, 10);
    let mut scheduler = ok(SingleScheduler::new(
        two_vm_scenario(
            "node-crash-discards-events-io-and-edges",
            (&crashed, 0),
            (&peer, 0),
            40,
            vec![
                backend_event(5, &crashed_node, &peer_node, 0, b"to-crashed"),
                backend_event(6, &peer_node, &crashed_node, 0, b"from-crashed"),
            ],
        )
        .with_effective_topology_edges(edges.clone()),
    ))
    .with_device_sub_node(block_sub_node(&crashed, "disk-a", 0, 8));
    let faults = CombinedNodeFaults {
        crash_restart: Some(RestartPolicy::FromReadyPoint),
        ..CombinedNodeFaults::default()
    };

    let application = ok(apply_combined_node_crash_to_scheduler(
        &mut scheduler,
        7,
        &crashed,
        &faults,
    ))
    .unwrap_or_else(|| panic!("crash fault should apply"));

    assert!(scheduler.is_node_crashed(&crashed));
    assert_eq!(application.sequence, 7);
    assert_eq!(
        application.previous_activity,
        SchedulerNodeActivity::Runnable
    );
    assert_eq!(
        application.discarded_events,
        vec![
            SchedulerDiscardedEvent {
                key: event_key(5, &crashed_node, &peer_node, 0),
                class: ScheduledEventResolveClass::FrameDelivery,
            },
            SchedulerDiscardedEvent {
                key: event_key(6, &peer_node, &crashed_node, 0),
                class: ScheduledEventResolveClass::FrameDelivery,
            },
        ],
        "the deterministic discard log records both incident backend inputs exactly"
    );
    assert_eq!(
        application.discarded_io,
        vec![discarded_block_completion(&crashed, "disk-a", 1008, 0)],
        "the pending block completion is discarded with its delivery tie-break key"
    );
    assert_eq!(
        application.removed_edges, edges,
        "both directions incident to the crashed node are removed"
    );
    assert!(!scheduler.has_undelivered_device_completion());

    let outcome = drive_scheduler(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(peer_node.clone()));
    assert_eq!(
        outcome.frontier.ticks, 40,
        "the crashed node does not hold back the live peer"
    );
    assert!(outcome.resolved_events.is_empty());
    let crashed_projection = ok(scheduler.node_timing_projection(&crashed));
    assert_eq!(crashed_projection.counter, NodeCounter { ticks: 0 });
    assert_eq!(crashed_projection.faulted_time, SimInstant { nanos: 0 });
    assert!(
        scheduler
            .authorize_cross_node_send(&crashed_node, &peer_node)
            .is_err()
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&peer_node, &crashed_node)
            .is_err()
    );
}

#[test]
fn crash_preserves_unrelated_events_and_device_completions() {
    let crashed = node_id("vm-a");
    let peer = node_id("vm-b");
    let observer = node_id("vm-c");
    let crashed_node = scheduler_node(&crashed);
    let peer_node = scheduler_node(&peer);
    let observer_node = scheduler_node(&observer);
    let mut scheduler = ok(SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "node-crash-preserves-unrelated-work",
            Shift { bits: 0 },
            8,
            SimInstant { nanos: 1200 },
            vec![
                node_with(
                    &crashed,
                    0,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Infinite,
                ),
                node_with(
                    &peer,
                    0,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Infinite,
                ),
                node_with(
                    &observer,
                    0,
                    SchedulerNodeActivity::Idle,
                    NetworkLookahead::Infinite,
                ),
            ],
            vec![
                backend_event(5, &crashed_node, &peer_node, 0, b"drop-me"),
                backend_event(5, &observer_node, &peer_node, 0, b"survive"),
            ],
        ),
    ))
    .with_device_sub_node(block_sub_node(&crashed, "disk-a", 0, 8))
    .with_device_sub_node(block_sub_node(&peer, "disk-b", 0, 8));

    let application = ok(scheduler.apply_node_crash(1, &crashed, RestartPolicy::StayDown));

    assert_eq!(
        application.discarded_events,
        vec![SchedulerDiscardedEvent {
            key: event_key(5, &crashed_node, &peer_node, 0),
            class: ScheduledEventResolveClass::FrameDelivery,
        }],
        "only events incident to the crashed node are discarded"
    );
    assert_eq!(
        application.discarded_io,
        vec![discarded_block_completion(&crashed, "disk-a", 1008, 0)]
    );
    assert!(
        scheduler.has_undelivered_device_completion(),
        "the peer's unrelated device completion remains in flight"
    );

    let event_outcome = drive_scheduler(&mut scheduler);
    assert_eq!(event_outcome.advanced_node, Some(observer_node.clone()));
    assert_eq!(
        event_outcome
            .resolved_events
            .iter()
            .map(event_payload)
            .collect::<Vec<_>>(),
        vec![b"survive".to_vec()]
    );

    let io_outcome = drive_scheduler(&mut scheduler);
    assert_eq!(io_outcome.advanced_node, Some(peer_node));
    assert!(matches!(
        io_outcome.resolved_events.first().map(|event| &event.payload),
        Some(ScheduledEventPayload::IoCompletion(completion))
            if completion.target == peer && completion.delivery_icount == Icount { retired: 1008 }
    ));
}

#[test]
fn from_ready_point_restart_reboots_at_current_frontier_and_restores_edges() {
    let restarted = node_id("vm-a");
    let peer = node_id("vm-b");
    let restarted_node = scheduler_node(&restarted);
    let peer_node = scheduler_node(&peer);
    let mut scheduler = ok(SingleScheduler::new(
        two_vm_scenario(
            "node-crash-from-ready-point-restart",
            (&restarted, 20),
            (&peer, 30),
            60,
            Vec::new(),
        )
        .with_effective_topology_edges(bidirectional_edges(
            &restarted_node,
            &peer_node,
            10,
        )),
    ));

    let _ = ok(scheduler.apply_node_crash(1, &restarted, RestartPolicy::FromReadyPoint));
    let restart = ok(scheduler.heal_node_crash(2, &restarted));

    assert!(restart.restarted);
    assert_eq!(restart.restart, RestartPolicy::FromReadyPoint);
    assert_eq!(restart.at, SimInstant { nanos: 30 });
    assert_eq!(restart.counter, NodeCounter { ticks: 0 });
    assert_eq!(restart.restored_edges.len(), 2);
    assert!(!scheduler.is_node_crashed(&restarted));
    let projection = ok(scheduler.node_timing_projection(&restarted));
    assert_eq!(projection.counter, NodeCounter { ticks: 0 });
    assert_eq!(
        projection.faulted_time,
        SimInstant { nanos: 30 },
        "the ready-point counter is re-anchored at the current scheduler frontier"
    );

    let _ = drive_scheduler(&mut scheduler);
    assert!(
        scheduler
            .authorize_cross_node_send(&restarted_node, &peer_node)
            .is_ok()
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&peer_node, &restarted_node)
            .is_ok()
    );
}

#[test]
fn from_last_checkpoint_restart_resumes_recorded_checkpoint_not_crash_counter() {
    let restarted = node_id("vm-a");
    let peer = node_id("vm-b");
    let restarted_node = scheduler_node(&restarted);
    let mut scheduler = ok(SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "node-crash-from-last-checkpoint-restart",
            Shift { bits: 0 },
            8,
            SimInstant { nanos: 42 },
            vec![
                node_with(
                    &restarted,
                    21,
                    SchedulerNodeActivity::Runnable,
                    NetworkLookahead::Infinite,
                ),
                node_with(
                    &peer,
                    50,
                    SchedulerNodeActivity::Done,
                    NetworkLookahead::Infinite,
                ),
            ],
            Vec::new(),
        ),
    ));

    let checkpoint = ok(scheduler.record_node_checkpoint(&restarted));
    assert_eq!(checkpoint.counter, NodeCounter { ticks: 21 });
    let advance = drive_scheduler(&mut scheduler);
    assert_eq!(advance.advanced_node, Some(restarted_node));
    assert_eq!(
        ok(scheduler.node_timing_projection(&restarted)).counter,
        NodeCounter { ticks: 42 }
    );

    let crash = ok(scheduler.apply_node_crash(1, &restarted, RestartPolicy::FromLastCheckpoint));
    assert_eq!(crash.counter, NodeCounter { ticks: 42 });
    assert_eq!(crash.checkpoint.as_ref(), Some(&checkpoint));
    let restart = ok(scheduler.heal_node_crash(2, &restarted));

    assert!(restart.restarted);
    assert_eq!(restart.restart, RestartPolicy::FromLastCheckpoint);
    assert_eq!(restart.checkpoint.as_ref(), Some(&checkpoint));
    assert_eq!(restart.counter, NodeCounter { ticks: 21 });
    let projection = ok(scheduler.node_timing_projection(&restarted));
    assert_eq!(projection.counter, NodeCounter { ticks: 21 });
    assert_eq!(
        projection.faulted_time,
        SimInstant { nanos: 50 },
        "the checkpoint counter resumes at the current scheduler frontier"
    );
}

#[test]
fn stay_down_heal_consumes_crash_and_waits_for_explicit_restart() {
    let crashed = node_id("vm-a");
    let peer = node_id("vm-b");
    let crashed_node = scheduler_node(&crashed);
    let peer_node = scheduler_node(&peer);
    let mut scheduler = ok(SingleScheduler::new(
        two_vm_scenario(
            "node-crash-stay-down",
            (&crashed, 10),
            (&peer, 0),
            40,
            Vec::new(),
        )
        .with_effective_topology_edges(bidirectional_edges(&crashed_node, &peer_node, 10)),
    ));

    let _ = ok(scheduler.apply_node_crash(1, &crashed, RestartPolicy::StayDown));
    let restart = ok(scheduler.heal_node_crash(2, &crashed));

    assert!(!restart.restarted);
    assert_eq!(restart.restart, RestartPolicy::StayDown);
    assert_eq!(restart.restored_edges, Vec::new());
    assert!(!scheduler.is_node_crashed(&crashed));
    assert!(scheduler.is_node_stopped_after_crash(&crashed));
    assert!(scheduler.heal_node_crash(3, &crashed).is_err());

    let outcome = drive_scheduler(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(peer_node.clone()));
    assert_eq!(outcome.frontier.ticks, 40);
    assert!(
        scheduler
            .authorize_cross_node_send(&peer_node, &crashed_node)
            .is_err()
    );

    let explicit = ok(scheduler.restart_stopped_node(4, &crashed));
    assert!(explicit.restarted);
    assert_eq!(explicit.counter, NodeCounter { ticks: 0 });
    assert_eq!(explicit.restored_edges.len(), 2);
    assert!(!scheduler.is_node_stopped_after_crash(&crashed));
    let _ = drive_scheduler(&mut scheduler);
    assert!(
        scheduler
            .authorize_cross_node_send(&peer_node, &crashed_node)
            .is_ok()
    );
}

#[test]
fn topology_updates_while_node_is_down_are_restored_on_restart() {
    let restarted = node_id("vm-a");
    let peer = node_id("vm-b");
    let restarted_node = scheduler_node(&restarted);
    let peer_node = scheduler_node(&peer);
    let updated_edges = bidirectional_edges(&restarted_node, &peer_node, 25);
    let mut scheduler = ok(SingleScheduler::new(
        two_vm_scenario(
            "node-crash-topology-updates-while-down",
            (&restarted, 0),
            (&peer, 0),
            80,
            Vec::new(),
        )
        .with_effective_topology_edges(bidirectional_edges(
            &restarted_node,
            &peer_node,
            10,
        )),
    ));

    let _ = ok(scheduler.apply_node_crash(1, &restarted, RestartPolicy::FromReadyPoint));
    scheduler.queue_topology_change(SchedulerTopologyChange::update_effective_edges(
        2,
        SchedulerTopologyChangeTrigger::LatencyChange,
        updated_edges.clone(),
    ));
    let _ = drive_scheduler(&mut scheduler);
    let restart = ok(scheduler.heal_node_crash(3, &restarted));

    assert_eq!(
        restart.restored_edges, updated_edges,
        "healing restores the latest suppressed endpoint edges, not stale activation edges"
    );
    let _ = drive_scheduler(&mut scheduler);
    let last_application = scheduler
        .topology_change_applications()
        .last()
        .unwrap_or_else(|| panic!("restart should apply a topology restore"));
    let peer_update = last_application
        .updates
        .iter()
        .find(|update| update.node == peer_node)
        .unwrap_or_else(|| panic!("peer lookahead should be recomputed"));
    assert_eq!(
        peer_update.recomputed_lookahead,
        NetworkLookahead::Finite(SimDuration { nanos: 25 })
    );
}

#[test]
fn netlink_latency_recompute_updates_suppressed_down_edge() {
    let restarted = node_id("vm-a");
    let peer = node_id("vm-b");
    let restarted_node = scheduler_node(&restarted);
    let peer_node = scheduler_node(&peer);
    let initial_edge = SchedulerLookaheadEdge::new(
        restarted_node.clone(),
        peer_node.clone(),
        SimDuration { nanos: 20 },
    );
    let updated_edge = SchedulerLookaheadEdge::new(
        restarted_node.clone(),
        peer_node.clone(),
        SimDuration { nanos: 27 },
    );
    let mut scheduler = ok(SingleScheduler::new(
        two_vm_scenario(
            "node-crash-netlink-recompute-while-down",
            (&restarted, 0),
            (&peer, 0),
            80,
            Vec::new(),
        )
        .with_effective_topology_edges(vec![initial_edge]),
    ));
    let mut link = ok(NetLink::new(0, 1, 20, 1, LinkFaults::none()));

    let _ = ok(scheduler.apply_node_crash(1, &restarted, RestartPolicy::FromReadyPoint));
    let _ = drive_scheduler(&mut scheduler);

    let mut faults = LinkFaults::none();
    faults.added_latency_ns = 7;
    link.set_faults(faults);
    assert!(
        ok(scheduler.schedule_link_latency_recompute(
            2,
            restarted_node.clone(),
            peer_node.clone(),
            &mut link,
        )),
        "a latency recompute for a crash-suppressed edge should still queue"
    );
    assert!(!link.lookahead_recompute_pending());

    let _ = drive_scheduler(&mut scheduler);
    let restart = ok(scheduler.heal_node_crash(3, &restarted));

    assert_eq!(
        restart.restored_edges,
        vec![updated_edge],
        "the public netlink recompute adapter updates the suppressed edge before restart"
    );
}

#[test]
fn topology_removal_while_node_is_down_is_not_restored_on_restart() {
    let restarted = node_id("vm-a");
    let peer = node_id("vm-b");
    let restarted_node = scheduler_node(&restarted);
    let peer_node = scheduler_node(&peer);
    let initial_edges = bidirectional_edges(&restarted_node, &peer_node, 10);
    let mut scheduler = ok(SingleScheduler::new(
        two_vm_scenario(
            "node-crash-topology-removal-while-down",
            (&restarted, 0),
            (&peer, 0),
            80,
            Vec::new(),
        )
        .with_effective_topology_edges(initial_edges.clone()),
    ));

    let _ = ok(scheduler.apply_node_crash(1, &restarted, RestartPolicy::FromReadyPoint));
    scheduler.queue_topology_change(SchedulerTopologyChange::partition(
        2,
        initial_edges
            .iter()
            .map(SchedulerLookaheadEdge::endpoint)
            .collect(),
    ));
    let _ = drive_scheduler(&mut scheduler);
    let restart = ok(scheduler.heal_node_crash(3, &restarted));

    assert!(
        restart.restored_edges.is_empty(),
        "a removal applied while the node is down deletes the stale suppressed edges"
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&peer_node, &restarted_node)
            .is_err()
    );
}

#[test]
fn crash_of_only_node_keeps_frontier_at_frozen_crash_time() {
    let crashed = node_id("vm-a");
    let mut scheduler = ok(SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "node-crash-only-node-frontier",
            Shift { bits: 0 },
            4,
            SimInstant { nanos: 80 },
            vec![scenario_node(&crashed, 25)],
            Vec::new(),
        ),
    ));

    let application = ok(scheduler.apply_node_crash(1, &crashed, RestartPolicy::StayDown));

    assert_eq!(application.at, SimInstant { nanos: 25 });
    assert_eq!(
        scheduler.frontier().ticks,
        25,
        "a sole crashed node freezes global time instead of rewinding to epoch"
    );
    let outcome = drive_scheduler(&mut scheduler);
    assert_eq!(outcome.frontier.ticks, 25);
    assert_eq!(outcome.advanced_node, None);
}

#[test]
fn crash_replay_trace_is_identical_across_independent_runs() {
    assert_eq!(crash_replay_trace(), crash_replay_trace());
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CrashReplayTrace {
    crash_applications: Vec<SchedulerNodeCrashApplication>,
    restart_applications: Vec<SchedulerNodeRestartApplication>,
    frontier: VirtualTime,
    configuration: Configuration,
    peer_to_restarted_allowed: bool,
}

fn crash_replay_trace() -> CrashReplayTrace {
    let restarted = node_id("vm-a");
    let peer = node_id("vm-b");
    let restarted_node = scheduler_node(&restarted);
    let peer_node = scheduler_node(&peer);
    let mut scheduler = ok(SingleScheduler::new(
        two_vm_scenario(
            "node-crash-replay-trace",
            (&restarted, 0),
            (&peer, 0),
            60,
            vec![backend_event(5, &restarted_node, &peer_node, 0, b"drop")],
        )
        .with_effective_topology_edges(bidirectional_edges(
            &restarted_node,
            &peer_node,
            10,
        )),
    ))
    .with_device_sub_node(block_sub_node(&restarted, "disk-a", 0, 8));

    let _ = ok(scheduler.apply_node_crash(1, &restarted, RestartPolicy::FromReadyPoint));
    let _ = drive_scheduler(&mut scheduler);
    let _ = ok(scheduler.heal_node_crash(2, &restarted));
    let _ = drive_scheduler(&mut scheduler);

    CrashReplayTrace {
        crash_applications: scheduler.node_crash_applications().to_vec(),
        restart_applications: scheduler.node_restart_applications().to_vec(),
        frontier: scheduler.frontier(),
        configuration: scheduler.configuration().clone(),
        peer_to_restarted_allowed: scheduler
            .authorize_cross_node_send(&peer_node, &restarted_node)
            .is_ok(),
    }
}

fn two_vm_scenario(
    material: &str,
    left: (&NodeId, u64),
    right: (&NodeId, u64),
    time_limit: u64,
    pending_events: Vec<ScheduledEvent>,
) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        material,
        Shift { bits: 0 },
        8,
        SimInstant { nanos: time_limit },
        vec![
            scenario_node(left.0, left.1),
            scenario_node(right.0, right.1),
        ],
        pending_events,
    )
}

fn scenario_node(node: &NodeId, counter: u64) -> SchedulerScenarioNode {
    node_with(
        node,
        counter,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Finite(SimDuration { nanos: 10 }),
    )
}

fn node_with(
    node: &NodeId,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(node),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn bidirectional_edges(
    left: &SchedulerNodeId,
    right: &SchedulerNodeId,
    latency: u64,
) -> Vec<SchedulerLookaheadEdge> {
    vec![
        SchedulerLookaheadEdge::new(left.clone(), right.clone(), SimDuration { nanos: latency }),
        SchedulerLookaheadEdge::new(right.clone(), left.clone(), SimDuration { nanos: latency }),
    ]
}

fn backend_event(
    at: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: event_key(at, consumer, producer, sequence),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn event_key(
    at: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
) -> ScheduledEventKey {
    ScheduledEventKey::from_parts(
        VirtualTime { ticks: at },
        consumer.clone(),
        producer.clone(),
        sequence,
    )
}

fn event_payload(event: &ScheduledEvent) -> Vec<u8> {
    match &event.payload {
        ScheduledEventPayload::BackendInput(input) => input.payload.clone(),
        ScheduledEventPayload::IoCompletion(completion) => completion.payload.clone(),
        ScheduledEventPayload::FaultActivation(_)
        | ScheduledEventPayload::ProbabilisticEffect(_)
        | ScheduledEventPayload::Control(_) => Vec::new(),
    }
}

fn discarded_block_completion(
    target: &NodeId,
    device_name: &str,
    delivery_icount: u64,
    sequence: u32,
) -> SchedulerDiscardedIoCompletion {
    SchedulerDiscardedIoCompletion {
        sub_node: scheduler_node_kind(device_name, SchedulingNodeKind::Disk),
        target: target.clone(),
        delivery_icount: Icount {
            retired: delivery_icount,
        },
        source_node: 1,
        sequence,
        payload: vec![
            0, 1, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        ],
    }
}

fn block_sub_node(
    target: &NodeId,
    device_name: &str,
    request_icount: u64,
    count: u32,
) -> crucible::DeviceSchedulingSubNode {
    let core = ok(IoCore::new(0, 1, 16, 16));
    let block = BlockDevice::new(
        core,
        BaseImage::new(vec![0x5a; 4096]),
        BlockLatency::default(),
    );
    let device_id = crucible::DeviceId {
        name: device_name.to_owned(),
    };
    let mut sub_node = crucible::DeviceSchedulingSubNode::new(
        scheduler_node_kind(device_name, SchedulingNodeKind::Disk),
        target.clone(),
        device_id,
        block,
        crucible::Seed::from_u64(0xca5_0008),
    );
    ok(sub_node.submit(request_icount, &BlockRequest::read(1, 0, count)));
    sub_node
}

fn scheduler_node(node: &NodeId) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node.clone(),
        kind: SchedulingNodeKind::Vm,
    }
}

fn scheduler_node_kind(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn drive_scheduler(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    ok(scheduler.drive_quantum(request))
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}
