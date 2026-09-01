//! Checks T-SCHED-22 topology-change lookahead recompute.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

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
fn netlink_latency_recompute_signal_queues_boundary_recompute() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "netlink-latency-recompute-signal",
        shift(0),
        64,
        SimInstant { nanos: 40 },
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
    let mut link = crucible_device::NetLink::new(0, 99, 20, 1, crucible_device::LinkFaults::none())
        .expect("link should build");

    assert!(
        !scheduler
            .schedule_link_latency_recompute(9, producer.clone(), consumer.clone(), &mut link)
            .expect("no-op recompute should succeed"),
        "a link with no pending recompute must not queue a topology change"
    );

    let mut faults = crucible_device::LinkFaults::none();
    faults.added_latency_ns = 7;
    link.set_faults(faults);
    assert!(
        scheduler
            .schedule_link_latency_recompute(9, producer.clone(), consumer.clone(), &mut link)
            .expect("recompute should queue"),
        "the link's pending recompute flag must be consumed into the scheduler"
    );
    assert!(
        !link.lookahead_recompute_pending(),
        "the scheduler adapter consumes the link flag exactly once"
    );
    assert!(
        matches!(
            scheduler.authorize_cross_node_send(&producer, &consumer),
            Err(SchedulerError::BoundaryViolation { .. })
        ),
        "cross-node sends must freeze while the recompute waits for the boundary"
    );

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(consumer.clone()));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 27 });
    let application = only_topology_application(&scheduler);
    assert_eq!(application.sequence, 9);
    assert_eq!(
        application.trigger,
        SchedulerTopologyChangeTrigger::LatencyChange
    );
    assert_eq!(
        application.updates[0].previous_lookahead,
        finite_lookahead(20)
    );
    assert_eq!(
        application.updates[0].recomputed_lookahead,
        finite_lookahead(27)
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&producer, &consumer)
            .is_ok(),
        "send authorization resumes after the boundary recompute"
    );
}

#[test]
fn netlink_recompute_validation_failure_keeps_signal_pending() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "netlink-recompute-retains-signal-on-error",
        shift(0),
        64,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(Vec::new());
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");
    let mut link = crucible_device::NetLink::new(0, 99, 20, 1, crucible_device::LinkFaults::none())
        .expect("link should build");
    let mut faults = crucible_device::LinkFaults::none();
    faults.added_latency_ns = 7;
    link.set_faults(faults);

    let error = scheduler
        .schedule_link_latency_recompute(9, producer, consumer, &mut link)
        .expect_err("missing edge should reject the recompute");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(
        link.lookahead_recompute_pending(),
        "failed validation must not consume the link recompute signal"
    );
    assert!(
        scheduler.topology_change_applications().is_empty(),
        "a rejected recompute must not apply any topology changes"
    );
}

#[test]
fn netlink_latency_update_does_not_restore_pending_partition_edge() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let endpoint = edge(&producer, &consumer, 20).endpoint();
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "netlink-latency-update-preserves-partition",
        shift(0),
        64,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_topology_change(SchedulerTopologyChange::partition(1, vec![endpoint]));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");
    let mut link = crucible_device::NetLink::new(0, 99, 20, 1, crucible_device::LinkFaults::none())
        .expect("link should build");
    let mut faults = crucible_device::LinkFaults::none();
    faults.added_latency_ns = 7;
    link.set_faults(faults);

    assert!(
        scheduler
            .schedule_link_latency_recompute(2, producer.clone(), consumer.clone(), &mut link)
            .expect("latency recompute should queue behind the partition"),
        "pending recompute must queue"
    );

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.frontier, VirtualTime { ticks: 40 });
    assert_eq!(scheduler.topology_change_applications().len(), 2);
    assert_eq!(
        scheduler.topology_change_applications()[0].trigger,
        SchedulerTopologyChangeTrigger::EdgeRemoval
    );
    assert_eq!(
        scheduler.topology_change_applications()[1].trigger,
        SchedulerTopologyChangeTrigger::LatencyChange
    );
    assert!(
        matches!(
            scheduler.authorize_cross_node_send(&producer, &consumer),
            Err(SchedulerError::BoundaryViolation { .. })
        ),
        "incremental latency updates must not re-add a partitioned edge"
    );
}

#[test]
fn netlink_latency_after_partition_is_recoverable_by_heal_with_current_latency() {
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let endpoint = edge(&producer, &consumer, 20).endpoint();
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "netlink-latency-after-partition-heals-current-latency",
        shift(0),
        64,
        SimInstant { nanos: 80 },
        vec![scenario_node(
            "consumer",
            0,
            SchedulerNodeActivity::Done,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)])
    .with_topology_change(SchedulerTopologyChange::partition(1, vec![endpoint]));
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");
    let mut link = crucible_device::NetLink::new(0, 99, 20, 1, crucible_device::LinkFaults::none())
        .expect("link should build");
    let mut faults = crucible_device::LinkFaults::none();
    faults.added_latency_ns = 7;
    link.set_faults(faults);

    assert!(
        scheduler
            .schedule_link_latency_recompute(2, producer.clone(), consumer.clone(), &mut link)
            .expect("latency recompute should queue behind the partition")
    );
    assert!(
        !link.lookahead_recompute_pending(),
        "the recompute signal is consumed once the boundary update is queued"
    );

    drive_one_quantum(&mut scheduler);
    assert!(
        matches!(
            scheduler.authorize_cross_node_send(&producer, &consumer),
            Err(SchedulerError::BoundaryViolation { .. })
        ),
        "the skipped latency update must not restore the partitioned edge"
    );

    scheduler
        .schedule_topology_change(SchedulerTopologyChange::heal(
            3,
            vec![edge(&producer, &consumer, link.effective_latency_ns())],
        ))
        .expect("heal should queue");

    drive_one_quantum(&mut scheduler);

    assert!(
        scheduler
            .authorize_cross_node_send(&producer, &consumer)
            .is_ok(),
        "heal restores the edge explicitly"
    );
    assert_eq!(scheduler.topology_change_applications().len(), 3);
    let heal_application = &scheduler.topology_change_applications()[2];
    assert_eq!(
        heal_application.trigger,
        SchedulerTopologyChangeTrigger::EdgeRestore
    );
    let consumer_heal_update = heal_application
        .updates
        .iter()
        .find(|update| update.node == consumer)
        .unwrap_or_else(|| panic!("consumer update should exist after heal"));
    assert_eq!(
        consumer_heal_update.recomputed_lookahead,
        finite_lookahead(27),
        "the heal edge must use the link's current effective latency"
    );
}

#[test]
fn multiple_netlink_latency_updates_preserve_unrelated_edges() {
    let producer_a = scheduler_node("producer-a");
    let producer_b = scheduler_node("producer-b");
    let consumer_a = scheduler_node("consumer-a");
    let consumer_b = scheduler_node("consumer-b");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "multiple-netlink-latency-updates-preserve-unrelated-edges",
        shift(0),
        64,
        SimInstant { nanos: 40 },
        vec![
            scenario_node(
                "consumer-a",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(20),
            ),
            scenario_node(
                "consumer-b",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(30),
            ),
        ],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![
        edge(&producer_a, &consumer_a, 20),
        edge(&producer_b, &consumer_b, 30),
    ]);
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");
    let mut link_a =
        crucible_device::NetLink::new(0, 99, 20, 1, crucible_device::LinkFaults::none())
            .expect("link a should build");
    let mut link_b =
        crucible_device::NetLink::new(0, 99, 30, 1, crucible_device::LinkFaults::none())
            .expect("link b should build");
    let mut faults_a = crucible_device::LinkFaults::none();
    faults_a.added_latency_ns = 7;
    link_a.set_faults(faults_a);
    let mut faults_b = crucible_device::LinkFaults::none();
    faults_b.added_latency_ns = 5;
    link_b.set_faults(faults_b);

    assert!(
        scheduler
            .schedule_link_latency_recompute(1, producer_a.clone(), consumer_a.clone(), &mut link_a)
            .expect("first recompute should queue")
    );
    assert!(
        scheduler
            .schedule_link_latency_recompute(2, producer_b, consumer_b.clone(), &mut link_b)
            .expect("second recompute should queue")
    );

    drive_one_quantum(&mut scheduler);

    assert_eq!(scheduler.topology_change_applications().len(), 2);
    let first_application = &scheduler.topology_change_applications()[0];
    let second_application = &scheduler.topology_change_applications()[1];
    let consumer_a_after_first = first_application
        .updates
        .iter()
        .find(|update| update.node == consumer_a)
        .unwrap_or_else(|| panic!("consumer-a update should exist after first recompute"));
    assert_eq!(
        consumer_a_after_first.recomputed_lookahead,
        finite_lookahead(27)
    );
    let consumer_a_after_second = second_application
        .updates
        .iter()
        .find(|update| update.node == consumer_a)
        .unwrap_or_else(|| panic!("consumer-a update should exist after second recompute"));
    assert_eq!(
        consumer_a_after_second.recomputed_lookahead,
        finite_lookahead(27),
        "the second recompute must not reset the first edge to its stale latency"
    );
    let consumer_b_after_second = second_application
        .updates
        .iter()
        .find(|update| update.node == consumer_b)
        .unwrap_or_else(|| panic!("consumer-b update should exist after second recompute"));
    assert_eq!(
        consumer_b_after_second.recomputed_lookahead,
        finite_lookahead(35)
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
        SchedulerTopologyChangeTrigger::EdgeRemoval,
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
        SchedulerTopologyChangeTrigger::EdgeRestore,
        vec![edge(&producer, &done, 9)],
    ));

    let report = check_scheduler_liveness(scenario).expect("topology-only boundary should settle");

    assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(report.quanta, 1);
    assert!(report.advanced_nodes.is_empty());
}

#[test]
fn network_bounded_nodes_climb_to_time_limit_without_freezing() {
    // Regression for the topology/horizon freeze deadlock (RFC-0010
    // [SCHED-7]/[SCHED-8]). A node bound by the conservative network-lookahead
    // term derived from a live effective topology is held at a *moving* cap
    // (`vt(n) + lookahead(n)`), not a genuine local quiescence point. A 2-node
    // ring with bidirectional latency-4 links and all-halted (no vCPU) nodes must
    // climb by successive quanta to the time limit (iterative conservative-PDES
    // advance), never park `Idle` at the first lookahead bound (frontier = 4).
    //
    // Before the fix, `advance_node_after_yield` parked each node `Idle` once it
    // reached `vt + lookahead`; the only `Idle -> Runnable` re-promotion path
    // (`effective_node_activity`) requires a non-halted or pending-input vCPU, so
    // these nodes never re-PICKed and the run wrongly settled `Quiescent` at
    // frontier 4. With the fix the run reaches the time limit at frontier 40.
    let a = scheduler_node("a");
    let b = scheduler_node("b");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "network-bounded-ring-climbs-to-time-limit",
        shift(0),
        // Generous quantum budget so the *frontier* (40 vs the frozen 4), not the
        // budget, is what terminates the run — the budget never bites with the fix.
        1024,
        SimInstant { nanos: 40 },
        vec![
            scenario_node("a", 0, SchedulerNodeActivity::Runnable, finite_lookahead(4)),
            scenario_node("b", 0, SchedulerNodeActivity::Runnable, finite_lookahead(4)),
        ],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&b, &a, 4), edge(&a, &b, 4)]);

    let report =
        check_scheduler_liveness(scenario).expect("network-bounded ring should not freeze");

    assert_eq!(
        report.terminal,
        SchedulerTerminal::TimeLimitReached,
        "a network-bounded ring must climb to the time limit, not freeze Quiescent \
         at the first lookahead bound"
    );
    assert_eq!(
        report.frontier,
        VirtualTime { ticks: 40 },
        "both ring nodes must climb all the way to the time limit (40), not park \
         Idle at the moving network bound (4)"
    );
    // Each node is re-PICKed many times as the frontier rises (10 climbs of 4 to
    // reach 40), proving the iterative advance rather than a single-quantum park.
    let advanced_a = report
        .advanced_nodes
        .iter()
        .filter(|node| **node == a)
        .count();
    let advanced_b = report
        .advanced_nodes
        .iter()
        .filter(|node| **node == b)
        .count();
    assert!(
        advanced_a > 1 && advanced_b > 1,
        "each network-bounded node must be advanced repeatedly as the frontier \
         rises: a={advanced_a}, b={advanced_b}"
    );
}

#[test]
fn topology_change_armed_in_the_past_is_rejected_at_enqueue() {
    // The fallible arming porcelain rejects an activation time the run has already
    // passed at enqueue time, rather than wedging the run with a repeating
    // boundary error at apply time.
    let producer = scheduler_node("producer");
    let consumer = scheduler_node("consumer");
    let scenario = base_scenario(
        "topology-change-armed-in-past",
        vec![scenario_node(
            "consumer",
            // Frontier starts at vt = 10; an activation armed at vt = 5 is in the
            // past.
            10,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(20),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &consumer, 20)]);
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 10 });

    let in_past = SchedulerTopologyChange::new(
        1,
        SchedulerTopologyChangeTrigger::LatencyChange,
        vec![edge(&producer, &consumer, 5)],
    )
    .with_activation_time(SimInstant { nanos: 5 });

    match scheduler.schedule_topology_change(in_past) {
        Err(SchedulerError::TopologyActivationInPast { at, frontier }) => {
            assert_eq!(at, 5);
            assert_eq!(frontier, 10);
        }
        other => panic!("expected TopologyActivationInPast, got {other:?}"),
    }
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
