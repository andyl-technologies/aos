//! Checks T-FAULT-6 network fault application on the link sub-node.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    CombinedFaults, CombinedNetworkFaults, Decision, DeviceId, ExactLocalEvent, Fault,
    FaultBandwidthBitsPerSecond, FaultDuration, FaultRateBasisPoints, LinkId,
    NetworkCorruptionFault, NetworkFault, NetworkLinkDirection, NetworkLookahead, NodeCounter,
    PartitionDirection, QuantumLoop, QuantumRequest, SchedulerLivenessScenario,
    SchedulerLookaheadEdge, SchedulerLookaheadEdgeEndpoint, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulingNodeKind, Seed, Shift, SimDuration, SimInstant,
    SingleScheduler, link_faults_from_combined_network, network_partition_removed_edges,
};
use crucible_device::{Frame, FrameDraws, LinkFaults, NetLink, PastDeliveryPolicy, Probability};

#[test]
fn combined_network_faults_apply_to_netlink_resolve_path() {
    let target = link("client-server");
    let combined = CombinedFaults::from_faults(&[
        Fault::Network(NetworkFault::LatencyBump {
            link: target.clone(),
            extra: duration(500),
        }),
        Fault::Network(NetworkFault::LatencyBump {
            link: target.clone(),
            extra: duration(700),
        }),
        Fault::Network(NetworkFault::Reorder {
            link: target.clone(),
            window: duration(30),
        }),
        Fault::Network(NetworkFault::Duplicate {
            link: target.clone(),
            rate: rate(10_000),
            gap: duration(256),
        }),
        Fault::Network(NetworkFault::Corruption {
            link: target.clone(),
            kind: NetworkCorruptionFault::Truncation {
                rate: rate(8_000),
                max_bytes: 1,
            },
        }),
        Fault::Network(NetworkFault::Corruption {
            link: target.clone(),
            kind: NetworkCorruptionFault::BitFlip {
                rate: rate(10_000),
                max_bits: 1,
            },
        }),
        Fault::Network(NetworkFault::Corruption {
            link: target.clone(),
            kind: NetworkCorruptionFault::FieldMutation { rate: rate(9_000) },
        }),
        Fault::Network(NetworkFault::Bandwidth {
            link: target.clone(),
            limit: bandwidth(8_000_000),
        }),
        Fault::Network(NetworkFault::Bandwidth {
            link: target.clone(),
            limit: bandwidth(16_000_000),
        }),
    ]);
    let faults = combined
        .network
        .get(&target)
        .unwrap_or_else(|| panic!("combined network faults should include target"));

    let lowered =
        link_faults_from_combined_network(faults, NetworkLinkDirection::EndpointAToEndpointB);
    assert_eq!(lowered.added_latency_ns, 1_200);
    assert_eq!(lowered.reorder_window_ns, 30);
    assert!(lowered.duplicate.fires(0));
    assert_eq!(lowered.duplicate_gap_ns, 256);
    assert_eq!(lowered.bandwidth_bits_per_sec, vec![8_000_000, 16_000_000]);
    assert!(lowered.corrupt.fires(0));

    let mut link = ok(NetLink::new(0, 1, 10, 1, LinkFaults::none()));
    crucible::apply_combined_network_faults_to_link(
        &mut link,
        faults,
        NetworkLinkDirection::EndpointAToEndpointB,
    );
    assert_eq!(
        link.effective_latency_ns(),
        1_210,
        "latency bumps raise the conservative link latency"
    );
    assert!(
        link.take_lookahead_recompute(),
        "latency-bound changes raise the scheduler recompute signal"
    );

    let outcome = ok(link.emit(
        &Frame::new(0, 7, vec![0, 0, 0, 0]),
        &FrameDraws {
            duplicate: 0,
            corrupt: 0,
            corrupt_bits: vec![0],
            ..FrameDraws::default()
        },
        PastDeliveryPolicy::FailLoud,
    ));

    assert_eq!(
        outcome.deliveries.len(),
        2,
        "duplicate emits a second frame"
    );
    assert_eq!(outcome.deliveries[0].delivery_icount(), 7_210);
    assert_eq!(outcome.deliveries[1].delivery_icount(), 7_466);
    assert_eq!(
        outcome.deliveries[0].payload,
        vec![0x81, 0, 0],
        "bit-flip, field-mutation, and truncation strategies mutate payload bytes"
    );
    assert_eq!(outcome.deliveries[1].payload, outcome.deliveries[0].payload);
}

#[test]
fn overlapping_loss_rates_drop_when_any_rate_fires() {
    let target = link("client-server");
    let combined = CombinedFaults::from_faults(&[
        Fault::Network(NetworkFault::Loss {
            link: target.clone(),
            rate: rate(100),
        }),
        Fault::Network(NetworkFault::Loss {
            link: target.clone(),
            rate: rate(2_500),
        }),
    ]);
    let faults = combined
        .network
        .get(&target)
        .unwrap_or_else(|| panic!("combined network faults should include target"));
    let lowered =
        link_faults_from_combined_network(faults, NetworkLinkDirection::EndpointAToEndpointB);
    assert_eq!(lowered.loss, Probability::new(2_500, 10_000));
    assert_eq!(lowered.additional_loss, vec![Probability::new(100, 10_000)]);

    let mut link = ok(NetLink::new(0, 1, 10, 1, lowered));
    let outcome = ok(link.emit(
        &Frame::new(0, 1, vec![1, 2, 3]),
        &FrameDraws {
            loss: 2_500,
            additional_loss: vec![0],
            ..FrameDraws::default()
        },
        PastDeliveryPolicy::FailLoud,
    ));

    assert!(
        outcome.deliveries.is_empty(),
        "the primary rate misses, but the second active loss rate fires"
    );
}

#[test]
fn partition_faults_remove_only_covered_scheduler_edges() {
    let target = link("client-server");
    let endpoint_a = scheduler_node("client");
    let endpoint_b = scheduler_node("server");
    let combined = CombinedFaults::from_faults(&[Fault::Network(NetworkFault::Partition {
        link: target.clone(),
        direction: PartitionDirection::EndpointAToEndpointB,
    })]);
    let faults = combined
        .network
        .get(&target)
        .unwrap_or_else(|| panic!("combined network faults should include target"));
    let removed = network_partition_removed_edges(
        endpoint_a.clone(),
        endpoint_b.clone(),
        &faults
            .partition
            .unwrap_or_else(|| panic!("partition should be active")),
    );

    assert_eq!(
        removed,
        vec![SchedulerLookaheadEdgeEndpoint::new(
            endpoint_a.clone(),
            endpoint_b.clone()
        )]
    );
    let dropped_direction =
        link_faults_from_combined_network(faults, NetworkLinkDirection::EndpointAToEndpointB);
    let live_direction =
        link_faults_from_combined_network(faults, NetworkLinkDirection::EndpointBToEndpointA);
    assert!(dropped_direction.partitioned);
    assert!(!live_direction.partitioned);

    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "network-fault-application-partition-topology",
        Shift { bits: 0 },
        4,
        SimInstant { nanos: 50 },
        vec![scenario_node(
            "server",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Finite(SimDuration { nanos: 10 }),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![
        SchedulerLookaheadEdge::new(
            endpoint_a.clone(),
            endpoint_b.clone(),
            duration(10).to_sim_duration(),
        ),
        SchedulerLookaheadEdge::new(
            endpoint_b.clone(),
            endpoint_a.clone(),
            duration(20).to_sim_duration(),
        ),
    ]);
    let mut scheduler = ok(SingleScheduler::new(scenario));

    let mut link = ok(NetLink::new(0, 1, 10, 1, LinkFaults::none()));
    let application = ok(crucible::apply_combined_network_faults_to_scheduler(
        3,
        endpoint_a.clone(),
        endpoint_b.clone(),
        &mut link,
        faults,
        NetworkLinkDirection::EndpointAToEndpointB,
        &mut scheduler,
    ));
    assert_eq!(application.link_faults, dropped_direction);
    assert_eq!(
        application
            .topology_changes
            .first()
            .map(|change| change.sequence),
        Some(3)
    );
    assert_eq!(application.topology_changes.len(), 1);
    let outcome = ok(link.emit(
        &Frame::new(0, 1, vec![1, 2, 3]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert!(
        outcome.deliveries.is_empty(),
        "a partition covering the directed link drops frames at RESOLVE"
    );

    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    let scheduler_outcome = ok(scheduler.drive_quantum(request));

    assert_eq!(
        scheduler_outcome.frontier,
        crucible::VirtualTime { ticks: 50 }
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err(),
        "the bridge-produced partition change removes the covered scheduler edge"
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_b, &endpoint_a)
            .is_ok(),
        "the opposite directed edge remains live"
    );
    assert_eq!(
        scheduler.topology_change_applications()[0].updates[0].recomputed_lookahead,
        NetworkLookahead::Infinite
    );

    let healed = ok(crucible::heal_combined_network_faults_to_scheduler(
        4,
        endpoint_a.clone(),
        endpoint_b.clone(),
        &mut link,
        &CombinedNetworkFaults::default(),
        NetworkLinkDirection::EndpointAToEndpointB,
        vec![SchedulerLookaheadEdge::new(
            endpoint_a.clone(),
            endpoint_b.clone(),
            duration(10).to_sim_duration(),
        )],
        &mut scheduler,
    ));
    assert_eq!(healed.link_faults, LinkFaults::none());
    assert_eq!(
        healed
            .topology_changes
            .first()
            .map(|change| change.sequence),
        Some(4)
    );
    assert_eq!(healed.topology_changes.len(), 1);
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    let _ = ok(scheduler.drive_quantum(request));
    let authorization = ok(scheduler.authorize_cross_node_send(&endpoint_a, &endpoint_b));
    assert_eq!(
        authorization.topology_epoch, 2,
        "the bridge-produced heal restores the covered scheduler edge"
    );
}

#[test]
fn partial_partition_heal_restores_only_uncovered_edges() {
    let target = link("client-server");
    let endpoint_a = scheduler_node("client");
    let endpoint_b = scheduler_node("server");
    let active = CombinedFaults::from_faults(&[Fault::Network(NetworkFault::Partition {
        link: target.clone(),
        direction: PartitionDirection::Bidirectional,
    })]);
    let active_faults = active
        .network
        .get(&target)
        .unwrap_or_else(|| panic!("combined network faults should include target"));
    let remaining = CombinedFaults::from_faults(&[Fault::Network(NetworkFault::Partition {
        link: target.clone(),
        direction: PartitionDirection::EndpointBToEndpointA,
    })]);
    let remaining_faults = remaining
        .network
        .get(&target)
        .unwrap_or_else(|| panic!("remaining network faults should include target"));

    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "network-fault-application-partial-partition-heal",
        Shift { bits: 0 },
        4,
        SimInstant { nanos: 50 },
        vec![scenario_node(
            "server",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Finite(SimDuration { nanos: 10 }),
        )],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![
        SchedulerLookaheadEdge::new(
            endpoint_a.clone(),
            endpoint_b.clone(),
            duration(10).to_sim_duration(),
        ),
        SchedulerLookaheadEdge::new(
            endpoint_b.clone(),
            endpoint_a.clone(),
            duration(20).to_sim_duration(),
        ),
    ]);
    let mut scheduler = ok(SingleScheduler::new(scenario));
    let mut link = ok(NetLink::new(0, 1, 10, 1, LinkFaults::none()));

    let activation = ok(crucible::apply_combined_network_faults_to_scheduler(
        3,
        endpoint_a.clone(),
        endpoint_b.clone(),
        &mut link,
        active_faults,
        NetworkLinkDirection::EndpointAToEndpointB,
        &mut scheduler,
    ));
    assert_eq!(activation.topology_changes.len(), 1);
    let _ = drive_scheduler(&mut scheduler);
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_err()
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_b, &endpoint_a)
            .is_err()
    );

    let healed = ok(crucible::heal_combined_network_faults_to_scheduler(
        4,
        endpoint_a.clone(),
        endpoint_b.clone(),
        &mut link,
        remaining_faults,
        NetworkLinkDirection::EndpointAToEndpointB,
        vec![
            SchedulerLookaheadEdge::new(
                endpoint_a.clone(),
                endpoint_b.clone(),
                duration(10).to_sim_duration(),
            ),
            SchedulerLookaheadEdge::new(
                endpoint_b.clone(),
                endpoint_a.clone(),
                duration(20).to_sim_duration(),
            ),
        ],
        &mut scheduler,
    ));

    assert_eq!(
        healed.link_faults,
        link_faults_from_combined_network(
            remaining_faults,
            NetworkLinkDirection::EndpointAToEndpointB
        )
    );
    assert!(
        !healed.link_faults.partitioned,
        "A->B link table is healed when only B->A remains partitioned"
    );
    assert_eq!(
        healed
            .topology_changes
            .iter()
            .map(|change| change.sequence)
            .collect::<Vec<_>>(),
        vec![4, 4],
        "partial heal queues the remaining removal and the uncovered restore"
    );
    let _ = drive_scheduler(&mut scheduler);

    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_a, &endpoint_b)
            .is_ok(),
        "A->B is restored because remaining coverage no longer removes it"
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&endpoint_b, &endpoint_a)
            .is_err(),
        "B->A stays removed because another active partition still covers it"
    );
}

#[test]
fn partition_drop_does_not_record_loss_fault_fire() {
    let link_id = device("client-server");
    let mut faults = LinkFaults::none();
    faults.partitioned = true;
    faults.loss = Probability::NEVER;
    let mut link = ok(NetLink::new(0, 1, 10, 1, faults));

    let record = ok(crucible::emit_link_frame_with_recorded_faults(
        Seed::from_u64(0x51eed),
        &link_id,
        &mut link,
        &Frame::new(0, 1, vec![1, 2, 3]),
        PastDeliveryPolicy::FailLoud,
    ));

    assert!(record.outcome.deliveries.is_empty());
    assert_eq!(
        fault_outcome(&record.decisions, &link_id, "loss"),
        Some(false),
        "partition drops are deterministic topology effects, not probabilistic loss fires"
    );
    assert_eq!(
        fault_outcome(&record.decisions, &link_id, "duplicate"),
        Some(false)
    );
    assert_eq!(
        fault_outcome(&record.decisions, &link_id, "corrupt"),
        Some(false)
    );
}

fn link(name: &str) -> LinkId {
    LinkId::from_name(name)
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: crucible::NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
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

fn device(name: &str) -> DeviceId {
    DeviceId {
        name: name.to_owned(),
    }
}

fn fault_outcome(decisions: &[Decision], device: &DeviceId, kind: &str) -> Option<bool> {
    let expected = crucible::io_fault_id(device, kind);
    decisions.iter().find_map(|decision| match decision {
        Decision::FaultFires(outcome) if outcome.fault == expected => Some(outcome.fired),
        _ => None,
    })
}

fn drive_scheduler(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    ok(scheduler.drive_quantum(request))
}

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("valid fault rate: {error}"))
}

fn duration(nanos: u64) -> FaultDuration {
    FaultDuration::from_nanos(nanos)
}

fn bandwidth(bits_per_second: u64) -> FaultBandwidthBitsPerSecond {
    FaultBandwidthBitsPerSecond::new(bits_per_second)
        .unwrap_or_else(|error| panic!("valid bandwidth limit: {error}"))
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}
