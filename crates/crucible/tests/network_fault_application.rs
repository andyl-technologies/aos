//! Checks T-FAULT-6 network fault application on the link sub-node.

#![forbid(unsafe_code)]

use crucible::{
    CombinedFaults, Fault, FaultBandwidthBitsPerSecond, FaultDuration, FaultRateBasisPoints,
    LinkId, NetworkCorruptionFault, NetworkFault, NetworkLinkDirection, NetworkLookahead,
    PartitionDirection, SchedulerLookaheadEdge, SchedulerLookaheadEdgeEndpoint,
    SchedulerLookaheadGraph, SchedulerNodeId, SchedulingNodeKind, SimDuration,
    link_faults_from_combined_network, network_partition_change, network_partition_removed_edges,
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

    let mut link = ok(NetLink::new(0, 1, 10, 1, dropped_direction));
    let outcome = ok(link.emit(
        &Frame::new(0, 1, vec![1, 2, 3]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert!(
        outcome.deliveries.is_empty(),
        "a partition covering the directed link drops frames at RESOLVE"
    );

    let change = network_partition_change(3, endpoint_a.clone(), endpoint_b.clone(), faults)
        .unwrap_or_else(|| panic!("partition should produce a topology change"));
    assert_eq!(change.sequence, 3);

    let graph = SchedulerLookaheadGraph::from_edges([
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
    let partitioned = graph.remove_effective_edges(removed);
    assert_eq!(
        partitioned.lookahead(&endpoint_b),
        NetworkLookahead::Infinite
    );
    assert_eq!(
        partitioned.lookahead(&endpoint_a),
        NetworkLookahead::Finite(SimDuration { nanos: 20 })
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
