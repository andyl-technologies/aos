//! Checks T-FAULT-5 deterministic overlapping-fault combination.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BlockFault, CombinedFaults, CombinedNinePFailureFault, DeviceId, Fault,
    FaultBandwidthBitsPerSecond, FaultDuration, FaultRateBasisPoints,
    FaultSlowdownFactorBasisPoints, IoFailureMode, LinkId, NetworkCorruptionFault, NetworkFault,
    NinePErrno, NinePFault, NodeFault, NodeId, PartitionDirection, RestartPolicy, SimOffset,
};

#[test]
fn overlapping_fault_combination_is_order_independent() {
    let first = sample_faults();
    let second = {
        let mut faults = sample_faults();
        faults.reverse();
        faults
    };

    assert_eq!(
        CombinedFaults::from_faults(&first),
        CombinedFaults::from_faults(&second)
    );
}

#[test]
fn network_faults_follow_the_rfc_combination_table() {
    let combined = CombinedFaults::from_faults(&sample_faults());
    let network = combined
        .network
        .get(&link("client-server"))
        .unwrap_or_else(|| panic!("combined network faults should include the link"));
    let partition = network
        .partition
        .unwrap_or_else(|| panic!("partition should be active"));

    assert!(partition.endpoint_a_to_endpoint_b);
    assert!(partition.endpoint_b_to_endpoint_a);
    assert_eq!(
        network.loss_rates,
        vec![rate(9_000), rate(2_500), rate(100)]
    );
    assert_eq!(network.latency.nanos(), 12);
    assert_eq!(network.reorder_window, Some(duration(44)));
    assert_eq!(
        network
            .duplicate
            .unwrap_or_else(|| panic!("duplicate should be active"))
            .rate,
        rate(8_000)
    );
    assert_eq!(
        network
            .duplicate
            .unwrap_or_else(|| panic!("duplicate should be active"))
            .gap,
        duration(7)
    );
    assert_eq!(
        network
            .corruption
            .as_ref()
            .unwrap_or_else(|| panic!("corruption should be active"))
            .rate,
        rate(7_000)
    );
    assert_eq!(
        network
            .corruption
            .as_ref()
            .unwrap_or_else(|| panic!("corruption should be active"))
            .strategies
            .iter()
            .map(NetworkCorruptionFault::kind_key)
            .collect::<Vec<_>>(),
        vec![
            "network.corruption.bit-flip",
            "network.corruption.field-mutation",
            "network.corruption.truncation"
        ]
    );
    assert_eq!(
        network.bandwidth_limits,
        vec![bandwidth(1_000), bandwidth(2_000)]
    );

    let isolated = combined
        .network
        .get(&link("admin-db"))
        .unwrap_or_else(|| panic!("combined network faults should include admin-db"));
    assert_eq!(isolated.loss_rates, vec![rate(4_000)]);
    assert_eq!(isolated.latency.nanos(), 99);
}

#[test]
fn node_faults_follow_the_rfc_combination_table() {
    let combined = CombinedFaults::from_faults(&sample_faults());
    let db = combined
        .node
        .get(&node("db"))
        .unwrap_or_else(|| panic!("combined node faults should include db"));

    assert!(db.is_crashed());
    assert_eq!(db.crash_restart, Some(RestartPolicy::StayDown));
    assert_eq!(db.slow_factor, Some(slowdown(20_000)));
    assert_eq!(db.clock_skew, SimOffset { nanos: 40 });

    let cache = combined
        .node
        .get(&node("cache"))
        .unwrap_or_else(|| panic!("combined node faults should include cache"));
    assert!(!cache.is_crashed());
    assert_eq!(cache.slow_factor, Some(slowdown(15_000)));
    assert_eq!(cache.clock_skew, SimOffset { nanos: -25 });
}

#[test]
fn block_and_9p_faults_follow_the_rfc_combination_table() {
    let combined = CombinedFaults::from_faults(&sample_faults());
    let block = combined
        .block
        .get(&device("disk0"))
        .unwrap_or_else(|| panic!("combined block faults should include disk0"));
    let ninep = combined
        .ninep
        .get(&device("fs0"))
        .unwrap_or_else(|| panic!("combined 9p faults should include fs0"));
    let second_block = combined
        .block
        .get(&device("disk1"))
        .unwrap_or_else(|| panic!("combined block faults should include disk1"));
    let second_ninep = combined
        .ninep
        .get(&device("fs1"))
        .unwrap_or_else(|| panic!("combined 9p faults should include fs1"));

    assert_eq!(block.latency_extra, duration(30));
    assert_eq!(block.latency_jitter, duration(3));
    assert_eq!(block.failure_rates, vec![rate(8_000), rate(1_000)]);
    assert_eq!(block.failure_mode, Some(IoFailureMode::Drop));
    assert_eq!(block.reorder_window, Some(duration(90)));
    assert_eq!(
        block
            .duplicate
            .unwrap_or_else(|| panic!("block duplicate should be active"))
            .rate,
        rate(7_000)
    );
    assert_eq!(
        block
            .duplicate
            .unwrap_or_else(|| panic!("block duplicate should be active"))
            .gap,
        duration(5)
    );
    assert_eq!(
        block
            .corruption
            .unwrap_or_else(|| panic!("block corruption should be active"))
            .rate,
        rate(6_500)
    );
    assert_eq!(
        block
            .corruption
            .unwrap_or_else(|| panic!("block corruption should be active"))
            .bit_flips,
        4
    );
    assert_eq!(
        block.bandwidth_limits,
        vec![bandwidth(500), bandwidth(1_500)]
    );

    assert_eq!(ninep.latency_extra, duration(12));
    assert_eq!(ninep.latency_jitter, duration(6));
    assert_eq!(
        ninep.failures,
        vec![ninep_failure(6_000, 5), ninep_failure(2_000, 13)]
    );
    assert_eq!(ninep.reorder_window, Some(duration(33)));
    assert_eq!(
        ninep
            .duplicate
            .unwrap_or_else(|| panic!("9p duplicate should be active"))
            .rate,
        rate(5_500)
    );
    assert_eq!(
        ninep
            .duplicate
            .unwrap_or_else(|| panic!("9p duplicate should be active"))
            .gap,
        duration(8)
    );
    assert_eq!(
        ninep
            .corruption
            .unwrap_or_else(|| panic!("9p corruption should be active"))
            .rate,
        rate(3_500)
    );
    assert_eq!(
        ninep
            .corruption
            .unwrap_or_else(|| panic!("9p corruption should be active"))
            .bit_flips,
        9
    );
    assert_eq!(
        ninep.bandwidth_limits,
        vec![bandwidth(3_000), bandwidth(4_000)]
    );

    assert_eq!(second_block.latency_extra, duration(77));
    assert_eq!(second_block.failure_rates, vec![rate(3_000)]);
    assert_eq!(second_block.failure_mode, Some(IoFailureMode::ErrorStatus));
    assert_eq!(second_ninep.latency_jitter, duration(9));
    assert_eq!(second_ninep.failures, vec![ninep_failure(4_000, 2)]);
}

fn sample_faults() -> Vec<Fault> {
    vec![
        Fault::Network(NetworkFault::Loss {
            link: link("client-server"),
            rate: rate(100),
        }),
        Fault::Network(NetworkFault::Loss {
            link: link("client-server"),
            rate: rate(9_000),
        }),
        Fault::Network(NetworkFault::Loss {
            link: link("client-server"),
            rate: rate(2_500),
        }),
        Fault::Network(NetworkFault::LatencyBump {
            link: link("client-server"),
            extra: duration(5),
        }),
        Fault::Network(NetworkFault::LatencyBump {
            link: link("client-server"),
            extra: duration(7),
        }),
        Fault::Network(NetworkFault::Bandwidth {
            link: link("client-server"),
            limit: bandwidth(2_000),
        }),
        Fault::Network(NetworkFault::Bandwidth {
            link: link("client-server"),
            limit: bandwidth(1_000),
        }),
        Fault::Network(NetworkFault::Reorder {
            link: link("client-server"),
            window: duration(17),
        }),
        Fault::Network(NetworkFault::Reorder {
            link: link("client-server"),
            window: duration(44),
        }),
        Fault::Network(NetworkFault::Duplicate {
            link: link("client-server"),
            rate: rate(8_000),
            gap: duration(3),
        }),
        Fault::Network(NetworkFault::Duplicate {
            link: link("client-server"),
            rate: rate(8_000),
            gap: duration(7),
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link("client-server"),
            kind: NetworkCorruptionFault::Truncation {
                rate: rate(7_000),
                max_bytes: 12,
            },
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link("client-server"),
            kind: NetworkCorruptionFault::FieldMutation { rate: rate(200) },
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link("client-server"),
            kind: NetworkCorruptionFault::BitFlip {
                rate: rate(5_000),
                max_bits: 3,
            },
        }),
        Fault::Network(NetworkFault::Partition {
            link: link("client-server"),
            direction: PartitionDirection::EndpointAToEndpointB,
        }),
        Fault::Network(NetworkFault::Partition {
            link: link("client-server"),
            direction: PartitionDirection::EndpointBToEndpointA,
        }),
        Fault::Network(NetworkFault::Loss {
            link: link("admin-db"),
            rate: rate(4_000),
        }),
        Fault::Network(NetworkFault::LatencyBump {
            link: link("admin-db"),
            extra: duration(99),
        }),
        Fault::Node(NodeFault::Crash {
            node: node("db"),
            restart: RestartPolicy::FromReadyPoint,
        }),
        Fault::Node(NodeFault::Crash {
            node: node("db"),
            restart: RestartPolicy::StayDown,
        }),
        Fault::Node(NodeFault::Slow {
            node: node("db"),
            factor: slowdown(12_500),
        }),
        Fault::Node(NodeFault::Slow {
            node: node("db"),
            factor: slowdown(20_000),
        }),
        Fault::Node(NodeFault::ClockSkew {
            node: node("db"),
            offset: SimOffset { nanos: 50 },
        }),
        Fault::Node(NodeFault::ClockSkew {
            node: node("db"),
            offset: SimOffset { nanos: -10 },
        }),
        Fault::Node(NodeFault::Slow {
            node: node("cache"),
            factor: slowdown(15_000),
        }),
        Fault::Node(NodeFault::ClockSkew {
            node: node("cache"),
            offset: SimOffset { nanos: -25 },
        }),
        Fault::Block(BlockFault::Latency {
            device: device("disk0"),
            extra: duration(10),
            jitter: duration(1),
        }),
        Fault::Block(BlockFault::Latency {
            device: device("disk0"),
            extra: duration(20),
            jitter: duration(2),
        }),
        Fault::Block(BlockFault::Failure {
            device: device("disk0"),
            rate: rate(1_000),
            mode: IoFailureMode::ErrorStatus,
        }),
        Fault::Block(BlockFault::Failure {
            device: device("disk0"),
            rate: rate(8_000),
            mode: IoFailureMode::Drop,
        }),
        Fault::Block(BlockFault::Reorder {
            device: device("disk0"),
            window: duration(11),
        }),
        Fault::Block(BlockFault::Reorder {
            device: device("disk0"),
            window: duration(90),
        }),
        Fault::Block(BlockFault::Duplicate {
            device: device("disk0"),
            rate: rate(7_000),
            gap: duration(2),
        }),
        Fault::Block(BlockFault::Duplicate {
            device: device("disk0"),
            rate: rate(7_000),
            gap: duration(5),
        }),
        Fault::Block(BlockFault::Corruption {
            device: device("disk0"),
            rate: rate(6_500),
            bit_flips: 2,
        }),
        Fault::Block(BlockFault::Corruption {
            device: device("disk0"),
            rate: rate(6_500),
            bit_flips: 4,
        }),
        Fault::Block(BlockFault::Bandwidth {
            device: device("disk0"),
            limit: bandwidth(1_500),
        }),
        Fault::Block(BlockFault::Bandwidth {
            device: device("disk0"),
            limit: bandwidth(500),
        }),
        Fault::Block(BlockFault::Latency {
            device: device("disk1"),
            extra: duration(77),
            jitter: duration(0),
        }),
        Fault::Block(BlockFault::Failure {
            device: device("disk1"),
            rate: rate(3_000),
            mode: IoFailureMode::ErrorStatus,
        }),
        Fault::NineP(NinePFault::Latency {
            device: device("fs0"),
            extra: duration(4),
            jitter: duration(2),
        }),
        Fault::NineP(NinePFault::Latency {
            device: device("fs0"),
            extra: duration(8),
            jitter: duration(4),
        }),
        Fault::NineP(NinePFault::Failure {
            device: device("fs0"),
            rate: rate(6_000),
            errno: errno(5),
        }),
        Fault::NineP(NinePFault::Failure {
            device: device("fs0"),
            rate: rate(2_000),
            errno: errno(13),
        }),
        Fault::NineP(NinePFault::Reorder {
            device: device("fs0"),
            window: duration(21),
        }),
        Fault::NineP(NinePFault::Reorder {
            device: device("fs0"),
            window: duration(33),
        }),
        Fault::NineP(NinePFault::Duplicate {
            device: device("fs0"),
            rate: rate(5_500),
            gap: duration(3),
        }),
        Fault::NineP(NinePFault::Duplicate {
            device: device("fs0"),
            rate: rate(5_500),
            gap: duration(8),
        }),
        Fault::NineP(NinePFault::Corruption {
            device: device("fs0"),
            rate: rate(3_500),
            bit_flips: 6,
        }),
        Fault::NineP(NinePFault::Corruption {
            device: device("fs0"),
            rate: rate(3_500),
            bit_flips: 9,
        }),
        Fault::NineP(NinePFault::Bandwidth {
            device: device("fs0"),
            limit: bandwidth(4_000),
        }),
        Fault::NineP(NinePFault::Bandwidth {
            device: device("fs0"),
            limit: bandwidth(3_000),
        }),
        Fault::NineP(NinePFault::Latency {
            device: device("fs1"),
            extra: duration(0),
            jitter: duration(9),
        }),
        Fault::NineP(NinePFault::Failure {
            device: device("fs1"),
            rate: rate(4_000),
            errno: errno(2),
        }),
    ]
}

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("test rate should be valid: {error}"))
}

fn slowdown(basis_points: u32) -> FaultSlowdownFactorBasisPoints {
    FaultSlowdownFactorBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("test slowdown should be valid: {error}"))
}

fn duration(nanos: u64) -> FaultDuration {
    FaultDuration::from_nanos(nanos)
}

fn bandwidth(bits_per_second: u64) -> FaultBandwidthBitsPerSecond {
    FaultBandwidthBitsPerSecond::new(bits_per_second)
        .unwrap_or_else(|error| panic!("test bandwidth should be valid: {error}"))
}

fn errno(code: i32) -> NinePErrno {
    NinePErrno::from_code(code)
        .unwrap_or_else(|error| panic!("test errno should be valid: {error}"))
}

fn ninep_failure(rate_basis_points: u32, errno_code: i32) -> CombinedNinePFailureFault {
    CombinedNinePFailureFault {
        rate: rate(rate_basis_points),
        errno: errno(errno_code),
    }
}

fn link(name: &str) -> LinkId {
    LinkId {
        name: name.to_owned(),
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn device(name: &str) -> DeviceId {
    DeviceId {
        name: name.to_owned(),
    }
}
