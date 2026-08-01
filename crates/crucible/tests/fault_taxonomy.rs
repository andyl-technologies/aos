#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BlockFault, DeviceId, EngineError, Fault, FaultBandwidthBitsPerSecond, FaultDuration,
    FaultRateBasisPoints, FaultSlowdownFactorBasisPoints, IoFailureMode, LinkId,
    NetworkCorruptionFault, NetworkFault, NinePErrno, NinePFault, NodeFault, NodeId,
    PartitionDirection, RestartPolicy, SimOffset,
};

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("basis-point rate should be valid: {error}"))
}

fn slowdown(basis_points: u32) -> FaultSlowdownFactorBasisPoints {
    FaultSlowdownFactorBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("slowdown factor should be valid: {error}"))
}

fn bandwidth(bits_per_second: u64) -> FaultBandwidthBitsPerSecond {
    FaultBandwidthBitsPerSecond::new(bits_per_second)
        .unwrap_or_else(|error| panic!("bandwidth should be valid: {error}"))
}

fn duration(nanos: u64) -> FaultDuration {
    FaultDuration::from_nanos(nanos)
}

fn link(name: &str) -> LinkId {
    LinkId::from_name(name)
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

fn errno(code: i32) -> NinePErrno {
    NinePErrno::from_code(code).unwrap_or_else(|error| panic!("errno should be valid: {error}"))
}

fn every_fault_kind() -> Vec<Fault> {
    vec![
        Fault::Network(NetworkFault::Partition {
            link: link("client-server"),
            direction: PartitionDirection::Bidirectional,
        }),
        Fault::Network(NetworkFault::Partition {
            link: link("client-server-a-to-b"),
            direction: PartitionDirection::EndpointAToEndpointB,
        }),
        Fault::Network(NetworkFault::Partition {
            link: link("client-server-b-to-a"),
            direction: PartitionDirection::EndpointBToEndpointA,
        }),
        Fault::Network(NetworkFault::Loss {
            link: link("lossy"),
            rate: rate(250),
        }),
        Fault::Network(NetworkFault::Reorder {
            link: link("reorder"),
            window: duration(7),
        }),
        Fault::Network(NetworkFault::Duplicate {
            link: link("duplicate"),
            rate: rate(375),
            gap: duration(11),
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link("bit-flip"),
            kind: NetworkCorruptionFault::BitFlip {
                rate: rate(500),
                max_bits: 3,
            },
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link("field-mutation"),
            kind: NetworkCorruptionFault::FieldMutation { rate: rate(625) },
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link("truncation"),
            kind: NetworkCorruptionFault::Truncation {
                rate: rate(750),
                max_bytes: 64,
            },
        }),
        Fault::Network(NetworkFault::Bandwidth {
            link: link("bandwidth"),
            limit: bandwidth(4096),
        }),
        Fault::Network(NetworkFault::LatencyBump {
            link: link("latency"),
            extra: duration(13),
        }),
        Fault::Node(NodeFault::Crash {
            node: node("server"),
            restart: RestartPolicy::FromReadyPoint,
        }),
        Fault::Node(NodeFault::Crash {
            node: node("checkpointed-server"),
            restart: RestartPolicy::FromLastCheckpoint,
        }),
        Fault::Node(NodeFault::Crash {
            node: node("stopped-server"),
            restart: RestartPolicy::StayDown,
        }),
        Fault::Node(NodeFault::Slow {
            node: node("slow-node"),
            factor: slowdown(20_000),
        }),
        Fault::Node(NodeFault::ClockSkew {
            node: node("skewed-node"),
            offset: SimOffset { nanos: -42 },
        }),
        Fault::Block(BlockFault::Latency {
            device: device("disk0"),
            extra: duration(17),
            jitter: duration(5),
        }),
        Fault::Block(BlockFault::Failure {
            device: device("disk1"),
            rate: rate(875),
            mode: IoFailureMode::ErrorStatus,
        }),
        Fault::Block(BlockFault::Reorder {
            device: device("disk2"),
            window: duration(19),
        }),
        Fault::Block(BlockFault::Duplicate {
            device: device("disk3"),
            rate: rate(125),
            gap: duration(29),
        }),
        Fault::Block(BlockFault::Corruption {
            device: device("disk4"),
            rate: rate(150),
            bit_flips: 4,
        }),
        Fault::Block(BlockFault::Bandwidth {
            device: device("disk5"),
            limit: bandwidth(8192),
        }),
        Fault::NineP(NinePFault::Latency {
            device: device("fs0"),
            extra: duration(23),
            jitter: duration(3),
        }),
        Fault::NineP(NinePFault::Failure {
            device: device("fs1"),
            rate: rate(1000),
            errno: errno(5),
        }),
        Fault::NineP(NinePFault::Reorder {
            device: device("fs2"),
            window: duration(31),
        }),
        Fault::NineP(NinePFault::Duplicate {
            device: device("fs3"),
            rate: rate(175),
            gap: duration(37),
        }),
        Fault::NineP(NinePFault::Corruption {
            device: device("fs4"),
            rate: rate(200),
            bit_flips: 5,
        }),
        Fault::NineP(NinePFault::Bandwidth {
            device: device("fs5"),
            limit: bandwidth(16_384),
        }),
    ]
}

#[test]
fn fault_taxonomy_covers_all_rfc_fault_kinds() {
    let faults = every_fault_kind();
    let kind_keys = faults
        .iter()
        .map(Fault::kind_key)
        .collect::<Vec<&'static str>>();

    assert_eq!(
        kind_keys,
        vec![
            "network.partition",
            "network.partition",
            "network.partition",
            "network.loss",
            "network.reorder",
            "network.duplicate",
            "network.corruption.bit-flip",
            "network.corruption.field-mutation",
            "network.corruption.truncation",
            "network.bandwidth",
            "network.latency-bump",
            "node.crash",
            "node.crash",
            "node.crash",
            "node.slow",
            "node.clock-skew",
            "block.latency",
            "block.failure",
            "block.reorder",
            "block.duplicate",
            "block.corruption.bit-flip",
            "block.bandwidth",
            "9p.latency",
            "9p.failure",
            "9p.reorder",
            "9p.duplicate",
            "9p.corruption.bit-flip",
            "9p.bandwidth",
        ]
    );

    assert!(faults.iter().any(|fault| {
        fault
            .canonical_material()
            .contains("direction=endpoint-a-to-endpoint-b")
    }));
    assert!(faults.iter().any(|fault| {
        fault
            .canonical_material()
            .contains("direction=endpoint-b-to-endpoint-a")
    }));
    assert!(faults.iter().any(|fault| {
        fault
            .canonical_material()
            .contains("restart=from-last-checkpoint")
    }));
    assert!(
        faults
            .iter()
            .any(|fault| { fault.canonical_material().contains("restart=stay-down") })
    );
    assert!(faults.iter().any(|fault| {
        fault
            .canonical_material()
            .contains("factor_basis_points=20000")
    }));
    assert!(
        faults
            .iter()
            .any(|fault| { fault.canonical_material().contains("mode=error-status") })
    );
    let drop_block_failure = Fault::Block(BlockFault::Failure {
        device: device("disk-drop"),
        rate: rate(100),
        mode: IoFailureMode::Drop,
    });
    assert!(
        drop_block_failure
            .canonical_material()
            .contains("mode=drop")
    );
    assert!(
        faults
            .iter()
            .any(|fault| { fault.canonical_material().contains("errno=5") })
    );
}

#[test]
fn fault_taxonomy_uses_integer_basis_point_time_and_bandwidth_units() {
    assert_eq!(FaultRateBasisPoints::ZERO.basis_points(), 0);
    assert_eq!(FaultRateBasisPoints::ONE.basis_points(), 10_000);
    assert_eq!(rate(9999).basis_points(), 9999);
    assert_eq!(FaultSlowdownFactorBasisPoints::ONE.basis_points(), 10_000);
    assert_eq!(slowdown(20_000).basis_points(), 20_000);
    assert_eq!(duration(31).nanos(), 31);
    assert_eq!(duration(31).to_sim_duration().nanos, 31);
    assert_eq!(bandwidth(8192).bits_per_second(), 8192);
    assert_eq!(NinePErrno::EIO.code(), 5);
    assert!(IoFailureMode::Drop > IoFailureMode::ErrorStatus);

    assert!(matches!(
        FaultRateBasisPoints::from_basis_points(10_001),
        Err(EngineError::FaultRateBasisPointsOutOfRange {
            basis_points: 10_001,
            maximum: 10_000
        })
    ));
    assert!(matches!(
        FaultSlowdownFactorBasisPoints::from_basis_points(9999),
        Err(EngineError::FaultSlowdownFactorBelowOne {
            basis_points: 9999,
            minimum: 10_000
        })
    ));
    assert!(matches!(
        FaultBandwidthBitsPerSecond::new(0),
        Err(EngineError::FaultBandwidthMustBeNonZero { bits_per_second: 0 })
    ));
    assert!(matches!(
        NinePErrno::from_code(0),
        Err(EngineError::NinePErrnoMustBePositive { code: 0 })
    ));

    for fault in every_fault_kind() {
        let material = fault.canonical_material();
        assert!(
            !material.contains("0.") && !material.contains("1."),
            "fault canonical material must not contain decimal rates: {material}"
        );
        assert!(
            material.contains("basis_points")
                || material.contains("nanos")
                || material.contains("bits_per_second")
                || material.contains("direction")
                || material.contains("restart")
                || material.contains("mode=")
                || material.contains("errno="),
            "fault canonical material must expose integer units: {material}"
        );
    }
}

#[test]
fn fault_taxonomy_content_hash_changes_with_parameters() {
    let first = Fault::Network(NetworkFault::Loss {
        link: link("client-server"),
        rate: rate(100),
    });
    let same = Fault::Network(NetworkFault::Loss {
        link: link("client-server"),
        rate: rate(100),
    });
    let changed_rate = Fault::Network(NetworkFault::Loss {
        link: link("client-server"),
        rate: rate(101),
    });
    let changed_kind = Fault::Network(NetworkFault::LatencyBump {
        link: link("client-server"),
        extra: duration(100),
    });

    assert_eq!(first.content_hash(), same.content_hash());
    assert_ne!(first.content_hash(), changed_rate.content_hash());
    assert_ne!(first.content_hash(), changed_kind.content_hash());
}

#[test]
fn fault_taxonomy_canonical_material_length_delimits_target_ids() {
    let adversarial_name = "client-server\nrate_basis_points=9999";
    let adversarial = Fault::Network(NetworkFault::Loss {
        link: link(adversarial_name),
        rate: rate(100),
    });
    let ordinary = Fault::Network(NetworkFault::Loss {
        link: link("client-server"),
        rate: rate(9999),
    });

    let material = adversarial.canonical_material();
    assert!(material.contains(&format!("link_len={}", adversarial_name.len())));
    assert!(material.contains(adversarial_name));
    assert_ne!(adversarial.content_hash(), ordinary.content_hash());
}
