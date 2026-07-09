//! Checks T-FAULT-4 integer fault rates and integer-only fault transforms.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BlockFault, Configuration, Decision, DecisionRecorder, DeviceId, Fault,
    FaultBandwidthBitsPerSecond, FaultDecision, FaultDuration, FaultId, FaultRateBasisPoints,
    FaultSlowdownFactorBasisPoints, FaultTag, Icount, IoFailureMode, LinkDef, LinkId,
    NetworkCorruptionFault, NetworkFault, NinePErrno, NinePFault, NodeFault, NodeId, NodeTemplate,
    Plan, PlanEntry, ReadyPoint, ScenarioDef, Seed, VirtualTime, WhiteBoxPolicy, WorldNode,
};

#[test]
fn basis_point_rates_compare_integer_buckets() {
    assert_eq!(FaultRateBasisPoints::DENOMINATOR, 10_000);
    assert_eq!(FaultRateBasisPoints::draw_bucket(0), 0);
    assert_eq!(FaultRateBasisPoints::draw_bucket(9_999), 9_999);
    assert_eq!(FaultRateBasisPoints::draw_bucket(10_000), 0);

    let quarter = rate(2_500);
    assert!(quarter.fires_on_draw(0));
    assert!(quarter.fires_on_draw(2_499));
    assert!(!quarter.fires_on_draw(2_500));
    assert!(quarter.fires_on_draw(10_000));
    assert!(!FaultRateBasisPoints::ZERO.fires_on_draw(0));
    assert!(FaultRateBasisPoints::ONE.fires_on_draw(u64::MAX));
}

#[test]
fn decision_recorder_records_basis_point_faults_from_seeded_draws() {
    let configuration = Configuration::genesis(scenario());
    let stream = crucible::RngStreamId::for_link("client-server/loss");
    let fault = FaultId {
        name: String::from("network.loss/client-server"),
    };
    let at = VirtualTime { ticks: 7 };
    let mut preview = DecisionRecorder::new(configuration.clone());
    let raw_draw = preview.draw_u64(stream.clone());
    let bucket = FaultRateBasisPoints::draw_bucket(raw_draw);

    let mut at_boundary = DecisionRecorder::new(configuration.clone());
    let fired_at_boundary = at_boundary.decide_fault_basis_points(
        at,
        fault.clone(),
        stream.clone(),
        rate(bucket.into()),
    );

    let mut above_boundary = DecisionRecorder::new(configuration);
    let fired_above_boundary = above_boundary.decide_fault_basis_points(
        at,
        fault.clone(),
        stream.clone(),
        rate(u32::from(bucket) + 1),
    );

    assert!(!fired_at_boundary, "bucket == rate must not fire");
    assert!(fired_above_boundary, "bucket < rate must fire");
    assert_recorded_basis_point_decision(
        at_boundary.schedule().decisions(),
        &stream,
        raw_draw,
        false,
    );
    assert_recorded_basis_point_decision(
        above_boundary.schedule().decisions(),
        &stream,
        raw_draw,
        true,
    );
}

#[test]
fn fault_canonical_material_uses_integer_rate_time_and_bandwidth_units() {
    let samples = [
        Fault::Network(NetworkFault::Loss {
            link: link("client-server"),
            rate: rate(2_500),
        }),
        Fault::Network(NetworkFault::Duplicate {
            link: link("client-server"),
            rate: rate(333),
            gap: duration(42),
        }),
        Fault::Network(NetworkFault::Corruption {
            link: link("client-server"),
            kind: NetworkCorruptionFault::BitFlip {
                rate: rate(1),
                max_bits: 8,
            },
        }),
        Fault::Network(NetworkFault::Bandwidth {
            link: link("client-server"),
            limit: FaultBandwidthBitsPerSecond::new(1_000_000)
                .unwrap_or_else(|error| panic!("test bandwidth should be valid: {error}")),
        }),
        Fault::Node(NodeFault::Slow {
            node: node("db"),
            factor: FaultSlowdownFactorBasisPoints::from_basis_points(12_500)
                .unwrap_or_else(|error| panic!("test slowdown should be valid: {error}")),
        }),
        Fault::Block(BlockFault::Latency {
            device: device("disk0"),
            extra: duration(300),
            jitter: duration(17),
        }),
        Fault::Block(BlockFault::Failure {
            device: device("disk0"),
            rate: rate(10_000),
            mode: IoFailureMode::ErrorStatus,
        }),
        Fault::Block(BlockFault::Duplicate {
            device: device("disk0"),
            rate: rate(125),
            gap: duration(9),
        }),
        Fault::Block(BlockFault::Corruption {
            device: device("disk0"),
            rate: rate(250),
            bit_flips: 3,
        }),
        Fault::Block(BlockFault::Bandwidth {
            device: device("disk0"),
            limit: FaultBandwidthBitsPerSecond::new(2_000_000)
                .unwrap_or_else(|error| panic!("test bandwidth should be valid: {error}")),
        }),
        Fault::NineP(NinePFault::Failure {
            device: device("fs0"),
            rate: rate(750),
            errno: NinePErrno::EIO,
        }),
        Fault::NineP(NinePFault::Reorder {
            device: device("fs0"),
            window: duration(11),
        }),
        Fault::NineP(NinePFault::Duplicate {
            device: device("fs0"),
            rate: rate(375),
            gap: duration(13),
        }),
        Fault::NineP(NinePFault::Corruption {
            device: device("fs0"),
            rate: rate(500),
            bit_flips: 4,
        }),
        Fault::NineP(NinePFault::Bandwidth {
            device: device("fs0"),
            limit: FaultBandwidthBitsPerSecond::new(3_000_000)
                .unwrap_or_else(|error| panic!("test bandwidth should be valid: {error}")),
        }),
    ];

    for fault in samples {
        let material = fault.canonical_material();
        assert!(
            !material.contains("0.") && !material.contains("1."),
            "canonical fault material must avoid decimal rates: {material}"
        );
        assert!(
            material.contains("rate_basis_points")
                || material.contains("factor_basis_points")
                || material.contains("nanos")
                || material.contains("bits_per_second"),
            "canonical fault material must expose integer units: {material}"
        );
    }
}

#[test]
fn scheduled_plan_toml_is_float_free_for_fault_entries() {
    let plan = Plan::from_entries_for_world(
        &world(),
        vec![PlanEntry::Activate {
            at: VirtualTime { ticks: 0 },
            tag: FaultTag {
                name: String::from("partition"),
            },
            fault: crucible::MembershipFault::Partition {
                endpoint_a: node("client"),
                endpoint_b: node("server"),
                direction: crucible::PartitionDirection::Bidirectional,
            },
        }],
    )
    .unwrap_or_else(|error| panic!("test plan should be valid: {error}"));
    let toml = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("test plan should serialize: {error}"));

    assert!(toml.contains("at_ticks = 0"));
    assert!(toml.contains("kind = \"partition\""));
    assert!(!toml.contains("0."));
    assert!(!toml.contains("rate ="));
}

#[test]
fn scheduled_plan_toml_rejects_decimal_fault_parameters() {
    let input = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = 0
tag = "decimal-rate"

[entry.fault]
kind = "crash"
node = "client"
restart = "stay_down"
rate = 1.5
"#;

    assert!(
        Plan::from_canonical_toml_for_world(&world(), input).is_err(),
        "decimal fault parameters must not enter canonical scheduled Plan TOML"
    );
}

fn assert_recorded_basis_point_decision(
    decisions: &[Decision],
    stream: &crucible::RngStreamId,
    raw_draw: u64,
    fired: bool,
) {
    assert_eq!(decisions.len(), 2);
    assert!(matches!(
        &decisions[0],
        Decision::RngDraw(draw) if &draw.stream == stream && draw.value == raw_draw
    ));
    assert!(matches!(
        &decisions[1],
        Decision::FaultFires(FaultDecision { at, fired: recorded, .. })
            if *at == (VirtualTime { ticks: 7 }) && *recorded == fired
    ));
}

fn scenario() -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.fault-integer-rates",
        "world.nodes=client,server\nworld.links=client-server",
        Seed::from_u64(0xface_b005),
    )
}

fn world() -> crucible::World {
    crucible::World::from_nodes_and_links(
        vec![ready_node("client", 1), ready_node("server", 1)],
        vec![
            LinkDef::new(node("client"), node("server"))
                .unwrap_or_else(|error| panic!("test link should be valid: {error}")),
        ],
    )
    .unwrap_or_else(|error| panic!("test world should be valid: {error}"))
}

fn ready_node(name: &str, retired: u64) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("test rate should be valid: {error}"))
}

fn duration(nanos: u64) -> FaultDuration {
    FaultDuration::from_nanos(nanos)
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
