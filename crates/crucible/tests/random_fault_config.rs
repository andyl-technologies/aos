//! Checks T-FAULT-14 random fault campaign generation.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BlockFault, ContentAddressedBlobRef, ContentHash, DeviceId, Fault, FaultBandwidthBitsPerSecond,
    FaultCaps, FaultDuration, FaultPlanEntry, FaultRateBasisPoints, FaultSlowdownFactorBasisPoints,
    FaultWeights, Icount, IoFailureMode, LinkDef, NetworkFault, NinePFault, NodeFault, NodeId,
    NodeTemplate, RandomFaultConfig, ReadyPoint, Seed, SeverityBounds, VmArchitecture,
    WhiteBoxPolicy, World, WorldBlockLatency, WorldDeviceKind, WorldIoCoreConfig, WorldIoNode,
    WorldNinePLatency, WorldNode, WorldNodeDef,
};
use crucible_device::{BaseImage, FsTree, Node};

#[test]
fn random_fault_config_generates_byte_identical_fault_plan() {
    let world = world();
    let config = base_config(42);

    let first = config
        .generate_for_world(&world)
        .expect("random fault plan should generate");
    let second = config
        .generate_for_world(&world)
        .expect("random fault plan should regenerate");
    let first_plan = crucible::Plan::from_fault_plan_for_world(&world, first.clone())
        .expect("generated plan should validate");
    let second_plan = crucible::Plan::from_fault_plan_for_world(&world, second.clone())
        .expect("generated plan should validate");

    assert_eq!(first.entries(), second.entries());
    assert_eq!(first_plan.content_hash(), second_plan.content_hash());
}

#[test]
fn random_fault_config_seed_changes_generated_plan() {
    let world = world();
    let first = base_config(42)
        .generate_for_world(&world)
        .expect("random fault plan should generate");
    let second = base_config(43)
        .generate_for_world(&world)
        .expect("random fault plan should generate");

    assert_ne!(first.entries(), second.entries());
}

#[test]
fn random_fault_config_uses_weighted_kind_selection_and_basis_point_bounds() {
    let world = world();
    let config = RandomFaultConfig {
        fault_slots: 6,
        duration: FaultDuration::from_nanos(100),
        weights: FaultWeights {
            message_loss: 1,
            ..zero_weights()
        },
        bounds: SeverityBounds {
            min_duration: FaultDuration::from_nanos(5),
            max_duration: FaultDuration::from_nanos(10),
            min_rate: rate(1234),
            max_rate: rate(1234),
            ..SeverityBounds::default()
        },
        caps: FaultCaps::default(),
        seed: Seed::from_u64(7),
    };

    let plan = config
        .generate_for_world(&world)
        .expect("loss-only random fault plan should generate");

    assert_eq!(plan.entries().len(), 6);
    for entry in plan.entries() {
        let FaultPlanEntry::At {
            fault: Fault::Network(NetworkFault::Loss { rate, .. }),
            ..
        } = entry
        else {
            panic!("only message-loss faults should be generated");
        };
        assert_eq!(rate.basis_points(), 1234);
    }
}

#[test]
fn random_fault_config_prunes_partition_crash_and_concurrency_caps() {
    let world = world();
    let partition_plan = RandomFaultConfig {
        fault_slots: 8,
        duration: FaultDuration::from_nanos(100),
        weights: FaultWeights {
            partition: 1,
            ..zero_weights()
        },
        bounds: fixed_overlap_bounds(),
        caps: FaultCaps {
            max_concurrent_faults: u32::MAX,
            max_partitions: 2,
            max_crashes: u32::MAX,
        },
        seed: Seed::from_u64(1),
    }
    .generate_for_world(&world)
    .expect("partition-only random fault plan should generate");
    assert_eq!(partition_plan.entries().len(), 2);
    assert!(partition_plan.entries().iter().all(|entry| matches!(
        entry,
        FaultPlanEntry::At {
            fault: Fault::Network(NetworkFault::Partition { .. }),
            ..
        }
    )));

    let crash_plan = RandomFaultConfig {
        fault_slots: 8,
        duration: FaultDuration::from_nanos(100),
        weights: FaultWeights {
            crash: 1,
            ..zero_weights()
        },
        bounds: fixed_overlap_bounds(),
        caps: FaultCaps {
            max_concurrent_faults: u32::MAX,
            max_partitions: u32::MAX,
            max_crashes: 1,
        },
        seed: Seed::from_u64(2),
    }
    .generate_for_world(&world)
    .expect("crash-only random fault plan should generate");
    assert_eq!(crash_plan.entries().len(), 1);
    assert!(matches!(
        crash_plan.entries()[0],
        FaultPlanEntry::At {
            fault: Fault::Node(NodeFault::Crash { .. }),
            ..
        }
    ));

    let concurrent_plan = RandomFaultConfig {
        fault_slots: 8,
        duration: FaultDuration::from_nanos(100),
        weights: FaultWeights {
            slow: 1,
            ..zero_weights()
        },
        bounds: fixed_overlap_bounds(),
        caps: FaultCaps {
            max_concurrent_faults: 3,
            max_partitions: u32::MAX,
            max_crashes: u32::MAX,
        },
        seed: Seed::from_u64(3),
    }
    .generate_for_world(&world)
    .expect("overlapping random fault plan should generate");
    assert_eq!(concurrent_plan.entries().len(), 3);
}

#[test]
fn random_fault_caps_prune_common_uncapped_generation_sequence() {
    let world = world();
    let uncapped = RandomFaultConfig {
        caps: FaultCaps::default(),
        ..partition_config(11)
    }
    .generate_for_world(&world)
    .expect("uncapped partition plan should generate");
    let capped = RandomFaultConfig {
        caps: FaultCaps {
            max_concurrent_faults: u32::MAX,
            max_partitions: 3,
            max_crashes: u32::MAX,
        },
        ..partition_config(11)
    }
    .generate_for_world(&world)
    .expect("capped partition plan should generate");

    assert_eq!(capped.entries(), &uncapped.entries()[..3]);
}

#[test]
fn random_fault_config_targets_collision_safe_world_link_ids() {
    let world = World::from_nodes_and_links(
        vec![
            ready_node("a"),
            ready_node("b--c"),
            ready_node("a--b"),
            ready_node("c"),
        ],
        vec![
            LinkDef::new(node("a"), node("b--c")).expect("test link should build"),
            LinkDef::new(node("a--b"), node("c")).expect("test link should build"),
        ],
    )
    .expect("adversarial link-name world should build");
    let config = RandomFaultConfig {
        fault_slots: 32,
        duration: FaultDuration::from_nanos(1_000),
        weights: FaultWeights {
            message_loss: 1,
            ..zero_weights()
        },
        bounds: SeverityBounds {
            min_rate: rate(10_000),
            max_rate: rate(10_000),
            ..SeverityBounds::default()
        },
        caps: FaultCaps::default(),
        seed: Seed::from_u64(19),
    };

    let plan = config
        .generate_for_world(&world)
        .expect("collision-safe link plan should generate");
    let mut links = std::collections::BTreeSet::new();
    for entry in plan.entries() {
        let FaultPlanEntry::At {
            fault: Fault::Network(NetworkFault::Loss { link, .. }),
            ..
        } = entry
        else {
            panic!("only loss faults should be generated");
        };
        links.insert(link.name.clone());
    }

    assert_eq!(links.len(), 2);
    assert!(
        links
            .iter()
            .all(|link| link.contains("link_endpoint_a_len="))
    );
}

#[test]
fn random_fault_config_returns_canonical_plan_and_pinned_scenario() {
    let world = world();
    let config = base_config(99);
    let plan = config
        .generate_for_world(&world)
        .expect("random fault plan should generate");

    assert!(plan.entries().windows(2).all(|pair| pair[0] <= pair[1]));
    let concrete_plan = crucible::Plan::from_fault_plan_for_world(&world, plan)
        .expect("generated fault plan should become a concrete plan component");
    let scenario = world
        .scenario_def_with_plan(&concrete_plan)
        .expect("generated concrete plan should pin a scenario");
    let repeat = world
        .scenario_def_with_plan(&concrete_plan)
        .expect("generated concrete plan should pin a scenario");

    assert_eq!(scenario.id(), repeat.id());
    assert_ne!(scenario.id(), world.scenario_def().id());
}

#[test]
fn random_fault_config_rejects_device_only_weights_without_matching_world_devices() {
    let world = world();
    let error = RandomFaultConfig {
        fault_slots: 4,
        duration: FaultDuration::from_nanos(100),
        weights: FaultWeights {
            block_latency: 1,
            block_failure: 1,
            block_reorder: 1,
            ninep_latency: 1,
            ninep_failure: 1,
            ..zero_weights()
        },
        bounds: SeverityBounds::default(),
        caps: FaultCaps::default(),
        seed: Seed::from_u64(5),
    }
    .generate_for_world(&world)
    .expect_err("device-only weights should be rejected without world devices");

    assert!(matches!(
        error,
        crucible::EngineError::RandomFaultConfigInvalid { .. }
    ));
}

#[test]
fn random_fault_config_generates_every_weighted_device_fault_kind() {
    let world = world_with_devices();
    let block_targets = device_targets(&world, WorldDeviceKind::Block);
    let ninep_targets = device_targets(&world, WorldDeviceKind::NineP);
    let cases = [
        (
            FaultWeights {
                block_latency: 1,
                ..zero_weights()
            },
            ExpectedDeviceFault::BlockLatency,
        ),
        (
            FaultWeights {
                block_failure: 1,
                ..zero_weights()
            },
            ExpectedDeviceFault::BlockFailure,
        ),
        (
            FaultWeights {
                block_reorder: 1,
                ..zero_weights()
            },
            ExpectedDeviceFault::BlockReorder,
        ),
        (
            FaultWeights {
                ninep_latency: 1,
                ..zero_weights()
            },
            ExpectedDeviceFault::NinePLatency,
        ),
        (
            FaultWeights {
                ninep_failure: 1,
                ..zero_weights()
            },
            ExpectedDeviceFault::NinePFailure,
        ),
    ];

    for (index, (weights, expected)) in cases.into_iter().enumerate() {
        let config = RandomFaultConfig {
            fault_slots: 12,
            duration: FaultDuration::from_nanos(1_000),
            weights,
            bounds: SeverityBounds {
                min_duration: FaultDuration::from_nanos(5),
                max_duration: FaultDuration::from_nanos(20),
                min_rate: rate(1_234),
                max_rate: rate(1_234),
                min_latency: FaultDuration::from_nanos(7),
                max_latency: FaultDuration::from_nanos(7),
                min_reorder_window: FaultDuration::from_nanos(11),
                max_reorder_window: FaultDuration::from_nanos(11),
                ..SeverityBounds::default()
            },
            caps: FaultCaps::default(),
            seed: Seed::from_u64(index as u64 + 100),
        };

        let first = config
            .generate_for_world(&world)
            .expect("device fault campaign should generate");
        let second = config
            .generate_for_world(&world)
            .expect("device fault campaign should reproduce");
        assert_eq!(first.entries(), second.entries());
        assert_eq!(first.entries().len(), 12);
        assert!(first.entries().iter().all(|entry| {
            let FaultPlanEntry::At { fault, .. } = entry else {
                return false;
            };
            exact_device_fault_matches(fault, expected, &block_targets, &ninep_targets)
        }));
    }
}

#[test]
fn device_fault_target_selection_stays_within_the_selected_device_family() {
    let world = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(ready_node("db-0")),
            WorldNodeDef::Io(io_ninep_node("a-share", "db-0")),
            WorldNodeDef::Io(io_block_node("z-disk", "db-0")),
        ],
        Vec::new(),
    )
    .expect("mixed device world should build");
    let expected = world
        .io_node(&node("z-disk"))
        .expect("block node should exist")
        .device_id();
    let plan = RandomFaultConfig {
        fault_slots: 32,
        duration: FaultDuration::from_nanos(1_000),
        weights: FaultWeights {
            block_latency: 1,
            ..zero_weights()
        },
        bounds: SeverityBounds::default(),
        caps: FaultCaps::default(),
        seed: Seed::from_u64(88),
    }
    .generate_for_world(&world)
    .expect("block-only campaign should generate");

    assert!(plan.entries().iter().all(|entry| matches!(
        entry,
        FaultPlanEntry::At {
            fault: Fault::Block(BlockFault::Latency { device, .. }),
            ..
        } if device == &expected
    )));
}

#[test]
fn mixed_device_weights_and_fixed_draw_order_have_a_golden_plan() {
    let world = world_with_devices();
    let config = RandomFaultConfig {
        fault_slots: 64,
        duration: FaultDuration::from_nanos(10_000),
        weights: FaultWeights {
            block_latency: 1,
            block_failure: 2,
            block_reorder: 3,
            ninep_latency: 4,
            ninep_failure: 5,
            ..zero_weights()
        },
        bounds: SeverityBounds {
            min_duration: FaultDuration::from_nanos(13),
            max_duration: FaultDuration::from_nanos(89),
            min_rate: rate(1_111),
            max_rate: rate(7_777),
            min_latency: FaultDuration::from_nanos(17),
            max_latency: FaultDuration::from_nanos(47),
            min_reorder_window: FaultDuration::from_nanos(19),
            max_reorder_window: FaultDuration::from_nanos(59),
            ..SeverityBounds::default()
        },
        caps: FaultCaps::default(),
        seed: Seed::from_u64(0x5eed_cafe),
    };
    let generated = config
        .generate_for_world(&world)
        .expect("mixed device campaign should generate");
    let mut kinds = std::collections::BTreeSet::new();
    for entry in generated.entries() {
        let FaultPlanEntry::At { fault, .. } = entry else {
            panic!("random campaign entries must be finite");
        };
        kinds.insert(fault.kind_key());
    }
    assert_eq!(
        kinds,
        [
            "block.failure",
            "block.latency",
            "block.reorder",
            "9p.failure",
            "9p.latency",
        ]
        .into_iter()
        .collect()
    );

    let plan = crucible::Plan::from_fault_plan_for_world(&world, generated)
        .expect("generated plan should validate");
    assert_eq!(
        ContentHash::from_bytes(&plan.canonical_bytes()).to_hex(),
        "3ee11b1ca171ff20296f5e687ed632223d0212e51c606424d062adae9810c279"
    );
}

fn base_config(seed: u64) -> RandomFaultConfig {
    RandomFaultConfig {
        fault_slots: 12,
        duration: FaultDuration::from_nanos(1_000),
        weights: FaultWeights {
            block_latency: 0,
            block_failure: 0,
            block_reorder: 0,
            ninep_latency: 0,
            ninep_failure: 0,
            ..FaultWeights::default()
        },
        bounds: SeverityBounds {
            min_duration: FaultDuration::from_nanos(10),
            max_duration: FaultDuration::from_nanos(80),
            min_rate: rate(100),
            max_rate: rate(1_000),
            min_latency: FaultDuration::from_nanos(3),
            max_latency: FaultDuration::from_nanos(30),
            min_reorder_window: FaultDuration::from_nanos(2),
            max_reorder_window: FaultDuration::from_nanos(20),
            min_duplicate_gap: FaultDuration::from_nanos(2),
            max_duplicate_gap: FaultDuration::from_nanos(20),
            min_bandwidth: bandwidth(1_000),
            max_bandwidth: bandwidth(10_000),
            min_slowdown: slowdown(10_000),
            max_slowdown: slowdown(30_000),
            ..SeverityBounds::default()
        },
        caps: FaultCaps {
            max_concurrent_faults: 4,
            max_partitions: 3,
            max_crashes: 2,
        },
        seed: Seed::from_u64(seed),
    }
}

fn fixed_overlap_bounds() -> SeverityBounds {
    SeverityBounds {
        min_duration: FaultDuration::from_nanos(100),
        max_duration: FaultDuration::from_nanos(100),
        min_rate: rate(10_000),
        max_rate: rate(10_000),
        min_slowdown: slowdown(20_000),
        max_slowdown: slowdown(20_000),
        ..SeverityBounds::default()
    }
}

fn partition_config(seed: u64) -> RandomFaultConfig {
    RandomFaultConfig {
        fault_slots: 8,
        duration: FaultDuration::from_nanos(100),
        weights: FaultWeights {
            partition: 1,
            ..zero_weights()
        },
        bounds: fixed_overlap_bounds(),
        caps: FaultCaps::default(),
        seed: Seed::from_u64(seed),
    }
}

fn zero_weights() -> FaultWeights {
    FaultWeights {
        partition: 0,
        message_loss: 0,
        reorder: 0,
        duplicate: 0,
        corruption: 0,
        bandwidth_limit: 0,
        latency_bump: 0,
        crash: 0,
        slow: 0,
        clock_skew: 0,
        block_latency: 0,
        block_failure: 0,
        block_reorder: 0,
        ninep_latency: 0,
        ninep_failure: 0,
    }
}

fn world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1"), ready_node("db-2")],
        vec![
            LinkDef::new(node("db-0"), node("db-1")).expect("test link should build"),
            LinkDef::new(node("db-1"), node("db-2")).expect("test link should build"),
        ],
    )
    .expect("test world should build")
}

fn world_with_devices() -> World {
    World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(ready_node("db-0")),
            WorldNodeDef::Vm(ready_node("db-1")),
            WorldNodeDef::Io(io_block_node("disk-a", "db-0")),
            WorldNodeDef::Io(io_block_node("disk-b", "db-1")),
            WorldNodeDef::Io(io_ninep_node("share-a", "db-0")),
        ],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("test device world should build")
}

fn io_block_node(name: &str, owner: &str) -> WorldIoNode {
    let bytes = format!("base-image-for-{name}").into_bytes();
    let base = BaseImage::new(bytes.clone());
    WorldIoNode::block(
        node(name),
        node(owner),
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(ContentHash { bytes: base.hash() }),
        bytes.len() as u64,
        WorldBlockLatency::new(100, 200, 30, 40, 1),
    )
}

fn io_ninep_node(name: &str, owner: &str) -> WorldIoNode {
    let tree = FsTree::try_new(Node::Directory {
        children: [(
            String::from("name"),
            Node::File {
                content: name.as_bytes().to_vec(),
            },
        )]
        .into_iter()
        .collect(),
    })
    .expect("test 9p tree components are valid");
    WorldIoNode::ninep(
        node(name),
        node(owner),
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(ContentHash {
            bytes: tree.content_hash(),
        }),
        WorldNinePLatency::new(80, 120, 1),
    )
}

fn device_targets(world: &World, kind: WorldDeviceKind) -> Vec<DeviceId> {
    world
        .io_nodes()
        .filter(|node| node.kind.family() == kind)
        .map(WorldIoNode::device_id)
        .collect()
}

#[derive(Clone, Copy)]
enum ExpectedDeviceFault {
    BlockLatency,
    BlockFailure,
    BlockReorder,
    NinePLatency,
    NinePFailure,
}

fn exact_device_fault_matches(
    fault: &Fault,
    expected: ExpectedDeviceFault,
    block_targets: &[DeviceId],
    ninep_targets: &[DeviceId],
) -> bool {
    match (expected, fault) {
        (
            ExpectedDeviceFault::BlockLatency,
            Fault::Block(BlockFault::Latency {
                device,
                extra,
                jitter,
            }),
        ) => {
            block_targets.contains(device)
                && *extra == FaultDuration::from_nanos(7)
                && *jitter == FaultDuration::from_nanos(7)
        }
        (
            ExpectedDeviceFault::BlockFailure,
            Fault::Block(BlockFault::Failure { device, rate, mode }),
        ) => {
            block_targets.contains(device)
                && rate.basis_points() == 1_234
                && matches!(mode, IoFailureMode::ErrorStatus | IoFailureMode::Drop)
        }
        (
            ExpectedDeviceFault::BlockReorder,
            Fault::Block(BlockFault::Reorder { device, window }),
        ) => block_targets.contains(device) && *window == FaultDuration::from_nanos(11),
        (
            ExpectedDeviceFault::NinePLatency,
            Fault::NineP(NinePFault::Latency {
                device,
                extra,
                jitter,
            }),
        ) => {
            ninep_targets.contains(device)
                && *extra == FaultDuration::from_nanos(7)
                && *jitter == FaultDuration::from_nanos(7)
        }
        (
            ExpectedDeviceFault::NinePFailure,
            Fault::NineP(NinePFault::Failure {
                device,
                rate,
                errno,
            }),
        ) => ninep_targets.contains(device) && rate.basis_points() == 1_234 && errno.code() == 5,
        _ => false,
    }
}

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("valid fault rate: {error}"))
}

fn bandwidth(bits_per_second: u64) -> FaultBandwidthBitsPerSecond {
    FaultBandwidthBitsPerSecond::new(bits_per_second)
        .unwrap_or_else(|error| panic!("valid bandwidth: {error}"))
}

fn slowdown(basis_points: u32) -> FaultSlowdownFactorBasisPoints {
    FaultSlowdownFactorBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("valid slowdown: {error}"))
}
