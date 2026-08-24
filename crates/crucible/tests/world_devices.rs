//! Verifies heterogeneous world VM/I/O topology and checked runtime binding.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use crucible::{
    ContentAddressedBlobRef, ContentHash, DagStore, DeviceSchedulingSubNode,
    DeviceSubNodeBindingError, EngineError, Icount, LinkDef, MemoryDagStore, NodeId, NodeTemplate,
    Plan, Properties, ReadyPoint, ReproductionArtifact, RngStreamId, ScenarioDefForm, Schedule,
    SchedulingNodeKind, Seed, VmArchitecture, WhiteBoxPolicy, World, WorldBlockLatency,
    WorldDeviceKind, WorldIoCoreConfig, WorldIoInstantiationError, WorldIoInstantiationLayout,
    WorldIoLayoutError, WorldIoLayoutPolicy, WorldIoNode, WorldIoNodeKind, WorldNinePLatency,
    WorldNode, WorldNodeDef, instantiate_world_io_sub_nodes,
};
use crucible_device::{BaseImage, FsTree, FsTreeDecodeError, Node};

#[test]
fn heterogeneous_nodes_are_canonical_addressed_serialized_and_rng_stable() {
    let first = world_with_order(["share", "disk"]);
    let second = world_with_order(["disk", "share"]);

    assert_eq!(first, second);
    assert_eq!(first.nodes().len(), 4);
    assert_eq!(first.vm_nodes().len(), 2, "VM projection stays VM-only");
    let io_nodes = first.io_nodes().collect::<Vec<_>>();
    assert_eq!(io_nodes.len(), 2);
    assert!(
        io_nodes
            .iter()
            .all(|node| node.device_id().name.starts_with("blake3:"))
    );

    let disk = first
        .io_node(&node_id("disk-node"))
        .expect("disk node exists");
    let share = first
        .io_node(&node_id("share-node"))
        .expect("9p node exists");
    assert_eq!(disk.kind.family(), WorldDeviceKind::Block);
    assert_eq!(share.kind.family(), WorldDeviceKind::NineP);

    let topology = first.static_topology();
    assert_eq!(
        topology.participants,
        vec![node_id("node-a"), node_id("node-b")]
    );
    assert_eq!(topology.bake_nodes, topology.participants);
    assert!(topology.scheduling_nodes.iter().any(|node| {
        node.node == node_id("disk-node") && node.kind == SchedulingNodeKind::Disk
    }));
    assert!(topology.scheduling_nodes.iter().any(|node| {
        node.node == node_id("share-node") && node.kind == SchedulingNodeKind::NineP
    }));
    let linked = World::from_node_defs_and_links(
        first.nodes().to_vec(),
        vec![LinkDef::new(node_id("node-a"), node_id("node-b")).expect("test link should build")],
    )
    .expect("linked heterogeneous world should build");
    assert_eq!(
        linked
            .static_topology()
            .scheduling_nodes
            .iter()
            .filter(|node| node.kind == SchedulingNodeKind::Network)
            .count(),
        linked.links().len(),
        "every logical LinkDef has one deterministic network scheduling node"
    );
    assert!(
        topology
            .rng_streams
            .contains(&RngStreamId::for_device(disk.device_id().name))
    );
    assert!(
        topology
            .rng_streams
            .contains(&RngStreamId::for_device(share.device_id().name))
    );

    let disk_only = world_with_io_nodes(vec![block_node()]);
    let disk_with_unrelated = world_with_io_nodes(vec![ninep_node(), block_node()]);
    let disk_only_id = disk_only
        .io_node(&node_id("disk-node"))
        .expect("disk node exists")
        .device_id();
    let disk_with_unrelated_id = disk_with_unrelated
        .io_node(&node_id("disk-node"))
        .expect("disk node exists")
        .device_id();
    assert_eq!(disk_only_id, disk_with_unrelated_id);
    let seed = Seed::from_u64(0x51ab1e);
    assert_eq!(
        seed.stream_seed(&RngStreamId::for_device(disk_only_id.name)),
        seed.stream_seed(&RngStreamId::for_device(disk_with_unrelated_id.name))
    );

    let toml = first
        .to_canonical_toml()
        .expect("heterogeneous world TOML should serialize");
    assert!(toml.contains("kind = \"block\""));
    assert!(toml.contains("kind = \"nine_p\""));
    assert_eq!(
        World::from_canonical_toml(&toml).expect("heterogeneous world TOML should parse"),
        first
    );

    let binary = first.to_compact_binary();
    assert!(binary.starts_with(b"crucible.world.v4\0"));
    assert_eq!(
        World::from_compact_binary(&binary).expect("heterogeneous world binary should parse"),
        first
    );

    let form = ScenarioDefForm::from_components(
        &first,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(9),
    )
    .expect("heterogeneous scenario should build");
    let form_binary = form.to_compact_binary();
    assert!(form_binary.starts_with(b"crucible.scenario-def-form.v6\0"));
    assert_eq!(
        ScenarioDefForm::from_compact_binary(&form_binary)
            .expect("heterogeneous scenario binary should parse"),
        form
    );

    let artifact = ReproductionArtifact::from_recorded_parts(form, Schedule::empty());
    let artifact_binary = artifact.to_compact_binary();
    assert!(artifact_binary.starts_with(b"crucible.reproduction-artifact.v6\0"));
    assert_eq!(
        ReproductionArtifact::from_compact_binary(&artifact_binary)
            .expect("heterogeneous reproduction artifact should parse"),
        artifact
    );

    let without_io = World::from_nodes(vec![ready_node("node-a"), ready_node("node-b")])
        .expect("VM-only world should build");
    assert!(
        without_io
            .to_compact_binary()
            .starts_with(b"crucible.world.v4\0")
    );
    let vm_only_toml = without_io.to_canonical_toml().expect("VM-only TOML");
    assert!(!vm_only_toml.contains("kind = \"block\""));
    assert!(!vm_only_toml.contains("kind = \"nine_p\""));

    let changed_latency = world_with_io_nodes(vec![WorldIoNode::block(
        node_id("disk-node"),
        node_id("node-a"),
        io_core(),
        block_artifact(),
        block_bytes().len() as u64,
        WorldBlockLatency::new(101, 200, 30, 40, 2),
    )]);
    assert_ne!(disk_only.id(), changed_latency.id());
    assert_ne!(
        disk_only
            .io_node(&node_id("disk-node"))
            .expect("disk node exists")
            .device_id(),
        changed_latency
            .io_node(&node_id("disk-node"))
            .expect("disk node exists")
            .device_id()
    );
}

#[test]
fn transport_layout_is_derived_and_cannot_change_world_or_device_identity() {
    let world = world_with_io_nodes(vec![ninep_node(), block_node()]);
    let compact = WorldIoInstantiationLayout::derive(
        &world,
        WorldIoLayoutPolicy {
            inbox_capacity: 8,
            outbox_capacity: 16,
        },
    )
    .expect("compact physical layout should derive");
    let roomy = WorldIoInstantiationLayout::derive(
        &world,
        WorldIoLayoutPolicy {
            inbox_capacity: 1024,
            outbox_capacity: 2048,
        },
    )
    .expect("roomy physical layout should derive");

    let disk = world
        .io_node(&node_id("disk-node"))
        .expect("disk node exists");
    let share = world
        .io_node(&node_id("share-node"))
        .expect("share node exists");
    assert_eq!(compact.get(&disk.id).expect("disk binding").source_node, 0);
    assert_eq!(
        compact.get(&share.id).expect("share binding").source_node,
        1
    );
    assert_ne!(compact, roomy);

    let before_world = world.id();
    let before_devices = world
        .io_nodes()
        .map(WorldIoNode::device_id)
        .collect::<Vec<_>>();
    assert_eq!(world.id(), before_world);
    assert_eq!(
        world
            .io_nodes()
            .map(WorldIoNode::device_id)
            .collect::<Vec<_>>(),
        before_devices
    );
    let toml = world.to_canonical_toml().expect("world TOML");
    assert!(!toml.contains("source_node"));
    assert!(!toml.contains("inbox_capacity"));
    assert!(!toml.contains("outbox_capacity"));

    assert!(matches!(
        WorldIoInstantiationLayout::derive(
            &world,
            WorldIoLayoutPolicy {
                inbox_capacity: 3,
                outbox_capacity: 16,
            }
        ),
        Err(WorldIoLayoutError::InvalidRingCapacity {
            ring: "inbox",
            capacity: 3,
        })
    ));
}

#[test]
fn device_identity_is_sensitive_to_every_logical_io_field() {
    let baseline = block_node();
    let baseline_id = baseline.device_id();
    let mut variants = Vec::new();

    let mut changed = baseline.clone();
    changed.id = node_id("different-disk-node");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.owner = node_id("node-b");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.core = WorldIoCoreConfig::new(1);
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.kind = WorldIoNodeKind::Block {
        base_image: ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"different")),
        base_length: block_bytes().len() as u64,
        latency: block_latency(),
    };
    variants.push(changed);
    let mut changed = baseline.clone();
    if let WorldIoNodeKind::Block { base_length, .. } = &mut changed.kind {
        *base_length = base_length.saturating_add(1);
    }
    variants.push(changed);
    for latency in [
        WorldBlockLatency::new(101, 200, 30, 40, 2),
        WorldBlockLatency::new(100, 201, 30, 40, 2),
        WorldBlockLatency::new(100, 200, 31, 40, 2),
        WorldBlockLatency::new(100, 200, 30, 41, 2),
        WorldBlockLatency::new(100, 200, 30, 40, 3),
    ] {
        let mut changed = baseline.clone();
        if let WorldIoNodeKind::Block {
            latency: current, ..
        } = &mut changed.kind
        {
            *current = latency;
        }
        variants.push(changed);
    }
    let mut changed = baseline;
    changed.kind = WorldIoNodeKind::NineP {
        tree: tree_artifact(&ninep_tree()),
        latency: WorldNinePLatency::new(80, 120, 1),
    };
    variants.push(changed);

    for variant in variants {
        assert_ne!(
            variant.device_id(),
            baseline_id,
            "logical field must affect DeviceId"
        );
    }
}

#[test]
fn heterogeneous_nodes_reject_duplicate_ids_bad_owners_and_bad_clock_geometry() {
    let duplicate = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(ready_node("node-a")),
            WorldNodeDef::Io(WorldIoNode::block(
                node_id("node-a"),
                node_id("node-a"),
                io_core(),
                block_artifact(),
                block_bytes().len() as u64,
                block_latency(),
            )),
        ],
        Vec::new(),
    );
    assert!(matches!(
        duplicate,
        Err(EngineError::DuplicateWorldNodeId { node }) if node == node_id("node-a")
    ));

    let unknown_owner = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(ready_node("node-a")),
            WorldNodeDef::Io(WorldIoNode::block(
                node_id("disk-node"),
                node_id("missing"),
                io_core(),
                block_artifact(),
                block_bytes().len() as u64,
                block_latency(),
            )),
        ],
        Vec::new(),
    );
    assert!(matches!(
        unknown_owner,
        Err(EngineError::WorldIoNodeUnknownOwner { node, owner })
            if node == node_id("disk-node") && owner == node_id("missing")
    ));

    let invalid_core = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(ready_node("node-a")),
            WorldNodeDef::Io(WorldIoNode::block(
                node_id("disk-node"),
                node_id("node-a"),
                WorldIoCoreConfig::new(64),
                block_artifact(),
                block_bytes().len() as u64,
                block_latency(),
            )),
        ],
        Vec::new(),
    );
    assert!(matches!(
        invalid_core,
        Err(EngineError::WorldIoNodeClockShiftTooLarge { node, shift: 64 })
            if node == node_id("disk-node")
    ));
}

#[test]
fn declared_io_nodes_bind_only_matching_concrete_artifacts() {
    let world = world_with_io_nodes(vec![block_node(), ninep_node()]);
    let disk = world
        .io_node(&node_id("disk-node"))
        .expect("disk node exists");
    let share = world
        .io_node(&node_id("share-node"))
        .expect("share node exists");

    let bound_disk = DeviceSchedulingSubNode::bind_world_block(
        &world,
        &node_id("disk-node"),
        BaseImage::new(block_bytes()),
        Seed::from_u64(3),
    )
    .expect("matching block artifact should bind");
    assert_eq!(bound_disk.sub_node(), &disk.scheduler_node_id());
    assert_eq!(bound_disk.target(), &node_id("node-a"));
    assert_eq!(bound_disk.device_id(), &disk.device_id());

    let bound_share = DeviceSchedulingSubNode::bind_world_ninep(
        &world,
        &node_id("share-node"),
        ninep_tree(),
        Seed::from_u64(4),
    )
    .expect("matching 9p artifact should bind");
    assert_eq!(bound_share.sub_node(), &share.scheduler_node_id());
    assert_eq!(bound_share.target(), &node_id("node-b"));
    assert_eq!(bound_share.device_id(), &share.device_id());

    let wrong_block = DeviceSchedulingSubNode::bind_world_block(
        &world,
        &node_id("disk-node"),
        BaseImage::new(vec![0xff; block_bytes().len()]),
        Seed::from_u64(3),
    );
    assert!(matches!(
        wrong_block,
        Err(DeviceSubNodeBindingError::ArtifactMismatch { .. })
    ));

    let wrong_tree = DeviceSchedulingSubNode::bind_world_ninep(
        &world,
        &node_id("share-node"),
        changed_ninep_tree(),
        Seed::from_u64(4),
    );
    assert!(matches!(
        wrong_tree,
        Err(DeviceSubNodeBindingError::ArtifactMismatch { .. })
    ));

    let wrong_family = DeviceSchedulingSubNode::bind_world_ninep(
        &world,
        &node_id("disk-node"),
        ninep_tree(),
        Seed::from_u64(4),
    );
    assert!(matches!(
        wrong_family,
        Err(DeviceSubNodeBindingError::KindMismatch {
            expected: WorldDeviceKind::NineP,
            actual: WorldDeviceKind::Block,
            ..
        })
    ));
}

#[test]
fn production_world_instantiation_rejects_malformed_ninep_artifact_bytes() {
    let store = MemoryDagStore::new();
    let malformed = b"not-a-canonical-ninep-tree".to_vec();
    let key = store
        .put(&malformed)
        .expect("malformed fixture should store");
    let world = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(ready_node("node-a")),
            WorldNodeDef::Io(WorldIoNode::ninep(
                node_id("share-node"),
                node_id("node-a"),
                WorldIoCoreConfig::new(0),
                ContentAddressedBlobRef::from_hash(key),
                WorldNinePLatency::new(80, 120, 1),
            )),
        ],
        Vec::new(),
    )
    .expect("logical World accepts a content-addressed tree declaration");

    assert!(matches!(
        instantiate_world_io_sub_nodes(
            &world,
            &store,
            Seed::from_u64(4),
            WorldIoLayoutPolicy::default(),
        ),
        Err(WorldIoInstantiationError::NinePArtifactDecode {
            node,
            source: FsTreeDecodeError::WrongMagic,
        }) if node == node_id("share-node")
    ));
}

#[test]
fn current_outer_envelopes_reject_retired_versions() {
    let world = world_with_io_nodes(vec![block_node()]);
    let form = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(99),
    )
    .expect("scenario should build");
    let artifact = ReproductionArtifact::from_recorded_parts(form.clone(), Schedule::empty());

    let world_v1_envelope = replace_magic(
        world.to_compact_binary(),
        b"crucible.world.v4\0",
        b"crucible.world.v1\0",
    );
    assert!(World::from_compact_binary(&world_v1_envelope).is_err());

    let scenario_v4_envelope = replace_magic(
        form.to_compact_binary(),
        b"crucible.scenario-def-form.v6\0",
        b"crucible.scenario-def-form.v4\0",
    );
    assert!(ScenarioDefForm::from_compact_binary(&scenario_v4_envelope).is_err());

    let artifact_v4_envelope = replace_magic(
        artifact.to_compact_binary(),
        b"crucible.reproduction-artifact.v6\0",
        b"crucible.reproduction-artifact.v4\0",
    );
    assert!(ReproductionArtifact::from_compact_binary(&artifact_v4_envelope).is_err());
    let mislabeled_artifact_v5 = replace_magic(
        artifact.to_compact_binary(),
        b"crucible.reproduction-artifact.v6\0",
        b"crucible.reproduction-artifact.v5\0",
    );
    assert!(ReproductionArtifact::from_compact_binary(&mislabeled_artifact_v5).is_err());

    let vm_only_world =
        World::from_nodes(vec![ready_node("node-a")]).expect("VM-only world should build");
    let vm_only_form = ScenarioDefForm::from_components(
        &vm_only_world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(100),
    )
    .expect("VM-only scenario should build");
    let vm_only_artifact =
        ReproductionArtifact::from_recorded_parts(vm_only_form.clone(), Schedule::empty());

    let world_v2_envelope = replace_magic(
        vm_only_world.to_compact_binary(),
        b"crucible.world.v4\0",
        b"crucible.world.v2\0",
    );
    assert!(World::from_compact_binary(&world_v2_envelope).is_err());

    let scenario_v1_envelope = replace_magic(
        vm_only_form.to_compact_binary(),
        b"crucible.scenario-def-form.v6\0",
        b"crucible.scenario-def-form.v1\0",
    );
    assert!(ScenarioDefForm::from_compact_binary(&scenario_v1_envelope).is_err());

    let artifact_v1_envelope = replace_magic(
        vm_only_artifact.to_compact_binary(),
        b"crucible.reproduction-artifact.v6\0",
        b"crucible.reproduction-artifact.v1\0",
    );
    assert!(ReproductionArtifact::from_compact_binary(&artifact_v1_envelope).is_err());
}

fn replace_magic(mut bytes: Vec<u8>, from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    assert!(bytes.starts_with(from));
    bytes[..from.len()].copy_from_slice(to);
    bytes
}

fn world_with_order(order: [&str; 2]) -> World {
    let mut io = Vec::new();
    for name in order {
        io.push(match name {
            "disk" => block_node(),
            "share" => ninep_node(),
            _ => panic!("unknown test node"),
        });
    }
    world_with_io_nodes(io)
}

fn world_with_io_nodes(io_nodes: Vec<WorldIoNode>) -> World {
    let mut nodes = vec![
        WorldNodeDef::Vm(ready_node("node-b")),
        WorldNodeDef::Vm(ready_node("node-a")),
    ];
    nodes.extend(io_nodes.into_iter().map(WorldNodeDef::Io));
    World::from_node_defs_and_links(nodes, Vec::new()).expect("test world should build")
}

fn block_node() -> WorldIoNode {
    WorldIoNode::block(
        node_id("disk-node"),
        node_id("node-a"),
        io_core(),
        block_artifact(),
        block_bytes().len() as u64,
        block_latency(),
    )
}

fn ninep_node() -> WorldIoNode {
    WorldIoNode::ninep(
        node_id("share-node"),
        node_id("node-b"),
        io_core(),
        tree_artifact(&ninep_tree()),
        WorldNinePLatency::new(80, 120, 1),
    )
}

fn io_core() -> WorldIoCoreConfig {
    WorldIoCoreConfig::new(0)
}

fn block_latency() -> WorldBlockLatency {
    WorldBlockLatency::new(100, 200, 30, 40, 2)
}

fn block_bytes() -> Vec<u8> {
    (0_u16..512).flat_map(u16::to_le_bytes).collect()
}

fn block_artifact() -> ContentAddressedBlobRef {
    let base = BaseImage::new(block_bytes());
    ContentAddressedBlobRef::from_hash(ContentHash { bytes: base.hash() })
}

fn tree_artifact(tree: &FsTree) -> ContentAddressedBlobRef {
    ContentAddressedBlobRef::from_hash(ContentHash {
        bytes: tree.content_hash(),
    })
}

fn ninep_tree() -> FsTree {
    FsTree::try_new(Node::Directory {
        children: [(
            String::from("config"),
            Node::File {
                content: b"stable".to_vec(),
            },
        )]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
    })
    .expect("test 9p tree components are valid")
}

fn changed_ninep_tree() -> FsTree {
    FsTree::try_new(Node::Directory {
        children: [(
            String::from("config"),
            Node::File {
                content: b"changed".to_vec(),
            },
        )]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
    })
    .expect("test 9p tree components are valid")
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: node_id(name),
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
