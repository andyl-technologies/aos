//! Checks source-role renames against the preceding model and I/O encodings.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- fixtures deliberately panic on invalid setup.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ComputeNodeDef, ComputeNodeTemplate, ContentAddressedBlobRef, ContentHash,
    DeviceSchedulingSubNode, DeviceSchedulingSubNodeCheckpoint, Icount, LinkDef, NodeId,
    NodeTemplate, ReadyPoint, ScenarioBuilder, ScheduledIoNode, SchedulerNodeId,
    SchedulingNodeKind, Seed, VmArchitecture, WhiteBoxPolicy, World, WorldBlockLatency,
    WorldIoCoreConfig, WorldIoNode, WorldNode, WorldNodeDef,
};
use crucible_device::{BaseImage, BlockRequest};

fn node(name: &str) -> NodeId {
    NodeId { name: name.into() }
}

fn compute(name: &str, arch: VmArchitecture) -> ComputeNodeDef {
    ComputeNodeDef {
        id: node(name),
        arch,
        memory_mib: ComputeNodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: "console=ttyS0 quiet".into(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 42 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: 2,
        kernel: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            b"kernel",
        ))),
        root_image: None,
        initrd: Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
            b"initrd",
        ))),
    }
}

fn fixture() -> (World, ScheduledIoNode) {
    let base = BaseImage::new(vec![0x5a; 4096]);
    let disk = WorldIoNode::block(
        node("disk"),
        node("a"),
        WorldIoCoreConfig::new(),
        ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(base.bytes())),
        4096,
        WorldBlockLatency::new(2, 3, 4, 5, 1),
    );
    let world = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(compute("b", VmArchitecture::Aarch64)),
            WorldNodeDef::Io(disk),
            WorldNodeDef::Vm(compute("a", VmArchitecture::X86_64)),
        ],
        vec![LinkDef::new(node("b"), node("a")).unwrap()],
    )
    .unwrap();
    let mut io =
        ScheduledIoNode::bind_world_block(&world, &node("disk"), base, Seed::default()).unwrap();
    io.submit_arrivals(vec![
        (200, BlockRequest::read(2, 8, 8)),
        (0, BlockRequest::read(1, 0, 8)),
    ])
    .unwrap();
    (world, io)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn compute_world_encodings_match_parent() {
    let (world, _) = fixture();
    let canonical = include_bytes!("fixtures/compute-source-compatibility/world.canonical");
    let toml = include_str!("fixtures/compute-source-compatibility/world.toml");
    let binary = unhex(include_str!(
        "fixtures/compute-source-compatibility/world.binary.hex"
    ));

    assert_eq!(world.canonical_bytes(), canonical);
    assert_eq!(world.to_canonical_toml().unwrap(), toml);
    assert_eq!(world.to_compact_binary(), binary);

    assert_eq!(World::from_canonical_toml(toml).unwrap(), world);
    assert_eq!(World::from_compact_binary(&binary).unwrap(), world);
}

#[test]
fn scheduling_identities_keep_legacy_serde_tags() {
    let (_, io) = fixture();
    let identities = [
        SchedulerNodeId {
            node: node("a"),
            kind: SchedulingNodeKind::Vm,
        },
        io.sub_node().clone(),
    ];
    let json = include_str!("fixtures/compute-source-compatibility/scheduler.identities.json");

    assert_eq!(serde_json::to_string(&identities).unwrap(), json);
    assert_eq!(
        serde_json::from_str::<[SchedulerNodeId; 2]>(json).unwrap(),
        identities
    );
}

#[test]
fn scheduled_io_checkpoint_and_delivery_match_parent() {
    let (_, mut io) = fixture();
    let checkpoint_hex = include_str!("fixtures/compute-source-compatibility/io.checkpoint.hex");
    let trace = include_str!("fixtures/compute-source-compatibility/io.delivery.trace");
    let checkpoint_bytes = io.checkpoint().canonical_bytes().unwrap();

    assert_eq!(hex(&checkpoint_bytes), checkpoint_hex);
    assert_eq!(format!("{:#?}\n", io.deliver_due(u64::MAX)), trace);
    assert!(io.deliver_due(u64::MAX).is_empty());

    // A consumed queue restores from the parent encoding through the source alias.
    let checkpoint =
        DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(&unhex(checkpoint_hex)).unwrap();
    let source_alias: &mut DeviceSchedulingSubNode = &mut io;
    source_alias.restore_checkpoint(&checkpoint).unwrap();

    assert_eq!(
        source_alias.checkpoint().canonical_bytes().unwrap(),
        checkpoint_bytes
    );
    assert_eq!(
        format!("{:#?}\n", source_alias.deliver_due(u64::MAX)),
        trace
    );
    assert!(source_alias.deliver_due(u64::MAX).is_empty());
}

#[test]
fn legacy_compute_names_construct_the_same_source_types() {
    let current = compute("a", VmArchitecture::X86_64);
    let legacy = WorldNode {
        id: current.id.clone(),
        ..current.clone()
    };
    let current_template = ComputeNodeTemplate::from_world_node(&current);
    let legacy_template = NodeTemplate::from_world_node(&legacy);

    assert_eq!(current, legacy);
    assert_eq!(current_template, legacy_template);
    let current_scenario = ScenarioBuilder::default()
        .node("a", current_template)
        .build()
        .unwrap();
    let legacy_scenario = ScenarioBuilder::default()
        .node("a", legacy_template)
        .build()
        .unwrap();
    assert_eq!(current_scenario, legacy_scenario);
}
