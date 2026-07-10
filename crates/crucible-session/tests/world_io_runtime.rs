//! Proves the L4 session boundary uses the production World-backed scheduler.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use crucible::{
    BlockFault, Checkpoint, CheckpointKind, Configuration, ContentAddressedBlobRef, ContentHash,
    DagStore, ExactLocalEvent, Fault, FaultDuration, FaultTag, GenesisCheckpoint, Icount,
    MemoryDagStore, NetworkLookahead, NodeCounter, NodeId, NodeTemplate, ReadyPoint,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, Shift, SimInstant, SingleScheduler, TemporalGraph, VirtualTime,
    VmArchitecture, WhiteBoxPolicy, World, WorldBlockLatency, WorldIoCoreConfig,
    WorldIoLayoutPolicy, WorldIoNode, WorldNode, WorldNodeDef,
};
use crucible_session::{CommandReply, Engine, FaultSpec, SessionCommand};

#[test]
fn session_fault_command_reaches_artifact_backed_world_device() {
    let (world, store) = world_and_store();
    let scenario = scheduler_scenario(&world);
    let expected = SingleScheduler::from_world(
        scenario.clone(),
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("World scheduler fixture should instantiate");
    let configuration = expected.configuration().clone();
    let graph = graph_with_baked_genesis(&configuration);
    let mut engine = Engine::from_world_scheduler(
        graph,
        scenario,
        &world,
        &store,
        WorldIoLayoutPolicy::default(),
    )
    .expect("session should construct its World-backed scheduler");
    engine
        .apply_command(SessionCommand::Start)
        .expect("session runtime should instantiate");

    let disk = world
        .io_node(&node_id("disk"))
        .expect("disk declaration")
        .device_id();
    engine
        .apply_command(SessionCommand::InjectFault {
            spec: FaultSpec::new(
                FaultTag::from_name("disk-latency"),
                Fault::Block(BlockFault::Latency {
                    device: disk,
                    extra: FaultDuration::from_nanos(777),
                    jitter: FaultDuration::ZERO,
                }),
            ),
            reply: CommandReply::discard(),
        })
        .expect("paused session should apply the device fault at its boundary");

    let mut scheduler = engine.into_quantum_loop();
    let disk = scheduler
        .device_sub_nodes_for_mut(&node_id("vm-a"))
        .expect("session scheduler owns vm-a devices")
        .iter()
        .find(|node| node.sub_node().kind == SchedulingNodeKind::Disk)
        .expect("artifact-backed disk is attached");
    assert_eq!(disk.io_faults().added_latency_ns, 777);
}

fn world_and_store() -> (World, MemoryDagStore) {
    let bytes = vec![0xab; 4096];
    let store = MemoryDagStore::new();
    let key = store.put(&bytes).expect("block artifact stores");
    assert_eq!(key, ContentHash::from_bytes(&bytes));
    let world = World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(WorldNode {
                id: node_id("vm-a"),
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
            }),
            WorldNodeDef::Io(WorldIoNode::block(
                node_id("disk"),
                node_id("vm-a"),
                WorldIoCoreConfig::new(0),
                ContentAddressedBlobRef::from_hash(key),
                bytes.len() as u64,
                WorldBlockLatency::new(100, 200, 30, 40, 2),
            )),
        ],
        Vec::new(),
    )
    .expect("session World should validate");
    (world, store)
}

fn scheduler_scenario(world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        "session-world-io-runtime",
        Shift { bits: 0 },
        8,
        SimInstant { nanos: 100_000 },
        vec![SchedulerScenarioNode {
            id: SchedulerNodeId {
                node: world.vm_nodes()[0].id.clone(),
                kind: SchedulingNodeKind::Vm,
            },
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Idle,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
}

fn graph_with_baked_genesis(configuration: &Configuration) -> TemporalGraph {
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .expect("genesis checkpoint should be recorded-shaped");
    TemporalGraph::empty()
        .with_baked_genesis(&configuration.def, GenesisCheckpoint { checkpoint })
        .expect("baked genesis should register")
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}
