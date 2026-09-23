//! Baked-genesis admission tests for production modeled checkpoints.

use std::collections::BTreeMap;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, Icount, NodeId, NodeTemplate, ReadyPoint,
    ScenarioDef, VirtualTime, WhiteBoxPolicy, World, WorldNode,
};

use super::{QemuBakedGenesisRestoreAdmission, QemuBakedGenesisSnapshot, QemuVmSnapshot};

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: NodeId {
            name: String::from(name),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
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

fn baked_snapshot(world: &World, nodes: &[&str]) -> QemuBakedGenesisSnapshot {
    let configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "baked-genesis-test",
        "native-closure",
    ));
    let node_icounts = nodes
        .iter()
        .map(|name| {
            (
                NodeId {
                    name: String::from(*name),
                },
                Icount { retired: 1 },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime { ticks: 1 },
        node_icounts,
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("modeled genesis checkpoint should build: {error}"));
    let snapshot = QemuVmSnapshot::diskless(checkpoint)
        .unwrap_or_else(|error| panic!("paired genesis snapshot should build: {error}"));

    QemuBakedGenesisSnapshot::new(world.id, &snapshot)
}

#[test]
fn native_baked_genesis_uses_exact_vm_clock_set_without_modeled_blob_refs() {
    let world = World::from_nodes(vec![ready_node("vm-a"), ready_node("vm-b")])
        .unwrap_or_else(|error| panic!("two-node world should build: {error}"));
    let complete = baked_snapshot(&world, &["vm-a", "vm-b"]);
    assert!(complete.checkpoint.node_blobs.is_empty());
    assert!(QemuBakedGenesisRestoreAdmission::new(&complete, &world).is_ok());

    let missing = baked_snapshot(&world, &["vm-a"]);
    assert!(QemuBakedGenesisRestoreAdmission::new(&missing, &world).is_err());

    let foreign = baked_snapshot(&world, &["vm-a", "foreign"]);
    assert!(QemuBakedGenesisRestoreAdmission::new(&foreign, &world).is_err());
}
