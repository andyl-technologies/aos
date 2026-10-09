//! Actual World projection tests for source/model capture custody separation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::{
    ComputeNodeDef, ContentAddressedBlobRef, ContentHash, Icount, LinkDef, NodeId, ReadyPoint,
    VmArchitecture, WhiteBoxPolicy, WorldBlockLatency, WorldIoCoreConfig, WorldIoNode,
};

fn vm(name: &str) -> ComputeNodeDef {
    ComputeNodeDef {
        id: NodeId { name: name.into() },
        arch: VmArchitecture::X86_64,
        memory_mib: 64,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn world() -> World {
    let a = vm("a");
    let z = vm("z");
    let disk = WorldIoNode::block(
        NodeId {
            name: "disk-a".into(),
        },
        a.id.clone(),
        WorldIoCoreConfig::new(),
        ContentAddressedBlobRef::from_hash(ContentHash::default()),
        4096,
        WorldBlockLatency::new(1, 1, 1, 1, 1),
    );
    let link = LinkDef::new(a.id.clone(), z.id.clone()).unwrap();
    World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(a),
            WorldNodeDef::Vm(z),
            WorldNodeDef::Io(disk),
        ],
        vec![link],
    )
    .unwrap()
}

#[test]
fn physical_io_stays_in_actual_compute_source_capture_owner() {
    let world = world();
    let physical = CurrentWorldInventory::from_world(
        &world,
        BackendIoInventoryAuthority::PhysicalSource,
        4,
        16,
    )
    .unwrap();
    let modeled = CurrentWorldInventory::from_world(
        &world,
        BackendIoInventoryAuthority::SchedulerOwnedModel,
        4,
        16,
    )
    .unwrap();
    let find = |inventory: &CurrentWorldInventory, name: &str| {
        inventory
            .participants
            .iter()
            .find(|row| row.id.as_str() == name)
            .unwrap()
            .capture_owner
            .clone()
    };
    assert_eq!(physical.participants.len(), 4);
    assert_eq!(find(&physical, "disk-a"), find(&physical, "a"));
    assert_ne!(find(&modeled, "disk-a"), find(&modeled, "a"));
    assert!(
        physical
            .participants
            .iter()
            .find(|row| row.id.as_str() == "disk-a")
            .unwrap()
            .native_inventory_required
    );
    let network = physical
        .participants
        .iter()
        .find(|row| row.role.as_str() == "network_link")
        .unwrap();
    assert_eq!(network.ports.len(), 4);
    assert_eq!(network.execution_owner, network.capture_owner);
}

#[test]
fn complete_projection_is_bounded_before_vector_allocation() {
    let world = world();
    let complete = CurrentWorldInventory::from_world(
        &world,
        BackendIoInventoryAuthority::PhysicalSource,
        4,
        16,
    )
    .unwrap();
    assert_eq!(
        complete
            .participants
            .iter()
            .map(|participant| participant.ports.len())
            .sum::<usize>(),
        16
    );
    assert!(
        CurrentWorldInventory::from_world(
            &world,
            BackendIoInventoryAuthority::PhysicalSource,
            3,
            16
        )
        .is_err()
    );
    assert!(
        CurrentWorldInventory::from_world(
            &world,
            BackendIoInventoryAuthority::PhysicalSource,
            4,
            15
        )
        .is_err()
    );
}
