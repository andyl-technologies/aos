//! Baked-genesis admission tests for production modeled checkpoints.

use std::collections::BTreeMap;

use crucible_engine::{
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

#[cfg(target_os = "linux")]
#[test]
fn dispatcher_retirement_preserves_both_actual_leaf_errors_and_first_source() {
    use crate::linux_cgroup::LinuxQemuCgroupError;
    use crucible_host_resources::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let preparation = supervisor.begin(HostOperationClass::Preparation).unwrap();
    supervisor.cancel().unwrap();
    let original = preparation.wait_slice().unwrap_err();
    let dispatcher = LinuxQemuCgroupError::Io {
        operation: "test retained dispatcher read",
        path: std::path::PathBuf::from("retained-dispatcher"),
        source: std::io::Error::from_raw_os_error(libc::EIO),
    };

    let error = super::QemuTargetDispatcherRetirementError::combine(
        Err(dispatcher),
        Err(crate::OriginalActorAccountError::Supervision(original)),
    )
    .unwrap_err();

    let super::QemuVmRealizationError::TargetDispatcherRetirement { source } = error else {
        panic!("both leaf errors must remain typed");
    };
    let dispatcher = source.dispatcher_error().unwrap();
    assert!(
        matches!(dispatcher, LinuxQemuCgroupError::Io { source, .. } if source.raw_os_error() == Some(libc::EIO))
    );
    assert!(
        matches!(source.pool_error(), Some(crate::OriginalActorAccountError::Supervision(actual)) if *actual == original)
    );
    assert!(std::ptr::eq(
        std::error::Error::source(&source)
            .unwrap()
            .downcast_ref::<LinuxQemuCgroupError>()
            .unwrap(),
        dispatcher
    ));
    assert!(source.is_retryable());
}

#[cfg(target_os = "linux")]
#[test]
fn dispatcher_retirement_keeps_single_failure_class_and_success_distinct() {
    use crate::linux_cgroup::LinuxQemuCgroupError;
    assert!(super::QemuTargetDispatcherRetirementError::combine(Ok(()), Ok(())).is_ok());
    let pool_only = super::QemuTargetDispatcherRetirementError::combine(
        Ok(()),
        Err(crate::OriginalActorAccountError::Unavailable),
    )
    .unwrap_err();
    let super::QemuVmRealizationError::TargetDispatcherRetirement { source } = pool_only else {
        panic!("typed pool report");
    };
    assert!(source.dispatcher_error().is_none());
    assert!(source.pool_error().is_some());
    assert!(source.is_retryable());

    let both = super::QemuTargetDispatcherRetirementError::combine(
        Err(LinuxQemuCgroupError::InvalidLimit),
        Err(crate::OriginalActorAccountError::Unavailable),
    )
    .unwrap_err();
    let super::QemuVmRealizationError::TargetDispatcherRetirement { source } = both else {
        panic!("typed independent report");
    };
    assert!(
        !source.is_retryable(),
        "pool refusal must not replace terminal dispatcher precedence"
    );
    assert!(source.dispatcher_error().is_some());
    assert!(source.pool_error().is_some());
}
