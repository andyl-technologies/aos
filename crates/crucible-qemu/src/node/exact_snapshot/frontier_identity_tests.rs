//! Exercises the complete producer identity with an authored native boundary.

use super::*;
use crate::ProductionFaultRuntime;
use std::collections::BTreeMap;

use crucible::model::{FaultSignalPlan, HostFaultAdapterManifests, SignalBoundarySnapshot};
use crucible::{CheckpointKind, Icount, SchedulerLivenessScenario, SimInstant, SingleScheduler};

#[test]
fn native_capture_identity_matches_original_material() -> Result<(), Box<dyn std::error::Error>> {
    let source = crucible::crash_restart_scenario()?.scenario;
    let node = source
        .world()
        .vm_nodes()
        .iter()
        .next()
        .ok_or("fixture VM")?
        .id
        .clone();
    let scenario = SchedulerLivenessScenario::from_runnable_world(
        "frontier-streaming-vectors",
        4,
        SimInstant { ticks: 100 },
        37,
        source.world(),
    )
    .with_scenario_def(source.scenario_def());
    let scheduler = SingleScheduler::new(scenario)?;
    let continuation = scheduler.checkpoint()?;
    let configuration = continuation.configuration_for(&source.scenario_def())?;
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        continuation.frontier(),
        BTreeMap::from([(node.clone(), Icount { retired: 37 })]),
        CheckpointKind::Thin,
        BTreeMap::new(),
    )?;
    let mut nodes = crate::QemuNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        FaultSignalPlan::empty(),
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"frontier-streaming-vectors"),
        HostFaultAdapterManifests::node_only()?,
        &nodes,
    )?;
    let fault = runtime.checkpoint(&mut nodes)?;
    let root = tempfile::tempdir()?;
    let backing = root.path().join("backing");
    std::fs::write(&backing, b"crash-restart-unmodified-store-root-image")?;
    let ram = root.path().join("ram");
    let device = root.path().join("device");

    let basis = QemuExactCheckpointCaptureBasis::admit(QemuExactCheckpointCaptureBoundary {
        configuration: &configuration,
        immutable_root_image: &backing,
        node: &node,
        counter: 37,
        scheduler_time: continuation.frontier(),
        checkpoint: &checkpoint,
        fault: &fault,
        scheduler: &continuation,
    })?;
    let expected_target = ContentHash::from_canonical_material(
        EXACT_RAM_TARGET_IDENTITY_DOMAIN,
        &format!(
            "configuration={}\nimmutable_backing={}\nnode={}\ncounter={}\nscheduler_time={}\nfault={}",
            basis.configuration.id().to_hex(),
            basis.immutable_backing.to_hex(),
            basis.node.name,
            basis.counter,
            basis.scheduler_time.ticks,
            basis.fault_identity.to_hex(),
        ),
    );
    let expected_frontier = ContentHash::from_canonical_hex_bytes(
        "crucible.production-vm-exact-ram-frontier.v1",
        &continuation.canonical_bytes()?,
    );
    let identity = basis.derive_identity()?;
    assert_eq!(
        checkpoint.id.to_hex(),
        "0d44a0d48dda20bf061c5877f0ff695d76c8e1599563a5c7490dede395186daf"
    );
    assert_eq!(
        expected_target.to_hex(),
        "29b9130671e55685bb907a92f395b5c164fc0851f8881cfe72e906d1b3a3a06b"
    );
    assert_eq!(
        expected_frontier.to_hex(),
        "6fad36a20ae2cf07e9289339be884e47cc76ede5d1f2c2b125c53c28dd6def47"
    );
    assert_eq!(
        identity,
        crate::QmpCheckpointIdentity::new(checkpoint.id, expected_target, expected_frontier)
    );

    let admission = QemuExactCheckpointCaptureAdmission::admit_paged(
        QemuExactCheckpointCaptureBoundary {
            configuration: &configuration,
            immutable_root_image: &backing,
            node: &node,
            counter: 37,
            scheduler_time: continuation.frontier(),
            checkpoint: &checkpoint,
            fault: &fault,
            scheduler: &continuation,
        },
        None,
        QemuExactCheckpointCaptureOutputs {
            maximum_ram_bytes: 16 * 1024 * 1024,
            maximum_device_bytes: 16 * 1024 * 1024,
            ram: &ram,
            device: &device,
        },
        true,
    )?;
    assert_eq!(admission.request.identity(), identity);
    assert_eq!(std::fs::metadata(&ram)?.len(), 0);
    assert_eq!(std::fs::metadata(&device)?.len(), 0);
    println!(
        "PRODUCER_VECTOR checkpoint={} target={} frontier={}",
        identity.checkpoint().to_hex(),
        expected_target.to_hex(),
        expected_frontier.to_hex()
    );
    Ok(())
}
