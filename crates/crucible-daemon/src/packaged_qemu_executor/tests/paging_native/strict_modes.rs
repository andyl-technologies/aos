//! Verified parent locking and authenticated disk cuts under genuine node ownership.
//!
//! This flight keeps the full execution peak and an independent finite memlock
//! entitlement. A receipt is observed only after the actual kernel transition;
//! it does not qualify child relocking or a general low-residency execution peak.

use super::super::hot_fork_native::native_repository;
use super::*;
use crucible_api::host_operational::{HostRamMode, HostRamPlacementReceipt};

const LOCK_ENTITLEMENT: u64 = 128 * 1024 * 1024;

#[test]
#[ignore = "requires isolated AOS paging VM, finite memlock entitlement and real ext4 quotas"]
fn production_strict_placement_has_verified_kernel_and_disk_evidence() {
    let source = paging_scenario();
    let reference = strict_lane(&source, "strict-reference", 57_000, false);
    let strict = strict_lane(&source, "strict-parent", 57_100, true);

    assert_eq!(reference.boundaries, strict.boundaries);
    assert_eq!(reference.ram_record, strict.ram_record);
    assert!(strict.activity.successful_missing_installs > 0);
    assert!(strict.activity.physical_discards > 0);
    assert!(strict.activity.preservation_writes > 0);
    println!("strict_placement_state_identity=true");
    println!("strict_placement_ram_root_identity=true");
    println!("strict_placement_modeled_time_identity=true");
    println!("strict_placement_actual_parent_locks=true");
    println!("strict_placement_verified_unlock=true");
    println!("strict_placement_authenticated_disk_cut=true");
    println!("strict_placement_historical_cut_preserved=true");
    println!(
        "strict_placement_missing_installs={}",
        strict.activity.successful_missing_installs
    );
    println!(
        "strict_placement_cold_discards={}",
        strict.activity.physical_discards
    );
    println!("STRICT_PLACEMENT_NATIVE_PASS");
}

fn strict_lane(source: &ScenarioDefForm, lane: &str, project: u32, exercise: bool) -> Lane {
    environment::with_native_repository_environment(
        lane,
        project,
        |root, storage| native_repository(source, root, storage),
        |mut config| {
            config.host = config
                .host
                .with_maximum_locked_bytes(LOCK_ENTITLEMENT)
                .expect("independent finite authored guest mapping lock ceiling");
            config
        },
        |prepared, config, _repository| {
            run_capture(prepared, config, source, |context| {
                let supervisor = context
                    .host_operation_supervisor()
                    .expect("original real supervision");
                let (revision, mut budgets) = supervisor.budgets().expect("live class roster");
                for class in HostOperationClass::ALL {
                    budgets.classes[class as usize] =
                        HostOperationBudget::finite(Duration::from_secs(900));
                }
                supervisor
                    .update_budgets(revision, budgets)
                    .expect("finite original class allowances");
                let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
                    .expect("actual native containment factory");
                let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
                    config.lifecycle.clone(),
                    ComposedQemuAttemptResourceGuardFactory::new(host),
                );
                let mut lifecycle = factory
                    .begin_fresh(&source.scenario_def(), source, context)
                    .expect("genuine admitted strict placement node");
                let registry = &prepared.host_operational_registry;
                let target = super::faults::discover_target(registry, context);
                let initial = status(registry, target);
                let logical = match registry
                    .execute(OPERATOR, HostOperationalRequest::Capabilities { target })
                    .expect("sealed actual RAM size")
                    .value()
                {
                    HostOperationalResponse::Capabilities { capabilities, .. } => {
                        capabilities.logical_ram_bytes
                    }
                    response => panic!("unexpected capability reply: {response:?}"),
                };
                assert!(logical > 0 && logical <= LOCK_ENTITLEMENT);
                registry
                    .apply_native_qualification_policy(target, logical)
                    .expect("genuine initial resident target");
                let mut configuration = lifecycle
                    .resume_state()
                    .expect("initial scheduler")
                    .into_parts()
                    .0;
                let mut boundaries = Vec::with_capacity(QUANTA);
                let mut locked = None;
                let mut disk = None;
                let mut before_unlock = None;
                for round in 0..QUANTA {
                    if exercise {
                        match round {
                            8 => registry
                                .apply_native_qualification_mode(
                                    target,
                                    HostRamMode::ResidentRequired,
                                    logical,
                                )
                                .expect("real manager accepts separately admitted locks"),
                            12 => {
                                before_unlock = status(registry, target).activity;
                                registry
                                    .apply_native_qualification_policy(target, 0)
                                    .expect(
                                        "real downgrade schedules verified unlock and reclamation",
                                    );
                            }
                            16 => registry
                                .apply_native_qualification_mode(
                                    target,
                                    HostRamMode::DiskOriented,
                                    logical,
                                )
                                .expect("real disk cut retains resident pages for later writes"),
                            18 => registry
                                .apply_native_qualification_mode(
                                    target,
                                    HostRamMode::DiskOriented,
                                    0,
                                )
                                .expect("later cut authenticates writes before physical removal"),
                            _ => {}
                        }
                    }
                    let outcome = QemuFreshAttemptLifecycleOwner::drive_quantum(
                        &mut lifecycle,
                        QuantumRequest {
                            configuration,
                            control: Vec::new(),
                        },
                    )
                    .expect("resume only after real strict boundary completion");
                    configuration = outcome.configuration;
                    boundaries.push(boundary(&mut lifecycle));
                    let observed = status(registry, target);
                    assert_eq!(observed.admitted_resources, initial.admitted_resources);
                    assert_eq!(observed.reservation_revision, initial.reservation_revision);
                    if exercise {
                        match round {
                            8 => {
                                let receipt =
                                    completed_receipt(&observed, HostRamMode::ResidentRequired);
                                assert!(
                                    receipt.locked_bytes >= logical
                                        && receipt.locked_bytes <= LOCK_ENTITLEMENT
                                );
                                assert!(observed.effective_floor_bytes >= receipt.locked_bytes);
                                locked = Some(receipt);
                            }
                            9..=11 => assert_eq!(observed.placement_receipt, locked),
                            12 => {
                                assert_eq!(observed.applied_policy.mode, HostRamMode::Managed);
                                assert!(observed.placement_receipt.is_none());
                                assert!(
                                    observed.effective_floor_bytes
                                        < locked.expect("completed lock receipt").locked_bytes
                                );
                                assert!(
                                    observed
                                        .activity
                                        .expect("actual reclaim counters")
                                        .physical_discards
                                        > before_unlock
                                            .expect("pre-unlock actual counters")
                                            .physical_discards
                                );
                            }
                            16 => {
                                let receipt =
                                    completed_receipt(&observed, HostRamMode::DiskOriented);
                                assert_eq!(receipt.disk_preserved_logical_bytes, logical);
                                assert!(
                                    receipt.disk_preserved_logical_pages >= logical.div_ceil(4096)
                                );
                                assert!(receipt.ram_write_generation_at_cut > 0);
                                assert!(
                                    receipt.placement_epoch
                                        > locked.expect("actual earlier lock").placement_epoch
                                );
                                disk = Some(receipt);
                            }
                            18 => {
                                let receipt =
                                    completed_receipt(&observed, HostRamMode::DiskOriented);
                                let previous = disk.expect("actual earlier disk cut");
                                assert!(receipt.placement_epoch > previous.placement_epoch);
                                assert!(receipt.policy_revision > previous.policy_revision);
                                assert_eq!(receipt.disk_preserved_logical_bytes, logical);
                                disk = Some(receipt);
                            }
                            17 | 19.. => assert_eq!(
                                observed.placement_receipt, disk,
                                "later guest writes cannot renew a historical disk cut"
                            ),
                            _ => {}
                        }
                    }
                }
                let closure = lifecycle
                    .capture_portable_exact_checkpoint_with_boundary(&mut || Ok(()))
                    .expect("actual frozen RAM projection after strict transitions");
                let record = closure
                    .ram_sources()
                    .first()
                    .expect("one native RAM root")
                    .root()
                    .record();
                let ram_record = record.encode();
                let topology = record.topology().digest().to_string();
                let activity = status(registry, target)
                    .activity
                    .expect("actual successful kernel actor counters");
                drop(closure);
                QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
                    .expect("actual native reap discharges locks and source authority");
                Ok(Lane {
                    boundaries,
                    ram_record,
                    topology,
                    activity,
                })
            })
            .expect("original admitted assignment completes before real service cleanup")
        },
    )
}

fn completed_receipt(status: &HostRamStatus, mode: HostRamMode) -> HostRamPlacementReceipt {
    assert_eq!(status.applied_policy_revision, status.policy_revision);
    assert_eq!(status.applied_policy.mode, mode);
    let receipt = status
        .placement_receipt
        .expect("actual verified native completion receipt");
    assert_eq!(receipt.mode, mode);
    assert_eq!(receipt.policy_revision, status.applied_policy_revision);
    assert!(receipt.topology_generation > 0 && receipt.placement_epoch > 0);
    receipt
}
