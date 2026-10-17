//! Exercises actual retained spill writeback through a failing block device.
//!
//! The operator-created error target affects native private storage alone.
//! Catalog and registry namespaces remain on their independently admitted
//! healthy quota filesystem. No proof source or synthetic I/O error substitutes
//! for the retained inode's write and sync failure.

use super::super::hot_fork_native::native_repository;
use super::*;
use crucible_api::host_operational::{HostRamConvergence, HostRamMode, HostResourceVector};
use crucible_protocol::ram_control::{RamControlFailureCause, RamControlFailureOperation};
use crucible_qemu::ram_control::RamControlRegistrar;

use crucible_linux_resource::test_support::LinuxDeviceMapperFaultTarget;

const LANE: &str = "spill-io";
const PROJECT: u32 = 59_000;
const SPILL_MOUNT: &str = "/var/paging-spill-io";

#[test]
#[ignore = "requires isolated AOS paging VM and a separately mounted device-mapper target"]
fn production_spill_sync_failure_retains_original_cause_and_refuses_guest_cut() {
    let source = paging_scenario();
    environment::with_native_repository_environment(
        LANE,
        PROJECT,
        |root, storage| native_repository(&source, root, storage),
        |mut config| {
            config.host = LinuxQemuAttemptHostConfig::new(
                config.host.cgroup_root(),
                std::path::Path::new(SPILL_MOUNT).join(LANE),
                config.host.attempt_namespace(),
                PROJECT,
                1,
                65_534,
                65_534,
                64,
                TEST_HOST_FILE_DESCRIPTORS,
                TEST_HOST_SERVICE_TASKS,
                TEST_HOST_SERVICE_FILE_DESCRIPTORS,
                TEST_HOST_SERVICE_RESIDENT_BYTES,
                TEST_WATCHER_SERVICE_RESIDENT_BYTES,
                4096,
                Duration::from_secs(30),
            )
            .expect("same native entitlement with independently faultable spill storage");
            config
        },
        |prepared, config, repository| {
            let before = available(prepared);
            run_capture(prepared, config, &source, |context| {
                let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
                    .expect("genuine native cgroup and faultable ext4 quota admission");
                let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
                    Arc::clone(&config.lifecycle),
                    ComposedQemuAttemptResourceGuardFactory::new(host),
                );
                let mut lifecycle = factory
                    .begin_fresh(&source.scenario_def(), &source, context)
                    .expect("successful native spill preallocation and controller admission");
                let registry = &prepared.host_operational_registry;
                let target = super::faults::discover_target(registry, context);
                let admitted = status(registry, target);
                let supervisor = context
                    .host_operation_supervisor()
                    .expect("same original accepted preparation lifetime");
                let logical = match registry
                    .execute(OPERATOR, HostOperationalRequest::Capabilities { target })
                    .expect("actual sealed RAM geometry")
                    .value()
                {
                    HostOperationalResponse::Capabilities { capabilities, .. } => {
                        capabilities.logical_ram_bytes
                    }
                    response => panic!("unexpected capabilities: {response:?}"),
                };
                let operator = supervisor
                    .begin(HostOperationClass::Writeback)
                    .expect("original finite Writeback scope before operator I/O");
                let credit = repository
                    .blob_backend()
                    .metadata_resources()
                    .expect("original independent catalog authority")
                    .reserve_resources(1, 4096)
                    .expect("operator FD and fixed ioctl scratch before opening control");
                let device = LinuxDeviceMapperFaultTarget::open(
                    std::path::Path::new(SPILL_MOUNT),
                    credit,
                    &operator,
                )
                .expect("exact original UUID, single linear target and mounted geometry");
                registry
                    .apply_native_qualification_policy(target, logical)
                    .expect("retained full resident baseline");
                for _ in 0..8 {
                    drive(&mut lifecycle);
                }
                let initial_writes = status(registry, target)
                    .activity
                    .expect("actual initial writes")
                    .preservation_writes;
                registry
                    .apply_native_qualification_mode(target, HostRamMode::DiskOriented, logical)
                    .expect("genuine resident-retaining authenticated disk cut");
                drive(&mut lifecycle);
                let preserved = status(registry, target)
                    .activity
                    .expect("successful disk cut");
                assert!(preserved.preservation_writes > initial_writes);

                // An actual WP fault caused by a later guest store changes the
                // page version. Its prior immutable disk slot cannot satisfy
                // the next cut's preservation requirement.
                for _ in 0..QUANTA {
                    drive(&mut lifecycle);
                    if status(registry, target)
                        .activity
                        .expect("actual write transitions")
                        .write_protect_transitions
                        > preserved.write_protect_transitions
                    {
                        break;
                    }
                }
                let dirty = status(registry, target);
                assert!(
                    dirty
                        .activity
                        .expect("actual dirty cut")
                        .write_protect_transitions
                        > preserved.write_protect_transitions
                );
                let (configuration, _, _, _, frontier, _, _) = lifecycle
                    .resume_state()
                    .expect("last published pre-failure cut")
                    .into_parts();
                let configuration_id = configuration.id();
                let scheduler = lifecycle
                    .canonical_scheduler_evidence()
                    .expect("last published scheduler")
                    .0;
                device
                    .switch_to_error(&operator)
                    .expect("actual atomic block target switch");
                registry
                    .apply_native_qualification_mode(target, HostRamMode::DiskOriented, 0)
                    .expect("next native cut requires preservation of actual changed pages");
                let result = QemuFreshAttemptLifecycleOwner::drive_quantum(
                    &mut lifecycle,
                    QuantumRequest {
                        configuration,
                        control: Vec::new(),
                    },
                );
                let error = match &result {
                    Err(error) => error,
                    Ok(_) => panic!("failed spill writeback permits a guest quantum"),
                };
                let failure = original_writeback_failure(error)
                    .expect("original typed native operation cause survives host health polling");
                assert_eq!(failure.operation, RamControlFailureOperation::Writeback);
                assert_eq!(
                    failure.cause,
                    RamControlFailureCause::Io {
                        errno: rustix::io::Errno::IO.raw_os_error()
                    }
                );
                assert!(failure.policy_revision > dirty.policy_revision);
                let observed = status(registry, target);
                assert_eq!(observed.admitted_resources, admitted.admitted_resources);
                assert_eq!(observed.reservation_revision, admitted.reservation_revision);
                assert_eq!(observed.convergence, HostRamConvergence::Failed);
                let (actor, retained) = registry
                    .native_paging_health(target)
                    .expect("independent controller remains alive after writeback failure");
                assert_eq!(retained, Some(failure));
                assert!(actor.is_some_and(|actor| actor.failure.is_none()));
                let after = lifecycle
                    .resume_state()
                    .expect("unchanged published cut")
                    .into_parts();
                assert_eq!(after.0.id(), configuration_id);
                assert_eq!(after.4, frontier);
                assert_eq!(
                    lifecycle
                        .canonical_scheduler_evidence()
                        .expect("unchanged scheduler")
                        .0,
                    scheduler
                );
                assert_eq!(
                    observed
                        .activity
                        .expect("actual failed cut")
                        .successful_missing_installs,
                    dirty
                        .activity
                        .expect("pre-failure installs")
                        .successful_missing_installs
                );
                assert!(available(prepared).resident_peak_bytes < before.resident_peak_bytes);

                // Repairing operator availability neither clears the retained
                // native failure nor resumes the guest nor releases custody.
                device
                    .restore_operator_availability(&operator)
                    .expect("restore original operator table");
                assert_eq!(
                    registry
                        .native_paging_health(target)
                        .expect("retained error after device repair")
                        .1,
                    Some(failure)
                );
                operator
                    .complete()
                    .expect("same original Writeback cap remains valid");
                QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
                    .expect("actual reap, source join, final FD close and native quota cleanup");
                drop(lifecycle);
                drop(factory);
                drop(result);
                drop(device);
                Ok(())
            })
            .expect("original full-vector preparation and watchdog terminal cleanup");
            assert_eq!(available(prepared), before);
        },
    );
    println!("spill_io_initial_admission_and_authenticated_preservation=true");
    println!("spill_io_actual_guest_write_requires_new_preservation=true");
    println!("spill_io_actual_error_target_after_admission=true");
    println!("spill_io_original_writeback_eio_retained=true");
    println!("spill_io_controller_alive_no_install_or_cut=true");
    println!("spill_io_original_full_vector_until_physical_cleanup=true");
    println!("SPILL_WRITEBACK_EIO_NATIVE_PASS");
}

fn drive(lifecycle: &mut ProductionVmLifecycleLoop) {
    let configuration = lifecycle
        .resume_state()
        .expect("current scheduler cut")
        .into_parts()
        .0;
    QemuFreshAttemptLifecycleOwner::drive_quantum(
        lifecycle,
        QuantumRequest {
            configuration,
            control: Vec::new(),
        },
    )
    .expect("healthy admitted guest quantum");
}

fn available(
    prepared: &crate::packaged_qemu_executor::preparation::PackagedPreparation,
) -> HostResourceVector {
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .host_resource_availability()
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("actual complete eight-dimensional ledger")
}

fn original_writeback_failure(
    error: &(dyn std::error::Error + 'static),
) -> Option<crucible_protocol::ram_control::RamControlOperationFailure> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(source) = error.downcast_ref::<crucible_qemu::QemuNativeOperationFailure>() {
            return Some(source.failure);
        }
        current = error.source();
    }
    None
}
