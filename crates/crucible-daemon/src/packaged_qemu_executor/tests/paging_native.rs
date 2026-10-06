//! Real-kernel paging evidence under genuine preparation and native ownership.
//!
//! The disposable outer VM enables userfaultfd. The inner guest runs the same
//! unmodified AOS kernel and initramfs in both lanes. The test preserves the
//! full execution peak and exercises the implementation beneath the public
//! capability gate; successful socket setup does not authorize that gate.

use super::super::preparation::run_capture;
use super::*;
use crate::{ComposedQemuAttemptResourceGuardFactory, QemuAttemptProductionVmLifecycleFactory};
use crucible_api::host_operational::{
    HostOperationalControl, HostOperationalDisposition, HostOperationalRequest,
    HostOperationalResponse, HostRamActivity, HostRamOwnerTarget, HostRamStatus, HostRamTarget,
};
use crucible_api::vm_lifecycle::ProductionVmLifecycleLoop;
use crucible_linux_resource::host_supervision::{HostOperationBudget, HostOperationClass};

use environment::{OPERATOR, environment_path};
const QUANTA: usize = 64;

pub(super) mod accepted_promotion;
mod blocked_control;
mod byte_service;
pub(super) mod environment;
mod equivalence;
mod faults;
mod host_parallel;
mod lazy_restore;
mod performance;
mod plugin_flight;
mod source_failures;
mod spill_io;
mod storage_scale;
mod strict_child;
mod strict_modes;
mod throughput;
mod transfer;
use crate::paging_qualification::artifacts as evidence;
pub(crate) use equivalence::{
    NativeAtomicFailureCase, NativeAtomicWorldCase, NativeEquivalenceCase,
    run as run_equivalence_native, run_atomic_failure_native, run_atomic_world_native,
    run_dma_borrowers_native,
};
pub(crate) use host_parallel::run as run_host_parallel_native;

#[derive(Debug, PartialEq, Eq)]
struct Boundary {
    configuration: Configuration,
    scheduler: Vec<u8>,
    event_log: Vec<SchedulerEventLogEntry>,
    log_base: u64,
    log_segments: Vec<ContentHash>,
    frontier: VirtualTime,
    fingerprint: ExecutionFingerprint,
}

struct Lane {
    boundaries: Vec<Boundary>,
    ram_record: Vec<u8>,
    topology: String,
    activity: HostRamActivity,
}

#[test]
#[ignore = "requires the isolated AOS paging VM, userfaultfd, cgroup v2 and project quotas"]
fn production_managed_paging_preserves_guest_state_and_cold_writes() {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/vm/unprivileged_userfaultfd")
            .expect("real kernel policy")
            .trim(),
        "1"
    );
    let source = paging_scenario();
    let reference = run_lane(&source, "resident", 31_000, false);
    let paged = run_lane(&source, "paged", 31_100, true);

    assert_eq!(reference.boundaries, paged.boundaries);
    assert_eq!(reference.ram_record, paged.ram_record);
    assert_eq!(reference.topology, paged.topology);
    assert!(paged.activity.successful_missing_installs > 0);
    assert!(paged.activity.successful_missing_read_installs > 0);
    assert!(paged.activity.successful_missing_write_installs > 0);
    assert!(paged.activity.write_protect_transitions > 0);
    assert!(paged.activity.preservation_reads > 0);
    assert!(paged.activity.preservation_writes > 0);
    assert!(paged.activity.physical_discards > 0);

    let kernel_build_id = evidence::kernel_build_id().expect("actual booted kernel GNU build ID");
    let kernel_build_id = kernel_build_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!("managed_paging_host_kernel_build_id={kernel_build_id}");
    let mut artifacts = BTreeMap::new();
    for (label, environment) in [
        // The fixture boots the same immutable image as its outer host kernel.
        ("host_kernel", "CRUCIBLE_PAGING_KERNEL"),
        ("qemu", "CRUCIBLE_PAGING_QEMU"),
        ("plugin", "CRUCIBLE_PAGING_PLUGIN"),
    ] {
        let hash = evidence::artifact_hash(&environment_path(environment))
            .expect("identity of the exact immutable launch artifact");
        println!("managed_paging_{label}_blake3={hash}");
        artifacts.insert(label, hash.to_string());
    }
    println!(
        "managed_paging_build_graph={}",
        std::env::var("CRUCIBLE_PAGING_BUILD_GRAPH").expect("immutable Nix input graph")
    );
    println!("managed_paging_profile=pc-q35-9.2,sim-thread-single,x86_64,64-mib,one-vcpu");
    let topology = &paged.topology;
    println!("managed_paging_topology_blake3={topology}");

    println!("managed_paging_guest_state_identity=true");
    println!("managed_paging_scheduler_and_clock_identity=true");
    println!("managed_paging_published_ram_root_identity=true");
    println!("managed_paging_full_execution_peak_retained=true");
    println!("managed_paging_public_unqualified_policy_refused=true");
    println!(
        "managed_paging_missing_installs={}",
        paged.activity.successful_missing_installs
    );
    println!(
        "managed_paging_missing_read_installs={}",
        paged.activity.successful_missing_read_installs
    );
    println!(
        "managed_paging_missing_write_installs={}",
        paged.activity.successful_missing_write_installs
    );
    println!(
        "managed_paging_write_protect_transitions={}",
        paged.activity.write_protect_transitions
    );
    println!(
        "managed_paging_preservation_reads={}",
        paged.activity.preservation_reads
    );
    println!(
        "managed_paging_preservation_writes={}",
        paged.activity.preservation_writes
    );
    println!(
        "managed_paging_physical_discards={}",
        paged.activity.physical_discards
    );
    let receipt = serde_json::json!({
        "edition": 1,
        "host_kernel_build_id": kernel_build_id,
        "host_kernel_blake3": artifacts["host_kernel"],
        "qemu_blake3": artifacts["qemu"],
        "plugin_blake3": artifacts["plugin"],
        "topology_blake3": topology,
        "build_graph_sha256": std::env::var("CRUCIBLE_PAGING_BUILD_GRAPH").expect("immutable build graph"),
        "profile": {
            "machine": "pc-q35-9.2", "accelerator": "sim", "thread_mode": "single",
            "architecture": "x86_64", "guest_ram_bytes": 64 * 1024 * 1024,
            "vcpu_count": 1, "page_bytes": 4096,
        },
        "operations": {
            "full_peak_paused_reclamation": true, "read_first_faults": true,
            "write_first_faults": true, "authenticated_spill": true,
            "logical_state_unchanged": true, "strict_low_peak": false,
            "hot_fork": false, "lazy_restore": false, "transfer": false,
        },
        "activity": {
            "successful_missing_installs": paged.activity.successful_missing_installs,
            "successful_missing_read_installs": paged.activity.successful_missing_read_installs,
            "successful_missing_write_installs": paged.activity.successful_missing_write_installs,
            "write_protect_transitions": paged.activity.write_protect_transitions,
            "preservation_reads": paged.activity.preservation_reads,
            "preservation_writes": paged.activity.preservation_writes,
            "physical_discards": paged.activity.physical_discards,
        },
    });
    println!("managed_paging_receipt={receipt}");
    println!("MANAGED_PAGING_NATIVE_PASS");
}

fn paging_scenario() -> ScenarioDefForm {
    let world = World::from_nodes(vec![crucible::WorldNode {
        id: NodeId {
            name: String::from("memory"),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: 64,
        cmdline: String::new(),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("static Linux guest");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )
    .expect("identical guest in both host placement lanes")
}

fn run_lane(source: &ScenarioDefForm, lane: &str, project: u32, paging: bool) -> Lane {
    environment::with_native_preparation(source, lane, project, |prepared, config, context| {
        let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
            .expect("actual native containment factory");
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            config.lifecycle.clone(),
            ComposedQemuAttemptResourceGuardFactory::new(host),
        );
        let mut lifecycle = factory
            .begin_fresh(&source.scenario_def(), source, context)
            .expect("production lifecycle with genuine admitted RAM registration");
        let registry = &prepared.host_operational_registry;
        let owner = HostRamOwnerTarget {
            daemon_epoch: context.host_daemon_epoch(),
            owner_id: context
                .host_ram_owner_id()
                .expect("actual preparation owner"),
        };
        let target = match registry
            .execute(
                OPERATOR,
                HostOperationalRequest::ListTargets {
                    target: owner,
                    after: None,
                    limit: 32,
                },
            )
            .expect("discover current registered arena")
            .value()
        {
            HostOperationalResponse::Targets { targets, next, .. } => {
                assert_eq!(targets.len(), 1);
                assert!(next.is_none());
                targets[0]
            }
            response => panic!("unexpected discovery: {response:?}"),
        };
        let initial = status(registry, target);
        let resources = initial.admitted_resources;
        let logical_ram = match registry
            .execute(OPERATOR, HostOperationalRequest::Capabilities { target })
            .expect("actual capability declaration")
            .value()
        {
            HostOperationalResponse::Capabilities {
                capabilities,
                qualification,
                ..
            } => {
                assert!(!capabilities.dynamic_residency);
                assert!(!qualification.bounded_execution_peak);
                capabilities.logical_ram_bytes
            }
            response => panic!("unexpected capabilities: {response:?}"),
        };
        let mut cold = initial.requested_policy;
        cold.resident_target_bytes = 0;
        assert!(matches!(
            registry
                .execute(
                    OPERATOR,
                    HostOperationalRequest::UpdatePolicy {
                        target,
                        expected_policy_revision: initial.policy_revision,
                        idempotency_key: [0x51; 32],
                        policy: Box::new(cold),
                        reservation_amendment: None,
                    }
                )
                .expect("public qualification gate")
                .value(),
            HostOperationalResponse::PolicyUpdate {
                disposition: HostOperationalDisposition::Unsupported,
                ..
            }
        ));

        registry
            .apply_native_qualification_policy(target, logical_ram)
            .expect("full resident baseline without granting public capabilities");
        let mut boundaries = Vec::with_capacity(QUANTA);
        let mut configuration = lifecycle
            .resume_state()
            .expect("initial scheduler")
            .into_parts()
            .0;
        let mut before_cold = None;
        for round in 0..QUANTA {
            if paging && matches!(round, 8 | 24) {
                before_cold = Some(
                    status(registry, target)
                        .activity
                        .expect("actual paging owner counters"),
                );
                registry
                    .apply_native_qualification_policy(target, 0)
                    .expect("pause-qualified cold target");
            }
            if paging && matches!(round, 10 | 26) {
                registry
                    .apply_native_qualification_policy(target, logical_ram)
                    .expect("runtime resident target increase");
            }

            let outcome = QemuFreshAttemptLifecycleOwner::drive_quantum(
                &mut lifecycle,
                QuantumRequest {
                    configuration,
                    control: Vec::new(),
                },
            )
            .expect("resume through real physical collector and kernel faults");
            configuration = outcome.configuration;
            boundaries.push(boundary(&mut lifecycle));
            let current = status(registry, target);
            assert_eq!(current.admitted_resources, resources);
            assert_eq!(current.reservation_revision, initial.reservation_revision);
            assert!(
                !current.measurements_available,
                "activity must not invent RSS observations"
            );
            if paging && matches!(round, 9 | 25) {
                let before = before_cold.take().expect("pre-reclaim observation");
                let after = current.activity.expect("actual successful fault counters");
                assert!(after.physical_discards > before.physical_discards);
                assert!(after.preservation_writes > before.preservation_writes);
                assert!(after.successful_missing_installs > before.successful_missing_installs);
                assert!(after.write_protect_transitions > before.write_protect_transitions);
                assert!(after.preservation_reads > before.preservation_reads);
            }
        }

        let closure = lifecycle
            .capture_portable_exact_checkpoint_with_boundary(&mut || Ok(()))
            .expect("capture actual paged VMState at the final frozen cut");
        let record = closure
            .ram_sources()
            .first()
            .expect("one actual RAM root")
            .root()
            .record();
        let ram_record = record.encode();
        let topology = record.topology().digest().to_string();
        let checkpoint = prepared
            .checkpoints
            .prepare_production_closure(closure)
            .expect("bounded complete RAM CAS preparation");
        let published = prepared
            .checkpoints
            .publish_production_closure(&checkpoint)
            .expect("durable authenticated RAM graph publication");
        let loaded = prepared
            .checkpoints
            .load_attempt_checkpoint(published.root())
            .expect("authenticate persisted complete RAM closure");
        let activity = status(registry, target)
            .activity
            .expect("real kernel paging activity");
        drop(loaded);
        drop(checkpoint);
        QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
            .expect("reap native process, join workers, and release real reservations");
        Ok(Lane {
            boundaries,
            ram_record,
            topology,
            activity,
        })
    })
}

fn boundary(lifecycle: &mut ProductionVmLifecycleLoop) -> Boundary {
    let fingerprint = QemuFreshAttemptLifecycleOwner::sample_fingerprint(
        lifecycle,
        NodeId {
            name: String::from("memory"),
        },
    )
    .expect("logical RAM fingerprint at identical scheduler cut")
    .fingerprint;
    let (scheduler, log_segments) = lifecycle
        .canonical_scheduler_evidence()
        .expect("canonical scheduler");
    let (configuration, event_log, log_base, _, frontier, _, terminal) = lifecycle
        .resume_state()
        .expect("complete current boundary")
        .into_parts();
    assert!(terminal.is_none());
    Boundary {
        configuration,
        scheduler,
        event_log,
        log_base,
        log_segments,
        frontier,
        fingerprint,
    }
}

fn status(
    registry: &crate::HostOperationalRegistry,
    target: HostRamTarget,
) -> crucible_api::AdmittedOutput<HostRamStatus> {
    registry
        .execute(OPERATOR, HostOperationalRequest::Status { target })
        .expect("independent authenticated status")
        .try_map(|response| match response {
            HostOperationalResponse::Status(status) => Ok(*status),
            response => Err(format!("unexpected status: {response:?}")),
        })
        .unwrap_or_else(|error| panic!("{error}"))
}
