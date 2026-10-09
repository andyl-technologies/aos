//! Observes a fixed guest CPU write under the original admitted native owner.
//!
//! A genuine ordinary fingerprint at instruction one establishes the committed
//! baseline before either candidate. The signed native comparator then borrows
//! one stopped physical token across its no-ack candidate and independent full
//! read. The fixed adversary preserves the first horizon's notifications and
//! omits the RAM range client only afterward. Native scalar records must be
//! validated separately by the exact artifact-bound evidence checker.
//!
//! This ignored source fixture is one CPU-path test. DMA, reset, restore,
//! remap/discard, fork/stream and complete scratch/payer qualifications are not
//! inferred from its arithmetic witness or from parser unit controls.

use super::super::hot_fork_native::{native_repository, native_request};
use super::*;
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct, RepositoryAttemptWorker,
    decode_crucible_attempt_execution,
};
use crucible::SimulationBackend;
use crucible_campaign::{CampaignExecutorStore, ExecutorService, SubmitAttemptDisposition};
use crucible_qemu::{QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig};

const FIRST: u64 = 700_000;
const SECOND: u64 = 1_400_000;
const MEMORY_MIB: u32 = 64;

#[test]
#[ignore = "requires final paired native artifact, complete scratch/payer proof, and owned kernel admission"]
fn managed_complete_write_oracle() {
    let negative = match std::env::var("CRUCIBLE_COMPLETE_WRITE_ORACLE_ROLE").as_deref() {
        Ok("oracle-positive") => false,
        Ok("notification-adversary") => true,
        _ => panic!("explicit fixed diagnostic role required"),
    };
    let (lane, project) = if negative {
        ("write-oracle-negative", 37_100)
    } else {
        ("write-oracle-positive", 37_000)
    };
    let world = World::from_nodes(vec![crucible::WorldNode {
        id: NodeId {
            name: "dirty-writer".into(),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: MEMORY_MIB,
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
    .expect("unchanged arithmetic ROM machine");
    let source = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )
    .expect("authored accepted scenario");
    environment::with_native_repository_environment(
        lane,
        project,
        |root, storage| native_repository(&source, root, storage),
        |config| config,
        |prepared, config, repository| {
            let baseline = prepared
                .actor
                .with_supervisor(|actor| Ok(actor.host_resource_availability()))
                .expect("original actor")
                .expect("full eight-field baseline");
            let request = native_request(&repository, config);
            let queued =
                prepared
                    .actor
                    .with_supervisor(|actor| {
                        assert!(matches!(actor.submit_attempt(&request)
                    .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)?
                    .disposition(), SubmitAttemptDisposition::Accepted { .. }));
                        actor.next_queued().ok_or(
                            crucible_api::host_operational::HostOperationalError::Unavailable,
                        )
                    })
                    .expect("canonical accepted assignment and original queue claim");
            let store = CampaignExecutorStore::new(repository);
            let mut worker = RepositoryAttemptWorker::new(
                store.clone(),
                DiagnosticModel {
                    store,
                    config: config.clone(),
                    negative,
                    observed: false,
                },
            );
            let (queued, result) = worker.execute(queued).into_parts();
            assert!(
                matches!(result, Err(AttemptWorkerFailure::Canceled(_))),
                "diagnostic closes and reconciles its original process: {result:?}"
            );
            assert!(worker.model().observed);
            prepared
                .actor
                .with_supervisor(|actor| {
                    actor
                        .stage_and_reconcile_cancellation(&queued)
                        .map_err(|_| {
                            crucible_api::host_operational::HostOperationalError::Unavailable
                        })
                })
                .expect("original accepted assignment cancellation");
            let restored = prepared
                .actor
                .with_supervisor(|actor| Ok(actor.host_resource_availability()))
                .expect("same actor after reap")
                .expect("full eight-field restored vector");
            assert_eq!(restored, baseline);
            println!("complete_write_oracle_cleanup reaped=true resources_restored=true");
        },
    );
    println!("COMPLETE_WRITE_ORACLE_ONE_CPU_FIXTURE_PASS");
}

struct DiagnosticModel {
    store: CampaignExecutorStore,
    config: PackagedQemuExecutorConfig,
    negative: bool,
    observed: bool,
}

impl AttemptExecutionModel for DiagnosticModel {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        let decoded = decode_crucible_attempt_execution(&self.store, input)
            .expect("original accepted decode authority");
        // The fixed QMP observer bounds each response at 32 KiB. Retain banks
        // for the two replies, parsed register strings and both returned samples.
        let mut factory = plugin_flight::admission::AdmittedFlightFactory::with_evidence_bound(
            &self.config,
            context,
            decoded.scenario(),
            5 * 32 * 1024,
        )
        .expect("actual catalog evidence and native world admission");
        let qemu = environment_path("CRUCIBLE_PAGING_QEMU");
        let firmware = environment_path("CRUCIBLE_COMPLETE_WRITE_ORACLE_ROM");
        let mut owner = factory
            .begin(1, u64::from(MEMORY_MIB) * 1024 * 1024, 0)
            .expect("original full-vector native owner");
        let launch = QemuLiveNodeStepGateConfig::new(
            &qemu,
            environment_path("CRUCIBLE_PAGING_PLUGIN"),
            environment_path("CRUCIBLE_PAGING_KERNEL"),
            firmware,
            self.config.host.run_root(),
        )
        .with_vm_shape(MEMORY_MIB, 1)
        .with_rr_switch_quantum(4096)
        .with_coverage(crucible_qemu::QemuLaunchPluginSwitch::Off)
        .with_fingerprint(crucible_qemu::QemuLaunchPluginSwitch::On)
        .with_firmware_boot();
        let mut directory = owner
            .prepare_generation_run_directory(launch.resource_requirements())
            .expect("original quota namespace and process owner");
        owner
            .prepare_fresh_artifacts(&mut directory, &qemu)
            .expect("same original preparation cap");
        let launch = owner
            .configure_launch(launch.with_run_directory(directory.path()))
            .expect("genuine native inventory admission");
        let mut node = owner
            .launch(
                &launch,
                &directory,
                QemuLiveNodeIdentity::new("dirty-writer", "dirty-router", "dirty-crash"),
            )
            .expect("actual supervised diagnostic QEMU");

        // This genuine ordinary observation precedes the native candidate at
        // FIRST. The fixed adversary retains every notification until FIRST.
        let genesis = SimulationBackend::step_to(&mut node, VirtualTime { ticks: 50 })
            .expect("actual guest coordinate before first candidate");
        assert_eq!(genesis.reached.ticks, 50);
        assert_eq!(
            node.logical_time_calibration()
                .expect("ordinary baseline coordinate")
                .raw_icount,
            1
        );
        let baseline = node
            .execution_fingerprint()
            .expect("original ordinary capture establishes committed baseline");
        println!(
            "complete_write_oracle_baseline raw=1 hash={}",
            baseline.hash.to_hex()
        );

        let first = SimulationBackend::step_to(&mut node, VirtualTime { ticks: FIRST * 50 })
            .expect("first authenticated stopped boundary");
        assert_eq!(first.reached.ticks, FIRST * 50);
        let initial = node
            .execution_fingerprint()
            .expect("first candidate equality and subsequent ordinary acknowledgement");
        println!(
            "complete_write_oracle_first raw=700000 hash={}",
            initial.hash.to_hex()
        );
        let guard = factory
            .observation_guard()
            .expect("original fixed observation budget");
        let before = node
            .observe_performance_fixture(&guard, factory.evidence_custody())
            .expect("first paused arithmetic witness");
        guard.complete().expect("original observation boundary");
        require_arithmetic(&before.registers, before.bios_prefix, FIRST);
        assert_eq!(
            node.logical_time_calibration()
                .expect("first coordinate")
                .raw_icount,
            FIRST
        );

        let second = SimulationBackend::step_to(&mut node, VirtualTime { ticks: SECOND * 50 });
        if !self.negative {
            assert_eq!(
                second
                    .expect("second genuine positive stopped boundary")
                    .reached
                    .ticks,
                SECOND * 50
            );
        }
        // A contained mismatch may make advance itself refuse. It is not a
        // passing negative without the exact native EBADMSG record, actual
        // stopped coordinate and independently read changed guest bytes below.
        let guard = factory
            .observation_guard()
            .expect("original second observation budget");
        let after = node
            .observe_performance_fixture(&guard, factory.evidence_custody())
            .expect("actual paused CPU write witness before root request");
        guard.complete().expect("original observation boundary");
        require_arithmetic(&after.registers, after.bios_prefix, SECOND);
        assert_eq!(
            node.logical_time_calibration()
                .expect("second coordinate")
                .raw_icount,
            SECOND
        );
        assert_ne!(
            &before.bios_prefix[..8],
            &after.bios_prefix[..8],
            "a real supported CPU store must change the independently read RAM"
        );
        println!(
            "complete_write_oracle_write raw=1400000 before={:016x} after={:016x}",
            u64::from_le_bytes(before.bios_prefix),
            u64::from_le_bytes(after.bios_prefix)
        );
        let final_root = node.execution_fingerprint();
        if self.negative {
            assert!(
                final_root.is_err(),
                "stale incremental root must not return a usable receipt"
            );
            println!("complete_write_oracle_identity unavailable=true");
        } else {
            assert_ne!(
                final_root
                    .expect("positive independent oracle equality")
                    .hash,
                initial.hash
            );
            println!("complete_write_oracle_identity changed=true");
        }
        let shutdown = node
            .shutdown_child()
            .expect("original admitted process cleanup");
        assert!(shutdown.reaped && !shutdown.leaked);
        drop(node);
        owner
            .finish()
            .expect("physical node and watcher retirement");
        self.observed = true;
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "fixed diagnostic observed and original process physically closed",
        )))
    }
}

fn require_arithmetic(registers: &str, prefix: [u8; 8], stop: u64) {
    let complete = (stop - 6) / 7;
    let partial = (stop - 6) % 7;
    let mut accumulator = 0x51f1_5eed_u32;
    for _ in 0..complete {
        accumulator = (accumulator.rotate_left(13) ^ 0x9e37_79b9).wrapping_add(0x6d2b_79f5);
    }
    let mut memory_accumulator = accumulator;
    let mut counter = u32::try_from(complete).expect("fixed instruction horizon");
    let mut memory_counter = counter;
    if partial >= 1 {
        accumulator = accumulator.rotate_left(13);
    }
    if partial >= 2 {
        accumulator ^= 0x9e37_79b9;
    }
    if partial >= 3 {
        accumulator = accumulator.wrapping_add(0x6d2b_79f5);
    }
    if partial >= 4 {
        memory_accumulator = accumulator;
    }
    if partial >= 5 {
        counter = counter.wrapping_add(1);
    }
    if partial >= 6 {
        memory_counter = counter;
    }
    let mut expected = [0_u8; 8];
    expected[..4].copy_from_slice(&memory_accumulator.to_le_bytes());
    expected[4..].copy_from_slice(&memory_counter.to_le_bytes());
    assert_eq!(prefix, expected, "independent actual CPU store oracle");
    for (name, value) in [("EAX", accumulator), ("ECX", counter)] {
        let observed = registers.split_whitespace().find_map(|field| {
            let (field_name, encoded) = field.split_once('=')?;
            (field_name == name)
                .then(|| u32::from_str_radix(encoded, 16).ok())
                .flatten()
        });
        assert_eq!(observed, Some(value), "independent stopped register oracle");
    }
}
