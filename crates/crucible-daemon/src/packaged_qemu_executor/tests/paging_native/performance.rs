//! Managed performance trials under the actual accepted repository worker.
//!
//! Ordinary TCG controls remain external. Each Sim trial uses the original
//! full-vector actor, catalog quota and admitted native world. Measurements
//! stop before fingerprint requests; reconciled console timings are explicitly
//! distinguished from the ordinary controls' immediate socket-receipt timings.

use super::super::hot_fork_native::{native_repository, native_request};
use super::*;
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct, RepositoryAttemptWorker,
    decode_crucible_attempt_execution,
};
use crucible::{AdvanceOutcome, ObservableEventPayload, SimulationBackend};
use crucible_campaign::{CampaignExecutorStore, ExecutorService, SubmitAttemptDisposition};
use crucible_qemu::{QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig};
use serde_json::{Value, json};
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

const ARGUMENTS: &str = "CRUCIBLE_TCG_PERFORMANCE_ARGUMENTS";
const WORKLOAD: &str = "CRUCIBLE_TCG_PERFORMANCE_WORKLOAD";
const CONSOLE_LIMIT: usize = 64 * 1024;

fn measurement_time() -> Result<Duration, Box<dyn Error>> {
    // Host measurements are report fields, never guest decisions or identities.
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(value.tv_sec)?;
    let nanoseconds = u32::try_from(value.tv_nsec)?;
    if nanoseconds >= 1_000_000_000 {
        return Err("host measurement clock returned an invalid nanosecond field".into());
    }
    Ok(Duration::new(seconds, nanoseconds))
}

fn measured_interval(end: Duration, start: Duration) -> Result<f64, Box<dyn Error>> {
    end.checked_sub(start)
        .map(|interval| interval.as_secs_f64())
        .ok_or_else(|| "host measurement clock moved backwards".into())
}

struct Trial {
    workload: String,
    trial_index: u32,
    cpu: usize,
    qemu: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    initrd: Option<PathBuf>,
    firmware: PathBuf,
    memory_mib: u32,
    horizon: u64,
    start_token: Option<Vec<u8>>,
    end_token: Option<Vec<u8>>,
    manifest: Option<Value>,
}

impl Trial {
    fn from_environment() -> Result<Self, Box<dyn Error>> {
        let workload = std::env::var(WORKLOAD)?;
        let trial_index: u32 = std::env::var("CRUCIBLE_TCG_TRIAL_INDEX")?.parse()?;
        if trial_index >= 64 {
            return Err("trial index exceeds its operator-installed namespace inventory".into());
        }
        let encoded = std::env::var(ARGUMENTS)?;
        if encoded.len() > 16 * 1024 {
            return Err("performance argument inventory exceeds its fixture ceiling".into());
        }
        let args: Vec<String> = serde_json::from_str(&encoded)?;
        let mut trial = Self {
            workload: workload.clone(),
            trial_index,
            cpu: 0,
            qemu: PathBuf::new(),
            plugin: PathBuf::new(),
            kernel: environment_path("CRUCIBLE_PAGING_KERNEL"),
            initrd: None,
            firmware: environment_path("CRUCIBLE_TCG_FIRMWARE"),
            memory_mib: 64,
            horizon: 0,
            start_token: None,
            end_token: None,
            manifest: None,
        };
        match workload.as_str() {
            "bios" if args.len() == 7 => {
                trial.cpu = args[6].parse()?;
                trial.qemu = args[1].clone().into();
                trial.plugin = args[2].clone().into();
                trial.firmware = args[3].clone().into();
                trial.horizon = args[4]
                    .parse::<u64>()?
                    .checked_mul(crucible::SIM_TICKS_PER_INSTRUCTION)
                    .ok_or("BIOS instruction horizon overflow")?;
            }
            "linux" if (9..=10).contains(&args.len()) => {
                trial.cpu = args[7].parse()?;
                trial.qemu = args[2].clone().into();
                trial.plugin = args[3].clone().into();
                trial.kernel = args[4].clone().into();
                trial.initrd = Some(args[5].clone().into());
                trial.memory_mib = args[8].parse()?;
                trial.horizon = 20_000_000_000_000;
                trial.end_token = Some(b"\nCRUCIBLE_TCG_BOOT_READY_V1\n".to_vec());
            }
            "rom" if args.len() == 8 => {
                trial.cpu = args[6].parse()?;
                trial.qemu = args[2].clone().into();
                trial.plugin = args[3].clone().into();
                trial.firmware = args[4].clone().into();
                trial.horizon = 20_000_000_000_000;
                let bytes = std::fs::read(&args[7])?;
                if bytes.len() > 4096 {
                    return Err("ROM manifest exceeds its immutable fixture ceiling".into());
                }
                let manifest: Value = serde_json::from_slice(&bytes)?;
                trial.start_token = Some(
                    manifest["start_token"]
                        .as_str()
                        .ok_or("ROM manifest has no START token")?
                        .as_bytes()
                        .to_vec(),
                );
                trial.end_token = Some(
                    manifest["end_token"]
                        .as_str()
                        .ok_or("ROM manifest has no checksum END token")?
                        .as_bytes()
                        .to_vec(),
                );
                trial.manifest = Some(manifest);
            }
            _ => return Err("invalid admitted performance workload or arguments".into()),
        }
        if !(64..=512).contains(&trial.memory_mib)
            || trial.horizon == 0
            || trial.qemu != environment_path("CRUCIBLE_PAGING_QEMU")
            || trial.plugin != environment_path("CRUCIBLE_PAGING_PLUGIN")
        {
            return Err(
                "trial differs from the actual kernel wrapper's bound artifacts or limits".into(),
            );
        }
        Ok(trial)
    }
}

#[test]
#[ignore = "requires an isolated source-built kernel, project quota, cgroups and managed UFFD"]
fn managed_tcg_performance_trial() {
    let trial = Trial::from_environment().expect("explicit native performance input");
    let lane = format!("perf-{}-{}", trial.workload, trial.trial_index);
    let project = 35_000 + trial.trial_index * 100;
    let source = scenario(trial.memory_mib);
    environment::with_native_repository_environment(
        &lane,
        project,
        |root, storage| native_repository(&source, root, storage),
        |config| config,
        |prepared, config, repository| {
            let baseline = prepared
                .actor
                .with_supervisor(|actor| Ok(actor.host_resource_availability()))
                .expect("actual full-vector baseline including persistent namespaces")
                .expect("available original actor capacity");
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
                    .expect("canonical accepted assignment and queue claim");
            let store = CampaignExecutorStore::new(repository);
            let mut worker = RepositoryAttemptWorker::new(
                store.clone(),
                MeasurementModel {
                    trial,
                    config: config.clone(),
                    store,
                    sample: None,
                    sample_resident: None,
                },
            );
            let (queued, result) = worker.execute(queued).into_parts();
            assert!(
                matches!(result, Err(AttemptWorkerFailure::Canceled(_))),
                "native trial must clean and reconcile before reporting: {result:?}"
            );
            prepared
                .actor
                .with_supervisor(|actor| {
                    actor
                        .stage_and_reconcile_cancellation(&queued)
                        .map_err(|_| {
                            crucible_api::host_operational::HostOperationalError::Unavailable
                        })
                })
                .expect("reconcile same accepted owner after actual reap");
            let available = prepared
                .actor
                .with_supervisor(|actor| Ok(actor.host_resource_availability()))
                .expect("actual full-vector availability after native close")
                .expect("available original actor capacity after physical cleanup");
            assert_eq!(
                available, baseline,
                "all eight assignment charges restore only after physical cleanup"
            );
            let sample = worker
                .model()
                .sample
                .as_ref()
                .expect("successful native measurement");
            println!("\nTCG_MANAGED_SAMPLE={sample}");
        },
    );
}

fn scenario(memory_mib: u32) -> ScenarioDefForm {
    let world = World::from_nodes(vec![crucible::WorldNode {
        id: NodeId {
            name: "performance-node".into(),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib,
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
    .expect("authored performance machine shape");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )
    .expect("canonical accepted performance scenario")
}

struct MeasurementModel {
    trial: Trial,
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    sample: Option<Value>,
    sample_resident: Option<Arc<dyn Send + Sync>>,
}

impl AttemptExecutionModel for MeasurementModel {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        let decoded = decode_crucible_attempt_execution(&self.store, input)
            .expect("original accepted scenario and retained decode authority");
        let mut factory = plugin_flight::admission::AdmittedFlightFactory::with_evidence_bound(
            &self.config,
            context,
            decoded.scenario(),
            evidence_bound(),
        )
        .expect("actual world partition and original native supervision");
        self.sample_resident = Some(factory.evidence_custody());
        self.sample = Some(
            measure(&self.trial, &mut factory, self.config.host.run_root())
                .unwrap_or_else(|error| panic!("admitted performance trial failed: {error}")),
        );
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "native measurement completed and actual process/resources closed",
        )))
    }
}

fn measure(
    trial: &Trial,
    factory: &mut plugin_flight::admission::AdmittedFlightFactory<'_>,
    run_root: &std::path::Path,
) -> Result<Value, Box<dyn Error>> {
    let memory = u64::from(trial.memory_mib) * 1024 * 1024;
    let mut owner = factory.begin(1, memory, 0)?;
    let mut config = QemuLiveNodeStepGateConfig::new(
        &trial.qemu,
        &trial.plugin,
        &trial.kernel,
        &trial.firmware,
        run_root,
    )
    .with_vm_shape(trial.memory_mib, 1)
    .with_rr_switch_quantum(4096)
    .with_coverage(crucible_qemu::QemuLaunchPluginSwitch::Off)
    .with_fingerprint(crucible_qemu::QemuLaunchPluginSwitch::On)
    .with_console_capture();
    if let Some(initrd) = &trial.initrd {
        config = config
            .with_initrd(initrd)
            .with_kernel_cmdline("console=ttyS0 reboot=k panic=1 quiet rdinit=/init");
    } else {
        config = config.with_firmware_boot();
    }
    if trial.workload != "bios" {
        use crucible_protocol::selectable_catalog_plan::*;
        let declaration = SelectablePlanDeclaration::new(
            "flight.ready",
            vec![1],
            vec![1],
            vec!["readiness".into()],
            SelectablePlanPresence::Required,
        )?;
        config = config
            .with_whitebox(crucible_qemu::QemuLaunchPluginSwitch::On)
            .with_selectable_catalog_plan(SelectableCatalogPlan::new(
                SelectablePlanLimits::new(1, 1, 1)?,
                vec![declaration],
                SelectablePlanContinuation::cold(),
            )?);
    }
    let mut directory = owner.prepare_generation_run_directory(config.resource_requirements())?;
    owner.prepare_fresh_artifacts(&mut directory, &trial.qemu)?;
    let config = owner.configure_launch(config.with_run_directory(directory.path()))?;
    let launch_start = measurement_time()?;
    let mut node = owner.launch(
        &config,
        &directory,
        QemuLiveNodeIdentity::new(
            "performance-node",
            "performance-router",
            "performance-crash",
        ),
    )?;
    let startup_seconds = measured_interval(measurement_time()?, launch_start)?;
    let boot_start = measurement_time()?;
    let stopped = SimulationBackend::step_to(
        &mut node,
        VirtualTime {
            ticks: trial.horizon,
        },
    )?;
    let end = measurement_time()?;
    let calibration = node.logical_time_calibration()?;
    if stopped.reached.ticks != calibration.logical_icount {
        return Err("native stop differs from the original authorized coordinate".into());
    }
    let mut console = Vec::new();
    for event in SimulationBackend::drain_observable_events(&mut node)? {
        if let ObservableEventPayload::ConsoleOutput { bytes, .. } = event.payload() {
            if console
                .len()
                .checked_add(bytes.len())
                .is_none_or(|length| length > CONSOLE_LIMIT)
            {
                return Err("native console exceeds its finite witness ceiling".into());
            }
            crucible::owned_decode::reserve_vec(&mut console, bytes.len())?;
            console.extend_from_slice(bytes);
        }
    }
    let token_count = |token: &[u8]| {
        console
            .windows(token.len())
            .filter(|bytes| *bytes == token)
            .count()
    };
    if trial
        .end_token
        .as_ref()
        .is_some_and(|token| token.is_empty() || token_count(token) != 1)
        || trial
            .start_token
            .as_ref()
            .is_some_and(|token| token.is_empty() || token_count(token) != 1)
    {
        return Err(
            "native measurement lacks its exact unique serial token/checksum witness".into(),
        );
    }
    if let (Some(start), Some(end)) = (&trial.start_token, &trial.end_token) {
        let start_at = console
            .windows(start.len())
            .position(|bytes| bytes == start);
        let end_at = console.windows(end.len()).position(|bytes| bytes == end);
        if start_at >= end_at {
            return Err("finite ROM END precedes its actual START token".into());
        }
    }
    let timer_witness = node.virtual_timer_fire_witness()?.map(|timer| {
        json!({
            "generation": timer.generation, "deadline_ps": timer.deadline_ps,
            "deadline_tick": timer.deadline_tick, "armed_raw_icount": timer.armed_raw_icount,
            "fired_expire_ps": timer.fired_expire_ps, "fired_virtual_ps": timer.fired_virtual_ps,
            "fired_raw_icount": timer.fired_raw_icount,
            "completed": timer.completed, "reserved": timer.reserved,
        })
    });
    let pending = node.drain_pending_selectable_requests()?;
    let request = if trial.workload == "bios" {
        if !pending.is_empty() || stopped.reached.ticks != trial.horizon {
            return Err("BIOS measurement did not end at its exact authored horizon".into());
        }
        None
    } else {
        let [pending] = pending.as_slice() else {
            return Err(
                "native readiness must retain exactly one authenticated selectable request".into(),
            );
        };
        let request = pending.request();
        if !matches!(stopped.outcome, AdvanceOutcome::Paused { .. })
            || request.sequence() != 2
            || request.selectable_id() != "flight.ready"
            || request.instance_key() != "boot"
            || pending.vcpu_index() != 0
            || calibration.raw_icount != pending.raw_icount() + 1
            || calibration.logical_icount
                != pending.trap_tick_ps() + crucible::SIM_TICKS_PER_INSTRUCTION
        {
            return Err(
                "native stop does not authenticate the exact request+one-instruction boundary"
                    .into(),
            );
        }
        Some(
            json!({"sequence": request.sequence(), "selectable_id": request.selectable_id(),
            "instance_key": request.instance_key(), "raw_icount": pending.raw_icount(),
            "logical_tick": pending.trap_tick_ps()}),
        )
    };
    // The measurement endpoint precedes every requested fingerprint and reap.
    let fingerprint = node.execution_fingerprint()?;
    let sample = node.fingerprint_sample()?;
    if sample.sample_icount != calibration.logical_icount
        || sample.component_failures != 0
        || sample.vcpu_count != 1
        || sample.ram_bytes < memory
    {
        return Err("native stopped state lacks the complete admitted fingerprint witness".into());
    }
    let observation_guard = factory.observation_guard()?;
    let observation =
        node.observe_performance_fixture(&observation_guard, factory.evidence_custody())?;
    observation_guard.complete()?;
    let shutdown = node.shutdown_child()?;
    if !shutdown.reaped || shutdown.leaked {
        return Err("performance native process did not physically close".into());
    }
    drop(node);
    owner.finish()?;
    Ok(json!({
        "schema": "crucible.managed-tcg-performance.v1", "mode": "sim",
        "managed_owner": true, "accepted_assignment": true,
        "workload": trial.workload, "seconds": measured_interval(end, launch_start)?,
        "boot_seconds": measured_interval(end, boot_start)?, "startup_seconds": startup_seconds,
        "measurement_scope": "native spawn through authenticated stopped boundary; serial bytes reconciled at that boundary",
        "serial_receipt_roi_seconds": null,
        "raw_icount": calibration.raw_icount, "logical_tick": calibration.logical_icount,
        "request": request, "manifest": trial.manifest, "timer_witness": timer_witness,
        "canonical_execution_fingerprint": fingerprint.hash.to_hex(),
        "canonical_ram_blake3": ContentHash { bytes: sample.ram_digest }.to_hex(),
        "canonical_register_blake3": ContentHash { bytes: sample.vcpus[0].register_digest }.to_hex(),
        "canonical_device_blake3": ContentHash { bytes: sample.device_state_digest }.to_hex(),
        "ram_bytes": sample.ram_bytes, "ram_mib": trial.memory_mib,
        "component_failures": sample.component_failures,
        "registers": observation.registers,
        "ram_prefix_hex": encode_bytes(&observation.bios_prefix),
        "record_hex": encode_bytes(&observation.finite_record),
        "sim_saved_registers_hex": encode_bytes(&observation.finite_saved_registers),
        "serial_hex": encode_bytes(&console), "native_cleanup": true,
        "qemu": trial.qemu, "plugin": trial.plugin,
        "kernel": trial.kernel, "initrd": trial.initrd, "rom": trial.firmware, "cpu": trial.cpu,
        "milestone": "CRUCIBLE_TCG_BOOT_READY_V1", "milestone_count": if trial.workload == "linux" { 1 } else { 0 },
        "fingerprint_requests_after_measurement": true,
    }))
}

fn encode_bytes(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").expect("String formatting cannot fail");
    }
    result
}

fn evidence_bound() -> u64 {
    // At most one console Vec, its two-byte hex renderer and its JSON-owned
    // copy coexist. The bounded QMP line, parser, register owner, sample copy,
    // and final renderer each have a distinct 32 KiB bank. Fixed JSON objects
    // have fewer than 128 keys; sixteen typed B-tree slots per insertion cover
    // node splits and geometric growth alongside owned key buffers.
    let console_banks = CONSOLE_LIMIT * (1 + 2 + 2);
    let monitor_banks = 32 * 1024 * 5;
    let object_banks = 128 * (16 * std::mem::size_of::<(String, Value)>() + 512);
    let input_and_keys = 2 * 16 * 1024 + 128 * 128;
    (console_banks + monitor_banks + object_banks + input_and_keys) as u64
}
