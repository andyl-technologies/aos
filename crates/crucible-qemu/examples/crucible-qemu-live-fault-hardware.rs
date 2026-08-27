//! Runs the live guest-clock, memory, and accelerator hardware workload.
//!
//! This gate launches the production patched QEMU process, Rust control plugin,
//! scheduler-facing [`crucible_qemu::QemuNode`], shared-memory host runtime, and
//! `virtio-crucible-accelerator` servicer. The guest itself enumerates the real
//! PCI function and submits the closed GPU, TPU, and FPGA job schemas through a
//! modern split virtqueue. Console bytes are collected only through Crucible's
//! normal observable-event path.
//!
//! Positional arguments: `QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY`.

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use crucible::model::{
    ContentHash, FaultCoordinate, FaultObservationKind, FaultOperation, FaultOpportunity,
    FaultPhase, HostFaultAdapterManifests, OpportunityPayload, SignalBoundarySnapshot,
};
#[cfg(target_os = "linux")]
use crucible::{Checkpoint, CheckpointKind, Icount, NodeId, SimulationBackend, VirtualTime};
#[cfg(target_os = "linux")]
use crucible_qemu::{
    DEFAULT_VMSTATE_FILE_NAME, ProductionFaultRuntime, QemuLaunchPluginSwitch,
    QemuLiveNodeStepGateConfig, QemuNodeSet, launch_qemu_live_node,
    launch_qemu_live_node_exact_snapshot,
};

#[cfg(target_os = "linux")]
#[path = "crucible_qemu_live_fault_hardware/plan.rs"]
mod plan;
#[cfg(target_os = "linux")]
use plan::{accelerator_target, fault_hardware_plan};
#[cfg(target_os = "linux")]
#[path = "crucible_qemu_live_fault_hardware/support.rs"]
mod support;
#[cfg(target_os = "linux")]
use support::{collect_console, contains, error_chain, required_arg, usage};

#[cfg(target_os = "linux")]
// Linux reaches its initramfs workload near 3.35 billion retired instructions
// under the deterministic sim accelerator. One wide, finite authorization lets
// QEMU advance directly through guest timer deadlines; scheduler boundaries are
// reserved for actual fault and device events rather than host polling slices.
const MAX_STEPS: u64 = 1;
#[cfg(target_os = "linux")]
const STEP_ICOUNT: u64 = 5_120_000_000;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    support::entry(run)
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let program = args
        .next()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("crucible-qemu-live-fault-hardware"));
    let qemu = required_arg(&mut args, &program)?;
    let plugin = required_arg(&mut args, &program)?;
    let kernel = required_arg(&mut args, &program)?;
    let firmware = required_arg(&mut args, &program)?;
    let initrd = required_arg(&mut args, &program)?;
    let run_directory = std::path::PathBuf::from(required_arg(&mut args, &program)?);
    if args.next().is_some() {
        return Err(usage(&program));
    }

    let capture_directory = run_directory.join("capture");
    let restore_directory = run_directory.join("restore");
    fs::create_dir_all(&capture_directory)
        .map_err(|error| format!("create capture directory: {error}"))?;
    fs::create_dir_all(&restore_directory)
        .map_err(|error| format!("create restore directory: {error}"))?;
    let config =
        QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, &capture_directory)
            .with_initrd(initrd)
            .with_kernel_cmdline("console=ttyS0 reboot=k panic=1 quiet")
            .with_vm_shape(128, 1, 0)
            .with_fingerprint(QemuLaunchPluginSwitch::On)
            .with_accelerator()
            .with_console_capture()
            .with_second_run_scheduler_preemption(false);
    let mut node = launch_qemu_live_node(
        &config,
        &capture_directory,
        "fault-hardware-node",
        "fault-hardware-router",
        "fault-hardware-crash-detector",
    )
    .map_err(|error| error_chain(&error))?;

    let node_id = NodeId {
        name: String::from("fault-hardware-node"),
    };
    let initial_icount = node
        .current_icount()
        .map_err(|error| format!("read live hardware guest boundary: {error}"))?
        .retired;
    let pre_fault_fingerprint = node
        .execution_fingerprint()
        .map_err(|error| format!("capture pre-fault execution fingerprint: {error}"))?;
    let pre_fault_sample = node
        .fingerprint_sample()
        .map_err(|error| format!("read pre-fault fingerprint components: {error}"))?;
    let mut nodes = QemuNodeSet::new();
    if nodes.insert(node_id.clone(), node).is_some() {
        return Err(String::from("live hardware node identity collided"));
    }

    let plan = fault_hardware_plan()?;
    let store: Arc<dyn crucible::model::DagStore> =
        Arc::new(crucible::model::MemoryDagStore::new());
    let artifacts: Arc<dyn crucible::model::SignalArtifactProvider> =
        Arc::new(crucible::model::OwnedDagSignalArtifactProvider::new(store));
    let mut runtime = ProductionFaultRuntime::new(
        plan.clone(),
        Some(Arc::clone(&artifacts)),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"crucible.live-fault-hardware.v1"),
        HostFaultAdapterManifests::node_only()
            .map_err(|error| format!("build node-only fault manifests: {error}"))?,
        &nodes,
    )
    .map_err(|error| format!("admit live fault-hardware plan: {error}"))?;
    let fault_coordinate = FaultCoordinate {
        virtual_nanos: 1,
        retired_instructions: Some(initial_icount),
    };
    let boundary = runtime
        .evaluate_boundary(fault_coordinate, 0, &mut nodes)
        .map_err(|error| format!("apply guest-clock signal boundary: {error}"))?;
    let accelerator_lifecycle_boundary = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 3,
                retired_instructions: Some(initial_icount),
            },
            0,
            &mut nodes,
        )
        .map_err(|error| format!("apply accelerator-lifecycle signal boundary: {error}"))?;
    let accelerator_memory_boundary = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 4,
                retired_instructions: Some(initial_icount),
            },
            0,
            &mut nodes,
        )
        .map_err(|error| format!("apply accelerator-memory signal boundary: {error}"))?;
    let accelerator_service_boundary = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 5,
                retired_instructions: Some(initial_icount),
            },
            0,
            &mut nodes,
        )
        .map_err(|error| format!("apply accelerator-service signal boundary: {error}"))?;
    let boundary_action_counts = [
        boundary.actions.len(),
        accelerator_lifecycle_boundary.actions.len(),
        accelerator_memory_boundary.actions.len(),
        accelerator_service_boundary.actions.len(),
    ];
    if boundary_action_counts != [2, 1, 1, 1] {
        return Err(format!(
            "pre-workload hardware signal boundary action counts were {boundary_action_counts:?} instead of [2, 1, 1, 1]"
        ));
    }
    let pre_workload_action_count = boundary_action_counts
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .ok_or_else(|| String::from("hardware signal action count overflowed"))?;
    if pre_workload_action_count != 5 {
        return Err(format!(
            "pre-workload hardware signal boundaries produced {pre_workload_action_count} actions instead of five"
        ));
    }
    let actions = || {
        boundary
            .actions
            .iter()
            .chain(accelerator_lifecycle_boundary.actions.iter())
            .chain(accelerator_memory_boundary.actions.iter())
            .chain(accelerator_service_boundary.actions.iter())
    };
    let clock_action_count = actions()
        .filter(|action| action.binding.as_str() == "guest-clock-offset-binding")
        .count();
    let memory_action_count = actions()
        .filter(|action| action.binding.as_str() == "fingerprint-memory-binding")
        .count();
    let accelerator_lifecycle_action_count = actions()
        .filter(|action| action.binding.as_str() == "accelerator-lifecycle-reset-binding")
        .count();
    let accelerator_memory_action_count = actions()
        .filter(|action| action.binding.as_str() == "accelerator-memory-corrected-binding")
        .count();
    let accelerator_service_action_count = actions()
        .filter(|action| action.binding.as_str() == "accelerator-service-throttle-binding")
        .count();
    if clock_action_count != 1
        || memory_action_count != 1
        || accelerator_lifecycle_action_count != 1
        || accelerator_memory_action_count != 1
        || accelerator_service_action_count != 1
    {
        return Err(format!(
            "pre-workload hardware actions were clock={clock_action_count}, memory={memory_action_count}, accelerator-lifecycle={accelerator_lifecycle_action_count}, accelerator-memory={accelerator_memory_action_count}, accelerator-service={accelerator_service_action_count}"
        ));
    }
    let mut node = nodes
        .take(&node_id)
        .ok_or_else(|| String::from("clock-fault node disappeared"))?;
    let post_fault_icount = node
        .current_icount()
        .map_err(|error| format!("read post-fault execution coordinate: {error}"))?
        .retired;
    let post_fault_fingerprint = node
        .execution_fingerprint()
        .map_err(|error| format!("capture post-fault execution fingerprint: {error}"))?;
    let post_fault_sample = node
        .fingerprint_sample()
        .map_err(|error| format!("read post-fault fingerprint components: {error}"))?;
    if post_fault_icount != initial_icount {
        return Err(format!(
            "same-boundary clock fault advanced icount from {initial_icount} to {post_fault_icount}"
        ));
    }
    if pre_fault_sample.sample_icount != initial_icount
        || post_fault_sample.sample_icount != initial_icount
    {
        return Err(format!(
            "same-boundary fingerprint samples were stamped pre={} post={} instead of {initial_icount}",
            pre_fault_sample.sample_icount, post_fault_sample.sample_icount
        ));
    }
    if pre_fault_sample.ram_bytes == 0 || pre_fault_sample.ram_bytes != post_fault_sample.ram_bytes
    {
        return Err(format!(
            "same-boundary RAM coverage changed from {} to {} bytes",
            pre_fault_sample.ram_bytes, post_fault_sample.ram_bytes
        ));
    }
    if post_fault_fingerprint == pre_fault_fingerprint {
        return Err(String::from(
            "same-icount guest-RAM mutation retained the pre-fault execution fingerprint",
        ));
    }
    if pre_fault_sample.ram_digest == post_fault_sample.ram_digest {
        return Err(String::from(
            "same-icount guest-RAM mutation retained the pre-fault RAM digest",
        ));
    }
    if nodes.insert(node_id.clone(), node).is_some() {
        return Err(String::from("clock-fault node identity collided"));
    }
    let accelerator_opportunity = FaultOpportunity::new(
        accelerator_target()?,
        FaultOperation::AcceleratorComplete,
        FaultPhase::Complete,
        FaultCoordinate {
            virtual_nanos: 5,
            retired_instructions: Some(initial_icount),
        },
        0,
        None,
        OpportunityPayload::AcceleratorJob {
            job_sequence: 2,
            job_digest: ContentHash::from_bytes(
                &crucible_shmem::canonical_accelerator_job_material(
                    crucible_shmem::AcceleratorClass::Tpu,
                    1,
                    0,
                    1_000,
                    4,
                    &[1, 0, 2, 0, 1, 0, 2, 3, 4, 5],
                )
                .map_err(|error| format!("encode TPU job identity: {error}"))?,
            ),
        },
    )
    .map_err(|error| format!("build accelerator opportunity: {error}"))?;
    let opportunity = runtime
        .evaluate_opportunity(&accelerator_opportunity, 1, &mut nodes)
        .map_err(|error| format!("apply accelerator opportunity: {error}"))?;
    if opportunity.actions.len() != 1 {
        return Err(format!(
            "accelerator opportunity produced {} actions instead of one",
            opportunity.actions.len()
        ));
    }

    // Capture after the one-shot accelerator rule is armed but before any
    // guest job can complete. The old QEMU process and its plugin are then
    // destroyed, so the occurrence can only succeed if a fresh plugin rebuilds
    // its validation state from authenticated VMState and the event envelope.
    let runtime_checkpoint = runtime
        .checkpoint(&mut nodes)
        .map_err(|error| format!("checkpoint armed fault runtime: {error}"))?;
    let checkpoint_identity = ContentHash::from_canonical_material(
        "crucible.live-fault-hardware.restore.v1",
        &format!(
            "node={}\nicount={initial_icount}\nruntime={}",
            node_id.name,
            runtime_checkpoint.id().to_hex()
        ),
    );
    let mut checkpoint = Checkpoint::new(
        checkpoint_identity,
        checkpoint_identity,
        CheckpointKind::Fat,
    );
    checkpoint.virtual_time = VirtualTime {
        ticks: initial_icount,
    };
    checkpoint.node_icounts.insert(
        node_id.clone(),
        Icount {
            retired: initial_icount,
        },
    );
    let snapshot = nodes
        .capture_exact_snapshot(&node_id, checkpoint)
        .map_err(|error| format!("capture armed QEMU snapshot: {error}"))?;
    let mut captured = nodes
        .take(&node_id)
        .ok_or_else(|| String::from("captured live hardware node disappeared"))?;
    let terminated = captured
        .shutdown_child()
        .map_err(|error| format!("terminate captured QEMU process: {error}"))?;
    if !terminated.reaped || terminated.leaked {
        return Err(String::from("captured QEMU process was not reaped"));
    }
    drop(captured);
    fs::copy(
        capture_directory.join(DEFAULT_VMSTATE_FILE_NAME),
        restore_directory.join(DEFAULT_VMSTATE_FILE_NAME),
    )
    .map_err(|error| format!("copy captured VMState into fresh run directory: {error}"))?;

    let restore_config = config.clone().with_run_directory(&restore_directory);
    let restored = launch_qemu_live_node_exact_snapshot(
        &restore_config,
        &restore_directory,
        "fault-hardware-node",
        "fault-hardware-router",
        "fault-hardware-restore-crash-detector",
        &snapshot,
    )
    .map_err(|error| {
        format!(
            "launch fresh QEMU process from armed snapshot: {}",
            error_chain(&error)
        )
    })?;
    if nodes.insert(node_id.clone(), restored).is_some() {
        return Err(String::from(
            "restored live hardware node identity collided",
        ));
    }
    runtime = ProductionFaultRuntime::restore(
        plan,
        Some(artifacts),
        ContentHash::from_bytes(b"crucible.live-fault-hardware.v1"),
        runtime_checkpoint,
        HostFaultAdapterManifests::node_only()
            .map_err(|error| format!("build restored node-only fault manifests: {error}"))?,
        &mut nodes,
    )
    .map_err(|error| format!("restore armed fault runtime: {error}"))?;

    let mut console = Vec::new();
    let mut final_icount = initial_icount;
    collect_console(&mut nodes, &mut console)?;
    for step in 1..=MAX_STEPS {
        if contains(&console, b"CRUCIBLE_FAULT_HARDWARE_GUEST=PASS\n") {
            break;
        }
        let target_icount = initial_icount
            .checked_add(
                step.checked_mul(STEP_ICOUNT)
                    .ok_or_else(|| String::from("guest step span overflowed"))?,
            )
            .ok_or_else(|| String::from("guest step coordinate overflowed"))?;
        let advance = SimulationBackend::step_to(
            &mut nodes,
            VirtualTime {
                ticks: target_icount,
            },
        );
        let observation = match advance {
            Ok(observation) => observation,
            Err(error) => {
                let _ = collect_console(&mut nodes, &mut console);
                return Err(format!(
                    "advance live hardware guest: {error}; console follows:\n{}",
                    String::from_utf8_lossy(&console)
                ));
            }
        };
        final_icount = observation.reached.ticks;
        collect_console(&mut nodes, &mut console)?;
    }

    let final_evaluation = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 6,
                retired_instructions: Some(final_icount),
            },
            0,
            &mut nodes,
        )
        .map_err(|error| format!("authenticate hardware fault occurrences: {error}"))?;
    let clock_source_action_count = final_evaluation
        .actions
        .iter()
        .filter(|action| action.binding.as_str() == "guest-clock-source-degraded-binding")
        .count();
    let action_count = pre_workload_action_count
        .checked_add(final_evaluation.actions.len())
        .ok_or_else(|| String::from("hardware signal action count overflowed"))?;
    if action_count != 6 || final_evaluation.actions.len() != 1 || clock_source_action_count != 1 {
        return Err(format!(
            "post-workload clock-source boundary produced {} actions ({clock_source_action_count} clock-source) and {action_count} total instead of one and six",
            final_evaluation.actions.len()
        ));
    }
    let hardware_observations = boundary
        .observations
        .iter()
        .chain(accelerator_lifecycle_boundary.observations.iter())
        .chain(accelerator_memory_boundary.observations.iter())
        .chain(accelerator_service_boundary.observations.iter())
        .chain(final_evaluation.observations.iter());
    let clock_occurrences = hardware_observations
        .clone()
        .filter(|observation| {
            observation.kind == FaultObservationKind::EffectApplied
                && observation.opportunity.is_some()
                && observation
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.as_str() == "guest-clock-offset-binding")
        })
        .count();
    let accelerator_occurrences = hardware_observations
        .clone()
        .filter(|observation| {
            observation.kind == FaultObservationKind::EffectApplied
                && observation.opportunity.is_some()
                && observation
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.as_str() == "tpu-result-transform-binding")
        })
        .count();
    let clock_source_occurrences = hardware_observations
        .clone()
        .filter(|observation| {
            observation.kind == FaultObservationKind::EffectApplied
                && observation.opportunity.is_some()
                && observation.binding.as_ref().is_some_and(|binding| {
                    binding.as_str() == "guest-clock-source-degraded-binding"
                })
        })
        .count();
    let accelerator_lifecycle_occurrences = hardware_observations
        .clone()
        .filter(|observation| {
            observation.kind == FaultObservationKind::EffectApplied
                && observation.opportunity.is_some()
                && observation.binding.as_ref().is_some_and(|binding| {
                    binding.as_str() == "accelerator-lifecycle-reset-binding"
                })
        })
        .count();
    let accelerator_memory_occurrences = hardware_observations
        .clone()
        .filter(|observation| {
            observation.kind == FaultObservationKind::EffectApplied
                && observation.opportunity.is_some()
                && observation.binding.as_ref().is_some_and(|binding| {
                    binding.as_str() == "accelerator-memory-corrected-binding"
                })
        })
        .count();
    let accelerator_service_occurrences = hardware_observations
        .filter(|observation| {
            observation.kind == FaultObservationKind::EffectApplied
                && observation.opportunity.is_some()
                && observation.binding.as_ref().is_some_and(|binding| {
                    binding.as_str() == "accelerator-service-throttle-binding"
                })
        })
        .count();
    // `EffectCommitted` records only transaction acceptance. `EffectApplied`
    // reaches this list solely after the GPL bridge validates the QEMU clock
    // impulse's authenticated old-offset + requested-offset = new-offset
    // evidence and the accelerator's exact opportunity and job sequence.
    if clock_occurrences != 1
        || accelerator_occurrences != 1
        || clock_source_occurrences != 2
        || accelerator_lifecycle_occurrences != 1
        || accelerator_memory_occurrences != 1
        || accelerator_service_occurrences != 3
    {
        return Err(format!(
            "authenticated occurrence counts were clock={clock_occurrences}, accelerator-result={accelerator_occurrences}, clock-source={clock_source_occurrences}, accelerator-lifecycle={accelerator_lifecycle_occurrences}, accelerator-memory={accelerator_memory_occurrences}, accelerator-service={accelerator_service_occurrences}"
        ));
    }

    let output = String::from_utf8(console)
        .map_err(|error| format!("guest console was not UTF-8: {error}"))?;
    for required in [
        "CRUCIBLE_FAULT_HARDWARE_GUEST=READY",
        "CRUCIBLE_CLOCK_BEFORE counter=",
        "CRUCIBLE_ACCELERATOR_GPU status=0 length=8 values=4,6",
        "CRUCIBLE_ACCELERATOR_TPU status=0 length=4 value=43",
        "CRUCIBLE_ACCELERATOR_FPGA status=0 length=3 values=255,254,0",
        "CRUCIBLE_CLOCK_AFTER counter=",
        "CRUCIBLE_FAULT_HARDWARE_GUEST=PASS",
    ] {
        if !output.contains(required) {
            return Err(format!(
                "live hardware guest omitted `{required}`; console follows:\n{output}"
            ));
        }
    }

    let mut node = nodes
        .take(&node_id)
        .ok_or_else(|| String::from("live hardware node disappeared"))?;
    let shutdown = node
        .shutdown_child()
        .map_err(|error| format!("shut down live hardware guest: {error}"))?;
    if !shutdown.reaped || shutdown.leaked {
        return Err(String::from("live hardware QEMU child was not reaped"));
    }

    println!("PASS");
    println!("gate=gate:live-fault-hardware");
    println!("guest_clock_reads=architecture-counter,posix-monotonic,posix-realtime");
    println!("clock_effect_proof=authenticated-old-plus-offset-equals-new");
    println!("accelerator_transport=real-modern-virtio-pci");
    println!("accelerator_jobs=gpu-vector-add,tpu-matrix-multiply,fpga-lookup-table");
    println!("accelerator_mutation=tpu-result-42-to-43");
    println!("host_adapter=qemu-live-accelerator-servicer");
    println!("boundary_signal_actions={action_count}");
    println!("clock_signal_actions={clock_action_count}");
    println!("memory_signal_actions={memory_action_count}");
    println!("clock_source_signal_actions={clock_source_action_count}");
    println!("accelerator_lifecycle_signal_actions={accelerator_lifecycle_action_count}");
    println!("accelerator_memory_signal_actions={accelerator_memory_action_count}");
    println!("accelerator_service_signal_actions={accelerator_service_action_count}");
    println!("same_icount_fault_fingerprint_changed=true");
    println!("same_icount_ram_fingerprint_changed=true");
    println!("same_icount_fault_fingerprint_icount={initial_icount}");
    println!("accelerator_signal_actions={}", opportunity.actions.len());
    println!("clock_occurrences={clock_occurrences}");
    println!("accelerator_occurrences={accelerator_occurrences}");
    println!("clock_source_occurrences={clock_source_occurrences}");
    println!("accelerator_lifecycle_occurrences={accelerator_lifecycle_occurrences}");
    println!("accelerator_memory_occurrences={accelerator_memory_occurrences}");
    println!("accelerator_service_occurrences={accelerator_service_occurrences}");
    println!("fresh_plugin_restore=true");
    println!("orderly_child_exit=true");
    println!(
        "production_effect_row=clock.transform|offset-monotonic-overdue|gate:live-fault-hardware|production-qemu-signal-runtime|raw+transformed+timer-state"
    );
    println!(
        "production_effect_row=accelerator.result_transform|tpu-result-buffer-transform|gate:live-fault-hardware|production-qemu-signal-runtime|job-id+before-after-digest+guest-result"
    );
    println!(
        "production_effect_row=clock.source_state|degraded-step-synchronization|gate:live-fault-hardware|production-qemu-signal-runtime|old-new-source-state+timer-rearm"
    );
    println!(
        "production_effect_row=accelerator.lifecycle|reset-preserve-queues-and-memory|gate:live-fault-hardware|production-qemu-signal-runtime|enumeration+reset-generation+memory-digest"
    );
    println!(
        "production_effect_row=accelerator.memory_event|corrected-device-memory-ecc|gate:live-fault-hardware|production-qemu-signal-runtime|range+syndrome+corrected-counter+guest-results"
    );
    println!(
        "production_effect_row=accelerator.service|half-capacity-thermal-power|gate:live-fault-hardware|production-qemu-signal-runtime|three-job-service-ledger+thermal-power"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-fault-hardware requires Linux");
}
