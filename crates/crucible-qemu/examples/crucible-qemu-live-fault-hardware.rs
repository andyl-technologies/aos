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
use std::error::Error;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use crucible::model::{
    AcceleratorJobSelector, AcceleratorResultMutation, BindingEventParent, BindingMapping,
    BindingObservabilityPolicy, BindingSampling, BindingSearchPolicy, ByteRange,
    ClockMonotonicityPolicy, ClockMutation, ClockOverdueTimerPolicy, ContentHash,
    EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest, EffectSpecification, FaultAdapter,
    FaultBinding, FaultCoordinate, FaultObjectId, FaultObservationKind, FaultOperation,
    FaultOpportunity, FaultPhase, FaultResourceLimits, FaultSignalPlan, FaultTargetKind, HexBytes,
    HostFaultAdapterManifests, MemoryAddressSpace, MemoryMutationAtomicity, MemoryMutationKind,
    NodeEffectSpecification, NodeOccurrencePolicy, OperationSet, OpportunityFilter,
    OpportunityPayload, ResolvedFaultTarget, ResolvedTargetSet, SignalBoundarySnapshot,
    SignalCoordinate, SignalDomain, SignalId, SignalNode, SignalNodeKind, SignalPoint,
    SignalProgram, SignalResourceLimits, SignalShape, SignalSourceSpecification, SignalUnit,
    SignalValue, SignalValueType, TargetSelector,
};
#[cfg(target_os = "linux")]
use crucible::{
    Checkpoint, CheckpointKind, Icount, NodeId, ObservableEventPayload, SimulationBackend,
    VirtualTime,
};
#[cfg(target_os = "linux")]
use crucible_qemu::{
    DEFAULT_VMSTATE_FILE_NAME, ProductionFaultRuntime, QemuLaunchPluginSwitch,
    QemuLiveNodeStepGateConfig, QemuNodeSet, launch_qemu_live_node,
    launch_qemu_live_node_exact_snapshot,
};

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
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-live-fault-hardware: {error}");
            ExitCode::FAILURE
        }
    }
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
    if boundary.actions.len() != 2 {
        return Err(format!(
            "same-coordinate hardware signal boundary produced {} actions instead of two",
            boundary.actions.len()
        ));
    }
    let clock_action_count = boundary
        .actions
        .iter()
        .filter(|action| action.binding.as_str() == "guest-clock-offset-binding")
        .count();
    let memory_action_count = boundary
        .actions
        .iter()
        .filter(|action| action.binding.as_str() == "fingerprint-memory-binding")
        .count();
    if clock_action_count != 1 || memory_action_count != 1 {
        return Err(format!(
            "same-coordinate hardware actions were clock={clock_action_count}, memory={memory_action_count}"
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
        fault_coordinate,
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
    collect_console(&mut nodes, &mut console)?;
    for step in 1..=MAX_STEPS {
        if contains(&console, b"CRUCIBLE_FAULT_HARDWARE_GUEST=PASS\n") {
            break;
        }
        let advance = SimulationBackend::step_to(
            &mut nodes,
            VirtualTime {
                ticks: initial_icount
                    .checked_add(
                        step.checked_mul(STEP_ICOUNT)
                            .ok_or_else(|| String::from("guest step span overflowed"))?,
                    )
                    .ok_or_else(|| String::from("guest step coordinate overflowed"))?,
            },
        );
        if let Err(error) = advance {
            let _ = collect_console(&mut nodes, &mut console);
            return Err(format!(
                "advance live hardware guest: {error}; console follows:\n{}",
                String::from_utf8_lossy(&console)
            ));
        }
        collect_console(&mut nodes, &mut console)?;
    }

    let final_icount = initial_icount
        .checked_add(
            MAX_STEPS
                .checked_mul(STEP_ICOUNT)
                .ok_or_else(|| String::from("final live hardware guest coordinate overflowed"))?,
        )
        .ok_or_else(|| String::from("final live hardware guest coordinate overflowed"))?;
    let final_evaluation = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 2,
                retired_instructions: Some(final_icount),
            },
            0,
            &mut nodes,
        )
        .map_err(|error| format!("authenticate hardware fault occurrences: {error}"))?;
    let hardware_observations = boundary
        .observations
        .iter()
        .chain(final_evaluation.observations.iter());
    let clock_occurrences = hardware_observations
        .clone()
        .filter(|observation| {
            observation.kind == FaultObservationKind::EffectApplied
                && observation
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.as_str() == "guest-clock-offset-binding")
        })
        .count();
    let accelerator_occurrences = hardware_observations
        .filter(|observation| {
            observation.kind == FaultObservationKind::EffectApplied
                && observation
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.as_str() == "tpu-result-transform-binding")
        })
        .count();
    // `EffectCommitted` records only transaction acceptance. `EffectApplied`
    // reaches this list solely after the GPL bridge validates the QEMU clock
    // impulse's authenticated old-offset + requested-offset = new-offset
    // evidence and the accelerator's exact opportunity and job sequence.
    if clock_occurrences != 1 || accelerator_occurrences != 1 {
        return Err(format!(
            "authenticated occurrence counts were clock={clock_occurrences}, accelerator={accelerator_occurrences}"
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
    println!("boundary_signal_actions={}", boundary.actions.len());
    println!("clock_signal_actions={clock_action_count}");
    println!("memory_signal_actions={memory_action_count}");
    println!("same_icount_fault_fingerprint_changed=true");
    println!("same_icount_ram_fingerprint_changed=true");
    println!("same_icount_fault_fingerprint_icount={initial_icount}");
    println!("accelerator_signal_actions={}", opportunity.actions.len());
    println!("clock_occurrences={clock_occurrences}");
    println!("accelerator_occurrences={accelerator_occurrences}");
    println!("fresh_plugin_restore=true");
    println!("orderly_child_exit=true");
    Ok(())
}

#[cfg(target_os = "linux")]
fn fault_hardware_plan() -> Result<FaultSignalPlan, String> {
    let clock_output = signal_id("guest-clock-offset")?;
    let clock_event_schema = signal_id("guest-clock-offset-event")?;
    let accelerator_output = signal_id("tpu-result-hazard")?;
    let clock_program = SignalProgram::new(
        vec![
            SignalNode {
                id: clock_output.clone(),
                domain: SignalDomain::Event,
                output: SignalShape::new(
                    SignalValueType::Event(clock_event_schema.clone()),
                    SignalUnit::Dimensionless,
                    0,
                )
                .map_err(|error| format!("clock activation shape: {error}"))?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                    events: vec![SignalPoint {
                        coordinate: SignalCoordinate::Event {
                            parent: Box::new(SignalCoordinate::VirtualTime { nanos: 1 }),
                            sequence: 0,
                        },
                        sequence: 0,
                        value: SignalValue::Event {
                            schema: clock_event_schema,
                            payload: Vec::new(),
                        },
                    }],
                }),
            },
            SignalNode {
                id: accelerator_output.clone(),
                domain: SignalDomain::VirtualTime,
                output: SignalShape::new(
                    SignalValueType::ProbabilityMillionths,
                    SignalUnit::ProbabilityMillionths,
                    0,
                )
                .map_err(|error| format!("accelerator hazard shape: {error}"))?,
                inputs: Vec::new(),
                kind: SignalNodeKind::Constant {
                    value: SignalValue::ProbabilityMillionths(1_000_000),
                },
            },
        ],
        vec![clock_output.clone(), accelerator_output.clone()],
        SignalResourceLimits::default(),
    )
    .map_err(|error| format!("clock signal program: {error}"))?;
    let clock_target = ResolvedFaultTarget::ClockSource {
        node: object_id("fault-hardware-node")?,
        source: object_id("x86-tsc-vcpu-0")?,
    };
    let clock_binding = FaultBinding::new(
        object_id("guest-clock-offset-binding")?,
        vec![clock_output.clone()],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(target_set(clock_target)?),
        [FaultPhase::ClockRead].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::ClockTransform {
                source: object_id("x86-tsc-vcpu-0")?,
                mutation: ClockMutation::Offset {
                    offset_nanos: 1_000_000_000,
                },
                monotonicity: ClockMonotonicityPolicy::ClampMonotonic,
                overdue_timer_policy: ClockOverdueTimerPolicy::FireAtBoundary,
            }),
        )
        .map_err(|error| format!("clock effect: {error}"))?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
    )
    .map_err(|error| format!("clock binding: {error}"))?;

    // 0x9ffff is the last writable conventional-RAM byte below the PC ROM
    // aperture. Linux has completed firmware handoff before this boundary, so
    // flipping one bit is inert to the workload while necessarily changing the
    // execution fingerprint's writable-RAM digest.
    let memory_range =
        ByteRange::new(0x9ffff, 1).map_err(|error| format!("fingerprint memory range: {error}"))?;
    let memory_binding = FaultBinding::new(
        object_id("fingerprint-memory-binding")?,
        vec![clock_output],
        BindingSampling::AtEvent(BindingEventParent::VirtualTime),
        BindingMapping::ImpulseOnEvent,
        TargetSelector::Exact(target_set(ResolvedFaultTarget::MemoryRange {
            node: object_id("fault-hardware-node")?,
            address_space: object_id("gpa")?,
            guest_address: memory_range.start(),
            vcpu: None,
            length_bytes: memory_range.length(),
        })?),
        [FaultPhase::Boundary].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            EffectSpecification::Node(NodeEffectSpecification::MemoryMutation {
                address_space: MemoryAddressSpace::GuestPhysical,
                range: memory_range,
                mutation: MemoryMutationKind::BitFlip {
                    mask: HexBytes::parse("01", 1)
                        .map_err(|error| format!("fingerprint memory mask: {error}"))?,
                },
                atomicity: MemoryMutationAtomicity::AllOrNothing,
            }),
        )
        .map_err(|error| format!("fingerprint memory effect: {error}"))?,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
    )
    .map_err(|error| format!("fingerprint memory binding: {error}"))?;

    let accelerator_binding = FaultBinding::new(
        object_id("tpu-result-transform-binding")?,
        vec![accelerator_output],
        BindingSampling::AtOpportunity,
        BindingMapping::Hazard,
        TargetSelector::Exact(target_set(accelerator_target()?)?),
        [FaultPhase::Complete].into_iter().collect(),
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Opportunity,
            EffectSpecification::Node(NodeEffectSpecification::AcceleratorResultTransform {
                job_selector: AcceleratorJobSelector {
                    job_kind: object_id("matrix-multiply")?,
                    queue: Some(0),
                    occurrence: NodeOccurrencePolicy::Every,
                },
                transform: AcceleratorResultMutation {
                    offset: 0,
                    mask: HexBytes::parse("ff", 1)
                        .map_err(|error| format!("accelerator mask: {error}"))?,
                    value: HexBytes::parse("2b", 1)
                        .map_err(|error| format!("accelerator value: {error}"))?,
                },
            }),
        )
        .map_err(|error| format!("accelerator effect: {error}"))?,
        Some(OpportunityFilter {
            adapter: FaultAdapter::Node,
            operations: OperationSet::new(vec![FaultOperation::AcceleratorComplete])
                .map_err(|error| format!("accelerator operations: {error}"))?,
            phases: [FaultPhase::Complete].into_iter().collect(),
            target_kinds: [FaultTargetKind::Accelerator].into_iter().collect(),
        }),
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy::default(),
        &clock_program,
    )
    .map_err(|error| format!("accelerator binding: {error}"))?;

    FaultSignalPlan::new(
        vec![clock_program],
        vec![clock_binding, memory_binding, accelerator_binding],
        FaultResourceLimits::default(),
    )
    .map_err(|error| format!("fault hardware plan: {error}"))
}

#[cfg(target_os = "linux")]
fn accelerator_target() -> Result<ResolvedFaultTarget, String> {
    Ok(ResolvedFaultTarget::Accelerator {
        node: object_id("fault-hardware-node")?,
        device: object_id("accelerator-0")?,
    })
}

#[cfg(target_os = "linux")]
fn target_set(target: ResolvedFaultTarget) -> Result<ResolvedTargetSet, String> {
    ResolvedTargetSet::new(vec![target], false).map_err(|error| format!("fault target: {error}"))
}

#[cfg(target_os = "linux")]
fn signal_id(value: &str) -> Result<SignalId, String> {
    SignalId::parse(value).map_err(|error| format!("signal ID `{value}`: {error}"))
}

#[cfg(target_os = "linux")]
fn object_id(value: &str) -> Result<FaultObjectId, String> {
    FaultObjectId::parse(value).map_err(|error| format!("object ID `{value}`: {error}"))
}

#[cfg(target_os = "linux")]
fn collect_console(nodes: &mut QemuNodeSet, output: &mut Vec<u8>) -> Result<(), String> {
    let events = SimulationBackend::drain_observable_events(nodes)
        .map_err(|error| format!("drain live guest observations: {error}"))?;
    for event in events {
        if let ObservableEventPayload::ConsoleOutput { bytes, .. } = event.payload() {
            output.extend_from_slice(bytes);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(target_os = "linux")]
fn required_arg(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    program: &str,
) -> Result<std::ffi::OsString, String> {
    args.next().ok_or_else(|| usage(program))
}

#[cfg(target_os = "linux")]
fn usage(program: &str) -> String {
    format!("usage: {program} QEMU PLUGIN KERNEL FIRMWARE INITRD RUN_DIRECTORY")
}

#[cfg(target_os = "linux")]
fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(current) = source {
        message.push_str(": ");
        message.push_str(&current.to_string());
        source = current.source();
    }
    message
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("crucible-qemu-live-fault-hardware requires Linux");
}
