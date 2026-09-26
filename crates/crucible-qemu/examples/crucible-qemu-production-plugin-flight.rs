//! Exercises the loaded Rust plugin through the guarded production node boundary.
//!
//! The flight launches the same four-vCPU diskless guest under reference and
//! host-preempted conditions. It requests fingerprints at exact scheduler
//! boundaries, applies typed scheduler preemptions, and crosses an all-vCPU
//! idle timer wake. A separate real block recovery subflight proves the causal
//! recovery transition, exact settled write, and hot-fork preparation.
//! Successful runs emit only typed shared-memory and node-level evidence.
//! Native traces are retained only after clean reap.
//! Setting `CRUCIBLE_PRODUCTION_PLUGIN_FLIGHT_BLOCK_RECOVERY_ONLY=1` runs the
//! block-recovery subflight alone for focused failure diagnosis.
//!
//! ```text
//! crucible-qemu-production-plugin-flight QEMU PLUGIN KERNEL IDLE_INITRD BLOCK_INITRD FIRMWARE CGROUP_ROOT RUN_ROOT REFERENCE_TRACE_OUT
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, BackendEffect, ExecutionFingerprint, Icount, IrqVector, NodeId,
    ObservableEvent, ObservableEventPayload, PreemptionDecision, PreemptionKind, SimulationBackend,
    VcpuId, VirtualTime,
};
use crucible_protocol::selectable_catalog_plan::{
    SELECTABLE_NATIVE_HANDOFF_INSTRUCTIONS, SelectableCatalogPlan, SelectablePlanContinuation,
    SelectablePlanDeclaration, SelectablePlanLimits, SelectablePlanPresence,
};
use crucible_protocol::{SelectionReply, SelectionReplyStatus};
use crucible_qemu::{
    BoundedSchedulerPreemptionEvidence, LinuxQemuAttemptHostConfig, LinuxQemuAttemptHostFactory,
    QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig, QemuLogicalTimeCalibration, QemuNode,
    QemuNodeIdleState, QemuProductionFreshLaunchAdmission, QemuRuntimeDeterminismTraceRecord,
    QemuShutdownReport, QemuVirtualTimerFireWitness, QmpHotForkTemplateOutcome,
    launch_qemu_production_fresh_node, parse_qemu_runtime_determinism_trace,
};
use crucible_shmem::FingerprintSample;

#[path = "crucible-qemu-production-plugin-flight/block_recovery_hot_fork.rs"]
mod block_recovery_hot_fork;

const MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const DISK_BYTES: u64 = 1024 * 1024 * 1024;
const RR_SWITCH_QUANTUM: u64 = 4096;
const FLIGHT_TICKS_PER_INSTRUCTION: u64 = crucible::SIM_TICKS_PER_INSTRUCTION;
const TARGETS: [u64; 4] = [2_000_000, 2_000_001, 4_000_000, 8_000_000];
const INSTRUCTION_EXACT_LOWER_TARGET: u64 = 2_000_000;
const INSTRUCTION_EXACT_UPPER_TARGET: u64 = INSTRUCTION_EXACT_LOWER_TARGET + 1;
// The selectable request is the authenticated readiness boundary. Give QEMU's
// signed virtual-picosecond API its full positive domain so a machine-specific
// boot instruction count cannot become a second readiness condition; the
// production host supervision deadline remains the fail-closed liveness bound.
const READINESS_ADMISSION_CEILING: u64 = i64::MAX.unsigned_abs();
const READINESS_SELECTABLE_ID: &str = "flight.ready";
const READINESS_INSTANCE_KEY: &str = "boot";
const READINESS_REQUEST_SEQUENCE: u64 = 2;
const READINESS_VCPU_INDEX: u32 = 0;
const READINESS_REPLY_CAPACITY: usize = 128;
const FLIGHT_NODE_ID: &str = "plugin-flight-node";
const SETUP_COMPLETE_MARKER: &str = "lifecycle.setup_complete";
const MAXIMUM_HOT_FORK_RING_IMAGE_BYTES: usize = 64 * 1024 * 1024;
const BLOCK_RECOVERY_ONLY_ENVIRONMENT: &str =
    "CRUCIBLE_PRODUCTION_PLUGIN_FLIGHT_BLOCK_RECOVERY_ONLY";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-qemu-production-plugin-flight: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let [
        qemu,
        plugin,
        kernel,
        idle_initrd,
        block_initrd,
        firmware,
        cgroup_root,
        run_root,
        reference_trace_output,
    ] = arguments.as_slice()
    else {
        return Err(
            "expected QEMU PLUGIN KERNEL IDLE_INITRD BLOCK_INITRD FIRMWARE CGROUP_ROOT RUN_ROOT REFERENCE_TRACE_OUT".into(),
        );
    };
    let host = LinuxQemuAttemptHostConfig::new(
        cgroup_root,
        run_root,
        "production-plugin-flight",
        21000,
        1,
        65534,
        65534,
        64,
        RR_SWITCH_QUANTUM,
        Duration::from_secs(30),
    )?;
    let mut factory = LinuxQemuAttemptHostFactory::open(host)?;
    if block_recovery_only_requested()? {
        let evidence = block_recovery_hot_fork::run(
            &mut factory,
            qemu,
            plugin,
            kernel,
            block_initrd,
            firmware,
            run_root,
            true,
        )?;

        println!("PASS");
        println!("diagnostic_mode=block-recovery-only");
        print_block_recovery_evidence(evidence);
        return Ok(());
    }

    let selectable_catalog_plan = readiness_selectable_catalog_plan()?;
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_initrd(idle_initrd)
        .with_vm_shape(128, 4)
        .with_rr_switch_quantum(RR_SWITCH_QUANTUM)
        .with_whitebox(crucible_qemu::QemuLaunchPluginSwitch::On)
        .with_selectable_catalog_plan(selectable_catalog_plan)
        .with_fingerprint(crucible_qemu::QemuLaunchPluginSwitch::On)
        // Full hot-fork preparation stages a connected child console.
        .with_console_capture()
        .with_runtime_determinism_trace()
        .with_completion_timeout(Duration::from_secs(60));

    let reference = run_once(&mut factory, &config, qemu, false)?;
    let hostile = run_once(&mut factory, &config, qemu, true)?;
    fs::write(reference_trace_output, &reference.diagnostics.trace)?;
    compare_boundaries(
        "host-preempted restart",
        &reference.boundaries,
        &hostile.boundaries,
    )?;
    let instruction_exact = &reference.instruction_exact;
    if instruction_exact != &hostile.instruction_exact {
        return Err("instruction-exact evidence changed across flight variants".into());
    }
    if !idle_evidence_matches_across_runs(&reference.idle, &hostile.idle) {
        let localization = compare_runtime_determinism_diagnostics([
            ("reference", &reference.diagnostics),
            ("hostile", &hostile.diagnostics),
        ]);
        return Err(format!(
            "loaded-plugin idle/wake evidence changed across flight variants: \
             reference={:?}; hostile={:?}; \
             runtime_determinism_localization={localization}",
            reference.idle, hostile.idle,
        )
        .into());
    }
    if !reference.shutdown.reaped || reference.shutdown.leaked {
        return Err("reference QEMU did not shut down cleanly".into());
    }
    if !hostile.shutdown.reaped || hostile.shutdown.leaked {
        return Err("hostile QEMU did not shut down cleanly".into());
    }
    let production_variants = [&reference, &hostile];
    let on_demand_acknowledgements = production_variants
        .iter()
        .map(|run| run.on_demand_acknowledgements)
        .sum::<usize>();
    let expected_acknowledgements = production_variants.len() * (TARGETS.len() + 2);
    if on_demand_acknowledgements != expected_acknowledgements {
        return Err(format!(
            "production variants authenticated {on_demand_acknowledgements} on-demand fingerprint acknowledgements instead of {expected_acknowledgements}"
        )
        .into());
    }

    let block_recovery_hot_fork = block_recovery_hot_fork::run(
        &mut factory,
        qemu,
        plugin,
        kernel,
        block_initrd,
        firmware,
        run_root,
        false,
    )?;

    println!("PASS");
    println!("gate=gate:production-rust-plugin-flight");
    println!("rust_plugin_loaded=true");
    println!("diskless_multiboot_runs={}", production_variants.len());
    println!("fingerprint_flight_variants=reference,host-preempted");
    println!("vcpu_count=4");
    println!("rr_switch_quantum={RR_SWITCH_QUANTUM}");
    println!("sample_count={}", reference.boundaries.len());
    println!("sample_target_icounts=2000000,2000001,4000000,8000000");
    println!("sample_stream_restart_identical=true");
    println!("on_demand_worker_acknowledgements={on_demand_acknowledgements}");
    println!("on_demand_boundary_stream_bit_identical=true");
    println!(
        "instruction_exact_window_lower_icount={}",
        instruction_exact.lower_target
    );
    println!(
        "instruction_exact_window_upper_icount={}",
        instruction_exact.upper_target
    );
    println!("instruction_exact_window_width=1");
    println!(
        "instruction_exact_lower_rr_vcpu={}",
        instruction_exact.lower_rr_vcpu
    );
    println!(
        "instruction_exact_upper_rr_vcpu={}",
        instruction_exact.upper_rr_vcpu
    );
    println!(
        "instruction_exact_lower_rr_position={}",
        instruction_exact.lower_rr_position
    );
    println!(
        "instruction_exact_upper_rr_position={}",
        instruction_exact.upper_rr_position
    );
    println!("instruction_exact_rr_successor=true");
    println!(
        "instruction_exact_changed_components={}",
        instruction_exact.changed_components.join(",")
    );
    println!(
        "instruction_exact_first_differing_state_component={}",
        instruction_exact.first_differing_state_component
    );
    println!(
        "instruction_exact_owning_vcpu_state_projection={}",
        instruction_exact.owning_vcpu_state_projection
    );
    println!("instruction_exact_state_projection_changed=true");
    println!("instruction_exact_fingerprint_changed=true");
    println!("instruction_exact_localization=one-instruction-window");
    println!("bounded_scheduler_preemption_applied=true");
    println!("pending_quantum_preemption_certified=true");
    println!("scheduler_preemption_mailbox_decisions=2");
    println!("scheduler_vcpu_switch_applied=true");
    println!("scheduler_interrupt_applied=true");
    println!("readiness_setup_marker_authenticated=true");
    println!(
        "readiness_setup_marker_icount={}",
        reference.idle.setup_marker_icount
    );
    println!("all_vcpus_halted_observed=true");
    println!("exact_timer_deadline_observed=true");
    println!("queued_idle_wake_reached_exact_deadline=true");
    println!("actual_virtual_timer_fire_authenticated=true");
    println!(
        "timer_witness_generation={}",
        reference.idle.timer_fire.generation
    );
    println!(
        "timer_witness_armed_deadline_ps={}",
        reference.idle.timer_fire.armed_deadline_ps
    );
    println!(
        "timer_witness_armed_deadline_tick={}",
        reference.idle.timer_fire.armed_deadline_tick
    );
    println!("timer_witness_ticks_per_instruction={FLIGHT_TICKS_PER_INSTRUCTION}");
    println!(
        "timer_witness_retirement_step_ps={}",
        reference.idle.timer_fire.retirement_step_ps
    );
    println!(
        "timer_witness_armed_raw_icount={}",
        reference.idle.timer_fire.armed_raw_icount
    );
    println!(
        "timer_witness_fired_expire_ps={}",
        reference.idle.timer_fire.fired_expire_ps
    );
    println!(
        "timer_witness_fired_virtual_ps={}",
        reference.idle.timer_fire.fired_virtual_ps
    );
    println!(
        "timer_witness_fired_raw_icount={}",
        reference.idle.timer_fire.fired_raw_icount
    );
    println!(
        "timer_witness_published_wake_tick={}",
        reference.idle.timer_fire.published_wake_tick
    );
    println!(
        "timer_witness_post_wake_tick={}",
        reference.idle.timer_fire.post_wake_tick
    );
    println!(
        "timer_witness_completed={}",
        reference.idle.timer_fire.completed
    );
    println!(
        "timer_witness_reserved={}",
        reference.idle.timer_fire.reserved
    );
    println!("idle_wake_stream_restart_identical=true");
    print_block_recovery_evidence(block_recovery_hot_fork);
    println!("component_failures=0");
    println!("per_vcpu_register_files_present=true");
    println!("aggregate_icount_equals_target=true");
    Ok(())
}

fn block_recovery_only_requested() -> Result<bool, Box<dyn Error>> {
    let value = std::env::var_os(BLOCK_RECOVERY_ONLY_ENVIRONMENT);
    parse_block_recovery_only(value.as_deref())
}

fn parse_block_recovery_only(value: Option<&std::ffi::OsStr>) -> Result<bool, Box<dyn Error>> {
    match value {
        None => Ok(false),
        Some(value) if value == "1" => Ok(true),
        Some(value) => Err(format!(
            "{BLOCK_RECOVERY_ONLY_ENVIRONMENT} must be unset or exactly 1, got {value:?}"
        )
        .into()),
    }
}

fn print_block_recovery_evidence(hot_fork: block_recovery_hot_fork::BlockRecoveryHotForkEvidence) {
    println!("block_recovery_hot_fork_subflight=true");
    println!(
        "block_recovery_start_tick={}",
        hot_fork.recovery_started_tick
    );
    println!("block_recovery_nanos={}", hot_fork.recovery_nanos);
    println!("block_recovery_write_completed=true");
    println!(
        "block_recovery_pause_logical_icount={}",
        hot_fork.pause_logical_icount
    );
    println!(
        "block_recovery_pause_raw_icount={}",
        hot_fork.pause_raw_icount
    );
    println!(
        "hot_fork_template_generation={}",
        hot_fork.template_generation
    );
    println!("hot_fork_template_draining=true");
    println!("hot_fork_template_prepared=true");
    println!("hot_fork_preparation_order=block-recovery-settled,draining,prepared");
}

struct FlightRun {
    boundaries: Vec<BoundaryEvidence>,
    instruction_exact: InstructionExactEvidence,
    idle: IdleEvidence,
    on_demand_acknowledgements: usize,
    shutdown: QemuShutdownReport,
    diagnostics: RuntimeDeterminismDiagnostics,
}

#[derive(Debug)]
struct RuntimeDeterminismDiagnostics {
    baseline: RuntimeDeterminismBaseline,
    trace: String,
}

#[derive(Debug)]
struct RuntimeDeterminismBaseline {
    calibration: Result<QemuLogicalTimeCalibration, String>,
    idle_state: Result<QemuNodeIdleState, String>,
    timer_witness: Result<Option<QemuVirtualTimerFireWitness>, String>,
    rr_current_vcpu: u32,
    rr_position_in_quantum: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundaryEvidence {
    target: u64,
    outcome: AdvanceOutcome,
    fingerprint: ExecutionFingerprint,
    sample: FingerprintSample,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InstructionExactEvidence {
    lower_target: u64,
    upper_target: u64,
    lower_rr_vcpu: u32,
    upper_rr_vcpu: u32,
    lower_rr_position: u64,
    upper_rr_position: u64,
    first_differing_state_component: String,
    owning_vcpu_state_projection: String,
    changed_components: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IdleEvidence {
    setup_marker_icount: u64,
    halted_at: u64,
    deadline: u64,
    halted_fingerprint: ExecutionFingerprint,
    halted_sample: FingerprintSample,
    wake_outcome: AdvanceOutcome,
    wake_fingerprint: ExecutionFingerprint,
    wake_sample: FingerprintSample,
    timer_fire: VirtualTimerFireEvidence,
    on_demand_acknowledgements: usize,
}

/// Numeric certificate for the plugin-validated native timer callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VirtualTimerFireEvidence {
    generation: u64,
    armed_deadline_ps: u64,
    armed_deadline_tick: u64,
    retirement_step_ps: u64,
    armed_raw_icount: u64,
    fired_expire_ps: u64,
    fired_virtual_ps: u64,
    fired_raw_icount: u64,
    published_wake_tick: u64,
    post_wake_tick: u64,
    completed: u32,
    reserved: u32,
}

fn idle_evidence_matches_across_runs(reference: &IdleEvidence, candidate: &IdleEvidence) -> bool {
    let mut normalized_reference = reference.clone();

    // Generation identifies one process-local publication, not guest state.
    normalized_reference.timer_fire.generation = candidate.timer_fire.generation;
    normalized_reference == *candidate
}

fn compare_boundaries(
    variant: &str,
    reference: &[BoundaryEvidence],
    candidate: &[BoundaryEvidence],
) -> Result<(), String> {
    if reference.len() != candidate.len() {
        return Err(format!(
            "{variant}: boundary count differs: {} != {}",
            reference.len(),
            candidate.len()
        ));
    }
    for (index, (left, right)) in reference.iter().zip(candidate).enumerate() {
        let lower_bound = index
            .checked_sub(1)
            .and_then(|previous| reference.get(previous))
            .map_or(0, |boundary| boundary.target);
        if left.target != right.target {
            return Err(format!(
                "{variant}: boundary {index} window ({lower_bound},{}]: target differs",
                left.target
            ));
        }
        if left.outcome != right.outcome {
            return Err(format!(
                "{variant}: boundary {index} window ({lower_bound},{}]: outcome differs",
                left.target
            ));
        }
        if left.fingerprint != right.fingerprint {
            return Err(format!(
                "{variant}: boundary {index} window ({lower_bound},{}]: execution_fingerprint differs",
                left.target
            ));
        }
        if let Some(component) = first_sample_difference(&left.sample, &right.sample) {
            return Err(format!(
                "{variant}: boundary {index} window ({lower_bound},{}]: {component} differs",
                left.target
            ));
        }
    }
    Ok(())
}

fn instruction_exact_evidence(
    boundaries: &[BoundaryEvidence],
) -> Result<InstructionExactEvidence, String> {
    let lower = boundaries
        .iter()
        .find(|boundary| boundary.target == INSTRUCTION_EXACT_LOWER_TARGET)
        .ok_or_else(|| String::from("instruction-exact lower boundary is absent"))?;
    let upper = boundaries
        .iter()
        .find(|boundary| boundary.target == INSTRUCTION_EXACT_UPPER_TARGET)
        .ok_or_else(|| String::from("instruction-exact upper boundary is absent"))?;

    if upper.target != lower.target + 1
        || lower.sample.sample_icount != lower.target
        || upper.sample.sample_icount != upper.target
    {
        return Err(format!(
            "instruction-exact samples do not bind adjacent requested coordinates: lower={lower:?}, upper={upper:?}"
        ));
    }
    if lower.sample.rr_switch_quantum != RR_SWITCH_QUANTUM
        || upper.sample.rr_switch_quantum != RR_SWITCH_QUANTUM
        || !is_exact_rr_successor(&lower.sample, &upper.sample)
    {
        return Err(format!(
            "instruction-exact samples do not describe one exact RR successor: lower={lower:?}, upper={upper:?}"
        ));
    }
    if lower.fingerprint == upper.fingerprint {
        return Err(
            "adjacent instruction coordinates produced the same execution fingerprint".into(),
        );
    }
    let changed_components = sample_differences(&lower.sample, &upper.sample);
    let first_differing_state_component = changed_components
        .iter()
        .find(|component| {
            !matches!(
                component.as_str(),
                "sample_icount" | "rr_current_vcpu" | "rr_position_in_quantum"
            )
        })
        .cloned()
        .ok_or_else(|| {
            String::from("adjacent instruction samples have no differing state component")
        })?;
    let owner_index = usize::try_from(lower.sample.rr_current_vcpu)
        .map_err(|_| String::from("instruction-exact owner index does not fit usize"))?;
    let expected_register_projection =
        format!("vcpu[{}].register_digest", lower.sample.rr_current_vcpu);
    let lower_owner = lower
        .sample
        .vcpus
        .get(owner_index)
        .ok_or_else(|| format!("instruction-exact owner vCPU {owner_index} is absent"))?;
    let upper_owner = upper
        .sample
        .vcpus
        .get(owner_index)
        .ok_or_else(|| format!("instruction-exact owner vCPU {owner_index} is absent"))?;
    if lower_owner.register_digest == upper_owner.register_digest {
        return Err(format!(
            "adjacent instruction samples did not change the owning {expected_register_projection}"
        ));
    }
    validate_instruction_exact_shape_stability(&lower.sample, &upper.sample, owner_index)?;
    let owning_vcpu_state_projection = expected_register_projection;

    Ok(InstructionExactEvidence {
        lower_target: lower.target,
        upper_target: upper.target,
        lower_rr_vcpu: lower.sample.rr_current_vcpu,
        upper_rr_vcpu: upper.sample.rr_current_vcpu,
        lower_rr_position: lower.sample.rr_position_in_quantum,
        upper_rr_position: upper.sample.rr_position_in_quantum,
        first_differing_state_component,
        owning_vcpu_state_projection,
        changed_components,
    })
}

fn validate_instruction_exact_shape_stability(
    lower: &FingerprintSample,
    upper: &FingerprintSample,
    owner_index: usize,
) -> Result<(), String> {
    if lower.vcpu_count != upper.vcpu_count
        || lower.component_failures != upper.component_failures
        || lower.ram_bytes != upper.ram_bytes
        || lower.ram_digest != upper.ram_digest
        || lower.device_state_bytes != upper.device_state_bytes
        || lower.device_state_sections != upper.device_state_sections
        || lower.device_state_schema_digest != upper.device_state_schema_digest
    {
        return Err(String::from(
            "adjacent instruction samples changed invariant fingerprint shape or RAM state",
        ));
    }

    for (index, (lower_vcpu, upper_vcpu)) in lower.vcpus.iter().zip(&upper.vcpus).enumerate() {
        if lower_vcpu.register_file_bytes != upper_vcpu.register_file_bytes
            || lower_vcpu.retired_instruction_count != upper_vcpu.retired_instruction_count
            || (index != owner_index && lower_vcpu.register_digest != upper_vcpu.register_digest)
        {
            return Err(format!(
                "adjacent instruction samples changed invariant vCPU {index} state"
            ));
        }
    }
    Ok(())
}

fn is_exact_rr_successor(lower: &FingerprintSample, upper: &FingerprintSample) -> bool {
    let quantum = lower.rr_switch_quantum;
    if quantum == 0
        || upper.rr_switch_quantum != quantum
        || lower.vcpu_count == 0
        || upper.vcpu_count != lower.vcpu_count
        || lower.rr_current_vcpu >= lower.vcpu_count
        || upper.rr_current_vcpu >= upper.vcpu_count
        || lower.rr_position_in_quantum >= quantum
        || upper.rr_position_in_quantum >= quantum
    {
        return false;
    }

    if lower.rr_position_in_quantum + 1 < quantum {
        upper.rr_current_vcpu == lower.rr_current_vcpu
            && upper.rr_position_in_quantum == lower.rr_position_in_quantum + 1
    } else {
        upper.rr_current_vcpu == (lower.rr_current_vcpu + 1) % lower.vcpu_count
            && upper.rr_position_in_quantum == 0
    }
}

fn first_sample_difference(left: &FingerprintSample, right: &FingerprintSample) -> Option<String> {
    sample_differences(left, right).into_iter().next()
}

fn sample_differences(left: &FingerprintSample, right: &FingerprintSample) -> Vec<String> {
    let scalar_components = [
        ("sample_icount", left.sample_icount != right.sample_icount),
        ("vcpu_count", left.vcpu_count != right.vcpu_count),
        (
            "rr_current_vcpu",
            left.rr_current_vcpu != right.rr_current_vcpu,
        ),
        (
            "rr_position_in_quantum",
            left.rr_position_in_quantum != right.rr_position_in_quantum,
        ),
        (
            "rr_switch_quantum",
            left.rr_switch_quantum != right.rr_switch_quantum,
        ),
        (
            "component_failures",
            left.component_failures != right.component_failures,
        ),
        ("ram_bytes", left.ram_bytes != right.ram_bytes),
        ("ram_digest", left.ram_digest != right.ram_digest),
        (
            "device_state_bytes",
            left.device_state_bytes != right.device_state_bytes,
        ),
        (
            "device_state_sections",
            left.device_state_sections != right.device_state_sections,
        ),
        (
            "device_state_digest",
            left.device_state_digest != right.device_state_digest,
        ),
        (
            "device_state_schema_digest",
            left.device_state_schema_digest != right.device_state_schema_digest,
        ),
    ];
    let mut differences = scalar_components
        .into_iter()
        .filter(|(_, differs)| *differs)
        .map(|(name, _)| String::from(name))
        .collect::<Vec<_>>();
    for (index, (left, right)) in left.vcpus.iter().zip(&right.vcpus).enumerate() {
        if left.register_digest != right.register_digest {
            differences.push(format!("vcpu[{index}].register_digest"));
        }
        if left.register_file_bytes != right.register_file_bytes {
            differences.push(format!("vcpu[{index}].register_file_bytes"));
        }
        if left.retired_instruction_count != right.retired_instruction_count {
            differences.push(format!("vcpu[{index}].retired_instruction_count"));
        }
    }
    differences
}

fn compare_runtime_determinism_diagnostics(
    variants: [(&str, &RuntimeDeterminismDiagnostics); 2],
) -> String {
    let baselines = variants
        .iter()
        .map(|(name, diagnostics)| {
            format!(
                "{name}={}",
                describe_runtime_baseline(&diagnostics.baseline)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let (reference_name, reference) = variants[0];
    let reference_records = match parse_qemu_runtime_determinism_trace(&reference.trace) {
        Ok(records) => records,
        Err(error) => {
            return format!("baselines=[{baselines}]; {reference_name}_trace_error={error}");
        }
    };
    let reference_suffix = post_final_busy_boundary(&reference_records);
    let mut comparisons = Vec::with_capacity(variants.len() - 1);
    let mut identical = true;

    for (candidate_name, candidate) in variants.into_iter().skip(1) {
        let candidate_records = match parse_qemu_runtime_determinism_trace(&candidate.trace) {
            Ok(records) => records,
            Err(error) => {
                identical = false;
                comparisons.push(format!("{candidate_name}_trace_error={error}"));
                continue;
            }
        };
        let candidate_suffix = post_final_busy_boundary(&candidate_records);
        let common = reference_suffix.len().min(candidate_suffix.len());
        let first_difference = (0..common).find(|&index| {
            normalized_runtime_record(reference_suffix[index])
                != normalized_runtime_record(candidate_suffix[index])
        });
        if let Some(index) = first_difference {
            identical = false;
            comparisons.push(format!(
                "first_split={reference_name}/{candidate_name} \
                 index={index} reference={:?} candidate={:?} reference_context={:?} \
                 candidate_context={:?}",
                reference_suffix[index],
                candidate_suffix[index],
                bounded_trace_context(&reference_suffix, index),
                bounded_trace_context(&candidate_suffix, index),
            ));
            continue;
        }
        if reference_suffix.len() != candidate_suffix.len() {
            identical = false;
            comparisons.push(format!(
                "first_split={reference_name}/{candidate_name} \
                 common_rows={common} reference_rows={} candidate_rows={} \
                 reference_tail={:?} candidate_tail={:?}",
                reference_suffix.len(),
                candidate_suffix.len(),
                reference_suffix.last(),
                candidate_suffix.last(),
            ));
        } else {
            comparisons.push(format!(
                "comparison={reference_name}/{candidate_name} \
                 post_8m_native_sequences_identical=true rows={common}"
            ));
        }
    }

    if identical {
        format!(
            "baselines=[{baselines}]; post_8m_native_sequences_identical=true rows={}",
            reference_suffix.len()
        )
    } else {
        format!(
            "baselines=[{baselines}]; comparisons=[{}]",
            comparisons.join("; ")
        )
    }
}

fn describe_runtime_baseline(baseline: &RuntimeDeterminismBaseline) -> String {
    format!(
        "calibration={:?},idle_state={:?},timer_witness={:?},rr_current_vcpu={},rr_position_in_quantum={}",
        baseline.calibration,
        baseline.idle_state,
        baseline.timer_witness,
        baseline.rr_current_vcpu,
        baseline.rr_position_in_quantum,
    )
}

fn post_final_busy_boundary(
    records: &[QemuRuntimeDeterminismTraceRecord],
) -> Vec<QemuRuntimeDeterminismTraceRecord> {
    records
        .iter()
        .copied()
        .filter(|record| record.raw_icount() >= TARGETS[TARGETS.len() - 1])
        .collect()
}

fn normalized_runtime_record(
    record: QemuRuntimeDeterminismTraceRecord,
) -> QemuRuntimeDeterminismTraceRecord {
    match record {
        QemuRuntimeDeterminismTraceRecord::Idle(mut record) => {
            record.sequence = 0;
            QemuRuntimeDeterminismTraceRecord::Idle(record)
        }
        QemuRuntimeDeterminismTraceRecord::Timer(mut record) => {
            record.sequence = 0;
            QemuRuntimeDeterminismTraceRecord::Timer(record)
        }
    }
}

fn bounded_trace_context(
    records: &[QemuRuntimeDeterminismTraceRecord],
    index: usize,
) -> &[QemuRuntimeDeterminismTraceRecord] {
    let start = index.saturating_sub(1);
    let end = (index + 2).min(records.len());
    &records[start..end]
}

fn run_once(
    factory: &mut LinuxQemuAttemptHostFactory,
    config: &QemuLiveNodeStepGateConfig,
    qemu: &Path,
    hostile: bool,
) -> Result<FlightRun, Box<dyn Error>> {
    let mut owner = factory.begin(4, MEMORY_BYTES, DISK_BYTES)?;
    let mut directory = owner.prepare_generation_run_directory(config.resource_requirements())?;
    directory.prepare_fresh_artifacts_guarded(qemu, None, owner.process_contract()?)?;
    let launch = config.clone().with_run_directory(directory.path());
    let mut node = launch_qemu_production_fresh_node(
        &launch,
        QemuProductionFreshLaunchAdmission::admit(
            &launch,
            &directory,
            owner.process_contract()?,
            QemuLiveNodeIdentity::new(
                "plugin-flight-node",
                "plugin-flight-router",
                "plugin-flight-crash",
            ),
        )?,
    )?;
    let preemption = hostile.then(BoundedSchedulerPreemptionEvidence::default);
    let mut boundaries = Vec::with_capacity(TARGETS.len());

    for (index, target) in TARGETS.into_iter().enumerate() {
        if index == 2
            && let Some(evidence) = &preemption
        {
            node.enable_bounded_scheduler_preemption(evidence.claim()?);
        }
        if index == 2 {
            let at = aligned_preemption_tick(&mut node, 3_000_000, target)?;
            install_preemption(
                &mut node,
                PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
                at,
            )?;
        } else if index == 3 {
            let at = aligned_preemption_tick(&mut node, 6_000_000, target)?;
            install_preemption(
                &mut node,
                PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: 2 },
                    irq: IrqVector { vector: 32 },
                },
                at,
            )?;
        }
        let observation = match SimulationBackend::step_to(&mut node, VirtualTime { ticks: target })
        {
            Ok(observation) => observation,
            Err(source) => {
                return Err(node_state_failure(
                    &mut node,
                    &format!("busy target index {index} ({target})"),
                    source,
                ));
            }
        };
        let outcome = observation.outcome;
        if observation.requested_ceiling.ticks != target || observation.reached.ticks != target {
            return Err(
                format!("scheduler backend returned invalid boundary: {observation:?}").into(),
            );
        }
        match outcome {
            AdvanceOutcome::ReachedHorizon => {}
            AdvanceOutcome::Paused { at } => {
                return Err(
                    format!("guest paused at {} before busy target {target}", at.retired).into(),
                );
            }
        }
        // This call requests a capture and waits for the exact generation ACK.
        // Only the production plugin's digest worker publishes that ACK.
        let fingerprint = node.execution_fingerprint()?;
        let sample = node.fingerprint_sample()?;
        validate_sample(sample, target)?;
        boundaries.push(BoundaryEvidence {
            target,
            outcome,
            fingerprint,
            sample,
        });
    }
    if let Some(evidence) = preemption {
        let report = evidence
            .snapshot()
            .ok_or("bounded preemption did not publish evidence")?;
        if !report.applied || !report.pending_quantum_certified || report.perturbations == 0 {
            return Err("bounded preemption did not overlap the live quantum".into());
        }
    }
    let instruction_exact = instruction_exact_evidence(&boundaries)?;
    let final_busy_sample = boundaries
        .last()
        .ok_or("production flight omitted its final busy boundary")?
        .sample;
    // These are passive shared-memory reads at the already-established 8M
    // boundary. In particular, localization does not issue a QMP query or add
    // another scheduler step that could perturb the ordering under inspection.
    let runtime_baseline = RuntimeDeterminismBaseline {
        calibration: node
            .logical_time_calibration()
            .map_err(|error| error.to_string()),
        idle_state: node.idle_state().map_err(|error| error.to_string()),
        timer_witness: node
            .virtual_timer_fire_witness()
            .map_err(|error| error.to_string()),
        rr_current_vcpu: final_busy_sample.rr_current_vcpu,
        rr_position_in_quantum: final_busy_sample.rr_position_in_quantum,
    };

    let idle = match probe_idle_wake(&mut node) {
        Ok(idle) => idle,
        Err(source) => {
            let shutdown = node.shutdown_child();
            drop(node);
            let trace = match &shutdown {
                Ok(report) if report.reaped && !report.leaked => directory
                    .retain_runtime_determinism_trace_after_reap()
                    .map_err(|error| error.to_string()),
                _ => Err(String::from(
                    "trace unavailable because clean QEMU reap was not proven",
                )),
            };
            drop(directory);
            let finish = owner.finish();

            return Err(format!(
                "idle probe failed: hostile={hostile}; {source}; \
                 diagnostic_shutdown={shutdown:?}; diagnostic_finish={finish:?}; \
                 retained_native_rr_trace={trace:?}"
            )
            .into());
        }
    };

    let shutdown = node.shutdown_child()?;
    drop(node);
    let trace = if shutdown.reaped && !shutdown.leaked {
        directory.retain_runtime_determinism_trace_after_reap()?
    } else {
        String::new()
    };
    drop(directory);
    owner.finish()?;
    Ok(FlightRun {
        on_demand_acknowledgements: boundaries.len() + idle.on_demand_acknowledgements,
        boundaries,
        instruction_exact,
        idle,
        shutdown,
        diagnostics: RuntimeDeterminismDiagnostics {
            baseline: runtime_baseline,
            trace,
        },
    })
}

fn prepare_live_hot_fork_template(node: &mut QemuNode) -> Result<u64, Box<dyn Error>> {
    node.pause_at_exact_checkpoint_boundary()?;

    let draining = node.prepare_hot_fork_template(&[])?;
    if draining.outcome() != QmpHotForkTemplateOutcome::Draining
        || !draining.transaction_active()
        || draining.ready()
    {
        return Err(format!("hot-fork template did not enter draining: {draining:?}").into());
    }

    let barriers = node.prepare_hot_fork_template_barriers(&[])?;
    if barriers.generation() != draining.generation()
        || barriers.outcome() != QmpHotForkTemplateOutcome::Draining
        || !barriers.transaction_active()
        || barriers.ready()
    {
        return Err(format!("hot-fork barriers did not retain draining: {barriers:?}").into());
    }

    let resources = node.prepare_hot_fork_child_resources(MAXIMUM_HOT_FORK_RING_IMAGE_BYTES)?;
    let prepared = resources.template();
    if prepared.generation() != draining.generation()
        || prepared.outcome() != QmpHotForkTemplateOutcome::Prepared
        || !prepared.transaction_active()
        || !prepared.ready()
        || prepared.missing_proofs() != 0
    {
        return Err(format!("hot-fork template did not become prepared: {prepared:?}").into());
    }

    Ok(prepared.generation())
}

fn node_state_failure(
    node: &mut QemuNode,
    phase: &str,
    source: impl std::fmt::Display,
) -> Box<dyn Error> {
    let idle_state = node.idle_state().map_err(|error| error.to_string());
    let calibration = node
        .logical_time_calibration()
        .map_err(|error| error.to_string());
    let timer_witness = node
        .virtual_timer_fire_witness()
        .map_err(|error| error.to_string());

    format!(
        "production flight failed during {phase}: source={source}; \
         idle_state={idle_state:?}; calibration={calibration:?}; \
         timer_witness={timer_witness:?}"
    )
    .into()
}

fn probe_idle_wake(node: &mut QemuNode) -> Result<IdleEvidence, Box<dyn Error>> {
    let readiness = match SimulationBackend::step_to(
        node,
        VirtualTime {
            ticks: READINESS_ADMISSION_CEILING,
        },
    ) {
        Ok(observation) => observation,
        Err(source) => return Err(node_state_failure(node, "readiness admission", source)),
    };
    let AdvanceOutcome::Paused { at: readiness_at } = readiness.outcome else {
        return Err(format!(
            "diskless guest did not publish its authenticated readiness request: {readiness:?}"
        )
        .into());
    };
    let readiness_events = SimulationBackend::drain_observable_events(node)?;
    let setup_marker_icount = authenticate_readiness_marker(&readiness_events, readiness_at)?;

    let pending_requests = node.drain_pending_selectable_requests()?;
    let [pending] = pending_requests.as_slice() else {
        return Err(format!(
            "readiness boundary carried {} pending selectable requests instead of one",
            pending_requests.len()
        )
        .into());
    };
    let request = pending.request();
    let expected_boundary = pending
        .icount()
        .checked_add(SELECTABLE_NATIVE_HANDOFF_INSTRUCTIONS)
        .ok_or("readiness boundary overflowed")?;
    if readiness.reached.ticks != readiness_at.retired
        || readiness_at.retired != expected_boundary
        || pending.vcpu_index() != READINESS_VCPU_INDEX
        || request.sequence() != READINESS_REQUEST_SEQUENCE
        || request.selectable_id() != READINESS_SELECTABLE_ID
        || request.instance_key() != READINESS_INSTANCE_KEY
        || request.narrowed_domain().is_some()
        || request.reply_capacity() != READINESS_REPLY_CAPACITY
    {
        return Err(format!(
            "readiness boundary did not match the launch-authenticated request: \
             observation={readiness:?}, pending={pending:?}"
        )
        .into());
    }

    let reply = SelectionReply::rejected(
        READINESS_REQUEST_SEQUENCE,
        SelectionReplyStatus::Unavailable,
        [0; 32],
        [0; 32],
    )?;
    node.enqueue_selectable_reply(pending, &reply)?;

    let halted = match node.advance_to_next_idle(Icount {
        retired: READINESS_ADMISSION_CEILING,
    }) {
        Ok(outcome) => outcome,
        Err(source) => {
            return Err(node_state_failure(
                node,
                "readiness reply completion",
                source,
            ));
        }
    };
    let AdvanceOutcome::Paused { at } = halted else {
        return Err(
            "diskless guest reached the readiness liveness ceiling before all-vCPU idle".into(),
        );
    };
    let completion_events = SimulationBackend::drain_observable_events(node)?;
    if !completion_events.is_empty() {
        return Err(format!(
            "readiness reply completion carried unexpected observable events: \
             {completion_events:?}"
        )
        .into());
    }
    if !node.selectable_reply_is_checkpoint_quiescent() {
        return Err("guest readiness reply was not consumed before idle".into());
    }
    let state = node.idle_state()?;
    let deadline = state
        .next_deadline
        .ok_or("all-vCPU idle boundary did not publish an exact timer deadline")?;
    if state.current_icount != at || deadline <= at {
        return Err(format!("invalid all-vCPU idle state: {state:?}").into());
    }
    let halted_fingerprint = node.execution_fingerprint()?;
    let halted_sample = node.fingerprint_sample()?;
    validate_sample(halted_sample, at.retired)?;
    let armed_calibration = node.logical_time_calibration()?;
    if armed_calibration.logical_icount != at.retired {
        return Err(format!(
            "idle witness armed at incoherent logical/raw calibration: {armed_calibration:?}"
        )
        .into());
    }
    let prior_timer_witness = node.virtual_timer_fire_witness()?;

    let wake = match SimulationBackend::step_to(
        node,
        VirtualTime {
            ticks: deadline.retired,
        },
    ) {
        Ok(observation) => observation,
        Err(source) => return Err(node_state_failure(node, "virtual-timer wake", source)),
    };
    if wake.reached.ticks != deadline.retired {
        return Err(format!("idle wake missed exact deadline: {wake:?}").into());
    }
    let wake_fingerprint = node.execution_fingerprint()?;
    let wake_sample = node.fingerprint_sample()?;
    validate_sample(wake_sample, deadline.retired)?;
    let post_wake_calibration = node.logical_time_calibration()?;
    if post_wake_calibration.logical_icount != deadline.retired
        || post_wake_calibration.raw_icount != armed_calibration.raw_icount
    {
        return Err(format!(
            "actual timer callback did not preserve raw icount while publishing the exact logical wake: armed={armed_calibration:?}, post={post_wake_calibration:?}"
        )
        .into());
    }
    let target_virtual_ps = deadline.retired;
    let retirement_step_ps = FLIGHT_TICKS_PER_INSTRUCTION;
    let native_witness = node
        .virtual_timer_fire_witness()?
        .ok_or("timer wake did not publish an actual callback witness")?;
    if prior_timer_witness.is_some_and(|prior| prior.generation == native_witness.generation)
        || native_witness.completed != 1
        || native_witness.reserved != 0
        || native_witness.deadline_tick != deadline.retired
        || native_witness.armed_raw_icount != armed_calibration.raw_icount
        || native_witness.fired_expire_ps != native_witness.deadline_ps
        || native_witness.fired_virtual_ps != target_virtual_ps
        || native_witness.deadline_ps > native_witness.fired_virtual_ps
        || native_witness.fired_virtual_ps - native_witness.deadline_ps >= retirement_step_ps
        || native_witness.fired_raw_icount != native_witness.armed_raw_icount
        || native_witness.fired_raw_icount != post_wake_calibration.raw_icount
    {
        return Err(format!(
            "published virtual-timer witness did not authenticate this exact idle wake: prior={prior_timer_witness:?}, native={native_witness:?}, armed={armed_calibration:?}, post={post_wake_calibration:?}, deadline={deadline:?}, target_virtual_ps={target_virtual_ps}, step_ps={retirement_step_ps}"
        )
        .into());
    }
    let timer_fire = VirtualTimerFireEvidence {
        generation: native_witness.generation,
        armed_deadline_ps: native_witness.deadline_ps,
        armed_deadline_tick: native_witness.deadline_tick,
        retirement_step_ps,
        armed_raw_icount: native_witness.armed_raw_icount,
        fired_expire_ps: native_witness.fired_expire_ps,
        fired_virtual_ps: native_witness.fired_virtual_ps,
        fired_raw_icount: native_witness.fired_raw_icount,
        published_wake_tick: deadline.retired,
        post_wake_tick: post_wake_calibration.logical_icount,
        completed: native_witness.completed,
        reserved: native_witness.reserved,
    };

    Ok(IdleEvidence {
        setup_marker_icount,
        halted_at: at.retired,
        deadline: deadline.retired,
        halted_fingerprint,
        halted_sample,
        wake_outcome: wake.outcome,
        wake_fingerprint,
        wake_sample,
        timer_fire,
        on_demand_acknowledgements: 2,
    })
}

fn authenticate_readiness_marker(
    events: &[ObservableEvent],
    readiness_at: Icount,
) -> Result<u64, String> {
    let [event] = events else {
        return Err(format!(
            "readiness boundary carried {} observable events instead of one setup marker",
            events.len()
        ));
    };
    let ObservableEventPayload::GuestMarker {
        retired_icount,
        node,
        marker,
    } = event.payload()
    else {
        return Err(format!(
            "readiness boundary carried a non-marker observable event: {event:?}"
        ));
    };
    if node.name != FLIGHT_NODE_ID
        || marker.name != SETUP_COMPLETE_MARKER
        || event.at().ticks != retired_icount.retired
        || retired_icount.retired > readiness_at.retired
    {
        return Err(format!(
            "readiness boundary carried an unauthenticated setup marker: event={event:?}, paused={readiness_at:?}"
        ));
    }
    Ok(retired_icount.retired)
}

fn readiness_selectable_catalog_plan() -> Result<SelectableCatalogPlan, Box<dyn Error>> {
    let declaration = SelectablePlanDeclaration::new(
        READINESS_SELECTABLE_ID,
        vec![1],
        vec![1],
        vec![String::from("readiness")],
        SelectablePlanPresence::Required,
    )?;
    Ok(SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 1, 1)?,
        vec![declaration],
        SelectablePlanContinuation::cold(),
    )?)
}

fn install_preemption(
    node: &mut QemuNode,
    kind: PreemptionKind,
    at: u64,
) -> Result<(), Box<dyn Error>> {
    let current = SimulationBackend::now(node);
    SimulationBackend::apply(
        node,
        &BackendEffect::Preemption(PreemptionDecision {
            node: NodeId {
                name: String::from("plugin-flight-node"),
            },
            at: crucible::SimInstant { ticks: at },
            kind,
        }),
        current,
    )?;
    Ok(())
}

fn aligned_preemption_tick(
    node: &mut QemuNode,
    requested: u64,
    horizon: u64,
) -> Result<u64, Box<dyn Error>> {
    let calibration = node.logical_time_calibration()?;
    align_preemption_tick(calibration, requested, horizon)
}

fn align_preemption_tick(
    calibration: QemuLogicalTimeCalibration,
    requested: u64,
    horizon: u64,
) -> Result<u64, Box<dyn Error>> {
    let raw_ticks = calibration
        .raw_icount
        .checked_mul(FLIGHT_TICKS_PER_INSTRUCTION)
        .ok_or("raw preemption calibration overflowed")?;
    let offset = calibration
        .logical_icount
        .checked_sub(raw_ticks)
        .ok_or("raw preemption calibration exceeded logical time")?;
    let raw_at = requested
        .checked_sub(offset)
        .ok_or("preemption target precedes the raw origin")?
        .div_ceil(FLIGHT_TICKS_PER_INSTRUCTION);
    let at = raw_at
        .checked_mul(FLIGHT_TICKS_PER_INSTRUCTION)
        .and_then(|raw_ticks| raw_ticks.checked_add(offset))
        .ok_or("aligned preemption tick overflowed")?;

    // QEMU can preempt only at a retired instruction. Keep the request inside
    // its scheduler RUN while choosing the first retirement at or after it.
    if at > horizon {
        return Err(format!("aligned preemption tick {at} exceeds horizon {horizon}").into());
    }
    Ok(at)
}

fn validate_sample(sample: FingerprintSample, target: u64) -> Result<(), Box<dyn Error>> {
    if sample.sample_icount != target
        || sample.vcpu_count != 4
        || sample.rr_current_vcpu >= sample.vcpu_count
        || sample.rr_switch_quantum != RR_SWITCH_QUANTUM
        || sample.component_failures != 0
        || sample.ram_bytes == 0
        || sample.device_state_bytes == 0
    {
        return Err(format!("invalid fingerprint sample at target {target}: {sample:?}").into());
    }
    if sample.vcpus[..sample.vcpu_count as usize]
        .iter()
        .any(|vcpu| vcpu.register_file_bytes == 0 || vcpu.register_digest == [0; 32])
    {
        return Err(format!("fingerprint sample lacks vCPU register state: {sample:?}").into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "crucible-qemu-production-plugin-flight/tests.rs"]
mod tests;
