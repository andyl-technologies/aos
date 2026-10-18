//! Exercises the loaded Rust plugin through the guarded production node boundary.
//!
//! The flight launches the same four-vCPU diskless guest under reference and
//! host-preempted conditions. It requests fingerprints at exact scheduler
//! boundaries, applies typed scheduler preemptions, and crosses an all-vCPU
//! idle timer wake. A separate real block recovery subflight proves the causal
//! recovery transition, exact settled write, and hot-fork preparation.
//! Successful runs emit only typed shared-memory and node-level evidence.
//! Native traces are validated through pinned files after clean reap; the
//! exported summary contains their full-file hashes and bounded row context.
//! Setting `CRUCIBLE_PRODUCTION_PLUGIN_FLIGHT_BLOCK_RECOVERY_ONLY=1` runs the
//! block-recovery subflight alone for focused failure diagnosis.
//! Setting `CRUCIBLE_PHASE4_PARTITION_PROBE=1` compares coarse and fine
//! post-selection scheduler steps across an exact virtual-timer wake.
//!
//! The deployed service supplies immutable guest artifacts and the authentic
//! Main-held factory. A component selector cannot issue that owner. Full
//! normalized trace spools remain under the admitted catalog quota through comparison.

#![forbid(unsafe_code)]

use crate::NativeObservationError;

use crate::qemu_lifecycle_launcher::ObservedNativeNode;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crucible_engine::{
    AdvanceOutcome, BackendEffect, ExecutionFingerprint, Icount, IrqVector, NodeId,
    ObservableEvent, ObservableEventPayload, PreemptionDecision, PreemptionKind, SimulationBackend,
    VcpuId, VirtualTime,
};
use crucible_qemu_host::{
    BoundedSchedulerPreemptionEvidence, QemuLiveNodeStepGateConfig, QemuLogicalTimeCalibration,
    QemuNodeIdleState, QemuShutdownReport, QemuVirtualTimerFireWitness, QmpHotForkTemplateOutcome,
};
use crucible_qemu_protocol::selectable_catalog_plan::{
    SELECTABLE_NATIVE_HANDOFF_TICKS_PS, SelectableCatalogPlan, SelectablePlanContinuation,
    SelectablePlanDeclaration, SelectablePlanLimits, SelectablePlanPresence,
};
use crucible_qemu_protocol::{SelectionReply, SelectionReplyStatus};

use crucible_qemu_shmem::FingerprintSample;

#[path = "block_recovery_hot_fork.rs"]
mod block_recovery_hot_fork;

#[path = "runtime_trace.rs"]
mod runtime_trace;

#[path = "partition_probe.rs"]
mod partition_probe;

#[path = "node_run.rs"]
mod node_run;

#[path = "evidence.rs"]
mod evidence;
use evidence::*;

const MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const DISK_BYTES: u64 = 1024 * 1024 * 1024;
const RR_SWITCH_QUANTUM: u64 = 4096;
const FLIGHT_TICKS_PER_INSTRUCTION: u64 = crucible_engine::SIM_TICKS_PER_INSTRUCTION;
const FRACTIONAL_PHASE_LOWER_TARGET: u64 = 2_000_000;
const INSTRUCTION_EXACT_LOWER_TARGET: u64 = FRACTIONAL_PHASE_LOWER_TARGET + 1;
const INSTRUCTION_EXACT_UPPER_TARGET: u64 =
    INSTRUCTION_EXACT_LOWER_TARGET + FLIGHT_TICKS_PER_INSTRUCTION;
const TARGETS: [u64; 5] = [
    FRACTIONAL_PHASE_LOWER_TARGET,
    INSTRUCTION_EXACT_LOWER_TARGET,
    INSTRUCTION_EXACT_UPPER_TARGET,
    4_000_000,
    8_000_000,
];
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
// The readiness flight produced a 95.6-million-byte trace through idle wake.
// Reserve a finite product-only ceiling and validate through a pinned stream.
const PRODUCTION_RUNTIME_TRACE_BYTES: u64 = 256 * 1024 * 1024;
const BLOCK_RECOVERY_ONLY_ENVIRONMENT: &str =
    "CRUCIBLE_PRODUCTION_PLUGIN_FLIGHT_BLOCK_RECOVERY_ONLY";
const PHASE4_PARTITION_PROBE_ENVIRONMENT: &str = "CRUCIBLE_PHASE4_PARTITION_PROBE";

pub(in crate::packaged_qemu_executor) fn run_four(
    factory: &mut dyn super::admission::FlightAdmission,
    qemu: &Path,
    plugin: &Path,
    kernel: &Path,
    idle_initrd: &Path,
    firmware: &Path,
    run_root: &Path,
) -> Result<(), NativeObservationError> {
    let selectable_catalog_plan = readiness_selectable_catalog_plan()?;
    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_initrd(idle_initrd)
        .with_vm_shape(128, 4)
        .with_rr_switch_quantum(RR_SWITCH_QUANTUM)
        .with_whitebox(crucible_qemu_host::QemuLaunchPluginSwitch::On)
        .with_selectable_catalog_plan(selectable_catalog_plan)
        .with_fingerprint(crucible_qemu_host::QemuLaunchPluginSwitch::On)
        // Full hot-fork preparation stages a connected child console.
        .with_console_capture()
        .with_runtime_determinism_trace()
        .with_runtime_determinism_trace_budget(PRODUCTION_RUNTIME_TRACE_BYTES)?
        // The exact four-vCPU guest authenticated readiness after about 110
        // host seconds. Keep a finite per-advance guard with measured headroom.
        .with_completion_timeout(Duration::from_secs(300));

    if std::env::var_os(PHASE4_PARTITION_PROBE_ENVIRONMENT).is_some() {
        let coarse = run_once(
            factory,
            &config,
            false,
            Some(partition_probe::POST_SELECTION_SPAN_PS),
        )?;
        let fine = run_once(factory, &config, false, Some(partition_probe::FINE_STEP_PS))?;
        publish_trace_summary(&coarse.diagnostics.trace.report());
        compare_boundaries("partitioned replay", &coarse.boundaries, &fine.boundaries)?;
        if !idle_evidence_matches_across_runs(&coarse.idle, &fine.idle) {
            return Err(format!(
                "partitioned replay did not start from the same authenticated timer wake: coarse={:?} fine={:?}",
                coarse.idle, fine.idle,
            )
            .into());
        }
        partition_probe::compare(
            coarse
                .partition_probe
                .as_ref()
                .ok_or("missing coarse partition probe")?,
            fine.partition_probe
                .as_ref()
                .ok_or("missing fine partition probe")?,
        )?;
        println!("PASS");
        println!("diagnostic_mode=phase4-partition-probe");
        coarse.diagnostics.trace.finish()?;
        fine.diagnostics.trace.finish()?;
        return Ok(());
    }

    let reference = run_once(factory, &config, false, None)?;
    let hostile = run_once(factory, &config, true, None)?;
    publish_trace_summary(&reference.diagnostics.trace.report());
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

    // Keep the validated, bounded evidence visible if the independent block
    // recovery subflight fails before the normal result file is emitted.
    eprintln!(
        "PRODUCTION_PLUGIN_RUNTIME_TRACE_REFERENCE_SUMMARY_BEGIN\n{}\
         PRODUCTION_PLUGIN_RUNTIME_TRACE_REFERENCE_SUMMARY_END",
        reference.diagnostics.trace.report()
    );
    eprintln!(
        "PRODUCTION_PLUGIN_RUNTIME_TRACE_HOSTILE_SUMMARY_BEGIN\n{}\
         PRODUCTION_PLUGIN_RUNTIME_TRACE_HOSTILE_SUMMARY_END",
        hostile.diagnostics.trace.report()
    );
    eprintln!(
        "production_runtime_trace_comparison={}",
        runtime_trace::compare(
            "reference",
            &reference.diagnostics.trace,
            "hostile",
            &hostile.diagnostics.trace,
        )?
    );

    println!("rust_plugin_loaded=true");
    println!("diskless_multiboot_runs={}", production_variants.len());
    println!("fingerprint_flight_variants=reference,host-preempted");
    println!("vcpu_count=4");
    println!("rr_switch_quantum={RR_SWITCH_QUANTUM}");
    println!("sample_count={}", reference.boundaries.len());
    println!("sample_target_picoseconds=2000000,2000001,2000051,4000000,8000000");
    println!("sample_stream_restart_identical=true");
    println!("on_demand_worker_acknowledgements={on_demand_acknowledgements}");
    println!("on_demand_boundary_stream_bit_identical=true");
    println!(
        "instruction_exact_window_lower_picoseconds={}",
        instruction_exact.lower_target
    );
    println!(
        "instruction_exact_window_upper_picoseconds={}",
        instruction_exact.upper_target
    );
    println!("instruction_exact_window_width_picoseconds={FLIGHT_TICKS_PER_INSTRUCTION}");
    println!("fractional_phase_window_lower_picoseconds={FRACTIONAL_PHASE_LOWER_TARGET}");
    println!("fractional_phase_window_upper_picoseconds={INSTRUCTION_EXACT_LOWER_TARGET}");
    println!("fractional_phase_no_retirement=true");
    println!("fractional_phase_timer_projection_changed=true");
    println!("fractional_phase_fingerprint_changed=true");
    println!("instruction_exact_raw_retirement_successor=true");
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

    println!("component_failures=0");
    println!("per_vcpu_register_files_present=true");
    println!("sample_logical_picoseconds_equal_target=true");
    reference.diagnostics.trace.finish()?;
    hostile.diagnostics.trace.finish()?;
    Ok(())
}

pub(in crate::packaged_qemu_executor) fn block_recovery_only_requested()
-> Result<bool, NativeObservationError> {
    let value = std::env::var_os(BLOCK_RECOVERY_ONLY_ENVIRONMENT);
    parse_block_recovery_only(value.as_deref())
}

fn parse_block_recovery_only(
    value: Option<&std::ffi::OsStr>,
) -> Result<bool, NativeObservationError> {
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

fn run_once(
    factory: &mut dyn super::admission::FlightAdmission,
    config: &QemuLiveNodeStepGateConfig,
    hostile: bool,
    partition_step_ps: Option<u64>,
) -> Result<FlightRun, NativeObservationError> {
    let mut owner = factory.begin(4, MEMORY_BYTES, DISK_BYTES)?;
    let driven = owner.with_launch(
        config,
        "plugin-flight-router",
        "plugin-flight-crash",
        |node| node_run::drive(node, hostile, partition_step_ps),
    )?;
    let node_run::DrivenNode {
        boundaries,
        instruction_exact,
        idle,
        partition_probe,
        shutdown,
        runtime_baseline,
    } = match driven {
        node_run::DrivenFlight::Complete(run) => run,
        node_run::DrivenFlight::IdleFailed { source, shutdown } => {
            let trace = match &shutdown {
                Ok(report) if report.reaped && !report.leaked => owner.liveness_tail(),
                _ => Err(NativeObservationError::from(
                    "trace unavailable because clean QEMU reap was not proven",
                )),
            };
            let finish = owner.finish();
            return Err(source.with_cleanup(
                format!("idle probe failed: hostile={hostile}"),
                Some(shutdown),
                Some(finish),
                Some(trace),
            ));
        }
        node_run::DrivenFlight::PartitionFailed { source, shutdown } => {
            let finish = owner.finish();
            return Err(source.with_cleanup(
                String::from("post-selection partition probe failed"),
                Some(shutdown),
                Some(finish),
                None,
            ));
        }
    };
    let raw_boundary = match final_busy_raw_boundary(&runtime_baseline) {
        Ok(boundary) => boundary,
        Err(source) => {
            let failure = NativeObservationError::Context(Box::new(
                crate::native_observation_error::NativeObservationContext {
                    source,
                    phase: String::from("final busy boundary calibration"),
                    idle_state: runtime_baseline.idle_state,
                    calibration: runtime_baseline.calibration,
                    timer_witness: runtime_baseline.timer_witness,
                },
            ));
            let finish = owner.finish();
            return Err(failure.with_cleanup(
                String::from("failed final busy boundary calibration"),
                None,
                Some(finish),
                None,
            ));
        }
    };
    let spool = owner.create_trace_spool()?;
    let trace_result = owner.inspect_trace(PRODUCTION_RUNTIME_TRACE_BYTES, |reader| {
        runtime_trace::summarize(
            reader,
            raw_boundary,
            TARGETS[TARGETS.len() - 1] as i64,
            spool,
        )
    });
    let finish_result = owner.finish();
    let trace = match (trace_result, finish_result) {
        (Ok(trace), Ok(())) => trace,
        (Err(error), finish) => {
            return Err(error.with_cleanup(
                format!(
                    "runtime trace validation failed after authenticated idle wake: idle={idle:?}"
                ),
                Some(Ok(shutdown)),
                Some(finish),
                None,
            ));
        }
        (Ok(_), Err(error)) => return Err(error.into()),
    };
    Ok(FlightRun {
        on_demand_acknowledgements: boundaries.len() + idle.on_demand_acknowledgements,
        boundaries,
        instruction_exact,
        idle,
        partition_probe,
        shutdown,
        diagnostics: RuntimeDeterminismDiagnostics {
            baseline: runtime_baseline,
            trace,
        },
    })
}

fn prepare_live_hot_fork_template(
    node: &mut ObservedNativeNode<'_>,
) -> Result<u64, NativeObservationError> {
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
    node: &mut ObservedNativeNode<'_>,
    phase: &str,
    source: impl Into<NativeObservationError>,
) -> NativeObservationError {
    let source = source.into();
    let idle_state = node.idle_state().map_err(Arc::new);
    let calibration = node.logical_time_calibration().map_err(Arc::new);
    let timer_witness = node.virtual_timer_fire_witness().map_err(Arc::new);
    NativeObservationError::Context(Box::new(
        crate::native_observation_error::NativeObservationContext {
            source,
            phase: phase.to_owned(),
            idle_state,
            calibration,
            timer_witness,
        },
    ))
}

fn probe_idle_wake(
    node: &mut ObservedNativeNode<'_>,
) -> Result<IdleEvidence, NativeObservationError> {
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
        .trap_tick_ps()
        .checked_add(SELECTABLE_NATIVE_HANDOFF_TICKS_PS)
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

fn readiness_selectable_catalog_plan() -> Result<SelectableCatalogPlan, NativeObservationError> {
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
    node: &mut ObservedNativeNode<'_>,
    kind: PreemptionKind,
    at: u64,
) -> Result<(), NativeObservationError> {
    let current = SimulationBackend::now(node);
    SimulationBackend::apply(
        node,
        &BackendEffect::Preemption(PreemptionDecision {
            node: NodeId {
                name: String::from("plugin-flight-node"),
            },
            at: crucible_engine::SimInstant { ticks: at },
            kind,
        }),
        current,
    )?;
    Ok(())
}

fn aligned_preemption_tick(
    node: &mut ObservedNativeNode<'_>,
    requested: u64,
    horizon: u64,
) -> Result<u64, NativeObservationError> {
    let calibration = node.logical_time_calibration()?;
    align_preemption_tick(calibration, requested, horizon)
}

fn align_preemption_tick(
    calibration: QemuLogicalTimeCalibration,
    requested: u64,
    horizon: u64,
) -> Result<u64, NativeObservationError> {
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

fn validate_sample(sample: FingerprintSample, target: u64) -> Result<(), NativeObservationError> {
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
#[path = "tests.rs"]
mod tests;

fn publish_trace_summary(report: &str) {
    println!("PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_BEGIN");
    print!("{report}");
    println!("PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_END");
}

pub(in crate::packaged_qemu_executor) fn run_block(
    factory: &mut dyn super::admission::FlightAdmission,
    qemu: &Path,
    plugin: &Path,
    kernel: &Path,
    initrd: &Path,
    firmware: &Path,
    run_root: &Path,
) -> Result<(), NativeObservationError> {
    let diagnostic = block_recovery_only_requested()?;
    let evidence = block_recovery_hot_fork::run(
        factory, qemu, plugin, kernel, initrd, firmware, run_root, diagnostic,
    )?;
    if diagnostic {
        println!("diagnostic_mode=block-recovery-only");
    }
    print_block_recovery_evidence(evidence);
    Ok(())
}

/// Bounds fixture-owned resident buffers before any native generation starts.
///
/// The ring image, region allocation, and serialized setup bytes can overlap
/// during private-mapping construction.
/// Console collection, both fingerprint streams, and bounded trace/partition
/// localization retain separate credit. Native pager metadata is admitted by
/// the production inventory handshake, independently of this diagnostic loan.
pub(in crate::packaged_qemu_executor) fn evidence_resident_bound()
-> Result<u64, NativeObservationError> {
    let bytes = (3 * MAXIMUM_HOT_FORK_RING_IMAGE_BYTES)
        .checked_add(2 * 4 * 1024 * 1024)
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<FlightRun>()))
        .and_then(|bytes| {
            bytes.checked_add(2 * TARGETS.len() * std::mem::size_of::<BoundaryEvidence>())
        })
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<node_run::DrivenFlight>()))
        .and_then(|bytes| bytes.checked_add(32 * 1024))
        .and_then(|bytes| bytes.checked_add(runtime_trace::resident_bound()))
        .and_then(|bytes| bytes.checked_add(partition_probe::resident_bound()))
        .ok_or("native assertion buffer bound overflowed")?;
    Ok(u64::try_from(bytes)?)
}
