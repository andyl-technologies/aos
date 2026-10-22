//! Compares plain diagnostic serialization with the previous canonical transcript.
//!
//! These values issue no Main, Source, native role or return certificate.

use super::*;

fn timer() -> NativeFlightTimerObservation {
    NativeFlightTimerObservation {
        generation: 11,
        armed_deadline_ps: 12,
        armed_deadline_tick: 13,
        retirement_step_ps: 14,
        armed_raw_icount: 15,
        fired_expire_ps: 16,
        fired_virtual_ps: 17,
        fired_raw_icount: 18,
        published_wake_tick: 19,
        post_wake_tick: 20,
        completed: 21,
        reserved: 22,
    }
}

#[test]
fn four_vcpu_transcript_preserves_every_legacy_row_and_order() {
    let components = [String::from("vcpu[1].register_digest"), String::from("ram")];
    let report = NativeFourVcpuDiagnostic {
        runs: 2,
        samples: 5,
        acknowledgements: 14,
        rr_switch_quantum: 4096,
        ticks_per_instruction: 50,
        fractional_target: 2_000_000,
        lower_target: 2_000_001,
        upper_target: 2_000_051,
        lower_rr_vcpu: 1,
        upper_rr_vcpu: 1,
        lower_rr_position: 2,
        upper_rr_position: 3,
        changed_components: &components,
        first_differing_state_component: "vcpu[1].register_digest",
        owning_vcpu_state_projection: "vcpu[1].register_digest",
        setup_marker_icount: 23,
        timer: timer(),
    };
    let record = NativePluginFlightDiagnostic::FourVcpu(&report);
    assert_eq!(record.channel(), NativeFlightOutputChannel::StandardOutput);
    assert_eq!(record.to_string(), LEGACY_FOUR_VCPU);
}

// Captured from the original driver format strings, independently of this encoder.
const LEGACY_FOUR_VCPU: &str = r#"rust_plugin_loaded=true
diskless_multiboot_runs=2
fingerprint_flight_variants=reference,host-preempted
vcpu_count=4
rr_switch_quantum=4096
sample_count=5
sample_target_picoseconds=2000000,2000001,2000051,4000000,8000000
sample_stream_restart_identical=true
on_demand_worker_acknowledgements=14
on_demand_boundary_stream_bit_identical=true
instruction_exact_window_lower_picoseconds=2000001
instruction_exact_window_upper_picoseconds=2000051
instruction_exact_window_width_picoseconds=50
fractional_phase_window_lower_picoseconds=2000000
fractional_phase_window_upper_picoseconds=2000001
fractional_phase_no_retirement=true
fractional_phase_timer_projection_changed=true
fractional_phase_fingerprint_changed=true
instruction_exact_raw_retirement_successor=true
instruction_exact_lower_rr_vcpu=1
instruction_exact_upper_rr_vcpu=1
instruction_exact_lower_rr_position=2
instruction_exact_upper_rr_position=3
instruction_exact_rr_successor=true
instruction_exact_changed_components=vcpu[1].register_digest,ram
instruction_exact_first_differing_state_component=vcpu[1].register_digest
instruction_exact_owning_vcpu_state_projection=vcpu[1].register_digest
instruction_exact_state_projection_changed=true
instruction_exact_fingerprint_changed=true
instruction_exact_localization=one-instruction-window
bounded_scheduler_preemption_applied=true
pending_quantum_preemption_certified=true
scheduler_preemption_mailbox_decisions=2
scheduler_vcpu_switch_applied=true
scheduler_interrupt_applied=true
readiness_setup_marker_authenticated=true
readiness_setup_marker_icount=23
all_vcpus_halted_observed=true
exact_timer_deadline_observed=true
queued_idle_wake_reached_exact_deadline=true
actual_virtual_timer_fire_authenticated=true
timer_witness_generation=11
timer_witness_armed_deadline_ps=12
timer_witness_armed_deadline_tick=13
timer_witness_ticks_per_instruction=50
timer_witness_retirement_step_ps=14
timer_witness_armed_raw_icount=15
timer_witness_fired_expire_ps=16
timer_witness_fired_virtual_ps=17
timer_witness_fired_raw_icount=18
timer_witness_published_wake_tick=19
timer_witness_post_wake_tick=20
timer_witness_completed=21
timer_witness_reserved=22
idle_wake_stream_restart_identical=true
component_failures=0
per_vcpu_register_files_present=true
sample_logical_picoseconds_equal_target=true
"#;

#[test]
fn trace_envelopes_preserve_original_channels_and_exact_newlines() {
    let tail = VecDeque::new();
    let summary = NativeRuntimeTraceSummary {
        bytes: 24,
        rows: 2,
        raw_sha256: "raw",
        post_boundary_rows: 1,
        post_boundary_sha256: "normalized",
        prefix: &[],
        tail: &tail,
    };
    let body = "schema=crucible-runtime-trace-summary-v1\nbytes=24\nrows=2\nraw_sha256=raw\npost_8m_rows=1\npost_8m_normalized_sha256=normalized\npost_8m_first=[]\npost_8m_tail=[]\n";
    let record = NativePluginFlightDiagnostic::ReferenceTrace(summary);
    assert_eq!(record.channel(), NativeFlightOutputChannel::StandardOutput);
    assert_eq!(
        record.to_string(),
        format!(
            "PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_BEGIN\n{body}PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_END\n"
        )
    );
    for (variant, name) in [
        (NativeRuntimeTraceVariant::Reference, "REFERENCE"),
        (NativeRuntimeTraceVariant::Hostile, "HOSTILE"),
    ] {
        let record = NativePluginFlightDiagnostic::RuntimeTrace { variant, summary };
        assert_eq!(record.channel(), NativeFlightOutputChannel::StandardError);
        assert_eq!(
            record.to_string(),
            format!(
                "PRODUCTION_PLUGIN_RUNTIME_TRACE_{name}_SUMMARY_BEGIN\n{body}PRODUCTION_PLUGIN_RUNTIME_TRACE_{name}_SUMMARY_END\n"
            )
        );
    }
    let record = NativePluginFlightDiagnostic::RuntimeComparison("exact comparison");
    assert_eq!(record.channel(), NativeFlightOutputChannel::StandardError);
    assert_eq!(
        record.to_string(),
        "production_runtime_trace_comparison=exact comparison\n"
    );
}

#[test]
fn block_recovery_and_accepted_assignment_rows_keep_their_original_order() {
    let record = NativePluginFlightDiagnostic::BlockRecovery(NativeBlockRecoveryObservation {
        template_generation: 5,
        recovery_started_tick: 1,
        recovery_nanos: 2,
        pause_logical_icount: 3,
        pause_raw_icount: 4,
    });
    assert_eq!(
        record.to_string(),
        "block_recovery_hot_fork_subflight=true\nblock_recovery_start_tick=1\nblock_recovery_nanos=2\nblock_recovery_write_completed=true\nblock_recovery_pause_logical_icount=3\nblock_recovery_pause_raw_icount=4\nhot_fork_template_generation=5\nhot_fork_template_draining=true\nhot_fork_template_prepared=true\nhot_fork_preparation_order=block-recovery-settled,draining,prepared\n"
    );
    assert_eq!(
        NativePluginFlightDiagnostic::AcceptedAssignment.to_string(),
        "gate=gate:production-rust-plugin-flight\nproduction_accepted_assignment=true\n"
    );
}

#[test]
fn partition_and_diagnostic_mode_records_preserve_their_native_fields() {
    let initial = NativePluginFlightDiagnostic::PartitionInitial {
        variant: NativePartitionVariant::Coarse,
        logical: 11,
        raw: 12,
        bias: 13,
        rr_vcpu: 1,
        rr_position: 2,
        rr_quantum: 4096,
    };
    assert_eq!(
        initial.to_string(),
        "phase4_partition_initial variant=coarse logical=11 raw=12 bias=13 rr=1/2/4096\n"
    );
    let step = NativePluginFlightDiagnostic::PartitionStep {
        variant: NativePartitionVariant::Fine,
        target: 10,
        projected: true,
        outcome: &AdvanceOutcome::ReachedHorizon,
        logical: 11,
        raw: 12,
        bias: 13,
        rr_vcpu: 1,
        rr_position: 2,
        rr_quantum: 4096,
    };
    assert_eq!(
        step.to_string(),
        "phase4_partition_step variant=fine target=10 projected=true outcome=ReachedHorizon logical=11 raw=12 bias=13 rr=1/2/4096\n"
    );
    let matched = NativePluginFlightDiagnostic::PartitionMatched {
        target: 10,
        coarse_steps: 2,
        fine_steps: 3,
        span: 1_000_000,
    };
    assert_eq!(
        matched.to_string(),
        "phase4_partition_exact_match=true target=10 coarse_steps=2 fine_steps=3\nphase4_partition_span_ps=1000000\n"
    );
    assert_eq!(
        NativePluginFlightDiagnostic::Mode(NativeFlightDiagnosticMode::PartitionProbe).to_string(),
        "diagnostic_mode=phase4-partition-probe\n"
    );
    assert_eq!(
        NativePluginFlightDiagnostic::Mode(NativeFlightDiagnosticMode::BlockRecoveryOnly)
            .to_string(),
        "diagnostic_mode=block-recovery-only\n"
    );
    assert_eq!(NativePluginFlightDiagnostic::Pass.to_string(), "PASS\n");
}
