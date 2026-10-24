//! Defines borrowed native assertion records and their canonical transcript.
//!
//! Records contain observations, never a Source, operation guard, file or native
//! return certificate. The application owns synchronous standard-stream I/O.
//! Formatting borrows the existing evidence rather than allocating a transcript.

use std::collections::VecDeque;
use std::fmt::{self, Write};

use crucible_engine::AdvanceOutcome;
use crucible_qemu_host::QemuRuntimeDeterminismTraceRecord;

/// Performs application-owned output for one borrowed diagnostic record.
///
/// The callback captures no worker state or additional resource owner. Its
/// containing input body is admitted before allocation and worker birth.
/// Applications retain responsibility for their standard streams' supervision.
pub type NativePluginFlightOutput =
    for<'a> fn(NativePluginFlightDiagnostic<'a>) -> std::io::Result<()>;

/// Selects an existing application standard stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeFlightOutputChannel {
    /// Ordinary assertion rows and the reference trace summary.
    StandardOutput,
    /// Early runtime comparison evidence retained on later assertion failure.
    StandardError,
}

/// Identifies a runtime comparison variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRuntimeTraceVariant {
    /// The reference run.
    Reference,
    /// The host-preempted run.
    Hostile,
}

/// Identifies a post-selection partition schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePartitionVariant {
    /// The coarse partition schedule.
    Coarse,
    /// The fine partition schedule.
    Fine,
}

impl NativePartitionVariant {
    fn name(self) -> &'static str {
        match self {
            Self::Coarse => "coarse",
            Self::Fine => "fine",
        }
    }
}

/// Identifies an explicitly selected diagnostic program mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeFlightDiagnosticMode {
    /// Compares coarse and fine post-selection schedules.
    PartitionProbe,
    /// Runs only the existing block-recovery subflight.
    BlockRecoveryOnly,
}

/// Borrows the complete bounded public portion of a validated runtime trace.
#[derive(Clone, Copy, Debug)]
pub struct NativeRuntimeTraceSummary<'a> {
    /// Number of authenticated raw bytes.
    pub bytes: u64,
    /// Number of authenticated raw rows.
    pub rows: u64,
    /// Existing full-file SHA-256 identity, distinct from RAM identity.
    pub raw_sha256: &'a str,
    /// Number of normalized rows after the selected boundary.
    pub post_boundary_rows: u64,
    /// Existing normalized trace identity after the boundary.
    pub post_boundary_sha256: &'a str,
    /// Original bounded first-row context.
    pub prefix: &'a [QemuRuntimeDeterminismTraceRecord],
    /// Original bounded trailing-row context.
    pub tail: &'a VecDeque<QemuRuntimeDeterminismTraceRecord>,
}

impl fmt::Display for NativeRuntimeTraceSummary<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(output, "schema=crucible-runtime-trace-summary-v1")?;
        writeln!(output, "bytes={}", self.bytes)?;
        writeln!(output, "rows={}", self.rows)?;
        writeln!(output, "raw_sha256={}", self.raw_sha256)?;
        writeln!(output, "post_8m_rows={}", self.post_boundary_rows)?;
        writeln!(
            output,
            "post_8m_normalized_sha256={}",
            self.post_boundary_sha256
        )?;
        writeln!(output, "post_8m_first={:?}", self.prefix)?;
        writeln!(output, "post_8m_tail={:?}", self.tail)
    }
}

/// Describes the observed native timer callback without carrying its authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeFlightTimerObservation {
    /// Original native process generation.
    pub generation: u64,
    /// Armed deadline in picoseconds.
    pub armed_deadline_ps: u64,
    /// Armed deadline in scheduler ticks.
    pub armed_deadline_tick: u64,
    /// Native retirement step in picoseconds.
    pub retirement_step_ps: u64,
    /// Raw instruction count when armed.
    pub armed_raw_icount: u64,
    /// Native callback's expiration in picoseconds.
    pub fired_expire_ps: u64,
    /// Native virtual clock when fired.
    pub fired_virtual_ps: u64,
    /// Raw instruction count when fired.
    pub fired_raw_icount: u64,
    /// Published wake tick.
    pub published_wake_tick: u64,
    /// Tick observed after wake.
    pub post_wake_tick: u64,
    /// Original callback completion field.
    pub completed: u32,
    /// Original reserved field.
    pub reserved: u32,
}

/// Borrows the validated instruction window and idle-wake assertion values.
#[derive(Clone, Copy, Debug)]
pub struct NativeFourVcpuDiagnostic<'a> {
    /// Number of compared native runs.
    pub runs: usize,
    /// Number of reference boundary samples.
    pub samples: usize,
    /// Total actual on-demand acknowledgements.
    pub acknowledgements: usize,
    /// Configured round-robin quantum.
    pub rr_switch_quantum: u64,
    /// Picoseconds per retired instruction.
    pub ticks_per_instruction: u64,
    /// Lower fractional-phase target.
    pub fractional_target: u64,
    /// Lower instruction-exact target.
    pub lower_target: u64,
    /// Upper instruction-exact target.
    pub upper_target: u64,
    /// Owning vCPU at the lower target.
    pub lower_rr_vcpu: u32,
    /// Owning vCPU at the upper target.
    pub upper_rr_vcpu: u32,
    /// Round-robin position at the lower target.
    pub lower_rr_position: u64,
    /// Round-robin position at the upper target.
    pub upper_rr_position: u64,
    /// Original changed-component names, emitted without joining an allocation.
    pub changed_components: &'a [String],
    /// Original first differing state component.
    pub first_differing_state_component: &'a str,
    /// Original owning-vCPU projection name.
    pub owning_vcpu_state_projection: &'a str,
    /// Authenticated setup marker coordinate.
    pub setup_marker_icount: u64,
    /// Original timer observation.
    pub timer: NativeFlightTimerObservation,
}

/// Contains the observed values of the real block-recovery subflight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBlockRecoveryObservation {
    /// Original prepared template generation.
    pub template_generation: u64,
    /// Logical recovery start coordinate.
    pub recovery_started_tick: u64,
    /// Modeled recovery duration in nanoseconds.
    pub recovery_nanos: u64,
    /// Logical instruction count at the actual pause.
    pub pause_logical_icount: u64,
    /// Raw instruction count at the actual pause.
    pub pause_raw_icount: u64,
}

/// Borrows one canonical diagnostic emitted by the native assertion program.
///
/// Success records are emitted by the driver only after their corresponding
/// assertions. Rendering a record supplies no execution or return authority.
#[derive(Clone, Copy, Debug)]
pub enum NativePluginFlightDiagnostic<'a> {
    /// The bounded reference summary is available on standard output.
    ReferenceTrace(NativeRuntimeTraceSummary<'a>),
    /// Early reference or hostile trace context is available on standard error.
    RuntimeTrace {
        /// The original compared variant.
        variant: NativeRuntimeTraceVariant,
        /// The complete bounded trace summary.
        summary: NativeRuntimeTraceSummary<'a>,
    },
    /// The existing full-spool runtime comparison has completed.
    RuntimeComparison(&'a str),
    /// The four-vCPU instruction, preemption and timer assertions completed.
    FourVcpu(&'a NativeFourVcpuDiagnostic<'a>),
    /// The real block-recovery and template preparation assertions completed.
    BlockRecovery(NativeBlockRecoveryObservation),
    /// An explicitly selected diagnostic mode is active.
    Mode(NativeFlightDiagnosticMode),
    /// The partition comparison's initial state is observable.
    PartitionInitial {
        /// Original partition schedule.
        variant: NativePartitionVariant,
        /// Logical coordinate.
        logical: u64,
        /// Raw coordinate.
        raw: u64,
        /// Original logical/raw bias.
        bias: u64,
        /// Original round-robin vCPU.
        rr_vcpu: u32,
        /// Original round-robin position.
        rr_position: u64,
        /// Original round-robin quantum.
        rr_quantum: u64,
    },
    /// One original bounded partition step is observable.
    PartitionStep {
        /// Original partition schedule.
        variant: NativePartitionVariant,
        /// Requested target.
        target: u64,
        /// Whether the scheduler projected a safe frontier.
        projected: bool,
        /// Original observed outcome.
        outcome: &'a AdvanceOutcome,
        /// Logical coordinate.
        logical: u64,
        /// Raw coordinate.
        raw: u64,
        /// Original logical/raw bias.
        bias: u64,
        /// Original round-robin vCPU.
        rr_vcpu: u32,
        /// Original round-robin position.
        rr_position: u64,
        /// Original round-robin quantum.
        rr_quantum: u64,
    },
    /// Both actual partition schedules reached identical exact state.
    PartitionMatched {
        /// Shared exact target.
        target: u64,
        /// Original coarse step count.
        coarse_steps: usize,
        /// Original fine step count.
        fine_steps: usize,
        /// Existing post-selection span.
        span: u64,
    },
    /// The selected diagnostic assertions completed.
    Pass,
    /// The actual accepted worker observed successful Source retirement.
    AcceptedAssignment,
}

impl NativePluginFlightDiagnostic<'_> {
    /// Selects the existing stream required by this record's transcript contract.
    #[must_use]
    pub fn channel(&self) -> NativeFlightOutputChannel {
        match self {
            Self::RuntimeTrace { .. } | Self::RuntimeComparison(_) => {
                NativeFlightOutputChannel::StandardError
            }
            _ => NativeFlightOutputChannel::StandardOutput,
        }
    }
}

impl fmt::Display for NativePluginFlightDiagnostic<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceTrace(summary) => write!(
                output,
                "PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_BEGIN\n{summary}PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_END\n"
            ),
            Self::RuntimeTrace { variant, summary } => {
                let variant = match variant {
                    NativeRuntimeTraceVariant::Reference => "REFERENCE",
                    NativeRuntimeTraceVariant::Hostile => "HOSTILE",
                };
                write!(
                    output,
                    "PRODUCTION_PLUGIN_RUNTIME_TRACE_{variant}_SUMMARY_BEGIN\n{summary}PRODUCTION_PLUGIN_RUNTIME_TRACE_{variant}_SUMMARY_END\n"
                )
            }
            Self::RuntimeComparison(report) => {
                writeln!(output, "production_runtime_trace_comparison={report}")
            }
            Self::FourVcpu(report) => fmt::Display::fmt(report, output),
            Self::BlockRecovery(report) => {
                writeln!(output, "block_recovery_hot_fork_subflight=true")?;
                writeln!(
                    output,
                    "block_recovery_start_tick={}",
                    report.recovery_started_tick
                )?;
                writeln!(output, "block_recovery_nanos={}", report.recovery_nanos)?;
                writeln!(output, "block_recovery_write_completed=true")?;
                writeln!(
                    output,
                    "block_recovery_pause_logical_icount={}",
                    report.pause_logical_icount
                )?;
                writeln!(
                    output,
                    "block_recovery_pause_raw_icount={}",
                    report.pause_raw_icount
                )?;
                writeln!(
                    output,
                    "hot_fork_template_generation={}",
                    report.template_generation
                )?;
                output.write_str("hot_fork_template_draining=true\nhot_fork_template_prepared=true\nhot_fork_preparation_order=block-recovery-settled,draining,prepared\n")
            }
            Self::Mode(mode) => writeln!(
                output,
                "diagnostic_mode={}",
                match mode {
                    NativeFlightDiagnosticMode::PartitionProbe => "phase4-partition-probe",
                    NativeFlightDiagnosticMode::BlockRecoveryOnly => "block-recovery-only",
                }
            ),
            Self::PartitionInitial {
                variant,
                logical,
                raw,
                bias,
                rr_vcpu,
                rr_position,
                rr_quantum,
            } => writeln!(
                output,
                "phase4_partition_initial variant={} logical={logical} raw={raw} bias={bias} rr={rr_vcpu}/{rr_position}/{rr_quantum}",
                variant.name()
            ),
            Self::PartitionStep {
                variant,
                target,
                projected,
                outcome,
                logical,
                raw,
                bias,
                rr_vcpu,
                rr_position,
                rr_quantum,
            } => writeln!(
                output,
                "phase4_partition_step variant={} target={target} projected={projected} outcome={outcome:?} logical={logical} raw={raw} bias={bias} rr={rr_vcpu}/{rr_position}/{rr_quantum}",
                variant.name()
            ),
            Self::PartitionMatched {
                target,
                coarse_steps,
                fine_steps,
                span,
            } => write!(
                output,
                "phase4_partition_exact_match=true target={target} coarse_steps={coarse_steps} fine_steps={fine_steps}\nphase4_partition_span_ps={span}\n"
            ),
            Self::Pass => output.write_str("PASS\n"),
            Self::AcceptedAssignment => output.write_str(
                "gate=gate:production-rust-plugin-flight\nproduction_accepted_assignment=true\n",
            ),
        }
    }
}

impl fmt::Display for NativeFourVcpuDiagnostic<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("rust_plugin_loaded=true\n")?;
        writeln!(output, "diskless_multiboot_runs={}", self.runs)?;
        output.write_str("fingerprint_flight_variants=reference,host-preempted\nvcpu_count=4\n")?;
        writeln!(output, "rr_switch_quantum={}", self.rr_switch_quantum)?;
        writeln!(output, "sample_count={}", self.samples)?;
        output.write_str("sample_target_picoseconds=2000000,2000001,2000051,4000000,8000000\nsample_stream_restart_identical=true\n")?;
        writeln!(
            output,
            "on_demand_worker_acknowledgements={}",
            self.acknowledgements
        )?;
        output.write_str("on_demand_boundary_stream_bit_identical=true\n")?;
        writeln!(
            output,
            "instruction_exact_window_lower_picoseconds={}",
            self.lower_target
        )?;
        writeln!(
            output,
            "instruction_exact_window_upper_picoseconds={}",
            self.upper_target
        )?;
        writeln!(
            output,
            "instruction_exact_window_width_picoseconds={}",
            self.ticks_per_instruction
        )?;
        writeln!(
            output,
            "fractional_phase_window_lower_picoseconds={}",
            self.fractional_target
        )?;
        writeln!(
            output,
            "fractional_phase_window_upper_picoseconds={}",
            self.lower_target
        )?;
        output.write_str("fractional_phase_no_retirement=true\nfractional_phase_timer_projection_changed=true\nfractional_phase_fingerprint_changed=true\ninstruction_exact_raw_retirement_successor=true\n")?;
        writeln!(
            output,
            "instruction_exact_lower_rr_vcpu={}",
            self.lower_rr_vcpu
        )?;
        writeln!(
            output,
            "instruction_exact_upper_rr_vcpu={}",
            self.upper_rr_vcpu
        )?;
        writeln!(
            output,
            "instruction_exact_lower_rr_position={}",
            self.lower_rr_position
        )?;
        writeln!(
            output,
            "instruction_exact_upper_rr_position={}",
            self.upper_rr_position
        )?;
        output.write_str(
            "instruction_exact_rr_successor=true\ninstruction_exact_changed_components=",
        )?;
        for (index, component) in self.changed_components.iter().enumerate() {
            if index != 0 {
                output.write_char(',')?;
            }
            output.write_str(component)?;
        }
        output.write_char('\n')?;
        writeln!(
            output,
            "instruction_exact_first_differing_state_component={}",
            self.first_differing_state_component
        )?;
        writeln!(
            output,
            "instruction_exact_owning_vcpu_state_projection={}",
            self.owning_vcpu_state_projection
        )?;
        output.write_str("instruction_exact_state_projection_changed=true\ninstruction_exact_fingerprint_changed=true\ninstruction_exact_localization=one-instruction-window\nbounded_scheduler_preemption_applied=true\npending_quantum_preemption_certified=true\nscheduler_preemption_mailbox_decisions=2\nscheduler_vcpu_switch_applied=true\nscheduler_interrupt_applied=true\nreadiness_setup_marker_authenticated=true\n")?;
        writeln!(
            output,
            "readiness_setup_marker_icount={}",
            self.setup_marker_icount
        )?;
        output.write_str("all_vcpus_halted_observed=true\nexact_timer_deadline_observed=true\nqueued_idle_wake_reached_exact_deadline=true\nactual_virtual_timer_fire_authenticated=true\n")?;
        writeln!(output, "timer_witness_generation={}", self.timer.generation)?;
        writeln!(
            output,
            "timer_witness_armed_deadline_ps={}",
            self.timer.armed_deadline_ps
        )?;
        writeln!(
            output,
            "timer_witness_armed_deadline_tick={}",
            self.timer.armed_deadline_tick
        )?;
        writeln!(
            output,
            "timer_witness_ticks_per_instruction={}",
            self.ticks_per_instruction
        )?;
        writeln!(
            output,
            "timer_witness_retirement_step_ps={}",
            self.timer.retirement_step_ps
        )?;
        writeln!(
            output,
            "timer_witness_armed_raw_icount={}",
            self.timer.armed_raw_icount
        )?;
        writeln!(
            output,
            "timer_witness_fired_expire_ps={}",
            self.timer.fired_expire_ps
        )?;
        writeln!(
            output,
            "timer_witness_fired_virtual_ps={}",
            self.timer.fired_virtual_ps
        )?;
        writeln!(
            output,
            "timer_witness_fired_raw_icount={}",
            self.timer.fired_raw_icount
        )?;
        writeln!(
            output,
            "timer_witness_published_wake_tick={}",
            self.timer.published_wake_tick
        )?;
        writeln!(
            output,
            "timer_witness_post_wake_tick={}",
            self.timer.post_wake_tick
        )?;
        writeln!(output, "timer_witness_completed={}", self.timer.completed)?;
        writeln!(output, "timer_witness_reserved={}", self.timer.reserved)?;
        output.write_str("idle_wake_stream_restart_identical=true\ncomponent_failures=0\nper_vcpu_register_files_present=true\nsample_logical_picoseconds_equal_target=true\n")
    }
}

#[cfg(test)]
mod tests;
