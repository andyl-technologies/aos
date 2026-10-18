//! Retains native boundary records and compares their exact semantic projections.
//!
//! The driver supplies observations from actual loaded nodes. These functions
//! compare them without issuing QMP commands, resource owners or scheduler work.

use super::*;
use std::sync::Arc;

use crucible_qemu_host::QemuNodeError;

pub(super) struct FlightRun {
    pub(super) boundaries: Vec<BoundaryEvidence>,
    pub(super) instruction_exact: InstructionExactEvidence,
    pub(super) idle: IdleEvidence,
    pub(super) partition_probe: Option<partition_probe::PartitionProbe>,
    pub(super) on_demand_acknowledgements: usize,
    pub(super) shutdown: QemuShutdownReport,
    pub(super) diagnostics: RuntimeDeterminismDiagnostics,
}

#[derive(Debug)]
pub(super) struct RuntimeDeterminismDiagnostics {
    pub(super) baseline: RuntimeDeterminismBaseline,
    pub(super) trace: runtime_trace::RuntimeTraceSummary,
}

#[derive(Debug)]
pub(super) struct RuntimeDeterminismBaseline {
    // A calibration refusal may be both the first cause and a retained passive
    // observation. Sharing that error preserves its identity in both views.
    pub(super) calibration: Result<QemuLogicalTimeCalibration, Arc<QemuNodeError>>,
    pub(super) idle_state: Result<QemuNodeIdleState, Arc<QemuNodeError>>,
    pub(super) timer_witness: Result<Option<QemuVirtualTimerFireWitness>, Arc<QemuNodeError>>,
    pub(super) rr_current_vcpu: u32,
    pub(super) rr_position_in_quantum: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BoundaryEvidence {
    pub(super) target: u64,
    pub(super) outcome: AdvanceOutcome,
    pub(super) fingerprint: ExecutionFingerprint,
    pub(super) sample: FingerprintSample,
    pub(super) calibration: QemuLogicalTimeCalibration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InstructionExactEvidence {
    pub(super) lower_target: u64,
    pub(super) upper_target: u64,
    pub(super) lower_rr_vcpu: u32,
    pub(super) upper_rr_vcpu: u32,
    pub(super) lower_rr_position: u64,
    pub(super) upper_rr_position: u64,
    pub(super) first_differing_state_component: String,
    pub(super) owning_vcpu_state_projection: String,
    pub(super) changed_components: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct IdleEvidence {
    pub(super) setup_marker_icount: u64,
    pub(super) halted_at: u64,
    pub(super) deadline: u64,
    pub(super) halted_fingerprint: ExecutionFingerprint,
    pub(super) halted_sample: FingerprintSample,
    pub(super) wake_outcome: AdvanceOutcome,
    pub(super) wake_fingerprint: ExecutionFingerprint,
    pub(super) wake_sample: FingerprintSample,
    pub(super) timer_fire: VirtualTimerFireEvidence,
    pub(super) on_demand_acknowledgements: usize,
}

/// Numeric certificate for the plugin-validated native timer callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VirtualTimerFireEvidence {
    pub(super) generation: u64,
    pub(super) armed_deadline_ps: u64,
    pub(super) armed_deadline_tick: u64,
    pub(super) retirement_step_ps: u64,
    pub(super) armed_raw_icount: u64,
    pub(super) fired_expire_ps: u64,
    pub(super) fired_virtual_ps: u64,
    pub(super) fired_raw_icount: u64,
    pub(super) published_wake_tick: u64,
    pub(super) post_wake_tick: u64,
    pub(super) completed: u32,
    pub(super) reserved: u32,
}

pub(super) fn idle_evidence_matches_across_runs(
    reference: &IdleEvidence,
    candidate: &IdleEvidence,
) -> bool {
    let mut normalized_reference = reference.clone();

    // Generation identifies one process-local publication, not guest state.
    normalized_reference.timer_fire.generation = candidate.timer_fire.generation;
    normalized_reference == *candidate
}

pub(super) fn compare_boundaries(
    variant: &str,
    reference: &[BoundaryEvidence],
    candidate: &[BoundaryEvidence],
) -> Result<(), NativeObservationError> {
    if reference.len() != candidate.len() {
        return Err(format!(
            "{variant}: boundary count differs: {} != {}",
            reference.len(),
            candidate.len()
        )
        .into());
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
            )
            .into());
        }
        if left.outcome != right.outcome {
            return Err(format!(
                "{variant}: boundary {index} window ({lower_bound},{}]: outcome differs",
                left.target
            )
            .into());
        }
        if left.fingerprint != right.fingerprint {
            return Err(format!(
                "{variant}: boundary {index} window ({lower_bound},{}]: execution_fingerprint differs",
                left.target
            ).into());
        }
        if let Some(component) = first_sample_difference(&left.sample, &right.sample) {
            return Err(format!(
                "{variant}: boundary {index} window ({lower_bound},{}]: {component} differs",
                left.target
            )
            .into());
        }
        if left.calibration != right.calibration {
            return Err(format!(
                "{variant}: boundary {index} window ({lower_bound},{}]: logical/raw calibration differs",
                left.target
            ).into());
        }
    }
    Ok(())
}

pub(super) fn instruction_exact_evidence(
    boundaries: &[BoundaryEvidence],
) -> Result<InstructionExactEvidence, NativeObservationError> {
    let lower = boundaries
        .iter()
        .find(|boundary| boundary.target == INSTRUCTION_EXACT_LOWER_TARGET)
        .ok_or_else(|| String::from("instruction-exact lower boundary is absent"))?;
    let upper = boundaries
        .iter()
        .find(|boundary| boundary.target == INSTRUCTION_EXACT_UPPER_TARGET)
        .ok_or_else(|| String::from("instruction-exact upper boundary is absent"))?;
    let fractional_lower = boundaries
        .iter()
        .find(|boundary| boundary.target == FRACTIONAL_PHASE_LOWER_TARGET)
        .ok_or_else(|| String::from("fractional-phase lower boundary is absent"))?;

    if upper.target != lower.target + FLIGHT_TICKS_PER_INSTRUCTION
        || lower.sample.sample_icount != lower.target
        || fractional_lower.sample.sample_icount != fractional_lower.target
        || upper.sample.sample_icount != upper.target
        || lower.calibration.logical_icount != lower.target
        || upper.calibration.logical_icount != upper.target
        || fractional_lower.calibration.logical_icount != fractional_lower.target
    {
        return Err(format!(
            "instruction-exact samples do not bind adjacent requested coordinates: lower={lower:?}, upper={upper:?}"
        ).into());
    }
    let fractional_differences = sample_differences(&fractional_lower.sample, &lower.sample);
    let mut expected_fractional_sample = fractional_lower.sample;
    expected_fractional_sample.sample_icount = lower.target;
    expected_fractional_sample.device_state_digest = lower.sample.device_state_digest;
    if lower.target != fractional_lower.target + 1
        || fractional_differences.len() != 2
        || fractional_differences[0] != "sample_icount"
        || fractional_differences[1] != "device_state_digest"
        || lower.sample != expected_fractional_sample
        || lower.calibration.raw_icount != fractional_lower.calibration.raw_icount
        || lower.fingerprint == fractional_lower.fingerprint
    {
        return Err(format!(
            "fractional-phase sample changed retired state or omitted timer projection: lower={fractional_lower:?}, upper={lower:?}, changed_components={fractional_differences:?}"
        ).into());
    }
    if Some(upper.calibration.raw_icount) != lower.calibration.raw_icount.checked_add(1) {
        return Err(format!(
            "instruction-exact samples do not advance raw retirement by one: lower={lower:?}, upper={upper:?}"
        ).into());
    }
    if lower.sample.rr_switch_quantum != RR_SWITCH_QUANTUM
        || upper.sample.rr_switch_quantum != RR_SWITCH_QUANTUM
        || !is_exact_rr_successor(&lower.sample, &upper.sample)
    {
        return Err(format!(
            "instruction-exact samples do not describe one exact RR successor: lower={lower:?}, upper={upper:?}"
        ).into());
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
    let owner_index = usize::try_from(lower.sample.rr_current_vcpu)?;
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
        )
        .into());
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

pub(super) fn validate_instruction_exact_shape_stability(
    lower: &FingerprintSample,
    upper: &FingerprintSample,
    owner_index: usize,
) -> Result<(), NativeObservationError> {
    if lower.vcpu_count != upper.vcpu_count
        || lower.component_failures != upper.component_failures
        || lower.ram_bytes != upper.ram_bytes
        || lower.device_state_bytes != upper.device_state_bytes
        || lower.device_state_sections != upper.device_state_sections
        || lower.device_state_schema_digest != upper.device_state_schema_digest
    {
        return Err(format!(
            "adjacent instruction samples changed invariant fingerprint shape: {:?}",
            sample_differences(lower, upper)
        )
        .into());
    }

    for (index, (lower_vcpu, upper_vcpu)) in lower.vcpus.iter().zip(&upper.vcpus).enumerate() {
        if lower_vcpu.register_file_bytes != upper_vcpu.register_file_bytes
            || lower_vcpu.retired_instruction_count != upper_vcpu.retired_instruction_count
            || (index != owner_index && lower_vcpu.register_digest != upper_vcpu.register_digest)
        {
            return Err(format!(
                "adjacent instruction samples changed invariant vCPU {index} state"
            )
            .into());
        }
    }
    Ok(())
}

pub(super) fn is_exact_rr_successor(lower: &FingerprintSample, upper: &FingerprintSample) -> bool {
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

pub(super) fn first_sample_difference(
    left: &FingerprintSample,
    right: &FingerprintSample,
) -> Option<String> {
    sample_differences(left, right).into_iter().next()
}

pub(super) fn sample_differences(
    left: &FingerprintSample,
    right: &FingerprintSample,
) -> Vec<String> {
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

pub(super) fn compare_runtime_determinism_diagnostics(
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
    let [(reference_name, reference), (candidate_name, candidate)] = variants;
    format!(
        "baselines=[{baselines}]; {}",
        runtime_trace::compare(
            reference_name,
            &reference.trace,
            candidate_name,
            &candidate.trace,
        )
        .unwrap_or_else(|error| format!("runtime_trace_comparison_error={error}"))
    )
}

pub(super) fn describe_runtime_baseline(baseline: &RuntimeDeterminismBaseline) -> String {
    format!(
        "calibration={:?},idle_state={:?},timer_witness={:?},rr_current_vcpu={},rr_position_in_quantum={}",
        baseline.calibration,
        baseline.idle_state,
        baseline.timer_witness,
        baseline.rr_current_vcpu,
        baseline.rr_position_in_quantum,
    )
}

pub(super) fn final_busy_raw_boundary(
    baseline: &RuntimeDeterminismBaseline,
) -> Result<u64, NativeObservationError> {
    let calibration = baseline
        .calibration
        .as_ref()
        .map_err(|error| NativeObservationError::Node(Arc::clone(error)))?;
    if calibration.logical_icount != TARGETS[TARGETS.len() - 1] {
        return Err(format!(
            "boundary_logical_picoseconds={} expected={}",
            calibration.logical_icount,
            TARGETS[TARGETS.len() - 1]
        )
        .into());
    }
    Ok(calibration.raw_icount)
}
