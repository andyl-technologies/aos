//! Drives one borrowed native node and returns only owned flight evidence.
//!
//! The caller holds the same Main projection throughout node operations. No
//! launcher, native guard or borrowed node leaves this callback.

use crate::NativeObservationError;
use std::sync::Arc;

use super::*;

pub(super) struct DrivenNode {
    pub(super) boundaries: Vec<BoundaryEvidence>,
    pub(super) instruction_exact: InstructionExactEvidence,
    pub(super) idle: IdleEvidence,
    pub(super) partition_probe: Option<partition_probe::PartitionProbe>,
    pub(super) shutdown: QemuShutdownReport,
    pub(super) runtime_baseline: RuntimeDeterminismBaseline,
}

pub(super) enum DrivenFlight {
    Complete(DrivenNode),
    IdleFailed {
        source: NativeObservationError,
        shutdown: Result<QemuShutdownReport, crucible_qemu_host::QemuNodeError>,
    },
    PartitionFailed {
        source: NativeObservationError,
        shutdown: Result<QemuShutdownReport, crucible_qemu_host::QemuNodeError>,
    },
}

pub(super) fn drive(
    node: &mut ObservedNativeNode<'_>,
    hostile: bool,
    partition_step_ps: Option<u64>,
) -> Result<DrivenFlight, NativeObservationError> {
    let preemption = hostile.then(BoundedSchedulerPreemptionEvidence::default);
    let mut boundaries = Vec::with_capacity(TARGETS.len());

    for (index, target) in TARGETS.into_iter().enumerate() {
        if target == 4_000_000
            && let Some(evidence) = &preemption
        {
            node.enable_bounded_scheduler_preemption(evidence.claim()?);
        }
        if target == 4_000_000 {
            let at = aligned_preemption_tick(node, 3_000_000, target)?;
            install_preemption(
                node,
                PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
                at,
            )?;
        } else if target == 8_000_000 {
            let at = aligned_preemption_tick(node, 6_000_000, target)?;
            install_preemption(
                node,
                PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: 2 },
                    irq: IrqVector { vector: 32 },
                },
                at,
            )?;
        }
        let observation = match SimulationBackend::step_to(node, VirtualTime { ticks: target }) {
            Ok(observation) => observation,
            Err(source) => {
                return Err(node_state_failure(
                    node,
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
        let calibration = node.logical_time_calibration()?;
        if calibration.logical_icount != target {
            return Err(format!(
                "logical/raw calibration did not bind busy target {target}: {calibration:?}"
            )
            .into());
        }
        boundaries.push(BoundaryEvidence {
            target,
            outcome,
            fingerprint,
            sample,
            calibration,
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
        calibration: node.logical_time_calibration().map_err(Arc::new),
        idle_state: node.idle_state().map_err(Arc::new),
        timer_witness: node.virtual_timer_fire_witness().map_err(Arc::new),
        rr_current_vcpu: final_busy_sample.rr_current_vcpu,
        rr_position_in_quantum: final_busy_sample.rr_position_in_quantum,
    };

    let idle = match probe_idle_wake(node) {
        Ok(idle) => idle,
        Err(source) => {
            let shutdown = node.shutdown_child();
            return Ok(DrivenFlight::IdleFailed { source, shutdown });
        }
    };

    let partition_probe = match partition_step_ps
        .map(|step| partition_probe::run(node, idle.deadline, step))
        .transpose()
    {
        Ok(probe) => probe,
        Err(source) => {
            let shutdown = node.shutdown_child();
            return Ok(DrivenFlight::PartitionFailed { source, shutdown });
        }
    };

    let shutdown = node.shutdown_child()?;
    if !shutdown.reaped || shutdown.leaked {
        return Err(format!(
            "QEMU did not cleanly reap after authenticated idle wake: {shutdown:?}"
        )
        .into());
    }
    Ok(DrivenFlight::Complete(DrivenNode {
        boundaries,
        instruction_exact,
        idle,
        partition_probe,
        shutdown,
        runtime_baseline,
    }))
}
