//! Opt-in post-selection step-partition comparison for the live QEMU flight.
//!
//! This uses the flight's authenticated selectable reply and timer wake as a
//! common starting state. It is a short analogue of the campaign checkpoint
//! interval, not a replacement for the exact guest-choice replay oracle.

use super::*;

// The archived Phase4 second-choice stop and checkpoint differ by this many
// logical picoseconds. One coarse RUN spans it; the thin-style path uses 10us.
pub(super) const POST_SELECTION_SPAN_PS: u64 = 73_202_050;
pub(super) const FINE_STEP_PS: u64 = 10_000_000;

#[derive(Debug)]
pub(super) struct PartitionProbe {
    initial_calibration: QemuLogicalTimeCalibration,
    initial_sample: FingerprintSample,
    steps: Vec<PartitionStep>,
}

#[derive(Debug)]
struct PartitionStep {
    target: u64,
    outcome: AdvanceOutcome,
    calibration: QemuLogicalTimeCalibration,
    sample: FingerprintSample,
    fingerprint: ExecutionFingerprint,
}

pub(super) fn run(
    node: &mut QemuNode,
    wake_tick: u64,
    step_ps: u64,
) -> Result<PartitionProbe, Box<dyn Error>> {
    let initial_calibration = node.logical_time_calibration()?;
    let initial_sample = node.fingerprint_sample()?;
    if initial_calibration.logical_icount != wake_tick || initial_sample.sample_icount != wake_tick
    {
        return Err(format!(
            "partition probe did not start at its authenticated wake: wake={wake_tick} calibration={initial_calibration:?} sample_tick={}",
            initial_sample.sample_icount
        )
        .into());
    }

    let ceilings = partition_ceilings(wake_tick, POST_SELECTION_SPAN_PS, step_ps)?;
    let mut steps = Vec::with_capacity(ceilings.len());
    for target in ceilings {
        let observation = SimulationBackend::step_to(node, VirtualTime { ticks: target })?;
        if observation.requested_ceiling.ticks != target || observation.reached.ticks != target {
            return Err(format!(
                "partition probe missed exact scheduler boundary {target}: {observation:?}"
            )
            .into());
        }

        let fingerprint = node.execution_fingerprint()?;
        let sample = node.fingerprint_sample()?;
        let calibration = node.logical_time_calibration()?;
        if sample.sample_icount != target || calibration.logical_icount != target {
            return Err(format!(
                "partition probe sampled an incoherent boundary: target={target} sample_tick={} calibration={calibration:?}",
                sample.sample_icount
            )
            .into());
        }
        steps.push(PartitionStep {
            target,
            outcome: observation.outcome,
            calibration,
            sample,
            fingerprint,
        });
    }

    Ok(PartitionProbe {
        initial_calibration,
        initial_sample,
        steps,
    })
}

pub(super) fn compare(
    coarse: &PartitionProbe,
    fine: &PartitionProbe,
) -> Result<(), Box<dyn Error>> {
    for (name, probe) in [("coarse", coarse), ("fine", fine)] {
        println!(
            "phase4_partition_initial variant={name} logical={} raw={} bias={} rr={}/{}/{}",
            probe.initial_calibration.logical_icount,
            probe.initial_calibration.raw_icount,
            probe.initial_calibration.offset()?,
            probe.initial_sample.rr_current_vcpu,
            probe.initial_sample.rr_position_in_quantum,
            probe.initial_sample.rr_switch_quantum,
        );
        for step in &probe.steps {
            println!(
                "phase4_partition_step variant={name} target={} outcome={:?} logical={} raw={} bias={} rr={}/{}/{}",
                step.target,
                step.outcome,
                step.calibration.logical_icount,
                step.calibration.raw_icount,
                step.calibration.offset()?,
                step.sample.rr_current_vcpu,
                step.sample.rr_position_in_quantum,
                step.sample.rr_switch_quantum,
            );
        }
    }

    if coarse.initial_calibration != fine.initial_calibration
        || coarse.initial_sample != fine.initial_sample
    {
        return Err("partition variants did not share the same authenticated wake state".into());
    }
    let coarse_final = coarse
        .steps
        .last()
        .ok_or("coarse partition omitted final step")?;
    let fine_final = fine
        .steps
        .last()
        .ok_or("fine partition omitted final step")?;
    if coarse_final.target != fine_final.target
        || coarse_final.calibration != fine_final.calibration
        || coarse_final.sample != fine_final.sample
        || coarse_final.fingerprint != fine_final.fingerprint
    {
        return Err(format!(
            "post-selection QEMU step partition changed exact state: coarse={coarse_final:?} fine={fine_final:?}"
        )
        .into());
    }
    println!(
        "phase4_partition_exact_match=true target={} coarse_steps={} fine_steps={}",
        coarse_final.target,
        coarse.steps.len(),
        fine.steps.len(),
    );
    Ok(())
}

fn partition_ceilings(start: u64, span: u64, step: u64) -> Result<Vec<u64>, &'static str> {
    if span == 0 || step == 0 {
        return Err("partition span and step must be positive");
    }
    let target = start
        .checked_add(span)
        .ok_or("partition target overflowed")?;
    let mut ceilings = Vec::new();
    let mut current = start;
    while current < target {
        current = current.saturating_add(step).min(target);
        ceilings.push(current);
    }
    Ok(ceilings)
}

#[cfg(test)]
mod tests {
    use super::partition_ceilings;

    #[test]
    fn coarse_and_fine_partitions_end_at_the_same_exact_tick() {
        let start = 555_311_823_700;
        let span = 73_202_050;
        assert_eq!(
            partition_ceilings(start, span, span),
            Ok(vec![start + span])
        );
        assert_eq!(
            partition_ceilings(start, span, 10_000_000),
            Ok(vec![
                start + 10_000_000,
                start + 20_000_000,
                start + 30_000_000,
                start + 40_000_000,
                start + 50_000_000,
                start + 60_000_000,
                start + 70_000_000,
                start + span,
            ])
        );
        assert!(partition_ceilings(start, span, 0).is_err());
        assert!(partition_ceilings(u64::MAX - 1, span, span).is_err());
    }
}
