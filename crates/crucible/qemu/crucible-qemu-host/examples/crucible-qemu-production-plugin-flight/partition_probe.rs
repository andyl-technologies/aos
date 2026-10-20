//! Opt-in post-selection step-partition comparison for the live QEMU flight.
//!
//! This uses the flight's authenticated selectable reply and timer wake as a
//! common starting state. It compares the first bounded post-wake interval,
//! including safe idle projections, not the campaign checkpoint interval or its
//! oracle.

use super::*;

// The next physical stop occurs this measured 1 us after the authenticated
// timer wake. Smaller ceilings may project a safe frontier while QEMU is parked.
pub(super) const POST_SELECTION_SPAN_PS: u64 = 1_000_000;
pub(super) const FINE_STEP_PS: u64 = 250_000;
const MAX_PARTITION_BOUNDARIES: usize = 1024;

#[derive(Debug)]
pub(super) struct PartitionProbe {
    initial_calibration: QemuLogicalTimeCalibration,
    initial_sample: FingerprintSample,
    steps: Vec<PartitionStep>,
}

#[derive(Debug)]
struct PartitionStep {
    target: u64,
    projected: bool,
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
    let mut steps: Vec<PartitionStep> = Vec::with_capacity(ceilings.len());
    for target in ceilings {
        loop {
            let before = steps
                .last()
                .map_or(wake_tick, |step| step.calibration.logical_icount);
            let observation = SimulationBackend::step_to(node, VirtualTime { ticks: target })?;
            if observation.requested_ceiling.ticks != target
                || observation.reached.ticks < before
                || observation.reached.ticks > target
            {
                return Err(format!(
                    "partition probe did not advance toward exact ceiling {target} from {before}: {observation:?}"
                )
                .into());
            }
            let requests = node.drain_pending_selectable_requests()?;
            let outputs = SimulationBackend::drain_network_outputs(node)?;
            if !requests.is_empty() || !outputs.is_empty() {
                return Err(format!(
                    "partition probe encountered an unmodeled output: target={target} requests={requests:?} outputs={outputs:?}"
                )
                .into());
            }
            let projected = if observation.reached.ticks == before {
                let idle = node.idle_state()?;
                if !matches!(observation.outcome, AdvanceOutcome::Paused { at } if at.retired == before)
                    || idle.current_icount.retired != before
                    || !idle
                        .next_deadline
                        .is_some_and(|deadline| deadline.retired > target)
                {
                    return Err(format!(
                        "partition probe stalled without an exact future idle wake: target={target} observation={observation:?} idle={idle:?}"
                    )
                    .into());
                }
                // A scheduler may project a safe frontier before the next
                // exact wake; QEMU's physical clock remains at the park point.
                true
            } else {
                false
            };

            let fingerprint = node.execution_fingerprint()?;
            let sample = node.fingerprint_sample()?;
            let calibration = node.logical_time_calibration()?;
            if sample.sample_icount != observation.reached.ticks
                || calibration.logical_icount != observation.reached.ticks
            {
                return Err(format!(
                    "partition probe sampled an incoherent boundary: target={target} reached={} sample_tick={} calibration={calibration:?}",
                    observation.reached.ticks, sample.sample_icount
                )
                .into());
            }
            steps.push(PartitionStep {
                target,
                projected,
                outcome: observation.outcome,
                calibration,
                sample,
                fingerprint,
            });
            if steps.len() > MAX_PARTITION_BOUNDARIES {
                return Err("partition probe exceeded its bounded physical stop count".into());
            }
            if projected || observation.reached.ticks == target {
                break;
            }
        }
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
                "phase4_partition_step variant={name} target={} projected={} outcome={:?} logical={} raw={} bias={} rr={}/{}/{}",
                step.target,
                step.projected,
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
    if coarse_final.projected
        || fine_final.projected
        || coarse_final.calibration.logical_icount != coarse_final.target
        || fine_final.calibration.logical_icount != fine_final.target
        || coarse_final.target != fine_final.target
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
    println!("phase4_partition_span_ps={POST_SELECTION_SPAN_PS}");
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
    use super::{FINE_STEP_PS, partition_ceilings};

    #[test]
    fn coarse_and_fine_partitions_end_at_the_same_exact_tick() {
        let start = 555_311_823_700;
        let span = super::POST_SELECTION_SPAN_PS;
        assert_eq!(
            partition_ceilings(start, span, span),
            Ok(vec![start + span])
        );
        let fine = partition_ceilings(start, span, FINE_STEP_PS).expect("finite partition");
        assert_eq!(fine.len(), 4);
        assert_eq!(fine.first(), Some(&(start + FINE_STEP_PS)));
        assert_eq!(fine.last(), Some(&(start + span)));
        assert!(partition_ceilings(start, span, 0).is_err());
        assert!(partition_ceilings(u64::MAX - 1, span, span).is_err());
    }
}
