//! Opt-in post-selection step-partition comparison for the live QEMU flight.
//!
//! This uses the flight's authenticated selectable reply and timer wake as a
//! common starting state. Each variant boots the same guest and splits the
//! first bounded post-wake interval into a different ceiling schedule: one
//! coarse step, 250 ns steps, alternating `R - 1` and `R` bounds, 10 ns steps,
//! and seeded odd-picosecond steps. A ceiling is an upper bound (RFC-0010
//! SCHED-12), so every schedule must reach the same final stop, raw count,
//! sample and fingerprint. A backend that credited the gap below any ceiling
//! would move the guest clock differently per schedule. This compares the
//! post-wake interval, including safe idle projections, not the campaign
//! checkpoint interval or its oracle.

use super::*;

// The next physical stop occurs this measured 1 us after the authenticated
// timer wake. Smaller ceilings may project a safe frontier while QEMU is parked.
pub(super) const POST_SELECTION_SPAN_PS: u64 = 1_000_000;
pub(super) const FINE_STEP_PS: u64 = 250_000;
const TEN_NANOSECOND_STEP_PS: u64 = 10_000;
const SEEDED_ODD_SEED: u64 = 0x5eed_0dd5_ce11_1265;
// Odd steps stay below this bound so the schedule has roughly 50 ceilings.
const SEEDED_ODD_MAX_STEP_PS: u64 = 40_001;
const MAX_PARTITION_BOUNDARIES: usize = 1024;

/// One ceiling schedule over the post-wake interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PartitionSchedule {
    /// One step to the end of the interval.
    Coarse,
    /// Fixed 250 ns steps.
    Fine,
    /// A bound one picosecond below each 250 ns rendezvous, then the
    /// rendezvous itself.
    AlternatingRendezvous,
    /// Fixed 10 ns steps.
    TenNanosecond,
    /// Seeded odd-picosecond steps that rarely fall on a retirement.
    SeededOdd,
}

impl PartitionSchedule {
    /// Every schedule, with the comparison reference first.
    pub(super) const ALL: [Self; 5] = [
        Self::Coarse,
        Self::Fine,
        Self::AlternatingRendezvous,
        Self::TenNanosecond,
        Self::SeededOdd,
    ];

    /// Returns the evidence label for this schedule.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Coarse => "coarse",
            Self::Fine => "fine",
            Self::AlternatingRendezvous => "alternating-rendezvous",
            Self::TenNanosecond => "ten-nanosecond",
            Self::SeededOdd => "seeded-odd",
        }
    }
}

#[derive(Debug)]
pub(super) struct PartitionProbe {
    schedule: PartitionSchedule,
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
    schedule: PartitionSchedule,
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

    let ceilings = partition_ceilings(wake_tick, POST_SELECTION_SPAN_PS, schedule)?;
    let mut steps: Vec<PartitionStep> = Vec::with_capacity(ceilings.len());
    for target in ceilings {
        loop {
            let step = step_toward(node, &steps, wake_tick, target)?;
            let finished = step.projected || step.settled;
            steps.push(step.step);
            if steps.len() > MAX_PARTITION_BOUNDARIES {
                return Err("partition probe exceeded its bounded physical stop count".into());
            }
            if finished {
                break;
            }
        }
    }

    Ok(PartitionProbe {
        schedule,
        initial_calibration,
        initial_sample,
        steps,
    })
}

struct ObservedStep {
    step: PartitionStep,
    projected: bool,
    settled: bool,
}

/// Takes one physical step toward `target` and samples where it stopped.
fn step_toward(
    node: &mut QemuNode,
    steps: &[PartitionStep],
    wake_tick: u64,
    target: u64,
) -> Result<ObservedStep, Box<dyn Error>> {
    let before = steps
        .last()
        .map_or(wake_tick, |step| step.calibration.logical_icount);
    let observation = SimulationBackend::step_to(node, VirtualTime { ticks: target })?;
    if observation.requested_ceiling.ticks != target
        || observation.reached.ticks < before
        || observation.reached.ticks > target
    {
        return Err(format!(
            "partition probe did not advance toward ceiling {target} from {before}: {observation:?}"
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

    // A settled busy step may stop below its ceiling; only an unsettled stop
    // that did not move is an idle park.
    let settled = observation.is_settled();
    let projected = if !settled && observation.reached.ticks == before {
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
        // A scheduler may project a safe frontier before the next exact
        // wake; QEMU's physical clock remains at the park point.
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
    Ok(ObservedStep {
        step: PartitionStep {
            target,
            projected,
            outcome: observation.outcome,
            calibration,
            sample,
            fingerprint,
        },
        projected,
        settled,
    })
}

/// Requires every schedule to reach the reference schedule's final state.
///
/// # Errors
///
/// Returns an error when the variants did not start from one authenticated
/// wake, or when any schedule's final stop, raw count, sample or fingerprint
/// differs from the reference.
pub(super) fn compare(probes: &[PartitionProbe]) -> Result<(), Box<dyn Error>> {
    let (reference, candidates) = probes
        .split_first()
        .ok_or("partition comparison has no variants")?;
    for probe in probes {
        print_probe(probe)?;
    }

    let reference_final = final_step(reference)?;
    for candidate in candidates {
        if candidate.initial_calibration != reference.initial_calibration
            || candidate.initial_sample != reference.initial_sample
        {
            return Err(format!(
                "partition variant {} did not share the authenticated wake state",
                candidate.schedule.label()
            )
            .into());
        }
        let candidate_final = final_step(candidate)?;
        if candidate_final.target != reference_final.target
            || candidate_final.projected != reference_final.projected
            || candidate_final.calibration != reference_final.calibration
            || candidate_final.sample != reference_final.sample
            || candidate_final.fingerprint != reference_final.fingerprint
        {
            return Err(format!(
                "post-selection QEMU step partition changed guest state: {}={reference_final:?} {}={candidate_final:?}",
                reference.schedule.label(),
                candidate.schedule.label(),
            )
            .into());
        }
    }

    let step_counts = probes
        .iter()
        .map(|probe| format!("{}:{}", probe.schedule.label(), probe.steps.len()))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "phase4_partition_exact_match=true target={} logical={} raw={} steps={step_counts}",
        reference_final.target,
        reference_final.calibration.logical_icount,
        reference_final.calibration.raw_icount,
    );
    println!(
        "phase4_partition_variants={}",
        probes
            .iter()
            .map(|probe| probe.schedule.label())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("phase4_partition_span_ps={POST_SELECTION_SPAN_PS}");
    println!("bound_frequency_independent=true");
    Ok(())
}

fn print_probe(probe: &PartitionProbe) -> Result<(), Box<dyn Error>> {
    let name = probe.schedule.label();
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
    Ok(())
}

/// Returns a schedule's final step, which must settle the interval's end.
fn final_step(probe: &PartitionProbe) -> Result<&PartitionStep, Box<dyn Error>> {
    let last = probe
        .steps
        .last()
        .ok_or_else(|| format!("{} partition omitted final step", probe.schedule.label()))?;
    if !last.projected && !settles_target(last.calibration.logical_icount, last.target) {
        return Err(format!(
            "{} partition final stop does not settle its target: {last:?}",
            probe.schedule.label()
        )
        .into());
    }
    Ok(last)
}

fn partition_ceilings(
    start: u64,
    span: u64,
    schedule: PartitionSchedule,
) -> Result<Vec<u64>, &'static str> {
    if span == 0 {
        return Err("partition span must be positive");
    }
    let target = start
        .checked_add(span)
        .ok_or("partition target overflowed")?;
    let ceilings = match schedule {
        PartitionSchedule::Coarse => vec![target],
        PartitionSchedule::Fine => fixed_steps(start, target, FINE_STEP_PS),
        PartitionSchedule::TenNanosecond => fixed_steps(start, target, TEN_NANOSECOND_STEP_PS),
        PartitionSchedule::AlternatingRendezvous => fixed_steps(start, target, FINE_STEP_PS)
            .into_iter()
            .flat_map(|rendezvous| [rendezvous - 1, rendezvous])
            .collect(),
        PartitionSchedule::SeededOdd => seeded_odd_steps(start, target),
    };
    Ok(ceilings)
}

fn fixed_steps(start: u64, target: u64, step: u64) -> Vec<u64> {
    let mut ceilings = Vec::new();
    let mut current = start;
    while current < target {
        current = current.saturating_add(step).min(target);
        ceilings.push(current);
    }
    ceilings
}

/// Draws odd steps from a fixed xorshift stream, ending exactly at `target`.
fn seeded_odd_steps(start: u64, target: u64) -> Vec<u64> {
    let mut state = SEEDED_ODD_SEED;
    let mut ceilings = Vec::new();
    let mut current = start;
    while current < target {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let step = (state % SEEDED_ODD_MAX_STEP_PS) | 1;
        current = current.saturating_add(step).min(target);
        ceilings.push(current);
    }
    ceilings
}

#[cfg(test)]
mod tests {
    use super::{
        FINE_STEP_PS, MAX_PARTITION_BOUNDARIES, POST_SELECTION_SPAN_PS, PartitionSchedule,
        partition_ceilings,
    };

    const START: u64 = 555_311_823_700;

    #[test]
    fn every_partition_ends_at_the_same_tick() {
        for schedule in PartitionSchedule::ALL {
            let ceilings = partition_ceilings(START, POST_SELECTION_SPAN_PS, schedule)
                .expect("finite partition");
            assert_eq!(ceilings.last(), Some(&(START + POST_SELECTION_SPAN_PS)));
            assert!(ceilings.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(ceilings.len() < MAX_PARTITION_BOUNDARIES);
        }
    }

    #[test]
    fn coarse_and_fine_partitions_keep_their_shapes() {
        assert_eq!(
            partition_ceilings(START, POST_SELECTION_SPAN_PS, PartitionSchedule::Coarse),
            Ok(vec![START + POST_SELECTION_SPAN_PS])
        );
        let fine = partition_ceilings(START, POST_SELECTION_SPAN_PS, PartitionSchedule::Fine)
            .expect("finite partition");
        assert_eq!(fine.len(), 4);
        assert_eq!(fine.first(), Some(&(START + FINE_STEP_PS)));
        assert!(partition_ceilings(START, 0, PartitionSchedule::Fine).is_err());
        assert!(
            partition_ceilings(
                u64::MAX - 1,
                POST_SELECTION_SPAN_PS,
                PartitionSchedule::Fine
            )
            .is_err()
        );
    }

    #[test]
    fn alternating_partition_bounds_one_picosecond_below_each_rendezvous() {
        let ceilings = partition_ceilings(
            START,
            POST_SELECTION_SPAN_PS,
            PartitionSchedule::AlternatingRendezvous,
        )
        .expect("finite partition");
        assert_eq!(ceilings.len(), 8);
        assert_eq!(ceilings[0], START + FINE_STEP_PS - 1);
        assert_eq!(ceilings[1], START + FINE_STEP_PS);
    }

    #[test]
    fn seeded_odd_partition_is_fixed_and_mostly_odd() {
        let first = partition_ceilings(START, POST_SELECTION_SPAN_PS, PartitionSchedule::SeededOdd)
            .expect("finite partition");
        let second =
            partition_ceilings(START, POST_SELECTION_SPAN_PS, PartitionSchedule::SeededOdd)
                .expect("finite partition");
        assert_eq!(first, second);
        // Every step but the clamped final one has an odd picosecond width.
        let mut previous = START;
        for ceiling in &first[..first.len() - 1] {
            assert_eq!((ceiling - previous) % 2, 1);
            previous = *ceiling;
        }
    }
}
