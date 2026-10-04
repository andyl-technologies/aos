//! Compares ACK polling during one bounded, real Linux boot segment.
//!
//! Both fresh nodes receive the same grants and original readiness/idle checks.
//! Only an explicitly feature-enabled candidate caps completed-clamp polling;
//! host duration is advisory and never changes the scheduler's coordinates.

use super::*;
use crucible::{BackendError, BackendPhysicalStop, StepObservation};
use crucible_qemu::QemuNodeError;

const GRANTS: u64 = 20_000;
const STEP_PS: u64 = 10_000_000;
const INITIAL_PS: u64 = 8_000_000;
const FINAL_PS: u64 = 200_008_000_000;
const MAX_CONTROL_RETURNS: u64 = 40_000;

#[derive(Debug, thiserror::Error)]
pub(super) enum ProbeError {
    #[error("Linux ACK polling comparison requires the exact opt-in value 1")]
    InvalidMode,
    #[error("Linux ACK polling evidence refused: {0}")]
    InvalidEvidence(&'static str),
    #[error("Linux ACK polling canonical comparison refused: {0}")]
    CanonicalMismatch(String),
    #[error("original prelude comparison failed: {0}")]
    Prelude(String),
    #[error(transparent)]
    Node(Box<QemuNodeError>),
    #[error(transparent)]
    Backend(Box<BackendError>),
    #[error(transparent)]
    Flight(#[from] Box<dyn Error>),
}

impl From<QemuNodeError> for ProbeError {
    fn from(source: QemuNodeError) -> Self {
        Self::Node(Box::new(source))
    }
}

impl From<BackendError> for ProbeError {
    fn from(source: BackendError) -> Self {
        Self::Backend(Box::new(source))
    }
}

pub(super) fn requested() -> Result<bool, ProbeError> {
    mode(std::env::var_os(LINUX_ACK_PAIR_ENVIRONMENT).as_deref())
}

fn mode(value: Option<&std::ffi::OsStr>) -> Result<bool, ProbeError> {
    match value {
        None => Ok(false),
        Some(value) if value == "1" => Ok(true),
        Some(_) => Err(ProbeError::InvalidMode),
    }
}

#[derive(Debug)]
pub(super) struct BootProbe {
    canonical: CanonicalProbe,
    elapsed_us: u128,
}

#[derive(Debug, PartialEq, Eq)]
struct CanonicalProbe {
    control_returns: u64,
    projected_grants: u64,
    initial: BoundaryEvidence,
    final_boundary: BoundaryEvidence,
    transcript: String,
}

pub(super) fn run(
    factory: &mut LinuxQemuAttemptHostFactory,
    config: &QemuLiveNodeStepGateConfig,
    qemu: &Path,
) -> Result<(), ProbeError> {
    let baseline = run_once_with_boot_probe(factory, config, qemu, false, None, true)?;
    let candidate_config = config.clone().with_short_clamp_ack_poll_for_test();
    let candidate = run_once_with_boot_probe(factory, &candidate_config, qemu, false, None, true)?;
    compare_boundaries(
        "Linux boot ACK pair",
        &baseline.boundaries,
        &candidate.boundaries,
    )
    .map_err(ProbeError::Prelude)?;
    if !idle_evidence_matches_across_runs(&baseline.idle, &candidate.idle) {
        return Err(ProbeError::InvalidEvidence(
            "readiness or idle/wake changed",
        ));
    }
    let original = baseline
        .boot_probe
        .as_ref()
        .ok_or(ProbeError::InvalidEvidence("missing baseline"))?;
    let changed = candidate
        .boot_probe
        .as_ref()
        .ok_or(ProbeError::InvalidEvidence("missing candidate"))?;
    compare(original, changed)?;

    for (name, interval, evidence) in [
        ("baseline", 1000, original),
        ("ack-poll-100us", 100, changed),
    ] {
        println!("CRUCIBLE_LINUX_ACK_POLL_RESULT_BEGIN {name}");
        println!("PASS");
        println!("experiment_ack_poll_us={interval}");
        println!("host_segment_elapsed_us={}", evidence.elapsed_us);
        println!("grants={GRANTS}");
        println!("step_ps={STEP_PS}");
        println!("initial_ps={INITIAL_PS}");
        println!("final_scheduler_ps={FINAL_PS}");
        println!(
            "final_physical_ps={}",
            evidence.canonical.final_boundary.calibration.logical_icount
        );
        println!(
            "initial_raw={}",
            evidence.canonical.initial.calibration.raw_icount
        );
        println!(
            "final_raw={}",
            evidence.canonical.final_boundary.calibration.raw_icount
        );
        println!("control_returns={}", evidence.canonical.control_returns);
        println!("projected_grants={}", evidence.canonical.projected_grants);
        println!("transcript_blake3={}", evidence.canonical.transcript);
        println!(
            "initial_fingerprint={}",
            blake3::Hash::from_bytes(evidence.canonical.initial.fingerprint.hash.bytes).to_hex()
        );
        println!(
            "final_fingerprint={}",
            blake3::Hash::from_bytes(evidence.canonical.final_boundary.fingerprint.hash.bytes)
                .to_hex()
        );
        println!("clamp_guard_ms=1000");
        println!("advance_guard_s=300");
        println!("guest_profile=production-diskless-linux-four-vcpu");
        println!("readiness_idle_wake_equal=true");
        println!("canonical_results_equal=true");
        println!("owned_cleanup=complete");
        println!("qemu_cpu_time=unavailable");
        println!("CRUCIBLE_LINUX_ACK_POLL_RESULT_END {name}");
    }
    Ok(())
}

pub(super) fn probe(node: &mut QemuNode) -> Result<BootProbe, ProbeError> {
    let initial = boundary(node)?;
    if initial.target != INITIAL_PS {
        return Err(ProbeError::InvalidEvidence(
            "segment did not begin at original prelude",
        ));
    }
    let mut previous = initial.calibration;
    let mut control_returns = 0;
    let mut projected_grants = 0;
    let mut transcript = blake3::Hasher::new();
    transcript.update(b"crucible-linux-boot-ack-pair-v1\0");
    let started = diagnostic_clock();

    for index in 1..=GRANTS {
        let target = ceiling(index)?;
        loop {
            if control_returns == MAX_CONTROL_RETURNS {
                return Err(ProbeError::InvalidEvidence(
                    "control-return budget exhausted",
                ));
            }
            let observation = SimulationBackend::step_to(node, VirtualTime { ticks: target })?;
            control_returns += 1;
            let calibration = node.logical_time_calibration()?;
            let idle = node.idle_state()?;
            let projected = validate_step(previous, target, &observation, calibration, idle)?;
            let requests = node.drain_pending_selectable_requests()?;
            let outputs = SimulationBackend::drain_network_outputs(node)?;
            let events = SimulationBackend::drain_observable_events(node)?;
            if !requests.is_empty() || !outputs.is_empty() {
                return Err(ProbeError::InvalidEvidence(
                    "unmodeled request or network output during segment",
                ));
            }
            // Length framing binds every original event at its exact grant,
            // without retaining a growing transcript or logging every quantum.
            for scalar in [
                index,
                target,
                observation.reached.ticks,
                calibration.logical_icount,
                calibration.raw_icount,
                u64::from(projected),
            ] {
                transcript.update(&scalar.to_le_bytes());
            }
            transcript.update(&[match observation.outcome {
                AdvanceOutcome::ReachedHorizon => 0,
                AdvanceOutcome::Paused { .. } => 1,
            }]);
            transcript.update(&[match observation.physical_stop {
                BackendPhysicalStop::Horizon => 0,
                BackendPhysicalStop::UnclassifiedPause => 1,
                BackendPhysicalStop::Idle => 2,
                _ => return Err(ProbeError::InvalidEvidence("unmodeled physical output")),
            }]);
            transcript.update(&idle.current_icount.retired.to_le_bytes());
            transcript.update(&[u8::from(idle.next_deadline.is_some())]);
            transcript.update(
                &idle
                    .next_deadline
                    .map_or(0, |deadline| deadline.retired)
                    .to_le_bytes(),
            );
            hash_console_events(&mut transcript, &events, observation.reached.ticks)?;
            previous = calibration;
            if projected || observation.reached.ticks == target {
                projected_grants += u64::from(projected);
                break;
            }
        }
    }
    let elapsed_us = diagnostic_clock()
        .saturating_duration_since(started)
        .as_micros();
    let final_boundary = boundary(node)?;
    if final_boundary.calibration != previous
        || previous.raw_icount <= initial.calibration.raw_icount
    {
        return Err(ProbeError::InvalidEvidence(
            "segment omitted genuine Linux retirement",
        ));
    }
    Ok(BootProbe {
        canonical: CanonicalProbe {
            control_returns,
            projected_grants,
            initial,
            final_boundary,
            transcript: transcript.finalize().to_hex().to_string(),
        },
        elapsed_us,
    })
}

fn hash_console_events(
    transcript: &mut blake3::Hasher,
    events: &[ObservableEvent],
    reached: u64,
) -> Result<(), ProbeError> {
    transcript.update(&(events.len() as u64).to_le_bytes());
    for event in events {
        let ObservableEventPayload::ConsoleOutput { node, bytes } = event.payload() else {
            return Err(ProbeError::InvalidEvidence(
                "unmodeled observable during boot segment",
            ));
        };
        if node.name != FLIGHT_NODE_ID || event.at().ticks != reached {
            return Err(ProbeError::InvalidEvidence(
                "console observation has a foreign owner or boundary",
            ));
        }
        transcript.update(&event.at().ticks.to_le_bytes());
        transcript.update(&(bytes.len() as u64).to_le_bytes());
        transcript.update(bytes);
    }
    Ok(())
}

fn boundary(node: &mut QemuNode) -> Result<BoundaryEvidence, ProbeError> {
    let calibration = node.logical_time_calibration()?;
    let fingerprint = node.execution_fingerprint()?;
    let sample = node.fingerprint_sample()?;
    validate_sample(sample, calibration.logical_icount)?;
    Ok(BoundaryEvidence {
        target: calibration.logical_icount,
        outcome: AdvanceOutcome::Paused {
            at: Icount {
                retired: calibration.logical_icount,
            },
        },
        fingerprint,
        sample,
        calibration,
    })
}

fn ceiling(index: u64) -> Result<u64, ProbeError> {
    if !(1..=GRANTS).contains(&index) {
        return Err(ProbeError::InvalidEvidence(
            "grant index outside fixed segment",
        ));
    }
    index
        .checked_mul(STEP_PS)
        .and_then(|span| INITIAL_PS.checked_add(span))
        .ok_or(ProbeError::InvalidEvidence("grant ceiling overflowed"))
}

fn validate_step(
    previous: QemuLogicalTimeCalibration,
    target: u64,
    observation: &StepObservation,
    current: QemuLogicalTimeCalibration,
    idle: QemuNodeIdleState,
) -> Result<bool, ProbeError> {
    let physical = match observation.outcome {
        AdvanceOutcome::ReachedHorizon => target,
        AdvanceOutcome::Paused { at } => at.retired,
    };
    if observation.requested_ceiling.ticks != target
        || current.logical_icount != physical
        || physical < previous.logical_icount
        || physical > target
        || current.raw_icount < previous.raw_icount
        || observation.reached.ticks < physical
        || observation.reached.ticks > target
        || !observation.applied_preemptions.is_empty()
        || matches!(
            observation.physical_stop,
            BackendPhysicalStop::NetworkOutput
                | BackendPhysicalStop::GuestSelectable
                | BackendPhysicalStop::CampaignMarker
        )
    {
        return Err(ProbeError::InvalidEvidence("incoherent physical return"));
    }
    let projected = physical < target
        && idle.current_icount.retired == physical
        && idle
            .next_deadline
            .is_some_and(|deadline| deadline.retired > target)
        && matches!(observation.outcome, AdvanceOutcome::Paused { .. });
    if physical == previous.logical_icount && !projected {
        return Err(ProbeError::InvalidEvidence(
            "no progress without authenticated future idle wake",
        ));
    }
    if !projected && observation.reached.ticks != physical {
        return Err(ProbeError::InvalidEvidence("unproven scheduler projection"));
    }
    Ok(projected)
}

fn compare(baseline: &BootProbe, candidate: &BootProbe) -> Result<(), ProbeError> {
    if baseline.canonical != candidate.canonical {
        let original = &baseline.canonical;
        let changed = &candidate.canonical;
        let difference = if original.control_returns != changed.control_returns {
            String::from("control_returns")
        } else if original.projected_grants != changed.projected_grants {
            String::from("projected_grants")
        } else {
            compare_boundaries(
                "canonical segment",
                &[original.initial.clone(), original.final_boundary.clone()],
                &[changed.initial.clone(), changed.final_boundary.clone()],
            )
            .err()
            .unwrap_or_else(|| String::from("transcript_blake3"))
        };
        return Err(ProbeError::CanonicalMismatch(format!(
            "fresh Linux runs changed canonical segment evidence; difference={difference}; baseline=[{}]; candidate=[{}]",
            describe_canonical(original),
            describe_canonical(changed),
        )));
    }
    Ok(())
}

fn describe_canonical(evidence: &CanonicalProbe) -> String {
    // Boundary samples contain only fixed-size scalar/digest arrays. A genuine
    // transcript is a 64-character hash, never the original console payload.
    let transcript = evidence.transcript.chars().take(64).collect::<String>();
    format!(
        "control_returns={},projected_grants={},initial={:?},final_boundary={:?},transcript_blake3={transcript}",
        evidence.control_returns,
        evidence.projected_grants,
        evidence.initial,
        evidence.final_boundary,
    )
}

/// Measures the segment only; host time never selects guest state.
// crucible-lint: allow clippy-disallowed-method -- advisory wall time measures this controlled comparison only.
#[allow(clippy::disallowed_methods)]
fn diagnostic_clock() -> std::time::Instant {
    std::time::Instant::now()
}

#[cfg(test)]
#[path = "linux_ack_poll_tests.rs"]
mod tests;
