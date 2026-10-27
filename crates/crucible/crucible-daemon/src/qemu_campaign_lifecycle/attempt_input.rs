//! Pure validation of an attempt's continuation inputs and replayed start.
//!
//! A fresh attempt may continue earlier attempts only at their authenticated
//! stop frontiers, and may replay only start decisions the fresh path can
//! reproduce. These checks read the resolved attempt alone and run before any
//! lifecycle is started.

use super::*;

/// Controlled continuations of one attempt, each paired with its source origin.
///
/// Source origins are materialized from the decoded ancestry and share the
/// terminal origin's decision storage, so this owns them while lifecycle
/// factories borrow them through [`ValidatedAttemptContinuations::controls`].
#[derive(Debug, Default)]
pub(super) struct ValidatedAttemptContinuations {
    continuations: Vec<(AttemptContinuationInput, CrucibleAttemptOrigin)>,
}

impl ValidatedAttemptContinuations {
    /// Returns the modeled controls from the oldest source boundary through
    /// the current attempt.
    pub(super) fn controls(&self) -> Vec<QemuAttemptContinuation<'_>> {
        self.continuations
            .iter()
            .map(|(input, source)| QemuAttemptContinuation {
                input,
                source: source.reached(),
            })
            .collect()
    }
}

pub(super) fn validated_attempt_continuations(
    input: &CrucibleAttemptExecution,
) -> Result<ValidatedAttemptContinuations, ()> {
    let Some((origins, terminal_input)) = input.continuation_replay_basis() else {
        return input
            .attempt()
            .continuation_input()
            .is_none()
            .then(ValidatedAttemptContinuations::default)
            .ok_or(());
    };
    let mut continuations = Vec::new();
    let mut source: Option<CrucibleAttemptOrigin> = None;
    for origin in origins.iter() {
        let origin = origin.map_err(|_| ())?;
        if let Some(continuation_input) = origin.attempt().continuation_input() {
            let source = source.take().ok_or(())?;
            validate_source_frontier(continuation_input, &source)?;
            continuations.push((continuation_input.clone(), source));
        }
        source = Some(origin);
    }
    if let Some(continuation_input) = terminal_input {
        let source = source.ok_or(())?;
        validate_source_frontier(continuation_input, &source)?;
        continuations.push((continuation_input.clone(), source));
    }
    Ok(ValidatedAttemptContinuations { continuations })
}

/// Checks that a continuation starts exactly at its source origin's stop.
fn validate_source_frontier(
    continuation_input: &AttemptContinuationInput,
    source: &CrucibleAttemptOrigin,
) -> Result<(), ()> {
    let source_frontier_ticks = match (source.attempt().stop(), source.source_stop()) {
        (
            StopCondition::VirtualTimePicoseconds(requested),
            Some(crucible_campaign::StopOutcome::Reached(StopCondition::VirtualTimePicoseconds(
                reached,
            ))),
        ) if requested == reached => *reached,
        (
            StopCondition::Observation(condition),
            Some(crucible_campaign::StopOutcome::ObservationReached(proof)),
        ) if proof.condition() == condition => proof.boundary().frontier_picoseconds(),
        (
            requested @ StopCondition::Bounded { .. },
            Some(crucible_campaign::StopOutcome::BoundedPrimaryReached { stop, proof }),
        ) if requested == stop => proof.frontier_picoseconds(),
        (
            StopCondition::Bounded { primary, .. },
            Some(crucible_campaign::StopOutcome::ObservationReached(proof)),
        ) if matches!(primary.as_ref(), StopCondition::Observation(condition) if proof.condition() == condition) => {
            proof.boundary().frontier_picoseconds()
        }
        _ => return Err(()),
    };
    if source_frontier_ticks != continuation_input.source_frontier_ticks() {
        return Err(());
    }
    Ok(())
}

pub(super) fn unsupported_fresh_replay_decision(
    target: &Configuration,
    signal_fault_replay: &crucible_engine::SignalFaultCampaignReplayPlan,
) -> Option<usize> {
    if signal_fault_replay.target() != target {
        return Some(0);
    }
    let covered_signal_fault_overrides = signal_fault_replay
        .branches()
        .iter()
        .filter(|branch| branch.decisions().len() == 2)
        .map(|branch| branch.parent().len() + 1)
        .collect::<BTreeSet<_>>();
    target
        .schedule
        .decision_history()
        .iter()
        .enumerate()
        .find_map(|(index, decision)| match decision {
            Decision::Override(_) if covered_signal_fault_overrides.contains(&index) => None,
            Decision::Override(_) => Some(index),
            Decision::Selection(selection) => selection
                .selection()
                .map_or(true, |decoded| {
                    matches!(decoded.origin(), SelectionOrigin::ModelSample(_))
                        && !selection.is_app_random_model_sample()
                })
                .then_some(index),
            Decision::DeliveryOrder(_) | Decision::RngDraw(_) | Decision::Preemption(_) => None,
        })
}
