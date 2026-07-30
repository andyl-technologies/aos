//! Canonical probabilistic decision recording during scheduler RESOLVE.

use super::*;

/// Records every probabilistic RESOLVE choice in canonical event order.
///
/// Only [`ScheduledEventPayload::ProbabilisticFault`] payloads produce decisions.
/// For each such event, this helper draws from the payload's seeded stream and
/// records the raw [`Decision::RngDraw`] followed by the derived
/// [`Decision::FaultFires`] outcome. Non-probabilistic events are ignored.
#[must_use]
pub fn resolve_probabilistic_decisions(
    configuration: Configuration,
    resolved_events: &[ScheduledEvent],
) -> SchedulerResolveDecisionRecord {
    record_probabilistic_decisions(DecisionRecorder::new(configuration), resolved_events)
}

pub(in crate::scheduler) fn resolve_probabilistic_decisions_from_seed(
    configuration: Configuration,
    resolved_events: &[ScheduledEvent],
    seed: Seed,
    positions: &DecisionRngState,
) -> SchedulerResolveDecisionRecord {
    record_probabilistic_decisions(
        DecisionRecorder::from_seed_and_positions(configuration, seed, positions),
        resolved_events,
    )
}

fn record_probabilistic_decisions(
    mut recorder: DecisionRecorder,
    resolved_events: &[ScheduledEvent],
) -> SchedulerResolveDecisionRecord {
    let mut decisions = Vec::new();

    for event in ordered_scheduled_events(resolved_events) {
        let ScheduledEventPayload::ProbabilisticFault(choice) = &event.payload else {
            continue;
        };

        let before = recorder.schedule().len();
        recorder.decide_fault_basis_points(
            event.key.virtual_time(),
            choice.fault.clone(),
            choice.stream.clone(),
            choice.rate,
        );
        decisions.extend_from_slice(&recorder.schedule().decisions()[before..]);
    }

    SchedulerResolveDecisionRecord {
        configuration: recorder.into_configuration(),
        decisions,
    }
}
