//! Canonical merge policy for production host-concurrent scheduler rounds.

use super::*;

pub(super) fn merge_host_concurrent_outcomes(
    outcomes: Vec<QuantumOutcome>,
) -> Result<QuantumOutcome, SchedulerError> {
    let mut outcomes = outcomes.into_iter();
    let mut merged = outcomes
        .next()
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("production host-concurrent round returned no scheduler outcome"),
        })?;
    for outcome in outcomes {
        merged.configuration = outcome.configuration;
        merged.frontier = outcome.frontier;
        merged.advanced_node = outcome.advanced_node;
        merged.resolved_events.extend(outcome.resolved_events);
        merged.decisions.extend(outcome.decisions);
        merged.discovered_choices.extend(outcome.discovered_choices);
        merged.event_log_entries.extend(outcome.event_log_entries);
        merged.event_log_segment_bytes = outcome.event_log_segment_bytes;
        merged.event_log_segment_text = outcome.event_log_segment_text;
        merged.event_log_segment_hash = outcome.event_log_segment_hash;
        merged.event_log_offset = outcome.event_log_offset;
        merged.scheduler_quiescence = outcome.scheduler_quiescence;
    }
    Ok(merged)
}
