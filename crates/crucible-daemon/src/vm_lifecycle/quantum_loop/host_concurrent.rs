//! Canonical merge policy for production host-concurrent scheduler rounds.

use super::*;

pub(super) fn copy_host_concurrent_outcomes(
    outcomes: &[QuantumOutcome],
) -> Result<Vec<QuantumOutcome>, SchedulerError> {
    if outcomes.is_empty() {
        return Ok(Vec::new());
    }

    let _original = outcomes[0].event_log_custody.enter_decode_scope();
    let budget = crucible::owned_decode::require_current_child_budget()
        .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
    let _scope = budget.enter();
    let mut copies = Vec::new();
    crucible::owned_decode::reserve_vec(&mut copies, outcomes.len())
        .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
    let table_custody = crucible::EventLogOutputCustody::retain_current()?;
    for outcome in outcomes {
        let mut copy = outcome.try_clone_admitted()?;
        copy.event_log_custody = copy.event_log_custody.combine(&table_custody)?;
        copies.push(copy);
    }
    Ok(copies)
}

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
        merged.event_log_custody = merged
            .event_log_custody
            .combine(&outcome.event_log_custody)?;
        let _scope = merged.event_log_custody.enter_decode_scope();
        // Reserve every destination table before moving semantic output fields.
        crucible::owned_decode::reserve_vec(
            &mut merged.resolved_events,
            outcome.resolved_events.len(),
        )
        .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
        crucible::owned_decode::reserve_vec(&mut merged.decisions, outcome.decisions.len())
            .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
        crucible::owned_decode::reserve_vec(
            &mut merged.discovered_choices,
            outcome.discovered_choices.len(),
        )
        .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
        crucible::owned_decode::reserve_vec(
            &mut merged.event_log_entries,
            outcome.event_log_entries.len(),
        )
        .map_err(|source| crucible::EngineError::ArtifactDecodeAdmission { source })?;
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
