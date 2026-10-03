//! Canonical trace composition for committed scenario-owned frame effects.

use std::collections::BTreeMap;

use super::*;
use crucible::model::{FaultReplayMode, ResolvedEffectTrace, ResolvedReplayWorkItem};

pub(in crate::vm_lifecycle) fn campaign_network_binding_name(name: &str) -> bool {
    matches!(name, "campaign-network-first" | "campaign-network-followup")
}

/// Separates campaign-owned effects from signal replay without changing either
/// owner's derivation fingerprint or the canonical trace representation.
pub(crate) fn split_campaign_network_trace(
    trace: ResolvedEffectTrace,
    selected_network: bool,
) -> Result<(ResolvedEffectTrace, Vec<ResolvedEffectRecord>), SchedulerError> {
    let mut signal = ResolvedEffectTrace {
        mode: trace.mode,
        work_items: Vec::new(),
        cursor: trace.cursor,
    };
    let mut campaign = Vec::new();
    if trace.cursor != 0 {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("fresh campaign replay trace already has a cursor"),
        });
    }
    for item in trace.work_items {
        let campaign_count = item
            .records
            .iter()
            .filter(|record| campaign_network_binding_name(record.binding.as_str()))
            .count();
        if campaign_count == 0 {
            signal.work_items.push(item);
            continue;
        }
        if !selected_network
            || campaign_count != item.records.len()
            || item.records.iter().any(|record| {
                record.derivation_fingerprint != item.derivation_fingerprint
                    || record.parameters_digest != item.derivation_fingerprint
            })
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "campaign network trace has mixed ownership or unauthenticated provenance",
                ),
            });
        }
        campaign.extend(item.records);
    }
    Ok((signal, campaign))
}

/// Adds committed campaign frame outcomes to the canonical resolved-effect trace.
///
/// # Errors
///
/// Returns an error if the combined trace exceeds authored bounds or has
/// inconsistent opportunity and effect evidence.
pub(crate) fn trace_with_campaign_network_records(
    trace: Option<ResolvedEffectTrace>,
    records: &[ResolvedEffectRecord],
    limits: FaultResourceLimits,
    mode: FaultReplayMode,
) -> Result<Option<ResolvedEffectTrace>, SchedulerError> {
    if records.is_empty() {
        return Ok(trace);
    }
    let mut trace = trace.unwrap_or(ResolvedEffectTrace {
        mode,
        work_items: Vec::new(),
        cursor: 0,
    });
    if trace.mode != mode {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("campaign network trace mode differs from its capture mode"),
        });
    }
    // Signal and campaign work may have the same scheduler coordinate. Their
    // derivation fingerprints authenticate different owners and must remain
    // distinct even when both mutate the same frame.
    let mut work_item_indexes: BTreeMap<_, usize> = BTreeMap::new();
    for record in records {
        let key = (
            record.coordinate,
            record.same_coordinate_sequence,
            record.opportunity,
            record.derivation_fingerprint,
        );
        if let Some(&index) = work_item_indexes.get(&key) {
            let item = &mut trace.work_items[index];
            item.records.push(record.clone());
        } else {
            work_item_indexes.insert(key, trace.work_items.len());
            trace.work_items.push(ResolvedReplayWorkItem {
                coordinate: record.coordinate,
                same_coordinate_sequence: record.same_coordinate_sequence,
                opportunity: record.opportunity,
                target: Some(record.target.clone()),
                operation: record.operation,
                direction: record.direction,
                phase: Some(record.phase),
                network_frame_key: record.network_frame_key,
                network_producer_direction_key: record.network_producer_direction_key,
                derivation_fingerprint: record.derivation_fingerprint,
                records: vec![record.clone()],
            });
        }
    }
    trace
        .work_items
        .sort_by_key(|item| (item.coordinate, item.same_coordinate_sequence));
    trace
        .validate(limits)
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("campaign network effects violate the resolved trace: {error}"),
        })?;
    Ok(Some(trace))
}
