//! Coverage and assertion-proximity projection entry materialization.

use super::*;

pub(in super::super) fn event_log_coverage_entry(
    raw_index: usize,
    entry: &SchedulerEventLogEntry,
) -> Option<EventLogCoverageProjectionEntry> {
    let observation = match entry.payload() {
        SchedulerEventLogPayload::Observable(ObservableEventPayload::CoverageBlock {
            node,
            guest_pc,
            block_len,
            ..
        }) => EventLogCoverageObservation::BasicBlock {
            node: node.clone(),
            guest_pc: *guest_pc,
            block_len: *block_len,
        },
        SchedulerEventLogPayload::Observable(ObservableEventPayload::CoverageMarker {
            node,
            marker,
            ..
        }) => EventLogCoverageObservation::Named {
            node: node.clone(),
            marker: marker.clone(),
        },
        SchedulerEventLogPayload::ResolvedHappening(_)
        | SchedulerEventLogPayload::Decision(_)
        | SchedulerEventLogPayload::Observable(_)
        | SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::TriggerActionApplied(_)
        | SchedulerEventLogPayload::Diagnostic(_) => return None,
    };
    Some(EventLogCoverageProjectionEntry {
        raw_index,
        at: entry.time().icount.clone(),
        source: entry.source().clone(),
        observation,
    })
}

pub(in super::super) fn event_log_assertion_proximity_entry(
    raw_index: usize,
    entry: &SchedulerEventLogEntry,
) -> Option<EventLogAssertionProximityProjectionEntry> {
    let SchedulerEventLogPayload::Observable(ObservableEventPayload::AssertionProximity {
        assertion,
        quantifier,
        distance,
        node,
    }) = entry.payload()
    else {
        return None;
    };
    Some(EventLogAssertionProximityProjectionEntry {
        raw_index,
        at: entry.time().icount.clone(),
        source: entry.source().clone(),
        assertion: assertion.clone(),
        quantifier: *quantifier,
        distance: *distance,
        node: node.clone(),
    })
}

pub(in super::super) fn assertion_proximity_entry_is_better(
    candidate: &EventLogAssertionProximityProjectionEntry,
    current: &EventLogAssertionProximityProjectionEntry,
) -> bool {
    candidate
        .distance
        .cmp(&current.distance)
        .then_with(|| candidate.at.icount.retired.cmp(&current.at.icount.retired))
        .then_with(|| candidate.raw_index.cmp(&current.raw_index))
        .is_lt()
}

pub(in super::super) fn event_log_assertion_proximity_minimum_material(
    entry: &EventLogAssertionProximityProjectionEntry,
) -> String {
    let node_material = match &entry.node {
        Some(node) => format!(
            "node=some\nnode_len={}\nnode={}",
            node.name.len(),
            node.name
        ),
        None => String::from("node=none"),
    };
    format!(
        "assertion_len={}\nassertion={}\nquantifier={}\ndistance={}\n{}",
        entry.assertion.name.len(),
        entry.assertion.name,
        assertion_quantifier_kind_label(entry.quantifier),
        entry.distance,
        node_material,
    )
}

pub(in super::super) fn event_log_coverage_observation_material(
    entry: &EventLogCoverageProjectionEntry,
) -> String {
    match &entry.observation {
        EventLogCoverageObservation::BasicBlock {
            node,
            guest_pc,
            block_len,
        } => format!(
            "kind=basic_block\nnode_len={}\nnode={}\nguest_pc={guest_pc}\nblock_len={block_len}",
            node.name.len(),
            node.name
        ),
        EventLogCoverageObservation::Named { node, marker } => format!(
            "kind=named\nnode_len={}\nnode={}\nid_len={}\nid={}",
            node.name.len(),
            node.name,
            marker.name.len(),
            marker.name
        ),
    }
}
