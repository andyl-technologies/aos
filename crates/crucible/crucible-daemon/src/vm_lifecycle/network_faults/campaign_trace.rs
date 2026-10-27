//! Canonical trace composition for committed scenario-owned frame effects.
//!
//! The published resolved-effect trace interleaves two owners: the signal
//! runtime's work items and the campaign network log's work items. Both are
//! in scheduler order, so composition is a streaming merge by coordinate and
//! same-coordinate sequence, with the signal item first when both owners
//! recorded work at the same position. Replay reverses it: a streaming split
//! routes each work item to its owner. Neither direction holds more than one
//! decoded segment per input trace.

use std::sync::Arc;

use super::campaign_log::CampaignRecordLog;
use super::*;
use crucible_engine::model::{
    FaultCoordinate, FaultReplayMode, ResolvedEffectTrace, ResolvedEffectTraceWriter,
    ResolvedReplayWorkItem,
};
use crucible_engine::segment_store::SegmentSink;

pub(in crate::vm_lifecycle) fn campaign_network_binding_name(name: &str) -> bool {
    matches!(name, "campaign-network-first" | "campaign-network-followup")
}

/// Owner of one replay work item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkItemOwner {
    Signal,
    Campaign,
}

/// Separates campaign-owned effects from signal replay without changing either
/// owner's derivation fingerprint or the canonical trace representation.
///
/// A trace without campaign work items is returned unchanged as the signal
/// trace. Otherwise both partitions are written to `sink` as fresh traces in
/// the input's mode.
///
/// # Errors
///
/// Returns an error when the trace exceeds `limits`, a segment cannot be read
/// or stored, or a work item mixes owners or lacks authenticated provenance.
pub(crate) fn split_campaign_network_trace(
    trace: ResolvedEffectTrace,
    selected_network: bool,
    sink: &Arc<dyn SegmentSink>,
    limits: FaultResourceLimits,
) -> Result<(ResolvedEffectTrace, ResolvedEffectTrace), SchedulerError> {
    let mode = trace.mode();
    trace
        .manifest()
        .admit(limits)
        .map_err(|error| trace_error("admit fault replay", &error))?;

    // A first pass authenticates every item and finds whether the campaign
    // owns any of them; most replays are signal-only and need no copy.
    let mut campaign_found = false;
    for item in trace.items() {
        let item = item.map_err(|error| trace_error("read fault replay", &error))?;
        campaign_found |= owner(&item, selected_network)? == WorkItemOwner::Campaign;
    }
    let empty =
        || ResolvedEffectTrace::empty(mode).map_err(|error| trace_error("empty replay", &error));
    if !campaign_found {
        return Ok((trace, empty()?));
    }

    let mut signal = ResolvedEffectTraceWriter::new(Arc::clone(sink), limits);
    let mut campaign = ResolvedEffectTraceWriter::new(Arc::clone(sink), limits);
    for item in trace.items() {
        let item = item.map_err(|error| trace_error("read fault replay", &error))?;
        let writer = match owner(&item, selected_network)? {
            WorkItemOwner::Signal => &mut signal,
            WorkItemOwner::Campaign => &mut campaign,
        };
        writer
            .append(item)
            .map_err(|error| trace_error("partition fault replay", &error))?;
    }
    let signal = signal
        .finish(mode)
        .map_err(|error| trace_error("partition fault replay", &error))?;
    let campaign = campaign
        .finish(mode)
        .map_err(|error| trace_error("partition fault replay", &error))?;
    Ok((signal, campaign))
}

/// Adds committed campaign frame outcomes to the canonical resolved-effect trace.
///
/// The merged trace is written to the campaign log's sink.
///
/// # Errors
///
/// Returns an error if the combined trace exceeds authored bounds, either
/// owner is out of scheduler order, a segment cannot be read or stored, or the
/// signal trace was captured in another mode.
pub(crate) fn trace_with_campaign_network_records(
    trace: Option<ResolvedEffectTrace>,
    campaign: &CampaignRecordLog,
    mode: FaultReplayMode,
) -> Result<Option<ResolvedEffectTrace>, SchedulerError> {
    if campaign.is_empty() {
        return Ok(trace);
    }
    let campaign_trace = campaign.export(mode)?;
    let signal = match trace {
        Some(trace) if trace.mode() != mode => {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("campaign network trace mode differs from its capture mode"),
            });
        }
        Some(trace) => trace,
        None => ResolvedEffectTrace::empty(mode)
            .map_err(|error| trace_error("empty signal trace", &error))?,
    };

    // Signal and campaign work may have the same scheduler coordinate. Their
    // derivation fingerprints authenticate different owners and stay in
    // separate work items, signal first.
    let mut merged =
        ResolvedEffectTraceWriter::new(Arc::clone(campaign.sink()), campaign.resource_limits());
    let mut signal_items = signal.items().peekable();
    let mut campaign_items = campaign_trace.items().peekable();
    let mut last: Option<(FaultCoordinate, u64)> = None;
    loop {
        let take_signal = match (signal_items.peek(), campaign_items.peek()) {
            (None, None) => break,
            (Some(Ok(signal)), Some(Ok(campaign))) => order(signal) <= order(campaign),
            (Some(_), _) => true,
            (None, Some(_)) => false,
        };
        let next = if take_signal {
            signal_items.next()
        } else {
            campaign_items.next()
        };
        let Some(item) = next else {
            break;
        };
        let item = item.map_err(|error| trace_error("read resolved-effect trace", &error))?;

        let position = order(&item);
        if last.is_some_and(|last| position < last) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("resolved-effect trace owners are out of scheduler order"),
            });
        }
        last = Some(position);
        merged.append(item).map_err(|error| {
            trace_error(
                "campaign network effects violate the resolved trace",
                &error,
            )
        })?;
    }
    merged
        .finish(mode)
        .map(Some)
        .map_err(|error| trace_error("finish resolved-effect trace", &error))
}

fn owner(
    item: &ResolvedReplayWorkItem,
    selected_network: bool,
) -> Result<WorkItemOwner, SchedulerError> {
    let campaign_count = item
        .records
        .iter()
        .filter(|record| campaign_network_binding_name(record.binding.as_str()))
        .count();
    if campaign_count == 0 {
        return Ok(WorkItemOwner::Signal);
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
    Ok(WorkItemOwner::Campaign)
}

fn order(item: &ResolvedReplayWorkItem) -> (FaultCoordinate, u64) {
    (item.coordinate, item.same_coordinate_sequence)
}

fn trace_error(context: &str, error: &impl std::fmt::Display) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: format!("{context}: {error}"),
    }
}
