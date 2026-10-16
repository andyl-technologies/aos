//! Recorded scheduler-control settlement and selectable-reply validation.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecordedControlBoundary {
    Pending,
    Ready,
    Bypassed,
}

pub(super) fn classify_recorded_control_boundary(
    expected: &BTreeMap<NodeId, VirtualTime>,
    observed: &BTreeMap<NodeId, VirtualTime>,
) -> RecordedControlBoundary {
    let mut pending = false;
    for (node, expected_at) in expected {
        let Some(observed_at) = observed.get(node) else {
            return RecordedControlBoundary::Bypassed;
        };
        if observed_at > expected_at {
            return RecordedControlBoundary::Bypassed;
        }
        pending |= observed_at < expected_at;
    }
    if pending {
        RecordedControlBoundary::Pending
    } else {
        RecordedControlBoundary::Ready
    }
}

pub(super) fn selectable_catalogs_checkpoint_ready(
    configuration: &Configuration,
    initial_lifecycle_observations_pending: bool,
    event_log_events: u64,
    live_nodes: &[NodeId],
    plans: &BTreeMap<NodeId, crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan>,
) -> bool {
    live_nodes.iter().all(|node| {
        plans.get(node).is_none_or(|plan| {
            selectable_catalog_checkpoint_ready(
                configuration,
                initial_lifecycle_observations_pending,
                event_log_events,
                plan,
            )
        })
    })
}

pub(super) fn validate_selectable_reply_pairing(
    decision: &SelectionDecision,
    pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
    reply: &crucible_protocol::SelectionReply,
) -> Result<(), SchedulerError> {
    let selection = decision
        .selection()
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("external selection decision is invalid: {error}"),
        })?;
    let opportunity = selection.opportunity().content_id().digest();
    let domain = selection.domain().content_id().digest();
    let value = selection.value().canonical_bytes();
    if reply.sequence() != pending.request().sequence()
        || reply.status() != crucible_protocol::SelectionReplyStatus::Selected
        || reply.opportunity_id() != &opportunity
        || reply.domain_id() != &domain
        || reply.selected_value() != Some(value.as_slice())
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "external selection decision does not match its pending guest reply",
            ),
        });
    }
    Ok(())
}
