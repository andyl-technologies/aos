//! Root-authenticated input and decision order for physical QEMU replay.

use crucible::{
    BackendInput, Configuration, EventLogSegmentReader, Icount, NodeId, ScheduledEventPayload,
    SchedulerEventLogClass, SchedulerEventLogPayload, SingleSchedulerCheckpoint, World,
};
use crucible_qemu::QemuVmRealizationError;

/// One scheduler-recorded effect that the local replay must enact in order.
pub(super) enum ReplayStep {
    Decision {
        index: usize,
    },
    Input {
        input: BackendInput,
        /// Physical QEMU counter at which the live VM received the frame.
        delivery_icount: Icount,
    },
}

/// Validates a complete event prefix and extracts the local physical replay plan.
pub(super) fn authenticated_replay_steps(
    world: &World,
    configuration: &Configuration,
    scheduler: &SingleSchedulerCheckpoint,
    event_log_segments: &(impl EventLogSegmentReader + ?Sized),
    process_generation: u64,
    node: &NodeId,
    expected_inbound: u64,
) -> Result<Vec<ReplayStep>, QemuVmRealizationError> {
    // A successor QEMU generation can reset its physical counter and inbound
    // sequence. The complete log lacks authenticated transition snapshots, so
    // genesis replay may only consume the first generation's coordinates.
    if process_generation != 1 {
        return Err(invalid_input(
            "multi-generation replay lacks authenticated generation transitions",
        ));
    }
    if scheduler.event_log_base_events() != 0 {
        return Err(invalid_input("scheduler retained only an event-log suffix"));
    }
    let mut nodes = world
        .vm_nodes()
        .iter()
        .filter(|candidate| &candidate.id == node);
    nodes
        .next()
        .ok_or_else(|| invalid_input("replay node is absent from the authenticated world"))?;
    if nodes.next().is_some() {
        return Err(invalid_input(
            "replay node occurs more than once in the world",
        ));
    }

    let mut steps = Vec::new();
    let mut next_decision = 0_usize;
    let mut next_sequence = 0_u64;
    let mut inbound = 0_u64;
    // Entries stream from the referenced segments, one segment resident at a
    // time; a segment that cannot be read or authenticated refuses replay.
    for entry in scheduler.event_log_entries(event_log_segments) {
        let entry =
            entry.map_err(|_| invalid_input("scheduler event-log segment is unreadable"))?;
        if entry.sequence() != next_sequence
            || !entry.has_valid_content_hash()
            || !entry.class_matches_catalog()
        {
            return Err(invalid_input(
                "scheduler event-log prefix is not dense and authentic",
            ));
        }
        next_sequence = next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_input("scheduler event-log sequence overflowed"))?;

        match entry.payload() {
            SchedulerEventLogPayload::Decision(decision) => {
                let expected = configuration
                    .schedule
                    .decision_history()
                    .get(next_decision)
                    .ok_or_else(|| invalid_input("event log has an extra replay decision"))?;
                if entry.class() != SchedulerEventLogClass::Causal || decision != expected {
                    return Err(invalid_input(
                        "event-log decision differs from the authenticated schedule",
                    ));
                }
                steps
                    .try_reserve(1)
                    .map_err(|_| invalid_input("replay operation allocation failed"))?;
                steps.push(ReplayStep::Decision {
                    index: next_decision,
                });
                next_decision += 1;
            }
            SchedulerEventLogPayload::ResolvedHappening(event) => {
                let ScheduledEventPayload::BackendInput(input) = &event.payload else {
                    continue;
                };
                if entry.class() != SchedulerEventLogClass::Causal
                    || event.key.consumer().node != input.node
                {
                    return Err(invalid_input(
                        "resolved input has invalid class or consumer",
                    ));
                }
                if &input.node != node {
                    continue;
                }
                if !world.links().iter().any(|link| {
                    let (left, right) = link.endpoints();
                    (left == node || right == node)
                        && link.scheduler_node_id() == *event.key.producer()
                }) {
                    return Err(invalid_input(
                        "resolved input has no declared producer link",
                    ));
                }
                // The scheduler fixed this input's physical counter at RESOLVE.
                // Scheduler time differs from that counter whenever the VM's
                // time mapping is not the identity (a ready point after counter
                // zero, a resume rebase), so only the recorded counter names the
                // instant the live guest received the frame.
                let delivery_icount = match entry.time().stamp.retired {
                    Some(delivery_icount)
                        if entry.at() == event.key.virtual_time()
                            && entry.time().stamp.node.as_ref() == Some(node) =>
                    {
                        delivery_icount
                    }
                    _ => {
                        return Err(invalid_input(
                            "resolved input lacks its exact node-local delivery stamp",
                        ));
                    }
                };
                inbound = inbound
                    .checked_add(1)
                    .ok_or_else(|| invalid_input("replay inbound sequence overflowed"))?;
                steps
                    .try_reserve(1)
                    .map_err(|_| invalid_input("replay operation allocation failed"))?;
                steps.push(ReplayStep::Input {
                    input: input.clone(),
                    delivery_icount,
                });
            }
            _ => {}
        }
    }
    if next_decision != configuration.schedule.decision_history().len() {
        return Err(invalid_input(
            "event log omits an authenticated replay decision",
        ));
    }
    if inbound != expected_inbound {
        return Err(invalid_input(
            "event-log inbound count differs from exact network continuation",
        ));
    }
    Ok(steps)
}

fn invalid_input(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::InvalidCheckpoint {
        role: "guarded replay backend input",
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
