//! Start replay across the all-VM network fault boundary.
//!
//! The modeled driver parks every VM at a network fault phase marker, joins
//! the parks to one frontier, and offers the atomic `fault.network` choice.
//! A branch child starts from the parent's genesis, so its replay reaches the
//! same all-parked boundary. With every VM paused, no quantum can advance, so
//! replay must take the driver's boundary step itself: join the parks, commit
//! the recorded branch Selection, and release each VM with that selection.
//! After replay, the driver's first quantum then finds no parks and accepts
//! the boundary only through the committed release proofs.
//!
//! Anchor retention asks replay to stop at one recorded branch parent instead:
//! after the parks are joined and the frontier is checked, but before the
//! branch is appended or any VM released. That joined park is the exact
//! boundary every descendant's replay crosses, so a world kept there serves
//! later branches without changing any replayed fact.

use super::*;
use crate::qemu_campaign_driver::{
    NETWORK_FAULT_PHASE_MARKERS, declares_network_fault, phase_marker,
};
use crucible_engine::NetworkFaultCampaignBranch;

/// Parks VMs held at network fault phase markers during start replay.
///
/// The modeled driver parks these holds after every quantum so staggered VMs
/// each reach their marker before the atomic choice. Replay must do the same:
/// an unparked hold blocks every later RUN, so a replay crossing the first
/// marker would otherwise fail before reaching its target.
pub(super) fn park_replayed_network_fault_markers<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    outcome: &mut QuantumOutcome,
) -> Result<(), AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    if !declares_network_fault(input) {
        return Ok(());
    }
    lifecycle
        .park_held_campaign_markers(&NETWORK_FAULT_PHASE_MARKERS, outcome)
        .map_err(map_start_replay_scheduler_failure)?;
    Ok(())
}

/// Commits a recorded network fault branch once every VM is parked for it.
///
/// Returns the branch quantum's event-log entries, or none when `current` is
/// not a recorded branch parent or some VM has not yet parked for its phase.
/// On success `current` names the selected configuration, and the replay's
/// quantum coordinate and frontier name the committed branch boundary. When
/// `current` is the replay's anchor stop, the parks are joined but the branch
/// is neither appended nor released; `current` stays the parent and the
/// replay records that it reached its anchor.
///
/// # Errors
///
/// Returns a divergence when the target leaves the recorded branch at its
/// parent or the joined frontier differs from the recorded boundary, and a
/// scheduler failure when the join, append, or a marker release is refused.
pub(super) fn cross_replayed_network_fault_boundary<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    target: &Configuration,
    current: &mut Configuration,
    replay: &mut QemuFreshStartMaterialization,
) -> Result<Vec<SchedulerEventLogEntry>, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>>
{
    if !declares_network_fault(input) {
        return Ok(Vec::new());
    }
    let Some(branch) = recorded_branch_at(input, current) else {
        return Ok(Vec::new());
    };
    if !every_vm_parked_for(lifecycle, input, branch)? {
        return Ok(Vec::new());
    }

    // A parked parent is only a boundary; the target must continue through
    // exactly this branch or replay has left the recorded lineage.
    let index = current.schedule.len();
    let expected = target.schedule.decision_history().get(index);
    if expected != Some(branch.decision()) {
        return Err(replay_divergence(
            "network fault branch",
            index,
            replay_decision_detail(Some(branch.decision())),
            replay_decision_detail(expected),
        ));
    }

    let frontier = lifecycle
        .join_campaign_parks_to_frontier()
        .map_err(map_start_replay_scheduler_failure)?
        .map_or(replay.frontier, |joined| joined.max(replay.frontier));
    if frontier != branch.at() {
        return Err(replay_divergence(
            "network fault boundary",
            index,
            branch.at().ticks.to_string(),
            frontier.ticks.to_string(),
        ));
    }

    // An anchor stop keeps the joined, unreleased park: the boundary every
    // descendant's thin replay crosses next, and the one anchor retention
    // keeps. Nothing is appended or released, so the branch quantum and the
    // marker releases still belong to whichever replay crosses it later.
    if replay.stops_at_anchor(current) {
        replay.stop_at_anchor(frontier);
        return Ok(Vec::new());
    }

    let (selected, entries) = lifecycle
        .append_network_fault_campaign_branch(branch)
        .map_err(map_start_replay_scheduler_failure)?;
    let marker = phase_marker(branch.phase());
    for vm in input.scenario().world().vm_nodes().iter() {
        lifecycle
            .release_parked_campaign_marker(&vm.id, marker, branch.selected().id())
            .map_err(map_start_replay_scheduler_failure)?;
    }

    // The branch append is a scheduler quantum of its own; the driver
    // requires the replayed coordinate to match the live one exactly.
    *current = selected;
    replay.completed_quanta = lifecycle.completed_quanta();
    replay.frontier = frontier;
    Ok(entries)
}

/// Finds the recorded network fault branch whose parent is `current`.
///
/// An after-attempt start replays its base through the base attempt's plan,
/// so both plans are consulted; branch parents are exact configurations, so
/// at most one recorded branch can match.
pub(super) fn recorded_branch_at<'a>(
    input: &'a CrucibleAttemptExecution,
    current: &Configuration,
) -> Option<&'a NetworkFaultCampaignBranch> {
    let base_branches = match input.start() {
        CrucibleResolvedAttemptStart::AfterAttempt {
            base_signal_fault_replay,
            ..
        } => base_signal_fault_replay.network_branches(),
        _ => &[],
    };
    base_branches
        .iter()
        .chain(input.signal_fault_replay().network_branches())
        .find(|branch| branch.parent() == current)
}

/// Returns whether every VM holds an exact physical park at `branch`'s marker.
pub(super) fn every_vm_parked_for<F, D>(
    lifecycle: &mut dyn QemuFreshAttemptLifecycleOwner,
    input: &CrucibleAttemptExecution,
    branch: &NetworkFaultCampaignBranch,
) -> Result<bool, AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>> {
    let marker = phase_marker(branch.phase());
    for vm in input.scenario().world().vm_nodes().iter() {
        let parked = lifecycle
            .parked_campaign_marker(&vm.id)
            .map_err(map_start_replay_scheduler_failure)?;
        if !parked.is_some_and(|proof| proof.marker == marker) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn replay_divergence<F, D>(
    reason: &'static str,
    index: usize,
    expected: String,
    observed: String,
) -> AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(QemuFreshExecutionRunnerError::StartReplay(
        QemuFreshStartReplayError::DivergedAt {
            reason,
            index,
            expected,
            observed,
        },
    ))
}
