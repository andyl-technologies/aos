//! Ancestor starts: forking from a published root below the branch parent.
//!
//! A child forked from a published-boundary root inherits the root's
//! lifecycle configuration, which carries no attempt-specific replay inputs:
//! no app-random substitutions, no authenticated live-network selections, and
//! no signal-fault replay plan. Any decision those inputs would have served
//! therefore cannot be replayed inside such a child. Every other decision is
//! replayed from attempt input by the same start-replay function thin replay
//! uses, so a child may start from a root at a strict ancestor `C` of its
//! parent `P` when the whole recorded range is of that kind:
//!
//! ```text
//! C.len            P.len               selected.len
//!   |-- suffix ------|-- attempt edge ----|
//!   bounded, replay-only decisions; the recorded pause mode of the root's
//!   prefix equals the attempt's own
//! ```
//!
//! The same configuration rule applies to the edge of a child of an exact
//! published root at `P`, which is otherwise forked unchecked. A suffix
//! divergence is operational: the child is quarantined, the root abandoned,
//! and the retry runs thin.

use std::io::Write;
use std::sync::Arc;

use crucible::{Configuration, Decision, SelectionDecision};

use crate::CrucibleAttemptExecution;
use crate::qemu_hot_fork_source_capture::{QemuPublishedRootOrigin, QemuPublishedRootProvenance};

/// Upper bound on suffix decisions one ancestor child may replay.
///
/// A deeper suffix belongs to thin replay, whose progress and resource
/// accounting are proven for arbitrary prefix lengths.
pub(crate) const MAX_ANCESTOR_SUFFIX_DECISIONS: usize = 4096;

/// Upper bound on recorded selections in one ancestor suffix.
pub(crate) const MAX_ANCESTOR_SUFFIX_SELECTIONS: usize = 8;

/// Where a hot-fork child's materialized start boundary sits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum QemuHotForkStartOrigin {
    /// The source is paused at the attempt's own start boundary.
    Exact,
    /// The source is a published root at a strict ancestor of the parent.
    Ancestor {
        /// The root's configuration `C`, from which the suffix is replayed.
        anchor: Arc<Configuration>,
        /// How the root was produced, named in the ancestor diagnostic.
        root: QemuPublishedRootOrigin,
    },
}

/// Returns why a child of a published root cannot replay `selected[from..]`.
///
/// The range is refused when any decision in it is served by lifecycle
/// configuration rather than by start replay from attempt input. `edge` is
/// where the attempt's own branch edge begins: a live-network selection there
/// is installed as an authenticated lifecycle choice, while earlier ones are
/// replayed at their reserved choice pause.
pub(crate) fn configuration_carried_decision(
    input: &CrucibleAttemptExecution,
    selected: &Configuration,
    from: usize,
    edge: usize,
) -> Option<&'static str> {
    // A signal-fault branch still to be injected after `from` is installed
    // only through the lifecycle's replay plan.
    let pending_signal_fault = input.signal_fault_replay().branches().iter().any(|branch| {
        branch
            .parent()
            .len()
            .saturating_add(branch.decisions().len())
            > from
    });
    if pending_signal_fault {
        return Some("signal-fault-branch");
    }

    let decisions = selected.schedule.decision_history();
    (from..decisions.len()).find_map(|index| {
        let decision = decisions.get(index)?;
        match decision {
            Decision::Override(_) => Some("override-decision"),
            Decision::RngDraw(draw) => app_random_campaign_draw(draw, decisions.get(index + 1))
                .then_some("app-random-draw"),
            Decision::Selection(selection) => {
                if recorded_network_fault_branch(input, index, decision) {
                    return None;
                }
                configuration_carried_selection(selection, index >= edge)
            }
            Decision::DeliveryOrder(_) | Decision::Preemption(_) => None,
        }
    })
}

/// Returns why `provenance`'s root cannot serve the attempt as an ancestor.
pub(crate) fn ancestor_suffix_refusal(
    input: &CrucibleAttemptExecution,
    parent: &Configuration,
    selected: &Configuration,
    provenance: &QemuPublishedRootProvenance,
) -> Option<&'static str> {
    let anchor = provenance.configuration();
    let start = anchor.schedule.len();
    if anchor.def != parent.def
        || start >= parent.schedule.len()
        || !parent.schedule.starts_with(&anchor.schedule)
    {
        return Some("ancestor-not-strict-prefix");
    }
    let suffix = parent.schedule.len() - start;
    if suffix > MAX_ANCESTOR_SUFFIX_DECISIONS {
        return Some("ancestor-suffix-too-long");
    }
    let selections = parent
        .schedule
        .decision_history()
        .iter_from(start)
        .filter(|decision| matches!(decision, Decision::Selection(_)))
        .count();
    if selections > MAX_ANCESTOR_SUFFIX_SELECTIONS {
        return Some("ancestor-suffix-too-many-selections");
    }

    // Replay groups RUNs by its pause mode, so the root's prefix must have
    // run in the mode the attempt's own replay will use.
    let pause = crate::qemu_campaign_lifecycle::replay_pauses_before_live_network_choice(selected);
    if provenance.live_network_choice_pause() != Some(pause) {
        return Some("ancestor-pause-mode-mismatch");
    }
    configuration_carried_decision(input, selected, start, parent.schedule.len())
}

/// Returns whether `draw` is an app-random draw substituted by a campaign branch.
fn app_random_campaign_draw(draw: &crucible::RngDecision, next: Option<&Decision>) -> bool {
    let app_random = draw.stream.is_default_domain()
        && crucible_protocol::app_random_transport::app_random_stream_name_components(
            &draw.stream.name,
        )
        .is_some();
    app_random
        && matches!(next, Some(Decision::Selection(selection)) if selection.is_campaign_branch())
}

/// Returns whether the decision at `index` is a recorded network fault branch.
///
/// Those branches are crossed at their joined park from attempt input.
fn recorded_network_fault_branch(
    input: &CrucibleAttemptExecution,
    index: usize,
    decision: &Decision,
) -> bool {
    input
        .signal_fault_replay()
        .network_branches()
        .iter()
        .any(|branch| branch.parent().schedule.len() == index && branch.decision() == decision)
}

/// Returns why a recorded selection needs lifecycle configuration to replay.
fn configuration_carried_selection(
    selection: &SelectionDecision,
    on_edge: bool,
) -> Option<&'static str> {
    if selection.is_app_random_model_sample() {
        return Some("app-random-selection");
    }
    if selection.preemption_config().is_some() {
        return Some("preemption-selection");
    }
    let Ok(decoded) = selection.selection() else {
        return Some("undecodable-selection");
    };
    if on_edge && crucible::is_live_world_network_selection(&decoded) {
        return Some("live-network-selection");
    }
    if matches!(
        decoded.origin(),
        crucible_campaign::SelectionOrigin::ModelSample(_)
    ) {
        return Some("model-sample-selection");
    }
    None
}

/// Writes one bounded operational ancestor diagnostic.
///
/// ```text
/// CRUCIBLE-HOT-FORK-ANCESTOR-V1 attempt=<id> anchor=<configuration-hex> suffix_decisions=<n> decision=<decision> reason=<token>
/// ```
pub(crate) fn record_ancestor_decision(
    input: &CrucibleAttemptExecution,
    anchor: Option<&Configuration>,
    suffix_decisions: usize,
    decision: &str,
    reason: &str,
) {
    let attempt = input
        .attempt()
        .id()
        .map_or_else(|_| String::from("unavailable"), |id| id.to_string());
    let anchor = anchor.map_or_else(|| String::from("none"), |anchor| anchor.id().to_hex());
    let _ = writeln!(
        std::io::stderr().lock(),
        "CRUCIBLE-HOT-FORK-ANCESTOR-V1 attempt={attempt} anchor={anchor} \
         suffix_decisions={suffix_decisions} decision={decision} reason={reason}"
    );
}

/// Returns the diagnostic reason naming how an ancestor root was produced.
pub(crate) const fn forked_reason(root: QemuPublishedRootOrigin) -> &'static str {
    match root {
        QemuPublishedRootOrigin::AttemptStop => "ancestor-stop-root",
        QemuPublishedRootOrigin::BranchParentAnchor => "ancestor-anchor-root",
    }
}
