//! App-random campaign selections projected into scheduler and plugin plans.
//!
//! A launch serves only the app-random requests after its restore point. The
//! plugin skips every plan entry whose node-local draw index precedes the
//! launch's draw offset, which counts the requests answered inside the
//! restored prefix. The projection therefore keeps exactly the entries a
//! launch can serve:
//!
//! ```text
//! genesis launch:   [draw sel .. draw sel .. draw sel]     every entry
//! restored target:  [draw sel .. draw sel .. draw sel] ^   no entry
//! ```
//!
//! Campaign launches either boot from genesis or restore a checkpoint at the
//! target itself (an exact resume or a retained hot-fork source), so the
//! per-node entry bound limits only the selections a genesis replay must
//! substitute, never the depth of a resumed campaign.

use std::collections::BTreeMap;

use crucible_campaign::{ChoiceValue, IntegerValue};
use crucible_engine::{Configuration, ConfigurationPrefix, ContentHash, Decision, NodeId};
use crucible_qemu_protocol::app_random_branch_plan::{
    AppRandomBranchPlan, AppRandomBranchPlanEntry, MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES,
};
use crucible_qemu_protocol::app_random_transport::app_random_stream_name_components;

type AppRandomBranchReplay = (
    BTreeMap<ContentHash, crucible_engine::SelectionDecision>,
    BTreeMap<NodeId, AppRandomBranchPlan>,
);

/// Where a launch begins replaying the target schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AppRandomLaunchWindow {
    /// The launch boots from scenario genesis and serves every request.
    Genesis,
    /// The launch restores a checkpoint at the target itself.
    ///
    /// Every request on the target's path lies inside the restored prefix,
    /// so the launch serves no recorded substitution.
    RestoredTarget,
}

/// Projects the target's campaign app-random selections inside `window`.
///
/// Returns the scheduler selections keyed by exact branch parent and the
/// per-node plugin plans. Both cover the same selections.
pub(super) fn app_random_branch_replay(
    target: &Configuration,
    window: AppRandomLaunchWindow,
) -> Result<AppRandomBranchReplay, String> {
    if window == AppRandomLaunchWindow::RestoredTarget {
        return Ok((BTreeMap::new(), BTreeMap::new()));
    }

    let decisions = target.schedule.decision_history();
    let mut draw_indexes = BTreeMap::<NodeId, u64>::new();
    let mut selections = BTreeMap::new();
    let mut plan_entries = BTreeMap::<NodeId, Vec<AppRandomBranchPlanEntry>>::new();

    for (index, decision) in decisions.iter().enumerate() {
        let Decision::RngDraw(draw) = decision else {
            continue;
        };
        if !draw.stream.is_default_domain() {
            continue;
        }
        let Some((node_name, _stream_tag)) = app_random_stream_name_components(&draw.stream.name)
        else {
            continue;
        };
        let node = NodeId {
            name: node_name.to_owned(),
        };
        let draw_index = *draw_indexes.entry(node.clone()).or_default();
        draw_indexes.insert(
            node.clone(),
            draw_index
                .checked_add(1)
                .ok_or_else(|| String::from("node-local app-random draw index overflow"))?,
        );

        let selection_index = index + 1;
        let Some(Decision::Selection(selection_decision)) = decisions.get(selection_index) else {
            continue;
        };
        if !selection_decision.is_campaign_branch() {
            continue;
        }

        // The bound is per node because each node receives its own plan.
        let node_entries = plan_entries.entry(node).or_default();
        if node_entries.len() >= MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES {
            return Err(format!(
                "target schedule exceeds the {MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES}-entry \
                 node-local app-random campaign selection bound"
            ));
        }
        let selection = selection_decision.selection().map_err(|error| {
            format!("decode campaign selection at decision {selection_index}: {error}")
        })?;
        let selected_value = match selection.value() {
            ChoiceValue::Integer(IntegerValue::Unsigned(value)) => *value,
            _ => {
                return Err(format!(
                    "campaign selection at decision {selection_index} is not an unsigned app-random value"
                ));
            }
        };

        // The canonical configuration hash commits to the decision count
        // first, so each parent identity rereads its prefix. A shared prefix
        // at least avoids copying the schedule for every selection.
        let parent = ConfigurationPrefix::new(target, selection_index)
            .map_err(|error| format!("derive app-random branch parent: {error}"))?
            .id();
        if selections
            .insert(parent, selection_decision.clone())
            .is_some()
        {
            return Err(String::from(
                "target schedule repeats one app-random branch parent",
            ));
        }
        let selection_id = selection
            .id()
            .map_err(|error| format!("derive app-random selection identity: {error}"))?
            .content_id()
            .digest();
        let entry = AppRandomBranchPlanEntry::new(
            draw_index,
            draw.value,
            selected_value,
            selection_id,
            draw.stream.name.clone(),
        )
        .map_err(|error| format!("build node-local app-random branch entry: {error}"))?;
        node_entries.push(entry);
    }

    let plans = plan_entries
        .into_iter()
        .map(|(node, entries)| {
            AppRandomBranchPlan::new(entries)
                .map(|plan| (node, plan))
                .map_err(|error| format!("build node-local app-random branch plan: {error}"))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok((selections, plans))
}
