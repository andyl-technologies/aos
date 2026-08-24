//! App-random campaign selections projected into scheduler and plugin plans.

use std::collections::BTreeMap;

use crucible::{Configuration, ContentHash, Decision, NodeId};
use crucible_campaign::{ChoiceValue, IntegerValue};
use crucible_protocol::app_random_branch_plan::{
    AppRandomBranchPlan, AppRandomBranchPlanEntry, MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES,
};
use crucible_protocol::app_random_transport::app_random_stream_name_components;

type AppRandomBranchReplay = (
    BTreeMap<ContentHash, crucible::SelectionDecision>,
    BTreeMap<NodeId, AppRandomBranchPlan>,
);

pub(super) fn app_random_branch_replay(
    target: &Configuration,
) -> Result<AppRandomBranchReplay, String> {
    let decisions = target.schedule.decisions();
    let mut draw_indexes = BTreeMap::<NodeId, u64>::new();
    let mut selections = BTreeMap::new();
    let mut plan_entries = BTreeMap::<NodeId, Vec<AppRandomBranchPlanEntry>>::new();

    validate_branch_placement(decisions)?;

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

        let Some(Decision::Selection(selection_decision)) = decisions.get(index + 1) else {
            continue;
        };
        if !selection_decision.is_campaign_branch() {
            continue;
        }
        if selections.len() >= MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES {
            return Err(String::from(
                "target schedule exceeds the app-random campaign selection bound",
            ));
        }
        let selection = selection_decision.selection().map_err(|error| {
            format!(
                "decode campaign selection at decision {}: {error}",
                index + 1
            )
        })?;
        let selected_value = match selection.value() {
            ChoiceValue::Integer(IntegerValue::Unsigned(value)) => *value,
            _ => {
                return Err(format!(
                    "campaign selection at decision {} is not an unsigned app-random value",
                    index + 1
                ));
            }
        };
        let parent = Configuration {
            def: target.def.clone(),
            schedule: target
                .schedule
                .prefix(index + 1)
                .map_err(|error| format!("derive app-random branch parent: {error}"))?,
        }
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
        plan_entries.entry(node).or_default().push(entry);
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

fn validate_branch_placement(decisions: &[Decision]) -> Result<(), String> {
    for (index, decision) in decisions.iter().enumerate() {
        let Decision::Selection(selection) = decision else {
            continue;
        };
        if !selection.is_campaign_branch() {
            continue;
        }
        let Some(Decision::RngDraw(draw)) = index
            .checked_sub(1)
            .and_then(|previous| decisions.get(previous))
        else {
            return Err(format!(
                "campaign selection at decision {index} is not preceded by an app-random draw"
            ));
        };
        if !draw.stream.is_default_domain()
            || app_random_stream_name_components(&draw.stream.name).is_none()
        {
            return Err(format!(
                "campaign selection at decision {index} follows a nonstandard app-random stream"
            ));
        }
    }
    Ok(())
}
