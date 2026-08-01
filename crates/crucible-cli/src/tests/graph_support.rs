//! Shared graph fixtures for search and replay tests.

use super::*;

pub(super) fn search_frontier_graph(
    scenario: &crucible::ScenarioDefForm,
) -> Result<ValidationDag, Box<dyn Error>> {
    let baked = baked_with_search_frontier_choices(scenario.world(), search_frontier_decisions())?;
    let graph = crucible_session::validation::empty_validation_dag();
    Ok(graph.with_baked_genesis(&scenario.scenario_def(), baked)?)
}

fn baked_with_search_frontier_choices(
    world: &crucible::World,
    decisions: Vec<crucible::Decision>,
) -> Result<crucible::GenesisCheckpoint, Box<dyn Error>> {
    let mut baked = crucible::bake(world)?;
    let state =
        baked.checkpoint.state.as_ref().ok_or_else(|| {
            std::io::Error::other("search frontier genesis checkpoint missing state")
        })?;
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier = crucible::SearchFrontierChoices::from_decisions(decisions);
    baked.checkpoint.state = Some(
        crucible::MaterializedState::from_components_with_event_log_segments(
            state.vm_snapshots.clone(),
            state.device_overlays.clone(),
            scheduler,
            state.decision_rng.clone(),
            state.event_log,
            state.event_log_segments.clone(),
        ),
    );
    Ok(baked)
}
