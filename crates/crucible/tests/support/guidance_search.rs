//! Shared fixtures for integrated guidance-search gates.

use crucible::{
    AssertionId, AssertionQuantifierKind, Decision, EngineError, GenesisCheckpoint, Icount,
    ObservableEvent, RngDecision, RngStreamId, SchedulerEventLogEntry, SearchFrontierChoices,
    VirtualTime, World, bake,
};

use super::node;

pub(super) fn bake_with_search_frontier_choices(
    world: &World,
    decisions: Vec<Decision>,
) -> Result<GenesisCheckpoint, EngineError> {
    let mut baked = bake(world)?;
    let state = baked.checkpoint.state.as_ref().ok_or(
        EngineError::CheckpointMaterializedStateIncomplete {
            checkpoint: baked.checkpoint.id,
            reason: "missing-guidance-test-genesis-state",
        },
    )?;
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier = SearchFrontierChoices::from_decisions(decisions);
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

pub(super) fn guidance_decision(index: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(format!("guidance-{index}")),
        value: index,
    })
}

pub(super) fn guidance_event_log(index: u64) -> Vec<SchedulerEventLogEntry> {
    let coverage_pc = if index < 2 { 0x4000 } else { 0x5000 };
    let coverage = ObservableEvent::coverage_block(
        Icount {
            retired: 10 + index,
        },
        node("guest-a"),
        coverage_pc,
        0x20,
    );
    let proximity = ObservableEvent::assertion_proximity(
        VirtualTime { ticks: 20 + index },
        AssertionId::from_name("eventually-ready"),
        AssertionQuantifierKind::Eventually,
        u128::from(3 - index),
        Some(node("guest-a")),
    );
    vec![
        crucible::test_support::condition_observation_entry_for_test(0, &coverage),
        crucible::test_support::condition_observation_entry_for_test(1, &proximity),
    ]
}
