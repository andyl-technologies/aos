//! HTTP/2 lifecycle scenario, resume request, and checkpoint fixtures.

use super::*;

pub(crate) fn resume_session_request(seed: u64) -> ResumeSessionRequest {
    let mut scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("happy path scenario should build: {error}"))
        .scenario;
    if scenario.seed() != Seed::from_u64(seed) {
        scenario = scenario_with_seed(&scenario, Seed::from_u64(seed));
    }
    let scenario_def = scenario.scenario_def();
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: Vec::new(),
    }));
    let configuration = Configuration {
        def: scenario_def,
        schedule: schedule.clone(),
    };
    let checkpoint = checkpoint_for_configuration(&configuration, VirtualTime { ticks: 1 });
    ResumeSessionRequest::new(scenario, schedule, checkpoint, Seed::from_u64(seed))
}

pub(crate) fn scenario_with_seed(scenario: &ScenarioDefForm, seed: Seed) -> ScenarioDefForm {
    ScenarioDefForm::from_components_with_app_random_draw_cap(
        scenario.world(),
        scenario.plan(),
        scenario.properties(),
        seed,
        scenario.app_random_draw_cap(),
    )
    .unwrap_or_else(|error| panic!("test scenario should rebuild with seed: {error}"))
}

pub(crate) fn checkpoint_for_configuration(
    configuration: &Configuration,
    frontier: VirtualTime,
) -> Checkpoint {
    let parent = if configuration.schedule.is_empty() {
        None
    } else {
        let prefix = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .unwrap_or_else(|error| panic!("test schedule prefix should exist: {error}"));
        Some(Configuration {
            def: configuration.def.clone(),
            schedule: prefix,
        })
    };
    Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        frontier,
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("test checkpoint should record configuration: {error}"))
}
