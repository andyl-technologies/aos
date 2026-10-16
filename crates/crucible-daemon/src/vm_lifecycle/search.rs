//! Production scheduler search-frontier construction without VM launch.

use super::*;

/// Derives the production scheduler's initial state-space search frontier.
///
/// The returned choices come from the same [`SingleScheduler`] construction
/// used by live QEMU execution. Backend processes are not launched by this
/// policy-only query; callers must execute every selected branch through
/// the production lifecycle coordinator to obtain runtime evidence. Exact
/// checkpoint continuations enter through
/// [`build_production_vm_exact_resume_lifecycle`].
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the World is empty, VM
/// configured bounds are invalid or the authoritative scheduler rejects the scenario.
pub fn production_vm_search_frontier(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
) -> Result<SearchFrontierChoices, LifecycleApiError> {
    if source.world().vm_nodes().is_empty() {
        return Err(loop_factory_error("scenario World has no VM nodes"));
    }
    if config.run_ceiling_ticks == 0 || config.quantum_budget == 0 {
        return Err(loop_factory_error(
            "production QEMU lifecycle bounds must be nonzero",
        ));
    }
    let mut runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        config.quantum_budget,
        SimInstant {
            ticks: config.run_ceiling_ticks,
        },
        0,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    if let Some(interval_ticks) = config.rendezvous_interval_ticks {
        runtime_scenario = runtime_scenario
            .with_rendezvous_interval(SimDuration {
                ticks: interval_ticks,
            })
            .map_err(|error| loop_factory_error(format!("configure QEMU rendezvous: {error}")))?;
    }
    let scheduler = SingleScheduler::new(runtime_scenario)
        .map_err(|error| loop_factory_error(format!("construct QEMU scheduler: {error}")))?;
    Ok(scheduler.materialized_scheduler_state().search_frontier)
}
