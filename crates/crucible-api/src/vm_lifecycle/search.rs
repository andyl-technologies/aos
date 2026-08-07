//! Production scheduler search-frontier construction without VM launch.

use super::*;

/// Derives the production scheduler's initial state-space search frontier.
///
/// The returned choices come from the same [`SingleScheduler`] construction
/// used by live QEMU execution. Backend processes are not launched by this
/// policy-only query; callers must execute every selected branch through
/// [`build_production_vm_lifecycle_loop`] to obtain runtime evidence.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the World is empty, VM
/// shifts differ, time conversion overflows, configured bounds are invalid, or
/// the authoritative scheduler rejects the scenario.
pub fn production_vm_search_frontier(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
) -> Result<SearchFrontierChoices, LifecycleApiError> {
    let nodes = source.world().vm_nodes();
    let first = nodes
        .first()
        .ok_or_else(|| loop_factory_error("scenario World has no VM nodes"))?;
    if nodes
        .iter()
        .any(|node| node.icount_shift != first.icount_shift)
    {
        return Err(loop_factory_error(
            "production QEMU lifecycle currently requires one shared icount shift",
        ));
    }
    if config.run_ceiling_icount == 0 || config.quantum_budget == 0 {
        return Err(loop_factory_error(
            "production QEMU lifecycle bounds must be nonzero",
        ));
    }
    let shift = Shift::new(first.icount_shift)
        .map_err(|error| loop_factory_error(format!("validate icount shift: {error}")))?;
    let time_limit_nanos = config
        .run_ceiling_icount
        .checked_shl(u32::from(first.icount_shift))
        .ok_or_else(|| loop_factory_error("QEMU lifecycle time limit overflow"))?;
    let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        shift,
        config.quantum_budget,
        SimInstant {
            nanos: time_limit_nanos,
        },
        0,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    let scheduler = SingleScheduler::new(runtime_scenario)
        .map_err(|error| loop_factory_error(format!("construct QEMU scheduler: {error}")))?;
    Ok(scheduler.materialized_scheduler_state().search_frontier)
}
