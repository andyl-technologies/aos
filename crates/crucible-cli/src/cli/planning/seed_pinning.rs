//! Executable run-identity seed pinning.

use super::*;

/// Pins a run plan's executable scenario and request seed to one run identity.
///
/// # Errors
///
/// Returns [`CliError`] when the scenario cannot be rematerialized with
/// `seed`.
pub(crate) fn pin_run_invocation_seed(
    plan: &mut RunInvocationPlan,
    seed: crucible::Seed,
) -> Result<(), CliError> {
    plan.scenario = reseed_run_scenario_ref(&plan.scenario, seed)?;
    plan.request_seed = Some(seed);
    Ok(())
}

/// Pins a search plan and reloads scenario-bound exploration evidence.
///
/// # Errors
///
/// Returns [`CliError`] when the scenario cannot be rematerialized with
/// `seed`, or when named-truth or retained-evidence input does not match the
/// seeded scenario identity.
pub(crate) fn pin_search_invocation_seed(
    plan: &mut SearchDriverPlan,
    seed: crucible::Seed,
) -> Result<(), CliError> {
    plan.scenario = reseed_run_scenario_ref(&plan.scenario, seed)?;
    if let Some(named_truths) = &plan.schedule_named_truths {
        plan.schedule_named_truths = Some(load_search_schedule_named_truths_file(
            &named_truths.path,
            plan.scenario.scenario_form(),
        )?);
    }
    if let Some(retained_evidence) = &plan.retained_evidence {
        plan.retained_evidence = Some(load_search_retained_evidence_file(
            &retained_evidence.path,
            plan.scenario.scenario_form(),
        )?);
    }
    Ok(())
}
