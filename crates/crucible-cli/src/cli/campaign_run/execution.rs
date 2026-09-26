//! Guarded production campaign execution for local QEMU commands.

use super::*;

pub(super) fn execute_local_qemu_campaign(
    backend: &ResolvedLocalBackend,
    run_plan: &RunInvocationPlan,
    lifecycle: crucible_api::ProductionVmLifecycleConfig,
) -> Result<GuardedDefaultCampaignRun, CliError> {
    if !batch_campaign_run_eligible(run_plan) {
        return Err(backend_error(
            "the requested run shape does not have an exact batch campaign QEMU adapter",
        ));
    }

    let deployment_path =
        resolve_guarded_campaign_deployment_path(run_plan.campaign_deployment.as_deref())?;
    let deployment = load_campaign_run_deployment(&deployment_path)?;
    let resources = guarded_run_resources(deployment.resources, run_plan.max_quanta)?;
    let verify_determinism_findings = deployment.verify_determinism_findings;
    let qemu_build_id = match backend {
        ResolvedLocalBackend::Qemu { qemu_build_id, .. } => qemu_build_id.clone(),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "campaign QEMU run requires a resolved production backend",
            ));
        }
    };
    let scenario = run_plan.scenario.scenario_form().clone();
    let seed = run_plan
        .request_seed
        .unwrap_or_else(|| scenario.scenario_def().seed());
    let request = GuardedDefaultCampaignRunRequest::new(
        scenario,
        seed,
        env!("CARGO_PKG_VERSION"),
        qemu_build_id,
        lifecycle,
        deployment.host,
        resources,
    )
    .with_discovery_stop(guarded_discovery_stop(run_plan)?);
    let request = apply_guarded_campaign_determinism_policy(request, verify_determinism_findings);
    let request = if run_plan.watch_streams_live_status {
        request.with_watch_frames()
    } else {
        request
    };

    run_guarded_default_campaign(request)
        .map_err(|error| campaign_run_error("execute shared campaign owner", error))
}
