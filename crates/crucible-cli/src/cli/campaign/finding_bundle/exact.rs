//! Fresh local-QEMU reproduction of an archived finding capture.

use std::sync::Arc;
use std::time::Duration;

use crucible::DagStore;
use crucible_campaign::{
    AttemptResourceLimits, CampaignArchiveManifestId, CampaignRepository, FindingId, StopCondition,
    StopOutcome,
};
use crucible_daemon::finding_production_replay::{
    FindingProductionReplayExecutionSide, FindingProductionReplayRootImageFormat,
    FindingProductionReplaySelectedSide, FindingProductionReplayTerminalOutcome,
};
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedCampaignReplayClosure, GuardedDefaultCampaignRunRequest, run_guarded_default_campaign,
};
use serde::Serialize;

use super::*;

/// Result of repeating one selected retained role in a fresh local lifecycle.
#[derive(Serialize)]
pub(super) struct ExactFindingReplayReport {
    pub(super) role: &'static str,
    pub(super) reproduced: bool,
    pub(super) completed_quanta: u64,
    pub(super) frontier_ticks: u64,
}

/// Replays the selected archived production boundary without a campaign service.
///
/// # Errors
///
/// Returns an error if the archive, runtime, guest assets, replay closure, or
/// fresh scheduler evidence differs from the retained capture.
pub(super) fn replay_exact_finding(
    cli: &Cli,
    repository: &CampaignRepository,
    archive: CampaignArchiveManifestId,
    finding: FindingId,
    role: CampaignFindingBundleRole,
) -> Result<ExactFindingReplayReport, CliError> {
    let capture = crucible_daemon::load_archived_finding_production_capture(
        repository,
        archive,
        finding,
        role.campaign_role(),
    )
    .map_err(|error| backend_error(format!("archived production replay is invalid: {error}")))?;
    let (qemu, plugin, build_id) = resolve_immutable_qemu(cli)?;
    let private = private_bundle_tempdir()?;
    let guests = crucible_daemon::materialize_finding_replay_guest_assets(
        capture.deployment(),
        &qemu,
        &plugin,
        private.path(),
    )
    .map_err(|error| backend_error(format!("finding guest assets are invalid: {error}")))?;
    let model = crucible::ReproductionArtifact::from_compact_binary(capture.model_reproduction())
        .map_err(|error| {
        backend_error(format!("finding model reproduction is invalid: {error}"))
    })?;
    let closure =
        GuardedCampaignReplayClosure::from_canonical_bytes(capture.campaign_replay_closure())
            .map_err(|error| {
                backend_error(format!("finding replay closure is invalid: {error}"))
            })?;
    closure
        .validate_for_schedule(model.scenario_form(), model.schedule())
        .map_err(|error| backend_error(format!("finding replay choices are invalid: {error}")))?;
    let deployment = crate::cli_verify_serve::load_guarded_campaign_deployment(
        cli.campaign_deployment.as_deref(),
    )?;
    let recipe = capture.recipe();
    if deployment.resources.maximum_execution_quanta() < recipe.lifecycle_quantum_budget {
        return Err(backend_error(
            "local host deployment cannot admit captured replay budget",
        ));
    }
    let resources = AttemptResourceLimits::new(
        deployment.resources.maximum_vcpus(),
        deployment.resources.maximum_resident_bytes(),
        deployment.resources.maximum_disk_bytes(),
        recipe.lifecycle_quantum_budget,
    )
    .map_err(|error| backend_error(format!("finding replay resources are invalid: {error}")))?;
    let lifecycle_objects = load_lifecycle_objects(&capture)?;

    for (index, side) in capture.sides().iter().enumerate() {
        let mut lifecycle = lifecycle_config(
            &qemu,
            &plugin,
            &guests,
            &private.path().join(format!("run-side-{index}")),
            recipe,
            Arc::clone(&lifecycle_objects),
        )?;
        if let Some(trace) = side.resolved_effect_trace() {
            let trace = crucible::ResolvedEffectTrace::from_canonical_bytes(
                trace,
                model
                    .scenario_form()
                    .plan()
                    .fault_signals()
                    .resource_limits(),
            )
            .map_err(|error| backend_error(format!("finding effect trace is invalid: {error}")))?;
            lifecycle = lifecycle.with_fault_replay(trace);
        }
        if side.completed_quanta() == 0 || side.frontier().ticks == 0 {
            return Err(backend_error(
                "finding capture has no replayable scheduler boundary",
            ));
        }
        let request = GuardedDefaultCampaignRunRequest::new(
            model.scenario_form().clone(),
            model.seed(),
            env!("CARGO_PKG_VERSION"),
            build_id.clone(),
            lifecycle,
            deployment.host.clone(),
            resources,
        )
        .with_initial_replay(model.schedule().clone(), Some(closure.clone()))
        .with_discovery_stop(StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds: side.frontier().ticks,
            execution_quanta: side.completed_quanta(),
        });
        let replay = run_guarded_default_campaign(request)
            .map_err(|error| backend_error(format!("fresh finding QEMU replay failed: {error}")))?;
        compare_side(side, &replay)?;
    }

    let selected_index = match capture.selected_side() {
        FindingProductionReplaySelectedSide::Observed
        | FindingProductionReplaySelectedSide::Expected => 0,
        FindingProductionReplaySelectedSide::Reproduced => 1,
    };
    let selected = capture
        .sides()
        .get(selected_index)
        .ok_or_else(|| backend_error("finding capture has no selected replay side"))?;
    Ok(ExactFindingReplayReport {
        role: role.name(),
        reproduced: true,
        completed_quanta: selected.completed_quanta(),
        frontier_ticks: selected.frontier().ticks,
    })
}

pub(super) fn resolve_immutable_qemu(cli: &Cli) -> Result<(PathBuf, PathBuf, String), CliError> {
    // Marker identity does not hash the executable bytes. Reject mutable
    // overrides before discovery probes or executes either candidate.
    for path in [cli.qemu.as_deref(), cli.plugin.as_deref()]
        .into_iter()
        .flatten()
    {
        require_immutable_store_path(path)?;
    }
    for name in [CRUCIBLE_QEMU_ENV, CRUCIBLE_PLUGIN_ENV] {
        if let Some(path) = std::env::var_os(name).filter(|value| !value.is_empty()) {
            require_immutable_store_path(Path::new(&path))?;
        }
    }
    let backend = crate::cli_run_save::require_selftest_qemu_backend(cli)?;
    let (qemu, plugin, build_id) = match backend {
        ResolvedLocalBackend::Qemu {
            qemu,
            plugin,
            qemu_build_id,
            ..
        } => {
            require_immutable_store_path(&qemu)?;
            require_immutable_store_path(&plugin)?;
            (qemu, plugin, qemu_build_id)
        }
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error("exact finding replay requires local QEMU"));
        }
    };
    Ok((qemu, plugin, build_id))
}

fn require_immutable_store_path(path: &Path) -> Result<(), CliError> {
    let canonical = std::fs::canonicalize(path).map_err(CliError::Io)?;
    if !canonical.starts_with("/nix/store") {
        return Err(usage_error(format!(
            "exact finding replay requires an immutable packaged QEMU or plugin path: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn load_lifecycle_objects(
    capture: &crucible_daemon::FindingProductionReplayCapture,
) -> Result<Arc<crucible::MemoryDagStore>, CliError> {
    let objects = Arc::new(crucible::MemoryDagStore::new());
    for (identity, bytes) in capture.lifecycle_objects() {
        let observed = objects.put(bytes).map_err(|error| {
            backend_error(format!("finding lifecycle object is invalid: {error}"))
        })?;
        if observed != *identity {
            return Err(backend_error("finding lifecycle object hash disagrees"));
        }
    }
    Ok(objects)
}

pub(super) fn lifecycle_config(
    qemu: &Path,
    plugin: &Path,
    guests: &crucible_daemon::MaterializedFindingReplayGuestAssets,
    run_state_root: &Path,
    recipe: crucible_daemon::FindingProductionReplayRecipe,
    objects: Arc<crucible::MemoryDagStore>,
) -> Result<crucible_api::ProductionVmLifecycleConfig, CliError> {
    let first = guests
        .guest_assets()
        .first()
        .ok_or_else(|| backend_error("finding capture contains no guest assets"))?;
    let mut config = crucible_api::ProductionVmLifecycleConfig::new_for_guest_architecture(
        qemu,
        plugin,
        first.architecture(),
        first.kernel(),
        first.root_image(),
        run_state_root,
    )
    .with_run_ceiling_ticks(recipe.run_ceiling_ticks)
    .with_quantum_budget(recipe.lifecycle_quantum_budget)
    .with_completion_timeout(Duration::from_secs(300))
    .with_world_artifacts(objects.clone())
    .with_signal_artifacts(objects);
    for guest in guests.guest_assets() {
        config = config.with_guest_assets(
            guest.architecture(),
            guest.kernel(),
            guest.root_image(),
            guest.kernel_cmdline_prefix().map(ToOwned::to_owned),
        );
    }
    if let Some(initrd) = guests.initrd() {
        config = config.with_initrd(initrd);
    }
    if let Some(interval) = recipe.rendezvous_interval_ticks {
        config = config.with_rendezvous_interval_ticks(interval);
    }
    if recipe.coverage {
        config = crucible_daemon::with_production_qemu_coverage(config, true);
    }
    config = match guests.root_image_format() {
        FindingProductionReplayRootImageFormat::Qcow2 => config,
        FindingProductionReplayRootImageFormat::Raw => {
            crucible_daemon::with_production_qemu_raw_root_image(config)
        }
    };
    Ok(config)
}

fn compare_side(
    retained: &FindingProductionReplayExecutionSide,
    replay: &crucible_daemon::qemu_campaign_lifecycle::GuardedDefaultCampaignRun,
) -> Result<(), CliError> {
    let evidence = replay.evidence();
    let outcome = match replay.terminal().observation().stop() {
        StopOutcome::TerminalSuccess
        | StopOutcome::Reached(_)
        | StopOutcome::BoundedPrimaryReached { .. } => {
            FindingProductionReplayTerminalOutcome::Passed
        }
        StopOutcome::ModeledTimeout(_)
        | StopOutcome::BoundedPrimaryTimeout { .. }
        | StopOutcome::PolicyTimeout { .. } => FindingProductionReplayTerminalOutcome::Timeout,
        StopOutcome::AssertionFailure(_)
        | StopOutcome::ScenarioFailure(_)
        | StopOutcome::GuestCrash(_) => FindingProductionReplayTerminalOutcome::Failed,
        StopOutcome::ObservationReached(_) => {
            return Err(backend_error(
                "fresh finding replay has an unexpected terminal outcome",
            ));
        }
    };
    if outcome != retained.outcome()
        || evidence.quanta() != retained.completed_quanta()
        || evidence.frontier() != retained.frontier()
        || evidence.event_log_entries() != retained.event_log()
        || evidence.terminal_fingerprints() != Some(retained.terminal_fingerprints())
        || evidence.resolved_effect_trace() != retained.resolved_effect_trace()
    {
        return Err(backend_error(
            "fresh finding QEMU evidence differs from retained capture",
        ));
    }
    Ok(())
}

impl CampaignFindingBundleRole {
    const fn name(self) -> &'static str {
        match self {
            Self::MinimizationOriginal => "minimization-original",
            Self::MinimizationSelected => "minimization-selected",
            Self::VerificationOriginal => "verification-original",
            Self::VerificationSelected => "verification-selected",
        }
    }
}
