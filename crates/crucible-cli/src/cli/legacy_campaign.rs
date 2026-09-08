//! Thin CLI projection for guarded campaign-backed legacy runs.
//!
//! This module validates command compatibility, translates the deployment and
//! backend configuration into one shared daemon request, and renders the
//! daemon-owned campaign result through the existing run output contract.

use super::*;

use std::sync::Arc;

use super::packaged_executor::{
    load_guarded_campaign_run_deployment, resolve_guarded_campaign_deployment_path,
};
use crucible_campaign::{AttemptResourceLimits, CampaignState, StopCondition, StopOutcome};
use crucible_cas::content_store::{DirectoryBlobBackend, ImmutableBlobBackend};
// crucible-lint: allow host-nondeterminism-state -- rendering projects accepted scheduler evidence into the existing CLI wire-frame contract without influencing execution.
use crucible_api as campaign_output_api;
use crucible_daemon::ExactCheckpointStore;
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedCampaignReplayClosure, GuardedDefaultCampaignRun, GuardedDefaultCampaignRunRequest,
    GuardedDefaultCampaignSavepoint, GuardedDefaultCampaignWatchFrame,
    run_guarded_default_campaign,
};

pub(super) fn run_local_qemu_campaign_replay(
    backend: &ResolvedLocalBackend,
    run_plan: &RunInvocationPlan,
    lifecycle: crucible_api::ProductionVmLifecycleConfig,
    schedule: crucible::Schedule,
    replay_closure: GuardedCampaignReplayClosure,
) -> Result<RunWorkflowReport, CliError> {
    let deployment_path =
        resolve_guarded_campaign_deployment_path(run_plan.campaign_deployment.as_deref())?;
    let deployment = load_guarded_campaign_run_deployment(&deployment_path)?;
    let resources = guarded_run_resources(deployment.resources, run_plan.max_quanta)?;
    let qemu_build_id = match backend {
        ResolvedLocalBackend::Qemu { qemu_build_id, .. } => qemu_build_id.clone(),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "campaign QEMU replay requires a resolved production backend",
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
    .with_discovery_stop(guarded_discovery_stop(run_plan)?)
    .with_initial_replay(schedule, replay_closure);
    let request = if run_plan.watch_streams_live_status {
        request.with_watch_frames()
    } else {
        request
    };
    let campaign = run_guarded_default_campaign(request)
        .map_err(|error| campaign_run_error("replay through shared campaign owner", error))?;
    let (status, terminal_outcome) = campaign_terminal_status(run_plan, &campaign)?;
    campaign_run_report(run_plan, &campaign, terminal_outcome, status)
}

/// Returns whether the shared campaign owner can execute this run exactly.
pub(super) fn guarded_campaign_run_eligible(plan: &RunInvocationPlan) -> bool {
    guarded_discovery_stop(plan).is_ok()
        && plan.execution_mode == RunExecutionMode::ToCompletion
        && plan.save_policy == RunSavePolicy::Never
        && plan.startup_commands == [SessionCommandKind::Start, SessionCommandKind::Continue]
        && plan.initial_control_commands == [SessionCommandKind::Query]
        && plan.accepted_interactive_commands.is_empty()
        && plan.observer_profile == VERIFY_BASELINE_PROFILE
        && !plan.collect_execution_fingerprints
}

/// Returns whether the shared campaign owner can capture this save exactly.
pub(super) fn guarded_campaign_save_eligible(plan: &SaveInvocationPlan) -> bool {
    plan.at == SaveAtArg::VirtualTime
        && plan.selector.is_none()
        && guarded_campaign_run_eligible(&plan.run_plan)
}

/// Runs one local-QEMU virtual-time save through campaign savepoint capture.
pub(super) fn run_local_qemu_campaign_save_workflow(
    backend: &ResolvedLocalBackend,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    if !guarded_campaign_save_eligible(save_plan) {
        return Err(backend_error(
            "the requested save boundary or control mode does not have an exact campaign-backed QEMU adapter",
        ));
    }

    let run_plan = &save_plan.run_plan;
    let deployment_path =
        resolve_guarded_campaign_deployment_path(run_plan.campaign_deployment.as_deref())?;
    let deployment = load_guarded_campaign_run_deployment(&deployment_path)?;
    let resources = guarded_run_resources(deployment.resources, run_plan.max_quanta)?;
    let qemu_build_id = match backend {
        ResolvedLocalBackend::Qemu { qemu_build_id, .. } => qemu_build_id.clone(),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "campaign QEMU save requires a resolved production backend",
            ));
        }
    };
    let deadline = run_plan
        .max_virtual_time_ticks
        .ok_or_else(|| usage_error("save --at virtual-time requires --max-virtual-time <dur>"))?;
    let stop = StopCondition::VirtualTimeNanoseconds(deadline);
    // The physical closure authenticates this one replay. The exported v3
    // handle and logical DAG closure remain the durable legacy savepoint.
    let checkpoint_directory = tempfile::Builder::new()
        .prefix("crucible-campaign-save-")
        .tempdir()
        .map_err(|error| campaign_run_error("create transient exact checkpoint store", error))?;
    let checkpoint_root = checkpoint_directory.path().to_path_buf();
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "legacy-campaign-savepoints",
        &checkpoint_root,
    ));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(checkpoint_backend, resources.maximum_disk_bytes())
            .map_err(|error| campaign_run_error("open exact checkpoint store", error))?,
    );
    let lifecycle = production_qemu_lifecycle_config(backend)?;
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
    .with_discovery_stop(stop.clone())
    .with_reached_stop_savepoint_capture(Arc::clone(&checkpoints));
    let campaign = run_guarded_default_campaign(request).map_err(|error| {
        campaign_run_error("capture savepoint through shared campaign owner", error)
    })?;
    let report = campaign_save_workflow_report(save_plan, &campaign, &stop)?;

    drop(checkpoints);
    checkpoint_directory.close().map_err(|error| {
        campaign_run_error(
            &format!(
                "remove transient exact checkpoint store {}",
                checkpoint_root.display()
            ),
            error,
        )
    })?;

    let mut outcome =
        finish_save_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, save_plan, report)?;
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "save-live-checkpoint");
    Ok(outcome)
}

fn campaign_save_workflow_report(
    save_plan: &SaveInvocationPlan,
    campaign: &GuardedDefaultCampaignRun,
    stop: &StopCondition,
) -> Result<SaveWorkflowReport, CliError> {
    let savepoint = campaign.savepoint().ok_or_else(|| {
        campaign_run_error_message("campaign completed without an exact savepoint")
    })?;
    validate_campaign_savepoint(campaign, savepoint, stop)?;

    let configuration = campaign.terminal_configuration();
    let evidence = savepoint.evidence();
    let frontier = evidence.frontier();
    let checkpoint = recorded_checkpoint_for_configuration(configuration, frontier)
        .map_err(|error| campaign_run_error("build legacy logical checkpoint", error))?;
    let oracle = validate_savepoint_checkpoint(save_plan, configuration, &checkpoint, frontier)?;
    let mut run = campaign_run_report(
        &save_plan.run_plan,
        campaign,
        OutcomeKind::Passed,
        BackendCommandStatus::Passed,
    )?;
    run.final_state = String::from("virtual-time");
    run.outcome = Some(OutcomeKind::Passed);
    run.terminal_savepoint = Some(oracle.fat_checkpoint);
    run.final_frontier_ticks = frontier.ticks;
    run.final_quanta = evidence.quanta();
    run.budget_timed_out = false;

    Ok(SaveWorkflowReport {
        run,
        oracle,
        boundary_evidence: SaveBoundaryEvidence {
            at: save_plan.at,
            selector: None,
            frontier_ticks: frontier.ticks,
            quanta: evidence.quanta(),
            breakpoint_firing: None,
        },
    })
}

fn validate_campaign_savepoint(
    campaign: &GuardedDefaultCampaignRun,
    savepoint: &GuardedDefaultCampaignSavepoint,
    stop: &StopCondition,
) -> Result<(), CliError> {
    let observation = campaign.terminal().observation();
    if observation.stop() != &StopOutcome::Reached(stop.clone())
        || savepoint.attempt() != observation.attempt()
        || savepoint.configuration() != observation.child()
        || savepoint.stop() != stop
        || savepoint.evidence() != campaign.evidence()
    {
        return Err(campaign_run_error_message(
            "campaign savepoint proof differs from its terminal observation",
        ));
    }
    Ok(())
}

fn campaign_run_error_message(message: impl Into<String>) -> CliError {
    backend_error(format!(
        "campaign-backed QEMU execution failed: {}",
        message.into()
    ))
}

/// Runs one local-QEMU command through shared campaign ownership.
pub(super) fn run_local_qemu_campaign_workflow(
    backend: &ResolvedLocalBackend,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    if !guarded_campaign_run_eligible(run_plan) {
        return Err(backend_error(
            "the requested stop, budget, save, or interactive mode does not have an exact campaign-backed QEMU adapter",
        ));
    }

    let deployment_path =
        resolve_guarded_campaign_deployment_path(run_plan.campaign_deployment.as_deref())?;
    let deployment = load_guarded_campaign_run_deployment(&deployment_path)?;
    let resources = guarded_run_resources(deployment.resources, run_plan.max_quanta)?;
    let qemu_build_id = match backend {
        ResolvedLocalBackend::Qemu { qemu_build_id, .. } => qemu_build_id.clone(),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "campaign QEMU run requires a resolved production backend",
            ));
        }
    };
    let lifecycle = production_qemu_lifecycle_config(backend)?;
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
    let request = if run_plan.watch_streams_live_status {
        request.with_watch_frames()
    } else {
        request
    };
    let campaign = run_guarded_default_campaign(request)
        .map_err(|error| campaign_run_error("execute shared campaign owner", error))?;

    campaign_run_outcome(
        CampaignRunOutcomeContext {
            thin_plan,
            backend_plan,
            ergonomics_plan,
            run_plan,
            backend,
        },
        campaign,
    )
}

fn guarded_run_resources(
    deployment: AttemptResourceLimits,
    requested_quanta: Option<u64>,
) -> Result<AttemptResourceLimits, CliError> {
    let admitted_quanta = requested_quanta
        .unwrap_or(PRODUCTION_CLI_QUANTUM_BUDGET)
        .max(PRODUCTION_CLI_QUANTUM_BUDGET);
    if deployment.maximum_execution_quanta() < admitted_quanta {
        return Err(backend_error(format!(
            "campaign deployment admits {} execution quanta, below the run requirement of {admitted_quanta}",
            deployment.maximum_execution_quanta(),
        )));
    }
    AttemptResourceLimits::new(
        deployment.maximum_vcpus(),
        deployment.maximum_resident_bytes(),
        deployment.maximum_disk_bytes(),
        admitted_quanta,
    )
    .map_err(|error| campaign_run_error("build guarded execution limits", error))
}

fn guarded_discovery_stop(plan: &RunInvocationPlan) -> Result<StopCondition, CliError> {
    if plan.terminal_condition == RunTerminalCondition::Property {
        return Err(backend_error(
            "campaign-backed QEMU execution does not yet support stopping at the first property violation",
        ));
    }

    let virtual_time_deadline = match (&plan.max_virtual_time, plan.max_virtual_time_ticks) {
        (Some(_), Some(deadline)) => Some(deadline),
        (Some(_), None) | (None, Some(_)) => {
            return Err(backend_error(
                "the parsed virtual-time deadline is internally inconsistent",
            ));
        }
        (None, None) => None,
    };

    match (virtual_time_deadline, plan.max_quanta) {
        (Some(virtual_time_nanoseconds), Some(execution_quanta)) => {
            return Ok(StopCondition::VirtualTimeOrExecutionQuanta {
                virtual_time_nanoseconds,
                execution_quanta,
            });
        }
        (Some(deadline), None) => {
            return Ok(StopCondition::VirtualTimeNanoseconds(deadline));
        }
        (None, Some(bound)) => {
            return Ok(StopCondition::ExecutionQuanta(bound));
        }
        (None, None) => {}
    }

    match plan.terminal_condition {
        RunTerminalCondition::Quiescence => Ok(StopCondition::NextChoice),
        RunTerminalCondition::Stopped => Ok(StopCondition::Terminal),
        RunTerminalCondition::VirtualTime => Err(usage_error(
            "--until virtual-time requires --max-virtual-time",
        )),
        RunTerminalCondition::Property => Err(backend_error(
            "campaign-backed QEMU execution does not yet support stopping at the first property violation",
        )),
    }
}

struct CampaignRunOutcomeContext<'a> {
    thin_plan: &'a CliThinWrapperPlan,
    backend_plan: &'a BackendSelectionPlan,
    ergonomics_plan: Option<&'a DeterminismErgonomicsPlan>,
    run_plan: &'a RunInvocationPlan,
    backend: &'a ResolvedLocalBackend,
}

fn campaign_run_outcome(
    context: CampaignRunOutcomeContext<'_>,
    campaign: GuardedDefaultCampaignRun,
) -> Result<BackendCommandOutcome, CliError> {
    let CampaignRunOutcomeContext {
        thin_plan,
        backend_plan,
        ergonomics_plan,
        run_plan,
        backend,
    } = context;
    let terminal = campaign.terminal();
    let observation = terminal.observation();
    let configuration = campaign.terminal_configuration();
    let (status, terminal_outcome) = campaign_terminal_status(run_plan, &campaign)?;
    let report = campaign_run_report(run_plan, &campaign, terminal_outcome, status)?;
    let mut outcome =
        finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, run_plan, report)?;
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "run-campaign-default-path");
    outcome.stdout.push(format!(
        "campaign-run\tcampaign={}\tsnapshot={}\tobservation={}\tconfiguration={}\tstop={}\tattempts={}\tdefaults={}",
        campaign.campaign().as_str(),
        campaign.final_snapshot(),
        terminal.id(),
        observation.child(),
        campaign_stop_label(observation.stop()),
        campaign.observations().len(),
        campaign.branch_request_count(),
    ));
    for (index, accepted) in campaign.observations().iter().enumerate() {
        let observation_ordinal = u64::try_from(index)
            .map_err(|_| backend_error("campaign observation ordinal overflowed"))?;
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: accepted.virtual_time_ticks(),
            node: String::from("campaign"),
            kind: String::from("authenticated_observation"),
            summary: format!(
                "ordinal={} observation={} attempt={} child={} stop={}",
                observation_ordinal,
                accepted.id(),
                accepted.observation().attempt(),
                accepted.observation().child(),
                campaign_stop_label(accepted.observation().stop()),
            ),
        });
    }
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: configuration
            .schedule
            .recorded_virtual_time()
            .unwrap_or_default()
            .ticks,
        node: String::from("campaign"),
        kind: String::from("campaign_completed"),
        summary: format!(
            "campaign={} snapshot={} observation={} configuration={} decisions={} defaults={} frontier_ticks={} quanta={}",
            campaign.campaign().as_str(),
            campaign.final_snapshot(),
            terminal.id(),
            observation.child(),
            configuration.schedule.len(),
            campaign.branch_request_count(),
            campaign.evidence().frontier().ticks,
            campaign.evidence().quanta(),
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(outcome)
}

fn campaign_terminal_status(
    run_plan: &RunInvocationPlan,
    campaign: &GuardedDefaultCampaignRun,
) -> Result<(BackendCommandStatus, OutcomeKind), CliError> {
    campaign_stop_status(run_plan, campaign.terminal().observation().stop())
}

fn campaign_stop_status(
    run_plan: &RunInvocationPlan,
    stop: &StopOutcome,
) -> Result<(BackendCommandStatus, OutcomeKind), CliError> {
    Ok(match stop {
        StopOutcome::TerminalSuccess => (BackendCommandStatus::Passed, OutcomeKind::Passed),
        StopOutcome::ModeledTimeout(_) => (BackendCommandStatus::Timeout, OutcomeKind::Timeout),
        StopOutcome::GuestCrash(_) => (BackendCommandStatus::Crashed, OutcomeKind::Crashed),
        StopOutcome::AssertionFailure(_) => (BackendCommandStatus::Failed, OutcomeKind::Failed),
        StopOutcome::ScenarioFailure(_) => (BackendCommandStatus::Failed, OutcomeKind::Failed),
        StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(deadline))
            if run_plan.max_virtual_time_ticks == Some(*deadline) =>
        {
            (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
        }
        StopOutcome::Reached(StopCondition::ExecutionQuanta(bound))
            if run_plan.max_quanta == Some(*bound) =>
        {
            (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
        }
        StopOutcome::Reached(StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            execution_quanta,
        }) if run_plan.max_virtual_time_ticks == Some(*virtual_time_nanoseconds)
            && run_plan.max_quanta == Some(*execution_quanta) =>
        {
            (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
        }
        StopOutcome::Reached(_) => {
            return Err(backend_error(
                "campaign default run ended at an unexpected nonterminal boundary",
            ));
        }
    })
}

pub(super) fn campaign_run_report(
    run_plan: &RunInvocationPlan,
    campaign: &GuardedDefaultCampaignRun,
    terminal_outcome: OutcomeKind,
    status: BackendCommandStatus,
) -> Result<RunWorkflowReport, CliError> {
    let evidence = campaign.evidence();
    let configuration = campaign.terminal_configuration();
    let streamed_events = evidence
        .event_log_entries()
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| campaign_run_error("encode scheduler event evidence", error))?;
    let streamed_event_frames = evidence
        .event_log_entries()
        .iter()
        .map(|entry| {
            canonical_streaming_event_frame_bytes(&campaign_output_api::StreamingEventFrame {
                generation: 0,
                cursor: campaign_output_api::EventLogCursor::new(entry.sequence()),
                next_cursor: campaign_output_api::EventLogCursor::new(
                    entry.sequence().saturating_add(1),
                ),
                event: campaign_output_api::open_set_event_envelope_from_entry(entry),
            })
        })
        .collect();
    let watch_statuses = if run_plan.watch_streams_live_status {
        campaign
            .watch_frames()
            .iter()
            .map(|frame| campaign_watch_status(frame, campaign.final_snapshot(), terminal_outcome))
            .collect()
    } else {
        Vec::new()
    };
    Ok(RunWorkflowReport {
        status,
        execution_owner: RunExecutionOwner::Campaign,
        campaign_replay_closure: Some(
            campaign
                .replay_closure()
                .to_canonical_bytes()
                .map_err(|error| campaign_run_error("encode replay closure", error))?,
        ),
        created_state: String::from("created"),
        final_state: terminal_final_state(run_plan, Some(terminal_outcome)),
        outcome: Some(terminal_outcome),
        terminal_savepoint: None,
        terminal_configuration: Some(configuration.clone()),
        final_frontier_ticks: evidence.frontier().ticks,
        final_quanta: evidence.quanta(),
        budget_timed_out: terminal_outcome == OutcomeKind::Timeout,
        state_updates: campaign
            .state_updates()
            .iter()
            .copied()
            .map(campaign_state_label)
            .collect(),
        streamed_events,
        streamed_event_frames,
        coverage_feedback: crucible::EventLogCoverageFeedback::from_event_log(
            evidence.event_log_entries(),
        ),
        execution_fingerprints: evidence.execution_fingerprints().to_vec(),
        resolved_effect_trace: evidence.resolved_effect_trace().map(ToOwned::to_owned),
        acknowledged_commands: Vec::new(),
        watch_statuses,
    })
}

fn campaign_watch_status(
    frame: &GuardedDefaultCampaignWatchFrame,
    final_snapshot: crucible_campaign::CampaignSnapshotId,
    terminal_outcome: OutcomeKind,
) -> String {
    let outcome = (frame.snapshot() == final_snapshot).then_some(terminal_outcome);
    let observation = frame
        .observation()
        .map(|observation| observation.to_string())
        .unwrap_or_else(|| String::from("none"));
    format!(
        "state={}\tfrontier_ticks={}\tquanta={}\toutcome={}\tsavepoint=none\towner=campaign\tcampaign={}\tsnapshot={}\tobservation={observation}",
        campaign_state_label(frame.state()),
        frame.frontier().ticks,
        frame.quanta(),
        terminal_outcome_label(outcome),
        frame.campaign().as_str(),
        frame.snapshot(),
    )
}

fn campaign_stop_label(stop: &StopOutcome) -> String {
    match stop {
        StopOutcome::Reached(boundary) => format!("reached:{boundary:?}"),
        StopOutcome::TerminalSuccess => String::from("terminal-success"),
        StopOutcome::ModeledTimeout(name) => format!("timeout:{name}"),
        StopOutcome::GuestCrash(class) => format!("crash:{class}"),
        StopOutcome::AssertionFailure(property) => format!("assertion:{property}"),
        StopOutcome::ScenarioFailure(reasons) => {
            format!("scenario-failure:{}", reasons.join(" | "))
        }
    }
}

fn campaign_state_label(state: CampaignState) -> String {
    match state {
        CampaignState::Created => String::from("created"),
        CampaignState::Running => String::from("running"),
        CampaignState::Paused => String::from("paused"),
        CampaignState::Completed => String::from("completed"),
        CampaignState::Sealed => String::from("sealed"),
    }
}

fn campaign_run_error(context: &str, error: impl fmt::Display) -> CliError {
    backend_error(format!("campaign default run could not {context}: {error}"))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use clap::Parser;
    use crucible_api::ProductionVmLifecycleConfig;
    use crucible_daemon::LinuxQemuAttemptHostConfig;
    use crucible_daemon::qemu_campaign_lifecycle::run_guarded_default_campaign_test_fixture;
    use tempfile::TempDir;

    fn default_run_plan() -> RunInvocationPlan {
        let cli = Cli::parse_from(["crucible", "run", "builtin:happy-path"]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        plan_run_invocation(args, Path::new("."))
            .expect("built-in default run should produce an invocation plan")
    }

    #[test]
    fn campaign_route_accepts_exact_semantic_stops_and_rejects_session_only_modes() {
        let mut default = default_run_plan();
        assert!(guarded_campaign_run_eligible(&default));
        default.campaign_deployment = Some(PathBuf::from("guarded.toml"));
        assert!(guarded_campaign_run_eligible(&default));

        let mut plan = default.clone();
        plan.terminal_condition = RunTerminalCondition::VirtualTime;
        plan.max_virtual_time = Some(String::from("1tick"));
        plan.max_virtual_time_ticks = Some(1);
        assert!(guarded_campaign_run_eligible(&plan));
        assert_eq!(
            guarded_discovery_stop(&plan).expect("virtual-time stop"),
            StopCondition::VirtualTimeNanoseconds(1)
        );

        let cli = Cli::parse_from([
            "crucible",
            "run",
            "builtin:happy-path",
            "--until",
            "virtual-time",
            "--max-virtual-time",
            "2ms",
        ]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        let plan = plan_run_invocation(args, Path::new("."))
            .expect("virtual-time run should produce an invocation plan");
        assert_eq!(
            guarded_discovery_stop(&plan).expect("converted virtual-time stop"),
            StopCondition::VirtualTimeNanoseconds(2_000_000)
        );
        assert_eq!(
            campaign_stop_status(
                &plan,
                &StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(2_000_000)),
            )
            .expect("reached deadline status"),
            (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
        );

        let mut plan = default.clone();
        plan.max_virtual_time = Some(String::from("1tick"));
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.max_virtual_time_ticks = Some(1);
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.terminal_condition = RunTerminalCondition::Stopped;
        assert!(guarded_campaign_run_eligible(&plan));
        assert_eq!(
            guarded_discovery_stop(&plan).expect("terminal stop"),
            StopCondition::Terminal
        );

        let mut plan = default.clone();
        plan.terminal_condition = RunTerminalCondition::Property;
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.max_quanta = Some(1);
        assert!(guarded_campaign_run_eligible(&plan));
        assert_eq!(
            guarded_discovery_stop(&plan).expect("execution-quanta stop"),
            StopCondition::ExecutionQuanta(1)
        );
        assert_eq!(
            campaign_stop_status(
                &plan,
                &StopOutcome::Reached(StopCondition::ExecutionQuanta(1)),
            )
            .expect("reached execution-quanta status"),
            (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
        );

        plan.max_virtual_time = Some(String::from("2ms"));
        plan.max_virtual_time_ticks = Some(2_000_000);
        assert_eq!(
            guarded_discovery_stop(&plan).expect("combined stop"),
            StopCondition::VirtualTimeOrExecutionQuanta {
                virtual_time_nanoseconds: 2_000_000,
                execution_quanta: 1,
            }
        );
        assert_eq!(
            campaign_stop_status(
                &plan,
                &StopOutcome::Reached(StopCondition::VirtualTimeOrExecutionQuanta {
                    virtual_time_nanoseconds: 2_000_000,
                    execution_quanta: 1,
                }),
            )
            .expect("reached combined status"),
            (BackendCommandStatus::Timeout, OutcomeKind::Timeout)
        );

        let mut plan = default.clone();
        plan.execution_mode = RunExecutionMode::Interactive;
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.save_policy = RunSavePolicy::OnFail;
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.watch_streams_live_status = true;
        assert!(guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.startup_commands.pop();
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.initial_control_commands.clear();
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.accepted_interactive_commands
            .push(SessionCommandKind::Continue);
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.observer_profile = VERIFY_HOSTILE_PROFILES[0];
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default;
        plan.collect_execution_fingerprints = true;
        assert!(!guarded_campaign_run_eligible(&plan));
    }

    #[test]
    fn campaign_save_route_accepts_only_standard_virtual_time_saves() {
        let cli = Cli::parse_from([
            "crucible",
            "save",
            "builtin:happy-path",
            "--at",
            "virtual-time",
            "--max-virtual-time",
            "2ms",
        ]);
        let Commands::Save(args) = &cli.command else {
            panic!("expected save command");
        };
        let mut plan = plan_save_invocation(args, Path::new("."), Path::new("./artifacts"))
            .expect("virtual-time save plan");

        assert!(plan.run_plan.campaign_deployment.is_none());
        assert!(guarded_campaign_save_eligible(&plan));

        plan.run_plan.campaign_deployment = Some(PathBuf::from("guarded.toml"));
        assert!(guarded_campaign_save_eligible(&plan));

        let mut unsupported = plan.clone();
        unsupported.at = SaveAtArg::Quiescence;
        unsupported.run_plan.terminal_condition = RunTerminalCondition::Quiescence;
        unsupported.run_plan.max_virtual_time = None;
        unsupported.run_plan.max_virtual_time_ticks = None;
        assert!(!guarded_campaign_save_eligible(&unsupported));

        let mut unsupported = plan.clone();
        unsupported.selector = Some(SaveAtSelector::Marker {
            name: String::from("checkpoint"),
        });
        assert!(!guarded_campaign_save_eligible(&unsupported));

        let mut unsupported = plan;
        unsupported.run_plan.execution_mode = RunExecutionMode::Interactive;
        assert!(!guarded_campaign_save_eligible(&unsupported));
    }

    #[test]
    fn campaign_virtual_time_save_exports_closure_for_unchanged_resume_and_fork_readers() {
        let temporary = TempDir::new().expect("temporary save workspace");
        let artifact_directory = temporary.path().join("artifacts");
        let output = temporary.path().join("campaign.crucible-savepoint");
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--store"),
            temporary.path().display().to_string(),
            String::from("--artifact-dir"),
            artifact_directory.display().to_string(),
            String::from("save"),
            String::from("builtin:happy-path"),
            String::from("--at"),
            String::from("virtual-time"),
            String::from("--max-virtual-time"),
            String::from("2ms"),
            String::from("--out"),
            output.display().to_string(),
        ]);
        let Commands::Save(args) = &cli.command else {
            panic!("expected save command");
        };
        let save_plan = plan_save_invocation(args, temporary.path(), &artifact_directory)
            .expect("virtual-time save plan");
        let stop = StopCondition::VirtualTimeNanoseconds(2_000_000);
        let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
            .expect("campaign fixture resources");
        let exact_root = temporary.path().join("transient-exact");
        let exact_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "legacy-campaign-save-reader-test",
            exact_root.clone(),
        ));
        let checkpoints = Arc::new(
            ExactCheckpointStore::new(exact_backend, resources.maximum_disk_bytes())
                .expect("exact checkpoint store"),
        );
        let scenario = save_plan.run_plan.scenario.scenario_form().clone();
        let seed = save_plan
            .run_plan
            .request_seed
            .unwrap_or_else(|| scenario.scenario_def().seed());
        let host = LinuxQemuAttemptHostConfig::new(
            "/sys/fs/cgroup/crucible-campaign-save-reader-test",
            "/tmp/crucible-campaign-save-reader-test",
            "campaign-save-reader-test",
            1,
            1,
            65_529,
            65_529,
            16,
            1_024,
            Duration::from_secs(1),
        )
        .expect("fixture host configuration");
        let request = GuardedDefaultCampaignRunRequest::new(
            scenario,
            seed,
            "campaign-save-reader-test-engine",
            "campaign-save-reader-test-qemu",
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
            host,
            resources,
        )
        .with_discovery_stop(stop.clone())
        .with_reached_stop_savepoint_capture(checkpoints);
        let campaign = run_guarded_default_campaign_test_fixture(request)
            .expect("campaign fixture should capture an authenticated savepoint");
        std::fs::remove_dir_all(&exact_root)
            .expect("remove transient physical checkpoint before durable readers run");
        let report = campaign_save_workflow_report(&save_plan, &campaign, &stop)
            .expect("project campaign capture into legacy save contract");
        let thin_plan = plan_cli_invocation(&cli);
        let backend_plan = plan_backend_selection(&cli)
            .expect("backend plan")
            .expect("save requires a backend");
        let mut outcome =
            finish_save_workflow_outcome(&thin_plan, &backend_plan, None, &save_plan, report)
                .expect("finish projected save workflow");
        export_savepoint_handle(&save_plan, &mut outcome)
            .expect("export v3 handle and DAG closure");

        let checkpoint = outcome
            .terminal_savepoint
            .expect("projected save exposes its logical checkpoint");
        let handle_evidence = resume_evidence_from_cli(&output, temporary.path());
        let handle_fork_evidence = fork_evidence_from_cli(
            &output.display().to_string(),
            temporary.path(),
            &artifact_directory,
        );
        let checkpoint_reference = format_content_hash_ref(checkpoint);
        let store_evidence =
            resume_evidence_from_cli(Path::new(&checkpoint_reference), temporary.path());
        let store_fork_evidence =
            fork_evidence_from_cli(&checkpoint_reference, temporary.path(), &artifact_directory);

        assert_eq!(handle_evidence, handle_fork_evidence);
        assert_eq!(handle_evidence, store_evidence);
        assert_eq!(handle_evidence, store_fork_evidence);
        assert_eq!(handle_evidence.checkpoint.id, checkpoint);
    }

    fn resume_evidence_from_cli(savepoint: &Path, store: &Path) -> ResumeHandleEvidence {
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--store"),
            store.display().to_string(),
            String::from("resume"),
            savepoint.display().to_string(),
        ]);
        let Commands::Resume(args) = &cli.command else {
            panic!("expected resume command");
        };
        let plan = plan_resume_invocation(args, store).expect("resume plan");
        resume_handle_evidence(&plan).expect("unchanged resume reader accepts campaign save")
    }

    fn fork_evidence_from_cli(
        savepoint: &str,
        store: &Path,
        artifact_directory: &Path,
    ) -> ResumeHandleEvidence {
        let cli = Cli::parse_from([
            String::from("crucible"),
            String::from("--store"),
            store.display().to_string(),
            String::from("fork"),
            String::from(savepoint),
        ]);
        let Commands::Fork(args) = &cli.command else {
            panic!("expected fork command");
        };
        let plan = plan_fork_invocation(args, None, artifact_directory, store).expect("fork plan");
        fork_handle_evidence(&plan).expect("unchanged fork reader accepts campaign save")
    }

    #[test]
    fn guarded_campaign_route_uses_the_deployment_quanta_ceiling() {
        let insufficient = AttemptResourceLimits::new(1, 1, 1, PRODUCTION_CLI_QUANTUM_BUDGET - 1)
            .expect("nonzero limits");
        assert!(guarded_run_resources(insufficient, None).is_err());

        let sufficient = AttemptResourceLimits::new(
            2,
            1024 * 1024 * 1024,
            2 * 1024 * 1024 * 1024,
            PRODUCTION_CLI_QUANTUM_BUDGET,
        )
        .expect("guarded capacity");
        let resources = guarded_run_resources(sufficient, None).expect("default run resources");
        assert_eq!(
            resources.maximum_execution_quanta(),
            PRODUCTION_CLI_QUANTUM_BUDGET
        );

        let larger = AttemptResourceLimits::new(
            2,
            1024 * 1024 * 1024,
            2 * 1024 * 1024 * 1024,
            PRODUCTION_CLI_QUANTUM_BUDGET + 10,
        )
        .expect("larger guarded capacity");
        let resources = guarded_run_resources(larger, Some(PRODUCTION_CLI_QUANTUM_BUDGET + 10))
            .expect("requested run resources");
        assert_eq!(
            resources.maximum_execution_quanta(),
            PRODUCTION_CLI_QUANTUM_BUDGET + 10
        );
        assert!(guarded_run_resources(larger, Some(PRODUCTION_CLI_QUANTUM_BUDGET + 11)).is_err());
    }
}
