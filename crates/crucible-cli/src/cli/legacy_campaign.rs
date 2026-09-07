//! Thin CLI projection for guarded campaign-backed legacy runs.
//!
//! This module validates command compatibility, translates the deployment and
//! backend configuration into one shared daemon request, and renders the
//! daemon-owned campaign result through the existing run output contract.

use super::*;

use super::packaged_executor::{
    load_guarded_campaign_run_deployment, resolve_guarded_campaign_deployment_path,
};
use crucible_campaign::{AttemptResourceLimits, CampaignState, StopOutcome};
// crucible-lint: allow host-nondeterminism-state -- rendering projects accepted scheduler evidence into the existing CLI wire-frame contract without influencing execution.
use crucible_api as campaign_output_api;
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedDefaultCampaignRun, GuardedDefaultCampaignRunRequest, run_guarded_default_campaign,
};

pub(super) fn run_local_qemu_campaign_replay(
    backend: &ResolvedLocalBackend,
    run_plan: &RunInvocationPlan,
    lifecycle: crucible_api::ProductionVmLifecycleConfig,
    schedule: crucible::Schedule,
) -> Result<RunWorkflowReport, CliError> {
    let deployment_path =
        resolve_guarded_campaign_deployment_path(run_plan.campaign_deployment.as_deref())?;
    let deployment = load_guarded_campaign_run_deployment(&deployment_path)?;
    let resources = guarded_run_resources(deployment.resources)?;
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
    .with_initial_schedule(schedule);
    let campaign = run_guarded_default_campaign(request)
        .map_err(|error| campaign_run_error("replay through shared campaign owner", error))?;
    let (status, terminal_outcome) = campaign_terminal_status(&campaign)?;
    campaign_run_report(run_plan, &campaign, terminal_outcome, status)
}

/// Returns whether the shared campaign owner can execute this run exactly.
pub(super) fn guarded_campaign_run_eligible(plan: &RunInvocationPlan) -> bool {
    plan.terminal_condition == RunTerminalCondition::Quiescence
        && plan.max_virtual_time.is_none()
        && plan.max_virtual_time_ticks.is_none()
        && plan.max_quanta.is_none()
        && plan.execution_mode == RunExecutionMode::ToCompletion
        && plan.save_policy == RunSavePolicy::Never
        && !plan.watch_streams_live_status
        && plan.startup_commands == [SessionCommandKind::Start, SessionCommandKind::Continue]
        && plan.initial_control_commands == [SessionCommandKind::Query]
        && plan.accepted_interactive_commands.is_empty()
        && plan.observer_profile == VERIFY_BASELINE_PROFILE
        && !plan.collect_execution_fingerprints
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
            "campaign-backed QEMU execution currently requires the default run mode without stop, save, watch, or interactive overrides",
        ));
    }

    let deployment_path =
        resolve_guarded_campaign_deployment_path(run_plan.campaign_deployment.as_deref())?;
    let deployment = load_guarded_campaign_run_deployment(&deployment_path)?;
    let resources = guarded_run_resources(deployment.resources)?;
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
    );
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
) -> Result<AttemptResourceLimits, CliError> {
    if deployment.maximum_execution_quanta() < PRODUCTION_CLI_QUANTUM_BUDGET {
        return Err(backend_error(format!(
            "campaign deployment admits {} execution quanta, below the default run requirement of {PRODUCTION_CLI_QUANTUM_BUDGET}",
            deployment.maximum_execution_quanta(),
        )));
    }
    AttemptResourceLimits::new(
        deployment.maximum_vcpus(),
        deployment.maximum_resident_bytes(),
        deployment.maximum_disk_bytes(),
        PRODUCTION_CLI_QUANTUM_BUDGET,
    )
    .map_err(|error| campaign_run_error("build guarded execution limits", error))
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
    let (status, terminal_outcome) = campaign_terminal_status(&campaign)?;
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
            "campaign={} snapshot={} observation={} configuration={} decisions={} defaults={}",
            campaign.campaign().as_str(),
            campaign.final_snapshot(),
            terminal.id(),
            observation.child(),
            configuration.schedule.len(),
            campaign.branch_request_count(),
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(outcome)
}

fn campaign_terminal_status(
    campaign: &GuardedDefaultCampaignRun,
) -> Result<(BackendCommandStatus, OutcomeKind), CliError> {
    Ok(match campaign.terminal().observation().stop() {
        StopOutcome::TerminalSuccess => (BackendCommandStatus::Passed, OutcomeKind::Passed),
        StopOutcome::ModeledTimeout(_) => (BackendCommandStatus::Timeout, OutcomeKind::Timeout),
        StopOutcome::GuestCrash(_) => (BackendCommandStatus::Crashed, OutcomeKind::Crashed),
        StopOutcome::AssertionFailure(_) => (BackendCommandStatus::Failed, OutcomeKind::Failed),
        StopOutcome::ScenarioFailure(_) => (BackendCommandStatus::Failed, OutcomeKind::Failed),
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
    Ok(RunWorkflowReport {
        status,
        execution_owner: RunExecutionOwner::Campaign,
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
        watch_statuses: Vec::new(),
    })
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

    use std::path::Path;

    use clap::Parser;

    fn default_run_plan() -> RunInvocationPlan {
        let cli = Cli::parse_from(["crucible", "run", "builtin:happy-path"]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        plan_run_invocation(args, Path::new("."))
            .expect("built-in default run should produce an invocation plan")
    }

    #[test]
    fn default_campaign_route_rejects_every_explicit_legacy_mode() {
        let mut default = default_run_plan();
        assert!(guarded_campaign_run_eligible(&default));
        default.campaign_deployment = Some(PathBuf::from("guarded.toml"));
        assert!(guarded_campaign_run_eligible(&default));

        let mut plan = default.clone();
        plan.terminal_condition = RunTerminalCondition::VirtualTime;
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.max_virtual_time = Some(String::from("1tick"));
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.max_virtual_time_ticks = Some(1);
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.max_quanta = Some(1);
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.execution_mode = RunExecutionMode::Interactive;
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.save_policy = RunSavePolicy::OnFail;
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default.clone();
        plan.watch_streams_live_status = true;
        assert!(!guarded_campaign_run_eligible(&plan));

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
    fn guarded_campaign_route_uses_the_deployment_quanta_ceiling() {
        let insufficient = AttemptResourceLimits::new(1, 1, 1, PRODUCTION_CLI_QUANTUM_BUDGET - 1)
            .expect("nonzero limits");
        assert!(guarded_run_resources(insufficient).is_err());

        let sufficient = AttemptResourceLimits::new(
            2,
            1024 * 1024 * 1024,
            2 * 1024 * 1024 * 1024,
            PRODUCTION_CLI_QUANTUM_BUDGET,
        )
        .expect("guarded capacity");
        let resources = guarded_run_resources(sufficient).expect("default run resources");
        assert_eq!(
            resources.maximum_execution_quanta(),
            PRODUCTION_CLI_QUANTUM_BUDGET
        );
    }
}
