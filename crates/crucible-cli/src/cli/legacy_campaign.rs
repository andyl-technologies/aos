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
use crucible_campaign::{
    AttemptResourceLimits, CampaignState, ObservationCondition, ObservationStopSatisfaction,
    StopCondition, StopOutcome,
};
// crucible-lint: allow host-nondeterminism-state -- rendering projects accepted scheduler evidence into the existing CLI wire-frame contract without influencing execution.
use crucible_api as campaign_output_api;
use crucible_daemon::ExactCheckpointStore;
use crucible_daemon::campaign_store_composition::{DirectoryBlobBackend, ImmutableBlobBackend};
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedCampaignContinuationControl, GuardedCampaignReplayClosure,
    GuardedDefaultCampaignObservationSource, GuardedDefaultCampaignRun,
    GuardedDefaultCampaignRunRequest, GuardedDefaultCampaignSavepoint,
    GuardedDefaultCampaignWatchFrame, run_guarded_default_campaign,
};

/// Returns whether the shared campaign owner can resume this logical checkpoint exactly.
pub(super) fn guarded_campaign_resume_eligible(
    plan: &ResumeInvocationPlan,
    evidence: &ResumeHandleEvidence,
) -> bool {
    plan.execution_mode == RunExecutionMode::ToCompletion
        && plan.startup_commands == [SessionCommandKind::Start, SessionCommandKind::Continue]
        && plan.initial_control_commands == [SessionCommandKind::Query]
        && plan.accepted_interactive_commands.is_empty()
        && guarded_resume_stop(plan, evidence).is_ok()
        && campaign_resume_evidence_supported(evidence)
}

/// Returns whether the shared campaign owner can execute a standard fork exactly.
pub(super) fn guarded_campaign_fork_eligible(
    plan: &ForkInvocationPlan,
    evidence: &ResumeHandleEvidence,
) -> bool {
    plan.execution_mode == RunExecutionMode::ToCompletion
        && plan.startup_commands == [SessionCommandKind::Fork, SessionCommandKind::Continue]
        && plan.initial_control_commands == [SessionCommandKind::Query]
        && plan.accepted_interactive_commands.is_empty()
        && guarded_continuation_stop(
            plan.terminal_condition,
            plan.max_virtual_time_ticks,
            &evidence.scenario_form,
        )
        .is_ok()
        && campaign_resume_evidence_supported(evidence)
}

fn campaign_resume_evidence_supported(evidence: &ResumeHandleEvidence) -> bool {
    evidence.schedule.decisions().iter().all(|decision| {
        matches!(
            decision,
            // crucible-lint: allow host-nondeterminism-state -- eligibility reads authenticated scheduler evidence only to choose the exact campaign resume route.
            crucible::Decision::DeliveryOrder(_)
                // crucible-lint: allow host-nondeterminism-state -- eligibility reads authenticated scheduler evidence only to choose the exact campaign resume route.
                | crucible::Decision::RngDraw(_)
                // crucible-lint: allow host-nondeterminism-state -- eligibility reads authenticated scheduler evidence only to choose the exact campaign resume route.
                | crucible::Decision::Preemption(_)
                // crucible-lint: allow host-nondeterminism-state -- eligibility reads an authenticated typed choice whose exact closure is carried by the savepoint.
                | crucible::Decision::Selection(_)
        )
    }) && evidence.schedule.decisions().iter().all(|decision| {
        // crucible-lint: allow host-nondeterminism-state -- eligibility inspects authenticated scheduler evidence only to reject unsupported model-sampled selections before routing.
        let crucible::Decision::Selection(decision) = decision else {
            return true;
        };
        decision.selection().is_ok_and(|selection| {
            !matches!(
                selection.origin(),
                crucible_campaign::SelectionOrigin::ModelSample(_)
            )
        })
    }) && evidence
        .replay_closure
        .validate_for_schedule(&evidence.scenario_form, &evidence.schedule)
        .is_ok()
}

/// Resumes one local-QEMU checkpoint through campaign ownership.
pub(super) fn run_local_qemu_campaign_resume_workflow(
    backend: &ResolvedLocalBackend,
    resume_plan: &ResumeInvocationPlan,
    evidence: &ResumeHandleEvidence,
) -> Result<ResumeWorkflowReport, CliError> {
    if !guarded_campaign_resume_eligible(resume_plan, evidence) {
        return Err(backend_error(
            "the requested checkpoint, stop, or control mode does not have an exact campaign-backed QEMU resume adapter",
        ));
    }

    run_local_qemu_campaign_continuation_workflow(backend, resume_plan, evidence, None)
}

fn run_local_qemu_campaign_continuation_workflow(
    backend: &ResolvedLocalBackend,
    resume_plan: &ResumeInvocationPlan,
    evidence: &ResumeHandleEvidence,
    continuation_control: Option<GuardedCampaignContinuationControl>,
) -> Result<ResumeWorkflowReport, CliError> {
    let deployment_path = resolve_guarded_campaign_deployment_path(None)?;
    let deployment = load_guarded_campaign_run_deployment(&deployment_path)?;
    let resources = guarded_run_resources(deployment.resources, None)?;
    let qemu_build_id = match backend {
        ResolvedLocalBackend::Qemu { qemu_build_id, .. } => qemu_build_id.clone(),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "campaign QEMU resume requires a resolved production backend",
            ));
        }
    };
    let lifecycle = production_qemu_lifecycle_config(backend)?;
    let final_stop = guarded_resume_stop(resume_plan, evidence)?;
    let checkpoint_directory = tempfile::Builder::new()
        .prefix("crucible-campaign-resume-")
        .tempdir()
        .map_err(|error| campaign_run_error("create transient exact checkpoint store", error))?;
    let checkpoint_root = checkpoint_directory.path().to_path_buf();
    let checkpoint_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "legacy-campaign-resume-checkpoints",
        &checkpoint_root,
    ));
    let checkpoints = Arc::new(
        ExactCheckpointStore::new(checkpoint_backend, resources.maximum_disk_bytes())
            .map_err(|error| campaign_run_error("open exact checkpoint store", error))?,
    );
    let request = GuardedDefaultCampaignRunRequest::new(
        evidence.scenario_form.clone(),
        evidence.scenario.seed(),
        env!("CARGO_PKG_VERSION"),
        qemu_build_id,
        lifecycle,
        deployment.host,
        resources,
    );
    let request = attach_guarded_resume_source(
        request,
        evidence,
        final_stop,
        Arc::clone(&checkpoints),
        continuation_control,
    );
    let request = if resume_plan.watch_streams_live_status {
        request.with_watch_frames()
    } else {
        request
    };
    let result = run_guarded_default_campaign(request)
        .map_err(|error| campaign_run_error("resume through shared campaign owner", error))
        .and_then(|campaign| campaign_resume_workflow_report(resume_plan, evidence, &campaign));
    complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        result,
    )
}

fn attach_guarded_resume_source(
    request: GuardedDefaultCampaignRunRequest,
    evidence: &ResumeHandleEvidence,
    final_stop: StopCondition,
    checkpoints: Arc<ExactCheckpointStore>,
    continuation_control: Option<GuardedCampaignContinuationControl>,
) -> GuardedDefaultCampaignRunRequest {
    if let (Some(proof), Some(source_evidence)) = (
        evidence.source_observation_proof.as_deref(),
        evidence.source_observation_evidence.as_deref(),
    ) {
        let source =
            GuardedDefaultCampaignObservationSource::new(proof.clone(), source_evidence.clone());
        return match continuation_control {
            Some(control) => request.with_controlled_observation_resume_source(
                evidence.schedule.clone(),
                evidence.replay_closure.clone(),
                evidence.checkpoint.clone(),
                source,
                final_stop,
                checkpoints,
                control,
            ),
            None => request.with_observation_resume_source(
                evidence.schedule.clone(),
                evidence.replay_closure.clone(),
                evidence.checkpoint.clone(),
                source,
                final_stop,
                checkpoints,
            ),
        };
    }

    match continuation_control {
        Some(control) => request.with_controlled_resume_source(
            evidence.schedule.clone(),
            evidence.replay_closure.clone(),
            evidence.checkpoint.clone(),
            final_stop,
            checkpoints,
            control,
        ),
        None => request.with_resume_source(
            evidence.schedule.clone(),
            evidence.replay_closure.clone(),
            evidence.checkpoint.clone(),
            final_stop,
            checkpoints,
        ),
    }
}

/// Forks one local-QEMU checkpoint through campaign-owned continuation control.
pub(super) fn run_local_qemu_campaign_fork_workflow(
    backend: &ResolvedLocalBackend,
    fork_plan: &ForkInvocationPlan,
    evidence: &ResumeHandleEvidence,
) -> Result<ForkWorkflowReport, CliError> {
    if !guarded_campaign_fork_eligible(fork_plan, evidence) {
        return Err(backend_error(
            "the requested checkpoint, fork recipe, stop, or control mode does not have an exact campaign-backed QEMU fork adapter",
        ));
    }

    let resume_plan = ResumeInvocationPlan {
        savepoint: fork_plan.source.clone(),
        store_root: fork_plan.store_root.clone(),
        terminal_condition: fork_plan.terminal_condition,
        max_virtual_time: fork_plan.max_virtual_time.clone(),
        max_virtual_time_ticks: fork_plan.max_virtual_time_ticks,
        execution_mode: fork_plan.execution_mode,
        watch_streams_live_status: fork_plan.watch_streams_live_status,
        startup_commands: vec![SessionCommandKind::Start, SessionCommandKind::Continue],
        initial_control_commands: fork_plan.initial_control_commands.clone(),
        accepted_interactive_commands: Vec::new(),
    };
    let control = guarded_campaign_fork_control(fork_plan, evidence)?;
    let resumed =
        run_local_qemu_campaign_continuation_workflow(backend, &resume_plan, evidence, control)?;

    Ok(campaign_fork_workflow_report(fork_plan, evidence, resumed))
}

fn guarded_campaign_fork_control(
    plan: &ForkInvocationPlan,
    evidence: &ResumeHandleEvidence,
) -> Result<Option<GuardedCampaignContinuationControl>, CliError> {
    if let Some(seed) = plan.fork_seed {
        return Ok(Some(GuardedCampaignContinuationControl::reseed(
            evidence.checkpoint.virtual_time,
            crucible::Seed::from_u64(seed),
        )));
    }
    if plan.decision_overrides.is_empty() {
        return Ok(None);
    }

    let overrides = fork_override_decisions(plan)
        .into_iter()
        .filter_map(|decision| match decision {
            crucible::Decision::Override(decision) => Some(decision),
            _ => None,
        })
        .collect();
    GuardedCampaignContinuationControl::scheduler_overrides(
        evidence.checkpoint.virtual_time,
        overrides,
    )
    .map(Some)
    .map_err(|error| campaign_run_error("model fork continuation input", error))
}

fn campaign_fork_workflow_report(
    fork_plan: &ForkInvocationPlan,
    evidence: &ResumeHandleEvidence,
    resumed: ResumeWorkflowReport,
) -> ForkWorkflowReport {
    ForkWorkflowReport {
        run: resumed.run,
        source_checkpoint: resumed.source_checkpoint,
        branch_checkpoint: evidence.checkpoint.id,
        branch_configuration: resumed.resumed_configuration,
        terminal_configuration: resumed.terminal_configuration,
        scenario_form: evidence.scenario_form.clone(),
        scenario_label: fork_plan.source.label(),
        label: fork_plan.label.clone(),
        terminal_oracle: resumed.terminal_oracle,
    }
}

fn guarded_resume_stop(
    plan: &ResumeInvocationPlan,
    evidence: &ResumeHandleEvidence,
) -> Result<StopCondition, CliError> {
    guarded_continuation_stop(
        plan.terminal_condition,
        plan.max_virtual_time_ticks,
        &evidence.scenario_form,
    )
}

fn guarded_continuation_stop(
    terminal_condition: RunTerminalCondition,
    max_virtual_time_ticks: Option<u64>,
    scenario: &crucible::ScenarioDefForm,
) -> Result<StopCondition, CliError> {
    match terminal_condition {
        RunTerminalCondition::Quiescence => Ok(StopCondition::Observation(
            ObservationCondition::SchedulerQuiescent,
        )),
        RunTerminalCondition::VirtualTime => max_virtual_time_ticks
            .map(StopCondition::VirtualTimeNanoseconds)
            .ok_or_else(|| usage_error("resume --until virtual-time requires --max-virtual-time")),
        RunTerminalCondition::Stopped => Ok(StopCondition::Terminal),
        RunTerminalCondition::Property if scenario.properties().assertions().is_empty() => {
            Err(invalid_scenario(format!(
                "resume --until property requires scenario {} to declare at least one assertion",
                scenario.id().to_hex()
            )))
        }
        RunTerminalCondition::Property => Ok(StopCondition::Observation(
            ObservationCondition::AnyAssertionViolationTransition,
        )),
    }
}

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
    guarded_discovery_stop(plan).is_ok() && guarded_campaign_execution_shape_eligible(plan)
}

fn guarded_campaign_execution_shape_eligible(plan: &RunInvocationPlan) -> bool {
    plan.execution_mode == RunExecutionMode::ToCompletion
        && plan.save_policy == RunSavePolicy::Never
        && plan.startup_commands == [SessionCommandKind::Start, SessionCommandKind::Continue]
        && plan.initial_control_commands == [SessionCommandKind::Query]
        && plan.accepted_interactive_commands.is_empty()
        && plan.observer_profile == VERIFY_BASELINE_PROFILE
        && !plan.collect_execution_fingerprints
}

/// Returns whether the shared campaign owner can capture this save exactly.
pub(super) fn guarded_campaign_save_eligible(plan: &SaveInvocationPlan) -> bool {
    guarded_campaign_save_stop(plan).is_ok()
        && guarded_campaign_execution_shape_eligible(&plan.run_plan)
}

/// Runs one local-QEMU semantic save through campaign savepoint capture.
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
    let stop = guarded_campaign_save_stop(save_plan)?;
    // The physical closure authenticates this one replay. The exported
    // versioned handle and logical DAG closure remain the durable savepoint.
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
    let report = run_guarded_default_campaign(request)
        .map_err(|error| {
            campaign_run_error("capture savepoint through shared campaign owner", error)
        })
        .and_then(|campaign| campaign_save_workflow_report(save_plan, &campaign, &stop));
    let report = complete_transient_checkpoint_workflow(
        checkpoints,
        checkpoint_directory,
        &checkpoint_root,
        report,
    )?;

    let mut outcome =
        finish_save_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, save_plan, report)?;
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "save-live-checkpoint");
    Ok(outcome)
}

fn complete_transient_checkpoint_workflow<T>(
    checkpoints: Arc<ExactCheckpointStore>,
    checkpoint_directory: tempfile::TempDir,
    checkpoint_root: &Path,
    result: Result<T, CliError>,
) -> Result<T, CliError> {
    drop(checkpoints);
    let cleanup = checkpoint_directory.close().map_err(|error| {
        campaign_run_error(
            &format!(
                "remove transient exact checkpoint store {}",
                checkpoint_root.display()
            ),
            error,
        )
    });
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
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
    validate_portable_campaign_save_schedule(&configuration.schedule)?;
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
    run.final_state = save_plan.at.label().to_owned();
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
            selector: save_plan.selector.clone(),
            frontier_ticks: frontier.ticks,
            quanta: evidence.quanta(),
            proof: campaign_save_boundary_proof(
                save_plan,
                campaign.terminal().observation().stop(),
                evidence,
                campaign.terminal().observation_evidence(),
            )?,
        },
    })
}

// crucible-lint: allow host-nondeterminism-state -- validation reads the canonical campaign schedule only to fail closed before portable export.
fn validate_portable_campaign_save_schedule(schedule: &Schedule) -> Result<(), CliError> {
    let supports_portable_resume = schedule.decisions().iter().all(|decision| {
        matches!(
            decision,
            // crucible-lint: allow host-nondeterminism-state -- validation accepts only scheduler-authored decisions supported by portable replay.
            crucible::Decision::DeliveryOrder(_)
                // crucible-lint: allow host-nondeterminism-state -- validation accepts only scheduler-authored decisions supported by portable replay.
                | crucible::Decision::RngDraw(_)
                // crucible-lint: allow host-nondeterminism-state -- validation accepts only scheduler-authored decisions supported by portable replay.
                | crucible::Decision::Preemption(_)
                // crucible-lint: allow host-nondeterminism-state -- portable save retains the exact authenticated choice closure for this selection.
                | crucible::Decision::Selection(_)
        )
    });
    if !supports_portable_resume {
        return Err(backend_error(
            "campaign-backed save reached a recorded decision that portable resume and fork cannot yet authenticate from the savepoint handle",
        ));
    }
    Ok(())
}

fn campaign_resume_workflow_report(
    resume_plan: &ResumeInvocationPlan,
    evidence: &ResumeHandleEvidence,
    campaign: &GuardedDefaultCampaignRun,
) -> Result<ResumeWorkflowReport, CliError> {
    let resume = campaign.resume().ok_or_else(|| {
        campaign_run_error_message("campaign completed without authenticated resume evidence")
    })?;
    if resume.source_checkpoint() != evidence.checkpoint.id
        || resume.source_configuration().as_hash().as_bytes() != evidence.configuration.id().bytes
        || resume.source_frontier() != evidence.checkpoint.virtual_time
        || !campaign
            .observations()
            .iter()
            .any(|observation| observation.id() == resume.source_observation())
    {
        return Err(CliError::Identity(String::from(
            "campaign resume source proof differs from the requested legacy checkpoint",
        )));
    }
    match (
        resume.source_savepoint(),
        resume.ready(),
        resume.selection(),
        resume.continuation(),
    ) {
        (Some(_), Some(_), Some(_), Some(_)) | (None, None, None, None) => {}
        _ => {
            return Err(CliError::Identity(String::from(
                "campaign resume continuation lost its exact capture or typed selection proof",
            )));
        }
    }
    validate_replayed_source_observation(evidence, campaign, resume.source_observation())?;

    let configuration = campaign.terminal_configuration();
    validate_resume_terminal_source_ancestor(evidence, configuration)?;
    let frontier = campaign.evidence().frontier();
    let stop = campaign.terminal().observation().stop();
    let (status, terminal_outcome) = campaign_resume_status(resume_plan, stop)?;
    validate_campaign_resume_frontier(resume_plan, resume.source_frontier(), stop, frontier)?;
    let checkpoint = recorded_checkpoint_for_configuration(configuration, frontier)
        .map_err(|error| campaign_run_error("build resumed terminal checkpoint", error))?;
    let terminal_oracle = validate_checkpoint_with_replay_oracle_anchored(
        "resume",
        &evidence.scenario,
        [(&evidence.configuration, &evidence.checkpoint)],
        configuration,
        &checkpoint,
        frontier,
    )?;
    let final_state = campaign_resume_final_state(resume_plan, stop, terminal_outcome);
    let mut run = campaign_run_report_with_state(
        campaign,
        terminal_outcome,
        status,
        final_state,
        resume_plan.watch_streams_live_status,
    )?;
    run.terminal_savepoint = Some(terminal_oracle.fat_checkpoint);

    Ok(ResumeWorkflowReport {
        run,
        source_checkpoint: evidence.checkpoint.id,
        resumed_configuration: evidence.configuration.id(),
        terminal_configuration: configuration.clone(),
        scenario_label: resume_plan.savepoint.label(),
        terminal_oracle,
    })
}

fn validate_replayed_source_observation(
    evidence: &ResumeHandleEvidence,
    campaign: &GuardedDefaultCampaignRun,
    source_observation: crucible_campaign::ObservationId,
) -> Result<(), CliError> {
    let (Some(expected), Some(expected_evidence)) = (
        evidence.source_observation_proof.as_deref(),
        evidence.source_observation_evidence.as_deref(),
    ) else {
        return Ok(());
    };
    let actual = campaign
        .observations()
        .iter()
        .find(|observation| observation.id() == source_observation)
        .ok_or_else(|| {
            CliError::Identity(String::from(
                "campaign resume omitted the replayed source observation",
            ))
        })?;
    if !matches!(
        actual.observation().stop(),
        StopOutcome::ObservationReached(proof) if proof.as_ref() == expected
    ) {
        return Err(CliError::Identity(String::from(
            "campaign resume did not reproduce the portable source observation proof",
        )));
    }
    let actual_evidence = actual.observation_evidence().ok_or_else(|| {
        CliError::Identity(String::from(
            "campaign resume omitted the replayed source observation evidence",
        ))
    })?;
    actual_evidence
        .verify_observation_stop_proof(expected)
        .map_err(|error| {
            campaign_run_error("authenticate replayed source observation evidence", error)
        })?;
    if actual_evidence != expected_evidence {
        return Err(CliError::Identity(String::from(
            "campaign resume did not reproduce the portable source observation evidence",
        )));
    }

    Ok(())
}

fn campaign_resume_status(
    plan: &ResumeInvocationPlan,
    stop: &StopOutcome,
) -> Result<(BackendCommandStatus, OutcomeKind), CliError> {
    Ok(match stop {
        StopOutcome::TerminalSuccess => (BackendCommandStatus::Passed, OutcomeKind::Passed),
        StopOutcome::ModeledTimeout(_) => (BackendCommandStatus::Timeout, OutcomeKind::Timeout),
        StopOutcome::GuestCrash(_) => (BackendCommandStatus::Crashed, OutcomeKind::Crashed),
        StopOutcome::AssertionFailure(_) | StopOutcome::ScenarioFailure(_) => {
            (BackendCommandStatus::Failed, OutcomeKind::Failed)
        }
        StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(deadline))
            if plan.terminal_condition == RunTerminalCondition::VirtualTime
                && plan.max_virtual_time_ticks == Some(*deadline) =>
        {
            (BackendCommandStatus::Passed, OutcomeKind::Passed)
        }
        StopOutcome::Reached(_) => {
            return Err(campaign_run_error_message(
                "campaign resume ended at an unexpected nonterminal boundary",
            ));
        }
        StopOutcome::ObservationReached(proof)
            if plan.terminal_condition == RunTerminalCondition::Quiescence
                && proof.condition() == &ObservationCondition::SchedulerQuiescent
                && proof.satisfaction() == ObservationStopSatisfaction::SchedulerQuiescent =>
        {
            (BackendCommandStatus::Passed, OutcomeKind::Passed)
        }
        StopOutcome::ObservationReached(proof)
            if plan.terminal_condition == RunTerminalCondition::Property
                && proof.condition() == &ObservationCondition::AnyAssertionViolationTransition
                && proof.satisfaction()
                    == ObservationStopSatisfaction::AssertionViolationTransition =>
        {
            (BackendCommandStatus::Failed, OutcomeKind::Failed)
        }
        StopOutcome::ObservationReached(_) => {
            return Err(campaign_run_error_message(
                "campaign resume ended at an unexpected observation boundary",
            ));
        }
    })
}

fn campaign_resume_final_state(
    plan: &ResumeInvocationPlan,
    stop: &StopOutcome,
    outcome: OutcomeKind,
) -> String {
    match (plan.terminal_condition, stop) {
        (RunTerminalCondition::Quiescence, StopOutcome::ObservationReached(_)) => {
            String::from("quiescent")
        }
        (RunTerminalCondition::Property, StopOutcome::ObservationReached(_)) => {
            String::from("property-failed")
        }
        (
            RunTerminalCondition::VirtualTime,
            StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(_)),
        ) => String::from("virtual-time"),
        (RunTerminalCondition::Stopped, _) => String::from("stopped"),
        _ => terminal_outcome_label(Some(outcome)).to_owned(),
    }
}

fn validate_campaign_resume_frontier(
    plan: &ResumeInvocationPlan,
    source_frontier: crucible::VirtualTime,
    stop: &StopOutcome,
    frontier: crucible::VirtualTime,
) -> Result<(), CliError> {
    if frontier.ticks < source_frontier.ticks {
        return Err(CliError::Identity(format!(
            "campaign resume terminal frontier {} precedes authenticated source frontier {}",
            frontier.ticks, source_frontier.ticks
        )));
    }

    if let StopOutcome::ObservationReached(proof) = stop {
        let proof_frontier = proof.boundary().frontier_nanoseconds();
        if proof_frontier != frontier.ticks {
            return Err(CliError::Identity(format!(
                "campaign resume observation proof frontier {proof_frontier} differs from terminal frontier {}",
                frontier.ticks
            )));
        }
        return Ok(());
    }

    let StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(deadline)) = stop else {
        return Ok(());
    };
    if plan.terminal_condition != RunTerminalCondition::VirtualTime
        || plan.max_virtual_time_ticks != Some(*deadline)
    {
        return Ok(());
    }

    // Resuming cannot rewind an already-reached source. A deadline behind the
    // source applies to the continuation and therefore completes at the source.
    let expected_frontier = source_frontier.ticks.max(*deadline);
    if frontier.ticks != expected_frontier {
        return Err(CliError::Identity(format!(
            "campaign resume virtual-time boundary produced frontier {}, expected {} from source {} and deadline {}",
            frontier.ticks, expected_frontier, source_frontier.ticks, deadline
        )));
    }

    Ok(())
}

fn guarded_campaign_save_stop(plan: &SaveInvocationPlan) -> Result<StopCondition, CliError> {
    match (plan.at, plan.selector.as_ref()) {
        (SaveAtArg::VirtualTime, None) => plan
            .run_plan
            .max_virtual_time_ticks
            .map(StopCondition::VirtualTimeNanoseconds)
            .ok_or_else(|| usage_error("save --at virtual-time requires --max-virtual-time <dur>")),
        (SaveAtArg::Marker, Some(SaveAtSelector::Marker { name })) => {
            Ok(StopCondition::NamedBoundary(name.clone()))
        }
        (SaveAtArg::Quiescence, None) => Ok(StopCondition::Observation(
            ObservationCondition::SchedulerQuiescent,
        )),
        (SaveAtArg::Property, Some(SaveAtSelector::PropertyViolation { assertion })) => {
            Ok(StopCondition::Observation(
                ObservationCondition::AssertionViolationTransition(assertion.clone()),
            ))
        }
        _ => Err(backend_error(
            "the requested save boundary does not have an exact campaign-backed QEMU adapter",
        )),
    }
}

fn campaign_save_boundary_proof(
    plan: &SaveInvocationPlan,
    terminal: &StopOutcome,
    evidence: &crucible_daemon::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot,
    observation_evidence: Option<&crucible_daemon::CrucibleMeasurementReplayEvidence>,
) -> Result<SaveBoundaryProof, CliError> {
    match (plan.at, plan.selector.as_ref(), terminal) {
        (SaveAtArg::VirtualTime, None, _) => return Ok(SaveBoundaryProof::Coordinate),
        (SaveAtArg::Quiescence, None, StopOutcome::ObservationReached(proof))
        | (
            SaveAtArg::Property,
            Some(SaveAtSelector::PropertyViolation { .. }),
            StopOutcome::ObservationReached(proof),
        ) => {
            let observation_evidence = observation_evidence.ok_or_else(|| {
                campaign_run_error_message(
                    "campaign observation save lost its authenticated raw boundary evidence",
                )
            })?;
            observation_evidence
                .verify_observation_stop_proof(proof)
                .map_err(|error| {
                    campaign_run_error(
                        "authenticate campaign observation save boundary evidence",
                        error,
                    )
                })?;
            return Ok(SaveBoundaryProof::CampaignObservation {
                proof: proof.clone(),
                evidence: observation_evidence.canonical_bytes().map_err(|error| {
                    campaign_run_error("encode campaign observation boundary evidence", error)
                })?,
            });
        }
        (SaveAtArg::Marker, Some(SaveAtSelector::Marker { .. }), _) => {}
        _ => {
            return Err(campaign_run_error_message(
                "campaign save terminal outcome does not carry its requested boundary proof",
            ));
        }
    };
    let Some(SaveAtSelector::Marker { name }) = plan.selector.as_ref() else {
        return Err(campaign_run_error_message(
            "campaign marker save has no marker selector",
        ));
    };
    let marker = crucible::MarkerId::from_name(name);
    let entry = evidence
        .event_log_entries()
        .iter()
        .rev()
        .find(|entry| {
            matches!(
                entry.payload(),
                crucible_model::SchedulerEventLogPayload::Observable(_)
            ) && entry.event_payload().kind() == "guest_marker"
                && entry.event_payload().string("marker") == Some(name)
        })
        .ok_or_else(|| {
            campaign_run_error_message(format!(
                "campaign marker save reached `{name}` without its scheduler event proof"
            ))
        })?;

    // The campaign owner stops directly on NamedBoundary and does not register
    // a session breakpoint. Preserve the scheduler-owned marker identity so
    // the v4 handle cannot claim an actor-assigned breakpoint that never fired.
    if !entry.has_valid_content_hash() {
        return Err(campaign_run_error_message(
            "campaign marker proof has an invalid retained event content hash",
        ));
    }
    let node = entry.event_payload().node("node").ok_or_else(|| {
        campaign_run_error_message("campaign marker proof has no typed source node")
    })?;
    let retired_icount = entry
        .event_payload()
        .icount("retired_icount")
        .ok_or_else(|| {
            campaign_run_error_message("campaign marker proof has no typed retired icount")
        })?;
    Ok(SaveBoundaryProof::CampaignMarkerEvent {
        sequence: entry.sequence(),
        content_hash: entry.content_hash(),
        node: node.clone(),
        retired_icount: retired_icount.retired,
        marker,
    })
}

fn validate_campaign_savepoint(
    campaign: &GuardedDefaultCampaignRun,
    savepoint: &GuardedDefaultCampaignSavepoint,
    stop: &StopCondition,
) -> Result<(), CliError> {
    let observation = campaign.terminal().observation();
    if !observation.stop().reaches(stop)
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
        StopOutcome::ObservationReached(_) => {
            return Err(backend_error(
                "campaign default run ended at an unsupported observation boundary",
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
    campaign_run_report_with_state(
        campaign,
        terminal_outcome,
        status,
        terminal_final_state(run_plan, Some(terminal_outcome)),
        run_plan.watch_streams_live_status,
    )
}

fn campaign_run_report_with_state(
    campaign: &GuardedDefaultCampaignRun,
    terminal_outcome: OutcomeKind,
    status: BackendCommandStatus,
    final_state: String,
    watch_streams_live_status: bool,
) -> Result<RunWorkflowReport, CliError> {
    let evidence = campaign.evidence();
    let configuration = campaign.terminal_configuration();
    let execution_fingerprints = campaign_execution_fingerprints(
        evidence.execution_fingerprints(),
        evidence.terminal_fingerprints(),
    )?;
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
    let watch_statuses = if watch_streams_live_status {
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
        final_state,
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
        execution_fingerprints,
        resolved_effect_trace: evidence.resolved_effect_trace().map(ToOwned::to_owned),
        acknowledged_commands: Vec::new(),
        watch_statuses,
    })
}

fn campaign_execution_fingerprints(
    diagnostics: &[crucible::FingerprintSample],
    terminal: Option<&[crucible::FingerprintSample]>,
) -> Result<Vec<crucible::FingerprintSample>, CliError> {
    let terminal = terminal.ok_or_else(|| {
        backend_error("campaign default run completed without terminal fingerprint evidence")
    })?;
    let mut execution_fingerprints = diagnostics.to_vec();
    execution_fingerprints.extend_from_slice(terminal);
    Ok(execution_fingerprints)
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
        StopOutcome::ObservationReached(proof) => match proof.condition() {
            ObservationCondition::SchedulerQuiescent => {
                String::from("observation-reached:scheduler-quiescent")
            }
            ObservationCondition::AssertionViolationTransition(assertion) => {
                format!("observation-reached:assertion-violation-transition:{assertion}")
            }
            ObservationCondition::AnyAssertionViolationTransition => {
                let assertion = proof
                    .assertion_witness()
                    .map_or("unknown", |witness| witness.assertion());
                format!("observation-reached:any-assertion-violation-transition:{assertion}")
            }
            ObservationCondition::SchedulerQuiescentOrExecutionQuanta { execution_quanta } => {
                let satisfaction = match proof.satisfaction() {
                    ObservationStopSatisfaction::SchedulerQuiescent => "scheduler-quiescent",
                    ObservationStopSatisfaction::ExecutionQuanta => "execution-quanta",
                    ObservationStopSatisfaction::AssertionViolationTransition => {
                        "invalid-assertion-transition"
                    }
                };
                format!(
                    "observation-reached:scheduler-quiescent-or-execution-quanta:{execution_quanta}:{satisfaction}"
                )
            }
        },
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
#[path = "legacy_campaign/tests.rs"]
mod tests;
