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
// crucible-lint: allow host-nondeterminism-state -- rendering projects accepted scheduler evidence into the existing CLI wire-frame contract without influencing execution.
use crucible_api as campaign_output_api;
use crucible_daemon::ExactCheckpointStore;
use crucible_daemon::campaign_store_composition::{DirectoryBlobBackend, ImmutableBlobBackend};
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedCampaignReplayClosure, GuardedDefaultCampaignRun, GuardedDefaultCampaignRunRequest,
    GuardedDefaultCampaignSavepoint, GuardedDefaultCampaignWatchFrame,
    run_guarded_default_campaign,
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
        && matches!(
            plan.terminal_condition,
            RunTerminalCondition::Quiescence
                | RunTerminalCondition::VirtualTime
                | RunTerminalCondition::Stopped
        )
        && (plan.terminal_condition != RunTerminalCondition::VirtualTime
            || plan.max_virtual_time_ticks.is_some())
        && evidence.schedule.decisions().iter().all(|decision| {
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
        })
        && evidence.schedule.decisions().iter().all(|decision| {
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
        })
        && evidence
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
    let final_stop = guarded_resume_stop(resume_plan)?;
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
    )
    .with_resume_source(
        evidence.schedule.clone(),
        evidence.replay_closure.clone(),
        evidence.checkpoint.clone(),
        final_stop,
        Arc::clone(&checkpoints),
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

fn guarded_resume_stop(plan: &ResumeInvocationPlan) -> Result<StopCondition, CliError> {
    match plan.terminal_condition {
        RunTerminalCondition::Quiescence => Ok(StopCondition::NextChoice),
        RunTerminalCondition::VirtualTime => plan
            .max_virtual_time_ticks
            .map(StopCondition::VirtualTimeNanoseconds)
            .ok_or_else(|| usage_error("resume --until virtual-time requires --max-virtual-time")),
        RunTerminalCondition::Stopped => Ok(StopCondition::Terminal),
        RunTerminalCondition::Property => Err(backend_error(
            "campaign-backed QEMU resume does not support property breakpoints",
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
    guarded_campaign_save_stop(plan).is_ok() && guarded_campaign_run_eligible(&plan.run_plan)
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
            proof: campaign_save_boundary_proof(save_plan, evidence)?,
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
    let final_state = match resume_plan.terminal_condition {
        RunTerminalCondition::Quiescence => String::from("quiescent"),
        RunTerminalCondition::VirtualTime => String::from("virtual-time"),
        RunTerminalCondition::Stopped => String::from("stopped"),
        RunTerminalCondition::Property => {
            return Err(campaign_run_error_message(
                "property resume entered the selection-free campaign path",
            ));
        }
    };
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
        StopOutcome::Reached(StopCondition::NextChoice)
            if plan.terminal_condition == RunTerminalCondition::Quiescence =>
        {
            (BackendCommandStatus::Passed, OutcomeKind::Passed)
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
    })
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
        _ => Err(backend_error(
            "the requested save boundary does not have an exact campaign-backed QEMU adapter",
        )),
    }
}

fn campaign_save_boundary_proof(
    plan: &SaveInvocationPlan,
    evidence: &crucible_daemon::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot,
) -> Result<SaveBoundaryProof, CliError> {
    let Some(SaveAtSelector::Marker { name }) = plan.selector.as_ref() else {
        return Ok(SaveBoundaryProof::Coordinate);
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

    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use clap::Parser;
    use crucible_api::ProductionVmLifecycleConfig;
    use crucible_campaign::{
        BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
        ChoiceOpportunity, ChoiceSource, ChoiceValue, SelectableDeclaration, Selection,
        SelectionOrigin,
    };
    use crucible_core::AppRandomDecision;
    use crucible_daemon::LinuxQemuAttemptHostConfig;
    use crucible_daemon::qemu_campaign_lifecycle::{
        GuardedDefaultCampaignTestTrace, run_guarded_default_campaign_test_fixture,
        run_guarded_default_campaign_test_fixture_with_trace,
    };
    use tempfile::TempDir;

    fn default_run_plan() -> RunInvocationPlan {
        let cli = Cli::parse_from(["crucible", "run", "builtin:happy-path"]);
        let Commands::Run(args) = &cli.command else {
            panic!("expected run command");
        };
        plan_run_invocation(args, Path::new("."))
            .expect("built-in default run should produce an invocation plan")
    }

    fn resume_evidence(schedule: Schedule, frontier: VirtualTime) -> ResumeHandleEvidence {
        let scenario_form = default_run_plan().scenario.scenario_form().clone();
        let scenario = scenario_form.scenario_def();
        let configuration = crucible::Configuration {
            def: scenario.clone(),
            schedule: schedule.clone(),
        };
        let checkpoint = checkpoint_for_resume_configuration(&configuration, frontier)
            .expect("resume checkpoint");
        let replay_closure =
            GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&schedule)
                .unwrap_or_else(|_| {
                    GuardedCampaignReplayClosure::empty_for_selection_free_schedule(
                        &Schedule::empty(),
                    )
                    .expect("empty replay closure")
                });
        ResumeHandleEvidence {
            scenario_form,
            scenario,
            schedule,
            configuration,
            checkpoint,
            replay_closure,
        }
    }

    fn default_resume_plan(evidence: &ResumeHandleEvidence, store: &Path) -> ResumeInvocationPlan {
        ResumeInvocationPlan {
            savepoint: ResumeSavepointRef::CheckpointHash(evidence.checkpoint.id),
            store_root: store.to_path_buf(),
            terminal_condition: RunTerminalCondition::Stopped,
            max_virtual_time: None,
            max_virtual_time_ticks: None,
            execution_mode: RunExecutionMode::ToCompletion,
            watch_streams_live_status: false,
            startup_commands: vec![SessionCommandKind::Start, SessionCommandKind::Continue],
            initial_control_commands: vec![SessionCommandKind::Query],
            accepted_interactive_commands: Vec::new(),
        }
    }

    fn typed_selection_schedule(scenario: &crucible::ScenarioDef) -> Schedule {
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
        let declaration = SelectableDeclaration::new(
            "product.test.legacy-resume-route",
            ChoiceSource::Scheduler {
                producer: String::from("legacy-resume-route-test"),
            },
            domain.clone(),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
            BTreeSet::new(),
            true,
        )
        .expect("selectable declaration");
        let opportunity = ChoiceOpportunity::new(
            crucible_campaign::ScenarioDefId::from_hash(CampaignHash::from_bytes(
                scenario.id().bytes,
            )),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test", b"legacy-resume-scheduler"),
                producer: CampaignHash::derive("test", b"legacy-resume-producer"),
            },
            "legacy-resume-route",
            None,
        )
        .expect("choice opportunity");
        let selection = Selection::new(
            &opportunity,
            &domain,
            ChoiceValue::Boolean(false),
            SelectionOrigin::Default,
        )
        .expect("default selection");
        Schedule::from_decisions([crucible::Decision::Selection(
            crucible::SelectionDecision::new(&selection),
        )])
    }

    struct ResumeCampaignFixture {
        campaign: GuardedDefaultCampaignRun,
        trace: GuardedDefaultCampaignTestTrace,
        checkpoints: Arc<ExactCheckpointStore>,
        checkpoint_directory: TempDir,
        checkpoint_root: PathBuf,
    }

    fn resume_campaign_fixture(
        temporary: &TempDir,
        evidence: &ResumeHandleEvidence,
        final_stop: StopCondition,
        watch_frames: bool,
    ) -> ResumeCampaignFixture {
        let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 1024 * 1024, 16)
            .expect("campaign fixture resources");
        let checkpoint_directory = tempfile::Builder::new()
            .prefix("transient-resume-exact-")
            .tempdir_in(temporary.path())
            .expect("transient exact directory");
        let checkpoint_root = checkpoint_directory.path().to_path_buf();
        let exact_backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "legacy-campaign-resume-projection-test",
            checkpoint_root.clone(),
        ));
        let checkpoints = Arc::new(
            ExactCheckpointStore::new(exact_backend, resources.maximum_disk_bytes())
                .expect("exact checkpoint store"),
        );
        let host = LinuxQemuAttemptHostConfig::new(
            "/sys/fs/cgroup/crucible-campaign-resume-projection-test",
            "/tmp/crucible-campaign-resume-projection-test",
            "campaign-resume-projection-test",
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
            evidence.scenario_form.clone(),
            evidence.scenario.seed(),
            "campaign-resume-projection-test-engine",
            "campaign-resume-projection-test-qemu",
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state"),
            host,
            resources,
        )
        .with_resume_source(
            evidence.schedule.clone(),
            evidence.replay_closure.clone(),
            evidence.checkpoint.clone(),
            final_stop,
            Arc::clone(&checkpoints),
        );
        let request = if watch_frames {
            request.with_watch_frames()
        } else {
            request
        };
        let (campaign, trace) = run_guarded_default_campaign_test_fixture_with_trace(request)
            .expect("campaign fixture should resume through exact capture");

        ResumeCampaignFixture {
            campaign,
            trace,
            checkpoints,
            checkpoint_directory,
            checkpoint_root,
        }
    }

    #[test]
    fn campaign_resume_route_accepts_only_standard_selection_free_workflows() {
        let temporary = TempDir::new().expect("resume route workspace");
        let supported = Schedule::from_decisions([
            crucible::Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks: 5 },
                order: Vec::new(),
            }),
            crucible::Decision::RngDraw(crucible::RngDecision {
                stream: crucible::RngStreamId::from_name("legacy-resume-route"),
                value: 7,
            }),
        ]);
        let evidence = resume_evidence(supported, VirtualTime { ticks: 5 });
        let default = default_resume_plan(&evidence, temporary.path());
        assert!(guarded_campaign_resume_eligible(&default, &evidence));

        let mut virtual_time = default.clone();
        virtual_time.terminal_condition = RunTerminalCondition::VirtualTime;
        virtual_time.max_virtual_time = Some(String::from("10ticks"));
        virtual_time.max_virtual_time_ticks = Some(10);
        assert!(guarded_campaign_resume_eligible(&virtual_time, &evidence));

        let mut unsupported_evidence = evidence.clone();
        unsupported_evidence.schedule =
            Schedule::from_decisions([crucible::Decision::Override(crucible::OverrideDecision {
                point: crucible::SchedulingPoint {
                    key: String::from("legacy-resume/override"),
                },
                choice: crucible::ChoiceTag {
                    name: String::from("alternate"),
                },
            })]);
        assert!(!guarded_campaign_resume_eligible(
            &default,
            &unsupported_evidence
        ));
        unsupported_evidence.schedule =
            Schedule::from_decisions([crucible::Decision::AppRandom(AppRandomDecision {
                node: crucible::NodeId {
                    name: String::from("legacy-resume-node"),
                },
                stream: crucible::RngStreamId::from_name("legacy-resume-app-random"),
                request_id: 1,
                width: 8,
                value: 3,
            })]);
        assert!(!guarded_campaign_resume_eligible(
            &default,
            &unsupported_evidence
        ));
        unsupported_evidence.schedule = typed_selection_schedule(&evidence.scenario);
        assert!(!guarded_campaign_resume_eligible(
            &default,
            &unsupported_evidence
        ));

        let mut property = default.clone();
        property.terminal_condition = RunTerminalCondition::Property;
        assert!(!guarded_campaign_resume_eligible(&property, &evidence));
        let mut interactive = default.clone();
        interactive.execution_mode = RunExecutionMode::Interactive;
        interactive.startup_commands = vec![SessionCommandKind::Start];
        interactive.accepted_interactive_commands = run_interactive_session_command_set();
        assert!(!guarded_campaign_resume_eligible(&interactive, &evidence));
        let mut changed_controls = default;
        changed_controls.initial_control_commands.clear();
        assert!(!guarded_campaign_resume_eligible(
            &changed_controls,
            &evidence
        ));
    }

    #[test]
    fn campaign_resume_projection_preserves_source_oracle_watch_and_cleanup() {
        let temporary = TempDir::new().expect("resume projection workspace");
        let source_frontier = VirtualTime { ticks: 5 };
        let schedule = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
            crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks: 10 },
                order: Vec::new(),
            },
        )]);
        let evidence = resume_evidence(schedule.clone(), source_frontier);
        let mut resume_plan = default_resume_plan(&evidence, temporary.path());
        resume_plan.terminal_condition = RunTerminalCondition::VirtualTime;
        resume_plan.max_virtual_time = Some(String::from("10ticks"));
        resume_plan.max_virtual_time_ticks = Some(10);
        resume_plan.watch_streams_live_status = true;
        let ResumeCampaignFixture {
            campaign,
            trace: _,
            checkpoints,
            checkpoint_directory,
            checkpoint_root,
        } = resume_campaign_fixture(
            &temporary,
            &evidence,
            StopCondition::VirtualTimeNanoseconds(10),
            true,
        );
        let result = campaign_resume_workflow_report(&resume_plan, &evidence, &campaign);
        let proof = campaign.resume().cloned().expect("campaign resume proof");
        let terminal_observation = campaign.terminal().id();
        drop(campaign);
        let report = complete_transient_checkpoint_workflow(
            checkpoints,
            checkpoint_directory,
            &checkpoint_root,
            result,
        )
        .expect("project campaign resume into legacy contract");

        assert_eq!(report.run.execution_owner, RunExecutionOwner::Campaign);
        assert_eq!(report.source_checkpoint, evidence.checkpoint.id);
        assert_eq!(report.resumed_configuration, evidence.configuration.id());
        assert_eq!(report.run.final_frontier_ticks, 10);
        assert_eq!(report.run.final_state, "virtual-time");
        assert_eq!(
            report.run.terminal_savepoint,
            Some(report.terminal_oracle.fat_checkpoint)
        );
        assert_eq!(
            report
                .terminal_oracle
                .schedule
                .prefix(evidence.schedule.len()),
            Ok(evidence.schedule.clone())
        );
        assert!(report.run.campaign_replay_closure.is_some());
        assert!(!report.run.watch_statuses.is_empty());
        assert!(
            report
                .run
                .watch_statuses
                .iter()
                .all(|status| status.contains("owner=campaign"))
        );
        assert!(report.run.watch_statuses.iter().any(|status| {
            status.contains(&format!("observation={}", proof.source_observation()))
        }));
        assert!(
            report
                .run
                .watch_statuses
                .iter()
                .any(|status| { status.contains(&format!("observation={terminal_observation}")) })
        );
        assert_eq!(proof.source_frontier(), source_frontier);
        assert!(proof.source_savepoint().is_some());
        assert!(proof.ready().is_some());
        assert!(proof.selection().is_some());
        assert!(proof.continuation().is_some());

        assert!(!checkpoint_root.exists());
    }

    #[test]
    fn campaign_resume_projection_does_not_rewind_for_an_earlier_deadline() {
        let temporary = TempDir::new().expect("resume no-rewind workspace");
        let source_frontier = VirtualTime { ticks: 5 };
        let evidence = resume_evidence(Schedule::empty(), source_frontier);
        let mut resume_plan = default_resume_plan(&evidence, temporary.path());
        resume_plan.terminal_condition = RunTerminalCondition::VirtualTime;
        resume_plan.max_virtual_time = Some(String::from("3ticks"));
        resume_plan.max_virtual_time_ticks = Some(3);
        let ResumeCampaignFixture {
            campaign,
            trace: _,
            checkpoints,
            checkpoint_directory,
            checkpoint_root,
        } = resume_campaign_fixture(
            &temporary,
            &evidence,
            StopCondition::VirtualTimeNanoseconds(3),
            false,
        );

        assert_eq!(
            campaign.terminal().observation().stop(),
            &StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(3))
        );
        assert_eq!(campaign.evidence().frontier(), source_frontier);

        let result = campaign_resume_workflow_report(&resume_plan, &evidence, &campaign);
        drop(campaign);
        let report = complete_transient_checkpoint_workflow(
            checkpoints,
            checkpoint_directory,
            &checkpoint_root,
            result,
        )
        .expect("project no-rewind campaign resume into legacy contract");

        assert_eq!(report.run.status, BackendCommandStatus::Passed);
        assert_eq!(report.run.outcome, Some(OutcomeKind::Passed));
        assert_eq!(report.run.final_frontier_ticks, source_frontier.ticks);
        assert_eq!(report.terminal_oracle.frontier, source_frontier);
        assert!(!checkpoint_root.exists());
    }

    #[test]
    fn campaign_resume_frontier_validation_binds_reached_deadlines_only() {
        let temporary = TempDir::new().expect("resume frontier workspace");
        let source_frontier = VirtualTime { ticks: 5 };
        let evidence = resume_evidence(Schedule::empty(), source_frontier);
        let mut plan = default_resume_plan(&evidence, temporary.path());
        plan.terminal_condition = RunTerminalCondition::VirtualTime;
        plan.max_virtual_time = Some(String::from("3ticks"));
        plan.max_virtual_time_ticks = Some(3);
        let earlier_stop = StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(3));

        validate_campaign_resume_frontier(&plan, source_frontier, &earlier_stop, source_frontier)
            .expect("an earlier deadline must preserve the source frontier");
        assert!(
            validate_campaign_resume_frontier(
                &plan,
                source_frontier,
                &earlier_stop,
                VirtualTime { ticks: 3 }
            )
            .is_err()
        );
        assert!(
            validate_campaign_resume_frontier(
                &plan,
                source_frontier,
                &earlier_stop,
                VirtualTime { ticks: 6 }
            )
            .is_err()
        );

        plan.max_virtual_time = Some(String::from("10ticks"));
        plan.max_virtual_time_ticks = Some(10);
        let future_stop = StopOutcome::Reached(StopCondition::VirtualTimeNanoseconds(10));
        validate_campaign_resume_frontier(
            &plan,
            source_frontier,
            &future_stop,
            VirtualTime { ticks: 10 },
        )
        .expect("a future deadline must advance to that exact frontier");
    }

    #[test]
    fn campaign_resume_terminal_outcomes_bypass_the_requested_future_deadline() {
        let temporary = TempDir::new().expect("resume terminal outcome workspace");
        let source_frontier = VirtualTime { ticks: 5 };
        let evidence = resume_evidence(Schedule::empty(), source_frontier);
        let mut plan = default_resume_plan(&evidence, temporary.path());
        plan.terminal_condition = RunTerminalCondition::VirtualTime;
        plan.max_virtual_time = Some(String::from("10ticks"));
        plan.max_virtual_time_ticks = Some(10);
        let terminal_cases = [
            (
                StopOutcome::ModeledTimeout(String::from("deadline")),
                BackendCommandStatus::Timeout,
                OutcomeKind::Timeout,
            ),
            (
                StopOutcome::GuestCrash(String::from("guest-crash")),
                BackendCommandStatus::Crashed,
                OutcomeKind::Crashed,
            ),
            (
                StopOutcome::AssertionFailure(String::from("invariant")),
                BackendCommandStatus::Failed,
                OutcomeKind::Failed,
            ),
            (
                StopOutcome::ScenarioFailure(vec![String::from("scenario failed")]),
                BackendCommandStatus::Failed,
                OutcomeKind::Failed,
            ),
        ];

        for (stop, expected_status, expected_outcome) in terminal_cases {
            assert_eq!(
                campaign_resume_status(&plan, &stop).expect("terminal outcome status"),
                (expected_status, expected_outcome)
            );
            validate_campaign_resume_frontier(&plan, source_frontier, &stop, source_frontier)
                .expect("terminal outcomes may precede the requested future deadline");
        }
    }

    #[test]
    fn transient_checkpoint_cleanup_preserves_the_execution_error() {
        let temporary = TempDir::new().expect("cleanup workspace");
        let checkpoint_directory = tempfile::Builder::new()
            .prefix("transient-resume-error-")
            .tempdir_in(temporary.path())
            .expect("transient exact directory");
        let checkpoint_root = checkpoint_directory.path().to_path_buf();
        let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "legacy-campaign-resume-cleanup-test",
            &checkpoint_root,
        ));
        let checkpoints = Arc::new(
            ExactCheckpointStore::new(backend, 1024 * 1024).expect("exact checkpoint store"),
        );
        let expected = "injected campaign resume failure";
        let result: Result<(), CliError> = Err(backend_error(expected));

        let error = complete_transient_checkpoint_workflow(
            checkpoints,
            checkpoint_directory,
            &checkpoint_root,
            result,
        )
        .expect_err("execution failure must survive successful cleanup");

        assert!(error.to_string().contains(expected));
        assert!(!checkpoint_root.exists());
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
        plan.observer_profile = VERIFY_OBSERVER_PROFILES[0];
        assert!(!guarded_campaign_run_eligible(&plan));

        let mut plan = default;
        plan.collect_execution_fingerprints = true;
        assert!(!guarded_campaign_run_eligible(&plan));
    }

    #[test]
    fn campaign_save_route_accepts_standard_virtual_time_and_marker_saves() {
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

        let marker_cli = Cli::parse_from([
            "crucible",
            "save",
            "builtin:happy-path",
            "--at",
            "marker",
            "--marker",
            "checkpoint",
        ]);
        let Commands::Save(args) = &marker_cli.command else {
            panic!("expected marker save command");
        };
        let marker = plan_save_invocation(args, Path::new("."), Path::new("./artifacts"))
            .expect("marker save plan");
        assert!(guarded_campaign_save_eligible(&marker));
        assert_eq!(
            guarded_campaign_save_stop(&marker).expect("marker campaign stop"),
            StopCondition::NamedBoundary(String::from("checkpoint"))
        );

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
    fn campaign_save_schedule_taxonomy_admits_typed_selections() {
        let scenario = default_run_plan().scenario.scenario_def().clone();
        let schedule = typed_selection_schedule(&scenario);

        validate_portable_campaign_save_schedule(&schedule)
            .expect("typed saves carry their portable replay closure during export");
        validate_portable_campaign_save_schedule(&Schedule::empty())
            .expect("selection-free saves remain portable");
    }

    #[test]
    fn campaign_virtual_time_save_exports_closure_for_unchanged_resume_and_fork_readers() {
        assert_campaign_save_exports_closure(
            &["--at", "virtual-time", "--max-virtual-time", "2ms"],
            StopCondition::VirtualTimeNanoseconds(2_000_000),
            false,
        );
    }

    #[test]
    fn campaign_marker_save_exports_v4_event_proof_for_resume_and_fork_readers() {
        let marker = "guarded-campaign-save-fixture-marker";
        assert_campaign_save_exports_closure(
            &["--at", "marker", "--marker", marker],
            StopCondition::NamedBoundary(String::from(marker)),
            false,
        );
    }

    #[test]
    fn campaign_marker_save_after_a_typed_choice_exports_a_portable_resume() {
        let marker = "guarded-campaign-save-fixture-marker";
        assert_campaign_save_exports_closure(
            &["--at", "marker", "--marker", marker],
            StopCondition::NamedBoundary(String::from(marker)),
            true,
        );
    }

    #[test]
    fn campaign_virtual_time_save_after_a_typed_choice_exports_a_portable_resume() {
        assert_campaign_save_exports_closure(
            &["--at", "virtual-time", "--max-virtual-time", "2ticks"],
            StopCondition::VirtualTimeNanoseconds(2),
            true,
        );
    }

    #[test]
    fn campaign_typed_save_without_a_replay_closure_fails_before_export() {
        let marker = "guarded-campaign-save-fixture-marker";
        let stop = StopCondition::NamedBoundary(String::from(marker));
        let capture =
            capture_campaign_save(&["--at", "marker", "--marker", marker], stop.clone(), true);
        let report = campaign_save_workflow_report(&capture.save_plan, &capture.campaign, &stop)
            .expect("typed campaign save report");
        let thin_plan = plan_cli_invocation(&capture.cli);
        let backend_plan = plan_backend_selection(&capture.cli)
            .expect("backend plan")
            .expect("save requires a backend");
        let mut outcome = finish_save_workflow_outcome(
            &thin_plan,
            &backend_plan,
            None,
            &capture.save_plan,
            report,
        )
        .expect("finish typed save report");
        outcome.savepoint_replay_closure = None;

        let error = export_savepoint_handle(&capture.save_plan, &mut outcome)
            .expect_err("typed save missing its closure must fail before persistence");

        assert!(error.to_string().contains("missing the replay closure"));
        assert!(!capture.output.exists());
        assert!(!capture.temporary.path().join("_indexes").exists());
    }

    struct CampaignSaveCapture {
        temporary: TempDir,
        artifact_directory: PathBuf,
        output: PathBuf,
        cli: Cli,
        save_plan: SaveInvocationPlan,
        campaign: GuardedDefaultCampaignRun,
    }

    fn capture_campaign_save(
        boundary_arguments: &[&str],
        stop: StopCondition,
        marker_with_selection: bool,
    ) -> CampaignSaveCapture {
        let temporary = TempDir::new().expect("temporary save workspace");
        let artifact_directory = temporary.path().join("artifacts");
        let output = temporary.path().join("campaign.crucible-savepoint");
        let scenario = if marker_with_selection || matches!(&stop, StopCondition::NamedBoundary(_))
        {
            campaign_marker_save_scenario(&temporary, marker_with_selection)
        } else {
            String::from("builtin:happy-path")
        };
        let mut arguments = vec![
            String::from("crucible"),
            String::from("--backend"),
            String::from("double"),
            String::from("--store"),
            temporary.path().display().to_string(),
            String::from("--artifact-dir"),
            artifact_directory.display().to_string(),
            String::from("save"),
            scenario,
        ];
        arguments.extend(
            boundary_arguments
                .iter()
                .map(|argument| String::from(*argument)),
        );
        arguments.extend([String::from("--out"), output.display().to_string()]);
        let cli = Cli::parse_from(arguments);
        let Commands::Save(args) = &cli.command else {
            panic!("expected save command");
        };
        let save_plan = plan_save_invocation(args, temporary.path(), &artifact_directory)
            .expect("campaign save plan");
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
        .with_discovery_stop(stop)
        .with_reached_stop_savepoint_capture(checkpoints);
        let campaign = run_guarded_default_campaign_test_fixture(request)
            .expect("campaign fixture should capture an authenticated savepoint");
        std::fs::remove_dir_all(&exact_root)
            .expect("remove transient physical checkpoint before durable readers run");

        CampaignSaveCapture {
            temporary,
            artifact_directory,
            output,
            cli,
            save_plan,
            campaign,
        }
    }

    fn assert_campaign_save_exports_closure(
        boundary_arguments: &[&str],
        stop: StopCondition,
        with_selection: bool,
    ) {
        let CampaignSaveCapture {
            temporary,
            artifact_directory,
            output,
            cli,
            save_plan,
            campaign,
        } = capture_campaign_save(boundary_arguments, stop.clone(), with_selection);
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
            .expect("export versioned handle and DAG closure");

        match &stop {
            StopCondition::NamedBoundary(name) => {
                assert_eq!(
                    campaign.terminal_configuration().schedule.len(),
                    usize::from(with_selection)
                );
                let boundary = outcome
                    .save_boundary_evidence
                    .as_ref()
                    .expect("marker save boundary evidence");
                assert_eq!(
                    boundary.selector,
                    Some(SaveAtSelector::Marker { name: name.clone() })
                );
                let SaveBoundaryProof::CampaignMarkerEvent {
                    sequence,
                    content_hash,
                    node: proved_node,
                    retired_icount,
                    marker: proved_marker,
                } = &boundary.proof
                else {
                    panic!("expected authenticated campaign marker event proof");
                };
                let marker_entry = campaign
                    .evidence()
                    .event_log_entries()
                    .iter()
                    .find(|entry| entry.sequence() == *sequence)
                    .expect("retained marker proof entry");
                assert_eq!(*content_hash, marker_entry.content_hash());
                assert_eq!(proved_marker, &crucible::MarkerId::from_name(name));
                assert_eq!(marker_entry.event_payload().kind(), "guest_marker");
                assert_eq!(marker_entry.event_payload().node("node"), Some(proved_node));
                assert_eq!(
                    marker_entry.event_payload().icount("retired_icount"),
                    Some(crucible::Icount {
                        retired: *retired_icount,
                    })
                );
                assert_eq!(
                    marker_entry.event_payload().string("marker"),
                    Some(proved_marker.name.as_str())
                );
                let handle = std::fs::read_to_string(&output).expect("marker v5 handle");
                assert!(handle.contains("schema\tcrucible.savepoint-handle.v5\n"));
                assert!(handle.contains("campaign-replay-closure\tcrucible-hash:"));
                assert!(handle.contains("boundary-proof\tcampaign-marker-event\t"));
                assert!(handle.contains("boundary-predicate\t"));
                let decoded = decode_savepoint_handle(handle.as_bytes())
                    .expect("decode authenticated campaign marker handle");
                assert!(matches!(
                    decoded.boundary_proof,
                    Some(SavepointBoundaryProof::CampaignMarkerEvent {
                        event_sequence,
                        event_content_hash,
                        node,
                        retired_icount: decoded_retired_icount,
                        frontier_ticks,
                        quanta,
                    }) if event_sequence == *sequence
                        && event_content_hash == *content_hash
                        && node == *proved_node
                        && decoded_retired_icount == *retired_icount
                        && frontier_ticks == campaign.evidence().frontier().ticks
                        && quanta == campaign.evidence().quanta()
                ));
                assert_eq!(
                    decoded.boundary_predicate,
                    Some(crucible::Predicate::guest_marker(proved_marker.clone()))
                );
                if !with_selection {
                    let legacy_v4 = handle
                        .lines()
                        .filter(|line| !line.starts_with("campaign-replay-closure\t"))
                        .map(|line| {
                            if line == "schema\tcrucible.savepoint-handle.v5" {
                                String::from("schema\tcrucible.savepoint-handle.v4")
                            } else {
                                line.to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n";
                    let legacy_v4 = decode_savepoint_handle(legacy_v4.as_bytes())
                        .expect("historical selection-free v4 marker handle remains readable");
                    savepoint_handle_evidence("resume", &legacy_v4)
                        .expect("historical v4 marker evidence synthesizes an empty closure");
                }

                let mislabeled_v3 = handle.replace(
                    "schema\tcrucible.savepoint-handle.v5",
                    "schema\tcrucible.savepoint-handle.v4",
                );
                assert!(decode_savepoint_handle(mislabeled_v3.as_bytes()).is_err());

                let wrong_hash = handle.replace(
                    &format_content_hash_ref(*content_hash),
                    &format_content_hash_ref(crucible::ContentHash::default()),
                );
                let error = decode_savepoint_handle(wrong_hash.as_bytes())
                    .expect_err("v5 campaign marker hash must bind its canonical event");
                assert!(error.to_string().contains("canonical event"));

                let wrong_predicate = handle
                    .lines()
                    .map(|line| {
                        if line.starts_with("boundary-predicate\t") {
                            String::from("boundary-predicate\tnone")
                        } else {
                            line.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                assert!(decode_savepoint_handle(wrong_predicate.as_bytes()).is_err());

                let coordinate_proof = handle
                    .lines()
                    .map(|line| {
                        if line.starts_with("boundary-proof\t") {
                            format!(
                                "boundary-proof\tcoordinate\t{}\t{}",
                                campaign.evidence().frontier().ticks,
                                campaign.evidence().quanta()
                            )
                        } else {
                            line.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                assert!(decode_savepoint_handle(coordinate_proof.as_bytes()).is_err());

                let missing_node = crucible::NodeId {
                    name: String::from("missing-campaign-marker-node"),
                };
                let missing_node_event = crucible::SchedulerEventLogEntry::guest_marker_observation(
                    *sequence,
                    crucible::Icount {
                        retired: *retired_icount,
                    },
                    missing_node.clone(),
                    proved_marker.clone(),
                );
                let missing_source = handle
                    .lines()
                    .map(|line| {
                        if line.starts_with("boundary-proof\t") {
                            format!(
                                "boundary-proof\tcampaign-marker-event\t{}\t{}\t{}\t{}\t{}\t{}",
                                sequence,
                                format_content_hash_ref(missing_node_event.content_hash()),
                                missing_node.name,
                                retired_icount,
                                campaign.evidence().frontier().ticks,
                                campaign.evidence().quanta()
                            )
                        } else {
                            line.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                let missing_source = decode_savepoint_handle(missing_source.as_bytes())
                    .expect("structurally valid v5 event record");
                let error = savepoint_handle_evidence("resume", &missing_source)
                    .expect_err("v5 source node must belong to the embedded scenario");
                assert!(error.to_string().contains("not declared"));
            }
            StopCondition::VirtualTimeNanoseconds(_) => {
                assert_eq!(
                    outcome
                        .save_boundary_evidence
                        .as_ref()
                        .expect("virtual-time boundary evidence")
                        .proof,
                    SaveBoundaryProof::Coordinate
                );
                let handle = std::fs::read_to_string(&output).expect("virtual-time v5 handle");
                assert!(handle.contains("schema\tcrucible.savepoint-handle.v5\n"));
                assert!(handle.contains("campaign-replay-closure\tcrucible-hash:"));
                decode_savepoint_handle(handle.as_bytes())
                    .expect("v5 decoder accepts campaign coordinate proof");
                if !with_selection {
                    let legacy_v3 = handle
                        .lines()
                        .filter(|line| !line.starts_with("campaign-replay-closure\t"))
                        .map(|line| {
                            if line == "schema\tcrucible.savepoint-handle.v5" {
                                String::from("schema\tcrucible.savepoint-handle.v3")
                            } else {
                                line.to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n";
                    let legacy_v3 = decode_savepoint_handle(legacy_v3.as_bytes())
                        .expect("historical selection-free v3 coordinate handle remains readable");
                    savepoint_handle_evidence("resume", &legacy_v3)
                        .expect("historical v3 coordinate evidence synthesizes an empty closure");
                }
            }
            other => panic!("unsupported campaign save test boundary: {other:?}"),
        }

        let checkpoint = outcome
            .terminal_savepoint
            .expect("projected save exposes its logical checkpoint");
        let (handle_resume_plan, handle_evidence) =
            resume_plan_and_evidence_from_cli(&output, temporary.path());
        let handle_fork_evidence = fork_evidence_from_cli(
            &output.display().to_string(),
            temporary.path(),
            &artifact_directory,
        );
        let checkpoint_reference = format_content_hash_ref(checkpoint);
        let (store_resume_plan, store_evidence) =
            resume_plan_and_evidence_from_cli(Path::new(&checkpoint_reference), temporary.path());
        let store_fork_evidence =
            fork_evidence_from_cli(&checkpoint_reference, temporary.path(), &artifact_directory);

        assert_eq!(handle_evidence, handle_fork_evidence);
        assert_eq!(handle_evidence, store_evidence);
        assert_eq!(handle_evidence, store_fork_evidence);
        assert_eq!(handle_evidence.checkpoint.id, checkpoint);
        assert!(guarded_campaign_resume_eligible(
            &handle_resume_plan,
            &handle_evidence
        ));
        assert!(guarded_campaign_resume_eligible(
            &store_resume_plan,
            &store_evidence
        ));

        if with_selection {
            handle_evidence
                .replay_closure
                .validate_for_schedule(&handle_evidence.scenario_form, &handle_evidence.schedule)
                .expect("v5 handle closure authenticates its typed schedule");
            assert!(
                ensure_session_replay_evidence_supported(
                    "typed fork regression",
                    &handle_fork_evidence
                )
                .is_err()
            );
            let lifecycle_starts = Arc::new(AtomicUsize::new(0));
            let counted_starts = Arc::clone(&lifecycle_starts);
            let control_plane = LifecycleControlPlane::new(
                "typed-selection-session-refusal",
                Vec::new(),
                move |_scenario: &crucible::ScenarioDef, _seed| {
                    counted_starts.fetch_add(1, Ordering::Relaxed);
                    QuiescentLifecycleLoop::new()
                },
            );
            let client = InProcessLifecycleClient::new(control_plane);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("typed fallback test runtime");
            let error = runtime
                .block_on(
                    run_remote_control_client_resume_from_evidence_with_driver_async(
                        &client,
                        &handle_resume_plan,
                        handle_evidence.clone(),
                        ResumeInteractiveCommandDriver::Preparsed(&[]),
                        false,
                    ),
                )
                .expect_err("remote session path must reject typed evidence before resume");
            assert!(
                error
                    .to_string()
                    .contains("cannot consume a typed selection")
            );
            assert_eq!(runtime.block_on(client.session_count()), 0);
            assert_eq!(lifecycle_starts.load(Ordering::Relaxed), 0);

            for (reader, mut plan, evidence) in [
                (
                    "v5 handle",
                    handle_resume_plan.clone(),
                    handle_evidence.clone(),
                ),
                (
                    "v3 DAG index",
                    store_resume_plan.clone(),
                    store_evidence.clone(),
                ),
            ] {
                let source_frontier = evidence.checkpoint.virtual_time.ticks;
                let terminal_frontier = source_frontier.saturating_mul(2);
                plan.terminal_condition = RunTerminalCondition::VirtualTime;
                plan.max_virtual_time = Some(format!("{terminal_frontier}ticks"));
                plan.max_virtual_time_ticks = Some(terminal_frontier);
                assert!(guarded_campaign_resume_eligible(&plan, &evidence));

                // This modeled lifecycle proves campaign ownership and exact
                // reply application. Packaged-QEMU acceptance remains a VM gate.
                let fixture = resume_campaign_fixture(
                    &temporary,
                    &evidence,
                    StopCondition::VirtualTimeNanoseconds(terminal_frontier),
                    true,
                );
                let resume = fixture
                    .campaign
                    .resume()
                    .unwrap_or_else(|| panic!("{reader} resume must retain its source proof"));
                let source_savepoint = resume
                    .source_savepoint()
                    .unwrap_or_else(|| panic!("{reader} resume must capture its exact source"));

                assert_eq!(resume.source_checkpoint(), checkpoint);
                assert_eq!(resume.source_frontier().ticks, source_frontier);
                assert!(resume.ready().is_some());
                assert!(resume.selection().is_some());
                assert!(resume.continuation().is_some());
                let selection_applications = fixture
                    .trace
                    .selection_applications()
                    .expect("read explicit fixture reply trace");
                assert_eq!(selection_applications.len(), 3);
                assert!(selection_applications.iter().enumerate().all(
                    |(generation, (actual_generation, frontier))| {
                        *actual_generation == generation as u64 && frontier.ticks == source_frontier
                    }
                ));
                assert_eq!(
                    source_savepoint.evidence().frontier().ticks,
                    source_frontier
                );
                assert_eq!(
                    fixture.campaign.evidence().frontier().ticks,
                    terminal_frontier
                );
                assert!(terminal_frontier > source_frontier);
                assert!(
                    fixture
                        .campaign
                        .evidence()
                        .event_log_entries()
                        .iter()
                        .any(|entry| {
                            entry
                                .event_payload()
                                .icount("retired_icount")
                                .is_some_and(|icount| icount.retired > source_frontier)
                        })
                );
                assert_eq!(
                    fixture
                        .campaign
                        .terminal_configuration()
                        .schedule
                        .decisions()
                        .get(..evidence.schedule.len()),
                    Some(evidence.schedule.decisions())
                );

                let report = campaign_resume_workflow_report(&plan, &evidence, &fixture.campaign)
                    .unwrap_or_else(|error| panic!("{reader} projection should pass: {error}"));
                assert_eq!(report.run.execution_owner, RunExecutionOwner::Campaign);
                assert_eq!(report.run.final_frontier_ticks, terminal_frontier);
            }

            let handle_text = std::fs::read_to_string(&output).expect("read v5 handle");
            let missing_closure = handle_text
                .lines()
                .filter(|line| !line.starts_with("campaign-replay-closure\t"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert!(decode_savepoint_handle(missing_closure.as_bytes()).is_err());
            let historical_schema = match stop {
                StopCondition::NamedBoundary(_) => "crucible.savepoint-handle.v4",
                StopCondition::VirtualTimeNanoseconds(_) => "crucible.savepoint-handle.v3",
                _ => panic!("typed portable-save regression uses marker or virtual time"),
            };
            let typed_legacy_handle = handle_text
                .lines()
                .filter(|line| !line.starts_with("campaign-replay-closure\t"))
                .map(|line| {
                    if line == "schema\tcrucible.savepoint-handle.v5" {
                        format!("schema\t{historical_schema}")
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let typed_legacy_handle = decode_savepoint_handle(typed_legacy_handle.as_bytes())
                .expect("historical schema remains structurally readable");
            let error = savepoint_handle_evidence("resume", &typed_legacy_handle)
                .expect_err("historical typed handle without closure must fail closed");
            assert!(error.to_string().contains("missing the replay closure"));
            let empty_closure =
                GuardedCampaignReplayClosure::empty_for_selection_free_schedule(&Schedule::empty())
                    .expect("empty closure")
                    .to_canonical_bytes()
                    .expect("encode empty closure");
            let mismatched_closure = handle_text
                .lines()
                .map(|line| {
                    if line.starts_with("campaign-replay-closure\t") {
                        format!(
                            "campaign-replay-closure\t{}\t{}",
                            content_address_bytes(&empty_closure),
                            hex_bytes(&empty_closure)
                        )
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let mismatched_closure = decode_savepoint_handle(mismatched_closure.as_bytes())
                .expect("mismatched closure remains structurally canonical");
            let error = savepoint_handle_evidence("resume", &mismatched_closure)
                .expect_err("closure must cover its exact typed schedule");
            assert!(error.to_string().contains("missing a schedule selection"));

            let store = crucible::LocalDagStore::new(temporary.path().to_path_buf());
            let index = store
                .read_checkpoint_closure_index(checkpoint)
                .expect("read v3 checkpoint closure index");
            let replay_object = index
                .opaque_replay_artifact
                .expect("v3 index retains replay closure object");
            assert_eq!(
                index.referenced_objects(),
                BTreeSet::from([index.reproduction_artifact, replay_object])
            );
            assert!(
                store
                    .delete(&replay_object)
                    .expect("delete closure fixture")
            );
            let error = savepoint_store_evidence("resume", checkpoint, temporary.path())
                .expect_err("missing retained closure object must fail closed");
            assert!(error.to_string().contains("missing retained object"));
            store
                .write_checkpoint_closure_index(
                    checkpoint,
                    index.reproduction_artifact,
                    handle_evidence.checkpoint.virtual_time,
                )
                .expect("write historical v2 typed index fixture");
            let error = savepoint_store_evidence("resume", checkpoint, temporary.path())
                .expect_err("historical typed index without closure must fail closed");
            assert!(error.to_string().contains("missing the replay closure"));
        }
    }

    fn campaign_marker_save_scenario(temporary: &TempDir, with_selection: bool) -> String {
        let node = crucible::NodeId {
            name: String::from("campaign-marker-save-node"),
        };
        let world = crucible::World::from_nodes(vec![crucible::WorldNode {
            id: node.clone(),
            arch: crucible::NodeTemplate::DEFAULT_ARCH,
            memory_mib: crucible::NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::from("crucible-campaign-marker-save-fixture"),
            ready_point: crucible::ReadyPoint::FixedIcount {
                icount: crucible::Icount { retired: 1 },
            },
            white_box: crucible::WhiteBoxPolicy::Enabled,
            smp_vcpus: crucible::NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: crucible::NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }])
        .expect("campaign marker save world");
        let declaration = SelectableDeclaration::new(
            "campaign.save.fixture-choice",
            ChoiceSource::Guest {
                node: node.name.clone(),
                protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
            },
            ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain")),
            ChoiceValue::Boolean(false),
            ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
            BTreeSet::from([String::from("campaign-save")]),
            true,
        )
        .expect("campaign marker save selectable declaration");
        let selectables = crucible::ScenarioSelectables::new(
            &world,
            crucible::ScenarioSelectableLimits::new(4, 8, 16, 32)
                .expect("campaign marker selectable limits"),
            vec![declaration],
        )
        .expect("campaign marker save selectables");
        let mut form = crucible::ScenarioDefForm::from_components(
            &world,
            &crucible::Plan::empty(),
            &crucible::Properties::empty(),
            crucible::Seed::from_u64(8_004),
        )
        .expect("campaign marker save scenario");
        if with_selection {
            form = form
                .with_selectables(selectables)
                .expect("attach campaign marker save selectables");
        }
        let path = temporary.path().join("campaign-marker-save.toml");
        std::fs::write(
            &path,
            form.to_canonical_toml()
                .expect("canonical campaign marker save scenario"),
        )
        .expect("write campaign marker save scenario");
        path.display().to_string()
    }

    fn resume_plan_and_evidence_from_cli(
        savepoint: &Path,
        store: &Path,
    ) -> (ResumeInvocationPlan, ResumeHandleEvidence) {
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
        let evidence =
            resume_handle_evidence(&plan).expect("unchanged resume reader accepts campaign save");
        (plan, evidence)
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
