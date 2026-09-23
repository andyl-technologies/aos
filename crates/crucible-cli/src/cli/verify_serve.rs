//! Verification comparison, canonical witnesses, and control-client workflows.

use super::*;

#[path = "artifact_capture.rs"]
mod artifact_capture;
pub(super) use artifact_capture::*;

#[path = "verify_serve/packaged_executor.rs"]
mod packaged_executor;
pub(crate) fn load_guarded_campaign_deployment(
    explicit: Option<&Path>,
) -> Result<packaged_executor::GuardedCampaignRunDeployment, CliError> {
    let path = packaged_executor::resolve_guarded_campaign_deployment_path(explicit)?;
    packaged_executor::load_campaign_run_deployment(&path)
}

/// Applies the deployment's paired-replay policy to one guarded campaign request.
#[must_use]
pub(crate) fn apply_guarded_campaign_determinism_policy(
    request: crucible_daemon::qemu_campaign_lifecycle::GuardedDefaultCampaignRunRequest,
    verify_determinism_findings: bool,
) -> crucible_daemon::qemu_campaign_lifecycle::GuardedDefaultCampaignRunRequest {
    if verify_determinism_findings {
        request.with_determinism_finding_verification()
    } else {
        request
    }
}

#[path = "campaign_run.rs"]
pub(crate) mod campaign_run;

pub(crate) fn run_local_qemu_campaign_workflow(
    backend: &ResolvedLocalBackend,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    campaign_run::run_local_qemu_campaign_workflow(
        backend,
        thin_plan,
        backend_plan,
        ergonomics_plan,
        run_plan,
    )
}

pub(crate) fn run_local_qemu_interactive_workflow(
    backend: &ResolvedLocalBackend,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    campaign_run::run_local_qemu_interactive_workflow(
        backend,
        thin_plan,
        backend_plan,
        ergonomics_plan,
        run_plan,
    )
}

pub(crate) fn guarded_campaign_resume_eligible(
    plan: &ResumeInvocationPlan,
    evidence: &ResumeHandleEvidence,
) -> bool {
    campaign_run::guarded_campaign_resume_eligible(plan, evidence)
}

pub(crate) fn run_local_qemu_campaign_save_workflow(
    backend: &ResolvedLocalBackend,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    campaign_run::run_local_qemu_campaign_save_workflow(
        backend,
        thin_plan,
        backend_plan,
        ergonomics_plan,
        save_plan,
    )
}

pub(crate) fn run_local_qemu_campaign_replay(
    backend: &ResolvedLocalBackend,
    run_plan: &RunInvocationPlan,
    lifecycle: crucible_api::ProductionVmLifecycleConfig,
    schedule: crucible::Schedule,
    replay_closure: crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
) -> Result<RunWorkflowReport, CliError> {
    campaign_run::run_local_qemu_campaign_replay(
        backend,
        run_plan,
        lifecycle,
        schedule,
        replay_closure,
    )
}

pub(super) async fn run_control_client_verify_reduction_async<C>(
    client: &C,
    seeded_scenario: RunScenarioRef,
    request_seed: crucible::Seed,
    reduction: VerifyReductionPlan,
    backend: Option<&ResolvedLocalBackend>,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    store_root: &Path,
) -> Result<VerifyRunWitness, CliError>
where
    C: ControlClient + Sync,
{
    if !reduction.host_profile.is_valid() {
        return Err(backend_error(format!(
            "verify hostile host profile `{}` is invalid",
            reduction.host_profile.label()
        )));
    }
    let run_plan = verify_run_invocation_plan(seeded_scenario, request_seed, reduction.clone());
    let report = run_control_client_workflow_async(client, &run_plan, &[]).await?;

    // Determinism applies to failing and budget-terminated executions too. A
    // completed reduction remains comparable; transport/backend errors have
    // already returned above without producing a report.
    verify_witness_from_run_report(
        reduction.clone(),
        &run_plan,
        &report,
        backend,
        ergonomics_plan,
        store_root,
    )
}

pub(super) fn verify_compare_artifacts(
    verify_plan: &VerifyInvocationPlan,
) -> Result<VerifyWorkflowReport, CliError> {
    let VerifyMode::CompareArtifacts { left, right } = &verify_plan.mode else {
        return Err(backend_error(
            "verify run mode must use the live control-client workflow",
        ));
    };
    let left_bytes = fs::read(left)?;
    let right_bytes = fs::read(right)?;
    let left_artifact = decode_reproduction_artifact(&left_bytes)?;
    let right_artifact = decode_reproduction_artifact(&right_bytes)?;
    verify_replay_identity(&right_artifact.identity, &left_artifact.identity)?;
    verify_compare_artifact_inputs_match("verify --compare", &left_artifact, &right_artifact)?;
    let witnesses = vec![
        verify_witness_from_artifact(verify_plan.reductions[0].clone(), left_artifact, left_bytes)?,
        verify_witness_from_artifact(
            verify_plan.reductions[1].clone(),
            right_artifact,
            right_bytes,
        )?,
    ];
    let divergence = compare_verify_witnesses(&witnesses);
    Ok(VerifyWorkflowReport {
        witnesses,
        divergence,
    })
}

pub(super) fn verify_compare_artifact_inputs_match(
    command: &str,
    left: &CliReproductionArtifact,
    right: &CliReproductionArtifact,
) -> Result<(), CliError> {
    if left.seed != right.seed {
        return Err(artifact_error(format!(
            "{command} requires matching seeds, got left={} right={}",
            left.seed, right.seed
        )));
    }
    if left.scenario.digest != right.scenario.digest {
        return Err(artifact_error(format!(
            "{command} requires matching scenario digests, got left={} right={}",
            left.scenario.digest, right.scenario.digest
        )));
    }
    if left.scenario.media_type != right.scenario.media_type {
        return Err(artifact_error(format!(
            "{command} requires matching scenario media types, got left={} right={}",
            left.scenario.media_type, right.scenario.media_type
        )));
    }
    Ok(())
}

pub(super) fn verify_run_invocation_plan(
    scenario: RunScenarioRef,
    request_seed: crucible::Seed,
    reduction: VerifyReductionPlan,
) -> RunInvocationPlan {
    RunInvocationPlan {
        scenario,
        save_store_root: None,
        campaign_deployment: None,
        request_seed: Some(request_seed),
        terminal_condition: RunTerminalCondition::Quiescence,
        max_virtual_time: None,
        max_virtual_time_ticks: None,
        max_quanta: None,
        execution_mode: RunExecutionMode::ToCompletion,
        save_policy: RunSavePolicy::Never,
        watch_streams_live_status: false,
        startup_commands: vec![
            SessionCommandKind::Start,
            SessionCommandKind::StepQuantum,
            SessionCommandKind::Continue,
        ],
        initial_control_commands: vec![SessionCommandKind::Query, SessionCommandKind::Query],
        accepted_interactive_commands: Vec::new(),
        host_profile: reduction.host_profile,
        collect_execution_fingerprints: true,
        bounded_ack_quanta: RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        outcome_exit_codes: vec![
            (
                BackendCommandStatus::Passed,
                CliError::Outcome(BackendCommandStatus::Passed).exit_code(),
            ),
            (
                BackendCommandStatus::Failed,
                CliError::Outcome(BackendCommandStatus::Failed).exit_code(),
            ),
            (
                BackendCommandStatus::Timeout,
                CliError::Outcome(BackendCommandStatus::Timeout).exit_code(),
            ),
            (
                BackendCommandStatus::Crashed,
                CliError::Outcome(BackendCommandStatus::Crashed).exit_code(),
            ),
        ],
        invalid_scenario_exit_code: CliError::InvalidScenario(String::new()).exit_code(),
    }
}

pub(super) fn verify_witness_from_run_report(
    reduction: VerifyReductionPlan,
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
    backend: Option<&ResolvedLocalBackend>,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    store_root: &Path,
) -> Result<VerifyRunWitness, CliError> {
    let canonical_log = canonical_run_log_entries(run_plan, report);
    let canonical_log_bytes =
        canonical_verify_log_stream_bytes(&canonical_log, &report.streamed_event_frames);
    let fingerprint_samples = verify_fingerprint_samples(report)?;
    let fingerprint_stream = verify_fingerprint_stream_bytes(&fingerprint_samples);
    let live_event_evidence = verify_live_event_evidence(&report.streamed_event_frames)?;
    let request_seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    let seed = ergonomics_plan
        .map(|plan| plan.seed.value)
        .unwrap_or_else(|| seed_to_u64(request_seed));
    let state_dump = verify_state_dump(run_plan, report);
    let artifact = backend
        .map(|backend| {
            if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
                return verify_reproduction_artifact_bytes(
                    seed,
                    Some(backend),
                    run_plan.scenario.scenario_def(),
                    &canonical_log,
                    &fingerprint_samples,
                );
            }
            let scenario = run_plan.scenario.scenario_form();
            let terminal = report.terminal_configuration.as_ref().ok_or_else(|| {
                artifact_error("verify artifact capture requires a terminal configuration")
            })?;
            let model = crucible::ReproductionArtifact::capture(scenario, &terminal.schedule)
                .map_err(|error| {
                    artifact_error(format!("verify model reproduction capture failed: {error}"))
                })?;
            let replay = model.replay().map_err(|error| {
                artifact_error(format!("verify model reproduction replay failed: {error}"))
            })?;
            let live = live_qemu_artifact_evidence_from_run(
                LiveQemuArtifactRecipe {
                    producer: "campaign-run",
                    terminal_condition: run_plan.terminal_condition,
                    max_virtual_time_ticks: run_plan.max_virtual_time_ticks,
                    max_quanta: run_plan.max_quanta,
                    coverage: false,
                    execution_mode: run_plan.execution_mode,
                    startup_commands: &run_plan.startup_commands,
                    initial_control_commands: &run_plan.initial_control_commands,
                    branch: LiveQemuReplayBranch::None,
                },
                scenario,
                report,
            )?;
            let mut payloads = model_reproduction_artifact_payloads(&model, replay.state);
            payloads.extend(live_qemu_artifact_payloads(&live));
            let store = crucible::LocalDagStore::new(store_root.to_path_buf());
            payloads.extend(lifecycle_artifact_payloads(
                scenario.world(),
                scenario.plan().fault_signals(),
                &store,
                None,
            )?);
            let scenario_bytes = scenario.to_compact_binary();
            reproduction_artifact_bytes_with_scenario_payload(
                seed,
                Some(backend),
                ReproductionScenarioPayload {
                    name: "verify-scenario.crucible-scenario",
                    media_type: "application/vnd.crucible.scenario.compact-binary",
                    bytes: &scenario_bytes,
                },
                &canonical_log,
                &fingerprint_samples,
                &payloads,
            )
        })
        .transpose()?;
    Ok(VerifyRunWitness {
        reduction,
        canonical_log,
        canonical_log_bytes,
        fingerprint_samples,
        fingerprint_stream,
        live_event_evidence,
        host_scheduler_preemption: None,
        state_dump,
        artifact,
    })
}

pub(super) fn verify_witness_from_artifact(
    reduction: VerifyReductionPlan,
    artifact: CliReproductionArtifact,
    bytes: Vec<u8>,
) -> Result<VerifyRunWitness, CliError> {
    let canonical_log = canonical_log_entries_from_artifact(&artifact)?;
    let canonical_log_bytes = canonical_log_entry_bytes(&canonical_log);
    let fingerprint_samples = artifact_fingerprint_samples(&artifact);
    let fingerprint_stream = verify_fingerprint_stream_bytes(&fingerprint_samples);
    let state_dump = artifact_state_dump(&artifact);
    Ok(VerifyRunWitness {
        reduction,
        canonical_log,
        canonical_log_bytes,
        fingerprint_samples,
        fingerprint_stream,
        live_event_evidence: VerifyLiveEventEvidence::default(),
        host_scheduler_preemption: None,
        state_dump,
        artifact: Some(bytes),
    })
}

pub(super) fn verify_live_event_evidence(
    frames: &[Vec<u8>],
) -> Result<VerifyLiveEventEvidence, CliError> {
    let mut evidence = VerifyLiveEventEvidence::default();
    for frame in frames {
        let event = std::str::from_utf8(frame)
            .map_err(|error| backend_error(format!("verify event frame is not UTF-8: {error}")))?;
        let kind = verify_frame_value(event, "kind");
        if kind == Some("crucible.event.effect_applied") {
            evidence.fault_effects_applied += 1;
            if let Some(binding) = verify_frame_string_attribute(event, "binding")? {
                evidence.applied_fault_bindings.push(binding);
            }
        } else if kind == Some("crucible.event.assertion_evaluated") {
            evidence.assertions_evaluated += 1;
            if let Some(assertion) = verify_frame_string_attribute(event, "id")? {
                evidence.evaluated_assertions.push(assertion);
            }
        } else if kind == Some("crucible.event.assertion_state_changed") {
            evidence.assertion_state_changes += 1;
            if let (Some(assertion), Some(state)) = (
                verify_frame_string_attribute(event, "id")?,
                verify_frame_string_attribute(event, "new_state")?,
            ) {
                evidence
                    .assertion_transitions
                    .push(format!("{assertion}:{state}"));
            }
        }
    }
    evidence.applied_fault_bindings.sort();
    evidence.applied_fault_bindings.dedup();
    evidence.evaluated_assertions.sort();
    evidence.evaluated_assertions.dedup();
    evidence.assertion_transitions.sort();
    evidence.assertion_transitions.dedup();
    Ok(evidence)
}

fn verify_frame_value<'a>(frame: &'a str, key: &str) -> Option<&'a str> {
    frame.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
    })
}

fn verify_frame_string_attribute(
    frame: &str,
    requested_name: &str,
) -> Result<Option<String>, CliError> {
    for attribute in frame
        .lines()
        .filter_map(|line| line.strip_prefix("attribute="))
    {
        let mut fields = attribute.split('|');
        let (Some(name_hex), Some(value_kind), Some(value_hex)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let name = String::from_utf8(parse_hex_bytes(0, "attribute-name", name_hex)?).map_err(
            |error| backend_error(format!("event attribute name is not UTF-8: {error}")),
        )?;
        if name != requested_name {
            continue;
        }
        if value_kind != "string" {
            return Err(backend_error(format!(
                "verify event attribute `{requested_name}` is not a string"
            )));
        }
        return String::from_utf8(parse_hex_bytes(0, requested_name, value_hex)?)
            .map(Some)
            .map_err(|error| {
                backend_error(format!(
                    "verify event attribute `{requested_name}` is not UTF-8: {error}"
                ))
            });
    }
    Ok(None)
}

#[path = "verify_serve/evidence.rs"]
mod evidence;

pub(crate) use evidence::*;

fn validate_remote_resume_replay_closure(
    scenario: &crucible::ScenarioDefForm,
    configuration: &crucible::Configuration,
    checkpoint: &crucible::Checkpoint,
    envelope: &crucible_api::ResumeReplayClosure,
) -> Result<(), crucible_api::ResumeReplayClosureValidationError> {
    crucible_daemon::qemu_campaign_lifecycle::validate_remote_resume_replay_closure(
        scenario,
        configuration,
        checkpoint,
        envelope,
    )
    .map_err(|error| crucible_api::ResumeReplayClosureValidationError::new(error.to_string()))
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn run_local_double_workflow_async(
    run_plan: &RunInvocationPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    interactive_commands: &[SessionCommandKind],
) -> Result<RunWorkflowReport, CliError> {
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-double",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_terminal_session_retention(true);
    let client = InProcessLifecycleClient::new(control_plane);
    run_control_client_workflow_async(&client, run_plan, interactive_commands).await
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn run_local_double_workflow_stdin_async(
    run_plan: &RunInvocationPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<RunWorkflowReport, CliError> {
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-double",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    )
    .with_terminal_session_retention(true);
    let client = InProcessLifecycleClient::new(control_plane);
    run_control_client_workflow_stdin_async(&client, run_plan, false).await
}

#[path = "verify_serve/service.rs"]
mod service;
pub(crate) use service::*;

pub(super) async fn run_control_client_workflow_async<C>(
    client: &C,
    run_plan: &RunInvocationPlan,
    interactive_commands: &[SessionCommandKind],
) -> Result<RunWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    run_control_client_workflow_with_interactive_driver(
        client,
        run_plan,
        InteractiveCommandDriver::Preparsed(interactive_commands),
        false,
        false,
    )
    .await
}
