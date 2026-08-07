//! Save control-client workflows, interactive run control, and outcome projection.

use super::*;
pub(super) async fn run_remote_control_client_save_workflow_async<C>(
    client: &C,
    save_plan: &SaveInvocationPlan,
) -> Result<SaveWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let run_plan = &save_plan.run_plan;
    let seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    let request =
        CreateSessionRequest::inline_form(run_plan.scenario.scenario_form().clone(), seed)
            .with_start_paused(true);
    let created = client
        .create_session(request)
        .await
        .map_err(save_control_client_error)?;
    let mut acknowledged_commands = Vec::new();
    let mut state_updates = Vec::new();
    let mut command_id = 1;

    let boundary = match save_plan.at {
        SaveAtArg::Quiescence => {
            let before =
                wait_for_save_workflow_state(client, created.session, LiveStateKind::Paused)
                    .await?;
            send_save_workflow_command(
                client,
                created.session,
                &mut command_id,
                SessionCommand::step(StepMode::Quantum),
                &mut acknowledged_commands,
                &mut state_updates,
            )
            .await?;
            wait_for_save_workflow_advanced_paused(
                client,
                created.session,
                &before,
                "paused remote quiescence save boundary",
            )
            .await?
        }
        SaveAtArg::VirtualTime => {
            let budget = run_plan.max_virtual_time_ticks.ok_or_else(|| {
                usage_error("save --at virtual-time requires --max-virtual-time <dur>")
            })?;
            drive_save_to_virtual_time_boundary(
                client,
                created.session,
                budget,
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
                "remote ",
            )
            .await?
        }
        SaveAtArg::Property | SaveAtArg::Marker => {
            run_save_selector_to_boundary(
                client,
                created.session,
                save_plan,
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
            )
            .await?
        }
    };

    let snapshot_response = send_save_workflow_command(
        client,
        created.session,
        &mut command_id,
        SessionCommand::query_snapshot(),
        &mut acknowledged_commands,
        &mut state_updates,
    )
    .await?;
    let snapshot = match snapshot_response.query_result {
        Some(QueryResult::Snapshot(snapshot)) => *snapshot,
        Some(other) => {
            return Err(save_backend_error(format!(
                "remote save boundary snapshot returned unexpected query payload: {other:?}"
            )));
        }
        None => {
            return Err(save_backend_error(
                "remote save boundary snapshot returned no query payload",
            ));
        }
    };
    let savepoint_response = send_save_workflow_command(
        client,
        created.session,
        &mut command_id,
        SessionCommand::CreateSavepoint {
            label: save_plan.label.clone(),
            reply: CommandReply::discard(),
        },
        &mut acknowledged_commands,
        &mut state_updates,
    )
    .await?;
    let savepoint = savepoint_response.savepoint_info.ok_or_else(|| {
        save_backend_error("remote savepoint command returned no savepoint payload")
    })?;
    if savepoint.label != save_plan.label {
        return Err(CliError::Identity(format!(
            "remote savepoint label mismatch: expected `{}`, got `{}`",
            save_plan.label, savepoint.label
        )));
    }
    let configuration = snapshot.configuration.id();
    if savepoint.configuration != configuration {
        return Err(CliError::Identity(format!(
            "remote savepoint configuration {} did not match boundary snapshot {}",
            format_content_hash_ref(savepoint.configuration),
            format_content_hash_ref(configuration)
        )));
    }
    let confirmed_snapshot_response = send_save_workflow_command(
        client,
        created.session,
        &mut command_id,
        SessionCommand::query_snapshot(),
        &mut acknowledged_commands,
        &mut state_updates,
    )
    .await?;
    let confirmed_snapshot = match confirmed_snapshot_response.query_result {
        Some(QueryResult::Snapshot(snapshot)) => *snapshot,
        Some(other) => {
            return Err(save_backend_error(format!(
                "remote savepoint confirmation snapshot returned unexpected query payload: {other:?}"
            )));
        }
        None => {
            return Err(save_backend_error(
                "remote savepoint confirmation snapshot returned no query payload",
            ));
        }
    };
    if confirmed_snapshot.configuration.id() != configuration {
        return Err(CliError::Identity(format!(
            "remote savepoint confirmation configuration {} did not match boundary snapshot {}",
            format_content_hash_ref(confirmed_snapshot.configuration.id()),
            format_content_hash_ref(configuration)
        )));
    }
    if confirmed_snapshot.frontier != boundary.frontier {
        return Err(CliError::Identity(format!(
            "remote savepoint confirmation frontier {} did not match boundary {}",
            confirmed_snapshot.frontier.ticks, boundary.frontier.ticks
        )));
    }
    let oracle = validate_savepoint_checkpoint(
        save_plan,
        &snapshot.configuration,
        &savepoint.checkpoint,
        boundary.frontier,
    )?;
    send_save_workflow_command(
        client,
        created.session,
        &mut command_id,
        SessionCommand::Stop,
        &mut acknowledged_commands,
        &mut state_updates,
    )
    .await?;
    let stopped = client
        .list_sessions()
        .await
        .map_err(control_client_error)?
        .sessions
        .into_iter()
        .find(|summary| summary.session == created.session);
    let final_state = match save_plan.at {
        SaveAtArg::Quiescence => String::from("quiescent"),
        SaveAtArg::VirtualTime => String::from("virtual-time"),
        SaveAtArg::Property => String::from("property"),
        SaveAtArg::Marker => String::from("marker"),
    };
    if state_updates.last() != Some(&final_state) {
        state_updates.push(final_state.clone());
    }
    Ok(SaveWorkflowReport {
        run: RunWorkflowReport {
            status: BackendCommandStatus::Passed,
            created_state: format!("{:?}", created.state).to_ascii_lowercase(),
            final_state,
            outcome: Some(OutcomeKind::Passed),
            terminal_savepoint: Some(oracle.fat_checkpoint),
            terminal_configuration: Some(snapshot.configuration.clone()),
            final_frontier_ticks: stopped
                .as_ref()
                .map(|summary| summary.frontier.ticks)
                .unwrap_or(boundary.frontier.ticks)
                .max(boundary.frontier.ticks),
            final_quanta: stopped
                .as_ref()
                .map(|summary| summary.quanta_stepped)
                .unwrap_or(boundary.quanta_stepped)
                .max(boundary.quanta_stepped),
            budget_timed_out: false,
            state_updates,
            streamed_events: Vec::new(),
            streamed_event_frames: Vec::new(),
            coverage_feedback: crucible::EventLogCoverageFeedback::from_event_log(&[]),
            execution_fingerprints: Vec::new(),
            acknowledged_commands,
            watch_statuses: Vec::new(),
        },
        oracle,
    })
}

pub(super) async fn run_save_selector_to_boundary<C>(
    client: &C,
    session: SessionRef,
    save_plan: &SaveInvocationPlan,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    let Some(selector) = save_plan.selector.as_ref() else {
        return Err(save_backend_error(format!(
            "save --at {} requires a selector proof",
            save_plan.at.label()
        )));
    };
    let spec = save_selector_breakpoint_spec(selector)?;
    let response = send_save_workflow_command(
        client,
        session,
        command_id,
        SessionCommand::SetBreakpoint {
            spec,
            reply: CommandReply::discard(),
        },
        acknowledged_commands,
        state_updates,
    )
    .await?;
    let breakpoint_id = response.breakpoint_id.ok_or_else(|| {
        save_backend_error("save selector breakpoint command returned no breakpoint id")
    })?;
    let before = wait_for_save_workflow_state(client, session, LiveStateKind::Paused).await?;
    send_save_workflow_command(
        client,
        session,
        command_id,
        SessionCommand::step(StepMode::Quantum),
        acknowledged_commands,
        state_updates,
    )
    .await?;
    let boundary = wait_for_save_workflow_advanced_paused(
        client,
        session,
        &before,
        "paused save selector breakpoint boundary",
    )
    .await?;
    let firings_response = send_save_workflow_command(
        client,
        session,
        command_id,
        SessionCommand::query_breakpoint_firings(),
        acknowledged_commands,
        state_updates,
    )
    .await?;
    let firings = match firings_response.query_result {
        Some(QueryResult::BreakpointFirings(firings)) => firings,
        Some(other) => {
            return Err(save_backend_error(format!(
                "save selector proof query returned unexpected payload: {other:?}"
            )));
        }
        None => {
            return Err(save_backend_error(
                "save selector proof query returned no breakpoint firing payload",
            ));
        }
    };
    validate_save_selector_firing(selector, breakpoint_id, &boundary, &firings)?;
    Ok(boundary)
}

pub(super) fn save_selector_breakpoint_spec(
    selector: &SaveAtSelector,
) -> Result<BreakpointSpec, CliError> {
    match selector {
        SaveAtSelector::PropertyViolation { assertion: _ } | SaveAtSelector::Marker { .. } => Ok(
            BreakpointSpec::suspend_once(save_selector_predicate(selector)?),
        ),
    }
}

pub(super) fn save_selector_predicate(
    selector: &SaveAtSelector,
) -> Result<crucible::Predicate, CliError> {
    match selector {
        SaveAtSelector::PropertyViolation { assertion } => {
            Ok(crucible::Predicate::assertion_state(
                crucible::AssertionId::from_name(assertion.clone()),
                crucible::AssertionPhase::Violated,
            ))
        }
        SaveAtSelector::Marker { name } => Ok(crucible::Predicate::guest_marker(
            crucible::MarkerId::from_name(name.clone()),
        )),
    }
}

pub(super) fn validate_save_selector_firing(
    selector: &SaveAtSelector,
    breakpoint_id: BreakpointId,
    boundary: &crucible_api::SessionSummary,
    firings: &[crucible_session::BreakpointFiring],
) -> Result<(), CliError> {
    let expected = save_selector_predicate(selector)?;
    let firing = firings
        .iter()
        .find(|firing| firing.id == breakpoint_id)
        .ok_or_else(|| {
            save_backend_error(format!(
                "save selector breakpoint {breakpoint_id} did not fire before savepoint"
            ))
        })?;
    if firing.predicate != expected {
        return Err(CliError::Identity(format!(
            "save selector breakpoint predicate {:?} did not match expected {:?}",
            firing.predicate, expected
        )));
    }
    if firing.disposition != BreakpointDisposition::Suspend {
        return Err(CliError::Identity(format!(
            "save selector breakpoint used {:?} disposition instead of suspend",
            firing.disposition
        )));
    }
    if firing.frontier != boundary.frontier {
        return Err(CliError::Identity(format!(
            "save selector breakpoint fired at {}, but boundary is {}",
            firing.frontier.ticks, boundary.frontier.ticks
        )));
    }
    if firing.quanta != boundary.quanta_stepped {
        return Err(CliError::Identity(format!(
            "save selector breakpoint fired at quantum {}, but boundary is {}",
            firing.quanta, boundary.quanta_stepped
        )));
    }
    Ok(())
}

pub(super) async fn send_save_workflow_command<C>(
    client: &C,
    session: SessionRef,
    command_id: &mut u64,
    command: SessionCommand,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
) -> Result<crucible_api::SendResponse, CliError>
where
    C: ControlClient + Sync,
{
    let command_kind = SessionCommandKind::from(&command);
    let request =
        SendRequest::new(session, *command_id, command).with_expected_epoch(session.epoch);
    let response = client
        .send_command(request)
        .await
        .map_err(save_control_client_error)?;
    *command_id = command_id.saturating_add(1);
    if let Some(update) = response.state_update {
        state_updates.push(format!("{:?}", update.state).to_ascii_lowercase());
    }
    match &response.result.status {
        CommandResultStatus::Accepted => {
            acknowledged_commands.push(command_kind);
            Ok(response)
        }
        CommandResultStatus::Rejected { reason } => Err(save_backend_error(format!(
            "save workflow command `{}` was rejected: {reason:?}",
            session_command_name(command_kind)
        ))),
    }
}

pub(super) async fn wait_for_save_workflow_state<C>(
    client: &C,
    session: SessionRef,
    expected: LiveStateKind,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    let description = format!("{expected:?}");
    wait_for_save_workflow_summary(
        client,
        session,
        |summary| summary.state == expected,
        &description,
        RUN_INTERACTIVE_ACK_QUANTA_BOUND,
    )
    .await
}

pub(super) async fn wait_for_save_workflow_advanced_paused<C>(
    client: &C,
    session: SessionRef,
    before: &crucible_api::SessionSummary,
    description: &str,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    wait_for_save_workflow_summary(
        client,
        session,
        |summary| {
            summary.state == LiveStateKind::Paused
                && summary.frontier.ticks > before.frontier.ticks
                && summary.quanta_stepped > before.quanta_stepped
        },
        description,
        RUN_INTERACTIVE_ACK_QUANTA_BOUND,
    )
    .await
}

pub(super) async fn drive_save_to_virtual_time_boundary<C>(
    client: &C,
    session: SessionRef,
    budget: u64,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
    route_label: &str,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    let mut boundary = wait_for_save_workflow_state(client, session, LiveStateKind::Paused).await?;
    let mut stagnant_quanta = 0_u64;
    while boundary.frontier.ticks < budget {
        let before = boundary;
        send_save_workflow_command(
            client,
            session,
            command_id,
            SessionCommand::step(StepMode::Quantum),
            acknowledged_commands,
            state_updates,
        )
        .await?;
        boundary = wait_for_save_workflow_summary(
            client,
            session,
            |candidate| {
                candidate.state == LiveStateKind::Paused
                    && candidate.quanta_stepped > before.quanta_stepped
            },
            "paused requested virtual-time save boundary",
            RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        )
        .await?;
        if boundary.frontier.ticks <= before.frontier.ticks {
            stagnant_quanta = stagnant_quanta.saturating_add(1);
            if stagnant_quanta >= RUN_INTERACTIVE_ACK_QUANTA_BOUND {
                return Err(save_backend_error(format!(
                    "save {route_label}virtual-time boundary made no progress from {} after {stagnant_quanta} quanta",
                    before.frontier.ticks
                )));
            }
        } else {
            stagnant_quanta = 0;
        }
    }
    if boundary.frontier.ticks != budget {
        return Err(CliError::Identity(format!(
            "save {route_label}virtual-time boundary reached {}, expected {}",
            boundary.frontier.ticks, budget
        )));
    }
    Ok(boundary)
}

pub(super) async fn wait_for_save_workflow_summary<C>(
    client: &C,
    session: SessionRef,
    mut accepts: impl FnMut(&crucible_api::SessionSummary) -> bool,
    description: &str,
    max_attempts: u64,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    for _ in 0..max_attempts {
        let sessions = client
            .list_sessions()
            .await
            .map_err(save_control_client_error)?;
        let Some(summary) = sessions
            .sessions
            .iter()
            .find(|summary| summary.session == session)
        else {
            return Err(save_backend_error("save workflow session disappeared"));
        };
        if accepts(summary) {
            return Ok(summary.clone());
        }
        if summary.state == LiveStateKind::Stopped {
            return Err(CliError::Outcome(status_from_outcome(summary.outcome)?));
        }
        // A local control client can answer ListSessions immediately. A small
        // observer delay prevents that polling loop from starving the actor
        // task that must drive the requested boundary.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Err(save_backend_error(format!(
        "save workflow did not reach {description}"
    )))
}

pub(super) fn validate_savepoint_checkpoint(
    save_plan: &SaveInvocationPlan,
    configuration: &crucible::Configuration,
    checkpoint: &Checkpoint,
    boundary: crucible::VirtualTime,
) -> Result<SavepointOracleProof, CliError> {
    validate_checkpoint_with_replay_oracle(
        "save",
        save_plan.run_plan.scenario.scenario_def(),
        configuration,
        checkpoint,
        boundary,
    )
}

pub(super) fn validate_resume_terminal_savepoint(
    evidence: &ResumeHandleEvidence,
    final_snapshot: &EngineSnapshot,
) -> Result<SavepointOracleProof, CliError> {
    let checkpoint = final_snapshot.terminal_savepoint.as_ref().ok_or_else(|| {
        backend_error("resume completed without a terminal savepoint for replay-oracle validation")
    })?;
    let mut graph = save_validation_graph(&evidence.scenario)?;
    validate_resume_terminal_source_ancestor(evidence, &final_snapshot.configuration)?;
    if !evidence.configuration.is_genesis() {
        graph
            .cache_snapshot(&evidence.configuration, evidence.checkpoint.clone())
            .map_err(|error| {
                CliError::Identity(format!(
                    "resume source checkpoint cache admission failed: {error}"
                ))
            })?;
    }
    validate_resume_replay_anchor(&graph, evidence, &final_snapshot.configuration)?;
    validate_checkpoint_metadata(
        "resume",
        &final_snapshot.configuration,
        checkpoint,
        final_snapshot.frontier,
    )?;
    let replay = graph
        .replay_checkpoint(&final_snapshot.configuration, checkpoint)
        .map_err(|error| {
            CliError::Identity(format!(
                "resume replay-oracle fat==thin validation failed: {error}"
            ))
        })?;
    if replay.fat_checkpoint != checkpoint.id || replay.thin_checkpoint != checkpoint.id {
        return Err(CliError::Identity(format!(
            "resume replay-oracle mismatch: fat={} thin={} saved={}",
            format_content_hash_ref(replay.fat_checkpoint),
            format_content_hash_ref(replay.thin_checkpoint),
            format_content_hash_ref(checkpoint.id)
        )));
    }
    Ok(SavepointOracleProof {
        configuration: replay.configuration,
        fat_checkpoint: replay.fat_checkpoint,
        thin_checkpoint: replay.thin_checkpoint,
        frontier: checkpoint.virtual_time,
        schedule: final_snapshot.configuration.schedule.clone(),
        store_objects: 0,
    })
}

pub(super) fn validate_resume_terminal_source_ancestor(
    evidence: &ResumeHandleEvidence,
    final_configuration: &crucible::Configuration,
) -> Result<(), CliError> {
    if final_configuration.def.id() != evidence.scenario.id() {
        return Err(CliError::Identity(format!(
            "resume terminal scenario {} did not match source scenario {}",
            final_configuration.def.id().to_hex(),
            evidence.scenario.id().to_hex()
        )));
    }
    if final_configuration.schedule.len() < evidence.schedule.len() {
        return Err(CliError::Identity(format!(
            "resume terminal schedule length {} is shorter than source schedule length {}",
            final_configuration.schedule.len(),
            evidence.schedule.len()
        )));
    }
    let source_prefix = final_configuration
        .schedule
        .prefix(evidence.schedule.len())
        .map_err(|error| {
            CliError::Identity(format!("resume terminal source prefix failed: {error}"))
        })?;
    if source_prefix != evidence.schedule {
        return Err(CliError::Identity(format!(
            "resume terminal schedule is not descended from source checkpoint {}",
            format_content_hash_ref(evidence.checkpoint.id)
        )));
    }
    let source_configuration = crucible::Configuration {
        def: final_configuration.def.clone(),
        schedule: source_prefix,
    };
    if source_configuration.id() != evidence.configuration.id() {
        return Err(CliError::Identity(format!(
            "resume terminal source prefix reconstructed {}, expected {}",
            format_content_hash_ref(source_configuration.id()),
            format_content_hash_ref(evidence.configuration.id())
        )));
    }
    validate_checkpoint_metadata(
        "resume source",
        &evidence.configuration,
        &evidence.checkpoint,
        validate_resume_handle_frontier(
            &evidence.schedule,
            evidence.checkpoint.virtual_time.ticks,
        )?,
    )
}

pub(super) fn validate_resume_replay_anchor(
    graph: &ValidationDag,
    evidence: &ResumeHandleEvidence,
    final_configuration: &crucible::Configuration,
) -> Result<(), CliError> {
    if evidence.configuration.is_genesis()
        || final_configuration.id() == evidence.configuration.id()
    {
        return Ok(());
    }
    let ancestor = graph
        .nearest_cached_ancestor(final_configuration)
        .map_err(|error| {
            CliError::Identity(format!("resume replay anchor lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            CliError::Identity(format!(
                "resume replay did not find cached source checkpoint {} as an ancestor",
                format_content_hash_ref(evidence.checkpoint.id)
            ))
        })?;
    if ancestor.id() != evidence.configuration.id() {
        return Err(CliError::Identity(format!(
            "resume replay anchor {} did not match source checkpoint {}",
            format_content_hash_ref(ancestor.id()),
            format_content_hash_ref(evidence.checkpoint.id)
        )));
    }
    Ok(())
}

pub(super) fn validate_checkpoint_with_replay_oracle(
    operation: &'static str,
    scenario: &crucible::ScenarioDef,
    configuration: &crucible::Configuration,
    checkpoint: &Checkpoint,
    boundary: crucible::VirtualTime,
) -> Result<SavepointOracleProof, CliError> {
    validate_checkpoint_with_replay_oracle_anchored(
        operation,
        scenario,
        [],
        configuration,
        checkpoint,
        boundary,
    )
}

pub(super) fn validate_checkpoint_with_replay_oracle_anchored<'a>(
    operation: &'static str,
    scenario: &crucible::ScenarioDef,
    anchors: impl IntoIterator<Item = (&'a crucible::Configuration, &'a Checkpoint)>,
    configuration: &crucible::Configuration,
    checkpoint: &Checkpoint,
    boundary: crucible::VirtualTime,
) -> Result<SavepointOracleProof, CliError> {
    let mut graph = save_validation_graph(scenario)?;
    for (anchor_configuration, anchor_checkpoint) in anchors {
        if !anchor_configuration.is_genesis() {
            graph
                .cache_snapshot(anchor_configuration, anchor_checkpoint.clone())
                .map_err(|error| {
                    CliError::Identity(format!(
                        "{operation} source checkpoint cache admission failed: {error}"
                    ))
                })?;
        }
    }
    validate_checkpoint_metadata(operation, configuration, checkpoint, boundary)?;
    if !configuration.is_genesis() {
        graph
            .cache_snapshot(configuration, checkpoint.clone())
            .map_err(|error| {
                CliError::Identity(format!(
                    "{operation} checkpoint cache admission failed: {error}"
                ))
            })?;
    }
    let replay = graph
        .replay_checkpoint(configuration, checkpoint)
        .map_err(|error| {
            CliError::Identity(format!(
                "{operation} replay-oracle fat==thin validation failed: {error}"
            ))
        })?;
    if replay.fat_checkpoint != checkpoint.id || replay.thin_checkpoint != checkpoint.id {
        return Err(CliError::Identity(format!(
            "{operation} replay-oracle mismatch: fat={} thin={} saved={}",
            format_content_hash_ref(replay.fat_checkpoint),
            format_content_hash_ref(replay.thin_checkpoint),
            format_content_hash_ref(checkpoint.id)
        )));
    }
    let store = MemoryDagStore::new();
    graph
        .persist_checkpoint_closure(&store, configuration)
        .map_err(save_temporal_graph_error)?;
    let store_objects = store.object_count().map_err(CliError::Store)?;
    Ok(SavepointOracleProof {
        configuration: replay.configuration,
        fat_checkpoint: replay.fat_checkpoint,
        thin_checkpoint: replay.thin_checkpoint,
        frontier: checkpoint.virtual_time,
        schedule: configuration.schedule.clone(),
        store_objects,
    })
}

pub(super) fn validate_checkpoint_metadata(
    operation: &'static str,
    configuration: &crucible::Configuration,
    checkpoint: &Checkpoint,
    boundary: crucible::VirtualTime,
) -> Result<(), CliError> {
    if checkpoint.configuration != configuration.id() {
        return Err(CliError::Identity(format!(
            "{operation} checkpoint {} named configuration {}, expected {}",
            format_content_hash_ref(checkpoint.id),
            format_content_hash_ref(checkpoint.configuration),
            format_content_hash_ref(configuration.id())
        )));
    }
    if checkpoint.kind != CheckpointKind::Fat {
        return Err(CliError::Identity(format!(
            "{operation} checkpoint {} was not materialized as fat",
            format_content_hash_ref(checkpoint.id)
        )));
    }
    if checkpoint.virtual_time != boundary {
        return Err(CliError::Identity(format!(
            "{operation} checkpoint {} virtual time {} did not match boundary {}",
            format_content_hash_ref(checkpoint.id),
            checkpoint.virtual_time.ticks,
            boundary.ticks
        )));
    }
    Ok(())
}

pub(super) fn save_validation_graph(
    scenario: &crucible::ScenarioDef,
) -> Result<ValidationDag, CliError> {
    validation_dag_with_baked_genesis(scenario)
        .map_err(|error| CliError::Identity(format!("save validation graph setup failed: {error}")))
}

pub(super) fn save_temporal_graph_error(error: ValidationDagStoreError) -> CliError {
    match error {
        ValidationDagStoreError::Engine { operation, source } => CliError::Identity(format!(
            "save temporal graph {operation} failed replay-oracle validation: {source}"
        )),
        ValidationDagStoreError::Store { source, .. } => CliError::Store(source),
    }
}

pub(super) fn save_control_client_error(error: crucible_api::ControlClientError) -> CliError {
    save_backend_error(format!("control API error: {error}"))
}

pub(super) fn save_backend_error(reason: impl Into<String>) -> CliError {
    CliError::Identity(reason.into())
}

pub(super) fn run_save_policy_label(policy: RunSavePolicy) -> &'static str {
    match policy {
        RunSavePolicy::OnFail => "fail",
        RunSavePolicy::Always => "always",
        RunSavePolicy::Never => "never",
    }
}

pub(super) fn run_terminal_savepoint_for_policy(
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
) -> Result<Option<crucible::ContentHash>, CliError> {
    let should_save = match run_plan.save_policy {
        RunSavePolicy::Always => true,
        RunSavePolicy::OnFail => report.status.is_non_passing(),
        RunSavePolicy::Never => false,
    };
    if !should_save {
        return Ok(None);
    }
    report.terminal_savepoint.map(Some).ok_or_else(|| {
        backend_error(format!(
            "run save policy `{}` required an outcome savepoint, but the session did not materialize one",
            run_save_policy_label(run_plan.save_policy)
        ))
    })
}

pub(super) async fn run_control_client_workflow_stdin_async<C>(
    client: &C,
    run_plan: &RunInvocationPlan,
    announce_remote_session: bool,
) -> Result<RunWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    run_control_client_workflow_with_interactive_driver(
        client,
        run_plan,
        InteractiveCommandDriver::Stdin,
        announce_remote_session,
    )
    .await
}

pub(super) enum InteractiveCommandDriver<'a> {
    Preparsed(&'a [SessionCommandKind]),
    Stdin,
}

pub(super) async fn run_control_client_workflow_with_interactive_driver<C>(
    client: &C,
    run_plan: &RunInvocationPlan,
    interactive_driver: InteractiveCommandDriver<'_>,
    announce_remote_session: bool,
) -> Result<RunWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    let request =
        CreateSessionRequest::inline_form(run_plan.scenario.scenario_form().clone(), seed)
            .with_start_paused(true);
    let created = client
        .create_session(request)
        .await
        .map_err(control_client_error)?;
    if announce_remote_session {
        eprintln!(
            "crucible: live-session\tref={}",
            canonical_debug_session_ref(created.session)
        );
    }
    let mut control = client
        .control_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_client_name("crucible-cli-run"),
        )
        .await
        .map_err(control_client_error)?;

    let mut acknowledged_commands = Vec::new();
    let mut execution_fingerprints = Vec::new();
    let mut command_id = 1;
    acknowledge_stream_command(
        &control,
        &mut command_id,
        SessionCommandKind::Query,
        &mut acknowledged_commands,
    )
    .await?;
    if run_plan.collect_execution_fingerprints {
        query_execution_fingerprint(
            &control,
            &mut command_id,
            run_plan,
            &mut acknowledged_commands,
            &mut execution_fingerprints,
        )
        .await?;
        acknowledge_stream_command(
            &control,
            &mut command_id,
            SessionCommandKind::StepQuantum,
            &mut acknowledged_commands,
        )
        .await?;
        query_execution_fingerprint(
            &control,
            &mut command_id,
            run_plan,
            &mut acknowledged_commands,
            &mut execution_fingerprints,
        )
        .await?;
    }

    let interactive_terminal_snapshot = match run_plan.execution_mode {
        RunExecutionMode::ToCompletion => {
            // Budget boundaries are replay evidence. Drive them one quantum at
            // a time so frontend observation latency cannot add a final quantum.
            if run_plan.max_quanta.is_some() || run_plan.max_virtual_time_ticks.is_some() {
                drive_run_to_exact_budget(
                    client,
                    &control,
                    created.session,
                    run_plan.max_virtual_time_ticks,
                    run_plan.max_quanta,
                    &mut command_id,
                    &mut acknowledged_commands,
                )
                .await?;
            } else {
                let probe_boundary = current_remote_resume_summary(client, created.session).await?;
                if should_continue_after_probe(probe_boundary.state) {
                    acknowledge_stream_command(
                        &control,
                        &mut command_id,
                        SessionCommandKind::Continue,
                        &mut acknowledged_commands,
                    )
                    .await?;
                }
            }
            None
        }
        RunExecutionMode::Interactive => match interactive_driver {
            InteractiveCommandDriver::Preparsed(commands) => {
                let mut terminal_snapshot = None;
                for command in commands {
                    let response = acknowledge_stream_command_payload(
                        &control,
                        &mut command_id,
                        cli_stream_command(*command)?,
                        &mut acknowledged_commands,
                    )
                    .await?;
                    if *command == SessionCommandKind::Stop {
                        terminal_snapshot = terminal_snapshot_from_stop_response(response)?;
                        break;
                    }
                }
                terminal_snapshot
            }
            InteractiveCommandDriver::Stdin => {
                drive_interactive_stdin_commands(
                    &control,
                    &mut command_id,
                    &mut acknowledged_commands,
                )
                .await?
            }
        },
    };

    let mut state_updates = Vec::new();
    let mut streamed_events = Vec::new();
    let mut streamed_event_frames = Vec::new();
    let mut coverage_events = Vec::new();
    let mut streamed_event_cursor = 0;
    let observation = observe_run_final_state(
        client,
        &mut control,
        run_plan,
        created.session,
        &mut command_id,
        &mut acknowledged_commands,
        &mut state_updates,
        &mut streamed_events,
        &mut streamed_event_frames,
        &mut coverage_events,
        &mut streamed_event_cursor,
        interactive_terminal_snapshot.as_deref(),
    )
    .await?;
    if state_updates.last() != Some(&observation.final_state) {
        state_updates.push(observation.final_state.clone());
    }
    let status = run_status_from_observation(run_plan, &observation)?;

    Ok(RunWorkflowReport {
        status,
        created_state: format!("{:?}", created.state).to_ascii_lowercase(),
        final_state: observation.final_state,
        outcome: observation.outcome,
        terminal_savepoint: observation.terminal_savepoint,
        terminal_configuration: Some(observation.terminal_configuration),
        final_frontier_ticks: observation.frontier_ticks,
        final_quanta: observation.quanta,
        budget_timed_out: observation.budget_timed_out,
        state_updates,
        streamed_events,
        streamed_event_frames,
        coverage_feedback: coverage_feedback_from_streamed_events(coverage_events)?,
        execution_fingerprints,
        acknowledged_commands,
        watch_statuses: observation.watch_statuses,
    })
}

pub(super) fn canonical_debug_session_ref(session: crucible_api::SessionRef) -> String {
    format!(
        "{}:{}:{}",
        session.id.value,
        session.epoch,
        session.seed.to_hex()
    )
}

fn should_continue_after_probe(state: LiveStateKind) -> bool {
    state != LiveStateKind::Stopped
}

async fn drive_run_to_exact_budget<C>(
    client: &C,
    control: &crucible_api::ClientControlStream,
    session: crucible_api::SessionRef,
    virtual_time_budget: Option<u64>,
    quantum_budget: Option<u64>,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<(), CliError>
where
    C: ControlClient + Sync,
{
    let mut boundary = current_remote_resume_summary(client, session).await?;
    while boundary.state != LiveStateKind::Stopped
        && quantum_budget.is_none_or(|budget| boundary.quanta_stepped < budget)
        && !virtual_time_budget.is_some_and(|budget| boundary.frontier.ticks >= budget)
    {
        if boundary.state != LiveStateKind::Paused {
            boundary = wait_for_save_workflow_summary(
                client,
                session,
                |summary| {
                    matches!(
                        summary.state,
                        LiveStateKind::Paused | LiveStateKind::Stopped
                    )
                },
                "paused bounded-run quantum boundary",
                RUN_INTERACTIVE_ACK_QUANTA_BOUND,
            )
            .await?;
            continue;
        }

        let before = boundary;
        acknowledge_stream_command(
            control,
            command_id,
            SessionCommandKind::StepQuantum,
            acknowledged_commands,
        )
        .await?;
        boundary = wait_for_save_workflow_summary(
            client,
            session,
            |summary| {
                matches!(
                    summary.state,
                    LiveStateKind::Paused | LiveStateKind::Stopped
                ) && summary.quanta_stepped > before.quanta_stepped
            },
            "completed bounded-run quantum boundary",
            RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn drive_interactive_stdin_commands(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<Option<Box<crucible_session::EngineSnapshot>>, CliError> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    drive_interactive_command_reader(
        control,
        command_id,
        acknowledged_commands,
        stdin.lock(),
        &mut stdout,
    )
    .await
}

pub(super) async fn drive_interactive_command_reader<R, W>(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    reader: R,
    writer: &mut W,
) -> Result<Option<Box<crucible_session::EngineSnapshot>>, CliError>
where
    R: BufRead,
    W: Write,
{
    let mut terminal_snapshot = None;
    for line in reader.lines() {
        let line = line?;
        let Some(command) = parse_interactive_session_command_line(&line)? else {
            continue;
        };
        let response = acknowledge_stream_command_payload(
            control,
            command_id,
            cli_stream_command(command)?,
            acknowledged_commands,
        )
        .await?;
        writeln!(
            writer,
            "interactive-ack\tcommand={}\tstatus=accepted",
            session_command_name(command)
        )?;
        if command == SessionCommandKind::Query {
            write_interactive_query_result(writer, response.query_result.as_ref())?;
        }
        if command == SessionCommandKind::Stop {
            terminal_snapshot = terminal_snapshot_from_stop_response(response)?;
        }
        writer.flush()?;
        if command == SessionCommandKind::Stop {
            break;
        }
    }
    Ok(terminal_snapshot)
}

fn write_interactive_query_result<W: Write>(
    writer: &mut W,
    result: Option<&QueryResult>,
) -> Result<(), CliError> {
    match result {
        Some(QueryResult::State(state)) => write_interactive_query_state(writer, state),
        Some(other) => Err(backend_error(format!(
            "interactive state query returned unexpected payload: {other:?}"
        ))),
        None => Err(backend_error("interactive state query returned no payload")),
    }
}

/// Writes the agent-readable lifecycle state returned by an interactive query.
///
/// # Errors
///
/// Returns [`CliError`] when the output stream cannot accept the line.
pub(super) fn write_interactive_query_state<W: Write>(
    writer: &mut W,
    state: impl std::fmt::Debug,
) -> Result<(), CliError> {
    writeln!(
        writer,
        "interactive-query\tstate={}",
        format!("{state:?}").to_ascii_lowercase()
    )?;
    Ok(())
}

fn terminal_snapshot_from_stop_response(
    response: crucible_api::SendResponse,
) -> Result<Option<Box<crucible_session::EngineSnapshot>>, CliError> {
    match response.query_result {
        Some(QueryResult::Snapshot(snapshot)) => Ok(Some(snapshot)),
        Some(other) => Err(backend_error(format!(
            "interactive stop returned unexpected terminal payload: {other:?}"
        ))),
        None => Err(backend_error(
            "interactive stop returned no terminal snapshot",
        )),
    }
}

pub(super) async fn acknowledge_stream_command(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    command: SessionCommandKind,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<(), CliError> {
    let model_command = cli_stream_command(command)?;
    acknowledge_stream_command_payload(control, command_id, model_command, acknowledged_commands)
        .await
        .map(|_| ())
}

pub(super) async fn acknowledge_stream_command_payload(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    model_command: SessionCommand,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<crucible_api::SendResponse, CliError> {
    let command = SessionCommandKind::from(&model_command);
    let response = control
        .send_command(*command_id, model_command)
        .await
        .map_err(control_client_error)?;
    *command_id = command_id.saturating_add(1);
    match response.result.status {
        CommandResultStatus::Accepted => {
            acknowledged_commands.push(command);
            Ok(response)
        }
        CommandResultStatus::Rejected { reason } => Err(backend_error(format!(
            "session command `{}` was rejected: {reason:?}",
            session_command_name(command)
        ))),
    }
}

pub(super) fn cli_stream_command(command: SessionCommandKind) -> Result<SessionCommand, CliError> {
    if command == SessionCommandKind::Query {
        return Ok(SessionCommand::Query {
            kind: QueryKind::State,
            reply: CommandReply::discard(),
        });
    }
    command.representative_command().ok_or_else(|| {
        backend_error(format!(
            "session command `{}` is not supported",
            session_command_name(command)
        ))
    })
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
// crucible-lint: allow rust-allow -- the drain boundary carries the control stream, terminal extent, timeout, decoded events, exact frames, coverage events, and cursor as distinct ownership domains.
#[allow(clippy::too_many_arguments)]
pub(super) async fn observe_run_final_state<C>(
    client: &C,
    control: &mut crucible_api::ClientControlStream,
    run_plan: &RunInvocationPlan,
    session_ref: crucible_api::SessionRef,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
    streamed_events: &mut Vec<String>,
    streamed_event_frames: &mut Vec<Vec<u8>>,
    coverage_events: &mut Vec<crucible::ObservableEvent>,
    streamed_event_cursor: &mut u64,
    interactive_terminal_snapshot: Option<&crucible_session::EngineSnapshot>,
) -> Result<RunObservation, CliError>
where
    C: ControlClient + Sync,
{
    let mut watch_statuses = Vec::new();
    loop {
        for _ in 0..run_plan.observer_profile.pre_poll_yields {
            tokio::task::yield_now().await;
        }
        let mut stream_ended = false;
        match run_plan.observer_profile.poll_order {
            VerifyPollOrder::EventThenState => {
                if observe_next_event(
                    control,
                    run_plan.observer_profile.event_timeout_ms,
                    streamed_events,
                    streamed_event_frames,
                    coverage_events,
                    streamed_event_cursor,
                )
                .await?
                {
                    stream_ended = true;
                }
                if !stream_ended
                    && observe_next_state_update(
                        control,
                        run_plan.observer_profile.state_timeout_ms,
                        state_updates,
                    )
                    .await?
                {
                    stream_ended = true;
                }
            }
            VerifyPollOrder::StateThenEvent => {
                if observe_next_state_update(
                    control,
                    run_plan.observer_profile.state_timeout_ms,
                    state_updates,
                )
                .await?
                {
                    stream_ended = true;
                }
                if !stream_ended
                    && observe_next_event(
                        control,
                        run_plan.observer_profile.event_timeout_ms,
                        streamed_events,
                        streamed_event_frames,
                        coverage_events,
                        streamed_event_cursor,
                    )
                    .await?
                {
                    stream_ended = true;
                }
            }
        }
        let sessions = client.list_sessions().await.map_err(control_client_error)?;
        let Some(session) = sessions
            .sessions
            .iter()
            .find(|summary| summary.session == session_ref)
        else {
            if let Some(snapshot) = interactive_terminal_snapshot {
                let outcome = match &snapshot.state {
                    crucible_session::EngineState::Stopped { outcome } => {
                        Some(OutcomeKind::from(outcome))
                    }
                    state => {
                        return Err(backend_error(format!(
                            "run session disappeared after stop returned non-terminal state {state:?}"
                        )));
                    }
                };
                let terminal_event_log_len =
                    u64::try_from(snapshot.event_log_len).map_err(|_| {
                        backend_error(
                            "terminal event-log length exceeded the supported cursor range",
                        )
                    })?;
                drain_terminal_event_log(
                    control,
                    terminal_event_log_len,
                    run_plan.observer_profile.event_timeout_ms,
                    streamed_events,
                    streamed_event_frames,
                    coverage_events,
                    streamed_event_cursor,
                )
                .await?;
                if run_plan.watch_streams_live_status {
                    watch_statuses.push(run_snapshot_watch_status(snapshot, outcome));
                }
                return Ok(RunObservation {
                    final_state: terminal_final_state(run_plan, outcome),
                    outcome,
                    terminal_savepoint: snapshot.terminal_savepoint.as_ref().map(|value| value.id),
                    terminal_configuration: snapshot.configuration.clone(),
                    frontier_ticks: snapshot.frontier.ticks,
                    quanta: snapshot.quanta,
                    budget_timed_out: outcome == Some(OutcomeKind::Timeout),
                    watch_statuses,
                });
            }
            return Err(backend_error(
                "run session disappeared before the engine reported an outcome",
            ));
        };
        if run_plan.watch_streams_live_status {
            watch_statuses.push(run_watch_status(session));
        }
        let virtual_time_timed_out = run_plan
            .max_virtual_time_ticks
            .is_some_and(|budget| session.frontier.ticks >= budget);
        let quantum_timed_out = run_plan.max_quanta.is_some_and(|budget| {
            session.quanta_stepped >= budget && session.state != LiveStateKind::Stopped
        });
        if virtual_time_timed_out {
            return stop_budget_timed_out_session(
                client,
                control,
                command_id,
                acknowledged_commands,
                String::from("virtual-time"),
                session.clone(),
                watch_statuses,
                run_plan.watch_streams_live_status,
            )
            .await;
        }
        if quantum_timed_out {
            return stop_budget_timed_out_session(
                client,
                control,
                command_id,
                acknowledged_commands,
                String::from("timeout"),
                session.clone(),
                watch_statuses,
                run_plan.watch_streams_live_status,
            )
            .await;
        }
        if session.state == LiveStateKind::Stopped {
            drain_terminal_event_log(
                control,
                session.event_log_len,
                run_plan.observer_profile.event_timeout_ms,
                streamed_events,
                streamed_event_frames,
                coverage_events,
                streamed_event_cursor,
            )
            .await?;
            let terminal_configuration =
                query_run_terminal_configuration(control, command_id, acknowledged_commands)
                    .await?;
            return Ok(RunObservation {
                final_state: terminal_final_state(run_plan, session.outcome),
                outcome: session.outcome,
                terminal_savepoint: session.terminal_savepoint,
                terminal_configuration,
                frontier_ticks: session.frontier.ticks,
                quanta: session.quanta_stepped,
                budget_timed_out: session.outcome == Some(OutcomeKind::Timeout),
                watch_statuses,
            });
        }
        if stream_ended {
            return Err(backend_error(format!(
                "run observation stream ended while session remained running at frontier {} after {} quanta",
                session.frontier.ticks, session.quanta_stepped
            )));
        }
        for _ in 0..run_plan.observer_profile.post_poll_yields {
            tokio::task::yield_now().await;
        }
    }
}

pub(super) async fn query_execution_fingerprint(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    run_plan: &RunInvocationPlan,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    execution_fingerprints: &mut Vec<crucible::FingerprintSample>,
) -> Result<(), CliError> {
    let mut nodes = run_plan
        .scenario
        .scenario_form()
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    if nodes.is_empty() {
        return Err(backend_error(
            "verify requires at least one scenario node for execution fingerprint sampling",
        ));
    }
    for node in nodes {
        let response = control
            .send_command(
                *command_id,
                SessionCommand::Query {
                    kind: QueryKind::ExecutionFingerprint { node: node.clone() },
                    reply: CommandReply::discard(),
                },
            )
            .await
            .map_err(control_client_error)?;
        *command_id = command_id.saturating_add(1);
        match response.result.status {
            CommandResultStatus::Accepted => {
                acknowledged_commands.push(SessionCommandKind::Query);
            }
            CommandResultStatus::Rejected { reason } => {
                return Err(backend_error(format!(
                    "execution fingerprint query for node `{}` was rejected: {reason:?}",
                    node.name
                )));
            }
        }
        match response.query_result {
            Some(QueryResult::ExecutionFingerprint(sample)) => {
                execution_fingerprints.push(sample);
            }
            Some(other) => {
                return Err(backend_error(format!(
                    "execution fingerprint query for node `{}` returned unexpected payload: {other:?}",
                    node.name
                )));
            }
            None => {
                return Err(backend_error(format!(
                    "execution fingerprint query for node `{}` returned no payload",
                    node.name
                )));
            }
        }
    }
    Ok(())
}

pub(super) async fn observe_next_state_update(
    control: &mut crucible_api::ClientControlStream,
    timeout_ms: u64,
    state_updates: &mut Vec<String>,
) -> Result<bool, CliError> {
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        control.recv_state_update(),
    )
    .await
    {
        Ok(Ok(Some(frame))) => {
            state_updates.push(format!("{:?}", frame.update.state).to_ascii_lowercase());
            Ok(false)
        }
        Ok(Ok(None)) => Ok(true),
        Ok(Err(error)) => Err(control_client_error(error)),
        Err(_) => Ok(false),
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) async fn stop_budget_timed_out_session<C>(
    client: &C,
    // crucible-lint: allow host-nondeterminism-state -- the typed client stream is observation transport; the session engine remains authoritative.
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    final_state: String,
    initial: crucible_api::SessionSummary,
    mut watch_statuses: Vec<String>,
    watch_streams_live_status: bool,
) -> Result<RunObservation, CliError>
where
    C: ControlClient + Sync,
{
    let stopped = if initial.state == LiveStateKind::Stopped {
        initial
    } else {
        acknowledge_stream_command(
            control,
            command_id,
            SessionCommandKind::ExhaustBudget,
            acknowledged_commands,
        )
        .await?;
        let mut stopped = initial;
        for _ in 0..RUN_INTERACTIVE_ACK_QUANTA_BOUND {
            let sessions = client.list_sessions().await.map_err(control_client_error)?;
            let Some(session) = sessions
                .sessions
                .iter()
                .find(|summary| summary.session == stopped.session)
            else {
                break;
            };
            stopped = session.clone();
            if watch_streams_live_status {
                watch_statuses.push(run_watch_status(session));
            }
            if session.state == LiveStateKind::Stopped {
                break;
            }
            tokio::task::yield_now().await;
        }
        stopped
    };

    Ok(RunObservation {
        final_state,
        outcome: stopped.outcome,
        terminal_savepoint: stopped.terminal_savepoint,
        terminal_configuration: query_run_terminal_configuration(
            control,
            command_id,
            acknowledged_commands,
        )
        .await?,
        frontier_ticks: stopped.frontier.ticks,
        quanta: stopped.quanta_stepped,
        budget_timed_out: stopped.outcome == Some(OutcomeKind::Timeout),
        watch_statuses,
    })
}

// crucible-lint: allow host-nondeterminism-state -- formatting a validated API summary cannot admit host-derived engine state.
pub(super) fn run_watch_status(session: &crucible_api::SessionSummary) -> String {
    format!(
        "state={}\tfrontier_ticks={}\tquanta={}\toutcome={}\tsavepoint={}",
        format!("{:?}", session.state).to_ascii_lowercase(),
        session.frontier.ticks,
        session.quanta_stepped,
        terminal_outcome_label(session.outcome),
        session
            .terminal_savepoint
            .map(format_content_hash_ref)
            .unwrap_or_else(|| String::from("none"))
    )
}

fn run_snapshot_watch_status(
    snapshot: &crucible_session::EngineSnapshot,
    outcome: Option<OutcomeKind>,
) -> String {
    format!(
        "state=stopped\tfrontier_ticks={}\tquanta={}\toutcome={}\tsavepoint={}",
        snapshot.frontier.ticks,
        snapshot.quanta,
        terminal_outcome_label(outcome),
        snapshot
            .terminal_savepoint
            .as_ref()
            .map(|checkpoint| format_content_hash_ref(checkpoint.id))
            .unwrap_or_else(|| String::from("none"))
    )
}

pub(super) fn terminal_final_state(
    run_plan: &RunInvocationPlan,
    outcome: Option<OutcomeKind>,
) -> String {
    match run_plan.terminal_condition {
        RunTerminalCondition::Quiescence => match outcome {
            Some(OutcomeKind::Passed) => String::from("quiescent"),
            _ => terminal_outcome_label(outcome).to_string(),
        },
        RunTerminalCondition::VirtualTime => match outcome {
            Some(OutcomeKind::Passed) => String::from("stopped-before-virtual-time"),
            _ => terminal_outcome_label(outcome).to_string(),
        },
        RunTerminalCondition::Stopped => match outcome {
            Some(OutcomeKind::Passed) => String::from("stopped-passed"),
            _ => terminal_outcome_label(outcome).to_string(),
        },
        RunTerminalCondition::Property => match outcome {
            Some(OutcomeKind::Failed) => String::from("property-failed"),
            Some(OutcomeKind::Passed) | None => String::from("property-missing"),
            _ => terminal_outcome_label(outcome).to_string(),
        },
    }
}

pub(super) fn terminal_outcome_label(outcome: Option<OutcomeKind>) -> &'static str {
    match outcome {
        Some(OutcomeKind::Passed) => "passed",
        Some(OutcomeKind::Failed) => "failed",
        Some(OutcomeKind::Timeout) => "timeout",
        Some(OutcomeKind::Crashed) => "crashed",
        Some(OutcomeKind::Stopped) => "stopped",
        None => "unknown",
    }
}

#[cfg(test)]
pub(super) fn parse_interactive_session_commands(
    input: &str,
) -> Result<Vec<SessionCommandKind>, CliError> {
    input
        .lines()
        .filter_map(|line| parse_interactive_session_command_line(line).transpose())
        .collect()
}

pub(super) fn parse_interactive_session_command_line(
    line: &str,
) -> Result<Option<SessionCommandKind>, CliError> {
    let command = line.split('#').next().unwrap_or("").trim();
    if command.is_empty() {
        Ok(None)
    } else {
        parse_interactive_session_command(command).map(Some)
    }
}

pub(super) fn parse_interactive_session_command(
    command: &str,
) -> Result<SessionCommandKind, CliError> {
    match command {
        "continue" => Ok(SessionCommandKind::Continue),
        "pause" => Ok(SessionCommandKind::Pause),
        "step" | "step-quantum" => Ok(SessionCommandKind::StepQuantum),
        "step-event" => Ok(SessionCommandKind::StepEvent),
        "step-assertion" => Ok(SessionCommandKind::StepAssertion),
        "step-timer" => Ok(SessionCommandKind::StepTimer),
        "step-duration" => Ok(SessionCommandKind::StepDuration),
        "inject" => Ok(SessionCommandKind::Inject),
        "inject-fault" => Ok(SessionCommandKind::InjectFault),
        "heal" | "heal-fault" => Ok(SessionCommandKind::HealFault),
        "save" | "create-savepoint" => Ok(SessionCommandKind::CreateSavepoint),
        "fork" => Ok(SessionCommandKind::Fork),
        "query" => Ok(SessionCommandKind::Query),
        "stop" => Ok(SessionCommandKind::Stop),
        _ => Err(usage_error(format!(
            "unknown interactive session command `{command}`"
        ))),
    }
}

pub(super) fn append_local_double_run_entries(
    outcome: &mut BackendCommandOutcome,
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
) {
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("scenario"),
        kind: String::from("run_scenario"),
        summary: format!("id={}", run_plan.scenario.scenario_id().to_hex()),
    });
    let request_seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("run_seed"),
        summary: request_seed.to_hex(),
    });
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("run_terminal_condition"),
        summary: format!("{:?}", run_plan.terminal_condition),
    });
    for state in &report.state_updates {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("session"),
            kind: String::from("run_state_update"),
            summary: state.clone(),
        });
    }
    for event in &report.streamed_events {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("event-log"),
            kind: String::from("run_stream_event"),
            summary: event.clone(),
        });
    }
    for command in &report.acknowledged_commands {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("control"),
            kind: String::from("interactive_ack"),
            summary: session_command_name(*command).to_string(),
        });
    }
    for status in &report.watch_statuses {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("session"),
            kind: String::from("run_watch_status"),
            summary: status.clone(),
        });
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}

pub(super) fn session_command_name(command: SessionCommandKind) -> &'static str {
    match command {
        SessionCommandKind::Start => "start",
        SessionCommandKind::Continue => "continue",
        SessionCommandKind::Pause => "pause",
        SessionCommandKind::StepQuantum => "step-quantum",
        SessionCommandKind::StepEvent => "step-event",
        SessionCommandKind::StepAssertion => "step-assertion",
        SessionCommandKind::StepTimer => "step-timer",
        SessionCommandKind::StepDuration => "step-duration",
        SessionCommandKind::Inject => "inject",
        SessionCommandKind::InjectFault => "inject-fault",
        SessionCommandKind::HealFault => "heal-fault",
        SessionCommandKind::SetBreakpoint => "set-breakpoint",
        SessionCommandKind::RemoveBreakpoint => "remove-breakpoint",
        SessionCommandKind::CreateSavepoint => "create-savepoint",
        SessionCommandKind::Fork => "fork",
        SessionCommandKind::Query => "query",
        SessionCommandKind::Stop => "stop",
        SessionCommandKind::ExhaustBudget => "exhaust-budget",
        SessionCommandKind::Snapshot => "snapshot",
        SessionCommandKind::AttachGdb => "attach-gdb",
        SessionCommandKind::DebugGoto => "debug-goto",
        SessionCommandKind::DebugReverseStep => "debug-reverse-step",
        SessionCommandKind::DebugReverseContinue => "debug-reverse-continue",
        SessionCommandKind::DebugForkNonCanonical => "debug-fork-non-canonical",
        SessionCommandKind::GuestIntrospection => "guest-introspection",
    }
}

// crucible-lint: allow host-nondeterminism-state -- this boundary converts a typed transport failure without constructing session state.
pub(super) fn control_client_error(error: crucible_api::ControlClientError) -> CliError {
    backend_error(format!("control API error: {error}"))
}

pub(super) fn backend_command_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> BackendCommandOutcome {
    let canonical_log = backend_canonical_log_entries(thin_plan, backend_plan, ergonomics_plan);
    let canonical_log_digest = canonical_log_digest(&canonical_log);
    let artifact_digest = content_address_bytes(
        format!(
            "artifact\n{:?}\n{}\nseed={}\n",
            thin_plan.subcommand,
            canonical_log_digest,
            ergonomics_plan
                .map(|plan| format_seed(plan.seed.value))
                .unwrap_or_else(|| String::from("artifact-or-savepoint-owned"))
        )
        .as_bytes(),
    );

    BackendCommandOutcome {
        subcommand: backend_plan.subcommand,
        status: BackendCommandStatus::Passed,
        exit_code: 0,
        stdout: vec![format!(
            "outcome\t{:?}\t{}",
            thin_plan.subcommand, canonical_log_digest
        )],
        stderr: Vec::new(),
        canonical_log,
        canonical_log_digest,
        artifact_digest,
        terminal_savepoint: None,
        savepoint_oracle: None,
        reproduction_artifact: None,
        side_reproduction_artifacts: Vec::new(),
    }
}

pub(super) fn backend_canonical_log_entries(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Vec<CanonicalLogEntry> {
    let mut entries = Vec::new();
    let seed_summary = ergonomics_plan
        .map(|plan| {
            format!(
                "seed={} source={:?}",
                format_seed(plan.seed.value),
                plan.seed.source
            )
        })
        .unwrap_or_else(|| String::from("seed=artifact-or-savepoint-owned"));
    entries.push(CanonicalLogEntry {
        sequence: entries.len() as u64,
        virtual_time_ticks: 0,
        node: String::from("cli"),
        kind: String::from("run_identity"),
        summary: seed_summary,
    });
    entries.push(CanonicalLogEntry {
        sequence: entries.len() as u64,
        virtual_time_ticks: 0,
        node: String::from("cli"),
        kind: String::from("backend_fidelity"),
        summary: format!("{:?}", backend_plan.requested_backend),
    });
    for command in &thin_plan.session_commands {
        entries.push(CanonicalLogEntry {
            sequence: entries.len() as u64,
            virtual_time_ticks: entries.len() as u64,
            node: String::from("session"),
            kind: String::from("session_command"),
            summary: format!("{command:?}"),
        });
    }
    for call in &thin_plan.api_calls {
        entries.push(CanonicalLogEntry {
            sequence: entries.len() as u64,
            virtual_time_ticks: entries.len() as u64,
            node: String::from("api"),
            kind: String::from("api_call"),
            summary: call.control_client_method().to_string(),
        });
    }
    entries
}
#[path = "control/streaming_events.rs"]
mod streaming_events;

pub(crate) use streaming_events::*;

#[cfg(test)]
mod completion_probe_tests {
    use super::*;

    #[test]
    fn terminal_fingerprint_probe_does_not_issue_continue() {
        assert!(!should_continue_after_probe(LiveStateKind::Stopped));
        assert!(should_continue_after_probe(LiveStateKind::Paused));
    }
}
