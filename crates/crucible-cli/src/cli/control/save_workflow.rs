//! Remote save-boundary driving and breakpoint selection.

use super::*;

// Live QEMU quanta may spend most of the per-node completion window inside the
// backend. Keep save observation aligned with that 300-second production bound;
// the streaming acknowledgement yield budget is not a wall-clock run timeout.
pub(in super::super) const SAVE_WORKFLOW_OBSERVER_TIMEOUT: Duration = Duration::from_secs(300);

pub(in super::super) async fn run_remote_control_client_save_workflow_async<C>(
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

    let (boundary, breakpoint_firing) = match save_plan.at {
        SaveAtArg::Quiescence => {
            let predicate = crucible::Predicate::quiescent();
            let (boundary, breakpoint_id) = run_save_predicate_to_boundary(
                client,
                created.session,
                BreakpointSpec::suspend_once(predicate.clone()),
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
                "paused remote quiescence save boundary",
                false,
            )
            .await?;
            let firings = query_save_breakpoint_firings(
                client,
                created.session,
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
            )
            .await?;
            let firing = validate_save_breakpoint_firing(
                "quiescence",
                &predicate,
                breakpoint_id,
                &boundary,
                &firings,
            )?;
            (boundary, Some(firing))
        }
        SaveAtArg::VirtualTime => {
            let budget = run_plan.max_virtual_time_ticks.ok_or_else(|| {
                usage_error("save --at virtual-time requires --max-virtual-time <dur>")
            })?;
            let boundary = drive_save_to_virtual_time_boundary(
                client,
                created.session,
                budget,
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
                "remote ",
            )
            .await?;
            (boundary, None)
        }
        SaveAtArg::Property | SaveAtArg::Marker => {
            let (boundary, firing) = run_save_selector_to_boundary(
                client,
                created.session,
                save_plan,
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
            )
            .await?;
            (boundary, Some(firing))
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
            resolved_effect_trace: None,
            acknowledged_commands,
            watch_statuses: Vec::new(),
        },
        oracle,
        boundary_evidence: SaveBoundaryEvidence {
            at: save_plan.at,
            selector: save_plan.selector.clone(),
            frontier_ticks: boundary.frontier.ticks,
            quanta: boundary.quanta_stepped,
            breakpoint_firing,
        },
    })
}
