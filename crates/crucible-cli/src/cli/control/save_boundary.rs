//! Save breakpoint selection and boundary observation.

use super::*;

pub(in super::super) async fn run_save_selector_to_boundary<C>(
    client: &C,
    session: SessionRef,
    save_plan: &SaveInvocationPlan,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
) -> Result<
    (
        crucible_api::SessionSummary,
        crucible_session::BreakpointFiring,
    ),
    CliError,
>
where
    C: ControlClient + Sync,
{
    let Some(selector) = save_plan.selector.as_ref() else {
        return Err(save_backend_error(format!(
            "save --at {} requires a selector proof",
            save_plan.at.label()
        )));
    };
    let (boundary, breakpoint_id) = run_save_predicate_to_boundary(
        client,
        session,
        save_selector_breakpoint_spec(selector)?,
        command_id,
        acknowledged_commands,
        state_updates,
        "paused save selector breakpoint boundary",
        true,
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
    let firing = validate_save_selector_firing(selector, breakpoint_id, &boundary, &firings)
        .map_err(|source| CliError::SaveWorkflowTrace {
            source: Box::new(source),
            trace: SaveWorkflowFailureTrace {
                selector: selector.clone(),
                frontier_ticks: boundary.frontier.ticks,
                quanta: boundary.quanta_stepped,
                state_updates: state_updates.clone(),
                acknowledged_commands: acknowledged_commands.clone(),
            },
        })?;
    Ok((boundary, firing))
}

// crucible-lint: allow rust-allow -- the save boundary keeps command identity, exact acknowledgements, state updates, selector context, and quiescence policy explicit.
#[allow(clippy::too_many_arguments)]
pub(in super::super) async fn run_save_predicate_to_boundary<C>(
    client: &C,
    session: SessionRef,
    spec: BreakpointSpec,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
    description: &str,
    guard_at_quiescence: bool,
) -> Result<(crucible_api::SessionSummary, BreakpointId), CliError>
where
    C: ControlClient + Sync,
{
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
    let mut breakpoint_id = response.breakpoint_id.ok_or_else(|| {
        save_backend_error("save boundary breakpoint command returned no breakpoint id")
    })?;
    let guard_id = if guard_at_quiescence {
        let response = send_save_workflow_command(
            client,
            session,
            command_id,
            SessionCommand::SetBreakpoint {
                spec: BreakpointSpec::suspend_once(crucible::Predicate::quiescent()),
                reply: CommandReply::discard(),
            },
            acknowledged_commands,
            state_updates,
        )
        .await?;
        Some(response.breakpoint_id.ok_or_else(|| {
            save_backend_error("save selector quiescence breakpoint command returned no id")
        })?)
    } else {
        None
    };
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
    let primed = wait_for_save_workflow_advanced_paused(
        client,
        session,
        &before,
        "paused initial save boundary",
    )
    .await?;
    let priming_firings = query_save_breakpoint_firings(
        client,
        session,
        command_id,
        acknowledged_commands,
        state_updates,
    )
    .await?;
    let target_fired_during_priming = priming_firings
        .iter()
        .any(|firing| firing.id == breakpoint_id);
    let priming_advanced_quantum = primed.quanta_stepped > before.quanta_stepped;
    if target_fired_during_priming && (guard_at_quiescence || priming_advanced_quantum) {
        return Ok((primed, breakpoint_id));
    }
    if target_fired_during_priming {
        let response = send_save_workflow_command(
            client,
            session,
            command_id,
            SessionCommand::SetBreakpoint {
                spec: BreakpointSpec::suspend_once(crucible::Predicate::quiescent()),
                reply: CommandReply::discard(),
            },
            acknowledged_commands,
            state_updates,
        )
        .await?;
        breakpoint_id = response.breakpoint_id.ok_or_else(|| {
            save_backend_error("replacement quiescence breakpoint command returned no id")
        })?;
    }
    let guard_fired_during_priming =
        guard_id.is_some_and(|id| priming_firings.iter().any(|firing| firing.id == id));
    if guard_fired_during_priming && priming_advanced_quantum {
        return Ok((primed, breakpoint_id));
    }
    if guard_fired_during_priming {
        let response = send_save_workflow_command(
            client,
            session,
            command_id,
            SessionCommand::SetBreakpoint {
                spec: BreakpointSpec::suspend_once(crucible::Predicate::quiescent()),
                reply: CommandReply::discard(),
            },
            acknowledged_commands,
            state_updates,
        )
        .await?;
        response.breakpoint_id.ok_or_else(|| {
            save_backend_error("replacement selector quiescence breakpoint returned no id")
        })?;
    }
    send_save_workflow_command(
        client,
        session,
        command_id,
        SessionCommand::Continue,
        acknowledged_commands,
        state_updates,
    )
    .await?;
    let boundary =
        wait_for_save_workflow_advanced_paused(client, session, &primed, description).await?;
    Ok((boundary, breakpoint_id))
}

pub(in super::super) async fn query_save_breakpoint_firings<C>(
    client: &C,
    session: SessionRef,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
) -> Result<Vec<crucible_session::BreakpointFiring>, CliError>
where
    C: ControlClient + Sync,
{
    let response = send_save_workflow_command(
        client,
        session,
        command_id,
        SessionCommand::query_breakpoint_firings(),
        acknowledged_commands,
        state_updates,
    )
    .await?;
    match response.query_result {
        Some(QueryResult::BreakpointFirings(firings)) => Ok(firings),
        Some(other) => Err(save_backend_error(format!(
            "save boundary proof query returned unexpected payload: {other:?}"
        ))),
        None => Err(save_backend_error(
            "save boundary proof query returned no breakpoint firing payload",
        )),
    }
}

pub(in super::super) fn save_selector_breakpoint_spec(
    selector: &SaveAtSelector,
) -> Result<BreakpointSpec, CliError> {
    match selector {
        SaveAtSelector::PropertyViolation { assertion: _ } | SaveAtSelector::Marker { .. } => Ok(
            BreakpointSpec::suspend_once(save_selector_predicate(selector)?),
        ),
    }
}

pub(in super::super) fn save_selector_predicate(
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

pub(in super::super) fn validate_save_selector_firing(
    selector: &SaveAtSelector,
    breakpoint_id: BreakpointId,
    boundary: &crucible_api::SessionSummary,
    firings: &[crucible_session::BreakpointFiring],
) -> Result<crucible_session::BreakpointFiring, CliError> {
    let expected = save_selector_predicate(selector)?;
    let label = match selector {
        SaveAtSelector::PropertyViolation { assertion } => {
            format!("property `{assertion}` violation selector")
        }
        SaveAtSelector::Marker { name } => format!("marker `{name}` selector"),
    };
    validate_save_breakpoint_firing(&label, &expected, breakpoint_id, boundary, firings)
}

pub(in super::super) fn validate_save_breakpoint_firing(
    label: &str,
    expected: &crucible::Predicate,
    breakpoint_id: BreakpointId,
    boundary: &crucible_api::SessionSummary,
    firings: &[crucible_session::BreakpointFiring],
) -> Result<crucible_session::BreakpointFiring, CliError> {
    let firing = firings
        .iter()
        .find(|firing| firing.id == breakpoint_id)
        .ok_or_else(|| {
            save_backend_error(format!(
                "save {label} breakpoint {breakpoint_id} did not fire at the selected boundary; no savepoint was created"
            ))
        })?;
    if &firing.predicate != expected {
        return Err(CliError::Identity(format!(
            "save {label} breakpoint predicate {:?} did not match expected {:?}",
            firing.predicate, expected
        )));
    }
    if firing.disposition != BreakpointDisposition::Suspend {
        return Err(CliError::Identity(format!(
            "save {label} breakpoint used {:?} disposition instead of suspend",
            firing.disposition
        )));
    }
    if firing.frontier != boundary.frontier {
        return Err(CliError::Identity(format!(
            "save {label} breakpoint fired at {}, but boundary is {}",
            firing.frontier.ticks, boundary.frontier.ticks
        )));
    }
    if firing.quanta != boundary.quanta_stepped {
        return Err(CliError::Identity(format!(
            "save {label} breakpoint fired at quantum {}, but boundary is {}",
            firing.quanta, boundary.quanta_stepped
        )));
    }
    Ok(firing.clone())
}

pub(in super::super) async fn send_save_workflow_command<C>(
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

pub(in super::super) async fn wait_for_save_workflow_state<C>(
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
        SAVE_WORKFLOW_OBSERVER_TIMEOUT,
    )
    .await
}

pub(in super::super) async fn wait_for_save_workflow_advanced_paused<C>(
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
                && (summary.quanta_stepped > before.quanta_stepped
                    || summary.event_log_len > before.event_log_len)
        },
        description,
        SAVE_WORKFLOW_OBSERVER_TIMEOUT,
    )
    .await
}

pub(in super::super) async fn drive_save_to_virtual_time_boundary<C>(
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
            SAVE_WORKFLOW_OBSERVER_TIMEOUT,
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

pub(in super::super) async fn wait_for_save_workflow_summary<C>(
    client: &C,
    session: SessionRef,
    mut accepts: impl FnMut(&crucible_api::SessionSummary) -> bool,
    description: &str,
    timeout: Duration,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    let observation = async {
        loop {
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
            // A local control client can answer ListSessions immediately. A
            // short delay avoids starving the actor and bounds remote polling.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(timeout, observation)
        .await
        .map_err(|_| save_backend_error(format!("save workflow did not reach {description}")))?
}
