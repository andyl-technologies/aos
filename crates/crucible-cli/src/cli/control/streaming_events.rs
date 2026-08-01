//! Terminal event-stream draining and canonical coverage reconstruction.

use super::*;

pub(crate) async fn observe_next_event(
    control: &mut crucible_api::ClientControlStream,
    timeout_ms: u64,
    streamed_events: &mut Vec<String>,
    streamed_event_frames: &mut Vec<Vec<u8>>,
    coverage_events: &mut Vec<crucible::ObservableEvent>,
    streamed_event_cursor: &mut u64,
) -> Result<bool, CliError> {
    match tokio::time::timeout(Duration::from_millis(timeout_ms), control.recv_event()).await {
        Ok(Ok(Some(frame))) => {
            if let Some(event) = coverage_event_from_streaming_frame(&frame)? {
                coverage_events.push(event);
            }
            *streamed_event_cursor = frame.next_cursor.next_sequence;
            streamed_event_frames.push(canonical_streaming_event_frame_bytes(&frame));
            streamed_events.push(frame.event.payload.kind);
            Ok(false)
        }
        Ok(Ok(None)) => Ok(true),
        Ok(Err(error)) => Err(control_client_error(error)),
        Err(_) => Ok(false),
    }
}

// crucible-lint: allow rust-allow -- the terminal drain carries the control stream, terminal extent, timeout, decoded events, exact frames, coverage events, and cursor as distinct ownership domains.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drain_terminal_event_log(
    control: &mut crucible_api::ClientControlStream,
    terminal_event_log_len: u64,
    timeout_ms: u64,
    streamed_events: &mut Vec<String>,
    streamed_event_frames: &mut Vec<Vec<u8>>,
    coverage_events: &mut Vec<crucible::ObservableEvent>,
    streamed_event_cursor: &mut u64,
) -> Result<(), CliError> {
    while *streamed_event_cursor < terminal_event_log_len {
        let received = tokio::time::timeout(
            Duration::from_millis(timeout_ms.max(1)),
            control.recv_event(),
        )
        .await
        .map_err(|_| {
            backend_error(format!(
                "terminal event-log drain timed out at cursor {} before retained tail {terminal_event_log_len}",
                *streamed_event_cursor
            ))
        })?
        .map_err(control_client_error)?;
        let Some(frame) = received else {
            return Err(backend_error(format!(
                "terminal event-log stream closed at cursor {} before retained tail {terminal_event_log_len}",
                *streamed_event_cursor
            )));
        };
        if let Some(event) = coverage_event_from_streaming_frame(&frame)? {
            coverage_events.push(event);
        }
        *streamed_event_cursor = frame.next_cursor.next_sequence;
        streamed_event_frames.push(canonical_streaming_event_frame_bytes(&frame));
        streamed_events.push(frame.event.payload.kind);
    }
    Ok(())
}

pub(crate) fn coverage_event_from_streaming_frame(
    frame: &crucible_api::StreamingEventFrame,
) -> Result<Option<crucible::ObservableEvent>, CliError> {
    use crucible_api::OpenSetAttributeValue;

    if frame.event.payload.kind != "crucible.event.coverage" {
        return Ok(None);
    }
    let string = |name: &str| match frame.event.payload.attribute(name) {
        Some(OpenSetAttributeValue::String(value)) => Ok(value.clone()),
        _ => Err(backend_error(format!(
            "coverage event {} has missing or non-string `{name}` attribute",
            frame.event.sequence
        ))),
    };
    let uint = |name: &str| match frame.event.payload.attribute(name) {
        Some(OpenSetAttributeValue::Uint(value)) => Ok(*value),
        _ => Err(backend_error(format!(
            "coverage event {} has missing or non-unsigned `{name}` attribute",
            frame.event.sequence
        ))),
    };
    let node = crucible::NodeId {
        name: string("node")?,
    };
    match string("kind")?.as_str() {
        "basic_block" => {
            let block_len = u32::try_from(uint("block_len")?).map_err(|_| {
                backend_error(format!(
                    "coverage event {} block length exceeds u32",
                    frame.event.sequence
                ))
            })?;
            Ok(Some(crucible::ObservableEvent::coverage_block(
                crucible::Icount {
                    retired: uint("execution_icount")?,
                },
                node,
                uint("guest_pc")?,
                block_len,
            )))
        }
        "named" => Ok(Some(crucible::ObservableEvent::coverage_marker(
            crucible::Icount {
                retired: uint("retired_icount")?,
            },
            node,
            crucible::MarkerId::from_name(string("id")?),
        ))),
        kind => Err(backend_error(format!(
            "coverage event {} has unsupported coverage kind `{kind}`",
            frame.event.sequence
        ))),
    }
}

pub(crate) fn coverage_feedback_from_streamed_events(
    events: Vec<crucible::ObservableEvent>,
) -> Result<crucible::EventLogCoverageFeedback, CliError> {
    if events.is_empty() {
        return Ok(crucible::EventLogCoverageFeedback::from_event_log(&[]));
    }
    let boundary = events
        .iter()
        .map(crucible::ObservableEvent::at)
        .max_by_key(|at| at.ticks)
        .unwrap_or_default();
    let mut event_log = crucible::EventLog::new();
    let append = event_log
        .append_observations_at_boundary(
            events,
            boundary,
            crucible::SchedulerEvaluationBoundaryKind::Quantum,
        )
        .map_err(|error| {
            backend_error(format!(
                "streamed coverage could not rebuild canonical feedback: {error}"
            ))
        })?;
    Ok(crucible::EventLogCoverageFeedback::from_event_log(
        &append.entries,
    ))
}

pub(crate) async fn query_run_terminal_configuration(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<crucible::Configuration, CliError> {
    let response = control
        .send_command(*command_id, SessionCommand::query_snapshot())
        .await
        .map_err(control_client_error)?;
    *command_id = command_id.saturating_add(1);
    match response.result.status {
        CommandResultStatus::Accepted => {
            acknowledged_commands.push(SessionCommandKind::Query);
        }
        CommandResultStatus::Rejected { reason } => {
            return Err(backend_error(format!(
                "terminal configuration snapshot was rejected: {reason:?}"
            )));
        }
    }
    match response.query_result {
        Some(QueryResult::Snapshot(snapshot)) => Ok(snapshot.configuration),
        Some(other) => Err(backend_error(format!(
            "terminal configuration snapshot returned unexpected payload: {other:?}"
        ))),
        None => Err(backend_error(
            "terminal configuration snapshot returned no payload",
        )),
    }
}

pub(crate) fn run_status_from_observation(
    _run_plan: &RunInvocationPlan,
    observation: &RunObservation,
) -> Result<BackendCommandStatus, CliError> {
    if observation.budget_timed_out != (observation.outcome == Some(OutcomeKind::Timeout)) {
        return Err(backend_error(
            "budget observation did not match the session engine terminal outcome",
        ));
    }
    status_from_outcome(observation.outcome)
}

pub(crate) fn status_from_outcome(
    outcome: Option<OutcomeKind>,
) -> Result<BackendCommandStatus, CliError> {
    match outcome {
        Some(OutcomeKind::Passed | OutcomeKind::Stopped) => Ok(BackendCommandStatus::Passed),
        Some(OutcomeKind::Failed) => Ok(BackendCommandStatus::Failed),
        Some(OutcomeKind::Timeout) => Ok(BackendCommandStatus::Timeout),
        Some(OutcomeKind::Crashed) => Ok(BackendCommandStatus::Crashed),
        None => Err(backend_error(
            "session reached a terminal observation without an engine outcome",
        )),
    }
}
