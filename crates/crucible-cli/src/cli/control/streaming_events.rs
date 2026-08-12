//! Terminal event-stream draining and canonical coverage reconstruction.

use super::*;
use crucible_session::{EngineState, Outcome};

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
            streamed_events.push(streaming_event_summary(&frame));
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
        streamed_events.push(streaming_event_summary(&frame));
    }
    Ok(())
}

fn streaming_event_summary(frame: &crucible_api::StreamingEventFrame) -> String {
    use crucible_api::{OpenSetAttributeValue, OpenSetEventSource};

    const DIAGNOSTIC_ATTRIBUTES: &[&str] = &[
        "action",
        "assertion",
        "at",
        "boundary",
        "cause",
        "condition",
        "consumer",
        "description",
        "disposition",
        "distance",
        "event",
        "fault",
        "fired",
        "flavor",
        "from_state",
        "id",
        "kind",
        "location",
        "marker",
        "marker_kind",
        "message",
        "must_hit",
        "name",
        "new_state",
        "node",
        "outcome",
        "policy",
        "predicate",
        "producer",
        "quantifier",
        "ready_point",
        "reason",
        "retired_icount",
        "sequence",
        "state",
        "summary",
        "tag",
        "targets",
        "to_state",
        "virtual_time",
    ];

    let mut summary = frame.event.payload.kind.clone();
    summary.push_str(" sequence=");
    summary.push_str(&frame.event.sequence.to_string());
    summary.push_str(" virtual_time=");
    summary.push_str(&frame.event.at.virtual_time_ticks.to_string());
    summary.push_str(" icount=");
    summary.push_str(&frame.event.at.icount_retired.to_string());
    if let Some(node) = &frame.event.at.icount_node {
        summary.push_str(" icount_node=");
        summary.push_str(&escape_event_summary_field(node));
    }
    summary.push_str(" source=");
    let (source, source_detail) = match &frame.event.source {
        OpenSetEventSource::Scenario { event } => ("scenario", Some(event.as_str())),
        OpenSetEventSource::Engine => ("engine", None),
        OpenSetEventSource::Node { node } => ("node", Some(node.as_str())),
        OpenSetEventSource::Guest { node } => ("guest", Some(node.as_str())),
        OpenSetEventSource::Command { command_id } => {
            summary.push_str("command:");
            summary.push_str(&command_id.to_string());
            ("", None)
        }
    };
    summary.push_str(source);
    if let Some(detail) = source_detail {
        summary.push(':');
        summary.push_str(&escape_event_summary_field(detail));
    }
    summary.push_str(if frame.event.observational {
        " class=observational"
    } else {
        " class=causal"
    });
    for name in DIAGNOSTIC_ATTRIBUTES {
        let Some(value) = frame.event.payload.attribute(name) else {
            continue;
        };
        let value = match value {
            OpenSetAttributeValue::Bool(value) => value.to_string(),
            OpenSetAttributeValue::Int(value) => value.to_string(),
            OpenSetAttributeValue::Uint(value) => value.to_string(),
            OpenSetAttributeValue::Uint128(value) => value.to_string(),
            OpenSetAttributeValue::Float64Bits(value) => format!("bits:{value}"),
            OpenSetAttributeValue::String(value) => escape_event_summary_field(value),
            OpenSetAttributeValue::Bytes(value) => format!("<{} bytes>", value.len()),
        };
        summary.push(' ');
        summary.push_str(name);
        summary.push('=');
        summary.push_str(&value);
    }
    if let Some(OpenSetAttributeValue::Bytes(bytes)) = frame.event.payload.attribute("bytes") {
        summary.push_str(" bytes_len=");
        summary.push_str(&bytes.len().to_string());
        summary.push_str(" bytes_content=redacted");
    }
    summary
}

fn escape_event_summary_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace(' ', "\\s")
        .replace('=', "\\=")
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
        Some(QueryResult::Snapshot(snapshot)) => {
            if let EngineState::Stopped {
                outcome: Outcome::Crashed { detail },
            } = &snapshot.state
            {
                eprintln!("crucible: terminal backend crash: {detail}");
            }
            Ok(snapshot.configuration)
        }
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

#[cfg(test)]
mod summary_tests {
    use super::*;

    #[test]
    fn assertion_summary_preserves_agent_diagnostic_fields() {
        let frame = crucible_api::StreamingEventFrame {
            generation: 0,
            cursor: crucible_api::EventLogCursor::new(3),
            next_cursor: crucible_api::EventLogCursor::new(4),
            event: crucible_api::OpenSetEventEnvelope {
                sequence: 3,
                at: crucible_api::OpenSetEventTime {
                    virtual_time_ticks: 40,
                    icount_retired: 40,
                    icount_node: None,
                },
                source: crucible_api::OpenSetEventSource::Engine,
                level: crucible::EventLevel::Info,
                observational: false,
                payload: crucible_api::OpenSetPayload::new(
                    "crucible.event.assertion_state_changed",
                    [
                        (
                            String::from("id"),
                            crucible_api::OpenSetAttributeValue::String(String::from(
                                "suspect-must-crash",
                            )),
                        ),
                        (
                            String::from("new_state"),
                            crucible_api::OpenSetAttributeValue::String(String::from("Violated")),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        };

        assert_eq!(
            streaming_event_summary(&frame),
            "crucible.event.assertion_state_changed sequence=3 virtual_time=40 icount=40 source=engine class=causal id=suspect-must-crash new_state=Violated"
        );
    }

    #[test]
    fn effect_summary_preserves_coordinate_source_and_effect_fields() {
        let frame = crucible_api::StreamingEventFrame {
            generation: 0,
            cursor: crucible_api::EventLogCursor::new(7),
            next_cursor: crucible_api::EventLogCursor::new(8),
            event: crucible_api::OpenSetEventEnvelope {
                sequence: 7,
                at: crucible_api::OpenSetEventTime {
                    virtual_time_ticks: 91,
                    icount_retired: 27,
                    icount_node: Some(String::from("server")),
                },
                source: crucible_api::OpenSetEventSource::Scenario {
                    event: String::from("partition-server"),
                },
                level: crucible::EventLevel::Info,
                observational: false,
                payload: crucible_api::OpenSetPayload::new(
                    "crucible.event.effect_applied",
                    [
                        (
                            String::from("description"),
                            crucible_api::OpenSetAttributeValue::String(String::from(
                                "partition client to server",
                            )),
                        ),
                        (
                            String::from("kind"),
                            crucible_api::OpenSetAttributeValue::String(String::from("partition")),
                        ),
                        (
                            String::from("tag"),
                            crucible_api::OpenSetAttributeValue::String(String::from(
                                "network-cut",
                            )),
                        ),
                        (
                            String::from("targets"),
                            crucible_api::OpenSetAttributeValue::String(String::from(
                                "client,server",
                            )),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        };

        assert_eq!(
            streaming_event_summary(&frame),
            "crucible.event.effect_applied sequence=7 virtual_time=91 icount=27 icount_node=server source=scenario:partition-server class=causal description=partition\\sclient\\sto\\sserver kind=partition tag=network-cut targets=client,server"
        );
    }

    #[test]
    fn console_summary_redacts_guest_bytes() {
        let secret = b"token=super-secret".to_vec();
        let frame = crucible_api::StreamingEventFrame {
            generation: 0,
            cursor: crucible_api::EventLogCursor::new(1),
            next_cursor: crucible_api::EventLogCursor::new(2),
            event: crucible_api::OpenSetEventEnvelope {
                sequence: 1,
                at: crucible_api::OpenSetEventTime {
                    virtual_time_ticks: 1,
                    icount_retired: 1,
                    icount_node: Some(String::from("suspect")),
                },
                source: crucible_api::OpenSetEventSource::Node {
                    node: String::from("suspect"),
                },
                level: crucible::EventLevel::Info,
                observational: true,
                payload: crucible_api::OpenSetPayload::new(
                    "crucible.event.console_output",
                    [(
                        String::from("bytes"),
                        crucible_api::OpenSetAttributeValue::Bytes(secret),
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
        };

        let summary = streaming_event_summary(&frame);
        assert_eq!(
            summary,
            "crucible.event.console_output sequence=1 virtual_time=1 icount=1 icount_node=suspect source=node:suspect class=observational bytes_len=18 bytes_content=redacted"
        );
        assert!(!summary.contains("super-secret"));
    }
}
