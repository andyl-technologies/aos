//! Canonical lifecycle RPC responses and streaming frames.
//!
//! Request handlers own transport policy; this module serializes their typed
//! results into the frozen text wire model and drives attached event streams.
//! A create-session response has this shape:
//!
//! ```text
//! crucible.rpc/create-session-response
//! session-id=42
//! epoch=3
//! seed=<64 lowercase hexadecimal digits>
//! state=paused
//! ```

use super::*;

pub(super) fn encode_list_scenarios_response(response: &ListScenariosResponse) -> String {
    let mut output = String::from("crucible.rpc/list-scenarios-response\n");
    for scenario in &response.scenarios {
        output.push_str("scenario=");
        output.push_str(&scenario.name);
        output.push('|');
        output.push_str(&scenario.description);
        output.push('|');
        output.push_str(&scenario.source_id);
        output.push('\n');
    }
    output
}

pub(super) fn encode_create_session_response(response: &CreateSessionResponse) -> String {
    let mut output = String::from("crucible.rpc/create-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(&mut output, "state", state_wire_name(response.state));
    output
}

pub(super) fn encode_resume_session_response(response: &ResumeSessionResponse) -> String {
    let mut output = String::from("crucible.rpc/resume-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(&mut output, "state", state_wire_name(response.state));
    push_wire_line(&mut output, "checkpoint", &response.checkpoint.to_hex());
    push_wire_line(
        &mut output,
        "configuration",
        &response.configuration.to_hex(),
    );
    output
}

pub(super) fn encode_list_sessions_response(response: &ListSessionsResponse) -> String {
    let mut output = String::from("crucible.rpc/list-sessions-response\n");
    for session in &response.sessions {
        output.push_str("session=");
        output.push_str(&session.session.id.value.to_string());
        output.push('|');
        output.push_str(&session.session.epoch.to_string());
        output.push('|');
        output.push_str(&session.session.seed.to_hex());
        output.push('|');
        output.push_str(state_wire_name(session.state));
        output.push('|');
        output.push_str(&session.event_log_len.to_string());
        output.push('|');
        output.push_str(&session.frontier.ticks.to_string());
        output.push('|');
        output.push_str(&session.quanta_stepped.to_string());
        output.push('|');
        output.push_str(outcome_wire_name(session.outcome));
        output.push('|');
        output.push_str(&content_hash_option_wire(session.terminal_savepoint));
        output.push('\n');
    }
    output
}

pub(super) fn encode_destroy_session_response(response: &DestroySessionResponse) -> String {
    let mut output = String::from("crucible.rpc/destroy-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(
        &mut output,
        "already-absent",
        if response.already_absent {
            "true"
        } else {
            "false"
        },
    );
    push_wire_line(
        &mut output,
        "stopped",
        if response.stopped { "true" } else { "false" },
    );
    output
}

pub(super) fn encode_get_reproduction_response(response: &GetReproductionResponse) -> String {
    let mut output = String::from("crucible.rpc/get-reproduction-response\n");
    push_session_ref(&mut output, response.session);
    for command in &response.commands {
        push_wire_line(&mut output, "command", &reproduction_record_wire(command));
    }
    output
}

pub(super) fn encode_attached_response(attached: &Attached) -> String {
    let mut output = String::from("crucible.rpc/attached-response\n");
    push_session_ref(&mut output, attached.session);
    push_wire_line(
        &mut output,
        "event-log-len",
        &attached.event_log_len.to_string(),
    );
    push_wire_line(&mut output, "state", state_wire_name(attached.state));
    push_wire_line(
        &mut output,
        "version",
        &format!(
            "{}.{}.{}+{}",
            attached.version.major,
            attached.version.minor,
            attached.version.patch,
            attached.version.build
        ),
    );
    let commands = attached
        .capabilities
        .commands
        .iter()
        .map(|capability| {
            open_set_command_kind(capability.command_kind)
                .unwrap_or_else(|| format!("crucible.cmd.{}", capability.command_name))
        })
        .collect::<Vec<_>>()
        .join(",");
    push_wire_line(&mut output, "commands", &commands);
    push_wire_line(&mut output, "snapshot", &snapshot_wire(attached));
    let reproduction = attached
        .snapshot
        .as_ref()
        .map(|snapshot| reproduction_records_wire(&snapshot.reproduction))
        .unwrap_or_else(|| String::from("none"));
    push_wire_line(&mut output, "reproduction", &reproduction);
    output
}

pub(super) fn encode_send_response(response: &SendResponse) -> String {
    let mut output = String::from("crucible.rpc/send-response\n");
    push_wire_line(
        &mut output,
        "command-id",
        &response.result.command_id.to_string(),
    );
    push_wire_line(
        &mut output,
        "command",
        &command_name(response.result.command_kind),
    );
    push_wire_line(
        &mut output,
        "status",
        &command_status_wire(response.result.status),
    );
    match response.state_update {
        Some(update) => push_wire_line(&mut output, "state-update", &state_update_wire(update)),
        None => push_wire_line(&mut output, "state-update", "none"),
    }
    push_wire_line(
        &mut output,
        "query-result",
        &query_result_wire(response.query_result.as_ref()),
    );
    push_wire_line(
        &mut output,
        "breakpoint-id",
        &breakpoint_id_wire(response.breakpoint_id),
    );
    push_wire_line(
        &mut output,
        "savepoint-info",
        &savepoint_info_wire(response.savepoint_info.as_ref()),
    );
    output
}

pub(super) fn breakpoint_firings_wire(firings: &[crucible_session::BreakpointFiring]) -> String {
    let mut output = format!("breakpoint-firings|{}", firings.len());
    for firing in firings {
        output.push('|');
        output.push_str(&firing.sequence.to_string());
        output.push('|');
        output.push_str(&firing.id.to_string());
        output.push('|');
        output.push_str(&firing.frontier.ticks.to_string());
        output.push('|');
        output.push_str(&firing.quanta.to_string());
        output.push('|');
        output.push_str(&hex_encode(&firing.predicate.to_compact_binary()));
        output.push('|');
        output.push_str(&breakpoint_disposition_wire(&firing.disposition));
        output.push('|');
        output.push_str(&firing.scheduler_controls.len().to_string());
        for control in &firing.scheduler_controls {
            output.push('|');
            output.push_str(&hex_encode(&control.to_compact_binary()));
        }
    }
    output
}

pub(super) fn breakpoint_disposition_wire(disposition: &BreakpointDisposition) -> String {
    match disposition {
        BreakpointDisposition::Suspend => String::from("suspend"),
        BreakpointDisposition::Trace => String::from("trace"),
        BreakpointDisposition::Action(action) => {
            format!("action:{}", hex_encode(&action.to_compact_binary()))
        }
    }
}

pub(super) fn breakpoint_id_wire(id: Option<crucible_session::BreakpointId>) -> String {
    id.map(|id| id.to_string())
        .unwrap_or_else(|| String::from("none"))
}

pub(super) fn savepoint_info_wire(info: Option<&crucible_session::SavepointInfo>) -> String {
    match info {
        Some(info) => format!(
            "savepoint|{}|{}|{}",
            hex_encode(info.label.as_bytes()),
            info.configuration.to_hex(),
            hex_encode(&info.checkpoint.to_compact_binary())
        ),
        None => String::from("none"),
    }
}

pub(super) fn snapshot_engine_state_wire(state: &EngineState) -> String {
    match state {
        EngineState::Loaded => String::from("loaded"),
        EngineState::Running => String::from("running"),
        EngineState::Paused { reason } => format!("paused:{}", pause_reason_wire(reason)),
        EngineState::Stopped { outcome } => format!("stopped:{}", snapshot_outcome_wire(outcome)),
    }
}

pub(super) fn pause_reason_wire(reason: &PauseReason) -> String {
    match reason {
        PauseReason::Instantiated => String::from("instantiated"),
        PauseReason::UserRequested => String::from("user-requested"),
        PauseReason::Breakpoint { id } => format!("breakpoint:{id}"),
        PauseReason::StepComplete { mode } => format!("step:{}", step_mode_wire(*mode)),
    }
}

pub(super) fn step_mode_wire(mode: StepMode) -> String {
    match mode {
        StepMode::Quantum => String::from("quantum"),
        StepMode::Event => String::from("event"),
        StepMode::Assertion => String::from("assertion"),
        StepMode::Timer => String::from("timer"),
        StepMode::Duration(duration) => format!("duration:{}", duration.nanos),
    }
}

pub(super) fn snapshot_outcome_wire(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Passed => String::from("passed"),
        Outcome::Failed { violations } => {
            let violations = violations
                .iter()
                .map(|violation| hex_encode(violation.as_bytes()))
                .collect::<Vec<_>>()
                .join(",");
            format!("failed:{violations}")
        }
        Outcome::Timeout => String::from("timeout"),
        Outcome::Crashed { detail } => format!("crashed:{}", hex_encode(detail.as_bytes())),
        Outcome::Stopped => String::from("stopped"),
    }
}

pub(super) fn control_event_body(
    control: ControlStream,
    shutdown: watch::Receiver<bool>,
) -> impl futures_util::Stream<Item = Result<Bytes, Infallible>> {
    let attached = framed_rpc_message(encode_attached_response(control.attached()));
    stream::unfold(
        (control, shutdown, Some(attached)),
        |(mut control, mut shutdown, pending)| async move {
            if let Some(message) = pending {
                return Some((Ok(message), (control, shutdown, None)));
            }
            if *shutdown.borrow() {
                return None;
            }
            // crucible-lint: allow unordered-select -- stream delivery may race with shutdown without affecting engine state.
            let frame = tokio::select! {
                frame = control.recv_frame() => match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => return None,
                },
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        return None;
                    }
                    return None;
                }
            };
            Some((
                Ok(framed_rpc_message(encode_streaming_frame(&frame))),
                (control, shutdown, None),
            ))
        },
    )
}

pub(super) fn watch_event_body(
    watch: WatchStream,
    shutdown: watch::Receiver<bool>,
) -> impl futures_util::Stream<Item = Result<Bytes, Infallible>> {
    let attached = framed_rpc_message(encode_attached_response(watch.attached()));
    stream::unfold(
        (watch, shutdown, Some(attached)),
        |(mut watch, mut shutdown, pending)| async move {
            if let Some(message) = pending {
                return Some((Ok(message), (watch, shutdown, None)));
            }
            if *shutdown.borrow() {
                return None;
            }
            // crucible-lint: allow unordered-select -- watch delivery may race with shutdown without affecting engine state.
            let frame = tokio::select! {
                frame = watch.recv_frame() => match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => return None,
                },
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        return None;
                    }
                    return None;
                }
            };
            Some((
                Ok(framed_rpc_message(encode_streaming_frame(&frame))),
                (watch, shutdown, None),
            ))
        },
    )
}

pub(super) fn encode_streaming_frame(frame: &StreamingFrame) -> String {
    match frame {
        StreamingFrame::Event(frame) => encode_streaming_event_frame(frame),
        StreamingFrame::StateUpdate(frame) => encode_streaming_state_update_frame(*frame),
    }
}

pub(super) fn encode_streaming_event_frame(frame: &StreamingEventFrame) -> String {
    let mut output = String::from("crucible.rpc/event-frame\n");
    push_wire_line(&mut output, "generation", &frame.generation.to_string());
    push_wire_line(
        &mut output,
        "cursor",
        &frame.cursor.next_sequence.to_string(),
    );
    push_wire_line(
        &mut output,
        "next-cursor",
        &frame.next_cursor.next_sequence.to_string(),
    );
    push_wire_line(&mut output, "sequence", &frame.event.sequence.to_string());
    push_wire_line(
        &mut output,
        "virtual-time-ticks",
        &frame.event.at.virtual_time_ticks.to_string(),
    );
    push_wire_line(
        &mut output,
        "icount-retired",
        &frame.event.at.icount_retired.to_string(),
    );
    push_wire_line(
        &mut output,
        "icount-node",
        &optional_string_wire(frame.event.at.icount_node.as_deref()),
    );
    push_wire_line(
        &mut output,
        "source",
        &event_source_wire(&frame.event.source),
    );
    push_wire_line(&mut output, "level", event_level_wire(frame.event.level));
    push_wire_line(
        &mut output,
        "observational",
        if frame.event.observational {
            "true"
        } else {
            "false"
        },
    );
    push_wire_line(&mut output, "kind", &frame.event.payload.kind);
    for (name, value) in &frame.event.payload.attributes {
        push_wire_line(
            &mut output,
            "attribute",
            &format!("{}|{}", hex_encode(name.as_bytes()), attribute_wire(value)),
        );
    }
    output
}

pub(super) fn encode_streaming_state_update_frame(frame: StreamingStateUpdateFrame) -> String {
    let mut output = String::from("crucible.rpc/state-update-frame\n");
    push_wire_line(&mut output, "sequence", &frame.sequence.to_string());
    push_wire_line(
        &mut output,
        "state-update",
        &state_update_wire(frame.update),
    );
    output
}
