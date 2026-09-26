//! Canonical HTTP/2 fixture response encoders.

use super::*;

pub(crate) fn encode_list_scenarios_response(response: &ListScenariosResponse) -> String {
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

pub(crate) fn encode_create_session_response(response: &CreateSessionResponse) -> String {
    let mut output = String::from("crucible.rpc/create-session-response\n");
    push_session_ref(&mut output, response.session);
    push_wire_line(&mut output, "state", state_wire_name(response.state));
    output
}

pub(crate) fn encode_resume_session_response(response: &ResumeSessionResponse) -> String {
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

pub(crate) fn encode_list_sessions_response(response: &ListSessionsResponse) -> String {
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

pub(crate) fn encode_destroy_session_response(response: &DestroySessionResponse) -> String {
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

pub(crate) fn encode_get_reproduction_response(response: &GetReproductionResponse) -> String {
    let mut output = String::from("crucible.rpc/get-reproduction-response\n");
    push_session_ref(&mut output, response.session);
    for command in &response.commands {
        push_wire_line(&mut output, "command", &reproduction_record_wire(command));
    }
    output
}

pub(crate) fn lifecycle_error_response(error: LifecycleApiError) -> axum::response::Response {
    match error {
        LifecycleApiError::EpochMismatch {
            session_id,
            expected,
            actual,
        } => lifecycle_epoch_mismatch_response(session_id, expected, actual),
        LifecycleApiError::ScenarioNotFound { name } => {
            let mut output = String::from("crucible.rpc/error\n");
            push_wire_line(&mut output, "status", "not-found");
            push_wire_line(&mut output, "reason", "scenario-not-found");
            push_wire_line(&mut output, "name", &hex_encode(name.as_bytes()));
            http2_response(axum::http::StatusCode::NOT_FOUND, output)
        }
        LifecycleApiError::SessionNotFound { session } => {
            lifecycle_session_not_found_response(session)
        }
        LifecycleApiError::SessionLimitReached { .. } => typed_rpc_status_response(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            crucible_api::RpcStatusCode::InvalidState,
            "session-limit",
            &error.to_string(),
        ),
        LifecycleApiError::ScenarioSeedMismatch { .. } => typed_rpc_status_response(
            axum::http::StatusCode::BAD_REQUEST,
            crucible_api::RpcStatusCode::InvalidArgument,
            "invalid-argument",
            &error.to_string(),
        ),
        LifecycleApiError::ResumeCheckpoint { .. } => typed_rpc_status_response(
            axum::http::StatusCode::BAD_REQUEST,
            crucible_api::RpcStatusCode::InvalidArgument,
            "invalid-argument",
            &error.to_string(),
        ),
        LifecycleApiError::ResumeReplayClosure { .. } => typed_rpc_status_response(
            axum::http::StatusCode::BAD_REQUEST,
            crucible_api::RpcStatusCode::InvalidArgument,
            "resume-replay-closure",
            &error.to_string(),
        ),
        LifecycleApiError::ResumeObservationSource { .. } => typed_rpc_status_response(
            axum::http::StatusCode::BAD_REQUEST,
            crucible_api::RpcStatusCode::InvalidArgument,
            "resume-observation-source",
            &error.to_string(),
        ),
        LifecycleApiError::DebugAccess { .. }
        | LifecycleApiError::DebugEndpointUnavailable
        | LifecycleApiError::ReadOnlySession { .. } => typed_rpc_status_response(
            axum::http::StatusCode::FORBIDDEN,
            crucible_api::RpcStatusCode::InvalidState,
            "debug-access-denied",
            &error.to_string(),
        ),
        LifecycleApiError::SessionCommandRejected { .. } => typed_rpc_status_response(
            axum::http::StatusCode::CONFLICT,
            crucible_api::RpcStatusCode::InvalidState,
            "session-command-rejected",
            &error.to_string(),
        ),
        LifecycleApiError::RpcAbi { .. }
        | LifecycleApiError::GenesisGraph { .. }
        | LifecycleApiError::ResourceLimit(..)
        | LifecycleApiError::SessionRetention { .. }
        | LifecycleApiError::CommandChannelClosed { .. }
        | LifecycleApiError::StateDidNotAdvance { .. }
        | LifecycleApiError::ActorJoin { .. }
        | LifecycleApiError::ActorFailed { .. }
        | LifecycleApiError::LoopFactory { .. }
        | LifecycleApiError::AttemptOperational { .. } => typed_rpc_status_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            crucible_api::RpcStatusCode::Internal,
            "internal",
            &error.to_string(),
        ),
    }
}

pub(crate) fn streaming_error_response(error: StreamingApiError) -> axum::response::Response {
    match error {
        StreamingApiError::EpochMismatch { expected, actual } => {
            streaming_epoch_mismatch_response(expected, actual)
        }
        StreamingApiError::SessionNotFound { session } => {
            streaming_session_not_found_response(session)
        }
        StreamingApiError::SessionMismatch { .. } => typed_rpc_status_response(
            axum::http::StatusCode::BAD_REQUEST,
            crucible_api::RpcStatusCode::InvalidArgument,
            "invalid-argument",
            &error.to_string(),
        ),
        StreamingApiError::CommandChannelClosed { .. }
        | StreamingApiError::CommandResponseMissing { .. }
        | StreamingApiError::StateDidNotAdvance { .. }
        | StreamingApiError::EventStreamLagged { .. } => typed_rpc_status_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            crucible_api::RpcStatusCode::Internal,
            "internal",
            &error.to_string(),
        ),
    }
}

pub(crate) fn lifecycle_epoch_mismatch_response(
    session_id: SessionId,
    expected: u64,
    actual: u64,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "invalid-state");
    push_wire_line(&mut output, "reason", "epoch-mismatch");
    push_wire_line(&mut output, "session-id", &session_id.value.to_string());
    push_wire_line(&mut output, "expected", &expected.to_string());
    push_wire_line(&mut output, "actual", &actual.to_string());
    http2_response(axum::http::StatusCode::PRECONDITION_FAILED, output)
}

pub(crate) fn lifecycle_session_not_found_response(
    session: SessionRef,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "not-found");
    push_wire_line(&mut output, "reason", "lifecycle-session-not-found");
    push_session_ref(&mut output, session);
    http2_response(axum::http::StatusCode::NOT_FOUND, output)
}

pub(crate) fn streaming_session_not_found_response(
    session: SessionRef,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "not-found");
    push_wire_line(&mut output, "reason", "streaming-session-not-found");
    push_session_ref(&mut output, session);
    http2_response(axum::http::StatusCode::NOT_FOUND, output)
}

pub(crate) fn streaming_epoch_mismatch_response(
    expected: u64,
    actual: u64,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", "invalid-state");
    push_wire_line(&mut output, "reason", "streaming-epoch-mismatch");
    push_wire_line(&mut output, "expected", &expected.to_string());
    push_wire_line(&mut output, "actual", &actual.to_string());
    http2_response(axum::http::StatusCode::PRECONDITION_FAILED, output)
}

pub(crate) fn typed_rpc_status_response(
    http_status: axum::http::StatusCode,
    status: crucible_api::RpcStatusCode,
    reason: &'static str,
    message: &str,
) -> axum::response::Response {
    let mut output = String::from("crucible.rpc/error\n");
    push_wire_line(&mut output, "status", rpc_status_code_wire_name(status));
    push_wire_line(&mut output, "reason", reason);
    push_wire_line(&mut output, "message", &hex_encode(message.as_bytes()));
    http2_response(http_status, output)
}

pub(crate) fn encode_attached_response(attached: &Attached) -> String {
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

pub(crate) fn snapshot_wire(attached: &Attached) -> String {
    let Some(snapshot) = &attached.snapshot else {
        return String::from("none");
    };
    let last = snapshot
        .last_sequence
        .map(|sequence| sequence.to_string())
        .unwrap_or_else(|| String::from("none"));
    format!(
        "{}|{}|{}|{}|{}",
        snapshot.through.next_sequence,
        snapshot.event_count,
        snapshot.causal_event_count,
        snapshot.observational_event_count,
        last,
    )
}

pub(crate) fn reproduction_records_wire(commands: &[ReproductionCommandRecord]) -> String {
    if commands.is_empty() {
        return String::from("none");
    }
    commands
        .iter()
        .map(reproduction_record_wire)
        .collect::<Vec<_>>()
        .join(";")
}

pub(crate) fn reproduction_record_wire(command: &ReproductionCommandRecord) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        command.sequence,
        command_name(command.payload.command),
        command.virtual_time.ticks,
        command.quanta,
        command.at_sequence,
        match command.result {
            ReproductionCommandResult::Accepted => "accepted",
        },
        command.observational_order,
        command.payload.scheduler_batch,
        scheduler_control_wire(command.payload.scheduler_control.as_ref()),
        command_payload_material_wire(&command.payload.command_payload),
    )
}

pub(crate) fn command_payload_material_wire(material: &str) -> String {
    hex_encode(material.as_bytes())
}

pub(crate) fn scheduler_control_wire(control: Option<&String>) -> String {
    control
        .map(|material| hex_encode(material.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

pub(crate) fn encode_send_response(response: &SendResponse) -> String {
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
    push_wire_line(&mut output, "query-result", "none");
    push_wire_line(
        &mut output,
        "breakpoint-id",
        &response
            .breakpoint_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| String::from("none")),
    );
    push_wire_line(&mut output, "savepoint-info", "none");
    output
}

pub(crate) fn command_status_wire(status: CommandResultStatus) -> String {
    match status {
        CommandResultStatus::Accepted => String::from("accepted"),
        CommandResultStatus::Rejected { reason } => {
            format!(
                "rejected:{}",
                rpc_status_code_wire_name(reason.rpc_status())
            )
        }
    }
}
