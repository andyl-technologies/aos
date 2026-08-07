//! Authenticated debugger time-travel HTTP/2 routes.
//!
//! These routes keep coordinate resolution, event-log history, restore/replay,
//! and live-runtime replacement behind the session actor boundary. Remote
//! clients submit only operator intent under an exclusive controller lease.

use super::*;

pub(super) async fn handle_debug_goto<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    identity: Option<Extension<DebugTransportIdentity>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match authorized_debug_reposition_body(&state, identity.as_ref(), request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, coordinate) = match parse_debug_goto_request(&body) {
        Ok(parsed) => parsed,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let dispatch = match authorized_reposition_dispatch(
        &state,
        identity.as_ref(),
        session,
        generation,
        holder,
    )
    .await
    {
        Ok(dispatch) => dispatch,
        Err(response) => return response,
    };
    match dispatch.goto(coordinate).await {
        Ok(report) => {
            debug_reposition_response("crucible.rpc/debug-goto-response", Some(&report), None)
        }
        Err(error) => lifecycle_error_response(error),
    }
}

pub(super) async fn handle_debug_reverse_step<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    identity: Option<Extension<DebugTransportIdentity>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match authorized_debug_reposition_body(&state, identity.as_ref(), request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, grain) = match parse_debug_reverse_step_request(&body) {
        Ok(parsed) => parsed,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let dispatch = match authorized_reposition_dispatch(
        &state,
        identity.as_ref(),
        session,
        generation,
        holder,
    )
    .await
    {
        Ok(dispatch) => dispatch,
        Err(response) => return response,
    };
    match dispatch.reverse_step(grain).await {
        Ok(report) => debug_reposition_response(
            "crucible.rpc/debug-reverse-step-response",
            Some(&report.goto),
            report.target_event_sequence,
        ),
        Err(error) => lifecycle_error_response(error),
    }
}

pub(super) async fn handle_debug_reverse_continue<L, F>(
    State(state): State<Http2LifecycleState<L, F>>,
    identity: Option<Extension<DebugTransportIdentity>>,
    request: Request<Body>,
) -> Response
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let body = match authorized_debug_reposition_body(&state, identity.as_ref(), request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (session, generation, holder, condition) = match parse_debug_reverse_continue_request(&body)
    {
        Ok(parsed) => parsed,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let dispatch = match authorized_reposition_dispatch(
        &state,
        identity.as_ref(),
        session,
        generation,
        holder,
    )
    .await
    {
        Ok(dispatch) => dispatch,
        Err(response) => return response,
    };
    match dispatch.reverse_continue(condition).await {
        Ok(report) => {
            let event_sequence = report
                .matched
                .as_ref()
                .map(|matched| matched.event_sequence);
            debug_reposition_response(
                "crucible.rpc/debug-reverse-continue-response",
                report.matched.as_ref().map(|matched| &matched.goto),
                event_sequence,
            )
        }
        Err(error) => lifecycle_error_response(error),
    }
}

async fn authorized_debug_reposition_body<L, F>(
    state: &Http2LifecycleState<L, F>,
    identity: Option<&Extension<DebugTransportIdentity>>,
    request: Request<Body>,
) -> Result<Vec<u8>, Response>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    if state.mode.is_read_only() {
        return Err(read_only_rejection_response("debug-reposition"));
    }
    debug_principal(&state.debug_authorization, identity).map_err(|response| *response)?;
    read_debug_rpc_body(request).await
}

async fn authorized_reposition_dispatch<L, F>(
    state: &Http2LifecycleState<L, F>,
    identity: Option<&Extension<DebugTransportIdentity>>,
    session: SessionRef,
    generation: u64,
    holder: DebugControllerHolderId,
) -> Result<crate::DebugRepositionDispatch, Response>
where
    L: QuantumLoop + Send + 'static,
    F: Fn(&ScenarioDef, Option<&ScenarioDefForm>, Seed) -> Result<L, LifecycleApiError>
        + Send
        + Sync
        + 'static,
{
    let (client, role) =
        debug_principal(&state.debug_authorization, identity).map_err(|response| *response)?;
    let lease = DebugControllerLease { client, generation };
    authorize_debug_holder(state, session, &lease, holder).await?;
    let control_plane = state.control_plane.lock().await;
    for capability in [DebugCapability::Control, DebugCapability::Observe] {
        control_plane
            .authorize_debug_controller_operation(session, &lease, &role, capability)
            .map_err(lifecycle_error_response)?;
    }
    control_plane
        .debug_reposition_dispatch(session)
        .map_err(lifecycle_error_response)
}

fn parse_debug_goto_request(
    body: &[u8],
) -> Result<
    (
        SessionRef,
        u64,
        DebugControllerHolderId,
        crucible::DebugCoordinate,
    ),
    String,
> {
    let text =
        std::str::from_utf8(body).map_err(|error| format!("request is not UTF-8: {error}"))?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-goto-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let coordinate = parse_debug_coordinate(parse_wire_line(lines.next(), "coordinate=")?)?;
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder, coordinate))
}

fn parse_debug_reverse_step_request(
    body: &[u8],
) -> Result<
    (
        SessionRef,
        u64,
        DebugControllerHolderId,
        crucible::DebugReverseStepGrain,
    ),
    String,
> {
    let text =
        std::str::from_utf8(body).map_err(|error| format!("request is not UTF-8: {error}"))?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-reverse-step-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let grain = match parse_wire_line(lines.next(), "grain=")? {
        "instruction" => crucible::DebugReverseStepGrain::Instruction,
        "quantum" => crucible::DebugReverseStepGrain::Quantum,
        "event" => crucible::DebugReverseStepGrain::Event,
        "assertion" => crucible::DebugReverseStepGrain::Assertion,
        "timer" => crucible::DebugReverseStepGrain::Timer,
        value => return Err(format!("invalid reverse-step grain `{value}`")),
    };
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder, grain))
}

fn parse_debug_reverse_continue_request(
    body: &[u8],
) -> Result<
    (
        SessionRef,
        u64,
        DebugControllerHolderId,
        crucible::Condition,
    ),
    String,
> {
    let text =
        std::str::from_utf8(body).map_err(|error| format!("request is not UTF-8: {error}"))?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-reverse-continue-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let encoded = parse_wire_line(lines.next(), "condition=")?;
    let condition = crucible::Predicate::from_compact_binary(&parse_hex_bytes(encoded)?)
        .map_err(|error| format!("invalid reverse-continue condition: {error}"))?;
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder, condition))
}

fn parse_debug_coordinate(value: &str) -> Result<crucible::DebugCoordinate, String> {
    if let Some(ticks) = value.strip_prefix("virtual-time:") {
        return Ok(crucible::DebugCoordinate::virtual_time(
            crucible::VirtualTime {
                ticks: ticks
                    .parse::<u64>()
                    .map_err(|error| format!("invalid virtual-time coordinate: {error}"))?,
            },
        ));
    }
    if let Some(node_icount) = value.strip_prefix("node-icount:") {
        let Some((node, retired)) = node_icount.split_once(':') else {
            return Err(String::from(
                "node-icount coordinate must contain an encoded node and icount",
            ));
        };
        let node = String::from_utf8(parse_hex_bytes(node)?)
            .map_err(|error| format!("debug coordinate node is not UTF-8: {error}"))?;
        if node.is_empty() {
            return Err(String::from("debug coordinate node must not be empty"));
        }
        let retired = retired
            .parse::<u64>()
            .map_err(|error| format!("invalid node-icount coordinate: {error}"))?;
        return Ok(crucible::DebugCoordinate::node_icount(
            crucible::NodeId { name: node },
            crucible::Icount { retired },
        ));
    }
    Err(format!("unsupported debug coordinate `{value}`"))
}

fn debug_reposition_response(
    header: &'static str,
    report: Option<&crucible::DebugGotoReport>,
    event_sequence: Option<u64>,
) -> Response {
    let mut output = String::new();
    output.push_str(header);
    output.push('\n');
    push_wire_line(
        &mut output,
        "target-configuration",
        &report
            .map(|report| report.target_configuration.to_hex())
            .unwrap_or_default(),
    );
    push_wire_line(
        &mut output,
        "event-sequence",
        &event_sequence
            .map(|sequence| sequence.to_string())
            .unwrap_or_else(|| String::from("none")),
    );
    if let Some(report) = report {
        let Some(promotion) = report.live_reposition.as_ref() else {
            return http2_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "debug reposition completed without production gateway evidence",
            );
        };
        push_wire_line(
            &mut output,
            "requested-coordinate",
            &debug_coordinate_text(&report.target_coordinate),
        );
        push_wire_line(
            &mut output,
            "runtime-state",
            &report.runtime.runtime.id.to_hex(),
        );
        push_wire_line(
            &mut output,
            "virtual-time-ticks",
            &report.landed_virtual_time.ticks.to_string(),
        );
        push_wire_line(
            &mut output,
            "schedule-prefix-len",
            &report.landed_schedule_prefix_len.to_string(),
        );
        push_wire_line(
            &mut output,
            "event-log-prefix",
            &report.runtime.runtime.event_log.prefix.to_hex(),
        );
        push_wire_line(
            &mut output,
            "event-log-bytes",
            &report.runtime.runtime.event_log.bytes.to_string(),
        );
        push_wire_line(
            &mut output,
            "event-log-events",
            &report.runtime.runtime.event_log.events.to_string(),
        );
        push_wire_line(
            &mut output,
            "node-icount-count",
            &report.runtime.runtime.node_icounts.len().to_string(),
        );
        for (index, (node, icount)) in report.runtime.runtime.node_icounts.iter().enumerate() {
            push_wire_line(
                &mut output,
                &format!("node-icount-{index}-name"),
                &hex_encode(node.name.as_bytes()),
            );
            push_wire_line(
                &mut output,
                &format!("node-icount-{index}-retired"),
                &icount.retired.to_string(),
            );
        }
        push_wire_line(
            &mut output,
            "gateway-generation",
            &promotion.gateway_generation.to_string(),
        );
        let cleanup = match &promotion.retired_world_cleanup {
            crucible::DebugRetiredWorldCleanup::Reaped => "reaped",
            crucible::DebugRetiredWorldCleanup::DetachedCleanupPending { .. } => {
                "detached-cleanup-pending"
            }
        };
        push_wire_line(&mut output, "retired-world-cleanup", cleanup);
    }
    http2_response(StatusCode::OK, output)
}

fn debug_coordinate_text(coordinate: &crucible::DebugCoordinate) -> String {
    match coordinate {
        crucible::DebugCoordinate::Configuration(configuration) => {
            format!("configuration:{}", configuration.id().to_hex())
        }
        crucible::DebugCoordinate::Checkpoint(checkpoint) => {
            format!("checkpoint:{}", checkpoint.to_hex())
        }
        crucible::DebugCoordinate::EventSequence(sequence) => format!("event:{sequence}"),
        crucible::DebugCoordinate::VirtualTime(time) => {
            format!("virtual-time:{}", time.ticks)
        }
        crucible::DebugCoordinate::NodeIcount { node, icount } => format!(
            "node-icount:{}:{}",
            hex_encode(node.name.as_bytes()),
            icount.retired
        ),
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- parser fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const TEST_SEED: &str = "000000000000000000000000000000000000000000000000000000000000004d";
    const TEST_HOLDER: &str = "00000000-0000-0000-0000-000000000009";

    #[test]
    fn goto_parser_accepts_actor_owned_coordinate_intents() {
        let virtual_time = format!(
            "crucible.rpc/debug-goto-request\nsession-id=7\nepoch=3\nseed={TEST_SEED}\ngeneration=9\nholder={TEST_HOLDER}\ncoordinate=virtual-time:42\n"
        );
        let (_, generation, _, coordinate) =
            parse_debug_goto_request(virtual_time.as_bytes()).expect("virtual time must parse");
        assert_eq!(generation, 9);
        assert_eq!(
            coordinate,
            crucible::DebugCoordinate::virtual_time(crucible::VirtualTime { ticks: 42 })
        );

        let node = hex_encode(b"node-a");
        let node_icount = format!(
            "crucible.rpc/debug-goto-request\nsession-id=7\nepoch=3\nseed={TEST_SEED}\ngeneration=9\nholder={TEST_HOLDER}\ncoordinate=node-icount:{node}:81\n"
        );
        let (_, _, _, coordinate) =
            parse_debug_goto_request(node_icount.as_bytes()).expect("node icount must parse");
        assert_eq!(
            coordinate,
            crucible::DebugCoordinate::node_icount(
                crucible::NodeId {
                    name: String::from("node-a"),
                },
                crucible::Icount { retired: 81 },
            )
        );
    }

    #[test]
    fn reverse_parsers_preserve_closed_grain_and_condition_sets() {
        let step = format!(
            "crucible.rpc/debug-reverse-step-request\nsession-id=7\nepoch=3\nseed={TEST_SEED}\ngeneration=9\nholder={TEST_HOLDER}\ngrain=assertion\n"
        );
        let (_, _, _, grain) =
            parse_debug_reverse_step_request(step.as_bytes()).expect("grain must parse");
        assert_eq!(grain, crucible::DebugReverseStepGrain::Assertion);

        let predicate = crucible::Predicate::quiescent();
        let condition = hex_encode(&predicate.to_compact_binary());
        let request = format!(
            "crucible.rpc/debug-reverse-continue-request\nsession-id=7\nepoch=3\nseed={TEST_SEED}\ngeneration=9\nholder={TEST_HOLDER}\ncondition={condition}\n"
        );
        let (_, _, _, parsed) =
            parse_debug_reverse_continue_request(request.as_bytes()).expect("condition must parse");
        assert_eq!(parsed, predicate);
    }
}
