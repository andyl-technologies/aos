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
    let (session, generation, coordinate) = match parse_debug_goto_request(&body) {
        Ok(parsed) => parsed,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let dispatch = match authorized_reposition_dispatch(
        &state,
        identity.as_ref(),
        session,
        generation,
    )
    .await
    {
        Ok(dispatch) => dispatch,
        Err(response) => return response,
    };
    match dispatch.goto(coordinate).await {
        Ok(report) => debug_reposition_response(
            "crucible.rpc/debug-goto-response",
            Some(report.target_configuration),
            None,
        ),
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
    let (session, generation, grain) = match parse_debug_reverse_step_request(&body) {
        Ok(parsed) => parsed,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let dispatch = match authorized_reposition_dispatch(
        &state,
        identity.as_ref(),
        session,
        generation,
    )
    .await
    {
        Ok(dispatch) => dispatch,
        Err(response) => return response,
    };
    match dispatch.reverse_step(grain).await {
        Ok(report) => debug_reposition_response(
            "crucible.rpc/debug-reverse-step-response",
            Some(report.target_configuration),
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
    let (session, generation, condition) = match parse_debug_reverse_continue_request(&body) {
        Ok(parsed) => parsed,
        Err(error) => return http2_response(StatusCode::BAD_REQUEST, error),
    };
    let _operation_guard = debug_operation_guard(&state, session).await;
    let dispatch = match authorized_reposition_dispatch(
        &state,
        identity.as_ref(),
        session,
        generation,
    )
    .await
    {
        Ok(dispatch) => dispatch,
        Err(response) => return response,
    };
    match dispatch.reverse_continue(condition).await {
        Ok(report) => {
            let target = report
                .matched
                .as_ref()
                .map(|matched| matched.target_configuration);
            let event_sequence = report
                .matched
                .as_ref()
                .map(|matched| matched.event_sequence);
            debug_reposition_response(
                "crucible.rpc/debug-reverse-continue-response",
                target,
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
) -> Result<(SessionRef, u64, crucible::DebugCoordinate), String> {
    let text =
        std::str::from_utf8(body).map_err(|error| format!("request is not UTF-8: {error}"))?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-goto-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let coordinate = parse_debug_coordinate(parse_wire_line(lines.next(), "coordinate=")?)?;
    reject_extra_line(lines.next())?;
    Ok((session, generation, coordinate))
}

fn parse_debug_reverse_step_request(
    body: &[u8],
) -> Result<(SessionRef, u64, crucible::DebugReverseStepGrain), String> {
    let text =
        std::str::from_utf8(body).map_err(|error| format!("request is not UTF-8: {error}"))?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-reverse-step-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let grain = match parse_wire_line(lines.next(), "grain=")? {
        "instruction" => crucible::DebugReverseStepGrain::Instruction,
        "quantum" => crucible::DebugReverseStepGrain::Quantum,
        "event" => crucible::DebugReverseStepGrain::Event,
        "assertion" => crucible::DebugReverseStepGrain::Assertion,
        "timer" => crucible::DebugReverseStepGrain::Timer,
        value => return Err(format!("invalid reverse-step grain `{value}`")),
    };
    reject_extra_line(lines.next())?;
    Ok((session, generation, grain))
}

fn parse_debug_reverse_continue_request(
    body: &[u8],
) -> Result<(SessionRef, u64, crucible::Condition), String> {
    let text =
        std::str::from_utf8(body).map_err(|error| format!("request is not UTF-8: {error}"))?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-reverse-continue-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let encoded = parse_wire_line(lines.next(), "condition=")?;
    let condition = crucible::Predicate::from_compact_binary(&parse_hex_bytes(encoded)?)
        .map_err(|error| format!("invalid reverse-continue condition: {error}"))?;
    reject_extra_line(lines.next())?;
    Ok((session, generation, condition))
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
    target: Option<ContentHash>,
    event_sequence: Option<u64>,
) -> Response {
    let mut output = String::new();
    output.push_str(header);
    output.push('\n');
    push_wire_line(
        &mut output,
        "target-configuration",
        &target.map(|target| target.to_hex()).unwrap_or_default(),
    );
    push_wire_line(
        &mut output,
        "event-sequence",
        &event_sequence
            .map(|sequence| sequence.to_string())
            .unwrap_or_else(|| String::from("none")),
    );
    http2_response(StatusCode::OK, output)
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- parser fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const TEST_SEED: &str = "000000000000000000000000000000000000000000000000000000000000004d";

    #[test]
    fn goto_parser_accepts_actor_owned_coordinate_intents() {
        let virtual_time = format!(
            "crucible.rpc/debug-goto-request\nsession-id=7\nepoch=3\nseed={TEST_SEED}\ngeneration=9\ncoordinate=virtual-time:42\n"
        );
        let (_, generation, coordinate) =
            parse_debug_goto_request(virtual_time.as_bytes()).expect("virtual time must parse");
        assert_eq!(generation, 9);
        assert_eq!(
            coordinate,
            crucible::DebugCoordinate::virtual_time(crucible::VirtualTime { ticks: 42 })
        );

        let node = hex_encode(b"node-a");
        let node_icount = format!(
            "crucible.rpc/debug-goto-request\nsession-id=7\nepoch=3\nseed={TEST_SEED}\ngeneration=9\ncoordinate=node-icount:{node}:81\n"
        );
        let (_, _, coordinate) =
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
            "crucible.rpc/debug-reverse-step-request\nsession-id=7\nepoch=3\nseed={TEST_SEED}\ngeneration=9\ngrain=assertion\n"
        );
        let (_, _, grain) =
            parse_debug_reverse_step_request(step.as_bytes()).expect("grain must parse");
        assert_eq!(grain, crucible::DebugReverseStepGrain::Assertion);

        let predicate = crucible::Predicate::quiescent();
        let condition = hex_encode(&predicate.to_compact_binary());
        let request = format!(
            "crucible.rpc/debug-reverse-continue-request\nsession-id=7\nepoch=3\nseed={TEST_SEED}\ngeneration=9\ncondition={condition}\n"
        );
        let (_, _, parsed) =
            parse_debug_reverse_continue_request(request.as_bytes()).expect("condition must parse");
        assert_eq!(parsed, predicate);
    }
}
