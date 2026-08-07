//! Wire encoding and decoding for debugger-controller RPC operations.

use super::*;

pub(super) fn parse_debug_bool_line(
    line: Option<&str>,
    prefix: &'static str,
) -> Result<bool, ControlClientError> {
    match parse_prefixed_line(line, prefix)? {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(rpc_decode(format!(
            "invalid boolean `{value}` for {prefix}"
        ))),
    }
}

pub(super) fn encode_debug_controller_acquire_request(
    session: SessionRef,
    holder: uuid::Uuid,
) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/debug-controller-acquire-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "holder", &holder.to_string());
    output.into_bytes()
}

pub(super) fn encode_debug_controller_release_request(
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/debug-controller-release-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    output.into_bytes()
}

pub(super) fn encode_debug_relay_open_request(
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/debug-relay-open-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    output.into_bytes()
}

pub(super) fn encode_debug_goto_request(
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
    target: &crucible::DebugCoordinate,
) -> Result<Vec<u8>, ControlClientError> {
    let coordinate = match target {
        crucible::DebugCoordinate::VirtualTime(time) => format!("virtual-time:{}", time.ticks),
        crucible::DebugCoordinate::NodeIcount { node, icount } => format!(
            "node-icount:{}:{}",
            hex_encode(node.name.as_bytes()),
            icount.retired
        ),
        crucible::DebugCoordinate::Configuration(_)
        | crucible::DebugCoordinate::Checkpoint(_)
        | crucible::DebugCoordinate::EventSequence(_) => {
            return Err(rpc_decode(
                "unary remote goto accepts virtual-time or node-icount coordinates",
            ));
        }
    };
    let mut output = String::from("crucible.rpc/debug-goto-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    push_line(&mut output, "coordinate", &coordinate);
    Ok(output.into_bytes())
}

pub(super) fn encode_debug_reverse_step_request(
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
    grain: crucible::DebugReverseStepGrain,
) -> Vec<u8> {
    let grain = match grain {
        crucible::DebugReverseStepGrain::Instruction => "instruction",
        crucible::DebugReverseStepGrain::Quantum => "quantum",
        crucible::DebugReverseStepGrain::Event => "event",
        crucible::DebugReverseStepGrain::Assertion => "assertion",
        crucible::DebugReverseStepGrain::Timer => "timer",
    };
    let mut output = String::from("crucible.rpc/debug-reverse-step-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    push_line(&mut output, "grain", grain);
    output.into_bytes()
}

pub(super) fn encode_debug_reverse_continue_request(
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
    condition: &crucible::Predicate,
) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/debug-reverse-continue-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    push_line(
        &mut output,
        "condition",
        &hex_encode(&condition.to_compact_binary()),
    );
    output.into_bytes()
}

pub(super) fn decode_debug_reposition_response(
    body: &[u8],
    header: &'static str,
) -> Result<Option<crate::DebugRepositionResult>, ControlClientError> {
    let text = response_text(body)?;
    let mut lines = text.lines();
    expect_header(lines.next(), header)?;
    let target = parse_prefixed_line(lines.next(), "target-configuration=")?;
    let target = (!target.is_empty()).then(|| target.to_owned());
    let event = parse_prefixed_line(lines.next(), "event-sequence=")?;
    let event = if event == "none" {
        None
    } else {
        Some(
            event
                .parse::<u64>()
                .map_err(|error| rpc_decode(format!("invalid event sequence: {error}")))?,
        )
    };
    let Some(configuration) = target else {
        reject_trailing(lines.next())?;
        return Ok(None);
    };
    let requested_coordinate =
        parse_prefixed_line(lines.next(), "requested-coordinate=")?.to_owned();
    let runtime_state = parse_prefixed_line(lines.next(), "runtime-state=")?.to_owned();
    let virtual_time_ticks = parse_u64_response_line(
        parse_prefixed_line(lines.next(), "virtual-time-ticks=")?,
        "virtual time ticks",
    )?;
    let schedule_prefix_len = parse_prefixed_line(lines.next(), "schedule-prefix-len=")?
        .parse::<usize>()
        .map_err(|error| rpc_decode(format!("invalid schedule prefix length: {error}")))?;
    let event_log_prefix = parse_prefixed_line(lines.next(), "event-log-prefix=")?.to_owned();
    let event_log_bytes = parse_u64_response_line(
        parse_prefixed_line(lines.next(), "event-log-bytes=")?,
        "event-log byte offset",
    )?;
    let event_log_events = parse_u64_response_line(
        parse_prefixed_line(lines.next(), "event-log-events=")?,
        "event-log event count",
    )?;
    let node_count = parse_prefixed_line(lines.next(), "node-icount-count=")?
        .parse::<usize>()
        .map_err(|error| rpc_decode(format!("invalid node icount count: {error}")))?;
    let mut node_icounts = BTreeMap::new();
    for index in 0..node_count {
        let encoded_name =
            parse_dynamic_prefixed_line(lines.next(), &format!("node-icount-{index}-name="))?;
        let name = parse_hex_string(encoded_name)?;
        let retired = parse_u64_response_line(
            parse_dynamic_prefixed_line(lines.next(), &format!("node-icount-{index}-retired="))?,
            "node retired instruction count",
        )?;
        if node_icounts.insert(name.clone(), retired).is_some() {
            return Err(rpc_decode(format!(
                "debug reposition response repeated node `{name}`"
            )));
        }
    }
    let gateway_generation = parse_u64_response_line(
        parse_prefixed_line(lines.next(), "gateway-generation=")?,
        "gateway generation",
    )?;
    if gateway_generation == 0 {
        return Err(rpc_decode(
            "debug reposition response reported zero gateway generation",
        ));
    }
    let retired_world_cleanup =
        parse_prefixed_line(lines.next(), "retired-world-cleanup=")?.to_owned();
    if !matches!(
        retired_world_cleanup.as_str(),
        "reaped" | "detached-cleanup-pending"
    ) {
        return Err(rpc_decode(format!(
            "invalid retired-world cleanup state `{retired_world_cleanup}`"
        )));
    }
    reject_trailing(lines.next())?;
    Ok(Some(crate::DebugRepositionResult {
        landed: crate::DebugLandedRuntimeCoordinate {
            requested_coordinate,
            configuration,
            runtime_state,
            virtual_time_ticks,
            schedule_prefix_len,
            event_log_prefix,
            event_log_bytes,
            event_log_events,
            node_icounts,
            gateway_generation,
            retired_world_cleanup,
        },
        target_event_sequence: event,
    }))
}

pub(super) fn parse_u64_response_line(
    value: &str,
    field: &'static str,
) -> Result<u64, ControlClientError> {
    value
        .parse::<u64>()
        .map_err(|error| rpc_decode(format!("invalid {field}: {error}")))
}

pub(super) fn parse_dynamic_prefixed_line<'a>(
    line: Option<&'a str>,
    prefix: &str,
) -> Result<&'a str, ControlClientError> {
    let line = line.ok_or_else(|| rpc_decode(format!("missing `{prefix}` line")))?;
    line.strip_prefix(prefix)
        .ok_or_else(|| rpc_decode(format!("expected `{prefix}` line, got `{line}`")))
}

pub(super) fn encode_debug_attach_request(
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
    node: &NodeId,
) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/debug-attach-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    push_line(&mut output, "node", &hex_encode(node.name.as_bytes()));
    output.into_bytes()
}

pub(super) fn encode_debug_relay_request(
    header: &'static str,
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
    relay_tail: Option<(crate::DebugRelayId, &'static str, String)>,
) -> Vec<u8> {
    let mut output = String::new();
    output.push_str(header);
    output.push('\n');
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    if let Some((relay, field, value)) = relay_tail {
        push_line(&mut output, "relay-id", &relay.0.to_string());
        if field != "close" {
            push_line(&mut output, field, &value);
        }
    }
    output.into_bytes()
}

pub(super) fn encode_debug_guest_exchange_request(
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
    node: &NodeId,
    channel_id: u64,
    record: Option<&crucible_protocol::guest_introspection::GuestIntrospectionRecord>,
) -> Result<Vec<u8>, ControlClientError> {
    let mut output = String::from("crucible.rpc/debug-guest-exchange-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    push_line(&mut output, "node", &hex_encode(node.name.as_bytes()));
    push_line(&mut output, "channel-id", &channel_id.to_string());
    let encoded = match record {
        Some(record) => hex_encode(
            &record
                .encode()
                .map_err(|error| rpc_decode(error.to_string()))?,
        ),
        None => String::new(),
    };
    push_line(&mut output, "record", &encoded);
    Ok(output.into_bytes())
}

pub(super) fn encode_debug_guest_fork_request(
    session: SessionRef,
    generation: u64,
    holder: uuid::Uuid,
    node: &NodeId,
) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/debug-guest-fork-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "holder", &holder.to_string());
    push_line(&mut output, "node", &hex_encode(node.name.as_bytes()));
    output.into_bytes()
}
