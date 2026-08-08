//! Debugger-controller HTTP/2 request decoding.
//!
//! Every controller-owned operation carries both the authenticated lease
//! generation and its acquisition holder. These parsers preserve that pairing
//! before authorization and actor dispatch.

use super::*;

pub(super) fn parse_debug_controller_acquire_request(
    body: &[u8],
) -> Result<(SessionRef, DebugControllerHolderId), String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(
        lines.next(),
        "crucible.rpc/debug-controller-acquire-request",
    )?;
    let session = parse_session_ref(&mut lines)?;
    let holder = parse_debug_holder(lines.next())?;
    reject_extra_line(lines.next())?;
    Ok((session, holder))
}

pub(super) fn parse_debug_controller_release_request(
    body: &[u8],
) -> Result<(SessionRef, u64, DebugControllerHolderId), String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(
        lines.next(),
        "crucible.rpc/debug-controller-release-request",
    )?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder))
}

pub(super) fn parse_debug_attach_request(
    body: &[u8],
) -> Result<(SessionRef, u64, DebugControllerHolderId, NodeId), String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-attach-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let node = parse_hex_string_field(
        Some(parse_wire_line(lines.next(), "node=")?),
        "debug attach node",
    )?;
    if node.is_empty() {
        return Err(String::from("debug attach node must not be empty"));
    }
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder, NodeId { name: node }))
}

pub(super) fn parse_debug_relay_open_request(
    body: &[u8],
) -> Result<(SessionRef, u64, DebugControllerHolderId), String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-relay-open-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder))
}

pub(super) fn parse_debug_holder(line: Option<&str>) -> Result<DebugControllerHolderId, String> {
    parse_wire_line(line, "holder=")?
        .parse()
        .map_err(|error| format!("invalid debug controller holder UUID: {error}"))
}

pub(super) fn parse_debug_relay_write_request(
    body: &[u8],
) -> Result<
    (
        SessionRef,
        u64,
        DebugControllerHolderId,
        DebugRelayId,
        Vec<u8>,
    ),
    String,
> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-relay-write-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let id = DebugRelayId(parse_u64_line(lines.next(), "relay-id=")?);
    let bytes = parse_hex_bytes(parse_wire_line(lines.next(), "data=")?)?;
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder, id, bytes))
}

pub(super) fn parse_debug_relay_read_request(
    body: &[u8],
) -> Result<
    (
        SessionRef,
        u64,
        DebugControllerHolderId,
        DebugRelayId,
        usize,
    ),
    String,
> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-relay-read-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let id = DebugRelayId(parse_u64_line(lines.next(), "relay-id=")?);
    let maximum_u64 = parse_u64_line(lines.next(), "maximum=")?;
    let maximum = usize::try_from(maximum_u64)
        .map_err(|_| format!("debug relay maximum {maximum_u64} does not fit usize"))?;
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder, id, maximum))
}

pub(super) fn parse_debug_relay_close_request(
    body: &[u8],
) -> Result<(SessionRef, u64, DebugControllerHolderId, DebugRelayId), String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-relay-close-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let id = DebugRelayId(parse_u64_line(lines.next(), "relay-id=")?);
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder, id))
}

type DebugGuestExchangeRequest = (
    SessionRef,
    u64,
    DebugControllerHolderId,
    NodeId,
    u64,
    Option<GuestIntrospectionRecord>,
);

pub(super) fn parse_debug_guest_exchange_request(
    body: &[u8],
) -> Result<DebugGuestExchangeRequest, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-guest-exchange-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let node = parse_hex_string_field(
        Some(parse_wire_line(lines.next(), "node=")?),
        "debug guest node",
    )?;
    if node.is_empty() {
        return Err(String::from("debug guest node must not be empty"));
    }
    let channel_id = parse_u64_line(lines.next(), "channel-id=")?;
    if channel_id == 0 {
        return Err(String::from("debug guest channel id must not be zero"));
    }
    let encoded = parse_wire_line(lines.next(), "record=")?;
    let record = if encoded.is_empty() {
        None
    } else {
        Some(
            GuestIntrospectionRecord::decode(&parse_hex_bytes(encoded)?)
                .map_err(|error| error.to_string())?,
        )
    };
    reject_extra_line(lines.next())?;
    Ok((
        session,
        generation,
        holder,
        NodeId { name: node },
        channel_id,
        record,
    ))
}

pub(super) fn parse_debug_guest_fork_request(
    body: &[u8],
) -> Result<(SessionRef, u64, DebugControllerHolderId, NodeId), String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    expect_wire_header(lines.next(), "crucible.rpc/debug-guest-fork-request")?;
    let session = parse_session_ref(&mut lines)?;
    let generation = parse_u64_line(lines.next(), "generation=")?;
    let holder = parse_debug_holder(lines.next())?;
    let node = parse_hex_string_field(
        Some(parse_wire_line(lines.next(), "node=")?),
        "debug guest fork node",
    )?;
    if node.is_empty() {
        return Err(String::from("debug guest fork node must not be empty"));
    }
    reject_extra_line(lines.next())?;
    Ok((session, generation, holder, NodeId { name: node }))
}
