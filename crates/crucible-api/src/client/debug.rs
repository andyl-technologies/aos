//! Authenticated debugger-controller and byte-relay RPC client operations.

use super::*;

const DEBUG_CONTROLLER_ACQUIRE_RPC_PATH: &str = "/crucible.rpc/debug/controller/acquire";
const DEBUG_CONTROLLER_RELEASE_RPC_PATH: &str = "/crucible.rpc/debug/controller/release";
const DEBUG_ATTACH_RPC_PATH: &str = "/crucible.rpc/debug/attach";
const DEBUG_GOTO_RPC_PATH: &str = "/crucible.rpc/debug/goto";
const DEBUG_REVERSE_STEP_RPC_PATH: &str = "/crucible.rpc/debug/reverse-step";
const DEBUG_REVERSE_CONTINUE_RPC_PATH: &str = "/crucible.rpc/debug/reverse-continue";
const DEBUG_RELAY_OPEN_RPC_PATH: &str = "/crucible.rpc/debug/relay/open";
const DEBUG_RELAY_WRITE_RPC_PATH: &str = "/crucible.rpc/debug/relay/write";
const DEBUG_RELAY_READ_RPC_PATH: &str = "/crucible.rpc/debug/relay/read";
const DEBUG_RELAY_CLOSE_RPC_PATH: &str = "/crucible.rpc/debug/relay/close";
const DEBUG_GUEST_EXCHANGE_RPC_PATH: &str = "/crucible.rpc/debug/guest/exchange";
const DEBUG_GUEST_FORK_RPC_PATH: &str = "/crucible.rpc/debug/guest/fork";

impl RpcControlClient {
    /// Acquires the session's exclusive debugger controller lease.
    ///
    /// The daemon derives client identity and role exclusively from the
    /// authenticated transport; neither is supplied in the request body.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when transport authentication or role
    /// policy rejects the request, another controller owns the lease, the
    /// session reference is stale, or the response is malformed.
    pub async fn acquire_debug_controller(
        &self,
        session: SessionRef,
    ) -> Result<DebugControllerLease, ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_CONTROLLER_ACQUIRE_RPC_PATH,
                encode_debug_session_request(
                    "crucible.rpc/debug-controller-acquire-request",
                    session,
                ),
            )
            .await?;
        decode_debug_controller_acquire_response(&body)
    }

    /// Releases a debugger controller lease using its complete generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the authenticated client does not
    /// own `lease`, its generation is stale, the session is stale, or the
    /// transport rejects the request.
    pub async fn release_debug_controller(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
    ) -> Result<(), ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_CONTROLLER_RELEASE_RPC_PATH,
                encode_debug_controller_release_request(session, lease.generation),
            )
            .await?;
        let text = response_text(&body)?;
        let mut lines = text.lines();
        expect_header(
            lines.next(),
            "crucible.rpc/debug-controller-release-response",
        )?;
        reject_trailing(lines.next())?;
        Ok(())
    }

    /// Attaches a controller-owned session debugger to one scenario node.
    ///
    /// The daemon chooses the private loopback gateway endpoint and does not
    /// disclose it to the remote client.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the lease is stale or foreign, the
    /// role lacks control capability, the node cannot expose a gdbstub, or the
    /// daemon rejects the request.
    pub async fn attach_debugger(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        node: &NodeId,
    ) -> Result<(), ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_ATTACH_RPC_PATH,
                encode_debug_attach_request(session, lease.generation, node),
            )
            .await?;
        let text = response_text(&body)?;
        let mut lines = text.lines();
        expect_header(lines.next(), "crucible.rpc/debug-attach-response")?;
        reject_trailing(lines.next())?;
        Ok(())
    }

    /// Moves an attached debugger to a deterministic temporal coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the lease is stale, the role lacks
    /// control capability, the coordinate is unsupported by the unary wire
    /// format, or actor-owned restore/replay and replacement fail.
    pub async fn debug_goto(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        target: &crucible::DebugCoordinate,
    ) -> Result<crate::DebugRepositionResult, ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_GOTO_RPC_PATH,
                encode_debug_goto_request(session, lease.generation, target)?,
            )
            .await?;
        decode_debug_reposition_response(&body, "crucible.rpc/debug-goto-response")?
            .ok_or_else(|| rpc_decode("debug goto response omitted its landed runtime coordinate"))
    }

    /// Reverse-steps an attached debugger by one deterministic grain.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when authorization, target resolution,
    /// replay validation, or live-runtime replacement fails.
    pub async fn debug_reverse_step(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        grain: crucible::DebugReverseStepGrain,
    ) -> Result<crate::DebugRepositionResult, ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_REVERSE_STEP_RPC_PATH,
                encode_debug_reverse_step_request(session, lease.generation, grain),
            )
            .await?;
        decode_debug_reposition_response(&body, "crucible.rpc/debug-reverse-step-response")?
            .ok_or_else(|| {
                rpc_decode("debug reverse-step response omitted its landed runtime coordinate")
            })
    }

    /// Reverse-continues to the latest prior event prefix matching `condition`.
    ///
    /// A successful `None` result means the checked history contained no match.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when authorization, condition decoding or
    /// evaluation, replay validation, or live-runtime replacement fails.
    pub async fn debug_reverse_continue(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        condition: &crucible::Predicate,
    ) -> Result<Option<crate::DebugRepositionResult>, ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_REVERSE_CONTINUE_RPC_PATH,
                encode_debug_reverse_continue_request(session, lease.generation, condition),
            )
            .await?;
        decode_debug_reposition_response(&body, "crucible.rpc/debug-reverse-continue-response")
    }

    /// Opens a daemon-side connection to the session's stable local GDB gateway.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when `lease` is stale or foreign, the role
    /// lacks control capability, no debugger is attached, or the daemon cannot
    /// connect to the actor-reported loopback endpoint.
    pub async fn open_debug_relay(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
    ) -> Result<crate::DebugRelayId, ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_RELAY_OPEN_RPC_PATH,
                encode_debug_relay_request(
                    "crucible.rpc/debug-relay-open-request",
                    session,
                    lease.generation,
                    None,
                ),
            )
            .await?;
        let text = response_text(&body)?;
        let mut lines = text.lines();
        expect_header(lines.next(), "crucible.rpc/debug-relay-open-response")?;
        let id = crate::DebugRelayId(parse_u64_line(lines.next(), "relay-id=")?);
        reject_trailing(lines.next())?;
        Ok(id)
    }

    /// Writes one bounded byte chunk to an open GDB relay.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the relay or lease is stale, the
    /// chunk exceeds the protocol limit, or transport I/O fails.
    pub async fn write_debug_relay(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        relay: crate::DebugRelayId,
        bytes: &[u8],
    ) -> Result<usize, ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_RELAY_WRITE_RPC_PATH,
                encode_debug_relay_request(
                    "crucible.rpc/debug-relay-write-request",
                    session,
                    lease.generation,
                    Some((relay, "data", hex_encode(bytes))),
                ),
            )
            .await?;
        let text = response_text(&body)?;
        let mut lines = text.lines();
        expect_header(lines.next(), "crucible.rpc/debug-relay-write-response")?;
        let written_u64 = parse_u64_line(lines.next(), "written=")?;
        let written = usize::try_from(written_u64).map_err(|_| {
            rpc_decode(format!(
                "relay write length {written_u64} does not fit usize"
            ))
        })?;
        reject_trailing(lines.next())?;
        Ok(written)
    }

    /// Reads currently available bytes from an open GDB relay without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the relay or lease is stale,
    /// `maximum` is outside the protocol bound, or transport I/O fails.
    pub async fn read_debug_relay(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        relay: crate::DebugRelayId,
        maximum: usize,
    ) -> Result<crate::DebugRelayChunk, ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_RELAY_READ_RPC_PATH,
                encode_debug_relay_request(
                    "crucible.rpc/debug-relay-read-request",
                    session,
                    lease.generation,
                    Some((relay, "maximum", maximum.to_string())),
                ),
            )
            .await?;
        decode_debug_relay_read_response(&body)
    }

    /// Closes an open GDB relay without releasing its controller lease.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the relay or lease is stale or the
    /// transport rejects the request.
    pub async fn close_debug_relay(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        relay: crate::DebugRelayId,
    ) -> Result<(), ControlClientError> {
        let body = self
            .post_rpc_body(
                DEBUG_RELAY_CLOSE_RPC_PATH,
                encode_debug_relay_request(
                    "crucible.rpc/debug-relay-close-request",
                    session,
                    lease.generation,
                    Some((relay, "close", String::new())),
                ),
            )
            .await?;
        let text = response_text(&body)?;
        let mut lines = text.lines();
        expect_header(lines.next(), "crucible.rpc/debug-relay-close-response")?;
        reject_trailing(lines.next())?;
        Ok(())
    }

    /// Exchanges one bounded record with a node's debug guest agent.
    ///
    /// Passing `Some` sends a host request. Passing `None` polls one available
    /// response without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the lease is stale, the authenticated
    /// role lacks shell capability, the session has not been explicitly forked,
    /// or the protocol/backend rejects the record.
    pub async fn exchange_guest_introspection(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        node: &NodeId,
        channel_id: u64,
        request: Option<&crucible_protocol::guest_introspection::GuestIntrospectionRecord>,
    ) -> Result<
        Option<crucible_protocol::guest_introspection::GuestIntrospectionRecord>,
        ControlClientError,
    > {
        let body = self
            .post_rpc_body(
                DEBUG_GUEST_EXCHANGE_RPC_PATH,
                encode_debug_guest_exchange_request(
                    session,
                    lease.generation,
                    node,
                    channel_id,
                    request,
                )?,
            )
            .await?;
        let text = response_text(&body)?;
        let mut lines = text.lines();
        expect_header(lines.next(), "crucible.rpc/debug-guest-exchange-response")?;
        let encoded = parse_prefixed_line(lines.next(), "record=")?;
        let record = if encoded.is_empty() {
            None
        } else {
            Some(
                crucible_protocol::guest_introspection::GuestIntrospectionRecord::decode(
                    &parse_hex_bytes(encoded)?,
                )
                .map_err(|error| rpc_decode(error.to_string()))?,
            )
        };
        reject_trailing(lines.next())?;
        Ok(record)
    }

    /// Forks an attached session for guest exec, PTY, or SSH introspection.
    ///
    /// # Errors
    ///
    /// Returns [`ControlClientError`] when the lease is stale, the role lacks
    /// control/mutate/shell capability, no debugger is attached, or the actor
    /// rejects the non-canonical branch marker.
    pub async fn fork_debug_guest_introspection(
        &self,
        session: SessionRef,
        lease: &DebugControllerLease,
        node: &NodeId,
    ) -> Result<
        crucible_protocol::guest_introspection::GuestIntrospectionFeatures,
        ControlClientError,
    > {
        let body = self
            .post_rpc_body(
                DEBUG_GUEST_FORK_RPC_PATH,
                encode_debug_guest_fork_request(session, lease.generation, node),
            )
            .await?;
        let text = response_text(&body)?;
        let mut lines = text.lines();
        expect_header(lines.next(), "crucible.rpc/debug-guest-fork-response")?;
        let branch = parse_prefixed_line(lines.next(), "branch=")?;
        if branch.len() != 64 || !branch.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(rpc_decode("invalid debug guest fork branch identity"));
        }
        let status = parse_prefixed_line(lines.next(), "status=")?;
        let failure = parse_prefixed_line(lines.next(), "failure=")?;
        let argv_exec = parse_debug_bool_line(lines.next(), "argv-exec=")?;
        let pty = parse_debug_bool_line(lines.next(), "pty=")?;
        let resize = parse_debug_bool_line(lines.next(), "resize=")?;
        let ssh_bridge = parse_debug_bool_line(lines.next(), "ssh-bridge=")?;
        let max_channels = parse_prefixed_line(lines.next(), "max-channels=")?
            .parse::<u16>()
            .map_err(|error| rpc_decode(error.to_string()))?;
        if status == "failed" {
            let failure = String::from_utf8(parse_hex_bytes(failure)?)
                .map_err(|error| rpc_decode(error.to_string()))?;
            reject_trailing(lines.next())?;
            return Err(rpc_decode(format!(
                "non-canonical branch {branch} committed, but guest activation failed: {failure}"
            )));
        }
        if status != "ready" {
            return Err(rpc_decode(format!(
                "invalid debug guest fork status `{status}`"
            )));
        }
        if !failure.is_empty() {
            return Err(rpc_decode("ready debug guest fork carried a failure"));
        }
        if max_channels == 0 {
            return Err(rpc_decode("max-channels must be nonzero"));
        }
        reject_trailing(lines.next())?;
        Ok(
            crucible_protocol::guest_introspection::GuestIntrospectionFeatures::new(
                argv_exec,
                pty,
                resize,
                ssh_bridge,
                max_channels,
            ),
        )
    }
}

#[path = "debug/wire.rs"]
mod wire;

use wire::*;
