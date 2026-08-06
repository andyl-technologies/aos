//! Authenticated debugger-controller and byte-relay RPC client operations.

use super::*;

const DEBUG_CONTROLLER_ACQUIRE_RPC_PATH: &str = "/crucible.rpc/debug/controller/acquire";
const DEBUG_CONTROLLER_RELEASE_RPC_PATH: &str = "/crucible.rpc/debug/controller/release";
const DEBUG_ATTACH_RPC_PATH: &str = "/crucible.rpc/debug/attach";
const DEBUG_RELAY_OPEN_RPC_PATH: &str = "/crucible.rpc/debug/relay/open";
const DEBUG_RELAY_WRITE_RPC_PATH: &str = "/crucible.rpc/debug/relay/write";
const DEBUG_RELAY_READ_RPC_PATH: &str = "/crucible.rpc/debug/relay/read";
const DEBUG_RELAY_CLOSE_RPC_PATH: &str = "/crucible.rpc/debug/relay/close";

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
}

fn encode_debug_session_request(header: &'static str, session: SessionRef) -> Vec<u8> {
    let mut output = String::new();
    output.push_str(header);
    output.push('\n');
    push_session_ref(&mut output, session);
    output.into_bytes()
}

fn encode_debug_controller_release_request(session: SessionRef, generation: u64) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/debug-controller-release-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    output.into_bytes()
}

fn encode_debug_attach_request(session: SessionRef, generation: u64, node: &NodeId) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/debug-attach-request\n");
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    push_line(&mut output, "node", &hex_encode(node.name.as_bytes()));
    output.into_bytes()
}

fn encode_debug_relay_request(
    header: &'static str,
    session: SessionRef,
    generation: u64,
    relay_tail: Option<(crate::DebugRelayId, &'static str, String)>,
) -> Vec<u8> {
    let mut output = String::new();
    output.push_str(header);
    output.push('\n');
    push_session_ref(&mut output, session);
    push_line(&mut output, "generation", &generation.to_string());
    if let Some((relay, field, value)) = relay_tail {
        push_line(&mut output, "relay-id", &relay.0.to_string());
        if field != "close" {
            push_line(&mut output, field, &value);
        }
    }
    output.into_bytes()
}
