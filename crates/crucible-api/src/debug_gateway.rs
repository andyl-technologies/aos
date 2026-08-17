//! Apache-side client for the standalone debugger gateway control protocol.
//!
//! The client exchanges versioned owned-byte frames over a Unix socket. It
//! never links the GPL gateway or QEMU and carries no process-private object.
//! A new connection negotiates `Hello`, queries backend status, and can then
//! reconcile idempotent prepare/commit operations after a lost acknowledgement.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use crucible_protocol::debug_gateway::{
    DEBUG_GATEWAY_HEADER_LEN, DEBUG_GATEWAY_MAX_PAYLOAD, DebugGatewayBackendStatus,
    DebugGatewayErrorPayload, DebugGatewayFrame, DebugGatewayMessageKind,
    decode_debug_gateway_frame,
};
use thiserror::Error;

/// Version-1 gateway capability token returned by negotiation.
pub const DEBUG_GATEWAY_V1_CAPABILITY: &[u8] = b"debug-gateway.v1";
/// Default time allowed for a newly spawned gateway to bind and negotiate.
pub const DEBUG_GATEWAY_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Owned debugger gateway child and its negotiated control connection.
pub struct DebugGatewayProcess {
    child: Child,
    client: DebugGatewayControlClient,
    control_socket: std::path::PathBuf,
    operator_listen: Option<SocketAddr>,
    _directory: tempfile::TempDir,
}

impl DebugGatewayProcess {
    /// Spawns a standalone gateway and waits for version negotiation.
    ///
    /// The executable is invoked directly with a private control socket under
    /// an owned temporary directory; no shell or ambient host utility is used.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when the temporary directory cannot
    /// be created, the process cannot be spawned, exits before negotiation, or
    /// does not become ready within [`DEBUG_GATEWAY_STARTUP_TIMEOUT`].
    pub fn launch(executable: impl AsRef<Path>) -> Result<Self, DebugGatewayClientError> {
        Self::launch_internal(executable.as_ref(), DEBUG_GATEWAY_STARTUP_TIMEOUT, None)
    }

    /// Spawns a standalone gateway with an explicit startup bound.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] for the same conditions as
    /// [`Self::launch`] or when child status inspection fails.
    pub fn launch_with_timeout(
        executable: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Self, DebugGatewayClientError> {
        Self::launch_internal(executable.as_ref(), timeout, None)
    }

    /// Spawns a gateway with an explicitly unauthenticated loopback GDB listener.
    ///
    /// This mode is intended only for a trusted local host. Remote and
    /// multi-user access must use the authenticated daemon relay instead.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] for process startup, negotiation, or
    /// listener-status failures.
    pub fn launch_with_trusted_loopback(
        executable: impl AsRef<Path>,
        listen: SocketAddr,
    ) -> Result<Self, DebugGatewayClientError> {
        if !listen.ip().is_loopback() {
            return Err(DebugGatewayClientError::UntrustedOperatorListen(listen));
        }
        Self::launch_internal(
            executable.as_ref(),
            DEBUG_GATEWAY_STARTUP_TIMEOUT,
            Some(listen),
        )
    }

    fn launch_internal(
        executable: &Path,
        timeout: Duration,
        trusted_loopback: Option<SocketAddr>,
    ) -> Result<Self, DebugGatewayClientError> {
        let directory = tempfile::tempdir().map_err(DebugGatewayClientError::CreateDirectory)?;
        let control_socket = directory.path().join("control.sock");
        let mut command = Command::new(executable);
        command.arg("--control-socket").arg(&control_socket);
        if let Some(listen) = trusted_loopback {
            command
                .arg("--allow-unauthenticated-gdb")
                .arg("--gdb-listen")
                .arg(listen.to_string());
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(DebugGatewayClientError::Spawn)?;
        let mut remaining = timeout;
        loop {
            match DebugGatewayControlClient::connect(&control_socket) {
                Ok(mut client) => {
                    let operator_listen = match client.operator_listen() {
                        Ok(operator_listen) => operator_listen,
                        Err(error) => {
                            let _ = terminate_child(&mut child);
                            return Err(error);
                        }
                    };
                    return Ok(Self {
                        child,
                        client,
                        control_socket,
                        operator_listen,
                        _directory: directory,
                    });
                }
                Err(error) => {
                    if let Some(status) = child
                        .try_wait()
                        .map_err(DebugGatewayClientError::InspectChild)?
                    {
                        return Err(DebugGatewayClientError::EarlyExit { status });
                    }
                    if !matches!(
                        &error,
                        DebugGatewayClientError::Connect(source)
                            if matches!(
                                source.kind(),
                                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                            )
                    ) {
                        let _ = terminate_child(&mut child);
                        return Err(error);
                    }
                    if remaining.is_zero() {
                        let _ = terminate_child(&mut child);
                        return Err(DebugGatewayClientError::StartupTimeout {
                            timeout,
                            last_error: Box::new(error),
                        });
                    }
                    let delay = remaining.min(Duration::from_millis(10));
                    std::thread::sleep(delay);
                    remaining = remaining.saturating_sub(delay);
                }
            }
        }
    }

    /// Returns the private control-socket path used by the child.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    /// Returns the stable operator-facing GDB listener bound by the gateway.
    #[must_use]
    pub const fn operator_listen(&self) -> Option<SocketAddr> {
        self.operator_listen
    }

    /// Returns the negotiated control client.
    pub fn client_mut(&mut self) -> &mut DebugGatewayControlClient {
        &mut self.client
    }

    /// Returns the next scheduler-owned RSP run-control request, if one is queued.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when the control exchange fails or
    /// the gateway returns an unexpected response kind.
    pub fn poll_run_control(&mut self) -> Result<Option<Vec<u8>>, DebugGatewayClientError> {
        match self.client.poll_run_control() {
            Ok(request) => Ok(request),
            Err(_) => {
                self.reconnect_control()?;
                self.client.poll_run_control()
            }
        }
    }

    /// Sends a scheduler-produced RSP response to the attached operator.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when the control exchange fails or
    /// no operator connection can receive the response.
    pub fn complete_run_control(&mut self, response: &[u8]) -> Result<(), DebugGatewayClientError> {
        match self.client.complete_run_control(response) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.reconnect_control()?;
                self.client.complete_run_control(response)
            }
        }
    }

    /// Acquires scheduler ownership of the active QEMU backend.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when control transport or backend
    /// breakpoint suspension fails.
    pub fn acquire_scheduler_lease(&mut self) -> Result<(), DebugGatewayClientError> {
        match self.client.acquire_scheduler_lease() {
            Ok(()) => Ok(()),
            Err(_) => {
                self.reconnect_control()?;
                self.client.acquire_scheduler_lease()
            }
        }
    }

    /// Releases scheduler ownership of the active QEMU backend.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when control transport or backend
    /// breakpoint restoration fails.
    pub fn release_scheduler_lease(&mut self) -> Result<(), DebugGatewayClientError> {
        match self.client.release_scheduler_lease() {
            Ok(()) => Ok(()),
            Err(_) => {
                self.reconnect_control()?;
                self.client.release_scheduler_lease()
            }
        }
    }

    /// Reconnects and renegotiates the private control channel.
    ///
    /// The gateway process and any operator-facing GDB connection remain
    /// untouched. Callers use this after an ambiguous control acknowledgement
    /// and reconcile through [`DebugGatewayControlClient::backend_status`].
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when the gateway cannot be reached or
    /// version negotiation fails.
    pub fn reconnect_control(&mut self) -> Result<(), DebugGatewayClientError> {
        let pending_run_control_stream = self.client.pending_run_control_stream;
        self.client.disconnect();
        self.client = DebugGatewayControlClient::connect(&self.control_socket)?;
        self.client.pending_run_control_stream = pending_run_control_stream;
        Ok(())
    }

    /// Prepares and commits one backend with lost-acknowledgement reconciliation.
    ///
    /// A failed prepare or commit may mean the gateway applied the request but
    /// the acknowledgement was lost. This method reconnects, queries backend
    /// status, and accepts only exact endpoint and generation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when promotion is rejected, control
    /// transport cannot be reconciled, or reported state does not prove the
    /// requested transition.
    pub fn promote_backend(&mut self, endpoint: &Path) -> Result<u64, DebugGatewayClientError> {
        let endpoint_text = endpoint
            .to_str()
            .ok_or_else(|| DebugGatewayClientError::InvalidEndpoint(endpoint.to_path_buf()))?;
        let generation = match self.client.prepare_backend(endpoint) {
            Ok(generation) => generation,
            Err(prepare_error) => {
                let reconciled = self
                    .reconnect_control()
                    .and_then(|()| self.client.backend_status());
                if let Some(generation) = reconciled.as_ref().ok().and_then(|status| {
                    status.prepared.as_ref().and_then(|prepared| {
                        (prepared.endpoint == endpoint_text).then_some(prepared.generation)
                    })
                }) {
                    generation
                } else {
                    let gateway_state_indeterminate = reconciled.is_err();
                    return Err(DebugGatewayClientError::PromotionReconciliation {
                        operation: "prepare",
                        failure: prepare_error.to_string(),
                        reconciliation: format_reconciliation(reconciled),
                        gateway_state_indeterminate,
                    });
                }
            }
        };
        if let Err(commit_error) = self.client.commit_backend(generation) {
            let reconciled = self
                .reconnect_control()
                .and_then(|()| self.client.backend_status());
            if reconciled.as_ref().is_ok_and(|status| {
                status.active.as_ref().map(|active| active.generation) == Some(generation)
            }) {
                return Ok(generation);
            }
            let candidate_is_prepared = reconciled.as_ref().is_ok_and(|status| {
                status.prepared.as_ref().map(|prepared| prepared.generation) == Some(generation)
            });
            let mut gateway_state_indeterminate = reconciled.is_err();
            let mut reconciliation = format_reconciliation(reconciled);
            if candidate_is_prepared && let Err(abort_error) = self.client.abort_backend(generation)
            {
                let after_abort = self
                    .reconnect_control()
                    .and_then(|()| self.client.backend_status());
                gateway_state_indeterminate = match after_abort.as_ref() {
                    Ok(status) => {
                        status.active.as_ref().map(|active| active.generation) == Some(generation)
                            || status.prepared.as_ref().map(|prepared| prepared.generation)
                                == Some(generation)
                    }
                    Err(_) => true,
                };
                reconciliation = format!(
                    "{reconciliation}; abort failed: {abort_error}; after abort: {}",
                    format_reconciliation(after_abort)
                );
            }
            return Err(DebugGatewayClientError::PromotionReconciliation {
                operation: "commit",
                failure: commit_error.to_string(),
                reconciliation,
                gateway_state_indeterminate,
            });
        }
        Ok(generation)
    }

    /// Terminates and reaps the gateway process.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] if child status inspection, signal
    /// delivery, or reaping fails.
    pub fn shutdown(mut self) -> Result<ExitStatus, DebugGatewayClientError> {
        terminate_child(&mut self.child)
    }

    /// Terminates and reaps the gateway while retaining the process handle on failure.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] if child status inspection, signal
    /// delivery, or reaping fails. Callers may retry while retaining dependent
    /// backend ownership.
    pub fn terminate(&mut self) -> Result<ExitStatus, DebugGatewayClientError> {
        terminate_child(&mut self.child)
    }
}

impl Drop for DebugGatewayProcess {
    fn drop(&mut self) {
        let _ = terminate_child(&mut self.child);
    }
}

fn terminate_child(child: &mut Child) -> Result<ExitStatus, DebugGatewayClientError> {
    if let Some(status) = child
        .try_wait()
        .map_err(DebugGatewayClientError::InspectChild)?
    {
        return Ok(status);
    }
    child.kill().map_err(DebugGatewayClientError::Terminate)?;
    child.wait().map_err(DebugGatewayClientError::Reap)
}

fn format_reconciliation(
    status: Result<DebugGatewayBackendStatus, DebugGatewayClientError>,
) -> String {
    status.map_or_else(
        |error| format!("unavailable: {error}"),
        |status| format!("active={:?}, prepared={:?}", status.active, status.prepared),
    )
}

/// Blocking control client for one debugger gateway process.
pub struct DebugGatewayControlClient {
    stream: UnixStream,
    pending_run_control_stream: Option<u32>,
}

impl DebugGatewayControlClient {
    /// Connects to and negotiates a debugger gateway control socket.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when the socket cannot be connected,
    /// framing fails, negotiation is rejected, or the peer selects an unknown
    /// capability contract.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, DebugGatewayClientError> {
        let stream = UnixStream::connect(path).map_err(DebugGatewayClientError::Connect)?;
        let mut client = Self {
            stream,
            pending_run_control_stream: None,
        };
        let reply = client.request(DebugGatewayMessageKind::Hello, 0, Vec::new())?;
        if reply.kind != DebugGatewayMessageKind::HelloAck
            || reply.payload != DEBUG_GATEWAY_V1_CAPABILITY
        {
            return Err(DebugGatewayClientError::UnexpectedReply {
                expected: DebugGatewayMessageKind::HelloAck,
                actual: reply.kind,
            });
        }
        Ok(client)
    }

    fn disconnect(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    /// Returns active and prepared backend identities for reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when transport, framing, peer
    /// rejection, or status decoding fails.
    pub fn backend_status(&mut self) -> Result<DebugGatewayBackendStatus, DebugGatewayClientError> {
        let reply = self.request(DebugGatewayMessageKind::BackendStatus, 0, Vec::new())?;
        if reply.kind != DebugGatewayMessageKind::BackendStatusAck {
            return Err(DebugGatewayClientError::UnexpectedReply {
                expected: DebugGatewayMessageKind::BackendStatusAck,
                actual: reply.kind,
            });
        }
        DebugGatewayBackendStatus::decode(&reply.payload)
            .map_err(|error| DebugGatewayClientError::InvalidPayload(error.to_string()))
    }

    /// Returns the stable operator-facing GDB listener address.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when transport or framing fails, the
    /// gateway rejects the query, or the response is not a valid socket address.
    pub fn operator_listen(&mut self) -> Result<Option<SocketAddr>, DebugGatewayClientError> {
        let reply = self.request(DebugGatewayMessageKind::OperatorStatus, 0, Vec::new())?;
        if reply.kind != DebugGatewayMessageKind::OperatorStatusAck {
            return Err(DebugGatewayClientError::UnexpectedReply {
                expected: DebugGatewayMessageKind::OperatorStatusAck,
                actual: reply.kind,
            });
        }
        if reply.payload.is_empty() {
            return Ok(None);
        }
        let value = std::str::from_utf8(&reply.payload)
            .map_err(|error| DebugGatewayClientError::InvalidPayload(error.to_string()))?;
        value
            .parse()
            .map(Some)
            .map_err(|_| DebugGatewayClientError::InvalidOperatorListen(value.to_owned()))
    }

    /// Polls one raw RSP run-control packet queued by the operator connection.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] for transport, framing, or an
    /// unexpected gateway reply.
    pub fn poll_run_control(&mut self) -> Result<Option<Vec<u8>>, DebugGatewayClientError> {
        let reply = self.request(DebugGatewayMessageKind::RunControl, 1, Vec::new())?;
        match reply.kind {
            DebugGatewayMessageKind::RunControl if reply.payload.is_empty() => Ok(None),
            DebugGatewayMessageKind::RunControl => {
                if self.pending_run_control_stream == Some(reply.stream_id) {
                    return Ok(None);
                }
                self.pending_run_control_stream = Some(reply.stream_id);
                Ok(Some(reply.payload))
            }
            actual => Err(DebugGatewayClientError::UnexpectedReply {
                expected: DebugGatewayMessageKind::RunControl,
                actual,
            }),
        }
    }

    /// Delivers a scheduler-produced RSP response to the operator connection.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] for an empty response, transport,
    /// framing, gateway rejection, or an unexpected reply.
    pub fn complete_run_control(&mut self, response: &[u8]) -> Result<(), DebugGatewayClientError> {
        if response.is_empty() {
            return Err(DebugGatewayClientError::InvalidPayload(String::from(
                "scheduler RSP response must not be empty",
            )));
        }
        let stream_id = self.pending_run_control_stream.ok_or_else(|| {
            DebugGatewayClientError::InvalidPayload(String::from(
                "no scheduler RSP request is pending",
            ))
        })?;
        let reply = self.request(
            DebugGatewayMessageKind::RspData,
            stream_id,
            response.to_vec(),
        )?;
        if reply.kind != DebugGatewayMessageKind::Ack {
            return Err(DebugGatewayClientError::UnexpectedReply {
                expected: DebugGatewayMessageKind::Ack,
                actual: reply.kind,
            });
        }
        self.pending_run_control_stream = None;
        Ok(())
    }

    /// Acquires scheduler ownership while preserving operator RSP state.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when the gateway has pending RSP
    /// work, no active backend, or cannot suspend installed hardware breakpoints.
    pub fn acquire_scheduler_lease(&mut self) -> Result<(), DebugGatewayClientError> {
        self.scheduler_lease_request(1)
    }

    /// Releases scheduler ownership and restores operator RSP state.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when the gateway cannot restore the
    /// active backend's installed hardware breakpoints.
    pub fn release_scheduler_lease(&mut self) -> Result<(), DebugGatewayClientError> {
        self.scheduler_lease_request(2)
    }

    fn scheduler_lease_request(&mut self, operation: u8) -> Result<(), DebugGatewayClientError> {
        let reply = self.request(DebugGatewayMessageKind::SchedulerLease, 0, vec![operation])?;
        if reply.kind != DebugGatewayMessageKind::Ack {
            return Err(DebugGatewayClientError::UnexpectedReply {
                expected: DebugGatewayMessageKind::Ack,
                actual: reply.kind,
            });
        }
        Ok(())
    }

    /// Connects and validates a candidate private QEMU RSP endpoint.
    ///
    /// Repeating the same endpoint after an acknowledgement loss returns the
    /// original prepared generation.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when transport, framing, validation,
    /// or generation decoding fails.
    pub fn prepare_backend(&mut self, endpoint: &Path) -> Result<u64, DebugGatewayClientError> {
        let endpoint = endpoint
            .to_str()
            .ok_or_else(|| DebugGatewayClientError::InvalidEndpoint(endpoint.to_path_buf()))?;
        let reply = self.request(
            DebugGatewayMessageKind::BackendPrepare,
            0,
            endpoint.as_bytes().to_vec(),
        )?;
        decode_generation_ack(reply)
    }

    /// Atomically promotes a prepared backend generation.
    ///
    /// Repeating a commit for the active generation succeeds, allowing recovery
    /// when the first acknowledgement was lost.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when transport, framing, promotion,
    /// or acknowledgement decoding fails.
    pub fn commit_backend(&mut self, generation: u64) -> Result<(), DebugGatewayClientError> {
        let reply = self.request(
            DebugGatewayMessageKind::BackendCommit,
            0,
            generation.to_be_bytes().to_vec(),
        )?;
        let acknowledged = decode_generation_ack(reply)?;
        if acknowledged != generation {
            return Err(DebugGatewayClientError::GenerationMismatch {
                expected: generation,
                actual: acknowledged,
            });
        }
        Ok(())
    }

    /// Drops one prepared backend without disturbing the active backend.
    ///
    /// # Errors
    ///
    /// Returns [`DebugGatewayClientError`] when transport, framing, or the
    /// abort operation fails.
    pub fn abort_backend(&mut self, generation: u64) -> Result<(), DebugGatewayClientError> {
        let reply = self.request(
            DebugGatewayMessageKind::BackendAbort,
            0,
            generation.to_be_bytes().to_vec(),
        )?;
        if reply.kind != DebugGatewayMessageKind::Ack {
            return Err(DebugGatewayClientError::UnexpectedReply {
                expected: DebugGatewayMessageKind::Ack,
                actual: reply.kind,
            });
        }
        Ok(())
    }

    fn request(
        &mut self,
        kind: DebugGatewayMessageKind,
        stream_id: u32,
        payload: Vec<u8>,
    ) -> Result<DebugGatewayFrame, DebugGatewayClientError> {
        let frame = DebugGatewayFrame::v1(kind, stream_id, payload)
            .map_err(|error| DebugGatewayClientError::Encode(error.to_string()))?;
        let encoded = frame
            .encode()
            .map_err(|error| DebugGatewayClientError::Encode(error.to_string()))?;
        self.stream
            .write_all(&encoded)
            .map_err(DebugGatewayClientError::Write)?;
        let reply = read_frame(&mut self.stream)?;
        if reply.kind == DebugGatewayMessageKind::Error {
            let payload = DebugGatewayErrorPayload::decode(&reply.payload)
                .map_err(|error| DebugGatewayClientError::InvalidPayload(error.to_string()))?;
            return Err(DebugGatewayClientError::Rejected {
                code: payload.code as u16,
                detail: payload.detail,
            });
        }
        Ok(reply)
    }
}

fn decode_generation_ack(frame: DebugGatewayFrame) -> Result<u64, DebugGatewayClientError> {
    if frame.kind != DebugGatewayMessageKind::Ack {
        return Err(DebugGatewayClientError::UnexpectedReply {
            expected: DebugGatewayMessageKind::Ack,
            actual: frame.kind,
        });
    }
    let bytes: [u8; 8] = frame.payload.try_into().map_err(|_| {
        DebugGatewayClientError::InvalidPayload(String::from(
            "backend acknowledgement must contain one eight-byte generation",
        ))
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_frame(stream: &mut UnixStream) -> Result<DebugGatewayFrame, DebugGatewayClientError> {
    let mut header = [0_u8; DEBUG_GATEWAY_HEADER_LEN];
    stream
        .read_exact(&mut header)
        .map_err(DebugGatewayClientError::Read)?;
    let payload_len = u32::from_be_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if payload_len > DEBUG_GATEWAY_MAX_PAYLOAD {
        return Err(DebugGatewayClientError::PayloadTooLarge {
            length: payload_len,
        });
    }
    let mut bytes = Vec::with_capacity(DEBUG_GATEWAY_HEADER_LEN + payload_len);
    bytes.extend_from_slice(&header);
    bytes.resize(DEBUG_GATEWAY_HEADER_LEN + payload_len, 0);
    stream
        .read_exact(&mut bytes[DEBUG_GATEWAY_HEADER_LEN..])
        .map_err(DebugGatewayClientError::Read)?;
    decode_debug_gateway_frame(&bytes)
        .map_err(|error| DebugGatewayClientError::Decode(error.to_string()))
}

/// Errors returned by the debugger gateway control client.
#[derive(Debug, Error)]
pub enum DebugGatewayClientError {
    /// A private gateway run directory could not be created.
    #[error("create debugger gateway run directory: {0}")]
    CreateDirectory(#[source] io::Error),
    /// The standalone gateway process could not be spawned.
    #[error("spawn debugger gateway process: {0}")]
    Spawn(#[source] io::Error),
    /// Child status could not be inspected during startup or shutdown.
    #[error("inspect debugger gateway process: {0}")]
    InspectChild(#[source] io::Error),
    /// The child exited before its control socket negotiated.
    #[error("debugger gateway exited before negotiation with status {status}")]
    EarlyExit {
        /// Observed child status.
        status: ExitStatus,
    },
    /// The child did not negotiate before the startup bound.
    #[error("debugger gateway did not negotiate within {timeout:?}: {last_error}")]
    StartupTimeout {
        /// Applied startup bound.
        timeout: Duration,
        /// Last connection or negotiation error.
        last_error: Box<DebugGatewayClientError>,
    },
    /// The gateway child could not be terminated.
    #[error("terminate debugger gateway process: {0}")]
    Terminate(#[source] io::Error),
    /// The gateway child could not be reaped.
    #[error("reap debugger gateway process: {0}")]
    Reap(#[source] io::Error),
    /// The Unix control socket could not be connected.
    #[error("connect debugger gateway control socket: {0}")]
    Connect(#[source] io::Error),
    /// A request frame could not be encoded.
    #[error("encode debugger gateway request: {0}")]
    Encode(String),
    /// A request could not be written completely.
    #[error("write debugger gateway request: {0}")]
    Write(#[source] io::Error),
    /// A response could not be read completely.
    #[error("read debugger gateway response: {0}")]
    Read(#[source] io::Error),
    /// A response frame was malformed.
    #[error("decode debugger gateway response: {0}")]
    Decode(String),
    /// A response payload was malformed.
    #[error("invalid debugger gateway response payload: {0}")]
    InvalidPayload(String),
    /// A peer response exceeded the fixed frame limit.
    #[error("debugger gateway response payload length {length} exceeds the limit")]
    PayloadTooLarge {
        /// Rejected payload length.
        length: usize,
    },
    /// The gateway rejected a request with a stable code.
    #[error("debugger gateway rejected request with code {code}: {detail}")]
    Rejected {
        /// Stable protocol error code.
        code: u16,
        /// Bounded operator diagnostic.
        detail: String,
    },
    /// A response used the wrong message kind.
    #[error("unexpected debugger gateway reply {actual:?}; expected {expected:?}")]
    UnexpectedReply {
        /// Required response kind.
        expected: DebugGatewayMessageKind,
        /// Received response kind.
        actual: DebugGatewayMessageKind,
    },
    /// A commit acknowledgement named a different generation.
    #[error("debugger gateway acknowledged generation {actual}, expected {expected}")]
    GenerationMismatch {
        /// Requested generation.
        expected: u64,
        /// Acknowledged generation.
        actual: u64,
    },
    /// A QEMU endpoint could not be represented by the protocol.
    #[error("QEMU debugger endpoint is not valid UTF-8: {0}")]
    InvalidEndpoint(std::path::PathBuf),
    /// The gateway reported an invalid operator listener address.
    #[error("debugger gateway reported invalid operator listener `{0}`")]
    InvalidOperatorListen(String),
    /// A direct unauthenticated listener was requested outside loopback.
    #[error("unauthenticated debugger listener must be loopback, not `{0}`")]
    UntrustedOperatorListen(SocketAddr),
    /// A backend promotion could not be proven after an ambiguous response.
    #[error(
        "debugger backend {operation} failed with `{failure}`; reconciliation {reconciliation}"
    )]
    PromotionReconciliation {
        /// Promotion phase whose acknowledgement was ambiguous.
        operation: &'static str,
        /// Original transport or gateway failure.
        failure: String,
        /// Status observed after reconnecting, or the reconnect failure.
        reconciliation: String,
        /// Whether the gateway may still have applied an unobserved transition.
        gateway_state_indeterminate: bool,
    },
}

impl DebugGatewayClientError {
    /// Returns whether this failure requires terminating the gateway session.
    ///
    /// An indeterminate promotion cannot safely discard either backend while
    /// the gateway might still route the stable operator connection to it.
    #[must_use]
    pub const fn promotion_requires_gateway_teardown(&self) -> bool {
        matches!(
            self,
            Self::PromotionReconciliation {
                gateway_state_indeterminate: true,
                ..
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;

    use crucible_protocol::debug_gateway::{DebugGatewayBackendIdentity, DebugGatewayErrorCode};

    use super::*;

    fn write_reply(stream: &mut UnixStream, frame: DebugGatewayFrame) {
        let bytes = frame
            .encode()
            .unwrap_or_else(|error| panic!("reply should encode: {error}"));
        stream
            .write_all(&bytes)
            .unwrap_or_else(|error| panic!("reply should write: {error}"));
    }

    #[test]
    fn client_negotiates_and_decodes_backend_status() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("temporary directory should open: {error}"));
        let socket = directory.path().join("gateway.sock");
        let listener = UnixListener::bind(&socket)
            .unwrap_or_else(|error| panic!("test listener should bind: {error}"));
        let server = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .unwrap_or_else(|error| panic!("test connection should accept: {error}"));
            let hello = read_frame(&mut stream)
                .unwrap_or_else(|error| panic!("hello should read: {error}"));
            assert_eq!(hello.kind, DebugGatewayMessageKind::Hello);
            write_reply(
                &mut stream,
                DebugGatewayFrame::v1(
                    DebugGatewayMessageKind::HelloAck,
                    0,
                    DEBUG_GATEWAY_V1_CAPABILITY.to_vec(),
                )
                .unwrap_or_else(|error| panic!("hello acknowledgement should build: {error}")),
            );
            let status = read_frame(&mut stream)
                .unwrap_or_else(|error| panic!("status should read: {error}"));
            assert_eq!(status.kind, DebugGatewayMessageKind::BackendStatus);
            let payload = DebugGatewayBackendStatus {
                active: Some(DebugGatewayBackendIdentity {
                    generation: 4,
                    endpoint: String::from("/run/crucible/qemu.sock"),
                }),
                prepared: None,
            }
            .encode()
            .unwrap_or_else(|error| panic!("status should encode: {error}"));
            write_reply(
                &mut stream,
                DebugGatewayFrame::v1(DebugGatewayMessageKind::BackendStatusAck, 0, payload)
                    .unwrap_or_else(|error| panic!("status reply should build: {error}")),
            );
        });

        let mut client = DebugGatewayControlClient::connect(&socket)
            .unwrap_or_else(|error| panic!("client should negotiate: {error}"));
        let status = client
            .backend_status()
            .unwrap_or_else(|error| panic!("client should decode status: {error}"));
        assert_eq!(status.active.map(|identity| identity.generation), Some(4));
        server
            .join()
            .unwrap_or_else(|_| panic!("test server should not panic"));
    }

    #[test]
    fn client_preserves_typed_gateway_rejection() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("temporary directory should open: {error}"));
        let socket = directory.path().join("gateway.sock");
        let listener = UnixListener::bind(&socket)
            .unwrap_or_else(|error| panic!("test listener should bind: {error}"));
        let server = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .unwrap_or_else(|error| panic!("test connection should accept: {error}"));
            let _hello = read_frame(&mut stream)
                .unwrap_or_else(|error| panic!("hello should read: {error}"));
            write_reply(
                &mut stream,
                DebugGatewayFrame::v1(
                    DebugGatewayMessageKind::HelloAck,
                    0,
                    DEBUG_GATEWAY_V1_CAPABILITY.to_vec(),
                )
                .unwrap_or_else(|error| panic!("hello acknowledgement should build: {error}")),
            );
            let _status = read_frame(&mut stream)
                .unwrap_or_else(|error| panic!("status should read: {error}"));
            let payload = DebugGatewayErrorPayload::new(
                DebugGatewayErrorCode::BackendUnavailable,
                "candidate failed validation",
            )
            .unwrap_or_else(|error| panic!("typed error should build: {error}"));
            write_reply(
                &mut stream,
                DebugGatewayFrame::v1(DebugGatewayMessageKind::Error, 0, payload.encode())
                    .unwrap_or_else(|error| panic!("error reply should build: {error}")),
            );
        });

        let mut client = DebugGatewayControlClient::connect(&socket)
            .unwrap_or_else(|error| panic!("client should negotiate: {error}"));
        assert!(matches!(
            client.backend_status(),
            Err(DebugGatewayClientError::Rejected { code: 3, detail })
                if detail == "candidate failed validation"
        ));
        server
            .join()
            .unwrap_or_else(|_| panic!("test server should not panic"));
    }
}
