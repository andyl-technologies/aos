//! SPDX-License-Identifier: GPL-2.0-only
//! Standalone GPL-side debugger gateway process.
//!
//! The process owns QEMU RSP Unix connections while the Apache-licensed
//! Crucible host communicates through the versioned owned-byte protocol in
//! [`crucible_protocol::debug_gateway`]. Every control connection must begin
//! with `Hello`. Backend replacement then follows prepare, validate and
//! hydrate, and commit or abort so a failed candidate never displaces the
//! active backend.
//!
//! A malformed or disconnected control client is isolated to its connection;
//! the process and active backend remain available for the next client. The
//! private operator Unix listener relays allowlisted read-only RSP traffic
//! across backend replacement. An owner control transition admits guest writes
//! only after a noncanonical fork. Run control crosses the scheduler ownership
//! protocol; guest channels fail closed until their shared-memory routes are active.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::env;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crucible_debug_gateway::{
    BackendGeneration, DebugGateway, QemuRspEndpoint, RspDisposition, RspSessionState,
    RspStreamDecoder, RspUnit, classify_rsp_packet,
};
use crucible_protocol::debug_gateway::{
    DEBUG_GATEWAY_HEADER_LEN, DEBUG_GATEWAY_MAX_PAYLOAD, DebugGatewayBackendIdentity,
    DebugGatewayBackendStatus, DebugGatewayErrorCode, DebugGatewayErrorPayload, DebugGatewayFrame,
    DebugGatewayMessageKind, decode_debug_gateway_frame,
};

#[path = "main/operator_relay.rs"]
mod operator_relay;

use operator_relay::{
    handle_operator_rsp_unit, record_semantic_response, restore_backend_after_operator_disconnect,
    rsp_payload, serve_operator_connection, spawn_operator_listener, write_active_backend,
};

#[path = "main/scheduler_ownership.rs"]
mod scheduler_ownership;

use scheduler_ownership::{
    acknowledge_scheduler_response, finish_gdb_scheduler_run, interrupt_scheduler_backend,
    poll_scheduler_run_control, scheduler_lease,
};

struct GatewayProcess {
    model: DebugGateway,
    active: Option<(BackendGeneration, UnixStream)>,
    prepared: Option<(BackendGeneration, UnixStream, u64)>,
    operator_listen: Option<String>,
    operator_writer: Option<UnixStream>,
    branch_guest_write_enabled: bool,
    operator_admission_paused: bool,
    rsp_responses_pending: usize,
    rsp_state_epoch: u64,
    replacement_epoch: u64,
    operator_epoch: u32,
    next_run_control_id: u32,
    run_control_requests: VecDeque<(u32, u32, Vec<u8>)>,
    run_control_inflight: Option<(u32, u32, Vec<u8>)>,
    run_control_cancelled: Option<u32>,
    run_control_completed: Option<(u32, Vec<u8>, Vec<u8>)>,
    scheduler_response_pending: Option<Vec<u8>>,
    scheduler_lease_active: bool,
    gdb_scheduler_run_active: Option<u32>,
}

const QEMU_RSP_TIMEOUT: Duration = Duration::from_secs(5);
const RSP_RELAY_POLL_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_PENDING_RSP_REQUESTS: usize = 64;
const MAX_PENDING_RSP_BYTES: usize = 64 * 1024;

impl GatewayProcess {
    fn new(operator_listen: Option<String>) -> Self {
        Self {
            model: DebugGateway::new(),
            active: None,
            prepared: None,
            operator_listen,
            operator_writer: None,
            branch_guest_write_enabled: false,
            operator_admission_paused: false,
            rsp_responses_pending: 0,
            rsp_state_epoch: 0,
            replacement_epoch: 0,
            operator_epoch: 0,
            next_run_control_id: 0,
            run_control_requests: VecDeque::new(),
            run_control_inflight: None,
            run_control_cancelled: None,
            run_control_completed: None,
            scheduler_response_pending: None,
            scheduler_lease_active: false,
            gdb_scheduler_run_active: None,
        }
    }

    fn handle(&mut self, frame: DebugGatewayFrame) -> Result<DebugGatewayFrame, String> {
        match frame.kind {
            DebugGatewayMessageKind::Hello => {
                response(DebugGatewayMessageKind::HelloAck, 0, b"debug-gateway.v1")
            }
            DebugGatewayMessageKind::BackendPrepare => Err(String::from(
                "backend prepare must use the shared candidate dispatcher",
            )),
            DebugGatewayMessageKind::BackendCommit => {
                let generation = generation_payload(&frame.payload)?;
                if self.model.active().map(|active| active.generation) == Some(generation) {
                    self.operator_admission_paused = false;
                    return response(DebugGatewayMessageKind::Ack, 0, generation.0.to_be_bytes());
                }
                if !self.replacement_boundary_is_clean() {
                    return Err(String::from(
                        "cannot commit a backend while an operator RSP or scheduler run-control operation is pending",
                    ));
                }
                let Some((prepared_generation, stream, hydrated_epoch)) = self.prepared.take()
                else {
                    return Err(String::from("no candidate QEMU RSP endpoint is prepared"));
                };
                if prepared_generation != generation {
                    self.prepared = Some((prepared_generation, stream, hydrated_epoch));
                    return Err(String::from("prepared backend generation mismatch"));
                }
                if hydrated_epoch != self.rsp_state_epoch {
                    self.prepared = Some((prepared_generation, stream, hydrated_epoch));
                    return Err(String::from(
                        "prepared backend debugger state is stale; prepare it again",
                    ));
                }
                self.model
                    .commit_backend(generation)
                    .map_err(|error| error.to_string())?;
                self.active = Some((generation, stream));
                self.branch_guest_write_enabled = false;
                self.operator_admission_paused = false;
                self.replacement_epoch = self.replacement_epoch.saturating_add(1);
                response(DebugGatewayMessageKind::Ack, 0, generation.0.to_be_bytes())
            }
            DebugGatewayMessageKind::BackendAbort => {
                let generation = generation_payload(&frame.payload)?;
                self.model
                    .abort_backend(generation)
                    .map_err(|error| error.to_string())?;
                self.prepared = None;
                self.operator_admission_paused = false;
                response(DebugGatewayMessageKind::Ack, 0, Vec::new())
            }
            DebugGatewayMessageKind::BackendStatus => {
                if !frame.payload.is_empty() {
                    return Err(String::from("backend status request payload must be empty"));
                }
                let status = DebugGatewayBackendStatus {
                    active: self.model.active().map(backend_identity),
                    prepared: self.model.prepared().map(backend_identity),
                };
                let payload = status.encode().map_err(|error| error.to_string())?;
                response(DebugGatewayMessageKind::BackendStatusAck, 0, payload)
            }
            DebugGatewayMessageKind::OperatorStatus => {
                if !frame.payload.is_empty() {
                    return Err(String::from(
                        "operator status request payload must be empty",
                    ));
                }
                response(
                    DebugGatewayMessageKind::OperatorStatusAck,
                    0,
                    self.operator_listen
                        .as_ref()
                        .map(|listen| listen.as_bytes().to_vec())
                        .unwrap_or_default(),
                )
            }
            DebugGatewayMessageKind::OperatorAccess => {
                if frame.payload != b"branch-guest-write" {
                    return Err(String::from("unsupported operator access transition"));
                }
                if !self
                    .operator_listen
                    .as_deref()
                    .is_some_and(|value| value.starts_with("unix:"))
                {
                    return Err(String::from(
                        "guest writes require a private Unix operator endpoint",
                    ));
                }
                self.branch_guest_write_enabled = true;
                response(DebugGatewayMessageKind::Ack, 0, Vec::new())
            }
            DebugGatewayMessageKind::SchedulerLease => Err(String::from(
                "scheduler lease must use the ownership dispatcher",
            )),
            DebugGatewayMessageKind::RspData => {
                Err(String::from("RSP data must use the scheduler dispatcher"))
            }
            DebugGatewayMessageKind::RunControl => Err(String::from(
                "run control must use the ownership dispatcher",
            )),
            DebugGatewayMessageKind::ExecOpen
            | DebugGatewayMessageKind::PtyOpen
            | DebugGatewayMessageKind::SshOpen
            | DebugGatewayMessageKind::ChannelData
            | DebugGatewayMessageKind::ChannelClose => Err(String::from(
                "guest debug transport is not available in this gateway build",
            )),
            DebugGatewayMessageKind::HelloAck
            | DebugGatewayMessageKind::Ack
            | DebugGatewayMessageKind::BackendStatusAck
            | DebugGatewayMessageKind::OperatorStatusAck
            | DebugGatewayMessageKind::Error => {
                Err(String::from("message kind is not a host request"))
            }
        }
    }

    fn replacement_boundary_is_clean(&self) -> bool {
        self.rsp_responses_pending == 0
            && self.run_control_requests.is_empty()
            && self.run_control_inflight.is_none()
            && self.run_control_cancelled.is_none()
            && self.scheduler_response_pending.is_none()
            && !self.scheduler_lease_active
            && self.gdb_scheduler_run_active.is_none()
    }
}

fn backend_identity(
    backend: &crucible_debug_gateway::PreparedBackend,
) -> DebugGatewayBackendIdentity {
    DebugGatewayBackendIdentity {
        generation: backend.generation.0,
        endpoint: backend.endpoint.as_str().to_owned(),
    }
}

fn validate_and_hydrate_candidate(
    stream: &mut UnixStream,
    state: &RspSessionState,
) -> Result<(), String> {
    let stop = exchange_rsp_packet(stream, b"?")?;
    if !matches!(stop.first(), Some(b'S' | b'T')) {
        return Err(String::from(
            "candidate QEMU RSP endpoint did not report a paused stop state",
        ));
    }
    for packet in state
        .general_thread
        .iter()
        .chain(state.continue_thread.iter())
        .chain(state.hardware_breakpoints.iter())
    {
        let reply = exchange_rsp_packet(stream, packet)?;
        if reply != b"OK" {
            return Err(format!(
                "candidate QEMU RSP endpoint rejected replayed session state with {}",
                String::from_utf8_lossy(&reply)
            ));
        }
    }
    Ok(())
}

fn exchange_rsp_packet(stream: &mut UnixStream, payload: &[u8]) -> Result<Vec<u8>, String> {
    let packet = encode_rsp_packet(payload);
    stream
        .write_all(&packet)
        .map_err(|error| format!("write candidate QEMU RSP packet: {error}"))?;
    let mut decoder = RspStreamDecoder::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("read candidate QEMU RSP response: {error}"))?;
        if read == 0 {
            return Err(String::from(
                "candidate QEMU RSP endpoint closed before replying",
            ));
        }
        for unit in decoder
            .push(&buffer[..read])
            .map_err(|error| format!("decode candidate QEMU RSP response: {error}"))?
        {
            match unit {
                RspUnit::Ack => {}
                RspUnit::Nack => {
                    return Err(String::from(
                        "candidate QEMU RSP endpoint rejected a validation packet",
                    ));
                }
                RspUnit::Interrupt => {
                    return Err(String::from(
                        "candidate QEMU RSP endpoint sent an unexpected interrupt",
                    ));
                }
                RspUnit::Packet(packet) => {
                    stream.write_all(b"+").map_err(|error| {
                        format!("acknowledge candidate QEMU RSP reply: {error}")
                    })?;
                    return Ok(packet[1..packet.len() - 3].to_vec());
                }
            }
        }
    }
}

fn encode_rsp_packet(payload: &[u8]) -> Vec<u8> {
    let checksum = payload
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push(b'$');
    packet.extend_from_slice(payload);
    packet.push(b'#');
    const HEX: &[u8; 16] = b"0123456789abcdef";
    packet.push(HEX[usize::from(checksum >> 4)]);
    packet.push(HEX[usize::from(checksum & 0x0f)]);
    packet
}

fn response(
    kind: DebugGatewayMessageKind,
    stream_id: u32,
    payload: impl Into<Vec<u8>>,
) -> Result<DebugGatewayFrame, String> {
    DebugGatewayFrame::v1(kind, stream_id, payload).map_err(|error| error.to_string())
}

fn error_response(
    code: DebugGatewayErrorCode,
    stream_id: u32,
    detail: &str,
) -> Result<DebugGatewayFrame, String> {
    let payload = DebugGatewayErrorPayload::new(code, bounded_diagnostic(detail))
        .map_err(|error| error.to_string())?;
    response(DebugGatewayMessageKind::Error, stream_id, payload.encode())
}

fn generation_payload(payload: &[u8]) -> Result<BackendGeneration, String> {
    let bytes: [u8; 8] = payload
        .try_into()
        .map_err(|_| String::from("backend generation payload must contain eight bytes"))?;
    Ok(BackendGeneration(u64::from_be_bytes(bytes)))
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; DEBUG_GATEWAY_HEADER_LEN];
    let mut header_read = 0;
    while header_read < header.len() {
        match stream.read(&mut header[header_read..]) {
            Ok(0) if header_read == 0 => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated debugger gateway frame header",
                ));
            }
            Ok(read) => header_read += read,
            Err(error) => return Err(error),
        }
    }
    let payload_len = u32::from_be_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if payload_len > DEBUG_GATEWAY_MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "debug gateway payload exceeds limit",
        ));
    }
    let mut bytes = Vec::with_capacity(DEBUG_GATEWAY_HEADER_LEN + payload_len);
    bytes.extend_from_slice(&header);
    bytes.resize(DEBUG_GATEWAY_HEADER_LEN + payload_len, 0);
    stream.read_exact(&mut bytes[DEBUG_GATEWAY_HEADER_LEN..])?;
    Ok(Some(bytes))
}

type SharedGatewayProcess = Arc<Mutex<GatewayProcess>>;

fn with_gateway<T>(
    process: &SharedGatewayProcess,
    operation: impl FnOnce(&mut GatewayProcess) -> Result<T, String>,
) -> Result<T, String> {
    let mut process = process
        .lock()
        .map_err(|_| String::from("debug gateway shared state is poisoned"))?;
    operation(&mut process)
}

fn dispatch_request(
    process: &SharedGatewayProcess,
    frame: DebugGatewayFrame,
) -> Result<DebugGatewayFrame, String> {
    if frame.kind == DebugGatewayMessageKind::RspData {
        if frame.payload.is_empty() {
            return Err(String::from("scheduler RSP response must not be empty"));
        }
        with_gateway(process, |gateway| {
            if gateway.run_control_cancelled == Some(frame.stream_id) {
                gateway.run_control_cancelled = None;
                return Ok(());
            }
            if gateway
                .run_control_completed
                .as_ref()
                .is_some_and(|(epoch, _, response)| {
                    *epoch == frame.stream_id && response == &frame.payload
                })
            {
                return Ok(());
            }
            if gateway
                .run_control_inflight
                .as_ref()
                .map(|(stream_id, _, _)| *stream_id)
                != Some(frame.stream_id)
                || gateway
                    .run_control_inflight
                    .as_ref()
                    .map(|(_, operator_epoch, _)| *operator_epoch)
                    != Some(gateway.operator_epoch)
            {
                return Ok(());
            }
            let request = gateway
                .run_control_inflight
                .as_ref()
                .map(|(_, _, request)| request.clone())
                .ok_or_else(|| String::from("scheduler run-control request disappeared"))?;
            let operator_epoch = gateway
                .run_control_inflight
                .as_ref()
                .map(|(_, operator_epoch, _)| *operator_epoch)
                .ok_or_else(|| String::from("scheduler run-control request disappeared"))?;
            let response_payload =
                if gateway
                    .run_control_requests
                    .front()
                    .is_some_and(|(_, queued_epoch, queued)| {
                        *queued_epoch == operator_epoch && queued == &[0x03]
                    })
                {
                    // An accepted Ctrl-C wins over a stop completed in the same relay interval.
                    let _interrupt = gateway.run_control_requests.pop_front();
                    b"T02".to_vec()
                } else {
                    frame.payload.clone()
                };
            finish_gdb_scheduler_run(gateway, frame.stream_id)?;
            let operator = gateway
                .operator_writer
                .as_mut()
                .ok_or_else(|| String::from("operator gdb connection is not active"))?;
            let encoded_response = encode_rsp_packet(&response_payload);
            operator.write_all(&encoded_response).map_err(|error| {
                format!("write scheduler RSP response to operator gdb: {error}")
            })?;
            gateway.run_control_inflight = None;
            gateway.run_control_completed = Some((frame.stream_id, request, response_payload));
            gateway.scheduler_response_pending = Some(encoded_response);
            Ok(())
        })?;
        response(DebugGatewayMessageKind::Ack, 0, Vec::new())
    } else if frame.kind == DebugGatewayMessageKind::BackendPrepare {
        prepare_backend(process, frame.payload)
    } else if frame.kind == DebugGatewayMessageKind::BackendCommit {
        commit_backend_at_packet_boundary(process, frame)
    } else if frame.kind == DebugGatewayMessageKind::SchedulerLease {
        scheduler_lease(process, &frame.payload)
    } else if frame.kind == DebugGatewayMessageKind::RunControl {
        poll_scheduler_run_control(process, frame)
    } else {
        with_gateway(process, |process| process.handle(frame))
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "wall-clock deadline bounds gateway transport waiting, not simulation time"
)]
fn commit_backend_at_packet_boundary(
    process: &SharedGatewayProcess,
    frame: DebugGatewayFrame,
) -> Result<DebugGatewayFrame, String> {
    let deadline = Instant::now() + QEMU_RSP_TIMEOUT;
    loop {
        let committed = with_gateway(process, |gateway| {
            if !gateway.replacement_boundary_is_clean() {
                return Ok(None);
            }
            gateway.handle(frame.clone()).map(Some)
        })?;
        if let Some(response) = committed {
            return Ok(response);
        }
        if Instant::now() >= deadline {
            return Err(String::from(
                "timed out waiting for the debugger replacement packet boundary",
            ));
        }
        std::thread::yield_now();
    }
}

fn prepare_backend(
    process: &SharedGatewayProcess,
    payload: Vec<u8>,
) -> Result<DebugGatewayFrame, String> {
    const MAX_STATE_REPLAY_ATTEMPTS: usize = 3;
    let path = String::from_utf8(payload)
        .map_err(|error| format!("backend endpoint is not UTF-8: {error}"))?;
    let endpoint = QemuRspEndpoint::new(path)
        .map_err(|error| format!("validate backend endpoint: {error}"))?;
    for _attempt in 0..MAX_STATE_REPLAY_ATTEMPTS {
        let state = with_gateway(process, |gateway| Ok(gateway.model.rsp_state().clone()))?;
        let mut stream = connect_candidate(&endpoint)?;
        validate_and_hydrate_candidate(&mut stream, &state)?;
        let committed = with_gateway(process, |gateway| {
            if gateway.model.rsp_state() != &state {
                return Ok(None);
            }
            let prepared = gateway
                .model
                .prepare_backend(endpoint.clone())
                .map_err(|error| error.to_string())?;
            gateway.prepared = Some((prepared.generation, stream, gateway.rsp_state_epoch));
            gateway.operator_admission_paused = true;
            Ok(Some(prepared))
        })?;
        if let Some(prepared) = committed {
            return response(
                DebugGatewayMessageKind::Ack,
                0,
                prepared.generation.0.to_be_bytes(),
            );
        }
    }
    Err(String::from(
        "debugger session state changed repeatedly while preparing candidate backend",
    ))
}

fn connect_candidate(endpoint: &QemuRspEndpoint) -> Result<UnixStream, String> {
    let stream = UnixStream::connect(endpoint.as_str())
        .map_err(|error| format!("connect candidate QEMU RSP endpoint: {error}"))?;
    stream
        .set_read_timeout(Some(QEMU_RSP_TIMEOUT))
        .map_err(|error| format!("set candidate QEMU RSP read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(QEMU_RSP_TIMEOUT))
        .map_err(|error| format!("set candidate QEMU RSP write timeout: {error}"))?;
    Ok(stream)
}

fn serve_connection(process: &SharedGatewayProcess, mut stream: UnixStream) -> Result<(), String> {
    let mut negotiated = false;
    while let Some(bytes) = read_frame(&mut stream).map_err(|error| error.to_string())? {
        let frame = decode_debug_gateway_frame(&bytes).map_err(|error| error.to_string())?;
        let stream_id = frame.stream_id;
        let request_kind = frame.kind;
        let mut error_code = request_error_code(request_kind);
        let reply = if request_kind == DebugGatewayMessageKind::Hello {
            if negotiated {
                error_code = DebugGatewayErrorCode::ProtocolViolation;
                Err(String::from(
                    "debug gateway connection is already negotiated",
                ))
            } else {
                negotiated = true;
                dispatch_request(process, frame)
            }
        } else if !negotiated {
            error_code = DebugGatewayErrorCode::ProtocolViolation;
            Err(String::from(
                "debug gateway Hello must precede every other request",
            ))
        } else {
            dispatch_request(process, frame)
        }
        .or_else(|message| error_response(error_code, stream_id, &message))?;
        let encoded = reply.encode().map_err(|error| error.to_string())?;
        stream
            .write_all(&encoded)
            .map_err(|error| format!("write gateway response: {error}"))?;
    }
    Ok(())
}

fn request_error_code(kind: DebugGatewayMessageKind) -> DebugGatewayErrorCode {
    match kind {
        DebugGatewayMessageKind::BackendPrepare
        | DebugGatewayMessageKind::BackendCommit
        | DebugGatewayMessageKind::BackendAbort
        | DebugGatewayMessageKind::BackendStatus => DebugGatewayErrorCode::BackendUnavailable,
        DebugGatewayMessageKind::OperatorStatus
        | DebugGatewayMessageKind::OperatorAccess
        | DebugGatewayMessageKind::SchedulerLease => DebugGatewayErrorCode::InvalidRequest,
        DebugGatewayMessageKind::ExecOpen
        | DebugGatewayMessageKind::PtyOpen
        | DebugGatewayMessageKind::SshOpen
        | DebugGatewayMessageKind::ChannelData
        | DebugGatewayMessageKind::ChannelClose => DebugGatewayErrorCode::Unsupported,
        DebugGatewayMessageKind::Hello
        | DebugGatewayMessageKind::HelloAck
        | DebugGatewayMessageKind::Ack
        | DebugGatewayMessageKind::BackendStatusAck
        | DebugGatewayMessageKind::OperatorStatusAck
        | DebugGatewayMessageKind::Error => DebugGatewayErrorCode::InvalidRequest,
        DebugGatewayMessageKind::RspData | DebugGatewayMessageKind::RunControl => {
            DebugGatewayErrorCode::InvalidRequest
        }
    }
}

struct GatewayArguments {
    control_socket: PathBuf,
    owner_gdb_socket: Option<PathBuf>,
}

fn gateway_arguments() -> Result<GatewayArguments, String> {
    let mut arguments = env::args_os();
    let program = arguments.next();
    let program = program
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("crucible-debug-gateway");
    let mut control_socket = None;
    let mut owner_gdb_socket = None;
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or_else(|| gateway_usage(program))?;
        if flag == std::ffi::OsStr::new("--control-socket") && control_socket.is_none() {
            control_socket = Some(PathBuf::from(value));
        } else if flag == std::ffi::OsStr::new("--owner-gdb-socket") && owner_gdb_socket.is_none() {
            owner_gdb_socket = Some(PathBuf::from(value));
        } else {
            return Err(gateway_usage(program));
        }
    }
    let control_socket = control_socket.ok_or_else(|| String::from("missing control socket"))?;
    if !control_socket.is_absolute() {
        return Err(String::from("control socket path must be absolute"));
    }
    if owner_gdb_socket
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err(String::from("owner GDB socket path must be absolute"));
    }
    Ok(GatewayArguments {
        control_socket,
        owner_gdb_socket,
    })
}

fn gateway_usage(program: &str) -> String {
    format!(
        "usage: {program} --control-socket <absolute-path> [--owner-gdb-socket <absolute-path>]"
    )
}

fn run() -> Result<(), String> {
    let arguments = gateway_arguments()?;
    let owner_listener = arguments
        .owner_gdb_socket
        .as_ref()
        .map(|path| {
            require_private_socket_parent(path)?;
            let listener = UnixListener::bind(path)
                .map_err(|error| format!("bind owner gdb socket {}: {error}", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |error| format!("restrict owner gdb socket {}: {error}", path.display()),
            )?;
            Ok::<_, String>(listener)
        })
        .transpose()?;
    let operator_listen = arguments
        .owner_gdb_socket
        .as_ref()
        .map(|path| format!("unix:{}", path.display()));
    let process = Arc::new(Mutex::new(GatewayProcess::new(operator_listen)));
    if let Some(owner_listener) = owner_listener {
        spawn_operator_listener(process.clone(), owner_listener)?;
    }
    let listener = UnixListener::bind(&arguments.control_socket).map_err(|error| {
        format!(
            "bind control socket {}: {error}",
            arguments.control_socket.display()
        )
    })?;
    for connection in listener.incoming() {
        let stream = connection.map_err(|error| format!("accept control connection: {error}"))?;
        if let Err(error) = serve_connection(&process, stream) {
            eprintln!(
                "crucible-debug-gateway: control connection closed: {}",
                bounded_diagnostic(&error)
            );
        }
    }
    Ok(())
}

fn require_private_socket_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| String::from("owner GDB socket has no parent"))?;
    let metadata = std::fs::metadata(parent).map_err(|error| {
        format!(
            "inspect owner GDB socket directory {}: {error}",
            parent.display()
        )
    })?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(String::from(
            "owner GDB socket directory must be private (0700)",
        ));
    }
    Ok(())
}

fn bounded_diagnostic(message: &str) -> String {
    const MAX_DIAGNOSTIC_CHARS: usize = 512;
    let mut bounded = message
        .chars()
        .take(MAX_DIAGNOSTIC_CHARS)
        .collect::<String>();
    if message.chars().count() > MAX_DIAGNOSTIC_CHARS {
        bounded.push_str("...");
    }
    bounded
}

fn main() {
    if let Err(error) = run() {
        eprintln!("crucible-debug-gateway: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "main/tests.rs"]
mod tests;
