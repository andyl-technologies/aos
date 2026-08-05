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
//! stable operator listener relays allowlisted read-only RSP traffic across
//! backend replacement. Scheduler run control and guest channels intentionally
//! fail closed until their dedicated host and shared-memory routes are active.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible_debug_gateway::{
    BackendGeneration, DebugGateway, QemuRspEndpoint, RspDisposition, RspSessionState,
    RspStreamDecoder, RspUnit, classify_rsp_packet,
};
use crucible_protocol::debug_gateway::{
    DEBUG_GATEWAY_HEADER_LEN, DEBUG_GATEWAY_MAX_PAYLOAD, DebugGatewayBackendIdentity,
    DebugGatewayBackendStatus, DebugGatewayErrorCode, DebugGatewayErrorPayload, DebugGatewayFrame,
    DebugGatewayMessageKind, decode_debug_gateway_frame,
};

struct GatewayProcess {
    model: DebugGateway,
    active: Option<(BackendGeneration, UnixStream)>,
    prepared: Option<(BackendGeneration, UnixStream, u64)>,
    operator_listen: Option<SocketAddr>,
    operator_writer: Option<TcpStream>,
    rsp_responses_pending: usize,
    rsp_state_epoch: u64,
    replacement_epoch: u64,
}

const QEMU_RSP_TIMEOUT: Duration = Duration::from_secs(5);
const RSP_RELAY_POLL_TIMEOUT: Duration = Duration::from_millis(10);

impl GatewayProcess {
    fn new(operator_listen: Option<SocketAddr>) -> Self {
        Self {
            model: DebugGateway::new(),
            active: None,
            prepared: None,
            operator_listen,
            operator_writer: None,
            rsp_responses_pending: 0,
            rsp_state_epoch: 0,
            replacement_epoch: 0,
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
                    return response(DebugGatewayMessageKind::Ack, 0, generation.0.to_be_bytes());
                }
                if self.rsp_responses_pending != 0 {
                    return Err(String::from(
                        "cannot commit a backend while an operator RSP response is pending",
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
                if let Some(operator) = self.operator_writer.as_mut() {
                    operator
                        .write_all(&encode_rsp_packet(b"T05"))
                        .map_err(|error| {
                            format!("write replacement stop to operator gdb: {error}")
                        })?;
                }
                self.replacement_epoch = self.replacement_epoch.saturating_add(1);
                response(DebugGatewayMessageKind::Ack, 0, generation.0.to_be_bytes())
            }
            DebugGatewayMessageKind::BackendAbort => {
                let generation = generation_payload(&frame.payload)?;
                self.model
                    .abort_backend(generation)
                    .map_err(|error| error.to_string())?;
                self.prepared = None;
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
                        .map(|listen| listen.to_string().into_bytes())
                        .unwrap_or_default(),
                )
            }
            DebugGatewayMessageKind::RspData => Err(String::from(
                "RSP relay is disabled until the persistent asynchronous stream pump is active",
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
            | DebugGatewayMessageKind::RunControl
            | DebugGatewayMessageKind::Error => {
                Err(String::from("message kind is not a host request"))
            }
        }
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
    if frame.kind == DebugGatewayMessageKind::BackendPrepare {
        prepare_backend(process, frame.payload)
    } else {
        with_gateway(process, |process| process.handle(frame))
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

fn spawn_operator_listener(
    process: SharedGatewayProcess,
    listener: TcpListener,
) -> Result<(), String> {
    std::thread::Builder::new()
        .name(String::from("crucible-debug-gdb-listener"))
        .spawn(move || operator_listener_loop(&process, listener))
        .map(|_| ())
        .map_err(|error| format!("spawn operator gdb listener: {error}"))
}

fn operator_listener_loop(process: &SharedGatewayProcess, listener: TcpListener) {
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let result = serve_operator_connection(process, stream);
                let cleanup = deactivate_unrecoverable_backend(process);
                if let Err(error) = result {
                    eprintln!(
                        "crucible-debug-gateway: operator gdb connection closed: {}",
                        bounded_diagnostic(&error)
                    );
                }
                if let Err(error) = cleanup {
                    eprintln!(
                        "crucible-debug-gateway: operator cleanup failed: {}",
                        bounded_diagnostic(&error)
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "crucible-debug-gateway: accept operator gdb connection: {}",
                    bounded_diagnostic(&error.to_string())
                );
            }
        }
    }
}

fn deactivate_unrecoverable_backend(process: &SharedGatewayProcess) -> Result<(), String> {
    with_gateway(process, |gateway| {
        gateway.model.deactivate_backend();
        gateway.active = None;
        gateway.operator_writer = None;
        gateway.rsp_responses_pending = 0;
        Ok(())
    })
}

fn serve_operator_connection(
    process: &SharedGatewayProcess,
    mut operator: TcpStream,
) -> Result<(), String> {
    operator
        .set_read_timeout(Some(RSP_RELAY_POLL_TIMEOUT))
        .map_err(|error| format!("set operator gdb read timeout: {error}"))?;
    let operator_writer = operator
        .try_clone()
        .map_err(|error| format!("clone operator gdb stream: {error}"))?;
    operator_writer
        .set_write_timeout(Some(QEMU_RSP_TIMEOUT))
        .map_err(|error| format!("set operator gdb write timeout: {error}"))?;
    let (mut observed_replacement_epoch, mut synthetic_stop_ack_pending) =
        with_gateway(process, |gateway| {
            if gateway.operator_writer.is_some() {
                return Err(String::from("an operator gdb connection is already active"));
            }
            let active = gateway.active.is_some();
            gateway.operator_writer = Some(operator_writer);
            if active {
                let writer = gateway
                    .operator_writer
                    .as_mut()
                    .ok_or_else(|| String::from("operator gdb writer disappeared during attach"))?;
                writer
                    .write_all(&encode_rsp_packet(b"T05"))
                    .map_err(|error| format!("write initial stop to operator gdb: {error}"))?;
                gateway.replacement_epoch = gateway.replacement_epoch.saturating_add(1);
            }
            Ok((gateway.replacement_epoch, active))
        })?;
    let mut operator_decoder = RspStreamDecoder::new();
    let mut backend_decoder = RspStreamDecoder::new();
    let mut pending_state = VecDeque::<Vec<u8>>::new();
    let mut buffer = [0_u8; 4096];

    loop {
        let replacement_epoch = with_gateway(process, |gateway| Ok(gateway.replacement_epoch))?;
        if replacement_epoch != observed_replacement_epoch {
            observed_replacement_epoch = replacement_epoch;
            backend_decoder = RspStreamDecoder::new();
            pending_state.clear();
            synthetic_stop_ack_pending = true;
        }

        match operator.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                let units = operator_decoder
                    .push(&buffer[..read])
                    .map_err(|error| format!("decode operator RSP stream: {error}"))?;
                for unit in units {
                    handle_operator_rsp_unit(
                        process,
                        unit,
                        &mut pending_state,
                        &mut synthetic_stop_ack_pending,
                    )?;
                }
            }
            Err(error) if is_poll_timeout(&error) => {}
            Err(error) => return Err(format!("read operator gdb stream: {error}")),
        }

        let Some(read) = read_and_forward_active_backend(process, &mut buffer)? else {
            continue;
        };
        let units = backend_decoder
            .push(&buffer[..read])
            .map_err(|error| format!("decode QEMU RSP stream: {error}"))?;
        for unit in units {
            match unit {
                RspUnit::Nack => {
                    pending_state.pop_front();
                    resolve_pending_response(process)?;
                }
                RspUnit::Packet(response) if !is_async_console_packet(&response) => {
                    if let Some(request) = pending_state.pop_front() {
                        record_semantic_response(process, &request, &response)?;
                        resolve_pending_response(process)?;
                    }
                }
                RspUnit::Ack | RspUnit::Interrupt | RspUnit::Packet(_) => {}
            }
        }
    }
}

fn read_and_forward_active_backend(
    process: &SharedGatewayProcess,
    buffer: &mut [u8],
) -> Result<Option<usize>, String> {
    with_gateway(process, |gateway| {
        let Some((_, stream)) = gateway.active.as_mut() else {
            return Ok(None);
        };
        stream
            .set_read_timeout(Some(RSP_RELAY_POLL_TIMEOUT))
            .map_err(|error| format!("set active QEMU RSP read timeout: {error}"))?;
        let read = match stream.read(buffer) {
            Ok(0) => Err(String::from("active QEMU RSP backend closed")),
            Ok(read) => Ok(Some(read)),
            Err(error) if is_poll_timeout(&error) => Ok(None),
            Err(error) => Err(format!("read active QEMU RSP backend: {error}")),
        }?;
        if let Some(read) = read {
            let operator = gateway
                .operator_writer
                .as_mut()
                .ok_or_else(|| String::from("operator gdb connection is not active"))?;
            operator
                .write_all(&buffer[..read])
                .map_err(|error| format!("forward QEMU RSP bytes to operator gdb: {error}"))?;
        }
        Ok(read)
    })
}

fn handle_operator_rsp_unit(
    process: &SharedGatewayProcess,
    unit: RspUnit,
    pending_state: &mut VecDeque<Vec<u8>>,
    synthetic_stop_ack_pending: &mut bool,
) -> Result<(), String> {
    match unit {
        RspUnit::Ack if *synthetic_stop_ack_pending => {
            *synthetic_stop_ack_pending = false;
            Ok(())
        }
        RspUnit::Ack => write_active_backend(process, b"+").map(|_| ()),
        RspUnit::Nack => write_active_backend(process, b"-").map(|_| ()),
        RspUnit::Interrupt => write_rsp_rejection(process, b"E31", false),
        RspUnit::Packet(packet) => match classify_rsp_packet(&packet) {
            RspDisposition::ForwardToQemu => {
                if !admit_operator_request(process, &packet)? {
                    return write_rsp_rejection(process, b"E20", true);
                }
                pending_state.push_back(packet);
                Ok(())
            }
            RspDisposition::SchedulerRunControl => write_rsp_rejection(process, b"E31", true),
            RspDisposition::RejectReadOnly => write_rsp_rejection(process, b"E22", true),
            RspDisposition::RejectUnsupported => write_rsp_rejection(process, b"E01", true),
        },
    }
}

fn admit_operator_request(process: &SharedGatewayProcess, packet: &[u8]) -> Result<bool, String> {
    with_gateway(process, |gateway| {
        let Some((_, backend)) = gateway.active.as_mut() else {
            return Ok(false);
        };
        backend
            .write_all(packet)
            .map_err(|error| format!("forward operator RSP packet to QEMU: {error}"))?;
        gateway.rsp_responses_pending = gateway.rsp_responses_pending.saturating_add(1);
        Ok(true)
    })
}

fn write_active_backend(process: &SharedGatewayProcess, bytes: &[u8]) -> Result<bool, String> {
    with_gateway(process, |gateway| {
        let Some((_, backend)) = gateway.active.as_mut() else {
            return Ok(false);
        };
        backend
            .write_all(bytes)
            .map_err(|error| format!("forward operator RSP bytes to QEMU: {error}"))?;
        Ok(true)
    })
}

fn write_rsp_rejection(
    process: &SharedGatewayProcess,
    payload: &[u8],
    acknowledge_request: bool,
) -> Result<(), String> {
    if acknowledge_request {
        write_operator_bytes(process, b"+")?;
    }
    write_operator_bytes(process, &encode_rsp_packet(payload))
}

fn write_operator_bytes(process: &SharedGatewayProcess, bytes: &[u8]) -> Result<(), String> {
    with_gateway(process, |gateway| {
        let operator = gateway
            .operator_writer
            .as_mut()
            .ok_or_else(|| String::from("operator gdb connection is not active"))?;
        operator
            .write_all(bytes)
            .map_err(|error| format!("write operator gdb bytes: {error}"))
    })
}

fn resolve_pending_response(process: &SharedGatewayProcess) -> Result<(), String> {
    with_gateway(process, |gateway| {
        gateway.rsp_responses_pending = gateway.rsp_responses_pending.saturating_sub(1);
        Ok(())
    })
}

fn record_semantic_response(
    process: &SharedGatewayProcess,
    request: &[u8],
    response: &[u8],
) -> Result<(), String> {
    if rsp_payload(response) != b"OK" {
        return Ok(());
    }
    with_gateway(process, |gateway| {
        let before = gateway.model.rsp_state().clone();
        gateway.model.observe_acknowledged_rsp(request);
        if gateway.model.rsp_state() != &before {
            gateway.rsp_state_epoch = gateway.rsp_state_epoch.saturating_add(1);
        }
        Ok(())
    })
}

fn is_async_console_packet(packet: &[u8]) -> bool {
    let payload = rsp_payload(packet);
    payload.starts_with(b"O") && payload != b"OK"
}

fn rsp_payload(packet: &[u8]) -> &[u8] {
    &packet[1..packet.len() - 3]
}

fn is_poll_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
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
        DebugGatewayMessageKind::OperatorStatus => DebugGatewayErrorCode::InvalidRequest,
        DebugGatewayMessageKind::RspData
        | DebugGatewayMessageKind::ExecOpen
        | DebugGatewayMessageKind::PtyOpen
        | DebugGatewayMessageKind::SshOpen
        | DebugGatewayMessageKind::ChannelData
        | DebugGatewayMessageKind::ChannelClose => DebugGatewayErrorCode::Unsupported,
        DebugGatewayMessageKind::Hello
        | DebugGatewayMessageKind::HelloAck
        | DebugGatewayMessageKind::Ack
        | DebugGatewayMessageKind::BackendStatusAck
        | DebugGatewayMessageKind::OperatorStatusAck
        | DebugGatewayMessageKind::RunControl
        | DebugGatewayMessageKind::Error => DebugGatewayErrorCode::InvalidRequest,
    }
}

struct GatewayArguments {
    control_socket: PathBuf,
    gdb_listen: Option<SocketAddr>,
}

fn gateway_arguments() -> Result<GatewayArguments, String> {
    let mut arguments = env::args_os();
    let program = arguments.next();
    let program = program
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("crucible-debug-gateway");
    let mut control_socket = None;
    let mut gdb_listen = None;
    let mut allow_unauthenticated_gdb = false;
    while let Some(flag) = arguments.next() {
        if flag == std::ffi::OsStr::new("--allow-unauthenticated-gdb") {
            allow_unauthenticated_gdb = true;
            continue;
        }
        let value = arguments.next().ok_or_else(|| gateway_usage(program))?;
        if flag == std::ffi::OsStr::new("--control-socket") && control_socket.is_none() {
            control_socket = Some(PathBuf::from(value));
        } else if flag == std::ffi::OsStr::new("--gdb-listen") {
            gdb_listen = Some(
                value
                    .into_string()
                    .map_err(|_| String::from("gdb listen address is not UTF-8"))?,
            );
        } else {
            return Err(gateway_usage(program));
        }
    }
    let control_socket = control_socket.ok_or_else(|| String::from("missing control socket"))?;
    if !control_socket.is_absolute() {
        return Err(String::from("control socket path must be absolute"));
    }
    if gdb_listen.is_some() && !allow_unauthenticated_gdb {
        return Err(String::from(
            "--gdb-listen requires explicit --allow-unauthenticated-gdb trusted-loopback policy",
        ));
    }
    let gdb_listen = allow_unauthenticated_gdb
        .then(|| gdb_listen.unwrap_or_else(|| String::from("127.0.0.1:0")))
        .map(|listen| {
            let listen = listen
                .parse::<SocketAddr>()
                .map_err(|error| format!("parse gdb listen address: {error}"))?;
            if !listen.ip().is_loopback() {
                return Err(String::from(
                    "standalone gateway gdb listener must use a loopback address",
                ));
            }
            Ok(listen)
        })
        .transpose()?;
    Ok(GatewayArguments {
        control_socket,
        gdb_listen,
    })
}

fn gateway_usage(program: &str) -> String {
    format!(
        "usage: {program} --control-socket <absolute-path> [--allow-unauthenticated-gdb [--gdb-listen <loopback-address>]]"
    )
}

fn run() -> Result<(), String> {
    let arguments = gateway_arguments()?;
    let gdb_listener = arguments
        .gdb_listen
        .map(|listen| {
            TcpListener::bind(listen)
                .map_err(|error| format!("bind operator gdb listener {listen}: {error}"))
        })
        .transpose()?;
    let operator_listen = gdb_listener
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()
        .map_err(|error| format!("inspect operator gdb listener: {error}"))?;
    let process = Arc::new(Mutex::new(GatewayProcess::new(operator_listen)));
    if let Some(gdb_listener) = gdb_listener {
        spawn_operator_listener(process.clone(), gdb_listener)?;
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
mod tests {
    use std::thread;

    use super::*;

    fn write_and_close(bytes: Vec<u8>) -> UnixStream {
        let (reader, mut writer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("Unix stream pair should open: {error}"));
        thread::spawn(move || {
            writer
                .write_all(&bytes)
                .unwrap_or_else(|error| panic!("test request should write: {error}"));
        });
        reader
    }

    fn serve_frames(
        process: &SharedGatewayProcess,
        frames: Vec<DebugGatewayFrame>,
    ) -> Vec<DebugGatewayFrame> {
        let mut bytes = Vec::new();
        for frame in frames {
            bytes.extend(
                frame
                    .encode()
                    .unwrap_or_else(|error| panic!("request should encode: {error}")),
            );
        }
        let (mut client, server) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("Unix stream pair should open: {error}"));
        client
            .write_all(&bytes)
            .unwrap_or_else(|error| panic!("requests should write: {error}"));
        client
            .shutdown(std::net::Shutdown::Write)
            .unwrap_or_else(|error| panic!("test client should half-close: {error}"));
        serve_connection(process, server)
            .unwrap_or_else(|error| panic!("requests should be served: {error}"));

        let mut replies = Vec::new();
        while let Some(bytes) =
            read_frame(&mut client).unwrap_or_else(|error| panic!("reply should read: {error}"))
        {
            replies.push(
                decode_debug_gateway_frame(&bytes)
                    .unwrap_or_else(|error| panic!("reply should decode: {error}")),
            );
        }
        replies
    }

    fn hello() -> DebugGatewayFrame {
        DebugGatewayFrame::v1(DebugGatewayMessageKind::Hello, 0, b"v1".to_vec())
            .unwrap_or_else(|error| panic!("hello should build: {error}"))
    }

    fn test_process() -> SharedGatewayProcess {
        Arc::new(Mutex::new(GatewayProcess::new(Some(
            "127.0.0.1:12345"
                .parse()
                .unwrap_or_else(|error| panic!("test listener should parse: {error}")),
        ))))
    }

    #[test]
    fn partial_header_is_a_connection_error_without_mutating_process_state() {
        let process = test_process();
        let before = with_gateway(&process, |process| Ok(process.model.clone()))
            .unwrap_or_else(|error| panic!("test process should lock: {error}"));
        let error = match serve_connection(&process, write_and_close(b"CRDBG".to_vec())) {
            Ok(()) => panic!("partial header must fail"),
            Err(error) => error,
        };

        assert!(error.contains("truncated debugger gateway frame header"));
        let after = with_gateway(&process, |process| Ok(process.model.clone()))
            .unwrap_or_else(|error| panic!("test process should lock: {error}"));
        assert_eq!(after, before);
    }

    #[test]
    fn truncated_payload_is_a_connection_error_without_mutating_process_state() {
        let process = test_process();
        let before = with_gateway(&process, |process| Ok(process.model.clone()))
            .unwrap_or_else(|error| panic!("test process should lock: {error}"));
        let mut bytes = DebugGatewayFrame::v1(DebugGatewayMessageKind::Hello, 0, b"v1".to_vec())
            .unwrap_or_else(|error| panic!("hello should build: {error}"))
            .encode()
            .unwrap_or_else(|error| panic!("hello should encode: {error}"));
        bytes.pop();

        assert!(serve_connection(&process, write_and_close(bytes)).is_err());
        let after = with_gateway(&process, |process| Ok(process.model.clone()))
            .unwrap_or_else(|error| panic!("test process should lock: {error}"));
        assert_eq!(after, before);
    }

    #[test]
    fn negotiation_rejection_has_a_typed_correlated_error() {
        let (mut client, server) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("Unix stream pair should open: {error}"));
        let request =
            DebugGatewayFrame::v1(DebugGatewayMessageKind::RspData, 19, b"$?#3f".to_vec())
                .unwrap_or_else(|error| panic!("request should build: {error}"))
                .encode()
                .unwrap_or_else(|error| panic!("request should encode: {error}"));
        client
            .write_all(&request)
            .unwrap_or_else(|error| panic!("request should write: {error}"));
        client
            .shutdown(std::net::Shutdown::Write)
            .unwrap_or_else(|error| panic!("test client should half-close: {error}"));

        let process = test_process();
        serve_connection(&process, server)
            .unwrap_or_else(|error| panic!("valid rejected request should be served: {error}"));
        let reply = read_frame(&mut client)
            .unwrap_or_else(|error| panic!("reply should read: {error}"))
            .unwrap_or_else(|| panic!("reply should be present"));
        let reply = decode_debug_gateway_frame(&reply)
            .unwrap_or_else(|error| panic!("reply should decode: {error}"));
        let payload = DebugGatewayErrorPayload::decode(&reply.payload)
            .unwrap_or_else(|error| panic!("error should be typed: {error}"));

        assert_eq!(reply.kind, DebugGatewayMessageKind::Error);
        assert_eq!(reply.stream_id, 19);
        assert_eq!(payload.code, DebugGatewayErrorCode::ProtocolViolation);
    }

    #[test]
    fn diagnostics_are_bounded_on_character_boundaries() {
        let message = "é".repeat(600);
        let bounded = bounded_diagnostic(&message);
        assert_eq!(bounded.chars().count(), 515);
        assert!(bounded.ends_with("..."));
    }

    #[test]
    fn persistent_rsp_state_requires_semantic_ok_response() {
        let process = test_process();
        let request = encode_rsp_packet(b"Z1,4000,1");
        record_semantic_response(&process, &request, &encode_rsp_packet(b"E22"))
            .unwrap_or_else(|error| panic!("semantic rejection should record: {error}"));
        let (state_after_error, epoch_after_error) = with_gateway(&process, |gateway| {
            Ok((gateway.model.rsp_state().clone(), gateway.rsp_state_epoch))
        })
        .unwrap_or_else(|error| panic!("test process should lock: {error}"));
        assert!(state_after_error.hardware_breakpoints.is_empty());
        assert_eq!(epoch_after_error, 0);

        record_semantic_response(&process, &request, &encode_rsp_packet(b"OK"))
            .unwrap_or_else(|error| panic!("semantic success should record: {error}"));
        let (state_after_ok, epoch_after_ok) = with_gateway(&process, |gateway| {
            Ok((gateway.model.rsp_state().clone(), gateway.rsp_state_epoch))
        })
        .unwrap_or_else(|error| panic!("test process should lock: {error}"));
        assert!(
            state_after_ok
                .hardware_breakpoints
                .contains(b"Z1,4000,1".as_slice())
        );
        assert_eq!(epoch_after_ok, 1);
    }

    #[test]
    fn commit_rejects_candidate_hydrated_before_rsp_state_change() {
        let process = test_process();
        let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
            .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
        let (stream, peer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
        let prepared = with_gateway(&process, |gateway| {
            let prepared = gateway
                .model
                .prepare_backend(endpoint)
                .map_err(|error| error.to_string())?;
            gateway.prepared = Some((prepared.generation, stream, gateway.rsp_state_epoch));
            Ok(prepared)
        })
        .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));
        record_semantic_response(
            &process,
            &encode_rsp_packet(b"Hg1"),
            &encode_rsp_packet(b"OK"),
        )
        .unwrap_or_else(|error| panic!("thread selection should record: {error}"));
        let commit = DebugGatewayFrame::v1(
            DebugGatewayMessageKind::BackendCommit,
            0,
            prepared.generation.0.to_be_bytes(),
        )
        .unwrap_or_else(|error| panic!("commit should build: {error}"));

        let error = match with_gateway(&process, |gateway| gateway.handle(commit)) {
            Ok(_) => panic!("stale prepared debugger state must reject commit"),
            Err(error) => error,
        };
        assert!(error.contains("stale"));
        let active = with_gateway(&process, |gateway| Ok(gateway.model.active().cloned()))
            .unwrap_or_else(|error| panic!("test process should lock: {error}"));
        assert!(active.is_none());
        drop(peer);
    }

    #[test]
    fn packet_admitted_after_commit_barrier_reaches_only_new_backend() {
        let process = test_process();
        let (old_stream, mut old_peer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("old backend pair should open: {error}"));
        let (new_stream, mut new_peer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("new backend pair should open: {error}"));
        old_peer
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap_or_else(|error| panic!("old backend timeout should set: {error}"));
        new_peer
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap_or_else(|error| panic!("new backend timeout should set: {error}"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("operator listener should bind: {error}"));
        let operator_peer = TcpStream::connect(
            listener
                .local_addr()
                .unwrap_or_else(|error| panic!("operator address should inspect: {error}")),
        )
        .unwrap_or_else(|error| panic!("operator peer should connect: {error}"));
        let (operator_writer, _) = listener
            .accept()
            .unwrap_or_else(|error| panic!("operator writer should accept: {error}"));
        let new_generation = with_gateway(&process, |gateway| {
            let old = gateway
                .model
                .prepare_backend(
                    QemuRspEndpoint::new("/run/crucible/old.sock")
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
            gateway
                .model
                .commit_backend(old.generation)
                .map_err(|error| error.to_string())?;
            gateway.active = Some((old.generation, old_stream));
            let new = gateway
                .model
                .prepare_backend(
                    QemuRspEndpoint::new("/run/crucible/new.sock")
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
            gateway.prepared = Some((new.generation, new_stream, gateway.rsp_state_epoch));
            gateway.operator_writer = Some(operator_writer);
            Ok(new.generation)
        })
        .unwrap_or_else(|error| panic!("backend fixture should configure: {error}"));
        let commit = DebugGatewayFrame::v1(
            DebugGatewayMessageKind::BackendCommit,
            0,
            new_generation.0.to_be_bytes(),
        )
        .unwrap_or_else(|error| panic!("commit should build: {error}"));
        with_gateway(&process, |gateway| gateway.handle(commit))
            .unwrap_or_else(|error| panic!("commit barrier should complete: {error}"));
        assert!(
            write_active_backend(&process, b"$g#67")
                .unwrap_or_else(|error| panic!("post-commit packet should write: {error}"))
        );

        let mut packet = [0_u8; 5];
        new_peer
            .read_exact(&mut packet)
            .unwrap_or_else(|error| panic!("new backend should receive packet: {error}"));
        assert_eq!(&packet, b"$g#67");
        let mut old_byte = [0_u8; 1];
        assert!(old_peer.read(&mut old_byte).is_err());
        drop(operator_peer);
    }

    #[test]
    fn reconnect_recovers_prepare_whose_acknowledgement_was_lost() {
        let process = test_process();
        let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
            .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
        let (stream, peer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
        drop(peer);
        let prepared = with_gateway(&process, |process| {
            let prepared = process
                .model
                .prepare_backend(endpoint)
                .map_err(|error| error.to_string())?;
            process.prepared = Some((prepared.generation, stream, process.rsp_state_epoch));
            Ok(prepared)
        })
        .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));

        let status = DebugGatewayFrame::v1(DebugGatewayMessageKind::BackendStatus, 0, Vec::new())
            .unwrap_or_else(|error| panic!("status request should build: {error}"));
        let replies = serve_frames(&process, vec![hello(), status]);
        let recovered = DebugGatewayBackendStatus::decode(&replies[1].payload)
            .unwrap_or_else(|error| panic!("status should decode: {error}"));

        assert_eq!(replies[1].kind, DebugGatewayMessageKind::BackendStatusAck);
        assert_eq!(
            recovered.prepared.map(|identity| identity.generation),
            Some(prepared.generation.0)
        );
        assert!(recovered.active.is_none());
    }

    #[test]
    fn reconnect_repeats_commit_whose_acknowledgement_was_lost() {
        let process = test_process();
        let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
            .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
        let (stream, peer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
        drop(peer);
        let prepared = with_gateway(&process, |process| {
            let prepared = process
                .model
                .prepare_backend(endpoint)
                .map_err(|error| error.to_string())?;
            process.prepared = Some((prepared.generation, stream, process.rsp_state_epoch));
            Ok(prepared)
        })
        .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));
        let commit = DebugGatewayFrame::v1(
            DebugGatewayMessageKind::BackendCommit,
            0,
            prepared.generation.0.to_be_bytes(),
        )
        .unwrap_or_else(|error| panic!("commit should build: {error}"));

        let _lost_reply = with_gateway(&process, |process| process.handle(commit.clone()))
            .unwrap_or_else(|error| panic!("first commit should succeed: {error}"));
        let status = DebugGatewayFrame::v1(DebugGatewayMessageKind::BackendStatus, 0, Vec::new())
            .unwrap_or_else(|error| panic!("status request should build: {error}"));
        let replies = serve_frames(&process, vec![hello(), commit, status]);
        let recovered = DebugGatewayBackendStatus::decode(&replies[2].payload)
            .unwrap_or_else(|error| panic!("status should decode: {error}"));

        assert_eq!(replies[1].kind, DebugGatewayMessageKind::Ack);
        assert_eq!(
            recovered.active.map(|identity| identity.generation),
            Some(prepared.generation.0)
        );
        assert!(recovered.prepared.is_none());
    }
}
