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
//! backend replacement. Scheduler run control is queued for the host session;
//! guest channels fail closed until their shared-memory routes are active.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
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

struct GatewayProcess {
    model: DebugGateway,
    active: Option<(BackendGeneration, UnixStream)>,
    prepared: Option<(BackendGeneration, UnixStream, u64)>,
    operator_listen: Option<SocketAddr>,
    operator_writer: Option<TcpStream>,
    operator_admission_paused: bool,
    rsp_responses_pending: usize,
    rsp_state_epoch: u64,
    replacement_epoch: u64,
    operator_epoch: u32,
    next_run_control_stream: u32,
    run_control_requests: VecDeque<(u32, u32, Vec<u8>)>,
    run_control_inflight: Option<(u32, u32, Vec<u8>)>,
    run_control_completed: Option<(u32, Vec<u8>, Vec<u8>)>,
    scheduler_response_pending: Option<Vec<u8>>,
    scheduler_lease_active: bool,
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
            operator_admission_paused: false,
            rsp_responses_pending: 0,
            rsp_state_epoch: 0,
            replacement_epoch: 0,
            operator_epoch: 0,
            next_run_control_stream: 0,
            run_control_requests: VecDeque::new(),
            run_control_inflight: None,
            run_control_completed: None,
            scheduler_response_pending: None,
            scheduler_lease_active: false,
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
                        .map(|listen| listen.to_string().into_bytes())
                        .unwrap_or_default(),
                )
            }
            DebugGatewayMessageKind::SchedulerLease => Err(String::from(
                "scheduler lease must use the ownership dispatcher",
            )),
            DebugGatewayMessageKind::RspData => {
                Err(String::from("RSP data must use the scheduler dispatcher"))
            }
            DebugGatewayMessageKind::RunControl => {
                if !frame.payload.is_empty() {
                    return Err(String::from("run-control poll payload must be empty"));
                }
                let stream_id = frame.stream_id;
                match self.run_control_requests.pop_front() {
                    Some((stream_id, operator_epoch, packet)) => {
                        self.run_control_inflight =
                            Some((stream_id, operator_epoch, packet.clone()));
                        response(DebugGatewayMessageKind::RunControl, stream_id, packet)
                    }
                    None if self.run_control_inflight.is_some() => {
                        let (stream_id, _operator_epoch, packet) = self
                            .run_control_inflight
                            .as_ref()
                            .cloned()
                            .ok_or_else(|| String::from("run-control request disappeared"))?;
                        response(DebugGatewayMessageKind::RunControl, stream_id, packet)
                    }
                    None => response(DebugGatewayMessageKind::RunControl, stream_id, Vec::new()),
                }
            }
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
            && self.scheduler_response_pending.is_none()
            && !self.scheduler_lease_active
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
            let operator = gateway
                .operator_writer
                .as_mut()
                .ok_or_else(|| String::from("operator gdb connection is not active"))?;
            let encoded_response = encode_rsp_packet(&frame.payload);
            operator.write_all(&encoded_response).map_err(|error| {
                format!("write scheduler RSP response to operator gdb: {error}")
            })?;
            gateway.run_control_inflight = None;
            gateway.run_control_completed = Some((frame.stream_id, request, frame.payload.clone()));
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
    } else {
        with_gateway(process, |process| process.handle(frame))
    }
}

fn scheduler_lease(
    process: &SharedGatewayProcess,
    payload: &[u8],
) -> Result<DebugGatewayFrame, String> {
    let acquire = match payload {
        [1] => true,
        [2] => false,
        _ => {
            return Err(String::from(
                "scheduler lease payload must be acquire=1 or release=2",
            ));
        }
    };
    if acquire {
        let deadline = Instant::now() + QEMU_RSP_TIMEOUT;
        loop {
            let acquired = with_gateway(process, |gateway| {
                if gateway.scheduler_lease_active {
                    return Ok(true);
                }
                if !gateway.run_control_requests.is_empty()
                    || gateway.run_control_inflight.is_some()
                    || gateway.scheduler_response_pending.is_some()
                    || gateway.prepared.is_some()
                {
                    return Err(String::from(
                        "cannot acquire scheduler ownership with pending run-control or replacement work",
                    ));
                }
                let breakpoints = gateway
                    .model
                    .rsp_state()
                    .hardware_breakpoints
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>();
                if breakpoints
                    .iter()
                    .any(|breakpoint| breakpoint.first() != Some(&b'Z'))
                {
                    return Err(String::from("stored hardware breakpoint is malformed"));
                }
                if gateway.active.is_none() {
                    return Err(String::from(
                        "scheduler ownership requires an active backend",
                    ));
                }
                gateway.operator_admission_paused = true;
                if gateway.rsp_responses_pending != 0 {
                    return Ok(false);
                }
                let active = gateway.active.as_mut().ok_or_else(|| {
                    String::from("scheduler ownership requires an active backend")
                })?;
                let mut removed = Vec::new();
                for breakpoint in breakpoints {
                    let mut remove = breakpoint.clone();
                    remove[0] = b'z';
                    match exchange_rsp_packet(&mut active.1, &remove) {
                        Ok(reply) if reply == b"OK" => removed.push(breakpoint),
                        Ok(reply) => {
                            let rollback = restore_scheduler_breakpoints(&mut active.1, &removed);
                            gateway.operator_admission_paused = false;
                            rollback?;
                            return Err(format!(
                                "QEMU rejected scheduler breakpoint suspension with {}",
                                String::from_utf8_lossy(&reply)
                            ));
                        }
                        Err(error) => {
                            let rollback = restore_scheduler_breakpoints(&mut active.1, &removed);
                            gateway.operator_admission_paused = false;
                            rollback?;
                            return Err(error);
                        }
                    }
                }
                if let Err(error) = resume_scheduler_backend(&mut active.1) {
                    let rollback = restore_scheduler_breakpoints(&mut active.1, &removed);
                    gateway.operator_admission_paused = false;
                    rollback?;
                    return Err(error);
                }
                gateway.scheduler_lease_active = true;
                Ok(true)
            })?;
            if acquired {
                break;
            }
            if Instant::now() >= deadline {
                with_gateway(process, |gateway| {
                    gateway.operator_admission_paused = false;
                    Ok(())
                })?;
                return Err(String::from(
                    "timed out waiting for the scheduler ownership packet boundary",
                ));
            }
            std::thread::yield_now();
        }
    } else {
        with_gateway(process, |gateway| {
            if !gateway.scheduler_lease_active {
                return Ok(());
            }
            let breakpoints = gateway
                .model
                .rsp_state()
                .hardware_breakpoints
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            let active = gateway
                .active
                .as_mut()
                .ok_or_else(|| String::from("scheduler ownership lost its active backend"))?;
            interrupt_scheduler_backend(&mut active.1)?;
            restore_scheduler_breakpoints(&mut active.1, &breakpoints)?;
            gateway.scheduler_lease_active = false;
            gateway.operator_admission_paused = false;
            Ok(())
        })?;
    }
    response(DebugGatewayMessageKind::Ack, 0, Vec::new())
}

fn resume_scheduler_backend(stream: &mut UnixStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(QEMU_RSP_TIMEOUT))
        .map_err(|error| format!("set QEMU scheduler-resume timeout: {error}"))?;
    stream
        .write_all(&encode_rsp_packet(b"c"))
        .map_err(|error| format!("resume QEMU for scheduler ownership: {error}"))?;
    let mut decoder = RspStreamDecoder::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("read QEMU scheduler-resume acknowledgement: {error}"))?;
        if read == 0 {
            return Err(String::from(
                "QEMU RSP backend closed before scheduler resume was acknowledged",
            ));
        }
        let mut acknowledged = false;
        for unit in decoder
            .push(&buffer[..read])
            .map_err(|error| format!("decode QEMU scheduler-resume acknowledgement: {error}"))?
        {
            match unit {
                RspUnit::Ack => acknowledged = true,
                RspUnit::Nack => {
                    return Err(String::from("QEMU rejected scheduler resume"));
                }
                RspUnit::Packet(_) | RspUnit::Interrupt => {
                    return Err(String::from(
                        "QEMU stopped unexpectedly while scheduler ownership was acquired",
                    ));
                }
            }
        }
        if acknowledged {
            return Ok(());
        }
    }
}

fn interrupt_scheduler_backend(stream: &mut UnixStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(QEMU_RSP_TIMEOUT))
        .map_err(|error| format!("set QEMU scheduler-stop timeout: {error}"))?;
    stream
        .write_all(&[0x03])
        .map_err(|error| format!("interrupt QEMU after scheduler ownership: {error}"))?;
    let mut decoder = RspStreamDecoder::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("read QEMU scheduler-stop response: {error}"))?;
        if read == 0 {
            return Err(String::from(
                "QEMU RSP backend closed before scheduler stop was reported",
            ));
        }
        for unit in decoder
            .push(&buffer[..read])
            .map_err(|error| format!("decode QEMU scheduler-stop response: {error}"))?
        {
            match unit {
                RspUnit::Packet(packet)
                    if matches!(rsp_payload(&packet).first(), Some(b'S' | b'T')) =>
                {
                    stream
                        .write_all(b"+")
                        .map_err(|error| format!("acknowledge QEMU scheduler stop: {error}"))?;
                    return Ok(());
                }
                RspUnit::Ack => {}
                RspUnit::Nack | RspUnit::Interrupt | RspUnit::Packet(_) => {
                    return Err(String::from(
                        "QEMU returned an invalid scheduler-stop response",
                    ));
                }
            }
        }
    }
}

fn restore_scheduler_breakpoints(
    stream: &mut UnixStream,
    breakpoints: &[Vec<u8>],
) -> Result<(), String> {
    for breakpoint in breakpoints {
        let reply = exchange_rsp_packet(stream, breakpoint)?;
        if reply != b"OK" {
            return Err(format!(
                "QEMU rejected scheduler breakpoint restoration with {}",
                String::from_utf8_lossy(&reply)
            ));
        }
    }
    Ok(())
}

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
                let cleanup = restore_backend_after_operator_disconnect(process, result.is_ok());
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

fn restore_backend_after_operator_disconnect(
    process: &SharedGatewayProcess,
    relay_closed_cleanly: bool,
) -> Result<(), String> {
    let reconnect = with_gateway(process, |gateway| {
        let recovery_is_unambiguous =
            relay_closed_cleanly && gateway.replacement_boundary_is_clean();
        let active = recovery_is_unambiguous
            .then(|| gateway.model.active().cloned())
            .flatten();
        if !recovery_is_unambiguous {
            gateway.model.deactivate_backend();
        }
        gateway.active = None;
        gateway.operator_writer = None;
        gateway.rsp_responses_pending = 0;
        gateway.run_control_requests.clear();
        gateway.run_control_inflight = None;
        gateway.scheduler_response_pending = None;
        Ok(active.map(|active| {
            (
                active.generation,
                active.endpoint,
                gateway.model.rsp_state().clone(),
                gateway.rsp_state_epoch,
            )
        }))
    })?;
    let Some((generation, endpoint, state, state_epoch)) = reconnect else {
        return Ok(());
    };

    let restored = connect_candidate(&endpoint).and_then(|mut stream| {
        validate_and_hydrate_candidate(&mut stream, &state)?;
        with_gateway(process, |gateway| {
            if gateway.active.is_some() {
                return Ok(true);
            }
            let unchanged = gateway.model.active().is_some_and(|active| {
                active.generation == generation && active.endpoint == endpoint
            }) && gateway.rsp_state_epoch == state_epoch;
            if !unchanged {
                return Ok(false);
            }
            gateway.active = Some((generation, stream));
            Ok(true)
        })
    });
    match restored {
        Ok(true) => Ok(()),
        Ok(false) => Ok(()),
        Err(error) => {
            with_gateway(process, |gateway| {
                let failed_backend_is_still_active = gateway.active.is_none()
                    && gateway.model.active().is_some_and(|active| {
                        active.generation == generation && active.endpoint == endpoint
                    });
                if failed_backend_is_still_active {
                    gateway.model.deactivate_backend();
                }
                Ok(())
            })?;
            Err(format!(
                "restore QEMU RSP backend after operator disconnect: {error}"
            ))
        }
    }
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
            gateway.operator_epoch = gateway
                .operator_epoch
                .checked_add(1)
                .ok_or_else(|| String::from("operator connection generation exhausted"))?;
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
            // The prepare barrier drains the old backend before commit. A
            // packet waiting at that barrier is admitted only after commit and
            // must retain its request/response correlation on the new backend.
            synthetic_stop_ack_pending = false;
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
        RspUnit::Ack => {
            if acknowledge_scheduler_response(process, false)? {
                return Ok(());
            }
            if *synthetic_stop_ack_pending {
                *synthetic_stop_ack_pending = false;
                return Ok(());
            }
            write_active_backend(process, b"+").map(|_| ())
        }
        RspUnit::Nack => {
            if acknowledge_scheduler_response(process, true)? {
                return Ok(());
            }
            write_active_backend(process, b"-").map(|_| ())
        }
        RspUnit::Interrupt => queue_scheduler_run_control(process, vec![0x03], false),
        RspUnit::Packet(packet) => match classify_rsp_packet(&packet) {
            RspDisposition::ForwardToQemu => {
                if !admit_operator_request(process, &packet)? {
                    return write_rsp_rejection(process, b"E20", true);
                }
                pending_state.push_back(packet);
                Ok(())
            }
            RspDisposition::SchedulerRunControl => {
                queue_scheduler_run_control(process, rsp_payload(&packet).to_vec(), true)
            }
            RspDisposition::RejectReadOnly => write_rsp_rejection(process, b"E22", true),
            RspDisposition::RejectUnsupported => write_rsp_rejection(process, b"E01", true),
        },
    }
}

fn acknowledge_scheduler_response(
    process: &SharedGatewayProcess,
    retransmit: bool,
) -> Result<bool, String> {
    with_gateway(process, |gateway| {
        let Some(response) = gateway.scheduler_response_pending.as_ref() else {
            return Ok(false);
        };
        if retransmit {
            gateway
                .operator_writer
                .as_mut()
                .ok_or_else(|| String::from("operator gdb connection is not active"))?
                .write_all(response)
                .map_err(|error| format!("retransmit scheduler RSP response: {error}"))?;
        } else {
            gateway.scheduler_response_pending = None;
        }
        Ok(true)
    })
}

fn queue_scheduler_run_control(
    process: &SharedGatewayProcess,
    packet: Vec<u8>,
    acknowledge: bool,
) -> Result<(), String> {
    with_gateway(process, |gateway| {
        let is_interrupt = packet == [0x03];
        let duplicate = gateway
            .run_control_requests
            .front()
            .or(gateway.run_control_inflight.as_ref())
            .is_some_and(|(_, epoch, pending)| {
                *epoch == gateway.operator_epoch && pending == &packet
            });
        let completed_duplicate = gateway.scheduler_response_pending.is_some()
            && gateway
                .run_control_completed
                .as_ref()
                .is_some_and(|(_, completed, _)| completed == &packet);
        let request_pending = !gateway.run_control_requests.is_empty()
            || gateway.run_control_inflight.is_some()
            || gateway.scheduler_response_pending.is_some();
        let interrupt_can_supersede = is_interrupt && gateway.scheduler_response_pending.is_none();
        let admission_conflict =
            request_pending && !(duplicate || completed_duplicate || interrupt_can_supersede);
        if admission_conflict {
            return Err(String::from(
                "operator issued run control while a scheduler request is pending",
            ));
        }
        if acknowledge {
            gateway
                .operator_writer
                .as_mut()
                .ok_or_else(|| String::from("operator gdb connection is not active"))?
                .write_all(b"+")
                .map_err(|error| format!("acknowledge scheduler RSP request: {error}"))?;
        }
        if !duplicate && !completed_duplicate {
            if is_interrupt {
                gateway.run_control_requests.clear();
            }
            gateway.next_run_control_stream = gateway
                .next_run_control_stream
                .checked_add(1)
                .ok_or_else(|| String::from("run-control stream generation exhausted"))?;
            gateway.run_control_requests.push_back((
                gateway.next_run_control_stream,
                gateway.operator_epoch,
                packet,
            ));
        }
        Ok(())
    })
}

fn admit_operator_request(process: &SharedGatewayProcess, packet: &[u8]) -> Result<bool, String> {
    loop {
        let admitted = with_gateway(process, |gateway| {
            if gateway.operator_admission_paused {
                return Ok(None);
            }
            let Some((_, backend)) = gateway.active.as_mut() else {
                return Ok(Some(false));
            };
            backend
                .write_all(packet)
                .map_err(|error| format!("forward operator RSP packet to QEMU: {error}"))?;
            gateway.rsp_responses_pending = gateway.rsp_responses_pending.saturating_add(1);
            Ok(Some(true))
        })?;
        if let Some(admitted) = admitted {
            return Ok(admitted);
        }
        std::thread::yield_now();
    }
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
        DebugGatewayMessageKind::OperatorStatus | DebugGatewayMessageKind::SchedulerLease => {
            DebugGatewayErrorCode::InvalidRequest
        }
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
#[path = "main/tests.rs"]
mod tests;
