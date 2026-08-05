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
//! the process and active backend remain available for the next client. RSP
//! relay and guest channels intentionally fail closed until their persistent
//! asynchronous pumps are implemented.

#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use crucible_debug_gateway::{
    BackendGeneration, DebugGateway, QemuRspEndpoint, RspSessionState, RspStreamDecoder, RspUnit,
};
use crucible_protocol::debug_gateway::{
    DEBUG_GATEWAY_HEADER_LEN, DEBUG_GATEWAY_MAX_PAYLOAD, DebugGatewayBackendIdentity,
    DebugGatewayBackendStatus, DebugGatewayErrorCode, DebugGatewayErrorPayload, DebugGatewayFrame,
    DebugGatewayMessageKind, decode_debug_gateway_frame,
};

struct GatewayProcess {
    model: DebugGateway,
    _active: Option<UnixStream>,
    prepared: Option<(BackendGeneration, UnixStream)>,
}

const QEMU_RSP_TIMEOUT: Duration = Duration::from_secs(5);

impl GatewayProcess {
    fn new() -> Self {
        Self {
            model: DebugGateway::new(),
            _active: None,
            prepared: None,
        }
    }

    fn handle(&mut self, frame: DebugGatewayFrame) -> Result<DebugGatewayFrame, String> {
        match frame.kind {
            DebugGatewayMessageKind::Hello => {
                response(DebugGatewayMessageKind::HelloAck, 0, b"debug-gateway.v1")
            }
            DebugGatewayMessageKind::BackendPrepare => {
                let path = String::from_utf8(frame.payload)
                    .map_err(|error| format!("backend endpoint is not UTF-8: {error}"))?;
                let endpoint = QemuRspEndpoint::new(path)
                    .map_err(|error| format!("validate backend endpoint: {error}"))?;
                let mut stream = UnixStream::connect(endpoint.as_str())
                    .map_err(|error| format!("connect candidate QEMU RSP endpoint: {error}"))?;
                stream
                    .set_read_timeout(Some(QEMU_RSP_TIMEOUT))
                    .map_err(|error| format!("set candidate QEMU RSP read timeout: {error}"))?;
                stream
                    .set_write_timeout(Some(QEMU_RSP_TIMEOUT))
                    .map_err(|error| format!("set candidate QEMU RSP write timeout: {error}"))?;
                validate_and_hydrate_candidate(&mut stream, self.model.rsp_state())?;
                let prepared = self
                    .model
                    .prepare_backend(endpoint)
                    .map_err(|error| error.to_string())?;
                self.prepared = Some((prepared.generation, stream));
                response(
                    DebugGatewayMessageKind::Ack,
                    0,
                    prepared.generation.0.to_be_bytes(),
                )
            }
            DebugGatewayMessageKind::BackendCommit => {
                let generation = generation_payload(&frame.payload)?;
                if self.model.active().map(|active| active.generation) == Some(generation) {
                    return response(DebugGatewayMessageKind::Ack, 0, generation.0.to_be_bytes());
                }
                let Some((prepared_generation, stream)) = self.prepared.take() else {
                    return Err(String::from("no candidate QEMU RSP endpoint is prepared"));
                };
                if prepared_generation != generation {
                    self.prepared = Some((prepared_generation, stream));
                    return Err(String::from("prepared backend generation mismatch"));
                }
                self.model
                    .commit_backend(generation)
                    .map_err(|error| error.to_string())?;
                self._active = Some(stream);
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

fn serve_connection(process: &mut GatewayProcess, mut stream: UnixStream) -> Result<(), String> {
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
                process.handle(frame)
            }
        } else if !negotiated {
            error_code = DebugGatewayErrorCode::ProtocolViolation;
            Err(String::from(
                "debug gateway Hello must precede every other request",
            ))
        } else {
            process.handle(frame)
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
        | DebugGatewayMessageKind::RunControl
        | DebugGatewayMessageKind::Error => DebugGatewayErrorCode::InvalidRequest,
    }
}

fn control_socket_argument() -> Result<PathBuf, String> {
    let mut arguments = env::args_os();
    let program = arguments.next();
    let flag = arguments.next();
    let value = arguments.next();
    if flag.as_deref() != Some(std::ffi::OsStr::new("--control-socket"))
        || value.is_none()
        || arguments.next().is_some()
    {
        let program = program
            .as_deref()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("crucible-debug-gateway");
        return Err(format!("usage: {program} --control-socket <absolute-path>"));
    }
    let path = PathBuf::from(value.ok_or_else(|| String::from("missing control socket"))?);
    if !path.is_absolute() {
        return Err(String::from("control socket path must be absolute"));
    }
    Ok(path)
}

fn run() -> Result<(), String> {
    let path = control_socket_argument()?;
    let listener = UnixListener::bind(&path)
        .map_err(|error| format!("bind control socket {}: {error}", path.display()))?;
    let mut process = GatewayProcess::new();
    for connection in listener.incoming() {
        let stream = connection.map_err(|error| format!("accept control connection: {error}"))?;
        if let Err(error) = serve_connection(&mut process, stream) {
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
        process: &mut GatewayProcess,
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

    #[test]
    fn partial_header_is_a_connection_error_without_mutating_process_state() {
        let mut process = GatewayProcess::new();
        let before = process.model.clone();
        let error = serve_connection(&mut process, write_and_close(b"CRDBG".to_vec()))
            .expect_err("partial header must fail");

        assert!(error.contains("truncated debugger gateway frame header"));
        assert_eq!(process.model, before);
    }

    #[test]
    fn truncated_payload_is_a_connection_error_without_mutating_process_state() {
        let mut process = GatewayProcess::new();
        let before = process.model.clone();
        let mut bytes = DebugGatewayFrame::v1(DebugGatewayMessageKind::Hello, 0, b"v1".to_vec())
            .unwrap_or_else(|error| panic!("hello should build: {error}"))
            .encode()
            .unwrap_or_else(|error| panic!("hello should encode: {error}"));
        bytes.pop();

        assert!(serve_connection(&mut process, write_and_close(bytes)).is_err());
        assert_eq!(process.model, before);
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

        let mut process = GatewayProcess::new();
        serve_connection(&mut process, server)
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
    fn reconnect_recovers_prepare_whose_acknowledgement_was_lost() {
        let mut process = GatewayProcess::new();
        let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
            .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
        let prepared = process
            .model
            .prepare_backend(endpoint)
            .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));
        let (stream, peer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
        drop(peer);
        process.prepared = Some((prepared.generation, stream));

        let status = DebugGatewayFrame::v1(DebugGatewayMessageKind::BackendStatus, 0, Vec::new())
            .unwrap_or_else(|error| panic!("status request should build: {error}"));
        let replies = serve_frames(&mut process, vec![hello(), status]);
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
        let mut process = GatewayProcess::new();
        let endpoint = QemuRspEndpoint::new("/run/crucible/qemu-candidate.sock")
            .unwrap_or_else(|error| panic!("candidate endpoint should build: {error}"));
        let prepared = process
            .model
            .prepare_backend(endpoint)
            .unwrap_or_else(|error| panic!("candidate should prepare: {error}"));
        let (stream, peer) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("backend stream pair should open: {error}"));
        drop(peer);
        process.prepared = Some((prepared.generation, stream));
        let commit = DebugGatewayFrame::v1(
            DebugGatewayMessageKind::BackendCommit,
            0,
            prepared.generation.0.to_be_bytes(),
        )
        .unwrap_or_else(|error| panic!("commit should build: {error}"));

        let _lost_reply = process
            .handle(commit.clone())
            .unwrap_or_else(|error| panic!("first commit should succeed: {error}"));
        let status = DebugGatewayFrame::v1(DebugGatewayMessageKind::BackendStatus, 0, Vec::new())
            .unwrap_or_else(|error| panic!("status request should build: {error}"));
        let replies = serve_frames(&mut process, vec![hello(), commit, status]);
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
