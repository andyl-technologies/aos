//! Mediated QEMU gdbstub proxy.
//!
//! This module owns the safe host-side bridge between QEMU's raw gdbstub and
//! the operator-facing `--gdb-listen` endpoint. It is deliberately outside the
//! scheduler-facing [`crate::QemuNode`] channel bundle: forwarding debugger
//! packets here does not touch the shared-memory quantum path or frame delivery.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::QemuGdbstubChannelConfig;

const GDB_ERROR_MEMORY_PATCH_REFUSED: &str = "E22";

/// Errors returned while binding or serving the gdbstub proxy.
#[derive(Debug, Error)]
pub enum QemuGdbstubProxyError {
    /// An endpoint used an address family this proxy does not implement yet.
    #[error("{field} endpoint `{value}` is unsupported; expected a TCP endpoint")]
    UnsupportedEndpoint {
        /// Endpoint field being parsed.
        field: &'static str,
        /// Rejected endpoint text.
        value: String,
    },
    /// An endpoint was not a valid socket address.
    #[error("{field} endpoint `{value}` is not a socket address: {message}")]
    InvalidSocketAddress {
        /// Endpoint field being parsed.
        field: &'static str,
        /// Rejected endpoint text.
        value: String,
        /// Parser failure message.
        message: String,
    },
    /// The operator-facing listener could not be bound.
    #[error("failed to bind gdbstub proxy listener at {addr}: {source}")]
    Bind {
        /// Address requested by `--gdb-listen`.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The operator-facing listener could not report its bound address.
    #[error("failed to inspect gdbstub proxy listener address: {source}")]
    LocalAddr {
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The operator-facing listener could not be switched to non-blocking mode.
    #[error("failed to configure non-blocking gdbstub listener at {addr}: {source}")]
    SetNonblocking {
        /// Operator-facing listener address.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The proxy could not accept an operator connection.
    #[error("failed to accept operator gdb-protocol connection at {addr}: {source}")]
    Accept {
        /// Operator-facing listener address.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The proxy could not connect to QEMU's raw gdbstub endpoint.
    #[error("failed to connect to QEMU gdbstub at {addr}: {source}")]
    ConnectQemu {
        /// Parsed QEMU gdbstub endpoint.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The proxy could not clone a TCP stream for bidirectional forwarding.
    #[error("failed to clone {role} gdbstub stream: {source}")]
    CloneStream {
        /// Stream role being cloned.
        role: &'static str,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The proxy failed while forwarding a byte stream.
    #[error("failed to forward {direction} gdbstub bytes: {source}")]
    Forward {
        /// Forwarding direction.
        direction: &'static str,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The proxy could not write a local gdb-protocol response.
    #[error("failed to write local gdbstub response: {source}")]
    LocalResponse {
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// One forwarding half panicked.
    #[error("{direction} gdbstub forwarding thread panicked")]
    ForwardThreadPanicked {
        /// Forwarding direction.
        direction: &'static str,
    },
}

/// Canonical breakpoint handling policy for the mediated gdbstub proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuGdbstubBreakpointPolicy {
    hardware_breakpoints: bool,
}

impl QemuGdbstubBreakpointPolicy {
    /// Builds the default canonical policy backed by QEMU hardware breakpoints.
    #[must_use]
    pub const fn canonical_hardware_breakpoints() -> Self {
        Self {
            hardware_breakpoints: true,
        }
    }

    /// Builds a policy that refuses software breakpoints instead of patching memory.
    #[must_use]
    pub const fn canonical_without_hardware_breakpoints() -> Self {
        Self {
            hardware_breakpoints: false,
        }
    }

    /// Returns whether the proxy may translate software breakpoints to hardware.
    #[must_use]
    pub const fn hardware_breakpoints(self) -> bool {
        self.hardware_breakpoints
    }
}

/// A parsed gdbstub proxy endpoint pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuGdbstubProxy {
    qemu_addr: SocketAddr,
    operator_listen: SocketAddr,
    breakpoint_policy: QemuGdbstubBreakpointPolicy,
}

impl QemuGdbstubProxy {
    /// Builds a proxy endpoint pair from the launch-channel configuration.
    ///
    /// QEMU endpoints use the `tcp:<addr>:<port>` form accepted by QEMU `-gdb`.
    /// Operator endpoints use the `--gdb-listen` socket form `<addr>:<port>`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuGdbstubProxyError`] when either endpoint is not a supported
    /// TCP socket endpoint.
    pub fn new(channel: &QemuGdbstubChannelConfig) -> Result<Self, QemuGdbstubProxyError> {
        Ok(Self {
            qemu_addr: parse_qemu_tcp_endpoint(channel.qemu_endpoint())?,
            operator_listen: parse_operator_listen_endpoint(channel.operator_listen())?,
            breakpoint_policy: QemuGdbstubBreakpointPolicy::canonical_hardware_breakpoints(),
        })
    }

    /// Returns the parsed QEMU gdbstub address.
    #[must_use]
    pub const fn qemu_addr(&self) -> SocketAddr {
        self.qemu_addr
    }

    /// Returns the parsed operator-facing listen address.
    #[must_use]
    pub const fn operator_listen(&self) -> SocketAddr {
        self.operator_listen
    }

    /// Returns the canonical breakpoint policy applied to operator packets.
    #[must_use]
    pub const fn breakpoint_policy(&self) -> QemuGdbstubBreakpointPolicy {
        self.breakpoint_policy
    }

    /// Returns this proxy with an explicit canonical breakpoint policy.
    #[must_use]
    pub const fn with_breakpoint_policy(mut self, policy: QemuGdbstubBreakpointPolicy) -> Self {
        self.breakpoint_policy = policy;
        self
    }

    /// Binds the operator-facing `--gdb-listen` endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`QemuGdbstubProxyError::Bind`] when the listener cannot be
    /// opened or [`QemuGdbstubProxyError::LocalAddr`] when its final address
    /// cannot be queried.
    pub fn bind(self) -> Result<QemuGdbstubProxyListener, QemuGdbstubProxyError> {
        let listener = TcpListener::bind(self.operator_listen).map_err(|source| {
            QemuGdbstubProxyError::Bind {
                addr: self.operator_listen,
                source,
            }
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|source| QemuGdbstubProxyError::LocalAddr { source })?;
        Ok(QemuGdbstubProxyListener {
            listener,
            qemu_addr: self.qemu_addr,
            local_addr,
            breakpoint_policy: self.breakpoint_policy,
        })
    }

    /// Binds and starts a cancellable one-session proxy server.
    ///
    /// The returned handle owns the bound operator listener. Dropping it requests
    /// shutdown before an operator connects.
    ///
    /// # Errors
    ///
    /// Returns [`QemuGdbstubProxyError`] when the listener cannot be bound or
    /// prepared for background serving.
    pub fn spawn_one(self) -> Result<QemuGdbstubProxyServer, QemuGdbstubProxyError> {
        self.bind()?.spawn_one()
    }
}

/// A bound operator-facing gdbstub proxy listener.
#[derive(Debug)]
pub struct QemuGdbstubProxyListener {
    listener: TcpListener,
    qemu_addr: SocketAddr,
    local_addr: SocketAddr,
    breakpoint_policy: QemuGdbstubBreakpointPolicy,
}

impl QemuGdbstubProxyListener {
    /// Returns the actual operator-facing address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the canonical breakpoint policy enforced by this listener.
    #[must_use]
    pub const fn breakpoint_policy(&self) -> QemuGdbstubBreakpointPolicy {
        self.breakpoint_policy
    }

    /// Proxies one operator gdb-protocol connection to QEMU's raw gdbstub.
    ///
    /// This call blocks until the accepted operator session and the QEMU
    /// connection close. Callers that need a background session can run it on
    /// their own thread or runtime boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuGdbstubProxyError`] when accepting the operator connection,
    /// connecting to QEMU, cloning streams, or forwarding bytes fails.
    pub fn serve_one(self) -> Result<QemuGdbstubProxySessionReport, QemuGdbstubProxyError> {
        let (operator, _) =
            self.listener
                .accept()
                .map_err(|source| QemuGdbstubProxyError::Accept {
                    addr: self.local_addr,
                    source,
                })?;
        let qemu = TcpStream::connect(self.qemu_addr).map_err(|source| {
            QemuGdbstubProxyError::ConnectQemu {
                addr: self.qemu_addr,
                source,
            }
        })?;
        proxy_tcp_pair(operator, qemu, self.breakpoint_policy)
    }

    /// Starts this listener on a background thread for one operator session.
    ///
    /// The thread waits for either an operator connection or a shutdown request
    /// from the returned handle. Once an operator connects, normal gdbstub byte
    /// forwarding runs until the operator or QEMU closes the session.
    ///
    /// # Errors
    ///
    /// Returns [`QemuGdbstubProxyError::SetNonblocking`] when the listener cannot
    /// be prepared for cancellable background accept.
    pub fn spawn_one(self) -> Result<QemuGdbstubProxyServer, QemuGdbstubProxyError> {
        self.listener.set_nonblocking(true).map_err(|source| {
            QemuGdbstubProxyError::SetNonblocking {
                addr: self.local_addr,
                source,
            }
        })?;
        let local_addr = self.local_addr;
        let (shutdown, shutdown_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            serve_one_until_shutdown(
                self.listener,
                self.qemu_addr,
                self.local_addr,
                self.breakpoint_policy,
                shutdown_rx,
            )
        });
        Ok(QemuGdbstubProxyServer {
            local_addr,
            shutdown,
            handle: Some(handle),
        })
    }
}

/// Background handle for one bound gdbstub proxy listener.
#[derive(Debug)]
pub struct QemuGdbstubProxyServer {
    local_addr: SocketAddr,
    shutdown: mpsc::Sender<()>,
    handle: Option<
        thread::JoinHandle<Result<Option<QemuGdbstubProxySessionReport>, QemuGdbstubProxyError>>,
    >,
}

impl QemuGdbstubProxyServer {
    /// Returns the actual operator-facing listen address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Requests shutdown and detaches the background server thread.
    ///
    /// If no operator has connected, the server notices the request and exits.
    /// If a debugger is already attached, forwarding continues until either side
    /// closes the TCP streams.
    pub fn request_shutdown(mut self) {
        self.request_shutdown_ref();
    }

    fn request_shutdown_ref(&mut self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.take();
    }
}

impl Drop for QemuGdbstubProxyServer {
    fn drop(&mut self) {
        self.request_shutdown_ref();
    }
}

/// Byte counts for one proxied gdbstub session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QemuGdbstubProxySessionReport {
    /// Bytes forwarded from the operator client to QEMU.
    pub operator_to_qemu_bytes: u64,
    /// Bytes forwarded from QEMU to the operator client.
    pub qemu_to_operator_bytes: u64,
    /// Software breakpoint packets translated to hardware breakpoint packets.
    pub software_breakpoints_translated: u64,
    /// Software breakpoint packets refused without forwarding to QEMU.
    pub software_breakpoints_refused: u64,
    /// Client acknowledgments consumed for locally generated refusal responses.
    pub local_response_acks_consumed: u64,
}

fn serve_one_until_shutdown(
    listener: TcpListener,
    qemu_addr: SocketAddr,
    local_addr: SocketAddr,
    breakpoint_policy: QemuGdbstubBreakpointPolicy,
    shutdown: mpsc::Receiver<()>,
) -> Result<Option<QemuGdbstubProxySessionReport>, QemuGdbstubProxyError> {
    loop {
        match shutdown.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => return Ok(None),
            Err(TryRecvError::Empty) => {}
        }
        match listener.accept() {
            Ok((operator, _)) => {
                let qemu = TcpStream::connect(qemu_addr).map_err(|source| {
                    QemuGdbstubProxyError::ConnectQemu {
                        addr: qemu_addr,
                        source,
                    }
                })?;
                return proxy_tcp_pair(operator, qemu, breakpoint_policy).map(Some);
            }
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(source) => {
                return Err(QemuGdbstubProxyError::Accept {
                    addr: local_addr,
                    source,
                });
            }
        }
    }
}

fn parse_qemu_tcp_endpoint(value: &str) -> Result<SocketAddr, QemuGdbstubProxyError> {
    let Some(addr) = value.strip_prefix("tcp:") else {
        return Err(QemuGdbstubProxyError::UnsupportedEndpoint {
            field: "qemu_gdbstub_endpoint",
            value: value.to_owned(),
        });
    };
    parse_socket_addr("qemu_gdbstub_endpoint", value, addr)
}

fn parse_operator_listen_endpoint(value: &str) -> Result<SocketAddr, QemuGdbstubProxyError> {
    let addr = value.strip_prefix("tcp:").unwrap_or(value);
    parse_socket_addr("gdb_listen_endpoint", value, addr)
}

fn parse_socket_addr(
    field: &'static str,
    original: &str,
    addr: &str,
) -> Result<SocketAddr, QemuGdbstubProxyError> {
    addr.parse::<SocketAddr>()
        .map_err(|source| QemuGdbstubProxyError::InvalidSocketAddress {
            field,
            value: original.to_owned(),
            message: source.to_string(),
        })
}

fn proxy_tcp_pair(
    operator: TcpStream,
    qemu: TcpStream,
    breakpoint_policy: QemuGdbstubBreakpointPolicy,
) -> Result<QemuGdbstubProxySessionReport, QemuGdbstubProxyError> {
    let operator_reader =
        operator
            .try_clone()
            .map_err(|source| QemuGdbstubProxyError::CloneStream {
                role: "operator",
                source,
            })?;
    let operator_local_writer =
        operator
            .try_clone()
            .map_err(|source| QemuGdbstubProxyError::CloneStream {
                role: "operator-local-response",
                source,
            })?;
    let qemu_reader = qemu
        .try_clone()
        .map_err(|source| QemuGdbstubProxyError::CloneStream {
            role: "qemu",
            source,
        })?;

    let to_qemu = thread::spawn(move || {
        copy_operator_to_qemu(
            operator_reader,
            qemu,
            operator_local_writer,
            breakpoint_policy,
        )
    });
    let to_operator =
        thread::spawn(move || copy_proxy_direction("qemu-to-operator", qemu_reader, operator));

    let operator_report = join_proxy_direction("operator-to-qemu", to_qemu)?;
    let qemu_to_operator_bytes = join_proxy_direction("qemu-to-operator", to_operator)?;

    Ok(QemuGdbstubProxySessionReport {
        operator_to_qemu_bytes: operator_report.bytes_forwarded,
        qemu_to_operator_bytes,
        software_breakpoints_translated: operator_report.software_breakpoints_translated,
        software_breakpoints_refused: operator_report.software_breakpoints_refused,
        local_response_acks_consumed: operator_report.local_response_acks_consumed,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OperatorToQemuReport {
    bytes_forwarded: u64,
    software_breakpoints_translated: u64,
    software_breakpoints_refused: u64,
    local_response_acks_pending: u64,
    local_response_acks_consumed: u64,
}

fn copy_operator_to_qemu(
    mut reader: TcpStream,
    mut qemu_writer: TcpStream,
    mut operator_writer: TcpStream,
    breakpoint_policy: QemuGdbstubBreakpointPolicy,
) -> Result<OperatorToQemuReport, QemuGdbstubProxyError> {
    let mut report = OperatorToQemuReport::default();
    let mut pending = Vec::<u8>::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|source| QemuGdbstubProxyError::Forward {
                direction: "operator-to-qemu",
                source,
            })?;
        if read == 0 {
            break;
        }
        pending.extend_from_slice(&chunk[..read]);
        process_operator_gdbstub_bytes(
            &mut pending,
            &mut qemu_writer,
            &mut operator_writer,
            breakpoint_policy,
            &mut report,
            false,
        )?;
    }
    process_operator_gdbstub_bytes(
        &mut pending,
        &mut qemu_writer,
        &mut operator_writer,
        breakpoint_policy,
        &mut report,
        true,
    )?;
    qemu_writer
        .shutdown(Shutdown::Write)
        .map_err(|source| QemuGdbstubProxyError::Forward {
            direction: "operator-to-qemu",
            source,
        })?;
    Ok(report)
}

fn process_operator_gdbstub_bytes(
    pending: &mut Vec<u8>,
    qemu_writer: &mut TcpStream,
    operator_writer: &mut TcpStream,
    breakpoint_policy: QemuGdbstubBreakpointPolicy,
    report: &mut OperatorToQemuReport,
    flush_partial: bool,
) -> Result<(), QemuGdbstubProxyError> {
    loop {
        if pending.is_empty() {
            return Ok(());
        }
        if pending[0] != b'$' {
            if pending[0] == b'+' && report.local_response_acks_pending > 0 {
                report.local_response_acks_pending =
                    report.local_response_acks_pending.saturating_sub(1);
                report.local_response_acks_consumed =
                    report.local_response_acks_consumed.saturating_add(1);
                pending.drain(..1);
                continue;
            }
            let next_packet = pending.iter().position(|byte| *byte == b'$');
            let raw_len = next_packet.unwrap_or(pending.len());
            forward_operator_bytes(qemu_writer, &pending[..raw_len], report)?;
            pending.drain(..raw_len);
            continue;
        }
        let Some(hash_index) = pending.iter().position(|byte| *byte == b'#') else {
            if flush_partial {
                forward_operator_bytes(qemu_writer, pending, report)?;
                pending.clear();
            }
            return Ok(());
        };
        if pending.len() < hash_index + 3 {
            if flush_partial {
                forward_operator_bytes(qemu_writer, pending, report)?;
                pending.clear();
            }
            return Ok(());
        }

        let packet = pending[..hash_index + 3].to_vec();
        let payload = &packet[1..hash_index];
        if is_software_breakpoint_packet(payload) {
            if breakpoint_policy.hardware_breakpoints() {
                let rewritten = hardware_breakpoint_packet(payload);
                forward_operator_bytes(qemu_writer, &rewritten, report)?;
                report.software_breakpoints_translated =
                    report.software_breakpoints_translated.saturating_add(1);
            } else {
                let response = gdb_packet(GDB_ERROR_MEMORY_PATCH_REFUSED.as_bytes());
                operator_writer
                    .write_all(b"+")
                    .map_err(|source| QemuGdbstubProxyError::LocalResponse { source })?;
                operator_writer
                    .write_all(&response)
                    .map_err(|source| QemuGdbstubProxyError::LocalResponse { source })?;
                report.software_breakpoints_refused =
                    report.software_breakpoints_refused.saturating_add(1);
                report.local_response_acks_pending =
                    report.local_response_acks_pending.saturating_add(1);
            }
        } else {
            forward_operator_bytes(qemu_writer, &packet, report)?;
        }
        pending.drain(..hash_index + 3);
    }
}

fn forward_operator_bytes(
    writer: &mut TcpStream,
    bytes: &[u8],
    report: &mut OperatorToQemuReport,
) -> Result<(), QemuGdbstubProxyError> {
    writer
        .write_all(bytes)
        .map_err(|source| QemuGdbstubProxyError::Forward {
            direction: "operator-to-qemu",
            source,
        })?;
    report.bytes_forwarded = report
        .bytes_forwarded
        .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    Ok(())
}

fn is_software_breakpoint_packet(payload: &[u8]) -> bool {
    payload.starts_with(b"Z0,") || payload.starts_with(b"z0,")
}

fn hardware_breakpoint_packet(payload: &[u8]) -> Vec<u8> {
    let mut rewritten = payload.to_vec();
    rewritten[1] = b'1';
    gdb_packet(&rewritten)
}

fn gdb_packet(payload: &[u8]) -> Vec<u8> {
    let checksum = payload
        .iter()
        .fold(0_u8, |checksum, byte| checksum.wrapping_add(*byte));
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push(b'$');
    packet.extend_from_slice(payload);
    packet.push(b'#');
    packet.extend_from_slice(format!("{checksum:02x}").as_bytes());
    packet
}

fn copy_proxy_direction(
    direction: &'static str,
    mut reader: TcpStream,
    mut writer: TcpStream,
) -> Result<u64, QemuGdbstubProxyError> {
    let bytes = io::copy(&mut reader, &mut writer)
        .map_err(|source| QemuGdbstubProxyError::Forward { direction, source })?;
    writer
        .shutdown(Shutdown::Write)
        .map_err(|source| QemuGdbstubProxyError::Forward { direction, source })?;
    Ok(bytes)
}

fn join_proxy_direction<T>(
    direction: &'static str,
    handle: thread::JoinHandle<Result<T, QemuGdbstubProxyError>>,
) -> Result<T, QemuGdbstubProxyError> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(QemuGdbstubProxyError::ForwardThreadPanicked { direction }),
    }
}
