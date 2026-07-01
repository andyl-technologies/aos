//! Mediated QEMU gdbstub proxy.
//!
//! This module owns the safe host-side bridge between QEMU's raw gdbstub and
//! the operator-facing `--gdb-listen` endpoint. It is deliberately outside the
//! scheduler-facing [`crate::QemuNode`] channel bundle: forwarding debugger
//! packets here does not touch the shared-memory quantum path or frame delivery.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;

use thiserror::Error;

use crate::QemuGdbstubChannelConfig;

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
    /// One forwarding half panicked.
    #[error("{direction} gdbstub forwarding thread panicked")]
    ForwardThreadPanicked {
        /// Forwarding direction.
        direction: &'static str,
    },
}

/// A parsed gdbstub proxy endpoint pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuGdbstubProxy {
    qemu_addr: SocketAddr,
    operator_listen: SocketAddr,
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
        })
    }
}

/// A bound operator-facing gdbstub proxy listener.
#[derive(Debug)]
pub struct QemuGdbstubProxyListener {
    listener: TcpListener,
    qemu_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl QemuGdbstubProxyListener {
    /// Returns the actual operator-facing address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
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
        proxy_tcp_pair(operator, qemu)
    }
}

/// Byte counts for one proxied gdbstub session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QemuGdbstubProxySessionReport {
    /// Bytes forwarded from the operator client to QEMU.
    pub operator_to_qemu_bytes: u64,
    /// Bytes forwarded from QEMU to the operator client.
    pub qemu_to_operator_bytes: u64,
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
) -> Result<QemuGdbstubProxySessionReport, QemuGdbstubProxyError> {
    let operator_reader =
        operator
            .try_clone()
            .map_err(|source| QemuGdbstubProxyError::CloneStream {
                role: "operator",
                source,
            })?;
    let qemu_reader = qemu
        .try_clone()
        .map_err(|source| QemuGdbstubProxyError::CloneStream {
            role: "qemu",
            source,
        })?;

    let to_qemu =
        thread::spawn(move || copy_proxy_direction("operator-to-qemu", operator_reader, qemu));
    let to_operator =
        thread::spawn(move || copy_proxy_direction("qemu-to-operator", qemu_reader, operator));

    let operator_to_qemu_bytes = join_proxy_direction("operator-to-qemu", to_qemu)?;
    let qemu_to_operator_bytes = join_proxy_direction("qemu-to-operator", to_operator)?;

    Ok(QemuGdbstubProxySessionReport {
        operator_to_qemu_bytes,
        qemu_to_operator_bytes,
    })
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

fn join_proxy_direction(
    direction: &'static str,
    handle: thread::JoinHandle<Result<u64, QemuGdbstubProxyError>>,
) -> Result<u64, QemuGdbstubProxyError> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(QemuGdbstubProxyError::ForwardThreadPanicked { direction }),
    }
}
