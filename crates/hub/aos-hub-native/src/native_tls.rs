//! Native TLS listener for the Hub HTTP server.
//!
//! TLS terminates in the Hub process so route dispatch can rely on transport
//! evidence derived from the authenticated handshake instead of forgeable
//! forwarding headers. Each accepted connection must present the configured
//! public hostname through SNI.

use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use axum::serve::Listener;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// A TCP listener that authenticates TLS and enforces one expected SNI name.
pub struct NativeTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    expected_server_name: String,
}

/// Peer address authenticated as the source of a native TLS connection.
#[derive(Clone, Copy, Debug)]
pub struct NativeTlsPeer(
    /// Remote TCP address observed by the native listener.
    pub SocketAddr,
);

impl NativeTlsListener {
    /// Configures a TLS listener from PEM certificate and private-key files.
    ///
    /// # Errors
    ///
    /// Returns an error when a PEM file cannot be read, contains no usable
    /// certificate or private key, or the key does not match the certificate.
    pub fn new(
        listener: TcpListener,
        certificate_file: &Path,
        private_key_file: &Path,
        expected_server_name: String,
    ) -> Result<Self> {
        let certificate = std::fs::File::open(certificate_file)
            .with_context(|| format!("opening TLS certificate {}", certificate_file.display()))?;
        let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        anyhow::ensure!(!certificates.is_empty(), "TLS certificate file is empty");

        let private_key = std::fs::File::open(private_key_file)
            .with_context(|| format!("opening TLS private key {}", private_key_file.display()))?;
        let private_key = rustls_pemfile::private_key(&mut BufReader::new(private_key))?
            .context("TLS private-key file contains no supported key")?;
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .context("selecting safe TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("TLS certificate and private key are incompatible")?;

        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            expected_server_name,
        })
    }
}

impl Listener for NativeTlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "native TLS listener failed to accept TCP connection");
                    continue;
                }
            };
            let tls = match self.acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(error) => {
                    tracing::warn!(%peer, %error, "native TLS handshake failed");
                    continue;
                }
            };
            if tls.get_ref().1.server_name() != Some(self.expected_server_name.as_str()) {
                tracing::warn!(
                    %peer,
                    expected = %self.expected_server_name,
                    "native TLS client used an absent or unexpected SNI name"
                );
                continue;
            }
            return (tls, peer);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

impl Connected<IncomingStream<'_, NativeTlsListener>> for NativeTlsPeer {
    fn connect_info(stream: IncomingStream<'_, NativeTlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}
