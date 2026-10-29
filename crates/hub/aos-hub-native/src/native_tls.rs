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
use std::time::Duration;

use anyhow::{Context as _, Result};
use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use axum::serve::Listener;
use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use futures_util::FutureExt as _;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

// The kernel backlog absorbs brief bursts; these limits bound the application
// memory and CPU committed before a peer completes transport authentication.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_HANDSHAKES: usize = 128;

type AcceptedTlsConnection = (TlsStream<tokio::net::TcpStream>, SocketAddr);
type PendingHandshake = BoxFuture<'static, Option<AcceptedTlsConnection>>;

/// A TCP listener that bounds TLS authentication and enforces one SNI name.
pub struct NativeTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    expected_server_name: Arc<str>,
    pending_handshakes: FuturesUnordered<PendingHandshake>,
    handshake_timeout: Duration,
    max_pending_handshakes: usize,
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
            expected_server_name: expected_server_name.into(),
            pending_handshakes: FuturesUnordered::new(),
            handshake_timeout: HANDSHAKE_TIMEOUT,
            max_pending_handshakes: MAX_PENDING_HANDSHAKES,
        })
    }

    fn start_handshake(&mut self, stream: tokio::net::TcpStream, peer: SocketAddr) {
        // A small response must not wait for acknowledgement of TLS handshake
        // records. This matters for control callers opening a fresh connection.
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%peer, %error, "native TLS failed to disable TCP coalescing");
            return;
        }

        let acceptor = self.acceptor.clone();
        let expected_server_name = Arc::clone(&self.expected_server_name);
        let handshake_timeout = self.handshake_timeout;

        self.pending_handshakes.push(
            async move {
                let tls =
                    match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => tls,
                        Ok(Err(error)) => {
                            tracing::warn!(%peer, %error, "native TLS handshake failed");
                            return None;
                        }
                        Err(_) => {
                            tracing::warn!(%peer, "native TLS handshake timed out");
                            return None;
                        }
                    };
                if tls.get_ref().1.server_name() != Some(expected_server_name.as_ref()) {
                    tracing::warn!(
                        %peer,
                        expected = %expected_server_name,
                        "native TLS client used an absent or unexpected SNI name"
                    );
                    return None;
                }

                Some((tls, peer))
            }
            .boxed(),
        );
    }
}

impl Listener for NativeTlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if self.pending_handshakes.len() >= self.max_pending_handshakes {
                if let Some(connection) = self.pending_handshakes.next().await.flatten() {
                    return connection;
                }

                continue;
            }

            if self.pending_handshakes.is_empty() {
                match self.listener.accept().await {
                    Ok((stream, peer)) => self.start_handshake(stream, peer),
                    Err(error) => {
                        tracing::warn!(%error, "native TLS listener failed to accept TCP connection");
                    }
                }

                continue;
            }

            tokio::select! {
                biased;
                completed = self.pending_handshakes.next() => {
                    if let Some(connection) = completed.flatten() {
                        return connection;
                    }
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => self.start_handshake(stream, peer),
                        Err(error) => {
                            tracing::warn!(%error, "native TLS listener failed to accept TCP connection");
                        }
                    }
                }
            }
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::extract::ConnectInfo;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::serve::Listener as _;
    use axum::Router;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;
    use tokio::sync::oneshot;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    use super::{NativeTlsListener, NativeTlsPeer};

    const SERVER_NAME: &str = "hub.test";

    struct TlsFixture {
        listener: NativeTlsListener,
        address: std::net::SocketAddr,
        connector: TlsConnector,
        _directory: TempDir,
    }

    async fn tls_fixture(max_pending_handshakes: usize, handshake_timeout: Duration) -> TlsFixture {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let certificate_file = directory.path().join("certificate.pem");
        let private_key_file = directory.path().join("private-key.pem");
        std::fs::write(&certificate_file, cert.pem()).unwrap();
        std::fs::write(&private_key_file, signing_key.serialize_pem()).unwrap();

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp_listener.local_addr().unwrap();
        let mut listener = NativeTlsListener::new(
            tcp_listener,
            &certificate_file,
            &private_key_file,
            SERVER_NAME.to_owned(),
        )
        .unwrap();
        listener.max_pending_handshakes = max_pending_handshakes;
        listener.handshake_timeout = handshake_timeout;

        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client_config = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

        TlsFixture {
            listener,
            address,
            connector: TlsConnector::from(Arc::new(client_config)),
            _directory: directory,
        }
    }

    async fn connect_tls(
        connector: TlsConnector,
        address: std::net::SocketAddr,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let stream = TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from(SERVER_NAME).unwrap();

        connector.connect(server_name, stream).await.unwrap()
    }

    #[tokio::test]
    async fn idle_peer_does_not_block_health_check() {
        let fixture = tls_fixture(4, Duration::from_secs(5)).await;
        let app = Router::new().route(
            "/healthz",
            get(
                |ConnectInfo(NativeTlsPeer(_peer)): ConnectInfo<NativeTlsPeer>| async {
                    StatusCode::NO_CONTENT
                },
            ),
        );
        let server = tokio::spawn(async move {
            axum::serve(
                fixture.listener,
                app.into_make_service_with_connect_info::<NativeTlsPeer>(),
            )
            .await
            .unwrap();
        });

        let _idle_peer = TcpStream::connect(fixture.address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;

        let mut client = connect_tls(fixture.connector, fixture.address).await;
        client
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: hub.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();

        assert!(response.starts_with(b"HTTP/1.1 204 No Content\r\n"));
        server.abort();
    }

    #[tokio::test]
    async fn saturated_handshakes_resume_after_the_deadline() {
        let mut fixture = tls_fixture(1, Duration::from_millis(150)).await;
        let mut server = tokio::spawn(async move { fixture.listener.accept().await });

        let _idle_peer = TcpStream::connect(fixture.address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;

        let connector = fixture.connector;
        let address = fixture.address;
        let mut client = tokio::spawn(async move { connect_tls(connector, address).await });
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut client)
            .await
            .is_err());

        tokio::time::timeout(Duration::from_secs(1), &mut client)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), &mut server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn graceful_shutdown_cancels_an_incomplete_handshake() {
        let fixture = tls_fixture(4, Duration::from_secs(30)).await;
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(fixture.listener, Router::new())
                .with_graceful_shutdown(async {
                    let _ = shutdown_receiver.await;
                })
                .await
                .unwrap();
        });

        let mut idle_peer = TcpStream::connect(fixture.address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        shutdown_sender.send(()).unwrap();

        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0_u8; 1];
        let bytes_read = tokio::time::timeout(Duration::from_secs(1), idle_peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes_read, 0);
    }
}
