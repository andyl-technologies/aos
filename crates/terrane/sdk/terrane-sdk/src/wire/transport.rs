//! Binds native Distribution services to bounded HTTP/1 and HTTP/2 listeners.
//!
//! This runtime binding registers complete Content, Ref and Tier service
//! implementations supplied by its caller. Those implementations own request
//! authentication, authorization, content verification and acknowledgement.
//! Binding a listener establishes none of those properties. Plaintext is
//! accepted only on an actual loopback socket; remote listeners require TLS 1.3.

use std::{fmt, future::Future, net::SocketAddr, sync::Arc, time::Duration};

use connectrpc::{BoundServer, ConnectRpcService, DeadlinePolicy, Limits, Router, Server};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::services::{ContentService, RefService, TierService};

/// Retains a certificate and private key in a TLS-1.3-only server configuration.
///
/// The private configuration cannot be replaced with a permissive protocol
/// configuration after construction. Certificate identity and trust deployment
/// remain the operator's responsibility. Both HTTP/2 and HTTP/1.1 are advertised.
pub struct TlsIdentity {
    config: Arc<rustls::ServerConfig>,
}

impl TlsIdentity {
    /// Loads DER certificates and a DER private key without global TLS state.
    ///
    /// # Errors
    /// Rejects malformed keys, invalid certificate/key pairs and unsupported
    /// cryptography. The error text never includes private key bytes.
    pub fn from_der(
        certificates: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> Result<Self, TransportError> {
        let certificates = certificates.into_iter().map(CertificateDer::from).collect();
        let private_key =
            PrivateKeyDer::try_from(private_key).map_err(|_| TransportError::PrivateKey)?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(TransportError::Tls)?
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(TransportError::Tls)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            config: Arc::new(config),
        })
    }
}

/// Supplies explicit finite native transport resources.
///
/// Encoded-message limits include protobuf and framing overhead. Service
/// implementations separately enforce the RFC's 4 MiB data-field limit and
/// 4,096-hash request bound; transport limits are not semantic validation.
#[derive(Clone, Debug)]
pub struct TransportLimits {
    /// Bounds whole unary/server-streaming request bodies before decompression.
    pub max_request_bytes: usize,
    /// Bounds a decompressed unary or streaming protobuf/JSON message.
    pub max_message_bytes: usize,
    /// Bounds allocations for repeated/map/string/bytes element bookkeeping.
    pub max_element_memory: usize,
    /// Bounds concurrent HTTP/2 streams on one connection.
    pub max_concurrent_streams: u32,
    /// Bounds each TLS handshake; configuration must retain a finite duration.
    pub handshake_timeout: Duration,
    /// Bounds incomplete HTTP request headers.
    pub header_timeout: Duration,
    /// Caps caller deadlines and supplies the default for every complete RPC.
    pub request_timeout: Duration,
}

impl TransportLimits {
    fn validate(&self) -> Result<(), TransportError> {
        let sizes = [
            self.max_request_bytes,
            self.max_message_bytes,
            self.max_element_memory,
        ];
        if sizes.iter().any(|size| *size == 0 || *size == usize::MAX)
            || self.max_request_bytes < self.max_message_bytes
            || self.max_concurrent_streams == 0
        {
            return Err(TransportError::Limits);
        }
        // This native binding validates the runtime clock's timeout range.
        #[allow(clippy::disallowed_methods)]
        let now = std::time::Instant::now();
        for duration in [
            self.handshake_timeout,
            self.header_timeout,
            self.request_timeout,
        ] {
            if duration.is_zero() || now.checked_add(duration).is_none() {
                return Err(TransportError::Limits);
            }
        }
        Ok(())
    }

    fn codec_limits(&self) -> Limits {
        Limits::default()
            .with_max_request_body_size(self.max_request_bytes)
            .with_max_message_size(self.max_message_bytes)
            .with_element_memory_limit(self.max_element_memory)
    }
}

/// Owns a native listener and the caller's complete generated service bindings.
///
/// All mandatory methods are registered through generated service traits. A
/// caller cannot accidentally register only a subset by omitting a service.
/// This binding does not implement backend methods or authorize requests.
pub struct DistributionTransport {
    bound: BoundServer,
    service: ConnectRpcService<Router>,
    address: SocketAddr,
    procedures: Vec<String>,
}

impl DistributionTransport {
    /// Binds complete services to an already-opened TCP listener.
    ///
    /// The listener's actual local address determines plaintext eligibility.
    /// TLS configuration is created only by [`TlsIdentity`]. Stream deadlines
    /// apply through the complete response body, not merely its first frame.
    ///
    /// # Errors
    /// Rejects invalid finite limits, inaccessible local socket metadata and a
    /// plaintext listener bound to any nonloopback or unspecified address.
    pub fn from_listener<C, R, T>(
        listener: tokio::net::TcpListener,
        content: Arc<C>,
        references: Arc<R>,
        tiers: Arc<T>,
        tls: Option<TlsIdentity>,
        limits: TransportLimits,
    ) -> Result<Self, TransportError>
    where
        C: ContentService,
        R: RefService,
        T: TierService,
    {
        limits.validate()?;
        let address = listener.local_addr().map_err(TransportError::Io)?;
        if tls.is_none() && !address.ip().is_loopback() {
            return Err(TransportError::PlaintextRemote);
        }

        let router = Router::new()
            .add_service(content)
            .add_service(references)
            .add_service(tiers);
        let mut procedures = router
            .methods()
            .map(|method| format!("/{method}"))
            .collect::<Vec<_>>();
        procedures.sort();
        let service = ConnectRpcService::new(router)
            .with_limits(limits.codec_limits())
            .with_deadline_policy(
                DeadlinePolicy::new()
                    .with_max(limits.request_timeout)
                    .with_default_timeout(limits.request_timeout)
                    .with_enforce_on_streams(true),
            );
        let mut bound = Server::from_listener(listener)
            .with_max_concurrent_streams(limits.max_concurrent_streams)
            .with_header_read_timeout(limits.header_timeout)
            .with_tls_handshake_timeout(limits.handshake_timeout);
        if let Some(identity) = tls {
            bound = bound.with_tls(identity.config);
        }

        Ok(Self {
            bound,
            service,
            address,
            procedures,
        })
    }

    /// Returns the actual bound address, including an OS-selected ephemeral port.
    pub const fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Returns the actual registered method paths in lexical order.
    pub fn procedures(&self) -> &[String] {
        &self.procedures
    }

    /// Serves until shutdown, then drains in-flight bounded RPCs.
    ///
    /// Dropping or cancelling this future releases the owned listener and
    /// transport state. It establishes no acknowledgement for an interrupted
    /// backend operation. Service implementations own associated reservation
    /// and multipart cleanup, independently of transport cancellation.
    ///
    /// # Errors
    /// Preserves native serving failures without claiming that requests finished.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), TransportError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.bound
            .serve_with_service_and_shutdown(self.service, shutdown)
            .await
            .map_err(TransportError::Serving)
    }
}

/// Reports invalid native transport policy or actual setup and serving failures.
#[derive(Debug)]
pub enum TransportError {
    /// Requires positive bounded resources and representable finite timeouts.
    Limits,
    /// Refuses plaintext outside an actual loopback listener.
    PlaintextRemote,
    /// Refuses an undecodable private key without exposing its bytes.
    PrivateKey,
    /// Preserves certificate, key-pair and TLS configuration failures.
    Tls(rustls::Error),
    /// Preserves actual listener metadata and socket errors.
    Io(std::io::Error),
    /// Preserves actual server failures without converting them into success.
    Serving(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "invalid finite transport limits",
            Self::PlaintextRemote => "remote Distribution listeners require TLS 1.3",
            Self::PrivateKey => "invalid TLS private key",
            Self::Tls(_) => "invalid TLS identity",
            Self::Io(_) => "Distribution listener I/O failure",
            Self::Serving(_) => "Distribution server failed",
        })
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tls(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Serving(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
