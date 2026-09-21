//! Mutually authenticated TLS sessions for the public sandbox API.
//!
//! Fixed systemd credentials supply the server identity, client trust anchors,
//! and explicit certificate-to-principal registrations. TLS 1.3 client proof
//! and HTTP/2 negotiation precede any peer evidence. Connections cannot resume
//! sessions or use early data. Each request must recheck the peer and then pass
//! the controller's independent current capability, policy, and revocation checks.
//! This module grants no capabilities and registers no public RPC handlers.

mod credentials;
mod registration;
mod stream;

use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use aos_sandbox_core::{ChannelBinding, PrincipalId, ProjectId};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::{WebPkiClientVerifier, danger::ClientCertVerifier};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

pub use stream::AuthenticatedPublicApiStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SESSION_LIFETIME_NANOSECONDS: u64 = 300_000_000_000;
const KEY_BINDING_DOMAIN: &[u8] = b"aos.sandbox.public-api.registered-certificate.v1\0";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-AOS-SANDBOX-PUBLIC-API-V1";

/// Reports redacted public-session configuration, authentication, or currentness failure.
#[derive(Debug, thiserror::Error)]
pub enum PublicApiSessionError {
    /// Protected credential provenance or the closed registration schema is invalid.
    #[error("public API session credentials are invalid")]
    Configuration,
    /// TLS proof, registered identity, HTTP/2 negotiation, or handshake timing failed.
    #[error("public API session authentication failed")]
    Authentication,
    /// The connection, certificate, credential snapshot, or bounded lifetime is no longer current.
    #[error("public API session is no longer current")]
    Stale,
}

/// Owns the fixed protected server configuration and registered client identities.
pub struct PublicApiSessionAcceptor {
    acceptor: TlsAcceptor,
    verifier: Arc<dyn ClientCertVerifier>,
    credentials: Arc<credentials::Credentials>,
    registrations: BTreeMap<[u8; 32], registration::Registration>,
}

impl PublicApiSessionAcceptor {
    /// Loads all four fixed public API credentials from systemd's credential directory.
    ///
    /// No caller-selected identity, certificate, trust root, or verifier enters
    /// this constructor. Registration is identity evidence, not project authority.
    ///
    /// # Errors
    ///
    /// Rejects unsafe or changed credential files, invalid PEM, empty trust,
    /// mismatched server keys, or an invalid/ambiguous principal registration.
    pub fn from_systemd_credentials() -> Result<Self, PublicApiSessionError> {
        let (credentials, bytes) = credentials::Credentials::load()?;
        let registrations = registration::decode(&bytes[3])?;
        let server_certificates = certificates(&bytes[0])?;
        let key = rustls_pemfile::private_key(&mut bytes[1].as_slice())
            .map_err(|_| PublicApiSessionError::Configuration)?
            .ok_or(PublicApiSessionError::Configuration)?;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in certificates(&bytes[2])? {
            roots
                .add(certificate)
                .map_err(|_| PublicApiSessionError::Configuration)?;
        }

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| PublicApiSessionError::Configuration)?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| PublicApiSessionError::Configuration)?
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(server_certificates, key)
            .map_err(|_| PublicApiSessionError::Configuration)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        credentials.recheck()?;

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            verifier,
            credentials: Arc::new(credentials),
            registrations,
        })
    }

    /// Authenticates one connection before exposing HTTP/2 bytes or peer evidence.
    ///
    /// # Errors
    ///
    /// Rejects expired handshake time, missing or invalid client proof,
    /// unregistered certificates, non-HTTP/2 negotiation, or changed credentials.
    pub async fn accept<IO>(
        &self,
        io: IO,
    ) -> Result<AuthenticatedPublicApiStream<IO>, PublicApiSessionError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.credentials.recheck()?;
        let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(io))
            .await
            .map_err(|_| PublicApiSessionError::Authentication)?
            .map_err(|_| PublicApiSessionError::Authentication)?;
        let connection = stream.get_ref().1;
        if connection.alpn_protocol() != Some(b"h2")
            || connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        {
            return Err(PublicApiSessionError::Authentication);
        }
        let chain = connection
            .peer_certificates()
            .ok_or(PublicApiSessionError::Authentication)?;
        let certificate = chain.first().ok_or(PublicApiSessionError::Authentication)?;
        let digest: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        let registration = self
            .registrations
            .get(&digest)
            .ok_or(PublicApiSessionError::Authentication)?;
        let session_binding = connection
            .export_keying_material([0; 32], EXPORTER_LABEL, Some(&digest))
            .map_err(|_| PublicApiSessionError::Authentication)?;
        let key_binding = ChannelBinding::new(
            Sha256::new()
                .chain_update(KEY_BINDING_DOMAIN)
                .chain_update(digest)
                .finalize()
                .into(),
        );
        let deadline = boottime()?
            .checked_add(SESSION_LIFETIME_NANOSECONDS)
            .ok_or(PublicApiSessionError::Stale)?;
        let peer = PublicApiPeer(Arc::new(PeerState {
            registration: *registration,
            key_binding,
            session_binding,
            chain: chain.to_vec(),
            verifier: self.verifier.clone(),
            credentials: self.credentials.clone(),
            active: AtomicBool::new(true),
            deadline,
        }));
        peer.recheck()?;
        Ok(AuthenticatedPublicApiStream::new(stream, peer))
    }
}

/// Retains authenticated peer identity without granting a capability.
///
/// Copies share the connection's liveness marker. Consumers must call
/// [`Self::recheck`] before independent protected authorization and use.
#[derive(Clone)]
pub struct PublicApiPeer(Arc<PeerState>);

struct PeerState {
    registration: registration::Registration,
    key_binding: ChannelBinding,
    session_binding: [u8; 32],
    chain: Vec<CertificateDer<'static>>,
    verifier: Arc<dyn ClientCertVerifier>,
    credentials: Arc<credentials::Credentials>,
    active: AtomicBool,
    deadline: u64,
}

impl PublicApiPeer {
    /// Returns the principal from the protected registration, never a request field.
    #[must_use]
    pub fn principal(&self) -> PrincipalId {
        self.0.registration.principal
    }

    /// Returns the registration's project boundary, not permission to mutate it.
    #[must_use]
    pub fn project(&self) -> ProjectId {
        self.0.registration.project
    }

    /// Returns the registered certificate's proof-of-possession binding.
    #[must_use]
    pub fn key_binding(&self) -> ChannelBinding {
        self.0.key_binding
    }

    /// Returns the TLS exporter binding unique to this authenticated connection.
    #[must_use]
    pub fn session_binding(&self) -> [u8; 32] {
        self.0.session_binding
    }

    /// Rechecks connection lifetime, certificate validity, and protected registration.
    ///
    /// This does not check capability expiry, policy, or revocation generations;
    /// those remain mandatory in the controller's protected authorization step.
    ///
    /// # Errors
    ///
    /// Rejects a closed/expired session, invalid certificate chain, changed
    /// protected credential files, or unavailable kernel time.
    pub fn recheck(&self) -> Result<(), PublicApiSessionError> {
        if !self.0.active.load(Ordering::Acquire) || boottime()? >= self.0.deadline {
            return Err(PublicApiSessionError::Stale);
        }
        self.0.credentials.recheck()?;
        let (leaf, intermediates) = self
            .0
            .chain
            .split_first()
            .ok_or(PublicApiSessionError::Stale)?;
        self.0
            .verifier
            .verify_client_cert(leaf, intermediates, UnixTime::now())
            .map_err(|_| PublicApiSessionError::Stale)?;
        if !self.0.active.load(Ordering::Acquire) || boottime()? >= self.0.deadline {
            return Err(PublicApiSessionError::Stale);
        }
        Ok(())
    }

    fn close(&self) {
        self.0.active.store(false, Ordering::Release);
    }
}

fn certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, PublicApiSessionError> {
    let certificates = rustls_pemfile::certs(&mut bytes.as_ref())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PublicApiSessionError::Configuration)?;
    if certificates.is_empty() {
        return Err(PublicApiSessionError::Configuration);
    }
    Ok(certificates)
}

fn boottime() -> Result<u64, PublicApiSessionError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| PublicApiSessionError::Stale)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(|_| PublicApiSessionError::Stale)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(PublicApiSessionError::Stale)
}
