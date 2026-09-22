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

        let (config, verifier) = tls_configuration(server_certificates, key, roots)?;
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
        require_public_protocol(connection)?;
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
    /// A failed recheck permanently retires this connection's peer evidence;
    /// restoring old credentials cannot revive an already rejected session.
    ///
    /// # Errors
    ///
    /// Rejects a closed/expired session, invalid certificate chain, changed
    /// protected credential files, or unavailable kernel time.
    pub fn recheck(&self) -> Result<(), PublicApiSessionError> {
        let result = self.recheck_current();
        if result.is_err() {
            self.close();
        }
        result
    }

    fn recheck_current(&self) -> Result<(), PublicApiSessionError> {
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

fn tls_configuration(
    server_certificates: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    roots: rustls::RootCertStore,
) -> Result<(rustls::ServerConfig, Arc<dyn ClientCertVerifier>), PublicApiSessionError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
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
    Ok((config, verifier))
}

fn require_public_protocol(
    connection: &rustls::ServerConnection,
) -> Result<(), PublicApiSessionError> {
    if connection.alpn_protocol() != Some(b"h2")
        || connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
    {
        return Err(PublicApiSessionError::Authentication);
    }
    Ok(())
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

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use tokio::io::DuplexStream;

    struct Authority {
        certificate: Certificate,
        issuer: Issuer<'static, KeyPair>,
    }

    impl Authority {
        fn new() -> Self {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let key = KeyPair::generate().unwrap();
            let certificate = params.self_signed(&key).unwrap();
            Self {
                certificate,
                issuer: Issuer::new(params, key),
            }
        }

        fn leaf(
            &self,
            usage: ExtendedKeyUsagePurpose,
        ) -> (
            CertificateDer<'static>,
            rustls::pki_types::PrivateKeyDer<'static>,
        ) {
            let mut params = CertificateParams::new(vec!["sandbox.test".to_owned()]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate().unwrap();
            let certificate = params.signed_by(&key, &self.issuer).unwrap();
            (
                certificate.der().clone(),
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
        }

        fn roots(&self) -> rustls::RootCertStore {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.certificate.der().clone()).unwrap();
            roots
        }

        fn server(&self) -> rustls::ServerConfig {
            let (certificate, key) = self.leaf(ExtendedKeyUsagePurpose::ServerAuth);
            tls_configuration(vec![certificate], key, self.roots())
                .unwrap()
                .0
        }

        fn client(
            &self,
            identity: Option<&Authority>,
            usage: ExtendedKeyUsagePurpose,
            tls12: bool,
        ) -> rustls::ClientConfig {
            let versions = if tls12 {
                vec![&rustls::version::TLS12]
            } else {
                vec![&rustls::version::TLS13]
            };
            let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_protocol_versions(&versions)
            .unwrap()
            .with_root_certificates(self.roots());
            let mut config = match identity {
                Some(authority) => {
                    let (certificate, key) = authority.leaf(usage);
                    builder
                        .with_client_auth_cert(vec![certificate], key)
                        .unwrap()
                }
                None => builder.with_no_client_auth(),
            };
            config.alpn_protocols = vec![b"h2".to_vec()];
            config
        }
    }

    type ServerStream = tokio_rustls::server::TlsStream<DuplexStream>;
    type ClientStream = tokio_rustls::client::TlsStream<DuplexStream>;

    async fn handshake(
        server: rustls::ServerConfig,
        client: rustls::ClientConfig,
    ) -> (std::io::Result<ServerStream>, std::io::Result<ClientStream>) {
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                acceptor.accept(server_io),
                connector.connect(ServerName::try_from("sandbox.test").unwrap(), client_io),
            )
        })
        .await
        .expect("TLS handshake must terminate within its test bound")
    }

    #[tokio::test]
    async fn authenticates_both_peers_and_binds_exporters_to_each_connection() {
        let authority = Authority::new();
        let server = authority.server();
        let client = authority.client(Some(&authority), ExtendedKeyUsagePurpose::ClientAuth, false);
        let mut bindings = Vec::new();

        for _ in 0..2 {
            let (server, client) = handshake(server.clone(), client.clone()).await;
            let server = server.unwrap();
            let client = client.unwrap();
            let connection = server.get_ref().1;
            require_public_protocol(connection).unwrap();
            let certificate = connection.peer_certificates().unwrap().first().unwrap();
            let digest: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
            let server_binding = connection
                .export_keying_material([0; 32], EXPORTER_LABEL, Some(&digest))
                .unwrap();
            let client_binding = client
                .get_ref()
                .1
                .export_keying_material([0; 32], EXPORTER_LABEL, Some(&digest))
                .unwrap();

            assert_eq!(server_binding, client_binding);
            assert_ne!(server_binding, [0; 32]);
            bindings.push(server_binding);
        }
        assert_ne!(bindings[0], bindings[1]);
    }

    #[tokio::test]
    async fn rejects_absent_untrusted_and_wrong_usage_client_certificates() {
        let authority = Authority::new();
        let unrelated = Authority::new();
        for (identity, usage) in [
            (None, ExtendedKeyUsagePurpose::ClientAuth),
            (Some(&unrelated), ExtendedKeyUsagePurpose::ClientAuth),
            (Some(&authority), ExtendedKeyUsagePurpose::ServerAuth),
        ] {
            let client = authority.client(identity, usage, false);
            let (server, _) = handshake(authority.server(), client).await;

            assert!(server.is_err());
        }
    }

    #[tokio::test]
    async fn rejects_tls12_and_non_http2_sessions() {
        let authority = Authority::new();
        let client = authority.client(Some(&authority), ExtendedKeyUsagePurpose::ClientAuth, true);
        let (server, _) = handshake(authority.server(), client).await;
        assert!(server.is_err());

        for protocols in [vec![], vec![b"http/1.1".to_vec()]] {
            let mut client =
                authority.client(Some(&authority), ExtendedKeyUsagePurpose::ClientAuth, false);
            client.alpn_protocols = protocols;
            let (server, _) = handshake(authority.server(), client).await;

            if let Ok(server) = server {
                assert!(require_public_protocol(server.get_ref().1).is_err());
            }
        }
    }

    #[test]
    fn disables_resumption_and_early_data() {
        let authority = Authority::new();
        let server = authority.server();

        assert_eq!(server.send_tls13_tickets, 0);
        assert_eq!(server.max_early_data_size, 0);
        assert!(!server.session_storage.can_cache());
        assert!(!server.ticketer.enabled());
    }
}
