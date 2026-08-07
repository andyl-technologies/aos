//! Mutual-TLS configuration and authenticated daemon transport identities.
//!
//! Remote Crucible clients authenticate with an X.509 certificate rooted in
//! the daemon's configured client CA. The transport exposes only a stable
//! SHA-256 certificate fingerprint to higher layers; certificate parsing and
//! policy remain transport concerns.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

/// Identity proven by one authenticated daemon transport connection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugTransportIdentity {
    certificate_sha256: String,
}

impl DebugTransportIdentity {
    /// Derives an identity from the authenticated leaf certificate bytes.
    #[must_use]
    pub fn from_leaf_certificate(certificate: &[u8]) -> Self {
        let digest = Sha256::digest(certificate);
        let mut certificate_sha256 = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(certificate_sha256, "{byte:02x}");
        }
        Self { certificate_sha256 }
    }

    /// Returns the lowercase SHA-256 fingerprint of the leaf certificate.
    #[must_use]
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
}

/// Errors returned while loading mutual-TLS server material.
#[derive(Debug, Error)]
pub enum MutualTlsServerConfigError {
    /// A PEM file could not be opened.
    #[error("cannot open mutual-TLS {kind} file {path}: {source}")]
    Open {
        /// Kind of TLS material being loaded.
        kind: &'static str,
        /// Path that could not be opened.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// A PEM file contained malformed material.
    #[error("cannot parse mutual-TLS {kind} file {path}: {message}")]
    Parse {
        /// Kind of TLS material being loaded.
        kind: &'static str,
        /// Path containing invalid material.
        path: PathBuf,
        /// Parser diagnostic.
        message: String,
    },
    /// A required PEM file contained no usable records.
    #[error("mutual-TLS {kind} file {path} contains no usable records")]
    Empty {
        /// Kind of TLS material being loaded.
        kind: &'static str,
        /// Empty or unsupported PEM file.
        path: PathBuf,
    },
    /// Rustls rejected the configured trust anchors or server identity.
    #[error("invalid mutual-TLS server configuration: {message}")]
    InvalidConfiguration {
        /// Stable configuration diagnostic.
        message: String,
    },
}

/// Loads a mutual-TLS server acceptor from PEM files.
///
/// Every accepted connection must present a client certificate chaining to
/// `client_ca_path`. The acceptor advertises HTTP/2 only.
///
/// # Errors
///
/// Returns [`MutualTlsServerConfigError`] when a file cannot be read or parsed,
/// no required record is present, or rustls rejects the trust roots or server
/// certificate and private key.
pub fn mutual_tls_acceptor_from_pem(
    certificate_path: &Path,
    private_key_path: &Path,
    client_ca_path: &Path,
) -> Result<TlsAcceptor, MutualTlsServerConfigError> {
    let certificates = load_certificates(certificate_path, "server certificate")?;
    let private_key = load_private_key(private_key_path)?;
    let client_roots = load_certificates(client_ca_path, "client CA")?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(client_roots);
    if accepted == 0 || rejected != 0 {
        return Err(MutualTlsServerConfigError::InvalidConfiguration {
            message: format!(
                "client CA set accepted {accepted} certificate(s) and rejected {rejected}"
            ),
        });
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| MutualTlsServerConfigError::InvalidConfiguration {
            message: error.to_string(),
        })?;
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .map_err(|error| MutualTlsServerConfigError::InvalidConfiguration {
            message: error.to_string(),
        })?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certificates(
    path: &Path,
    kind: &'static str,
) -> Result<Vec<CertificateDer<'static>>, MutualTlsServerConfigError> {
    let file = File::open(path).map_err(|source| MutualTlsServerConfigError::Open {
        kind,
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| MutualTlsServerConfigError::Parse {
            kind,
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    if certificates.is_empty() {
        return Err(MutualTlsServerConfigError::Empty {
            kind,
            path: path.to_path_buf(),
        });
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, MutualTlsServerConfigError> {
    let file = File::open(path).map_err(|source| MutualTlsServerConfigError::Open {
        kind: "server private key",
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| MutualTlsServerConfigError::Parse {
            kind: "server private key",
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .ok_or_else(|| MutualTlsServerConfigError::Empty {
            kind: "server private key",
            path: path.to_path_buf(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_identity_is_stable_and_unambiguous() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"client-certificate");
        assert_eq!(identity.certificate_sha256().len(), 64);
        assert!(
            identity
                .certificate_sha256()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(
            identity,
            DebugTransportIdentity::from_leaf_certificate(b"client-certificate")
        );
        assert_ne!(
            identity,
            DebugTransportIdentity::from_leaf_certificate(b"other-certificate")
        );
    }
}
