//! TLS acceptor construction for the HTTPS listener.
//!
//! Supports two modes, selected by [`crate::config::TlsConfig`]:
//!
//! - **Operator-provided material** — [`acceptor_from_pem`] loads an
//!   existing PEM certificate chain and private key.
//! - **Self-signed fallback** — [`generate_self_signed`] mints a fresh
//!   key pair and certificate (via `rcgen`), persists both to disk with
//!   `0600` permissions on the key, and returns a ready acceptor.
//!
//! [`load_or_generate`] is the usual entry point: it reuses existing files
//! when both are present and generates new ones otherwise, so the same
//! self-signed identity survives server restarts.

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

/// Builds a [`TlsAcceptor`] from PEM certificate and key files.
///
/// The certificate file may contain a full chain; the key may be in any
/// format `rustls-pemfile` recognises (PKCS#1, PKCS#8, or SEC1).
///
/// # Errors
///
/// Returns an error if either file cannot be opened or parsed, if the
/// certificate file contains no certificates, if the key file contains no
/// private key, or if rustls rejects the cert/key pair.
pub fn acceptor_from_pem(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS server config")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Generates a self-signed certificate + private key, writes them to
/// `cert_path` / `key_path`, and returns a ready-to-use [`TlsAcceptor`].
///
/// The certificate is valid for the given `san` subjects (DNS names and/or
/// IPs). If `san` is empty, `["localhost", "127.0.0.1", "::1"]` is used.
/// Parent directories are created as needed, and the key file is restricted
/// to mode `0600` on Unix (best-effort).
///
/// # Errors
///
/// Returns an error if a SAN entry is invalid, key generation or
/// self-signing fails, the files cannot be written, or the freshly written
/// PEM material cannot be loaded back into an acceptor.
pub fn generate_self_signed(
    cert_path: &Path,
    key_path: &Path,
    san: &[String],
) -> Result<TlsAcceptor> {
    let subjects: Vec<String> = if san.is_empty() {
        vec!["localhost".into(), "127.0.0.1".into(), "::1".into()]
    } else {
        san.to_vec()
    };

    let mut params = CertificateParams::new(subjects).context("invalid SAN entries")?;
    params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        rcgen::DnValue::Utf8String("AOS".into()),
    );
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("AOS Build Server".into()),
    );

    let key_pair = KeyPair::generate().context("generating TLS key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("signing certificate")?;

    // Ensure parent directories exist.
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    std::fs::write(cert_path, cert.pem())
        .with_context(|| format!("writing certificate to {}", cert_path.display()))?;
    std::fs::write(key_path, key_pair.serialize_pem())
        .with_context(|| format!("writing private key to {}", key_path.display()))?;

    // Restrict key file permissions (best-effort on non-Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }

    acceptor_from_pem(cert_path, key_path)
}

/// Loads an existing cert/key pair, or generates a self-signed one.
///
/// If both `cert_path` and `key_path` exist they are loaded as-is via
/// [`acceptor_from_pem`]; otherwise a new self-signed pair is created via
/// [`generate_self_signed`] and persisted to those paths for reuse on the
/// next start.
///
/// # Errors
///
/// Propagates errors from [`acceptor_from_pem`] or
/// [`generate_self_signed`].
pub fn load_or_generate(cert_path: &Path, key_path: &Path, san: &[String]) -> Result<TlsAcceptor> {
    if cert_path.exists() && key_path.exists() {
        acceptor_from_pem(cert_path, key_path)
    } else {
        generate_self_signed(cert_path, key_path, san)
    }
}

/// Returns the default filesystem path for the auto-generated certificate
/// (`/var/lib/aos/tls/server.crt`).
pub fn default_cert_path() -> PathBuf {
    PathBuf::from("/var/lib/aos/tls/server.crt")
}

/// Returns the default filesystem path for the auto-generated private key
/// (`/var/lib/aos/tls/server.key`).
pub fn default_key_path() -> PathBuf {
    PathBuf::from("/var/lib/aos/tls/server.key")
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Reads all PEM certificates from `path`, requiring at least one.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening certificate file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates from {}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

/// Reads the first PEM private key from `path`.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening private key file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing private key from {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path.display()))
}
