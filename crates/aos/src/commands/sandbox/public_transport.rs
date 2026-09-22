//! Connects the sandbox CLI to the registered mutual-TLS public Unix endpoint.
//!
//! The credential bundle is a private user-owned directory containing:
//!
//! ```text
//! sandbox-server-ca
//! sandbox-client-cert
//! sandbox-client-key
//! ```
//!
//! Ancestors must not be group- or world-writable, the ownership chain cannot
//! return to root after entering user custody, and the private key is accepted
//! only as a private single-link regular file.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use connectrpc::client::Http2Connection;
use http::Uri;
use rustix::fs::{Mode, OFlags, open, openat};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use zeroize::Zeroizing;

const PUBLIC_SOCKET: &str = "/run/aos/sandboxd/public.sock";
const SERVER_CA: &str = "sandbox-server-ca";
const CLIENT_CERTIFICATE: &str = "sandbox-client-cert";
const CLIENT_KEY: &str = "sandbox-client-key";
const MAXIMUM_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

struct CredentialBundle {
    server_ca: Vec<u8>,
    client_certificate: Vec<u8>,
    client_key: Zeroizing<Vec<u8>>,
}

/// Establishes one TLS 1.3 and HTTP/2 connection to the fixed public socket.
///
/// # Errors
///
/// Rejects unsafe credential custody, malformed PEM, an invalid server name,
/// failure to connect, TLS authentication failure, or HTTP/2 negotiation failure.
pub(super) async fn connect(
    credentials: &Path,
    server_name: &str,
) -> Result<(Http2Connection, Uri)> {
    let (server_name, authority) = server_identity(server_name)?;
    let configuration = Arc::new(tls_configuration(load_bundle(credentials)?)?);
    let connector = tower::service_fn(move |_uri: Uri| {
        let configuration = Arc::clone(&configuration);
        let server_name = server_name.clone();
        async move {
            let stream = tokio::net::UnixStream::connect(PUBLIC_SOCKET).await?;
            let stream = tokio_rustls::TlsConnector::from(configuration)
                .connect(server_name, stream)
                .await
                .map_err(std::io::Error::other)?;
            let negotiated = stream.get_ref().1;
            if negotiated.alpn_protocol() != Some(b"h2")
                || negotiated.protocol_version()
                    != Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
            {
                return Err(std::io::Error::other(
                    "sandbox public API did not negotiate TLS 1.3 with HTTP/2",
                ));
            }
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
        }
    });
    let connection = tokio::time::timeout(
        CONNECT_TIMEOUT,
        Http2Connection::connect_with_connector(connector, authority.clone()),
    )
    .await
    .context("sandbox public API authentication timed out")?
    .context("cannot authenticate the sandbox public API")?;

    Ok((connection, authority))
}

fn server_identity(value: &str) -> Result<(ServerName<'static>, Uri)> {
    let starts_with_bracket = value.starts_with('[');
    let ends_with_bracket = value.ends_with(']');
    if starts_with_bracket != ends_with_bracket {
        bail!("sandbox public API server name has unmatched brackets");
    }
    let tls_name = if starts_with_bracket {
        value
            .strip_prefix('[')
            .and_then(|name| name.strip_suffix(']'))
            .context("invalid sandbox public API server name")?
    } else {
        value
    };
    if starts_with_bracket && !tls_name.contains(':') {
        bail!("only an IPv6 sandbox public API server name may use brackets");
    }

    let server_name =
        ServerName::try_from(tls_name.to_owned()).context("invalid sandbox public API TLS name")?;
    let authority_name = if tls_name.contains(':') {
        format!("[{tls_name}]")
    } else {
        tls_name.to_owned()
    };
    let authority = format!("https://{authority_name}")
        .parse()
        .context("invalid sandbox public API authority")?;
    Ok((server_name, authority))
}

fn load_bundle(path: &Path) -> Result<CredentialBundle> {
    let uid = rustix::process::geteuid().as_raw();
    let directory = open_protected_directory(path, uid)?;
    Ok(CredentialBundle {
        server_ca: read_credential(&directory, uid, SERVER_CA, false)?,
        client_certificate: read_credential(&directory, uid, CLIENT_CERTIFICATE, false)?,
        client_key: Zeroizing::new(read_credential(&directory, uid, CLIENT_KEY, true)?),
    })
}

fn open_protected_directory(path: &Path, uid: u32) -> Result<OwnedFd> {
    if !path.is_absolute() {
        bail!("sandbox public credential directory must be absolute");
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open("/", flags, Mode::empty()).context("cannot open sandbox public credential root")?;
    let mut user_owned = false;

    for component in path.components() {
        let metadata = rustix::fs::fstat(&directory)
            .context("cannot inspect sandbox public credential custody")?;
        if metadata.st_mode & 0o022 != 0
            || (metadata.st_uid != 0 && metadata.st_uid != uid)
            || (user_owned && metadata.st_uid != uid)
        {
            bail!("sandbox public credential directory has unsafe custody");
        }
        user_owned |= metadata.st_uid == uid;

        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .context("cannot open sandbox public credential directory")?;
            }
            _ => bail!("sandbox public credential directory is not canonical"),
        }
    }

    let metadata = rustix::fs::fstat(&directory)
        .context("cannot inspect sandbox public credential directory")?;
    if metadata.st_uid != uid || metadata.st_mode & 0o077 != 0 {
        bail!("sandbox public credential directory must be private and user-owned");
    }
    Ok(directory)
}

fn read_credential(directory: &OwnedFd, uid: u32, name: &str, private: bool) -> Result<Vec<u8>> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| format!("cannot open sandbox public credential {name}"))?;
    let mut file = File::from(descriptor);
    let before = file
        .metadata()
        .with_context(|| format!("cannot inspect sandbox public credential {name}"))?;
    let forbidden_mode = if private { 0o077 } else { 0o022 };
    if !before.is_file()
        || before.uid() != uid
        || before.mode() & forbidden_mode != 0
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAXIMUM_CREDENTIAL_BYTES
    {
        bail!("sandbox public credential {name} has unsafe custody");
    }

    let mut bytes = Vec::new();
    (&mut file)
        .take(MAXIMUM_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read sandbox public credential {name}"))?;
    let after = file
        .metadata()
        .with_context(|| format!("cannot recheck sandbox public credential {name}"))?;
    if before.len() != bytes.len() as u64 || metadata_identity(&before) != metadata_identity(&after)
    {
        bail!("sandbox public credential {name} changed while loading");
    }
    Ok(bytes)
}

fn metadata_identity(
    metadata: &std::fs::Metadata,
) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn tls_configuration(bundle: CredentialBundle) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let roots_read = rustls_pemfile::certs(&mut bundle.server_ca.as_slice())
        .collect::<std::io::Result<Vec<_>>>()?;
    if roots_read.is_empty() {
        bail!("sandbox public server CA contains no certificates");
    }
    for certificate in roots_read {
        roots
            .add(certificate)
            .context("sandbox public server CA contains an invalid certificate")?;
    }

    let certificates = rustls_pemfile::certs(&mut bundle.client_certificate.as_slice())
        .collect::<std::io::Result<Vec<_>>>()?;
    if certificates.is_empty() {
        bail!("sandbox public client certificate file contains no certificates");
    }
    let mut key_reader = bundle.client_key.as_slice();
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .context("sandbox public client key file contains no private key")?;
    if rustls_pemfile::private_key(&mut key_reader)?.is_some() {
        bail!("sandbox public client key file contains multiple private keys");
    }

    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let mut configuration = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .context("cannot require TLS 1.3 for the sandbox public API")?
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)
        .context("sandbox public client identity is invalid")?;
    configuration.alpn_protocols = vec![b"h2".to_vec()];
    configuration.enable_early_data = false;
    configuration.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    Ok(configuration)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    fn credential_directory() -> tempfile::TempDir {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        std::fs::write(directory.path().join(SERVER_CA), b"ca").unwrap();
        std::fs::write(directory.path().join(CLIENT_CERTIFICATE), b"cert").unwrap();
        std::fs::write(directory.path().join(CLIENT_KEY), b"key").unwrap();
        std::fs::set_permissions(
            directory.path().join(CLIENT_KEY),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        directory
    }

    fn open_credential_directory(directory: &tempfile::TempDir) -> OwnedFd {
        open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn protected_bundle_requires_private_key_custody() {
        let directory = credential_directory();
        let descriptor = open_credential_directory(&directory);
        assert_eq!(
            read_credential(
                &descriptor,
                rustix::process::geteuid().as_raw(),
                CLIENT_KEY,
                true
            )
            .unwrap(),
            b"key"
        );

        std::fs::set_permissions(
            directory.path().join(CLIENT_KEY),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(
            read_credential(
                &descriptor,
                rustix::process::geteuid().as_raw(),
                CLIENT_KEY,
                true
            )
            .is_err()
        );
    }

    #[test]
    fn protected_bundle_rejects_a_symlinked_key() {
        let directory = credential_directory();
        let key = directory.path().join(CLIENT_KEY);
        std::fs::remove_file(&key).unwrap();
        symlink(directory.path().join(CLIENT_CERTIFICATE), key).unwrap();

        assert!(
            read_credential(
                &open_credential_directory(&directory),
                rustix::process::geteuid().as_raw(),
                CLIENT_KEY,
                true
            )
            .is_err()
        );
    }

    #[test]
    fn protected_bundle_rejects_a_writable_ancestor() {
        let directory = credential_directory();
        assert!(
            open_protected_directory(directory.path(), rustix::process::geteuid().as_raw())
                .is_err()
        );
    }

    #[test]
    fn public_transport_server_identity_accepts_dns_and_ipv6_without_ports() {
        let (_, dns_authority) = server_identity("sandbox-controller.example").unwrap();
        assert_eq!(
            dns_authority.authority().map(http::uri::Authority::host),
            Some("sandbox-controller.example")
        );

        for value in ["2001:db8::1", "[2001:db8::1]"] {
            let (_, ipv6_authority) = server_identity(value).unwrap();
            assert_eq!(
                ipv6_authority.authority().map(http::uri::Authority::host),
                Some("[2001:db8::1]")
            );
        }

        assert!(server_identity("sandbox-controller.example:443").is_err());
        assert!(server_identity("[sandbox-controller.example]").is_err());
    }
}
