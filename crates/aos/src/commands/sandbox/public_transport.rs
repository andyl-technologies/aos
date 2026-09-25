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
//! Authorized calls load `sandbox-capability-id` and a separate
//! `sandbox-capability-handle`. Both are bound to the authenticated TLS holder.
//! Attenuation saves a named, versioned capability ID and holder handle record
//! without modifying the active credential pair.
//! Execution attachment additionally loads one private file named
//! `sandbox-execution-<32 lowercase hex execution ID>-key`.
//!
//! Ancestors must not be group- or world-writable, the ownership chain cannot
//! return to root after entering user custody, and the private key is accepted
//! only as a private single-link regular file.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_sandbox_core::CapabilityId;
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
const CAPABILITY_ID: &str = "sandbox-capability-id";
const CAPABILITY_HANDLE: &str = "sandbox-capability-handle";
const NAMED_CAPABILITY_VERSION: &str = "aos.sandbox.capability/v1";
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
    connect_bundle(load_bundle(credentials)?, server_name).await
}

/// Establishes the public connection and loads its protected capability lookup key.
///
/// # Errors
///
/// Rejects the ordinary public transport failures or an absent, unsafe,
/// malformed, noncanonical, or zero capability identity credential.
pub(super) async fn connect_authorized(
    credentials: &Path,
    server_name: &str,
    capability_name: Option<&str>,
) -> Result<(Http2Connection, Uri, CapabilityId, [u8; 32])> {
    let (bundle, capability_id, capability_handle) =
        load_authorized_bundle(credentials, capability_name)?;
    let (connection, authority) = connect_bundle(bundle, server_name).await?;
    Ok((connection, authority, capability_id, capability_handle))
}

async fn connect_bundle(
    bundle: CredentialBundle,
    server_name: &str,
) -> Result<(Http2Connection, Uri)> {
    let (server_name, authority) = server_identity(server_name)?;
    let configuration = Arc::new(tls_configuration(bundle)?);
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
    load_bundle_from(&directory, uid)
}

fn load_authorized_bundle(
    path: &Path,
    capability_name: Option<&str>,
) -> Result<(CredentialBundle, CapabilityId, [u8; 32])> {
    let uid = rustix::process::geteuid().as_raw();
    let directory = open_protected_directory(path, uid)?;
    let bundle = load_bundle_from(&directory, uid)?;
    let (capability, handle) = load_capability_from(&directory, uid, capability_name)?;

    Ok((bundle, capability, handle))
}

/// Loads the protected capability lookup key without opening a connection.
///
/// # Errors
///
/// Rejects an absent, unsafe, malformed, noncanonical, or zero capability
/// identity credential.
pub(super) fn load_capability_id(
    path: &Path,
    capability_name: Option<&str>,
) -> Result<CapabilityId> {
    let uid = rustix::process::geteuid().as_raw();
    let directory = open_protected_directory(path, uid)?;
    let (capability, _) = load_capability_from(&directory, uid, capability_name)?;
    Ok(capability)
}

fn load_capability_from(
    directory: &OwnedFd,
    uid: u32,
    capability_name: Option<&str>,
) -> Result<(CapabilityId, [u8; 32])> {
    if let Some(name) = capability_name {
        let filename = named_capability_filename(name)?;
        let record = Zeroizing::new(read_credential(directory, uid, &filename, true)?);
        return parse_named_capability(&record);
    }

    let id = read_credential(directory, uid, CAPABILITY_ID, true)?;
    let handle = Zeroizing::new(read_credential(directory, uid, CAPABILITY_HANDLE, true)?);
    Ok((parse_capability_id(&id)?, parse_capability_handle(&handle)?))
}

fn named_capability_filename(name: &str) -> Result<String> {
    crate::cli::sandbox::capability_name(name)
        .map_err(anyhow::Error::msg)
        .context("named capability selector is invalid")?;
    Ok(format!("sandbox-capability-{name}"))
}

fn parse_named_capability(record: &[u8]) -> Result<(CapabilityId, [u8; 32])> {
    let text = std::str::from_utf8(record).context("named capability is not UTF-8")?;
    let mut lines = text.split('\n');
    if lines.next() != Some(NAMED_CAPABILITY_VERSION) {
        bail!("named capability has an unsupported format version");
    }
    let id = lines
        .next()
        .context("named capability omits its identity")?;
    let handle = lines
        .next()
        .context("named capability omits its holder handle")?;
    if lines.next().is_some() {
        bail!("named capability has trailing data");
    }
    Ok((
        parse_capability_id(id.as_bytes())?,
        parse_capability_handle(handle.as_bytes())?,
    ))
}

/// Saves a returned capability ID and handle as one new private record.
///
/// # Errors
///
/// Rejects unsafe directory custody, invalid identity or handle, a mismatched
/// existing record, and any failure to durably publish the credential.
pub(super) fn save_named_capability(
    path: &Path,
    name: &str,
    capability_id: &[u8],
    handle: &[u8],
) -> Result<()> {
    let filename = named_capability_filename(name)?;
    let id_bytes: [u8; 16] = capability_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("successor capability identity is invalid"))?;
    if id_bytes == [0; 16] {
        bail!("successor capability identity is invalid");
    }
    let id = CapabilityId::from_bytes(id_bytes);
    if handle.len() != 32 || handle.iter().all(|byte| *byte == 0) {
        bail!("successor holder handle is invalid");
    }

    let uid = rustix::process::geteuid().as_raw();
    let directory = open_protected_directory(path, uid)?;
    save_named_capability_in(directory, uid, &filename, id, handle)
}

fn save_named_capability_in(
    directory: OwnedFd,
    uid: u32,
    filename: &str,
    id: CapabilityId,
    handle: &[u8],
) -> Result<()> {
    let encoded_handle = Zeroizing::new(hex::encode(handle));
    let record = Zeroizing::new(format!(
        "{NAMED_CAPABILITY_VERSION}\n{id}\n{}",
        encoded_handle.as_str()
    ));
    let temporary_name = format!(
        ".sandbox-capability-{}.tmp",
        hex::encode(rand::random::<[u8; 16]>())
    );
    let descriptor = openat(
        &directory,
        &temporary_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .context("cannot create temporary named capability")?;
    let mut file = File::from(descriptor);

    let publication = (|| -> Result<()> {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("cannot protect temporary named capability")?;
        file.write_all(record.as_bytes())
            .context("cannot write temporary named capability")?;
        file.sync_all()
            .context("cannot sync temporary named capability")?;

        // Readers see either the complete record or no named capability.
        match rustix::fs::renameat_with(
            &directory,
            &temporary_name,
            &directory,
            filename,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::EXIST) => {
                let existing = Zeroizing::new(read_credential(&directory, uid, filename, true)?);
                if existing.as_slice() == record.as_bytes() {
                    Ok(())
                } else {
                    bail!("named capability {filename} already contains another identity or handle")
                }
            }
            Err(error) => Err(error).context("cannot publish named capability"),
        }
    })();
    if let Err(error) =
        rustix::fs::unlinkat(&directory, &temporary_name, rustix::fs::AtFlags::empty())
    {
        if error != rustix::io::Errno::NOENT {
            return Err(error).context("cannot remove temporary named capability");
        }
    }
    publication?;
    File::from(directory)
        .sync_all()
        .context("cannot sync named capability directory")
}

/// Loads the holder's execution-specific OpenSSH key from protected custody.
///
/// # Errors
///
/// Rejects an invalid execution identity, absent key, or unsafe directory or
/// file custody.
pub(super) fn load_execution_private_key(
    path: &Path,
    execution_id: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if execution_id.len() != 16 || execution_id.iter().all(|byte| *byte == 0) {
        bail!("sandbox execution private key requires an exact execution identity");
    }
    let name = format!("sandbox-execution-{}-key", hex::encode(execution_id));
    let uid = rustix::process::geteuid().as_raw();
    let directory = open_protected_directory(path, uid)?;
    Ok(Zeroizing::new(read_credential(
        &directory, uid, &name, true,
    )?))
}

fn parse_capability_id(bytes: &[u8]) -> Result<CapabilityId> {
    let capability = std::str::from_utf8(bytes)
        .context("sandbox public capability identity is not UTF-8")?
        .parse::<CapabilityId>()
        .context("sandbox public capability identity is not canonical")?;
    if capability.as_bytes() == &[0; 16] {
        bail!("sandbox public capability identity must be nonzero");
    }

    Ok(capability)
}

fn parse_capability_handle(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        bail!("sandbox public capability handle is not canonical lowercase hex");
    }
    let text =
        std::str::from_utf8(bytes).context("sandbox public capability handle is not UTF-8")?;
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("sandbox public capability handle is not canonical lowercase hex");
    }
    let decoded = hex::decode(text).context("sandbox public capability handle is invalid")?;
    let handle: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("sandbox public capability handle is invalid"))?;
    if handle == [0; 32] {
        bail!("sandbox public capability handle must be nonzero");
    }
    Ok(handle)
}

fn load_bundle_from(directory: &OwnedFd, uid: u32) -> Result<CredentialBundle> {
    Ok(CredentialBundle {
        server_ca: read_credential(directory, uid, SERVER_CA, false)?,
        client_certificate: read_credential(directory, uid, CLIENT_CERTIFICATE, false)?,
        client_key: Zeroizing::new(read_credential(directory, uid, CLIENT_KEY, true)?),
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
    use std::os::unix::fs::symlink;

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

    fn save_test_named_capability(
        directory: &tempfile::TempDir,
        name: &str,
        id: CapabilityId,
        handle: &[u8],
    ) -> Result<()> {
        save_named_capability_in(
            open_credential_directory(directory),
            rustix::process::geteuid().as_raw(),
            &named_capability_filename(name)?,
            id,
            handle,
        )
    }

    #[test]
    fn bootstrap_tls_bundle_does_not_require_an_active_capability() {
        let directory = credential_directory();
        let descriptor = open_credential_directory(&directory);
        let uid = rustix::process::geteuid().as_raw();

        assert!(load_bundle_from(&descriptor, uid).is_ok());
        assert!(load_capability_from(&descriptor, uid, None).is_err());
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

    #[test]
    fn capability_identity_is_exact_canonical_nonzero_text() {
        let capability = parse_capability_id(b"00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(
            capability.to_string(),
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        for invalid in [
            b"00112233-4455-6677-8899-AABBCCDDEEFF".as_slice(),
            b"00112233-4455-6677-8899-aabbccddeeff\n".as_slice(),
            b"00000000-0000-0000-0000-000000000000".as_slice(),
            &[0xff],
        ] {
            assert!(parse_capability_id(invalid).is_err());
        }
    }

    #[test]
    fn capability_handle_is_exact_lowercase_nonzero_hex() {
        let handle = [0x5a; 32];
        let encoded = hex::encode(handle);
        assert_eq!(parse_capability_handle(encoded.as_bytes()).unwrap(), handle);

        for invalid in [
            encoded.to_uppercase(),
            format!("{encoded}\n"),
            "00".repeat(32),
            "5a".repeat(16),
        ] {
            assert!(parse_capability_handle(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn named_capability_is_atomic_private_and_idempotent_for_the_same_pair() {
        let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let name = "child";
        let id = CapabilityId::from_bytes([0x11; 16]);
        let handle = [0x5a; 32];
        let parent_id = CapabilityId::from_bytes([0x22; 16]);
        let parent_handle = [0x6b; 32];
        std::fs::write(directory.path().join(CAPABILITY_ID), parent_id.to_string()).unwrap();
        std::fs::write(
            directory.path().join(CAPABILITY_HANDLE),
            hex::encode(parent_handle),
        )
        .unwrap();
        for credential in [CAPABILITY_ID, CAPABILITY_HANDLE] {
            std::fs::set_permissions(
                directory.path().join(credential),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }

        save_test_named_capability(&directory, name, id, &handle).unwrap();
        let file = directory.path().join("sandbox-capability-child");
        assert_eq!(
            parse_named_capability(&std::fs::read(&file).unwrap()).unwrap(),
            (id, handle)
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let opened = open_credential_directory(&directory);
        let uid = rustix::process::geteuid().as_raw();
        assert_eq!(
            load_capability_from(&opened, uid, Some(name)).unwrap(),
            (id, handle)
        );
        assert_eq!(
            load_capability_from(&opened, uid, None).unwrap(),
            (parent_id, parent_handle)
        );
        assert_eq!(
            std::fs::read(directory.path().join(CAPABILITY_HANDLE)).unwrap(),
            hex::encode(parent_handle).as_bytes()
        );
        save_test_named_capability(&directory, name, id, &handle).unwrap();

        assert!(save_test_named_capability(&directory, name, id, &[0xa5; 32]).is_err());
        assert!(save_test_named_capability(&directory, name, parent_id, &handle).is_err());
        assert_eq!(
            parse_named_capability(&std::fs::read(&file).unwrap()).unwrap(),
            (id, handle)
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 3);
    }

    #[test]
    fn named_capability_rejects_symlinks_and_hardlinks() {
        let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"unchanged").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

        let symlink_name = "sandbox-capability-symlink";
        symlink(&target, directory.path().join(symlink_name)).unwrap();
        assert!(
            save_test_named_capability(
                &directory,
                "symlink",
                CapabilityId::from_bytes([0x11; 16]),
                &[0x5a; 32]
            )
            .is_err()
        );

        let hardlink_name = "sandbox-capability-hardlink";
        std::fs::hard_link(&target, directory.path().join(hardlink_name)).unwrap();
        assert!(
            save_test_named_capability(
                &directory,
                "hardlink",
                CapabilityId::from_bytes([0x11; 16]),
                &[0x5a; 32]
            )
            .is_err()
        );
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    }

    #[test]
    fn named_capability_write_stays_on_the_opened_directory_after_replacement() {
        let parent = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let original = parent.path().join("credentials");
        let moved = parent.path().join("moved-credentials");
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();

        let uid = rustix::process::geteuid().as_raw();
        let opened = open(
            &original,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();

        let name = "sandbox-capability-raced";
        save_named_capability_in(
            opened,
            uid,
            name,
            CapabilityId::from_bytes([0x11; 16]),
            &[0x5a; 32],
        )
        .unwrap();
        assert!(moved.join(name).is_file());
        assert!(!original.join(name).exists());
    }

    #[test]
    fn named_capability_decoder_rejects_other_versions_and_trailing_data() {
        let id = "11111111-1111-1111-1111-111111111111";
        let handle = "5a".repeat(32);
        for record in [
            format!("aos.sandbox.capability/v2\n{id}\n{handle}"),
            format!("{NAMED_CAPABILITY_VERSION}\n{id}\n{handle}\n"),
            format!("{NAMED_CAPABILITY_VERSION}\n{id}\n{}", "5A".repeat(32)),
        ] {
            assert!(parse_named_capability(record.as_bytes()).is_err());
        }
    }
}
