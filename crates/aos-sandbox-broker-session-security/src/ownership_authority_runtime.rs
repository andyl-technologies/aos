//! Fixed activation and protected credentials for the ownership authority.
//!
//! Only systemd's one named `SOCK_SEQPACKET` listener is accepted. Its record
//! subject options and filesystem path are verified before any connection is
//! admitted. The authority journal, trust bootstrap, issuer inbox, and paired
//! clock come from the existing fixed root owner, never from client messages.
//! A malformed or lost connection is discarded without abandoning the durable
//! transaction; a later client must query its exact binding.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

use aos_sandbox::multi_node::ProtectedFixedMultiNodeLeaseOwnerV1;
use aos_sandbox::ownership_service::OwnershipProtocolRequestHandler;
use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{Mode, OFlags, open};
use zeroize::Zeroizing;

use crate::ownership_authority_server::LocalOwnershipAuthorityServerV1;
use crate::production_activation::{activation_names, validate_activation_process};

const FD_NAME: &str = "aos-sandbox-ownership";
const SOCKET_PATH: &str = "/run/aos/sandbox-ownership/control.sock";
const CREDENTIAL_NAME: &str = "ownership-session-key";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Reports fail-closed ownership-authority activation or protected-state failure.
#[derive(Debug, thiserror::Error)]
pub enum ProductionOwnershipAuthorityRuntimeErrorV1 {
    /// The daemon is not running under the fixed root service identity.
    #[error("ownership authority requires real and effective UID zero")]
    Identity,
    /// The controller's fixed UID/GID arguments are malformed.
    #[error("ownership authority controller identity is invalid")]
    Arguments,
    /// The exact named systemd listener was not supplied.
    #[error("ownership authority activation is invalid")]
    Activation,
    /// The inherited listener or accepted child violates its socket contract.
    #[error("ownership authority listener is invalid")]
    Listener,
    /// The local record-authentication credential is absent or unsafe.
    #[error("ownership authority session credential is invalid")]
    Credential,
    /// The fixed authority bootstrap, journal, issuer, or clock failed to open.
    #[error("ownership authority protected state is unavailable")]
    ProtectedState,
}

/// Runs the fixed authority service from systemd's protected environment.
///
/// Arguments are the configured controller UID and GID. The sole inherited
/// descriptor must be named `aos-sandbox-ownership` and bound to
/// `/run/aos/sandbox-ownership/control.sock`. The 32-byte
/// `ownership-session-key` is loaded from `CREDENTIALS_DIRECTORY`.
///
/// # Errors
///
/// Returns an error for invalid activation, credentials, process identity,
/// listener state, or protected authority opening. Individual untrusted
/// connection failures close only that connection.
pub fn run_from_environment() -> Result<(), ProductionOwnershipAuthorityRuntimeErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(ProductionOwnershipAuthorityRuntimeErrorV1::Identity);
    }
    let (controller_uid, controller_gid) = controller_identity()?;
    let mut listener = adopt_listener()?;
    let secret = load_session_secret()?;
    let mut owner = ProtectedFixedMultiNodeLeaseOwnerV1::open_fixed_protected()
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::ProtectedState)?;

    loop {
        let socket = accept_next(&mut listener)?;
        let server = LocalOwnershipAuthorityServerV1::from_accepted(
            socket,
            owner.authority().clone(),
            controller_uid,
            controller_gid,
            secret.clone(),
            REQUEST_TIMEOUT,
        );
        let Ok(mut server) = server else {
            continue;
        };
        while server.serve_one(&mut owner).is_ok() {}
    }
}

fn controller_identity() -> Result<(u32, u32), ProductionOwnershipAuthorityRuntimeErrorV1> {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    let uid = arguments
        .next()
        .ok_or(ProductionOwnershipAuthorityRuntimeErrorV1::Arguments)?
        .parse()
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Arguments)?;
    let gid = arguments
        .next()
        .ok_or(ProductionOwnershipAuthorityRuntimeErrorV1::Arguments)?
        .parse()
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Arguments)?;
    if arguments.next().is_some() {
        return Err(ProductionOwnershipAuthorityRuntimeErrorV1::Arguments);
    }
    Ok((uid, gid))
}

fn adopt_listener() -> Result<RecordSubjectListener, ProductionOwnershipAuthorityRuntimeErrorV1> {
    validate_activation_process(1)
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Activation)?;
    let names =
        activation_names(1).map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Activation)?;
    if names[0] != FD_NAME {
        return Err(ProductionOwnershipAuthorityRuntimeErrorV1::Activation);
    }
    // SAFETY: this is the single-threaded process entrypoint before any code
    // owns or mutates systemd's fixed descriptor 3. PID 1 transfers exactly
    // one listener under the checked descriptor name and process identity.
    let descriptors = unsafe { claim_systemd_activation_descriptor_range(0, 1) }
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Activation)?
        .into_descriptors();
    let [descriptor]: [OwnedFd; 1] = descriptors
        .try_into()
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Activation)?;
    let listener = RecordSubjectListener::from_owned(descriptor)
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Listener)?;
    listener
        .require_local_filesystem_path(Path::new(SOCKET_PATH))
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Listener)?;
    Ok(listener)
}

fn load_session_secret() -> Result<Zeroizing<[u8; 32]>, ProductionOwnershipAuthorityRuntimeErrorV1>
{
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or(ProductionOwnershipAuthorityRuntimeErrorV1::Credential)?;
    if !Path::new(&directory).is_absolute() {
        return Err(ProductionOwnershipAuthorityRuntimeErrorV1::Credential);
    }
    let path = Path::new(&directory).join(CREDENTIAL_NAME);
    let descriptor = open(
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Credential)?;
    let metadata = rustix::fs::fstat(&descriptor)
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Credential)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o077 != 0
        || metadata.st_size != 32
    {
        return Err(ProductionOwnershipAuthorityRuntimeErrorV1::Credential);
    }
    let mut file = File::from(descriptor);
    let mut secret = Zeroizing::new([0; 32]);
    file.read_exact(&mut *secret)
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Credential)?;
    let mut trailing = [0];
    if file
        .read(&mut trailing)
        .map_err(|_| ProductionOwnershipAuthorityRuntimeErrorV1::Credential)?
        != 0
        || *secret == [0; 32]
    {
        return Err(ProductionOwnershipAuthorityRuntimeErrorV1::Credential);
    }
    Ok(secret)
}

fn accept_next(
    listener: &mut RecordSubjectListener,
) -> Result<aos_sandbox_linux::seqpacket::SeqpacketSocket, ProductionOwnershipAuthorityRuntimeErrorV1>
{
    loop {
        match listener.accept() {
            Ok(socket) => return Ok(socket),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {}
            Err(_) => return Err(ProductionOwnershipAuthorityRuntimeErrorV1::Listener),
        }
        let mut descriptors = [PollFd::from_borrowed_fd(listener.as_fd(), PollFlags::IN)];
        match poll(&mut descriptors, None) {
            Ok(_) if descriptors[0].revents() == PollFlags::IN => {}
            Err(rustix::io::Errno::INTR) => {}
            _ => return Err(ProductionOwnershipAuthorityRuntimeErrorV1::Listener),
        }
    }
}
