//! Installs the publisher's fixed Unix-only socket boundary before resource startup.
//!
//! The quota filter first fixes credentials, ABIs and descriptor-import rules.
//! This layer checks inherited descriptors, adds an irreversible socket-family
//! restriction, and exercises its actual kernel decisions. It creates no cache
//! admission, metadata-retention or serving authority.

use super::{Installed, policy};
use rustix::{
    fs::{self as native, FileType, Mode, OFlags},
    net::{self, AddressFamily, SocketFlags, SocketType},
};
use std::{
    io::{self, IsTerminal},
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    sync::Arc,
};

/// Retains the originating process's installed publisher confinement.
///
/// Construction requires actual kernel installation and denied non-Unix socket
/// operations. Private fields prevent a caller-supplied assertion from creating
/// the receipt. The trusted host supplies standard input/output descriptors and
/// excludes inherited writable cache handles as required by [`super::install`].
#[derive(Debug)]
pub struct PublisherInstalled {
    quota: Arc<Installed>,
}

impl PublisherInstalled {
    /// Borrows the original quota-confinement receipt from the same installation.
    pub fn quota(&self) -> &Arc<Installed> {
        &self.quota
    }

    /// Checks the originating process and its irreversible confinement state.
    ///
    /// Additional seccomp filters cannot remove either installed restriction.
    ///
    /// # Errors
    /// Refuses a forked process or unavailable/changed kernel confinement state.
    pub fn check_current(&self) -> io::Result<()> {
        self.quota.check_current()
    }
}

/// Installs quota confinement and Unix-only socket creation for a fresh publisher.
///
/// The role must call this before runtimes, native roots or channels exist.
/// Inherited descriptors beyond standard input/output are refused. Standard
/// descriptors must be regular files, pipes, terminals, `/dev/null` or Unix
/// sockets; network sockets and other device handles are refused. The base
/// quota policy also rejects rings, alternate ABIs and cross-process descriptor
/// import. New descriptors received over the publisher protocol remain subject
/// to that protocol's independent regular-file checks.
///
/// # Errors
/// Returns base quota-confinement failures, unsupported inherited descriptors,
/// kernel installation failures or ineffective socket restrictions. Failure can
/// leave irreversible partial hardening; the process must exit without fallback.
pub fn install_publisher() -> io::Result<PublisherInstalled> {
    let quota = Arc::new(super::install()?);
    audit_descriptors(None, "publisher")?;
    policy::install_publisher()?;
    verify_socket_policy("publisher")?;
    let installed = PublisherInstalled { quota };
    installed.check_current()?;
    Ok(installed)
}

// The worker caller first validates its one declared original FUSE descriptor.
// A borrowed descriptor cannot disappear during this single-threaded bootstrap.
pub(super) fn audit_descriptors(fuse: Option<BorrowedFd<'_>>, role: &str) -> io::Result<()> {
    let fuse_number = fuse.map(|descriptor| descriptor.as_raw_fd());
    audit_standard(&io::stdin(), fuse_number, role)?;
    audit_standard(&io::stdout(), fuse_number, role)?;
    audit_standard(&io::stderr(), fuse_number, role)?;

    let descriptor = native::open(
        "/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let scanner_number = descriptor.as_raw_fd();
    let directory = native::Dir::new(descriptor)?;
    for entry in directory {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        let number = std::str::from_utf8(name)
            .map_err(io::Error::other)?
            .parse::<i32>()
            .map_err(io::Error::other)?;
        if number > 2 && number != scanner_number && Some(number) != fuse_number {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{role} inherited an undeclared descriptor"),
            ));
        }
    }
    Ok(())
}

fn audit_standard(
    handle: &(impl AsFd + IsTerminal),
    fuse: Option<i32>,
    role: &str,
) -> io::Result<()> {
    if Some(handle.as_fd().as_raw_fd()) == fuse {
        return Ok(());
    }
    let metadata = native::fstat(handle)?;
    match FileType::from_raw_mode(metadata.st_mode) {
        FileType::RegularFile | FileType::Fifo => Ok(()),
        FileType::CharacterDevice
            if metadata.st_rdev == libc::makedev(1, 3) || handle.is_terminal() =>
        {
            Ok(())
        }
        FileType::Socket if net::sockopt::socket_domain(handle)? == AddressFamily::UNIX => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{role} inherited unsupported standard I/O"),
        )),
    }
}

pub(super) fn verify_socket_policy(role: &str) -> io::Result<()> {
    // These calls allocate no network endpoint after a successful restriction;
    // they exchange no traffic and require no configured interface or service.
    for family in [AddressFamily::INET, AddressFamily::INET6] {
        match net::socket_with(family, SocketType::STREAM, SocketFlags::CLOEXEC, None) {
            Err(rustix::io::Errno::PERM) => {}
            Err(error) => return Err(error.into()),
            Ok(socket) => {
                drop(socket);
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{role} network socket creation remained available"),
                ));
            }
        }
    }
    match net::socketpair(
        AddressFamily::INET,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    ) {
        Err(rustix::io::Errno::PERM) => {}
        Err(error) => return Err(error.into()),
        Ok(sockets) => {
            drop(sockets);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{role} non-Unix socket pair remained available"),
            ));
        }
    }
    // The registered publisher and quota transports still need local sockets.
    drop(net::socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?);
    Ok(())
}
