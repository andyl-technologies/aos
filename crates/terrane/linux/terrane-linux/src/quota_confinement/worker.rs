//! Installs a Unix-only network boundary around an original worker FUSE handle.
//!
//! The trusted launcher retains responsibility for the actual connection,
//! private backing channel, identity and filesystem isolation. This boundary
//! grants no mount, passthrough-registration or backing-disclosure authority.

use super::{Installed, policy, publisher};
use rustix::fs::{FileType, OFlags, fcntl_getfl, fstat};
use std::{io, os::fd::BorrowedFd};

/// Retains the original process's irreversible worker network confinement.
///
/// Only successful native installation and kernel socket probes construct this
/// value. It does not attest a complete worker sandbox or a mounted connection.
#[derive(Debug)]
pub struct WorkerNetworkInstalled {
    base: Installed,
}

impl WorkerNetworkInstalled {
    /// Checks the originating process and its irreversible kernel confinement.
    ///
    /// # Errors
    /// Refuses a forked process or unavailable/changed confinement state.
    pub fn check_current(&self) -> io::Result<()> {
        self.base.check_current()
    }
}

/// Installs Unix-only socket creation for a fresh worker with a real FUSE handle.
///
/// The launcher supplies its original read/write `/dev/fuse` descriptor before
/// any runtime or backing descriptors are created. Apart from that descriptor,
/// only standard I/O is accepted, under the same checked rules as the publisher.
/// Connected non-Unix sockets, extra handles and inherited rings are refused.
/// New backing descriptors remain subject to the independent worker protocol.
///
/// This uses the same source-audited ABI, credential, ring and descriptor-import
/// restrictions as the publisher. Unix socket creation remains available for
/// local protocols. The caller separately supplies filesystem isolation and the
/// remaining worker syscall policy; this is not a complete sandbox receipt.
///
/// # Errors
/// Refuses a descriptor other than a read/write FUSE character device before
/// installing any policy. Otherwise returns bootstrap, inherited-descriptor,
/// kernel-installation or socket-probe errors. Those later failures may leave
/// irreversible partial confinement and require process exit without fallback.
pub fn install_worker_network(fuse: BorrowedFd<'_>) -> io::Result<WorkerNetworkInstalled> {
    let metadata = fstat(fuse)?;
    let flags = fcntl_getfl(fuse)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::CharacterDevice
        || metadata.st_rdev != libc::makedev(10, 229)
        || flags.contains(OFlags::PATH)
        || flags & OFlags::ACCMODE != OFlags::RDWR
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker requires the original read/write FUSE descriptor",
        ));
    }

    let base = super::install()?;
    publisher::audit_descriptors(Some(fuse), "worker")?;
    policy::install_publisher()?;
    publisher::verify_socket_policy("worker")?;
    let installed = WorkerNetworkInstalled { base };
    installed.check_current()?;
    Ok(installed)
}
