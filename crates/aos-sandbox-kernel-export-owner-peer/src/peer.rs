//! Closed two-descriptor Storage handoff receiver.
//!
//! The caller must independently pin the exact Storage service cgroup and
//! accept from a protected `RecordSubjectListener`. A peer/subject pidfd
//! sandwich rejects a different nominated process and stale service execution.
//! Kernel-authorized subject nomination alone cannot exclude a privileged
//! writer holding a delegated copy of the connected socket. Both
//! descriptor roles are remeasured, then dropped on every return path. No
//! descriptor, map handle, or stage capability leaves this module.

use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, KernelAuthorizedRecordSubject};
use rustix::fs::{FileType, OFlags, StatVfsMountFlags};

use crate::OwnerPeerError;
use crate::handoff::{DenyStageHandoff, HANDOFF_BYTES};

/// Retains only scalar observations after the incoming FDs are closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedHandoffReadback {
    frame: DenyStageHandoff,
    storage_process: PidFdInfo,
}

impl ClosedHandoffReadback {
    /// Returns the canonical frame without descriptor or stage authority.
    #[must_use]
    pub const fn frame(&self) -> &DenyStageHandoff {
        &self.frame
    }

    /// Returns the observed live Storage process snapshot.
    #[must_use]
    pub const fn storage_process(&self) -> PidFdInfo {
        self.storage_process
    }
}

/// Receives one exact two-FD handoff and closes both descriptors after readback.
///
/// `storage_cgroup` must come from independent protected deployment scope;
/// neither the socket path nor the received packet establishes that trust.
/// An accepted socket must come from a `RecordSubjectListener` with identity
/// options set before any child could be enqueued. The listener and cgroup
/// constructor remain unwired in production.
///
/// # Errors
///
/// Rejects wrong root Storage execution, changed connection/record subject,
/// malformed/truncated ancillary data, stale frame, wrong clone FD, wrong
/// cgroup FD, or any uncertain kernel identity/readback. On every outcome,
/// the transferred descriptors are closed and no map operation occurs.
pub fn receive_closed_handoff(
    socket: &mut DescriptorSubjectSocket,
    storage_cgroup: &RetainedCgroupAnchor,
) -> Result<ClosedHandoffReadback, OwnerPeerError> {
    let before = verify_storage_peer(storage_cgroup, socket.peer())?;
    let record = socket
        .receive(HANDOFF_BYTES, 2)
        .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
    let record = socket
        .bind_received(record)
        .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
    verify_record(storage_cgroup, before, record.peer(), record.subject())?;

    let frame = DenyStageHandoff::parse(record.payload())?;
    let descriptors = record.descriptors();
    let [clone, cgroup] = descriptors else {
        return Err(OwnerPeerError::Physical);
    };
    readback_clone(&frame, clone)?;
    readback_consumer(&frame, cgroup)?;
    verify_record(storage_cgroup, before, record.peer(), record.subject())?;

    Ok(ClosedHandoffReadback {
        frame,
        storage_process: before,
    })
}

fn verify_storage_peer(
    storage_cgroup: &RetainedCgroupAnchor,
    peer: &ConnectionPeerIdentity,
) -> Result<PidFdInfo, OwnerPeerError> {
    let credentials = peer.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(OwnerPeerError::Physical);
    }
    let info = storage_cgroup
        .verify_exact_membership(peer.pidfd())
        .map_err(|_| OwnerPeerError::Physical)?;
    let pid = credentials.pid().get();
    if info.pid() != pid
        || info.thread_group_id() != pid
        || !peer.is_alive().map_err(|_| OwnerPeerError::Physical)?
    {
        return Err(OwnerPeerError::Physical);
    }
    Ok(info)
}

fn verify_record(
    storage_cgroup: &RetainedCgroupAnchor,
    expected: PidFdInfo,
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(), OwnerPeerError> {
    let connection = verify_storage_peer(storage_cgroup, peer)?;
    let credentials = subject.credentials();
    let pid = credentials.pid().get();
    let current = storage_cgroup
        .verify_exact_membership(subject.pidfd())
        .map_err(|_| OwnerPeerError::Physical)?;
    if connection != expected
        || credentials.uid() != peer.credentials().uid()
        || credentials.gid() != peer.credentials().gid()
        || pid != peer.credentials().pid().get()
        || current != expected
        || current.pid() != pid
        || current.thread_group_id() != pid
        || !subject.is_alive().map_err(|_| OwnerPeerError::Physical)?
    {
        return Err(OwnerPeerError::Physical);
    }
    verify_storage_peer(storage_cgroup, peer).and_then(|after| {
        if after == expected {
            Ok(())
        } else {
            Err(OwnerPeerError::Physical)
        }
    })
}

fn readback_clone(
    frame: &DenyStageHandoff,
    clone: &std::os::fd::OwnedFd,
) -> Result<(), OwnerPeerError> {
    let stat = rustix::fs::fstat(clone).map_err(|_| OwnerPeerError::Physical)?;
    let flags = rustix::fs::fstatvfs(clone)
        .map_err(|_| OwnerPeerError::Physical)?
        .f_flag;
    let status = rustix::fs::fcntl_getfl(clone).map_err(|_| OwnerPeerError::Physical)?;
    let descriptor = rustix::io::fcntl_getfd(clone).map_err(|_| OwnerPeerError::Physical)?;
    let boot = KernelBootId::current()
        .map_err(|_| OwnerPeerError::Physical)?
        .into_bytes();
    let mount_id = MountId::from_fd(clone.as_fd())
        .map_err(|_| OwnerPeerError::Physical)?
        .get();

    if boot != frame.boot_id()
        || mount_id != frame.clone_mount_id()
        || (stat.st_dev, stat.st_ino) != frame.clone_root()
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || !flags.contains(
            StatVfsMountFlags::RDONLY | StatVfsMountFlags::NOSUID | StatVfsMountFlags::NODEV,
        )
        || !status.contains(OFlags::PATH)
        || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(OwnerPeerError::Physical);
    }
    Ok(())
}

fn readback_consumer(
    frame: &DenyStageHandoff,
    cgroup: &std::os::fd::OwnedFd,
) -> Result<(), OwnerPeerError> {
    let status = rustix::fs::fcntl_getfl(cgroup).map_err(|_| OwnerPeerError::Physical)?;
    let descriptor = rustix::io::fcntl_getfd(cgroup).map_err(|_| OwnerPeerError::Physical)?;
    if !status.contains(OFlags::PATH) || !descriptor.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(OwnerPeerError::Physical);
    }

    let duplicate = rustix::io::dup(cgroup).map_err(|_| OwnerPeerError::Physical)?;
    let root = CgroupV2Root::from_owned(duplicate).map_err(|_| OwnerPeerError::Physical)?;
    let anchor = root
        .resolve(Path::new("."))
        .map_err(|_| OwnerPeerError::Physical)?;
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if anchor.kernel_id() != frame.cgroup_id() || now >= frame.exclusive_expiry_seconds() {
        return Err(OwnerPeerError::Physical);
    }
    anchor
        .validate_current()
        .map_err(|_| OwnerPeerError::Physical)
}
