//! Host client for one Storage-authenticated detached guest-root mount.
//!
//! The caller supplies an assignment-bound [`ResolvedWorkspace`] from the
//! protected Host catalog. Storage rederives current authenticated inventory;
//! Host verifies the exact reply, live Storage record subject, and mount FD.
//! The returned mount is still not launch permission: backend and resource
//! readiness must independently admit the payload.

use std::path::Path;

use aos_sandbox_agent::guest_root_label::verify_copied_guest_executable_labels_fd_v1;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::mount::DetachedMount;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::storage_root_export::{
    STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1, StorageRootExportRequestV1, StorageRootExportResponseV1,
};
use rand::{TryRngCore as _, rngs::OsRng};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::plan::ResolvedWorkspace;
use crate::{HostError, Result};

const EXPORT_SOCKET: &str = "/run/aos/sandbox-storage/root-export.sock";
const STORAGE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const EXPORT_DEADLINE_NANOSECONDS: u64 = 130_000_000_000;

/// Retains the exact Storage service cgroup for detached-root replies.
#[derive(Debug)]
pub struct StorageRootMountClientV1 {
    storage_cgroup: RetainedCgroupAnchor,
}

impl StorageRootMountClientV1 {
    /// Opens the fixed Storage service cgroup beneath a retained cgroup-v2 root.
    ///
    /// # Errors
    ///
    /// Returns an error when the service cgroup is absent or inactive.
    pub fn new(cgroup_root: CgroupV2Root) -> Result<Self> {
        let storage_cgroup = cgroup_root
            .resolve(Path::new(STORAGE_CGROUP))
            .map_err(|error| HostError::State(error.to_string()))?;
        storage_cgroup
            .validate_current()
            .map_err(|error| HostError::State(error.to_string()))?;
        Ok(Self { storage_cgroup })
    }

    /// Requests one exact catalogued guest root and validates its detached FD.
    ///
    /// Storage clones a fresh mount for each request. Its unique mount ID is
    /// valid for this returned descriptor, not a stable assignment identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for missing publication proof, stale Storage inventory,
    /// wrong responder, malformed reply, expired deadline, or mismatched mount.
    pub fn export(&self, workspace: &ResolvedWorkspace) -> Result<DetachedMount> {
        let proof = workspace.guest_root_publication().ok_or_else(|| {
            HostError::Catalog("workspace lacks guest-root publication proof".to_owned())
        })?;
        self.storage_cgroup
            .validate_current()
            .map_err(export_error)?;
        let mut socket =
            DescriptorSubjectSocket::connect(Path::new(EXPORT_SOCKET)).map_err(export_error)?;
        let mut nonce = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| HostError::State("root export entropy unavailable".to_owned()))?;
        if nonce == [0; 32] {
            return Err(HostError::State("root export nonce is invalid".to_owned()));
        }
        let deadline = boottime()?
            .checked_add(EXPORT_DEADLINE_NANOSECONDS)
            .ok_or_else(|| HostError::State("root export deadline overflow".to_owned()))?;
        let request = StorageRootExportRequestV1 {
            nonce,
            deadline_boottime_nanoseconds: deadline,
            proof,
        };
        let bytes = request.encode().map_err(export_error)?;
        send_request(&mut socket, &bytes, deadline)?;

        let record = receive_reply(&mut socket, deadline)?;
        let record = socket.bind_received(record).map_err(export_error)?;
        let credentials = record.subject().credentials();
        if credentials.uid() != 0 || credentials.gid() != 0 {
            return Err(HostError::State(
                "root export responder is invalid".to_owned(),
            ));
        }
        let info = self
            .storage_cgroup
            .verify_exact_membership(record.subject().pidfd())
            .map_err(export_error)?;
        if info.pid() != credentials.pid().get()
            || info.thread_group_id() != info.pid()
            || !record.subject().is_alive().map_err(export_error)?
            || record.descriptors().len() != 1
        {
            return Err(HostError::State(
                "root export responder is invalid".to_owned(),
            ));
        }
        let response =
            StorageRootExportResponseV1::decode(record.payload()).map_err(export_error)?;
        if response.nonce != nonce
            || response.request_digest != request.digest().map_err(export_error)?
            || response.root_device != workspace.device
            || response.root_inode != workspace.inode
        {
            return Err(HostError::State(
                "root export reply differs from catalog".to_owned(),
            ));
        }
        let (_, subject, mut descriptors, _) = record.into_parts();
        // Detachment is vouched for by the authenticated Storage export path;
        // kernel identity checks below bind that claim to the received object.
        let mount = DetachedMount::from_inherited(
            descriptors
                .pop()
                .ok_or_else(|| HostError::State("root export FD absent".to_owned()))?,
        )
        .map_err(export_error)?;
        let stat = rustix::fs::fstat(mount.as_fd()).map_err(export_error)?;
        if stat.st_dev != response.root_device
            || stat.st_ino != response.root_inode
            || mount.mount_id().get() != response.detached_mount_id
            || boottime()? >= deadline
            || self
                .storage_cgroup
                .verify_exact_membership(subject.pidfd())
                .map_err(export_error)?
                != info
            || !subject.is_alive().map_err(export_error)?
        {
            return Err(HostError::State(
                "root export mount identity changed".to_owned(),
            ));
        }
        verify_copied_guest_executable_labels_fd_v1(mount.as_fd()).map_err(|error| {
            HostError::State(format!("root export payload labels invalid: {error}"))
        })?;
        Ok(mount)
    }
}

fn send_request(socket: &mut DescriptorSubjectSocket, bytes: &[u8], deadline: u64) -> Result<()> {
    loop {
        if boottime()? >= deadline {
            return Err(HostError::State("root export deadline elapsed".to_owned()));
        }
        match socket.send(bytes) {
            Ok(()) => return Ok(()),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_until(socket, PollFlags::OUT, deadline)?;
            }
            Err(error) => return Err(export_error(error)),
        }
    }
}

fn receive_reply(
    socket: &mut DescriptorSubjectSocket,
    deadline: u64,
) -> Result<aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord> {
    loop {
        if boottime()? >= deadline {
            return Err(HostError::State("root export deadline elapsed".to_owned()));
        }
        match socket.receive(STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1, 1) {
            Ok(record) => return Ok(record),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_until(socket, PollFlags::IN, deadline)?;
            }
            Err(error) => return Err(export_error(error)),
        }
    }
}

fn wait_until(socket: &DescriptorSubjectSocket, events: PollFlags, deadline: u64) -> Result<()> {
    let remaining = deadline
        .checked_sub(boottime()?)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| HostError::State("root export deadline elapsed".to_owned()))?;
    let timeout =
        Timespec::try_from(std::time::Duration::from_nanos(remaining)).map_err(export_error)?;
    let fd = socket.as_fd().map_err(export_error)?;
    let mut ready = [PollFd::from_borrowed_fd(fd, events)];
    match poll(&mut ready, Some(&timeout)) {
        Ok(0) => Err(HostError::State("root export deadline elapsed".to_owned())),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(export_error(error)),
    }
}

fn boottime() -> Result<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(export_error)?;
    let nanos = u64::try_from(now.tv_nsec).map_err(export_error)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| HostError::State("root export clock overflow".to_owned()))
}

fn export_error(error: impl std::fmt::Display) -> HostError {
    HostError::State(format!("root export failed: {error}"))
}
