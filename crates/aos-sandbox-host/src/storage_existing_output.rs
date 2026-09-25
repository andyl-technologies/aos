//! Host client for one authenticated Storage AOSEOR03 logical readback.
//!
//! A successful response is a current Storage-local observation only. It
//! cannot authorize Create, Observe, or a Host effect without the ordered
//! all-owner barrier.

use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::Path;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::storage_existing_output::{
    ExistingOutputRequestV1, ExistingOutputResponseV1, RESPONSE_BYTES,
};
use rand::{TryRngCore as _, rngs::OsRng};

use crate::storage_root_export::{boottime, receive_reply, send_request};
use crate::{HostError, Result};

const QUERY_SOCKET: &str = "/run/aos/sandbox-storage/existing-output.sock";
const STORAGE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const QUERY_DEADLINE_NANOSECONDS: u64 = 10_000_000_000;

/// Retains the exact Storage service cgroup for output query replies.
#[derive(Debug)]
pub struct StorageExistingOutputClientV1 {
    storage_cgroup: RetainedCgroupAnchor,
    manager_cgroup: RetainedCgroupAnchor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketRouteIdentity {
    device: u64,
    inode: u64,
}

impl StorageExistingOutputClientV1 {
    /// Opens the fixed Storage service cgroup beneath a retained cgroup-v2 root.
    ///
    /// # Errors
    ///
    /// Rejects an absent, inactive, or unsafe Storage service cgroup.
    pub fn new(cgroup_root: CgroupV2Root) -> Result<Self> {
        let storage_cgroup = cgroup_root
            .resolve(Path::new(STORAGE_CGROUP))
            .map_err(query_error)?;
        let manager_cgroup = cgroup_root
            .resolve(Path::new(SYSTEMD_MANAGER_CGROUP))
            .map_err(query_error)?;
        storage_cgroup.validate_current().map_err(query_error)?;
        manager_cgroup.validate_current().map_err(query_error)?;
        Ok(Self {
            storage_cgroup,
            manager_cgroup,
        })
    }

    /// Queries the exact retained AOSEOR03 row known to Host.
    ///
    /// The returned sequence identifies only Storage's local journal head.
    /// The caller must retain and compare the independently authenticated
    /// accepted-Create, environment, Host, and physical Storage observations
    /// before using this readback at a future effect barrier.
    ///
    /// # Errors
    ///
    /// Rejects an absent row, missing endpoint, wrong responder, malformed or
    /// swapped reply, changed cgroup, or expired deadline.
    pub fn query(
        &self,
        execution: [u8; 16],
        create: [u8; 16],
        record_digest: [u8; 32],
    ) -> Result<ExistingOutputResponseV1> {
        self.storage_cgroup
            .validate_current()
            .map_err(query_error)?;
        let route = validate_socket_route()?;
        let mut socket =
            DescriptorSubjectSocket::connect(Path::new(QUERY_SOCKET)).map_err(query_error)?;
        let manager = self.verify_activation_peer(&socket)?;
        if validate_socket_route()? != route {
            return Err(query_error("socket route changed"));
        }
        let mut nonce = [0; 32];
        OsRng.try_fill_bytes(&mut nonce).map_err(query_error)?;
        let deadline = boottime()?
            .checked_add(QUERY_DEADLINE_NANOSECONDS)
            .ok_or_else(|| query_error("deadline overflow"))?;
        let request = ExistingOutputRequestV1 {
            nonce,
            deadline_boottime_nanoseconds: deadline,
            execution,
            create,
            record_digest,
        };
        if self.verify_activation_peer(&socket)? != manager || validate_socket_route()? != route {
            return Err(query_error("socket activation peer changed"));
        }
        send_request(
            &mut socket,
            &request.encode().map_err(query_error)?,
            deadline,
        )?;

        let packet = receive_reply(&mut socket, deadline, RESPONSE_BYTES, 0)?;
        let record = socket.bind_received(packet).map_err(query_error)?;
        let credentials = record.subject().credentials();
        if credentials.uid() != 0 || credentials.gid() != 0 || !record.descriptors().is_empty() {
            return Err(query_error("responder identity is invalid"));
        }
        let info = self
            .storage_cgroup
            .verify_exact_membership(record.subject().pidfd())
            .map_err(query_error)?;
        if info.pid() != credentials.pid().get()
            || info.thread_group_id() != info.pid()
            || !record.subject().is_alive().map_err(query_error)?
        {
            return Err(query_error("responder execution is invalid"));
        }
        let response = ExistingOutputResponseV1::decode(record.payload()).map_err(query_error)?;
        response.verify_request(request).map_err(query_error)?;
        if boottime()? >= deadline
            || self.verify_activation_peer(&socket)? != manager
            || validate_socket_route()? != route
            || self
                .storage_cgroup
                .verify_exact_membership(record.subject().pidfd())
                .map_err(query_error)?
                != info
            || !record.subject().is_alive().map_err(query_error)?
        {
            return Err(query_error("responder changed or deadline elapsed"));
        }
        Ok(response)
    }

    fn verify_activation_peer(&self, socket: &DescriptorSubjectSocket) -> Result<PidFdInfo> {
        // A systemd-owned listening socket reports PID 1 as the connection
        // peer. The response record independently names the Storage worker.
        let peer = socket.peer();
        let credentials = peer.credentials();
        if credentials.uid() != 0 || credentials.gid() != 0 || credentials.pid().get() != 1 {
            return Err(query_error("socket activation peer is invalid"));
        }
        let info = self
            .manager_cgroup
            .verify_exact_membership(peer.pidfd())
            .map_err(query_error)?;
        if info.pid() != 1
            || info.thread_group_id() != 1
            || !peer.is_alive().map_err(query_error)?
        {
            return Err(query_error("socket activation manager is invalid"));
        }
        Ok(info)
    }
}

fn validate_socket_route() -> Result<SocketRouteIdentity> {
    for directory in ["/run", "/run/aos", "/run/aos/sandbox-storage"] {
        let metadata = fs::symlink_metadata(directory).map_err(query_error)?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(query_error("socket route directory is unsafe"));
        }
    }
    let metadata = fs::symlink_metadata(QUERY_SOCKET).map_err(query_error)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(query_error("socket route endpoint is unsafe"));
    }
    Ok(SocketRouteIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn query_error(error: impl std::fmt::Display) -> HostError {
    HostError::State(format!("existing-output query failed: {error}"))
}
