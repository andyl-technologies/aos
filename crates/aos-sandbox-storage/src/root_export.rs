//! Host-only, one-request export of a freshly observed detached guest-root mount.
//!
//! The listener is distinct from controller RPC. Its caller must be the live
//! root-account Host service in the retained service cgroup. The canonical
//! AOSRME01 proof is only a selector; Storage independently derives its current
//! physical inventory before and after cloning the mount.

use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use aos_sandbox_protocol::storage_root_export::{
    STORAGE_ROOT_EXPORT_REQUEST_BYTES_V1, StorageRootExportRequestV1, StorageRootExportResponseV1,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use crate::guest_root_inventory::ProtectedGuestRootTemplateV1;
use crate::peer::HostRootExportPeerVerifier;
use crate::runtime::{StorageBrokerRuntime, StorageRuntimeError};
use crate::service::StorageServiceError;
use crate::transport::boottime;

const REQUEST_RECEIVE_NANOSECONDS: u64 = 5_000_000_000;
const MAXIMUM_EXPORT_NANOSECONDS: u64 = 130_000_000_000;

/// Classifies one Host root-export connection without disclosing inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootExportOutcome {
    /// Storage transferred one exact detached mount descriptor.
    Exported,
    /// Peer identity, request, inventory, or transfer failed closed.
    Rejected,
}

/// Serves one ready Host connection using the same protected Storage runtime.
///
/// # Errors
///
/// Returns an error for a changed listener, retired Host cgroup, invalid local
/// clock, or Storage runtime state requiring process reopen. Ordinary request
/// and export failures close the connection without an authority-bearing reply.
pub fn serve_root_export_once(
    listener: &mut RecordSubjectListener,
    runtime: &mut StorageBrokerRuntime,
    verifier: &HostRootExportPeerVerifier,
    template: &ProtectedGuestRootTemplateV1,
) -> Result<RootExportOutcome, StorageServiceError> {
    if runtime.requires_reopen() {
        return Err(StorageRuntimeError::ReopenRequired.into());
    }
    verifier.validate_current()?;
    listener.validate_current()?;
    let mut connection = match listener.accept_descriptor_subject() {
        Ok(connection) => connection,
        Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
            return Ok(RootExportOutcome::Rejected);
        }
        // An old queued child can lack inherited identity options. Reject it
        // without bringing down the broker's protected runtime.
        Err(_) => return Ok(RootExportOutcome::Rejected),
    };
    let execution = match verifier.verify_connection(connection.peer()) {
        Ok(execution) => execution,
        Err(()) => return Ok(RootExportOutcome::Rejected),
    };

    let receive_deadline = boottime()?
        .checked_add(REQUEST_RECEIVE_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    let record = match receive_request(&mut connection, receive_deadline) {
        Ok(record) => record,
        Err(()) => return Ok(RootExportOutcome::Rejected),
    };
    let record = match connection.bind_received(record) {
        Ok(record) => record,
        Err(_) => return Ok(RootExportOutcome::Rejected),
    };
    if verifier
        .verify_record(execution, record.peer(), record.subject())
        .is_err()
        || !record.descriptors().is_empty()
    {
        return Ok(RootExportOutcome::Rejected);
    }
    let request = match StorageRootExportRequestV1::decode(record.payload()) {
        Ok(request) => request,
        Err(_) => return Ok(RootExportOutcome::Rejected),
    };
    drop(record);

    let now = boottime()?;
    let latest = now
        .checked_add(MAXIMUM_EXPORT_NANOSECONDS)
        .ok_or(StorageServiceError::Clock)?;
    if request.deadline_boottime_nanoseconds <= now
        || request.deadline_boottime_nanoseconds > latest
        || verifier.verify_connection(connection.peer()) != Ok(execution)
    {
        return Ok(RootExportOutcome::Rejected);
    }

    let mount = match runtime.export_guest_root_mount(
        request.proof,
        template,
        request.deadline_boottime_nanoseconds,
    ) {
        Ok(mount) => mount,
        Err(StorageRuntimeError::ReopenRequired) => {
            return Err(StorageRuntimeError::ReopenRequired.into());
        }
        Err(_) => return Ok(RootExportOutcome::Rejected),
    };
    let identity = match (
        rustix::fs::fstat(mount.as_fd()),
        MountId::from_fd(mount.as_fd()),
    ) {
        (Ok(stat), Ok(mount_id)) if stat.st_dev != 0 && stat.st_ino != 0 => {
            (stat.st_dev, stat.st_ino, mount_id.get())
        }
        _ => return Ok(RootExportOutcome::Rejected),
    };
    let response = StorageRootExportResponseV1 {
        nonce: request.nonce,
        request_digest: request.digest().map_err(|_| {
            StorageServiceError::Activation("canonical root export request was invalid".to_owned())
        })?,
        root_device: identity.0,
        root_inode: identity.1,
        detached_mount_id: identity.2,
    };
    let bytes = response.encode().map_err(|_| {
        StorageServiceError::Activation("root export response was invalid".to_owned())
    })?;
    if boottime()? >= request.deadline_boottime_nanoseconds
        || verifier.verify_connection(connection.peer()) != Ok(execution)
        || connection
            .send_with_descriptors(&bytes, &[mount.as_fd()])
            .is_err()
    {
        return Ok(RootExportOutcome::Rejected);
    }
    Ok(RootExportOutcome::Exported)
}

fn receive_request(
    socket: &mut DescriptorSubjectSocket,
    deadline: u64,
) -> Result<aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord, ()> {
    loop {
        if boottime().map_err(|_| ())? >= deadline {
            return Err(());
        }
        match socket.receive(STORAGE_ROOT_EXPORT_REQUEST_BYTES_V1, 0) {
            Ok(record) => return Ok(record),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                let remaining = deadline
                    .checked_sub(boottime().map_err(|_| ())?)
                    .ok_or(())?;
                let timeout = Timespec::try_from(std::time::Duration::from_nanos(remaining))
                    .map_err(|_| ())?;
                let fd = socket.as_fd().map_err(|_| ())?;
                let mut ready = [PollFd::from_borrowed_fd(fd, PollFlags::IN)];
                match poll(&mut ready, Some(&timeout)) {
                    Ok(0) => return Err(()),
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(_) => return Err(()),
                }
            }
            Err(_) => return Err(()),
        }
    }
}
