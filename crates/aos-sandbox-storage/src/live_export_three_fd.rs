//! Closed Storage custody for the version 3 kernel-export owner exchange.
//!
//! ```text
//! AOSKGQ03[856] = header[16] | AOSKGH01[344] | AOSSLE01[496]
//! SCM_RIGHTS = [detached clone O_PATH, independently opened origin O_PATH,
//!               exact consumer cgroup-v2 O_PATH]
//! AOSKGC03[168] = closed, unsigned physical readback
//! ```
//!
//! This is a nonauthorizing precursor. No production service constructs it:
//! Storage still lacks a held Provider selected-row/current-attempt proof and
//! durable recovery for a possibly delivered FD. The opt-in owner does not
//! send AOSKGC03. A successful readback here cannot mean PREPARED or ACTIVE.

use std::os::fd::{AsFd as _, OwnedFd};
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::storage_live_export_lease::SignedStorageLiveExportLeaseV1;
use sha2::{Digest as _, Sha256};

use crate::live_export_clone::{
    StorageLiveExportCloneErrorV1, StorageLiveExportCloneLedgerV1, StorageLiveExportCloneV1,
};
use crate::live_export_grant_handoff::{
    ProtectedConsumerCgroupV1, StorageDenyStageFrameV1, StorageGrantHandoffErrorV1,
};
use crate::live_export_key::{StorageLiveExportKeyErrorV1, StorageLiveExportKeyV1};
use crate::live_export_request_readback::{
    StorageLiveExportReadbackErrorV1, StorageLiveExportReadbackV1,
};
use crate::runtime::StorageBrokerRuntime;

const REQUEST_BYTES: usize = 856;
const ACK_BYTES: usize = 168;
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.kernel-export.closed-three-fd-request.v3\0";

/// Reports a rejected or uncertain closed owner exchange.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageClosedThreeFdErrorV3 {
    /// The signed lease or acknowledgment differs from held Storage evidence.
    #[error("closed three-FD exchange is noncanonical")]
    Noncanonical,
    /// Protected Storage signing-key custody changed.
    #[error("closed three-FD key custody failed: {0}")]
    Key(#[from] StorageLiveExportKeyErrorV1),
    /// The detached clone or its active journal row changed.
    #[error("closed three-FD clone changed: {0}")]
    Clone(#[from] StorageLiveExportCloneErrorV1),
    /// The signed plan, Storage publication, or mutable origin changed.
    #[error("closed three-FD origin changed: {0}")]
    Origin(#[from] StorageLiveExportReadbackErrorV1),
    /// The named consumer or its Host cgroup changed.
    #[error("closed three-FD consumer changed: {0}")]
    Consumer(#[from] StorageGrantHandoffErrorV1),
    /// The owner process or exact descriptor transport is uncertain.
    #[error("closed three-FD transport is uncertain")]
    Transport,
}

/// Retains the three role owners and protected currentness inputs through ACK.
///
/// This value cannot release a clone FD or produce a kernel grant. Its private
/// constructor is deliberately disconnected from Storage's production service.
pub(crate) struct StorageClosedThreeFdSenderV3<'a> {
    request: [u8; REQUEST_BYTES],
    origin: OwnedFd,
    clone: &'a mut StorageLiveExportCloneV1,
    ledger: &'a mut StorageLiveExportCloneLedgerV1,
    readback: &'a StorageLiveExportReadbackV1,
    consumer: &'a ProtectedConsumerCgroupV1,
    lease: SignedStorageLiveExportLeaseV1,
    key: &'a StorageLiveExportKeyV1,
    runtime: &'a mut StorageBrokerRuntime,
    deadline_boottime_nanoseconds: u64,
    sent: bool,
}

/// Returns only the exact unsigned owner observation after Storage rechecks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageClosedThreeFdReadbackV3 {
    bytes: [u8; ACK_BYTES],
}

impl StorageClosedThreeFdReadbackV3 {
    /// Returns the nonauthorizing owner observation bytes.
    pub(crate) const fn as_bytes(&self) -> &[u8; ACK_BYTES] {
        &self.bytes
    }
}

impl<'a> StorageClosedThreeFdSenderV3<'a> {
    /// Prepares the exact request while retaining independent origin custody.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or stale lease, changed protected key or catalog,
    /// changed clone journal, changed physical origin, or expired Host cgroup.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        clone: &'a mut StorageLiveExportCloneV1,
        ledger: &'a mut StorageLiveExportCloneLedgerV1,
        readback: &'a StorageLiveExportReadbackV1,
        consumer: &'a ProtectedConsumerCgroupV1,
        lease: SignedStorageLiveExportLeaseV1,
        key: &'a StorageLiveExportKeyV1,
        runtime: &'a mut StorageBrokerRuntime,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, StorageClosedThreeFdErrorV3> {
        let frame = StorageDenyStageFrameV1::prepare(clone, ledger, readback, consumer)?;
        verify_lease(lease, readback, frame.as_bytes(), key)?;
        let origin = readback.reopen_current_origin(runtime, deadline_boottime_nanoseconds)?;
        let request = encode_request(frame.as_bytes(), &lease.encode());

        let mut sender = Self {
            request,
            origin,
            clone,
            ledger,
            readback,
            consumer,
            lease,
            key,
            runtime,
            deadline_boottime_nanoseconds,
            sent: false,
        };
        sender.recheck()?;
        Ok(sender)
    }

    /// Sends one exact three-role SCM_RIGHTS packet and closes on uncertainty.
    ///
    /// # Errors
    ///
    /// Rejects stale protected state, a repeated send, or any transport error.
    /// A failed send is ambiguous and cannot be retried on this object.
    pub(crate) fn send(
        &mut self,
        socket: &mut DescriptorSubjectSocket,
    ) -> Result<(), StorageClosedThreeFdErrorV3> {
        if self.sent {
            return Err(StorageClosedThreeFdErrorV3::Transport);
        }
        self.recheck()?;
        self.sent = true;
        let consumer = self.consumer.cgroup_fd(self.readback)?;
        let clone = self.clone.export_fd(self.ledger)?;
        let result =
            socket.send_kernel_export_three(&self.request, [clone, self.origin.as_fd(), consumer]);
        if result.is_err() {
            socket.close();
            return Err(StorageClosedThreeFdErrorV3::Transport);
        }
        Ok(())
    }

    /// Accepts only a matching closed ACK from the pinned owner process.
    ///
    /// # Errors
    ///
    /// Rejects missing or extra FDs, a different owner subject, any ACK drift,
    /// or changed Storage/Host currentness. Every failure closes the socket.
    pub(crate) fn receive_ack(
        &mut self,
        socket: &mut DescriptorSubjectSocket,
        owner_cgroup: &RetainedCgroupAnchor,
    ) -> Result<StorageClosedThreeFdReadbackV3, StorageClosedThreeFdErrorV3> {
        let result = self.receive_ack_inner(socket, owner_cgroup);
        socket.close();
        result
    }

    fn receive_ack_inner(
        &mut self,
        socket: &mut DescriptorSubjectSocket,
        owner_cgroup: &RetainedCgroupAnchor,
    ) -> Result<StorageClosedThreeFdReadbackV3, StorageClosedThreeFdErrorV3> {
        if !self.sent {
            return Err(StorageClosedThreeFdErrorV3::Transport);
        }
        let record = socket
            .receive(ACK_BYTES, 0)
            .map_err(|_| StorageClosedThreeFdErrorV3::Transport)?;
        let record = socket
            .bind_received(record)
            .map_err(|_| StorageClosedThreeFdErrorV3::Transport)?;
        let subject = record.subject();
        // Socket activation may make PID 1 the connection peer. The kernel
        // record subject, held in the protected owner cgroup, identifies the
        // actual ACK writer on this bound socket.
        let credentials = subject.credentials();
        let before = owner_cgroup
            .verify_exact_membership(subject.pidfd())
            .map_err(|_| StorageClosedThreeFdErrorV3::Transport)?;
        if credentials.uid() != 0
            || credentials.gid() != 0
            || before.pid() != credentials.pid().get()
            || before.thread_group_id() != before.pid()
            || !subject
                .is_alive()
                .map_err(|_| StorageClosedThreeFdErrorV3::Transport)?
        {
            return Err(StorageClosedThreeFdErrorV3::Transport);
        }
        let ack = verify_ack(record.payload(), &self.request, &self.lease)?;
        if owner_cgroup
            .verify_exact_membership(subject.pidfd())
            .map_err(|_| StorageClosedThreeFdErrorV3::Transport)?
            != before
        {
            return Err(StorageClosedThreeFdErrorV3::Transport);
        }
        self.recheck()?;
        Ok(ack)
    }

    fn recheck(&mut self) -> Result<(), StorageClosedThreeFdErrorV3> {
        let current = StorageDenyStageFrameV1::prepare(
            self.clone,
            self.ledger,
            self.readback,
            self.consumer,
        )?;
        if self.request[16..360] != current.as_bytes()[..] {
            return Err(StorageClosedThreeFdErrorV3::Noncanonical);
        }
        verify_lease(self.lease, self.readback, current.as_bytes(), self.key)?;
        let fresh = self
            .readback
            .reopen_current_origin(self.runtime, self.deadline_boottime_nanoseconds)?;
        // The original independent origin FD remains owned through the ACK;
        // a fresh inventory/open proves that its path still selects this root.
        let old = rustix::fs::fstat(&self.origin)
            .map_err(|_| StorageClosedThreeFdErrorV3::Noncanonical)?;
        let new =
            rustix::fs::fstat(&fresh).map_err(|_| StorageClosedThreeFdErrorV3::Noncanonical)?;
        let old_mount = MountId::from_fd(self.origin.as_fd())
            .map_err(|_| StorageClosedThreeFdErrorV3::Noncanonical)?;
        let new_mount = MountId::from_fd(fresh.as_fd())
            .map_err(|_| StorageClosedThreeFdErrorV3::Noncanonical)?;
        if (old.st_dev, old.st_ino, old_mount) != (new.st_dev, new.st_ino, new_mount) {
            return Err(StorageClosedThreeFdErrorV3::Noncanonical);
        }
        Ok(())
    }
}

fn verify_lease(
    lease: SignedStorageLiveExportLeaseV1,
    readback: &StorageLiveExportReadbackV1,
    frame: &[u8; 344],
    key: &StorageLiveExportKeyV1,
) -> Result<(), StorageClosedThreeFdErrorV3> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageClosedThreeFdErrorV3::Noncanonical)?;
    let now =
        i64::try_from(now.as_secs()).map_err(|_| StorageClosedThreeFdErrorV3::Noncanonical)?;
    key.verify_current_lease(lease, now)?;
    let consumer = lease.lease().consumer();
    if lease.lease().source() != readback.source()
        || consumer.effect_id() != readback.replay_identity().2
        || consumer.valid_until_seconds() > readback.expires_seconds()
        || consumer.valid_until_seconds()
            > i64::from_be_bytes(
                frame[336..344]
                    .try_into()
                    .map_err(|_| StorageClosedThreeFdErrorV3::Noncanonical)?,
            )
    {
        return Err(StorageClosedThreeFdErrorV3::Noncanonical);
    }
    Ok(())
}

fn encode_request(frame: &[u8; 344], lease: &[u8; 496]) -> [u8; REQUEST_BYTES] {
    let mut bytes = [0; REQUEST_BYTES];
    bytes[..8].copy_from_slice(b"AOSKGQ03");
    bytes[8..10].copy_from_slice(&3_u16.to_be_bytes());
    bytes[10] = 1;
    bytes[11] = 3;
    bytes[12..15].copy_from_slice(&[1, 2, 3]);
    bytes[16..360].copy_from_slice(frame);
    bytes[360..].copy_from_slice(lease);
    bytes
}

fn verify_ack(
    bytes: &[u8],
    request: &[u8; REQUEST_BYTES],
    lease: &SignedStorageLiveExportLeaseV1,
) -> Result<StorageClosedThreeFdReadbackV3, StorageClosedThreeFdErrorV3> {
    let ack: [u8; ACK_BYTES] = bytes
        .try_into()
        .map_err(|_| StorageClosedThreeFdErrorV3::Noncanonical)?;
    let request_digest: [u8; 32] = Sha256::new()
        .chain_update(REQUEST_DOMAIN)
        .chain_update(request)
        .finalize()
        .into();
    if &ack[..8] != b"AOSKGC03"
        || ack[8..10] != 3_u16.to_be_bytes()
        || ack[10] != 1
        || ack[11..16] != [0; 5]
        || ack[16..48] != request_digest
        || ack[48..80] != request[32..64]
        || ack[80..112] != *lease.digest().as_bytes()
        || ack[112..128] != request[240..256]
        || ack[128..136] != lease.lease().source().origin_mount_id().to_be_bytes()
        || ack[136..144] != request[256..264]
        || ack[144..152] != request[264..272]
        || ack[152..160] != request[272..280]
        || ack[160..168] != request[336..344]
    {
        return Err(StorageClosedThreeFdErrorV3::Noncanonical);
    }
    Ok(StorageClosedThreeFdReadbackV3 { bytes: ack })
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_source_provider_protocol::storage_live_export_lease::{
        StorageLiveExportConsumerV1, StorageLiveExportLeaseV1, StorageLiveExportSignerV1,
        StorageLiveExportSourceV1,
    };

    use super::*;

    fn packet() -> ([u8; REQUEST_BYTES], SignedStorageLiveExportLeaseV1) {
        let source = StorageLiveExportSourceV1::new(
            ObjectDigest::from_bytes([1; 32]),
            [2; 16],
            [3; 16],
            [4; 16],
            5,
            ObjectDigest::from_bytes([6; 32]),
            [7; 32],
            ObjectDigest::from_bytes([8; 32]),
            [9; 16],
            10,
            11,
            12,
        )
        .unwrap();
        let consumer = StorageLiveExportConsumerV1::new(
            ObjectDigest::from_bytes([13; 32]),
            [14; 16],
            [15; 16],
            16,
            [17; 16],
            18,
            100,
            200,
        )
        .unwrap();
        let signer = StorageLiveExportSignerV1::new(
            [19; 16],
            20,
            ObjectDigest::from_bytes([21; 32]),
            [22; 16],
            23,
        )
        .unwrap();
        let lease = SignedStorageLiveExportLeaseV1::new(
            StorageLiveExportLeaseV1::new(source, consumer),
            signer,
            [24; 64],
        );
        let mut frame = [0; 344];
        frame[..8].copy_from_slice(b"AOSKGH01");
        frame[8..10].copy_from_slice(&1_u16.to_be_bytes());
        frame[10] = 1;
        frame[16..48].fill(25);
        frame[224..240].copy_from_slice(&[9; 16]);
        frame[240..248].copy_from_slice(&26_u64.to_be_bytes());
        frame[248..256].copy_from_slice(&10_u64.to_be_bytes());
        frame[256..264].copy_from_slice(&11_u64.to_be_bytes());
        frame[320..328].copy_from_slice(&27_u64.to_be_bytes());
        (encode_request(&frame, &lease.encode()), lease)
    }

    fn acknowledgment(
        request: &[u8; REQUEST_BYTES],
        lease: SignedStorageLiveExportLeaseV1,
    ) -> [u8; ACK_BYTES] {
        let mut bytes = [0; ACK_BYTES];
        bytes[..8].copy_from_slice(b"AOSKGC03");
        bytes[8..10].copy_from_slice(&3_u16.to_be_bytes());
        bytes[10] = 1;
        let digest: [u8; 32] = Sha256::new()
            .chain_update(REQUEST_DOMAIN)
            .chain_update(request)
            .finalize()
            .into();
        bytes[16..48].copy_from_slice(&digest);
        bytes[48..80].copy_from_slice(&request[32..64]);
        bytes[80..112].copy_from_slice(lease.digest().as_bytes());
        bytes[112..128].copy_from_slice(&request[240..256]);
        bytes[128..136].copy_from_slice(&lease.lease().source().origin_mount_id().to_be_bytes());
        bytes[136..144].copy_from_slice(&request[256..264]);
        bytes[144..152].copy_from_slice(&request[264..272]);
        bytes[152..160].copy_from_slice(&request[272..280]);
        bytes[160..168].copy_from_slice(&request[336..344]);
        bytes
    }

    #[test]
    fn closed_ack_binds_exact_request_lease_and_physical_roles() {
        let (request, lease) = packet();
        let bytes = acknowledgment(&request, lease);
        let readback = verify_ack(&bytes, &request, &lease).unwrap();
        assert_eq!(readback.as_bytes(), &bytes);
        assert_eq!(&request[..8], b"AOSKGQ03");
        assert_eq!(&request[12..15], &[1, 2, 3]);
        assert_eq!(&request[360..], &lease.encode());
    }

    #[test]
    fn closed_ack_rejects_stale_head_boot_role_and_length_drift() {
        let (request, lease) = packet();
        let original = acknowledgment(&request, lease);
        for offset in [0, 8, 10, 11, 16, 48, 80, 112, 128, 136, 144, 152, 160] {
            let mut changed = original;
            changed[offset] ^= 1;
            assert!(
                verify_ack(&changed, &request, &lease).is_err(),
                "offset {offset}"
            );
        }
        assert!(verify_ack(&original[..ACK_BYTES - 1], &request, &lease).is_err());

        let mut stale_head = request;
        stale_head[200] ^= 1;
        assert!(verify_ack(&original, &stale_head, &lease).is_err());
        let mut stale_boot = request;
        stale_boot[240] ^= 1;
        assert!(verify_ack(&original, &stale_boot, &lease).is_err());
    }
}
