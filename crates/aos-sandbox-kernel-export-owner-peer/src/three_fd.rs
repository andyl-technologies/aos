//! Version 3 closed, three-descriptor Storage handoff observation.
//!
//! ```text
//! AOSKGQ03[856] = header[16] | AOSKGH01[344] | AOSSLE01[496]
//! header = magic[8] | version:u16be=3 | closed-check:u8=1 |
//!          descriptor-count:u8=3 | roles[3]=[clone=1, origin=2, cgroup=3] |
//!          reserved:u8=0
//! SCM_RIGHTS = [detached read-only clone O_PATH,
//!               independent mutable-origin directory O_PATH,
//!               exact consumer cgroup-v2 O_PATH]
//! AOSKGC03[168] = header[16] | request-digest[32] | handoff-id[32] |
//!                 signed-lease-digest[32] | current-boot[16] |
//!                 origin-mount[8] | clone-mount[8] | root-device[8] |
//!                 root-inode[8] | consumer-cgroup-id[8]
//! ```
//!
//! The reply is an unsigned, nonauthorizing observation. It is constructed
//! only after the same authenticated Storage subject and all three FD roles
//! have been checked. Neither this module nor the deployed two-FD daemon sends
//! a reply, stages a map, or releases an FD. A future Storage sender must hold
//! current assignment and clone custody across the exchange before any grant
//! transition can be considered.

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use sha2::{Digest as _, Sha256};

use crate::OwnerPeerError;
use crate::deployment::OwnerPublicVerifiers;
use crate::handoff::{DenyStageHandoff, HANDOFF_BYTES};
use crate::origin::{ClosedOriginReadback, verify_closed_mutable_origin_ref};
use crate::peer::{readback_clone, readback_consumer, verify_record, verify_storage_peer};
use crate::stage_ack::LEASE_BYTES;

/// Exact version 3 request size.
pub const REQUEST_BYTES: usize = 16 + HANDOFF_BYTES + LEASE_BYTES;
/// Exact version 3 closed acknowledgment size.
pub const CLOSED_ACK_BYTES: usize = 168;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.kernel-export.closed-three-fd-request.v3\0";

/// Owns canonical bytes for a closed three-FD request, without any FDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedThreeFdRequest {
    bytes: [u8; REQUEST_BYTES],
    handoff: DenyStageHandoff,
}

impl ClosedThreeFdRequest {
    /// Parses a distinct version 3 request containing the unchanged v1 frame.
    ///
    /// # Errors
    ///
    /// Rejects the wrong length, magic, version, phase, role order, reserved
    /// byte, or embedded deny-stage frame. The lease signature is checked only
    /// when the independent origin FD is physically read back.
    pub fn parse(input: &[u8]) -> Result<Self, OwnerPeerError> {
        let bytes: [u8; REQUEST_BYTES] =
            input.try_into().map_err(|_| OwnerPeerError::Noncanonical)?;
        if &bytes[..8] != b"AOSKGQ03"
            || bytes[8..10] != 3_u16.to_be_bytes()
            || bytes[10] != 1
            || bytes[11] != 3
            || bytes[12..15] != [1, 2, 3]
            || bytes[15] != 0
        {
            return Err(OwnerPeerError::Noncanonical);
        }
        let handoff = DenyStageHandoff::parse(&bytes[16..16 + HANDOFF_BYTES])?;
        Ok(Self { bytes, handoff })
    }

    /// Returns the canonical request bytes without assigning authority.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REQUEST_BYTES] {
        &self.bytes
    }

    /// Returns the unchanged Storage deny-stage frame.
    #[must_use]
    pub const fn handoff(&self) -> &DenyStageHandoff {
        &self.handoff
    }

    fn lease(&self) -> &[u8] {
        &self.bytes[16 + HANDOFF_BYTES..]
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(REQUEST_DIGEST_DOMAIN)
            .chain_update(self.bytes)
            .finalize()
            .into()
    }
}

/// Holds an unsigned, observation-only acknowledgment; it cannot grant access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedThreeFdAck {
    bytes: [u8; CLOSED_ACK_BYTES],
}

impl ClosedThreeFdAck {
    /// Returns the exact version 3 closed-check acknowledgment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CLOSED_ACK_BYTES] {
        &self.bytes
    }

    fn from_observation(request: &ClosedThreeFdRequest, origin: ClosedOriginReadback) -> Self {
        let mut bytes = [0_u8; CLOSED_ACK_BYTES];
        bytes[..8].copy_from_slice(b"AOSKGC03");
        bytes[8..10].copy_from_slice(&3_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(&request.digest());
        bytes[48..80].copy_from_slice(&origin.handoff_id());
        bytes[80..112].copy_from_slice(&origin.lease_digest());
        bytes[112..128].copy_from_slice(&request.handoff.boot_id());
        bytes[128..136].copy_from_slice(&origin.origin_mount_id().to_be_bytes());
        bytes[136..144].copy_from_slice(&origin.clone_mount_id().to_be_bytes());
        let (device, inode) = origin.root();
        bytes[144..152].copy_from_slice(&device.to_be_bytes());
        bytes[152..160].copy_from_slice(&inode.to_be_bytes());
        bytes[160..168].copy_from_slice(&request.handoff.cgroup_id().to_be_bytes());
        Self { bytes }
    }
}

/// Retains only scalar observations after all transferred FDs are closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedThreeFdReadback {
    ack: ClosedThreeFdAck,
    storage_process: PidFdInfo,
}

impl ClosedThreeFdReadback {
    /// Returns a closed-check acknowledgment with no stage or grant authority.
    #[must_use]
    pub const fn ack(&self) -> &ClosedThreeFdAck {
        &self.ack
    }

    /// Returns the live Storage process snapshot checked around the packet.
    #[must_use]
    pub const fn storage_process(&self) -> PidFdInfo {
        self.storage_process
    }
}

/// Receives and closes one exact version 3 three-FD request.
///
/// `storage_cgroup` and `verifiers` must be loaded from protected owner
/// deployment custody. This opt-in receiver is not called by the deployed
/// two-FD daemon. The unsigned result must not be treated as Storage-held
/// currentness, a PREPARED acknowledgment, or a grant capability.
///
/// # Errors
///
/// Rejects wrong Storage process identity; malformed, missing, extra, or
/// reordered FDs; invalid signed lease; stale boot; and any clone, origin, or
/// cgroup physical mismatch. Every received FD is closed on every return path.
pub fn receive_closed_three_fd(
    socket: &mut DescriptorSubjectSocket,
    storage_cgroup: &RetainedCgroupAnchor,
    verifiers: &OwnerPublicVerifiers,
) -> Result<ClosedThreeFdReadback, OwnerPeerError> {
    let before = verify_storage_peer(storage_cgroup, socket.peer())?;
    let record = socket
        .receive(REQUEST_BYTES, 3)
        .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
    let record = socket
        .bind_received(record)
        .map_err(|error| OwnerPeerError::Transport(error.to_string()))?;
    verify_record(storage_cgroup, before, record.peer(), record.subject())?;

    let request = ClosedThreeFdRequest::parse(record.payload())?;
    let ack = check_roles(&request, record.descriptors(), verifiers.lease())?;
    verify_record(storage_cgroup, before, record.peer(), record.subject())?;

    Ok(ClosedThreeFdReadback {
        ack,
        storage_process: before,
    })
}

fn check_roles(
    request: &ClosedThreeFdRequest,
    descriptors: &[std::os::fd::OwnedFd],
    lease_verifier: &[u8; crate::stage_ack::VERIFIER_BYTES],
) -> Result<ClosedThreeFdAck, OwnerPeerError> {
    check_roles_with(
        request,
        descriptors,
        lease_verifier,
        readback_clone,
        readback_consumer,
    )
}

fn check_roles_with(
    request: &ClosedThreeFdRequest,
    descriptors: &[std::os::fd::OwnedFd],
    lease_verifier: &[u8; crate::stage_ack::VERIFIER_BYTES],
    check_clone: impl Fn(&DenyStageHandoff, &std::os::fd::OwnedFd) -> Result<(), OwnerPeerError>,
    check_consumer: impl Fn(&DenyStageHandoff, &std::os::fd::OwnedFd) -> Result<(), OwnerPeerError>,
) -> Result<ClosedThreeFdAck, OwnerPeerError> {
    let [clone, origin, cgroup] = descriptors else {
        return Err(OwnerPeerError::Physical);
    };
    check_clone(request.handoff(), clone)?;
    let origin = verify_closed_mutable_origin_ref(
        origin,
        request.lease(),
        lease_verifier,
        request.handoff(),
    )?;
    check_consumer(request.handoff(), cgroup)?;
    Ok(ClosedThreeFdAck::from_observation(request, origin))
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
    use std::path::Path;

    use rustix::fs::{Mode, OFlags, open};

    use super::*;
    use crate::origin::tests::{fixture, handoff_id, open_origin, sign_lease};
    use crate::stage_ack::{StorageRoleVerifiers, verify_closed_prepared_ack};

    fn request_bytes() -> ([u8; REQUEST_BYTES], [u8; 112], ed25519_dalek::SigningKey) {
        let source = fixture();
        let mut bytes = [0_u8; REQUEST_BYTES];
        bytes[..8].copy_from_slice(b"AOSKGQ03");
        bytes[8..10].copy_from_slice(&3_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[11] = 3;
        bytes[12..15].copy_from_slice(&[1, 2, 3]);
        bytes[16..16 + HANDOFF_BYTES].copy_from_slice(&source.handoff);
        bytes[16 + HANDOFF_BYTES..].copy_from_slice(&source.lease);
        (bytes, source.verifier, source.key)
    }

    fn descriptors() -> Vec<OwnedFd> {
        let clone = open(
            Path::new("Cargo.toml"),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let cgroup = open(
            Path::new("Cargo.toml"),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        vec![clone, open_origin(), cgroup]
    }

    // These callbacks isolate wire role order and the real signed-origin
    // verifier; the production path uses the kernel clone/cgroup readbacks.
    fn check_with_role_probes(
        request: &ClosedThreeFdRequest,
        fds: &[OwnedFd],
        verifier: &[u8; 112],
        clone_fd: RawFd,
        cgroup_fd: RawFd,
    ) -> Result<ClosedThreeFdAck, OwnerPeerError> {
        check_roles_with(
            request,
            fds,
            verifier,
            |_, fd| {
                if fd.as_raw_fd() == clone_fd {
                    Ok(())
                } else {
                    Err(OwnerPeerError::Physical)
                }
            },
            |_, fd| {
                if fd.as_raw_fd() == cgroup_fd {
                    Ok(())
                } else {
                    Err(OwnerPeerError::Physical)
                }
            },
        )
    }

    #[test]
    fn version_and_exact_role_table_are_distinct_from_two_fd_wire() {
        let (bytes, _, _) = request_bytes();
        assert!(ClosedThreeFdRequest::parse(&bytes).is_ok());
        assert!(ClosedThreeFdRequest::parse(&bytes[..REQUEST_BYTES - 1]).is_err());

        for offset in [0, 8, 10, 11, 12, 13, 14, 15] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(ClosedThreeFdRequest::parse(&changed).is_err());
        }
        assert!(ClosedThreeFdRequest::parse(&bytes[16..16 + HANDOFF_BYTES]).is_err());
    }

    #[test]
    fn closed_ack_binds_signed_origin_and_exact_request() {
        let (bytes, verifier, _) = request_bytes();
        let request = ClosedThreeFdRequest::parse(&bytes).unwrap();
        let fds = descriptors();
        let ack = check_with_role_probes(
            &request,
            &fds,
            &verifier,
            fds[0].as_raw_fd(),
            fds[2].as_raw_fd(),
        )
        .unwrap();
        let ack = ack.as_bytes();
        assert_eq!(&ack[..8], b"AOSKGC03");
        assert_eq!(&ack[8..10], &3_u16.to_be_bytes());
        assert_eq!(ack[10], 1);
        assert_eq!(&ack[16..48], &request.digest());
        assert_eq!(&ack[48..80], &request.handoff().handoff_id());
        assert_ne!(&ack[80..112], &[0; 32]);
        assert_ne!(&ack[128..136], &ack[136..144]);

        let now = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        assert!(matches!(
            verify_closed_prepared_ack(
                ack,
                request.lease(),
                request.handoff(),
                StorageRoleVerifiers {
                    lease: &verifier,
                    stage: &verifier,
                },
                &[1; 32],
                1,
                now,
            ),
            Err(OwnerPeerError::Noncanonical)
        ));
    }

    #[test]
    fn wrong_lease_key_pin_cannot_produce_closed_ack() {
        let (bytes, mut verifier, _) = request_bytes();
        let request = ClosedThreeFdRequest::parse(&bytes).unwrap();
        let fds = descriptors();
        verifier[80] ^= 1;
        assert!(matches!(
            check_with_role_probes(
                &request,
                &fds,
                &verifier,
                fds[0].as_raw_fd(),
                fds[2].as_raw_fd(),
            ),
            Err(OwnerPeerError::Signature)
        ));
    }

    #[test]
    fn missing_extra_and_swapped_descriptors_fail_closed() {
        let (bytes, verifier, _) = request_bytes();
        let request = ClosedThreeFdRequest::parse(&bytes).unwrap();
        let mut fds = descriptors();
        let clone_fd = fds[0].as_raw_fd();
        let cgroup_fd = fds[2].as_raw_fd();

        assert!(
            check_with_role_probes(&request, &fds[..2], &verifier, clone_fd, cgroup_fd).is_err()
        );
        fds.push(open_origin());
        assert!(check_with_role_probes(&request, &fds, &verifier, clone_fd, cgroup_fd).is_err());
        fds.pop();

        for (left, right) in [(0, 1), (0, 2), (1, 2)] {
            fds.swap(left, right);
            assert!(matches!(
                check_with_role_probes(&request, &fds, &verifier, clone_fd, cgroup_fd),
                Err(OwnerPeerError::Physical)
            ));
            fds.swap(left, right);
        }
    }

    #[test]
    fn stale_boot_and_mismatched_origin_clone_fail_before_ack() {
        let (mut bytes, verifier, key) = request_bytes();
        let fds = descriptors();
        let clone_fd = fds[0].as_raw_fd();
        let cgroup_fd = fds[2].as_raw_fd();
        let lease_offset = 16 + HANDOFF_BYTES;
        bytes[lease_offset + 200] ^= 1;
        let lease: &mut [u8; LEASE_BYTES] = (&mut bytes[lease_offset..]).try_into().unwrap();
        sign_lease(lease, &key);
        let request = ClosedThreeFdRequest::parse(&bytes).unwrap();
        assert!(matches!(
            check_with_role_probes(&request, &fds, &verifier, clone_fd, cgroup_fd),
            Err(OwnerPeerError::Physical)
        ));

        let (mut bytes, verifier, _) = request_bytes();
        let mut handoff: [u8; HANDOFF_BYTES] = bytes[16..16 + HANDOFF_BYTES].try_into().unwrap();
        handoff[256] ^= 1;
        handoff_id(&mut handoff);
        bytes[16..16 + HANDOFF_BYTES].copy_from_slice(&handoff);
        let request = ClosedThreeFdRequest::parse(&bytes).unwrap();
        assert!(matches!(
            check_with_role_probes(&request, &fds, &verifier, clone_fd, cgroup_fd),
            Err(OwnerPeerError::Physical)
        ));

        let (mut bytes, verifier, _) = request_bytes();
        let origin_mount = bytes[lease_offset + 232..lease_offset + 240].to_vec();
        let mut handoff: [u8; HANDOFF_BYTES] = bytes[16..16 + HANDOFF_BYTES].try_into().unwrap();
        handoff[240..248].copy_from_slice(&origin_mount);
        handoff_id(&mut handoff);
        bytes[16..16 + HANDOFF_BYTES].copy_from_slice(&handoff);
        let request = ClosedThreeFdRequest::parse(&bytes).unwrap();
        assert!(matches!(
            check_with_role_probes(&request, &fds, &verifier, clone_fd, cgroup_fd),
            Err(OwnerPeerError::Physical)
        ));
    }

    #[test]
    fn role_readbacks_reject_wrong_types_and_flags() {
        let (bytes, verifier, _) = request_bytes();
        let request = ClosedThreeFdRequest::parse(&bytes).unwrap();
        let fds = descriptors();
        assert!(matches!(
            readback_clone(request.handoff(), &fds[0]),
            Err(OwnerPeerError::Physical)
        ));
        assert!(matches!(
            readback_consumer(request.handoff(), &fds[2]),
            Err(OwnerPeerError::Physical)
        ));

        let readable_origin = open(
            Path::new("."),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            verify_closed_mutable_origin_ref(
                &readable_origin,
                request.lease(),
                &verifier,
                request.handoff(),
            ),
            Err(OwnerPeerError::Physical)
        ));
    }
}
