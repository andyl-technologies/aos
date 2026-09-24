//! Independent physical readback of a mutable Storage export origin.
//!
//! ```text
//! AOSSLE01 (signed mutable-origin boot, device, inode, unique mount ID)
//!     + separately authenticated origin O_PATH FD
//!     + AOSKGH01 (separately remeasured detached-clone tuple)
//!     -> closed scalar observation, never a KernelExportGrant
//! ```
//!
//! The deployed AOSKGH01 carrier has exactly two FDs and cannot deliver an
//! origin FD. This check is therefore not called by ownerd. A future versioned
//! three-FD carrier must authenticate Storage's live subject and retain a held
//! Storage currentness barrier before passing its third FD here. The origin
//! mount may remain mutable after this observation; neither this result nor
//! the existing signed stage-ack authorizes Stage, ACTIVE, or FD release.

use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_source_provider_protocol::storage_live_export_lease::{
    SignedStorageLiveExportLeaseV1, StorageLiveExportLeaseErrorV1, StorageLiveExportSourceV1,
    StorageLiveExportVerifierV1,
};
use rustix::fs::{FileType, OFlags};

use crate::OwnerPeerError;
use crate::handoff::DenyStageHandoff;
use crate::stage_ack::{LEASE_BYTES, VERIFIER_BYTES};

/// Retains only the checked physical tuple and signed commitments, not an FD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedOriginReadback {
    origin_mount_id: u64,
    clone_mount_id: u64,
    root_device: u64,
    root_inode: u64,
    lease_digest: [u8; 32],
    handoff_id: [u8; 32],
}

impl ClosedOriginReadback {
    /// Returns the independently measured mutable-origin mount identity.
    #[must_use]
    pub const fn origin_mount_id(&self) -> u64 {
        self.origin_mount_id
    }

    /// Returns the distinct clone mount identity committed by AOSKGH01.
    #[must_use]
    pub const fn clone_mount_id(&self) -> u64 {
        self.clone_mount_id
    }

    /// Returns the root device and inode shared by origin and clone claims.
    #[must_use]
    pub const fn root(&self) -> (u64, u64) {
        (self.root_device, self.root_inode)
    }

    /// Returns the verified signed-lease commitment, not lease authority.
    #[must_use]
    pub const fn lease_digest(&self) -> [u8; 32] {
        self.lease_digest
    }

    /// Returns the unkeyed handoff commitment, not grant authority.
    #[must_use]
    pub const fn handoff_id(&self) -> [u8; 32] {
        self.handoff_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhysicalOrigin {
    boot_id: [u8; 16],
    mount_id: u64,
    device: u64,
    inode: u64,
}

impl PhysicalOrigin {
    fn from_fd(fd: &OwnedFd) -> Result<Self, OwnerPeerError> {
        let status = rustix::fs::fcntl_getfl(fd).map_err(|_| OwnerPeerError::Physical)?;
        let descriptor = rustix::io::fcntl_getfd(fd).map_err(|_| OwnerPeerError::Physical)?;
        let stat = rustix::fs::fstat(fd).map_err(|_| OwnerPeerError::Physical)?;
        if !status.contains(OFlags::PATH)
            || !descriptor.contains(rustix::io::FdFlags::CLOEXEC)
            || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        {
            return Err(OwnerPeerError::Physical);
        }

        let boot_id = KernelBootId::current()
            .map_err(|_| OwnerPeerError::Physical)?
            .into_bytes();
        let mount_id = MountId::from_fd(fd.as_fd())
            .map_err(|_| OwnerPeerError::Physical)?
            .get();
        if stat.st_dev == 0 || stat.st_ino == 0 {
            return Err(OwnerPeerError::Physical);
        }
        Ok(Self {
            boot_id,
            mount_id,
            device: stat.st_dev,
            inode: stat.st_ino,
        })
    }

    fn matches_signed_roles(
        self,
        source: StorageLiveExportSourceV1,
        handoff: &DenyStageHandoff,
    ) -> bool {
        self.boot_id == source.origin_boot_id()
            && self.boot_id == handoff.boot_id()
            && self.mount_id == source.origin_mount_id()
            && self.mount_id != handoff.clone_mount_id()
            && (self.device, self.inode) == (source.origin_device(), source.origin_inode())
            && (self.device, self.inode) == handoff.clone_root()
    }
}

/// Consumes one separately authenticated origin descriptor and returns no FD.
///
/// The caller must obtain `origin_fd` from a future authenticated Storage
/// subject in the same versioned transfer as a physically checked clone FD;
/// this function cannot authenticate descriptor provenance by itself. The
/// pinned lease verifier must come from protected deployment custody. The
/// present two-FD owner daemon has no route to call this function.
///
/// # Errors
///
/// Rejects malformed, unsigned, expired, or wrong-signer AOSSLE01 bytes;
/// wrong FD flags/type; a stale boot, mount, device, or inode; a clone/origin
/// role swap; or a handoff outside its exclusive expiry. The FD is closed on
/// success and failure, and no kernel map transition occurs.
pub fn verify_closed_mutable_origin(
    origin_fd: OwnedFd,
    lease_bytes: &[u8],
    lease_verifier: &[u8; VERIFIER_BYTES],
    handoff: &DenyStageHandoff,
) -> Result<ClosedOriginReadback, OwnerPeerError> {
    let lease: &[u8; LEASE_BYTES] = lease_bytes
        .try_into()
        .map_err(|_| OwnerPeerError::Noncanonical)?;
    let signed_lease =
        SignedStorageLiveExportLeaseV1::decode(lease).map_err(|_| OwnerPeerError::Noncanonical)?;
    let public_key: [u8; 32] = lease_verifier[80..]
        .try_into()
        .map_err(|_| OwnerPeerError::Noncanonical)?;
    let verifier = StorageLiveExportVerifierV1::new(signed_lease.signer(), public_key)
        .map_err(|_| OwnerPeerError::Signature)?;
    if lease[352..432] != lease_verifier[..80] {
        return Err(OwnerPeerError::Signature);
    }

    let now_seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if now_seconds <= 0 {
        return Err(OwnerPeerError::Physical);
    }
    verifier
        .verify(signed_lease, now_seconds)
        .map_err(|error| match error {
            StorageLiveExportLeaseErrorV1::NotCurrent => OwnerPeerError::NotCurrent,
            StorageLiveExportLeaseErrorV1::Signature => OwnerPeerError::Signature,
            StorageLiveExportLeaseErrorV1::Noncanonical => OwnerPeerError::Noncanonical,
        })?;
    if now_seconds >= handoff.exclusive_expiry_seconds() {
        return Err(OwnerPeerError::NotCurrent);
    }
    if lease[288..312] != handoff.as_bytes()[48..72] {
        return Err(OwnerPeerError::Noncanonical);
    }

    let observed = PhysicalOrigin::from_fd(&origin_fd)?;
    if !observed.matches_signed_roles(signed_lease.lease().source(), handoff) {
        return Err(OwnerPeerError::Physical);
    }
    Ok(ClosedOriginReadback {
        origin_mount_id: observed.mount_id,
        clone_mount_id: handoff.clone_mount_id(),
        root_device: observed.device,
        root_inode: observed.inode,
        lease_digest: *signed_lease.digest().as_bytes(),
        handoff_id: handoff.handoff_id(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ed25519_dalek::{Signer as _, SigningKey};
    use rustix::fs::{Mode, open};
    use sha2::{Digest as _, Sha256};

    use super::*;

    const HANDOFF_DOMAIN: &[u8] = b"aos.sandbox.storage.kernel-export-deny-handoff.v1\0";
    const LEASE_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-lease.signature.v1\0";

    struct Fixture {
        handoff: [u8; 344],
        lease: [u8; LEASE_BYTES],
        verifier: [u8; VERIFIER_BYTES],
        key: SigningKey,
        physical: PhysicalOrigin,
    }

    fn open_origin() -> OwnedFd {
        open(
            Path::new("."),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn handoff_id(frame: &mut [u8; 344]) {
        let digest: [u8; 32] = Sha256::new()
            .chain_update(HANDOFF_DOMAIN)
            .chain_update(&frame[48..])
            .finalize()
            .into();
        frame[16..48].copy_from_slice(&digest);
    }

    fn sign_lease(lease: &mut [u8; LEASE_BYTES], key: &SigningKey) {
        let mut message = LEASE_DOMAIN.to_vec();
        message.extend_from_slice(&lease[..432]);
        lease[432..].copy_from_slice(&key.sign(&message).to_bytes());
    }

    fn fixture() -> Fixture {
        let physical = PhysicalOrigin::from_fd(&open_origin()).unwrap();
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        let key = SigningKey::from_bytes(&[77; 32]);

        let mut handoff = [0_u8; 344];
        handoff[..8].copy_from_slice(b"AOSKGH01");
        handoff[8..10].copy_from_slice(&1_u16.to_be_bytes());
        handoff[10] = 1;
        for (start, end, value) in [
            (48, 64, 1),
            (72, 88, 2),
            (88, 120, 3),
            (120, 152, 4),
            (152, 184, 5),
            (192, 224, 6),
            (264, 280, 7),
            (288, 320, 8),
        ] {
            handoff[start..end].fill(value);
        }
        handoff[64..72].copy_from_slice(&1_u64.to_be_bytes());
        handoff[184..192].copy_from_slice(&1_u64.to_be_bytes());
        handoff[224..240].copy_from_slice(&physical.boot_id);
        handoff[240..248].copy_from_slice(&(physical.mount_id + 1).to_be_bytes());
        handoff[248..256].copy_from_slice(&physical.device.to_be_bytes());
        handoff[256..264].copy_from_slice(&physical.inode.to_be_bytes());
        handoff[280..288].copy_from_slice(&1_u64.to_be_bytes());
        handoff[320..328].copy_from_slice(&1_u64.to_be_bytes());
        handoff[336..344].copy_from_slice(&(now + 300).to_be_bytes());
        handoff_id(&mut handoff);

        let mut lease = [0_u8; LEASE_BYTES];
        lease[..8].copy_from_slice(b"AOSSLE01");
        lease[8..10].copy_from_slice(&1_u16.to_be_bytes());
        for (start, end, value) in [
            (16, 48, 1),
            (48, 64, 2),
            (64, 80, 3),
            (80, 96, 4),
            (104, 136, 5),
            (136, 168, 6),
            (168, 200, 7),
            (240, 272, 8),
            (272, 288, 9),
            (312, 328, 10),
            (352, 368, 11),
            (376, 408, 12),
            (408, 424, 13),
        ] {
            lease[start..end].fill(value);
        }
        lease[96..104].copy_from_slice(&1_u64.to_be_bytes());
        lease[200..216].copy_from_slice(&physical.boot_id);
        lease[216..224].copy_from_slice(&physical.device.to_be_bytes());
        lease[224..232].copy_from_slice(&physical.inode.to_be_bytes());
        lease[232..240].copy_from_slice(&physical.mount_id.to_be_bytes());
        lease[288..312].copy_from_slice(&handoff[48..72]);
        lease[328..336].copy_from_slice(&1_u64.to_be_bytes());
        lease[336..344].copy_from_slice(&(now - 10).to_be_bytes());
        lease[344..352].copy_from_slice(&(now + 300).to_be_bytes());
        lease[368..376].copy_from_slice(&1_u64.to_be_bytes());
        lease[424..432].copy_from_slice(&1_u64.to_be_bytes());
        sign_lease(&mut lease, &key);

        let mut verifier = [0_u8; VERIFIER_BYTES];
        verifier[..80].copy_from_slice(&lease[352..432]);
        verifier[80..].copy_from_slice(&key.verifying_key().to_bytes());
        Fixture {
            handoff,
            lease,
            verifier,
            key,
            physical,
        }
    }

    fn verify(
        fixture: &Fixture,
        origin_fd: OwnedFd,
    ) -> Result<ClosedOriginReadback, OwnerPeerError> {
        let handoff = DenyStageHandoff::parse(&fixture.handoff)?;
        verify_closed_mutable_origin(origin_fd, &fixture.lease, &fixture.verifier, &handoff)
    }

    #[test]
    fn signed_lease_and_real_origin_fd_yield_only_closed_identity() {
        let fixture = fixture();
        let readback = verify(&fixture, open_origin()).unwrap();
        assert_eq!(readback.origin_mount_id(), fixture.physical.mount_id);
        assert_eq!(readback.clone_mount_id(), fixture.physical.mount_id + 1);
        assert_eq!(
            readback.root(),
            (fixture.physical.device, fixture.physical.inode)
        );
        assert_ne!(readback.lease_digest(), [0; 32]);
        assert_ne!(readback.handoff_id(), [0; 32]);
    }

    #[test]
    fn wrong_mount_with_same_device_inode_and_swapped_roles_fail() {
        let mut fixture = self::fixture();
        fixture.lease[232..240].copy_from_slice(&(fixture.physical.mount_id + 2).to_be_bytes());
        sign_lease(&mut fixture.lease, &fixture.key);
        assert!(matches!(
            verify(&fixture, open_origin()),
            Err(OwnerPeerError::Physical)
        ));

        let mut fixture = self::fixture();
        fixture.lease[232..240].copy_from_slice(&(fixture.physical.mount_id + 1).to_be_bytes());
        sign_lease(&mut fixture.lease, &fixture.key);
        fixture.handoff[240..248].copy_from_slice(&fixture.physical.mount_id.to_be_bytes());
        handoff_id(&mut fixture.handoff);
        assert!(matches!(
            verify(&fixture, open_origin()),
            Err(OwnerPeerError::Physical)
        ));
    }

    #[test]
    fn stale_boot_and_wrong_descriptor_profile_fail() {
        let mut fixture = fixture();
        fixture.lease[200] ^= 1;
        sign_lease(&mut fixture.lease, &fixture.key);
        assert!(matches!(
            verify(&fixture, open_origin()),
            Err(OwnerPeerError::Physical)
        ));

        let fixture = self::fixture();
        let readable = open(
            Path::new("."),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            verify(&fixture, readable),
            Err(OwnerPeerError::Physical)
        ));
        let no_close_on_exec = open_origin();
        rustix::io::fcntl_setfd(&no_close_on_exec, rustix::io::FdFlags::empty()).unwrap();
        assert!(matches!(
            verify(&fixture, no_close_on_exec),
            Err(OwnerPeerError::Physical)
        ));
        let wrong_type = open(Path::new("Cargo.toml"), OFlags::PATH, Mode::empty()).unwrap();
        assert!(matches!(
            verify(&fixture, wrong_type),
            Err(OwnerPeerError::Physical)
        ));
    }

    #[test]
    fn wrong_signer_and_expired_handoff_fail_closed() {
        let mut fixture = self::fixture();
        fixture.verifier[80] ^= 1;
        assert!(matches!(
            verify(&fixture, open_origin()),
            Err(OwnerPeerError::Signature)
        ));

        let mut fixture = self::fixture();
        fixture.handoff[336..344].copy_from_slice(&1_i64.to_be_bytes());
        handoff_id(&mut fixture.handoff);
        assert!(matches!(
            verify(&fixture, open_origin()),
            Err(OwnerPeerError::NotCurrent)
        ));
    }
}
