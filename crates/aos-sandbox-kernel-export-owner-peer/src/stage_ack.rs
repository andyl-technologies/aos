//! Closed AOSKGA02 signed PREPARED acknowledgment verification.
//!
//! ```text
//! AOSKGA02[600] = header[16] | AOSKGH01[344] | AOSSLE01-digest[32] |
//!   mutable-origin-mount/device/inode[24] | prepared-epoch[8] |
//!   owner-map-row-digest[32] | Storage-signer-projection[80] | signature[64]
//! ```
//!
//! The explicit origin mount is Storage's signed assertion, not a physical
//! observation by the owner. The clone tuple is separately committed by the
//! embedded handoff. No Storage signer is deployed for this format, no owner
//! stage/map readback is connected, and verification never activates a grant.

use aos_sandbox_source_provider_protocol::storage_live_export_lease::{
    SignedStorageLiveExportLeaseV1, StorageLiveExportVerifierV1,
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::OwnerPeerError;
use crate::handoff::DenyStageHandoff;

/// Exact signed PREPARED acknowledgment length.
pub const ACK_BYTES: usize = 600;
/// Exact signed Storage lease length.
pub const LEASE_BYTES: usize = 496;
/// Exact protected verifier projection plus Ed25519 public key length.
pub const VERIFIER_BYTES: usize = 112;
const ACK_DOMAIN: &[u8] = b"aos.sandbox.storage.kernel-export-stage-ack.signature.v2\0";

/// Borrows two distinct, independently pinned role-specific verifier records.
///
/// Constructing this pair does not establish protected deployment custody.
/// The opt-in daemon loads public verifiers but does not call this codec.
pub struct StorageRoleVerifiers<'a> {
    /// The earlier mutable-origin lease verifier.
    pub lease: &'a [u8; VERIFIER_BYTES],
    /// The distinct PREPARED stage-ack verifier.
    pub stage: &'a [u8; VERIFIER_BYTES],
}

/// Reports a closed codec consistency check, never map or effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedPreparedAckCheck {
    handoff_id: [u8; 32],
    origin_mount_id: u64,
    clone_mount_id: u64,
    cgroup_id: u64,
    epoch: u64,
    map_row_digest: [u8; 32],
}

impl ClosedPreparedAckCheck {
    /// Returns the signed handoff commitment, not a grant identifier.
    #[must_use]
    pub const fn handoff_id(&self) -> [u8; 32] {
        self.handoff_id
    }

    /// Returns the Storage-asserted mutable-origin unique mount ID.
    #[must_use]
    pub const fn origin_mount_id(&self) -> u64 {
        self.origin_mount_id
    }

    /// Returns the separately committed detached clone unique mount ID.
    #[must_use]
    pub const fn clone_mount_id(&self) -> u64 {
        self.clone_mount_id
    }

    /// Returns the exact consumer cgroup kernfs ID in the deny-stage frame.
    #[must_use]
    pub const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    /// Returns the signed PREPARED epoch, not a live map readback.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the signed digest of a claimed owner PREPARED map row.
    #[must_use]
    pub const fn map_row_digest(&self) -> [u8; 32] {
        self.map_row_digest
    }
}

/// Verifies the closed signed lease/ack binding against caller-pinned inputs.
///
/// The `prepared_map_digest` must come from a separate current C-owner map
/// readback; this pure verifier cannot produce or authenticate it. The
/// Both role-specific verifiers must be independently pinned by deployment.
/// Passing caller-controlled bytes establishes no authority. Neither input is wired
/// in production, and this function cannot install or activate a grant.
///
/// # Errors
///
/// Rejects any invalid signature, stale lease/handoff, wrong Storage signer,
/// wrong origin/clone/cgroup/epoch, or map-row digest mismatch.
pub fn verify_closed_prepared_ack(
    ack: &[u8],
    lease: &[u8],
    handoff: &DenyStageHandoff,
    verifiers: StorageRoleVerifiers<'_>,
    prepared_map_digest: &[u8; 32],
    prepared_epoch: u64,
    now_seconds: i64,
) -> Result<ClosedPreparedAckCheck, OwnerPeerError> {
    let StorageRoleVerifiers {
        lease: lease_verifier,
        stage: stage_verifier,
    } = verifiers;
    let ack: &[u8; ACK_BYTES] = ack.try_into().map_err(|_| OwnerPeerError::Noncanonical)?;
    let lease: &[u8; LEASE_BYTES] = lease.try_into().map_err(|_| OwnerPeerError::Noncanonical)?;
    let signed_lease =
        SignedStorageLiveExportLeaseV1::decode(lease).map_err(|_| OwnerPeerError::Noncanonical)?;
    let lease_public_key: [u8; 32] = lease_verifier[80..112]
        .try_into()
        .map_err(|_| OwnerPeerError::Noncanonical)?;
    let pinned_lease_verifier =
        StorageLiveExportVerifierV1::new(signed_lease.signer(), lease_public_key)
            .map_err(|_| OwnerPeerError::Signature)?;
    if lease[352..432] != lease_verifier[..80] {
        return Err(OwnerPeerError::Signature);
    }
    pinned_lease_verifier
        .verify(signed_lease, now_seconds)
        .map_err(|_| OwnerPeerError::Signature)?;

    let source = signed_lease.lease().source();
    let origin_mount_id = u64::from_be_bytes(
        ack[392..400]
            .try_into()
            .map_err(|_| OwnerPeerError::Noncanonical)?,
    );
    let origin_device = u64::from_be_bytes(
        ack[400..408]
            .try_into()
            .map_err(|_| OwnerPeerError::Noncanonical)?,
    );
    let origin_inode = u64::from_be_bytes(
        ack[408..416]
            .try_into()
            .map_err(|_| OwnerPeerError::Noncanonical)?,
    );
    let epoch = u64::from_be_bytes(
        ack[416..424]
            .try_into()
            .map_err(|_| OwnerPeerError::Noncanonical)?,
    );
    let (clone_device, clone_inode) = handoff.clone_root();

    if &ack[..8] != b"AOSKGA02"
        || ack[8..10] != 2_u16.to_be_bytes()
        || ack[10..16] != [0; 6]
        || ack[16..360] != handoff.as_bytes()[..]
        || ack[360..392] != *signed_lease.digest().as_bytes()
        || source.origin_boot_id() != handoff.boot_id()
        || origin_mount_id != source.origin_mount_id()
        || origin_mount_id == handoff.clone_mount_id()
        || origin_device != source.origin_device()
        || origin_inode != source.origin_inode()
        || (origin_device, origin_inode) != (clone_device, clone_inode)
        || ack[424..456] != prepared_map_digest[..]
        || *prepared_map_digest == [0; 32]
        || epoch == 0
        || epoch != prepared_epoch
        || ack[456..536] != stage_verifier[..80]
        || stage_verifier[..16] == [0; 16]
        || stage_verifier[16..24] == [0; 8]
        || stage_verifier[24..56] == [0; 32]
        || stage_verifier[56..72] == [0; 16]
        || stage_verifier[72..80] == [0; 8]
        || stage_verifier[..80] == lease_verifier[..80]
        || now_seconds <= 0
        || now_seconds >= handoff.exclusive_expiry_seconds()
        || lease[288..312] != handoff.as_bytes()[48..72]
    {
        return Err(OwnerPeerError::Noncanonical);
    }

    let stage_public_key: [u8; 32] = stage_verifier[80..112]
        .try_into()
        .map_err(|_| OwnerPeerError::Noncanonical)?;
    if stage_public_key == lease_public_key {
        return Err(OwnerPeerError::Signature);
    }
    let key = VerifyingKey::from_bytes(&stage_public_key).map_err(|_| OwnerPeerError::Signature)?;
    if key.is_weak() {
        return Err(OwnerPeerError::Signature);
    }
    let mut message = Vec::with_capacity(ACK_DOMAIN.len() + 536);
    message.extend_from_slice(ACK_DOMAIN);
    message.extend_from_slice(&ack[..536]);
    let signature: [u8; 64] = ack[536..600]
        .try_into()
        .map_err(|_| OwnerPeerError::Noncanonical)?;
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| OwnerPeerError::Signature)?;

    let map_row_digest = *prepared_map_digest;
    Ok(ClosedPreparedAckCheck {
        handoff_id: handoff.handoff_id(),
        origin_mount_id,
        clone_mount_id: handoff.clone_mount_id(),
        cgroup_id: handoff.cgroup_id(),
        epoch,
        map_row_digest,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use sha2::{Digest as _, Sha256};

    use super::*;

    const LEASE_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-lease.signature.v1\0";
    const HANDOFF_DOMAIN: &[u8] = b"aos.sandbox.storage.kernel-export-deny-handoff.v1\0";

    struct Fixture {
        ack: [u8; ACK_BYTES],
        lease: [u8; LEASE_BYTES],
        handoff: DenyStageHandoff,
        lease_verifier: [u8; VERIFIER_BYTES],
        stage_verifier: [u8; VERIFIER_BYTES],
        stage_key: SigningKey,
        map_digest: [u8; 32],
    }

    fn fill(bytes: &mut [u8], start: usize, end: usize, value: u8) {
        bytes[start..end].fill(value);
    }

    fn fixture() -> Fixture {
        let lease_key = SigningKey::from_bytes(&[77; 32]);
        let stage_key = SigningKey::from_bytes(&[78; 32]);
        let mut frame = [0_u8; 344];
        frame[..8].copy_from_slice(b"AOSKGH01");
        frame[8..10].copy_from_slice(&1_u16.to_be_bytes());
        frame[10] = 1;
        for (start, end, value) in [
            (48, 64, 1),
            (72, 88, 2),
            (88, 120, 3),
            (120, 152, 4),
            (152, 184, 5),
            (192, 224, 6),
            (224, 240, 9),
            (264, 280, 7),
            (288, 320, 8),
        ] {
            fill(&mut frame, start, end, value);
        }
        frame[64..72].copy_from_slice(&2_u64.to_be_bytes());
        frame[184..192].copy_from_slice(&3_u64.to_be_bytes());
        frame[240..248].copy_from_slice(&44_u64.to_be_bytes());
        frame[248..256].copy_from_slice(&10_u64.to_be_bytes());
        frame[256..264].copy_from_slice(&11_u64.to_be_bytes());
        frame[280..288].copy_from_slice(&4_u64.to_be_bytes());
        frame[320..328].copy_from_slice(&60_u64.to_be_bytes());
        frame[336..344].copy_from_slice(&200_i64.to_be_bytes());
        let id: [u8; 32] = Sha256::new()
            .chain_update(HANDOFF_DOMAIN)
            .chain_update(&frame[48..])
            .finalize()
            .into();
        frame[16..48].copy_from_slice(&id);
        let handoff = DenyStageHandoff::parse(&frame).unwrap();

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
            (200, 216, 9),
            (240, 272, 8),
            (272, 288, 10),
            (312, 328, 11),
            (352, 368, 12),
            (376, 408, 13),
            (408, 424, 14),
        ] {
            fill(&mut lease, start, end, value);
        }
        lease[96..104].copy_from_slice(&1_u64.to_be_bytes());
        lease[216..224].copy_from_slice(&10_u64.to_be_bytes());
        lease[224..232].copy_from_slice(&11_u64.to_be_bytes());
        lease[232..240].copy_from_slice(&55_u64.to_be_bytes());
        lease[288..304].copy_from_slice(&frame[48..64]);
        lease[304..312].copy_from_slice(&frame[64..72]);
        lease[328..336].copy_from_slice(&1_u64.to_be_bytes());
        lease[336..344].copy_from_slice(&100_i64.to_be_bytes());
        lease[344..352].copy_from_slice(&200_i64.to_be_bytes());
        lease[368..376].copy_from_slice(&1_u64.to_be_bytes());
        lease[424..432].copy_from_slice(&1_u64.to_be_bytes());
        let mut message = LEASE_DOMAIN.to_vec();
        message.extend_from_slice(&lease[..432]);
        lease[432..496].copy_from_slice(&lease_key.sign(&message).to_bytes());
        let signed = SignedStorageLiveExportLeaseV1::decode(&lease).unwrap();

        let mut lease_verifier = [0_u8; VERIFIER_BYTES];
        lease_verifier[..80].copy_from_slice(&lease[352..432]);
        lease_verifier[80..].copy_from_slice(&lease_key.verifying_key().to_bytes());
        let mut stage_verifier = [0_u8; VERIFIER_BYTES];
        stage_verifier[..16].fill(21);
        stage_verifier[16..24].copy_from_slice(&1_u64.to_be_bytes());
        stage_verifier[24..56].fill(22);
        stage_verifier[56..72].fill(23);
        stage_verifier[72..80].copy_from_slice(&1_u64.to_be_bytes());
        stage_verifier[80..].copy_from_slice(&stage_key.verifying_key().to_bytes());
        let map_digest = [15; 32];
        let mut ack = [0_u8; ACK_BYTES];
        ack[..8].copy_from_slice(b"AOSKGA02");
        ack[8..10].copy_from_slice(&2_u16.to_be_bytes());
        ack[16..360].copy_from_slice(&frame);
        ack[360..392].copy_from_slice(signed.digest().as_bytes());
        ack[392..400].copy_from_slice(&55_u64.to_be_bytes());
        ack[400..408].copy_from_slice(&10_u64.to_be_bytes());
        ack[408..416].copy_from_slice(&11_u64.to_be_bytes());
        ack[416..424].copy_from_slice(&1_u64.to_be_bytes());
        ack[424..456].copy_from_slice(&map_digest);
        ack[456..536].copy_from_slice(&stage_verifier[..80]);
        sign_ack(&mut ack, &stage_key);

        Fixture {
            ack,
            lease,
            handoff,
            lease_verifier,
            stage_verifier,
            stage_key,
            map_digest,
        }
    }

    fn sign_ack(ack: &mut [u8; ACK_BYTES], key: &SigningKey) {
        let mut message = ACK_DOMAIN.to_vec();
        message.extend_from_slice(&ack[..536]);
        ack[536..].copy_from_slice(&key.sign(&message).to_bytes());
    }

    fn verify(fixture: &Fixture) -> Result<ClosedPreparedAckCheck, OwnerPeerError> {
        verify_closed_prepared_ack(
            &fixture.ack,
            &fixture.lease,
            &fixture.handoff,
            StorageRoleVerifiers {
                lease: &fixture.lease_verifier,
                stage: &fixture.stage_verifier,
            },
            &fixture.map_digest,
            1,
            150,
        )
    }

    #[test]
    fn signed_closed_ack_binds_origin_clone_epoch_and_cgroup() {
        let fixture = fixture();
        let readback = verify(&fixture).unwrap();
        assert_eq!(readback.origin_mount_id(), 55);
        assert_eq!(readback.clone_mount_id(), 44);
        assert_eq!(readback.cgroup_id(), 60);
        assert_eq!(readback.epoch(), 1);
    }

    #[test]
    fn signed_wrong_origin_mount_and_clone_tuple_are_rejected() {
        let mut fixture = fixture();
        fixture.ack[392..400].copy_from_slice(&56_u64.to_be_bytes());
        sign_ack(&mut fixture.ack, &fixture.stage_key);
        assert!(matches!(
            verify(&fixture),
            Err(OwnerPeerError::Noncanonical)
        ));

        let mut fixture = self::fixture();
        fixture.ack[400..408].copy_from_slice(&12_u64.to_be_bytes());
        sign_ack(&mut fixture.ack, &fixture.stage_key);
        assert!(matches!(
            verify(&fixture),
            Err(OwnerPeerError::Noncanonical)
        ));

        let mut fixture = self::fixture();
        fixture.ack[392..400].copy_from_slice(&44_u64.to_be_bytes());
        sign_ack(&mut fixture.ack, &fixture.stage_key);
        assert!(matches!(
            verify(&fixture),
            Err(OwnerPeerError::Noncanonical)
        ));
    }

    #[test]
    fn changed_cgroup_epoch_map_and_handoff_fail_closed() {
        let mut fixture = fixture();
        fixture.ack[16 + 320] ^= 1;
        assert!(matches!(
            verify(&fixture),
            Err(OwnerPeerError::Noncanonical)
        ));

        let fixture = self::fixture();
        assert!(
            verify_closed_prepared_ack(
                &fixture.ack,
                &fixture.lease,
                &fixture.handoff,
                StorageRoleVerifiers {
                    lease: &fixture.lease_verifier,
                    stage: &fixture.stage_verifier,
                },
                &fixture.map_digest,
                2,
                150,
            )
            .is_err()
        );

        let mut fixture = self::fixture();
        fixture.ack[424] ^= 1;
        sign_ack(&mut fixture.ack, &fixture.stage_key);
        assert!(matches!(
            verify(&fixture),
            Err(OwnerPeerError::Noncanonical)
        ));

        let mut fixture = self::fixture();
        fixture.ack[192] ^= 1;
        sign_ack(&mut fixture.ack, &fixture.stage_key);
        assert!(matches!(
            verify(&fixture),
            Err(OwnerPeerError::Noncanonical)
        ));
    }

    #[test]
    fn wrong_signer_signature_and_expiry_fail_closed() {
        let mut fixture = fixture();
        fixture.stage_verifier[80] ^= 1;
        assert!(matches!(verify(&fixture), Err(OwnerPeerError::Signature)));

        let mut fixture = self::fixture();
        fixture.stage_verifier = fixture.lease_verifier;
        assert!(verify(&fixture).is_err());

        let mut fixture = self::fixture();
        fixture.lease[495] ^= 1;
        assert!(matches!(verify(&fixture), Err(OwnerPeerError::Signature)));

        let mut fixture = self::fixture();
        fixture.ack[599] ^= 1;
        assert!(matches!(verify(&fixture), Err(OwnerPeerError::Signature)));

        let fixture = self::fixture();
        assert!(
            verify_closed_prepared_ack(
                &fixture.ack,
                &fixture.lease,
                &fixture.handoff,
                StorageRoleVerifiers {
                    lease: &fixture.lease_verifier,
                    stage: &fixture.stage_verifier,
                },
                &fixture.map_digest,
                1,
                200,
            )
            .is_err()
        );
    }
}
