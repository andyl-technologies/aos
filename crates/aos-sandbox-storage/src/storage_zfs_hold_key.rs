//! Dedicated root-owned Storage ZFS hold receipt signing-key custody.
//!
//! ```text
//! AOSZHK01 | version:u16be=1 | reserved[6]=0 |
//! authority-id[16] | authority-generation:u64be |
//! authority-digest[32] | key-id[16] | key-generation:u64be |
//! ed25519-public[32] | ed25519-seed[32]
//! ```
//!
//! This systemd credential is separate from the LocalLive lease key and
//! operator Repair key. It is pinned at Storage startup and rechecked against
//! the exact credential directory, file identity, and bytes. Signing remains
//! unavailable until an authenticated broker carrier conveys the Provider's
//! owner-minted challenge, exact attempt, and holder session. Storage also
//! derives a nonauthorizing AOSZHR01 head from its protected journal cut and
//! confined physical readback. The key exposes no signing method while
//! authenticated attempt and SourceRoot descriptor custody are absent. A
//! retained readback does not prove that the hold or journal remains current.

use std::path::PathBuf;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::storage_zfs_hold_receipt::{
    StorageZfsHoldHeadV1, StorageZfsHoldSignerV1, StorageZfsHoldVerifierV1,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::operator_recovery_credentials::{
    FileIdentity, PinnedCredential, open_directory, read_credential,
};
use crate::process::HeldSnapshotReaderObservationV1;
use crate::runtime::StorageHeldSnapshotReadbackV1;
use crate::service::StorageServiceError;

const CREDENTIAL_NAME: &str = "storage-zfs-hold-key-v1";
const MAGIC: &[u8; 8] = b"AOSZHK01";
const VERSION: u16 = 1;
const KEY_BYTES: usize = 160;
const RECEIPT_PHYSICAL_DOMAIN: &[u8] = b"aos.sandbox.storage.zfs-hold.receipt-physical.v1\0";

/// Pins the separately provisioned Storage ZFS hold receipt role key.
pub struct StorageZfsHoldKeyV1 {
    directory: PathBuf,
    directory_identity: FileIdentity,
    key: PinnedCredential,
    signer: StorageZfsHoldSignerV1,
    verifier: StorageZfsHoldVerifierV1,
    seed: Zeroizing<[u8; 32]>,
}

impl StorageZfsHoldKeyV1 {
    /// Loads the fixed systemd credential without creating signing authority.
    ///
    /// # Errors
    ///
    /// Rejects an absent, aliased, unsafe, malformed, or changed credential.
    pub fn load() -> Result<Self, StorageServiceError> {
        let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or_else(|| invalid("Storage ZFS hold credential directory is absent"))?;
        let (fd, directory_identity) = open_directory(&directory)?;
        let key = read_credential(&fd, CREDENTIAL_NAME, KEY_BYTES)?;
        let (signer, verifier, seed) = decode_key_record(&key.bytes)?;
        let retained = Self {
            directory,
            directory_identity,
            key,
            signer,
            verifier,
            seed,
        };
        retained.recheck()?;
        Ok(retained)
    }

    /// Reopens the exact protected key and refuses rotation within this process.
    ///
    /// # Errors
    ///
    /// Rejects any changed directory, file identity, metadata, or key bytes.
    pub fn recheck(&self) -> Result<(), StorageServiceError> {
        let (fd, identity) = open_directory(&self.directory)?;
        if identity != self.directory_identity {
            return Err(invalid("Storage ZFS hold credential directory changed"));
        }
        let current = read_credential(&fd, self.key.name, KEY_BYTES)?;
        if current.identity != self.key.identity || current.bytes != self.key.bytes {
            return Err(invalid("Storage ZFS hold credential changed"));
        }
        let (signer, verifier, seed) = decode_key_record(&current.bytes)?;
        if signer != self.signer || verifier != self.verifier || seed != self.seed {
            return Err(invalid("Storage ZFS hold credential changed"));
        }
        Ok(())
    }

    /// Returns the public verifier projection for trusted publication.
    #[must_use]
    pub const fn verifier(&self) -> StorageZfsHoldVerifierV1 {
        self.verifier
    }

    /// Derives an unsigned head for the time of the supplied Storage readback.
    ///
    /// No Provider attempt, SourceRoot descriptor, or receipt signature is
    /// accepted or emitted here. Key rotation requires a new Storage process.
    /// A later issuance path must rejoin the live held snapshot, protected
    /// journal, and policy before it can claim currentness after this readback.
    ///
    /// # Errors
    ///
    /// Rejects changed key custody or an invalid protected readback head.
    pub(crate) fn receipt_head(
        &self,
        readback: &StorageHeldSnapshotReadbackV1,
    ) -> Result<StorageZfsHoldHeadV1, StorageServiceError> {
        self.recheck()?;
        let (_, authority_generation, authority_digest) = self.signer.authority();
        let head = StorageZfsHoldHeadV1::new(
            readback.cut.catalog.generation(),
            readback.cut.catalog.digest(),
            authority_generation,
            authority_digest,
            readback.cut.authority_sequence,
            readback.cut.materialized_state_digest,
            held_snapshot_receipt_physical_digest(
                readback.physical_observation_digest,
                readback.post_measurement_observation_digest,
                &readback.measured_tree,
            ),
        )
        .map_err(|_| invalid("Storage ZFS hold receipt head is invalid"))?;
        self.recheck()?;
        Ok(head)
    }
}

fn held_snapshot_receipt_physical_digest(
    before: ObjectDigest,
    after: ObjectDigest,
    measured: &HeldSnapshotReaderObservationV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(RECEIPT_PHYSICAL_DOMAIN)
            .chain_update(before.as_bytes())
            .chain_update(after.as_bytes())
            .chain_update(measured.content_digest.as_bytes())
            .chain_update(measured.tree_digest.as_bytes())
            .chain_update(measured.tree_size.to_be_bytes())
            .chain_update(measured.mount_id.to_be_bytes())
            .chain_update(measured.root_device.to_be_bytes())
            .chain_update(measured.root_inode.to_be_bytes())
            .chain_update(measured.nodes.to_be_bytes())
            .chain_update(measured.file_bytes.to_be_bytes())
            .chain_update(measured.mounted_snapshot_guid.to_be_bytes())
            .chain_update(measured.identity.root_attributes.uid().to_be_bytes())
            .chain_update(measured.identity.root_attributes.gid().to_be_bytes())
            .chain_update(measured.identity.root_attributes.mode().to_be_bytes())
            .chain_update(measured.identity.maximum_portable_uid.to_be_bytes())
            .chain_update(measured.identity.maximum_portable_gid.to_be_bytes())
            .chain_update(measured.identity.distinct_inode_count.to_be_bytes())
            .chain_update(measured.identity.directory_entry_count.to_be_bytes())
            .chain_update(measured.identity.identity_tree_digest.as_bytes())
            .finalize()
            .into(),
    )
}

fn decode_key_record(
    bytes: &[u8],
) -> Result<
    (
        StorageZfsHoldSignerV1,
        StorageZfsHoldVerifierV1,
        Zeroizing<[u8; 32]>,
    ),
    StorageServiceError,
> {
    if bytes.len() != KEY_BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
        || bytes.get(10..16) != Some([0; 6].as_slice())
    {
        return Err(invalid("Storage ZFS hold key record is noncanonical"));
    }
    let authority_id = array(bytes, 16)?;
    let authority_generation = u64::from_be_bytes(array(bytes, 32)?);
    let authority_digest = ObjectDigest::from_bytes(array(bytes, 40)?);
    let key_id = array(bytes, 72)?;
    let key_generation = u64::from_be_bytes(array(bytes, 88)?);
    let public_key = array(bytes, 96)?;
    let seed = Zeroizing::new(array(bytes, 128)?);
    if *seed == [0; 32] || SigningKey::from_bytes(&seed).verifying_key().to_bytes() != public_key {
        return Err(invalid(
            "Storage ZFS hold signing key does not match public key",
        ));
    }
    let signer = StorageZfsHoldSignerV1::new(
        authority_id,
        authority_generation,
        authority_digest,
        key_id,
        key_generation,
    )
    .map_err(|_| invalid("Storage ZFS hold signer is invalid"))?;
    let verifier = StorageZfsHoldVerifierV1::new(signer, public_key)
        .map_err(|_| invalid("Storage ZFS hold public key is invalid"))?;
    Ok((signer, verifier, seed))
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], StorageServiceError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid("Storage ZFS hold key record is truncated"))
}

fn invalid(message: &str) -> StorageServiceError {
    StorageServiceError::Activation(message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use rustix::fs::{Mode, OFlags};
    use tempfile::TempDir;

    use super::*;
    use crate::held_snapshot_tree::HeldSnapshotIdentityObservationV1;
    use crate::root_policy::PortableRootAttributesV1;

    fn record() -> [u8; KEY_BYTES] {
        let mut bytes = [0; KEY_BYTES];
        let seed = [7; 32];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..32].copy_from_slice(&[1; 16]);
        bytes[32..40].copy_from_slice(&2_u64.to_be_bytes());
        bytes[40..72].copy_from_slice(&[3; 32]);
        bytes[72..88].copy_from_slice(&[4; 16]);
        bytes[88..96].copy_from_slice(&5_u64.to_be_bytes());
        bytes[96..128].copy_from_slice(&SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        bytes[128..160].copy_from_slice(&seed);
        bytes
    }

    fn measured_observation() -> HeldSnapshotReaderObservationV1 {
        HeldSnapshotReaderObservationV1 {
            content_digest: ObjectDigest::from_bytes([3; 32]),
            tree_digest: ObjectDigest::from_bytes([4; 32]),
            tree_size: 5,
            mount_id: 6,
            root_device: 7,
            root_inode: 8,
            nodes: 9,
            file_bytes: 10,
            mounted_snapshot_guid: 11,
            identity: HeldSnapshotIdentityObservationV1 {
                root_attributes: PortableRootAttributesV1::new(0, 0, 0o755).unwrap(),
                maximum_portable_uid: 12,
                maximum_portable_gid: 13,
                distinct_inode_count: 9,
                directory_entry_count: 8,
                identity_tree_digest: ObjectDigest::from_bytes([14; 32]),
            },
        }
    }

    #[test]
    fn receipt_physical_commitment_binds_both_holds_mount_and_tree() {
        let before = ObjectDigest::from_bytes([1; 32]);
        let after = ObjectDigest::from_bytes([2; 32]);
        let measured = measured_observation();
        let expected = held_snapshot_receipt_physical_digest(before, after, &measured);

        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(
                ObjectDigest::from_bytes([15; 32]),
                after,
                &measured,
            )
        );
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(
                before,
                ObjectDigest::from_bytes([16; 32]),
                &measured,
            )
        );
        let mut changed = measured;
        changed.mount_id += 1;
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
        changed = measured;
        changed.content_digest = ObjectDigest::from_bytes([17; 32]);
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
    }

    #[test]
    fn receipt_physical_commitment_binds_every_reader_identity_field() {
        let before = ObjectDigest::from_bytes([1; 32]);
        let after = ObjectDigest::from_bytes([2; 32]);
        let measured = measured_observation();
        let expected = held_snapshot_receipt_physical_digest(before, after, &measured);
        let mut changed = measured;

        changed.identity.root_attributes = PortableRootAttributesV1::new(1, 0, 0o755).unwrap();
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
        changed.identity.root_attributes = PortableRootAttributesV1::new(0, 1, 0o755).unwrap();
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
        changed.identity.root_attributes = PortableRootAttributesV1::new(0, 0, 0o700).unwrap();
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );

        changed = measured;
        changed.identity.maximum_portable_uid += 1;
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
        changed = measured;
        changed.identity.maximum_portable_gid += 1;
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
        changed = measured;
        changed.identity.distinct_inode_count += 1;
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
        changed = measured;
        changed.identity.directory_entry_count += 1;
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
        changed = measured;
        changed.identity.identity_tree_digest = ObjectDigest::from_bytes([18; 32]);
        assert_ne!(
            expected,
            held_snapshot_receipt_physical_digest(before, after, &changed)
        );
    }

    #[test]
    fn dedicated_role_key_rejects_malformed_and_mismatched_records() {
        assert!(decode_key_record(&record()).is_ok());
        for index in [0, 8, 10, 16, 40, 72, 96, 128] {
            let mut changed = record();
            changed[index] ^= 1;
            if index == 16 || index == 40 || index == 72 {
                // Nonzero identities may change, but their signature role is
                // still bound by the protected exact-byte recheck.
                assert!(decode_key_record(&changed).is_ok());
            } else {
                assert!(decode_key_record(&changed).is_err(), "byte {index}");
            }
        }
    }

    #[test]
    fn dedicated_role_rejects_cross_role_or_missing_signer_authority() {
        let (signer, verifier, seed) = decode_key_record(&record()).unwrap();
        assert_eq!(
            verifier.projection(),
            (
                signer,
                SigningKey::from_bytes(&seed).verifying_key().to_bytes()
            )
        );

        let mut source_role = record();
        source_role[..8].copy_from_slice(b"AOSSPK01");
        assert!(decode_key_record(&source_role).is_err());

        let mut live_export_role = record();
        live_export_role[..8].copy_from_slice(b"AOSSLK01");
        assert!(decode_key_record(&live_export_role).is_err());

        for range in [16..32, 32..40, 40..72, 72..88, 88..96] {
            let mut missing = record();
            missing[range].fill(0);
            assert!(decode_key_record(&missing).is_err());
        }
    }

    #[test]
    fn credential_reader_rejects_insecure_mode_and_alias() {
        let directory = TempDir::new().unwrap();
        let key_path = directory.path().join(CREDENTIAL_NAME);
        std::fs::write(&key_path, record()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let descriptor = rustix::fs::open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(read_credential(&descriptor, CREDENTIAL_NAME, KEY_BYTES).is_err());

        let alternate = directory.path().join("alternate-key");
        std::fs::rename(&key_path, &alternate).unwrap();
        symlink(&alternate, &key_path).unwrap();
        assert!(read_credential(&descriptor, CREDENTIAL_NAME, KEY_BYTES).is_err());
    }
}
