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
//! restricted to the authenticated native carrier's exact attempt and original
//! measured SourceRoot under the held Storage cut. Storage also
//! derives a nonauthorizing AOSZHR01 head from its protected journal cut and
//! confined physical readback. The key exposes no raw key or general signing
//! method. Its separate AOSZNS01 metadata domain signs only an owner's original
//! unsigned acceptance observation and grants no descriptor or hold authority.
//! A retained readback does not prove the hold or journal remains current.

use std::path::PathBuf;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::storage_zfs_hold_receipt::{
    StorageZfsHoldHeadV1, StorageZfsHoldSignerV1, StorageZfsHoldVerifierV1,
};
use aos_sandbox_source_provider_protocol::{
    SignedStorageNativeAcceptanceReadbackV1, SignedStorageNativeAcceptanceV3,
    SignedStorageZfsHoldReceiptV1, StorageNativeAcceptanceV3, StorageNativeAcquireReplyV3,
    StorageZfsHoldReceiptV1, storage_native_nonrecursive_topology_v1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::live_export_request_trust::{
    AuthenticatedStorageNativeAcceptanceReadbackQueryV1, AuthenticatedStorageNativeRequestV2,
};
use crate::native_issuance::StorageNativeAcceptanceMetadataV1;
use crate::operator_recovery_credentials::{
    FileIdentity, PinnedCredential, open_directory, read_credential,
};
use crate::process::HeldSnapshotReaderObservationV1;
use crate::runtime::StorageHeldSnapshotReadbackV1;
use crate::runtime::StorageHeldSnapshotReadbackWithMountV1;
use crate::service::StorageServiceError;

const CREDENTIAL_NAME: &str = "storage-zfs-hold-key-v1";
const MAGIC: &[u8; 8] = b"AOSZHK01";
const VERSION: u16 = 1;
const KEY_BYTES: usize = 160;
const RECEIPT_PHYSICAL_DOMAIN: &[u8] = b"aos.sandbox.storage.zfs-hold.receipt-physical.v1\0";

/// Pins the separately provisioned Storage ZFS hold receipt role key.
pub struct StorageZfsHoldKeyV1 {
    custody: StorageZfsHoldKeyCustodyV1,
    signer: StorageZfsHoldSignerV1,
    verifier: StorageZfsHoldVerifierV1,
    seed: Zeroizing<[u8; 32]>,
}

enum StorageZfsHoldKeyCustodyV1 {
    Protected {
        directory: PathBuf,
        directory_identity: FileIdentity,
        key: PinnedCredential,
    },
    #[cfg(test)]
    SyntheticFixture,
}

impl StorageZfsHoldKeyV1 {
    // This purpose-private crossing accepts only the concrete stored-original
    // loan. Message/key preparation precedes its final genuine owner/clock cut.
    pub(crate) fn sign_stored_original_held_control(
        &self,
        loan: &mut crate::runtime::StoredOriginalHeldSigningLoanV1<'_, '_, '_>,
    ) -> Result<
        aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1,
        crate::runtime::original_held_measurement::OriginalHeldMeasurementErrorV3,
    > {
        self.recheck()?;
        let prepared = loan.prepared()?.clone();
        let message = prepared.signature_message();
        let key = SigningKey::from_bytes(&self.seed);
        loan.consume_last_cut(self)?;
        Ok(prepared.with_signature(key.sign(&message).to_bytes()))
    }

    /// Signs only an owner's exact historical acceptance metadata observation.
    ///
    /// This dedicated metadata domain is not a positive receipt or acceptance.
    /// The caller retains and rejoins all owner cuts through descriptor-free
    /// send. No historical signing key, receipt, validity, or mount is restored.
    ///
    /// # Errors
    ///
    /// Rejects changed credentials/current query pins or a foreign observation.
    pub(crate) fn sign_native_acceptance_readback(
        &self,
        authenticated: &AuthenticatedStorageNativeAcceptanceReadbackQueryV1<'_>,
        observed: &StorageNativeAcceptanceMetadataV1,
    ) -> Result<SignedStorageNativeAcceptanceReadbackV1, StorageServiceError> {
        self.recheck()?;
        authenticated
            .recheck()
            .map_err(|_| invalid("native metadata query trust changed"))?;
        if !observed.matches_query(authenticated) {
            return Err(invalid("native metadata observation names another query"));
        }
        let reply = SignedStorageNativeAcceptanceReadbackV1::sign(
            authenticated.query(),
            observed.sequence(),
            observed.acceptance().cloned(),
            self.signer,
            &SigningKey::from_bytes(&self.seed),
        )
        .map_err(|_| invalid("native metadata observation is invalid"))?;
        reply
            .verify_for(authenticated.query(), self.verifier)
            .map_err(|_| invalid("native metadata signature is invalid"))?;
        self.recheck()?;
        authenticated
            .recheck()
            .map_err(|_| invalid("native metadata query trust changed"))?;
        Ok(reply)
    }

    /// Loads and pins the existing dedicated-role systemd credential.
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
            custody: StorageZfsHoldKeyCustodyV1::Protected {
                directory,
                directory_identity,
                key,
            },
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
        let (directory, directory_identity, key) = match &self.custody {
            StorageZfsHoldKeyCustodyV1::Protected {
                directory,
                directory_identity,
                key,
            } => (directory, directory_identity, key),
            #[cfg(test)]
            StorageZfsHoldKeyCustodyV1::SyntheticFixture => return Ok(()),
        };
        let (fd, identity) = open_directory(directory)?;
        if identity != *directory_identity {
            return Err(invalid("Storage ZFS hold credential directory changed"));
        }
        let current = read_credential(&fd, key.name, KEY_BYTES)?;
        if current.identity != key.identity || current.bytes != key.bytes {
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

    /// Signs only a joined native request and its continuously retained original root.
    ///
    /// The caller retains all Storage writers and must durably accept the exact
    /// reply before transfer. It must rejoin the protected final cut around this
    /// call: this method checks retained evidence, not journal currentness itself.
    ///
    /// # Errors
    ///
    /// Rejects changed credentials/pins, scope, clock, hold claims, or original FD.
    pub(crate) fn sign_native_reply(
        &self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        held: &StorageHeldSnapshotReadbackWithMountV1,
        issuance_id: [u8; 16],
        clock: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<StorageNativeAcquireReplyV3, StorageServiceError> {
        let request = authenticated.request();
        let claims = request.request().claims();
        let (issued, expires) = claims.validity();
        let (receipt, descriptor) = self.native_receipt_basis(
            authenticated,
            held,
            clock,
            (clock.wall_seconds().max(issued), expires),
        )?;
        let unsigned = SignedStorageZfsHoldReceiptV1::new(receipt.clone(), self.signer, [0; 64]);
        let key = SigningKey::from_bytes(&self.seed);
        let receipt = SignedStorageZfsHoldReceiptV1::new(
            receipt,
            self.signer,
            key.sign(&unsigned.signing_message()).to_bytes(),
        );
        let topology = native_topology_from_original(request, &receipt, &descriptor, held)?;
        let acceptance = StorageNativeAcceptanceV3::new(
            issuance_id,
            request.digest(),
            receipt.digest(),
            descriptor,
            topology,
        )
        .map_err(|_| invalid("native acceptance is invalid"))?;
        let signed_acceptance =
            SignedStorageNativeAcceptanceV3::sign(acceptance, self.signer, &key);
        let reply = StorageNativeAcquireReplyV3::new(signed_acceptance, receipt)
            .map_err(|_| invalid("native signed reply is inconsistent"))?;
        self.recheck()?;
        authenticated
            .recheck()
            .map_err(|_| invalid("native request trust changed"))?;
        Ok(reply)
    }

    /// Verifies saved signed bytes against freshly rejoined original custody.
    ///
    /// # Errors
    ///
    /// Rejects changed custody, signed bytes, claims, head, original FD, or time.
    pub(crate) fn verify_native_reply(
        &self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        held: &StorageHeldSnapshotReadbackWithMountV1,
        reply: &StorageNativeAcquireReplyV3,
        clock: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), StorageServiceError> {
        let (issued, expires) = reply.receipt().receipt().validity();
        let (expected, descriptor) =
            self.native_receipt_basis(authenticated, held, clock, (issued, expires))?;
        // The shared verifier validates signed topology crosslinks, but its
        // counts come from the packet. Independently rejoin the original
        // confined measurement retained with this FD before exact replay.
        let topology = native_topology_from_original(
            authenticated.request(),
            reply.receipt(),
            &descriptor,
            held,
        )?;
        if reply.acceptance().acceptance().topology() != &topology {
            return Err(invalid(
                "saved native topology differs from original measurement",
            ));
        }
        authenticated
            .verify_reply(
                reply,
                self.verifier,
                &expected,
                &descriptor,
                clock.wall_seconds(),
            )
            .map_err(|_| {
                invalid("saved native reply differs from authenticated original evidence")
            })?;
        self.recheck()?;
        Ok(())
    }

    fn native_receipt_basis(
        &self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        held: &StorageHeldSnapshotReadbackWithMountV1,
        clock: aos_sandbox_core::RawPairedClockSample,
        validity: (i64, i64),
    ) -> Result<
        (
            StorageZfsHoldReceiptV1,
            aos_sandbox_source_provider_protocol::SourceRootObservationV1,
        ),
        StorageServiceError,
    > {
        authenticated
            .recheck()
            .map_err(|_| invalid("native request trust changed"))?;
        let descriptor = held
            .observe_root()
            .map_err(|_| invalid("original root changed"))?;
        let request = authenticated.request();
        crate::runtime::validate_native_request_clock(request, clock)
            .map_err(|_| invalid("native request is no longer current"))?;
        let claims = request.request().claims();
        let catalog = claims.catalog();
        let (resource, snapshot) = catalog
            .select_under_head(
                catalog.generation(),
                catalog.digest(),
                catalog.namespace_digest(),
                claims.selection().0,
            )
            .map_err(|_| invalid("native selection is invalid"))?;
        if descriptor.kernel_boot_id() != clock.host_boot_id()
            || validity.0 < claims.validity().0
            || validity.1 != claims.validity().1
            || !held.readback.cut.matches_native_claim(
                &snapshot,
                held.readback.pool_guid,
                held.readback.measured_tree.content_digest,
                held.readback.measured_tree.mounted_snapshot_guid,
            )
        {
            return Err(invalid(
                "native receipt basis differs from held original scope",
            ));
        }
        let (challenge, attempt) = claims.attempt();
        let receipt = StorageZfsHoldReceiptV1::new(
            challenge,
            attempt,
            claims.selection().0,
            resource,
            snapshot,
            self.receipt_head(&held.readback)?,
            validity.0,
            validity.1,
        )
        .map_err(|_| invalid("native hold receipt is invalid"))?;
        Ok((receipt, descriptor))
    }

    #[cfg(test)]
    pub(crate) fn synthetic_key_for_test() -> Self {
        Self::synthetic_rotated_key_for_test([7; 32], 5)
    }

    #[cfg(test)]
    pub(crate) fn synthetic_rotated_key_for_test(seed: [u8; 32], generation: u64) -> Self {
        let mut record = tests::record();
        record[88..96].copy_from_slice(&generation.to_be_bytes());
        record[96..128].copy_from_slice(&SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        record[128..160].copy_from_slice(&seed);
        let (signer, verifier, seed) = decode_key_record(&record).unwrap();
        Self {
            custody: StorageZfsHoldKeyCustodyV1::SyntheticFixture,
            signer,
            verifier,
            seed,
        }
    }
}

/// Derives mount-shaped topology only from the confined original-reader result.
///
/// Fresh private fscontext construction and the reader's complete NO_XDEV
/// walk establish depth one and no attached submounts. Directory nesting is
/// not mount depth, and a generic inherited FD/tree walk cannot mint this
/// owner's production readback-with-mount. Exact retry retains these counts.
fn native_topology_from_original(
    request: &aos_sandbox_source_provider_protocol::SignedStorageNativeAcquireRequestV2,
    receipt: &SignedStorageZfsHoldReceiptV1,
    descriptor: &aos_sandbox_source_provider_protocol::SourceRootObservationV1,
    held: &StorageHeldSnapshotReadbackWithMountV1,
) -> Result<aos_sandbox_source_provider_protocol::RecursiveTopologyProofV1, StorageServiceError> {
    storage_native_nonrecursive_topology_v1(
        request,
        receipt,
        descriptor,
        u64::from(held.readback.measured_tree.nodes),
        held.readback.measured_tree.file_bytes,
    )
    .map_err(|_| invalid("native confined topology is invalid"))
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

    pub(super) fn record() -> [u8; KEY_BYTES] {
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
