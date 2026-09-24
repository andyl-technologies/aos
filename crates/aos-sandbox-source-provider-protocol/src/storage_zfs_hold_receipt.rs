//! Storage's signed observation of one exact held ZFS snapshot.
//!
//! ```text
//! AOSZHR01 | version:u16be=1 | reserved[6]=0 |
//! provider-challenge[32] | provider-attempt-digest[32] | binding-digest[32] |
//! source-resource[184] | ZFS-held-snapshot-proof[184] |
//! storage-catalog-generation:u64be | storage-catalog-digest[32] |
//! storage-authority-generation:u64be | storage-authority-digest[32] |
//! storage-journal-sequence:u64be | storage-journal-digest[32] |
//! physical-observation-digest[32] |
//! issued-seconds:i64be | valid-until-seconds:i64be |
//! AOSZHSG1 | signer-authority-id[16] | signer-authority-generation:u64be |
//! signer-authority-digest[32] |
//! signer-key-id[16] | signer-key-generation:u64be | signature[64]
//! ```
//!
//! This role is distinct from Storage's LocalLive export lease. A verifier
//! must independently pin its key and compare the entire receipt with its
//! current protected selection, fresh challenge, and durable attempt. A valid
//! signature by itself does not establish a live hold or authorize Acquire.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{SourceResourceV1, ZfsHeldSnapshotProofV1};

const MAGIC: &[u8; 8] = b"AOSZHR01";
const ROLE: &[u8; 8] = b"AOSZHSG1";
const VERSION: u16 = 1;
const SUBJECT_BYTES: usize = 648;
const SIGNER_BYTES: usize = 88;
const SIGNATURE_BYTES: usize = 64;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.storage.zfs-hold.receipt.signature.v1\0";
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.zfs-hold.receipt.digest.v1\0";
const MAXIMUM_VALIDITY_SECONDS: i64 = 60;

/// Exact byte length of one signed Storage ZFS hold receipt.
pub const SIGNED_STORAGE_ZFS_HOLD_RECEIPT_BYTES_V1: usize =
    SUBJECT_BYTES + SIGNER_BYTES + SIGNATURE_BYTES;

/// Rejects malformed, unauthenticated, stale, or mismatched hold receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageZfsHoldReceiptErrorV1 {
    /// A field, record length, role, version, or reserved byte is invalid.
    #[error("Storage ZFS hold receipt is noncanonical")]
    Noncanonical,
    /// The protected signer projection or signature does not match.
    #[error("Storage ZFS hold receipt signature is invalid")]
    Signature,
    /// The signed receipt is outside its bounded validity interval.
    #[error("Storage ZFS hold receipt is not current")]
    NotCurrent,
    /// The signed observation differs from the independently expected tuple.
    #[error("Storage ZFS hold receipt does not match current selection and attempt")]
    Mismatch,
}

/// Pins Storage's catalog, authority, journal, and physical readback heads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageZfsHoldHeadV1 {
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    authority_generation: u64,
    authority_digest: ObjectDigest,
    journal_sequence: u64,
    journal_digest: ObjectDigest,
    physical_observation_digest: ObjectDigest,
}

impl StorageZfsHoldHeadV1 {
    /// Constructs the independently recovered Storage state and observation.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, sequence, or commitments.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        catalog_generation: u64,
        catalog_digest: ObjectDigest,
        authority_generation: u64,
        authority_digest: ObjectDigest,
        journal_sequence: u64,
        journal_digest: ObjectDigest,
        physical_observation_digest: ObjectDigest,
    ) -> Result<Self, StorageZfsHoldReceiptErrorV1> {
        if catalog_generation == 0
            || authority_generation == 0
            || journal_sequence == 0
            || [
                catalog_digest,
                authority_digest,
                journal_digest,
                physical_observation_digest,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(StorageZfsHoldReceiptErrorV1::Noncanonical);
        }
        Ok(Self {
            catalog_generation,
            catalog_digest,
            authority_generation,
            authority_digest,
            journal_sequence,
            journal_digest,
            physical_observation_digest,
        })
    }

    /// Returns the current protected Storage catalog generation and digest.
    #[must_use]
    pub const fn catalog(self) -> (u64, ObjectDigest) {
        (self.catalog_generation, self.catalog_digest)
    }

    /// Returns the current Storage authority generation and digest.
    #[must_use]
    pub const fn authority(self) -> (u64, ObjectDigest) {
        (self.authority_generation, self.authority_digest)
    }

    /// Returns the current durable journal sequence and digest.
    #[must_use]
    pub const fn journal(self) -> (u64, ObjectDigest) {
        (self.journal_sequence, self.journal_digest)
    }

    /// Returns the digest of the exact physical GUID and hold readback.
    #[must_use]
    pub const fn physical_observation_digest(self) -> ObjectDigest {
        self.physical_observation_digest
    }
}

/// Binds one Provider attempt to its selected native row and Storage readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageZfsHoldReceiptV1 {
    provider_challenge: [u8; 32],
    provider_attempt_digest: ObjectDigest,
    binding_digest: ObjectDigest,
    resource: SourceResourceV1,
    snapshot: ZfsHeldSnapshotProofV1,
    head: StorageZfsHoldHeadV1,
    issued_seconds: i64,
    valid_until_seconds: i64,
}

impl StorageZfsHoldReceiptV1 {
    /// Constructs a bounded observation for an exact fresh Provider attempt.
    ///
    /// # Errors
    ///
    /// Rejects zero attempt fields or an invalid validity interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_challenge: [u8; 32],
        provider_attempt_digest: ObjectDigest,
        binding_digest: ObjectDigest,
        resource: SourceResourceV1,
        snapshot: ZfsHeldSnapshotProofV1,
        head: StorageZfsHoldHeadV1,
        issued_seconds: i64,
        valid_until_seconds: i64,
    ) -> Result<Self, StorageZfsHoldReceiptErrorV1> {
        if provider_challenge == [0; 32]
            || provider_attempt_digest.as_bytes() == &[0; 32]
            || binding_digest.as_bytes() == &[0; 32]
            || issued_seconds <= 0
            || valid_until_seconds <= issued_seconds
            || valid_until_seconds
                .checked_sub(issued_seconds)
                .is_none_or(|duration| duration > MAXIMUM_VALIDITY_SECONDS)
        {
            return Err(StorageZfsHoldReceiptErrorV1::Noncanonical);
        }
        Ok(Self {
            provider_challenge,
            provider_attempt_digest,
            binding_digest,
            resource,
            snapshot,
            head,
            issued_seconds,
            valid_until_seconds,
        })
    }

    /// Returns the Provider challenge and durable attempt commitment.
    #[must_use]
    pub const fn attempt(&self) -> ([u8; 32], ObjectDigest) {
        (self.provider_challenge, self.provider_attempt_digest)
    }

    /// Returns the exact logical binding selected under AOSPCZ01.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the exact selected Provider resource and catalog head.
    #[must_use]
    pub const fn resource(&self) -> &SourceResourceV1 {
        &self.resource
    }

    /// Returns the exact selected physical GUID, hold, and content claims.
    #[must_use]
    pub const fn snapshot(&self) -> &ZfsHeldSnapshotProofV1 {
        &self.snapshot
    }

    /// Returns the independently recovered Storage state and observation.
    #[must_use]
    pub const fn head(&self) -> StorageZfsHoldHeadV1 {
        self.head
    }

    /// Returns the inclusive issue and exclusive expiry second.
    #[must_use]
    pub const fn validity(&self) -> (i64, i64) {
        (self.issued_seconds, self.valid_until_seconds)
    }

    /// Encodes the exact unsigned receipt subject.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SUBJECT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.provider_challenge);
        bytes.extend_from_slice(self.provider_attempt_digest.as_bytes());
        bytes.extend_from_slice(self.binding_digest.as_bytes());
        for field in [
            self.resource
                .resource_namespace_digest()
                .as_bytes()
                .as_slice(),
            self.resource.resource_id().as_slice(),
            self.resource.resource_generation().to_be_bytes().as_slice(),
            self.resource.resource_digest().as_bytes().as_slice(),
            self.resource.catalog_generation().to_be_bytes().as_slice(),
            self.resource.catalog_digest().as_bytes().as_slice(),
            self.resource
                .selection_generation()
                .to_be_bytes()
                .as_slice(),
            self.resource.selection_digest().as_bytes().as_slice(),
            self.snapshot.storage_handle().as_slice(),
            self.snapshot.storage_version().to_be_bytes().as_slice(),
            self.snapshot.pool_guid().to_be_bytes().as_slice(),
            self.snapshot.dataset_guid().to_be_bytes().as_slice(),
            self.snapshot.snapshot_guid().to_be_bytes().as_slice(),
            self.snapshot.hold_id().as_slice(),
            self.snapshot.hold_generation().to_be_bytes().as_slice(),
            self.snapshot.active_hold_digest().as_bytes().as_slice(),
            self.snapshot.root_policy_digest().as_bytes().as_slice(),
            self.snapshot
                .read_only_content_digest()
                .as_bytes()
                .as_slice(),
            self.head.catalog_generation.to_be_bytes().as_slice(),
            self.head.catalog_digest.as_bytes().as_slice(),
            self.head.authority_generation.to_be_bytes().as_slice(),
            self.head.authority_digest.as_bytes().as_slice(),
            self.head.journal_sequence.to_be_bytes().as_slice(),
            self.head.journal_digest.as_bytes().as_slice(),
            self.head.physical_observation_digest.as_bytes().as_slice(),
            self.issued_seconds.to_be_bytes().as_slice(),
            self.valid_until_seconds.to_be_bytes().as_slice(),
        ] {
            bytes.extend_from_slice(field);
        }
        debug_assert_eq!(bytes.len(), SUBJECT_BYTES);
        bytes
    }

    /// Decodes exactly one canonical unsigned subject.
    ///
    /// # Errors
    ///
    /// Rejects invalid length, version, padding, or field values.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageZfsHoldReceiptErrorV1> {
        if bytes.len() != SUBJECT_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || bytes.get(10..16) != Some([0; 6].as_slice())
        {
            return Err(StorageZfsHoldReceiptErrorV1::Noncanonical);
        }
        let mut cursor = Cursor::new(&bytes[16..]);
        let challenge = cursor.take()?;
        let attempt = digest(&mut cursor)?;
        let binding = digest(&mut cursor)?;
        let resource = SourceResourceV1::new(
            digest(&mut cursor)?,
            cursor.take()?,
            cursor.u64()?,
            digest(&mut cursor)?,
            cursor.u64()?,
            digest(&mut cursor)?,
            cursor.u64()?,
            digest(&mut cursor)?,
        )
        .map_err(|_| StorageZfsHoldReceiptErrorV1::Noncanonical)?;
        let snapshot = ZfsHeldSnapshotProofV1::new(
            cursor.take()?,
            cursor.u64()?,
            cursor.u64()?,
            cursor.u64()?,
            cursor.u64()?,
            cursor.take()?,
            cursor.u64()?,
            digest(&mut cursor)?,
            digest(&mut cursor)?,
            digest(&mut cursor)?,
        )
        .map_err(|_| StorageZfsHoldReceiptErrorV1::Noncanonical)?;
        let head = StorageZfsHoldHeadV1::new(
            cursor.u64()?,
            digest(&mut cursor)?,
            cursor.u64()?,
            digest(&mut cursor)?,
            cursor.u64()?,
            digest(&mut cursor)?,
            digest(&mut cursor)?,
        )?;
        let receipt = Self::new(
            challenge,
            attempt,
            binding,
            resource,
            snapshot,
            head,
            cursor.i64()?,
            cursor.i64()?,
        )?;
        if cursor.done() && receipt.encode() == bytes {
            Ok(receipt)
        } else {
            Err(StorageZfsHoldReceiptErrorV1::Noncanonical)
        }
    }
}

/// Identifies a dedicated Storage ZFS hold signer and key generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageZfsHoldSignerV1 {
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: ObjectDigest,
    key_id: [u8; 16],
    key_generation: u64,
}

impl StorageZfsHoldSignerV1 {
    /// Constructs a non-sentinel signer for the ZFS hold receipt role.
    ///
    /// # Errors
    ///
    /// Rejects zero authority or key identities and generations.
    pub fn new(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: ObjectDigest,
        key_id: [u8; 16],
        key_generation: u64,
    ) -> Result<Self, StorageZfsHoldReceiptErrorV1> {
        if authority_id == [0; 16]
            || authority_generation == 0
            || authority_digest.as_bytes() == &[0; 32]
            || key_id == [0; 16]
            || key_generation == 0
        {
            return Err(StorageZfsHoldReceiptErrorV1::Noncanonical);
        }
        Ok(Self {
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
        })
    }

    /// Returns the Storage authority identity and generation.
    #[must_use]
    pub const fn authority(self) -> ([u8; 16], u64, ObjectDigest) {
        (
            self.authority_id,
            self.authority_generation,
            self.authority_digest,
        )
    }

    /// Returns the exact key identity and generation.
    #[must_use]
    pub const fn key(self) -> ([u8; 16], u64) {
        (self.key_id, self.key_generation)
    }

    fn encode(self) -> [u8; SIGNER_BYTES] {
        let mut bytes = [0; SIGNER_BYTES];
        bytes[..8].copy_from_slice(ROLE);
        bytes[8..24].copy_from_slice(&self.authority_id);
        bytes[24..32].copy_from_slice(&self.authority_generation.to_be_bytes());
        bytes[32..64].copy_from_slice(self.authority_digest.as_bytes());
        bytes[64..80].copy_from_slice(&self.key_id);
        bytes[80..88].copy_from_slice(&self.key_generation.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageZfsHoldReceiptErrorV1> {
        if bytes.len() != SIGNER_BYTES || bytes.get(..8) != Some(ROLE.as_slice()) {
            return Err(StorageZfsHoldReceiptErrorV1::Noncanonical);
        }
        let mut cursor = Cursor::new(&bytes[8..]);
        Self::new(
            cursor.take()?,
            cursor.u64()?,
            digest(&mut cursor)?,
            cursor.take()?,
            cursor.u64()?,
        )
    }
}

/// Carries an untrusted fixed-size Storage ZFS hold signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedStorageZfsHoldReceiptV1 {
    receipt: StorageZfsHoldReceiptV1,
    signer: StorageZfsHoldSignerV1,
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedStorageZfsHoldReceiptV1 {
    /// Collects one claimed signature over a complete Storage observation.
    #[must_use]
    pub const fn new(
        receipt: StorageZfsHoldReceiptV1,
        signer: StorageZfsHoldSignerV1,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Self {
        Self {
            receipt,
            signer,
            signature,
        }
    }

    /// Returns the unsigned observation for exact expected-tuple comparison.
    #[must_use]
    pub const fn receipt(&self) -> &StorageZfsHoldReceiptV1 {
        &self.receipt
    }

    /// Returns the claimed Storage signer projection.
    #[must_use]
    pub const fn signer(&self) -> StorageZfsHoldSignerV1 {
        self.signer
    }

    /// Returns the exact role-separated signing message.
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + SUBJECT_BYTES + SIGNER_BYTES);
        bytes.extend_from_slice(SIGNATURE_DOMAIN);
        bytes.extend_from_slice(&self.receipt.encode());
        bytes.extend_from_slice(&self.signer.encode());
        bytes
    }

    /// Encodes the sole canonical signed receipt representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.receipt.encode();
        bytes.extend_from_slice(&self.signer.encode());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Commits the exact signed bytes under the ZFS hold receipt domain.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(DIGEST_DOMAIN)
                .chain_update(self.encode())
                .finalize()
                .into(),
        )
    }

    /// Decodes an untrusted exact signed receipt.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, role, version, padding, or sentinel fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageZfsHoldReceiptErrorV1> {
        if bytes.len() != SIGNED_STORAGE_ZFS_HOLD_RECEIPT_BYTES_V1 {
            return Err(StorageZfsHoldReceiptErrorV1::Noncanonical);
        }
        let receipt = StorageZfsHoldReceiptV1::decode(&bytes[..SUBJECT_BYTES])?;
        let signer =
            StorageZfsHoldSignerV1::decode(&bytes[SUBJECT_BYTES..SUBJECT_BYTES + SIGNER_BYTES])?;
        let signature = bytes[SUBJECT_BYTES + SIGNER_BYTES..]
            .try_into()
            .map_err(|_| StorageZfsHoldReceiptErrorV1::Noncanonical)?;
        if signature == [0; SIGNATURE_BYTES] {
            return Err(StorageZfsHoldReceiptErrorV1::Noncanonical);
        }
        let signed = Self::new(receipt, signer, signature);
        if signed.encode() == bytes {
            Ok(signed)
        } else {
            Err(StorageZfsHoldReceiptErrorV1::Noncanonical)
        }
    }
}

/// Pins the independently provisioned ZFS hold signer and Ed25519 public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageZfsHoldVerifierV1 {
    signer: StorageZfsHoldSignerV1,
    public_key: [u8; 32],
}

impl StorageZfsHoldVerifierV1 {
    /// Validates a dedicated protected Storage ZFS hold verifier projection.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or weak Ed25519 public key.
    pub fn new(
        signer: StorageZfsHoldSignerV1,
        public_key: [u8; 32],
    ) -> Result<Self, StorageZfsHoldReceiptErrorV1> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| StorageZfsHoldReceiptErrorV1::Noncanonical)?;
        if key.is_weak() {
            return Err(StorageZfsHoldReceiptErrorV1::Noncanonical);
        }
        Ok(Self { signer, public_key })
    }

    /// Returns the exact pinned signer and public key for protected publication.
    #[must_use]
    pub const fn projection(self) -> (StorageZfsHoldSignerV1, [u8; 32]) {
        (self.signer, self.public_key)
    }

    /// Verifies a signature, bounded time, and the entire independently expected tuple.
    ///
    /// The caller must obtain `expected` from protected current state and a
    /// fresh durable attempt. Replaying a signed receipt with its own decoded
    /// subject as `expected` proves no currentness.
    ///
    /// # Errors
    ///
    /// Rejects a differing signer or subject, signature, or trusted time.
    pub fn verify_for(
        self,
        signed: &SignedStorageZfsHoldReceiptV1,
        expected: &StorageZfsHoldReceiptV1,
        now_seconds: i64,
    ) -> Result<(), StorageZfsHoldReceiptErrorV1> {
        if signed.signer != self.signer
            || signed.signer.authority_generation != signed.receipt.head.authority_generation
            || signed.signer.authority_digest != signed.receipt.head.authority_digest
        {
            return Err(StorageZfsHoldReceiptErrorV1::Signature);
        }
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| StorageZfsHoldReceiptErrorV1::Signature)?;
        key.verify_strict(
            &signed.signing_message(),
            &Signature::from_bytes(&signed.signature),
        )
        .map_err(|_| StorageZfsHoldReceiptErrorV1::Signature)?;
        if now_seconds < signed.receipt.issued_seconds
            || now_seconds >= signed.receipt.valid_until_seconds
        {
            return Err(StorageZfsHoldReceiptErrorV1::NotCurrent);
        }
        if signed.receipt != *expected {
            return Err(StorageZfsHoldReceiptErrorV1::Mismatch);
        }
        Ok(())
    }
}

fn digest(cursor: &mut Cursor<'_>) -> Result<ObjectDigest, StorageZfsHoldReceiptErrorV1> {
    Ok(ObjectDigest::from_bytes(cursor.take()?))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], StorageZfsHoldReceiptErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(StorageZfsHoldReceiptErrorV1::Noncanonical)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(StorageZfsHoldReceiptErrorV1::Noncanonical)?;
        self.offset = end;
        Ok(value)
    }

    fn u64(&mut self) -> Result<u64, StorageZfsHoldReceiptErrorV1> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn i64(&mut self) -> Result<i64, StorageZfsHoldReceiptErrorV1> {
        Ok(i64::from_be_bytes(self.take()?))
    }

    const fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn fixture() -> (
        SignedStorageZfsHoldReceiptV1,
        StorageZfsHoldVerifierV1,
        StorageZfsHoldReceiptV1,
    ) {
        let resource =
            SourceResourceV1::new(digest(1), [2; 32], 3, digest(4), 5, digest(6), 7, digest(8))
                .unwrap();
        let snapshot = ZfsHeldSnapshotProofV1::new(
            [9; 32],
            10,
            11,
            12,
            13,
            [14; 16],
            15,
            digest(16),
            digest(17),
            digest(18),
        )
        .unwrap();
        let head =
            StorageZfsHoldHeadV1::new(19, digest(20), 21, digest(22), 23, digest(24), digest(25))
                .unwrap();
        let receipt = StorageZfsHoldReceiptV1::new(
            [26; 32],
            digest(27),
            digest(28),
            resource,
            snapshot,
            head,
            100,
            150,
        )
        .unwrap();
        let signer = StorageZfsHoldSignerV1::new([29; 16], 21, digest(22), [30; 16], 31).unwrap();
        let key = SigningKey::from_bytes(&[32; 32]);
        let unsigned = SignedStorageZfsHoldReceiptV1::new(receipt.clone(), signer, [1; 64]);
        let signed = SignedStorageZfsHoldReceiptV1::new(
            receipt.clone(),
            signer,
            key.sign(&unsigned.signing_message()).to_bytes(),
        );
        let verifier =
            StorageZfsHoldVerifierV1::new(signer, key.verifying_key().to_bytes()).unwrap();
        (signed, verifier, receipt)
    }

    #[test]
    fn signed_hold_receipt_binds_selection_physical_hold_and_fresh_attempt() {
        let (signed, verifier, expected) = fixture();
        let bytes = signed.encode();
        assert_eq!(bytes.len(), SIGNED_STORAGE_ZFS_HOLD_RECEIPT_BYTES_V1);
        assert_eq!(
            SignedStorageZfsHoldReceiptV1::decode(&bytes),
            Ok(signed.clone())
        );
        assert_eq!(verifier.verify_for(&signed, &expected, 100), Ok(()));
        assert_eq!(verifier.verify_for(&signed, &expected, 149), Ok(()));
        assert_eq!(
            verifier.verify_for(&signed, &expected, 150),
            Err(StorageZfsHoldReceiptErrorV1::NotCurrent)
        );

        let mut altered = bytes.clone();
        altered[16 + 32 + 32 + 32 + 184 + 32 + 8 + 8 + 8] ^= 1;
        let altered = SignedStorageZfsHoldReceiptV1::decode(&altered).unwrap();
        assert_eq!(
            verifier.verify_for(&altered, &expected, 120),
            Err(StorageZfsHoldReceiptErrorV1::Signature)
        );
        assert_ne!(altered.digest(), signed.digest());

        let wrong_challenge = StorageZfsHoldReceiptV1::new(
            [33; 32],
            expected.provider_attempt_digest,
            expected.binding_digest,
            expected.resource.clone(),
            expected.snapshot.clone(),
            expected.head,
            100,
            150,
        )
        .unwrap();
        assert_eq!(
            verifier.verify_for(&signed, &wrong_challenge, 120),
            Err(StorageZfsHoldReceiptErrorV1::Mismatch)
        );
    }

    #[test]
    fn malformed_role_and_key_confusion_fail_closed() {
        let (signed, verifier, expected) = fixture();
        let mut bytes = signed.encode();
        bytes[SUBJECT_BYTES] ^= 1;
        assert_eq!(
            SignedStorageZfsHoldReceiptV1::decode(&bytes),
            Err(StorageZfsHoldReceiptErrorV1::Noncanonical)
        );
        let mut bytes = signed.encode();
        bytes[10] = 1;
        assert_eq!(
            SignedStorageZfsHoldReceiptV1::decode(&bytes),
            Err(StorageZfsHoldReceiptErrorV1::Noncanonical)
        );
        let wrong_signer =
            StorageZfsHoldSignerV1::new([34; 16], 21, digest(22), [30; 16], 31).unwrap();
        let wrong_verifier =
            StorageZfsHoldVerifierV1::new(wrong_signer, verifier.public_key).unwrap();
        assert_eq!(
            wrong_verifier.verify_for(&signed, &expected, 120),
            Err(StorageZfsHoldReceiptErrorV1::Signature)
        );
    }
}
