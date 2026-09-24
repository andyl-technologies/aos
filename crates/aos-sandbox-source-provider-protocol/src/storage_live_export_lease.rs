//! Canonical Storage authority for one LocalLive export lease.
//!
//! The Storage lease names the mutable, assignment-bound workspace origin. A
//! separate kernel-grant owner creates and attests the read-only native clone;
//! its unique mount ID therefore cannot appear in this earlier lease.
//!
//! ```text
//! AOSSLE01 | version:u16be=1 | reserved[6]=0 |
//! source-assignment-digest[32] | owner-sandbox[16] | source-incarnation[16] |
//! export-id[16] | export-generation:u64be | export-revocation-digest[32] |
//! workspace-id[32] | workspace-digest[32] | origin-boot-id[16] |
//! origin-device:u64be | origin-inode:u64be | origin-unique-mount-id:u64be |
//! acquisition-id[32] | effect-id[16] | consumer-authority-id[16] |
//! consumer-generation:u64be | lease-id[16] | lease-generation:u64be |
//! issued-seconds:i64be | valid-until-seconds:i64be |
//! signer-authority-id[16] | signer-authority-generation:u64be |
//! signer-authority-digest[32] | signer-key-id[16] |
//! signer-key-generation:u64be | ed25519-signature[64]
//! ```
//!
//! The signature covers a domain-separated message containing all bytes before
//! the signature. The lease digest covers the entire signed record. A caller
//! must pin the verifier independently and recheck Storage's physical origin;
//! decoding or verifying these bytes alone grants no backend effect authority.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::model::MAXIMUM_SOURCE_LEASE_SECONDS;

const MAGIC: &[u8; 8] = b"AOSSLE01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 16;
const SOURCE_BYTES: usize = 224;
const CONSUMER_BYTES: usize = 112;
const SIGNER_BYTES: usize = 80;
const SIGNATURE_BYTES: usize = 64;
const LEASE_BYTES: usize = HEADER_BYTES + SOURCE_BYTES + CONSUMER_BYTES;
const SIGNED_BYTES: usize = LEASE_BYTES + SIGNER_BYTES + SIGNATURE_BYTES;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-lease.signature.v1\0";
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-lease.digest.v1\0";

/// Reports malformed, unauthenticated, or expired Storage lease bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageLiveExportLeaseErrorV1 {
    /// A field, size, version, or reserved byte is invalid.
    #[error("Storage live-export lease is noncanonical")]
    Noncanonical,
    /// The signer does not match the protected verifier or its signature fails.
    #[error("Storage live-export lease signature is invalid")]
    Signature,
    /// The bounded lease is not current at the verifier's trusted time.
    #[error("Storage live-export lease is not current")]
    NotCurrent,
}

/// Names the exact authenticated workspace origin and logical export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLiveExportSourceV1 {
    source_assignment_digest: ObjectDigest,
    owner_sandbox: [u8; 16],
    source_incarnation: [u8; 16],
    export_id: [u8; 16],
    export_generation: u64,
    export_revocation_digest: ObjectDigest,
    workspace_id: [u8; 32],
    workspace_digest: ObjectDigest,
    origin_boot_id: [u8; 16],
    origin_device: u64,
    origin_inode: u64,
    origin_mount_id: u64,
}

impl StorageLiveExportSourceV1 {
    /// Constructs one complete assignment, export, and physical-origin tuple.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportLeaseErrorV1::Noncanonical`] for any sentinel
    /// identity, digest, generation, or kernel object number.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_assignment_digest: ObjectDigest,
        owner_sandbox: [u8; 16],
        source_incarnation: [u8; 16],
        export_id: [u8; 16],
        export_generation: u64,
        export_revocation_digest: ObjectDigest,
        workspace_id: [u8; 32],
        workspace_digest: ObjectDigest,
        origin_boot_id: [u8; 16],
        origin_device: u64,
        origin_inode: u64,
        origin_mount_id: u64,
    ) -> Result<Self, StorageLiveExportLeaseErrorV1> {
        if source_assignment_digest.as_bytes() == &[0; 32]
            || owner_sandbox == [0; 16]
            || source_incarnation == [0; 16]
            || export_id == [0; 16]
            || export_generation == 0
            || export_revocation_digest.as_bytes() == &[0; 32]
            || workspace_id == [0; 32]
            || workspace_digest.as_bytes() == &[0; 32]
            || origin_boot_id == [0; 16]
            || origin_device == 0
            || origin_inode == 0
            || origin_mount_id == 0
        {
            return Err(StorageLiveExportLeaseErrorV1::Noncanonical);
        }
        Ok(Self {
            source_assignment_digest,
            owner_sandbox,
            source_incarnation,
            export_id,
            export_generation,
            export_revocation_digest,
            workspace_id,
            workspace_digest,
            origin_boot_id,
            origin_device,
            origin_inode,
            origin_mount_id,
        })
    }

    /// Returns the source assignment commitment.
    #[must_use]
    pub const fn source_assignment_digest(self) -> ObjectDigest {
        self.source_assignment_digest
    }

    /// Returns the source owner sandbox.
    #[must_use]
    pub const fn owner_sandbox(self) -> [u8; 16] {
        self.owner_sandbox
    }

    /// Returns the source incarnation.
    #[must_use]
    pub const fn source_incarnation(self) -> [u8; 16] {
        self.source_incarnation
    }

    /// Returns the logical export identity.
    #[must_use]
    pub const fn export_id(self) -> [u8; 16] {
        self.export_id
    }

    /// Returns the generation fencing replacement of the logical export.
    #[must_use]
    pub const fn export_generation(self) -> u64 {
        self.export_generation
    }

    /// Returns the current export revocation-state commitment.
    #[must_use]
    pub const fn export_revocation_digest(self) -> ObjectDigest {
        self.export_revocation_digest
    }

    /// Returns Storage's opaque workspace handle.
    #[must_use]
    pub const fn workspace_id(self) -> [u8; 32] {
        self.workspace_id
    }

    /// Returns the complete current Storage workspace observation commitment.
    #[must_use]
    pub const fn workspace_digest(self) -> ObjectDigest {
        self.workspace_digest
    }

    /// Returns the boot in which the mutable origin mount was observed.
    #[must_use]
    pub const fn origin_boot_id(self) -> [u8; 16] {
        self.origin_boot_id
    }

    /// Returns the origin root's kernel device identity.
    #[must_use]
    pub const fn origin_device(self) -> u64 {
        self.origin_device
    }

    /// Returns the origin root's kernel inode identity.
    #[must_use]
    pub const fn origin_inode(self) -> u64 {
        self.origin_inode
    }

    /// Returns the origin's non-recycled kernel mount identity.
    #[must_use]
    pub const fn origin_mount_id(self) -> u64 {
        self.origin_mount_id
    }
}

/// Fences one consumer and effect to a finite Storage lease lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLiveExportConsumerV1 {
    acquisition_id: ObjectDigest,
    effect_id: [u8; 16],
    consumer_authority_id: [u8; 16],
    consumer_generation: u64,
    lease_id: [u8; 16],
    lease_generation: u64,
    issued_seconds: i64,
    valid_until_seconds: i64,
}

impl StorageLiveExportConsumerV1 {
    /// Constructs a bounded one-effect consumer lease.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportLeaseErrorV1::Noncanonical`] for a sentinel
    /// identity or an empty or overlong validity interval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        acquisition_id: ObjectDigest,
        effect_id: [u8; 16],
        consumer_authority_id: [u8; 16],
        consumer_generation: u64,
        lease_id: [u8; 16],
        lease_generation: u64,
        issued_seconds: i64,
        valid_until_seconds: i64,
    ) -> Result<Self, StorageLiveExportLeaseErrorV1> {
        if acquisition_id.as_bytes() == &[0; 32]
            || effect_id == [0; 16]
            || consumer_authority_id == [0; 16]
            || consumer_generation == 0
            || lease_id == [0; 16]
            || lease_generation == 0
            || issued_seconds <= 0
            || valid_until_seconds <= issued_seconds
            || valid_until_seconds
                .checked_sub(issued_seconds)
                .is_none_or(|duration| duration > MAXIMUM_SOURCE_LEASE_SECONDS as i64)
        {
            return Err(StorageLiveExportLeaseErrorV1::Noncanonical);
        }
        Ok(Self {
            acquisition_id,
            effect_id,
            consumer_authority_id,
            consumer_generation,
            lease_id,
            lease_generation,
            issued_seconds,
            valid_until_seconds,
        })
    }

    /// Returns the stable SourceProvider acquisition identity.
    #[must_use]
    pub const fn acquisition_id(self) -> ObjectDigest {
        self.acquisition_id
    }

    /// Returns the reserved SourceProvider effect identity.
    #[must_use]
    pub const fn effect_id(self) -> [u8; 16] {
        self.effect_id
    }

    /// Returns the consumer authority identity and generation.
    #[must_use]
    pub const fn consumer_authority(self) -> ([u8; 16], u64) {
        (self.consumer_authority_id, self.consumer_generation)
    }

    /// Returns Storage's non-recycled lease identity.
    #[must_use]
    pub const fn lease_id(self) -> [u8; 16] {
        self.lease_id
    }

    /// Returns the monotonic lease generation.
    #[must_use]
    pub const fn lease_generation(self) -> u64 {
        self.lease_generation
    }

    /// Returns the first accepted wall-clock second.
    #[must_use]
    pub const fn issued_seconds(self) -> i64 {
        self.issued_seconds
    }

    /// Returns the exclusive wall-clock expiry second.
    #[must_use]
    pub const fn valid_until_seconds(self) -> i64 {
        self.valid_until_seconds
    }
}

/// Joins a protected Storage source and exact consumer effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLiveExportLeaseV1 {
    source: StorageLiveExportSourceV1,
    consumer: StorageLiveExportConsumerV1,
}

impl StorageLiveExportLeaseV1 {
    /// Constructs one nonauthorizing lease statement.
    #[must_use]
    pub const fn new(
        source: StorageLiveExportSourceV1,
        consumer: StorageLiveExportConsumerV1,
    ) -> Self {
        Self { source, consumer }
    }

    /// Returns the observed source and logical export.
    #[must_use]
    pub const fn source(self) -> StorageLiveExportSourceV1 {
        self.source
    }

    /// Returns the consumer effect and finite lease lifetime.
    #[must_use]
    pub const fn consumer(self) -> StorageLiveExportConsumerV1 {
        self.consumer
    }

    /// Encodes the exact unsigned Storage lease statement.
    #[must_use]
    pub fn encode(self) -> [u8; LEASE_BYTES] {
        let mut bytes = [0; LEASE_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        let mut cursor = 16;
        for field in [
            self.source.source_assignment_digest.as_bytes().as_slice(),
            self.source.owner_sandbox.as_slice(),
            self.source.source_incarnation.as_slice(),
            self.source.export_id.as_slice(),
            self.source.export_generation.to_be_bytes().as_slice(),
            self.source.export_revocation_digest.as_bytes().as_slice(),
            self.source.workspace_id.as_slice(),
            self.source.workspace_digest.as_bytes().as_slice(),
            self.source.origin_boot_id.as_slice(),
            self.source.origin_device.to_be_bytes().as_slice(),
            self.source.origin_inode.to_be_bytes().as_slice(),
            self.source.origin_mount_id.to_be_bytes().as_slice(),
            self.consumer.acquisition_id.as_bytes().as_slice(),
            self.consumer.effect_id.as_slice(),
            self.consumer.consumer_authority_id.as_slice(),
            self.consumer.consumer_generation.to_be_bytes().as_slice(),
            self.consumer.lease_id.as_slice(),
            self.consumer.lease_generation.to_be_bytes().as_slice(),
            self.consumer.issued_seconds.to_be_bytes().as_slice(),
            self.consumer.valid_until_seconds.to_be_bytes().as_slice(),
        ] {
            bytes[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        }
        bytes
    }

    /// Decodes an exact unsigned lease statement.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportLeaseErrorV1::Noncanonical`] for malformed
    /// length, version, padding, or field values.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageLiveExportLeaseErrorV1> {
        if bytes.len() != LEASE_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || bytes.get(10..16) != Some([0_u8; 6].as_slice())
        {
            return Err(StorageLiveExportLeaseErrorV1::Noncanonical);
        }
        let mut cursor = Cursor::new(&bytes[HEADER_BYTES..]);
        let source = StorageLiveExportSourceV1::new(
            ObjectDigest::from_bytes(cursor.take()?),
            cursor.take()?,
            cursor.take()?,
            cursor.take()?,
            cursor.u64()?,
            ObjectDigest::from_bytes(cursor.take()?),
            cursor.take()?,
            ObjectDigest::from_bytes(cursor.take()?),
            cursor.take()?,
            cursor.u64()?,
            cursor.u64()?,
            cursor.u64()?,
        )?;
        let consumer = StorageLiveExportConsumerV1::new(
            ObjectDigest::from_bytes(cursor.take()?),
            cursor.take()?,
            cursor.take()?,
            cursor.u64()?,
            cursor.take()?,
            cursor.u64()?,
            cursor.i64()?,
            cursor.i64()?,
        )?;
        let lease = Self { source, consumer };
        if cursor.done() && lease.encode().as_slice() == bytes {
            Ok(lease)
        } else {
            Err(StorageLiveExportLeaseErrorV1::Noncanonical)
        }
    }
}

/// Names the StorageExport authority and exact signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLiveExportSignerV1 {
    authority_id: [u8; 16],
    authority_generation: u64,
    authority_digest: ObjectDigest,
    key_id: [u8; 16],
    key_generation: u64,
}

impl StorageLiveExportSignerV1 {
    /// Constructs one non-sentinel signer projection.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportLeaseErrorV1::Noncanonical`] for a sentinel
    /// authority or key identity.
    pub fn new(
        authority_id: [u8; 16],
        authority_generation: u64,
        authority_digest: ObjectDigest,
        key_id: [u8; 16],
        key_generation: u64,
    ) -> Result<Self, StorageLiveExportLeaseErrorV1> {
        if authority_id == [0; 16]
            || authority_generation == 0
            || authority_digest.as_bytes() == &[0; 32]
            || key_id == [0; 16]
            || key_generation == 0
        {
            return Err(StorageLiveExportLeaseErrorV1::Noncanonical);
        }
        Ok(Self {
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
        })
    }

    /// Returns the authority identity, generation, and state commitment.
    #[must_use]
    pub const fn authority(self) -> ([u8; 16], u64, ObjectDigest) {
        (
            self.authority_id,
            self.authority_generation,
            self.authority_digest,
        )
    }

    /// Returns the signing key identity and generation.
    #[must_use]
    pub const fn key(self) -> ([u8; 16], u64) {
        (self.key_id, self.key_generation)
    }

    fn encode(self) -> [u8; SIGNER_BYTES] {
        let mut bytes = [0; SIGNER_BYTES];
        bytes[..16].copy_from_slice(&self.authority_id);
        bytes[16..24].copy_from_slice(&self.authority_generation.to_be_bytes());
        bytes[24..56].copy_from_slice(self.authority_digest.as_bytes());
        bytes[56..72].copy_from_slice(&self.key_id);
        bytes[72..80].copy_from_slice(&self.key_generation.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageLiveExportLeaseErrorV1> {
        if bytes.len() != SIGNER_BYTES {
            return Err(StorageLiveExportLeaseErrorV1::Noncanonical);
        }
        Self::new(
            bytes[..16]
                .try_into()
                .map_err(|_| StorageLiveExportLeaseErrorV1::Noncanonical)?,
            u64::from_be_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| StorageLiveExportLeaseErrorV1::Noncanonical)?,
            ),
            ObjectDigest::from_bytes(
                bytes[24..56]
                    .try_into()
                    .map_err(|_| StorageLiveExportLeaseErrorV1::Noncanonical)?,
            ),
            bytes[56..72]
                .try_into()
                .map_err(|_| StorageLiveExportLeaseErrorV1::Noncanonical)?,
            u64::from_be_bytes(
                bytes[72..80]
                    .try_into()
                    .map_err(|_| StorageLiveExportLeaseErrorV1::Noncanonical)?,
            ),
        )
    }
}

/// Carries untrusted signed Storage lease bytes for independent verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedStorageLiveExportLeaseV1 {
    lease: StorageLiveExportLeaseV1,
    signer: StorageLiveExportSignerV1,
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedStorageLiveExportLeaseV1 {
    /// Collects one untrusted Storage signature over an exact lease statement.
    #[must_use]
    pub const fn new(
        lease: StorageLiveExportLeaseV1,
        signer: StorageLiveExportSignerV1,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Self {
        Self {
            lease,
            signer,
            signature,
        }
    }

    /// Returns the nonauthorizing lease statement.
    #[must_use]
    pub const fn lease(self) -> StorageLiveExportLeaseV1 {
        self.lease
    }

    /// Returns the claimed Storage signer projection.
    #[must_use]
    pub const fn signer(self) -> StorageLiveExportSignerV1 {
        self.signer
    }

    /// Returns the domain-separated exact signing message.
    #[must_use]
    pub fn signing_message(self) -> Vec<u8> {
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + LEASE_BYTES + SIGNER_BYTES);
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&self.lease.encode());
        message.extend_from_slice(&self.signer.encode());
        message
    }

    /// Encodes the exact signed record.
    #[must_use]
    pub fn encode(self) -> [u8; SIGNED_BYTES] {
        let mut bytes = [0; SIGNED_BYTES];
        bytes[..LEASE_BYTES].copy_from_slice(&self.lease.encode());
        bytes[LEASE_BYTES..LEASE_BYTES + SIGNER_BYTES].copy_from_slice(&self.signer.encode());
        bytes[LEASE_BYTES + SIGNER_BYTES..].copy_from_slice(&self.signature);
        bytes
    }

    /// Returns the commitment used by the SourceProvider proof and kernel grant.
    #[must_use]
    pub fn digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(DIGEST_DOMAIN)
                .chain_update(self.encode())
                .finalize()
                .into(),
        )
    }

    /// Decodes an exact signed record without granting signature authority.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportLeaseErrorV1::Noncanonical`] for an invalid
    /// length, header, field, or sentinel signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageLiveExportLeaseErrorV1> {
        if bytes.len() != SIGNED_BYTES {
            return Err(StorageLiveExportLeaseErrorV1::Noncanonical);
        }
        let lease = StorageLiveExportLeaseV1::decode(&bytes[..LEASE_BYTES])?;
        let signer =
            StorageLiveExportSignerV1::decode(&bytes[LEASE_BYTES..LEASE_BYTES + SIGNER_BYTES])?;
        let signature = bytes[LEASE_BYTES + SIGNER_BYTES..]
            .try_into()
            .map_err(|_| StorageLiveExportLeaseErrorV1::Noncanonical)?;
        if signature == [0; SIGNATURE_BYTES] {
            return Err(StorageLiveExportLeaseErrorV1::Noncanonical);
        }
        let signed = Self::new(lease, signer, signature);
        if signed.encode().as_slice() == bytes {
            Ok(signed)
        } else {
            Err(StorageLiveExportLeaseErrorV1::Noncanonical)
        }
    }
}

/// Pins one independently obtained StorageExport verifier key and identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageLiveExportVerifierV1 {
    signer: StorageLiveExportSignerV1,
    public_key: [u8; 32],
}

impl StorageLiveExportVerifierV1 {
    /// Validates a protected StorageExport verifier projection.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportLeaseErrorV1::Noncanonical`] for an invalid
    /// or weak Ed25519 public key.
    pub fn new(
        signer: StorageLiveExportSignerV1,
        public_key: [u8; 32],
    ) -> Result<Self, StorageLiveExportLeaseErrorV1> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| StorageLiveExportLeaseErrorV1::Noncanonical)?;
        if key.is_weak() {
            return Err(StorageLiveExportLeaseErrorV1::Noncanonical);
        }
        Ok(Self { signer, public_key })
    }

    /// Authenticates one exact lease against the pinned key and trusted time.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportLeaseErrorV1::Signature`] for a mismatched
    /// signer or signature, and [`StorageLiveExportLeaseErrorV1::NotCurrent`]
    /// outside the lease's bounded validity interval.
    pub fn verify(
        self,
        signed: SignedStorageLiveExportLeaseV1,
        now_seconds: i64,
    ) -> Result<(), StorageLiveExportLeaseErrorV1> {
        if signed.signer != self.signer {
            return Err(StorageLiveExportLeaseErrorV1::Signature);
        }
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| StorageLiveExportLeaseErrorV1::Signature)?;
        key.verify_strict(
            &signed.signing_message(),
            &Signature::from_bytes(&signed.signature),
        )
        .map_err(|_| StorageLiveExportLeaseErrorV1::Signature)?;
        let consumer = signed.lease.consumer;
        if now_seconds < consumer.issued_seconds || now_seconds >= consumer.valid_until_seconds {
            return Err(StorageLiveExportLeaseErrorV1::NotCurrent);
        }
        Ok(())
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], StorageLiveExportLeaseErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(StorageLiveExportLeaseErrorV1::Noncanonical)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(StorageLiveExportLeaseErrorV1::Noncanonical)?;
        self.offset = end;
        Ok(result)
    }

    fn u64(&mut self) -> Result<u64, StorageLiveExportLeaseErrorV1> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn i64(&mut self) -> Result<i64, StorageLiveExportLeaseErrorV1> {
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

    fn digest(value: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([value; 32])
    }

    fn signed_lease() -> (SignedStorageLiveExportLeaseV1, StorageLiveExportVerifierV1) {
        let source = StorageLiveExportSourceV1::new(
            digest(1),
            [2; 16],
            [3; 16],
            [4; 16],
            5,
            digest(6),
            [7; 32],
            digest(8),
            [9; 16],
            10,
            11,
            12,
        )
        .unwrap();
        let consumer = StorageLiveExportConsumerV1::new(
            digest(13),
            [14; 16],
            [15; 16],
            16,
            [17; 16],
            18,
            100,
            200,
        )
        .unwrap();
        let lease = StorageLiveExportLeaseV1::new(source, consumer);
        let signer =
            StorageLiveExportSignerV1::new([19; 16], 20, digest(21), [22; 16], 23).unwrap();
        let key = SigningKey::from_bytes(&[24; 32]);
        let unsigned = SignedStorageLiveExportLeaseV1::new(lease, signer, [1; 64]);
        let signature = key.sign(&unsigned.signing_message()).to_bytes();
        let signed = SignedStorageLiveExportLeaseV1::new(lease, signer, signature);
        let verifier =
            StorageLiveExportVerifierV1::new(signer, key.verifying_key().to_bytes()).unwrap();
        (signed, verifier)
    }

    #[test]
    fn signed_lease_round_trips_and_binds_every_field() {
        let (signed, verifier) = signed_lease();
        let bytes = signed.encode();
        assert_eq!(bytes.len(), SIGNED_BYTES);
        assert_eq!(SignedStorageLiveExportLeaseV1::decode(&bytes), Ok(signed));
        assert_eq!(
            StorageLiveExportLeaseV1::decode(&bytes[..LEASE_BYTES]),
            Ok(signed.lease())
        );
        assert!(verifier.verify(signed, 100).is_ok());
        assert!(verifier.verify(signed, 199).is_ok());
        assert_eq!(
            verifier.verify(signed, 200),
            Err(StorageLiveExportLeaseErrorV1::NotCurrent)
        );

        let mut changed = bytes;
        changed[16 + 32 + 16 + 16 + 16 + 7] ^= 1;
        let changed = SignedStorageLiveExportLeaseV1::decode(&changed).unwrap();
        assert_eq!(
            verifier.verify(changed, 150),
            Err(StorageLiveExportLeaseErrorV1::Signature)
        );
        assert_ne!(changed.digest(), signed.digest());
    }

    #[test]
    fn malformed_and_wrong_verifier_lease_fail_closed() {
        let (signed, verifier) = signed_lease();
        let mut bytes = signed.encode();
        bytes[10] = 1;
        assert_eq!(
            SignedStorageLiveExportLeaseV1::decode(&bytes),
            Err(StorageLiveExportLeaseErrorV1::Noncanonical)
        );

        let mut bytes = signed.encode();
        bytes[LEASE_BYTES + SIGNER_BYTES..].fill(0);
        assert_eq!(
            SignedStorageLiveExportLeaseV1::decode(&bytes),
            Err(StorageLiveExportLeaseErrorV1::Noncanonical)
        );

        let wrong_signer =
            StorageLiveExportSignerV1::new([25; 16], 20, digest(21), [22; 16], 23).unwrap();
        let wrong_verifier =
            StorageLiveExportVerifierV1::new(wrong_signer, verifier.public_key).unwrap();
        assert_eq!(
            wrong_verifier.verify(signed, 150),
            Err(StorageLiveExportLeaseErrorV1::Signature)
        );
    }
}
