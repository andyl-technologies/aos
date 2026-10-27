//! Canonical Controller V8 evidence floor before Cache and Source release.
//!
//! The parent journal owns protected writer custody and idempotent commits.
//! This row preserves the exact held owner evidence seen after Root Released.
//!
//! ```text
//! AOSQ8F01 | version=1 | phase=owner-evidence-held | reserved[5]=0 |
//! binding[32] | epoch[8] | SHA-256(AOSQ8R01)[32] |
//! SHA-256(AOSPC88L)[32] | SHA-256(held AOSCPH01)[32] |
//! SHA-256(held AOSSDH01)[32] |
//! SHA-256(floor-domain || preceding 184 bytes)[32]
//! ```

use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::root_v8_receipt::RootV8EffectAckV1;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;

use super::{
    ControllerPolicyHoldV1, controller_v8_root_receipt_record_digest_v1, take_attempt,
    validate_held_owner_cut,
};

/// Names the canonical row key.
#[doc(hidden)]
pub const KEY: &[u8] = b"\0aos-controller-policy-v8-pre-release-floor-v1\0";
/// Separates native transaction hashes for this row.
#[doc(hidden)]
pub const TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-pre-release-floor-transaction.v1\0";
/// Bounds the complete checksummed record.
#[doc(hidden)]
pub const RECORD_BYTES: usize = 216;
const MAGIC: &[u8; 8] = b"AOSQ8F01";
/// Separates the record checksum from other formats.
#[doc(hidden)]
pub const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-v8-pre-release-floor.v1\0";

/// Freezes the exact Root Released and held owner cut before local release.
///
/// The floor is not a Root proof, release grant, successor admission, or Apply
/// capability. Its Root digest must originate from a peer-checked R8X proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyV8PreReleaseFloorV1 {
    /// Commits the proposed policy binding.
    pub binding: ObjectDigest,
    /// Names the policy handoff epoch.
    pub epoch: u64,
    /// Commits the Controller-wrapped Root ACK row.
    pub root_receipt: ObjectDigest,
    /// Commits the historical Root release marker.
    pub root_release_marker: ObjectDigest,
    /// Commits the held Cache row.
    pub cache_held: ObjectDigest,
    /// Commits the held Source row.
    pub source_held: ObjectDigest,
}

impl ControllerPolicyV8PreReleaseFloorV1 {
    /// Returns the Root release marker digest preserved before owner release.
    #[must_use]
    pub const fn root_release_marker_digest(self) -> ObjectDigest {
        self.root_release_marker
    }

    /// Returns the digest of the actual held Cache row.
    #[must_use]
    pub const fn cache_held_digest(self) -> ObjectDigest {
        self.cache_held
    }

    /// Returns the digest of the actual held Source row.
    #[must_use]
    pub const fn source_held_digest(self) -> ObjectDigest {
        self.source_held
    }

    /// Builds the evidence floor from matching held owners and a Root receipt.
    ///
    /// # Errors
    ///
    /// Rejects a changed held owner cut, mismatched Root identity, invalid receipt
    /// or zero evidence digests.
    pub fn from_held_rows(
        controller: ControllerPolicyHoldV1,
        receipt: RootV8EffectAckV1,
        root_release_marker: ObjectDigest,
        cache: CachePolicyHoldV1,
        source: SourceDomainPolicyHoldV1,
    ) -> Result<Self, MechanicalError> {
        validate_held_owner_cut(controller, cache, source)?;
        if receipt.binding() != controller.binding()
            || receipt.epoch() != controller.epoch()
            || receipt.operation() != controller.operation()
            || receipt.sandbox() != controller.sandbox()
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let floor = Self {
            binding: controller.binding(),
            epoch: controller.epoch(),
            root_receipt: controller_v8_root_receipt_record_digest_v1(receipt)?,
            root_release_marker,
            cache_held: cache
                .record_digest()
                .map_err(|_| MechanicalError::ProtectedBoundary)?,
            source_held: source
                .record_digest()
                .map_err(|_| MechanicalError::ProtectedBoundary)?,
        };
        floor.validate()?;
        Ok(floor)
    }

    /// Compares this floor with a Controller hold and Root receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if the compared Root receipt cannot be encoded.
    pub fn matches_chain(
        self,
        controller: ControllerPolicyHoldV1,
        receipt: RootV8EffectAckV1,
    ) -> Result<bool, MechanicalError> {
        Ok(self.binding == controller.binding()
            && self.epoch == controller.epoch()
            && self.root_receipt == controller_v8_root_receipt_record_digest_v1(receipt)?)
    }

    /// Checks the evidence floor identity and row digests.
    ///
    /// # Errors
    ///
    /// Rejects a zero binding, epoch, Root marker or owner evidence digest.
    pub fn validate(self) -> Result<(), MechanicalError> {
        if self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || [
                self.root_receipt,
                self.root_release_marker,
                self.cache_held,
                self.source_held,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Encodes the AOSQ8F01 held-owner evidence floor.
    ///
    /// # Errors
    ///
    /// Rejects a zero binding, epoch or evidence digest.
    pub fn encode(self) -> Result<[u8; RECORD_BYTES], MechanicalError> {
        self.validate()?;
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        for (index, digest) in [
            self.root_receipt,
            self.root_release_marker,
            self.cache_held,
            self.source_held,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[56 + index * 32..88 + index * 32].copy_from_slice(digest.as_bytes());
        }
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..184])
            .finalize();
        bytes[184..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes the AOSQ8F01 held-owner evidence floor.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, zero identity/evidence fields or a checksum mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, MechanicalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let digest = |offset| -> Result<ObjectDigest, MechanicalError> {
            Ok(ObjectDigest::from_bytes(take_attempt::<32>(bytes, offset)?))
        };
        let floor = Self {
            binding: digest(16)?,
            epoch: u64::from_be_bytes(take_attempt::<8>(bytes, 48)?),
            root_receipt: digest(56)?,
            root_release_marker: digest(88)?,
            cache_held: digest(120)?,
            source_held: digest(152)?,
        };
        if floor.encode()?.as_slice() != bytes {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(floor)
    }

    /// Returns the digest of the canonical durable floor row.
    ///
    /// # Errors
    ///
    /// Rejects malformed floor fields.
    pub fn record_digest(self) -> Result<ObjectDigest, MechanicalError> {
        Ok(digest_record(&self.encode()?))
    }

    /// Returns the exact canonical floor row for a challenged readback.
    ///
    /// # Errors
    ///
    /// Rejects malformed floor fields.
    pub fn record_bytes(self) -> Result<[u8; RECORD_BYTES], MechanicalError> {
        self.encode()
    }

    /// Parses one exact canonical floor row from a challenged readback.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, or corrupt floor bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, MechanicalError> {
        Self::decode(bytes)
    }
}

fn digest_record(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}
