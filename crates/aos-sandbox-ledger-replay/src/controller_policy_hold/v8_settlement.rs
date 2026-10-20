//! Canonical Controller V8 owner-release evidence and local settlement row.
//!
//! The parent journal owns writer custody, atomic commits, and replay gates.
//! This module owns the AOSQ8S01 codec and comparison of typed owner readbacks.
//!
//! ```text
//! AOSQ8S01 | version=1 | phase=owner-releases-recorded | reserved[5]=0 |
//! binding[32] | epoch[8] | SHA-256(AOSQ8A01)[32] |
//! SHA-256(AOSQ8K01)[32] | SHA-256(AOSQ8R01)[32] |
//! SHA-256(AOSPC88L)[32] | SHA-256(released AOSCPH01)[32] |
//! SHA-256(released AOSSDH01)[32] | SHA-256(released AOSCTH01)[32] |
//! SHA-256(settlement-domain || preceding 280 bytes)[32]
//! ```

use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::root_v8_receipt::RootV8EffectAckV1;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;

use super::{
    ControllerPolicyHoldV1, ControllerPolicyV8AttemptV1, ControllerPolicyV8EffectAckV1,
    V8_SETTLEMENT_CHECKSUM_DOMAIN, V8_SETTLEMENT_MAGIC, V8_SETTLEMENT_RECORD_BYTES,
    encode_v8_root_receipt, take_attempt, v8_root_receipt_matches_ack, validate_held_owner_cut,
};

/// Retains typed owner readbacks for one local V8 release transition.
///
/// This value does not authenticate Root by itself. Only a peer-checked R8X
/// Root Released proof may supply `root_release_marker` to a future caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyV8ReleaseEvidenceV1 {
    /// Commits the historical Root release marker.
    pub root_release_marker: ObjectDigest,
    /// Records the held Cache evidence.
    pub cache_held: CachePolicyHoldV1,
    /// Records the released Cache evidence.
    pub cache_released: CachePolicyHoldV1,
    /// Records the held Source evidence.
    pub source_held: SourceDomainPolicyHoldV1,
    /// Records the released Source evidence.
    pub source_released: SourceDomainPolicyHoldV1,
}

impl ControllerPolicyV8ReleaseEvidenceV1 {
    /// Binds exact held and released owner rows before local Controller release.
    ///
    /// # Errors
    ///
    /// Rejects a missing Root marker or a changed Cache, Source, or Controller cut.
    pub fn new(
        controller: ControllerPolicyHoldV1,
        root_release_marker: ObjectDigest,
        cache_held: CachePolicyHoldV1,
        cache_released: CachePolicyHoldV1,
        source_held: SourceDomainPolicyHoldV1,
        source_released: SourceDomainPolicyHoldV1,
    ) -> Result<Self, MechanicalError> {
        let evidence = Self {
            root_release_marker,
            cache_held,
            cache_released,
            source_held,
            source_released,
        };
        evidence.validate_for(controller)?;
        Ok(evidence)
    }

    /// Checks that owner release rows preserve their held identities.
    ///
    /// # Errors
    ///
    /// Rejects mismatched held owners, a missing Root marker, still-held release rows
    /// or changed Cache/Source identities.
    pub fn validate_for(self, controller: ControllerPolicyHoldV1) -> Result<(), MechanicalError> {
        validate_held_owner_cut(controller, self.cache_held, self.source_held)?;
        if self.root_release_marker.as_bytes() == &[0; 32]
            || self.cache_released.is_held()
            || self.cache_held.project() != self.cache_released.project()
            || self.cache_held.partition() != self.cache_released.partition()
            || self.cache_held.cache_head() != self.cache_released.cache_head()
            || self.cache_held.binding() != self.cache_released.binding()
            || self.cache_held.epoch() != self.cache_released.epoch()
            || self.source_released.is_held()
            || self.source_held.operation() != self.source_released.operation()
            || self.source_held.sandbox() != self.source_released.sandbox()
            || self.source_held.controller_source() != self.source_released.controller_source()
            || self.source_held.ancestry() != self.source_released.ancestry()
            || self.source_held.binding() != self.source_released.binding()
            || self.source_held.epoch() != self.source_released.epoch()
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(())
    }
}

/// Records owner releases under Controller custody pending Root settlement.
///
/// This row is not a signed Root successor grant or an Apply capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerPolicyV8SettlementV1 {
    /// Commits the proposed policy binding.
    pub binding: ObjectDigest,
    /// Names the policy handoff epoch.
    pub epoch: u64,
    /// Commits the terminal attempt row.
    pub attempt: ObjectDigest,
    /// Commits the Controller no-Apply ACK row.
    pub ack: ObjectDigest,
    /// Commits the Controller-wrapped Root ACK row.
    pub root_receipt: ObjectDigest,
    /// Commits the historical Root release marker.
    pub root_release_marker: ObjectDigest,
    /// Commits the released Cache row.
    pub cache_released: ObjectDigest,
    /// Commits the released Source row.
    pub source_released: ObjectDigest,
    /// Commits the released Controller hold row.
    pub controller_released: ObjectDigest,
}

impl ControllerPolicyV8SettlementV1 {
    /// Returns the settled Root binding identity.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the settled Root binding epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the digest of the accepted V8 attempt row.
    #[must_use]
    pub const fn attempt_digest(self) -> ObjectDigest {
        self.attempt
    }

    /// Returns the digest of the accepted V8 effect ACK row.
    #[must_use]
    pub const fn ack_digest(self) -> ObjectDigest {
        self.ack
    }

    /// Returns the digest of the historical Root ACK receipt row.
    #[must_use]
    pub const fn root_receipt_digest(self) -> ObjectDigest {
        self.root_receipt
    }

    /// Returns the digest of Root's exact AOSPC88L release marker.
    #[must_use]
    pub const fn root_release_marker_digest(self) -> ObjectDigest {
        self.root_release_marker
    }

    /// Returns the digest of the released Cache hold row.
    #[must_use]
    pub const fn cache_released_digest(self) -> ObjectDigest {
        self.cache_released
    }

    /// Returns the digest of the released Source hold row.
    #[must_use]
    pub const fn source_released_digest(self) -> ObjectDigest {
        self.source_released
    }

    /// Returns the digest of the released Controller hold row.
    #[must_use]
    pub const fn controller_released_digest(self) -> ObjectDigest {
        self.controller_released
    }

    /// Builds a settlement from a released hold and its ACK/receipt chain.
    ///
    /// # Errors
    ///
    /// Rejects a held Controller row, mismatched attempt or receipt, malformed chain
    /// fields or zero release evidence digests.
    pub fn from_chain(
        released: ControllerPolicyHoldV1,
        attempt: ControllerPolicyV8AttemptV1,
        ack: ControllerPolicyV8EffectAckV1,
        root_receipt: RootV8EffectAckV1,
        root_release_marker: ObjectDigest,
        cache_released: ObjectDigest,
        source_released: ObjectDigest,
    ) -> Result<Self, MechanicalError> {
        if released.is_held()
            || attempt.hold()
                != (ControllerPolicyHoldV1 {
                    held: true,
                    ..released
                })
            || ack.attempt() != attempt
            || !v8_root_receipt_matches_ack(root_receipt, ack)?
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let settlement = Self {
            binding: released.binding(),
            epoch: released.epoch(),
            attempt: digest_record(&attempt.encode()?),
            ack: ack.record_digest()?,
            root_receipt: digest_record(&encode_v8_root_receipt(root_receipt)?),
            root_release_marker,
            cache_released,
            source_released,
            controller_released: digest_record(&released.encode()?),
        };
        settlement.validate()?;
        Ok(settlement)
    }

    /// Checks the settlement identity and evidence digests.
    ///
    /// # Errors
    ///
    /// Rejects a zero binding, epoch or evidence digest.
    pub fn validate(self) -> Result<(), MechanicalError> {
        if self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || [
                self.attempt,
                self.ack,
                self.root_receipt,
                self.root_release_marker,
                self.cache_released,
                self.source_released,
                self.controller_released,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Encodes the AOSQ8S01 local settlement row.
    ///
    /// # Errors
    ///
    /// Rejects a zero binding, epoch or evidence digest.
    pub fn encode(self) -> Result<[u8; V8_SETTLEMENT_RECORD_BYTES], MechanicalError> {
        self.validate()?;
        let mut bytes = [0; V8_SETTLEMENT_RECORD_BYTES];
        bytes[..8].copy_from_slice(V8_SETTLEMENT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        for (offset, digest) in [
            self.attempt,
            self.ack,
            self.root_receipt,
            self.root_release_marker,
            self.cache_released,
            self.source_released,
            self.controller_released,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[56 + offset * 32..88 + offset * 32].copy_from_slice(digest.as_bytes());
        }
        let checksum = Sha256::new()
            .chain_update(V8_SETTLEMENT_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..280])
            .finalize();
        bytes[280..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes the AOSQ8S01 local settlement row.
    ///
    /// # Errors
    ///
    /// Rejects wrong framing, zero identity/evidence fields or a checksum mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, MechanicalError> {
        if bytes.len() != V8_SETTLEMENT_RECORD_BYTES
            || bytes.get(..8) != Some(V8_SETTLEMENT_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let digest = |offset| -> Result<ObjectDigest, MechanicalError> {
            Ok(ObjectDigest::from_bytes(take_attempt::<32>(bytes, offset)?))
        };
        let settlement = Self {
            binding: digest(16)?,
            epoch: u64::from_be_bytes(take_attempt::<8>(bytes, 48)?),
            attempt: digest(56)?,
            ack: digest(88)?,
            root_receipt: digest(120)?,
            root_release_marker: digest(152)?,
            cache_released: digest(184)?,
            source_released: digest(216)?,
            controller_released: digest(248)?,
        };
        if settlement.encode()?.as_slice() != bytes {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(settlement)
    }

    /// Returns the digest of the canonical local settlement row.
    ///
    /// # Errors
    ///
    /// Rejects malformed local settlement fields.
    pub fn record_digest(self) -> Result<ObjectDigest, MechanicalError> {
        Ok(digest_record(&self.encode()?))
    }

    /// Returns the exact canonical settlement row for a challenged readback.
    ///
    /// # Errors
    ///
    /// Rejects malformed local settlement fields.
    pub fn record_bytes(self) -> Result<[u8; 312], MechanicalError> {
        self.encode()
    }

    /// Parses one exact canonical settlement row from a challenged readback.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, or corrupt settlement bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, MechanicalError> {
        Self::decode(bytes)
    }
}

fn digest_record(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}
