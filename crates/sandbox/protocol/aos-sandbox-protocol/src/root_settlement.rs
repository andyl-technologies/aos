//! Canonical Root V8 successor-settlement record DATA.
//!
//! ```text
//! AOSPC88S | version:u16=1 | reserved[6]=0 | predecessor[32] | epoch:u64 |
//! next-epoch:u64 | Controller-settlement[32] | Root-release[32] |
//! Cache-release[32] | Source-release[32] | signed-receipt[32] | checksum[32]
//! ```
//!
//! Canonical fields and a checksum establish only record shape. Native issuer
//! custody and the fixed contacted peer remain separate requirements.

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

/// Names the fixed Root policy-authority endpoint.
pub const POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2: &str =
    "/run/aos/sandbox-policy-authority/current-head.sock";

const MAGIC: &[u8; 8] = b"AOSPC88S";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.root-v8-successor-settlement.v1\0";
const RECORD_BYTES: usize = 256;

/// Reports invalid canonical settlement fields or framing.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum RootV8SettlementDataErrorV1 {
    /// Rejects malformed, nonconsecutive, zero or checksum-invalid fields.
    #[error("compiled policy candidate lacks authenticated publication authority")]
    UnauthenticatedCandidate,
}

/// Carries the canonical settlement record without native custody or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootV8SuccessorSettlementV1 {
    /// Identifies the predecessor whose release is recorded.
    pub predecessor: ObjectDigest,
    /// Names the predecessor handoff epoch.
    pub epoch: u64,
    /// Names the required consecutive successor epoch.
    pub next_epoch: u64,
    /// Commits the Controller settlement record.
    pub settlement: ObjectDigest,
    /// Commits the Root release marker.
    pub release_marker: ObjectDigest,
    /// Commits the released Cache hold.
    pub cache_released: ObjectDigest,
    /// Commits the released Source hold.
    pub source_released: ObjectDigest,
    /// Commits the signed Controller receipt.
    pub signed_receipt: ObjectDigest,
}

impl RootV8SuccessorSettlementV1 {
    /// Returns the released predecessor binding.
    #[must_use]
    pub const fn predecessor(self) -> ObjectDigest {
        self.predecessor
    }

    /// Returns the predecessor handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the next permitted Root epoch.
    #[must_use]
    pub const fn next_epoch(self) -> u64 {
        self.next_epoch
    }

    /// Returns the canonical Controller AOSQ8S01 digest.
    #[must_use]
    pub const fn settlement(self) -> ObjectDigest {
        self.settlement
    }

    /// Returns the canonical Root AOSPC88L digest.
    #[must_use]
    pub const fn release_marker(self) -> ObjectDigest {
        self.release_marker
    }

    /// Returns the exact released Cache hold digest.
    #[must_use]
    pub const fn cache_released(self) -> ObjectDigest {
        self.cache_released
    }

    /// Returns the exact released Source hold digest.
    #[must_use]
    pub const fn source_released(self) -> ObjectDigest {
        self.source_released
    }

    /// Returns the digest of the signed Controller settlement receipt.
    #[must_use]
    pub const fn signed_receipt(self) -> ObjectDigest {
        self.signed_receipt
    }

    /// Encodes the canonical Root settlement for a future fixed Root signer.
    ///
    /// # Errors
    ///
    /// Rejects invalid predecessor epochs or zero evidence digests.
    pub fn record_bytes(self) -> Result<[u8; RECORD_BYTES], RootV8SettlementDataErrorV1> {
        self.encode()
    }

    /// Decodes the exact canonical Root settlement record.
    ///
    /// # Errors
    ///
    /// Rejects malformed fields or a changed checksum.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, RootV8SettlementDataErrorV1> {
        Self::decode(bytes)
    }

    fn encode(self) -> Result<[u8; RECORD_BYTES], RootV8SettlementDataErrorV1> {
        if self.predecessor.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.next_epoch
                != self
                    .epoch
                    .checked_add(1)
                    .ok_or(RootV8SettlementDataErrorV1::UnauthenticatedCandidate)?
            || [
                self.settlement,
                self.release_marker,
                self.cache_released,
                self.source_released,
                self.signed_receipt,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(RootV8SettlementDataErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(self.predecessor.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.next_epoch.to_be_bytes());
        for (index, digest) in [
            self.settlement,
            self.release_marker,
            self.cache_released,
            self.source_released,
            self.signed_receipt,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 64 + index * 32;
            bytes[offset..offset + 32].copy_from_slice(digest.as_bytes());
        }
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..224])
            .finalize();
        bytes[224..256].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RootV8SettlementDataErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(RootV8SettlementDataErrorV1::UnauthenticatedCandidate);
        }
        let digest = |offset: usize| -> Result<ObjectDigest, RootV8SettlementDataErrorV1> {
            Ok(ObjectDigest::from_bytes(
                bytes[offset..offset + 32]
                    .try_into()
                    .map_err(|_| RootV8SettlementDataErrorV1::UnauthenticatedCandidate)?,
            ))
        };
        let settlement = Self {
            predecessor: digest(16)?,
            epoch: u64::from_be_bytes(
                bytes[48..56]
                    .try_into()
                    .map_err(|_| RootV8SettlementDataErrorV1::UnauthenticatedCandidate)?,
            ),
            next_epoch: u64::from_be_bytes(
                bytes[56..64]
                    .try_into()
                    .map_err(|_| RootV8SettlementDataErrorV1::UnauthenticatedCandidate)?,
            ),
            settlement: digest(64)?,
            release_marker: digest(96)?,
            cache_released: digest(128)?,
            source_released: digest(160)?,
            signed_receipt: digest(192)?,
        };
        if settlement.encode()?.as_slice() != bytes {
            return Err(RootV8SettlementDataErrorV1::UnauthenticatedCandidate);
        }
        Ok(settlement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_settlement_record_rejects_changed_owner_or_release_digests() {
        let marker = RootV8SuccessorSettlementV1 {
            predecessor: ObjectDigest::from_bytes([1; 32]),
            epoch: 2,
            next_epoch: 3,
            settlement: ObjectDigest::from_bytes([4; 32]),
            release_marker: ObjectDigest::from_bytes([5; 32]),
            cache_released: ObjectDigest::from_bytes([6; 32]),
            source_released: ObjectDigest::from_bytes([7; 32]),
            signed_receipt: ObjectDigest::from_bytes([8; 32]),
        };
        let encoded = marker.record_bytes().unwrap();
        assert_eq!(
            RootV8SuccessorSettlementV1::from_record_bytes(&encoded).unwrap(),
            marker,
        );
        for offset in [0, 8, 16, 48, 56, 64, 96, 128, 160, 192, 224] {
            let mut changed = encoded;
            changed[offset] ^= 1;
            assert!(RootV8SuccessorSettlementV1::from_record_bytes(&changed).is_err());
        }
    }
}
