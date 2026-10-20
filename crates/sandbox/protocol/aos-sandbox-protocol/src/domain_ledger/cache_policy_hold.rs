//! Owns established policy-hold record DATA without native writer authority.
//!
//! These codecs preserve the original physical bytes and canonical checks.
//! Held/released values are comparison DATA: mutation, currentness, signing,
//! Root grants and protected writer disposition stay with actual native owners.

//! The canonical record retains its established layout:
//!
//! ```text
//! AOSCPH01 | version:u16 | held/released:u8 | reserved:5 |
//! project:16 | partition:32 | cache-head:32 | binding:32 |
//! epoch:u64 | domain-separated SHA256:32
//! ```
//!
use aos_sandbox_model::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};
use super::ProtectedHistoryDataErrorV1;

const MAGIC: &[u8; 8] = b"AOSCPH01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.cache-policy-hold.v1\0";
const RECORD_BYTES: usize = 168;

/// Identifies one exact, nonauthorizing protected Cache policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePolicyHoldV1 {
    project: ProjectId,
    partition: ObjectDigest,
    cache_head: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
    held: bool,
}

impl CachePolicyHoldV1 {
    /// Returns the same fields with the held phase as comparison DATA.
    ///
    /// Native writer membership and mutation authority remain independent.
    #[must_use]
    pub const fn held_data(self) -> Self {
        Self { held: true, ..self }
    }

    /// Returns the same fields with the released phase as comparison DATA.
    ///
    /// This cannot release a writer, clear a gate or create a current loan.
    #[must_use]
    pub const fn released_data(self) -> Self {
        Self { held: false, ..self }
    }

    /// Constructs canonical comparison DATA for the exact proposed Cache cut.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities and a zero epoch.
    pub fn new(
        project: ProjectId,
        partition: ObjectDigest,
        cache_head: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let hold = Self {
            project,
            partition,
            cache_head,
            binding,
            epoch,
            held: true,
        };
        hold.validate()?;
        Ok(hold)
    }

    /// Returns the held project.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the held physical partition digest.
    #[must_use]
    pub const fn partition(self) -> ObjectDigest {
        self.partition
    }

    /// Returns the exact protected Cache replay head.
    #[must_use]
    pub const fn cache_head(self) -> ObjectDigest {
        self.cache_head
    }

    /// Returns the proposed root binding digest.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the proposed root handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether this record encodes the held phase.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    /// Returns the digest of the exact canonical held or released record.
    ///
    /// # Errors
    ///
    /// Rejects invalid Cache hold fields.
    pub fn record_digest(self) -> Result<ObjectDigest, ProtectedHistoryDataErrorV1> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    // Comparison DATA from the same canonical hold encoder. Actual native
    // membership and the original owner loan still prove any live release.
    /// Returns canonical released-record comparison DATA for this same hold.
    ///
    /// This neither releases a writer nor proves a native transition.
    ///
    /// # Errors
    /// Rejects invalid canonical hold fields.
    pub fn q04_released_record_digest(self) -> Result<ObjectDigest, ProtectedHistoryDataErrorV1> {
        Self { held: false, ..self }.record_digest()
    }

    /// Checks canonical identity DATA without native custody or admission.
    ///
    /// # Errors
    /// Rejects the existing reserved identity or epoch sentinels.
    pub fn validate(self) -> Result<(), ProtectedHistoryDataErrorV1> {
        if self.project.as_bytes() == &[0; 16]
            || self.partition.as_bytes() == &[0; 32]
            || self.cache_head.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }

    /// Encodes the exact established canonical record as nonauthorizing DATA.
    ///
    /// # Errors
    /// Rejects fields that fail the existing canonical record constraints.
    pub fn encode(self) -> Result<[u8; RECORD_BYTES], ProtectedHistoryDataErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = if self.held { 1 } else { 2 };
        bytes[16..32].copy_from_slice(self.project.as_bytes());
        bytes[32..64].copy_from_slice(self.partition.as_bytes());
        bytes[64..96].copy_from_slice(self.cache_head.as_bytes());
        bytes[96..128].copy_from_slice(self.binding.as_bytes());
        bytes[128..136].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..136])
            .finalize();
        bytes[136..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes exact established bytes without proving native membership.
    ///
    /// # Errors
    /// Rejects malformed fields, reserved bytes, phase, version or checksum.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let hold = Self {
            project: ProjectId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            partition: ObjectDigest::from_bytes(
                bytes[32..64]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            cache_head: ObjectDigest::from_bytes(
                bytes[64..96]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[96..128]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[128..136]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            held: bytes[10] == 1,
        };
        if hold.encode()?.as_slice() != bytes {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(hold)
    }
}
