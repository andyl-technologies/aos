//! Encodes the existing historical Source-writer challenge DATA.
//!
//! The fixed AOSSCW01 record describes a saved writer cut. Neither its fields,
//! decoder nor comparison authenticates a physical writer, issues a nonce,
//! acquires a receiving original or permits a held Source transition.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1;
use aos_sandbox_protocol::domain_ledger::{
    protected_names::ProtectedJournalNamesV1, source_policy_hold::SourceDomainPolicyHoldV1,
};
use sha2::{Digest as _, Sha256};

/// Names the existing fixed historical record field.
#[doc(hidden)]
pub const KEY: &[u8] = b"\0aos-source-domain-root-challenge-v1\0";
/// Names the existing fixed historical record field.
#[doc(hidden)]
pub const MAGIC: &[u8; 8] = b"AOSSCW01";
/// Names the existing fixed historical record field.
#[doc(hidden)]
pub const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.source-domain-root-challenge.v1\0";
/// Names the existing fixed historical record field.
#[doc(hidden)]
pub const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-domain-root-challenge-transaction.v1\0";
/// Names the existing fixed historical record field.
#[doc(hidden)]
pub const RECORD_BYTES: usize = 200;

/// Retains one Root challenge spent in the held Source writer journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDomainChallengeDataV1 {
    /// Retains the same historical comparison field without native authority.
    pub issue: u64,
    /// Retains the same historical comparison field without native authority.
    pub nonce: [u8; 16],
    /// Retains the same historical comparison field without native authority.
    pub cut: ObjectDigest,
    /// Retains the same historical comparison field without native authority.
    pub project: ProjectId,
    /// Retains the same historical comparison field without native authority.
    pub hold: ObjectDigest,
    /// Retains the same historical comparison field without native authority.
    pub names: ProtectedJournalNamesV1,
}

impl SourceDomainChallengeDataV1 {
    /// Returns this Source journal's monotone challenge issue number.
    #[must_use]
    pub const fn issue(self) -> u64 {
        self.issue
    }

    /// Returns the exact Root challenge nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the exact Root cut.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }

    /// Returns the held project whose ancestry the signer must replay.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the digest of the current held Source record.
    #[must_use]
    pub const fn hold(self) -> ObjectDigest {
        self.hold
    }

    /// Returns the directory, journal, and lock identities named by the writer.
    #[must_use]
    pub const fn names(self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the digest of the exact canonical challenge record.
    #[must_use]
    pub fn record_digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(Sha256::digest(self.encode()).into())
    }

    /// Compares the row to the signer's independently replayed held Source cut.
    ///
    /// # Errors
    ///
    /// Rejects an invalid held Source record.
    pub fn matches_current(
        self,
        nonce: [u8; 16],
        cut: ObjectDigest,
        project: ProjectId,
        hold: SourceDomainPolicyHoldV1,
        names: ProtectedJournalNamesV1,
    ) -> Result<bool, ProtectedHistoryDataErrorV1> {
        Ok(self.nonce == nonce
            && self.cut == cut
            && self.project == project
            && self.hold == hold.record_digest()?
            && self.names == names
            && hold.is_held())
    }

    /// Encodes the same fixed canonical historical record.
    pub fn encode(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.issue.to_be_bytes());
        bytes[24..40].copy_from_slice(&self.nonce);
        bytes[40..72].copy_from_slice(self.cut.as_bytes());
        bytes[72..88].copy_from_slice(self.project.as_bytes());
        bytes[88..120].copy_from_slice(self.hold.as_bytes());
        bytes[120..168].copy_from_slice(&self.names.to_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..168])
            .finalize();
        bytes[168..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes the exact historical fixed record without native authority.
    ///
    /// # Errors
    /// Refuses noncanonical bytes, zero fields or a mismatched checksum.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
            || bytes[168..]
                != Sha256::new()
                    .chain_update(CHECKSUM_DOMAIN)
                    .chain_update(&bytes[..168])
                    .finalize()[..]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let row = Self {
            issue: u64::from_be_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            nonce: bytes[24..40]
                .try_into()
                .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            cut: ObjectDigest::from_bytes(
                bytes[40..72]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            project: ProjectId::from_bytes(
                bytes[72..88]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            hold: ObjectDigest::from_bytes(
                bytes[88..120]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            names: ProtectedJournalNamesV1::from_bytes(&bytes[120..168])?,
        };
        if row.issue == 0
            || row.nonce == [0; 16]
            || row.cut.as_bytes() == &[0; 32]
            || row.project.as_bytes() == &[0; 16]
            || row.hold.as_bytes() == &[0; 32]
            || row.encode().as_slice() != bytes
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(row)
    }
}
