//! Canonical whole-tree identity requirement for Storage Clone catalogs.
//!
//! ```text
//! AOSCIR01 | version:u16 | identity-profile:u16 | coverage-mask:u32
//! source-snapshot-guid:u64 | source-metadata-record-digest:32
//! maximum-portable-uid:u32 | maximum-portable-gid:u32
//! distinct-inode-count:u64 | directory-entry-count:u64
//! identity-tree-digest:32
//! ```

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::snapshot_metadata::{CheckedSnapshotMetadataRecordV1, IDENTITY_COVERAGE_MASK};

const MAGIC: &[u8; 8] = b"AOSCIR01";
const VERSION: u16 = 1;
const IDENTITY_PROFILE: u16 = 1;
const RECORD_BYTES: usize = 112;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.clone-identity-requirement.v1\0";

/// Reports malformed or inconsistent Clone identity requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CloneIdentityRequirementError {
    /// A GUID, digest, count, or portable identity bound uses a reserved value.
    #[error("Clone identity requirement contains a reserved value")]
    InvalidValue,
    /// The requirement selects an unsupported identity interpretation profile.
    #[error("Clone identity requirement profile is unsupported")]
    UnsupportedIdentityProfile,
    /// The requirement omits a mandatory identity-bearing feature.
    #[error("Clone identity requirement coverage is incomplete")]
    IncompleteIdentityCoverage,
    /// The requirement differs from its authenticated source metadata.
    #[error("Clone identity requirement does not match source metadata")]
    InconsistentSourceMetadata,
    /// Canonical bytes have the wrong length, magic, or shape.
    #[error("Clone identity requirement encoding is malformed or noncanonical")]
    MalformedEncoding,
    /// Canonical bytes use an unsupported format version.
    #[error("Clone identity requirement encoding version is unsupported")]
    UnsupportedEncodingVersion,
}

/// Commits the exhaustive source identity summary required by one Clone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CloneIdentityRequirementV1 {
    source_snapshot_guid: u64,
    source_metadata_record_digest: ObjectDigest,
    maximum_portable_uid: u32,
    maximum_portable_gid: u32,
    distinct_inode_count: u64,
    directory_entry_count: u64,
    identity_tree_digest: ObjectDigest,
}

impl CloneIdentityRequirementV1 {
    /// Derives a Clone requirement from one authenticated metadata record.
    pub(crate) fn from_snapshot_metadata(metadata: &CheckedSnapshotMetadataRecordV1) -> Self {
        Self {
            source_snapshot_guid: metadata.snapshot_guid(),
            source_metadata_record_digest: metadata.record_digest(),
            maximum_portable_uid: metadata.maximum_portable_uid(),
            maximum_portable_gid: metadata.maximum_portable_gid(),
            distinct_inode_count: metadata.distinct_inode_count(),
            directory_entry_count: metadata.directory_entry_count(),
            identity_tree_digest: metadata.identity_tree_digest(),
        }
    }

    /// Reconstructs the requirement from its exact canonical representation.
    ///
    /// # Errors
    ///
    /// Returns [`CloneIdentityRequirementError`] for malformed, noncanonical,
    /// unsupported, or invalid bytes.
    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, CloneIdentityRequirementError> {
        if bytes.len() != RECORD_BYTES || &bytes[..8] != MAGIC {
            return Err(CloneIdentityRequirementError::MalformedEncoding);
        }
        if u16::from_be_bytes(array(bytes, 8)?) != VERSION {
            return Err(CloneIdentityRequirementError::UnsupportedEncodingVersion);
        }
        if u16::from_be_bytes(array(bytes, 10)?) != IDENTITY_PROFILE {
            return Err(CloneIdentityRequirementError::UnsupportedIdentityProfile);
        }
        if u32::from_be_bytes(array(bytes, 12)?) != IDENTITY_COVERAGE_MASK {
            return Err(CloneIdentityRequirementError::IncompleteIdentityCoverage);
        }
        let requirement = Self {
            source_snapshot_guid: u64::from_be_bytes(array(bytes, 16)?),
            source_metadata_record_digest: ObjectDigest::from_bytes(array(bytes, 24)?),
            maximum_portable_uid: u32::from_be_bytes(array(bytes, 56)?),
            maximum_portable_gid: u32::from_be_bytes(array(bytes, 60)?),
            distinct_inode_count: u64::from_be_bytes(array(bytes, 64)?),
            directory_entry_count: u64::from_be_bytes(array(bytes, 72)?),
            identity_tree_digest: ObjectDigest::from_bytes(array(bytes, 80)?),
        };
        requirement.validate()?;
        if requirement.canonical_bytes() != bytes {
            return Err(CloneIdentityRequirementError::MalformedEncoding);
        }
        Ok(requirement)
    }

    /// Encodes the exact AOSCIR01 requirement.
    pub(crate) fn canonical_bytes(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&IDENTITY_PROFILE.to_be_bytes());
        bytes[12..16].copy_from_slice(&IDENTITY_COVERAGE_MASK.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.source_snapshot_guid.to_be_bytes());
        bytes[24..56].copy_from_slice(self.source_metadata_record_digest.as_bytes());
        bytes[56..60].copy_from_slice(&self.maximum_portable_uid.to_be_bytes());
        bytes[60..64].copy_from_slice(&self.maximum_portable_gid.to_be_bytes());
        bytes[64..72].copy_from_slice(&self.distinct_inode_count.to_be_bytes());
        bytes[72..80].copy_from_slice(&self.directory_entry_count.to_be_bytes());
        bytes[80..112].copy_from_slice(self.identity_tree_digest.as_bytes());
        bytes
    }

    /// Returns the domain-separated digest retained by execution preparation.
    pub(crate) fn commitment(self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.canonical_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    /// Requires this summary to have been derived from the given metadata.
    ///
    /// # Errors
    ///
    /// Returns [`CloneIdentityRequirementError::InconsistentSourceMetadata`]
    /// when any committed source field differs.
    pub(crate) fn validate_source_metadata(
        self,
        metadata: &CheckedSnapshotMetadataRecordV1,
    ) -> Result<(), CloneIdentityRequirementError> {
        if self == Self::from_snapshot_metadata(metadata) {
            Ok(())
        } else {
            Err(CloneIdentityRequirementError::InconsistentSourceMetadata)
        }
    }

    /// Returns the exact immutable source snapshot GUID.
    pub(crate) const fn source_snapshot_guid(self) -> u64 {
        self.source_snapshot_guid
    }
    /// Returns the digest of the authenticated AOSSMT01 source record.
    pub(crate) const fn source_metadata_record_digest(self) -> ObjectDigest {
        self.source_metadata_record_digest
    }
    /// Returns the greatest UID committed by the source traversal.
    pub(crate) const fn maximum_portable_uid(self) -> u32 {
        self.maximum_portable_uid
    }
    /// Returns the greatest GID committed by the source traversal.
    pub(crate) const fn maximum_portable_gid(self) -> u32 {
        self.maximum_portable_gid
    }
    /// Returns the source traversal's distinct-inode count.
    pub(crate) const fn distinct_inode_count(self) -> u64 {
        self.distinct_inode_count
    }
    /// Returns the source traversal's entries below the root.
    ///
    /// An otherwise empty source tree has zero entries and one distinct inode.
    pub(crate) const fn directory_entry_count(self) -> u64 {
        self.directory_entry_count
    }
    /// Returns the source traversal's canonical identity-tree digest.
    pub(crate) const fn identity_tree_digest(self) -> ObjectDigest {
        self.identity_tree_digest
    }

    fn validate(self) -> Result<(), CloneIdentityRequirementError> {
        if self.source_snapshot_guid == 0
            || self.source_metadata_record_digest.as_bytes() == &[0; 32]
            || self.maximum_portable_uid == u32::MAX
            || self.maximum_portable_gid == u32::MAX
            || self.distinct_inode_count == 0
            || self.identity_tree_digest.as_bytes() == &[0; 32]
        {
            Err(CloneIdentityRequirementError::InvalidValue)
        } else {
            Ok(())
        }
    }
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CloneIdentityRequirementError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(CloneIdentityRequirementError::MalformedEncoding)
}
