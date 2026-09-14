//! Canonical whole-tree identity metadata for immutable Storage snapshots.
//!
//! The record commits the exact Snapshot request and ZFS observation to an
//! exhaustive, portable identity traversal. It deliberately excludes the
//! broker-minted version handle: that handle depends on the result catalog,
//! while this record contributes to that catalog's transition digest.
//!
//! ```text
//! AOSSMT01 | version:u16 | identity-profile:u16 | coverage-mask:u32
//! snapshot-operation-id:16 | request-digest:32 | mutation-digest:32
//! request-catalog:(generation:u64,digest:32)
//! snapshot-guid:u64 | source-dataset-guid:u64 | source-storage-handle:32
//! source-creation-operation-id:16 | source-publication-record-digest:32
//! source-pin-attempt-id:16 | source-pin-record-digest:32
//! raw-zfs-observation-digest:32
//! root:(uid:u32,gid:u32,mode:u16,reserved:u16)
//! maximum-portable:(uid:u32,gid:u32) | reserved:u32
//! distinct-inode-count:u64 | directory-entry-count:u64
//! identity-tree-digest:32
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::semantics::CatalogBindingV1;
use sha2::{Digest as _, Sha256};

use crate::root_policy::PortableRootAttributesV1;

const MAGIC: &[u8; 8] = b"AOSSMT01";
const VERSION: u16 = 1;
const IDENTITY_PROFILE: u16 = 1;
const RECORD_BYTES: usize = 384;
const RECORD_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.snapshot-metadata-record.v1\0";
const COMMIT_OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.storage.snapshot-commit-observation.v1\0";

const COVER_INODE_OWNER_IDS: u32 = 1 << 0;
const COVER_ACCESS_ACL_IDENTITIES: u32 = 1 << 1;
const COVER_DEFAULT_ACL_IDENTITIES: u32 = 1 << 2;
const COVER_CAPABILITY_ROOT_ID: u32 = 1 << 3;
const REJECT_UNSUPPORTED_IDENTITY_ACLS: u32 = 1 << 4;
pub(crate) const IDENTITY_COVERAGE_MASK: u32 = COVER_INODE_OWNER_IDS
    | COVER_ACCESS_ACL_IDENTITIES
    | COVER_DEFAULT_ACL_IDENTITIES
    | COVER_CAPABILITY_ROOT_ID
    | REJECT_UNSUPPORTED_IDENTITY_ACLS;

/// Reports malformed or incomplete immutable-snapshot identity metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SnapshotMetadataError {
    /// An identifier, digest, GUID, or count uses a reserved zero value.
    #[error("snapshot identity metadata contains a reserved value")]
    InvalidValue,
    /// Portable root attributes are malformed or outside their summary.
    #[error("snapshot identity metadata has invalid root attributes")]
    InvalidRootAttributes,
    /// The record selects an unsupported identity interpretation profile.
    #[error("snapshot identity metadata profile is unsupported")]
    UnsupportedIdentityProfile,
    /// The observer did not cover every required identity-bearing feature.
    #[error("snapshot identity metadata coverage is incomplete")]
    IncompleteIdentityCoverage,
    /// Root identities or traversal counts contradict the whole-tree summary.
    #[error("snapshot identity metadata summary is inconsistent")]
    InconsistentIdentitySummary,
    /// Canonical bytes have the wrong length, magic, reserved fields, or shape.
    #[error("snapshot identity metadata encoding is malformed or noncanonical")]
    MalformedEncoding,
    /// Canonical bytes use an unsupported format version.
    #[error("snapshot identity metadata encoding version is unsupported")]
    UnsupportedEncodingVersion,
}

/// Collects checked inputs for one immutable-snapshot metadata record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SnapshotMetadataRecordPartsV1 {
    /// Identifies the exact Snapshot transaction.
    pub(crate) operation_id: [u8; 16],
    /// Commits the authenticated Apply request.
    pub(crate) request_digest: ObjectDigest,
    /// Commits the exact ZFS mutation program.
    pub(crate) mutation_digest: ObjectDigest,
    /// Identifies the resolved request catalog.
    pub(crate) request_catalog: CatalogBindingV1,
    /// Identifies the immutable snapshot observed after mutation.
    pub(crate) snapshot_guid: u64,
    /// Identifies the snapshot's exact source dataset.
    pub(crate) source_dataset_guid: u64,
    /// Identifies the source dataset through its opaque durable handle.
    pub(crate) source_storage_handle: [u8; 32],
    /// Identifies the committed Create or Clone that produced the source.
    pub(crate) source_creation_operation_id: [u8; 16],
    /// Authenticates the source workspace's durable publication record.
    pub(crate) source_publication_record_digest: ObjectDigest,
    /// Identifies the satisfied historical pin used for source custody.
    pub(crate) source_pin_attempt_id: [u8; 16],
    /// Authenticates the selected pin-attempt record.
    pub(crate) source_pin_record_digest: ObjectDigest,
    /// Commits the raw exact ZFS postcondition observation.
    pub(crate) zfs_observation_digest: ObjectDigest,
    /// Retains the portable root attributes included in the tree digest.
    pub(crate) root_attributes: PortableRootAttributesV1,
    /// Bounds every UID observed in the immutable tree.
    pub(crate) maximum_portable_uid: u32,
    /// Bounds every GID observed in the immutable tree.
    pub(crate) maximum_portable_gid: u32,
    /// Counts distinct inode identities visited by the traversal.
    pub(crate) distinct_inode_count: u64,
    /// Counts canonical directory entries incorporated into the traversal.
    pub(crate) directory_entry_count: u64,
    /// Commits the canonical exhaustive identity traversal.
    pub(crate) identity_tree_digest: ObjectDigest,
}

/// Stores a canonically checked whole-tree identity observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CheckedSnapshotMetadataRecordV1 {
    parts: SnapshotMetadataRecordPartsV1,
}

impl CheckedSnapshotMetadataRecordV1 {
    /// Validates and constructs one complete metadata record.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotMetadataError`] when any identity, digest, GUID,
    /// portable-ID bound, root attribute, or traversal count is invalid.
    pub(crate) fn new(parts: SnapshotMetadataRecordPartsV1) -> Result<Self, SnapshotMetadataError> {
        if parts.operation_id == [0; 16]
            || parts.request_digest.as_bytes() == &[0; 32]
            || parts.mutation_digest.as_bytes() == &[0; 32]
            || parts.request_catalog.generation() == 0
            || parts.request_catalog.digest().as_bytes() == &[0; 32]
            || parts.snapshot_guid == 0
            || parts.source_dataset_guid == 0
            || parts.source_storage_handle == [0; 32]
            || parts.source_creation_operation_id == [0; 16]
            || parts.source_publication_record_digest.as_bytes() == &[0; 32]
            || parts.source_pin_attempt_id == [0; 16]
            || parts.source_pin_record_digest.as_bytes() == &[0; 32]
            || parts.zfs_observation_digest.as_bytes() == &[0; 32]
            || parts.identity_tree_digest.as_bytes() == &[0; 32]
            || parts.distinct_inode_count == 0
        {
            return Err(SnapshotMetadataError::InvalidValue);
        }
        if parts.root_attributes.validate().is_err()
            || parts.maximum_portable_uid == u32::MAX
            || parts.maximum_portable_gid == u32::MAX
        {
            return Err(SnapshotMetadataError::InvalidRootAttributes);
        }
        if parts.root_attributes.uid() > parts.maximum_portable_uid
            || parts.root_attributes.gid() > parts.maximum_portable_gid
        {
            return Err(SnapshotMetadataError::InconsistentIdentitySummary);
        }

        Ok(Self { parts })
    }

    /// Reconstructs a record from the sole exact 384-byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotMetadataError`] for malformed, noncanonical, or
    /// unsupported bytes and for invalid decoded field values.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SnapshotMetadataError> {
        if bytes.len() != RECORD_BYTES || &bytes[..8] != MAGIC {
            return Err(SnapshotMetadataError::MalformedEncoding);
        }
        if u16::from_be_bytes(array(bytes, 8)?) != VERSION {
            return Err(SnapshotMetadataError::UnsupportedEncodingVersion);
        }
        if u16::from_be_bytes(array(bytes, 10)?) != IDENTITY_PROFILE {
            return Err(SnapshotMetadataError::UnsupportedIdentityProfile);
        }
        if u32::from_be_bytes(array(bytes, 12)?) != IDENTITY_COVERAGE_MASK {
            return Err(SnapshotMetadataError::IncompleteIdentityCoverage);
        }
        if bytes[322..324] != [0, 0] || bytes[332..336] != [0, 0, 0, 0] {
            return Err(SnapshotMetadataError::MalformedEncoding);
        }

        let request_catalog = CatalogBindingV1::from_publisher(
            u64::from_be_bytes(array(bytes, 96)?),
            ObjectDigest::from_bytes(array(bytes, 104)?),
        )
        .map_err(|_| SnapshotMetadataError::InvalidValue)?;
        let parts = SnapshotMetadataRecordPartsV1 {
            operation_id: array(bytes, 16)?,
            request_digest: ObjectDigest::from_bytes(array(bytes, 32)?),
            mutation_digest: ObjectDigest::from_bytes(array(bytes, 64)?),
            request_catalog,
            snapshot_guid: u64::from_be_bytes(array(bytes, 136)?),
            source_dataset_guid: u64::from_be_bytes(array(bytes, 144)?),
            source_storage_handle: array(bytes, 152)?,
            source_creation_operation_id: array(bytes, 184)?,
            source_publication_record_digest: ObjectDigest::from_bytes(array(bytes, 200)?),
            source_pin_attempt_id: array(bytes, 232)?,
            source_pin_record_digest: ObjectDigest::from_bytes(array(bytes, 248)?),
            zfs_observation_digest: ObjectDigest::from_bytes(array(bytes, 280)?),
            root_attributes: PortableRootAttributesV1::new(
                u32::from_be_bytes(array(bytes, 312)?),
                u32::from_be_bytes(array(bytes, 316)?),
                u32::from(u16::from_be_bytes(array(bytes, 320)?)),
            )
            .map_err(|_| SnapshotMetadataError::InvalidRootAttributes)?,
            maximum_portable_uid: u32::from_be_bytes(array(bytes, 324)?),
            maximum_portable_gid: u32::from_be_bytes(array(bytes, 328)?),
            distinct_inode_count: u64::from_be_bytes(array(bytes, 336)?),
            directory_entry_count: u64::from_be_bytes(array(bytes, 344)?),
            identity_tree_digest: ObjectDigest::from_bytes(array(bytes, 352)?),
        };
        let record = Self::new(parts)?;
        if record.canonical_bytes() != bytes {
            return Err(SnapshotMetadataError::MalformedEncoding);
        }
        Ok(record)
    }

    /// Encodes the record in the exact AOSSMT01 representation.
    pub(crate) fn canonical_bytes(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&IDENTITY_PROFILE.to_be_bytes());
        bytes[12..16].copy_from_slice(&IDENTITY_COVERAGE_MASK.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.parts.operation_id);
        bytes[32..64].copy_from_slice(self.parts.request_digest.as_bytes());
        bytes[64..96].copy_from_slice(self.parts.mutation_digest.as_bytes());
        bytes[96..104].copy_from_slice(&self.parts.request_catalog.generation().to_be_bytes());
        bytes[104..136].copy_from_slice(self.parts.request_catalog.digest().as_bytes());
        bytes[136..144].copy_from_slice(&self.parts.snapshot_guid.to_be_bytes());
        bytes[144..152].copy_from_slice(&self.parts.source_dataset_guid.to_be_bytes());
        bytes[152..184].copy_from_slice(&self.parts.source_storage_handle);
        bytes[184..200].copy_from_slice(&self.parts.source_creation_operation_id);
        bytes[200..232].copy_from_slice(self.parts.source_publication_record_digest.as_bytes());
        bytes[232..248].copy_from_slice(&self.parts.source_pin_attempt_id);
        bytes[248..280].copy_from_slice(self.parts.source_pin_record_digest.as_bytes());
        bytes[280..312].copy_from_slice(self.parts.zfs_observation_digest.as_bytes());
        bytes[312..316].copy_from_slice(&self.parts.root_attributes.uid().to_be_bytes());
        bytes[316..320].copy_from_slice(&self.parts.root_attributes.gid().to_be_bytes());
        bytes[320..322].copy_from_slice(&self.parts.root_attributes.mode().to_be_bytes());
        bytes[324..328].copy_from_slice(&self.parts.maximum_portable_uid.to_be_bytes());
        bytes[328..332].copy_from_slice(&self.parts.maximum_portable_gid.to_be_bytes());
        bytes[336..344].copy_from_slice(&self.parts.distinct_inode_count.to_be_bytes());
        bytes[344..352].copy_from_slice(&self.parts.directory_entry_count.to_be_bytes());
        bytes[352..384].copy_from_slice(self.parts.identity_tree_digest.as_bytes());
        bytes
    }

    /// Returns the domain-separated digest of the exact record bytes.
    pub(crate) fn record_digest(self) -> ObjectDigest {
        digest(RECORD_DIGEST_DOMAIN, &self.canonical_bytes())
    }

    /// Returns the exact Snapshot operation identifier.
    pub(crate) const fn operation_id(self) -> [u8; 16] {
        self.parts.operation_id
    }
    /// Returns the authenticated Apply request digest.
    pub(crate) const fn request_digest(self) -> ObjectDigest {
        self.parts.request_digest
    }
    /// Returns the exact ZFS mutation digest.
    pub(crate) const fn mutation_digest(self) -> ObjectDigest {
        self.parts.mutation_digest
    }
    /// Returns the resolved request-catalog binding.
    pub(crate) const fn request_catalog(self) -> CatalogBindingV1 {
        self.parts.request_catalog
    }
    /// Returns the observed immutable snapshot GUID.
    pub(crate) const fn snapshot_guid(self) -> u64 {
        self.parts.snapshot_guid
    }
    /// Returns the exact source dataset GUID.
    pub(crate) const fn source_dataset_guid(self) -> u64 {
        self.parts.source_dataset_guid
    }
    /// Returns the opaque source storage handle.
    pub(crate) const fn source_storage_handle(self) -> [u8; 32] {
        self.parts.source_storage_handle
    }
    /// Returns the source workspace creation operation.
    pub(crate) const fn source_creation_operation_id(self) -> [u8; 16] {
        self.parts.source_creation_operation_id
    }
    /// Returns the authenticated source publication-record digest.
    pub(crate) const fn source_publication_record_digest(self) -> ObjectDigest {
        self.parts.source_publication_record_digest
    }
    /// Returns the selected satisfied source pin attempt.
    pub(crate) const fn source_pin_attempt_id(self) -> [u8; 16] {
        self.parts.source_pin_attempt_id
    }
    /// Returns the authenticated source pin-record digest.
    pub(crate) const fn source_pin_record_digest(self) -> ObjectDigest {
        self.parts.source_pin_record_digest
    }
    /// Returns the raw exact ZFS observation digest.
    pub(crate) const fn zfs_observation_digest(self) -> ObjectDigest {
        self.parts.zfs_observation_digest
    }
    /// Returns the portable source-root attributes.
    pub(crate) const fn root_attributes(self) -> PortableRootAttributesV1 {
        self.parts.root_attributes
    }
    /// Returns the greatest portable UID found in the tree.
    pub(crate) const fn maximum_portable_uid(self) -> u32 {
        self.parts.maximum_portable_uid
    }
    /// Returns the greatest portable GID found in the tree.
    pub(crate) const fn maximum_portable_gid(self) -> u32 {
        self.parts.maximum_portable_gid
    }
    /// Returns the number of distinct inode identities visited.
    pub(crate) const fn distinct_inode_count(self) -> u64 {
        self.parts.distinct_inode_count
    }
    /// Returns the number of canonical directory entries below the root.
    ///
    /// An otherwise empty snapshot has zero entries while still containing its
    /// nonzero root inode in [`Self::distinct_inode_count`].
    pub(crate) const fn directory_entry_count(self) -> u64 {
        self.parts.directory_entry_count
    }
    /// Returns the canonical whole-tree identity digest.
    pub(crate) const fn identity_tree_digest(self) -> ObjectDigest {
        self.parts.identity_tree_digest
    }
}

/// Carries checked metadata supplied by the protected snapshot observer.
#[derive(Debug)]
pub(crate) struct SnapshotCommitEvidenceV1 {
    metadata: CheckedSnapshotMetadataRecordV1,
}

impl SnapshotCommitEvidenceV1 {
    /// Wraps one checked record for the forthcoming protected observer.
    #[allow(
        dead_code,
        reason = "the protected observer is introduced in the next source partition"
    )]
    const fn from_checked_record(metadata: CheckedSnapshotMetadataRecordV1) -> Self {
        Self { metadata }
    }

    /// Returns the exact checked metadata record.
    pub(crate) const fn metadata(&self) -> CheckedSnapshotMetadataRecordV1 {
        self.metadata
    }
}

/// Selects the exact extra evidence required by one catalog commit.
#[derive(Debug)]
pub(crate) enum CatalogCommitSupplementV1 {
    /// Carries no operation-specific observation beyond the ZFS result.
    None,
    /// Carries the exhaustive identity observation required by Snapshot.
    Snapshot(SnapshotCommitEvidenceV1),
}

/// Commits the raw ZFS observation and authenticated identity record together.
pub(crate) fn snapshot_commit_observation_digest(
    zfs_observation_digest: ObjectDigest,
    metadata_record_digest: ObjectDigest,
) -> Result<ObjectDigest, SnapshotMetadataError> {
    if zfs_observation_digest.as_bytes() == &[0; 32]
        || metadata_record_digest.as_bytes() == &[0; 32]
    {
        return Err(SnapshotMetadataError::InvalidValue);
    }

    let mut hasher = Sha256::new();
    hasher.update(COMMIT_OBSERVATION_DOMAIN);
    hasher.update(zfs_observation_digest.as_bytes());
    hasher.update(metadata_record_digest.as_bytes());
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SnapshotMetadataError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(SnapshotMetadataError::MalformedEncoding)
}
