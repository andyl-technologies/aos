//! Canonical Profile2 census DATA for a genuinely observed fresh Snapshot.
//!
//! The coordinate codec and validator are shared with Profile1. The selected
//! header, commitments, full Tree descriptor and fifteen measured counters are
//! distinct; decoding these bytes neither acquires a Snapshot nor admits G0.
//!
//! ```text
//! AOSSMT02 | version2 | profile2 | coverage0x7ff | coordinates368
//! content-digest32 | Tree-digest32 | Tree-size8 | fifteen BEu64 counters120
//! ```

use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, encode_object_descriptor,
};
use aos_sandbox_source_provider_protocol::held_snapshot_content_digest_v1;

use super::{
    CheckedSnapshotMetadataRecordV1, SnapshotMetadataError, SnapshotMetadataRecordPartsV1,
    array, digest,
};

pub(crate) const RECORD_BYTES: usize = 576;
pub(crate) const COVERAGE_MASK: u32 = 0x7ff;
const MAGIC: &[u8; 8] = b"AOSSMT02";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.storage.snapshot-metadata-record.v2\0";
const IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.storage.snapshot-identity-census.v2\0";
const OBSERVATION_DOMAIN: &[u8] = b"aos.sandbox.storage.snapshot-commit-observation.v2\0";

/// Counts the complete portable projection, including expanded hardlink paths.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SnapshotCensusCountersV2 {
    pub(crate) directory_count: u64,
    pub(crate) unique_regular_inode_count: u64,
    pub(crate) regular_entry_count: u64,
    pub(crate) symlink_entry_count: u64,
    pub(crate) hardlink_group_count: u64,
    pub(crate) hardlink_member_count: u64,
    pub(crate) unique_regular_logical_bytes: u64,
    pub(crate) expanded_regular_logical_bytes: u64,
    pub(crate) stored_content_bytes: u64,
    pub(crate) canonical_object_bytes: u64,
    pub(crate) name_bytes: u64,
    pub(crate) xattr_count: u64,
    pub(crate) xattr_name_value_bytes: u64,
    pub(crate) access_acl_entries: u64,
    pub(crate) default_acl_entries: u64,
}

impl SnapshotCensusCountersV2 {
    pub(crate) const fn values(self) -> [u64; 15] {
        [
            self.directory_count,
            self.unique_regular_inode_count,
            self.regular_entry_count,
            self.symlink_entry_count,
            self.hardlink_group_count,
            self.hardlink_member_count,
            self.unique_regular_logical_bytes,
            self.expanded_regular_logical_bytes,
            self.stored_content_bytes,
            self.canonical_object_bytes,
            self.name_bytes,
            self.xattr_count,
            self.xattr_name_value_bytes,
            self.access_acl_entries,
            self.default_acl_entries,
        ]
    }

    fn from_values(values: [u64; 15]) -> Self {
        Self {
            directory_count: values[0],
            unique_regular_inode_count: values[1],
            regular_entry_count: values[2],
            symlink_entry_count: values[3],
            hardlink_group_count: values[4],
            hardlink_member_count: values[5],
            unique_regular_logical_bytes: values[6],
            expanded_regular_logical_bytes: values[7],
            stored_content_bytes: values[8],
            canonical_object_bytes: values[9],
            name_bytes: values[10],
            xattr_count: values[11],
            xattr_name_value_bytes: values[12],
            access_acl_entries: values[13],
            default_acl_entries: values[14],
        }
    }

    /// Checks equations and the independently rejecting traversal envelope.
    pub(crate) fn validate(
        self,
        coordinates: &SnapshotMetadataRecordPartsV1,
    ) -> Result<(), SnapshotMetadataError> {
        let distinct = self
            .directory_count
            .checked_add(self.unique_regular_inode_count)
            .and_then(|value| value.checked_add(self.symlink_entry_count));
        let nodes = self
            .directory_count
            .checked_add(self.regular_entry_count)
            .and_then(|value| value.checked_add(self.symlink_entry_count));
        let linked_excess = self
            .regular_entry_count
            .checked_sub(self.unique_regular_inode_count);
        let grouped_excess = self
            .hardlink_member_count
            .checked_sub(self.hardlink_group_count);

        if self.directory_count == 0
            || distinct != Some(coordinates.distinct_inode_count)
            || nodes.and_then(|value| value.checked_sub(1)) != Some(coordinates.directory_entry_count)
            || nodes.is_none_or(|value| value > 4096)
            || linked_excess != grouped_excess
            || self.hardlink_group_count
                .checked_mul(2)
                .is_none_or(|minimum| self.hardlink_member_count < minimum)
            || self.hardlink_member_count > self.regular_entry_count
            || self.unique_regular_logical_bytes > self.expanded_regular_logical_bytes
            || self.expanded_regular_logical_bytes > 64 * 1024 * 1024
            || self.stored_content_bytes > self.unique_regular_logical_bytes
            || self.canonical_object_bytes == 0
            || self.canonical_object_bytes > 80 * 1024 * 1024
            || self.name_bytes > 1024 * 1024
            || self.xattr_count > 16384
            || self.xattr_name_value_bytes > 8 * 1024 * 1024
            || self.access_acl_entries > 65536
            || self.default_acl_entries > 65536
            || self.access_acl_entries.checked_add(self.default_acl_entries)
                .is_none_or(|entries| entries > 65536)
        {
            return Err(SnapshotMetadataError::InconsistentIdentitySummary);
        }
        Ok(())
    }
}

/// Retains canonical census DATA without a Profile1 conversion or effect accessor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckedSnapshotMetadataRecordV2 {
    coordinates: SnapshotMetadataRecordPartsV1,
    content_digest: ObjectDigest,
    tree: ObjectDescriptor,
    counters: SnapshotCensusCountersV2,
}

impl CheckedSnapshotMetadataRecordV2 {
    /// Validates measured summaries against the sole canonical Tree commitment.
    pub(crate) fn new(
        coordinates: SnapshotMetadataRecordPartsV1,
        content_digest: ObjectDigest,
        tree: ObjectDescriptor,
        counters: SnapshotCensusCountersV2,
    ) -> Result<Self, SnapshotMetadataError> {
        CheckedSnapshotMetadataRecordV1::new(coordinates)?;
        counters.validate(&coordinates)?;
        if tree.media_type().as_str() != PortableMediaType::Tree.as_str()
            || tree.digest().as_bytes() == &[0; 32]
            || tree.encoded_size() == 0
            || tree.encoded_size() > counters.canonical_object_bytes
            || held_snapshot_content_digest_v1(&tree)
                .map_err(|_| SnapshotMetadataError::InvalidValue)? != content_digest
            || identity_tree_digest(&tree) != coordinates.identity_tree_digest
        {
            return Err(SnapshotMetadataError::InconsistentIdentitySummary);
        }
        Ok(Self {
            coordinates,
            content_digest,
            tree,
            counters,
        })
    }

    /// Decodes exact Profile2 bytes through the shared coordinate decoder.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SnapshotMetadataError> {
        if bytes.len() != RECORD_BYTES || &bytes[..8] != MAGIC {
            return Err(SnapshotMetadataError::MalformedEncoding);
        }
        if u16::from_be_bytes(array(bytes, 8)?) != 2 {
            return Err(SnapshotMetadataError::UnsupportedEncodingVersion);
        }
        if u16::from_be_bytes(array(bytes, 10)?) != 2 {
            return Err(SnapshotMetadataError::UnsupportedIdentityProfile);
        }
        if u32::from_be_bytes(array(bytes, 12)?) != COVERAGE_MASK {
            return Err(SnapshotMetadataError::IncompleteIdentityCoverage);
        }

        // Normalize only the private coordinate view. No V1 record escapes
        // and the original V2 header is checked before this common decoder.
        let mut coordinate_bytes = [0_u8; 384];
        coordinate_bytes.copy_from_slice(&bytes[..384]);
        coordinate_bytes[..8].copy_from_slice(super::MAGIC);
        coordinate_bytes[8..10].copy_from_slice(&super::VERSION.to_be_bytes());
        coordinate_bytes[10..12].copy_from_slice(&super::IDENTITY_PROFILE.to_be_bytes());
        coordinate_bytes[12..16].copy_from_slice(&super::IDENTITY_COVERAGE_MASK.to_be_bytes());
        let coordinates =
            CheckedSnapshotMetadataRecordV1::from_canonical_bytes(&coordinate_bytes)?.parts;
        let tree = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::Tree.as_str())
                .map_err(|_| SnapshotMetadataError::InvalidValue)?,
            ObjectDigest::from_bytes(array(bytes, 416)?),
            u64::from_be_bytes(array(bytes, 448)?),
        );
        let mut values = [0_u64; 15];
        for (index, value) in values.iter_mut().enumerate() {
            *value = u64::from_be_bytes(array(bytes, 456 + index * 8)?);
        }
        let record = Self::new(
            coordinates,
            ObjectDigest::from_bytes(array(bytes, 384)?),
            tree,
            SnapshotCensusCountersV2::from_values(values),
        )?;
        if record.canonical_bytes() != bytes {
            return Err(SnapshotMetadataError::MalformedEncoding);
        }
        Ok(record)
    }

    /// Encodes the distinct header and complete selected census.
    pub(crate) fn canonical_bytes(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0_u8; RECORD_BYTES];
        let coordinates = CheckedSnapshotMetadataRecordV1 { parts: self.coordinates };
        bytes[..384].copy_from_slice(&coordinates.canonical_bytes());
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        bytes[10..12].copy_from_slice(&2_u16.to_be_bytes());
        bytes[12..16].copy_from_slice(&COVERAGE_MASK.to_be_bytes());
        bytes[384..416].copy_from_slice(self.content_digest.as_bytes());
        bytes[416..448].copy_from_slice(self.tree.digest().as_bytes());
        bytes[448..456].copy_from_slice(&self.tree.encoded_size().to_be_bytes());
        for (index, value) in self.counters.values().iter().enumerate() {
            bytes[456 + index * 8..464 + index * 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    pub(crate) fn record_digest(&self) -> ObjectDigest {
        digest(RECORD_DOMAIN, &self.canonical_bytes())
    }

    pub(crate) fn commit_observation_digest(&self) -> ObjectDigest {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(self.coordinates.zfs_observation_digest.as_bytes());
        bytes[32..].copy_from_slice(self.record_digest().as_bytes());
        digest(OBSERVATION_DOMAIN, &bytes)
    }

    pub(crate) const fn coordinates(&self) -> &SnapshotMetadataRecordPartsV1 {
        &self.coordinates
    }

    pub(crate) const fn tree(&self) -> &ObjectDescriptor {
        &self.tree
    }

    pub(crate) const fn content_digest(&self) -> ObjectDigest {
        self.content_digest
    }

    pub(crate) const fn counters(&self) -> SnapshotCensusCountersV2 {
        self.counters
    }
}

/// Shares the Profile2 identity commitment with physical census and Clone DATA.
pub(crate) fn identity_tree_digest(tree: &ObjectDescriptor) -> ObjectDigest {
    digest(IDENTITY_DOMAIN, &encode_object_descriptor(tree))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_order_is_fixed_and_lossless() {
        let values = std::array::from_fn(|index| index as u64 + 1);
        let counters = SnapshotCensusCountersV2::from_values(values);

        assert_eq!(counters.values(), values);
        assert_eq!(counters.directory_count, 1);
        assert_eq!(counters.default_acl_entries, 15);
    }

    #[test]
    fn old_or_mixed_metadata_headers_are_not_census_records() {
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(super::super::MAGIC);

        assert_eq!(
            CheckedSnapshotMetadataRecordV2::from_canonical_bytes(&bytes),
            Err(SnapshotMetadataError::MalformedEncoding),
        );

        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());

        assert_eq!(
            CheckedSnapshotMetadataRecordV2::from_canonical_bytes(&bytes),
            Err(SnapshotMetadataError::UnsupportedEncodingVersion),
        );
    }

    #[test]
    fn exact_census_extent_rejects_trailing_bytes_before_fields() {
        let bytes = [0_u8; RECORD_BYTES + 1];

        assert_eq!(
            CheckedSnapshotMetadataRecordV2::from_canonical_bytes(&bytes),
            Err(SnapshotMetadataError::MalformedEncoding),
        );
    }
}
