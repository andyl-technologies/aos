//! Reachability diagnostics for persistent blob packs.

use super::*;

/// A latest node-metadata value link resolved to a verified value blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistNodeValueRoot {
    node_key: PersistNodeMetadataKey,
    value_hash: ValueHash,
    location: PersistBlobLocation,
}

impl PersistNodeValueRoot {
    pub(in crate::cache::persist::cache) const fn new(
        node_key: PersistNodeMetadataKey,
        value_hash: ValueHash,
        location: PersistBlobLocation,
    ) -> Self {
        Self {
            node_key,
            value_hash,
            location,
        }
    }

    /// Returns the demand-node metadata key that published this value root.
    pub const fn node_key(self) -> PersistNodeMetadataKey {
        self.node_key
    }

    /// Returns the materialized value hash linked from node metadata.
    pub const fn value_hash(self) -> ValueHash {
        self.value_hash
    }

    /// Returns the typed value-blob lookup key for this root.
    pub const fn blob_key(self) -> PersistBlobKey {
        PersistBlobKey::for_value(self.value_hash)
    }

    /// Returns the verified value-pack location for this root.
    pub const fn location(self) -> PersistBlobLocation {
        self.location
    }
}

/// A latest node-metadata value link with no value-blob index location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistMissingNodeValueRoot {
    node_key: PersistNodeMetadataKey,
    value_hash: ValueHash,
}

impl PersistMissingNodeValueRoot {
    pub(in crate::cache::persist::cache) const fn new(
        node_key: PersistNodeMetadataKey,
        value_hash: ValueHash,
    ) -> Self {
        Self {
            node_key,
            value_hash,
        }
    }

    /// Returns the demand-node metadata key that published this value link.
    pub const fn node_key(self) -> PersistNodeMetadataKey {
        self.node_key
    }

    /// Returns the materialized value hash missing from the value-blob index.
    pub const fn value_hash(self) -> ValueHash {
        self.value_hash
    }

    /// Returns the typed value-blob lookup key for the missing root.
    pub const fn blob_key(self) -> PersistBlobKey {
        PersistBlobKey::for_value(self.value_hash)
    }
}

/// Read-only diagnostics for node-metadata value roots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistNodeValueRootPlan {
    resolved_roots: Vec<PersistNodeValueRoot>,
    missing_roots: Vec<PersistMissingNodeValueRoot>,
}

impl PersistNodeValueRootPlan {
    pub(in crate::cache::persist::cache) fn new(
        resolved_roots: Vec<PersistNodeValueRoot>,
        missing_roots: Vec<PersistMissingNodeValueRoot>,
    ) -> Self {
        Self {
            resolved_roots,
            missing_roots,
        }
    }

    /// Returns latest node-metadata value links that resolve to verified blobs.
    pub fn resolved_roots(&self) -> &[PersistNodeValueRoot] {
        &self.resolved_roots
    }

    /// Returns latest node-metadata value links missing from the blob index.
    pub fn missing_roots(&self) -> &[PersistMissingNodeValueRoot] {
        &self.missing_roots
    }

    /// Returns whether any node-metadata value link is missing from the blob index.
    pub fn repair_needed(&self) -> bool {
        !self.missing_roots.is_empty()
    }
}

/// Read-only diagnostics for value-pack reachability.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistValueBlobReachabilityPlan {
    pub(in crate::cache::persist::cache) node_roots: Vec<PersistNodeValueRoot>,
    pub(in crate::cache::persist::cache) missing_node_roots: Vec<PersistMissingNodeValueRoot>,
    pub(in crate::cache::persist::cache) node_rooted_records: Vec<PersistBlobPackRecord>,
    pub(in crate::cache::persist::cache) indexed_unrooted_records: Vec<PersistBlobPackRecord>,
    pub(in crate::cache::persist::cache) unindexed_records: Vec<PersistBlobPackRecord>,
    pub(in crate::cache::persist::cache) bytes_before: u64,
    pub(in crate::cache::persist::cache) node_rooted_record_bytes: u64,
    pub(in crate::cache::persist::cache) indexed_unrooted_record_bytes: u64,
    pub(in crate::cache::persist::cache) unindexed_record_bytes: u64,
}

impl PersistValueBlobReachabilityPlan {
    /// Returns node-metadata value links resolved to verified value blobs.
    pub fn node_roots(&self) -> &[PersistNodeValueRoot] {
        &self.node_roots
    }

    /// Returns node-metadata value links missing from the value blob index.
    pub fn missing_node_roots(&self) -> &[PersistMissingNodeValueRoot] {
        &self.missing_node_roots
    }

    /// Returns verified physical value records reachable from node metadata.
    pub fn node_rooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.node_rooted_records
    }

    /// Returns verified indexed value records without current node roots.
    pub fn indexed_unrooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.indexed_unrooted_records
    }

    /// Returns verified physical value records absent from current index roots.
    pub fn unindexed_records(&self) -> &[PersistBlobPackRecord] {
        &self.unindexed_records
    }

    /// Returns the value packfile length observed while planning.
    pub const fn bytes_before(&self) -> u64 {
        self.bytes_before
    }

    /// Returns bytes occupied by node-rooted value records.
    pub const fn node_rooted_record_bytes(&self) -> u64 {
        self.node_rooted_record_bytes
    }

    /// Returns bytes occupied by indexed records without current node roots.
    pub const fn indexed_unrooted_record_bytes(&self) -> u64 {
        self.indexed_unrooted_record_bytes
    }

    /// Returns bytes occupied by records absent from current index roots.
    pub const fn unindexed_record_bytes(&self) -> u64 {
        self.unindexed_record_bytes
    }

    /// Returns whether any node-metadata value link is missing from the blob index.
    pub fn repair_needed(&self) -> bool {
        !self.missing_node_roots.is_empty()
    }
}

/// Read-only diagnostics for file-pack artifact reachability.
///
/// Physical records are assigned to one exclusive class in precedence order:
/// durable file-artifact roots, durable parse-artifact roots, same-process
/// pending artifact roots, blob-index-only roots, then records absent from all
/// captured roots. Root lists still expose every captured root, including blob
/// index roots whose record is also artifact-rooted. A concurrent same-process
/// artifact publication can appear in both a pending-root list and a durable
/// artifact-root list because this is a diagnostic snapshot, not a GC barrier.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistFileBlobReachabilityPlan {
    pub(in crate::cache::persist::cache) file_artifact_roots: Vec<PersistBlobLiveRoot>,
    pub(in crate::cache::persist::cache) parse_artifact_roots: Vec<PersistBlobLiveRoot>,
    pub(in crate::cache::persist::cache) pending_artifact_roots: Vec<PersistBlobLiveRoot>,
    pub(in crate::cache::persist::cache) blob_index_roots: Vec<PersistBlobLiveRoot>,
    pub(in crate::cache::persist::cache) file_artifact_rooted_records: Vec<PersistBlobPackRecord>,
    pub(in crate::cache::persist::cache) parse_artifact_rooted_records: Vec<PersistBlobPackRecord>,
    pub(in crate::cache::persist::cache) pending_artifact_rooted_records:
        Vec<PersistBlobPackRecord>,
    pub(in crate::cache::persist::cache) indexed_unrooted_records: Vec<PersistBlobPackRecord>,
    pub(in crate::cache::persist::cache) unindexed_records: Vec<PersistBlobPackRecord>,
    pub(in crate::cache::persist::cache) bytes_before: u64,
    pub(in crate::cache::persist::cache) file_artifact_rooted_record_bytes: u64,
    pub(in crate::cache::persist::cache) parse_artifact_rooted_record_bytes: u64,
    pub(in crate::cache::persist::cache) pending_artifact_rooted_record_bytes: u64,
    pub(in crate::cache::persist::cache) indexed_unrooted_record_bytes: u64,
    pub(in crate::cache::persist::cache) unindexed_record_bytes: u64,
}

impl PersistFileBlobReachabilityPlan {
    /// Returns latest file-artifact sidecar roots resolved to verified blobs.
    pub fn file_artifact_roots(&self) -> &[PersistBlobLiveRoot] {
        &self.file_artifact_roots
    }

    /// Returns latest parse-artifact sidecar roots resolved to verified blobs.
    pub fn parse_artifact_roots(&self) -> &[PersistBlobLiveRoot] {
        &self.parse_artifact_roots
    }

    /// Returns same-process artifact roots that are not durably recorded yet.
    pub fn pending_artifact_roots(&self) -> &[PersistBlobLiveRoot] {
        &self.pending_artifact_roots
    }

    /// Returns latest `files/` blob-index roots resolved to verified blobs.
    pub fn blob_index_roots(&self) -> &[PersistBlobLiveRoot] {
        &self.blob_index_roots
    }

    /// Returns verified physical records rooted by file-artifact mappings.
    pub fn file_artifact_rooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.file_artifact_rooted_records
    }

    /// Returns verified physical records rooted by parse-artifact mappings only.
    pub fn parse_artifact_rooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.parse_artifact_rooted_records
    }

    /// Returns verified physical records rooted only by same-process pending roots.
    pub fn pending_artifact_rooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.pending_artifact_rooted_records
    }

    /// Returns verified indexed file records without current artifact roots.
    pub fn indexed_unrooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.indexed_unrooted_records
    }

    /// Returns verified physical file records absent from all captured roots.
    pub fn unindexed_records(&self) -> &[PersistBlobPackRecord] {
        &self.unindexed_records
    }

    /// Returns the file packfile length observed while planning.
    pub const fn bytes_before(&self) -> u64 {
        self.bytes_before
    }

    /// Returns bytes occupied by file-artifact-rooted records.
    pub const fn file_artifact_rooted_record_bytes(&self) -> u64 {
        self.file_artifact_rooted_record_bytes
    }

    /// Returns bytes occupied by parse-artifact-rooted records.
    pub const fn parse_artifact_rooted_record_bytes(&self) -> u64 {
        self.parse_artifact_rooted_record_bytes
    }

    /// Returns bytes occupied by pending-artifact-rooted records.
    pub const fn pending_artifact_rooted_record_bytes(&self) -> u64 {
        self.pending_artifact_rooted_record_bytes
    }

    /// Returns bytes occupied by indexed records without current artifact roots.
    pub const fn indexed_unrooted_record_bytes(&self) -> u64 {
        self.indexed_unrooted_record_bytes
    }

    /// Returns bytes occupied by records absent from captured roots.
    pub const fn unindexed_record_bytes(&self) -> u64 {
        self.unindexed_record_bytes
    }
}
