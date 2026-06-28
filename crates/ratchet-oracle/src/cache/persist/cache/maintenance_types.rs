//! Maintenance, liveness, reachability, and repack result types.

use super::*;

const DEFAULT_STORAGE_REPACK_RECLAIMABLE_BYTES: u64 = 64 * 1024 * 1024;

/// Policy inputs for automatic persistent storage maintenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistStorageMaintenancePolicy {
    min_repack_reclaimable_bytes: u64,
}

impl Default for PersistStorageMaintenancePolicy {
    fn default() -> Self {
        Self {
            min_repack_reclaimable_bytes: DEFAULT_STORAGE_REPACK_RECLAIMABLE_BYTES,
        }
    }
}

impl PersistStorageMaintenancePolicy {
    /// Returns a policy that repacks only after `min_repack_reclaimable_bytes`.
    pub const fn with_min_repack_reclaimable_bytes(
        mut self,
        min_repack_reclaimable_bytes: u64,
    ) -> Self {
        self.min_repack_reclaimable_bytes = min_repack_reclaimable_bytes;
        self
    }

    /// Returns the minimum total reclaimable pack bytes needed before repack.
    pub const fn min_repack_reclaimable_bytes(self) -> u64 {
        self.min_repack_reclaimable_bytes
    }
}

/// The action selected by automatic persistent storage maintenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistStorageMaintenanceAction {
    /// No maintenance is needed under the selected policy.
    Skip,
    /// Blob indexes should be repaired before any pack bytes are reclaimed.
    RepairIndexes,
    /// Blob packs should be repacked to reclaim duplicate or unrooted bytes.
    RepackBlobs,
}

/// Read-only diagnostics used to choose automatic storage maintenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistStorageMaintenancePlan {
    policy: PersistStorageMaintenancePolicy,
    blob_indexes: PersistBlobIndexRebuild,
    value_blob_pack: PersistBlobPackRepackPlan,
    file_blob_pack: PersistBlobPackRepackPlan,
}

impl PersistStorageMaintenancePlan {
    pub(super) const fn new(
        policy: PersistStorageMaintenancePolicy,
        blob_indexes: PersistBlobIndexRebuild,
        value_blob_pack: PersistBlobPackRepackPlan,
        file_blob_pack: PersistBlobPackRepackPlan,
    ) -> Self {
        Self {
            policy,
            blob_indexes,
            value_blob_pack,
            file_blob_pack,
        }
    }

    /// Returns the policy used to classify this plan.
    pub const fn policy(&self) -> PersistStorageMaintenancePolicy {
        self.policy
    }

    /// Returns blob-index rebuild diagnostics.
    pub const fn blob_indexes(&self) -> &PersistBlobIndexRebuild {
        &self.blob_indexes
    }

    /// Returns the value pack repack plan.
    pub const fn value_blob_pack(&self) -> &PersistBlobPackRepackPlan {
        &self.value_blob_pack
    }

    /// Returns the file pack repack plan.
    pub const fn file_blob_pack(&self) -> &PersistBlobPackRepackPlan {
        &self.file_blob_pack
    }

    /// Returns whether either blob index needs lookup repair.
    pub fn blob_index_repair_needed(&self) -> bool {
        self.blob_indexes.lookup_repair_needed()
    }

    /// Returns total bytes a repack would reclaim across both blob packs.
    pub const fn repack_reclaimable_bytes(&self) -> u64 {
        self.value_blob_pack
            .reclaimable_bytes()
            .saturating_add(self.file_blob_pack.reclaimable_bytes())
    }

    /// Returns whether the policy threshold selects blob-pack repacking.
    pub const fn repack_needed(&self) -> bool {
        let reclaimable = self.repack_reclaimable_bytes();
        reclaimable > 0 && reclaimable >= self.policy.min_repack_reclaimable_bytes()
    }

    /// Returns the automatic maintenance action selected by this plan.
    pub fn action(&self) -> PersistStorageMaintenanceAction {
        if self.blob_index_repair_needed() {
            return PersistStorageMaintenanceAction::RepairIndexes;
        }
        if self.repack_needed() {
            return PersistStorageMaintenanceAction::RepackBlobs;
        }
        PersistStorageMaintenanceAction::Skip
    }
}

/// The result of applying automatic persistent storage maintenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistStorageMaintenanceOutcome {
    /// No maintenance was run.
    Skipped {
        /// The read-only plan that justified skipping maintenance.
        plan: PersistStorageMaintenancePlan,
    },
    /// Blob indexes were repaired before reclaiming bytes.
    Repaired {
        /// The read-only plan that selected repair.
        plan: PersistStorageMaintenancePlan,
        /// The applied repair/compaction/tail-trim result.
        maintenance: PersistStorageMaintenance,
    },
    /// Blob packs were repacked after the policy threshold was met.
    Repacked {
        /// The read-only plan that selected repacking.
        plan: PersistStorageMaintenancePlan,
        /// The repair/compaction/tail-trim sweep run before repack.
        maintenance: PersistStorageMaintenance,
        /// The applied repack result.
        repack: PersistStorageRepack,
    },
}

impl PersistStorageMaintenanceOutcome {
    /// Returns the top-level action selected by this outcome.
    pub const fn action(&self) -> PersistStorageMaintenanceAction {
        match self {
            Self::Skipped { .. } => PersistStorageMaintenanceAction::Skip,
            Self::Repaired { .. } => PersistStorageMaintenanceAction::RepairIndexes,
            Self::Repacked { .. } => PersistStorageMaintenanceAction::RepackBlobs,
        }
    }

    /// Returns the plan used to select this outcome.
    pub const fn plan(&self) -> &PersistStorageMaintenancePlan {
        match self {
            Self::Skipped { plan } | Self::Repaired { plan, .. } | Self::Repacked { plan, .. } => {
                plan
            }
        }
    }
}

/// Entry counts retained by persistent sidecar compaction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PersistCompaction {
    value_blob_index_entries: usize,
    file_blob_index_entries: usize,
    file_artifact_entries: usize,
    parse_artifact_entries: usize,
    node_metadata_entries: usize,
    node_trace_entries: usize,
}

impl PersistCompaction {
    pub(super) const fn new(
        value_blob_index_entries: usize,
        file_blob_index_entries: usize,
        file_artifact_entries: usize,
        parse_artifact_entries: usize,
        node_metadata_entries: usize,
        node_trace_entries: usize,
    ) -> Self {
        Self {
            value_blob_index_entries,
            file_blob_index_entries,
            file_artifact_entries,
            parse_artifact_entries,
            node_metadata_entries,
            node_trace_entries,
        }
    }

    /// Returns the newest value blob-index entries retained.
    pub const fn value_blob_index_entries(self) -> usize {
        self.value_blob_index_entries
    }

    /// Returns the newest file blob-index entries retained.
    pub const fn file_blob_index_entries(self) -> usize {
        self.file_blob_index_entries
    }

    /// Returns the newest file-artifact index entries retained.
    pub const fn file_artifact_entries(self) -> usize {
        self.file_artifact_entries
    }

    /// Returns the newest parse-artifact index entries retained.
    pub const fn parse_artifact_entries(self) -> usize {
        self.parse_artifact_entries
    }

    /// Returns the newest demand-node metadata entries retained.
    pub const fn node_metadata_entries(self) -> usize {
        self.node_metadata_entries
    }

    /// Returns the newest node verifying-trace entries retained.
    pub const fn node_trace_entries(self) -> usize {
        self.node_trace_entries
    }

    /// Returns the total newest entries retained across all compacted sidecars.
    pub const fn total_entries(self) -> usize {
        self.value_blob_index_entries
            .saturating_add(self.file_blob_index_entries)
            .saturating_add(self.file_artifact_entries)
            .saturating_add(self.parse_artifact_entries)
            .saturating_add(self.node_metadata_entries)
            .saturating_add(self.node_trace_entries)
    }
}

/// Byte counts from persistent blob-pack tail trimming.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PersistBlobPackTrim {
    live_entries: usize,
    bytes_before: u64,
    bytes_after: u64,
}

impl PersistBlobPackTrim {
    pub(super) const fn new(live_entries: usize, bytes_before: u64, bytes_after: u64) -> Self {
        Self {
            live_entries,
            bytes_before,
            bytes_after,
        }
    }

    /// Returns the number of latest live root entries that bounded the trim.
    pub const fn live_entries(self) -> usize {
        self.live_entries
    }

    /// Returns the packfile length before trimming.
    pub const fn bytes_before(self) -> u64 {
        self.bytes_before
    }

    /// Returns the packfile length after trimming.
    pub const fn bytes_after(self) -> u64 {
        self.bytes_after
    }

    /// Returns the number of unindexed tail bytes reclaimed.
    pub const fn reclaimed_bytes(self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

/// The source that keeps a blob-pack record live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistBlobLiveRootSource {
    /// The selected store's hash-to-offset blob index.
    BlobIndex,
    /// The file-artifact mapping index in the `files/` store.
    FileArtifactIndex,
    /// The parse-artifact mapping index in the `files/` store.
    ParseArtifactIndex,
    /// A same-process file-artifact append whose mapping is not recorded yet.
    PendingFileArtifact,
    /// A same-process parse-artifact append whose mapping is not recorded yet.
    PendingParseArtifact,
}

/// A latest or in-flight root that keeps a blob-pack record live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistBlobLiveRoot {
    source: PersistBlobLiveRootSource,
    key: PersistBlobKey,
    location: PersistBlobLocation,
}

impl PersistBlobLiveRoot {
    pub(super) const fn new(
        source: PersistBlobLiveRootSource,
        key: PersistBlobKey,
        location: PersistBlobLocation,
    ) -> Self {
        Self {
            source,
            key,
            location,
        }
    }

    /// Returns the source that published or registered this live root.
    pub const fn source(self) -> PersistBlobLiveRootSource {
        self.source
    }

    /// Returns the typed blob key for the rooted pack record.
    pub const fn key(self) -> PersistBlobKey {
        self.key
    }

    /// Returns the rooted pack location.
    pub const fn location(self) -> PersistBlobLocation {
        self.location
    }
}

/// Read-only liveness diagnostics for one persistent blob pack.
///
/// This is a physical-record classification against current blob sidecars,
/// file/parse artifact sidecars, and same-process pending artifact roots. It
/// is not the final RFC garbage-collection live set: node metadata references,
/// cross-process raw writers, and future metadata engines are outside this
/// diagnostic plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistBlobPackLivenessPlan {
    live_roots: Vec<PersistBlobLiveRoot>,
    rooted_records: Vec<PersistBlobPackRecord>,
    unrooted_records: Vec<PersistBlobPackRecord>,
    bytes_before: u64,
    rooted_record_bytes: u64,
    unrooted_record_bytes: u64,
    tail_reclaimable_bytes: u64,
}

impl PersistBlobPackLivenessPlan {
    pub(super) fn new(
        live_roots: Vec<PersistBlobLiveRoot>,
        rooted_records: Vec<PersistBlobPackRecord>,
        unrooted_records: Vec<PersistBlobPackRecord>,
        bytes_before: u64,
        rooted_record_bytes: u64,
        unrooted_record_bytes: u64,
        tail_reclaimable_bytes: u64,
    ) -> Self {
        Self {
            live_roots,
            rooted_records,
            unrooted_records,
            bytes_before,
            rooted_record_bytes,
            unrooted_record_bytes,
            tail_reclaimable_bytes,
        }
    }

    /// Returns latest sidecar roots and in-flight same-process roots.
    pub fn live_roots(&self) -> &[PersistBlobLiveRoot] {
        &self.live_roots
    }

    /// Returns verified physical records reachable from at least one live root.
    pub fn rooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.rooted_records
    }

    /// Returns physical records unreachable from this plan's current roots.
    pub fn unrooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.unrooted_records
    }

    /// Returns the packfile length observed while planning.
    pub const fn bytes_before(&self) -> u64 {
        self.bytes_before
    }

    /// Returns the total bytes occupied by rooted physical records.
    pub const fn rooted_record_bytes(&self) -> u64 {
        self.rooted_record_bytes
    }

    /// Returns bytes occupied by records unreachable from this plan's roots.
    pub const fn unrooted_record_bytes(&self) -> u64 {
        self.unrooted_record_bytes
    }

    /// Returns unrooted suffix bytes that a tail trim could reclaim.
    pub const fn tail_reclaimable_bytes(&self) -> u64 {
        self.tail_reclaimable_bytes
    }
}

/// One verified blob-pack record relocation in a future repack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistBlobRecordRelocation {
    key: PersistBlobKey,
    old_location: PersistBlobLocation,
    new_location: PersistBlobLocation,
}

impl PersistBlobRecordRelocation {
    pub(super) const fn new(
        key: PersistBlobKey,
        old_location: PersistBlobLocation,
        new_location: PersistBlobLocation,
    ) -> Self {
        Self {
            key,
            old_location,
            new_location,
        }
    }

    /// Returns the typed blob key for the relocated record.
    pub const fn key(self) -> PersistBlobKey {
        self.key
    }

    /// Returns the record location in the current pack.
    pub const fn old_location(self) -> PersistBlobLocation {
        self.old_location
    }

    /// Returns the planned record location in the compacted pack.
    pub const fn new_location(self) -> PersistBlobLocation {
        self.new_location
    }
}

/// Read-only relocation diagnostics for a future blob-pack repack.
///
/// The plan preserves the selected store's verified live records in current
/// pack order and places them contiguously after a fresh pack header. For
/// `files/`, pending artifact roots are planned as live but applying such a
/// relocation still requires a quiescent writer protocol because in-flight
/// artifact callers hold old locations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistBlobPackRepackPlan {
    live_roots: Vec<PersistBlobLiveRoot>,
    record_relocations: Vec<PersistBlobRecordRelocation>,
    unrooted_records: Vec<PersistBlobPackRecord>,
    bytes_before: u64,
    bytes_after: u64,
    rooted_record_bytes: u64,
    unrooted_record_bytes: u64,
}

impl PersistBlobPackRepackPlan {
    pub(super) fn new(
        live_roots: Vec<PersistBlobLiveRoot>,
        record_relocations: Vec<PersistBlobRecordRelocation>,
        unrooted_records: Vec<PersistBlobPackRecord>,
        bytes_before: u64,
        bytes_after: u64,
        rooted_record_bytes: u64,
        unrooted_record_bytes: u64,
    ) -> Self {
        Self {
            live_roots,
            record_relocations,
            unrooted_records,
            bytes_before,
            bytes_after,
            rooted_record_bytes,
            unrooted_record_bytes,
        }
    }

    /// Returns latest sidecar roots and in-flight same-process roots.
    pub fn live_roots(&self) -> &[PersistBlobLiveRoot] {
        &self.live_roots
    }

    /// Returns verified live records with their planned compacted locations.
    pub fn record_relocations(&self) -> &[PersistBlobRecordRelocation] {
        &self.record_relocations
    }

    /// Returns verified records that a repack using this plan would omit.
    pub fn unrooted_records(&self) -> &[PersistBlobPackRecord] {
        &self.unrooted_records
    }

    /// Returns the current packfile length observed while planning.
    pub const fn bytes_before(&self) -> u64 {
        self.bytes_before
    }

    /// Returns the planned compacted packfile length.
    pub const fn bytes_after(&self) -> u64 {
        self.bytes_after
    }

    /// Returns bytes occupied by records retained by the planned repack.
    pub const fn rooted_record_bytes(&self) -> u64 {
        self.rooted_record_bytes
    }

    /// Returns bytes occupied by records omitted by the planned repack.
    pub const fn unrooted_record_bytes(&self) -> u64 {
        self.unrooted_record_bytes
    }

    /// Returns the bytes a repack using this plan would reclaim.
    pub const fn reclaimable_bytes(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

/// A latest node-metadata value link resolved to a verified value blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistNodeValueRoot {
    node_key: PersistNodeMetadataKey,
    value_hash: ValueHash,
    location: PersistBlobLocation,
}

impl PersistNodeValueRoot {
    pub(super) const fn new(
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
        PersistBlobKey::for_value(self.value_hash.as_durable_hash())
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
    pub(super) const fn new(node_key: PersistNodeMetadataKey, value_hash: ValueHash) -> Self {
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
        PersistBlobKey::for_value(self.value_hash.as_durable_hash())
    }
}

/// Read-only diagnostics for node-metadata value roots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistNodeValueRootPlan {
    resolved_roots: Vec<PersistNodeValueRoot>,
    missing_roots: Vec<PersistMissingNodeValueRoot>,
}

impl PersistNodeValueRootPlan {
    pub(super) fn new(
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
    pub(super) node_roots: Vec<PersistNodeValueRoot>,
    pub(super) missing_node_roots: Vec<PersistMissingNodeValueRoot>,
    pub(super) node_rooted_records: Vec<PersistBlobPackRecord>,
    pub(super) indexed_unrooted_records: Vec<PersistBlobPackRecord>,
    pub(super) unindexed_records: Vec<PersistBlobPackRecord>,
    pub(super) bytes_before: u64,
    pub(super) node_rooted_record_bytes: u64,
    pub(super) indexed_unrooted_record_bytes: u64,
    pub(super) unindexed_record_bytes: u64,
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
    pub(super) file_artifact_roots: Vec<PersistBlobLiveRoot>,
    pub(super) parse_artifact_roots: Vec<PersistBlobLiveRoot>,
    pub(super) pending_artifact_roots: Vec<PersistBlobLiveRoot>,
    pub(super) blob_index_roots: Vec<PersistBlobLiveRoot>,
    pub(super) file_artifact_rooted_records: Vec<PersistBlobPackRecord>,
    pub(super) parse_artifact_rooted_records: Vec<PersistBlobPackRecord>,
    pub(super) pending_artifact_rooted_records: Vec<PersistBlobPackRecord>,
    pub(super) indexed_unrooted_records: Vec<PersistBlobPackRecord>,
    pub(super) unindexed_records: Vec<PersistBlobPackRecord>,
    pub(super) bytes_before: u64,
    pub(super) file_artifact_rooted_record_bytes: u64,
    pub(super) parse_artifact_rooted_record_bytes: u64,
    pub(super) pending_artifact_rooted_record_bytes: u64,
    pub(super) indexed_unrooted_record_bytes: u64,
    pub(super) unindexed_record_bytes: u64,
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

/// Applied repack plans for both persistent blob packs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistBlobPacksRepack {
    value_blob_pack: PersistBlobPackRepackPlan,
    file_blob_pack: PersistBlobPackRepackPlan,
}

impl PersistBlobPacksRepack {
    pub(super) fn new(
        value_blob_pack: PersistBlobPackRepackPlan,
        file_blob_pack: PersistBlobPackRepackPlan,
    ) -> Self {
        Self {
            value_blob_pack,
            file_blob_pack,
        }
    }

    /// Returns the applied `values/` blob-pack repack plan.
    pub const fn value_blob_pack(&self) -> &PersistBlobPackRepackPlan {
        &self.value_blob_pack
    }

    /// Returns the applied `files/` blob-pack repack plan.
    pub const fn file_blob_pack(&self) -> &PersistBlobPackRepackPlan {
        &self.file_blob_pack
    }

    /// Returns total bytes reclaimed from both blob packs.
    pub fn reclaimed_blob_bytes(&self) -> u64 {
        self.value_blob_pack
            .reclaimable_bytes()
            .saturating_add(self.file_blob_pack.reclaimable_bytes())
    }
}

/// Results from an explicit persistent storage maintenance sweep.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistStorageMaintenance {
    sidecars: PersistCompaction,
    blob_indexes: PersistBlobIndexRebuild,
    value_blob_pack: PersistBlobPackTrim,
    file_blob_pack: PersistBlobPackTrim,
}

impl PersistStorageMaintenance {
    pub(super) fn new(
        sidecars: PersistCompaction,
        blob_indexes: PersistBlobIndexRebuild,
        value_blob_pack: PersistBlobPackTrim,
        file_blob_pack: PersistBlobPackTrim,
    ) -> Self {
        Self {
            sidecars,
            blob_indexes,
            value_blob_pack,
            file_blob_pack,
        }
    }

    /// Returns sidecar compaction counts from the maintenance sweep.
    pub const fn sidecars(&self) -> PersistCompaction {
        self.sidecars
    }

    /// Returns blob-index rebuild plans from the maintenance sweep.
    pub fn blob_indexes(&self) -> &PersistBlobIndexRebuild {
        &self.blob_indexes
    }

    /// Returns tail-trim counts for the `values/` blob pack.
    pub const fn value_blob_pack(&self) -> PersistBlobPackTrim {
        self.value_blob_pack
    }

    /// Returns tail-trim counts for the `files/` blob pack.
    pub const fn file_blob_pack(&self) -> PersistBlobPackTrim {
        self.file_blob_pack
    }

    /// Returns total bytes reclaimed from both blob packs.
    pub const fn reclaimed_blob_bytes(&self) -> u64 {
        self.value_blob_pack
            .reclaimed_bytes()
            .saturating_add(self.file_blob_pack.reclaimed_bytes())
    }
}

/// Results from an explicit persistent storage repack sweep.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistStorageRepack {
    sidecars: PersistCompaction,
    blob_packs: PersistBlobPacksRepack,
}

impl PersistStorageRepack {
    pub(super) fn new(sidecars: PersistCompaction, blob_packs: PersistBlobPacksRepack) -> Self {
        Self {
            sidecars,
            blob_packs,
        }
    }

    /// Returns sidecar compaction counts from the repack sweep.
    pub const fn sidecars(&self) -> PersistCompaction {
        self.sidecars
    }

    /// Returns applied blob-pack repack plans from the repack sweep.
    pub const fn blob_packs(&self) -> &PersistBlobPacksRepack {
        &self.blob_packs
    }

    /// Returns total bytes reclaimed from both blob packs.
    pub fn reclaimed_blob_bytes(&self) -> u64 {
        self.blob_packs.reclaimed_blob_bytes()
    }
}

/// A sidecar entry that would be replaced by a blob-index rebuild.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistBlobIndexStaleEntry {
    current: PersistBlobIndexEntry,
    planned: PersistBlobIndexEntry,
}

impl PersistBlobIndexStaleEntry {
    /// Creates a stale-entry diagnostic from current and planned index entries.
    pub const fn new(current: PersistBlobIndexEntry, planned: PersistBlobIndexEntry) -> Self {
        Self { current, planned }
    }

    /// Returns the newest sidecar entry currently present for this blob key.
    pub const fn current(self) -> PersistBlobIndexEntry {
        self.current
    }

    /// Returns the verified physical pack entry a rebuild would install.
    pub const fn planned(self) -> PersistBlobIndexEntry {
        self.planned
    }
}

/// Read-only diagnostics for rebuilding one blob-index sidecar from its pack.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistBlobIndexRebuildPlan {
    planned_entries: Vec<PersistBlobIndexEntry>,
    missing_entries: Vec<PersistBlobIndexEntry>,
    stale_entries: Vec<PersistBlobIndexStaleEntry>,
    dangling_entries: Vec<PersistBlobIndexEntry>,
}

impl PersistBlobIndexRebuildPlan {
    pub(super) fn new(
        planned_entries: Vec<PersistBlobIndexEntry>,
        missing_entries: Vec<PersistBlobIndexEntry>,
        stale_entries: Vec<PersistBlobIndexStaleEntry>,
        dangling_entries: Vec<PersistBlobIndexEntry>,
    ) -> Self {
        Self {
            planned_entries,
            missing_entries,
            stale_entries,
            dangling_entries,
        }
    }

    /// Returns the complete newest physical pack entries a rebuild would write.
    pub fn planned_entries(&self) -> &[PersistBlobIndexEntry] {
        &self.planned_entries
    }

    /// Returns verified physical pack entries absent from the sidecar.
    pub fn missing_entries(&self) -> &[PersistBlobIndexEntry] {
        &self.missing_entries
    }

    /// Returns sidecar entries whose blob key points at an older or invalid location.
    pub fn stale_entries(&self) -> &[PersistBlobIndexStaleEntry] {
        &self.stale_entries
    }

    /// Returns sidecar entries with no verified physical record in the selected pack.
    pub fn dangling_entries(&self) -> &[PersistBlobIndexEntry] {
        &self.dangling_entries
    }

    /// Returns whether newest sidecar lookups differ from the verified pack scan.
    ///
    /// This reports semantic lookup repair only. It does not report older
    /// append-only sidecar records that a future rewrite would canonicalize
    /// away when the newest entry for each key already matches the pack.
    pub fn lookup_repair_needed(&self) -> bool {
        !self.missing_entries.is_empty()
            || !self.stale_entries.is_empty()
            || !self.dangling_entries.is_empty()
    }
}

/// Plans returned by rebuilding both blob-index sidecars.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistBlobIndexRebuild {
    value_blob_index: PersistBlobIndexRebuildPlan,
    file_blob_index: PersistBlobIndexRebuildPlan,
}

impl PersistBlobIndexRebuild {
    pub(super) const fn new(
        value_blob_index: PersistBlobIndexRebuildPlan,
        file_blob_index: PersistBlobIndexRebuildPlan,
    ) -> Self {
        Self {
            value_blob_index,
            file_blob_index,
        }
    }

    /// Returns the rebuild plan applied to the `values/` blob index.
    pub fn value_blob_index(&self) -> &PersistBlobIndexRebuildPlan {
        &self.value_blob_index
    }

    /// Returns the rebuild plan applied to the `files/` blob index.
    pub fn file_blob_index(&self) -> &PersistBlobIndexRebuildPlan {
        &self.file_blob_index
    }

    /// Returns whether either applied plan observed pre-rebuild lookup differences.
    pub fn lookup_repair_needed(&self) -> bool {
        self.value_blob_index.lookup_repair_needed() || self.file_blob_index.lookup_repair_needed()
    }
}
