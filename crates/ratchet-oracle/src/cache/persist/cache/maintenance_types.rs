//! Maintenance, liveness, reachability, and repack result types.

use super::*;

mod index_rebuild_types;
mod reachability_types;

pub use index_rebuild_types::{
    PersistBlobIndexRebuild, PersistBlobIndexRebuildPlan, PersistBlobIndexStaleEntry,
};
pub use reachability_types::{
    PersistFileBlobReachabilityPlan, PersistMissingNodeValueRoot, PersistNodeValueRoot,
    PersistNodeValueRootPlan, PersistValueBlobReachabilityPlan,
};

const DEFAULT_STORAGE_REPACK_RECLAIMABLE_BYTES: u64 = 64 * 1024 * 1024;

/// Policy inputs for automatic persistent storage maintenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistStorageMaintenancePolicy {
    min_repack_reclaimable_bytes: u64,
    primary_size_pressure_bytes: Option<u64>,
}

impl Default for PersistStorageMaintenancePolicy {
    fn default() -> Self {
        Self {
            min_repack_reclaimable_bytes: DEFAULT_STORAGE_REPACK_RECLAIMABLE_BYTES,
            primary_size_pressure_bytes: None,
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

    /// Returns a policy that demotes primary root records once the primary's
    /// resident footprint exceeds `bound` bytes.
    ///
    /// Demotion (doc 29 §5.4/§5.6) is disabled by default. Setting a bound opts
    /// the primary location into cold-root-record demotion under size pressure:
    /// when the primary's resident bytes exceed `bound`, maintenance moves the
    /// largest, coldest root-instantiation records down to the next slower
    /// latency class (a demoted root re-promotes on its next hit).
    pub const fn with_primary_size_pressure_bytes(mut self, bound: u64) -> Self {
        self.primary_size_pressure_bytes = Some(bound);
        self
    }

    /// Returns the primary resident-byte bound above which root records demote,
    /// or `None` when demotion is disabled.
    pub const fn primary_size_pressure_bytes(self) -> Option<u64> {
        self.primary_size_pressure_bytes
    }

    /// Returns the bytes demotion should free given the primary's resident total.
    ///
    /// This is `primary_used_bytes` saturating-minus the configured size-pressure
    /// bound, or `0` when demotion is disabled or the primary is within its
    /// bound. A non-zero result is the [`select_demotion_victims`] target.
    pub const fn demotion_bytes_to_free(self, primary_used_bytes: u64) -> u64 {
        match self.primary_size_pressure_bytes {
            Some(bound) => primary_used_bytes.saturating_sub(bound),
            None => 0,
        }
    }
}

/// One primary root-instantiation record eligible for demotion under size
/// pressure (doc 29 §5.4/§5.6).
///
/// Candidates are enumerated read-only from the primary root-record index. The
/// `mtime_unix_secs` field carries a monotonic recency proxy — smaller means
/// older/colder — for which callers pass the record blob's files-pack append
/// offset, because packed blobs share one packfile and carry no independent
/// filesystem mtime. `resident_bytes` is the cheap files-blob proxy (the record
/// blob plus its closure blobs), which may over-count blobs shared by identical
/// closures; the §5.7-faithful exclusive-byte accounting is a follow-up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistDemotionCandidate {
    key: PersistRootRecordKey,
    resident_bytes: u64,
    mtime_unix_secs: u64,
}

impl PersistDemotionCandidate {
    /// Creates a demotion candidate from its root-record key, resident-byte
    /// estimate, and recency proxy (smaller = older/colder).
    pub const fn new(key: PersistRootRecordKey, resident_bytes: u64, mtime_unix_secs: u64) -> Self {
        Self {
            key,
            resident_bytes,
            mtime_unix_secs,
        }
    }

    /// Returns the root-record index key of this candidate.
    pub const fn key(self) -> PersistRootRecordKey {
        self.key
    }

    /// Returns the estimated resident bytes this record holds in the primary.
    pub const fn resident_bytes(self) -> u64 {
        self.resident_bytes
    }

    /// Returns the recency proxy (smaller is older/colder).
    pub const fn mtime_unix_secs(self) -> u64 {
        self.mtime_unix_secs
    }
}

/// Orders unrooted candidates largest-and-oldest first and returns the prefix
/// relieving `bytes_to_free`.
///
/// Implements the interim placement policy of doc 29 §5.7's demotion half:
/// value density (`est_recompute / entry_bytes`) is not persisted yet, so this
/// approximates "lowest value density first" by demoting the largest records
/// (maximum pressure relief per record moved), breaking byte ties toward the
/// coldest (smallest recency proxy) and then by key for a total order. Sorts
/// `candidates` in place and returns the minimal prefix whose cumulative
/// `resident_bytes` reaches `bytes_to_free`; the prefix is empty when
/// `bytes_to_free` is `0` and the whole slice when the target exceeds the
/// available bytes.
pub fn select_demotion_victims(
    candidates: &mut [PersistDemotionCandidate],
    bytes_to_free: u64,
) -> &[PersistDemotionCandidate] {
    candidates.sort_unstable_by(|l, r| {
        r.resident_bytes
            .cmp(&l.resident_bytes)
            .then(l.mtime_unix_secs.cmp(&r.mtime_unix_secs))
            .then(l.key.cmp(&r.key))
    });
    if bytes_to_free == 0 {
        return &candidates[..0];
    }
    let (mut freed, mut count) = (0u64, 0usize);
    for c in candidates.iter() {
        if freed >= bytes_to_free {
            break;
        }
        freed = freed.saturating_add(c.resident_bytes);
        count += 1;
    }
    &candidates[..count]
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
    /// The durable root-instantiation record index in the `roots/` sidecar.
    ///
    /// Roots from this source cover both the encoded record blob itself and
    /// every closure `.drv` blob the record references, so storage maintenance
    /// never reclaims a byte a live root-cutoff record still needs.
    RootRecordIndex,
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
