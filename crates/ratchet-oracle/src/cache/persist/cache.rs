//! The opened persistent eval-cache root and its store operations.
//!
//! [`PersistCache`] ties together the per-store packfiles and indexes, routing
//! blob and file-artifact reads, writes, materialization decisions, and parse
//! artifact hydration through the on-disk layout.

use super::*;

use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockMode};
use ratchet_cache::file_replace::{FileReplacement, FileReplacementError, FileReplacementSet};
use ratchet_cache::root_locks::{
    self as engine_root_locks, CacheRootLockError, CacheRootLockSlot,
    CacheRootLocks as EngineCacheRootLocks,
};

use std::sync::atomic::Ordering;

/// An opened persistent eval-cache root.
#[derive(Clone, Debug)]
pub struct PersistCache {
    layout: PersistLayout,
    value_pack: PersistBlobPack,
    file_pack: PersistBlobPack,
    value_index: PersistBlobIndex,
    file_index: PersistBlobIndex,
    file_artifact_index: PersistFileArtifactIndex,
    parse_artifact_index: PersistParseArtifactIndex,
    node_metadata_index: PersistNodeMetadataIndex,
    node_trace_log: PersistNodeTraceLog,
    root_locks: Arc<PersistRootLocks>,
}

type PendingFileRootKey = ([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64);
type PendingFileRoots = Mutex<BTreeMap<PendingFileRootKey, PersistBlobLiveRoot>>;

#[derive(Debug)]
struct PersistRootLocks {
    locks: Arc<EngineCacheRootLocks>,
    pending_file_roots: Arc<PendingFileRoots>,
}

impl PersistRootLocks {
    fn new(locks: Arc<EngineCacheRootLocks>, pending_file_roots: Arc<PendingFileRoots>) -> Self {
        Self {
            locks,
            pending_file_roots,
        }
    }

    fn lock_open(&self) -> Result<MutexGuard<'_, ()>, PersistError> {
        self.lock_slot(CacheRootLockSlot::Open)
            .map_err(|_| PersistError::RootOpenLockPoisoned)
    }

    fn lock(
        &self,
        store: PersistBlobStore,
    ) -> Result<MutexGuard<'_, ()>, PersistBlobIndexedWriteError> {
        self.lock_blob_store(store)
            .map_err(|_| PersistBlobIndexedWriteError::WriteLockPoisoned { store })
    }

    fn lock_blob_pack(
        &self,
        store: PersistBlobStore,
    ) -> Result<MutexGuard<'_, ()>, PersistBlobPackError> {
        self.lock_blob_store(store)
            .map_err(|_| PersistBlobPackError::WriteLockPoisoned { store })
    }

    fn lock_blob_index(
        &self,
        store: PersistBlobStore,
    ) -> Result<MutexGuard<'_, ()>, PersistBlobIndexError> {
        self.lock_blob_store(store)
            .map_err(|_| PersistBlobIndexError::WriteLockPoisoned { store })
    }

    fn lock_blob_store(
        &self,
        store: PersistBlobStore,
    ) -> Result<MutexGuard<'_, ()>, CacheRootLockError> {
        self.lock_slot(blob_store_lock_slot(store))
    }

    fn lock_slot(&self, slot: CacheRootLockSlot) -> Result<MutexGuard<'_, ()>, CacheRootLockError> {
        self.locks.lock(slot)
    }
}

fn blob_store_lock_slot(store: PersistBlobStore) -> CacheRootLockSlot {
    match store {
        PersistBlobStore::Values => CacheRootLockSlot::Values,
        PersistBlobStore::Files => CacheRootLockSlot::Files,
    }
}

impl PersistRootLocks {
    fn insert_pending_file_root(
        &self,
        root: PersistBlobLiveRoot,
    ) -> Result<(), PersistBlobPackError> {
        self.pending_file_roots
            .lock()
            .map_err(|_| PersistBlobPackError::WriteLockPoisoned {
                store: PersistBlobStore::Files,
            })?
            .insert(blob_live_root_identity(root), root);
        Ok(())
    }

    fn remove_pending_file_root(&self, root: PersistBlobLiveRoot) {
        let Ok(mut pending_roots) = self.pending_file_roots.lock() else {
            return;
        };
        pending_roots.remove(&blob_live_root_identity(root));
    }

    fn pending_file_roots(&self) -> Result<Vec<PersistBlobLiveRoot>, PersistBlobLiveRootError> {
        Ok(self
            .pending_file_roots
            .lock()
            .map_err(|_| PersistBlobLiveRootError::PendingFileRoots)?
            .values()
            .copied()
            .collect())
    }

    fn lock_file_artifacts(&self) -> Result<MutexGuard<'_, ()>, PersistFileArtifactIndexError> {
        self.lock_slot(CacheRootLockSlot::FileArtifacts)
            .map_err(|_| PersistFileArtifactIndexError::WriteLockPoisoned)
    }

    fn lock_parse_artifacts(&self) -> Result<MutexGuard<'_, ()>, PersistParseArtifactIndexError> {
        self.lock_slot(CacheRootLockSlot::ParseArtifacts)
            .map_err(|_| PersistParseArtifactIndexError::WriteLockPoisoned)
    }

    fn lock_node_metadata(&self) -> Result<MutexGuard<'_, ()>, PersistNodeMetadataIndexError> {
        self.lock_slot(CacheRootLockSlot::NodeMetadata)
            .map_err(|_| PersistNodeMetadataIndexError::WriteLockPoisoned)
    }

    fn lock_node_traces(&self) -> Result<MutexGuard<'_, ()>, PersistNodeTraceLogError> {
        self.lock_slot(CacheRootLockSlot::NodeTraces)
            .map_err(|_| PersistNodeTraceLogError::WriteLockPoisoned)
    }
}

static PERSIST_PENDING_FILE_ROOT_REGISTRY: OnceLock<
    Mutex<BTreeMap<PathBuf, Weak<PendingFileRoots>>>,
> = OnceLock::new();

fn root_locks_for_root(root: &Path) -> Result<Arc<PersistRootLocks>, PersistError> {
    let locks = engine_root_locks::locks_for_root(root).map_err(root_lock_registry_error)?;
    let pending_file_roots = pending_file_roots_for_canonical_root(locks.root())?;
    Ok(Arc::new(PersistRootLocks::new(locks, pending_file_roots)))
}

fn root_lock_registry_error(error: engine_root_locks::CacheRootLockRegistryError) -> PersistError {
    match error {
        engine_root_locks::CacheRootLockRegistryError::CanonicalizeRoot { path, source } => {
            PersistError::CanonicalizeRoot { path, source }
        }
        engine_root_locks::CacheRootLockRegistryError::RegistryPoisoned => {
            PersistError::RootLockRegistryPoisoned
        }
    }
}

fn pending_file_roots_for_canonical_root(
    root: &Path,
) -> Result<Arc<PendingFileRoots>, PersistError> {
    let registry = PERSIST_PENDING_FILE_ROOT_REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut pending_roots = registry
        .lock()
        .map_err(|_| PersistError::RootLockRegistryPoisoned)?;
    pending_roots.retain(|_, candidate| candidate.strong_count() > 0);
    if let Some(existing) = pending_roots.get(root).and_then(Weak::upgrade) {
        return Ok(existing);
    }

    let created = Arc::new(Mutex::new(BTreeMap::new()));
    pending_roots.insert(root.to_path_buf(), Arc::downgrade(&created));
    Ok(created)
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
    const fn new(
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
    const fn new(live_entries: usize, bytes_before: u64, bytes_after: u64) -> Self {
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
    const fn new(
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
    fn new(
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
    const fn new(
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
    fn new(
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
    const fn new(
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
    const fn new(node_key: PersistNodeMetadataKey, value_hash: ValueHash) -> Self {
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
    fn new(
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
    node_roots: Vec<PersistNodeValueRoot>,
    missing_node_roots: Vec<PersistMissingNodeValueRoot>,
    node_rooted_records: Vec<PersistBlobPackRecord>,
    indexed_unrooted_records: Vec<PersistBlobPackRecord>,
    unindexed_records: Vec<PersistBlobPackRecord>,
    bytes_before: u64,
    node_rooted_record_bytes: u64,
    indexed_unrooted_record_bytes: u64,
    unindexed_record_bytes: u64,
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
    file_artifact_roots: Vec<PersistBlobLiveRoot>,
    parse_artifact_roots: Vec<PersistBlobLiveRoot>,
    pending_artifact_roots: Vec<PersistBlobLiveRoot>,
    blob_index_roots: Vec<PersistBlobLiveRoot>,
    file_artifact_rooted_records: Vec<PersistBlobPackRecord>,
    parse_artifact_rooted_records: Vec<PersistBlobPackRecord>,
    pending_artifact_rooted_records: Vec<PersistBlobPackRecord>,
    indexed_unrooted_records: Vec<PersistBlobPackRecord>,
    unindexed_records: Vec<PersistBlobPackRecord>,
    bytes_before: u64,
    file_artifact_rooted_record_bytes: u64,
    parse_artifact_rooted_record_bytes: u64,
    pending_artifact_rooted_record_bytes: u64,
    indexed_unrooted_record_bytes: u64,
    unindexed_record_bytes: u64,
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
    fn new(
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
    fn new(
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
    fn new(sidecars: PersistCompaction, blob_packs: PersistBlobPacksRepack) -> Self {
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
    fn new(
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
    const fn new(
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

fn push_blob_index_roots(
    roots: &mut Vec<PersistBlobLiveRoot>,
    entries: Vec<PersistBlobIndexEntry>,
    expected_store: PersistBlobStore,
    source: PersistBlobLiveRootSource,
) -> Result<(), PersistBlobLiveRootError> {
    for entry in entries {
        let key = entry.key();
        let actual_store = key.store();
        if actual_store != expected_store {
            return Err(PersistBlobLiveRootError::WrongStoreEntry {
                expected: expected_store,
                actual: actual_store,
            });
        }
        roots.push(PersistBlobLiveRoot::new(source, key, entry.location()));
    }
    Ok(())
}

fn blob_record_identity(
    key: PersistBlobKey,
    location: PersistBlobLocation,
) -> ([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64) {
    (
        key.index_bytes(),
        location.record_offset(),
        location.payload_len(),
    )
}

fn blob_live_root_identity(
    root: PersistBlobLiveRoot,
) -> ([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64) {
    blob_record_identity(root.key(), root.location())
}

const fn blob_record_bytes(record: PersistBlobPackRecord) -> u64 {
    PERSIST_BLOB_RECORD_HEADER_LEN as u64 + record.location().payload_len()
}

fn blob_pack_repack_plan_from_liveness(
    store: PersistBlobStore,
    liveness: PersistBlobPackLivenessPlan,
) -> Result<PersistBlobPackRepackPlan, PersistBlobPackRepackPlanError> {
    let mut next_offset = PERSIST_BLOB_PACK_HEADER_LEN as u64;
    let mut record_relocations = Vec::new();
    for record in liveness.rooted_records() {
        let new_location = PersistBlobLocation::new(next_offset, record.location().payload_len());
        record_relocations.push(PersistBlobRecordRelocation::new(
            record.key(store),
            record.location(),
            new_location,
        ));
        let after_header = next_offset
            .checked_add(PERSIST_BLOB_RECORD_HEADER_LEN as u64)
            .ok_or(PersistBlobPackRepackPlanError::RecordBoundsOverflow {
                record_offset: next_offset,
                payload_len: record.location().payload_len(),
            })?;
        next_offset = after_header
            .checked_add(record.location().payload_len())
            .ok_or(PersistBlobPackRepackPlanError::RecordBoundsOverflow {
                record_offset: next_offset,
                payload_len: record.location().payload_len(),
            })?;
    }
    Ok(PersistBlobPackRepackPlan::new(
        liveness.live_roots().to_vec(),
        record_relocations,
        liveness.unrooted_records().to_vec(),
        liveness.bytes_before(),
        next_offset,
        liveness.rooted_record_bytes(),
        liveness.unrooted_record_bytes(),
    ))
}

fn write_repacked_blob_index(
    tmp_path: &Path,
    relocations: &[PersistBlobRecordRelocation],
) -> Result<(), PersistBlobIndexError> {
    let mut entries = relocations
        .iter()
        .map(|relocation| PersistBlobIndexEntry::new(relocation.key(), relocation.new_location()))
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.key().index_bytes());
    PersistBlobIndex::write_entries_to(tmp_path, &entries)?;
    Ok(())
}

fn file_relocation_locations(
    relocations: &[PersistBlobRecordRelocation],
) -> BTreeMap<([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64), PersistBlobLocation> {
    relocations
        .iter()
        .map(|relocation| {
            (
                blob_record_identity(relocation.key(), relocation.old_location()),
                relocation.new_location(),
            )
        })
        .collect()
}

fn relocate_file_artifact_entries(
    entries: Vec<PersistFileArtifactIndexEntry>,
    relocations: &BTreeMap<([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64), PersistBlobLocation>,
) -> Result<Vec<PersistFileArtifactIndexEntry>, PersistFileBlobPackRepackError> {
    entries
        .into_iter()
        .map(|entry| {
            let value = entry.value();
            let key = value.blob_key();
            let location = value.location();
            let Some(new_location) = relocations
                .get(&blob_record_identity(key, location))
                .copied()
            else {
                return Err(PersistFileBlobPackRepackError::MissingRelocation { key, location });
            };
            Ok(PersistFileArtifactIndexEntry::new(
                entry.key(),
                PersistFileArtifactIndexValue::new(value.blob_hash(), new_location),
            ))
        })
        .collect()
}

fn relocate_parse_artifact_entries(
    entries: Vec<PersistParseArtifactIndexEntry>,
    relocations: &BTreeMap<([u8; PERSIST_BLOB_INDEX_KEY_LEN], u64, u64), PersistBlobLocation>,
) -> Result<Vec<PersistParseArtifactIndexEntry>, PersistFileBlobPackRepackError> {
    entries
        .into_iter()
        .map(|entry| {
            let value = entry.value();
            let key = value.blob_key();
            let location = value.location();
            let Some(new_location) = relocations
                .get(&blob_record_identity(key, location))
                .copied()
            else {
                return Err(PersistFileBlobPackRepackError::MissingRelocation { key, location });
            };
            Ok(PersistParseArtifactIndexEntry::new(
                entry.key(),
                PersistParseArtifactIndexValue::new(value.blob_hash(), new_location),
            ))
        })
        .collect()
}

fn write_repacked_file_artifact_index(
    tmp_path: &Path,
    entries: &[PersistFileArtifactIndexEntry],
) -> Result<(), PersistFileArtifactIndexError> {
    PersistFileArtifactIndex::write_entries_to(tmp_path, entries)?;
    Ok(())
}

fn write_repacked_parse_artifact_index(
    tmp_path: &Path,
    entries: &[PersistParseArtifactIndexEntry],
) -> Result<(), PersistParseArtifactIndexError> {
    PersistParseArtifactIndex::write_entries_to(tmp_path, entries)?;
    Ok(())
}

fn swap_repacked_value_store(
    replacements: &FileReplacementSet,
) -> Result<(), PersistValueBlobPackRepackError> {
    replacements
        .replace_all()
        .map_err(value_repack_replacement_error_to_persist)
}

const VALUE_REPACK_PACK_REPLACEMENT: usize = 0;
const VALUE_REPACK_INDEX_REPLACEMENT: usize = 1;

fn value_repack_replacements(
    pack_path: &Path,
    index_path: &Path,
    tmp_pack_path: &Path,
    tmp_index_path: &Path,
    rewrite_id: u64,
) -> FileReplacementSet {
    FileReplacementSet::new([
        FileReplacement::new(
            pack_path.to_path_buf(),
            tmp_pack_path.to_path_buf(),
            pack_path.with_extension(format!(
                "repack-backup-pack-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            index_path.to_path_buf(),
            tmp_index_path.to_path_buf(),
            index_path.with_extension(format!(
                "repack-backup-index-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
    ])
}

fn value_repack_replacement_error_to_persist(
    error: FileReplacementError,
) -> PersistValueBlobPackRepackError {
    match error {
        FileReplacementError::RemoveBackup {
            index,
            path,
            source,
        } => value_repack_file_error(index, path, source),
        FileReplacementError::BackupTarget {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::InstallStaged {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::RemoveTargetBeforeRestore {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::RestoreBackup {
            index,
            target: path,
            source,
            ..
        } => value_repack_file_error(index, path, source),
    }
}

fn value_repack_file_error(
    index: usize,
    path: PathBuf,
    source: io::Error,
) -> PersistValueBlobPackRepackError {
    match index {
        VALUE_REPACK_PACK_REPLACEMENT => PersistValueBlobPackRepackError::Pack {
            source: PersistBlobPackError::Write { path, source },
        },
        VALUE_REPACK_INDEX_REPLACEMENT => PersistValueBlobPackRepackError::BlobIndex {
            source: PersistBlobIndexError::Write { path, source },
        },
        _ => PersistValueBlobPackRepackError::BlobIndex {
            source: PersistBlobIndexError::Write { path, source },
        },
    }
}

#[derive(Clone, Copy)]
struct FileRepackPaths<'a> {
    pack: &'a Path,
    blob_index: &'a Path,
    file_artifact_index: &'a Path,
    parse_artifact_index: &'a Path,
}

#[derive(Clone, Copy)]
struct FileRepackStagePaths<'a> {
    pack: &'a Path,
    blob_index: &'a Path,
    file_artifact_index: &'a Path,
    parse_artifact_index: &'a Path,
}

fn swap_repacked_file_store(
    replacements: &FileReplacementSet,
) -> Result<(), PersistFileBlobPackRepackError> {
    replacements
        .replace_all()
        .map_err(file_repack_replacement_error_to_persist)
}

const FILE_REPACK_PACK_REPLACEMENT: usize = 0;
const FILE_REPACK_BLOB_INDEX_REPLACEMENT: usize = 1;
const FILE_REPACK_FILE_ARTIFACT_REPLACEMENT: usize = 2;
const FILE_REPACK_PARSE_ARTIFACT_REPLACEMENT: usize = 3;

fn file_repack_replacements(
    paths: FileRepackPaths<'_>,
    stage: FileRepackStagePaths<'_>,
    rewrite_id: u64,
) -> FileReplacementSet {
    FileReplacementSet::new([
        FileReplacement::new(
            paths.pack.to_path_buf(),
            stage.pack.to_path_buf(),
            paths.pack.with_extension(format!(
                "repack-backup-pack-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            paths.blob_index.to_path_buf(),
            stage.blob_index.to_path_buf(),
            paths.blob_index.with_extension(format!(
                "repack-backup-index-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            paths.file_artifact_index.to_path_buf(),
            stage.file_artifact_index.to_path_buf(),
            paths.file_artifact_index.with_extension(format!(
                "repack-backup-file-artifacts-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
        FileReplacement::new(
            paths.parse_artifact_index.to_path_buf(),
            stage.parse_artifact_index.to_path_buf(),
            paths.parse_artifact_index.with_extension(format!(
                "repack-backup-parse-artifacts-{}-{rewrite_id}.tmp",
                std::process::id()
            )),
        ),
    ])
}

fn file_repack_replacement_error_to_persist(
    error: FileReplacementError,
) -> PersistFileBlobPackRepackError {
    match error {
        FileReplacementError::RemoveBackup {
            index,
            path,
            source,
        } => file_repack_file_error(index, path, source),
        FileReplacementError::BackupTarget {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::InstallStaged {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::RemoveTargetBeforeRestore {
            index,
            target: path,
            source,
            ..
        }
        | FileReplacementError::RestoreBackup {
            index,
            target: path,
            source,
            ..
        } => file_repack_file_error(index, path, source),
    }
}

fn file_repack_file_error(
    index: usize,
    path: PathBuf,
    source: io::Error,
) -> PersistFileBlobPackRepackError {
    match index {
        FILE_REPACK_PACK_REPLACEMENT => PersistFileBlobPackRepackError::Pack {
            source: PersistBlobPackError::Write { path, source },
        },
        FILE_REPACK_BLOB_INDEX_REPLACEMENT => PersistFileBlobPackRepackError::BlobIndex {
            source: PersistBlobIndexError::Write { path, source },
        },
        FILE_REPACK_FILE_ARTIFACT_REPLACEMENT => {
            PersistFileBlobPackRepackError::FileArtifactIndex {
                source: PersistFileArtifactIndexError::Write { path, source },
            }
        }
        FILE_REPACK_PARSE_ARTIFACT_REPLACEMENT => {
            PersistFileBlobPackRepackError::ParseArtifactIndex {
                source: PersistParseArtifactIndexError::Write { path, source },
            }
        }
        _ => {
            debug_assert!(
                index <= FILE_REPACK_PARSE_ARTIFACT_REPLACEMENT,
                "unexpected file repack replacement index {index}"
            );
            PersistFileBlobPackRepackError::ParseArtifactIndex {
                source: PersistParseArtifactIndexError::Write { path, source },
            }
        }
    }
}

impl PersistCache {
    /// Opens or initializes a persistent eval-cache root.
    ///
    /// A matching schema preserves existing payload directories. A well-formed
    /// mismatched schema discards `nodes/`, `values/`, and `files/` before
    /// rewriting current metadata. Malformed schema metadata is reported as an
    /// error and is not discarded.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if the cache root cannot be created or
    /// canonicalized, schema metadata cannot be read, parsed, or written, cache
    /// payload directories cannot be created or discarded, the process-local
    /// root-lock registry is poisoned, the cross-process advisory open lock
    /// cannot be acquired, the same-root open lock is poisoned, or packfiles or
    /// sidecar indexes cannot be initialized.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PersistError> {
        let layout = PersistLayout::new(root);
        ensure_root_dir(layout.root())?;
        let layout = PersistLayout::new(fs::canonicalize(layout.root()).map_err(|source| {
            PersistError::CanonicalizeRoot {
                path: layout.root().to_path_buf(),
                source,
            }
        })?);
        let root_locks = root_locks_for_root(layout.root())?;
        let open_lock_path = layout.open_lock_path();
        let _open_advisory_guard =
            AdvisoryFileLock::lock(open_lock_path.clone(), AdvisoryFileLockMode::Exclusive)
                .map_err(|source| PersistError::OpenAdvisoryLock {
                    path: open_lock_path,
                    source,
                })?;
        let open_guard = root_locks.lock_open()?;
        match read_schema_version(&layout)? {
            Some(PERSIST_CACHE_SCHEMA_VERSION) => {
                ensure_payload_dirs(&layout)?;
            }
            Some(_) => {
                discard_payload_dirs(&layout)?;
                ensure_payload_dirs(&layout)?;
                write_schema(&layout)?;
            }
            None => {
                ensure_payload_dirs(&layout)?;
                write_schema(&layout)?;
            }
        }
        let value_pack_path = layout.value_packfile_path();
        let value_pack = PersistBlobPack::open(value_pack_path.clone()).map_err(|source| {
            PersistError::OpenBlobPack {
                path: value_pack_path,
                source,
            }
        })?;
        let file_pack_path = layout.file_packfile_path();
        let file_pack = PersistBlobPack::open(file_pack_path.clone()).map_err(|source| {
            PersistError::OpenBlobPack {
                path: file_pack_path,
                source,
            }
        })?;
        let value_index_path = layout.value_index_path();
        let value_index = PersistBlobIndex::open(value_index_path.clone()).map_err(|source| {
            PersistError::OpenBlobIndex {
                path: value_index_path,
                source,
            }
        })?;
        let file_index_path = layout.file_index_path();
        let file_index = PersistBlobIndex::open(file_index_path.clone()).map_err(|source| {
            PersistError::OpenBlobIndex {
                path: file_index_path,
                source,
            }
        })?;
        let file_artifact_index_path = layout.file_artifact_index_path();
        let file_artifact_index = PersistFileArtifactIndex::open(file_artifact_index_path.clone())
            .map_err(|source| PersistError::OpenFileArtifactIndex {
                path: file_artifact_index_path,
                source,
            })?;
        let parse_artifact_index_path = layout.parse_artifact_index_path();
        let parse_artifact_index = PersistParseArtifactIndex::open(
            parse_artifact_index_path.clone(),
        )
        .map_err(|source| PersistError::OpenParseArtifactIndex {
            path: parse_artifact_index_path,
            source,
        })?;
        let node_metadata_index_path = layout.node_metadata_index_path();
        let node_metadata_index = PersistNodeMetadataIndex::open(node_metadata_index_path.clone())
            .map_err(|source| PersistError::OpenNodeMetadataIndex {
                path: node_metadata_index_path,
                source,
            })?;
        let node_trace_log_path = layout.node_trace_log_path();
        let node_trace_log =
            PersistNodeTraceLog::open(node_trace_log_path.clone()).map_err(|source| {
                PersistError::OpenNodeTraceLog {
                    path: node_trace_log_path,
                    source,
                }
            })?;
        drop(open_guard);
        Ok(Self {
            layout,
            value_pack,
            file_pack,
            value_index,
            file_index,
            file_artifact_index,
            parse_artifact_index,
            node_metadata_index,
            node_trace_log,
            root_locks,
        })
    }

    #[cfg(test)]
    pub(super) fn lock_open_for_tests(&self) -> Result<MutexGuard<'_, ()>, PersistError> {
        self.root_locks.lock_open()
    }

    #[cfg(test)]
    pub(super) fn lock_blob_materialization_for_tests(
        &self,
        store: PersistBlobStore,
    ) -> Result<MutexGuard<'_, ()>, PersistBlobIndexedWriteError> {
        self.root_locks.lock(store)
    }

    #[cfg(test)]
    pub(super) fn lock_file_artifacts_for_tests(
        &self,
    ) -> Result<MutexGuard<'_, ()>, PersistFileArtifactIndexError> {
        self.root_locks.lock_file_artifacts()
    }

    #[cfg(test)]
    pub(super) fn lock_parse_artifacts_for_tests(
        &self,
    ) -> Result<MutexGuard<'_, ()>, PersistParseArtifactIndexError> {
        self.root_locks.lock_parse_artifacts()
    }

    #[cfg(test)]
    pub(super) fn lock_node_metadata_for_tests(
        &self,
    ) -> Result<MutexGuard<'_, ()>, PersistNodeMetadataIndexError> {
        self.root_locks.lock_node_metadata()
    }

    #[cfg(test)]
    pub(super) fn lock_node_traces_for_tests(
        &self,
    ) -> Result<MutexGuard<'_, ()>, PersistNodeTraceLogError> {
        self.root_locks.lock_node_traces()
    }

    /// Compacts every current append-only sidecar to its newest entries.
    ///
    /// This explicit maintenance operation rewrites the value and file blob
    /// indexes, file-artifact and parse-artifact indexes, demand-node metadata
    /// index, and node verifying-trace log. The blob-index, artifact-mapping,
    /// node-metadata, and node-trace compaction phases use per-sidecar
    /// advisory locks. This does not rewrite blob packs, drop unreferenced
    /// blobs, coordinate raw lower-level sidecar users, or implement an
    /// automatic GC policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCompactionError`] identifying the sidecar whose
    /// compaction failed. Sidecars compacted before the failure remain
    /// rewritten; later sidecars are not attempted.
    pub fn compact_sidecars(&self) -> Result<PersistCompaction, PersistCompactionError> {
        let value_blob_index_entries = self
            .compact_blob_index(PersistBlobStore::Values)
            .map_err(|source| PersistCompactionError::ValueBlobIndex { source })?;
        let file_blob_index_entries = self
            .compact_blob_index(PersistBlobStore::Files)
            .map_err(|source| PersistCompactionError::FileBlobIndex { source })?;
        let file_artifact_entries = self
            .compact_file_artifact_index()
            .map_err(|source| PersistCompactionError::FileArtifactIndex { source })?;
        let parse_artifact_entries = self
            .compact_parse_artifact_index()
            .map_err(|source| PersistCompactionError::ParseArtifactIndex { source })?;
        let node_metadata_entries = self
            .compact_node_metadata()
            .map_err(|source| PersistCompactionError::NodeMetadataIndex { source })?;
        let node_trace_entries = self
            .compact_node_traces()
            .map_err(|source| PersistCompactionError::NodeTraceLog { source })?;
        Ok(PersistCompaction::new(
            value_blob_index_entries,
            file_blob_index_entries,
            file_artifact_entries,
            parse_artifact_entries,
            node_metadata_entries,
            node_trace_entries,
        ))
    }

    /// Runs explicit persistent storage maintenance.
    ///
    /// This caller-driven sweep first compacts append-only sidecars to their
    /// latest entries, rebuilds both blob-index sidecars from verified physical
    /// pack scans, then trims tails from the `values/` and `files/` blob packs
    /// when their records still have no live index roots after rebuild. The
    /// rebuild phase indexes every verified newest physical record, so
    /// previously unindexed tails can become roots instead of reclaimed bytes.
    /// It is sequential and non-transactional: work completed before a later
    /// phase fails remains committed. It does not implement an automatic GC
    /// policy, relocate live pack records, coordinate raw lower-level pack or
    /// sidecar users, or replace the future LMDB/redb metadata engine. Only
    /// the blob-index compaction/rebuild, file/parse artifact compaction,
    /// node-metadata compaction, node-trace compaction, and blob-pack
    /// tail-trim phases use advisory locks.
    ///
    /// # Errors
    ///
    /// Returns [`PersistStorageMaintenanceError`] identifying the phase that
    /// failed. Earlier phases may already have rewritten sidecars or trimmed a
    /// blob pack.
    pub fn compact_storage(
        &self,
    ) -> Result<PersistStorageMaintenance, PersistStorageMaintenanceError> {
        let sidecars = self
            .compact_sidecars()
            .map_err(|source| PersistStorageMaintenanceError::Sidecars { source })?;
        let blob_indexes = self
            .rebuild_blob_indexes_from_packs()
            .map_err(|source| PersistStorageMaintenanceError::BlobIndexes { source })?;
        let value_blob_pack = self
            .trim_blob_pack_tail(PersistBlobStore::Values)
            .map_err(|source| PersistStorageMaintenanceError::ValueBlobPack { source })?;
        let file_blob_pack = self
            .trim_blob_pack_tail(PersistBlobStore::Files)
            .map_err(|source| PersistStorageMaintenanceError::FileBlobPack { source })?;
        Ok(PersistStorageMaintenance::new(
            sidecars,
            blob_indexes,
            value_blob_pack,
            file_blob_pack,
        ))
    }

    /// Runs explicit persistent storage repacking.
    ///
    /// This caller-driven sweep compacts append-only sidecars to their latest
    /// entries, then runs [`Self::repack_blob_packs`] against the current live
    /// roots. Unlike [`Self::compact_storage`], it does not rebuild blob-index
    /// sidecars from physical pack scans before planning, so unindexed pack
    /// records stay unrooted and can be omitted by the repack. It is sequential
    /// and non-transactional: sidecar compaction remains committed if a later
    /// pack repack fails, and value-pack rewrites may remain committed if the
    /// file-pack repack fails. The blob-pack repack phases use each selected
    /// store's advisory lock file, and file-pack repack also uses file/parse
    /// artifact advisory locks. It does not implement an automatic GC policy,
    /// coordinate raw lower-level pack or sidecar users or cross-process
    /// pending artifact publication, or replace the future LMDB/redb metadata
    /// engine.
    ///
    /// # Errors
    ///
    /// Returns [`PersistStorageRepackError`] identifying the phase that failed.
    /// Earlier phases may already have rewritten sidecars or repacked a blob
    /// pack.
    pub fn repack_storage(&self) -> Result<PersistStorageRepack, PersistStorageRepackError> {
        let sidecars = self
            .compact_sidecars()
            .map_err(|source| PersistStorageRepackError::Sidecars { source })?;
        let blob_packs = self
            .repack_blob_packs()
            .map_err(|source| PersistStorageRepackError::BlobPacks { source })?;
        Ok(PersistStorageRepack::new(sidecars, blob_packs))
    }

    /// Returns this cache's canonicalized filesystem layout.
    pub const fn layout(&self) -> &PersistLayout {
        &self.layout
    }

    /// Returns the immutable value blob packfile.
    pub const fn value_pack(&self) -> &PersistBlobPack {
        &self.value_pack
    }

    /// Returns the immutable file/frontend artifact blob packfile.
    pub const fn file_pack(&self) -> &PersistBlobPack {
        &self.file_pack
    }

    /// Returns the fixed-record blob index for serialized value blobs.
    pub const fn value_index(&self) -> &PersistBlobIndex {
        &self.value_index
    }

    /// Returns the fixed-record blob index for serialized file blobs.
    pub const fn file_index(&self) -> &PersistBlobIndex {
        &self.file_index
    }

    /// Returns the fixed-record index for durable file-artifact mappings.
    pub const fn file_artifact_index(&self) -> &PersistFileArtifactIndex {
        &self.file_artifact_index
    }

    /// Returns the fixed-record index for durable parse-artifact mappings.
    pub const fn parse_artifact_index(&self) -> &PersistParseArtifactIndex {
        &self.parse_artifact_index
    }

    /// Returns the fixed-record index for durable demand-node metadata.
    pub const fn node_metadata_index(&self) -> &PersistNodeMetadataIndex {
        &self.node_metadata_index
    }

    /// Returns the append-only log for durable demand-node traces.
    pub const fn node_trace_log(&self) -> &PersistNodeTraceLog {
        &self.node_trace_log
    }

    /// Returns the fixed-record blob index for `store`.
    pub const fn blob_index(&self, store: PersistBlobStore) -> &PersistBlobIndex {
        match store {
            PersistBlobStore::Values => &self.value_index,
            PersistBlobStore::Files => &self.file_index,
        }
    }

    /// Returns the immutable blob packfile for `store`.
    pub fn blob_pack(&self, store: PersistBlobStore) -> &PersistBlobPack {
        match store {
            PersistBlobStore::Values => &self.value_pack,
            PersistBlobStore::Files => &self.file_pack,
        }
    }

    fn lock_indexed_blob_write(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobIndexedWriteError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobIndexedWriteError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self.root_locks.lock(store)?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_blob_pack_write(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobPackError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobPackError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self.root_locks.lock_blob_pack(store)?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_blob_index_write(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobIndexError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobIndexError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self.root_locks.lock_blob_index(store)?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_blob_index_rebuild(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobIndexRebuildError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobIndexRebuildError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self
            .root_locks
            .lock_blob_store(store)
            .map_err(|_| PersistBlobIndexRebuildError::WriteLockPoisoned { store })?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_blob_pack_tail_trim(
        &self,
        store: PersistBlobStore,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistBlobPackTrimError> {
        let path = self.layout.blob_store_lock_path(store);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistBlobPackTrimError::AdvisoryWriteLock {
                store,
                path,
                source,
            })?;
        let write_guard = self
            .root_locks
            .lock_blob_index(store)
            .map_err(|source| PersistBlobPackTrimError::BlobIndex { source })?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_value_blob_pack_repack(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistValueBlobPackRepackError> {
        let path = self.layout.blob_store_lock_path(PersistBlobStore::Values);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(
                |source| PersistValueBlobPackRepackError::AdvisoryWriteLock { path, source },
            )?;
        let write_guard = self
            .root_locks
            .lock_blob_store(PersistBlobStore::Values)
            .map_err(|_| PersistValueBlobPackRepackError::WriteLockPoisoned)?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_file_blob_pack_repack(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistFileBlobPackRepackError> {
        let path = self.layout.blob_store_lock_path(PersistBlobStore::Files);
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistFileBlobPackRepackError::AdvisoryWriteLock { path, source })?;
        let write_guard = self
            .root_locks
            .lock_blob_store(PersistBlobStore::Files)
            .map_err(|_| PersistFileBlobPackRepackError::WriteLockPoisoned)?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_file_artifact_write(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistFileArtifactIndexError> {
        let path = self.layout.file_artifact_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistFileArtifactIndexError::AdvisoryWriteLock { path, source })?;
        let write_guard = self.root_locks.lock_file_artifacts()?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_parse_artifact_write(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistParseArtifactIndexError> {
        let path = self.layout.parse_artifact_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistParseArtifactIndexError::AdvisoryWriteLock { path, source })?;
        let write_guard = self.root_locks.lock_parse_artifacts()?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_node_metadata_write(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistNodeMetadataIndexError> {
        let path = self.layout.node_metadata_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistNodeMetadataIndexError::AdvisoryWriteLock { path, source })?;
        let write_guard = self.root_locks.lock_node_metadata()?;
        Ok((advisory_guard, write_guard))
    }

    fn lock_node_traces_write(
        &self,
    ) -> Result<(AdvisoryFileLock, MutexGuard<'_, ()>), PersistNodeTraceLogError> {
        let path = self.layout.node_traces_lock_path();
        let advisory_guard = AdvisoryFileLock::lock(path.clone(), AdvisoryFileLockMode::Exclusive)
            .map_err(|source| PersistNodeTraceLogError::AdvisoryWriteLock { path, source })?;
        let write_guard = self.root_locks.lock_node_traces()?;
        Ok((advisory_guard, write_guard))
    }

    /// Appends a blob to the packfile selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected advisory lock cannot
    /// be acquired, the same-root blob-pack write lock is poisoned, the
    /// selected packfile cannot be opened, validated, or written, or if
    /// `payload` does not hash to `key.hash()`.
    pub fn append_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        let (_advisory_guard, _write_guard) = self.lock_blob_pack_write(key.store())?;
        self.append_blob_unlocked(key, payload)
    }

    fn append_blob_unlocked(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        self.blob_pack(key.store()).append_blob(key.hash(), payload)
    }

    fn append_pending_file_artifact_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        source: PersistBlobLiveRootSource,
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        let (_advisory_guard, _write_guard) = self.lock_blob_pack_write(PersistBlobStore::Files)?;
        let location = self.append_blob_unlocked(key, payload)?;
        self.root_locks
            .insert_pending_file_root(PersistBlobLiveRoot::new(source, key, location))?;
        Ok(location)
    }

    /// Reads a blob from the packfile selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected packfile cannot be
    /// opened or read, if `location` is invalid, or if record/payload hashes do
    /// not match `key.hash()`.
    pub fn read_blob(
        &self,
        key: PersistBlobKey,
        location: PersistBlobLocation,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.blob_pack(key.store()).read_blob(location, key.hash())
    }

    /// Appends a durable file-artifact mapping entry to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the advisory mapping lock
    /// cannot be acquired, if the same-root file-artifact write lock is
    /// poisoned, or if the sidecar index cannot be opened, validated, written,
    /// or flushed.
    pub fn record_file_artifact(
        &self,
        entry: PersistFileArtifactIndexEntry,
    ) -> Result<(), PersistFileArtifactIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_file_artifact_write()?;
        self.file_artifact_index.append_entry(entry)?;
        let value = entry.value();
        self.root_locks
            .remove_pending_file_root(PersistBlobLiveRoot::new(
                PersistBlobLiveRootSource::PendingFileArtifact,
                value.blob_key(),
                value.location(),
            ));
        Ok(())
    }

    /// Looks up a durable file-artifact mapping through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`. Same-process file-artifact
    /// writers and file-pack repacks for the same cache root share the
    /// file-artifact mapping lock while this sidecar is read. This is still a
    /// raw mapping lookup: callers that need the returned location to remain
    /// consistent with a following `files/` pack read must hold the file-store
    /// lock across both operations or use the higher-level hydration helpers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the same-root
    /// file-artifact lock is poisoned or if the sidecar index cannot be opened,
    /// read, or decoded.
    pub fn lookup_file_artifact(
        &self,
        key: PersistFileArtifactKey,
    ) -> Result<Option<PersistFileArtifactIndexValue>, PersistFileArtifactIndexError> {
        let _read_guard = self.root_locks.lock_file_artifacts()?;
        self.file_artifact_index.lookup(key)
    }

    /// Appends a durable parse-artifact mapping entry to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the advisory mapping lock
    /// cannot be acquired, if the same-root parse-artifact write lock is
    /// poisoned, or if the sidecar index cannot be opened, validated, written,
    /// or flushed.
    pub fn record_parse_artifact(
        &self,
        entry: PersistParseArtifactIndexEntry,
    ) -> Result<(), PersistParseArtifactIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_parse_artifact_write()?;
        self.parse_artifact_index.append_entry(entry)?;
        let value = entry.value();
        self.root_locks
            .remove_pending_file_root(PersistBlobLiveRoot::new(
                PersistBlobLiveRootSource::PendingParseArtifact,
                value.blob_key(),
                value.location(),
            ));
        Ok(())
    }

    /// Looks up a durable parse-artifact mapping through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`. Same-process parse-artifact
    /// writers and file-pack repacks for the same cache root share the
    /// parse-artifact mapping lock while this sidecar is read. This is still a
    /// raw mapping lookup: callers that need the returned location to remain
    /// consistent with a following `files/` pack read must hold the file-store
    /// lock across both operations or use the higher-level hydration helpers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the same-root
    /// parse-artifact lock is poisoned or if the sidecar index cannot be
    /// opened, read, or decoded.
    pub fn lookup_parse_artifact(
        &self,
        key: PersistParseArtifactKey,
    ) -> Result<Option<PersistParseArtifactIndexValue>, PersistParseArtifactIndexError> {
        let _read_guard = self.root_locks.lock_parse_artifacts()?;
        self.parse_artifact_index.lookup(key)
    }

    /// Compacts file-artifact mappings to the newest entry for every known key.
    ///
    /// Cache-level writers opened on the same cache root share the
    /// file-artifact advisory lock and same-root write lock while this method
    /// rewrites the sidecar. Raw lower-level sidecar users and unrelated
    /// maintenance writers must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the advisory mapping lock
    /// cannot be acquired, if the same-root file-artifact write lock is
    /// poisoned, or if the sidecar index cannot be created, opened, inspected,
    /// read, decoded, written, flushed, or renamed into place.
    pub fn compact_file_artifact_index(&self) -> Result<usize, PersistFileArtifactIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_file_artifact_write()?;
        self.file_artifact_index.compact_latest_entries()
    }

    /// Compacts parse-artifact mappings to the newest entry for every known key.
    ///
    /// Cache-level writers opened on the same cache root share the
    /// parse-artifact advisory lock and same-root write lock while this method
    /// rewrites the sidecar. Raw lower-level sidecar users and unrelated
    /// maintenance writers must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the advisory mapping lock
    /// cannot be acquired, if the same-root parse-artifact write lock is
    /// poisoned, or if the sidecar index cannot be created, opened, inspected,
    /// read, decoded, written, flushed, or renamed into place.
    pub fn compact_parse_artifact_index(&self) -> Result<usize, PersistParseArtifactIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_parse_artifact_write()?;
        self.parse_artifact_index.compact_latest_entries()
    }

    /// Appends durable demand-node metadata to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, validated, written, or flushed.
    pub fn record_node_metadata(
        &self,
        entry: PersistNodeMetadataIndexEntry,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        self.record_node_metadata_unlocked(entry)
    }

    fn record_node_metadata_unlocked(
        &self,
        entry: PersistNodeMetadataIndexEntry,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        self.node_metadata_index.append_entry(entry)
    }

    /// Looks up durable demand-node metadata through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn lookup_node_metadata(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeMetadataIndexValue>, PersistNodeMetadataIndexError> {
        self.lookup_node_metadata_unlocked(key)
    }

    fn lookup_node_metadata_unlocked(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeMetadataIndexValue>, PersistNodeMetadataIndexError> {
        self.node_metadata_index.lookup(key)
    }

    /// Appends a durable verifying-trace payload for one materialized demand node.
    ///
    /// The trace log is append-only and newest-record-wins on lookup.
    /// Cache-level writers share the node-trace advisory lock and same-root
    /// trace write lock while appending. Raw lower-level log users must still
    /// be excluded by the caller. The caller supplies the materialized value
    /// hash so future hit selection can reject stale trace/value pairings.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the advisory trace lock cannot
    /// be acquired, if the same-root trace write lock is poisoned, or if the
    /// trace log cannot be opened, validated, written, flushed, or decoded
    /// during validation.
    pub fn record_node_trace(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
        payload: &PersistNodeTracePayload,
    ) -> Result<(), PersistNodeTraceLogError> {
        let (_advisory_guard, _write_guard) = self.lock_node_traces_write()?;
        self.node_trace_log.append_trace(key, value_hash, payload)
    }

    /// Appends a trace tombstone for one demand node.
    ///
    /// The tombstone becomes the newest trace record for `key`, so durable
    /// trace-verified loads miss even if older trace records still carry the
    /// same materialized value hash.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the advisory trace lock cannot
    /// be acquired, if the same-root trace write lock is poisoned, or if the
    /// trace log cannot be opened, validated, written, flushed, or decoded
    /// during validation.
    pub fn record_node_trace_tombstone(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<(), PersistNodeTraceLogError> {
        let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(
            b"aos-nix-node-trace-tombstone-v1",
        ));
        self.record_node_trace(key, value_hash, &PersistNodeTracePayload::tombstone())
    }

    /// Looks up the newest durable verifying-trace record for one demand node.
    ///
    /// Missing trace records return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the trace log cannot be opened,
    /// read, or decoded.
    pub fn lookup_node_trace(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        self.node_trace_log.lookup(key)
    }

    /// Compacts node traces to the newest record for every known demand node.
    ///
    /// Cache-level writers share the node-trace advisory lock and same-root
    /// trace write lock while this method rewrites the log. Raw lower-level
    /// log users must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the advisory trace lock cannot
    /// be acquired, if the same-root trace write lock is poisoned, or if the
    /// trace log cannot be opened, read, decoded, written, flushed, or renamed
    /// into place.
    pub fn compact_node_traces(&self) -> Result<usize, PersistNodeTraceLogError> {
        let (_advisory_guard, _write_guard) = self.lock_node_traces_write()?;
        self.node_trace_log.compact_latest_entries()
    }

    /// Appends materialization reuse counters for one demand node.
    ///
    /// Existing materialized value-hash metadata for the same node is
    /// preserved in the appended record. Missing metadata starts from an empty
    /// value-hash link.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn record_node_materialization_reuse(
        &self,
        key: PersistNodeMetadataKey,
        reuse: MaterializationReuse,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let value = self
            .lookup_node_metadata_unlocked(key)?
            .unwrap_or_else(|| PersistNodeMetadataIndexValue::new(MaterializationReuse::default()))
            .with_materialization_reuse(reuse);
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(key, value))
    }

    /// Looks up materialization reuse counters for one demand node.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn lookup_node_materialization_reuse(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<MaterializationReuse>, PersistNodeMetadataIndexError> {
        Ok(self
            .lookup_node_metadata(key)?
            .map(PersistNodeMetadataIndexValue::materialization_reuse))
    }

    /// Records the newest materialized value hash for one demand node.
    ///
    /// Existing materialization reuse counters for the same node are preserved
    /// in the appended metadata record. Missing metadata starts from empty
    /// reuse counters.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn record_node_materialized_value_hash(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let value = self
            .lookup_node_metadata_unlocked(key)?
            .unwrap_or_else(|| PersistNodeMetadataIndexValue::new(MaterializationReuse::default()))
            .with_value_hash(value_hash);
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(key, value))
    }

    /// Clears the newest materialized value hash for one demand node.
    ///
    /// Existing materialization reuse counters for the same node are preserved
    /// in the appended metadata record. Missing metadata or metadata that
    /// already has no materialized value hash returns `Ok(false)` without
    /// appending a record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn clear_node_materialized_value_hash(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<bool, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let Some(value) = self.lookup_node_metadata_unlocked(key)? else {
            return Ok(false);
        };
        if value.materialized_value_hash().is_none() {
            return Ok(false);
        }
        let value = PersistNodeMetadataIndexValue::new(value.materialization_reuse());
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(key, value))?;
        Ok(true)
    }

    /// Looks up the newest materialized value hash for one demand node.
    ///
    /// Missing node metadata and metadata without a materialized value hash
    /// both return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn lookup_node_materialized_value_hash(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<ValueHash>, PersistNodeMetadataIndexError> {
        Ok(self
            .lookup_node_metadata(key)?
            .and_then(PersistNodeMetadataIndexValue::materialized_value_hash))
    }

    /// Plans node-metadata value roots for future persistent value GC.
    ///
    /// This read-only diagnostic snapshots the latest demand-node metadata
    /// records plus the latest `values/` blob-index entries, resolves each
    /// materialized value hash through that value-index snapshot, and verifies
    /// resolved pack records without materializing payloads. Metadata records
    /// without a value hash are ignored. Metadata
    /// links whose value hash is missing from the blob index are reported as
    /// missing roots. The method does not rewrite sidecars, choose a retention
    /// window, delete blobs, relocate records, or coordinate with cross-process
    /// writers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeValueRootPlanError`] if the same-root value-index
    /// or node-metadata lock is poisoned, if either sidecar cannot be
    /// snapshotted, or if a blob location selected by node metadata cannot be
    /// verified against the linked value hash.
    pub fn plan_node_value_roots(
        &self,
    ) -> Result<PersistNodeValueRootPlan, PersistNodeValueRootPlanError> {
        let _value_guard = self
            .root_locks
            .lock_blob_index(PersistBlobStore::Values)
            .map_err(|source| PersistNodeValueRootPlanError::BlobIndex { source })?;
        let _metadata_guard = self
            .root_locks
            .lock_node_metadata()
            .map_err(|source| PersistNodeValueRootPlanError::Metadata { source })?;
        let metadata_entries = self
            .node_metadata_index
            .latest_entries()
            .map_err(|source| PersistNodeValueRootPlanError::Metadata { source })?;
        let value_entries = self
            .value_index
            .latest_entries()
            .map_err(|source| PersistNodeValueRootPlanError::BlobIndex { source })?;
        let mut value_locations = BTreeMap::new();
        for entry in value_entries {
            value_locations.insert(entry.key().index_bytes(), entry.location());
        }
        let mut resolved_roots = Vec::new();
        let mut missing_roots = Vec::new();
        for entry in metadata_entries {
            let Some(value_hash) = entry.value().materialized_value_hash() else {
                continue;
            };
            let blob_key = PersistBlobKey::for_value(value_hash.as_durable_hash());
            let Some(location) = value_locations.get(&blob_key.index_bytes()).copied() else {
                missing_roots.push(PersistMissingNodeValueRoot::new(entry.key(), value_hash));
                continue;
            };
            self.value_pack
                .verify_blob(location, blob_key.hash())
                .map_err(|source| PersistNodeValueRootPlanError::Read { source })?;
            resolved_roots.push(PersistNodeValueRoot::new(entry.key(), value_hash, location));
        }
        Ok(PersistNodeValueRootPlan::new(resolved_roots, missing_roots))
    }

    /// Plans physical `values/` pack reachability from current metadata/index roots.
    ///
    /// This read-only diagnostic snapshots the latest demand-node metadata and
    /// `values/` blob-index entries, verifies every latest value-index root,
    /// scans the value pack, and classifies verified physical records as
    /// node-rooted, indexed without a current node root, or absent from the
    /// latest value index. Missing node value links are reported separately.
    /// The method does not choose a retention window, prune metadata, rewrite
    /// sidecars, delete blobs, relocate records, or coordinate with
    /// cross-process writers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistValueBlobReachabilityPlanError`] if the same-root
    /// value-index or node-metadata lock is poisoned, if either sidecar cannot
    /// be snapshotted, if the value index contains a non-value key, if an
    /// indexed value blob cannot be verified, or if the value pack cannot be
    /// fully scanned and verified.
    pub fn plan_value_blob_reachability(
        &self,
    ) -> Result<PersistValueBlobReachabilityPlan, PersistValueBlobReachabilityPlanError> {
        let metadata_entries = {
            let _metadata_guard = self
                .root_locks
                .lock_node_metadata()
                .map_err(|source| PersistValueBlobReachabilityPlanError::Metadata { source })?;
            self.node_metadata_index
                .latest_entries()
                .map_err(|source| PersistValueBlobReachabilityPlanError::Metadata { source })?
        };
        let _value_guard = self
            .root_locks
            .lock_blob_index(PersistBlobStore::Values)
            .map_err(|source| PersistValueBlobReachabilityPlanError::BlobIndex { source })?;
        let value_entries = self
            .value_index
            .latest_entries()
            .map_err(|source| PersistValueBlobReachabilityPlanError::BlobIndex { source })?;
        let mut value_locations = BTreeMap::new();
        let mut index_identities = BTreeMap::new();
        for entry in value_entries {
            let key = entry.key();
            if key.store() != PersistBlobStore::Values {
                return Err(PersistValueBlobReachabilityPlanError::WrongStoreEntry {
                    actual: key.store(),
                });
            }
            self.value_pack
                .verify_blob(entry.location(), key.hash())
                .map_err(|source| PersistValueBlobReachabilityPlanError::Read { source })?;
            value_locations.insert(key.index_bytes(), entry.location());
            index_identities.insert(blob_record_identity(key, entry.location()), ());
        }
        let mut node_roots = Vec::new();
        let mut missing_node_roots = Vec::new();
        let mut node_root_identities = BTreeMap::new();
        for entry in metadata_entries {
            let Some(value_hash) = entry.value().materialized_value_hash() else {
                continue;
            };
            let blob_key = PersistBlobKey::for_value(value_hash.as_durable_hash());
            let Some(location) = value_locations.get(&blob_key.index_bytes()).copied() else {
                missing_node_roots.push(PersistMissingNodeValueRoot::new(entry.key(), value_hash));
                continue;
            };
            node_root_identities.insert(blob_record_identity(blob_key, location), ());
            node_roots.push(PersistNodeValueRoot::new(entry.key(), value_hash, location));
        }

        let bytes_before = self
            .value_pack
            .len()
            .map_err(|source| PersistValueBlobReachabilityPlanError::Pack { source })?;
        let records = self
            .value_pack
            .records()
            .map_err(|source| PersistValueBlobReachabilityPlanError::Pack { source })?;
        let mut node_rooted_records = Vec::new();
        let mut indexed_unrooted_records = Vec::new();
        let mut unindexed_records = Vec::new();
        let mut node_rooted_record_bytes = 0u64;
        let mut indexed_unrooted_record_bytes = 0u64;
        let mut unindexed_record_bytes = 0u64;
        for record in records {
            let identity =
                blob_record_identity(record.key(PersistBlobStore::Values), record.location());
            let record_bytes = blob_record_bytes(record);
            if node_root_identities.contains_key(&identity) {
                node_rooted_record_bytes = node_rooted_record_bytes.saturating_add(record_bytes);
                node_rooted_records.push(record);
            } else if index_identities.contains_key(&identity) {
                indexed_unrooted_record_bytes =
                    indexed_unrooted_record_bytes.saturating_add(record_bytes);
                indexed_unrooted_records.push(record);
            } else {
                unindexed_record_bytes = unindexed_record_bytes.saturating_add(record_bytes);
                unindexed_records.push(record);
            }
        }

        Ok(PersistValueBlobReachabilityPlan {
            node_roots,
            missing_node_roots,
            node_rooted_records,
            indexed_unrooted_records,
            unindexed_records,
            bytes_before,
            node_rooted_record_bytes,
            indexed_unrooted_record_bytes,
            unindexed_record_bytes,
        })
    }

    /// Plans physical `files/` pack reachability from current artifact/index roots.
    ///
    /// This read-only diagnostic snapshots same-process pending artifact roots,
    /// latest file-artifact mappings, latest parse-artifact mappings, and the
    /// latest `files/` blob-index entries. It verifies every captured root,
    /// scans the file pack, and classifies verified physical records by the
    /// strongest root source: file artifact, parse artifact, pending artifact,
    /// blob-index-only, or unindexed. The method does not choose a retention
    /// window, rewrite sidecars, delete blobs, relocate records, or coordinate
    /// with cross-process writers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileBlobReachabilityPlanError`] if the same-root file
    /// blob-index, file-artifact, or parse-artifact lock is poisoned, if roots
    /// cannot be snapshotted, if the file blob index contains a non-file key,
    /// if any captured root cannot be verified, or if the file pack cannot be
    /// fully scanned and verified.
    pub fn plan_file_blob_reachability(
        &self,
    ) -> Result<PersistFileBlobReachabilityPlan, PersistFileBlobReachabilityPlanError> {
        let _file_guard = self
            .root_locks
            .lock_blob_index(PersistBlobStore::Files)
            .map_err(|source| PersistFileBlobReachabilityPlanError::BlobIndex { source })?;
        let pending_artifact_roots = self
            .root_locks
            .pending_file_roots()
            .map_err(|source| PersistFileBlobReachabilityPlanError::Roots { source })?;
        let file_artifact_roots = {
            let _file_artifact_guard = self.root_locks.lock_file_artifacts().map_err(|source| {
                PersistFileBlobReachabilityPlanError::FileArtifactIndex { source }
            })?;
            self.file_artifact_index
                .latest_entries()
                .map_err(
                    |source| PersistFileBlobReachabilityPlanError::FileArtifactIndex { source },
                )?
                .into_iter()
                .map(|entry| {
                    let value = entry.value();
                    PersistBlobLiveRoot::new(
                        PersistBlobLiveRootSource::FileArtifactIndex,
                        value.blob_key(),
                        value.location(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let parse_artifact_roots = {
            let _parse_artifact_guard =
                self.root_locks.lock_parse_artifacts().map_err(|source| {
                    PersistFileBlobReachabilityPlanError::ParseArtifactIndex { source }
                })?;
            self.parse_artifact_index
                .latest_entries()
                .map_err(
                    |source| PersistFileBlobReachabilityPlanError::ParseArtifactIndex { source },
                )?
                .into_iter()
                .map(|entry| {
                    let value = entry.value();
                    PersistBlobLiveRoot::new(
                        PersistBlobLiveRootSource::ParseArtifactIndex,
                        value.blob_key(),
                        value.location(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let file_entries = self
            .file_index
            .latest_entries()
            .map_err(|source| PersistFileBlobReachabilityPlanError::BlobIndex { source })?;

        let mut blob_index_roots = Vec::new();
        let mut index_identities = BTreeMap::new();
        for entry in file_entries {
            let key = entry.key();
            if key.store() != PersistBlobStore::Files {
                return Err(PersistFileBlobReachabilityPlanError::WrongStoreEntry {
                    actual: key.store(),
                });
            }
            self.file_pack
                .verify_blob(entry.location(), key.hash())
                .map_err(|source| PersistFileBlobReachabilityPlanError::Read { source })?;
            blob_index_roots.push(PersistBlobLiveRoot::new(
                PersistBlobLiveRootSource::BlobIndex,
                key,
                entry.location(),
            ));
            index_identities.insert(blob_record_identity(key, entry.location()), ());
        }

        let mut file_artifact_identities = BTreeMap::new();
        for root in &file_artifact_roots {
            self.file_pack
                .verify_blob(root.location(), root.key().hash())
                .map_err(|source| PersistFileBlobReachabilityPlanError::Read { source })?;
            file_artifact_identities.insert(blob_live_root_identity(*root), ());
        }
        let mut parse_artifact_identities = BTreeMap::new();
        for root in &parse_artifact_roots {
            self.file_pack
                .verify_blob(root.location(), root.key().hash())
                .map_err(|source| PersistFileBlobReachabilityPlanError::Read { source })?;
            parse_artifact_identities.insert(blob_live_root_identity(*root), ());
        }
        let mut pending_artifact_identities = BTreeMap::new();
        for root in &pending_artifact_roots {
            self.file_pack
                .verify_blob(root.location(), root.key().hash())
                .map_err(|source| PersistFileBlobReachabilityPlanError::Read { source })?;
            pending_artifact_identities.insert(blob_live_root_identity(*root), ());
        }

        let bytes_before = self
            .file_pack
            .len()
            .map_err(|source| PersistFileBlobReachabilityPlanError::Pack { source })?;
        let records = self
            .file_pack
            .records()
            .map_err(|source| PersistFileBlobReachabilityPlanError::Pack { source })?;
        let mut file_artifact_rooted_records = Vec::new();
        let mut parse_artifact_rooted_records = Vec::new();
        let mut pending_artifact_rooted_records = Vec::new();
        let mut indexed_unrooted_records = Vec::new();
        let mut unindexed_records = Vec::new();
        let mut file_artifact_rooted_record_bytes = 0u64;
        let mut parse_artifact_rooted_record_bytes = 0u64;
        let mut pending_artifact_rooted_record_bytes = 0u64;
        let mut indexed_unrooted_record_bytes = 0u64;
        let mut unindexed_record_bytes = 0u64;
        for record in records {
            let identity =
                blob_record_identity(record.key(PersistBlobStore::Files), record.location());
            let record_bytes = blob_record_bytes(record);
            if file_artifact_identities.contains_key(&identity) {
                file_artifact_rooted_record_bytes =
                    file_artifact_rooted_record_bytes.saturating_add(record_bytes);
                file_artifact_rooted_records.push(record);
            } else if parse_artifact_identities.contains_key(&identity) {
                parse_artifact_rooted_record_bytes =
                    parse_artifact_rooted_record_bytes.saturating_add(record_bytes);
                parse_artifact_rooted_records.push(record);
            } else if pending_artifact_identities.contains_key(&identity) {
                pending_artifact_rooted_record_bytes =
                    pending_artifact_rooted_record_bytes.saturating_add(record_bytes);
                pending_artifact_rooted_records.push(record);
            } else if index_identities.contains_key(&identity) {
                indexed_unrooted_record_bytes =
                    indexed_unrooted_record_bytes.saturating_add(record_bytes);
                indexed_unrooted_records.push(record);
            } else {
                unindexed_record_bytes = unindexed_record_bytes.saturating_add(record_bytes);
                unindexed_records.push(record);
            }
        }

        Ok(PersistFileBlobReachabilityPlan {
            file_artifact_roots,
            parse_artifact_roots,
            pending_artifact_roots,
            blob_index_roots,
            file_artifact_rooted_records,
            parse_artifact_rooted_records,
            pending_artifact_rooted_records,
            indexed_unrooted_records,
            unindexed_records,
            bytes_before,
            file_artifact_rooted_record_bytes,
            parse_artifact_rooted_record_bytes,
            pending_artifact_rooted_record_bytes,
            indexed_unrooted_record_bytes,
            unindexed_record_bytes,
        })
    }

    /// Records one current-run demand observation for a demand node.
    ///
    /// The helper reads the latest persisted counters, starts from empty
    /// counters on a miss, appends the updated counters while preserving any
    /// materialized value-hash link, and returns the value that was recorded
    /// while holding the advisory and same-root metadata write locks. Raw
    /// lower-level sidecar users must still be excluded by the caller because
    /// this fixed-record sidecar stores absolute counters under newest-record
    /// lookup semantics.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn record_node_current_demand(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<MaterializationReuse, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let value = self
            .lookup_node_metadata_unlocked(key)?
            .unwrap_or_else(|| PersistNodeMetadataIndexValue::new(MaterializationReuse::default()));
        let reuse = value.materialization_reuse().record_current_demand();
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(
            key,
            value.with_materialization_reuse(reuse),
        ))?;
        Ok(reuse)
    }

    /// Builds durable materialization threshold signals for one demand node.
    ///
    /// Missing metadata starts from empty reuse counters, so current payloads
    /// are kept in memory until a previous run has demanded the same node and
    /// the caller-supplied cost model says writing is profitable.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn node_materialization_signals(
        &self,
        key: PersistNodeMetadataKey,
        costs: MaterializationCosts,
    ) -> Result<MaterializationSignals, PersistNodeMetadataIndexError> {
        Ok(self
            .lookup_node_materialization_reuse(key)?
            .unwrap_or_default()
            .signals(costs))
    }

    /// Returns the durable materialization decision for one demand node.
    ///
    /// This is the cache-level bridge from persisted cross-run demand counters
    /// to the existing materialization threshold policy. It does not write the
    /// payload; callers pass the returned decision to the appropriate
    /// materialization helper.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn node_materialization_decision(
        &self,
        key: PersistNodeMetadataKey,
        costs: MaterializationCosts,
    ) -> Result<MaterializationDecision, PersistNodeMetadataIndexError> {
        Ok(self.node_materialization_signals(key, costs)?.decide())
    }

    /// Advances persisted reuse counters for one demand node to the next run.
    ///
    /// Missing index entries return `Ok(None)` without appending an empty
    /// record. Existing entries append the counters returned by
    /// [`MaterializationReuse::advance_run`], preserve any materialized
    /// value-hash link, and return the recorded reuse counters while holding
    /// the advisory and same-root metadata write locks. Raw lower-level
    /// sidecar users must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn advance_node_materialization_reuse_run(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<MaterializationReuse>, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let Some(value) = self.lookup_node_metadata_unlocked(key)? else {
            return Ok(None);
        };
        let reuse = value.materialization_reuse();
        let advanced = reuse.advance_run();
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(
            key,
            value.with_materialization_reuse(advanced),
        ))?;
        Ok(Some(advanced))
    }

    /// Advances persisted reuse counters for all known demand nodes.
    ///
    /// This reads the newest metadata value for every node key, appends
    /// [`MaterializationReuse::advance_run`] for entries whose counters change
    /// while preserving any materialized value-hash link, and returns the
    /// entries that were appended in stable key order while holding the
    /// advisory and same-root metadata write locks. Raw lower-level sidecar
    /// users must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn advance_all_node_materialization_reuse_runs(
        &self,
    ) -> Result<Vec<PersistNodeMetadataIndexEntry>, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let mut recorded = Vec::new();
        for entry in self.node_metadata_index.latest_entries()? {
            let reuse = entry.value().materialization_reuse();
            let advanced = reuse.advance_run();
            if advanced == reuse {
                continue;
            }
            let advanced_entry = PersistNodeMetadataIndexEntry::new(
                entry.key(),
                entry.value().with_materialization_reuse(advanced),
            );
            self.record_node_metadata_unlocked(advanced_entry)?;
            recorded.push(advanced_entry);
        }
        Ok(recorded)
    }

    /// Compacts node metadata to the newest record for every known demand node.
    ///
    /// Cache-level writers opened on the same cache root share the metadata
    /// advisory lock and same-root write lock while this method rewrites the
    /// sidecar. Raw lower-level sidecar users must still be excluded by the
    /// caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, flushed,
    /// or renamed into place.
    pub fn compact_node_metadata(&self) -> Result<usize, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        self.node_metadata_index.compact_latest_entries()
    }

    /// Looks up a blob location through the sidecar index selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the selected index cannot be
    /// opened, read, or decoded.
    pub fn lookup_blob_location(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<PersistBlobLocation>, PersistBlobIndexError> {
        self.blob_index(key.store()).lookup(key)
    }

    /// Compacts the selected blob index to the newest entry for every known key.
    ///
    /// Cache-level writers opened on the same cache root acquire the selected
    /// store's advisory lock file and same-process blob-index write lock while
    /// this method rewrites the sidecar. Raw lower-level sidecar users and
    /// unrelated maintenance writers must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the selected advisory lock cannot
    /// be acquired, the same-root blob-index write lock is poisoned, or if the
    /// selected index cannot be created, opened, inspected, read, decoded,
    /// written, flushed, or renamed into place.
    pub fn compact_blob_index(
        &self,
        store: PersistBlobStore,
    ) -> Result<usize, PersistBlobIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_blob_index_write(store)?;
        self.blob_index(store).compact_latest_entries()
    }

    fn snapshot_blob_live_roots_unlocked(
        &self,
        store: PersistBlobStore,
    ) -> Result<Vec<PersistBlobLiveRoot>, PersistBlobLiveRootError> {
        let blob_entries = self
            .blob_index(store)
            .latest_entries()
            .map_err(|source| PersistBlobLiveRootError::BlobIndex { source })?;
        let mut roots = Vec::new();
        push_blob_index_roots(
            &mut roots,
            blob_entries,
            store,
            PersistBlobLiveRootSource::BlobIndex,
        )?;
        if store == PersistBlobStore::Files {
            roots.extend(self.root_locks.pending_file_roots()?);
            for entry in self
                .file_artifact_index
                .latest_entries()
                .map_err(|source| PersistBlobLiveRootError::FileArtifactIndex { source })?
            {
                let value = entry.value();
                roots.push(PersistBlobLiveRoot::new(
                    PersistBlobLiveRootSource::FileArtifactIndex,
                    value.blob_key(),
                    value.location(),
                ));
            }
            for entry in self
                .parse_artifact_index
                .latest_entries()
                .map_err(|source| PersistBlobLiveRootError::ParseArtifactIndex { source })?
            {
                let value = entry.value();
                roots.push(PersistBlobLiveRoot::new(
                    PersistBlobLiveRootSource::ParseArtifactIndex,
                    value.blob_key(),
                    value.location(),
                ));
            }
        }
        Ok(roots)
    }

    /// Trims unindexed tail bytes from the selected blob pack.
    ///
    /// This explicit maintenance operation snapshots the selected store's
    /// latest live roots, verifies each referenced blob against the selected
    /// pack, and truncates only bytes after the highest live record. For
    /// `values/`, the roots are the value blob-index entries. For `files/`, the
    /// roots also include file-artifact mappings, parse-artifact mappings, and
    /// same-process pending artifact roots because legacy non-indexed artifact
    /// materializers can publish those values without adding a blob-index
    /// entry. This can reclaim unindexed trailing records, including blobs left
    /// behind by non-transactional append paths, but it does not relocate live
    /// records or reclaim unindexed records that precede a live record.
    /// Cache-level writers opened on the same cache root share the selected
    /// store's advisory lock file and same-process store lock while this method
    /// snapshots roots and truncates the pack; `files/` trims also share the
    /// file-artifact and parse-artifact advisory and same-root mapping locks.
    /// Raw lower-level pack or sidecar users, cross-process pending artifact
    /// publication, and unrelated maintenance writers must still be excluded by
    /// the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackTrimError`] if the selected advisory lock cannot
    /// be acquired, if a same-root root-sidecar lock is poisoned, if a root
    /// sidecar cannot be snapshotted, if a blob-index entry contains a key for a
    /// different store, if any latest live blob fails verification, or if the
    /// pack cannot be inspected or truncated.
    pub fn trim_blob_pack_tail(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobPackTrim, PersistBlobPackTrimError> {
        let (_advisory_guard, _blob_guard) = self.lock_blob_pack_tail_trim(store)?;
        let _file_artifact_guard = if store == PersistBlobStore::Files {
            Some(
                self.lock_file_artifact_write()
                    .map_err(|source| PersistBlobPackTrimError::FileArtifactIndex { source })?,
            )
        } else {
            None
        };
        let _parse_artifact_guard = if store == PersistBlobStore::Files {
            Some(
                self.lock_parse_artifact_write()
                    .map_err(|source| PersistBlobPackTrimError::ParseArtifactIndex { source })?,
            )
        } else {
            None
        };
        let roots = self
            .snapshot_blob_live_roots_unlocked(store)
            .map_err(PersistBlobPackTrimError::from)?;
        let pack = self.blob_pack(store);
        let mut live_end = PERSIST_BLOB_PACK_HEADER_LEN as u64;
        for root in &roots {
            let window = pack
                .verify_blob(root.location(), root.key().hash())
                .map_err(|source| PersistBlobPackTrimError::Read { source })?;
            live_end = live_end.max(window.payload_end());
        }
        let bytes_before = pack
            .len()
            .map_err(|source| PersistBlobPackTrimError::Trim { source })?;
        pack.trim_tail(live_end)
            .map_err(|source| PersistBlobPackTrimError::Trim { source })?;
        let bytes_after = pack
            .len()
            .map_err(|source| PersistBlobPackTrimError::Trim { source })?;
        Ok(PersistBlobPackTrim::new(
            roots.len(),
            bytes_before,
            bytes_after,
        ))
    }

    /// Plans blob-pack liveness for future repack maintenance.
    ///
    /// This read-only diagnostic snapshots the selected store's latest live
    /// roots and same-process pending artifact roots, verifies every rooted
    /// record without materializing payloads, then scans the selected pack to
    /// classify verified physical records as rooted or unrooted. For `values`,
    /// roots come from the value blob index. For `files`, roots also include
    /// file-artifact and parse-artifact mappings because legacy non-indexed
    /// artifact materializers can publish those records without a blob-index
    /// entry. The returned byte counts are sidecar/pending-root diagnostics
    /// only; node metadata references, cross-process raw writers, and the
    /// final RFC GC live-root model are outside this plan. The method does not
    /// write sidecars, truncate packs, relocate records, or coordinate with
    /// cross-process writers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackLivenessPlanError`] if a same-root root-sidecar
    /// lock is poisoned, if roots cannot be snapshotted, if a blob-index entry
    /// targets the wrong store, if any latest live root fails verification, or
    /// if the selected pack cannot be fully scanned and verified.
    pub fn plan_blob_pack_liveness(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobPackLivenessPlan, PersistBlobPackLivenessPlanError> {
        let _blob_guard = self.root_locks.lock_blob_index(store).map_err(|source| {
            PersistBlobPackLivenessPlanError::Roots {
                source: PersistBlobLiveRootError::BlobIndex { source },
            }
        })?;
        let _file_artifact_guard = if store == PersistBlobStore::Files {
            Some(self.root_locks.lock_file_artifacts().map_err(|source| {
                PersistBlobPackLivenessPlanError::Roots {
                    source: PersistBlobLiveRootError::FileArtifactIndex { source },
                }
            })?)
        } else {
            None
        };
        let _parse_artifact_guard = if store == PersistBlobStore::Files {
            Some(self.root_locks.lock_parse_artifacts().map_err(|source| {
                PersistBlobPackLivenessPlanError::Roots {
                    source: PersistBlobLiveRootError::ParseArtifactIndex { source },
                }
            })?)
        } else {
            None
        };
        let roots = self
            .snapshot_blob_live_roots_unlocked(store)
            .map_err(|source| PersistBlobPackLivenessPlanError::Roots { source })?;
        self.plan_blob_pack_liveness_from_roots(store, roots)
    }

    fn plan_blob_pack_liveness_unlocked(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobPackLivenessPlan, PersistBlobPackLivenessPlanError> {
        let roots = self
            .snapshot_blob_live_roots_unlocked(store)
            .map_err(|source| PersistBlobPackLivenessPlanError::Roots { source })?;
        self.plan_blob_pack_liveness_from_roots(store, roots)
    }

    fn plan_blob_pack_liveness_from_roots(
        &self,
        store: PersistBlobStore,
        roots: Vec<PersistBlobLiveRoot>,
    ) -> Result<PersistBlobPackLivenessPlan, PersistBlobPackLivenessPlanError> {
        let pack = self.blob_pack(store);
        let mut rooted_identities = std::collections::BTreeSet::new();
        let mut live_end = PERSIST_BLOB_PACK_HEADER_LEN as u64;
        for root in &roots {
            let window = pack
                .verify_blob(root.location(), root.key().hash())
                .map_err(|source| PersistBlobPackLivenessPlanError::Read { source })?;
            live_end = live_end.max(window.payload_end());
            rooted_identities.insert(blob_record_identity(root.key(), root.location()));
        }

        let bytes_before = pack
            .len()
            .map_err(|source| PersistBlobPackLivenessPlanError::Scan { source })?;
        let records = pack
            .records()
            .map_err(|source| PersistBlobPackLivenessPlanError::Scan { source })?;
        let mut rooted_records = Vec::new();
        let mut unrooted_records = Vec::new();
        let mut rooted_record_bytes = 0u64;
        let mut unrooted_record_bytes = 0u64;
        for record in records {
            let record_bytes = blob_record_bytes(record);
            if rooted_identities
                .contains(&blob_record_identity(record.key(store), record.location()))
            {
                rooted_record_bytes = rooted_record_bytes.saturating_add(record_bytes);
                rooted_records.push(record);
            } else {
                unrooted_record_bytes = unrooted_record_bytes.saturating_add(record_bytes);
                unrooted_records.push(record);
            }
        }
        let tail_reclaimable_bytes = bytes_before.saturating_sub(live_end);
        Ok(PersistBlobPackLivenessPlan::new(
            roots,
            rooted_records,
            unrooted_records,
            bytes_before,
            rooted_record_bytes,
            unrooted_record_bytes,
            tail_reclaimable_bytes,
        ))
    }

    /// Plans live-record relocation for a future blob-pack repack.
    ///
    /// This read-only diagnostic first builds [`Self::plan_blob_pack_liveness`],
    /// then assigns each verified rooted record a contiguous location in a
    /// fresh compacted pack while preserving current pack order. Unrooted
    /// records are reported as omitted. The method does not write sidecars,
    /// copy payload bytes, replace packfiles, choose a retention policy, or
    /// coordinate with cross-process writers. For `files/`, the returned plan
    /// can include same-process pending artifact roots, but applying such a
    /// relocation still requires a writer-quiescence protocol because callers
    /// with in-flight artifact index entries hold old locations.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackRepackPlanError`] if liveness planning fails
    /// or if the planned compacted pack length would overflow `u64`.
    pub fn plan_blob_pack_repack(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobPackRepackPlan, PersistBlobPackRepackPlanError> {
        let liveness = self
            .plan_blob_pack_liveness(store)
            .map_err(|source| PersistBlobPackRepackPlanError::Liveness { source })?;
        blob_pack_repack_plan_from_liveness(store, liveness)
    }

    fn plan_blob_pack_repack_unlocked(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobPackRepackPlan, PersistBlobPackRepackPlanError> {
        let liveness = self
            .plan_blob_pack_liveness_unlocked(store)
            .map_err(|source| PersistBlobPackRepackPlanError::Liveness { source })?;
        blob_pack_repack_plan_from_liveness(store, liveness)
    }

    /// Rewrites the `values/` pack to the current live value roots.
    ///
    /// This explicit maintenance operation builds a value-pack repack plan
    /// while holding the selected store's advisory lock file and same-root value
    /// store write lock, stages a compacted value pack and replacement value
    /// blob index, then swaps both files into place with best-effort rollback
    /// for ordinary filesystem errors. It preserves the latest indexed value
    /// roots and omits records that are not live under the current value blob
    /// index. The cache is advisory: this operation is not crash-transactional,
    /// does not prune node metadata, coordinate with raw lower-level users or
    /// unrelated sidecar writers, or apply the future full GC retention policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistValueBlobPackRepackError`] if the selected advisory lock
    /// cannot be acquired, the same-root value store write lock is poisoned, if
    /// repack planning fails, if the compacted pack image cannot be written or
    /// swapped, or if the replacement value index cannot be written or swapped.
    pub fn repack_value_blob_pack(
        &self,
    ) -> Result<PersistBlobPackRepackPlan, PersistValueBlobPackRepackError> {
        let (_advisory_guard, _write_guard) = self.lock_value_blob_pack_repack()?;
        let plan = self
            .plan_blob_pack_repack_unlocked(PersistBlobStore::Values)
            .map_err(|source| PersistValueBlobPackRepackError::Plan { source })?;
        if plan.reclaimable_bytes() == 0 {
            return Ok(plan);
        }
        let rewrite_id = INDEX_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_pack_path = self.value_pack.path().with_extension(format!(
            "repack-pack-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let tmp_index_path = self.value_index.path().with_extension(format!(
            "repack-index-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let replacements = value_repack_replacements(
            self.value_pack.path(),
            self.value_index.path(),
            &tmp_pack_path,
            &tmp_index_path,
            rewrite_id,
        );
        self.value_pack
            .write_relocated_records_to(&tmp_pack_path, plan.record_relocations())
            .map_err(|source| PersistValueBlobPackRepackError::Pack { source })?;
        if let Err(source) = write_repacked_blob_index(&tmp_index_path, plan.record_relocations()) {
            replacements.cleanup_staged();
            return Err(PersistValueBlobPackRepackError::BlobIndex { source });
        }
        swap_repacked_value_store(&replacements)?;
        Ok(plan)
    }

    /// Rewrites the `files/` pack to the current artifact and blob-index roots.
    ///
    /// This explicit maintenance operation builds a file-pack repack plan while
    /// holding the selected store's advisory lock file plus same-root file
    /// store lock plus file-artifact and parse-artifact advisory and same-root
    /// locks, stages a compacted file pack plus relocated file blob,
    /// file-artifact, and parse-artifact sidecars, then swaps them into place
    /// with best-effort rollback for
    /// ordinary filesystem errors. It refuses to run while same-process pending
    /// non-indexed artifact roots exist because those callers still hold old
    /// pack locations that would become invalid after relocation. The cache is
    /// advisory: this operation is not crash-transactional, does not coordinate
    /// with raw lower-level users or cross-process pending artifact publication,
    /// and does not apply the future full GC retention policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileBlobPackRepackError`] if the selected advisory lock
    /// cannot be acquired, if a same-root lock is poisoned, if pending artifact
    /// roots exist, if repack planning fails, if an artifact sidecar root has no
    /// planned relocation, if the compacted pack image cannot be written or
    /// swapped, or if any replacement sidecar cannot be written or swapped.
    pub fn repack_file_blob_pack(
        &self,
    ) -> Result<PersistBlobPackRepackPlan, PersistFileBlobPackRepackError> {
        let (_advisory_guard, _file_guard) = self.lock_file_blob_pack_repack()?;
        let _file_artifact_guard = self
            .lock_file_artifact_write()
            .map_err(|source| PersistFileBlobPackRepackError::FileArtifactIndex { source })?;
        let _parse_artifact_guard = self
            .lock_parse_artifact_write()
            .map_err(|source| PersistFileBlobPackRepackError::ParseArtifactIndex { source })?;
        let pending_roots = self
            .root_locks
            .pending_file_roots()
            .map_err(|source| PersistFileBlobPackRepackError::PendingRoots { source })?;
        if !pending_roots.is_empty() {
            return Err(PersistFileBlobPackRepackError::PendingArtifactRoots {
                roots: pending_roots.len(),
            });
        }
        let plan = self
            .plan_blob_pack_repack_unlocked(PersistBlobStore::Files)
            .map_err(|source| PersistFileBlobPackRepackError::Plan { source })?;
        if plan.reclaimable_bytes() == 0 {
            return Ok(plan);
        }
        let relocation_locations = file_relocation_locations(plan.record_relocations());
        let file_artifact_entries = relocate_file_artifact_entries(
            self.file_artifact_index
                .latest_entries()
                .map_err(|source| PersistFileBlobPackRepackError::FileArtifactIndex { source })?,
            &relocation_locations,
        )?;
        let parse_artifact_entries = relocate_parse_artifact_entries(
            self.parse_artifact_index
                .latest_entries()
                .map_err(|source| PersistFileBlobPackRepackError::ParseArtifactIndex { source })?,
            &relocation_locations,
        )?;

        let rewrite_id = INDEX_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_pack_path = self.file_pack.path().with_extension(format!(
            "repack-pack-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let tmp_index_path = self.file_index.path().with_extension(format!(
            "repack-index-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let tmp_file_artifact_path = self.file_artifact_index.path().with_extension(format!(
            "repack-file-artifacts-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let tmp_parse_artifact_path = self.parse_artifact_index.path().with_extension(format!(
            "repack-parse-artifacts-{}-{rewrite_id}.tmp",
            std::process::id()
        ));
        let stage = FileRepackStagePaths {
            pack: &tmp_pack_path,
            blob_index: &tmp_index_path,
            file_artifact_index: &tmp_file_artifact_path,
            parse_artifact_index: &tmp_parse_artifact_path,
        };
        let paths = FileRepackPaths {
            pack: self.file_pack.path(),
            blob_index: self.file_index.path(),
            file_artifact_index: self.file_artifact_index.path(),
            parse_artifact_index: self.parse_artifact_index.path(),
        };
        let replacements = file_repack_replacements(paths, stage, rewrite_id);
        if let Err(source) = self
            .file_pack
            .write_relocated_records_to(&tmp_pack_path, plan.record_relocations())
        {
            replacements.cleanup_staged();
            return Err(PersistFileBlobPackRepackError::Pack { source });
        }
        if let Err(source) = write_repacked_blob_index(&tmp_index_path, plan.record_relocations()) {
            replacements.cleanup_staged();
            return Err(PersistFileBlobPackRepackError::BlobIndex { source });
        }
        if let Err(source) =
            write_repacked_file_artifact_index(&tmp_file_artifact_path, &file_artifact_entries)
        {
            replacements.cleanup_staged();
            return Err(PersistFileBlobPackRepackError::FileArtifactIndex { source });
        }
        if let Err(source) =
            write_repacked_parse_artifact_index(&tmp_parse_artifact_path, &parse_artifact_entries)
        {
            replacements.cleanup_staged();
            return Err(PersistFileBlobPackRepackError::ParseArtifactIndex { source });
        }
        swap_repacked_file_store(&replacements)?;
        Ok(plan)
    }

    /// Rewrites both persistent blob packs to their current live roots.
    ///
    /// This caller-driven maintenance helper runs
    /// [`Self::repack_value_blob_pack`] and then [`Self::repack_file_blob_pack`].
    /// It is sequential and non-transactional: if the file-pack repack fails,
    /// the value-pack repack may already be committed. Each pack repack holds
    /// its selected store's advisory lock file, and file-pack repack also holds
    /// artifact-mapping advisory locks. The method does not compact unrelated
    /// sidecars, rebuild blob indexes from physical pack scans before planning,
    /// coordinate raw lower-level users or cross-process pending artifact
    /// publication, or apply the future full GC retention policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPacksRepackError`] identifying the pack whose
    /// repack failed. Earlier pack rewrites may already be committed.
    pub fn repack_blob_packs(&self) -> Result<PersistBlobPacksRepack, PersistBlobPacksRepackError> {
        let value_blob_pack = self
            .repack_value_blob_pack()
            .map_err(|source| PersistBlobPacksRepackError::ValueBlobPack { source })?;
        let file_blob_pack = self
            .repack_file_blob_pack()
            .map_err(|source| PersistBlobPacksRepackError::FileBlobPack { source })?;
        Ok(PersistBlobPacksRepack::new(value_blob_pack, file_blob_pack))
    }

    /// Returns verified pack records as typed blob-index entries for `store`.
    ///
    /// This read-only adapter scans the selected store's pack, verifies every
    /// record through [`PersistBlobPack::records`], and maps each record to the
    /// `PersistBlobIndexEntry` shape used by the hash-to-offset sidecar. It
    /// returns physical pack records, including stale duplicate records and
    /// unindexed records. It does not write or repair the sidecar index, select
    /// live roots, or compact the pack.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected pack cannot be opened,
    /// inspected, seeked, or read, if any record header is malformed or
    /// truncated, if a record points past the current packfile length, or if a
    /// payload hash does not match its record header.
    pub fn blob_pack_index_entries(
        &self,
        store: PersistBlobStore,
    ) -> Result<Vec<PersistBlobIndexEntry>, PersistBlobPackError> {
        self.blob_pack(store).records().map(|records| {
            records
                .into_iter()
                .map(|record| PersistBlobIndexEntry::new(record.key(store), record.location()))
                .collect()
        })
    }

    /// Returns newest physical pack records as typed blob-index entries.
    ///
    /// This read-only adapter scans the selected store's pack and collapses
    /// duplicate physical records for the same content hash with
    /// newest-record-wins semantics. Entries are returned in stable encoded-key
    /// order, matching the current fixed-record sidecar's latest-entry
    /// encoded-key ordering. It does not write or repair the sidecar index,
    /// select live roots, or compact the pack.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected pack cannot be opened,
    /// inspected, seeked, or read, if any record header is malformed or
    /// truncated, if a record points past the current packfile length, or if a
    /// payload hash does not match its record header.
    pub fn latest_blob_pack_index_entries(
        &self,
        store: PersistBlobStore,
    ) -> Result<Vec<PersistBlobIndexEntry>, PersistBlobPackError> {
        let mut latest = std::collections::BTreeMap::new();
        for entry in self.blob_pack_index_entries(store)? {
            latest.insert(entry.key().index_bytes(), entry);
        }
        Ok(latest.into_values().collect())
    }

    /// Plans a blob-index rebuild from the selected store's verified pack.
    ///
    /// This read-only diagnostic compares the sidecar's newest lookup entries
    /// with [`Self::latest_blob_pack_index_entries`]. `planned_entries` is the
    /// exact newest physical pack entry set a future canonical rewrite would
    /// write; missing, stale, and dangling lists describe semantic lookup
    /// differences between the current sidecar and that set. Older append-only
    /// sidecar records are ignored once the newest entry for a key matches. The
    /// method does not write the sidecar, choose live roots, trim pack bytes,
    /// or coordinate with other writers.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexRebuildPlanError`] if the selected pack cannot
    /// be fully verified or the selected sidecar cannot be snapshotted.
    pub fn plan_blob_index_rebuild(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobIndexRebuildPlan, PersistBlobIndexRebuildPlanError> {
        let planned_entries = self
            .latest_blob_pack_index_entries(store)
            .map_err(|source| PersistBlobIndexRebuildPlanError::Pack { source })?;
        let current_entries = self
            .blob_index(store)
            .latest_entries()
            .map_err(|source| PersistBlobIndexRebuildPlanError::Index { source })?;

        let mut planned_by_key = std::collections::BTreeMap::new();
        for entry in &planned_entries {
            planned_by_key.insert(entry.key().index_bytes(), *entry);
        }

        let mut current_by_key = std::collections::BTreeMap::new();
        let mut stale_entries = Vec::new();
        let mut dangling_entries = Vec::new();
        for entry in current_entries {
            let key = entry.key().index_bytes();
            current_by_key.insert(key, entry);
            match planned_by_key.get(&key) {
                Some(planned) if *planned == entry => {}
                Some(planned) => {
                    stale_entries.push(PersistBlobIndexStaleEntry::new(entry, *planned));
                }
                None => dangling_entries.push(entry),
            }
        }

        let mut missing_entries = Vec::new();
        for entry in &planned_entries {
            if !current_by_key.contains_key(&entry.key().index_bytes()) {
                missing_entries.push(*entry);
            }
        }

        Ok(PersistBlobIndexRebuildPlan::new(
            planned_entries,
            missing_entries,
            stale_entries,
            dangling_entries,
        ))
    }

    /// Rebuilds the selected blob-index sidecar from its verified pack.
    ///
    /// This explicit maintenance operation first builds
    /// [`Self::plan_blob_index_rebuild`], then replaces the selected sidecar
    /// with the plan's newest physical pack entries. It indexes every verified
    /// newest physical record in that pack, including records that were
    /// previously unindexed, and drops sidecar entries that do not correspond
    /// to a verified physical record in the selected store. It does not choose
    /// live roots, trim pack bytes, relocate records, coordinate with raw
    /// lower-level sidecar users or unrelated maintenance writers, or implement
    /// an automatic repair policy.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexRebuildError`] if planning fails or if the
    /// selected advisory lock cannot be acquired, the same-root blob-index write
    /// lock is poisoned, or the selected sidecar cannot be replaced with the
    /// planned entries.
    pub fn rebuild_blob_index_from_pack(
        &self,
        store: PersistBlobStore,
    ) -> Result<PersistBlobIndexRebuildPlan, PersistBlobIndexRebuildError> {
        let (_advisory_guard, _write_guard) = self.lock_blob_index_rebuild(store)?;
        let plan = self
            .plan_blob_index_rebuild(store)
            .map_err(|source| PersistBlobIndexRebuildError::Plan { source })?;
        self.blob_index(store)
            .replace_entries(&plan.planned_entries)
            .map_err(|source| PersistBlobIndexRebuildError::Write { source })?;
        Ok(plan)
    }

    /// Rebuilds both blob-index sidecars from their verified packs.
    ///
    /// This explicit maintenance helper runs
    /// [`Self::rebuild_blob_index_from_pack`] for `values/` and then `files/`,
    /// returning the plans that were applied to each sidecar. It is sequential
    /// and non-transactional: if the `files/` rebuild fails, the `values/`
    /// rebuild may already be committed. It does not choose live roots, trim
    /// pack bytes, relocate records, coordinate with raw lower-level sidecar
    /// users or unrelated maintenance writers, or implement an automatic repair
    /// policy. Cache-level writers opened on the same cache root share each
    /// selected store's advisory lock file and same-process blob-index write
    /// lock during its rebuild step.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexesRebuildError`] identifying the sidecar whose
    /// rebuild failed. Earlier sidecars may already have been rewritten.
    pub fn rebuild_blob_indexes_from_packs(
        &self,
    ) -> Result<PersistBlobIndexRebuild, PersistBlobIndexesRebuildError> {
        let value_blob_index = self
            .rebuild_blob_index_from_pack(PersistBlobStore::Values)
            .map_err(|source| PersistBlobIndexesRebuildError::ValueBlobIndex { source })?;
        let file_blob_index = self
            .rebuild_blob_index_from_pack(PersistBlobStore::Files)
            .map_err(|source| PersistBlobIndexesRebuildError::FileBlobIndex { source })?;
        Ok(PersistBlobIndexRebuild::new(
            value_blob_index,
            file_blob_index,
        ))
    }

    /// Appends a blob and records its location in the sidecar index.
    ///
    /// This helper is explicit and non-transactional: if the pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record. Same-process writers
    /// opened on the same cache root share the selected store's blob-store write
    /// lock while this method writes the pack and sidecar; cooperating
    /// cross-process writers share the selected store's advisory lock file.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] if the selected advisory lock
    /// cannot be acquired, the same-root blob-store write lock is poisoned, if
    /// the selected packfile cannot append/verify the payload, or if the
    /// selected sidecar index cannot write the resulting hash-to-offset record.
    pub fn append_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let (_advisory_guard, _write_guard) = self.lock_indexed_blob_write(key.store())?;
        self.append_blob_indexed_unlocked(key, payload)
    }

    fn append_blob_indexed_unlocked(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let location = self
            .append_blob_unlocked(key, payload)
            .map_err(|source| PersistBlobIndexedWriteError::Append { source })?;
        let entry = PersistBlobIndexEntry::new(key, location);
        self.blob_index(key.store())
            .append_entry(entry)
            .map_err(|source| PersistBlobIndexedWriteError::Index { source })?;
        Ok(entry)
    }

    /// Reads a blob through the sidecar index selected by `key`.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedReadError`] if the same-root store lock is
    /// poisoned, if the selected index cannot be read/decoded, or if the
    /// indexed pack location cannot be read and verified.
    pub fn read_blob_indexed(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<Vec<u8>>, PersistBlobIndexedReadError> {
        let _read_guard = self
            .root_locks
            .lock_blob_store(key.store())
            .map_err(|_| PersistBlobIndexedReadError::ReadLockPoisoned { store: key.store() })?;
        let Some(location) = self
            .lookup_blob_location(key)
            .map_err(|source| PersistBlobIndexedReadError::Lookup { source })?
        else {
            return Ok(None);
        };
        self.read_blob(key, location)
            .map(Some)
            .map_err(|source| PersistBlobIndexedReadError::Read { source })
    }

    /// Ensures a blob is present in the selected pack and sidecar index.
    ///
    /// If the sidecar index can be read and already points at a pack record
    /// that verifies for `key` and exactly matches `payload`, the existing
    /// location is reused without appending duplicate bytes or index records.
    /// Missing, stale, mismatching, or unreadable indexed records append a fresh
    /// blob and record a newer sidecar entry while holding the selected store's
    /// advisory and same-root write locks.
    ///
    /// This helper is explicit and non-transactional: if a fresh pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] if the selected advisory lock
    /// cannot be acquired, the selected in-process materialization lock is
    /// poisoned, if the selected packfile cannot append or verify a fresh
    /// payload, or if the selected sidecar index cannot write a fresh
    /// hash-to-offset record. A lookup failure falls back to the append path so
    /// this helper preserves append-first failure semantics.
    pub fn ensure_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let (_advisory_guard, _write_guard) = self.lock_indexed_blob_write(key.store())?;
        if let Ok(Some(location)) = self.lookup_blob_location(key) {
            let pack = self.blob_pack(key.store());
            if matches!(
                pack.payload_matches(location, key.hash(), payload),
                Ok(true)
            ) {
                return Ok(PersistBlobIndexEntry::new(key, location));
            }
        }
        self.append_blob_indexed_unlocked(key, payload)
    }

    /// Materializes a cached expression payload into the indexed `values/` pack.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing, encoding, or
    /// writing `value`. [`MaterializationDecision::Materialize`] encodes the
    /// payload as canonical value-store bytes, uses the payload's
    /// [`ValueHash`] as the `values/` content address, and records the pack
    /// location in the sidecar blob index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedWriteError`] when
    /// materialization is requested and the payload cannot be hashed, encoded,
    /// appended, or indexed.
    pub fn materialize_cached_expression_value_indexed(
        &self,
        value: &CachedExpressionValue,
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistCachedExpressionValueIndexedWriteError> {
        let MaterializationDecision::Materialize = decision else {
            return Ok(PersistMaterialization::Skipped);
        };
        let value_hash = value
            .value_hash()
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Hash { source })?;
        let payload = value
            .encode_persistent_payload()
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Encode { source })?;
        let key = PersistBlobKey::for_value(value_hash.as_durable_hash());
        self.materialize_blob_indexed(key, &payload, MaterializationDecision::Materialize)
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Write { source })
    }

    /// Applies materialization threshold signals to a cached expression payload.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through
    /// [`Self::materialize_cached_expression_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedWriteError`] when the
    /// signals choose materialization and the payload cannot be hashed,
    /// encoded, appended, or indexed.
    pub fn materialize_cached_expression_value_indexed_with_signals(
        &self,
        value: &CachedExpressionValue,
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistCachedExpressionValueIndexedWriteError> {
        self.materialize_cached_expression_value_indexed(value, signals.decide())
    }

    /// Loads a cached expression payload from the indexed `values/` pack.
    ///
    /// Missing index entries return `Ok(None)`. Present entries are read by
    /// `value_hash`, verified by the blob pack, and decoded as a cached
    /// expression payload. The decoded value is then hashed again and must
    /// match `value_hash` before being returned for evaluator-local
    /// rehydration.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedLoadError`] if the sidecar
    /// index cannot be read, the indexed blob cannot be verified, the bytes
    /// are not a supported cached-expression payload, or the decoded payload's
    /// value hash does not match `value_hash`.
    pub fn load_cached_expression_value_indexed(
        &self,
        value_hash: ValueHash,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionValueIndexedLoadError> {
        let key = PersistBlobKey::for_value(value_hash.as_durable_hash());
        let Some(payload) = self
            .read_blob_indexed(key)
            .map_err(|source| PersistCachedExpressionValueIndexedLoadError::Read { source })?
        else {
            return Ok(None);
        };
        let value = CachedExpressionValue::decode_persistent_payload(&payload)
            .map_err(|source| PersistCachedExpressionValueIndexedLoadError::Decode { source })?;
        let actual = value
            .value_hash()
            .map_err(|source| PersistCachedExpressionValueIndexedLoadError::Hash { source })?;
        if actual != value_hash {
            return Err(
                PersistCachedExpressionValueIndexedLoadError::ValueHashMismatch {
                    expected: value_hash,
                    actual,
                },
            );
        }
        Ok(Some(value))
    }

    /// Materializes a cached expression payload and links it from node metadata.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing, encoding, writing,
    /// or updating node metadata. [`MaterializationDecision::Materialize`]
    /// writes the payload through the indexed `values/` pack and then records
    /// the resulting [`ValueHash`] in the demand-node metadata sidecar while
    /// preserving existing reuse counters for `node_key`.
    ///
    /// This helper is explicit and non-transactional: if the value-pack write
    /// succeeds but the node metadata write fails, the indexed value remains
    /// addressable by value hash but is not linked from `node_key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedWriteError`] when
    /// materialization is requested and the payload cannot be hashed, encoded,
    /// indexed, or linked from node metadata.
    pub fn materialize_cached_expression_node_value_indexed(
        &self,
        node_key: PersistNodeMetadataKey,
        value: &CachedExpressionValue,
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistCachedExpressionNodeValueIndexedWriteError> {
        let MaterializationDecision::Materialize = decision else {
            return Ok(PersistMaterialization::Skipped);
        };
        let value_hash = value
            .value_hash()
            .map_err(|source| PersistCachedExpressionNodeValueIndexedWriteError::Hash { source })?;
        let payload = value.encode_persistent_payload().map_err(|source| {
            PersistCachedExpressionNodeValueIndexedWriteError::Encode { source }
        })?;
        let blob_key = PersistBlobKey::for_value(value_hash.as_durable_hash());
        let materialization = self
            .materialize_blob_indexed(blob_key, &payload, MaterializationDecision::Materialize)
            .map_err(
                |source| PersistCachedExpressionNodeValueIndexedWriteError::Write { source },
            )?;
        self.record_node_materialized_value_hash(node_key, value_hash)
            .map_err(
                |source| PersistCachedExpressionNodeValueIndexedWriteError::Metadata { source },
            )?;
        Ok(materialization)
    }

    /// Applies materialization threshold signals to a node-linked payload write.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through
    /// [`Self::materialize_cached_expression_node_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedWriteError`] when the
    /// signals choose materialization and the payload cannot be hashed,
    /// encoded, indexed, or linked from node metadata.
    pub fn materialize_cached_expression_node_value_indexed_with_signals(
        &self,
        node_key: PersistNodeMetadataKey,
        value: &CachedExpressionValue,
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistCachedExpressionNodeValueIndexedWriteError> {
        self.materialize_cached_expression_node_value_indexed(node_key, value, signals.decide())
    }

    /// Loads a cached expression payload through one demand-node metadata key.
    ///
    /// Missing node metadata, metadata without a materialized value hash, and
    /// missing indexed value blobs all return `Ok(None)`. Present value blobs
    /// are decoded and rehashed by [`Self::load_cached_expression_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedLoadError`] if node
    /// metadata cannot be read or the linked value payload cannot be loaded.
    pub fn load_cached_expression_node_value_indexed(
        &self,
        node_key: PersistNodeMetadataKey,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionNodeValueIndexedLoadError>
    {
        let Some(value_hash) =
            self.lookup_node_materialized_value_hash(node_key)
                .map_err(
                    |source| PersistCachedExpressionNodeValueIndexedLoadError::Metadata { source },
                )?
        else {
            return Ok(None);
        };
        self.load_cached_expression_value_indexed(value_hash)
            .map_err(|source| PersistCachedExpressionNodeValueIndexedLoadError::Value { source })
    }

    /// Loads a node-linked payload after value-associated trace revalidation.
    ///
    /// This helper is for trace-backed durable hit selection. Missing node
    /// metadata, missing trace records, trace records whose associated
    /// [`ValueHash`] differs from the current node metadata link, tombstone
    /// trace records, stale input observations, and missing indexed value blobs
    /// all return `Ok(None)`. The revalidator is called only after the node
    /// metadata value hash and trace-record value hash match.
    ///
    /// This does not insert the value into the in-memory demand graph or choose
    /// evaluator hits; it only proves that the persistent node metadata, trace,
    /// and value payload agree at this cache boundary.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueTraceLoadError`] if node
    /// metadata, the trace log, or the linked value payload cannot be read.
    pub fn load_cached_expression_node_value_with_trace_revalidation<R>(
        &self,
        node_key: PersistNodeMetadataKey,
        revalidator: &mut R,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionNodeValueTraceLoadError>
    where
        R: ImpureInputRevalidator + ?Sized,
    {
        let Some(value_hash) =
            self.lookup_node_materialized_value_hash(node_key)
                .map_err(
                    |source| PersistCachedExpressionNodeValueTraceLoadError::Metadata { source },
                )?
        else {
            return Ok(None);
        };
        let Some(trace) = self
            .lookup_node_trace(node_key)
            .map_err(|source| PersistCachedExpressionNodeValueTraceLoadError::Trace { source })?
        else {
            return Ok(None);
        };
        if trace.value_hash() != value_hash {
            return Ok(None);
        }
        if trace.payload().is_tombstone() {
            return Ok(None);
        }
        if !revalidate_persist_node_trace_payload(trace.payload(), revalidator) {
            return Ok(None);
        }
        self.load_cached_expression_value_indexed(value_hash)
            .map_err(|source| PersistCachedExpressionNodeValueTraceLoadError::Value { source })
    }

    /// Applies `decision` to `payload` in the packfile selected by `key`.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing or writing
    /// `payload`. [`MaterializationDecision::Materialize`] appends the payload
    /// through [`Self::append_blob`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the selected advisory lock
    /// cannot be acquired, the selected same-root blob write lock is poisoned,
    /// the selected packfile cannot be opened, validated, or written, or when
    /// `payload` does not hash to `key.hash()`.
    pub fn materialize_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistBlobPackError> {
        match decision {
            MaterializationDecision::Materialize => self
                .append_blob(key, payload)
                .map(PersistMaterialization::Materialized),
            MaterializationDecision::KeepInMemory => Ok(PersistMaterialization::Skipped),
        }
    }

    /// Applies `decision` to `payload` and records materialized blobs in the
    /// sidecar index.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing or writing
    /// `payload`. [`MaterializationDecision::Materialize`] ensures the payload
    /// is present through [`Self::ensure_blob_indexed`].
    ///
    /// This helper is explicit and non-transactional: if a fresh pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the selected in-process
    /// materialization advisory lock cannot be acquired, the selected
    /// in-process materialization lock is poisoned, the selected packfile
    /// cannot append/verify a fresh payload, or the selected sidecar index
    /// cannot write a fresh hash-to-offset record. A sidecar lookup failure
    /// falls back to the append path.
    pub fn materialize_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistBlobIndexedWriteError> {
        match decision {
            MaterializationDecision::Materialize => self
                .ensure_blob_indexed(key, payload)
                .map(|entry| PersistMaterialization::Materialized(entry.location())),
            MaterializationDecision::KeepInMemory => Ok(PersistMaterialization::Skipped),
        }
    }

    /// Applies materialization threshold signals to `payload`.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_blob`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the selected advisory lock
    /// cannot be acquired, the selected same-root blob write lock is poisoned,
    /// the selected packfile cannot be opened, validated, or written, or when
    /// `payload` does not hash to `key.hash()`.
    pub fn materialize_blob_with_signals(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistBlobPackError> {
        self.materialize_blob(key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to indexed blob materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_blob_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the selected in-process
    /// materialization advisory lock cannot be acquired, the selected
    /// in-process materialization lock is poisoned, the selected packfile
    /// cannot append/verify a fresh payload, or the selected sidecar index
    /// cannot write a fresh hash-to-offset record. A sidecar lookup failure
    /// falls back to the append path.
    pub fn materialize_blob_indexed_with_signals(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistBlobIndexedWriteError> {
        self.materialize_blob_indexed(key, payload, signals.decide())
    }

    /// Applies `decision` to a frontend file artifact payload.
    ///
    /// The artifact mapping key is derived from `file_key` and `parse_key`.
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, appends it to the `files/` pack, and returns the typed
    /// index value a future durable index would store. The appended record is
    /// registered as a same-process pending file-artifact root until
    /// [`Self::record_file_artifact`] publishes the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the advisory file-blob
    /// write lock cannot be acquired, the same-root file-blob write lock is
    /// poisoned, or the `files/` pack cannot be opened, validated, or written.
    pub fn materialize_file_artifact(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistBlobPackError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let location = self.append_pending_file_artifact_blob(
                    PersistBlobKey::for_file(blob_hash),
                    payload,
                    PersistBlobLiveRootSource::PendingFileArtifact,
                )?;
                Ok(PersistFileArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value: PersistFileArtifactIndexValue::new(blob_hash, location),
                })
            }
        }
    }

    /// Applies `decision` to a frontend file artifact and records index entries.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, ensures it is present in the `files/` pack through
    /// [`Self::ensure_blob_indexed`], and records the file-artifact mapping
    /// through [`Self::record_file_artifact`].
    ///
    /// This helper is explicit and non-transactional: if the blob append or
    /// blob-index write succeeds but the file-artifact index write fails, the
    /// blob bytes and any blob hash-to-offset record remain without a
    /// corresponding file-artifact mapping record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// verified/reused, appended, or indexed, or when the file-artifact mapping
    /// cannot be recorded.
    pub fn materialize_file_artifact_indexed(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistFileArtifactIndexedWriteError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let blob_entry = self
                    .ensure_blob_indexed(PersistBlobKey::for_file(blob_hash), payload)
                    .map_err(|source| PersistFileArtifactIndexedWriteError::Blob { source })?;
                let index_value =
                    PersistFileArtifactIndexValue::new(blob_hash, blob_entry.location());
                self.record_file_artifact(PersistFileArtifactIndexEntry::new(
                    artifact_key,
                    index_value,
                ))
                .map_err(|source| PersistFileArtifactIndexedWriteError::Index { source })?;
                Ok(PersistFileArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value,
                })
            }
        }
    }

    /// Applies `decision` to a frontend parse artifact payload.
    ///
    /// The artifact mapping key is derived only from `parse_key`.
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, appends it to the `files/` pack, and returns the typed
    /// index value a future durable index would store. The appended record is
    /// registered as a same-process pending parse-artifact root until
    /// [`Self::record_parse_artifact`] publishes the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the advisory file-blob
    /// write lock cannot be acquired, the same-root file-blob write lock is
    /// poisoned, or the `files/` pack cannot be opened, validated, or written.
    pub fn materialize_parse_artifact(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistParseArtifactMaterialization, PersistBlobPackError> {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistParseArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let location = self.append_pending_file_artifact_blob(
                    PersistBlobKey::for_file(blob_hash),
                    payload,
                    PersistBlobLiveRootSource::PendingParseArtifact,
                )?;
                Ok(PersistParseArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value: PersistParseArtifactIndexValue::new(blob_hash, location),
                })
            }
        }
    }

    /// Applies `decision` to a frontend parse artifact and records index entries.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, ensures it is present in the `files/` pack through
    /// [`Self::ensure_blob_indexed`], and records the parse-artifact mapping
    /// through [`Self::record_parse_artifact`].
    ///
    /// This helper is explicit and non-transactional: if the blob append or
    /// blob-index write succeeds but the parse-artifact index write fails, the
    /// blob bytes and any blob hash-to-offset record remain without a
    /// corresponding parse-artifact mapping record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// verified/reused, appended, or indexed, or when the parse-artifact mapping
    /// cannot be recorded.
    pub fn materialize_parse_artifact_indexed(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactIndexedWriteError> {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistParseArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let blob_entry = self
                    .ensure_blob_indexed(PersistBlobKey::for_file(blob_hash), payload)
                    .map_err(|source| PersistParseArtifactIndexedWriteError::Blob { source })?;
                let index_value =
                    PersistParseArtifactIndexValue::new(blob_hash, blob_entry.location());
                self.record_parse_artifact(PersistParseArtifactIndexEntry::new(
                    artifact_key,
                    index_value,
                ))
                .map_err(|source| PersistParseArtifactIndexedWriteError::Index { source })?;
                Ok(PersistParseArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value,
                })
            }
        }
    }

    /// Applies materialization threshold signals to a frontend file artifact.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_file_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the advisory file-blob
    /// write lock cannot be acquired, the same-root file-blob write lock is
    /// poisoned, or the `files/` pack cannot be opened, validated, or written.
    pub fn materialize_file_artifact_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistBlobPackError> {
        self.materialize_file_artifact(file_key, parse_key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to indexed file-artifact materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_file_artifact_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// verified/reused, appended, or indexed, or when the file-artifact mapping
    /// cannot be recorded.
    pub fn materialize_file_artifact_indexed_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistFileArtifactIndexedWriteError> {
        self.materialize_file_artifact_indexed(file_key, parse_key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to a frontend parse artifact.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the advisory file-blob
    /// write lock cannot be acquired, the same-root file-blob write lock is
    /// poisoned, or the `files/` pack cannot be opened, validated, or written.
    pub fn materialize_parse_artifact_with_signals(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistParseArtifactMaterialization, PersistBlobPackError> {
        self.materialize_parse_artifact(parse_key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to indexed parse-artifact materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// appended/indexed, or when the parse-artifact mapping cannot be recorded.
    pub fn materialize_parse_artifact_indexed_with_signals(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactIndexedWriteError> {
        self.materialize_parse_artifact_indexed(parse_key, payload, signals.decide())
    }

    /// Reads and verifies a materialized frontend file artifact.
    ///
    /// This is a typed wrapper over [`Self::read_blob`] for values decoded from
    /// the future file-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the same-root `files/` pack lock is
    /// poisoned, if the `files/` pack cannot be opened or read, if
    /// `index_value` points at an invalid location, or if the record or payload
    /// hash does not match `index_value`.
    pub fn read_file_artifact(
        &self,
        index_value: PersistFileArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        let _read_guard = self.root_locks.lock_blob_pack(PersistBlobStore::Files)?;
        self.read_file_artifact_unlocked(index_value)
    }

    fn read_file_artifact_unlocked(
        &self,
        index_value: PersistFileArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob(index_value.blob_key(), index_value.location())
    }

    /// Reads and verifies a materialized frontend parse artifact.
    ///
    /// This is a typed wrapper over [`Self::read_blob`] for values decoded from
    /// the parse-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the same-root `files/` pack lock is
    /// poisoned, if the `files/` pack cannot be opened or read, if
    /// `index_value` points at an invalid location, or if the record or payload
    /// hash does not match `index_value`.
    pub fn read_parse_artifact(
        &self,
        index_value: PersistParseArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        let _read_guard = self.root_locks.lock_blob_pack(PersistBlobStore::Files)?;
        self.read_parse_artifact_unlocked(index_value)
    }

    fn read_parse_artifact_unlocked(
        &self,
        index_value: PersistParseArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob(index_value.blob_key(), index_value.location())
    }

    /// Reads a materialized parse-artifact bundle into a parse-cache entry.
    ///
    /// This adapter consumes a caller-supplied parse-artifact index value and
    /// target entry. The decoded bundle must validate against the current
    /// parse-cache schema before any entry files are written. This adapter does
    /// not perform durable index lookup or decide whether the hydrated entry
    /// should be used for a cache hit.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if the artifact cannot be
    /// read from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_parse_artifact_bundle(
        &self,
        index_value: PersistParseArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let _read_guard = self
            .root_locks
            .lock_blob_pack(PersistBlobStore::Files)
            .map_err(|source| PersistParseArtifactHydrationError::Read { source })?;
        self.hydrate_parse_artifact_bundle_unlocked(index_value, entry)
    }

    fn hydrate_parse_artifact_bundle_unlocked(
        &self,
        index_value: PersistParseArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let payload = self
            .read_parse_artifact_unlocked(index_value)
            .map_err(|source| PersistParseArtifactHydrationError::Read { source })?;
        let bundle = ParseArtifactBundle::decode(&payload)
            .map_err(|source| PersistParseArtifactHydrationError::Decode { source })?;
        bundle
            .validate_meta(PARSE_CACHE_SCHEMA_VERSION)
            .map_err(|source| PersistParseArtifactHydrationError::Validate { source })?;
        entry
            .write_artifact_bundle(&bundle)
            .map_err(|source| PersistParseArtifactHydrationError::Write { source })
    }

    /// Reads a keyed parse-artifact bundle into a parse-cache entry.
    ///
    /// The supplied `artifact_key` must match the key derived from `parse_key`
    /// before the `files/` pack is read. This adapter still relies on its
    /// caller to perform the durable index lookup.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if `artifact_key` does not
    /// match `parse_key`, if the artifact cannot be read from the `files/` pack,
    /// if the payload is not a valid [`ParseArtifactBundle`], if the bundle
    /// metadata/artifact counts do not validate, or if the target entry cannot
    /// be written.
    pub fn hydrate_parse_artifact_bundle_for_key(
        &self,
        parse_key: ParseCacheKey,
        artifact_key: PersistParseArtifactKey,
        index_value: PersistParseArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let expected = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        if artifact_key != expected {
            return Err(PersistParseArtifactHydrationError::KeyMismatch {
                expected,
                actual: artifact_key,
            });
        }
        self.hydrate_parse_artifact_bundle(index_value, entry)
    }

    /// Reads an indexed parse-artifact bundle into a parse-cache entry.
    ///
    /// This is the entry-shaped variant of
    /// [`Self::hydrate_parse_artifact_bundle_for_key`]. It still relies on its
    /// caller to perform the durable index lookup that produced `index_entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if `index_entry.key()`
    /// does not match `parse_key`, if the artifact cannot be read from the
    /// `files/` pack, if the payload is not a valid [`ParseArtifactBundle`], if
    /// the bundle metadata/artifact counts do not validate, or if the target
    /// entry cannot be written.
    pub fn hydrate_parse_artifact_bundle_from_entry(
        &self,
        parse_key: ParseCacheKey,
        index_entry: PersistParseArtifactIndexEntry,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        self.hydrate_parse_artifact_bundle_for_key(
            parse_key,
            index_entry.key(),
            index_entry.value(),
            entry,
        )
    }

    /// Reads a materialized parse-artifact bundle into a parse-cache entry.
    ///
    /// This adapter consumes a caller-supplied file-artifact index value and
    /// target entry. The decoded bundle must validate against the current
    /// parse-cache schema before any entry files are written. This adapter does
    /// not perform durable index lookup or decide whether the hydrated entry
    /// should be used for a cache hit.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if the artifact cannot be
    /// read from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_file_artifact_bundle(
        &self,
        index_value: PersistFileArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let _read_guard = self
            .root_locks
            .lock_blob_pack(PersistBlobStore::Files)
            .map_err(|source| PersistFileArtifactHydrationError::Read { source })?;
        self.hydrate_file_artifact_bundle_unlocked(index_value, entry)
    }

    fn hydrate_file_artifact_bundle_unlocked(
        &self,
        index_value: PersistFileArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let payload = self
            .read_file_artifact_unlocked(index_value)
            .map_err(|source| PersistFileArtifactHydrationError::Read { source })?;
        let bundle = ParseArtifactBundle::decode(&payload)
            .map_err(|source| PersistFileArtifactHydrationError::Decode { source })?;
        bundle
            .validate_meta(PARSE_CACHE_SCHEMA_VERSION)
            .map_err(|source| PersistFileArtifactHydrationError::Validate { source })?;
        entry
            .write_artifact_bundle(&bundle)
            .map_err(|source| PersistFileArtifactHydrationError::Write { source })
    }

    /// Reads a keyed parse-artifact bundle into a parse-cache entry.
    ///
    /// The supplied `artifact_key` must match the key derived from `file_key`
    /// and `parse_key` before the `files/` pack is read. This adapter still
    /// relies on its caller to perform the durable index lookup.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if `artifact_key` does not
    /// match `file_key`/`parse_key`, if the artifact cannot be read from the
    /// `files/` pack, if the payload is not a valid [`ParseArtifactBundle`], if
    /// the bundle metadata/artifact counts do not validate, or if the target
    /// entry cannot be written.
    pub fn hydrate_file_artifact_bundle_for_key(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        artifact_key: PersistFileArtifactKey,
        index_value: PersistFileArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let expected = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        if artifact_key != expected {
            return Err(PersistFileArtifactHydrationError::KeyMismatch {
                expected,
                actual: artifact_key,
            });
        }
        self.hydrate_file_artifact_bundle(index_value, entry)
    }

    /// Reads an indexed parse-artifact bundle into a parse-cache entry.
    ///
    /// This is the entry-shaped variant of
    /// [`Self::hydrate_file_artifact_bundle_for_key`]. It still relies on its
    /// caller to perform the durable index lookup that produced `index_entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if `index_entry.key()`
    /// does not match `file_key`/`parse_key`, if the artifact cannot be read
    /// from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_file_artifact_bundle_from_entry(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        index_entry: PersistFileArtifactIndexEntry,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        self.hydrate_file_artifact_bundle_for_key(
            file_key,
            parse_key,
            index_entry.key(),
            index_entry.value(),
            entry,
        )
    }

    /// Looks up and hydrates an indexed parse-artifact bundle.
    ///
    /// This is the cache-level hit adapter for the explicit file-artifact
    /// sidecar index. It derives the expected mapping key from `file_key` and
    /// `parse_key`, returns `Ok(None)` when the index has no matching entry,
    /// and otherwise validates and writes the indexed bundle into `entry`. The
    /// same-root file store and file-artifact locks are held across lookup and
    /// pack read so same-process repacks cannot expose a split sidecar/pack
    /// view.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedHydrationError`] if the
    /// file-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into `entry`.
    pub fn hydrate_file_artifact_bundle_from_index(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexedHydrationError>
    {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        let _file_guard = self
            .root_locks
            .lock_blob_pack(PersistBlobStore::Files)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Hydrate {
                source: PersistFileArtifactHydrationError::Read { source },
            })?;
        let _file_artifact_guard = self
            .root_locks
            .lock_file_artifacts()
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Lookup { source })?;
        let Some(index_value) = self
            .file_artifact_index
            .lookup(artifact_key)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Lookup { source })?
        else {
            return Ok(None);
        };
        let index_entry = PersistFileArtifactIndexEntry::new(artifact_key, index_value);
        self.hydrate_file_artifact_bundle_unlocked(index_value, entry)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Hydrate { source })?;
        Ok(Some(index_entry))
    }

    /// Looks up and hydrates an indexed parse-artifact bundle.
    ///
    /// This is the cache-level hit adapter for the parse-artifact sidecar
    /// index. It derives the expected mapping key from `parse_key`, returns
    /// `Ok(None)` when the index has no matching entry, and otherwise validates
    /// and writes the indexed bundle into `entry`. The same-root file store
    /// and parse-artifact locks are held across lookup and pack read so
    /// same-process repacks cannot expose a split sidecar/pack view.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedHydrationError`] if the
    /// parse-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into `entry`.
    pub fn hydrate_parse_artifact_bundle_from_index(
        &self,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
    ) -> Result<Option<PersistParseArtifactIndexEntry>, PersistParseArtifactIndexedHydrationError>
    {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        let _file_guard = self
            .root_locks
            .lock_blob_pack(PersistBlobStore::Files)
            .map_err(
                |source| PersistParseArtifactIndexedHydrationError::Hydrate {
                    source: PersistParseArtifactHydrationError::Read { source },
                },
            )?;
        let _parse_artifact_guard = self
            .root_locks
            .lock_parse_artifacts()
            .map_err(|source| PersistParseArtifactIndexedHydrationError::Lookup { source })?;
        let Some(index_value) = self
            .parse_artifact_index
            .lookup(artifact_key)
            .map_err(|source| PersistParseArtifactIndexedHydrationError::Lookup { source })?
        else {
            return Ok(None);
        };
        let index_entry = PersistParseArtifactIndexEntry::new(artifact_key, index_value);
        self.hydrate_parse_artifact_bundle_unlocked(index_value, entry)
            .map_err(|source| PersistParseArtifactIndexedHydrationError::Hydrate { source })?;
        Ok(Some(index_entry))
    }

    /// Derives parse identity from source bytes and hydrates the parse cache.
    ///
    /// This source-shaped adapter derives `ParseCacheKey` through
    /// `parse_cache` and hydrates the parse cache's normal entry directory when
    /// the persistent parse-artifact index has a matching bundle. Missing index
    /// entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedHydrationError`] if the
    /// parse-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_parse_index(
        &self,
        parse_cache: &ParseCache,
        source: &[u8],
    ) -> Result<Option<PersistParseArtifactIndexEntry>, PersistParseArtifactIndexedHydrationError>
    {
        let parse_key = parse_cache.key_for_source(source);
        let entry = parse_cache.entry_for_key(parse_key);
        self.hydrate_parse_artifact_bundle_from_index(parse_key, &entry)
    }

    /// Loads an indexed parse-cache hit for caller-supplied source bytes.
    ///
    /// This is a source-shaped load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_parse_index`] and
    /// [`ParseCache::load_cached_bytes`]. It derives identity from `source`
    /// bytes alone, hydrates the normal parse-cache entry from the persistent
    /// parse-artifact index, and returns the hydrated entry as a
    /// [`CachedParse`] hit. Missing parse-artifact index entries return
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseBytesIndexedLoadError`] if the parse-artifact
    /// index cannot be read, a matching indexed artifact cannot be hydrated, or
    /// the hydrated parse-cache entry cannot be read back as a [`CachedParse`].
    pub fn load_parse_cache_bytes_from_index(
        &self,
        parse_cache: &ParseCache,
        source: &[u8],
    ) -> Result<Option<CachedParse>, PersistParseBytesIndexedLoadError> {
        if self
            .hydrate_parse_cache_entry_from_parse_index(parse_cache, source)
            .map_err(|source| PersistParseBytesIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(source)
            .map_err(|source| PersistParseBytesIndexedLoadError::Load { source })
    }

    /// Derives parse identities from source bytes and hydrates the parse cache.
    ///
    /// This source-shaped adapter derives `ParseFileKey` from `realpath` and
    /// `source`, derives `ParseCacheKey` through `parse_cache`, and hydrates
    /// the parse cache's normal entry directory when the persistent
    /// file-artifact index has a matching bundle. Missing index entries return
    /// `Ok(None)`.
    ///
    /// `realpath` must already be the canonical path used for file-artifact
    /// identity; this helper does not canonicalize or read source files.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedHydrationError`] if the
    /// file-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_source_index(
        &self,
        parse_cache: &ParseCache,
        realpath: impl AsRef<Path>,
        source: &[u8],
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexedHydrationError>
    {
        let file_key = ParseFileKey::for_source(realpath.as_ref(), source);
        let parse_key = parse_cache.key_for_source(source);
        let entry = parse_cache.entry_for_key(parse_key);
        self.hydrate_file_artifact_bundle_from_index(&file_key, parse_key, &entry)
    }

    /// Loads an indexed parse-cache hit for caller-supplied source bytes.
    ///
    /// This is a source-shaped load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_source_index`] and
    /// [`ParseCache::load_cached_bytes`]. It derives both identities from the
    /// same canonical `realpath` and `source` bytes, hydrates the normal
    /// parse-cache entry from the persistent file-artifact index, and returns
    /// the hydrated entry as a [`CachedParse`] hit. Missing file-artifact index
    /// entries return `Ok(None)`.
    ///
    /// `realpath` must already be the canonical path used for file-artifact
    /// identity; this helper does not canonicalize or read source files.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseSourceIndexedLoadError`] if the file-artifact index
    /// cannot be read, a matching indexed artifact cannot be hydrated, or the
    /// hydrated parse-cache entry cannot be read back as a [`CachedParse`].
    pub fn load_parse_cache_source_from_index(
        &self,
        parse_cache: &ParseCache,
        realpath: impl AsRef<Path>,
        source: &[u8],
    ) -> Result<Option<CachedParse>, PersistParseSourceIndexedLoadError> {
        if self
            .hydrate_parse_cache_entry_from_source_index(parse_cache, realpath, source)
            .map_err(|source| PersistParseSourceIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(source)
            .map_err(|source| PersistParseSourceIndexedLoadError::Load { source })
    }

    /// Canonicalizes a source path and hydrates the matching parse-cache entry.
    ///
    /// This file-shaped adapter canonicalizes `path`, reads the canonical
    /// source bytes, derives the file and parse identities from those bytes,
    /// and delegates to [`Self::hydrate_parse_cache_entry_from_source_index`].
    /// Missing file-artifact index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseFileIndexedHydrationError`] if `path` cannot be
    /// canonicalized, the canonical source file cannot be read, the
    /// file-artifact index cannot be read, or a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_file_index(
        &self,
        parse_cache: &ParseCache,
        path: impl AsRef<Path>,
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistParseFileIndexedHydrationError> {
        let requested = path.as_ref();
        let realpath = fs::canonicalize(requested).map_err(|source| {
            PersistParseFileIndexedHydrationError::CanonicalizeSource {
                path: requested.to_path_buf(),
                source,
            }
        })?;
        let source = fs::read(&realpath).map_err(|source| {
            PersistParseFileIndexedHydrationError::ReadSource {
                path: realpath.clone(),
                source,
            }
        })?;
        self.hydrate_parse_cache_entry_from_source_index(parse_cache, &realpath, &source)
            .map_err(|source| PersistParseFileIndexedHydrationError::Hydrate { source })
    }

    /// Canonicalizes a source path and loads an indexed parse-cache hit.
    ///
    /// This is an explicit load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_source_index`] and
    /// [`ParseCache::load_cached_bytes`]. It canonicalizes `path`, reads the
    /// canonical source bytes, hydrates the normal parse-cache entry from the
    /// persistent file-artifact index, and returns the hydrated entry as a
    /// [`CachedParse`] hit. Missing file-artifact index entries return
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseFileIndexedLoadError`] if `path` cannot be
    /// canonicalized, the canonical source file cannot be read, the
    /// file-artifact index cannot be read, a matching indexed artifact cannot
    /// be hydrated, or the hydrated parse-cache entry cannot be read back as a
    /// [`CachedParse`].
    pub fn load_parse_cache_file_from_index(
        &self,
        parse_cache: &ParseCache,
        path: impl AsRef<Path>,
    ) -> Result<Option<CachedParse>, PersistParseFileIndexedLoadError> {
        let requested = path.as_ref();
        let realpath = fs::canonicalize(requested).map_err(|source| {
            PersistParseFileIndexedLoadError::CanonicalizeSource {
                path: requested.to_path_buf(),
                source,
            }
        })?;
        let source =
            fs::read(&realpath).map_err(|source| PersistParseFileIndexedLoadError::ReadSource {
                path: realpath.clone(),
                source,
            })?;
        if self
            .hydrate_parse_cache_entry_from_source_index(parse_cache, &realpath, &source)
            .map_err(|source| PersistParseFileIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(&source)
            .map_err(|source| PersistParseFileIndexedLoadError::Load { source })
    }

    /// Applies `decision` to an existing parse-cache artifact entry.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without reading or encoding `entry`. [`MaterializationDecision::Materialize`]
    /// reads the entry as a [`ParseArtifactBundle`], encodes it as one payload,
    /// and appends it through [`Self::materialize_file_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the source entry cannot be
    /// read, the bundle payload cannot be encoded, the advisory file-blob write
    /// lock cannot be acquired, the same-root file-blob write lock is poisoned,
    /// or the `files/` pack cannot be written.
    pub fn materialize_parse_artifact_entry(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                validate_parse_cache_entry_key(parse_key, entry)?;
                let bundle = entry.read_artifact_bundle().map_err(|source| {
                    PersistParseArtifactMaterializationError::ReadBundle { source }
                })?;
                let payload = bundle.encode().map_err(|source| {
                    PersistParseArtifactMaterializationError::EncodeBundle { source }
                })?;
                self.materialize_file_artifact(
                    file_key,
                    parse_key,
                    &payload,
                    MaterializationDecision::Materialize,
                )
                .map_err(|source| PersistParseArtifactMaterializationError::Write { source })
            }
        }
    }

    /// Applies `decision` to an existing parse-cache entry and records indexes.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without reading or encoding `entry`. [`MaterializationDecision::Materialize`]
    /// reads the entry as a [`ParseArtifactBundle`], encodes it as one payload,
    /// then delegates to [`Self::materialize_file_artifact_indexed`] so the
    /// file blob is verified/reused or freshly indexed before the file-artifact
    /// mapping is recorded.
    ///
    /// This helper inherits the explicit non-transactional behavior of
    /// [`Self::materialize_file_artifact_indexed`]: a fresh blob append/index
    /// write can remain even when the file-artifact mapping write fails.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the source entry cannot be
    /// read, the bundle payload cannot be encoded, the `files/` blob cannot be
    /// appended/indexed, or the file-artifact mapping cannot be recorded.
    pub fn materialize_parse_artifact_entry_indexed(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                validate_parse_cache_entry_key(parse_key, entry)?;
                let bundle = entry.read_artifact_bundle().map_err(|source| {
                    PersistParseArtifactMaterializationError::ReadBundle { source }
                })?;
                let payload = bundle.encode().map_err(|source| {
                    PersistParseArtifactMaterializationError::EncodeBundle { source }
                })?;
                self.materialize_file_artifact_indexed(
                    file_key,
                    parse_key,
                    &payload,
                    MaterializationDecision::Materialize,
                )
                .map_err(|source| PersistParseArtifactMaterializationError::WriteIndexed { source })
            }
        }
    }

    /// Applies `decision` to an existing parse-cache entry and records parse indexes.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without reading or encoding `entry`. [`MaterializationDecision::Materialize`]
    /// reads the entry as a [`ParseArtifactBundle`], encodes it as one payload,
    /// appends it through [`Self::materialize_parse_artifact_indexed`], and
    /// records both blob and parse-artifact sidecar indexes.
    ///
    /// This helper inherits the explicit non-transactional behavior of
    /// [`Self::materialize_parse_artifact_indexed`]: a blob append/index write
    /// can remain even when the parse-artifact mapping write fails.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the source entry cannot be
    /// read, the bundle payload cannot be encoded, the `files/` blob cannot be
    /// appended/indexed, or the parse-artifact mapping cannot be recorded.
    pub fn materialize_parse_cache_entry_indexed(
        &self,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        decision: MaterializationDecision,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactMaterializationError> {
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistParseArtifactMaterialization::Skipped {
                    artifact_key: PersistParseArtifactKey::from_parse_cache_key(parse_key),
                })
            }
            MaterializationDecision::Materialize => {
                validate_parse_cache_entry_key(parse_key, entry)?;
                let bundle = entry.read_artifact_bundle().map_err(|source| {
                    PersistParseArtifactMaterializationError::ReadBundle { source }
                })?;
                let payload = bundle.encode().map_err(|source| {
                    PersistParseArtifactMaterializationError::EncodeBundle { source }
                })?;
                self.materialize_parse_artifact_indexed(
                    parse_key,
                    &payload,
                    MaterializationDecision::Materialize,
                )
                .map_err(|source| {
                    PersistParseArtifactMaterializationError::WriteParseIndexed { source }
                })
            }
        }
    }

    /// Applies materialization threshold signals to an existing parse-cache entry.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_entry`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when the signals
    /// choose [`MaterializationDecision::Materialize`] and the source entry
    /// cannot be read, the bundle payload cannot be encoded, the advisory
    /// file-blob write lock cannot be acquired, the same-root file-blob write
    /// lock is poisoned, or the `files/` pack cannot be written.
    pub fn materialize_parse_artifact_entry_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        self.materialize_parse_artifact_entry(file_key, parse_key, entry, signals.decide())
    }

    /// Applies threshold signals to indexed parse-cache entry materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_entry_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when the signals
    /// choose [`MaterializationDecision::Materialize`] and the source entry
    /// cannot be read, the bundle payload cannot be encoded, the `files/` blob
    /// cannot be appended/indexed, or the file-artifact mapping cannot be
    /// recorded.
    pub fn materialize_parse_artifact_entry_indexed_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        self.materialize_parse_artifact_entry_indexed(file_key, parse_key, entry, signals.decide())
    }

    /// Applies threshold signals to parse-keyed parse-cache entry materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_cache_entry_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when the signals
    /// choose [`MaterializationDecision::Materialize`] and the source entry
    /// cannot be read, the bundle payload cannot be encoded, the `files/` blob
    /// cannot be appended/indexed, or the parse-artifact mapping cannot be
    /// recorded.
    pub fn materialize_parse_cache_entry_indexed_with_signals(
        &self,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        signals: MaterializationSignals,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactMaterializationError> {
        self.materialize_parse_cache_entry_indexed(parse_key, entry, signals.decide())
    }
}

fn revalidate_persist_node_trace_payload<R>(
    payload: &PersistNodeTracePayload,
    revalidator: &mut R,
) -> bool
where
    R: ImpureInputRevalidator + ?Sized,
{
    if payload.is_tombstone() {
        return false;
    }
    for expected in payload.inputs() {
        let Some(fresh) = revalidator.revalidate_impure_input(expected.identity()) else {
            return false;
        };
        let Some(fresh) = fresh.as_cacheable() else {
            return false;
        };
        if fresh.identity() != expected.identity() {
            return false;
        }
        if fresh.observation_hash() != expected.observation_hash() {
            return false;
        }
    }
    true
}

fn validate_parse_cache_entry_key(
    parse_key: ParseCacheKey,
    entry: &ParseCacheEntry,
) -> Result<(), PersistParseArtifactMaterializationError> {
    let expected = parse_key.to_hex();
    let matches = entry
        .dir()
        .file_name()
        .map(|name| name.as_bytes() == expected.as_bytes())
        .unwrap_or(false);
    if matches {
        return Ok(());
    }
    Err(PersistParseArtifactMaterializationError::EntryKeyMismatch {
        expected: parse_key,
        path: entry.dir().to_path_buf(),
    })
}
