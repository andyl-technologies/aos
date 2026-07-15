//! The opened persistent eval-cache root and its store operations.
//!
//! [`PersistCache`] ties together the per-store packfiles and indexes, routing
//! blob and file-artifact reads, writes, materialization decisions, and parse
//! artifact hydration through the on-disk layout.

use super::*;

use crate::cache::hashing::{CacheHashFamily, cache_hash_family};

mod artifact_hydration;
mod artifact_materialization;
mod blob_index_rebuild;
mod blob_liveness;
mod blob_repack;
mod demotion;
mod indexed_values;
mod maintenance_types;
mod node_demand;
mod node_io;
mod open;
mod reachability;
mod repack_helpers;
mod root_record_io;
mod run_scope;
mod store_io;
mod file_write_behind;
mod value_write_behind;

pub use demotion::{
    PersistDemotionError, PersistDemotionOutcome, PersistDemotionPlan, PersistDemotionSkip,
};
pub use root_record_io::HydratedRootInstantiation;

pub use maintenance_types::{
    PersistBlobIndexRebuild, PersistBlobIndexRebuildPlan, PersistBlobIndexStaleEntry,
    PersistBlobLiveRoot, PersistBlobLiveRootSource, PersistBlobPackLivenessPlan,
    PersistBlobPackRepackPlan, PersistBlobPackTrim, PersistBlobPacksRepack,
    PersistBlobRecordRelocation, PersistCompaction, PersistDemotionCandidate,
    PersistFileBlobReachabilityPlan, PersistMissingNodeValueRoot, PersistNodeValueRoot,
    PersistNodeValueRootPlan, PersistStorageMaintenance, PersistStorageMaintenanceAction,
    PersistStorageMaintenanceOutcome, PersistStorageMaintenancePlan,
    PersistStorageMaintenancePolicy, PersistStorageRepack, PersistValueBlobReachabilityPlan,
    select_demotion_victims,
};

use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockMode};
use ratchet_cache::root_locks::{
    self as engine_root_locks, CacheRootLockError, CacheRootLockSlot,
    CacheRootLocks as EngineCacheRootLocks,
};
use repack_helpers::blob_live_root_identity;

/// An opened persistent eval-cache root.
///
/// Beyond the on-disk packs and sidecar indexes, a handle carries two
/// run-scoped in-memory coordination tables shared across clones of the same
/// opened root:
///
/// * a **verified-node memo** ([`Self::verified_node_trace_is_cached`]) that
///   records `(node key, value hash)` pairs already proven to be valid
///   trace-verified hits during the current run, so a dependency shared by many
///   dependents is verified once per run instead of once per dependent; and
/// * a **pending-demand buffer** ([`Self::buffer_node_current_demand`]) that
///   coalesces warm-hit demand observations in memory and writes them back once
///   at the run boundary rather than appending one sidecar record per hit.
///
/// Both tables are cleared/flushed at the run boundary
/// ([`Self::flush_buffered_node_demands`],
/// [`Self::clear_verified_node_trace_memo`]); the demand buffer additionally
/// flushes when the last handle to a root is dropped so its coalesced
/// observations are never silently lost.
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
    /// The content-hash family this root's keys and blob addresses are computed
    /// under (RFC-0007 §P4 Option C). A primary root is always opened under, and
    /// reconciled to, the process family; a secondary root reports the family
    /// recorded in its own manifest so a differently-configured reader can skip
    /// or (once wired) cross-probe it without re-keying its shared payload.
    hash_family: CacheHashFamily,
    /// Whether indexed value decoding re-hashes each decoded payload against its
    /// content-address key. Off by default; enabled through the
    /// `AOS_NIX_CACHE_VERIFY` knob for defensive verification.
    value_decode_verification: bool,
    /// Run-scoped `(node key, value hash)` pairs already proven valid this run.
    verified_node_traces: Arc<Mutex<BTreeMap<PersistNodeMetadataKey, ValueHash>>>,
    /// Run-scoped coalesced current-run demand counts awaiting write-back.
    pending_node_demands: Arc<Mutex<BTreeMap<PersistNodeMetadataKey, u64>>>,
    /// Whether the VALUES-store write-behind buffer is active (RFC-0007 §3.2(b));
    /// off by default, enabled through the `AOS_NIX_CACHE_WRITE_BEHIND` knob.
    write_behind_values: bool,
    /// VALUES-store blob records buffered in memory until the run-boundary flush.
    pending_value_blobs: Arc<Mutex<value_write_behind::PendingValueBatch>>,
    /// FILES-store file/parse-artifact records buffered until the run-boundary flush.
    pending_file_artifacts: Arc<Mutex<file_write_behind::PendingFileArtifactBatch>>,
}

impl Drop for PersistCache {
    /// Flushes any coalesced current-run demand observations when the last
    /// handle to this opened root is dropped.
    ///
    /// The run boundary normally flushes the demand buffer, but callers that
    /// drive the lower-level cache directly (without advancing a run boundary)
    /// still expect their observed demand to reach disk. Flushing on the final
    /// handle drop preserves that behavior. Errors are logged rather than
    /// propagated because a destructor cannot return them.
    fn drop(&mut self) {
        if Arc::strong_count(&self.pending_node_demands) != 1 {
            return;
        }
        // The run boundary is the normal flush point for the write-behind value
        // buffer; the final-handle drop is the safety net for callers that drive
        // the cache without advancing a run, mirroring the demand buffer.
        if Arc::strong_count(&self.pending_value_blobs) == 1 {
            if let Err(error) = self.flush_buffered_value_blobs() {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "persistent eval cache value write-behind flush on drop failed"
                );
            }
        }
        self.flush_file_artifacts_on_final_drop();
        if let Err(error) = self.flush_buffered_node_demands() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "persistent eval cache demand buffer flush on drop failed"
            );
        }
    }
}


/// Compaction fires when a node sidecar's physical record count exceeds this
/// multiple of its live keys. A warm re-run appends about one record per live
/// key, so a factor of four bounds the append log to a few runs' worth of churn
/// before it is rewritten to one record per key.
const NODE_SIDECAR_COMPACTION_FACTOR: u64 = 4;

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

/// Whether a persistent root is opened as the process's authoritative primary
/// or as additive, safe-to-lose secondary read capacity (RFC-0007 §P4 Option C
/// / MEMO-2 §5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistOpenMode {
    /// The primary root: reconciled to the process content-hash family and
    /// re-initialized on any family or schema-version mismatch.
    Primary,
    /// A secondary root: opened non-destructively under whatever family its own
    /// manifest records, so a differently-configured reader never rewrites or
    /// discards its shared payload.
    Secondary,
}

impl PersistCache {
    /// Returns this handle with indexed value-decode content re-hashing set.
    ///
    /// When `verify` is `false` (the default), indexed cached-expression value
    /// decoding trusts the content-address key and pack integrity header and
    /// skips recomputing each decoded payload's [`ValueHash`]. When `verify` is
    /// `true`, every decoded payload is re-hashed and must match its content
    /// address, restoring the fully defensive decode path.
    #[must_use]
    pub fn with_value_decode_verification(mut self, verify: bool) -> Self {
        self.value_decode_verification = verify;
        self
    }

    /// Returns whether indexed value decoding re-hashes decoded payloads.
    pub const fn value_decode_verification(&self) -> bool {
        self.value_decode_verification
    }

    /// Returns the content-hash family this root's keys and blob addresses use.
    ///
    /// A primary root reports the process family it was reconciled to; a
    /// secondary reports the family recorded in its own manifest (RFC-0007 §P4
    /// Option C). Two locations are probeable under one family's keys only when
    /// their families are equal.
    pub const fn hash_family(&self) -> CacheHashFamily {
        self.hash_family
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

    /// Plans automatic persistent storage maintenance.
    ///
    /// The plan first compares both blob-index sidecars to verified physical
    /// pack records, then computes value/file pack repack plans under the same
    /// policy. Callers can inspect [`PersistStorageMaintenancePlan::action`] to
    /// see whether automatic maintenance would repair indexes, repack blobs, or
    /// skip work. Index repair has priority over repacking so recoverable
    /// unindexed newest records are indexed before any policy-driven byte
    /// reclamation can delete them.
    ///
    /// # Errors
    ///
    /// Returns [`PersistStorageMaintenancePlanError`] if a blob-index rebuild
    /// plan or blob-pack repack plan cannot be produced.
    pub fn plan_storage_maintenance(
        &self,
        policy: PersistStorageMaintenancePolicy,
    ) -> Result<PersistStorageMaintenancePlan, PersistStorageMaintenancePlanError> {
        let value_blob_index = self
            .plan_blob_index_rebuild(PersistBlobStore::Values)
            .map_err(|source| PersistStorageMaintenancePlanError::ValueBlobIndex { source })?;
        let file_blob_index = self
            .plan_blob_index_rebuild(PersistBlobStore::Files)
            .map_err(|source| PersistStorageMaintenancePlanError::FileBlobIndex { source })?;
        let value_blob_pack = self
            .plan_blob_pack_repack(PersistBlobStore::Values)
            .map_err(|source| PersistStorageMaintenancePlanError::ValueBlobPack { source })?;
        let file_blob_pack = self
            .plan_blob_pack_repack(PersistBlobStore::Files)
            .map_err(|source| PersistStorageMaintenancePlanError::FileBlobPack { source })?;
        Ok(PersistStorageMaintenancePlan::new(
            policy,
            PersistBlobIndexRebuild::new(value_blob_index, file_blob_index),
            value_blob_pack,
            file_blob_pack,
        ))
    }

    /// Runs automatic persistent storage maintenance under `policy`.
    ///
    /// The automatic action is conservative. If blob-index repair is needed,
    /// this runs [`Self::compact_storage`] even when the same plan also shows
    /// reclaimable pack bytes, because the repair step can make previously
    /// unindexed records live. Only repair-clean plans whose reclaimable bytes
    /// meet [`PersistStorageMaintenancePolicy::min_repack_reclaimable_bytes`]
    /// run [`Self::repack_storage`] after a fresh [`Self::compact_storage`]
    /// sweep. That pre-repack sweep repairs records visible to that sweep, but
    /// it is not a transaction with the later repack; callers that need
    /// cache-level raw blob appends preserved across automatic repack must
    /// quiesce those writers under the same coordination requirement as
    /// explicit [`Self::repack_storage`]. Otherwise the cache is left
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns [`PersistStorageAutoMaintenanceError`] if planning fails, if the
    /// selected repair/compaction maintenance fails, or if the selected repack
    /// fails. Work completed by the selected explicit maintenance operation
    /// keeps that operation's normal non-transactional semantics.
    pub fn maintain_storage(
        &self,
        policy: PersistStorageMaintenancePolicy,
    ) -> Result<PersistStorageMaintenanceOutcome, PersistStorageAutoMaintenanceError> {
        let plan = self
            .plan_storage_maintenance(policy)
            .map_err(|source| PersistStorageAutoMaintenanceError::Plan { source })?;
        match plan.action() {
            PersistStorageMaintenanceAction::Skip => {
                Ok(PersistStorageMaintenanceOutcome::Skipped { plan })
            }
            PersistStorageMaintenanceAction::RepairIndexes => {
                let maintenance = self
                    .compact_storage()
                    .map_err(|source| PersistStorageAutoMaintenanceError::Repair { source })?;
                Ok(PersistStorageMaintenanceOutcome::Repaired { plan, maintenance })
            }
            PersistStorageMaintenanceAction::RepackBlobs => {
                let maintenance = self
                    .compact_storage()
                    .map_err(|source| PersistStorageAutoMaintenanceError::Repair { source })?;
                let repack = self
                    .repack_storage()
                    .map_err(|source| PersistStorageAutoMaintenanceError::Repack { source })?;
                Ok(PersistStorageMaintenanceOutcome::Repacked {
                    plan,
                    maintenance,
                    repack,
                })
            }
        }
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

fn validate_parse_cache_entry_key(
    parse_key: ParseCacheKey,
    entry: &ParseCacheEntry,
) -> Result<(), PersistParseArtifactMaterializationError> {
    let expected = parse_key.cache_dir_name();
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
