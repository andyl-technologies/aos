//! The opened persistent eval-cache root and its store operations.
//!
//! [`PersistCache`] ties together the per-store packfiles and indexes, routing
//! blob and file-artifact reads, writes, materialization decisions, and parse
//! artifact hydration through the on-disk layout.

use super::*;

mod blob_index_rebuild;
mod blob_liveness;
mod blob_repack;
mod indexed_values;
mod maintenance_types;
mod node_demand;
mod node_io;
mod reachability;
mod repack_helpers;
mod store_io;

pub use maintenance_types::{
    PersistBlobIndexRebuild, PersistBlobIndexRebuildPlan, PersistBlobIndexStaleEntry,
    PersistBlobLiveRoot, PersistBlobLiveRootSource, PersistBlobPackLivenessPlan,
    PersistBlobPackRepackPlan, PersistBlobPackTrim, PersistBlobPacksRepack,
    PersistBlobRecordRelocation, PersistCompaction, PersistFileBlobReachabilityPlan,
    PersistMissingNodeValueRoot, PersistNodeValueRoot, PersistNodeValueRootPlan,
    PersistStorageMaintenance, PersistStorageRepack, PersistValueBlobReachabilityPlan,
};

use ratchet_cache::file_lock::{AdvisoryFileLock, AdvisoryFileLockMode};
use ratchet_cache::root_locks::{
    self as engine_root_locks, CacheRootLockError, CacheRootLockSlot,
    CacheRootLocks as EngineCacheRootLocks,
};
use repack_helpers::blob_live_root_identity;

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
