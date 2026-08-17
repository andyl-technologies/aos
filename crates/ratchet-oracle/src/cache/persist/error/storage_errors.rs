//! Persistent storage maintenance error types.

use super::*;

/// Persistent sidecar compaction failed.
#[derive(Debug, Error)]
pub enum PersistCompactionError {
    /// The value blob index could not be compacted.
    #[error("failed to compact persistent value blob index")]
    ValueBlobIndex {
        /// The underlying blob index error.
        source: PersistBlobIndexError,
    },
    /// The file blob index could not be compacted.
    #[error("failed to compact persistent file blob index")]
    FileBlobIndex {
        /// The underlying blob index error.
        source: PersistBlobIndexError,
    },
    /// The file-artifact index could not be compacted.
    #[error("failed to compact persistent file artifact index")]
    FileArtifactIndex {
        /// The underlying file-artifact index error.
        source: PersistFileArtifactIndexError,
    },
    /// The parse-artifact index could not be compacted.
    #[error("failed to compact persistent parse artifact index")]
    ParseArtifactIndex {
        /// The underlying parse-artifact index error.
        source: PersistParseArtifactIndexError,
    },
    /// The demand-node metadata index could not be compacted.
    #[error("failed to compact persistent node metadata index")]
    NodeMetadataIndex {
        /// The underlying node metadata index error.
        source: PersistNodeMetadataIndexError,
    },
    /// The node verifying-trace log could not be compacted.
    #[error("failed to compact persistent node trace log")]
    NodeTraceLog {
        /// The underlying node trace log error.
        source: PersistNodeTraceLogError,
    },
}

/// Persistent blob live-root collection failed.
#[derive(Debug, Error)]
pub enum PersistBlobLiveRootError {
    /// The selected blob index could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent blob index live roots")]
    BlobIndex {
        /// The underlying blob-index lock or read error.
        source: PersistBlobIndexError,
    },
    /// The file-artifact index could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent file-artifact live roots")]
    FileArtifactIndex {
        /// The underlying file-artifact lock or read error.
        source: PersistFileArtifactIndexError,
    },
    /// The parse-artifact index could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent parse-artifact live roots")]
    ParseArtifactIndex {
        /// The underlying parse-artifact lock or read error.
        source: PersistParseArtifactIndexError,
    },
    /// The root-record index could not be snapshotted.
    #[error("failed to snapshot persistent root-record live roots")]
    RootRecordIndex {
        /// The underlying root-record index error.
        source: PersistRootRecordIndexError,
    },
    /// The shared root-record advisory lock could not be acquired.
    #[error("failed to acquire persistent root-record advisory lock at {path} for live roots")]
    RootRecordLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The same-process pending file-root registry could not be snapshotted.
    #[error("failed to snapshot pending persistent file roots")]
    PendingFileRoots,
    /// The selected blob index contained a key for the wrong blob namespace.
    #[error("persistent blob index entry targets {actual:?}, expected {expected:?}")]
    WrongStoreEntry {
        /// The blob namespace selected by the caller.
        expected: PersistBlobStore,
        /// The blob namespace encoded in the index entry.
        actual: PersistBlobStore,
    },
}

/// Persistent blob-pack tail trimming failed.
#[derive(Debug, Error)]
pub enum PersistBlobPackTrimError {
    /// The advisory blob-pack tail-trim write lock could not be acquired.
    #[error(
        "failed to acquire persistent blob-pack tail-trim advisory write lock for {store:?} at {path}"
    )]
    AdvisoryWriteLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The selected blob index could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent blob index before tail trim")]
    BlobIndex {
        /// The underlying blob-index lock or read error.
        source: PersistBlobIndexError,
    },
    /// The file-artifact index could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent file-artifact index before tail trim")]
    FileArtifactIndex {
        /// The underlying file-artifact lock or read error.
        source: PersistFileArtifactIndexError,
    },
    /// The parse-artifact index could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent parse-artifact index before tail trim")]
    ParseArtifactIndex {
        /// The underlying parse-artifact lock or read error.
        source: PersistParseArtifactIndexError,
    },
    /// The root-record index could not be snapshotted.
    #[error("failed to snapshot persistent root-record live roots before tail trim")]
    RootRecordIndex {
        /// The underlying root-record index error.
        source: PersistRootRecordIndexError,
    },
    /// The shared root-record advisory lock could not be acquired.
    #[error("failed to acquire persistent root-record advisory lock at {path} before tail trim")]
    RootRecordLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The same-process pending file-root registry could not be snapshotted.
    #[error("failed to snapshot pending persistent file roots before tail trim")]
    PendingFileRoots,
    /// The selected blob index contained a key for the wrong blob namespace.
    #[error("persistent blob index entry targets {actual:?}, expected {expected:?}")]
    WrongStoreEntry {
        /// The blob namespace selected by the caller.
        expected: PersistBlobStore,
        /// The blob namespace encoded in the index entry.
        actual: PersistBlobStore,
    },
    /// A latest live blob could not be read and verified before trimming.
    #[error("failed to verify persistent blob before tail trim")]
    Read {
        /// The underlying packfile read error.
        source: PersistBlobPackError,
    },
    /// The selected blob pack could not be inspected or truncated.
    #[error("failed to trim persistent blob pack tail")]
    Trim {
        /// The underlying packfile trim error.
        source: PersistBlobPackError,
    },
}

impl From<PersistBlobLiveRootError> for PersistBlobPackTrimError {
    fn from(source: PersistBlobLiveRootError) -> Self {
        match source {
            PersistBlobLiveRootError::BlobIndex { source } => Self::BlobIndex { source },
            PersistBlobLiveRootError::FileArtifactIndex { source } => {
                Self::FileArtifactIndex { source }
            }
            PersistBlobLiveRootError::ParseArtifactIndex { source } => {
                Self::ParseArtifactIndex { source }
            }
            PersistBlobLiveRootError::RootRecordIndex { source } => {
                Self::RootRecordIndex { source }
            }
            PersistBlobLiveRootError::RootRecordLock { path, source } => {
                Self::RootRecordLock { path, source }
            }
            PersistBlobLiveRootError::PendingFileRoots => Self::PendingFileRoots,
            PersistBlobLiveRootError::WrongStoreEntry { expected, actual } => {
                Self::WrongStoreEntry { expected, actual }
            }
        }
    }
}

/// Persistent blob-pack liveness planning failed.
#[derive(Debug, Error)]
pub enum PersistBlobPackLivenessPlanError {
    /// The advisory blob-store read lock could not be acquired.
    #[error(
        "failed to acquire persistent blob-pack liveness advisory read lock for {store:?} at {path}"
    )]
    AdvisoryReadLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// Live roots could not be locked, snapshotted, or decoded.
    #[error("failed to collect persistent blob live roots before liveness planning")]
    Roots {
        /// The underlying live-root collection error.
        source: PersistBlobLiveRootError,
    },
    /// A latest live root could not be verified before planning.
    #[error("failed to verify persistent blob root before liveness planning")]
    Read {
        /// The underlying packfile read error.
        source: PersistBlobPackError,
    },
    /// The selected blob pack could not be scanned and verified.
    #[error("failed to scan persistent blob pack before liveness planning")]
    Scan {
        /// The underlying packfile scan error.
        source: PersistBlobPackError,
    },
}

/// Persistent blob-pack repack planning failed.
#[derive(Debug, Error)]
pub enum PersistBlobPackRepackPlanError {
    /// The selected pack's liveness plan could not be produced.
    #[error("failed to plan persistent blob-pack liveness before repack planning")]
    Liveness {
        /// The underlying liveness planning error.
        source: PersistBlobPackLivenessPlanError,
    },
    /// The planned compacted pack length overflowed.
    #[error(
        "persistent blob-pack repack length overflow at record offset {record_offset} with payload length {payload_len}"
    )]
    RecordBoundsOverflow {
        /// The planned record offset that overflowed.
        record_offset: u64,
        /// The payload length for the record being placed.
        payload_len: u64,
    },
}

/// Persistent value blob-pack repack failed.
#[derive(Debug, Error)]
pub enum PersistValueBlobPackRepackError {
    /// The same-root value blob-pack write lock was poisoned.
    #[error("persistent value blob-pack repack write lock is poisoned")]
    WriteLockPoisoned,
    /// The advisory value blob-pack repack write lock could not be acquired.
    #[error("failed to acquire persistent value blob-pack repack advisory write lock at {path}")]
    AdvisoryWriteLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The value repack plan could not be produced.
    #[error("failed to plan persistent value blob-pack repack")]
    Plan {
        /// The underlying repack planning error.
        source: PersistBlobPackRepackPlanError,
    },
    /// The compacted value pack could not be written or swapped.
    #[error("failed to write or swap persistent value blob pack during repack")]
    Pack {
        /// The underlying packfile error.
        source: PersistBlobPackError,
    },
    /// The compacted value index could not be written or swapped.
    #[error("failed to write or swap persistent value blob index during repack")]
    BlobIndex {
        /// The underlying blob-index error.
        source: PersistBlobIndexError,
    },
}

/// Persistent file blob-pack repack failed.
#[derive(Debug, Error)]
pub enum PersistFileBlobPackRepackError {
    /// The same-root file blob-pack write lock was poisoned.
    #[error("persistent file blob-pack repack write lock is poisoned")]
    WriteLockPoisoned,
    /// The advisory file blob-pack repack write lock could not be acquired.
    #[error("failed to acquire persistent file blob-pack repack advisory write lock at {path}")]
    AdvisoryWriteLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// In-flight non-indexed file artifacts still point at the current pack.
    #[error(
        "persistent file blob-pack repack cannot run while {roots} pending artifact roots exist"
    )]
    PendingArtifactRoots {
        /// The number of same-process pending file-artifact roots.
        roots: usize,
    },
    /// The current pending root set could not be snapshotted.
    #[error("failed to snapshot pending persistent file roots before file blob-pack repack")]
    PendingRoots {
        /// The underlying pending-root error.
        source: PersistBlobLiveRootError,
    },
    /// The file repack plan could not be produced.
    #[error("failed to plan persistent file blob-pack repack")]
    Plan {
        /// The underlying repack planning error.
        source: PersistBlobPackRepackPlanError,
    },
    /// A sidecar root had no planned relocation in the compacted file pack.
    #[error("persistent file blob-pack repack is missing a relocation for {key:?} at {location:?}")]
    MissingRelocation {
        /// The rooted file-blob key.
        key: PersistBlobKey,
        /// The rooted file-blob location.
        location: PersistBlobLocation,
    },
    /// The compacted file pack could not be written or swapped.
    #[error("failed to write or swap persistent file blob pack during repack")]
    Pack {
        /// The underlying packfile error.
        source: PersistBlobPackError,
    },
    /// The compacted file blob index could not be written or swapped.
    #[error("failed to write or swap persistent file blob index during repack")]
    BlobIndex {
        /// The underlying blob-index error.
        source: PersistBlobIndexError,
    },
    /// The relocated file-artifact mapping index could not be written or swapped.
    #[error("failed to write or swap persistent file-artifact index during file blob-pack repack")]
    FileArtifactIndex {
        /// The underlying file-artifact index error.
        source: PersistFileArtifactIndexError,
    },
    /// The relocated parse-artifact mapping index could not be written or swapped.
    #[error("failed to write or swap persistent parse-artifact index during file blob-pack repack")]
    ParseArtifactIndex {
        /// The underlying parse-artifact index error.
        source: PersistParseArtifactIndexError,
    },
    /// The relocated root-record index could not be read, written, or swapped.
    #[error("failed to relocate persistent root-record index during file blob-pack repack")]
    RootRecordIndex {
        /// The underlying root-record index error.
        source: PersistRootRecordIndexError,
    },
    /// The advisory root-record lock could not be acquired for relocation.
    #[error(
        "failed to acquire persistent root-record advisory lock at {path} during file blob-pack repack"
    )]
    RootRecordLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
}

/// Persistent node-metadata value-root planning failed.
#[derive(Debug, Error)]
pub enum PersistNodeValueRootPlanError {
    /// The advisory value-store read lock could not be acquired.
    #[error(
        "failed to acquire persistent node value-root advisory read lock for {store:?} at {path}"
    )]
    AdvisoryReadLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// Node metadata roots could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent node metadata value roots")]
    Metadata {
        /// The underlying node metadata error.
        source: PersistNodeMetadataIndexError,
    },
    /// The value blob index could not be locked or read.
    #[error("failed to lock or read persistent value blob index for node value roots")]
    BlobIndex {
        /// The underlying value blob-index error.
        source: PersistBlobIndexError,
    },
    /// A value blob root could not be verified.
    #[error("failed to verify persistent value blob for node value root")]
    Read {
        /// The underlying packfile read error.
        source: PersistBlobPackError,
    },
}

/// Persistent value-pack reachability planning failed.
#[derive(Debug, Error)]
pub enum PersistValueBlobReachabilityPlanError {
    /// The advisory value-store read lock could not be acquired.
    #[error(
        "failed to acquire persistent value reachability advisory read lock for {store:?} at {path}"
    )]
    AdvisoryReadLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// Node metadata roots could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent node metadata for value reachability")]
    Metadata {
        /// The underlying node metadata error.
        source: PersistNodeMetadataIndexError,
    },
    /// The value blob index could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent value blob index for reachability")]
    BlobIndex {
        /// The underlying value blob-index error.
        source: PersistBlobIndexError,
    },
    /// The value blob index contained a key for the wrong blob namespace.
    #[error("persistent value blob index entry targets {actual:?}, expected Values")]
    WrongStoreEntry {
        /// The blob namespace encoded in the value index entry.
        actual: PersistBlobStore,
    },
    /// A value-index root could not be verified.
    #[error("failed to verify persistent indexed value blob")]
    Read {
        /// The underlying packfile read error.
        source: PersistBlobPackError,
    },
    /// The value blob pack could not be scanned and verified.
    #[error("failed to scan persistent value blob pack for reachability")]
    Pack {
        /// The underlying packfile scan error.
        source: PersistBlobPackError,
    },
}

/// Persistent file-pack reachability planning failed.
#[derive(Debug, Error)]
pub enum PersistFileBlobReachabilityPlanError {
    /// The advisory file-store read lock could not be acquired.
    #[error(
        "failed to acquire persistent file reachability advisory read lock for {store:?} at {path}"
    )]
    AdvisoryReadLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The file blob index could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent file blob index for reachability")]
    BlobIndex {
        /// The underlying file blob-index error.
        source: PersistBlobIndexError,
    },
    /// Pending artifact roots could not be snapshotted.
    #[error("failed to snapshot pending persistent file artifact roots for reachability")]
    Roots {
        /// The underlying live-root collection error.
        source: PersistBlobLiveRootError,
    },
    /// File-artifact roots could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent file-artifact roots for reachability")]
    FileArtifactIndex {
        /// The underlying file-artifact index error.
        source: PersistFileArtifactIndexError,
    },
    /// Parse-artifact roots could not be locked or snapshotted.
    #[error("failed to lock or snapshot persistent parse-artifact roots for reachability")]
    ParseArtifactIndex {
        /// The underlying parse-artifact index error.
        source: PersistParseArtifactIndexError,
    },
    /// The file blob index contained a key for the wrong blob namespace.
    #[error("persistent file blob index entry targets {actual:?}, expected Files")]
    WrongStoreEntry {
        /// The blob namespace encoded in the file index entry.
        actual: PersistBlobStore,
    },
    /// A file-pack root could not be verified.
    #[error("failed to verify persistent indexed or artifact file blob")]
    Read {
        /// The underlying packfile read error.
        source: PersistBlobPackError,
    },
    /// The file blob pack could not be scanned and verified.
    #[error("failed to scan persistent file blob pack for reachability")]
    Pack {
        /// The underlying packfile scan error.
        source: PersistBlobPackError,
    },
}

/// Persistent blob-index rebuild planning failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexRebuildPlanError {
    /// The selected blob pack could not be scanned and verified.
    #[error("failed to scan persistent blob pack before index rebuild planning")]
    Pack {
        /// The underlying packfile scan error.
        source: PersistBlobPackError,
    },
    /// The selected blob index could not be snapshotted.
    #[error("failed to snapshot persistent blob index before rebuild planning")]
    Index {
        /// The underlying blob-index error.
        source: PersistBlobIndexError,
    },
}

/// Persistent blob-index rebuild failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexRebuildError {
    /// The same-root blob-index write lock was poisoned.
    #[error("persistent blob index write lock for {store:?} is poisoned")]
    WriteLockPoisoned {
        /// The blob namespace whose lock could not be acquired.
        store: PersistBlobStore,
    },
    /// The advisory blob-index write lock could not be acquired.
    #[error(
        "failed to acquire persistent blob index rebuild advisory write lock for {store:?} at {path}"
    )]
    AdvisoryWriteLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The rebuild plan could not be produced.
    #[error("failed to plan persistent blob index rebuild")]
    Plan {
        /// The underlying planning error.
        source: PersistBlobIndexRebuildPlanError,
    },
    /// The sidecar could not be replaced with the planned entries.
    #[error("failed to replace persistent blob index during rebuild")]
    Write {
        /// The underlying blob-index write error.
        source: PersistBlobIndexError,
    },
}

/// Rebuilding all persistent blob-index sidecars failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexesRebuildError {
    /// The `values/` blob index could not be rebuilt.
    #[error("failed to rebuild persistent value blob index")]
    ValueBlobIndex {
        /// The underlying single-index rebuild error.
        source: PersistBlobIndexRebuildError,
    },
    /// The `files/` blob index could not be rebuilt.
    #[error("failed to rebuild persistent file blob index")]
    FileBlobIndex {
        /// The underlying single-index rebuild error.
        source: PersistBlobIndexRebuildError,
    },
}

/// Repacking all persistent blob-pack sidecars failed.
#[derive(Debug, Error)]
pub enum PersistBlobPacksRepackError {
    /// The `values/` blob pack could not be repacked.
    #[error("failed to repack persistent value blob pack")]
    ValueBlobPack {
        /// The underlying value-pack repack error.
        source: PersistValueBlobPackRepackError,
    },
    /// The `files/` blob pack could not be repacked.
    #[error("failed to repack persistent file blob pack")]
    FileBlobPack {
        /// The underlying file-pack repack error.
        source: PersistFileBlobPackRepackError,
    },
}

/// Persistent storage maintenance failed.
#[derive(Debug, Error)]
pub enum PersistStorageMaintenanceError {
    /// Sidecar compaction failed.
    #[error("failed to compact persistent sidecars during storage maintenance")]
    Sidecars {
        /// The underlying sidecar compaction error.
        source: PersistCompactionError,
    },
    /// Blob-index rebuild failed.
    #[error("failed to rebuild persistent blob indexes during storage maintenance")]
    BlobIndexes {
        /// The underlying blob-index rebuild error.
        source: PersistBlobIndexesRebuildError,
    },
    /// The `values/` blob pack tail trim failed.
    #[error("failed to trim persistent value blob pack during storage maintenance")]
    ValueBlobPack {
        /// The underlying blob-pack trim error.
        source: PersistBlobPackTrimError,
    },
    /// The `files/` blob pack tail trim failed.
    #[error("failed to trim persistent file blob pack during storage maintenance")]
    FileBlobPack {
        /// The underlying blob-pack trim error.
        source: PersistBlobPackTrimError,
    },
}

/// Persistent storage repacking failed.
#[derive(Debug, Error)]
pub enum PersistStorageRepackError {
    /// Sidecar compaction failed.
    #[error("failed to compact persistent sidecars before storage repack")]
    Sidecars {
        /// The underlying sidecar compaction error.
        source: PersistCompactionError,
    },
    /// Blob-pack repacking failed.
    #[error("failed to repack persistent blob packs during storage repack")]
    BlobPacks {
        /// The underlying blob-pack repack error.
        source: PersistBlobPacksRepackError,
    },
}

/// Automatic persistent storage maintenance planning failed.
#[derive(Debug, Error)]
pub enum PersistStorageMaintenancePlanError {
    /// The value blob index could not be planned for rebuild.
    #[error("failed to plan persistent value blob-index repair during storage maintenance")]
    ValueBlobIndex {
        /// The underlying rebuild-plan error.
        source: PersistBlobIndexRebuildPlanError,
    },
    /// The file blob index could not be planned for rebuild.
    #[error("failed to plan persistent file blob-index repair during storage maintenance")]
    FileBlobIndex {
        /// The underlying rebuild-plan error.
        source: PersistBlobIndexRebuildPlanError,
    },
    /// The value blob pack could not be planned for repack.
    #[error("failed to plan persistent value blob-pack repack during storage maintenance")]
    ValueBlobPack {
        /// The underlying repack-plan error.
        source: PersistBlobPackRepackPlanError,
    },
    /// The file blob pack could not be planned for repack.
    #[error("failed to plan persistent file blob-pack repack during storage maintenance")]
    FileBlobPack {
        /// The underlying repack-plan error.
        source: PersistBlobPackRepackPlanError,
    },
}

/// Automatic persistent storage maintenance failed.
#[derive(Debug, Error)]
pub enum PersistStorageAutoMaintenanceError {
    /// Maintenance planning failed.
    #[error("failed to plan automatic persistent storage maintenance")]
    Plan {
        /// The underlying planning error.
        source: PersistStorageMaintenancePlanError,
    },
    /// Index repair and tail maintenance failed.
    #[error("failed to repair persistent storage during automatic maintenance")]
    Repair {
        /// The underlying maintenance error.
        source: PersistStorageMaintenanceError,
    },
    /// Blob-pack repacking failed.
    #[error("failed to repack persistent storage during automatic maintenance")]
    Repack {
        /// The underlying repack error.
        source: PersistStorageRepackError,
    },
}
