//! Indexed materialization, hydration, and cache-open error types.

use super::*;

/// Indexed blob append failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexedWriteError {
    /// The in-process materialization lock was poisoned by a prior panic.
    #[error("persistent blob write lock for {store:?} is poisoned")]
    WriteLockPoisoned {
        /// The blob namespace whose lock could not be acquired.
        store: PersistBlobStore,
    },
    /// The advisory materialization lock could not be acquired.
    #[error(
        "failed to acquire persistent indexed blob write advisory lock for {store:?} at {path}"
    )]
    AdvisoryWriteLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The blob could not be appended to its selected packfile.
    #[error("failed to append indexed persistent blob")]
    Append {
        /// The underlying packfile error.
        source: PersistBlobPackError,
    },
    /// The appended blob location could not be recorded in the sidecar index.
    #[error("failed to record indexed persistent blob location")]
    Index {
        /// The underlying index error.
        source: PersistBlobIndexError,
    },
}

/// Indexed blob read failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexedReadError {
    /// The same-root blob-store read lock was poisoned by a prior panic.
    #[error("persistent indexed blob read lock for {store:?} is poisoned")]
    ReadLockPoisoned {
        /// The selected blob store.
        store: PersistBlobStore,
    },
    /// The advisory store read lock could not be acquired.
    #[error("failed to acquire persistent indexed blob read advisory lock for {store:?} at {path}")]
    AdvisoryReadLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The sidecar index lookup failed.
    #[error("failed to look up indexed persistent blob")]
    Lookup {
        /// The underlying index error.
        source: PersistBlobIndexError,
    },
    /// The indexed packfile location could not be read and verified.
    #[error("failed to read indexed persistent blob")]
    Read {
        /// The underlying packfile error.
        source: PersistBlobPackError,
    },
}

/// Indexed cached-expression payload materialization failed.
#[derive(Debug, Error)]
pub enum PersistCachedExpressionValueIndexedWriteError {
    /// The cached payload could not be hashed as a durable value.
    #[error("failed to hash cached expression payload for persistent materialization")]
    Hash {
        /// The underlying value-hash error.
        source: ValueHashError,
    },
    /// The cached payload could not be encoded as stable value-store bytes.
    #[error("failed to encode cached expression payload for persistent materialization")]
    Encode {
        /// The underlying payload encoding error.
        source: CachedExpressionValuePayloadError,
    },
    /// The encoded cached payload could not be written to the indexed `values/` pack.
    #[error("failed to write indexed cached expression payload")]
    Write {
        /// The underlying indexed blob write error.
        source: PersistBlobIndexedWriteError,
    },
}

/// Indexed cached-expression payload materialization plus node-link recording failed.
#[derive(Debug, Error)]
pub enum PersistCachedExpressionNodeValueIndexedWriteError {
    /// The cached payload could not be hashed as a durable value.
    #[error("failed to hash cached expression node payload for persistent materialization")]
    Hash {
        /// The underlying value-hash error.
        source: ValueHashError,
    },
    /// The cached payload could not be encoded as stable value-store bytes.
    #[error("failed to encode cached expression node payload for persistent materialization")]
    Encode {
        /// The underlying payload encoding error.
        source: CachedExpressionValuePayloadError,
    },
    /// The encoded cached payload could not be written to the indexed `values/` pack.
    #[error("failed to write indexed cached expression node payload")]
    Write {
        /// The underlying indexed blob write error.
        source: PersistBlobIndexedWriteError,
    },
    /// The materialized value hash could not be recorded for the node.
    #[error("failed to record cached expression node payload metadata")]
    Metadata {
        /// The underlying node metadata index error.
        source: PersistNodeMetadataIndexError,
    },
}

/// Indexed cached-expression payload load failed.
#[derive(Debug, Error)]
pub enum PersistCachedExpressionValueIndexedLoadError {
    /// The indexed value blob could not be read.
    #[error("failed to read indexed cached expression payload")]
    Read {
        /// The underlying indexed blob read error.
        source: PersistBlobIndexedReadError,
    },
    /// The materialized payload bytes were not a cached expression value.
    #[error("failed to decode indexed cached expression payload")]
    Decode {
        /// The underlying payload decoding error.
        source: CachedExpressionValuePayloadError,
    },
    /// The decoded payload could not be hashed as a durable value.
    #[error("failed to hash decoded indexed cached expression payload")]
    Hash {
        /// The underlying value-hash error.
        source: ValueHashError,
    },
    /// The decoded payload did not hash back to the requested value hash.
    #[error(
        "indexed cached expression payload hash mismatch: expected {expected:?}, got {actual:?}"
    )]
    ValueHashMismatch {
        /// The value hash requested by the caller and blob index.
        expected: ValueHash,
        /// The value hash recomputed from the decoded payload.
        actual: ValueHash,
    },
}

/// Indexed cached-expression payload load through node metadata failed.
#[derive(Debug, Error)]
pub enum PersistCachedExpressionNodeValueIndexedLoadError {
    /// The node metadata could not be read.
    #[error("failed to read cached expression node payload metadata")]
    Metadata {
        /// The underlying node metadata index error.
        source: PersistNodeMetadataIndexError,
    },
    /// The linked cached-expression payload could not be loaded.
    #[error("failed to load cached expression node payload")]
    Value {
        /// The underlying indexed payload load error.
        source: PersistCachedExpressionValueIndexedLoadError,
    },
}

/// Trace-verified indexed cached-expression payload load failed.
#[derive(Debug, Error)]
pub enum PersistCachedExpressionNodeValueTraceLoadError {
    /// The node metadata could not be read.
    #[error("failed to read trace-verified cached expression node payload metadata")]
    Metadata {
        /// The underlying node metadata index error.
        source: PersistNodeMetadataIndexError,
    },
    /// The node trace log could not be read.
    #[error("failed to read cached expression node trace")]
    Trace {
        /// The underlying node trace log error.
        source: PersistNodeTraceLogError,
    },
    /// The linked cached-expression payload could not be loaded.
    #[error("failed to load trace-verified cached expression node payload")]
    Value {
        /// The underlying indexed payload load error.
        source: PersistCachedExpressionValueIndexedLoadError,
    },
}

/// Indexed file-artifact materialization failed.
#[derive(Debug, Error)]
pub enum PersistFileArtifactIndexedWriteError {
    /// The artifact payload could not be appended to the `files/` blob pack or
    /// recorded in the blob sidecar index.
    #[error("failed to append indexed persistent file artifact blob")]
    Blob {
        /// The underlying indexed blob write error.
        source: PersistBlobIndexedWriteError,
    },
    /// The file-artifact mapping could not be recorded in the sidecar index.
    #[error("failed to record persistent file artifact mapping")]
    Index {
        /// The underlying file-artifact index error.
        source: PersistFileArtifactIndexError,
    },
}

/// Indexed parse-artifact materialization failed.
#[derive(Debug, Error)]
pub enum PersistParseArtifactIndexedWriteError {
    /// The artifact payload could not be appended to the `files/` blob pack or
    /// recorded in the blob sidecar index.
    #[error("failed to append indexed persistent parse artifact blob")]
    Blob {
        /// The underlying indexed blob write error.
        source: PersistBlobIndexedWriteError,
    },
    /// The parse-artifact mapping could not be recorded in the sidecar index.
    #[error("failed to record persistent parse artifact mapping")]
    Index {
        /// The underlying parse-artifact index error.
        source: PersistParseArtifactIndexError,
    },
}

/// Persistent file-artifact hydration failed.
#[derive(Debug, Error)]
pub enum PersistFileArtifactHydrationError {
    /// The supplied artifact key does not match the requested source identity.
    #[error("persistent file artifact key mismatch: expected {expected:?}, got {actual:?}")]
    KeyMismatch {
        /// The key derived from the requested file and parse identities.
        expected: PersistFileArtifactKey,
        /// The key supplied by the caller's artifact lookup.
        actual: PersistFileArtifactKey,
    },
    /// The materialized artifact payload could not be read from the `files/` pack.
    #[error("failed to read persistent file artifact")]
    Read {
        /// The underlying packfile read error.
        source: PersistBlobPackError,
    },
    /// The materialized artifact payload was not a valid parse-artifact bundle.
    #[error("failed to decode persistent file artifact bundle")]
    Decode {
        /// The underlying bundle decode error.
        source: ParseCacheError,
    },
    /// The decoded artifact bundle failed parse-cache schema/count validation.
    #[error("failed to validate persistent file artifact bundle")]
    Validate {
        /// The underlying parse-cache validation error.
        source: ParseCacheError,
    },
    /// The decoded artifact bundle could not be written to the target entry.
    #[error("failed to hydrate parse-cache entry from persistent file artifact")]
    Write {
        /// The underlying parse-cache write error.
        source: ParseCacheError,
    },
}

/// Persistent parse-artifact hydration failed.
#[derive(Debug, Error)]
pub enum PersistParseArtifactHydrationError {
    /// The supplied artifact key does not match the requested parse identity.
    #[error("persistent parse artifact key mismatch: expected {expected:?}, got {actual:?}")]
    KeyMismatch {
        /// The key derived from the requested parse identity.
        expected: PersistParseArtifactKey,
        /// The key supplied by the caller's artifact lookup.
        actual: PersistParseArtifactKey,
    },
    /// The materialized artifact payload could not be read from the `files/` pack.
    #[error("failed to read persistent parse artifact")]
    Read {
        /// The underlying packfile read error.
        source: PersistBlobPackError,
    },
    /// The materialized artifact payload was not a valid parse-artifact bundle.
    #[error("failed to decode persistent parse artifact bundle")]
    Decode {
        /// The underlying bundle decode error.
        source: ParseCacheError,
    },
    /// The decoded artifact bundle failed parse-cache schema/count validation.
    #[error("failed to validate persistent parse artifact bundle")]
    Validate {
        /// The underlying parse-cache validation error.
        source: ParseCacheError,
    },
    /// The decoded artifact bundle could not be written to the target entry.
    #[error("failed to hydrate parse-cache entry from persistent parse artifact")]
    Write {
        /// The underlying parse-cache write error.
        source: ParseCacheError,
    },
}

/// Indexed persistent file-artifact hydration failed.
#[derive(Debug, Error)]
pub enum PersistFileArtifactIndexedHydrationError {
    /// The advisory files-store read lock could not be acquired.
    #[error("failed to acquire persistent file artifact hydration files advisory lock at {path}")]
    AdvisoryFileStoreReadLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The advisory file-artifact mapping read lock could not be acquired.
    #[error("failed to acquire persistent file artifact hydration mapping advisory lock at {path}")]
    AdvisoryFileArtifactReadLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The file-artifact sidecar index could not be looked up.
    #[error("failed to look up persistent file artifact for hydration")]
    Lookup {
        /// The underlying file-artifact index error.
        source: PersistFileArtifactIndexError,
    },
    /// The indexed file artifact could not be hydrated into the target entry.
    #[error("failed to hydrate indexed persistent file artifact")]
    Hydrate {
        /// The underlying hydration error.
        source: PersistFileArtifactHydrationError,
    },
}

/// Indexed persistent parse-artifact hydration failed.
#[derive(Debug, Error)]
pub enum PersistParseArtifactIndexedHydrationError {
    /// The advisory files-store read lock could not be acquired.
    #[error("failed to acquire persistent parse artifact hydration files advisory lock at {path}")]
    AdvisoryFileStoreReadLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The advisory parse-artifact mapping read lock could not be acquired.
    #[error(
        "failed to acquire persistent parse artifact hydration mapping advisory lock at {path}"
    )]
    AdvisoryParseArtifactReadLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The parse-artifact sidecar index could not be looked up.
    #[error("failed to look up persistent parse artifact for hydration")]
    Lookup {
        /// The underlying parse-artifact index error.
        source: PersistParseArtifactIndexError,
    },
    /// The indexed parse artifact could not be hydrated into the target entry.
    #[error("failed to hydrate indexed persistent parse artifact")]
    Hydrate {
        /// The underlying hydration error.
        source: PersistParseArtifactHydrationError,
    },
}

/// Indexed parse-cache load from source bytes failed.
#[derive(Debug, Error)]
pub enum PersistParseBytesIndexedLoadError {
    /// The indexed parse artifact could not hydrate the parse-cache entry.
    #[error("failed to hydrate indexed parse-cache entry for byte-source load")]
    Hydrate {
        /// The underlying indexed hydration error.
        source: PersistParseArtifactIndexedHydrationError,
    },
    /// The hydrated parse-cache entry could not be loaded as a cache hit.
    #[error("failed to load hydrated byte-source parse-cache entry")]
    Load {
        /// The underlying parse-cache read error.
        source: ParseCacheError,
    },
}

/// Indexed parse-cache hydration from a filesystem source failed.
#[derive(Debug, Error)]
pub enum PersistParseFileIndexedHydrationError {
    /// The requested source path could not be canonicalized.
    #[error("failed to canonicalize source path {path:?} for indexed parse-cache hydration")]
    CanonicalizeSource {
        /// The requested source path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The canonicalized source file could not be read.
    #[error("failed to read source file {path:?} for indexed parse-cache hydration")]
    ReadSource {
        /// The canonical source path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The indexed file artifact could not be hydrated from the canonical source identity.
    #[error("failed to hydrate indexed parse-cache entry from source file")]
    Hydrate {
        /// The underlying indexed hydration error.
        source: PersistFileArtifactIndexedHydrationError,
    },
}

/// Indexed parse-cache load from a caller-supplied source buffer failed.
#[derive(Debug, Error)]
pub enum PersistParseSourceIndexedLoadError {
    /// The indexed file artifact could not hydrate the parse-cache entry.
    #[error("failed to hydrate indexed parse-cache entry for source load")]
    Hydrate {
        /// The underlying indexed hydration error.
        source: PersistFileArtifactIndexedHydrationError,
    },
    /// The hydrated parse-cache entry could not be loaded as a cache hit.
    #[error("failed to load hydrated source parse-cache entry")]
    Load {
        /// The underlying parse-cache read error.
        source: ParseCacheError,
    },
}

/// Indexed parse-cache load from a filesystem source failed.
#[derive(Debug, Error)]
pub enum PersistParseFileIndexedLoadError {
    /// The requested source path could not be canonicalized.
    #[error("failed to canonicalize source path {path:?} for indexed parse-cache load")]
    CanonicalizeSource {
        /// The requested source path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The canonicalized source file could not be read.
    #[error("failed to read source file {path:?} for indexed parse-cache load")]
    ReadSource {
        /// The canonical source path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The indexed file artifact could not hydrate the parse-cache entry.
    #[error("failed to hydrate indexed parse-cache entry for load")]
    Hydrate {
        /// The underlying indexed hydration error.
        source: PersistFileArtifactIndexedHydrationError,
    },
    /// The hydrated parse-cache entry could not be loaded as a cache hit.
    #[error("failed to load hydrated parse-cache entry")]
    Load {
        /// The underlying parse-cache read error.
        source: ParseCacheError,
    },
}

/// Persistent parse-artifact materialization failed.
#[derive(Debug, Error)]
pub enum PersistParseArtifactMaterializationError {
    /// The parse-cache entry directory did not match the supplied parse key.
    #[error("parse-cache entry {path:?} does not match parse key {expected}")]
    EntryKeyMismatch {
        /// The supplied parse-cache key.
        expected: ParseCacheKey,
        /// The mismatched parse-cache entry directory.
        path: PathBuf,
    },
    /// The source parse-cache entry could not be read as an artifact bundle.
    #[error("failed to read parse-cache artifact bundle for persistent materialization")]
    ReadBundle {
        /// The underlying parse-cache read error.
        source: ParseCacheError,
    },
    /// The parse-cache artifact bundle could not be encoded as one payload.
    #[error("failed to encode parse-cache artifact bundle for persistent materialization")]
    EncodeBundle {
        /// The underlying bundle encode error.
        source: ParseCacheError,
    },
    /// The encoded artifact payload could not be written to the `files/` pack.
    #[error("failed to write parse-cache artifact bundle to persistent files pack")]
    Write {
        /// The underlying packfile write error.
        source: PersistBlobPackError,
    },
    /// The encoded artifact payload could not be written with durable indexes.
    #[error("failed to write indexed parse-cache artifact bundle to persistent files pack")]
    WriteIndexed {
        /// The underlying indexed write error.
        source: PersistFileArtifactIndexedWriteError,
    },
    /// The encoded artifact payload could not be written with parse-artifact indexes.
    #[error("failed to write parse-indexed parse-cache artifact bundle to persistent files pack")]
    WriteParseIndexed {
        /// The underlying indexed write error.
        source: PersistParseArtifactIndexedWriteError,
    },
}

/// Persistent-cache layout initialization failed.
#[derive(Debug, Error)]
pub enum PersistError {
    /// The cache root or payload directory could not be created.
    #[error("failed to create persistent cache directory {path}")]
    CreateDir {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The cache root could not be canonicalized.
    #[error("failed to canonicalize persistent cache root {path}")]
    CanonicalizeRoot {
        /// The cache root path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The process-local root-lock registry was poisoned by a prior panic.
    #[error("persistent cache root-lock registry is poisoned")]
    RootLockRegistryPoisoned,
    /// The cross-process open initialization advisory lock could not be acquired.
    #[error("failed to acquire persistent cache open advisory lock {path}")]
    OpenAdvisoryLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The same-root open initialization lock was poisoned by a prior panic.
    #[error("persistent cache root open lock is poisoned")]
    RootOpenLockPoisoned,
    /// Existing cache payload could not be discarded after a schema mismatch.
    #[error("failed to discard persistent cache payload {path}")]
    DiscardPayload {
        /// The path that could not be removed.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Schema metadata could not be read.
    #[error("failed to read persistent cache schema {path}")]
    ReadSchema {
        /// The schema file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Schema metadata could not be parsed as TOML.
    #[error("failed to parse persistent cache schema {path}")]
    ParseSchema {
        /// The schema file path.
        path: PathBuf,
        /// The TOML parse error.
        source: toml::de::Error,
    },
    /// Schema metadata did not contain an integer `schema_version`.
    #[error("persistent cache schema {path} is missing integer schema_version")]
    MissingSchemaVersion {
        /// The schema file path.
        path: PathBuf,
    },
    /// Schema metadata did not contain a string `format`.
    #[error("persistent cache schema {path} is missing string format")]
    MissingFormat {
        /// The schema file path.
        path: PathBuf,
    },
    /// Schema metadata was for another cache format.
    #[error("persistent cache schema {path} has unsupported format {format:?}")]
    InvalidFormat {
        /// The schema file path.
        path: PathBuf,
        /// The unsupported schema format.
        format: String,
    },
    /// Schema metadata contained a version outside the supported `u32` range.
    #[error("persistent cache schema {path} has unsupported schema_version {version}")]
    InvalidSchemaVersion {
        /// The schema file path.
        path: PathBuf,
        /// The unsupported schema version.
        version: i64,
    },
    /// Schema metadata could not be written.
    #[error("failed to write persistent cache schema {path}")]
    WriteSchema {
        /// The schema file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A value/file blob packfile could not be initialized.
    #[error("failed to initialize persistent blob pack {path}")]
    OpenBlobPack {
        /// The blob packfile path.
        path: PathBuf,
        /// The underlying packfile error.
        source: PersistBlobPackError,
    },
    /// A value/file blob index file could not be initialized.
    #[error("failed to initialize persistent blob index {path}")]
    OpenBlobIndex {
        /// The blob index file path.
        path: PathBuf,
        /// The underlying index error.
        source: PersistBlobIndexError,
    },
    /// The file-artifact mapping index file could not be initialized.
    #[error("failed to initialize persistent file artifact index {path}")]
    OpenFileArtifactIndex {
        /// The file-artifact index file path.
        path: PathBuf,
        /// The underlying index error.
        source: PersistFileArtifactIndexError,
    },
    /// The parse-artifact mapping index file could not be initialized.
    #[error("failed to initialize persistent parse artifact index {path}")]
    OpenParseArtifactIndex {
        /// The parse-artifact index file path.
        path: PathBuf,
        /// The underlying index error.
        source: PersistParseArtifactIndexError,
    },
    /// The demand-node metadata index file could not be initialized.
    #[error("failed to initialize persistent node metadata index {path}")]
    OpenNodeMetadataIndex {
        /// The node metadata index file path.
        path: PathBuf,
        /// The underlying index error.
        source: PersistNodeMetadataIndexError,
    },
    /// The demand-node trace log file could not be initialized.
    #[error("failed to initialize persistent node trace log {path}")]
    OpenNodeTraceLog {
        /// The node trace log file path.
        path: PathBuf,
        /// The underlying log error.
        source: PersistNodeTraceLogError,
    },
}

/// Durable root-instantiation record store or load failed.
///
/// Any variant reported to the root-cutoff caller is treated as a cache miss:
/// the caller silently falls through to a normal evaluation rather than
/// surfacing the error, so these variants exist for diagnostics and tests.
#[derive(Debug, Error)]
pub enum PersistRootRecordError {
    /// The advisory root-record lock could not be acquired.
    #[error("failed to acquire persistent root-record advisory lock at {path}")]
    AdvisoryLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// A root-record payload could not be encoded from its impure-input trace.
    #[error("failed to encode persistent root record impure-input trace")]
    TraceEncode {
        /// The underlying node-trace payload error.
        source: PersistNodeTracePayloadError,
    },
    /// A record or closure blob could not be appended or indexed.
    #[error("failed to store persistent root record blob")]
    Blob {
        /// The underlying indexed blob write error.
        source: PersistBlobIndexedWriteError,
    },
    /// A record or closure blob location could not be looked up.
    #[error("failed to look up persistent root record blob")]
    BlobIndex {
        /// The underlying blob index error.
        source: PersistBlobIndexError,
    },
    /// A record or closure blob could not be read from the pack.
    #[error("failed to read persistent root record blob")]
    BlobPack {
        /// The underlying blob pack error.
        source: PersistBlobPackError,
    },
    /// The root-record sidecar index could not be opened, read, or written.
    #[error("failed to access persistent root record index")]
    Index {
        /// The underlying root-record index error.
        source: PersistRootRecordIndexError,
    },
    /// A root-record payload could not be decoded.
    #[error("persistent root record payload is malformed: {source}")]
    Format {
        /// The underlying payload format error.
        source: PersistPackFormatError,
    },
    /// The root-record payload directory could not be created.
    #[error("failed to create persistent root record directory {path:?}")]
    CreateDir {
        /// The directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
}
