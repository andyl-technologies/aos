//! Persistent sidecar index error types.

use super::*;

/// Fixed-record blob index operation failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexError {
    /// The in-process blob-index write lock was poisoned by a prior panic.
    #[error("persistent blob index write lock for {store:?} is poisoned")]
    WriteLockPoisoned {
        /// The blob namespace whose lock could not be acquired.
        store: PersistBlobStore,
    },
    /// The advisory blob-index write lock could not be acquired.
    #[error("failed to acquire persistent blob index advisory write lock for {store:?} at {path}")]
    AdvisoryWriteLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The index parent directory could not be created.
    #[error("failed to create persistent blob index parent {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open persistent blob index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read persistent blob index metadata {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read persistent blob index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write persistent blob index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("persistent blob index {path:?} has invalid format: {source}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
}

/// Fixed-record file-artifact index file IO failed.
#[derive(Debug, Error)]
pub enum PersistFileArtifactIndexError {
    /// The in-process file-artifact write lock was poisoned by a prior panic.
    #[error("persistent file artifact write lock was poisoned")]
    WriteLockPoisoned,
    /// The advisory file-artifact write lock could not be acquired.
    #[error("failed to acquire persistent file-artifact advisory write lock at {path}")]
    AdvisoryWriteLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The advisory file-artifact read lock could not be acquired.
    #[error("failed to acquire persistent file-artifact advisory read lock at {path}")]
    AdvisoryReadLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The index parent directory could not be created.
    #[error("failed to create persistent file artifact index parent {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open persistent file artifact index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read persistent file artifact index metadata {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read persistent file artifact index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write persistent file artifact index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("persistent file artifact index {path:?} has invalid format: {source}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
}

/// Fixed-record parse-artifact index file IO failed.
#[derive(Debug, Error)]
pub enum PersistParseArtifactIndexError {
    /// The in-process parse-artifact write lock was poisoned by a prior panic.
    #[error("persistent parse artifact write lock was poisoned")]
    WriteLockPoisoned,
    /// The advisory parse-artifact write lock could not be acquired.
    #[error("failed to acquire persistent parse-artifact advisory write lock at {path}")]
    AdvisoryWriteLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The advisory parse-artifact read lock could not be acquired.
    #[error("failed to acquire persistent parse-artifact advisory read lock at {path}")]
    AdvisoryReadLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The index parent directory could not be created.
    #[error("failed to create persistent parse artifact index parent {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open persistent parse artifact index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read persistent parse artifact index metadata {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read persistent parse artifact index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write persistent parse artifact index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("persistent parse artifact index {path:?} has invalid format: {source}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
}

/// Fixed-record demand-node metadata index file IO failed.
#[derive(Debug, Error)]
pub enum PersistNodeMetadataIndexError {
    /// The in-process node metadata write lock was poisoned by a prior panic.
    #[error("persistent node metadata write lock was poisoned")]
    WriteLockPoisoned,
    /// The advisory node-metadata write lock could not be acquired.
    #[error("failed to acquire persistent node metadata advisory write lock at {path}")]
    AdvisoryWriteLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The advisory node-metadata read lock could not be acquired.
    #[error("failed to acquire persistent node metadata advisory read lock at {path}")]
    AdvisoryReadLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The index parent directory could not be created.
    #[error("failed to create persistent node metadata index parent {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open persistent node metadata index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read persistent node metadata index metadata {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read persistent node metadata index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write persistent node metadata index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("persistent node metadata index {path:?} has invalid format: {source}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
}

/// Fixed-record root-instantiation record index operation failed.
#[derive(Debug, Error)]
pub enum PersistRootRecordIndexError {
    /// The index parent directory could not be created.
    #[error("failed to create persistent root record index parent {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open persistent root record index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read persistent root record index metadata {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read persistent root record index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write persistent root record index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("persistent root record index {path:?} has invalid format: {source}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
}
