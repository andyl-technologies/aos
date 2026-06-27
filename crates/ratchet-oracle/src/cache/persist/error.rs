//! Error types for the persistent eval-cache stores.
//!
//! Models the failure modes of packfile decoding, index reads and writes,
//! blob-pack I/O, file-artifact hydration, and schema management.

use super::*;

/// Immutable blob packfile metadata could not be decoded.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PersistPackFormatError {
    /// A blob index key was shorter than the fixed encoded key length.
    #[error("persistent blob index key has {actual} bytes, expected at least {expected}")]
    ShortBlobIndexKey {
        /// The required fixed index key length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A blob index key carried an unknown store tag.
    #[error("persistent blob index key has invalid store tag {tag}")]
    InvalidBlobIndexStoreTag {
        /// The unknown store tag.
        tag: u8,
    },
    /// A file-artifact index key was shorter than the fixed encoded key length.
    #[error("persistent file artifact index key has {actual} bytes, expected at least {expected}")]
    ShortFileArtifactIndexKey {
        /// The required fixed file-artifact index key length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A file-artifact index key carried an unexpected index tag.
    #[error("persistent file artifact index key has invalid tag {tag}")]
    InvalidFileArtifactIndexTag {
        /// The unexpected index tag.
        tag: u8,
    },
    /// A parse-artifact index key was shorter than the fixed encoded key length.
    #[error("persistent parse artifact index key has {actual} bytes, expected at least {expected}")]
    ShortParseArtifactIndexKey {
        /// The required fixed parse-artifact index key length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A parse-artifact index key carried an unexpected index tag.
    #[error("persistent parse artifact index key has invalid tag {tag}")]
    InvalidParseArtifactIndexTag {
        /// The unexpected index tag.
        tag: u8,
    },
    /// A demand-node metadata index key was shorter than the fixed encoded key length.
    #[error("persistent node metadata index key has {actual} bytes, expected at least {expected}")]
    ShortNodeMetadataIndexKey {
        /// The required fixed node metadata index key length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A demand-node metadata index key carried an unexpected index tag.
    #[error("persistent node metadata index key has invalid tag {tag}")]
    InvalidNodeMetadataIndexTag {
        /// The unexpected index tag.
        tag: u8,
    },
    /// The packfile header was shorter than the fixed header length.
    #[error("persistent blob pack header has {actual} bytes, expected at least {expected}")]
    ShortPackHeader {
        /// The required fixed header length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// The packfile header did not start with the expected magic bytes.
    #[error("persistent blob pack header has invalid magic bytes {actual:?}")]
    InvalidPackMagic {
        /// The observed magic bytes.
        actual: [u8; 16],
    },
    /// The packfile header declares an unsupported format version.
    #[error("persistent blob pack header declares unsupported version {version}")]
    UnsupportedPackVersion {
        /// The unsupported format version.
        version: u32,
    },
    /// The packfile header declares an unexpected encoded header length.
    #[error("persistent blob pack header declares invalid header length {header_len}")]
    InvalidPackHeaderLength {
        /// The unexpected header length.
        header_len: u32,
    },
    /// A record header was shorter than the fixed record header length.
    #[error("persistent blob record header has {actual} bytes, expected at least {expected}")]
    ShortRecordHeader {
        /// The required fixed record header length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// An index value was shorter than the fixed encoded location length.
    #[error("persistent blob index value has {actual} bytes, expected at least {expected}")]
    ShortIndexValue {
        /// The required fixed index value length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A blob index entry was shorter than the fixed encoded length.
    #[error("persistent blob index entry has {actual} bytes, expected at least {expected}")]
    ShortBlobIndexEntry {
        /// The required fixed blob index entry length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A file-artifact index value was shorter than the fixed encoded length.
    #[error(
        "persistent file artifact index value has {actual} bytes, expected at least {expected}"
    )]
    ShortFileArtifactIndexValue {
        /// The required fixed file-artifact index value length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A file-artifact index entry was shorter than the fixed encoded length.
    #[error(
        "persistent file artifact index entry has {actual} bytes, expected at least {expected}"
    )]
    ShortFileArtifactIndexEntry {
        /// The required fixed file-artifact index entry length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A parse-artifact index value was shorter than the fixed encoded length.
    #[error(
        "persistent parse artifact index value has {actual} bytes, expected at least {expected}"
    )]
    ShortParseArtifactIndexValue {
        /// The required fixed parse-artifact index value length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A parse-artifact index entry was shorter than the fixed encoded length.
    #[error(
        "persistent parse artifact index entry has {actual} bytes, expected at least {expected}"
    )]
    ShortParseArtifactIndexEntry {
        /// The required fixed parse-artifact index entry length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A demand-node metadata index value was shorter than the fixed encoded length.
    #[error(
        "persistent node metadata index value has {actual} bytes, expected at least {expected}"
    )]
    ShortNodeMetadataIndexValue {
        /// The required fixed node metadata index value length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A demand-node metadata index entry was shorter than the fixed encoded length.
    #[error(
        "persistent node metadata index entry has {actual} bytes, expected at least {expected}"
    )]
    ShortNodeMetadataIndexEntry {
        /// The required fixed node metadata index entry length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A demand-node metadata value carried an unknown optional value-hash tag.
    #[error("persistent node metadata value hash has invalid tag {tag}")]
    InvalidNodeMetadataValueHashTag {
        /// The unknown value-hash presence tag.
        tag: u8,
    },
    /// A demand-node metadata value carried bytes in an absent value-hash slot.
    #[error("persistent node metadata value hash absent slot is not zeroed")]
    NonZeroNodeMetadataValueHashPadding,
    /// A file-artifact index value pointed at a non-file blob store.
    #[error("persistent file artifact index value points at {store:?}, expected Files")]
    InvalidFileArtifactBlobStore {
        /// The decoded blob store.
        store: PersistBlobStore,
    },
    /// A parse-artifact index value pointed at a non-file blob store.
    #[error("persistent parse artifact index value points at {store:?}, expected Files")]
    InvalidParseArtifactBlobStore {
        /// The decoded blob store.
        store: PersistBlobStore,
    },
    /// Materialization reuse metadata was shorter than the fixed encoded length.
    #[error(
        "persistent materialization reuse metadata has {actual} bytes, expected at least {expected}"
    )]
    ShortMaterializationReuseMetadata {
        /// The required fixed reuse metadata length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
}

/// Node verifying-trace payload bytes could not be encoded or decoded.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PersistNodeTracePayloadError {
    /// A trace payload had an unexpected magic prefix.
    #[error("persistent node trace payload has invalid magic bytes {actual:?}")]
    InvalidMagic {
        /// The observed magic bytes.
        actual: [u8; 16],
    },
    /// A trace payload declared an unsupported format version.
    #[error("persistent node trace payload declares unsupported version {version}")]
    UnsupportedVersion {
        /// The unsupported format version.
        version: u32,
    },
    /// A trace payload was shorter than a required fixed-width region.
    #[error("persistent node trace payload has {actual} bytes, expected at least {expected}")]
    ShortPayload {
        /// The required byte length.
        expected: usize,
        /// The available byte length.
        actual: usize,
    },
    /// A trace payload declared too many input records for this platform.
    #[error("persistent node trace payload input count {count} does not fit in usize")]
    InputCountOverflow {
        /// The decoded input count.
        count: u64,
    },
    /// A trace payload input count is too large to encode.
    #[error("persistent node trace payload cannot encode {inputs} inputs")]
    EncodedInputCountOverflow {
        /// The requested input count.
        inputs: usize,
    },
    /// A trace payload declared an input subject that is too large for this platform.
    #[error("persistent node trace payload subject length {len} does not fit in usize")]
    SubjectLengthOverflow {
        /// The decoded subject length.
        len: u64,
    },
    /// A trace payload input subject is too large to encode.
    #[error("persistent node trace payload cannot encode subject length {len}")]
    EncodedSubjectLengthOverflow {
        /// The requested subject byte length.
        len: usize,
    },
    /// A trace payload contained an unknown input kind tag.
    #[error("persistent node trace payload has invalid input kind tag {tag}")]
    InvalidInputKindTag {
        /// The unknown input kind tag.
        tag: u8,
    },
    /// A trace payload contained an unknown input mode tag.
    #[error("persistent node trace payload has invalid input mode tag {tag}")]
    InvalidInputModeTag {
        /// The unknown input mode tag.
        tag: u8,
    },
    /// A trace payload contained bytes after the declared input records.
    #[error("persistent node trace payload has {remaining} trailing bytes")]
    TrailingBytes {
        /// The number of trailing bytes.
        remaining: usize,
    },
    /// A trace payload could not reserve storage for input records.
    #[error("failed to reserve persistent node trace payload for {inputs} inputs")]
    InputAllocationFailed {
        /// The requested input count.
        inputs: usize,
    },
    /// A trace payload could not reserve encoded output storage.
    #[error("failed to reserve persistent node trace payload with {len} bytes")]
    PayloadAllocationFailed {
        /// The requested encoded byte length.
        len: usize,
    },
    /// A trace included an input that must never be cached.
    #[error("persistent node trace payload cannot encode uncacheable input {input:?}")]
    UncacheableInput {
        /// The uncacheable input.
        input: UncacheableInput,
    },
    /// A decoded trace input could not be reconstructed.
    #[error("failed to reconstruct persistent node trace input")]
    Input {
        /// The underlying input fingerprint error.
        source: InputFingerprintError,
    },
}

/// Node trace log bytes had an invalid on-disk shape.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PersistNodeTraceLogFormatError {
    /// A trace log record was shorter than the fixed header length.
    #[error("persistent node trace log record has {actual} bytes, expected at least {expected}")]
    ShortRecordHeader {
        /// The required fixed record header length.
        expected: u64,
        /// The available bytes.
        actual: u64,
    },
    /// A trace log record payload length cannot fit in the local address space.
    #[error("persistent node trace log payload length {len} does not fit in usize")]
    PayloadLengthOverflow {
        /// The decoded payload length.
        len: u64,
    },
    /// A trace log record range cannot be represented.
    #[error(
        "persistent node trace log record at offset {record_offset} with payload length {payload_len} overflows"
    )]
    RecordBoundsOverflow {
        /// The record offset.
        record_offset: u64,
        /// The decoded payload length.
        payload_len: u64,
    },
    /// A trace log record payload was shorter than its declared length.
    #[error("persistent node trace log payload ends at {expected}, past log length {actual}")]
    ShortRecordPayload {
        /// The byte offset one past the declared payload.
        expected: u64,
        /// The current log length.
        actual: u64,
    },
    /// A trace log record key could not be decoded.
    #[error("failed to decode persistent node trace log key")]
    Key {
        /// The underlying key format error.
        source: PersistPackFormatError,
    },
    /// A trace log record payload could not be decoded.
    #[error("failed to decode persistent node trace log payload")]
    Payload {
        /// The underlying payload format error.
        source: PersistNodeTracePayloadError,
    },
}

/// Variable-length node trace log IO failed.
#[derive(Debug, Error)]
pub enum PersistNodeTraceLogError {
    /// The in-process node trace write lock was poisoned by a prior panic.
    #[error("persistent node trace write lock was poisoned")]
    WriteLockPoisoned,
    /// The log parent directory could not be created.
    #[error("failed to create persistent node trace log parent {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The log file could not be opened.
    #[error("failed to open persistent node trace log {path:?}")]
    Open {
        /// The log file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Log file metadata could not be read.
    #[error("failed to read persistent node trace log metadata {path:?}")]
    Metadata {
        /// The log file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The log file could not be read.
    #[error("failed to read persistent node trace log {path:?}")]
    Read {
        /// The log file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The log file could not be written.
    #[error("failed to write persistent node trace log {path:?}")]
    Write {
        /// The log file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A node trace payload could not be encoded for appending.
    #[error("failed to encode persistent node trace log payload")]
    Encode {
        /// The underlying payload encoding error.
        source: PersistNodeTracePayloadError,
    },
    /// A node trace payload length is too large for the log record format.
    #[error("persistent node trace log payload length {len} is too large")]
    PayloadTooLarge {
        /// The oversized payload length.
        len: usize,
    },
    /// A node trace log record could not reserve contiguous output storage.
    #[error("failed to reserve persistent node trace log record with {len} bytes")]
    RecordAllocationFailed {
        /// The requested encoded record byte length.
        len: usize,
    },
    /// A node trace payload could not reserve storage while reading.
    #[error("failed to reserve persistent node trace log payload with {len} bytes")]
    PayloadAllocationFailed {
        /// The requested payload byte length.
        len: usize,
    },
    /// The log file has malformed variable-length record bytes.
    #[error("persistent node trace log {path:?} has invalid format: {source}")]
    Format {
        /// The log file path.
        path: PathBuf,
        /// The format error.
        source: PersistNodeTraceLogFormatError,
    },
}

/// Fixed-record blob index operation failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexError {
    /// The in-process blob-index write lock was poisoned by a prior panic.
    #[error("persistent blob index write lock for {store:?} is poisoned")]
    WriteLockPoisoned {
        /// The blob namespace whose lock could not be acquired.
        store: PersistBlobStore,
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
}

/// Persistent node-metadata value-root planning failed.
#[derive(Debug, Error)]
pub enum PersistNodeValueRootPlanError {
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

/// Indexed blob append failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexedWriteError {
    /// The in-process materialization lock was poisoned by a prior panic.
    #[error("persistent blob write lock for {store:?} is poisoned")]
    WriteLockPoisoned {
        /// The blob namespace whose lock could not be acquired.
        store: PersistBlobStore,
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

/// Immutable blob packfile operation failed.
#[derive(Debug, Error)]
pub enum PersistBlobPackError {
    /// The same-root blob-pack write lock was poisoned by a prior panic.
    #[error("persistent blob pack write lock for {store:?} is poisoned")]
    WriteLockPoisoned {
        /// The selected blob store.
        store: PersistBlobStore,
    },
    /// The packfile's parent directory could not be created.
    #[error("failed to create persistent blob pack parent directory {path}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile could not be opened.
    #[error("failed to open persistent blob pack {path}")]
    Open {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile metadata could not be read.
    #[error("failed to inspect persistent blob pack {path}")]
    Metadata {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile could not be seeked.
    #[error("failed to seek persistent blob pack {path}")]
    Seek {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile could not be read.
    #[error("failed to read persistent blob pack {path}")]
    Read {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile could not be written.
    #[error("failed to write persistent blob pack {path}")]
    Write {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile metadata has an unsupported or malformed format.
    #[error("persistent blob pack {path} has invalid metadata")]
    Format {
        /// The packfile path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
    /// A caller supplied a record offset inside the fixed packfile header.
    #[error("persistent blob pack record offset {record_offset} points inside the pack header")]
    InvalidRecordOffset {
        /// The invalid record offset.
        record_offset: u64,
    },
    /// A blob payload cannot fit in the local address space or on-disk length field.
    #[error("persistent blob payload length {payload_len} is too large")]
    PayloadTooLarge {
        /// The oversized payload length.
        payload_len: u128,
    },
    /// Record metadata did not match the hash looked up through the index.
    #[error("persistent blob record hash mismatch: expected {expected}, got {actual}")]
    RecordHashMismatch {
        /// The expected durable hash from the lookup key.
        expected: DurableBlake3Hash,
        /// The durable hash declared by the record.
        actual: DurableBlake3Hash,
    },
    /// Record metadata did not match the length looked up through the index.
    #[error("persistent blob record length mismatch: expected {expected}, got {actual}")]
    RecordLengthMismatch {
        /// The expected payload length from the lookup location.
        expected: u64,
        /// The payload length declared by the record.
        actual: u64,
    },
    /// A copied record did not land at the planned pack location.
    #[error("persistent blob record location mismatch: expected {expected:?}, got {actual:?}")]
    RecordLocationMismatch {
        /// The planned location for the copied record.
        expected: PersistBlobLocation,
        /// The actual location returned by the destination pack append.
        actual: PersistBlobLocation,
    },
    /// Record metadata cannot be represented as an in-pack byte range.
    #[error(
        "persistent blob record at offset {record_offset} with payload length {payload_len} overflows"
    )]
    RecordBoundsOverflow {
        /// The record offset.
        record_offset: u64,
        /// The record payload length.
        payload_len: u64,
    },
    /// Record metadata points beyond the end of the packfile.
    #[error("persistent blob record ends at {payload_end}, past pack length {pack_len}")]
    RecordExtendsPastEnd {
        /// The byte offset one past the declared record payload.
        payload_end: u64,
        /// The current packfile length.
        pack_len: u64,
    },
    /// Blob payload bytes did not match the expected content hash.
    #[error("persistent blob payload hash mismatch: expected {expected}, got {actual}")]
    PayloadHashMismatch {
        /// The expected durable hash.
        expected: DurableBlake3Hash,
        /// The hash computed from the payload bytes.
        actual: DurableBlake3Hash,
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
