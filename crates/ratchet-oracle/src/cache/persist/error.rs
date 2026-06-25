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
    /// A file-artifact index value pointed at a non-file blob store.
    #[error("persistent file artifact index value points at {store:?}, expected Files")]
    InvalidFileArtifactBlobStore {
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

/// Fixed-record blob index file IO failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexError {
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

/// Indexed blob append failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexedWriteError {
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

/// Immutable blob packfile IO failed.
#[derive(Debug, Error)]
pub enum PersistBlobPackError {
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

/// Persistent parse-artifact materialization failed.
#[derive(Debug, Error)]
pub enum PersistParseArtifactMaterializationError {
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
}
