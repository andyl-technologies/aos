//! Wire-format and blob-pack error types.

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
    /// A root-record index key was shorter than the fixed encoded key length.
    #[error("persistent root record index key has {actual} bytes, expected at least {expected}")]
    ShortRootRecordIndexKey {
        /// The required fixed root-record index key length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A root-record index key carried an unexpected index tag.
    #[error("persistent root record index key has invalid tag {tag}")]
    InvalidRootRecordIndexTag {
        /// The unexpected index tag.
        tag: u8,
    },
    /// A root-record index value was shorter than the fixed encoded value length.
    #[error("persistent root record index value has {actual} bytes, expected at least {expected}")]
    ShortRootRecordIndexValue {
        /// The required fixed root-record index value length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A root-record index entry was shorter than the fixed encoded entry length.
    #[error("persistent root record index entry has {actual} bytes, expected at least {expected}")]
    ShortRootRecordIndexEntry {
        /// The required fixed root-record index entry length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A root-record index value pointed at a blob store other than `files/`.
    #[error("persistent root record index value points at unexpected blob store {store:?}")]
    InvalidRootRecordBlobStore {
        /// The unexpected blob store.
        store: PersistBlobStore,
    },
    /// A root-record payload was shorter than a required field boundary.
    #[error("persistent root record payload has {actual} bytes, expected at least {expected}")]
    ShortRootRecordPayload {
        /// The required minimum byte length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A root-record payload carried unexpected magic bytes.
    #[error("persistent root record payload has invalid magic")]
    InvalidRootRecordMagic {
        /// The observed magic bytes.
        actual: [u8; 16],
    },
    /// A root-record payload carried an unsupported format version.
    #[error("persistent root record payload has unsupported version {version}")]
    UnsupportedRootRecordVersion {
        /// The unsupported version marker.
        version: u32,
    },
    /// A root-record payload carried a length field that overflowed the platform.
    #[error("persistent root record payload length field {len} overflows this platform")]
    RootRecordLengthOverflow {
        /// The offending encoded length.
        len: u64,
    },
    /// A root-record payload carried trailing bytes after the final field.
    #[error("persistent root record payload has {remaining} trailing bytes")]
    RootRecordTrailingBytes {
        /// The number of unexpected trailing bytes.
        remaining: usize,
    },
    /// A root-record payload could not reconstruct its embedded impure-input trace.
    #[error("persistent root record payload has invalid impure-input trace: {source}")]
    RootRecordTrace {
        /// The node-trace payload decoding error.
        source: Box<PersistNodeTracePayloadError>,
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
    /// A trace payload declared too many memo-read dependency keys for this platform.
    #[error("persistent node trace payload dependency count {count} does not fit in usize")]
    DependencyCountOverflow {
        /// The decoded dependency count.
        count: u64,
    },
    /// A trace payload dependency count is too large to encode.
    #[error("persistent node trace payload cannot encode {dependencies} dependency keys")]
    EncodedDependencyCountOverflow {
        /// The requested dependency count.
        dependencies: usize,
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
    /// A trace payload could not reserve storage for memo-read dependency keys.
    #[error("failed to reserve persistent node trace payload for {dependencies} dependency keys")]
    DependencyAllocationFailed {
        /// The requested dependency count.
        dependencies: usize,
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
    /// A decoded memo-read dependency key could not be reconstructed.
    #[error("failed to reconstruct persistent node trace dependency key")]
    Dependency {
        /// The underlying persistent index-key error.
        source: PersistPackFormatError,
    },
    /// A dependency value-hash field used the absent tag with non-zero padding.
    #[error("persistent node trace dependency value hash has non-zero absent padding")]
    NonZeroDependencyValueHashPadding,
    /// A dependency value-hash field had an unexpected presence tag.
    #[error("persistent node trace dependency value hash has invalid tag {tag}")]
    InvalidDependencyValueHashTag {
        /// The malformed optional value-hash tag.
        tag: u8,
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
    /// The in-process node trace read lock was poisoned by a prior panic.
    #[error("persistent node trace read lock was poisoned")]
    ReadLockPoisoned,
    /// The advisory node trace write lock could not be acquired.
    #[error("failed to acquire persistent node trace advisory write lock at {path}")]
    AdvisoryWriteLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The advisory node trace read lock could not be acquired.
    #[error("failed to acquire persistent node trace advisory read lock at {path}")]
    AdvisoryReadLock {
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
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

/// Immutable blob packfile operation failed.
#[derive(Debug, Error)]
pub enum PersistBlobPackError {
    /// The same-root blob-pack write lock was poisoned by a prior panic.
    #[error("persistent blob pack write lock for {store:?} is poisoned")]
    WriteLockPoisoned {
        /// The selected blob store.
        store: PersistBlobStore,
    },
    /// The same-root blob-pack read lock was poisoned by a prior panic.
    #[error("persistent blob pack read lock for {store:?} is poisoned")]
    ReadLockPoisoned {
        /// The selected blob store.
        store: PersistBlobStore,
    },
    /// The advisory blob-pack write lock could not be acquired.
    #[error("failed to acquire persistent blob pack advisory write lock for {store:?} at {path}")]
    AdvisoryWriteLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
    },
    /// The advisory blob-pack read lock could not be acquired.
    #[error("failed to acquire persistent blob pack advisory read lock for {store:?} at {path}")]
    AdvisoryReadLock {
        /// The selected blob store.
        store: PersistBlobStore,
        /// The advisory lock file path.
        path: PathBuf,
        /// The underlying advisory lock error.
        source: ratchet_cache::file_lock::AdvisoryFileLockError,
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
    /// The packfile could not be memory-mapped.
    #[error("failed to memory-map persistent blob pack {path}")]
    Map {
        /// The packfile path.
        path: PathBuf,
        /// The underlying memory-map error.
        source: ratchet_cache::store::ReadOnlyMmapError,
    },
    /// The packfile could not be written.
    #[error("failed to write persistent blob pack {path}")]
    Write {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A staged pack rewrite path aliases the source pack path.
    #[error("persistent blob pack rewrite temp {tmp_path} aliases source {source_path}")]
    SourceEqualsTemp {
        /// The source pack path.
        source_path: PathBuf,
        /// The rejected temporary pack path.
        tmp_path: PathBuf,
    },
    /// The packfile metadata has an unsupported or malformed format.
    #[error("persistent blob pack {path} has invalid metadata")]
    Format {
        /// The packfile path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
    /// The packfile descriptor did not refer to a regular file.
    #[error("persistent blob pack {path} is not a regular file")]
    NotRegularFile {
        /// The packfile path.
        path: PathBuf,
    },
    /// The mapped-read lease did not cover the packfile descriptor.
    #[error("persistent blob pack mapped-read lease rejected {path}")]
    MappedReadLeaseRejected {
        /// The packfile path.
        path: PathBuf,
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
