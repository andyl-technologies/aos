//! Initialized immutable blob packfile handle.
//!
//! Wraps an opened packfile, appends hash-verified payloads, and reads them
//! back through validated record metadata.

use super::*;

use ratchet_cache::blob_pack::{
    BLOB_PACK_HEADER_LEN, BlobPackAppendError, BlobPackAppender, BlobPackFileIdentityError,
    BlobPackFileReadLease, BlobPackFormatError, BlobPackHash, BlobPackLocation,
    BlobPackPayloadWindow, BlobPackReadError, BlobPackReadLeaseError, BlobPackRecord,
    BlobPackRewriteError, BlobPackTrimError, MappedBlobPack, MappedBlobPackError,
    blob_pack_rewrite_paths_alias, write_staged_blob_pack,
};
use ratchet_cache::file_lock::AdvisoryFileLock;
use ratchet_cache::store::ReadOnlyMmapError;

/// Verified metadata for one immutable blob-pack record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistBlobPackRecord {
    hash: DurableBlake3Hash,
    location: PersistBlobLocation,
}

impl PersistBlobPackRecord {
    const fn new(hash: DurableBlake3Hash, location: PersistBlobLocation) -> Self {
        Self { hash, location }
    }

    /// Returns the durable BLAKE3 content address declared by this record.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.hash
    }

    /// Returns this record's byte location in the packfile.
    pub const fn location(self) -> PersistBlobLocation {
        self.location
    }

    /// Returns this record as a typed blob lookup key for `store`.
    pub const fn key(self, store: PersistBlobStore) -> PersistBlobKey {
        PersistBlobKey::new(store, self.hash)
    }
}

fn open_engine_blob_pack_appender(path: &Path) -> Result<BlobPackAppender, PersistBlobPackError> {
    BlobPackAppender::open(path.to_path_buf()).map_err(engine_append_error_to_persist)
}

fn durable_hash_to_engine(hash: DurableBlake3Hash) -> BlobPackHash {
    BlobPackHash::from_bytes(hash.as_bytes())
}

fn engine_hash_to_durable(hash: BlobPackHash) -> DurableBlake3Hash {
    DurableBlake3Hash::from_bytes(hash.as_bytes())
}

fn engine_location_to_persist(location: BlobPackLocation) -> PersistBlobLocation {
    PersistBlobLocation::new(location.record_offset(), location.payload_len())
}

fn persist_location_to_engine(location: PersistBlobLocation) -> BlobPackLocation {
    BlobPackLocation::new(location.record_offset(), location.payload_len())
}

fn engine_record_to_persist(record: BlobPackRecord) -> PersistBlobPackRecord {
    PersistBlobPackRecord::new(
        engine_hash_to_durable(record.hash()),
        engine_location_to_persist(record.location()),
    )
}

fn engine_payload_window_to_persist(window: BlobPackPayloadWindow) -> PersistBlobPayloadWindow {
    PersistBlobPayloadWindow::new(
        engine_record_to_persist(window.record()),
        window.payload_start(),
        window.payload_end(),
    )
}

fn engine_append_error_to_persist(error: BlobPackAppendError) -> PersistBlobPackError {
    match error {
        BlobPackAppendError::CreateParent { path, source } => {
            PersistBlobPackError::CreateParent { path, source }
        }
        BlobPackAppendError::Open { path, source } => PersistBlobPackError::Open { path, source },
        BlobPackAppendError::Lock { path, source } => PersistBlobPackError::Write { path, source },
        BlobPackAppendError::Metadata { path, source } => {
            PersistBlobPackError::Metadata { path, source }
        }
        BlobPackAppendError::Seek { path, source } => PersistBlobPackError::Seek { path, source },
        BlobPackAppendError::Read { path, source } => PersistBlobPackError::Read { path, source },
        BlobPackAppendError::Write { path, source } => PersistBlobPackError::Write { path, source },
        BlobPackAppendError::Format { path, source } => PersistBlobPackError::Format {
            path,
            source: engine_format_error_to_persist(source),
        },
        BlobPackAppendError::PayloadTooLarge { payload_len } => {
            PersistBlobPackError::PayloadTooLarge { payload_len }
        }
        BlobPackAppendError::PayloadHashMismatch { expected, actual } => {
            PersistBlobPackError::PayloadHashMismatch {
                expected: engine_hash_to_durable(expected),
                actual: engine_hash_to_durable(actual),
            }
        }
        BlobPackAppendError::InvalidRecordOffset { record_offset } => {
            PersistBlobPackError::InvalidRecordOffset { record_offset }
        }
    }
}

fn engine_read_error_to_persist(error: BlobPackReadError) -> PersistBlobPackError {
    match error {
        BlobPackReadError::Open { path, source } => PersistBlobPackError::Open { path, source },
        BlobPackReadError::Metadata { path, source } => {
            PersistBlobPackError::Metadata { path, source }
        }
        BlobPackReadError::Seek { path, source } => PersistBlobPackError::Seek { path, source },
        BlobPackReadError::Read { path, source } => PersistBlobPackError::Read { path, source },
        BlobPackReadError::Format { path, source } => PersistBlobPackError::Format {
            path,
            source: engine_format_error_to_persist(source),
        },
        BlobPackReadError::InvalidRecordOffset { record_offset } => {
            PersistBlobPackError::InvalidRecordOffset { record_offset }
        }
        BlobPackReadError::PayloadTooLarge { payload_len } => {
            PersistBlobPackError::PayloadTooLarge { payload_len }
        }
        BlobPackReadError::RecordBoundsOverflow {
            record_offset,
            payload_len,
        } => PersistBlobPackError::RecordBoundsOverflow {
            record_offset,
            payload_len,
        },
        BlobPackReadError::RecordExtendsPastEnd {
            payload_end,
            pack_len,
        } => PersistBlobPackError::RecordExtendsPastEnd {
            payload_end,
            pack_len,
        },
        BlobPackReadError::RecordHashMismatch { expected, actual } => {
            PersistBlobPackError::RecordHashMismatch {
                expected: engine_hash_to_durable(expected),
                actual: engine_hash_to_durable(actual),
            }
        }
        BlobPackReadError::RecordLengthMismatch { expected, actual } => {
            PersistBlobPackError::RecordLengthMismatch { expected, actual }
        }
        BlobPackReadError::PayloadHashMismatch { expected, actual } => {
            PersistBlobPackError::PayloadHashMismatch {
                expected: engine_hash_to_durable(expected),
                actual: engine_hash_to_durable(actual),
            }
        }
    }
}

fn engine_mapped_error_to_persist(path: &Path, error: MappedBlobPackError) -> PersistBlobPackError {
    match error {
        MappedBlobPackError::Map(source) => engine_mmap_error_to_persist(path, source),
        MappedBlobPackError::Format(source) => PersistBlobPackError::Format {
            path: path.to_path_buf(),
            source: engine_format_error_to_persist(source),
        },
        MappedBlobPackError::LeaseRejected => PersistBlobPackError::MappedReadLeaseRejected {
            path: path.to_path_buf(),
        },
        MappedBlobPackError::InvalidRecordOffset { record_offset } => {
            PersistBlobPackError::InvalidRecordOffset { record_offset }
        }
        MappedBlobPackError::RecordBoundsOverflow {
            record_offset,
            payload_len,
        } => PersistBlobPackError::RecordBoundsOverflow {
            record_offset,
            payload_len,
        },
        MappedBlobPackError::RecordExtendsPastEnd {
            payload_end,
            pack_len,
        } => PersistBlobPackError::RecordExtendsPastEnd {
            payload_end: u128_to_u64_saturating(payload_end),
            pack_len: u128_to_u64_saturating(pack_len),
        },
        MappedBlobPackError::RecordHashMismatch { expected, actual } => {
            PersistBlobPackError::RecordHashMismatch {
                expected: engine_hash_to_durable(expected),
                actual: engine_hash_to_durable(actual),
            }
        }
        MappedBlobPackError::RecordLengthMismatch { expected, actual } => {
            PersistBlobPackError::RecordLengthMismatch { expected, actual }
        }
        MappedBlobPackError::PayloadHashMismatch { expected, actual } => {
            PersistBlobPackError::PayloadHashMismatch {
                expected: engine_hash_to_durable(expected),
                actual: engine_hash_to_durable(actual),
            }
        }
    }
}

fn u128_to_u64_saturating(value: u128) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}

fn engine_mmap_error_to_persist(path: &Path, error: ReadOnlyMmapError) -> PersistBlobPackError {
    match error {
        ReadOnlyMmapError::Metadata { source } => PersistBlobPackError::Metadata {
            path: path.to_path_buf(),
            source,
        },
        source => PersistBlobPackError::Map {
            path: path.to_path_buf(),
            source,
        },
    }
}

fn engine_file_identity_error_to_persist(
    path: &Path,
    error: BlobPackFileIdentityError,
) -> PersistBlobPackError {
    match error {
        BlobPackFileIdentityError::Metadata(source) => PersistBlobPackError::Metadata {
            path: path.to_path_buf(),
            source,
        },
        BlobPackFileIdentityError::NotRegularFile => PersistBlobPackError::NotRegularFile {
            path: path.to_path_buf(),
        },
    }
}

fn engine_read_lease_error_to_persist(
    path: &Path,
    error: BlobPackReadLeaseError,
) -> PersistBlobPackError {
    match error {
        BlobPackReadLeaseError::Lock { source } => PersistBlobPackError::Read {
            path: path.to_path_buf(),
            source,
        },
        BlobPackReadLeaseError::Identity { source } => {
            engine_file_identity_error_to_persist(path, source)
        }
    }
}

fn engine_rewrite_error_to_persist(error: BlobPackRewriteError) -> PersistBlobPackError {
    match error {
        BlobPackRewriteError::SourceEqualsTemp {
            source_path,
            tmp_path,
        } => PersistBlobPackError::SourceEqualsTemp {
            source_path,
            tmp_path,
        },
        BlobPackRewriteError::RemoveTemp { path, source } => {
            PersistBlobPackError::Write { path, source }
        }
        BlobPackRewriteError::OpenTemp { source } | BlobPackRewriteError::AppendTemp { source } => {
            engine_append_error_to_persist(source)
        }
        BlobPackRewriteError::ReadSource { source }
        | BlobPackRewriteError::ValidateTemp { source } => engine_read_error_to_persist(source),
        BlobPackRewriteError::RecordLocationMismatch { expected, actual } => {
            PersistBlobPackError::RecordLocationMismatch {
                expected: engine_location_to_persist(expected),
                actual: engine_location_to_persist(actual),
            }
        }
    }
}

impl From<BlobPackRewriteError> for PersistBlobPackError {
    fn from(error: BlobPackRewriteError) -> Self {
        engine_rewrite_error_to_persist(error)
    }
}

fn engine_trim_error_to_persist(error: BlobPackTrimError) -> PersistBlobPackError {
    match error {
        BlobPackTrimError::Open { path, source } => PersistBlobPackError::Open { path, source },
        BlobPackTrimError::Lock { path, source } => PersistBlobPackError::Write { path, source },
        BlobPackTrimError::Metadata { path, source } => {
            PersistBlobPackError::Metadata { path, source }
        }
        BlobPackTrimError::Seek { path, source } => PersistBlobPackError::Seek { path, source },
        BlobPackTrimError::Read { path, source } => PersistBlobPackError::Read { path, source },
        BlobPackTrimError::Write { path, source } => PersistBlobPackError::Write { path, source },
        BlobPackTrimError::Format { path, source } => PersistBlobPackError::Format {
            path,
            source: engine_format_error_to_persist(source),
        },
        BlobPackTrimError::InvalidRecordOffset { record_offset } => {
            PersistBlobPackError::InvalidRecordOffset { record_offset }
        }
        BlobPackTrimError::RecordExtendsPastEnd {
            payload_end,
            pack_len,
        } => PersistBlobPackError::RecordExtendsPastEnd {
            payload_end,
            pack_len,
        },
    }
}

fn engine_format_error_to_persist(error: BlobPackFormatError) -> PersistPackFormatError {
    match error {
        BlobPackFormatError::ShortPackHeader { expected, actual } => {
            PersistPackFormatError::ShortPackHeader { expected, actual }
        }
        BlobPackFormatError::InvalidPackMagic { actual } => {
            PersistPackFormatError::InvalidPackMagic { actual }
        }
        BlobPackFormatError::UnsupportedPackVersion { version } => {
            PersistPackFormatError::UnsupportedPackVersion { version }
        }
        BlobPackFormatError::InvalidPackHeaderLength { header_len } => {
            PersistPackFormatError::InvalidPackHeaderLength { header_len }
        }
        BlobPackFormatError::ShortRecordHeader { expected, actual } => {
            PersistPackFormatError::ShortRecordHeader { expected, actual }
        }
    }
}

/// Validated byte window for one immutable blob-pack payload.
///
/// This is a point-in-time description of a record's byte range. It does not
/// pin the packfile contents; callers that read from the range after obtaining
/// it must hold their own file or mapping validity guarantees and still verify
/// payload bytes before trusting them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistBlobPayloadWindow {
    record: PersistBlobPackRecord,
    payload_start: u64,
    payload_end: u64,
}

impl PersistBlobPayloadWindow {
    const fn new(record: PersistBlobPackRecord, payload_start: u64, payload_end: u64) -> Self {
        Self {
            record,
            payload_start,
            payload_end,
        }
    }

    /// Returns the record metadata that owns this payload window.
    pub const fn record(self) -> PersistBlobPackRecord {
        self.record
    }

    /// Returns the durable BLAKE3 content address declared by this record.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.record.hash()
    }

    /// Returns this record's byte location in the packfile.
    pub const fn location(self) -> PersistBlobLocation {
        self.record.location()
    }

    /// Returns this record as a typed blob lookup key for `store`.
    pub const fn key(self, store: PersistBlobStore) -> PersistBlobKey {
        self.record.key(store)
    }

    /// Returns the byte offset where the payload starts.
    pub const fn payload_start(self) -> u64 {
        self.payload_start
    }

    /// Returns the byte offset one past the end of the payload.
    pub const fn payload_end(self) -> u64 {
        self.payload_end
    }

    /// Returns the payload length declared by this record.
    pub const fn payload_len(self) -> u64 {
        self.record.location().payload_len()
    }

    /// Returns the half-open byte range occupied by this payload.
    pub fn payload_range(self) -> std::ops::Range<u64> {
        self.payload_start..self.payload_end
    }
}

/// An initialized immutable blob packfile.
#[derive(Clone, Debug)]
pub struct PersistBlobPack {
    appender: BlobPackAppender,
    path: PathBuf,
    #[cfg(test)]
    mapped_read_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PersistBlobPack {
    /// Opens or initializes an immutable blob packfile at `path`.
    ///
    /// An empty file is initialized with the current packfile header. A
    /// non-empty file must already contain a valid current header.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if parent directories or the packfile
    /// cannot be created/opened/read/written, or if existing packfile metadata
    /// is invalid.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistBlobPackError> {
        let path = path.into();
        let appender = open_engine_blob_pack_appender(&path)?;
        Ok(Self {
            appender,
            path,
            #[cfg(test)]
            mapped_read_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Returns this packfile's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the number of scoped mapped reads made through this handle.
    #[cfg(test)]
    pub(crate) fn mapped_read_count_for_tests(&self) -> usize {
        self.mapped_read_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns the current packfile length after validating its header.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// leased, mapped, or if its header is malformed.
    pub fn len(&self) -> Result<u64, PersistBlobPackError> {
        self.mapped_len_unlocked()
    }

    /// Returns whether the packfile has no blob records.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// leased, mapped, or if its header is malformed.
    pub fn is_empty(&self) -> Result<bool, PersistBlobPackError> {
        Ok(self.len()? == BLOB_PACK_HEADER_LEN as u64)
    }

    /// Returns all mapped and verified blob records in packfile order.
    ///
    /// This holds a descriptor read lease while it maps the packfile, validates
    /// each record header and payload window, verifies mapped payload hashes,
    /// and returns only owned record metadata. Payload bytes are not copied out
    /// of the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the descriptor read lease does not cover the opened packfile,
    /// if any record header is malformed or truncated, if any payload window
    /// falls outside the mapping, or if any payload hash does not match its
    /// record header.
    pub fn records(&self) -> Result<Vec<PersistBlobPackRecord>, PersistBlobPackError> {
        self.mapped_records_unlocked()
    }

    /// Appends `payload` as a content-addressed immutable blob.
    ///
    /// The payload is checked against `hash` before any bytes are appended.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// validated, or written, or if `hash` does not match `payload`.
    pub fn append_blob(
        &self,
        hash: DurableBlake3Hash,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        let appender = open_engine_blob_pack_appender(&self.path)?;
        appender
            .append_payload(durable_hash_to_engine(hash), payload)
            .map(engine_location_to_persist)
            .map_err(engine_append_error_to_persist)
    }

    /// Appends many content-addressed blobs in one open/lock/flush cycle.
    ///
    /// This is the write-behind flush primitive: it opens the packfile once,
    /// exclusively locks it once, and writes every record with a single buffered
    /// `write_all`, amortizing the per-record open/flock/flush of
    /// [`Self::append_blob`]. The returned [`PersistBlobLocation`] values record
    /// the offsets in input order. An empty batch is a no-op.
    ///
    /// Every record is content-addressed: `hash` is the caller-computed BLAKE3 of
    /// its payload (the store key the record was just looked up under), so this
    /// path trusts that pairing and does not re-hash each payload — re-hashing
    /// would repeat the digest that dominates the cold populate profile. A torn
    /// tail from a crash mid-flush is a hash-invalid record the reader discards as
    /// a miss.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// exclusively locked, stat'd, or written.
    pub fn append_blobs_batch(
        &self,
        records: &[(DurableBlake3Hash, &[u8])],
    ) -> Result<Vec<PersistBlobLocation>, PersistBlobPackError> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let engine_records: Vec<_> = records
            .iter()
            .map(|(hash, payload)| (durable_hash_to_engine(*hash), *payload))
            .collect();
        let appender = open_engine_blob_pack_appender(&self.path)?;
        appender
            .append_payloads_batch_trusted(&engine_records)
            .map(|locations| locations.into_iter().map(engine_location_to_persist).collect())
            .map_err(engine_append_error_to_persist)
    }

    /// Validates record metadata for `location` and returns its payload window.
    ///
    /// The record header's hash and length must match `expected_hash` and
    /// `location`, and the resulting payload byte range must fit inside the
    /// current packfile. This helper does not read or hash the payload bytes;
    /// callers that materialize the payload must still verify its content, as
    /// [`Self::read_blob`] does. The returned window is not a lease on the
    /// file's contents; long-lived readers must revalidate or otherwise hold a
    /// stable file/mapping view before using the range.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the descriptor read lease does not cover the opened packfile,
    /// if `location` is invalid, if record metadata does not match the expected
    /// lookup, or if the declared payload window falls outside the mapping.
    pub fn payload_window(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<PersistBlobPayloadWindow, PersistBlobPackError> {
        self.mapped_payload_window_unlocked(location, expected_hash)
    }

    /// Maps and verifies the payload at `location` without materializing it.
    ///
    /// This validates the record metadata and pack bounds in the same way as
    /// [`Self::payload_window`], then hashes mapped payload bytes and returns
    /// the verified byte window. It is intended for maintenance paths that need
    /// to prove a pack root is live without allocating the payload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the descriptor read lease does not cover the opened packfile,
    /// if `location` is invalid, if record metadata does not match the expected
    /// lookup, if the declared payload window falls outside the mapping, or if
    /// the payload hash does not verify.
    pub fn verify_blob(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<PersistBlobPayloadWindow, PersistBlobPackError> {
        self.with_blob(location, expected_hash, |_| {
            verified_payload_window(location, expected_hash)
        })?
    }

    /// Returns whether the verified payload at `location` equals `expected_payload`.
    ///
    /// This validates the record metadata and pack bounds, maps and hashes the
    /// payload bytes once, compares them with `expected_payload`, and still
    /// verifies that the stored payload hashes to `expected_hash`. A length
    /// mismatch after metadata validation returns `Ok(false)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the descriptor read lease does not cover the opened packfile,
    /// if `location` is invalid, if record metadata does not match the expected
    /// lookup, if the declared payload window falls outside the mapping, if
    /// `expected_payload` is too large to compare with a pack record, or if the
    /// stored payload hash does not verify.
    pub fn payload_matches(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
        expected_payload: &[u8],
    ) -> Result<bool, PersistBlobPackError> {
        let expected_len = u64::try_from(expected_payload.len()).map_err(|_| {
            PersistBlobPackError::PayloadTooLarge {
                payload_len: expected_payload.len() as u128,
            }
        })?;
        self.with_blob(location, expected_hash, |payload| {
            expected_len == location.payload_len() && payload == expected_payload
        })
    }

    /// Reads and verifies a blob at `location`.
    ///
    /// The record header's hash and length must match `expected_hash` and
    /// `location`, and the payload bytes must hash to `expected_hash`. This is
    /// an owned-byte wrapper around [`Self::with_blob`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the descriptor read lease does not cover the opened packfile,
    /// if `location` is invalid, if record metadata does not match the expected
    /// lookup, if the payload hash does not verify, or if cloning the mapped
    /// payload cannot reserve enough memory.
    pub fn read_blob(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.with_blob(location, expected_hash, clone_mapped_blob_payload)?
    }

    /// Maps, verifies, and visits a blob payload.
    ///
    /// The callback receives a borrowed payload slice from a memory-mapped
    /// packfile. The borrowed slice cannot escape this method, and the pack
    /// descriptor read lease is held for the duration of the callback. This is a
    /// lower-level pack API; cache-level readers that need the cache-root
    /// advisory store lock should use [`PersistCache::with_blob`] instead.
    /// Callbacks must not re-enter same-pack operations that need the exclusive
    /// descriptor lock, such as append or tail-trim operations, because those
    /// operations wait for this method's read lease to be released.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the descriptor read lease does not cover the opened packfile,
    /// if `location` is invalid, or if record/payload hashes do not match
    /// `expected_hash`.
    ///
    /// # Panics
    ///
    /// Panics if `visit` panics.
    pub fn with_blob<R>(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
        visit: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, PersistBlobPackError> {
        self.with_mapped_blob_unlocked(location, expected_hash, visit)
    }

    /// Maps, verifies, and visits a blob payload while a caller-owned read lease is held.
    ///
    /// The callback receives a borrowed payload slice from a memory-mapped
    /// packfile. That slice cannot escape this method, and the caller must hold
    /// the same advisory read lock used by cooperating blob-pack writers for
    /// the duration of the call.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the advisory read lease does not cover the opened packfile,
    /// if `location` is invalid, or if record/payload hashes do not match
    /// `expected_hash`.
    pub(super) fn with_mapped_blob<R>(
        &self,
        _read_lease: &AdvisoryFileLock,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
        visit: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, PersistBlobPackError> {
        self.with_mapped_blob_unlocked(location, expected_hash, visit)
    }

    fn with_mapped_blob_unlocked<R>(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
        visit: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, PersistBlobPackError> {
        let file = fs::File::open(&self.path).map_err(|source| PersistBlobPackError::Open {
            path: self.path.clone(),
            source,
        })?;
        let lease = BlobPackFileReadLease::new(&file)
            .map_err(|source| engine_read_lease_error_to_persist(&self.path, source))?;
        let pack = MappedBlobPack::map_file_with_lease(&file, &lease)
            .map_err(|source| engine_mapped_error_to_persist(&self.path, source))?;
        let payload = pack
            .payload(
                persist_location_to_engine(location),
                durable_hash_to_engine(expected_hash),
            )
            .map_err(|source| engine_mapped_error_to_persist(&self.path, source))?;
        #[cfg(test)]
        self.mapped_read_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(visit(payload.as_bytes()))
    }

    fn mapped_payload_window_unlocked(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<PersistBlobPayloadWindow, PersistBlobPackError> {
        let file = fs::File::open(&self.path).map_err(|source| PersistBlobPackError::Open {
            path: self.path.clone(),
            source,
        })?;
        let lease = BlobPackFileReadLease::new(&file)
            .map_err(|source| engine_read_lease_error_to_persist(&self.path, source))?;
        let pack = MappedBlobPack::map_file_with_lease(&file, &lease)
            .map_err(|source| engine_mapped_error_to_persist(&self.path, source))?;
        let window = pack
            .payload_window(
                persist_location_to_engine(location),
                durable_hash_to_engine(expected_hash),
            )
            .map_err(|source| engine_mapped_error_to_persist(&self.path, source))?;
        #[cfg(test)]
        self.mapped_read_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(engine_payload_window_to_persist(window))
    }

    fn mapped_len_unlocked(&self) -> Result<u64, PersistBlobPackError> {
        let file = fs::File::open(&self.path).map_err(|source| PersistBlobPackError::Open {
            path: self.path.clone(),
            source,
        })?;
        let lease = BlobPackFileReadLease::new(&file)
            .map_err(|source| engine_read_lease_error_to_persist(&self.path, source))?;
        let pack = MappedBlobPack::map_file_with_lease(&file, &lease)
            .map_err(|source| engine_mapped_error_to_persist(&self.path, source))?;
        let pack_len = pack.len();
        let len = u64::try_from(pack_len).map_err(|_| PersistBlobPackError::PayloadTooLarge {
            payload_len: pack_len as u128,
        })?;
        #[cfg(test)]
        self.mapped_read_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(len)
    }

    /// Maps and verifies a blob payload while returning only owned window metadata.
    ///
    /// The caller must hold the same advisory read lock used by cooperating
    /// blob-pack writers for the duration of the call. Payload bytes are verified
    /// through the scoped mapping but are not copied or exposed to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the advisory read lease does not cover the opened packfile,
    /// if `location` is invalid, or if record/payload hashes do not match
    /// `expected_hash`.
    pub(super) fn verify_mapped_blob(
        &self,
        read_lease: &AdvisoryFileLock,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<PersistBlobPayloadWindow, PersistBlobPackError> {
        self.with_mapped_blob(read_lease, location, expected_hash, |_| {
            verified_payload_window(location, expected_hash)
        })?
    }

    /// Maps, verifies, and visits all blob records while a caller-owned read lease is held.
    ///
    /// The callback receives owned record metadata produced from a memory-mapped
    /// pack scan. Payload bytes are verified through the mapping but cannot
    /// escape this method, and the caller must hold the same advisory read lock
    /// used by cooperating blob-pack writers for the duration of the call.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// mapped, if the advisory read lease does not cover the opened packfile,
    /// if any record header is malformed or truncated, if any payload window
    /// falls outside the mapping, or if any payload hash does not match its
    /// record header.
    pub(super) fn with_mapped_records<R>(
        &self,
        _read_lease: &AdvisoryFileLock,
        visit: impl FnOnce(Vec<PersistBlobPackRecord>) -> R,
    ) -> Result<R, PersistBlobPackError> {
        let records = self.mapped_records_unlocked()?;
        Ok(visit(records))
    }

    fn mapped_records_unlocked(&self) -> Result<Vec<PersistBlobPackRecord>, PersistBlobPackError> {
        let file = fs::File::open(&self.path).map_err(|source| PersistBlobPackError::Open {
            path: self.path.clone(),
            source,
        })?;
        let lease = BlobPackFileReadLease::new(&file)
            .map_err(|source| engine_read_lease_error_to_persist(&self.path, source))?;
        let pack = MappedBlobPack::map_file_with_lease(&file, &lease)
            .map_err(|source| engine_mapped_error_to_persist(&self.path, source))?;
        let records = pack
            .records()
            .map_err(|source| engine_mapped_error_to_persist(&self.path, source))?
            .into_iter()
            .map(engine_record_to_persist)
            .collect();
        #[cfg(test)]
        self.mapped_read_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(records)
    }

    /// Writes a compacted copy of the supplied records to `tmp_path`.
    ///
    /// Each relocation is read from the current pack at its old location,
    /// payload-verified against its key, appended to a temporary pack, and
    /// checked against the relocation's planned new location. Callers are
    /// responsible for renaming the completed temporary pack into place with
    /// whatever sidecar updates make those new locations visible.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the current pack cannot be read, a
    /// relocated source record fails verification, the temporary pack cannot be
    /// created or written, `tmp_path` aliases the source pack, a copied record
    /// lands at a different location than planned, or the completed temporary
    /// pack fails validation.
    pub(super) fn write_relocated_records_to(
        &self,
        tmp_path: impl Into<PathBuf>,
        relocations: &[PersistBlobRecordRelocation],
    ) -> Result<PersistBlobPack, PersistBlobPackError> {
        self.write_relocated_records_from_mapped_source_to(
            tmp_path.into(),
            relocations,
            |pack, location, hash, tmp_appender| {
                pack.with_mapped_blob_unlocked(location, hash, |payload| {
                    tmp_appender
                        .append_payload(durable_hash_to_engine(hash), payload)
                        .map_err(engine_append_error_to_persist)
                })?
            },
        )
    }

    /// Writes a compacted mapped copy of the supplied records to `tmp_path`.
    ///
    /// The temporary pack is staged through the shared engine rewrite helper so
    /// source/temp alias rejection and stale temporary cleanup stay centralized.
    /// Each relocated source record is then verified through a scoped mapped
    /// payload read while `read_lease` is held, appended to the temporary pack,
    /// and checked against the planned new location.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the current pack cannot be read or
    /// mapped, a relocated source record fails verification, the temporary pack
    /// cannot be created or written, `tmp_path` aliases the source pack, a copied
    /// record lands at a different location than planned, or the completed
    /// temporary pack fails validation.
    pub(super) fn write_relocated_records_mapped_to(
        &self,
        read_lease: &AdvisoryFileLock,
        tmp_path: impl Into<PathBuf>,
        relocations: &[PersistBlobRecordRelocation],
    ) -> Result<PersistBlobPack, PersistBlobPackError> {
        self.write_relocated_records_from_mapped_source_to(
            tmp_path.into(),
            relocations,
            |pack, location, hash, tmp_appender| {
                pack.with_mapped_blob(read_lease, location, hash, |payload| {
                    tmp_appender
                        .append_payload(durable_hash_to_engine(hash), payload)
                        .map_err(engine_append_error_to_persist)
                })?
            },
        )
    }

    fn write_relocated_records_from_mapped_source_to(
        &self,
        tmp_path: PathBuf,
        relocations: &[PersistBlobRecordRelocation],
        mut append_mapped_payload: impl FnMut(
            &Self,
            PersistBlobLocation,
            DurableBlake3Hash,
            &BlobPackAppender,
        ) -> Result<BlobPackLocation, PersistBlobPackError>,
    ) -> Result<PersistBlobPack, PersistBlobPackError> {
        if blob_pack_rewrite_paths_alias(&self.path, &tmp_path) {
            return Err(PersistBlobPackError::SourceEqualsTemp {
                source_path: self.path.clone(),
                tmp_path,
            });
        }
        open_engine_blob_pack_appender(&self.path)?;
        let (tmp_appender, tmp_reader, ()) =
            write_staged_blob_pack(&self.path, tmp_path, |tmp_appender| {
                for relocation in relocations {
                    let hash = relocation.key().hash();
                    let copied =
                        append_mapped_payload(self, relocation.old_location(), hash, tmp_appender)?;
                    let copied = engine_location_to_persist(copied);
                    if copied != relocation.new_location() {
                        return Err(PersistBlobPackError::RecordLocationMismatch {
                            expected: relocation.new_location(),
                            actual: copied,
                        });
                    }
                }
                Ok(())
            })?;
        let path = tmp_reader.path().to_path_buf();
        Ok(Self {
            appender: tmp_appender,
            path,
            #[cfg(test)]
            mapped_read_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Truncates unneeded bytes after `end_offset`.
    ///
    /// `end_offset` must be at least the fixed pack header length and no larger
    /// than the current file length. The returned value is the number of bytes
    /// removed.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// inspected, truncated, or if `end_offset` is outside the packfile.
    pub(super) fn trim_tail(&self, end_offset: u64) -> Result<u64, PersistBlobPackError> {
        self.appender
            .trim_tail(end_offset)
            .map_err(engine_trim_error_to_persist)
    }
}

fn verified_payload_window(
    location: PersistBlobLocation,
    expected_hash: DurableBlake3Hash,
) -> Result<PersistBlobPayloadWindow, PersistBlobPackError> {
    let payload_start = location
        .record_offset()
        .checked_add(PERSIST_BLOB_RECORD_HEADER_LEN as u64)
        .ok_or(PersistBlobPackError::RecordBoundsOverflow {
            record_offset: location.record_offset(),
            payload_len: location.payload_len(),
        })?;
    let payload_end = payload_start.checked_add(location.payload_len()).ok_or(
        PersistBlobPackError::RecordBoundsOverflow {
            record_offset: location.record_offset(),
            payload_len: location.payload_len(),
        },
    )?;
    Ok(PersistBlobPayloadWindow::new(
        PersistBlobPackRecord::new(expected_hash, location),
        payload_start,
        payload_end,
    ))
}

fn clone_mapped_blob_payload(payload: &[u8]) -> Result<Vec<u8>, PersistBlobPackError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(payload.len())
        .map_err(|_| PersistBlobPackError::PayloadTooLarge {
            payload_len: payload.len() as u128,
        })?;
    owned.extend_from_slice(payload);
    Ok(owned)
}
