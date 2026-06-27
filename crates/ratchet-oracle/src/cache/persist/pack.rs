//! Initialized immutable blob packfile handle.
//!
//! Wraps an opened packfile, appends hash-verified payloads, and reads them
//! back through validated record metadata.

use super::*;

use ratchet_cache::blob_pack::{
    BLOB_PACK_HEADER_LEN, BlobPackAppendError, BlobPackAppender, BlobPackFormatError, BlobPackHash,
    BlobPackLocation, BlobPackPayloadWindow, BlobPackReadError, BlobPackReader, BlobPackRecord,
    BlobPackRecordRelocation, BlobPackRewriteError, BlobPackTrimError,
};

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

fn open_engine_blob_pack_reader(path: &Path) -> Result<BlobPackReader, PersistBlobPackError> {
    BlobPackReader::open(path.to_path_buf()).map_err(engine_read_error_to_persist)
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

fn persist_relocation_to_engine(
    relocation: PersistBlobRecordRelocation,
) -> BlobPackRecordRelocation {
    BlobPackRecordRelocation::new(
        durable_hash_to_engine(relocation.key().hash()),
        persist_location_to_engine(relocation.old_location()),
        persist_location_to_engine(relocation.new_location()),
    )
}

fn engine_append_error_to_persist(error: BlobPackAppendError) -> PersistBlobPackError {
    match error {
        BlobPackAppendError::CreateParent { path, source } => {
            PersistBlobPackError::CreateParent { path, source }
        }
        BlobPackAppendError::Open { path, source } => PersistBlobPackError::Open { path, source },
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

fn engine_trim_error_to_persist(error: BlobPackTrimError) -> PersistBlobPackError {
    match error {
        BlobPackTrimError::Open { path, source } => PersistBlobPackError::Open { path, source },
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
        Ok(Self { appender, path })
    }

    /// Returns this packfile's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the current packfile length after validating its header.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// inspected, or if its header is malformed.
    pub fn len(&self) -> Result<u64, PersistBlobPackError> {
        let reader = open_engine_blob_pack_reader(&self.path)?;
        reader.len().map_err(engine_read_error_to_persist)
    }

    /// Returns whether the packfile has no blob records.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// inspected, or if its header is malformed.
    pub fn is_empty(&self) -> Result<bool, PersistBlobPackError> {
        Ok(self.len()? == BLOB_PACK_HEADER_LEN as u64)
    }

    /// Returns all verified blob records in packfile order.
    ///
    /// This reads each record header and payload, verifies that the payload
    /// bytes hash to the record's declared content address, and returns only
    /// record metadata. It is a buffered integrity-scan helper for future
    /// maintenance paths; hot cache-hit reads still use direct indexed lookups.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// inspected, seeked, or read, if any record header is malformed or
    /// truncated, if a record points past the current packfile length, if a
    /// payload length cannot fit in memory, or if a payload hash does not match
    /// the record header.
    pub fn records(&self) -> Result<Vec<PersistBlobPackRecord>, PersistBlobPackError> {
        let reader = open_engine_blob_pack_reader(&self.path)?;
        reader
            .records()
            .map(|records| records.into_iter().map(engine_record_to_persist).collect())
            .map_err(engine_read_error_to_persist)
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
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// inspected, seeked, or read, if `location` is invalid, if record metadata
    /// does not match the expected lookup, or if the declared payload window
    /// falls outside the current packfile.
    pub fn payload_window(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<PersistBlobPayloadWindow, PersistBlobPackError> {
        let reader = open_engine_blob_pack_reader(&self.path)?;
        reader
            .payload_window(
                persist_location_to_engine(location),
                durable_hash_to_engine(expected_hash),
            )
            .map(engine_payload_window_to_persist)
            .map_err(engine_read_error_to_persist)
    }

    /// Verifies the payload at `location` without materializing it.
    ///
    /// This validates the record metadata and pack bounds in the same way as
    /// [`Self::payload_window`], then streams the payload bytes through BLAKE3
    /// and returns the verified byte window. It is intended for maintenance
    /// paths that need to prove a pack root is live without allocating the
    /// payload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// inspected, seeked, or read, if `location` is invalid, if record metadata
    /// does not match the expected lookup, if the declared payload window falls
    /// outside the current packfile, or if the payload hash does not verify.
    pub fn verify_blob(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<PersistBlobPayloadWindow, PersistBlobPackError> {
        let reader = open_engine_blob_pack_reader(&self.path)?;
        reader
            .verify_payload(
                persist_location_to_engine(location),
                durable_hash_to_engine(expected_hash),
            )
            .map(engine_payload_window_to_persist)
            .map_err(engine_read_error_to_persist)
    }

    /// Returns whether the verified payload at `location` equals `expected_payload`.
    ///
    /// This validates the record metadata and pack bounds, streams the payload
    /// bytes once, compares them with `expected_payload`, and still verifies
    /// that the stored payload hashes to `expected_hash`. A length mismatch
    /// after metadata validation returns `Ok(false)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// inspected, seeked, or read, if `location` is invalid, if record metadata
    /// does not match the expected lookup, if the declared payload window falls
    /// outside the current packfile, if `expected_payload` is too large to
    /// compare with a pack record, or if the stored payload hash does not
    /// verify.
    pub fn payload_matches(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
        expected_payload: &[u8],
    ) -> Result<bool, PersistBlobPackError> {
        let reader = open_engine_blob_pack_reader(&self.path)?;
        reader
            .payload_matches(
                persist_location_to_engine(location),
                durable_hash_to_engine(expected_hash),
                expected_payload,
            )
            .map_err(engine_read_error_to_persist)
    }

    /// Reads and verifies a blob at `location`.
    ///
    /// The record header's hash and length must match `expected_hash` and
    /// `location`, and the payload bytes must hash to `expected_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// read, if `location` is invalid, if record metadata does not match the
    /// expected lookup, or if the payload hash does not verify.
    pub fn read_blob(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        let reader = open_engine_blob_pack_reader(&self.path)?;
        reader
            .read_payload(
                persist_location_to_engine(location),
                durable_hash_to_engine(expected_hash),
            )
            .map_err(engine_read_error_to_persist)
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
        let tmp_path = tmp_path.into();
        open_engine_blob_pack_appender(&self.path)?;
        let reader = open_engine_blob_pack_reader(&self.path)?;
        let engine_relocations = relocations
            .iter()
            .copied()
            .map(persist_relocation_to_engine)
            .collect::<Vec<_>>();
        let tmp_reader = reader
            .write_relocated_records_to(tmp_path, &engine_relocations)
            .map_err(engine_rewrite_error_to_persist)?;
        let path = tmp_reader.path().to_path_buf();
        let appender = open_engine_blob_pack_appender(&path)?;
        Ok(Self { appender, path })
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
