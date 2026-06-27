//! Initialized immutable blob packfile handle.
//!
//! Wraps an opened packfile, appends hash-verified payloads, and reads them
//! back through validated record metadata.

use super::*;

const PERSIST_BLOB_SCAN_BUFFER_LEN: usize = 8 * 1024;

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
        ensure_blob_pack_file(&path)?;
        Ok(Self { path })
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
        let file = open_validated_blob_pack_for_read(&self.path)?;
        file.metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| PersistBlobPackError::Metadata {
                path: self.path.clone(),
                source,
            })
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
        let mut file = open_validated_blob_pack_for_read(&self.path)?;
        let pack_len = file
            .metadata()
            .map_err(|source| PersistBlobPackError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        let mut offset = PERSIST_BLOB_PACK_HEADER_LEN as u64;
        let mut records = Vec::new();
        while offset < pack_len {
            let remaining = pack_len - offset;
            if remaining < PERSIST_BLOB_RECORD_HEADER_LEN as u64 {
                return Err(PersistBlobPackError::Format {
                    path: self.path.clone(),
                    source: PersistPackFormatError::ShortRecordHeader {
                        expected: PERSIST_BLOB_RECORD_HEADER_LEN,
                        actual: remaining as usize,
                    },
                });
            }
            file.seek(SeekFrom::Start(offset))
                .map_err(|source| PersistBlobPackError::Seek {
                    path: self.path.clone(),
                    source,
                })?;
            let mut record_header = [0; PERSIST_BLOB_RECORD_HEADER_LEN];
            file.read_exact(&mut record_header)
                .map_err(|source| PersistBlobPackError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            let record = PersistBlobRecordHeader::decode(&record_header).map_err(|source| {
                PersistBlobPackError::Format {
                    path: self.path.clone(),
                    source,
                }
            })?;
            let payload_start = offset
                .checked_add(PERSIST_BLOB_RECORD_HEADER_LEN as u64)
                .ok_or(PersistBlobPackError::RecordBoundsOverflow {
                    record_offset: offset,
                    payload_len: record.payload_len(),
                })?;
            let payload_end = payload_start.checked_add(record.payload_len()).ok_or(
                PersistBlobPackError::RecordBoundsOverflow {
                    record_offset: offset,
                    payload_len: record.payload_len(),
                },
            )?;
            if payload_end > pack_len {
                return Err(PersistBlobPackError::RecordExtendsPastEnd {
                    payload_end,
                    pack_len,
                });
            }
            let mut remaining = record.payload_len();
            let mut hasher = blake3::Hasher::new();
            let mut buffer = [0; PERSIST_BLOB_SCAN_BUFFER_LEN];
            while remaining > 0 {
                let chunk_len = usize::try_from(remaining.min(PERSIST_BLOB_SCAN_BUFFER_LEN as u64))
                    .map_err(|_| PersistBlobPackError::PayloadTooLarge {
                        payload_len: record.payload_len() as u128,
                    })?;
                file.read_exact(&mut buffer[..chunk_len])
                    .map_err(|source| PersistBlobPackError::Read {
                        path: self.path.clone(),
                        source,
                    })?;
                hasher.update(&buffer[..chunk_len]);
                remaining -= chunk_len as u64;
            }
            let actual = DurableBlake3Hash::from_bytes(hasher.finalize().into());
            if actual != record.hash() {
                return Err(PersistBlobPackError::PayloadHashMismatch {
                    expected: record.hash(),
                    actual,
                });
            }
            records.push(PersistBlobPackRecord::new(
                record.hash(),
                PersistBlobLocation::new(offset, record.payload_len()),
            ));
            offset = payload_end;
        }
        Ok(records)
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
        ensure_blob_pack_file(&self.path)?;
        let actual = DurableBlake3Hash::for_bytes(payload);
        if actual != hash {
            return Err(PersistBlobPackError::PayloadHashMismatch {
                expected: hash,
                actual,
            });
        }
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| PersistBlobPackError::PayloadTooLarge {
                payload_len: payload.len() as u128,
            })?;
        let header = PersistBlobRecordHeader::new(hash, payload_len);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| PersistBlobPackError::Open {
                path: self.path.clone(),
                source,
            })?;
        let record_offset = file
            .metadata()
            .map_err(|source| PersistBlobPackError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        if record_offset < PERSIST_BLOB_PACK_HEADER_LEN as u64 {
            return Err(PersistBlobPackError::InvalidRecordOffset { record_offset });
        }
        file.write_all(&header.encode())
            .and_then(|()| file.write_all(payload))
            .and_then(|()| file.flush())
            .map_err(|source| PersistBlobPackError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(PersistBlobLocation::new(record_offset, payload_len))
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
        let mut file = open_validated_blob_pack_for_read(&self.path)?;
        self.payload_window_from_open_file(&mut file, location, expected_hash)
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
        let mut file = open_validated_blob_pack_for_read(&self.path)?;
        let window = self.payload_window_from_open_file(&mut file, location, expected_hash)?;
        self.verify_payload_from_open_file(&mut file, window)?;
        Ok(window)
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
        let mut file = open_validated_blob_pack_for_read(&self.path)?;
        let window = self.payload_window_from_open_file(&mut file, location, expected_hash)?;
        let expected_len = u64::try_from(expected_payload.len()).map_err(|_| {
            PersistBlobPackError::PayloadTooLarge {
                payload_len: expected_payload.len() as u128,
            }
        })?;
        if expected_len != window.payload_len() {
            self.verify_payload_from_open_file(&mut file, window)?;
            return Ok(false);
        }
        self.payload_matches_from_open_file(&mut file, window, expected_payload)
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
        let mut file = open_validated_blob_pack_for_read(&self.path)?;
        let window = self.payload_window_from_open_file(&mut file, location, expected_hash)?;
        let payload_len = usize::try_from(window.payload_len()).map_err(|_| {
            PersistBlobPackError::PayloadTooLarge {
                payload_len: window.payload_len() as u128,
            }
        })?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_len).map_err(|_| {
            PersistBlobPackError::PayloadTooLarge {
                payload_len: window.payload_len() as u128,
            }
        })?;
        payload.resize(payload_len, 0);
        file.seek(SeekFrom::Start(window.payload_start()))
            .map_err(|source| PersistBlobPackError::Seek {
                path: self.path.clone(),
                source,
            })?;
        file.read_exact(&mut payload)
            .map_err(|source| PersistBlobPackError::Read {
                path: self.path.clone(),
                source,
            })?;
        let actual = DurableBlake3Hash::for_bytes(&payload);
        if actual != expected_hash {
            return Err(PersistBlobPackError::PayloadHashMismatch {
                expected: expected_hash,
                actual,
            });
        }
        Ok(payload)
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
    /// created or written, a copied record lands at a different location than
    /// planned, or the completed temporary pack fails validation.
    pub(super) fn write_relocated_records_to(
        &self,
        tmp_path: impl Into<PathBuf>,
        relocations: &[PersistBlobRecordRelocation],
    ) -> Result<PersistBlobPack, PersistBlobPackError> {
        ensure_blob_pack_file(&self.path)?;
        let tmp_path = tmp_path.into();
        match fs::remove_file(&tmp_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(PersistBlobPackError::Write {
                    path: tmp_path,
                    source,
                });
            }
        }
        let tmp_pack = PersistBlobPack::open(tmp_path.clone())?;
        let copy_result = (|| {
            for relocation in relocations {
                let payload = self.read_blob(relocation.old_location(), relocation.key().hash())?;
                let copied = tmp_pack.append_blob(relocation.key().hash(), &payload)?;
                if copied != relocation.new_location() {
                    return Err(PersistBlobPackError::RecordLocationMismatch {
                        expected: relocation.new_location(),
                        actual: copied,
                    });
                }
            }
            Ok(())
        })();
        if let Err(error) = copy_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(error);
        }
        tmp_pack.len()?;
        Ok(tmp_pack)
    }

    fn payload_window_from_open_file(
        &self,
        file: &mut fs::File,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<PersistBlobPayloadWindow, PersistBlobPackError> {
        if location.record_offset() < PERSIST_BLOB_PACK_HEADER_LEN as u64 {
            return Err(PersistBlobPackError::InvalidRecordOffset {
                record_offset: location.record_offset(),
            });
        }
        file.seek(SeekFrom::Start(location.record_offset()))
            .map_err(|source| PersistBlobPackError::Seek {
                path: self.path.clone(),
                source,
            })?;
        let mut record_header = [0; PERSIST_BLOB_RECORD_HEADER_LEN];
        file.read_exact(&mut record_header)
            .map_err(|source| PersistBlobPackError::Read {
                path: self.path.clone(),
                source,
            })?;
        let record = PersistBlobRecordHeader::decode(&record_header).map_err(|source| {
            PersistBlobPackError::Format {
                path: self.path.clone(),
                source,
            }
        })?;
        if record.hash() != expected_hash {
            return Err(PersistBlobPackError::RecordHashMismatch {
                expected: expected_hash,
                actual: record.hash(),
            });
        }
        if record.payload_len() != location.payload_len() {
            return Err(PersistBlobPackError::RecordLengthMismatch {
                expected: location.payload_len(),
                actual: record.payload_len(),
            });
        }
        let payload_start = location
            .record_offset()
            .checked_add(PERSIST_BLOB_RECORD_HEADER_LEN as u64)
            .ok_or(PersistBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: record.payload_len(),
            })?;
        let payload_end = payload_start.checked_add(record.payload_len()).ok_or(
            PersistBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: record.payload_len(),
            },
        )?;
        let pack_len = file
            .metadata()
            .map_err(|source| PersistBlobPackError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        if payload_end > pack_len {
            return Err(PersistBlobPackError::RecordExtendsPastEnd {
                payload_end,
                pack_len,
            });
        }
        Ok(PersistBlobPayloadWindow::new(
            PersistBlobPackRecord::new(record.hash(), location),
            payload_start,
            payload_end,
        ))
    }

    fn verify_payload_from_open_file(
        &self,
        file: &mut fs::File,
        window: PersistBlobPayloadWindow,
    ) -> Result<(), PersistBlobPackError> {
        file.seek(SeekFrom::Start(window.payload_start()))
            .map_err(|source| PersistBlobPackError::Seek {
                path: self.path.clone(),
                source,
            })?;
        let mut remaining = window.payload_len();
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0; PERSIST_BLOB_SCAN_BUFFER_LEN];
        while remaining > 0 {
            let chunk_len = usize::try_from(remaining.min(PERSIST_BLOB_SCAN_BUFFER_LEN as u64))
                .map_err(|_| PersistBlobPackError::PayloadTooLarge {
                    payload_len: window.payload_len() as u128,
                })?;
            file.read_exact(&mut buffer[..chunk_len])
                .map_err(|source| PersistBlobPackError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            hasher.update(&buffer[..chunk_len]);
            remaining -= chunk_len as u64;
        }
        let actual = DurableBlake3Hash::from_bytes(hasher.finalize().into());
        if actual != window.hash() {
            return Err(PersistBlobPackError::PayloadHashMismatch {
                expected: window.hash(),
                actual,
            });
        }
        Ok(())
    }

    fn payload_matches_from_open_file(
        &self,
        file: &mut fs::File,
        window: PersistBlobPayloadWindow,
        expected_payload: &[u8],
    ) -> Result<bool, PersistBlobPackError> {
        file.seek(SeekFrom::Start(window.payload_start()))
            .map_err(|source| PersistBlobPackError::Seek {
                path: self.path.clone(),
                source,
            })?;
        let mut remaining = window.payload_len();
        let mut compared = 0usize;
        let mut payload_matches = true;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0; PERSIST_BLOB_SCAN_BUFFER_LEN];
        while remaining > 0 {
            let chunk_len = usize::try_from(remaining.min(PERSIST_BLOB_SCAN_BUFFER_LEN as u64))
                .map_err(|_| PersistBlobPackError::PayloadTooLarge {
                    payload_len: window.payload_len() as u128,
                })?;
            file.read_exact(&mut buffer[..chunk_len])
                .map_err(|source| PersistBlobPackError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            hasher.update(&buffer[..chunk_len]);
            let next_compared =
                compared
                    .checked_add(chunk_len)
                    .ok_or(PersistBlobPackError::PayloadTooLarge {
                        payload_len: window.payload_len() as u128,
                    })?;
            if payload_matches && buffer[..chunk_len] != expected_payload[compared..next_compared] {
                payload_matches = false;
            }
            compared = next_compared;
            remaining -= chunk_len as u64;
        }
        let actual = DurableBlake3Hash::from_bytes(hasher.finalize().into());
        if actual != window.hash() {
            return Err(PersistBlobPackError::PayloadHashMismatch {
                expected: window.hash(),
                actual,
            });
        }
        Ok(payload_matches)
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
        if end_offset < PERSIST_BLOB_PACK_HEADER_LEN as u64 {
            return Err(PersistBlobPackError::InvalidRecordOffset {
                record_offset: end_offset,
            });
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(|source| PersistBlobPackError::Open {
                path: self.path.clone(),
                source,
            })?;
        validate_blob_pack_header(&self.path, &mut file)?;
        let len = file
            .metadata()
            .map_err(|source| PersistBlobPackError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        if end_offset > len {
            return Err(PersistBlobPackError::RecordExtendsPastEnd {
                payload_end: end_offset,
                pack_len: len,
            });
        }
        if end_offset == len {
            return Ok(0);
        }
        file.set_len(end_offset)
            .and_then(|()| file.flush())
            .map_err(|source| PersistBlobPackError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(len - end_offset)
    }
}
