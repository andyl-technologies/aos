//! Initialized immutable blob packfile handle.
//!
//! Wraps an opened packfile, appends hash-verified payloads, and reads them
//! back through validated record metadata.

use super::*;

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
        if location.record_offset() < PERSIST_BLOB_PACK_HEADER_LEN as u64 {
            return Err(PersistBlobPackError::InvalidRecordOffset {
                record_offset: location.record_offset(),
            });
        }
        let mut file = open_validated_blob_pack_for_read(&self.path)?;
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
        let payload_len = usize::try_from(record.payload_len()).map_err(|_| {
            PersistBlobPackError::PayloadTooLarge {
                payload_len: record.payload_len() as u128,
            }
        })?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_len).map_err(|_| {
            PersistBlobPackError::PayloadTooLarge {
                payload_len: record.payload_len() as u128,
            }
        })?;
        payload.resize(payload_len, 0);
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
