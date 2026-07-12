//! Buffered append and tail-trim operations for blob packfiles.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::locking::{BlobPackFileLockMode, lock_blob_pack_file};
use super::{
    BLOB_PACK_HEADER_LEN, BlobPackAppendError, BlobPackHash, BlobPackHeader, BlobPackLocation,
    BlobPackTrimError, BlobRecordHeader,
};

/// A writer for one blob packfile.
///
/// Empty packfiles are initialized with the current [`BlobPackHeader`].
/// Non-empty packfiles must already contain a valid current header. Appends and
/// tail trims are ordinary buffered filesystem writes and do not provide writer
/// coordination, index updates, or crash-durability guarantees beyond flushing
/// the opened descriptor.
#[derive(Clone, Debug)]
pub struct BlobPackAppender {
    path: PathBuf,
}

impl BlobPackAppender {
    /// Opens or initializes the blob packfile at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackAppendError`] if the parent directory or packfile
    /// cannot be created/opened/read/written, or if an existing non-empty
    /// packfile has an invalid header.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, BlobPackAppendError> {
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
    /// Returns [`BlobPackAppendError`] if the packfile cannot be opened,
    /// inspected, or if its header is malformed.
    pub fn len(&self) -> Result<u64, BlobPackAppendError> {
        let file = open_validated_blob_pack_for_read(&self.path)?;
        file.metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| BlobPackAppendError::Metadata {
                path: self.path.clone(),
                source,
            })
    }

    /// Returns whether the current packfile has no bytes.
    ///
    /// Opened packfiles should normally be at least [`BLOB_PACK_HEADER_LEN`]
    /// bytes because [`Self::open`] initializes empty files with a header.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackAppendError`] if [`Self::len`] fails.
    pub fn is_empty(&self) -> Result<bool, BlobPackAppendError> {
        self.len().map(|len| len == 0)
    }

    /// Appends `payload` as a content-addressed immutable record.
    ///
    /// The payload is checked against `expected_hash` before any record bytes
    /// are appended. Callers that need stable returned locations must serialize
    /// writers around this method; this low-level writer does not perform
    /// cache-root locking.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackAppendError`] if the packfile cannot be opened,
    /// validated, or written, if `payload` is too large for the on-disk format,
    /// or if `expected_hash` does not match `payload`.
    pub fn append_payload(
        &self,
        expected_hash: BlobPackHash,
        payload: &[u8],
    ) -> Result<BlobPackLocation, BlobPackAppendError> {
        let actual = BlobPackHash::for_bytes(payload);
        if actual != expected_hash {
            return Err(BlobPackAppendError::PayloadHashMismatch {
                expected: expected_hash,
                actual,
            });
        }

        let payload_len =
            u64::try_from(payload.len()).map_err(|_| BlobPackAppendError::PayloadTooLarge {
                payload_len: payload.len() as u128,
            })?;
        let record_header = BlobRecordHeader::new(expected_hash, payload_len);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| BlobPackAppendError::Open {
                path: self.path.clone(),
                source,
            })?;
        lock_blob_pack_file(&file, BlobPackFileLockMode::Exclusive).map_err(|source| {
            BlobPackAppendError::Lock {
                path: self.path.clone(),
                source,
            }
        })?;
        let record_offset = file
            .metadata()
            .map_err(|source| BlobPackAppendError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        if record_offset < BLOB_PACK_HEADER_LEN as u64 {
            return Err(BlobPackAppendError::InvalidRecordOffset { record_offset });
        }

        file.write_all(&record_header.encode())
            .and_then(|()| file.write_all(payload))
            .and_then(|()| file.flush())
            .map_err(|source| BlobPackAppendError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(BlobPackLocation::new(record_offset, payload_len))
    }

    /// Truncates unneeded bytes after `end_offset`.
    ///
    /// `end_offset` must be at least the fixed pack header length and no larger
    /// than the current file length. The returned value is the number of bytes
    /// removed.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackTrimError`] if the packfile cannot be opened,
    /// inspected, truncated, or if `end_offset` is outside the packfile.
    pub fn trim_tail(&self, end_offset: u64) -> Result<u64, BlobPackTrimError> {
        if end_offset < BLOB_PACK_HEADER_LEN as u64 {
            return Err(BlobPackTrimError::InvalidRecordOffset {
                record_offset: end_offset,
            });
        }

        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(|source| BlobPackTrimError::Open {
                path: self.path.clone(),
                source,
            })?;
        lock_blob_pack_file(&file, BlobPackFileLockMode::Exclusive).map_err(|source| {
            BlobPackTrimError::Lock {
                path: self.path.clone(),
                source,
            }
        })?;
        let len = file
            .metadata()
            .map_err(|source| BlobPackTrimError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_open_blob_pack_header_for_trim(&self.path, &mut file, len)?;

        if end_offset > len {
            return Err(BlobPackTrimError::RecordExtendsPastEnd {
                payload_end: end_offset,
                pack_len: len,
            });
        }
        if end_offset == len {
            return Ok(0);
        }

        file.set_len(end_offset)
            .and_then(|()| file.flush())
            .map_err(|source| BlobPackTrimError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(len - end_offset)
    }
}

fn ensure_blob_pack_file(path: &Path) -> Result<(), BlobPackAppendError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| BlobPackAppendError::CreateParent {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| BlobPackAppendError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    lock_blob_pack_file(&file, BlobPackFileLockMode::Exclusive).map_err(|source| {
        BlobPackAppendError::Lock {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let len = file
        .metadata()
        .map_err(|source| BlobPackAppendError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if len == 0 {
        file.write_all(&BlobPackHeader::current().encode())
            .and_then(|()| file.flush())
            .map_err(|source| BlobPackAppendError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        return Ok(());
    }

    validate_open_blob_pack_header(path, &mut file, len)
}

fn open_validated_blob_pack_for_read(path: &Path) -> Result<fs::File, BlobPackAppendError> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| BlobPackAppendError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| BlobPackAppendError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_open_blob_pack_header(path, &mut file, len)?;
    Ok(file)
}

fn validate_open_blob_pack_header(
    path: &Path,
    file: &mut fs::File,
    len: u64,
) -> Result<(), BlobPackAppendError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BlobPackAppendError::Seek {
            path: path.to_path_buf(),
            source,
        })?;

    let header_len = len.min(BLOB_PACK_HEADER_LEN as u64) as usize;
    let mut bytes = vec![0; header_len];
    file.read_exact(&mut bytes)
        .map_err(|source| BlobPackAppendError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    BlobPackHeader::decode(&bytes).map_err(|source| BlobPackAppendError::Format {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn validate_open_blob_pack_header_for_trim(
    path: &Path,
    file: &mut fs::File,
    len: u64,
) -> Result<(), BlobPackTrimError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BlobPackTrimError::Seek {
            path: path.to_path_buf(),
            source,
        })?;

    let header_len = len.min(BLOB_PACK_HEADER_LEN as u64) as usize;
    let mut bytes = vec![0; header_len];
    file.read_exact(&mut bytes)
        .map_err(|source| BlobPackTrimError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    BlobPackHeader::decode(&bytes).map_err(|source| BlobPackTrimError::Format {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}
