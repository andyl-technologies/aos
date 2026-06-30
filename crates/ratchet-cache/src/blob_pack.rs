//! Content-addressed blob packfiles.
//!
//! RFC-0007 stores immutable `values/` and `files/` payloads in append-only
//! packfiles. This module owns the stable pack header and record format,
//! append-only buffered writes, tail trimming, rewrite staging, buffered
//! integrity reads that return owned payload bytes, and memory-mapped reads
//! that return borrowed payload slices.
//!
//! ```text
//! pack = header || record*
//!
//! header:
//!   magic:      16 bytes, "AOS-NIX-BLOBPACK"
//!   version:    4-byte little-endian u32
//!   header_len: 4-byte little-endian u32
//!
//! record:
//!   hash:        32 bytes, BLAKE3 digest of payload
//!   payload_len: 8-byte little-endian u64
//!   payload:     payload_len bytes
//! ```

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

mod appender;
mod errors;
mod format;
mod locking;
mod mapped;

pub use appender::BlobPackAppender;
pub use errors::{
    BlobPackAppendError, BlobPackFileIdentityError, BlobPackFormatError, BlobPackReadError,
    BlobPackReadLeaseError, BlobPackRewriteError, BlobPackTrimError, MappedBlobPackError,
};
pub use format::{
    BLOB_PACK_HEADER_LEN, BLOB_PACK_MAGIC, BLOB_PACK_VERSION, BLOB_RECORD_HEADER_LEN,
    BlobPackFileIdentity, BlobPackHash, BlobPackHeader, BlobPackLocation, BlobPackPayloadWindow,
    BlobPackRecord, BlobPackRecordRelocation, BlobRecordHeader,
};
pub use mapped::{
    BlobPackFileReadLease, BlobPackReadLease, LeasedMappedBlobPack, MappedBlobPack,
    MappedBlobPayload,
};

const BLOB_PACK_SCAN_BUFFER_LEN: usize = 8 * 1024;

/// A buffered read-only blob packfile handle.
#[derive(Clone, Debug)]
pub struct BlobPackReader {
    path: PathBuf,
}

impl BlobPackReader {
    /// Opens a read-only blob packfile at `path` and validates its header.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackReadError`] if the packfile cannot be opened/read, or
    /// if its existing header is malformed.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, BlobPackReadError> {
        let path = path.into();
        open_blob_pack_for_buffered_read(&path)?;
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
    /// Returns [`BlobPackReadError`] if the packfile cannot be opened,
    /// inspected, or if its header is malformed.
    pub fn len(&self) -> Result<u64, BlobPackReadError> {
        let file = open_blob_pack_for_buffered_read(&self.path)?;
        file.metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| BlobPackReadError::Metadata {
                path: self.path.clone(),
                source,
            })
    }

    /// Returns whether the packfile has no bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackReadError`] if [`Self::len`] fails.
    pub fn is_empty(&self) -> Result<bool, BlobPackReadError> {
        self.len().map(|len| len == 0)
    }

    /// Returns all verified blob records in packfile order.
    ///
    /// The scan validates each record header, checks payload bounds, streams
    /// payload bytes through BLAKE3, and returns only record metadata.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackReadError`] if the packfile cannot be opened,
    /// inspected, seeked, or read, if any record header is malformed or
    /// truncated, if a record points past the current packfile length, if a
    /// payload length cannot fit in memory, or if a payload hash does not match
    /// the record header.
    pub fn records(&self) -> Result<Vec<BlobPackRecord>, BlobPackReadError> {
        let mut file = open_blob_pack_for_buffered_read(&self.path)?;
        let pack_len = file
            .metadata()
            .map_err(|source| BlobPackReadError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        let mut offset = BLOB_PACK_HEADER_LEN as u64;
        let mut records = Vec::new();
        while offset < pack_len {
            let window = self.payload_window_from_open_file(
                &mut file,
                BlobPackLocation::new(offset, 0),
                None,
            )?;
            self.verify_payload_from_open_file(&mut file, window)?;
            records.push(window.record());
            offset = window.payload_end();
        }
        Ok(records)
    }

    /// Validates record metadata for `location` and returns its payload window.
    ///
    /// The record header's hash and length must match `expected_hash` and
    /// `location`, and the resulting payload byte range must fit inside the
    /// current packfile. This helper does not read or hash the payload bytes;
    /// callers that materialize the payload must still verify its content, as
    /// [`Self::read_payload`] does.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackReadError`] if the packfile cannot be opened,
    /// inspected, seeked, or read, if `location` is invalid, if record metadata
    /// does not match the expected lookup, or if the declared payload window
    /// falls outside the current packfile.
    pub fn payload_window(
        &self,
        location: BlobPackLocation,
        expected_hash: BlobPackHash,
    ) -> Result<BlobPackPayloadWindow, BlobPackReadError> {
        let mut file = open_blob_pack_for_buffered_read(&self.path)?;
        self.payload_window_from_open_file(&mut file, location, Some(expected_hash))
    }

    /// Verifies the payload at `location` without materializing it.
    ///
    /// This validates record metadata and pack bounds, then streams the payload
    /// bytes through BLAKE3 and returns the verified byte window.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackReadError`] if the packfile cannot be opened,
    /// inspected, seeked, or read, if `location` is invalid, if record metadata
    /// does not match the expected lookup, if the declared payload window falls
    /// outside the current packfile, or if the payload hash does not verify.
    pub fn verify_payload(
        &self,
        location: BlobPackLocation,
        expected_hash: BlobPackHash,
    ) -> Result<BlobPackPayloadWindow, BlobPackReadError> {
        let mut file = open_blob_pack_for_buffered_read(&self.path)?;
        let window =
            self.payload_window_from_open_file(&mut file, location, Some(expected_hash))?;
        self.verify_payload_from_open_file(&mut file, window)?;
        Ok(window)
    }

    /// Returns whether the verified payload equals `expected_payload`.
    ///
    /// This validates record metadata and pack bounds, streams the payload
    /// bytes once, compares them with `expected_payload`, and still verifies
    /// that the stored payload hashes to `expected_hash`. A length mismatch
    /// after metadata validation returns `Ok(false)`.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackReadError`] if the packfile cannot be opened,
    /// inspected, seeked, or read, if `location` is invalid, if record metadata
    /// does not match the expected lookup, if the declared payload window falls
    /// outside the current packfile, if `expected_payload` is too large to
    /// compare with a pack record, or if the stored payload hash does not
    /// verify.
    pub fn payload_matches(
        &self,
        location: BlobPackLocation,
        expected_hash: BlobPackHash,
        expected_payload: &[u8],
    ) -> Result<bool, BlobPackReadError> {
        let mut file = open_blob_pack_for_buffered_read(&self.path)?;
        let window =
            self.payload_window_from_open_file(&mut file, location, Some(expected_hash))?;
        let expected_len = u64::try_from(expected_payload.len()).map_err(|_| {
            BlobPackReadError::PayloadTooLarge {
                payload_len: expected_payload.len() as u128,
            }
        })?;
        if expected_len != window.payload_len() {
            self.verify_payload_from_open_file(&mut file, window)?;
            return Ok(false);
        }
        self.payload_matches_from_open_file(&mut file, window, expected_payload)
    }

    /// Reads and verifies a blob payload at `location`.
    ///
    /// The record header's hash and length must match `expected_hash` and
    /// `location`, and the payload bytes must hash to `expected_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackReadError`] if the packfile cannot be opened or read,
    /// if `location` is invalid, if record metadata does not match the expected
    /// lookup, if the payload cannot fit in memory, or if the payload hash does
    /// not verify.
    pub fn read_payload(
        &self,
        location: BlobPackLocation,
        expected_hash: BlobPackHash,
    ) -> Result<Vec<u8>, BlobPackReadError> {
        let mut file = open_blob_pack_for_buffered_read(&self.path)?;
        let window =
            self.payload_window_from_open_file(&mut file, location, Some(expected_hash))?;
        let payload_len = usize::try_from(window.payload_len()).map_err(|_| {
            BlobPackReadError::PayloadTooLarge {
                payload_len: window.payload_len() as u128,
            }
        })?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_len)
            .map_err(|_| BlobPackReadError::PayloadTooLarge {
                payload_len: window.payload_len() as u128,
            })?;
        payload.resize(payload_len, 0);
        file.seek(SeekFrom::Start(window.payload_start()))
            .map_err(|source| BlobPackReadError::Seek {
                path: self.path.clone(),
                source,
            })?;
        file.read_exact(&mut payload)
            .map_err(|source| BlobPackReadError::Read {
                path: self.path.clone(),
                source,
            })?;
        let actual = BlobPackHash::for_bytes(&payload);
        if actual != expected_hash {
            return Err(BlobPackReadError::PayloadHashMismatch {
                expected: expected_hash,
                actual,
            });
        }
        Ok(payload)
    }

    /// Writes a compacted pack containing `relocations` to `tmp_path`.
    ///
    /// Each relocation reads and verifies the payload from this source pack,
    /// appends it to a fresh temporary pack, and checks that the append lands at
    /// the caller-planned destination location. Any pre-existing `tmp_path` is
    /// removed before writing. If copying fails, the temporary file is removed
    /// on a best-effort basis before returning the original error.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackRewriteError`] if `tmp_path` cannot be removed,
    /// if it aliases this source pack, if it cannot be opened as a fresh pack,
    /// appended to, or validated, if any source record cannot be read and
    /// verified, or if a copied record lands at a different location than the
    /// supplied relocation plan.
    pub fn write_relocated_records_to(
        &self,
        tmp_path: impl Into<PathBuf>,
        relocations: &[BlobPackRecordRelocation],
    ) -> Result<BlobPackReader, BlobPackRewriteError> {
        let (_tmp_pack, reader, ()) = write_staged_blob_pack(&self.path, tmp_path, |tmp_pack| {
            for relocation in relocations {
                let payload = self
                    .read_payload(relocation.old_location(), relocation.hash())
                    .map_err(|source| BlobPackRewriteError::ReadSource { source })?;
                let copied = tmp_pack
                    .append_payload(relocation.hash(), &payload)
                    .map_err(|source| BlobPackRewriteError::AppendTemp { source })?;
                if copied != relocation.new_location() {
                    return Err(BlobPackRewriteError::RecordLocationMismatch {
                        expected: relocation.new_location(),
                        actual: copied,
                    });
                }
            }
            Ok(())
        })?;
        Ok(reader)
    }

    fn payload_window_from_open_file(
        &self,
        file: &mut fs::File,
        location: BlobPackLocation,
        expected_hash: Option<BlobPackHash>,
    ) -> Result<BlobPackPayloadWindow, BlobPackReadError> {
        if location.record_offset() < BLOB_PACK_HEADER_LEN as u64 {
            return Err(BlobPackReadError::InvalidRecordOffset {
                record_offset: location.record_offset(),
            });
        }
        let pack_len = file
            .metadata()
            .map_err(|source| BlobPackReadError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        let record_end = location
            .record_offset()
            .checked_add(BLOB_RECORD_HEADER_LEN as u64)
            .ok_or(BlobPackReadError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: location.payload_len(),
            })?;
        if record_end > pack_len {
            return Err(BlobPackReadError::Format {
                path: self.path.clone(),
                source: BlobPackFormatError::ShortRecordHeader {
                    expected: BLOB_RECORD_HEADER_LEN,
                    actual: pack_len.saturating_sub(location.record_offset()) as usize,
                },
            });
        }
        file.seek(SeekFrom::Start(location.record_offset()))
            .map_err(|source| BlobPackReadError::Seek {
                path: self.path.clone(),
                source,
            })?;
        let mut record_header = [0; BLOB_RECORD_HEADER_LEN];
        file.read_exact(&mut record_header)
            .map_err(|source| BlobPackReadError::Read {
                path: self.path.clone(),
                source,
            })?;
        let record = BlobRecordHeader::decode(&record_header).map_err(|source| {
            BlobPackReadError::Format {
                path: self.path.clone(),
                source,
            }
        })?;
        if let Some(expected_hash) = expected_hash {
            if record.hash() != expected_hash {
                return Err(BlobPackReadError::RecordHashMismatch {
                    expected: expected_hash,
                    actual: record.hash(),
                });
            }
            if record.payload_len() != location.payload_len() {
                return Err(BlobPackReadError::RecordLengthMismatch {
                    expected: location.payload_len(),
                    actual: record.payload_len(),
                });
            }
        }
        let payload_start = location
            .record_offset()
            .checked_add(BLOB_RECORD_HEADER_LEN as u64)
            .ok_or(BlobPackReadError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: record.payload_len(),
            })?;
        let payload_end = payload_start.checked_add(record.payload_len()).ok_or(
            BlobPackReadError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: record.payload_len(),
            },
        )?;
        if payload_end > pack_len {
            return Err(BlobPackReadError::RecordExtendsPastEnd {
                payload_end,
                pack_len,
            });
        }
        Ok(BlobPackPayloadWindow::new(
            BlobPackRecord::new(
                record.hash(),
                BlobPackLocation::new(location.record_offset(), record.payload_len()),
            ),
            payload_start,
            payload_end,
        ))
    }

    fn verify_payload_from_open_file(
        &self,
        file: &mut fs::File,
        window: BlobPackPayloadWindow,
    ) -> Result<(), BlobPackReadError> {
        file.seek(SeekFrom::Start(window.payload_start()))
            .map_err(|source| BlobPackReadError::Seek {
                path: self.path.clone(),
                source,
            })?;
        let mut remaining = window.payload_len();
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0; BLOB_PACK_SCAN_BUFFER_LEN];
        while remaining > 0 {
            let chunk_len = usize::try_from(remaining.min(BLOB_PACK_SCAN_BUFFER_LEN as u64))
                .map_err(|_| BlobPackReadError::PayloadTooLarge {
                    payload_len: window.payload_len() as u128,
                })?;
            file.read_exact(&mut buffer[..chunk_len])
                .map_err(|source| BlobPackReadError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            hasher.update(&buffer[..chunk_len]);
            remaining -= chunk_len as u64;
        }
        let actual = BlobPackHash::from_bytes(*hasher.finalize().as_bytes());
        if actual != window.hash() {
            return Err(BlobPackReadError::PayloadHashMismatch {
                expected: window.hash(),
                actual,
            });
        }
        Ok(())
    }

    fn payload_matches_from_open_file(
        &self,
        file: &mut fs::File,
        window: BlobPackPayloadWindow,
        expected_payload: &[u8],
    ) -> Result<bool, BlobPackReadError> {
        file.seek(SeekFrom::Start(window.payload_start()))
            .map_err(|source| BlobPackReadError::Seek {
                path: self.path.clone(),
                source,
            })?;
        let mut remaining = window.payload_len();
        let mut compared = 0usize;
        let mut payload_matches = true;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0; BLOB_PACK_SCAN_BUFFER_LEN];
        while remaining > 0 {
            let chunk_len = usize::try_from(remaining.min(BLOB_PACK_SCAN_BUFFER_LEN as u64))
                .map_err(|_| BlobPackReadError::PayloadTooLarge {
                    payload_len: window.payload_len() as u128,
                })?;
            file.read_exact(&mut buffer[..chunk_len])
                .map_err(|source| BlobPackReadError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            hasher.update(&buffer[..chunk_len]);
            let next_compared =
                compared
                    .checked_add(chunk_len)
                    .ok_or(BlobPackReadError::PayloadTooLarge {
                        payload_len: window.payload_len() as u128,
                    })?;
            if payload_matches && buffer[..chunk_len] != expected_payload[compared..next_compared] {
                payload_matches = false;
            }
            compared = next_compared;
            remaining -= chunk_len as u64;
        }
        let actual = BlobPackHash::from_bytes(*hasher.finalize().as_bytes());
        if actual != window.hash() {
            return Err(BlobPackReadError::PayloadHashMismatch {
                expected: window.hash(),
                actual,
            });
        }
        Ok(payload_matches)
    }
}

/// Writes a staged blob-pack rewrite through a caller-provided append closure.
///
/// This helper owns the common rewrite protocol: source/temp alias rejection,
/// stale temp removal, fresh temporary pack initialization, cleanup when
/// `write_records` fails, and final temporary-pack validation. The caller owns
/// the actual relocation strategy and appends records through the supplied
/// [`BlobPackAppender`].
///
/// # Errors
///
/// Returns `E` when the staging protocol fails or when `write_records`
/// returns an error. Staging failures are converted from
/// [`BlobPackRewriteError`] through `E::from`.
pub fn write_staged_blob_pack<R, E>(
    source_path: impl AsRef<Path>,
    tmp_path: impl Into<PathBuf>,
    write_records: impl FnOnce(&BlobPackAppender) -> Result<R, E>,
) -> Result<(BlobPackAppender, BlobPackReader, R), E>
where
    E: From<BlobPackRewriteError>,
{
    let source_path = source_path.as_ref();
    let tmp_path = tmp_path.into();
    if blob_pack_rewrite_paths_alias(source_path, &tmp_path) {
        return Err(BlobPackRewriteError::SourceEqualsTemp {
            source_path: source_path.to_path_buf(),
            tmp_path,
        }
        .into());
    }
    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(BlobPackRewriteError::RemoveTemp {
                path: tmp_path,
                source,
            }
            .into());
        }
    }

    let tmp_pack = BlobPackAppender::open(tmp_path.clone())
        .map_err(|source| BlobPackRewriteError::OpenTemp { source })?;
    let output = match write_records(&tmp_pack) {
        Ok(output) => output,
        Err(error) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(error);
        }
    };
    let reader = BlobPackReader::open(tmp_path.clone()).map_err(|source| {
        let _ = fs::remove_file(&tmp_path);
        BlobPackRewriteError::ValidateTemp { source }
    })?;
    reader.len().map_err(|source| {
        let _ = fs::remove_file(&tmp_path);
        BlobPackRewriteError::ValidateTemp { source }
    })?;
    Ok((tmp_pack, reader, output))
}

/// Returns whether a blob-pack rewrite source and temporary path alias.
///
/// The check first compares the path strings directly, then falls back to
/// canonicalized filesystem paths when both paths currently exist.
pub fn blob_pack_rewrite_paths_alias(source_path: &Path, tmp_path: &Path) -> bool {
    if source_path == tmp_path {
        return true;
    }
    match (fs::canonicalize(source_path), fs::canonicalize(tmp_path)) {
        (Ok(source), Ok(tmp)) => source == tmp,
        _ => false,
    }
}

fn open_blob_pack_for_buffered_read(path: &Path) -> Result<fs::File, BlobPackReadError> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| BlobPackReadError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| BlobPackReadError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_open_blob_pack_header_for_read(path, &mut file, len)?;
    Ok(file)
}

fn validate_open_blob_pack_header_for_read(
    path: &Path,
    file: &mut fs::File,
    len: u64,
) -> Result<(), BlobPackReadError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BlobPackReadError::Seek {
            path: path.to_path_buf(),
            source,
        })?;

    let header_len = len.min(BLOB_PACK_HEADER_LEN as u64) as usize;
    let mut bytes = vec![0; header_len];
    file.read_exact(&mut bytes)
        .map_err(|source| BlobPackReadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    BlobPackHeader::decode(&bytes).map_err(|source| BlobPackReadError::Format {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
