//! Content-addressed blob packfiles.
//!
//! RFC-0007 stores immutable `values/` and `files/` payloads in append-only
//! packfiles. This module owns the stable pack header and record format,
//! append-only buffered writes, tail trimming, buffered integrity reads that
//! return owned payload bytes, and memory-mapped reads that return borrowed
//! payload slices.
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
use std::marker::PhantomData;
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::store::ReadOnlyMmap;

mod appender;
mod errors;
mod format;

pub use appender::BlobPackAppender;
pub use errors::{
    BlobPackAppendError, BlobPackFileIdentityError, BlobPackFormatError, BlobPackReadError,
    BlobPackRewriteError, BlobPackTrimError, MappedBlobPackError,
};
pub use format::{
    BLOB_PACK_HEADER_LEN, BLOB_PACK_MAGIC, BLOB_PACK_VERSION, BLOB_RECORD_HEADER_LEN,
    BlobPackFileIdentity, BlobPackHash, BlobPackHeader, BlobPackLocation, BlobPackPayloadWindow,
    BlobPackRecord, BlobPackRecordRelocation, BlobRecordHeader,
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
        let tmp_path = tmp_path.into();
        if blob_pack_paths_alias(&self.path, &tmp_path) {
            return Err(BlobPackRewriteError::SourceEqualsTemp {
                source_path: self.path.clone(),
                tmp_path,
            });
        }
        match fs::remove_file(&tmp_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(BlobPackRewriteError::RemoveTemp {
                    path: tmp_path,
                    source,
                });
            }
        }

        let tmp_pack = BlobPackAppender::open(tmp_path.clone())
            .map_err(|source| BlobPackRewriteError::OpenTemp { source })?;
        let copy_result = (|| {
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
        })();
        if let Err(error) = copy_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(error);
        }

        let reader = BlobPackReader::open(tmp_path)
            .map_err(|source| BlobPackRewriteError::ValidateTemp { source })?;
        reader
            .len()
            .map_err(|source| BlobPackRewriteError::ValidateTemp { source })?;
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

/// A memory-mapped immutable blob packfile.
#[derive(Debug)]
pub struct MappedBlobPack {
    map: ReadOnlyMmap,
}

/// A lease that permits safe construction of a mapped blob pack.
///
/// The trait is unsafe to implement because [`MappedBlobPack::map_file_with_lease`]
/// relies on implementors to uphold the same immutability invariant as
/// [`MappedBlobPack::map_file`] without forcing callers of the leased API to use
/// an unsafe block.
///
/// # Safety
///
/// When [`Self::covers_file`] returns `true`, the implementor must guarantee
/// that the supplied file's bytes are not mutated for the entire lifetime of
/// the borrowed lease. This includes appends, truncation, replacement, and
/// writes through other file descriptors or processes. Returning `true` for a
/// file that can be mutated while a mapped payload slice is alive violates the
/// contract.
///
/// The leased mapping cannot outlive the borrowed lease:
///
/// ```compile_fail
/// use std::fs;
///
/// use ratchet_cache::blob_pack::{
///     BlobPackReadLease, LeasedMappedBlobPack, MappedBlobPack,
/// };
///
/// struct TemporaryLease;
///
/// unsafe impl BlobPackReadLease for TemporaryLease {
///     fn covers_file(&self, _file: &fs::File) -> bool {
///         true
///     }
/// }
///
/// fn escape_lease(file: &fs::File) -> LeasedMappedBlobPack<'static> {
///     let lease = TemporaryLease;
///     MappedBlobPack::map_file_with_lease(file, &lease).unwrap()
/// }
/// ```
pub unsafe trait BlobPackReadLease {
    /// Returns whether this lease covers `file`.
    fn covers_file(&self, file: &fs::File) -> bool;
}

/// A memory-mapped blob pack whose lifetime is tied to a read lease.
#[derive(Debug)]
pub struct LeasedMappedBlobPack<'lease> {
    pack: MappedBlobPack,
    _lease: PhantomData<&'lease ()>,
}

impl<'lease> LeasedMappedBlobPack<'lease> {
    /// Returns the mapped packfile length.
    pub const fn len(&self) -> usize {
        self.pack.len()
    }

    /// Returns whether the mapped packfile is empty.
    pub const fn is_empty(&self) -> bool {
        self.pack.is_empty()
    }

    /// Reads, validates, and returns a zero-copy payload view.
    ///
    /// The returned payload is borrowed from this leased mapping and cannot
    /// outlive it.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if the record offset is invalid, record
    /// metadata does not match the expected lookup, the payload window falls
    /// outside the mapping, or the payload bytes do not hash to
    /// `expected_hash`.
    pub fn payload(
        &self,
        location: BlobPackLocation,
        expected_hash: BlobPackHash,
    ) -> Result<MappedBlobPayload<'_>, MappedBlobPackError> {
        self.pack.payload(location, expected_hash)
    }

    /// Returns all verified blob records in packfile order.
    ///
    /// The scan validates each record header, checks payload bounds, hashes each
    /// mapped payload, and returns only record metadata.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if any record header is malformed or
    /// truncated, if any payload window falls outside the mapping, or if any
    /// payload bytes do not hash to the record's declared content address.
    pub fn records(&self) -> Result<Vec<BlobPackRecord>, MappedBlobPackError> {
        self.pack.records()
    }

    /// Returns the underlying mapped pack.
    pub fn as_mapped_pack(&self) -> &MappedBlobPack {
        &self.pack
    }
}

impl MappedBlobPack {
    /// Maps `file` and validates its blob packfile header.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if the file cannot be memory-mapped or
    /// if its packfile header is malformed.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that the mapped file's bytes are not mutated
    /// for the lifetime of the returned mapping. This includes writes through
    /// other file descriptors and other processes. Appending, truncating, or
    /// replacing the underlying file while borrowed payload slices from this
    /// mapping exist violates the contract.
    pub unsafe fn map_file(file: &fs::File) -> Result<Self, MappedBlobPackError> {
        let map = unsafe {
            // SAFETY: The caller upholds the file immutability contract
            // documented on this constructor; this wrapper validates the pack
            // header before exposing any borrowed payload slices.
            ReadOnlyMmap::map_file(file)
        }
        .map_err(MappedBlobPackError::Map)?;
        Self::from_mmap(map)
    }

    /// Maps `file` after validating that `lease` covers it.
    ///
    /// The returned mapping is lifetime-bound to `lease`, so borrowed payload
    /// slices cannot outlive the lease value that upholds the file immutability
    /// contract.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if `lease` does not cover `file`, the
    /// file cannot be memory-mapped, or its packfile header is malformed.
    pub fn map_file_with_lease<'lease, L>(
        file: &fs::File,
        lease: &'lease L,
    ) -> Result<LeasedMappedBlobPack<'lease>, MappedBlobPackError>
    where
        L: BlobPackReadLease + ?Sized,
    {
        if !lease.covers_file(file) {
            return Err(MappedBlobPackError::LeaseRejected);
        }
        let pack = unsafe {
            // SAFETY: `BlobPackReadLease` is unsafe to implement, and
            // `covers_file` returning true promises that `file` remains
            // immutable for the borrowed lease lifetime. The returned wrapper
            // carries that lease lifetime, so mapped payload borrows cannot
            // outlive the lease.
            Self::map_file(file)
        }?;
        Ok(LeasedMappedBlobPack {
            pack,
            _lease: PhantomData,
        })
    }

    /// Creates a mapped blob pack from an existing read-only mapping.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if the mapping does not start with a
    /// valid blob packfile header.
    pub fn from_mmap(map: ReadOnlyMmap) -> Result<Self, MappedBlobPackError> {
        BlobPackHeader::decode(map.as_bytes()).map_err(MappedBlobPackError::Format)?;
        Ok(Self { map })
    }

    /// Returns the mapped packfile length.
    pub const fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns whether the mapped packfile is empty.
    pub const fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Reads, validates, and returns a zero-copy payload view.
    ///
    /// The record header at `location` must declare `expected_hash` and the
    /// same payload length as `location`, the declared payload window must fit
    /// inside the mapped pack, and the borrowed payload bytes must hash to
    /// `expected_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if the record offset is invalid, record
    /// metadata does not match the expected lookup, the payload window falls
    /// outside the mapping, or the payload bytes do not hash to
    /// `expected_hash`.
    pub fn payload(
        &self,
        location: BlobPackLocation,
        expected_hash: BlobPackHash,
    ) -> Result<MappedBlobPayload<'_>, MappedBlobPackError> {
        let record = self.record_header(location)?;
        if record.hash() != expected_hash {
            return Err(MappedBlobPackError::RecordHashMismatch {
                expected: expected_hash,
                actual: record.hash(),
            });
        }
        if record.payload_len() != location.payload_len() {
            return Err(MappedBlobPackError::RecordLengthMismatch {
                expected: location.payload_len(),
                actual: record.payload_len(),
            });
        }
        let range = self.payload_range(location, record.payload_len())?;
        let bytes =
            self.map
                .get(range)
                .ok_or_else(|| MappedBlobPackError::RecordExtendsPastEnd {
                    payload_end: payload_end_for_error(location, record.payload_len()),
                    pack_len: self.map.len() as u128,
                })?;
        let actual = BlobPackHash::for_bytes(bytes);
        if actual != expected_hash {
            return Err(MappedBlobPackError::PayloadHashMismatch {
                expected: expected_hash,
                actual,
            });
        }
        Ok(MappedBlobPayload {
            hash: expected_hash,
            location,
            bytes,
        })
    }

    /// Returns all verified blob records in packfile order.
    ///
    /// The scan validates each record header, checks payload bounds, hashes each
    /// mapped payload, and returns only record metadata. It is intended for
    /// read-only index rebuild and maintenance paths that need physical pack
    /// contents without copying payloads out of the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if any record header is malformed or
    /// truncated, if any payload window falls outside the mapping, or if any
    /// payload bytes do not hash to the record's declared content address.
    pub fn records(&self) -> Result<Vec<BlobPackRecord>, MappedBlobPackError> {
        let mut offset = BLOB_PACK_HEADER_LEN as u64;
        let mut records = Vec::new();
        while u128::from(offset) < self.map.len() as u128 {
            let header = self.record_header(BlobPackLocation::new(offset, 0))?;
            let location = BlobPackLocation::new(offset, header.payload_len());
            let range = self.payload_range(location, header.payload_len())?;
            let bytes =
                self.map
                    .get(range)
                    .ok_or_else(|| MappedBlobPackError::RecordExtendsPastEnd {
                        payload_end: payload_end_for_error(location, header.payload_len()),
                        pack_len: self.map.len() as u128,
                    })?;
            let actual = BlobPackHash::for_bytes(bytes);
            if actual != header.hash() {
                return Err(MappedBlobPackError::PayloadHashMismatch {
                    expected: header.hash(),
                    actual,
                });
            }
            records.push(BlobPackRecord::new(header.hash(), location));
            offset = payload_end_for_scan(location, header.payload_len())?;
        }
        Ok(records)
    }

    fn record_header(
        &self,
        location: BlobPackLocation,
    ) -> Result<BlobRecordHeader, MappedBlobPackError> {
        if location.record_offset() < BLOB_PACK_HEADER_LEN as u64 {
            return Err(MappedBlobPackError::InvalidRecordOffset {
                record_offset: location.record_offset(),
            });
        }
        let record_start = usize::try_from(location.record_offset()).map_err(|_| {
            MappedBlobPackError::InvalidRecordOffset {
                record_offset: location.record_offset(),
            }
        })?;
        let record_end_u64 = location
            .record_offset()
            .checked_add(BLOB_RECORD_HEADER_LEN as u64)
            .ok_or(MappedBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: location.payload_len(),
            })?;
        let record_end = usize::try_from(record_end_u64).map_err(|_| {
            MappedBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: location.payload_len(),
            }
        })?;
        if record_end > self.map.len() {
            return Err(BlobPackFormatError::ShortRecordHeader {
                expected: BLOB_RECORD_HEADER_LEN,
                actual: self.map.len().saturating_sub(record_start),
            }
            .into());
        }
        let bytes = self.map.get(record_start..record_end).ok_or_else(|| {
            BlobPackFormatError::ShortRecordHeader {
                expected: BLOB_RECORD_HEADER_LEN,
                actual: self.map.len().saturating_sub(record_start),
            }
        })?;
        BlobRecordHeader::decode(bytes).map_err(MappedBlobPackError::Format)
    }

    fn payload_range(
        &self,
        location: BlobPackLocation,
        payload_len: u64,
    ) -> Result<Range<usize>, MappedBlobPackError> {
        let payload_start = location
            .record_offset()
            .checked_add(BLOB_RECORD_HEADER_LEN as u64)
            .ok_or(MappedBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len,
            })?;
        let payload_end = payload_start.checked_add(payload_len).ok_or(
            MappedBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len,
            },
        )?;
        if u128::from(payload_end) > self.map.len() as u128 {
            return Err(MappedBlobPackError::RecordExtendsPastEnd {
                payload_end: u128::from(payload_end),
                pack_len: self.map.len() as u128,
            });
        }
        let payload_start = usize::try_from(payload_start).map_err(|_| {
            MappedBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len,
            }
        })?;
        let payload_end = usize::try_from(payload_end).map_err(|_| {
            MappedBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len,
            }
        })?;
        Ok(payload_start..payload_end)
    }
}

/// A verified zero-copy payload borrowed from a mapped blob pack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappedBlobPayload<'a> {
    hash: BlobPackHash,
    location: BlobPackLocation,
    bytes: &'a [u8],
}

impl<'a> MappedBlobPayload<'a> {
    /// Returns the content address verified for this payload.
    pub const fn hash(self) -> BlobPackHash {
        self.hash
    }

    /// Returns this payload's record location.
    pub const fn location(self) -> BlobPackLocation {
        self.location
    }

    /// Returns the verified payload bytes borrowed from the mapping.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

fn blob_pack_paths_alias(source_path: &Path, tmp_path: &Path) -> bool {
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

fn payload_end_for_error(location: BlobPackLocation, payload_len: u64) -> u128 {
    u128::from(location.record_offset())
        + u128::from(BLOB_RECORD_HEADER_LEN as u64)
        + u128::from(payload_len)
}

fn payload_end_for_scan(
    location: BlobPackLocation,
    payload_len: u64,
) -> Result<u64, MappedBlobPackError> {
    location
        .record_offset()
        .checked_add(BLOB_RECORD_HEADER_LEN as u64)
        .and_then(|payload_start| payload_start.checked_add(payload_len))
        .ok_or(MappedBlobPackError::RecordBoundsOverflow {
            record_offset: location.record_offset(),
            payload_len,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const FROZEN_EMPTY_BLOB_PACK: [u8; BLOB_PACK_HEADER_LEN + BLOB_RECORD_HEADER_LEN] = [
        b'A', b'O', b'S', b'-', b'N', b'I', b'X', b'-', b'B', b'L', b'O', b'B', b'P', b'A', b'C',
        b'K', 1, 0, 0, 0, 24, 0, 0, 0, 0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40,
        0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc,
        0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    struct FrozenTestLease;

    // SAFETY: Tests only use this lease after writing a temporary pack fully
    // and perform no mutation until after the leased mapping is dropped.
    unsafe impl BlobPackReadLease for FrozenTestLease {
        fn covers_file(&self, _file: &fs::File) -> bool {
            true
        }
    }

    struct RejectingTestLease;

    // SAFETY: This lease never covers any file, so it never asserts an
    // immutability guarantee.
    unsafe impl BlobPackReadLease for RejectingTestLease {
        fn covers_file(&self, _file: &fs::File) -> bool {
            false
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ratchet-cache-blob-pack-{name}-{}-{nonce}.tmp",
            std::process::id()
        ))
    }

    fn write_pack(path: &PathBuf, records: &[&[u8]]) -> Vec<BlobPackLocation> {
        let mut file = fs::File::create(path).expect("pack file creates");
        file.write_all(&BlobPackHeader::current().encode())
            .expect("pack header writes");
        let mut offset = BLOB_PACK_HEADER_LEN as u64;
        let mut locations = Vec::new();
        for payload in records {
            let hash = BlobPackHash::for_bytes(payload);
            let payload_len = u64::try_from(payload.len()).expect("payload length fits");
            file.write_all(&BlobRecordHeader::new(hash, payload_len).encode())
                .expect("record header writes");
            file.write_all(payload).expect("payload writes");
            locations.push(BlobPackLocation::new(offset, payload_len));
            offset += BLOB_RECORD_HEADER_LEN as u64 + payload_len;
        }
        file.sync_all().expect("pack file syncs");
        locations
    }

    fn map_pack(path: &PathBuf) -> MappedBlobPack {
        let file = fs::File::open(path).expect("pack opens read-only");
        unsafe {
            // SAFETY: Each test writes the pack completely before mapping and
            // performs no mutation until after the mapping is dropped.
            MappedBlobPack::map_file(&file)
        }
        .expect("pack maps")
    }

    #[test]
    fn blob_pack_appender_open_initializes_header() {
        let root = temp_path("appender-open-root");
        let path = root.join("values").join("pack.blob");
        let appender = BlobPackAppender::open(path.clone()).expect("appender opens");

        assert_eq!(appender.path(), path.as_path());
        assert_eq!(
            fs::read(&path).expect("pack header reads").as_slice(),
            BlobPackHeader::current().encode().as_slice()
        );
        assert_eq!(
            appender.len().expect("pack length reads"),
            BLOB_PACK_HEADER_LEN as u64
        );
        assert!(!appender.is_empty().expect("pack emptiness reads"));
        BlobPackAppender::open(path.clone()).expect("initialized appender reopens");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn blob_pack_appender_rejects_corrupt_header_without_rewriting() {
        let root = temp_path("appender-corrupt-root");
        let path = root.join("values").join("pack.blob");
        fs::create_dir_all(path.parent().expect("pack parent exists")).expect("parent creates");
        fs::write(&path, b"bad").expect("corrupt pack writes");

        let error = BlobPackAppender::open(path.clone()).expect_err("corrupt pack errors");

        assert!(matches!(
            error,
            BlobPackAppendError::Format {
                source: BlobPackFormatError::ShortPackHeader { actual: 3, .. },
                ..
            }
        ));
        assert_eq!(
            fs::read(&path).expect("corrupt pack reads").as_slice(),
            b"bad"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn blob_pack_appender_appends_mapped_payloads() {
        let path = temp_path("appender-payloads");
        let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
        let first = b"first payload".as_slice();
        let second = b"second payload".as_slice();
        let first_hash = BlobPackHash::for_bytes(first);
        let second_hash = BlobPackHash::for_bytes(second);

        let first_location = appender
            .append_payload(first_hash, first)
            .expect("first payload appends");
        let second_location = appender
            .append_payload(second_hash, second)
            .expect("second payload appends");

        assert_eq!(first_location.record_offset(), BLOB_PACK_HEADER_LEN as u64);
        assert_eq!(first_location.payload_len(), first.len() as u64);
        assert_eq!(
            second_location.record_offset(),
            BLOB_PACK_HEADER_LEN as u64 + BLOB_RECORD_HEADER_LEN as u64 + first.len() as u64
        );
        assert_eq!(second_location.payload_len(), second.len() as u64);

        let pack = map_pack(&path);
        assert_eq!(
            pack.payload(first_location, first_hash)
                .expect("first mapped payload reads")
                .as_bytes(),
            first
        );
        assert_eq!(
            pack.payload(second_location, second_hash)
                .expect("second mapped payload reads")
                .as_bytes(),
            second
        );

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_appender_rejects_payload_hash_mismatch_without_appending() {
        let path = temp_path("appender-hash-mismatch");
        let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
        let payload = b"payload".as_slice();
        let wrong_hash = BlobPackHash::for_bytes(b"wrong");
        let before_len = appender.len().expect("initial pack length reads");

        let error = appender
            .append_payload(wrong_hash, payload)
            .expect_err("hash mismatch errors");

        assert!(matches!(
            error,
            BlobPackAppendError::PayloadHashMismatch { expected, actual }
                if expected == wrong_hash && actual == BlobPackHash::for_bytes(payload)
        ));
        assert_eq!(appender.len().expect("final pack length reads"), before_len);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_appender_trim_tail_removes_unneeded_records() {
        let path = temp_path("appender-trim-tail");
        let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
        let first = b"first payload".as_slice();
        let second = b"second payload".as_slice();
        let first_hash = BlobPackHash::for_bytes(first);
        let second_hash = BlobPackHash::for_bytes(second);
        let first_location = appender
            .append_payload(first_hash, first)
            .expect("first payload appends");
        let second_location = appender
            .append_payload(second_hash, second)
            .expect("second payload appends");
        let before_len = appender.len().expect("pack length reads");

        let removed = appender
            .trim_tail(second_location.record_offset())
            .expect("tail trims");

        assert_eq!(removed, before_len - second_location.record_offset());
        assert_eq!(
            appender.len().expect("trimmed pack length reads"),
            second_location.record_offset()
        );
        let reader = BlobPackReader::open(path.clone()).expect("reader opens trimmed pack");
        assert_eq!(
            reader.records().expect("trimmed records scan"),
            [BlobPackRecord::new(first_hash, first_location)]
        );
        assert_eq!(
            reader
                .read_payload(first_location, first_hash)
                .expect("retained payload reads"),
            first
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_appender_trim_tail_noops_at_current_len() {
        let path = temp_path("appender-trim-tail-noop");
        let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
        let payload = b"payload".as_slice();
        appender
            .append_payload(BlobPackHash::for_bytes(payload), payload)
            .expect("payload appends");
        let len = appender.len().expect("pack length reads");

        let removed = appender.trim_tail(len).expect("current len trim noops");

        assert_eq!(removed, 0);
        assert_eq!(appender.len().expect("final pack length reads"), len);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_appender_trim_tail_rejects_offset_before_header() {
        let path = temp_path("appender-trim-tail-before-header");
        let appender = BlobPackAppender::open(path.clone()).expect("appender opens");

        let error = appender
            .trim_tail(BLOB_PACK_HEADER_LEN as u64 - 1)
            .expect_err("offset before header errors");

        assert!(matches!(
            error,
            BlobPackTrimError::InvalidRecordOffset { record_offset }
                if record_offset == BLOB_PACK_HEADER_LEN as u64 - 1
        ));
        assert_eq!(
            appender.len().expect("final pack length reads"),
            BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_appender_trim_tail_rejects_offset_past_end() {
        let path = temp_path("appender-trim-tail-past-end");
        let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
        let len = appender.len().expect("pack length reads");

        let error = appender
            .trim_tail(len + 1)
            .expect_err("offset past end errors");

        assert!(matches!(
            error,
            BlobPackTrimError::RecordExtendsPastEnd {
                payload_end,
                pack_len,
            } if payload_end == len + 1 && pack_len == len
        ));
        assert_eq!(appender.len().expect("final pack length reads"), len);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_appender_trim_tail_rejects_corrupt_header_without_rewriting() {
        let path = temp_path("appender-trim-tail-corrupt-header");
        let appender = BlobPackAppender::open(path.clone()).expect("appender opens");
        fs::write(&path, b"bad").expect("corrupt pack writes");

        let error = appender
            .trim_tail(BLOB_PACK_HEADER_LEN as u64)
            .expect_err("corrupt header errors");

        assert!(matches!(
            error,
            BlobPackTrimError::Format {
                source: BlobPackFormatError::ShortPackHeader { actual: 3, .. },
                ..
            }
        ));
        assert_eq!(
            fs::read(&path).expect("corrupt pack reads").as_slice(),
            b"bad"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_reads_and_verifies_buffered_payloads() {
        let path = temp_path("reader-payloads");
        let first = b"first payload".as_slice();
        let second = b"second payload".as_slice();
        let locations = write_pack(&path, &[first, second]);
        let first_hash = BlobPackHash::for_bytes(first);
        let second_hash = BlobPackHash::for_bytes(second);
        let reader = BlobPackReader::open(path.clone()).expect("reader opens");

        assert_eq!(reader.path(), path.as_path());
        assert_eq!(
            reader.len().expect("reader length reads"),
            BLOB_PACK_HEADER_LEN as u64
                + (BLOB_RECORD_HEADER_LEN as u64 * 2)
                + first.len() as u64
                + second.len() as u64
        );
        assert!(!reader.is_empty().expect("reader emptiness reads"));
        assert_eq!(
            reader.records().expect("records scan"),
            [
                BlobPackRecord::new(first_hash, locations[0]),
                BlobPackRecord::new(second_hash, locations[1]),
            ]
        );

        let window = reader
            .payload_window(locations[0], first_hash)
            .expect("payload window reads");
        assert_eq!(
            window.record(),
            BlobPackRecord::new(first_hash, locations[0])
        );
        assert_eq!(
            window.payload_range(),
            locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64
                ..locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64 + first.len() as u64
        );
        assert_eq!(
            reader
                .verify_payload(locations[0], first_hash)
                .expect("payload verifies"),
            window
        );
        assert!(
            reader
                .payload_matches(locations[0], first_hash, first)
                .expect("payload match reads")
        );
        assert!(
            !reader
                .payload_matches(locations[0], first_hash, b"first payloae")
                .expect("payload mismatch reads")
        );
        assert!(
            !reader
                .payload_matches(locations[0], first_hash, b"short")
                .expect("payload length mismatch reads")
        );
        assert_eq!(
            reader
                .read_payload(locations[1], second_hash)
                .expect("payload reads"),
            second
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_writes_relocated_records_to_temp_pack() {
        let path = temp_path("reader-relocated-source");
        let tmp_path = temp_path("reader-relocated-temp");
        let first = b"first payload".as_slice();
        let stale = b"stale payload".as_slice();
        let second = b"second payload".as_slice();
        let locations = write_pack(&path, &[first, stale, second]);
        fs::write(&tmp_path, b"stale temp").expect("stale temp writes");
        let first_hash = BlobPackHash::for_bytes(first);
        let stale_hash = BlobPackHash::for_bytes(stale);
        let second_hash = BlobPackHash::for_bytes(second);
        let relocated_first =
            BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, first.len() as u64);
        let relocated_second = BlobPackLocation::new(
            BLOB_PACK_HEADER_LEN as u64 + BLOB_RECORD_HEADER_LEN as u64 + first.len() as u64,
            second.len() as u64,
        );
        let relocations = [
            BlobPackRecordRelocation::new(first_hash, locations[0], relocated_first),
            BlobPackRecordRelocation::new(second_hash, locations[2], relocated_second),
        ];
        let reader = BlobPackReader::open(path.clone()).expect("reader opens");

        let rewritten = reader
            .write_relocated_records_to(tmp_path.clone(), &relocations)
            .expect("records relocate");

        assert_eq!(rewritten.path(), tmp_path.as_path());
        assert_eq!(
            rewritten.records().expect("rewritten records scan"),
            [
                BlobPackRecord::new(first_hash, relocated_first),
                BlobPackRecord::new(second_hash, relocated_second),
            ]
        );
        assert_eq!(
            rewritten
                .read_payload(relocated_first, first_hash)
                .expect("relocated first reads"),
            first
        );
        assert_eq!(
            rewritten
                .read_payload(relocated_second, second_hash)
                .expect("relocated second reads"),
            second
        );
        assert_eq!(
            reader
                .read_payload(locations[1], stale_hash)
                .expect("source stale record remains"),
            stale
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(tmp_path);
    }

    #[test]
    fn blob_pack_reader_relocation_rejects_source_as_temp_path() {
        let path = temp_path("reader-relocation-source-as-temp");
        let payload = b"payload".as_slice();
        let locations = write_pack(&path, &[payload]);
        let hash = BlobPackHash::for_bytes(payload);
        let relocation = BlobPackRecordRelocation::new(
            hash,
            locations[0],
            BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, payload.len() as u64),
        );
        let reader = BlobPackReader::open(path.clone()).expect("reader opens");

        let error = reader
            .write_relocated_records_to(path.clone(), &[relocation])
            .expect_err("source path as temp errors");

        assert!(matches!(
            error,
            BlobPackRewriteError::SourceEqualsTemp { source_path, tmp_path }
                if source_path == path && tmp_path == path
        ));
        assert_eq!(
            reader
                .read_payload(locations[0], hash)
                .expect("source remains readable after exact rejection"),
            payload
        );

        let alias_path = path
            .parent()
            .expect("pack parent exists")
            .join(".")
            .join(path.file_name().expect("pack file name exists"));
        let error = reader
            .write_relocated_records_to(alias_path.clone(), &[relocation])
            .expect_err("source alias as temp errors");
        assert!(matches!(
            error,
            BlobPackRewriteError::SourceEqualsTemp { source_path, tmp_path }
                if source_path == path && tmp_path == alias_path
        ));
        assert_eq!(
            reader
                .read_payload(locations[0], hash)
                .expect("source remains readable after alias rejection"),
            payload
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_relocation_cleans_temp_on_location_mismatch() {
        let path = temp_path("reader-relocation-mismatch-source");
        let tmp_path = temp_path("reader-relocation-mismatch-temp");
        let payload = b"payload".as_slice();
        let locations = write_pack(&path, &[payload]);
        let hash = BlobPackHash::for_bytes(payload);
        let wrong_location =
            BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64 + 1, payload.len() as u64);
        let relocations = [BlobPackRecordRelocation::new(
            hash,
            locations[0],
            wrong_location,
        )];
        let reader = BlobPackReader::open(path.clone()).expect("reader opens");

        let error = reader
            .write_relocated_records_to(tmp_path.clone(), &relocations)
            .expect_err("mismatched location errors");

        assert!(matches!(
            error,
            BlobPackRewriteError::RecordLocationMismatch { expected, actual }
                if expected == wrong_location
                    && actual == BlobPackLocation::new(
                        BLOB_PACK_HEADER_LEN as u64,
                        payload.len() as u64
                    )
        ));
        assert!(!tmp_path.exists());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_relocation_cleans_temp_on_corrupt_source() {
        let path = temp_path("reader-relocation-corrupt-source");
        let tmp_path = temp_path("reader-relocation-corrupt-temp");
        let payload = b"payload".as_slice();
        let locations = write_pack(&path, &[payload]);
        let hash = BlobPackHash::for_bytes(payload);
        let payload_offset = locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("source opens for corruption");
        file.seek(SeekFrom::Start(payload_offset))
            .expect("payload offset seeks");
        file.write_all(b"X").expect("payload corrupts");
        file.flush().expect("payload corruption flushes");
        let relocation = BlobPackRecordRelocation::new(
            hash,
            locations[0],
            BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, payload.len() as u64),
        );
        let reader = BlobPackReader::open(path.clone()).expect("reader opens");

        let error = reader
            .write_relocated_records_to(tmp_path.clone(), &[relocation])
            .expect_err("corrupt source errors");

        assert!(matches!(
            error,
            BlobPackRewriteError::ReadSource {
                source: BlobPackReadError::PayloadHashMismatch { .. }
            }
        ));
        assert!(!tmp_path.exists());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_rejects_corrupt_header_without_rewriting() {
        let path = temp_path("reader-corrupt-header");
        fs::write(&path, b"bad").expect("corrupt pack writes");

        let error = BlobPackReader::open(path.clone()).expect_err("corrupt pack errors");

        assert!(matches!(
            error,
            BlobPackReadError::Format {
                source: BlobPackFormatError::ShortPackHeader { actual: 3, .. },
                ..
            }
        ));
        assert_eq!(
            fs::read(&path).expect("corrupt pack reads").as_slice(),
            b"bad"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_rejects_mismatched_lookup_metadata() {
        let path = temp_path("reader-mismatch");
        let payload = b"payload".as_slice();
        let locations = write_pack(&path, &[payload]);
        let reader = BlobPackReader::open(path.clone()).expect("reader opens");
        let hash = BlobPackHash::for_bytes(payload);
        let wrong_hash = BlobPackHash::for_bytes(b"other");

        assert!(matches!(
            reader
                .payload_window(locations[0], wrong_hash)
                .expect_err("wrong hash errors"),
            BlobPackReadError::RecordHashMismatch { expected, actual }
                if expected == wrong_hash && actual == hash
        ));
        assert!(matches!(
            reader
                .payload_window(BlobPackLocation::new(
                    locations[0].record_offset(),
                    locations[0].payload_len() + 1
                ), hash)
                .expect_err("wrong length errors"),
            BlobPackReadError::RecordLengthMismatch { expected, actual }
                if expected == locations[0].payload_len() + 1 && actual == locations[0].payload_len()
        ));
        assert!(matches!(
            reader
                .read_payload(BlobPackLocation::new(0, locations[0].payload_len()), hash)
                .expect_err("header offset errors"),
            BlobPackReadError::InvalidRecordOffset { record_offset: 0 }
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_rejects_short_trailing_record_header() {
        let path = temp_path("reader-short-tail");
        write_pack(&path, &[b"payload"]);
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("pack opens for corruption");
        file.write_all(b"tail").expect("tail writes");
        file.flush().expect("tail flushes");
        let reader = BlobPackReader::open(path.clone()).expect("reader opens by header");

        let error = reader.records().expect_err("short tail errors");

        assert!(matches!(
            error,
            BlobPackReadError::Format {
                source: BlobPackFormatError::ShortRecordHeader { actual: 4, .. },
                ..
            }
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_rejects_record_payload_past_end() {
        let path = temp_path("reader-past-end");
        let hash = BlobPackHash::for_bytes(b"payload");
        let mut file = fs::File::create(&path).expect("pack file creates");
        file.write_all(&BlobPackHeader::current().encode())
            .expect("pack header writes");
        file.write_all(&BlobRecordHeader::new(hash, 7).encode())
            .expect("record header writes");
        file.write_all(b"pay").expect("partial payload writes");
        file.flush().expect("partial payload flushes");
        let reader = BlobPackReader::open(path.clone()).expect("reader opens by header");

        let error = reader.records().expect_err("past-end payload errors");

        assert!(matches!(
            error,
            BlobPackReadError::RecordExtendsPastEnd {
                payload_end,
                pack_len,
            } if payload_end == BLOB_PACK_HEADER_LEN as u64 + BLOB_RECORD_HEADER_LEN as u64 + 7
                && pack_len == BLOB_PACK_HEADER_LEN as u64 + BLOB_RECORD_HEADER_LEN as u64 + 3
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_reader_rejects_corrupt_payload_bytes() {
        let path = temp_path("reader-corrupt-payload");
        let payload = b"payload".as_slice();
        let locations = write_pack(&path, &[payload]);
        let hash = BlobPackHash::for_bytes(payload);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("pack opens for corruption");
        file.seek(SeekFrom::Start(
            locations[0].record_offset() + BLOB_RECORD_HEADER_LEN as u64,
        ))
        .expect("payload offset seeks");
        file.write_all(b"X").expect("payload corrupts");
        file.flush().expect("payload corruption flushes");
        let reader = BlobPackReader::open(path.clone()).expect("reader opens by header");

        assert!(matches!(
            reader
                .records()
                .expect_err("corrupt payload scan errors"),
            BlobPackReadError::PayloadHashMismatch { expected, actual }
                if expected == hash && actual == BlobPackHash::for_bytes(b"Xayload")
        ));
        assert!(matches!(
            reader
                .read_payload(locations[0], hash)
                .expect_err("corrupt payload read errors"),
            BlobPackReadError::PayloadHashMismatch { expected, actual }
                if expected == hash && actual == BlobPackHash::for_bytes(b"Xayload")
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_reads_frozen_empty_payload_fixture() {
        let path = temp_path("frozen-empty");
        {
            let mut file = fs::File::create(&path).expect("fixture file creates");
            file.write_all(&FROZEN_EMPTY_BLOB_PACK)
                .expect("fixture bytes write");
            file.sync_all().expect("fixture file syncs");
        }
        let pack = map_pack(&path);
        let payload = pack
            .payload(
                BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, 0),
                BlobPackHash::for_bytes(b""),
            )
            .expect("frozen empty fixture payload reads");

        assert_eq!(pack.len(), FROZEN_EMPTY_BLOB_PACK.len());
        assert_eq!(payload.as_bytes(), b"");

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_with_read_lease_returns_payload_slices() {
        let path = temp_path("leased-payloads");
        let payload = b"leased payload".as_slice();
        let locations = write_pack(&path, &[payload]);
        let file = fs::File::open(&path).expect("pack opens read-only");
        let lease = FrozenTestLease;
        let pack =
            MappedBlobPack::map_file_with_lease(&file, &lease).expect("lease maps blob pack");
        let mapped_payload = pack
            .payload(locations[0], BlobPackHash::for_bytes(payload))
            .expect("leased payload reads");

        assert_eq!(pack.len(), pack.as_mapped_pack().len());
        assert_eq!(
            pack.records().expect("leased records scan"),
            [BlobPackRecord::new(
                BlobPackHash::for_bytes(payload),
                locations[0]
            )]
        );
        assert_eq!(mapped_payload.as_bytes(), payload);

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_with_read_lease_rejects_uncovered_files() {
        let path = temp_path("rejected-lease");
        write_pack(&path, &[b"payload"]);
        let file = fs::File::open(&path).expect("pack opens read-only");
        let lease = RejectingTestLease;

        let error = MappedBlobPack::map_file_with_lease(&file, &lease)
            .expect_err("uncovered file is rejected");

        assert!(matches!(error, MappedBlobPackError::LeaseRejected));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_file_identity_matches_reopened_same_file() {
        let path = temp_path("identity-same");
        write_pack(&path, &[b"payload"]);
        let file = fs::File::open(&path).expect("pack opens read-only");
        let identity = BlobPackFileIdentity::for_file(&file).expect("identity snapshots");
        let reopened = fs::File::open(&path).expect("pack reopens read-only");

        assert!(
            identity
                .matches_file(&reopened)
                .expect("same file metadata reads")
        );
        assert!(!identity.is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_pack_file_identity_rejects_different_file() {
        let left_path = temp_path("identity-left");
        let right_path = temp_path("identity-right");
        write_pack(&left_path, &[b"left"]);
        write_pack(&right_path, &[b"right"]);
        let left = fs::File::open(&left_path).expect("left pack opens read-only");
        let right = fs::File::open(&right_path).expect("right pack opens read-only");
        let identity = BlobPackFileIdentity::for_file(&left).expect("left identity snapshots");

        assert!(
            !identity
                .matches_file(&right)
                .expect("right file metadata reads")
        );

        let _ = fs::remove_file(left_path);
        let _ = fs::remove_file(right_path);
    }

    #[test]
    fn blob_pack_file_identity_rejects_changed_length() {
        let path = temp_path("identity-changed-length");
        write_pack(&path, &[b"payload"]);
        let file = fs::File::open(&path).expect("pack opens read-only");
        let identity = BlobPackFileIdentity::for_file(&file).expect("identity snapshots");
        {
            let mut append = fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("pack opens for append");
            append.write_all(b"tail").expect("tail writes");
            append.sync_all().expect("appended pack syncs");
        }

        assert!(
            !identity
                .matches_file(&file)
                .expect("changed file metadata reads")
        );
        assert_eq!(
            identity.len() + 4,
            file.metadata().expect("metadata reads").len()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_returns_verified_payload_slices() {
        let path = temp_path("payloads");
        let first = b"first payload".as_slice();
        let second = b"second payload".as_slice();
        let locations = write_pack(&path, &[first, second]);
        let pack = map_pack(&path);

        let first_payload = pack
            .payload(locations[0], BlobPackHash::for_bytes(first))
            .expect("first payload maps");
        let second_payload = pack
            .payload(locations[1], BlobPackHash::for_bytes(second))
            .expect("second payload maps");

        assert_eq!(
            pack.len(),
            BLOB_PACK_HEADER_LEN + 2 * BLOB_RECORD_HEADER_LEN + 27
        );
        assert_eq!(first_payload.hash(), BlobPackHash::for_bytes(first));
        assert_eq!(first_payload.location(), locations[0]);
        assert_eq!(first_payload.as_bytes(), first);
        assert_eq!(second_payload.as_bytes(), second);

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_scans_verified_records() {
        let path = temp_path("record-scan");
        let first = b"first payload".as_slice();
        let second = b"second payload".as_slice();
        let locations = write_pack(&path, &[first, second]);
        let pack = map_pack(&path);

        let records = pack.records().expect("records scan");

        assert_eq!(
            records,
            [
                BlobPackRecord::new(BlobPackHash::for_bytes(first), locations[0]),
                BlobPackRecord::new(BlobPackHash::for_bytes(second), locations[1]),
            ]
        );
        assert_eq!(records[0].hash(), BlobPackHash::for_bytes(first));
        assert_eq!(records[1].location(), locations[1]);

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_records_returns_empty_for_header_only_pack() {
        let path = temp_path("record-scan-empty");
        BlobPackAppender::open(path.clone()).expect("header-only pack initializes");
        let pack = map_pack(&path);

        assert!(pack.records().expect("empty records scan").is_empty());

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_rejects_wrong_lookup_hash() {
        let path = temp_path("wrong-hash");
        let payload = b"payload".as_slice();
        let locations = write_pack(&path, &[payload]);
        let pack = map_pack(&path);
        let other = BlobPackHash::for_bytes(b"other");

        let error = pack
            .payload(locations[0], other)
            .expect_err("wrong lookup hash fails");

        assert!(matches!(
            error,
            MappedBlobPackError::RecordHashMismatch { expected, actual }
                if expected == other && actual == BlobPackHash::for_bytes(payload)
        ));

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_rejects_payload_hash_mismatch() {
        let path = temp_path("payload-mismatch");
        let declared = BlobPackHash::for_bytes(b"declared");
        let actual = b"actual!!".as_slice();
        let location = BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, actual.len() as u64);
        {
            let mut file = fs::File::create(&path).expect("pack file creates");
            file.write_all(&BlobPackHeader::current().encode())
                .expect("pack header writes");
            file.write_all(&BlobRecordHeader::new(declared, actual.len() as u64).encode())
                .expect("record header writes");
            file.write_all(actual).expect("payload writes");
            file.sync_all().expect("pack file syncs");
        }
        let pack = map_pack(&path);

        let error = pack
            .payload(location, declared)
            .expect_err("payload hash mismatch fails");

        assert!(matches!(
            error,
            MappedBlobPackError::PayloadHashMismatch { expected, actual: observed }
                if expected == declared && observed == BlobPackHash::for_bytes(actual)
        ));

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_records_rejects_payload_hash_mismatch() {
        let path = temp_path("record-scan-payload-mismatch");
        let declared = BlobPackHash::for_bytes(b"declared");
        let actual = b"actual!!".as_slice();
        {
            let mut file = fs::File::create(&path).expect("pack file creates");
            file.write_all(&BlobPackHeader::current().encode())
                .expect("pack header writes");
            file.write_all(&BlobRecordHeader::new(declared, actual.len() as u64).encode())
                .expect("record header writes");
            file.write_all(actual).expect("payload writes");
            file.sync_all().expect("pack file syncs");
        }
        let pack = map_pack(&path);

        let error = pack.records().expect_err("payload hash mismatch fails");

        assert!(matches!(
            error,
            MappedBlobPackError::PayloadHashMismatch { expected, actual: observed }
                if expected == declared && observed == BlobPackHash::for_bytes(actual)
        ));

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_rejects_truncated_payload_window() {
        let path = temp_path("truncated");
        let hash = BlobPackHash::for_bytes(b"too short");
        let location = BlobPackLocation::new(BLOB_PACK_HEADER_LEN as u64, 9);
        {
            let mut file = fs::File::create(&path).expect("pack file creates");
            file.write_all(&BlobPackHeader::current().encode())
                .expect("pack header writes");
            file.write_all(&BlobRecordHeader::new(hash, 9).encode())
                .expect("record header writes");
            file.write_all(b"short").expect("payload writes");
            file.sync_all().expect("pack file syncs");
        }
        let pack = map_pack(&path);

        let error = pack
            .payload(location, hash)
            .expect_err("truncated payload fails");

        assert!(matches!(
            error,
            MappedBlobPackError::RecordExtendsPastEnd { .. }
        ));

        drop(pack);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mapped_blob_pack_records_rejects_truncated_record_tail() {
        let path = temp_path("record-scan-truncated-tail");
        {
            let mut file = fs::File::create(&path).expect("pack file creates");
            file.write_all(&BlobPackHeader::current().encode())
                .expect("pack header writes");
            file.write_all(b"bad").expect("truncated tail writes");
            file.sync_all().expect("pack file syncs");
        }
        let pack = map_pack(&path);

        let error = pack.records().expect_err("truncated record tail fails");

        assert!(matches!(
            error,
            MappedBlobPackError::Format(BlobPackFormatError::ShortRecordHeader { actual: 3, .. })
        ));

        drop(pack);
        let _ = fs::remove_file(path);
    }
}
