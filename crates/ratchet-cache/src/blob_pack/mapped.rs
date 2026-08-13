//! Memory-mapped zero-copy reads for immutable blob packfiles.

use std::fs;
use std::marker::PhantomData;
use std::ops::Range;

use super::locking::{BlobPackFileLockMode, lock_blob_pack_file, unlock_blob_pack_file};
use super::{
    BLOB_PACK_HEADER_LEN, BLOB_RECORD_HEADER_LEN, BlobPackFileIdentity, BlobPackFormatError,
    BlobPackHash, BlobPackHeader, BlobPackLocation, BlobPackPayloadWindow, BlobPackReadLeaseError,
    BlobPackRecord, BlobRecordHeader, MappedBlobPackError,
};
use crate::store::ReadOnlyMmap;

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

/// A blob-pack read lease backed by a shared packfile advisory lock.
///
/// The lease acquires a shared descriptor lock on the packfile itself, records
/// the descriptor's Unix file identity, and validates that the descriptor being
/// mapped still matches that identity before allowing a borrowed mapping. Safe
/// `ratchet-cache` packfile writers acquire the corresponding exclusive
/// descriptor lock before initializing, appending, or trimming packfiles.
#[derive(Debug)]
pub struct BlobPackFileReadLease<'lease> {
    file: &'lease fs::File,
    identity: BlobPackFileIdentity,
}

impl<'lease> BlobPackFileReadLease<'lease> {
    /// Creates a read lease for `file`.
    ///
    /// The returned lease holds a shared advisory lock on `file`. Safe
    /// blob-pack writer APIs in this crate acquire the corresponding exclusive
    /// lock before mutating the file.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackReadLeaseError`] if the shared descriptor lock cannot
    /// be acquired or the file identity cannot be read.
    pub fn new(file: &'lease fs::File) -> Result<Self, BlobPackReadLeaseError> {
        lock_blob_pack_file(file, BlobPackFileLockMode::Shared)
            .map_err(|source| BlobPackReadLeaseError::Lock { source })?;
        let identity = BlobPackFileIdentity::for_file(file)
            .map_err(|source| BlobPackReadLeaseError::Identity { source })?;
        Ok(Self { file, identity })
    }
}

impl Drop for BlobPackFileReadLease<'_> {
    fn drop(&mut self) {
        unlock_blob_pack_file(self.file);
    }
}

// SAFETY: `BlobPackFileReadLease::new` holds a shared descriptor lock on the
// packfile itself and records the exact file identity opened under that lock.
// `covers_file` only accepts descriptors that still match that identity. Safe
// packfile writers in this crate acquire the corresponding exclusive descriptor
// lock before mutation; non-cooperating raw filesystem mutation is outside this
// blob-pack API's protocol.
unsafe impl BlobPackReadLease for BlobPackFileReadLease<'_> {
    fn covers_file(&self, file: &fs::File) -> bool {
        matches!(self.identity.matches_file(file), Ok(true))
    }
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

    /// Validates record metadata and returns the mapped payload byte window.
    ///
    /// This checks the record header, lookup hash, declared length, and mapped
    /// pack bounds, but does not read or hash the payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if the record offset is invalid, record
    /// metadata does not match the expected lookup, or the payload window falls
    /// outside the mapping.
    pub fn payload_window(
        &self,
        location: BlobPackLocation,
        expected_hash: BlobPackHash,
    ) -> Result<BlobPackPayloadWindow, MappedBlobPackError> {
        self.pack.payload_window(location, expected_hash)
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

    /// Validates record metadata and returns this payload's mapped byte window.
    ///
    /// The record header at `location` must declare `expected_hash` and the
    /// same payload length as `location`, and the declared payload window must
    /// fit inside the mapped pack. This is a metadata-only helper: it does not
    /// read or hash payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MappedBlobPackError`] if the record offset is invalid, record
    /// metadata does not match the expected lookup, or the payload window falls
    /// outside the mapping.
    pub fn payload_window(
        &self,
        location: BlobPackLocation,
        expected_hash: BlobPackHash,
    ) -> Result<BlobPackPayloadWindow, MappedBlobPackError> {
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
        let payload_start =
            u64::try_from(range.start).map_err(|_| MappedBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: record.payload_len(),
            })?;
        let payload_end =
            u64::try_from(range.end).map_err(|_| MappedBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: record.payload_len(),
            })?;
        Ok(BlobPackPayloadWindow::new(
            BlobPackRecord::new(expected_hash, location),
            payload_start,
            payload_end,
        ))
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
