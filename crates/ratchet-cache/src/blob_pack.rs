//! Memory-mapped content-addressed blob packfiles.
//!
//! RFC-0007 stores immutable `values/` and `files/` payloads in append-only
//! packfiles. This module validates the stable pack header and record format
//! from a read-only mapping, then returns borrowed payload bytes without
//! copying them into an intermediate buffer.

use std::fmt;
use std::fs;
use std::ops::Range;

use thiserror::Error;

use crate::store::{ReadOnlyMmap, ReadOnlyMmapError};

/// The fixed magic bytes at the start of every blob packfile.
pub const BLOB_PACK_MAGIC: [u8; 16] = *b"AOS-NIX-BLOBPACK";
/// The current blob packfile format version.
pub const BLOB_PACK_VERSION: u32 = 1;
/// The encoded length of a blob packfile header.
pub const BLOB_PACK_HEADER_LEN: usize = 24;
/// The encoded length of one blob record header.
pub const BLOB_RECORD_HEADER_LEN: usize = 40;

/// A BLAKE3 digest used as a blob pack content address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobPackHash([u8; 32]);

impl BlobPackHash {
    /// Computes the BLAKE3 content address for `bytes`.
    pub fn for_bytes(bytes: &[u8]) -> Self {
        Self::from_bytes(*blake3::hash(bytes).as_bytes())
    }

    /// Wraps raw BLAKE3 digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32-byte digest.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for BlobPackHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The fixed header for an immutable blob packfile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPackHeader {
    version: u32,
}

impl BlobPackHeader {
    /// Returns the current blob packfile header.
    pub const fn current() -> Self {
        Self {
            version: BLOB_PACK_VERSION,
        }
    }

    /// Returns the blob packfile format version.
    pub const fn version(self) -> u32 {
        self.version
    }

    /// Encodes the header as stable little-endian bytes.
    pub fn encode(self) -> [u8; BLOB_PACK_HEADER_LEN] {
        let mut bytes = [0; BLOB_PACK_HEADER_LEN];
        bytes[..16].copy_from_slice(&BLOB_PACK_MAGIC);
        bytes[16..20].copy_from_slice(&self.version.to_le_bytes());
        bytes[20..24].copy_from_slice(&(BLOB_PACK_HEADER_LEN as u32).to_le_bytes());
        bytes
    }

    /// Decodes and validates a blob packfile header prefix.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackFormatError`] if `bytes` is shorter than
    /// [`BLOB_PACK_HEADER_LEN`], has the wrong magic bytes, declares an
    /// unsupported version, or declares an unexpected header length.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlobPackFormatError> {
        if bytes.len() < BLOB_PACK_HEADER_LEN {
            return Err(BlobPackFormatError::ShortPackHeader {
                expected: BLOB_PACK_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let mut magic = [0; 16];
        magic.copy_from_slice(&bytes[..16]);
        if magic != BLOB_PACK_MAGIC {
            return Err(BlobPackFormatError::InvalidPackMagic { actual: magic });
        }

        let version = read_u32(&bytes[16..20]);
        if version != BLOB_PACK_VERSION {
            return Err(BlobPackFormatError::UnsupportedPackVersion { version });
        }

        let header_len = read_u32(&bytes[20..24]);
        if header_len as usize != BLOB_PACK_HEADER_LEN {
            return Err(BlobPackFormatError::InvalidPackHeaderLength { header_len });
        }

        Ok(Self { version })
    }
}

/// The fixed header for one blob record in a packfile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobRecordHeader {
    hash: BlobPackHash,
    payload_len: u64,
}

impl BlobRecordHeader {
    /// Creates a blob record header for `hash` and `payload_len`.
    pub const fn new(hash: BlobPackHash, payload_len: u64) -> Self {
        Self { hash, payload_len }
    }

    /// Returns the content address declared by this record.
    pub const fn hash(self) -> BlobPackHash {
        self.hash
    }

    /// Returns the number of payload bytes following this record header.
    pub const fn payload_len(self) -> u64 {
        self.payload_len
    }

    /// Encodes the record header as stable little-endian bytes.
    pub fn encode(self) -> [u8; BLOB_RECORD_HEADER_LEN] {
        let mut bytes = [0; BLOB_RECORD_HEADER_LEN];
        bytes[..32].copy_from_slice(&self.hash.as_bytes());
        bytes[32..40].copy_from_slice(&self.payload_len.to_le_bytes());
        bytes
    }

    /// Decodes a blob record header prefix.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackFormatError::ShortRecordHeader`] if `bytes` is
    /// shorter than [`BLOB_RECORD_HEADER_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, BlobPackFormatError> {
        if bytes.len() < BLOB_RECORD_HEADER_LEN {
            return Err(BlobPackFormatError::ShortRecordHeader {
                expected: BLOB_RECORD_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[..32]);
        Ok(Self {
            hash: BlobPackHash::from_bytes(hash),
            payload_len: read_u64(&bytes[32..40]),
        })
    }
}

/// A byte range for one immutable blob record in a packfile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPackLocation {
    record_offset: u64,
    payload_len: u64,
}

impl BlobPackLocation {
    /// Creates a blob location from its record offset and payload length.
    pub const fn new(record_offset: u64, payload_len: u64) -> Self {
        Self {
            record_offset,
            payload_len,
        }
    }

    /// Returns the byte offset where this record's header starts.
    pub const fn record_offset(self) -> u64 {
        self.record_offset
    }

    /// Returns the payload length declared by the lookup index.
    pub const fn payload_len(self) -> u64 {
        self.payload_len
    }
}

/// A memory-mapped immutable blob packfile.
#[derive(Debug)]
pub struct MappedBlobPack {
    map: ReadOnlyMmap,
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

/// Blob packfile format validation failed.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum BlobPackFormatError {
    /// The mapped file is too short to hold a packfile header.
    #[error("blob pack header is shorter than {expected} bytes: {actual}")]
    ShortPackHeader {
        /// The expected header length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// The packfile magic bytes do not match the supported format.
    #[error("invalid blob pack magic bytes")]
    InvalidPackMagic {
        /// The observed magic bytes.
        actual: [u8; 16],
    },
    /// The packfile version is unsupported.
    #[error("unsupported blob pack version {version}")]
    UnsupportedPackVersion {
        /// The observed version.
        version: u32,
    },
    /// The packfile header length field does not match this decoder.
    #[error("invalid blob pack header length {header_len}")]
    InvalidPackHeaderLength {
        /// The observed header length.
        header_len: u32,
    },
    /// The mapped file is too short to hold a complete record header.
    #[error("blob record header is shorter than {expected} bytes: {actual}")]
    ShortRecordHeader {
        /// The expected record header length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
}

/// A memory-mapped blob pack operation failed.
#[derive(Debug, Error)]
pub enum MappedBlobPackError {
    /// Memory mapping failed.
    #[error("failed to map blob pack")]
    Map(#[source] ReadOnlyMmapError),
    /// Blob pack bytes have an invalid format.
    #[error(transparent)]
    Format(#[from] BlobPackFormatError),
    /// The record offset points into the pack header.
    #[error("invalid blob record offset {record_offset}")]
    InvalidRecordOffset {
        /// The invalid record offset.
        record_offset: u64,
    },
    /// Record offset plus payload length cannot be represented.
    #[error(
        "blob record bounds overflow at offset {record_offset} with payload length {payload_len}"
    )]
    RecordBoundsOverflow {
        /// The record offset.
        record_offset: u64,
        /// The payload length.
        payload_len: u64,
    },
    /// The record payload window extends past the mapped pack.
    #[error("blob record payload ends at {payload_end}, past pack length {pack_len}")]
    RecordExtendsPastEnd {
        /// The byte offset one past the payload end.
        payload_end: u128,
        /// The mapped pack length.
        pack_len: u128,
    },
    /// The record header declares a different hash from the lookup key.
    #[error("blob record hash mismatch: expected {expected}, got {actual}")]
    RecordHashMismatch {
        /// The expected content address.
        expected: BlobPackHash,
        /// The content address declared by the record header.
        actual: BlobPackHash,
    },
    /// The record header declares a different payload length from the lookup.
    #[error("blob record length mismatch: expected {expected}, got {actual}")]
    RecordLengthMismatch {
        /// The expected payload length.
        expected: u64,
        /// The payload length declared by the record header.
        actual: u64,
    },
    /// The payload bytes do not hash to the expected content address.
    #[error("blob payload hash mismatch: expected {expected}, got {actual}")]
    PayloadHashMismatch {
        /// The expected content address.
        expected: BlobPackHash,
        /// The hash computed from the mapped payload bytes.
        actual: BlobPackHash,
    },
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(bytes);
    u32::from_le_bytes(value)
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(bytes);
    u64::from_le_bytes(value)
}

fn payload_end_for_error(location: BlobPackLocation, payload_len: u64) -> u128 {
    u128::from(location.record_offset())
        + u128::from(BLOB_RECORD_HEADER_LEN as u64)
        + u128::from(payload_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    const FROZEN_EMPTY_BLOB_PACK: [u8; BLOB_PACK_HEADER_LEN + BLOB_RECORD_HEADER_LEN] = [
        b'A', b'O', b'S', b'-', b'N', b'I', b'X', b'-', b'B', b'L', b'O', b'B', b'P', b'A', b'C',
        b'K', 1, 0, 0, 0, 24, 0, 0, 0, 0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40,
        0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc,
        0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

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
}
