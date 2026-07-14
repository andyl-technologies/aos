//! Stable wire-format value types for blob packfiles.

use std::fmt;
use std::fs;
use std::ops::Range;
use std::os::unix::fs::MetadataExt;

use super::errors::{BlobPackFileIdentityError, BlobPackFormatError};

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

/// High 16 bytes stamped into every xxh128 content address (must match the
/// evaluator cache's `XXH128_FAMILY_TAG` so a cache key equals its blob-pack
/// verify digest for the same payload under the experiment family).
const XXH128_FAMILY_TAG: [u8; 16] = *b"aos-nix-xxh128\0\0";

/// Returns whether the `AOS_NIX_CACHE_HASH=xxh128` populate-hash experiment is
/// selected. Read once for the process; BLAKE3 is the default.
fn use_xxh128_content_hash() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("AOS_NIX_CACHE_HASH")
            .map(|value| {
                value.eq_ignore_ascii_case("xxh128") || value.eq_ignore_ascii_case("xxh3-128")
            })
            .unwrap_or(false)
    })
}

impl BlobPackHash {
    /// Computes the content address for `bytes` under the process hash family.
    ///
    /// BLAKE3 by default; under `AOS_NIX_CACHE_HASH=xxh128` the address is the
    /// little-endian xxh3-128 digest in the low 16 bytes and [`XXH128_FAMILY_TAG`]
    /// in the high 16, matching the evaluator cache's key derivation so a record's
    /// key equals this verify digest for the same payload.
    pub fn for_bytes(bytes: &[u8]) -> Self {
        if use_xxh128_content_hash() {
            let mut out = [0u8; 32];
            out[..16].copy_from_slice(&xxhash_rust::xxh3::xxh3_128(bytes).to_le_bytes());
            out[16..].copy_from_slice(&XXH128_FAMILY_TAG);
            Self(out)
        } else {
            Self::from_bytes(*blake3::hash(bytes).as_bytes())
        }
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

/// Verified metadata for one immutable blob-pack record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPackRecord {
    hash: BlobPackHash,
    location: BlobPackLocation,
}

impl BlobPackRecord {
    pub(super) const fn new(hash: BlobPackHash, location: BlobPackLocation) -> Self {
        Self { hash, location }
    }

    /// Returns the content address declared and verified for this record.
    pub const fn hash(self) -> BlobPackHash {
        self.hash
    }

    /// Returns this record's byte location in the packfile.
    pub const fn location(self) -> BlobPackLocation {
        self.location
    }
}

/// A planned relocation of one verified blob-pack record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPackRecordRelocation {
    hash: BlobPackHash,
    old_location: BlobPackLocation,
    new_location: BlobPackLocation,
}

impl BlobPackRecordRelocation {
    /// Creates a planned relocation for `hash`.
    pub const fn new(
        hash: BlobPackHash,
        old_location: BlobPackLocation,
        new_location: BlobPackLocation,
    ) -> Self {
        Self {
            hash,
            old_location,
            new_location,
        }
    }

    /// Returns the content address that must verify at both locations.
    pub const fn hash(self) -> BlobPackHash {
        self.hash
    }

    /// Returns the source record location in the current pack.
    pub const fn old_location(self) -> BlobPackLocation {
        self.old_location
    }

    /// Returns the expected destination record location in the compacted pack.
    pub const fn new_location(self) -> BlobPackLocation {
        self.new_location
    }
}

/// A verified byte window for one blob-pack payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPackPayloadWindow {
    record: BlobPackRecord,
    payload_start: u64,
    payload_end: u64,
}

impl BlobPackPayloadWindow {
    pub(super) const fn new(record: BlobPackRecord, payload_start: u64, payload_end: u64) -> Self {
        Self {
            record,
            payload_start,
            payload_end,
        }
    }

    /// Returns the record metadata that owns this payload window.
    pub const fn record(self) -> BlobPackRecord {
        self.record
    }

    /// Returns the content address declared by this record.
    pub const fn hash(self) -> BlobPackHash {
        self.record.hash()
    }

    /// Returns this record's byte location in the packfile.
    pub const fn location(self) -> BlobPackLocation {
        self.record.location()
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
    pub fn payload_range(self) -> Range<u64> {
        self.payload_start..self.payload_end
    }
}

/// A Unix file-identity snapshot for a blob pack descriptor.
///
/// This identity records the device, inode, size, modification time, and
/// change time observed through an already-opened file descriptor. It is useful
/// for detecting that a later descriptor no longer refers to the same stable
/// pack bytes, but it is not an immutability guarantee by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPackFileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_secs: i64,
    mtime_nanos: i64,
    ctime_secs: i64,
    ctime_nanos: i64,
}

impl BlobPackFileIdentity {
    /// Snapshots the current identity of `file`.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackFileIdentityError`] if file metadata cannot be read or
    /// if `file` does not refer to a regular file.
    pub fn for_file(file: &fs::File) -> Result<Self, BlobPackFileIdentityError> {
        let metadata = file
            .metadata()
            .map_err(BlobPackFileIdentityError::Metadata)?;
        Self::from_metadata(&metadata)
    }

    /// Returns whether `file` still has the same observed identity.
    ///
    /// # Errors
    ///
    /// Returns [`BlobPackFileIdentityError`] if file metadata cannot be read or
    /// if `file` does not refer to a regular file.
    pub fn matches_file(self, file: &fs::File) -> Result<bool, BlobPackFileIdentityError> {
        Ok(Self::for_file(file)? == self)
    }

    /// Returns the Unix device id recorded for the file.
    pub const fn dev(self) -> u64 {
        self.dev
    }

    /// Returns the Unix inode recorded for the file.
    pub const fn ino(self) -> u64 {
        self.ino
    }

    /// Returns the file length recorded for the file.
    pub const fn len(self) -> u64 {
        self.len
    }

    /// Returns whether the recorded file length is zero.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the recorded Unix modification timestamp seconds.
    pub const fn mtime_secs(self) -> i64 {
        self.mtime_secs
    }

    /// Returns the recorded Unix modification timestamp nanoseconds.
    pub const fn mtime_nanos(self) -> i64 {
        self.mtime_nanos
    }

    /// Returns the recorded Unix change timestamp seconds.
    pub const fn ctime_secs(self) -> i64 {
        self.ctime_secs
    }

    /// Returns the recorded Unix change timestamp nanoseconds.
    pub const fn ctime_nanos(self) -> i64 {
        self.ctime_nanos
    }

    fn from_metadata(metadata: &fs::Metadata) -> Result<Self, BlobPackFileIdentityError> {
        if !metadata.is_file() {
            return Err(BlobPackFileIdentityError::NotRegularFile);
        }

        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mtime_secs: metadata.mtime(),
            mtime_nanos: metadata.mtime_nsec(),
            ctime_secs: metadata.ctime(),
            ctime_nanos: metadata.ctime_nsec(),
        })
    }
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
