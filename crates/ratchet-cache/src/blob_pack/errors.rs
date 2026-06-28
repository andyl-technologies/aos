//! Error types reported by blob pack operations.

use std::path::PathBuf;

use thiserror::Error;

use super::{BlobPackHash, BlobPackLocation};
use crate::store::ReadOnlyMmapError;

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
    /// The supplied lease does not cover the file being mapped.
    #[error("blob pack read lease does not cover the mapped file")]
    LeaseRejected,
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

/// A buffered blob pack read operation failed.
#[derive(Debug, Error)]
pub enum BlobPackReadError {
    /// The packfile could not be opened.
    #[error("failed to open blob pack {path:?}")]
    Open {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// File metadata could not be read.
    #[error("failed to read blob pack metadata for {path:?}")]
    Metadata {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be seeked.
    #[error("failed to seek blob pack {path:?}")]
    Seek {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be read.
    #[error("failed to read blob pack {path:?}")]
    Read {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile header or record metadata is invalid.
    #[error("invalid blob pack format in {path:?}")]
    Format {
        /// The packfile path.
        path: PathBuf,
        /// The format error.
        #[source]
        source: BlobPackFormatError,
    },
    /// The record offset points before the initialized pack header.
    #[error("invalid blob record offset {record_offset}")]
    InvalidRecordOffset {
        /// The invalid record offset.
        record_offset: u64,
    },
    /// The payload is too large for the local address space.
    #[error("blob payload length {payload_len} does not fit in memory")]
    PayloadTooLarge {
        /// The rejected payload length.
        payload_len: u128,
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
    /// The record payload window extends past the packfile length.
    #[error("blob record payload ends at {payload_end}, past pack length {pack_len}")]
    RecordExtendsPastEnd {
        /// The byte offset one past the payload end.
        payload_end: u64,
        /// The packfile length.
        pack_len: u64,
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
        /// The hash computed from the payload bytes.
        actual: BlobPackHash,
    },
}

/// A blob pack relocation rewrite failed.
#[derive(Debug, Error)]
pub enum BlobPackRewriteError {
    /// The temporary path points at the source pack.
    #[error("staged blob pack {tmp_path:?} aliases source blob pack {source_path:?}")]
    SourceEqualsTemp {
        /// The source pack path.
        source_path: PathBuf,
        /// The rejected temporary pack path.
        tmp_path: PathBuf,
    },
    /// A stale temporary pack could not be removed before writing.
    #[error("failed to remove staged blob pack {path:?}")]
    RemoveTemp {
        /// The temporary pack path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The temporary pack could not be opened.
    #[error("failed to open staged blob pack")]
    OpenTemp {
        /// The append error reported by the temporary pack.
        #[source]
        source: BlobPackAppendError,
    },
    /// A source record could not be read and verified.
    #[error("failed to read source blob record")]
    ReadSource {
        /// The read error reported by the source pack.
        #[source]
        source: BlobPackReadError,
    },
    /// A verified source payload could not be appended to the temporary pack.
    #[error("failed to append staged blob record")]
    AppendTemp {
        /// The append error reported by the temporary pack.
        #[source]
        source: BlobPackAppendError,
    },
    /// The copied record did not land at the caller-planned location.
    #[error("relocated blob record landed at {actual:?}, expected {expected:?}")]
    RecordLocationMismatch {
        /// The expected compacted record location.
        expected: BlobPackLocation,
        /// The actual appended record location.
        actual: BlobPackLocation,
    },
    /// The completed temporary pack could not be validated.
    #[error("failed to validate staged blob pack")]
    ValidateTemp {
        /// The read error reported by the completed temporary pack.
        #[source]
        source: BlobPackReadError,
    },
}

/// A blob pack tail trim failed.
#[derive(Debug, Error)]
pub enum BlobPackTrimError {
    /// The packfile could not be opened.
    #[error("failed to open blob pack {path:?}")]
    Open {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile advisory lock could not be acquired.
    #[error("failed to lock blob pack {path:?}")]
    Lock {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// File metadata could not be read.
    #[error("failed to read blob pack metadata for {path:?}")]
    Metadata {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be seeked.
    #[error("failed to seek blob pack {path:?}")]
    Seek {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be read.
    #[error("failed to read blob pack {path:?}")]
    Read {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be written.
    #[error("failed to write blob pack {path:?}")]
    Write {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile header is invalid.
    #[error("invalid blob pack format in {path:?}")]
    Format {
        /// The packfile path.
        path: PathBuf,
        /// The format error.
        #[source]
        source: BlobPackFormatError,
    },
    /// The trim offset points before the initialized pack header.
    #[error("invalid blob pack trim offset {record_offset}")]
    InvalidRecordOffset {
        /// The invalid trim offset.
        record_offset: u64,
    },
    /// The trim offset is past the current packfile length.
    #[error("blob pack trim offset {payload_end} is past pack length {pack_len}")]
    RecordExtendsPastEnd {
        /// The requested byte offset one past the retained tail.
        payload_end: u64,
        /// The current packfile length.
        pack_len: u64,
    },
}

/// A blob pack append operation failed.
#[derive(Debug, Error)]
pub enum BlobPackAppendError {
    /// A parent directory could not be created.
    #[error("failed to create blob pack parent directory {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be opened.
    #[error("failed to open blob pack {path:?}")]
    Open {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile advisory lock could not be acquired.
    #[error("failed to lock blob pack {path:?}")]
    Lock {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// File metadata could not be read.
    #[error("failed to read blob pack metadata for {path:?}")]
    Metadata {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be seeked.
    #[error("failed to seek blob pack {path:?}")]
    Seek {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be read.
    #[error("failed to read blob pack {path:?}")]
    Read {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile could not be written.
    #[error("failed to write blob pack {path:?}")]
    Write {
        /// The packfile path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile header is invalid.
    #[error("invalid blob pack format in {path:?}")]
    Format {
        /// The packfile path.
        path: PathBuf,
        /// The format error.
        #[source]
        source: BlobPackFormatError,
    },
    /// The payload is too large for the on-disk record format.
    #[error("blob payload length {payload_len} does not fit in u64")]
    PayloadTooLarge {
        /// The rejected payload length.
        payload_len: u128,
    },
    /// The payload bytes do not hash to the expected content address.
    #[error("blob payload hash mismatch: expected {expected}, got {actual}")]
    PayloadHashMismatch {
        /// The expected content address.
        expected: BlobPackHash,
        /// The hash computed from the supplied payload.
        actual: BlobPackHash,
    },
    /// The record offset points before the initialized pack header.
    #[error("invalid blob record offset {record_offset}")]
    InvalidRecordOffset {
        /// The invalid record offset.
        record_offset: u64,
    },
}

/// A blob pack file identity operation failed.
#[derive(Debug, Error)]
pub enum BlobPackFileIdentityError {
    /// File metadata could not be read.
    #[error("failed to read blob pack file metadata")]
    Metadata(#[source] std::io::Error),
    /// The file descriptor does not refer to a regular file.
    #[error("blob pack file descriptor does not refer to a regular file")]
    NotRegularFile,
}

/// A blob pack read lease could not be created.
#[derive(Debug, Error)]
pub enum BlobPackReadLeaseError {
    /// The shared packfile advisory lock could not be acquired.
    #[error("failed to acquire shared blob pack read lease")]
    Lock {
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The packfile identity could not be read.
    #[error("failed to snapshot blob pack file identity")]
    Identity {
        /// The underlying identity error.
        #[source]
        source: BlobPackFileIdentityError,
    },
}
