//! Serializes and validates the complete version-one pack format without I/O.
//!
//! Native writers supply already verified stored bodies and runtime-generated
//! identifiers. This module owns every header, index, footer, and CRC byte;
//! native readers add decompression and content identity verification before
//! exposing a body. Detached indexes are derivable from the pack alone.
//!
//! ```text
//! TRPK | version:u16le | flags:u16le | id:16 | bodies ...
//! TRIX | count:u64le | records:56 ...
//! index-offset:u64le | index-crc32c:u32le | TRPE
//! ```

mod bundle;
mod merged;

#[cfg(test)]
mod tests;

pub use bundle::{
    BundleRecord, BundleView, MAX_BUNDLE_BYTES, MAX_BUNDLE_OBJECTS, bundle_size, decode_bundle,
    encode_bundle, validate_metadata,
};
pub use merged::{MergedRecord, decode_shard, encode_shard};

use alloc::vec::Vec;
use core::fmt;

/// The width of a pack header.
pub const HEADER_SIZE: usize = 24;
/// The width of the trailing footer.
pub const FOOTER_SIZE: usize = 16;
/// The width of one per-pack index record.
pub const RECORD_SIZE: usize = 56;
/// The width of the index magic and count.
pub const PREAMBLE_SIZE: usize = 12;

/// A checked version-one header with no reserved flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    id: [u8; 16],
    flags: u16,
}

impl Header {
    /// Creates a header without generating or claiming entropy for its identifier.
    pub const fn new(id: [u8; 16], meta: bool, compressed_default: bool) -> Self {
        Self {
            id,
            flags: (compressed_default as u16) | ((meta as u16) << 1),
        }
    }

    /// Returns the exact identifier bytes used by the native publication layer.
    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Returns whether this header belongs to a metadata pack.
    pub const fn is_meta(&self) -> bool {
        self.flags & 2 != 0
    }

    /// Returns the writer's compression-default flag.
    pub const fn compressed_default(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Returns the exact fixed-width header bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_SIZE);
        bytes.extend_from_slice(b"TRPK");
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&self.flags.to_le_bytes());
        bytes.extend_from_slice(&self.id);
        bytes
    }

    /// Decodes a header and rejects unknown versions or reserved flags.
    ///
    /// # Errors
    /// Rejects truncated input, unknown magic/version, or nonzero reserved flags.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if array::<4>(bytes, 0)? != *b"TRPK" || u16::from_le_bytes(array(bytes, 4)?) != 1 {
            return Err(Error::Version);
        }
        let flags = u16::from_le_bytes(array(bytes, 6)?);
        if flags & !3 != 0 {
            return Err(Error::Reserved);
        }
        Ok(Self {
            id: array(bytes, 8)?,
            flags,
        })
    }
}

/// A wire record whose fields become trusted only after structural validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// The content digest in the domain selected by `kind`.
    pub hash: [u8; 32],
    /// The stored-body offset measured from the beginning of the pack.
    pub offset: u64,
    /// The stored length including a data chunk's codec envelope.
    pub body_len: u32,
    /// The plaintext length excluding a chunk envelope.
    pub plaintext_len: u32,
    /// The registered codec byte, zero through two.
    pub codec: u8,
    /// The registered kind byte, zero through six.
    pub kind: u8,
    /// The reserved two-byte dictionary field, zero in version one.
    pub dictionary_id: u16,
}

/// A structural pack-format error before any content is served.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A structure is truncated or malformed.
    Malformed,
    /// A magic or version is not recognized.
    Version,
    /// A reserved flag or field is nonzero.
    Reserved,
    /// The trailing index CRC32C does not match.
    Crc,
    /// Hash order, count, coverage, offset, or length is inconsistent.
    Index,
    /// The same content hash occurs more than once.
    Duplicate,
    /// A kind is unknown or mixed into the wrong pack class.
    Kind,
    /// A codec is unknown or inappropriate for the entry kind.
    Codec,
    /// Checked integer arithmetic or a target-size conversion failed.
    Limit,
    /// Canonical metadata failed CBOR validation.
    Cbor(crate::cbor::Error),
    /// A bundle triple failed its domain-separated identity check.
    Identity(crate::identity::IdentityError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => write!(formatter, "pack metadata: {error}"),
            Self::Identity(error) => write!(formatter, "pack metadata identity: {error}"),
            error => formatter.write_str(match error {
                Self::Malformed => "malformed pack structure",
                Self::Version => "unrecognized pack format",
                Self::Reserved => "nonzero reserved pack field",
                Self::Crc => "pack index CRC32C mismatch",
                Self::Index => "pack index coverage or ordering mismatch",
                Self::Duplicate => "duplicate pack content identity",
                Self::Kind => "pack entry kind mismatch",
                Self::Codec => "pack body codec mismatch",
                Self::Limit => "pack format limit exceeded",
                Self::Cbor(_) | Self::Identity(_) => "pack metadata validation failed",
            }),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cbor(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<crate::cbor::Error> for Error {
    fn from(error: crate::cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl From<crate::identity::IdentityError> for Error {
    fn from(error: crate::identity::IdentityError) -> Self {
        Self::Identity(error)
    }
}

/// Encodes index records in their supplied order without changing any location.
///
/// This representation primitive does not validate ordering or body coverage;
/// [`encode_pack`] validates all records before publishing complete pack bytes.
pub fn encode_index(records: &[Record]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"TRIX");
    bytes.extend_from_slice(&(records.len() as u64).to_le_bytes());
    for record in records {
        bytes.extend_from_slice(&record.hash);
        bytes.extend_from_slice(&record.offset.to_le_bytes());
        bytes.extend_from_slice(&record.body_len.to_le_bytes());
        bytes.extend_from_slice(&record.plaintext_len.to_le_bytes());
        bytes.push(record.codec);
        bytes.push(record.kind);
        bytes.extend_from_slice(&record.dictionary_id.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
    }
    bytes
}

/// Checks an index preamble against the exact record width and input size.
///
/// # Errors
/// Rejects unknown magic, overflowing counts, or incomplete/trailing records.
pub fn index_count(bytes: &[u8], width: usize) -> Result<usize, Error> {
    if array::<4>(bytes, 0)? != *b"TRIX" {
        return Err(Error::Version);
    }
    let count = usize::try_from(u64::from_le_bytes(array(bytes, 4)?)).map_err(|_| Error::Limit)?;
    let expected = count
        .checked_mul(width)
        .and_then(|size| size.checked_add(PREAMBLE_SIZE))
        .ok_or(Error::Limit)?;
    if expected != bytes.len() {
        return Err(Error::Index);
    }
    Ok(count)
}

/// Validates an index's count, records, class separation, and hash ordering.
///
/// # Errors
/// Rejects invalid records, nonzero reserved bytes, unknown kinds or codecs,
/// mixed pack classes, nonascending hashes, or duplicate identities.
pub fn decode_index(bytes: &[u8], header: Header) -> Result<Vec<Record>, Error> {
    let count = index_count(bytes, RECORD_SIZE)?;
    let mut records: Vec<Record> = Vec::with_capacity(count);
    for body in bytes[PREAMBLE_SIZE..].as_chunks::<RECORD_SIZE>().0 {
        if array::<4>(body, 52)? != [0; 4] {
            return Err(Error::Reserved);
        }
        let record = Record {
            hash: array(body, 0)?,
            offset: u64::from_le_bytes(array(body, 32)?),
            body_len: u32::from_le_bytes(array(body, 40)?),
            plaintext_len: u32::from_le_bytes(array(body, 44)?),
            codec: body[48],
            kind: body[49],
            dictionary_id: u16::from_le_bytes(array(body, 50)?),
        };
        validate_record(&record, header.is_meta())?;
        if let Some(previous) = records.last()
            && previous.hash >= record.hash
        {
            return Err(if previous.hash == record.hash {
                Error::Duplicate
            } else {
                Error::Index
            });
        }
        records.push(record);
    }
    Ok(records)
}

/// Decodes a detached per-pack index and checks physical record overlap.
///
/// A detached index has no bodies or footer, so only the pack's authoritative
/// trailing index can establish the final body region bound.
///
/// # Errors
/// Rejects malformed headers/indexes, unknown or reserved fields, ordering,
/// duplicates, overlap, and overflowing body endpoints.
pub fn decode_detached_index(bytes: &[u8]) -> Result<(Header, Vec<Record>), Error> {
    let header = Header::decode(bytes)?;
    let records = decode_index(bytes.get(HEADER_SIZE..).ok_or(Error::Malformed)?, header)?;
    let mut physical: Vec<_> = records.iter().collect();
    physical.sort_by_key(|record| record.offset);
    let mut end = HEADER_SIZE as u64;
    for record in physical {
        if record.offset < end {
            return Err(Error::Index);
        }
        end = record
            .offset
            .checked_add(u64::from(record.body_len))
            .ok_or(Error::Limit)?;
    }
    Ok((header, records))
}

/// Validates one record's registered fields and pack class.
///
/// # Errors
/// Rejects unknown fields, nonzero dictionary reservation, class mixing,
/// inappropriate metadata codecs, impossible raw lengths, or header overlap.
pub fn validate_record(record: &Record, meta: bool) -> Result<(), Error> {
    if record.kind > 6 || (record.kind == 0) == meta {
        return Err(Error::Kind);
    }
    if record.codec > 2 || (meta && record.codec != 0) {
        return Err(Error::Codec);
    }
    if record.dictionary_id != 0 {
        return Err(Error::Reserved);
    }
    if record.codec == 0
        && record
            .plaintext_len
            .checked_add(u32::from(record.kind == 0))
            != Some(record.body_len)
    {
        return Err(Error::Index);
    }
    if record.offset < HEADER_SIZE as u64 || record.body_len == 0 {
        return Err(Error::Index);
    }
    Ok(())
}

/// Encodes a complete sealed pack after checking records and body coverage.
///
/// Bodies retain write order; callers supply a hash-sorted record list.
///
/// # Errors
/// Rejects structural inconsistencies, unknown/reserved fields, duplicates,
/// overlap, trailing unindexed bodies, or arithmetic overflow.
pub fn encode_pack(header: Header, bodies: &[u8], records: &[Record]) -> Result<Vec<u8>, Error> {
    let index_offset = HEADER_SIZE.checked_add(bodies.len()).ok_or(Error::Limit)?;
    validate_records(records, header, index_offset)?;
    for record in records {
        let offset = usize::try_from(record.offset).map_err(|_| Error::Limit)? - HEADER_SIZE;
        if record.kind == 0 && bodies.get(offset) != Some(&record.codec) {
            return Err(Error::Codec);
        }
    }
    let index = encode_index(records);
    let size = index_offset
        .checked_add(index.len())
        .and_then(|size| size.checked_add(FOOTER_SIZE))
        .ok_or(Error::Limit)?;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(bodies);
    bytes.extend_from_slice(&index);
    bytes.extend_from_slice(&(index_offset as u64).to_le_bytes());
    bytes.extend_from_slice(&crc32c(&index).to_le_bytes());
    bytes.extend_from_slice(b"TRPE");
    Ok(bytes)
}

/// A zero-copy pack view with a fully checked structural index.
#[derive(Debug)]
pub struct PackView<'a> {
    bytes: &'a [u8],
    header: Header,
    records: Vec<Record>,
    index_offset: usize,
}

impl<'a> PackView<'a> {
    /// Decodes the footer, checks index CRC, and validates all structural records.
    ///
    /// # Errors
    /// Rejects any malformed, unsupported, corrupt, reserved, or inconsistent
    /// structure. Body identities require native decoding before serving.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = Header::decode(bytes)?;
        let footer_start = bytes
            .len()
            .checked_sub(FOOTER_SIZE)
            .ok_or(Error::Malformed)?;
        let footer = bytes.get(footer_start..).ok_or(Error::Malformed)?;
        if array::<4>(footer, 12)? != *b"TRPE" {
            return Err(Error::Version);
        }
        let index_offset =
            usize::try_from(u64::from_le_bytes(array(footer, 0)?)).map_err(|_| Error::Limit)?;
        if index_offset < HEADER_SIZE || index_offset > footer_start {
            return Err(Error::Index);
        }
        let index = bytes.get(index_offset..footer_start).ok_or(Error::Index)?;
        if crc32c(index) != u32::from_le_bytes(array(footer, 8)?) {
            return Err(Error::Crc);
        }
        let records = decode_index(index, header)?;
        validate_records(&records, header, index_offset)?;
        for record in &records {
            let start = usize::try_from(record.offset).map_err(|_| Error::Limit)?;
            if record.kind == 0 && bytes.get(start) != Some(&record.codec) {
                return Err(Error::Codec);
            }
        }
        Ok(Self {
            bytes,
            header,
            records,
            index_offset,
        })
    }

    /// Returns the checked header.
    pub const fn header(&self) -> Header {
        self.header
    }

    /// Borrows the checked hash-sorted wire records.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Returns the authoritative index's byte offset.
    pub const fn index_offset(&self) -> usize {
        self.index_offset
    }

    /// Reconstructs the header-prefixed detached index without external metadata.
    pub fn index_object(&self) -> Vec<u8> {
        let mut bytes = self.header.encode();
        bytes.extend_from_slice(&self.bytes[self.index_offset..self.bytes.len() - FOOTER_SIZE]);
        bytes
    }
}

fn validate_records(records: &[Record], header: Header, index_offset: usize) -> Result<(), Error> {
    let mut previous = None;
    for record in records {
        validate_record(record, header.is_meta())?;
        if let Some(hash) = previous
            && hash >= record.hash
        {
            return Err(if hash == record.hash {
                Error::Duplicate
            } else {
                Error::Index
            });
        }
        previous = Some(record.hash);
    }
    let mut physical: Vec<_> = records.iter().collect();
    physical.sort_by_key(|record| record.offset);
    let mut next = HEADER_SIZE as u64;
    for record in physical {
        if record.offset < next {
            return Err(Error::Index);
        }
        next = record
            .offset
            .checked_add(u64::from(record.body_len))
            .ok_or(Error::Limit)?;
        if next > index_offset as u64 {
            return Err(Error::Index);
        }
    }
    if next != index_offset as u64 {
        return Err(Error::Index);
    }
    Ok(())
}

/// Computes reflected CRC32C with the standard initial and final inversions.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(Error::Limit)?)
        .ok_or(Error::Malformed)?
        .try_into()
        .map_err(|_| Error::Malformed)
}
