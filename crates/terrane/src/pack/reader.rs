//! Validates sealed pack structure and verifies each body before serving it.
//!
//! ```text
//! footer = index-offset:u64le | CRC32C(index):u32le | "TRPE"
//! detached-index = header:24 | authoritative-index-bytes
//! ```

use super::binary::{array, crc32c, decode_header, decode_index, encode_header};
use super::{
    Codec, EntryKind, FOOTER_SIZE, HEADER_SIZE, IndexEntry, PackError, PackHeader, verify,
};
use terrane_core::cbor::Decoder;
use terrane_core::identity::Digest;

/// A bounded chunk-envelope decoder supplied by the runtime codec layer.
///
/// Implementations verify sized, single-frame encoding and resolve dictionary
/// plaintext from the envelope's digest. A dictionary registry hint must never
/// replace verification against that digest. Returned bytes remain private
/// until the reader has independently verified their length and identity.
pub trait BodyDecoder {
    /// Decodes one chunk into at most its declared plaintext length.
    ///
    /// # Errors
    /// Rejects unavailable dictionaries, malformed frames, length or resource
    /// limits, codec disagreement, and decompression failures.
    fn decode(
        &self,
        encoded: &[u8],
        plaintext_len: u32,
        dictionary_id: u16,
    ) -> Result<Vec<u8>, PackError>;
}

/// A raw-only decoder for stores that receive uncompressed chunk envelopes.
///
/// Compressed entries fail explicitly and can be read by another decoder.
pub struct RawBodyDecoder;

impl BodyDecoder for RawBodyDecoder {
    fn decode(
        &self,
        encoded: &[u8],
        plaintext_len: u32,
        dictionary_id: u16,
    ) -> Result<Vec<u8>, PackError> {
        if encoded.first() != Some(&(Codec::Raw as u8)) || dictionary_id != 0 {
            return Err(PackError::Decoder);
        }
        let bytes = encoded.get(1..).ok_or(PackError::Codec)?;
        if bytes.len() != plaintext_len as usize {
            return Err(PackError::Index);
        }
        Ok(bytes.to_vec())
    }
}

/// A reader whose index has passed CRC, ordering, and body-coverage validation.
#[derive(Debug)]
pub struct PackReader<'a> {
    bytes: &'a [u8],
    header: PackHeader,
    index_offset: usize,
    entries: Vec<IndexEntry>,
}

impl<'a> PackReader<'a> {
    /// Opens a sealed pack using only its own authoritative bytes.
    ///
    /// Version, reserved fields, index CRC, kinds, codecs, offsets, overlap,
    /// coverage, count, and duplicate hashes are checked before any lookup.
    /// Inter-body padding is permitted when the next recorded offset skips it.
    ///
    /// # Errors
    /// Returns a format, CRC, reserved-field, ordering, duplicate, or bounds error.
    pub fn open(bytes: &'a [u8]) -> Result<Self, PackError> {
        let header = decode_header(bytes)?;
        let footer_start = bytes
            .len()
            .checked_sub(FOOTER_SIZE)
            .ok_or(PackError::Malformed)?;
        let footer = bytes.get(footer_start..).ok_or(PackError::Malformed)?;
        if array::<4>(footer, 12)? != *b"TRPE" {
            return Err(PackError::Version);
        }
        let index_offset =
            usize::try_from(u64::from_le_bytes(array(footer, 0)?)).map_err(|_| PackError::Limit)?;
        if index_offset < HEADER_SIZE || index_offset > footer_start {
            return Err(PackError::Index);
        }
        let index = bytes
            .get(index_offset..footer_start)
            .ok_or(PackError::Index)?;
        if crc32c(index) != u32::from_le_bytes(array(footer, 8)?) {
            return Err(PackError::Crc);
        }
        let entries = decode_index(index, header)?;
        validate_coverage(&entries, index_offset)?;
        for entry in &entries {
            let body = body_slice(bytes, entry)?;
            if entry.kind == EntryKind::Chunk && body.first() != Some(&(entry.codec as u8)) {
                return Err(PackError::Codec);
            }
        }
        Ok(Self {
            bytes,
            header,
            index_offset,
            entries,
        })
    }

    /// Returns the validated header.
    pub const fn header(&self) -> PackHeader {
        self.header
    }

    /// Borrows the hash-sorted authoritative index records.
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    /// Reconstructs the detached index from the pack's validated trailing index.
    pub fn index_object(&self) -> Vec<u8> {
        let mut output = encode_header(self.header);
        output.extend_from_slice(&self.bytes[self.index_offset..self.bytes.len() - FOOTER_SIZE]);
        output
    }

    /// Reports corruption when a detached index disagrees with the pack.
    ///
    /// The reader remains usable because its trailing index is authoritative.
    ///
    /// # Errors
    /// Returns [`PackError::DetachedIndex`] for any byte disagreement.
    pub fn check_index_object(&self, detached: &[u8]) -> Result<(), PackError> {
        if detached != self.index_object() {
            return Err(PackError::DetachedIndex);
        }
        Ok(())
    }

    /// Reads and verifies plaintext under the exact kind recorded in the index.
    ///
    /// # Errors
    /// Rejects absent content, another kind, decoder failure, incorrect plaintext
    /// length, malformed canonical metadata, or identity disagreement.
    pub fn read<D: BodyDecoder>(
        &self,
        kind: EntryKind,
        hash: &Digest,
        decoder: &D,
    ) -> Result<Vec<u8>, PackError> {
        let position = self
            .entries
            .binary_search_by_key(hash, |entry| entry.hash)
            .map_err(|_| PackError::Missing)?;
        let entry = &self.entries[position];
        if entry.kind != kind {
            return Err(PackError::Kind);
        }
        let body = body_slice(self.bytes, entry)?;
        let plaintext = if kind == EntryKind::Chunk {
            decoder.decode(body, entry.plaintext_len, entry.dictionary_id)?
        } else {
            validate_metadata(kind, body)?;
            body.to_vec()
        };
        if plaintext.len() != entry.plaintext_len as usize {
            return Err(PackError::Index);
        }
        verify(kind, hash, &plaintext)?;
        Ok(plaintext)
    }

    /// Verifies an entire fetched pack before producing any cache admissions.
    ///
    /// Requested content is distinguished from unrequested bystanders; every
    /// admission has `pinned = false`, since pin ownership belongs to a separate
    /// explicit consumer operation. One bad body rejects the whole result.
    ///
    /// # Errors
    /// Returns the first verification error from [`Self::read`].
    pub fn verified_admissions<D: BodyDecoder>(
        &self,
        requested: &[(EntryKind, Digest)],
        decoder: &D,
    ) -> Result<Vec<Admission>, PackError> {
        let mut admissions = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            admissions.push(Admission {
                kind: entry.kind,
                hash: entry.hash,
                bytes: self.read(entry.kind, &entry.hash, decoder)?,
                requested: requested.contains(&(entry.kind, entry.hash)),
            });
        }
        Ok(admissions)
    }

    /// Returns whether requested body bytes meet a whole-pack fetch threshold.
    ///
    /// The threshold is an integer percentage from zero through 100; 50 is the
    /// recommended default. Each body is counted once regardless of repeated
    /// requests. Empty packs never require a content fetch.
    ///
    /// # Errors
    /// Returns a limit error if `percentage` is greater than 100.
    pub fn prefer_whole_pack(
        &self,
        requested: &[(EntryKind, Digest)],
        percentage: u8,
    ) -> Result<bool, PackError> {
        if percentage > 100 {
            return Err(PackError::Limit);
        }
        let total: u128 = self
            .entries
            .iter()
            .map(|entry| u128::from(entry.body_len))
            .sum();
        let wanted: u128 = self
            .entries
            .iter()
            .filter(|entry| requested.contains(&(entry.kind, entry.hash)))
            .map(|entry| u128::from(entry.body_len))
            .sum();
        Ok(total != 0 && wanted * 100 >= total * u128::from(percentage))
    }
}

/// A verified body eligible for admission after a whole-pack fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    /// The identity domain used during verification.
    pub kind: EntryKind,
    /// The verified content digest.
    pub hash: Digest,
    /// The verified plaintext or canonical metadata bytes.
    pub bytes: Vec<u8>,
    /// Whether the caller explicitly requested this content.
    pub requested: bool,
}

impl Admission {
    /// Returns false because cache admission never creates a consumer pin.
    pub const fn pinned(&self) -> bool {
        false
    }
}

fn body_slice<'a>(bytes: &'a [u8], entry: &IndexEntry) -> Result<&'a [u8], PackError> {
    let start = usize::try_from(entry.offset).map_err(|_| PackError::Limit)?;
    let end = start
        .checked_add(entry.body_len as usize)
        .ok_or(PackError::Limit)?;
    bytes.get(start..end).ok_or(PackError::Index)
}

fn validate_coverage(entries: &[IndexEntry], index_offset: usize) -> Result<(), PackError> {
    let mut physical: Vec<_> = entries.iter().collect();
    physical.sort_by_key(|entry| entry.offset);
    let mut next = HEADER_SIZE as u64;
    for entry in physical {
        if entry.offset < next {
            return Err(PackError::Index);
        }
        next = entry
            .offset
            .checked_add(u64::from(entry.body_len))
            .ok_or(PackError::Limit)?;
        if next > index_offset as u64 {
            return Err(PackError::Index);
        }
    }
    if next != index_offset as u64 {
        return Err(PackError::Index);
    }
    Ok(())
}

pub(super) fn validate_metadata(kind: EntryKind, bytes: &[u8]) -> Result<(), PackError> {
    if kind == EntryKind::Chunk {
        return Err(PackError::Kind);
    }
    // Index copies have a registered binary representation, unlike CBOR meta.
    if kind == EntryKind::Index {
        if bytes.starts_with(b"TRPK") {
            super::PackIndexSnapshot::decode(bytes, 0)?;
        } else if bytes.starts_with(b"TRIX") {
            let shard = bytes
                .get(super::binary::PREAMBLE_SIZE)
                .copied()
                .unwrap_or(0);
            super::MergedShard::decode(bytes, 0, shard)?;
        } else {
            return Err(PackError::Index);
        }
        return Ok(());
    }
    let mut decoder = Decoder::new(bytes);
    decoder.skip_value(bytes.len())?;
    decoder.finish()?;
    Ok(())
}
