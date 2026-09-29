//! Validates sealed pack structure and verifies each body before serving it.
//!
//! ```text
//! footer = index-offset:u64le | CRC32C(index):u32le | "TRPE"
//! detached-index = header:24 | authoritative-index-bytes
//! ```

use super::binary::{encode_header, native_header, native_record};
use super::{Codec, EntryKind, FOOTER_SIZE, IndexEntry, PackError, PackHeader, verify};
use terrane_core::identity::Digest;

/// A bounded chunk-envelope decoder supplied by the runtime codec layer.
///
/// Implementations verify sized, single-frame encoding and resolve dictionary
/// plaintext from the envelope's digest. The reserved dictionary field must
/// remain zero; the envelope digest is authoritative. Returned bytes remain private
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
        expected_hash: &Digest,
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
        _expected_hash: &Digest,
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
        let view = terrane_core::pack_format::PackView::decode(bytes)?;
        let header = native_header(view.header());
        let index_offset = view.index_offset();
        let entries = view
            .records()
            .iter()
            .map(native_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            bytes,
            header,
            index_offset,
            entries,
        })
    }

    /// Opens recoverable structure or explicitly quarantines a damaged pack.
    ///
    /// An intact embedded index reconstructs the detached index with
    /// [`Self::index_object`]. V1 raw bodies have no lengths and meta bodies have
    /// no kind tags outside the index, so a damaged footer or index cannot
    /// safely be recovered by forward scanning. This implementation does not
    /// invent framing, infer kinds, or serve damaged bytes in place.
    ///
    /// # Errors
    /// Returns [`PackError::RecoveryUnsupported`] containing the original
    /// structural error when a pack must be quarantined for offline recovery.
    pub fn recover(bytes: &'a [u8]) -> Result<Self, PackError> {
        Self::open(bytes).map_err(|error| PackError::RecoveryUnsupported(Box::new(error)))
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
            decoder.decode(body, entry.plaintext_len, entry.dictionary_id, &entry.hash)?
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

pub(super) fn validate_metadata(kind: EntryKind, bytes: &[u8]) -> Result<(), PackError> {
    Ok(terrane_core::pack_format::validate_metadata(
        kind as u8, bytes,
    )?)
}
