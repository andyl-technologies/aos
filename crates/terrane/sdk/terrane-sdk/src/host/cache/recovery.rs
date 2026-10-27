//! Prepares detached-index reconstruction after verifying every pack body.
//!
//! The result is derived encoded data, not native filesystem, pin, admission or
//! quota evidence. A native repair owner must retain the actual source inode,
//! verify its incarnation, reserve and measure the real index allocation, and
//! durably publish the existing index key before claiming recovery completion.

use super::HostReadLimits;
use crate::{
    pack::{
        EntryKind, FOOTER_SIZE, HEADER_SIZE, IndexEntry, NativeBodyDecoder, PackId, PackReader,
    },
    store::{ContentValidator, CorruptSubject, MetaUpload, StoreErrorKind, StoreFailure},
};
use std::collections::BTreeMap;
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
    pack_format::{RECORD_SIZE, Record, index_count},
};

/// Retains exact derived index bytes after complete configured pack verification.
///
/// No file is created and no native repair is acknowledged by this value.
/// Its pack identity binds the bytes to the native owner's retained source.
pub struct ReconstructedPackIndex {
    pack_id: PackId,
    pack_identity: Identity,
    index: Vec<u8>,
}

impl ReconstructedPackIndex {
    /// Returns the existing random identifier selecting the canonical index key.
    pub fn pack_id(&self) -> PackId {
        self.pack_id
    }

    /// Returns the verified whole-pack identity for source-incarnation checks.
    pub fn pack_identity(&self) -> &Identity {
        &self.pack_identity
    }

    /// Borrows exact existing-format detached index bytes awaiting native repair.
    pub fn bytes(&self) -> &[u8] {
        &self.index
    }
}

/// Verifies a complete pack before deriving its missing detached index.
///
/// The configured validator checks every metadata schema. The existing native
/// decoder independently verifies supplied dictionary plaintext against its
/// digest before decoding each dependent chunk. Dictionary lookup remains the
/// native owner's domain-bound responsibility; this helper performs no I/O.
///
/// # Errors
/// Returns capacity for operator allocation limits, corruption for damaged
/// structure/body/hash or a header inconsistent with the canonical pack key,
/// and the configured metadata validator's explicit schema/dependency errors.
/// Missing or corrupt dictionaries identify that dependency, rather than
/// misclassifying an otherwise healthy pack as corrupt.
pub fn reconstruct_pack_index(
    bytes: &[u8],
    expected_id: PackId,
    profile: &ChunkProfile,
    validator: &(impl ContentValidator + ?Sized),
    dictionaries: &BTreeMap<Digest, Vec<u8>>,
    limits: HostReadLimits,
) -> Result<ReconstructedPackIndex, StoreFailure> {
    if limits.max_allocation_bytes == 0 || bytes.len() > limits.max_allocation_bytes {
        return Err(capacity());
    }
    let identity = TERRANE_V1
        .calculate(IdentityKind::Pack, bytes)
        .map_err(|error| StoreFailure::with_source(StoreErrorKind::Unsupported, error))?;
    let malformed = || {
        corrupt(
            &identity,
            "pack cannot reconstruct an index from damaged framing",
        )
    };
    let footer_start = bytes.len().checked_sub(FOOTER_SIZE).ok_or_else(malformed)?;
    let offset_bytes: [u8; 8] = bytes
        .get(footer_start..footer_start + 8)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    let index_offset =
        usize::try_from(u64::from_le_bytes(offset_bytes)).map_err(|_| malformed())?;
    let trailing = bytes
        .get(index_offset..footer_start)
        .ok_or_else(malformed)?;
    let count = index_count(trailing, RECORD_SIZE).map_err(|_| malformed())?;
    let allocation_per_record =
        std::mem::size_of::<Record>().max(std::mem::size_of::<IndexEntry>());
    if count
        .checked_mul(allocation_per_record)
        .ok_or_else(capacity)?
        > limits.max_allocation_bytes
        || trailing
            .len()
            .checked_add(HEADER_SIZE)
            .ok_or_else(capacity)?
            > limits.max_allocation_bytes
    {
        return Err(capacity());
    }
    let reader = PackReader::recover(bytes).map_err(|error| {
        StoreFailure::with_source(
            StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
            error,
        )
    })?;
    if reader.header().id() != expected_id {
        return Err(corrupt(
            &identity,
            "pack header differs from canonical pack key",
        ));
    }
    let decoder = NativeBodyDecoder::new(profile, dictionaries);
    for entry in reader.entries() {
        if entry.plaintext_len() as usize > limits.max_allocation_bytes {
            return Err(capacity());
        }
        if entry.kind() == EntryKind::Chunk {
            check_dictionary(bytes, entry, &identity, profile, dictionaries, limits)?;
        }
        let plaintext = reader
            .read(entry.kind(), entry.hash(), &decoder)
            .map_err(|error| {
                StoreFailure::with_source(
                    StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
                    error,
                )
            })?;
        if entry.kind() != EntryKind::Chunk {
            validator.validate_meta(&MetaUpload::new(entry.kind().identity_kind(), &plaintext)?)?;
        }
    }
    Ok(ReconstructedPackIndex {
        pack_id: expected_id,
        pack_identity: identity,
        index: reader.index_object(),
    })
}

fn check_dictionary(
    bytes: &[u8],
    entry: &IndexEntry,
    pack_identity: &Identity,
    profile: &ChunkProfile,
    dictionaries: &BTreeMap<Digest, Vec<u8>>,
    limits: HostReadLimits,
) -> Result<(), StoreFailure> {
    let invalid = || corrupt(pack_identity, "pack body range is invalid");
    let start = usize::try_from(entry.offset()).map_err(|_| invalid())?;
    let end = start
        .checked_add(entry.body_len() as usize)
        .ok_or_else(invalid)?;
    let body = bytes.get(start..end).ok_or_else(invalid)?;
    let envelope = terrane_format::codec::parse_envelope(body).map_err(|error| {
        StoreFailure::with_source(
            StoreErrorKind::Corrupt(CorruptSubject::Identity(pack_identity.clone())),
            error,
        )
    })?;
    let terrane_format::codec::Codec::ZstdDictionary(digest) = envelope.codec else {
        return Ok(());
    };
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, &digest)
        .map_err(|error| {
            StoreFailure::with_source(
                StoreErrorKind::Corrupt(CorruptSubject::Identity(pack_identity.clone())),
                error,
            )
        })?;
    let dictionary = dictionaries
        .get(&digest)
        .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone())))?;
    if dictionary.len() > limits.max_allocation_bytes {
        return Err(capacity());
    }
    if dictionary.len() > profile.maximum() {
        return Err(corrupt(
            &identity,
            "dictionary exceeds the configured chunk profile",
        ));
    }
    TERRANE_V1.verify(&identity, dictionary).map_err(|error| {
        StoreFailure::with_source(
            StoreErrorKind::Corrupt(CorruptSubject::Identity(identity)),
            error,
        )
    })
}

fn capacity() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Capacity)
}

fn corrupt(identity: &Identity, message: &'static str) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
        std::io::Error::new(std::io::ErrorKind::InvalidData, message),
    )
}
