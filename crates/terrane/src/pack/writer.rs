//! Builds writer-private packs and consumes them into immutable sealed artifacts.
//!
//! Body write order is independent of hash-sorted index order. A caller emits
//! directory entries and each object's missing chunks in tree order; already
//! held identities can be omitted without changing the adjacent body layout.

use super::binary::{core_header, core_record, encode_header, encode_index, validate_entry};
use super::{
    BodyDecoder, Codec, DATA_PACK_LIMIT, EntryKind, HEADER_SIZE, IndexEntry, PackClass, PackError,
    PackHeader, PackId, digest, verify,
};
use std::collections::BTreeSet;
use terrane_core::identity::Digest;

/// A single owner's private, noncloneable append-only pack builder.
///
/// There is deliberately no API exposing its bytes or an index before sealing.
/// A sealed artifact must be durably stored together with its index before the
/// caller acknowledges content or publishes any ref containing it.
pub struct PackWriter {
    header: PackHeader,
    bodies: Vec<u8>,
    entries: Vec<IndexEntry>,
    hashes: BTreeSet<Digest>,
    last_object_path: Option<Vec<u8>>,
}

impl PackWriter {
    /// Creates a private writer using an identifier from secure runtime entropy.
    pub fn new(id: PackId, class: PackClass, compressed_default: bool) -> Self {
        Self {
            header: PackHeader {
                id,
                class,
                compressed_default,
            },
            bodies: Vec::new(),
            entries: Vec::new(),
            hashes: BTreeSet::new(),
            last_object_path: None,
        }
    }

    /// Appends plaintext under its kind, returning the domain-separated digest.
    ///
    /// # Errors
    /// Rejects duplicate identities, mixed data and metadata, oversized lengths,
    /// noncanonical metadata, and appends after the data size threshold.
    pub fn append_raw(&mut self, kind: EntryKind, plaintext: &[u8]) -> Result<Digest, PackError> {
        let envelope = usize::from(kind == EntryKind::Chunk);
        u32::try_from(
            plaintext
                .len()
                .checked_add(envelope)
                .ok_or(PackError::Limit)?,
        )
        .map_err(|_| PackError::Limit)?;

        let hash = digest(kind, plaintext)?;
        let body = if kind == EntryKind::Chunk {
            let mut encoded =
                Vec::with_capacity(plaintext.len().checked_add(1).ok_or(PackError::Limit)?);
            encoded.push(Codec::Raw as u8);
            encoded.extend_from_slice(plaintext);
            encoded
        } else {
            super::reader::validate_metadata(kind, plaintext)?;
            plaintext.to_vec()
        };
        self.append_verified(kind, hash, &body, plaintext.len(), Codec::Raw, 0)?;
        Ok(hash)
    }

    /// Emits one object's missing raw chunks consecutively in bytewise tree order.
    ///
    /// Held content and chunks already staged in this pack are omitted. The
    /// returned digest list always preserves the object's full chunk order,
    /// including omitted chunks. Callers split a large object across sealed
    /// packs when the size threshold requests a seal.
    ///
    /// # Errors
    /// Rejects metadata writers, empty or nonascending paths, invalid lengths,
    /// or a seal threshold reached before all new chunks were appended.
    pub fn append_object<'a>(
        &mut self,
        path: &[u8],
        chunks: impl IntoIterator<Item = &'a [u8]>,
        held: &BTreeSet<Digest>,
    ) -> Result<Vec<Digest>, PackError> {
        if self.header.class != PackClass::Data {
            return Err(PackError::Kind);
        }
        if path.is_empty()
            || self
                .last_object_path
                .as_ref()
                .is_some_and(|previous| previous.as_slice() >= path)
        {
            return Err(PackError::Index);
        }

        let mut identities = Vec::new();
        for plaintext in chunks {
            let hash = digest(EntryKind::Chunk, plaintext)?;
            if !held.contains(&hash) && !self.hashes.contains(&hash) {
                self.append_raw(EntryKind::Chunk, plaintext)?;
            }
            identities.push(hash);
        }
        self.last_object_path = Some(path.to_vec());
        Ok(identities)
    }

    /// Verifies and appends one independently decodable chunk envelope.
    ///
    /// Decoder output is length- and identity-checked again by the writer.
    /// Boundary admission requires the object's final/nonfinal chunk context
    /// at the content-store boundary; the pack format does not encode it.
    ///
    /// # Errors
    /// Rejects codec or identity disagreement, unavailable decoding, invalid
    /// lengths, duplicate content, mixed classes, or a required seal.
    pub fn append_chunk<D: BodyDecoder>(
        &mut self,
        hash: Digest,
        encoded: &[u8],
        plaintext_len: u32,
        dictionary_id: u16,
        decoder: &D,
    ) -> Result<(), PackError> {
        let codec = Codec::try_from(*encoded.first().ok_or(PackError::Codec)?)?;
        let plaintext = decoder.decode(encoded, plaintext_len, dictionary_id, &hash)?;
        if plaintext.len() != plaintext_len as usize {
            return Err(PackError::Index);
        }
        verify(EntryKind::Chunk, &hash, &plaintext)?;
        self.append_verified(
            EntryKind::Chunk,
            hash,
            encoded,
            plaintext.len(),
            codec,
            dictionary_id,
        )
    }

    fn append_verified(
        &mut self,
        kind: EntryKind,
        hash: Digest,
        body: &[u8],
        plaintext_len: usize,
        codec: Codec,
        dictionary_id: u16,
    ) -> Result<(), PackError> {
        if self.seal_required() {
            return Err(PackError::SealRequired);
        }
        if self.hashes.contains(&hash) {
            return Err(PackError::Duplicate);
        }
        let entry = IndexEntry {
            hash,
            offset: u64::try_from(
                HEADER_SIZE
                    .checked_add(self.bodies.len())
                    .ok_or(PackError::Limit)?,
            )
            .map_err(|_| PackError::Limit)?,
            body_len: u32::try_from(body.len()).map_err(|_| PackError::Limit)?,
            plaintext_len: u32::try_from(plaintext_len).map_err(|_| PackError::Limit)?,
            codec,
            kind,
            dictionary_id,
        };
        validate_entry(&entry, self.header.class)?;
        self.bodies
            .len()
            .checked_add(body.len())
            .ok_or(PackError::Limit)?;

        self.hashes.insert(hash);
        self.bodies.extend_from_slice(body);
        self.entries.push(entry);
        Ok(())
    }

    /// Returns whether this data pack reached the mandatory 32 MiB seal point.
    pub fn seal_required(&self) -> bool {
        self.header.class == PackClass::Data && self.bodies.len() >= DATA_PACK_LIMIT
    }

    /// Returns whether a caller-provided monotonic elapsed interval requests a seal.
    ///
    /// Runtime scheduling supplies elapsed seconds; no clock enters pack identity.
    pub fn seal_due(&self, elapsed_seconds: u64, interval_seconds: u64) -> bool {
        self.seal_required() || elapsed_seconds >= interval_seconds
    }

    /// Consumes the sole writer and returns immutable pack and index bytes.
    ///
    /// # Errors
    /// Returns a limit error if offsets do not fit the versioned format.
    pub fn seal(mut self) -> Result<SealedPack, PackError> {
        self.entries.sort_by_key(|entry| entry.hash);
        let records = self.entries.iter().map(core_record).collect::<Vec<_>>();
        let bytes = terrane_core::pack_format::encode_pack(
            core_header(self.header),
            &self.bodies,
            &records,
        )?;
        let header = encode_header(self.header);
        let index = encode_index(&self.entries);

        let mut detached_index = header;
        detached_index.extend_from_slice(&index);
        Ok(SealedPack {
            header: self.header,
            bytes,
            detached_index,
        })
    }
}

/// Immutable bytes produced only by consuming a completed private writer.
#[derive(Debug)]
pub struct SealedPack {
    header: PackHeader,
    bytes: Vec<u8>,
    detached_index: Vec<u8>,
}

impl SealedPack {
    /// Returns the identity and classification shared by both immutable artifacts.
    pub const fn header(&self) -> PackHeader {
        self.header
    }

    /// Borrows the complete sealed pack, including its authoritative index.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the byte-identical header-prefixed per-pack index object.
    pub fn index_object(&self) -> &[u8] {
        &self.detached_index
    }
}

/// A backend's durable create-if-absent boundary for sealed pack artifacts.
///
/// Implementations must preserve immutable keys and treat an existing key as
/// success only after verifying byte equality. A conflicting existing pack ID
/// is corruption, never a reason to overwrite. Success means the complete
/// object and its publication metadata are durable and readable by key.
#[async_trait::async_trait]
pub trait PackPublisher: Sync {
    /// The backend's original durable-publication error.
    type Error: std::error::Error + Send + Sync;

    /// Stores one immutable artifact durably under its registered key.
    ///
    /// # Errors
    /// Returns the backend's error for I/O, durability failure, unavailable
    /// conditional writes, or an existing immutable key with differing bytes.
    async fn put_immutable(&self, key: &str, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// Proof that both the pack and its index passed durable publication in order.
///
/// Construction is private; callers receive a receipt only after publishing
/// both artifacts. A ref coordinator must require all relevant receipts before
/// publishing any ref that reaches newly written content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedPack {
    id: PackId,
}

impl PublishedPack {
    /// Returns the durable pack identifier shared by both stored artifacts.
    pub const fn id(&self) -> PackId {
        self.id
    }
}

impl SealedPack {
    /// Publishes the sealed pack first and its identical detached index second.
    ///
    /// No receipt is returned on partial failure. A pack stored without its
    /// index stays unreachable until a retry completes publication or GC removes
    /// it after the grace window; it cannot authorize a ref update.
    ///
    /// # Errors
    /// Returns the original publication error from either immutable write.
    pub async fn publish<P: PackPublisher>(
        &self,
        publisher: &P,
    ) -> Result<PublishedPack, P::Error> {
        publisher
            .put_immutable(&self.header.id.pack_key(), &self.bytes)
            .await?;
        publisher
            .put_immutable(&self.header.id.index_key(), &self.detached_index)
            .await?;
        Ok(PublishedPack { id: self.header.id })
    }
}
