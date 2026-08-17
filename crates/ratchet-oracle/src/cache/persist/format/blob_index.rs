//! Blob namespace, pack header, location, and index format adapters.

use super::*;
use ratchet_cache::blob_index::{
    BlobIndex as EngineBlobIndex, BlobIndexEntry as EngineBlobIndexEntry,
    BlobIndexError as EngineBlobIndexError, BlobIndexFormatError as EngineBlobIndexFormatError,
    BlobIndexKey as EngineBlobIndexKey, BlobIndexNamespace,
};
use ratchet_cache::blob_pack::{BlobPackHash, BlobPackLocation};
use ratchet_cache::sidecar_index::{LatestIndex, SidecarStatsSnapshot};

/// A content-addressed immutable blob namespace in the persistent cache.
///
/// The declaration order (`Values` before `Files`) matches the encoded
/// [`index_tag`](Self::index_tag) order, so deriving [`Ord`] keeps
/// [`PersistBlobKey`] ordering aligned with encoded-key byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PersistBlobStore {
    /// Serialized WHNF values owned by the constructive value store.
    Values,
    /// Serialized frontend artifacts and file-derived cache payloads.
    Files,
}

impl PersistBlobStore {
    pub(in crate::cache::persist) const fn index_tag(self) -> u8 {
        match self {
            Self::Values => 1,
            Self::Files => 2,
        }
    }

    fn from_index_tag(tag: u8) -> Result<Self, PersistPackFormatError> {
        match tag {
            1 => Ok(Self::Values),
            2 => Ok(Self::Files),
            _ => Err(PersistPackFormatError::InvalidBlobIndexStoreTag { tag }),
        }
    }
}

/// A typed immutable blob lookup key for the persistent hash-to-offset index.
///
/// Ordering is `(store, hash)`, which matches the encoded key byte order
/// (`index_tag` then digest), so an in-memory map keyed on it iterates in the
/// same stable order the on-disk index uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PersistBlobKey {
    store: PersistBlobStore,
    hash: DurableBlake3Hash,
}

impl PersistBlobKey {
    /// Creates a persistent blob key in `store` for `hash`.
    pub(in crate::cache::persist) const fn new(
        store: PersistBlobStore,
        hash: DurableBlake3Hash,
    ) -> Self {
        Self { store, hash }
    }

    /// Creates a persistent value-blob key for `hash`.
    pub const fn for_value(hash: ValueHash) -> Self {
        Self::new(PersistBlobStore::Values, hash.as_durable_hash())
    }

    /// Creates a persistent file-blob key for `hash`.
    pub const fn for_file(hash: PersistFileBlobHash) -> Self {
        Self::new(PersistBlobStore::Files, hash.as_durable_hash())
    }

    /// Returns the immutable blob namespace addressed by this key.
    pub const fn store(self) -> PersistBlobStore {
        self.store
    }

    /// Returns the durable BLAKE3 content address carried by this key.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.hash
    }

    /// Returns the stable binary key for the future hash-to-offset index.
    ///
    /// The first byte separates the `values/` and `files/` namespaces; the
    /// remaining 32 bytes are the durable BLAKE3 digest.
    pub fn index_bytes(self) -> [u8; PERSIST_BLOB_INDEX_KEY_LEN] {
        let mut bytes = [0; PERSIST_BLOB_INDEX_KEY_LEN];
        bytes[0] = self.store.index_tag();
        bytes[1..].copy_from_slice(&self.hash.as_bytes());
        bytes
    }

    /// Decodes the stable binary key for the future hash-to-offset index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_BLOB_INDEX_KEY_LEN`] or carries an unknown store tag.
    pub fn decode_index_bytes(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_BLOB_INDEX_KEY_LEN {
            return Err(PersistPackFormatError::ShortBlobIndexKey {
                expected: PERSIST_BLOB_INDEX_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let store = PersistBlobStore::from_index_tag(bytes[0])?;
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[1..PERSIST_BLOB_INDEX_KEY_LEN]);
        Ok(Self::new(store, DurableBlake3Hash::from_bytes(hash)))
    }
}

/// The fixed header for an immutable blob packfile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistBlobPackHeader {
    version: u32,
}

impl PersistBlobPackHeader {
    /// Returns the current immutable blob packfile header.
    pub const fn current() -> Self {
        Self {
            version: PERSIST_BLOB_PACK_VERSION,
        }
    }

    /// Returns the immutable blob packfile format version.
    pub const fn version(self) -> u32 {
        self.version
    }

    /// Encodes the packfile header as stable little-endian bytes.
    pub fn encode(self) -> [u8; PERSIST_BLOB_PACK_HEADER_LEN] {
        let mut bytes = [0; PERSIST_BLOB_PACK_HEADER_LEN];
        bytes[..16].copy_from_slice(&PERSIST_BLOB_PACK_MAGIC);
        bytes[16..20].copy_from_slice(&self.version.to_le_bytes());
        bytes[20..24].copy_from_slice(&(PERSIST_BLOB_PACK_HEADER_LEN as u32).to_le_bytes());
        bytes
    }

    /// Decodes and validates a packfile header prefix.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_BLOB_PACK_HEADER_LEN`], has the wrong magic bytes, declares an
    /// unsupported version, or declares an unexpected header length.
    pub fn decode(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_BLOB_PACK_HEADER_LEN {
            return Err(PersistPackFormatError::ShortPackHeader {
                expected: PERSIST_BLOB_PACK_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let mut magic = [0; 16];
        magic.copy_from_slice(&bytes[..16]);
        if magic != PERSIST_BLOB_PACK_MAGIC {
            return Err(PersistPackFormatError::InvalidPackMagic { actual: magic });
        }

        let version = read_u32(&bytes[16..20]);
        if version != PERSIST_BLOB_PACK_VERSION {
            return Err(PersistPackFormatError::UnsupportedPackVersion { version });
        }

        let header_len = read_u32(&bytes[20..24]);
        if header_len as usize != PERSIST_BLOB_PACK_HEADER_LEN {
            return Err(PersistPackFormatError::InvalidPackHeaderLength { header_len });
        }

        Ok(Self { version })
    }
}

/// The fixed header for one immutable blob record in a packfile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistBlobRecordHeader {
    hash: DurableBlake3Hash,
    payload_len: u64,
}

impl PersistBlobRecordHeader {
    /// Creates a blob record header for `hash` and `payload_len`.
    pub const fn new(hash: DurableBlake3Hash, payload_len: u64) -> Self {
        Self { hash, payload_len }
    }

    /// Returns the durable BLAKE3 content address carried by this record.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.hash
    }

    /// Returns the number of payload bytes following this record header.
    pub const fn payload_len(self) -> u64 {
        self.payload_len
    }

    /// Returns this record's typed lookup key in `store`.
    pub const fn key(self, store: PersistBlobStore) -> PersistBlobKey {
        PersistBlobKey::new(store, self.hash)
    }

    /// Encodes the record header as stable little-endian bytes.
    pub fn encode(self) -> [u8; PERSIST_BLOB_RECORD_HEADER_LEN] {
        let mut bytes = [0; PERSIST_BLOB_RECORD_HEADER_LEN];
        bytes[..32].copy_from_slice(&self.hash.as_bytes());
        bytes[32..40].copy_from_slice(&self.payload_len.to_le_bytes());
        bytes
    }

    /// Decodes a blob record header prefix.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError::ShortRecordHeader`] if `bytes` is
    /// shorter than [`PERSIST_BLOB_RECORD_HEADER_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_BLOB_RECORD_HEADER_LEN {
            return Err(PersistPackFormatError::ShortRecordHeader {
                expected: PERSIST_BLOB_RECORD_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[..32]);
        let payload_len = read_u64(&bytes[32..40]);
        Ok(Self {
            hash: DurableBlake3Hash::from_bytes(hash),
            payload_len,
        })
    }
}

/// A byte range for one immutable blob record in a packfile.
///
/// This is the value stored by the future hash-to-offset index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistBlobLocation {
    record_offset: u64,
    payload_len: u64,
}

impl PersistBlobLocation {
    /// Creates a blob location from its record offset and payload length.
    pub const fn new(record_offset: u64, payload_len: u64) -> Self {
        Self {
            record_offset,
            payload_len,
        }
    }

    /// Returns the byte offset of this blob's record header in the packfile.
    pub const fn record_offset(self) -> u64 {
        self.record_offset
    }

    /// Returns the number of payload bytes following this blob's record header.
    pub const fn payload_len(self) -> u64 {
        self.payload_len
    }

    /// Encodes this location as a stable hash-to-offset index value.
    pub fn encode_index_value(self) -> [u8; PERSIST_BLOB_INDEX_VALUE_LEN] {
        let mut bytes = [0; PERSIST_BLOB_INDEX_VALUE_LEN];
        bytes[..8].copy_from_slice(&self.record_offset.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.payload_len.to_le_bytes());
        bytes
    }

    /// Decodes a hash-to-offset index value prefix.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError::ShortIndexValue`] if `bytes` is
    /// shorter than [`PERSIST_BLOB_INDEX_VALUE_LEN`].
    pub fn decode_index_value(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_BLOB_INDEX_VALUE_LEN {
            return Err(PersistPackFormatError::ShortIndexValue {
                expected: PERSIST_BLOB_INDEX_VALUE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            record_offset: read_u64(&bytes[..8]),
            payload_len: read_u64(&bytes[8..16]),
        })
    }
}

/// A complete key/value record for the future hash-to-offset index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistBlobIndexEntry {
    key: PersistBlobKey,
    location: PersistBlobLocation,
}

impl PersistBlobIndexEntry {
    /// Creates a blob index entry from its lookup key and pack location.
    pub const fn new(key: PersistBlobKey, location: PersistBlobLocation) -> Self {
        Self { key, location }
    }

    /// Returns the blob lookup key.
    pub const fn key(self) -> PersistBlobKey {
        self.key
    }

    /// Returns the blob pack location.
    pub const fn location(self) -> PersistBlobLocation {
        self.location
    }

    /// Encodes this record as stable hash-to-offset index bytes.
    pub fn encode_index_entry(self) -> [u8; PERSIST_BLOB_INDEX_ENTRY_LEN] {
        let encoded = persist_blob_index_entry_to_engine(self).encode();
        let mut bytes = [0; PERSIST_BLOB_INDEX_ENTRY_LEN];
        bytes.copy_from_slice(&encoded);
        bytes
    }

    /// Decodes a complete hash-to-offset index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_BLOB_INDEX_ENTRY_LEN`] or if the embedded key/value codecs
    /// reject their prefixes.
    pub fn decode_index_entry(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        let entry = EngineBlobIndexEntry::decode(bytes).map_err(engine_blob_index_format_error)?;
        engine_blob_index_entry_to_persist(entry)
    }
}

fn persist_blob_key_to_engine(key: PersistBlobKey) -> EngineBlobIndexKey {
    EngineBlobIndexKey::new(
        BlobIndexNamespace::from_tag(key.store().index_tag()),
        BlobPackHash::from_bytes(key.hash().as_bytes()),
    )
}

fn engine_blob_index_key_to_persist(
    key: EngineBlobIndexKey,
) -> Result<PersistBlobKey, PersistPackFormatError> {
    Ok(PersistBlobKey::new(
        PersistBlobStore::from_index_tag(key.namespace().tag())?,
        DurableBlake3Hash::from_bytes(key.hash().as_bytes()),
    ))
}

fn persist_blob_location_to_engine(location: PersistBlobLocation) -> BlobPackLocation {
    BlobPackLocation::new(location.record_offset(), location.payload_len())
}

fn engine_blob_location_to_persist(location: BlobPackLocation) -> PersistBlobLocation {
    PersistBlobLocation::new(location.record_offset(), location.payload_len())
}

fn persist_blob_index_entry_to_engine(entry: PersistBlobIndexEntry) -> EngineBlobIndexEntry {
    EngineBlobIndexEntry::new(
        persist_blob_key_to_engine(entry.key()),
        persist_blob_location_to_engine(entry.location()),
    )
}

fn engine_blob_index_entry_to_persist(
    entry: EngineBlobIndexEntry,
) -> Result<PersistBlobIndexEntry, PersistPackFormatError> {
    Ok(PersistBlobIndexEntry::new(
        engine_blob_index_key_to_persist(entry.key())?,
        engine_blob_location_to_persist(entry.location()),
    ))
}

fn engine_blob_index_error(error: EngineBlobIndexError) -> PersistBlobIndexError {
    match error {
        EngineBlobIndexError::CreateParent { path, source } => {
            PersistBlobIndexError::CreateParent { path, source }
        }
        EngineBlobIndexError::Open { path, source } => PersistBlobIndexError::Open { path, source },
        EngineBlobIndexError::Metadata { path, source } => {
            PersistBlobIndexError::Metadata { path, source }
        }
        EngineBlobIndexError::Read { path, source } => PersistBlobIndexError::Read { path, source },
        EngineBlobIndexError::Write { path, source } => {
            PersistBlobIndexError::Write { path, source }
        }
        EngineBlobIndexError::Format { path, source } => PersistBlobIndexError::Format {
            path,
            source: engine_blob_index_format_error(source),
        },
    }
}

fn engine_blob_index_format_error(error: EngineBlobIndexFormatError) -> PersistPackFormatError {
    match error {
        EngineBlobIndexFormatError::ShortKey { expected, actual } => {
            PersistPackFormatError::ShortBlobIndexKey { expected, actual }
        }
        EngineBlobIndexFormatError::ShortValue { expected, actual } => {
            PersistPackFormatError::ShortIndexValue { expected, actual }
        }
        EngineBlobIndexFormatError::ShortEntry { expected, actual } => {
            PersistPackFormatError::ShortBlobIndexEntry { expected, actual }
        }
    }
}

/// A fixed-record hash-to-offset index file for immutable blob pack entries.
///
/// This is a simple durable substrate for tests and future cache integration.
/// It is not the final LMDB/redb metadata engine: writes append one fixed
/// record at a time, and lookups scan records linearly and return the newest
/// matching entry.
/// The newest location per key is held in a shared in-memory
/// [`LatestIndex`](ratchet_cache::sidecar_index::LatestIndex), refreshed from the
/// file before each read by decoding only the appended tail. This keeps lookups
/// as map probes while staying coherent with writes made through other handles
/// or processes; a rewrite (compaction or repack) marks the map stale so the
/// next read reloads.
#[derive(Clone, Debug)]
pub struct PersistBlobIndex {
    engine: EngineBlobIndex,
    index: LatestIndex<PersistBlobKey, PersistBlobLocation>,
}

impl PersistBlobIndex {
    /// Opens or initializes a fixed-record blob index file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if parent directories or the index
    /// file cannot be created/opened, or if the existing file ends with a
    /// partial fixed-width record.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistBlobIndexError> {
        let engine = EngineBlobIndex::open(path.into()).map_err(engine_blob_index_error)?;
        Ok(Self {
            engine,
            index: LatestIndex::new(),
        })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Returns a snapshot of the lookup and records-scanned counters.
    pub fn stats(&self) -> SidecarStatsSnapshot {
        self.index.stats().snapshot()
    }

    /// Appends one hash-to-offset index entry.
    ///
    /// The record is written to the append-only file; the next read folds it
    /// into the in-memory index through the tail reload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entry(&self, entry: PersistBlobIndexEntry) -> Result<(), PersistBlobIndexError> {
        self.engine
            .append_entry(persist_blob_index_entry_to_engine(entry))
            .map_err(engine_blob_index_error)
    }

    /// Appends many hash-to-offset entries in one open/write/flush cycle.
    ///
    /// The write-behind flush pairs this with the batched pack append so the
    /// value sidecar is opened and flushed once per flush instead of once per
    /// record. An empty batch is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be opened, written,
    /// or flushed.
    pub fn append_entries_batch(
        &self,
        entries: &[PersistBlobIndexEntry],
    ) -> Result<(), PersistBlobIndexError> {
        let engine_entries: Vec<_> = entries
            .iter()
            .map(|entry| persist_blob_index_entry_to_engine(*entry))
            .collect();
        self.engine
            .append_entries_batch(&engine_entries)
            .map_err(engine_blob_index_error)
    }

    /// Refreshes the in-memory index from the file, decoding only new records.
    ///
    /// Malformed records surface here as the tail reload decodes them, which is
    /// why lookups on a corrupt sidecar return a format error.
    fn refresh(&self) -> Result<(), PersistBlobIndexError> {
        let len = self.engine.len().map_err(engine_blob_index_error)?;
        let path = self.path().to_path_buf();
        self.index.refresh_with(len, |from| {
            let (entries, end) = self
                .engine
                .read_entries_from(from)
                .map_err(engine_blob_index_error)?;
            let mut pairs = Vec::with_capacity(entries.len());
            for entry in entries {
                let entry = engine_blob_index_entry_to_persist(entry).map_err(|source| {
                    PersistBlobIndexError::Format {
                        path: path.clone(),
                        source,
                    }
                })?;
                pairs.push((entry.key(), entry.location()));
            }
            Ok((pairs, end))
        })
    }

    /// Looks up the newest location for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be created,
    /// opened, inspected, read, or decoded during the refresh.
    pub fn lookup(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<PersistBlobLocation>, PersistBlobIndexError> {
        self.refresh()?;
        Ok(self.index.get(&key))
    }

    /// Returns the newest entry for every blob key.
    ///
    /// Entries are returned in stable encoded-key order. If a key appears
    /// multiple times in the append-only sidecar, only its newest location is
    /// returned.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be created,
    /// opened, inspected, read, or decoded.
    pub fn latest_entries(&self) -> Result<Vec<PersistBlobIndexEntry>, PersistBlobIndexError> {
        self.refresh()?;
        Ok(self
            .index
            .latest_pairs()
            .into_iter()
            .map(|(key, location)| PersistBlobIndexEntry::new(key, location))
            .collect())
    }

    /// Rewrites the sidecar to the newest entry for every blob key.
    ///
    /// Entries are written in stable encoded-key order through a temporary file
    /// that is renamed over the original index. The returned count is the
    /// number of latest entries preserved after compaction. Callers must
    /// exclude all concurrent sidecar writers across threads and processes
    /// while this method runs; an append that races between the snapshot and
    /// rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be created,
    /// opened, inspected, read, decoded, written, flushed, or renamed into
    /// place.
    pub fn compact_latest_entries(&self) -> Result<usize, PersistBlobIndexError> {
        let entries = self.latest_entries()?;
        self.replace_entries(&entries)
    }

    /// Rewrites the sidecar to exactly `entries` in caller-supplied order.
    ///
    /// Entries are written through a temporary file that is renamed over the
    /// original index. The returned count is the number of entries written. This
    /// low-level helper does not validate that entries match any specific blob
    /// store or packfile; callers that rebuild from pack contents must provide
    /// already verified entries. Callers must also exclude all concurrent
    /// sidecar writers across threads and processes while this method runs; an
    /// append that races between the caller's snapshot and this rename can be
    /// lost.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be created,
    /// opened, inspected, written, flushed, or renamed into place.
    pub fn replace_entries(
        &self,
        entries: &[PersistBlobIndexEntry],
    ) -> Result<usize, PersistBlobIndexError> {
        let engine_entries = entries
            .iter()
            .copied()
            .map(persist_blob_index_entry_to_engine)
            .collect::<Vec<_>>();
        let count = self
            .engine
            .replace_entries(&engine_entries)
            .map_err(engine_blob_index_error)?;
        self.index.mark_stale();
        Ok(count)
    }

    /// Invalidates the in-memory index so the next read fully reloads the file.
    ///
    /// Callers use this after replacing the backing file out-of-band — for
    /// example a pack repack that stages a new index at a temporary path and
    /// swaps it into place with [`ratchet_cache::file_replace::FileReplacementSet`]
    /// rather than going through [`Self::replace_entries`]. Such a swap can leave
    /// the file the same length with different record offsets, which the length
    /// based tail reload would not otherwise detect.
    pub(in crate::cache::persist) fn mark_stale(&self) {
        self.index.mark_stale();
    }

    /// Writes `entries` exactly to `path`, replacing any stale file there.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the staged index cannot be removed,
    /// created, written, or flushed.
    pub(in crate::cache::persist) fn write_entries_to(
        path: impl Into<PathBuf>,
        entries: &[PersistBlobIndexEntry],
    ) -> Result<usize, PersistBlobIndexError> {
        let entries = entries
            .iter()
            .copied()
            .map(persist_blob_index_entry_to_engine)
            .collect::<Vec<_>>();
        EngineBlobIndex::write_entries_to(path.into(), &entries).map_err(engine_blob_index_error)
    }
}
