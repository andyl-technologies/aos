//! On-disk format primitives for the persistent eval cache.
//!
//! Owns the typed blob namespaces ([`PersistBlobStore`]), content-addressed
//! lookup keys, packfile and record headers, blob locations, and the
//! append-only hash-to-offset and file-artifact index encodings. These types
//! define the byte layout shared by the values and files stores.

use super::*;

use ratchet_cache::artifact_index::{
    ArtifactIndex as EngineArtifactIndex, ArtifactIndexEntry as EngineArtifactIndexEntry,
    ArtifactIndexError as EngineArtifactIndexError,
    ArtifactIndexFormatError as EngineArtifactIndexFormatError,
    ArtifactIndexKey as EngineArtifactIndexKey, ArtifactIndexValue as EngineArtifactIndexValue,
};
use ratchet_cache::blob_index::{
    BlobIndex as EngineBlobIndex, BlobIndexEntry as EngineBlobIndexEntry,
    BlobIndexError as EngineBlobIndexError, BlobIndexFormatError as EngineBlobIndexFormatError,
    BlobIndexKey as EngineBlobIndexKey, BlobIndexNamespace,
};
use ratchet_cache::blob_pack::{BlobPackHash, BlobPackLocation};
use ratchet_cache::node_metadata::{
    NodeMetadataEntry as EngineNodeMetadataEntry,
    NodeMetadataFormatError as EngineNodeMetadataFormatError,
    NodeMetadataIndex as EngineNodeMetadataIndex,
    NodeMetadataIndexError as EngineNodeMetadataIndexError,
    NodeMetadataKey as EngineNodeMetadataKey, NodeMetadataValue as EngineNodeMetadataValue,
};
use ratchet_cache::node_trace_log::{
    NODE_TRACE_LOG_KEY_LEN as ENGINE_NODE_TRACE_LOG_KEY_LEN,
    NODE_TRACE_LOG_RECORD_HEADER_LEN as ENGINE_NODE_TRACE_LOG_RECORD_HEADER_LEN,
    NodeTraceLog as EngineNodeTraceLog, NodeTraceLogEntry as EngineNodeTraceLogEntry,
    NodeTraceLogError as EngineNodeTraceLogError,
    NodeTraceLogFormatError as EngineNodeTraceLogFormatError,
    NodeTraceLogKey as EngineNodeTraceLogKey, NodeTraceLogValueHash as EngineNodeTraceLogValueHash,
};

/// A content-addressed immutable blob namespace in the persistent cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistBlobStore {
    /// Serialized WHNF values owned by the constructive value store.
    Values,
    /// Serialized frontend artifacts and file-derived cache payloads.
    Files,
}

impl PersistBlobStore {
    pub(super) const fn index_tag(self) -> u8 {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistBlobKey {
    store: PersistBlobStore,
    hash: DurableBlake3Hash,
}

impl PersistBlobKey {
    /// Creates a persistent blob key in `store` for `hash`.
    pub const fn new(store: PersistBlobStore, hash: DurableBlake3Hash) -> Self {
        Self { store, hash }
    }

    /// Creates a persistent value-blob key for `hash`.
    pub const fn for_value(hash: DurableBlake3Hash) -> Self {
        Self::new(PersistBlobStore::Values, hash)
    }

    /// Creates a persistent file-blob key for `hash`.
    pub const fn for_file(hash: DurableBlake3Hash) -> Self {
        Self::new(PersistBlobStore::Files, hash)
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
#[derive(Clone, Debug)]
pub struct PersistBlobIndex {
    engine: EngineBlobIndex,
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
        Ok(Self { engine })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Appends one hash-to-offset index entry.
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

    /// Looks up the newest location for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be created,
    /// opened, inspected, read, or decoded.
    pub fn lookup(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<PersistBlobLocation>, PersistBlobIndexError> {
        let mut found = None;
        for entry in self.latest_entries()? {
            if entry.key() == key {
                found = Some(entry.location());
            }
        }
        Ok(found)
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
        self.engine
            .latest_entries()
            .map_err(engine_blob_index_error)?
            .into_iter()
            .map(engine_blob_index_entry_to_persist)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| PersistBlobIndexError::Format {
                path: self.path().to_path_buf(),
                source,
            })
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
        let entries = entries
            .iter()
            .copied()
            .map(persist_blob_index_entry_to_engine)
            .collect::<Vec<_>>();
        self.engine
            .replace_entries(&entries)
            .map_err(engine_blob_index_error)
    }

    /// Writes `entries` exactly to `path`, replacing any stale file there.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the staged index cannot be removed,
    /// created, written, or flushed.
    pub(super) fn write_entries_to(
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

/// A stable index key for a durable frontend file artifact.
///
/// The key is derived from the canonical realpath bytes, the source-content
/// hash, and the parse-cache key that includes parser schema and flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistFileArtifactKey {
    hash: DurableBlake3Hash,
}

impl PersistFileArtifactKey {
    /// Creates a persistent file-artifact index key from a parse file key.
    pub fn from_parse_file_key(file_key: &ParseFileKey, parse_key: ParseCacheKey) -> Self {
        Self::for_realpath_bytes(
            file_key.realpath().as_os_str().as_bytes(),
            file_key.content_hash(),
            parse_key,
        )
    }

    /// Creates a persistent file-artifact index key from raw canonical realpath bytes.
    pub fn for_realpath_bytes(
        realpath: &[u8],
        content_hash: DurableBlake3Hash,
        parse_key: ParseCacheKey,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PERSIST_FILE_ARTIFACT_KEY_PERSONALIZATION);
        update_persist_index_chunk(&mut hasher, realpath);
        hasher.update(&content_hash.as_bytes());
        hasher.update(&parse_key.as_bytes());
        Self {
            hash: DurableBlake3Hash::from_hasher(hasher),
        }
    }

    /// Returns the durable hash of the file-artifact mapping identity.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.hash
    }

    /// Returns the stable binary key for the future file-artifact index.
    pub fn index_bytes(self) -> [u8; PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN] {
        let mut bytes = [0; PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN];
        bytes[0] = PERSIST_FILE_ARTIFACT_INDEX_TAG;
        bytes[1..].copy_from_slice(&self.hash.as_bytes());
        bytes
    }

    /// Decodes the stable binary key for the future file-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN`] or carries an unexpected index
    /// tag.
    pub fn decode_index_bytes(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN {
            return Err(PersistPackFormatError::ShortFileArtifactIndexKey {
                expected: PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != PERSIST_FILE_ARTIFACT_INDEX_TAG {
            return Err(PersistPackFormatError::InvalidFileArtifactIndexTag { tag: bytes[0] });
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[1..PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN]);
        Ok(Self {
            hash: DurableBlake3Hash::from_bytes(hash),
        })
    }
}

/// A stable index value for a durable frontend file artifact.
///
/// The value points at a blob in the `files/` pack. The blob payload format is
/// intentionally outside this codec; the pack still verifies the payload hash
/// on read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistFileArtifactIndexValue {
    blob_hash: DurableBlake3Hash,
    location: PersistBlobLocation,
}

impl PersistFileArtifactIndexValue {
    /// Creates a file-artifact index value for a `files/` blob hash and location.
    pub const fn new(blob_hash: DurableBlake3Hash, location: PersistBlobLocation) -> Self {
        Self {
            blob_hash,
            location,
        }
    }

    /// Returns the durable hash of the file artifact blob.
    pub const fn blob_hash(self) -> DurableBlake3Hash {
        self.blob_hash
    }

    /// Returns the typed blob lookup key in the `files/` store.
    pub const fn blob_key(self) -> PersistBlobKey {
        PersistBlobKey::for_file(self.blob_hash)
    }

    /// Returns the blob packfile location.
    pub const fn location(self) -> PersistBlobLocation {
        self.location
    }

    /// Encodes this value as stable file-artifact index metadata.
    pub fn encode_index_value(self) -> [u8; PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN] {
        let mut bytes = [0; PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN];
        bytes[..PERSIST_BLOB_INDEX_KEY_LEN].copy_from_slice(&self.blob_key().index_bytes());
        bytes[PERSIST_BLOB_INDEX_KEY_LEN..].copy_from_slice(&self.location.encode_index_value());
        bytes
    }

    /// Decodes stable file-artifact index metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN`], if the embedded blob key is
    /// malformed, or if the embedded blob key does not point at `files/`.
    pub fn decode_index_value(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN {
            return Err(PersistPackFormatError::ShortFileArtifactIndexValue {
                expected: PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN,
                actual: bytes.len(),
            });
        }
        let blob_key = PersistBlobKey::decode_index_bytes(&bytes[..PERSIST_BLOB_INDEX_KEY_LEN])?;
        if blob_key.store() != PersistBlobStore::Files {
            return Err(PersistPackFormatError::InvalidFileArtifactBlobStore {
                store: blob_key.store(),
            });
        }
        let location =
            PersistBlobLocation::decode_index_value(&bytes[PERSIST_BLOB_INDEX_KEY_LEN..])?;
        Ok(Self::new(blob_key.hash(), location))
    }
}

/// A complete key/value record for the future file-artifact index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistFileArtifactIndexEntry {
    key: PersistFileArtifactKey,
    value: PersistFileArtifactIndexValue,
}

impl PersistFileArtifactIndexEntry {
    /// Creates a file-artifact index entry from its mapping key and value.
    pub const fn new(key: PersistFileArtifactKey, value: PersistFileArtifactIndexValue) -> Self {
        Self { key, value }
    }

    /// Returns the file-artifact mapping key.
    pub const fn key(self) -> PersistFileArtifactKey {
        self.key
    }

    /// Returns the file-artifact blob lookup value.
    pub const fn value(self) -> PersistFileArtifactIndexValue {
        self.value
    }

    /// Encodes this record as stable file-artifact index bytes.
    pub fn encode_index_entry(self) -> [u8; PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN] {
        let encoded = persist_file_artifact_entry_to_engine(self).encode();
        let mut bytes = [0; PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN];
        bytes.copy_from_slice(&encoded);
        bytes
    }

    /// Decodes a complete file-artifact index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN`], if the key is malformed, or
    /// if the value is malformed.
    pub fn decode_index_entry(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        let entry =
            EngineArtifactIndexEntry::decode(bytes).map_err(engine_file_artifact_format_error)?;
        engine_file_artifact_entry_to_persist(entry)
    }
}

fn persist_file_artifact_key_to_engine(key: PersistFileArtifactKey) -> EngineArtifactIndexKey {
    EngineArtifactIndexKey::new(PERSIST_FILE_ARTIFACT_INDEX_TAG, key.hash().as_bytes())
}

fn engine_file_artifact_key_to_persist(
    key: EngineArtifactIndexKey,
) -> Result<PersistFileArtifactKey, PersistPackFormatError> {
    PersistFileArtifactKey::decode_index_bytes(&key.encode())
}

fn persist_file_artifact_value_to_engine(
    value: PersistFileArtifactIndexValue,
) -> EngineArtifactIndexValue {
    EngineArtifactIndexValue::from_bytes(value.encode_index_value())
}

fn engine_file_artifact_value_to_persist(
    value: EngineArtifactIndexValue,
) -> Result<PersistFileArtifactIndexValue, PersistPackFormatError> {
    PersistFileArtifactIndexValue::decode_index_value(&value.encode())
}

fn persist_file_artifact_entry_to_engine(
    entry: PersistFileArtifactIndexEntry,
) -> EngineArtifactIndexEntry {
    EngineArtifactIndexEntry::new(
        persist_file_artifact_key_to_engine(entry.key()),
        persist_file_artifact_value_to_engine(entry.value()),
    )
}

fn engine_file_artifact_entry_to_persist(
    entry: EngineArtifactIndexEntry,
) -> Result<PersistFileArtifactIndexEntry, PersistPackFormatError> {
    Ok(PersistFileArtifactIndexEntry::new(
        engine_file_artifact_key_to_persist(entry.key())?,
        engine_file_artifact_value_to_persist(entry.value())?,
    ))
}

fn engine_file_artifact_index_error(
    error: EngineArtifactIndexError,
) -> PersistFileArtifactIndexError {
    match error {
        EngineArtifactIndexError::CreateParent { path, source } => {
            PersistFileArtifactIndexError::CreateParent { path, source }
        }
        EngineArtifactIndexError::Open { path, source } => {
            PersistFileArtifactIndexError::Open { path, source }
        }
        EngineArtifactIndexError::Metadata { path, source } => {
            PersistFileArtifactIndexError::Metadata { path, source }
        }
        EngineArtifactIndexError::Read { path, source } => {
            PersistFileArtifactIndexError::Read { path, source }
        }
        EngineArtifactIndexError::Write { path, source } => {
            PersistFileArtifactIndexError::Write { path, source }
        }
        EngineArtifactIndexError::Format { path, source } => {
            PersistFileArtifactIndexError::Format {
                path,
                source: engine_file_artifact_format_error(source),
            }
        }
    }
}

fn engine_file_artifact_format_error(
    error: EngineArtifactIndexFormatError,
) -> PersistPackFormatError {
    match error {
        EngineArtifactIndexFormatError::ShortKey { expected, actual } => {
            PersistPackFormatError::ShortFileArtifactIndexKey { expected, actual }
        }
        EngineArtifactIndexFormatError::ShortValue { expected, actual } => {
            PersistPackFormatError::ShortFileArtifactIndexValue { expected, actual }
        }
        EngineArtifactIndexFormatError::ShortEntry { expected, actual } => {
            PersistPackFormatError::ShortFileArtifactIndexEntry { expected, actual }
        }
    }
}

/// A fixed-record index file for durable frontend file-artifact mappings.
///
/// This is a simple durable substrate for tests and future cache integration.
/// It is not the final LMDB/redb metadata engine: writes append one fixed
/// record at a time, and lookups scan records linearly and return the newest
/// matching entry.
#[derive(Clone, Debug)]
pub struct PersistFileArtifactIndex {
    engine: EngineArtifactIndex,
}

impl PersistFileArtifactIndex {
    /// Opens or initializes a fixed-record file-artifact index file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if parent directories or the
    /// index file cannot be created/opened, or if the existing file ends with a
    /// partial fixed-width record.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistFileArtifactIndexError> {
        let engine =
            EngineArtifactIndex::open(path.into()).map_err(engine_file_artifact_index_error)?;
        Ok(Self { engine })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Appends one file-artifact index entry.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entry(
        &self,
        entry: PersistFileArtifactIndexEntry,
    ) -> Result<(), PersistFileArtifactIndexError> {
        self.engine
            .append_entry(persist_file_artifact_entry_to_engine(entry))
            .map_err(engine_file_artifact_index_error)
    }

    /// Looks up the newest file-artifact value for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the index cannot be opened,
    /// read, or decoded.
    pub fn lookup(
        &self,
        key: PersistFileArtifactKey,
    ) -> Result<Option<PersistFileArtifactIndexValue>, PersistFileArtifactIndexError> {
        let mut found = None;
        for entry in self.entries()? {
            if entry.key() == key {
                found = Some(entry.value());
            }
        }
        Ok(found)
    }

    /// Returns the newest entry for every file-artifact key.
    ///
    /// Entries are returned in stable encoded-key order. If a key appears
    /// multiple times in the append-only sidecar, only its newest value is
    /// returned.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the index cannot be
    /// created, opened, inspected, read, or decoded.
    pub fn latest_entries(
        &self,
    ) -> Result<Vec<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexError> {
        let mut latest = std::collections::BTreeMap::new();
        for entry in self.entries()? {
            latest.insert(entry.key().index_bytes(), entry);
        }
        Ok(latest.into_values().collect())
    }

    /// Rewrites the sidecar to the newest entry for every file-artifact key.
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
    /// Returns [`PersistFileArtifactIndexError`] if the index cannot be
    /// created, opened, inspected, read, decoded, written, flushed, or renamed
    /// into place.
    pub fn compact_latest_entries(&self) -> Result<usize, PersistFileArtifactIndexError> {
        let entries = self.latest_entries()?;
        let entries = entries
            .iter()
            .copied()
            .map(persist_file_artifact_entry_to_engine)
            .collect::<Vec<_>>();
        self.engine
            .replace_entries(&entries)
            .map_err(engine_file_artifact_index_error)
    }

    /// Writes `entries` exactly to `path`, replacing any stale file there.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the staged index cannot be
    /// removed, created, written, or flushed.
    pub(super) fn write_entries_to(
        path: impl Into<PathBuf>,
        entries: &[PersistFileArtifactIndexEntry],
    ) -> Result<usize, PersistFileArtifactIndexError> {
        let entries = entries
            .iter()
            .copied()
            .map(persist_file_artifact_entry_to_engine)
            .collect::<Vec<_>>();
        EngineArtifactIndex::write_entries_to(path.into(), &entries)
            .map_err(engine_file_artifact_index_error)
    }

    fn entries(&self) -> Result<Vec<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexError> {
        self.engine
            .entries()
            .map_err(engine_file_artifact_index_error)?
            .into_iter()
            .map(engine_file_artifact_entry_to_persist)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| PersistFileArtifactIndexError::Format {
                path: self.path().to_path_buf(),
                source,
            })
    }
}

/// A stable index key for a durable frontend parse artifact.
///
/// The key is derived from the parse-cache key, which already includes source
/// bytes, parser schema version, and parse flags. Unlike
/// [`PersistFileArtifactKey`], this identity is not tied to a filesystem path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistParseArtifactKey {
    hash: DurableBlake3Hash,
}

impl PersistParseArtifactKey {
    /// Creates a persistent parse-artifact index key from a parse-cache key.
    pub const fn from_parse_cache_key(parse_key: ParseCacheKey) -> Self {
        Self {
            hash: DurableBlake3Hash::from_bytes(parse_key.as_bytes()),
        }
    }

    /// Returns the durable hash of the parse-artifact mapping identity.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.hash
    }

    /// Returns the stable binary key for the parse-artifact index.
    pub fn index_bytes(self) -> [u8; PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN] {
        let mut bytes = [0; PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN];
        bytes[0] = PERSIST_PARSE_ARTIFACT_INDEX_TAG;
        bytes[1..].copy_from_slice(&self.hash.as_bytes());
        bytes
    }

    /// Decodes the stable binary key for the parse-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN`] or carries an unexpected index
    /// tag.
    pub fn decode_index_bytes(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN {
            return Err(PersistPackFormatError::ShortParseArtifactIndexKey {
                expected: PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != PERSIST_PARSE_ARTIFACT_INDEX_TAG {
            return Err(PersistPackFormatError::InvalidParseArtifactIndexTag { tag: bytes[0] });
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[1..PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN]);
        Ok(Self {
            hash: DurableBlake3Hash::from_bytes(hash),
        })
    }
}

/// A stable index value for a durable frontend parse artifact.
///
/// The value points at a blob in the `files/` pack. The blob payload format is
/// intentionally outside this codec; the pack still verifies the payload hash
/// on read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistParseArtifactIndexValue {
    blob_hash: DurableBlake3Hash,
    location: PersistBlobLocation,
}

impl PersistParseArtifactIndexValue {
    /// Creates a parse-artifact index value for a `files/` blob hash and location.
    pub const fn new(blob_hash: DurableBlake3Hash, location: PersistBlobLocation) -> Self {
        Self {
            blob_hash,
            location,
        }
    }

    /// Returns the durable hash of the parse artifact blob.
    pub const fn blob_hash(self) -> DurableBlake3Hash {
        self.blob_hash
    }

    /// Returns the typed blob lookup key in the `files/` store.
    pub const fn blob_key(self) -> PersistBlobKey {
        PersistBlobKey::for_file(self.blob_hash)
    }

    /// Returns the blob packfile location.
    pub const fn location(self) -> PersistBlobLocation {
        self.location
    }

    /// Encodes this value as stable parse-artifact index metadata.
    pub fn encode_index_value(self) -> [u8; PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN] {
        let mut bytes = [0; PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN];
        bytes[..PERSIST_BLOB_INDEX_KEY_LEN].copy_from_slice(&self.blob_key().index_bytes());
        bytes[PERSIST_BLOB_INDEX_KEY_LEN..].copy_from_slice(&self.location.encode_index_value());
        bytes
    }

    /// Decodes stable parse-artifact index metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN`], if the embedded blob key is
    /// malformed, or if the embedded blob key does not point at `files/`.
    pub fn decode_index_value(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN {
            return Err(PersistPackFormatError::ShortParseArtifactIndexValue {
                expected: PERSIST_PARSE_ARTIFACT_INDEX_VALUE_LEN,
                actual: bytes.len(),
            });
        }
        let blob_key = PersistBlobKey::decode_index_bytes(&bytes[..PERSIST_BLOB_INDEX_KEY_LEN])?;
        if blob_key.store() != PersistBlobStore::Files {
            return Err(PersistPackFormatError::InvalidParseArtifactBlobStore {
                store: blob_key.store(),
            });
        }
        let location =
            PersistBlobLocation::decode_index_value(&bytes[PERSIST_BLOB_INDEX_KEY_LEN..])?;
        Ok(Self::new(blob_key.hash(), location))
    }
}

/// A complete key/value record for the parse-artifact index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistParseArtifactIndexEntry {
    key: PersistParseArtifactKey,
    value: PersistParseArtifactIndexValue,
}

impl PersistParseArtifactIndexEntry {
    /// Creates a parse-artifact index entry from its mapping key and value.
    pub const fn new(key: PersistParseArtifactKey, value: PersistParseArtifactIndexValue) -> Self {
        Self { key, value }
    }

    /// Returns the parse-artifact mapping key.
    pub const fn key(self) -> PersistParseArtifactKey {
        self.key
    }

    /// Returns the parse-artifact blob lookup value.
    pub const fn value(self) -> PersistParseArtifactIndexValue {
        self.value
    }

    /// Encodes this record as stable parse-artifact index bytes.
    pub fn encode_index_entry(self) -> [u8; PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN] {
        let encoded = persist_parse_artifact_entry_to_engine(self).encode();
        let mut bytes = [0; PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN];
        bytes.copy_from_slice(&encoded);
        bytes
    }

    /// Decodes a complete parse-artifact index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN`], if the key is malformed, or
    /// if the value is malformed.
    pub fn decode_index_entry(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        let entry =
            EngineArtifactIndexEntry::decode(bytes).map_err(engine_parse_artifact_format_error)?;
        engine_parse_artifact_entry_to_persist(entry)
    }
}

fn persist_parse_artifact_key_to_engine(key: PersistParseArtifactKey) -> EngineArtifactIndexKey {
    EngineArtifactIndexKey::new(PERSIST_PARSE_ARTIFACT_INDEX_TAG, key.hash().as_bytes())
}

fn engine_parse_artifact_key_to_persist(
    key: EngineArtifactIndexKey,
) -> Result<PersistParseArtifactKey, PersistPackFormatError> {
    PersistParseArtifactKey::decode_index_bytes(&key.encode())
}

fn persist_parse_artifact_value_to_engine(
    value: PersistParseArtifactIndexValue,
) -> EngineArtifactIndexValue {
    EngineArtifactIndexValue::from_bytes(value.encode_index_value())
}

fn engine_parse_artifact_value_to_persist(
    value: EngineArtifactIndexValue,
) -> Result<PersistParseArtifactIndexValue, PersistPackFormatError> {
    PersistParseArtifactIndexValue::decode_index_value(&value.encode())
}

fn persist_parse_artifact_entry_to_engine(
    entry: PersistParseArtifactIndexEntry,
) -> EngineArtifactIndexEntry {
    EngineArtifactIndexEntry::new(
        persist_parse_artifact_key_to_engine(entry.key()),
        persist_parse_artifact_value_to_engine(entry.value()),
    )
}

fn engine_parse_artifact_entry_to_persist(
    entry: EngineArtifactIndexEntry,
) -> Result<PersistParseArtifactIndexEntry, PersistPackFormatError> {
    Ok(PersistParseArtifactIndexEntry::new(
        engine_parse_artifact_key_to_persist(entry.key())?,
        engine_parse_artifact_value_to_persist(entry.value())?,
    ))
}

fn engine_parse_artifact_index_error(
    error: EngineArtifactIndexError,
) -> PersistParseArtifactIndexError {
    match error {
        EngineArtifactIndexError::CreateParent { path, source } => {
            PersistParseArtifactIndexError::CreateParent { path, source }
        }
        EngineArtifactIndexError::Open { path, source } => {
            PersistParseArtifactIndexError::Open { path, source }
        }
        EngineArtifactIndexError::Metadata { path, source } => {
            PersistParseArtifactIndexError::Metadata { path, source }
        }
        EngineArtifactIndexError::Read { path, source } => {
            PersistParseArtifactIndexError::Read { path, source }
        }
        EngineArtifactIndexError::Write { path, source } => {
            PersistParseArtifactIndexError::Write { path, source }
        }
        EngineArtifactIndexError::Format { path, source } => {
            PersistParseArtifactIndexError::Format {
                path,
                source: engine_parse_artifact_format_error(source),
            }
        }
    }
}

fn engine_parse_artifact_format_error(
    error: EngineArtifactIndexFormatError,
) -> PersistPackFormatError {
    match error {
        EngineArtifactIndexFormatError::ShortKey { expected, actual } => {
            PersistPackFormatError::ShortParseArtifactIndexKey { expected, actual }
        }
        EngineArtifactIndexFormatError::ShortValue { expected, actual } => {
            PersistPackFormatError::ShortParseArtifactIndexValue { expected, actual }
        }
        EngineArtifactIndexFormatError::ShortEntry { expected, actual } => {
            PersistPackFormatError::ShortParseArtifactIndexEntry { expected, actual }
        }
    }
}

/// A fixed-record index file for durable frontend parse-artifact mappings.
///
/// This is a simple durable substrate for tests and future cache integration.
/// It is not the final LMDB/redb metadata engine: writes append one fixed
/// record at a time, and lookups scan records linearly and return the newest
/// matching entry.
#[derive(Clone, Debug)]
pub struct PersistParseArtifactIndex {
    engine: EngineArtifactIndex,
}

impl PersistParseArtifactIndex {
    /// Opens or initializes a fixed-record parse-artifact index file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if parent directories or the
    /// index file cannot be created/opened, or if the existing file ends with a
    /// partial fixed-width record.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistParseArtifactIndexError> {
        let engine =
            EngineArtifactIndex::open(path.into()).map_err(engine_parse_artifact_index_error)?;
        Ok(Self { engine })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Appends one parse-artifact index entry.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entry(
        &self,
        entry: PersistParseArtifactIndexEntry,
    ) -> Result<(), PersistParseArtifactIndexError> {
        self.engine
            .append_entry(persist_parse_artifact_entry_to_engine(entry))
            .map_err(engine_parse_artifact_index_error)
    }

    /// Looks up the newest parse-artifact value for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the index cannot be opened,
    /// read, or decoded.
    pub fn lookup(
        &self,
        key: PersistParseArtifactKey,
    ) -> Result<Option<PersistParseArtifactIndexValue>, PersistParseArtifactIndexError> {
        let mut found = None;
        for entry in self.entries()? {
            if entry.key() == key {
                found = Some(entry.value());
            }
        }
        Ok(found)
    }

    /// Returns the newest entry for every parse-artifact key.
    ///
    /// Entries are returned in stable encoded-key order. If a key appears
    /// multiple times in the append-only sidecar, only its newest value is
    /// returned.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the index cannot be
    /// created, opened, inspected, read, or decoded.
    pub fn latest_entries(
        &self,
    ) -> Result<Vec<PersistParseArtifactIndexEntry>, PersistParseArtifactIndexError> {
        let mut latest = std::collections::BTreeMap::new();
        for entry in self.entries()? {
            latest.insert(entry.key().index_bytes(), entry);
        }
        Ok(latest.into_values().collect())
    }

    /// Rewrites the sidecar to the newest entry for every parse-artifact key.
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
    /// Returns [`PersistParseArtifactIndexError`] if the index cannot be
    /// created, opened, inspected, read, decoded, written, flushed, or renamed
    /// into place.
    pub fn compact_latest_entries(&self) -> Result<usize, PersistParseArtifactIndexError> {
        let entries = self.latest_entries()?;
        let entries = entries
            .iter()
            .copied()
            .map(persist_parse_artifact_entry_to_engine)
            .collect::<Vec<_>>();
        self.engine
            .replace_entries(&entries)
            .map_err(engine_parse_artifact_index_error)
    }

    /// Writes `entries` exactly to `path`, replacing any stale file there.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the staged index cannot be
    /// removed, created, written, or flushed.
    pub(super) fn write_entries_to(
        path: impl Into<PathBuf>,
        entries: &[PersistParseArtifactIndexEntry],
    ) -> Result<usize, PersistParseArtifactIndexError> {
        let entries = entries
            .iter()
            .copied()
            .map(persist_parse_artifact_entry_to_engine)
            .collect::<Vec<_>>();
        EngineArtifactIndex::write_entries_to(path.into(), &entries)
            .map_err(engine_parse_artifact_index_error)
    }

    fn entries(
        &self,
    ) -> Result<Vec<PersistParseArtifactIndexEntry>, PersistParseArtifactIndexError> {
        self.engine
            .entries()
            .map_err(engine_parse_artifact_index_error)?
            .into_iter()
            .map(engine_parse_artifact_entry_to_persist)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| PersistParseArtifactIndexError::Format {
                path: self.path().to_path_buf(),
                source,
            })
    }
}

/// A stable index key for durable demand-node metadata.
///
/// This key lives in a persistent BLAKE3 domain separate from the hot
/// in-process `DemandCacheKey` domain. It can address expression nodes keyed
/// by expression identity plus ordered free-variable value hashes, or impure
/// input leaves keyed by their typed input identity hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersistNodeMetadataKey {
    hash: DurableBlake3Hash,
}

impl PersistNodeMetadataKey {
    /// Creates a persistent metadata key for an expression demand node.
    ///
    /// `free_var_value_hashes` must be supplied in the same canonical slot
    /// order used for the in-process demand-cache key.
    pub fn for_expression<I>(identity: CacheExprIdentity, free_var_value_hashes: I) -> Self
    where
        I: IntoIterator<Item = DurableBlake3Hash>,
    {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PERSIST_NODE_METADATA_EXPRESSION_KEY_PERSONALIZATION);
        hasher.update(&identity.source_hash().as_bytes());
        hasher.update(&identity.node().as_u32().to_le_bytes());
        for value_hash in free_var_value_hashes {
            update_persist_index_chunk(&mut hasher, &value_hash.as_bytes());
        }
        Self {
            hash: DurableBlake3Hash::from_hasher(hasher),
        }
    }

    /// Creates a persistent metadata key for an impure-input leaf node.
    pub fn for_impure_input(identity_hash: DurableBlake3Hash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PERSIST_NODE_METADATA_IMPURE_INPUT_KEY_PERSONALIZATION);
        hasher.update(&identity_hash.as_bytes());
        Self {
            hash: DurableBlake3Hash::from_hasher(hasher),
        }
    }

    /// Returns the durable hash of the demand-node metadata identity.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.hash
    }

    /// Returns the stable binary key for the future demand-node metadata index.
    pub fn index_bytes(self) -> [u8; PERSIST_NODE_METADATA_INDEX_KEY_LEN] {
        let mut bytes = [0; PERSIST_NODE_METADATA_INDEX_KEY_LEN];
        bytes[0] = PERSIST_NODE_METADATA_INDEX_TAG;
        bytes[1..].copy_from_slice(&self.hash.as_bytes());
        bytes
    }

    /// Decodes the stable binary key for the demand-node metadata index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_NODE_METADATA_INDEX_KEY_LEN`] or carries an unexpected index
    /// tag.
    pub fn decode_index_bytes(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_NODE_METADATA_INDEX_KEY_LEN {
            return Err(PersistPackFormatError::ShortNodeMetadataIndexKey {
                expected: PERSIST_NODE_METADATA_INDEX_KEY_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != PERSIST_NODE_METADATA_INDEX_TAG {
            return Err(PersistPackFormatError::InvalidNodeMetadataIndexTag { tag: bytes[0] });
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[1..PERSIST_NODE_METADATA_INDEX_KEY_LEN]);
        Ok(Self {
            hash: DurableBlake3Hash::from_bytes(hash),
        })
    }
}

/// A stable value for durable demand-node metadata.
///
/// This fixed-width value stores the cross-run materialization reuse counters
/// plus the newest materialized cached-expression value hash for the node, when
/// one is known. The value hash links a demand-node metadata key to the indexed
/// `values/` pack; the pack's own content-addressed index remains the source of
/// the payload location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistNodeMetadataIndexValue {
    materialization_reuse: MaterializationReuse,
    materialized_value_hash: Option<ValueHash>,
}

impl PersistNodeMetadataIndexValue {
    /// Creates node metadata from materialization reuse counters.
    pub const fn new(materialization_reuse: MaterializationReuse) -> Self {
        Self {
            materialization_reuse,
            materialized_value_hash: None,
        }
    }

    /// Creates node metadata from reuse counters and a materialized value hash.
    pub const fn with_materialized_value_hash(
        materialization_reuse: MaterializationReuse,
        value_hash: ValueHash,
    ) -> Self {
        Self {
            materialization_reuse,
            materialized_value_hash: Some(value_hash),
        }
    }

    /// Returns the materialization reuse counters.
    pub const fn materialization_reuse(self) -> MaterializationReuse {
        self.materialization_reuse
    }

    /// Returns the newest materialized cached-expression value hash, if any.
    pub const fn materialized_value_hash(self) -> Option<ValueHash> {
        self.materialized_value_hash
    }

    /// Returns this metadata with updated materialization reuse counters.
    pub const fn with_materialization_reuse(
        self,
        materialization_reuse: MaterializationReuse,
    ) -> Self {
        Self {
            materialization_reuse,
            materialized_value_hash: self.materialized_value_hash,
        }
    }

    /// Returns this metadata with an updated materialized value hash.
    pub const fn with_value_hash(self, value_hash: ValueHash) -> Self {
        Self {
            materialization_reuse: self.materialization_reuse,
            materialized_value_hash: Some(value_hash),
        }
    }

    /// Encodes this value as stable node metadata index bytes.
    pub fn encode_index_value(self) -> [u8; PERSIST_NODE_METADATA_INDEX_VALUE_LEN] {
        let mut bytes = [0; PERSIST_NODE_METADATA_INDEX_VALUE_LEN];
        bytes[..PERSIST_MATERIALIZATION_REUSE_LEN]
            .copy_from_slice(&self.materialization_reuse.encode_persist_metadata());
        let value_hash_offset = PERSIST_MATERIALIZATION_REUSE_LEN;
        match self.materialized_value_hash {
            Some(value_hash) => {
                bytes[value_hash_offset] = PERSIST_NODE_METADATA_VALUE_HASH_PRESENT_TAG;
                bytes[value_hash_offset + 1..]
                    .copy_from_slice(&value_hash.as_durable_hash().as_bytes());
            }
            None => {
                bytes[value_hash_offset] = PERSIST_NODE_METADATA_VALUE_HASH_NONE_TAG;
            }
        }
        bytes
    }

    /// Decodes stable node metadata index bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_NODE_METADATA_INDEX_VALUE_LEN`] or if the optional value-hash
    /// field is not canonical.
    pub fn decode_index_value(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_NODE_METADATA_INDEX_VALUE_LEN {
            return Err(PersistPackFormatError::ShortNodeMetadataIndexValue {
                expected: PERSIST_NODE_METADATA_INDEX_VALUE_LEN,
                actual: bytes.len(),
            });
        }
        let materialization_reuse = MaterializationReuse::decode_persist_metadata(
            &bytes[..PERSIST_MATERIALIZATION_REUSE_LEN],
        )?;
        let value_hash_offset = PERSIST_MATERIALIZATION_REUSE_LEN;
        let value_hash_payload =
            &bytes[value_hash_offset + 1..PERSIST_NODE_METADATA_INDEX_VALUE_LEN];
        let materialized_value_hash = match bytes[value_hash_offset] {
            PERSIST_NODE_METADATA_VALUE_HASH_NONE_TAG => {
                if value_hash_payload.iter().any(|byte| *byte != 0) {
                    return Err(PersistPackFormatError::NonZeroNodeMetadataValueHashPadding);
                }
                None
            }
            PERSIST_NODE_METADATA_VALUE_HASH_PRESENT_TAG => {
                let mut hash = [0; 32];
                hash.copy_from_slice(value_hash_payload);
                Some(ValueHash::from_canonical_value_hash(
                    DurableBlake3Hash::from_bytes(hash),
                ))
            }
            tag => return Err(PersistPackFormatError::InvalidNodeMetadataValueHashTag { tag }),
        };
        Ok(Self {
            materialization_reuse,
            materialized_value_hash,
        })
    }
}

/// A complete key/value record for the demand-node metadata index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistNodeMetadataIndexEntry {
    key: PersistNodeMetadataKey,
    value: PersistNodeMetadataIndexValue,
}

impl PersistNodeMetadataIndexEntry {
    /// Creates a node metadata index entry from its key and value.
    pub const fn new(key: PersistNodeMetadataKey, value: PersistNodeMetadataIndexValue) -> Self {
        Self { key, value }
    }

    /// Returns the node metadata key.
    pub const fn key(self) -> PersistNodeMetadataKey {
        self.key
    }

    /// Returns the node metadata value.
    pub const fn value(self) -> PersistNodeMetadataIndexValue {
        self.value
    }

    /// Encodes this record as stable node metadata index bytes.
    pub fn encode_index_entry(self) -> [u8; PERSIST_NODE_METADATA_INDEX_ENTRY_LEN] {
        let encoded = persist_node_metadata_entry_to_engine(self).encode();
        let mut bytes = [0; PERSIST_NODE_METADATA_INDEX_ENTRY_LEN];
        bytes.copy_from_slice(&encoded);
        bytes
    }

    /// Decodes a complete node metadata index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_NODE_METADATA_INDEX_ENTRY_LEN`], if the key is malformed, or
    /// if the value is malformed.
    pub fn decode_index_entry(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        let entry =
            EngineNodeMetadataEntry::decode(bytes).map_err(engine_node_metadata_format_error)?;
        engine_node_metadata_entry_to_persist(entry)
    }
}

fn persist_node_metadata_key_to_engine(key: PersistNodeMetadataKey) -> EngineNodeMetadataKey {
    EngineNodeMetadataKey::new(PERSIST_NODE_METADATA_INDEX_TAG, key.hash().as_bytes())
}

fn engine_node_metadata_key_to_persist(
    key: EngineNodeMetadataKey,
) -> Result<PersistNodeMetadataKey, PersistPackFormatError> {
    PersistNodeMetadataKey::decode_index_bytes(&key.encode())
}

fn persist_node_metadata_value_to_engine(
    value: PersistNodeMetadataIndexValue,
) -> EngineNodeMetadataValue {
    EngineNodeMetadataValue::from_bytes(value.encode_index_value())
}

fn engine_node_metadata_value_to_persist(
    value: EngineNodeMetadataValue,
) -> Result<PersistNodeMetadataIndexValue, PersistPackFormatError> {
    PersistNodeMetadataIndexValue::decode_index_value(&value.encode())
}

fn persist_node_metadata_entry_to_engine(
    entry: PersistNodeMetadataIndexEntry,
) -> EngineNodeMetadataEntry {
    EngineNodeMetadataEntry::new(
        persist_node_metadata_key_to_engine(entry.key()),
        persist_node_metadata_value_to_engine(entry.value()),
    )
}

fn engine_node_metadata_entry_to_persist(
    entry: EngineNodeMetadataEntry,
) -> Result<PersistNodeMetadataIndexEntry, PersistPackFormatError> {
    Ok(PersistNodeMetadataIndexEntry::new(
        engine_node_metadata_key_to_persist(entry.key())?,
        engine_node_metadata_value_to_persist(entry.value())?,
    ))
}

fn engine_node_metadata_index_error(
    error: EngineNodeMetadataIndexError,
) -> PersistNodeMetadataIndexError {
    match error {
        EngineNodeMetadataIndexError::CreateParent { path, source } => {
            PersistNodeMetadataIndexError::CreateParent { path, source }
        }
        EngineNodeMetadataIndexError::Open { path, source } => {
            PersistNodeMetadataIndexError::Open { path, source }
        }
        EngineNodeMetadataIndexError::Metadata { path, source } => {
            PersistNodeMetadataIndexError::Metadata { path, source }
        }
        EngineNodeMetadataIndexError::Read { path, source } => {
            PersistNodeMetadataIndexError::Read { path, source }
        }
        EngineNodeMetadataIndexError::Write { path, source } => {
            PersistNodeMetadataIndexError::Write { path, source }
        }
        EngineNodeMetadataIndexError::Format { path, source } => {
            PersistNodeMetadataIndexError::Format {
                path,
                source: engine_node_metadata_format_error(source),
            }
        }
    }
}

fn engine_node_metadata_format_error(
    error: EngineNodeMetadataFormatError,
) -> PersistPackFormatError {
    match error {
        EngineNodeMetadataFormatError::ShortKey { expected, actual } => {
            PersistPackFormatError::ShortNodeMetadataIndexKey { expected, actual }
        }
        EngineNodeMetadataFormatError::ShortValue { expected, actual } => {
            PersistPackFormatError::ShortNodeMetadataIndexValue { expected, actual }
        }
        EngineNodeMetadataFormatError::ShortEntry { expected, actual } => {
            PersistPackFormatError::ShortNodeMetadataIndexEntry { expected, actual }
        }
    }
}

/// A stable payload for one persisted node verifying trace.
///
/// Ordinary payloads preserve evaluator trace order and store only cacheable
/// impure-input fingerprints: each record carries the typed input identity
/// parts plus the observed-result hash. Tombstone payloads carry no inputs and
/// explicitly invalidate older trace records for the same node. The eventual
/// persistent demand-graph sidecar can attach ordinary payload bytes to an
/// expression node and replay the fingerprints during durable-hit revalidation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistNodeTracePayload {
    inputs: Vec<CacheableInputFingerprint>,
    tombstone: bool,
}

impl PersistNodeTracePayload {
    /// Creates a tombstone payload that invalidates older trace records for a node.
    pub fn tombstone() -> Self {
        Self {
            inputs: Vec::new(),
            tombstone: true,
        }
    }

    /// Creates a node trace payload from cacheable input fingerprints.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if storage for the input list
    /// cannot be reserved.
    pub fn from_cacheable_inputs<I>(inputs: I) -> Result<Self, PersistNodeTracePayloadError>
    where
        I: IntoIterator<Item = CacheableInputFingerprint>,
    {
        let inputs = inputs.into_iter();
        let (minimum, _) = inputs.size_hint();
        let mut stored = Vec::new();
        stored
            .try_reserve_exact(minimum)
            .map_err(|_| PersistNodeTracePayloadError::InputAllocationFailed { inputs: minimum })?;
        for input in inputs {
            if stored.len() == stored.capacity() {
                let requested = stored.len().saturating_add(1);
                stored.try_reserve_exact(1).map_err(|_| {
                    PersistNodeTracePayloadError::InputAllocationFailed { inputs: requested }
                })?;
            }
            stored.push(input);
        }
        Ok(Self {
            inputs: stored,
            tombstone: false,
        })
    }

    /// Creates a node trace payload from an evaluator impure-input trace.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if the trace contains an
    /// uncacheable input or if storage for the input list cannot be reserved.
    pub fn from_impure_trace<'a, I>(trace: I) -> Result<Self, PersistNodeTracePayloadError>
    where
        I: IntoIterator<Item = &'a ImpureInputFingerprint>,
    {
        let trace = trace.into_iter();
        let (minimum, _) = trace.size_hint();
        let mut inputs = Vec::new();
        inputs
            .try_reserve_exact(minimum)
            .map_err(|_| PersistNodeTracePayloadError::InputAllocationFailed { inputs: minimum })?;
        for fingerprint in trace {
            match fingerprint {
                ImpureInputFingerprint::Cacheable(input) => {
                    if inputs.len() == inputs.capacity() {
                        let requested = inputs.len().saturating_add(1);
                        inputs.try_reserve_exact(1).map_err(|_| {
                            PersistNodeTracePayloadError::InputAllocationFailed {
                                inputs: requested,
                            }
                        })?;
                    }
                    inputs.push(input.clone());
                }
                ImpureInputFingerprint::Uncacheable(input) => {
                    return Err(PersistNodeTracePayloadError::UncacheableInput { input: *input });
                }
            }
        }
        Ok(Self {
            inputs,
            tombstone: false,
        })
    }

    /// Returns whether this payload tombstones older traces for the same node.
    pub const fn is_tombstone(&self) -> bool {
        self.tombstone
    }

    /// Returns the cacheable input fingerprints in trace order.
    pub fn inputs(&self) -> &[CacheableInputFingerprint] {
        &self.inputs
    }

    /// Encodes this node trace payload as stable little-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if the input count or any
    /// subject length cannot be represented in the on-disk format, or if
    /// encoded output storage cannot be reserved.
    pub fn encode(&self) -> Result<Vec<u8>, PersistNodeTracePayloadError> {
        let count = if self.tombstone {
            PERSIST_NODE_TRACE_PAYLOAD_TOMBSTONE_COUNT
        } else {
            u64::try_from(self.inputs.len()).map_err(|_| {
                PersistNodeTracePayloadError::EncodedInputCountOverflow {
                    inputs: self.inputs.len(),
                }
            })?
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN)
            .map_err(|_| PersistNodeTracePayloadError::PayloadAllocationFailed {
                len: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
            })?;
        bytes.extend_from_slice(&PERSIST_NODE_TRACE_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&PERSIST_NODE_TRACE_PAYLOAD_VERSION.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());

        if self.tombstone {
            return Ok(bytes);
        }

        for input in &self.inputs {
            let identity = input.identity();
            let subject = identity.subject();
            let subject_len = u64::try_from(subject.len()).map_err(|_| {
                PersistNodeTracePayloadError::EncodedSubjectLengthOverflow { len: subject.len() }
            })?;
            let record_len = PERSIST_NODE_TRACE_INPUT_FIXED_LEN
                .checked_add(subject.len())
                .ok_or(PersistNodeTracePayloadError::PayloadAllocationFailed { len: usize::MAX })?;
            bytes.try_reserve_exact(record_len).map_err(|_| {
                PersistNodeTracePayloadError::PayloadAllocationFailed { len: record_len }
            })?;
            bytes.push(node_trace_input_kind_tag(identity.kind()));
            bytes.push(node_trace_input_mode_tag(identity.mode()));
            bytes.extend_from_slice(&subject_len.to_le_bytes());
            bytes.extend_from_slice(&input.observation_hash().as_bytes());
            bytes.extend_from_slice(subject);
        }

        Ok(bytes)
    }

    /// Decodes a stable node trace payload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTracePayloadError`] if `bytes` has the wrong magic
    /// or version, contains malformed input records, contains trailing bytes,
    /// or cannot reconstruct an input fingerprint.
    pub fn decode(bytes: &[u8]) -> Result<Self, PersistNodeTracePayloadError> {
        if bytes.len() < PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN {
            return Err(PersistNodeTracePayloadError::ShortPayload {
                expected: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let mut magic = [0; 16];
        magic.copy_from_slice(&bytes[..16]);
        if magic != PERSIST_NODE_TRACE_PAYLOAD_MAGIC {
            return Err(PersistNodeTracePayloadError::InvalidMagic { actual: magic });
        }

        let version = read_u32(&bytes[16..20]);
        if !(PERSIST_NODE_TRACE_PAYLOAD_MIN_VERSION..=PERSIST_NODE_TRACE_PAYLOAD_VERSION)
            .contains(&version)
        {
            return Err(PersistNodeTracePayloadError::UnsupportedVersion { version });
        }

        let count = read_u64(&bytes[20..28]);
        if count == PERSIST_NODE_TRACE_PAYLOAD_TOMBSTONE_COUNT {
            if version < 2 {
                return Err(PersistNodeTracePayloadError::InputCountOverflow { count });
            }
            if bytes.len() != PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN {
                return Err(PersistNodeTracePayloadError::TrailingBytes {
                    remaining: bytes.len() - PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
                });
            }
            return Ok(Self::tombstone());
        }
        let count_usize = usize::try_from(count)
            .map_err(|_| PersistNodeTracePayloadError::InputCountOverflow { count })?;
        let fixed_records_len = count_usize
            .checked_mul(PERSIST_NODE_TRACE_INPUT_FIXED_LEN)
            .ok_or(PersistNodeTracePayloadError::ShortPayload {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        let minimum_len = PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN
            .checked_add(fixed_records_len)
            .ok_or(PersistNodeTracePayloadError::ShortPayload {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        if minimum_len > bytes.len() {
            return Err(PersistNodeTracePayloadError::ShortPayload {
                expected: minimum_len,
                actual: bytes.len(),
            });
        }

        let mut inputs = Vec::new();
        inputs.try_reserve_exact(count_usize).map_err(|_| {
            PersistNodeTracePayloadError::InputAllocationFailed {
                inputs: count_usize,
            }
        })?;

        let mut cursor = PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN;
        for _ in 0..count_usize {
            let fixed_end = cursor
                .checked_add(PERSIST_NODE_TRACE_INPUT_FIXED_LEN)
                .ok_or(PersistNodeTracePayloadError::ShortPayload {
                    expected: usize::MAX,
                    actual: bytes.len(),
                })?;
            if fixed_end > bytes.len() {
                return Err(PersistNodeTracePayloadError::ShortPayload {
                    expected: fixed_end,
                    actual: bytes.len(),
                });
            }

            let kind = node_trace_input_kind_from_tag(bytes[cursor])?;
            let mode = node_trace_input_mode_from_tag(bytes[cursor + 1])?;
            let subject_len = read_u64(&bytes[cursor + 2..cursor + 10]);
            let mut observation_hash = [0; 32];
            observation_hash.copy_from_slice(&bytes[cursor + 10..cursor + 42]);
            cursor = fixed_end;

            let subject_len = usize::try_from(subject_len).map_err(|_| {
                PersistNodeTracePayloadError::SubjectLengthOverflow { len: subject_len }
            })?;
            let subject_end = cursor.checked_add(subject_len).ok_or(
                PersistNodeTracePayloadError::ShortPayload {
                    expected: usize::MAX,
                    actual: bytes.len(),
                },
            )?;
            if subject_end > bytes.len() {
                return Err(PersistNodeTracePayloadError::ShortPayload {
                    expected: subject_end,
                    actual: bytes.len(),
                });
            }
            let input = CacheableInputFingerprint::from_observation_hash(
                kind,
                mode,
                &bytes[cursor..subject_end],
                DurableBlake3Hash::from_bytes(observation_hash),
            )
            .map_err(|source| PersistNodeTracePayloadError::Input { source })?;
            inputs.push(input);
            cursor = subject_end;
        }

        if cursor != bytes.len() {
            return Err(PersistNodeTracePayloadError::TrailingBytes {
                remaining: bytes.len() - cursor,
            });
        }

        Ok(Self {
            inputs,
            tombstone: false,
        })
    }
}

fn node_trace_input_kind_tag(kind: ImpureInputKind) -> u8 {
    match kind {
        ImpureInputKind::Import => 1,
        ImpureInputKind::ReadFile => 2,
        ImpureInputKind::ReadDir => 3,
        ImpureInputKind::ReadFileType => 4,
        ImpureInputKind::PathExists => 5,
        ImpureInputKind::GetEnv => 6,
        ImpureInputKind::HashFile => 7,
    }
}

fn node_trace_input_kind_from_tag(
    tag: u8,
) -> Result<ImpureInputKind, PersistNodeTracePayloadError> {
    match tag {
        1 => Ok(ImpureInputKind::Import),
        2 => Ok(ImpureInputKind::ReadFile),
        3 => Ok(ImpureInputKind::ReadDir),
        4 => Ok(ImpureInputKind::ReadFileType),
        5 => Ok(ImpureInputKind::PathExists),
        6 => Ok(ImpureInputKind::GetEnv),
        7 => Ok(ImpureInputKind::HashFile),
        _ => Err(PersistNodeTracePayloadError::InvalidInputKindTag { tag }),
    }
}

fn node_trace_input_mode_tag(mode: ImpureInputMode) -> u8 {
    match mode {
        ImpureInputMode::Default => 1,
        ImpureInputMode::RequireDirectory => 2,
    }
}

fn node_trace_input_mode_from_tag(
    tag: u8,
) -> Result<ImpureInputMode, PersistNodeTracePayloadError> {
    match tag {
        1 => Ok(ImpureInputMode::Default),
        2 => Ok(ImpureInputMode::RequireDirectory),
        _ => Err(PersistNodeTracePayloadError::InvalidInputModeTag { tag }),
    }
}

/// A complete key/value-hash/payload record in the node trace log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistNodeTraceLogEntry {
    key: PersistNodeMetadataKey,
    value_hash: ValueHash,
    payload: PersistNodeTracePayload,
}

impl PersistNodeTraceLogEntry {
    /// Creates a node trace log entry.
    pub fn new(
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
        payload: PersistNodeTracePayload,
    ) -> Self {
        Self {
            key,
            value_hash,
            payload,
        }
    }

    /// Returns the node metadata key this trace belongs to.
    pub const fn key(&self) -> PersistNodeMetadataKey {
        self.key
    }

    /// Returns the materialized value hash this trace verifies.
    ///
    /// Tombstone entries carry a synthetic hash because they invalidate older
    /// trace records rather than verifying a materialized value.
    pub const fn value_hash(&self) -> ValueHash {
        self.value_hash
    }

    /// Returns the persisted node trace payload.
    pub const fn payload(&self) -> &PersistNodeTracePayload {
        &self.payload
    }

    /// Consumes the entry and returns its persisted node trace payload.
    pub fn into_payload(self) -> PersistNodeTracePayload {
        self.payload
    }
}

/// An append-only log for persisted node verifying traces.
///
/// This is a simple durable substrate for the future `nodes/` table. Each
/// ordinary record stores a [`PersistNodeMetadataKey`], the materialized
/// [`ValueHash`] the trace verifies, and a variable-length
/// [`PersistNodeTracePayload`]. Tombstone records use the same envelope with a
/// synthetic hash and a tombstone payload. Lookups scan linearly and return the
/// newest matching trace record for the requested node key.
#[derive(Clone, Debug)]
pub struct PersistNodeTraceLog {
    engine: EngineNodeTraceLog,
}

impl PersistNodeTraceLog {
    /// Opens or initializes a node trace log file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if parent directories or the log
    /// file cannot be created/opened, or if an existing log contains malformed
    /// variable-length records.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistNodeTraceLogError> {
        let engine = EngineNodeTraceLog::open(path.into()).map_err(engine_node_trace_log_error)?;
        let log = Self { engine };
        log.entries()?;
        Ok(log)
    }

    /// Returns this log file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Appends one node trace entry.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened,
    /// validated, written, or flushed, or if the payload cannot be encoded.
    pub fn append_entry(
        &self,
        entry: PersistNodeTraceLogEntry,
    ) -> Result<(), PersistNodeTraceLogError> {
        self.append_trace(entry.key, entry.value_hash, &entry.payload)
    }

    /// Appends one node trace payload for `key` and `value_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened,
    /// validated, written, or flushed, or if the payload cannot be encoded.
    pub fn append_trace(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
        payload: &PersistNodeTracePayload,
    ) -> Result<(), PersistNodeTraceLogError> {
        self.entries()?;
        let payload_bytes = payload
            .encode()
            .map_err(|source| PersistNodeTraceLogError::Encode { source })?;
        self.engine
            .append_entry(EngineNodeTraceLogEntry::new(
                persist_node_trace_key_to_engine(key),
                persist_node_trace_value_hash_to_engine(value_hash),
                payload_bytes,
            ))
            .map_err(engine_node_trace_log_error)
    }

    /// Looks up the newest trace record recorded for `key`.
    ///
    /// Missing trace records return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened, read,
    /// or decoded.
    pub fn lookup(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        let mut found = None;
        for entry in self.entries()? {
            if entry.key() == key {
                found = Some(entry);
            }
        }
        Ok(found)
    }

    /// Returns the newest trace log entry for every node metadata key.
    ///
    /// Entries are returned in stable key order. If a key appears multiple
    /// times in the append-only log, only its newest trace entry is returned.
    /// Tombstones are entries and are preserved when they are newest for a key.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened, read,
    /// or decoded.
    pub fn latest_entries(
        &self,
    ) -> Result<Vec<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        let mut latest = std::collections::BTreeMap::new();
        for entry in self.entries()? {
            latest.insert(entry.key(), entry);
        }
        Ok(latest.into_values().collect())
    }

    /// Rewrites the log to the newest trace entry for every node metadata key.
    ///
    /// Entries are written in stable key order through a temporary file that is
    /// renamed over the original log. The returned count is the number of
    /// latest entries preserved after compaction. Tombstones are preserved when
    /// they are the newest entry for a key. Callers must exclude all concurrent
    /// log writers across threads and processes while this method runs; an
    /// append that races between the snapshot and rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened, read,
    /// decoded, written, flushed, or renamed into place.
    pub fn compact_latest_entries(&self) -> Result<usize, PersistNodeTraceLogError> {
        let entries = self.latest_entries()?;
        self.replace_entries(&entries)
    }

    #[cfg(test)]
    pub(crate) fn compact_latest_entries_with_rewrite_id_for_tests(
        &self,
        rewrite_id: u64,
    ) -> Result<usize, PersistNodeTraceLogError> {
        let entries = self.latest_entries()?;
        self.replace_entries_with_rewrite_id(&entries, rewrite_id)
    }

    fn entries(&self) -> Result<Vec<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        self.engine
            .entries()
            .map_err(engine_node_trace_log_error)?
            .into_iter()
            .map(|entry| engine_node_trace_entry_to_persist(self.path(), entry))
            .collect()
    }

    fn replace_entries(
        &self,
        entries: &[PersistNodeTraceLogEntry],
    ) -> Result<usize, PersistNodeTraceLogError> {
        let engine_entries = entries
            .iter()
            .map(persist_node_trace_entry_to_engine)
            .collect::<Result<Vec<_>, _>>()?;
        self.engine
            .replace_entries(&engine_entries)
            .map_err(engine_node_trace_log_error)
    }

    #[cfg(test)]
    fn replace_entries_with_rewrite_id(
        &self,
        entries: &[PersistNodeTraceLogEntry],
        rewrite_id: u64,
    ) -> Result<usize, PersistNodeTraceLogError> {
        let tmp_path = self
            .path()
            .with_extension(format!("compact-{}-{rewrite_id}.tmp", std::process::id()));
        {
            let _ = fs::remove_file(&tmp_path);
            let tmp_log =
                EngineNodeTraceLog::open(tmp_path.clone()).map_err(engine_node_trace_log_error)?;
            for entry in entries {
                tmp_log
                    .append_entry(persist_node_trace_entry_to_engine(entry)?)
                    .map_err(engine_node_trace_log_error)?;
            }
        }
        fs::rename(&tmp_path, self.path()).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            PersistNodeTraceLogError::Write {
                path: self.path().to_path_buf(),
                source,
            }
        })?;
        Ok(entries.len())
    }
}

fn persist_node_trace_key_to_engine(key: PersistNodeMetadataKey) -> EngineNodeTraceLogKey {
    let encoded = key.index_bytes();
    let mut digest = [0; 32];
    digest.copy_from_slice(&encoded[1..]);
    EngineNodeTraceLogKey::new(encoded[0], digest)
}

fn engine_node_trace_key_to_persist(
    key: EngineNodeTraceLogKey,
) -> Result<PersistNodeMetadataKey, PersistPackFormatError> {
    PersistNodeMetadataKey::decode_index_bytes(&key.encode())
}

fn persist_node_trace_value_hash_to_engine(value_hash: ValueHash) -> EngineNodeTraceLogValueHash {
    EngineNodeTraceLogValueHash::from_bytes(value_hash.as_durable_hash().as_bytes())
}

fn engine_node_trace_value_hash_to_persist(value_hash: EngineNodeTraceLogValueHash) -> ValueHash {
    ValueHash::from_canonical_value_hash(DurableBlake3Hash::from_bytes(value_hash.bytes()))
}

fn persist_node_trace_entry_to_engine(
    entry: &PersistNodeTraceLogEntry,
) -> Result<EngineNodeTraceLogEntry, PersistNodeTraceLogError> {
    let payload = entry
        .payload()
        .encode()
        .map_err(|source| PersistNodeTraceLogError::Encode { source })?;
    Ok(EngineNodeTraceLogEntry::new(
        persist_node_trace_key_to_engine(entry.key()),
        persist_node_trace_value_hash_to_engine(entry.value_hash()),
        payload,
    ))
}

fn engine_node_trace_entry_to_persist(
    path: &Path,
    entry: EngineNodeTraceLogEntry,
) -> Result<PersistNodeTraceLogEntry, PersistNodeTraceLogError> {
    let key = engine_node_trace_key_to_persist(entry.key()).map_err(|source| {
        node_trace_log_format_error(path, PersistNodeTraceLogFormatError::Key { source })
    })?;
    let value_hash = engine_node_trace_value_hash_to_persist(entry.value_hash());
    let payload = PersistNodeTracePayload::decode(entry.payload()).map_err(|source| {
        node_trace_log_format_error(path, PersistNodeTraceLogFormatError::Payload { source })
    })?;
    Ok(PersistNodeTraceLogEntry::new(key, value_hash, payload))
}

fn engine_node_trace_log_error(error: EngineNodeTraceLogError) -> PersistNodeTraceLogError {
    match error {
        EngineNodeTraceLogError::CreateParent { path, source } => {
            PersistNodeTraceLogError::CreateParent { path, source }
        }
        EngineNodeTraceLogError::Open { path, source } => {
            PersistNodeTraceLogError::Open { path, source }
        }
        EngineNodeTraceLogError::Metadata { path, source } => {
            PersistNodeTraceLogError::Metadata { path, source }
        }
        EngineNodeTraceLogError::Read { path, source } => {
            PersistNodeTraceLogError::Read { path, source }
        }
        EngineNodeTraceLogError::Write { path, source } => {
            PersistNodeTraceLogError::Write { path, source }
        }
        EngineNodeTraceLogError::PayloadTooLarge { len } => {
            PersistNodeTraceLogError::PayloadTooLarge { len }
        }
        EngineNodeTraceLogError::RecordAllocationFailed { len } => {
            PersistNodeTraceLogError::RecordAllocationFailed { len }
        }
        EngineNodeTraceLogError::PayloadAllocationFailed { len } => {
            PersistNodeTraceLogError::PayloadAllocationFailed { len }
        }
        EngineNodeTraceLogError::Format { path, source } => PersistNodeTraceLogError::Format {
            path,
            source: engine_node_trace_log_format_error(source),
        },
    }
}

fn engine_node_trace_log_format_error(
    error: EngineNodeTraceLogFormatError,
) -> PersistNodeTraceLogFormatError {
    match error {
        EngineNodeTraceLogFormatError::ShortKey { expected, actual } => {
            PersistNodeTraceLogFormatError::Key {
                source: PersistPackFormatError::ShortNodeMetadataIndexKey { expected, actual },
            }
        }
        EngineNodeTraceLogFormatError::ShortValueHash { actual, .. } => {
            PersistNodeTraceLogFormatError::ShortRecordHeader {
                expected: ENGINE_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64,
                actual: (ENGINE_NODE_TRACE_LOG_KEY_LEN + actual) as u64,
            }
        }
        EngineNodeTraceLogFormatError::ShortRecordHeader { expected, actual } => {
            PersistNodeTraceLogFormatError::ShortRecordHeader { expected, actual }
        }
        EngineNodeTraceLogFormatError::PayloadLengthOverflow { len } => {
            PersistNodeTraceLogFormatError::PayloadLengthOverflow { len }
        }
        EngineNodeTraceLogFormatError::RecordBoundsOverflow {
            record_offset,
            payload_len,
        } => PersistNodeTraceLogFormatError::RecordBoundsOverflow {
            record_offset,
            payload_len,
        },
        EngineNodeTraceLogFormatError::ShortRecordPayload { expected, actual } => {
            PersistNodeTraceLogFormatError::ShortRecordPayload { expected, actual }
        }
    }
}

fn node_trace_log_format_error(
    path: &Path,
    source: PersistNodeTraceLogFormatError,
) -> PersistNodeTraceLogError {
    PersistNodeTraceLogError::Format {
        path: path.to_path_buf(),
        source,
    }
}

/// A fixed-record index file for durable demand-node metadata.
///
/// This is a simple durable substrate for tests and future cache integration.
/// It is not the final LMDB/redb metadata engine: writes append one fixed
/// record at a time, and lookups scan records linearly and return the newest
/// matching entry.
#[derive(Clone, Debug)]
pub struct PersistNodeMetadataIndex {
    engine: EngineNodeMetadataIndex,
}

impl PersistNodeMetadataIndex {
    /// Opens or initializes a fixed-record node metadata index file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if parent directories or the
    /// index file cannot be created/opened, or if the existing file ends with a
    /// partial fixed-width record.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistNodeMetadataIndexError> {
        let engine =
            EngineNodeMetadataIndex::open(path.into()).map_err(engine_node_metadata_index_error)?;
        Ok(Self { engine })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Appends one node metadata index entry.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entry(
        &self,
        entry: PersistNodeMetadataIndexEntry,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        self.engine
            .append_entry(persist_node_metadata_entry_to_engine(entry))
            .map_err(engine_node_metadata_index_error)
    }

    /// Looks up the newest node metadata value for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the index cannot be opened,
    /// read, or decoded.
    pub fn lookup(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeMetadataIndexValue>, PersistNodeMetadataIndexError> {
        let mut found = None;
        for entry in self.entries()? {
            if entry.key() == key {
                found = Some(entry.value());
            }
        }
        Ok(found)
    }

    /// Returns the newest entry for every node metadata key.
    ///
    /// Entries are returned in stable key order. If a key appears multiple
    /// times in the append-only sidecar, only its newest value is returned.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the index cannot be opened,
    /// read, or decoded.
    pub fn latest_entries(
        &self,
    ) -> Result<Vec<PersistNodeMetadataIndexEntry>, PersistNodeMetadataIndexError> {
        let mut latest = std::collections::BTreeMap::new();
        for entry in self.entries()? {
            latest.insert(entry.key(), entry.value());
        }
        Ok(latest
            .into_iter()
            .map(|(key, value)| PersistNodeMetadataIndexEntry::new(key, value))
            .collect())
    }

    /// Rewrites the sidecar to the newest entry for every node metadata key.
    ///
    /// Entries are written in stable key order through a temporary file that is
    /// renamed over the original index. The returned count is the number of
    /// latest entries preserved after compaction. Callers must exclude all
    /// concurrent sidecar writers across threads and processes while this
    /// method runs; an append that races between the snapshot and rename can be
    /// lost.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the index cannot be opened,
    /// read, decoded, written, flushed, or renamed into place.
    pub fn compact_latest_entries(&self) -> Result<usize, PersistNodeMetadataIndexError> {
        let entries = self.latest_entries()?;
        let entries = entries
            .iter()
            .copied()
            .map(persist_node_metadata_entry_to_engine)
            .collect::<Vec<_>>();
        self.engine
            .replace_entries(&entries)
            .map_err(engine_node_metadata_index_error)
    }

    fn entries(&self) -> Result<Vec<PersistNodeMetadataIndexEntry>, PersistNodeMetadataIndexError> {
        self.engine
            .entries()
            .map_err(engine_node_metadata_index_error)?
            .into_iter()
            .map(engine_node_metadata_entry_to_persist)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| PersistNodeMetadataIndexError::Format {
                path: self.path().to_path_buf(),
                source,
            })
    }
}
