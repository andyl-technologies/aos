//! Parse-artifact index key, value, entry, and storage format adapters.

use super::*;
use ratchet_cache::artifact_index::{
    ArtifactIndex as EngineArtifactIndex, ArtifactIndexEntry as EngineArtifactIndexEntry,
    ArtifactIndexError as EngineArtifactIndexError,
    ArtifactIndexFormatError as EngineArtifactIndexFormatError,
    ArtifactIndexKey as EngineArtifactIndexKey, ArtifactIndexValue as EngineArtifactIndexValue,
};

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
            hash: parse_key.as_durable_hash(),
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
    blob_hash: PersistFileBlobHash,
    location: PersistBlobLocation,
}

impl PersistParseArtifactIndexValue {
    /// Creates a parse-artifact index value for a `files/` blob hash and location.
    pub const fn new(blob_hash: PersistFileBlobHash, location: PersistBlobLocation) -> Self {
        Self {
            blob_hash,
            location,
        }
    }

    /// Returns the durable hash of the parse artifact blob.
    pub const fn blob_hash(self) -> PersistFileBlobHash {
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
        Ok(Self::new(
            PersistFileBlobHash::from_durable_hash(blob_key.hash()),
            location,
        ))
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

    /// Appends many parse-artifact index entries in one open/write/flush cycle.
    ///
    /// This is the batched sibling of [`Self::append_entry`] used by the
    /// write-behind flush (RFC-0007 §3.2(b)): the whole run's parse-artifact
    /// mappings are written with a single open + `write_all` + flush. An empty
    /// batch is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entries_batch(
        &self,
        entries: &[PersistParseArtifactIndexEntry],
    ) -> Result<(), PersistParseArtifactIndexError> {
        let engine_entries: Vec<_> = entries
            .iter()
            .copied()
            .map(persist_parse_artifact_entry_to_engine)
            .collect();
        self.engine
            .append_entries_batch(&engine_entries)
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
    pub(in crate::cache::persist) fn write_entries_to(
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
