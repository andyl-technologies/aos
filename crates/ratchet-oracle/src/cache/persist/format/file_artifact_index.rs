//! File-artifact index key, value, entry, and storage format adapters.

use super::*;
use crate::cache::CompiledBodyRecordHash;
use crate::cache::hashing::{CacheDigestHasher, CacheHashFamily};
use ratchet_cache::artifact_index::{
    ArtifactIndex as EngineArtifactIndex, ArtifactIndexEntry as EngineArtifactIndexEntry,
    ArtifactIndexError as EngineArtifactIndexError,
    ArtifactIndexFormatError as EngineArtifactIndexFormatError,
    ArtifactIndexKey as EngineArtifactIndexKey, ArtifactIndexValue as EngineArtifactIndexValue,
};

/// A stable index key for a durable file-derived or compiled artifact.
///
/// Frontend keys derive from canonical realpath bytes, source content, and
/// parse identity. Compiled-body keys enter through their separately
/// domain-separated lowering identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistFileArtifactKey {
    hash: DurableBlake3Hash,
}

impl PersistFileArtifactKey {
    /// Creates a persistent artifact mapping key for a compiled-body record.
    pub const fn for_compiled_body(hash: CompiledBodyRecordHash) -> Self {
        Self {
            hash: hash.as_durable_hash(),
        }
    }

    /// Creates a persistent file-artifact index key from a parse file key.
    pub fn from_parse_file_key(file_key: &ParseFileKey, parse_key: ParseCacheKey) -> Self {
        Self::for_realpath_bytes_with_hasher(
            CacheDigestHasher::new(),
            file_key.realpath().as_os_str().as_bytes(),
            file_key.content_hash(),
            parse_key,
        )
    }

    /// Creates a file-artifact index key from a parse file key under a family.
    ///
    /// Folds the identity under `family` rather than the process family so a
    /// foreign-family secondary's index entry can be addressed from an
    /// identity-carrying preimage (RFC-0007 §P4 Option C cross-family probe).
    /// The `file_key` and `parse_key` must already be derived under the same
    /// family.
    pub fn from_parse_file_key_with_family(
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        family: CacheHashFamily,
    ) -> Self {
        Self::for_realpath_bytes_with_hasher(
            CacheDigestHasher::for_family(family),
            file_key.realpath().as_os_str().as_bytes(),
            file_key.content_hash(),
            parse_key,
        )
    }

    /// Creates a persistent file-artifact index key from raw canonical realpath bytes.
    pub fn for_realpath_bytes(
        realpath: &[u8],
        content_hash: ParseFileContentHash,
        parse_key: ParseCacheKey,
    ) -> Self {
        Self::for_realpath_bytes_with_hasher(
            CacheDigestHasher::new(),
            realpath,
            content_hash,
            parse_key,
        )
    }

    fn for_realpath_bytes_with_hasher(
        mut hasher: CacheDigestHasher,
        realpath: &[u8],
        content_hash: ParseFileContentHash,
        parse_key: ParseCacheKey,
    ) -> Self {
        hasher.update(PERSIST_FILE_ARTIFACT_KEY_PERSONALIZATION);
        update_persist_index_chunk(&mut hasher, realpath);
        hasher.update(&content_hash.as_durable_hash().as_bytes());
        hasher.update(&parse_key.as_durable_hash().as_bytes());
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

/// A stable index value for a durable file-derived or compiled artifact.
///
/// The value points at a blob in the `files/` pack. The blob payload format is
/// intentionally outside this codec; the pack still verifies the payload hash
/// on read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistFileArtifactIndexValue {
    blob_hash: PersistFileBlobHash,
    location: PersistBlobLocation,
}

impl PersistFileArtifactIndexValue {
    /// Creates a file-artifact index value for a `files/` blob hash and location.
    pub const fn new(blob_hash: PersistFileBlobHash, location: PersistBlobLocation) -> Self {
        Self {
            blob_hash,
            location,
        }
    }

    /// Returns the durable hash of the file artifact blob.
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
        Ok(Self::new(
            PersistFileBlobHash::from_durable_hash(blob_key.hash()),
            location,
        ))
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

    /// Appends many file-artifact index entries in one open/write/flush cycle.
    ///
    /// This is the batched sibling of [`Self::append_entry`] used by the
    /// write-behind flush (RFC-0007 §3.2(b)): the whole run's file-artifact
    /// mappings are written with a single open + `write_all` + flush. An empty
    /// batch is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entries_batch(
        &self,
        entries: &[PersistFileArtifactIndexEntry],
    ) -> Result<(), PersistFileArtifactIndexError> {
        let engine_entries: Vec<_> = entries
            .iter()
            .copied()
            .map(persist_file_artifact_entry_to_engine)
            .collect();
        self.engine
            .append_entries_batch(&engine_entries)
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
    pub(in crate::cache::persist) fn write_entries_to(
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
