//! Root-instantiation record index key, value, entry, and storage adapters.
//!
//! The root-record index maps a caller-supplied root cutoff key — an opaque
//! 32-byte digest over the entry file identity, selected attribute, and
//! result-affecting evaluator settings — to a `files/` blob holding the encoded
//! [`RootInstantiationRecord`](super::root_record::RootInstantiationRecord).
//! It reuses the shared fixed-record artifact-index engine and the same
//! blob-key/location value layout as the parse-artifact index.
//!
//! ```text
//! key   = tag(1) || blake3-digest(32)              (33 bytes)
//! value = blob-key(33) || blob-location(16)        (49 bytes)
//! entry = key(33) || value(49)                     (82 bytes)
//! ```

use super::*;
use ratchet_cache::artifact_index::{
    ArtifactIndex as EngineArtifactIndex, ArtifactIndexEntry as EngineArtifactIndexEntry,
    ArtifactIndexError as EngineArtifactIndexError,
    ArtifactIndexFormatError as EngineArtifactIndexFormatError,
    ArtifactIndexKey as EngineArtifactIndexKey, ArtifactIndexValue as EngineArtifactIndexValue,
};

/// A stable index key for one durable root-instantiation record.
///
/// The key wraps an opaque BLAKE3 digest computed by the evaluator front end
/// over every input to a root cutoff decision. This type is agnostic to how the
/// digest is composed; it only frames it for the fixed-record index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersistRootRecordKey {
    hash: DurableBlake3Hash,
}

impl PersistRootRecordKey {
    /// Creates a root-record key from a precomputed 32-byte cutoff digest.
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self {
            hash: DurableBlake3Hash::from_bytes(digest),
        }
    }

    /// Returns the durable digest identifying this root record.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.hash
    }

    /// Returns the stable binary key for the root-record index.
    pub fn index_bytes(self) -> [u8; PERSIST_ROOT_RECORD_INDEX_KEY_LEN] {
        let mut bytes = [0; PERSIST_ROOT_RECORD_INDEX_KEY_LEN];
        bytes[0] = PERSIST_ROOT_RECORD_INDEX_TAG;
        bytes[1..].copy_from_slice(&self.hash.as_bytes());
        bytes
    }

    /// Decodes the stable binary key for the root-record index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_ROOT_RECORD_INDEX_KEY_LEN`] or carries an unexpected index tag.
    pub fn decode_index_bytes(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_ROOT_RECORD_INDEX_KEY_LEN {
            return Err(PersistPackFormatError::ShortRootRecordIndexKey {
                expected: PERSIST_ROOT_RECORD_INDEX_KEY_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != PERSIST_ROOT_RECORD_INDEX_TAG {
            return Err(PersistPackFormatError::InvalidRootRecordIndexTag { tag: bytes[0] });
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[1..PERSIST_ROOT_RECORD_INDEX_KEY_LEN]);
        Ok(Self {
            hash: DurableBlake3Hash::from_bytes(hash),
        })
    }
}

/// A stable index value for one durable root-instantiation record.
///
/// The value points at the `files/` blob holding the encoded record payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistRootRecordIndexValue {
    blob_hash: PersistFileBlobHash,
    location: PersistBlobLocation,
}

impl PersistRootRecordIndexValue {
    /// Creates a root-record index value for a `files/` blob hash and location.
    pub const fn new(blob_hash: PersistFileBlobHash, location: PersistBlobLocation) -> Self {
        Self {
            blob_hash,
            location,
        }
    }

    /// Returns the durable hash of the root-record payload blob.
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

    /// Encodes this value as stable root-record index metadata.
    pub fn encode_index_value(self) -> [u8; PERSIST_ROOT_RECORD_INDEX_VALUE_LEN] {
        let mut bytes = [0; PERSIST_ROOT_RECORD_INDEX_VALUE_LEN];
        bytes[..PERSIST_BLOB_INDEX_KEY_LEN].copy_from_slice(&self.blob_key().index_bytes());
        bytes[PERSIST_BLOB_INDEX_KEY_LEN..].copy_from_slice(&self.location.encode_index_value());
        bytes
    }

    /// Decodes stable root-record index metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError`] if `bytes` is shorter than
    /// [`PERSIST_ROOT_RECORD_INDEX_VALUE_LEN`], if the embedded blob key is
    /// malformed, or if the embedded blob key does not point at `files/`.
    pub fn decode_index_value(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_ROOT_RECORD_INDEX_VALUE_LEN {
            return Err(PersistPackFormatError::ShortRootRecordIndexValue {
                expected: PERSIST_ROOT_RECORD_INDEX_VALUE_LEN,
                actual: bytes.len(),
            });
        }
        let blob_key = PersistBlobKey::decode_index_bytes(&bytes[..PERSIST_BLOB_INDEX_KEY_LEN])?;
        if blob_key.store() != PersistBlobStore::Files {
            return Err(PersistPackFormatError::InvalidRootRecordBlobStore {
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

/// A complete key/value record for the root-record index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistRootRecordIndexEntry {
    key: PersistRootRecordKey,
    value: PersistRootRecordIndexValue,
}

impl PersistRootRecordIndexEntry {
    /// Creates a root-record index entry from its mapping key and value.
    pub const fn new(key: PersistRootRecordKey, value: PersistRootRecordIndexValue) -> Self {
        Self { key, value }
    }

    /// Returns the root-record mapping key.
    pub const fn key(self) -> PersistRootRecordKey {
        self.key
    }

    /// Returns the root-record blob lookup value.
    pub const fn value(self) -> PersistRootRecordIndexValue {
        self.value
    }
}

fn persist_root_record_key_to_engine(key: PersistRootRecordKey) -> EngineArtifactIndexKey {
    EngineArtifactIndexKey::new(PERSIST_ROOT_RECORD_INDEX_TAG, key.hash().as_bytes())
}

fn engine_root_record_key_to_persist(
    key: EngineArtifactIndexKey,
) -> Result<PersistRootRecordKey, PersistPackFormatError> {
    PersistRootRecordKey::decode_index_bytes(&key.encode())
}

fn persist_root_record_value_to_engine(
    value: PersistRootRecordIndexValue,
) -> EngineArtifactIndexValue {
    EngineArtifactIndexValue::from_bytes(value.encode_index_value())
}

fn engine_root_record_value_to_persist(
    value: EngineArtifactIndexValue,
) -> Result<PersistRootRecordIndexValue, PersistPackFormatError> {
    PersistRootRecordIndexValue::decode_index_value(&value.encode())
}

fn persist_root_record_entry_to_engine(
    entry: PersistRootRecordIndexEntry,
) -> EngineArtifactIndexEntry {
    EngineArtifactIndexEntry::new(
        persist_root_record_key_to_engine(entry.key()),
        persist_root_record_value_to_engine(entry.value()),
    )
}

fn engine_root_record_entry_to_persist(
    entry: EngineArtifactIndexEntry,
) -> Result<PersistRootRecordIndexEntry, PersistPackFormatError> {
    Ok(PersistRootRecordIndexEntry::new(
        engine_root_record_key_to_persist(entry.key())?,
        engine_root_record_value_to_persist(entry.value())?,
    ))
}

fn engine_root_record_format_error(
    error: EngineArtifactIndexFormatError,
) -> PersistPackFormatError {
    match error {
        EngineArtifactIndexFormatError::ShortKey { expected, actual } => {
            PersistPackFormatError::ShortRootRecordIndexKey { expected, actual }
        }
        EngineArtifactIndexFormatError::ShortValue { expected, actual } => {
            PersistPackFormatError::ShortRootRecordIndexValue { expected, actual }
        }
        EngineArtifactIndexFormatError::ShortEntry { expected, actual } => {
            PersistPackFormatError::ShortRootRecordIndexEntry { expected, actual }
        }
    }
}

fn engine_root_record_index_error(error: EngineArtifactIndexError) -> PersistRootRecordIndexError {
    match error {
        EngineArtifactIndexError::CreateParent { path, source } => {
            PersistRootRecordIndexError::CreateParent { path, source }
        }
        EngineArtifactIndexError::Open { path, source } => {
            PersistRootRecordIndexError::Open { path, source }
        }
        EngineArtifactIndexError::Metadata { path, source } => {
            PersistRootRecordIndexError::Metadata { path, source }
        }
        EngineArtifactIndexError::Read { path, source } => {
            PersistRootRecordIndexError::Read { path, source }
        }
        EngineArtifactIndexError::Write { path, source } => {
            PersistRootRecordIndexError::Write { path, source }
        }
        EngineArtifactIndexError::Format { path, source } => PersistRootRecordIndexError::Format {
            path,
            source: engine_root_record_format_error(source),
        },
    }
}

/// A fixed-record index file for durable root-instantiation records.
///
/// Like the sibling parse-artifact index, this is a simple append-and-scan
/// substrate: writes append one fixed record, and lookups return the newest
/// matching entry.
#[derive(Clone, Debug)]
pub struct PersistRootRecordIndex {
    engine: EngineArtifactIndex,
}

impl PersistRootRecordIndex {
    /// Opens or initializes a fixed-record root-record index file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistRootRecordIndexError`] if parent directories or the
    /// index file cannot be created/opened, or if the existing file ends with a
    /// partial fixed-width record.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistRootRecordIndexError> {
        let engine =
            EngineArtifactIndex::open(path.into()).map_err(engine_root_record_index_error)?;
        Ok(Self { engine })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Appends one root-record index entry.
    ///
    /// # Errors
    ///
    /// Returns [`PersistRootRecordIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entry(
        &self,
        entry: PersistRootRecordIndexEntry,
    ) -> Result<(), PersistRootRecordIndexError> {
        self.engine
            .append_entry(persist_root_record_entry_to_engine(entry))
            .map_err(engine_root_record_index_error)
    }

    /// Looks up the newest root-record value for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistRootRecordIndexError`] if the index cannot be opened,
    /// read, or decoded.
    pub fn lookup(
        &self,
        key: PersistRootRecordKey,
    ) -> Result<Option<PersistRootRecordIndexValue>, PersistRootRecordIndexError> {
        let mut found = None;
        for entry in self.entries()? {
            if entry.key() == key {
                found = Some(entry.value());
            }
        }
        Ok(found)
    }

    fn entries(&self) -> Result<Vec<PersistRootRecordIndexEntry>, PersistRootRecordIndexError> {
        self.engine
            .entries()
            .map_err(engine_root_record_index_error)?
            .into_iter()
            .map(engine_root_record_entry_to_persist)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| PersistRootRecordIndexError::Format {
                path: self.path().to_path_buf(),
                source,
            })
    }
}
