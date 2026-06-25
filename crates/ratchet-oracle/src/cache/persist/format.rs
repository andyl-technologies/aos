//! On-disk format primitives for the persistent eval cache.
//!
//! Owns the typed blob namespaces ([`PersistBlobStore`]), content-addressed
//! lookup keys, packfile and record headers, blob locations, and the
//! append-only hash-to-offset and file-artifact index encodings. These types
//! define the byte layout shared by the values and files stores.

use super::*;

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
        let mut bytes = [0; PERSIST_BLOB_INDEX_ENTRY_LEN];
        bytes[..PERSIST_BLOB_INDEX_KEY_LEN].copy_from_slice(&self.key.index_bytes());
        bytes[PERSIST_BLOB_INDEX_KEY_LEN..].copy_from_slice(&self.location.encode_index_value());
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
        if bytes.len() < PERSIST_BLOB_INDEX_ENTRY_LEN {
            return Err(PersistPackFormatError::ShortBlobIndexEntry {
                expected: PERSIST_BLOB_INDEX_ENTRY_LEN,
                actual: bytes.len(),
            });
        }
        let key = PersistBlobKey::decode_index_bytes(&bytes[..PERSIST_BLOB_INDEX_KEY_LEN])?;
        let location = PersistBlobLocation::decode_index_value(
            &bytes[PERSIST_BLOB_INDEX_KEY_LEN..PERSIST_BLOB_INDEX_ENTRY_LEN],
        )?;
        Ok(Self::new(key, location))
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
    path: PathBuf,
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
        let path = path.into();
        ensure_blob_index_file(&path)?;
        Ok(Self { path })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one hash-to-offset index entry.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entry(&self, entry: PersistBlobIndexEntry) -> Result<(), PersistBlobIndexError> {
        ensure_blob_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| PersistBlobIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&entry.encode_index_entry())
            .and_then(|()| file.flush())
            .map_err(|source| PersistBlobIndexError::Write {
                path: self.path.clone(),
                source,
            })
    }

    /// Looks up the newest location for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the index cannot be opened, read,
    /// or decoded.
    pub fn lookup(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<PersistBlobLocation>, PersistBlobIndexError> {
        ensure_blob_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| PersistBlobIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| PersistBlobIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_blob_index_len(&self.path, len)?;

        let mut found = None;
        let records = len / PERSIST_BLOB_INDEX_ENTRY_LEN as u64;
        let mut encoded = [0; PERSIST_BLOB_INDEX_ENTRY_LEN];
        for _ in 0..records {
            file.read_exact(&mut encoded)
                .map_err(|source| PersistBlobIndexError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            let entry = PersistBlobIndexEntry::decode_index_entry(&encoded).map_err(|source| {
                PersistBlobIndexError::Format {
                    path: self.path.clone(),
                    source,
                }
            })?;
            if entry.key() == key {
                found = Some(entry.location());
            }
        }
        Ok(found)
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
        let mut bytes = [0; PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN];
        bytes[..PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN].copy_from_slice(&self.key.index_bytes());
        bytes[PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN..]
            .copy_from_slice(&self.value.encode_index_value());
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
        if bytes.len() < PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN {
            return Err(PersistPackFormatError::ShortFileArtifactIndexEntry {
                expected: PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN,
                actual: bytes.len(),
            });
        }
        let key = PersistFileArtifactKey::decode_index_bytes(
            &bytes[..PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN],
        )?;
        let value = PersistFileArtifactIndexValue::decode_index_value(
            &bytes[PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN..],
        )?;
        Ok(Self::new(key, value))
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
    path: PathBuf,
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
        let path = path.into();
        ensure_file_artifact_index_file(&path)?;
        Ok(Self { path })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
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
        ensure_file_artifact_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| PersistFileArtifactIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&entry.encode_index_entry())
            .and_then(|()| file.flush())
            .map_err(|source| PersistFileArtifactIndexError::Write {
                path: self.path.clone(),
                source,
            })
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
        ensure_file_artifact_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| PersistFileArtifactIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| PersistFileArtifactIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_file_artifact_index_len(&self.path, len)?;

        let mut found = None;
        let records = len / PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64;
        let mut encoded = [0; PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN];
        for _ in 0..records {
            file.read_exact(&mut encoded).map_err(|source| {
                PersistFileArtifactIndexError::Read {
                    path: self.path.clone(),
                    source,
                }
            })?;
            let entry =
                PersistFileArtifactIndexEntry::decode_index_entry(&encoded).map_err(|source| {
                    PersistFileArtifactIndexError::Format {
                        path: self.path.clone(),
                        source,
                    }
                })?;
            if entry.key() == key {
                found = Some(entry.value());
            }
        }
        Ok(found)
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
        let mut bytes = [0; PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN];
        bytes[..PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN].copy_from_slice(&self.key.index_bytes());
        bytes[PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN..]
            .copy_from_slice(&self.value.encode_index_value());
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
        if bytes.len() < PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN {
            return Err(PersistPackFormatError::ShortParseArtifactIndexEntry {
                expected: PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN,
                actual: bytes.len(),
            });
        }
        let key = PersistParseArtifactKey::decode_index_bytes(
            &bytes[..PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN],
        )?;
        let value = PersistParseArtifactIndexValue::decode_index_value(
            &bytes[PERSIST_PARSE_ARTIFACT_INDEX_KEY_LEN..],
        )?;
        Ok(Self::new(key, value))
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
    path: PathBuf,
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
        let path = path.into();
        ensure_parse_artifact_index_file(&path)?;
        Ok(Self { path })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
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
        ensure_parse_artifact_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| PersistParseArtifactIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&entry.encode_index_entry())
            .and_then(|()| file.flush())
            .map_err(|source| PersistParseArtifactIndexError::Write {
                path: self.path.clone(),
                source,
            })
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
        ensure_parse_artifact_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| PersistParseArtifactIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| PersistParseArtifactIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_parse_artifact_index_len(&self.path, len)?;

        let mut found = None;
        let records = len / PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN as u64;
        let mut encoded = [0; PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN];
        for _ in 0..records {
            file.read_exact(&mut encoded).map_err(|source| {
                PersistParseArtifactIndexError::Read {
                    path: self.path.clone(),
                    source,
                }
            })?;
            let entry =
                PersistParseArtifactIndexEntry::decode_index_entry(&encoded).map_err(|source| {
                    PersistParseArtifactIndexError::Format {
                        path: self.path.clone(),
                        source,
                    }
                })?;
            if entry.key() == key {
                found = Some(entry.value());
            }
        }
        Ok(found)
    }
}
