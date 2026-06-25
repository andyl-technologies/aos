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
        let mut bytes = [0; PERSIST_NODE_METADATA_INDEX_ENTRY_LEN];
        bytes[..PERSIST_NODE_METADATA_INDEX_KEY_LEN].copy_from_slice(&self.key.index_bytes());
        bytes[PERSIST_NODE_METADATA_INDEX_KEY_LEN..]
            .copy_from_slice(&self.value.encode_index_value());
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
        if bytes.len() < PERSIST_NODE_METADATA_INDEX_ENTRY_LEN {
            return Err(PersistPackFormatError::ShortNodeMetadataIndexEntry {
                expected: PERSIST_NODE_METADATA_INDEX_ENTRY_LEN,
                actual: bytes.len(),
            });
        }
        let key = PersistNodeMetadataKey::decode_index_bytes(
            &bytes[..PERSIST_NODE_METADATA_INDEX_KEY_LEN],
        )?;
        let value = PersistNodeMetadataIndexValue::decode_index_value(
            &bytes[PERSIST_NODE_METADATA_INDEX_KEY_LEN..],
        )?;
        Ok(Self::new(key, value))
    }
}

/// A stable payload for one persisted node verifying trace.
///
/// The payload preserves the evaluator trace order and stores only cacheable
/// impure-input fingerprints: each record carries the typed input identity
/// parts plus the observed-result hash. The eventual persistent demand-graph
/// sidecar can attach these bytes to an expression node and replay the
/// fingerprints during durable-hit revalidation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistNodeTracePayload {
    inputs: Vec<CacheableInputFingerprint>,
}

impl PersistNodeTracePayload {
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
        Ok(Self { inputs: stored })
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
        Ok(Self { inputs })
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
        let count = u64::try_from(self.inputs.len()).map_err(|_| {
            PersistNodeTracePayloadError::EncodedInputCountOverflow {
                inputs: self.inputs.len(),
            }
        })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN)
            .map_err(|_| PersistNodeTracePayloadError::PayloadAllocationFailed {
                len: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
            })?;
        bytes.extend_from_slice(&PERSIST_NODE_TRACE_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&PERSIST_NODE_TRACE_PAYLOAD_VERSION.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());

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
        if version != PERSIST_NODE_TRACE_PAYLOAD_VERSION {
            return Err(PersistNodeTracePayloadError::UnsupportedVersion { version });
        }

        let count = read_u64(&bytes[20..28]);
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

        Ok(Self { inputs })
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

/// A fixed-record index file for durable demand-node metadata.
///
/// This is a simple durable substrate for tests and future cache integration.
/// It is not the final LMDB/redb metadata engine: writes append one fixed
/// record at a time, and lookups scan records linearly and return the newest
/// matching entry.
#[derive(Clone, Debug)]
pub struct PersistNodeMetadataIndex {
    path: PathBuf,
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
        let path = path.into();
        ensure_node_metadata_index_file(&path)?;
        Ok(Self { path })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
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
        ensure_node_metadata_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| PersistNodeMetadataIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&entry.encode_index_entry())
            .and_then(|()| file.flush())
            .map_err(|source| PersistNodeMetadataIndexError::Write {
                path: self.path.clone(),
                source,
            })
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
        ensure_node_metadata_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| PersistNodeMetadataIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| PersistNodeMetadataIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_node_metadata_index_len(&self.path, len)?;

        let mut found = None;
        let records = len / PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64;
        let mut encoded = [0; PERSIST_NODE_METADATA_INDEX_ENTRY_LEN];
        for _ in 0..records {
            file.read_exact(&mut encoded).map_err(|source| {
                PersistNodeMetadataIndexError::Read {
                    path: self.path.clone(),
                    source,
                }
            })?;
            let entry =
                PersistNodeMetadataIndexEntry::decode_index_entry(&encoded).map_err(|source| {
                    PersistNodeMetadataIndexError::Format {
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
        ensure_node_metadata_index_file(&self.path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| PersistNodeMetadataIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| PersistNodeMetadataIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_node_metadata_index_len(&self.path, len)?;

        let mut latest = std::collections::BTreeMap::new();
        let records = len / PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64;
        let mut encoded = [0; PERSIST_NODE_METADATA_INDEX_ENTRY_LEN];
        for _ in 0..records {
            file.read_exact(&mut encoded).map_err(|source| {
                PersistNodeMetadataIndexError::Read {
                    path: self.path.clone(),
                    source,
                }
            })?;
            let entry =
                PersistNodeMetadataIndexEntry::decode_index_entry(&encoded).map_err(|source| {
                    PersistNodeMetadataIndexError::Format {
                        path: self.path.clone(),
                        source,
                    }
                })?;
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
        let rewrite_id = INDEX_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self
            .path
            .with_extension(format!("compact-{}-{rewrite_id}.tmp", std::process::id()));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|source| PersistNodeMetadataIndexError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
            for entry in &entries {
                file.write_all(&entry.encode_index_entry())
                    .map_err(|source| PersistNodeMetadataIndexError::Write {
                        path: tmp_path.clone(),
                        source,
                    })?;
            }
            file.flush()
                .map_err(|source| PersistNodeMetadataIndexError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
        }
        fs::rename(&tmp_path, &self.path).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            PersistNodeMetadataIndexError::Write {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(entries.len())
    }
}
