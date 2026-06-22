//! Versioned persistent-cache layout.
//!
//! The full Phase-2 storage engine will fill `nodes/`, `values/`, and `files/`
//! with verifying traces and content-addressed artifacts. This module owns the
//! on-disk layout contract and schema-version guard those stores share.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use super::parse::{
    PARSE_CACHE_SCHEMA_VERSION, ParseArtifactBundle, ParseCacheEntry, ParseCacheError,
    ParseCacheKey, ParseFileKey,
};
use super::{
    DurableBlake3Hash, MaterializationDecision, MaterializationReuse, MaterializationSignals,
};

/// The persistent eval-cache schema format marker.
pub const PERSIST_CACHE_FORMAT: &str = "aos-nix-eval-cache";
/// The persistent eval-cache schema version.
pub const PERSIST_CACHE_SCHEMA_VERSION: u32 = 1;
/// The fixed magic bytes at the start of every immutable blob packfile.
pub const PERSIST_BLOB_PACK_MAGIC: [u8; 16] = *b"AOS-NIX-BLOBPACK";
/// The immutable blob packfile format version.
pub const PERSIST_BLOB_PACK_VERSION: u32 = 1;
/// The encoded length of an immutable blob packfile header.
pub const PERSIST_BLOB_PACK_HEADER_LEN: usize = 24;
/// The encoded length of an immutable blob record header.
pub const PERSIST_BLOB_RECORD_HEADER_LEN: usize = 40;
/// The encoded length of a hash-to-offset index key.
pub const PERSIST_BLOB_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a hash-to-offset index value.
pub const PERSIST_BLOB_INDEX_VALUE_LEN: usize = 16;
/// The encoded length of a complete hash-to-offset index entry.
pub const PERSIST_BLOB_INDEX_ENTRY_LEN: usize =
    PERSIST_BLOB_INDEX_KEY_LEN + PERSIST_BLOB_INDEX_VALUE_LEN;
/// The encoded length of a file-artifact index key.
pub const PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a file-artifact index value.
pub const PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN: usize =
    PERSIST_BLOB_INDEX_KEY_LEN + PERSIST_BLOB_INDEX_VALUE_LEN;
/// The encoded length of a complete file-artifact index entry.
pub const PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN: usize =
    PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN + PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN;
/// The encoded length of durable materialization reuse metadata.
pub const PERSIST_MATERIALIZATION_REUSE_LEN: usize = 16;

static SCHEMA_WRITE_ID: AtomicU64 = AtomicU64::new(0);
const PERSIST_FILE_ARTIFACT_INDEX_TAG: u8 = 3;
const PERSIST_FILE_ARTIFACT_KEY_PERSONALIZATION: &[u8] = b"aos-nix-persist-file-artifact-key-v1";

/// A content-addressed immutable blob namespace in the persistent cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistBlobStore {
    /// Serialized WHNF values owned by the constructive value store.
    Values,
    /// Serialized frontend artifacts and file-derived cache payloads.
    Files,
}

impl PersistBlobStore {
    const fn index_tag(self) -> u8 {
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

impl MaterializationReuse {
    /// Encodes the counters as stable persistent metadata.
    ///
    /// The first little-endian `u64` is the previous-run demand count; the
    /// second is the current-run demand count. This only defines the record
    /// payload a future node-metadata index can store.
    pub fn encode_persist_metadata(self) -> [u8; PERSIST_MATERIALIZATION_REUSE_LEN] {
        let mut bytes = [0; PERSIST_MATERIALIZATION_REUSE_LEN];
        bytes[..8].copy_from_slice(&self.previous_run_demands().to_le_bytes());
        bytes[8..16].copy_from_slice(&self.current_run_demands().to_le_bytes());
        bytes
    }

    /// Decodes materialization reuse counters from stable persistent metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PersistPackFormatError::ShortMaterializationReuseMetadata`]
    /// if `bytes` is shorter than [`PERSIST_MATERIALIZATION_REUSE_LEN`].
    pub fn decode_persist_metadata(bytes: &[u8]) -> Result<Self, PersistPackFormatError> {
        if bytes.len() < PERSIST_MATERIALIZATION_REUSE_LEN {
            return Err(PersistPackFormatError::ShortMaterializationReuseMetadata {
                expected: PERSIST_MATERIALIZATION_REUSE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self::new(read_u64(&bytes[..8]), read_u64(&bytes[8..16])))
    }
}

/// The result of applying a durable materialization decision to a blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistMaterialization {
    /// The blob was appended to the selected persistent packfile.
    Materialized(PersistBlobLocation),
    /// The blob stayed in the in-process tier and no persistent bytes were written.
    Skipped,
}

impl PersistMaterialization {
    /// Returns the complete blob index entry when materialized.
    ///
    /// The caller must pass the same key that was used to materialize the blob;
    /// this type only records the pack location returned by the append path.
    pub const fn index_entry(self, key: PersistBlobKey) -> Option<PersistBlobIndexEntry> {
        match self {
            Self::Materialized(location) => Some(PersistBlobIndexEntry::new(key, location)),
            Self::Skipped => None,
        }
    }
}

/// The result of applying a durable materialization decision to a file artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistFileArtifactMaterialization {
    /// The artifact was appended to the `files/` pack and has index metadata.
    Materialized {
        /// The source realpath/content mapping key for the artifact.
        artifact_key: PersistFileArtifactKey,
        /// The file-blob lookup value a future durable index would store.
        index_value: PersistFileArtifactIndexValue,
    },
    /// The artifact stayed in the in-process tier and no persistent bytes were written.
    Skipped {
        /// The source realpath/content mapping key for the artifact.
        artifact_key: PersistFileArtifactKey,
    },
}

impl PersistFileArtifactMaterialization {
    /// Returns the source realpath/content mapping key.
    pub const fn artifact_key(self) -> PersistFileArtifactKey {
        match self {
            Self::Materialized { artifact_key, .. } | Self::Skipped { artifact_key } => {
                artifact_key
            }
        }
    }

    /// Returns the file-blob index value when the artifact was materialized.
    pub const fn index_value(self) -> Option<PersistFileArtifactIndexValue> {
        match self {
            Self::Materialized { index_value, .. } => Some(index_value),
            Self::Skipped { .. } => None,
        }
    }

    /// Returns the complete file-artifact index entry when materialized.
    pub const fn index_entry(self) -> Option<PersistFileArtifactIndexEntry> {
        match self {
            Self::Materialized {
                artifact_key,
                index_value,
            } => Some(PersistFileArtifactIndexEntry::new(
                artifact_key,
                index_value,
            )),
            Self::Skipped { .. } => None,
        }
    }
}

/// Filesystem paths for one persistent eval-cache root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistLayout {
    root: PathBuf,
}

impl PersistLayout {
    /// Creates paths rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the schema metadata path.
    pub fn schema_path(&self) -> PathBuf {
        self.root.join("schema.toml")
    }

    /// Returns the mutable node metadata directory.
    pub fn nodes_dir(&self) -> PathBuf {
        self.root.join("nodes")
    }

    /// Returns the durable value store directory.
    pub fn values_dir(&self) -> PathBuf {
        self.root.join("values")
    }

    /// Returns the durable file/frontend artifact directory.
    pub fn files_dir(&self) -> PathBuf {
        self.root.join("files")
    }

    /// Returns the append-only packfile path for immutable blobs in `store`.
    ///
    /// The helper only computes the path; callers remain responsible for the
    /// packfile format, memory mapping, append protocol, and hash-to-offset
    /// index updates.
    pub fn blob_packfile_path(&self, store: PersistBlobStore) -> PathBuf {
        self.blob_store_dir(store).join("pack.blob")
    }

    /// Returns the fixed-record hash-to-offset index path for blobs in `store`.
    pub fn blob_index_path(&self, store: PersistBlobStore) -> PathBuf {
        self.blob_store_dir(store).join("index.blob")
    }

    /// Returns the fixed-record file-artifact mapping index path.
    pub fn file_artifact_index_path(&self) -> PathBuf {
        self.nodes_dir().join("file-artifacts.index")
    }

    /// Returns the append-only packfile path for serialized value blobs.
    pub fn value_packfile_path(&self) -> PathBuf {
        self.blob_packfile_path(PersistBlobStore::Values)
    }

    /// Returns the append-only packfile path for serialized file blobs.
    pub fn file_packfile_path(&self) -> PathBuf {
        self.blob_packfile_path(PersistBlobStore::Files)
    }

    /// Returns the fixed-record hash-to-offset index path for serialized values.
    pub fn value_index_path(&self) -> PathBuf {
        self.blob_index_path(PersistBlobStore::Values)
    }

    /// Returns the fixed-record hash-to-offset index path for serialized files.
    pub fn file_index_path(&self) -> PathBuf {
        self.blob_index_path(PersistBlobStore::Files)
    }

    fn blob_store_dir(&self, store: PersistBlobStore) -> PathBuf {
        match store {
            PersistBlobStore::Values => self.values_dir(),
            PersistBlobStore::Files => self.files_dir(),
        }
    }
}

/// An initialized immutable blob packfile.
#[derive(Clone, Debug)]
pub struct PersistBlobPack {
    path: PathBuf,
}

impl PersistBlobPack {
    /// Opens or initializes an immutable blob packfile at `path`.
    ///
    /// An empty file is initialized with the current packfile header. A
    /// non-empty file must already contain a valid current header.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if parent directories or the packfile
    /// cannot be created/opened/read/written, or if existing packfile metadata
    /// is invalid.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistBlobPackError> {
        let path = path.into();
        ensure_blob_pack_file(&path)?;
        Ok(Self { path })
    }

    /// Returns this packfile's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends `payload` as a content-addressed immutable blob.
    ///
    /// The payload is checked against `hash` before any bytes are appended.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened,
    /// validated, or written, or if `hash` does not match `payload`.
    pub fn append_blob(
        &self,
        hash: DurableBlake3Hash,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        ensure_blob_pack_file(&self.path)?;
        let actual = DurableBlake3Hash::for_bytes(payload);
        if actual != hash {
            return Err(PersistBlobPackError::PayloadHashMismatch {
                expected: hash,
                actual,
            });
        }
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| PersistBlobPackError::PayloadTooLarge {
                payload_len: payload.len() as u128,
            })?;
        let header = PersistBlobRecordHeader::new(hash, payload_len);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| PersistBlobPackError::Open {
                path: self.path.clone(),
                source,
            })?;
        let record_offset = file
            .metadata()
            .map_err(|source| PersistBlobPackError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        if record_offset < PERSIST_BLOB_PACK_HEADER_LEN as u64 {
            return Err(PersistBlobPackError::InvalidRecordOffset { record_offset });
        }
        file.write_all(&header.encode())
            .and_then(|()| file.write_all(payload))
            .and_then(|()| file.flush())
            .map_err(|source| PersistBlobPackError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(PersistBlobLocation::new(record_offset, payload_len))
    }

    /// Reads and verifies a blob at `location`.
    ///
    /// The record header's hash and length must match `expected_hash` and
    /// `location`, and the payload bytes must hash to `expected_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the packfile cannot be opened or
    /// read, if `location` is invalid, if record metadata does not match the
    /// expected lookup, or if the payload hash does not verify.
    pub fn read_blob(
        &self,
        location: PersistBlobLocation,
        expected_hash: DurableBlake3Hash,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        if location.record_offset() < PERSIST_BLOB_PACK_HEADER_LEN as u64 {
            return Err(PersistBlobPackError::InvalidRecordOffset {
                record_offset: location.record_offset(),
            });
        }
        let mut file = open_validated_blob_pack_for_read(&self.path)?;
        file.seek(SeekFrom::Start(location.record_offset()))
            .map_err(|source| PersistBlobPackError::Seek {
                path: self.path.clone(),
                source,
            })?;
        let mut record_header = [0; PERSIST_BLOB_RECORD_HEADER_LEN];
        file.read_exact(&mut record_header)
            .map_err(|source| PersistBlobPackError::Read {
                path: self.path.clone(),
                source,
            })?;
        let record = PersistBlobRecordHeader::decode(&record_header).map_err(|source| {
            PersistBlobPackError::Format {
                path: self.path.clone(),
                source,
            }
        })?;
        if record.hash() != expected_hash {
            return Err(PersistBlobPackError::RecordHashMismatch {
                expected: expected_hash,
                actual: record.hash(),
            });
        }
        if record.payload_len() != location.payload_len() {
            return Err(PersistBlobPackError::RecordLengthMismatch {
                expected: location.payload_len(),
                actual: record.payload_len(),
            });
        }
        let payload_start = location
            .record_offset()
            .checked_add(PERSIST_BLOB_RECORD_HEADER_LEN as u64)
            .ok_or(PersistBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: record.payload_len(),
            })?;
        let payload_end = payload_start.checked_add(record.payload_len()).ok_or(
            PersistBlobPackError::RecordBoundsOverflow {
                record_offset: location.record_offset(),
                payload_len: record.payload_len(),
            },
        )?;
        let pack_len = file
            .metadata()
            .map_err(|source| PersistBlobPackError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        if payload_end > pack_len {
            return Err(PersistBlobPackError::RecordExtendsPastEnd {
                payload_end,
                pack_len,
            });
        }
        let payload_len = usize::try_from(record.payload_len()).map_err(|_| {
            PersistBlobPackError::PayloadTooLarge {
                payload_len: record.payload_len() as u128,
            }
        })?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_len).map_err(|_| {
            PersistBlobPackError::PayloadTooLarge {
                payload_len: record.payload_len() as u128,
            }
        })?;
        payload.resize(payload_len, 0);
        file.read_exact(&mut payload)
            .map_err(|source| PersistBlobPackError::Read {
                path: self.path.clone(),
                source,
            })?;
        let actual = DurableBlake3Hash::for_bytes(&payload);
        if actual != expected_hash {
            return Err(PersistBlobPackError::PayloadHashMismatch {
                expected: expected_hash,
                actual,
            });
        }
        Ok(payload)
    }
}

/// An opened persistent eval-cache root.
#[derive(Clone, Debug)]
pub struct PersistCache {
    layout: PersistLayout,
    value_pack: PersistBlobPack,
    file_pack: PersistBlobPack,
    value_index: PersistBlobIndex,
    file_index: PersistBlobIndex,
    file_artifact_index: PersistFileArtifactIndex,
}

impl PersistCache {
    /// Opens or initializes a persistent eval-cache root.
    ///
    /// A matching schema preserves existing payload directories. A well-formed
    /// mismatched schema discards `nodes/`, `values/`, and `files/` before
    /// rewriting current metadata. Malformed schema metadata is reported as an
    /// error and is not discarded.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError`] if schema metadata cannot be read, parsed,
    /// written, if cache directories cannot be created or discarded, or if blob
    /// packfiles cannot be initialized.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PersistError> {
        let layout = PersistLayout::new(root);
        match read_schema_version(&layout)? {
            Some(PERSIST_CACHE_SCHEMA_VERSION) => {
                ensure_payload_dirs(&layout)?;
            }
            Some(_) => {
                discard_payload_dirs(&layout)?;
                ensure_payload_dirs(&layout)?;
                write_schema(&layout)?;
            }
            None => {
                ensure_payload_dirs(&layout)?;
                write_schema(&layout)?;
            }
        }
        let value_pack_path = layout.value_packfile_path();
        let value_pack = PersistBlobPack::open(value_pack_path.clone()).map_err(|source| {
            PersistError::OpenBlobPack {
                path: value_pack_path,
                source,
            }
        })?;
        let file_pack_path = layout.file_packfile_path();
        let file_pack = PersistBlobPack::open(file_pack_path.clone()).map_err(|source| {
            PersistError::OpenBlobPack {
                path: file_pack_path,
                source,
            }
        })?;
        let value_index_path = layout.value_index_path();
        let value_index = PersistBlobIndex::open(value_index_path.clone()).map_err(|source| {
            PersistError::OpenBlobIndex {
                path: value_index_path,
                source,
            }
        })?;
        let file_index_path = layout.file_index_path();
        let file_index = PersistBlobIndex::open(file_index_path.clone()).map_err(|source| {
            PersistError::OpenBlobIndex {
                path: file_index_path,
                source,
            }
        })?;
        let file_artifact_index_path = layout.file_artifact_index_path();
        let file_artifact_index = PersistFileArtifactIndex::open(file_artifact_index_path.clone())
            .map_err(|source| PersistError::OpenFileArtifactIndex {
                path: file_artifact_index_path,
                source,
            })?;
        Ok(Self {
            layout,
            value_pack,
            file_pack,
            value_index,
            file_index,
            file_artifact_index,
        })
    }

    /// Returns this cache's filesystem layout.
    pub const fn layout(&self) -> &PersistLayout {
        &self.layout
    }

    /// Returns the immutable value blob packfile.
    pub const fn value_pack(&self) -> &PersistBlobPack {
        &self.value_pack
    }

    /// Returns the immutable file/frontend artifact blob packfile.
    pub const fn file_pack(&self) -> &PersistBlobPack {
        &self.file_pack
    }

    /// Returns the fixed-record blob index for serialized value blobs.
    pub const fn value_index(&self) -> &PersistBlobIndex {
        &self.value_index
    }

    /// Returns the fixed-record blob index for serialized file blobs.
    pub const fn file_index(&self) -> &PersistBlobIndex {
        &self.file_index
    }

    /// Returns the fixed-record index for durable file-artifact mappings.
    pub const fn file_artifact_index(&self) -> &PersistFileArtifactIndex {
        &self.file_artifact_index
    }

    /// Returns the fixed-record blob index for `store`.
    pub const fn blob_index(&self, store: PersistBlobStore) -> &PersistBlobIndex {
        match store {
            PersistBlobStore::Values => &self.value_index,
            PersistBlobStore::Files => &self.file_index,
        }
    }

    /// Returns the immutable blob packfile for `store`.
    pub fn blob_pack(&self, store: PersistBlobStore) -> &PersistBlobPack {
        match store {
            PersistBlobStore::Values => &self.value_pack,
            PersistBlobStore::Files => &self.file_pack,
        }
    }

    /// Appends a blob to the packfile selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected packfile cannot be
    /// opened, validated, or written, or if `payload` does not hash to
    /// `key.hash()`.
    pub fn append_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobLocation, PersistBlobPackError> {
        self.blob_pack(key.store()).append_blob(key.hash(), payload)
    }

    /// Reads a blob from the packfile selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the selected packfile cannot be
    /// opened or read, if `location` is invalid, or if record/payload hashes do
    /// not match `key.hash()`.
    pub fn read_blob(
        &self,
        key: PersistBlobKey,
        location: PersistBlobLocation,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.blob_pack(key.store()).read_blob(location, key.hash())
    }

    /// Appends a durable file-artifact mapping entry to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the sidecar index cannot be
    /// opened, validated, written, or flushed.
    pub fn record_file_artifact(
        &self,
        entry: PersistFileArtifactIndexEntry,
    ) -> Result<(), PersistFileArtifactIndexError> {
        self.file_artifact_index.append_entry(entry)
    }

    /// Looks up a durable file-artifact mapping through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexError`] if the sidecar index cannot be
    /// opened, read, or decoded.
    pub fn lookup_file_artifact(
        &self,
        key: PersistFileArtifactKey,
    ) -> Result<Option<PersistFileArtifactIndexValue>, PersistFileArtifactIndexError> {
        self.file_artifact_index.lookup(key)
    }

    /// Looks up a blob location through the sidecar index selected by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexError`] if the selected index cannot be
    /// opened, read, or decoded.
    pub fn lookup_blob_location(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<PersistBlobLocation>, PersistBlobIndexError> {
        self.blob_index(key.store()).lookup(key)
    }

    /// Appends a blob and records its location in the sidecar index.
    ///
    /// This helper is explicit and non-transactional: if the pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] if the selected packfile cannot
    /// append/verify the payload, or if the selected sidecar index cannot write
    /// the resulting hash-to-offset record.
    pub fn append_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let location = self
            .append_blob(key, payload)
            .map_err(|source| PersistBlobIndexedWriteError::Append { source })?;
        let entry = PersistBlobIndexEntry::new(key, location);
        self.blob_index(key.store())
            .append_entry(entry)
            .map_err(|source| PersistBlobIndexedWriteError::Index { source })?;
        Ok(entry)
    }

    /// Reads a blob through the sidecar index selected by `key`.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedReadError`] if the selected index cannot be
    /// read/decoded or if the indexed pack location cannot be read and verified.
    pub fn read_blob_indexed(
        &self,
        key: PersistBlobKey,
    ) -> Result<Option<Vec<u8>>, PersistBlobIndexedReadError> {
        let Some(location) = self
            .lookup_blob_location(key)
            .map_err(|source| PersistBlobIndexedReadError::Lookup { source })?
        else {
            return Ok(None);
        };
        self.read_blob(key, location)
            .map(Some)
            .map_err(|source| PersistBlobIndexedReadError::Read { source })
    }

    /// Applies `decision` to `payload` in the packfile selected by `key`.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing or writing
    /// `payload`. [`MaterializationDecision::Materialize`] appends the payload
    /// through [`Self::append_blob`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the selected packfile cannot
    /// be opened, validated, or written, or when `payload` does not hash to
    /// `key.hash()`.
    pub fn materialize_blob(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistBlobPackError> {
        match decision {
            MaterializationDecision::Materialize => self
                .append_blob(key, payload)
                .map(PersistMaterialization::Materialized),
            MaterializationDecision::KeepInMemory => Ok(PersistMaterialization::Skipped),
        }
    }

    /// Applies `decision` to `payload` and records materialized blobs in the
    /// sidecar index.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing or writing
    /// `payload`. [`MaterializationDecision::Materialize`] appends the payload
    /// through [`Self::append_blob_indexed`].
    ///
    /// This helper is explicit and non-transactional: if the pack append
    /// succeeds but the sidecar index write fails, the blob bytes remain in the
    /// pack without a corresponding durable index record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the selected packfile cannot
    /// append/verify the payload, or when the selected sidecar index cannot
    /// write the resulting hash-to-offset record.
    pub fn materialize_blob_indexed(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistBlobIndexedWriteError> {
        match decision {
            MaterializationDecision::Materialize => self
                .append_blob_indexed(key, payload)
                .map(|entry| PersistMaterialization::Materialized(entry.location())),
            MaterializationDecision::KeepInMemory => Ok(PersistMaterialization::Skipped),
        }
    }

    /// Applies materialization threshold signals to `payload`.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_blob`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the selected packfile cannot
    /// be opened, validated, or written, or when `payload` does not hash to
    /// `key.hash()`.
    pub fn materialize_blob_with_signals(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistBlobPackError> {
        self.materialize_blob(key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to indexed blob materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_blob_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the selected packfile cannot
    /// append/verify the payload, or when the selected sidecar index cannot
    /// write the resulting hash-to-offset record.
    pub fn materialize_blob_indexed_with_signals(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistBlobIndexedWriteError> {
        self.materialize_blob_indexed(key, payload, signals.decide())
    }

    /// Applies `decision` to a frontend file artifact payload.
    ///
    /// The artifact mapping key is derived from `file_key` and `parse_key`.
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, appends it to the `files/` pack, and returns the typed
    /// index value a future durable index would store.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the `files/` pack cannot be
    /// opened, validated, or written.
    pub fn materialize_file_artifact(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistBlobPackError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let location = self.append_blob(PersistBlobKey::for_file(blob_hash), payload)?;
                Ok(PersistFileArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value: PersistFileArtifactIndexValue::new(blob_hash, location),
                })
            }
        }
    }

    /// Applies materialization threshold signals to a frontend file artifact.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_file_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` pack cannot be
    /// opened, validated, or written.
    pub fn materialize_file_artifact_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistBlobPackError> {
        self.materialize_file_artifact(file_key, parse_key, payload, signals.decide())
    }

    /// Reads and verifies a materialized frontend file artifact.
    ///
    /// This is a typed wrapper over [`Self::read_blob`] for values decoded from
    /// the future file-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the `files/` pack cannot be opened
    /// or read, if `index_value` points at an invalid location, or if the record
    /// or payload hash does not match `index_value`.
    pub fn read_file_artifact(
        &self,
        index_value: PersistFileArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob(index_value.blob_key(), index_value.location())
    }

    /// Reads a materialized parse-artifact bundle into a parse-cache entry.
    ///
    /// This adapter consumes a caller-supplied file-artifact index value and
    /// target entry. The decoded bundle must validate against the current
    /// parse-cache schema before any entry files are written. This adapter does
    /// not perform durable index lookup or decide whether the hydrated entry
    /// should be used for a cache hit.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if the artifact cannot be
    /// read from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_file_artifact_bundle(
        &self,
        index_value: PersistFileArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let payload = self
            .read_file_artifact(index_value)
            .map_err(|source| PersistFileArtifactHydrationError::Read { source })?;
        let bundle = ParseArtifactBundle::decode(&payload)
            .map_err(|source| PersistFileArtifactHydrationError::Decode { source })?;
        bundle
            .validate_meta(PARSE_CACHE_SCHEMA_VERSION)
            .map_err(|source| PersistFileArtifactHydrationError::Validate { source })?;
        entry
            .write_artifact_bundle(&bundle)
            .map_err(|source| PersistFileArtifactHydrationError::Write { source })
    }

    /// Reads a keyed parse-artifact bundle into a parse-cache entry.
    ///
    /// The supplied `artifact_key` must match the key derived from `file_key`
    /// and `parse_key` before the `files/` pack is read. This adapter still
    /// relies on its caller to perform the durable index lookup.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if `artifact_key` does not
    /// match `file_key`/`parse_key`, if the artifact cannot be read from the
    /// `files/` pack, if the payload is not a valid [`ParseArtifactBundle`], if
    /// the bundle metadata/artifact counts do not validate, or if the target
    /// entry cannot be written.
    pub fn hydrate_file_artifact_bundle_for_key(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        artifact_key: PersistFileArtifactKey,
        index_value: PersistFileArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        let expected = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        if artifact_key != expected {
            return Err(PersistFileArtifactHydrationError::KeyMismatch {
                expected,
                actual: artifact_key,
            });
        }
        self.hydrate_file_artifact_bundle(index_value, entry)
    }

    /// Reads an indexed parse-artifact bundle into a parse-cache entry.
    ///
    /// This is the entry-shaped variant of
    /// [`Self::hydrate_file_artifact_bundle_for_key`]. It still relies on its
    /// caller to perform the durable index lookup that produced `index_entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactHydrationError`] if `index_entry.key()`
    /// does not match `file_key`/`parse_key`, if the artifact cannot be read
    /// from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_file_artifact_bundle_from_entry(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        index_entry: PersistFileArtifactIndexEntry,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistFileArtifactHydrationError> {
        self.hydrate_file_artifact_bundle_for_key(
            file_key,
            parse_key,
            index_entry.key(),
            index_entry.value(),
            entry,
        )
    }

    /// Applies `decision` to an existing parse-cache artifact entry.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without reading or encoding `entry`. [`MaterializationDecision::Materialize`]
    /// reads the entry as a [`ParseArtifactBundle`], encodes it as one payload,
    /// and appends it through [`Self::materialize_file_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the source entry cannot be
    /// read, the bundle payload cannot be encoded, or the `files/` pack cannot
    /// be written.
    pub fn materialize_parse_artifact_entry(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let bundle = entry.read_artifact_bundle().map_err(|source| {
                    PersistParseArtifactMaterializationError::ReadBundle { source }
                })?;
                let payload = bundle.encode().map_err(|source| {
                    PersistParseArtifactMaterializationError::EncodeBundle { source }
                })?;
                self.materialize_file_artifact(
                    file_key,
                    parse_key,
                    &payload,
                    MaterializationDecision::Materialize,
                )
                .map_err(|source| PersistParseArtifactMaterializationError::Write { source })
            }
        }
    }

    /// Applies materialization threshold signals to an existing parse-cache entry.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_entry`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when the signals
    /// choose [`MaterializationDecision::Materialize`] and the source entry
    /// cannot be read, the bundle payload cannot be encoded, or the `files/`
    /// pack cannot be written.
    pub fn materialize_parse_artifact_entry_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        self.materialize_parse_artifact_entry(file_key, parse_key, entry, signals.decide())
    }
}

/// Immutable blob packfile metadata could not be decoded.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PersistPackFormatError {
    /// A blob index key was shorter than the fixed encoded key length.
    #[error("persistent blob index key has {actual} bytes, expected at least {expected}")]
    ShortBlobIndexKey {
        /// The required fixed index key length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A blob index key carried an unknown store tag.
    #[error("persistent blob index key has invalid store tag {tag}")]
    InvalidBlobIndexStoreTag {
        /// The unknown store tag.
        tag: u8,
    },
    /// A file-artifact index key was shorter than the fixed encoded key length.
    #[error("persistent file artifact index key has {actual} bytes, expected at least {expected}")]
    ShortFileArtifactIndexKey {
        /// The required fixed file-artifact index key length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A file-artifact index key carried an unexpected index tag.
    #[error("persistent file artifact index key has invalid tag {tag}")]
    InvalidFileArtifactIndexTag {
        /// The unexpected index tag.
        tag: u8,
    },
    /// The packfile header was shorter than the fixed header length.
    #[error("persistent blob pack header has {actual} bytes, expected at least {expected}")]
    ShortPackHeader {
        /// The required fixed header length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// The packfile header did not start with the expected magic bytes.
    #[error("persistent blob pack header has invalid magic bytes {actual:?}")]
    InvalidPackMagic {
        /// The observed magic bytes.
        actual: [u8; 16],
    },
    /// The packfile header declares an unsupported format version.
    #[error("persistent blob pack header declares unsupported version {version}")]
    UnsupportedPackVersion {
        /// The unsupported format version.
        version: u32,
    },
    /// The packfile header declares an unexpected encoded header length.
    #[error("persistent blob pack header declares invalid header length {header_len}")]
    InvalidPackHeaderLength {
        /// The unexpected header length.
        header_len: u32,
    },
    /// A record header was shorter than the fixed record header length.
    #[error("persistent blob record header has {actual} bytes, expected at least {expected}")]
    ShortRecordHeader {
        /// The required fixed record header length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// An index value was shorter than the fixed encoded location length.
    #[error("persistent blob index value has {actual} bytes, expected at least {expected}")]
    ShortIndexValue {
        /// The required fixed index value length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A blob index entry was shorter than the fixed encoded length.
    #[error("persistent blob index entry has {actual} bytes, expected at least {expected}")]
    ShortBlobIndexEntry {
        /// The required fixed blob index entry length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A file-artifact index value was shorter than the fixed encoded length.
    #[error(
        "persistent file artifact index value has {actual} bytes, expected at least {expected}"
    )]
    ShortFileArtifactIndexValue {
        /// The required fixed file-artifact index value length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A file-artifact index entry was shorter than the fixed encoded length.
    #[error(
        "persistent file artifact index entry has {actual} bytes, expected at least {expected}"
    )]
    ShortFileArtifactIndexEntry {
        /// The required fixed file-artifact index entry length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
    /// A file-artifact index value pointed at a non-file blob store.
    #[error("persistent file artifact index value points at {store:?}, expected Files")]
    InvalidFileArtifactBlobStore {
        /// The decoded blob store.
        store: PersistBlobStore,
    },
    /// Materialization reuse metadata was shorter than the fixed encoded length.
    #[error(
        "persistent materialization reuse metadata has {actual} bytes, expected at least {expected}"
    )]
    ShortMaterializationReuseMetadata {
        /// The required fixed reuse metadata length.
        expected: usize,
        /// The available bytes.
        actual: usize,
    },
}

/// Fixed-record blob index file IO failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexError {
    /// The index parent directory could not be created.
    #[error("failed to create persistent blob index parent {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open persistent blob index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read persistent blob index metadata {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read persistent blob index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write persistent blob index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("persistent blob index {path:?} has invalid format: {source}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
}

/// Fixed-record file-artifact index file IO failed.
#[derive(Debug, Error)]
pub enum PersistFileArtifactIndexError {
    /// The index parent directory could not be created.
    #[error("failed to create persistent file artifact index parent {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open persistent file artifact index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read persistent file artifact index metadata {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read persistent file artifact index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write persistent file artifact index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("persistent file artifact index {path:?} has invalid format: {source}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
}

/// Indexed blob append failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexedWriteError {
    /// The blob could not be appended to its selected packfile.
    #[error("failed to append indexed persistent blob")]
    Append {
        /// The underlying packfile error.
        source: PersistBlobPackError,
    },
    /// The appended blob location could not be recorded in the sidecar index.
    #[error("failed to record indexed persistent blob location")]
    Index {
        /// The underlying index error.
        source: PersistBlobIndexError,
    },
}

/// Indexed blob read failed.
#[derive(Debug, Error)]
pub enum PersistBlobIndexedReadError {
    /// The sidecar index lookup failed.
    #[error("failed to look up indexed persistent blob")]
    Lookup {
        /// The underlying index error.
        source: PersistBlobIndexError,
    },
    /// The indexed packfile location could not be read and verified.
    #[error("failed to read indexed persistent blob")]
    Read {
        /// The underlying packfile error.
        source: PersistBlobPackError,
    },
}

/// Immutable blob packfile IO failed.
#[derive(Debug, Error)]
pub enum PersistBlobPackError {
    /// The packfile's parent directory could not be created.
    #[error("failed to create persistent blob pack parent directory {path}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile could not be opened.
    #[error("failed to open persistent blob pack {path}")]
    Open {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile metadata could not be read.
    #[error("failed to inspect persistent blob pack {path}")]
    Metadata {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile could not be seeked.
    #[error("failed to seek persistent blob pack {path}")]
    Seek {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile could not be read.
    #[error("failed to read persistent blob pack {path}")]
    Read {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile could not be written.
    #[error("failed to write persistent blob pack {path}")]
    Write {
        /// The packfile path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// The packfile metadata has an unsupported or malformed format.
    #[error("persistent blob pack {path} has invalid metadata")]
    Format {
        /// The packfile path.
        path: PathBuf,
        /// The format error.
        source: PersistPackFormatError,
    },
    /// A caller supplied a record offset inside the fixed packfile header.
    #[error("persistent blob pack record offset {record_offset} points inside the pack header")]
    InvalidRecordOffset {
        /// The invalid record offset.
        record_offset: u64,
    },
    /// A blob payload cannot fit in the local address space or on-disk length field.
    #[error("persistent blob payload length {payload_len} is too large")]
    PayloadTooLarge {
        /// The oversized payload length.
        payload_len: u128,
    },
    /// Record metadata did not match the hash looked up through the index.
    #[error("persistent blob record hash mismatch: expected {expected}, got {actual}")]
    RecordHashMismatch {
        /// The expected durable hash from the lookup key.
        expected: DurableBlake3Hash,
        /// The durable hash declared by the record.
        actual: DurableBlake3Hash,
    },
    /// Record metadata did not match the length looked up through the index.
    #[error("persistent blob record length mismatch: expected {expected}, got {actual}")]
    RecordLengthMismatch {
        /// The expected payload length from the lookup location.
        expected: u64,
        /// The payload length declared by the record.
        actual: u64,
    },
    /// Record metadata cannot be represented as an in-pack byte range.
    #[error(
        "persistent blob record at offset {record_offset} with payload length {payload_len} overflows"
    )]
    RecordBoundsOverflow {
        /// The record offset.
        record_offset: u64,
        /// The record payload length.
        payload_len: u64,
    },
    /// Record metadata points beyond the end of the packfile.
    #[error("persistent blob record ends at {payload_end}, past pack length {pack_len}")]
    RecordExtendsPastEnd {
        /// The byte offset one past the declared record payload.
        payload_end: u64,
        /// The current packfile length.
        pack_len: u64,
    },
    /// Blob payload bytes did not match the expected content hash.
    #[error("persistent blob payload hash mismatch: expected {expected}, got {actual}")]
    PayloadHashMismatch {
        /// The expected durable hash.
        expected: DurableBlake3Hash,
        /// The hash computed from the payload bytes.
        actual: DurableBlake3Hash,
    },
}

/// Persistent file-artifact hydration failed.
#[derive(Debug, Error)]
pub enum PersistFileArtifactHydrationError {
    /// The supplied artifact key does not match the requested source identity.
    #[error("persistent file artifact key mismatch: expected {expected:?}, got {actual:?}")]
    KeyMismatch {
        /// The key derived from the requested file and parse identities.
        expected: PersistFileArtifactKey,
        /// The key supplied by the caller's artifact lookup.
        actual: PersistFileArtifactKey,
    },
    /// The materialized artifact payload could not be read from the `files/` pack.
    #[error("failed to read persistent file artifact")]
    Read {
        /// The underlying packfile read error.
        source: PersistBlobPackError,
    },
    /// The materialized artifact payload was not a valid parse-artifact bundle.
    #[error("failed to decode persistent file artifact bundle")]
    Decode {
        /// The underlying bundle decode error.
        source: ParseCacheError,
    },
    /// The decoded artifact bundle failed parse-cache schema/count validation.
    #[error("failed to validate persistent file artifact bundle")]
    Validate {
        /// The underlying parse-cache validation error.
        source: ParseCacheError,
    },
    /// The decoded artifact bundle could not be written to the target entry.
    #[error("failed to hydrate parse-cache entry from persistent file artifact")]
    Write {
        /// The underlying parse-cache write error.
        source: ParseCacheError,
    },
}

/// Persistent parse-artifact materialization failed.
#[derive(Debug, Error)]
pub enum PersistParseArtifactMaterializationError {
    /// The source parse-cache entry could not be read as an artifact bundle.
    #[error("failed to read parse-cache artifact bundle for persistent materialization")]
    ReadBundle {
        /// The underlying parse-cache read error.
        source: ParseCacheError,
    },
    /// The parse-cache artifact bundle could not be encoded as one payload.
    #[error("failed to encode parse-cache artifact bundle for persistent materialization")]
    EncodeBundle {
        /// The underlying bundle encode error.
        source: ParseCacheError,
    },
    /// The encoded artifact payload could not be written to the `files/` pack.
    #[error("failed to write parse-cache artifact bundle to persistent files pack")]
    Write {
        /// The underlying packfile write error.
        source: PersistBlobPackError,
    },
}

/// Persistent-cache layout initialization failed.
#[derive(Debug, Error)]
pub enum PersistError {
    /// The cache root or payload directory could not be created.
    #[error("failed to create persistent cache directory {path}")]
    CreateDir {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Existing cache payload could not be discarded after a schema mismatch.
    #[error("failed to discard persistent cache payload {path}")]
    DiscardPayload {
        /// The path that could not be removed.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Schema metadata could not be read.
    #[error("failed to read persistent cache schema {path}")]
    ReadSchema {
        /// The schema file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// Schema metadata could not be parsed as TOML.
    #[error("failed to parse persistent cache schema {path}")]
    ParseSchema {
        /// The schema file path.
        path: PathBuf,
        /// The TOML parse error.
        source: toml::de::Error,
    },
    /// Schema metadata did not contain an integer `schema_version`.
    #[error("persistent cache schema {path} is missing integer schema_version")]
    MissingSchemaVersion {
        /// The schema file path.
        path: PathBuf,
    },
    /// Schema metadata did not contain a string `format`.
    #[error("persistent cache schema {path} is missing string format")]
    MissingFormat {
        /// The schema file path.
        path: PathBuf,
    },
    /// Schema metadata was for another cache format.
    #[error("persistent cache schema {path} has unsupported format {format:?}")]
    InvalidFormat {
        /// The schema file path.
        path: PathBuf,
        /// The unsupported schema format.
        format: String,
    },
    /// Schema metadata contained a version outside the supported `u32` range.
    #[error("persistent cache schema {path} has unsupported schema_version {version}")]
    InvalidSchemaVersion {
        /// The schema file path.
        path: PathBuf,
        /// The unsupported schema version.
        version: i64,
    },
    /// Schema metadata could not be written.
    #[error("failed to write persistent cache schema {path}")]
    WriteSchema {
        /// The schema file path.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },
    /// A value/file blob packfile could not be initialized.
    #[error("failed to initialize persistent blob pack {path}")]
    OpenBlobPack {
        /// The blob packfile path.
        path: PathBuf,
        /// The underlying packfile error.
        source: PersistBlobPackError,
    },
    /// A value/file blob index file could not be initialized.
    #[error("failed to initialize persistent blob index {path}")]
    OpenBlobIndex {
        /// The blob index file path.
        path: PathBuf,
        /// The underlying index error.
        source: PersistBlobIndexError,
    },
    /// The file-artifact mapping index file could not be initialized.
    #[error("failed to initialize persistent file artifact index {path}")]
    OpenFileArtifactIndex {
        /// The file-artifact index file path.
        path: PathBuf,
        /// The underlying index error.
        source: PersistFileArtifactIndexError,
    },
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut raw = [0; 4];
    raw.copy_from_slice(bytes);
    u32::from_le_bytes(raw)
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut raw = [0; 8];
    raw.copy_from_slice(bytes);
    u64::from_le_bytes(raw)
}

fn update_persist_index_chunk(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn ensure_blob_index_file(path: &Path) -> Result<(), PersistBlobIndexError> {
    ensure_blob_index_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|source| PersistBlobIndexError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| PersistBlobIndexError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_blob_index_len(path, len)
}

fn ensure_blob_index_parent(path: &Path) -> Result<(), PersistBlobIndexError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|source| PersistBlobIndexError::CreateParent {
        path: parent.to_path_buf(),
        source,
    })
}

fn validate_blob_index_len(path: &Path, len: u64) -> Result<(), PersistBlobIndexError> {
    let remainder = len % PERSIST_BLOB_INDEX_ENTRY_LEN as u64;
    if remainder == 0 {
        return Ok(());
    }
    Err(PersistBlobIndexError::Format {
        path: path.to_path_buf(),
        source: PersistPackFormatError::ShortBlobIndexEntry {
            expected: PERSIST_BLOB_INDEX_ENTRY_LEN,
            actual: remainder as usize,
        },
    })
}

fn ensure_file_artifact_index_file(path: &Path) -> Result<(), PersistFileArtifactIndexError> {
    ensure_file_artifact_index_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|source| PersistFileArtifactIndexError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| PersistFileArtifactIndexError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_file_artifact_index_len(path, len)
}

fn ensure_file_artifact_index_parent(path: &Path) -> Result<(), PersistFileArtifactIndexError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|source| PersistFileArtifactIndexError::CreateParent {
        path: parent.to_path_buf(),
        source,
    })
}

fn validate_file_artifact_index_len(
    path: &Path,
    len: u64,
) -> Result<(), PersistFileArtifactIndexError> {
    let remainder = len % PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64;
    if remainder == 0 {
        return Ok(());
    }
    Err(PersistFileArtifactIndexError::Format {
        path: path.to_path_buf(),
        source: PersistPackFormatError::ShortFileArtifactIndexEntry {
            expected: PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN,
            actual: remainder as usize,
        },
    })
}

fn ensure_blob_pack_file(path: &Path) -> Result<(), PersistBlobPackError> {
    ensure_blob_pack_parent(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|source| PersistBlobPackError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| PersistBlobPackError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    match len {
        0 => file
            .write_all(&PersistBlobPackHeader::current().encode())
            .and_then(|()| file.flush())
            .map_err(|source| PersistBlobPackError::Write {
                path: path.to_path_buf(),
                source,
            }),
        len if len < PERSIST_BLOB_PACK_HEADER_LEN as u64 => Err(PersistBlobPackError::Format {
            path: path.to_path_buf(),
            source: PersistPackFormatError::ShortPackHeader {
                expected: PERSIST_BLOB_PACK_HEADER_LEN,
                actual: len as usize,
            },
        }),
        _ => validate_blob_pack_header(path, &mut file),
    }
}

fn ensure_blob_pack_parent(path: &Path) -> Result<(), PersistBlobPackError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|source| PersistBlobPackError::CreateParent {
        path: parent.to_path_buf(),
        source,
    })
}

fn open_validated_blob_pack_for_read(path: &Path) -> Result<std::fs::File, PersistBlobPackError> {
    let mut file =
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|source| PersistBlobPackError::Open {
                path: path.to_path_buf(),
                source,
            })?;
    validate_blob_pack_header(path, &mut file)?;
    Ok(file)
}

fn validate_blob_pack_header(
    path: &Path,
    file: &mut std::fs::File,
) -> Result<(), PersistBlobPackError> {
    let len = file
        .metadata()
        .map_err(|source| PersistBlobPackError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if len < PERSIST_BLOB_PACK_HEADER_LEN as u64 {
        return Err(PersistBlobPackError::Format {
            path: path.to_path_buf(),
            source: PersistPackFormatError::ShortPackHeader {
                expected: PERSIST_BLOB_PACK_HEADER_LEN,
                actual: len as usize,
            },
        });
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| PersistBlobPackError::Seek {
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = [0; PERSIST_BLOB_PACK_HEADER_LEN];
    file.read_exact(&mut bytes)
        .map_err(|source| PersistBlobPackError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    PersistBlobPackHeader::decode(&bytes)
        .map(|_| ())
        .map_err(|source| PersistBlobPackError::Format {
            path: path.to_path_buf(),
            source,
        })
}

fn ensure_payload_dirs(layout: &PersistLayout) -> Result<(), PersistError> {
    for path in [
        layout.root().to_path_buf(),
        layout.nodes_dir(),
        layout.values_dir(),
        layout.files_dir(),
    ] {
        fs::create_dir_all(&path).map_err(|source| PersistError::CreateDir { path, source })?;
    }
    Ok(())
}

fn discard_payload_dirs(layout: &PersistLayout) -> Result<(), PersistError> {
    for path in [layout.nodes_dir(), layout.values_dir(), layout.files_dir()] {
        remove_path_if_exists(&path)?;
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), PersistError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(path).map_err(|source| PersistError::DiscardPayload {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => fs::remove_file(path).map_err(|source| PersistError::DiscardPayload {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(PersistError::DiscardPayload {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_schema_version(layout: &PersistLayout) -> Result<Option<u32>, PersistError> {
    let path = layout.schema_path();
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(PersistError::ReadSchema { path, source }),
    };
    let value = text
        .parse::<toml::Value>()
        .map_err(|source| PersistError::ParseSchema {
            path: path.clone(),
            source,
        })?;
    let format = value
        .get("format")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| PersistError::MissingFormat { path: path.clone() })?;
    if format != PERSIST_CACHE_FORMAT {
        return Err(PersistError::InvalidFormat {
            path,
            format: format.to_owned(),
        });
    }
    let version = value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| PersistError::MissingSchemaVersion { path: path.clone() })?;
    let version =
        u32::try_from(version).map_err(|_| PersistError::InvalidSchemaVersion { path, version })?;
    Ok(Some(version))
}

fn write_schema(layout: &PersistLayout) -> Result<(), PersistError> {
    fs::create_dir_all(layout.root()).map_err(|source| PersistError::CreateDir {
        path: layout.root().to_path_buf(),
        source,
    })?;
    let path = layout.schema_path();
    let write_id = SCHEMA_WRITE_ID.fetch_add(1, Ordering::Relaxed);
    let tmp_path = layout
        .root()
        .join(format!("schema.toml.tmp-{}-{write_id}", std::process::id()));
    let text = format!(
        "format = {PERSIST_CACHE_FORMAT:?}\nschema_version = {PERSIST_CACHE_SCHEMA_VERSION}\n"
    );
    fs::write(&tmp_path, text).map_err(|source| PersistError::WriteSchema {
        path: tmp_path.clone(),
        source,
    })?;
    fs::rename(&tmp_path, &path).map_err(|source| {
        let _ = fs::remove_file(&tmp_path);
        PersistError::WriteSchema { path, source }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::cache::MaterializationCosts;

    static TEST_ID: AtomicUsize = AtomicUsize::new(0);

    fn temp_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("aos-nix-persist-cache-{id}-{}", std::process::id()))
    }

    fn sentinel(path: PathBuf) -> PathBuf {
        fs::create_dir_all(path.parent().expect("sentinel parent exists"))
            .expect("sentinel parent creates");
        fs::write(&path, b"keep me").expect("sentinel writes");
        path
    }

    fn test_parse_key(source: &[u8]) -> ParseCacheKey {
        use crate::cache::parse::{PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags};

        ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags::new())
    }

    fn bundle_with_meta(
        bundle: &ParseArtifactBundle,
        meta: crate::cache::parse::ParseCacheMeta,
    ) -> ParseArtifactBundle {
        ParseArtifactBundle::new(
            bundle.resolved_bytes(),
            bundle.ir_bytes(),
            bundle.symbols_bytes(),
            meta.to_toml().into_bytes(),
        )
    }

    fn profitable_materialization_signals(
        likely_redemanded_across_runs: bool,
    ) -> MaterializationSignals {
        MaterializationSignals::new(
            MaterializationCosts::new(100, 10, 20, 30),
            likely_redemanded_across_runs,
        )
    }

    #[test]
    fn blob_packfile_paths_are_store_separated() {
        let layout = PersistLayout::new(temp_root());

        assert_eq!(
            layout.blob_packfile_path(PersistBlobStore::Values),
            layout.value_packfile_path()
        );
        assert_eq!(
            layout.blob_packfile_path(PersistBlobStore::Files),
            layout.file_packfile_path()
        );
        assert_eq!(
            layout.value_packfile_path(),
            layout.values_dir().join("pack.blob")
        );
        assert_eq!(
            layout.file_packfile_path(),
            layout.files_dir().join("pack.blob")
        );
        assert_ne!(layout.value_packfile_path(), layout.file_packfile_path());
    }

    #[test]
    fn blob_index_paths_are_store_separated() {
        let layout = PersistLayout::new(temp_root());

        assert_eq!(
            layout.blob_index_path(PersistBlobStore::Values),
            layout.value_index_path()
        );
        assert_eq!(
            layout.blob_index_path(PersistBlobStore::Files),
            layout.file_index_path()
        );
        assert_eq!(
            layout.value_index_path(),
            layout.values_dir().join("index.blob")
        );
        assert_eq!(
            layout.file_index_path(),
            layout.files_dir().join("index.blob")
        );
        assert_eq!(
            layout.file_artifact_index_path(),
            layout.nodes_dir().join("file-artifacts.index")
        );
        assert_ne!(layout.value_index_path(), layout.file_index_path());
        assert_ne!(layout.file_artifact_index_path(), layout.file_index_path());
    }

    #[test]
    fn blob_index_keys_are_domain_separated_by_store() {
        let hash = DurableBlake3Hash::for_bytes(b"same bytes");
        let value_key = PersistBlobKey::for_value(hash).index_bytes();
        let file_key = PersistBlobKey::for_file(hash).index_bytes();

        assert_ne!(value_key, file_key);
        assert_eq!(value_key[0], 1);
        assert_eq!(file_key[0], 2);
        assert_eq!(&value_key[1..], hash.as_bytes().as_slice());
        assert_eq!(&file_key[1..], hash.as_bytes().as_slice());
    }

    #[test]
    fn blob_index_keys_are_stable_content_addresses() {
        let first = DurableBlake3Hash::for_bytes(b"first payload");
        let first_again = DurableBlake3Hash::for_bytes(b"first payload");
        let second = DurableBlake3Hash::for_bytes(b"second payload");
        let first_key = PersistBlobKey::for_value(first);
        let first_key_again = PersistBlobKey::for_value(first_again);
        let second_key = PersistBlobKey::for_value(second);

        assert_eq!(first_key.store(), PersistBlobStore::Values);
        assert_eq!(first_key.hash(), first);
        assert_eq!(first_key.index_bytes(), first_key_again.index_bytes());
        assert_ne!(first_key.index_bytes(), second_key.index_bytes());
    }

    #[test]
    fn blob_index_keys_decode_and_reject_invalid_prefixes() {
        let key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"payload"));
        let mut encoded = key.index_bytes().to_vec();
        encoded.extend_from_slice(b"trailing index bytes");

        assert_eq!(
            PersistBlobKey::decode_index_bytes(&encoded).expect("blob index key decodes"),
            key
        );

        let error =
            PersistBlobKey::decode_index_bytes(&[0; 8]).expect_err("short index key errors");
        assert_eq!(
            error,
            PersistPackFormatError::ShortBlobIndexKey {
                expected: PERSIST_BLOB_INDEX_KEY_LEN,
                actual: 8,
            }
        );

        let mut invalid_tag = key.index_bytes();
        invalid_tag[0] = 99;
        let error = PersistBlobKey::decode_index_bytes(&invalid_tag).expect_err("bad tag errors");
        assert_eq!(
            error,
            PersistPackFormatError::InvalidBlobIndexStoreTag { tag: 99 }
        );
    }

    #[test]
    fn blob_index_values_round_trip_locations() {
        let location = PersistBlobLocation::new(123, 456);
        let encoded = location.encode_index_value();

        assert_eq!(encoded.len(), PERSIST_BLOB_INDEX_VALUE_LEN);
        assert_eq!(&encoded[..8], 123u64.to_le_bytes().as_slice());
        assert_eq!(&encoded[8..16], 456u64.to_le_bytes().as_slice());
        assert_eq!(
            PersistBlobLocation::decode_index_value(&encoded).expect("index value decodes"),
            location
        );
    }

    #[test]
    fn blob_index_values_decode_from_prefix() {
        let location = PersistBlobLocation::new(123, 456);
        let mut encoded = location.encode_index_value().to_vec();
        encoded.extend_from_slice(b"trailing index bytes");

        assert_eq!(
            PersistBlobLocation::decode_index_value(&encoded)
                .expect("index value decodes from prefix"),
            location
        );
    }

    #[test]
    fn blob_index_values_reject_short_prefix() {
        let error =
            PersistBlobLocation::decode_index_value(&[0; 8]).expect_err("short index value errors");

        assert_eq!(
            error,
            PersistPackFormatError::ShortIndexValue {
                expected: PERSIST_BLOB_INDEX_VALUE_LEN,
                actual: 8,
            }
        );
    }

    #[test]
    fn file_artifact_index_keys_include_path_content_and_parse_identity() {
        use crate::cache::parse::{PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags};

        let source = b"let x = 1; in x";
        let flags = ParseCacheFlags::new();
        let parse_key = ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION, flags);
        let file_key = ParseFileKey::for_source("/src/default.nix", source);

        let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let same = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let other_path = PersistFileArtifactKey::for_realpath_bytes(
            b"/src/other.nix",
            file_key.content_hash(),
            parse_key,
        );
        let changed_source = b"let x = 2; in x";
        let changed_file_key = ParseFileKey::for_source("/src/default.nix", changed_source);
        let changed_parse_key =
            ParseCacheKey::for_source(changed_source, PARSE_CACHE_SCHEMA_VERSION, flags);
        let changed_content =
            PersistFileArtifactKey::from_parse_file_key(&changed_file_key, changed_parse_key);
        let bumped_parse_key =
            ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION + 1, flags);
        let changed_parse_identity =
            PersistFileArtifactKey::from_parse_file_key(&file_key, bumped_parse_key);

        assert_eq!(key, same);
        assert_eq!(key.index_bytes().len(), PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN);
        assert_eq!(key.index_bytes()[0], PERSIST_FILE_ARTIFACT_INDEX_TAG);
        assert_ne!(key, other_path);
        assert_ne!(key, changed_content);
        assert_ne!(key, changed_parse_identity);
    }

    #[test]
    fn file_artifact_index_keys_decode_and_reject_invalid_prefixes() {
        let source = b"let x = 1; in x";
        let parse_key = test_parse_key(source);
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let mut encoded = key.index_bytes().to_vec();
        encoded.extend_from_slice(b"trailing index bytes");

        assert_eq!(
            PersistFileArtifactKey::decode_index_bytes(&encoded)
                .expect("file artifact key decodes"),
            key
        );

        let error = PersistFileArtifactKey::decode_index_bytes(&[0; 8])
            .expect_err("short file artifact key errors");
        assert_eq!(
            error,
            PersistPackFormatError::ShortFileArtifactIndexKey {
                expected: PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN,
                actual: 8,
            }
        );

        let mut invalid_tag = key.index_bytes();
        invalid_tag[0] = 99;
        let error = PersistFileArtifactKey::decode_index_bytes(&invalid_tag)
            .expect_err("bad file artifact tag errors");
        assert_eq!(
            error,
            PersistPackFormatError::InvalidFileArtifactIndexTag { tag: 99 }
        );
    }

    #[test]
    fn file_artifact_index_values_round_trip_file_blob_locations() {
        let blob_hash = DurableBlake3Hash::for_bytes(b"serialized IR artifact");
        let location = PersistBlobLocation::new(123, 456);
        let value = PersistFileArtifactIndexValue::new(blob_hash, location);
        let mut encoded = value.encode_index_value().to_vec();
        encoded.extend_from_slice(b"trailing index bytes");

        assert_eq!(
            value.blob_key(),
            PersistBlobKey::for_file(value.blob_hash())
        );
        assert_eq!(value.location(), location);
        assert_eq!(
            value.encode_index_value().len(),
            PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN
        );
        assert_eq!(
            PersistFileArtifactIndexValue::decode_index_value(&encoded)
                .expect("file artifact value decodes"),
            value
        );
    }

    #[test]
    fn file_artifact_index_values_reject_invalid_prefixes() {
        let error = PersistFileArtifactIndexValue::decode_index_value(&[0; 8])
            .expect_err("short file artifact index value errors");
        assert_eq!(
            error,
            PersistPackFormatError::ShortFileArtifactIndexValue {
                expected: PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN,
                actual: 8,
            }
        );

        let blob_hash = DurableBlake3Hash::for_bytes(b"serialized value");
        let location = PersistBlobLocation::new(123, 456);
        let mut encoded = [0; PERSIST_FILE_ARTIFACT_INDEX_VALUE_LEN];
        encoded[..PERSIST_BLOB_INDEX_KEY_LEN]
            .copy_from_slice(&PersistBlobKey::for_value(blob_hash).index_bytes());
        encoded[PERSIST_BLOB_INDEX_KEY_LEN..].copy_from_slice(&location.encode_index_value());

        let error = PersistFileArtifactIndexValue::decode_index_value(&encoded)
            .expect_err("value blob store errors");
        assert_eq!(
            error,
            PersistPackFormatError::InvalidFileArtifactBlobStore {
                store: PersistBlobStore::Values,
            }
        );
    }

    #[test]
    fn file_artifact_index_entries_round_trip_key_value_records() {
        let source = b"let x = 1; in x";
        let parse_key = test_parse_key(source);
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let value = PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
            PersistBlobLocation::new(123, 456),
        );
        let entry = PersistFileArtifactIndexEntry::new(key, value);
        let mut encoded = entry.encode_index_entry().to_vec();
        encoded.extend_from_slice(b"trailing index bytes");

        assert_eq!(entry.key(), key);
        assert_eq!(entry.value(), value);
        assert_eq!(
            entry.encode_index_entry().len(),
            PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN
        );
        assert_eq!(
            PersistFileArtifactIndexEntry::decode_index_entry(&encoded)
                .expect("file artifact entry decodes"),
            entry
        );
    }

    #[test]
    fn file_artifact_index_entries_reject_invalid_prefixes() {
        let error = PersistFileArtifactIndexEntry::decode_index_entry(&[0; 8])
            .expect_err("short file artifact entry errors");
        assert_eq!(
            error,
            PersistPackFormatError::ShortFileArtifactIndexEntry {
                expected: PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN,
                actual: 8,
            }
        );

        let source = b"let x = 1; in x";
        let parse_key = test_parse_key(source);
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let value = PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
            PersistBlobLocation::new(123, 456),
        );
        let entry = PersistFileArtifactIndexEntry::new(key, value);

        let mut invalid_key = entry.encode_index_entry();
        invalid_key[0] = 99;
        let error = PersistFileArtifactIndexEntry::decode_index_entry(&invalid_key)
            .expect_err("bad entry key tag errors");
        assert_eq!(
            error,
            PersistPackFormatError::InvalidFileArtifactIndexTag { tag: 99 }
        );

        let mut invalid_value = entry.encode_index_entry();
        invalid_value[PERSIST_FILE_ARTIFACT_INDEX_KEY_LEN] = PersistBlobStore::Values.index_tag();
        let error = PersistFileArtifactIndexEntry::decode_index_entry(&invalid_value)
            .expect_err("bad entry value store errors");
        assert_eq!(
            error,
            PersistPackFormatError::InvalidFileArtifactBlobStore {
                store: PersistBlobStore::Values,
            }
        );
    }

    #[test]
    fn file_artifact_index_appends_and_finds_latest_matching_entry() {
        let root = temp_root();
        let index_path = root.join("nodes").join("file-artifacts.index");
        let index = PersistFileArtifactIndex::open(&index_path).expect("index opens");
        let source = b"let x = 1; in x";
        let parse_key = test_parse_key(source);
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let other_key = PersistFileArtifactKey::for_realpath_bytes(
            b"/src/other.nix",
            file_key.content_hash(),
            parse_key,
        );
        let first = PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"first artifact"),
            PersistBlobLocation::new(123, 456),
        );
        let other = PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"other artifact"),
            PersistBlobLocation::new(789, 10),
        );
        let latest = PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"latest artifact"),
            PersistBlobLocation::new(999, 11),
        );

        assert_eq!(index.path(), index_path.as_path());
        assert_eq!(index.lookup(key).expect("empty lookup succeeds"), None);

        index
            .append_entry(PersistFileArtifactIndexEntry::new(key, first))
            .expect("first entry appends");
        index
            .append_entry(PersistFileArtifactIndexEntry::new(other_key, other))
            .expect("other entry appends");
        index
            .append_entry(PersistFileArtifactIndexEntry::new(key, latest))
            .expect("latest entry appends");

        assert_eq!(
            index.lookup(key).expect("key lookup succeeds"),
            Some(latest)
        );
        assert_eq!(
            index.lookup(other_key).expect("other lookup succeeds"),
            Some(other)
        );
        assert_eq!(
            fs::metadata(index.path()).expect("index metadata").len(),
            (PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN * 3) as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_artifact_index_open_rejects_truncated_records() {
        let root = temp_root();
        let index_path = root.join("nodes").join("file-artifacts.index");
        fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
        fs::write(&index_path, b"partial").expect("partial index writes");

        let error =
            PersistFileArtifactIndex::open(&index_path).expect_err("truncated index errors");

        assert!(matches!(
            error,
            PersistFileArtifactIndexError::Format {
                source: PersistPackFormatError::ShortFileArtifactIndexEntry {
                    expected: PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN,
                    actual: 7,
                },
                ..
            }
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_artifact_index_lookup_rejects_malformed_records() {
        let root = temp_root();
        let index_path = root.join("nodes").join("file-artifacts.index");
        let source = b"let x = 1; in x";
        let parse_key = test_parse_key(source);
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let value = PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
            PersistBlobLocation::new(123, 456),
        );
        let mut encoded = PersistFileArtifactIndexEntry::new(key, value).encode_index_entry();
        encoded[0] = 99;
        fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
        fs::write(&index_path, encoded).expect("malformed index writes");
        let index = PersistFileArtifactIndex::open(&index_path).expect("index opens by length");

        let error = index.lookup(key).expect_err("malformed record errors");

        assert!(matches!(
            error,
            PersistFileArtifactIndexError::Format {
                source: PersistPackFormatError::InvalidFileArtifactIndexTag { tag: 99 },
                ..
            }
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn materialization_reuse_metadata_round_trips_counters() {
        let reuse = MaterializationReuse::new(2, 3);
        let encoded = reuse.encode_persist_metadata();
        let mut prefixed = encoded.to_vec();
        prefixed.extend_from_slice(b"trailing metadata bytes");

        assert_eq!(encoded.len(), PERSIST_MATERIALIZATION_REUSE_LEN);
        assert_eq!(&encoded[..8], 2u64.to_le_bytes().as_slice());
        assert_eq!(&encoded[8..16], 3u64.to_le_bytes().as_slice());
        assert_eq!(
            MaterializationReuse::decode_persist_metadata(&prefixed)
                .expect("reuse metadata decodes"),
            reuse
        );
    }

    #[test]
    fn materialization_reuse_metadata_rejects_short_prefix() {
        let error = MaterializationReuse::decode_persist_metadata(&[0; 8])
            .expect_err("short reuse metadata errors");

        assert_eq!(
            error,
            PersistPackFormatError::ShortMaterializationReuseMetadata {
                expected: PERSIST_MATERIALIZATION_REUSE_LEN,
                actual: 8,
            }
        );
    }

    #[test]
    fn blob_index_entries_round_trip_key_value_records() {
        let key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"payload"));
        let location = PersistBlobLocation::new(123, 456);
        let entry = PersistBlobIndexEntry::new(key, location);
        let entry_bytes = entry.encode_index_entry();
        let mut encoded = entry_bytes.to_vec();
        encoded.extend_from_slice(b"trailing index bytes");

        assert_eq!(entry.key(), key);
        assert_eq!(entry.location(), location);
        assert_eq!(entry_bytes.len(), PERSIST_BLOB_INDEX_ENTRY_LEN);
        assert_eq!(
            &entry_bytes[..PERSIST_BLOB_INDEX_KEY_LEN],
            key.index_bytes().as_slice()
        );
        assert_eq!(
            &entry_bytes[PERSIST_BLOB_INDEX_KEY_LEN..],
            location.encode_index_value().as_slice()
        );
        assert_eq!(
            PersistBlobIndexEntry::decode_index_entry(&encoded).expect("blob index entry decodes"),
            entry
        );
    }

    #[test]
    fn blob_index_entries_reject_invalid_prefixes() {
        let error =
            PersistBlobIndexEntry::decode_index_entry(&[0; 8]).expect_err("short entry errors");
        assert_eq!(
            error,
            PersistPackFormatError::ShortBlobIndexEntry {
                expected: PERSIST_BLOB_INDEX_ENTRY_LEN,
                actual: 8,
            }
        );

        let key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"payload"));
        let location = PersistBlobLocation::new(123, 456);
        let entry = PersistBlobIndexEntry::new(key, location);
        let mut invalid_key = entry.encode_index_entry();
        invalid_key[0] = 99;
        let error = PersistBlobIndexEntry::decode_index_entry(&invalid_key)
            .expect_err("bad embedded blob key errors");
        assert_eq!(
            error,
            PersistPackFormatError::InvalidBlobIndexStoreTag { tag: 99 }
        );
    }

    #[test]
    fn blob_index_appends_and_finds_latest_matching_entry() {
        let root = temp_root();
        let index_path = root.join("values").join("index.blob");
        let index = PersistBlobIndex::open(&index_path).expect("index opens");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"payload"));
        let other_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"other payload"));
        let first = PersistBlobLocation::new(123, 456);
        let other = PersistBlobLocation::new(789, 10);
        let latest = PersistBlobLocation::new(999, 11);

        assert_eq!(index.path(), index_path.as_path());
        assert_eq!(index.lookup(key).expect("empty lookup succeeds"), None);

        index
            .append_entry(PersistBlobIndexEntry::new(key, first))
            .expect("first entry appends");
        index
            .append_entry(PersistBlobIndexEntry::new(other_key, other))
            .expect("other entry appends");
        index
            .append_entry(PersistBlobIndexEntry::new(key, latest))
            .expect("latest entry appends");

        assert_eq!(
            index.lookup(key).expect("key lookup succeeds"),
            Some(latest)
        );
        assert_eq!(
            index.lookup(other_key).expect("other lookup succeeds"),
            Some(other)
        );
        assert_eq!(
            fs::metadata(index.path()).expect("index metadata").len(),
            (PERSIST_BLOB_INDEX_ENTRY_LEN * 3) as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn blob_index_open_rejects_truncated_records() {
        let root = temp_root();
        let index_path = root.join("values").join("index.blob");
        fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
        fs::write(&index_path, b"partial").expect("partial index writes");

        let error = PersistBlobIndex::open(&index_path).expect_err("truncated index errors");

        assert!(matches!(
            error,
            PersistBlobIndexError::Format {
                source: PersistPackFormatError::ShortBlobIndexEntry {
                    expected: PERSIST_BLOB_INDEX_ENTRY_LEN,
                    actual: 7,
                },
                ..
            }
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn blob_index_lookup_rejects_malformed_records() {
        let root = temp_root();
        let index_path = root.join("values").join("index.blob");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"payload"));
        let location = PersistBlobLocation::new(123, 456);
        let mut encoded = PersistBlobIndexEntry::new(key, location).encode_index_entry();
        encoded[0] = 99;
        fs::create_dir_all(index_path.parent().expect("index parent")).expect("parent creates");
        fs::write(&index_path, encoded).expect("malformed index writes");
        let index = PersistBlobIndex::open(&index_path).expect("index opens by length");

        let error = index.lookup(key).expect_err("malformed record errors");

        assert!(matches!(
            error,
            PersistBlobIndexError::Format {
                source: PersistPackFormatError::InvalidBlobIndexStoreTag { tag: 99 },
                ..
            }
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn packfile_header_round_trips() {
        let header = PersistBlobPackHeader::current();
        let encoded = header.encode();

        assert_eq!(encoded.len(), PERSIST_BLOB_PACK_HEADER_LEN);
        assert_eq!(&encoded[..16], PERSIST_BLOB_PACK_MAGIC.as_slice());
        assert_eq!(
            &encoded[16..20],
            PERSIST_BLOB_PACK_VERSION.to_le_bytes().as_slice()
        );
        assert_eq!(
            &encoded[20..24],
            (PERSIST_BLOB_PACK_HEADER_LEN as u32)
                .to_le_bytes()
                .as_slice()
        );
        assert_eq!(
            PersistBlobPackHeader::decode(&encoded).expect("pack header decodes"),
            header
        );
        assert_eq!(header.version(), PERSIST_BLOB_PACK_VERSION);
    }

    #[test]
    fn packfile_header_decodes_from_prefix() {
        let header = PersistBlobPackHeader::current();
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(b"trailing pack bytes");

        assert_eq!(
            PersistBlobPackHeader::decode(&bytes).expect("pack header decodes from prefix"),
            header
        );
    }

    #[test]
    fn packfile_header_rejects_invalid_prefixes() {
        let encoded = PersistBlobPackHeader::current().encode();

        let error = PersistBlobPackHeader::decode(&encoded[..8]).expect_err("short header errors");
        assert_eq!(
            error,
            PersistPackFormatError::ShortPackHeader {
                expected: PERSIST_BLOB_PACK_HEADER_LEN,
                actual: 8,
            }
        );

        let mut invalid_magic = encoded;
        invalid_magic[0] = b'X';
        let error = PersistBlobPackHeader::decode(&invalid_magic).expect_err("bad magic errors");
        assert!(matches!(
            error,
            PersistPackFormatError::InvalidPackMagic { .. }
        ));

        let mut invalid_version = encoded;
        invalid_version[16..20].copy_from_slice(&2u32.to_le_bytes());
        let error =
            PersistBlobPackHeader::decode(&invalid_version).expect_err("bad version errors");
        assert_eq!(
            error,
            PersistPackFormatError::UnsupportedPackVersion { version: 2 }
        );

        let mut invalid_len = encoded;
        invalid_len[20..24].copy_from_slice(&12u32.to_le_bytes());
        let error =
            PersistBlobPackHeader::decode(&invalid_len).expect_err("bad header length errors");
        assert_eq!(
            error,
            PersistPackFormatError::InvalidPackHeaderLength { header_len: 12 }
        );
    }

    #[test]
    fn blob_record_header_round_trips() {
        let hash = DurableBlake3Hash::for_bytes(b"record payload");
        let header = PersistBlobRecordHeader::new(hash, 987);
        let encoded = header.encode();

        assert_eq!(encoded.len(), PERSIST_BLOB_RECORD_HEADER_LEN);
        assert_eq!(&encoded[..32], hash.as_bytes().as_slice());
        assert_eq!(&encoded[32..40], 987u64.to_le_bytes().as_slice());
        assert_eq!(
            PersistBlobRecordHeader::decode(&encoded).expect("record header decodes"),
            header
        );
        assert_eq!(header.hash(), hash);
        assert_eq!(header.payload_len(), 987);
        assert_eq!(
            header.key(PersistBlobStore::Values),
            PersistBlobKey::for_value(hash)
        );
    }

    #[test]
    fn blob_record_header_decodes_from_prefix() {
        let hash = DurableBlake3Hash::for_bytes(b"record payload");
        let header = PersistBlobRecordHeader::new(hash, 987);
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(b"serialized payload bytes");

        assert_eq!(
            PersistBlobRecordHeader::decode(&bytes).expect("record header decodes from prefix"),
            header
        );
    }

    #[test]
    fn blob_record_header_rejects_short_prefix() {
        let error = PersistBlobRecordHeader::decode(&[0; 8]).expect_err("short record errors");

        assert_eq!(
            error,
            PersistPackFormatError::ShortRecordHeader {
                expected: PERSIST_BLOB_RECORD_HEADER_LEN,
                actual: 8,
            }
        );
    }

    #[test]
    fn blob_pack_open_initializes_header() {
        let path = temp_root().join("values").join("pack.blob");
        let pack = PersistBlobPack::open(&path).expect("pack opens");

        assert_eq!(pack.path(), path.as_path());
        assert_eq!(
            fs::read(&path).expect("pack header reads").as_slice(),
            PersistBlobPackHeader::current().encode().as_slice()
        );
        PersistBlobPack::open(&path).expect("initialized pack reopens");

        let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
    }

    #[test]
    fn blob_pack_open_rejects_corrupt_header_without_rewriting() {
        let path = temp_root().join("values").join("pack.blob");
        fs::create_dir_all(path.parent().expect("pack parent exists")).expect("parent creates");
        fs::write(&path, b"bad").expect("corrupt pack writes");

        let error = PersistBlobPack::open(&path).expect_err("corrupt pack errors");

        assert!(matches!(
            error,
            PersistBlobPackError::Format {
                source: PersistPackFormatError::ShortPackHeader { actual: 3, .. },
                ..
            }
        ));
        assert_eq!(
            fs::read(&path).expect("corrupt pack reads").as_slice(),
            b"bad"
        );

        let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
    }

    #[test]
    fn blob_pack_appends_and_reads_verified_payloads() {
        let path = temp_root().join("values").join("pack.blob");
        let pack = PersistBlobPack::open(&path).expect("pack opens");
        let first_payload = b"first payload";
        let first_hash = DurableBlake3Hash::for_bytes(first_payload);
        let second_payload = b"second payload";
        let second_hash = DurableBlake3Hash::for_bytes(second_payload);

        let first = pack
            .append_blob(first_hash, first_payload)
            .expect("first blob appends");
        let second = pack
            .append_blob(second_hash, second_payload)
            .expect("second blob appends");

        assert_eq!(first.record_offset(), PERSIST_BLOB_PACK_HEADER_LEN as u64);
        assert_eq!(first.payload_len(), first_payload.len() as u64);
        assert_eq!(
            second.record_offset(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
                + PERSIST_BLOB_RECORD_HEADER_LEN as u64
                + first_payload.len() as u64
        );
        assert_eq!(
            pack.read_blob(first, first_hash)
                .expect("first blob reads")
                .as_slice(),
            first_payload
        );
        assert_eq!(
            pack.read_blob(second, second_hash)
                .expect("second blob reads")
                .as_slice(),
            second_payload
        );

        let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
    }

    #[test]
    fn blob_pack_rejects_append_payload_hash_mismatch() {
        let path = temp_root().join("values").join("pack.blob");
        let pack = PersistBlobPack::open(&path).expect("pack opens");
        let payload = b"payload";
        let wrong_hash = DurableBlake3Hash::for_bytes(b"other payload");

        let error = pack
            .append_blob(wrong_hash, payload)
            .expect_err("hash mismatch errors");

        assert!(matches!(
            error,
            PersistBlobPackError::PayloadHashMismatch { .. }
        ));
        assert_eq!(
            fs::metadata(&path).expect("pack metadata reads").len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
    }

    #[test]
    fn blob_pack_read_rejects_mismatched_lookup_metadata() {
        let path = temp_root().join("values").join("pack.blob");
        let pack = PersistBlobPack::open(&path).expect("pack opens");
        let payload = b"payload";
        let hash = DurableBlake3Hash::for_bytes(payload);
        let location = pack.append_blob(hash, payload).expect("blob appends");

        let error = pack
            .read_blob(location, DurableBlake3Hash::for_bytes(b"other payload"))
            .expect_err("wrong hash errors");
        assert!(matches!(
            error,
            PersistBlobPackError::RecordHashMismatch { .. }
        ));

        let error = pack
            .read_blob(
                PersistBlobLocation::new(location.record_offset(), location.payload_len() + 1),
                hash,
            )
            .expect_err("wrong length errors");
        assert!(matches!(
            error,
            PersistBlobPackError::RecordLengthMismatch { .. }
        ));

        let error = pack
            .read_blob(PersistBlobLocation::new(0, location.payload_len()), hash)
            .expect_err("header offset errors");
        assert!(matches!(
            error,
            PersistBlobPackError::InvalidRecordOffset { record_offset: 0 }
        ));

        let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
    }

    #[test]
    fn blob_pack_read_rejects_truncated_payload_before_allocation() {
        let path = temp_root().join("values").join("pack.blob");
        let pack = PersistBlobPack::open(&path).expect("pack opens");
        let payload = b"payload";
        let hash = DurableBlake3Hash::for_bytes(payload);
        let location = pack.append_blob(hash, payload).expect("blob appends");
        let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
        OpenOptions::new()
            .write(true)
            .open(pack.path())
            .expect("pack opens for truncation")
            .set_len(payload_offset + 1)
            .expect("pack truncates");

        let error = pack
            .read_blob(location, hash)
            .expect_err("truncated payload errors");

        assert!(matches!(
            error,
            PersistBlobPackError::RecordExtendsPastEnd { .. }
        ));

        let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
    }

    #[test]
    fn blob_pack_read_rejects_corrupt_payload() {
        let path = temp_root().join("values").join("pack.blob");
        let pack = PersistBlobPack::open(&path).expect("pack opens");
        let payload = b"payload";
        let hash = DurableBlake3Hash::for_bytes(payload);
        let location = pack.append_blob(hash, payload).expect("blob appends");
        let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
        let mut file = OpenOptions::new()
            .write(true)
            .open(pack.path())
            .expect("pack opens for mutation");
        file.seek(SeekFrom::Start(payload_offset))
            .expect("payload offset seeks");
        file.write_all(b"X").expect("payload corrupts");
        file.flush().expect("payload corruption flushes");

        let error = pack
            .read_blob(location, hash)
            .expect_err("corrupt payload errors");

        assert!(matches!(
            error,
            PersistBlobPackError::PayloadHashMismatch { .. }
        ));

        let _ = fs::remove_dir_all(path.parent().expect("pack parent exists"));
    }

    #[test]
    fn open_creates_versioned_layout() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout();

        assert_eq!(layout.root(), root.as_path());
        assert!(layout.nodes_dir().is_dir());
        assert!(layout.values_dir().is_dir());
        assert!(layout.files_dir().is_dir());
        assert_eq!(cache.value_pack().path(), layout.value_packfile_path());
        assert_eq!(cache.file_pack().path(), layout.file_packfile_path());
        assert_eq!(cache.value_index().path(), layout.value_index_path());
        assert_eq!(cache.file_index().path(), layout.file_index_path());
        assert_eq!(
            cache.file_artifact_index().path(),
            layout.file_artifact_index_path()
        );
        assert_eq!(
            cache.blob_pack(PersistBlobStore::Values).path(),
            layout.value_packfile_path()
        );
        assert_eq!(
            cache.blob_pack(PersistBlobStore::Files).path(),
            layout.file_packfile_path()
        );
        assert_eq!(
            cache.blob_index(PersistBlobStore::Values).path(),
            layout.value_index_path()
        );
        assert_eq!(
            cache.blob_index(PersistBlobStore::Files).path(),
            layout.file_index_path()
        );
        assert_eq!(
            fs::read(layout.value_packfile_path())
                .expect("value pack header reads")
                .as_slice(),
            PersistBlobPackHeader::current().encode().as_slice()
        );
        assert_eq!(
            fs::read(layout.file_packfile_path())
                .expect("file pack header reads")
                .as_slice(),
            PersistBlobPackHeader::current().encode().as_slice()
        );
        assert_eq!(
            fs::metadata(layout.value_index_path())
                .expect("value index metadata")
                .len(),
            0
        );
        assert_eq!(
            fs::metadata(layout.file_index_path())
                .expect("file index metadata")
                .len(),
            0
        );
        assert_eq!(
            fs::metadata(layout.file_artifact_index_path())
                .expect("file artifact index metadata")
                .len(),
            0
        );
        assert_eq!(
            fs::read_to_string(layout.schema_path()).expect("schema reads"),
            "format = \"aos-nix-eval-cache\"\nschema_version = 1\n"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_blob_pack_errors_without_rewriting() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout().clone();
        fs::write(layout.value_packfile_path(), b"bad").expect("value pack corrupts");

        let error = PersistCache::open(&root).expect_err("corrupt value pack errors");

        assert!(matches!(
            error,
            PersistError::OpenBlobPack {
                source: PersistBlobPackError::Format {
                    source: PersistPackFormatError::ShortPackHeader { actual: 3, .. },
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            fs::read(layout.value_packfile_path())
                .expect("corrupt pack reads")
                .as_slice(),
            b"bad"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_blob_index_errors_without_rewriting() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout().clone();
        fs::write(layout.value_index_path(), b"partial").expect("value index corrupts");

        let error = PersistCache::open(&root).expect_err("corrupt value index errors");

        assert!(matches!(
            error,
            PersistError::OpenBlobIndex {
                source: PersistBlobIndexError::Format {
                    source: PersistPackFormatError::ShortBlobIndexEntry { actual: 7, .. },
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            fs::read(layout.value_index_path())
                .expect("corrupt index reads")
                .as_slice(),
            b"partial"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_file_artifact_index_errors_without_rewriting() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout().clone();
        fs::write(layout.file_artifact_index_path(), b"partial")
            .expect("file artifact index corrupts");

        let error = PersistCache::open(&root).expect_err("corrupt file artifact index errors");

        assert!(matches!(
            error,
            PersistError::OpenFileArtifactIndex {
                source: PersistFileArtifactIndexError::Format {
                    source: PersistPackFormatError::ShortFileArtifactIndexEntry { actual: 7, .. },
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            fs::read(layout.file_artifact_index_path())
                .expect("corrupt index reads")
                .as_slice(),
            b"partial"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_blob_io_is_routed_by_key_store() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let payload = b"shared payload";
        let hash = DurableBlake3Hash::for_bytes(payload);
        let value_key = PersistBlobKey::for_value(hash);
        let file_key = PersistBlobKey::for_file(hash);

        let value_location = cache
            .append_blob(value_key, payload)
            .expect("value blob appends");
        let file_location = cache
            .append_blob(file_key, payload)
            .expect("file blob appends");

        assert_eq!(
            value_location.record_offset(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );
        assert_eq!(
            file_location.record_offset(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );
        assert_eq!(
            cache
                .read_blob(value_key, value_location)
                .expect("value blob reads")
                .as_slice(),
            payload
        );
        assert_eq!(
            cache
                .read_blob(file_key, file_location)
                .expect("file blob reads")
                .as_slice(),
            payload
        );
        assert_eq!(
            fs::metadata(cache.value_pack().path())
                .expect("value pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
                + PERSIST_BLOB_RECORD_HEADER_LEN as u64
                + payload.len() as u64
        );
        assert_eq!(
            fs::metadata(cache.file_pack().path())
                .expect("file pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
                + PERSIST_BLOB_RECORD_HEADER_LEN as u64
                + payload.len() as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_blob_indexed_io_updates_index_and_reads_by_key() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let payload = b"indexed payload";
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
        let same_hash_file_key = PersistBlobKey::for_file(key.hash());

        let entry = cache
            .append_blob_indexed(key, payload)
            .expect("indexed blob appends");

        assert_eq!(entry.key(), key);
        assert_eq!(
            entry.location().record_offset(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );
        assert_eq!(
            cache
                .lookup_blob_location(key)
                .expect("indexed lookup succeeds"),
            Some(entry.location())
        );
        assert_eq!(
            cache
                .read_blob_indexed(key)
                .expect("indexed read succeeds")
                .expect("indexed blob exists")
                .as_slice(),
            payload
        );
        assert_eq!(
            cache
                .read_blob_indexed(same_hash_file_key)
                .expect("other store lookup succeeds"),
            None
        );
        assert_eq!(
            fs::metadata(cache.value_index().path())
                .expect("value index metadata")
                .len(),
            PERSIST_BLOB_INDEX_ENTRY_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_blob_indexed_read_returns_none_on_miss() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"missing"));

        assert_eq!(
            cache
                .lookup_blob_location(key)
                .expect("lookup miss succeeds"),
            None
        );
        assert_eq!(
            cache.read_blob_indexed(key).expect("read miss succeeds"),
            None
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_blob_indexed_append_rejects_hash_mismatch_before_index_write() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

        let error = cache
            .append_blob_indexed(key, b"payload")
            .expect_err("hash mismatch errors");

        assert!(matches!(
            error,
            PersistBlobIndexedWriteError::Append {
                source: PersistBlobPackError::PayloadHashMismatch { .. },
            }
        ));
        assert_eq!(
            fs::metadata(cache.value_pack().path())
                .expect("value pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );
        assert_eq!(
            fs::metadata(cache.value_index().path())
                .expect("value index metadata")
                .len(),
            0
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_blob_io_rejects_payload_hash_mismatch() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

        let error = cache
            .append_blob(key, b"payload")
            .expect_err("hash mismatch errors");

        assert!(matches!(
            error,
            PersistBlobPackError::PayloadHashMismatch { .. }
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_index_records_and_looks_up_entries() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let parse_key = test_parse_key(source);
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let other_key = PersistFileArtifactKey::for_realpath_bytes(
            b"/src/other.nix",
            file_key.content_hash(),
            parse_key,
        );
        let value = PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
        );

        cache
            .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
            .expect("file artifact index entry records");

        assert_eq!(
            cache
                .lookup_file_artifact(key)
                .expect("file artifact lookup succeeds"),
            Some(value)
        );
        assert_eq!(
            cache
                .lookup_file_artifact(other_key)
                .expect("file artifact miss succeeds"),
            None
        );
        assert_eq!(
            fs::metadata(cache.file_artifact_index().path())
                .expect("file artifact index metadata")
                .len(),
            PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_materialization_decision_can_skip_without_writing() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

        let result = cache
            .materialize_blob(key, b"payload", MaterializationDecision::KeepInMemory)
            .expect("skip succeeds");

        assert_eq!(result, PersistMaterialization::Skipped);
        assert_eq!(result.index_entry(key), None);
        assert_eq!(
            fs::metadata(cache.value_pack().path())
                .expect("value pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_materialization_decision_appends_when_requested() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let payload = b"payload";
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

        let result = cache
            .materialize_blob(key, payload, MaterializationDecision::Materialize)
            .expect("materialization succeeds");

        let PersistMaterialization::Materialized(location) = result else {
            panic!("materialization should append");
        };
        assert_eq!(
            location.record_offset(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );
        assert_eq!(
            result.index_entry(key),
            Some(PersistBlobIndexEntry::new(key, location))
        );
        assert_eq!(
            cache
                .read_blob(key, location)
                .expect("materialized blob reads")
                .as_slice(),
            payload
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_indexed_materialization_decision_can_skip_without_writing() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

        let result = cache
            .materialize_blob_indexed(key, b"payload", MaterializationDecision::KeepInMemory)
            .expect("skip succeeds");

        assert_eq!(result, PersistMaterialization::Skipped);
        assert_eq!(result.index_entry(key), None);
        assert_eq!(
            fs::metadata(cache.value_pack().path())
                .expect("value pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );
        assert_eq!(
            fs::metadata(cache.value_index().path())
                .expect("value index metadata")
                .len(),
            0
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_indexed_materialization_decision_appends_and_indexes_when_requested() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let payload = b"payload";
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

        let result = cache
            .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
            .expect("indexed materialization succeeds");

        let PersistMaterialization::Materialized(location) = result else {
            panic!("materialization should append");
        };
        assert_eq!(
            result.index_entry(key),
            Some(PersistBlobIndexEntry::new(key, location))
        );
        assert_eq!(
            cache
                .lookup_blob_location(key)
                .expect("indexed lookup succeeds"),
            Some(location)
        );
        assert_eq!(
            cache
                .read_blob_indexed(key)
                .expect("indexed read succeeds")
                .expect("indexed blob exists")
                .as_slice(),
            payload
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_materialization_decision_propagates_append_errors() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

        let error = cache
            .materialize_blob(key, b"payload", MaterializationDecision::Materialize)
            .expect_err("materialization hash mismatch errors");

        assert!(matches!(
            error,
            PersistBlobPackError::PayloadHashMismatch { .. }
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_indexed_materialization_signals_append_when_threshold_passes() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let payload = b"payload";
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

        let result = cache
            .materialize_blob_indexed_with_signals(
                key,
                payload,
                profitable_materialization_signals(true),
            )
            .expect("indexed materialization succeeds");

        let PersistMaterialization::Materialized(location) = result else {
            panic!("materialization should append");
        };
        assert_eq!(
            cache
                .lookup_blob_location(key)
                .expect("indexed lookup succeeds"),
            Some(location)
        );
        assert_eq!(
            cache
                .read_blob_indexed(key)
                .expect("indexed read succeeds")
                .expect("indexed blob exists")
                .as_slice(),
            payload
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_materialization_signals_can_skip_without_hashing() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

        let result = cache
            .materialize_blob_with_signals(
                key,
                b"payload",
                profitable_materialization_signals(false),
            )
            .expect("skip succeeds");

        assert_eq!(result, PersistMaterialization::Skipped);
        assert_eq!(result.index_entry(key), None);
        assert_eq!(
            fs::metadata(cache.value_pack().path())
                .expect("value pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_materialization_signals_append_when_threshold_passes() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let payload = b"payload";
        let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

        let result = cache
            .materialize_blob_with_signals(key, payload, profitable_materialization_signals(true))
            .expect("materialization succeeds");

        let PersistMaterialization::Materialized(location) = result else {
            panic!("materialization should append");
        };
        assert_eq!(
            result.index_entry(key),
            Some(PersistBlobIndexEntry::new(key, location))
        );
        assert_eq!(
            cache
                .read_blob(key, location)
                .expect("materialized blob reads")
                .as_slice(),
            payload
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_materialization_can_skip_without_writing() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let parse_key = test_parse_key(source);
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

        let result = cache
            .materialize_file_artifact(
                &file_key,
                parse_key,
                b"serialized IR artifact",
                MaterializationDecision::KeepInMemory,
            )
            .expect("file artifact skip succeeds");

        assert_eq!(
            result,
            PersistFileArtifactMaterialization::Skipped { artifact_key }
        );
        assert_eq!(result.artifact_key(), artifact_key);
        assert_eq!(result.index_value(), None);
        assert_eq!(result.index_entry(), None);
        assert_eq!(
            fs::metadata(cache.file_pack().path())
                .expect("file pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_materialization_appends_files_blob_when_requested() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let parse_key = test_parse_key(source);
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let payload = b"serialized IR artifact";

        let result = cache
            .materialize_file_artifact(
                &file_key,
                parse_key,
                payload,
                MaterializationDecision::Materialize,
            )
            .expect("file artifact materializes");

        let PersistFileArtifactMaterialization::Materialized {
            artifact_key: actual_key,
            index_value,
        } = result
        else {
            panic!("file artifact should materialize");
        };
        assert_eq!(actual_key, artifact_key);
        assert_eq!(result.artifact_key(), artifact_key);
        assert_eq!(result.index_value(), Some(index_value));
        assert_eq!(
            result.index_entry(),
            Some(PersistFileArtifactIndexEntry::new(
                artifact_key,
                index_value
            ))
        );
        assert_eq!(
            index_value.blob_hash(),
            DurableBlake3Hash::for_bytes(payload)
        );
        assert_eq!(
            index_value.location().record_offset(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );
        assert_eq!(
            cache
                .read_file_artifact(index_value)
                .expect("file artifact blob reads")
                .as_slice(),
            payload
        );
        assert_eq!(
            fs::metadata(cache.value_pack().path())
                .expect("value pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );
        assert_eq!(
            fs::metadata(cache.file_pack().path())
                .expect("file pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
                + PERSIST_BLOB_RECORD_HEADER_LEN as u64
                + payload.len() as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_materialization_signals_can_skip_without_writing() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let parse_key = test_parse_key(source);
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

        let result = cache
            .materialize_file_artifact_with_signals(
                &file_key,
                parse_key,
                b"serialized IR artifact",
                profitable_materialization_signals(false),
            )
            .expect("file artifact skip succeeds");

        assert_eq!(
            result,
            PersistFileArtifactMaterialization::Skipped { artifact_key }
        );
        assert_eq!(
            fs::metadata(cache.file_pack().path())
                .expect("file pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_materialization_signals_append_when_threshold_passes() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let parse_key = test_parse_key(source);
        let payload = b"serialized IR artifact";

        let result = cache
            .materialize_file_artifact_with_signals(
                &file_key,
                parse_key,
                payload,
                profitable_materialization_signals(true),
            )
            .expect("file artifact materializes");

        let Some(index_value) = result.index_value() else {
            panic!("file artifact should materialize");
        };
        assert_eq!(
            cache
                .read_file_artifact(index_value)
                .expect("file artifact blob reads")
                .as_slice(),
            payload
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_hydrates_parse_entry_from_materialized_bundle() {
        use crate::cache::parse::ParseCache;

        let root = temp_root();
        let persist = PersistCache::open(root.join("persist")).expect("cache opens");
        let parse_cache = ParseCache::new(root.join("parse"));
        let source = b"let x = 1; in x";
        let parsed = parse_cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source parses");
        let bundle = parsed
            .entry
            .read_artifact_bundle()
            .expect("artifact bundle reads");
        let payload = bundle.encode().expect("bundle encodes");
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let materialized = persist
            .materialize_file_artifact(
                &file_key,
                parsed.key,
                &payload,
                MaterializationDecision::Materialize,
            )
            .expect("bundle materializes");
        let Some(index_value) = materialized.index_value() else {
            panic!("bundle should materialize");
        };
        let hydrated = ParseCacheEntry::new(root.join("hydrated-entry"));

        persist
            .hydrate_file_artifact_bundle(index_value, &hydrated)
            .expect("bundle hydrates");

        assert!(hydrated.is_complete());
        assert_eq!(
            hydrated
                .read_artifact_bundle()
                .expect("hydrated bundle reads"),
            bundle
        );
        let resolved = hydrated
            .read_resolved()
            .expect("hydrated resolved artifact reads");
        assert_eq!(resolved.arena.nodes(), parsed.resolved.arena.nodes());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_hydration_validates_bundle_before_write() {
        use crate::cache::parse::{ParseCache, ParseCacheMeta};

        let root = temp_root();
        let persist = PersistCache::open(root.join("persist")).expect("cache opens");
        let parse_cache = ParseCache::new(root.join("parse"));
        let source = b"let x = 1; in x";
        let parsed = parse_cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source parses");
        let bundle = parsed
            .entry
            .read_artifact_bundle()
            .expect("artifact bundle reads");
        let meta = bundle.decode_meta().expect("bundle metadata decodes");
        let wrong_meta = ParseCacheMeta::new(
            meta.schema_version,
            meta.source_hint,
            meta.node_count + 1,
            meta.symbol_count,
        );
        let wrong_bundle = bundle_with_meta(&bundle, wrong_meta);
        let payload = wrong_bundle.encode().expect("bundle encodes");
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let materialized = persist
            .materialize_file_artifact(
                &file_key,
                parsed.key,
                &payload,
                MaterializationDecision::Materialize,
            )
            .expect("bundle materializes");
        let Some(index_value) = materialized.index_value() else {
            panic!("bundle should materialize");
        };
        let hydrated = ParseCacheEntry::new(root.join("hydrated-entry"));

        let error = persist
            .hydrate_file_artifact_bundle(index_value, &hydrated)
            .expect_err("invalid bundle metadata fails hydration");

        assert!(matches!(
            error,
            PersistFileArtifactHydrationError::Validate {
                source: ParseCacheError::DecodeMeta { message },
            } if message.contains("node_count")
        ));
        assert!(!hydrated.dir().exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_hydration_rejects_key_mismatch_before_read() {
        let root = temp_root();
        let persist = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let parse_key = test_parse_key(source);
        let expected = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let actual = PersistFileArtifactKey::for_realpath_bytes(
            b"/src/other.nix",
            file_key.content_hash(),
            parse_key,
        );
        let index_value = PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"missing artifact"),
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        );
        let target = ParseCacheEntry::new(root.join("target-entry"));

        let error = persist
            .hydrate_file_artifact_bundle_for_key(
                &file_key,
                parse_key,
                actual,
                index_value,
                &target,
            )
            .expect_err("key mismatch errors before read");

        assert!(matches!(
            error,
            PersistFileArtifactHydrationError::KeyMismatch {
                expected: observed_expected,
                actual: observed_actual,
            } if observed_expected == expected && observed_actual == actual
        ));
        assert_eq!(
            fs::metadata(persist.file_pack().path())
                .expect("file pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_hydrates_parse_entry_after_key_match() {
        use crate::cache::parse::ParseCache;

        let root = temp_root();
        let persist = PersistCache::open(root.join("persist")).expect("cache opens");
        let parse_cache = ParseCache::new(root.join("parse"));
        let source = b"let x = 1; in x";
        let parsed = parse_cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source parses");
        let bundle = parsed
            .entry
            .read_artifact_bundle()
            .expect("artifact bundle reads");
        let payload = bundle.encode().expect("bundle encodes");
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let materialized = persist
            .materialize_file_artifact(
                &file_key,
                parsed.key,
                &payload,
                MaterializationDecision::Materialize,
            )
            .expect("bundle materializes");
        let Some(index_value) = materialized.index_value() else {
            panic!("bundle should materialize");
        };
        let hydrated = ParseCacheEntry::new(root.join("hydrated-keyed-entry"));

        persist
            .hydrate_file_artifact_bundle_for_key(
                &file_key,
                parsed.key,
                materialized.artifact_key(),
                index_value,
                &hydrated,
            )
            .expect("keyed bundle hydrates");

        assert!(hydrated.is_complete());
        assert_eq!(
            hydrated
                .read_artifact_bundle()
                .expect("hydrated bundle reads"),
            bundle
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_hydration_from_entry_rejects_key_mismatch() {
        let root = temp_root();
        let persist = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let parse_key = test_parse_key(source);
        let expected = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        let actual = PersistFileArtifactKey::for_realpath_bytes(
            b"/src/other.nix",
            file_key.content_hash(),
            parse_key,
        );
        let index_entry = PersistFileArtifactIndexEntry::new(
            actual,
            PersistFileArtifactIndexValue::new(
                DurableBlake3Hash::for_bytes(b"missing artifact"),
                PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
            ),
        );
        let target = ParseCacheEntry::new(root.join("target-entry"));

        let error = persist
            .hydrate_file_artifact_bundle_from_entry(&file_key, parse_key, index_entry, &target)
            .expect_err("entry key mismatch errors before read");

        assert!(matches!(
            error,
            PersistFileArtifactHydrationError::KeyMismatch {
                expected: observed_expected,
                actual: observed_actual,
            } if observed_expected == expected && observed_actual == actual
        ));
        assert_eq!(
            fs::metadata(persist.file_pack().path())
                .expect("file pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_file_artifact_hydrates_parse_entry_from_index_entry() {
        use crate::cache::parse::ParseCache;

        let root = temp_root();
        let persist = PersistCache::open(root.join("persist")).expect("cache opens");
        let parse_cache = ParseCache::new(root.join("parse"));
        let source = b"let x = 1; in x";
        let parsed = parse_cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source parses");
        let bundle = parsed
            .entry
            .read_artifact_bundle()
            .expect("artifact bundle reads");
        let payload = bundle.encode().expect("bundle encodes");
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let materialized = persist
            .materialize_file_artifact(
                &file_key,
                parsed.key,
                &payload,
                MaterializationDecision::Materialize,
            )
            .expect("bundle materializes");
        let Some(index_entry) = materialized.index_entry() else {
            panic!("bundle should materialize");
        };
        let hydrated = ParseCacheEntry::new(root.join("hydrated-entry-record"));

        persist
            .hydrate_file_artifact_bundle_from_entry(&file_key, parsed.key, index_entry, &hydrated)
            .expect("entry bundle hydrates");

        assert!(hydrated.is_complete());
        assert_eq!(
            hydrated
                .read_artifact_bundle()
                .expect("hydrated bundle reads"),
            bundle
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_parse_artifact_entry_materialization_can_skip_missing_entry() {
        let root = temp_root();
        let persist = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let parse_key = test_parse_key(source);
        let missing_entry = ParseCacheEntry::new(root.join("missing-entry"));
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

        let result = persist
            .materialize_parse_artifact_entry(
                &file_key,
                parse_key,
                &missing_entry,
                MaterializationDecision::KeepInMemory,
            )
            .expect("skip does not read missing entry");

        assert_eq!(
            result,
            PersistFileArtifactMaterialization::Skipped { artifact_key }
        );
        assert_eq!(
            fs::metadata(persist.file_pack().path())
                .expect("file pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_parse_artifact_entry_materialization_appends_bundle_payload() {
        use crate::cache::parse::ParseCache;

        let root = temp_root();
        let persist = PersistCache::open(root.join("persist")).expect("cache opens");
        let parse_cache = ParseCache::new(root.join("parse"));
        let source = b"let x = 1; in x";
        let parsed = parse_cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source parses");
        let bundle = parsed
            .entry
            .read_artifact_bundle()
            .expect("artifact bundle reads");
        let file_key = ParseFileKey::for_source("/src/default.nix", source);

        let result = persist
            .materialize_parse_artifact_entry(
                &file_key,
                parsed.key,
                &parsed.entry,
                MaterializationDecision::Materialize,
            )
            .expect("entry materializes");

        let Some(index_value) = result.index_value() else {
            panic!("entry should materialize");
        };
        let payload = persist
            .read_file_artifact(index_value)
            .expect("materialized entry reads");
        let decoded = ParseArtifactBundle::decode(&payload).expect("bundle decodes");
        assert_eq!(decoded, bundle);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_parse_artifact_entry_materialization_signals_can_skip_missing_entry() {
        let root = temp_root();
        let persist = PersistCache::open(&root).expect("cache opens");
        let source = b"let x = 1; in x";
        let file_key = ParseFileKey::for_source("/src/default.nix", source);
        let parse_key = test_parse_key(source);
        let missing_entry = ParseCacheEntry::new(root.join("missing-entry"));
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

        let result = persist
            .materialize_parse_artifact_entry_with_signals(
                &file_key,
                parse_key,
                &missing_entry,
                profitable_materialization_signals(false),
            )
            .expect("skip does not read missing entry");

        assert_eq!(
            result,
            PersistFileArtifactMaterialization::Skipped { artifact_key }
        );
        assert_eq!(
            fs::metadata(persist.file_pack().path())
                .expect("file pack metadata")
                .len(),
            PERSIST_BLOB_PACK_HEADER_LEN as u64
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_parse_artifact_entry_materialization_signals_append_when_threshold_passes() {
        use crate::cache::parse::ParseCache;

        let root = temp_root();
        let persist = PersistCache::open(root.join("persist")).expect("cache opens");
        let parse_cache = ParseCache::new(root.join("parse"));
        let source = b"let x = 1; in x";
        let parsed = parse_cache
            .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
            .expect("source parses");
        let bundle = parsed
            .entry
            .read_artifact_bundle()
            .expect("artifact bundle reads");
        let file_key = ParseFileKey::for_source("/src/default.nix", source);

        let result = persist
            .materialize_parse_artifact_entry_with_signals(
                &file_key,
                parsed.key,
                &parsed.entry,
                profitable_materialization_signals(true),
            )
            .expect("entry materializes");

        let Some(index_value) = result.index_value() else {
            panic!("entry should materialize");
        };
        let payload = persist
            .read_file_artifact(index_value)
            .expect("materialized entry reads");
        let decoded = ParseArtifactBundle::decode(&payload).expect("bundle decodes");
        assert_eq!(decoded, bundle);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn matching_schema_preserves_payload_directories() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout().clone();
        let node_file = sentinel(layout.nodes_dir().join("node"));
        let value_file = sentinel(layout.values_dir().join("value"));
        let file_file = sentinel(layout.files_dir().join("file"));

        PersistCache::open(&root).expect("matching schema opens");

        assert!(node_file.is_file());
        assert!(value_file.is_file());
        assert!(file_file.is_file());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mismatched_schema_discards_payload_and_rewrites_version() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout().clone();
        let node_file = sentinel(layout.nodes_dir().join("stale-node"));
        let value_file = sentinel(layout.values_dir().join("stale-value"));
        let file_file = sentinel(layout.files_dir().join("stale-file"));
        fs::write(
            layout.schema_path(),
            "format = \"aos-nix-eval-cache\"\nschema_version = 0\n",
        )
        .expect("schema downgrades");

        PersistCache::open(&root).expect("mismatched schema opens");

        assert!(!node_file.exists());
        assert!(!value_file.exists());
        assert!(!file_file.exists());
        assert!(layout.nodes_dir().is_dir());
        assert!(layout.values_dir().is_dir());
        assert!(layout.files_dir().is_dir());
        assert_eq!(
            fs::read_to_string(layout.schema_path()).expect("schema reads"),
            "format = \"aos-nix-eval-cache\"\nschema_version = 1\n"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_schema_errors_without_discarding_payload() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout().clone();
        let node_file = sentinel(layout.nodes_dir().join("node"));
        fs::write(layout.schema_path(), "schema_version =").expect("schema corrupts");

        let error = PersistCache::open(&root).expect_err("malformed schema errors");

        assert!(matches!(error, PersistError::ParseSchema { .. }));
        assert!(node_file.is_file());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wrong_schema_format_errors_without_discarding_payload() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout().clone();
        let value_file = sentinel(layout.values_dir().join("value"));
        fs::write(
            layout.schema_path(),
            "format = \"other-cache\"\nschema_version = 1\n",
        )
        .expect("schema rewrites");

        let error = PersistCache::open(&root).expect_err("wrong format errors");

        assert!(matches!(error, PersistError::InvalidFormat { .. }));
        assert!(value_file.is_file());

        let _ = fs::remove_dir_all(root);
    }
}
