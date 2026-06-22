//! Versioned persistent-cache layout.
//!
//! The full Phase-2 storage engine will fill `nodes/`, `values/`, and `files/`
//! with verifying traces and content-addressed artifacts. This module owns the
//! on-disk layout contract and schema-version guard those stores share.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use super::DurableBlake3Hash;

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

static SCHEMA_WRITE_ID: AtomicU64 = AtomicU64::new(0);

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
    pub fn index_bytes(self) -> [u8; 33] {
        let mut bytes = [0; 33];
        bytes[0] = self.store.index_tag();
        bytes[1..].copy_from_slice(&self.hash.as_bytes());
        bytes
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

    /// Returns the append-only packfile path for serialized value blobs.
    pub fn value_packfile_path(&self) -> PathBuf {
        self.blob_packfile_path(PersistBlobStore::Values)
    }

    /// Returns the append-only packfile path for serialized file blobs.
    pub fn file_packfile_path(&self) -> PathBuf {
        self.blob_packfile_path(PersistBlobStore::Files)
    }

    fn blob_store_dir(&self, store: PersistBlobStore) -> PathBuf {
        match store {
            PersistBlobStore::Values => self.values_dir(),
            PersistBlobStore::Files => self.files_dir(),
        }
    }
}

/// An opened persistent eval-cache root.
#[derive(Clone, Debug)]
pub struct PersistCache {
    layout: PersistLayout,
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
    /// written, or if cache directories cannot be created or discarded.
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
        Ok(Self { layout })
    }

    /// Returns this cache's filesystem layout.
    pub const fn layout(&self) -> &PersistLayout {
        &self.layout
    }
}

/// Immutable blob packfile metadata could not be decoded.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PersistPackFormatError {
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
    fn open_creates_versioned_layout() {
        let root = temp_root();
        let cache = PersistCache::open(&root).expect("cache opens");
        let layout = cache.layout();

        assert_eq!(layout.root(), root.as_path());
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
