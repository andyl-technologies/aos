//! Fixed-record hash-to-offset indexes for blob packfiles.
//!
//! RFC-0007's final metadata engine is an MVCC table, but the current
//! persistent cache still uses append-only fixed-record sidecars. This module
//! owns the generic engine representation of that sidecar layout so language
//! adapters can share one hash-to-offset encoding while the final metadata
//! engine is developed.
//!
//! ```text
//! entry = key || value
//!
//! key:
//!   namespace: 1 byte
//!   hash:      32 bytes, BLAKE3 digest
//!
//! value:
//!   record_offset: 8-byte little-endian u64
//!   payload_len:   8-byte little-endian u64
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::blob_pack::{BlobPackHash, BlobPackLocation};

/// The encoded length of a hash-to-offset index key.
pub const BLOB_INDEX_KEY_LEN: usize = 33;
/// The encoded length of a hash-to-offset index value.
pub const BLOB_INDEX_VALUE_LEN: usize = 16;
/// The encoded length of a complete hash-to-offset index entry.
pub const BLOB_INDEX_ENTRY_LEN: usize = BLOB_INDEX_KEY_LEN + BLOB_INDEX_VALUE_LEN;

static BLOB_INDEX_REWRITE_ID: AtomicU64 = AtomicU64::new(0);

/// A generic blob-index namespace tag.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobIndexNamespace(u8);

impl BlobIndexNamespace {
    /// Creates a namespace from its stable encoded tag.
    pub const fn from_tag(tag: u8) -> Self {
        Self(tag)
    }

    /// Returns this namespace's stable encoded tag.
    pub const fn tag(self) -> u8 {
        self.0
    }
}

/// A namespaced content-addressed lookup key for a blob index.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobIndexKey {
    namespace: BlobIndexNamespace,
    hash: BlobPackHash,
}

impl BlobIndexKey {
    /// Creates a blob index key from its namespace and content address.
    pub const fn new(namespace: BlobIndexNamespace, hash: BlobPackHash) -> Self {
        Self { namespace, hash }
    }

    /// Returns this key's namespace.
    pub const fn namespace(self) -> BlobIndexNamespace {
        self.namespace
    }

    /// Returns this key's content address.
    pub const fn hash(self) -> BlobPackHash {
        self.hash
    }

    /// Encodes this key as stable index bytes.
    pub fn encode(self) -> [u8; BLOB_INDEX_KEY_LEN] {
        let mut bytes = [0; BLOB_INDEX_KEY_LEN];
        bytes[0] = self.namespace.tag();
        bytes[1..].copy_from_slice(&self.hash.as_bytes());
        bytes
    }

    /// Decodes a stable index key prefix.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexFormatError::ShortKey`] if `bytes` is shorter than
    /// [`BLOB_INDEX_KEY_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, BlobIndexFormatError> {
        if bytes.len() < BLOB_INDEX_KEY_LEN {
            return Err(BlobIndexFormatError::ShortKey {
                expected: BLOB_INDEX_KEY_LEN,
                actual: bytes.len(),
            });
        }

        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[1..BLOB_INDEX_KEY_LEN]);
        Ok(Self::new(
            BlobIndexNamespace::from_tag(bytes[0]),
            BlobPackHash::from_bytes(hash),
        ))
    }
}

/// A complete hash-to-offset index entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobIndexEntry {
    key: BlobIndexKey,
    location: BlobPackLocation,
}

impl BlobIndexEntry {
    /// Creates a blob index entry from its lookup key and pack location.
    pub const fn new(key: BlobIndexKey, location: BlobPackLocation) -> Self {
        Self { key, location }
    }

    /// Returns the blob lookup key.
    pub const fn key(self) -> BlobIndexKey {
        self.key
    }

    /// Returns the blob pack location.
    pub const fn location(self) -> BlobPackLocation {
        self.location
    }

    /// Encodes this entry as stable index bytes.
    pub fn encode(self) -> [u8; BLOB_INDEX_ENTRY_LEN] {
        let mut bytes = [0; BLOB_INDEX_ENTRY_LEN];
        bytes[..BLOB_INDEX_KEY_LEN].copy_from_slice(&self.key.encode());
        bytes[BLOB_INDEX_KEY_LEN..].copy_from_slice(&encode_location(self.location));
        bytes
    }

    /// Decodes a stable index entry prefix.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexFormatError`] if `bytes` is shorter than
    /// [`BLOB_INDEX_ENTRY_LEN`] or any embedded codec rejects its prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlobIndexFormatError> {
        if bytes.len() < BLOB_INDEX_ENTRY_LEN {
            return Err(BlobIndexFormatError::ShortEntry {
                expected: BLOB_INDEX_ENTRY_LEN,
                actual: bytes.len(),
            });
        }

        let key = BlobIndexKey::decode(&bytes[..BLOB_INDEX_KEY_LEN])?;
        let location = decode_location(&bytes[BLOB_INDEX_KEY_LEN..BLOB_INDEX_ENTRY_LEN])?;
        Ok(Self::new(key, location))
    }
}

/// An append-only fixed-record blob index file.
#[derive(Clone, Debug)]
pub struct BlobIndex {
    path: PathBuf,
}

impl BlobIndex {
    /// Opens or initializes a fixed-record blob index file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if parent directories or the index file
    /// cannot be created/opened, or if the existing file ends with a partial
    /// fixed-width record.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, BlobIndexError> {
        let path = path.into();
        ensure_blob_index_file(&path)?;
        Ok(Self { path })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes `entries` exactly to `path`, replacing any stale file there.
    ///
    /// This staging helper is for callers that need to build a replacement
    /// sidecar at a separate path before a later multi-file swap. Entries are
    /// written in caller-supplied order; this helper does not sort, deduplicate,
    /// or validate namespace policy.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if a stale staged file cannot be removed, the
    /// parent directory cannot be created, or the staged entries cannot be
    /// written and flushed.
    pub fn write_entries_to(
        path: impl Into<PathBuf>,
        entries: &[BlobIndexEntry],
    ) -> Result<usize, BlobIndexError> {
        let path = path.into();
        remove_blob_index_file_if_exists(&path)?;
        let write_result = (|| {
            let index = Self::open(path.clone())?;
            for entry in entries {
                index.append_entry(*entry)?;
            }
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(entries.len())
    }

    /// Appends one hash-to-offset index entry.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if the index cannot be opened, validated,
    /// written, or flushed.
    pub fn append_entry(&self, entry: BlobIndexEntry) -> Result<(), BlobIndexError> {
        ensure_blob_index_file(&self.path)?;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| BlobIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&entry.encode())
            .and_then(|()| file.flush())
            .map_err(|source| BlobIndexError::Write {
                path: self.path.clone(),
                source,
            })
    }

    /// Looks up the newest location for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if the index cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn lookup(&self, key: BlobIndexKey) -> Result<Option<BlobPackLocation>, BlobIndexError> {
        let mut found = None;
        self.scan_entries(|entry| {
            if entry.key() == key {
                found = Some(entry.location());
            }
        })?;
        Ok(found)
    }

    /// Returns the newest entry for every key in stable key order.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if the index cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn latest_entries(&self) -> Result<Vec<BlobIndexEntry>, BlobIndexError> {
        let mut latest = BTreeMap::new();
        self.scan_entries(|entry| {
            latest.insert(entry.key().encode(), entry);
        })?;
        Ok(latest.into_values().collect())
    }

    /// Rewrites the index to the newest entry for every key.
    ///
    /// Entries are written in stable encoded-key order through a temporary file
    /// that is renamed over the original index. The returned count is the
    /// number of latest entries preserved after compaction. Callers must
    /// exclude concurrent sidecar writers while this method runs; an append
    /// that races between the snapshot and rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if the index cannot be created, opened,
    /// inspected, read, decoded, written, flushed, or renamed into place.
    pub fn compact_latest_entries(&self) -> Result<usize, BlobIndexError> {
        let entries = self.latest_entries()?;
        self.replace_entries(&entries)
    }

    /// Rewrites the index to exactly `entries` in caller-supplied order.
    ///
    /// Entries are written through a temporary file that is renamed over the
    /// original index. The returned count is the number of entries written.
    /// This low-level helper does not validate that entries match any specific
    /// blob namespace or packfile. Callers must exclude concurrent sidecar
    /// writers while this method runs; an append that races between the
    /// caller's snapshot and this rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if the index cannot be created, opened,
    /// inspected, written, flushed, or renamed into place.
    pub fn replace_entries(&self, entries: &[BlobIndexEntry]) -> Result<usize, BlobIndexError> {
        ensure_blob_index_file(&self.path)?;
        let rewrite_id = BLOB_INDEX_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self
            .path
            .with_extension(format!("compact-{}-{rewrite_id}.tmp", std::process::id()));
        let write_result = write_blob_index_entries(&tmp_path, entries);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(error);
        }
        fs::rename(&tmp_path, &self.path).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            BlobIndexError::Write {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(entries.len())
    }

    /// Returns the current index file length in bytes, or `0` if it is absent.
    ///
    /// This is the cheap change-detection primitive for callers maintaining an
    /// in-memory tail cache: it is a single stat with no directory creation or
    /// file open, so it stays cheap on the lookup hot path. Record-boundary
    /// validation is deferred to [`Self::read_entries_from`].
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if the index length cannot be inspected for a
    /// reason other than the file being absent.
    pub fn len(&self) -> Result<u64, BlobIndexError> {
        match fs::metadata(&self.path) {
            Ok(metadata) => Ok(metadata.len()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(source) => Err(BlobIndexError::Metadata {
                path: self.path.clone(),
                source,
            }),
        }
    }

    /// Reads records from byte `offset` to end of file in physical append order.
    ///
    /// Returns the decoded records and the byte offset one past the last record
    /// read (the file length at read time). `offset` must be a record boundary
    /// (`0` or a previously returned end offset); the append-only fixed-record
    /// format guarantees earlier offsets stay valid. An `offset` at or past the
    /// end yields no records.
    ///
    /// # Errors
    ///
    /// Returns [`BlobIndexError`] if the index cannot be created, opened,
    /// inspected, seeked, read, or decoded, or if the byte range from `offset`
    /// is not a whole number of records.
    pub fn read_entries_from(
        &self,
        offset: u64,
    ) -> Result<(Vec<BlobIndexEntry>, u64), BlobIndexError> {
        ensure_blob_index_file(&self.path)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| BlobIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| BlobIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_blob_index_len(&self.path, len)?;
        if offset >= len {
            return Ok((Vec::new(), len));
        }
        validate_blob_index_len(&self.path, len - offset)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|source| BlobIndexError::Read {
                path: self.path.clone(),
                source,
            })?;
        let remaining = (len - offset) as usize;
        let mut buffer = vec![0; remaining];
        file.read_exact(&mut buffer)
            .map_err(|source| BlobIndexError::Read {
                path: self.path.clone(),
                source,
            })?;
        let mut entries = Vec::with_capacity(remaining / BLOB_INDEX_ENTRY_LEN);
        for chunk in buffer.chunks_exact(BLOB_INDEX_ENTRY_LEN) {
            entries.push(BlobIndexEntry::decode(chunk).map_err(|source| {
                BlobIndexError::Format {
                    path: self.path.clone(),
                    source,
                }
            })?);
        }
        Ok((entries, len))
    }

    fn scan_entries(&self, mut visit: impl FnMut(BlobIndexEntry)) -> Result<(), BlobIndexError> {
        ensure_blob_index_file(&self.path)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| BlobIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| BlobIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_blob_index_len(&self.path, len)?;

        let records = len / BLOB_INDEX_ENTRY_LEN as u64;
        let mut encoded = [0; BLOB_INDEX_ENTRY_LEN];
        for _ in 0..records {
            file.read_exact(&mut encoded)
                .map_err(|source| BlobIndexError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            let entry =
                BlobIndexEntry::decode(&encoded).map_err(|source| BlobIndexError::Format {
                    path: self.path.clone(),
                    source,
                })?;
            visit(entry);
        }
        Ok(())
    }
}

/// Blob index bytes had an invalid shape.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BlobIndexFormatError {
    /// An index key was shorter than the fixed encoded key length.
    #[error("blob index key is shorter than {expected} bytes: {actual}")]
    ShortKey {
        /// The expected key length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// An index value was shorter than the fixed encoded location length.
    #[error("blob index value is shorter than {expected} bytes: {actual}")]
    ShortValue {
        /// The expected value length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// An index entry was shorter than the fixed encoded entry length.
    #[error("blob index entry is shorter than {expected} bytes: {actual}")]
    ShortEntry {
        /// The expected entry length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
}

/// A blob index operation failed.
#[derive(Debug, Error)]
pub enum BlobIndexError {
    /// A parent directory could not be created.
    #[error("failed to create blob index parent directory {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open blob index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read blob index metadata for {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read blob index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write blob index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("invalid blob index format in {path:?}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        #[source]
        source: BlobIndexFormatError,
    },
}

fn encode_location(location: BlobPackLocation) -> [u8; BLOB_INDEX_VALUE_LEN] {
    let mut bytes = [0; BLOB_INDEX_VALUE_LEN];
    bytes[..8].copy_from_slice(&location.record_offset().to_le_bytes());
    bytes[8..16].copy_from_slice(&location.payload_len().to_le_bytes());
    bytes
}

fn decode_location(bytes: &[u8]) -> Result<BlobPackLocation, BlobIndexFormatError> {
    if bytes.len() < BLOB_INDEX_VALUE_LEN {
        return Err(BlobIndexFormatError::ShortValue {
            expected: BLOB_INDEX_VALUE_LEN,
            actual: bytes.len(),
        });
    }
    Ok(BlobPackLocation::new(
        read_u64(&bytes[..8]),
        read_u64(&bytes[8..16]),
    ))
}

fn ensure_blob_index_file(path: &Path) -> Result<(), BlobIndexError> {
    ensure_blob_index_parent(path)?;

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| BlobIndexError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| BlobIndexError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_blob_index_len(path, len)
}

fn ensure_blob_index_parent(path: &Path) -> Result<(), BlobIndexError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| BlobIndexError::CreateParent {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn write_blob_index_entries(path: &Path, entries: &[BlobIndexEntry]) -> Result<(), BlobIndexError> {
    ensure_blob_index_parent(path)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|source| BlobIndexError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    for entry in entries {
        file.write_all(&entry.encode())
            .map_err(|source| BlobIndexError::Write {
                path: path.to_path_buf(),
                source,
            })?;
    }
    file.flush().map_err(|source| BlobIndexError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_blob_index_file_if_exists(path: &Path) -> Result<(), BlobIndexError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(BlobIndexError::Write {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_blob_index_len(path: &Path, len: u64) -> Result<(), BlobIndexError> {
    let remainder = len % BLOB_INDEX_ENTRY_LEN as u64;
    if remainder == 0 {
        return Ok(());
    }
    Err(BlobIndexError::Format {
        path: path.to_path_buf(),
        source: BlobIndexFormatError::ShortEntry {
            expected: BLOB_INDEX_ENTRY_LEN,
            actual: remainder as usize,
        },
    })
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(bytes);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const VALUES: BlobIndexNamespace = BlobIndexNamespace::from_tag(1);
    const FILES: BlobIndexNamespace = BlobIndexNamespace::from_tag(2);

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ratchet-cache-blob-index-{name}-{}-{nonce}.idx",
            std::process::id()
        ))
    }

    #[test]
    fn blob_index_entry_round_trips_stable_bytes() {
        let expected_hash = [
            0xec, 0x90, 0x91, 0x5f, 0xa2, 0x6a, 0xb0, 0x12, 0xa8, 0x9a, 0x88, 0xec, 0xc8, 0xb4,
            0x7e, 0x4d, 0xd7, 0x6c, 0x4a, 0xdf, 0xd6, 0xab, 0xd1, 0xfc, 0x10, 0xe3, 0x21, 0xb0,
            0xfc, 0xa1, 0x8d, 0x1d,
        ];
        let key = BlobIndexKey::new(VALUES, BlobPackHash::from_bytes(expected_hash));
        let location = BlobPackLocation::new(24, 7);
        let entry = BlobIndexEntry::new(key, location);
        let encoded = entry.encode();

        assert_eq!(encoded.len(), BLOB_INDEX_ENTRY_LEN);
        assert_eq!(encoded[0], VALUES.tag());
        assert_eq!(&encoded[1..BLOB_INDEX_KEY_LEN], expected_hash.as_slice());
        assert_eq!(
            &encoded[BLOB_INDEX_KEY_LEN..BLOB_INDEX_KEY_LEN + 8],
            24_u64.to_le_bytes().as_slice()
        );
        assert_eq!(
            &encoded[BLOB_INDEX_KEY_LEN + 8..BLOB_INDEX_ENTRY_LEN],
            7_u64.to_le_bytes().as_slice()
        );
        assert_eq!(
            BlobIndexEntry::decode(&encoded).expect("entry decodes"),
            entry
        );
        assert_eq!(
            BlobIndexKey::decode(&encoded[..BLOB_INDEX_KEY_LEN])
                .expect("key decodes")
                .namespace(),
            VALUES
        );
        assert_eq!(
            decode_location(&encoded[BLOB_INDEX_KEY_LEN..]).expect("location decodes"),
            location
        );
    }

    #[test]
    fn blob_index_rejects_short_prefixes() {
        assert!(matches!(
            BlobIndexKey::decode(&[0; 8]),
            Err(BlobIndexFormatError::ShortKey { actual: 8, .. })
        ));
        assert!(matches!(
            decode_location(&[0; 8]),
            Err(BlobIndexFormatError::ShortValue { actual: 8, .. })
        ));
        assert!(matches!(
            BlobIndexEntry::decode(&[0; 8]),
            Err(BlobIndexFormatError::ShortEntry { actual: 8, .. })
        ));
    }

    #[test]
    fn blob_index_opens_and_creates_parent_directories() {
        let root = temp_path("open-root");
        let path = root.join("values").join("index.bin");
        let index = BlobIndex::open(path.clone()).expect("index opens");

        assert_eq!(index.path(), path.as_path());
        assert_eq!(fs::read(&path).expect("index reads"), b"");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn blob_index_appends_and_finds_newest_matching_location() {
        let path = temp_path("lookup");
        let index = BlobIndex::open(path.clone()).expect("index opens");
        let key = BlobIndexKey::new(VALUES, BlobPackHash::for_bytes(b"payload"));
        let first = BlobPackLocation::new(24, 7);
        let second = BlobPackLocation::new(71, 7);
        let other = BlobIndexEntry::new(
            BlobIndexKey::new(FILES, BlobPackHash::for_bytes(b"payload")),
            BlobPackLocation::new(24, 9),
        );

        index
            .append_entry(BlobIndexEntry::new(key, first))
            .expect("first entry appends");
        index.append_entry(other).expect("other entry appends");
        index
            .append_entry(BlobIndexEntry::new(key, second))
            .expect("second entry appends");

        assert_eq!(index.lookup(key).expect("lookup succeeds"), Some(second));
        assert_eq!(
            index
                .lookup(BlobIndexKey::new(
                    VALUES,
                    BlobPackHash::for_bytes(b"missing")
                ))
                .expect("missing lookup succeeds"),
            None
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_index_latest_entries_are_newest_and_key_sorted() {
        let path = temp_path("latest");
        let index = BlobIndex::open(path.clone()).expect("index opens");
        let lower = BlobIndexKey::new(VALUES, BlobPackHash::from_bytes([0; 32]));
        let upper = BlobIndexKey::new(FILES, BlobPackHash::from_bytes([0xff; 32]));
        let stale_lower = BlobPackLocation::new(24, 1);
        let fresh_lower = BlobPackLocation::new(65, 1);
        let upper_location = BlobPackLocation::new(106, 2);

        index
            .append_entry(BlobIndexEntry::new(upper, upper_location))
            .expect("upper entry appends");
        index
            .append_entry(BlobIndexEntry::new(lower, stale_lower))
            .expect("stale lower entry appends");
        index
            .append_entry(BlobIndexEntry::new(lower, fresh_lower))
            .expect("fresh lower entry appends");

        assert_eq!(
            index.latest_entries().expect("latest entries scan"),
            [
                BlobIndexEntry::new(lower, fresh_lower),
                BlobIndexEntry::new(upper, upper_location),
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_index_compacts_to_latest_entries() {
        let path = temp_path("compact");
        let index = BlobIndex::open(path.clone()).expect("index opens");
        let lower = BlobIndexKey::new(VALUES, BlobPackHash::from_bytes([0; 32]));
        let upper = BlobIndexKey::new(FILES, BlobPackHash::from_bytes([0xff; 32]));
        let stale_lower = BlobPackLocation::new(24, 1);
        let fresh_lower = BlobPackLocation::new(65, 1);
        let upper_location = BlobPackLocation::new(106, 2);

        index
            .append_entry(BlobIndexEntry::new(upper, upper_location))
            .expect("upper entry appends");
        index
            .append_entry(BlobIndexEntry::new(lower, stale_lower))
            .expect("stale lower entry appends");
        index
            .append_entry(BlobIndexEntry::new(lower, fresh_lower))
            .expect("fresh lower entry appends");

        assert_eq!(
            fs::metadata(index.path()).expect("index metadata").len(),
            (BLOB_INDEX_ENTRY_LEN * 3) as u64
        );
        assert_eq!(index.compact_latest_entries().expect("index compacts"), 2);
        assert_eq!(
            fs::metadata(index.path()).expect("index metadata").len(),
            (BLOB_INDEX_ENTRY_LEN * 2) as u64
        );
        assert_eq!(
            index.latest_entries().expect("latest entries scan"),
            [
                BlobIndexEntry::new(lower, fresh_lower),
                BlobIndexEntry::new(upper, upper_location),
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_index_replaces_entries_in_caller_order() {
        let path = temp_path("replace");
        let index = BlobIndex::open(path.clone()).expect("index opens");
        let first = BlobIndexEntry::new(
            BlobIndexKey::new(FILES, BlobPackHash::from_bytes([0xff; 32])),
            BlobPackLocation::new(24, 1),
        );
        let second = BlobIndexEntry::new(
            BlobIndexKey::new(VALUES, BlobPackHash::from_bytes([0; 32])),
            BlobPackLocation::new(65, 2),
        );

        index
            .append_entry(BlobIndexEntry::new(
                BlobIndexKey::new(VALUES, BlobPackHash::for_bytes(b"stale")),
                BlobPackLocation::new(106, 3),
            ))
            .expect("stale entry appends");

        assert_eq!(
            index
                .replace_entries(&[first, second])
                .expect("entries replace"),
            2
        );
        assert_eq!(
            fs::read(index.path()).expect("index bytes read"),
            [first.encode(), second.encode()].concat()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_index_write_entries_to_replaces_stale_stage() {
        let path = temp_path("write-entries");
        let first = BlobIndexEntry::new(
            BlobIndexKey::new(FILES, BlobPackHash::from_bytes([0xff; 32])),
            BlobPackLocation::new(24, 1),
        );
        let second = BlobIndexEntry::new(
            BlobIndexKey::new(VALUES, BlobPackHash::from_bytes([0; 32])),
            BlobPackLocation::new(65, 2),
        );
        fs::write(&path, b"stale").expect("stale stage writes");

        assert_eq!(
            BlobIndex::write_entries_to(&path, &[first, second]).expect("entries stage"),
            2
        );

        assert_eq!(
            fs::read(&path).expect("index bytes read"),
            [first.encode(), second.encode()].concat()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_index_rejects_truncated_record_tail() {
        let path = temp_path("truncated");
        fs::write(&path, b"partial").expect("partial index writes");

        let error = BlobIndex::open(path.clone()).expect_err("truncated index errors");

        assert!(matches!(
            error,
            BlobIndexError::Format {
                source: BlobIndexFormatError::ShortEntry { actual: 7, .. },
                ..
            }
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn blob_index_read_entries_from_returns_only_the_tail() {
        let path = temp_path("read-from");
        let index = BlobIndex::open(path.clone()).expect("index opens");
        let first = BlobIndexEntry::new(
            BlobIndexKey::new(VALUES, BlobPackHash::for_bytes(b"a")),
            BlobPackLocation::new(24, 7),
        );
        let second = BlobIndexEntry::new(
            BlobIndexKey::new(VALUES, BlobPackHash::for_bytes(b"b")),
            BlobPackLocation::new(48, 7),
        );
        index.append_entry(first).expect("first entry appends");

        let (head, head_end) = index.read_entries_from(0).expect("full read succeeds");
        assert_eq!(head, [first]);
        assert_eq!(head_end, BLOB_INDEX_ENTRY_LEN as u64);

        index.append_entry(second).expect("second entry appends");
        let (tail, tail_end) = index
            .read_entries_from(head_end)
            .expect("tail read succeeds");
        assert_eq!(tail, [second]);
        assert_eq!(tail_end, (BLOB_INDEX_ENTRY_LEN * 2) as u64);

        let _ = fs::remove_file(path);
    }
}
