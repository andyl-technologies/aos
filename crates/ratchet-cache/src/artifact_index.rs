//! Fixed-record frontend artifact mapping sidecars.
//!
//! RFC-0007's final metadata engine is an MVCC table, but the current
//! persistent cache still stores append-only fixed-record sidecars for
//! frontend file and parse artifacts. This module owns the language-agnostic
//! engine representation of that record layout. It treats the artifact value
//! as opaque bytes so dialect-specific payload and blob-store semantics stay in
//! the safe oracle and dialect crates.
//!
//! ```text
//! entry = key || value
//!
//! key:
//!   namespace: 1 byte
//!   digest:    32 bytes, dialect-defined artifact identity digest
//!
//! value:
//!   payload:   49 bytes, dialect-defined fixed artifact mapping payload
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

/// The encoded length of an artifact mapping index key.
pub const ARTIFACT_INDEX_KEY_LEN: usize = 33;
/// The encoded length of an artifact mapping index value.
pub const ARTIFACT_INDEX_VALUE_LEN: usize = 49;
/// The encoded length of a complete artifact mapping index entry.
pub const ARTIFACT_INDEX_ENTRY_LEN: usize = ARTIFACT_INDEX_KEY_LEN + ARTIFACT_INDEX_VALUE_LEN;

static ARTIFACT_INDEX_REWRITE_ID: AtomicU64 = AtomicU64::new(0);

/// A stable frontend artifact mapping lookup key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArtifactIndexKey {
    namespace_tag: u8,
    digest: [u8; 32],
}

impl ArtifactIndexKey {
    /// Creates an artifact mapping key from its namespace tag and durable digest.
    pub const fn new(namespace_tag: u8, digest: [u8; 32]) -> Self {
        Self {
            namespace_tag,
            digest,
        }
    }

    /// Returns this key's stable namespace tag.
    pub const fn namespace_tag(self) -> u8 {
        self.namespace_tag
    }

    /// Returns this key's durable digest bytes.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Encodes this key as stable index bytes.
    pub fn encode(self) -> [u8; ARTIFACT_INDEX_KEY_LEN] {
        let mut bytes = [0; ARTIFACT_INDEX_KEY_LEN];
        bytes[0] = self.namespace_tag;
        bytes[1..].copy_from_slice(&self.digest);
        bytes
    }

    /// Decodes a stable artifact mapping key prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexFormatError::ShortKey`] if `bytes` is shorter
    /// than [`ARTIFACT_INDEX_KEY_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactIndexFormatError> {
        if bytes.len() < ARTIFACT_INDEX_KEY_LEN {
            return Err(ArtifactIndexFormatError::ShortKey {
                expected: ARTIFACT_INDEX_KEY_LEN,
                actual: bytes.len(),
            });
        }

        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes[1..ARTIFACT_INDEX_KEY_LEN]);
        Ok(Self::new(bytes[0], digest))
    }
}

/// An opaque fixed-width frontend artifact mapping value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactIndexValue {
    bytes: [u8; ARTIFACT_INDEX_VALUE_LEN],
}

impl ArtifactIndexValue {
    /// Creates an artifact mapping value from its stable encoded bytes.
    pub const fn from_bytes(bytes: [u8; ARTIFACT_INDEX_VALUE_LEN]) -> Self {
        Self { bytes }
    }

    /// Returns this value's stable encoded bytes.
    pub const fn bytes(self) -> [u8; ARTIFACT_INDEX_VALUE_LEN] {
        self.bytes
    }

    /// Encodes this value as stable index bytes.
    pub const fn encode(self) -> [u8; ARTIFACT_INDEX_VALUE_LEN] {
        self.bytes
    }

    /// Decodes a stable artifact mapping value prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexFormatError::ShortValue`] if `bytes` is shorter
    /// than [`ARTIFACT_INDEX_VALUE_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactIndexFormatError> {
        if bytes.len() < ARTIFACT_INDEX_VALUE_LEN {
            return Err(ArtifactIndexFormatError::ShortValue {
                expected: ARTIFACT_INDEX_VALUE_LEN,
                actual: bytes.len(),
            });
        }

        let mut value = [0; ARTIFACT_INDEX_VALUE_LEN];
        value.copy_from_slice(&bytes[..ARTIFACT_INDEX_VALUE_LEN]);
        Ok(Self::from_bytes(value))
    }
}

/// A complete frontend artifact mapping index entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactIndexEntry {
    key: ArtifactIndexKey,
    value: ArtifactIndexValue,
}

impl ArtifactIndexEntry {
    /// Creates an artifact mapping index entry from its lookup key and value.
    pub const fn new(key: ArtifactIndexKey, value: ArtifactIndexValue) -> Self {
        Self { key, value }
    }

    /// Returns the artifact mapping lookup key.
    pub const fn key(self) -> ArtifactIndexKey {
        self.key
    }

    /// Returns the artifact mapping value.
    pub const fn value(self) -> ArtifactIndexValue {
        self.value
    }

    /// Encodes this entry as stable index bytes.
    pub fn encode(self) -> [u8; ARTIFACT_INDEX_ENTRY_LEN] {
        let mut bytes = [0; ARTIFACT_INDEX_ENTRY_LEN];
        bytes[..ARTIFACT_INDEX_KEY_LEN].copy_from_slice(&self.key.encode());
        bytes[ARTIFACT_INDEX_KEY_LEN..].copy_from_slice(&self.value.encode());
        bytes
    }

    /// Decodes a stable artifact mapping index entry prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexFormatError`] if `bytes` is shorter than
    /// [`ARTIFACT_INDEX_ENTRY_LEN`] or any embedded codec rejects its prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactIndexFormatError> {
        if bytes.len() < ARTIFACT_INDEX_ENTRY_LEN {
            return Err(ArtifactIndexFormatError::ShortEntry {
                expected: ARTIFACT_INDEX_ENTRY_LEN,
                actual: bytes.len(),
            });
        }

        let key = ArtifactIndexKey::decode(&bytes[..ARTIFACT_INDEX_KEY_LEN])?;
        let value =
            ArtifactIndexValue::decode(&bytes[ARTIFACT_INDEX_KEY_LEN..ARTIFACT_INDEX_ENTRY_LEN])?;
        Ok(Self::new(key, value))
    }
}

/// An append-only fixed-record frontend artifact mapping index file.
#[derive(Clone, Debug)]
pub struct ArtifactIndex {
    path: PathBuf,
}

impl ArtifactIndex {
    /// Opens or initializes a fixed-record artifact mapping index file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexError`] if parent directories or the index file
    /// cannot be created/opened, or if the existing file ends with a partial
    /// fixed-width record.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ArtifactIndexError> {
        let path = path.into();
        ensure_artifact_index_file(&path)?;
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
    /// Returns [`ArtifactIndexError`] if a stale staged file cannot be removed,
    /// the parent directory cannot be created, or the staged entries cannot be
    /// written and flushed.
    pub fn write_entries_to(
        path: impl Into<PathBuf>,
        entries: &[ArtifactIndexEntry],
    ) -> Result<usize, ArtifactIndexError> {
        let path = path.into();
        remove_artifact_index_file_if_exists(&path)?;
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

    /// Appends one artifact mapping index entry.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexError`] if the index cannot be opened, validated,
    /// written, or flushed.
    pub fn append_entry(&self, entry: ArtifactIndexEntry) -> Result<(), ArtifactIndexError> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| ArtifactIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&entry.encode())
            .and_then(|()| file.flush())
            .map_err(|source| ArtifactIndexError::Write {
                path: self.path.clone(),
                source,
            })
    }

    /// Looks up the newest value for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexError`] if the index cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn lookup(
        &self,
        key: ArtifactIndexKey,
    ) -> Result<Option<ArtifactIndexValue>, ArtifactIndexError> {
        let mut found = None;
        self.scan_entries(|entry| {
            if entry.key() == key {
                found = Some(entry.value());
            }
        })?;
        Ok(found)
    }

    /// Returns every entry in physical append order.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexError`] if the index cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn entries(&self) -> Result<Vec<ArtifactIndexEntry>, ArtifactIndexError> {
        let mut entries = Vec::new();
        self.scan_entries(|entry| {
            entries.push(entry);
        })?;
        Ok(entries)
    }

    /// Returns the newest entry for every key in stable key order.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexError`] if the index cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn latest_entries(&self) -> Result<Vec<ArtifactIndexEntry>, ArtifactIndexError> {
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
    /// Returns [`ArtifactIndexError`] if the index cannot be created, opened,
    /// inspected, read, decoded, written, flushed, or renamed into place.
    pub fn compact_latest_entries(&self) -> Result<usize, ArtifactIndexError> {
        let entries = self.latest_entries()?;
        self.replace_entries(&entries)
    }

    /// Rewrites the index to exactly `entries` in caller-supplied order.
    ///
    /// Entries are written through a temporary file that is renamed over the
    /// original index. The returned count is the number of entries written.
    /// This low-level helper does not validate that entries match any specific
    /// artifact namespace or value schema. Callers must exclude concurrent
    /// sidecar writers while this method runs; an append that races between
    /// the caller's snapshot and this rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIndexError`] if the index cannot be created, opened,
    /// inspected, written, flushed, or renamed into place.
    pub fn replace_entries(
        &self,
        entries: &[ArtifactIndexEntry],
    ) -> Result<usize, ArtifactIndexError> {
        let rewrite_id = ARTIFACT_INDEX_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self
            .path
            .with_extension(format!("compact-{}-{rewrite_id}.tmp", std::process::id()));
        let write_result = write_artifact_index_entries(&tmp_path, entries);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(error);
        }
        fs::rename(&tmp_path, &self.path).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            ArtifactIndexError::Write {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(entries.len())
    }

    fn scan_entries(
        &self,
        mut visit: impl FnMut(ArtifactIndexEntry),
    ) -> Result<(), ArtifactIndexError> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| ArtifactIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| ArtifactIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_artifact_index_len(&self.path, len)?;

        let records = len / ARTIFACT_INDEX_ENTRY_LEN as u64;
        let mut encoded = [0; ARTIFACT_INDEX_ENTRY_LEN];
        for _ in 0..records {
            file.read_exact(&mut encoded)
                .map_err(|source| ArtifactIndexError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            let entry = ArtifactIndexEntry::decode(&encoded).map_err(|source| {
                ArtifactIndexError::Format {
                    path: self.path.clone(),
                    source,
                }
            })?;
            visit(entry);
        }
        Ok(())
    }
}

/// Artifact mapping sidecar bytes had an invalid shape.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ArtifactIndexFormatError {
    /// An index key was shorter than the fixed encoded key length.
    #[error("artifact index key is shorter than {expected} bytes: {actual}")]
    ShortKey {
        /// The expected key length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// An index value was shorter than the fixed encoded value length.
    #[error("artifact index value is shorter than {expected} bytes: {actual}")]
    ShortValue {
        /// The expected value length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// An index entry was shorter than the fixed encoded entry length.
    #[error("artifact index entry is shorter than {expected} bytes: {actual}")]
    ShortEntry {
        /// The expected entry length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
}

/// An artifact mapping sidecar operation failed.
#[derive(Debug, Error)]
pub enum ArtifactIndexError {
    /// A parent directory could not be created.
    #[error("failed to create artifact index parent directory {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open artifact index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read artifact index metadata for {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read artifact index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write artifact index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("invalid artifact index format in {path:?}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        #[source]
        source: ArtifactIndexFormatError,
    },
}

fn ensure_artifact_index_file(path: &Path) -> Result<(), ArtifactIndexError> {
    ensure_artifact_index_parent(path)?;

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| ArtifactIndexError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| ArtifactIndexError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_artifact_index_len(path, len)
}

fn ensure_artifact_index_parent(path: &Path) -> Result<(), ArtifactIndexError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| ArtifactIndexError::CreateParent {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn write_artifact_index_entries(
    path: &Path,
    entries: &[ArtifactIndexEntry],
) -> Result<(), ArtifactIndexError> {
    ensure_artifact_index_parent(path)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|source| ArtifactIndexError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    for entry in entries {
        file.write_all(&entry.encode())
            .map_err(|source| ArtifactIndexError::Write {
                path: path.to_path_buf(),
                source,
            })?;
    }
    file.flush().map_err(|source| ArtifactIndexError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_artifact_index_file_if_exists(path: &Path) -> Result<(), ArtifactIndexError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ArtifactIndexError::Write {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_artifact_index_len(path: &Path, len: u64) -> Result<(), ArtifactIndexError> {
    let remainder = len % ARTIFACT_INDEX_ENTRY_LEN as u64;
    if remainder == 0 {
        return Ok(());
    }
    Err(ArtifactIndexError::Format {
        path: path.to_path_buf(),
        source: ArtifactIndexFormatError::ShortEntry {
            expected: ARTIFACT_INDEX_ENTRY_LEN,
            actual: remainder as usize,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const FILE_ARTIFACTS: u8 = 3;
    const PARSE_ARTIFACTS: u8 = 4;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ratchet-cache-artifact-index-{name}-{}-{nonce}.idx",
            std::process::id()
        ))
    }

    fn artifact_key(namespace_tag: u8, digest_byte: u8) -> ArtifactIndexKey {
        ArtifactIndexKey::new(namespace_tag, [digest_byte; 32])
    }

    fn artifact_value(marker: u8) -> ArtifactIndexValue {
        let mut bytes = [0; ARTIFACT_INDEX_VALUE_LEN];
        bytes[0] = 2;
        bytes[1..33].copy_from_slice(&[marker; 32]);
        bytes[33..41].copy_from_slice(&(marker as u64).to_le_bytes());
        bytes[41..49].copy_from_slice(&(marker as u64 + 1).to_le_bytes());
        ArtifactIndexValue::from_bytes(bytes)
    }

    #[test]
    fn artifact_index_entry_round_trips_stable_bytes() {
        let digest = [
            0xd5, 0xd5, 0x59, 0x5f, 0x1b, 0xc7, 0xdb, 0x47, 0xf6, 0x47, 0x2f, 0x20, 0x90, 0x38,
            0x6e, 0x3b, 0x01, 0x92, 0xdf, 0x19, 0x08, 0xa0, 0x72, 0x34, 0x04, 0xc1, 0xdc, 0x66,
            0xc3, 0x07, 0x71, 0xf7,
        ];
        let key = ArtifactIndexKey::new(FILE_ARTIFACTS, digest);
        let value = artifact_value(7);
        let entry = ArtifactIndexEntry::new(key, value);
        let encoded = entry.encode();

        assert_eq!(encoded.len(), ARTIFACT_INDEX_ENTRY_LEN);
        assert_eq!(encoded[0], FILE_ARTIFACTS);
        assert_eq!(&encoded[1..ARTIFACT_INDEX_KEY_LEN], digest.as_slice());
        assert_eq!(
            &encoded[ARTIFACT_INDEX_KEY_LEN..ARTIFACT_INDEX_ENTRY_LEN],
            value.encode().as_slice()
        );
        assert_eq!(
            ArtifactIndexEntry::decode(&encoded).expect("entry decodes"),
            entry
        );
        assert_eq!(
            ArtifactIndexKey::decode(&encoded[..ARTIFACT_INDEX_KEY_LEN])
                .expect("key decodes")
                .namespace_tag(),
            FILE_ARTIFACTS
        );
        assert_eq!(
            ArtifactIndexValue::decode(&encoded[ARTIFACT_INDEX_KEY_LEN..]).expect("value decodes"),
            value
        );
    }

    #[test]
    fn artifact_index_rejects_short_prefixes() {
        assert!(matches!(
            ArtifactIndexKey::decode(&[0; 8]),
            Err(ArtifactIndexFormatError::ShortKey { actual: 8, .. })
        ));
        assert!(matches!(
            ArtifactIndexValue::decode(&[0; 8]),
            Err(ArtifactIndexFormatError::ShortValue { actual: 8, .. })
        ));
        assert!(matches!(
            ArtifactIndexEntry::decode(&[0; 8]),
            Err(ArtifactIndexFormatError::ShortEntry { actual: 8, .. })
        ));
    }

    #[test]
    fn artifact_index_opens_and_creates_parent_directories() {
        let root = temp_path("open-root");
        let path = root.join("nodes").join("file-artifacts.index");
        let index = ArtifactIndex::open(path.clone()).expect("index opens");

        assert_eq!(index.path(), path.as_path());
        assert_eq!(fs::read(&path).expect("index reads"), b"");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_index_appends_and_finds_newest_matching_value() {
        let path = temp_path("lookup");
        let index = ArtifactIndex::open(path.clone()).expect("index opens");
        let key = artifact_key(FILE_ARTIFACTS, 1);
        let first = artifact_value(1);
        let second = artifact_value(2);
        let other = ArtifactIndexEntry::new(artifact_key(PARSE_ARTIFACTS, 1), artifact_value(3));

        index
            .append_entry(ArtifactIndexEntry::new(key, first))
            .expect("first entry appends");
        index.append_entry(other).expect("other entry appends");
        index
            .append_entry(ArtifactIndexEntry::new(key, second))
            .expect("second entry appends");

        assert_eq!(index.lookup(key).expect("lookup succeeds"), Some(second));
        assert_eq!(
            index
                .lookup(artifact_key(FILE_ARTIFACTS, 9))
                .expect("missing lookup succeeds"),
            None
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn artifact_index_entries_preserve_physical_append_order() {
        let path = temp_path("entries");
        let index = ArtifactIndex::open(path.clone()).expect("index opens");
        let first = ArtifactIndexEntry::new(artifact_key(PARSE_ARTIFACTS, 0xff), artifact_value(1));
        let second = ArtifactIndexEntry::new(artifact_key(FILE_ARTIFACTS, 0), artifact_value(2));
        let third = ArtifactIndexEntry::new(artifact_key(PARSE_ARTIFACTS, 0xff), artifact_value(3));

        index.append_entry(first).expect("first entry appends");
        index.append_entry(second).expect("second entry appends");
        index.append_entry(third).expect("third entry appends");

        assert_eq!(
            index.entries().expect("physical entries scan"),
            [first, second, third]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn artifact_index_latest_entries_are_newest_and_key_sorted() {
        let path = temp_path("latest");
        let index = ArtifactIndex::open(path.clone()).expect("index opens");
        let lower = artifact_key(FILE_ARTIFACTS, 0);
        let upper = artifact_key(PARSE_ARTIFACTS, 0xff);
        let stale_lower = artifact_value(1);
        let fresh_lower = artifact_value(2);
        let upper_value = artifact_value(3);

        index
            .append_entry(ArtifactIndexEntry::new(upper, upper_value))
            .expect("upper entry appends");
        index
            .append_entry(ArtifactIndexEntry::new(lower, stale_lower))
            .expect("stale lower entry appends");
        index
            .append_entry(ArtifactIndexEntry::new(lower, fresh_lower))
            .expect("fresh lower entry appends");

        assert_eq!(
            index.latest_entries().expect("latest entries scan"),
            [
                ArtifactIndexEntry::new(lower, fresh_lower),
                ArtifactIndexEntry::new(upper, upper_value),
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn artifact_index_compacts_to_latest_entries() {
        let path = temp_path("compact");
        let index = ArtifactIndex::open(path.clone()).expect("index opens");
        let lower = artifact_key(FILE_ARTIFACTS, 0);
        let upper = artifact_key(PARSE_ARTIFACTS, 0xff);
        let stale_lower = artifact_value(1);
        let fresh_lower = artifact_value(2);
        let upper_value = artifact_value(3);

        index
            .append_entry(ArtifactIndexEntry::new(upper, upper_value))
            .expect("upper entry appends");
        index
            .append_entry(ArtifactIndexEntry::new(lower, stale_lower))
            .expect("stale lower entry appends");
        index
            .append_entry(ArtifactIndexEntry::new(lower, fresh_lower))
            .expect("fresh lower entry appends");

        assert_eq!(
            fs::metadata(index.path()).expect("index metadata").len(),
            (ARTIFACT_INDEX_ENTRY_LEN * 3) as u64
        );
        assert_eq!(index.compact_latest_entries().expect("index compacts"), 2);
        assert_eq!(
            fs::metadata(index.path()).expect("index metadata").len(),
            (ARTIFACT_INDEX_ENTRY_LEN * 2) as u64
        );
        assert_eq!(
            index.latest_entries().expect("latest entries scan"),
            [
                ArtifactIndexEntry::new(lower, fresh_lower),
                ArtifactIndexEntry::new(upper, upper_value),
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn artifact_index_replaces_entries_in_caller_order() {
        let path = temp_path("replace");
        let index = ArtifactIndex::open(path.clone()).expect("index opens");
        let first = ArtifactIndexEntry::new(artifact_key(PARSE_ARTIFACTS, 0xff), artifact_value(1));
        let second = ArtifactIndexEntry::new(artifact_key(FILE_ARTIFACTS, 0), artifact_value(2));

        index
            .append_entry(ArtifactIndexEntry::new(
                artifact_key(FILE_ARTIFACTS, 7),
                artifact_value(3),
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
    fn artifact_index_write_entries_to_replaces_stale_stage() {
        let path = temp_path("write-entries");
        let first = ArtifactIndexEntry::new(artifact_key(PARSE_ARTIFACTS, 0xff), artifact_value(1));
        let second = ArtifactIndexEntry::new(artifact_key(FILE_ARTIFACTS, 0), artifact_value(2));
        fs::write(&path, b"stale").expect("stale stage writes");

        assert_eq!(
            ArtifactIndex::write_entries_to(&path, &[first, second]).expect("entries stage"),
            2
        );

        assert_eq!(
            fs::read(&path).expect("index bytes read"),
            [first.encode(), second.encode()].concat()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn artifact_index_rejects_truncated_record_tail() {
        let path = temp_path("truncated");
        fs::write(&path, b"partial").expect("partial index writes");

        let error = ArtifactIndex::open(path.clone()).expect_err("truncated index errors");

        assert!(matches!(
            error,
            ArtifactIndexError::Format {
                source: ArtifactIndexFormatError::ShortEntry { actual: 7, .. },
                ..
            }
        ));

        let _ = fs::remove_file(path);
    }
}
