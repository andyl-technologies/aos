//! Fixed-record demand-node metadata sidecars.
//!
//! RFC-0007's final node metadata engine is an MVCC table, but the current
//! persistent cache still stores append-only fixed-record sidecars. This module
//! owns the language-agnostic engine representation of that record layout. It
//! treats the metadata value as opaque bytes so dialect-specific semantics stay
//! in the safe oracle and dialect crates.
//!
//! ```text
//! entry = key || value
//!
//! key:
//!   namespace: 1 byte
//!   digest:    32 bytes, dialect-defined durable node identity digest
//!
//! value:
//!   payload:   49 bytes, dialect-defined fixed metadata payload
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

/// The encoded length of a node metadata index key.
pub const NODE_METADATA_KEY_LEN: usize = 33;
/// The encoded length of a node metadata index value.
pub const NODE_METADATA_VALUE_LEN: usize = 49;
/// The encoded length of a complete node metadata index entry.
pub const NODE_METADATA_ENTRY_LEN: usize = NODE_METADATA_KEY_LEN + NODE_METADATA_VALUE_LEN;

static NODE_METADATA_INDEX_REWRITE_ID: AtomicU64 = AtomicU64::new(0);

/// A stable demand-node metadata lookup key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeMetadataKey {
    namespace_tag: u8,
    digest: [u8; 32],
}

impl NodeMetadataKey {
    /// Creates a node metadata key from its namespace tag and durable digest.
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
    pub fn encode(self) -> [u8; NODE_METADATA_KEY_LEN] {
        let mut bytes = [0; NODE_METADATA_KEY_LEN];
        bytes[0] = self.namespace_tag;
        bytes[1..].copy_from_slice(&self.digest);
        bytes
    }

    /// Decodes a stable node metadata key prefix.
    ///
    /// # Errors
    ///
    /// Returns [`NodeMetadataFormatError::ShortKey`] if `bytes` is shorter
    /// than [`NODE_METADATA_KEY_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeMetadataFormatError> {
        if bytes.len() < NODE_METADATA_KEY_LEN {
            return Err(NodeMetadataFormatError::ShortKey {
                expected: NODE_METADATA_KEY_LEN,
                actual: bytes.len(),
            });
        }

        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes[1..NODE_METADATA_KEY_LEN]);
        Ok(Self::new(bytes[0], digest))
    }
}

/// An opaque fixed-width demand-node metadata value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeMetadataValue {
    bytes: [u8; NODE_METADATA_VALUE_LEN],
}

impl NodeMetadataValue {
    /// Creates a node metadata value from its stable encoded bytes.
    pub const fn from_bytes(bytes: [u8; NODE_METADATA_VALUE_LEN]) -> Self {
        Self { bytes }
    }

    /// Returns this value's stable encoded bytes.
    pub const fn bytes(self) -> [u8; NODE_METADATA_VALUE_LEN] {
        self.bytes
    }

    /// Encodes this value as stable index bytes.
    pub const fn encode(self) -> [u8; NODE_METADATA_VALUE_LEN] {
        self.bytes
    }

    /// Decodes a stable node metadata value prefix.
    ///
    /// # Errors
    ///
    /// Returns [`NodeMetadataFormatError::ShortValue`] if `bytes` is shorter
    /// than [`NODE_METADATA_VALUE_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeMetadataFormatError> {
        if bytes.len() < NODE_METADATA_VALUE_LEN {
            return Err(NodeMetadataFormatError::ShortValue {
                expected: NODE_METADATA_VALUE_LEN,
                actual: bytes.len(),
            });
        }

        let mut value = [0; NODE_METADATA_VALUE_LEN];
        value.copy_from_slice(&bytes[..NODE_METADATA_VALUE_LEN]);
        Ok(Self::from_bytes(value))
    }
}

/// A complete demand-node metadata index entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeMetadataEntry {
    key: NodeMetadataKey,
    value: NodeMetadataValue,
}

impl NodeMetadataEntry {
    /// Creates a node metadata index entry from its lookup key and value.
    pub const fn new(key: NodeMetadataKey, value: NodeMetadataValue) -> Self {
        Self { key, value }
    }

    /// Returns the node metadata lookup key.
    pub const fn key(self) -> NodeMetadataKey {
        self.key
    }

    /// Returns the node metadata value.
    pub const fn value(self) -> NodeMetadataValue {
        self.value
    }

    /// Encodes this entry as stable index bytes.
    pub fn encode(self) -> [u8; NODE_METADATA_ENTRY_LEN] {
        let mut bytes = [0; NODE_METADATA_ENTRY_LEN];
        bytes[..NODE_METADATA_KEY_LEN].copy_from_slice(&self.key.encode());
        bytes[NODE_METADATA_KEY_LEN..].copy_from_slice(&self.value.encode());
        bytes
    }

    /// Decodes a stable node metadata index entry prefix.
    ///
    /// # Errors
    ///
    /// Returns [`NodeMetadataFormatError`] if `bytes` is shorter than
    /// [`NODE_METADATA_ENTRY_LEN`] or any embedded codec rejects its prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeMetadataFormatError> {
        if bytes.len() < NODE_METADATA_ENTRY_LEN {
            return Err(NodeMetadataFormatError::ShortEntry {
                expected: NODE_METADATA_ENTRY_LEN,
                actual: bytes.len(),
            });
        }

        let key = NodeMetadataKey::decode(&bytes[..NODE_METADATA_KEY_LEN])?;
        let value =
            NodeMetadataValue::decode(&bytes[NODE_METADATA_KEY_LEN..NODE_METADATA_ENTRY_LEN])?;
        Ok(Self::new(key, value))
    }
}

/// An append-only fixed-record node metadata index file.
#[derive(Clone, Debug)]
pub struct NodeMetadataIndex {
    path: PathBuf,
}

impl NodeMetadataIndex {
    /// Opens or initializes a fixed-record node metadata index file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeMetadataIndexError`] if parent directories or the index
    /// file cannot be created/opened, or if the existing file ends with a
    /// partial fixed-width record.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, NodeMetadataIndexError> {
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
    /// Returns [`NodeMetadataIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entry(&self, entry: NodeMetadataEntry) -> Result<(), NodeMetadataIndexError> {
        ensure_node_metadata_index_file(&self.path)?;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| NodeMetadataIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&entry.encode())
            .and_then(|()| file.flush())
            .map_err(|source| NodeMetadataIndexError::Write {
                path: self.path.clone(),
                source,
            })
    }

    /// Looks up the newest value for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeMetadataIndexError`] if the index cannot be created,
    /// opened, inspected, read, or decoded.
    pub fn lookup(
        &self,
        key: NodeMetadataKey,
    ) -> Result<Option<NodeMetadataValue>, NodeMetadataIndexError> {
        let mut found = None;
        self.scan_entries(|entry| {
            if entry.key() == key {
                found = Some(entry.value());
            }
        })?;
        Ok(found)
    }

    /// Returns the newest entry for every key in stable key order.
    ///
    /// # Errors
    ///
    /// Returns [`NodeMetadataIndexError`] if the index cannot be created,
    /// opened, inspected, read, or decoded.
    pub fn latest_entries(&self) -> Result<Vec<NodeMetadataEntry>, NodeMetadataIndexError> {
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
    /// Returns [`NodeMetadataIndexError`] if the index cannot be created,
    /// opened, inspected, read, decoded, written, flushed, or renamed into
    /// place.
    pub fn compact_latest_entries(&self) -> Result<usize, NodeMetadataIndexError> {
        let entries = self.latest_entries()?;
        self.replace_entries(&entries)
    }

    /// Rewrites the index to exactly `entries` in caller-supplied order.
    ///
    /// Entries are written through a temporary file that is renamed over the
    /// original index. The returned count is the number of entries written.
    /// This low-level helper does not validate that entries match any specific
    /// node namespace or value schema. Callers must exclude concurrent sidecar
    /// writers while this method runs; an append that races between the
    /// caller's snapshot and this rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`NodeMetadataIndexError`] if the index cannot be created,
    /// opened, inspected, written, flushed, or renamed into place.
    pub fn replace_entries(
        &self,
        entries: &[NodeMetadataEntry],
    ) -> Result<usize, NodeMetadataIndexError> {
        ensure_node_metadata_index_file(&self.path)?;
        let rewrite_id = NODE_METADATA_INDEX_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self
            .path
            .with_extension(format!("compact-{}-{rewrite_id}.tmp", std::process::id()));
        let write_result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|source| NodeMetadataIndexError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
            for entry in entries {
                file.write_all(&entry.encode()).map_err(|source| {
                    NodeMetadataIndexError::Write {
                        path: tmp_path.clone(),
                        source,
                    }
                })?;
            }
            file.flush()
                .map_err(|source| NodeMetadataIndexError::Write {
                    path: tmp_path.clone(),
                    source,
                })
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(error);
        }
        fs::rename(&tmp_path, &self.path).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            NodeMetadataIndexError::Write {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(entries.len())
    }

    fn scan_entries(
        &self,
        mut visit: impl FnMut(NodeMetadataEntry),
    ) -> Result<(), NodeMetadataIndexError> {
        ensure_node_metadata_index_file(&self.path)?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|source| NodeMetadataIndexError::Open {
                path: self.path.clone(),
                source,
            })?;
        let len = file
            .metadata()
            .map_err(|source| NodeMetadataIndexError::Metadata {
                path: self.path.clone(),
                source,
            })?
            .len();
        validate_node_metadata_index_len(&self.path, len)?;

        let records = len / NODE_METADATA_ENTRY_LEN as u64;
        let mut encoded = [0; NODE_METADATA_ENTRY_LEN];
        for _ in 0..records {
            file.read_exact(&mut encoded)
                .map_err(|source| NodeMetadataIndexError::Read {
                    path: self.path.clone(),
                    source,
                })?;
            let entry = NodeMetadataEntry::decode(&encoded).map_err(|source| {
                NodeMetadataIndexError::Format {
                    path: self.path.clone(),
                    source,
                }
            })?;
            visit(entry);
        }
        Ok(())
    }
}

/// Node metadata sidecar bytes had an invalid shape.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NodeMetadataFormatError {
    /// An index key was shorter than the fixed encoded key length.
    #[error("node metadata key is shorter than {expected} bytes: {actual}")]
    ShortKey {
        /// The expected key length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// An index value was shorter than the fixed encoded value length.
    #[error("node metadata value is shorter than {expected} bytes: {actual}")]
    ShortValue {
        /// The expected value length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// An index entry was shorter than the fixed encoded entry length.
    #[error("node metadata entry is shorter than {expected} bytes: {actual}")]
    ShortEntry {
        /// The expected entry length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
}

/// A node metadata sidecar operation failed.
#[derive(Debug, Error)]
pub enum NodeMetadataIndexError {
    /// A parent directory could not be created.
    #[error("failed to create node metadata index parent directory {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be opened.
    #[error("failed to open node metadata index {path:?}")]
    Open {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// Index file metadata could not be read.
    #[error("failed to read node metadata index metadata for {path:?}")]
    Metadata {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be read.
    #[error("failed to read node metadata index {path:?}")]
    Read {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file could not be written.
    #[error("failed to write node metadata index {path:?}")]
    Write {
        /// The index file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The index file has malformed fixed-record bytes.
    #[error("invalid node metadata index format in {path:?}")]
    Format {
        /// The index file path.
        path: PathBuf,
        /// The format error.
        #[source]
        source: NodeMetadataFormatError,
    },
}

fn ensure_node_metadata_index_file(path: &Path) -> Result<(), NodeMetadataIndexError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| NodeMetadataIndexError::CreateParent {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| NodeMetadataIndexError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| NodeMetadataIndexError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    validate_node_metadata_index_len(path, len)
}

fn validate_node_metadata_index_len(path: &Path, len: u64) -> Result<(), NodeMetadataIndexError> {
    let remainder = len % NODE_METADATA_ENTRY_LEN as u64;
    if remainder == 0 {
        return Ok(());
    }
    Err(NodeMetadataIndexError::Format {
        path: path.to_path_buf(),
        source: NodeMetadataFormatError::ShortEntry {
            expected: NODE_METADATA_ENTRY_LEN,
            actual: remainder as usize,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NODES: u8 = 5;
    const OTHER_NODES: u8 = 6;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ratchet-cache-node-metadata-{name}-{}-{nonce}.idx",
            std::process::id()
        ))
    }

    fn metadata_key(namespace_tag: u8, digest_byte: u8) -> NodeMetadataKey {
        NodeMetadataKey::new(namespace_tag, [digest_byte; 32])
    }

    fn value(marker: u8) -> NodeMetadataValue {
        let mut bytes = [0; NODE_METADATA_VALUE_LEN];
        bytes[0] = marker;
        bytes[16] = 1;
        bytes[17..].copy_from_slice(&[marker; 32]);
        NodeMetadataValue::from_bytes(bytes)
    }

    #[test]
    fn node_metadata_entry_round_trips_stable_bytes() {
        let digest = [
            0x0b, 0xb8, 0x10, 0x6c, 0x2f, 0x35, 0x15, 0x93, 0x71, 0xd1, 0xaa, 0xe5, 0x54, 0x24,
            0x77, 0x29, 0x50, 0x1e, 0x79, 0xa0, 0xc8, 0x55, 0xf5, 0xc9, 0x3d, 0x2a, 0x34, 0xfe,
            0xd1, 0x7f, 0xd6, 0x2a,
        ];
        let key = NodeMetadataKey::new(NODES, digest);
        let value = value(7);
        let entry = NodeMetadataEntry::new(key, value);
        let encoded = entry.encode();

        assert_eq!(encoded.len(), NODE_METADATA_ENTRY_LEN);
        assert_eq!(encoded[0], NODES);
        assert_eq!(&encoded[1..NODE_METADATA_KEY_LEN], digest.as_slice());
        assert_eq!(
            &encoded[NODE_METADATA_KEY_LEN..NODE_METADATA_ENTRY_LEN],
            value.encode().as_slice()
        );
        assert_eq!(
            NodeMetadataEntry::decode(&encoded).expect("entry decodes"),
            entry
        );
        assert_eq!(
            NodeMetadataKey::decode(&encoded[..NODE_METADATA_KEY_LEN])
                .expect("key decodes")
                .namespace_tag(),
            NODES
        );
        assert_eq!(
            NodeMetadataValue::decode(&encoded[NODE_METADATA_KEY_LEN..]).expect("value decodes"),
            value
        );
    }

    #[test]
    fn node_metadata_rejects_short_prefixes() {
        assert!(matches!(
            NodeMetadataKey::decode(&[0; 8]),
            Err(NodeMetadataFormatError::ShortKey { actual: 8, .. })
        ));
        assert!(matches!(
            NodeMetadataValue::decode(&[0; 8]),
            Err(NodeMetadataFormatError::ShortValue { actual: 8, .. })
        ));
        assert!(matches!(
            NodeMetadataEntry::decode(&[0; 8]),
            Err(NodeMetadataFormatError::ShortEntry { actual: 8, .. })
        ));
    }

    #[test]
    fn node_metadata_index_opens_and_creates_parent_directories() {
        let root = temp_path("open-root");
        let path = root.join("nodes").join("metadata.index");
        let index = NodeMetadataIndex::open(path.clone()).expect("index opens");

        assert_eq!(index.path(), path.as_path());
        assert_eq!(fs::read(&path).expect("index reads"), b"");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn node_metadata_index_appends_and_finds_newest_matching_value() {
        let path = temp_path("lookup");
        let index = NodeMetadataIndex::open(path.clone()).expect("index opens");
        let key = metadata_key(NODES, 1);
        let first = value(1);
        let second = value(2);
        let other = NodeMetadataEntry::new(metadata_key(OTHER_NODES, 1), value(3));

        index
            .append_entry(NodeMetadataEntry::new(key, first))
            .expect("first entry appends");
        index.append_entry(other).expect("other entry appends");
        index
            .append_entry(NodeMetadataEntry::new(key, second))
            .expect("second entry appends");

        assert_eq!(index.lookup(key).expect("lookup succeeds"), Some(second));
        assert_eq!(
            index
                .lookup(metadata_key(NODES, 9))
                .expect("missing lookup succeeds"),
            None
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_metadata_index_latest_entries_are_newest_and_key_sorted() {
        let path = temp_path("latest");
        let index = NodeMetadataIndex::open(path.clone()).expect("index opens");
        let lower = metadata_key(NODES, 0);
        let upper = metadata_key(OTHER_NODES, 0xff);
        let stale_lower = value(1);
        let fresh_lower = value(2);
        let upper_value = value(3);

        index
            .append_entry(NodeMetadataEntry::new(upper, upper_value))
            .expect("upper entry appends");
        index
            .append_entry(NodeMetadataEntry::new(lower, stale_lower))
            .expect("stale lower entry appends");
        index
            .append_entry(NodeMetadataEntry::new(lower, fresh_lower))
            .expect("fresh lower entry appends");

        assert_eq!(
            index.latest_entries().expect("latest entries scan"),
            [
                NodeMetadataEntry::new(lower, fresh_lower),
                NodeMetadataEntry::new(upper, upper_value),
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_metadata_index_compacts_to_latest_entries() {
        let path = temp_path("compact");
        let index = NodeMetadataIndex::open(path.clone()).expect("index opens");
        let lower = metadata_key(NODES, 0);
        let upper = metadata_key(OTHER_NODES, 0xff);
        let stale_lower = value(1);
        let fresh_lower = value(2);
        let upper_value = value(3);

        index
            .append_entry(NodeMetadataEntry::new(upper, upper_value))
            .expect("upper entry appends");
        index
            .append_entry(NodeMetadataEntry::new(lower, stale_lower))
            .expect("stale lower entry appends");
        index
            .append_entry(NodeMetadataEntry::new(lower, fresh_lower))
            .expect("fresh lower entry appends");

        assert_eq!(
            fs::metadata(index.path()).expect("index metadata").len(),
            (NODE_METADATA_ENTRY_LEN * 3) as u64
        );
        assert_eq!(index.compact_latest_entries().expect("index compacts"), 2);
        assert_eq!(
            fs::metadata(index.path()).expect("index metadata").len(),
            (NODE_METADATA_ENTRY_LEN * 2) as u64
        );
        assert_eq!(
            index.latest_entries().expect("latest entries scan"),
            [
                NodeMetadataEntry::new(lower, fresh_lower),
                NodeMetadataEntry::new(upper, upper_value),
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_metadata_index_replaces_entries_in_caller_order() {
        let path = temp_path("replace");
        let index = NodeMetadataIndex::open(path.clone()).expect("index opens");
        let first = NodeMetadataEntry::new(metadata_key(OTHER_NODES, 0xff), value(1));
        let second = NodeMetadataEntry::new(metadata_key(NODES, 0), value(2));

        index
            .append_entry(NodeMetadataEntry::new(metadata_key(NODES, 7), value(3)))
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
    fn node_metadata_index_rejects_truncated_record_tail() {
        let path = temp_path("truncated");
        fs::write(&path, b"partial").expect("partial index writes");

        let error = NodeMetadataIndex::open(path.clone()).expect_err("truncated index errors");

        assert!(matches!(
            error,
            NodeMetadataIndexError::Format {
                source: NodeMetadataFormatError::ShortEntry { actual: 7, .. },
                ..
            }
        ));

        let _ = fs::remove_file(path);
    }
}
