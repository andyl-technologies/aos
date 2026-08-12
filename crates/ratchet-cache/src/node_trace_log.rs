//! Variable-length demand-node trace log sidecars.
//!
//! RFC-0007's final node engine is an MVCC table, but the current persistent
//! cache still stores append-only trace records in `nodes/traces.log`. This
//! module owns the language-agnostic engine representation of that record
//! layout. It treats trace payloads as opaque bytes so dialect-specific trace
//! validation stays in the safe oracle and dialect crates.
//!
//! ```text
//! record = key || value_hash || payload_len || payload
//!
//! key:
//!   namespace: 1 byte
//!   digest:    32 bytes, dialect-defined durable node identity digest
//!
//! value_hash:
//!   digest:    32 bytes, dialect-defined materialized value hash
//!
//! payload_len:
//!   len:       8-byte little-endian u64
//!
//! payload:
//!   bytes:     payload_len opaque bytes
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

/// The encoded length of a node trace log key.
pub const NODE_TRACE_LOG_KEY_LEN: usize = 33;
/// The encoded length of a trace-associated materialized value hash.
pub const NODE_TRACE_LOG_VALUE_HASH_LEN: usize = 32;
/// The fixed header bytes in one node trace log record.
pub const NODE_TRACE_LOG_RECORD_HEADER_LEN: usize =
    NODE_TRACE_LOG_KEY_LEN + NODE_TRACE_LOG_VALUE_HASH_LEN + 8;

static NODE_TRACE_LOG_REWRITE_ID: AtomicU64 = AtomicU64::new(0);

/// A stable demand-node trace lookup key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeTraceLogKey {
    namespace_tag: u8,
    digest: [u8; 32],
}

impl NodeTraceLogKey {
    /// Creates a node trace log key from its namespace tag and durable digest.
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

    /// Encodes this key as stable log bytes.
    pub fn encode(self) -> [u8; NODE_TRACE_LOG_KEY_LEN] {
        let mut bytes = [0; NODE_TRACE_LOG_KEY_LEN];
        bytes[0] = self.namespace_tag;
        bytes[1..].copy_from_slice(&self.digest);
        bytes
    }

    /// Decodes a stable node trace log key prefix.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogFormatError::ShortKey`] if `bytes` is shorter
    /// than [`NODE_TRACE_LOG_KEY_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeTraceLogFormatError> {
        if bytes.len() < NODE_TRACE_LOG_KEY_LEN {
            return Err(NodeTraceLogFormatError::ShortKey {
                expected: NODE_TRACE_LOG_KEY_LEN,
                actual: bytes.len(),
            });
        }

        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes[1..NODE_TRACE_LOG_KEY_LEN]);
        Ok(Self::new(bytes[0], digest))
    }
}

/// An opaque materialized value hash recorded beside a node trace payload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeTraceLogValueHash {
    bytes: [u8; NODE_TRACE_LOG_VALUE_HASH_LEN],
}

impl NodeTraceLogValueHash {
    /// Creates a node trace log value hash from its stable encoded bytes.
    pub const fn from_bytes(bytes: [u8; NODE_TRACE_LOG_VALUE_HASH_LEN]) -> Self {
        Self { bytes }
    }

    /// Returns this value hash's stable encoded bytes.
    pub const fn bytes(self) -> [u8; NODE_TRACE_LOG_VALUE_HASH_LEN] {
        self.bytes
    }

    /// Encodes this value hash as stable log bytes.
    pub const fn encode(self) -> [u8; NODE_TRACE_LOG_VALUE_HASH_LEN] {
        self.bytes
    }

    /// Decodes a stable node trace log value-hash prefix.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogFormatError::ShortValueHash`] if `bytes` is
    /// shorter than [`NODE_TRACE_LOG_VALUE_HASH_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NodeTraceLogFormatError> {
        if bytes.len() < NODE_TRACE_LOG_VALUE_HASH_LEN {
            return Err(NodeTraceLogFormatError::ShortValueHash {
                expected: NODE_TRACE_LOG_VALUE_HASH_LEN,
                actual: bytes.len(),
            });
        }

        let mut value_hash = [0; NODE_TRACE_LOG_VALUE_HASH_LEN];
        value_hash.copy_from_slice(&bytes[..NODE_TRACE_LOG_VALUE_HASH_LEN]);
        Ok(Self::from_bytes(value_hash))
    }
}

/// A complete key/value-hash/payload record in a node trace log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeTraceLogEntry {
    key: NodeTraceLogKey,
    value_hash: NodeTraceLogValueHash,
    payload: Vec<u8>,
}

impl NodeTraceLogEntry {
    /// Creates a node trace log entry from its lookup key, value hash, and payload.
    pub fn new(key: NodeTraceLogKey, value_hash: NodeTraceLogValueHash, payload: Vec<u8>) -> Self {
        Self {
            key,
            value_hash,
            payload,
        }
    }

    /// Returns the node trace lookup key.
    pub const fn key(&self) -> NodeTraceLogKey {
        self.key
    }

    /// Returns the materialized value hash this trace verifies.
    pub const fn value_hash(&self) -> NodeTraceLogValueHash {
        self.value_hash
    }

    /// Returns the opaque trace payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the entry and returns its opaque trace payload bytes.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// An append-only variable-length node trace log file.
#[derive(Clone, Debug)]
pub struct NodeTraceLog {
    path: PathBuf,
}

impl NodeTraceLog {
    /// Opens or initializes a variable-length node trace log file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if parent directories or the log file
    /// cannot be created/opened, or if an existing log contains malformed
    /// variable-length records.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, NodeTraceLogError> {
        let path = path.into();
        ensure_node_trace_log_file(&path)?;
        // Validate the whole log's record framing once at open. `ensure` only
        // creates and stats the file (running a full scan on every append made
        // appends quadratic), so the open-time framing check lives here.
        scan_node_trace_log_entries_from(&path, 0, |_| {})?;
        Ok(Self { path })
    }

    /// Returns this log file's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one node trace log entry.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if the log cannot be opened, validated,
    /// written, or flushed, or if the encoded record cannot be allocated.
    pub fn append_entry(&self, entry: NodeTraceLogEntry) -> Result<(), NodeTraceLogError> {
        let record = encode_node_trace_log_entry(&entry)?;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| NodeTraceLogError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(&record)
            .and_then(|()| file.flush())
            .map_err(|source| NodeTraceLogError::Write {
                path: self.path.clone(),
                source,
            })
    }

    /// Looks up the newest trace record recorded for `key`.
    ///
    /// Missing trace records return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if the log cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn lookup(
        &self,
        key: NodeTraceLogKey,
    ) -> Result<Option<NodeTraceLogEntry>, NodeTraceLogError> {
        let mut found = None;
        self.scan_entries(|entry| {
            if entry.key() == key {
                found = Some(entry);
            }
        })?;
        Ok(found)
    }

    /// Returns every entry in physical append order.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if the log cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn entries(&self) -> Result<Vec<NodeTraceLogEntry>, NodeTraceLogError> {
        let mut entries = Vec::new();
        self.scan_entries(|entry| {
            entries.push(entry);
        })?;
        Ok(entries)
    }

    /// Returns the current log file length in bytes, or `0` if it is absent.
    ///
    /// This is the cheap change-detection primitive for callers maintaining an
    /// in-memory tail cache: it is a single stat with no directory creation or
    /// file open, so it stays cheap on the lookup hot path.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if the log length cannot be inspected for a
    /// reason other than the file being absent.
    pub fn len(&self) -> Result<u64, NodeTraceLogError> {
        match fs::metadata(&self.path) {
            Ok(metadata) => Ok(metadata.len()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(source) => Err(NodeTraceLogError::Metadata {
                path: self.path.clone(),
                source,
            }),
        }
    }

    /// Reads records from byte `offset` to end of file in physical append order.
    ///
    /// Returns the decoded records and the byte offset one past the last record
    /// read (the log length at read time). `offset` must be a record boundary
    /// (`0` or a previously returned end offset); the append-only format
    /// guarantees earlier offsets stay valid. An `offset` at or past the end
    /// yields no records.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if the log cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn read_entries_from(
        &self,
        offset: u64,
    ) -> Result<(Vec<NodeTraceLogEntry>, u64), NodeTraceLogError> {
        let mut entries = Vec::new();
        let end = scan_node_trace_log_entries_from(&self.path, offset, |entry| {
            entries.push(entry);
        })?;
        Ok((entries, end))
    }

    /// Returns the newest trace log entry for every key in stable key order.
    ///
    /// Tombstones are not interpreted by this engine layer; if callers encode
    /// tombstones in payload bytes, the newest tombstone record is preserved as
    /// an ordinary entry.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if the log cannot be created, opened,
    /// inspected, read, or decoded.
    pub fn latest_entries(&self) -> Result<Vec<NodeTraceLogEntry>, NodeTraceLogError> {
        let mut latest = BTreeMap::new();
        self.scan_entries(|entry| {
            latest.insert(entry.key(), entry);
        })?;
        Ok(latest.into_values().collect())
    }

    /// Rewrites the log to the newest trace entry for every key.
    ///
    /// Entries are written in stable key order through a temporary file that is
    /// renamed over the original log. The returned count is the number of
    /// latest entries preserved after compaction. Callers must exclude
    /// concurrent log writers while this method runs; an append that races
    /// between the snapshot and rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if the log cannot be created, opened,
    /// inspected, read, decoded, written, flushed, or renamed into place.
    pub fn compact_latest_entries(&self) -> Result<usize, NodeTraceLogError> {
        let entries = self.latest_entries()?;
        self.replace_entries(&entries)
    }

    /// Rewrites the log to exactly `entries` in caller-supplied order.
    ///
    /// Entries are written through a temporary file that is renamed over the
    /// original log. The returned count is the number of entries written. This
    /// low-level helper does not validate payload semantics. Callers must
    /// exclude concurrent log writers while this method runs; an append that
    /// races between the caller's snapshot and this rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`NodeTraceLogError`] if the log cannot be created, opened,
    /// inspected, written, flushed, or renamed into place.
    pub fn replace_entries(
        &self,
        entries: &[NodeTraceLogEntry],
    ) -> Result<usize, NodeTraceLogError> {
        let rewrite_id = NODE_TRACE_LOG_REWRITE_ID.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self
            .path
            .with_extension(format!("compact-{}-{rewrite_id}.tmp", std::process::id()));
        let write_result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|source| NodeTraceLogError::Write {
                    path: tmp_path.clone(),
                    source,
                })?;
            for entry in entries {
                let record = encode_node_trace_log_entry(entry)?;
                file.write_all(&record)
                    .map_err(|source| NodeTraceLogError::Write {
                        path: tmp_path.clone(),
                        source,
                    })?;
            }
            file.flush().map_err(|source| NodeTraceLogError::Write {
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
            NodeTraceLogError::Write {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(entries.len())
    }

    fn scan_entries(&self, visit: impl FnMut(NodeTraceLogEntry)) -> Result<(), NodeTraceLogError> {
        scan_node_trace_log_entries_from(&self.path, 0, visit)?;
        Ok(())
    }
}

/// Node trace log bytes had an invalid shape.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NodeTraceLogFormatError {
    /// A log key was shorter than the fixed encoded key length.
    #[error("node trace log key is shorter than {expected} bytes: {actual}")]
    ShortKey {
        /// The expected key length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// A value hash was shorter than the fixed encoded hash length.
    #[error("node trace log value hash is shorter than {expected} bytes: {actual}")]
    ShortValueHash {
        /// The expected value-hash length.
        expected: usize,
        /// The available byte count.
        actual: usize,
    },
    /// A trace log record was shorter than the fixed header length.
    #[error("node trace log record has {actual} bytes, expected at least {expected}")]
    ShortRecordHeader {
        /// The required fixed record header length.
        expected: u64,
        /// The available bytes.
        actual: u64,
    },
    /// A trace log record payload length cannot fit in the local address space.
    #[error("node trace log payload length {len} does not fit in usize")]
    PayloadLengthOverflow {
        /// The decoded payload length.
        len: u64,
    },
    /// A trace log record range cannot be represented.
    #[error(
        "node trace log record at offset {record_offset} with payload length {payload_len} overflows"
    )]
    RecordBoundsOverflow {
        /// The record offset.
        record_offset: u64,
        /// The decoded payload length.
        payload_len: u64,
    },
    /// A trace log record payload was shorter than its declared length.
    #[error("node trace log payload ends at {expected}, past log length {actual}")]
    ShortRecordPayload {
        /// The byte offset one past the declared payload.
        expected: u64,
        /// The current log length.
        actual: u64,
    },
}

/// A variable-length node trace log operation failed.
#[derive(Debug, Error)]
pub enum NodeTraceLogError {
    /// A parent directory could not be created.
    #[error("failed to create node trace log parent directory {path:?}")]
    CreateParent {
        /// The parent directory path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The log file could not be opened.
    #[error("failed to open node trace log {path:?}")]
    Open {
        /// The log file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// Log file metadata could not be read.
    #[error("failed to read node trace log metadata for {path:?}")]
    Metadata {
        /// The log file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The log file could not be read.
    #[error("failed to read node trace log {path:?}")]
    Read {
        /// The log file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// The log file could not be written.
    #[error("failed to write node trace log {path:?}")]
    Write {
        /// The log file path.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// A node trace payload length is too large for the log record format.
    #[error("node trace log payload length {len} is too large")]
    PayloadTooLarge {
        /// The oversized payload length.
        len: usize,
    },
    /// A node trace log record could not reserve contiguous output storage.
    #[error("failed to reserve node trace log record with {len} bytes")]
    RecordAllocationFailed {
        /// The requested encoded record byte length.
        len: usize,
    },
    /// A node trace payload could not reserve storage while reading.
    #[error("failed to reserve node trace log payload with {len} bytes")]
    PayloadAllocationFailed {
        /// The requested payload byte length.
        len: usize,
    },
    /// The log file has malformed variable-length record bytes.
    #[error("invalid node trace log format in {path:?}")]
    Format {
        /// The log file path.
        path: PathBuf,
        /// The format error.
        #[source]
        source: NodeTraceLogFormatError,
    },
}

fn encode_node_trace_log_entry(entry: &NodeTraceLogEntry) -> Result<Vec<u8>, NodeTraceLogError> {
    let payload_len =
        u64::try_from(entry.payload().len()).map_err(|_| NodeTraceLogError::PayloadTooLarge {
            len: entry.payload().len(),
        })?;
    let record_len = NODE_TRACE_LOG_RECORD_HEADER_LEN
        .checked_add(entry.payload().len())
        .ok_or(NodeTraceLogError::PayloadTooLarge {
            len: entry.payload().len(),
        })?;
    let mut record = Vec::new();
    record
        .try_reserve_exact(record_len)
        .map_err(|_| NodeTraceLogError::RecordAllocationFailed { len: record_len })?;
    record.extend_from_slice(&encode_node_trace_log_record_header(
        entry.key(),
        entry.value_hash(),
        payload_len,
    ));
    record.extend_from_slice(entry.payload());
    Ok(record)
}

fn encode_node_trace_log_record_header(
    key: NodeTraceLogKey,
    value_hash: NodeTraceLogValueHash,
    payload_len: u64,
) -> [u8; NODE_TRACE_LOG_RECORD_HEADER_LEN] {
    let mut bytes = [0; NODE_TRACE_LOG_RECORD_HEADER_LEN];
    let key_end = NODE_TRACE_LOG_KEY_LEN;
    let value_hash_end = key_end + NODE_TRACE_LOG_VALUE_HASH_LEN;
    bytes[..key_end].copy_from_slice(&key.encode());
    bytes[key_end..value_hash_end].copy_from_slice(&value_hash.encode());
    bytes[value_hash_end..].copy_from_slice(&payload_len.to_le_bytes());
    bytes
}

fn ensure_node_trace_log_file(path: &Path) -> Result<(), NodeTraceLogError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| NodeTraceLogError::CreateParent {
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
        .map_err(|source| NodeTraceLogError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    // Only create and stat the file here; full record-framing validation runs
    // once at `open` (and per tail read). Scanning the whole log on every append
    // through this helper made appends quadratic in the number of records.
    file.metadata()
        .map_err(|source| NodeTraceLogError::Metadata {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

/// Parses trace records from `start_offset` to end of file, returning the file
/// length at read time.
///
/// `start_offset` must be a record boundary (`0` or a length previously returned
/// by this function); the append-only format keeps earlier offsets valid.
fn scan_node_trace_log_entries_from(
    path: &Path,
    start_offset: u64,
    mut visit: impl FnMut(NodeTraceLogEntry),
) -> Result<u64, NodeTraceLogError> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| NodeTraceLogError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    let len = file
        .metadata()
        .map_err(|source| NodeTraceLogError::Metadata {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if start_offset >= len {
        return Ok(len);
    }
    file.seek(SeekFrom::Start(start_offset))
        .map_err(|source| NodeTraceLogError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let mut offset = start_offset;
    while offset < len {
        let remaining = len - offset;
        if remaining < NODE_TRACE_LOG_RECORD_HEADER_LEN as u64 {
            return Err(node_trace_log_format_error(
                path,
                NodeTraceLogFormatError::ShortRecordHeader {
                    expected: NODE_TRACE_LOG_RECORD_HEADER_LEN as u64,
                    actual: remaining,
                },
            ));
        }

        let mut header = [0; NODE_TRACE_LOG_RECORD_HEADER_LEN];
        file.read_exact(&mut header)
            .map_err(|source| NodeTraceLogError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        let key = NodeTraceLogKey::decode(&header[..NODE_TRACE_LOG_KEY_LEN])
            .map_err(|source| node_trace_log_format_error(path, source))?;
        let value_hash_start = NODE_TRACE_LOG_KEY_LEN;
        let value_hash_end = value_hash_start + NODE_TRACE_LOG_VALUE_HASH_LEN;
        let value_hash = NodeTraceLogValueHash::decode(&header[value_hash_start..value_hash_end])
            .map_err(|source| node_trace_log_format_error(path, source))?;
        let payload_len = read_u64(&header[value_hash_end..]);
        let payload_start = offset
            .checked_add(NODE_TRACE_LOG_RECORD_HEADER_LEN as u64)
            .ok_or_else(|| {
                node_trace_log_format_error(
                    path,
                    NodeTraceLogFormatError::RecordBoundsOverflow {
                        record_offset: offset,
                        payload_len,
                    },
                )
            })?;
        let payload_end = payload_start.checked_add(payload_len).ok_or_else(|| {
            node_trace_log_format_error(
                path,
                NodeTraceLogFormatError::RecordBoundsOverflow {
                    record_offset: offset,
                    payload_len,
                },
            )
        })?;
        if payload_end > len {
            return Err(node_trace_log_format_error(
                path,
                NodeTraceLogFormatError::ShortRecordPayload {
                    expected: payload_end,
                    actual: len,
                },
            ));
        }

        let payload_len_usize = usize::try_from(payload_len).map_err(|_| {
            node_trace_log_format_error(
                path,
                NodeTraceLogFormatError::PayloadLengthOverflow { len: payload_len },
            )
        })?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_len_usize).map_err(|_| {
            NodeTraceLogError::PayloadAllocationFailed {
                len: payload_len_usize,
            }
        })?;
        payload.resize(payload_len_usize, 0);
        file.read_exact(&mut payload)
            .map_err(|source| NodeTraceLogError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        visit(NodeTraceLogEntry::new(key, value_hash, payload));
        offset = payload_end;
    }
    Ok(len)
}

fn node_trace_log_format_error(path: &Path, source: NodeTraceLogFormatError) -> NodeTraceLogError {
    NodeTraceLogError::Format {
        path: path.to_path_buf(),
        source,
    }
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const EXPRESSION_NODE: u8 = 5;
    const IMPURE_INPUT_NODE: u8 = 6;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ratchet-cache-node-trace-log-{name}-{}-{nonce}.log",
            std::process::id()
        ))
    }

    fn trace_key(namespace_tag: u8, digest_byte: u8) -> NodeTraceLogKey {
        NodeTraceLogKey::new(namespace_tag, [digest_byte; 32])
    }

    fn value_hash(byte: u8) -> NodeTraceLogValueHash {
        NodeTraceLogValueHash::from_bytes([byte; NODE_TRACE_LOG_VALUE_HASH_LEN])
    }

    fn trace_entry(
        namespace_tag: u8,
        digest_byte: u8,
        value_hash_byte: u8,
        payload: &[u8],
    ) -> NodeTraceLogEntry {
        NodeTraceLogEntry::new(
            trace_key(namespace_tag, digest_byte),
            value_hash(value_hash_byte),
            payload.to_vec(),
        )
    }

    #[test]
    fn node_trace_log_entry_round_trips_stable_bytes() {
        let path = temp_path("stable");
        let log = NodeTraceLog::open(path.clone()).expect("log opens");
        let digest = [
            0xd5, 0xd5, 0x59, 0x5f, 0x1b, 0xc7, 0xdb, 0x47, 0xf6, 0x47, 0x2f, 0x20, 0x90, 0x38,
            0x6e, 0x3b, 0x01, 0x92, 0xdf, 0x19, 0x08, 0xa0, 0x72, 0x34, 0x04, 0xc1, 0xdc, 0x66,
            0xc3, 0x07, 0x71, 0xf7,
        ];
        let key = NodeTraceLogKey::new(EXPRESSION_NODE, digest);
        let hash = value_hash(7);
        let payload = b"payload-bytes".to_vec();
        let entry = NodeTraceLogEntry::new(key, hash, payload.clone());

        log.append_entry(entry.clone()).expect("entry appends");

        let bytes = fs::read(&path).expect("log bytes read");
        assert_eq!(
            bytes.len(),
            NODE_TRACE_LOG_RECORD_HEADER_LEN + payload.len()
        );
        assert_eq!(&bytes[..NODE_TRACE_LOG_KEY_LEN], key.encode().as_slice());
        assert_eq!(
            &bytes[NODE_TRACE_LOG_KEY_LEN..NODE_TRACE_LOG_KEY_LEN + NODE_TRACE_LOG_VALUE_HASH_LEN],
            hash.encode().as_slice()
        );
        assert_eq!(
            read_u64(&bytes[NODE_TRACE_LOG_KEY_LEN + NODE_TRACE_LOG_VALUE_HASH_LEN..]),
            payload.len() as u64
        );
        assert_eq!(
            &bytes[NODE_TRACE_LOG_RECORD_HEADER_LEN..],
            payload.as_slice()
        );
        assert_eq!(log.entries().expect("entries scan"), [entry]);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_trace_log_rejects_short_prefixes() {
        assert!(matches!(
            NodeTraceLogKey::decode(&[0; 8]),
            Err(NodeTraceLogFormatError::ShortKey { actual: 8, .. })
        ));
        assert!(matches!(
            NodeTraceLogValueHash::decode(&[0; 8]),
            Err(NodeTraceLogFormatError::ShortValueHash { actual: 8, .. })
        ));
    }

    #[test]
    fn node_trace_log_opens_and_creates_parent_directories() {
        let root = temp_path("open-root");
        let path = root.join("nodes").join("traces.log");
        let log = NodeTraceLog::open(path.clone()).expect("log opens");

        assert_eq!(log.path(), path.as_path());
        assert_eq!(fs::read(&path).expect("log reads"), b"");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn node_trace_log_appends_and_finds_newest_matching_entry() {
        let path = temp_path("lookup");
        let log = NodeTraceLog::open(path.clone()).expect("log opens");
        let key = trace_key(EXPRESSION_NODE, 1);
        let first = NodeTraceLogEntry::new(key, value_hash(1), b"first".to_vec());
        let second = NodeTraceLogEntry::new(key, value_hash(2), b"second".to_vec());
        let other = trace_entry(IMPURE_INPUT_NODE, 1, 3, b"other");

        log.append_entry(first).expect("first entry appends");
        log.append_entry(other).expect("other entry appends");
        log.append_entry(second.clone())
            .expect("second entry appends");

        assert_eq!(log.lookup(key).expect("lookup succeeds"), Some(second));
        assert_eq!(
            log.lookup(trace_key(EXPRESSION_NODE, 9))
                .expect("missing lookup succeeds"),
            None
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_trace_log_entries_preserve_physical_append_order() {
        let path = temp_path("entries");
        let log = NodeTraceLog::open(path.clone()).expect("log opens");
        let first = trace_entry(IMPURE_INPUT_NODE, 0xff, 1, b"first");
        let second = trace_entry(EXPRESSION_NODE, 0, 2, b"second");
        let third = trace_entry(IMPURE_INPUT_NODE, 0xff, 3, b"third");

        log.append_entry(first.clone())
            .expect("first entry appends");
        log.append_entry(second.clone())
            .expect("second entry appends");
        log.append_entry(third.clone())
            .expect("third entry appends");

        assert_eq!(
            log.entries().expect("physical entries scan"),
            [first, second, third]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_trace_log_latest_entries_are_newest_and_key_sorted() {
        let path = temp_path("latest");
        let log = NodeTraceLog::open(path.clone()).expect("log opens");
        let lower = trace_key(EXPRESSION_NODE, 0);
        let upper = trace_key(IMPURE_INPUT_NODE, 0xff);
        let stale_lower = NodeTraceLogEntry::new(lower, value_hash(1), b"stale".to_vec());
        let fresh_lower = NodeTraceLogEntry::new(lower, value_hash(2), b"fresh".to_vec());
        let upper_entry = NodeTraceLogEntry::new(upper, value_hash(3), b"upper".to_vec());

        log.append_entry(upper_entry.clone())
            .expect("upper entry appends");
        log.append_entry(stale_lower)
            .expect("stale lower entry appends");
        log.append_entry(fresh_lower.clone())
            .expect("fresh lower entry appends");

        assert_eq!(
            log.latest_entries().expect("latest entries scan"),
            [fresh_lower, upper_entry]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_trace_log_compacts_to_latest_entries() {
        let path = temp_path("compact");
        let log = NodeTraceLog::open(path.clone()).expect("log opens");
        let lower = trace_key(EXPRESSION_NODE, 0);
        let upper = trace_key(IMPURE_INPUT_NODE, 0xff);
        let stale_lower = NodeTraceLogEntry::new(lower, value_hash(1), b"stale".to_vec());
        let fresh_lower = NodeTraceLogEntry::new(lower, value_hash(2), b"fresh".to_vec());
        let upper_entry = NodeTraceLogEntry::new(upper, value_hash(3), b"upper".to_vec());

        log.append_entry(upper_entry.clone())
            .expect("upper entry appends");
        log.append_entry(stale_lower)
            .expect("stale lower entry appends");
        log.append_entry(fresh_lower.clone())
            .expect("fresh lower entry appends");

        assert!(fs::metadata(log.path()).expect("log metadata").len() > 0);
        assert_eq!(log.compact_latest_entries().expect("log compacts"), 2);
        assert_eq!(
            log.latest_entries().expect("latest entries scan"),
            [fresh_lower, upper_entry]
        );
        assert_eq!(log.entries().expect("physical entries scan").len(), 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_trace_log_replaces_entries_in_caller_order() {
        let path = temp_path("replace");
        let log = NodeTraceLog::open(path.clone()).expect("log opens");
        let first = trace_entry(IMPURE_INPUT_NODE, 0xff, 1, b"first");
        let second = trace_entry(EXPRESSION_NODE, 0, 2, b"second");

        log.append_entry(trace_entry(EXPRESSION_NODE, 7, 3, b"stale"))
            .expect("stale entry appends");

        assert_eq!(
            log.replace_entries(&[first.clone(), second.clone()])
                .expect("entries replace"),
            2
        );
        assert_eq!(
            log.entries().expect("physical entries scan"),
            [first, second]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_trace_log_rejects_truncated_record_header() {
        let path = temp_path("truncated-header");
        fs::write(&path, b"partial").expect("partial log writes");

        let error = NodeTraceLog::open(path.clone()).expect_err("truncated header errors");

        assert!(matches!(
            error,
            NodeTraceLogError::Format {
                source: NodeTraceLogFormatError::ShortRecordHeader { actual: 7, .. },
                ..
            }
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_trace_log_rejects_truncated_record_payload() {
        let path = temp_path("truncated-payload");
        let header =
            encode_node_trace_log_record_header(trace_key(EXPRESSION_NODE, 1), value_hash(2), 8);
        fs::write(&path, [header.as_slice(), b"abc"].concat()).expect("partial payload writes");

        let error = NodeTraceLog::open(path.clone()).expect_err("truncated payload errors");

        assert!(matches!(
            error,
            NodeTraceLogError::Format {
                source: NodeTraceLogFormatError::ShortRecordPayload { actual, .. },
                ..
            } if actual == (NODE_TRACE_LOG_RECORD_HEADER_LEN + 3) as u64
        ));

        let _ = fs::remove_file(path);
    }
}
