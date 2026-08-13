//! Append-only log adapter for persisted demand-node verifying traces.
//!
//! Owns [`PersistNodeTraceLogEntry`] and [`PersistNodeTraceLog`], which wrap the
//! language-agnostic `ratchet_cache` trace-log engine and translate its records
//! to and from the persist-layer key, value hash, and
//! [`PersistNodeTracePayload`] types.

use super::super::*;
use super::payload::PersistNodeTracePayload;
use ratchet_cache::node_trace_log::{
    NODE_TRACE_LOG_KEY_LEN as ENGINE_NODE_TRACE_LOG_KEY_LEN,
    NODE_TRACE_LOG_RECORD_HEADER_LEN as ENGINE_NODE_TRACE_LOG_RECORD_HEADER_LEN,
    NodeTraceLog as EngineNodeTraceLog, NodeTraceLogEntry as EngineNodeTraceLogEntry,
    NodeTraceLogError as EngineNodeTraceLogError,
    NodeTraceLogFormatError as EngineNodeTraceLogFormatError,
    NodeTraceLogKey as EngineNodeTraceLogKey, NodeTraceLogValueHash as EngineNodeTraceLogValueHash,
};
use ratchet_cache::sidecar_index::{LatestIndex, SidecarStatsSnapshot};

/// A complete key/value-hash/payload record in the node trace log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistNodeTraceLogEntry {
    key: PersistNodeMetadataKey,
    value_hash: ValueHash,
    payload: PersistNodeTracePayload,
}

impl PersistNodeTraceLogEntry {
    /// Creates a node trace log entry.
    pub fn new(
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
        payload: PersistNodeTracePayload,
    ) -> Self {
        Self {
            key,
            value_hash,
            payload,
        }
    }

    /// Returns the node metadata key this trace belongs to.
    pub const fn key(&self) -> PersistNodeMetadataKey {
        self.key
    }

    /// Returns the materialized value hash this trace verifies.
    ///
    /// Tombstone entries carry a synthetic hash because they invalidate older
    /// trace records rather than verifying a materialized value.
    pub const fn value_hash(&self) -> ValueHash {
        self.value_hash
    }

    /// Returns the persisted node trace payload.
    pub const fn payload(&self) -> &PersistNodeTracePayload {
        &self.payload
    }

    /// Consumes the entry and returns its persisted node trace payload.
    pub fn into_payload(self) -> PersistNodeTracePayload {
        self.payload
    }
}

/// An append-only log for persisted node verifying traces.
///
/// This is a simple durable substrate for the future `nodes/` table. Each
/// ordinary record stores a [`PersistNodeMetadataKey`], the materialized
/// [`ValueHash`] the trace verifies, and a variable-length
/// [`PersistNodeTracePayload`]. Tombstone records use the same envelope with a
/// synthetic hash and a tombstone payload. Lookups scan linearly and return the
/// newest matching trace record for the requested node key.
#[derive(Clone, Debug)]
pub struct PersistNodeTraceLog {
    engine: EngineNodeTraceLog,
    index: LatestIndex<PersistNodeMetadataKey, PersistNodeTraceLogEntry>,
}

impl PersistNodeTraceLog {
    /// Opens or initializes a node trace log file at `path`.
    ///
    /// The whole log is decoded and validated once into an in-memory index; a
    /// record whose payload cannot be decoded fails the open.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if parent directories or the log
    /// file cannot be created/opened, or if an existing log contains malformed
    /// variable-length records or an undecodable trace payload.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistNodeTraceLogError> {
        let engine = EngineNodeTraceLog::open(path.into()).map_err(engine_node_trace_log_error)?;
        let log = Self {
            engine,
            index: LatestIndex::new(),
        };
        // Eagerly load and payload-validate the whole log at open, matching the
        // historical open-time contract that a malformed trace payload is
        // rejected before the log is used.
        log.refresh()?;
        Ok(log)
    }

    /// Returns this log file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Returns a snapshot of the lookup and records-scanned counters.
    pub fn stats(&self) -> SidecarStatsSnapshot {
        self.index.stats().snapshot()
    }

    /// Appends one node trace entry.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened,
    /// validated, written, or flushed, or if the payload cannot be encoded.
    pub fn append_entry(
        &self,
        entry: PersistNodeTraceLogEntry,
    ) -> Result<(), PersistNodeTraceLogError> {
        self.append_trace(entry.key, entry.value_hash, &entry.payload)
    }

    /// Appends one node trace payload for `key` and `value_hash`.
    ///
    /// The record is written to the append-only log; the next read folds it into
    /// the in-memory index through the tail reload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened,
    /// validated, written, or flushed, or if the payload cannot be encoded.
    pub fn append_trace(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
        payload: &PersistNodeTracePayload,
    ) -> Result<(), PersistNodeTraceLogError> {
        let payload_bytes = payload
            .encode()
            .map_err(|source| PersistNodeTraceLogError::Encode { source })?;
        self.engine
            .append_entry(EngineNodeTraceLogEntry::new(
                persist_node_trace_key_to_engine(key),
                persist_node_trace_value_hash_to_engine(value_hash),
                payload_bytes,
            ))
            .map_err(engine_node_trace_log_error)
    }

    /// Refreshes the in-memory index from the log, decoding only new records.
    ///
    /// A record whose payload cannot be decoded surfaces here, so both `open`
    /// and lookups on a corrupt log return a payload format error.
    fn refresh(&self) -> Result<(), PersistNodeTraceLogError> {
        let len = self.engine.len().map_err(engine_node_trace_log_error)?;
        let path = self.path().to_path_buf();
        self.index.refresh_with(len, |from| {
            let (entries, end) = self
                .engine
                .read_entries_from(from)
                .map_err(engine_node_trace_log_error)?;
            let mut pairs = Vec::with_capacity(entries.len());
            for entry in entries {
                let entry = engine_node_trace_entry_to_persist(&path, entry)?;
                pairs.push((entry.key(), entry));
            }
            Ok((pairs, end))
        })
    }

    /// Looks up the newest trace record recorded for `key`.
    ///
    /// Missing trace records return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened, read,
    /// or decoded during the refresh.
    pub fn lookup(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        self.refresh()?;
        Ok(self.index.get(&key))
    }

    /// Returns the newest trace log entry for every node metadata key.
    ///
    /// Entries are returned in stable key order. If a key appears multiple
    /// times in the append-only log, only its newest trace entry is returned.
    /// Tombstones are entries and are preserved when they are newest for a key.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened, read,
    /// or decoded during the refresh.
    pub fn latest_entries(
        &self,
    ) -> Result<Vec<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        self.refresh()?;
        Ok(self.index.latest_values())
    }

    /// Rewrites the log to the newest trace entry for every node metadata key.
    ///
    /// Entries are written in stable key order through a temporary file that is
    /// renamed over the original log. The returned count is the number of
    /// latest entries preserved after compaction. Tombstones are preserved when
    /// they are the newest entry for a key. Callers must exclude all concurrent
    /// log writers across threads and processes while this method runs; an
    /// append that races between the snapshot and rename can be lost.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened, read,
    /// decoded, written, flushed, or renamed into place.
    pub fn compact_latest_entries(&self) -> Result<usize, PersistNodeTraceLogError> {
        let entries = self.latest_entries()?;
        self.replace_entries(&entries)
    }

    /// Compacts the log only if it has bloated past `factor` times live keys.
    ///
    /// Returns the retained entry count when a compaction ran, or `None`
    /// otherwise. Concurrency requirements match [`Self::compact_latest_entries`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if a triggered compaction cannot be
    /// opened, read, decoded, written, flushed, or renamed into place.
    pub fn compact_if_bloated(
        &self,
        factor: u64,
    ) -> Result<Option<usize>, PersistNodeTraceLogError> {
        self.refresh()?;
        if self.index.is_bloated(factor) {
            Ok(Some(self.compact_latest_entries()?))
        } else {
            Ok(None)
        }
    }

    #[cfg(test)]
    pub(crate) fn compact_latest_entries_with_rewrite_id_for_tests(
        &self,
        rewrite_id: u64,
    ) -> Result<usize, PersistNodeTraceLogError> {
        let entries = self.latest_entries()?;
        self.replace_entries_with_rewrite_id(&entries, rewrite_id)
    }

    fn replace_entries(
        &self,
        entries: &[PersistNodeTraceLogEntry],
    ) -> Result<usize, PersistNodeTraceLogError> {
        let engine_entries = entries
            .iter()
            .map(persist_node_trace_entry_to_engine)
            .collect::<Result<Vec<_>, _>>()?;
        let count = self
            .engine
            .replace_entries(&engine_entries)
            .map_err(engine_node_trace_log_error)?;
        self.index.mark_stale();
        Ok(count)
    }

    #[cfg(test)]
    fn replace_entries_with_rewrite_id(
        &self,
        entries: &[PersistNodeTraceLogEntry],
        rewrite_id: u64,
    ) -> Result<usize, PersistNodeTraceLogError> {
        let tmp_path = self
            .path()
            .with_extension(format!("compact-{}-{rewrite_id}.tmp", std::process::id()));
        {
            let _ = fs::remove_file(&tmp_path);
            let tmp_log =
                EngineNodeTraceLog::open(tmp_path.clone()).map_err(engine_node_trace_log_error)?;
            for entry in entries {
                tmp_log
                    .append_entry(persist_node_trace_entry_to_engine(entry)?)
                    .map_err(engine_node_trace_log_error)?;
            }
        }
        fs::rename(&tmp_path, self.path()).map_err(|source| {
            let _ = fs::remove_file(&tmp_path);
            PersistNodeTraceLogError::Write {
                path: self.path().to_path_buf(),
                source,
            }
        })?;
        self.index.mark_stale();
        Ok(entries.len())
    }
}

fn persist_node_trace_key_to_engine(key: PersistNodeMetadataKey) -> EngineNodeTraceLogKey {
    let encoded = key.index_bytes();
    let mut digest = [0; 32];
    digest.copy_from_slice(&encoded[1..]);
    EngineNodeTraceLogKey::new(encoded[0], digest)
}

fn engine_node_trace_key_to_persist(
    key: EngineNodeTraceLogKey,
) -> Result<PersistNodeMetadataKey, PersistPackFormatError> {
    PersistNodeMetadataKey::decode_index_bytes(&key.encode())
}

fn persist_node_trace_value_hash_to_engine(value_hash: ValueHash) -> EngineNodeTraceLogValueHash {
    EngineNodeTraceLogValueHash::from_bytes(value_hash.as_durable_hash().as_bytes())
}

fn engine_node_trace_value_hash_to_persist(value_hash: EngineNodeTraceLogValueHash) -> ValueHash {
    ValueHash::from_canonical_value_hash(DurableBlake3Hash::from_bytes(value_hash.bytes()))
}

fn persist_node_trace_entry_to_engine(
    entry: &PersistNodeTraceLogEntry,
) -> Result<EngineNodeTraceLogEntry, PersistNodeTraceLogError> {
    let payload = entry
        .payload()
        .encode()
        .map_err(|source| PersistNodeTraceLogError::Encode { source })?;
    Ok(EngineNodeTraceLogEntry::new(
        persist_node_trace_key_to_engine(entry.key()),
        persist_node_trace_value_hash_to_engine(entry.value_hash()),
        payload,
    ))
}

fn engine_node_trace_entry_to_persist(
    path: &Path,
    entry: EngineNodeTraceLogEntry,
) -> Result<PersistNodeTraceLogEntry, PersistNodeTraceLogError> {
    let key = engine_node_trace_key_to_persist(entry.key()).map_err(|source| {
        node_trace_log_format_error(path, PersistNodeTraceLogFormatError::Key { source })
    })?;
    let value_hash = engine_node_trace_value_hash_to_persist(entry.value_hash());
    let payload = PersistNodeTracePayload::decode(entry.payload()).map_err(|source| {
        node_trace_log_format_error(path, PersistNodeTraceLogFormatError::Payload { source })
    })?;
    Ok(PersistNodeTraceLogEntry::new(key, value_hash, payload))
}

fn engine_node_trace_log_error(error: EngineNodeTraceLogError) -> PersistNodeTraceLogError {
    match error {
        EngineNodeTraceLogError::CreateParent { path, source } => {
            PersistNodeTraceLogError::CreateParent { path, source }
        }
        EngineNodeTraceLogError::Open { path, source } => {
            PersistNodeTraceLogError::Open { path, source }
        }
        EngineNodeTraceLogError::Metadata { path, source } => {
            PersistNodeTraceLogError::Metadata { path, source }
        }
        EngineNodeTraceLogError::Read { path, source } => {
            PersistNodeTraceLogError::Read { path, source }
        }
        EngineNodeTraceLogError::Write { path, source } => {
            PersistNodeTraceLogError::Write { path, source }
        }
        EngineNodeTraceLogError::PayloadTooLarge { len } => {
            PersistNodeTraceLogError::PayloadTooLarge { len }
        }
        EngineNodeTraceLogError::RecordAllocationFailed { len } => {
            PersistNodeTraceLogError::RecordAllocationFailed { len }
        }
        EngineNodeTraceLogError::PayloadAllocationFailed { len } => {
            PersistNodeTraceLogError::PayloadAllocationFailed { len }
        }
        EngineNodeTraceLogError::Format { path, source } => PersistNodeTraceLogError::Format {
            path,
            source: engine_node_trace_log_format_error(source),
        },
    }
}

fn engine_node_trace_log_format_error(
    error: EngineNodeTraceLogFormatError,
) -> PersistNodeTraceLogFormatError {
    match error {
        EngineNodeTraceLogFormatError::ShortKey { expected, actual } => {
            PersistNodeTraceLogFormatError::Key {
                source: PersistPackFormatError::ShortNodeMetadataIndexKey { expected, actual },
            }
        }
        EngineNodeTraceLogFormatError::ShortValueHash { actual, .. } => {
            PersistNodeTraceLogFormatError::ShortRecordHeader {
                expected: ENGINE_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64,
                actual: (ENGINE_NODE_TRACE_LOG_KEY_LEN + actual) as u64,
            }
        }
        EngineNodeTraceLogFormatError::ShortRecordHeader { expected, actual } => {
            PersistNodeTraceLogFormatError::ShortRecordHeader { expected, actual }
        }
        EngineNodeTraceLogFormatError::PayloadLengthOverflow { len } => {
            PersistNodeTraceLogFormatError::PayloadLengthOverflow { len }
        }
        EngineNodeTraceLogFormatError::RecordBoundsOverflow {
            record_offset,
            payload_len,
        } => PersistNodeTraceLogFormatError::RecordBoundsOverflow {
            record_offset,
            payload_len,
        },
        EngineNodeTraceLogFormatError::ShortRecordPayload { expected, actual } => {
            PersistNodeTraceLogFormatError::ShortRecordPayload { expected, actual }
        }
    }
}

fn node_trace_log_format_error(
    path: &Path,
    source: PersistNodeTraceLogFormatError,
) -> PersistNodeTraceLogError {
    PersistNodeTraceLogError::Format {
        path: path.to_path_buf(),
        source,
    }
}
