//! Demand-node verifying trace payload and append log format adapters.

use super::*;
use ratchet_cache::node_trace_log::{
    NODE_TRACE_LOG_KEY_LEN as ENGINE_NODE_TRACE_LOG_KEY_LEN,
    NODE_TRACE_LOG_RECORD_HEADER_LEN as ENGINE_NODE_TRACE_LOG_RECORD_HEADER_LEN,
    NodeTraceLog as EngineNodeTraceLog, NodeTraceLogEntry as EngineNodeTraceLogEntry,
    NodeTraceLogError as EngineNodeTraceLogError,
    NodeTraceLogFormatError as EngineNodeTraceLogFormatError,
    NodeTraceLogKey as EngineNodeTraceLogKey, NodeTraceLogValueHash as EngineNodeTraceLogValueHash,
};

/// A stable payload for one persisted node verifying trace.
///
/// Ordinary payloads preserve evaluator trace order and store only cacheable
/// impure-input fingerprints: each record carries the typed input identity
/// parts plus the observed-result hash. Tombstone payloads carry no inputs and
/// explicitly invalidate older trace records for the same node. The eventual
/// persistent demand-graph sidecar can attach ordinary payload bytes to an
/// expression node and replay the fingerprints during durable-hit revalidation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistNodeTracePayload {
    inputs: Vec<CacheableInputFingerprint>,
    tombstone: bool,
}

impl PersistNodeTracePayload {
    /// Creates a tombstone payload that invalidates older trace records for a node.
    pub fn tombstone() -> Self {
        Self {
            inputs: Vec::new(),
            tombstone: true,
        }
    }

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
        Ok(Self {
            inputs: stored,
            tombstone: false,
        })
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
        Ok(Self {
            inputs,
            tombstone: false,
        })
    }

    /// Returns whether this payload tombstones older traces for the same node.
    pub const fn is_tombstone(&self) -> bool {
        self.tombstone
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
        let count = if self.tombstone {
            PERSIST_NODE_TRACE_PAYLOAD_TOMBSTONE_COUNT
        } else {
            u64::try_from(self.inputs.len()).map_err(|_| {
                PersistNodeTracePayloadError::EncodedInputCountOverflow {
                    inputs: self.inputs.len(),
                }
            })?
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN)
            .map_err(|_| PersistNodeTracePayloadError::PayloadAllocationFailed {
                len: PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
            })?;
        bytes.extend_from_slice(&PERSIST_NODE_TRACE_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&PERSIST_NODE_TRACE_PAYLOAD_VERSION.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());

        if self.tombstone {
            return Ok(bytes);
        }

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
        if !(PERSIST_NODE_TRACE_PAYLOAD_MIN_VERSION..=PERSIST_NODE_TRACE_PAYLOAD_VERSION)
            .contains(&version)
        {
            return Err(PersistNodeTracePayloadError::UnsupportedVersion { version });
        }

        let count = read_u64(&bytes[20..28]);
        if count == PERSIST_NODE_TRACE_PAYLOAD_TOMBSTONE_COUNT {
            if version < 2 {
                return Err(PersistNodeTracePayloadError::InputCountOverflow { count });
            }
            if bytes.len() != PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN {
                return Err(PersistNodeTracePayloadError::TrailingBytes {
                    remaining: bytes.len() - PERSIST_NODE_TRACE_PAYLOAD_HEADER_LEN,
                });
            }
            return Ok(Self::tombstone());
        }
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
            let mode = node_trace_input_mode_from_tag(version, bytes[cursor + 1])?;
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

        Ok(Self {
            inputs,
            tombstone: false,
        })
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
        ImpureInputKind::HashFile => 7,
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
        7 => Ok(ImpureInputKind::HashFile),
        _ => Err(PersistNodeTracePayloadError::InvalidInputKindTag { tag }),
    }
}

fn node_trace_input_mode_tag(mode: ImpureInputMode) -> u8 {
    match mode {
        ImpureInputMode::Default => 1,
        ImpureInputMode::RequireDirectory => 2,
        ImpureInputMode::FindFileCandidate => 3,
    }
}

fn node_trace_input_mode_from_tag(
    version: u32,
    tag: u8,
) -> Result<ImpureInputMode, PersistNodeTracePayloadError> {
    match tag {
        1 => Ok(ImpureInputMode::Default),
        2 => Ok(ImpureInputMode::RequireDirectory),
        3 if version >= 3 => Ok(ImpureInputMode::FindFileCandidate),
        _ => Err(PersistNodeTracePayloadError::InvalidInputModeTag { tag }),
    }
}

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
}

impl PersistNodeTraceLog {
    /// Opens or initializes a node trace log file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if parent directories or the log
    /// file cannot be created/opened, or if an existing log contains malformed
    /// variable-length records.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PersistNodeTraceLogError> {
        let engine = EngineNodeTraceLog::open(path.into()).map_err(engine_node_trace_log_error)?;
        let log = Self { engine };
        log.entries()?;
        Ok(log)
    }

    /// Returns this log file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
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
        self.entries()?;
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

    /// Looks up the newest trace record recorded for `key`.
    ///
    /// Missing trace records return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the log cannot be opened, read,
    /// or decoded.
    pub fn lookup(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        let mut found = None;
        for entry in self.entries()? {
            if entry.key() == key {
                found = Some(entry);
            }
        }
        Ok(found)
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
    /// or decoded.
    pub fn latest_entries(
        &self,
    ) -> Result<Vec<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        let mut latest = std::collections::BTreeMap::new();
        for entry in self.entries()? {
            latest.insert(entry.key(), entry);
        }
        Ok(latest.into_values().collect())
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

    #[cfg(test)]
    pub(crate) fn compact_latest_entries_with_rewrite_id_for_tests(
        &self,
        rewrite_id: u64,
    ) -> Result<usize, PersistNodeTraceLogError> {
        let entries = self.latest_entries()?;
        self.replace_entries_with_rewrite_id(&entries, rewrite_id)
    }

    fn entries(&self) -> Result<Vec<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        self.engine
            .entries()
            .map_err(engine_node_trace_log_error)?
            .into_iter()
            .map(|entry| engine_node_trace_entry_to_persist(self.path(), entry))
            .collect()
    }

    fn replace_entries(
        &self,
        entries: &[PersistNodeTraceLogEntry],
    ) -> Result<usize, PersistNodeTraceLogError> {
        let engine_entries = entries
            .iter()
            .map(persist_node_trace_entry_to_engine)
            .collect::<Result<Vec<_>, _>>()?;
        self.engine
            .replace_entries(&engine_entries)
            .map_err(engine_node_trace_log_error)
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
