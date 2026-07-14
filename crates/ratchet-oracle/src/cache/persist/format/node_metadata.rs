//! Demand-node metadata key, value, entry, and index format adapters.

use crate::cache::hashing::CacheDigestHasher;
use super::*;
use crate::cache::hashing::PersistNodeMetadataKeyHash;
use ratchet_cache::node_metadata::{
    NodeMetadataEntry as EngineNodeMetadataEntry,
    NodeMetadataFormatError as EngineNodeMetadataFormatError,
    NodeMetadataIndex as EngineNodeMetadataIndex,
    NodeMetadataIndexError as EngineNodeMetadataIndexError,
    NodeMetadataKey as EngineNodeMetadataKey, NodeMetadataValue as EngineNodeMetadataValue,
};
use ratchet_cache::sidecar_index::{LatestIndex, SidecarStatsSnapshot};

/// A stable index key for durable demand-node metadata.
///
/// This key lives in a persistent BLAKE3 domain separate from the hot
/// in-process `DemandCacheKey` domain. It can address expression nodes keyed
/// by expression identity plus ordered free-variable value hashes, or impure
/// input leaves keyed by their typed input identity hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersistNodeMetadataKey {
    hash: PersistNodeMetadataKeyHash,
}

impl PersistNodeMetadataKey {
    /// Creates a persistent metadata key for an expression demand node.
    ///
    /// `free_var_value_hashes` must be supplied in the same canonical slot
    /// order used for the in-process demand-cache key.
    pub fn for_expression<I>(identity: CacheExprIdentity, free_var_value_hashes: I) -> Self
    where
        I: IntoIterator<Item = ValueHash>,
    {
        let mut hasher = CacheDigestHasher::new();
        hasher.update(PERSIST_NODE_METADATA_EXPRESSION_KEY_PERSONALIZATION);
        hasher.update(&identity.source_hash().as_durable_hash().as_bytes());
        hasher.update(&identity.node().as_u32().to_le_bytes());
        for value_hash in free_var_value_hashes {
            update_persist_index_chunk(&mut hasher, &value_hash.as_durable_hash().as_bytes());
        }
        Self {
            hash: PersistNodeMetadataKeyHash::from_hasher(hasher),
        }
    }

    /// Creates a persistent metadata key for an impure-input leaf node.
    pub fn for_impure_input(identity_hash: ImpureInputIdentityHash) -> Self {
        let identity_hash = identity_hash.as_durable_hash();
        let mut hasher = CacheDigestHasher::new();
        hasher.update(PERSIST_NODE_METADATA_IMPURE_INPUT_KEY_PERSONALIZATION);
        hasher.update(&identity_hash.as_bytes());
        Self {
            hash: PersistNodeMetadataKeyHash::from_hasher(hasher),
        }
    }

    /// Returns the durable hash for sidecar/engine adapters and inspection callers.
    pub const fn hash(self) -> DurableBlake3Hash {
        self.hash.as_durable_hash()
    }

    /// Returns the stable binary key for the future demand-node metadata index.
    pub fn index_bytes(self) -> [u8; PERSIST_NODE_METADATA_INDEX_KEY_LEN] {
        let mut bytes = [0; PERSIST_NODE_METADATA_INDEX_KEY_LEN];
        bytes[0] = PERSIST_NODE_METADATA_INDEX_TAG;
        bytes[1..].copy_from_slice(&self.hash.as_durable_hash().as_bytes());
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
            hash: PersistNodeMetadataKeyHash::from_persisted_hash(DurableBlake3Hash::from_bytes(
                hash,
            )),
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
        let encoded = persist_node_metadata_entry_to_engine(self).encode();
        let mut bytes = [0; PERSIST_NODE_METADATA_INDEX_ENTRY_LEN];
        bytes.copy_from_slice(&encoded);
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
        let entry =
            EngineNodeMetadataEntry::decode(bytes).map_err(engine_node_metadata_format_error)?;
        engine_node_metadata_entry_to_persist(entry)
    }
}

fn persist_node_metadata_key_to_engine(key: PersistNodeMetadataKey) -> EngineNodeMetadataKey {
    EngineNodeMetadataKey::new(PERSIST_NODE_METADATA_INDEX_TAG, key.hash().as_bytes())
}

fn engine_node_metadata_key_to_persist(
    key: EngineNodeMetadataKey,
) -> Result<PersistNodeMetadataKey, PersistPackFormatError> {
    PersistNodeMetadataKey::decode_index_bytes(&key.encode())
}

fn persist_node_metadata_value_to_engine(
    value: PersistNodeMetadataIndexValue,
) -> EngineNodeMetadataValue {
    EngineNodeMetadataValue::from_bytes(value.encode_index_value())
}

fn engine_node_metadata_value_to_persist(
    value: EngineNodeMetadataValue,
) -> Result<PersistNodeMetadataIndexValue, PersistPackFormatError> {
    PersistNodeMetadataIndexValue::decode_index_value(&value.encode())
}

fn persist_node_metadata_entry_to_engine(
    entry: PersistNodeMetadataIndexEntry,
) -> EngineNodeMetadataEntry {
    EngineNodeMetadataEntry::new(
        persist_node_metadata_key_to_engine(entry.key()),
        persist_node_metadata_value_to_engine(entry.value()),
    )
}

fn engine_node_metadata_entry_to_persist(
    entry: EngineNodeMetadataEntry,
) -> Result<PersistNodeMetadataIndexEntry, PersistPackFormatError> {
    Ok(PersistNodeMetadataIndexEntry::new(
        engine_node_metadata_key_to_persist(entry.key())?,
        engine_node_metadata_value_to_persist(entry.value())?,
    ))
}

fn engine_node_metadata_index_error(
    error: EngineNodeMetadataIndexError,
) -> PersistNodeMetadataIndexError {
    match error {
        EngineNodeMetadataIndexError::CreateParent { path, source } => {
            PersistNodeMetadataIndexError::CreateParent { path, source }
        }
        EngineNodeMetadataIndexError::Open { path, source } => {
            PersistNodeMetadataIndexError::Open { path, source }
        }
        EngineNodeMetadataIndexError::Metadata { path, source } => {
            PersistNodeMetadataIndexError::Metadata { path, source }
        }
        EngineNodeMetadataIndexError::Read { path, source } => {
            PersistNodeMetadataIndexError::Read { path, source }
        }
        EngineNodeMetadataIndexError::Write { path, source } => {
            PersistNodeMetadataIndexError::Write { path, source }
        }
        EngineNodeMetadataIndexError::Format { path, source } => {
            PersistNodeMetadataIndexError::Format {
                path,
                source: engine_node_metadata_format_error(source),
            }
        }
    }
}

fn engine_node_metadata_format_error(
    error: EngineNodeMetadataFormatError,
) -> PersistPackFormatError {
    match error {
        EngineNodeMetadataFormatError::ShortKey { expected, actual } => {
            PersistPackFormatError::ShortNodeMetadataIndexKey { expected, actual }
        }
        EngineNodeMetadataFormatError::ShortValue { expected, actual } => {
            PersistPackFormatError::ShortNodeMetadataIndexValue { expected, actual }
        }
        EngineNodeMetadataFormatError::ShortEntry { expected, actual } => {
            PersistPackFormatError::ShortNodeMetadataIndexEntry { expected, actual }
        }
    }
}

/// A fixed-record index file for durable demand-node metadata.
///
/// The newest value per key is held in a shared in-memory
/// [`LatestIndex`](ratchet_cache::sidecar_index::LatestIndex). Before each read
/// the wrapper refreshes it from the file, decoding only the newly appended
/// tail, so lookups are map probes that still observe writes made through other
/// handles or processes. The on-disk append-only file remains the source of
/// truth; a rewrite (compaction) marks the map stale so the next read reloads.
#[derive(Clone, Debug)]
pub struct PersistNodeMetadataIndex {
    engine: EngineNodeMetadataIndex,
    index: LatestIndex<PersistNodeMetadataKey, PersistNodeMetadataIndexValue>,
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
        let engine =
            EngineNodeMetadataIndex::open(path.into()).map_err(engine_node_metadata_index_error)?;
        Ok(Self {
            engine,
            index: LatestIndex::new(),
        })
    }

    /// Returns this index file's filesystem path.
    pub fn path(&self) -> &Path {
        self.engine.path()
    }

    /// Returns a snapshot of the lookup and records-scanned counters.
    pub fn stats(&self) -> SidecarStatsSnapshot {
        self.index.stats().snapshot()
    }

    /// Appends one node metadata index entry.
    ///
    /// The record is written to the append-only file; the next read folds it
    /// into the in-memory index through the tail reload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the index cannot be opened,
    /// validated, written, or flushed.
    pub fn append_entry(
        &self,
        entry: PersistNodeMetadataIndexEntry,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        self.engine
            .append_entry(persist_node_metadata_entry_to_engine(entry))
            .map_err(engine_node_metadata_index_error)
    }

    /// Refreshes the in-memory index from the file, decoding only new records.
    ///
    /// Malformed records surface here as the tail reload decodes them, which is
    /// why lookups on a corrupt sidecar return a format error.
    fn refresh(&self) -> Result<(), PersistNodeMetadataIndexError> {
        let len = self
            .engine
            .len()
            .map_err(engine_node_metadata_index_error)?;
        let path = self.path().to_path_buf();
        self.index.refresh_with(len, |from| {
            let (entries, end) = self
                .engine
                .read_entries_from(from)
                .map_err(engine_node_metadata_index_error)?;
            let mut pairs = Vec::with_capacity(entries.len());
            for entry in entries {
                let entry = engine_node_metadata_entry_to_persist(entry).map_err(|source| {
                    PersistNodeMetadataIndexError::Format {
                        path: path.clone(),
                        source,
                    }
                })?;
                pairs.push((entry.key(), entry.value()));
            }
            Ok((pairs, end))
        })
    }

    /// Looks up the newest node metadata value for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the index cannot be opened,
    /// read, or decoded during the refresh.
    pub fn lookup(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeMetadataIndexValue>, PersistNodeMetadataIndexError> {
        self.refresh()?;
        Ok(self.index.get(&key))
    }

    /// Returns the newest entry for every node metadata key.
    ///
    /// Entries are returned in stable key order. If a key appears multiple
    /// times in the append-only sidecar, only its newest value is returned.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the index cannot be opened,
    /// read, or decoded during the refresh.
    pub fn latest_entries(
        &self,
    ) -> Result<Vec<PersistNodeMetadataIndexEntry>, PersistNodeMetadataIndexError> {
        self.refresh()?;
        Ok(self
            .index
            .latest_pairs()
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
        self.refresh()?;
        let entries = self
            .index
            .latest_pairs()
            .into_iter()
            .map(|(key, value)| {
                persist_node_metadata_entry_to_engine(PersistNodeMetadataIndexEntry::new(
                    key, value,
                ))
            })
            .collect::<Vec<_>>();
        let count = self
            .engine
            .replace_entries(&entries)
            .map_err(engine_node_metadata_index_error)?;
        self.index.mark_stale();
        Ok(count)
    }

    /// Compacts the sidecar only if it has bloated past `factor` times live keys.
    ///
    /// Returns the retained entry count when a compaction ran, or `None`
    /// otherwise. Concurrency requirements match [`Self::compact_latest_entries`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if a triggered compaction
    /// cannot be opened, read, decoded, written, flushed, or renamed into place.
    pub fn compact_if_bloated(
        &self,
        factor: u64,
    ) -> Result<Option<usize>, PersistNodeMetadataIndexError> {
        self.refresh()?;
        if self.index.is_bloated(factor) {
            Ok(Some(self.compact_latest_entries()?))
        } else {
            Ok(None)
        }
    }
}
