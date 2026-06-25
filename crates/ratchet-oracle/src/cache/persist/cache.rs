//! The opened persistent eval-cache root and its store operations.
//!
//! [`PersistCache`] ties together the per-store packfiles and indexes, routing
//! blob and file-artifact reads, writes, materialization decisions, and parse
//! artifact hydration through the on-disk layout.

use super::*;

/// An opened persistent eval-cache root.
#[derive(Clone, Debug)]
pub struct PersistCache {
    layout: PersistLayout,
    value_pack: PersistBlobPack,
    file_pack: PersistBlobPack,
    value_index: PersistBlobIndex,
    file_index: PersistBlobIndex,
    file_artifact_index: PersistFileArtifactIndex,
    parse_artifact_index: PersistParseArtifactIndex,
    node_metadata_index: PersistNodeMetadataIndex,
    node_trace_log: PersistNodeTraceLog,
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
    /// written, if cache directories cannot be created or discarded, or if
    /// packfiles or sidecar indexes cannot be initialized.
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
        let parse_artifact_index_path = layout.parse_artifact_index_path();
        let parse_artifact_index = PersistParseArtifactIndex::open(
            parse_artifact_index_path.clone(),
        )
        .map_err(|source| PersistError::OpenParseArtifactIndex {
            path: parse_artifact_index_path,
            source,
        })?;
        let node_metadata_index_path = layout.node_metadata_index_path();
        let node_metadata_index = PersistNodeMetadataIndex::open(node_metadata_index_path.clone())
            .map_err(|source| PersistError::OpenNodeMetadataIndex {
                path: node_metadata_index_path,
                source,
            })?;
        let node_trace_log_path = layout.node_trace_log_path();
        let node_trace_log =
            PersistNodeTraceLog::open(node_trace_log_path.clone()).map_err(|source| {
                PersistError::OpenNodeTraceLog {
                    path: node_trace_log_path,
                    source,
                }
            })?;
        Ok(Self {
            layout,
            value_pack,
            file_pack,
            value_index,
            file_index,
            file_artifact_index,
            parse_artifact_index,
            node_metadata_index,
            node_trace_log,
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

    /// Returns the fixed-record index for durable parse-artifact mappings.
    pub const fn parse_artifact_index(&self) -> &PersistParseArtifactIndex {
        &self.parse_artifact_index
    }

    /// Returns the fixed-record index for durable demand-node metadata.
    pub const fn node_metadata_index(&self) -> &PersistNodeMetadataIndex {
        &self.node_metadata_index
    }

    /// Returns the append-only log for durable demand-node traces.
    pub const fn node_trace_log(&self) -> &PersistNodeTraceLog {
        &self.node_trace_log
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

    /// Appends a durable parse-artifact mapping entry to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the sidecar index cannot
    /// be opened, validated, written, or flushed.
    pub fn record_parse_artifact(
        &self,
        entry: PersistParseArtifactIndexEntry,
    ) -> Result<(), PersistParseArtifactIndexError> {
        self.parse_artifact_index.append_entry(entry)
    }

    /// Looks up a durable parse-artifact mapping through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn lookup_parse_artifact(
        &self,
        key: PersistParseArtifactKey,
    ) -> Result<Option<PersistParseArtifactIndexValue>, PersistParseArtifactIndexError> {
        self.parse_artifact_index.lookup(key)
    }

    /// Appends durable demand-node metadata to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, validated, written, or flushed.
    pub fn record_node_metadata(
        &self,
        entry: PersistNodeMetadataIndexEntry,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        self.node_metadata_index.append_entry(entry)
    }

    /// Looks up durable demand-node metadata through the sidecar index.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn lookup_node_metadata(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeMetadataIndexValue>, PersistNodeMetadataIndexError> {
        self.node_metadata_index.lookup(key)
    }

    /// Appends a durable verifying-trace payload for one materialized demand node.
    ///
    /// The trace log is append-only and newest-record-wins on lookup. This
    /// fixed-file sidecar has no cross-process write lock; callers must
    /// serialize concurrent writes to the same log. The caller supplies the
    /// materialized value hash so future hit selection can reject stale
    /// trace/value pairings.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the trace log cannot be opened,
    /// validated, written, flushed, or decoded during validation.
    pub fn record_node_trace(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
        payload: &PersistNodeTracePayload,
    ) -> Result<(), PersistNodeTraceLogError> {
        self.node_trace_log.append_trace(key, value_hash, payload)
    }

    /// Looks up the newest durable verifying-trace record for one demand node.
    ///
    /// Missing trace records return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the trace log cannot be opened,
    /// read, or decoded.
    pub fn lookup_node_trace(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        self.node_trace_log.lookup(key)
    }

    /// Appends materialization reuse counters for one demand node.
    ///
    /// Existing materialized value-hash metadata for the same node is
    /// preserved in the appended record. Missing metadata starts from an empty
    /// value-hash link.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, validated, written, or flushed.
    pub fn record_node_materialization_reuse(
        &self,
        key: PersistNodeMetadataKey,
        reuse: MaterializationReuse,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        let value = self
            .lookup_node_metadata(key)?
            .unwrap_or_else(|| PersistNodeMetadataIndexValue::new(MaterializationReuse::default()))
            .with_materialization_reuse(reuse);
        self.record_node_metadata(PersistNodeMetadataIndexEntry::new(key, value))
    }

    /// Looks up materialization reuse counters for one demand node.
    ///
    /// Missing index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn lookup_node_materialization_reuse(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<MaterializationReuse>, PersistNodeMetadataIndexError> {
        Ok(self
            .lookup_node_metadata(key)?
            .map(PersistNodeMetadataIndexValue::materialization_reuse))
    }

    /// Records the newest materialized value hash for one demand node.
    ///
    /// Existing materialization reuse counters for the same node are preserved
    /// in the appended metadata record. Missing metadata starts from empty
    /// reuse counters.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, decoded, written, or flushed.
    pub fn record_node_materialized_value_hash(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        let value = self
            .lookup_node_metadata(key)?
            .unwrap_or_else(|| PersistNodeMetadataIndexValue::new(MaterializationReuse::default()))
            .with_value_hash(value_hash);
        self.record_node_metadata(PersistNodeMetadataIndexEntry::new(key, value))
    }

    /// Clears the newest materialized value hash for one demand node.
    ///
    /// Existing materialization reuse counters for the same node are preserved
    /// in the appended metadata record. Missing metadata or metadata that
    /// already has no materialized value hash returns `Ok(false)` without
    /// appending a record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, decoded, written, or flushed.
    pub fn clear_node_materialized_value_hash(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<bool, PersistNodeMetadataIndexError> {
        let Some(value) = self.lookup_node_metadata(key)? else {
            return Ok(false);
        };
        if value.materialized_value_hash().is_none() {
            return Ok(false);
        }
        let value = PersistNodeMetadataIndexValue::new(value.materialization_reuse());
        self.record_node_metadata(PersistNodeMetadataIndexEntry::new(key, value))?;
        Ok(true)
    }

    /// Looks up the newest materialized value hash for one demand node.
    ///
    /// Missing node metadata and metadata without a materialized value hash
    /// both return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn lookup_node_materialized_value_hash(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<ValueHash>, PersistNodeMetadataIndexError> {
        Ok(self
            .lookup_node_metadata(key)?
            .and_then(PersistNodeMetadataIndexValue::materialized_value_hash))
    }

    /// Records one current-run demand observation for a demand node.
    ///
    /// The helper reads the latest persisted counters, starts from empty
    /// counters on a miss, appends the updated counters while preserving any
    /// materialized value-hash link, and returns the value that was recorded.
    /// Callers must serialize writes for the same node key: this fixed-record
    /// sidecar stores absolute counters, so concurrent read-modify-append calls
    /// can overwrite one another under newest-record lookup semantics.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, decoded, written, or flushed.
    pub fn record_node_current_demand(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<MaterializationReuse, PersistNodeMetadataIndexError> {
        let reuse = self
            .lookup_node_materialization_reuse(key)?
            .unwrap_or_default()
            .record_current_demand();
        self.record_node_materialization_reuse(key, reuse)?;
        Ok(reuse)
    }

    /// Builds durable materialization threshold signals for one demand node.
    ///
    /// Missing metadata starts from empty reuse counters, so current payloads
    /// are kept in memory until a previous run has demanded the same node and
    /// the caller-supplied cost model says writing is profitable.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn node_materialization_signals(
        &self,
        key: PersistNodeMetadataKey,
        costs: MaterializationCosts,
    ) -> Result<MaterializationSignals, PersistNodeMetadataIndexError> {
        Ok(self
            .lookup_node_materialization_reuse(key)?
            .unwrap_or_default()
            .signals(costs))
    }

    /// Returns the durable materialization decision for one demand node.
    ///
    /// This is the cache-level bridge from persisted cross-run demand counters
    /// to the existing materialization threshold policy. It does not write the
    /// payload; callers pass the returned decision to the appropriate
    /// materialization helper.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, or decoded.
    pub fn node_materialization_decision(
        &self,
        key: PersistNodeMetadataKey,
        costs: MaterializationCosts,
    ) -> Result<MaterializationDecision, PersistNodeMetadataIndexError> {
        Ok(self.node_materialization_signals(key, costs)?.decide())
    }

    /// Advances persisted reuse counters for one demand node to the next run.
    ///
    /// Missing index entries return `Ok(None)` without appending an empty
    /// record. Existing entries append the counters returned by
    /// [`MaterializationReuse::advance_run`], preserve any materialized
    /// value-hash link, and return the recorded reuse counters. Callers must
    /// serialize writes for the same node key for the same reason as
    /// [`Self::record_node_current_demand`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, decoded, written, or flushed.
    pub fn advance_node_materialization_reuse_run(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<MaterializationReuse>, PersistNodeMetadataIndexError> {
        let Some(reuse) = self.lookup_node_materialization_reuse(key)? else {
            return Ok(None);
        };
        let advanced = reuse.advance_run();
        self.record_node_materialization_reuse(key, advanced)?;
        Ok(Some(advanced))
    }

    /// Advances persisted reuse counters for all known demand nodes.
    ///
    /// This reads the newest metadata value for every node key, appends
    /// [`MaterializationReuse::advance_run`] for entries whose counters change
    /// while preserving any materialized value-hash link, and returns the
    /// entries that were appended in stable key order. Callers must serialize
    /// writes to the node metadata sidecar while this method runs.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, decoded, written, or flushed.
    pub fn advance_all_node_materialization_reuse_runs(
        &self,
    ) -> Result<Vec<PersistNodeMetadataIndexEntry>, PersistNodeMetadataIndexError> {
        let mut recorded = Vec::new();
        for entry in self.node_metadata_index.latest_entries()? {
            let reuse = entry.value().materialization_reuse();
            let advanced = reuse.advance_run();
            if advanced == reuse {
                continue;
            }
            let advanced_entry = PersistNodeMetadataIndexEntry::new(
                entry.key(),
                entry.value().with_materialization_reuse(advanced),
            );
            self.record_node_metadata(advanced_entry)?;
            recorded.push(advanced_entry);
        }
        Ok(recorded)
    }

    /// Compacts node metadata to the newest record for every known demand node.
    ///
    /// This delegates to [`PersistNodeMetadataIndex::compact_latest_entries`].
    /// Callers must serialize writes to the node metadata sidecar while this
    /// method runs.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the sidecar index cannot
    /// be opened, read, decoded, written, flushed, or renamed into place.
    pub fn compact_node_metadata(&self) -> Result<usize, PersistNodeMetadataIndexError> {
        self.node_metadata_index.compact_latest_entries()
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

    /// Materializes a cached expression payload into the indexed `values/` pack.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing, encoding, or
    /// writing `value`. [`MaterializationDecision::Materialize`] encodes the
    /// payload as canonical value-store bytes, uses the payload's
    /// [`ValueHash`] as the `values/` content address, and records the pack
    /// location in the sidecar blob index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedWriteError`] when
    /// materialization is requested and the payload cannot be hashed, encoded,
    /// appended, or indexed.
    pub fn materialize_cached_expression_value_indexed(
        &self,
        value: &CachedExpressionValue,
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistCachedExpressionValueIndexedWriteError> {
        let MaterializationDecision::Materialize = decision else {
            return Ok(PersistMaterialization::Skipped);
        };
        let value_hash = value
            .value_hash()
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Hash { source })?;
        let payload = value
            .encode_persistent_payload()
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Encode { source })?;
        let key = PersistBlobKey::for_value(value_hash.as_durable_hash());
        self.materialize_blob_indexed(key, &payload, MaterializationDecision::Materialize)
            .map_err(|source| PersistCachedExpressionValueIndexedWriteError::Write { source })
    }

    /// Applies materialization threshold signals to a cached expression payload.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through
    /// [`Self::materialize_cached_expression_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedWriteError`] when the
    /// signals choose materialization and the payload cannot be hashed,
    /// encoded, appended, or indexed.
    pub fn materialize_cached_expression_value_indexed_with_signals(
        &self,
        value: &CachedExpressionValue,
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistCachedExpressionValueIndexedWriteError> {
        self.materialize_cached_expression_value_indexed(value, signals.decide())
    }

    /// Loads a cached expression payload from the indexed `values/` pack.
    ///
    /// Missing index entries return `Ok(None)`. Present entries are read by
    /// `value_hash`, verified by the blob pack, and decoded as a cached
    /// expression payload. The decoded value is then hashed again and must
    /// match `value_hash` before being returned for evaluator-local
    /// rehydration.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionValueIndexedLoadError`] if the sidecar
    /// index cannot be read, the indexed blob cannot be verified, the bytes
    /// are not a supported cached-expression payload, or the decoded payload's
    /// value hash does not match `value_hash`.
    pub fn load_cached_expression_value_indexed(
        &self,
        value_hash: ValueHash,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionValueIndexedLoadError> {
        let key = PersistBlobKey::for_value(value_hash.as_durable_hash());
        let Some(payload) = self
            .read_blob_indexed(key)
            .map_err(|source| PersistCachedExpressionValueIndexedLoadError::Read { source })?
        else {
            return Ok(None);
        };
        let value = CachedExpressionValue::decode_persistent_payload(&payload)
            .map_err(|source| PersistCachedExpressionValueIndexedLoadError::Decode { source })?;
        let actual = value
            .value_hash()
            .map_err(|source| PersistCachedExpressionValueIndexedLoadError::Hash { source })?;
        if actual != value_hash {
            return Err(
                PersistCachedExpressionValueIndexedLoadError::ValueHashMismatch {
                    expected: value_hash,
                    actual,
                },
            );
        }
        Ok(Some(value))
    }

    /// Materializes a cached expression payload and links it from node metadata.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns
    /// [`PersistMaterialization::Skipped`] without hashing, encoding, writing,
    /// or updating node metadata. [`MaterializationDecision::Materialize`]
    /// writes the payload through the indexed `values/` pack and then records
    /// the resulting [`ValueHash`] in the demand-node metadata sidecar while
    /// preserving existing reuse counters for `node_key`.
    ///
    /// This helper is explicit and non-transactional: if the value-pack write
    /// succeeds but the node metadata write fails, the indexed value remains
    /// addressable by value hash but is not linked from `node_key`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedWriteError`] when
    /// materialization is requested and the payload cannot be hashed, encoded,
    /// indexed, or linked from node metadata.
    pub fn materialize_cached_expression_node_value_indexed(
        &self,
        node_key: PersistNodeMetadataKey,
        value: &CachedExpressionValue,
        decision: MaterializationDecision,
    ) -> Result<PersistMaterialization, PersistCachedExpressionNodeValueIndexedWriteError> {
        let MaterializationDecision::Materialize = decision else {
            return Ok(PersistMaterialization::Skipped);
        };
        let value_hash = value
            .value_hash()
            .map_err(|source| PersistCachedExpressionNodeValueIndexedWriteError::Hash { source })?;
        let payload = value.encode_persistent_payload().map_err(|source| {
            PersistCachedExpressionNodeValueIndexedWriteError::Encode { source }
        })?;
        let blob_key = PersistBlobKey::for_value(value_hash.as_durable_hash());
        let materialization = self
            .materialize_blob_indexed(blob_key, &payload, MaterializationDecision::Materialize)
            .map_err(
                |source| PersistCachedExpressionNodeValueIndexedWriteError::Write { source },
            )?;
        self.record_node_materialized_value_hash(node_key, value_hash)
            .map_err(
                |source| PersistCachedExpressionNodeValueIndexedWriteError::Metadata { source },
            )?;
        Ok(materialization)
    }

    /// Applies materialization threshold signals to a node-linked payload write.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through
    /// [`Self::materialize_cached_expression_node_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedWriteError`] when the
    /// signals choose materialization and the payload cannot be hashed,
    /// encoded, indexed, or linked from node metadata.
    pub fn materialize_cached_expression_node_value_indexed_with_signals(
        &self,
        node_key: PersistNodeMetadataKey,
        value: &CachedExpressionValue,
        signals: MaterializationSignals,
    ) -> Result<PersistMaterialization, PersistCachedExpressionNodeValueIndexedWriteError> {
        self.materialize_cached_expression_node_value_indexed(node_key, value, signals.decide())
    }

    /// Loads a cached expression payload through one demand-node metadata key.
    ///
    /// Missing node metadata, metadata without a materialized value hash, and
    /// missing indexed value blobs all return `Ok(None)`. Present value blobs
    /// are decoded and rehashed by [`Self::load_cached_expression_value_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistCachedExpressionNodeValueIndexedLoadError`] if node
    /// metadata cannot be read or the linked value payload cannot be loaded.
    pub fn load_cached_expression_node_value_indexed(
        &self,
        node_key: PersistNodeMetadataKey,
    ) -> Result<Option<CachedExpressionValue>, PersistCachedExpressionNodeValueIndexedLoadError>
    {
        let Some(value_hash) =
            self.lookup_node_materialized_value_hash(node_key)
                .map_err(
                    |source| PersistCachedExpressionNodeValueIndexedLoadError::Metadata { source },
                )?
        else {
            return Ok(None);
        };
        self.load_cached_expression_value_indexed(value_hash)
            .map_err(|source| PersistCachedExpressionNodeValueIndexedLoadError::Value { source })
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

    /// Applies `decision` to a frontend file artifact and records index entries.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, appends it to the `files/` pack through
    /// [`Self::append_blob_indexed`], and records the file-artifact mapping
    /// through [`Self::record_file_artifact`].
    ///
    /// This helper is explicit and non-transactional: if the blob append or
    /// blob-index write succeeds but the file-artifact index write fails, the
    /// blob bytes and any blob hash-to-offset record remain without a
    /// corresponding file-artifact mapping record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// appended/indexed, or when the file-artifact mapping cannot be recorded.
    pub fn materialize_file_artifact_indexed(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistFileArtifactMaterialization, PersistFileArtifactIndexedWriteError> {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistFileArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let blob_entry = self
                    .append_blob_indexed(PersistBlobKey::for_file(blob_hash), payload)
                    .map_err(|source| PersistFileArtifactIndexedWriteError::Blob { source })?;
                let index_value =
                    PersistFileArtifactIndexValue::new(blob_hash, blob_entry.location());
                self.record_file_artifact(PersistFileArtifactIndexEntry::new(
                    artifact_key,
                    index_value,
                ))
                .map_err(|source| PersistFileArtifactIndexedWriteError::Index { source })?;
                Ok(PersistFileArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value,
                })
            }
        }
    }

    /// Applies `decision` to a frontend parse artifact payload.
    ///
    /// The artifact mapping key is derived only from `parse_key`.
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
    pub fn materialize_parse_artifact(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistParseArtifactMaterialization, PersistBlobPackError> {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistParseArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let location = self.append_blob(PersistBlobKey::for_file(blob_hash), payload)?;
                Ok(PersistParseArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value: PersistParseArtifactIndexValue::new(blob_hash, location),
                })
            }
        }
    }

    /// Applies `decision` to a frontend parse artifact and records index entries.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without hashing or writing `payload`. [`MaterializationDecision::Materialize`]
    /// hashes `payload`, appends it to the `files/` pack through
    /// [`Self::append_blob_indexed`], and records the parse-artifact mapping
    /// through [`Self::record_parse_artifact`].
    ///
    /// This helper is explicit and non-transactional: if the blob append or
    /// blob-index write succeeds but the parse-artifact index write fails, the
    /// blob bytes and any blob hash-to-offset record remain without a
    /// corresponding parse-artifact mapping record.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedWriteError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// appended/indexed, or when the parse-artifact mapping cannot be recorded.
    pub fn materialize_parse_artifact_indexed(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        decision: MaterializationDecision,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactIndexedWriteError> {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistParseArtifactMaterialization::Skipped { artifact_key })
            }
            MaterializationDecision::Materialize => {
                let blob_hash = DurableBlake3Hash::for_bytes(payload);
                let blob_entry = self
                    .append_blob_indexed(PersistBlobKey::for_file(blob_hash), payload)
                    .map_err(|source| PersistParseArtifactIndexedWriteError::Blob { source })?;
                let index_value =
                    PersistParseArtifactIndexValue::new(blob_hash, blob_entry.location());
                self.record_parse_artifact(PersistParseArtifactIndexEntry::new(
                    artifact_key,
                    index_value,
                ))
                .map_err(|source| PersistParseArtifactIndexedWriteError::Index { source })?;
                Ok(PersistParseArtifactMaterialization::Materialized {
                    artifact_key,
                    index_value,
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

    /// Applies materialization threshold signals to indexed file-artifact materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_file_artifact_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// appended/indexed, or when the file-artifact mapping cannot be recorded.
    pub fn materialize_file_artifact_indexed_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistFileArtifactIndexedWriteError> {
        self.materialize_file_artifact_indexed(file_key, parse_key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to a frontend parse artifact.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` pack cannot be
    /// opened, validated, or written.
    pub fn materialize_parse_artifact_with_signals(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistParseArtifactMaterialization, PersistBlobPackError> {
        self.materialize_parse_artifact(parse_key, payload, signals.decide())
    }

    /// Applies materialization threshold signals to indexed parse-artifact materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedWriteError`] when the signals choose
    /// [`MaterializationDecision::Materialize`] and the `files/` blob cannot be
    /// appended/indexed, or when the parse-artifact mapping cannot be recorded.
    pub fn materialize_parse_artifact_indexed_with_signals(
        &self,
        parse_key: ParseCacheKey,
        payload: &[u8],
        signals: MaterializationSignals,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactIndexedWriteError> {
        self.materialize_parse_artifact_indexed(parse_key, payload, signals.decide())
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

    /// Reads and verifies a materialized frontend parse artifact.
    ///
    /// This is a typed wrapper over [`Self::read_blob`] for values decoded from
    /// the parse-artifact index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobPackError`] if the `files/` pack cannot be opened
    /// or read, if `index_value` points at an invalid location, or if the record
    /// or payload hash does not match `index_value`.
    pub fn read_parse_artifact(
        &self,
        index_value: PersistParseArtifactIndexValue,
    ) -> Result<Vec<u8>, PersistBlobPackError> {
        self.read_blob(index_value.blob_key(), index_value.location())
    }

    /// Reads a materialized parse-artifact bundle into a parse-cache entry.
    ///
    /// This adapter consumes a caller-supplied parse-artifact index value and
    /// target entry. The decoded bundle must validate against the current
    /// parse-cache schema before any entry files are written. This adapter does
    /// not perform durable index lookup or decide whether the hydrated entry
    /// should be used for a cache hit.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if the artifact cannot be
    /// read from the `files/` pack, if the payload is not a valid
    /// [`ParseArtifactBundle`], if the bundle metadata/artifact counts do not
    /// validate, or if the target entry cannot be written.
    pub fn hydrate_parse_artifact_bundle(
        &self,
        index_value: PersistParseArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let payload = self
            .read_parse_artifact(index_value)
            .map_err(|source| PersistParseArtifactHydrationError::Read { source })?;
        let bundle = ParseArtifactBundle::decode(&payload)
            .map_err(|source| PersistParseArtifactHydrationError::Decode { source })?;
        bundle
            .validate_meta(PARSE_CACHE_SCHEMA_VERSION)
            .map_err(|source| PersistParseArtifactHydrationError::Validate { source })?;
        entry
            .write_artifact_bundle(&bundle)
            .map_err(|source| PersistParseArtifactHydrationError::Write { source })
    }

    /// Reads a keyed parse-artifact bundle into a parse-cache entry.
    ///
    /// The supplied `artifact_key` must match the key derived from `parse_key`
    /// before the `files/` pack is read. This adapter still relies on its
    /// caller to perform the durable index lookup.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if `artifact_key` does not
    /// match `parse_key`, if the artifact cannot be read from the `files/` pack,
    /// if the payload is not a valid [`ParseArtifactBundle`], if the bundle
    /// metadata/artifact counts do not validate, or if the target entry cannot
    /// be written.
    pub fn hydrate_parse_artifact_bundle_for_key(
        &self,
        parse_key: ParseCacheKey,
        artifact_key: PersistParseArtifactKey,
        index_value: PersistParseArtifactIndexValue,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        let expected = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        if artifact_key != expected {
            return Err(PersistParseArtifactHydrationError::KeyMismatch {
                expected,
                actual: artifact_key,
            });
        }
        self.hydrate_parse_artifact_bundle(index_value, entry)
    }

    /// Reads an indexed parse-artifact bundle into a parse-cache entry.
    ///
    /// This is the entry-shaped variant of
    /// [`Self::hydrate_parse_artifact_bundle_for_key`]. It still relies on its
    /// caller to perform the durable index lookup that produced `index_entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactHydrationError`] if `index_entry.key()`
    /// does not match `parse_key`, if the artifact cannot be read from the
    /// `files/` pack, if the payload is not a valid [`ParseArtifactBundle`], if
    /// the bundle metadata/artifact counts do not validate, or if the target
    /// entry cannot be written.
    pub fn hydrate_parse_artifact_bundle_from_entry(
        &self,
        parse_key: ParseCacheKey,
        index_entry: PersistParseArtifactIndexEntry,
        entry: &ParseCacheEntry,
    ) -> Result<(), PersistParseArtifactHydrationError> {
        self.hydrate_parse_artifact_bundle_for_key(
            parse_key,
            index_entry.key(),
            index_entry.value(),
            entry,
        )
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

    /// Looks up and hydrates an indexed parse-artifact bundle.
    ///
    /// This is the cache-level hit adapter for the explicit file-artifact
    /// sidecar index. It derives the expected mapping key from `file_key` and
    /// `parse_key`, returns `Ok(None)` when the index has no matching entry,
    /// and otherwise validates and writes the indexed bundle into `entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedHydrationError`] if the
    /// file-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into `entry`.
    pub fn hydrate_file_artifact_bundle_from_index(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexedHydrationError>
    {
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(file_key, parse_key);
        let Some(index_value) = self
            .lookup_file_artifact(artifact_key)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Lookup { source })?
        else {
            return Ok(None);
        };
        let index_entry = PersistFileArtifactIndexEntry::new(artifact_key, index_value);
        self.hydrate_file_artifact_bundle_from_entry(file_key, parse_key, index_entry, entry)
            .map_err(|source| PersistFileArtifactIndexedHydrationError::Hydrate { source })?;
        Ok(Some(index_entry))
    }

    /// Looks up and hydrates an indexed parse-artifact bundle.
    ///
    /// This is the cache-level hit adapter for the parse-artifact sidecar
    /// index. It derives the expected mapping key from `parse_key`, returns
    /// `Ok(None)` when the index has no matching entry, and otherwise validates
    /// and writes the indexed bundle into `entry`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedHydrationError`] if the
    /// parse-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into `entry`.
    pub fn hydrate_parse_artifact_bundle_from_index(
        &self,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
    ) -> Result<Option<PersistParseArtifactIndexEntry>, PersistParseArtifactIndexedHydrationError>
    {
        let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
        let Some(index_value) = self
            .lookup_parse_artifact(artifact_key)
            .map_err(|source| PersistParseArtifactIndexedHydrationError::Lookup { source })?
        else {
            return Ok(None);
        };
        let index_entry = PersistParseArtifactIndexEntry::new(artifact_key, index_value);
        self.hydrate_parse_artifact_bundle_from_entry(parse_key, index_entry, entry)
            .map_err(|source| PersistParseArtifactIndexedHydrationError::Hydrate { source })?;
        Ok(Some(index_entry))
    }

    /// Derives parse identity from source bytes and hydrates the parse cache.
    ///
    /// This source-shaped adapter derives `ParseCacheKey` through
    /// `parse_cache` and hydrates the parse cache's normal entry directory when
    /// the persistent parse-artifact index has a matching bundle. Missing index
    /// entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedHydrationError`] if the
    /// parse-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_parse_index(
        &self,
        parse_cache: &ParseCache,
        source: &[u8],
    ) -> Result<Option<PersistParseArtifactIndexEntry>, PersistParseArtifactIndexedHydrationError>
    {
        let parse_key = parse_cache.key_for_source(source);
        let entry = parse_cache.entry_for_key(parse_key);
        self.hydrate_parse_artifact_bundle_from_index(parse_key, &entry)
    }

    /// Loads an indexed parse-cache hit for caller-supplied source bytes.
    ///
    /// This is a source-shaped load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_parse_index`] and
    /// [`ParseCache::load_cached_bytes`]. It derives identity from `source`
    /// bytes alone, hydrates the normal parse-cache entry from the persistent
    /// parse-artifact index, and returns the hydrated entry as a
    /// [`CachedParse`] hit. Missing parse-artifact index entries return
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseBytesIndexedLoadError`] if the parse-artifact
    /// index cannot be read, a matching indexed artifact cannot be hydrated, or
    /// the hydrated parse-cache entry cannot be read back as a [`CachedParse`].
    pub fn load_parse_cache_bytes_from_index(
        &self,
        parse_cache: &ParseCache,
        source: &[u8],
    ) -> Result<Option<CachedParse>, PersistParseBytesIndexedLoadError> {
        if self
            .hydrate_parse_cache_entry_from_parse_index(parse_cache, source)
            .map_err(|source| PersistParseBytesIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(source)
            .map_err(|source| PersistParseBytesIndexedLoadError::Load { source })
    }

    /// Derives parse identities from source bytes and hydrates the parse cache.
    ///
    /// This source-shaped adapter derives `ParseFileKey` from `realpath` and
    /// `source`, derives `ParseCacheKey` through `parse_cache`, and hydrates
    /// the parse cache's normal entry directory when the persistent
    /// file-artifact index has a matching bundle. Missing index entries return
    /// `Ok(None)`.
    ///
    /// `realpath` must already be the canonical path used for file-artifact
    /// identity; this helper does not canonicalize or read source files.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedHydrationError`] if the
    /// file-artifact index cannot be read, or if a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_source_index(
        &self,
        parse_cache: &ParseCache,
        realpath: impl AsRef<Path>,
        source: &[u8],
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistFileArtifactIndexedHydrationError>
    {
        let file_key = ParseFileKey::for_source(realpath.as_ref(), source);
        let parse_key = parse_cache.key_for_source(source);
        let entry = parse_cache.entry_for_key(parse_key);
        self.hydrate_file_artifact_bundle_from_index(&file_key, parse_key, &entry)
    }

    /// Loads an indexed parse-cache hit for caller-supplied source bytes.
    ///
    /// This is a source-shaped load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_source_index`] and
    /// [`ParseCache::load_cached_bytes`]. It derives both identities from the
    /// same canonical `realpath` and `source` bytes, hydrates the normal
    /// parse-cache entry from the persistent file-artifact index, and returns
    /// the hydrated entry as a [`CachedParse`] hit. Missing file-artifact index
    /// entries return `Ok(None)`.
    ///
    /// `realpath` must already be the canonical path used for file-artifact
    /// identity; this helper does not canonicalize or read source files.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseSourceIndexedLoadError`] if the file-artifact index
    /// cannot be read, a matching indexed artifact cannot be hydrated, or the
    /// hydrated parse-cache entry cannot be read back as a [`CachedParse`].
    pub fn load_parse_cache_source_from_index(
        &self,
        parse_cache: &ParseCache,
        realpath: impl AsRef<Path>,
        source: &[u8],
    ) -> Result<Option<CachedParse>, PersistParseSourceIndexedLoadError> {
        if self
            .hydrate_parse_cache_entry_from_source_index(parse_cache, realpath, source)
            .map_err(|source| PersistParseSourceIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(source)
            .map_err(|source| PersistParseSourceIndexedLoadError::Load { source })
    }

    /// Canonicalizes a source path and hydrates the matching parse-cache entry.
    ///
    /// This file-shaped adapter canonicalizes `path`, reads the canonical
    /// source bytes, derives the file and parse identities from those bytes,
    /// and delegates to [`Self::hydrate_parse_cache_entry_from_source_index`].
    /// Missing file-artifact index entries return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseFileIndexedHydrationError`] if `path` cannot be
    /// canonicalized, the canonical source file cannot be read, the
    /// file-artifact index cannot be read, or a matching indexed artifact
    /// cannot be read from the `files/` pack, decoded, validated, or written
    /// into the parse cache entry.
    pub fn hydrate_parse_cache_entry_from_file_index(
        &self,
        parse_cache: &ParseCache,
        path: impl AsRef<Path>,
    ) -> Result<Option<PersistFileArtifactIndexEntry>, PersistParseFileIndexedHydrationError> {
        let requested = path.as_ref();
        let realpath = fs::canonicalize(requested).map_err(|source| {
            PersistParseFileIndexedHydrationError::CanonicalizeSource {
                path: requested.to_path_buf(),
                source,
            }
        })?;
        let source = fs::read(&realpath).map_err(|source| {
            PersistParseFileIndexedHydrationError::ReadSource {
                path: realpath.clone(),
                source,
            }
        })?;
        self.hydrate_parse_cache_entry_from_source_index(parse_cache, &realpath, &source)
            .map_err(|source| PersistParseFileIndexedHydrationError::Hydrate { source })
    }

    /// Canonicalizes a source path and loads an indexed parse-cache hit.
    ///
    /// This is an explicit load adapter over
    /// [`Self::hydrate_parse_cache_entry_from_source_index`] and
    /// [`ParseCache::load_cached_bytes`]. It canonicalizes `path`, reads the
    /// canonical source bytes, hydrates the normal parse-cache entry from the
    /// persistent file-artifact index, and returns the hydrated entry as a
    /// [`CachedParse`] hit. Missing file-artifact index entries return
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseFileIndexedLoadError`] if `path` cannot be
    /// canonicalized, the canonical source file cannot be read, the
    /// file-artifact index cannot be read, a matching indexed artifact cannot
    /// be hydrated, or the hydrated parse-cache entry cannot be read back as a
    /// [`CachedParse`].
    pub fn load_parse_cache_file_from_index(
        &self,
        parse_cache: &ParseCache,
        path: impl AsRef<Path>,
    ) -> Result<Option<CachedParse>, PersistParseFileIndexedLoadError> {
        let requested = path.as_ref();
        let realpath = fs::canonicalize(requested).map_err(|source| {
            PersistParseFileIndexedLoadError::CanonicalizeSource {
                path: requested.to_path_buf(),
                source,
            }
        })?;
        let source =
            fs::read(&realpath).map_err(|source| PersistParseFileIndexedLoadError::ReadSource {
                path: realpath.clone(),
                source,
            })?;
        if self
            .hydrate_parse_cache_entry_from_source_index(parse_cache, &realpath, &source)
            .map_err(|source| PersistParseFileIndexedLoadError::Hydrate { source })?
            .is_none()
        {
            return Ok(None);
        }
        parse_cache
            .load_cached_bytes(&source)
            .map_err(|source| PersistParseFileIndexedLoadError::Load { source })
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
                validate_parse_cache_entry_key(parse_key, entry)?;
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

    /// Applies `decision` to an existing parse-cache entry and records indexes.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without reading or encoding `entry`. [`MaterializationDecision::Materialize`]
    /// reads the entry as a [`ParseArtifactBundle`], encodes it as one payload,
    /// appends it through [`Self::materialize_file_artifact_indexed`], and
    /// records both blob and file-artifact sidecar indexes.
    ///
    /// This helper inherits the explicit non-transactional behavior of
    /// [`Self::materialize_file_artifact_indexed`]: a blob append/index write
    /// can remain even when the file-artifact mapping write fails.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the source entry cannot be
    /// read, the bundle payload cannot be encoded, the `files/` blob cannot be
    /// appended/indexed, or the file-artifact mapping cannot be recorded.
    pub fn materialize_parse_artifact_entry_indexed(
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
                validate_parse_cache_entry_key(parse_key, entry)?;
                let bundle = entry.read_artifact_bundle().map_err(|source| {
                    PersistParseArtifactMaterializationError::ReadBundle { source }
                })?;
                let payload = bundle.encode().map_err(|source| {
                    PersistParseArtifactMaterializationError::EncodeBundle { source }
                })?;
                self.materialize_file_artifact_indexed(
                    file_key,
                    parse_key,
                    &payload,
                    MaterializationDecision::Materialize,
                )
                .map_err(|source| PersistParseArtifactMaterializationError::WriteIndexed { source })
            }
        }
    }

    /// Applies `decision` to an existing parse-cache entry and records parse indexes.
    ///
    /// [`MaterializationDecision::KeepInMemory`] returns a skipped result
    /// without reading or encoding `entry`. [`MaterializationDecision::Materialize`]
    /// reads the entry as a [`ParseArtifactBundle`], encodes it as one payload,
    /// appends it through [`Self::materialize_parse_artifact_indexed`], and
    /// records both blob and parse-artifact sidecar indexes.
    ///
    /// This helper inherits the explicit non-transactional behavior of
    /// [`Self::materialize_parse_artifact_indexed`]: a blob append/index write
    /// can remain even when the parse-artifact mapping write fails.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when `decision` is
    /// [`MaterializationDecision::Materialize`] and the source entry cannot be
    /// read, the bundle payload cannot be encoded, the `files/` blob cannot be
    /// appended/indexed, or the parse-artifact mapping cannot be recorded.
    pub fn materialize_parse_cache_entry_indexed(
        &self,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        decision: MaterializationDecision,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactMaterializationError> {
        match decision {
            MaterializationDecision::KeepInMemory => {
                Ok(PersistParseArtifactMaterialization::Skipped {
                    artifact_key: PersistParseArtifactKey::from_parse_cache_key(parse_key),
                })
            }
            MaterializationDecision::Materialize => {
                validate_parse_cache_entry_key(parse_key, entry)?;
                let bundle = entry.read_artifact_bundle().map_err(|source| {
                    PersistParseArtifactMaterializationError::ReadBundle { source }
                })?;
                let payload = bundle.encode().map_err(|source| {
                    PersistParseArtifactMaterializationError::EncodeBundle { source }
                })?;
                self.materialize_parse_artifact_indexed(
                    parse_key,
                    &payload,
                    MaterializationDecision::Materialize,
                )
                .map_err(|source| {
                    PersistParseArtifactMaterializationError::WriteParseIndexed { source }
                })
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

    /// Applies threshold signals to indexed parse-cache entry materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_artifact_entry_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when the signals
    /// choose [`MaterializationDecision::Materialize`] and the source entry
    /// cannot be read, the bundle payload cannot be encoded, the `files/` blob
    /// cannot be appended/indexed, or the file-artifact mapping cannot be
    /// recorded.
    pub fn materialize_parse_artifact_entry_indexed_with_signals(
        &self,
        file_key: &ParseFileKey,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        signals: MaterializationSignals,
    ) -> Result<PersistFileArtifactMaterialization, PersistParseArtifactMaterializationError> {
        self.materialize_parse_artifact_entry_indexed(file_key, parse_key, entry, signals.decide())
    }

    /// Applies threshold signals to parse-keyed parse-cache entry materialization.
    ///
    /// The signals are evaluated with [`MaterializationSignals::decide`] and
    /// then applied through [`Self::materialize_parse_cache_entry_indexed`].
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactMaterializationError`] when the signals
    /// choose [`MaterializationDecision::Materialize`] and the source entry
    /// cannot be read, the bundle payload cannot be encoded, the `files/` blob
    /// cannot be appended/indexed, or the parse-artifact mapping cannot be
    /// recorded.
    pub fn materialize_parse_cache_entry_indexed_with_signals(
        &self,
        parse_key: ParseCacheKey,
        entry: &ParseCacheEntry,
        signals: MaterializationSignals,
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactMaterializationError> {
        self.materialize_parse_cache_entry_indexed(parse_key, entry, signals.decide())
    }
}

fn validate_parse_cache_entry_key(
    parse_key: ParseCacheKey,
    entry: &ParseCacheEntry,
) -> Result<(), PersistParseArtifactMaterializationError> {
    let expected = parse_key.to_hex();
    let matches = entry
        .dir()
        .file_name()
        .map(|name| name.as_bytes() == expected.as_bytes())
        .unwrap_or(false);
    if matches {
        return Ok(());
    }
    Err(PersistParseArtifactMaterializationError::EntryKeyMismatch {
        expected: parse_key,
        path: entry.dir().to_path_buf(),
    })
}
