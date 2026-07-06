//! Demand-node metadata and verifying-trace sidecar operations.

use super::*;

impl PersistCache {
    /// Returns the fixed-record index for durable demand-node metadata.
    pub const fn node_metadata_index(&self) -> &PersistNodeMetadataIndex {
        &self.node_metadata_index
    }

    /// Returns the append-only log for durable demand-node traces.
    pub const fn node_trace_log(&self) -> &PersistNodeTraceLog {
        &self.node_trace_log
    }

    /// Appends durable demand-node metadata to the sidecar index.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, validated, written, or flushed.
    pub fn record_node_metadata(
        &self,
        entry: PersistNodeMetadataIndexEntry,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        self.record_node_metadata_unlocked(entry)
    }

    pub(super) fn record_node_metadata_unlocked(
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
        self.lookup_node_metadata_unlocked(key)
    }

    pub(super) fn lookup_node_metadata_unlocked(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeMetadataIndexValue>, PersistNodeMetadataIndexError> {
        self.node_metadata_index.lookup(key)
    }

    /// Appends a durable verifying-trace payload for one materialized demand node.
    ///
    /// The trace log is append-only and newest-record-wins on lookup.
    /// Cache-level writers share the node-trace advisory lock and same-root
    /// trace write lock while appending. Raw lower-level log users must still
    /// be excluded by the caller. The caller supplies the materialized value
    /// hash so future hit selection can reject stale trace/value pairings.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the advisory trace lock cannot
    /// be acquired, if the same-root trace write lock is poisoned, or if the
    /// trace log cannot be opened, validated, written, flushed, or decoded
    /// during validation.
    pub fn record_node_trace(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
        payload: &PersistNodeTracePayload,
    ) -> Result<(), PersistNodeTraceLogError> {
        let (_advisory_guard, _write_guard) = self.lock_node_traces_write()?;
        self.node_trace_log.append_trace(key, value_hash, payload)
    }

    /// Appends a trace tombstone for one demand node.
    ///
    /// The tombstone becomes the newest trace record for `key`, so durable
    /// trace-verified loads miss even if older trace records still carry the
    /// same materialized value hash.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the advisory trace lock cannot
    /// be acquired, if the same-root trace write lock is poisoned, or if the
    /// trace log cannot be opened, validated, written, flushed, or decoded
    /// during validation.
    pub fn record_node_trace_tombstone(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<(), PersistNodeTraceLogError> {
        let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(
            b"aos-nix-node-trace-tombstone-v1",
        ));
        self.record_node_trace(key, value_hash, &PersistNodeTracePayload::tombstone())
    }

    /// Looks up the newest durable verifying-trace record for one demand node.
    ///
    /// Missing trace records return `Ok(None)`. Cache-level lookups hold the
    /// shared node-trace advisory lock and same-root trace lock while scanning
    /// the append-only log.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the advisory trace read lock
    /// cannot be acquired, if the same-root trace lock is poisoned, or if the
    /// trace log cannot be opened, read, or decoded.
    pub fn lookup_node_trace(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<PersistNodeTraceLogEntry>, PersistNodeTraceLogError> {
        let (_advisory_guard, _read_guard) = self.lock_node_traces_read()?;
        self.node_trace_log.lookup(key)
    }

    /// Compacts node traces to the newest record for every known demand node.
    ///
    /// Cache-level writers share the node-trace advisory lock and same-root
    /// trace write lock while this method rewrites the log. Raw lower-level
    /// log users must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the advisory trace lock cannot
    /// be acquired, if the same-root trace write lock is poisoned, or if the
    /// trace log cannot be opened, read, decoded, written, flushed, or renamed
    /// into place.
    pub fn compact_node_traces(&self) -> Result<usize, PersistNodeTraceLogError> {
        let (_advisory_guard, _write_guard) = self.lock_node_traces_write()?;
        self.node_trace_log.compact_latest_entries()
    }

    /// Compacts node traces only when the log has bloated past the run-boundary
    /// factor.
    ///
    /// This is the run-boundary counterpart to [`Self::compact_node_traces`]: it
    /// rewrites the append-only log to one record per key only once physical
    /// records exceed the node sidecar compaction factor times the live keys, so
    /// warm re-runs that re-record traces cannot grow the log without bound.
    /// Returns the retained entry count when a compaction ran, or `None`
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeTraceLogError`] if the advisory trace lock cannot be
    /// acquired, if the same-root trace write lock is poisoned, or if a
    /// triggered compaction cannot be opened, read, decoded, written, flushed,
    /// or renamed into place.
    pub fn compact_node_traces_if_bloated(
        &self,
    ) -> Result<Option<usize>, PersistNodeTraceLogError> {
        let (_advisory_guard, _write_guard) = self.lock_node_traces_write()?;
        self.node_trace_log
            .compact_if_bloated(NODE_SIDECAR_COMPACTION_FACTOR)
    }

    /// Appends materialization reuse counters for one demand node.
    ///
    /// Existing materialized value-hash metadata for the same node is
    /// preserved in the appended record. Missing metadata starts from an empty
    /// value-hash link.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn record_node_materialization_reuse(
        &self,
        key: PersistNodeMetadataKey,
        reuse: MaterializationReuse,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let value = self
            .lookup_node_metadata_unlocked(key)?
            .unwrap_or_else(|| PersistNodeMetadataIndexValue::new(MaterializationReuse::default()))
            .with_materialization_reuse(reuse);
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(key, value))
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
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn record_node_materialized_value_hash(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
    ) -> Result<(), PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let value = self
            .lookup_node_metadata_unlocked(key)?
            .unwrap_or_else(|| PersistNodeMetadataIndexValue::new(MaterializationReuse::default()))
            .with_value_hash(value_hash);
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(key, value))
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
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn clear_node_materialized_value_hash(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<bool, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let Some(value) = self.lookup_node_metadata_unlocked(key)? else {
            return Ok(false);
        };
        if value.materialized_value_hash().is_none() {
            return Ok(false);
        }
        let value = PersistNodeMetadataIndexValue::new(value.materialization_reuse());
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(key, value))?;
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
}
