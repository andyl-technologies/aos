//! Demand-node reuse counter operations.

use super::*;

impl PersistCache {
    /// Records one current-run demand observation for a demand node.
    ///
    /// The helper reads the latest persisted counters, starts from empty
    /// counters on a miss, appends the updated counters while preserving any
    /// materialized value-hash link, and returns the value that was recorded
    /// while holding the advisory and same-root metadata write locks. Raw
    /// lower-level sidecar users must still be excluded by the caller because
    /// this fixed-record sidecar stores absolute counters under newest-record
    /// lookup semantics.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn record_node_current_demand(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<MaterializationReuse, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let value = self
            .lookup_node_metadata_unlocked(key)?
            .unwrap_or_else(|| PersistNodeMetadataIndexValue::new(MaterializationReuse::default()));
        let reuse = value.materialization_reuse().record_current_demand();
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(
            key,
            value.with_materialization_reuse(reuse),
        ))?;
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
    /// value-hash link, and return the recorded reuse counters while holding
    /// the advisory and same-root metadata write locks. Raw lower-level
    /// sidecar users must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn advance_node_materialization_reuse_run(
        &self,
        key: PersistNodeMetadataKey,
    ) -> Result<Option<MaterializationReuse>, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        let Some(value) = self.lookup_node_metadata_unlocked(key)? else {
            return Ok(None);
        };
        let reuse = value.materialization_reuse();
        let advanced = reuse.advance_run();
        self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(
            key,
            value.with_materialization_reuse(advanced),
        ))?;
        Ok(Some(advanced))
    }

    /// Advances persisted reuse counters for all known demand nodes.
    ///
    /// This reads the newest metadata value for every node key, appends
    /// [`MaterializationReuse::advance_run`] for entries whose counters change
    /// while preserving any materialized value-hash link, and returns the
    /// entries that were appended in stable key order while holding the
    /// advisory and same-root metadata write locks. Raw lower-level sidecar
    /// users must still be excluded by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, or
    /// flushed.
    pub fn advance_all_node_materialization_reuse_runs(
        &self,
    ) -> Result<Vec<PersistNodeMetadataIndexEntry>, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
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
            self.record_node_metadata_unlocked(advanced_entry)?;
            recorded.push(advanced_entry);
        }
        self.node_metadata_index
            .compact_if_bloated(NODE_SIDECAR_COMPACTION_FACTOR)?;
        Ok(recorded)
    }

    /// Compacts node metadata to the newest record for every known demand node.
    ///
    /// Cache-level writers opened on the same cache root share the metadata
    /// advisory lock and same-root write lock while this method rewrites the
    /// sidecar. Raw lower-level sidecar users must still be excluded by the
    /// caller.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, if the same-root metadata write lock is poisoned, or
    /// if the sidecar index cannot be opened, read, decoded, written, flushed,
    /// or renamed into place.
    pub fn compact_node_metadata(&self) -> Result<usize, PersistNodeMetadataIndexError> {
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        self.node_metadata_index.compact_latest_entries()
    }
}
