//! Run-scoped in-memory coordination for warm hit verification.
//!
//! Two per-run tables live on the [`PersistCache`] handle and are shared across
//! its clones:
//!
//! * the **verified-node memo** records `(node key, value hash)` pairs already
//!   proven to be valid trace-verified hits this run, so a dependency shared by
//!   many dependents is verified once per run instead of once per dependent; and
//! * the **pending-demand buffer** coalesces warm-hit demand observations in
//!   memory so they are written back once at the run boundary rather than one
//!   sidecar record per hit.
//!
//! The memo is cleared and the demand buffer flushed at the run boundary; the
//! demand buffer additionally flushes when the last handle to a root is dropped
//! (see [`PersistCache`]'s `Drop` implementation) so coalesced observations are
//! never silently lost.

use super::*;

impl PersistCache {
    /// Returns whether `(key, value_hash)` is already a proven trace hit this run.
    ///
    /// The run-scoped verified-node memo is populated by successful
    /// trace-verified loads. A poisoned memo lock is treated as an empty memo so
    /// verification falls back to the full check rather than trusting stale
    /// state.
    pub(crate) fn verified_node_trace_is_cached(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
    ) -> bool {
        let Ok(memo) = self.verified_node_traces.lock() else {
            return false;
        };
        memo.get(&key) == Some(&value_hash)
    }

    /// Records `(key, value_hash)` as a proven trace hit for the current run.
    ///
    /// A poisoned memo lock is recovered in place because the memo only holds
    /// simple key/value pairs that a panicking writer cannot leave inconsistent.
    pub(crate) fn remember_verified_node_trace(
        &self,
        key: PersistNodeMetadataKey,
        value_hash: ValueHash,
    ) {
        let mut memo = self
            .verified_node_traces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        memo.insert(key, value_hash);
    }

    /// Evicts any verified-node memo entry for `key`.
    ///
    /// This is called from every write that can change a node's trace-hit
    /// status (materialized value-hash link changes, trace appends, and trace
    /// tombstones) so a previously proven hit cannot be trusted after it may
    /// have become a miss.
    pub(crate) fn evict_verified_node_trace(&self, key: PersistNodeMetadataKey) {
        let mut memo = self
            .verified_node_traces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        memo.remove(&key);
    }

    /// Clears the entire run-scoped verified-node memo.
    ///
    /// Called at the run boundary so a later run re-verifies every node against
    /// freshly observed impure inputs.
    pub(crate) fn clear_verified_node_trace_memo(&self) {
        let mut memo = self
            .verified_node_traces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        memo.clear();
    }

    /// Buffers one coalesced current-run demand observation for `key`.
    ///
    /// Warm hits observe demand on every hit. Rather than appending one sidecar
    /// record per hit, the counts are coalesced in memory and written back once
    /// by [`Self::flush_buffered_node_demands`] at the run boundary. The buffer
    /// only affects the current-run demand counter; the cross-run
    /// `previous_run_demands` counter that every mid-run heuristic reads is
    /// untouched, so buffering is transparent to those readers.
    pub(crate) fn buffer_node_current_demand(&self, key: PersistNodeMetadataKey) {
        let mut pending = self
            .pending_node_demands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = pending.entry(key).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// Writes back and clears all buffered current-run demand observations.
    ///
    /// For every buffered key this reads the newest persisted metadata (starting
    /// from empty counters on a miss), adds the coalesced count to the
    /// current-run demand counter while preserving any materialized value-hash
    /// link, and appends one record. The resulting newest-record state is
    /// identical to applying [`MaterializationReuse::record_current_demand`] once
    /// per buffered observation. All write-backs share a single metadata write
    /// lock acquisition.
    ///
    /// # Errors
    ///
    /// Returns [`PersistNodeMetadataIndexError`] if the advisory metadata lock
    /// cannot be acquired, the same-root metadata write lock is poisoned, or the
    /// sidecar index cannot be opened, read, decoded, written, or flushed.
    pub(crate) fn flush_buffered_node_demands(&self) -> Result<(), PersistNodeMetadataIndexError> {
        let pending = {
            let mut guard = self
                .pending_node_demands
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        if pending.is_empty() {
            return Ok(());
        }
        let (_advisory_guard, _write_guard) = self.lock_node_metadata_write()?;
        for (key, count) in pending {
            let value = self.lookup_node_metadata_unlocked(key)?.unwrap_or_else(|| {
                PersistNodeMetadataIndexValue::new(MaterializationReuse::default())
            });
            let reuse = value.materialization_reuse();
            let bumped = MaterializationReuse::new(
                reuse.previous_run_demands(),
                reuse.current_run_demands().saturating_add(count),
            );
            self.record_node_metadata_unlocked(PersistNodeMetadataIndexEntry::new(
                key,
                value.with_materialization_reuse(bumped),
            ))?;
        }
        Ok(())
    }
}
