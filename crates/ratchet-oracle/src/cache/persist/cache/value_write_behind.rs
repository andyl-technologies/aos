//! Write-behind buffer for VALUES-store blob records (RFC-0007 §3.2(b)).
//!
//! On a cold-populate run the per-node value materialize path pays an
//! open + exclusive-flock + write + flush per record on the values pack and its
//! sidecar index. This buffer coalesces those writes: `materialize` pushes
//! `(key, payload)` into an in-memory batch and the batch is flushed once at the
//! eval run boundary (strictly before the synchronous root-cutoff record),
//! amortizing the open/flock/flush across the whole run.
//!
//! Scope is the **VALUES store only**. The FILES store keeps its synchronous
//! pending-root path untouched, so this buffer never interacts with the pending
//! file-artifact GC roots (the #25 increment-0 contract): the only store with
//! pending roots is never buffered.
//!
//! Correctness. Buffered records are not in the values pack or sidecar index
//! until flush, so garbage collection / repack — which run only via explicit
//! maintenance, never on the eval path — never observe them. The flush appends
//! payloads and writes their blob-index root entries together under the held
//! values-store write lock, so the append→index-entry window never opens for a
//! concurrent repack. A crash before flush loses buffered records, which is a
//! re-eval (the pack is advisory and never `fsync`'d per record). Write-dedup
//! consults the buffer's by-key map so a buffered-but-unflushed value never
//! double-appends.

use super::*;
use std::collections::BTreeMap;

/// Flush mid-run once buffered payloads reach this many bytes, so the buffer
/// stays a rounding error against the wide-eval RSS budget.
const WRITE_BEHIND_FLUSH_BYTES: usize = 8 * 1024 * 1024;

/// An in-memory batch of VALUES-store blob records awaiting a run-boundary flush.
#[derive(Debug, Default)]
pub(super) struct PendingValueBatch {
    /// Buffered payloads keyed by blob key, for write-dedup and flush lookup.
    by_key: BTreeMap<PersistBlobKey, Vec<u8>>,
    /// Blob keys in insertion order, giving a deterministic flush order.
    order: Vec<PersistBlobKey>,
    /// Currently buffered payload bytes (drives the mid-run flush cap).
    bytes: usize,
    /// Cumulative buffered payload bytes this process (a memory-scoreboard counter).
    buffered_bytes_total: u64,
    /// Count of within-run re-materializations of an already-buffered value — a
    /// value whose buffered state cost it a within-run memo read and forced a
    /// recompute.
    buffered_miss_recompute: u64,
}

impl PersistCache {
    /// Returns this handle with the VALUES-store write-behind buffer set.
    ///
    /// When `enabled` is `true`, per-node value materializations are buffered in
    /// memory and flushed once at the run boundary (RFC-0007 §3.2(b)) instead of
    /// paying an open/flock/flush per record. Off by default and per the
    /// `AOS_NIX_CACHE_WRITE_BEHIND` knob applied at
    /// [`PersistCache::open`](super::super::PersistCache::open); this builder
    /// overrides that for callers that manage the flag directly (tests, tools).
    #[must_use]
    pub const fn with_write_behind_values(mut self, enabled: bool) -> Self {
        self.write_behind_values = enabled;
        self
    }

    /// Returns whether the VALUES-store write-behind buffer is active.
    pub(super) const fn write_behind_values_enabled(&self) -> bool {
        self.write_behind_values
    }

    /// Buffers a VALUES-store blob for a run-boundary flush, deduping against the
    /// on-disk index and the buffer.
    ///
    /// Returns a [`PersistBlobIndexEntry`] whose location is a deferred sentinel
    /// (`u64::MAX` offset) for a freshly buffered or already-buffered record; the
    /// value materialize caller consumes only the Materialized/Skipped
    /// distinction, never the location. An on-disk dedup hit returns the real
    /// existing location.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] if the values-store write lock
    /// cannot be acquired or is poisoned, if the buffer mutex is poisoned, or if
    /// a cap-triggered flush fails.
    pub(super) fn ensure_value_blob_buffered(
        &self,
        key: PersistBlobKey,
        payload: &[u8],
    ) -> Result<PersistBlobIndexEntry, PersistBlobIndexedWriteError> {
        let (_advisory_guard, _write_guard) = self.lock_indexed_blob_write(key.store())?;
        // On-disk dedup: an already-durable identical record reuses its location.
        if let Ok(Some(location)) = self.lookup_blob_location(key) {
            let pack = self.blob_pack(key.store());
            if matches!(pack.payload_matches(location, key.hash(), payload), Ok(true)) {
                return Ok(PersistBlobIndexEntry::new(key, location));
            }
        }
        let should_flush = {
            let mut batch = self.lock_pending_value_blobs()?;
            if batch.by_key.contains_key(&key) {
                batch.buffered_miss_recompute = batch.buffered_miss_recompute.saturating_add(1);
                return Ok(PersistBlobIndexEntry::new(
                    key,
                    deferred_value_location(payload.len()),
                ));
            }
            batch.by_key.insert(key, payload.to_vec());
            batch.order.push(key);
            batch.bytes = batch.bytes.saturating_add(payload.len());
            batch.buffered_bytes_total =
                batch.buffered_bytes_total.saturating_add(payload.len() as u64);
            batch.bytes >= WRITE_BEHIND_FLUSH_BYTES
        };
        if should_flush {
            self.flush_buffered_value_blobs()?;
        }
        Ok(PersistBlobIndexEntry::new(
            key,
            deferred_value_location(payload.len()),
        ))
    }

    /// Flushes the buffered VALUES-store records to the pack and sidecar index.
    ///
    /// Opens/flocks the values pack once, appends every buffered payload with a
    /// single batched write recording real offsets, then writes all blob-index
    /// entries — all under the held values-store write lock, so the
    /// append→index-entry window stays inside the lock and no repack can
    /// interleave. A no-op when the buffer is empty.
    ///
    /// # Errors
    ///
    /// Returns [`PersistBlobIndexedWriteError`] if the values-store write lock or
    /// buffer mutex is poisoned, or if the batched pack append or index write
    /// fails.
    pub fn flush_buffered_value_blobs(&self) -> Result<(), PersistBlobIndexedWriteError> {
        let (_advisory_guard, _write_guard) =
            self.lock_indexed_blob_write(PersistBlobStore::Values)?;
        let drained: Vec<(PersistBlobKey, Vec<u8>)> = {
            let mut batch = self.lock_pending_value_blobs()?;
            if batch.order.is_empty() {
                return Ok(());
            }
            let order = std::mem::take(&mut batch.order);
            batch.bytes = 0;
            order
                .into_iter()
                .filter_map(|key| batch.by_key.remove(&key).map(|payload| (key, payload)))
                .collect()
        };
        let pack_records: Vec<(DurableBlake3Hash, &[u8])> = drained
            .iter()
            .map(|(key, payload)| (key.hash(), payload.as_slice()))
            .collect();
        let locations = self
            .blob_pack(PersistBlobStore::Values)
            .append_blobs_batch(&pack_records)
            .map_err(|source| PersistBlobIndexedWriteError::Append { source })?;
        let entries: Vec<PersistBlobIndexEntry> = drained
            .iter()
            .zip(locations)
            .map(|((key, _), location)| PersistBlobIndexEntry::new(*key, location))
            .collect();
        self.blob_index(PersistBlobStore::Values)
            .append_entries_batch(&entries)
            .map_err(|source| PersistBlobIndexedWriteError::Index { source })?;
        Ok(())
    }

    fn lock_pending_value_blobs(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, PendingValueBatch>, PersistBlobIndexedWriteError> {
        self.pending_value_blobs
            .lock()
            .map_err(|_| PersistBlobIndexedWriteError::PendingValueBufferPoisoned)
    }

    /// Returns the cumulative buffered value bytes (memory-scoreboard counter).
    pub fn write_behind_buffered_bytes(&self) -> u64 {
        self.pending_value_blobs
            .lock()
            .map_or(0, |batch| batch.buffered_bytes_total)
    }

    /// Returns the within-run buffered-miss recompute count.
    pub fn write_behind_buffered_miss_recompute(&self) -> u64 {
        self.pending_value_blobs
            .lock()
            .map_or(0, |batch| batch.buffered_miss_recompute)
    }

    /// Returns whether the buffer currently holds any unflushed records.
    #[cfg(test)]
    pub(crate) fn write_behind_buffer_is_empty(&self) -> bool {
        self.pending_value_blobs
            .lock()
            .map_or(true, |batch| batch.order.is_empty())
    }
}

/// The deferred sentinel location returned for a buffered (unflushed) value.
///
/// The value materialize caller consumes only the Materialized/Skipped
/// distinction; this location is never read. The `u64::MAX` offset makes any
/// accidental read fail loudly rather than silently return wrong bytes.
const fn deferred_value_location(payload_len: usize) -> PersistBlobLocation {
    PersistBlobLocation::new(u64::MAX, payload_len as u64)
}

/// Returns whether the VALUES-store write-behind buffer is enabled by the
/// `AOS_NIX_CACHE_WRITE_BEHIND` environment knob (`1`/`true` enables it).
///
/// Off by default. The buffer only changes *when* value records reach disk
/// (batched at the run boundary instead of inline), never the bytes written, so
/// this is a pure write-side toggle that does not affect eval results.
pub(super) fn write_behind_values_from_env() -> bool {
    std::env::var("AOS_NIX_CACHE_WRITE_BEHIND")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
