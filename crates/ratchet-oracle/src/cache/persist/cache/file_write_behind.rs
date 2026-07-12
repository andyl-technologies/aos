//! Write-behind buffer for FILES-store file/parse-artifact records (RFC-0007 §3.2(b)).
//!
//! On a cold-populate run the frontend promotes every imported `.nix` file's
//! parse artifact into the persist cache. Each promotion synchronously appends
//! the artifact blob to the `files/` pack, writes its `files/` blob-index entry,
//! and appends the file/parse-artifact mapping — three open + flock + write +
//! flush cycles per file. This buffer coalesces the whole run's promotions:
//! `buffer_*_artifact` pushes the payload and mapping into an in-memory batch and
//! the batch is flushed once at the eval run boundary (strictly before the
//! synchronous root-cutoff record), amortizing the open/flock/flush across the
//! run.
//!
//! # No pending GC root
//!
//! The synchronous indexed path anchors a freshly appended `files/` blob's
//! liveness with its `files/` blob-index entry (the `BlobIndex` root source in
//! [`PersistCache::snapshot_blob_live_roots`](super::PersistCache)); the legacy
//! non-indexed path instead registers an in-process pending file-artifact root.
//! This buffer takes neither on the eval path: **nothing durable exists until
//! flush**. The flush writes the blob and its blob-index entry *before* the
//! artifact mapping, so the blob-index entry roots the blob the instant it
//! reaches disk and no `append → index-entry` window ever opens for a
//! concurrent repack (the #25 increment-0 contract, extended to the FILES
//! store).
//!
//! # Crash windows (all benign)
//!
//! * **Before flush** — the batch is memory only, so no blob, no blob-index, no
//!   mapping reach disk. Reopen sees a clean miss and re-promotes.
//! * **Mid-flush, torn pack tail** — a torn `files/` record is rejected by the
//!   pack's per-record integrity header on read, and its blob-index and mapping
//!   entries (written after the append) never landed, so it is a clean miss.
//! * **After the blob append but before the two index writes** — the orphan
//!   blob bytes have no blob-index entry, so a later repack (explicit
//!   maintenance, never on the eval path) reaps them as unrooted garbage. That
//!   is benign: the mapping was never published, so nothing can reference the
//!   orphan; reaping it only reclaims space.
//! * **After the blob-index write but before the mapping write** — the blob is
//!   durable and rooted by its blob-index entry (repack keeps it) but has no
//!   artifact mapping; a lookup misses cleanly and a later identical promotion
//!   dedups against the already-durable blob.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Flush mid-run once buffered payloads reach this many bytes, matching the
/// value buffer's cap so both write-behind buffers share the wide-eval RSS
/// budget.
const WRITE_BEHIND_FLUSH_BYTES: usize = 8 * 1024 * 1024;

/// Which artifact sidecar a buffered mapping targets.
#[derive(Debug)]
enum PendingArtifactMapping {
    /// A file-artifact mapping keyed by file identity plus parse key.
    File(PersistFileArtifactKey),
    /// A parse-artifact mapping keyed by parse key alone.
    Parse(PersistParseArtifactKey),
}

/// One buffered artifact mapping and the `files/` blob it references.
#[derive(Debug)]
struct PendingArtifactRecord {
    blob_hash: PersistFileBlobHash,
    mapping: PendingArtifactMapping,
}

/// An in-memory batch of FILES-store artifact records awaiting a run-boundary flush.
#[derive(Debug, Default)]
pub(super) struct PendingFileArtifactBatch {
    /// Dedup'd `files/` blob payloads keyed by content hash; multiple mappings
    /// may reference one blob, so the payload is stored once.
    blobs_by_hash: BTreeMap<PersistFileBlobHash, Vec<u8>>,
    /// Buffered mappings in insertion order, giving a deterministic flush order.
    records: Vec<PendingArtifactRecord>,
    /// Encoded file-artifact keys already buffered, so one mapping is emitted per key.
    buffered_file_keys: BTreeSet<Vec<u8>>,
    /// Encoded parse-artifact keys already buffered, so one mapping is emitted per key.
    buffered_parse_keys: BTreeSet<Vec<u8>>,
    /// Currently buffered payload bytes (drives the mid-run flush cap).
    bytes: usize,
    /// Cumulative buffered payload bytes this process (a memory-scoreboard counter).
    buffered_bytes_total: u64,
    /// Count of within-run re-promotions of an already-buffered artifact — its
    /// buffered state cost it a within-run mapping and forced a recompute.
    buffered_miss_recompute: u64,
}

impl PersistCache {
    /// Returns whether the FILES-store file/parse-artifact write-behind buffer is
    /// active. Driven by the same flag as the value buffer: the single
    /// `AOS_NIX_CACHE_WRITE_BEHIND` knob gates both stores.
    pub(super) const fn write_behind_files_enabled(&self) -> bool {
        self.write_behind_values
    }

    /// Buffers a file-artifact promotion for the run-boundary flush.
    ///
    /// Returns a [`PersistFileArtifactMaterialization::Materialized`] whose index
    /// value carries a deferred sentinel location; the eval-path caller consumes
    /// only the Materialized/Skipped distinction, never the location.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactIndexedWriteError::Flush`] if the buffer mutex
    /// is poisoned or a cap-triggered flush fails.
    pub(super) fn buffer_file_artifact(
        &self,
        artifact_key: PersistFileArtifactKey,
        payload: &[u8],
    ) -> Result<PersistFileArtifactMaterialization, PersistFileArtifactIndexedWriteError> {
        let blob_hash = PersistFileBlobHash::for_payload(payload);
        let should_flush = self
            .buffer_artifact_record(
                blob_hash,
                payload,
                PendingArtifactMapping::File(artifact_key),
                DedupKind::File(artifact_key.index_bytes().to_vec()),
            )
            .map_err(|source| PersistFileArtifactIndexedWriteError::Flush { source })?;
        if should_flush {
            self.flush_buffered_file_artifacts()
                .map_err(|source| PersistFileArtifactIndexedWriteError::Flush { source })?;
        }
        Ok(PersistFileArtifactMaterialization::Materialized {
            artifact_key,
            index_value: PersistFileArtifactIndexValue::new(
                blob_hash,
                deferred_file_location(payload.len()),
            ),
        })
    }

    /// Buffers a parse-artifact promotion for the run-boundary flush.
    ///
    /// Returns a [`PersistParseArtifactMaterialization::Materialized`] whose index
    /// value carries a deferred sentinel location; the eval-path caller consumes
    /// only the Materialized/Skipped distinction, never the location.
    ///
    /// # Errors
    ///
    /// Returns [`PersistParseArtifactIndexedWriteError::Flush`] if the buffer
    /// mutex is poisoned or a cap-triggered flush fails.
    pub(super) fn buffer_parse_artifact(
        &self,
        artifact_key: PersistParseArtifactKey,
        payload: &[u8],
    ) -> Result<PersistParseArtifactMaterialization, PersistParseArtifactIndexedWriteError> {
        let blob_hash = PersistFileBlobHash::for_payload(payload);
        let should_flush = self
            .buffer_artifact_record(
                blob_hash,
                payload,
                PendingArtifactMapping::Parse(artifact_key),
                DedupKind::Parse(artifact_key.index_bytes().to_vec()),
            )
            .map_err(|source| PersistParseArtifactIndexedWriteError::Flush { source })?;
        if should_flush {
            self.flush_buffered_file_artifacts()
                .map_err(|source| PersistParseArtifactIndexedWriteError::Flush { source })?;
        }
        Ok(PersistParseArtifactMaterialization::Materialized {
            artifact_key,
            index_value: PersistParseArtifactIndexValue::new(
                blob_hash,
                deferred_file_location(payload.len()),
            ),
        })
    }

    /// Pushes one artifact record into the buffer, returning whether the byte cap
    /// was reached and a flush should follow.
    fn buffer_artifact_record(
        &self,
        blob_hash: PersistFileBlobHash,
        payload: &[u8],
        mapping: PendingArtifactMapping,
        dedup: DedupKind,
    ) -> Result<bool, PersistFileArtifactFlushError> {
        let mut batch = self.lock_pending_file_artifacts()?;
        let newly_buffered = match &dedup {
            DedupKind::File(encoded) => batch.buffered_file_keys.insert(encoded.clone()),
            DedupKind::Parse(encoded) => batch.buffered_parse_keys.insert(encoded.clone()),
        };
        if !newly_buffered {
            batch.buffered_miss_recompute = batch.buffered_miss_recompute.saturating_add(1);
            return Ok(false);
        }
        batch.records.push(PendingArtifactRecord { blob_hash, mapping });
        if let std::collections::btree_map::Entry::Vacant(slot) = batch.blobs_by_hash.entry(blob_hash)
        {
            slot.insert(payload.to_vec());
            batch.bytes = batch.bytes.saturating_add(payload.len());
            batch.buffered_bytes_total =
                batch.buffered_bytes_total.saturating_add(payload.len() as u64);
        }
        Ok(batch.bytes >= WRITE_BEHIND_FLUSH_BYTES)
    }

    /// Flushes the buffered FILES-store artifact records to the pack and sidecars.
    ///
    /// The blobs are appended and blob-indexed together under the `files/` store
    /// write lock (through [`Self::ensure_blobs_indexed_batch`]), then the
    /// resolved locations are written into the file- and parse-artifact sidecars.
    /// Blobs and their blob-index entries always reach disk before the mappings,
    /// so every crash window is a clean miss or benign orphan (see the module
    /// docs). A no-op when the buffer is empty.
    ///
    /// # Errors
    ///
    /// Returns [`PersistFileArtifactFlushError`] if the buffer mutex is poisoned,
    /// or if the batched blob, file-artifact, or parse-artifact write fails.
    pub fn flush_buffered_file_artifacts(&self) -> Result<(), PersistFileArtifactFlushError> {
        let (blobs, records) = {
            let mut batch = self.lock_pending_file_artifacts()?;
            if batch.records.is_empty() {
                return Ok(());
            }
            let blobs = std::mem::take(&mut batch.blobs_by_hash);
            let records = std::mem::take(&mut batch.records);
            batch.buffered_file_keys.clear();
            batch.buffered_parse_keys.clear();
            batch.bytes = 0;
            (blobs, records)
        };
        // Phase 1: append every buffered blob and write its `files/` blob-index
        // entry under the held `files/` store write lock.
        let blob_records: Vec<(PersistBlobKey, &[u8])> = blobs
            .iter()
            .map(|(hash, payload)| (PersistBlobKey::for_file(*hash), payload.as_slice()))
            .collect();
        let locations = self
            .ensure_blobs_indexed_batch(PersistBlobStore::Files, &blob_records)
            .map_err(|source| PersistFileArtifactFlushError::Blob { source })?;
        // Phase 2: publish the artifact mappings with their resolved locations.
        let mut file_entries = Vec::new();
        let mut parse_entries = Vec::new();
        for record in &records {
            let blob_key = PersistBlobKey::for_file(record.blob_hash);
            let Some(location) = locations.get(&blob_key).copied() else {
                continue;
            };
            match record.mapping {
                PendingArtifactMapping::File(artifact_key) => {
                    let value = PersistFileArtifactIndexValue::new(record.blob_hash, location);
                    file_entries.push(PersistFileArtifactIndexEntry::new(artifact_key, value));
                }
                PendingArtifactMapping::Parse(artifact_key) => {
                    let value = PersistParseArtifactIndexValue::new(record.blob_hash, location);
                    parse_entries.push(PersistParseArtifactIndexEntry::new(artifact_key, value));
                }
            }
        }
        if !file_entries.is_empty() {
            let (_advisory_guard, _write_guard) = self
                .lock_file_artifact_write()
                .map_err(|source| PersistFileArtifactFlushError::FileIndex { source })?;
            self.file_artifact_index
                .append_entries_batch(&file_entries)
                .map_err(|source| PersistFileArtifactFlushError::FileIndex { source })?;
        }
        if !parse_entries.is_empty() {
            let (_advisory_guard, _write_guard) = self
                .lock_parse_artifact_write()
                .map_err(|source| PersistFileArtifactFlushError::ParseIndex { source })?;
            self.parse_artifact_index
                .append_entries_batch(&parse_entries)
                .map_err(|source| PersistFileArtifactFlushError::ParseIndex { source })?;
        }
        Ok(())
    }

    /// Flushes both write-behind buffers (RFC-0007 §3.2(b)) at the eval run
    /// boundary and logs their memory-scoreboard counters.
    ///
    /// The value buffer flushes first, then the file/parse-artifact buffer, both
    /// strictly before the synchronous root-cutoff record (native/mod.rs): each
    /// batched flush writes a blob and its blob-index entry before any mapping or
    /// root, so the root-cutoff never references an unflushed or unindexed blob.
    /// Flush errors are logged, not propagated — a failed batch is a re-eval, not
    /// a corrupt cache.
    pub fn flush_write_behind_at_run_boundary(&self) {
        if let Err(error) = self.flush_buffered_value_blobs() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator value write-behind flush failed"
            );
        }
        let value_bytes = self.write_behind_buffered_bytes();
        if value_bytes > 0 {
            tracing::info!(
                target: "aos_nix::cache",
                write_behind_buffered_bytes = value_bytes,
                write_behind_buffered_miss_recompute = self.write_behind_buffered_miss_recompute(),
                "value write-behind counters"
            );
        }
        if let Err(error) = self.flush_buffered_file_artifacts() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator file-artifact write-behind flush failed"
            );
        }
        let file_bytes = self.write_behind_file_buffered_bytes();
        if file_bytes > 0 {
            tracing::info!(
                target: "aos_nix::cache",
                write_behind_file_buffered_bytes = file_bytes,
                write_behind_file_buffered_miss_recompute =
                    self.write_behind_file_buffered_miss_recompute(),
                "file-artifact write-behind counters"
            );
        }
    }

    /// Flushes the file-artifact buffer when the last handle to this root is
    /// dropped, mirroring the value buffer's final-handle safety net for callers
    /// that drive the cache without advancing a run boundary. Errors are logged
    /// rather than propagated because a destructor cannot return them.
    pub(super) fn flush_file_artifacts_on_final_drop(&self) {
        if Arc::strong_count(&self.pending_file_artifacts) != 1 {
            return;
        }
        if let Err(error) = self.flush_buffered_file_artifacts() {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "persistent eval cache file-artifact write-behind flush on drop failed"
            );
        }
    }

    fn lock_pending_file_artifacts(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, PendingFileArtifactBatch>, PersistFileArtifactFlushError>
    {
        self.pending_file_artifacts
            .lock()
            .map_err(|_| PersistFileArtifactFlushError::BufferPoisoned)
    }

    /// Returns the cumulative buffered file-artifact payload bytes (scoreboard counter).
    pub fn write_behind_file_buffered_bytes(&self) -> u64 {
        self.pending_file_artifacts
            .lock()
            .map_or(0, |batch| batch.buffered_bytes_total)
    }

    /// Returns the within-run buffered-miss recompute count for artifacts.
    pub fn write_behind_file_buffered_miss_recompute(&self) -> u64 {
        self.pending_file_artifacts
            .lock()
            .map_or(0, |batch| batch.buffered_miss_recompute)
    }

    /// Returns whether the file-artifact buffer currently holds any unflushed records.
    #[cfg(test)]
    pub(crate) fn write_behind_file_buffer_is_empty(&self) -> bool {
        self.pending_file_artifacts
            .lock()
            .map_or(true, |batch| batch.records.is_empty())
    }
}

/// The encoded artifact key used to dedup within-run re-promotions.
enum DedupKind {
    File(Vec<u8>),
    Parse(Vec<u8>),
}

/// The deferred sentinel location returned for a buffered (unflushed) artifact.
///
/// The eval-path caller consumes only the Materialized/Skipped distinction; this
/// location is never read. The `u64::MAX` offset makes any accidental read fail
/// loudly rather than silently return wrong bytes.
const fn deferred_file_location(payload_len: usize) -> PersistBlobLocation {
    PersistBlobLocation::new(u64::MAX, payload_len as u64)
}
