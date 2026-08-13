//! Shared in-memory tail-reload index for append-only sidecars.
//!
//! The persistent cache's sidecar engines are append-only: a key's newest record
//! wins on lookup. Re-decoding the whole file on every lookup made warm
//! evaluation scan-bound. This module keeps the decoded newest record per key
//! resident in memory so lookups are `O(log n)` map probes, while staying
//! coherent with the on-disk file — including writes made by other handles or
//! processes — through a tail reload keyed on the byte offset already consumed.
//!
//! [`LatestIndex`] holds the map plus `loaded_offset`, the file length consumed
//! at the last load. A caller refreshes before serving: it cheaply stats the
//! file, and
//!
//! - if the length is unchanged, serves straight from the map;
//! - if the length grew, decodes only the new tail `[loaded_offset..len]` and
//!   folds it in (append-only makes this exact);
//! - if the length shrank, the file was rewritten (compaction/repack), so it
//!   fully reloads from `0`.
//!
//! [`LatestIndex::mark_stale`] forces the next refresh to fully reload even when
//! the length is unchanged, which a same-length rewrite (for example a blob
//! index repack that only rewrites offsets) requires.
//!
//! Clones share the state through an [`Arc`], so every handle opened onto one
//! sidecar within a process observes the same map. The decode itself lives in
//! the caller (it owns the record format); this type only does the map and
//! offset bookkeeping under one lock, so a refresh is atomic against concurrent
//! lookups on the same handle.
//!
//! [`SidecarStats`] holds always-on lookup and records-scanned counters. A
//! regression that reintroduces per-lookup scanning shows up as records-scanned
//! climbing with lookups rather than staying near the load count.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Always-on lookup and records-scanned counters for one sidecar index.
///
/// Counters use [`Ordering::Relaxed`]; they are diagnostics, not
/// synchronization. `records_scanned` counts records decoded while (re)loading
/// the sidecar into memory, and `lookups` counts map probes. A healthy index
/// shows `records_scanned` growing only with the physical record count, not with
/// lookups.
#[derive(Debug, Default)]
pub struct SidecarStats {
    lookups: AtomicU64,
    records_scanned: AtomicU64,
}

impl SidecarStats {
    fn record_lookup(&self) {
        self.lookups.fetch_add(1, Ordering::Relaxed);
    }

    fn add_records_scanned(&self, records: u64) {
        self.records_scanned.fetch_add(records, Ordering::Relaxed);
    }

    /// Returns the number of lookups served since the index was opened.
    pub fn lookups(&self) -> u64 {
        self.lookups.load(Ordering::Relaxed)
    }

    /// Returns the number of records decoded while (re)loading the index.
    pub fn records_scanned(&self) -> u64 {
        self.records_scanned.load(Ordering::Relaxed)
    }

    /// Returns a point-in-time copy of both counters.
    pub fn snapshot(&self) -> SidecarStatsSnapshot {
        SidecarStatsSnapshot {
            lookups: self.lookups(),
            records_scanned: self.records_scanned(),
        }
    }
}

/// A point-in-time copy of a [`SidecarStats`] pair.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SidecarStatsSnapshot {
    /// The number of lookups served since the index was opened.
    pub lookups: u64,
    /// The number of records decoded while (re)loading the index.
    pub records_scanned: u64,
}

/// A sentinel `loaded_offset` that forces the next refresh to fully reload.
///
/// Any real file length is below `u64::MAX`, so a refresh sees `len < offset`
/// and reloads from `0`.
const FORCE_RELOAD_OFFSET: u64 = u64::MAX;

#[derive(Debug)]
struct LatestIndexState<K, V> {
    latest: BTreeMap<K, V>,
    loaded_offset: u64,
    record_count: u64,
}

/// The action a refresh must take, decided from the current file length.
enum RefreshPlan {
    /// The file is unchanged; serve from the map.
    UpToDate,
    /// The file grew; decode the tail starting at this byte offset.
    Tail(u64),
    /// The file shrank or was invalidated; fully reload from `0`.
    Full,
}

/// An in-memory newest-record-wins map over an append-only sidecar, refreshed
/// from the file by consuming only the newly appended tail.
pub struct LatestIndex<K, V> {
    state: Arc<Mutex<LatestIndexState<K, V>>>,
    stats: Arc<SidecarStats>,
}

impl<K, V> Clone for LatestIndex<K, V> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            stats: Arc::clone(&self.stats),
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for LatestIndex<K, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        formatter
            .debug_struct("LatestIndex")
            .field("live_keys", &state.latest.len())
            .field("loaded_offset", &state.loaded_offset)
            .field("record_count", &state.record_count)
            .finish()
    }
}

impl<K, V> Default for LatestIndex<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> LatestIndex<K, V> {
    /// Creates an empty index with nothing loaded yet.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(LatestIndexState {
                latest: BTreeMap::new(),
                loaded_offset: 0,
                record_count: 0,
            })),
            stats: Arc::new(SidecarStats::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, LatestIndexState<K, V>> {
        // A panic can only unwind here across a `BTreeMap` insert or clone,
        // neither of which leaves the map logically inconsistent, so recovering
        // the guard from a poisoned lock is safe and avoids cascading a poison
        // error type through every sidecar operation.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the always-on lookup and records-scanned counters.
    pub fn stats(&self) -> &SidecarStats {
        &self.stats
    }

    /// Marks the index stale so the next refresh fully reloads from the file.
    ///
    /// Callers use this after rewriting the whole sidecar (compaction or repack),
    /// which can leave the file the same length with different contents.
    pub fn mark_stale(&self) {
        self.lock().loaded_offset = FORCE_RELOAD_OFFSET;
    }
}

impl<K: Ord + Clone, V: Clone> LatestIndex<K, V> {
    /// Returns the newest value recorded for `key`, if any.
    ///
    /// Serves from the resident map and performs no file access; callers must
    /// have refreshed first for the answer to reflect other writers. Each call
    /// increments the lookup counter.
    pub fn get(&self, key: &K) -> Option<V> {
        self.stats.record_lookup();
        self.lock().latest.get(key).cloned()
    }

    /// Returns the newest key/value pair for every live key in key order.
    pub fn latest_pairs(&self) -> Vec<(K, V)> {
        self.lock()
            .latest
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    /// Returns the newest value for every live key in key order.
    pub fn latest_values(&self) -> Vec<V> {
        self.lock().latest.values().cloned().collect()
    }

    /// Returns the number of physical records folded in since the last reload.
    pub fn record_count(&self) -> u64 {
        self.lock().record_count
    }

    /// Returns the number of live keys currently in the map.
    pub fn live_key_count(&self) -> usize {
        self.lock().latest.len()
    }

    /// Returns whether the file has bloated past `factor` times the live keys.
    pub fn is_bloated(&self, factor: u64) -> bool {
        let state = self.lock();
        let live = state.latest.len() as u64;
        live > 0 && state.record_count > factor.saturating_mul(live)
    }

    /// Refreshes the map from the file, decoding only what is needed.
    ///
    /// `current_len` is the file's current byte length (a cheap stat by the
    /// caller). `read` decodes records in physical order from a byte offset,
    /// returning the decoded `(key, value)` pairs and the byte offset one past
    /// the last record read; it is called with `0` for a full reload or with the
    /// current `loaded_offset` for a tail read, and never called when the file is
    /// unchanged. Later pairs win for a repeated key.
    ///
    /// # Errors
    ///
    /// Returns any error `read` returns; the map and offset are left unchanged in
    /// that case.
    pub fn refresh_with<F, E>(&self, current_len: u64, read: F) -> Result<(), E>
    where
        F: FnOnce(u64) -> Result<(Vec<(K, V)>, u64), E>,
    {
        let mut state = self.lock();
        match refresh_plan(current_len, state.loaded_offset) {
            RefreshPlan::UpToDate => Ok(()),
            RefreshPlan::Tail(offset) => {
                let (records, end) = read(offset)?;
                self.stats.add_records_scanned(records.len() as u64);
                state.record_count = state.record_count.saturating_add(records.len() as u64);
                for (key, value) in records {
                    state.latest.insert(key, value);
                }
                state.loaded_offset = end;
                Ok(())
            }
            RefreshPlan::Full => {
                let (records, end) = read(0)?;
                self.stats.add_records_scanned(records.len() as u64);
                let record_count = records.len() as u64;
                state.latest = records.into_iter().collect();
                state.record_count = record_count;
                state.loaded_offset = end;
                Ok(())
            }
        }
    }
}

fn refresh_plan(current_len: u64, loaded_offset: u64) -> RefreshPlan {
    if loaded_offset != FORCE_RELOAD_OFFSET && current_len == loaded_offset {
        RefreshPlan::UpToDate
    } else if current_len < loaded_offset {
        RefreshPlan::Full
    } else {
        RefreshPlan::Tail(loaded_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake append-only file of `(key, value)` records for exercising refresh.
    #[derive(Default)]
    struct FakeLog {
        records: Vec<(u8, u8)>,
    }

    impl FakeLog {
        fn len(&self) -> u64 {
            self.records.len() as u64
        }

        fn read_from(&self, offset: u64) -> Result<(Vec<(u8, u8)>, u64), &'static str> {
            let start = offset as usize;
            Ok((self.records[start..].to_vec(), self.records.len() as u64))
        }
    }

    fn refresh(index: &LatestIndex<u8, u8>, log: &FakeLog) {
        index
            .refresh_with(log.len(), |from| log.read_from(from))
            .expect("refresh succeeds");
    }

    #[test]
    fn refresh_full_loads_newest_value_per_key() {
        let index = LatestIndex::new();
        let log = FakeLog {
            records: vec![(1, 10), (2, 20), (1, 11)],
        };
        refresh(&index, &log);

        assert_eq!(index.get(&1), Some(11));
        assert_eq!(index.get(&2), Some(20));
        assert_eq!(index.get(&3), None);
        assert_eq!(index.record_count(), 3);
        assert_eq!(index.live_key_count(), 2);
        assert_eq!(index.latest_pairs(), [(1, 11), (2, 20)]);
    }

    #[test]
    fn refresh_reads_only_the_appended_tail() {
        let index = LatestIndex::new();
        let mut log = FakeLog {
            records: vec![(1, 10)],
        };
        refresh(&index, &log);
        assert_eq!(index.stats().records_scanned(), 1);

        log.records.push((2, 20));
        log.records.push((1, 11));
        refresh(&index, &log);

        // Only the two tail records were decoded on the second refresh.
        assert_eq!(index.stats().records_scanned(), 3);
        assert_eq!(index.get(&1), Some(11));
        assert_eq!(index.get(&2), Some(20));
        assert_eq!(index.record_count(), 3);
    }

    #[test]
    fn refresh_unchanged_length_serves_from_map() {
        let index = LatestIndex::new();
        let log = FakeLog {
            records: vec![(1, 10)],
        };
        refresh(&index, &log);
        refresh(&index, &log);

        assert_eq!(index.stats().records_scanned(), 1);
    }

    #[test]
    fn refresh_shorter_file_triggers_full_reload() {
        let index = LatestIndex::new();
        let mut log = FakeLog {
            records: vec![(1, 10), (1, 11), (2, 20)],
        };
        refresh(&index, &log);
        // Simulate a compaction that rewrote the file to one record per key.
        log.records = vec![(2, 20)];
        refresh(&index, &log);

        assert_eq!(index.get(&1), None);
        assert_eq!(index.get(&2), Some(20));
        assert_eq!(index.record_count(), 1);
    }

    #[test]
    fn mark_stale_forces_full_reload_at_same_length() {
        let index = LatestIndex::new();
        let mut log = FakeLog {
            records: vec![(1, 10)],
        };
        refresh(&index, &log);
        // Same length, different content (an in-place rewrite).
        log.records = vec![(1, 99)];
        index.mark_stale();
        refresh(&index, &log);

        assert_eq!(index.get(&1), Some(99));
    }

    #[test]
    fn refresh_propagates_decode_errors() {
        let index: LatestIndex<u8, u8> = LatestIndex::new();
        let result = index.refresh_with(4, |_from| Err::<(Vec<(u8, u8)>, u64), _>("bad record"));

        assert_eq!(result, Err("bad record"));
        assert_eq!(index.record_count(), 0);
    }

    #[test]
    fn clone_shares_state() {
        let index = LatestIndex::new();
        let log = FakeLog {
            records: vec![(1, 10)],
        };
        refresh(&index, &log);
        let clone = index.clone();

        assert_eq!(clone.get(&1), Some(10));
    }

    #[test]
    fn bloat_gate_tracks_factor() {
        let index = LatestIndex::new();
        let log = FakeLog {
            records: vec![(1, 10), (1, 11), (2, 20)],
        };
        refresh(&index, &log);

        // 3 records over 2 live keys: not past 2x.
        assert!(!index.is_bloated(2));
        let log = FakeLog {
            records: vec![(1, 10), (1, 11), (1, 12), (2, 20), (2, 21)],
        };
        index.mark_stale();
        refresh(&index, &log);
        // 5 records over 2 live keys: past 2x, not past 4x.
        assert!(index.is_bloated(2));
        assert!(!index.is_bloated(4));
    }
}
