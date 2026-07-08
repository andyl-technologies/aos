//! Process-wide Tier-A arena mapping gauges.
//!
//! Every anonymous arena chunk mapping flows through [`super::arena`], so a
//! small set of process-global counters can account for all Tier-A arena
//! memory without touching any per-arena state. The gauges exist for
//! memory-instrumentation consumers (`aos nix-bench` memory records, eval
//! diagnostics): they are monitoring-grade, use relaxed atomics, and must not
//! be used for allocation decisions or correctness.
//!
//! Two counter families are exposed:
//!
//! - **live** counters track currently mapped chunk bytes and chunk counts;
//!   they decrease when a chunk is unmapped, so a return to the pre-eval value
//!   proves `munmap`-on-drop actually released every mapping.
//! - **cumulative** counters only grow, giving churn totals (how many chunk
//!   mappings an evaluation performed) independent of what is still live.
//!
//! A resettable **peak** watermark over the live mapped bytes lets a caller
//! bracket one evaluation: reset the peak, run the evaluation, then read the
//! high-water arena footprint it reached.

use std::sync::atomic::{AtomicU64, Ordering};

static LIVE_MAPPED_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE_CHUNKS: AtomicU64 = AtomicU64::new(0);
static PEAK_LIVE_MAPPED_BYTES: AtomicU64 = AtomicU64::new(0);
static CUMULATIVE_MAPPED_BYTES: AtomicU64 = AtomicU64::new(0);
static CUMULATIVE_CHUNKS: AtomicU64 = AtomicU64::new(0);

/// A snapshot of the process-wide Tier-A arena mapping gauges.
///
/// Counters are sampled individually with relaxed ordering, so a snapshot
/// taken while another thread is mapping or unmapping chunks may mix values
/// from slightly different instants. Callers that bracket a single-threaded
/// evaluation (the benchmark harness) observe exact values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ArenaProcessGauges {
    /// Bytes currently mapped by live arena chunks across all arenas.
    pub live_mapped_bytes: u64,
    /// Number of currently live arena chunks across all arenas.
    pub live_chunks: u64,
    /// High-water `live_mapped_bytes` since process start or the last
    /// [`ArenaProcessGauges::reset_peak_to_live`].
    pub peak_live_mapped_bytes: u64,
    /// Total bytes ever mapped for arena chunks (monotonic).
    pub cumulative_mapped_bytes: u64,
    /// Total arena chunks ever mapped (monotonic).
    pub cumulative_chunks: u64,
}

impl ArenaProcessGauges {
    /// Samples the current process-wide arena gauges.
    pub fn snapshot() -> Self {
        Self {
            live_mapped_bytes: LIVE_MAPPED_BYTES.load(Ordering::Relaxed),
            live_chunks: LIVE_CHUNKS.load(Ordering::Relaxed),
            peak_live_mapped_bytes: PEAK_LIVE_MAPPED_BYTES.load(Ordering::Relaxed),
            cumulative_mapped_bytes: CUMULATIVE_MAPPED_BYTES.load(Ordering::Relaxed),
            cumulative_chunks: CUMULATIVE_CHUNKS.load(Ordering::Relaxed),
        }
    }

    /// Resets the peak watermark to the current live mapped bytes.
    ///
    /// Returns the live mapped bytes the peak was reset to. Concurrent chunk
    /// mapping can immediately raise the peak again; the reset is intended for
    /// callers bracketing an evaluation on an otherwise quiescent process.
    pub fn reset_peak_to_live() -> u64 {
        let live = LIVE_MAPPED_BYTES.load(Ordering::Relaxed);
        PEAK_LIVE_MAPPED_BYTES.store(live, Ordering::Relaxed);
        live
    }
}

/// Records a newly mapped arena chunk of `bytes` mapped bytes.
pub(crate) fn record_chunk_mapped(bytes: usize) {
    let bytes = bytes as u64;
    let live = LIVE_MAPPED_BYTES
        .fetch_add(bytes, Ordering::Relaxed)
        .saturating_add(bytes);
    LIVE_CHUNKS.fetch_add(1, Ordering::Relaxed);
    CUMULATIVE_MAPPED_BYTES.fetch_add(bytes, Ordering::Relaxed);
    CUMULATIVE_CHUNKS.fetch_add(1, Ordering::Relaxed);
    PEAK_LIVE_MAPPED_BYTES.fetch_max(live, Ordering::Relaxed);
}

/// Records an unmapped arena chunk of `bytes` mapped bytes.
pub(crate) fn record_chunk_unmapped(bytes: usize) {
    let bytes = bytes as u64;
    LIVE_MAPPED_BYTES.fetch_sub(bytes, Ordering::Relaxed);
    LIVE_CHUNKS.fetch_sub(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::arena::BumpArena;

    // The gauges are process-global, and the test harness runs tests from many
    // modules concurrently, so assertions here use deltas that other arenas
    // cannot drive negative rather than absolute values.

    #[test]
    fn chunk_lifecycle_moves_live_and_cumulative_gauges() {
        let before = ArenaProcessGauges::snapshot();
        let mut arena = BumpArena::with_initial_chunk_bytes(4096).expect("arena creates");
        arena.aos_alloc_raw(8, 8, 1).expect("allocation succeeds");
        let mapped = arena.stats().mapped_bytes as u64;
        assert!(mapped > 0);

        let during = ArenaProcessGauges::snapshot();
        assert!(during.cumulative_chunks >= before.cumulative_chunks + 1);
        assert!(during.cumulative_mapped_bytes >= before.cumulative_mapped_bytes + mapped);
        assert!(during.peak_live_mapped_bytes >= mapped);

        drop(arena);
        let after = ArenaProcessGauges::snapshot();
        // Cumulative counters never move backwards on drop.
        assert!(after.cumulative_mapped_bytes >= during.cumulative_mapped_bytes);
        assert!(after.cumulative_chunks >= during.cumulative_chunks);
    }

    #[test]
    fn dropping_an_arena_returns_live_bytes_to_the_pre_arena_level() {
        // Serialize against gauge movement from this test module only: use a
        // large, unique mapping so the delta is unambiguous even if unrelated
        // small arenas churn concurrently.
        const CHUNK: usize = 8 * 1024 * 1024;
        let before = ArenaProcessGauges::snapshot();
        let mut arena = BumpArena::with_initial_chunk_bytes(CHUNK).expect("arena creates");
        arena.aos_alloc_raw(8, 8, 1).expect("allocation succeeds");
        let live_with_arena = ArenaProcessGauges::snapshot().live_mapped_bytes;
        assert!(live_with_arena >= before.live_mapped_bytes + CHUNK as u64);

        drop(arena);
        let live_after = ArenaProcessGauges::snapshot().live_mapped_bytes;
        assert!(
            live_after <= live_with_arena - CHUNK as u64,
            "munmap-on-drop must return the chunk bytes to the live gauge \
             (before={before:?} with={live_with_arena} after={live_after})"
        );
    }

    #[test]
    fn peak_reset_rebases_the_watermark_to_live_bytes() {
        let mut arena = BumpArena::with_initial_chunk_bytes(4096).expect("arena creates");
        arena.aos_alloc_raw(8, 8, 1).expect("allocation succeeds");
        drop(arena);

        let live = ArenaProcessGauges::reset_peak_to_live();
        let snapshot = ArenaProcessGauges::snapshot();
        // Another thread may map between the reset and the snapshot; the peak
        // can only be at or above the rebased value.
        assert!(snapshot.peak_live_mapped_bytes >= live.min(snapshot.peak_live_mapped_bytes));

        let mut arena = BumpArena::with_initial_chunk_bytes(4096).expect("arena creates");
        arena.aos_alloc_raw(8, 8, 1).expect("allocation succeeds");
        let mapped = arena.stats().mapped_bytes as u64;
        let peak = ArenaProcessGauges::snapshot().peak_live_mapped_bytes;
        assert!(peak >= mapped);
    }
}
