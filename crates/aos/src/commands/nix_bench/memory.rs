//! Per-sample memory capture for `aos nix-bench`.
//!
//! The native evaluator runs inside the benchmark process, so its memory cost
//! is observed by bracketing each native sample with in-process probes from
//! [`aos_core::nix::native_memory`]: current RSS, the monotonic `getrusage`
//! peak-RSS watermark, and the evaluator's process-wide Tier-A arena mapping
//! gauges. The C++ Nix oracle runs as a child process, so its peak RSS is
//! attributed through the `RUSAGE_CHILDREN` watermark, which only identifies a
//! child's peak when that child raised the watermark.
//!
//! Every probe is optional: builds without `native-eval`, or targets without a
//! resident-memory sampler, capture no memory data and the benchmark records
//! simply omit it.
//!
//! Setting `AOS_NIX_BENCH_MEM_TRACE=1` prints a phase-labelled probe line to
//! stderr at each capture point, which is the decomposition tool for
//! attributing process RSS to benchmark phases. Setting
//! `AOS_NIX_BENCH_MEM_PURGE=1` additionally asks the allocator to release
//! dirty-but-free pages before each native sample (Linux/glibc), isolating
//! each sample's true footprint from earlier evals' freed pages.

use aos_core::nix::{
    NativeArenaGauges, children_peak_rss_bytes, current_rss_bytes, native_arena_gauges,
    peak_rss_bytes, release_free_memory, reset_native_arena_peak,
};

use super::record::{NativeSampleArena, NativeSampleMemory};

/// Probes captured immediately before a native evaluator sample runs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NativeMemoryBefore {
    rss_before_bytes: Option<u64>,
    peak_rss_before_bytes: Option<u64>,
    arena_before: Option<NativeArenaGauges>,
}

impl NativeMemoryBefore {
    /// Captures the pre-sample probes and rebases the arena peak watermark.
    ///
    /// When `AOS_NIX_BENCH_MEM_PURGE=1`, the process allocator is first asked
    /// to return dirty-but-free pages (Linux/glibc only), so each sample's RSS
    /// starts from a clean floor instead of inheriting earlier evals' freed
    /// pages. The purge happens outside the timed window, but the following
    /// eval pays the page-refault cost — purge mode is for memory measurement,
    /// not for timing comparisons against non-purge baselines.
    pub(crate) fn capture() -> Self {
        if mem_purge_enabled() {
            let released = release_free_memory();
            if mem_trace_enabled() {
                eprintln!("aos-nix-bench-mem phase=purge released={released}");
            }
        }
        reset_native_arena_peak();
        Self {
            rss_before_bytes: current_rss_bytes(),
            peak_rss_before_bytes: peak_rss_bytes(),
            arena_before: native_arena_gauges(),
        }
    }

    /// Captures the post-sample probes and folds both into a memory record.
    ///
    /// Returns `None` when no probe produced data (e.g. a build without
    /// `native-eval`).
    pub(crate) fn finish(self) -> Option<NativeSampleMemory> {
        let rss_after_bytes = current_rss_bytes();
        let peak_rss_after_bytes = peak_rss_bytes();
        let arena_after = native_arena_gauges();
        if self.rss_before_bytes.is_none() && rss_after_bytes.is_none() && arena_after.is_none() {
            return None;
        }

        let peak_rss_delta_bytes = match (self.peak_rss_before_bytes, peak_rss_after_bytes) {
            (Some(before), Some(after)) => Some(after.saturating_sub(before)),
            _ => None,
        };
        let arena = match (self.arena_before, arena_after) {
            (Some(before), Some(after)) => Some(NativeSampleArena {
                live_mapped_bytes_before: before.live_mapped_bytes,
                live_mapped_bytes_after: after.live_mapped_bytes,
                peak_live_mapped_bytes: after.peak_live_mapped_bytes,
                live_chunks_after: after.live_chunks,
                chunks_mapped: after.cumulative_chunks.saturating_sub(before.cumulative_chunks),
                bytes_mapped: after
                    .cumulative_mapped_bytes
                    .saturating_sub(before.cumulative_mapped_bytes),
            }),
            _ => None,
        };

        Some(NativeSampleMemory {
            rss_before_bytes: self.rss_before_bytes,
            rss_after_bytes,
            peak_rss_before_bytes: self.peak_rss_before_bytes,
            peak_rss_after_bytes,
            peak_rss_delta_bytes,
            arena,
        })
    }
}

/// The waited-children peak-RSS watermark bracketing one oracle child.
///
/// `RUSAGE_CHILDREN`'s `ru_maxrss` is the maximum over all waited-for
/// children, so a sample's child peak is only known when the watermark rose
/// while that child ran; otherwise the child peaked below an earlier child and
/// its exact peak is unknowable from here.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OracleChildPeakBefore {
    watermark_before: Option<u64>,
}

impl OracleChildPeakBefore {
    /// Captures the children peak-RSS watermark before spawning the child.
    pub(crate) fn capture() -> Self {
        Self {
            watermark_before: children_peak_rss_bytes(),
        }
    }

    /// Attributes the watermark to the child that just exited, if it rose.
    pub(crate) fn finish(self) -> Option<u64> {
        let after = children_peak_rss_bytes()?;
        let before = self.watermark_before?;
        (after > before).then_some(after)
    }
}

/// Returns whether phase-probe tracing is enabled via `AOS_NIX_BENCH_MEM_TRACE`.
fn mem_trace_enabled() -> bool {
    std::env::var("AOS_NIX_BENCH_MEM_TRACE").is_ok_and(|value| value == "1")
}

/// Returns whether pre-sample allocator purging is enabled via
/// `AOS_NIX_BENCH_MEM_PURGE`.
fn mem_purge_enabled() -> bool {
    std::env::var("AOS_NIX_BENCH_MEM_PURGE").is_ok_and(|value| value == "1")
}

/// Prints one phase-labelled memory probe line to stderr when tracing is on.
///
/// This is deliberately stderr (not the [`aos_core::output::Printer`]) so the
/// probe stream can be separated from benchmark output and captured by
/// decomposition tooling.
pub(crate) fn trace_phase(phase: &str) {
    if !mem_trace_enabled() {
        return;
    }
    let rss = current_rss_bytes();
    let peak = peak_rss_bytes();
    let arena = native_arena_gauges();
    let children = children_peak_rss_bytes();
    eprintln!(
        "aos-nix-bench-mem phase={phase} rss={} peak_rss={} children_peak_rss={} \
         arena_live={} arena_peak={} arena_chunks={} arena_cum_bytes={} arena_cum_chunks={}",
        fmt_opt(rss),
        fmt_opt(peak),
        fmt_opt(children),
        fmt_opt(arena.map(|gauges| gauges.live_mapped_bytes)),
        fmt_opt(arena.map(|gauges| gauges.peak_live_mapped_bytes)),
        fmt_opt(arena.map(|gauges| gauges.live_chunks)),
        fmt_opt(arena.map(|gauges| gauges.cumulative_mapped_bytes)),
        fmt_opt(arena.map(|gauges| gauges.cumulative_chunks)),
    );
}

fn fmt_opt(value: Option<u64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| value.to_string())
}

/// Formats a byte count as mebibytes with one decimal for human output.
pub(crate) fn mib(bytes: u64) -> String {
    format!("{:.1}MiB", bytes as f64 / (1024.0 * 1024.0))
}
