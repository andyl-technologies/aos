//! Memory probes for benchmarking the in-process native evaluator.
//!
//! `aos nix-bench` runs the native evaluator inside its own process, so its
//! memory footprint must be observed in-process: current and peak resident-set
//! samples for the benchmark process itself, the `getrusage` children
//! watermark for the spawned C++ Nix oracle, and the native evaluator's
//! process-wide Tier-A arena mapping gauges.
//!
//! Every probe degrades to `None` instead of failing: when the crate is built
//! without the `native-eval` feature there is no in-process evaluator to
//! measure (the "native" candidate is a CLI fallback), and on targets without
//! a resident-memory sampler the platform reports nothing. Callers therefore
//! treat memory data as optional instrumentation, never as a required input.

#[cfg(feature = "native-eval")]
use aos_nix::heap::{
    ArenaProcessGauges, PeakResidentMemoryScope, peak_resident_memory_bytes,
    process_resident_memory_sample, release_free_allocator_memory,
};

/// A snapshot of the native evaluator's process-wide arena mapping gauges.
///
/// Mirrors the Tier-A arena gauges so `aos` commands can record them without
/// naming evaluator-internal types. All byte counts are `mmap`-level mapped
/// bytes, not resident bytes: untouched pages in a mapped chunk cost address
/// space but no RSS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeArenaGauges {
    /// Bytes currently mapped by live arena chunks.
    pub live_mapped_bytes: u64,
    /// Number of currently live arena chunks.
    pub live_chunks: u64,
    /// High-water live mapped bytes since process start or the last
    /// [`reset_native_arena_peak`].
    pub peak_live_mapped_bytes: u64,
    /// Total bytes ever mapped for arena chunks (monotonic).
    pub cumulative_mapped_bytes: u64,
    /// Total arena chunks ever mapped (monotonic).
    pub cumulative_chunks: u64,
}

/// Returns whether this build carries the in-process native evaluator probes.
///
/// `false` means every probe in this module returns `None` by construction
/// (the crate was built without the `native-eval` feature).
pub const fn native_memory_probes_supported() -> bool {
    cfg!(feature = "native-eval")
}

/// Samples the current process resident set in bytes.
///
/// Returns `None` without the `native-eval` feature, on targets without a
/// resident-memory sampler, or when the platform sampler fails.
pub fn current_rss_bytes() -> Option<u64> {
    #[cfg(feature = "native-eval")]
    {
        process_resident_memory_sample()
            .ok()
            .flatten()
            .map(|sample| sample.resident_bytes() as u64)
    }
    #[cfg(not(feature = "native-eval"))]
    {
        None
    }
}

/// Samples this process's peak resident set (`ru_maxrss`) in bytes.
///
/// The watermark is monotonic for the life of the process; bracket an
/// operation with two samples to attribute peak growth to it. Returns `None`
/// without the `native-eval` feature or when the platform has no sampler.
pub fn peak_rss_bytes() -> Option<u64> {
    #[cfg(feature = "native-eval")]
    {
        peak_resident_memory_bytes(PeakResidentMemoryScope::SelfProcess)
            .ok()
            .flatten()
    }
    #[cfg(not(feature = "native-eval"))]
    {
        None
    }
}

/// Samples the waited-children peak resident set (`ru_maxrss`) in bytes.
///
/// The value is the maximum resident set over **all** children this process
/// has waited for, not a sum and never decreasing. Attribute it to a specific
/// child by sampling before and after that child exits: the child's own peak
/// is only known when the watermark rose. Returns `None` without the
/// `native-eval` feature or when the platform has no sampler.
pub fn children_peak_rss_bytes() -> Option<u64> {
    #[cfg(feature = "native-eval")]
    {
        peak_resident_memory_bytes(PeakResidentMemoryScope::WaitedChildren)
            .ok()
            .flatten()
    }
    #[cfg(not(feature = "native-eval"))]
    {
        None
    }
}

/// Snapshots the native evaluator's process-wide arena mapping gauges.
///
/// Returns `None` without the `native-eval` feature.
pub fn native_arena_gauges() -> Option<NativeArenaGauges> {
    #[cfg(feature = "native-eval")]
    {
        let gauges = ArenaProcessGauges::snapshot();
        Some(NativeArenaGauges {
            live_mapped_bytes: gauges.live_mapped_bytes,
            live_chunks: gauges.live_chunks,
            peak_live_mapped_bytes: gauges.peak_live_mapped_bytes,
            cumulative_mapped_bytes: gauges.cumulative_mapped_bytes,
            cumulative_chunks: gauges.cumulative_chunks,
        })
    }
    #[cfg(not(feature = "native-eval"))]
    {
        None
    }
}

/// Resets the arena peak watermark to the current live mapped bytes.
///
/// No-op without the `native-eval` feature. Intended for callers bracketing
/// one evaluation on an otherwise quiescent process.
pub fn reset_native_arena_peak() {
    #[cfg(feature = "native-eval")]
    {
        let _ = ArenaProcessGauges::reset_peak_to_live();
    }
}

/// Asks the process allocator to return dirty-but-free pages to the OS.
///
/// Returns `true` when the allocator released memory. Supported on
/// Linux/glibc (`malloc_trim(0)`); other targets and builds without the
/// `native-eval` feature return `false`. Call only at evaluation or sample
/// boundaries: released pages fault back in on next use.
pub fn release_free_memory() -> bool {
    #[cfg(feature = "native-eval")]
    {
        matches!(
            release_free_allocator_memory(),
            aos_nix::heap::AllocatorReleaseOutcome::Released
        )
    }
    #[cfg(not(feature = "native-eval"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_agree_with_feature_support() {
        if native_memory_probes_supported() {
            assert!(native_arena_gauges().is_some());
            // Resident samplers exist on the supported desktop targets.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                assert!(current_rss_bytes().is_some());
                assert!(peak_rss_bytes().is_some());
                assert!(children_peak_rss_bytes().is_some());
            }
        } else {
            assert!(current_rss_bytes().is_none());
            assert!(peak_rss_bytes().is_none());
            assert!(children_peak_rss_bytes().is_none());
            assert!(native_arena_gauges().is_none());
        }
        reset_native_arena_peak();
    }
}
