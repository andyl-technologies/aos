//! Lexical-depth distribution probe (RFC-0007 instruction-bloat / depth lane).
//!
//! Tests the depth-amplifier hypothesis: several per-op costs scale with lexical
//! depth (`clone_env_frames` is `O(depth)` instructions per apply/force since the
//! stage-A fix; `capture_env`), and the module fixpoint plausibly builds much
//! deeper environments than shallow package bodies. If so, a flat per-op
//! instruction average hides a depth-linear amplifier specific to the toplevel.
//!
//! This probe records the environment depth (`frames().len()`, the shared
//! lexical frame count) at two sites, bucketed and weighted both by **count**
//! (how many installs/captures) and by **depth-mass** (sum of `len` — the total
//! `O(depth)` work):
//!
//! - **install** — `clone_env_frames`, the per-apply/per-force env install.
//! - **capture** — `capture_env`, the per-closure env capture (conceptual active
//!   depth at closure creation).
//!
//! Opt-in via `AOS_NIX_DEPTH_PROBE=1` (off by default, a plain atomic-bucket
//! increment when on — no map, no timing), emitted as JSON on the
//! `AOS_NIX_EVAL_STATS` stderr channel:
//!
//! ```text
//! aos_nix_env_install_depth {"total":N,"depth_mass":N,"len0":N,"len1":N,"len2":N,
//!   "len3_4":N,"len5_8":N,"len9_16":N,"len17_32":N,"len33p":N}
//! aos_nix_env_capture_depth {"total":N,"depth_mass":N,...}
//! ```
//!
//! Verdict metric: `depth_mass / total` = average depth per install. If the
//! toplevel's is much larger than a shallow package's (`pkgs.zlib`), the shape
//! amplifier is confirmed and an `O(1)` env install is justified by data;
//! similar distributions exonerate depth (uniform per-op bloat).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// One count+mass histogram over lexical depths, in log2-ish buckets.
struct DepthHistogram {
    total: AtomicU64,
    depth_mass: AtomicU64,
    buckets: [AtomicU64; BUCKETS],
}

/// Number of depth buckets: `{0, 1, 2, 3-4, 5-8, 9-16, 17-32, 33+}`.
const BUCKETS: usize = 8;

impl DepthHistogram {
    const fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            depth_mass: AtomicU64::new(0),
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    fn record(&self, len: usize) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.depth_mass.fetch_add(len as u64, Ordering::Relaxed);
        self.buckets[bucket_index(len)].fetch_add(1, Ordering::Relaxed);
    }

    /// Emits one JSON line under `key` if this histogram recorded anything.
    fn emit(&self, key: &str) {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return;
        }
        let depth_mass = self.depth_mass.load(Ordering::Relaxed);
        let b: [u64; BUCKETS] = std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed));
        eprintln!(
            "{{\"{key}\":{{\
\"total\":{total},\
\"depth_mass\":{depth_mass},\
\"len0\":{},\"len1\":{},\"len2\":{},\"len3_4\":{},\
\"len5_8\":{},\"len9_16\":{},\"len17_32\":{},\"len33p\":{}\
}}}}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        );
    }
}

/// Maps a depth to its bucket index: `{0,1,2,3-4,5-8,9-16,17-32,33+}`.
fn bucket_index(len: usize) -> usize {
    match len {
        0 => 0,
        1 => 1,
        2 => 2,
        3..=4 => 3,
        5..=8 => 4,
        9..=16 => 5,
        17..=32 => 6,
        _ => 7,
    }
}

static ENABLED: OnceLock<bool> = OnceLock::new();
static INSTALL: DepthHistogram = DepthHistogram::new();
static CAPTURE: DepthHistogram = DepthHistogram::new();

/// Returns whether the probe is enabled (`AOS_NIX_DEPTH_PROBE=1`), reading the
/// environment once.
pub(crate) fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var("AOS_NIX_DEPTH_PROBE").is_ok_and(|value| matches!(value.trim(), "1" | "true"))
    })
}

/// Records one environment install at lexical depth `len` (`clone_env_frames`).
pub(crate) fn note_install_depth(len: usize) {
    INSTALL.record(len);
}

/// Records one environment capture at conceptual depth `len` (`capture_env`).
pub(crate) fn note_capture_depth(len: usize) {
    CAPTURE.record(len);
}

/// Prints the install and capture depth-distribution lines to stderr, or does
/// nothing for a histogram that recorded no samples (probe disabled this run).
pub(crate) fn emit_depth_report() {
    INSTALL.emit("aos_nix_env_install_depth");
    CAPTURE.emit("aos_nix_env_capture_depth");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_boundaries() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(1), 1);
        assert_eq!(bucket_index(2), 2);
        assert_eq!(bucket_index(3), 3);
        assert_eq!(bucket_index(4), 3);
        assert_eq!(bucket_index(5), 4);
        assert_eq!(bucket_index(8), 4);
        assert_eq!(bucket_index(9), 5);
        assert_eq!(bucket_index(16), 5);
        assert_eq!(bucket_index(17), 6);
        assert_eq!(bucket_index(32), 6);
        assert_eq!(bucket_index(33), 7);
        assert_eq!(bucket_index(10_000), 7);
    }

    /// `record` accumulates count and depth-mass and lands in the right bucket.
    #[test]
    fn record_accumulates_count_and_mass() {
        let hist = DepthHistogram::new();
        hist.record(1);
        hist.record(4);
        hist.record(4);
        assert_eq!(hist.total.load(Ordering::Relaxed), 3);
        assert_eq!(hist.depth_mass.load(Ordering::Relaxed), 9);
        assert_eq!(hist.buckets[1].load(Ordering::Relaxed), 1); // one len-1
        assert_eq!(hist.buckets[3].load(Ordering::Relaxed), 2); // two len-4 (3-4 bucket)
    }
}
