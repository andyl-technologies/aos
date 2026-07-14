//! Dynamic force-shape wall census (RFC-0007 JIT fuse-shapes, measurement-first).
//!
//! Answers the load-bearing question for the JIT fuse-shapes program: **what
//! fraction of the toplevel's evaluation wall is spent inside body shapes the
//! tier-2 compiler could take once the fuse-shapes grammar additions land?**
//!
//! The existing `aos_nix_tier1_gated_histogram` (see the JIT engine) is a
//! **static** census: it counts distinct *def-sites* the engine declined to
//! promote, at most once each, because a gated def-site is dropped from the
//! force hook after its first consulted force. It therefore reports shape
//! *variety*, not dynamic call frequency and not wall. It cannot rank shape
//! classes by the wall a compiler could remove.
//!
//! This probe closes that gap. It runs on **every** thunk force (not just the
//! first) from the tree walk's [`eval_thunk_body`](super::alloc_intern) seam,
//! classifies the forced body into a **shape class** matching the gated
//! histogram's taxonomy (`AttrSet`, `Select`, `Interp`, `BinOp:Update`,
//! `LocalVar`, `apply`, `PrimOp`, …), and attributes to that class:
//!
//! - the **dynamic force count** — how many times a body of this shape is
//!   forced (the population a compiler would cover); and
//! - the **exclusive self-nanos** — wall spent inside the body's own
//!   interpretation, with nested child forces subtracted out.
//!
//! Exclusive self-time is the metric that matters: compiling a body removes its
//! *own* interpreter dispatch and setup overhead, not the wall of the child
//! thunks it forces (those are separately-forced, separately-compilable bodies).
//! Attributing inclusive time would over-count the outer shapes (`Let`, `Apply`,
//! `AttrSet`) that merely drive child forces. The sum of all classes' self-time
//! is therefore the total top-level inclusive wall, partitioned without
//! double-counting.
//!
//! ## Reading the numbers
//!
//! Self-time is the *addressable ceiling* for a shape only to the extent the
//! shape's self-work is interpreter overhead. `PrimOp` self-time is mostly
//! **genuine native work** (string ops, `derivationStrict`, I/O) that a compiled
//! caller still pays via an FFI out-call, so it is largely non-addressable.
//! `AttrSet`/`Select`/`Interp`/`BinOp`/`LocalVar`/`apply` self-time is
//! interpreter dispatch, env setup, and allocation — the part a fused compiled
//! body reduces (an allocation FFI out-call remains, hence the measured
//! compute-shape 20x does not apply; expect 2-5x per covered call).
//!
//! ## Scope
//!
//! Nesting bookkeeping (the child-nanos accumulator) is **per worker thread**;
//! the aggregate map is process-wide. On the toplevel serial/JIT census legs the
//! main spine does the forcing and emits the report, matching the
//! main-worker-only convention of the env apply-count histogram. Parallel helper
//! forces fold their self-time into the shared map but their nesting is tracked
//! against their own thread-local accumulator, so per-thread self-time stays
//! correct.
//!
//! Collection is opt-in: the evaluator only calls in when `AOS_NIX_EVAL_STATS`
//! is enabled, so a normal or production evaluation pays nothing. The report is
//! one greppable JSON line on the `AOS_NIX_EVAL_STATS` stderr dump path (not the
//! tracing target), because a benchmark run captures this evaluator's stderr:
//!
//! ```text
//! aos_nix_force_shape_census {"total_forces":3210000,"total_self_ns":2400000000,
//!   "shapes":{"AttrSet":{"forces":540000,"self_ns":410000000,"incl_ns":900000000},
//!             "Select":{"forces":300000,"self_ns":250000000,"incl_ns":300000000},
//!             "PrimOp":{"forces":1200000,"self_ns":700000000,"incl_ns":800000000}}}
//! ```
//!
//! Totals are process-wide and cumulative across every evaluation in the
//! process; the last line a run prints holds the full picture.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide census state, `None` until the first force records.
static CENSUS: Mutex<Option<Census>> = Mutex::new(None);

/// Total forces recorded across all shape classes and threads.
static TOTAL_FORCES: AtomicU64 = AtomicU64::new(0);

/// Number of exclusive-self-time break-even buckets.
///
/// Bucket `b` (for `b < 63`) holds forces whose exclusive self-time is in
/// `[2^b, 2^(b+1))` nanoseconds; bucket 0 also holds zero-nanos forces. The
/// break-even decision for per-force JIT dispatch is a self-time threshold (a
/// compiled body must save more than the per-dispatch tax), so this power-of-two
/// partition of self-time answers directly: *what fraction of total self-time
/// lives in forces above the tax?*
const SELF_NS_BUCKETS: usize = 40;

thread_local! {
    /// Sum of the inclusive nanos of the direct child forces of the force
    /// currently open on this thread.
    ///
    /// [`open_force`] saves and zeroes it on entry; [`close_force`] reads it to
    /// derive the closing force's exclusive self-time, then restores the parent's
    /// running sum plus this force's own inclusive nanos. Per-thread so nested
    /// forces on different worker threads never cross-contaminate.
    static CHILDREN_NANOS: Cell<u64> = const { Cell::new(0) };
}

/// Per-shape-class running totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ShapeAgg {
    /// Dynamic count of forces of a body in this shape class.
    forces: u64,
    /// Exclusive nanos (nested child forces subtracted) spent in this class.
    self_nanos: u64,
    /// Inclusive nanos (child forces included) spent in this class.
    inclusive_nanos: u64,
}

/// A single exclusive-self-time break-even bucket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BucketAgg {
    /// Forces whose exclusive self-time fell in this bucket's nanos range.
    forces: u64,
    /// Summed exclusive self-nanos of those forces.
    self_nanos: u64,
}

/// Process-wide census aggregation: per-shape totals and the self-time
/// break-even bucket histogram, updated together under one lock per force.
struct Census {
    /// Exclusive self-time and force counts keyed by shape class.
    shapes: HashMap<&'static str, ShapeAgg>,
    /// Forces and self-nanos partitioned by self-time power-of-two bucket.
    self_ns_buckets: [BucketAgg; SELF_NS_BUCKETS],
}

impl Census {
    /// Creates an empty census.
    fn new() -> Self {
        Self {
            shapes: HashMap::new(),
            self_ns_buckets: [BucketAgg::default(); SELF_NS_BUCKETS],
        }
    }
}

/// Returns the break-even bucket index for an exclusive self-time in nanos.
///
/// Bucket `b` covers `[2^b, 2^(b+1))` ns; zero maps to bucket 0. Saturates at
/// the last bucket so a pathological outlier never indexes out of range.
const fn self_ns_bucket(self_nanos: u64) -> usize {
    if self_nanos == 0 {
        return 0;
    }
    let bucket = (63 - self_nanos.leading_zeros()) as usize;
    if bucket >= SELF_NS_BUCKETS {
        SELF_NS_BUCKETS - 1
    } else {
        bucket
    }
}

/// Opens a force's self-time accounting frame on the current thread.
///
/// Returns the parent frame's accumulated child-nanos, which the caller must
/// hand back to [`close_force`] unchanged. Resets the thread-local child
/// accumulator to zero so the opening force sees only its own direct children.
pub(super) fn open_force() -> u64 {
    CHILDREN_NANOS.with(|c| c.replace(0))
}

/// Closes the force opened by [`open_force`], attributing its exclusive
/// self-time to `shape`.
///
/// `elapsed_nanos` is the force's inclusive wall; `saved_children` is the value
/// [`open_force`] returned. The force's own children summed into the
/// thread-local accumulator while it ran; self-time is `elapsed - children`.
/// After recording, the parent's accumulator is restored and credited with this
/// force's full inclusive nanos so the parent's self-time excludes it in turn.
///
/// A poisoned probe lock is treated as a lost sample and silently skipped: this
/// is diagnostic instrumentation and must never perturb evaluation.
pub(super) fn close_force(shape: &'static str, elapsed_nanos: u64, saved_children: u64) {
    let my_children = CHILDREN_NANOS.with(|c| {
        let mine = c.get();
        c.set(saved_children.saturating_add(elapsed_nanos));
        mine
    });
    let self_nanos = elapsed_nanos.saturating_sub(my_children);
    TOTAL_FORCES.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut guard) = CENSUS.lock() {
        let census = guard.get_or_insert_with(Census::new);
        let agg = census.shapes.entry(shape).or_default();
        agg.forces = agg.forces.saturating_add(1);
        agg.self_nanos = agg.self_nanos.saturating_add(self_nanos);
        agg.inclusive_nanos = agg.inclusive_nanos.saturating_add(elapsed_nanos);
        let bucket = &mut census.self_ns_buckets[self_ns_bucket(self_nanos)];
        bucket.forces = bucket.forces.saturating_add(1);
        bucket.self_nanos = bucket.self_nanos.saturating_add(self_nanos);
    }
}

/// Returns the recorded force count for a shape class, or `0` when the census
/// holds no data for it.
///
/// A poisoned probe lock reads as `0`: this is diagnostic-only state. Intended
/// for tests asserting a given force shape was classified under a stats-dump
/// evaluation; production reporting goes through
/// [`emit_force_shape_census_report`].
#[cfg(test)]
pub(super) fn recorded_forces(shape: &'static str) -> u64 {
    match CENSUS.lock() {
        Ok(guard) => guard
            .as_ref()
            .and_then(|census| census.shapes.get(shape))
            .map_or(0, |agg| agg.forces),
        Err(_) => 0,
    }
}

/// Prints the force-shape census as one JSON line to stderr, or does nothing
/// when the probe holds no data.
///
/// Shapes are ordered by exclusive self-nanos, most first, so the wall-dominant
/// classes lead. The `self_ns_buckets` object maps a power-of-two nanos lower
/// bound (`"128"` = `[128, 256)` ns of exclusive self-time) to that bucket's
/// `{forces, self_ns}`, so a reader can sum the self-nanos above any JIT
/// per-dispatch break-even threshold and read the addressable-if-fused fraction
/// directly. Emitted on the `AOS_NIX_EVAL_STATS` diagnostic dump path so it
/// lands on the same stderr stream a benchmark run already captures. The line is
/// prefixed with `aos_nix_force_shape_census` for grepping.
pub(super) fn emit_force_shape_census_report() {
    let total_forces = TOTAL_FORCES.load(Ordering::Relaxed);
    if total_forces == 0 {
        return;
    }
    let (mut entries, buckets): (Vec<(&'static str, ShapeAgg)>, [BucketAgg; SELF_NS_BUCKETS]) =
        match CENSUS.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(census) => (
                    census
                        .shapes
                        .iter()
                        .map(|(shape, agg)| (*shape, *agg))
                        .collect(),
                    census.self_ns_buckets,
                ),
                None => return,
            },
            Err(_) => return,
        };
    entries.sort_by(|a, b| {
        b.1.self_nanos
            .cmp(&a.1.self_nanos)
            .then_with(|| a.0.cmp(b.0))
    });
    let total_self_ns: u64 = entries
        .iter()
        .fold(0u64, |acc, (_, agg)| acc.saturating_add(agg.self_nanos));
    let shapes = entries
        .iter()
        .map(|(shape, agg)| {
            format!(
                "\"{shape}\":{{\"forces\":{},\"self_ns\":{},\"incl_ns\":{}}}",
                agg.forces, agg.self_nanos, agg.inclusive_nanos,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let bucket_json = buckets
        .iter()
        .enumerate()
        .filter(|(_, agg)| agg.forces > 0)
        .map(|(index, agg)| {
            format!(
                "\"{}\":{{\"forces\":{},\"self_ns\":{}}}",
                1u64 << index,
                agg.forces,
                agg.self_nanos,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    eprintln!(
        "aos_nix_force_shape_census {{\"total_forces\":{total_forces},\
         \"total_self_ns\":{total_self_ns},\"shapes\":{{{shapes}}},\
         \"self_ns_buckets\":{{{bucket_json}}}}}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child force's inclusive time is subtracted from its parent's self-time,
    /// so the two classes partition the parent's inclusive wall.
    #[test]
    fn exclusive_self_time_subtracts_nested_children() {
        // Simulate: parent force of 100ns inclusive, containing one child of
        // 30ns inclusive. Parent self-time must be 70ns, child self-time 30ns.
        let parent_saved = open_force();
        {
            let child_saved = open_force();
            close_force("child", 30, child_saved);
        }
        close_force("parent", 100, parent_saved);

        let guard = CENSUS.lock().expect("census lock");
        let shapes = &guard.as_ref().expect("recorded census").shapes;
        assert_eq!(shapes["parent"].self_nanos, 70);
        assert_eq!(shapes["parent"].inclusive_nanos, 100);
        assert_eq!(shapes["child"].self_nanos, 30);
        assert_eq!(shapes["child"].inclusive_nanos, 30);
    }

    /// Self-time bucket indexing is the power-of-two floor: `[2^b, 2^(b+1))`.
    #[test]
    fn self_ns_bucket_is_power_of_two_floor() {
        assert_eq!(self_ns_bucket(0), 0);
        assert_eq!(self_ns_bucket(1), 0);
        assert_eq!(self_ns_bucket(127), 6);
        assert_eq!(self_ns_bucket(128), 7);
        assert_eq!(self_ns_bucket(255), 7);
        assert_eq!(self_ns_bucket(256), 8);
        assert_eq!(self_ns_bucket(u64::MAX), SELF_NS_BUCKETS - 1);
    }
}
