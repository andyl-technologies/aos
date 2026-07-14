//! Per-frame allocation-cost probe (RFC-0007 FV-6 frame-arena ceiling gate).
//!
//! Answers one question before anyone specs arena-owned `EvalFrame`s: what
//! share of the cold toplevel wall is spent allocating and freeing the ~3.45M
//! `Arc<EvalFrame>` per eval? The §5.5 profile shows `EvalFrame::new_linked` at
//! ~2.1% and `Arc` drops at ~3.5% (mixed with thunk/value drops), and the
//! campaign has repeatedly found allocation/`Arc` line items to be
//! counters-large but wall-small on this flat-tail shape. This probe puts a
//! direct number on it.
//!
//! Two measurements, both opt-in via `AOS_NIX_FRAME_PROBE=1` (off by default, so
//! a normal eval pays nothing) and emitted as one JSON line on the
//! `AOS_NIX_EVAL_STATS` stderr channel:
//!
//! - **in-eval alloc time** — `EvalFrame::new_linked` timed in context, summed.
//!   This is the real allocation half, including cache/allocator state during
//!   the fixpoint.
//! - **calibration** — a tight `new_linked` + drop loop measures the full
//!   alloc-plus-`Arc`-dealloc lifecycle of one small frame. The `Arc` box free
//!   fires inside `Arc`'s own drop (not interceptable from an `EvalFrame` `Drop`
//!   impl), so the calibration is how the drop side is measured. It is a *lower*
//!   bound on the real per-frame cost: a tight loop reuses freed memory
//!   immediately, warmer than the real eval.
//!
//! ```text
//! aos_nix_frame_probe {"frame_allocs":3450000,"frame_alloc_nanos":..,
//!   "frame_slots_total":..,"calib_slot_count":1,"calib_iters":1048576,
//!   "calib_alloc_drop_nanos":..}
//! ```
//!
//! Ceiling estimate: `frame_allocs * (calib_alloc_drop_nanos / calib_iters)` is
//! the full-lifecycle frame cost; divide by the clean (stats-off) wall for the
//! share. Cross-check the alloc half against `frame_alloc_nanos / frame_allocs`.

use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::EvalFrame;

/// Iterations of the alloc+drop calibration loop.
const CALIB_ITERS: u64 = 1 << 20;
/// Slot count used for the calibration frame (a representative small/inline
/// frame — [`super::INLINE_SLOT_CAPACITY`] is 2, so 1 is the common case).
const CALIB_SLOT_COUNT: usize = 1;

static ENABLED: OnceLock<bool> = OnceLock::new();
static FRAME_ALLOCS: AtomicU64 = AtomicU64::new(0);
static FRAME_ALLOC_NANOS: AtomicU64 = AtomicU64::new(0);
static FRAME_SLOTS_TOTAL: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Set while the calibration loop runs, so its own `new_linked` calls are
    /// neither timed nor counted (they would otherwise pollute the in-eval
    /// figures and self-inflate the calibration with timer overhead).
    static CALIBRATING: Cell<bool> = const { Cell::new(false) };
}

/// Returns whether the probe is enabled (`AOS_NIX_FRAME_PROBE=1`), reading the
/// environment once.
pub(crate) fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var("AOS_NIX_FRAME_PROBE").is_ok_and(|value| matches!(value.trim(), "1" | "true"))
    })
}

/// Returns whether `EvalFrame::new_linked` should time this allocation: enabled
/// and not inside the calibration loop.
pub(crate) fn should_time() -> bool {
    enabled() && !CALIBRATING.with(Cell::get)
}

/// Records one in-eval frame allocation timed over `nanos` with `slots` cells.
pub(crate) fn note_alloc(nanos: u64, slots: usize) {
    FRAME_ALLOCS.fetch_add(1, Ordering::Relaxed);
    FRAME_ALLOC_NANOS.fetch_add(nanos, Ordering::Relaxed);
    FRAME_SLOTS_TOTAL.fetch_add(slots as u64, Ordering::Relaxed);
}

/// Times `CALIB_ITERS` full `new_linked` + drop lifecycles of one small frame.
///
/// Returns the total elapsed nanoseconds. Runs with [`CALIBRATING`] set so the
/// loop's allocations are excluded from the in-eval counters and untimed.
fn calibrate_alloc_drop() -> u64 {
    CALIBRATING.with(|calibrating| calibrating.set(true));
    // Warm the frame-sized allocator size class before timing.
    for _ in 0..4096 {
        if let Ok(frame) = EvalFrame::new_linked(CALIB_SLOT_COUNT, None) {
            drop(frame);
        }
    }
    let start = Instant::now();
    for _ in 0..CALIB_ITERS {
        match EvalFrame::new_linked(CALIB_SLOT_COUNT, None) {
            Ok(frame) => drop(frame),
            Err(_) => break,
        }
    }
    let nanos = start.elapsed().as_nanos() as u64;
    CALIBRATING.with(|calibrating| calibrating.set(false));
    nanos
}

/// Prints the frame-probe JSON line to stderr, or does nothing when the probe
/// recorded no allocations (it was disabled this run).
pub(crate) fn emit_frame_probe_report() {
    let frame_allocs = FRAME_ALLOCS.load(Ordering::Relaxed);
    if frame_allocs == 0 {
        return;
    }
    let frame_alloc_nanos = FRAME_ALLOC_NANOS.load(Ordering::Relaxed);
    let frame_slots_total = FRAME_SLOTS_TOTAL.load(Ordering::Relaxed);
    let calib_alloc_drop_nanos = calibrate_alloc_drop();
    eprintln!(
        "{{\"aos_nix_frame_probe\":{{\
\"frame_allocs\":{frame_allocs},\
\"frame_alloc_nanos\":{frame_alloc_nanos},\
\"frame_slots_total\":{frame_slots_total},\
\"calib_slot_count\":{CALIB_SLOT_COUNT},\
\"calib_iters\":{CALIB_ITERS},\
\"calib_alloc_drop_nanos\":{calib_alloc_drop_nanos}\
}}}}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The calibration loop returns a positive, plausible per-frame cost and
    /// leaves the in-eval counters untouched (its allocations are excluded).
    #[test]
    fn calibration_excludes_itself_from_in_eval_counters() {
        let before = FRAME_ALLOCS.load(Ordering::Relaxed);
        let nanos = calibrate_alloc_drop();
        assert_eq!(
            FRAME_ALLOCS.load(Ordering::Relaxed),
            before,
            "calibration allocations must not count as in-eval allocations",
        );
        assert!(
            nanos > 0,
            "a million alloc+drop lifecycles take nonzero time"
        );
        // Sanity bound: a frame alloc+drop is nanoseconds, so a million of them
        // is well under a second on any builder.
        assert!(
            nanos < 5_000_000_000,
            "calibration unexpectedly slow: {nanos} ns for {CALIB_ITERS} iters",
        );
    }

    /// `should_time` is false inside a calibration scope even when enabled.
    #[test]
    fn should_time_is_false_during_calibration() {
        CALIBRATING.with(|calibrating| calibrating.set(true));
        assert!(!should_time());
        CALIBRATING.with(|calibrating| calibrating.set(false));
    }
}
