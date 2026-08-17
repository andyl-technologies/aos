//! Applied-package boundary economics probe (RFC-0007 MEMO-2, measurement-first).
//!
//! A diagnostic that answers the load-bearing precondition for the MEMO-2
//! applied-package boundary design (see
//! `design-notes/memo2-applied-boundary-seeding-plan.md`): **could a boundary
//! record even be keyed?**
//!
//! MEMO-2 would seed a durable record at each `callPackage` application
//! (`fn (auto // overrides)`), keyed by the applied lambda's def-site plus the
//! ordered durable [`ValueHash`](crate::cache::cutoff::ValueHash)es of its
//! argument set. But a durable value hash exists only for **forced, non-closure**
//! values; a package's argument set almost always still holds **unforced thunks**
//! (dependencies it never demanded), and forcing them to hash would perturb
//! force order and break byte-parity — the supreme gate. Per MEMO-1's
//! unhashable-memo precedent, any boundary whose argument set contains an
//! unforced (or closure) member must **decline** admission. If most package
//! argument sets contain such a member the decline rate approaches 100% and the
//! whole design caps out regardless of the economics — so this number gates
//! everything, and is the cheapest possible kill/redirect signal.
//!
//! This probe classifies, for every formal-set-pattern (`{ a, b, ... }:`) lambda
//! application at result-record time, each argument member as **hashable**
//! (a durable [`ValueHash`] is derivable without forcing, via the force cache's
//! own `force_cache_free_var_value_hash` predicate) or **unhashable** (an
//! unforced thunk or a closure), and reports:
//!
//! - the **decline rate** — the fraction of boundaries with at least one
//!   unhashable argument member (number #0, the gating precondition);
//! - the boundary **counts** — distinct def-sites and total applications
//!   (number #1); and
//! - the **top-level wall** spent inside package-boundary bodies (number #2),
//!   attributed only to the outermost boundary on each worker thread so nested
//!   package applications are not double-counted.
//!
//! The partial-warm stability fraction (number #3 of the plan) is a separate,
//! harder measurement gated on this one and is **not** collected here.
//!
//! Collection is opt-in: the evaluator only calls into this module when
//! `AOS_NIX_EVAL_STATS` stats collection is enabled, so a normal or production
//! evaluation pays nothing. The report is emitted as one greppable JSON line to
//! stderr by [`emit_pkg_boundary_report`], on the same `AOS_NIX_EVAL_STATS` dump
//! path as the evaluator's other stderr diagnostics (not the tracing stats
//! target), because a benchmark run captures this evaluator's stderr:
//!
//! ```text
//! aos_nix_pkg_boundary {"applications":420,"distinct_def_sites":210,
//!   "declined_applications":400,"distinct_declined_def_sites":205,
//!   "arg_members":3100,"hashable_arg_members":900,"toplevel_wall_ns":1234567}
//! ```
//!
//! Counts are process-wide and cumulative across every evaluation in the process
//! (matching the [`apply_probe`](super::super::env) convention); the last line
//! printed by a run holds the full picture.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Total formal-set-pattern boundary applications observed.
static APPLICATIONS: AtomicU64 = AtomicU64::new(0);
/// Applications with at least one unhashable (unforced/closure) argument member.
static DECLINED_APPLICATIONS: AtomicU64 = AtomicU64::new(0);
/// Total argument members inspected across all boundary applications.
static ARG_MEMBERS: AtomicU64 = AtomicU64::new(0);
/// Argument members that were forced-and-hashable at record time.
static HASHABLE_ARG_MEMBERS: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds spent inside outermost package-boundary bodies (no nesting
/// double-count; see [`BoundaryWallGuard`]).
static TOPLEVEL_WALL_NANOS: AtomicU64 = AtomicU64::new(0);

/// Per-def-site aggregation, keyed by `(module.index() << 32) | body IrId`.
///
/// `None` until the first recorded application. Tracks distinct package
/// boundaries and which of them ever declined, so the report can separate
/// "how many distinct packages" from "how many applications".
static DEF_SITES: Mutex<Option<HashMap<u64, DefSiteAgg>>> = Mutex::new(None);

thread_local! {
    /// True while this worker thread is evaluating inside a package-boundary
    /// body, so nested boundary applications attribute their wall to the
    /// outermost one rather than double-counting.
    static IN_BOUNDARY: Cell<bool> = const { Cell::new(false) };
}

/// Per-def-site running totals.
#[derive(Clone, Copy, Debug, Default)]
struct DefSiteAgg {
    /// Applications of this def-site.
    applications: u64,
    /// Applications of this def-site that declined (>=1 unhashable member).
    declined: u64,
}

/// Records one formal-set-pattern boundary application against its def-site.
///
/// `def_site` is `(module.index() << 32) | body IrId`; `arg_members` and
/// `hashable_members` are the total and forced-and-hashable argument-member
/// counts for this application. Call this only when stats collection is active.
///
/// A poisoned probe lock is treated as a lost sample and silently skipped: this
/// is diagnostic instrumentation and must never perturb evaluation.
pub(super) fn note_pkg_boundary_apply(def_site: u64, arg_members: u32, hashable_members: u32) {
    APPLICATIONS.fetch_add(1, Ordering::Relaxed);
    ARG_MEMBERS.fetch_add(u64::from(arg_members), Ordering::Relaxed);
    HASHABLE_ARG_MEMBERS.fetch_add(u64::from(hashable_members), Ordering::Relaxed);
    let declined = hashable_members < arg_members;
    if declined {
        DECLINED_APPLICATIONS.fetch_add(1, Ordering::Relaxed);
    }
    if let Ok(mut guard) = DEF_SITES.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        let agg = map.entry(def_site).or_default();
        agg.applications = agg.applications.saturating_add(1);
        if declined {
            agg.declined = agg.declined.saturating_add(1);
        }
    }
}

/// A scope guard that attributes wall time to the outermost package-boundary
/// body on the current worker thread.
///
/// Constructed with [`BoundaryWallGuard::enter`] just before a boundary body is
/// evaluated. If the thread was not already inside a boundary this guard is the
/// outermost one and, on drop, folds its elapsed wall into
/// [`TOPLEVEL_WALL_NANOS`]; nested guards record nothing (their wall is already
/// counted under the outer body). Drop-based so an evaluation error or unwind
/// still clears the thread-local flag.
pub(super) struct BoundaryWallGuard {
    /// `Some(start)` only for the outermost boundary on this thread.
    start: Option<Instant>,
}

impl BoundaryWallGuard {
    /// Enters a package-boundary body, marking the thread and starting the wall
    /// clock when this is the outermost boundary.
    pub(super) fn enter() -> Self {
        let outermost = IN_BOUNDARY.with(|flag| {
            let was_inside = flag.get();
            flag.set(true);
            !was_inside
        });
        Self {
            start: outermost.then(Instant::now),
        }
    }
}

impl Drop for BoundaryWallGuard {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            let nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            TOPLEVEL_WALL_NANOS.fetch_add(nanos, Ordering::Relaxed);
            IN_BOUNDARY.with(|flag| flag.set(false));
        }
    }
}

/// A point-in-time snapshot of the boundary economics.
///
/// Fields are process-wide cumulative totals. The decline rate is
/// `declined_applications / applications`; the argument-availability fraction is
/// `hashable_arg_members / arg_members`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PkgBoundaryReport {
    /// Total formal-set-pattern boundary applications.
    pub applications: u64,
    /// Distinct package-boundary def-sites applied at least once.
    pub distinct_def_sites: u64,
    /// Applications with at least one unhashable argument member (would decline).
    pub declined_applications: u64,
    /// Distinct def-sites that declined on at least one application.
    pub distinct_declined_def_sites: u64,
    /// Total argument members inspected.
    pub arg_members: u64,
    /// Argument members forced-and-hashable at record time.
    pub hashable_arg_members: u64,
    /// Nanoseconds spent inside outermost package-boundary bodies.
    pub toplevel_wall_ns: u64,
}

/// Returns the current boundary economics snapshot, or `None` when the probe has
/// recorded nothing (stats collection was never active this process).
pub(super) fn pkg_boundary_report() -> Option<PkgBoundaryReport> {
    let applications = APPLICATIONS.load(Ordering::Relaxed);
    if applications == 0 {
        return None;
    }
    let mut report = PkgBoundaryReport {
        applications,
        declined_applications: DECLINED_APPLICATIONS.load(Ordering::Relaxed),
        arg_members: ARG_MEMBERS.load(Ordering::Relaxed),
        hashable_arg_members: HASHABLE_ARG_MEMBERS.load(Ordering::Relaxed),
        toplevel_wall_ns: TOPLEVEL_WALL_NANOS.load(Ordering::Relaxed),
        ..PkgBoundaryReport::default()
    };
    if let Ok(guard) = DEF_SITES.lock() {
        if let Some(map) = guard.as_ref() {
            report.distinct_def_sites = map.len() as u64;
            report.distinct_declined_def_sites =
                map.values().filter(|agg| agg.declined > 0).count() as u64;
        }
    }
    Some(report)
}

/// Prints the boundary economics as one JSON line to stderr, or does nothing
/// when the probe holds no data.
///
/// Emitted on the `AOS_NIX_EVAL_STATS` diagnostic dump path so it lands on the
/// same stderr stream a benchmark run already captures. The line is prefixed
/// with `aos_nix_pkg_boundary` for grepping.
pub(super) fn emit_pkg_boundary_report() {
    let Some(r) = pkg_boundary_report() else {
        return;
    };
    eprintln!(
        "aos_nix_pkg_boundary {{\"applications\":{},\"distinct_def_sites\":{},\"declined_applications\":{},\"distinct_declined_def_sites\":{},\"arg_members\":{},\"hashable_arg_members\":{},\"toplevel_wall_ns\":{}}}",
        r.applications,
        r.distinct_def_sites,
        r.declined_applications,
        r.distinct_declined_def_sites,
        r.arg_members,
        r.hashable_arg_members,
        r.toplevel_wall_ns,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A boundary with any unhashable member counts as declined; the per-def-site
    /// aggregate separates distinct sites from total applications.
    #[test]
    fn aggregates_applications_and_declines_per_def_site() {
        let mut map: HashMap<u64, DefSiteAgg> = HashMap::new();
        // Two applications of one def-site, one declining; one clean application
        // of a second def-site.
        for (def_site, arg_members, hashable) in [(1u64, 3u32, 2u32), (1, 3, 3), (2, 1, 1)] {
            let agg = map.entry(def_site).or_default();
            agg.applications += 1;
            if hashable < arg_members {
                agg.declined += 1;
            }
        }
        assert_eq!(map.len(), 2, "two distinct def-sites");
        assert_eq!(map[&1].applications, 2);
        assert_eq!(map[&1].declined, 1);
        assert_eq!(map[&2].declined, 0);
        let declined_sites = map.values().filter(|a| a.declined > 0).count();
        assert_eq!(declined_sites, 1);
    }

    /// The outermost guard owns the wall; a nested guard records nothing and
    /// leaves the thread flag set until the outer guard drops.
    #[test]
    fn nested_wall_guard_attributes_only_the_outermost() {
        IN_BOUNDARY.with(|f| f.set(false));
        let outer = BoundaryWallGuard::enter();
        assert!(outer.start.is_some(), "outermost guard starts the clock");
        let inner = BoundaryWallGuard::enter();
        assert!(inner.start.is_none(), "nested guard does not double-count");
        assert!(
            IN_BOUNDARY.with(Cell::get),
            "still inside after nested enter"
        );
        drop(inner);
        assert!(
            IN_BOUNDARY.with(Cell::get),
            "outer guard keeps the thread marked inside"
        );
        drop(outer);
        assert!(
            !IN_BOUNDARY.with(Cell::get),
            "outermost drop clears the flag"
        );
    }
}
