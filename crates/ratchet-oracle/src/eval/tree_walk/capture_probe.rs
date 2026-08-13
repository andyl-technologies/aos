//! Capture-on-demand attribution probe (RFC-0007 §P1 dynamic-env lever).
//!
//! Every tree-walk thunk and lambda allocation captures the ambient `with`
//! scopes and scoped-import globals, yet most bodies can reach neither. This
//! probe measures, at each such allocation, two independent skip conditions per
//! dynamic environment:
//!
//! - **ambient-empty**: the active scope is already empty, so the capture is
//!   trivially nothing to carry;
//! - **body-clean**: the body's lowered subtree cannot read a `with` var /
//!   scoped global (per
//!   [`analyze_dynamic_scope_reach`](crate::compile::analysis::dynamic_scope::analyze_dynamic_scope_reach)),
//!   so the capture is dead even when the ambient scope is non-empty — the
//!   capture-on-demand lever proper.
//!
//! Collection is opt-in: [`note_capture`] runs only when the evaluator has
//! `AOS_NIX_EVAL_STATS` stats collection active (see the allocation sites), so a
//! normal or production eval pays nothing. The per-module reachability analysis
//! is memoized in a thread-local keyed by module index, so it runs once per
//! module per collecting worker. Totals are emitted as one greppable JSON line
//! to stderr on the `AOS_NIX_EVAL_STATS` dump path (not the tracing target):
//!
//! ```text
//! aos_nix_capture_on_demand {"captures":2440748,"with_ambient_empty":123,
//!   "with_body_clean":2200000,"global_ambient_empty":2440000,
//!   "global_body_clean":2400000}
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::compile::Ir;
use crate::compile::analysis::dynamic_scope::{DynamicScopeReach, analyze_dynamic_scope_reach};
use crate::compile::ir::IrId;

thread_local! {
    /// Per-module dynamic-scope reachability, computed once per collecting worker.
    static REACH_MEMO: RefCell<HashMap<usize, DynamicScopeReach>> =
        RefCell::new(HashMap::new());
}

/// Thunk/lambda allocations observed while collecting.
static CAPTURES: AtomicU64 = AtomicU64::new(0);
/// Allocations whose ambient `with` scope was already empty.
static WITH_AMBIENT_EMPTY: AtomicU64 = AtomicU64::new(0);
/// Allocations whose body cannot read a `with` var.
static WITH_BODY_CLEAN: AtomicU64 = AtomicU64::new(0);
/// Allocations whose ambient scoped-global scope was already empty.
static GLOBAL_AMBIENT_EMPTY: AtomicU64 = AtomicU64::new(0);
/// Allocations whose body cannot read a scoped global.
static GLOBAL_BODY_CLEAN: AtomicU64 = AtomicU64::new(0);

/// Records one thunk/lambda capture against the two per-environment skip
/// conditions.
///
/// `body` is the lowered body node whose subtree determines reachability;
/// `module_index` selects `ir` for the memoized reachability analysis;
/// `with_ambient_empty` / `global_ambient_empty` report whether the active
/// scopes were empty at the allocation. Call this only when stats collection is
/// active.
pub(crate) fn note_capture(
    ir: &Ir,
    module_index: usize,
    body: IrId,
    with_ambient_empty: bool,
    global_ambient_empty: bool,
) {
    let (reaches_with, reaches_global) = REACH_MEMO.with(|memo| {
        let mut memo = memo.borrow_mut();
        let reach = memo
            .entry(module_index)
            .or_insert_with(|| analyze_dynamic_scope_reach(ir));
        (
            reach.reaches_with_var(body),
            reach.reaches_scoped_global(body),
        )
    });
    CAPTURES.fetch_add(1, Ordering::Relaxed);
    if with_ambient_empty {
        WITH_AMBIENT_EMPTY.fetch_add(1, Ordering::Relaxed);
    }
    if !reaches_with {
        WITH_BODY_CLEAN.fetch_add(1, Ordering::Relaxed);
    }
    if global_ambient_empty {
        GLOBAL_AMBIENT_EMPTY.fetch_add(1, Ordering::Relaxed);
    }
    if !reaches_global {
        GLOBAL_BODY_CLEAN.fetch_add(1, Ordering::Relaxed);
    }
}

/// Emits the capture-on-demand attribution totals to stderr as one greppable
/// JSON line, or nothing when no capture was recorded this process.
///
/// Called on the `AOS_NIX_EVAL_STATS` dump path so it lands on the evaluator's
/// stderr rather than the `aos_nix::eval::stats` trace subscriber.
pub(crate) fn emit_capture_on_demand_report() {
    let captures = CAPTURES.load(Ordering::Relaxed);
    if captures == 0 {
        return;
    }
    eprintln!(
        "aos_nix_capture_on_demand {{\"captures\":{},\"with_ambient_empty\":{},\"with_body_clean\":{},\"global_ambient_empty\":{},\"global_body_clean\":{}}}",
        captures,
        WITH_AMBIENT_EMPTY.load(Ordering::Relaxed),
        WITH_BODY_CLEAN.load(Ordering::Relaxed),
        GLOBAL_AMBIENT_EMPTY.load(Ordering::Relaxed),
        GLOBAL_BODY_CLEAN.load(Ordering::Relaxed),
    );
}
