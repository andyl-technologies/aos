//! Tier-B live reclamation for the evaluator heap (RFC-0007 Phase 3).
//!
//! This module owns the two *non-moving* reclaimers behind `AOS_NIX_GC=sweep`:
//!
//! 1. **Thunk capture shedding** ([`EvalHeap::shed_forced_thunk_captures`]) -
//!    the tree-walk analogue of GHC's destructive thunk update and C++ Nix's
//!    in-place `Value` overwrite. Once a serial thunk publishes its WHNF
//!    result, its deferred work (captured lexical/`with`/scoped-global
//!    environments, captured argument values) can never be evaluated again:
//!    every later force short-circuits on the `Forced` cell. Shedding swaps
//!    the record's payload for a lean [`EvalThunk::released_forced`] carrying
//!    only the forced result, dropping the closure graph (its `Rc<EvalFrame>`
//!    environments and their slot values) mid-evaluation. Handle identity is
//!    untouched: the record keeps its address, tag, and forced result, so
//!    `payload_bits`-keyed identity (force caches, tier-1 slots, pointer
//!    equality fast paths) is preserved bit-for-bit.
//!
//! 2. **The quiescent-point mark-sweep**
//!    ([`EvalHeap::sweep_unreachable_worker_records`]) - a precise, tracing,
//!    *non-moving* collection over worker-domain records (thunks, lambdas,
//!    partially applied builtins). Marking starts from the caller-supplied
//!    precise roots plus every worker value embedded in a permanent
//!    hash-consed object (permanent objects are immortal, so their worker
//!    edges are unconditionally live), and traverses only worker records via
//!    the same precise field enumeration the safepoint machinery uses
//!    ([`EvalHeap::scan_record_edges`]). Unmarked worker records are retired
//!    in place: the payload is dropped, the address index entry is removed,
//!    and the slot is recycled through the record table's free list.
//!
//! # Why non-moving (the approved Stage-B1 fork)
//!
//! On this heap architecture a `Value` is an opaque *address key* into the
//! record side table and all object state lives in malloc-backed payloads, so
//! reclaiming payloads and index entries captures the memory win a copying
//! collector would provide, while never perturbing address identity. The
//! decisive safety property is the failure mode: the bump arena never reuses
//! an address (region pops are fenced off after any retirement), so a *missed
//! root* dereferences to [`EvalHeapError::UnknownPointer`] - a loud,
//! deterministic error caught by the byte-parity gates - instead of silently
//! resolving to a recycled object. The RFC's copying-nursery mandate (doc 06
//! SS4) is staged behind this collector: B1's stress runs prove precise-root
//! completeness before anything ever moves.
//!
//! # Parallel mode
//!
//! Both reclaimers are quiesced under parallel evaluation
//! (`AOS_NIX_PARALLEL`): the shared-heap backend publishes records across
//! workers and per-worker/concurrent collection is Phase 8. Every entry point
//! here refuses shared-backend heaps.

use std::collections::HashSet;
use std::hash::BuildHasherDefault;

use super::record_table::AddressHasher;
use super::*;
use crate::eval::thunk::ThunkState;

/// The Tier-B live-reclamation mode (the `AOS_NIX_GC` knob).
///
/// Tier A (never free) remains the default; `Sweep` additionally enables
/// thunk capture shedding at force publish and precise non-moving sweeps at
/// evaluator quiescent points. Parallel evaluation pins the mode to `Off`
/// regardless of configuration (per-worker/concurrent GC is Phase 8).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EvalGcMode {
    /// Tier-A one-shot arena semantics: never reclaim within an evaluation.
    #[default]
    Off,
    /// Tier-B non-moving reclamation: capture shedding + quiescent sweeps.
    Sweep,
}

impl EvalGcMode {
    /// Returns `true` when any Tier-B reclamation is enabled.
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Sweep)
    }
}

/// One quiescent-point sweep's outcome, for cycle stats and diagnostics.
///
/// Counts are per-cycle except [`EvalHeapSweepReport::retired_total`] and
/// [`EvalHeapSweepReport::free_slots`], which describe the whole heap after
/// the cycle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvalHeapSweepReport {
    /// Root values supplied by the caller for this cycle.
    pub roots: usize,
    /// Worker values seeded from permanent hash-consed objects' fields.
    pub permanent_edge_seeds: usize,
    /// Heap records visited by the mark phase (worker and permanent).
    pub marked: usize,
    /// Worker records retired by this cycle, by original tag.
    pub swept_thunks: usize,
    /// Lambda records retired by this cycle.
    pub swept_lambdas: usize,
    /// Partially applied builtin records retired by this cycle.
    pub swept_primops: usize,
    /// Worker records still live after this cycle.
    pub live_worker_records: usize,
    /// Records ever retired by the sweep, across all cycles.
    pub retired_total: u64,
    /// Record-table slots currently parked on the free list.
    pub free_slots: usize,
}

impl EvalHeapSweepReport {
    /// Returns the total worker records retired by this cycle.
    pub const fn swept(&self) -> usize {
        self.swept_thunks + self.swept_lambdas + self.swept_primops
    }
}

impl EvalHeap {
    /// Sheds a forced serial thunk's captured environments and deferred work.
    ///
    /// Replaces the thunk record's payload with a lean
    /// [`EvalThunk::released_forced`] holding only the already published WHNF
    /// result, dropping the captured closure graph. This is observationally
    /// invisible: the record keeps its address and every later force
    /// short-circuits on the same `Forced` result.
    ///
    /// Returns `false` (without modifying anything) for the cases shedding
    /// does not cover: shared-backend (parallel) heaps, thunks with
    /// non-serial force storage (single-entry bodies re-evaluate on each
    /// force; parallel payload cells are cross-worker shared), and thunks
    /// already shed.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `value` is not a thunk handle of this
    /// heap, or if the thunk is not `Forced` with a published result (shedding
    /// runs strictly after publish, so anything else is an evaluator bug).
    pub(crate) fn shed_forced_thunk_captures(
        &mut self,
        value: Value,
    ) -> Result<bool, EvalHeapError> {
        if self.shared.is_some() {
            return Ok(false);
        }
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        let address = ptr.as_ptr() as usize;
        let Some(position) = self.records.index_of_address(address) else {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        };
        let Some(record) = self.records.get(position) else {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        };
        let HeapObjectValue::Thunk(thunk) = &record.object else {
            return Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                record.object.tag(),
                ptr,
            ));
        };
        if !thunk_kind_has_reclaimable_captures(thunk.kind()) {
            return Ok(false);
        }
        if !thunk.has_serial_only_force_storage() {
            return Ok(false);
        }
        let state = thunk.cell().state().map_err(EvalHeapError::Thunk)?;
        if state != ThunkState::Forced {
            return Err(EvalHeapError::ShedRejected {
                address,
                reason: "thunk is not forced",
            });
        }
        let Some(result) = thunk.cell().cached_value().map_err(EvalHeapError::Thunk)? else {
            return Err(EvalHeapError::ShedRejected {
                address,
                reason: "forced thunk has no published result",
            });
        };
        let Some(record) = self.records.get_mut(position) else {
            return Err(EvalHeapError::unknown(ValueTag::Thunk, ptr));
        };
        record.object = HeapObjectValue::Thunk(Arc::new(EvalThunk::released_forced(result)));
        self.alloc_counters.note_thunk_shed();
        Ok(true)
    }

    /// Retires every worker-domain record unreachable from `roots`.
    ///
    /// This is the Tier-B non-moving minor collection. Marking is precise: it
    /// starts from the caller's roots plus every worker value stored in a
    /// permanent hash-consed object (permanent objects are immortal, so those
    /// edges are live by construction), and expands worker records through
    /// [`EvalHeap::scan_record_edges`]. Permanent records terminate traversal.
    /// Unmarked worker records are retired in place through the record table
    /// (payload dropped, index entry removed, slot recycled); their addresses
    /// are never reissued, so a stale handle fails loudly as an unknown
    /// pointer.
    ///
    /// The caller owns quiescence: every live `Value` outside the heap must be
    /// reachable from `roots`. The tree-walk only invokes this at points where
    /// its transient stacks are empty and no force is in flight.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::ShedRejected`] with reason
    /// `"sweep requires the serial heap"` for shared-backend (parallel)
    /// heaps. Returns [`EvalHeapError::UnknownPointer`] if a root or a live
    /// edge names an address with no record (a stale root - an evaluator
    /// bug). Returns [`EvalHeapError::Thunk`] if an unreachable thunk is
    /// blackholed, which means a force was in flight and the caller was not
    /// quiescent.
    pub(crate) fn sweep_unreachable_worker_records(
        &mut self,
        roots: &EvalRootSet,
    ) -> Result<EvalHeapSweepReport, EvalHeapError> {
        if self.shared.is_some() {
            return Err(EvalHeapError::ShedRejected {
                address: 0,
                reason: "sweep requires the serial heap",
            });
        }

        let mut report = EvalHeapSweepReport {
            roots: roots.len(),
            ..EvalHeapSweepReport::default()
        };

        // Seed phase: worker-tagged caller roots, then worker values held by
        // permanent hash-consed objects. Permanent objects are immutable
        // after interning and never collected, so their worker edges are
        // unconditionally live and marking never touches the permanent graph
        // at all: worker-domain membership is decided by the value tag alone
        // (thunk/lambda/primop values are worker-allocated by construction),
        // so non-worker roots and edges are skipped without a record lookup.
        let mut worklist: Vec<Value> = Vec::new();
        worklist
            .try_reserve(roots.len())
            .map_err(|_| EvalHeapError::RecordAllocationFailed {
                records: roots.len(),
            })?;
        for root in roots.roots() {
            if is_worker_domain_tag(root.value().tag()) {
                worklist.push(root.value());
            }
        }
        for record in self.records.iter() {
            if record.is_retired()
                || record.allocation_domain != HeapAllocationDomain::PermanentShared
            {
                continue;
            }
            match &record.object {
                HeapObjectValue::List(list) => {
                    for value in list.iter().copied() {
                        if is_worker_domain_tag(value.tag()) {
                            report.permanent_edge_seeds += 1;
                            worklist.push(value);
                        }
                    }
                }
                HeapObjectValue::Attrs { attrs, .. } => {
                    for entry in attrs.entries_by_symbol() {
                        if is_worker_domain_tag(entry.value.tag()) {
                            report.permanent_edge_seeds += 1;
                            worklist.push(entry.value);
                        }
                    }
                }
                _ => {}
            }
        }
        // Flat lists (doc 30 FV-1) are permanent hash-consed objects outside
        // the record table; their element spines seed marking exactly as
        // record-backed permanent lists did. Flat strings/paths are edge-free
        // and need no seeding.
        for entry in self.flat_lists.iter() {
            for value in entry.object().payload().iter().copied() {
                if is_worker_domain_tag(value.tag()) {
                    report.permanent_edge_seeds += 1;
                    worklist.push(value);
                }
            }
        }

        // Mark phase: precise traversal over worker records only.
        let mut visited: HashSet<usize, BuildHasherDefault<AddressHasher>> = HashSet::default();
        visited
            .try_reserve(worklist.len())
            .map_err(|_| EvalHeapError::RecordAllocationFailed {
                records: worklist.len(),
            })?;
        while let Some(value) = worklist.pop() {
            debug_assert!(is_worker_domain_tag(value.tag()));
            let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?;
            let address = ptr.as_ptr() as usize;
            if !visited.insert(address) {
                continue;
            }
            let Some(position) = self.records.index_of_address(address) else {
                // A stale root or stale live edge: fail loudly rather than
                // sweep against an incomplete root set.
                return Err(EvalHeapError::unknown(value.tag(), ptr));
            };
            let Some(record) = self.records.get(position) else {
                return Err(EvalHeapError::unknown(value.tag(), ptr));
            };
            report.marked += 1;
            for edge in self.scan_record_edges(record)? {
                if is_worker_domain_tag(edge.value().tag()) {
                    worklist.push(edge.value());
                }
            }
        }

        // Validate-then-retire: collect unreachable worker positions first so
        // a quiescence violation (an in-flight blackholed thunk) aborts the
        // cycle before anything is reclaimed.
        let mut unreachable: Vec<(usize, ValueTag)> = Vec::new();
        let mut live_worker_records = 0usize;
        for (position, record) in self.records.iter().enumerate() {
            if record.is_retired() || record.allocation_domain != HeapAllocationDomain::Worker {
                continue;
            }
            let address = record.ptr.as_ptr() as usize;
            if visited.contains(&address) {
                live_worker_records += 1;
                continue;
            }
            if let HeapObjectValue::Thunk(thunk) = &record.object
                && thunk.cell().state().map_err(EvalHeapError::Thunk)? == ThunkState::Blackhole
            {
                return Err(EvalHeapError::ShedRejected {
                    address,
                    reason: "sweep found an unreachable blackholed thunk; caller not quiescent",
                });
            }
            unreachable
                .try_reserve(1)
                .map_err(|_| EvalHeapError::RecordAllocationFailed { records: 1 })?;
            unreachable.push((position, record.object.tag()));
        }

        for (position, tag) in unreachable {
            if self.records.retire_at_position(position).is_none() {
                continue;
            }
            match tag {
                ValueTag::Thunk => report.swept_thunks += 1,
                ValueTag::Lambda => report.swept_lambdas += 1,
                ValueTag::Primop => report.swept_primops += 1,
                _ => {}
            }
        }

        report.live_worker_records = live_worker_records;
        report.retired_total = self.records.retired_total();
        report.free_slots = self.records.free_slot_count();
        self.alloc_counters.note_sweep(report.swept() as u64);
        Ok(report)
    }
}

/// Returns `true` when releasing the kind would actually free captures.
///
/// Shedding swaps in a fresh lean `Arc`, so it only pays when the kind holds
/// something reclaimable: captured environments or captured argument values.
/// Environment-free `Node` kinds and `BuiltinAttr` kinds carry only IR ids
/// and are skipped, keeping the per-publish cost off capture-free thunks.
/// Already-released kinds are also skipped (shedding is idempotent).
fn thunk_kind_has_reclaimable_captures(kind: &EvalThunkKind) -> bool {
    match kind {
        EvalThunkKind::Node {
            env,
            with_env,
            scoped_globals,
            ..
        } => {
            !env.frames().is_empty()
                || !with_env.scopes().is_empty()
                || !scoped_globals.scopes().is_empty()
        }
        EvalThunkKind::Apply { .. }
        | EvalThunkKind::Apply2 { .. }
        | EvalThunkKind::Select { .. } => true,
        EvalThunkKind::BuiltinAttr { .. } | EvalThunkKind::Released => false,
    }
}

/// Returns `true` for value tags allocated in the worker domain.
///
/// Strings, paths, lists, and attrsets are hash-consed into the permanent
/// shared domain; thunks, lambdas, and partially applied builtins are the
/// worker-domain (collectible) population.
const fn is_worker_domain_tag(tag: ValueTag) -> bool {
    matches!(tag, ValueTag::Thunk | ValueTag::Lambda | ValueTag::Primop)
}
