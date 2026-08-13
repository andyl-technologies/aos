//! Quiescent-point driver for the Tier-B non-moving sweep (RFC-0007 Phase 3).
//!
//! The heap-side collector ([`EvalHeap::sweep_unreachable_worker_records`])
//! requires a root set that covers every live `Value` outside the heap. The
//! tree-walk is a recursive Rust interpreter, so that is only provable at
//! *quiescent points*: moments where no force is in flight and every
//! evaluator-held value lives in the explicit root structures enumerated by
//! [`TreeWalk::safepoint_root_set`] (lexical frames, `with` scopes, scoped
//! globals, suspended env stacks, force continuations, primop arguments, the
//! import cache, and the interned tables). This module owns the quiescence
//! guard, the growth-threshold cadence, and the driver-facing entry points.
//!
//! Sweeping at non-quiescent points is a *validation* activity: the GC-stress
//! proving ground calls [`TreeWalk::sweep_heap_for_validation`] at chosen
//! boundaries, and any incompleteness in the transient-root discipline
//! surfaces as a loud [`EvalHeapError::UnknownPointer`] instead of silent
//! corruption (retired addresses are never reissued). That loud-by-design
//! failure mode is what stages the RFC's copying collector: B2 moves objects
//! only after these sweeps run clean across the corpus.

use super::*;

/// A Tier-B quiescent-sweep failure.
///
/// Sweep failures are evaluator bugs by construction (a stale root, a
/// non-quiescent caller, or root-set storage exhaustion), never user errors;
/// they must propagate loudly so the byte-parity gates catch them.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkGcSweepError {
    /// The precise safepoint root set could not be built.
    #[error("failed to build quiescent sweep roots: {0}")]
    Roots(#[from] TreeWalkSafepointRootError),
    /// The heap-side mark/sweep failed.
    #[error("quiescent sweep failed: {0}")]
    Heap(#[from] EvalHeapError),
}

impl TreeWalk {
    /// Returns whether native frames must publish roots across helper calls.
    ///
    /// Sweep mode can cross the allocation threshold inside a nested force, so
    /// compiled roots stay registered for the whole helper call even when the
    /// threshold has not yet been reached at entry.
    pub fn compiled_safepoint_roots_required(&self) -> bool {
        self.shared.is_none() && self.gc_mode.is_enabled()
    }

    /// Returns whether a compiled safepoint should collect precise roots.
    ///
    /// Native wrappers use this cheap predicate before materializing their
    /// finalized stack-map roots. Parallel evaluators decline the serial
    /// non-moving sweep until the existing quiescent coordinator owns it.
    pub fn compiled_safepoint_sweep_requested(&self) -> bool {
        self.shared.is_none() && self.heap_sweep_threshold_reached()
    }

    /// Runs the Tier-B sweep with roots from active compiled frames.
    ///
    /// `compiled_roots` must be the finalized stack-map snapshot for every
    /// native frame live at this safepoint. `extra_roots` carries values
    /// returned by the runtime helper but not yet stored back into compiled
    /// spill slots. The collector is non-moving, so no root writeback is
    /// required after the sweep.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkErrorKind::GcQuiescentSweep`] if root construction or
    /// the heap-side mark/sweep fails.
    pub fn maybe_sweep_heap_at_compiled_safepoint(
        &mut self,
        compiled_roots: &EvalRootSet,
        extra_roots: &[Value],
    ) -> Result<Option<EvalHeapSweepReport>, TreeWalkError> {
        if !self.compiled_safepoint_sweep_requested() {
            return Ok(None);
        }
        let result = (|| -> Result<EvalHeapSweepReport, TreeWalkGcSweepError> {
            let mut roots = self.mutator_root_set()?;
            roots
                .try_extend(compiled_roots)
                .map_err(TreeWalkSafepointRootError::RootSet)?;
            for (slot, value) in self
                .transient_value_stack_roots
                .iter()
                .chain(extra_roots)
                .copied()
                .enumerate()
            {
                roots
                    .try_push_value_stack(slot, value)
                    .map_err(TreeWalkSafepointRootError::RootSet)?;
            }
            Ok(self.heap.sweep_unreachable_worker_records(&roots)?)
        })();
        let report = result.map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::GcQuiescentSweep { source },
                Span::default(),
            )
        })?;
        self.gc_records_at_last_sweep = self.stats.thunks_allocated;
        self.gc_last_sweep_report = Some(report);
        Ok(Some(report))
    }

    /// Sweeps unreachable worker records if the growth threshold was reached.
    ///
    /// This is the production cadence hook for `AOS_NIX_GC=sweep`: drivers
    /// call it at points they believe quiescent, and it no-ops unless (a) the
    /// mode is enabled, (b) at least [`TreeWalkOptions::gc_sweep_threshold`]
    /// thunks were allocated since the last sweep (a threshold of `0` sweeps
    /// at every opportunity - the stress cadence), and (c) the evaluator is
    /// actually quiescent. `extra_roots` names caller-held values (for
    /// example the just-produced root result) that must survive.
    ///
    /// Returns the cycle report when a sweep ran.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkErrorKind::GcQuiescentSweep`] if root collection or
    /// the heap sweep fails; both indicate evaluator bugs and must surface.
    pub(super) fn maybe_sweep_heap_at_quiescence(
        &mut self,
        extra_roots: &[Value],
    ) -> Result<Option<EvalHeapSweepReport>, TreeWalkError> {
        if !self.heap_sweep_threshold_reached() {
            return Ok(None);
        }
        self.sweep_heap_at_quiescence(extra_roots)
    }

    /// Sweeps at a caller-proven safepoint with live locals already registered.
    ///
    /// Unlike the driver-level quiescent point, this boundary may run while a
    /// strict traversal is active. The caller must publish every heap-backed
    /// Rust local through the evaluator's safepoint root structures before
    /// calling. The raw renderer does this for every pending list element and
    /// attribute value, including the corresponding roots of ancestor
    /// traversals. The sweep remains non-moving, so traversal-side copies of
    /// those registered words do not require writeback.
    ///
    /// Returns the cycle report when the configured allocation threshold was
    /// reached and a sweep ran.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkErrorKind::GcQuiescentSweep`] if root collection or
    /// the heap sweep fails.
    pub(super) fn maybe_sweep_heap_at_registered_safepoint(
        &mut self,
    ) -> Result<Option<EvalHeapSweepReport>, TreeWalkError> {
        if !self.heap_sweep_threshold_reached() {
            return Ok(None);
        }
        if !self.is_registered_post_root_traversal_safepoint() {
            self.gc_sweeps_skipped_nonquiescent =
                self.gc_sweeps_skipped_nonquiescent.saturating_add(1);
            return Ok(None);
        }
        self.sweep_heap_for_validation(&[]).map(Some)
    }

    /// Sweeps unreachable worker records at an evaluator quiescent point.
    ///
    /// Declines (returning `Ok(None)` and counting the skip) when the
    /// evaluator holds transient roots or an in-flight force: sweeping there
    /// could reclaim values held only by unregistered Rust locals. The
    /// quiescence predicate is deliberately conservative - a false negative
    /// costs memory, a false positive would cost correctness.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkErrorKind::GcQuiescentSweep`] if root collection or
    /// the heap sweep fails.
    pub(super) fn sweep_heap_at_quiescence(
        &mut self,
        extra_roots: &[Value],
    ) -> Result<Option<EvalHeapSweepReport>, TreeWalkError> {
        if !self.gc_mode.is_enabled() {
            return Ok(None);
        }
        if !self.is_heap_sweep_quiescent() {
            self.gc_sweeps_skipped_nonquiescent =
                self.gc_sweeps_skipped_nonquiescent.saturating_add(1);
            return Ok(None);
        }
        let report = self.sweep_heap_for_validation(extra_roots)?;
        Ok(Some(report))
    }

    /// Runs one sweep cycle unconditionally (the stress proving ground).
    ///
    /// Unlike [`Self::sweep_heap_at_quiescence`] this does not consult the
    /// mode, threshold, or quiescence predicate: the caller asserts that
    /// every live value outside the heap is reachable from the safepoint
    /// root structures plus `extra_roots`. Tests and stress harnesses use it
    /// to prove transient-root completeness at chosen boundaries - a missed
    /// root surfaces as a loud unknown-pointer error on the next resolution
    /// or during marking, never as silent reuse.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkErrorKind::GcQuiescentSweep`] if root collection or
    /// the heap sweep fails.
    pub(crate) fn sweep_heap_for_validation(
        &mut self,
        extra_roots: &[Value],
    ) -> Result<EvalHeapSweepReport, TreeWalkError> {
        let result = (|| -> Result<EvalHeapSweepReport, TreeWalkGcSweepError> {
            // Mutator roots only: the sweep never collects permanent records,
            // and its marking is worker-only, so the interned tables that
            // `safepoint_root_set` would append are pure overhead here.
            let mut roots = self.mutator_root_set()?;
            for (slot, value) in extra_roots.iter().copied().enumerate() {
                roots
                    .try_push_value_stack(slot, value)
                    .map_err(TreeWalkSafepointRootError::RootSet)?;
            }
            Ok(self.heap.sweep_unreachable_worker_records(&roots)?)
        })();
        let report = result.map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::GcQuiescentSweep { source },
                Span::default(),
            )
        })?;
        self.gc_records_at_last_sweep = self.stats.thunks_allocated;
        self.gc_last_sweep_report = Some(report);
        Ok(report)
    }

    /// Returns the most recent quiescent sweep's cycle report, if any ran.
    pub fn last_gc_sweep_report(&self) -> Option<EvalHeapSweepReport> {
        self.gc_last_sweep_report
    }

    /// Returns `true` when no force is in flight and no transient roots exist.
    ///
    /// At such a point every live value outside the heap is covered by
    /// [`TreeWalk::safepoint_root_set`] (plus caller-supplied extra roots),
    /// which is exactly the precondition of the precise sweep.
    fn is_heap_sweep_quiescent(&self) -> bool {
        self.has_complete_terminal_root_set()
    }

    /// Returns whether post-root diagnostics can build a complete root set.
    ///
    /// The returned root set still needs the caller-owned result value. Active
    /// evaluator continuations, detached work, or locally assembled composite
    /// state make a terminal census incomplete even when their ordinary force
    /// stacks happen to be empty.
    pub(super) fn has_complete_terminal_root_set(&self) -> bool {
        self.transient_value_stack_roots.is_empty()
            && self.active_force_roots.is_empty()
            && self.active_primop_arg_frames.is_empty()
            && self.active_primop_arg_roots.is_empty()
            && self.suspended_env_roots.is_empty()
            && self.active_memo_read_nodes.is_empty()
            && self.pending_flat_captures.is_empty()
            && self.active_call_argument_plans.is_empty()
            && self.active_composite_accumulator_depth == 0
            && self.order_sensitive_binding_depth == 0
            && self.active_import_cache_leases.is_empty()
            && self.active_import_module_leases.is_empty()
            && self.active_force_leases.is_empty()
            && self.active_typed_thunk_work_leases.is_empty()
            && self.active_lambda_call_leases.is_empty()
            && self.stg_apply_runtime.is_idle()
            && !self.stg_session_active
            && self.active_root_eval_node.is_none()
            && self.call_depth == 0
            && self.shared.is_none()
    }

    /// Returns whether only a registered post-root traversal remains active.
    fn is_registered_post_root_traversal_safepoint(&self) -> bool {
        self.active_root_eval_node.is_none()
            && self.active_env_is_empty()
            && self.with_scopes.is_empty()
            && self.scoped_globals.is_empty()
            && self.order_sensitive_binding_depth == 0
            && self.active_call_argument_plans.is_empty()
            && self.active_composite_accumulator_depth == 0
            && self.active_force_roots.is_empty()
            && self.stg_apply_runtime.is_idle()
            && self.active_primop_arg_frames.is_empty()
            && self.active_primop_arg_roots.is_empty()
            && self.suspended_env_roots.is_empty()
            && self.active_memo_read_nodes.is_empty()
            && self.call_depth == 0
            && self.shared.is_none()
    }

    /// Returns whether sweep mode has crossed its allocation cadence.
    fn heap_sweep_threshold_reached(&self) -> bool {
        if !self.gc_mode.is_enabled() {
            return false;
        }
        let allocated_since_last_sweep = self
            .stats
            .thunks_allocated
            .saturating_sub(self.gc_records_at_last_sweep);
        allocated_since_last_sweep >= self.options.gc_sweep_threshold()
    }
}
