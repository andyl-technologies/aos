//! The thunk force protocol: serial, single-entry, and parallel-cell paths.
//!
//! Owns [`TreeWalk::force_value`] and everything under it — the parallel
//! payload-cell claim/replay branches, the serial claimed-thunk body run
//! (with tier-1 dispatch), memoized force-cache consultation, and the
//! finish/shed steps that publish a forced result.

#[cfg(feature = "collection_poll_probe")]
use std::panic::Location;
#[cfg(feature = "collection_poll_probe")]
use std::sync::OnceLock;
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    ptr::NonNull,
};

use crate::value::HeapObject;

use super::*;

impl TreeWalk {
    #[cfg(feature = "collection_poll_probe")]
    fn active_node_work_detachment_enabled(&self) -> bool {
        #[cfg(test)]
        if self.active_node_work_detachment_test_enabled {
            return true;
        }
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| {
            std::env::var_os("AOS_ACTIVE_NODE_FORCE_DETACH")
                .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        })
    }

    /// Begins an evaluator-owned force of an admitted reusable thunk.
    ///
    /// The source thunk and a reserved result slot are installed in the
    /// existing scanned active-force root stack before the detached claim can
    /// escape this call. Consequently a continuation can allocate, trigger
    /// root writeback, and later resolve the thunk cell again using only the
    /// opaque token.
    ///
    /// Ordinary Node, Apply, and exact `GenListElemAtAddOne` marker thunks are
    /// admitted. Single-entry, parallel-payload, other shapes, and typed
    /// detached-work heads decline before mutating their force state. The
    /// latter is important for Candidate C: typed heads own separately
    /// detached work that this lease does not yet carry, so claiming one here
    /// would make that work invisible to the root scanner.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkErrorKind::Heap`] when `source_thunk` cannot be
    /// resolved, [`TreeWalkErrorKind::Force`] when its cell cannot be claimed,
    /// or a force-lease allocation/generation error before any state mutation.
    pub(crate) fn begin_force_lease(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
    ) -> Result<BeginForceLease, TreeWalkError> {
        let ptr = self
            .heap
            .thunk_ptr(source_thunk)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if self
            .heap
            .typed_thunk_force_parts(ptr)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?
            .is_some()
        {
            #[cfg(feature = "collection_poll_probe")]
            self.whole_demand_dispatcher
                .corridor_census
                .note_declined_special();
            return Ok(BeginForceLease::Declined);
        }
        let thunk = self
            .heap
            .get_thunk_ptr(ptr)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if thunk.is_single_entry_force_storage()
            || thunk.parallel_payload_cell().is_some()
            || !matches!(
                thunk.kind(),
                EvalThunkKind::Node { .. }
                    | EvalThunkKind::Apply { .. }
                    | EvalThunkKind::GenListElemAtAddOne { .. }
            )
        {
            #[cfg(feature = "collection_poll_probe")]
            self.whole_demand_dispatcher
                .corridor_census
                .note_declined_special();
            return Ok(BeginForceLease::Declined);
        }
        #[cfg(feature = "collection_poll_probe")]
        let corridor_coordinate = self
            .whole_demand_dispatcher
            .corridor_census
            .is_enabled()
            .then(|| {
                super::super::whole_demand_corridor_census::CorridorForceCoordinate::from_thunk(
                    self.current_module,
                    id,
                    thunk,
                    false,
                    false,
                    self.tier1_engine.is_some(),
                    false,
                )
            });
        #[cfg(feature = "collection_poll_probe")]
        let detach_node_work =
            self.active_node_work_detachment_enabled() && self.tier1_engine.is_none();

        let lease_count = self
            .active_force_leases
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ForceLeaseAllocationFailed {
                        id,
                        leases: usize::MAX,
                    },
                    span,
                )
            })?;
        self.active_force_leases.try_reserve(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ForceLeaseAllocationFailed {
                    id,
                    leases: lease_count,
                },
                span,
            )
        })?;
        let root_count = self
            .active_force_roots
            .len()
            .checked_add(2)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.active_force_roots.try_reserve(2).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed {
                    id,
                    roots: root_count,
                },
                span,
            )
        })?;
        #[cfg(feature = "collection_poll_probe")]
        if detach_node_work {
            self.active_node_work_leases.try_reserve(1).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ForceLeaseAllocationFailed {
                        id,
                        leases: lease_count,
                    },
                    span,
                )
            })?;
        }
        let generation = self
            .next_force_lease_generation
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ForceLeaseGenerationExhausted { id },
                    span,
                )
            })?;

        let claim = thunk
            .cell()
            .begin_detached_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        match claim {
            DetachedForceClaim::AlreadyForced(value) => {
                #[cfg(feature = "collection_poll_probe")]
                self.whole_demand_dispatcher
                    .corridor_census
                    .note_already_forced();
                self.unmark_relocated_lazy_identity_thunk(source_thunk);
                self.increment_thunk_cache_hits();
                Ok(BeginForceLease::AlreadyForced(value))
            }
            DetachedForceClaim::Claimed => {
                #[cfg(feature = "collection_poll_probe")]
                let detached_node_work = if detach_node_work {
                    match self.heap.detach_active_flat_node_work(ptr) {
                        Ok(work) => Some(work),
                        Err(_) => {
                            let source = self.heap.get_thunk_ptr(ptr).map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                            })?;
                            source.cell().abort_detached_force().map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
                            })?;
                            self.whole_demand_dispatcher
                                .corridor_census
                                .note_declined_special();
                            return Ok(BeginForceLease::Declined);
                        }
                    }
                } else {
                    None
                };
                let source_root_index = self.active_force_roots.len();
                let result_root_index = source_root_index + 1;
                self.active_force_roots.push(source_thunk);
                self.active_force_roots.push(Value::null());
                self.next_force_lease_generation = generation;
                let token = ForceLeaseToken::new(self.active_force_leases.len(), generation);
                self.active_force_leases.push(ActiveForceLease {
                    token,
                    id,
                    span,
                    source_root_index,
                    result_root_index,
                });
                #[cfg(feature = "collection_poll_probe")]
                if let Some(work) = detached_node_work {
                    self.active_node_work_leases.push(ActiveNodeWorkLease {
                        token,
                        source: source_thunk,
                        ptr,
                        work,
                    });
                }
                #[cfg(feature = "collection_poll_probe")]
                if let Some(corridor_coordinate) = corridor_coordinate {
                    self.whole_demand_dispatcher
                        .corridor_census
                        .begin_force_lease(token, corridor_coordinate);
                }
                Ok(BeginForceLease::Claimed(token))
            }
        }
    }

    /// Finishes the innermost evaluator-owned force lease.
    ///
    /// The result is copied into the lease's scanned result slot before the
    /// resolution barrier or capture shedding can allocate.
    ///
    /// # Errors
    ///
    /// Returns heap, barrier, or force-state errors from publishing the
    /// detached claim. A failed publication is aborted before the lease roots
    /// are removed, matching [`ForceGuard`]'s drop ordering.
    ///
    /// # Panics
    ///
    /// Panics if `token` is stale or not the innermost active force lease.
    pub(crate) fn finish_force_lease(
        &mut self,
        id: IrId,
        span: Span,
        token: ForceLeaseToken,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let lease = self.peek_force_lease(token);
        self.active_force_roots[lease.result_root_index] = value;
        let source_thunk = self.active_force_roots[lease.source_root_index];
        let ptr = self
            .heap
            .thunk_ptr(source_thunk)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        #[cfg(feature = "collection_poll_probe")]
        if self.active_node_work_for_token(token).is_some() {
            return self.finish_active_node_work_force_lease(id, span, token, source_thunk, value);
        }
        let thunk = self
            .heap
            .share_thunk_from_ptr(ptr, source_thunk)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let released_work_shape = self
            .options
            .eval_stats_dump()
            .then(|| self.force_shape_class(&thunk));
        let tier = self.options.thunk_resolve_barrier_tier();
        let publish: Result<Value, TreeWalkError> = if tier == GenerationalGcTier::OneShotArena {
            let mut barrier = crate::eval::DisabledThunkResolveBarrier;
            thunk
                .cell()
                .finish_detached_force(value, &mut barrier)
                .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))
        } else {
            runtime_thunk_resolve_write_barrier_with_card_table(
                tier,
                &self.heap,
                source_thunk,
                &mut self.thunk_resolve_remembered_set,
                &mut self.thunk_resolve_card_table,
            )
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
            .and_then(|mut barrier| {
                thunk
                    .cell()
                    .finish_detached_force(value, &mut barrier)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
                    })
            })
        };
        let value = match publish {
            Ok(value) => value,
            Err(error) => {
                let _ = thunk.cell().abort_detached_force();
                self.pop_force_lease(token);
                return Err(error);
            }
        };
        if let Some(shape) = released_work_shape {
            super::super::force_shape_census::record_work_release(shape);
        }
        if self.gc_mode.is_enabled()
            && let Err(error) = self.shed_forced_thunk_captures(id, span, source_thunk)
        {
            self.pop_force_lease(token);
            return Err(error);
        }
        let relocated_source_thunk = self.pop_force_lease(token);
        self.unmark_relocated_lazy_identity_thunk(relocated_source_thunk);
        Ok(value)
    }

    #[cfg(feature = "collection_poll_probe")]
    fn finish_active_node_work_force_lease(
        &mut self,
        id: IrId,
        span: Span,
        token: ForceLeaseToken,
        source_thunk: Value,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let ptr = self
            .heap
            .thunk_ptr(source_thunk)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let released_work_shape = self
            .options
            .eval_stats_dump()
            .then(|| self.active_node_work_for_token(token))
            .flatten()
            .map(|work| self.force_shape_class(work));
        let tier = self.options.thunk_resolve_barrier_tier();
        let publish = if tier == GenerationalGcTier::OneShotArena {
            let mut barrier = crate::eval::DisabledThunkResolveBarrier;
            self.heap
                .get_thunk_ptr(ptr)
                .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?
                .cell()
                .finish_detached_force(value, &mut barrier)
                .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))
        } else {
            runtime_thunk_resolve_write_barrier_with_card_table(
                tier,
                &self.heap,
                source_thunk,
                &mut self.thunk_resolve_remembered_set,
                &mut self.thunk_resolve_card_table,
            )
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))
            .and_then(|mut barrier| {
                self.heap
                    .get_thunk_ptr(ptr)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?
                    .cell()
                    .finish_detached_force(value, &mut barrier)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
                    })
            })
        };
        let value = match publish {
            Ok(value) => value,
            Err(error) => {
                self.restore_and_abort_active_node_work(id, span, token)?;
                self.pop_force_lease(token);
                return Err(error);
            }
        };
        let Some(_released_work) = self.pop_active_node_work_lease(token) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::TypedThunkWorkLeaseInvariant { id },
                span,
            ));
        };
        if let Some(shape) = released_work_shape {
            super::super::force_shape_census::record_work_release(shape);
        }
        let relocated_source_thunk = self.pop_force_lease(token);
        self.unmark_relocated_lazy_identity_thunk(relocated_source_thunk);
        Ok(value)
    }

    #[cfg(feature = "collection_poll_probe")]
    fn restore_and_abort_active_node_work(
        &mut self,
        id: IrId,
        span: Span,
        token: ForceLeaseToken,
    ) -> Result<(), TreeWalkError> {
        let Some(lease) = self.pop_active_node_work_lease(token) else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::TypedThunkWorkLeaseInvariant { id },
                span,
            ));
        };
        let ActiveNodeWorkLease {
            token: lease_token,
            source,
            ptr,
            work,
        } = lease;
        debug_assert_eq!(lease_token, token);
        match self.heap.restore_active_flat_node_work(ptr, work) {
            Ok(()) => {}
            Err((source_error, work)) => {
                self.active_node_work_leases.push(ActiveNodeWorkLease {
                    token: lease_token,
                    source,
                    ptr,
                    work,
                });
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id,
                        source: source_error,
                    },
                    span,
                ));
            }
        }
        self.heap
            .get_thunk_ptr(ptr)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?
            .cell()
            .abort_detached_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))
    }

    /// Aborts the innermost evaluator-owned force lease.
    ///
    /// # Errors
    ///
    /// Returns heap or force-state errors while restoring the thunk to
    /// suspended. The lease remains active if the cell cannot be resolved or
    /// aborted.
    ///
    /// # Panics
    ///
    /// Panics if `token` is stale or not the innermost active force lease.
    pub(crate) fn abort_force_lease(
        &mut self,
        id: IrId,
        span: Span,
        token: ForceLeaseToken,
    ) -> Result<(), TreeWalkError> {
        let lease = self.peek_force_lease(token);
        let source_thunk = self.active_force_roots[lease.source_root_index];
        #[cfg(feature = "collection_poll_probe")]
        if self.active_node_work_for_token(token).is_some() {
            self.restore_and_abort_active_node_work(id, span, token)?;
            self.pop_force_lease(token);
            return Ok(());
        }
        let ptr = self
            .heap
            .thunk_ptr(source_thunk)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let thunk = self
            .heap
            .share_thunk_from_ptr(ptr, source_thunk)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        thunk
            .cell()
            .abort_detached_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        self.pop_force_lease(token);
        Ok(())
    }

    /// Runs a body under a panic-safe evaluator-owned force lease.
    ///
    /// Ordinary tail-free Node forces use this owner after detaching their
    /// suspended work from the stable blackholed publication shell.
    ///
    /// # Errors
    ///
    /// Returns the body error after aborting the claim, or any error returned
    /// while publishing a successful body result.
    ///
    /// # Panics
    ///
    /// Resumes a body panic after first aborting the claim. Panics instead with
    /// the cleanup failure if work cannot be restored during unwinding. Also
    /// panics when `token` is stale or not the innermost lease.
    pub(crate) fn run_force_lease_with(
        &mut self,
        id: IrId,
        span: Span,
        token: ForceLeaseToken,
        body: impl FnOnce(&mut Self) -> Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self)));
        match result {
            Ok(Ok(value)) => self.finish_force_lease(id, span, token, value),
            Ok(Err(error)) => {
                self.abort_force_lease(id, span, token)?;
                Err(error)
            }
            Err(payload) => {
                if let Err(cleanup) = self.abort_force_lease(id, span, token) {
                    panic!("failed to restore active force work during panic cleanup: {cleanup}");
                }
                std::panic::resume_unwind(payload)
            }
        }
    }

    fn peek_force_lease(&self, token: ForceLeaseToken) -> ActiveForceLease {
        let Some(active) = self.active_force_leases.last().copied() else {
            unreachable!("active force lease stack is unbalanced");
        };
        assert_eq!(
            active.token, token,
            "force lease token is stale or out of order"
        );
        debug_assert_eq!(token.depth(), self.active_force_leases.len() - 1);
        debug_assert_eq!(token.generation(), active.token.generation());
        debug_assert_eq!(active.result_root_index, active.source_root_index + 1);
        debug_assert_eq!(active.result_root_index + 1, self.active_force_roots.len());
        active
    }

    fn pop_force_lease(&mut self, token: ForceLeaseToken) -> Value {
        let active = self.peek_force_lease(token);
        let Some(popped) = self.active_force_leases.pop() else {
            unreachable!("checked active force lease disappeared");
        };
        #[cfg(feature = "collection_poll_probe")]
        self.whole_demand_dispatcher
            .corridor_census
            .finish_force_lease(token);
        debug_assert_eq!(popped.token, token);
        let result = self.active_force_roots.pop();
        debug_assert!(result.is_some());
        let source = self.active_force_roots.pop();
        debug_assert_eq!(self.active_force_roots.len(), active.source_root_index);
        match source {
            Some(source) => source,
            None => unreachable!("force lease source root disappeared"),
        }
    }

    pub(super) fn admit_parallel_thunk_payload_cell(
        &self,
        id: IrId,
        span: Span,
        thunk: EvalThunk,
    ) -> EvalThunk {
        if self.options.parallel_thunk_payloads_enabled() {
            thunk.with_parallel_payload_cell(
                TreeWalkError::new(TreeWalkErrorKind::ParallelThunkClaimDropped { id }, span),
                self.parallel_force_registry.clone(),
            )
        } else {
            thunk
        }
    }

    #[allow(unsafe_code)]
    #[cfg_attr(feature = "collection_poll_probe", track_caller)]
    pub(crate) fn force_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "collection_poll_probe")]
        {
            return self.force_value_from_caller(id, span, value, Location::caller());
        }
        #[cfg(not(feature = "collection_poll_probe"))]
        {
            self.force_value_with_native_census(id, span, value)
        }
    }

    /// Forces one value while retaining an outward caller captured by a portal.
    #[cfg(feature = "collection_poll_probe")]
    pub(in crate::eval::tree_walk) fn force_value_from_caller(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        caller_location: &'static Location<'static>,
    ) -> Result<Value, TreeWalkError> {
        self.with_attributed_native_continuation_edge(
            super::super::native_continuation_shadow::NativeContinuationEdge::ForceValue,
            super::super::native_continuation_shadow::NativeContinuationKind::PrimOpForceLeaf,
            id,
            caller_location,
            |eval| eval.force_value_with_native_census(id, span, value),
        )
    }

    #[allow(unsafe_code)]
    fn force_value_with_native_census(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = match classify_whnf_tag_fast_path(value) {
            WhnfTagFastPath::AlreadyWhnf(value) => return Ok(value),
            WhnfTagFastPath::RequiresThunkProtocol(value) => value,
        };
        #[cfg(feature = "collection_poll_probe")]
        let token = self.begin_speed_opportunity_phase(
            super::super::whole_demand_corridor_census::SpeedOpportunityPhase::Force,
        );
        let result = self.force_value_with_native_census_inner(id, span, value);
        #[cfg(feature = "collection_poll_probe")]
        self.finish_speed_opportunity_phase(token, &result);
        result
    }

    #[allow(unsafe_code)]
    fn force_value_with_native_census_inner(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "lifetime_cohort_probe")]
        {
            let mut roots = [value];
            return self.with_lifetime_cohort_shadow_roots(id, span, &mut roots, |eval, slots| {
                let value = eval
                    .current_transient_value_stack_root(slots.start)
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?;
                eval.force_value_with_lifetime_shadow(id, span, value)
            });
        }
        #[cfg(not(feature = "lifetime_cohort_probe"))]
        {
            self.force_value_with_lifetime_shadow(id, span, value)
        }
    }

    #[allow(unsafe_code)]
    fn force_value_with_lifetime_shadow(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "active_packed_thunk_probe")]
        if self.heap.is_active_packed_thunk(value) {
            return self.force_active_packed_thunk(id, span, value);
        }
        // Decode the thunk handle once. The re-force cache peek and the share
        // below both resolve this same value; decoding twice re-walks the
        // carrier word and the reservation-base registry for no gain (RFC-0007
        // instruction-tax lever 2).
        let ptr = self
            .heap
            .thunk_ptr(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if let Some(parts) = self
            .heap
            .typed_thunk_force_parts(ptr)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?
        {
            return self.force_typed_apply_thunk(id, span, value, ptr, parts);
        }
        #[cfg(feature = "collection_poll_probe")]
        if let Some(result) = self.try_force_detached_node_work(id, span, value, ptr)? {
            return Ok(result);
        }
        // The default serial one-shot heap never moves, retires, sheds, or
        // replaces a live thunk payload. Keep that payload in place while its
        // body re-enters evaluation, and use this same resolution for the
        // already-forced probe. Previously a suspended thunk was resolved once
        // for that probe and again before body evaluation. GC and tier-1
        // execution retain the shared handle path below because they may
        // replace a payload or invoke a heap-mutating engine hook while the
        // force is active.
        if !self.gc_mode.is_enabled()
            && self.tier1_engine.is_none()
            && let Some(thunk_ptr) =
                self.heap
                    .serial_flat_thunk_payload_ptr(ptr)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?
        {
            // SAFETY: `serial_flat_thunk_payload_ptr` proved that `thunk_ptr`
            // names a live thunk payload in this evaluator's serial flat
            // arena. The one-shot, GC-disabled path cannot retire, relocate,
            // shed, or replace that payload. `source_thunk` is pushed into the
            // active-force roots before body evaluation, preventing a lexical
            // region pop from reclaiming it during re-entry. The tier-1 engine
            // is absent, so no engine callback can mutate the source record.
            // Nested allocations use disjoint stable arena addresses. The
            // thunk's force cell uses interior atomic mutation by design.
            let thunk = unsafe { thunk_ptr.as_ref() };
            if thunk.parallel_payload_cell().is_none() {
                if let Some(forced) =
                    self.reforce_already_forced_serial_thunk(id, span, value, thunk)?
                {
                    return Ok(forced);
                }
                return self.force_serial_thunk_value(id, span, value, thunk);
            }
        }
        if let Some(forced) = self.reforce_already_forced_thunk(id, span, value, ptr)? {
            return Ok(forced);
        }
        let thunk = self
            .heap
            .share_thunk_from_ptr(ptr, value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if let Some(parallel_cell) = thunk.parallel_payload_cell() {
            return self.force_parallel_payload_thunk(id, span, value, &thunk, parallel_cell);
        }
        self.force_serial_thunk_value(id, span, value, &thunk)
    }

    #[cfg(feature = "active_packed_thunk_probe")]
    fn eval_active_packed_apply_work(
        &mut self,
        id: IrId,
        span: Span,
        work: crate::eval::heap::ActivePackedApplyWork,
    ) -> Result<Value, TreeWalkError> {
        self.note_direct_island_force();
        if work.gen_list_elem_at_add_one
            && let Some(result) = self.try_force_genlist_elem_at_add_one(
                id,
                span,
                work.function_value,
                work.argument_value,
            )
        {
            return result;
        }
        self.with_current_module(work.function.module(), |eval| {
            eval.apply_lambda_value(
                id,
                span,
                work.function.id(),
                work.function_value,
                work.function_span,
                work.argument.id(),
                work.argument_value,
            )
        })
    }

    #[cfg(feature = "collection_poll_probe")]
    fn try_force_detached_node_work(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        ptr: NonNull<HeapObject>,
    ) -> Result<Option<Value>, TreeWalkError> {
        if !self.active_node_work_detachment_enabled() || self.tier1_engine.is_some() {
            return Ok(None);
        }
        let eligible = {
            let thunk = self.heap.get_thunk_ptr(ptr).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            !thunk.is_single_entry_force_storage()
                && thunk.parallel_payload_cell().is_none()
                && matches!(
                    thunk.kind(),
                    EvalThunkKind::Node { .. }
                        | EvalThunkKind::Apply { .. }
                        | EvalThunkKind::GenListElemAtAddOne { .. }
                )
        };
        if !eligible {
            return Ok(None);
        }
        match self.begin_force_lease(id, span, source_thunk)? {
            BeginForceLease::AlreadyForced(value) => Ok(Some(value)),
            BeginForceLease::Claimed(token) => {
                let body_work =
                    self.active_node_work_for_token(token)
                        .cloned()
                        .ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::TypedThunkWorkLeaseInvariant { id },
                                span,
                            )
                        })?;
                self.increment_thunks_forced();
                self.run_force_lease_with(id, span, token, |eval| {
                    eval.eval_thunk_body(id, span, &body_work)
                })
                .map(Some)
            }
            BeginForceLease::Declined => Ok(None),
        }
    }

    #[cfg(feature = "active_packed_thunk_probe")]
    #[inline(never)]
    fn force_active_packed_thunk(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        match self
            .heap
            .begin_active_packed_thunk_force(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?
        {
            crate::eval::heap::ActivePackedThunkForce::NotPacked => Err(TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id,
                    source: EvalHeapError::ActivePackedThunk {
                        message: "active packed domain match disappeared before force".to_string(),
                    },
                },
                span,
            )),
            crate::eval::heap::ActivePackedThunkForce::AlreadyForced(result) => {
                self.unmark_relocated_lazy_identity_thunk(value);
                self.increment_thunk_cache_hits();
                Ok(result)
            }
            crate::eval::heap::ActivePackedThunkForce::Claimed {
                reference,
                handle,
                work,
            } => {
                self.increment_thunks_forced();
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if std::mem::take(&mut self.panic_active_packed_thunk_body_once) {
                        panic!("injected active packed thunk body panic");
                    }
                    self.eval_active_packed_apply_work(id, span, work)
                }));
                let result = match outcome {
                    Ok(Ok(result)) => result,
                    Ok(Err(error)) => {
                        self.heap
                            .abort_active_packed_thunk_force(reference, handle)
                            .map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                            })?;
                        return Err(error);
                    }
                    Err(payload) => {
                        let restored = self.heap.abort_active_packed_thunk_force(reference, handle);
                        assert!(
                            restored.is_ok(),
                            "failed to abort active packed thunk during panic cleanup"
                        );
                        resume_unwind(payload);
                    }
                };
                self.heap
                    .publish_active_packed_thunk_force(reference, handle, result)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                self.unmark_relocated_lazy_identity_thunk(value);
                Ok(result)
            }
        }
    }

    /// Forces one default-off typed Apply-shaped head through its stable cell.
    #[allow(unsafe_code)]
    fn force_typed_apply_thunk(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        ptr: NonNull<HeapObject>,
        parts: crate::eval::heap::TypedThunkForceParts,
    ) -> Result<Value, TreeWalkError> {
        // SAFETY: `parts` came from `self.heap`; the heap remains live for the
        // complete match, including every guard drop and publication path.
        match unsafe { parts.begin_force() }
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        {
            crate::eval::heap::TypedThunkForceClaim::AlreadyForced(value) => {
                #[cfg(feature = "collection_poll_probe")]
                self.whole_demand_dispatcher
                    .corridor_census
                    .note_already_forced();
                self.unmark_relocated_lazy_identity_thunk(source_thunk);
                self.increment_thunk_cache_hits();
                Ok(value)
            }
            crate::eval::heap::TypedThunkForceClaim::Claimed(guard) => {
                let handle = guard.handle();
                let work = self
                    .heap
                    .take_typed_thunk_work(ptr, handle)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                if let Err((error, work)) = self.push_active_typed_thunk_work_lease(
                    id,
                    span,
                    source_thunk,
                    ptr,
                    handle,
                    work,
                ) {
                    self.heap
                        .restore_typed_thunk_work(ptr, handle, work)
                        .map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                        })?;
                    return Err(error);
                }
                // Evaluation needs `&mut self`, so it reads an immutable clone
                // while the authoritative detached work remains evaluator-owned
                // and explicitly scannable for the complete re-entrant body.
                let body_work = match self.active_typed_thunk_work_leases.last() {
                    Some(lease) => lease.work.clone(),
                    None => {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::TypedThunkWorkLeaseInvariant { id },
                            span,
                        ));
                    }
                };
                let ready_probe = self.probe_typed_local_ready(&body_work);
                #[cfg(feature = "collection_poll_probe")]
                let corridor_coordinate = self
                    .whole_demand_dispatcher
                    .corridor_census
                    .is_enabled()
                    .then(|| {
                        super::super::whole_demand_corridor_census::CorridorForceCoordinate::from_thunk(
                            self.current_module,
                            id,
                            &body_work,
                            false,
                            body_work.parallel_payload_cell().is_some(),
                            self.tier1_engine.is_some(),
                            true,
                        )
                    });
                #[cfg(feature = "collection_poll_probe")]
                let corridor_token = corridor_coordinate.and_then(|coordinate| {
                    self.whole_demand_dispatcher
                        .corridor_census
                        .begin_typed_force(coordinate)
                });
                let result = match &ready_probe {
                    super::super::memo::TypedLocalReadyProbe::Hit(value) => Ok(Ok(*value)),
                    _ => {
                        self.increment_thunks_forced();
                        catch_unwind(AssertUnwindSafe(|| {
                            #[cfg(test)]
                            if std::mem::take(&mut self.panic_typed_thunk_body_once) {
                                panic!("injected typed thunk body panic");
                            }
                            self.eval_thunk_body(id, span, &body_work)
                        }))
                    }
                };
                let work = match self.pop_active_typed_thunk_work_lease(
                    id,
                    span,
                    source_thunk,
                    ptr,
                    handle,
                ) {
                    Ok(work) => work,
                    Err(error) => {
                        #[cfg(feature = "collection_poll_probe")]
                        if let Some(corridor_token) = corridor_token {
                            self.whole_demand_dispatcher
                                .corridor_census
                                .finish_force(corridor_token, false);
                        }
                        return Err(error);
                    }
                };
                #[cfg(feature = "collection_poll_probe")]
                if let Some(corridor_token) = corridor_token {
                    self.whole_demand_dispatcher
                        .corridor_census
                        .finish_force(corridor_token, result.is_ok());
                }
                let result = match result {
                    Ok(result) => result,
                    Err(payload) => {
                        self.fail_typed_local_ready(&ready_probe);
                        let restored = self.heap.restore_typed_thunk_work(ptr, handle, work);
                        assert!(
                            restored.is_ok(),
                            "failed to restore typed thunk work during panic cleanup"
                        );
                        resume_unwind(payload);
                    }
                };
                let relocated_source_thunk = source_thunk;
                let value = match result {
                    Ok(value) => value,
                    Err(error) => {
                        self.fail_typed_local_ready(&ready_probe);
                        self.heap
                            .restore_typed_thunk_work(ptr, handle, work)
                            .map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                            })?;
                        return Err(error);
                    }
                };
                let value = match guard.finish(value) {
                    Ok(value) => value,
                    Err(source) => {
                        self.fail_typed_local_ready(&ready_probe);
                        self.heap
                            .restore_typed_thunk_work(ptr, handle, work)
                            .map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                            })?;
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::Force { id, source },
                            span,
                        ));
                    }
                };
                self.heap
                    .release_taken_typed_thunk_work(ptr, handle)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                self.publish_typed_local_ready(&ready_probe, source_thunk, value);
                self.unmark_relocated_lazy_identity_thunk(relocated_source_thunk);
                Ok(value)
            }
        }
    }

    /// Replays a cached result from the already-resolved one-shot serial thunk.
    fn reforce_already_forced_serial_thunk(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        thunk: &EvalThunk,
    ) -> Result<Option<Value>, TreeWalkError> {
        if thunk.is_single_entry_force_storage() {
            return Ok(None);
        }
        let Some(cached) = thunk
            .cell()
            .cached_value()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        else {
            return Ok(None);
        };
        #[cfg(feature = "collection_poll_probe")]
        if matches!(thunk.kind(), EvalThunkKind::Node { .. }) {
            self.whole_demand_dispatcher
                .corridor_census
                .note_already_forced();
        } else {
            self.whole_demand_dispatcher
                .corridor_census
                .note_declined_special();
        }
        self.increment_reforce_fast_path_hits();
        self.unmark_relocated_lazy_identity_thunk(value);
        self.increment_thunk_cache_hits();
        Ok(Some(cached))
    }

    /// Returns a thunk's already-published forced result before the full
    /// force protocol runs, or `None` when the thunk must enter the protocol.
    ///
    /// Re-forcing a thunk that already cached a result is the dominant force
    /// class, yet the general path still pays [`EvalHeap::share_thunk`]'s Arc
    /// mint, the active-force root push/pop, and the [`ThunkCell::begin_force`]
    /// claim before the claim discovers the cell is already `Forced`. This
    /// fast path resolves the thunk record with a borrow only (no Arc mint),
    /// acquire-loads the write-once monotone cell, and returns the cached value
    /// directly on a `Forced` observation.
    ///
    /// The cell publishes its result exactly once and never changes it
    /// (`Suspended -> Blackhole -> Forced`), so a single acquire load observing
    /// `Forced` makes the subsequent result read sound — the identical argument
    /// the `begin_force` `AlreadyForced` arm relies on. The returned value stays
    /// reachable through the thunk record, so no rooting is required, matching
    /// the protocol's own `AlreadyForced` arm which also skips the force root.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkErrorKind::Heap`] if `value` does not resolve to a
    /// thunk record in this evaluator's heap, or [`TreeWalkErrorKind::Force`]
    /// if the resolved cell reports an invalid state word or a missing forced
    /// value.
    fn reforce_already_forced_thunk(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        ptr: NonNull<HeapObject>,
    ) -> Result<Option<Value>, TreeWalkError> {
        let thunk = self
            .heap
            .get_thunk_ptr(ptr)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        // Single-entry thunks re-evaluate their body on every force and never
        // publish a cached result, so they must always take the full path.
        if thunk.is_single_entry_force_storage() {
            return Ok(None);
        }
        let has_parallel_cell = thunk.parallel_payload_cell().is_some();
        #[cfg(feature = "collection_poll_probe")]
        let corridor_reusable_node =
            !has_parallel_cell && matches!(thunk.kind(), EvalThunkKind::Node { .. });
        let cached = thunk
            .cell()
            .cached_value()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        // The immutable-borrow of `thunk` ends here so the `&mut self` replay and
        // counter calls below can run.
        let Some(cached) = cached else {
            return Ok(None);
        };
        #[cfg(feature = "collection_poll_probe")]
        if corridor_reusable_node {
            self.whole_demand_dispatcher
                .corridor_census
                .note_already_forced();
        } else {
            self.whole_demand_dispatcher
                .corridor_census
                .note_declined_special();
        }
        self.increment_reforce_fast_path_hits();
        if has_parallel_cell {
            // A parallel-payload thunk forced by another worker still needs the
            // shared-context prefix refresh and cache-hit accounting the payload
            // replay performs; route through it rather than duplicating that
            // contract here.
            return self
                .replay_parallel_payload_terminal_result(value, Ok(cached))
                .map(Some);
        }
        self.unmark_relocated_lazy_identity_thunk(value);
        self.increment_thunk_cache_hits();
        Ok(Some(cached))
    }

    fn force_parallel_payload_thunk(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        thunk: &EvalThunk,
        parallel_cell: &TreeWalkParallelThunkCell,
    ) -> Result<Value, TreeWalkError> {
        // Fast path: a serial-cell `Forced` observation is release-published by
        // the forcing worker before the parallel cell's own terminal publish,
        // and the cached value is immutable after publication, so an
        // acquire-load hit here replays the exact result the parallel cell
        // would hand back - without the payload mutex or the payload clone.
        // Repeated forces of already-forced thunks dominate the parallel-mode
        // force mix, so this removes the largest single-worker overhead of the
        // shared backend (L2-P4 item 4). Failed forces never reach `Forced`,
        // so error replay still flows through the payload cell below.
        if let Some(value) = thunk
            .cell()
            .cached_value()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        {
            return self.replay_parallel_payload_terminal_result(source_thunk, Ok(value));
        }
        if let Some(result) = parallel_cell.checked_terminal_result().map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::ParallelThunkPayload { id, source }, span)
        })? {
            return self.replay_parallel_payload_terminal_result(source_thunk, result);
        }

        let worker = self.options.parallel_thunk_worker_id();
        let body_ran = std::cell::Cell::new(false);
        // Claim-wait diagnostics (stats runs only): time slow-path forces
        // that resolve without running the body - i.e. waits on a claim
        // another worker owns, plus racy terminal replays. Gated on the
        // stats dump so production parallel runs skip the per-force clock.
        let wait_started =
            (self.shared.is_some() && self.options.eval_stats_dump()).then(std::time::Instant::now);
        let outcome = parallel_cell
            .force_or_wait_with(worker, || {
                body_ran.set(true);
                self.force_serial_thunk_value(id, span, source_thunk, thunk)
            })
            .map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::ParallelThunkPayload { id, source }, span)
            })?;
        if let Some(started) = wait_started
            && !body_ran.get()
            && let Some(shared) = self.shared.as_ref()
        {
            shared.record_claim_wait(started.elapsed());
        }
        match outcome {
            TreeWalkParallelThunkForceOutcome::Ready(result) => {
                if body_ran.get() {
                    result
                } else {
                    self.replay_parallel_payload_terminal_result(source_thunk, result)
                }
            }
            TreeWalkParallelThunkForceOutcome::SelfCycle { .. } => Err(TreeWalkError::new(
                TreeWalkErrorKind::Force {
                    id,
                    source: ForceError::InfiniteRecursion,
                },
                span,
            )),
        }
    }

    fn replay_parallel_payload_terminal_result(
        &mut self,
        source_thunk: Value,
        result: Result<Value, TreeWalkError>,
    ) -> Result<Value, TreeWalkError> {
        // Replaying a result another worker published is a foreign-value
        // ingestion point: refresh the shared-context prefix replicas so all
        // symbols, modules, and derivation surfaces reachable from the
        // replayed value (or error) resolve locally. The publishing edge of
        // the parallel cell happens-before this call, so the shared logs are
        // never stale here.
        self.sync_shared_context();
        match result {
            Ok(value) => {
                self.unmark_relocated_lazy_identity_thunk(source_thunk);
                self.increment_thunk_cache_hits();
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    fn force_serial_thunk_value(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        thunk: &EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        if thunk.is_single_entry_force_storage() {
            #[cfg(test)]
            self.capture_validation_arm_force(source_thunk, thunk.kind());
            #[cfg(test)]
            let result = {
                let result = self.force_single_entry_thunk_value(id, span, source_thunk, thunk);
                self.capture_validation_disarm();
                result
            };
            #[cfg(not(test))]
            let result = self.force_single_entry_thunk_value(id, span, source_thunk, thunk);
            return result;
        }
        #[cfg(feature = "collection_poll_probe")]
        let corridor_coordinate = self
            .whole_demand_dispatcher
            .corridor_census
            .is_enabled()
            .then(|| {
                super::super::whole_demand_corridor_census::CorridorForceCoordinate::from_thunk(
                    self.current_module,
                    id,
                    thunk,
                    false,
                    thunk.parallel_payload_cell().is_some(),
                    self.tier1_engine.is_some(),
                    false,
                )
            });
        if let EvalThunkKind::Apply {
            function,
            function_span,
            function_value,
            argument,
            argument_value,
        } = thunk.kind()
            && let Some(result) = self.try_force_stg_apply(
                id,
                span,
                source_thunk,
                *function,
                *function_span,
                *function_value,
                *argument,
                *argument_value,
            )
        {
            return result;
        }
        match thunk
            .cell()
            .begin_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        {
            ForceClaim::AlreadyForced(value) => {
                #[cfg(feature = "collection_poll_probe")]
                self.whole_demand_dispatcher
                    .corridor_census
                    .note_already_forced();
                self.unmark_relocated_lazy_identity_thunk(source_thunk);
                self.increment_thunk_cache_hits();
                Ok(value)
            }
            ForceClaim::Claimed(guard) => {
                self.push_active_force_root(id, span, source_thunk)?;
                #[cfg(feature = "collection_poll_probe")]
                let corridor_token = corridor_coordinate.and_then(|coordinate| {
                    self.whole_demand_dispatcher
                        .corridor_census
                        .begin_generic_force(coordinate, 1)
                });
                #[cfg(test)]
                self.capture_validation_arm_force(source_thunk, thunk.kind());
                #[cfg(feature = "collection_poll_probe")]
                let result = if let Some(corridor_token) = corridor_token {
                    match catch_unwind(AssertUnwindSafe(|| {
                        self.force_claimed_thunk_with_tier1(id, span, source_thunk, thunk, guard)
                    })) {
                        Ok(result) => result,
                        Err(payload) => {
                            let _ = self.pop_active_force_root();
                            self.whole_demand_dispatcher
                                .corridor_census
                                .finish_force(corridor_token, false);
                            #[cfg(test)]
                            self.capture_validation_disarm();
                            resume_unwind(payload);
                        }
                    }
                } else {
                    self.force_claimed_thunk_with_tier1(id, span, source_thunk, thunk, guard)
                };
                #[cfg(not(feature = "collection_poll_probe"))]
                let result =
                    self.force_claimed_thunk_with_tier1(id, span, source_thunk, thunk, guard);
                let relocated_source_thunk = self.pop_active_force_root();
                #[cfg(feature = "collection_poll_probe")]
                if let Some(corridor_token) = corridor_token {
                    self.whole_demand_dispatcher
                        .corridor_census
                        .finish_force(corridor_token, result.is_ok());
                }
                #[cfg(test)]
                self.capture_validation_disarm();
                if result.is_ok() {
                    self.unmark_relocated_lazy_identity_thunk(relocated_source_thunk);
                }
                result
            }
        }
    }

    /// Consults the optional tier-1 engine before running the tree-walk body.
    ///
    /// When an engine is installed it is asked once whether this claimed thunk
    /// has published tier-1 native code to dispatch. On a successful dispatch the
    /// native value is published through the normal
    /// [`finish_forced_value`](Self::finish_forced_value) path. On a deopt (native
    /// code trapped or errored) or when the engine declines, evaluation falls
    /// through to the existing memoized tree-walk body. The engine borrows `&mut
    /// self`; the shared thunk `Rc` and its [`ForceGuard`] never borrow `self`, so
    /// the engine is free to re-enter forcing and mutate the heap while dispatching.
    fn force_claimed_thunk_with_tier1(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        thunk: &EvalThunk,
        guard: ForceGuard<'_>,
    ) -> Result<Value, TreeWalkError> {
        if let Some(engine) = self.tier1_engine.clone() {
            // Fast path: a thunk with no lowerable IR body can never dispatch, and
            // a def-site the engine has already gated will never dispatch again.
            // Both are recognized from a cheap `body_ref` field read, so skip the
            // engine hook (and its heap-record and side-table lookups) entirely.
            // This is byte-identical to consulting the engine, which would do
            // nothing for either case, but removes the per-force hook tax from the
            // common cold-thunk path.
            let def_site = thunk.body_ref();
            let consult = match def_site {
                Some(def_site) => !self.tier1_skipped_def_sites.contains(&def_site),
                None => false,
            };
            if consult {
                match engine.on_serial_force(self, source_thunk, id, span) {
                    Tier1ForceHook::Dispatched(value) => {
                        self.increment_tier1_dispatched();
                        let value =
                            self.finish_forced_value(id, span, source_thunk, guard, value)?;
                        return Ok(value);
                    }
                    Tier1ForceHook::Deopted => self.increment_tier1_deopted(),
                    Tier1ForceHook::Continued {
                        promoted,
                        blacklisted,
                        gated,
                    } => {
                        if promoted {
                            self.increment_tier1_promoted();
                        }
                        if blacklisted {
                            self.increment_tier1_blacklisted();
                        }
                        if gated && let Some(def_site) = def_site {
                            self.tier1_skipped_def_sites.insert(def_site);
                        }
                    }
                }
            }
        }
        self.force_claimed_thunk_with_memo(id, span, source_thunk, thunk, guard)
    }

    fn force_single_entry_thunk_value(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        thunk: &EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        self.push_active_force_root(id, span, source_thunk)?;
        #[cfg(feature = "collection_poll_probe")]
        let corridor_coordinate = self
            .whole_demand_dispatcher
            .corridor_census
            .is_enabled()
            .then(|| {
                super::super::whole_demand_corridor_census::CorridorForceCoordinate::from_thunk(
                    self.current_module,
                    id,
                    thunk,
                    true,
                    thunk.parallel_payload_cell().is_some(),
                    self.tier1_engine.is_some(),
                    false,
                )
            });
        #[cfg(feature = "collection_poll_probe")]
        let corridor_token = corridor_coordinate.and_then(|coordinate| {
            self.whole_demand_dispatcher
                .corridor_census
                .begin_generic_force(coordinate, 1)
        });
        #[cfg(feature = "collection_poll_probe")]
        let result = if let Some(corridor_token) = corridor_token {
            match catch_unwind(AssertUnwindSafe(|| {
                self.increment_thunks_forced();
                self.increment_single_entry_thunks_forced();
                self.eval_thunk_body(id, span, thunk)
            })) {
                Ok(result) => result,
                Err(payload) => {
                    let _ = self.pop_active_force_root();
                    self.whole_demand_dispatcher
                        .corridor_census
                        .finish_force(corridor_token, false);
                    resume_unwind(payload);
                }
            }
        } else {
            self.increment_thunks_forced();
            self.increment_single_entry_thunks_forced();
            self.eval_thunk_body(id, span, thunk)
        };
        #[cfg(not(feature = "collection_poll_probe"))]
        let result = (|| -> Result<Value, TreeWalkError> {
            self.increment_thunks_forced();
            self.increment_single_entry_thunks_forced();
            self.eval_thunk_body(id, span, thunk)
        })();
        let source_thunk = self.pop_active_force_root();
        #[cfg(feature = "collection_poll_probe")]
        if let Some(corridor_token) = corridor_token {
            self.whole_demand_dispatcher
                .corridor_census
                .finish_force(corridor_token, result.is_ok());
        }
        let value = result?;
        self.unmark_relocated_lazy_identity_thunk(source_thunk);
        Ok(value)
    }

    pub(in crate::eval::tree_walk) fn unmark_relocated_lazy_identity_thunk(
        &mut self,
        value: Value,
    ) {
        self.unmark_lazy_identity_thunk_payload(value.relocation_sensitive_identity_bits());
    }

    pub(in crate::eval::tree_walk) fn force_memoized_claimed_thunk(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        thunk: &EvalThunk,
        guard: ForceGuard<'_>,
    ) -> Result<Value, TreeWalkError> {
        // When no forced-expression cache is observable, every step below (subject
        // content hashing, memoization-demand recording, payload hashing on
        // observation) is a no-op that still pays for the hashes. Skip straight to
        // the body force. This is behaviorally identical to the cached path with an
        // always-`Admit` decision and disabled lookup/observe, but avoids the
        // hashing measured to dominate cache-off evaluation.
        if !self.force_cache_active {
            self.increment_thunks_forced();
            let value = self.eval_thunk_body(id, span, thunk)?;
            let value = self.finish_forced_value(id, span, source_thunk, guard, value)?;
            return Ok(value);
        }
        let cache_subject =
            self.force_cache_subject_for_thunk(EvalNodeRef::new(self.current_module, id), thunk);
        let memoization_decision = cache_subject
            .as_ref()
            .map(|subject| self.record_force_cache_memoization_demand(subject))
            .unwrap_or(MemoizationDecision::Admit);
        let memoization_admitted = memoization_decision == MemoizationDecision::Admit;
        if memoization_admitted
            && let Some(value) = self.lookup_forced_inline_expression_result(cache_subject.clone())
        {
            let value = self.finish_forced_value(id, span, source_thunk, guard, value)?;
            return Ok(value);
        }

        let thunks_forced_before = self.stats.thunks_forced;
        self.increment_thunks_forced();
        let impure_trace_cursor = memoization_admitted.then(|| self.impure_input_trace_cursor());
        let active_force_cache_node = memoization_admitted
            .then(|| self.active_force_cache_node_for_subject(cache_subject.as_ref()))
            .flatten();
        if let Some(node) = active_force_cache_node {
            self.active_memo_read_nodes
                .push(ActiveMemoReadNode::new(node));
        }
        let result = self.eval_thunk_body(id, span, thunk);
        let active_force_cache_node = if active_force_cache_node.is_some() {
            let popped = self.active_memo_read_nodes.pop();
            debug_assert_eq!(
                popped.as_ref().map(ActiveMemoReadNode::node),
                active_force_cache_node
            );
            popped
        } else {
            None
        };
        let value = result?;
        let impure_trace =
            impure_trace_cursor.map(|cursor| self.force_cache_impure_input_trace_segment(cursor));
        let value = self.finish_forced_value(id, span, source_thunk, guard, value)?;
        if let Some(active_force_cache_node) = active_force_cache_node {
            let dependency = active_force_cache_node.node();
            self.replace_active_memo_reads(active_force_cache_node);
            self.record_enclosing_memo_read(dependency);
        }
        if let Some(subject) = &cache_subject {
            self.record_forced_expression_demand(subject);
        }
        if let Some(impure_trace) = impure_trace {
            let scale_eval_work_by_payload = !impure_trace.trace.is_empty();
            let eval_work_units = self
                .stats
                .thunks_forced
                .saturating_sub(thunks_forced_before);
            self.observe_forced_inline_expression_result_with_eval_work_units(
                cache_subject,
                value,
                impure_trace,
                Some(eval_work_units),
                scale_eval_work_by_payload,
            );
        }
        Ok(value)
    }

    pub(in crate::eval::tree_walk) fn eval_thunk_body(
        &mut self,
        id: IrId,
        span: Span,
        thunk: &EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        self.note_direct_island_force();
        #[cfg(feature = "maximal_laziness_probe")]
        let maximal_laziness_token = self.begin_maximal_laziness_force(thunk);
        // Prelude-force-share accounting (RFC-0007 task #13): a no-op unless
        // `AOS_NIX_EVAL_STATS` is set, in which case it counts and inclusively
        // times prelude (`lib`/`stdenv`) body evaluations against all bodies.
        let force_accounting = self.begin_force_accounting(thunk);
        let result = self.eval_thunk_body_inner(id, span, thunk);
        if let Some(force_accounting) = force_accounting {
            let outcome = match &result {
                Ok(value) if value.is_thunk() => {
                    super::super::force_shape_census::ForceOutcomeClass::Thunk
                }
                Ok(_) => super::super::force_shape_census::ForceOutcomeClass::Whnf,
                Err(_) => super::super::force_shape_census::ForceOutcomeClass::Error,
            };
            self.end_force_accounting(Some(force_accounting), outcome);
        }
        #[cfg(feature = "maximal_laziness_probe")]
        self.finish_maximal_laziness_force(maximal_laziness_token, result.is_ok());
        result
    }

    fn eval_thunk_body_inner(
        &mut self,
        id: IrId,
        span: Span,
        thunk: &EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        match thunk.kind() {
            EvalThunkKind::Node { body, env } => {
                let (with_env, scoped_globals) = match thunk.dynamic_env() {
                    Some(dynamic) => (&dynamic.with_env, &dynamic.scoped_globals),
                    None => (EvalWithEnv::empty_ref(), EvalScopedGlobalEnv::empty_ref()),
                };
                let thunk_env = self.clone_env_frames(id, env, span)?;
                self.reserve_suspended_env_root_frame(id, span)?;
                self.push_env_scope(id, span, thunk_env, with_env, scoped_globals)?;
                self.enter_promise_region_thunk_entry(thunk);
                let direct_island = self.begin_direct_island_node(*body);
                let result = self.with_current_module(body.module(), |eval| {
                    eval.with_nonmoving_native_continuation(
                        super::super::native_continuation_shadow::NativeContinuationKind::NodeThunkBody,
                        body.id(),
                        &[],
                        Some(
                            super::super::native_continuation_shadow::NativeContinuationEdge::EvalNode,
                        ),
                        |eval| eval.eval_node(body.id()),
                    )
                });
                self.end_direct_island_node(direct_island);
                self.leave_promise_region_entry();
                self.pop_env_scope();
                result
            }
            EvalThunkKind::Apply {
                function,
                function_span,
                function_value,
                argument,
                argument_value,
            } => self.with_current_module(function.module(), |eval| {
                eval.apply_lambda_value(
                    id,
                    span,
                    function.id(),
                    *function_value,
                    *function_span,
                    argument.id(),
                    *argument_value,
                )
            }),
            EvalThunkKind::GenListElemAtAddOne {
                function,
                function_span,
                function_value,
                argument,
                argument_value,
            } => {
                if let Some(result) = self.try_force_genlist_elem_at_add_one(
                    id,
                    span,
                    *function_value,
                    *argument_value,
                ) {
                    return result;
                }
                self.with_current_module(function.module(), |eval| {
                    eval.apply_lambda_value(
                        id,
                        span,
                        function.id(),
                        *function_value,
                        *function_span,
                        argument.id(),
                        *argument_value,
                    )
                })
            }
            EvalThunkKind::Apply2(apply) => {
                self.with_current_module(apply.function.module(), |eval| {
                    eval.apply_lambda_value_2(
                        id,
                        span,
                        apply.function.id(),
                        apply.function_value,
                        apply.function_span,
                        apply.first_argument.id(),
                        apply.first_argument_span,
                        apply.first_argument_value,
                        apply.second_argument.id(),
                        apply.second_argument_span,
                        apply.second_argument_value,
                    )
                })
            }
            EvalThunkKind::Select {
                select,
                receiver,
                path,
            } => self.with_current_module(select.module(), |eval| {
                let node = *eval.node(select.id())?;
                let span = node.span;
                let IrData::Select { site, .. } = node.data else {
                    return Err(eval.invalid_payload(select.id(), &node, "select payload"));
                };
                // Lowering builds select thunks from the same select node whose
                // site id owns the payload path. Preserve that site so forced
                // select thunks share the active static-segment flat IC.
                let value = eval.eval_select_from_value(
                    select.id(),
                    span,
                    *receiver,
                    *path,
                    Some(site),
                    None,
                    true,
                )?;
                eval.force_node_result(select.id(), span, value)
            }),
            EvalThunkKind::BuiltinAttr { symbol, builtin } => {
                Builtin::from_kind(*builtin).select(self, id, span, *symbol)
            }
            // A shed thunk is already `Forced`, so every force re-entry
            // short-circuits on its cached result before reaching the body.
            // Evaluating a released body means a caller bypassed the force
            // protocol after capture shedding: fail loudly.
            EvalThunkKind::Released => Err(TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id,
                    source: EvalHeapError::ReleasedThunkWork { address: 0 },
                },
                span,
            )),
        }
    }

    pub(in crate::eval::tree_walk) fn finish_forced_value(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        guard: ForceGuard<'_>,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "collection_poll_probe")]
        let token = self.begin_speed_opportunity_phase(
            super::super::whole_demand_corridor_census::SpeedOpportunityPhase::Update,
        );
        let result = self.finish_forced_value_inner(id, span, source_thunk, guard, value);
        #[cfg(feature = "collection_poll_probe")]
        self.finish_speed_opportunity_phase(token, &result);
        result
    }

    fn finish_forced_value_inner(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
        guard: ForceGuard<'_>,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let released_work_shape = self.options.eval_stats_dump().then(|| {
            self.heap
                .get_thunk(source_thunk)
                .map_or("unknown", |thunk| self.force_shape_class(thunk))
        });
        #[cfg(feature = "collection_poll_probe")]
        let portal_shape = self
            .heap
            .get_thunk(source_thunk)
            .map_or("unknown", |thunk| self.force_shape_class(thunk));
        let tier = self.options.thunk_resolve_barrier_tier();
        if tier == GenerationalGcTier::OneShotArena {
            // Default tier: the one-shot arena barrier is `DisabledThunkResolveBarrier`,
            // whose `before_publish_forced` is a no-op. `ForceGuard::finish` publishes
            // with exactly that barrier, so take it directly and skip the vtable
            // lookup, function-pointer call, and `RuntimeThunkResolveBarrier` enum
            // construction on the hottest evaluator event.
            let value = guard.finish(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span)
            })?;
            if let Some(shape) = released_work_shape {
                super::super::force_shape_census::record_work_release(shape);
            }
            if self.gc_mode.is_enabled() {
                self.shed_forced_thunk_captures(id, span, source_thunk)?;
            }
            #[cfg(feature = "collection_poll_probe")]
            self.suspend_final_force_after_published_thunk(id, span, portal_shape)?;
            return Ok(value);
        }
        let mut barrier = runtime_thunk_resolve_write_barrier_with_card_table(
            tier,
            &self.heap,
            source_thunk,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
        )
        .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let value = guard
            .finish_with_barrier(value, &mut barrier)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        if let Some(shape) = released_work_shape {
            super::super::force_shape_census::record_work_release(shape);
        }
        if self.gc_mode.is_enabled() {
            self.shed_forced_thunk_captures(id, span, source_thunk)?;
        }
        #[cfg(feature = "collection_poll_probe")]
        self.suspend_final_force_after_published_thunk(id, span, portal_shape)?;
        Ok(value)
    }

    /// Sheds the just-published thunk's captures under `AOS_NIX_GC=sweep`.
    ///
    /// Runs strictly after the WHNF result is published, so the captured
    /// closure graph is provably dead for evaluation (every later force
    /// short-circuits on the cached result). This is the tree-walk analogue of
    /// GHC/C++ Nix's destructive thunk update; it preserves handle identity
    /// (the record keeps its address and forced result) and is therefore
    /// observationally invisible.
    fn shed_forced_thunk_captures(
        &mut self,
        id: IrId,
        span: Span,
        source_thunk: Value,
    ) -> Result<(), TreeWalkError> {
        self.heap
            .shed_forced_thunk_captures(source_thunk)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        Ok(())
    }
}
