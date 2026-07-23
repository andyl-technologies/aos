//! The thunk force protocol: serial, single-entry, and parallel-cell paths.
//!
//! Owns [`TreeWalk::force_value`] and everything under it — the parallel
//! payload-cell claim/replay branches, the serial claimed-thunk body run
//! (with tier-1 dispatch), memoized force-cache consultation, and the
//! finish/shed steps that publish a forced result.

use std::ptr::NonNull;

use crate::value::HeapObject;

use super::*;

impl TreeWalk {
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
    pub(crate) fn force_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = match classify_whnf_tag_fast_path(value) {
            WhnfTagFastPath::AlreadyWhnf(value) => return Ok(value),
            WhnfTagFastPath::RequiresThunkProtocol(value) => value,
        };
        // Decode the thunk handle once. The re-force cache peek and the share
        // below both resolve this same value; decoding twice re-walks the
        // carrier word and the reservation-base registry for no gain (RFC-0007
        // instruction-tax lever 2).
        let ptr = self
            .heap
            .thunk_ptr(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        if let Some(forced) = self.reforce_already_forced_thunk(id, span, value, ptr)? {
            return Ok(forced);
        }
        // The default serial one-shot heap never moves, retires, sheds, or
        // replaces a live thunk payload. Keep that payload in place while its
        // body re-enters evaluation instead of moving it into an `Arc` solely
        // to escape the heap borrow. GC and tier-1 execution retain the shared
        // handle path below because they may replace a payload or invoke a
        // heap-mutating engine hook while the force is active.
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
                return self.force_serial_thunk_value(id, span, value, thunk);
            }
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
        let cached = thunk
            .cell()
            .cached_value()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        // The immutable-borrow of `thunk` ends here so the `&mut self` replay and
        // counter calls below can run.
        let Some(cached) = cached else {
            return Ok(None);
        };
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
        match thunk
            .cell()
            .begin_force()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?
        {
            ForceClaim::AlreadyForced(value) => {
                self.unmark_relocated_lazy_identity_thunk(source_thunk);
                self.increment_thunk_cache_hits();
                Ok(value)
            }
            ForceClaim::Claimed(guard) => {
                self.push_active_force_root(id, span, source_thunk)?;
                #[cfg(test)]
                self.capture_validation_arm_force(source_thunk, thunk.kind());
                let result =
                    self.force_claimed_thunk_with_tier1(id, span, source_thunk, thunk, guard);
                let relocated_source_thunk = self.pop_active_force_root();
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
        let result = (|| -> Result<Value, TreeWalkError> {
            self.increment_thunks_forced();
            self.increment_single_entry_thunks_forced();
            self.eval_thunk_body(id, span, thunk)
        })();
        let source_thunk = self.pop_active_force_root();
        let value = result?;
        self.unmark_relocated_lazy_identity_thunk(source_thunk);
        Ok(value)
    }

    fn unmark_relocated_lazy_identity_thunk(&mut self, value: Value) {
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
        // Prelude-force-share accounting (RFC-0007 task #13): a no-op unless
        // `AOS_NIX_EVAL_STATS` is set, in which case it counts and inclusively
        // times prelude (`lib`/`stdenv`) body evaluations against all bodies.
        let force_accounting = self.begin_force_accounting(thunk);
        let result = self.eval_thunk_body_inner(id, span, thunk);
        self.end_force_accounting(force_accounting);
        result
    }

    fn eval_thunk_body_inner(
        &mut self,
        id: IrId,
        span: Span,
        thunk: &EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        match thunk.kind() {
            EvalThunkKind::Node {
                body,
                env,
                with_env,
                scoped_globals,
            } => {
                let thunk_env = self.clone_env_frames(id, env, span)?;
                self.reserve_suspended_env_root_frame(id, span)?;
                self.push_env_scope(id, span, thunk_env, with_env, scoped_globals)?;
                let result =
                    self.with_current_module(body.module(), |eval| eval.eval_node(body.id()));
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
            EvalThunkKind::Apply2 {
                function,
                function_span,
                function_value,
                first_argument,
                first_argument_span,
                first_argument_value,
                second_argument,
                second_argument_span,
                second_argument_value,
            } => self.with_current_module(function.module(), |eval| {
                eval.apply_lambda_value_2(
                    id,
                    span,
                    function.id(),
                    *function_value,
                    *function_span,
                    first_argument.id(),
                    *first_argument_span,
                    *first_argument_value,
                    second_argument.id(),
                    *second_argument_span,
                    *second_argument_value,
                )
            }),
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
                (*builtin).select(self, id, span, *symbol)
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
            if self.gc_mode.is_enabled() {
                self.shed_forced_thunk_captures(id, span, source_thunk)?;
            }
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
        if self.gc_mode.is_enabled() {
            self.shed_forced_thunk_captures(id, span, source_thunk)?;
        }
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
