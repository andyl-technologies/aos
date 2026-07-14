//! Transient value-stack roots and safepoint root-set/heap-scan construction.

use super::*;

impl TreeWalk {
    /// Runs `body` with caller-owned values published to allocation safepoints.
    ///
    /// The supplied slots are appended to the tree-walk transient value stack
    /// before `body` runs. GC-stress allocation safepoints scan that stack as
    /// [`EvalRootSource::ValueStack`] storage and write relocated values back
    /// into it. This helper copies the final stored values back to `roots` and
    /// restores the previous stack depth whether `body` succeeds or returns an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if transient-root storage cannot be reserved or
    /// if `body` returns an error.
    ///
    /// # Panics
    ///
    /// Panics if `body` panics. The transient root stack is restored before the
    /// panic resumes.
    pub fn with_transient_value_stack_roots<T>(
        &mut self,
        id: IrId,
        span: Span,
        roots: &mut [Value],
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        self.with_indexed_transient_value_stack_roots(id, span, roots, |eval, _| body(eval))
    }

    /// Runs `body` with access to the active transient-root stack slots.
    ///
    /// The passed range indexes into `self` while `body` runs, allowing callers
    /// that recurse across allocation safepoints to read roots after writeback.
    pub(in crate::eval::tree_walk) fn with_indexed_transient_value_stack_roots<T>(
        &mut self,
        id: IrId,
        span: Span,
        roots: &mut [Value],
        body: impl FnOnce(&mut Self, Range<usize>) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let start = self.transient_value_stack_roots.len();
        let end = start.checked_add(roots.len()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: roots.len(),
                },
                span,
            )
        })?;
        self.transient_value_stack_roots
            .try_reserve_exact(roots.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed { id, len: end },
                    span,
                )
            })?;
        self.transient_value_stack_roots.extend_from_slice(roots);

        let result = match catch_unwind(AssertUnwindSafe(|| body(self, start..end))) {
            Ok(result) => result,
            Err(payload) => {
                self.transient_value_stack_roots.truncate(start);
                resume_unwind(payload);
            }
        };
        if let Some(updated_roots) = self.transient_value_stack_roots.get(start..end) {
            for (root, updated) in roots.iter_mut().zip(updated_roots.iter().copied()) {
                *root = updated;
            }
        }
        self.transient_value_stack_roots.truncate(start);
        result
    }

    /// Returns the current value stored in one transient-root stack slot.
    pub(in crate::eval::tree_walk) fn current_transient_value_stack_root(
        &self,
        slot: usize,
    ) -> Option<Value> {
        self.transient_value_stack_roots.get(slot).copied()
    }

    /// Replaces the current value stored in one transient-root stack slot.
    pub(in crate::eval::tree_walk) fn set_current_transient_value_stack_root(
        &mut self,
        slot: usize,
        value: Value,
    ) -> bool {
        let Some(root) = self.transient_value_stack_roots.get_mut(slot) else {
            return false;
        };
        *root = value;
        true
    }

    /// Returns transient value-stack roots registered for allocation safepoints.
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn transient_value_stack_roots(&self) -> &[Value] {
        &self.transient_value_stack_roots
    }

    /// Builds the explicit heap roots live at the current tree-walk safepoint.
    ///
    /// The returned set includes active lexical frame slots, active `with`
    /// scopes, active scoped-import globals, active force continuations,
    /// first-class primop arguments, and permanent interned/hash-cons table
    /// entries. It deliberately does not infer roots from arbitrary Rust locals;
    /// evaluator code that keeps a heap value live across an allocation
    /// safepoint must register that value in one of these explicit structures.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootError`] if an active environment frame
    /// cannot be snapshotted, if a root-set length overflows, or if storage for
    /// another root cannot be reserved.
    pub fn safepoint_root_set(&self) -> Result<EvalRootSet, TreeWalkSafepointRootError> {
        let mut roots = self.mutator_root_set()?;
        roots.try_extend(&self.heap.interned_root_set()?)?;
        Ok(roots)
    }

    /// Builds the mutator-owned safepoint roots without the interned tables.
    ///
    /// This is [`Self::safepoint_root_set`] minus the permanent hash-cons
    /// entries. The Tier-B non-moving sweep uses it directly: permanent
    /// records are immortal and never traversed by the sweep's worker-only
    /// marking (their worker edges are seeded from the records themselves),
    /// so materializing and hash-sorting every interned entry as a root would
    /// be pure marking overhead.
    pub(in crate::eval::tree_walk) fn mutator_root_set(
        &self,
    ) -> Result<EvalRootSet, TreeWalkSafepointRootError> {
        let mut roots = EvalRootSet::new();

        for (frame_index, frame) in self.env.iter().enumerate() {
            let slots = frame.slot_values()?;
            for (slot_index, value) in slots.into_iter().enumerate() {
                roots.try_push_tree_walk_frame(frame_index, slot_index, value)?;
            }
        }
        if let Some(flat) = &self.flat_env {
            roots.try_push_tree_walk_flat_capture_owner(flat.inline_owner())?;
        }

        for (depth, scope) in self.with_scopes.iter().enumerate() {
            roots.try_push_with_scope(depth, scope.value())?;
        }

        for (depth, value) in self.scoped_globals.iter().copied().enumerate() {
            roots.try_push_scoped_global(depth, value)?;
        }

        for (depth, suspended) in self.suspended_env_roots.iter().rev().enumerate() {
            for (frame_index, frame) in suspended.env.frames.iter().enumerate() {
                let slots = frame.slot_values()?;
                for (slot_index, value) in slots.into_iter().enumerate() {
                    roots.try_push_suspended_tree_walk_frame(
                        depth,
                        frame_index,
                        slot_index,
                        value,
                    )?;
                }
            }
            if let Some(flat) = &suspended.env.flat_base {
                roots
                    .try_push_suspended_tree_walk_flat_capture_owner(depth, flat.inline_owner())?;
            }
            for (scope_depth, scope) in suspended.with_scopes.iter().enumerate() {
                roots.try_push_suspended_with_scope(depth, scope_depth, scope.value())?;
            }
            for (scope_depth, value) in suspended.scoped_globals.iter().copied().enumerate() {
                roots.try_push_suspended_scoped_global(depth, scope_depth, value)?;
            }
        }

        for (depth, value) in self.active_force_roots.iter().rev().copied().enumerate() {
            roots.try_push_force_continuation(depth, value)?;
        }

        for (call_depth, frame) in self.active_primop_arg_frames.iter().rev().enumerate() {
            let end = frame.start.checked_add(frame.len).ok_or(
                TreeWalkSafepointRootError::ActivePrimopRootFrameOutOfBounds {
                    start: frame.start,
                    len: frame.len,
                    roots: self.active_primop_arg_roots.len(),
                },
            )?;
            let args = self.active_primop_arg_roots.get(frame.start..end).ok_or(
                TreeWalkSafepointRootError::ActivePrimopRootFrameOutOfBounds {
                    start: frame.start,
                    len: frame.len,
                    roots: self.active_primop_arg_roots.len(),
                },
            )?;
            for (index, arg) in args.iter().enumerate() {
                roots.try_push_tree_walk_primop_argument(call_depth, index, arg.value())?;
            }
        }

        let mut import_index = 0usize;
        for entry in self.import_cache.values() {
            let ImportCacheEntry::Ready { value, .. } = entry else {
                continue;
            };
            roots.try_push_import_cache(import_index, *value)?;
            import_index = import_index
                .checked_add(1)
                .ok_or(crate::eval::heap::EvalRootSetError::LengthOverflow)?;
        }

        Ok(roots)
    }

    /// Builds the explicit safepoint roots with caller-owned value-stack slots.
    ///
    /// Scannable heap values yielded by `value_stack` are recorded as
    /// [`EvalRootSource::ValueStack`]
    /// roots in iteration order. Inline values are skipped as non-roots, but
    /// slot indexes still reflect the original iterator position. This gives
    /// allocation-safepoint callers an explicit place to publish transient Rust
    /// locals or allocation return values before a precise collector-poll scan,
    /// without relying on conservative stack discovery.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootError`] if the base tree-walk root set
    /// cannot be built or if recording an additional value-stack root fails.
    pub fn safepoint_root_set_with_value_stack(
        &self,
        value_stack: impl IntoIterator<Item = Value>,
    ) -> Result<EvalRootSet, TreeWalkSafepointRootError> {
        self.safepoint_root_set_with_value_stack_and_primop_arguments(value_stack, [])
    }

    /// Builds explicit safepoint roots with caller-owned value and primop slots.
    ///
    /// Scannable heap values yielded by `value_stack` are recorded as
    /// [`EvalRootSource::ValueStack`] roots. Scannable heap values yielded by
    /// `primop_arguments` are recorded as [`EvalRootSource::PrimopArgument`]
    /// roots. Inline values are skipped as non-roots, but slot indexes still
    /// reflect the original iterator position for both buffers.
    ///
    /// This gives allocation-safepoint callers explicit storage for transient
    /// Rust locals and spilled primop arguments without relying on conservative
    /// stack discovery.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootError`] if the base tree-walk root set
    /// cannot be built or if recording an additional caller-owned root fails.
    pub fn safepoint_root_set_with_value_stack_and_primop_arguments(
        &self,
        value_stack: impl IntoIterator<Item = Value>,
        primop_arguments: impl IntoIterator<Item = Value>,
    ) -> Result<EvalRootSet, TreeWalkSafepointRootError> {
        let mut roots = self.safepoint_root_set()?;
        for (slot, value) in value_stack.into_iter().enumerate() {
            roots.try_push_value_stack(slot, value)?;
        }
        for (index, value) in primop_arguments.into_iter().enumerate() {
            roots.try_push_primop_argument(index, value)?;
        }
        Ok(roots)
    }

    /// Scans the precise heap graph reachable at the current tree-walk
    /// safepoint.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointScanError`] if root construction fails or if
    /// the precise heap scanner rejects one of the constructed roots or edges.
    pub fn safepoint_heap_scan(&self) -> Result<PreciseHeapScan, TreeWalkSafepointScanError> {
        let roots = self.safepoint_root_set()?;
        Ok(self.heap.scan_precise_roots(&roots)?)
    }

    /// Scans the precise heap graph for a supplied allocation collector poll.
    ///
    /// The caller supplies the exact poll observed at the allocation safepoint
    /// and any transient value-stack roots that are live but not yet stored in
    /// the evaluator's explicit environment, force-continuation, primop, import,
    /// or intern tables. This method first rejects `poll` unless it is still
    /// the current collector poll for its allocator tier. It then validates and
    /// scans the same explicit roots used by [`Self::safepoint_heap_scan`],
    /// pairs the scan with `poll`, and does not invoke a collector or mutate
    /// heap state.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointScanError`] if `poll` is stale for its
    /// allocator tier, if root-set construction fails, or if the heap rejects
    /// the precise collector-poll scan.
    pub fn safepoint_collector_poll_scan(
        &self,
        poll: AllocationCollectorPoll,
        value_stack: impl IntoIterator<Item = Value>,
    ) -> Result<AllocationCollectorPollScan, TreeWalkSafepointScanError> {
        self.safepoint_collector_poll_scan_with_primop_arguments(poll, value_stack, [])
    }

    /// Scans the precise heap graph for a poll with spilled primop roots.
    ///
    /// The caller supplies the exact poll observed at the allocation safepoint,
    /// transient value-stack roots, and caller-owned primop argument roots that
    /// are live but not yet stored in evaluator-owned root storage.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointScanError`] if `poll` is stale for its
    /// allocator tier, if root-set construction fails, or if the heap rejects
    /// the precise collector-poll scan.
    pub fn safepoint_collector_poll_scan_with_primop_arguments(
        &self,
        poll: AllocationCollectorPoll,
        value_stack: impl IntoIterator<Item = Value>,
        primop_arguments: impl IntoIterator<Item = Value>,
    ) -> Result<AllocationCollectorPollScan, TreeWalkSafepointScanError> {
        self.validate_current_collector_poll(poll)?;
        self.safepoint_collector_poll_scan_with_primop_arguments_for_validated_poll(
            poll,
            value_stack,
            primop_arguments,
        )
    }

    pub(super) fn safepoint_collector_poll_scan_with_primop_arguments_for_validated_poll(
        &self,
        poll: AllocationCollectorPoll,
        value_stack: impl IntoIterator<Item = Value>,
        primop_arguments: impl IntoIterator<Item = Value>,
    ) -> Result<AllocationCollectorPollScan, TreeWalkSafepointScanError> {
        let roots = self.safepoint_root_set_with_value_stack_and_primop_arguments(
            value_stack,
            primop_arguments,
        )?;
        Ok(self.heap.scan_collector_poll_roots(poll, &roots)?)
    }
}
