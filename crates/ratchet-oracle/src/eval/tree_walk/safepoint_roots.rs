//! Safepoint root-set construction for the tree-walk evaluator.
//!
//! Allocation safepoints need a precise set of live heap values before a moving
//! collector can run. This module exposes the tree-walk evaluator state that is
//! already explicit in Rust data structures: active lexical frames, dynamic
//! `with` scopes, scoped-import globals, active force continuations,
//! first-class primop arguments, and permanent hash-cons roots.

use thiserror::Error;

use super::*;

/// A tree-walk safepoint root-set construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkSafepointRootError {
    /// Active environment state could not be snapshotted.
    #[error("failed to snapshot tree-walk environment roots: {0}")]
    Environment(#[from] EvalEnvError),
    /// Root-set storage could not be extended.
    #[error("failed to build tree-walk safepoint root set: {0}")]
    RootSet(#[from] super::super::heap::EvalRootSetError),
    /// Active primop root bookkeeping was internally inconsistent.
    #[error("active primop root frame [{start}, {start} + {len}) exceeds {roots} registered roots")]
    ActivePrimopRootFrameOutOfBounds {
        /// The recorded start offset in the active primop root stack.
        start: usize,
        /// The recorded frame length.
        len: usize,
        /// The number of active primop roots currently registered.
        roots: usize,
    },
}

/// A tree-walk safepoint heap-scan failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkSafepointScanError {
    /// Root-set construction failed before the heap scan began.
    #[error("failed to build tree-walk safepoint roots: {0}")]
    Roots(#[from] TreeWalkSafepointRootError),
    /// The supplied allocation poll is no longer current for its allocator tier.
    #[error(
        "allocation collector poll {poll:?} is stale for its allocator tier; current poll is {current:?}"
    )]
    StaleCollectorPoll {
        /// The stale collector poll supplied by the caller.
        poll: AllocationCollectorPoll,
        /// The current collector poll for the same allocation tier, if any.
        current: Option<AllocationCollectorPoll>,
    },
    /// The precise heap scanner rejected the constructed root graph.
    #[error("failed to scan tree-walk safepoint roots: {0}")]
    Heap(#[from] EvalHeapError),
}

impl TreeWalk {
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
        let mut roots = EvalRootSet::new();

        for (frame_index, frame) in self.env.iter().enumerate() {
            let slots = frame.slot_values()?;
            for (slot_index, value) in slots.into_iter().enumerate() {
                roots.try_push_tree_walk_frame(frame_index, slot_index, value)?;
            }
        }

        for (depth, scope) in self.with_scopes.iter().enumerate() {
            roots.try_push_with_scope(depth, scope.value())?;
        }

        for (depth, value) in self.scoped_globals.iter().copied().enumerate() {
            roots.try_push_scoped_global(depth, value)?;
        }

        for (depth, suspended) in self.suspended_env_roots.iter().rev().enumerate() {
            for (frame_index, frame) in suspended.env.iter().enumerate() {
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
                .ok_or(super::super::heap::EvalRootSetError::LengthOverflow)?;
        }

        roots.try_extend(&self.heap.interned_root_set()?)?;
        Ok(roots)
    }

    /// Builds the explicit safepoint roots with caller-owned value-stack slots.
    ///
    /// Scannable heap values yielded by `value_stack` are recorded as
    /// [`EvalRootSource::ValueStack`](crate::eval::heap::EvalRootSource::ValueStack)
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
        let mut roots = self.safepoint_root_set()?;
        for (slot, value) in value_stack.into_iter().enumerate() {
            roots.try_push_value_stack(slot, value)?;
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
        self.validate_current_collector_poll(poll)?;
        let roots = self.safepoint_root_set_with_value_stack(value_stack)?;
        Ok(self.heap.scan_collector_poll_roots(poll, &roots)?)
    }

    pub(in crate::eval::tree_walk) fn gc_stress_boundary_scans(
        &self,
        value: Value,
    ) -> Result<EvalGcStressBoundaryScans, TreeWalkSafepointScanError> {
        let worker = match self.current_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot)
        {
            Some(poll) => Some(self.safepoint_collector_poll_scan(poll, [value])?),
            None => None,
        };
        let permanent_shared =
            match self.current_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared) {
                Some(poll) => Some(self.safepoint_collector_poll_scan(poll, [value])?),
                None => None,
            };
        Ok(EvalGcStressBoundaryScans::new(worker, permanent_shared))
    }

    fn validate_current_collector_poll(
        &self,
        poll: AllocationCollectorPoll,
    ) -> Result<(), TreeWalkSafepointScanError> {
        let current = self.current_collector_poll_for_tier(poll.tier());
        if current == Some(poll) {
            return Ok(());
        }
        Err(TreeWalkSafepointScanError::StaleCollectorPoll { poll, current })
    }

    fn current_collector_poll_for_tier(
        &self,
        tier: RuntimeAllocatorTier,
    ) -> Option<AllocationCollectorPoll> {
        match tier {
            RuntimeAllocatorTier::TierAOneShot => self
                .heap
                .allocation_safepoints()
                .last_safepoint_collector_poll(),
            RuntimeAllocatorTier::PermanentShared => self
                .heap
                .permanent_allocation_safepoints()
                .last_safepoint_collector_poll(),
        }
    }

    pub(in crate::eval::tree_walk) fn push_active_force_root(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let roots = self
            .active_force_roots
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.active_force_roots.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots },
                span,
            )
        })?;
        self.active_force_roots.push(value);
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn reserve_suspended_env_root_frame(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let roots = self
            .suspended_env_roots
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.suspended_env_roots.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots },
                span,
            )
        })?;
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn push_suspended_env_roots(
        &mut self,
        env: Vec<Rc<EvalFrame>>,
        with_scopes: Vec<EvalWithScope>,
        scoped_globals: Vec<Value>,
    ) {
        self.suspended_env_roots
            .push(SuspendedTreeWalkEnv::new(env, with_scopes, scoped_globals));
    }

    pub(in crate::eval::tree_walk) fn pop_suspended_env_roots(
        &mut self,
    ) -> Option<SuspendedTreeWalkEnv> {
        self.suspended_env_roots.pop()
    }

    pub(in crate::eval::tree_walk) fn pop_active_force_root(&mut self, value: Value) {
        let popped = self.active_force_roots.pop();
        debug_assert!(
            popped.is_some_and(|popped| popped.raw_eq(value)),
            "active force root stack is unbalanced"
        );
    }

    pub(in crate::eval::tree_walk) fn push_active_primop_arg_roots(
        &mut self,
        id: IrId,
        span: Span,
        args: &[EvalPrimOpArg],
    ) -> Result<(), TreeWalkError> {
        let arg_roots = self
            .active_primop_arg_roots
            .len()
            .checked_add(args.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        let frames = self
            .active_primop_arg_frames
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.active_primop_arg_roots
            .try_reserve_exact(args.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed {
                        id,
                        roots: arg_roots,
                    },
                    span,
                )
            })?;
        self.active_primop_arg_frames
            .try_reserve_exact(1)
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots: frames },
                    span,
                )
            })?;

        let start = self.active_primop_arg_roots.len();
        self.active_primop_arg_roots.extend_from_slice(args);
        self.active_primop_arg_frames.push(ActivePrimopArgFrame {
            start,
            len: args.len(),
        });
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn pop_active_primop_arg_roots(&mut self) {
        let Some(frame) = self.active_primop_arg_frames.pop() else {
            debug_assert!(false, "active primop root stack is unbalanced");
            return;
        };
        debug_assert_eq!(
            self.active_primop_arg_roots.len(),
            frame.start.saturating_add(frame.len),
            "active primop root frame length is unbalanced"
        );
        self.active_primop_arg_roots.truncate(frame.start);
    }
}
