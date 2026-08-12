//! Root-writeback slot enumeration and the typed read/validate/write paths.

use super::*;

impl TreeWalk {
    /// Validates and commits opaque raw-value rewrites to suspended mutator roots.
    ///
    /// Every current root word and every write target is validated before the
    /// first mutation. The transient value stack is temporarily moved out only
    /// to satisfy Rust's exclusive-borrow rules and is restored on every exit.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkDirectRootRewriteError`] when observation storage
    /// cannot be reserved, a root is stale or unavailable, target validation
    /// fails, or the direct plan does not exactly cover its observations.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    pub(in crate::eval) fn apply_direct_root_rewrite_plan(
        &mut self,
        plan: &DirectRootRewritePlan,
    ) -> Result<usize, TreeWalkDirectRootRewriteError> {
        let mut value_stack = std::mem::take(&mut self.transient_value_stack_roots);
        let result = self.apply_direct_root_rewrite_plan_with_stack(plan, &mut value_stack);
        self.transient_value_stack_roots = value_stack;
        result
    }

    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    fn apply_direct_root_rewrite_plan_with_stack(
        &mut self,
        plan: &DirectRootRewritePlan,
        value_stack: &mut [Value],
    ) -> Result<usize, TreeWalkDirectRootRewriteError> {
        let mut observations = Vec::new();
        observations.try_reserve_exact(plan.len()).map_err(|_| {
            TreeWalkDirectRootRewriteError::AllocationFailed {
                entries: plan.len(),
            }
        })?;
        let primop_arguments: [Value; 0] = [];
        for rewrite in plan.rewrites() {
            let source = rewrite.source();
            let value =
                self.read_safepoint_root_writeback_value(source, value_stack, &primop_arguments)?;
            self.validate_safepoint_root_writeback_target(source, value_stack, &primop_arguments)?;
            observations.push(DirectRootObservation::new(source.clone(), value));
        }
        plan.validate_observations(&observations)?;

        let mut primop_arguments: [Value; 0] = [];
        for rewrite in plan.rewrites() {
            self.write_safepoint_root_writeback_value(
                rewrite.source(),
                rewrite.replacement(),
                value_stack,
                &mut primop_arguments,
            )?;
        }
        Ok(plan.len())
    }

    /// Verifies that every enumerated collection-poll root has one writable slot.
    ///
    /// The check reads each source back from evaluator-owned storage, compares
    /// it with the root snapshot, validates the corresponding write target, and
    /// rejects duplicate source labels. It performs no writes.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] when a source is
    /// duplicated, unsupported, unavailable, changed after enumeration, or
    /// cannot be validated as writable.
    #[cfg(feature = "collection_poll_probe")]
    pub(in crate::eval::tree_walk) fn validate_collection_poll_root_bijection(
        &self,
        roots: &EvalRootSet,
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        for (index, root) in roots.roots().iter().enumerate() {
            if roots.roots()[..index]
                .iter()
                .any(|prior| prior.source() == root.source())
            {
                return Err(TreeWalkSafepointRootWritebackError::DuplicateSource {
                    root_source: root.source().clone(),
                });
            }
            let current = self.read_safepoint_root_writeback_value(
                root.source(),
                &self.transient_value_stack_roots,
                &[],
            )?;
            if !current.raw_eq(root.value()) {
                return Err(TreeWalkSafepointRootWritebackError::SnapshotMismatch {
                    root_source: root.source().clone(),
                });
            }
            self.validate_safepoint_root_writeback_target(
                root.source(),
                &self.transient_value_stack_roots,
                &[],
            )?;
        }
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn safepoint_root_value_writeback_slots(
        &self,
        plan: &AllocationCollectorPollRootWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        Vec<AllocationCollectorPollRootValueWritebackSlot>,
        TreeWalkSafepointRootWritebackError,
    > {
        let writebacks = plan.writebacks();
        let mut slots = Vec::new();
        slots.try_reserve_exact(writebacks.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: TREE_WALK_SAFEPOINT_ROOT_WRITEBACK_SLOTS_TABLE,
                entries: writebacks.len(),
            }
        })?;

        for writeback in writebacks {
            let source = writeback.source().clone();
            let value =
                self.read_safepoint_root_writeback_value(&source, value_stack, primop_arguments)?;
            slots.push(AllocationCollectorPollRootValueWritebackSlot::new(
                source, value,
            ));
        }

        Ok(slots)
    }

    pub(in crate::eval::tree_walk) fn validate_safepoint_root_writeback_targets(
        &self,
        slots: &[AllocationCollectorPollRootValueWritebackSlot],
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        for slot in slots {
            self.validate_safepoint_root_writeback_target(
                slot.source(),
                value_stack,
                primop_arguments,
            )?;
        }
        Ok(())
    }

    pub(super) fn validate_safepoint_reference_writeback_source_gc_state(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        validate_safepoint_source_remembered_set(
            plan.source_remembered_set(),
            &self.thunk_resolve_remembered_set,
        )?;
        validate_safepoint_source_card_table(
            plan.source_card_table(),
            &self.thunk_resolve_card_table,
        )
    }

    fn read_safepoint_root_writeback_value(
        &self,
        source: &EvalRootSource,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<Value, TreeWalkSafepointRootWritebackError> {
        match source {
            EvalRootSource::ValueStack { slot } => value_stack
                .get(*slot)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::PrimopArgument { index } => primop_arguments
                .get(*index)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::TreeWalkFrame { frame, slot } => self
                .env
                .get(*frame)
                .ok_or_else(|| root_writeback_source_unavailable(source))?
                .get(root_writeback_frame_slot(source, *slot)?)
                .map_err(TreeWalkSafepointRootWritebackError::Environment),
            EvalRootSource::TreeWalkFlatCapture { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::TreeWalkFlatCaptureOwner => self
                .flat_env
                .as_ref()
                .ok_or_else(|| root_writeback_source_unavailable(source))
                .and_then(|flat| {
                    self.heap
                        .flat_closure_capture_owner(flat.tail_handle())
                        .map_err(TreeWalkSafepointRootWritebackError::Heap)
                }),
            EvalRootSource::SuspendedTreeWalkFrame { depth, frame, slot } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .env
                    .frames
                    .get(*frame)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?
                    .get(root_writeback_frame_slot(source, *slot)?)
                    .map_err(TreeWalkSafepointRootWritebackError::Environment)
            }
            EvalRootSource::SuspendedTreeWalkFlatCapture { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::SuspendedTreeWalkFlatCaptureOwner { depth } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .env
                    .flat_base
                    .as_ref()
                    .ok_or_else(|| root_writeback_source_unavailable(source))
                    .and_then(|flat| {
                        self.heap
                            .flat_closure_capture_owner(flat.tail_handle())
                            .map_err(TreeWalkSafepointRootWritebackError::Heap)
                    })
            }
            EvalRootSource::WithScope { depth } => self
                .with_scopes
                .get(*depth)
                .map(EvalWithScope::value)
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::SuspendedWithScope { depth, scope_depth } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .with_scopes
                    .get(*scope_depth)
                    .map(EvalWithScope::value)
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ScopedGlobal { depth } => self
                .scoped_globals
                .get(*depth)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::SuspendedScopedGlobal { depth, scope_depth } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .scoped_globals
                    .get(*scope_depth)
                    .copied()
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ForceContinuation { depth } => self
                .active_force_roots
                .get(reverse_root_index(
                    self.active_force_roots.len(),
                    *depth,
                    source,
                )?)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::StgValue { depth } => self
                .stg_apply_runtime
                .value_stack
                .get(reverse_root_index(
                    self.stg_apply_runtime.value_stack.len(),
                    *depth,
                    source,
                )?)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::StgArgument { depth } => self
                .stg_apply_runtime
                .argument_stack
                .get(reverse_root_index(
                    self.stg_apply_runtime.argument_stack.len(),
                    *depth,
                    source,
                )?)
                .map(EvalPrimOpArg::value)
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            #[cfg(feature = "collection_poll_probe")]
            EvalRootSource::DetachedNodeThunkWork { depth, edge } => self
                .active_node_work_root_value(*depth, *edge)
                .map_err(TreeWalkSafepointRootWritebackError::Heap)?
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            #[cfg(not(feature = "collection_poll_probe"))]
            EvalRootSource::DetachedNodeThunkWork { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::DetachedTypedThunkWork { .. }
            | EvalRootSource::DetachedTypedThunkHead { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::TreeWalkPrimopArgument { call_depth, index } => {
                let root_index = active_primop_arg_root_index(self, *call_depth, *index, source)?;
                self.active_primop_arg_roots
                    .get(root_index)
                    .map(EvalPrimOpArg::value)
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ImportCache { index } => {
                read_import_cache_root(&self.import_cache, *index, source)
            }
            EvalRootSource::Interned { .. } | EvalRootSource::StackMap { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
        }
    }

    fn validate_safepoint_root_writeback_target(
        &self,
        source: &EvalRootSource,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        match source {
            EvalRootSource::ValueStack { slot } => value_stack
                .get(*slot)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::PrimopArgument { index } => primop_arguments
                .get(*index)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::TreeWalkFrame { frame, slot } => self
                .env
                .get(*frame)
                .ok_or_else(|| root_writeback_source_unavailable(source))?
                .validate_set(root_writeback_frame_slot(source, *slot)?)
                .map_err(TreeWalkSafepointRootWritebackError::Environment),
            EvalRootSource::TreeWalkFlatCapture { .. }
            | EvalRootSource::TreeWalkFlatCaptureOwner
            | EvalRootSource::SuspendedTreeWalkFlatCapture { .. }
            | EvalRootSource::SuspendedTreeWalkFlatCaptureOwner { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::SuspendedTreeWalkFrame { depth, frame, slot } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .env
                    .frames
                    .get(*frame)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?
                    .validate_set(root_writeback_frame_slot(source, *slot)?)
                    .map_err(TreeWalkSafepointRootWritebackError::Environment)
            }
            EvalRootSource::WithScope { depth } => self
                .with_scopes
                .get(*depth)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::SuspendedWithScope { depth, scope_depth } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .with_scopes
                    .get(*scope_depth)
                    .map(|_| ())
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ScopedGlobal { depth } => self
                .scoped_globals
                .get(*depth)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::SuspendedScopedGlobal { depth, scope_depth } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .scoped_globals
                    .get(*scope_depth)
                    .map(|_| ())
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ForceContinuation { depth } => self
                .active_force_roots
                .get(reverse_root_index(
                    self.active_force_roots.len(),
                    *depth,
                    source,
                )?)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::StgValue { depth } => self
                .stg_apply_runtime
                .value_stack
                .get(reverse_root_index(
                    self.stg_apply_runtime.value_stack.len(),
                    *depth,
                    source,
                )?)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::StgArgument { depth } => self
                .stg_apply_runtime
                .argument_stack
                .get(reverse_root_index(
                    self.stg_apply_runtime.argument_stack.len(),
                    *depth,
                    source,
                )?)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            #[cfg(feature = "collection_poll_probe")]
            EvalRootSource::DetachedNodeThunkWork { depth, edge } => self
                .active_node_work_root_value(*depth, *edge)
                .map_err(TreeWalkSafepointRootWritebackError::Heap)?
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            #[cfg(not(feature = "collection_poll_probe"))]
            EvalRootSource::DetachedNodeThunkWork { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::DetachedTypedThunkWork { .. }
            | EvalRootSource::DetachedTypedThunkHead { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::TreeWalkPrimopArgument { call_depth, index } => {
                let root_index = active_primop_arg_root_index(self, *call_depth, *index, source)?;
                self.active_primop_arg_roots
                    .get(root_index)
                    .map(|_| ())
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ImportCache { index } => {
                read_import_cache_root(&self.import_cache, *index, source).map(|_| ())
            }
            EvalRootSource::Interned { .. } | EvalRootSource::StackMap { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
        }
    }

    pub(in crate::eval::tree_walk) fn write_safepoint_root_writeback_value(
        &mut self,
        source: &EvalRootSource,
        value: Value,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        match source {
            EvalRootSource::ValueStack { slot } => {
                let target = value_stack
                    .get_mut(*slot)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::PrimopArgument { index } => {
                let target = primop_arguments
                    .get_mut(*index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::TreeWalkFrame { frame, slot } => self
                .env
                .get(*frame)
                .ok_or_else(|| root_writeback_source_unavailable(source))?
                .set(root_writeback_frame_slot(source, *slot)?, value)
                .map_err(TreeWalkSafepointRootWritebackError::Environment),
            EvalRootSource::TreeWalkFlatCapture { .. }
            | EvalRootSource::TreeWalkFlatCaptureOwner
            | EvalRootSource::SuspendedTreeWalkFlatCapture { .. }
            | EvalRootSource::SuspendedTreeWalkFlatCaptureOwner { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::SuspendedTreeWalkFrame { depth, frame, slot } => {
                let suspended_index =
                    suspended_root_index(self.suspended_env_roots.len(), *depth, source)?;
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .env
                    .frames
                    .get(*frame)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?
                    .set(root_writeback_frame_slot(source, *slot)?, value)
                    .map_err(TreeWalkSafepointRootWritebackError::Environment)
            }
            EvalRootSource::WithScope { depth } => self
                .with_scopes
                .replace_value(*depth, value)
                .then_some(())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::SuspendedWithScope { depth, scope_depth } => {
                let suspended_index =
                    suspended_root_index(self.suspended_env_roots.len(), *depth, source)?;
                self.suspended_env_roots
                    .get_mut(suspended_index)
                    .is_some_and(|suspended| {
                        suspended.with_scopes.replace_value(*scope_depth, value)
                    })
                    .then_some(())
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ScopedGlobal { depth } => self
                .scoped_globals
                .replace_value(*depth, value)
                .then_some(())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::SuspendedScopedGlobal { depth, scope_depth } => {
                let suspended_index =
                    suspended_root_index(self.suspended_env_roots.len(), *depth, source)?;
                self.suspended_env_roots
                    .get_mut(suspended_index)
                    .is_some_and(|suspended| {
                        suspended.scoped_globals.replace_value(*scope_depth, value)
                    })
                    .then_some(())
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ForceContinuation { depth } => {
                let root_index = reverse_root_index(self.active_force_roots.len(), *depth, source)?;
                let target = self
                    .active_force_roots
                    .get_mut(root_index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::StgValue { depth } => {
                let root_index =
                    reverse_root_index(self.stg_apply_runtime.value_stack.len(), *depth, source)?;
                let target = self
                    .stg_apply_runtime
                    .value_stack
                    .get_mut(root_index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::StgArgument { depth } => {
                let root_index = reverse_root_index(
                    self.stg_apply_runtime.argument_stack.len(),
                    *depth,
                    source,
                )?;
                let argument = self
                    .stg_apply_runtime
                    .argument_stack
                    .get_mut(root_index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *argument = EvalPrimOpArg::new_in_module(
                    argument.module(),
                    argument.id(),
                    argument.span(),
                    value,
                );
                Ok(())
            }
            #[cfg(feature = "collection_poll_probe")]
            EvalRootSource::DetachedNodeThunkWork { depth, edge } => self
                .rewrite_active_node_work_root(*depth, *edge, value)
                .map_err(TreeWalkSafepointRootWritebackError::Heap)?
                .then_some(())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            #[cfg(not(feature = "collection_poll_probe"))]
            EvalRootSource::DetachedNodeThunkWork { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::DetachedTypedThunkWork { .. }
            | EvalRootSource::DetachedTypedThunkHead { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
            EvalRootSource::TreeWalkPrimopArgument { call_depth, index } => {
                let root_index = active_primop_arg_root_index(self, *call_depth, *index, source)?;
                let arg = self
                    .active_primop_arg_roots
                    .get_mut(root_index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *arg = EvalPrimOpArg::new_in_module(arg.module(), arg.id(), arg.span(), value);
                Ok(())
            }
            EvalRootSource::ImportCache { index } => {
                write_import_cache_root(&mut self.import_cache, *index, value, source)
            }
            EvalRootSource::Interned { .. } | EvalRootSource::StackMap { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
        }
    }
}

/// Applying one packed raw-root rewrite transaction failed.
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[derive(Debug, Error)]
pub(in crate::eval) enum TreeWalkDirectRootRewriteError {
    /// Scratch observations could not reserve exact storage.
    #[error("direct root rewrite could not reserve {entries} observations")]
    AllocationFailed {
        /// Exact observation count.
        entries: usize,
    },
    /// Reading, validating, or writing a concrete evaluator root failed.
    #[error("direct root rewrite storage access failed: {0}")]
    Root(#[from] TreeWalkSafepointRootWritebackError),
    /// The raw-value plan was stale, duplicated, or incompletely observed.
    #[error("direct root rewrite validation failed: {0}")]
    Plan(#[from] DirectRootRewriteError),
}
