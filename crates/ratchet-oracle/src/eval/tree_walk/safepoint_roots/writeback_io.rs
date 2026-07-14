//! Root-writeback slot enumeration and the typed read/validate/write paths.

use super::*;

impl TreeWalk {
    pub(super) fn safepoint_root_value_writeback_slots(
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

    pub(super) fn validate_safepoint_root_writeback_targets(
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
                Err(root_writeback_source_unavailable(source))
            }
            EvalRootSource::TreeWalkFlatCaptureOwner => self
                .flat_env
                .as_ref()
                .map(EvalFlatCapture::inline_owner)
                .ok_or_else(|| root_writeback_source_unavailable(source)),
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
                Err(root_writeback_source_unavailable(source))
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
                    .map(EvalFlatCapture::inline_owner)
                    .ok_or_else(|| root_writeback_source_unavailable(source))
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

    pub(super) fn write_safepoint_root_writeback_value(
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
