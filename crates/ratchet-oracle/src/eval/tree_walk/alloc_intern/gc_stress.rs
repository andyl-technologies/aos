//! GC-stress allocation-safepoint dispatch policy.
//!
//! Decides which just-allocated values may take a stress-mode allocation
//! safepoint (per tier, per allocation site, and per active primop-arg root
//! admission) and applies the safepoint plus source-card marking to values
//! that qualify.

use super::*;

impl TreeWalk {
    pub(super) fn can_dispatch_gc_stress_lambda_allocation_safepoint(
        &self,
        id: IrId,
        lambda: &EvalLambda,
    ) -> bool {
        self.can_dispatch_gc_stress_root_allocation_safepoint(id)
            && Self::is_gc_stress_uncaptured_lambda(lambda)
    }

    pub(super) fn can_dispatch_gc_stress_thunk_allocation_safepoint(
        &self,
        id: IrId,
        thunk: &EvalThunk,
    ) -> bool {
        self.can_dispatch_gc_stress_root_allocation_safepoint(id)
            && Self::is_gc_stress_uncaptured_node_thunk(thunk)
    }

    pub(super) fn can_dispatch_gc_stress_primop_allocation_safepoint(
        &self,
        id: IrId,
        primop: &EvalPrimOp,
    ) -> bool {
        self.can_dispatch_gc_stress_root_allocation_safepoint(id) && primop.args().is_empty()
    }

    pub(super) fn can_dispatch_gc_stress_permanent_list_allocation_safepoint(
        &self,
        id: IrId,
        list: &NixList,
    ) -> bool {
        self.can_dispatch_gc_stress_permanent_root_allocation_safepoint(id)
            && list
                .iter()
                .copied()
                .all(|value| self.can_dispatch_gc_stress_permanent_composite_field(value))
    }

    pub(super) fn can_dispatch_gc_stress_permanent_attrs_allocation_safepoint(
        &self,
        id: IrId,
        attrs: &FlatAttrs,
    ) -> bool {
        self.can_dispatch_gc_stress_permanent_root_allocation_safepoint(id)
            && matches!(self.node(id), Ok(node) if node.kind == IrKind::AttrSet)
            && attrs
                .iter_by_symbol()
                .all(|entry| self.can_dispatch_gc_stress_permanent_composite_field(entry.value))
    }

    pub(super) fn can_dispatch_gc_stress_permanent_root_allocation_safepoint(
        &self,
        id: IrId,
    ) -> bool {
        self.active_root_eval_node == Some(id)
            && self.can_dispatch_gc_stress_ambient_allocation_safepoint()
    }

    fn can_dispatch_gc_stress_permanent_composite_field(&self, value: Value) -> bool {
        match value.tag() {
            ValueTag::Lambda => matches!(
                self.heap.get_lambda(value),
                Ok(lambda) if Self::is_gc_stress_uncaptured_lambda(lambda)
            ),
            ValueTag::Primop => matches!(
                self.heap.get_primop(value),
                Ok(primop) if primop.args().is_empty()
            ),
            ValueTag::Thunk => matches!(
                self.heap.get_thunk(value),
                Ok(thunk) if Self::is_gc_stress_uncaptured_node_thunk(thunk)
            ),
            _ => true,
        }
    }

    fn is_gc_stress_uncaptured_lambda(lambda: &EvalLambda) -> bool {
        lambda.env().is_empty()
            && lambda.with_scope_env().scopes().is_empty()
            && lambda.scoped_global_env().scopes().is_empty()
    }

    fn is_gc_stress_uncaptured_node_thunk(thunk: &EvalThunk) -> bool {
        matches!(
            thunk.kind(),
            EvalThunkKind::Node {
                env,
                dynamic_env,
                ..
            } if env.is_empty()
                && dynamic_env.is_none()
        )
    }

    fn can_dispatch_gc_stress_root_allocation_safepoint(&self, id: IrId) -> bool {
        (self.active_root_eval_node == Some(id)
            || self.active_gc_stress_accumulator_allocation_node == Some(id))
            && self.can_dispatch_gc_stress_ambient_allocation_safepoint()
    }

    pub(in crate::eval::tree_walk) fn can_admit_gc_stress_root_accumulator_allocation_safepoints(
        &self,
        id: IrId,
    ) -> bool {
        self.active_root_eval_node == Some(id)
            && self.can_dispatch_gc_stress_ambient_allocation_safepoint()
    }

    fn can_dispatch_gc_stress_ambient_allocation_safepoint(&self) -> bool {
        self.active_root_eval_node.is_some()
            && self.active_env_is_empty()
            && self.with_scopes.is_empty()
            && self.scoped_globals.is_empty()
            && self.active_composite_accumulator_depth == 0
            && self.suspended_env_roots.is_empty()
            && self.active_force_roots.is_empty()
            && self.can_dispatch_gc_stress_active_primop_arg_roots()
            && self.import_cache.is_empty()
            && self.can_dispatch_gc_stress_interned_roots()
    }

    fn can_dispatch_gc_stress_active_primop_arg_roots(&self) -> bool {
        if self.active_primop_arg_roots.is_empty() && self.active_primop_arg_frames.is_empty() {
            return true;
        }
        self.active_gc_stress_primop_arg_root_admission_depth > 0
            && self.can_dispatch_gc_stress_admitted_active_primop_arg_roots()
    }

    fn can_dispatch_gc_stress_admitted_active_primop_arg_roots(&self) -> bool {
        let [frame] = self.active_primop_arg_frames.as_slice() else {
            return false;
        };
        if frame.start != 0 || frame.len != self.active_primop_arg_roots.len() {
            return false;
        }
        self.active_primop_arg_roots
            .iter()
            .all(|arg| self.can_dispatch_gc_stress_admitted_active_primop_arg_root(arg.value()))
    }

    fn can_dispatch_gc_stress_admitted_active_primop_arg_root(&self, value: Value) -> bool {
        if value.as_heap_ptr().is_err() {
            return true;
        }
        self.transient_value_stack_roots
            .iter()
            .any(|root| root.raw_eq(value))
    }

    fn can_dispatch_gc_stress_interned_roots(&self) -> bool {
        let Ok(roots) = self.heap.interned_root_set() else {
            return false;
        };
        roots
            .roots()
            .iter()
            .all(|root| matches!(root.value().tag(), ValueTag::String | ValueTag::Path))
    }

    pub(super) fn apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
        &mut self,
        id: IrId,
        span: Span,
        previous_poll: Option<AllocationCollectorPoll>,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let Some(current_poll) =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared)
        else {
            return Ok(value);
        };
        if Some(current_poll) == previous_poll {
            return Ok(value);
        }
        let original_card_table = self
            .thunk_resolve_card_table
            .try_clone()
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id,
                        source: EvalHeapError::GenerationalGc(source),
                    },
                    span,
                )
            })?;
        self.mark_gc_stress_allocation_source_card(id, span, value)?;
        let result = self.apply_gc_stress_allocation_safepoint_to_just_allocated_value(
            id,
            span,
            RuntimeAllocatorTier::PermanentShared,
            previous_poll,
            value,
            false,
        );
        if result.is_err() {
            self.thunk_resolve_card_table = original_card_table;
        }
        result
    }

    fn mark_gc_stress_allocation_source_card(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let ptr = value.as_heap_ptr().map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id,
                    source: EvalHeapError::Value(source),
                },
                span,
            )
        })?;
        let source = GcHeapAddress::new(ptr.as_ptr() as usize).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id,
                    source: EvalHeapError::GenerationalGc(source),
                },
                span,
            )
        })?;
        self.thunk_resolve_card_table
            .mark_source(source)
            .map(|_| ())
            .map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id,
                        source: EvalHeapError::GenerationalGc(source),
                    },
                    span,
                )
            })
    }

    pub(super) fn apply_gc_stress_allocation_safepoint_to_just_allocated_value(
        &mut self,
        id: IrId,
        span: Span,
        tier: RuntimeAllocatorTier,
        previous_poll: Option<AllocationCollectorPoll>,
        value: Value,
        install_forwarding_slots: bool,
    ) -> Result<Value, TreeWalkError> {
        let Some(current_poll) = self.last_allocation_collector_poll_for_tier(tier) else {
            return Ok(value);
        };
        if Some(current_poll) == previous_poll {
            return Ok(value);
        }

        let registered_roots = self.transient_value_stack_roots.len();
        let total_roots = registered_roots.checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: registered_roots,
                },
                span,
            )
        })?;
        let mut transient_roots = Vec::new();
        transient_roots
            .try_reserve_exact(total_roots)
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: total_roots,
                    },
                    span,
                )
            })?;
        transient_roots.extend_from_slice(&self.transient_value_stack_roots);
        transient_roots.push(value);

        let promotion_policy = MinorGcPromotionPolicy::new(
            TREE_WALK_GC_STRESS_ALLOCATION_SITE_PROMOTE_AFTER_SURVIVALS,
        );
        let writeback_result = if install_forwarding_slots {
            self.apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
                current_poll,
                promotion_policy,
                &mut transient_roots,
            )
            .map(|_| ())
        } else {
            self.apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
                current_poll,
                promotion_policy,
                &mut transient_roots,
            )
            .map(|_| ())
        };
        writeback_result.map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::GcStressAllocationSafepoint { id, source },
                span,
            )
        })?;
        for (registered_root, updated_root) in self
            .transient_value_stack_roots
            .iter_mut()
            .zip(transient_roots.iter().copied())
        {
            *registered_root = updated_root;
        }
        Ok(transient_roots
            .get(registered_roots)
            .copied()
            .unwrap_or(value))
    }

    pub(super) fn last_allocation_collector_poll_for_tier(
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
}
