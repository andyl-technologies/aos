//! Heap allocation, value interning, and attrset/path materialization helpers.

use super::*;
use crate::eval::{
    TreeWalkParallelThunkForceOutcome, TreeWalkThunkAllocationContext, TreeWalkThunkAllocationPlan,
    tree_walk_thunk_allocation_plan,
};
#[cfg(test)]
use crate::runtime::alloc::RuntimeAllocationEntryPoint;
use crate::runtime::barrier::runtime_thunk_resolve_write_barrier_with_card_table;

const TREE_WALK_GC_STRESS_ALLOCATION_SITE_PROMOTE_AFTER_SURVIVALS: u32 = 2;

mod coerce_ifd;
mod force_thunk;
mod gc_stress;

impl TreeWalk {
    pub(super) fn eval_attr_name(
        &mut self,
        id: IrId,
        segment: IrAttrPathSegment,
        null_policy: DynamicAttrNullPolicy,
        span: Span,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        match segment {
            IrAttrPathSegment::Static(symbol) => {
                if self.symbols.resolve(symbol).is_none() {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol { id, symbol },
                        span,
                    ));
                }
                Ok(Some(symbol))
            }
            IrAttrPathSegment::Dynamic(dynamic) => {
                self.eval_dynamic_attr_name(self.dynamic_attr_expression(dynamic)?, null_policy)
            }
        }
    }

    pub(super) fn dynamic_attr_expression(&self, dynamic: IrId) -> Result<IrId, TreeWalkError> {
        let node = self.node(dynamic)?;
        if node.kind == IrKind::Interp
            && let IrData::Node(child) = node.data
        {
            return Ok(child);
        }
        Ok(dynamic)
    }

    pub(super) fn eval_dynamic_attr_name(
        &mut self,
        expression: IrId,
        null_policy: DynamicAttrNullPolicy,
    ) -> Result<Option<Symbol>, TreeWalkError> {
        let span = self.node(expression)?.span;
        let value = self.eval_node(expression)?;
        match value.tag() {
            ValueTag::Null if null_policy == DynamicAttrNullPolicy::SkipNull => Ok(None),
            ValueTag::String => self
                .intern_context_free_string_value(expression, value, span, "dynamic attribute name")
                .map(Some),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: expression,
                    expected: "string",
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn intern_string_value(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
    ) -> Result<Symbol, TreeWalkError> {
        let bytes = {
            let string = self.heap.get_string_view(value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(string.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ByteAllocationFailed {
                        id,
                        len: string.len(),
                    },
                    span,
                )
            })?;
            bytes.extend_from_slice(string.bytes());
            bytes
        };
        self.intern_attr_name_bytes(id, &bytes)
    }

    pub(super) fn intern_context_free_string_value(
        &mut self,
        id: IrId,
        value: Value,
        span: Span,
        op: &'static str,
    ) -> Result<Symbol, TreeWalkError> {
        let bytes = self.context_free_string_bytes(id, span, value, op)?;
        self.intern_attr_name_bytes(id, &bytes)
    }

    pub(super) fn intern_attr_name_bytes(
        &mut self,
        id: IrId,
        bytes: &[u8],
    ) -> Result<Symbol, TreeWalkError> {
        self.intern_symbol_for_eval(bytes).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                source.span(),
            )
        })
    }

    pub(super) fn eval_list(&mut self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Children(children) = node.data else {
            return Err(self.invalid_payload(id, node, "list children"));
        };
        let children = self
            .current_ir()
            .arena
            .child_slice(children)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::InvalidChildSlice {
                        id,
                        slice: children,
                    },
                    node.span,
                )
            })?
            .to_vec();
        let mut elements = Vec::new();
        elements.try_reserve_exact(children.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: children.len(),
                },
                node.span,
            )
        })?;
        let result = if self.can_admit_gc_stress_root_accumulator_allocation_safepoints(id) {
            (|| {
                for child in children.iter().copied() {
                    let value = self.with_transient_value_stack_roots(
                        id,
                        node.span,
                        elements.as_mut_slice(),
                        |eval| {
                            eval.with_gc_stress_accumulator_allocation_node(child, |eval| {
                                eval.eval_lazy_node(child)
                            })
                        },
                    )?;
                    elements.push(value);
                }
                Ok(())
            })()
        } else {
            self.begin_gc_stress_composite_accumulator();
            let result = (|| {
                for child in children.iter().copied() {
                    elements.push(self.eval_lazy_node(child)?);
                }
                Ok(())
            })();
            self.end_gc_stress_composite_accumulator();
            result
        };
        result?;
        self.alloc_tree_walk_list(id, node.span, NixList::new(elements))
    }

    pub(super) fn eval_local_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Local { slot } = node.data else {
            return Err(self.invalid_payload(id, node, "local payload"));
        };
        if self.active_env_frame_count() == 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingEnvironment { id },
                node.span,
            ));
        }
        #[cfg(test)]
        self.capture_validation_on_slot_read(0, slot);
        self.active_env_value_for_read(id, 0, slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span))
    }

    pub(super) fn eval_upval_var(&self, id: IrId, node: &IrNode) -> Result<Value, TreeWalkError> {
        let IrData::Upval { depth, slot } = node.data else {
            return Err(self.invalid_payload(id, node, "upvalue payload"));
        };
        let depth = depth as usize;
        let frame_count = self.active_env_frame_count();
        if depth >= frame_count {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidUpvalueDepth {
                    id,
                    depth,
                    frames: frame_count,
                },
                node.span,
            ));
        }
        #[cfg(test)]
        self.capture_validation_on_slot_read(depth, slot);
        self.active_env_value_for_read(id, depth, slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span))
    }

    pub(super) fn eval_lazy_node(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        if node.kind == IrKind::ThunkAlloc {
            return self.eval_thunk_alloc(id, &node);
        }
        self.eval_node(id)
    }
    pub(super) fn eval_nested_equality_operand(
        &mut self,
        id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let node = *self.node(id)?;
        match node.kind {
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            _ => self.eval_node(id),
        }
    }
    pub(super) fn eval_thunk_alloc(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        if let Some(value) = self.eval_call_summary_planned_thunk(id, node)? {
            return Ok(value);
        }
        let IrData::Node(body) = node.data else {
            return Err(self.invalid_payload(id, node, "thunk body"));
        };
        let context = self.thunk_allocation_context();
        let plan =
            tree_walk_thunk_allocation_plan(self.current_ir(), id, context).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::ThunkAllocation { id, source }, node.span)
            })?;
        let body_node = *self.node(body)?;
        if context == TreeWalkThunkAllocationContext::DemandPosition
            && !self.force_cache_active
            && EvalFlatCapture::supports_frame_count(self.options.max_call_depth())
        {
            // A lexical alias has no work or dynamic scope of its own. Once
            // order-sensitive frame population has finished, reading the
            // referenced slot now returns exactly the value the deferred body
            // would return later, including an existing thunk's identity and
            // laziness. Assembly keeps storage because the target frame may
            // still be populated or semantically rewritten.
            let alias = match body_node.kind {
                IrKind::LocalVar => Some(self.eval_local_var(body, &body_node)),
                IrKind::UpvalVar => Some(self.eval_upval_var(body, &body_node)),
                _ => None,
            };
            if let Some(value) = alias {
                self.increment_thunks_elided();
                return value;
            }
        }
        if self.options.eval_stats_dump()
            && context == TreeWalkThunkAllocationContext::DemandPosition
            && self.force_cache_active
            && EvalFlatCapture::supports_frame_count(self.options.max_call_depth())
        {
            // This is a strictly observational census of the optimization
            // opportunity suppressed by force-cache semantics. Classification
            // uses only lowered node metadata: it must not read the referenced
            // slot, force a value, allocate, or otherwise perturb evaluation.
            match body_node.kind {
                IrKind::LocalVar => {
                    self.increment_force_cache_suppressed_local_var_alias_thunks();
                }
                IrKind::UpvalVar => {
                    self.increment_force_cache_suppressed_upval_var_alias_thunks();
                }
                _ => {}
            }
        }
        match plan {
            TreeWalkThunkAllocationPlan::UpdateSlot(update) => {
                self.alloc_update_thunk_from_plan(update.thunk(), update.body(), node.span)
            }
            TreeWalkThunkAllocationPlan::SingleEntry(single_entry) => self
                .alloc_single_entry_thunk_from_plan(
                    single_entry.thunk(),
                    single_entry.body(),
                    node.span,
                ),
            TreeWalkThunkAllocationPlan::Omit(omitted) => {
                self.alloc_update_thunk_from_plan(omitted.thunk(), omitted.body(), node.span)
            }
            TreeWalkThunkAllocationPlan::ElideToWhnf(elision) => {
                self.increment_thunks_elided();
                if context == TreeWalkThunkAllocationContext::OrderSensitiveBindingAssembly {
                    self.increment_binding_assembly_elisions();
                    // Hide the physical outer assembly from allocation
                    // planning so the body behaves like its deferred force,
                    // while preserving that assembly's publication lifetime
                    // and pending captures. The GC-stress accumulator depth is
                    // deliberately left in place - in-flight frame entries
                    // are not rooted during assembly, matching the existing
                    // dynamic-key evaluation path.
                    return self.with_order_sensitive_binding_planning_suspended(|eval| {
                        eval.eval_node(elision.body())
                    });
                }
                self.eval_node(elision.body())
            }
        }
    }
    fn thunk_allocation_context(&self) -> TreeWalkThunkAllocationContext {
        if self.order_sensitive_binding_allocation_is_active() {
            TreeWalkThunkAllocationContext::OrderSensitiveBindingAssembly
        } else {
            TreeWalkThunkAllocationContext::DemandPosition
        }
    }

    /// Returns whether allocation planning sees an active assembly scope.
    pub(super) fn order_sensitive_binding_allocation_is_active(&self) -> bool {
        self.order_sensitive_binding_depth > self.order_sensitive_binding_planning_floor
    }

    /// Runs an elided thunk body with its physical outer assembly scopes hidden
    /// from allocation planning while preserving their publication boundary.
    pub(super) fn with_order_sensitive_binding_planning_suspended<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let previous_floor = std::mem::replace(
            &mut self.order_sensitive_binding_planning_floor,
            self.order_sensitive_binding_depth,
        );
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self))) {
            Ok(result) => result,
            Err(payload) => {
                self.order_sensitive_binding_planning_floor = previous_floor;
                std::panic::resume_unwind(payload);
            }
        };
        self.order_sensitive_binding_planning_floor = previous_floor;
        result
    }

    fn alloc_update_thunk_from_plan(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let value = self.alloc_thunk_for_node(id, body, span)?;
        let region_plan = self.region_plan_for_allocation(id, RegionRuntimeTier::OneShotArena);
        self.record_source_thunk_region_plan_decision(region_plan);
        Ok(value)
    }

    pub(super) fn alloc_single_entry_thunk_from_plan(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let (thunk, capture) = self.thunk_for_node(id, body, span)?;
        let thunk = thunk.into_single_entry();
        // Single-entry storage bypasses the parallel payload-cell admission
        // entirely (S7): the C-8 frame-local proof keeps the thunk off every
        // cross-thread path, so it gets a plain cell with no CAS protocol and
        // skips the admission's per-allocation claim-error construction.
        let value = self.alloc_tree_walk_thunk_without_parallel_cell(id, span, thunk, capture)?;
        self.increment_single_entry_thunks_allocated();
        let region_plan = self.region_plan_for_allocation(id, RegionRuntimeTier::OneShotArena);
        self.record_source_thunk_region_plan_decision(region_plan);
        Ok(value)
    }

    pub(super) fn begin_order_sensitive_binding_assembly(&mut self) {
        if self.order_sensitive_binding_depth == 0 {
            debug_assert!(self.pending_flat_captures.is_empty());
            self.order_sensitive_binding_failed = false;
        }
        self.order_sensitive_binding_depth = self.order_sensitive_binding_depth.saturating_add(1);
        self.begin_gc_stress_composite_accumulator();
    }

    pub(super) fn end_order_sensitive_binding_assembly(&mut self, succeeded: bool) {
        self.finish_order_sensitive_binding_assembly(succeeded);
    }

    fn begin_gc_stress_composite_accumulator(&mut self) {
        self.active_composite_accumulator_depth =
            self.active_composite_accumulator_depth.saturating_add(1);
    }

    pub(super) fn end_gc_stress_composite_accumulator(&mut self) {
        self.active_composite_accumulator_depth =
            self.active_composite_accumulator_depth.saturating_sub(1);
    }

    pub(super) fn with_gc_stress_composite_accumulator_suspended<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let suspended = self.active_composite_accumulator_depth > 0;
        if suspended {
            self.end_gc_stress_composite_accumulator();
        }
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self))) {
            Ok(result) => result,
            Err(payload) => {
                if suspended {
                    self.begin_gc_stress_composite_accumulator();
                }
                std::panic::resume_unwind(payload);
            }
        };
        if suspended {
            self.begin_gc_stress_composite_accumulator();
        }
        result
    }

    pub(super) fn with_gc_stress_accumulator_allocation_node<T>(
        &mut self,
        id: IrId,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let previous = self
            .active_gc_stress_accumulator_allocation_node
            .replace(id);
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self))) {
            Ok(result) => result,
            Err(payload) => {
                self.active_gc_stress_accumulator_allocation_node = previous;
                std::panic::resume_unwind(payload);
            }
        };
        self.active_gc_stress_accumulator_allocation_node = previous;
        result
    }

    pub(super) fn with_gc_stress_primop_arg_root_admission<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        self.active_gc_stress_primop_arg_root_admission_depth = self
            .active_gc_stress_primop_arg_root_admission_depth
            .saturating_add(1);
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(self))) {
            Ok(result) => result,
            Err(payload) => {
                self.active_gc_stress_primop_arg_root_admission_depth = self
                    .active_gc_stress_primop_arg_root_admission_depth
                    .saturating_sub(1);
                std::panic::resume_unwind(payload);
            }
        };
        self.active_gc_stress_primop_arg_root_admission_depth = self
            .active_gc_stress_primop_arg_root_admission_depth
            .saturating_sub(1);
        result
    }

    pub(super) fn alloc_thunk_for_node(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let (thunk, capture) = self.thunk_for_node(id, body, span)?;
        let value = self.alloc_tree_walk_thunk_with_flat_capture(id, span, thunk, capture)?;
        Ok(value)
    }

    fn thunk_for_node(
        &mut self,
        id: IrId,
        body: IrId,
        span: Span,
    ) -> Result<(EvalThunk, Option<EvalFlatCaptureBuffer>), TreeWalkError> {
        self.node(body)?;
        let (env, capture) = self.capture_env(id, span)?;
        let (with_env, scoped_globals) = self.capture_dynamic_envs(id, body, span)?;
        // Capture-on-demand attribution (RFC-0007 §P1): a no-op unless
        // `AOS_NIX_EVAL_STATS` collection is active, so production pays nothing.
        if self.options.eval_stats_dump() {
            let module_index = self.current_module.index();
            let with_ambient_empty = self.with_scopes.is_empty();
            let global_ambient_empty = self.scoped_globals.is_empty();
            super::capture_probe::note_capture(
                self.current_ir(),
                module_index,
                body,
                with_ambient_empty,
                global_ambient_empty,
            );
        }
        let thunk =
            EvalThunk::with_captures(self.current_module, body, env, with_env, scoped_globals);
        #[cfg(feature = "maximal_laziness_probe")]
        self.note_maximal_laziness_allocation(&thunk);
        Ok((thunk, capture))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_apply_thunk(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        self.alloc_tree_walk_thunk(
            id,
            span,
            EvalThunk::apply(
                self.current_module,
                function_id,
                function_span,
                function,
                self.current_module,
                argument_id,
                argument,
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_genlist_elem_at_add_one_thunk(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        self.alloc_tree_walk_thunk(
            id,
            span,
            EvalThunk::genlist_elem_at_add_one(
                self.current_module,
                function_id,
                function_span,
                function,
                self.current_module,
                argument_id,
                argument,
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_apply2_thunk(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        first_argument_id: IrId,
        first_argument_span: Span,
        first_argument: Value,
        second_argument_id: IrId,
        second_argument_span: Span,
        second_argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.alloc_tree_walk_thunk(
            id,
            span,
            EvalThunk::apply2(
                self.current_module,
                function_id,
                function_span,
                function,
                self.current_module,
                first_argument_id,
                first_argument_span,
                first_argument,
                self.current_module,
                second_argument_id,
                second_argument_span,
                second_argument,
            ),
        )?;
        Ok(value)
    }

    pub(super) fn alloc_select_thunk(
        &mut self,
        id: IrId,
        span: Span,
        select_id: IrId,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Result<Value, TreeWalkError> {
        let value = self.alloc_tree_walk_thunk(
            id,
            span,
            EvalThunk::select(self.current_module, select_id, receiver, path),
        )?;
        Ok(value)
    }

    pub(super) fn alloc_builtin_attr_thunk(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Result<Value, TreeWalkError> {
        let value =
            self.alloc_tree_walk_thunk(id, span, EvalThunk::builtin_attr(symbol, builtin))?;
        Ok(value)
    }

    pub(super) fn alloc_tree_walk_thunk(
        &mut self,
        id: IrId,
        span: Span,
        thunk: EvalThunk,
    ) -> Result<Value, TreeWalkError> {
        self.alloc_tree_walk_thunk_with_flat_capture(id, span, thunk, None)
    }

    fn alloc_tree_walk_thunk_with_flat_capture(
        &mut self,
        id: IrId,
        span: Span,
        thunk: EvalThunk,
        capture: Option<EvalFlatCaptureBuffer>,
    ) -> Result<Value, TreeWalkError> {
        let thunk = self.admit_parallel_thunk_payload_cell(id, span, thunk);
        self.alloc_tree_walk_thunk_without_parallel_cell(id, span, thunk, capture)
    }

    /// Allocates a thunk record without consulting the parallel payload-cell
    /// admission.
    ///
    /// This is the single-entry allocation path: the C-8 frame-local proof
    /// already guarantees the record is unreachable from other workers, so
    /// the shared claim protocol (and the admission's eagerly built
    /// claim-drop error) is skipped.
    fn alloc_tree_walk_thunk_without_parallel_cell(
        &mut self,
        id: IrId,
        span: Span,
        thunk: EvalThunk,
        capture: Option<EvalFlatCaptureBuffer>,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "demand_region_shadow_probe")]
        let demand_region_before = self.demand_region_allocation_cursor();
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_thunk_allocation_safepoint(id, &thunk);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot);
        let pending_env = capture
            .as_ref()
            .filter(|capture| !capture.is_ready())
            .and_then(|_| thunk.env().cloned());
        #[cfg(test)]
        let kind_is_node = matches!(thunk.kind(), EvalThunkKind::Node { .. });
        if self.options.eval_stats_dump() {
            super::force_shape_census::record_allocation(
                self.force_shape_class(&thunk),
                self.order_sensitive_binding_depth > 0,
                thunk.env().map(EvalEnv::storage_class),
            );
        }
        let allocation = self.heap.alloc_thunk_with_flat_capture(thunk, capture);
        let (allocated_value, pending_tail) = allocation
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        #[cfg(feature = "demand_region_shadow_probe")]
        self.note_demand_region_source_allocation(
            id,
            crate::compile::VirtualAllocationKind::Promise,
            demand_region_before,
            0,
        );
        #[cfg(test)]
        self.capture_validation_record_alloc(id, allocated_value, kind_is_node);
        self.increment_thunks_allocated();
        let value = if dispatch_gc_stress_safepoint {
            self.apply_gc_stress_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                RuntimeAllocatorTier::TierAOneShot,
                previous_poll,
                allocated_value,
                true,
            )?
        } else {
            allocated_value
        };
        let pending_tail = pending_tail.filter(|_| value.raw_eq(allocated_value));
        self.defer_flat_capture_if_assembling(id, value, pending_tail, pending_env);
        #[cfg(feature = "peak_ordinal_probe")]
        self.capture_peak_ordinal_context();
        Ok(value)
    }

    pub(super) fn alloc_tree_walk_lambda_with_flat_capture(
        &mut self,
        id: IrId,
        span: Span,
        lambda: EvalLambda,
        capture: Option<EvalFlatCaptureBuffer>,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "demand_region_shadow_probe")]
        let demand_region_before = self.demand_region_allocation_cursor();
        if self.options.eval_stats_dump() {
            super::force_shape_census::record_lambda_env_storage(lambda.env().storage_class());
        }
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_lambda_allocation_safepoint(id, &lambda);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot);
        let pending_env = capture
            .as_ref()
            .filter(|capture| !capture.is_ready())
            .map(|_| lambda.env().clone());
        let allocation = self.heap.alloc_lambda_with_flat_capture(lambda, capture);
        let (allocated_value, pending_tail) = allocation
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        #[cfg(feature = "demand_region_shadow_probe")]
        self.note_demand_region_source_allocation(
            id,
            crate::compile::VirtualAllocationKind::Closure,
            demand_region_before,
            0,
        );
        let value = if dispatch_gc_stress_safepoint {
            self.apply_gc_stress_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                RuntimeAllocatorTier::TierAOneShot,
                previous_poll,
                allocated_value,
                false,
            )?
        } else {
            allocated_value
        };
        let pending_tail = pending_tail.filter(|_| value.raw_eq(allocated_value));
        self.defer_flat_capture_if_assembling(id, value, pending_tail, pending_env);
        #[cfg(feature = "peak_ordinal_probe")]
        self.capture_peak_ordinal_context();
        Ok(value)
    }

    pub(super) fn alloc_tree_walk_primop(
        &mut self,
        id: IrId,
        span: Span,
        primop: EvalPrimOp,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_primop_allocation_safepoint(id, &primop);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot);
        let allocation = self.heap.alloc_primop(primop);
        let value = allocation
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let value = if dispatch_gc_stress_safepoint {
            self.apply_gc_stress_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                RuntimeAllocatorTier::TierAOneShot,
                previous_poll,
                value,
                false,
            )
        } else {
            Ok(value)
        }?;
        #[cfg(feature = "peak_ordinal_probe")]
        self.capture_peak_ordinal_context();
        Ok(value)
    }

    pub(super) fn alloc_tree_walk_string(
        &mut self,
        id: IrId,
        span: Span,
        string: NixString,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_permanent_root_allocation_safepoint(id);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared);
        let allocation = self.heap.alloc_string(string);
        let value = allocation
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let value = if dispatch_gc_stress_safepoint {
            #[cfg(test)]
            self.record_gc_stress_permanent_root_allocation_dispatch(
                RuntimeAllocationEntryPoint::AosAllocString,
            );
            self.apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                previous_poll,
                value,
            )
        } else {
            Ok(value)
        }?;
        #[cfg(feature = "peak_ordinal_probe")]
        self.capture_peak_ordinal_context();
        Ok(value)
    }

    pub(super) fn alloc_replayed_payload_string(
        &mut self,
        origin: Option<EvalNodeRef>,
        string: NixString,
    ) -> Option<Value> {
        let Some(origin) = origin else {
            let allocation = self.heap.alloc_string(string);
            #[cfg(feature = "peak_ordinal_probe")]
            if allocation.is_ok() {
                self.capture_peak_ordinal_context();
            }
            return allocation.ok();
        };
        if origin.module() != self.current_module {
            let allocation = self.heap.alloc_string(string);
            #[cfg(feature = "peak_ordinal_probe")]
            if allocation.is_ok() {
                self.capture_peak_ordinal_context();
            }
            return allocation.ok();
        }
        let span = self.node_in_module(origin.module(), origin.id()).ok()?.span;
        self.alloc_tree_walk_string(origin.id(), span, string).ok()
    }

    pub(super) fn alloc_replayed_payload_path(
        &mut self,
        origin: Option<EvalNodeRef>,
        path: NixString,
    ) -> Option<Value> {
        let Some(origin) = origin else {
            let allocation = self.heap.alloc_path(path);
            #[cfg(feature = "peak_ordinal_probe")]
            if allocation.is_ok() {
                self.capture_peak_ordinal_context();
            }
            return allocation.ok();
        };
        if origin.module() != self.current_module {
            let allocation = self.heap.alloc_path(path);
            #[cfg(feature = "peak_ordinal_probe")]
            if allocation.is_ok() {
                self.capture_peak_ordinal_context();
            }
            return allocation.ok();
        }
        let span = self.node_in_module(origin.module(), origin.id()).ok()?.span;
        self.alloc_tree_walk_path(origin.id(), span, path).ok()
    }

    pub(super) fn alloc_replayed_payload_list(
        &mut self,
        origin: Option<EvalNodeRef>,
        list: NixList,
    ) -> Option<Value> {
        let Some(origin) = origin else {
            let allocation = self.heap.alloc_list(list);
            #[cfg(feature = "peak_ordinal_probe")]
            if allocation.is_ok() {
                self.capture_peak_ordinal_context();
            }
            return allocation.ok();
        };
        if origin.module() != self.current_module {
            let allocation = self.heap.alloc_list(list);
            #[cfg(feature = "peak_ordinal_probe")]
            if allocation.is_ok() {
                self.capture_peak_ordinal_context();
            }
            return allocation.ok();
        }
        let span = self.node_in_module(origin.module(), origin.id()).ok()?.span;
        self.alloc_tree_walk_list(origin.id(), span, list).ok()
    }

    pub(super) fn alloc_tree_walk_string_with_attr_entry_roots(
        &mut self,
        id: IrId,
        span: Span,
        entries: &mut [AttrEntry],
        string: NixString,
    ) -> Result<Value, TreeWalkError> {
        self.with_attr_entry_value_roots(id, span, entries, |eval| {
            eval.alloc_tree_walk_string(id, span, string)
        })
    }

    pub(super) fn with_attr_entry_value_roots<T>(
        &mut self,
        id: IrId,
        span: Span,
        entries: &mut [AttrEntry],
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if entries.is_empty() {
            return body(self);
        }

        let mut roots = Vec::new();
        roots.try_reserve_exact(entries.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: entries.len(),
                    },
                },
                span,
            )
        })?;
        roots.extend(entries.iter().map(|entry| entry.value));

        let result = self.with_transient_value_stack_roots(id, span, &mut roots, body)?;
        for (entry, root) in entries.iter_mut().zip(roots) {
            entry.value = root;
        }
        Ok(result)
    }

    pub(super) fn alloc_tree_walk_path(
        &mut self,
        id: IrId,
        span: Span,
        path: NixString,
    ) -> Result<Value, TreeWalkError> {
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_permanent_root_allocation_safepoint(id);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared);
        let allocation = self.heap.alloc_path(path);
        let value = allocation
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let value = if dispatch_gc_stress_safepoint {
            #[cfg(test)]
            self.record_gc_stress_permanent_root_allocation_dispatch(
                RuntimeAllocationEntryPoint::AosAllocString,
            );
            self.apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                previous_poll,
                value,
            )
        } else {
            Ok(value)
        }?;
        #[cfg(feature = "peak_ordinal_probe")]
        self.capture_peak_ordinal_context();
        Ok(value)
    }

    pub(super) fn alloc_tree_walk_list(
        &mut self,
        id: IrId,
        span: Span,
        list: NixList,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "demand_region_shadow_probe")]
        let demand_region_before = self.demand_region_allocation_cursor();
        #[cfg(feature = "demand_region_shadow_probe")]
        let demand_region_spine_bytes =
            list.capacity().saturating_mul(std::mem::size_of::<Value>());
        #[cfg(test)]
        {
            self.tree_walk_list_wrapper_calls = self.tree_walk_list_wrapper_calls.saturating_add(1);
        }
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_permanent_list_allocation_safepoint(id, &list);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared);
        let allocation = self.heap.alloc_list(list);
        let value = allocation
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        #[cfg(feature = "demand_region_shadow_probe")]
        self.note_demand_region_source_allocation(
            id,
            crate::compile::VirtualAllocationKind::List,
            demand_region_before,
            demand_region_spine_bytes,
        );
        let value = if dispatch_gc_stress_safepoint {
            #[cfg(test)]
            self.record_gc_stress_permanent_root_allocation_dispatch(
                RuntimeAllocationEntryPoint::AosAllocList,
            );
            self.apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                previous_poll,
                value,
            )
        } else {
            Ok(value)
        }?;
        #[cfg(feature = "peak_ordinal_probe")]
        self.capture_peak_ordinal_context();
        Ok(value)
    }

    #[cfg(test)]
    pub(in crate::eval::tree_walk) const fn tree_walk_list_wrapper_calls(&self) -> usize {
        self.tree_walk_list_wrapper_calls
    }

    #[cfg(test)]
    fn record_gc_stress_permanent_root_allocation_dispatch(
        &mut self,
        entrypoint: RuntimeAllocationEntryPoint,
    ) {
        self.gc_stress_permanent_root_allocation_dispatches
            .push(entrypoint);
    }

    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn gc_stress_permanent_root_allocation_dispatches(
        &self,
    ) -> &[RuntimeAllocationEntryPoint] {
        &self.gc_stress_permanent_root_allocation_dispatches
    }

    pub(super) fn alloc_tree_walk_attrs_with_projected_shape_metadata(
        &mut self,
        id: IrId,
        span: Span,
        shape: u32,
        repr: AttrSetReprKind,
        projected_shape: Option<ShapeId>,
        attrs: FlatAttrs,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "demand_region_shadow_probe")]
        let demand_region_before = self.demand_region_allocation_cursor();
        let dispatch_gc_stress_safepoint =
            self.can_dispatch_gc_stress_permanent_attrs_allocation_safepoint(id, &attrs);
        let previous_poll =
            self.last_allocation_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared);
        let allocation = self.heap.alloc_attrs_with_projected_shape_metadata(
            shape,
            repr,
            projected_shape,
            attrs,
        );
        let value = allocation
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        #[cfg(feature = "demand_region_shadow_probe")]
        self.note_demand_region_source_allocation(
            id,
            crate::compile::VirtualAllocationKind::Attrs,
            demand_region_before,
            0,
        );
        let value = if dispatch_gc_stress_safepoint {
            #[cfg(test)]
            self.record_gc_stress_permanent_root_allocation_dispatch(
                RuntimeAllocationEntryPoint::AosAllocAttrs,
            );
            self.apply_gc_stress_permanent_allocation_safepoint_to_just_allocated_value(
                id,
                span,
                previous_poll,
                value,
            )
        } else {
            Ok(value)
        }?;
        #[cfg(feature = "peak_ordinal_probe")]
        self.capture_peak_ordinal_context();
        Ok(value)
    }
}
