//! Primop application: arity-checked direct/strict builtin dispatch.

use super::mixed_apply_machine::PreparedMixedReadyCall;
use super::*;

/// Immutable lambda metadata retained across a repeated higher-order loop.
pub(in crate::eval::tree_walk) struct ReusedLambdaCall {
    lambda: EvalLambda,
    argument_span: Span,
    first_call_counted: bool,
}

impl TreeWalk {
    pub(super) fn alloc_static_string(
        &mut self,
        id: IrId,
        span: Span,
        bytes: &[u8],
    ) -> Result<Value, TreeWalkError> {
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.alloc_tree_walk_string(id, span, NixString::from_bytes(owned))
    }

    pub(super) fn alloc_static_string_with_attr_entry_roots(
        &mut self,
        id: IrId,
        span: Span,
        entries: &mut [AttrEntry],
        bytes: &[u8],
    ) -> Result<Value, TreeWalkError> {
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.alloc_tree_walk_string_with_attr_entry_roots(
            id,
            span,
            entries,
            NixString::from_bytes(owned),
        )
    }

    pub(super) fn alloc_symbol_string(
        &mut self,
        id: IrId,
        span: Span,
        symbol: Symbol,
    ) -> Result<Value, TreeWalkError> {
        let bytes = self.symbols.resolve(symbol).ok_or_else(|| {
            TreeWalkError::new(TreeWalkErrorKind::InvalidSymbol { id, symbol }, span)
        })?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ByteAllocationFailed {
                    id,
                    len: bytes.len(),
                },
                span,
            )
        })?;
        owned.extend_from_slice(bytes);
        self.alloc_tree_walk_string(id, span, NixString::from_bytes(owned))
    }

    pub(super) fn force_callable_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.with_nonmoving_native_continuation(
            super::native_continuation_shadow::NativeContinuationKind::CallableForce,
            id,
            &[],
            Some(super::native_continuation_shadow::NativeContinuationEdge::ForceValue),
            |eval| eval.force_value(id, span, value),
        )?;
        self.ensure_callable_value(id, span, value)
    }

    pub(super) fn force_primop_arg(
        &mut self,
        argument: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        self.with_current_module(argument.module(), |eval| {
            eval.force_uncovered_primop_leaf(argument.id(), argument.span(), argument.value())
        })
    }

    pub(super) fn ensure_applicable_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        self.ensure_callable_value_with_expected(id, span, value, "lambda")
    }

    pub(super) fn ensure_callable_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        self.ensure_callable_value_with_expected(id, span, value, "function")
    }

    pub(super) fn ensure_callable_value_with_expected(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
        expected: &'static str,
    ) -> Result<Value, TreeWalkError> {
        match value.tag() {
            ValueTag::Lambda | ValueTag::Primop => Ok(value),
            ValueTag::Attrs if self.functor_attr_value(id, span, value)?.is_some() => Ok(value),
            actual => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected,
                    actual,
                },
                span,
            )),
        }
    }

    pub(super) fn functor_attr_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Option<Value>, TreeWalkError> {
        let key = self.intern_builtin_attr_symbol(id, b"__functor", span)?;
        let attrs = self
            .heap
            .get_attrs_view(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        Ok(attrs.get(key))
    }

    pub(super) fn apply_functor_value(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        argument_span: Span,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let Some(functor) = self.functor_attr_value(function_id, function_span, function)? else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: function_id,
                    expected: "lambda",
                    actual: ValueTag::Attrs,
                },
                function_span,
            ));
        };

        self.apply_lambda_value_2(
            id,
            span,
            function_id,
            functor,
            function_span,
            function_id,
            function_span,
            function,
            argument_id,
            argument_span,
            argument,
        )
    }

    #[cfg(test)]
    pub(crate) fn apply_value(
        &mut self,
        id: IrId,
        span: Span,
        function: Value,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let mut function = function;
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop) {
            function = self.force_demanded_value(id, span, function)?;
        }
        function = self.ensure_applicable_value(id, span, function)?;
        self.apply_lambda_value_with_argument_span(id, span, id, function, span, id, span, argument)
    }

    pub(crate) fn apply_value_with_transient_roots(
        &mut self,
        id: IrId,
        span: Span,
        function: Value,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let mut roots = [function, argument];
        self.with_indexed_transient_value_stack_roots(id, span, &mut roots, |eval, slots| {
            let function_slot = slots.start;
            let argument_slot = function_slot.checked_add(1).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
            let mut function = eval
                .current_transient_value_stack_root(function_slot)
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    )
                })?;
            if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop) {
                function = eval.force_demanded_value(id, span, function)?;
                if !eval.set_current_transient_value_stack_root(function_slot, function) {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    ));
                }
            }
            function = eval.ensure_applicable_value(id, span, function)?;
            if !eval.set_current_transient_value_stack_root(function_slot, function) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                ));
            }
            let argument = eval
                .current_transient_value_stack_root(argument_slot)
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    )
                })?;
            eval.apply_lambda_value_with_argument_span(
                id, span, id, function, span, id, span, argument,
            )
        })
    }

    pub(super) fn apply_lambda_value(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "collection_poll_probe")]
        {
            let mut roots = [function, argument];
            return self.with_writeback_native_continuation(
                super::native_continuation_shadow::NativeContinuationKind::ApplyLambdaPortal,
                id,
                span,
                &mut roots,
                super::native_continuation_shadow::NativeContinuationEdge::ApplyLambda,
                |eval, slots| {
                    let function = eval
                        .current_transient_value_stack_root(slots.start)
                        .ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                                span,
                            )
                        })?;
                    let argument_slot = slots.start.checked_add(1).ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?;
                    let argument = eval
                        .current_transient_value_stack_root(argument_slot)
                        .ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                                span,
                            )
                        })?;
                    eval.with_native_continuation_edge(
                        super::native_continuation_shadow::NativeContinuationEdge::ApplyLambda,
                        id,
                        |eval| {
                            eval.apply_lambda_value_with_native_census(
                                id,
                                span,
                                function_id,
                                function,
                                function_span,
                                argument_id,
                                argument,
                            )
                        },
                    )
                },
            );
        }
        #[cfg(not(feature = "collection_poll_probe"))]
        {
            self.apply_lambda_value_with_native_census(
                id,
                span,
                function_id,
                function,
                function_span,
                argument_id,
                argument,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_lambda_value_with_native_census(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let argument_span = self.node(argument_id)?.span;
        #[cfg(feature = "collection_poll_probe")]
        let token = self.begin_speed_opportunity_phase(
            super::whole_demand_corridor_census::SpeedOpportunityPhase::Apply,
        );
        let result = self.apply_lambda_value_with_argument_span(
            id,
            span,
            function_id,
            function,
            function_span,
            argument_id,
            argument_span,
            argument,
        );
        #[cfg(feature = "collection_poll_probe")]
        self.finish_speed_opportunity_phase(token, &result);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_lambda_value_with_argument_span(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        argument_span: Span,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "lifetime_cohort_probe")]
        {
            let mut roots = [function, argument];
            return self.with_lifetime_cohort_shadow_roots(id, span, &mut roots, |eval, slots| {
                let function = eval
                    .current_transient_value_stack_root(slots.start)
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?;
                let argument_slot = slots.start.checked_add(1).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    )
                })?;
                let argument = eval
                    .current_transient_value_stack_root(argument_slot)
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?;
                eval.apply_lambda_value_with_argument_span_shadowed(
                    id,
                    span,
                    function_id,
                    function,
                    function_span,
                    argument_id,
                    argument_span,
                    argument,
                )
            });
        }
        #[cfg(not(feature = "lifetime_cohort_probe"))]
        {
            self.apply_lambda_value_with_argument_span_shadowed(
                id,
                span,
                function_id,
                function,
                function_span,
                argument_id,
                argument_span,
                argument,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_lambda_value_with_argument_span_shadowed(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        argument_span: Span,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        self.increment_function_calls();
        match function.tag() {
            ValueTag::Lambda => {}
            ValueTag::Primop => {
                return self.apply_primop_value(
                    id,
                    span,
                    function_id,
                    function,
                    function_span,
                    EvalPrimOpArg::new_in_module(
                        self.current_module,
                        argument_id,
                        argument_span,
                        argument,
                    ),
                );
            }
            ValueTag::Attrs => {
                return self.apply_functor_value(
                    id,
                    span,
                    function_id,
                    function,
                    function_span,
                    argument_id,
                    argument_span,
                    argument,
                );
            }
            actual => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: function_id,
                        expected: "lambda",
                        actual,
                    },
                    function_span,
                ));
            }
        }
        let lambda = self.heap.clone_lambda(function).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: function_id,
                    source,
                },
                function_span,
            )
        })?;
        self.apply_reused_lambda_value_with_argument_span(
            id,
            span,
            function,
            &lambda,
            argument_id,
            argument_span,
            argument,
        )
    }

    /// Applies an already-cloned lambda while retaining ordinary call semantics.
    ///
    /// Repeated higher-order builtin loops may reuse immutable closure metadata
    /// across elements. The caller must increment the function-call counter for
    /// each application before entering this helper, matching
    /// [`Self::apply_lambda_value_with_argument_span`].
    ///
    /// # Errors
    ///
    /// Returns the ordinary tier-dispatch, frame, environment, binding, body,
    /// memo-probe, or call-depth error for this application.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::eval::tree_walk) fn apply_reused_lambda_value_with_argument_span(
        &mut self,
        id: IrId,
        span: Span,
        function: Value,
        lambda: &EvalLambda,
        argument_id: IrId,
        argument_span: Span,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let direct_function_id = self.node(id).ok().and_then(|node| {
            if node.kind != IrKind::Apply {
                return None;
            }
            let IrData::Pair { first, second } = node.data else {
                return None;
            };
            (second == argument_id).then_some(first)
        });
        let prepared_mixed = direct_function_id.and_then(|function_id| {
            self.prepare_direct_mixed_ready_call(
                EvalNodeRef::new(self.current_module, id),
                EvalNodeRef::new(self.current_module, function_id),
                function,
                EvalNodeRef::new(self.current_module, argument_id),
                argument,
                lambda,
            )
        });
        // Tier-2 apply seam: with an engine installed, an undecided lambda
        // def-site is consulted once here; a published compiled body replaces
        // the interpreted call entirely. `None` (no engine, skipped def-site,
        // deopt, or no dispatch) falls through byte-for-byte unchanged.
        if prepared_mixed.is_none()
            && self.tier1_engine.is_some()
            && let Some(value) = self.try_tier2_lambda_apply(id, span, function, &lambda, argument)
        {
            return Ok(value);
        }
        if self.gc_mode.is_enabled() || self.native_continuation_shadow_enabled() {
            let mut roots = [argument];
            return self.with_indexed_transient_value_stack_roots(
                id,
                span,
                &mut roots,
                |eval, slots| {
                    let argument = eval
                        .current_transient_value_stack_root(slots.start)
                        .ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                                span,
                            )
                        })?;
                    eval.apply_reused_lambda_value_with_rooted_argument(
                        id,
                        span,
                        lambda,
                        argument_id,
                        argument_span,
                        argument,
                        Some(slots.start),
                        None,
                    )
                },
            );
        }
        self.apply_reused_lambda_value_with_rooted_argument(
            id,
            span,
            lambda,
            argument_id,
            argument_span,
            argument,
            None,
            prepared_mixed.as_ref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_reused_lambda_value_with_rooted_argument(
        &mut self,
        id: IrId,
        span: Span,
        lambda: &EvalLambda,
        argument_id: IrId,
        argument_span: Span,
        argument: Value,
        argument_slot: Option<usize>,
        prepared_mixed: Option<&PreparedMixedReadyCall>,
    ) -> Result<Value, TreeWalkError> {
        let caller_module = self.current_module;
        self.with_current_module(lambda.module(), |eval| {
            let slot_count = eval.frame_info(id, lambda.frame(), span)?.slot_count as usize;
            let mut call_env = eval.clone_env_frames(id, lambda.env(), span)?;
            let call_frame = EvalFrame::new_linked(slot_count, call_env.frames.last().cloned())
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                })?;
            #[cfg(feature = "demand_region_shadow_probe")]
            eval.note_demand_region_frame_allocation(id, slot_count);
            call_env.frames.try_reserve_exact(1).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Env {
                        id,
                        source: EvalEnvError::CaptureAllocationFailed {
                            frames: call_env.frame_count() + 1,
                        },
                    },
                    span,
                )
            })?;
            call_env.frames.push(call_frame);
            eval.reserve_suspended_env_root_frame(id, span)?;
            eval.enter_call(id, span)?;
            eval.push_env_scope(
                id,
                span,
                call_env,
                lambda.with_scope_env(),
                lambda.scoped_global_env(),
            )?;
            // MEMO-2 boundary economics probe (measurement only): a formal-set
            // pattern is the `callPackage` argument shape, so its applications
            // are the package boundaries the design would seed. The wall guard
            // attributes body time to the outermost boundary; the decline
            // classification below runs after the body so forced argument
            // members are reflected.
            let is_formal_set = matches!(
                eval.node(lambda.pattern()).map(|node| node.kind),
                Ok(IrKind::FormalSet)
            );
            // MEMO-2 M2-record incr. 2 (default-off): recognize and count a keyed
            // package-boundary application against the source-Merkle map. Reads
            // only; no record store, no replay.
            if is_formal_set && eval.options.boundary_memo_active() {
                eval.record_boundary_admission(&lambda);
            }
            let probe_boundary = is_formal_set && eval.options.eval_stats_dump();
            let boundary_wall =
                probe_boundary.then(super::pkg_boundary_probe::BoundaryWallGuard::enter);
            let result = (|| {
                let call_frame = eval.env.last().cloned().ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::MissingEnvironment { id }, span)
                })?;
                eval.begin_order_sensitive_binding_assembly();
                let bind_result = eval.bind_lambda_argument(
                    id,
                    lambda.pattern(),
                    slot_count,
                    &call_frame,
                    argument_id,
                    argument_span,
                    argument,
                    span,
                );
                eval.end_order_sensitive_binding_assembly(bind_result.is_ok());
                bind_result?;
                if let Some(prepared) = prepared_mixed.as_ref()
                    && let MixedReadyCallHook::Completed(value) = prepared.run()
                {
                    return Ok(value);
                }
                #[cfg(feature = "dedup_string_list_canary")]
                if let Some(result) = eval.try_dedup_string_list_canary(lambda, argument) {
                    return result;
                }
                eval.note_promise_region_unknown_call(caller_module, id, lambda);
                eval.enter_promise_region_lambda_entry(lambda);
                let result = eval.with_nonmoving_native_continuation(
                    super::native_continuation_shadow::NativeContinuationKind::LambdaBody,
                    lambda.body(),
                    &[],
                    Some(super::native_continuation_shadow::NativeContinuationEdge::EvalNode),
                    |eval| eval.eval_node(lambda.body()),
                );
                eval.leave_promise_region_entry();
                result
            })();
            // Close the wall window on the body before the (untimed) env
            // restore and decline classification.
            drop(boundary_wall);
            eval.pop_env_scope();
            eval.leave_call();
            let argument = match argument_slot {
                Some(slot) => eval
                    .current_transient_value_stack_root(slot)
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?,
                None => argument,
            };
            if probe_boundary {
                eval.record_pkg_boundary_probe(&lambda, argument);
            }
            result
        })
    }

    /// Prepares immutable lambda metadata for a loop that will apply it.
    ///
    /// Preparation follows the first generic call's observable order: it
    /// resolves the argument span, increments the function-call counter, and
    /// then clones the lambda. Non-lambda callables and tiered execution return
    /// `None` so the caller can retain generic application.
    ///
    /// # Errors
    ///
    /// Returns the ordinary argument-node or lambda-heap error that the first
    /// generic application would have returned.
    pub(in crate::eval::tree_walk) fn prepare_reused_lambda_call(
        &mut self,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument_id: IrId,
        will_call: bool,
    ) -> Result<Option<ReusedLambdaCall>, TreeWalkError> {
        if !will_call || function.tag() != ValueTag::Lambda || self.tier1_engine.is_some() {
            return Ok(None);
        }
        let argument_span = self.node(argument_id)?.span;
        self.increment_function_calls();
        let lambda = self.heap.clone_lambda(function).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: function_id,
                    source,
                },
                function_span,
            )
        })?;
        Ok(Some(ReusedLambdaCall {
            lambda,
            argument_span,
            first_call_counted: true,
        }))
    }

    /// Applies one element through metadata returned by
    /// [`Self::prepare_reused_lambda_call`].
    ///
    /// # Errors
    ///
    /// Returns the ordinary interpreted-lambda application error.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::eval::tree_walk) fn apply_prepared_reused_lambda_call(
        &mut self,
        id: IrId,
        span: Span,
        function: Value,
        call: &mut ReusedLambdaCall,
        argument_id: IrId,
        argument: Value,
    ) -> Result<Value, TreeWalkError> {
        if call.first_call_counted {
            call.first_call_counted = false;
        } else {
            self.increment_function_calls();
        }
        self.apply_reused_lambda_value_with_argument_span(
            id,
            span,
            function,
            &call.lambda,
            argument_id,
            call.argument_span,
            argument,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_lambda_value_2(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        first_argument_id: IrId,
        first_argument_span: Span,
        first_argument: Value,
        second_argument_id: IrId,
        second_argument_span: Span,
        second_argument: Value,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "lifetime_cohort_probe")]
        {
            let mut roots = [function, first_argument, second_argument, Value::null()];
            return self.with_lifetime_cohort_shadow_roots(id, span, &mut roots, |eval, slots| {
                eval.apply_lambda_value_2_with_lifetime_shadow(
                    id,
                    span,
                    function_id,
                    function_span,
                    first_argument_id,
                    first_argument_span,
                    second_argument_id,
                    second_argument_span,
                    slots,
                )
            });
        }
        #[cfg(not(feature = "lifetime_cohort_probe"))]
        {
            self.apply_lambda_value_2_unshadowed(
                id,
                span,
                function_id,
                function,
                function_span,
                first_argument_id,
                first_argument_span,
                first_argument,
                second_argument_id,
                second_argument_span,
                second_argument,
            )
        }
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    #[allow(clippy::too_many_arguments)]
    fn apply_lambda_value_2_with_lifetime_shadow(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        first_argument_id: IrId,
        first_argument_span: Span,
        second_argument_id: IrId,
        second_argument_span: Span,
        slots: std::ops::Range<usize>,
    ) -> Result<Value, TreeWalkError> {
        let slot = |offset: usize| {
            slots.start.checked_add(offset).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })
        };
        let function_slot = slot(0)?;
        let first_slot = slot(1)?;
        let second_slot = slot(2)?;
        let partial_slot = slot(3)?;
        let mut function = self
            .current_transient_value_stack_root(function_slot)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        let first_argument = self
            .current_transient_value_stack_root(first_slot)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        let second_argument = self
            .current_transient_value_stack_root(second_slot)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop) {
            function = self.force_demanded_value(function_id, function_span, function)?;
            if !self.set_current_transient_value_stack_root(function_slot, function) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                ));
            }
        }
        let mut partial = self.apply_lambda_value_with_argument_span(
            id,
            span,
            function_id,
            function,
            function_span,
            first_argument_id,
            first_argument_span,
            first_argument,
        )?;
        if !self.set_current_transient_value_stack_root(partial_slot, partial) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                span,
            ));
        }
        if !matches!(partial.tag(), ValueTag::Lambda | ValueTag::Primop) {
            partial = self.force_demanded_value(function_id, function_span, partial)?;
            if !self.set_current_transient_value_stack_root(partial_slot, partial) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                ));
            }
        }
        self.apply_lambda_value_with_argument_span(
            id,
            span,
            function_id,
            partial,
            first_argument_span,
            second_argument_id,
            second_argument_span,
            second_argument,
        )
    }

    #[cfg(not(feature = "lifetime_cohort_probe"))]
    #[allow(clippy::too_many_arguments)]
    fn apply_lambda_value_2_unshadowed(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        first_argument_id: IrId,
        first_argument_span: Span,
        first_argument: Value,
        second_argument_id: IrId,
        second_argument_span: Span,
        second_argument: Value,
    ) -> Result<Value, TreeWalkError> {
        let mut function = function;
        if !matches!(function.tag(), ValueTag::Lambda | ValueTag::Primop) {
            function = self.force_demanded_value(function_id, function_span, function)?;
        }
        let mut partial = self.apply_lambda_value_with_argument_span(
            id,
            span,
            function_id,
            function,
            function_span,
            first_argument_id,
            first_argument_span,
            first_argument,
        )?;
        if !matches!(partial.tag(), ValueTag::Lambda | ValueTag::Primop) {
            partial = self.force_demanded_value(function_id, function_span, partial)?;
        }
        self.apply_lambda_value_with_argument_span(
            id,
            span,
            function_id,
            partial,
            first_argument_span,
            second_argument_id,
            second_argument_span,
            second_argument,
        )
    }

    pub(super) fn apply_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function: Value,
        function_span: Span,
        argument: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let primop = self.heap.clone_primop(function).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: function_id,
                    source,
                },
                function_span,
            )
        })?;
        let Some(builtin) = primop
            .builtin()
            .or_else(|| lookup_builtin_by_symbol(&self.symbols, primop.symbol()))
        else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedPrimOp {
                    id: function_id,
                    symbol: primop.symbol(),
                },
                function_span,
            ));
        };
        let Some(arity) = builtin.first_class_arity() else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedBuiltinAttr {
                    id: function_id,
                    symbol: primop.symbol(),
                },
                function_span,
            ));
        };
        let len = primop.args().len().checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListLengthOverflow {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        let mut args = Vec::new();
        args.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        args.extend_from_slice(primop.args());
        args.push(argument);

        if len < arity {
            self.check_call_depth(id, span)?;
            return self.alloc_tree_walk_primop(
                id,
                span,
                EvalPrimOp::registered_with_args(primop.symbol(), builtin, args),
            );
        }
        if len > arity {
            self.check_call_depth(id, span)?;
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidPrimOpArity {
                    id,
                    symbol: primop.symbol(),
                    expected: arity,
                    actual: len,
                },
                span,
            ));
        }
        let cache_subject =
            self.force_cache_subject_for_first_class_cacheable_impure_call(id, builtin, &args);
        let memoization_decision = cache_subject
            .as_ref()
            .map(|subject| self.record_force_cache_memoization_demand(subject))
            .unwrap_or(MemoizationDecision::Admit);
        let memoization_admitted =
            cache_subject.is_some() && memoization_decision == MemoizationDecision::Admit;
        if memoization_admitted
            && let Some(value) = self.lookup_forced_inline_expression_result(cache_subject.clone())
        {
            return Ok(value);
        }

        self.enter_call(id, span)?;
        if let Err(error) = self.push_active_primop_arg_roots(id, span, &args) {
            self.leave_call();
            return Err(error);
        }
        let impure_trace_cursor = memoization_admitted.then(|| self.impure_input_trace_cursor());
        let thunks_forced_before = self.stats.thunks_forced;
        let result = builtin.apply(self, BuiltinCall::new(id, span, primop.symbol()), &args);
        self.pop_active_primop_arg_roots();
        self.leave_call();
        let value = result?;
        if let Some(subject) = &cache_subject {
            self.record_forced_expression_demand(subject);
        }
        if let Some(cursor) = impure_trace_cursor {
            let impure_trace = self.force_cache_impure_input_trace_segment(cursor);
            let scale_eval_work_by_payload = !impure_trace.trace.is_empty();
            let eval_work_units = self
                .stats
                .thunks_forced
                .saturating_sub(thunks_forced_before);
            let observed_node = self.observe_forced_inline_expression_result_with_eval_work_units(
                cache_subject,
                value,
                impure_trace,
                Some(eval_work_units),
                scale_eval_work_by_payload,
            );
            if let Some(observed_node) = observed_node {
                self.record_enclosing_memo_read(observed_node);
            }
        }
        Ok(value)
    }

    pub(super) fn eval_strict_ternary_primop_direct(
        &mut self,
        call: BuiltinCall,
        primop: StrictTernaryPrimOp,
        first: IrId,
        second: IrId,
        third: IrId,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictTernaryPrimOp::FoldlStrict => {
                self.eval_foldl_strict_primop(call.id, call.span, first, second, third)
            }
            StrictTernaryPrimOp::ReplaceStrings => {
                self.eval_replace_strings_primop(call.id, call.span, first, second, third)
            }
            StrictTernaryPrimOp::Substring => {
                self.eval_substring_primop(call.id, call.span, first, second, third)
            }
        }
    }

    pub(super) fn eval_strict_binary_primop_direct(
        &mut self,
        call: BuiltinCall,
        node: &IrNode,
        primop: StrictBinaryPrimOp,
        first: IrId,
        second: IrId,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            StrictBinaryPrimOp::AppendContext => {
                self.eval_append_context_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::ElemAt => self.eval_elem_at_primop(first, second),
            StrictBinaryPrimOp::LessThan => {
                self.eval_comparison(call.id, node, ComparisonOp::Lt, first, second)
            }
            StrictBinaryPrimOp::HashString => {
                self.eval_hash_string_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::HashFile => {
                self.eval_hash_file_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::Add => {
                self.eval_numeric_binary(call.id, node, BinaryArithmeticOp::Add, first, second)
            }
            StrictBinaryPrimOp::Sub => {
                self.eval_numeric_binary(call.id, node, BinaryArithmeticOp::Sub, first, second)
            }
            StrictBinaryPrimOp::Mul => {
                self.eval_numeric_binary(call.id, node, BinaryArithmeticOp::Mul, first, second)
            }
            StrictBinaryPrimOp::Div => {
                self.eval_numeric_binary(call.id, node, BinaryArithmeticOp::Div, first, second)
            }
            StrictBinaryPrimOp::BitAnd => self.eval_bitwise_primop(BitwiseOp::And, first, second),
            StrictBinaryPrimOp::BitOr => self.eval_bitwise_primop(BitwiseOp::Or, first, second),
            StrictBinaryPrimOp::BitXor => self.eval_bitwise_primop(BitwiseOp::Xor, first, second),
            StrictBinaryPrimOp::CompareVersions => self.eval_compare_versions_primop(first, second),
            StrictBinaryPrimOp::All => {
                self.eval_all_any_primop(AllAnyOp::All, call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::Any => {
                self.eval_all_any_primop(AllAnyOp::Any, call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::Match => self.eval_match_primop(call.id, call.span, first, second),
            StrictBinaryPrimOp::Split => self.eval_split_primop(call.id, call.span, first, second),
            StrictBinaryPrimOp::Filter => {
                self.eval_filter_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::GenList => {
                self.eval_gen_list_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::Map => self.eval_map_primop(call.id, call.span, first, second),
            StrictBinaryPrimOp::Partition => {
                self.eval_partition_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::ConcatMap => {
                self.eval_concat_map_primop(call.id, call.span, first, second)
            }
            StrictBinaryPrimOp::GroupBy => {
                self.eval_group_by_primop(call.id, call.span, first, second)
            }
        }
    }

    pub(super) fn eval_direct_binary_primop_direct(
        &mut self,
        call: BuiltinCall,
        node: &IrNode,
        primop: DirectBinaryPrimOp,
        first: IrId,
        second: IrId,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            DirectBinaryPrimOp::GetAttr => {
                self.eval_get_attr_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::HasAttr => self.eval_has_attr_primop(first, second),
            DirectBinaryPrimOp::UnsafeGetAttrPos => {
                self.eval_unsafe_get_attr_pos_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::RemoveAttrs => {
                self.eval_remove_attrs_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::IntersectAttrs => {
                self.eval_intersect_attrs_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::CatAttrs => {
                self.eval_cat_attrs_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::Elem => self.eval_elem_primop(call.id, node, first, second),
            DirectBinaryPrimOp::ConcatStringsSep => {
                self.eval_concat_strings_sep_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::MapAttrs => {
                self.eval_map_attrs_primop(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::ZipAttrsWith => {
                self.eval_zip_attrs_with_primop(call.id, call.span, first, second)
            }
        }
    }

    pub(super) fn eval_direct_binary_primop_value(
        &mut self,
        call: BuiltinCall,
        primop: DirectBinaryPrimOp,
        first: EvalPrimOpArg,
        second: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        match primop {
            DirectBinaryPrimOp::GetAttr => {
                let key = self.eval_attr_name_primop_value(first)?;
                self.eval_get_attr_primop_value(call.id, call.span, key, second)
            }
            DirectBinaryPrimOp::HasAttr => {
                let key = self.eval_attr_name_primop_value(first)?;
                self.eval_has_attr_primop_value(key, second)
            }
            DirectBinaryPrimOp::UnsafeGetAttrPos => {
                let key = self.eval_attr_name_primop_value(first)?;
                self.eval_unsafe_get_attr_pos_primop_value(call.id, call.span, key, second)
            }
            DirectBinaryPrimOp::RemoveAttrs => {
                self.eval_remove_attrs_primop_value(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::IntersectAttrs => {
                self.eval_intersect_attrs_primop_value(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::CatAttrs => {
                let key = self.eval_attr_name_primop_value(first)?;
                self.eval_cat_attrs_primop_value(call.id, call.span, key, second)
            }
            DirectBinaryPrimOp::Elem => self.eval_elem_primop_value(call.id, first, second),
            DirectBinaryPrimOp::ConcatStringsSep => {
                self.eval_concat_strings_sep_primop_value(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::MapAttrs => {
                self.eval_map_attrs_primop_value(call.id, call.span, first, second)
            }
            DirectBinaryPrimOp::ZipAttrsWith => {
                self.eval_zip_attrs_with_primop_value(call.id, call.span, first, second)
            }
        }
    }

    pub(super) fn eval_attr_name_primop_value(
        &mut self,
        argument: EvalPrimOpArg,
    ) -> Result<Symbol, TreeWalkError> {
        let value = self.force_primop_value(argument, "string", ValueTag::String)?;
        self.intern_string_value(argument.id(), value, argument.span())
    }

    pub(super) fn eval_get_attr_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        key: Symbol,
        attrs: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_primop_value(attrs, "attrs", ValueTag::Attrs)?;
        let selected = {
            let attrs_set = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs.id(),
                        source,
                    },
                    attrs.span(),
                )
            })?;
            attrs_set.get(key)
        };
        selected.ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                span,
            )
        })
    }

    pub(super) fn eval_unsafe_get_attr_pos_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        key: Symbol,
        attrs: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_primop_value(attrs, "attrs", ValueTag::Attrs)?;
        self.eval_unsafe_get_attr_pos_attrs_value(
            id,
            span,
            key,
            attrs.id(),
            attrs.span(),
            attrs_value,
        )
    }

    pub(super) fn eval_has_attr_primop_value(
        &mut self,
        key: Symbol,
        attrs: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_primop_value(attrs, "attrs", ValueTag::Attrs)?;
        let has_attr = {
            let attrs_set = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs.id(),
                        source,
                    },
                    attrs.span(),
                )
            })?;
            attrs_set.contains_key(key)
        };
        Ok(Value::bool(has_attr))
    }

    pub(super) fn eval_remove_attrs_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs: EvalPrimOpArg,
        names: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_primop_value(attrs, "attrs", ValueTag::Attrs)?;
        let names_value = self.force_primop_value(names, "list", ValueTag::List)?;
        let name_values = {
            let names_list = self.heap.get_list_view(names_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: names.id(),
                        source,
                    },
                    names.span(),
                )
            })?;
            Self::clone_list_elements(names.id(), names.span(), names_list)?
        };

        let mut remove = Vec::new();
        remove.try_reserve_exact(name_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: names.id(),
                    len: name_values.len(),
                },
                names.span(),
            )
        })?;
        for value in name_values {
            let value = self.force_uncovered_primop_leaf(names.id(), names.span(), value)?;
            if value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: names.id(),
                        expected: "string",
                        actual: value.tag(),
                    },
                    names.span(),
                ));
            }
            let key = self.intern_string_value(names.id(), value, names.span())?;
            if !remove.contains(&key) {
                remove.push(key);
            }
        }

        let entries = {
            let attrs_set = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs.id(),
                        source,
                    },
                    attrs.span(),
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs_set.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: attrs_set.len(),
                    },
                    span,
                )
            })?;
            for entry in attrs_set.iter_by_symbol() {
                if !remove.contains(&entry.key) {
                    entries.push(entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }
}

mod apply_helpers;
