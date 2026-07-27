//! Sorting builtins (`sort`/`genericClosure`) and fold helpers.

use super::*;

impl TreeWalk {
    pub(super) fn force_sort_elements(
        &mut self,
        list_id: IrId,
        list_span: Span,
        elements: Vec<Value>,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let mut forced = Vec::new();
        forced.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: list_id,
                    len: elements.len(),
                },
                list_span,
            )
        })?;
        for element in elements {
            forced.push(self.force_value(list_id, list_span, element)?);
        }
        Ok(forced)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_sort_libcxx_stable(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        elements: &mut [Value],
    ) -> Result<(), TreeWalkError> {
        const LIBCXX_STABLE_SORT_SWITCH_FOR_POINTERS: usize = 128;

        match elements.len() {
            0 | 1 => Ok(()),
            2 => {
                if self.eval_sort_comparator(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    elements[1],
                    elements[0],
                )? {
                    elements.swap(0, 1);
                }
                Ok(())
            }
            len if len <= LIBCXX_STABLE_SORT_SWITCH_FOR_POINTERS => self.eval_sort_insertion(
                id,
                span,
                comparator_id,
                comparator_span,
                comparator,
                list_id,
                elements,
            ),
            len => {
                let middle = len / 2;
                let left = self.eval_sort_libcxx_stable_move(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &mut elements[..middle],
                )?;
                let right = self.eval_sort_libcxx_stable_move(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &mut elements[middle..],
                )?;
                self.eval_sort_merge(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &left,
                    &right,
                    elements,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_sort_libcxx_stable_move(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        elements: &mut [Value],
    ) -> Result<Vec<Value>, TreeWalkError> {
        match elements.len() {
            0 => Ok(Vec::new()),
            1 => {
                let mut sorted = Self::sort_vec_with_capacity(id, span, 1)?;
                sorted.push(elements[0]);
                Ok(sorted)
            }
            2 => {
                let mut sorted = Self::sort_vec_with_capacity(id, span, 2)?;
                if self.eval_sort_comparator(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    elements[1],
                    elements[0],
                )? {
                    sorted.push(elements[1]);
                    sorted.push(elements[0]);
                } else {
                    sorted.push(elements[0]);
                    sorted.push(elements[1]);
                }
                Ok(sorted)
            }
            len if len <= 8 => self.eval_sort_insertion_moved(
                id,
                span,
                comparator_id,
                comparator_span,
                comparator,
                list_id,
                elements,
            ),
            len => {
                let middle = len / 2;
                self.eval_sort_libcxx_stable(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &mut elements[..middle],
                )?;
                self.eval_sort_libcxx_stable(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &mut elements[middle..],
                )?;
                let mut merged = Vec::new();
                merged.try_reserve_exact(len).map_err(|_| {
                    TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
                })?;
                self.eval_sort_merge_to_vec(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    &elements[..middle],
                    &elements[middle..],
                    &mut merged,
                )?;
                Ok(merged)
            }
        }
    }

    pub(super) fn sort_vec_with_capacity(
        id: IrId,
        span: Span,
        len: usize,
    ) -> Result<Vec<Value>, TreeWalkError> {
        let mut values = Vec::new();
        values.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
        })?;
        Ok(values)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_sort_insertion(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        elements: &mut [Value],
    ) -> Result<(), TreeWalkError> {
        for index in 1..elements.len() {
            let candidate = elements[index];
            let mut insert_at = index;
            while insert_at > 0 {
                let previous = elements[insert_at - 1];
                if !self.eval_sort_comparator(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    candidate,
                    previous,
                )? {
                    break;
                }
                elements[insert_at] = previous;
                insert_at -= 1;
            }
            elements[insert_at] = candidate;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_sort_insertion_moved(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        elements: &[Value],
    ) -> Result<Vec<Value>, TreeWalkError> {
        let mut sorted = Vec::new();
        sorted.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements.iter().copied() {
            let mut insert_at = sorted.len();
            while insert_at > 0 {
                let previous = sorted[insert_at - 1];
                if !self.eval_sort_comparator(
                    id,
                    span,
                    comparator_id,
                    comparator_span,
                    comparator,
                    list_id,
                    element,
                    previous,
                )? {
                    break;
                }
                insert_at -= 1;
            }
            sorted.insert(insert_at, element);
        }
        Ok(sorted)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_sort_merge(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        left: &[Value],
        right: &[Value],
        out: &mut [Value],
    ) -> Result<(), TreeWalkError> {
        let mut merged = Vec::new();
        merged.try_reserve_exact(out.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id, len: out.len() },
                span,
            )
        })?;
        self.eval_sort_merge_to_vec(
            id,
            span,
            comparator_id,
            comparator_span,
            comparator,
            list_id,
            left,
            right,
            &mut merged,
        )?;
        out.copy_from_slice(&merged);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_sort_merge_to_vec(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        left: &[Value],
        right: &[Value],
        out: &mut Vec<Value>,
    ) -> Result<(), TreeWalkError> {
        let mut left_index = 0;
        let mut right_index = 0;
        while left_index < left.len() && right_index < right.len() {
            if self.eval_sort_comparator(
                id,
                span,
                comparator_id,
                comparator_span,
                comparator,
                list_id,
                right[right_index],
                left[left_index],
            )? {
                out.push(right[right_index]);
                right_index += 1;
            } else {
                out.push(left[left_index]);
                left_index += 1;
            }
        }
        out.extend_from_slice(&left[left_index..]);
        out.extend_from_slice(&right[right_index..]);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_sort_comparator(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let step = self.apply_lambda_value(
            id,
            span,
            comparator_id,
            comparator,
            comparator_span,
            list_id,
            left,
        )?;
        let result = self.apply_lambda_value(
            id,
            span,
            comparator_id,
            step,
            comparator_span,
            list_id,
            right,
        )?;
        let result = self.force_value(comparator_id, comparator_span, result)?;
        let actual = result.tag();
        let ValueTag::Bool = actual else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: comparator_id,
                    expected: "bool",
                    actual,
                },
                comparator_span,
            ));
        };
        self.expect_bool(comparator_id, result, comparator_span)
    }

    pub(super) fn eval_foldl_strict_primop(
        &mut self,
        id: IrId,
        span: Span,
        op_id: IrId,
        initial_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let op_span = self.node(op_id)?.span;
        let op = self.eval_node(op_id)?;
        let op = self.force_callable_value(op_id, op_span, op)?;

        // Fused list generation (tier-2 landing 3): a direct `genList` list
        // argument is a pure local temporary here, so the fold can run as an
        // observationally identical index loop that never materializes the
        // list — and, with an engine installed, can fold generated elements
        // entirely in native code. See `fold_genlist` for the argument.
        if self.tier1_engine.is_some()
            && let Some(candidate) = self.foldl_genlist_fusion_candidate(list_id)
        {
            return self.eval_foldl_strict_over_genlist(
                id, span, op_id, op_span, op, initial_id, list_id, candidate,
            );
        }

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list_id,
                    expected: "list",
                    actual: list_value.tag(),
                },
                list_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list_view(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            Self::clone_list_view_elements(list_id, list_span, list)?
        };
        #[cfg(feature = "lifetime_cohort_probe")]
        {
            let mut roots = Vec::new();
            let root_len = elements.len().checked_add(3).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
            roots.try_reserve_exact(root_len).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed {
                        id,
                        roots: root_len,
                    },
                    span,
                )
            })?;
            roots.push(op);
            roots.push(list_value);
            roots.push(Value::null());
            roots.extend_from_slice(&elements);
            return self.with_lifetime_cohort_shadow_roots(id, span, &mut roots, |eval, slots| {
                eval.eval_foldl_strict_primop_shadowed(
                    id,
                    span,
                    op_id,
                    op_span,
                    op,
                    initial_id,
                    list_id,
                    list_value,
                    &elements,
                    slots.start.checked_add(2).ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?,
                )
            });
        }
        #[cfg(not(feature = "lifetime_cohort_probe"))]
        {
            self.eval_foldl_strict_primop_unshadowed(
                id, span, op_id, op_span, op, initial_id, list_id, list_value, &elements,
            )
        }
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    #[allow(clippy::too_many_arguments)]
    fn eval_foldl_strict_primop_shadowed(
        &mut self,
        id: IrId,
        span: Span,
        op_id: IrId,
        op_span: Span,
        op: Value,
        initial_id: IrId,
        list_id: IrId,
        list_value: Value,
        elements: &[Value],
        accumulator_slot: usize,
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "option_map_fold_probe")]
        let option_map_fold_plan = self.observe_option_map_fold(id, op, elements.len());
        #[cfg(feature = "final_config_trie_canary")]
        if let Some(value) =
            self.try_eval_final_config_trie_fold_with_native_shadow(id, op, list_value, elements)?
        {
            return Ok(value);
        }

        let initial_span = self.node(initial_id)?.span;
        let mut accumulator = self.alloc_thunk_for_node(initial_id, initial_id, initial_span)?;
        if !self.set_current_transient_value_stack_root(accumulator_slot, accumulator) {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                span,
            ));
        }
        if elements.is_empty() {
            return self.eval_lazy_foldl_initial_value(initial_id, initial_span, accumulator);
        }
        // Tier-2 fold seam: consult the engine at most twice — before the
        // first element, and once more after one interpreted iteration has
        // forced the operator's callee bindings (see `Tier2FoldHook`). A
        // native run advances the loop past its consumed prefix; everything
        // else proceeds through the interpreted steps byte-for-byte unchanged.
        let mut index = 0usize;
        let mut fold_consults = 0u32;
        while index < elements.len() {
            if fold_consults < 2 && self.tier1_engine.is_some() {
                fold_consults += 1;
                if let Some((consumed, folded)) =
                    self.try_tier2_foldl(id, span, op, accumulator, &elements[index..])
                {
                    accumulator = folded;
                    if !self.set_current_transient_value_stack_root(accumulator_slot, accumulator) {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        ));
                    }
                    index += consumed;
                    continue;
                }
            }
            let element = elements[index];
            let step =
                self.apply_lambda_value(id, span, op_id, op, op_span, initial_id, accumulator)?;
            let result =
                self.apply_lambda_value(id, span, op_id, step, op_span, list_id, element)?;
            accumulator = self.force_value(op_id, op_span, result)?;
            if !self.set_current_transient_value_stack_root(accumulator_slot, accumulator) {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                ));
            }
            index += 1;
        }

        #[cfg(feature = "option_map_fold_probe")]
        self.finish_option_map_fold_probe(option_map_fold_plan, elements);
        Ok(accumulator)
    }

    #[cfg(not(feature = "lifetime_cohort_probe"))]
    #[allow(clippy::too_many_arguments)]
    fn eval_foldl_strict_primop_unshadowed(
        &mut self,
        id: IrId,
        span: Span,
        op_id: IrId,
        op_span: Span,
        op: Value,
        initial_id: IrId,
        list_id: IrId,
        list_value: Value,
        elements: &[Value],
    ) -> Result<Value, TreeWalkError> {
        #[cfg(feature = "option_map_fold_probe")]
        let option_map_fold_plan = self.observe_option_map_fold(id, op, elements.len());
        #[cfg(feature = "final_config_trie_canary")]
        if let Some(value) =
            self.try_eval_final_config_trie_fold_with_native_shadow(id, op, list_value, elements)?
        {
            return Ok(value);
        }

        let initial_span = self.node(initial_id)?.span;
        let mut accumulator = self.alloc_thunk_for_node(initial_id, initial_id, initial_span)?;
        if elements.is_empty() {
            return self.eval_lazy_foldl_initial_value(initial_id, initial_span, accumulator);
        }
        let mut index = 0usize;
        let mut fold_consults = 0u32;
        while index < elements.len() {
            if fold_consults < 2 && self.tier1_engine.is_some() {
                fold_consults += 1;
                if let Some((consumed, folded)) =
                    self.try_tier2_foldl(id, span, op, accumulator, &elements[index..])
                {
                    accumulator = folded;
                    index += consumed;
                    continue;
                }
            }
            let element = elements[index];
            let step =
                self.apply_lambda_value(id, span, op_id, op, op_span, initial_id, accumulator)?;
            let result =
                self.apply_lambda_value(id, span, op_id, step, op_span, list_id, element)?;
            accumulator = self.force_value(op_id, op_span, result)?;
            index += 1;
        }
        #[cfg(feature = "option_map_fold_probe")]
        self.finish_option_map_fold_probe(option_map_fold_plan, elements);
        Ok(accumulator)
    }

    #[cfg(feature = "final_config_trie_canary")]
    fn try_eval_final_config_trie_fold_with_native_shadow(
        &mut self,
        id: IrId,
        op: Value,
        list_value: Value,
        elements: &[Value],
    ) -> Result<Option<Value>, TreeWalkError> {
        #[cfg(feature = "collection_poll_probe")]
        if self.native_continuation_shadow_enabled() {
            let mut roots = Vec::new();
            let root_len = match elements.len().checked_add(2) {
                Some(root_len) => root_len,
                None => return self.try_eval_final_config_trie_fold(id, op, elements),
            };
            if roots.try_reserve_exact(root_len).is_err() {
                return self.try_eval_final_config_trie_fold(id, op, elements);
            }
            roots.push(op);
            roots.push(list_value);
            roots.extend_from_slice(elements);
            return self.with_nonmoving_native_continuation(
                super::native_continuation_shadow::NativeContinuationKind::FoldCanary,
                id,
                &roots,
                None,
                |eval| eval.try_eval_final_config_trie_fold(id, op, elements),
            );
        }
        self.try_eval_final_config_trie_fold(id, op, elements)
    }

    pub(super) fn eval_generic_closure_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let value = self.force_value(argument, argument_span, value)?;
        let value = self.force_lazy_foldl_initial_value(argument, argument_span, value)?;
        if value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "attrs",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }

        let start_set =
            self.required_attr_value_by_name(argument, value, START_SET_ATTR, argument_span)?;
        let start_set = self.force_value(argument, argument_span, start_set)?;
        if start_set.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "list",
                    actual: start_set.tag(),
                },
                argument_span,
            ));
        }
        let start_items = {
            let start_set = self.heap.get_list_view(start_set).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            Self::clone_list_view_elements(argument, argument_span, start_set)?
        };

        if start_items.is_empty() {
            return self.alloc_tree_walk_list(id, span, NixList::new(Vec::new()));
        }

        let operator =
            self.required_attr_value_by_name(argument, value, OPERATOR_ATTR, argument_span)?;
        let operator = self.force_callable_value(argument, argument_span, operator)?;

        let mut work_items = start_items;
        let mut items = Vec::new();
        let mut keys = Vec::new();

        let mut cursor = 0usize;
        while cursor < work_items.len() {
            let item = work_items[cursor];
            cursor += 1;
            let Some(item) = self.accept_generic_closure_item(
                id,
                argument,
                argument_span,
                item,
                &mut items,
                &mut keys,
            )?
            else {
                continue;
            };
            let produced = self.apply_lambda_value(
                id,
                span,
                argument,
                operator,
                argument_span,
                argument,
                item,
            )?;
            let produced = self.force_value(argument, argument_span, produced)?;
            if produced.tag() != ValueTag::List {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "list",
                        actual: produced.tag(),
                    },
                    argument_span,
                ));
            }
            let produced_items = {
                let produced = self.heap.get_list_view(produced).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                Self::clone_list_view_elements(argument, argument_span, produced)?
            };
            self.enqueue_generic_closure_generated_items(
                id,
                argument,
                argument_span,
                produced_items,
                &mut work_items,
            )?;
        }

        self.alloc_tree_walk_list(id, span, NixList::new(items))
    }

    pub(super) fn accept_generic_closure_item(
        &mut self,
        id: IrId,
        item_id: IrId,
        item_span: Span,
        candidate: Value,
        items: &mut Vec<Value>,
        keys: &mut Vec<Value>,
    ) -> Result<Option<Value>, TreeWalkError> {
        let item = self.force_value(item_id, item_span, candidate)?;
        let item = self.force_lazy_foldl_initial_value(item_id, item_span, item)?;
        if item.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: item_id,
                    expected: "attrs",
                    actual: item.tag(),
                },
                item_span,
            ));
        }
        let key = self.required_attr_value_by_name(item_id, item, KEY_ATTR, item_span)?;
        let key = self.force_value(item_id, item_span, key)?;
        if self.generic_closure_key_seen(id, key, keys)? {
            return Ok(None);
        }

        let len = items.len().checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListLengthOverflow {
                    id,
                    len: usize::MAX,
                },
                item_span,
            )
        })?;
        items.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id, len },
                item_span,
            )
        })?;
        keys.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id, len },
                item_span,
            )
        })?;
        items.push(item);
        keys.push(key);
        Ok(Some(item))
    }

    pub(super) fn enqueue_generic_closure_generated_items(
        &mut self,
        id: IrId,
        item_id: IrId,
        item_span: Span,
        candidates: Vec<Value>,
        work_items: &mut Vec<Value>,
    ) -> Result<(), TreeWalkError> {
        for candidate in candidates {
            let item = self.force_value(item_id, item_span, candidate)?;
            let len = work_items.len().checked_add(1).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListLengthOverflow {
                        id,
                        len: usize::MAX,
                    },
                    item_span,
                )
            })?;
            work_items.try_reserve_exact(1).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed { id, len },
                    item_span,
                )
            })?;
            work_items.push(item);
        }
        Ok(())
    }

    pub(super) fn generic_closure_key_seen(
        &mut self,
        id: IrId,
        key: Value,
        keys: &[Value],
    ) -> Result<bool, TreeWalkError> {
        let node = *self.node(id)?;
        for existing in keys {
            if self.generic_closure_keys_equal(id, &node, key, *existing)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn generic_closure_keys_equal(
        &mut self,
        id: IrId,
        node: &IrNode,
        left: Value,
        right: Value,
    ) -> Result<bool, TreeWalkError> {
        let mut guard = EqualityPairGuard::default();
        let left_is_less =
            self.compare_values_for_ordering(id, node, ComparisonOp::Lt, left, right, &mut guard)?;
        let mut guard = EqualityPairGuard::default();
        let right_is_less =
            self.compare_values_for_ordering(id, node, ComparisonOp::Lt, right, left, &mut guard)?;
        Ok(!left_is_less && !right_is_less)
    }

    pub(super) fn eval_function_args_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let entries = match value.tag() {
            ValueTag::Lambda => {
                let lambda = self.heap.clone_lambda(value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                self.with_current_module(lambda.module(), |eval| {
                    eval.function_args_entries(id, span, lambda.pattern())
                })?
            }
            ValueTag::Primop => Vec::new(),
            actual => {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "function",
                        actual,
                    },
                    argument_span,
                ));
            }
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn function_args_entries(
        &self,
        id: IrId,
        span: Span,
        pattern: IrId,
    ) -> Result<Vec<AttrEntry>, TreeWalkError> {
        let pattern_node = *self.node(pattern)?;
        match pattern_node.kind {
            IrKind::Formal => Ok(Vec::new()),
            IrKind::FormalSet => {
                let IrData::FormalSet { formals, .. } = pattern_node.data else {
                    return Err(self.invalid_payload(pattern, &pattern_node, "formal-set payload"));
                };
                let formal_slice =
                    self.current_ir()
                        .arena
                        .child_slice(formals)
                        .ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::InvalidChildSlice {
                                    id: pattern,
                                    slice: formals,
                                },
                                pattern_node.span,
                            )
                        })?;
                let mut entries = Vec::new();
                entries.try_reserve_exact(formal_slice.len()).map_err(|_| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::ListAllocationFailed {
                            id,
                            len: formal_slice.len(),
                        },
                        span,
                    )
                })?;
                for formal in formal_slice {
                    let formal_node = *self.node(*formal)?;
                    let IrData::Formal { name, default } = formal_node.data else {
                        return Err(self.invalid_payload(*formal, &formal_node, "formal payload"));
                    };
                    if self.symbols.resolve(name).is_none() {
                        return Err(TreeWalkError::new(
                            TreeWalkErrorKind::InvalidSymbol {
                                id: *formal,
                                symbol: name,
                            },
                            formal_node.span,
                        ));
                    }
                    entries.push(AttrEntry::with_position(
                        name,
                        Value::bool(default.is_some()),
                        AttrPosition::new(self.current_module.as_u32(), formal_node.span),
                    ));
                }
                Ok(entries)
            }
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::UnsupportedLambdaPattern { id, pattern, kind },
                pattern_node.span,
            )),
        }
    }
}
