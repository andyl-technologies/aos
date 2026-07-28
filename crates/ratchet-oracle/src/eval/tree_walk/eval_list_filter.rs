//! List builtins: `all`/`any`, `filter`, `zipLists`, and mapping.

use super::*;

mod all_any;

impl TreeWalk {
    pub(super) fn alloc_dynamic_attrs_result_with_order_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        attrs: FlatAttrs,
    ) -> Result<Value, TreeWalkError> {
        let order_parity_result =
            collect_checked_lexicographic_keys(AttrOrderTarget::Flat(&attrs), &self.symbols)
                .map(|_| ());
        let len = attrs.len();
        let result = self.alloc_flat_attrs_with_repr_telemetry(
            id,
            span,
            0,
            attrs,
            AttrSetConstruction::Dynamic { len },
        )?;
        self.record_attr_order_parity_telemetry(id, span, order_parity_result);
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_mapped_attrs(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        attrs_id: IrId,
        entries: Vec<AttrEntry>,
    ) -> Result<Value, TreeWalkError> {
        let len = entries.len();
        let mut mapped = Vec::new();
        mapped.try_reserve_exact(len).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: len },
                },
                span,
            )
        })?;
        if self.options.eval_stats_dump() {
            super::force_shape_census::record_synthetic_apply_origin("mapAttrs", len);
        }
        // Keep the function, one slot per entry, and one name scratch slot
        // registered for the whole loop. Each entry slot starts with its
        // source value and is replaced by its mapped thunk after capture. The
        // former per-name helper rebuilt and copied an O(len) root vector on
        // every iteration, making mapAttrs construction O(len²) even though
        // every live value already has a stable slot in this batch.
        let entry_start = 1usize;
        let scratch_slot = entry_start.checked_add(len).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                span,
            )
        })?;
        let root_count = scratch_slot.checked_add(1).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                span,
            )
        })?;
        let mut roots = Vec::new();
        roots.try_reserve_exact(root_count).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: root_count,
                },
                span,
            )
        })?;
        roots.push(function);
        roots.extend(entries.iter().map(|entry| entry.value));
        roots.resize(root_count, Value::null());

        let attrs_span = self.node(attrs_id)?.span;
        self.with_indexed_transient_value_stack_roots(id, span, &mut roots, |eval, slots| {
            for (entry_index, entry) in entries.iter().enumerate() {
                let name = eval.with_gc_stress_primop_arg_root_admission(|eval| {
                    eval.alloc_symbol_string(id, span, entry.key)
                })?;
                let name_slot = slots.start.checked_add(scratch_slot).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    )
                })?;
                if !eval.set_current_transient_value_stack_root(name_slot, name) {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    ));
                }

                // Reload all operands after the string allocation: a
                // moving stress collection may have rewritten their root
                // slots.
                let function = eval
                    .current_transient_value_stack_root(slots.start)
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?;
                let source_slot = slots
                    .start
                    .checked_add(entry_start)
                    .and_then(|slot| slot.checked_add(entry_index))
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?;
                let entry_value = eval
                    .current_transient_value_stack_root(source_slot)
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?;
                let name = eval
                    .current_transient_value_stack_root(name_slot)
                    .ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                            span,
                        )
                    })?;
                let value = eval.alloc_apply2_thunk(
                    id,
                    span,
                    function_id,
                    function_span,
                    function,
                    id,
                    span,
                    name,
                    attrs_id,
                    attrs_span,
                    entry_value,
                )?;
                if !eval.set_current_transient_value_stack_root(source_slot, value) {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                        span,
                    ));
                }
            }
            Ok(())
        })?;
        mapped.extend(
            entries
                .iter()
                .zip(roots[entry_start..scratch_slot].iter().copied())
                .map(|(entry, value)| AttrEntry::new(entry.key, value)),
        );

        let attrs = FlatAttrs::new(mapped, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_zip_attrs_with_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let function_span = self.node(function_id)?.span;
        let function = self.eval_uncovered_primop_child(function_id)?;
        let function = self.force_zip_attrs_with_function(function_id, function_span, function)?;

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_uncovered_primop_child(list_id)?;
        let list_value = self.force_uncovered_primop_leaf(list_id, list_span, list_value)?;
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
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: list_id,
                        len: list.len(),
                    },
                    list_span,
                )
            })?;
            elements.extend(list.iter());
            elements
        };

        self.alloc_zipped_attrs_with(
            id,
            span,
            function_id,
            function_span,
            function,
            list_id,
            list_span,
            elements,
        )
    }

    pub(super) fn eval_zip_attrs_with_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let function_value =
            self.force_zip_attrs_with_function(function.id(), function.span(), function.value())?;

        let list_value = self.force_uncovered_primop_leaf(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list_view(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };

        self.alloc_zipped_attrs_with(
            id,
            span,
            function.id(),
            function.span(),
            function_value,
            list.id(),
            list.span(),
            elements,
        )
    }

    pub(super) fn force_zip_attrs_with_function(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        self.force_callable_value(id, span, value)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_zipped_attrs_with(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        mut function: Value,
        list_id: IrId,
        list_span: Span,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut groups: Vec<(Symbol, Vec<Value>)> = Vec::new();
        for element in elements {
            let element = self.force_uncovered_primop_leaf(list_id, list_span, element)?;
            let element = self.force_lazy_foldl_initial_value(list_id, list_span, element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: list_id,
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    list_span,
                ));
            }

            let attrs = self.heap.get_attrs_view(element).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            for entry in attrs.iter_by_symbol() {
                if let Some((_, values)) = groups.iter_mut().find(|(key, _)| *key == entry.key) {
                    let len = values.len().checked_add(1).ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::List {
                                id,
                                source: NixListError::LengthOverflow {
                                    left: values.len(),
                                    right: 1,
                                },
                            },
                            span,
                        )
                    })?;
                    values.try_reserve_exact(1).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed { id, len },
                            span,
                        )
                    })?;
                    values.push(entry.value);
                } else {
                    let len = groups.len().checked_add(1).ok_or_else(|| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListLengthOverflow {
                                id,
                                len: usize::MAX,
                            },
                            span,
                        )
                    })?;
                    groups.try_reserve_exact(1).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::Attr {
                                id,
                                source: AttrError::AllocationFailed { entries: len },
                            },
                            span,
                        )
                    })?;
                    let mut values = Vec::new();
                    values.try_reserve_exact(1).map_err(|_| {
                        TreeWalkError::new(
                            TreeWalkErrorKind::ListAllocationFailed { id, len: 1 },
                            span,
                        )
                    })?;
                    values.push(entry.value);
                    groups.push((entry.key, values));
                }
            }
        }

        let mut entries = Vec::new();
        entries.try_reserve_exact(groups.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: groups.len(),
                    },
                },
                span,
            )
        })?;
        if self.options.eval_stats_dump() {
            super::force_shape_census::record_synthetic_apply_origin("zipAttrsWith", groups.len());
        }
        for group_index in 0..groups.len() {
            let key = groups[group_index].0;
            let values = std::mem::take(&mut groups[group_index].1);
            let values = self.alloc_zipped_attrs_with_values_list(
                id,
                span,
                &mut function,
                &mut entries,
                &mut groups,
                values,
            )?;
            let mut values = values;
            let name = self.alloc_zipped_attrs_with_symbol_name(
                id,
                span,
                &mut function,
                &mut entries,
                &mut groups,
                &mut values,
                key,
            )?;
            let value = self.alloc_apply2_thunk(
                id,
                span,
                function_id,
                function_span,
                function,
                id,
                span,
                name,
                list_id,
                self.node(list_id)?.span,
                values,
            )?;
            entries.push(AttrEntry::new(key, value));
        }

        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    fn alloc_zipped_attrs_with_values_list(
        &mut self,
        id: IrId,
        span: Span,
        function: &mut Value,
        entries: &mut [AttrEntry],
        groups: &mut [(Symbol, Vec<Value>)],
        values: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let grouped_root_count = groups.iter().try_fold(0usize, |count, (_, values)| {
            count.checked_add(values.len()).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed { id, len: count },
                    span,
                )
            })
        })?;
        let root_count = 1usize
            .checked_add(entries.len())
            .and_then(|count| count.checked_add(grouped_root_count))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: entries.len(),
                    },
                    span,
                )
            })?;
        let mut roots = Vec::new();
        roots.try_reserve_exact(root_count).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: root_count,
                },
                span,
            )
        })?;
        roots.push(*function);
        roots.extend(entries.iter().map(|entry| entry.value));
        for (_, values) in groups.iter() {
            roots.extend(values.iter().copied());
        }

        let value = self.with_transient_value_stack_roots(id, span, &mut roots, |eval| {
            eval.alloc_tree_walk_list(id, span, NixList::new(values))
        })?;
        if let Some(root) = roots.first().copied() {
            *function = root;
        }
        for (entry, root) in entries.iter_mut().zip(roots.iter().copied().skip(1)) {
            entry.value = root;
        }
        let mut root_index = 1usize.saturating_add(entries.len());
        for (_, values) in groups.iter_mut() {
            for value in values.iter_mut() {
                if let Some(root) = roots.get(root_index).copied() {
                    *value = root;
                }
                root_index = root_index.saturating_add(1);
            }
        }
        Ok(value)
    }

    fn alloc_zipped_attrs_with_symbol_name(
        &mut self,
        id: IrId,
        span: Span,
        function: &mut Value,
        entries: &mut [AttrEntry],
        groups: &mut [(Symbol, Vec<Value>)],
        values: &mut Value,
        key: Symbol,
    ) -> Result<Value, TreeWalkError> {
        let grouped_root_count = groups.iter().try_fold(0usize, |count, (_, values)| {
            count.checked_add(values.len()).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed { id, len: count },
                    span,
                )
            })
        })?;
        let root_count = 2usize
            .checked_add(entries.len())
            .and_then(|count| count.checked_add(grouped_root_count))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: entries.len(),
                    },
                    span,
                )
            })?;
        let mut roots = Vec::new();
        roots.try_reserve_exact(root_count).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: root_count,
                },
                span,
            )
        })?;
        roots.push(*function);
        roots.extend(entries.iter().map(|entry| entry.value));
        for (_, values) in groups.iter() {
            roots.extend(values.iter().copied());
        }
        roots.push(*values);

        let name = self.with_transient_value_stack_roots(id, span, &mut roots, |eval| {
            eval.alloc_symbol_string(id, span, key)
        })?;
        if let Some(root) = roots.first().copied() {
            *function = root;
        }
        for (entry, root) in entries.iter_mut().zip(roots.iter().copied().skip(1)) {
            entry.value = root;
        }
        let mut root_index = 1usize.saturating_add(entries.len());
        for (_, group_values) in groups.iter_mut() {
            for value in group_values.iter_mut() {
                if let Some(root) = roots.get(root_index).copied() {
                    *value = root;
                }
                root_index = root_index.saturating_add(1);
            }
        }
        if let Some(root) = roots.get(root_index).copied() {
            *values = root;
        }
        Ok(name)
    }

    pub(super) fn eval_cat_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        name_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_uncovered_primop_child(list_id)?;
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
            Self::clone_list_elements(list_id, list_span, list)?
        };
        let mut values = Vec::new();
        values.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            let element = self.force_uncovered_primop_leaf(list_id, list_span, element)?;
            let element = self.force_lazy_foldl_initial_value(list_id, list_span, element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: list_id,
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    list_span,
                ));
            }
            let selected = {
                let attrs = self.heap.get_attrs_view(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: list_id,
                            source,
                        },
                        list_span,
                    )
                })?;
                attrs.get(key)
            };
            if let Some(value) = selected {
                values.push(value);
            }
        }
        self.alloc_tree_walk_list(id, span, NixList::new(values))
    }

    pub(super) fn eval_filter_primop(
        &mut self,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_uncovered_primop_child(list_id)?;
        let list_value = self.force_uncovered_primop_leaf(list_id, list_span, list_value)?;
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
            Self::clone_list_elements(list_id, list_span, list)?
        };
        if elements.is_empty() {
            return self.alloc_tree_walk_list(id, span, NixList::new(Vec::new()));
        }

        let predicate_span = self.node(predicate_id)?.span;
        let predicate = self.eval_uncovered_primop_child(predicate_id)?;
        let predicate = self.force_callable_value(predicate_id, predicate_span, predicate)?;

        self.eval_filter_elements(
            id,
            span,
            predicate_id,
            predicate_span,
            predicate,
            list_id,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_filter_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        predicate: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let list_value = self.force_uncovered_primop_leaf(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list_view(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };
        if elements.is_empty() {
            return self.alloc_tree_walk_list(id, span, NixList::new(Vec::new()));
        }

        let predicate_value =
            self.force_callable_value(predicate.id(), predicate.span(), predicate.value())?;

        self.eval_filter_elements(
            id,
            span,
            predicate.id(),
            predicate.span(),
            predicate_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_filter_elements(
        &mut self,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        predicate_span: Span,
        predicate: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut selected = Vec::new();
        selected.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        // Tier-2 filter seam: consult the engine at most twice — before the
        // first element, and once more after one interpreted iteration has
        // forced the predicate's callee bindings (see `Tier2FilterHook`). A
        // native run advances the loop past its decided prefix, appending
        // the kept subsequence; everything else proceeds through the
        // interpreted steps byte-for-byte unchanged.
        let mut index = 0usize;
        let mut filter_consults = 0u32;
        let mut reused_lambda = self.prepare_reused_lambda_call(
            predicate_id,
            predicate,
            predicate_span,
            list_id,
            !elements.is_empty(),
        )?;
        while index < elements.len() {
            if filter_consults < 2 && self.tier1_engine.is_some() {
                filter_consults += 1;
                if let Some((consumed, kept)) =
                    self.try_tier2_filter(id, span, predicate, &elements[index..])
                {
                    selected.extend(kept);
                    index += consumed;
                    continue;
                }
            }
            let element = elements[index];
            let result = match reused_lambda.as_mut() {
                Some(call) => self.apply_prepared_reused_lambda_call(
                    id, span, predicate, call, list_id, element,
                )?,
                None => self.apply_lambda_value(
                    id,
                    span,
                    predicate_id,
                    predicate,
                    predicate_span,
                    list_id,
                    element,
                )?,
            };
            let result = self.force_uncovered_primop_leaf(predicate_id, predicate_span, result)?;
            let actual = result.tag();
            let ValueTag::Bool = actual else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: predicate_id,
                        expected: "bool",
                        actual,
                    },
                    predicate_span,
                ));
            };
            if self.expect_bool(predicate_id, result, predicate_span)? {
                selected.push(element);
            }
            index += 1;
        }

        self.alloc_tree_walk_list(id, span, NixList::new(selected))
    }

    pub(super) fn eval_map_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let list_value = self.with_nonmoving_native_continuation(
            super::native_continuation_shadow::NativeContinuationKind::MapListArgumentEval,
            list_id,
            &[],
            Some(super::native_continuation_shadow::NativeContinuationEdge::EvalNode),
            |eval| eval.eval_node(list_id),
        )?;
        let list_value = self.force_uncovered_primop_leaf(list_id, list_span, list_value)?;
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
            Self::clone_list_elements(list_id, list_span, list)?
        };
        if elements.is_empty() {
            return self.alloc_tree_walk_list(id, span, NixList::new(Vec::new()));
        }

        let function_span = self.node(function_id)?.span;
        let function = self.eval_uncovered_primop_child(function_id)?;
        let function = self.force_callable_value(function_id, function_span, function)?;

        self.alloc_mapped_list(
            id,
            span,
            function_id,
            function_span,
            function,
            list_id,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_map_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let list_value = self.force_uncovered_primop_leaf(list.id(), list.span(), list.value())?;
        if list_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: list_value.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list_view(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };
        if elements.is_empty() {
            return self.alloc_tree_walk_list(id, span, NixList::new(Vec::new()));
        }

        let function_value =
            self.force_callable_value(function.id(), function.span(), function.value())?;

        self.alloc_mapped_list(
            id,
            span,
            function.id(),
            function.span(),
            function_value,
            list.id(),
            elements,
        )
    }
}
