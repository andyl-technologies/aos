//! List builtins: `all`/`any`, `filter`, `zipLists`, and mapping.

use super::*;

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
        mut function: Value,
        attrs_id: IrId,
        mut entries: Vec<AttrEntry>,
    ) -> Result<Value, TreeWalkError> {
        let mut mapped = Vec::new();
        mapped.try_reserve_exact(entries.len()).map_err(|_| {
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
        for entry_index in 0..entries.len() {
            let key = entries[entry_index].key;
            let name = self.alloc_mapped_attr_name(
                id,
                span,
                &mut function,
                &mut mapped,
                &mut entries[entry_index..],
                key,
            )?;
            let entry_value = entries[entry_index].value;
            let value = self.alloc_apply2_thunk(
                id,
                span,
                function_id,
                function_span,
                function,
                id,
                span,
                name,
                attrs_id,
                self.node(attrs_id)?.span,
                entry_value,
            )?;
            mapped.push(AttrEntry::new(key, value));
        }

        let attrs = FlatAttrs::new(mapped, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    fn alloc_mapped_attr_name(
        &mut self,
        id: IrId,
        span: Span,
        function: &mut Value,
        mapped: &mut [AttrEntry],
        remaining_entries: &mut [AttrEntry],
        key: Symbol,
    ) -> Result<Value, TreeWalkError> {
        let root_count = 1usize
            .checked_add(mapped.len())
            .and_then(|count| count.checked_add(remaining_entries.len()))
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: mapped.len(),
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
        roots.extend(mapped.iter().map(|entry| entry.value));
        roots.extend(remaining_entries.iter().map(|entry| entry.value));

        let name = self.with_transient_value_stack_roots(id, span, &mut roots, |eval| {
            eval.with_gc_stress_primop_arg_root_admission(|eval| {
                eval.alloc_symbol_string(id, span, key)
            })
        })?;
        if let Some(root) = roots.first().copied() {
            *function = root;
        }
        for (entry, root) in mapped.iter_mut().zip(roots.iter().copied().skip(1)) {
            entry.value = root;
        }
        let remaining_start = 1usize.saturating_add(mapped.len());
        for (entry, root) in remaining_entries
            .iter_mut()
            .zip(roots.iter().copied().skip(remaining_start))
        {
            entry.value = root;
        }
        Ok(name)
    }

    pub(super) fn eval_zip_attrs_with_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let function_span = self.node(function_id)?.span;
        let function = self.eval_node(function_id)?;
        let function = self.force_zip_attrs_with_function(function_id, function_span, function)?;

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
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
            let list = self.heap.get_list(list_value).map_err(|source| {
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

        let list_value = self.force_value(list.id(), list.span(), list.value())?;
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
            let list_value = self.heap.get_list(list_value).map_err(|source| {
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
            let element = self.force_value(list_id, list_span, element)?;
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

            let attrs = self.heap.get_attrs(element).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list_id,
                        source,
                    },
                    list_span,
                )
            })?;
            for entry in attrs.entries_by_symbol() {
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
            let list = self.heap.get_list(list_value).map_err(|source| {
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
            elements.extend_from_slice(list.as_slice());
            elements
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
            let element = self.force_value(list_id, list_span, element)?;
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
                let attrs = self.heap.get_attrs(element).map_err(|source| {
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

    pub(super) fn eval_all_any_primop(
        &mut self,
        op: AllAnyOp,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let predicate_span = self.node(predicate_id)?.span;
        let predicate = self.eval_node(predicate_id)?;
        let predicate = self.force_callable_value(predicate_id, predicate_span, predicate)?;

        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
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
            let list = self.heap.get_list(list_value).map_err(|source| {
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
            elements.extend_from_slice(list.as_slice());
            elements
        };

        self.eval_all_any_elements(
            op,
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
    pub(super) fn eval_all_any_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        op: AllAnyOp,
        predicate: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let predicate_value =
            self.force_callable_value(predicate.id(), predicate.span(), predicate.value())?;

        let list_value = self.force_value(list.id(), list.span(), list.value())?;
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
            let list_value = self.heap.get_list(list_value).map_err(|source| {
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

        self.eval_all_any_elements(
            op,
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
    pub(super) fn eval_all_any_elements(
        &mut self,
        op: AllAnyOp,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        predicate_span: Span,
        predicate: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        for element in elements {
            let result = self.apply_lambda_value(
                id,
                span,
                predicate_id,
                predicate,
                predicate_span,
                list_id,
                element,
            )?;
            let result = self.force_value(predicate_id, predicate_span, result)?;
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
            let result = self.expect_bool(predicate_id, result, predicate_span)?;
            if op.short_circuits(result) {
                return Ok(Value::bool(op.short_circuit_value()));
            }
        }

        Ok(Value::bool(op.empty_or_exhausted_value()))
    }

    pub(super) fn eval_filter_primop(
        &mut self,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let list_span = self.node(list_id)?.span;
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
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
            let list = self.heap.get_list(list_value).map_err(|source| {
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
        let predicate = self.eval_node(predicate_id)?;
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
        let list_value = self.force_value(list.id(), list.span(), list.value())?;
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
            let list_value = self.heap.get_list(list_value).map_err(|source| {
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
            let result = self.apply_lambda_value(
                id,
                span,
                predicate_id,
                predicate,
                predicate_span,
                list_id,
                element,
            )?;
            let result = self.force_value(predicate_id, predicate_span, result)?;
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
        let list_value = self.eval_node(list_id)?;
        let list_value = self.force_value(list_id, list_span, list_value)?;
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
            let list = self.heap.get_list(list_value).map_err(|source| {
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
        let function = self.eval_node(function_id)?;
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
        let list_value = self.force_value(list.id(), list.span(), list.value())?;
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
            let list_value = self.heap.get_list(list_value).map_err(|source| {
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
