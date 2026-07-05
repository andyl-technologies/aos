//! List builtins: `all`/`any`, `filter`, `zipLists`, and mapping.

use super::*;

impl TreeWalk {
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
        for entry in entries {
            let name = self.alloc_symbol_string(id, span, entry.key)?;
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
                entry.value,
            )?;
            mapped.push(AttrEntry::new(entry.key, value));
        }

        let attrs = FlatAttrs::new(mapped, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        let len = attrs.len();
        self.alloc_flat_attrs_with_repr_telemetry(
            id,
            span,
            0,
            attrs,
            AttrSetConstruction::Dynamic { len },
        )
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
        function: Value,
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
        for (key, values) in groups {
            let values = self
                .heap
                .alloc_list(NixList::new(values))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
            let name = self.alloc_symbol_string(id, span, key)?;
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
        let len = attrs.len();
        self.alloc_flat_attrs_with_repr_telemetry(
            id,
            span,
            0,
            attrs,
            AttrSetConstruction::Dynamic { len },
        )
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
            return self
                .heap
                .alloc_list(NixList::new(Vec::new()))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
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
            return self
                .heap
                .alloc_list(NixList::new(Vec::new()))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
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
            if self.expect_bool(predicate_id, result, predicate_span)? {
                selected.push(element);
            }
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
            return self
                .heap
                .alloc_list(NixList::new(Vec::new()))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
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
            return self
                .heap
                .alloc_list(NixList::new(Vec::new()))
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                });
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
