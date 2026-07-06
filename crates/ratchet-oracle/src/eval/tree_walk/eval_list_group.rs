//! List builtins: `partition`, `groupBy`, `concatMap`, and generators.

use super::*;

impl TreeWalk {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_mapped_list(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut mapped = Vec::new();
        mapped.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        for element in elements {
            mapped.push(self.alloc_apply_thunk(
                id,
                span,
                function_id,
                function_span,
                function,
                list_id,
                element,
            )?);
        }

        self.alloc_tree_walk_list(id, span, NixList::new(mapped))
    }

    pub(super) fn eval_gen_list_primop(
        &mut self,
        id: IrId,
        span: Span,
        generator_id: IrId,
        length_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let length_span = self.node(length_id)?.span;
        let length_value = self.eval_node(length_id)?;
        let length_value = self.force_value(length_id, length_span, length_value)?;
        let length = self.expect_int(length_id, length_value, length_span)?;
        let length = self.expect_non_negative_list_length(length_id, length, length_span)?;

        let generator_span = self.node(generator_id)?.span;
        let generator = self.eval_node(generator_id)?;
        let generator = self.force_callable_value(generator_id, generator_span, generator)?;

        self.alloc_generated_list(
            id,
            span,
            generator_id,
            generator_span,
            generator,
            length_id,
            length,
        )
    }

    pub(super) fn eval_gen_list_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        generator: EvalPrimOpArg,
        length: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let length_value = self.force_value(length.id(), length.span(), length.value())?;
        let length_value = self.expect_int(length.id(), length_value, length.span())?;
        let length_value =
            self.expect_non_negative_list_length(length.id(), length_value, length.span())?;

        let generator_value =
            self.force_callable_value(generator.id(), generator.span(), generator.value())?;

        self.alloc_generated_list(
            id,
            span,
            generator.id(),
            generator.span(),
            generator_value,
            length.id(),
            length_value,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn alloc_generated_list(
        &mut self,
        id: IrId,
        span: Span,
        generator_id: IrId,
        generator_span: Span,
        generator: Value,
        length_id: IrId,
        length: usize,
    ) -> Result<Value, TreeWalkError> {
        let mut generated = Vec::new();
        generated.try_reserve_exact(length).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id, len: length },
                span,
            )
        })?;
        for index in 0..length {
            let index = i64::try_from(index).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListLengthOverflow {
                        id: length_id,
                        len: length,
                    },
                    span,
                )
            })?;
            generated.push(self.alloc_apply_thunk(
                id,
                span,
                generator_id,
                generator_span,
                generator,
                length_id,
                Value::int(index),
            )?);
        }

        self.alloc_tree_walk_list(id, span, NixList::new(generated))
    }

    pub(super) fn expect_non_negative_list_length(
        &self,
        id: IrId,
        length: i64,
        span: Span,
    ) -> Result<usize, TreeWalkError> {
        if length < 0 {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::NegativeListLength { id, length },
                span,
            ));
        }
        usize::try_from(length).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListLengthOverflow {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })
    }

    pub(super) fn eval_partition_primop(
        &mut self,
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
            Self::clone_list_elements(list_id, list_span, list)?
        };

        self.eval_partition_elements(
            id,
            span,
            predicate_id,
            predicate_span,
            predicate,
            list_id,
            list_span,
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_partition_primop_value(
        &mut self,
        id: IrId,
        span: Span,
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

        self.eval_partition_elements(
            id,
            span,
            predicate.id(),
            predicate.span(),
            predicate_value,
            list.id(),
            list.span(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_partition_elements(
        &mut self,
        id: IrId,
        span: Span,
        predicate_id: IrId,
        predicate_span: Span,
        predicate: Value,
        list_id: IrId,
        list_span: Span,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut right = Vec::new();
        right.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: elements.len(),
                },
                span,
            )
        })?;
        let mut wrong = Vec::new();
        wrong.try_reserve_exact(elements.len()).map_err(|_| {
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
                right.push(element);
            } else {
                wrong.push(element);
            }
        }

        let right = self.alloc_tree_walk_list(id, span, NixList::new(right))?;
        let wrong = self.alloc_tree_walk_list(id, span, NixList::new(wrong))?;
        let right_key = self.intern_builtin_attr_symbol(id, b"right", span)?;
        let wrong_key = self.intern_builtin_attr_symbol(id, b"wrong", span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(2).map_err(|_| {
            TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len: 2 }, span)
        })?;
        entries.push(AttrEntry::new(right_key, right));
        entries.push(AttrEntry::new(wrong_key, wrong));
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

    pub(super) fn eval_concat_map_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let function_span = self.node(function_id)?.span;
        let function = self.eval_node(function_id)?;
        let function = self.force_callable_value(function_id, function_span, function)?;

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

        self.eval_concat_map_elements(
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
    pub(super) fn eval_concat_map_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let function_value =
            self.force_callable_value(function.id(), function.span(), function.value())?;

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

        self.eval_concat_map_elements(
            id,
            span,
            function.id(),
            function.span(),
            function_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_concat_map_elements(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut output = Vec::new();
        for element in elements {
            let mapped = self.apply_lambda_value(
                id,
                span,
                function_id,
                function,
                function_span,
                list_id,
                element,
            )?;
            let mapped = self.force_value(function_id, function_span, mapped)?;
            if mapped.tag() != ValueTag::List {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: function_id,
                        expected: "list",
                        actual: mapped.tag(),
                    },
                    function_span,
                ));
            }
            let inner = {
                let list = self.heap.get_list(mapped).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: function_id,
                            source,
                        },
                        function_span,
                    )
                })?;
                Self::clone_list_elements(function_id, function_span, list)?
            };
            let len = output.len().checked_add(inner.len()).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::LengthOverflow {
                            left: output.len(),
                            right: inner.len(),
                        },
                    },
                    span,
                )
            })?;
            output.try_reserve_exact(inner.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::AllocationFailed { len },
                    },
                    span,
                )
            })?;
            output.extend(inner);
        }

        self.alloc_tree_walk_list(id, span, NixList::new(output))
    }

    pub(super) fn eval_group_by_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let function_span = self.node(function_id)?.span;
        let function = self.eval_node(function_id)?;
        let function = self.force_callable_value(function_id, function_span, function)?;

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

        self.eval_group_by_elements(
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
    pub(super) fn eval_group_by_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let function_value =
            self.force_callable_value(function.id(), function.span(), function.value())?;

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

        self.eval_group_by_elements(
            id,
            span,
            function.id(),
            function.span(),
            function_value,
            list.id(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_group_by_elements(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        function_span: Span,
        function: Value,
        list_id: IrId,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let mut groups: Vec<(Symbol, Vec<Value>)> = Vec::new();
        groups.try_reserve_exact(elements.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed {
                        entries: elements.len(),
                    },
                },
                span,
            )
        })?;
        for element in elements {
            let key = self.apply_lambda_value(
                id,
                span,
                function_id,
                function,
                function_span,
                list_id,
                element,
            )?;
            let key = self.force_value(function_id, function_span, key)?;
            if key.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: function_id,
                        expected: "string",
                        actual: key.tag(),
                    },
                    function_span,
                ));
            }
            let key = self.intern_string_value(function_id, key, function_span)?;
            if let Some((_, values)) = groups.iter_mut().find(|(group_key, _)| *group_key == key) {
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
                    TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
                })?;
                values.push(element);
            } else {
                let mut values = Vec::new();
                values.try_reserve_exact(1).map_err(|_| {
                    TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len: 1 }, span)
                })?;
                values.push(element);
                groups.push((key, values));
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
            let value = self.alloc_tree_walk_list(id, span, NixList::new(values))?;
            entries.push(AttrEntry::new(key, value));
        }
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_sort_primop(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
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
            if list.is_empty() {
                return Ok(list_value);
            }
            Self::clone_list_elements(list_id, list_span, list)?
        };

        let comparator_span = self.node(comparator_id)?.span;
        let comparator = self.eval_node(comparator_id)?;
        let comparator = self.force_value(comparator_id, comparator_span, comparator)?;
        self.eval_sort_elements(
            id,
            span,
            comparator_id,
            comparator_span,
            comparator,
            list_id,
            list_span,
            elements,
        )
    }

    pub(super) fn eval_sort_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        comparator: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let forced_list = self.force_value(list.id(), list.span(), list.value())?;
        if forced_list.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: list.id(),
                    expected: "list",
                    actual: forced_list.tag(),
                },
                list.span(),
            ));
        }
        let elements = {
            let list_value = self.heap.get_list(forced_list).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            if list_value.is_empty() {
                return Ok(forced_list);
            }
            Self::clone_list_elements(list.id(), list.span(), list_value)?
        };

        let comparator_value =
            self.force_value(comparator.id(), comparator.span(), comparator.value())?;
        self.eval_sort_elements(
            id,
            span,
            comparator.id(),
            comparator.span(),
            comparator_value,
            list.id(),
            list.span(),
            elements,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_sort_elements(
        &mut self,
        id: IrId,
        span: Span,
        comparator_id: IrId,
        comparator_span: Span,
        comparator: Value,
        list_id: IrId,
        list_span: Span,
        elements: Vec<Value>,
    ) -> Result<Value, TreeWalkError> {
        let comparator = self.ensure_callable_value(comparator_id, comparator_span, comparator)?;

        let mut elements = self.force_sort_elements(list_id, list_span, elements)?;
        self.eval_sort_libcxx_stable(
            id,
            span,
            comparator_id,
            comparator_span,
            comparator,
            list_id,
            &mut elements,
        )?;

        self.alloc_tree_walk_list(id, span, NixList::new(elements))
    }
}
