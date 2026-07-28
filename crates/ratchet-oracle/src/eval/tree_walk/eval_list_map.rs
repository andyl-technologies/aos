//! List builtins: element access, mapping, and concatenation.

use super::*;

impl TreeWalk {
    pub(super) fn eval_list_to_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "list",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let elements = {
            let list = self.heap.get_list_view(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            let mut elements = Vec::new();
            elements.try_reserve_exact(list.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: argument,
                        len: list.len(),
                    },
                    argument_span,
                )
            })?;
            elements.extend(list.iter());
            elements
        };

        let name_attr = self.intern_builtin_attr_symbol(id, NAME_ATTR, span)?;
        let value_attr = self.intern_builtin_attr_symbol(id, VALUE_ATTR, span)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(elements.len()).map_err(|_| {
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
            let element = self.force_uncovered_primop_leaf(argument, argument_span, element)?;
            let element = self.force_lazy_foldl_initial_value(argument, argument_span, element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    argument_span,
                ));
            }
            let (name_value, name_position) = {
                let attrs = self.heap.get_attrs_view(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                let name_entry = attrs.get_entry(name_attr).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute {
                            id: argument,
                            symbol: name_attr,
                        },
                        argument_span,
                    )
                })?;
                (name_entry.value, name_entry.position)
            };
            let name_value =
                self.force_uncovered_primop_leaf(argument, argument_span, name_value)?;
            if name_value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "string",
                        actual: name_value.tag(),
                    },
                    argument_span,
                ));
            }
            let key = self.intern_string_value(argument, name_value, argument_span)?;
            if entries.iter().any(|entry: &AttrEntry| entry.key == key) {
                continue;
            }

            let attr_value = {
                let attrs = self.heap.get_attrs_view(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                attrs.get(value_attr).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute {
                            id: argument,
                            symbol: value_attr,
                        },
                        argument_span,
                    )
                })?
            };
            let entry = match name_position {
                Some(position) => AttrEntry::with_position(key, attr_value, position),
                None => AttrEntry::new(key, attr_value),
            };
            entries.push(entry);
        }

        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_concat_lists_primop(
        &mut self,
        id: IrId,
        span: Span,
        argument: IrId,
        argument_span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: argument,
                    expected: "list",
                    actual: value.tag(),
                },
                argument_span,
            ));
        }
        let lists = {
            let list = self.heap.get_list_view(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: argument,
                        source,
                    },
                    argument_span,
                )
            })?;
            Self::clone_list_elements(argument, argument_span, list)?
        };

        let mut elements = Vec::new();
        for list_value in lists {
            let list_value =
                self.force_uncovered_primop_leaf(argument, argument_span, list_value)?;
            if list_value.tag() != ValueTag::List {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: argument,
                        expected: "list",
                        actual: list_value.tag(),
                    },
                    argument_span,
                ));
            }
            let inner = {
                let list = self.heap.get_list_view(list_value).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: argument,
                            source,
                        },
                        argument_span,
                    )
                })?;
                Self::clone_list_elements(argument, argument_span, list)?
            };
            let len = elements.len().checked_add(inner.len()).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::LengthOverflow {
                            left: elements.len(),
                            right: inner.len(),
                        },
                    },
                    span,
                )
            })?;
            elements.try_reserve_exact(inner.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::List {
                        id,
                        source: NixListError::AllocationFailed { len },
                    },
                    span,
                )
            })?;
            elements.extend(inner);
        }
        self.alloc_tree_walk_list(id, span, NixList::new(elements))
    }

    pub(super) fn intern_builtin_attr_symbol(
        &mut self,
        id: IrId,
        name: &[u8],
        span: Span,
    ) -> Result<Symbol, TreeWalkError> {
        self.intern_symbol_for_eval(name).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::SymbolIntern {
                    id,
                    source: source.kind().clone(),
                },
                span,
            )
        })
    }

    pub(super) fn eval_elem_at_primop(
        &mut self,
        list_id: IrId,
        index_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let index_span = self.node(index_id)?.span;
        let index_value = self.eval_uncovered_primop_child(index_id)?;
        let index_value = self.force_uncovered_primop_leaf(index_id, index_span, index_value)?;
        if index_value.tag() != ValueTag::Int {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: index_id,
                    expected: "int",
                    actual: index_value.tag(),
                },
                index_span,
            ));
        }
        let index = self.heap.decode_int_value(index_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: index_id,
                    source,
                },
                index_span,
            )
        })?;
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
        let list = self.heap.get_list_view(list_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: list_id,
                    source,
                },
                list_span,
            )
        })?;
        let Some(value) = usize::try_from(index)
            .ok()
            .and_then(|index| list.get(index))
        else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ListIndexOutOfBounds {
                    id: index_id,
                    index,
                    len: list.len(),
                },
                index_span,
            ));
        };
        Ok(value)
    }

    pub(super) fn eval_elem_at_primop_value(
        &mut self,
        list: EvalPrimOpArg,
        index: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let index_value =
            self.force_uncovered_primop_leaf(index.id(), index.span(), index.value())?;
        if index_value.tag() != ValueTag::Int {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: index.id(),
                    expected: "int",
                    actual: index_value.tag(),
                },
                index.span(),
            ));
        }
        let index_value = self.heap.decode_int_value(index_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: index.id(),
                    source,
                },
                index.span(),
            )
        })?;
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
        let list_value = self.heap.get_list_view(list_value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: list.id(),
                    source,
                },
                list.span(),
            )
        })?;
        let Some(value) = usize::try_from(index_value)
            .ok()
            .and_then(|index| list_value.get(index))
        else {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::ListIndexOutOfBounds {
                    id: index.id(),
                    index: index_value,
                    len: list_value.len(),
                },
                index.span(),
            ));
        };
        Ok(value)
    }

    pub(super) fn eval_elem_primop(
        &mut self,
        id: IrId,
        node: &IrNode,
        candidate_id: IrId,
        list_id: IrId,
    ) -> Result<Value, TreeWalkError> {
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
        if elements.is_empty() {
            return Ok(Value::bool(false));
        }

        let candidate_span = self.node(candidate_id)?.span;
        let candidate = self.eval_nested_equality_operand(candidate_id)?;
        for element in elements {
            if self.values_equal_nested_lazy(
                id,
                node,
                candidate_id,
                candidate_span,
                candidate,
                list_id,
                list_span,
                element,
            )? {
                return Ok(Value::bool(true));
            }
        }
        Ok(Value::bool(false))
    }

    pub(super) fn eval_get_attr_primop(
        &mut self,
        id: IrId,
        span: Span,
        name_id: IrId,
        attrs_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.with_nonmoving_native_continuation(
            super::native_continuation_shadow::NativeContinuationKind::GetAttrArgumentEval,
            attrs_id,
            &[],
            Some(super::native_continuation_shadow::NativeContinuationEdge::EvalNode),
            |eval| eval.eval_node(attrs_id),
        )?;
        let attrs_value = self.force_lazy_foldl_initial_value(attrs_id, attrs_span, attrs_value)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }
        let selected = {
            let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            attrs.get(key)
        };
        selected.ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                span,
            )
        })
    }

    pub(super) fn eval_has_attr_primop(
        &mut self,
        name_id: IrId,
        attrs_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_uncovered_primop_child(attrs_id)?;
        let attrs_value = self.force_lazy_foldl_initial_value(attrs_id, attrs_span, attrs_value)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }
        let has_attr = {
            let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            attrs.contains_key(key)
        };
        Ok(Value::bool(has_attr))
    }

    pub(super) fn eval_unsafe_get_attr_pos_primop(
        &mut self,
        id: IrId,
        span: Span,
        name_id: IrId,
        attrs_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let key = self.eval_attr_name_primop_argument(name_id)?;
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_uncovered_primop_child(attrs_id)?;
        self.eval_unsafe_get_attr_pos_attrs_value(id, span, key, attrs_id, attrs_span, attrs_value)
    }

    pub(super) fn eval_unsafe_get_attr_pos_attrs_value(
        &mut self,
        id: IrId,
        span: Span,
        key: Symbol,
        attrs_id: IrId,
        attrs_span: Span,
        attrs_value: Value,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_lazy_foldl_initial_value(attrs_id, attrs_span, attrs_value)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }

        let position = {
            let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            attrs.get_entry(key).and_then(|entry| entry.position)
        };
        let Some(position) = position else {
            return Ok(Value::null());
        };

        let Some((file, line, column)) = self.attr_position_fields(position, span)? else {
            return Ok(Value::null());
        };
        self.alloc_attr_position_attrs(id, span, &file, line, column)
    }

    pub(super) fn attr_position_fields(
        &self,
        position: AttrPosition,
        span: Span,
    ) -> Result<Option<(Vec<u8>, i64, i64)>, TreeWalkError> {
        let Some(source) = self.module_source(EvalModuleId::new(position.module), span)? else {
            return Ok(None);
        };
        let start = position.span.start as usize;
        let end = position.span.end as usize;
        if start > end || end > source.bytes.len() {
            return Ok(None);
        }

        let Some((line, column)) = source.line_column_at_offset(start) else {
            return Ok(None);
        };
        Ok(Some((source.name.clone(), line, column)))
    }

    pub(super) fn eval_current_position(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<Value, TreeWalkError> {
        let position = AttrPosition::new(self.current_module.as_u32(), span);
        let Some((file, line, column)) = self.attr_position_fields(position, span)? else {
            return Ok(Value::null());
        };
        self.alloc_attr_position_attrs(id, span, &file, line, column)
    }

    pub(super) fn alloc_attr_position_attrs(
        &mut self,
        id: IrId,
        span: Span,
        file: &[u8],
        line: i64,
        column: i64,
    ) -> Result<Value, TreeWalkError> {
        let file_key = self.intern_builtin_attr_symbol(id, FILE_ATTR, span)?;
        let line_key = self.intern_builtin_attr_symbol(id, LINE_ATTR, span)?;
        let column_key = self.intern_builtin_attr_symbol(id, COLUMN_ATTR, span)?;
        let file_value = self.alloc_static_string(id, span, file)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(3).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id,
                    source: AttrError::AllocationFailed { entries: 3 },
                },
                span,
            )
        })?;
        entries.push(AttrEntry::new(file_key, file_value));
        let line = self.runtime_int_value(id, span, line)?;
        entries.push(AttrEntry::new(line_key, line));
        let column = self.runtime_int_value(id, span, column)?;
        entries.push(AttrEntry::new(column_key, column));
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_attr_name_primop_argument(
        &mut self,
        id: IrId,
    ) -> Result<Symbol, TreeWalkError> {
        let span = self.node(id)?.span;
        let value = self.eval_uncovered_primop_child(id)?;
        if value.tag() != ValueTag::String {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "string",
                    actual: value.tag(),
                },
                span,
            ));
        }
        self.intern_string_value(id, value, span)
    }

    pub(super) fn eval_remove_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        names_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_uncovered_primop_child(attrs_id)?;
        let attrs_value = self.force_lazy_foldl_initial_value(attrs_id, attrs_span, attrs_value)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }

        let names_span = self.node(names_id)?.span;
        let names_value = self.eval_uncovered_primop_child(names_id)?;
        if names_value.tag() != ValueTag::List {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: names_id,
                    expected: "list",
                    actual: names_value.tag(),
                },
                names_span,
            ));
        }
        let name_values = {
            let names = self.heap.get_list_view(names_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: names_id,
                        source,
                    },
                    names_span,
                )
            })?;
            let mut values = Vec::new();
            values.try_reserve_exact(names.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: names_id,
                        len: names.len(),
                    },
                    names_span,
                )
            })?;
            values.extend(names.iter());
            values
        };
        let mut remove = Vec::new();
        remove.try_reserve_exact(name_values.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id: names_id,
                    len: name_values.len(),
                },
                names_span,
            )
        })?;
        for value in name_values {
            let value = self.force_uncovered_primop_leaf(names_id, names_span, value)?;
            if value.tag() != ValueTag::String {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: names_id,
                        expected: "string",
                        actual: value.tag(),
                    },
                    names_span,
                ));
            }
            let key = self.intern_string_value(names_id, value, names_span)?;
            if !remove.contains(&key) {
                remove.push(key);
            }
        }

        let entries = {
            let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attrs.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: attrs.len(),
                    },
                    span,
                )
            })?;
            for entry in attrs.iter_by_symbol() {
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

    pub(super) fn eval_intersect_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        left_id: IrId,
        right_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let left_span = self.node(left_id)?.span;
        let left_value = self.eval_uncovered_primop_child(left_id)?;
        let left_value = self.force_lazy_foldl_initial_value(left_id, left_span, left_value)?;
        if left_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: left_id,
                    expected: "attrs",
                    actual: left_value.tag(),
                },
                left_span,
            ));
        }

        let right_span = self.node(right_id)?.span;
        let right_value = self.eval_uncovered_primop_child(right_id)?;
        let right_value = self.force_lazy_foldl_initial_value(right_id, right_span, right_value)?;
        if right_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: right_id,
                    expected: "attrs",
                    actual: right_value.tag(),
                },
                right_span,
            ));
        }

        let left_keys = {
            let left = self.heap.get_attrs_view(left_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: left_id,
                        source,
                    },
                    left_span,
                )
            })?;
            let mut keys = Vec::new();
            keys.try_reserve_exact(left.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: left_id,
                        len: left.len(),
                    },
                    left_span,
                )
            })?;
            keys.extend(left.iter_by_symbol().map(|entry| entry.key));
            keys
        };
        let entries = {
            let right = self.heap.get_attrs_view(right_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: right_id,
                        source,
                    },
                    right_span,
                )
            })?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(right.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: right.len(),
                    },
                    span,
                )
            })?;
            for entry in right.iter_by_symbol() {
                if left_keys.contains(&entry.key) {
                    entries.push(entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(super) fn eval_map_attrs_primop(
        &mut self,
        id: IrId,
        span: Span,
        function_id: IrId,
        attrs_id: IrId,
    ) -> Result<Value, TreeWalkError> {
        let attrs_span = self.node(attrs_id)?.span;
        let attrs_value = self.eval_uncovered_primop_child(attrs_id)?;
        let attrs_value = self.force_lazy_foldl_initial_value(attrs_id, attrs_span, attrs_value)?;
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: attrs_id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                attrs_span,
            ));
        }

        let entries = {
            let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            Self::clone_attr_entries_source_order(attrs_id, attrs_span, attrs)?
        };
        if entries.is_empty() {
            return self.alloc_dynamic_attrs_result_with_order_telemetry(
                id,
                span,
                FlatAttrs::empty(),
            );
        }

        let function_span = self.node(function_id)?.span;
        let function = self.alloc_thunk_for_node(function_id, function_id, function_span)?;
        self.alloc_mapped_attrs(
            id,
            span,
            function_id,
            function_span,
            function,
            attrs_id,
            entries,
        )
    }

    pub(super) fn eval_map_attrs_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        function: EvalPrimOpArg,
        attrs: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let attrs_value = self.force_primop_value(attrs, "attrs", ValueTag::Attrs)?;
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
            Self::clone_attr_entries_source_order(attrs.id(), attrs.span(), attrs_set)?
        };
        if entries.is_empty() {
            return self.alloc_dynamic_attrs_result_with_order_telemetry(
                id,
                span,
                FlatAttrs::empty(),
            );
        }

        self.alloc_mapped_attrs(
            id,
            span,
            function.id(),
            function.span(),
            function.value(),
            attrs.id(),
            entries,
        )
    }
}
