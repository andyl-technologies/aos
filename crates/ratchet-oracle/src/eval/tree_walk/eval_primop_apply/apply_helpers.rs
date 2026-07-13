//! `TreeWalk` methods (apply_helpers), split from the parent for the §2 line cap.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn eval_intersect_attrs_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        left: EvalPrimOpArg,
        right: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let left_value = self.force_primop_value(left, "attrs", ValueTag::Attrs)?;
        let right_value = self.force_primop_value(right, "attrs", ValueTag::Attrs)?;
        let left_keys = {
            let attrs = self.heap.get_attrs(left_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: left.id(),
                        source,
                    },
                    left.span(),
                )
            })?;
            let mut keys = Vec::new();
            keys.try_reserve_exact(attrs.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id: left.id(),
                        len: attrs.len(),
                    },
                    left.span(),
                )
            })?;
            keys.extend(attrs.entries_by_symbol().iter().map(|entry| entry.key));
            keys
        };
        let entries = {
            let attrs = self.heap.get_attrs(right_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: right.id(),
                        source,
                    },
                    right.span(),
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
            for entry in attrs.entries_by_symbol() {
                if left_keys.contains(&entry.key) {
                    entries.push(*entry);
                }
            }
            entries
        };
        let attrs = FlatAttrs::new(entries, &self.symbols)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, span))?;
        self.alloc_dynamic_attrs_result_with_order_telemetry(id, span, attrs)
    }

    pub(in crate::eval::tree_walk) fn eval_cat_attrs_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        key: Symbol,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let list_value = self.force_primop_value(list, "list", ValueTag::List)?;
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
            let element = self.force_value(list.id(), list.span(), element)?;
            let element = self.force_lazy_foldl_initial_value(list.id(), list.span(), element)?;
            if element.tag() != ValueTag::Attrs {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::Type {
                        id: list.id(),
                        expected: "attrs",
                        actual: element.tag(),
                    },
                    list.span(),
                ));
            }
            let selected = {
                let attrs = self.heap.get_attrs(element).map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: list.id(),
                            source,
                        },
                        list.span(),
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

    pub(in crate::eval::tree_walk) fn eval_elem_primop_value(
        &mut self,
        id: IrId,
        candidate: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let list_value = self.force_primop_value(list, "list", ValueTag::List)?;
        let elements = {
            let list_values = self.heap.get_list(list_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: list.id(),
                        source,
                    },
                    list.span(),
                )
            })?;
            Self::clone_list_elements(list.id(), list.span(), list_values)?
        };
        if elements.is_empty() {
            return Ok(Value::bool(false));
        }

        let node = *self.node(id)?;
        for element in elements {
            if self.values_equal_nested_lazy(
                id,
                &node,
                candidate.id(),
                candidate.span(),
                candidate.value(),
                list.id(),
                list.span(),
                element,
            )? {
                return Ok(Value::bool(true));
            }
        }
        Ok(Value::bool(false))
    }

    pub(in crate::eval::tree_walk) fn eval_concat_strings_sep_primop_value(
        &mut self,
        id: IrId,
        span: Span,
        separator: EvalPrimOpArg,
        list: EvalPrimOpArg,
    ) -> Result<Value, TreeWalkError> {
        let separator_value = self.force_primop_value(separator, "string", ValueTag::String)?;
        let (separator_bytes, separator_context) = {
            let separator_string = self.heap.get_string(separator_value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: separator.id(),
                        source,
                    },
                    separator.span(),
                )
            })?;
            let bytes = Self::copy_bytes_for_node(
                separator.id(),
                separator.span(),
                separator_string.bytes(),
            )?;
            let context = separator_string
                .context()
                .union(&StringContext::empty())
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::String {
                            id: separator.id(),
                            source,
                        },
                        separator.span(),
                    )
                })?;
            (bytes, context)
        };

        let list_value = self.force_primop_value(list, "list", ValueTag::List)?;
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
        let result = self.concat_strings_sep_values(
            id,
            span,
            list.id(),
            list.span(),
            &separator_bytes,
            separator_context,
            &elements,
        )?;
        self.alloc_tree_walk_string(id, span, result)
    }
}
