//! Strict raw value rendering for `nix-instantiate --eval --strict` parity.

use super::*;

impl TreeWalk {
    pub(super) fn write_raw_value(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        visited: &mut Vec<Value>,
    ) -> Result<(), TreeWalkError> {
        let mut active = Vec::new();
        let mut expanded_active_lists = Vec::new();
        let mut active_list_expansion_depth = 0usize;
        self.write_raw_value_inner(
            id,
            span,
            value_id,
            value_span,
            value,
            out,
            visited,
            &mut active,
            &mut expanded_active_lists,
            &mut active_list_expansion_depth,
        )
    }

    fn write_raw_value_inner(
        &mut self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        seen: &mut Vec<Value>,
        active: &mut Vec<Value>,
        expanded_active_lists: &mut Vec<Value>,
        active_list_expansion_depth: &mut usize,
    ) -> Result<(), TreeWalkError> {
        let value = self.with_raw_render_identity_roots(
            value_id,
            value_span,
            seen,
            active,
            expanded_active_lists,
            |eval| eval.force_value(value_id, value_span, value),
        )?;
        let tag = value.tag();
        let tracks_repeated = match tag {
            ValueTag::Attrs => !self
                .heap
                .get_attrs(value)
                .map_err(|source| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Heap {
                            id: value_id,
                            source,
                        },
                        value_span,
                    )
                })?
                .is_empty(),
            ValueTag::List => true,
            _ => false,
        };
        let entered = if tracks_repeated {
            if Self::raw_identity_contains(seen, value) {
                return match tag {
                    ValueTag::List
                        if Self::raw_identity_contains(active, value)
                            && *active_list_expansion_depth == 0
                            && !Self::raw_identity_contains(expanded_active_lists, value)
                            && self
                                .raw_repeated_list_can_expand(value_id, value_span, value)? =>
                    {
                        let len = expanded_active_lists.len() + 1;
                        expanded_active_lists.try_reserve_exact(1).map_err(|_| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::ListAllocationFailed { id, len },
                                span,
                            )
                        })?;
                        expanded_active_lists.push(value);
                        *active_list_expansion_depth += 1;
                        let result = self.write_raw_list(
                            id,
                            span,
                            value_id,
                            value_span,
                            value,
                            out,
                            seen,
                            active,
                            expanded_active_lists,
                            active_list_expansion_depth,
                        );
                        *active_list_expansion_depth -= 1;
                        result
                    }
                    _ => Self::extend_bytes_for_node(id, span, out, "«repeated»".as_bytes()),
                };
            }
            let len = seen.len() + 1;
            seen.try_reserve_exact(1).map_err(|_| {
                TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
            })?;
            seen.push(value);
            let len = active.len() + 1;
            active.try_reserve_exact(1).map_err(|_| {
                TreeWalkError::new(TreeWalkErrorKind::ListAllocationFailed { id, len }, span)
            })?;
            active.push(value);
            true
        } else {
            false
        };

        let result = match tag {
            ValueTag::Null => Self::extend_bytes_for_node(id, span, out, b"null"),
            ValueTag::Bool => {
                if self.expect_bool(value_id, value, value_span)? {
                    Self::extend_bytes_for_node(id, span, out, b"true")
                } else {
                    Self::extend_bytes_for_node(id, span, out, b"false")
                }
            }
            ValueTag::Int => {
                let scalar = self.heap.decode_int_value(value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                let bytes = Self::raw_int_bytes(scalar);
                Self::extend_bytes_for_node(id, span, out, &bytes)
            }
            ValueTag::Float => {
                let scalar = self.heap.decode_float_value(value).map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                })?;
                let bytes = Self::raw_float_bytes(scalar);
                Self::extend_bytes_for_node(id, span, out, &bytes)
            }
            ValueTag::String => self.write_raw_string(id, span, value_id, value_span, value, out),
            ValueTag::Path => self.write_trace_path(id, span, value_id, value_span, value, out),
            ValueTag::List => self.write_raw_list(
                id,
                span,
                value_id,
                value_span,
                value,
                out,
                seen,
                active,
                expanded_active_lists,
                active_list_expansion_depth,
            ),
            ValueTag::Attrs => self.write_raw_attrs(
                id,
                span,
                value_id,
                value_span,
                value,
                out,
                seen,
                active,
                expanded_active_lists,
                active_list_expansion_depth,
            ),
            ValueTag::Lambda => Self::extend_bytes_for_node(id, span, out, b"<LAMBDA>"),
            ValueTag::Primop => self.write_raw_primop(id, span, value_id, value_span, value, out),
            ValueTag::External => {
                Self::extend_bytes_for_node(id, span, out, "«external»".as_bytes())
            }
            ValueTag::Thunk => Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id: value_id,
                    expected: "forced value",
                    actual: ValueTag::Thunk,
                },
                value_span,
            )),
        };

        if entered {
            active.pop();
            if tag != ValueTag::Attrs {
                seen.pop();
            }
        }
        result
    }

    fn with_raw_render_identity_roots<T>(
        &mut self,
        id: IrId,
        span: Span,
        seen: &mut Vec<Value>,
        active: &mut Vec<Value>,
        expanded_active_lists: &mut Vec<Value>,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let seen_end = seen.len();
        let active_end = seen_end.checked_add(active.len()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: usize::MAX,
                },
                span,
            )
        })?;
        let roots_len = active_end
            .checked_add(expanded_active_lists.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed {
                        id,
                        len: usize::MAX,
                    },
                    span,
                )
            })?;
        if roots_len == 0 {
            return body(self);
        }

        let mut roots = Vec::new();
        roots.try_reserve_exact(roots_len).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed { id, len: roots_len },
                span,
            )
        })?;
        roots.extend_from_slice(seen);
        roots.extend_from_slice(active);
        roots.extend_from_slice(expanded_active_lists);
        let result = self.with_transient_value_stack_roots(id, span, &mut roots, body);
        seen.copy_from_slice(&roots[..seen_end]);
        active.copy_from_slice(&roots[seen_end..active_end]);
        expanded_active_lists.copy_from_slice(&roots[active_end..]);
        result
    }

    fn raw_identity_contains(identities: &[Value], value: Value) -> bool {
        identities.iter().any(|identity| identity.raw_eq(value))
    }

    fn raw_repeated_list_can_expand(
        &self,
        list_id: IrId,
        list_span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        let list = self.heap.get_list(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: list_id,
                    source,
                },
                list_span,
            )
        })?;
        Ok(list.len() <= 2)
    }

    fn write_raw_string(
        &self,
        id: IrId,
        span: Span,
        value_id: IrId,
        value_span: Span,
        value: Value,
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let string = self.heap.get_string(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: value_id,
                    source,
                },
                value_span,
            )
        })?;
        Self::write_trace_escaped_string(id, span, string.bytes(), out)
    }

    fn write_raw_primop(
        &self,
        id: IrId,
        span: Span,
        primop_id: IrId,
        primop_span: Span,
        value: Value,
        out: &mut Vec<u8>,
    ) -> Result<(), TreeWalkError> {
        let primop = self.heap.get_primop(value).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Heap {
                    id: primop_id,
                    source,
                },
                primop_span,
            )
        })?;
        if primop.args().is_empty() {
            Self::extend_bytes_for_node(id, span, out, b"<PRIMOP>")
        } else {
            Self::extend_bytes_for_node(id, span, out, b"<PRIMOP-APP>")
        }
    }

    fn write_raw_list(
        &mut self,
        id: IrId,
        span: Span,
        list_id: IrId,
        list_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        seen: &mut Vec<Value>,
        active: &mut Vec<Value>,
        expanded_active_lists: &mut Vec<Value>,
        active_list_expansion_depth: &mut usize,
    ) -> Result<(), TreeWalkError> {
        let mut elements = {
            let list = self.heap.get_list(value).map_err(|source| {
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
            return Self::extend_bytes_for_node(id, span, out, b"[ ]");
        }

        Self::extend_bytes_for_node(id, span, out, b"[ ")?;
        if self.gc_mode.is_enabled() {
            self.with_indexed_transient_value_stack_roots(
                list_id,
                list_span,
                &mut elements,
                |eval, slots| {
                    for index in 0..slots.len() {
                        if index > 0 {
                            Self::extend_bytes_for_node(id, span, out, b" ")?;
                        }
                        let root_slot = slots.start + index;
                        let Some(element) = eval.current_transient_value_stack_root(root_slot)
                        else {
                            return Err(TreeWalkError::new(
                                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id: list_id },
                                list_span,
                            ));
                        };
                        eval.write_raw_value_inner(
                            id,
                            span,
                            list_id,
                            list_span,
                            element,
                            out,
                            seen,
                            active,
                            expanded_active_lists,
                            active_list_expansion_depth,
                        )?;
                        eval.maybe_sweep_heap_at_registered_safepoint()?;
                    }
                    Ok(())
                },
            )?;
        } else {
            for (index, element) in elements.into_iter().enumerate() {
                if index > 0 {
                    Self::extend_bytes_for_node(id, span, out, b" ")?;
                }
                self.write_raw_value_inner(
                    id,
                    span,
                    list_id,
                    list_span,
                    element,
                    out,
                    seen,
                    active,
                    expanded_active_lists,
                    active_list_expansion_depth,
                )?;
            }
        }
        Self::extend_bytes_for_node(id, span, out, b" ]")
    }

    fn write_raw_attrs(
        &mut self,
        id: IrId,
        span: Span,
        attrs_id: IrId,
        attrs_span: Span,
        value: Value,
        out: &mut Vec<u8>,
        seen: &mut Vec<Value>,
        active: &mut Vec<Value>,
        expanded_active_lists: &mut Vec<Value>,
        active_list_expansion_depth: &mut usize,
    ) -> Result<(), TreeWalkError> {
        let entries = {
            let attrs = self.heap.get_attrs(value).map_err(|source| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Heap {
                        id: attrs_id,
                        source,
                    },
                    attrs_span,
                )
            })?;
            let attr_entries = Self::clone_attr_entries_lexicographic(attrs_id, attrs_span, attrs)?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(attr_entries.len()).map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed {
                            entries: attr_entries.len(),
                        },
                    },
                    span,
                )
            })?;
            for entry in attr_entries {
                let key = self.symbols.resolve(entry.key).ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::InvalidSymbol {
                            id: attrs_id,
                            symbol: entry.key,
                        },
                        attrs_span,
                    )
                })?;
                entries.push((Self::copy_bytes_for_node(id, span, key)?, entry.value));
            }
            entries
        };

        if entries.is_empty() {
            return Self::extend_bytes_for_node(id, span, out, b"{ }");
        }

        Self::extend_bytes_for_node(id, span, out, b"{ ")?;
        if self.gc_mode.is_enabled() {
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
            for (_, value) in &entries {
                roots.push(*value);
            }
            self.with_indexed_transient_value_stack_roots(
                attrs_id,
                attrs_span,
                &mut roots,
                |eval, slots| {
                    for (index, (key, _)) in entries.iter().enumerate() {
                        Self::write_trace_attr_key(id, span, key, out)?;
                        Self::extend_bytes_for_node(id, span, out, b" = ")?;
                        let root_slot = slots.start + index;
                        let Some(value) = eval.current_transient_value_stack_root(root_slot) else {
                            return Err(TreeWalkError::new(
                                TreeWalkErrorKind::SafepointRootStackLengthOverflow {
                                    id: attrs_id,
                                },
                                attrs_span,
                            ));
                        };
                        eval.write_raw_value_inner(
                            id,
                            span,
                            attrs_id,
                            attrs_span,
                            value,
                            out,
                            seen,
                            active,
                            expanded_active_lists,
                            active_list_expansion_depth,
                        )?;
                        Self::extend_bytes_for_node(id, span, out, b"; ")?;
                        eval.maybe_sweep_heap_at_registered_safepoint()?;
                    }
                    Ok(())
                },
            )?;
        } else {
            for (key, value) in entries {
                Self::write_trace_attr_key(id, span, &key, out)?;
                Self::extend_bytes_for_node(id, span, out, b" = ")?;
                self.write_raw_value_inner(
                    id,
                    span,
                    attrs_id,
                    attrs_span,
                    value,
                    out,
                    seen,
                    active,
                    expanded_active_lists,
                    active_list_expansion_depth,
                )?;
                Self::extend_bytes_for_node(id, span, out, b"; ")?;
            }
        }
        Self::extend_bytes_for_node(id, span, out, b"}")
    }
}
