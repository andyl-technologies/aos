//! `TreeWalk` methods (bind_helpers), split from the parent for the §2 line cap.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn eval_attrset(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::AttrSet {
            shape,
            bindings,
            recursive,
            has_dynamic,
            frame,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "attrset payload"));
        };
        let binding_range = self.binding_range(id, bindings, node.span)?;
        let overrides_symbol = if recursive {
            Some(self.intern_builtin_attr_symbol(id, OVERRIDES_ATTR, node.span)?)
        } else {
            None
        };
        let active_overrides_symbol = overrides_symbol.filter(|symbol| {
            binding_range.clone().any(|binding_index| {
                matches!(
                    self.current_ir().bindings[binding_index].key,
                    IrAttrPathSegment::Static(binding_symbol) if binding_symbol == *symbol
                )
            })
        });
        {
            let shape_keys = self
                .current_ir()
                .shapes
                .get(shape.index())
                .ok_or_else(|| {
                    TreeWalkError::new(TreeWalkErrorKind::InvalidShapeId { id, shape }, node.span)
                })?
                .keys
                .to_vec();
            self.validate_attrset_shape(id, shape, &shape_keys, binding_range.clone(), node.span)?;
        }
        let static_bindings = binding_range
            .clone()
            .filter(|binding_index| {
                matches!(
                    self.current_ir().bindings[*binding_index].key,
                    IrAttrPathSegment::Static(_)
                )
            })
            .count();
        let frame_values = if recursive {
            let Some(frame) = frame else {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::MissingFrameMetadata { id },
                    node.span,
                ));
            };
            let slot_count = self.frame_info(id, frame, node.span)?.slot_count as usize;
            if slot_count != static_bindings {
                return Err(TreeWalkError::new(
                    TreeWalkErrorKind::AttrSetFrameSlotMismatch {
                        id,
                        frame_slots: slot_count,
                        bindings: static_bindings,
                    },
                    node.span,
                ));
            }
            Some(
                EvalFrame::new_linked(slot_count, self.env.innermost().cloned()).map_err(
                    |source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span),
                )?,
            )
        } else {
            None
        };
        let admit_attrset_binding_accumulator = !recursive
            && active_overrides_symbol.is_none()
            && self.can_admit_gc_stress_root_accumulator_allocation_safepoints(id);
        let mut inherit_source_thunks = BTreeMap::new();
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(binding_range.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed {
                            entries: binding_range.len(),
                        },
                    },
                    node.span,
                )
            })?;
        if let Some(frame_values) = &frame_values {
            self.push_env_frame(Arc::clone(frame_values));
        }
        self.begin_order_sensitive_binding_assembly();
        let result = (|| {
            let mut static_slots = BTreeMap::new();
            if let Some(frame_values) = &frame_values {
                self.begin_order_sensitive_binding_assembly();
                let init_result = (|| {
                    let mut slot = 0u32;
                    for binding_index in binding_range.clone() {
                        let binding = self.current_ir().bindings[binding_index];
                        if let IrAttrPathSegment::Static(symbol) = binding.key {
                            let value = self.eval_attr_binding_value(
                                id,
                                node.span,
                                binding.value,
                                &mut inherit_source_thunks,
                            )?;
                            frame_values.set(slot, value).map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                            })?;
                            static_slots.insert(symbol, slot);
                            slot += 1;
                        }
                    }
                    Ok(())
                })();
                self.end_order_sensitive_binding_assembly(init_result.is_ok());
                init_result?;
            }

            if let Some(overrides_symbol) = active_overrides_symbol {
                let Some(frame_values) = frame_values.as_ref() else {
                    return Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingFrameMetadata { id },
                        node.span,
                    ));
                };
                let mut slot = 0u32;
                for binding_index in binding_range.clone() {
                    let binding = self.current_ir().bindings[binding_index];
                    if let IrAttrPathSegment::Static(key) = binding.key {
                        let value = frame_values.get(slot).map_err(|source| {
                            TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                        })?;
                        slot += 1;
                        let position = binding
                            .position
                            .map(|span| AttrPosition::new(self.current_module.as_u32(), span));
                        let entry = match position {
                            Some(position) => AttrEntry::with_position(key, value, position),
                            None => AttrEntry::new(key, value),
                        };
                        entries.push(entry);
                    }
                }

                self.apply_recursive_attrset_overrides(
                    id,
                    node.span,
                    overrides_symbol,
                    frame_values,
                    &static_slots,
                    &mut entries,
                )?;

                for binding_index in binding_range {
                    let binding = self.current_ir().bindings[binding_index];
                    if matches!(binding.key, IrAttrPathSegment::Static(_)) {
                        continue;
                    }
                    let key = self.eval_attr_name(
                        id,
                        binding.key,
                        DynamicAttrNullPolicy::SkipNull,
                        node.span,
                    )?;
                    let Some(key) = key else {
                        continue;
                    };
                    let value = self.eval_attr_binding_value(
                        id,
                        node.span,
                        binding.value,
                        &mut inherit_source_thunks,
                    )?;
                    let position = binding
                        .position
                        .map(|span| AttrPosition::new(self.current_module.as_u32(), span));
                    let entry = match position {
                        Some(position) => AttrEntry::with_position(key, value, position),
                        None => AttrEntry::new(key, value),
                    };
                    entries.push(entry);
                }
            } else {
                let mut slot = 0u32;
                for binding_index in binding_range {
                    let binding = self.current_ir().bindings[binding_index];
                    let key = self.eval_attr_name(
                        id,
                        binding.key,
                        DynamicAttrNullPolicy::SkipNull,
                        node.span,
                    )?;
                    let Some(key) = key else {
                        continue;
                    };
                    let value = if let Some(frame_values) = &frame_values {
                        if matches!(binding.key, IrAttrPathSegment::Static(_)) {
                            let value = frame_values.get(slot).map_err(|source| {
                                TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, node.span)
                            })?;
                            slot += 1;
                            value
                        } else {
                            self.eval_attr_binding_value(
                                id,
                                node.span,
                                binding.value,
                                &mut inherit_source_thunks,
                            )?
                        }
                    } else if admit_attrset_binding_accumulator {
                        self.with_attr_entry_value_roots(
                            id,
                            node.span,
                            entries.as_mut_slice(),
                            |eval| {
                                eval.with_gc_stress_composite_accumulator_suspended(|eval| {
                                    eval.with_gc_stress_accumulator_allocation_node(
                                        binding.value,
                                        |eval| {
                                            eval.eval_attr_binding_value(
                                                id,
                                                node.span,
                                                binding.value,
                                                &mut inherit_source_thunks,
                                            )
                                        },
                                    )
                                })
                            },
                        )?
                    } else {
                        self.eval_attr_binding_value(
                            id,
                            node.span,
                            binding.value,
                            &mut inherit_source_thunks,
                        )?
                    };
                    let position = binding
                        .position
                        .map(|span| AttrPosition::new(self.current_module.as_u32(), span));
                    let entry = match position {
                        Some(position) => AttrEntry::with_position(key, value, position),
                        None => AttrEntry::new(key, value),
                    };
                    entries.push(entry);
                }
            }
            Ok(entries)
        })();
        self.end_order_sensitive_binding_assembly(result.is_ok());
        if recursive {
            self.pop_env_frame();
        }
        let entries = result?;

        let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::Attr { id, source }, node.span)
        })?;
        let len = attrs.len();
        let is_static_literal = !has_dynamic && active_overrides_symbol.is_none();
        let construction = if is_static_literal {
            AttrSetConstruction::StaticLiteral { len }
        } else {
            AttrSetConstruction::Dynamic { len }
        };
        self.alloc_flat_attrs_with_repr_telemetry(
            id,
            node.span,
            shape.as_u32(),
            attrs,
            construction,
        )
    }

    pub(in crate::eval::tree_walk) fn apply_recursive_attrset_overrides(
        &mut self,
        id: IrId,
        span: Span,
        overrides_symbol: Symbol,
        frame_values: &Arc<EvalFrame>,
        static_slots: &BTreeMap<Symbol, u32>,
        entries: &mut Vec<AttrEntry>,
    ) -> Result<(), TreeWalkError> {
        let Some(overrides_slot) = static_slots.get(&overrides_symbol).copied() else {
            return Ok(());
        };
        let overrides_value = frame_values
            .get(overrides_slot)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span))?;
        let overrides_value = self
            .force_value(id, span, overrides_value)
            .map_err(|error| self.prepend_overrides_context(id, span, error))?;
        let overrides_value = self
            .force_lazy_foldl_initial_value(id, span, overrides_value)
            .map_err(|error| self.prepend_overrides_context(id, span, error))?;
        if overrides_value.tag() != ValueTag::Attrs {
            let error = TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "attrs",
                    actual: overrides_value.tag(),
                },
                span,
            );
            return Err(self.prepend_overrides_context(id, span, error));
        }

        let override_entries = {
            let attrs = self.heap.get_attrs(overrides_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            Self::clone_attr_entries_source_order(id, span, attrs)?
        };
        entries
            .try_reserve_exact(override_entries.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::Attr {
                        id,
                        source: AttrError::AllocationFailed {
                            entries: entries.len().saturating_add(override_entries.len()),
                        },
                    },
                    span,
                )
            })?;

        for override_entry in override_entries {
            if let Some(slot) = static_slots.get(&override_entry.key).copied() {
                frame_values
                    .set(slot, override_entry.value)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Env { id, source }, span)
                    })?;
                if let Some(entry) = entries
                    .iter_mut()
                    .find(|entry| entry.key == override_entry.key)
                {
                    *entry = override_entry;
                    continue;
                }
            }
            entries.push(override_entry);
        }

        Ok(())
    }

    pub(in crate::eval::tree_walk) fn prepend_overrides_context(
        &self,
        id: IrId,
        span: Span,
        error: TreeWalkError,
    ) -> TreeWalkError {
        error
            .try_prepend_context(
                id,
                span,
                self.context_with_current_source(b"the `__overrides` attribute".to_vec()),
            )
            .unwrap_or_else(|error| error)
    }
}
