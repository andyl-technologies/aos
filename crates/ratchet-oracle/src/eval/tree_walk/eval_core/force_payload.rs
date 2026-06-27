//! Force-cache payload extraction from heap values and closed IR literals.

use super::*;

impl TreeWalk {
    pub(super) fn force_cache_payload_for_value(
        &self,
        value: Value,
    ) -> Option<CachedExpressionValue> {
        self.force_cache_payload_for_value_with_depth(value, 0)
    }

    pub(super) fn force_cache_payload_for_suspended_thunk(
        &self,
        thunk: &EvalThunk,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        let EvalThunkKind::Node {
            body,
            env,
            with_env,
            scoped_globals,
        } = thunk.kind()
        else {
            return None;
        };
        if !with_env.scopes().is_empty() || !scoped_globals.scopes().is_empty() {
            return None;
        }
        let module = self.modules.get(body.module().index())?;
        let slots = Self::captured_free_variable_slots(&module.ir, body.id(), env.frames().len())?;
        if !slots.is_empty() {
            return None;
        }
        self.force_cache_payload_for_closed_ir_node(*body, depth)
    }

    pub(super) fn force_cache_payload_for_closed_ir_node(
        &self,
        id: EvalNodeRef,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        let module_id = id.module();
        let node_id = id.id();
        let node = *self
            .modules
            .get(module_id.index())?
            .ir
            .arena
            .node(node_id)?;
        if !node.effect.is_speculable() {
            return None;
        }
        match node.kind {
            IrKind::Int => {
                let IrData::Int(value) = node.data else {
                    return None;
                };
                CachedExpressionValue::immediate(Value::int(value)).ok()
            }
            IrKind::Float => {
                let IrData::Float(value) = node.data else {
                    return None;
                };
                CachedExpressionValue::immediate(Value::float(value)).ok()
            }
            IrKind::Bool => {
                let IrData::Bool(value) = node.data else {
                    return None;
                };
                CachedExpressionValue::immediate(Value::bool(value)).ok()
            }
            IrKind::Null => CachedExpressionValue::immediate(Value::null()).ok(),
            IrKind::Str | IrKind::Uri => {
                let IrData::Symbol(symbol) = node.data else {
                    return None;
                };
                let module = self.modules.get(module_id.index())?;
                let bytes = module.ir.symbols.resolve(symbol)?;
                Some(CachedExpressionValue::context_free_string(
                    try_clone_bytes(bytes).ok()?,
                ))
            }
            IrKind::Path => {
                let IrData::Symbol(symbol) = node.data else {
                    return None;
                };
                let module = self.modules.get(module_id.index())?;
                let bytes = module.ir.symbols.resolve(symbol)?;
                let path = self
                    .path_literal_bytes_for_module_node(module_id, node_id, node.span, bytes)
                    .ok()?;
                Some(CachedExpressionValue::path(path))
            }
            IrKind::List => {
                self.force_cache_payload_for_closed_ir_list(module_id, node_id, node.data, depth)
            }
            IrKind::AttrSet => {
                self.force_cache_payload_for_closed_ir_attrset(module_id, node_id, node.data, depth)
            }
            IrKind::ThunkAlloc => {
                let IrData::Node(child) = node.data else {
                    return None;
                };
                self.force_cache_payload_for_closed_ir_node(
                    EvalNodeRef::new(module_id, child),
                    depth.saturating_add(1),
                )
            }
            _ => None,
        }
    }

    fn force_cache_payload_for_closed_ir_list(
        &self,
        module_id: EvalModuleId,
        _id: IrId,
        data: IrData,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        let IrData::Children(children) = data else {
            return None;
        };
        let children = self
            .modules
            .get(module_id.index())?
            .ir
            .arena
            .child_slice(children)?
            .to_vec();
        let mut elements = Vec::new();
        elements.try_reserve_exact(children.len()).ok()?;
        for child in children {
            elements.push(self.force_cache_payload_for_closed_ir_node(
                EvalNodeRef::new(module_id, child),
                depth.saturating_add(1),
            )?);
        }
        Some(CachedExpressionValue::strict_list(elements))
    }

    fn force_cache_payload_for_closed_ir_attrset(
        &self,
        module_id: EvalModuleId,
        _id: IrId,
        data: IrData,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        let IrData::AttrSet {
            bindings,
            recursive,
            has_dynamic,
            ..
        } = data
        else {
            return None;
        };
        if recursive || has_dynamic {
            return None;
        }
        let entries = {
            let module = self.modules.get(module_id.index())?;
            let start = bindings.start as usize;
            let end = start.checked_add(bindings.len())?;
            let bindings = module.ir.bindings.get(start..end)?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(bindings.len()).ok()?;
            for binding in bindings {
                let IrAttrPathSegment::Static(symbol) = binding.key else {
                    return None;
                };
                let name = try_clone_bytes(module.ir.symbols.resolve(symbol)?).ok()?;
                let position = binding
                    .position
                    .map(|span| AttrPosition::new(module_id.as_u32(), span));
                entries.push((name, position, binding.value));
            }
            entries
        };
        let source_order_is_lexicographic = entries.windows(2).all(|pair| pair[0].0 < pair[1].0);
        let has_positions = entries.iter().any(|(_, position, _)| position.is_some());
        let mut payload_entries = Vec::new();
        payload_entries.try_reserve_exact(entries.len()).ok()?;
        for (name, position, value) in entries {
            payload_entries.push((
                name,
                position,
                self.force_cache_payload_for_closed_ir_node(
                    EvalNodeRef::new(module_id, value),
                    depth.saturating_add(1),
                )?,
            ));
        }
        if has_positions {
            if source_order_is_lexicographic {
                CachedExpressionValue::positioned_attrs(payload_entries).ok()
            } else {
                CachedExpressionValue::source_ordered_positioned_attrs(payload_entries).ok()
            }
        } else if source_order_is_lexicographic {
            CachedExpressionValue::strict_attrs(
                payload_entries
                    .into_iter()
                    .map(|(name, _, value)| (name, value))
                    .collect(),
            )
            .ok()
        } else {
            CachedExpressionValue::source_ordered_attrs(
                payload_entries
                    .into_iter()
                    .map(|(name, _, value)| (name, value))
                    .collect(),
            )
            .ok()
        }
    }

    fn force_cache_payload_for_value_with_depth(
        &self,
        value: Value,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        if let Ok(value) = CachedExpressionValue::immediate(value) {
            return Some(value);
        }
        match value.tag() {
            ValueTag::String => {
                let string = self.heap.get_string(value).ok()?;
                let bytes = try_clone_bytes(string.bytes()).ok()?;
                if string.has_context() {
                    let context = string.context().try_clone_context().ok()?;
                    Some(CachedExpressionValue::context_string(bytes, context))
                } else {
                    Some(CachedExpressionValue::context_free_string(bytes))
                }
            }
            ValueTag::Path => {
                let path = self.heap.get_path(value).ok()?;
                let bytes = try_clone_bytes(path.bytes()).ok()?;
                if path.has_context() {
                    let context = path.context().try_clone_context().ok()?;
                    Some(CachedExpressionValue::context_path(bytes, context))
                } else {
                    Some(CachedExpressionValue::path(bytes))
                }
            }
            ValueTag::List => {
                let list = self.heap.get_list(value).ok()?;
                if list.is_empty() {
                    Some(CachedExpressionValue::empty_list())
                } else {
                    let mut elements = Vec::new();
                    elements.try_reserve_exact(list.len()).ok()?;
                    for element in list {
                        elements.push(self.force_cache_payload_for_value_with_depth(
                            *element,
                            depth.saturating_add(1),
                        )?);
                    }
                    Some(CachedExpressionValue::strict_list(elements))
                }
            }
            ValueTag::Attrs => {
                let attrs = self.heap.get_attrs(value).ok()?;
                if attrs.is_empty() {
                    Some(CachedExpressionValue::empty_attrs())
                } else {
                    let mut entries = Vec::new();
                    entries.try_reserve_exact(attrs.len()).ok()?;
                    let source_order_is_lexicographic =
                        attrs.source_order() == attrs.iteration_order();
                    let has_positions =
                        attrs.iter_by_symbol().any(|entry| entry.position.is_some());
                    if source_order_is_lexicographic {
                        for entry in attrs.iter_lexicographic() {
                            let name = self.symbols.resolve(entry.key)?;
                            entries.push((
                                try_clone_bytes(name).ok()?,
                                entry.position,
                                self.force_cache_payload_for_value_with_depth(
                                    entry.value,
                                    depth.saturating_add(1),
                                )?,
                            ));
                        }
                    } else {
                        for entry in attrs.iter_source_order() {
                            let name = self.symbols.resolve(entry.key)?;
                            entries.push((
                                try_clone_bytes(name).ok()?,
                                entry.position,
                                self.force_cache_payload_for_value_with_depth(
                                    entry.value,
                                    depth.saturating_add(1),
                                )?,
                            ));
                        }
                    }
                    if has_positions {
                        if source_order_is_lexicographic {
                            CachedExpressionValue::positioned_attrs(entries).ok()
                        } else {
                            CachedExpressionValue::source_ordered_positioned_attrs(entries).ok()
                        }
                    } else if source_order_is_lexicographic {
                        CachedExpressionValue::strict_attrs(
                            entries
                                .into_iter()
                                .map(|(name, _, value)| (name, value))
                                .collect(),
                        )
                        .ok()
                    } else {
                        CachedExpressionValue::source_ordered_attrs(
                            entries
                                .into_iter()
                                .map(|(name, _, value)| (name, value))
                                .collect(),
                        )
                        .ok()
                    }
                }
            }
            ValueTag::Thunk => {
                let thunk = self.heap.get_thunk(value).ok()?;
                match thunk.cell().cached_value().ok()? {
                    Some(cached) if cached.is_thunk() => None,
                    Some(cached) => self
                        .force_cache_payload_for_value_with_depth(cached, depth.saturating_add(1)),
                    None => {
                        self.force_cache_payload_for_suspended_thunk(thunk, depth.saturating_add(1))
                    }
                }
            }
            _ => None,
        }
    }
}
