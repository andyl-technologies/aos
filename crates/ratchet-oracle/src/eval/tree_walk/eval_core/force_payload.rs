//! Force-cache payload extraction from heap values and closed IR literals.

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn force_cache_payload_for_value(
        &self,
        value: Value,
    ) -> Option<CachedExpressionValue> {
        let mut seen_thunks = BTreeSet::new();
        self.force_cache_payload_for_value_with_depth(value, 0, &mut seen_thunks, true)
    }

    pub(super) fn force_cache_payload_for_suspended_thunk_with_seen(
        &self,
        thunk: &EvalThunk,
        depth: usize,
        seen_thunks: &mut BTreeSet<u64>,
    ) -> Option<CachedExpressionValue> {
        let EvalThunkKind::Node {
            body,
            env,
            dynamic_env,
        } = thunk.kind()
        else {
            return None;
        };
        if dynamic_env.is_some() {
            return None;
        }
        self.force_cache_payload_for_ir_node_with_env(
            *body,
            self.captured_env_ref(env),
            depth,
            seen_thunks,
        )
    }

    pub(super) fn force_cache_payload_for_suspended_closed_thunk(
        &self,
        thunk: &EvalThunk,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        let EvalThunkKind::Node {
            body,
            env,
            dynamic_env,
        } = thunk.kind()
        else {
            return None;
        };
        if dynamic_env.is_some() {
            return None;
        }
        let module = self.modules.get(body.module().index())?;
        let slots = Self::captured_free_variable_slots(&module.ir, body.id(), env.frame_count())?;
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
                Some(CachedExpressionValue::int(value))
            }
            IrKind::Float => {
                let IrData::Float(value) = node.data else {
                    return None;
                };
                Some(CachedExpressionValue::float(value))
            }
            IrKind::Bool => {
                let IrData::Bool(value) = node.data else {
                    return None;
                };
                Some(CachedExpressionValue::bool(value))
            }
            IrKind::Null => Some(CachedExpressionValue::null()),
            IrKind::Str | IrKind::Uri => {
                let IrData::Symbol(symbol) = node.data else {
                    return None;
                };
                self.modules.get(module_id.index())?;
                debug_assert!(
                    self.symbols.resolve(symbol).is_some(),
                    "force-cache payload symbol is absent from the live symbol table"
                );
                let bytes = self.symbols.resolve(symbol)?;
                Some(CachedExpressionValue::context_free_string(
                    try_clone_bytes(bytes).ok()?,
                ))
            }
            IrKind::Path => {
                let IrData::Symbol(symbol) = node.data else {
                    return None;
                };
                self.modules.get(module_id.index())?;
                debug_assert!(
                    self.symbols.resolve(symbol).is_some(),
                    "force-cache payload symbol is absent from the live symbol table"
                );
                let bytes = self.symbols.resolve(symbol)?;
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

    fn force_cache_payload_for_ir_node_with_env(
        &self,
        id: EvalNodeRef,
        env: EvalEnvRef<'_>,
        depth: usize,
        seen_thunks: &mut BTreeSet<u64>,
    ) -> Option<CachedExpressionValue> {
        if env.is_empty() {
            return self.force_cache_payload_for_closed_ir_node(id, depth);
        }
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
        match node.data {
            IrData::Local { slot } => {
                let frame_index = env.frame_count().checked_sub(1)?;
                let value = self.env_ref_value_at_index(env, frame_index, slot)?;
                self.force_cache_payload_for_value_with_depth(
                    value,
                    depth.saturating_add(1),
                    seen_thunks,
                    true,
                )
            }
            IrData::Upval {
                depth: upval_depth,
                slot,
            } => {
                let upval_depth = upval_depth as usize;
                if upval_depth >= env.frame_count() {
                    return None;
                }
                let frame_index = env.frame_count() - 1 - upval_depth;
                let value = self.env_ref_value_at_index(env, frame_index, slot)?;
                self.force_cache_payload_for_value_with_depth(
                    value,
                    depth.saturating_add(1),
                    seen_thunks,
                    true,
                )
            }
            IrData::Node(child) if node.kind == IrKind::ThunkAlloc => self
                .force_cache_payload_for_ir_node_with_env(
                    EvalNodeRef::new(module_id, child),
                    env,
                    depth.saturating_add(1),
                    seen_thunks,
                ),
            _ => match node.kind {
                IrKind::Int
                | IrKind::Float
                | IrKind::Bool
                | IrKind::Null
                | IrKind::Str
                | IrKind::Uri
                | IrKind::Path => self.force_cache_payload_for_closed_ir_node(id, depth),
                IrKind::List => self.force_cache_payload_for_ir_list_with_env(
                    module_id,
                    node.data,
                    env,
                    depth,
                    seen_thunks,
                ),
                IrKind::AttrSet => self.force_cache_payload_for_ir_attrset_with_env(
                    module_id,
                    node.data,
                    env,
                    depth,
                    seen_thunks,
                ),
                _ => None,
            },
        }
    }

    fn force_cache_payload_for_ir_list_with_env(
        &self,
        module_id: EvalModuleId,
        data: IrData,
        env: EvalEnvRef<'_>,
        depth: usize,
        seen_thunks: &mut BTreeSet<u64>,
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
            elements.push(self.force_cache_payload_for_ir_node_with_env(
                EvalNodeRef::new(module_id, child),
                env,
                depth.saturating_add(1),
                seen_thunks,
            )?);
        }
        Some(CachedExpressionValue::strict_list(elements))
    }

    fn force_cache_payload_for_ir_attrset_with_env(
        &self,
        module_id: EvalModuleId,
        data: IrData,
        env: EvalEnvRef<'_>,
        depth: usize,
        seen_thunks: &mut BTreeSet<u64>,
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
                debug_assert!(
                    self.symbols.resolve(symbol).is_some(),
                    "force-cache payload symbol is absent from the live symbol table"
                );
                let name = try_clone_bytes(self.symbols.resolve(symbol)?).ok()?;
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
                self.force_cache_payload_for_ir_node_with_env(
                    EvalNodeRef::new(module_id, value),
                    env,
                    depth.saturating_add(1),
                    seen_thunks,
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
                debug_assert!(
                    self.symbols.resolve(symbol).is_some(),
                    "force-cache payload symbol is absent from the live symbol table"
                );
                let name = try_clone_bytes(self.symbols.resolve(symbol)?).ok()?;
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

    pub(super) fn force_cache_payload_for_value_with_depth(
        &self,
        value: Value,
        depth: usize,
        seen_thunks: &mut BTreeSet<u64>,
        allow_suspended_capture_aliases: bool,
    ) -> Option<CachedExpressionValue> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        // Identity-keyed memo for heap `List`/`Attrs` aggregates: a hit skips the
        // recursive re-encode and BLAKE3 of shared substructure. Sound only
        // because Tier-A never moves or reclaims these within one evaluation; see
        // `force_payload_memo`.
        let memo_key = self.force_payload_memo_key(value);
        if let Some(key) = memo_key {
            let hit = self.force_payload_memo.borrow_mut().get(key);
            if let Some(hit) = hit {
                #[cfg(debug_assertions)]
                self.debug_assert_force_payload_memo_hit(
                    value,
                    depth,
                    allow_suspended_capture_aliases,
                    &hit,
                );
                return Some(hit);
            }
        }
        let payload = match value.tag() {
            ValueTag::Int => CachedExpressionValue::int(self.heap.decode_int_value(value).ok()?),
            ValueTag::Float => {
                CachedExpressionValue::float(self.heap.decode_float_value(value).ok()?)
            }
            ValueTag::Bool => CachedExpressionValue::bool(value.as_bool().ok()?),
            ValueTag::Null => {
                value.as_null().ok()?;
                CachedExpressionValue::null()
            }
            ValueTag::String => {
                let string = self.heap.get_string(value).ok()?;
                let bytes = try_clone_bytes(string.bytes()).ok()?;
                if string.has_context() {
                    let context = string.context().try_clone_context().ok()?;
                    CachedExpressionValue::context_string(bytes, context)
                } else {
                    CachedExpressionValue::context_free_string(bytes)
                }
            }
            ValueTag::Path => {
                let path = self.heap.get_path(value).ok()?;
                let bytes = try_clone_bytes(path.bytes()).ok()?;
                if path.has_context() {
                    let context = path.context().try_clone_context().ok()?;
                    CachedExpressionValue::context_path(bytes, context)
                } else {
                    CachedExpressionValue::path(bytes)
                }
            }
            ValueTag::List => {
                let list = self.heap.get_list(value).ok()?;
                if list.is_empty() {
                    CachedExpressionValue::empty_list()
                } else {
                    let mut elements = Vec::new();
                    elements.try_reserve_exact(list.len()).ok()?;
                    for element in list {
                        elements.push(self.force_cache_payload_for_value_with_depth(
                            *element,
                            depth.saturating_add(1),
                            seen_thunks,
                            allow_suspended_capture_aliases,
                        )?);
                    }
                    CachedExpressionValue::strict_list(elements)
                }
            }
            ValueTag::Attrs => {
                let metadata = self.heap.get_attrs_metadata(value).ok()?;
                let attrs = self.heap.get_attrs(value).ok()?;
                let payload = if attrs.is_empty() {
                    CachedExpressionValue::empty_attrs()
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
                                    seen_thunks,
                                    allow_suspended_capture_aliases,
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
                                    seen_thunks,
                                    allow_suspended_capture_aliases,
                                )?,
                            ));
                        }
                    }
                    if has_positions {
                        if source_order_is_lexicographic {
                            CachedExpressionValue::positioned_attrs(entries).ok()?
                        } else {
                            CachedExpressionValue::source_ordered_positioned_attrs(entries).ok()?
                        }
                    } else if source_order_is_lexicographic {
                        CachedExpressionValue::strict_attrs(
                            entries
                                .into_iter()
                                .map(|(name, _, value)| (name, value))
                                .collect(),
                        )
                        .ok()?
                    } else {
                        CachedExpressionValue::source_ordered_attrs(
                            entries
                                .into_iter()
                                .map(|(name, _, value)| (name, value))
                                .collect(),
                        )
                        .ok()?
                    }
                };
                payload.with_attr_repr_metadata(metadata.repr()).ok()?
            }
            ValueTag::Thunk => {
                let thunk_key = value.address_identity_bits();
                if !seen_thunks.insert(thunk_key) {
                    return None;
                }
                let thunk = self.heap.get_thunk(value).ok()?;
                let result = match thunk.cell().cached_value().ok()? {
                    Some(cached) if cached.is_thunk() => None,
                    Some(cached) => self.force_cache_payload_for_value_with_depth(
                        cached,
                        depth.saturating_add(1),
                        seen_thunks,
                        allow_suspended_capture_aliases,
                    ),
                    None => {
                        if allow_suspended_capture_aliases {
                            self.force_cache_payload_for_suspended_thunk_with_seen(
                                thunk,
                                depth.saturating_add(1),
                                seen_thunks,
                            )
                        } else {
                            self.force_cache_payload_for_suspended_closed_thunk(
                                thunk,
                                depth.saturating_add(1),
                            )
                        }
                    }
                };
                seen_thunks.remove(&thunk_key);
                return result;
            }
            ValueTag::Lambda | ValueTag::Primop | ValueTag::External => return None,
        };
        if value.tag().is_heap() {
            self.cache_heap_value_hash(value, &payload);
            if let Some(key) = memo_key {
                self.force_payload_memo.borrow_mut().insert(key, &payload);
            }
        }
        Some(payload)
    }

    /// Returns the memo key for `value` when it is an eligible heap aggregate.
    ///
    /// `Some` only for heap-backed `List`/`Attrs` values while the memo is
    /// active (and not bypassed by the debug guard); every other value is
    /// cheap to re-encode or has force-state-dependent identity, so it is not
    /// memoized.
    fn force_payload_memo_key(&self, value: Value) -> Option<u64> {
        if !self.force_payload_memo.borrow().is_active() {
            return None;
        }
        match value.tag() {
            ValueTag::List | ValueTag::Attrs if value.tag().is_heap() => {
                Some(value.address_identity_bits())
            }
            _ => None,
        }
    }

    /// Asserts a served memo hit matches a fresh, memo-bypassing re-encode.
    ///
    /// Guards the Tier-A address-stability invariant: if a heap address were
    /// reused within one evaluation, the served payload would diverge from a
    /// fresh encode and this fires. A fresh `None` is tolerated — it only
    /// arises when this reach is deeper than the memoized encode and hits the
    /// recursion cutoff, in which case the memo legitimately holds the more
    /// complete result (harmless: the payload never affects `.drv` output).
    #[cfg(debug_assertions)]
    fn debug_assert_force_payload_memo_hit(
        &self,
        value: Value,
        depth: usize,
        allow_suspended_capture_aliases: bool,
        hit: &CachedExpressionValue,
    ) {
        self.force_payload_memo.borrow_mut().set_bypass(true);
        let mut fresh_seen = BTreeSet::new();
        let fresh = self.force_cache_payload_for_value_with_depth(
            value,
            depth,
            &mut fresh_seen,
            allow_suspended_capture_aliases,
        );
        self.force_payload_memo.borrow_mut().set_bypass(false);
        if let (Some(fresh), Ok(hit_hash)) = (fresh, hit.value_hash()) {
            if let Ok(fresh_hash) = fresh.value_hash() {
                debug_assert_eq!(
                    fresh_hash, hit_hash,
                    "observe payload memo served a payload that diverges from a fresh encode; \
                     a heap address was reused within an evaluation (Tier-A invariant broken)"
                );
            }
        }
    }

    fn cache_heap_value_hash(&self, value: Value, payload: &CachedExpressionValue) {
        let Ok(value_hash) = payload.value_hash() else {
            return;
        };
        match self.heap.cached_value_hash(value) {
            Ok(Some(existing)) if existing == value_hash => return,
            Ok(Some(existing)) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    existing = %existing.as_durable_hash(),
                    recomputed = %value_hash.as_durable_hash(),
                    "tree-walk evaluator heap value-hash cache mismatch"
                );
                return;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    target: "aos_nix::cache",
                    error = %error,
                    "tree-walk evaluator heap value-hash lookup failed"
                );
                return;
            }
        }
        if let Err(error) = self.heap.cache_value_hash(value, value_hash) {
            tracing::warn!(
                target: "aos_nix::cache",
                error = %error,
                "tree-walk evaluator heap value-hash caching failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::runtime::CachedScalarValue;
    use crate::compile::resolve as resolve_ast;
    use crate::syntax::parse_str;

    fn lower(source: &str) -> Ir {
        nix_lower(resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("source lowers")
    }

    #[test]
    fn scalar_payload_capture_decodes_through_the_owning_heap() {
        let ir = lower("null");
        let mut evaluator = TreeWalk::new(&ir);
        let float_bits = 0xfff8_0000_0000_0042;
        let integer = evaluator
            .heap
            .alloc_int_value(i64::MAX)
            .expect("integer allocates");
        let float = evaluator
            .heap
            .alloc_float_value(f64::from_bits(float_bits))
            .expect("float allocates");

        let cases = [
            (integer, CachedScalarValue::Int(i64::MAX)),
            (float, CachedScalarValue::FloatBits(float_bits)),
            (Value::bool(true), CachedScalarValue::Bool(true)),
            (Value::null(), CachedScalarValue::Null),
        ];
        for (value, expected) in cases {
            assert_eq!(
                evaluator
                    .force_cache_payload_for_value(value)
                    .and_then(|payload| payload.scalar_value()),
                Some(expected)
            );
        }
    }
}
