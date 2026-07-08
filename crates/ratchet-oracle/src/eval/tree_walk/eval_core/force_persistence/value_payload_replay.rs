//! Cached force-payload replay helpers.

use super::*;
use crate::cache::AttrPositionSourceHash;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn value_for_cached_expression_payload_for_subject(
        &mut self,
        payload: CachedExpressionValue,
        subject: &ForceCacheSubject,
    ) -> Option<Value> {
        let position_remap = self.payload_position_remap_for_subject(&payload, subject)?;
        self.value_for_cached_expression_payload_with_depth(
            payload,
            0,
            position_remap,
            subject.replay_allocation_node,
        )
    }

    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn value_for_cached_expression_payload_for_test(
        &mut self,
        payload: CachedExpressionValue,
    ) -> Option<Value> {
        self.value_for_cached_expression_payload_with_depth(payload, 0, None, None)
    }

    pub(in crate::eval::tree_walk) fn prepare_observable_payload_for_subject(
        &self,
        payload: CachedExpressionValue,
        subject: &ForceCacheSubject,
    ) -> Option<CachedExpressionValue> {
        if !payload.retains_attr_positions() {
            return Some(payload);
        }
        let module = subject.replay_position_module?;
        if !payload.attr_positions_all_in_module(module.as_u32()) {
            return None;
        }
        let source_hash = self.cache_module_identity_hash_for_id(module)?;
        Some(payload.with_attr_position_source_hash(source_hash))
    }

    pub(in crate::eval::tree_walk) fn payload_position_remap_for_subject(
        &self,
        payload: &CachedExpressionValue,
        subject: &ForceCacheSubject,
    ) -> Option<Option<(u32, u32)>> {
        if !payload.retains_attr_positions() {
            return Some(None);
        }
        let target_module = subject.replay_position_module?;
        let source_hash = self.cache_module_identity_hash_for_id(target_module)?;
        if payload.attr_position_source_hash()? != source_hash {
            return None;
        }
        let target = target_module.as_u32();
        let mut modules = BTreeSet::new();
        payload.collect_attr_position_modules(&mut modules);
        let mut modules = modules.into_iter();
        let source = modules.next()?;
        if modules.next().is_some() {
            return None;
        }
        Some(Some((source, target)))
    }

    fn cache_module_identity_hash_for_id(
        &self,
        module: EvalModuleId,
    ) -> Option<AttrPositionSourceHash> {
        Some(AttrPositionSourceHash::from_durable_hash(
            Self::cache_module_identity_hash(self.modules.get(module.index())?)?,
        ))
    }

    fn remap_cached_attr_position(
        position: AttrPosition,
        position_remap: Option<(u32, u32)>,
    ) -> Option<AttrPosition> {
        let Some((source, target)) = position_remap else {
            return Some(position);
        };
        if position.module != source {
            return None;
        }
        Some(AttrPosition::new(target, position.span))
    }

    fn alloc_replayed_attrs_with_census(
        &mut self,
        origin: Option<EvalNodeRef>,
        repr: AttrSetReprKind,
        attrs: FlatAttrs,
    ) -> Option<Value> {
        let (id, span, dispatch) = match origin {
            Some(origin) if origin.module() == self.current_module => {
                let span = self.node_in_module(origin.module(), origin.id()).ok()?.span;
                (origin.id(), span, true)
            }
            _ => (IrId::new(0), Span::new(0, 0), false),
        };
        let shape_telemetry = self.project_flat_attr_shape_telemetry(id, span, &attrs);
        let projected_shape = shape_telemetry.as_ref().map(|(shape, _)| shape.id());
        let value = if dispatch {
            self.alloc_tree_walk_attrs_with_projected_shape_metadata(
                id,
                span,
                0,
                repr,
                projected_shape,
                attrs,
            )
            .ok()?
        } else {
            self.heap
                .alloc_attrs_with_projected_shape_metadata(0, repr, projected_shape, attrs)
                .ok()?
        };
        if let Some((census_shape, transitions)) = shape_telemetry {
            self.record_projected_attr_shape_telemetry(id, span, &census_shape, transitions);
        }
        Some(value)
    }

    fn value_for_cached_expression_payload_with_depth(
        &mut self,
        payload: CachedExpressionValue,
        depth: usize,
        position_remap: Option<(u32, u32)>,
        replay_allocation_node: Option<EvalNodeRef>,
    ) -> Option<Value> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        if let Some(value) = payload.immediate_value() {
            return Some(value);
        }
        if let Some(bytes) = payload.context_free_string_bytes() {
            let bytes = try_clone_bytes(bytes).ok()?;
            return self.alloc_replayed_payload_string(
                replay_allocation_node,
                NixString::from_bytes(bytes),
            );
        }
        if let Some((bytes, context)) = payload.context_string_parts() {
            let bytes = try_clone_bytes(bytes).ok()?;
            let context = context.try_clone_context().ok()?;
            return self.alloc_replayed_payload_string(
                replay_allocation_node,
                NixString::new(bytes, context),
            );
        }
        if let Some((bytes, context)) = payload.context_path_parts() {
            let bytes = try_clone_bytes(bytes).ok()?;
            let context = context.try_clone_context().ok()?;
            return self.alloc_replayed_payload_path(
                replay_allocation_node,
                NixString::new(bytes, context),
            );
        }
        if payload.is_empty_list() {
            return self.alloc_replayed_payload_list(replay_allocation_node, NixList::empty());
        }
        if let Some(element_payloads) = payload.list_element_payloads() {
            let mut elements = Vec::new();
            elements.try_reserve_exact(element_payloads.len()).ok()?;
            for element in element_payloads {
                elements.push(self.value_for_cached_expression_payload_with_depth(
                    element,
                    depth.saturating_add(1),
                    position_remap,
                    replay_allocation_node,
                )?);
            }
            return self
                .alloc_replayed_payload_list(replay_allocation_node, NixList::new(elements));
        }
        if payload.is_empty_attrs() {
            let repr = payload.attr_repr_kind().unwrap_or(AttrSetReprKind::Flat);
            return self.alloc_replayed_attrs_with_census(
                replay_allocation_node,
                repr,
                FlatAttrs::empty(),
            );
        }
        if let Some(attr_payloads) = payload.attrs_entries_with_positions() {
            let repr = payload.attr_repr_kind().unwrap_or(AttrSetReprKind::Flat);
            let mut entries = Vec::new();
            entries.try_reserve_exact(attr_payloads.len()).ok()?;
            for (name, position, value_payload) in attr_payloads {
                let symbol = self.intern_symbol_for_eval(&name).ok()?;
                let value = self.value_for_cached_expression_payload_with_depth(
                    value_payload,
                    depth.saturating_add(1),
                    position_remap,
                    replay_allocation_node,
                )?;
                let entry = match position {
                    Some(position) => {
                        let position = Self::remap_cached_attr_position(position, position_remap)?;
                        AttrEntry::with_position(symbol, value, position)
                    }
                    None => AttrEntry::new(symbol, value),
                };
                entries.push(entry);
            }
            let attrs = FlatAttrs::new(entries, &self.symbols).ok()?;
            return self.alloc_replayed_attrs_with_census(replay_allocation_node, repr, attrs);
        }
        let bytes = try_clone_bytes(payload.path_bytes()?).ok()?;
        self.alloc_replayed_payload_path(replay_allocation_node, NixString::from_bytes(bytes))
    }
}
