//! Cached force-payload replay helpers.

use super::*;
use crate::cache::AttrPositionSourceHash;

impl TreeWalk {
    pub(super) fn value_for_cached_expression_payload_for_subject(
        &mut self,
        payload: CachedExpressionValue,
        subject: &ForceCacheSubject,
    ) -> Option<Value> {
        let position_remap = self.payload_position_remap_for_subject(&payload, subject)?;
        self.value_for_cached_expression_payload_with_depth(payload, 0, position_remap)
    }

    pub(super) fn prepare_observable_payload_for_subject(
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

    pub(super) fn payload_position_remap_for_subject(
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

    fn value_for_cached_expression_payload_with_depth(
        &mut self,
        payload: CachedExpressionValue,
        depth: usize,
        position_remap: Option<(u32, u32)>,
    ) -> Option<Value> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        if let Some(value) = payload.immediate_value() {
            return Some(value);
        }
        if let Some(bytes) = payload.context_free_string_bytes() {
            let bytes = try_clone_bytes(bytes).ok()?;
            return self.heap.alloc_string(NixString::from_bytes(bytes)).ok();
        }
        if let Some((bytes, context)) = payload.context_string_parts() {
            let bytes = try_clone_bytes(bytes).ok()?;
            let context = context.try_clone_context().ok()?;
            return self.heap.alloc_string(NixString::new(bytes, context)).ok();
        }
        if let Some((bytes, context)) = payload.context_path_parts() {
            let bytes = try_clone_bytes(bytes).ok()?;
            let context = context.try_clone_context().ok()?;
            return self.heap.alloc_path(NixString::new(bytes, context)).ok();
        }
        if payload.is_empty_list() {
            return self.heap.alloc_list(NixList::empty()).ok();
        }
        if let Some(element_payloads) = payload.list_element_payloads() {
            let mut elements = Vec::new();
            elements.try_reserve_exact(element_payloads.len()).ok()?;
            for element in element_payloads {
                elements.push(self.value_for_cached_expression_payload_with_depth(
                    element,
                    depth.saturating_add(1),
                    position_remap,
                )?);
            }
            return self.heap.alloc_list(NixList::new(elements)).ok();
        }
        if payload.is_empty_attrs() {
            return self.heap.alloc_attrs(0, FlatAttrs::empty()).ok();
        }
        if let Some(attr_payloads) = payload.attrs_entries_with_positions() {
            let mut entries = Vec::new();
            entries.try_reserve_exact(attr_payloads.len()).ok()?;
            for (name, position, value_payload) in attr_payloads {
                let symbol = self.symbols.intern(&name).ok()?;
                let value = self.value_for_cached_expression_payload_with_depth(
                    value_payload,
                    depth.saturating_add(1),
                    position_remap,
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
            return self.heap.alloc_attrs(0, attrs).ok();
        }
        let bytes = try_clone_bytes(payload.path_bytes()?).ok()?;
        self.heap.alloc_path(NixString::from_bytes(bytes)).ok()
    }
}
