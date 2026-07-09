//! Attribute binding inheritance and select evaluation helpers.

use crate::compile::IrInlineCacheSiteId;

use super::*;

impl TreeWalk {
    pub(in crate::eval::tree_walk) fn eval_attr_binding_value(
        &mut self,
        id: IrId,
        span: Span,
        value: IrId,
        inherit_source_thunks: &mut BTreeMap<u32, Value>,
    ) -> Result<Value, TreeWalkError> {
        let Some((select_id, receiver, path)) = self.inherit_source_select(value)? else {
            return self.eval_lazy_node(value);
        };

        let receiver_key = receiver.as_u32();
        let receiver_value = if let Some(receiver_value) = inherit_source_thunks.get(&receiver_key)
        {
            *receiver_value
        } else {
            let receiver_value = self.eval_lazy_node(receiver)?;
            inherit_source_thunks.insert(receiver_key, receiver_value);
            receiver_value
        };

        self.alloc_select_thunk(id, span, select_id, receiver_value, path)
    }

    pub(in crate::eval::tree_walk) fn preflight_omitted_attr_binding_value(
        &self,
        value: IrId,
    ) -> Result<bool, TreeWalkError> {
        let value_node = self.node(value)?;
        if value_node.kind != IrKind::ThunkAlloc {
            return Ok(false);
        }
        self.preflight_omitted_thunk_alloc(value, value_node)?;
        if let Some((_, receiver, _)) = self.inherit_source_select(value)? {
            let receiver_node = self.node(receiver)?;
            self.preflight_omitted_thunk_alloc(receiver, receiver_node)?;
        }
        Ok(true)
    }

    fn preflight_omitted_thunk_alloc(&self, id: IrId, node: &IrNode) -> Result<(), TreeWalkError> {
        let IrData::Node(body) = node.data else {
            return Err(self.invalid_payload(id, node, "thunk body"));
        };
        self.node(body)?;
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn inherit_source_select(
        &self,
        value: IrId,
    ) -> Result<Option<(IrId, IrId, IrAttrPathId)>, TreeWalkError> {
        // `inherit (e) name...` lowers each target to a lazy select whose receiver
        // is the same thunked source expression. Sharing that receiver at runtime
        // preserves Nix's one-evaluation source behavior without caching all
        // `ThunkAlloc` nodes globally across lexical environments.
        let value_node = self.node(value)?;
        if value_node.kind != IrKind::ThunkAlloc {
            return Ok(None);
        }
        let IrData::Node(select_id) = value_node.data else {
            return Err(self.invalid_payload(value, value_node, "thunk body"));
        };
        let select_node = self.node(select_id)?;
        if select_node.kind != IrKind::Select {
            return Ok(None);
        }
        let IrData::Select {
            receiver,
            path,
            default,
            ..
        } = select_node.data
        else {
            return Err(self.invalid_payload(select_id, select_node, "select payload"));
        };
        if default.is_some() || self.node(receiver)?.kind != IrKind::ThunkAlloc {
            return Ok(None);
        }
        if self
            .attr_path(select_id, path, select_node.span)?
            .iter()
            .any(|segment| matches!(segment, IrAttrPathSegment::Dynamic(_)))
        {
            return Ok(None);
        }

        Ok(Some((select_id, receiver, path)))
    }

    pub(in crate::eval::tree_walk) fn eval_select(
        &mut self,
        id: IrId,
        node: &IrNode,
    ) -> Result<Value, TreeWalkError> {
        let IrData::Select {
            receiver,
            path: path_id,
            default,
            site,
        } = node.data
        else {
            return Err(self.invalid_payload(id, node, "select payload"));
        };
        self.reject_empty_attr_path(id, path_id, node.span)?;
        if let Some(value) =
            self.eval_builtin_static_select(id, node, receiver, path_id, default)?
        {
            return Ok(value);
        }
        let current = self.eval_node(receiver)?;
        self.eval_select_from_value(id, node.span, current, path_id, Some(site), default, false)
    }

    pub(in crate::eval::tree_walk) fn eval_select_from_value(
        &mut self,
        id: IrId,
        span: Span,
        mut current: Value,
        path_id: IrAttrPathId,
        site: Option<IrInlineCacheSiteId>,
        default: Option<IrId>,
        force_receiver: bool,
    ) -> Result<Value, TreeWalkError> {
        let segments = self.attr_path_len(id, path_id, span)?;
        self.reject_empty_attr_path_len(id, path_id, span, segments)?;

        if force_receiver {
            current = self.force_value(id, span, current)?;
        }
        current = self.force_lazy_foldl_initial_value(id, span, current)?;
        for index in 0..segments {
            let segment = self.attr_path_segment(id, path_id, index, span)?;
            let key = self
                .eval_attr_name(id, segment, DynamicAttrNullPolicy::RejectNull, span)?
                .ok_or_else(|| {
                    TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "string",
                            actual: ValueTag::Null,
                        },
                        span,
                    )
                })?;
            if current.tag() != ValueTag::Attrs {
                return match default {
                    Some(default) => self.eval_node(default),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::Type {
                            id,
                            expected: "attrs",
                            actual: current.tag(),
                        },
                        span,
                    )),
                };
            }
            let outcome = if matches!(segment, IrAttrPathSegment::Static(_)) {
                if let Some(site) = site {
                    self.select_static_attr_with_cache(id, span, current, key, site, index)?
                } else {
                    self.select_slow_flat_attr(id, span, current, key)?
                }
            } else {
                self.select_slow_flat_attr(id, span, current, key)?
            };
            let AttrSelectOutcome::Hit { value, .. } = outcome else {
                return match default {
                    Some(default) => self.eval_node(default),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                        span,
                    )),
                };
            };
            if index + 1 == segments {
                return Ok(value);
            }
            current = self.force_value(id, span, value)?;
            current = self.force_lazy_foldl_initial_value(id, span, current)?;
        }

        Err(TreeWalkError::new(
            TreeWalkErrorKind::InvalidAttrPath { id, path: path_id },
            span,
        ))
    }

    /// Selects from an active evaluator attrset through the static-site cache for its representation.
    pub(in crate::eval::tree_walk) fn select_static_attr_with_cache(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        site: IrInlineCacheSiteId,
        path_index: usize,
    ) -> Result<AttrSelectOutcome, TreeWalkError> {
        let metadata = self
            .heap
            .get_attrs_metadata(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        match metadata.repr() {
            AttrSetReprKind::Flat => match metadata.projected_shape() {
                Some(projected_shape)
                    if self.options.attr_shape_mode() == AttrShapeMode::Record =>
                {
                    self.select_record_shaped_attr_with_cache(
                        id,
                        span,
                        attrs_value,
                        symbol,
                        projected_shape,
                        site,
                        path_index,
                    )
                }
                Some(projected_shape) => self.select_projected_shaped_attr_with_cache(
                    id,
                    span,
                    attrs_value,
                    symbol,
                    projected_shape,
                    site,
                    path_index,
                ),
                None => self.select_flat_attr_with_cache(
                    id,
                    span,
                    attrs_value,
                    symbol,
                    site,
                    path_index,
                ),
            },
            AttrSetReprKind::Hamt => {
                self.select_hamt_attr_with_cache(id, span, attrs_value, symbol, site, path_index)
            }
        }
    }

    /// Selects from the active flat evaluator attrset through the representation dispatcher.
    pub(in crate::eval::tree_walk) fn select_slow_flat_attr(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
    ) -> Result<AttrSelectOutcome, TreeWalkError> {
        let outcome = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            select_slow(AttrSelectTarget::Flat(attrs), symbol).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::AttrSelect { id, source }, span)
            })?
        };
        self.record_slow_select_telemetry(id, span, &outcome);
        Ok(outcome)
    }

    /// Selects from the active flat evaluator attrset through a static-site flat cache.
    pub(in crate::eval::tree_walk) fn select_flat_attr_with_cache(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        site: IrInlineCacheSiteId,
        path_index: usize,
    ) -> Result<AttrSelectOutcome, TreeWalkError> {
        let outcome = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let key = (self.current_module.as_u32(), site.as_u32(), path_index);
            self.flat_select_caches
                .entry(key)
                .or_default()
                .select(attrs, symbol)
                .map_err(|source| match source {
                    FlatSelectError::Select(source) => {
                        TreeWalkError::new(TreeWalkErrorKind::AttrSelect { id, source }, span)
                    }
                    source => {
                        TreeWalkError::new(TreeWalkErrorKind::FlatSelectCache { id, source }, span)
                    }
                })?
        };
        let select_outcome = match outcome {
            FlatSelectOutcome::Hit { value, source, .. } => {
                let select_outcome = AttrSelectOutcome::Hit {
                    value,
                    source: AttrSelectSource::Flat,
                };
                match source {
                    FlatSelectSource::Cached => {
                        self.increment_inline_cache_hits();
                    }
                    FlatSelectSource::Resolved { .. } => {
                        self.increment_inline_cache_misses();
                        self.record_slow_select_telemetry(id, span, &select_outcome);
                    }
                }
                select_outcome
            }
            FlatSelectOutcome::Missing => {
                let select_outcome = AttrSelectOutcome::Missing {
                    repr: AttrSelectRepr::Flat,
                };
                self.increment_inline_cache_misses();
                self.record_slow_select_telemetry(id, span, &select_outcome);
                select_outcome
            }
        };
        Ok(select_outcome)
    }

    /// Selects from a heap-resident shaped record through a static-site record cache.
    ///
    /// This is the [`AttrShapeMode::Record`] fast path: the projected shape
    /// id stored in the record's metadata at construction is the guard, and
    /// the flat symbol-order payload is the shaped slot layout itself, so a
    /// cached hit is a shape-id compare, a constant-offset entry load, and a
    /// key recheck - no transient [`ShapedAttrs`] view is materialized. Under
    /// parallel mode a foreign shape id needs no replica resolution: the
    /// per-hit key recheck keeps any id sound, so the id is used purely as an
    /// opaque guard token.
    pub(in crate::eval::tree_walk) fn select_record_shaped_attr_with_cache(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        projected_shape: ShapeId,
        site: IrInlineCacheSiteId,
        path_index: usize,
    ) -> Result<AttrSelectOutcome, TreeWalkError> {
        let key = (self.current_module.as_u32(), site.as_u32(), path_index);
        let outcome = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            self.record_select_caches
                .entry(key)
                .or_default()
                .select(projected_shape, attrs, symbol)
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::RecordSelectCache { id, source }, span)
                })?
        };
        let select_outcome = match outcome {
            RecordSelectOutcome::Hit {
                value,
                slot,
                source,
            } => {
                let select_outcome = AttrSelectOutcome::Hit {
                    value,
                    source: AttrSelectSource::Shaped { slot },
                };
                match source {
                    RecordSelectSource::Cached => {
                        self.increment_inline_cache_hits();
                    }
                    RecordSelectSource::Resolved { .. } => {
                        self.increment_inline_cache_misses();
                        self.record_slow_select_telemetry(id, span, &select_outcome);
                    }
                }
                select_outcome
            }
            RecordSelectOutcome::Missing => {
                let select_outcome = AttrSelectOutcome::Missing {
                    repr: AttrSelectRepr::Shaped,
                };
                self.increment_inline_cache_misses();
                self.record_slow_select_telemetry(id, span, &select_outcome);
                select_outcome
            }
        };
        Ok(select_outcome)
    }

    /// Selects from a flat payload through a transient shaped view and static-site shaped cache.
    pub(in crate::eval::tree_walk) fn select_projected_shaped_attr_with_cache(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        projected_shape: ShapeId,
        site: IrInlineCacheSiteId,
        path_index: usize,
    ) -> Result<AttrSelectOutcome, TreeWalkError> {
        // Resolve the projected shape id first: under parallel mode the id may
        // name a shape this worker's replica cannot resolve (a foreign id after
        // a failed replica sync, or a worker whose projection was disabled).
        // Shape projection is an accelerator, never a semantic requirement, so
        // an unresolved id falls back to the flat select path instead of
        // failing the evaluation.
        let Ok(shape) = self.shaped_handle_for_projected_shape(projected_shape) else {
            return self.select_flat_attr_with_cache(id, span, attrs_value, symbol, site, path_index);
        };
        let shaped =
            self.transient_shaped_attrs_for_projected_shape(id, span, attrs_value, shape)?;
        let key = (self.current_module.as_u32(), site.as_u32(), path_index);
        let (state, outcome) = {
            let cache = self.shaped_select_caches.entry(key).or_default();
            let state = cache.state().clone();
            let outcome = cache.select(&shaped, symbol).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::ShapedSelectCache { id, source }, span)
            })?;
            (state, outcome)
        };
        self.record_shaped_select_cache_lookup_telemetry(id, span, &state, &outcome);
        let select_outcome = match outcome {
            ShapedSelectOutcome::Hit {
                value,
                slot,
                source,
            } => {
                match source {
                    ShapedSelectSource::Cached => {
                        self.increment_inline_cache_hits();
                    }
                    ShapedSelectSource::Resolved { .. } => {
                        self.increment_inline_cache_misses();
                    }
                }
                let select_outcome = AttrSelectOutcome::Hit {
                    value,
                    source: AttrSelectSource::Shaped { slot },
                };
                if matches!(source, ShapedSelectSource::Resolved { .. }) {
                    self.record_slow_select_telemetry(id, span, &select_outcome);
                }
                select_outcome
            }
            ShapedSelectOutcome::Missing => {
                self.increment_inline_cache_misses();
                let select_outcome = AttrSelectOutcome::Missing {
                    repr: AttrSelectRepr::Shaped,
                };
                self.record_slow_select_telemetry(id, span, &select_outcome);
                select_outcome
            }
        };
        Ok(select_outcome)
    }

    fn transient_shaped_attrs_for_projected_shape(
        &self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        shape: ShapeHandle,
    ) -> Result<ShapedAttrs, TreeWalkError> {
        let attrs = self
            .heap
            .get_attrs(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let mut values = Vec::new();
        values.try_reserve_exact(attrs.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::ShapedAttr {
                    id,
                    source: ShapedAttrsError::AllocationFailed {
                        values: attrs.len(),
                    },
                },
                span,
            )
        })?;
        values.extend(attrs.entries_by_symbol().iter().map(|entry| entry.value));
        ShapedAttrs::from_symbol_order(shape, &values).map_err(|source| {
            TreeWalkError::new(TreeWalkErrorKind::ShapedAttr { id, source }, span)
        })
    }

    /// Selects from a projected-HAMT evaluator attrset through a static-site HAMT cache.
    pub(in crate::eval::tree_walk) fn select_hamt_attr_with_cache(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        site: IrInlineCacheSiteId,
        path_index: usize,
    ) -> Result<AttrSelectOutcome, TreeWalkError> {
        let hamt = {
            let attrs = self.heap.get_attrs(attrs_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            HamtAttrs::from_flat(attrs, &self.symbols).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::HamtAttr { id, source }, span)
            })?
        };
        let key = (self.current_module.as_u32(), site.as_u32(), path_index);
        let outcome = self
            .hamt_select_caches
            .entry(key)
            .or_insert_with(|| HamtSelectCache::new(HamtSelectPolicy::DistinguishedEntry))
            .select(&hamt, symbol)
            .map_err(|source| match source {
                HamtSelectError::Select(source) => {
                    TreeWalkError::new(TreeWalkErrorKind::AttrSelect { id, source }, span)
                }
                source => {
                    TreeWalkError::new(TreeWalkErrorKind::HamtSelectCache { id, source }, span)
                }
            })?;
        self.record_hamt_select_cache_lookup_telemetry(id, span, &outcome);
        let select_outcome = match outcome {
            HamtSelectOutcome::Hit { value, source } => {
                match source {
                    HamtSelectSource::CachedDistinguishedHamt => {
                        self.increment_inline_cache_hits();
                    }
                    HamtSelectSource::Resolved { .. } => {
                        self.increment_inline_cache_misses();
                    }
                }
                AttrSelectOutcome::Hit {
                    value,
                    source: AttrSelectSource::Hamt,
                }
            }
            HamtSelectOutcome::Missing { source } => {
                match source {
                    HamtSelectSource::CachedDistinguishedHamt => {
                        self.increment_inline_cache_hits();
                    }
                    HamtSelectSource::Resolved { .. } => {
                        self.increment_inline_cache_misses();
                    }
                }
                AttrSelectOutcome::Missing {
                    repr: AttrSelectRepr::Hamt,
                }
            }
        };
        self.record_slow_select_telemetry(id, span, &select_outcome);
        Ok(select_outcome)
    }

    /// Selects one attr from an already-forced attrset value.
    ///
    /// Callers own WHNF forcing and lazy-foldl normalization before entering this
    /// select-IC helper boundary; this routine only checks the receiver shape and
    /// performs the cached key lookup.
    pub(crate) fn select_attr_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        site: IrInlineCacheSiteId,
    ) -> Result<Value, TreeWalkError> {
        if attrs_value.tag() != ValueTag::Attrs {
            return Err(TreeWalkError::new(
                TreeWalkErrorKind::Type {
                    id,
                    expected: "attrs",
                    actual: attrs_value.tag(),
                },
                span,
            ));
        }
        match self.select_static_attr_with_cache(id, span, attrs_value, symbol, site, 0)? {
            AttrSelectOutcome::Hit { value, .. } => Ok(value),
            AttrSelectOutcome::Missing { .. } => Err(TreeWalkError::new(
                TreeWalkErrorKind::MissingAttribute { id, symbol },
                span,
            )),
        }
    }

    /// Returns whether an already-forced attrset value contains one static attr.
    ///
    /// Callers own WHNF forcing and lazy-foldl normalization before entering this
    /// helper boundary; this routine only checks the receiver shape and probes
    /// cached key presence.
    pub(crate) fn has_attr_value(
        &mut self,
        id: IrId,
        span: Span,
        attrs_value: Value,
        symbol: Symbol,
        site: IrInlineCacheSiteId,
    ) -> Result<Value, TreeWalkError> {
        if attrs_value.tag() != ValueTag::Attrs {
            return Ok(Value::bool(false));
        }
        match self.select_static_attr_with_cache(id, span, attrs_value, symbol, site, 0)? {
            AttrSelectOutcome::Hit { .. } => Ok(Value::bool(true)),
            AttrSelectOutcome::Missing { .. } => Ok(Value::bool(false)),
        }
    }
}
