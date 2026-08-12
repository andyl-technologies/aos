//! Attribute binding inheritance and select evaluation helpers.

use crate::compile::IrInlineCacheSiteId;
use crate::eval::heap::EvalAttrsView;

use super::super::native_continuation_shadow::{NativeContinuationEdge, NativeContinuationKind};
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
        let current = self.with_nonmoving_native_continuation(
            NativeContinuationKind::SelectReceiver,
            receiver,
            &[],
            Some(NativeContinuationEdge::EvalNode),
            |eval| eval.eval_node(receiver),
        )?;
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
        let observation = self.option_read_observation(span, current);
        let mut observed_paths = observation
            .as_ref()
            .map(|(_, _, paths)| paths.clone())
            .unwrap_or_default();
        for index in 0..segments {
            let segment = self.attr_path_segment(id, path_id, index, span)?;
            let key = match segment {
                IrAttrPathSegment::Dynamic(dynamic) => self
                    .with_uncovered_native_continuation_marker(
                        NativeContinuationKind::SelectDynamicAttr,
                        dynamic,
                        |eval| {
                            eval.eval_attr_name(
                                id,
                                segment,
                                DynamicAttrNullPolicy::RejectNull,
                                span,
                            )
                        },
                    )?,
                IrAttrPathSegment::Static(_) => {
                    self.eval_attr_name(id, segment, DynamicAttrNullPolicy::RejectNull, span)?
                }
            }
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
            if observation.is_some() {
                let segment = self.symbols.resolve(key).unwrap_or_default().to_vec();
                for path in &mut observed_paths {
                    path.push(segment.clone());
                }
            }
            if current.tag() != ValueTag::Attrs {
                self.record_config_reads(observation.as_ref(), &observed_paths);
                return match default {
                    Some(default) => self.with_uncovered_native_continuation_marker(
                        NativeContinuationKind::SelectDefault,
                        default,
                        |eval| eval.eval_node(default),
                    ),
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
                self.record_config_reads(observation.as_ref(), &observed_paths);
                return match default {
                    Some(default) => self.with_uncovered_native_continuation_marker(
                        NativeContinuationKind::SelectDefault,
                        default,
                        |eval| eval.eval_node(default),
                    ),
                    None => Err(TreeWalkError::new(
                        TreeWalkErrorKind::MissingAttribute { id, symbol: key },
                        span,
                    )),
                };
            };
            if let Some((observer, _, _)) = &observation {
                observer.associate_all(value, &observed_paths);
            }
            if index + 1 == segments {
                self.record_config_reads(observation.as_ref(), &observed_paths);
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

    /// Returns semantic config provenance and the currently executing source.
    fn option_read_observation(
        &self,
        span: Span,
        receiver: Value,
    ) -> Option<(OptionReadObserver, Vec<u8>, Vec<Vec<Vec<u8>>>)> {
        let observer = self.options.option_read_observer.clone()?;
        let source = self
            .modules
            .get(self.current_module.index())?
            .source
            .as_ref()?;
        if !observer.observes_source(&source.name) {
            return None;
        }
        let mut paths = observer.provenance(receiver);
        if paths.is_empty() && self.span_is_direct_config(span, &source.bytes) {
            paths.push(Vec::new());
            observer.associate(receiver, Vec::new());
        }
        if paths.is_empty() {
            return None;
        }
        Some((observer, source.name.clone(), paths))
    }

    fn span_is_direct_config(&self, span: Span, source: &[u8]) -> bool {
        let (Ok(start), Ok(end)) = (usize::try_from(span.start), usize::try_from(span.end)) else {
            return false;
        };
        let Some(expression) = source.get(start..end) else {
            return false;
        };
        let mut expression = trim_ascii(expression);
        while expression.first() == Some(&b'(') {
            expression = trim_ascii(&expression[1..]);
        }
        let Some(tail) = expression.strip_prefix(b"config") else {
            return false;
        };
        tail.first()
            .is_some_and(|byte| *byte == b'.' || byte.is_ascii_whitespace())
    }

    fn record_config_reads(
        &self,
        observation: Option<&(OptionReadObserver, Vec<u8>, Vec<Vec<Vec<u8>>>)>,
        paths: &[Vec<Vec<u8>>],
    ) {
        if let Some((observer, source, _)) = observation {
            for path in paths {
                observer.record(source.clone(), path.clone());
            }
        }
    }

    /// Records one semantically dynamic attribute access on a config-derived
    /// attrset and propagates the resulting path to the selected value.
    pub(in crate::eval::tree_walk) fn record_option_attr_access(
        &self,
        receiver: Value,
        key: Symbol,
        selected: Option<Value>,
    ) {
        let Some(observer) = self.options.option_read_observer.clone() else {
            return;
        };
        let Some(source) = self
            .modules
            .get(self.current_module.index())
            .and_then(|module| module.source.as_ref())
        else {
            return;
        };
        if !observer.observes_source(&source.name) {
            return;
        }
        let segment = self.symbols.resolve(key).unwrap_or_default().to_vec();
        let mut paths = observer.provenance(receiver);
        for path in &mut paths {
            path.push(segment.clone());
            observer.record(source.name.clone(), path.clone());
        }
        if let Some(selected) = selected {
            observer.associate_all(selected, &paths);
        }
    }

    /// Propagates config provenance through an attrset-preserving transform.
    pub(in crate::eval::tree_walk) fn propagate_option_provenance(
        &self,
        result: Value,
        inputs: &[Value],
    ) {
        let Some(observer) = &self.options.option_read_observer else {
            return;
        };
        for input in inputs {
            let paths = observer.provenance(*input);
            observer.associate_all(result, &paths);
        }
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
            let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let outcome = match attrs {
                EvalAttrsView::Flat(attrs) => select_slow(AttrSelectTarget::Flat(attrs), symbol)
                    .map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::AttrSelect { id, source }, span)
                    })?,
                #[cfg(any(
                    feature = "compact_destination_probe",
                    feature = "evacuation_plan_probe"
                ))]
                EvalAttrsView::Packed(_) => attrs
                    .get(symbol)
                    .map(|value| AttrSelectOutcome::Hit {
                        value,
                        source: AttrSelectSource::Flat,
                    })
                    .unwrap_or(AttrSelectOutcome::Missing {
                        repr: AttrSelectRepr::Flat,
                    }),
            };
            outcome
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
        let attrs = self
            .heap
            .get_attrs_view(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let outcome = match attrs {
            EvalAttrsView::Flat(attrs) => {
                let key = (self.current_module.as_u32(), site.as_u32(), path_index);
                self.flat_select_caches
                    .entry(key)
                    .or_default()
                    .select(attrs, symbol)
                    .map_err(|source| match source {
                        FlatSelectError::Select(source) => {
                            TreeWalkError::new(TreeWalkErrorKind::AttrSelect { id, source }, span)
                        }
                        source => TreeWalkError::new(
                            TreeWalkErrorKind::FlatSelectCache { id, source },
                            span,
                        ),
                    })?
            }
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            EvalAttrsView::Packed(_) => {
                let select_outcome = attrs
                    .get(symbol)
                    .map(|value| AttrSelectOutcome::Hit {
                        value,
                        source: AttrSelectSource::Flat,
                    })
                    .unwrap_or(AttrSelectOutcome::Missing {
                        repr: AttrSelectRepr::Flat,
                    });
                self.increment_inline_cache_misses();
                self.record_slow_select_telemetry(id, span, &select_outcome);
                return Ok(select_outcome);
            }
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
        let attrs = self
            .heap
            .get_attrs_view(attrs_value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let outcome = match attrs {
            EvalAttrsView::Flat(attrs) => self
                .record_select_caches
                .entry(key)
                .or_default()
                .select(projected_shape, attrs, symbol)
                .map_err(|source| {
                    TreeWalkError::new(TreeWalkErrorKind::RecordSelectCache { id, source }, span)
                })?,
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            EvalAttrsView::Packed(_) => {
                let select_outcome = match attrs.symbol_slot(symbol).and_then(|slot| {
                    attrs
                        .entry_by_symbol(slot as usize)
                        .map(|entry| (slot, entry))
                }) {
                    Some((slot, entry)) => AttrSelectOutcome::Hit {
                        value: entry.value,
                        source: AttrSelectSource::Shaped { slot },
                    },
                    None => AttrSelectOutcome::Missing {
                        repr: AttrSelectRepr::Shaped,
                    },
                };
                self.increment_inline_cache_misses();
                self.record_slow_select_telemetry(id, span, &select_outcome);
                return Ok(select_outcome);
            }
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
            return self.select_flat_attr_with_cache(
                id,
                span,
                attrs_value,
                symbol,
                site,
                path_index,
            );
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
            .get_attrs_view(attrs_value)
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
        values.extend(attrs.iter_by_symbol().map(|entry| entry.value));
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
            let attrs = self.heap.get_attrs_view(attrs_value).map_err(|source| {
                TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
            })?;
            let hamt = match attrs {
                EvalAttrsView::Flat(attrs) => HamtAttrs::from_flat(attrs, &self.symbols),
                #[cfg(any(
                    feature = "compact_destination_probe",
                    feature = "evacuation_plan_probe"
                ))]
                EvalAttrsView::Packed(_) => {
                    let mut entries = Vec::new();
                    let reservation = entries.try_reserve_exact(attrs.len()).map_err(|_| {
                        HamtError::AllocationFailed {
                            entries: attrs.len(),
                        }
                    });
                    reservation.and_then(|()| {
                        entries.extend(attrs.iter_by_symbol());
                        HamtAttrs::new(entries, &self.symbols)
                    })
                }
            };
            hamt.map_err(|source| {
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

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
