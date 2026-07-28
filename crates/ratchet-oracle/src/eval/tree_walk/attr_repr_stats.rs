//! Attribute-representation decision telemetry (split from
//! eval_stats.rs, §2 cap). Re-opens `impl TreeWalk`.
use super::*;

impl TreeWalk {
    fn classify_attr_repr_decision(
        &self,
        id: IrId,
        span: Span,
        construction: AttrSetConstruction,
    ) -> Option<AttrSetReprDecision> {
        match AttrSetReprPolicy::default().classify(construction) {
            Ok(decision) => Some(decision),
            Err(source) => {
                tracing::debug!(
                    target: "aos_nix::eval::attr_telemetry",
                    node = id.as_u32(),
                    span_start = span.start,
                    span_end = span.end,
                    error = %source,
                    "skipping attr representation telemetry after policy failure"
                );
                None
            }
        }
    }

    fn record_classified_attr_repr_decision_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        construction: AttrSetConstruction,
        decision: AttrSetReprDecision,
    ) {
        if let Err(source) = self
            .attr_telemetry
            .record_repr_decision(construction, decision)
        {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                error = %source,
                "skipping attr representation telemetry after recording failure"
            );
        }
    }

    pub(super) fn project_flat_attr_shape_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        attrs: &FlatAttrs,
    ) -> Option<(ShapeHandle, u64)> {
        // Bail before touching the per-entry key buffer when no shape table is
        // active (`AttrShapeMode::Off`, or a demand-pool worker that never
        // adopted one): the projection has no consumer, so the key copy and
        // transition walk below would be pure dead work.
        let Some(shape_table) = self.shape_table.as_ref() else {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                "skipping flat attr shape-census telemetry because no shape table is active"
            );
            return None;
        };
        let mut shape = shape_table.empty();

        let mut keys = Vec::new();
        if keys.try_reserve_exact(attrs.len()).is_err() {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                entries = attrs.len(),
                "skipping flat attr shape-census telemetry after key-buffer allocation failure"
            );
            return None;
        }
        keys.extend(attrs.iter_source_order().map(|entry| entry.key));
        let mut transitions = 0u64;
        for key in keys {
            // Transitions route through the parallel-aware choke point: local
            // cached edges stay lock-free and new shapes intern into the
            // shared log first, so the projected id is global under a demand
            // pool and plain-local in serial mode.
            let transition = match self.shape_transition_insert_key_for_eval(&shape, key) {
                Ok(transition) => transition,
                Err(source) => {
                    tracing::debug!(
                        target: "aos_nix::eval::attr_telemetry",
                        node = id.as_u32(),
                        span_start = span.start,
                        span_end = span.end,
                        error = %source,
                        "skipping flat attr shape-census telemetry after shape projection failure"
                    );
                    return None;
                }
            };
            match transition {
                ShapeTableTransition::ExistingKey { parent, .. } => {
                    shape = parent;
                }
                ShapeTableTransition::AppendKey { child, cached, .. } => {
                    if !cached {
                        transitions = transitions.saturating_add(1);
                    }
                    shape = child;
                }
            }
        }
        Some((shape, transitions))
    }

    pub(super) fn record_projected_attr_shape_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        shape: &ShapeHandle,
        transitions: u64,
    ) {
        if transitions > 0 {
            self.stats.shape_transitions = self.stats.shape_transitions.saturating_add(transitions);
        }
        if let Err(source) = self.attr_telemetry.record_shape_instance(shape) {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                error = %source,
                "skipping flat attr shape-census telemetry after recording failure"
            );
        }
    }

    pub(super) fn alloc_flat_attrs_with_repr_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        shape: u32,
        attrs: FlatAttrs,
        construction: AttrSetConstruction,
    ) -> Result<Value, TreeWalkError> {
        if self.options.attr_shape_mode() == AttrShapeMode::Record {
            return self.alloc_flat_attrs_record_shape_mode(id, span, shape, attrs, construction);
        }
        let shape_telemetry = self.project_flat_attr_shape_telemetry(id, span, &attrs);
        let projected_shape = shape_telemetry.as_ref().map(|(shape, _)| shape.id());
        let decision = self.classify_attr_repr_decision(id, span, construction);
        let repr = decision.map_or(AttrSetReprKind::Flat, AttrSetReprDecision::kind);
        let value = self.alloc_tree_walk_attrs_with_projected_shape_metadata(
            id,
            span,
            shape,
            repr,
            projected_shape,
            attrs,
        )?;
        // The projected shape and representation kind above are load-bearing:
        // both are stored in the value's metadata and route later selects
        // (`select_static_attr_with_cache`). Only the census and
        // representation-decision *recording* below feed telemetry with no
        // consumer in production binaries, so gate them behind the per-merge
        // telemetry toggle exactly as
        // [`Self::alloc_flat_attrs_record_shape_mode`] does — while still
        // folding the transition count into `stats` so that counter stays
        // identical whether or not telemetry is recorded.
        if self.attr_update_telemetry_enabled {
            if let Some((census_shape, transitions)) = shape_telemetry {
                self.record_projected_attr_shape_telemetry(id, span, &census_shape, transitions);
            }
            if let Some(decision) = decision {
                self.record_classified_attr_repr_decision_telemetry(
                    id,
                    span,
                    construction,
                    decision,
                );
            }
        } else if let Some((_, transitions)) = shape_telemetry {
            if transitions > 0 {
                self.stats.shape_transitions =
                    self.stats.shape_transitions.saturating_add(transitions);
            }
        }
        Ok(value)
    }

    /// Allocates a flat attrset under [`AttrShapeMode::Record`].
    ///
    /// A static literal's key sequence is fixed at its construction site, so
    /// the transition-tree walk resolves once per `(module, node)` site and
    /// later allocations reuse the interned [`ShapeHandle`] without touching
    /// the transition tree (RFC-0007 §09 §4.2: compile-time shape resolution
    /// for static literals). Dynamic constructions walk the tree as usual.
    /// The census/representation telemetry re-walks stay behind the
    /// per-merge telemetry toggle, matching the production `//` policy.
    fn alloc_flat_attrs_record_shape_mode(
        &mut self,
        id: IrId,
        span: Span,
        shape: u32,
        attrs: FlatAttrs,
        construction: AttrSetConstruction,
    ) -> Result<Value, TreeWalkError> {
        let site = (self.current_module.as_u32(), id.as_u32());
        let is_static_literal = matches!(construction, AttrSetConstruction::StaticLiteral { .. });
        let memoized = if is_static_literal {
            self.static_literal_shapes.get(&site).cloned()
        } else {
            None
        };
        let shape_telemetry = match memoized {
            Some(handle) => {
                debug_assert_eq!(
                    handle.shape().len(),
                    attrs.len(),
                    "static literal site changed its key count"
                );
                Some((handle, 0))
            }
            None => {
                let projected = self.project_flat_attr_shape_telemetry(id, span, &attrs);
                if is_static_literal {
                    if let Some((handle, _)) = &projected {
                        self.static_literal_shapes.insert(site, handle.clone());
                    }
                }
                projected
            }
        };
        let projected_shape = shape_telemetry.as_ref().map(|(shape, _)| shape.id());
        let telemetry_enabled = self.attr_update_telemetry_enabled;
        let decision = if telemetry_enabled {
            self.classify_attr_repr_decision(id, span, construction)
        } else {
            None
        };
        let repr = decision.map_or(AttrSetReprKind::Flat, AttrSetReprDecision::kind);
        let value = self.alloc_tree_walk_attrs_with_projected_shape_metadata(
            id,
            span,
            shape,
            repr,
            projected_shape,
            attrs,
        )?;
        if telemetry_enabled {
            if let Some((census_shape, transitions)) = shape_telemetry {
                self.record_projected_attr_shape_telemetry(id, span, &census_shape, transitions);
            }
            if let Some(decision) = decision {
                self.record_classified_attr_repr_decision_telemetry(
                    id,
                    span,
                    construction,
                    decision,
                );
            }
        } else if let Some((_, transitions)) = shape_telemetry {
            if transitions > 0 {
                self.stats.shape_transitions =
                    self.stats.shape_transitions.saturating_add(transitions);
            }
        }
        Ok(value)
    }

    pub(super) fn record_slow_select_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        outcome: &AttrSelectOutcome,
    ) {
        if let Err(source) = self.attr_telemetry.record_slow_select_lookup(outcome) {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                error = %source,
                "skipping attr slow-select telemetry after recording failure"
            );
        }
    }

    pub(super) fn record_attr_order_parity_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        result: Result<(), AttrOrderError>,
    ) {
        let matched = match result {
            Ok(()) => true,
            Err(AttrOrderError::AllocationFailed { repr, entries }) => {
                tracing::debug!(
                    target: "aos_nix::eval::attr_telemetry",
                    node = id.as_u32(),
                    span_start = span.start,
                    span_end = span.end,
                    ?repr,
                    entries,
                    "skipping attr order-parity telemetry after key-buffer allocation failure"
                );
                return;
            }
            Err(source) => {
                tracing::debug!(
                    target: "aos_nix::eval::attr_telemetry",
                    node = id.as_u32(),
                    span_start = span.start,
                    span_end = span.end,
                    error = %source,
                    "recording attr order-parity mismatch"
                );
                false
            }
        };

        if let Err(source) = self.attr_telemetry.record_order_parity_check(matched) {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                error = %source,
                "skipping attr order-parity telemetry after recording failure"
            );
        }
    }

    pub(super) fn record_hamt_select_cache_lookup_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        outcome: &HamtSelectOutcome,
    ) {
        if let Err(source) = self.attr_telemetry.record_hamt_select_lookup(outcome) {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                error = %source,
                "skipping HAMT select-cache lookup telemetry after recording failure"
            );
        }
    }

    pub(super) fn record_shaped_select_cache_lookup_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        state: &ShapedSelectCacheState,
        outcome: &ShapedSelectOutcome,
    ) {
        if let Err(source) = self
            .attr_telemetry
            .record_shaped_select_lookup(state, outcome)
        {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                error = %source,
                "skipping shaped select-cache lookup telemetry after recording failure"
            );
        }
    }

    pub(super) fn record_attr_select_cache_site_telemetry(&mut self) {
        for cache in self.flat_select_caches.values() {
            if let Err(source) = self.attr_telemetry.record_flat_select_site(cache.state()) {
                tracing::debug!(
                    target: "aos_nix::eval::attr_telemetry",
                    error = %source,
                    "skipping flat select-cache terminal-state telemetry after recording failure"
                );
            }
        }
        for cache in self.shaped_select_caches.values() {
            if let Err(source) = self.attr_telemetry.record_shaped_select_site(cache.state()) {
                tracing::debug!(
                    target: "aos_nix::eval::attr_telemetry",
                    error = %source,
                    "skipping shaped select-cache terminal-state telemetry after recording failure"
                );
            }
        }
        for cache in self.hamt_select_caches.values() {
            if let Err(source) = self.attr_telemetry.record_hamt_select_site(cache.state()) {
                tracing::debug!(
                    target: "aos_nix::eval::attr_telemetry",
                    error = %source,
                    "skipping HAMT select-cache terminal-state telemetry after recording failure"
                );
            }
        }
    }

    pub(super) fn increment_inline_cache_hits(&mut self) {
        self.stats.inline_cache_hits = self.stats.inline_cache_hits.saturating_add(1);
    }

    pub(super) fn increment_inline_cache_misses(&mut self) {
        self.stats.inline_cache_misses = self.stats.inline_cache_misses.saturating_add(1);
    }

    pub(super) fn increment_thunks_allocated(&mut self) {
        self.stats.thunks_allocated = self.stats.thunks_allocated.saturating_add(1);
    }

    pub(super) fn increment_thunks_elided(&mut self) {
        self.stats.thunks_elided = self.stats.thunks_elided.saturating_add(1);
    }

    /// Records one assembly-proof elision: an order-sensitive binding whose
    /// body was evaluated directly into its slot instead of a lazy thunk.
    pub(super) fn increment_binding_assembly_elisions(&mut self) {
        self.stats.binding_assembly_elisions =
            self.stats.binding_assembly_elisions.saturating_add(1);
    }

    /// Records one demand-position local-variable alias retained solely for
    /// active force-cache observation.
    pub(super) fn increment_force_cache_suppressed_local_var_alias_thunks(&mut self) {
        self.stats.force_cache_suppressed_lexical_alias_thunks = self
            .stats
            .force_cache_suppressed_lexical_alias_thunks
            .saturating_add(1);
        self.stats.force_cache_suppressed_local_var_alias_thunks = self
            .stats
            .force_cache_suppressed_local_var_alias_thunks
            .saturating_add(1);
    }

    /// Records one demand-position upvalue alias retained solely for active
    /// force-cache observation.
    pub(super) fn increment_force_cache_suppressed_upval_var_alias_thunks(&mut self) {
        self.stats.force_cache_suppressed_lexical_alias_thunks = self
            .stats
            .force_cache_suppressed_lexical_alias_thunks
            .saturating_add(1);
        self.stats.force_cache_suppressed_upval_var_alias_thunks = self
            .stats
            .force_cache_suppressed_upval_var_alias_thunks
            .saturating_add(1);
    }

    pub(super) fn increment_thunks_forced(&mut self) {
        self.stats.thunks_forced = self.stats.thunks_forced.saturating_add(1);
    }

    /// Records one single-entry (cheap cell) thunk allocation.
    pub(super) fn increment_single_entry_thunks_allocated(&mut self) {
        self.stats.single_entry_thunks_allocated =
            self.stats.single_entry_thunks_allocated.saturating_add(1);
    }
}
