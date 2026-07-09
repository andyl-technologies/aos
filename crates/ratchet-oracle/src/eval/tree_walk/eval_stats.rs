//! Mirrored evaluator statistics and tracing emission.

use super::*;

impl TreeWalk {
    pub(super) fn stats_snapshot(&self) -> EvalStats {
        let arena = self.heap.arena_stats();
        let permanent_arena = self.heap.permanent_arena_stats();
        let alloc_counters = self.heap.allocation_counters();
        let campaign = self.campaign_counters_snapshot();
        EvalStats {
            thunks_forced: self.stats.thunks_forced,
            thunks_allocated: self.stats.thunks_allocated,
            thunks_elided: self.stats.thunks_elided,
            binding_assembly_elisions: self.stats.binding_assembly_elisions,
            single_entry_thunks_allocated: self.stats.single_entry_thunks_allocated,
            single_entry_thunks_forced: self.stats.single_entry_thunks_forced,
            thunk_cache_hits: self.stats.thunk_cache_hits,
            inline_cache_hits: self.stats.inline_cache_hits,
            inline_cache_misses: self.stats.inline_cache_misses,
            shape_transitions: self.stats.shape_transitions,
            gc_bytes: self.stats.gc_bytes,
            gc_pause_us: self.stats.gc_pause_us,
            thunks_shed: alloc_counters.thunks_shed(),
            gc_sweeps: alloc_counters.gc_sweeps(),
            gc_records_swept: alloc_counters.gc_records_swept(),
            gc_sweeps_skipped_nonquiescent: self.gc_sweeps_skipped_nonquiescent,
            tier_promotions: self.stats.tier_promotions,
            deopts: self.stats.deopts,
            force_cache_hits: self.stats.force_cache_hits,
            force_cache_misses: self.stats.force_cache_misses,
            force_cache_memoization_admits: self.stats.force_cache_memoization_admits,
            force_cache_memoization_bypasses: self.stats.force_cache_memoization_bypasses,
            force_cache_materialization_materializes: self
                .stats
                .force_cache_materialization_materializes,
            force_cache_materialization_keeps_in_memory: self
                .stats
                .force_cache_materialization_keeps_in_memory,
            source_thunk_region_plan_decisions: self.stats.source_thunk_region_plan_decisions,
            source_thunk_region_plan_lexical_subregion_decisions: self
                .stats
                .source_thunk_region_plan_lexical_subregion_decisions,
            source_thunk_region_plan_conservative_fallbacks: self
                .stats
                .source_thunk_region_plan_conservative_fallbacks,
            cache_hits: self
                .stats
                .force_cache_hits
                .saturating_add(self.import_parse_cache_hits as u64)
                .saturating_add(self.find_file_cache_hits as u64),
            cache_misses: self
                .stats
                .force_cache_misses
                .saturating_add(self.import_parse_cache_misses as u64)
                .saturating_add(self.find_file_cache_misses as u64),
            early_cutoffs: self.stats.early_cutoffs,
            root_cutoffs: self.stats.root_cutoffs,
            derivation_aterm_path_reuses: self.stats.derivation_aterm_path_reuses,
            static_derivation_output_path_reuses: self.stats.static_derivation_output_path_reuses,
            derivation_hash_calculations: self.stats.derivation_hash_calculations,
            derivation_text_path_calculations: self.stats.derivation_text_path_calculations,
            heap_chunks: arena.chunks as u64,
            heap_reserved_bytes: arena.reserved_bytes as u64,
            heap_mapped_bytes: arena.mapped_bytes as u64,
            heap_used_bytes: arena.used_bytes as u64,
            permanent_heap_chunks: permanent_arena.chunks as u64,
            permanent_heap_reserved_bytes: permanent_arena.reserved_bytes as u64,
            permanent_heap_mapped_bytes: permanent_arena.mapped_bytes as u64,
            permanent_heap_used_bytes: permanent_arena.used_bytes as u64,
            heap_tier_b_admission_worker_records: self.stats.heap_tier_b_admission_worker_records,
            heap_tier_b_admission_permanent_shared_records: self
                .stats
                .heap_tier_b_admission_permanent_shared_records,
            heap_tier_b_admission_generation_rewrites: self
                .stats
                .heap_tier_b_admission_generation_rewrites,
            values_allocated: alloc_counters.values_allocated(),
            attrsets_built: alloc_counters.attrsets_built(),
            attrs_entries_total: alloc_counters.attrs_entries_total(),
            function_calls: self.stats.function_calls,
            hashcons_attempts: alloc_counters.hashcons_attempts(),
            hashcons_hits: alloc_counters.hashcons_hits(),
            symbols_interned: self.symbols.len() as u64,
            imports_evaluated: self.stats.imports_evaluated,
            tier1_promoted: self.stats.tier1_promoted,
            tier1_dispatched: self.stats.tier1_dispatched,
            tier1_deopted: self.stats.tier1_deopted,
            tier1_blacklisted: self.stats.tier1_blacklisted,
            tier2_promoted: self.stats.tier2_promoted,
            tier2_dispatched: self.stats.tier2_dispatched,
            tier2_deopted: self.stats.tier2_deopted,
            tier2_blacklisted: self.stats.tier2_blacklisted,
            memo_l0_hits: self.stats.memo_l0_hits,
            memo_l0_misses: self.stats.memo_l0_misses,
            memo_l0_admissions: self.stats.memo_l0_admissions,
            memo_l0_declines: self.stats.memo_l0_declines,
            memo_l1_hits: self.stats.memo_l1_hits,
            memo_l1_misses: self.stats.memo_l1_misses,
            memo_l1_admissions: self.stats.memo_l1_admissions,
            memo_l1_declines: self.stats.memo_l1_declines,
            memo_l2_secondary_hits: self.stats.memo_l2_secondary_hits,
            memo_l2_secondary_misses: self.stats.memo_l2_secondary_misses,
            memo_l2_promotions: self.stats.memo_l2_promotions,
            memo_l2_reval_failures: self.stats.memo_l2_reval_failures,
            memo_net_hits: self.stats.memo_net_hits,
            memo_net_misses: self.stats.memo_net_misses,
            memo_net_errors: self.stats.memo_net_errors,
            memo_net_reval_failures: self.stats.memo_net_reval_failures,
            campaign,
        }
    }

    /// Assembles the flat-value campaign counters (RFC-0007 doc 30 FV-0).
    ///
    /// Combines this evaluator's heap dereference counters, the heap's payload
    /// byte-mass counters, and the process-wide environment capture counters
    /// (as a delta from this evaluator's construction snapshot).
    fn campaign_counters_snapshot(&self) -> CampaignCounters {
        let deref = self.heap.deref_counters_snapshot();
        let alloc = self.heap.allocation_counters();
        let env = crate::eval::env::capture_stats::snapshot().delta_since(self.campaign_env_baseline);
        CampaignCounters {
            record_probes_string: deref.record_probes_string,
            record_probes_path: deref.record_probes_path,
            record_probes_list: deref.record_probes_list,
            record_probes_attrs: deref.record_probes_attrs,
            record_probes_lambda: deref.record_probes_lambda,
            record_probes_primop: deref.record_probes_primop,
            record_probes_thunk: deref.record_probes_thunk,
            record_probes_other: deref.record_probes_other,
            flat_string_resolutions: deref.flat_string_resolutions,
            flat_path_resolutions: deref.flat_path_resolutions,
            flat_list_resolutions: deref.flat_list_resolutions,
            flat_attrs_resolutions: deref.flat_attrs_resolutions,
            flat_thunk_resolutions: deref.flat_thunk_resolutions,
            flat_lambda_resolutions: deref.flat_lambda_resolutions,
            flat_primop_resolutions: deref.flat_primop_resolutions,
            payload_arc_clones: deref.payload_arc_clones,
            env_captures: env.env_captures,
            env_capture_frame_handles: env.env_capture_frame_handles,
            with_env_captures: env.with_env_captures,
            with_env_capture_scopes: env.with_env_capture_scopes,
            scoped_global_env_captures: env.scoped_global_env_captures,
            scoped_global_env_capture_scopes: env.scoped_global_env_capture_scopes,
            env_frame_allocs: env.env_frame_allocs,
            env_frame_slot_bytes: env.env_frame_slot_bytes,
            string_payload_bytes: alloc.string_payload_bytes,
            string_store_path_payload_bytes: alloc.string_store_path_payload_bytes,
            path_payload_bytes: alloc.path_payload_bytes,
            list_payload_elements: alloc.list_payload_elements,
            record_table_records: self.heap.record_count() as u64,
            flat_objects: self.heap.flat_object_count() as u64,
        }
    }

    pub(super) fn emit_stats_trace(stats: &EvalStats) {
        tracing::debug!(
            target: "aos_nix::eval::stats",
            thunks_forced = stats.thunks_forced(),
            thunks_allocated = stats.thunks_allocated(),
            thunks_elided = stats.thunks_elided(),
            binding_assembly_elisions = stats.binding_assembly_elisions(),
            single_entry_thunks_allocated = stats.single_entry_thunks_allocated(),
            single_entry_thunks_forced = stats.single_entry_thunks_forced(),
            thunk_cache_hits = stats.thunk_cache_hits(),
            inline_cache_hits = stats.inline_cache_hits(),
            inline_cache_misses = stats.inline_cache_misses(),
            shape_transitions = stats.shape_transitions(),
            gc_bytes = stats.gc_bytes(),
            gc_pause_us = stats.gc_pause_us(),
            thunks_shed = stats.thunks_shed(),
            gc_sweeps = stats.gc_sweeps(),
            gc_records_swept = stats.gc_records_swept(),
            gc_sweeps_skipped_nonquiescent = stats.gc_sweeps_skipped_nonquiescent(),
            tier_promotions = stats.tier_promotions(),
            deopts = stats.deopts(),
            tier1_promoted = stats.tier1_promoted(),
            tier1_dispatched = stats.tier1_dispatched(),
            tier1_deopted = stats.tier1_deopted(),
            tier1_blacklisted = stats.tier1_blacklisted(),
            tier2_promoted = stats.tier2_promoted(),
            tier2_dispatched = stats.tier2_dispatched(),
            tier2_deopted = stats.tier2_deopted(),
            tier2_blacklisted = stats.tier2_blacklisted(),
            memo_l0_hits = stats.memo_l0_hits(),
            memo_l0_misses = stats.memo_l0_misses(),
            memo_l0_admissions = stats.memo_l0_admissions(),
            memo_l0_declines = stats.memo_l0_declines(),
            memo_l1_hits = stats.memo_l1_hits(),
            memo_l1_misses = stats.memo_l1_misses(),
            memo_l1_admissions = stats.memo_l1_admissions(),
            memo_l1_declines = stats.memo_l1_declines(),
            force_cache_hits = stats.force_cache_hits(),
            force_cache_misses = stats.force_cache_misses(),
            force_cache_probes = stats.force_cache_probes(),
            force_cache_memoization_admits = stats.force_cache_memoization_admits(),
            force_cache_memoization_bypasses = stats.force_cache_memoization_bypasses(),
            force_cache_memoization_demands = stats.force_cache_memoization_demands(),
            force_cache_materialization_materializes = stats
                .force_cache_materialization_materializes(),
            force_cache_materialization_keeps_in_memory = stats
                .force_cache_materialization_keeps_in_memory(),
            force_cache_materialization_decisions = stats
                .force_cache_materialization_decisions(),
            source_thunk_region_plan_decisions = stats.source_thunk_region_plan_decisions(),
            source_thunk_region_plan_lexical_subregion_decisions = stats
                .source_thunk_region_plan_lexical_subregion_decisions(),
            source_thunk_region_plan_conservative_fallbacks = stats
                .source_thunk_region_plan_conservative_fallbacks(),
            cache_hits = stats.cache_hits(),
            cache_misses = stats.cache_misses(),
            early_cutoffs = stats.early_cutoffs(),
            derivation_aterm_path_reuses = stats.derivation_aterm_path_reuses(),
            static_derivation_output_path_reuses = stats.static_derivation_output_path_reuses(),
            derivation_hash_calculations = stats.derivation_hash_calculations(),
            derivation_text_path_calculations = stats.derivation_text_path_calculations(),
            heap_chunks = stats.heap_chunks(),
            heap_reserved_bytes = stats.heap_reserved_bytes(),
            heap_mapped_bytes = stats.heap_mapped_bytes(),
            heap_used_bytes = stats.heap_used_bytes(),
            permanent_heap_chunks = stats.permanent_heap_chunks(),
            permanent_heap_reserved_bytes = stats.permanent_heap_reserved_bytes(),
            permanent_heap_mapped_bytes = stats.permanent_heap_mapped_bytes(),
            permanent_heap_used_bytes = stats.permanent_heap_used_bytes(),
            heap_tier_b_admission_worker_records = stats.heap_tier_b_admission_worker_records(),
            heap_tier_b_admission_permanent_shared_records = stats
                .heap_tier_b_admission_permanent_shared_records(),
            heap_tier_b_admission_generation_rewrites = stats
                .heap_tier_b_admission_generation_rewrites(),
            "aos-nix tree-walk evaluation stats"
        );
    }

    pub(super) fn project_attr_update_merge(
        &self,
        id: IrId,
        span: Span,
        lhs: IrId,
        left_repr: AttrSetReprKind,
        left_len: usize,
        right_len: usize,
    ) -> Option<AttrUpdateMergeProjection> {
        let lhs_ref = (self.current_module.as_u32(), lhs.as_u32());
        let left_state = self
            .attr_update_node_states
            .get(&lhs_ref)
            .copied()
            .unwrap_or(AttrUpdateTelemetryState {
                override_chain_depth: 0,
                projected_repr: AttrSetReprKind::Flat,
            });
        let Some(override_chain_depth) = left_state.override_chain_depth.checked_add(1) else {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                "skipping attr update telemetry after override-chain depth overflow"
            );
            return None;
        };
        let policy = AttrSetReprPolicy::default();
        let construction = AttrSetConstruction::UpdateMerge {
            left_repr,
            left_len,
            right_len,
            override_chain_depth,
        };
        let decision = match policy.classify(construction) {
            Ok(decision) => decision,
            Err(source) => {
                tracing::debug!(
                    target: "aos_nix::eval::attr_telemetry",
                    node = id.as_u32(),
                    span_start = span.start,
                    span_end = span.end,
                    error = %source,
                    "skipping attr update telemetry after representation policy failure"
                );
                return None;
            }
        };

        Some(AttrUpdateMergeProjection {
            left_repr,
            override_chain_depth,
            decision,
        })
    }

    #[cfg(test)]
    pub(super) fn record_attr_update_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        lhs: IrId,
        left_len: usize,
        right_len: usize,
    ) {
        let lhs_ref = (self.current_module.as_u32(), lhs.as_u32());
        let left_repr = self
            .attr_update_node_states
            .get(&lhs_ref)
            .copied()
            .unwrap_or(AttrUpdateTelemetryState {
                override_chain_depth: 0,
                projected_repr: AttrSetReprKind::Flat,
            })
            .projected_repr;
        let Some(projection) =
            self.project_attr_update_merge(id, span, lhs, left_repr, left_len, right_len)
        else {
            return;
        };
        self.record_projected_attr_update_telemetry(
            id, span, left_len, right_len, projection, None,
        );
    }

    pub(super) fn record_projected_attr_update_telemetry(
        &mut self,
        id: IrId,
        span: Span,
        left_len: usize,
        right_len: usize,
        projection: AttrUpdateMergeProjection,
        hamt_summary: Option<HamtMergeSummary>,
    ) {
        if let Err(source) = self.attr_telemetry.record_update_merge(
            left_len,
            right_len,
            projection.override_chain_depth,
            projection.decision,
            hamt_summary,
        ) {
            tracing::debug!(
                target: "aos_nix::eval::attr_telemetry",
                node = id.as_u32(),
                span_start = span.start,
                span_end = span.end,
                error = %source,
                "skipping attr update telemetry after recording failure"
            );
            return;
        }

        let result_state = AttrUpdateTelemetryState {
            override_chain_depth: projection.override_chain_depth,
            projected_repr: projection.decision.kind(),
        };
        self.attr_update_node_states
            .insert((self.current_module.as_u32(), id.as_u32()), result_state);
    }

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
        if let Some((census_shape, transitions)) = shape_telemetry {
            self.record_projected_attr_shape_telemetry(id, span, &census_shape, transitions);
        }
        if let Some(decision) = decision {
            self.record_classified_attr_repr_decision_telemetry(id, span, construction, decision);
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

    pub(super) fn increment_thunks_forced(&mut self) {
        self.stats.thunks_forced = self.stats.thunks_forced.saturating_add(1);
    }

    /// Records one single-entry (cheap cell) thunk allocation.
    pub(super) fn increment_single_entry_thunks_allocated(&mut self) {
        self.stats.single_entry_thunks_allocated =
            self.stats.single_entry_thunks_allocated.saturating_add(1);
    }

    /// Records one force served by the single-entry direct path.
    pub(super) fn increment_single_entry_thunks_forced(&mut self) {
        self.stats.single_entry_thunks_forced =
            self.stats.single_entry_thunks_forced.saturating_add(1);
    }

    pub(crate) fn increment_tier1_promoted(&mut self) {
        self.stats.tier1_promoted = self.stats.tier1_promoted.saturating_add(1);
    }

    pub(crate) fn increment_tier1_dispatched(&mut self) {
        self.stats.tier1_dispatched = self.stats.tier1_dispatched.saturating_add(1);
    }

    pub(crate) fn increment_tier1_deopted(&mut self) {
        self.stats.tier1_deopted = self.stats.tier1_deopted.saturating_add(1);
    }

    pub(crate) fn increment_tier1_blacklisted(&mut self) {
        self.stats.tier1_blacklisted = self.stats.tier1_blacklisted.saturating_add(1);
    }

    pub(crate) fn increment_tier2_promoted(&mut self) {
        self.stats.tier2_promoted = self.stats.tier2_promoted.saturating_add(1);
    }

    pub(crate) fn increment_tier2_dispatched(&mut self) {
        self.stats.tier2_dispatched = self.stats.tier2_dispatched.saturating_add(1);
    }

    pub(crate) fn increment_tier2_deopted(&mut self) {
        self.stats.tier2_deopted = self.stats.tier2_deopted.saturating_add(1);
    }

    pub(crate) fn increment_tier2_blacklisted(&mut self) {
        self.stats.tier2_blacklisted = self.stats.tier2_blacklisted.saturating_add(1);
    }

    pub(super) fn increment_thunk_cache_hits(&mut self) {
        self.stats.thunk_cache_hits = self.stats.thunk_cache_hits.saturating_add(1);
    }

    pub(super) fn increment_eval_cache_hit(&mut self) {
        self.stats.force_cache_hits = self.stats.force_cache_hits.saturating_add(1);
    }

    pub(super) fn increment_eval_cache_miss(&mut self) {
        self.stats.force_cache_misses = self.stats.force_cache_misses.saturating_add(1);
    }

    pub(super) fn increment_force_cache_memoization_decision(
        &mut self,
        decision: MemoizationDecision,
    ) {
        match decision {
            MemoizationDecision::Admit => {
                self.stats.force_cache_memoization_admits =
                    self.stats.force_cache_memoization_admits.saturating_add(1);
            }
            MemoizationDecision::Bypass => {
                self.stats.force_cache_memoization_bypasses = self
                    .stats
                    .force_cache_memoization_bypasses
                    .saturating_add(1);
            }
        }
    }

    pub(super) fn increment_force_cache_materialization_decision(
        &mut self,
        decision: MaterializationDecision,
    ) {
        match decision {
            MaterializationDecision::Materialize => {
                self.stats.force_cache_materialization_materializes = self
                    .stats
                    .force_cache_materialization_materializes
                    .saturating_add(1);
            }
            MaterializationDecision::KeepInMemory => {
                self.stats.force_cache_materialization_keeps_in_memory = self
                    .stats
                    .force_cache_materialization_keeps_in_memory
                    .saturating_add(1);
            }
        }
    }

    pub(super) fn record_source_thunk_region_plan_decision(&mut self, plan: RegionPlan) {
        self.stats.source_thunk_region_plan_decisions = self
            .stats
            .source_thunk_region_plan_decisions
            .saturating_add(1);
        if matches!(plan.placement, RegionPlacement::LexicalSubregion) {
            self.stats
                .source_thunk_region_plan_lexical_subregion_decisions = self
                .stats
                .source_thunk_region_plan_lexical_subregion_decisions
                .saturating_add(1);
        }
        if matches!(plan.reason, RegionPlacementReason::ConservativeFallback) {
            self.stats.source_thunk_region_plan_conservative_fallbacks = self
                .stats
                .source_thunk_region_plan_conservative_fallbacks
                .saturating_add(1);
        }
    }

    pub(super) fn increment_early_cutoffs(&mut self) {
        self.stats.early_cutoffs = self.stats.early_cutoffs.saturating_add(1);
    }

    /// Records one value-level function application (lambda or builtin value).
    pub(super) fn increment_function_calls(&mut self) {
        self.stats.function_calls = self.stats.function_calls.saturating_add(1);
    }

    /// Records that one imported file was evaluated on an import-cache miss.
    pub(super) fn increment_imports_evaluated(&mut self) {
        self.stats.imports_evaluated = self.stats.imports_evaluated.saturating_add(1);
    }

    pub(super) fn increment_derivation_aterm_path_reuses(&mut self) {
        self.stats.derivation_aterm_path_reuses =
            self.stats.derivation_aterm_path_reuses.saturating_add(1);
    }

    pub(super) fn increment_static_derivation_output_path_reuses(&mut self) {
        self.stats.static_derivation_output_path_reuses = self
            .stats
            .static_derivation_output_path_reuses
            .saturating_add(1);
    }

    pub(super) fn increment_derivation_hash_calculations(&mut self) {
        self.stats.derivation_hash_calculations =
            self.stats.derivation_hash_calculations.saturating_add(1);
    }

    pub(super) fn increment_derivation_text_path_calculations(&mut self) {
        self.stats.derivation_text_path_calculations = self
            .stats
            .derivation_text_path_calculations
            .saturating_add(1);
    }
}
