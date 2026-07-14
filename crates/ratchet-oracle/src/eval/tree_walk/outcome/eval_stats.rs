//! Evaluation statistics counters and their merge/snapshot operations.

use super::*;

/// Mirrored native-evaluator counters aligned with the RFC-0007 stats schema.
///
/// Fields without an implementation yet stay present and zero so downstream
/// tracing consumers can rely on stable field names while later slices add GC,
/// promotions, deopts, and early-cutoff cache behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalStats {
    pub(crate) thunks_forced: u64,
    pub(crate) thunks_allocated: u64,
    pub(crate) thunks_elided: u64,
    pub(crate) binding_assembly_elisions: u64,
    /// Thunks allocated with single-entry storage (no update, no blackhole,
    /// no parallel payload cell) under the C-8 frame-local proof.
    pub(crate) single_entry_thunks_allocated: u64,
    /// Forces served by the single-entry direct-evaluation path.
    pub(crate) single_entry_thunks_forced: u64,
    pub(crate) thunk_cache_hits: u64,
    pub(crate) inline_cache_hits: u64,
    pub(crate) inline_cache_misses: u64,
    pub(crate) shape_transitions: u64,
    pub(crate) gc_bytes: u64,
    pub(crate) gc_pause_us: u64,
    /// Forced thunks whose captures were shed by `AOS_NIX_GC=sweep`.
    pub(crate) thunks_shed: u64,
    /// Tier-B quiescent sweep cycles performed.
    pub(crate) gc_sweeps: u64,
    /// Worker heap records retired across all Tier-B sweep cycles.
    pub(crate) gc_records_swept: u64,
    /// Quiescent-sweep requests declined because the evaluator was not quiescent.
    pub(crate) gc_sweeps_skipped_nonquiescent: u64,
    pub(crate) tier_promotions: u64,
    pub(crate) deopts: u64,
    pub(crate) force_cache_hits: u64,
    pub(crate) force_cache_misses: u64,
    pub(crate) force_cache_memoization_admits: u64,
    pub(crate) force_cache_memoization_bypasses: u64,
    pub(crate) force_cache_materialization_materializes: u64,
    pub(crate) force_cache_materialization_keeps_in_memory: u64,
    pub(crate) source_thunk_region_plan_decisions: u64,
    pub(crate) source_thunk_region_plan_lexical_subregion_decisions: u64,
    pub(crate) source_thunk_region_plan_conservative_fallbacks: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) early_cutoffs: u64,
    pub(crate) root_cutoffs: u64,
    pub(crate) derivation_aterm_path_reuses: u64,
    pub(crate) static_derivation_output_path_reuses: u64,
    pub(crate) derivation_hash_calculations: u64,
    pub(crate) derivation_text_path_calculations: u64,
    pub(crate) heap_chunks: u64,
    pub(crate) heap_reserved_bytes: u64,
    pub(crate) heap_mapped_bytes: u64,
    pub(crate) heap_used_bytes: u64,
    pub(crate) permanent_heap_chunks: u64,
    pub(crate) permanent_heap_reserved_bytes: u64,
    pub(crate) permanent_heap_mapped_bytes: u64,
    pub(crate) permanent_heap_used_bytes: u64,
    pub(crate) heap_tier_b_admission_worker_records: u64,
    pub(crate) heap_tier_b_admission_permanent_shared_records: u64,
    pub(crate) heap_tier_b_admission_generation_rewrites: u64,
    pub(crate) values_allocated: u64,
    pub(crate) attrsets_built: u64,
    pub(crate) attrs_entries_total: u64,
    pub(crate) function_calls: u64,
    pub(crate) hashcons_attempts: u64,
    pub(crate) hashcons_hits: u64,
    pub(crate) symbols_interned: u64,
    /// Estimated resident heap bytes of the live symbol table (interned strings
    /// stored twice, plus `Vec`/`BTreeMap` overhead and the rank view). A memory
    /// campaign L0 attribution gauge, not an exact allocator figure.
    pub(crate) symbol_table_resident_bytes: u64,
    pub(crate) imports_evaluated: u64,
    /// Nanoseconds spent in `parse_bytes_with_symbols` across imports, accumulated
    /// only under `AOS_NIX_EVAL_STATS`. Part of the RFC-0007 Tier-1a front-end
    /// share measurement (parse/lower is ~25% of cold eval).
    pub(crate) front_end_parse_nanos: u64,
    /// Nanoseconds spent in scope resolution across imports (`AOS_NIX_EVAL_STATS`).
    pub(crate) front_end_resolve_nanos: u64,
    /// Nanoseconds spent lowering resolved ASTs to IR across imports
    /// (`AOS_NIX_EVAL_STATS`).
    pub(crate) front_end_lower_nanos: u64,
    /// Nanoseconds spent in import IR analysis/annotation across imports
    /// (`AOS_NIX_EVAL_STATS`).
    pub(crate) front_end_annotate_nanos: u64,
    /// Forces whose thunk evaluates prelude (`lib`/`stdenv`) code, accumulated only
    /// under `AOS_NIX_EVAL_STATS`. The ratio to `thunks_forced` is the primary
    /// prelude-force-share signal gating heap-image snapshots (RFC-0007 task #6).
    pub(crate) prelude_thunks_forced: u64,
    /// Inclusive nanoseconds spent evaluating thunk bodies whose code is prelude
    /// (`AOS_NIX_EVAL_STATS`). A proxy only: nested forces are double-counted, so
    /// trust the ratio to `all_force_nanos` (bracketed identically), not the
    /// absolute value.
    pub(crate) prelude_force_nanos: u64,
    /// Inclusive nanoseconds spent evaluating all thunk bodies
    /// (`AOS_NIX_EVAL_STATS`); the denominator for the `prelude_force_nanos` ratio.
    pub(crate) all_force_nanos: u64,
    pub(crate) tier1_promoted: u64,
    pub(crate) tier1_dispatched: u64,
    pub(crate) tier1_deopted: u64,
    pub(crate) tier1_blacklisted: u64,
    pub(crate) tier2_promoted: u64,
    pub(crate) tier2_dispatched: u64,
    pub(crate) tier2_deopted: u64,
    pub(crate) tier2_blacklisted: u64,
    pub(crate) memo_l0_hits: u64,
    pub(crate) memo_l0_misses: u64,
    pub(crate) memo_l0_admissions: u64,
    pub(crate) memo_l0_declines: u64,
    pub(crate) memo_l1_hits: u64,
    pub(crate) memo_l1_misses: u64,
    pub(crate) memo_l1_admissions: u64,
    pub(crate) memo_l1_declines: u64,
    pub(crate) memo_l2_secondary_hits: u64,
    pub(crate) memo_l2_secondary_misses: u64,
    pub(crate) memo_l2_promotions: u64,
    pub(crate) memo_l2_reval_failures: u64,
    pub(crate) memo_net_hits: u64,
    pub(crate) memo_net_misses: u64,
    pub(crate) memo_net_errors: u64,
    pub(crate) memo_net_reval_failures: u64,
    pub(crate) memo_economics: MemoEconomicsStats,
    /// Flat-value campaign work-volume counters (RFC-0007 doc 30 FV-0).
    pub(crate) campaign: CampaignCounters,
}

impl EvalStats {
    /// Returns the number of thunks that performed suspended work.
    pub const fn thunks_forced(&self) -> u64 {
        self.thunks_forced
    }

    /// Returns the number of suspended thunk heap records allocated.
    pub const fn thunks_allocated(&self) -> u64 {
        self.thunks_allocated
    }

    /// Returns the number of planned thunk allocations elided by later tiers.
    pub const fn thunks_elided(&self) -> u64 {
        self.thunks_elided
    }

    /// Returns the number of elided thunks whose bodies were evaluated
    /// directly into their slots during order-sensitive binding assembly
    /// under the analysis' per-frame assembly proof (a subset of
    /// [`Self::thunks_elided`]).
    pub const fn binding_assembly_elisions(&self) -> u64 {
        self.binding_assembly_elisions
    }

    /// Returns the number of thunks allocated with single-entry storage.
    ///
    /// Single-entry thunks skip the update write-back, the blackhole
    /// transition, and the parallel payload cell; they are admitted only
    /// under the C-8 frame-local once-entered proof.
    pub const fn single_entry_thunks_allocated(&self) -> u64 {
        self.single_entry_thunks_allocated
    }

    /// Returns the number of forces served by the single-entry direct path.
    pub const fn single_entry_thunks_forced(&self) -> u64 {
        self.single_entry_thunks_forced
    }

    /// Returns the number of already-forced thunk cell reuses.
    pub const fn thunk_cache_hits(&self) -> u64 {
        self.thunk_cache_hits
    }

    /// Returns the number of inline-cache hits reported by active evaluator tiers.
    pub const fn inline_cache_hits(&self) -> u64 {
        self.inline_cache_hits
    }

    /// Returns the number of inline-cache misses reported by active evaluator tiers.
    pub const fn inline_cache_misses(&self) -> u64 {
        self.inline_cache_misses
    }

    /// Returns the number of object-shape transition edges observed by active tiers.
    pub const fn shape_transitions(&self) -> u64 {
        self.shape_transitions
    }

    /// Returns bytes reclaimed or scanned by a future GC subsystem.
    pub const fn gc_bytes(&self) -> u64 {
        self.gc_bytes
    }

    /// Returns microseconds spent in a future GC subsystem.
    pub const fn gc_pause_us(&self) -> u64 {
        self.gc_pause_us
    }

    /// Returns forced thunks whose captures were shed by `AOS_NIX_GC=sweep`.
    pub const fn thunks_shed(&self) -> u64 {
        self.thunks_shed
    }

    /// Returns Tier-B quiescent sweep cycles performed.
    pub const fn gc_sweeps(&self) -> u64 {
        self.gc_sweeps
    }

    /// Returns worker heap records retired across all Tier-B sweep cycles.
    pub const fn gc_records_swept(&self) -> u64 {
        self.gc_records_swept
    }

    /// Returns quiescent-sweep requests declined for lack of quiescence.
    pub const fn gc_sweeps_skipped_nonquiescent(&self) -> u64 {
        self.gc_sweeps_skipped_nonquiescent
    }

    /// Returns the number of promotions into optimized evaluator tiers.
    pub const fn tier_promotions(&self) -> u64 {
        self.tier_promotions
    }

    /// Returns the number of optimized-tier deoptimizations.
    pub const fn deopts(&self) -> u64 {
        self.deopts
    }

    /// Returns the number of advisory force-cache hits.
    pub const fn force_cache_hits(&self) -> u64 {
        self.force_cache_hits
    }

    /// Returns the number of advisory force-cache misses.
    pub const fn force_cache_misses(&self) -> u64 {
        self.force_cache_misses
    }

    /// Returns the number of advisory force-cache probes.
    pub const fn force_cache_probes(&self) -> u64 {
        self.force_cache_hits
            .saturating_add(self.force_cache_misses)
    }

    /// Returns force-cache memoization-policy decisions that admitted memoization.
    pub const fn force_cache_memoization_admits(&self) -> u64 {
        self.force_cache_memoization_admits
    }

    /// Returns force-cache memoization-policy decisions that bypassed memoization.
    pub const fn force_cache_memoization_bypasses(&self) -> u64 {
        self.force_cache_memoization_bypasses
    }

    /// Returns force-cache memoization-policy demands with a recorded decision.
    pub const fn force_cache_memoization_demands(&self) -> u64 {
        self.force_cache_memoization_admits
            .saturating_add(self.force_cache_memoization_bypasses)
    }

    /// Returns force-cache materialization decisions that selected durable storage.
    pub const fn force_cache_materialization_materializes(&self) -> u64 {
        self.force_cache_materialization_materializes
    }

    /// Returns force-cache materialization decisions that kept payloads in memory.
    pub const fn force_cache_materialization_keeps_in_memory(&self) -> u64 {
        self.force_cache_materialization_keeps_in_memory
    }

    /// Returns force-cache materialization threshold decisions.
    pub const fn force_cache_materialization_decisions(&self) -> u64 {
        self.force_cache_materialization_materializes
            .saturating_add(self.force_cache_materialization_keeps_in_memory)
    }

    /// Returns region-placement policy decisions sampled at source thunk allocations.
    pub const fn source_thunk_region_plan_decisions(&self) -> u64 {
        self.source_thunk_region_plan_decisions
    }

    /// Returns sampled source thunk decisions that selected a lexical subregion candidate.
    pub const fn source_thunk_region_plan_lexical_subregion_decisions(&self) -> u64 {
        self.source_thunk_region_plan_lexical_subregion_decisions
    }

    /// Returns sampled source thunk decisions that failed closed to the active runtime tier.
    pub const fn source_thunk_region_plan_conservative_fallbacks(&self) -> u64 {
        self.source_thunk_region_plan_conservative_fallbacks
    }

    /// Returns the aggregate number of evaluator cache hits.
    pub const fn cache_hits(&self) -> u64 {
        self.cache_hits
    }

    /// Returns the aggregate number of evaluator cache misses.
    pub const fn cache_misses(&self) -> u64 {
        self.cache_misses
    }

    /// Returns the number of incremental-cache early cutoffs.
    pub const fn early_cutoffs(&self) -> u64 {
        self.early_cutoffs
    }

    /// Returns the number of root-level early cutoffs served without evaluation.
    ///
    /// A root cutoff answers an entire `instantiate(file, attr)` request from a
    /// durable root record after revalidating its transitive impure inputs,
    /// skipping parse, lowering, and evaluation. This counter is one for a
    /// closure re-emitted from such a record and zero for a normal evaluation.
    pub const fn root_cutoffs(&self) -> u64 {
        self.root_cutoffs
    }

    /// Returns evaluator counters describing a root-level early cutoff.
    ///
    /// The returned stats carry a single [`Self::root_cutoffs`] and are
    /// otherwise zero, reflecting that no thunks were forced, no heap was
    /// allocated, and no cache probes were performed because the closure was
    /// re-emitted from a durable root record without evaluation.
    #[must_use]
    pub fn for_root_cutoff() -> Self {
        Self {
            root_cutoffs: 1,
            ..Self::default()
        }
    }

    /// Returns records served from a secondary L2 disk location.
    pub const fn memo_l2_secondary_hits(&self) -> u64 {
        self.memo_l2_secondary_hits
    }

    /// Returns probes that consulted secondaries and missed on every disk location.
    pub const fn memo_l2_secondary_misses(&self) -> u64 {
        self.memo_l2_secondary_misses
    }

    /// Returns records copied into the primary location after a slower-tier hit.
    pub const fn memo_l2_promotions(&self) -> u64 {
        self.memo_l2_promotions
    }

    /// Returns disk-tier records rejected by impure-input slice revalidation.
    pub const fn memo_l2_reval_failures(&self) -> u64 {
        self.memo_l2_reval_failures
    }

    /// Returns records fetched, validated, and accepted from the network tier.
    pub const fn memo_net_hits(&self) -> u64 {
        self.memo_net_hits
    }

    /// Returns network probes answered with "no such record".
    pub const fn memo_net_misses(&self) -> u64 {
        self.memo_net_misses
    }

    /// Returns network probes that failed at the transport or validation layer.
    pub const fn memo_net_errors(&self) -> u64 {
        self.memo_net_errors
    }

    /// Returns network records rejected by local impure-input revalidation.
    pub const fn memo_net_reval_failures(&self) -> u64 {
        self.memo_net_reval_failures
    }

    /// Folds durable-tier memo events observed outside the evaluator into
    /// these counters.
    ///
    /// The root-cutoff fast path answers without constructing an evaluator,
    /// so its L2/L3 probe outcomes arrive as a [`MemoTierEvents`] snapshot
    /// after the fact. Every field is combined with saturating addition.
    pub fn merge_memo_tier_events(&mut self, events: &MemoTierEvents) {
        let MemoTierEvents {
            l2_secondary_hits,
            l2_secondary_misses,
            l2_promotions,
            l2_reval_failures,
            net_hits,
            net_misses,
            net_errors,
            net_reval_failures,
        } = *events;
        self.memo_l2_secondary_hits = self
            .memo_l2_secondary_hits
            .saturating_add(l2_secondary_hits);
        self.memo_l2_secondary_misses = self
            .memo_l2_secondary_misses
            .saturating_add(l2_secondary_misses);
        self.memo_l2_promotions = self.memo_l2_promotions.saturating_add(l2_promotions);
        self.memo_l2_reval_failures = self
            .memo_l2_reval_failures
            .saturating_add(l2_reval_failures);
        self.memo_net_hits = self.memo_net_hits.saturating_add(net_hits);
        self.memo_net_misses = self.memo_net_misses.saturating_add(net_misses);
        self.memo_net_errors = self.memo_net_errors.saturating_add(net_errors);
        self.memo_net_reval_failures = self
            .memo_net_reval_failures
            .saturating_add(net_reval_failures);
    }

    /// Accumulates another evaluator's counters into this one.
    ///
    /// Parallel evaluation keeps per-worker [`EvalStats`] and merges them into
    /// one report after all workers join. Every field is combined with
    /// saturating addition: event counters sum naturally, and the heap gauge
    /// fields (`heap_*`/`permanent_heap_*`) become the total across all worker
    /// heaps, which is the meaningful resident-footprint figure for one shared
    /// evaluation. The destructuring is exhaustive so a newly added counter
    /// cannot be silently dropped from the merge.
    pub fn merge_from(&mut self, other: &Self) {
        let Self {
            thunks_forced,
            thunks_allocated,
            thunks_elided,
            binding_assembly_elisions,
            single_entry_thunks_allocated,
            single_entry_thunks_forced,
            thunk_cache_hits,
            inline_cache_hits,
            inline_cache_misses,
            shape_transitions,
            gc_bytes,
            gc_pause_us,
            thunks_shed,
            gc_sweeps,
            gc_records_swept,
            gc_sweeps_skipped_nonquiescent,
            tier_promotions,
            deopts,
            force_cache_hits,
            force_cache_misses,
            force_cache_memoization_admits,
            force_cache_memoization_bypasses,
            force_cache_materialization_materializes,
            force_cache_materialization_keeps_in_memory,
            source_thunk_region_plan_decisions,
            source_thunk_region_plan_lexical_subregion_decisions,
            source_thunk_region_plan_conservative_fallbacks,
            cache_hits,
            cache_misses,
            early_cutoffs,
            root_cutoffs,
            derivation_aterm_path_reuses,
            static_derivation_output_path_reuses,
            derivation_hash_calculations,
            derivation_text_path_calculations,
            heap_chunks,
            heap_reserved_bytes,
            heap_mapped_bytes,
            heap_used_bytes,
            permanent_heap_chunks,
            permanent_heap_reserved_bytes,
            permanent_heap_mapped_bytes,
            permanent_heap_used_bytes,
            heap_tier_b_admission_worker_records,
            heap_tier_b_admission_permanent_shared_records,
            heap_tier_b_admission_generation_rewrites,
            values_allocated,
            attrsets_built,
            attrs_entries_total,
            function_calls,
            hashcons_attempts,
            hashcons_hits,
            symbols_interned,
            symbol_table_resident_bytes,
            imports_evaluated,
            front_end_parse_nanos,
            front_end_resolve_nanos,
            front_end_lower_nanos,
            front_end_annotate_nanos,
            prelude_thunks_forced,
            prelude_force_nanos,
            all_force_nanos,
            tier1_promoted,
            tier1_dispatched,
            tier1_deopted,
            tier1_blacklisted,
            tier2_promoted,
            tier2_dispatched,
            tier2_deopted,
            tier2_blacklisted,
            memo_l0_hits,
            memo_l0_misses,
            memo_l0_admissions,
            memo_l0_declines,
            memo_l1_hits,
            memo_l1_misses,
            memo_l1_admissions,
            memo_l1_declines,
            memo_l2_secondary_hits,
            memo_l2_secondary_misses,
            memo_l2_promotions,
            memo_l2_reval_failures,
            memo_net_hits,
            memo_net_misses,
            memo_net_errors,
            memo_net_reval_failures,
            memo_economics,
            campaign,
        } = *other;
        self.thunks_forced = self.thunks_forced.saturating_add(thunks_forced);
        self.thunks_allocated = self.thunks_allocated.saturating_add(thunks_allocated);
        self.thunks_elided = self.thunks_elided.saturating_add(thunks_elided);
        self.binding_assembly_elisions = self
            .binding_assembly_elisions
            .saturating_add(binding_assembly_elisions);
        self.single_entry_thunks_allocated = self
            .single_entry_thunks_allocated
            .saturating_add(single_entry_thunks_allocated);
        self.single_entry_thunks_forced = self
            .single_entry_thunks_forced
            .saturating_add(single_entry_thunks_forced);
        self.thunk_cache_hits = self.thunk_cache_hits.saturating_add(thunk_cache_hits);
        self.inline_cache_hits = self.inline_cache_hits.saturating_add(inline_cache_hits);
        self.inline_cache_misses = self.inline_cache_misses.saturating_add(inline_cache_misses);
        self.shape_transitions = self.shape_transitions.saturating_add(shape_transitions);
        self.gc_bytes = self.gc_bytes.saturating_add(gc_bytes);
        self.gc_pause_us = self.gc_pause_us.saturating_add(gc_pause_us);
        self.thunks_shed = self.thunks_shed.saturating_add(thunks_shed);
        self.gc_sweeps = self.gc_sweeps.saturating_add(gc_sweeps);
        self.gc_records_swept = self.gc_records_swept.saturating_add(gc_records_swept);
        self.gc_sweeps_skipped_nonquiescent = self
            .gc_sweeps_skipped_nonquiescent
            .saturating_add(gc_sweeps_skipped_nonquiescent);
        self.tier_promotions = self.tier_promotions.saturating_add(tier_promotions);
        self.deopts = self.deopts.saturating_add(deopts);
        self.force_cache_hits = self.force_cache_hits.saturating_add(force_cache_hits);
        self.force_cache_misses = self.force_cache_misses.saturating_add(force_cache_misses);
        self.force_cache_memoization_admits = self
            .force_cache_memoization_admits
            .saturating_add(force_cache_memoization_admits);
        self.force_cache_memoization_bypasses = self
            .force_cache_memoization_bypasses
            .saturating_add(force_cache_memoization_bypasses);
        self.force_cache_materialization_materializes = self
            .force_cache_materialization_materializes
            .saturating_add(force_cache_materialization_materializes);
        self.force_cache_materialization_keeps_in_memory = self
            .force_cache_materialization_keeps_in_memory
            .saturating_add(force_cache_materialization_keeps_in_memory);
        self.source_thunk_region_plan_decisions = self
            .source_thunk_region_plan_decisions
            .saturating_add(source_thunk_region_plan_decisions);
        self.source_thunk_region_plan_lexical_subregion_decisions = self
            .source_thunk_region_plan_lexical_subregion_decisions
            .saturating_add(source_thunk_region_plan_lexical_subregion_decisions);
        self.source_thunk_region_plan_conservative_fallbacks = self
            .source_thunk_region_plan_conservative_fallbacks
            .saturating_add(source_thunk_region_plan_conservative_fallbacks);
        self.cache_hits = self.cache_hits.saturating_add(cache_hits);
        self.cache_misses = self.cache_misses.saturating_add(cache_misses);
        self.early_cutoffs = self.early_cutoffs.saturating_add(early_cutoffs);
        self.root_cutoffs = self.root_cutoffs.saturating_add(root_cutoffs);
        self.derivation_aterm_path_reuses = self
            .derivation_aterm_path_reuses
            .saturating_add(derivation_aterm_path_reuses);
        self.static_derivation_output_path_reuses = self
            .static_derivation_output_path_reuses
            .saturating_add(static_derivation_output_path_reuses);
        self.derivation_hash_calculations = self
            .derivation_hash_calculations
            .saturating_add(derivation_hash_calculations);
        self.derivation_text_path_calculations = self
            .derivation_text_path_calculations
            .saturating_add(derivation_text_path_calculations);
        self.heap_chunks = self.heap_chunks.saturating_add(heap_chunks);
        self.heap_reserved_bytes = self.heap_reserved_bytes.saturating_add(heap_reserved_bytes);
        self.heap_mapped_bytes = self.heap_mapped_bytes.saturating_add(heap_mapped_bytes);
        self.heap_used_bytes = self.heap_used_bytes.saturating_add(heap_used_bytes);
        self.permanent_heap_chunks = self
            .permanent_heap_chunks
            .saturating_add(permanent_heap_chunks);
        self.permanent_heap_reserved_bytes = self
            .permanent_heap_reserved_bytes
            .saturating_add(permanent_heap_reserved_bytes);
        self.permanent_heap_mapped_bytes = self
            .permanent_heap_mapped_bytes
            .saturating_add(permanent_heap_mapped_bytes);
        self.permanent_heap_used_bytes = self
            .permanent_heap_used_bytes
            .saturating_add(permanent_heap_used_bytes);
        self.heap_tier_b_admission_worker_records = self
            .heap_tier_b_admission_worker_records
            .saturating_add(heap_tier_b_admission_worker_records);
        self.heap_tier_b_admission_permanent_shared_records = self
            .heap_tier_b_admission_permanent_shared_records
            .saturating_add(heap_tier_b_admission_permanent_shared_records);
        self.heap_tier_b_admission_generation_rewrites = self
            .heap_tier_b_admission_generation_rewrites
            .saturating_add(heap_tier_b_admission_generation_rewrites);
        self.values_allocated = self.values_allocated.saturating_add(values_allocated);
        self.attrsets_built = self.attrsets_built.saturating_add(attrsets_built);
        self.attrs_entries_total = self.attrs_entries_total.saturating_add(attrs_entries_total);
        self.function_calls = self.function_calls.saturating_add(function_calls);
        self.hashcons_attempts = self.hashcons_attempts.saturating_add(hashcons_attempts);
        self.hashcons_hits = self.hashcons_hits.saturating_add(hashcons_hits);
        self.symbols_interned = self.symbols_interned.saturating_add(symbols_interned);
        self.symbol_table_resident_bytes = self
            .symbol_table_resident_bytes
            .saturating_add(symbol_table_resident_bytes);
        self.imports_evaluated = self.imports_evaluated.saturating_add(imports_evaluated);
        self.front_end_parse_nanos = self
            .front_end_parse_nanos
            .saturating_add(front_end_parse_nanos);
        self.front_end_resolve_nanos = self
            .front_end_resolve_nanos
            .saturating_add(front_end_resolve_nanos);
        self.front_end_lower_nanos = self
            .front_end_lower_nanos
            .saturating_add(front_end_lower_nanos);
        self.front_end_annotate_nanos = self
            .front_end_annotate_nanos
            .saturating_add(front_end_annotate_nanos);
        self.prelude_thunks_forced = self
            .prelude_thunks_forced
            .saturating_add(prelude_thunks_forced);
        self.prelude_force_nanos = self.prelude_force_nanos.saturating_add(prelude_force_nanos);
        self.all_force_nanos = self.all_force_nanos.saturating_add(all_force_nanos);
        self.tier1_promoted = self.tier1_promoted.saturating_add(tier1_promoted);
        self.tier1_dispatched = self.tier1_dispatched.saturating_add(tier1_dispatched);
        self.tier1_deopted = self.tier1_deopted.saturating_add(tier1_deopted);
        self.tier1_blacklisted = self.tier1_blacklisted.saturating_add(tier1_blacklisted);
        self.tier2_promoted = self.tier2_promoted.saturating_add(tier2_promoted);
        self.tier2_dispatched = self.tier2_dispatched.saturating_add(tier2_dispatched);
        self.tier2_deopted = self.tier2_deopted.saturating_add(tier2_deopted);
        self.tier2_blacklisted = self.tier2_blacklisted.saturating_add(tier2_blacklisted);
        self.memo_l0_hits = self.memo_l0_hits.saturating_add(memo_l0_hits);
        self.memo_l0_misses = self.memo_l0_misses.saturating_add(memo_l0_misses);
        self.memo_l0_admissions = self.memo_l0_admissions.saturating_add(memo_l0_admissions);
        self.memo_l0_declines = self.memo_l0_declines.saturating_add(memo_l0_declines);
        self.memo_l1_hits = self.memo_l1_hits.saturating_add(memo_l1_hits);
        self.memo_l1_misses = self.memo_l1_misses.saturating_add(memo_l1_misses);
        self.memo_l1_admissions = self.memo_l1_admissions.saturating_add(memo_l1_admissions);
        self.memo_l1_declines = self.memo_l1_declines.saturating_add(memo_l1_declines);
        self.memo_economics = self.memo_economics.merged(memo_economics);
        self.merge_memo_tier_events(&MemoTierEvents {
            l2_secondary_hits: memo_l2_secondary_hits,
            l2_secondary_misses: memo_l2_secondary_misses,
            l2_promotions: memo_l2_promotions,
            l2_reval_failures: memo_l2_reval_failures,
            net_hits: memo_net_hits,
            net_misses: memo_net_misses,
            net_errors: memo_net_errors,
            net_reval_failures: memo_net_reval_failures,
        });
        self.campaign = self.campaign.merged(campaign);
    }

    /// Returns the flat-value campaign work-volume counters (doc 30 FV-0).
    pub const fn campaign(&self) -> CampaignCounters {
        self.campaign
    }

    /// Returns the number of `.drv` paths reused from clean derivation ATerm records.
    pub const fn derivation_aterm_path_reuses(&self) -> u64 {
        self.derivation_aterm_path_reuses
    }

    /// Returns the number of static derivation output path sets reused from clean records.
    pub const fn static_derivation_output_path_reuses(&self) -> u64 {
        self.static_derivation_output_path_reuses
    }

    /// Returns the number of derivation hash-boundary calculations performed.
    pub const fn derivation_hash_calculations(&self) -> u64 {
        self.derivation_hash_calculations
    }

    /// Returns the number of derivation `.drv` text-path calculations performed.
    pub const fn derivation_text_path_calculations(&self) -> u64 {
        self.derivation_text_path_calculations
    }

    /// Returns the number of worker bump-arena chunks allocated by the evaluator heap.
    pub const fn heap_chunks(&self) -> u64 {
        self.heap_chunks
    }

    /// Returns bytes reserved by worker evaluator heap chunks.
    pub const fn heap_reserved_bytes(&self) -> u64 {
        self.heap_reserved_bytes
    }

    /// Returns page-rounded bytes mapped by the worker evaluator heap arena.
    pub const fn heap_mapped_bytes(&self) -> u64 {
        self.heap_mapped_bytes
    }

    /// Returns bytes consumed by worker evaluator heap allocations.
    pub const fn heap_used_bytes(&self) -> u64 {
        self.heap_used_bytes
    }

    /// Returns the number of permanent shared bump-arena chunks allocated.
    pub const fn permanent_heap_chunks(&self) -> u64 {
        self.permanent_heap_chunks
    }

    /// Returns bytes reserved by permanent shared evaluator heap chunks.
    pub const fn permanent_heap_reserved_bytes(&self) -> u64 {
        self.permanent_heap_reserved_bytes
    }

    /// Returns page-rounded bytes mapped by the permanent shared evaluator heap arena.
    pub const fn permanent_heap_mapped_bytes(&self) -> u64 {
        self.permanent_heap_mapped_bytes
    }

    /// Returns bytes consumed by permanent shared evaluator heap allocations.
    pub const fn permanent_heap_used_bytes(&self) -> u64 {
        self.permanent_heap_used_bytes
    }

    /// Returns worker-domain heap records counted by the latest Tier-B admission.
    pub const fn heap_tier_b_admission_worker_records(&self) -> u64 {
        self.heap_tier_b_admission_worker_records
    }

    /// Returns permanent-shared heap records counted by the latest Tier-B admission.
    pub const fn heap_tier_b_admission_permanent_shared_records(&self) -> u64 {
        self.heap_tier_b_admission_permanent_shared_records
    }

    /// Returns heap-record generation metadata rewrites from the latest Tier-B admission.
    pub const fn heap_tier_b_admission_generation_rewrites(&self) -> u64 {
        self.heap_tier_b_admission_generation_rewrites
    }

    /// Returns the number of typed-value heap records allocated.
    ///
    /// Counts string, path, list, attribute-set, lambda, builtin, and thunk
    /// records that materialized a new allocation. Hash-cons reuse is excluded,
    /// so this is the dedup-reduced boxed-value analog of C++ Nix's `nrValues`.
    pub const fn values_allocated(&self) -> u64 {
        self.values_allocated
    }

    /// Returns the number of attribute-set constructions requested.
    ///
    /// Includes requests satisfied by a hash-cons hit, matching the accounting
    /// of C++ Nix's `nrAttrsets`.
    pub const fn attrsets_built(&self) -> u64 {
        self.attrsets_built
    }

    /// Returns the total attribute entries summed over every attribute-set
    /// construction, the analog of C++ Nix's `nrAttrsInAttrsets`.
    pub const fn attrs_entries_total(&self) -> u64 {
        self.attrs_entries_total
    }

    /// Returns the number of value-level function applications performed.
    ///
    /// Counts every lambda and builtin application routed through the central
    /// apply path, the analog of C++ Nix's `nrFunctionCalls`. Builtins inlined
    /// as dedicated IR nodes are evaluated directly and are not counted here.
    pub const fn function_calls(&self) -> u64 {
        self.function_calls
    }

    /// Returns the number of structural-hash lookups against the hash-cons tables.
    pub const fn hashcons_attempts(&self) -> u64 {
        self.hashcons_attempts
    }

    /// Returns the number of hash-cons lookups that reused a canonical value.
    pub const fn hashcons_hits(&self) -> u64 {
        self.hashcons_hits
    }

    /// Returns the number of distinct symbols interned by the evaluation.
    ///
    /// This is a gauge of the final symbol-table size, the analog of the symbol
    /// count C++ Nix reports under `symbols`.
    pub const fn symbols_interned(&self) -> u64 {
        self.symbols_interned
    }

    /// Returns the estimated resident heap bytes of the live symbol table.
    ///
    /// A memory-campaign L0 attribution gauge (interned strings stored twice +
    /// `Vec`/`BTreeMap` overhead + rank view); not an exact allocator figure.
    pub const fn symbol_table_resident_bytes(&self) -> u64 {
        self.symbol_table_resident_bytes
    }

    /// Returns the number of imported files that were evaluated.
    ///
    /// Counts import-cache misses: an import whose target was evaluated rather
    /// than served from the per-evaluation import cache. A value below the total
    /// number of `import` expressions demonstrates the import cache working.
    pub const fn imports_evaluated(&self) -> u64 {
        self.imports_evaluated
    }

    /// Returns nanoseconds spent parsing imported sources (`AOS_NIX_EVAL_STATS`).
    pub const fn front_end_parse_nanos(&self) -> u64 {
        self.front_end_parse_nanos
    }

    /// Returns nanoseconds spent resolving import scopes (`AOS_NIX_EVAL_STATS`).
    pub const fn front_end_resolve_nanos(&self) -> u64 {
        self.front_end_resolve_nanos
    }

    /// Returns nanoseconds spent lowering imports to IR (`AOS_NIX_EVAL_STATS`).
    pub const fn front_end_lower_nanos(&self) -> u64 {
        self.front_end_lower_nanos
    }

    /// Returns nanoseconds spent annotating import IR (`AOS_NIX_EVAL_STATS`).
    pub const fn front_end_annotate_nanos(&self) -> u64 {
        self.front_end_annotate_nanos
    }

    /// Returns the number of forces whose thunk evaluated prelude (`lib`/`stdenv`)
    /// code (`AOS_NIX_EVAL_STATS`); ratio to [`Self::thunks_forced`] is the
    /// prelude-force-share signal.
    pub const fn prelude_thunks_forced(&self) -> u64 {
        self.prelude_thunks_forced
    }

    /// Returns inclusive nanoseconds spent in prelude thunk bodies
    /// (`AOS_NIX_EVAL_STATS`); trust only its ratio to [`Self::all_force_nanos`].
    pub const fn prelude_force_nanos(&self) -> u64 {
        self.prelude_force_nanos
    }

    /// Returns inclusive nanoseconds spent in all thunk bodies
    /// (`AOS_NIX_EVAL_STATS`); the denominator for the prelude-force wall ratio.
    pub const fn all_force_nanos(&self) -> u64 {
        self.all_force_nanos
    }

    /// Returns the number of thunks promoted to tier-1 native code during force.
    pub const fn tier1_promoted(&self) -> u64 {
        self.tier1_promoted
    }

    /// Returns the number of thunk forces served by dispatching tier-1 native code.
    pub const fn tier1_dispatched(&self) -> u64 {
        self.tier1_dispatched
    }

    /// Returns the number of tier-1 dispatch attempts that deoptimized to the tree walk.
    pub const fn tier1_deopted(&self) -> u64 {
        self.tier1_deopted
    }

    /// Returns the number of def-sites blacklisted after a failed tier-1 lowering.
    pub const fn tier1_blacklisted(&self) -> u64 {
        self.tier1_blacklisted
    }

    /// Returns the number of lambda def-sites promoted to tier-2 native code.
    pub const fn tier2_promoted(&self) -> u64 {
        self.tier2_promoted
    }

    /// Returns the number of lambda applications served by tier-2 native code.
    ///
    /// Each dispatch covers one *boundary* application; direct native
    /// self-calls inside a compiled recursion are not individually counted.
    pub const fn tier2_dispatched(&self) -> u64 {
        self.tier2_dispatched
    }

    /// Returns the number of tier-2 dispatch attempts that deoptimized to the
    /// interpreted call.
    pub const fn tier2_deopted(&self) -> u64 {
        self.tier2_deopted
    }

    /// Returns the number of lambda def-sites blacklisted after a failed tier-2
    /// lowering.
    pub const fn tier2_blacklisted(&self) -> u64 {
        self.tier2_blacklisted
    }

    /// Returns L0 content-memo hits (replayed instead of evaluated).
    pub const fn memo_l0_hits(&self) -> u64 {
        self.memo_l0_hits
    }

    /// Returns L0 content-memo probe misses (including failed revalidations).
    pub const fn memo_l0_misses(&self) -> u64 {
        self.memo_l0_misses
    }

    /// Returns entries admitted into the L0 content memo.
    pub const fn memo_l0_admissions(&self) -> u64 {
        self.memo_l0_admissions
    }

    /// Returns L0 content-memo eligibility and record declines.
    pub const fn memo_l0_declines(&self) -> u64 {
        self.memo_l0_declines
    }

    /// Returns L1 (in-process shared) content-memo hits.
    pub const fn memo_l1_hits(&self) -> u64 {
        self.memo_l1_hits
    }

    /// Returns L1 content-memo probe misses (including failed revalidations).
    pub const fn memo_l1_misses(&self) -> u64 {
        self.memo_l1_misses
    }

    /// Returns entries published into the L1 content memo.
    pub const fn memo_l1_admissions(&self) -> u64 {
        self.memo_l1_admissions
    }

    /// Returns L1 content-memo eligibility and record declines.
    pub const fn memo_l1_declines(&self) -> u64 {
        self.memo_l1_declines
    }

    /// Returns opt-in content-memo economics counters and timings.
    pub const fn memo_economics(&self) -> MemoEconomicsStats {
        self.memo_economics
    }

    pub(in crate::eval::tree_walk) fn record_heap_tier_b_admission(
        &mut self,
        report: EvalHeapTierBAdmissionReport,
    ) {
        self.heap_tier_b_admission_worker_records = report.worker_records() as u64;
        self.heap_tier_b_admission_permanent_shared_records =
            report.permanent_shared_records() as u64;
        self.heap_tier_b_admission_generation_rewrites = report.generation_rewrites() as u64;
    }
}
