//! Mirrored evaluator statistics and tracing emission.

use super::*;

impl TreeWalk {
    pub(super) fn stats_snapshot(&self) -> EvalStats {
        let arena = self.heap.arena_stats();
        EvalStats {
            thunks_forced: self.stats.thunks_forced,
            thunks_allocated: self.stats.thunks_allocated,
            thunks_elided: self.stats.thunks_elided,
            thunk_cache_hits: self.stats.thunk_cache_hits,
            inline_cache_hits: self.stats.inline_cache_hits,
            inline_cache_misses: self.stats.inline_cache_misses,
            shape_transitions: self.stats.shape_transitions,
            gc_bytes: self.stats.gc_bytes,
            gc_pause_us: self.stats.gc_pause_us,
            tier_promotions: self.stats.tier_promotions,
            deopts: self.stats.deopts,
            force_cache_hits: self.stats.force_cache_hits,
            force_cache_misses: self.stats.force_cache_misses,
            force_cache_memoization_admits: self.stats.force_cache_memoization_admits,
            force_cache_memoization_bypasses: self.stats.force_cache_memoization_bypasses,
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
            derivation_aterm_path_reuses: self.stats.derivation_aterm_path_reuses,
            static_derivation_output_path_reuses: self.stats.static_derivation_output_path_reuses,
            derivation_hash_calculations: self.stats.derivation_hash_calculations,
            derivation_text_path_calculations: self.stats.derivation_text_path_calculations,
            heap_chunks: arena.chunks as u64,
            heap_reserved_bytes: arena.reserved_bytes as u64,
            heap_used_bytes: arena.used_bytes as u64,
        }
    }

    pub(super) fn emit_stats_trace(stats: &EvalStats) {
        tracing::debug!(
            target: "aos_nix::eval::stats",
            thunks_forced = stats.thunks_forced(),
            thunks_allocated = stats.thunks_allocated(),
            thunks_elided = stats.thunks_elided(),
            thunk_cache_hits = stats.thunk_cache_hits(),
            inline_cache_hits = stats.inline_cache_hits(),
            inline_cache_misses = stats.inline_cache_misses(),
            shape_transitions = stats.shape_transitions(),
            gc_bytes = stats.gc_bytes(),
            gc_pause_us = stats.gc_pause_us(),
            tier_promotions = stats.tier_promotions(),
            deopts = stats.deopts(),
            force_cache_hits = stats.force_cache_hits(),
            force_cache_misses = stats.force_cache_misses(),
            force_cache_probes = stats.force_cache_probes(),
            force_cache_memoization_admits = stats.force_cache_memoization_admits(),
            force_cache_memoization_bypasses = stats.force_cache_memoization_bypasses(),
            force_cache_memoization_demands = stats.force_cache_memoization_demands(),
            cache_hits = stats.cache_hits(),
            cache_misses = stats.cache_misses(),
            early_cutoffs = stats.early_cutoffs(),
            derivation_aterm_path_reuses = stats.derivation_aterm_path_reuses(),
            static_derivation_output_path_reuses = stats.static_derivation_output_path_reuses(),
            derivation_hash_calculations = stats.derivation_hash_calculations(),
            derivation_text_path_calculations = stats.derivation_text_path_calculations(),
            heap_chunks = stats.heap_chunks(),
            heap_reserved_bytes = stats.heap_reserved_bytes(),
            heap_used_bytes = stats.heap_used_bytes(),
            "aos-nix tree-walk evaluation stats"
        );
    }

    pub(super) fn increment_thunks_allocated(&mut self) {
        self.stats.thunks_allocated = self.stats.thunks_allocated.saturating_add(1);
    }

    pub(super) fn increment_thunks_forced(&mut self) {
        self.stats.thunks_forced = self.stats.thunks_forced.saturating_add(1);
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

    pub(super) fn increment_early_cutoffs(&mut self) {
        self.stats.early_cutoffs = self.stats.early_cutoffs.saturating_add(1);
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
