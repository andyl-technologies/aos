//! `TreeWalkOptions` methods (option_queries), split from the parent for the §2 line cap.

use super::*;

impl TreeWalkOptions {
    /// Returns the configured evaluation start time, if one is available.
    pub const fn current_time(&self) -> Option<i64> {
        self.current_time
    }

    /// Returns whether `builtins.traceVerbose` emits output.
    pub const fn trace_verbose(&self) -> bool {
        self.trace_verbose
    }

    /// Returns whether `builtins.warn` aborts after emitting a warning.
    pub const fn abort_on_warn(&self) -> bool {
        self.abort_on_warn
    }

    /// Returns the configured maximum nested call depth.
    pub const fn max_call_depth(&self) -> usize {
        self.max_call_depth
    }

    /// Returns whether experimental TOML timestamp parsing is enabled.
    pub const fn parse_toml_timestamps(&self) -> bool {
        self.parse_toml_timestamps
    }

    /// Returns the configured value for an environment variable.
    pub fn env_var(&self, name: &[u8]) -> Option<&[u8]> {
        self.env_vars.get(name).map(Vec::as_slice)
    }

    /// Returns the configured Nix search-path entries.
    pub fn nix_path(&self) -> &[NixSearchPathEntry] {
        &self.nix_path
    }

    /// Returns the hidden C++ Nix corepkgs directory for `<nix/...>` fallback.
    pub fn corepkgs_path(&self) -> Option<&[u8]> {
        self.corepkgs_path.as_deref()
    }

    /// Returns whether ambient Nix search-path lookup is disabled.
    pub const fn reject_ambient_search_path(&self) -> bool {
        self.reject_ambient_search_path
    }

    /// Returns whether unconfigured impure builtin constants are rejected.
    pub const fn reject_unconfigured_impure_builtin_constants(&self) -> bool {
        self.reject_unconfigured_impure_builtin_constants
    }

    /// Returns the configured parse-cache root directory, if any.
    pub fn parse_cache_root(&self) -> Option<&Path> {
        self.parse_cache_root.as_deref()
    }

    /// Returns the configured persistent-cache root directory, if any.
    pub fn persist_cache_root(&self) -> Option<&Path> {
        self.persist_cache_root.as_deref()
    }

    /// Returns whether persistent value-decode content re-hashing is enabled.
    pub const fn persist_cache_verify(&self) -> bool {
        self.persist_cache_verify
    }

    /// Returns whether advisory incremental eval-cache observation is enabled.
    pub const fn eval_cache_enabled(&self) -> bool {
        self.eval_cache_enabled
    }

    /// Returns a stable digest over the result-affecting evaluator settings.
    ///
    /// The digest folds every option that can change an expression's derivation
    /// closure but is not otherwise captured by the impure-input trace, for use
    /// as a component of a durable root-record cutoff key. See the
    /// `result_fingerprint` module for the exact field set and rationale.
    pub fn result_affecting_fingerprint(&self) -> [u8; 32] {
        result_fingerprint::result_affecting_fingerprint(self)
    }

    /// Returns the durable materialization costs for forced-expression payloads.
    pub const fn force_cache_materialization_costs(&self) -> MaterializationCosts {
        self.force_cache_materialization_costs
    }

    /// Returns the configured high-water heap budget, if one is available.
    pub const fn heap_memory_budget(&self) -> Option<HeapMemoryBudget> {
        self.heap_memory_budget
    }

    /// Returns whether owned outcomes automatically apply Tier-B admission.
    pub const fn heap_tier_b_transition_admission_enabled(&self) -> bool {
        self.heap_tier_b_transition_admission_enabled
    }

    /// Returns whether worker closures use the record-table placement.
    pub const fn record_worker_closures_for_gc_scaffolding(&self) -> bool {
        self.record_worker_closures_for_gc_scaffolding
    }

    /// Returns whether tree-walk worker storage uses the current thread's Tier-A arena.
    pub const fn heap_thread_local_tier_a_enabled(&self) -> bool {
        self.heap_thread_local_tier_a_enabled
    }

    /// Returns the configured GC-stress polling policy.
    pub const fn gc_stress_policy(&self) -> GcStressPolicy {
        self.gc_stress_policy
    }

    /// Returns the configured Tier-B live-reclamation mode.
    pub const fn gc_mode(&self) -> EvalGcMode {
        self.gc_mode
    }

    /// Returns the worker-record growth required between Tier-B sweeps.
    pub const fn gc_sweep_threshold(&self) -> u64 {
        self.gc_sweep_threshold
    }

    /// Returns the configured thunk-resolution barrier tier.
    pub const fn thunk_resolve_barrier_tier(&self) -> GenerationalGcTier {
        self.thunk_resolve_barrier_tier
    }

    /// Returns whether newly allocated thunks receive parallel payload cells.
    ///
    /// This is true when the storage flag is set explicitly or when parallel
    /// evaluation mode is configured through [`Self::set_parallel_workers`].
    pub const fn parallel_thunk_payloads_enabled(&self) -> bool {
        self.parallel_thunk_payloads_enabled || self.parallel_workers.is_some()
    }

    /// Returns the configured parallel evaluation worker count, if enabled.
    pub const fn parallel_workers(&self) -> Option<std::num::NonZeroUsize> {
        self.parallel_workers
    }

    /// Returns whether hidden-class shape projection stays on at `K >= 2`.
    ///
    /// Defaults to `false`: multi-worker evaluations disable projection and
    /// take flat attr lookups instead. The shared-shape-log substrate keeps
    /// dense shape ids globally consistent when this is enabled, so the
    /// choice is purely a performance default - on the measured package
    /// corpus the projection plus transient shaped-select machinery costs
    /// more than shaped lookups save, and the gap widens with worker count.
    pub const fn parallel_shape_projection(&self) -> bool {
        self.parallel_shape_projection
    }

    /// Returns the hidden-class shape strategy for heap attrset records.
    pub const fn attr_shape_mode(&self) -> AttrShapeMode {
        self.attr_shape_mode
    }

    /// Returns whether promoted tier-1 native entries may be published for dispatch.
    pub const fn jit_tier1_publish_enabled(&self) -> bool {
        self.jit_tier1_publish_enabled
    }

    /// Returns the active worker id for parallel thunk sidecar claims.
    pub const fn parallel_thunk_worker_id(&self) -> ParallelThunkWorkerId {
        self.parallel_thunk_worker_id
    }

    /// Returns the idle-epoch threshold for post-evaluation cheap heap advice.
    pub const fn heap_cheap_memory_advice_min_idle_epochs(&self) -> Option<u64> {
        self.heap_cheap_memory_advice_min_idle_epochs
    }

    /// Returns the configured target for an exact indirect flake reference.
    pub fn flake_ref_resolution(&self, indirect: &[u8]) -> Option<&[u8]> {
        self.flake_ref_resolutions.get(indirect).map(Vec::as_slice)
    }
}
