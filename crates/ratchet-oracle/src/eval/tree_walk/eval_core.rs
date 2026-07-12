//! Core evaluation entry points, scope/environment management, and module bookkeeping.

use super::*;
use crate::cache::hashing::ForceCapturedValueHash;
use crate::eval::heap::{SharedHeapArena, SharedHeapShard};
mod force_identity;
mod force_payload;
mod force_persistence;
mod memo;
mod module_env;
mod stack;
const FORCE_EXPRESSION_IDENTITY_DOMAIN_VERSION: &[u8] = b"aos-nix-force-expression-identity-v1";
const FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION: &[u8] = b"aos-nix-force-captured-value-hash-v1";
const FORCE_FIRST_CLASS_PRIMOP_CALL_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-force-first-class-primop-call-identity-v1";
const FORCE_SYNTHETIC_BUILTIN_ATTR_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-force-synthetic-builtin-attr-identity-v1";
const FORCE_SYNTHETIC_SELECT_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-force-synthetic-select-identity-v1";
const DERIVATION_ATERM_EXPRESSION_IDENTITY_DOMAIN_VERSION: &[u8] =
    b"aos-nix-derivation-aterm-expression-identity-v1";
const FORCE_CACHE_PAYLOAD_MAX_DEPTH: usize = 64;

impl ForceCacheOptionsIdentity {
    fn new(options: &TreeWalkOptions) -> Self {
        Self {
            store_dir: options.store_dir().to_vec(),
            search_path_base: options.search_path_base().to_vec(),
            nix_path: options.nix_path().to_vec(),
            corepkgs_path: options.corepkgs_path().map(<[u8]>::to_vec),
            allowed_paths: options.allowed_paths().to_vec(),
            allowed_uris: options.allowed_uris().to_vec(),
            home_dir: options.home_dir().map(<[u8]>::to_vec),
            current_system: options.current_system().map(<[u8]>::to_vec),
            current_time: options.current_time(),
            eval_mode: options.eval_mode(),
            reject_ambient_search_path: options.reject_ambient_search_path(),
            reject_unconfigured_impure_builtin_constants: options
                .reject_unconfigured_impure_builtin_constants(),
        }
    }

    fn update_cache_identity(&self, hasher: &mut blake3::Hasher) -> Option<()> {
        hasher.update(b"force-cache-options-v4");
        hasher.update(b"store-dir");
        TreeWalk::update_cache_identity_chunk(hasher, &self.store_dir)?;
        hasher.update(b"search-path-base");
        TreeWalk::update_cache_identity_chunk(hasher, &self.search_path_base)?;
        hasher.update(b"nix-path");
        let nix_path_len = u64::try_from(self.nix_path.len()).ok()?;
        hasher.update(&nix_path_len.to_le_bytes());
        for entry in &self.nix_path {
            hasher.update(b"entry-prefix");
            TreeWalk::update_cache_identity_chunk(hasher, entry.prefix())?;
            hasher.update(b"entry-path");
            TreeWalk::update_cache_identity_chunk(hasher, entry.path())?;
        }
        match &self.corepkgs_path {
            Some(corepkgs_path) => {
                hasher.update(b"corepkgs-path");
                TreeWalk::update_cache_identity_chunk(hasher, corepkgs_path)?;
            }
            None => {
                hasher.update(b"no-corepkgs-path");
            }
        }
        hasher.update(b"allowed-paths");
        let allowed_paths_len = u64::try_from(self.allowed_paths.len()).ok()?;
        hasher.update(&allowed_paths_len.to_le_bytes());
        for path in &self.allowed_paths {
            hasher.update(b"allowed-path");
            TreeWalk::update_cache_identity_chunk(hasher, path)?;
        }
        hasher.update(b"allowed-uris");
        let allowed_uris_len = u64::try_from(self.allowed_uris.len()).ok()?;
        hasher.update(&allowed_uris_len.to_le_bytes());
        for uri in &self.allowed_uris {
            hasher.update(b"allowed-uri");
            TreeWalk::update_cache_identity_chunk(hasher, uri)?;
        }
        match &self.home_dir {
            Some(home_dir) => {
                hasher.update(b"home-dir");
                TreeWalk::update_cache_identity_chunk(hasher, home_dir)?;
            }
            None => {
                hasher.update(b"no-home-dir");
            }
        }
        match &self.current_system {
            Some(current_system) => {
                hasher.update(b"current-system");
                TreeWalk::update_cache_identity_chunk(hasher, current_system)?;
            }
            None => {
                hasher.update(b"no-current-system");
            }
        }
        match self.current_time {
            Some(current_time) => {
                hasher.update(b"current-time");
                hasher.update(&current_time.to_le_bytes());
            }
            None => {
                hasher.update(b"no-current-time");
            }
        }
        hasher.update(b"eval-mode");
        hasher.update(self.eval_mode_cache_identity_bytes());
        hasher.update(b"reject-ambient-search-path");
        hasher.update(&[u8::from(self.reject_ambient_search_path)]);
        hasher.update(b"reject-unconfigured-impure-builtin-constants");
        hasher.update(&[u8::from(self.reject_unconfigured_impure_builtin_constants)]);
        Some(())
    }

    const fn eval_mode_cache_identity_bytes(&self) -> &'static [u8] {
        match self.eval_mode {
            EvalMode::Impure => b"impure",
            EvalMode::Restricted => b"restricted",
            EvalMode::Pure => b"pure",
        }
    }

    fn update_synthetic_builtin_cache_identity(
        &self,
        hasher: &mut blake3::Hasher,
        execution: BuiltinExecution,
    ) -> Option<()> {
        hasher.update(b"force-cache-synthetic-builtin-options-v1");
        match execution {
            BuiltinExecution::TrueValue
            | BuiltinExecution::FalseValue
            | BuiltinExecution::NullValue => {
                hasher.update(b"no-option-dependencies");
            }
            BuiltinExecution::NixVersionValue => {
                hasher.update(b"nix-version");
                TreeWalk::update_cache_identity_chunk(hasher, PINNED_NIX_VERSION)?;
            }
            BuiltinExecution::LangVersionValue => {
                hasher.update(b"lang-version");
                hasher.update(&PINNED_NIX_LANG_VERSION.to_le_bytes());
            }
            BuiltinExecution::CurrentSystemValue => {
                hasher.update(b"current-system");
                self.update_synthetic_impure_constant_cache_identity(
                    hasher,
                    b"current-system-value",
                    self.current_system.as_deref(),
                )?;
            }
            BuiltinExecution::CurrentTimeValue => {
                hasher.update(b"current-time");
                let visible = self.eval_mode != EvalMode::Pure;
                if visible {
                    hasher.update(b"impure-constant-visible");
                } else {
                    hasher.update(b"impure-constant-hidden");
                }
                if visible {
                    match self.current_time {
                        Some(current_time) => {
                            hasher.update(b"current-time-value");
                            hasher.update(&current_time.to_le_bytes());
                        }
                        None => {
                            hasher.update(b"no-current-time-value");
                            hasher.update(b"reject-unconfigured-impure-builtin-constants");
                            hasher.update(&[u8::from(
                                self.reject_unconfigured_impure_builtin_constants,
                            )]);
                        }
                    }
                } else {
                    hasher.update(b"reject-unconfigured-impure-builtin-constants");
                    hasher.update(&[u8::from(self.reject_unconfigured_impure_builtin_constants)]);
                }
            }
            BuiltinExecution::StoreDirValue => {
                hasher.update(b"store-dir");
                TreeWalk::update_cache_identity_chunk(hasher, &self.store_dir)?;
            }
            BuiltinExecution::NixPathValue => {
                hasher.update(b"nix-path");
                hasher.update(b"reject-ambient-search-path");
                hasher.update(&[u8::from(self.reject_ambient_search_path)]);
                if self.reject_ambient_search_path {
                    return Some(());
                }
                let visible = self.eval_mode != EvalMode::Pure;
                if visible {
                    hasher.update(b"nix-path-visible");
                } else {
                    hasher.update(b"nix-path-hidden");
                }
                if !visible {
                    return Some(());
                }
                let nix_path_len = u64::try_from(self.nix_path.len()).ok()?;
                hasher.update(&nix_path_len.to_le_bytes());
                for entry in &self.nix_path {
                    hasher.update(b"entry-prefix");
                    TreeWalk::update_cache_identity_chunk(hasher, entry.prefix())?;
                    hasher.update(b"entry-path");
                    TreeWalk::update_cache_identity_chunk(hasher, entry.path())?;
                }
            }
            _ => {
                return None;
            }
        }
        Some(())
    }

    fn update_first_class_primop_cache_identity(
        &self,
        hasher: &mut blake3::Hasher,
        execution: BuiltinExecution,
    ) -> Option<()> {
        hasher.update(b"force-cache-first-class-primop-options-v1");
        match execution {
            BuiltinExecution::StrictUnary {
                primop: StrictUnaryPrimOp::GetEnv,
                ..
            } => {
                hasher.update(b"get-env");
                if self.eval_mode == EvalMode::Pure {
                    hasher.update(b"env-hidden");
                } else {
                    hasher.update(b"env-visible");
                }
            }
            _ => {
                return None;
            }
        }
        Some(())
    }

    fn update_synthetic_impure_constant_cache_identity(
        &self,
        hasher: &mut blake3::Hasher,
        value_label: &'static [u8],
        value: Option<&[u8]>,
    ) -> Option<()> {
        let visible = self.eval_mode != EvalMode::Pure;
        if visible {
            hasher.update(b"impure-constant-visible");
        } else {
            hasher.update(b"impure-constant-hidden");
        }
        if visible {
            match value {
                Some(value) => {
                    hasher.update(value_label);
                    TreeWalk::update_cache_identity_chunk(hasher, value)?;
                }
                None => {
                    hasher.update(b"no-impure-constant-value");
                    hasher.update(b"reject-unconfigured-impure-builtin-constants");
                    hasher.update(&[u8::from(self.reject_unconfigured_impure_builtin_constants)]);
                }
            }
        } else {
            hasher.update(b"reject-unconfigured-impure-builtin-constants");
            hasher.update(&[u8::from(self.reject_unconfigured_impure_builtin_constants)]);
        }
        Some(())
    }
}

impl TreeWalk {
    /// Creates a tree-walk evaluator over `ir`.
    pub fn new(ir: &Ir) -> Self {
        Self::with_options(ir, TreeWalkOptions::default())
    }

    /// Creates a tree-walk evaluator over `ir` with explicit runtime options.
    pub fn with_options(ir: &Ir, options: TreeWalkOptions) -> Self {
        let eval_cache = Arc::new(Mutex::new(EvalCacheRuntime::from_enabled(
            options.eval_cache_enabled(),
        )));
        Self::with_options_and_eval_cache(ir, options, eval_cache)
    }

    /// Creates a tree-walk evaluator over `ir` with caller-owned cache state.
    ///
    /// The cache runtime stays advisory. Disabled runtimes are no-ops; enabled
    /// runtimes record source-backed or lowered-IR-backed forced inline thunk
    /// results and may reuse clean pure inline-scalar force results for a
    /// conservative IR subset. They also observe `derivationStrict` `.drv`
    /// ATerm comparison hashes after normal path computation. They do not
    /// perform general demand-graph memo lookup. When options configure a
    /// persistent-cache root, forced-expression observations may read verifying
    /// durable force-cache payloads, record demand, and write threshold-selected
    /// durable value/trace payloads.
    ///
    /// Direct [`TreeWalk::eval_root`] and [`TreeWalk::eval_node`] callers do not
    /// perform automatic persistent run-boundary advancement; the public
    /// `eval_*` free-function wrappers advance successful evaluation exits.
    pub fn with_options_and_eval_cache(
        ir: &Ir,
        options: TreeWalkOptions,
        eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    ) -> Self {
        let path_literal_base = options.path_literal_base().map(<[u8]>::to_vec);
        let parse_cache = options.parse_cache_root().map(ParseCache::new);
        let mut heap = if let Some(workers) = options.parallel_workers() {
            // Parallel mode: allocate into one shard of a K-shard shared
            // arena so (in the P3b scheduler phase) K production workers can
            // dereference one another's fresh allocations. Until then the
            // single production TreeWalk drives shard 0.
            Self::shared_parallel_heap(workers)
        } else if options.heap_thread_local_tier_a_enabled() {
            EvalHeap::new_thread_local_tier_a()
        } else {
            EvalHeap::new()
        };
        // Parallel evaluation quiesces minor GC: production evaluation never
        // runs minor collections (arenas grow monotonically for the eval's
        // lifetime), and the GC-stress test machinery must not relocate
        // records while other workers may hold claims on their parallel
        // cells. Serial-mode GC behavior is unchanged.
        let gc_stress_policy = if options.parallel_workers().is_some() {
            debug_assert!(
                options.gc_stress_policy() == GcStressPolicy::disabled(),
                "parallel evaluation mode quiesces GC-stress minor collections"
            );
            GcStressPolicy::disabled()
        } else {
            options.gc_stress_policy()
        };
        heap.set_gc_stress_policy(gc_stress_policy);
        // The generational thunk-resolve write barrier resolves published
        // values against record generations, so barrier-exercising tiers keep
        // the record-table worker placement alongside the GC-stress proving
        // ground (doc 30 FV-3; see `flat_values::closures`).
        if options.thunk_resolve_barrier_tier() != GenerationalGcTier::OneShotArena
            || options.record_worker_closures_for_gc_scaffolding()
        {
            heap.use_record_worker_closures_for_gc_scaffolding();
        }
        // Tier-B live reclamation (AOS_NIX_GC=sweep) is likewise pinned OFF
        // under parallel evaluation: capture shedding and the quiescent sweep
        // both require the serial heap's single-mutator invariants, and the
        // per-worker/concurrent collector is Phase 8. This is an explicit
        // quiescence pin, not a default: a parallel evaluation with a
        // configured sweep mode runs byte-identically to gc-off.
        let gc_mode = if options.parallel_workers().is_some()
            || options.parallel_thunk_payloads_enabled()
        {
            EvalGcMode::Off
        } else {
            options.gc_mode()
        };
        if let Some(heap_memory_budget) = options.heap_memory_budget() {
            heap.set_memory_budget(heap_memory_budget);
            heap.set_resident_memory_mode(
                EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback,
            );
        }
        // Whether any forced-expression cache observation can have an effect. When
        // false, the per-force subject/payload content hashing is pure waste, so
        // the force hot path skips it. A poisoned lock means the shared runtime is
        // unusable (every later cache lock would fail and no-op anyway), so it is
        // treated as inactive; the cache is advisory, so skipping it never changes
        // results.
        let force_cache_active = options.persist_cache_root().is_some()
            || eval_cache.lock().is_ok_and(|runtime| runtime.is_enabled());
        let store_validity_checker = StoreValidityChecker::for_store_dir(options.store_dir());
        // Parallel forcing gives each evaluator a wait registry; demand-graph
        // workers replace it with one shared through `set_parallel_force_registry`.
        let parallel_force_registry = options
            .parallel_thunk_payloads_enabled()
            .then(|| Arc::new(ParallelForceCycleRegistry::new()));
        // Allocate the per-worker MEMO-1 L0 table only when its tier is enabled.
        let memo_l0 = options
            .memo_l0_active()
            .then(|| super::memo::MemoL0Table::new(options.memo_options().l0_entries));
        let memo_economics = options.memo_options().stats_enabled.then(Default::default);
        let attr_shape_mode = options.attr_shape_mode();
        Self {
            modules: vec![TreeWalkModule::new(
                ir.clone(),
                path_literal_base,
                ForceCacheOptionsIdentity::new(&options),
                None,
            )],
            current_module: EvalModuleId::ROOT,
            symbols: ir.symbols.clone(),
            heap,
            env: Vec::new(),
            flat_env: None,
            pending_flat_captures: Vec::new(),
            order_sensitive_binding_failed: false,
            with_scopes: EvalWithEnv::default(),
            scoped_globals: EvalScopedGlobalEnv::default(),
            options,
            stats: EvalStats::default(),
            campaign_env_baseline: crate::eval::env::capture_stats::snapshot(),
            attr_telemetry: AttrTelemetry::new(),
            // Hidden-class shape projection stores dense `ShapeId`s in shared
            // heap attrs metadata. Under multi-worker parallel mode the demand
            // pool replaces this table with a prefix replica of one shared
            // shape log at spawn (see `parallel_shape`), so the ids are global
            // and foreign readers resolve them through their own replicas.
            // `AOS_NIX_SHAPES=off` runs without a table, which disables shape
            // projection (and every shaped select path) entirely.
            shape_table: match attr_shape_mode {
                AttrShapeMode::Off => None,
                AttrShapeMode::Transient | AttrShapeMode::Record => ShapeTable::new().ok(),
            },
            flat_select_caches: SelectCacheMap::default(),
            shaped_select_caches: SelectCacheMap::default(),
            record_select_caches: SelectCacheMap::default(),
            static_literal_shapes: SelectCacheMap::default(),
            hamt_select_caches: SelectCacheMap::default(),
            attr_update_node_states: BTreeMap::new(),
            attr_update_telemetry_enabled: Self::attr_update_telemetry_default(),
            trace_output: Vec::new(),
            warning_output: Vec::new(),
            impure_input_trace: Vec::new(),
            impure_input_trace_complete: true,
            force_cache_impure_trace_epoch: 0,
            active_memo_read_nodes: Vec::new(),
            active_derivation_trace_cursors: Vec::new(),
            persist_force_cache_hit_keys: Vec::new(),
            stderr: EvalStderr::default(),
            find_file_cache: BTreeMap::new(),
            find_file_cache_hits: 0,
            find_file_cache_misses: 0,
            known_derivations: BTreeMap::new(),
            shared: None,
            shared_known_derivations_cursor: 0,
            shared_text_store_cursor: 0,
            shared_import_log_cursor: 0,
            shared_version_seen: 0,
            import_cache: BTreeMap::new(),
            import_traceable_nonsymlink_prefixes: HashSet::new(),
            import_paths_cache: HashMap::new(),
            parse_cache,
            persist_cache: None,
            persist_secondary_caches: Vec::new(),
            persist_cache_open_attempted: false,
            eval_cache,
            force_cache_active,
            import_parse_cache_hits: 0,
            import_parse_cache_misses: 0,
            text_store: BTreeMap::new(),
            store_validity_checker,
            ifd_realizer: None,
            call_depth: 0,
            order_sensitive_binding_depth: 0,
            active_call_argument_plans: Vec::new(),
            active_composite_accumulator_depth: 0,
            active_root_eval_node: None,
            active_gc_stress_accumulator_allocation_node: None,
            active_gc_stress_primop_arg_root_admission_depth: 0,
            active_force_roots: Vec::new(),
            active_primop_arg_roots: Vec::new(),
            active_primop_arg_frames: Vec::new(),
            transient_value_stack_roots: Vec::new(),
            suspended_env_roots: Vec::new(),
            thunk_resolve_remembered_set: RememberedSet::new(),
            thunk_resolve_card_table: GcCardTable::default(),
            gc_mode,
            gc_records_at_last_sweep: 0,
            gc_sweeps_skipped_nonquiescent: 0,
            gc_last_sweep_report: None,
            lazy_identity_thunks: HashSet::new(),
            lazy_foldl_initial_thunks: HashSet::new(),
            tier1_publish_slots: HashMap::new(),
            tier1_def_site_slots: HashMap::new(),
            tier1_skipped_def_sites: HashSet::new(),
            tier2_def_site_slots: HashMap::new(),
            tier2_skipped_def_sites: Vec::new(),
            tier2_skipped_def_site_total: 0,
            tier1_engine: None,
            parallel_force_registry,
            memo_l0,
            memo_economics,
            memo_def_sites: HashMap::new(),
            memo_unhashable_values: HashSet::new(),
            #[cfg(test)]
            tree_walk_list_wrapper_calls: 0,
            #[cfg(test)]
            gc_stress_permanent_root_allocation_dispatches: Vec::new(),
            #[cfg(test)]
            capture_plan_validation: None,
        }
    }

    /// Creates a tree-walk evaluator with source provenance for the root IR.
    ///
    /// Use this constructor for file-backed root modules whose attribute
    /// positions should be visible through `builtins.unsafeGetAttrPos`.
    /// Source-less expression evaluation should use [`Self::with_options`],
    /// matching C++ Nix `--expr` behavior where root positions are unavailable.
    pub fn with_options_and_source(
        ir: &Ir,
        options: TreeWalkOptions,
        source_name: impl Into<Vec<u8>>,
        source: impl Into<Vec<u8>>,
    ) -> Self {
        let mut eval = Self::with_options(ir, options);
        eval.modules[EvalModuleId::ROOT.index()].source = Some(ModuleSource {
            name: source_name.into(),
            bytes: source.into(),
        });
        eval
    }

    /// Creates a source-backed tree-walk evaluator with caller-owned cache state.
    ///
    /// This is the cache-sharing variant of [`Self::with_options_and_source`].
    /// Source provenance is used instead of the lowered-IR fingerprint as the
    /// first expression-identity component for advisory demand-graph
    /// observations.
    pub fn with_options_and_source_and_eval_cache(
        ir: &Ir,
        options: TreeWalkOptions,
        source_name: impl Into<Vec<u8>>,
        source: impl Into<Vec<u8>>,
        eval_cache: Arc<Mutex<EvalCacheRuntime>>,
    ) -> Self {
        let mut eval = Self::with_options_and_eval_cache(ir, options, eval_cache);
        eval.modules[EvalModuleId::ROOT.index()].source = Some(ModuleSource {
            name: source_name.into(),
            bytes: source.into(),
        });
        eval
    }

    /// Returns the evaluator heap that owns heap-backed values.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Returns the worker id configured for parallel thunk sidecar claims.
    pub(crate) const fn parallel_thunk_worker_id(&self) -> ParallelThunkWorkerId {
        self.options.parallel_thunk_worker_id()
    }

    /// Returns the cross-worker wait registry used for parallel forcing.
    ///
    /// The registry is present exactly when parallel thunk payloads are
    /// enabled. Worker evaluators sharing one demand graph must expose the
    /// same registry instance; see [`TreeWalk::set_parallel_force_registry`].
    pub fn parallel_force_registry(&self) -> Option<&Arc<ParallelForceCycleRegistry>> {
        self.parallel_force_registry.as_ref()
    }

    /// Replaces the cross-worker wait registry used for parallel forcing.
    ///
    /// Call this on every worker evaluator of one shared demand graph with a
    /// single shared registry instance before any thunks are allocated:
    /// parallel cells capture the registry at allocation time, so cells
    /// allocated earlier keep the evaluator's previous registry and their wait
    /// edges would be invisible to the shared cycle walk.
    pub fn set_parallel_force_registry(&mut self, registry: Arc<ParallelForceCycleRegistry>) {
        self.parallel_force_registry = Some(registry);
    }

    /// Returns the remembered set populated by thunk-resolution write barriers.
    pub const fn thunk_resolve_remembered_set(&self) -> &RememberedSet {
        &self.thunk_resolve_remembered_set
    }

    /// Returns the card table populated by thunk-resolution write barriers.
    pub const fn thunk_resolve_card_table(&self) -> &GcCardTable {
        &self.thunk_resolve_card_table
    }

    /// Returns user-facing trace output emitted so far.
    pub fn trace_output(&self) -> &[EvalTraceOutput] {
        &self.trace_output
    }

    /// Returns user-facing warning output emitted so far.
    pub fn warning_output(&self) -> &[EvalWarningOutput] {
        &self.warning_output
    }

    /// Returns impure evaluator inputs observed so far.
    pub fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
        &self.impure_input_trace
    }

    /// Resolves a `symbol` to its interned byte name against the evaluator table.
    ///
    /// This is the same evaluator-global [`SymbolTable`] `eval_primop` resolves
    /// primop names against — the one module load remaps PrimOp symbols into — so
    /// diagnostics that key on a lowered node's `Symbol` (e.g. a tier-1
    /// dispatched-primop histogram) name imported-module builtins correctly,
    /// unlike a per-module IR symbol table. Returns [`None`] when `symbol` is not
    /// interned.
    pub fn resolve_symbol(&self, symbol: Symbol) -> Option<&[u8]> {
        self.symbols.resolve(symbol)
    }

    /// Returns whether the impure input trace is complete and cache-usable.
    pub const fn impure_input_trace_complete(&self) -> bool {
        self.impure_input_trace_complete
    }

    /// Returns a snapshot of mirrored evaluator counters.
    pub fn stats(&self) -> EvalStats {
        self.stats_snapshot()
    }

    /// Builds a parallel-mode heap over a fresh K-shard shared arena.
    ///
    /// The evaluator uses shard 0; worker `TreeWalk`s adopt the remaining shards
    /// through [`TreeWalk::adopt_shared_heap_shard`].
    fn shared_parallel_heap(workers: std::num::NonZeroUsize) -> EvalHeap {
        /// Per-shard record capacity hint. Chunk levels grow geometrically, so
        /// a generous hint costs only `log2` empty chunk-table slots up front
        /// while making shard exhaustion unreachable for real evaluations.
        const SHARED_HEAP_SHARD_CAPACITY: usize = 1 << 32;
        let arena = Arc::new(SharedHeapArena::new(
            workers.get(),
            SHARED_HEAP_SHARD_CAPACITY,
        ));
        match arena.shard(0) {
            Ok(shard) => {
                let shard = Arc::clone(shard);
                EvalHeap::with_shared_shard(arena, shard)
            }
            Err(_) => {
                // Unreachable: a shared arena always holds shard 0. Degrade to
                // the serial heap rather than panicking in production.
                debug_assert!(false, "shared arena is never built without shard 0");
                EvalHeap::new()
            }
        }
    }

    /// Replaces this evaluator's heap with one allocating into `shard` of the
    /// caller's shared `arena`.
    ///
    /// This is the multi-worker construction seam: the P3b scheduler and
    /// K-worker harness build one arena, then one `TreeWalk`
    /// per worker, and hands worker `i` shard `i` so every worker can resolve
    /// every other worker's allocations. It must be called before evaluation
    /// begins - the freshly constructed heap it replaces must not have handed
    /// out any values yet.
    ///
    /// GC-stress stays quiesced; the options' memory budget is re-applied.
    // Production multi-worker wiring is the P3b scheduler slice; the in-crate
    // K-worker harness exercises this today.
    #[allow(dead_code)]
    pub(crate) fn adopt_shared_heap_shard(
        &mut self,
        arena: Arc<SharedHeapArena>,
        shard: Arc<SharedHeapShard>,
    ) {
        debug_assert!(
            self.heap.is_empty(),
            "shared heap shard adopted after values were allocated"
        );
        let attrs_hash_cons_enabled = self.heap.attrs_hash_cons_enabled();
        let mut heap = EvalHeap::with_shared_shard(arena, shard);
        heap.set_attrs_hash_cons_enabled(attrs_hash_cons_enabled);
        heap.set_gc_stress_policy(GcStressPolicy::disabled());
        if let Some(heap_memory_budget) = self.options.heap_memory_budget() {
            heap.set_memory_budget(heap_memory_budget);
            heap.set_resident_memory_mode(
                EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback,
            );
        }
        self.heap = heap;
    }

    /// Evaluates the IR root to weak head normal form.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if evaluation of the root node fails.
    pub fn eval_root(&mut self) -> Result<Value, TreeWalkError> {
        let root = self.current_ir().root;
        let previous_root_eval_node = self.active_root_eval_node.replace(root);
        let result = self.eval_node(root);
        self.active_root_eval_node = previous_root_eval_node;
        result
    }

    /// Evaluates a node to weak head normal form.
    ///
    /// This initial public node entry point is intentionally limited to scalar
    /// literal, list literal, static attrset literal, string and URI literal,
    /// control-flow, boolean operator, pipe application, string/list
    /// concatenation, attrset update, static
    /// attribute selection, lexical `let` environment, simple and formal-set
    /// lambda application, lazy `with` lookup, numeric arithmetic, numeric and
    /// string/list comparison, direct strict unary primops,
    /// scalar/string/function/list/attrset equality, and fact-guided thunk
    /// allocation nodes. Non-expression IR helper nodes return
    /// [`TreeWalkErrorKind::InvalidNodeKind`] when they are evaluated directly.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if `id` does not address a node in this IR, if
    /// the node payload does not match its kind, if a scalar type check fails,
    /// if thunk forcing fails, or if the node kind is not yet implemented by
    /// this evaluator slice.
    pub(super) fn eval_node_on_current_stack(&mut self, id: IrId) -> Result<Value, TreeWalkError> {
        let node = *self
            .node(id)
            .map_err(|error| self.error_with_current_source(error))?;
        let value = match node.kind {
            IrKind::Int => {
                if let IrData::Int(value) = node.data {
                    self.runtime_int_value(id, node.span, value)
                } else {
                    Err(self.invalid_payload(id, &node, "integer payload"))
                }
            }
            IrKind::Float => {
                if let IrData::Float(value) = node.data {
                    self.runtime_float_value(id, node.span, value)
                } else {
                    Err(self.invalid_payload(id, &node, "float payload"))
                }
            }
            IrKind::Bool => {
                if let IrData::Bool(value) = node.data {
                    Ok(Value::bool(value))
                } else {
                    Err(self.invalid_payload(id, &node, "boolean payload"))
                }
            }
            IrKind::Null => {
                if node.data == IrData::None {
                    Ok(Value::null())
                } else {
                    Err(self.invalid_payload(id, &node, "empty payload"))
                }
            }
            IrKind::Str | IrKind::Uri => self.eval_string(id, &node),
            IrKind::Path => self.eval_path(id, &node),
            IrKind::SearchPath => self.eval_search_path(id, &node),
            IrKind::Interp => self.eval_interp(id, &node),
            IrKind::LocalVar => self.eval_local_var(id, &node),
            IrKind::UpvalVar => self.eval_upval_var(id, &node),
            IrKind::GlobalVar => self.eval_global_var(id, &node),
            IrKind::BuiltinAttr => self.eval_builtin_attr(id, &node),
            IrKind::List => self.eval_list(id, &node),
            IrKind::AttrSet => self.eval_attrset(id, &node),
            IrKind::Lambda => self.eval_lambda(id, &node),
            IrKind::Apply => self.eval_apply(id, &node),
            IrKind::PrimOp => self.eval_primop(id, &node),
            IrKind::Let => self.eval_let(id, &node),
            IrKind::With => self.eval_with(id, &node),
            IrKind::If => self.eval_if(id, &node),
            IrKind::Assert => self.eval_assert(id, &node),
            IrKind::UnaryOp => self.eval_unary(id, &node),
            IrKind::BinOp => self.eval_binary(id, &node),
            IrKind::Select => self.eval_select(id, &node),
            IrKind::HasAttr => self.eval_has_attr(id, &node),
            IrKind::ThunkAlloc => self.eval_thunk_alloc(id, &node),
            kind => Err(TreeWalkError::new(
                TreeWalkErrorKind::InvalidNodeKind { id, kind },
                node.span,
            )),
        }
        .map_err(|error| self.error_with_current_source(error))?;
        self.force_node_result(id, node.span, value)
            .map_err(|error| self.error_with_current_source(error))
    }

    fn error_with_current_source(&self, error: TreeWalkError) -> TreeWalkError {
        if error.source().is_some() {
            return error;
        }
        let Some(source) = self.error_source_for_current_module() else {
            return error;
        };
        error.with_source(source)
    }

    pub(super) fn context_with_current_source(&self, message: Vec<u8>) -> EvalErrorContext {
        let context = EvalErrorContext::new(message);
        match self.error_source_for_current_module() {
            Some(source) => context.with_source(source),
            None => context,
        }
    }

    fn error_source_for_current_module(&self) -> Option<EvalErrorSource> {
        let source = self
            .modules
            .get(self.current_module.index())
            .and_then(|module| module.source.as_ref())?;
        Some(EvalErrorSource::new(
            source.name.clone(),
            source.bytes.clone(),
        ))
    }

    pub(super) fn force_node_result(
        &mut self,
        id: IrId,
        span: Span,
        mut value: Value,
    ) -> Result<Value, TreeWalkError> {
        loop {
            if self.is_suspended_lazy_identity_thunk(id, span, value)? {
                return Ok(value);
            }
            if !value.is_thunk() {
                return Ok(value);
            }
            let forced = self.force_value(id, span, value)?;
            if forced.raw_eq(value) {
                return Ok(forced);
            }
            value = forced;
        }
    }

    pub(super) fn is_suspended_lazy_identity_thunk(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if !value.is_thunk() || !self.lazy_identity_thunks.contains(&value.relocation_sensitive_identity_bits()) {
            return Ok(false);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let state = thunk
            .cell()
            .state()
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Force { id, source }, span))?;
        Ok(state == ThunkState::Suspended)
    }

    pub(super) fn mark_lazy_identity_thunk(&mut self, value: Value) {
        if value.is_thunk() {
            self.lazy_identity_thunks.insert(value.relocation_sensitive_identity_bits());
        }
    }

    pub(super) fn unmark_lazy_identity_thunk_payload(&mut self, payload: u64) {
        // This runs on every thunk force, but both sets are empty in the common
        // case (no lazy-identity primop is in flight). Skip the lookups entirely
        // when there is nothing to unmark. `lazy_foldl_initial_thunks` is a subset
        // of `lazy_identity_thunks`, so an empty identity set implies an empty
        // foldl set and its remove can be skipped too.
        if self.lazy_identity_thunks.is_empty() {
            return;
        }
        self.lazy_identity_thunks.remove(&payload);
        if !self.lazy_foldl_initial_thunks.is_empty() {
            self.lazy_foldl_initial_thunks.remove(&payload);
        }
    }

    pub(super) fn mark_lazy_foldl_initial_thunk(&mut self, value: Value) {
        self.mark_lazy_identity_thunk(value);
        if value.is_thunk() {
            self.lazy_foldl_initial_thunks.insert(value.relocation_sensitive_identity_bits());
        }
    }

    pub(super) fn eval_lazy_identity_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.is_path_literal_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        self.mark_lazy_identity_thunk(value);
        Ok(value)
    }

    pub(super) fn eval_lazy_foldl_initial_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.is_path_literal_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        self.mark_lazy_foldl_initial_thunk(value);
        Ok(value)
    }

    pub(super) fn is_path_literal_thunk(
        &self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if !value.is_thunk() {
            return Ok(false);
        }
        let thunk = self
            .heap
            .get_thunk(value)
            .map_err(|source| TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span))?;
        let Some(body) = thunk.body_ref() else {
            return Ok(false);
        };
        Ok(self.node_in_module(body.module(), body.id())?.kind == IrKind::Path)
    }

    pub(super) fn consume_suspended_lazy_identity_thunk(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<bool, TreeWalkError> {
        if self.is_suspended_lazy_identity_thunk(id, span, value)? {
            self.unmark_lazy_identity_thunk_payload(value.relocation_sensitive_identity_bits());
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn force_lazy_foldl_initial_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.is_suspended_lazy_identity_thunk(id, span, value)?
            && self
                .lazy_foldl_initial_thunks
                .contains(&value.relocation_sensitive_identity_bits())
        {
            self.unmark_lazy_identity_thunk_payload(value.relocation_sensitive_identity_bits());
            return self.force_value(id, span, value);
        }
        Ok(value)
    }

    pub(super) fn force_demanded_value(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        if self.consume_suspended_lazy_identity_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        let value = self.force_value(id, span, value)?;
        if self.consume_suspended_lazy_identity_thunk(id, span, value)? {
            return self.force_value(id, span, value);
        }
        Ok(value)
    }

    pub(super) fn force_cache_subject_for_thunk(
        &self,
        site: EvalNodeRef,
        thunk: &EvalThunk,
    ) -> Option<ForceCacheSubject> {
        match thunk.kind() {
            EvalThunkKind::Node { body, env, .. } => {
                if !thunk.with_scope_env()?.scopes().is_empty()
                    || !thunk.scoped_global_env()?.scopes().is_empty()
                {
                    return None;
                }
                let free_var_value_hashes =
                    self.inline_free_var_value_hashes_for_body(*body, env)?;
                let lookup_identity = self.cache_lookup_identity_for_node(*body);
                let pure_observation_identity = self.cache_identity_for_node(*body);
                let impure_observation_identity = self.cache_observation_identity_for_node(*body);
                if lookup_identity.is_none()
                    && pure_observation_identity.is_none()
                    && impure_observation_identity.is_none()
                {
                    return None;
                }
                let memoization_admission = if free_var_value_hashes.is_empty() {
                    self.force_cache_memoization_admission_for_node(*body)
                } else {
                    ForceCacheMemoizationAdmission::SelectedSubstrate
                };
                Some(ForceCacheSubject {
                    lookup_identity,
                    pure_observation_identity,
                    impure_observation_identity,
                    metadata_identity: lookup_identity,
                    persistent_clear_identity: impure_observation_identity,
                    free_var_value_hashes,
                    replay_position_module: Some(body.module()),
                    replay_allocation_node: Some(*body),
                    memoization_admission,
                })
            }
            EvalThunkKind::BuiltinAttr { symbol, builtin } => {
                self.force_cache_subject_for_builtin_attr(site, *symbol, *builtin)
            }
            EvalThunkKind::Select {
                select,
                receiver,
                path,
            } => self.force_cache_subject_for_select(*select, *receiver, *path),
            // Force-cache subjects are computed while forcing a claimed thunk,
            // before its captures can be shed; a released kind has no work to
            // cache and admits nothing.
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Released => None,
        }
    }

    fn force_cache_memoization_admission_for_node(
        &self,
        body: EvalNodeRef,
    ) -> ForceCacheMemoizationAdmission {
        if self
            .force_cache_closed_composite_payload_for_node(body, 0)
            .is_some()
        {
            ForceCacheMemoizationAdmission::SelectedSubstrate
        } else {
            ForceCacheMemoizationAdmission::ConditionalThunk
        }
    }

    fn force_cache_closed_composite_payload_for_node(
        &self,
        body: EvalNodeRef,
        depth: usize,
    ) -> Option<CachedExpressionValue> {
        if depth > FORCE_CACHE_PAYLOAD_MAX_DEPTH {
            return None;
        }
        let module_id = body.module();
        let node_id = body.id();
        let node = *self
            .modules
            .get(module_id.index())?
            .ir
            .arena
            .node(node_id)?;
        match node.kind {
            IrKind::List | IrKind::AttrSet => {
                self.force_cache_payload_for_closed_ir_node(body, depth.saturating_add(1))
            }
            IrKind::ThunkAlloc => {
                let IrData::Node(child) = node.data else {
                    return None;
                };
                self.force_cache_closed_composite_payload_for_node(
                    EvalNodeRef::new(module_id, child),
                    depth.saturating_add(1),
                )
            }
            _ => None,
        }
    }

    fn force_cache_subject_for_select(
        &self,
        select: EvalNodeRef,
        receiver: Value,
        path: IrAttrPathId,
    ) -> Option<ForceCacheSubject> {
        let identity = self.cache_synthetic_select_identity(select, path)?;
        let selected_hash =
            self.force_cache_static_select_value_hash(select.module(), receiver, path)?;
        Some(ForceCacheSubject {
            lookup_identity: Some(identity),
            pure_observation_identity: Some(identity),
            impure_observation_identity: None,
            metadata_identity: Some(identity),
            persistent_clear_identity: Some(identity),
            free_var_value_hashes: vec![selected_hash],
            replay_position_module: None,
            replay_allocation_node: None,
            memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
        })
    }

    fn force_cache_subject_for_builtin_attr(
        &self,
        site: EvalNodeRef,
        symbol: Symbol,
        builtin: Builtin,
    ) -> Option<ForceCacheSubject> {
        let execution = builtin.execution();
        let lookup_identity = if Self::builtin_execution_is_force_cache_lookup_safe(execution) {
            self.cache_synthetic_builtin_attr_identity(site, symbol, builtin)
        } else {
            None
        };
        let observation_identity =
            if Self::builtin_execution_is_force_cache_observation_safe(execution) {
                self.cache_synthetic_builtin_attr_identity(site, symbol, builtin)
            } else {
                None
            };
        if lookup_identity.is_none() && observation_identity.is_none() {
            return None;
        }
        Some(ForceCacheSubject {
            lookup_identity,
            pure_observation_identity: lookup_identity,
            impure_observation_identity: observation_identity,
            metadata_identity: lookup_identity,
            persistent_clear_identity: observation_identity,
            free_var_value_hashes: Vec::new(),
            replay_position_module: None,
            replay_allocation_node: None,
            memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
        })
    }

    pub(super) fn force_cache_subject_for_first_class_cacheable_impure_call(
        &self,
        id: IrId,
        builtin: Builtin,
        args: &[EvalPrimOpArg],
    ) -> Option<ForceCacheSubject> {
        if !Self::builtin_execution_is_cacheable_impure_call(builtin.execution(), args.len())
            || !self.with_scopes.is_empty()
            || !self.scoped_globals.is_empty()
        {
            return None;
        }
        let identity = self.cache_first_class_primop_call_identity_for_current_node(id, builtin)?;
        let mut free_var_value_hashes = Vec::new();
        free_var_value_hashes.try_reserve_exact(args.len()).ok()?;
        for (index, arg) in args.iter().enumerate() {
            free_var_value_hashes
                .push(self.force_cache_free_var_value_hash_for_primop_arg(builtin, index, arg)?);
        }
        Some(ForceCacheSubject {
            lookup_identity: Some(identity),
            pure_observation_identity: None,
            impure_observation_identity: Some(identity),
            metadata_identity: Some(identity),
            persistent_clear_identity: Some(identity),
            free_var_value_hashes,
            replay_position_module: None,
            replay_allocation_node: Some(EvalNodeRef::new(self.current_module, id)),
            memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
        })
    }

    fn force_cache_free_var_value_hash_for_primop_arg(
        &self,
        builtin: Builtin,
        index: usize,
        arg: &EvalPrimOpArg,
    ) -> Option<ValueHash> {
        if builtin.execution() == BuiltinExecution::FindFile && index == 0 {
            if let Some(hash) = self.force_cache_builtin_nix_path_arg_hash(arg.value()) {
                return Some(hash);
            }
        }
        if builtin.execution() == BuiltinExecution::FindFile {
            self.force_cache_free_var_value_hash(arg.value())
        } else {
            if Self::builtin_execution_allows_closed_alias_primop_arg(builtin.execution(), index)
                && let Some(hash) =
                    self.force_cache_closed_hash_for_suspended_capture_alias_target(arg.value())
            {
                return Some(hash);
            }
            self.force_cache_free_var_value_hash_without_suspended_aliases(arg.value())
        }
    }

    #[cfg(test)]
    pub(crate) fn test_first_class_primop_arg_hashes_for_current_apply(
        &mut self,
        id: IrId,
        builtin: Builtin,
    ) -> Option<Vec<ValueHash>> {
        let arity = builtin.first_class_arity()?;
        let mut argument_ids = Vec::new();
        let mut current = id;
        loop {
            let node = *self.node(current).ok()?;
            let IrData::Pair { first, second } = node.data else {
                return None;
            };
            argument_ids.push(second);
            let first_node = self.node(first).ok()?;
            if first_node.kind != IrKind::Apply {
                break;
            }
            current = first;
        }
        argument_ids.reverse();

        if argument_ids.len() == arity {
            let mut hashes = Vec::new();
            hashes.try_reserve_exact(argument_ids.len()).ok()?;
            for (index, argument_id) in argument_ids.iter().copied().enumerate() {
                let argument_span = self.node(argument_id).ok()?.span;
                let argument = self.eval_lazy_node(argument_id).ok()?;
                let argument = EvalPrimOpArg::new_in_module(
                    self.current_module,
                    argument_id,
                    argument_span,
                    argument,
                );
                hashes.push(
                    self.force_cache_free_var_value_hash_for_primop_arg(builtin, index, &argument)?,
                );
            }
            return Some(hashes);
        }

        if builtin.execution() != BuiltinExecution::FindFile || argument_ids.len() != 1 {
            return None;
        }
        let argument_id = argument_ids[0];
        let argument_span = self.node(argument_id).ok()?.span;
        let argument = self.eval_lazy_node(argument_id).ok()?;
        let argument =
            EvalPrimOpArg::new_in_module(self.current_module, argument_id, argument_span, argument);
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(2).ok()?;
        hashes.push(self.force_cache_visible_nix_path_arg_hash()?);
        hashes.push(self.force_cache_free_var_value_hash_for_primop_arg(builtin, 1, &argument)?);
        Some(hashes)
    }

    fn force_cache_builtin_nix_path_arg_hash(&self, value: Value) -> Option<ValueHash> {
        let thunk = self.heap.get_thunk(value).ok()?;
        if !self.thunk_is_builtin_nix_path(thunk) {
            return None;
        }
        self.force_cache_visible_nix_path_arg_hash()
    }

    fn force_cache_visible_nix_path_arg_hash(&self) -> Option<ValueHash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION);
        hasher.update(b"synthetic-builtin-nix-path-v1");
        let len = u64::try_from(self.visible_nix_path().len()).ok()?;
        hasher.update(&len.to_le_bytes());
        for entry in self.visible_nix_path() {
            hasher.update(b"entry-prefix");
            Self::update_cache_identity_chunk(&mut hasher, entry.prefix())?;
            hasher.update(b"entry-path");
            Self::update_cache_identity_chunk(&mut hasher, entry.path())?;
        }
        Some(ValueHash::from_force_captured_value_hash(
            ForceCapturedValueHash::from_hasher(hasher),
        ))
    }

    fn thunk_is_builtin_nix_path(&self, thunk: &EvalThunk) -> bool {
        match thunk.kind() {
            EvalThunkKind::BuiltinAttr { builtin, .. } => {
                builtin.execution() == BuiltinExecution::NixPathValue
            }
            EvalThunkKind::Node { body, .. } => {
                let symbols = &self.symbols;
                self.modules
                    .get(body.module().index())
                    .is_some_and(|module| {
                        let Some(node) = module.ir.arena.node(body.id()) else {
                            return false;
                        };
                        node.kind == IrKind::BuiltinAttr
                            && Self::builtin_attr_execution(symbols, node)
                                == Some(BuiltinExecution::NixPathValue)
                    })
            }
            EvalThunkKind::Apply { .. }
            | EvalThunkKind::Apply2 { .. }
            | EvalThunkKind::Select { .. }
            | EvalThunkKind::Released => false,
        }
    }

    const fn builtin_execution_is_cacheable_impure_call(
        execution: BuiltinExecution,
        arity: usize,
    ) -> bool {
        matches!(
            (execution, arity),
            (
                BuiltinExecution::Import
                    | BuiltinExecution::PathExists
                    | BuiltinExecution::ReadDir
                    | BuiltinExecution::ReadFile
                    | BuiltinExecution::ReadFileType
                    | BuiltinExecution::StrictUnary {
                        primop: StrictUnaryPrimOp::GetEnv,
                        ..
                    },
                1,
            ) | (
                BuiltinExecution::StrictBinary {
                    primop: StrictBinaryPrimOp::HashFile,
                    ..
                } | BuiltinExecution::FindFile,
                2,
            )
        )
    }

    const fn builtin_execution_allows_closed_alias_primop_arg(
        execution: BuiltinExecution,
        index: usize,
    ) -> bool {
        matches!(
            (execution, index),
            (
                BuiltinExecution::Import
                    | BuiltinExecution::PathExists
                    | BuiltinExecution::ReadDir
                    | BuiltinExecution::ReadFile
                    | BuiltinExecution::ReadFileType
                    | BuiltinExecution::StrictUnary {
                        primop: StrictUnaryPrimOp::GetEnv,
                        ..
                    },
                0,
            ) | (
                BuiltinExecution::StrictBinary {
                    primop: StrictBinaryPrimOp::HashFile,
                    ..
                },
                0 | 1,
            )
        )
    }
}
