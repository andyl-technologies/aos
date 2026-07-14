//! Core evaluation entry points, scope/environment management, and module bookkeeping.

use super::*;
use crate::cache::hashing::ForceCapturedValueHash;
use crate::eval::heap::{SharedHeapArena, SharedHeapShard};
mod force_identity;
mod force_payload;
mod force_payload_memo;
pub(in crate::eval::tree_walk) use force_payload_memo::ForcePayloadMemo;
mod cache_identity;
mod force_persistence;
mod force_subject;
#[cfg(feature = "candidate_c_value")]
mod heap_image;
#[cfg(feature = "candidate_c_value")]
mod snapshot_store;
#[cfg(feature = "candidate_c_value")]
pub(in crate::eval::tree_walk) use snapshot_store::{
    SnapshotAdoptAttempt, snapshot_tier_enabled, snapshot_warm_requested,
};
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
        let gc_mode =
            if options.parallel_workers().is_some() || options.parallel_thunk_payloads_enabled() {
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
            env: ActiveFrameStack::new(),
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
            primop_builtin_cache: primop_builtin_cache::PrimopBuiltinCache::default(),
            formal_set_layout_cache: formal_set_layout_cache::FormalSetLayoutCache::default(),
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
            source_store_string_cache: BTreeMap::new(),
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
            force_payload_memo: std::cell::RefCell::new(ForcePayloadMemo::new(force_cache_active)),
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
        if !value.is_thunk()
            || !self
                .lazy_identity_thunks
                .contains(&value.relocation_sensitive_identity_bits())
        {
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
            self.lazy_identity_thunks
                .insert(value.relocation_sensitive_identity_bits());
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
            self.lazy_foldl_initial_thunks
                .insert(value.relocation_sensitive_identity_bits());
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
}
