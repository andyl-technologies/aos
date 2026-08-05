//! The helper-worker pool lifecycle for one parallel evaluation.
//!
//! [`ParallelDemandPool::spawn`] stands up `K - 1` helper workers (plus the
//! optional speculation producer) around the main evaluator before root
//! evaluation starts; [`ParallelDemandPool::finish`] tears the pool down and
//! merges helper statistics and traces back into the main evaluator. The
//! helper worker loop itself ([`TreeWalk::parallel_worker_loop`]) lives here
//! next to the outcome type it returns.

use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::*;

/// Per-helper results carried back to the main evaluator at join.
struct ParallelWorkerOutcome {
    stats: EvalStats,
    trace_output: Vec<EvalTraceOutput>,
    warning_output: Vec<EvalWarningOutput>,
    impure_input_trace: Vec<ImpureInputFingerprint>,
    impure_input_trace_complete: bool,
}

/// The running helper-worker pool for one parallel evaluation.
///
/// Constructed by [`ParallelDemandPool::spawn`] before root evaluation starts
/// and torn down by [`ParallelDemandPool::finish`] after evaluation ends
/// (successful or not), which merges helper statistics and traces back into
/// the main evaluator.
pub(crate) struct ParallelDemandPool {
    shared: Arc<SharedEvalContext>,
    handles: Vec<std::thread::JoinHandle<ParallelWorkerOutcome>>,
    /// The pool-only speculative parse-ahead producer (RFC-0007 S2/S6), present
    /// only when `AOS_NIX_SPECULATE` enabled it. Stopped by closing the shared
    /// frontier and joined in [`Self::finish`].
    speculation: Option<std::thread::JoinHandle<()>>,
}

impl ParallelDemandPool {
    /// Spawns `K - 1` helper workers next to `main` when parallel mode asks
    /// for `K >= 2` workers.
    ///
    /// Returns `None` (and leaves evaluation fully serial) when parallel mode
    /// is off, when `K == 1`, or when the worker substrate (shared arena,
    /// force registry, worker ids, or OS threads) is unavailable.
    pub(crate) fn spawn(main: &mut TreeWalk) -> Option<Self> {
        let workers = main.options.parallel_workers()?.get();
        if workers < 2 {
            return None;
        }
        // Speculative parse-ahead is pool-only: read the budget here so the shared
        // frontier is created (and the producer spawned) only under a pool.
        let speculation_budget = super::speculation::SpeculationBudget::from_env();
        let root_ir = main.modules.first().map(|module| module.ir.clone())?;
        let arena = main.heap.shared_arena()?.clone();
        let attrs_hash_cons_enabled = main.heap.attrs_hash_cons_enabled();
        let registry = main.parallel_force_registry()?.clone();
        // Multi-worker shape projection is opt-in (see
        // `TreeWalkOptions::parallel_shape_projection`); the record shape
        // mode also keeps projection on at `K >= 2` because its heap-resident
        // select path is what the mode exists to measure. When enabled, seed
        // the authoritative shared shape table from the main worker's table:
        // record `Arc`s are shared, so main's existing handles remain valid
        // against the log. Whenever no shared log exists (default, or a
        // failed seed) projection is disabled everywhere - main's table is
        // dropped below - so no process-local id can ever reach shared attrs
        // metadata.
        let shapes = if main.options.parallel_shape_projection()
            || main.options.attr_shape_mode() == AttrShapeMode::Record
        {
            parallel_shape::SharedShapeLog::seed(main.shape_table.as_ref())
        } else {
            None
        };
        if shapes.is_none() {
            main.shape_table = None;
        }
        let shared = Arc::new(SharedEvalContext {
            version: AtomicU64::new(0),
            modules: SharedModuleRegistry::seed(&main.modules),
            symbols: SharedSymbolLog::seed(main.symbols.clone()),
            known_derivations: SharedKnownDerivationLog::default(),
            text_store: SharedTextStoreLog::default(),
            shapes,
            imports: parallel_import::SharedImportLog::default(),
            speculation: SpeculativeParseStore::default(),
            speculation_frontier: speculation_budget
                .as_ref()
                .map(|_| SpeculationFrontier::default()),
            memo: main.options.memo_l1_active().then(|| {
                Arc::new(super::memo::SharedMemoTable::new(
                    main.options.memo_options().l1_bytes,
                ))
            }),
            queue: DemandQueue::default(),
            counters: DemandCounters::default(),
        });
        let root_source = main
            .modules
            .first()
            .and_then(|module| module.source.clone());
        let realizer = main.ifd_realizer.clone();
        let mut handles = Vec::with_capacity(workers - 1);
        for worker_index in 1..workers {
            let Some(worker_id) = ParallelThunkWorkerId::new(
                ParallelThunkWorkerId::FIRST.get() + worker_index as u64,
            ) else {
                tracing::warn!(
                    target: "aos_nix::eval::parallel",
                    worker_index,
                    "parallel worker id space exhausted; running with fewer helpers"
                );
                break;
            };
            let Ok(shard) = arena.shard(worker_index).cloned() else {
                tracing::warn!(
                    target: "aos_nix::eval::parallel",
                    worker_index,
                    "shared arena is missing a worker shard; running with fewer helpers"
                );
                break;
            };
            let mut options = main.options.clone();
            options.set_parallel_thunk_worker_id(worker_id);
            // Helpers keep the demand-side semantics but skip advisory cache
            // persistence: durable cache writes stay owned by the main worker.
            options.clear_persist_cache_root();
            let ir = root_ir.clone();
            let arena = Arc::clone(&arena);
            let registry = Arc::clone(&registry);
            let shared_for_worker = Arc::clone(&shared);
            let root_source = root_source.clone();
            let realizer = realizer.clone();
            let memo_economics = main.memo_economics.clone();
            let spawned = std::thread::Builder::new()
                .name(format!("aos-nix-eval-{worker_index}"))
                // Helpers run full tree-walk recursion over the same package
                // spines as the main evaluator, which is tuned for a main
                // thread's 8 MiB stack; the Rust spawned-thread default of
                // 2 MiB overflows on deep instantiations. Give helpers the
                // same order of headroom the main thread gets.
                .stack_size(HELPER_STACK_SIZE)
                .spawn(move || {
                    let eval_cache = Arc::new(Mutex::new(EvalCacheRuntime::from_enabled(false)));
                    let mut walk = match root_source {
                        Some(source) => TreeWalk::with_options_and_source_and_eval_cache(
                            &ir,
                            options,
                            source.name,
                            source.bytes,
                            eval_cache,
                        ),
                        None => TreeWalk::with_options_and_eval_cache(&ir, options, eval_cache),
                    };
                    walk.heap
                        .set_attrs_hash_cons_enabled(attrs_hash_cons_enabled);
                    walk.adopt_shared_heap_shard(arena, shard);
                    walk.set_parallel_force_registry(registry);
                    walk.memo_economics = memo_economics;
                    if let Some(realizer) = realizer {
                        walk.set_ifd_realizer(realizer);
                    }
                    // Replace the shape table with a shared-log replica so record `Arc`s
                    // and dense ids agree globally; otherwise projection stays disabled.
                    walk.shape_table = shared_for_worker
                        .shapes
                        .as_ref()
                        .and_then(parallel_shape::SharedShapeLog::replica);
                    walk.shared = Some(shared_for_worker);
                    walk.parallel_worker_loop()
                });
            match spawned {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    tracing::warn!(
                        target: "aos_nix::eval::parallel",
                        worker_index,
                        %error,
                        "failed to spawn parallel eval worker; running with fewer helpers"
                    );
                    break;
                }
            }
        }
        if handles.is_empty() {
            return None;
        }
        // Pool-only speculative parse-ahead producer (RFC-0007 S2/S6, design B):
        // a single thread draining the shared candidate frontier (root static
        // path-literal edges seeded now, plus every `readDir`ed directory's `.nix`
        // entries fed by the evaluating threads) into the shared store ahead of
        // demand. Reached only here, so never at K == 1.
        let root_base = main
            .modules
            .first()
            .and_then(|module| module.path_literal_base.clone())
            .or_else(|| {
                root_source.as_ref().and_then(|source| {
                    Path::new(OsStr::from_bytes(&source.name))
                        .parent()
                        .map(|parent| parent.as_os_str().as_bytes().to_vec())
                })
            })
            .unwrap_or_default();
        let speculation = speculation_budget.and_then(|budget| {
            super::speculation::seed_static_edges(&root_ir, &root_base, &shared);
            let producer_shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("aos-nix-speculate".to_string())
                .stack_size(HELPER_STACK_SIZE)
                .spawn(move || {
                    super::speculation::run_speculation_producer(producer_shared, budget);
                })
                .ok()
        });
        main.shared = Some(shared.clone());
        Some(Self {
            shared,
            handles,
            speculation,
        })
    }

    /// Shuts the queue down, joins every helper, and merges their statistics
    /// and traces into `main`.
    ///
    /// Helper trace and warning output is appended after the main worker's
    /// (stderr interleaving across workers is inherently unordered); impure
    /// input traces are unioned, which is order-safe because the trace is
    /// canonicalized before durable use. The merged helper [`EvalStats`] are
    /// staged on `main` and folded into the next stats snapshot.
    ///
    /// # Panics
    ///
    /// Resumes the panic of any helper worker that panicked.
    pub(crate) fn finish(self, main: &mut TreeWalk) {
        self.shared.queue.shutdown();
        // Close the frontier and join the speculation producer before draining
        // helpers, so a still-parsing producer stops promptly rather than
        // speculating past the evaluation it was serving.
        if let Some(frontier) = self.shared.speculation_frontier.as_ref() {
            frontier.close();
        }
        if let Some(handle) = self.speculation {
            let _ = handle.join();
        }
        let mut panic: Option<Box<dyn std::any::Any + Send>> = None;
        for handle in self.handles {
            match handle.join() {
                Ok(outcome) => {
                    main.stats.merge_from(&outcome.stats);
                    main.trace_output.extend(outcome.trace_output);
                    main.warning_output.extend(outcome.warning_output);
                    main.impure_input_trace.extend(outcome.impure_input_trace);
                    main.impure_input_trace_complete &= outcome.impure_input_trace_complete;
                }
                Err(payload) => panic = Some(payload),
            }
        }
        main.sync_shared_context();
        main.shared = None;
        let published = self.shared.counters.published.load(Ordering::Relaxed);
        let dropped = self.shared.counters.dropped.load(Ordering::Relaxed);
        let executed = self.shared.counters.executed.load(Ordering::Relaxed);
        let executed_values = self.shared.counters.executed_values.load(Ordering::Relaxed);
        let task_nanos = self.shared.counters.task_nanos.load(Ordering::Relaxed);
        let loop_nanos = self.shared.counters.loop_nanos.load(Ordering::Relaxed);
        let claim_wait_nanos = self
            .shared
            .counters
            .claim_wait_nanos
            .load(Ordering::Relaxed);
        let claim_waits = self.shared.counters.claim_waits.load(Ordering::Relaxed);
        let queue_peak = self.shared.queue.peak.load(Ordering::Relaxed);
        let speculated = self.shared.speculation.len();
        let speculation_hits = self.shared.speculation.hits();
        // Helper occupancy: fraction of aggregate helper loop wall spent
        // executing tasks (task time still includes claim-wait blocking; the
        // claim-wait counters bound that share when stats are enabled).
        let helper_busy_permille = if loop_nanos > 0 {
            task_nanos.saturating_mul(1000) / loop_nanos
        } else {
            0
        };
        tracing::debug!(
            target: "aos_nix::eval::parallel",
            published,
            dropped,
            executed,
            executed_values,
            task_nanos,
            loop_nanos,
            helper_busy_permille,
            queue_peak,
            speculated,
            speculation_hits,
            "parallel demand pool drained"
        );
        if main.options.eval_stats_dump() {
            // Mirrors the `AOS_NIX_EVAL_STATS=1` JSON stats convention so
            // scheduler behavior is observable next to the eval work counters.
            // The `*_arc_clones` / `env_frame_allocs` "K-tax" counters ride here
            // (see `ParallelKtaxCounters`) so one benchmark pass captures the
            // per-thunk-cell coordination cost the L2 ceiling verdict named;
            // they are otherwise struct-only and invisible to a bench run.
            let ktax = main.parallel_ktax_snapshot();
            let thunk_state_arc_clones = ktax.thunk_state_arc_clones;
            let payload_arc_clones = ktax.payload_arc_clones;
            let env_frame_allocs = ktax.env_frame_allocs;
            eprintln!(
                "{{\"aos_nix_parallel_demand\":{{\
\"tasks_published\":{published},\
\"tasks_dropped\":{dropped},\
\"tasks_executed\":{executed},\
\"task_values_executed\":{executed_values},\
\"task_nanos\":{task_nanos},\
\"loop_nanos\":{loop_nanos},\
\"helper_busy_permille\":{helper_busy_permille},\
\"claim_wait_nanos\":{claim_wait_nanos},\
\"claim_waits\":{claim_waits},\
\"queue_peak\":{queue_peak},\
\"speculated\":{speculated},\
\"speculation_hits\":{speculation_hits},\
\"thunk_state_arc_clones\":{thunk_state_arc_clones},\
\"payload_arc_clones\":{payload_arc_clones},\
\"env_frame_allocs\":{env_frame_allocs}\
}}}}"
            );
        }
        if let Some(payload) = panic {
            std::panic::resume_unwind(payload);
        }
    }
}

impl TreeWalk {
    /// Runs a helper worker: steal demand tasks until the pool shuts down.
    fn parallel_worker_loop(mut self) -> ParallelWorkerOutcome {
        let loop_started = std::time::Instant::now();
        let id = self.current_ir().root;
        let span = self
            .current_ir()
            .arena
            .node(id)
            .map(|node| node.span)
            .unwrap_or_default();
        while let Some(task) = self
            .shared
            .as_ref()
            .map(Arc::clone)
            .and_then(|shared| shared.queue.pop_or_park())
        {
            self.sync_shared_context();
            let task_started = std::time::Instant::now();
            let mut executed_values = 0u64;
            for value in &task.values {
                // Task errors are deliberately dropped: any error inside a
                // shared thunk body has been published for deterministic
                // replay, and errors outside thunk bodies are re-derived by
                // the main worker's own serial pass.
                let _ = self.run_demand_value(id, span, task.kind, *value);
                executed_values += 1;
            }
            if let Some(shared) = self.shared.as_ref() {
                shared.counters.executed.fetch_add(1, Ordering::Relaxed);
                shared
                    .counters
                    .executed_values
                    .fetch_add(executed_values, Ordering::Relaxed);
                shared.counters.task_nanos.fetch_add(
                    u64::try_from(task_started.elapsed().as_nanos()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
            }
        }
        if let Some(shared) = self.shared.as_ref() {
            shared.counters.loop_nanos.fetch_add(
                u64::try_from(loop_started.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        ParallelWorkerOutcome {
            stats: self.stats_snapshot(),
            trace_output: std::mem::take(&mut self.trace_output),
            warning_output: std::mem::take(&mut self.warning_output),
            impure_input_trace: std::mem::take(&mut self.impure_input_trace),
            impure_input_trace_complete: self.impure_input_trace_complete,
        }
    }
}
