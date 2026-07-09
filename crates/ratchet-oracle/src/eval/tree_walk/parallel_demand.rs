//! Production demand fan-out scheduling for parallel evaluation (L2-P3b).
//!
//! Under `TreeWalkOptions::parallel_workers = Some(K)` with `K >= 2`, the
//! public evaluation drivers spawn `K - 1` helper worker threads next to the
//! main evaluator. Every worker owns a production [`TreeWalk`] over its own
//! shard of the one [`SharedHeapArena`](crate::eval::heap::SharedHeapArena),
//! and all workers share:
//!
//! - one **module registry** ([`SharedModuleRegistry`]): lowered modules are
//!   published append-only under a global dense id space, so any worker can
//!   force a thunk whose body [`EvalNodeRef`](crate::eval::EvalNodeRef) names
//!   a module another worker imported;
//! - one **symbol log** ([`SharedSymbolLog`]): every worker's live
//!   [`SymbolTable`] is a strict prefix replica of the shared log, so a
//!   `Symbol` allocated by any worker resolves identically on every worker;
//! - one **known-derivation log** and one **text-store log**: `.drv`
//!   surfaces and `builtins.toFile` texts computed by any worker are visible
//!   to the serializer on every worker;
//! - one **import-result log** ([`parallel_import::SharedImportLog`]):
//!   completed imports are adopted instead of re-parsed and re-evaluated by
//!   other workers (L2-P4);
//! - optionally one **shape log** ([`parallel_shape::SharedShapeLog`]): when
//!   [`TreeWalkOptions::parallel_shape_projection`] is enabled, hidden-class
//!   shape ids are dense in one shared table instead of projection being
//!   disabled at `K >= 2` (L2-P4);
//! - one **demand queue** ([`DemandQueue`]): strict-force fan-out sites (the
//!   `derivation` builtin's attribute and list coercion loops) publish
//!   batches of guaranteed-needed force work that idle helpers steal.
//!
//! # Replica synchronization
//!
//! Workers never translate ids. Instead every worker's local module vector,
//! symbol table, known-derivation map, and text store are prefix replicas of
//! the shared logs, refreshed by [`TreeWalk::sync_shared_context`] at the
//! *ingestion points* where foreign values can first become visible:
//!
//! - replaying a parallel thunk cell's published result (the P2 claim/park
//!   protocol's replay branch), and
//! - receiving a task from the demand queue.
//!
//! This is sound because a worker publishes every symbol, module, known
//! derivation, and text-store entry it creates *before* it publishes any
//! value that can reference them, and cross-worker value visibility always
//! flows through a release/acquire edge of a parallel thunk cell (or the
//! queue mutex). The shared-log version counters are therefore never stale
//! at an ingestion point.
//!
//! # What fan-out publishes
//!
//! Only work the serial evaluator is already committed to forcing:
//!
//! - every attribute value of a `derivation` call is forced unconditionally,
//!   so scalar-only attribute thunks are published as
//!   [`DemandTaskKind::Force`] batches;
//! - every non-scalar derivation attribute is string-coerced by the serial
//!   loop (lists element by element, hookless attrsets through `outPath`,
//!   and the same shapes under `__structuredAttrs`), so those entries are
//!   published as [`DemandTaskKind::Coerce`] batches *at `derivationStrict`
//!   entry* (L2-P5, see `eval_derivation::demand_fanout`) and again per
//!   attribute as the serial loop forces each list. The coercion executor
//!   mirrors exactly that demand (force; lists recurse; hookless attrsets
//!   force `outPath`), and a helper coercing a dependency attrset runs its
//!   `derivationStrict`, which publishes *its* entry fan-out - the eager
//!   transitive walk that keeps helpers saturated ahead of the serializer.
//!
//! Duplicate demand between the main worker and helpers is deduplicated by
//! the parallel thunk claim protocol: the first claimer runs a body once and
//! everyone else replays the published result.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};

use crate::syntax::AstError;

use super::*;

/// Values per published demand task.
///
/// One task must amortize queue and claim overhead across several forces;
/// derivation dependency elements are typically whole package instantiations,
/// so small batches keep the queue granular enough for stealing while
/// bounding per-task overhead.
const DEMAND_TASK_CHUNK: usize = 4;

/// Returns the batch size for one published task of `kind`.
///
/// Force tasks batch [`DEMAND_TASK_CHUNK`] plain forces to amortize queue
/// overhead. Coercion tasks carry a single value: each value can be a whole
/// package subtree, and batching would let one force blocked on a contended
/// claim hold the rest of the batch hostage inside a parked helper while
/// other helpers idle (L2-P5 convoy measurement).
const fn demand_task_chunk(kind: DemandTaskKind) -> usize {
    match kind {
        DemandTaskKind::Force => DEMAND_TASK_CHUNK,
        DemandTaskKind::Coerce => 1,
    }
}

/// Maximum queued tasks before publishers drop further fan-out.
///
/// The queue only ever holds work the publisher is itself about to perform
/// serially, so dropping under saturation costs nothing but lost overlap -
/// but lost overlap is precisely what starves helpers on wide evaluations
/// (P3b's cap of 1024 dropped ~35% of published fan-out on the wide corpus
/// while two of three helpers idled). Tasks are two machine words plus an
/// at-most-four-value batch, so a deep queue is memory-cheap; the cap now
/// exists only to bound a pathological publish storm.
const DEMAND_QUEUE_CAP: usize = 65536;

/// Stack size for helper worker threads.
///
/// Helper evaluation recurses as deeply as the main evaluator, whose
/// `max_call_depth` guard is calibrated against a main-thread stack (8 MiB on
/// the supported platforms), so helpers get double that rather than the 2 MiB
/// Rust spawned-thread default, which overflows on deep package spines.
const HELPER_STACK_SIZE: usize = 16 << 20;

/// Recovers a mutex guard, ignoring poisoning.
///
/// Every critical section guarded by the shared-context mutexes performs only
/// append-and-publish steps whose interruption points cannot unwind (memory
/// allocation failures abort), so a poisoned lock still guards consistent
/// data; the poison flag is only set if a panic unwinds through user-visible
/// evaluator bugs, in which case the pool propagates the panic at join.
pub(super) fn recover<'a, T: ?Sized>(
    result: Result<MutexGuard<'a, T>, std::sync::PoisonError<MutexGuard<'a, T>>>,
) -> MutexGuard<'a, T> {
    match result {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The append-only shared symbol log behind every worker's prefix replica.
#[derive(Debug, Default)]
pub(crate) struct SharedSymbolLog {
    /// Published length of `table`; release-stored after each append batch.
    version: AtomicUsize,
    /// The authoritative global symbol table.
    table: Mutex<SymbolTable>,
}

impl SharedSymbolLog {
    /// Seeds the log with the main evaluator's initial symbol table.
    fn seed(table: SymbolTable) -> Self {
        let version = AtomicUsize::new(table.len());
        Self {
            version,
            table: Mutex::new(table),
        }
    }

    /// Appends the log's unseen suffix to a worker's prefix replica.
    fn sync_into(&self, local: &mut SymbolTable) {
        if self.version.load(Ordering::Acquire) <= local.len() {
            return;
        }
        let table = recover(self.table.lock());
        for bytes in &table.symbols()[local.len()..] {
            if local.intern(bytes).is_err() {
                tracing::warn!(
                    target: "aos_nix::eval::parallel",
                    "shared symbol log sync aborted: local replica is full"
                );
                return;
            }
        }
    }

    /// Interns `bytes` in the shared log and mirrors it into `local`.
    ///
    /// The local replica is first synchronized to the log tip so the new
    /// symbol receives the same dense id on every worker.
    fn intern(&self, local: &mut SymbolTable, bytes: &[u8]) -> Result<Symbol, AstError> {
        let mut table = recover(self.table.lock());
        for text in &table.symbols()[local.len()..] {
            local.intern(text)?;
        }
        let symbol = table.intern(bytes)?;
        let local_symbol = local.intern(bytes)?;
        debug_assert_eq!(symbol, local_symbol, "prefix replica diverged from log");
        self.version.store(table.len(), Ordering::Release);
        Ok(symbol)
    }
}

/// The append-only shared registry of lowered modules.
///
/// Entry `i` is the module with [`EvalModuleId`] `i`; every worker's local
/// module vector is a prefix replica cloned from here.
#[derive(Debug, Default)]
pub(crate) struct SharedModuleRegistry {
    /// Published length of `entries`; release-stored after each append.
    version: AtomicUsize,
    entries: Mutex<Vec<TreeWalkModule>>,
}

impl SharedModuleRegistry {
    /// Seeds the registry with the main evaluator's modules (the root module).
    fn seed(modules: &[TreeWalkModule]) -> Self {
        let entries = modules.to_vec();
        Self {
            version: AtomicUsize::new(entries.len()),
            entries: Mutex::new(entries),
        }
    }

    /// Clones the registry's unseen suffix onto a worker's local vector.
    fn sync_into(&self, local: &mut Vec<TreeWalkModule>) {
        if self.version.load(Ordering::Acquire) <= local.len() {
            return;
        }
        let entries = recover(self.entries.lock());
        local.extend_from_slice(&entries[local.len()..]);
    }

    /// Publishes `module` under the next global id and installs it locally.
    ///
    /// The local vector is first synchronized so the freshly published module
    /// lands at the same index globally and locally. Returns the module id,
    /// or `None` if the id space is exhausted.
    fn publish(&self, local: &mut Vec<TreeWalkModule>, module: TreeWalkModule) -> Option<u32> {
        let mut entries = recover(self.entries.lock());
        if entries.len() > local.len() {
            local.extend_from_slice(&entries[local.len()..]);
        }
        let raw = u32::try_from(entries.len()).ok()?;
        entries.push(module.clone());
        local.push(module);
        self.version.store(entries.len(), Ordering::Release);
        Some(raw)
    }
}

/// The append-only shared log of `.drv` surfaces recorded by any worker.
#[derive(Debug, Default)]
pub(crate) struct SharedKnownDerivationLog {
    version: AtomicUsize,
    log: Mutex<Vec<(nix_compat::store_path::StorePath<String>, KnownDerivation)>>,
}

impl SharedKnownDerivationLog {
    /// Publishes one known derivation for other workers to adopt.
    fn publish(&self, path: &nix_compat::store_path::StorePath<String>, known: &KnownDerivation) {
        let mut log = recover(self.log.lock());
        log.push((path.clone(), known.clone()));
        self.version.store(log.len(), Ordering::Release);
    }

    /// Merges log entries past `cursor` into a worker's local map.
    fn sync_into(
        &self,
        cursor: &mut usize,
        local: &mut BTreeMap<nix_compat::store_path::StorePath<String>, KnownDerivation>,
    ) {
        if self.version.load(Ordering::Acquire) <= *cursor {
            return;
        }
        let log = recover(self.log.lock());
        for (path, known) in &log[*cursor..] {
            local.entry(path.clone()).or_insert_with(|| known.clone());
        }
        *cursor = log.len();
    }
}

/// The append-only shared log of `builtins.toFile` texts.
#[derive(Debug, Default)]
pub(crate) struct SharedTextStoreLog {
    version: AtomicUsize,
    log: Mutex<Vec<(Vec<u8>, TextStoreEntry)>>,
}

impl SharedTextStoreLog {
    /// Publishes one text-store entry for other workers to adopt.
    fn publish(&self, path: &[u8], entry: &TextStoreEntry) {
        let mut log = recover(self.log.lock());
        log.push((path.to_vec(), entry.clone()));
        self.version.store(log.len(), Ordering::Release);
    }

    /// Merges log entries past `cursor` into a worker's local map.
    fn sync_into(&self, cursor: &mut usize, local: &mut BTreeMap<Vec<u8>, TextStoreEntry>) {
        if self.version.load(Ordering::Acquire) <= *cursor {
            return;
        }
        let log = recover(self.log.lock());
        for (path, entry) in &log[*cursor..] {
            local
                .entry(path.clone())
                .or_insert_with(|| entry.clone());
        }
        *cursor = log.len();
    }
}

/// How a demand task's values are evaluated by the executing worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DemandTaskKind {
    /// Force each value to weak head normal form.
    Force,
    /// Mirror derivation string coercion demand: force each value, recurse
    /// into list elements, and force the `outPath` attribute of attrsets.
    Coerce,
}

/// One published batch of guaranteed-needed force work.
#[derive(Debug)]
struct DemandTask {
    kind: DemandTaskKind,
    values: Vec<Value>,
}

/// Queue state guarded by the demand-queue mutex.
#[derive(Debug, Default)]
struct DemandQueueState {
    tasks: VecDeque<DemandTask>,
    shutdown: bool,
}

/// The shared injector queue helpers park on while starved.
#[derive(Debug, Default)]
pub(crate) struct DemandQueue {
    state: Mutex<DemandQueueState>,
    available: Condvar,
    /// High-water mark of queued task depth (diagnostics only).
    peak: AtomicU64,
}

impl DemandQueue {
    /// Publishes `tasks`, waking parked helpers; drops work past the cap.
    fn push(&self, tasks: Vec<DemandTask>) -> usize {
        if tasks.is_empty() {
            return 0;
        }
        let mut accepted = 0usize;
        {
            let mut state = recover(self.state.lock());
            if state.shutdown {
                return 0;
            }
            for task in tasks {
                if state.tasks.len() >= DEMAND_QUEUE_CAP {
                    break;
                }
                state.tasks.push_back(task);
                accepted += 1;
            }
            self.peak
                .fetch_max(state.tasks.len() as u64, Ordering::Relaxed);
        }
        if accepted > 0 {
            self.available.notify_all();
        }
        accepted
    }

    /// Pops the next task, parking until work arrives or the pool shuts down.
    ///
    /// Shutdown returns `None` immediately even while tasks remain queued:
    /// in a successful evaluation every published value has already been
    /// forced by the time the pool shuts down (fan-out is need-only), so
    /// leftover tasks are pure replays; in a failed evaluation they are
    /// demand the aborted evaluation no longer needs. Dropping them makes
    /// pool teardown prompt in both cases.
    fn pop_or_park(&self) -> Option<DemandTask> {
        let mut state = recover(self.state.lock());
        loop {
            if state.shutdown {
                return None;
            }
            if let Some(task) = state.tasks.pop_front() {
                return Some(task);
            }
            state = recover(self.available.wait(state));
        }
    }

    /// Marks the queue shut down and wakes every parked helper.
    fn shutdown(&self) {
        {
            let mut state = recover(self.state.lock());
            state.shutdown = true;
        }
        self.available.notify_all();
    }
}

/// Scheduler-observability counters (diagnostics only; never eval-visible).
#[derive(Debug, Default)]
pub(crate) struct DemandCounters {
    published: AtomicU64,
    dropped: AtomicU64,
    executed: AtomicU64,
    executed_values: AtomicU64,
    /// Wall nanoseconds helpers spent executing demand tasks (includes time
    /// blocked on contended thunk claims inside a task).
    task_nanos: AtomicU64,
    /// Wall nanoseconds helpers spent in their worker loops overall; the
    /// difference to `task_nanos` is time parked on an empty queue.
    loop_nanos: AtomicU64,
    /// Wall nanoseconds workers spent on slow-path forces that resolved
    /// without running the thunk body (claim waits and racy replays).
    /// Collected only under `AOS_NIX_EVAL_STATS=1` to keep the per-force
    /// timing tax off production runs.
    claim_wait_nanos: AtomicU64,
    /// Number of slow-path forces counted into `claim_wait_nanos`.
    claim_waits: AtomicU64,
}

/// Cross-worker shared state for one parallel evaluation.
#[derive(Debug)]
pub(crate) struct SharedEvalContext {
    /// Coalesced publication version across all shared logs.
    ///
    /// Bumped (release) after any log append so ingestion points can verify
    /// replica freshness with a single acquire load on the hot replay path;
    /// the per-log versions are only consulted once this differs from the
    /// worker's last-seen value.
    version: AtomicU64,
    pub(super) modules: SharedModuleRegistry,
    pub(super) symbols: SharedSymbolLog,
    pub(super) known_derivations: SharedKnownDerivationLog,
    pub(super) text_store: SharedTextStoreLog,
    /// The shared hidden-class shape log (L2-P4).
    ///
    /// `Some` when the main evaluator's shape table seeded an authoritative
    /// shared table at pool spawn; `None` disables shape projection on every
    /// worker for this evaluation (the pre-P4 parallel behavior).
    pub(super) shapes: Option<parallel_shape::SharedShapeLog>,
    /// The shared import-result log (L2-P4).
    pub(super) imports: parallel_import::SharedImportLog,
    /// The in-process shared content-memo tier (MEMO-1 L1).
    ///
    /// `Some` exactly when the L1 tier is active for this evaluation. This is
    /// the parallel substrate's first shared *writable* map: probes lock one
    /// shard, publication is first-write-wins, and payloads are
    /// self-contained plain data, so no cross-worker heap publication
    /// protocol is involved beyond the shard mutex itself.
    pub(super) memo: Option<Arc<super::memo::SharedMemoTable>>,
    queue: DemandQueue,
    counters: DemandCounters,
}

impl SharedEvalContext {
    /// Marks a completed publication into any shared log.
    pub(super) fn bump_version(&self) {
        self.version.fetch_add(1, Ordering::AcqRel);
    }

    /// Records one slow-path force that resolved without running the body.
    ///
    /// Fed by the parallel force choke point under `AOS_NIX_EVAL_STATS=1`;
    /// the accumulated wait time separates "helpers busy" from "helpers
    /// blocked on contended claims" in the drained-pool diagnostics.
    pub(super) fn record_claim_wait(&self, elapsed: std::time::Duration) {
        self.counters
            .claim_wait_nanos
            .fetch_add(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.counters.claim_waits.fetch_add(1, Ordering::Relaxed);
    }
}

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
        let root_ir = main.modules.first().map(|module| module.ir.clone())?;
        let arena = main.heap.shared_arena()?.clone();
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
            let Some(worker_id) =
                ParallelThunkWorkerId::new(ParallelThunkWorkerId::FIRST.get() + worker_index as u64)
            else {
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
                    walk.adopt_shared_heap_shard(arena, shard);
                    walk.set_parallel_force_registry(registry);
                    if let Some(realizer) = realizer {
                        walk.set_ifd_realizer(realizer);
                    }
                    // Replace the fresh local shape table with a replica of
                    // the shared log so record `Arc`s and dense ids are
                    // globally consistent; without a shared log, projection
                    // stays disabled on this worker.
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
        main.shared = Some(shared.clone());
        Some(Self { shared, handles })
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
        let claim_wait_nanos = self.shared.counters.claim_wait_nanos.load(Ordering::Relaxed);
        let claim_waits = self.shared.counters.claim_waits.load(Ordering::Relaxed);
        let queue_peak = self.shared.queue.peak.load(Ordering::Relaxed);
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
            "parallel demand pool drained"
        );
        if main.options.eval_stats_dump() {
            // Mirrors the `AOS_NIX_EVAL_STATS=1` JSON stats convention so
            // scheduler behavior is observable next to the eval work counters.
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
\"queue_peak\":{queue_peak}\
}}}}"
            );
        }
        if let Some(payload) = panic {
            std::panic::resume_unwind(payload);
        }
    }
}

impl TreeWalk {
    /// Refreshes this worker's prefix replicas from the shared logs.
    ///
    /// Called at every ingestion point where a foreign value can first become
    /// visible (parallel-cell replays and demand-task receipt), so all
    /// symbols, modules, known derivations, text-store entries, shape
    /// records, and finished imports reachable from foreign values are
    /// locally resolvable. Cheap when already current: one acquire load per
    /// log.
    pub(super) fn sync_shared_context(&mut self) {
        let Some(shared) = self.shared.clone() else {
            return;
        };
        let version = shared.version.load(Ordering::Acquire);
        if version == self.shared_version_seen {
            return;
        }
        shared.modules.sync_into(&mut self.modules);
        shared.symbols.sync_into(&mut self.symbols);
        shared
            .known_derivations
            .sync_into(&mut self.shared_known_derivations_cursor, &mut self.known_derivations);
        shared
            .text_store
            .sync_into(&mut self.shared_text_store_cursor, &mut self.text_store);
        self.sync_shared_shape_table(&shared);
        shared
            .imports
            .sync_into(&mut self.shared_import_log_cursor, &mut self.import_cache);
        // Store the pre-sync observation: appends racing the sync above are
        // picked up by the next ingestion point.
        self.shared_version_seen = version;
    }

    /// Interns an evaluation-time symbol through the shared log when present.
    ///
    /// This is the single choke point for evaluator symbol interning: under
    /// parallel mode a locally-unknown symbol is appended to the shared log
    /// first so its dense id is identical on every worker; already-known
    /// symbols resolve lock-free from the prefix replica.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`AstError`] if the symbol id space overflows.
    pub(super) fn intern_symbol_for_eval(&mut self, bytes: &[u8]) -> Result<Symbol, AstError> {
        if let Some(symbol) = self.symbols.lookup(bytes) {
            return Ok(symbol);
        }
        match self.shared.clone() {
            Some(shared) => {
                let symbol = shared.symbols.intern(&mut self.symbols, bytes);
                shared.bump_version();
                symbol
            }
            None => self.symbols.intern(bytes),
        }
    }

    /// Publishes a known derivation to the shared log under parallel mode.
    pub(super) fn publish_known_derivation(
        &self,
        path: &nix_compat::store_path::StorePath<String>,
        known: &KnownDerivation,
    ) {
        if let Some(shared) = self.shared.as_ref() {
            shared.known_derivations.publish(path, known);
            shared.bump_version();
        }
    }

    /// Publishes a text-store entry to the shared log under parallel mode.
    pub(super) fn publish_text_store_entry(&self, path: &[u8], entry: &TextStoreEntry) {
        if let Some(shared) = self.shared.as_ref() {
            shared.text_store.publish(path, entry);
            shared.bump_version();
        }
    }

    /// Publishes guaranteed-needed force work for idle helpers to steal.
    ///
    /// `values` are split into small batches; work past the queue cap is
    /// dropped (the publisher performs it serially anyway). No-op unless this
    /// evaluation runs a demand pool. Force batches below two values are
    /// skipped (one plain force cannot amortize queue overhead), but a single
    /// coercion value is still worth publishing: its executor unfolds list
    /// and dependency subtrees transitively.
    pub(super) fn publish_demand_values(&self, kind: DemandTaskKind, values: &[Value]) {
        let Some(shared) = self.shared.as_ref() else {
            return;
        };
        if values.is_empty() || (kind == DemandTaskKind::Force && values.len() < 2) {
            return;
        }
        let chunk_size = demand_task_chunk(kind);
        let mut tasks = Vec::with_capacity(values.len().div_ceil(chunk_size));
        for chunk in values.chunks(chunk_size) {
            tasks.push(DemandTask {
                kind,
                values: chunk.to_vec(),
            });
        }
        let published = tasks.len();
        let accepted = shared.queue.push(tasks);
        shared
            .counters
            .published
            .fetch_add(accepted as u64, Ordering::Relaxed);
        shared
            .counters
            .dropped
            .fetch_add((published - accepted) as u64, Ordering::Relaxed);
    }

    /// Publishes coercion fan-out for a list-valued derivation attribute.
    ///
    /// Only attributes whose serial handling string-coerces every list
    /// element are eligible: scalar-only special attributes (`name`,
    /// `builder`, `system`, hash declarations, and the boolean `__` toggles)
    /// never reach element coercion, so publishing them would be speculative
    /// work the serial evaluator is not committed to.
    pub(super) fn publish_derivation_list_fanout(&mut self, key: &[u8], value: Value) {
        if Self::derivation_scalar_only_attr(key) {
            return;
        }
        let Ok(list) = self.heap.get_list(value) else {
            return;
        };
        let elements: Vec<Value> = list
            .as_slice()
            .iter()
            .copied()
            .filter(|element| {
                matches!(
                    classify_whnf_tag_fast_path(*element),
                    WhnfTagFastPath::RequiresThunkProtocol(_)
                ) || matches!(element.tag(), ValueTag::Attrs | ValueTag::List)
            })
            .collect();
        self.publish_demand_values(DemandTaskKind::Coerce, &elements);
    }

    /// Executes one demand value with the semantics of its task kind.
    ///
    /// Mirrors exactly the demand the serial derivation coercion path
    /// produces: force; recurse into lists (publishing all but the first
    /// element for other helpers); force the `outPath` attribute of hookless
    /// attrsets.
    ///
    /// # Errors
    ///
    /// Propagates forcing errors. Errors raised inside shared thunk bodies
    /// are published through the claim protocol and replayed identically by
    /// every other worker that demands the same thunk; errors outside thunk
    /// bodies are simply abandoned here because the main worker
    /// deterministically re-derives them on its own pass.
    fn run_demand_value(
        &mut self,
        id: IrId,
        span: Span,
        kind: DemandTaskKind,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let value = self.force_value(id, span, value)?;
        if kind == DemandTaskKind::Force {
            return Ok(());
        }
        match value.tag() {
            ValueTag::List => {
                let elements: Vec<Value> = {
                    let list = self.heap.get_list(value).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                    list.as_slice().to_vec()
                };
                let keep = demand_task_chunk(DemandTaskKind::Coerce);
                if elements.len() > keep {
                    self.publish_demand_values(DemandTaskKind::Coerce, &elements[keep..]);
                }
                for element in elements.into_iter().take(keep) {
                    self.run_demand_value(id, span, DemandTaskKind::Coerce, element)?;
                }
            }
            ValueTag::Attrs => {
                // Serial string coercion prefers a `__toString` hook, and
                // only the hookless path forces `outPath` (see
                // `derivation_attrs_to_string_value` / `write_json_attrs`).
                // Applying the hook here would duplicate unmemoized lambda
                // work, so hooked attrsets are left to the serializer, and
                // `outPath` is forced only when serial provably forces it.
                if self
                    .attr_value_by_name(id, value, TO_STRING_ATTR, span)?
                    .is_none()
                    && let Some(out_path) =
                        self.attr_value_by_name(id, value, OUT_PATH_ATTR, span)?
                {
                    self.run_demand_value(id, span, DemandTaskKind::Coerce, out_path)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

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

    /// Publishes a module through the shared registry under parallel mode.
    ///
    /// Returns the freshly assigned global module id, or `None` when the
    /// module id space is exhausted.
    pub(super) fn publish_shared_module(&mut self, module: TreeWalkModule) -> Option<u32> {
        let shared = self.shared.clone()?;
        let raw = shared.modules.publish(&mut self.modules, module);
        shared.bump_version();
        raw
    }
}
