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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};

use crate::syntax::AstError;

use super::*;

mod pool;
mod shared_logs;

pub(crate) use pool::*;
pub(crate) use shared_logs::*;

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
/// Helper evaluation recurses as deeply as the main evaluator; segmented-stack
/// growth protects semantics while this roomy base avoids ordinary switches.
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

/// Shared store of speculatively parsed module IRs (RFC-0007 S2/S3, design B).
///
/// The pool-only speculation producer parses files reachable along static
/// path-literal edges into this map, keyed by [`ParseFileKey`] (realpath plus
/// content hash). A demanding worker consults it before parsing an import: a hit
/// skips parse/resolve/lower and adopts the stored IR through the usual remap.
///
/// Only *successful* parses are stored. Speculative parse failures are dropped —
/// never stored, never persisted — so the demand path stays the sole source of
/// import parse errors (the C-19 error-quarantine invariant, satisfied here by
/// never recording a failure). Content-hash keying makes a file edited between
/// speculation and demand a harmless miss.
#[derive(Debug, Default)]
pub(crate) struct SpeculativeParseStore {
    entries: Mutex<BTreeMap<ParseFileKey, Ir>>,
    /// Demand-side adoptions of a stored speculative parse (diagnostics only).
    hits: AtomicUsize,
}

impl SpeculativeParseStore {
    /// Records a successful speculative parse; first write wins.
    pub(super) fn insert(&self, key: ParseFileKey, ir: Ir) {
        recover(self.entries.lock()).entry(key).or_insert(ir);
    }

    /// Returns a clone of the speculative IR stored for `key`, counting a hit.
    pub(super) fn get(&self, key: &ParseFileKey) -> Option<Ir> {
        let ir = recover(self.entries.lock()).get(key).cloned();
        if ir.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        ir
    }

    /// Returns the number of stored speculative parses (diagnostics and tests).
    pub(super) fn len(&self) -> usize {
        recover(self.entries.lock()).len()
    }

    /// Returns the number of demand-side adoptions of a speculative parse.
    pub(super) fn hits(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

/// The shared work frontier of candidate files to speculatively parse.
///
/// Fed by evaluating threads — root/module static path-literal edges and, more
/// importantly on the AOS corpus, the `.nix` entries of every directory the eval
/// `readDir`s (the `readDir`-prefetch stage, RFC-0007 S6) — and drained by the
/// single speculation producer. Candidates are *raw, unresolved* paths; the
/// producer canonicalizes and filters them, keeping that filesystem work off the
/// evaluating threads. `close` wakes the parked producer at pool teardown.
#[derive(Debug, Default)]
pub(crate) struct SpeculationFrontier {
    queue: Mutex<VecDeque<PathBuf>>,
    available: Condvar,
    closed: AtomicBool,
}

impl SpeculationFrontier {
    /// Enqueues a raw candidate path and wakes the producer.
    pub(super) fn push(&self, candidate: PathBuf) {
        {
            let mut queue = recover(self.queue.lock());
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            queue.push_back(candidate);
        }
        self.available.notify_one();
    }

    /// Pops the next candidate, parking until one arrives or the frontier closes.
    pub(super) fn pop_or_park(&self) -> Option<PathBuf> {
        let mut queue = recover(self.queue.lock());
        loop {
            if let Some(candidate) = queue.pop_front() {
                return Some(candidate);
            }
            if self.closed.load(Ordering::Relaxed) {
                return None;
            }
            queue = recover(self.available.wait(queue));
        }
    }

    /// Marks the frontier closed and wakes the parked producer.
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.available.notify_all();
    }
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
    /// The shared store of speculatively parsed module IRs (RFC-0007 S2/S3).
    pub(super) speculation: SpeculativeParseStore,
    /// The shared candidate frontier the speculation producer drains, present
    /// only when `AOS_NIX_SPECULATE` enabled it (RFC-0007 S2/S6).
    pub(super) speculation_frontier: Option<SpeculationFrontier>,
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
        self.counters.claim_wait_nanos.fetch_add(
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.counters.claim_waits.fetch_add(1, Ordering::Relaxed);
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
        shared.known_derivations.sync_into(
            &mut self.shared_known_derivations_cursor,
            &mut self.known_derivations,
        );
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
        // Defensive single-entry filter (S7): a single-entry thunk carries no
        // parallel payload cell, so handing one to a helper would let two
        // workers run its body concurrently. The C-8 frame-local proof keeps
        // such thunks off every fan-out surface, but the publish boundary
        // re-checks rather than trusting the analysis.
        let values: Vec<Value> = values
            .iter()
            .copied()
            .filter(|value| !self.is_single_entry_thunk_value(*value))
            .collect();
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

    /// Returns whether `value` is a thunk using single-entry force storage.
    ///
    /// Unreadable heap handles answer `true` (filtered) so the publish path
    /// fails closed; the publisher performs the same work serially anyway.
    fn is_single_entry_thunk_value(&self, value: Value) -> bool {
        if value.tag() != ValueTag::Thunk {
            return false;
        }
        match self.heap.get_thunk(value) {
            Ok(thunk) => thunk.is_single_entry_force_storage(),
            Err(_) => true,
        }
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
        let Ok(list) = self.heap.get_list_view(value) else {
            return;
        };
        let elements: Vec<Value> = list
            .iter()
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
                    let list = self.heap.get_list_view(value).map_err(|source| {
                        TreeWalkError::new(TreeWalkErrorKind::Heap { id, source }, span)
                    })?;
                    list.iter().collect()
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
