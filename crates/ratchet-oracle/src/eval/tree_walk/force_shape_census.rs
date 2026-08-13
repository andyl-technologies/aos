//! Dynamic force-shape wall census (RFC-0007 JIT fuse-shapes, measurement-first).
//!
//! Answers the load-bearing question for the JIT fuse-shapes program: **what
//! fraction of the toplevel's evaluation wall is spent inside body shapes the
//! tier-2 compiler could take once the fuse-shapes grammar additions land?**
//!
//! The existing `aos_nix_tier1_gated_histogram` (see the JIT engine) is a
//! **static** census: it counts distinct *def-sites* the engine declined to
//! promote, at most once each, because a gated def-site is dropped from the
//! force hook after its first consulted force. It therefore reports shape
//! *variety*, not dynamic call frequency and not wall. It cannot rank shape
//! classes by the wall a compiler could remove.
//!
//! This probe closes that gap. It runs on **every** thunk force (not just the
//! first) from the tree walk's [`eval_thunk_body`](super::alloc_intern) seam,
//! classifies the forced body into a **shape class** matching the gated
//! histogram's taxonomy (`AttrSet`, `Select`, `Interp`, `BinOp:Update`,
//! `LocalVar`, `apply`, `PrimOp`, …), and attributes to that class:
//!
//! - the **dynamic force count** — how many times a body of this shape is
//!   forced (the population a compiler would cover); and
//! - the **allocation count** — how many thunks of this shape are allocated,
//!   including the subset allocated during order-sensitive binding assembly;
//!   and
//! - the **exclusive self-nanos** — wall spent inside the body's own
//!   interpretation, with nested child forces subtracted out.
//!
//! Exclusive self-time is the metric that matters: compiling a body removes its
//! *own* interpreter dispatch and setup overhead, not the wall of the child
//! thunks it forces (those are separately-forced, separately-compilable bodies).
//! Attributing inclusive time would over-count the outer shapes (`Let`, `Apply`,
//! `AttrSet`) that merely drive child forces. The sum of all classes' self-time
//! is therefore the total top-level inclusive wall, partitioned without
//! double-counting.
//!
//! ## Reading the numbers
//!
//! Self-time is the *addressable ceiling* for a shape only to the extent the
//! shape's self-work is interpreter overhead. `PrimOp` self-time is mostly
//! **genuine native work** (string ops, `derivationStrict`, I/O) that a compiled
//! caller still pays via an FFI out-call, so it is largely non-addressable.
//! `AttrSet`/`Select`/`Interp`/`BinOp`/`LocalVar`/`apply` self-time is
//! interpreter dispatch, env setup, and allocation — the part a fused compiled
//! body reduces (an allocation FFI out-call remains, hence the measured
//! compute-shape 20x does not apply; expect 2-5x per covered call).
//!
//! ## Scope
//!
//! Nesting bookkeeping (the child-nanos accumulator) is **per worker thread**;
//! the aggregate map is process-wide. On the toplevel serial/JIT census legs the
//! main spine does the forcing and emits the report, matching the
//! main-worker-only convention of the env apply-count histogram. Parallel helper
//! forces fold their self-time into the shared map but their nesting is tracked
//! against their own thread-local accumulator, so per-thread self-time stays
//! correct.
//!
//! Collection is opt-in: the evaluator only calls in when `AOS_NIX_EVAL_STATS`
//! is enabled, so a normal or production evaluation pays nothing. The report is
//! one greppable JSON line on the `AOS_NIX_EVAL_STATS` stderr dump path (not the
//! tracing target), because a benchmark run captures this evaluator's stderr:
//!
//! ```text
//! aos_nix_force_shape_census {"total_allocations":3500000,"total_forces":3210000,
//!   "unpublished_work_upper_bound":290000,
//!   "peak_unpublished_work_upper_bound":310000,"work_releases":3210000,
//!   "shapes":{"AttrSet":{"allocations":560000,"order_sensitive_allocations":120000,
//!                       "forces":540000,"self_ns":410000000,"incl_ns":900000000}},
//!   "synthetic_apply_origins":{"genList":1130000,"map":210000},
//!   "env_storage":{"Chain":520000,"ChainFlat":640000,"Empty":700000,"Flat":40000}}
//! ```
//!
//! Totals are process-wide and cumulative across every evaluation in the
//! process; the last line a run prints holds the full picture.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide census state, `None` until the first force records.
static CENSUS: Mutex<Option<Census>> = Mutex::new(None);

/// Process-wide directly selected child shapes from the exact `genList` path.
///
/// Separate from [`CENSUS`] so the opt-in child classifier does not lengthen
/// the ordinary per-force census critical section.
static GENLIST_SELECTED_CHILD_CENSUS: Mutex<Option<HashMap<SelectedChildDescriptor, u64>>> =
    Mutex::new(None);
#[cfg(test)]
static GENLIST_SUSPENDED_CHILD_SAMPLES: AtomicU64 = AtomicU64::new(0);

/// Total forces recorded across all shape classes and threads.
static TOTAL_FORCES: AtomicU64 = AtomicU64::new(0);

/// Total allocations recorded across all shape classes and threads.
static TOTAL_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

/// Allocated work not yet released by successful publication.
///
/// This is an upper bound on live pooled work because identity destruction and
/// region retirement are not yet observed by this census.
static UNPUBLISHED_WORK_UPPER_BOUND: AtomicU64 = AtomicU64::new(0);

/// Maximum observed value of [`UNPUBLISHED_WORK_UPPER_BOUND`].
static PEAK_UNPUBLISHED_WORK_UPPER_BOUND: AtomicU64 = AtomicU64::new(0);

/// Suspended-work records hypothetically released after successful publication.
static WORK_RELEASES: AtomicU64 = AtomicU64::new(0);

/// Number of exclusive-self-time break-even buckets.
///
/// Bucket `b` (for `b < 63`) holds forces whose exclusive self-time is in
/// `[2^b, 2^(b+1))` nanoseconds; bucket 0 also holds zero-nanos forces. The
/// break-even decision for per-force JIT dispatch is a self-time threshold (a
/// compiled body must save more than the per-dispatch tax), so this power-of-two
/// partition of self-time answers directly: *what fraction of total self-time
/// lives in forces above the tax?*
const SELF_NS_BUCKETS: usize = 40;

thread_local! {
    /// Sum of the inclusive nanos of the direct child forces of the force
    /// currently open on this thread.
    ///
    /// [`open_force`] saves and zeroes it on entry; [`close_force`] reads it to
    /// derive the closing force's exclusive self-time, then restores the parent's
    /// running sum plus this force's own inclusive nanos. Per-thread so nested
    /// forces on different worker threads never cross-contaminate.
    static CHILDREN_NANOS: Cell<u64> = const { Cell::new(0) };

    /// Stats-only dynamic force nesting used to identify modal apply spines.
    static FORCE_NESTING: RefCell<Vec<OpenForceFrame>> = const { RefCell::new(Vec::new()) };
}

/// Structural classification of one forced synthetic application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ApplySpineDescriptor {
    /// Synthetic producer, or `other`/`ambiguous` when no unique site matches.
    pub(super) origin: &'static str,
    /// Runtime callee carrier class.
    pub(super) callee: &'static str,
    /// Lambda pattern class, or `not-lambda`.
    pub(super) pattern: &'static str,
    /// Lambda body class, or `not-lambda`.
    pub(super) body: &'static str,
    /// Lazy argument work class.
    pub(super) argument: &'static str,
}

/// Structural classification of a child selected by the exact `genList` path.
///
/// `runtime_kind` reports the direct [`Value`](crate::value::Value) tag before
/// forcing. Thunks additionally carry their suspended-work kind. Node thunks
/// use `body` for the lowered body shape; Apply-shaped thunks carry the same
/// callee/body/argument descriptor as the dynamic Apply-spine census.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct SelectedChildDescriptor {
    /// Direct runtime value tag (`int`, `list`, `thunk`, and so on).
    pub(super) runtime_kind: &'static str,
    /// Suspended-work kind, or `not-thunk`.
    pub(super) thunk_kind: &'static str,
    /// Thunk cell state at selection, or `not-thunk`.
    pub(super) thunk_state: &'static str,
    /// Lowered Node body shape, or `not-node`.
    pub(super) body: &'static str,
    /// Apply signature for Apply-shaped work.
    pub(super) apply: Option<ApplySpineDescriptor>,
    /// Reducer-oriented detail for an Apply-shaped selected child.
    pub(super) selected_apply: Option<SelectedApplyDescriptor>,
}

/// Runtime closure and static-code classification of a selected Apply thunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct SelectedApplyDescriptor {
    /// Direct runtime tag of the function carried by the Apply thunk.
    pub(super) callee_kind: &'static str,
    /// Whether a lambda belongs to the root or an imported module.
    pub(super) lambda_module: &'static str,
    /// Number of captured lexical frames, saturated to `u32::MAX`.
    pub(super) lexical_frames: u32,
    /// Number of captured `with` scopes, saturated to `u32::MAX`.
    pub(super) with_scopes: u32,
    /// Number of captured scoped-import globals, saturated to `u32::MAX`.
    pub(super) scoped_globals: u32,
    /// Static classification of the lambda body.
    pub(super) body: SelectedApplyBodyDescriptor,
}

/// Bounded static grammar summary for one selected Apply lambda body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct SelectedApplyBodyDescriptor {
    /// Body root kind after stripping one lazy-position wrapper.
    pub(super) root_kind: &'static str,
    /// Whether the bounded walk accepted the packed-reducer grammar.
    pub(super) grammar: &'static str,
    /// Bit set of reducer-relevant node families encountered by the walk.
    pub(super) features: u16,
    /// Distinct `(node, depth)` visits, saturated at the walk bound.
    pub(super) nodes: u16,
    /// Maximum static nesting depth, saturated at the walk bound.
    pub(super) depth: u8,
}

/// Result class of one forced body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum ForceOutcomeClass {
    /// The body completed with weak-head-normal-form data.
    Whnf,
    /// The body completed with a still-lazy thunk.
    Thunk,
    /// The body returned an evaluation error.
    Error,
}

impl ForceOutcomeClass {
    /// Returns the stable report spelling.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Whnf => "whnf",
            Self::Thunk => "thunk",
            Self::Error => "error",
        }
    }
}

/// Token pairing one force close with its open accounting frame.
pub(super) struct ForceCensusToken {
    /// Parent frame's accumulated child time.
    saved_children: u64,
}

/// Dynamic child topology accumulated while a force is open.
#[derive(Clone, Copy, Debug, Default)]
struct OpenForceFrame {
    /// Structural apply descriptor when this is an Apply force.
    descriptor: Option<ApplySpineDescriptor>,
    /// Number of direct child forces.
    direct_children: u32,
    /// Number of direct child forces whose work kind is Apply.
    direct_apply_children: u32,
}

/// Collision-audited synthetic Apply allocation-site identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ApplySiteKey {
    function_module: u32,
    function_id: u32,
    argument_module: u32,
    argument_id: u32,
}

/// Fully classified dynamic Apply force.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ApplySpineKey {
    descriptor: ApplySpineDescriptor,
    children: &'static str,
    outcome: ForceOutcomeClass,
}

/// Dynamic force and wall totals for an Apply-spine class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SpineAgg {
    forces: u64,
    self_nanos: u64,
    inclusive_nanos: u64,
    errors: u64,
}

/// Per-shape-class running totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ShapeAgg {
    /// Dynamic count of allocated thunks in this shape class.
    allocations: u64,
    /// Allocations made while order-sensitive bindings are being assembled.
    order_sensitive_allocations: u64,
    /// Successfully published thunks whose suspended work could be released.
    work_releases: u64,
    /// Allocated work in this class not yet successfully published.
    live_work: u64,
    /// Maximum observed [`Self::live_work`] for this class.
    peak_live_work: u64,
    /// Live work in this class when the process-wide live-work peak occurred.
    live_work_at_global_peak: u64,
    /// Dynamic count of forces of a body in this shape class.
    forces: u64,
    /// Exclusive nanos (nested child forces subtracted) spent in this class.
    self_nanos: u64,
    /// Inclusive nanos (child forces included) spent in this class.
    inclusive_nanos: u64,
}

/// Records one allocated thunk in `shape`.
///
/// `order_sensitive` identifies allocations made while source-ordered,
/// potentially recursive bindings are still being assembled. Those allocations
/// cannot be assumed safe for eager alias collapse merely because their body is
/// a local or upvalue reference.
///
/// A poisoned probe lock is treated as a lost sample and silently skipped:
/// this diagnostic must never perturb evaluation.
pub(super) fn record_allocation(
    shape: &'static str,
    order_sensitive: bool,
    env_storage: Option<&'static str>,
) {
    TOTAL_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    let live = UNPUBLISHED_WORK_UPPER_BOUND
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    let _ = PEAK_UNPUBLISHED_WORK_UPPER_BOUND.fetch_max(live, Ordering::Relaxed);
    if let Ok(mut guard) = CENSUS.lock() {
        let census = guard.get_or_insert_with(Census::new);
        let agg = census.shapes.entry(shape).or_default();
        agg.allocations = agg.allocations.saturating_add(1);
        agg.live_work = agg.live_work.saturating_add(1);
        agg.peak_live_work = agg.peak_live_work.max(agg.live_work);
        if order_sensitive {
            agg.order_sensitive_allocations = agg.order_sensitive_allocations.saturating_add(1);
        }
        census.live_work = census.live_work.saturating_add(1);
        if census.live_work > census.peak_live_work {
            census.peak_live_work = census.live_work;
            for aggregate in census.shapes.values_mut() {
                aggregate.live_work_at_global_peak = aggregate.live_work;
            }
        }
        if let Some(storage) = env_storage {
            let count = census.env_storage.entry(storage).or_default();
            *count = count.saturating_add(1);
        }
    }
}

/// Records one lambda's captured-environment storage representation.
pub(super) fn record_lambda_env_storage(storage: &'static str) {
    if let Ok(mut guard) = CENSUS.lock() {
        let census = guard.get_or_insert_with(Census::new);
        let count = census.env_storage.entry(storage).or_default();
        *count = count.saturating_add(1);
    }
}

/// Records the point where a successfully forced thunk in `shape` can release
/// its suspended work.
pub(super) fn record_work_release(shape: &'static str) {
    WORK_RELEASES.fetch_add(1, Ordering::Relaxed);
    let _ =
        UNPUBLISHED_WORK_UPPER_BOUND.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
            Some(live.saturating_sub(1))
        });
    if let Ok(mut guard) = CENSUS.lock() {
        let census = guard.get_or_insert_with(Census::new);
        let aggregate = census.shapes.entry(shape).or_default();
        aggregate.work_releases = aggregate.work_releases.saturating_add(1);
        aggregate.live_work = aggregate.live_work.saturating_sub(1);
        census.live_work = census.live_work.saturating_sub(1);
    }
}

/// A single exclusive-self-time break-even bucket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BucketAgg {
    /// Forces whose exclusive self-time fell in this bucket's nanos range.
    forces: u64,
    /// Summed exclusive self-nanos of those forces.
    self_nanos: u64,
}

/// Process-wide census aggregation: per-shape totals and the self-time
/// break-even bucket histogram, updated together under one lock per force.
struct Census {
    /// Exclusive self-time and force counts keyed by shape class.
    shapes: HashMap<&'static str, ShapeAgg>,
    /// Suspended work currently live across all shape classes.
    live_work: u64,
    /// Maximum observed [`Self::live_work`].
    peak_live_work: u64,
    /// Synthetic lazy-application allocations keyed by their builtin producer.
    synthetic_apply_origins: HashMap<&'static str, u64>,
    /// Node-thunk and lambda captures keyed by environment representation.
    env_storage: HashMap<&'static str, u64>,
    /// Unique producer origin by compact Apply def-site.
    apply_sites: HashMap<ApplySiteKey, &'static str>,
    /// Sites observed under more than one producer origin.
    ambiguous_apply_sites: u64,
    /// Fully classified dynamic Apply force spines.
    apply_spines: HashMap<ApplySpineKey, SpineAgg>,
    /// Cumulative modal-spine stage totals.
    apply_spine_stages: HashMap<&'static str, SpineAgg>,
    /// Forces and self-nanos partitioned by self-time power-of-two bucket.
    self_ns_buckets: [BucketAgg; SELF_NS_BUCKETS],
}

impl Census {
    /// Creates an empty census.
    fn new() -> Self {
        Self {
            shapes: HashMap::new(),
            live_work: 0,
            peak_live_work: 0,
            synthetic_apply_origins: HashMap::new(),
            env_storage: HashMap::new(),
            apply_sites: HashMap::new(),
            ambiguous_apply_sites: 0,
            apply_spines: HashMap::new(),
            apply_spine_stages: HashMap::new(),
            self_ns_buckets: [BucketAgg::default(); SELF_NS_BUCKETS],
        }
    }
}

/// Records a batch of synthetic lazy-application thunks from one producer.
///
/// Callers invoke this only on the stats-enabled path and batch whole result
/// collections, avoiding one probe lock per mapped element.
pub(super) fn record_synthetic_apply_origin(origin: &'static str, allocations: usize) {
    if allocations == 0 {
        return;
    }
    if let Ok(mut guard) = CENSUS.lock() {
        let census = guard.get_or_insert_with(Census::new);
        let count = census.synthetic_apply_origins.entry(origin).or_default();
        *count = count.saturating_add(allocations as u64);
    }
}

/// Records one batch-producing Apply def-site and its synthetic origin.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_synthetic_apply_site(
    origin: &'static str,
    function_module: u32,
    function_id: u32,
    argument_module: u32,
    argument_id: u32,
    allocations: usize,
) {
    if allocations == 0 {
        return;
    }
    if let Ok(mut guard) = CENSUS.lock() {
        let census = guard.get_or_insert_with(Census::new);
        let count = census.synthetic_apply_origins.entry(origin).or_default();
        *count = count.saturating_add(allocations as u64);
        let key = ApplySiteKey {
            function_module,
            function_id,
            argument_module,
            argument_id,
        };
        match census.apply_sites.get_mut(&key) {
            None => {
                census.apply_sites.insert(key, origin);
            }
            Some(recorded) if *recorded == origin || *recorded == "ambiguous" => {}
            Some(recorded) => {
                *recorded = "ambiguous";
                census.ambiguous_apply_sites = census.ambiguous_apply_sites.saturating_add(1);
            }
        }
    }
}

/// Returns the unique synthetic origin registered for an Apply def-site.
pub(super) fn synthetic_apply_origin(
    function_module: u32,
    function_id: u32,
    argument_module: u32,
    argument_id: u32,
) -> &'static str {
    let key = ApplySiteKey {
        function_module,
        function_id,
        argument_module,
        argument_id,
    };
    match CENSUS.lock() {
        Ok(guard) => guard
            .as_ref()
            .and_then(|census| census.apply_sites.get(&key))
            .copied()
            .unwrap_or("other"),
        Err(_) => "other",
    }
}

/// Records one directly selected child before the exact `genList` path forces it.
///
/// Callers invoke this only under the explicit stats-only child-census option.
/// A poisoned probe lock loses the sample rather than perturbing evaluation.
pub(super) fn record_genlist_selected_child(descriptor: SelectedChildDescriptor) {
    #[cfg(test)]
    if descriptor.runtime_kind == "thunk" && descriptor.thunk_state == "suspended" {
        GENLIST_SUSPENDED_CHILD_SAMPLES.fetch_add(1, Ordering::Relaxed);
    }
    if let Ok(mut guard) = GENLIST_SELECTED_CHILD_CENSUS.lock() {
        let census = guard.get_or_insert_with(HashMap::new);
        let count = census.entry(descriptor).or_default();
        *count = count.saturating_add(1);
    }
}

/// Returns the count recorded for one selected-child descriptor.
#[cfg(test)]
pub(super) fn recorded_genlist_selected_children(descriptor: SelectedChildDescriptor) -> u64 {
    match GENLIST_SELECTED_CHILD_CENSUS.lock() {
        Ok(guard) => guard
            .as_ref()
            .and_then(|census| census.get(&descriptor))
            .copied()
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Returns selected-child samples observed while the thunk was suspended.
#[cfg(test)]
pub(super) fn recorded_genlist_suspended_child_samples() -> u64 {
    GENLIST_SUSPENDED_CHILD_SAMPLES.load(Ordering::Relaxed)
}

/// Returns the break-even bucket index for an exclusive self-time in nanos.
///
/// Bucket `b` covers `[2^b, 2^(b+1))` ns; zero maps to bucket 0. Saturates at
/// the last bucket so a pathological outlier never indexes out of range.
const fn self_ns_bucket(self_nanos: u64) -> usize {
    if self_nanos == 0 {
        return 0;
    }
    let bucket = (63 - self_nanos.leading_zeros()) as usize;
    if bucket >= SELF_NS_BUCKETS {
        SELF_NS_BUCKETS - 1
    } else {
        bucket
    }
}

/// Opens a force's self-time accounting frame on the current thread.
///
/// Returns the parent frame's accumulated child-nanos, which the caller must
/// hand back to [`close_force`] unchanged. Resets the thread-local child
/// accumulator to zero so the opening force sees only its own direct children.
pub(super) fn open_force(descriptor: Option<ApplySpineDescriptor>) -> ForceCensusToken {
    FORCE_NESTING.with(|nesting| {
        nesting.borrow_mut().push(OpenForceFrame {
            descriptor,
            ..OpenForceFrame::default()
        });
    });
    ForceCensusToken {
        saved_children: CHILDREN_NANOS.with(|c| c.replace(0)),
    }
}

/// Closes the force opened by [`open_force`], attributing its exclusive
/// self-time to `shape`.
///
/// `elapsed_nanos` is the force's inclusive wall; `saved_children` is the value
/// [`open_force`] returned. The force's own children summed into the
/// thread-local accumulator while it ran; self-time is `elapsed - children`.
/// After recording, the parent's accumulator is restored and credited with this
/// force's full inclusive nanos so the parent's self-time excludes it in turn.
///
/// A poisoned probe lock is treated as a lost sample and silently skipped: this
/// is diagnostic instrumentation and must never perturb evaluation.
pub(super) fn close_force(
    shape: &'static str,
    elapsed_nanos: u64,
    token: ForceCensusToken,
    outcome: ForceOutcomeClass,
) {
    let my_children = CHILDREN_NANOS.with(|c| {
        let mine = c.get();
        c.set(token.saved_children.saturating_add(elapsed_nanos));
        mine
    });
    let self_nanos = elapsed_nanos.saturating_sub(my_children);
    let frame = FORCE_NESTING.with(|nesting| {
        let mut nesting = nesting.borrow_mut();
        let frame = nesting.pop().unwrap_or_default();
        if let Some(parent) = nesting.last_mut() {
            parent.direct_children = parent.direct_children.saturating_add(1);
            if frame.descriptor.is_some() {
                parent.direct_apply_children = parent.direct_apply_children.saturating_add(1);
            }
        }
        frame
    });
    TOTAL_FORCES.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut guard) = CENSUS.lock() {
        let census = guard.get_or_insert_with(Census::new);
        let agg = census.shapes.entry(shape).or_default();
        agg.forces = agg.forces.saturating_add(1);
        agg.self_nanos = agg.self_nanos.saturating_add(self_nanos);
        agg.inclusive_nanos = agg.inclusive_nanos.saturating_add(elapsed_nanos);
        let bucket = &mut census.self_ns_buckets[self_ns_bucket(self_nanos)];
        bucket.forces = bucket.forces.saturating_add(1);
        bucket.self_nanos = bucket.self_nanos.saturating_add(self_nanos);
        if let Some(descriptor) = frame.descriptor {
            let children = child_topology(&frame);
            let key = ApplySpineKey {
                descriptor,
                children,
                outcome,
            };
            add_spine_sample(
                census.apply_spines.entry(key).or_default(),
                self_nanos,
                elapsed_nanos,
                outcome,
            );
            record_spine_stages(census, key, self_nanos, elapsed_nanos);
        }
    }
}

/// Returns the stable direct-child topology class for one closed force.
const fn child_topology(frame: &OpenForceFrame) -> &'static str {
    match (frame.direct_children, frame.direct_apply_children) {
        (0, _) => "none",
        (1, 1) => "one-apply",
        (1, 0) => "one-other",
        _ => "many-or-mixed",
    }
}

/// Adds one force sample to an Apply-spine aggregate.
fn add_spine_sample(
    aggregate: &mut SpineAgg,
    self_nanos: u64,
    inclusive_nanos: u64,
    outcome: ForceOutcomeClass,
) {
    aggregate.forces = aggregate.forces.saturating_add(1);
    aggregate.self_nanos = aggregate.self_nanos.saturating_add(self_nanos);
    aggregate.inclusive_nanos = aggregate.inclusive_nanos.saturating_add(inclusive_nanos);
    if outcome == ForceOutcomeClass::Error {
        aggregate.errors = aggregate.errors.saturating_add(1);
    }
}

/// Records cumulative prefixes of the modal simple-lambda Apply spine.
fn record_spine_stages(
    census: &mut Census,
    key: ApplySpineKey,
    self_nanos: u64,
    inclusive_nanos: u64,
) {
    let descriptor = key.descriptor;
    let stages = [
        ("apply", true),
        ("lambda", descriptor.callee == "lambda"),
        ("simple_formal", descriptor.pattern == "simple-formal"),
        ("local_argument", descriptor.body == "local-argument"),
        ("argument_apply", descriptor.argument == "apply-thunk"),
        ("one_apply_child", key.children == "one-apply"),
        ("modal_complete", key.outcome == ForceOutcomeClass::Whnf),
    ];
    for (stage, matched) in stages {
        if !matched {
            break;
        }
        add_spine_sample(
            census.apply_spine_stages.entry(stage).or_default(),
            self_nanos,
            inclusive_nanos,
            key.outcome,
        );
    }
}

/// Returns the recorded force count for a shape class, or `0` when the census
/// holds no data for it.
///
/// A poisoned probe lock reads as `0`: this is diagnostic-only state. Intended
/// for tests asserting a given force shape was classified under a stats-dump
/// evaluation; production reporting goes through
/// [`emit_force_shape_census_report`].
#[cfg(test)]
pub(super) fn recorded_forces(shape: &'static str) -> u64 {
    match CENSUS.lock() {
        Ok(guard) => guard
            .as_ref()
            .and_then(|census| census.shapes.get(shape))
            .map_or(0, |agg| agg.forces),
        Err(_) => 0,
    }
}

/// Returns the recorded allocation count for a shape class.
#[cfg(test)]
pub(super) fn recorded_allocations(shape: &'static str) -> u64 {
    match CENSUS.lock() {
        Ok(guard) => guard
            .as_ref()
            .and_then(|census| census.shapes.get(shape))
            .map_or(0, |agg| agg.allocations),
        Err(_) => 0,
    }
}

/// Returns the number of suspended-work releases recorded by the census.
#[cfg(test)]
pub(super) fn recorded_work_releases() -> u64 {
    WORK_RELEASES.load(Ordering::Relaxed)
}

/// Prints the force-shape census as one JSON line to stderr, or does nothing
/// when the probe holds no data.
///
/// Shapes are ordered by exclusive self-nanos, most first, so the wall-dominant
/// classes lead. The `self_ns_buckets` object maps a power-of-two nanos lower
/// bound (`"128"` = `[128, 256)` ns of exclusive self-time) to that bucket's
/// `{forces, self_ns}`, so a reader can sum the self-nanos above any JIT
/// per-dispatch break-even threshold and read the addressable-if-fused fraction
/// directly. Emitted on the `AOS_NIX_EVAL_STATS` diagnostic dump path so it
/// lands on the same stderr stream a benchmark run already captures. The line is
/// prefixed with `aos_nix_force_shape_census` for grepping.
pub(super) fn emit_force_shape_census_report() {
    let total_forces = TOTAL_FORCES.load(Ordering::Relaxed);
    let total_allocations = TOTAL_ALLOCATIONS.load(Ordering::Relaxed);
    let unpublished_work_upper_bound = UNPUBLISHED_WORK_UPPER_BOUND.load(Ordering::Relaxed);
    let peak_unpublished_work_upper_bound =
        PEAK_UNPUBLISHED_WORK_UPPER_BOUND.load(Ordering::Relaxed);
    let work_releases = WORK_RELEASES.load(Ordering::Relaxed);
    if total_forces == 0 && total_allocations == 0 {
        return;
    }
    let (
        mut entries,
        buckets,
        mut apply_origins,
        mut env_storage,
        mut apply_spines,
        mut apply_stages,
        apply_sites,
        ambiguous_apply_sites,
    ): (
        Vec<(&'static str, ShapeAgg)>,
        [BucketAgg; SELF_NS_BUCKETS],
        Vec<(&'static str, u64)>,
        Vec<(&'static str, u64)>,
        Vec<(ApplySpineKey, SpineAgg)>,
        Vec<(&'static str, SpineAgg)>,
        usize,
        u64,
    ) = match CENSUS.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(census) => (
                census
                    .shapes
                    .iter()
                    .map(|(shape, agg)| (*shape, *agg))
                    .collect(),
                census.self_ns_buckets,
                census
                    .synthetic_apply_origins
                    .iter()
                    .map(|(origin, count)| (*origin, *count))
                    .collect(),
                census
                    .env_storage
                    .iter()
                    .map(|(storage, count)| (*storage, *count))
                    .collect(),
                census
                    .apply_spines
                    .iter()
                    .map(|(key, aggregate)| (*key, *aggregate))
                    .collect(),
                census
                    .apply_spine_stages
                    .iter()
                    .map(|(stage, aggregate)| (*stage, *aggregate))
                    .collect(),
                census.apply_sites.len(),
                census.ambiguous_apply_sites,
            ),
            None => return,
        },
        Err(_) => return,
    };
    entries.sort_by(|a, b| {
        b.1.self_nanos
            .cmp(&a.1.self_nanos)
            .then_with(|| a.0.cmp(b.0))
    });
    let total_self_ns: u64 = entries
        .iter()
        .fold(0u64, |acc, (_, agg)| acc.saturating_add(agg.self_nanos));
    let shapes = entries
        .iter()
        .map(|(shape, agg)| {
            format!(
                "\"{shape}\":{{\"allocations\":{},\"order_sensitive_allocations\":{},\
                 \"work_releases\":{},\"live_work\":{},\"peak_live_work\":{},\
                 \"live_work_at_global_peak\":{},\"forces\":{},\"self_ns\":{},\"incl_ns\":{}}}",
                agg.allocations,
                agg.order_sensitive_allocations,
                agg.work_releases,
                agg.live_work,
                agg.peak_live_work,
                agg.live_work_at_global_peak,
                agg.forces,
                agg.self_nanos,
                agg.inclusive_nanos,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let bucket_json = buckets
        .iter()
        .enumerate()
        .filter(|(_, agg)| agg.forces > 0)
        .map(|(index, agg)| {
            format!(
                "\"{}\":{{\"forces\":{},\"self_ns\":{}}}",
                1u64 << index,
                agg.forces,
                agg.self_nanos,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    apply_origins.sort_unstable_by_key(|(origin, _)| *origin);
    let apply_origin_json = apply_origins
        .iter()
        .map(|(origin, count)| format!("\"{origin}\":{count}"))
        .collect::<Vec<_>>()
        .join(",");
    env_storage.sort_unstable_by_key(|(storage, _)| *storage);
    let env_storage_json = env_storage
        .iter()
        .map(|(storage, count)| format!("\"{storage}\":{count}"))
        .collect::<Vec<_>>()
        .join(",");
    apply_spines.sort_unstable_by_key(|(key, _)| apply_spine_signature(*key));
    let apply_spine_json = apply_spines
        .iter()
        .map(|(key, aggregate)| {
            format!(
                "\"{}\":{{\"forces\":{},\"self_ns\":{},\"incl_ns\":{},\"errors\":{}}}",
                apply_spine_signature(*key),
                aggregate.forces,
                aggregate.self_nanos,
                aggregate.inclusive_nanos,
                aggregate.errors,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    apply_stages.sort_unstable_by_key(|(stage, _)| *stage);
    let apply_stage_json = apply_stages
        .iter()
        .map(|(stage, aggregate)| {
            format!(
                "\"{stage}\":{{\"forces\":{},\"self_ns\":{}}}",
                aggregate.forces, aggregate.self_nanos,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    eprintln!(
        "aos_nix_force_shape_census {{\"total_allocations\":{total_allocations},\
         \"total_forces\":{total_forces},\"total_self_ns\":{total_self_ns},\
         \"unpublished_work_upper_bound\":{unpublished_work_upper_bound},\
         \"peak_unpublished_work_upper_bound\":{peak_unpublished_work_upper_bound},\
         \"work_releases\":{work_releases},\
         \"shapes\":{{{shapes}}},\
         \"synthetic_apply_origins\":{{{apply_origin_json}}},\
         \"apply_origin_sites\":{{\"registered\":{apply_sites},\
         \"ambiguous\":{ambiguous_apply_sites}}},\
         \"apply_spine_stages\":{{{apply_stage_json}}},\
         \"apply_spines\":{{{apply_spine_json}}},\
         \"env_storage\":{{{env_storage_json}}},\
         \"self_ns_buckets\":{{{bucket_json}}}}}"
    );
}

/// Prints the exact `genList` selected-child census as deterministic JSON.
///
/// The line is absent when the explicit census recorded no selected children.
/// Classes are ordered by their complete structural signature, making output
/// stable across hash-map iteration orders and suitable for primary-run diffs.
pub(super) fn emit_genlist_selected_child_census_report() {
    let Some(json) = genlist_selected_child_census_json() else {
        return;
    };
    eprintln!("aos_nix_genlist_selected_child_census {json}");
}

/// Builds the selected-child census JSON in deterministic class order.
fn genlist_selected_child_census_json() -> Option<String> {
    let mut entries: Vec<(SelectedChildDescriptor, u64)> =
        match GENLIST_SELECTED_CHILD_CENSUS.lock() {
            Ok(mut guard) => guard.take()?.into_iter().collect(),
            Err(_) => return None,
        };
    entries.sort_unstable_by_key(|(descriptor, _)| selected_child_signature(*descriptor));
    let total = entries
        .iter()
        .fold(0u64, |sum, (_, count)| sum.saturating_add(*count));
    let classes = entries
        .iter()
        .map(|(descriptor, count)| {
            let apply = descriptor.apply.unwrap_or(ApplySpineDescriptor {
                origin: "not-apply",
                callee: "not-apply",
                pattern: "not-apply",
                body: "not-apply",
                argument: "not-apply",
            });
            let selected_apply = descriptor
                .selected_apply
                .unwrap_or(SelectedApplyDescriptor {
                    callee_kind: "not-apply",
                    lambda_module: "not-lambda",
                    lexical_frames: 0,
                    with_scopes: 0,
                    scoped_globals: 0,
                    body: SelectedApplyBodyDescriptor {
                        root_kind: "not-lambda",
                        grammar: "not-lambda",
                        features: 0,
                        nodes: 0,
                        depth: 0,
                    },
                });
            let grammar_features = selected_apply_body_features(selected_apply.body.features);
            format!(
                "{{\"runtime_kind\":\"{}\",\"thunk_kind\":\"{}\",\"body\":\"{}\",\
                 \"thunk_state\":\"{}\",\
                 \"apply_origin\":\"{}\",\"apply_callee\":\"{}\",\
                 \"apply_pattern\":\"{}\",\"apply_body\":\"{}\",\
                 \"apply_argument\":\"{}\",\
                 \"selected_callee_kind\":\"{}\",\"lambda_module\":\"{}\",\
                 \"lexical_frames\":{},\"with_scopes\":{},\"scoped_globals\":{},\
                 \"lambda_body_root\":\"{}\",\"body_grammar\":\"{}\",\
                 \"body_grammar_features\":[{}],\"body_grammar_nodes\":{},\
                 \"body_grammar_depth\":{},\"count\":{count}}}",
                descriptor.runtime_kind,
                descriptor.thunk_kind,
                descriptor.body,
                descriptor.thunk_state,
                apply.origin,
                apply.callee,
                apply.pattern,
                apply.body,
                apply.argument,
                selected_apply.callee_kind,
                selected_apply.lambda_module,
                selected_apply.lexical_frames,
                selected_apply.with_scopes,
                selected_apply.scoped_globals,
                selected_apply.body.root_kind,
                selected_apply.body.grammar,
                grammar_features,
                selected_apply.body.nodes,
                selected_apply.body.depth,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Some(format!("{{\"total\":{total},\"classes\":[{classes}]}}"))
}

/// Builds the complete stable sort key for one selected-child class.
fn selected_child_signature(descriptor: SelectedChildDescriptor) -> String {
    let apply = descriptor.apply.unwrap_or(ApplySpineDescriptor {
        origin: "not-apply",
        callee: "not-apply",
        pattern: "not-apply",
        body: "not-apply",
        argument: "not-apply",
    });
    let selected_apply = descriptor
        .selected_apply
        .unwrap_or(SelectedApplyDescriptor {
            callee_kind: "not-apply",
            lambda_module: "not-lambda",
            lexical_frames: 0,
            with_scopes: 0,
            scoped_globals: 0,
            body: SelectedApplyBodyDescriptor {
                root_kind: "not-lambda",
                grammar: "not-lambda",
                features: 0,
                nodes: 0,
                depth: 0,
            },
        });
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{:010}|{:010}|{:010}|{}|{}|{:05}|{:03}|{:03}",
        descriptor.runtime_kind,
        descriptor.thunk_kind,
        descriptor.thunk_state,
        descriptor.body,
        apply.origin,
        apply.callee,
        apply.pattern,
        apply.body,
        apply.argument,
        selected_apply.callee_kind,
        selected_apply.lambda_module,
        selected_apply.lexical_frames,
        selected_apply.with_scopes,
        selected_apply.scoped_globals,
        selected_apply.body.root_kind,
        selected_apply.body.grammar,
        selected_apply.body.features,
        selected_apply.body.nodes,
        selected_apply.body.depth,
    )
}

/// Formats the selected-body feature mask as a deterministic JSON string run.
fn selected_apply_body_features(features: u16) -> String {
    const FEATURES: &[(u16, &str)] = &[
        (1 << 0, "literal"),
        (1 << 1, "lexical"),
        (1 << 2, "select"),
        (1 << 3, "primop"),
        (1 << 4, "apply"),
        (1 << 5, "let"),
        (1 << 6, "attrs"),
        (1 << 7, "list"),
        (1 << 8, "operator"),
        (1 << 9, "thunk"),
        (1 << 10, "builtin"),
    ];
    FEATURES
        .iter()
        .filter_map(|(bit, name)| (features & bit != 0).then_some(format!("\"{name}\"")))
        .collect::<Vec<_>>()
        .join(",")
}

/// Builds the stable report key for a classified Apply spine.
fn apply_spine_signature(key: ApplySpineKey) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        key.descriptor.origin,
        key.descriptor.callee,
        key.descriptor.pattern,
        key.descriptor.body,
        key.descriptor.argument,
        key.children,
        key.outcome.as_str(),
    )
}

#[cfg(test)]
mod tests;
