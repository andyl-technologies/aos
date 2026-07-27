//! Heap-image snapshot refusal census (RFC-0007 doc 31 §1 feasibility probe).
//!
//! [`EvalHeap::capture_heap_image`](super::EvalHeap::capture_heap_image) refuses
//! a heap that holds worker closures or record-table objects. The compound
//! *data* class (strings, paths, attrsets, lists, and context-bearing strings)
//! now round-trips, so the open question for snapshotting the real forced
//! lib+stdenv prelude is the *refused* mass: how much of the heap is closures,
//! split by thunk/lambda/primop and — for thunks — by force state, since an
//! unforced (`Suspended`) thunk can be collapsed to a value the snapshot already
//! handles, whereas a lambda needs genuine closure serialization.
//!
//! This module walks a forced heap and tallies both the accepted (snapshottable)
//! and refused object mass by kind, producing a [`RefusalCensus`] table. It is a
//! diagnostic: it never mutates the heap and is not on the capture path.
//!
//! # Caveats
//!
//! - Byte mass is the *inline* flat-allocation size (`size_bytes()`): header plus
//!   inline payload plus the inline recursive-binding capture tail. It does **not**
//!   count a closure's captured [`EvalEnv`](crate::eval::env::EvalEnv), whose
//!   frames are `Arc`-shared outside the arena — so closure retention is
//!   undercounted. The census reports how many closures capture an environment as
//!   a proxy; precise retained-env mass needs a dedicated frame-graph walk.
//! - Source attribution (prelude vs package, top-level vs nested) needs the
//!   `TreeWalk` module registry, which the `EvalOutcome` does not retain. The
//!   census reports the count of distinct referenced code modules only.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use crate::eval::env::EvalFrame;
use crate::eval::module::EvalModuleId;
use crate::eval::thunk::ThunkState;
use crate::value::ValueTag;

use super::*;

/// A count-and-byte tally for one object kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct KindTally {
    /// Number of live objects of this kind.
    pub count: u64,
    /// Summed inline flat-allocation bytes (`size_bytes()`); see the module
    /// caveats — this excludes out-of-arena captured environments.
    pub inline_bytes: u64,
}

/// Serial flat-store allocation watermarks captured at one import miss.
///
/// The fence contains only store lengths and scalar payload totals. It does
/// not borrow the heap, root values, or alter allocation placement, so a
/// strictly nested cached import can retain it across arbitrary evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImportEpochCensusFence {
    import_ordinal: u64,
    import_depth: usize,
    records: usize,
    strings_and_paths: usize,
    lists: usize,
    attrs: usize,
    closures: usize,
    typed_thunks: usize,
    boxed_scalars: usize,
    boxed_scalar_payload_bytes: usize,
}

/// Root-liveness split for one allocation cohort kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ImportEpochKindCensus {
    cohort: KindTally,
    reachable: KindTally,
}

impl ImportEpochKindCensus {
    /// Returns the cohort mass not reached from the supplied root set.
    fn unreachable(self) -> KindTally {
        KindTally {
            count: self.cohort.count.saturating_sub(self.reachable.count),
            inline_bytes: self
                .cohort
                .inline_bytes
                .saturating_sub(self.reachable.inline_bytes),
        }
    }

    /// Records one cohort allocation and whether the weak root scan reached it.
    fn add(&mut self, inline_bytes: usize, reachable: bool) {
        self.cohort.add(inline_bytes);
        if reachable {
            self.reachable.add(inline_bytes);
        }
    }
}

/// Read-only survivor projection for allocations made during one import miss.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ImportEpochCensus {
    import_ordinal: u64,
    import_depth: u64,
    roots: u64,
    reachable_objects: u64,
    fence_valid: bool,
    stores_covered: u64,
    stores_total: u64,
    records: ImportEpochKindCensus,
    strings_and_paths: ImportEpochKindCensus,
    lists: ImportEpochKindCensus,
    attrs: ImportEpochKindCensus,
    closures: ImportEpochKindCensus,
    typed_thunks: ImportEpochKindCensus,
    list_spine_cohort_bytes: u64,
    list_spine_reachable_bytes: u64,
    boxed_scalar_cohort_count: u64,
    boxed_scalar_cohort_payload_bytes: u64,
}

/// Count and byte mass for one lifetime-cohort reachability class.
#[cfg(feature = "lifetime_cohort_probe")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LifetimeCohortMass {
    /// Live objects assigned to this class.
    pub(crate) objects: u64,
    /// Bytes reserved inline in evaluator heap arenas.
    pub(crate) inline_bytes: u64,
    /// Separately allocated bytes retained by object payloads.
    pub(crate) external_bytes: u64,
}

#[cfg(feature = "lifetime_cohort_probe")]
impl LifetimeCohortMass {
    /// Returns inline plus separately allocated payload bytes.
    pub(crate) const fn total_bytes(self) -> u64 {
        self.inline_bytes.saturating_add(self.external_bytes)
    }

    /// Records one live heap object.
    fn add(&mut self, inline_bytes: usize, external_bytes: usize) {
        self.objects = self.objects.saturating_add(1);
        self.inline_bytes = self.inline_bytes.saturating_add(inline_bytes as u64);
        self.external_bytes = self.external_bytes.saturating_add(external_bytes as u64);
    }
}

/// Read-only checkpoint aggregate for chronological lifetime-cohort replay.
///
/// The four reachability classes partition every root-reachable object.
/// [`Self::unreachable`] covers iterable live heap objects outside that root
/// closure. Boxed scalar cells remain explicitly pinned and unclassified.
#[cfg(feature = "lifetime_cohort_probe")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LifetimeCohortCensus {
    /// All iterable, non-retired heap objects.
    pub(crate) total: LifetimeCohortMass,
    /// Objects reached only from Ready import-cache roots.
    pub(crate) ready_only: LifetimeCohortMass,
    /// Objects reached only from non-import roots.
    pub(crate) other_only: LifetimeCohortMass,
    /// Objects reached from both root partitions.
    pub(crate) shared: LifetimeCohortMass,
    /// Objects reached from neither root partition.
    pub(crate) unreachable: LifetimeCohortMass,
    /// Number of Ready import-cache roots.
    pub(crate) ready_roots: u64,
    /// Number of non-import roots.
    pub(crate) other_roots: u64,
    /// Whether the independently scanned all-root closure equals the partition union.
    pub(crate) union_reconciled: bool,
    /// Live legacy record-table entries.
    pub(crate) records: u64,
    /// String/path flat-store entries and reserved registry capacity.
    pub(crate) strings_paths: [u64; 2],
    /// List flat-store entries and reserved registry capacity.
    pub(crate) lists: [u64; 2],
    /// Attrset flat-store entries and reserved registry capacity.
    pub(crate) attrs: [u64; 2],
    /// Worker-closure flat-store entries and reserved registry capacity.
    pub(crate) closures: [u64; 2],
    /// Headerless typed-thunk heads and reserved slot capacity.
    pub(crate) typed_heads: [u64; 2],
    /// Live, peak-live, allocated, and reserved typed-work slots.
    pub(crate) typed_work: [u64; 4],
    /// Boxed scalar cell count and payload bytes, conservatively pinned.
    pub(crate) boxed_scalars: [u64; 2],
    /// Hash-cons bucket/candidate length and capacity totals across four tables.
    pub(crate) hash_cons: [u64; 4],
}

/// Storage identity for one residual-retirement shadow candidate.
#[cfg(feature = "lifetime_cohort_probe")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifetimeCohortCandidateKind {
    /// A legacy record-table object with the captured runtime tag.
    Record(ValueTag),
    /// A flat string.
    String,
    /// A flat path.
    Path,
    /// A flat list.
    List,
    /// A flat attribute set.
    Attrs,
    /// A flat thunk, lambda, or primop with the captured storage kind.
    Closure(FlatObjectKind),
    /// A headerless typed-thunk head, which has no generic touch epoch.
    TypedThunk,
}

/// One stable-address object that was unreachable at a selected checkpoint.
#[cfg(feature = "lifetime_cohort_probe")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LifetimeCohortCandidate {
    pub(crate) address: usize,
    pub(crate) kind: LifetimeCohortCandidateKind,
    pub(crate) inline_bytes: u64,
    pub(crate) external_bytes: u64,
    pub(crate) initial_touch_epoch: Option<u64>,
}

#[cfg(feature = "lifetime_cohort_probe")]
impl LifetimeCohortCandidate {
    /// Returns inline plus separately allocated payload bytes.
    pub(crate) const fn attributable_bytes(self) -> u64 {
        self.inline_bytes.saturating_add(self.external_bytes)
    }
}

/// Current replay observation for one previously captured candidate.
#[cfg(feature = "lifetime_cohort_probe")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifetimeCohortCandidateObservation {
    /// The candidate was captured in the current window and has no later observation.
    Pending,
    /// The candidate remains unreachable and its touch epoch did not advance.
    Cold,
    /// The candidate was resolved after its capture checkpoint.
    Touched,
    /// A later complete root set reaches the candidate.
    Resurrected,
    /// The address no longer names the captured storage identity.
    VanishedOrReused,
    /// The storage kind has no complete generic touch-epoch coverage.
    NoEpoch,
}

/// Aggregate census plus the exact current residual-retirement inventory.
#[cfg(feature = "lifetime_cohort_probe")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifetimeCohortSnapshot {
    pub(crate) census: LifetimeCohortCensus,
    pub(crate) unreachable_candidates: Vec<LifetimeCohortCandidate>,
    pub(crate) prior_observations: Vec<LifetimeCohortCandidateObservation>,
}

impl fmt::Display for ImportEpochCensus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = |f: &mut fmt::Formatter<'_>, name: &str, census: ImportEpochKindCensus| {
            let dead = census.unreachable();
            write!(
                f,
                "\"{name}\":[{},{},{},{},{},{}]",
                census.cohort.count,
                census.reachable.count,
                dead.count,
                census.cohort.inline_bytes,
                census.reachable.inline_bytes,
                dead.inline_bytes
            )
        };
        write!(
            f,
            "aos_nix_import_epoch_census {{\"import_ordinal\":{},\"import_depth\":{},\
             \"fences\":1,\"fence_valid\":{},\
             \"roots\":{},\"reachable_objects\":{},\"coverage\":[{},{}],",
            self.import_ordinal,
            self.import_depth,
            self.fence_valid,
            self.roots,
            self.reachable_objects,
            self.stores_covered,
            self.stores_total
        )?;
        kind(f, "records", self.records)?;
        write!(f, ",")?;
        kind(f, "strings_paths", self.strings_and_paths)?;
        write!(f, ",")?;
        kind(f, "lists", self.lists)?;
        write!(f, ",")?;
        kind(f, "attrs", self.attrs)?;
        write!(f, ",")?;
        kind(f, "closures", self.closures)?;
        write!(f, ",")?;
        kind(f, "typed_thunks", self.typed_thunks)?;
        write!(
            f,
            ",\"list_spine_bytes\":[{},{},{}],\
             \"boxed_scalars_pinned_unclassified\":[{},{}],\
             \"nested_cohorts_overlap\":true,\
             \"dead_is_weak_root_projection\":true,\
             \"excluded\":{{\"captured_envs\":true,\"typed_work_slots\":true,\
             \"hash_indexes\":true,\"blackhole_external_state\":true}}}}",
            self.list_spine_cohort_bytes,
            self.list_spine_reachable_bytes,
            self.list_spine_cohort_bytes
                .saturating_sub(self.list_spine_reachable_bytes),
            self.boxed_scalar_cohort_count,
            self.boxed_scalar_cohort_payload_bytes
        )
    }
}

/// Reachability measured without treating hash-cons indexes as strong roots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WeakLivenessCensus {
    /// Explicit non-intern roots supplied by the evaluator.
    roots: u64,
    /// Distinct heap objects reached transitively from those roots.
    reachable_objects: u64,
    strings_and_paths: KindTally,
    attrs: KindTally,
    lists: KindTally,
    typed_thunks: KindTally,
    thunks_suspended: KindTally,
    thunks_forced: KindTally,
    lambdas: KindTally,
    primops: KindTally,
    list_spine_bytes: u64,
    total: RefusalCensus,
    total_typed_thunks: u64,
    total_list_spine_bytes: u64,
    reservation_total_pages: u64,
    reservation_live_pages: u64,
}

impl fmt::Display for WeakLivenessCensus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind =
            |f: &mut fmt::Formatter<'_>, name: &str, reachable: KindTally, total: KindTally| {
                write!(
                    f,
                    "\"{name}\":[{},{},{},{}]",
                    reachable.count, total.count, reachable.inline_bytes, total.inline_bytes
                )
            };
        write!(
            f,
            "aos_nix_weak_liveness_census {{\"roots\":{},\"reachable_objects\":{},",
            self.roots, self.reachable_objects
        )?;
        kind(
            f,
            "strings_paths",
            self.strings_and_paths,
            self.total.strings_and_paths,
        )?;
        write!(f, ",")?;
        kind(f, "attrs", self.attrs, self.total.attrs)?;
        write!(f, ",")?;
        kind(f, "lists", self.lists, self.total.lists)?;
        write!(
            f,
            ",\"typed_thunks\":[{},{},{},{}],",
            self.typed_thunks.count,
            self.total_typed_thunks,
            self.typed_thunks.inline_bytes,
            self.total_typed_thunks
                .saturating_mul(std::mem::size_of::<StableThunkHead>() as u64)
        )?;
        kind(
            f,
            "thunks_suspended",
            self.thunks_suspended,
            self.total.thunks_suspended,
        )?;
        write!(f, ",")?;
        kind(
            f,
            "thunks_forced",
            self.thunks_forced,
            self.total.thunks_forced,
        )?;
        write!(f, ",")?;
        kind(f, "lambdas", self.lambdas, self.total.lambdas)?;
        write!(f, ",")?;
        kind(f, "primops", self.primops, self.total.primops)?;
        write!(
            f,
            ",\"list_spine_bytes\":[{},{}],\
             \"reservation_pages\":[{},{},{},{}]}}",
            self.list_spine_bytes,
            self.total_list_spine_bytes,
            self.reservation_total_pages,
            self.reservation_live_pages,
            self.reservation_total_pages
                .saturating_sub(self.reservation_live_pages),
            self.reservation_total_pages
                .saturating_sub(self.reservation_live_pages)
                .saturating_mul(4096)
        )
    }
}

impl KindTally {
    /// Records one object of `inline_bytes` reserved size.
    fn add(&mut self, inline_bytes: usize) {
        self.count += 1;
        self.inline_bytes += inline_bytes as u64;
    }
}

/// A refusal census of one forced [`EvalHeap`] (RFC-0007 doc 31 §1 probe).
///
/// Groups every live flat object into the snapshot's *accepted* set (data that
/// already round-trips) and *refused* set (worker closures and record-table
/// objects), the latter split finely enough to choose the next increment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RefusalCensus {
    // Accepted (snapshottable) data.
    /// Strings and paths (`flat`): both are `NixString` objects.
    pub strings_and_paths: KindTally,
    /// Attribute sets (`flat_attrs`).
    pub attrs: KindTally,
    /// Lists (`flat_lists`).
    pub lists: KindTally,

    // Refused: worker closures (`flat_closures`), by payload kind.
    /// Unforced thunks — `Suspended` cell state; collapsible to a value.
    pub thunks_suspended: KindTally,
    /// Thunks that are `Forced` or `Blackhole` (in flight); the value exists or
    /// is being computed.
    pub thunks_forced: KindTally,
    /// Lambda closures (genuine function values).
    pub lambdas: KindTally,
    /// Builtins and partially applied builtins.
    pub primops: KindTally,
    /// Retired (swept) closure slots; refused by count but hold no live payload.
    pub retired_closures: KindTally,

    // Refused: record-table objects (≈0 without a GC-stress policy).
    /// Live typed record-table objects (`record_count()`).
    pub records: u64,

    /// Distinct code modules referenced by the live closures.
    pub distinct_code_modules: u64,
    /// Live closures that capture a lexical environment (retention proxy).
    pub closures_capturing_env: u64,

    // Forced-thunk collapse projection: what each forced thunk holds. Collapsing
    // a forced thunk replaces references to it with its cached value, so the
    // wrapper vanishes and the target (already counted elsewhere) remains. These
    // classify the collapse targets to confirm it is clean and to size the
    // post-collapse residual without mutating the heap.
    /// Forced thunks whose cached value is heap data (string/path/list/attrs) —
    /// collapse to an already-counted accepted object.
    pub forced_holds_heap_data: u64,
    /// Forced thunks whose cached value is an inline scalar (int/float/bool/null)
    /// — collapse to a wordless value, no object.
    pub forced_holds_inline_scalar: u64,
    /// Forced thunks whose cached value is a lambda — collapse reveals an
    /// already-counted lambda object.
    pub forced_holds_lambda: u64,
    /// Forced thunks whose cached value is a primop.
    pub forced_holds_primop: u64,
    /// Forced thunks whose cached value is another thunk (a collapse chain).
    pub forced_holds_thunk: u64,
    /// Forced thunks whose cached value was absent or an unclassified tag.
    pub forced_holds_unknown: u64,

    // Captured-environment frame graph (step-3 increment-2 stop-condition
    // measurement): the `Arc<EvalFrame>` retention the inline byte mass does not
    // count. Frames are deduplicated by `Arc` identity across all closure envs.
    /// Distinct `Arc<EvalFrame>` reached from every closure environment.
    pub env_distinct_frames: u64,
    /// Total frame references across all closure envs, before dedup (the ratio
    /// against `env_distinct_frames` shows how much sharing the DAG exploits).
    pub env_frame_refs: u64,
    /// Total slot count summed over the distinct frames (one `Value` word each).
    pub env_total_slots: u64,
}

impl RefusalCensus {
    /// Total live objects the snapshot would refuse (closures + records).
    pub fn refused_count(&self) -> u64 {
        self.thunks_suspended.count
            + self.thunks_forced.count
            + self.lambdas.count
            + self.primops.count
            + self.retired_closures.count
            + self.records
    }

    /// Total inline bytes held by the refused closures (records excluded — their
    /// bytes live in a separate table).
    pub fn refused_inline_bytes(&self) -> u64 {
        self.thunks_suspended.inline_bytes
            + self.thunks_forced.inline_bytes
            + self.lambdas.inline_bytes
            + self.primops.inline_bytes
            + self.retired_closures.inline_bytes
    }

    /// Total inline bytes held by the accepted data objects.
    pub fn accepted_inline_bytes(&self) -> u64 {
        self.strings_and_paths.inline_bytes + self.attrs.inline_bytes + self.lists.inline_bytes
    }

    /// Projected count of objects still refused after forced-thunk collapse.
    ///
    /// Collapsing a forced thunk replaces references to it with its cached value,
    /// so every forced thunk wrapper vanishes and its target is already counted
    /// elsewhere. The residual is the lambdas, primops, and thunks that forcing
    /// did not reach (suspended, e.g. inside lambda bodies). This is the size of
    /// the genuine closure-serialization problem that gates the next increment.
    pub fn projected_residual_refused_count(&self) -> u64 {
        self.lambdas.count + self.primops.count + self.thunks_suspended.count
    }

    /// Projected inline bytes still refused after forced-thunk collapse.
    pub fn projected_residual_refused_bytes(&self) -> u64 {
        self.lambdas.inline_bytes + self.primops.inline_bytes + self.thunks_suspended.inline_bytes
    }

    /// Frame-sharing dedup ratio: frame references per distinct frame. A high
    /// ratio means the `Arc<EvalFrame>` DAG shares heavily and the serialized
    /// frame table stays small relative to the closure count.
    pub fn env_frame_dedup_ratio(&self) -> f64 {
        if self.env_distinct_frames == 0 {
            0.0
        } else {
            self.env_frame_refs as f64 / self.env_distinct_frames as f64
        }
    }

    /// Estimated serialized frame-table size: per distinct frame an 8-byte header
    /// (parent frame id + slot count) plus one 8-byte `Value` word per slot. This
    /// is the retained env mass the inline byte census could not size — the
    /// step-3 stop-condition input.
    pub fn env_serialized_bytes_estimate(&self) -> u64 {
        self.env_distinct_frames * 8 + self.env_total_slots * 8
    }

    /// Classifies one thunk (owned or `Arc`-shared) into the refused-closure
    /// tallies: suspended vs forced, its collapse target, code module, and env.
    fn classify_thunk(
        &mut self,
        thunk: &EvalThunk,
        size: usize,
        modules: &mut HashSet<EvalModuleId>,
    ) {
        match thunk.cell().state() {
            Ok(ThunkState::Suspended) => self.thunks_suspended.add(size),
            // Forced or Blackhole: the value exists or is in flight.
            Ok(_) => {
                self.thunks_forced.add(size);
                match thunk.cell().cached_value() {
                    Ok(Some(value)) => self.classify_collapse_target(value.tag()),
                    _ => self.forced_holds_unknown += 1,
                }
            }
            // A poisoned cell still occupies a refused slot.
            Err(_) => self.thunks_forced.add(size),
        }
        if let Some(module) = thunk.code_module() {
            modules.insert(module);
        }
        if thunk.env().is_some() {
            self.closures_capturing_env += 1;
        }
    }

    /// Records the kind of value a forced thunk holds (its collapse target).
    fn classify_collapse_target(&mut self, tag: ValueTag) {
        match tag {
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs => {
                self.forced_holds_heap_data += 1
            }
            ValueTag::Int | ValueTag::Float | ValueTag::Bool | ValueTag::Null => {
                self.forced_holds_inline_scalar += 1
            }
            ValueTag::Lambda => self.forced_holds_lambda += 1,
            ValueTag::Primop => self.forced_holds_primop += 1,
            ValueTag::Thunk => self.forced_holds_thunk += 1,
            _ => self.forced_holds_unknown += 1,
        }
    }
}

impl fmt::Display for RefusalCensus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let row = |f: &mut fmt::Formatter<'_>, label: &str, t: KindTally| {
            writeln!(
                f,
                "  {label:<22} count={:>8}  inline_bytes={:>12}",
                t.count, t.inline_bytes
            )
        };
        writeln!(f, "heap-image refusal census (RFC-0007 doc 31 §1)")?;
        writeln!(f, "accepted (snapshottable) data:")?;
        row(f, "strings+paths", self.strings_and_paths)?;
        row(f, "attrs", self.attrs)?;
        row(f, "lists", self.lists)?;
        writeln!(
            f,
            "  accepted total          inline_bytes={:>12}",
            self.accepted_inline_bytes()
        )?;
        writeln!(f, "refused: closures:")?;
        row(f, "thunks (suspended)", self.thunks_suspended)?;
        row(f, "thunks (forced)", self.thunks_forced)?;
        row(f, "lambdas", self.lambdas)?;
        row(f, "primops", self.primops)?;
        row(f, "retired (swept)", self.retired_closures)?;
        writeln!(f, "refused: records:")?;
        writeln!(f, "  record-table objects   count={:>8}", self.records)?;
        writeln!(
            f,
            "refused total            count={:>8}  closure_inline_bytes={:>12}",
            self.refused_count(),
            self.refused_inline_bytes()
        )?;
        writeln!(f, "closure detail:")?;
        writeln!(f, "  distinct code modules  {}", self.distinct_code_modules)?;
        writeln!(
            f,
            "  closures capturing env {} (retained env bytes not counted here)",
            self.closures_capturing_env
        )?;
        writeln!(
            f,
            "forced-thunk collapse projection (targets, no mutation):"
        )?;
        writeln!(
            f,
            "  -> heap data           {}",
            self.forced_holds_heap_data
        )?;
        writeln!(
            f,
            "  -> inline scalar       {}",
            self.forced_holds_inline_scalar
        )?;
        writeln!(f, "  -> lambda              {}", self.forced_holds_lambda)?;
        writeln!(f, "  -> primop              {}", self.forced_holds_primop)?;
        writeln!(f, "  -> thunk (chain)       {}", self.forced_holds_thunk)?;
        writeln!(f, "  -> unknown/absent      {}", self.forced_holds_unknown)?;
        writeln!(
            f,
            "projected residual after collapse   count={:>8}  inline_bytes={:>12}",
            self.projected_residual_refused_count(),
            self.projected_residual_refused_bytes()
        )?;
        writeln!(f, "captured-env frame graph (step-3 stop condition):")?;
        writeln!(f, "  distinct frames        {}", self.env_distinct_frames)?;
        writeln!(f, "  frame refs (pre-dedup) {}", self.env_frame_refs)?;
        writeln!(
            f,
            "  dedup ratio            {:.2}",
            self.env_frame_dedup_ratio()
        )?;
        writeln!(f, "  total slots            {}", self.env_total_slots)?;
        writeln!(
            f,
            "  est. serialized bytes  {}",
            self.env_serialized_bytes_estimate()
        )
    }
}

impl EvalHeap {
    /// Aggregates heap ownership at one complete-root lifetime checkpoint.
    ///
    /// The diagnostic performs three independent weak-root scans: all roots,
    /// Ready import-cache roots, and every other root. Hash-cons tables are not
    /// roots. It never mutates heap state or logs allocation-path events.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a root or transitive edge is malformed, a
    /// thunk state is invalid, or scanner scratch storage cannot grow.
    #[cfg(feature = "lifetime_cohort_probe")]
    pub(crate) fn lifetime_cohort_census(
        &self,
        roots: &EvalRootSet,
        prior_candidates: &[LifetimeCohortCandidate],
    ) -> Result<LifetimeCohortSnapshot, EvalHeapError> {
        let all = self.weak_reachable_addresses(roots)?;
        let ready = self.weak_reachable_addresses_matching(roots, |source| {
            matches!(source, EvalRootSource::ImportCache { .. })
        })?;
        let other = self.weak_reachable_addresses_matching(roots, |source| {
            !matches!(source, EvalRootSource::ImportCache { .. })
        })?;
        let union_reconciled = all.len() == ready.union(&other).count()
            && all
                .iter()
                .all(|address| ready.contains(address) || other.contains(address));
        let ready_roots = roots
            .roots()
            .iter()
            .filter(|root| matches!(root.source(), EvalRootSource::ImportCache { .. }))
            .count();
        let mut census = LifetimeCohortCensus {
            ready_roots: ready_roots as u64,
            other_roots: roots.len().saturating_sub(ready_roots) as u64,
            union_reconciled,
            records: self
                .records
                .iter()
                .filter(|record| !record.is_retired())
                .count() as u64,
            strings_paths: [self.flat.len() as u64, self.flat.registry_capacity() as u64],
            lists: [
                self.flat_lists.len() as u64,
                self.flat_lists.registry_capacity() as u64,
            ],
            attrs: [
                self.flat_attrs.len() as u64,
                self.flat_attrs.registry_capacity() as u64,
            ],
            closures: [
                self.flat_closures.len() as u64,
                self.flat_closures.registry_capacity() as u64,
            ],
            typed_heads: [
                self.typed_thunk_heads.len() as u64,
                self.typed_thunk_heads.capacity() as u64,
            ],
            ..LifetimeCohortCensus::default()
        };
        let (_, live_work, peak_work, work_slots, work_capacity) = self.typed_thunk_head_counts();
        census.typed_work = [
            live_work as u64,
            peak_work as u64,
            work_slots as u64,
            work_capacity as u64,
        ];
        let (boxed_cells, boxed_bytes) = self.boxed_scalar_census_totals();
        census.boxed_scalars = [boxed_cells as u64, boxed_bytes as u64];
        for counts in [
            self.string_cons.storage_counts(),
            self.path_cons.storage_counts(),
            self.list_cons.storage_counts(),
            self.attrs_cons.storage_counts(),
        ] {
            census.hash_cons[0] = census.hash_cons[0].saturating_add(counts.0 as u64);
            census.hash_cons[1] = census.hash_cons[1].saturating_add(counts.1 as u64);
            census.hash_cons[2] = census.hash_cons[2].saturating_add(counts.2 as u64);
            census.hash_cons[3] = census.hash_cons[3].saturating_add(counts.3 as u64);
        }

        let mut record = |address: usize, inline_bytes: usize, external_bytes: usize| {
            census.total.add(inline_bytes, external_bytes);
            match (ready.contains(&address), other.contains(&address)) {
                (true, true) => census.shared.add(inline_bytes, external_bytes),
                (true, false) => census.ready_only.add(inline_bytes, external_bytes),
                (false, true) => census.other_only.add(inline_bytes, external_bytes),
                (false, false) => census.unreachable.add(inline_bytes, external_bytes),
            }
        };
        for entry in self.records.iter().filter(|record| !record.is_retired()) {
            record(entry.ptr.as_ptr() as usize, entry.layout.size_bytes, 0);
        }
        for entry in self.flat.iter() {
            record(entry.ptr().as_ptr() as usize, entry.size_bytes(), 0);
        }
        for entry in self.flat_lists.iter() {
            let external = entry
                .object()
                .payload()
                .capacity()
                .saturating_mul(std::mem::size_of::<Value>());
            record(entry.ptr().as_ptr() as usize, entry.size_bytes(), external);
        }
        for entry in self.flat_attrs.iter() {
            record(entry.ptr().as_ptr() as usize, entry.size_bytes(), 0);
        }
        for entry in self.flat_closures.iter() {
            if !entry.object().payload().is_retired() {
                record(entry.ptr().as_ptr() as usize, entry.size_bytes(), 0);
            }
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            record(address, bytes, 0);
        }

        let candidate_capacity = usize::try_from(census.unreachable.objects).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: "lifetime-cohort unreachable candidates",
                entries: usize::MAX,
            }
        })?;
        let mut unreachable_candidates = Vec::new();
        unreachable_candidates
            .try_reserve_exact(candidate_capacity)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: "lifetime-cohort unreachable candidates",
                entries: candidate_capacity,
            })?;
        for entry in self.records.iter().filter(|record| !record.is_retired()) {
            let address = entry.ptr.as_ptr() as usize;
            if !all.contains(&address) {
                unreachable_candidates.push(LifetimeCohortCandidate {
                    address,
                    kind: LifetimeCohortCandidateKind::Record(entry.object.tag()),
                    inline_bytes: entry.layout.size_bytes as u64,
                    external_bytes: 0,
                    initial_touch_epoch: Some(entry.last_touch_epoch.get()),
                });
            }
        }
        for entry in self.flat.iter() {
            let address = entry.ptr().as_ptr() as usize;
            if all.contains(&address) {
                continue;
            }
            let kind = match entry.object().kind() {
                FlatObjectKind::String => LifetimeCohortCandidateKind::String,
                FlatObjectKind::Path => LifetimeCohortCandidateKind::Path,
                _ => continue,
            };
            unreachable_candidates.push(LifetimeCohortCandidate {
                address,
                kind,
                inline_bytes: entry.size_bytes() as u64,
                external_bytes: 0,
                initial_touch_epoch: Some(entry.object().last_touch_epoch()),
            });
        }
        for entry in self.flat_lists.iter() {
            let address = entry.ptr().as_ptr() as usize;
            if !all.contains(&address) {
                unreachable_candidates.push(LifetimeCohortCandidate {
                    address,
                    kind: LifetimeCohortCandidateKind::List,
                    inline_bytes: entry.size_bytes() as u64,
                    external_bytes: entry
                        .object()
                        .payload()
                        .capacity()
                        .saturating_mul(std::mem::size_of::<Value>())
                        as u64,
                    initial_touch_epoch: Some(entry.object().last_touch_epoch()),
                });
            }
        }
        for entry in self.flat_attrs.iter() {
            let address = entry.ptr().as_ptr() as usize;
            if !all.contains(&address) {
                unreachable_candidates.push(LifetimeCohortCandidate {
                    address,
                    kind: LifetimeCohortCandidateKind::Attrs,
                    inline_bytes: entry.size_bytes() as u64,
                    external_bytes: 0,
                    initial_touch_epoch: Some(entry.object().last_touch_epoch()),
                });
            }
        }
        for entry in self.flat_closures.iter() {
            let payload = entry.object().payload();
            if payload.is_retired() {
                continue;
            }
            let address = entry.ptr().as_ptr() as usize;
            if all.contains(&address) {
                continue;
            }
            let kind = match payload {
                FlatClosurePayload::Thunk(_) | FlatClosurePayload::SharedThunk(_) => {
                    FlatObjectKind::Thunk
                }
                FlatClosurePayload::Lambda(_) => FlatObjectKind::Lambda,
                FlatClosurePayload::Primop(_) => FlatObjectKind::Primop,
                FlatClosurePayload::Retired(_) => continue,
            };
            unreachable_candidates.push(LifetimeCohortCandidate {
                address,
                kind: LifetimeCohortCandidateKind::Closure(kind),
                inline_bytes: entry.size_bytes() as u64,
                external_bytes: 0,
                initial_touch_epoch: Some(entry.object().last_touch_epoch()),
            });
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            if !all.contains(&address) {
                unreachable_candidates.push(LifetimeCohortCandidate {
                    address,
                    kind: LifetimeCohortCandidateKind::TypedThunk,
                    inline_bytes: bytes as u64,
                    external_bytes: 0,
                    initial_touch_epoch: None,
                });
            }
        }

        let mut prior_observations = Vec::new();
        prior_observations
            .try_reserve_exact(prior_candidates.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: "lifetime-cohort prior observations",
                entries: prior_candidates.len(),
            })?;
        for candidate in prior_candidates {
            let observation = if all.contains(&candidate.address) {
                LifetimeCohortCandidateObservation::Resurrected
            } else {
                self.lifetime_cohort_candidate_observation(*candidate)
            };
            prior_observations.push(observation);
        }
        Ok(LifetimeCohortSnapshot {
            census,
            unreachable_candidates,
            prior_observations,
        })
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    fn lifetime_cohort_candidate_observation(
        &self,
        candidate: LifetimeCohortCandidate,
    ) -> LifetimeCohortCandidateObservation {
        let Some(ptr) = NonNull::new(candidate.address as *mut HeapObject) else {
            return LifetimeCohortCandidateObservation::VanishedOrReused;
        };
        let current = match candidate.kind {
            LifetimeCohortCandidateKind::Record(tag) => self
                .records
                .iter()
                .find(|record| {
                    !record.is_retired() && record.ptr == ptr && record.object.tag() == tag
                })
                .map(|record| record.last_touch_epoch.get()),
            LifetimeCohortCandidateKind::String => self
                .flat
                .resolve(ptr, FlatObjectKind::String)
                .ok()
                .map(|object| object.last_touch_epoch()),
            LifetimeCohortCandidateKind::Path => self
                .flat
                .resolve(ptr, FlatObjectKind::Path)
                .ok()
                .map(|object| object.last_touch_epoch()),
            LifetimeCohortCandidateKind::List => self
                .flat_lists
                .resolve(ptr, FlatObjectKind::List)
                .ok()
                .map(|object| object.last_touch_epoch()),
            LifetimeCohortCandidateKind::Attrs => self
                .flat_attrs
                .resolve(ptr, FlatObjectKind::Attrs)
                .ok()
                .map(|object| object.last_touch_epoch()),
            LifetimeCohortCandidateKind::Closure(kind) => self
                .flat_closures
                .resolve(ptr, kind)
                .ok()
                .map(|object| object.last_touch_epoch()),
            LifetimeCohortCandidateKind::TypedThunk => {
                return if self.typed_thunk_heads.resolve(ptr).is_ok() {
                    LifetimeCohortCandidateObservation::NoEpoch
                } else {
                    LifetimeCohortCandidateObservation::VanishedOrReused
                };
            }
        };
        match (candidate.initial_touch_epoch, current) {
            (Some(initial), Some(current)) if current == initial => {
                LifetimeCohortCandidateObservation::Cold
            }
            (Some(initial), Some(current)) if current > initial => {
                LifetimeCohortCandidateObservation::Touched
            }
            (Some(_), Some(_)) | (_, None) => LifetimeCohortCandidateObservation::VanishedOrReused,
            (None, Some(_)) => LifetimeCohortCandidateObservation::NoEpoch,
        }
    }

    /// Returns boxed scalar cell count and scalar payload bytes.
    pub(in crate::eval::heap) fn boxed_scalar_census_totals(&self) -> (usize, usize) {
        let cells = self
            .compressed_scalars
            .boxed_int_count()
            .saturating_add(self.compressed_scalars.boxed_float_count());
        (cells, cells.saturating_mul(std::mem::size_of::<u64>()))
    }

    /// Captures serial allocation watermarks for an import-epoch diagnostic.
    ///
    /// Returns `None` for a shared heap because shard-local publication order
    /// does not define the single serial suffix this diagnostic measures.
    pub(crate) fn import_epoch_census_fence(
        &self,
        import_ordinal: u64,
        import_depth: usize,
    ) -> Option<ImportEpochCensusFence> {
        if self.shared.is_some() {
            return None;
        }
        let (boxed_scalars, boxed_scalar_payload_bytes) = self.boxed_scalar_census_totals();
        Some(ImportEpochCensusFence {
            import_ordinal,
            import_depth,
            records: self.records.len(),
            strings_and_paths: self.flat.len(),
            lists: self.flat_lists.len(),
            attrs: self.flat_attrs.len(),
            closures: self.flat_closures.len(),
            typed_thunks: self.typed_thunk_heads.len(),
            boxed_scalars,
            boxed_scalar_payload_bytes,
        })
    }

    /// Measures root-reachable and root-unreachable allocation suffixes.
    ///
    /// The scan is a projection only: it neither mutates nor reclaims objects,
    /// and hash-cons indexes are deliberately not roots. Boxed scalar cells are
    /// reported as pinned/unclassified because scalar words are intentionally
    /// outside the precise heap-edge scanner. Captured environments, typed
    /// thunk work slots, and hash-index storage are likewise not attributed to
    /// an allocation suffix.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an explicit root or edge is stale, a value
    /// tag disagrees with its object, a thunk state is invalid, or scanner
    /// work storage cannot grow.
    pub(crate) fn import_epoch_census(
        &self,
        fence: ImportEpochCensusFence,
        roots: &EvalRootSet,
    ) -> Result<ImportEpochCensus, EvalHeapError> {
        let visited = self.weak_reachable_addresses(roots)?;
        let (boxed_scalars, boxed_scalar_payload_bytes) = self.boxed_scalar_census_totals();
        let fence_valid = fence.records <= self.records.len()
            && fence.strings_and_paths <= self.flat.len()
            && fence.lists <= self.flat_lists.len()
            && fence.attrs <= self.flat_attrs.len()
            && fence.closures <= self.flat_closures.len()
            && fence.typed_thunks <= self.typed_thunk_heads.len()
            && fence.boxed_scalars <= boxed_scalars
            && fence.boxed_scalar_payload_bytes <= boxed_scalar_payload_bytes;
        let mut census = ImportEpochCensus {
            import_ordinal: fence.import_ordinal,
            import_depth: fence.import_depth as u64,
            roots: roots.len() as u64,
            reachable_objects: visited.len() as u64,
            fence_valid,
            stores_covered: 6,
            // The precise split covers records and the five directly iterable
            // serial stores. Boxed scalar cells are a seventh store population
            // but are conservatively pinned instead of called dead.
            stores_total: 7,
            boxed_scalar_cohort_count: boxed_scalars.saturating_sub(fence.boxed_scalars) as u64,
            boxed_scalar_cohort_payload_bytes: boxed_scalar_payload_bytes
                .saturating_sub(fence.boxed_scalar_payload_bytes)
                as u64,
            ..ImportEpochCensus::default()
        };
        if !fence_valid {
            return Ok(census);
        }

        for record in self.records.iter().skip(fence.records) {
            if record.is_retired() {
                continue;
            }
            let address = record.ptr.as_ptr() as usize;
            census
                .records
                .add(record.layout.size_bytes, visited.contains(&address));
        }
        for object in self.flat.iter().skip(fence.strings_and_paths) {
            let address = object.ptr().as_ptr() as usize;
            census
                .strings_and_paths
                .add(object.size_bytes(), visited.contains(&address));
        }
        for object in self.flat_lists.iter().skip(fence.lists) {
            let address = object.ptr().as_ptr() as usize;
            let reachable = visited.contains(&address);
            census.lists.add(object.size_bytes(), reachable);
            let spine_bytes = (object.object().payload().capacity() as u64)
                .saturating_mul(std::mem::size_of::<Value>() as u64);
            census.list_spine_cohort_bytes =
                census.list_spine_cohort_bytes.saturating_add(spine_bytes);
            if reachable {
                census.list_spine_reachable_bytes = census
                    .list_spine_reachable_bytes
                    .saturating_add(spine_bytes);
            }
        }
        for object in self.flat_attrs.iter().skip(fence.attrs) {
            let address = object.ptr().as_ptr() as usize;
            census
                .attrs
                .add(object.size_bytes(), visited.contains(&address));
        }
        for object in self.flat_closures.iter().skip(fence.closures) {
            let address = object.ptr().as_ptr() as usize;
            census
                .closures
                .add(object.size_bytes(), visited.contains(&address));
        }
        for (address, bytes) in self
            .typed_thunk_heads
            .initialized_regions()
            .skip(fence.typed_thunks)
        {
            census.typed_thunks.add(bytes, visited.contains(&address));
        }
        Ok(census)
    }

    /// Measures transitive liveness without rooting the hash-cons indexes.
    ///
    /// The diagnostic validates and traverses every evaluator heap kind,
    /// including headerless typed thunk heads. It never mutates the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an explicit root or edge is stale, a value
    /// tag disagrees with its object, a thunk state is invalid, or scanner
    /// work storage cannot grow.
    pub(crate) fn weak_liveness_census(
        &self,
        roots: &EvalRootSet,
    ) -> Result<WeakLivenessCensus, EvalHeapError> {
        let visited = self.weak_reachable_addresses(roots)?;
        let total = self.refusal_census();
        let mut census = WeakLivenessCensus {
            roots: roots.len() as u64,
            reachable_objects: visited.len() as u64,
            total_typed_thunks: self.typed_thunk_heads.len() as u64,
            total,
            ..WeakLivenessCensus::default()
        };
        let typed_size = std::mem::size_of::<StableThunkHead>();
        census.typed_thunks.count = visited
            .iter()
            .filter_map(|address| NonNull::new(*address as *mut HeapObject))
            .filter(|ptr| self.typed_thunk_heads.contains(*ptr))
            .count() as u64;
        census.typed_thunks.inline_bytes =
            census.typed_thunks.count.saturating_mul(typed_size as u64);

        for object in self.flat.iter() {
            if visited.contains(&(object.ptr().as_ptr() as usize)) {
                census.strings_and_paths.add(object.size_bytes());
            }
        }
        for object in self.flat_attrs.iter() {
            if visited.contains(&(object.ptr().as_ptr() as usize)) {
                census.attrs.add(object.size_bytes());
            }
        }
        for object in self.flat_lists.iter() {
            let list = object.object().payload();
            let spine_bytes =
                (list.capacity() as u64).saturating_mul(std::mem::size_of::<Value>() as u64);
            census.total_list_spine_bytes =
                census.total_list_spine_bytes.saturating_add(spine_bytes);
            if visited.contains(&(object.ptr().as_ptr() as usize)) {
                census.lists.add(object.size_bytes());
                census.list_spine_bytes = census.list_spine_bytes.saturating_add(spine_bytes);
            }
        }
        for object in self.flat_closures.iter() {
            if !visited.contains(&(object.ptr().as_ptr() as usize)) {
                continue;
            }
            let size = object.size_bytes();
            match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => match thunk.cell().state() {
                    Ok(ThunkState::Suspended) => census.thunks_suspended.add(size),
                    _ => census.thunks_forced.add(size),
                },
                FlatClosurePayload::SharedThunk(thunk) => match thunk.cell().state() {
                    Ok(ThunkState::Suspended) => census.thunks_suspended.add(size),
                    _ => census.thunks_forced.add(size),
                },
                FlatClosurePayload::Lambda(_) => census.lambdas.add(size),
                FlatClosurePayload::Primop(_) => census.primops.add(size),
                FlatClosurePayload::Retired(_) => {}
            }
        }
        let (reservation_total_pages, reservation_live_pages) =
            self.weak_liveness_reservation_pages(&visited);
        census.reservation_total_pages = reservation_total_pages;
        census.reservation_live_pages = reservation_live_pages;
        Ok(census)
    }

    /// Returns addresses transitively reached from explicit non-intern roots.
    pub(in crate::eval::heap) fn weak_reachable_addresses(
        &self,
        roots: &EvalRootSet,
    ) -> Result<HashSet<usize>, EvalHeapError> {
        self.weak_reachable_addresses_matching(roots, |_| true)
    }

    /// Returns addresses reached from roots accepted by `include`.
    ///
    /// Root sources are filtered before traversal, while detached typed-thunk
    /// heads retain their source-aware validation. This lets diagnostics split
    /// one complete safepoint root set without rebuilding roots under weaker
    /// generic source labels.
    pub(in crate::eval::heap) fn weak_reachable_addresses_matching(
        &self,
        roots: &EvalRootSet,
        include: impl Fn(&EvalRootSource) -> bool,
    ) -> Result<HashSet<usize>, EvalHeapError> {
        self.weak_reachable_addresses_matching_and_observe(roots, include, |_, _| {})
    }

    /// Returns reachable addresses while observing each object's first root.
    ///
    /// `observe` runs exactly once for every newly discovered address and
    /// receives the index of the explicit root whose traversal first found it.
    /// This preserves the live-graph-only cost of weak reachability while
    /// allowing bounded diagnostics to attribute selected objects without
    /// rescanning the graph once per root.
    pub(in crate::eval::heap) fn weak_reachable_addresses_matching_and_observe(
        &self,
        roots: &EvalRootSet,
        include: impl Fn(&EvalRootSource) -> bool,
        mut observe: impl FnMut(usize, usize),
    ) -> Result<HashSet<usize>, EvalHeapError> {
        let mut worklist = Vec::new();
        worklist
            .try_reserve(roots.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: "weak-liveness worklist",
                entries: roots.len(),
            })?;
        let mut visited = HashSet::new();
        for (root_index, root) in roots.roots().iter().enumerate() {
            if !include(root.source()) {
                continue;
            }
            if matches!(root.source(), EvalRootSource::DetachedTypedThunkHead { .. }) {
                let ptr = self.validate_detached_typed_thunk_head_root(root.value())?;
                let address = ptr.as_ptr() as usize;
                if visited.insert(address) {
                    observe(address, root_index);
                }
            } else {
                worklist.push((root.value(), root_index));
            }
        }

        while let Some((value, root_index)) = worklist.pop() {
            let (tag, ptr) = super::root_scan::heap_ptr(value)?;
            let address = ptr.as_ptr() as usize;
            if !visited.insert(address) {
                continue;
            }
            observe(address, root_index);
            let edges = if let Some(edges) = self.scan_typed_thunk_edges(ptr)? {
                if tag != ValueTag::Thunk {
                    return Err(EvalHeapError::record_type_mismatch(
                        tag,
                        ValueTag::Thunk,
                        ptr,
                    ));
                }
                edges
            } else if self.shared.is_none() && matches!(tag, ValueTag::String | ValueTag::Path) {
                self.flat_verify(tag, ptr)?;
                Vec::new()
            } else if self.shared.is_none() && tag == ValueTag::List {
                self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?
            } else if self.shared.is_none() && tag == ValueTag::Attrs {
                self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?
            } else if let Some(payload) = self.flat_closure_payload_any(ptr) {
                if payload.tag() != tag {
                    return Err(EvalHeapError::record_type_mismatch(tag, payload.tag(), ptr));
                }
                self.scan_flat_closure_edges(ptr, payload)?
            } else {
                let record = self.record_or_unknown(tag, ptr)?;
                if record.object.tag() != tag {
                    return Err(EvalHeapError::record_type_mismatch(
                        tag,
                        record.object.tag(),
                        ptr,
                    ));
                }
                self.scan_record_edges(record)?
            };
            for edge in edges {
                worklist.push((edge.value(), root_index));
            }
        }
        Ok(visited)
    }

    /// Projects pages reclaimable after invalidating every unreachable flat object.
    fn weak_liveness_reservation_pages(&self, visited: &HashSet<usize>) -> (u64, u64) {
        const PAGE_BYTES: usize = 4096;
        let mut total_pages = HashSet::new();
        let mut live_pages = HashSet::new();
        let mut record = |address: usize, bytes: usize, live: bool| {
            mark_extent_pages(&mut total_pages, address, bytes, PAGE_BYTES);
            if live {
                mark_extent_pages(&mut live_pages, address, bytes, PAGE_BYTES);
            }
        };
        for object in self.flat.iter() {
            let address = object.ptr().as_ptr() as usize;
            record(address, object.size_bytes(), visited.contains(&address));
        }
        for object in self.flat_attrs.iter() {
            let address = object.ptr().as_ptr() as usize;
            record(address, object.size_bytes(), visited.contains(&address));
        }
        for object in self.flat_lists.iter() {
            let address = object.ptr().as_ptr() as usize;
            record(address, object.size_bytes(), visited.contains(&address));
        }
        for object in self.flat_closures.iter() {
            let address = object.ptr().as_ptr() as usize;
            record(address, object.size_bytes(), visited.contains(&address));
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            record(address, bytes, visited.contains(&address));
        }
        #[cfg(feature = "candidate_c_value")]
        {
            let mut scalar_regions = Vec::new();
            self.compressed_scalars
                .append_cell_regions(0, &mut scalar_regions);
            for (address, bytes) in scalar_regions {
                // Boxed scalar cells are not yet part of the precise marker.
                // Pin their pages rather than overstating reclaimability.
                record(address, bytes, true);
            }
        }
        (total_pages.len() as u64, live_pages.len() as u64)
    }

    /// Emits allocation-capacity ownership counts for the serial flat heap.
    pub(crate) fn emit_storage_census(&self) {
        let (list_elements, list_capacity) =
            self.flat_lists
                .iter()
                .fold((0usize, 0usize), |(len, capacity), entry| {
                    let list = entry.object().payload();
                    (
                        len.saturating_add(list.len()),
                        capacity.saturating_add(list.capacity()),
                    )
                });
        let string_cons = self.string_cons.storage_counts();
        let path_cons = self.path_cons.storage_counts();
        let list_cons = self.list_cons.storage_counts();
        let attrs_cons = self.attrs_cons.storage_counts();
        eprintln!(
            "aos_nix_storage_census {{\
\"flat\":[{},{}],\"lists\":[{},{}],\"attrs\":[{},{}],\
\"closures\":[{},{}],\"typed_heads\":[{},{}],\
\"list_elements\":[{list_elements},{list_capacity}],\
\"string_cons\":[{},{},{},{}],\"path_cons\":[{},{},{},{}],\
\"list_cons\":[{},{},{},{}],\"attrs_cons\":[{},{},{},{}]\
}}",
            self.flat.len(),
            self.flat.registry_capacity(),
            self.flat_lists.len(),
            self.flat_lists.registry_capacity(),
            self.flat_attrs.len(),
            self.flat_attrs.registry_capacity(),
            self.flat_closures.len(),
            self.flat_closures.registry_capacity(),
            self.typed_thunk_heads.len(),
            self.typed_thunk_heads.capacity(),
            string_cons.0,
            string_cons.1,
            string_cons.2,
            string_cons.3,
            path_cons.0,
            path_cons.1,
            path_cons.2,
            path_cons.3,
            list_cons.0,
            list_cons.1,
            list_cons.2,
            list_cons.3,
            attrs_cons.0,
            attrs_cons.1,
            attrs_cons.2,
            attrs_cons.3,
        );
    }

    /// Tallies this forced heap's accepted and refused object mass by kind.
    ///
    /// Walks every flat store without mutating the heap: `flat` (strings/paths),
    /// `flat_attrs`, and `flat_lists` are the accepted data; `flat_closures` is
    /// the refused closure mass, split into suspended thunks, in-flight thunks,
    /// lambdas, primops, and retired slots; `record_count()` reports the refused
    /// record-table objects. Also collects the distinct code modules referenced
    /// by live closures and how many capture a lexical environment.
    ///
    /// This is the RFC-0007 doc 31 §1 feasibility probe: the numbers decide
    /// whether the next snapshot increment is closure serialization, a
    /// force-then-collapse hybrid, or a re-scope.
    pub(crate) fn refusal_census(&self) -> RefusalCensus {
        let mut census = RefusalCensus {
            records: self.record_count() as u64,
            ..RefusalCensus::default()
        };

        for object in self.flat.iter() {
            census.strings_and_paths.add(object.size_bytes());
        }
        for object in self.flat_attrs.iter() {
            census.attrs.add(object.size_bytes());
        }
        for object in self.flat_lists.iter() {
            census.lists.add(object.size_bytes());
        }

        let mut modules: HashSet<EvalModuleId> = HashSet::new();
        for object in self.flat_closures.iter() {
            let size = object.size_bytes();
            match object.object().payload() {
                // Owned and `Arc`-shared thunks classify identically (deref
                // coercion turns `&Arc<EvalThunk>` into `&EvalThunk`).
                FlatClosurePayload::Thunk(thunk) => {
                    census.classify_thunk(thunk, size, &mut modules)
                }
                FlatClosurePayload::SharedThunk(thunk) => {
                    census.classify_thunk(thunk, size, &mut modules)
                }
                FlatClosurePayload::Lambda(lambda) => {
                    census.lambdas.add(size);
                    modules.insert(lambda.module());
                    census.closures_capturing_env += 1;
                }
                FlatClosurePayload::Primop(primop) => {
                    census.primops.add(size);
                    // A primop is a builtin plus already-applied argument slots;
                    // each captured arg carries the module it was lowered in.
                    for arg in primop.args() {
                        modules.insert(arg.module());
                    }
                }
                FlatClosurePayload::Retired(_) => census.retired_closures.add(size),
            }
        }
        census.distinct_code_modules = modules.len() as u64;

        // Size the captured-environment frame DAG (step-3 stop condition): walk
        // every closure's env, deduplicating frames by `Arc` identity so shared
        // parents count once.
        let mut seen_frames: HashSet<*const EvalFrame> = HashSet::new();
        for object in self.flat_closures.iter() {
            let env = match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => thunk.env(),
                FlatClosurePayload::SharedThunk(thunk) => thunk.env(),
                FlatClosurePayload::Lambda(lambda) => Some(lambda.env()),
                FlatClosurePayload::Primop(_) | FlatClosurePayload::Retired(_) => None,
            };
            if let Some(env) = env {
                for frame in env.frames().iter() {
                    census.env_frame_refs += 1;
                    if seen_frames.insert(Arc::as_ptr(frame)) {
                        census.env_distinct_frames += 1;
                        if let Ok(values) = frame.slot_values() {
                            census.env_total_slots += values.len() as u64;
                        }
                    }
                }
            }
        }
        census
    }
}

/// Marks every page overlapped by one allocation extent.
fn mark_extent_pages(pages: &mut HashSet<usize>, address: usize, bytes: usize, page_bytes: usize) {
    if bytes == 0 {
        return;
    }
    let first = address / page_bytes;
    let last = address.saturating_add(bytes.saturating_sub(1)) / page_bytes;
    pages.extend(first..=last);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "lifetime_cohort_probe")]
    #[test]
    fn lifetime_shadow_classifies_untouched_candidate_as_cold() {
        let mut heap = EvalHeap::new();
        heap.set_epoch_tracking_enabled(true);
        let value = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("candidate list allocates");
        let roots = EvalRootSet::new();
        let first = heap
            .lifetime_cohort_census(&roots, &[])
            .expect("first shadow snapshot succeeds");
        let candidate = first
            .unreachable_candidates
            .iter()
            .find(|candidate| {
                value
                    .as_heap_ptr()
                    .is_ok_and(|ptr| ptr.as_ptr() as usize == candidate.address)
            })
            .copied()
            .expect("list candidate is inventoried");

        let later = heap
            .lifetime_cohort_census(&roots, &[candidate])
            .expect("later shadow snapshot succeeds");

        assert_eq!(
            later.prior_observations,
            vec![LifetimeCohortCandidateObservation::Cold]
        );
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    #[test]
    fn lifetime_shadow_detects_touch_without_later_root() {
        let mut heap = EvalHeap::new();
        heap.set_epoch_tracking_enabled(true);
        let value = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("candidate list allocates");
        let roots = EvalRootSet::new();
        let first = heap
            .lifetime_cohort_census(&roots, &[])
            .expect("first shadow snapshot succeeds");
        let candidate = first.unreachable_candidates[0];
        heap.get_list(value)
            .expect("candidate resolution stamps its touch epoch");

        let later = heap
            .lifetime_cohort_census(&roots, &[candidate])
            .expect("later shadow snapshot succeeds");

        assert_eq!(
            later.prior_observations,
            vec![LifetimeCohortCandidateObservation::Touched]
        );
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    #[test]
    fn lifetime_shadow_detects_candidate_resurrection() {
        let mut heap = EvalHeap::new();
        heap.set_epoch_tracking_enabled(true);
        let value = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("candidate list allocates");
        let empty_roots = EvalRootSet::new();
        let first = heap
            .lifetime_cohort_census(&empty_roots, &[])
            .expect("first shadow snapshot succeeds");
        let candidate = first.unreachable_candidates[0];
        let mut later_roots = EvalRootSet::new();
        later_roots
            .try_push_value_stack(0, value)
            .expect("later root records");

        let later = heap
            .lifetime_cohort_census(&later_roots, &[candidate])
            .expect("later shadow snapshot succeeds");

        assert_eq!(
            later.prior_observations,
            vec![LifetimeCohortCandidateObservation::Resurrected]
        );
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    #[test]
    fn lifetime_shadow_detects_changed_storage_identity() {
        let mut heap = EvalHeap::new();
        heap.set_epoch_tracking_enabled(true);
        let _value = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("candidate list allocates");
        let roots = EvalRootSet::new();
        let first = heap
            .lifetime_cohort_census(&roots, &[])
            .expect("first shadow snapshot succeeds");
        let mut candidate = first.unreachable_candidates[0];
        candidate.kind = LifetimeCohortCandidateKind::Attrs;

        let later = heap
            .lifetime_cohort_census(&roots, &[candidate])
            .expect("later shadow snapshot succeeds");

        assert_eq!(
            later.prior_observations,
            vec![LifetimeCohortCandidateObservation::VanishedOrReused]
        );
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    #[test]
    fn lifetime_shadow_pins_typed_heads_without_epochs() {
        let mut heap = EvalHeap::new();
        heap.enable_typed_apply_thunk_heads();
        let function = heap
            .alloc_string(NixString::from_bytes(b"function".to_vec()))
            .expect("function allocates");
        let argument = heap
            .alloc_string(NixString::from_bytes(b"argument".to_vec()))
            .expect("argument allocates");
        let typed = heap
            .try_typed_alloc_thunk(EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(1),
                Span::new(2, 3),
                function,
                EvalModuleId::ROOT,
                IrId::new(4),
                argument,
            ))
            .expect("typed allocation succeeds")
            .expect("plain apply thunk uses a typed head");
        let roots = EvalRootSet::new();
        let first = heap
            .lifetime_cohort_census(&roots, &[])
            .expect("first shadow snapshot succeeds");
        let address = typed
            .as_heap_ptr()
            .expect("typed thunk has a heap address")
            .as_ptr() as usize;
        let candidate = first
            .unreachable_candidates
            .iter()
            .find(|candidate| candidate.address == address)
            .copied()
            .expect("typed head is inventoried");
        assert_eq!(candidate.initial_touch_epoch, None);

        let later = heap
            .lifetime_cohort_census(&roots, &[candidate])
            .expect("later shadow snapshot succeeds");

        assert_eq!(
            later.prior_observations,
            vec![LifetimeCohortCandidateObservation::NoEpoch]
        );
    }

    #[cfg(feature = "lifetime_cohort_probe")]
    #[test]
    fn lifetime_shadow_inventory_exactly_reconciles_unreachable_bytes() {
        let mut heap = EvalHeap::new();
        let _list = heap
            .alloc_list(NixList::new(vec![Value::int(1), Value::int(2)]))
            .expect("candidate list allocates");
        let _string = heap
            .alloc_string(NixString::from_bytes(b"candidate".to_vec()))
            .expect("candidate string allocates");
        let snapshot = heap
            .lifetime_cohort_census(&EvalRootSet::new(), &[])
            .expect("shadow snapshot succeeds");
        let inventory_bytes = snapshot
            .unreachable_candidates
            .iter()
            .fold(0_u64, |total, candidate| {
                total.saturating_add(candidate.attributable_bytes())
            });

        assert_eq!(
            snapshot.unreachable_candidates.len() as u64,
            snapshot.census.unreachable.objects
        );
        assert_eq!(inventory_bytes, snapshot.census.unreachable.total_bytes());
    }

    #[test]
    fn weak_liveness_does_not_promote_hash_cons_entries_to_roots() {
        let mut heap = EvalHeap::new();
        let reachable = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("reachable list allocates");
        let _unreachable = heap
            .alloc_list(NixList::new(vec![Value::int(2)]))
            .expect("unreachable list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, reachable)
            .expect("root storage grows");

        let census = heap
            .weak_liveness_census(&roots)
            .expect("weak liveness traverses the rooted list");

        assert_eq!(census.lists.count, 1);
        assert_eq!(census.total.lists.count, 2);
        assert_eq!(census.reachable_objects, 1);
    }

    #[test]
    fn import_epoch_census_splits_suffix_survivors_without_mutation() {
        let mut heap = EvalHeap::new();
        let _before_fence = heap
            .alloc_list(NixList::new(vec![Value::int(0)]))
            .expect("pre-fence list allocates");
        let fence = heap
            .import_epoch_census_fence(1, 1)
            .expect("serial heap exposes a fence");
        let reachable = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("reachable cohort list allocates");
        let _unreachable = heap
            .alloc_list(NixList::new(vec![Value::int(2)]))
            .expect("unreachable cohort list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, reachable)
            .expect("root storage grows");

        let before_len = heap.len();
        let census = heap
            .import_epoch_census(fence, &roots)
            .expect("import cohort scan succeeds");

        assert!(census.fence_valid);
        assert_eq!(census.lists.cohort.count, 2);
        assert_eq!(census.lists.reachable.count, 1);
        assert_eq!(census.lists.unreachable().count, 1);
        assert!(census.list_spine_cohort_bytes >= census.list_spine_reachable_bytes);
        assert_eq!(heap.len(), before_len, "the projection must not reclaim");
    }

    #[test]
    fn nested_import_fences_intentionally_report_overlapping_cohorts() {
        let mut heap = EvalHeap::new();
        let outer = heap
            .import_epoch_census_fence(1, 1)
            .expect("serial heap exposes an outer fence");
        let outer_value = heap
            .alloc_list(NixList::new(vec![Value::int(1)]))
            .expect("outer cohort list allocates");
        let inner = heap
            .import_epoch_census_fence(2, 2)
            .expect("serial heap exposes an inner fence");
        let inner_value = heap
            .alloc_list(NixList::new(vec![Value::int(2)]))
            .expect("inner cohort list allocates");
        let mut roots = EvalRootSet::new();
        roots
            .try_push_value_stack(0, outer_value)
            .expect("outer root storage grows");
        roots
            .try_push_value_stack(1, inner_value)
            .expect("inner root storage grows");

        let outer_census = heap
            .import_epoch_census(outer, &roots)
            .expect("outer cohort scan succeeds");
        let inner_census = heap
            .import_epoch_census(inner, &roots)
            .expect("inner cohort scan succeeds");

        assert_eq!(outer_census.lists.cohort.count, 2);
        assert_eq!(inner_census.lists.cohort.count, 1);
    }

    #[test]
    fn extent_page_projection_includes_both_boundary_pages() {
        let mut pages = HashSet::new();
        mark_extent_pages(&mut pages, 8190, 4, 4096);

        assert_eq!(pages, HashSet::from([1, 2]));
    }
}
