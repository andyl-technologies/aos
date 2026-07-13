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
            writeln!(f, "  {label:<22} count={:>8}  inline_bytes={:>12}", t.count, t.inline_bytes)
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
        writeln!(f, "forced-thunk collapse projection (targets, no mutation):")?;
        writeln!(f, "  -> heap data           {}", self.forced_holds_heap_data)?;
        writeln!(f, "  -> inline scalar       {}", self.forced_holds_inline_scalar)?;
        writeln!(f, "  -> lambda              {}", self.forced_holds_lambda)?;
        writeln!(f, "  -> primop              {}", self.forced_holds_primop)?;
        writeln!(f, "  -> thunk (chain)       {}", self.forced_holds_thunk)?;
        writeln!(f, "  -> unknown/absent      {}", self.forced_holds_unknown)?;
        writeln!(
            f,
            "projected residual after collapse   count={:>8}  inline_bytes={:>12}",
            self.projected_residual_refused_count(),
            self.projected_residual_refused_bytes()
        )
    }
}

impl EvalHeap {
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
        census
    }
}
