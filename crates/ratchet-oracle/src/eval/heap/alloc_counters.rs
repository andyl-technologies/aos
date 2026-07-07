//! Heap allocation work counters for the tree-walk evaluator.
//!
//! [`EvalHeap`](super::EvalHeap) tallies the volume of typed-value allocation
//! it performs so a native evaluation can be compared, work-for-work, against
//! C++ Nix's `NIX_SHOW_STATS` output (`nrValues`, `nrAttrsets`,
//! `nrAttrsInAttrsets`). The counters are plain monotonic `u64`s bumped at the
//! natural chokepoints in [`super::arena`]; reading them is a cheap `Copy`.
//!
//! Hash-consing means a native heap allocates fewer records than C++ Nix for
//! the same program: a construction request whose structural hash already names
//! a canonical value reuses it instead of pushing a new record. The counters
//! separate the two so the comparison stays honest:
//!
//! * [`EvalHeapAllocationCounters::attrsets_built`] counts every attribute-set
//!   construction *request* (the analog of `nrAttrsets`), including the ones a
//!   hash-cons hit later satisfies without allocating.
//! * [`EvalHeapAllocationCounters::values_allocated`] counts only heap records
//!   actually pushed, so it is the dedup-reduced record count.
//! * [`EvalHeapAllocationCounters::hashcons_hits`] over
//!   [`EvalHeapAllocationCounters::hashcons_attempts`] is the reuse rate that
//!   explains the gap between the two.

/// Monotonic counters describing typed-value allocation performed by one heap.
///
/// Every field is a running total for the lifetime of the owning
/// [`EvalHeap`](super::EvalHeap); the counters never decrease and are snapshot
/// by value into the evaluator's public statistics at the end of an evaluation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvalHeapAllocationCounters {
    /// Heap records actually pushed across all typed-value kinds.
    ///
    /// Counts string, path, list, attribute-set, lambda, builtin, and thunk
    /// allocations that materialize a new record. Hash-cons reuse and
    /// GC-internal placeholder records are excluded, so this is the heap's
    /// dedup-reduced analog of C++ Nix's `nrValues` restricted to boxed values.
    pub(crate) values_allocated: u64,
    /// Attribute-set construction requests, including hash-cons hits.
    ///
    /// The analog of C++ Nix's `nrAttrsets`: one per `alloc_attrs*` call,
    /// whether or not a canonical value already existed.
    pub(crate) attrsets_built: u64,
    /// Total attribute entries summed over every attribute-set request.
    ///
    /// The analog of C++ Nix's `nrAttrsInAttrsets`.
    pub(crate) attrs_entries_total: u64,
    /// Structural-hash lookups performed against the hash-cons tables.
    ///
    /// Counts every string, path, list, and attribute-set construction request
    /// that consulted a hash-cons table before allocating.
    pub(crate) hashcons_attempts: u64,
    /// Hash-cons lookups that reused an existing canonical value.
    ///
    /// The difference from [`Self::hashcons_attempts`] is the number of records
    /// that had to be freshly allocated.
    pub(crate) hashcons_hits: u64,
}

impl EvalHeapAllocationCounters {
    /// Records that one typed-value heap record was pushed.
    pub(crate) fn note_value_allocated(&mut self) {
        self.values_allocated = self.values_allocated.saturating_add(1);
    }

    /// Records an attribute-set construction request over `entries` entries.
    pub(crate) fn note_attrs_built(&mut self, entries: usize) {
        self.attrsets_built = self.attrsets_built.saturating_add(1);
        self.attrs_entries_total = self.attrs_entries_total.saturating_add(entries as u64);
    }

    /// Records a hash-cons lookup, noting whether it reused a canonical value.
    pub(crate) fn note_hashcons(&mut self, hit: bool) {
        self.hashcons_attempts = self.hashcons_attempts.saturating_add(1);
        if hit {
            self.hashcons_hits = self.hashcons_hits.saturating_add(1);
        }
    }

    /// Returns heap records actually pushed across all typed-value kinds.
    pub(crate) const fn values_allocated(&self) -> u64 {
        self.values_allocated
    }

    /// Returns attribute-set construction requests, including hash-cons hits.
    pub(crate) const fn attrsets_built(&self) -> u64 {
        self.attrsets_built
    }

    /// Returns total attribute entries summed over every attribute-set request.
    pub(crate) const fn attrs_entries_total(&self) -> u64 {
        self.attrs_entries_total
    }

    /// Returns structural-hash lookups performed against the hash-cons tables.
    pub(crate) const fn hashcons_attempts(&self) -> u64 {
        self.hashcons_attempts
    }

    /// Returns hash-cons lookups that reused an existing canonical value.
    pub(crate) const fn hashcons_hits(&self) -> u64 {
        self.hashcons_hits
    }
}
