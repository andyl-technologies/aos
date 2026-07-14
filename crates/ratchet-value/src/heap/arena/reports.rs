//! Arena report and accounting types: allocation records, usage statistics,
//! region marks and pop reports, and memory-advice reports. Moved verbatim
//! from `arena.rs` under the RFC-0007 §2 file-size cap; the parent re-exports
//! every public path.

use super::*;

/// The logical heap object kind requested through an allocation entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapObjectKind {
    /// A suspended thunk object.
    Thunk,
    /// A user lambda closure object.
    Lambda,
    /// An attribute set with `slots` value cells.
    Attrs {
        /// The hidden-class shape id associated with the attrset.
        shape: u32,
        /// The number of value slots requested.
        slots: u32,
    },
    /// A list cons cell.
    Cons,
    /// A contiguous list spine with `len` elements.
    List {
        /// The number of value cells requested.
        len: u32,
    },
    /// A byte string payload with `len` bytes.
    String {
        /// The byte length requested for the string payload.
        len: usize,
    },
    /// A raw allocation for a future concrete runtime type.
    Raw {
        /// Runtime-specific type tag carried for diagnostics and future GC
        /// layout selection.
        type_tag: u32,
    },
}

/// One allocation returned by the bump arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaAllocation {
    /// The opaque heap-object address reserved for this allocation.
    pub ptr: std::ptr::NonNull<HeapObject>,
    /// The logical object kind requested by the caller.
    pub kind: HeapObjectKind,
    /// The caller-requested payload size in bytes.
    pub requested_size: usize,
    /// The actual bump distance in bytes after alignment and word rounding.
    pub reserved_size: usize,
    /// The requested alignment in bytes.
    pub align: usize,
}

/// Current bump-arena accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArenaStats {
    /// Number of chunks currently owned by the arena.
    pub chunks: usize,
    /// Logical bytes reserved by all chunks for bump allocation.
    pub reserved_bytes: usize,
    /// Page-rounded bytes mapped from the host OS.
    pub mapped_bytes: usize,
    /// Number of bytes consumed by allocations, including alignment padding and
    /// word rounding.
    pub used_bytes: usize,
}

impl ArenaStats {
    /// Returns the field-wise saturating sum of `self` and `other`.
    ///
    /// Used to fold multiple arenas of one allocation domain into a single
    /// accounting view (for example the worker allocator's arena plus the
    /// flat closure store's).
    pub fn merged(self, other: Self) -> Self {
        Self {
            chunks: self.chunks.saturating_add(other.chunks),
            reserved_bytes: self.reserved_bytes.saturating_add(other.reserved_bytes),
            mapped_bytes: self.mapped_bytes.saturating_add(other.mapped_bytes),
            used_bytes: self.used_bytes.saturating_add(other.used_bytes),
        }
    }
}

/// A LIFO marker for a future lexical allocation subregion.
///
/// Markers are produced by [`BumpArena::region_mark`] and can be passed back to
/// [`BumpArena::pop_caller_validated_region_to_mark`] once the caller has
/// proven that every allocation above the marker is dead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaRegionMark {
    // Fields are `pub(super)`: the parent's `BumpArena` region push/pop
    // methods construct and consume markers directly (the pre-split private
    // access, made module-explicit by the §2 relocation).
    pub(super) chunk_count: usize,
    pub(super) cursor: usize,
    pub(super) next_chunk_bytes: usize,
}

impl ArenaRegionMark {
    /// Returns the number of chunks present when the marker was captured.
    pub const fn chunk_count(self) -> usize {
        self.chunk_count
    }

    /// Returns the bump cursor in the last retained chunk.
    pub const fn cursor(self) -> usize {
        self.cursor
    }
}

/// Accounting returned after popping a lexical allocation subregion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaRegionPopReport {
    before: ArenaStats,
    after: ArenaStats,
    used_bytes_released: usize,
    released_mapped_bytes: usize,
    dead_range_bytes: usize,
    dead_range_outcome: MemoryAdviceOutcome,
}

impl ArenaRegionPopReport {
    pub(crate) const fn new(
        before: ArenaStats,
        after: ArenaStats,
        released_mapped_bytes: usize,
        dead_range_bytes: usize,
        dead_range_outcome: MemoryAdviceOutcome,
    ) -> Self {
        Self {
            before,
            after,
            used_bytes_released: before.used_bytes.saturating_sub(after.used_bytes),
            released_mapped_bytes,
            dead_range_bytes,
            dead_range_outcome,
        }
    }

    /// Returns arena accounting before the region pop.
    pub const fn before_stats(self) -> ArenaStats {
        self.before
    }

    /// Returns arena accounting after the region pop.
    pub const fn after_stats(self) -> ArenaStats {
        self.after
    }

    /// Returns used bytes made unavailable by cursor rewind or chunk release.
    pub const fn used_bytes_released(self) -> usize {
        self.used_bytes_released
    }

    /// Returns mapped bytes released by dropping whole chunks above the marker.
    pub const fn released_mapped_bytes(self) -> usize {
        self.released_mapped_bytes
    }

    /// Returns retained-chunk bytes made dead by rewinding the bump cursor.
    pub const fn dead_range_bytes(self) -> usize {
        self.dead_range_bytes
    }

    /// Returns the advisory outcome for the retained-chunk dead range.
    pub const fn dead_range_outcome(self) -> MemoryAdviceOutcome {
        self.dead_range_outcome
    }

    /// Merges two pop reports into one whole-domain accounting view.
    ///
    /// Used when one logical region pop rewinds more than one arena (doc 30
    /// FV-3: the worker allocator's arena plus the flat closure store's).
    /// Stats and byte counters add field-wise; the dead-range advisory
    /// outcome keeps whichever side actually advised a non-empty range,
    /// preferring `self` when both did (the composite outcome is
    /// diagnostics-only).
    pub fn merged(self, other: Self) -> Self {
        let dead_range_outcome = if self.dead_range_bytes != 0 || other.dead_range_bytes == 0 {
            self.dead_range_outcome
        } else {
            other.dead_range_outcome
        };
        Self {
            before: self.before.merged(other.before),
            after: self.after.merged(other.after),
            used_bytes_released: self
                .used_bytes_released
                .saturating_add(other.used_bytes_released),
            released_mapped_bytes: self
                .released_mapped_bytes
                .saturating_add(other.released_mapped_bytes),
            dead_range_bytes: self.dead_range_bytes.saturating_add(other.dead_range_bytes),
            dead_range_outcome,
        }
    }
}

/// Summary of memory advice applied to one bump arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaMemoryAdviceReport {
    kind: MemoryAdviceKind,
    chunks: usize,
    requested_bytes: usize,
    applied: usize,
    unsupported: usize,
    empty: usize,
    rejected: usize,
}

impl ArenaMemoryAdviceReport {
    /// Creates a report of `kind` describing no advised chunks.
    ///
    /// Merge-identity for accounting paths that must contribute nothing (for
    /// example flat stores on a shared arena, whose tail advice is issued
    /// once through the shared handle).
    pub const fn empty(kind: MemoryAdviceKind) -> Self {
        Self::for_kind(kind)
    }

    // `pub(super)`: constructed by the parent's chunk-advice walk.
    pub(super) const fn for_kind(kind: MemoryAdviceKind) -> Self {
        Self {
            kind,
            chunks: 0,
            requested_bytes: 0,
            applied: 0,
            unsupported: 0,
            empty: 0,
            rejected: 0,
        }
    }

    // `pub(super)`: fed by the parent's chunk-advice walk.
    pub(super) fn record(&mut self, requested_bytes: usize, outcome: MemoryAdviceOutcome) {
        self.chunks = self.chunks.saturating_add(1);
        self.requested_bytes = self.requested_bytes.saturating_add(requested_bytes);
        match outcome {
            MemoryAdviceOutcome::Applied { .. } => {
                self.applied = self.applied.saturating_add(1);
            }
            MemoryAdviceOutcome::Unsupported { .. } => {
                self.unsupported = self.unsupported.saturating_add(1);
            }
            MemoryAdviceOutcome::EmptyRange { .. } => {
                self.empty = self.empty.saturating_add(1);
            }
            MemoryAdviceOutcome::Rejected { .. } => {
                self.rejected = self.rejected.saturating_add(1);
            }
        }
    }

    /// Returns the field-wise sum of two advice reports.
    ///
    /// Used when one logical allocation domain spans more than one arena
    /// (the evaluator's permanent domain plus the flat-object store). Keeps
    /// `self`'s advice kind; callers pass reports produced for the same kind.
    pub fn merged(self, other: Self) -> Self {
        Self {
            kind: self.kind,
            chunks: self.chunks.saturating_add(other.chunks),
            requested_bytes: self.requested_bytes.saturating_add(other.requested_bytes),
            applied: self.applied.saturating_add(other.applied),
            unsupported: self.unsupported.saturating_add(other.unsupported),
            empty: self.empty.saturating_add(other.empty),
            rejected: self.rejected.saturating_add(other.rejected),
        }
    }

    /// Returns the advice kind requested for every chunk tail.
    pub const fn kind(self) -> MemoryAdviceKind {
        self.kind
    }

    /// Returns how many arena chunks were considered.
    pub const fn chunks(self) -> usize {
        self.chunks
    }

    /// Returns the total unused-tail bytes passed to the advice shim.
    pub const fn requested_bytes(self) -> usize {
        self.requested_bytes
    }

    /// Returns how many chunk-tail advice calls the operating system accepted.
    pub const fn applied(self) -> usize {
        self.applied
    }

    /// Returns how many chunk-tail advice calls had no platform lowering.
    pub const fn unsupported(self) -> usize {
        self.unsupported
    }

    /// Returns how many chunk tails contained no complete page to advise.
    pub const fn empty_ranges(self) -> usize {
        self.empty
    }

    /// Returns how many chunk-tail advice calls the platform rejected.
    pub const fn rejected(self) -> usize {
        self.rejected
    }
}
