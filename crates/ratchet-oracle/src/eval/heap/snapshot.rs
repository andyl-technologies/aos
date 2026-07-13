//! Evaluator-heap serialize-and-patch snapshot (RFC-0007 doc 31 §1, stage B /
//! §9 decision 6).
//!
//! Layers the `EvalHeap` over the reservation-level round-trip in
//! [`ratchet_value::heap::snapshot`]. Compound flat objects keep their absolute
//! interior pointers (`FlatBytes`/`FlatSlice`) — zero hot-path cost — so their
//! run bytes ride along in the dumped arena but their witness pointer words are
//! stale after a remap. [`EvalHeap::capture_heap_image`] records those objects
//! in the image's relocation table; [`EvalHeap::from_restored_heap_image`]
//! resolves each and shifts its witnesses by `new_base − old_base`.
//!
//! # Scope (increment 2)
//!
//! Strings, paths, and attrsets are handled. Lists (an owned out-of-arena `Vec`)
//! and `Arc`-backed string contexts are refused at capture and land in later
//! increments (list-payload segment; the §1.4 stage-2 context residual).
//!
//! # Completeness audit (`AOS_NIX_SNAPSHOT_VERIFY`)
//!
//! Delta-rebase correctness rests on the relocation table covering every
//! interior pointer. Under the verify flag, capture independently scans the
//! dumped lanes for any 8-byte-aligned word whose value lands in the reservation
//! and is not inside a relocation object or a boxed-scalar cell — a suspected
//! uncovered witness — and fails capture, converting store-enumeration
//! completeness into a checked invariant (doc 31 §9 decision 6).

use thiserror::Error;

use ratchet_value::heap::{
    ArenaIndex, HeapImage, RelocationEntry, SnapshotError, capture_reservation, reservation_base,
    restore_reservation,
};

use super::*;

/// Environment flag enabling the capture-time relocation completeness audit.
const SNAPSHOT_VERIFY_ENV: &str = "AOS_NIX_SNAPSHOT_VERIFY";

impl EvalHeap {
    /// Captures a serialize-and-patch heap image of this heap's serial flat arena.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError`] for a parallel heap, a heap holding a
    /// kind not yet snapshottable (worker closures, lists, record-table objects,
    /// or a flat string with a non-empty context), a reservation that is not
    /// address-free, or a failed completeness audit.
    pub fn capture_heap_image(&self) -> Result<HeapImage, EvalHeapSnapshotError> {
        if self.shared.is_some() {
            return Err(EvalHeapSnapshotError::ParallelMode);
        }
        let closures = self.flat_closures.len();
        if closures != 0 {
            return Err(EvalHeapSnapshotError::UnsnapshottableClosures { count: closures });
        }
        let lists = self.flat_lists.len();
        if lists != 0 {
            return Err(EvalHeapSnapshotError::UnsnapshottableLists { count: lists });
        }
        let records = self.record_count();
        if records != 0 {
            return Err(EvalHeapSnapshotError::UnsnapshottableRecords { count: records });
        }

        let mut relocations = Vec::new();
        for object in self.flat.iter() {
            if !object.object().payload().context().is_empty() {
                return Err(EvalHeapSnapshotError::UnsnapshottableStringContext);
            }
            relocations.push(self.relocation_entry_for(object.ptr(), object.object().kind())?);
        }
        for object in self.flat_attrs.iter() {
            relocations.push(self.relocation_entry_for(object.ptr(), FlatObjectKind::Attrs)?);
        }

        let mut image =
            capture_reservation(&self.flat_arena).map_err(EvalHeapSnapshotError::Snapshot)?;
        image.relocations = relocations;

        if std::env::var_os(SNAPSHOT_VERIFY_ENV).is_some() {
            self.verify_relocation_completeness(&image)?;
        }
        Ok(image)
    }

    /// Builds one relocation entry for the flat object at `ptr` of kind `kind`.
    fn relocation_entry_for(
        &self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<RelocationEntry, EvalHeapSnapshotError> {
        let index = self
            .flat_arena
            .index_for_pointer(ptr)
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        Ok(RelocationEntry {
            index: index.raw(),
            kind: kind as u8,
        })
    }

    /// Restores a fresh evaluator heap from a serialize-and-patch heap image.
    ///
    /// Maps the image into a new reservation (original domain preserved),
    /// assembles the flat stores, primes their membership indexes, and rebases
    /// every relocation object's interior witnesses by `new_base − old_base`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::Snapshot`] when the image is malformed or
    /// its domain is still live, [`EvalHeapSnapshotError::ObjectOutsideReservation`]
    /// when a relocation index does not resolve, [`EvalHeapSnapshotError::UnknownKind`]
    /// for an unrecognized relocation kind, and [`EvalHeapSnapshotError::FlatResolve`]
    /// when a recorded object cannot be resolved for rebasing.
    pub fn from_restored_heap_image(image: &HeapImage) -> Result<Self, EvalHeapSnapshotError> {
        let arena = restore_reservation(image).map_err(EvalHeapSnapshotError::Snapshot)?;
        let new_base = arena
            .arena_domain_id()
            .and_then(reservation_base)
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let delta = new_base as isize - image.old_base as isize;

        let mut heap = Self::assemble_over_arena(arena, RuntimeAllocator::tier_a_one_shot());
        heap.adopt_restored_regions();

        for entry in &image.relocations {
            let ptr = heap
                .flat_arena
                .pointer_for_index(ArenaIndex::new(entry.index))
                .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
            match kind_from_byte(entry.kind)? {
                kind @ (FlatObjectKind::String | FlatObjectKind::Path) => heap
                    .flat
                    .resolve_mut(ptr, kind)
                    .map_err(EvalHeapSnapshotError::FlatResolve)?
                    .rebase_witnesses(delta),
                FlatObjectKind::Attrs => heap
                    .flat_attrs
                    .resolve_mut(ptr, FlatObjectKind::Attrs)
                    .map_err(EvalHeapSnapshotError::FlatResolve)?
                    .attrs
                    .rebase_witnesses(delta),
                kind => return Err(EvalHeapSnapshotError::UnknownKind { kind: kind as u8 }),
            }
        }
        Ok(heap)
    }

    /// Primes each flat store's membership index over the restored arena.
    fn adopt_restored_regions(&mut self) {
        self.flat.adopt_shared_regions();
        self.flat_lists.adopt_shared_regions();
        self.flat_attrs.adopt_shared_regions();
        self.compressed_scalars.adopt_reloaded_regions();
    }

    /// Fails if any suspected interior pointer in the dumped lanes is not covered
    /// by a relocation object or a boxed-scalar cell (doc 31 §9 decision 6).
    ///
    /// Run automatically by [`EvalHeap::capture_heap_image`] under the
    /// `AOS_NIX_SNAPSHOT_VERIFY` flag; exposed for direct verification in tests.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::UncoveredInteriorPointer`] for a suspected
    /// witness outside every covered range, or
    /// [`EvalHeapSnapshotError::ObjectOutsideReservation`] for an object pointer
    /// below the reservation base.
    pub(crate) fn verify_relocation_completeness(
        &self,
        image: &HeapImage,
    ) -> Result<(), EvalHeapSnapshotError> {
        let base = image.old_base as usize;
        let capacity = image.capacity as usize;

        // Covered `(offset, size)` byte ranges: every relocation object plus every
        // boxed-scalar cell (known non-pointer data).
        let mut covered: Vec<(usize, usize)> = Vec::new();
        for object in self.flat.iter() {
            covered.push((self.offset_of(object.ptr(), base)?, object.size_bytes()));
        }
        for object in self.flat_attrs.iter() {
            covered.push((self.offset_of(object.ptr(), base)?, object.size_bytes()));
        }
        self.compressed_scalars
            .append_cell_regions(base, &mut covered);
        covered.sort_unstable();

        let high_start = capacity.saturating_sub(image.high.len());
        for (lane, lane_offset) in [(&image.low, 0usize), (&image.high, high_start)] {
            let mut offset = 0;
            while offset + 8 <= lane.len() {
                let mut word = [0u8; 8];
                word.copy_from_slice(&lane[offset..offset + 8]);
                let value = u64::from_le_bytes(word) as usize;
                let arena_offset = lane_offset + offset;
                if value >= base
                    && value < base + capacity
                    && value % 8 == 0
                    && !range_contains(&covered, arena_offset)
                {
                    return Err(EvalHeapSnapshotError::UncoveredInteriorPointer { arena_offset });
                }
                offset += 8;
            }
        }
        Ok(())
    }

    /// Returns `ptr`'s byte offset from the reservation `base`.
    fn offset_of(
        &self,
        ptr: NonNull<HeapObject>,
        base: usize,
    ) -> Result<usize, EvalHeapSnapshotError> {
        (ptr.as_ptr() as usize)
            .checked_sub(base)
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)
    }
}

/// Decodes a relocation-entry kind byte into a [`FlatObjectKind`].
fn kind_from_byte(byte: u8) -> Result<FlatObjectKind, EvalHeapSnapshotError> {
    match byte {
        b if b == FlatObjectKind::String as u8 => Ok(FlatObjectKind::String),
        b if b == FlatObjectKind::Path as u8 => Ok(FlatObjectKind::Path),
        b if b == FlatObjectKind::Attrs as u8 => Ok(FlatObjectKind::Attrs),
        kind => Err(EvalHeapSnapshotError::UnknownKind { kind }),
    }
}

/// Returns whether one of the sorted `(offset, size)` ranges contains `point`.
fn range_contains(ranges: &[(usize, usize)], point: usize) -> bool {
    let position = ranges.partition_point(|&(start, _)| start <= point);
    position
        .checked_sub(1)
        .and_then(|index| ranges.get(index))
        .is_some_and(|&(start, size)| point < start + size)
}

/// A failure capturing or restoring an [`EvalHeap`] serialize-and-patch image.
#[derive(Debug, Error)]
pub enum EvalHeapSnapshotError {
    /// A shared/parallel heap cannot be snapshotted (serial only).
    #[error("cannot snapshot a shared/parallel evaluator heap")]
    ParallelMode,
    /// The arena holds worker closures (thunks/lambdas/primops); their interior
    /// `Arc`s are the stage-2 collapse (doc 31 §3.2).
    #[error("cannot snapshot a heap with {count} live worker closure(s)")]
    UnsnapshottableClosures {
        /// The number of live flat worker-closure objects.
        count: usize,
    },
    /// The arena holds lists, whose owned out-of-arena `Vec` is a later increment.
    #[error("cannot snapshot a heap with {count} live list object(s)")]
    UnsnapshottableLists {
        /// The number of live flat list objects.
        count: usize,
    },
    /// The arena has record-table (non-flat) objects, which are not dumped.
    #[error("cannot snapshot a heap with {count} live record-table object(s)")]
    UnsnapshottableRecords {
        /// The number of live heap-record-table objects.
        count: usize,
    },
    /// A flat string carries an `Arc`-backed context (doc 31 §1.4 stage-2 residual).
    #[error("cannot snapshot a heap with a context-bearing string")]
    UnsnapshottableStringContext,
    /// A flat object's pointer did not lie inside the reservation.
    #[error("flat object is outside the snapshot reservation")]
    ObjectOutsideReservation,
    /// A relocation entry carried an unrecognized kind byte.
    #[error("relocation entry has unknown flat-object kind {kind}")]
    UnknownKind {
        /// The rejected kind byte.
        kind: u8,
    },
    /// A recorded relocation object could not be resolved for rebasing.
    #[error("relocation object resolution failed: {0}")]
    FlatResolve(#[source] ratchet_value::heap::FlatObjectError),
    /// The completeness audit found a suspected uncovered interior pointer.
    #[error(
        "relocation completeness audit: uncovered interior pointer at arena offset {arena_offset}"
    )]
    UncoveredInteriorPointer {
        /// The dumped-lane byte offset of the suspected uncovered witness.
        arena_offset: usize,
    },
    /// The reservation-level capture or restore failed.
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
}
