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
//! # Scope
//!
//! Strings, paths, attrsets, and lists are handled. A list's element `Vec` lives
//! outside the reservation, so capture serializes its address-free element words
//! into a [`ListPayload`] segment and restore rebuilds the `Vec`, overwrites the
//! stale dumped header, and registers the object so the rebuilt buffer drops
//! exactly once. `Arc`-backed string contexts remain refused at capture (the
//! §1.4 stage-2 residual).
//!
//! # Completeness audit (`AOS_NIX_SNAPSHOT_VERIFY`)
//!
//! Delta-rebase correctness rests on the relocation table covering every
//! interior pointer. Under the verify flag, capture independently scans the
//! dumped lanes for any 8-byte-aligned word whose value lands in the reservation
//! and is not inside a relocation object or a boxed-scalar cell — a suspected
//! uncovered witness — and fails capture, converting store-enumeration
//! completeness into a checked invariant (doc 31 §9 decision 6).

use std::collections::HashSet;

use thiserror::Error;

use ratchet_value::heap::{
    ArenaIndex, HeapImage, ListPayload, RelocationEntry, SnapshotError, capture_reservation,
    reservation_base, restore_reservation,
};

use crate::value::Value;
use crate::value::compressed::CompressedValueWord;

use super::*;

/// Byte width of one serialized Candidate-C list element word.
const LIST_ELEMENT_WORD_LEN: usize = 8;

/// Environment flag enabling the capture-time relocation completeness audit.
const SNAPSHOT_VERIFY_ENV: &str = "AOS_NIX_SNAPSHOT_VERIFY";

impl EvalHeap {
    /// Captures a serialize-and-patch heap image of this heap's serial flat arena.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError`] for a parallel heap, a heap holding a
    /// kind not yet snapshottable (worker closures, record-table objects, or a
    /// flat string with a non-empty context), a list object outside the
    /// reservation, a reservation that is not address-free, or a failed
    /// completeness audit.
    pub fn capture_heap_image(&self) -> Result<HeapImage, EvalHeapSnapshotError> {
        if self.shared.is_some() {
            return Err(EvalHeapSnapshotError::ParallelMode);
        }
        let closures = self.flat_closures.len();
        if closures != 0 {
            return Err(EvalHeapSnapshotError::UnsnapshottableClosures { count: closures });
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

        // Each flat list's element `Vec` lives outside the reservation, so the
        // dumped lanes do not carry it. Serialize each list's element words —
        // address-free Candidate-C words that resolve unchanged after restore —
        // into a list-payload segment tagged by the list header's arena index.
        // The closure guard above guarantees no element is an unforced thunk.
        let mut list_payloads = Vec::new();
        for object in self.flat_lists.iter() {
            let index = self
                .flat_arena
                .index_for_pointer(object.ptr())
                .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
            let elements = object.object().payload().as_slice();
            let mut element_bytes = Vec::with_capacity(elements.len() * LIST_ELEMENT_WORD_LEN);
            for value in elements {
                element_bytes.extend_from_slice(&value.word().raw().to_le_bytes());
            }
            list_payloads.push(ListPayload {
                index: index.raw(),
                element_bytes,
            });
        }

        let mut image =
            capture_reservation(&self.flat_arena).map_err(EvalHeapSnapshotError::Snapshot)?;
        image.relocations = relocations;
        image.list_payloads = list_payloads;

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
    /// assembles the flat stores, primes their membership indexes, rebases every
    /// relocation object's interior witnesses by `new_base − old_base`, and
    /// re-attaches each list's out-of-arena element `Vec` from its payload segment.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::Snapshot`] when the image is malformed or
    /// its domain is still live, [`EvalHeapSnapshotError::ObjectOutsideReservation`]
    /// when a relocation or list-payload index does not resolve,
    /// [`EvalHeapSnapshotError::UnknownKind`] for an unrecognized relocation kind,
    /// [`EvalHeapSnapshotError::DuplicateObjectIndex`] when two records name the
    /// same arena object (a malformed image that would otherwise double-rebase a
    /// witness or double-register a list for `Drop`),
    /// [`EvalHeapSnapshotError::MalformedListPayload`] when a list payload's bytes
    /// are not a whole number of valid words, and
    /// [`EvalHeapSnapshotError::FlatResolve`] when a recorded object cannot be
    /// resolved for rebasing or list rewriting.
    pub fn from_restored_heap_image(image: &HeapImage) -> Result<Self, EvalHeapSnapshotError> {
        let arena = restore_reservation(image).map_err(EvalHeapSnapshotError::Snapshot)?;
        let new_base = arena
            .arena_domain_id()
            .and_then(reservation_base)
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let delta = new_base as isize - image.old_base as isize;

        let mut heap = Self::assemble_over_arena(arena, RuntimeAllocator::tier_a_one_shot());
        heap.adopt_restored_regions();

        // Each arena object has exactly one kind, so every relocation and
        // list-payload index must be distinct across both records. Rejecting a
        // repeat closes an untrusted-image hazard: a duplicate relocation index
        // would delta-rebase a witness twice (a doubly-shifted, out-of-arena
        // pointer), and a duplicate list index would register the same object in
        // the store twice, dropping it twice (a double free).
        let mut seen: HashSet<u32> = HashSet::new();

        for entry in &image.relocations {
            if !seen.insert(entry.index) {
                return Err(EvalHeapSnapshotError::DuplicateObjectIndex { index: entry.index });
            }
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

        for payload in &image.list_payloads {
            if !seen.insert(payload.index) {
                return Err(EvalHeapSnapshotError::DuplicateObjectIndex {
                    index: payload.index,
                });
            }
            heap.restore_list_payload(payload)?;
        }
        Ok(heap)
    }

    /// Rebuilds one flat list's element `Vec` from its serialized words and
    /// re-attaches it to the restored list object.
    ///
    /// Decodes the address-free element words, then delegates the in-place
    /// header rewrite and Drop registration to
    /// [`FlatObjectStore::restore_payload`] (the unsafe write lives in
    /// `ratchet-value`, which this `#![forbid(unsafe_code)]` crate cannot host).
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::ObjectOutsideReservation`] when the
    /// payload index does not resolve, [`EvalHeapSnapshotError::MalformedListPayload`]
    /// when the element bytes are not a whole number of valid words, and
    /// [`EvalHeapSnapshotError::FlatResolve`] when the list object cannot be
    /// resolved for rewriting.
    fn restore_list_payload(&mut self, payload: &ListPayload) -> Result<(), EvalHeapSnapshotError> {
        let ptr = self
            .flat_arena
            .pointer_for_index(ArenaIndex::new(payload.index))
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let elements = decode_list_elements(&payload.element_bytes)?;
        self.flat_lists
            .restore_payload(ptr, FlatObjectKind::List, NixList::new(elements))
            .map_err(EvalHeapSnapshotError::FlatResolve)
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
        // List objects hold no interior reservation witness (their element `Vec`
        // is out of the reservation), but their header words — notably the
        // structural hash — can coincidentally look like an in-range pointer, so
        // cover their whole extent to keep the scan free of false positives.
        for object in self.flat_lists.iter() {
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

/// Decodes a list payload's little-endian words into runtime [`Value`]s.
///
/// The words are address-free Candidate-C words; each resolves unchanged once
/// its domain is re-registered against the restored base.
///
/// # Errors
///
/// Returns [`EvalHeapSnapshotError::MalformedListPayload`] when `bytes` is not a
/// whole number of word-sized chunks or a chunk is not a valid value word.
fn decode_list_elements(bytes: &[u8]) -> Result<Vec<Value>, EvalHeapSnapshotError> {
    if bytes.len() % LIST_ELEMENT_WORD_LEN != 0 {
        return Err(EvalHeapSnapshotError::MalformedListPayload {
            byte_len: bytes.len(),
        });
    }
    let mut elements = Vec::with_capacity(bytes.len() / LIST_ELEMENT_WORD_LEN);
    for chunk in bytes.chunks_exact(LIST_ELEMENT_WORD_LEN) {
        let mut word = [0u8; LIST_ELEMENT_WORD_LEN];
        word.copy_from_slice(chunk);
        let raw = u64::from_le_bytes(word);
        let word = CompressedValueWord::from_raw(raw).map_err(|_| {
            EvalHeapSnapshotError::MalformedListPayload {
                byte_len: bytes.len(),
            }
        })?;
        elements.push(Value::from_word(word));
    }
    Ok(elements)
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
    /// A list payload's serialized bytes are not a whole number of valid words.
    #[error("list payload has malformed element bytes (length {byte_len})")]
    MalformedListPayload {
        /// The offending payload's byte length.
        byte_len: usize,
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
    /// Two records named the same arena object; restoring both would double-rebase
    /// a witness or double-register a list for `Drop` (a malformed image).
    #[error("relocation records name arena object {index} more than once")]
    DuplicateObjectIndex {
        /// The arena index that appeared more than once.
        index: u32,
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
