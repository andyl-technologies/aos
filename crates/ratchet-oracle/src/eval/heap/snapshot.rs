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
//! Strings, paths, attrsets, lists, and context-bearing strings are handled. A
//! list's element `Vec` lives outside the reservation, so capture serializes its
//! address-free element words into a [`ListPayload`] segment and restore rebuilds
//! the `Vec`. A string's non-empty `Arc`-backed context is likewise out of arena:
//! capture serializes it into a [`ContextPayload`] keyed by the string's
//! relocation index, and restore rebuilds the context and re-installs it. In both
//! cases restore overwrites the stale dumped payload without dropping it and
//! registers the object so the rebuilt owner drops exactly once.
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

mod closures;
mod collapse;
mod env_frames;
mod owned_data;
mod wire;

use wire::{
    decode_context, decode_list_elements, decode_primop, encode_context, encode_primop,
    kind_from_byte, range_contains,
};

#[allow(unused_imports)] // Consumed by the tree-walk heap-snapshot tests.
pub(crate) use collapse::ForcedThunkCollapseReport;
pub(crate) use env_frames::{CapturedFrameTable, RestoredFrameTable};

use super::closure_code_ref::{LambdaCodeFingerprints, LambdaCodeResolver};

use ratchet_value::heap::{
    ArenaIndex, ContextPayload, HeapImage, ListPayload, OwnedAttrsPayload, OwnedStringPayload,
    PrimopPayload, RelocationEntry, SnapshotError, capture_reservation, reservation_base,
    restore_reservation,
};

use crate::attrs::AttrsStorageKind;
use crate::compile::builtins::{PINNED_NIX_VERSION, lookup_builtin};
use crate::string::{ContextElement, ContextKind, StringBytesStorageKind, StringContext};
use crate::syntax::{Span, Symbol};
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
    /// kind not yet snapshottable (worker thunks or lambdas, or record-table
    /// objects — primops are captured), a flat object outside the reservation, a
    /// reservation that is not address-free, or a failed completeness audit.
    pub fn capture_heap_image(&self) -> Result<HeapImage, EvalHeapSnapshotError> {
        self.capture_heap_image_inner(None)
    }

    /// Captures a heap image including lambdas and suspended thunks, keying
    /// their code by content through the supplied fingerprint context
    /// (RFC-0007 doc 31 §1 step-3 increment 3).
    ///
    /// The context is supplied by the `TreeWalk` that owns the module table;
    /// the heap itself holds no code identity. Restore requires the matching
    /// [`LambdaCodeResolver`] through
    /// [`EvalHeap::from_restored_heap_image_with_code_identity`].
    ///
    /// # Errors
    ///
    /// Returns every [`EvalHeap::capture_heap_image`] error except the closure
    /// refusal, plus the closure-serializer refusals: an unfingerprintable
    /// module, an unreadable captured frame, or a thunk whose force state is
    /// not plainly suspended (forced-thunk collapse is increment 4).
    pub(crate) fn capture_heap_image_with_code_identity(
        &self,
        code: &dyn LambdaCodeFingerprints,
    ) -> Result<HeapImage, EvalHeapSnapshotError> {
        self.capture_heap_image_inner(Some(code))
    }

    /// Shared capture core; `code` enables the closure serializer.
    fn capture_heap_image_inner(
        &self,
        code: Option<&dyn LambdaCodeFingerprints>,
    ) -> Result<HeapImage, EvalHeapSnapshotError> {
        if self.shared.is_some() {
            return Err(EvalHeapSnapshotError::ParallelMode);
        }
        // Without a code-identity context, worker closures other than primops
        // refuse (their code cannot be content-keyed). Count refusals before
        // encoding so a refused heap fails fast.
        if code.is_none() {
            let refused_closures = self
                .flat_closures
                .iter()
                .filter(|object| {
                    matches!(
                        object.object().payload(),
                        FlatClosurePayload::Thunk(_)
                            | FlatClosurePayload::SharedThunk(_)
                            | FlatClosurePayload::Lambda(_)
                    )
                })
                .count();
            if refused_closures != 0 {
                return Err(EvalHeapSnapshotError::UnsnapshottableClosures {
                    count: refused_closures,
                });
            }
        }
        let records = self.record_count();
        if records != 0 {
            return Err(EvalHeapSnapshotError::UnsnapshottableRecords { count: records });
        }

        let mut primop_payloads = Vec::new();
        for object in self.flat_closures.iter() {
            if let FlatClosurePayload::Primop(primop) = object.object().payload() {
                let index = self
                    .flat_arena
                    .index_for_pointer(object.ptr())
                    .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
                primop_payloads.push(PrimopPayload {
                    index: index.raw(),
                    primop_bytes: encode_primop(primop),
                });
            }
        }

        let mut relocations = Vec::new();
        let mut context_payloads = Vec::new();
        let mut string_payloads = Vec::new();
        for object in self.flat.iter() {
            // Default-deny storage routing (no wildcard arm): a new string
            // storage class must pick a capture strategy here or fail to
            // compile — the completeness audit cannot see out-pointing
            // storage, so this match is the standing guard.
            match object.object().payload().bytes_storage_kind() {
                // An over-threshold string keeps a moved owned `Vec<u8>`
                // behind the payload; its dumped header would restore
                // dangling, so the bytes (and context) ride a payload segment
                // instead of a relocation.
                StringBytesStorageKind::Owned => {
                    let index = self
                        .flat_arena
                        .index_for_pointer(object.ptr())
                        .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
                    string_payloads.push(OwnedStringPayload {
                        index: index.raw(),
                        string_bytes: owned_data::encode_owned_string(object.object().payload()),
                    });
                }
                StringBytesStorageKind::FlatWitness => {
                    let entry = self.relocation_entry_for(object.ptr(), object.object().kind())?;
                    // A non-empty string context is an out-of-arena
                    // `Arc`-backed set; the relocation entry rebases the
                    // inline bytes, and this supplemental payload (keyed by
                    // the same index) carries the context to rebuild.
                    let context = object.object().payload().context();
                    if !context.is_empty() {
                        context_payloads.push(ContextPayload {
                            index: entry.index,
                            context_bytes: encode_context(context),
                        });
                    }
                    relocations.push(entry);
                }
            }
        }
        let mut attrs_payloads = Vec::new();
        for object in self.flat_attrs.iter() {
            // Same default-deny routing for attrset array storage.
            match object.object().payload().attrs.storage_kind() {
                AttrsStorageKind::Owned => {
                    let index = self
                        .flat_arena
                        .index_for_pointer(object.ptr())
                        .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
                    attrs_payloads.push(OwnedAttrsPayload {
                        index: index.raw(),
                        attrs_bytes: owned_data::encode_owned_attrs(
                            &object.object().payload().attrs,
                        ),
                    });
                }
                AttrsStorageKind::FlatWitness => {
                    relocations
                        .push(self.relocation_entry_for(object.ptr(), FlatObjectKind::Attrs)?);
                }
            }
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

        let (frame_payloads, closure_payloads) = match code {
            Some(code) => self.capture_closure_payloads(code)?,
            None => (Vec::new(), Vec::new()),
        };

        let mut image =
            capture_reservation(&self.flat_arena).map_err(EvalHeapSnapshotError::Snapshot)?;
        image.relocations = relocations;
        image.list_payloads = list_payloads;
        image.context_payloads = context_payloads;
        image.primop_payloads = primop_payloads;
        image.frame_payloads = frame_payloads;
        image.closure_payloads = closure_payloads;
        image.attrs_payloads = attrs_payloads;
        image.string_payloads = string_payloads;

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
    /// relocation object's interior witnesses by `new_base − old_base`, re-attaches
    /// each list's out-of-arena element `Vec`, and rebuilds each context-bearing
    /// string's out-of-arena dependency set from its payload segment.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::Snapshot`] when the image is malformed or
    /// its domain is still live, [`EvalHeapSnapshotError::ObjectOutsideReservation`]
    /// when a relocation, list, or context index does not resolve,
    /// [`EvalHeapSnapshotError::UnknownKind`] for an unrecognized relocation kind,
    /// [`EvalHeapSnapshotError::DuplicateObjectIndex`] when two records name the
    /// same arena object (a malformed image that would otherwise double-rebase a
    /// witness, double-register a list, or double-install a context),
    /// [`EvalHeapSnapshotError::ContextForUnrelocatedString`] when a context
    /// payload names an object that was not rebased as a string,
    /// [`EvalHeapSnapshotError::MalformedListPayload`] or
    /// [`EvalHeapSnapshotError::MalformedContextPayload`] when a payload's bytes do
    /// not decode, and [`EvalHeapSnapshotError::FlatResolve`] when a recorded
    /// object cannot be resolved for rewriting.
    pub fn from_restored_heap_image(image: &HeapImage) -> Result<Self, EvalHeapSnapshotError> {
        Self::from_restored_heap_image_inner(image, None)
    }

    /// Restores a heap image whose closures were captured with a code-identity
    /// context, re-resolving every content-keyed code reference through
    /// `resolver` (RFC-0007 doc 31 §1 step-3 increment 3).
    ///
    /// # Errors
    ///
    /// Returns every [`EvalHeap::from_restored_heap_image`] error, plus the
    /// closure-restore refusals: [`EvalHeapSnapshotError::ClosureCodeDrift`]
    /// when a code fingerprint is absent from `resolver` (never a silent
    /// rebind), [`EvalHeapSnapshotError::MalformedClosurePayload`] and
    /// [`EvalHeapSnapshotError::MalformedFramePayload`] for segments that do
    /// not decode, and the builtin-registry refusals for builtin-attr thunks.
    pub(crate) fn from_restored_heap_image_with_code_identity(
        image: &HeapImage,
        resolver: &dyn LambdaCodeResolver,
    ) -> Result<Self, EvalHeapSnapshotError> {
        Self::from_restored_heap_image_inner(image, Some(resolver))
    }

    /// Shared restore core; `resolver` enables the closure restore path.
    fn from_restored_heap_image_inner(
        image: &HeapImage,
        resolver: Option<&dyn LambdaCodeResolver>,
    ) -> Result<Self, EvalHeapSnapshotError> {
        // Without a resolver the frame table and closure payloads have no
        // consumer; silently dropping them would restore closures without
        // their captured environments (or leave stale dumped payloads live).
        if resolver.is_none()
            && !(image.frame_payloads.is_empty() && image.closure_payloads.is_empty())
        {
            return Err(EvalHeapSnapshotError::UnexpectedFramePayloads {
                count: image.frame_payloads.len() + image.closure_payloads.len(),
            });
        }
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
        // Indices of the strings/paths whose inline byte witness was rebased —
        // exactly the objects a context payload may re-key against.
        let mut relocated_strings: HashSet<u32> = HashSet::new();

        for entry in &image.relocations {
            if !seen.insert(entry.index) {
                return Err(EvalHeapSnapshotError::DuplicateObjectIndex { index: entry.index });
            }
            let ptr = heap
                .flat_arena
                .pointer_for_index(ArenaIndex::new(entry.index))
                .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
            match kind_from_byte(entry.kind)? {
                kind @ (FlatObjectKind::String | FlatObjectKind::Path) => {
                    heap.flat
                        .resolve_mut(ptr, kind)
                        .map_err(EvalHeapSnapshotError::FlatResolve)?
                        .rebase_witnesses(delta);
                    relocated_strings.insert(entry.index);
                }
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

        // A context payload supplements a relocated string (not a new object), so
        // its index is checked against the string set, not the object-record set.
        let mut seen_contexts: HashSet<u32> = HashSet::new();
        for payload in &image.context_payloads {
            if !relocated_strings.contains(&payload.index) {
                return Err(EvalHeapSnapshotError::ContextForUnrelocatedString {
                    index: payload.index,
                });
            }
            if !seen_contexts.insert(payload.index) {
                return Err(EvalHeapSnapshotError::DuplicateObjectIndex {
                    index: payload.index,
                });
            }
            heap.restore_context_payload(payload)?;
        }

        // Primops are distinct flat-closure objects, so their indices share the
        // object-record set with relocations and lists.
        for payload in &image.primop_payloads {
            if !seen.insert(payload.index) {
                return Err(EvalHeapSnapshotError::DuplicateObjectIndex {
                    index: payload.index,
                });
            }
            heap.restore_primop_payload(payload)?;
        }

        // Over-threshold attrsets and strings carry owned arrays the dumped
        // lanes cannot: rebuild owned storage over the restored objects.
        for payload in &image.attrs_payloads {
            if !seen.insert(payload.index) {
                return Err(EvalHeapSnapshotError::DuplicateObjectIndex {
                    index: payload.index,
                });
            }
            heap.restore_owned_attrs_payload(payload)?;
        }
        for payload in &image.string_payloads {
            if !seen.insert(payload.index) {
                return Err(EvalHeapSnapshotError::DuplicateObjectIndex {
                    index: payload.index,
                });
            }
            heap.restore_owned_string_payload(payload)?;
        }

        // Lambdas and suspended thunks restore over the rebuilt frame table;
        // their indices share the object-record set with every other segment.
        if let Some(resolver) = resolver {
            let frame_table = RestoredFrameTable::rebuild(&image.frame_payloads)?;
            heap.restore_closure_payloads(
                &image.closure_payloads,
                &frame_table,
                resolver,
                &mut seen,
            )?;
        }
        Ok(heap)
    }

    /// Rebuilds one captured builtin (primop) closure and re-attaches it to the
    /// restored flat-closure object.
    ///
    /// Decodes the registry reference and applied arguments (re-resolving the
    /// builtin, refusing on a version or name mismatch), then delegates the
    /// in-place payload rewrite and Drop registration to
    /// [`FlatObjectStore::restore_payload`] (the unsafe write lives in
    /// `ratchet-value`).
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::ObjectOutsideReservation`] when the index
    /// does not resolve, the decode errors from [`decode_primop`], and
    /// [`EvalHeapSnapshotError::FlatResolve`] when the object cannot be resolved
    /// for rewriting.
    fn restore_primop_payload(
        &mut self,
        payload: &PrimopPayload,
    ) -> Result<(), EvalHeapSnapshotError> {
        let ptr = self
            .flat_arena
            .pointer_for_index(ArenaIndex::new(payload.index))
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let primop = decode_primop(&payload.primop_bytes)?;
        self.flat_closures
            .restore_payload(
                ptr,
                FlatObjectKind::Primop,
                FlatClosurePayload::Primop(primop),
            )
            .map_err(EvalHeapSnapshotError::FlatResolve)
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

    /// Rebuilds one context-bearing string's dependency set and re-installs it on
    /// the restored string.
    ///
    /// The string's inline bytes were already rebased by its relocation entry;
    /// this decodes the context, reconstructs the string over those rebased bytes
    /// with the rebuilt context ([`NixString::with_replaced_context`]), and
    /// delegates the in-place payload rewrite and Drop registration to
    /// [`FlatObjectStore::restore_payload`] so the stale dumped context `Arc` is
    /// overwritten without being dropped.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::ObjectOutsideReservation`] when the index
    /// does not resolve, [`EvalHeapSnapshotError::MalformedContextPayload`] when
    /// the context bytes do not decode, and [`EvalHeapSnapshotError::FlatResolve`]
    /// when the string cannot be resolved for rewriting.
    fn restore_context_payload(
        &mut self,
        payload: &ContextPayload,
    ) -> Result<(), EvalHeapSnapshotError> {
        let ptr = self
            .flat_arena
            .pointer_for_index(ArenaIndex::new(payload.index))
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        // The index was verified to be a relocated string, so it resolves as
        // String or Path; `kind_of` recovers which for the typed rewrite.
        let kind = self
            .flat
            .kind_of(ptr)
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let context = decode_context(&payload.context_bytes)?;
        let replacement = self
            .flat
            .resolve_mut(ptr, kind)
            .map_err(EvalHeapSnapshotError::FlatResolve)?
            .with_replaced_context(context);
        self.flat
            .restore_payload(ptr, kind, replacement)
            .map_err(EvalHeapSnapshotError::FlatResolve)
    }

    /// Primes each flat store's membership index over the restored arena.
    fn adopt_restored_regions(&mut self) {
        self.flat.adopt_shared_regions();
        self.flat_lists.adopt_shared_regions();
        self.flat_attrs.adopt_shared_regions();
        self.flat_closures.adopt_shared_regions();
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
        // Flat-closure objects (captured primops, refused-but-dead retired slots)
        // ride along in the dumped arena; their out-of-arena `Vec`/`Arc` fields
        // point outside the reservation, but cover their extent so no header word
        // false-positives as an interior pointer.
        for object in self.flat_closures.iter() {
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
    /// A context payload's bytes did not decode to a valid context.
    #[error("context payload has malformed element bytes (length {byte_len})")]
    MalformedContextPayload {
        /// The offending payload's byte length.
        byte_len: usize,
    },
    /// A context payload named an object that was not rebased as a string, so
    /// installing its context would attach to unrelocated (stale) bytes.
    #[error("context payload names object {index}, which was not relocated as a string")]
    ContextForUnrelocatedString {
        /// The arena index the context payload referenced.
        index: u32,
    },
    /// A primop payload's bytes did not decode to a valid builtin closure.
    #[error("primop payload has malformed bytes (length {byte_len})")]
    MalformedPrimopPayload {
        /// The offending payload's byte length.
        byte_len: usize,
    },
    /// A primop payload was captured against a different builtin-surface version.
    #[error("primop payload builtin version mismatch (expected {expected:?}, found {found:?})")]
    RegistryVersionMismatch {
        /// The builtin-surface version this build pins.
        expected: Vec<u8>,
        /// The version recorded in the image.
        found: Vec<u8>,
    },
    /// A primop payload referenced a builtin name absent from the registry.
    #[error("primop payload references unknown builtin {name:?}")]
    UnknownBuiltin {
        /// The unresolved builtin name.
        name: Vec<u8>,
    },
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
    /// A captured environment frame's slots could not be read at capture, or a
    /// rebuilt frame's slot storage could not be allocated or written.
    #[error("captured environment frame is unreadable: {0}")]
    EnvFrameUnreadable(#[source] crate::eval::env::EvalEnvError),
    /// An env-frame-table segment is out of dense order, truncated, carries
    /// trailing bytes, names a parent at or above its own id, or holds an
    /// invalid slot value word.
    #[error("env frame payload {index} is malformed")]
    MalformedFramePayload {
        /// The offending frame payload's table index.
        index: u32,
    },
    /// The image carries env-frame-table or closure segments, but restore was
    /// invoked without a code-identity resolver to consume them; ignoring them
    /// would silently drop captured environments and closures.
    #[error("image carries {count} closure/frame payload(s) but no code-identity resolver")]
    UnexpectedFramePayloads {
        /// The number of unconsumed frame and closure payload segments.
        count: usize,
    },
    /// A thunk's force state is not capturable: the cell is in flight
    /// (blackhole), poisoned, or forced without a classifiable cached value.
    #[error("closure at arena index {index} has an unsnapshottable thunk force state")]
    UnsnapshottableThunkState {
        /// The thunk object's arena index.
        index: u32,
    },
    /// A forced thunk's cached value is itself a thunk — a collapse chain the
    /// census measured as absent; the collapse refuses rather than
    /// mis-collapsing one step of an unmeasured chain.
    #[error("forced thunk at arena index {index} caches another thunk (collapse chain)")]
    ForcedThunkChain {
        /// The chained thunk object's arena index.
        index: u32,
    },
    /// A referenced module could not be fingerprinted, so its code cannot be
    /// content-keyed; capture refuses rather than emitting an unkeyed
    /// reference.
    #[error("module {module} has no code fingerprint; cannot content-key its closures")]
    CodeFingerprintUnavailable {
        /// The raw unfingerprintable module id.
        module: u32,
    },
    /// A closure payload's bytes did not decode, referenced an out-of-table
    /// frame, carried a trailing run, or failed its flat-capture re-signing.
    #[error("closure payload {index} is malformed")]
    MalformedClosurePayload {
        /// The offending closure payload's arena index.
        index: u32,
    },
    /// An owned-attrs payload's bytes did not decode, its permutations were
    /// out of bounds, or its entries were not strictly symbol-sorted.
    #[error("owned attrs payload {index} is malformed")]
    MalformedAttrsPayload {
        /// The offending attrs payload's arena index.
        index: u32,
    },
    /// An owned-string payload's bytes or context did not decode.
    #[error("owned string payload {index} is malformed")]
    MalformedStringPayload {
        /// The offending string payload's arena index.
        index: u32,
    },
    /// A closure payload's code fingerprint is absent from the current
    /// evaluator's module table — the IR drifted, and restore refuses to
    /// rebind rather than silently evaluating different code.
    #[error("closure payload {index} references drifted code (fingerprint unresolved)")]
    ClosureCodeDrift {
        /// The offending closure payload's arena index.
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
