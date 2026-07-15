//! Flat string/path allocation and resolution for the serial evaluator heap,
//! plus the shared seam machinery for every flat kind (submodules host the
//! list and attrs slices).
//!
//! RFC-0007 doc 30 stages FV-1/FV-2: strings, paths, lists, and attrsets —
//! the hash-consed, immortal, permanent-domain kinds — move out of the
//! record side table into flat object stores
//! (`ratchet_value::heap::flat`). One allocation holds header plus payload
//! at the value's address; resolution becomes a membership check plus one
//! header load, with no address-hash probe, no record `Vec` load, and no
//! record allocated at all. This file carries the string/path slice and the
//! kind-generic helpers; `lists` and `attrs` carry the edge-carrying kinds
//! and their GC couplings.
//!
//! # Mode coverage
//!
//! Serial mode. Parallel heaps are constructed fresh with the shared backend
//! installed (`EvalHeap::with_shared_shard`) and every entry point dispatches
//! to the shared backend before this store is consulted; shared mode has its
//! own flat stores (`heap::flat::shared`, published per shard with the
//! OnceLock release/acquire protocol) so string/path/list/attrs resolution
//! is index-free in both modes. Bytes-inline (FV-1b) is serial-only: shared
//! flat strings keep owned byte buffers inside their published slots.
//!
//! # What stays where
//!
//! - **Hash-cons identity** moves with the object: the cons tables keep their
//!   bucket structure, collision confirmation compares the header hash and the
//!   flat payload, and dedup semantics are unchanged.
//! - **Cold cutoff-cache hashes** stay in a sparse side map, keyed by the
//!   object address, exactly as the record table keeps them for record kinds.
//! - **GC**: strings/paths are permanent-domain (never swept, never region
//!   popped) and edge-free, so the B1 sweep's seed/mark phases and the
//!   worker-region pop's retained-edge validation need no flat awareness.
//! - **Allocator accounting**: the flat store owns its own arena; the heap
//!   folds its stats into the permanent-domain columns and replays a
//!   permanent allocation safepoint per flat allocation so GC-stress cadence
//!   observes string/path allocations exactly as before.

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use crate::heap::flat::{
    FlatObjectError, FlatObjectKind, FlatObjectRef, FlatTailLayout, FlatValueTailHandle,
    flat_aux_for_len,
};

use super::record_table::AddressHasher;
use super::*;

pub(super) mod attrs;
mod active_values;
pub(super) mod closures;
// The Candidate-B/-C `Value <-> word` bridges exist to exercise the compressed
// codecs against the baseline 16-byte carrier. Under the `candidate_c_value`
// carrier the runtime value already IS the compressed word, so the bridges are
// superseded (identity) and their only callers are the baseline-carrier tests.
#[cfg(not(feature = "candidate_c_value"))]
mod compressed_values;
mod lists;
mod scalars;
#[cfg(not(feature = "candidate_c_value"))]
mod tagged_values;

/// Byte-length ceiling for inlining string/path bytes into the flat
/// allocation (doc 30 FV-1b).
///
/// Inlining copies the byte run into the arena; for the short strings that
/// dominate package evaluation (store paths, attr names, interpolation
/// fragments) that copy is cheaper than the retired per-string `Vec`
/// allocation and buys header/byte locality. For large strings — the
/// quadratic accumulator products of `bench.compute.string-builder` are the
/// measured worst case — the extra copy is pure loss and the byte mass would
/// bloat the flat arena's mapped peak, so oversized payloads keep their
/// already-owned buffer, moved (not copied) behind the flat object exactly
/// as FV-1a stored them.
const FLAT_INLINE_BYTES_MAX: usize = 4096;

/// Trailing-array byte ceiling for inlining attrset arrays into the flat
/// allocation (doc 30 FV-4).
///
/// The typed-array analog of [`FLAT_INLINE_BYTES_MAX`], with the same
/// rationale: the small attrsets that dominate package evaluation trade one
/// short copy for the three retired per-attrset `Vec` allocations and
/// header/entry locality, while a large fresh attrset would pay a whole
/// extra pass over its payload (a measured 15-20% wall regression on
/// `bench.compute.attr-fixpoint`'s large-unique-attrset rebuild churn
/// before this cutoff existed). Oversized attrsets keep their moved owned
/// arrays behind the flat object exactly as FV-2 stored them. Lists do not
/// inline at all — see `lists::flat_alloc_list` for that measured decision.
const FLAT_INLINE_ELEMENT_BYTES_MAX: usize = 4096;

/// Maps a flat object kind to the runtime value tag it resolves under.
pub(super) const fn value_tag_for_flat_kind(kind: FlatObjectKind) -> ValueTag {
    match kind {
        FlatObjectKind::String => ValueTag::String,
        FlatObjectKind::Path => ValueTag::Path,
        FlatObjectKind::List => ValueTag::List,
        FlatObjectKind::Attrs => ValueTag::Attrs,
        FlatObjectKind::Thunk => ValueTag::Thunk,
        FlatObjectKind::Lambda => ValueTag::Lambda,
        FlatObjectKind::Primop => ValueTag::Primop,
        FlatObjectKind::BoxedInt => ValueTag::Int,
        FlatObjectKind::BoxedFloat => ValueTag::Float,
    }
}

/// The cutoff-cache value hashes optionally attached to one flat object.
///
/// The flat analog of the record table's sparse cold-hash side map: written
/// only for the small subset of values that become cutoff-cache subjects, so
/// it lives off the resolution hot path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FlatColdHashes {
    value: Option<ValueHash>,
    captured: Option<ValueHash>,
}

impl FlatColdHashes {
    const fn is_empty(self) -> bool {
        self.value.is_none() && self.captured.is_none()
    }
}

/// A sparse cold-hash side map for flat objects, keyed by object address.
#[derive(Debug, Default)]
pub(super) struct FlatColdHashStore {
    map: RefCell<HashMap<usize, FlatColdHashes, BuildHasherDefault<AddressHasher>>>,
}

impl FlatColdHashStore {
    fn value_hash(&self, address: usize) -> Option<ValueHash> {
        self.map.borrow().get(&address)?.value
    }

    fn captured_value_hash(&self, address: usize) -> Option<ValueHash> {
        self.map.borrow().get(&address)?.captured
    }

    fn write(&self, address: usize, mutate: impl FnOnce(&mut FlatColdHashes)) {
        let mut map = self.map.borrow_mut();
        let mut slot = map.get(&address).copied().unwrap_or_default();
        mutate(&mut slot);
        if slot.is_empty() {
            map.remove(&address);
        } else {
            map.insert(address, slot);
        }
    }

    /// Drops every cached hash for `address` (writeback commits).
    pub(super) fn clear(&self, address: usize) {
        self.map.borrow_mut().remove(&address);
    }
}

impl EvalHeap {
    /// Serial [`EvalHeap::alloc_string`]: hash-cons admission over the flat
    /// store, then one flat allocation (no heap record).
    pub(super) fn flat_alloc_string(&mut self, string: NixString) -> Result<Value, EvalHeapError> {
        let hash = string.structural_hash_xxh3();
        let cons_slot = match self.admit_flat_string_cons(hash, &string)? {
            HashConsReservation::Existing(value) => {
                self.alloc_counters.note_hashcons(true);
                self.touch_reusable_value(value)?;
                return Ok(value);
            }
            HashConsReservation::Vacant(slot) => {
                self.alloc_counters.note_hashcons(false);
                slot
            }
        };
        self.alloc_counters
            .note_string_payload(string.len(), string.bytes().starts_with(b"/nix/store/"));
        let len = string.len();
        let epoch = self.next_access_epoch();
        // FV-1b: short byte runs are copied inline into the flat allocation
        // and the stored payload keeps only the witness — no `Vec` survives
        // behind an interned small string. Oversized runs keep their moved
        // owned buffer (see `FLAT_INLINE_BYTES_MAX`).
        let allocation = if len <= FLAT_INLINE_BYTES_MAX {
            let (bytes, context) = string.into_parts();
            self.flat.alloc_with_trailing_bytes(
                FlatObjectKind::String,
                hash.raw(),
                epoch,
                &bytes,
                |flat_bytes| NixString::from_flat_bytes(flat_bytes, context),
            )
        } else {
            self.flat
                .alloc(FlatObjectKind::String, hash.raw(), epoch, string)
        };
        let allocation = match allocation {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_string_cons_slot(cons_slot);
                return Err(flat_alloc_error(error));
            }
        };
        self.permanent_allocator
            .record_flat_allocation_safepoint(len, allocation.allocation);
        let value = match Value::string(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_string_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.push_string_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Serial [`EvalHeap::alloc_path`]: the path analog of
    /// [`EvalHeap::flat_alloc_string`].
    pub(super) fn flat_alloc_path(&mut self, path: NixString) -> Result<Value, EvalHeapError> {
        let hash = path.structural_hash_xxh3();
        let cons_slot = match self.admit_flat_path_cons(hash, &path)? {
            HashConsReservation::Existing(value) => {
                self.alloc_counters.note_hashcons(true);
                self.touch_reusable_value(value)?;
                return Ok(value);
            }
            HashConsReservation::Vacant(slot) => {
                self.alloc_counters.note_hashcons(false);
                slot
            }
        };
        self.alloc_counters.note_path_payload(path.len());
        let len = path.len();
        let epoch = self.next_access_epoch();
        let allocation = if len <= FLAT_INLINE_BYTES_MAX {
            let (bytes, context) = path.into_parts();
            self.flat.alloc_with_trailing_bytes(
                FlatObjectKind::Path,
                hash.raw(),
                epoch,
                &bytes,
                |flat_bytes| NixString::from_flat_bytes(flat_bytes, context),
            )
        } else {
            self.flat.alloc(FlatObjectKind::Path, hash.raw(), epoch, path)
        };
        let allocation = match allocation {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_path_cons_slot(cons_slot);
                return Err(flat_alloc_error(error));
            }
        };
        self.permanent_allocator
            .record_flat_allocation_safepoint(len, allocation.allocation);
        let value = match Value::path(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_path_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.push_path_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Serial `get_string`/`get_path` resolution through the flat store.
    ///
    /// One membership check plus one header load; the record table is only
    /// consulted on the error path, to preserve the record-type-mismatch
    /// error fidelity for non-flat pointers.
    #[inline]
    pub(super) fn flat_get(
        &self,
        kind: FlatObjectKind,
        ptr: NonNull<HeapObject>,
    ) -> Result<&NixString, EvalHeapError> {
        let tag = value_tag_for_flat_kind(kind);
        match self.flat.resolve(ptr, kind) {
            Ok(object) => {
                self.deref_counters.note_flat_resolution(tag);
                if self.epoch_tracking_enabled {
                    object.touch(self.next_access_epoch());
                }
                Ok(object.payload())
            }
            Err(error) => Err(self.flat_resolution_error(tag, ptr, error)),
        }
    }

    /// Validates that `ptr` is a flat object of the kind `tag` names, without
    /// stamping its access epoch (the scan analog of a record lookup, which
    /// never touches).
    pub(super) fn flat_verify(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<(), EvalHeapError> {
        let result = match tag {
            ValueTag::String => self.flat.resolve(ptr, FlatObjectKind::String).map(|_| ()),
            ValueTag::Path => self.flat.resolve(ptr, FlatObjectKind::Path).map(|_| ()),
            ValueTag::List => self
                .flat_lists
                .resolve(ptr, FlatObjectKind::List)
                .map(|_| ()),
            ValueTag::Attrs => self
                .flat_attrs
                .resolve(ptr, FlatObjectKind::Attrs)
                .map(|_| ()),
            _ => return Err(EvalHeapError::unknown(tag, ptr)),
        };
        result.map_err(|error| self.flat_resolution_error(tag, ptr, error))
    }

    /// Resolves a flat object of `kind` and stamps its access epoch.
    fn flat_touch(
        &self,
        kind: FlatObjectKind,
        ptr: NonNull<HeapObject>,
    ) -> Result<FlatObjectRef<'_, NixString>, EvalHeapError> {
        let tag = value_tag_for_flat_kind(kind);
        match self.flat.resolve(ptr, kind) {
            Ok(object) => {
                if self.epoch_tracking_enabled {
                    object.touch(self.next_access_epoch());
                }
                Ok(object)
            }
            Err(error) => Err(self.flat_resolution_error(tag, ptr, error)),
        }
    }

    /// Maps a flat resolution failure to the heap's error vocabulary.
    ///
    /// Kind mismatches translate directly. Unknown addresses fall back to the
    /// *other* flat stores and then one record-table probe, so a pointer that
    /// names a flat object or record of another type still fails as a
    /// record-type mismatch (today's contract), and only a pointer no domain
    /// knows fails as an unknown pointer.
    pub(super) fn flat_resolution_error(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
        error: FlatObjectError,
    ) -> EvalHeapError {
        match error {
            FlatObjectError::KindMismatch { actual, .. } => EvalHeapError::record_type_mismatch(
                tag,
                value_tag_for_flat_kind(actual),
                ptr,
            ),
            FlatObjectError::UnknownAddress { .. } => match self.flat_kind_tag(ptr) {
                Some(actual) if actual != tag => {
                    EvalHeapError::record_type_mismatch(tag, actual, ptr)
                }
                _ => match self.records.find(ptr) {
                    Some(record) => {
                        EvalHeapError::record_type_mismatch(tag, record.object.tag(), ptr)
                    }
                    None => EvalHeapError::unknown(tag, ptr),
                },
            },
            error @ (FlatObjectError::Arena(_)
            | FlatObjectError::RegistryAllocationFailed { .. }
            | FlatObjectError::InvalidRegionMark { .. }
            | FlatObjectError::KindNotAllowed { .. }
            | FlatObjectError::SharedArenaRegionUnsupported) => {
                // Unreachable from resolution (the heap resolves each kind
                // through the store allowed to type it); keep a loud mapping.
                debug_assert!(false, "flat resolution returned an allocation error: {error}");
                EvalHeapError::unknown(tag, ptr)
            }
        }
    }

    /// Returns the value tag of the flat object at `ptr`, if there is one.
    ///
    /// Consults every flat store (strings/paths, lists, and attrsets). Used
    /// by [`EvalHeap::record_or_unknown`]'s error path so a flat pointer
    /// handed to a record-kind getter still reports a record-type mismatch.
    pub(super) fn flat_kind_tag(&self, ptr: NonNull<HeapObject>) -> Option<ValueTag> {
        self.flat
            .kind_of(ptr)
            .or_else(|| self.flat_lists.kind_of(ptr))
            .or_else(|| self.flat_attrs.kind_of(ptr))
            .map(value_tag_for_flat_kind)
            .or_else(|| self.flat_closure_tag(ptr))
    }

    /// Hash-cons admission for serial strings over the flat store.
    fn admit_flat_string_cons(
        &mut self,
        hash: HotXxh3Hash,
        string: &NixString,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let flat = &self.flat;
            self.string_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
                    let object = flat
                        .resolve(ptr, FlatObjectKind::String)
                        .map_err(|_| EvalHeapError::unknown(ValueTag::String, ptr))?;
                    let same_hash = object.structural_hash() == hash.raw();
                    Ok::<bool, EvalHeapError>(same_hash && object.payload() == string)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        Ok(HashConsReservation::Vacant(
            self.string_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    /// Hash-cons admission for serial paths over the flat store.
    fn admit_flat_path_cons(
        &mut self,
        hash: HotXxh3Hash,
        path: &NixString,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let flat = &self.flat;
            self.path_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
                    let object = flat
                        .resolve(ptr, FlatObjectKind::Path)
                        .map_err(|_| EvalHeapError::unknown(ValueTag::Path, ptr))?;
                    let same_hash = object.structural_hash() == hash.raw();
                    Ok::<bool, EvalHeapError>(same_hash && object.payload() == path)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        Ok(HashConsReservation::Vacant(
            self.path_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    /// Resolves the canonical address of a reusable serial flat value
    /// (string, path, list, or attrset), stamping its access epoch (the flat
    /// analog of `record_for_value`).
    pub(super) fn flat_canonical_address(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<usize, EvalHeapError> {
        match tag {
            ValueTag::String => self.flat_touch(FlatObjectKind::String, ptr).map(|_| ())?,
            ValueTag::Path => self.flat_touch(FlatObjectKind::Path, ptr).map(|_| ())?,
            ValueTag::List => self.flat_touch_list(ptr).map(|_| ())?,
            ValueTag::Attrs => self.flat_touch_attrs(ptr).map(|_| ())?,
            _ => return Err(EvalHeapError::unknown(tag, ptr)),
        }
        Ok(ptr.as_ptr() as usize)
    }

    /// Returns the cached canonical value hash for a flat object.
    pub(super) fn flat_cold_value_hash(&self, address: usize) -> Option<ValueHash> {
        self.flat_cold_hashes.value_hash(address)
    }

    /// Returns the cached force-capture value hash for a flat object.
    pub(super) fn flat_cold_captured_value_hash(&self, address: usize) -> Option<ValueHash> {
        self.flat_cold_hashes.captured_value_hash(address)
    }

    /// Sets the cached canonical value hash for a flat object.
    pub(super) fn set_flat_cold_value_hash(&self, address: usize, hash: Option<ValueHash>) {
        self.flat_cold_hashes.write(address, |slot| slot.value = hash);
    }

    /// Sets the cached force-capture value hash for a flat object.
    pub(super) fn set_flat_cold_captured_value_hash(
        &self,
        address: usize,
        hash: Option<ValueHash>,
    ) {
        self.flat_cold_hashes
            .write(address, |slot| slot.captured = hash);
    }
}

/// Maps a flat allocation failure into the heap error vocabulary.
fn flat_alloc_error(error: FlatObjectError) -> EvalHeapError {
    match error {
        FlatObjectError::Arena(source) => EvalHeapError::Arena(source),
        FlatObjectError::RegistryAllocationFailed { entries } => {
            EvalHeapError::RecordAllocationFailed { records: entries }
        }
        FlatObjectError::UnknownAddress { .. }
        | FlatObjectError::KindMismatch { .. }
        | FlatObjectError::InvalidRegionMark { .. }
        | FlatObjectError::KindNotAllowed { .. }
        | FlatObjectError::SharedArenaRegionUnsupported => {
            // Unreachable from allocation (each kind is allocated through the
            // store allowed to host it); surface a record failure loudly.
            debug_assert!(false, "flat allocation returned a resolution error: {error}");
            EvalHeapError::RecordAllocationFailed { records: 1 }
        }
    }
}
