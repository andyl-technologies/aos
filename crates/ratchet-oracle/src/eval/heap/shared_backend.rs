//! Shared-arena backend seam for the production evaluator heap (L2-P3a).
//!
//! # The seam
//!
//! [`super::EvalHeap`] owns two interchangeable allocation/resolution
//! backends:
//!
//! - **Serial** (the default): the record side table, bump arenas, hash-cons
//!   tables, and GC bookkeeping in [`super::arena`]. Bit-for-bit unchanged by
//!   this module.
//! - **Shared** (parallel mode): a [`SharedHeapBackend`] installed by
//!   [`super::EvalHeap::with_shared_shard`]. Every `alloc_*` publishes the
//!   typed record into the worker's own [`SharedHeapShard`]; every `get_*`
//!   resolves through the shard-aware path below, so a value allocated by
//!   *any* worker sharing the [`SharedHeapArena`] can be dereferenced.
//!
//! Dispatch is one branch on `EvalHeap::shared: Option<SharedHeapBackend>` at
//! the top of each entry point - always `None` in serial mode, so the branch
//! is perfectly predicted and the serial hot path is otherwise untouched.
//!
//! # Resolution order
//!
//! ```text
//! get_*(ptr), record-backed kinds (lambda/primop/thunk):
//!   1. own-shard private index (plain HashMap, no lock)  - hit: chunk deref
//!   2. arena cross-shard probe (per-shard RwLock read)   - other workers' values
//!   3. miss -> EvalHeapError::UnknownPointer
//!
//! get_*(ptr), flat kinds (string/path/list/attrs, doc 30 FV-1/FV-2):
//!   1. own-shard flat store membership (range compares, no index, no lock)
//!   2. cross-shard flat store membership (same arithmetic, per shard)
//!   3. miss -> type-mismatch fidelity probe, then UnknownPointer
//! ```
//!
//! The private index mirrors exactly the records this worker allocated into
//! its own shard, so the hot own-value path takes no atomics; the arena probe
//! is reserved for cross-worker dereference. Flat kinds skip both indexes:
//! the value address is the published slot, validated by chunk-range
//! membership and the slot's own once-published state — the `OnceLock`
//! release/acquire publication protocol is preserved exactly.
//!
//! # What shared mode deliberately drops
//!
//! - **Touch epochs.** The serial read path stamps `last_touch_epoch` cells
//!   for cold-value advice; GC is quiesced under parallel evaluation (the
//!   options force `GcStressPolicy::disabled()`), so shared-mode reads mutate
//!   nothing.
//! - **Worker regions / minor GC / Tier-B admission.** All GC machinery
//!   operates on the (empty) serial record table and is never dispatched in
//!   production parallel evaluation.
//! - **Cross-worker hash-consing.** Hash-cons stays *per worker*: each
//!   `EvalHeap` keeps its own cons tables over values it allocated into its
//!   own shard. Two workers may thus hold structurally identical values at
//!   distinct addresses; that costs memory, never semantics - the evaluator's
//!   pointer-equality checks are positive-only fast paths that fall through to
//!   content comparison (see `eval_compare`).
//!
//! # Memory accounting
//!
//! Budget polling keeps running after every shared allocation. The primary
//! resident-byte source is the process resident set (whole-process, so it
//! naturally sums over all workers' shards); the arena fallback adds the
//! shards' approximate payload bytes, summed from per-shard atomic counters.
//!
//! Cutoff-cache value hashes (`cached_value_hash` and friends) stay
//! per-worker side maps here, keyed by record address: advisory caches whose
//! cross-worker misses only cost a recompute.

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::ptr::NonNull;
use std::sync::Arc;

use crate::attrs::FlatAttrs;
use crate::cache::ValueHash;
use crate::list::NixList;
use crate::string::NixString;
use crate::value::{HeapObject, Value, ValueTag};

use super::arena::{any_value_heap_ptr, attrs_structural_hash, list_structural_hash};
use crate::heap::flat::FlatObjectKind;
use crate::heap::flat::shared::SharedFlatObject;
use super::record_table::AddressHasher;
use super::{
    FlatClosurePayload,
    EvalHeap, EvalHeapAttrsMetadata, EvalHeapError, EvalLambda, EvalPrimOp, EvalThunk,
    FlatAttrsPayload, HeapAllocationDomain, HeapObjectValue, HeapValueHashCacheUpdate,
    SharedHeapArena, SharedHeapShard, initial_generation_for_allocation_domain,
};
use crate::heap::HeapGeneration;


/// A worker-private cutoff-hash side map (record address -> cached hash).
type ColdHashIndex = HashMap<usize, ValueHash, BuildHasherDefault<AddressHasher>>;

/// The parallel-mode allocation/resolution backend of one worker's
/// [`EvalHeap`].
///
/// Owns the worker's shard of the shared arena plus the worker-private
/// indexes described in the [module documentation](self).
#[derive(Debug)]
pub(super) struct SharedHeapBackend {
    /// The arena shared by every worker of one parallel evaluation.
    arena: Arc<SharedHeapArena>,
    /// This worker's single-writer allocation shard.
    shard: Arc<SharedHeapShard>,
    /// Worker-private canonical value hashes (serial: record-table side map).
    cold_value_hashes: RefCell<ColdHashIndex>,
    /// Worker-private force-capture value hashes.
    cold_captured_value_hashes: RefCell<ColdHashIndex>,
}

impl SharedHeapBackend {
    /// Builds a backend for one worker over `arena`, allocating into `shard`.
    pub(super) fn new(arena: Arc<SharedHeapArena>, shard: Arc<SharedHeapShard>) -> Self {
        Self {
            arena,
            shard,
            cold_value_hashes: RefCell::new(ColdHashIndex::default()),
            cold_captured_value_hashes: RefCell::new(ColdHashIndex::default()),
        }
    }

    /// Returns the shared arena this backend allocates into.
    pub(super) fn arena(&self) -> &Arc<SharedHeapArena> {
        &self.arena
    }

    /// Returns the number of records this worker published into its shard.
    pub(super) fn published_len(&self) -> usize {
        self.shard.published_len()
    }

    /// Resolves an opaque heap pointer to its typed record object.
    ///
    /// FV-3 moved every worker-object publication into the shards' flat
    /// closure stores, so no production path publishes record slots anymore
    /// (the worker-private address mirror that served them is retired); this
    /// probe remains for the shard record machinery's remaining fixtures.
    pub(super) fn resolve_ptr(&self, ptr: NonNull<HeapObject>) -> Option<&HeapObjectValue> {
        self.arena.resolve_object(ptr)
    }

    /// Resolves `ptr` or reports it unknown under the expected `tag`.
    ///
    /// A pointer that names a *flat* shared object of another kind (doc 30
    /// FV-1) reports a record-type mismatch, preserving error fidelity.
    fn resolve_or_unknown(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<&HeapObjectValue, EvalHeapError> {
        self.resolve_ptr(ptr).ok_or_else(|| {
            match self.flat_tag_at(ptr) {
                Some(actual) => EvalHeapError::record_type_mismatch(tag, actual, ptr),
                None => EvalHeapError::unknown(tag, ptr),
            }
        })
    }

    /// Resolves `ptr` as a flat string/path of `kind`, own shard first.
    fn resolve_flat_string(
        &self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Option<&SharedFlatObject<NixString>> {
        // The own-shard membership check is index-free; cross-shard walks
        // every shard's flat regions (the flat analog of the arena probe).
        self.shard
            .resolve_flat_string(ptr, kind)
            .or_else(|| self.arena.resolve_flat_string(ptr, kind))
    }

    /// Resolves `ptr` as a flat list, own shard first.
    fn resolve_flat_list(&self, ptr: NonNull<HeapObject>) -> Option<&SharedFlatObject<NixList>> {
        self.shard
            .resolve_flat_list(ptr)
            .or_else(|| self.arena.resolve_flat_list(ptr))
    }

    /// Resolves `ptr` as a flat attrset, own shard first.
    fn resolve_flat_attrs(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Option<&SharedFlatObject<FlatAttrsPayload>> {
        self.shard
            .resolve_flat_attrs(ptr)
            .or_else(|| self.arena.resolve_flat_attrs(ptr))
    }

    /// Publishes a flat worker closure into this worker's shard.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::SharedArena`] if the shard's flat closure
    /// slots are exhausted.
    pub(super) fn publish_flat_closure(
        &self,
        kind: FlatObjectKind,
        payload: FlatClosurePayload,
    ) -> Result<Value, EvalHeapError> {
        self.shard
            .publish_flat_closure(kind, payload)
            .map_err(EvalHeapError::SharedArena)
    }

    /// Resolves `ptr` as a flat worker closure, own shard first.
    fn resolve_flat_closure(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Option<&SharedFlatObject<FlatClosurePayload>> {
        self.shard
            .resolve_flat_closure(ptr)
            .or_else(|| self.arena.resolve_flat_closure(ptr))
    }

    /// Returns the value tag of the flat object at `ptr`, if any shard owns
    /// one there.
    fn flat_tag_at(&self, ptr: NonNull<HeapObject>) -> Option<ValueTag> {
        self.shard
            .flat_tag_at(ptr)
            .or_else(|| self.arena.flat_tag_at(ptr))
    }

    /// Maps a flat resolution miss to the heap's error vocabulary: another
    /// flat kind or a slot record at the address is a type mismatch; a
    /// pointer no domain knows is unknown.
    fn flat_miss_error(&self, tag: ValueTag, ptr: NonNull<HeapObject>) -> EvalHeapError {
        if let Some(actual) = self.flat_tag_at(ptr)
            && actual != tag
        {
            return EvalHeapError::record_type_mismatch(tag, actual, ptr);
        }
        match self.resolve_ptr(ptr) {
            Some(object) => EvalHeapError::record_type_mismatch(tag, object.tag(), ptr),
            None => EvalHeapError::unknown(tag, ptr),
        }
    }

    /// Returns the string object behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a string.
    pub(super) fn get_string_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&NixString, EvalHeapError> {
        match self.resolve_flat_string(ptr, FlatObjectKind::String) {
            Some(object) => Ok(object.payload()),
            None => Err(self.flat_miss_error(ValueTag::String, ptr)),
        }
    }

    /// Returns the path object behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a path.
    pub(super) fn get_path_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&NixString, EvalHeapError> {
        match self.resolve_flat_string(ptr, FlatObjectKind::Path) {
            Some(object) => Ok(object.payload()),
            None => Err(self.flat_miss_error(ValueTag::Path, ptr)),
        }
    }

    /// Returns the list object behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a list.
    pub(super) fn get_list_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixList, EvalHeapError> {
        match self.resolve_flat_list(ptr) {
            Some(object) => Ok(object.payload()),
            None => Err(self.flat_miss_error(ValueTag::List, ptr)),
        }
    }

    /// Returns the attrset object behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not an attrset.
    pub(super) fn get_attrs_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&FlatAttrs, EvalHeapError> {
        match self.resolve_flat_attrs(ptr) {
            Some(object) => Ok(&object.payload().attrs),
            None => Err(self.flat_miss_error(ValueTag::Attrs, ptr)),
        }
    }

    /// Returns the attrset metadata behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not an attrset.
    pub(super) fn get_attrs_metadata_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<EvalHeapAttrsMetadata, EvalHeapError> {
        match self.resolve_flat_attrs(ptr) {
            Some(object) => Ok(object.payload().metadata),
            None => Err(self.flat_miss_error(ValueTag::Attrs, ptr)),
        }
    }

    /// Returns the lambda closure behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a lambda.
    pub(super) fn get_lambda_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&EvalLambda, EvalHeapError> {
        self.lambda_ref(ptr)
    }

    /// Returns the builtin record behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a builtin.
    pub(super) fn get_primop_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&EvalPrimOp, EvalHeapError> {
        self.primop_ref(ptr)
    }

    /// Returns the suspended thunk behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a thunk.
    pub(super) fn get_thunk_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&EvalThunk, EvalHeapError> {
        self.thunk_ref(ptr)
    }

    /// Clones the shared thunk metadata and force-state handles behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a thunk.
    pub(super) fn clone_thunk_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<EvalThunk, EvalHeapError> {
        self.thunk_ref(ptr).cloned()
    }

    /// Clones the shared lambda metadata behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a lambda.
    pub(super) fn clone_lambda_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<EvalLambda, EvalHeapError> {
        self.lambda_ref(ptr).cloned()
    }

    /// Clones the shared builtin metadata behind `ptr`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if no shard owns `ptr` and
    /// [`EvalHeapError::RecordTypeMismatch`] if the record is not a builtin.
    pub(super) fn clone_primop_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<EvalPrimOp, EvalHeapError> {
        self.primop_ref(ptr).cloned()
    }

    fn thunk_ref(&self, ptr: NonNull<HeapObject>) -> Result<&EvalThunk, EvalHeapError> {
        if let Some(object) = self.resolve_flat_closure(ptr) {
            return match object.payload() {
                FlatClosurePayload::Thunk(thunk) => Ok(thunk),
                payload => Err(EvalHeapError::record_type_mismatch(
                    ValueTag::Thunk,
                    payload.tag(),
                    ptr,
                )),
            };
        }
        match self.resolve_or_unknown(ValueTag::Thunk, ptr)? {
            HeapObjectValue::Thunk(thunk) => Ok(thunk),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    fn lambda_ref(&self, ptr: NonNull<HeapObject>) -> Result<&EvalLambda, EvalHeapError> {
        if let Some(object) = self.resolve_flat_closure(ptr) {
            return match object.payload() {
                FlatClosurePayload::Lambda(lambda) => Ok(lambda),
                payload => Err(EvalHeapError::record_type_mismatch(
                    ValueTag::Lambda,
                    payload.tag(),
                    ptr,
                )),
            };
        }
        match self.resolve_or_unknown(ValueTag::Lambda, ptr)? {
            HeapObjectValue::Lambda(lambda) => Ok(lambda),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Lambda,
                object.tag(),
                ptr,
            )),
        }
    }

    fn primop_ref(&self, ptr: NonNull<HeapObject>) -> Result<&EvalPrimOp, EvalHeapError> {
        if let Some(object) = self.resolve_flat_closure(ptr) {
            return match object.payload() {
                FlatClosurePayload::Primop(primop) => Ok(primop),
                payload => Err(EvalHeapError::record_type_mismatch(
                    ValueTag::Primop,
                    payload.tag(),
                    ptr,
                )),
            };
        }
        match self.resolve_or_unknown(ValueTag::Primop, ptr)? {
            HeapObjectValue::Primop(primop) => Ok(primop),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Primop,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the allocation domain that owns `value`.
    ///
    /// Shared records mirror the serial domain assignment by tag: reusable
    /// hash-consable shapes report the permanent shared domain, closure-like
    /// records the worker domain.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] for non-heap values,
    /// [`EvalHeapError::UnknownPointer`] for unowned handles, and
    /// [`EvalHeapError::RecordTypeMismatch`] on a tag/record disagreement.
    pub(super) fn allocation_domain(
        &self,
        value: Value,
    ) -> Result<HeapAllocationDomain, EvalHeapError> {
        let (tag, ptr) = any_value_heap_ptr(value)?;
        if let Some(actual) = self.flat_tag_at(ptr) {
            if actual == tag {
                return Ok(domain_for_tag(tag));
            }
            return Err(EvalHeapError::record_type_mismatch(tag, actual, ptr));
        }
        let object = self.resolve_or_unknown(tag, ptr)?;
        let actual = object.tag();
        if actual == tag {
            Ok(domain_for_tag(tag))
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    /// Returns the heap generation that currently owns `value`.
    ///
    /// GC is quiesced in shared mode, so records keep the initial generation
    /// of their (tag-derived) allocation domain forever.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] for non-heap values,
    /// [`EvalHeapError::UnknownPointer`] for unowned handles, and
    /// [`EvalHeapError::RecordTypeMismatch`] on a tag/record disagreement.
    pub(super) fn generation(&self, value: Value) -> Result<HeapGeneration, EvalHeapError> {
        let domain = self.allocation_domain(value)?;
        Ok(initial_generation_for_allocation_domain(domain))
    }

    /// Resolves a reusable value to its record address after a tag check.
    ///
    /// This mirrors the serial `record_for_value` validation (minus the touch
    /// epoch, which shared mode drops).
    fn reusable_value_address(&self, value: Value) -> Result<usize, EvalHeapError> {
        let (tag, ptr) = super::arena::value_heap_ptr(value)?;
        if let Some(actual) = self.flat_tag_at(ptr) {
            if actual == tag {
                return Ok(ptr.as_ptr() as usize);
            }
            return Err(EvalHeapError::record_type_mismatch(tag, actual, ptr));
        }
        let object = self.resolve_or_unknown(tag, ptr)?;
        let actual = object.tag();
        if actual == tag {
            Ok(ptr.as_ptr() as usize)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    /// Returns the cached canonical value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Mirrors the serial contract: [`EvalHeapError::Value`] for non-reusable
    /// values, [`EvalHeapError::UnknownPointer`] for unowned handles, and
    /// [`EvalHeapError::RecordTypeMismatch`] on tag disagreement.
    pub(super) fn cached_value_hash(
        &self,
        value: Value,
    ) -> Result<Option<ValueHash>, EvalHeapError> {
        let address = self.reusable_value_address(value)?;
        Ok(self.cold_value_hashes.borrow().get(&address).copied())
    }

    /// Stores the canonical value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Mirrors the serial contract, including
    /// [`EvalHeapError::ValueHashMismatch`] when a different hash is already
    /// cached for the record.
    pub(super) fn cache_value_hash(
        &self,
        value: Value,
        hash: ValueHash,
    ) -> Result<HeapValueHashCacheUpdate, EvalHeapError> {
        let address = self.reusable_value_address(value)?;
        let mut hashes = self.cold_value_hashes.borrow_mut();
        match hashes.get(&address).copied() {
            Some(existing) if existing == hash => Ok(HeapValueHashCacheUpdate::AlreadyPresent),
            Some(existing) => Err(EvalHeapError::ValueHashMismatch {
                existing,
                attempted: hash,
            }),
            None => {
                hashes.insert(address, hash);
                Ok(HeapValueHashCacheUpdate::Inserted)
            }
        }
    }

    /// Returns the cached force-capture value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Mirrors the serial contract; see [`Self::cached_value_hash`].
    pub(super) fn cached_captured_value_hash(
        &self,
        value: Value,
    ) -> Result<Option<ValueHash>, EvalHeapError> {
        let address = self.reusable_value_address(value)?;
        Ok(self
            .cold_captured_value_hashes
            .borrow()
            .get(&address)
            .copied())
    }

    /// Stores the force-capture value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Mirrors the serial contract; see [`Self::cache_value_hash`].
    pub(super) fn cache_captured_value_hash(
        &self,
        value: Value,
        hash: ValueHash,
    ) -> Result<(), EvalHeapError> {
        let address = self.reusable_value_address(value)?;
        self.cold_captured_value_hashes
            .borrow_mut()
            .insert(address, hash);
        Ok(())
    }
}

/// Maps a value tag to the allocation domain the serial heap would assign.
const fn domain_for_tag(tag: ValueTag) -> HeapAllocationDomain {
    match tag {
        ValueTag::Lambda | ValueTag::Primop | ValueTag::Thunk => HeapAllocationDomain::Worker,
        _ => HeapAllocationDomain::PermanentShared,
    }
}

impl EvalHeap {
    /// Creates an evaluator heap that allocates into `shard` of the shared
    /// `arena` and resolves values across every shard (parallel mode).
    ///
    /// The serial machinery (record table, bump arenas, GC bookkeeping) stays
    /// present but empty; all allocation and resolution dispatches to the
    /// shared backend. Callers are expected to run with GC quiesced
    /// (`TreeWalkOptions::parallel_workers` forces `GcStressPolicy::disabled()`).
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids
    /// (inherited from [`EvalHeap::new`]).
    pub fn with_shared_shard(arena: Arc<SharedHeapArena>, shard: Arc<SharedHeapShard>) -> Self {
        let mut heap = Self::new();
        heap.shared = Some(SharedHeapBackend::new(arena, shard));
        heap
    }

    /// Returns the shared arena backing this heap in parallel mode.
    pub fn shared_arena(&self) -> Option<&Arc<SharedHeapArena>> {
        self.shared.as_ref().map(SharedHeapBackend::arena)
    }

    /// Returns whether this heap allocates into a shared arena (parallel mode).
    pub fn uses_shared_arena(&self) -> bool {
        self.shared.is_some()
    }

    /// Borrows the shared backend or reports the internal invariant break.
    fn shared_backend(&self) -> Result<&SharedHeapBackend, EvalHeapError> {
        self.shared
            .as_ref()
            .ok_or(EvalHeapError::SharedBackendMissing)
    }

    /// Shared-mode [`EvalHeap::alloc_string`]: per-worker hash-cons over the
    /// worker's own shard, then shard publication.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if cons-table storage cannot be reserved or
    /// the shard rejects the allocation.
    pub(super) fn shared_alloc_string(&mut self, string: NixString) -> Result<Value, EvalHeapError> {
        let hash = string.structural_hash_xxh3();
        let existing = {
            let shared = self.shared_backend()?;
            self.string_cons
                .try_find(&hash, |value| {
                    let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
                    Ok::<bool, EvalHeapError>(matches!(
                        shared.resolve_flat_string(ptr, FlatObjectKind::String),
                        Some(candidate) if candidate.structural_hash() == hash.raw()
                            && candidate.payload() == &string
                    ))
                })?
                .copied()
        };
        if let Some(value) = existing {
            self.alloc_counters.note_hashcons(true);
            return Ok(value);
        }
        self.alloc_counters.note_hashcons(false);
        self.alloc_counters
            .note_string_payload(string.len(), string.bytes().starts_with(b"/nix/store/"));
        let slot = self
            .string_cons
            .reserve_slot(hash)
            .map_err(EvalHeapError::from)?;
        let result = match self.shared.as_ref() {
            Some(shared) => shared
                .shard
                .publish_flat_string(FlatObjectKind::String, hash.raw(), string)
                .map_err(EvalHeapError::SharedArena),
            None => Err(EvalHeapError::SharedBackendMissing),
        };
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                self.cancel_string_cons_slot(slot);
                return Err(error);
            }
        };
        self.push_string_cons_value(slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Shared-mode [`EvalHeap::alloc_path`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if cons-table storage cannot be reserved or
    /// the shard rejects the allocation.
    pub(super) fn shared_alloc_path(&mut self, path: NixString) -> Result<Value, EvalHeapError> {
        let hash = path.structural_hash_xxh3();
        let existing = {
            let shared = self.shared_backend()?;
            self.path_cons
                .try_find(&hash, |value| {
                    let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
                    Ok::<bool, EvalHeapError>(matches!(
                        shared.resolve_flat_string(ptr, FlatObjectKind::Path),
                        Some(candidate) if candidate.structural_hash() == hash.raw()
                            && candidate.payload() == &path
                    ))
                })?
                .copied()
        };
        if let Some(value) = existing {
            self.alloc_counters.note_hashcons(true);
            return Ok(value);
        }
        self.alloc_counters.note_hashcons(false);
        self.alloc_counters.note_path_payload(path.len());
        let slot = self
            .path_cons
            .reserve_slot(hash)
            .map_err(EvalHeapError::from)?;
        let result = match self.shared.as_ref() {
            Some(shared) => shared
                .shard
                .publish_flat_string(FlatObjectKind::Path, hash.raw(), path)
                .map_err(EvalHeapError::SharedArena),
            None => Err(EvalHeapError::SharedBackendMissing),
        };
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                self.cancel_path_cons_slot(slot);
                return Err(error);
            }
        };
        self.push_path_cons_value(slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Shared-mode [`EvalHeap::alloc_list`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if cons-table storage cannot be reserved or
    /// the shard rejects the allocation.
    pub(super) fn shared_alloc_list(&mut self, list: NixList) -> Result<Value, EvalHeapError> {
        let hash = list_structural_hash(&list);
        let existing = {
            let shared = self.shared_backend()?;
            self.list_cons
                .try_find(&hash, |value| {
                    let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
                    Ok::<bool, EvalHeapError>(matches!(
                        shared.resolve_flat_list(ptr),
                        Some(candidate) if candidate.structural_hash() == hash.raw()
                            && candidate.payload().raw_eq(&list)
                    ))
                })?
                .copied()
        };
        if let Some(value) = existing {
            self.alloc_counters.note_hashcons(true);
            return Ok(value);
        }
        self.alloc_counters.note_hashcons(false);
        self.alloc_counters.note_list_payload(list.len());
        let slot = self
            .list_cons
            .reserve_slot(hash)
            .map_err(EvalHeapError::from)?;
        let result = match self.shared.as_ref() {
            Some(shared) => shared
                .shard
                .publish_flat_list(hash.raw(), list)
                .map_err(EvalHeapError::SharedArena),
            None => Err(EvalHeapError::SharedBackendMissing),
        };
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                self.cancel_list_cons_slot(slot);
                return Err(error);
            }
        };
        self.push_list_cons_value(slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Shared-mode [`EvalHeap::alloc_attrs_with_projected_shape_metadata`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the attrset length overflows the runtime
    /// slot count, if cons-table storage cannot be reserved, or if the shard
    /// rejects the allocation.
    pub(super) fn shared_alloc_attrs_with_projected_shape_metadata(
        &mut self,
        shape: u32,
        repr: crate::attrs::repr::AttrSetReprKind,
        projected_shape: Option<crate::attrs::shape::ShapeId>,
        attrs: FlatAttrs,
    ) -> Result<Value, EvalHeapError> {
        self.alloc_counters.note_attrs_built(attrs.len());
        let metadata = match projected_shape {
            Some(projected_shape) => {
                EvalHeapAttrsMetadata::with_projected_shape(shape, repr, projected_shape)
            }
            None => EvalHeapAttrsMetadata::new(shape, repr),
        };
        let hash = attrs_structural_hash(metadata, &attrs);
        let existing = {
            let shared = self.shared_backend()?;
            self.attrs_cons
                .try_find(&hash, |value| {
                    let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
                    Ok::<bool, EvalHeapError>(matches!(
                        shared.resolve_flat_attrs(ptr),
                        Some(candidate) if candidate.structural_hash() == hash.raw()
                            && candidate.payload().metadata == metadata
                            && candidate.payload().attrs.raw_eq(&attrs)
                    ))
                })?
                .copied()
        };
        if let Some(value) = existing {
            self.alloc_counters.note_hashcons(true);
            return Ok(value);
        }
        self.alloc_counters.note_hashcons(false);
        let slot = self
            .attrs_cons
            .reserve_slot(hash)
            .map_err(EvalHeapError::from)?;
        let result = match self.shared.as_ref() {
            Some(shared) => shared
                .shard
                .publish_flat_attrs(hash.raw(), FlatAttrsPayload { metadata, attrs })
                .map_err(EvalHeapError::SharedArena),
            None => Err(EvalHeapError::SharedBackendMissing),
        };
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                self.cancel_attrs_cons_slot(slot);
                return Err(error);
            }
        };
        self.push_attrs_cons_value(slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Shared-mode [`EvalHeap::alloc_lambda`] (no hash-cons; closure records
    /// are identity-allocated exactly like the serial worker domain).
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the shard rejects the allocation.
    pub(super) fn shared_alloc_lambda(&mut self, lambda: EvalLambda) -> Result<Value, EvalHeapError> {
        self.shared_alloc_flat_closure(
            FlatObjectKind::Lambda,
            FlatClosurePayload::Lambda(lambda),
        )
    }

    /// Shared-mode [`EvalHeap::alloc_primop`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the shard rejects the allocation.
    pub(super) fn shared_alloc_primop(&mut self, primop: EvalPrimOp) -> Result<Value, EvalHeapError> {
        self.shared_alloc_flat_closure(
            FlatObjectKind::Primop,
            FlatClosurePayload::Primop(primop),
        )
    }

    /// Shared-mode [`EvalHeap::alloc_thunk`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the shard rejects the allocation.
    pub(super) fn shared_alloc_thunk(&mut self, thunk: EvalThunk) -> Result<Value, EvalHeapError> {
        self.shared_alloc_flat_closure(
            FlatObjectKind::Thunk,
            FlatClosurePayload::Thunk(thunk),
        )
    }

    /// Publishes a worker-domain flat closure into the shard (doc 30 FV-3).
    ///
    /// The flat analog of the retired record-slot worker path: the payload
    /// handle publishes once behind the slot's release edge and is never
    /// swapped (shedding and the sweep are serial-only), so cross-worker
    /// readers resolve it by membership arithmetic with no address-index
    /// probe.
    fn shared_alloc_flat_closure(
        &mut self,
        kind: FlatObjectKind,
        payload: FlatClosurePayload,
    ) -> Result<Value, EvalHeapError> {
        let value = match self.shared.as_mut() {
            Some(shared) => shared.publish_flat_closure(kind, payload)?,
            None => return Err(EvalHeapError::SharedBackendMissing),
        };
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
