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

mod active_values;
pub(super) mod attrs;
pub(super) mod closures;
#[cfg(feature = "candidate_c_value")]
pub(super) mod evacuated_closures;
#[cfg(feature = "candidate_c_value")]
pub(super) mod evacuated_permanent;
#[cfg(feature = "candidate_c_value")]
pub(super) mod permanent_batch_copy;
#[cfg(feature = "candidate_c_value")]
pub(super) mod permanent_publication;
pub(super) mod thunk_heads;
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

#[cfg(feature = "candidate_c_value")]
use evacuated_closures::EvacuatedClosureGeneration;
#[cfg(feature = "candidate_c_value")]
use evacuated_permanent::EvacuatedPermanentGeneration;

/// Owns every typed store in one compact Candidate-C destination generation.
///
/// Construction creates exactly one reservation/domain and gives each typed
/// subowner a clone of that shared arena. The arena field is declared last so
/// aggregate teardown drops every payload-owning store before releasing the
/// final reservation handle.
#[cfg(feature = "candidate_c_value")]
#[derive(Debug)]
pub(in crate::eval::heap) struct EvacuatedGeneration {
    closures: EvacuatedClosureGeneration,
    permanent: EvacuatedPermanentGeneration,
    arena: SharedFlatStoreArena,
}

#[cfg(feature = "candidate_c_value")]
impl EvacuatedGeneration {
    /// Creates an empty compact generation over one Candidate-C reservation.
    ///
    /// Returns `None` when Candidate-C reservation backing is unavailable.
    pub(in crate::eval::heap) fn new() -> Option<Self> {
        let arena = SharedFlatStoreArena::new();
        arena.arena_domain_id()?;
        let closures = EvacuatedClosureGeneration::with_shared_arena(arena.clone());
        let permanent = EvacuatedPermanentGeneration::with_shared_arena(arena.clone());
        Some(Self {
            closures,
            permanent,
            arena,
        })
    }

    /// Returns the compact generation's single Candidate-C domain.
    pub(in crate::eval::heap) fn domain(&self) -> Option<crate::heap::ArenaDomainId> {
        self.arena.arena_domain_id()
    }

    /// Returns the reserved virtual capacity backing the aggregate generation.
    pub(in crate::eval::heap) fn reservation_capacity(&self) -> Option<usize> {
        self.arena
            .reservation_stats()
            .map(|stats| stats.virtual_reserved_bytes)
    }

    /// Returns mutable access to the aggregate-owned closure stores.
    pub(in crate::eval::heap) fn closures_mut(&mut self) -> &mut EvacuatedClosureGeneration {
        &mut self.closures
    }

    /// Returns shared access to the aggregate-owned closure stores.
    pub(in crate::eval::heap) fn closures(&self) -> &EvacuatedClosureGeneration {
        &self.closures
    }

    /// Returns mutable access to the aggregate-owned permanent stores.
    pub(in crate::eval::heap) fn permanent_mut(&mut self) -> &mut EvacuatedPermanentGeneration {
        &mut self.permanent
    }

    /// Returns shared access to the aggregate-owned permanent stores.
    pub(in crate::eval::heap) fn permanent(&self) -> &EvacuatedPermanentGeneration {
        &self.permanent
    }

    /// Resolves a string pointer through the aggregate permanent stores.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is outside this generation or does
    /// not reference a live string.
    pub(in crate::eval::heap) fn get_string_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&NixString, EvalHeapError> {
        self.permanent
            .get_string(self.value_for_ptr(ValueTag::String, ptr)?)
    }

    /// Resolves a path pointer through the aggregate permanent stores.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is outside this generation or does
    /// not reference a live path.
    pub(in crate::eval::heap) fn get_path_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&NixString, EvalHeapError> {
        self.permanent
            .get_path(self.value_for_ptr(ValueTag::Path, ptr)?)
    }

    /// Resolves a list pointer through the aggregate permanent stores.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is outside this generation or does
    /// not reference a live list.
    pub(in crate::eval::heap) fn get_list_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&NixList, EvalHeapError> {
        self.permanent
            .get_list(self.value_for_ptr(ValueTag::List, ptr)?)
    }

    /// Resolves an attribute-set pointer through the aggregate permanent stores.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is outside this generation or does
    /// not reference a live attribute set.
    pub(in crate::eval::heap) fn get_attrs_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&FlatAttrs, EvalHeapError> {
        self.permanent
            .get_attrs(self.value_for_ptr(ValueTag::Attrs, ptr)?)
    }

    /// Resolves the complete attribute-set payload through the aggregate stores.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is outside this generation or does
    /// not reference a live attribute set.
    pub(in crate::eval::heap) fn get_attrs_payload_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&FlatAttrsPayload, EvalHeapError> {
        self.permanent
            .get_attrs_payload(self.value_for_ptr(ValueTag::Attrs, ptr)?)
    }

    /// Resolves attribute-set metadata through the aggregate permanent stores.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `ptr` is outside this generation or does
    /// not reference a live attribute set.
    pub(in crate::eval::heap) fn get_attrs_metadata_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<EvalHeapAttrsMetadata, EvalHeapError> {
        self.permanent
            .get_attrs_metadata(self.value_for_ptr(ValueTag::Attrs, ptr)?)
    }

    fn value_for_ptr(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<Value, EvalHeapError> {
        let domain = self.domain().ok_or(EvalHeapError::ShedRejected {
            address: ptr.as_ptr() as usize,
            reason: "evacuated aggregate generation has no Candidate-C domain",
        })?;
        let index = self
            .arena
            .index_for_pointer(ptr)
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated pointer is outside the aggregate reservation",
            })?;
        Value::from_domain_index(tag, domain, index).map_err(EvalHeapError::Value)
    }

    /// Extracts the closure owner for the phase-one installation seam.
    ///
    /// This compatibility door consumes the aggregate, so an independently
    /// constructed closure reservation remains impossible. The closure
    /// stores retain their clone of the aggregate arena.
    pub(in crate::eval::heap) fn into_closure_generation(self) -> EvacuatedClosureGeneration {
        self.closures
    }

    /// Extracts the permanent owner for focused phase-one relocation tests.
    ///
    /// This compatibility door consumes the aggregate and retains the same
    /// shared reservation through the permanent stores' arena clone.
    pub(in crate::eval::heap) fn into_permanent_generation(self) -> EvacuatedPermanentGeneration {
        self.permanent
    }
}

#[cfg(all(test, feature = "candidate_c_value"))]
mod evacuated_generation_tests {
    use super::*;
    use crate::attrs::AttrEntry;
    use crate::syntax::SymbolTable;

    #[test]
    fn mixed_destination_kinds_share_one_domain_and_global_index_space() {
        let mut source = EvalHeap::new();
        let Some(mut destination) = EvacuatedGeneration::new() else {
            return;
        };
        let primop = source
            .alloc_primop(EvalPrimOp::with_args(
                Symbol::new(17),
                vec![EvalPrimOpArg::new(
                    IrId::new(18),
                    Span::new(19, 20),
                    Value::int(21),
                )],
            ))
            .expect("source primop allocates");
        let string = source
            .alloc_string(NixString::from_bytes(vec![b's'; FLAT_INLINE_BYTES_MAX + 1]))
            .expect("source string allocates");
        let path = source
            .alloc_path(NixString::from_bytes(vec![b'p'; FLAT_INLINE_BYTES_MAX + 1]))
            .expect("source path allocates");
        let list_allocation = source
            .flat_lists
            .alloc_with_aux(
                FlatObjectKind::List,
                flat_aux_for_len(2),
                0x51_57,
                73,
                NixList::new(vec![Value::int(3), Value::int(5)]),
            )
            .expect("source list allocates");
        let list = source
            .value_for_flat_allocation(ValueTag::List, list_allocation.ptr)
            .expect("source list value publishes");
        let mut symbols = SymbolTable::new();
        let first = symbols.intern(b"first").expect("first symbol interns");
        let second = symbols.intern(b"second").expect("second symbol interns");
        let attrs_payload = FlatAttrs::new(
            vec![
                AttrEntry::new(first, Value::int(13)),
                AttrEntry::new(second, Value::int(21)),
            ],
            &symbols,
        )
        .expect("source attrs build");
        let attrs_metadata = EvalHeapAttrsMetadata::new(41, AttrSetReprKind::Flat);
        let attrs_allocation = source
            .flat_attrs
            .alloc_with_aux(
                FlatObjectKind::Attrs,
                flat_aux_for_len(2),
                0xa7_75,
                89,
                FlatAttrsPayload {
                    metadata: attrs_metadata,
                    attrs: attrs_payload,
                },
            )
            .expect("source attrs allocate");
        let attrs = source
            .value_for_flat_allocation(ValueTag::Attrs, attrs_allocation.ptr)
            .expect("source attrs value publishes");

        let moved_primop = source
            .relocate_plain_primop_to_generation(destination.closures_mut(), primop, |value| value)
            .expect("primop relocates");
        let moved_string = destination
            .permanent_mut()
            .relocate_string_from(&mut source.flat, string)
            .expect("string relocates");
        let moved_path = destination
            .permanent_mut()
            .relocate_path_from(&mut source.flat, path)
            .expect("path relocates");
        let moved_list = destination
            .permanent_mut()
            .relocate_list_from(&mut source.flat_lists, list, |value| value)
            .expect("list relocates");
        let moved_attrs = destination
            .permanent_mut()
            .relocate_attrs_from(&mut source.flat_attrs, attrs, |value| value)
            .expect("attrs relocate");

        let domain = destination
            .domain()
            .expect("aggregate has one Candidate-C domain");
        assert_eq!(moved_primop.word().arena_domain(), Some(domain));
        assert_eq!(moved_string.word().arena_domain(), Some(domain));
        assert_eq!(moved_path.word().arena_domain(), Some(domain));
        assert_eq!(moved_list.word().arena_domain(), Some(domain));
        assert_eq!(moved_attrs.word().arena_domain(), Some(domain));
        assert_eq!(destination.closures().domain(), Some(domain));
        assert_eq!(destination.permanent().domain(), Some(domain));

        let primop_index = moved_primop
            .word()
            .arena_index()
            .expect("moved primop has an arena index");
        let string_index = moved_string
            .word()
            .arena_index()
            .expect("moved string has an arena index");
        assert_ne!(primop_index, string_index);
        assert_eq!(
            destination.arena.pointer_for_index(primop_index),
            Some(
                moved_primop
                    .as_primop_ptr()
                    .expect("moved primop has a pointer")
            )
        );
        assert_eq!(
            destination.arena.pointer_for_index(string_index),
            Some(
                moved_string
                    .as_string_ptr()
                    .expect("moved string has a pointer")
            )
        );
        assert_eq!(
            destination
                .closures()
                .get_primop(moved_primop)
                .expect("closure store resolves")
                .symbol(),
            Symbol::new(17)
        );
        assert_eq!(
            destination
                .permanent()
                .get_string(moved_string)
                .expect("permanent store resolves")
                .bytes()[0],
            b's'
        );

        let string_ptr = moved_string
            .as_string_ptr()
            .expect("moved string has a pointer");
        let path_ptr = moved_path.as_path_ptr().expect("moved path has a pointer");
        let list_ptr = moved_list.as_list_ptr().expect("moved list has a pointer");
        let attrs_ptr = moved_attrs
            .as_attrs_ptr()
            .expect("moved attrs has a pointer");
        source
            .install_evacuated_closure_generation(destination)
            .expect("aggregate owner and resolver install together");
        assert_eq!(
            source
                .get_primop(moved_primop)
                .expect("installed closure subowner remains routable")
                .symbol(),
            Symbol::new(17)
        );
        assert_eq!(
            source
                .get_string(moved_string)
                .expect("installed string routes by value"),
            source
                .get_string_ptr(string_ptr)
                .expect("installed string routes by pointer")
        );
        assert_eq!(
            source
                .get_path(moved_path)
                .expect("installed path routes by value"),
            source
                .get_path_ptr(path_ptr)
                .expect("installed path routes by pointer")
        );
        assert!(std::ptr::eq(
            source
                .get_list(moved_list)
                .expect("installed list routes by value"),
            source
                .get_list_ptr(list_ptr)
                .expect("installed list routes by pointer")
        ));
        assert!(std::ptr::eq(
            source
                .get_attrs(moved_attrs)
                .expect("installed attrs route by value"),
            source
                .get_attrs_ptr(attrs_ptr)
                .expect("installed attrs route by pointer")
        ));
        assert_eq!(
            source
                .get_attrs_metadata(moved_attrs)
                .expect("installed attrs metadata routes by value"),
            source
                .get_attrs_metadata_ptr(attrs_ptr)
                .expect("installed attrs metadata routes by pointer")
        );
    }

    #[test]
    fn aggregate_and_extracted_owner_keep_one_registration_until_final_drop() {
        let Some(destination) = EvacuatedGeneration::new() else {
            return;
        };
        let domain = destination
            .domain()
            .expect("aggregate has a Candidate-C domain");
        assert!(
            crate::heap::reservation_base(domain).is_some(),
            "aggregate construction registers its sole reservation"
        );

        let closures = destination.into_closure_generation();
        assert!(
            crate::heap::reservation_base(domain).is_some(),
            "the extracted phase-one owner retains the shared reservation"
        );
        drop(closures);
        assert!(
            crate::heap::reservation_base(domain).is_none(),
            "the final owner withdraws the domain before releasing the mapping"
        );
    }
}

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
        FlatObjectKind::ThunkHead => ValueTag::Thunk,
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
    /// Builds a runtime handle for one just-allocated serial flat object.
    ///
    /// Candidate C already caches this heap's reservation identity, so its
    /// allocation path encodes the known pointer as `base + index` directly
    /// instead of scanning the process-global reverse registry. Compatibility
    /// heaps and other carriers retain the context-free constructor.
    pub(super) fn value_for_flat_allocation(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<Value, EvalHeapError> {
        #[cfg(feature = "candidate_c_value")]
        if let Some(resolver) = self.serial_reservation {
            let address = ptr.as_ptr() as usize;
            if let Some(offset) = address.checked_sub(resolver.base)
                && offset < resolver.capacity
                && let Ok(offset) = u32::try_from(offset)
            {
                return Value::from_domain_index(
                    tag,
                    resolver.domain,
                    crate::heap::ArenaIndex::new(offset),
                )
                .map_err(EvalHeapError::Value);
            }
        }
        Value::heap(tag, ptr).map_err(EvalHeapError::Value)
    }

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
        let value = match self.value_for_flat_allocation(ValueTag::String, allocation.ptr) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_string_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.push_string_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        #[cfg(feature = "peak_ordinal_probe")]
        self.note_peak_ordinal_publication(ValueTag::String);
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
            self.flat
                .alloc(FlatObjectKind::Path, hash.raw(), epoch, path)
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
        let value = match self.value_for_flat_allocation(ValueTag::Path, allocation.ptr) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_path_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.push_path_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        #[cfg(feature = "peak_ordinal_probe")]
        self.note_peak_ordinal_publication(ValueTag::Path);
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
                #[cfg(feature = "lifetime_cohort_probe")]
                self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::StringOrPath);
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
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            let generation =
                self.evacuated_generation
                    .as_ref()
                    .ok_or(EvalHeapError::ShedRejected {
                        address: ptr.as_ptr() as usize,
                        reason: "evacuated resolver has no aggregate generation owner",
                    })?;
            return match tag {
                ValueTag::String => generation.get_string_ptr(ptr).map(|_| ()),
                ValueTag::Path => generation.get_path_ptr(ptr).map(|_| ()),
                ValueTag::List => generation.get_list_ptr(ptr).map(|_| ()),
                ValueTag::Attrs => generation.get_attrs_payload_ptr(ptr).map(|_| ()),
                _ => Err(EvalHeapError::unknown(tag, ptr)),
            };
        }
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
            FlatObjectError::KindMismatch { actual, .. } => {
                EvalHeapError::record_type_mismatch(tag, value_tag_for_flat_kind(actual), ptr)
            }
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
            | FlatObjectError::RelocationRequiresPlainObject { .. }
            | FlatObjectError::RelocationRequiresDistinctBacking { .. }
            | FlatObjectError::SharedArenaRegionUnsupported) => {
                // Unreachable from resolution (the heap resolves each kind
                // through the store allowed to type it); keep a loud mapping.
                debug_assert!(
                    false,
                    "flat resolution returned an allocation error: {error}"
                );
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
        if self.typed_thunk_heads.contains(ptr) {
            return Some(ValueTag::Thunk);
        }
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
        #[cfg(feature = "lifetime_cohort_probe")]
        self.observe_lifetime_quarantine_ptr(
            ptr,
            match tag {
                ValueTag::String | ValueTag::Path => LifetimeQuarantineOrigin::StringOrPath,
                ValueTag::List => LifetimeQuarantineOrigin::List,
                ValueTag::Attrs => LifetimeQuarantineOrigin::Attrs,
                _ => LifetimeQuarantineOrigin::Record,
            },
        );
        self.flat_canonical_address_unobserved(tag, ptr)
    }

    /// Resolves one reusable flat address without recording a semantic origin.
    ///
    /// Hash-cons exact hits record their more precise origin before entering
    /// this door.
    pub(super) fn flat_canonical_address_unobserved(
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
        self.flat_cold_hashes
            .write(address, |slot| slot.value = hash);
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
        | FlatObjectError::RelocationRequiresPlainObject { .. }
        | FlatObjectError::RelocationRequiresDistinctBacking { .. }
        | FlatObjectError::SharedArenaRegionUnsupported => {
            // Unreachable from allocation (each kind is allocated through the
            // store allowed to host it); surface a record failure loudly.
            debug_assert!(
                false,
                "flat allocation returned a resolution error: {error}"
            );
            EvalHeapError::RecordAllocationFailed { records: 1 }
        }
    }
}
