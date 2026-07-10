//! Flat attribute-set allocation and resolution for the serial evaluator heap.
//!
//! RFC-0007 doc 30 stage FV-2: attrsets join strings, paths, and lists in the
//! flat object stores. Like lists they are hash-consed, immortal,
//! permanent-domain values whose fields carry heap *edges* (one per entry
//! value), which couples this store into the same four GC surfaces the flat
//! list store wired:
//!
//! 1. **B1 sweep permanent-edge seeding** (`eval/heap/gc.rs`): every worker
//!    value held by a flat attrset seeds marking, exactly as record-backed
//!    permanent attrsets seeded it.
//! 2. **Worker-region-pop retained-edge validation** (`eval/heap/arena.rs`):
//!    flat attrsets are pinned (never popped), so every flat attrset is a
//!    retained source whose entry edges must not point into a popped region.
//! 3. **Collector-poll edge snapshots and writebacks** (`eval/heap/roots.rs`):
//!    precise scans synthesize the same `AttrBinding`-labelled edges a record
//!    scan produced, and minor-GC heap-field writebacks rewrite one entry
//!    value through the flat store's exclusive `resolve_mut` door under the
//!    staged commit discipline records used.
//! 4. **Edge scans** (`scan_flat_attrs_edges` beside `scan_record_edges` and
//!    `scan_flat_list_edges`).
//!
//! # Metadata placement (the FV-2 header/shape-id decision)
//!
//! An attrset carries [`EvalHeapAttrsMetadata`] — the lowered shape id, the
//! optional projected hidden-class `ShapeId`, and the representation kind.
//! Doc 30 §2.1 sketches a header-resident shape id sharing header word 1 with
//! the structural hash; FV-2 instead keeps the full 64-bit hash-cons key in
//! the header (splitting it would weaken collision confirmation for *every*
//! flat kind) and puts the metadata at the **front of the payload**
//! ([`FlatAttrsPayload`]), immediately after the header words. The
//! select-cache guard (`get_attrs_metadata`) therefore still costs one flat
//! resolution — membership arithmetic plus a header-adjacent load — with no
//! record probe; the P5 select-cache contract (projected-`ShapeId` compare,
//! then offset load, then key recheck) is unchanged above the heap API.
//!
//! # Hash staleness after writebacks
//!
//! Same contract as flat lists: a collector-poll writeback that rewrites an
//! entry value marks the address in the heap's shared stale-hash side set, so
//! hash-cons admission never dedups against a rewritten attrset. Metadata is
//! immutable for the object's lifetime; only entry values are ever rewritten.

use crate::attrs::AttrEntry;

use super::*;

/// The flat payload of one attribute-set object: shape metadata followed by
/// the entry storage.
///
/// The metadata leads the struct so a metadata-only guard load touches the
/// bytes adjacent to the flat header (see the module docs for the placement
/// decision). Both fields are immutable after construction except through
/// the collector's exclusive writeback door, which replaces entry values but
/// never the metadata.
#[derive(Clone, Debug)]
pub(crate) struct FlatAttrsPayload {
    /// Shape metadata recorded at allocation (part of the hash-cons key).
    pub(crate) metadata: EvalHeapAttrsMetadata,
    /// The attribute entries behind the value.
    pub(crate) attrs: FlatAttrs,
}

impl EvalHeap {
    /// Returns whether new attrset allocations use structural hash-consing.
    pub(crate) const fn attrs_hash_cons_enabled(&self) -> bool {
        self.attrs_hash_cons_enabled
    }

    /// Selects whether new attrset allocations use structural hash-consing.
    ///
    /// Callers change this only on an empty heap before evaluation starts.
    pub(crate) fn set_attrs_hash_cons_enabled(&mut self, enabled: bool) {
        self.attrs_hash_cons_enabled = enabled;
    }

    pub(in crate::eval::heap) fn push_attrs_cons_value(
        &mut self,
        slot: HashConsSlot<HotXxh3Hash>,
        value: Value,
    ) {
        let pushed = self.attrs_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    pub(in crate::eval::heap) fn cancel_attrs_cons_slot(
        &mut self,
        slot: HashConsSlot<HotXxh3Hash>,
    ) {
        let canceled = self.attrs_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    /// Serial [`EvalHeap::alloc_attrs_with_projected_shape_metadata`]:
    /// hash-cons admission over the flat attrs store, then one flat
    /// allocation (no heap record).
    pub(in crate::eval::heap) fn flat_alloc_attrs(
        &mut self,
        metadata: EvalHeapAttrsMetadata,
        attrs: FlatAttrs,
    ) -> Result<Value, EvalHeapError> {
        let hash = crate::eval::heap::arena::attrs_structural_hash(metadata, &attrs);
        let slots = u32::try_from(attrs.len())
            .map_err(|_| EvalHeapError::Arena(ArenaError::SizeOverflow))?;
        let cons_slot = if self.attrs_hash_cons_enabled {
            match self.admit_flat_attrs_cons(hash, metadata, &attrs)? {
                HashConsReservation::Existing(value) => {
                    self.alloc_counters.note_hashcons(true);
                    self.touch_reusable_value(value)?;
                    return Ok(value);
                }
                HashConsReservation::Vacant(slot) => {
                    self.alloc_counters.note_hashcons(false);
                    Some(slot)
                }
            }
        } else {
            None
        };
        let epoch = self.next_access_epoch();
        let shape = metadata.shape();
        // FV-4: short entry arrays and their two order permutations are
        // copied inline into the flat allocation and the stored payload
        // keeps only the witnesses — no out-of-line `Vec` survives behind an
        // interned small attrset; the transient input arrays drop here.
        // Oversized attrsets keep their moved owned arrays (zero copy), the
        // same cutoff rationale as `FLAT_INLINE_BYTES_MAX` for strings: on
        // attrset-churn workloads (`bench.compute.attr-fixpoint`, ~1000
        // unique entries rebuilt per iteration) the unconditional inline
        // copy measured a 15-20% wall regression — a whole extra pass over
        // every unique payload.
        let allocation = {
            let entry_count = attrs.len();
            let per_entry =
                std::mem::size_of::<AttrEntry>() + 2 * std::mem::size_of::<u32>();
            let result = if entry_count <= FLAT_INLINE_ELEMENT_BYTES_MAX / per_entry {
                let mut tail = FlatTailLayout::new();
                tail.add_slice::<AttrEntry>(entry_count)
                    .and_then(|()| tail.add_slice::<u32>(entry_count))
                    .and_then(|()| tail.add_slice::<u32>(entry_count))
                    .and_then(|()| {
                        self.flat_attrs.alloc_with_trailing(
                            FlatObjectKind::Attrs,
                            flat_aux_for_len(entry_count),
                            hash.raw(),
                            epoch,
                            tail,
                            |writer| {
                                let entries = writer.write_slice(attrs.entries_by_symbol())?;
                                let source_order = writer.write_slice(attrs.source_order())?;
                                let iteration_order =
                                    writer.write_slice(attrs.iteration_order())?;
                                Ok(FlatAttrsPayload {
                                    metadata,
                                    attrs: FlatAttrs::from_flat_parts(
                                        entries,
                                        source_order,
                                        iteration_order,
                                    ),
                                })
                            },
                        )
                    })
            } else {
                self.flat_attrs.alloc_with_aux(
                    FlatObjectKind::Attrs,
                    flat_aux_for_len(entry_count),
                    hash.raw(),
                    epoch,
                    FlatAttrsPayload { metadata, attrs },
                )
            };
            match result {
                Ok(allocation) => allocation,
                Err(error) => {
                    if let Some(cons_slot) = cons_slot {
                        self.cancel_attrs_cons_slot(cons_slot);
                    }
                    return Err(flat_alloc_error(error));
                }
            }
        };
        self.permanent_allocator
            .record_flat_attrs_allocation_safepoint(shape, slots, allocation.allocation);
        let value = match Value::attrs(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                if let Some(cons_slot) = cons_slot {
                    self.cancel_attrs_cons_slot(cons_slot);
                }
                return Err(error);
            }
        };
        if let Some(cons_slot) = cons_slot {
            self.push_attrs_cons_value(cons_slot, value);
        }
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Serial `get_attrs` resolution through the flat attrs store.
    ///
    /// One membership check plus one header load; the record table is only
    /// consulted on the error path, to preserve record-type-mismatch error
    /// fidelity for non-flat pointers.
    #[inline]
    pub(in crate::eval::heap) fn flat_get_attrs(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&FlatAttrs, EvalHeapError> {
        match self.flat_attrs.resolve(ptr, FlatObjectKind::Attrs) {
            Ok(object) => {
                self.deref_counters.note_flat_resolution(ValueTag::Attrs);
                object.touch(self.next_access_epoch());
                Ok(&object.payload().attrs)
            }
            Err(error) => Err(self.flat_resolution_error(ValueTag::Attrs, ptr, error)),
        }
    }

    /// Serial `get_attrs_metadata` resolution through the flat attrs store.
    ///
    /// The select-cache guard path: the metadata words sit at the front of
    /// the payload, directly after the flat header, so the guard costs one
    /// header-adjacent load with no record probe.
    #[inline]
    pub(in crate::eval::heap) fn flat_get_attrs_metadata(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<EvalHeapAttrsMetadata, EvalHeapError> {
        match self.flat_attrs.resolve(ptr, FlatObjectKind::Attrs) {
            Ok(object) => {
                self.deref_counters.note_flat_resolution(ValueTag::Attrs);
                object.touch(self.next_access_epoch());
                Ok(object.payload().metadata)
            }
            Err(error) => Err(self.flat_resolution_error(ValueTag::Attrs, ptr, error)),
        }
    }

    /// Resolves a flat attrset and stamps its access epoch.
    pub(super) fn flat_touch_attrs(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<FlatObjectRef<'_, FlatAttrsPayload>, EvalHeapError> {
        match self.flat_attrs.resolve(ptr, FlatObjectKind::Attrs) {
            Ok(object) => {
                object.touch(self.next_access_epoch());
                Ok(object)
            }
            Err(error) => Err(self.flat_resolution_error(ValueTag::Attrs, ptr, error)),
        }
    }

    /// Resolves a flat attrset without stamping its access epoch (scan paths).
    pub(in crate::eval::heap) fn flat_attrs_payload(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&FlatAttrsPayload, EvalHeapError> {
        match self.flat_attrs.resolve(ptr, FlatObjectKind::Attrs) {
            Ok(object) => Ok(object.payload()),
            Err(error) => Err(self.flat_resolution_error(ValueTag::Attrs, ptr, error)),
        }
    }

    /// Overwrites a flat attrset's entry storage in place (writeback commits).
    ///
    /// The attrs analog of `flat_list_commit_writeback`: the header (address
    /// identity, kind) and the payload metadata are untouched, the entry
    /// storage is replaced wholesale, the header hash is marked stale until
    /// the enclosing structural-writeback commit repairs the header and
    /// hash-cons bucket, and the address's cutoff-cache hashes are dropped.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `ptr` is not a flat attrset of this heap.
    pub(in crate::eval::heap) fn flat_attrs_commit_writeback(
        &mut self,
        ptr: NonNull<HeapObject>,
        attrs: FlatAttrs,
    ) -> Result<(), EvalHeapError> {
        match self.flat_attrs.resolve_mut(ptr, FlatObjectKind::Attrs) {
            Ok(payload) => {
                payload.attrs = attrs;
            }
            Err(error) => return Err(self.flat_resolution_error(ValueTag::Attrs, ptr, error)),
        }
        let address = ptr.as_ptr() as usize;
        self.flat_stale_hashes.insert(address);
        self.flat_cold_hashes.clear(address);
        Ok(())
    }

    /// Hash-cons admission for serial attrsets over the flat attrs store.
    ///
    /// Confirmation compares the header hash word, the metadata (part of the
    /// structural key, exactly as the record-backed admission compared it),
    /// and the entry storage (`raw_eq`). The stale-address check is a
    /// fail-closed guard for a payload write whose enclosing structural
    /// commit has not yet published.
    fn admit_flat_attrs_cons(
        &mut self,
        hash: HotXxh3Hash,
        metadata: EvalHeapAttrsMetadata,
        attrs: &FlatAttrs,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let flat_attrs = &self.flat_attrs;
            let stale = &self.flat_stale_hashes;
            self.attrs_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
                    if !stale.is_empty() && stale.contains(&(ptr.as_ptr() as usize)) {
                        return Ok(false);
                    }
                    let object = flat_attrs
                        .resolve(ptr, FlatObjectKind::Attrs)
                        .map_err(|_| EvalHeapError::unknown(ValueTag::Attrs, ptr))?;
                    let same_hash = object.structural_hash() == hash.raw();
                    let payload = object.payload();
                    Ok::<bool, EvalHeapError>(
                        same_hash
                            && payload.metadata == metadata
                            && payload.attrs.raw_eq(attrs),
                    )
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        Ok(HashConsReservation::Vacant(
            self.attrs_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }
}
