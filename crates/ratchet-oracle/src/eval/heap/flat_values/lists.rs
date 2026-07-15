//! Flat list allocation and resolution for the serial evaluator heap.
//!
//! RFC-0007 doc 30 stage FV-1, list slice: lists join strings and paths in
//! the flat object store. Like strings they are hash-consed, immortal,
//! permanent-domain values that never enter the record table; **unlike**
//! strings their element spine carries heap *edges*, which couples this store
//! into four GC surfaces:
//!
//! 1. **B1 sweep permanent-edge seeding** (`eval/heap/gc.rs`): every worker
//!    value held by a flat list seeds marking, exactly as record-backed
//!    permanent lists seeded it.
//! 2. **Worker-region-pop retained-edge validation** (`eval/heap/arena.rs`):
//!    flat lists are pinned (never popped), so every flat list is a retained
//!    source whose edges must not point into a popped region.
//! 3. **Collector-poll edge snapshots and writebacks** (`eval/heap/roots.rs`):
//!    precise scans synthesize the same `ListElement`-labelled edges a record
//!    scan produced, and minor-GC heap-field writebacks rewrite one element
//!    through the flat store's exclusive `resolve_mut` door under the staged
//!    commit discipline records used.
//! 4. **Edge scans** (`scan_flat_list_edges` beside `scan_record_edges`).
//!
//! # Hash staleness after writebacks
//!
//! A record writeback commit set `structural_hash = None`; the flat header's
//! hash word has no vacant state, so the heap keeps a sparse stale-address
//! side set instead (populated by `flat_list_commit_writeback`). Hash-cons
//! admission treats a stale address as never-matching (a dedup miss), which
//! preserves correctness: confirmation always compares spines with `raw_eq`.

use super::*;

impl EvalHeap {
    /// Serial [`EvalHeap::alloc_list`]: hash-cons admission over the flat
    /// list store, then one flat allocation (no heap record).
    pub(in crate::eval::heap) fn flat_alloc_list(
        &mut self,
        list: NixList,
    ) -> Result<Value, EvalHeapError> {
        let hash = crate::eval::heap::arena::list_structural_hash(&list);
        let cons_slot = match self.admit_flat_list_cons(hash, &list)? {
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
        self.alloc_counters.note_list_payload(list.len());
        let len = list.len();
        let epoch = self.next_access_epoch();
        // FV-4 measured decision: list spines stay a moved owned `Vec`
        // behind the flat object — they are *not* copied inline. A fresh
        // interned list pays an inline copy plus the freed-`Vec` teardown
        // where the move costs nothing, list-churn workloads are almost
        // entirely hash-cons misses (`bench.compute.qsort` held ~+1.5% wall
        // under 4096- and 512-byte inline caps), and no package/wide
        // workload showed a win from inline spines. Even the two-variant
        // spine storage alone (the enum tag on every element access) held
        // ~+1% on qsort, so `NixList` keeps its plain contiguous-`Vec`
        // representation; the trailing-array machinery serves attrsets,
        // where the same trade measurably pays. The header `aux` field
        // still carries the spine length.
        let allocation = match self.flat_lists.alloc_with_aux(
            FlatObjectKind::List,
            flat_aux_for_len(len),
            hash.raw(),
            epoch,
            list,
        ) {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_list_cons_slot(cons_slot);
                return Err(flat_alloc_error(error));
            }
        };
        self.permanent_allocator
            .record_flat_list_allocation_safepoint(len, allocation.allocation);
        let value = match Value::list(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_list_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.push_list_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Serial `get_list` resolution through the flat list store.
    ///
    /// One membership check plus one header load; the record table is only
    /// consulted on the error path, to preserve record-type-mismatch error
    /// fidelity for non-flat pointers.
    #[inline]
    pub(in crate::eval::heap) fn flat_get_list(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&NixList, EvalHeapError> {
        match self.flat_lists.resolve(ptr, FlatObjectKind::List) {
            Ok(object) => {
                self.deref_counters.note_flat_resolution(ValueTag::List);
                if self.epoch_tracking_enabled {
                    object.touch(self.next_access_epoch());
                }
                Ok(object.payload())
            }
            Err(error) => Err(self.flat_resolution_error(ValueTag::List, ptr, error)),
        }
    }

    /// Resolves a flat list and stamps its access epoch.
    pub(super) fn flat_touch_list(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<FlatObjectRef<'_, NixList>, EvalHeapError> {
        match self.flat_lists.resolve(ptr, FlatObjectKind::List) {
            Ok(object) => {
                if self.epoch_tracking_enabled {
                    object.touch(self.next_access_epoch());
                }
                Ok(object)
            }
            Err(error) => Err(self.flat_resolution_error(ValueTag::List, ptr, error)),
        }
    }

    /// Resolves a flat list without stamping its access epoch (scan paths).
    pub(in crate::eval::heap) fn flat_list_payload(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<&NixList, EvalHeapError> {
        match self.flat_lists.resolve(ptr, FlatObjectKind::List) {
            Ok(object) => Ok(object.payload()),
            Err(error) => Err(self.flat_resolution_error(ValueTag::List, ptr, error)),
        }
    }

    /// Overwrites a flat list's element spine in place (writeback commits).
    ///
    /// This is the flat analog of the record table's staged heap-field
    /// writeback commit: the header (address identity, kind) is untouched,
    /// the payload is replaced wholesale, the header hash is marked stale
    /// until the enclosing structural-writeback commit repairs the header and
    /// hash-cons bucket, and the address's cutoff-cache hashes are dropped.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `ptr` is not a flat list of this heap.
    pub(in crate::eval::heap) fn flat_list_commit_writeback(
        &mut self,
        ptr: NonNull<HeapObject>,
        list: NixList,
    ) -> Result<(), EvalHeapError> {
        match self.flat_lists.resolve_mut(ptr, FlatObjectKind::List) {
            Ok(payload) => {
                *payload = list;
            }
            Err(error) => return Err(self.flat_resolution_error(ValueTag::List, ptr, error)),
        }
        let address = ptr.as_ptr() as usize;
        self.flat_stale_hashes.insert(address);
        self.flat_cold_hashes.clear(address);
        Ok(())
    }

    /// Hash-cons admission for serial lists over the flat list store.
    ///
    /// Confirmation compares the header hash word and the element spine
    /// (`raw_eq`). The stale-address check is a fail-closed guard for a
    /// payload write whose enclosing structural commit has not yet published.
    fn admit_flat_list_cons(
        &mut self,
        hash: HotXxh3Hash,
        list: &NixList,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let flat_lists = &self.flat_lists;
            let stale = &self.flat_stale_hashes;
            self.list_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
                    if !stale.is_empty() && stale.contains(&(ptr.as_ptr() as usize)) {
                        return Ok(false);
                    }
                    let object = flat_lists
                        .resolve(ptr, FlatObjectKind::List)
                        .map_err(|_| EvalHeapError::unknown(ValueTag::List, ptr))?;
                    let same_hash = object.structural_hash() == hash.raw();
                    Ok::<bool, EvalHeapError>(same_hash && object.payload().raw_eq(list))
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        Ok(HashConsReservation::Vacant(
            self.list_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }
}
