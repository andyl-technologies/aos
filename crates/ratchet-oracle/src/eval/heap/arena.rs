//! Allocation, lookup, and cons-table machinery for the [`EvalHeap`] arena.

use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use xxhash_rust::xxh3::Xxh3;

use crate::heap::{
    ArenaMemoryAdviceReport, GcHeapAddress, HeapMemoryBudget, HeapMemoryBudgetResponse,
    HeapMemorySample, MemoryAdviceKind, MemoryAdviceOutcome, ProcessResidentMemorySample,
    ProcessResidentMemorySource, RegionPlan, advise_cold_heap_object_allocation,
    advise_evict_heap_object_allocation,
};

use super::*;

static NEXT_HEAP_REGION_OWNER: AtomicU64 = AtomicU64::new(1);

/// A thunk handle detached from the heap for the force path (doc 15 §5.5).
///
/// [`EvalHeap::share_thunk`] returns this so the serial flat store can hand back
/// a cheap [`Shared`](Self::Shared) `Arc` clone minted on a thunk's first force,
/// while the record-table and shared-backend paths keep returning an
/// [`Owned`](Self::Owned) clone with no behavior change and no extra allocation
/// (I2 promotes those to `Shared` too). Both dereference to `&EvalThunk`, so the
/// serial and parallel force paths read the handle uniformly.
pub(crate) enum ClonedThunk {
    /// An owned clone, from the record-table or shared-backend paths (pre-I2).
    Owned(EvalThunk),
    /// A shared handle minted lazily on the serial flat force path (I1).
    Shared(Arc<EvalThunk>),
}

impl std::ops::Deref for ClonedThunk {
    type Target = EvalThunk;

    fn deref(&self) -> &EvalThunk {
        match self {
            Self::Owned(thunk) => thunk,
            Self::Shared(thunk) => thunk,
        }
    }
}

/// A whole-heap high-water memory-budget decision.
///
mod budget_types;
mod memory_governance;
mod values;

pub use budget_types::{
    EvalHeapCheapMemoryAdviceReport, EvalHeapCheapMemoryBudgetPlan,
    EvalHeapColdHashConsedAdviceReport, EvalHeapMemoryAdviceReport, EvalHeapMemoryBudgetAction,
    EvalHeapMemoryBudgetDecision, EvalHeapResidentMemoryMode, EvalHeapResidentMemorySource,
    EvalHeapTierBAdmissionPlan, EvalHeapTierBAdmissionRecord, EvalHeapTierBAdmissionReport,
};

impl EvalHeap {
    /// Samples physical residency for the serial Candidate-C reservation.
    ///
    /// Returns `None` when the heap uses the chunked compatibility backend. A
    /// present error means the operating system rejected the residency query.
    pub fn flat_reservation_residency(
        &self,
    ) -> Option<Result<crate::heap::ReservedArenaResidency, crate::heap::ReservedArenaError>> {
        self.flat_arena.reservation_residency()
    }

    /// Creates an empty evaluator heap.
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids.
    pub fn new() -> Self {
        Self::with_worker_allocator(RuntimeAllocator::tier_a_one_shot())
    }

    /// Creates an empty evaluator heap backed by the current thread's Tier-A arena.
    ///
    /// The heap still reports the [`RuntimeAllocatorTier::TierAOneShot`] tier,
    /// but worker storage comes from [`crate::heap::arena::ThreadLocalBumpArena`]
    /// through the same `aos_alloc_*` dispatch table. This is an opt-in
    /// per-worker precursor for the final CLI-wide Tier-A default.
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids, if
    /// the current thread already has an active thread-local runtime allocator,
    /// if the allocator owner-token counter is exhausted, or if the current
    /// thread's arena is already mutably borrowed.
    pub fn new_thread_local_tier_a() -> Self {
        Self::with_worker_allocator(RuntimeAllocator::tier_a_thread_local_empty())
    }

    fn with_worker_allocator(allocator: RuntimeAllocator) -> Self {
        Self::assemble_over_arena(SharedFlatStoreArena::new(), allocator)
    }

    /// Assembles an evaluator heap over an already-constructed serial flat arena.
    ///
    /// The shared field-initialization seam behind both the fresh constructor
    /// (a brand-new [`SharedFlatStoreArena`]) and the RFC-0007 doc-31 §1
    /// heap-image restore path (an arena mapped from a snapshot; see
    /// `eval::heap::snapshot`). Every arena-derived field — the flat string/path,
    /// list, and attrset stores, the compressed scalar store, and the worker
    /// closure store — is built over `flat_arena`; all remaining state is fresh
    /// and empty.
    pub(super) fn assemble_over_arena(
        flat_arena: SharedFlatStoreArena,
        allocator: RuntimeAllocator,
    ) -> Self {
        #[cfg(feature = "hole_reuse_shadow_probe")]
        if flat_arena.uses_reservation()
            && std::env::var("AOS_NIX_HOLE_REUSE_SHADOW").is_ok_and(|value| value == "1")
        {
            ratchet_value::heap::flat::hole_reuse_shadow::start_hole_reuse_shadow();
        }
        #[cfg(feature = "candidate_c_value")]
        let serial_reservation = serial_reservation_resolver(&flat_arena);
        let flat_closures = serial_flat_closure_store(&flat_arena);
        Self {
            allocator,
            permanent_allocator: PermanentSharedAllocator::new(),
            region_owner: next_heap_region_owner(),
            worker_allocator_epoch: 0,
            worker_region_epoch: 0,
            next_worker_region_mark: 1,
            worker_region_mark_stack: Vec::new(),
            access_epoch: Cell::new(0),
            epoch_tracking_enabled: false,
            memory_budget: None,
            resident_memory_mode: EvalHeapResidentMemoryMode::ArenaMappedBytes,
            memory_budget_poll_count: 0,
            last_memory_budget_action: None,
            records: HeapRecordTable::new(),
            string_cons: HashConsTable::new(),
            path_cons: HashConsTable::new(),
            list_cons: HashConsTable::new(),
            attrs_cons: HashConsTable::new(),
            attrs_hash_cons_enabled: true,
            alloc_counters: EvalHeapAllocationCounters::default(),
            #[cfg(feature = "peak_ordinal_probe")]
            peak_ordinal_probe: PeakOrdinalProbe::from_env(),
            deref_counters: EvalHeapDerefCounters::default(),
            #[cfg(feature = "lifetime_cohort_probe")]
            lifetime_quarantine: None,
            flat: FlatObjectStore::with_shared_arena(
                flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::String, FlatObjectKind::Path]),
            ),
            flat_lists: FlatObjectStore::with_shared_arena(
                flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::List]),
            ),
            flat_attrs: FlatObjectStore::with_shared_arena(
                flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::Attrs]),
            ),
            typed_thunk_heads: HeaderlessFlatLane::new(
                flat_arena.clone(),
                FlatObjectKind::ThunkHead,
            ),
            typed_thunk_work: TypedThunkWorkPool::default(),
            typed_node_thunk_work: TypedThunkWorkPool::default(),
            typed_apply_thunk_heads_enabled: false,
            #[cfg(feature = "active_packed_thunk_probe")]
            active_packed_thunks: active_packed_thunks::ActivePackedThunkStore::default(),
            compressed_scalars: crate::value::compressed::CandidateCScalarStore::new(
                flat_arena.clone(),
            ),
            flat_arena,
            flat_closures,
            flat_closures_retired: 0,
            worker_closure_placement: WorkerClosurePlacement::default(),
            flat_cold_hashes: FlatColdHashStore::default(),
            flat_stale_hashes: std::collections::HashSet::default(),
            shared: None,
            #[cfg(feature = "candidate_c_value")]
            serial_reservation,
            #[cfg(feature = "candidate_c_value")]
            evacuated_serial_reservation: None,
            #[cfg(feature = "candidate_c_value")]
            evacuated_generation: None,
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            packed_generation: None,
            #[cfg(feature = "candidate_c_value")]
            evacuated_closure_forwarding: None,
        }
    }

    /// Creates an empty evaluator heap with an explicit first arena chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Arena`] if the requested chunk size is invalid
    /// or overflows while being rounded to the arena word size.
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids.
    pub fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, EvalHeapError> {
        let flat_arena = SharedFlatStoreArena::with_initial_chunk_bytes(chunk_bytes)
            .map_err(EvalHeapError::Arena)?;
        Ok(Self {
            allocator: RuntimeAllocator::tier_a_with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            permanent_allocator: PermanentSharedAllocator::with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            region_owner: next_heap_region_owner(),
            worker_allocator_epoch: 0,
            worker_region_epoch: 0,
            next_worker_region_mark: 1,
            worker_region_mark_stack: Vec::new(),
            access_epoch: Cell::new(0),
            epoch_tracking_enabled: false,
            memory_budget: None,
            resident_memory_mode: EvalHeapResidentMemoryMode::ArenaMappedBytes,
            memory_budget_poll_count: 0,
            last_memory_budget_action: None,
            records: HeapRecordTable::new(),
            string_cons: HashConsTable::new(),
            path_cons: HashConsTable::new(),
            list_cons: HashConsTable::new(),
            attrs_cons: HashConsTable::new(),
            attrs_hash_cons_enabled: true,
            alloc_counters: EvalHeapAllocationCounters::default(),
            #[cfg(feature = "peak_ordinal_probe")]
            peak_ordinal_probe: PeakOrdinalProbe::from_env(),
            deref_counters: EvalHeapDerefCounters::default(),
            #[cfg(feature = "lifetime_cohort_probe")]
            lifetime_quarantine: None,
            flat: FlatObjectStore::with_shared_arena(
                flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::String, FlatObjectKind::Path]),
            ),
            flat_lists: FlatObjectStore::with_shared_arena(
                flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::List]),
            ),
            flat_attrs: FlatObjectStore::with_shared_arena(
                flat_arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::Attrs]),
            ),
            typed_thunk_heads: HeaderlessFlatLane::new(
                flat_arena.clone(),
                FlatObjectKind::ThunkHead,
            ),
            typed_thunk_work: TypedThunkWorkPool::default(),
            typed_node_thunk_work: TypedThunkWorkPool::default(),
            typed_apply_thunk_heads_enabled: false,
            #[cfg(feature = "active_packed_thunk_probe")]
            active_packed_thunks: active_packed_thunks::ActivePackedThunkStore::default(),
            compressed_scalars: crate::value::compressed::CandidateCScalarStore::new(
                flat_arena.clone(),
            ),
            flat_arena,
            flat_closures: FlatObjectStore::with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            flat_closures_retired: 0,
            worker_closure_placement: WorkerClosurePlacement::default(),
            flat_cold_hashes: FlatColdHashStore::default(),
            flat_stale_hashes: std::collections::HashSet::default(),
            shared: None,
            #[cfg(feature = "candidate_c_value")]
            serial_reservation: None,
            #[cfg(feature = "candidate_c_value")]
            evacuated_serial_reservation: None,
            #[cfg(feature = "candidate_c_value")]
            evacuated_generation: None,
            #[cfg(any(
                feature = "compact_destination_probe",
                feature = "evacuation_plan_probe"
            ))]
            packed_generation: None,
            #[cfg(feature = "candidate_c_value")]
            evacuated_closure_forwarding: None,
        })
    }

    /// Returns the configured automatic heap memory budget, if any.
    pub const fn memory_budget(&self) -> Option<HeapMemoryBudget> {
        self.memory_budget
    }

    /// Returns the allocation domain that owns `value`'s typed heap record.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an evaluator heap
    /// value. Returns [`EvalHeapError::UnknownPointer`] if the heap handle does
    /// not belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`]
    /// if the handle belongs to this heap but references another typed record.
    pub fn allocation_domain(&self, value: Value) -> Result<HeapAllocationDomain, EvalHeapError> {
        if let Some(shared) = &self.shared {
            return shared.allocation_domain(value);
        }
        let (tag, ptr) = any_value_heap_ptr(value)?;
        if matches!(
            tag,
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
        ) {
            self.flat_canonical_address(tag, ptr)?;
            return Ok(HeapAllocationDomain::PermanentShared);
        }
        // Flat worker closures (doc 30 FV-3) are worker-domain by
        // construction; the record path below serves the Tier-B B2 proving
        // ground's record placement.
        if let Some(actual) = self.flat_closure_tag(ptr) {
            return if actual == tag {
                #[cfg(feature = "lifetime_cohort_probe")]
                self.observe_lifetime_quarantine_ptr(
                    ptr,
                    LifetimeQuarantineOrigin::AllocationDomain,
                );
                Ok(HeapAllocationDomain::Worker)
            } else {
                Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
            };
        }
        if tag == ValueTag::Thunk && self.is_typed_thunk_head(ptr) {
            return Ok(HeapAllocationDomain::Worker);
        }
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            #[cfg(feature = "lifetime_cohort_probe")]
            self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::Record);
            Ok(record.allocation_domain)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    /// Returns the heap generation that currently owns `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an evaluator heap
    /// value. Returns [`EvalHeapError::UnknownPointer`] if the heap handle does
    /// not belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`]
    /// if the handle belongs to this heap but references another typed record.
    pub fn generation(&self, value: Value) -> Result<HeapGeneration, EvalHeapError> {
        if let Some(shared) = &self.shared {
            return shared.generation(value);
        }
        let (tag, ptr) = any_value_heap_ptr(value)?;
        if matches!(
            tag,
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
        ) {
            self.flat_canonical_address(tag, ptr)?;
            return Ok(HeapGeneration::Permanent);
        }
        // Flat worker closures (doc 30 FV-3) stay in their initial worker
        // generation: production never runs minor collections, and the B2
        // proving ground's generation machinery uses the record placement.
        if let Some(actual) = self.flat_closure_tag(ptr) {
            return if actual == tag {
                #[cfg(feature = "lifetime_cohort_probe")]
                self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::Generation);
                Ok(initial_generation_for_allocation_domain(
                    HeapAllocationDomain::Worker,
                ))
            } else {
                Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
            };
        }
        if tag == ValueTag::Thunk && self.is_typed_thunk_head(ptr) {
            return Ok(initial_generation_for_allocation_domain(
                HeapAllocationDomain::Worker,
            ));
        }
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            #[cfg(feature = "lifetime_cohort_probe")]
            self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::Record);
            Ok(record.generation)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    /// Replaces a heap record's allocation domain in evaluator tests.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an evaluator heap
    /// value. Returns [`EvalHeapError::UnknownPointer`] if the heap handle does
    /// not belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`]
    /// if the handle belongs to this heap but references another typed record.
    #[cfg(test)]
    pub(crate) fn set_allocation_domain_for_test(
        &mut self,
        value: Value,
        domain: HeapAllocationDomain,
    ) -> Result<(), EvalHeapError> {
        let (tag, ptr) = any_value_heap_ptr(value)?;
        // Flat strings/paths/lists/attrsets (doc 30 FV-1/FV-2) are
        // permanent-shared by construction and have no record; confirming
        // their intrinsic domain is a fixture no-op, anything else fails as
        // an unknown pointer.
        if self.shared.is_none()
            && matches!(
                tag,
                ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
            )
            && self.flat_kind_tag(ptr) == Some(tag)
        {
            if domain == HeapAllocationDomain::PermanentShared {
                return Ok(());
            }
            return Err(EvalHeapError::unknown(tag, ptr));
        }
        let address = ptr.as_ptr() as usize;
        let record = self
            .records
            .iter_mut()
            .find(|record| record.ptr.as_ptr() as usize == address)
            .ok_or_else(|| EvalHeapError::unknown(tag, ptr))?;
        let actual = record.object.tag();
        if actual != tag {
            return Err(EvalHeapError::record_type_mismatch(tag, actual, ptr));
        }
        record.allocation_domain = domain;
        record.generation = initial_generation_for_allocation_domain(domain);
        Ok(())
    }

    /// Returns the number of typed objects registered in this heap.
    pub fn len(&self) -> usize {
        if let Some(shared) = &self.shared {
            return shared.published_len();
        }
        self.records
            .len()
            .saturating_add(self.flat.len())
            .saturating_add(self.flat_lists.len())
            .saturating_add(self.flat_attrs.len())
            .saturating_add(self.typed_thunk_heads.len())
            .saturating_add(self.flat_closures.len())
    }

    /// Returns whether this heap contains no typed objects.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of typed objects in the record side table.
    ///
    /// Excludes flat objects (strings/paths/lists/attrsets per doc 30
    /// FV-1/FV-2 and worker closures per FV-3), which never enter the record
    /// table; Tier-B admission plans cover exactly this population. In
    /// production this reads zero — the table's only remaining population is
    /// the Tier-B B2 relocation proving ground's record-placed closures.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Returns the number of flat objects across every flat store: strings,
    /// paths, lists, attrsets (doc 30 FV-1/FV-2), and worker closures
    /// (doc 30 FV-3).
    pub fn flat_object_count(&self) -> usize {
        self.flat
            .len()
            .saturating_add(self.flat_lists.len())
            .saturating_add(self.flat_attrs.len())
            .saturating_add(self.typed_thunk_heads.len())
            .saturating_add(self.flat_closures.len())
    }

    #[cfg(test)]
    pub(crate) fn test_record_value(&self, index: usize) -> Option<Result<Value, EvalHeapError>> {
        self.records.get(index).map(Self::value_for_record)
    }

    #[cfg(test)]
    pub(crate) fn test_record_values(
        &self,
    ) -> impl Iterator<Item = Result<Value, EvalHeapError>> + '_ {
        self.records.iter().map(Self::value_for_record)
    }

    /// Enumerates live flat worker-closure values (doc 30 FV-3), for tests
    /// that inspect the worker population regardless of placement.
    #[cfg(test)]
    pub(crate) fn test_flat_closure_values(
        &self,
    ) -> impl Iterator<Item = Result<Value, EvalHeapError>> + '_ {
        self.flat_closures.iter().filter_map(|entry| {
            let payload = entry.object().payload();
            if payload.is_retired() {
                return None;
            }
            Some(Value::heap(payload.tag(), entry.ptr()).map_err(EvalHeapError::Value))
        })
    }

    fn reserve_record_slot(&mut self) -> Result<(), EvalHeapError> {
        let records = self
            .records
            .len()
            .checked_add(1)
            .ok_or(EvalHeapError::RecordLengthOverflow)?;
        self.records
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RecordAllocationFailed { records })
    }

    pub(super) fn push_string_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.string_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    pub(super) fn push_path_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.path_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    pub(super) fn push_list_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.list_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    pub(super) fn cancel_string_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.string_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    pub(super) fn cancel_path_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.path_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    pub(super) fn cancel_list_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.list_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    /// Linearly resolves `ptr` within an arbitrary record sub-slice.
    ///
    /// Whole-table resolution goes through the address-keyed index on
    /// [`super::HeapRecordTable`] and is `O(1)`; this scan is reserved for the
    /// bounded reclaimed-record sub-slice examined during a worker-region pop,
    /// whose length is the popped region size rather than the monotonic record
    /// count, so a scan is acceptable there.
    fn record_in(records: &[HeapRecord], ptr: NonNull<HeapObject>) -> Option<&HeapRecord> {
        let address = ptr.as_ptr() as usize;
        records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == address)
    }

    fn record_for_value(&self, value: Value) -> Result<&HeapRecord, EvalHeapError> {
        let (tag, ptr) = value_heap_ptr(value)?;
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            self.touch_record(record);
            Ok(record)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    pub(super) fn touch_reusable_value(&self, value: Value) -> Result<(), EvalHeapError> {
        let (tag, ptr) = value_heap_ptr(value)?;
        #[cfg(feature = "lifetime_cohort_probe")]
        self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::HashConsReuse);
        if self.shared.is_none()
            && matches!(
                tag,
                ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
            )
        {
            self.flat_canonical_address_unobserved(tag, ptr)?;
            return Ok(());
        }
        if self.shared.is_none() && tag == ValueTag::Thunk && self.is_typed_thunk_head(ptr) {
            return Ok(());
        }
        self.record_for_value(value)?;
        Ok(())
    }

    fn validate_worker_region_pop(
        &self,
        mark: EvalHeapWorkerRegionMark,
    ) -> Result<usize, EvalHeapError> {
        self.validate_worker_region_mark_is_innermost(mark)?;

        // A worker-region pop rewinds the bump arena, so a later allocation may
        // reuse a truncated record's address. That is only sound while the
        // Tier-B sweep has never retired a record: a retired record's address
        // must keep failing as an unknown pointer forever, and slot recycling
        // additionally breaks the "records are in allocation order" tail
        // assumption this validation depends on. Region pops and the sweep are
        // therefore mutually exclusive within one heap (RFC-0007 06 SS3.3/SS5).
        let retired_total = self
            .records
            .retired_total()
            .saturating_add(self.flat_closures_retired);
        if retired_total != 0 {
            return Err(EvalHeapError::RegionPopAfterSweep {
                retired: retired_total,
            });
        }

        let reclaimed = self.records.len() - mark.records;
        // The reclaimed suffix spans both worker-object populations: the
        // record-table suffix above `mark.records` and the flat closures
        // above the flat store's registry mark (doc 30 FV-3). Retained-edge
        // validation must reject an edge into either.
        let flat_suffix_start = mark.flat_closures.entries();
        let flat_suffix: std::collections::HashSet<
            usize,
            std::hash::BuildHasherDefault<record_table::AddressHasher>,
        > = self
            .flat_closures
            .iter()
            .skip(flat_suffix_start)
            .map(|entry| entry.ptr().as_ptr() as usize)
            .collect();
        let reclaimed_records = &self.records[mark.records..];
        let non_worker_records = reclaimed_records
            .iter()
            .filter(|record| record.allocation_domain != HeapAllocationDomain::Worker)
            .count();
        if non_worker_records != 0 {
            return Err(EvalHeapError::WorkerRegionPopNonWorkerRecords {
                records: non_worker_records,
            });
        }

        let target_in_suffix = |target_ptr: NonNull<HeapObject>| {
            Self::record_in(reclaimed_records, target_ptr).is_some()
                || (!flat_suffix.is_empty()
                    && flat_suffix.contains(&(target_ptr.as_ptr() as usize)))
        };

        for record in &self.records[..mark.records] {
            let source_address = gc_address_for_heap_record(record)?;
            for edge in self.scan_record_edges(record)? {
                let (_tag, target_ptr) = any_value_heap_ptr(edge.value())?;
                if target_in_suffix(target_ptr) {
                    return Err(EvalHeapError::WorkerRegionPopRetainedEdge {
                        source_address,
                        edge_source: edge.source().clone(),
                        target_address: GcHeapAddress::new(target_ptr.as_ptr() as usize)
                            .map_err(EvalHeapError::GenerationalGc)?,
                    });
                }
            }
        }

        // Flat worker closures below the marker are retained sources exactly
        // like retained records: their captured environments, application
        // operands, and primop arguments must not reference the reclaimed
        // suffix (doc 30 FV-3).
        for entry in self.flat_closures.iter().take(flat_suffix_start) {
            let source_address = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_closure_edges(entry.ptr(), entry.object().payload())? {
                let (_tag, target_ptr) = any_value_heap_ptr(edge.value())?;
                if target_in_suffix(target_ptr) {
                    return Err(EvalHeapError::WorkerRegionPopRetainedEdge {
                        source_address,
                        edge_source: edge.source().clone(),
                        target_address: GcHeapAddress::new(target_ptr.as_ptr() as usize)
                            .map_err(EvalHeapError::GenerationalGc)?,
                    });
                }
            }
        }

        // Flat lists and attrsets (doc 30 FV-1/FV-2) are permanent-domain
        // and pinned — they are never above a marker and never popped — but
        // their element spines and entry values carry edges, so every flat
        // list/attrset is a retained source: an edge into the reclaimed
        // suffix rejects the pop exactly as a retained record edge did
        // before flattening. Allocation order is irrelevant here (all flat
        // objects are retained), so the whole registries are walked.
        for entry in self.flat_lists.iter() {
            let source_address = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_list_edges(entry.object().payload())? {
                let (_tag, target_ptr) = any_value_heap_ptr(edge.value())?;
                if target_in_suffix(target_ptr) {
                    return Err(EvalHeapError::WorkerRegionPopRetainedEdge {
                        source_address,
                        edge_source: edge.source().clone(),
                        target_address: GcHeapAddress::new(target_ptr.as_ptr() as usize)
                            .map_err(EvalHeapError::GenerationalGc)?,
                    });
                }
            }
        }
        for entry in self.flat_attrs.iter() {
            let source_address = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_attrs_edges(entry.object().payload())? {
                let (_tag, target_ptr) = any_value_heap_ptr(edge.value())?;
                if target_in_suffix(target_ptr) {
                    return Err(EvalHeapError::WorkerRegionPopRetainedEdge {
                        source_address,
                        edge_source: edge.source().clone(),
                        target_address: GcHeapAddress::new(target_ptr.as_ptr() as usize)
                            .map_err(EvalHeapError::GenerationalGc)?,
                    });
                }
            }
        }

        Ok(reclaimed)
    }

    fn validate_tier_b_admission_plan(
        &self,
        plan: &EvalHeapTierBAdmissionPlan,
    ) -> Result<(), EvalHeapError> {
        let worker_stats = self.arena_stats();
        if worker_stats != plan.worker_stats {
            return Err(EvalHeapError::TierBAdmissionStaleArenaStats {
                domain: "worker",
                expected: plan.worker_stats,
                actual: worker_stats,
            });
        }

        let permanent_stats = self.permanent_arena_stats();
        if permanent_stats != plan.permanent_stats {
            return Err(EvalHeapError::TierBAdmissionStaleArenaStats {
                domain: "permanent-shared",
                expected: plan.permanent_stats,
                actual: permanent_stats,
            });
        }

        if self.records.len() != plan.records.len() {
            return Err(EvalHeapError::TierBAdmissionStaleRecordCount {
                expected_records: plan.records.len(),
                actual_records: self.records.len(),
            });
        }

        for (index, (record, planned)) in self.records.iter().zip(plan.records.iter()).enumerate() {
            let address = gc_address_for_heap_record(record)?;
            if address != planned.address {
                return Err(EvalHeapError::TierBAdmissionStaleRecordAddress {
                    index,
                    expected: planned.address,
                    actual: address,
                });
            }
            if record.allocation_domain != planned.allocation_domain {
                return Err(EvalHeapError::TierBAdmissionStaleRecordDomain {
                    index,
                    address,
                    expected: planned.allocation_domain,
                    actual: record.allocation_domain,
                });
            }
            if record.generation != planned.current_generation {
                return Err(EvalHeapError::TierBAdmissionStaleRecordGeneration {
                    index,
                    address,
                    expected: planned.current_generation,
                    actual: record.generation,
                });
            }
        }

        Ok(())
    }

    fn validate_worker_region_mark_is_innermost(
        &self,
        mark: EvalHeapWorkerRegionMark,
    ) -> Result<(), EvalHeapError> {
        // Stale-mark diagnostics count typed worker objects across both
        // placements (record-table records plus flat closures, doc 30 FV-3)
        // so the figures read the same whichever placement allocated them.
        let marker_records = mark.records.saturating_add(mark.flat_closures.entries());
        let current_records = self.records.len().saturating_add(self.flat_closures.len());
        if mark.owner != self.region_owner {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "marker was captured from another heap",
                marker_records,
                current_records,
            });
        }
        if mark.allocator_epoch != self.worker_allocator_epoch {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "worker allocator epoch changed",
                marker_records,
                current_records,
            });
        }
        if self.worker_region_mark_stack.last().copied() != Some(mark.mark_id) {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "worker region mark is not innermost",
                marker_records,
                current_records,
            });
        }
        if mark.records > self.records.len() {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "marker record prefix exceeds current records",
                marker_records,
                current_records,
            });
        }
        if mark.flat_closures.entries() > self.flat_closures.len() {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "marker flat-closure prefix exceeds current flat closures",
                marker_records,
                current_records,
            });
        }

        Ok(())
    }

    fn touch_record(&self, record: &HeapRecord) {
        #[cfg(feature = "lifetime_cohort_probe")]
        self.observe_lifetime_quarantine_ptr(record.ptr, LifetimeQuarantineOrigin::Record);
        record.last_touch_epoch.set(self.next_access_epoch());
    }

    pub(in crate::eval::heap) fn value_for_record(
        record: &HeapRecord,
    ) -> Result<Value, EvalHeapError> {
        Ok(Value::heap(record.object.tag(), record.ptr)?)
    }

    pub(super) fn advance_worker_region_epoch(&mut self) {
        if let Some(next) = self.worker_region_epoch.checked_add(1) {
            self.worker_region_epoch = next;
        } else {
            self.rotate_region_owner();
        }
    }

    pub(super) fn advance_worker_allocator_epoch(&mut self) {
        if let Some(next) = self.worker_allocator_epoch.checked_add(1) {
            self.worker_allocator_epoch = next;
        } else {
            self.rotate_region_owner();
        }
    }

    fn rotate_region_owner(&mut self) {
        self.region_owner = next_heap_region_owner();
        self.worker_allocator_epoch = 0;
        self.worker_region_epoch = 0;
        self.worker_region_mark_stack.clear();
    }

    pub(super) fn next_access_epoch(&self) -> u64 {
        let next_epoch = self.access_epoch.get().saturating_add(1);
        self.access_epoch.set(next_epoch);
        next_epoch
    }

    /// Enables per-resolve last-touch epoch stamping, off by default and set from
    /// the `heap_cheap_memory_advice_min_idle_epochs` option (its only consumer)
    /// so the hot resolve path pays nothing (RFC-0007 §P1 ledger lever 5).
    pub fn set_epoch_tracking_enabled(&mut self, enabled: bool) {
        self.epoch_tracking_enabled = enabled;
    }

    /// Enables detailed heap-dereference campaign counters.
    ///
    /// These counters update on every heap resolution, so production
    /// evaluations keep them disabled unless the caller requested the
    /// evaluator statistics dump.
    pub(crate) fn set_deref_counters_enabled(&mut self, enabled: bool) {
        self.deref_counters.set_enabled(enabled);
    }

    fn is_cold_hash_consed_record(
        record: &HeapRecord,
        current_epoch: u64,
        min_idle_epochs: u64,
    ) -> bool {
        if record.allocation_domain != HeapAllocationDomain::PermanentShared
            || record.structural_hash.is_none()
        {
            return false;
        }
        let idle_epochs = current_epoch.saturating_sub(record.last_touch_epoch.get());
        idle_epochs >= min_idle_epochs
    }

    fn cold_hash_consed_record_idle_epochs(record: &HeapRecord, current_epoch: u64) -> u64 {
        current_epoch.saturating_sub(record.last_touch_epoch.get())
    }

    pub(super) fn record_or_unknown(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<&HeapRecord, EvalHeapError> {
        self.deref_counters.note_record_probe(tag);
        self.records.find(ptr).ok_or_else(|| {
            // Error fidelity: a flat string/path pointer handed to a
            // record-kind getter still reports a record-type mismatch, as
            // record-backed strings did before FV-1.
            match self.flat_kind_tag(ptr) {
                Some(actual) => EvalHeapError::record_type_mismatch(tag, actual, ptr),
                None => EvalHeapError::unknown(tag, ptr),
            }
        })
    }

    /// Returns the dereference-chain volume counters for this heap (FV-0).
    pub(crate) fn deref_counters_snapshot(&self) -> EvalHeapDerefCountersSnapshot {
        self.deref_counters.snapshot()
    }
}

/// Captures the stable reservation metadata owned by a production serial heap.
#[cfg(feature = "candidate_c_value")]
fn serial_reservation_resolver(arena: &SharedFlatStoreArena) -> Option<SerialReservationResolver> {
    let domain = arena.arena_domain_id()?;
    let base = crate::heap::reservation_base(domain)?;
    let capacity = arena.reservation_stats()?.virtual_reserved_bytes;
    Some(SerialReservationResolver {
        domain,
        base,
        capacity,
    })
}

pub(super) fn value_heap_ptr(
    value: Value,
) -> Result<(ValueTag, NonNull<HeapObject>), EvalHeapError> {
    match value.tag() {
        ValueTag::String => Ok((
            ValueTag::String,
            value.as_string_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Path => Ok((
            ValueTag::Path,
            value.as_path_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::List => Ok((
            ValueTag::List,
            value.as_list_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Attrs => Ok((
            ValueTag::Attrs,
            value.as_attrs_ptr().map_err(EvalHeapError::Value)?,
        )),
        actual => Err(EvalHeapError::Value(ValueError::Type {
            expected: "string, path, list, or attrs",
            actual,
        })),
    }
}

pub(super) fn any_value_heap_ptr(
    value: Value,
) -> Result<(ValueTag, NonNull<HeapObject>), EvalHeapError> {
    match value.tag() {
        ValueTag::String => Ok((
            ValueTag::String,
            value.as_string_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Path => Ok((
            ValueTag::Path,
            value.as_path_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::List => Ok((
            ValueTag::List,
            value.as_list_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Attrs => Ok((
            ValueTag::Attrs,
            value.as_attrs_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Lambda => Ok((
            ValueTag::Lambda,
            value.as_lambda_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Primop => Ok((
            ValueTag::Primop,
            value.as_primop_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Thunk => Ok((
            ValueTag::Thunk,
            value.as_thunk_ptr().map_err(EvalHeapError::Value)?,
        )),
        actual => Err(EvalHeapError::Value(ValueError::Type {
            expected: "evaluator heap value",
            actual,
        })),
    }
}

fn gc_address_for_heap_record(record: &HeapRecord) -> Result<GcHeapAddress, EvalHeapError> {
    GcHeapAddress::new(record.ptr.as_ptr() as usize).map_err(EvalHeapError::GenerationalGc)
}

const fn tier_b_admitted_generation_for_allocation_domain(
    allocation_domain: HeapAllocationDomain,
) -> HeapGeneration {
    match allocation_domain {
        HeapAllocationDomain::Worker => HeapGeneration::Old,
        HeapAllocationDomain::PermanentShared => HeapGeneration::Permanent,
    }
}

fn next_heap_region_owner() -> u64 {
    let mut current = NEXT_HEAP_REGION_OWNER.load(Ordering::Relaxed);
    loop {
        if current == 0 || current == u64::MAX {
            panic!("evaluator heap region-owner id space exhausted");
        }
        let next = current + 1;
        match NEXT_HEAP_REGION_OWNER.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(owner) => return owner,
            Err(observed) => current = observed,
        }
    }
}

/// Component-wise saturating sum of two arena accountings.
fn merged_arena_stats(left: ArenaStats, right: ArenaStats) -> ArenaStats {
    ArenaStats {
        chunks: left.chunks.saturating_add(right.chunks),
        reserved_bytes: left.reserved_bytes.saturating_add(right.reserved_bytes),
        mapped_bytes: left.mapped_bytes.saturating_add(right.mapped_bytes),
        used_bytes: left.used_bytes.saturating_add(right.used_bytes),
    }
}

const fn whole_heap_memory_budget_sample(
    worker_stats: ArenaStats,
    permanent_stats: ArenaStats,
    dead_arena_bytes: usize,
    cold_hash_consed_bytes: usize,
) -> HeapMemorySample {
    HeapMemorySample::new(
        worker_stats
            .mapped_bytes
            .saturating_add(permanent_stats.mapped_bytes),
        dead_arena_bytes,
        cold_hash_consed_bytes,
    )
}

pub(super) fn list_structural_hash(list: &NixList) -> HotXxh3Hash {
    let mut hasher = Xxh3::new();
    ValueTag::List.hash(&mut hasher);
    list.len().hash(&mut hasher);
    for value in list {
        value.tag().hash(&mut hasher);
        value.relocation_sensitive_identity_bits().hash(&mut hasher);
    }
    HotXxh3Hash::from_xxh3(hasher.finish())
}

pub(super) fn attrs_structural_hash(
    metadata: EvalHeapAttrsMetadata,
    attrs: &FlatAttrs,
) -> HotXxh3Hash {
    let mut hasher = Xxh3::new();
    ValueTag::Attrs.hash(&mut hasher);
    metadata.hash(&mut hasher);
    attrs.len().hash(&mut hasher);
    attrs.source_order().hash(&mut hasher);
    attrs.iteration_order().hash(&mut hasher);
    for entry in attrs.entries_by_symbol() {
        entry.key.hash(&mut hasher);
        entry.value.tag().hash(&mut hasher);
        entry
            .value
            .relocation_sensitive_identity_bits()
            .hash(&mut hasher);
        match entry.position {
            Some(position) => {
                true.hash(&mut hasher);
                position.module.hash(&mut hasher);
                position.span.hash(&mut hasher);
            }
            None => false.hash(&mut hasher),
        }
    }
    HotXxh3Hash::from_xxh3(hasher.finish())
}
