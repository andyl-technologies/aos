//! Allocation, lookup, and cons-table machinery for the [`EvalHeap`] arena.

use std::hash::{Hash, Hasher};

use xxhash_rust::xxh3::Xxh3;

use crate::heap::{HeapMemoryBudget, HeapMemoryBudgetResponse, HeapMemorySample};

use super::*;

/// A whole-heap high-water memory-budget decision.
///
/// `EvalHeap` owns a worker allocation domain and a permanent shared domain, so
/// this decision records both accounting snapshots alongside the single sample
/// classified by the shared budget policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapMemoryBudgetDecision {
    budget: HeapMemoryBudget,
    sample: HeapMemorySample,
    worker_stats: ArenaStats,
    permanent_stats: ArenaStats,
    response: HeapMemoryBudgetResponse,
}

impl EvalHeapMemoryBudgetDecision {
    const fn new(
        budget: HeapMemoryBudget,
        sample: HeapMemorySample,
        worker_stats: ArenaStats,
        permanent_stats: ArenaStats,
    ) -> Self {
        Self {
            budget,
            sample,
            worker_stats,
            permanent_stats,
            response: budget.classify(sample),
        }
    }

    /// Returns the budget used to classify memory pressure.
    pub const fn budget(self) -> HeapMemoryBudget {
        self.budget
    }

    /// Returns the whole-heap memory sample classified by the budget policy.
    pub const fn sample(self) -> HeapMemorySample {
        self.sample
    }

    /// Returns worker-domain arena accounting captured for this decision.
    pub const fn worker_stats(self) -> ArenaStats {
        self.worker_stats
    }

    /// Returns permanent-shared arena accounting captured for this decision.
    pub const fn permanent_stats(self) -> ArenaStats {
        self.permanent_stats
    }

    /// Returns the high-water budget response selected for the whole heap.
    pub const fn response(self) -> HeapMemoryBudgetResponse {
        self.response
    }

    /// Returns whether the response asks runtime code to do more than continue.
    pub const fn requires_runtime_action(self) -> bool {
        match self.response {
            HeapMemoryBudgetResponse::ContinueTierA { .. } => false,
            HeapMemoryBudgetResponse::SpillCold { .. }
            | HeapMemoryBudgetResponse::InstallTierB { .. } => true,
        }
    }

    /// Returns whether the response asks the runtime to install Tier B.
    pub const fn requests_tier_b(self) -> bool {
        matches!(self.response, HeapMemoryBudgetResponse::InstallTierB { .. })
    }
}

impl EvalHeap {
    /// Creates an empty evaluator heap.
    pub fn new() -> Self {
        Self {
            allocator: RuntimeAllocator::tier_a_one_shot(),
            permanent_allocator: PermanentSharedAllocator::new(),
            records: Vec::new(),
            string_cons: HashConsTable::new(),
            path_cons: HashConsTable::new(),
            list_cons: HashConsTable::new(),
            attrs_cons: HashConsTable::new(),
        }
    }

    /// Creates an empty evaluator heap with an explicit first arena chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Arena`] if the requested chunk size is invalid
    /// or overflows while being rounded to the arena word size.
    pub fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, EvalHeapError> {
        Ok(Self {
            allocator: RuntimeAllocator::tier_a_with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            permanent_allocator: PermanentSharedAllocator::with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            records: Vec::new(),
            string_cons: HashConsTable::new(),
            path_cons: HashConsTable::new(),
            list_cons: HashConsTable::new(),
            attrs_cons: HashConsTable::new(),
        })
    }

    /// Returns current runtime allocator accounting.
    pub fn arena_stats(&self) -> ArenaStats {
        self.allocator.stats()
    }

    /// Returns current permanent shared allocation accounting.
    pub fn permanent_arena_stats(&self) -> ArenaStats {
        self.permanent_allocator.stats()
    }

    /// Builds a high-water budget sample for both heap allocation domains.
    ///
    /// The active runtime does not have live RSS sampling yet, so the sample uses
    /// the saturating sum of worker and permanent mapped arena bytes as the
    /// resident-memory proxy. The caller supplies cheap-reclaim estimates for
    /// dead arena pages and cold hash-consed values.
    pub fn memory_budget_sample(
        &self,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> HeapMemorySample {
        whole_heap_memory_budget_sample(
            self.arena_stats(),
            self.permanent_arena_stats(),
            dead_arena_bytes,
            cold_hash_consed_bytes,
        )
    }

    /// Classifies the whole heap against a high-water memory budget.
    pub fn classify_memory_budget(
        &self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> EvalHeapMemoryBudgetDecision {
        let worker_stats = self.arena_stats();
        let permanent_stats = self.permanent_arena_stats();
        let sample = whole_heap_memory_budget_sample(
            worker_stats,
            permanent_stats,
            dead_arena_bytes,
            cold_hash_consed_bytes,
        );
        EvalHeapMemoryBudgetDecision::new(budget, sample, worker_stats, permanent_stats)
    }

    /// Installs one GC-stress polling policy for both worker and permanent
    /// allocation domains.
    pub fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.allocator.set_gc_stress_policy(policy);
        self.permanent_allocator.set_gc_stress_policy(policy);
    }

    /// Returns the worker allocation-domain GC-stress polling policy.
    pub const fn allocator_gc_stress_policy(&self) -> GcStressPolicy {
        self.allocator.gc_stress_policy()
    }

    /// Returns the permanent allocation-domain GC-stress polling policy.
    pub const fn permanent_allocator_gc_stress_policy(&self) -> GcStressPolicy {
        self.permanent_allocator.gc_stress_policy()
    }

    /// Returns allocation-safepoint accounting for worker-domain allocations.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocator.allocation_safepoints()
    }

    /// Returns allocation-safepoint accounting for permanent shared
    /// allocations.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocator.allocation_safepoints()
    }

    /// Returns the runtime allocation tier backing this heap.
    pub fn allocator_tier(&self) -> RuntimeAllocatorTier {
        self.allocator.tier()
    }

    /// Returns the runtime allocation tier backing permanent shared values.
    pub fn permanent_allocator_tier(&self) -> RuntimeAllocatorTier {
        self.permanent_allocator.tier()
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
        let (tag, ptr) = any_value_heap_ptr(value)?;
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            Ok(record.allocation_domain)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    /// Returns the number of typed objects registered in this heap.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether this heap contains no typed objects.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Allocates a Nix string object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_string`] to recover the typed string.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the runtime allocator cannot reserve a string handle, or if
    /// the resulting handle violates the runtime value alignment contract.
    pub fn alloc_string(&mut self, string: NixString) -> Result<Value, EvalHeapError> {
        let hash = string.structural_hash_xxh3();
        let cons_slot = match self.admit_string_cons(hash, &string)? {
            HashConsReservation::Existing(value) => return Ok(value),
            HashConsReservation::Vacant(slot) => slot,
        };
        let allocation = match self
            .permanent_allocator
            .aos_alloc_string(string.len())
            .map_err(EvalHeapError::Arena)
        {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_string_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let value = match Value::string(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_string_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: Some(hash),
            allocation_domain: HeapAllocationDomain::PermanentShared,
            value_hash: Cell::new(None),
            captured_value_hash: Cell::new(None),
            object: HeapObjectValue::String(string),
        });
        self.push_string_cons_value(cons_slot, value);
        Ok(value)
    }

    /// Allocates a Nix path object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_path`] to recover the typed path bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the runtime allocator cannot reserve a path handle, or if
    /// the resulting handle violates the runtime value alignment contract.
    pub fn alloc_path(&mut self, path: NixString) -> Result<Value, EvalHeapError> {
        let hash = path.structural_hash_xxh3();
        let cons_slot = match self.admit_path_cons(hash, &path)? {
            HashConsReservation::Existing(value) => return Ok(value),
            HashConsReservation::Vacant(slot) => slot,
        };
        let allocation = match self
            .permanent_allocator
            .aos_alloc_string(path.len())
            .map_err(EvalHeapError::Arena)
        {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_path_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let value = match Value::path(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_path_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: Some(hash),
            allocation_domain: HeapAllocationDomain::PermanentShared,
            value_hash: Cell::new(None),
            captured_value_hash: Cell::new(None),
            object: HeapObjectValue::Path(path),
        });
        self.push_path_cons_value(cons_slot, value);
        Ok(value)
    }

    /// Allocates a Nix list object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_list`] to recover the typed list.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the runtime allocator cannot reserve a list handle, or if
    /// the resulting handle violates the runtime value alignment contract.
    pub fn alloc_list(&mut self, list: NixList) -> Result<Value, EvalHeapError> {
        let hash = list_structural_hash(&list);
        let cons_slot = match self.admit_list_cons(hash, &list)? {
            HashConsReservation::Existing(value) => return Ok(value),
            HashConsReservation::Vacant(slot) => slot,
        };
        let allocation = match self
            .permanent_allocator
            .aos_alloc_list(list.len())
            .map_err(EvalHeapError::Arena)
        {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_list_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let value = match Value::list(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_list_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: Some(hash),
            allocation_domain: HeapAllocationDomain::PermanentShared,
            value_hash: Cell::new(None),
            captured_value_hash: Cell::new(None),
            object: HeapObjectValue::List(list),
        });
        self.push_list_cons_value(cons_slot, value);
        Ok(value)
    }

    /// Allocates an attribute-set object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_attrs`] to recover the typed attrset.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the attrset length cannot fit the runtime slot count, if
    /// the runtime allocator cannot reserve an attrset handle, or if the
    /// resulting handle violates the runtime value alignment contract.
    pub fn alloc_attrs(&mut self, shape: u32, attrs: FlatAttrs) -> Result<Value, EvalHeapError> {
        let hash = attrs_structural_hash(shape, &attrs);
        let slots = u32::try_from(attrs.len())
            .map_err(|_| EvalHeapError::Arena(ArenaError::SizeOverflow))?;
        let cons_slot = match self.admit_attrs_cons(hash, shape, &attrs)? {
            HashConsReservation::Existing(value) => return Ok(value),
            HashConsReservation::Vacant(slot) => slot,
        };
        let allocation = match self
            .permanent_allocator
            .aos_alloc_attrs(shape, slots)
            .map_err(EvalHeapError::Arena)
        {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_attrs_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let value = match Value::attrs(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_attrs_cons_slot(cons_slot);
                return Err(error);
            }
        };
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: Some(hash),
            allocation_domain: HeapAllocationDomain::PermanentShared,
            value_hash: Cell::new(None),
            captured_value_hash: Cell::new(None),
            object: HeapObjectValue::Attrs { shape, attrs },
        });
        self.push_attrs_cons_value(cons_slot, value);
        Ok(value)
    }

    /// Allocates a lambda closure object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_lambda`] to recover the typed closure.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// runtime allocator cannot reserve a lambda handle, or if the resulting
    /// handle violates the runtime value alignment contract.
    pub fn alloc_lambda(&mut self, lambda: EvalLambda) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_lambda()
            .map_err(EvalHeapError::Arena)?;
        let value = Value::lambda(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            value_hash: Cell::new(None),
            captured_value_hash: Cell::new(None),
            object: HeapObjectValue::Lambda(Rc::new(lambda)),
        });
        Ok(value)
    }

    /// Allocates a builtin function object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_primop`] to recover the typed builtin record.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// runtime allocator cannot reserve a builtin handle, or if the resulting
    /// handle violates the runtime value alignment contract.
    pub fn alloc_primop(&mut self, primop: EvalPrimOp) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_raw(PRIMOP_HANDLE_BYTES, PRIMOP_HANDLE_ALIGN, PRIMOP_TYPE_TAG)
            .map_err(EvalHeapError::Arena)?;
        let value = Value::primop(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            value_hash: Cell::new(None),
            captured_value_hash: Cell::new(None),
            object: HeapObjectValue::Primop(Rc::new(primop)),
        });
        Ok(value)
    }

    /// Allocates a suspended thunk object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_thunk`] to recover the typed thunk record.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// runtime allocator cannot reserve a thunk handle, or if the resulting
    /// handle violates the runtime value alignment contract.
    pub fn alloc_thunk(&mut self, thunk: EvalThunk) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_thunk()
            .map_err(EvalHeapError::Arena)?;
        let value = Value::thunk(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            value_hash: Cell::new(None),
            captured_value_hash: Cell::new(None),
            object: HeapObjectValue::Thunk(Rc::new(thunk)),
        });
        Ok(value)
    }

    /// Returns the cached canonical value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string, path, list,
    /// or attrset. Returns [`EvalHeapError::UnknownPointer`] if the heap handle
    /// does not belong to this heap. Returns
    /// [`EvalHeapError::RecordTypeMismatch`] if the handle belongs to this heap
    /// but references a different typed record.
    pub(crate) fn cached_value_hash(
        &self,
        value: Value,
    ) -> Result<Option<ValueHash>, EvalHeapError> {
        Ok(self.record_for_value(value)?.value_hash.get())
    }

    /// Stores the canonical value hash for a reusable heap value.
    ///
    /// Repeated writes of the same hash are accepted, but a different hash for
    /// the same immutable heap record is rejected and leaves the cached hash
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string, path, list,
    /// or attrset. Returns [`EvalHeapError::UnknownPointer`] if the heap handle
    /// does not belong to this heap. Returns
    /// [`EvalHeapError::RecordTypeMismatch`] if the handle belongs to this heap
    /// but references a different typed record. Returns
    /// [`EvalHeapError::ValueHashMismatch`] if the record already carries a
    /// different canonical value hash.
    pub(crate) fn cache_value_hash(
        &self,
        value: Value,
        hash: ValueHash,
    ) -> Result<HeapValueHashCacheUpdate, EvalHeapError> {
        let record = self.record_for_value(value)?;
        match record.value_hash.get() {
            Some(existing) if existing == hash => Ok(HeapValueHashCacheUpdate::AlreadyPresent),
            Some(existing) => Err(EvalHeapError::ValueHashMismatch {
                existing,
                attempted: hash,
            }),
            None => {
                record.value_hash.set(Some(hash));
                Ok(HeapValueHashCacheUpdate::Inserted)
            }
        }
    }

    /// Returns the cached force-capture value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string, path, list,
    /// or attrset. Returns [`EvalHeapError::UnknownPointer`] if the heap handle
    /// does not belong to this heap. Returns
    /// [`EvalHeapError::RecordTypeMismatch`] if the handle belongs to this heap
    /// but references a different typed record.
    pub(crate) fn cached_captured_value_hash(
        &self,
        value: Value,
    ) -> Result<Option<ValueHash>, EvalHeapError> {
        Ok(self.record_for_value(value)?.captured_value_hash.get())
    }

    /// Stores the force-capture value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string, path, list,
    /// or attrset. Returns [`EvalHeapError::UnknownPointer`] if the heap handle
    /// does not belong to this heap. Returns
    /// [`EvalHeapError::RecordTypeMismatch`] if the handle belongs to this heap
    /// but references a different typed record.
    pub(crate) fn cache_captured_value_hash(
        &self,
        value: Value,
        hash: ValueHash,
    ) -> Result<(), EvalHeapError> {
        self.record_for_value(value)?
            .captured_value_hash
            .set(Some(hash));
        Ok(())
    }

    /// Returns the string object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the string handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-string record.
    pub fn get_string(&self, value: Value) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.get_string_ptr(ptr)
    }

    /// Returns the string object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-string record.
    pub fn get_string_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::String, ptr)?;
        match &record.object {
            HeapObjectValue::String(string) => Ok(string),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::String,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the path object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a path value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the path handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-path record.
    pub fn get_path(&self, value: Value) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
        self.get_path_ptr(ptr)
    }

    /// Returns the path object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-path record.
    pub fn get_path_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Path, ptr)?;
        match &record.object {
            HeapObjectValue::Path(path) => Ok(path),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Path,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the list object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a list value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the list handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-list record.
    pub fn get_list(&self, value: Value) -> Result<&NixList, EvalHeapError> {
        let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
        self.get_list_ptr(ptr)
    }

    /// Returns the list object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-list record.
    pub fn get_list_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixList, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::List, ptr)?;
        match &record.object {
            HeapObjectValue::List(list) => Ok(list),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::List,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the attribute-set object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an attrset value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the attrset handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-attrset record.
    pub fn get_attrs(&self, value: Value) -> Result<&FlatAttrs, EvalHeapError> {
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        self.get_attrs_ptr(ptr)
    }

    /// Returns the attribute-set object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-attrset record.
    pub fn get_attrs_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&FlatAttrs, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Attrs, ptr)?;
        match &record.object {
            HeapObjectValue::Attrs { attrs, .. } => Ok(attrs),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Attrs,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the lambda closure object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a lambda value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the lambda handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-lambda record.
    pub fn get_lambda(&self, value: Value) -> Result<&EvalLambda, EvalHeapError> {
        let ptr = value.as_lambda_ptr().map_err(EvalHeapError::Value)?;
        self.get_lambda_ptr(ptr)
    }

    /// Returns the lambda closure object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-lambda record.
    pub fn get_lambda_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&EvalLambda, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Lambda, ptr)?;
        match &record.object {
            HeapObjectValue::Lambda(lambda) => Ok(lambda.as_ref()),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Lambda,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the builtin record referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a builtin value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the builtin handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-builtin record.
    pub fn get_primop(&self, value: Value) -> Result<&EvalPrimOp, EvalHeapError> {
        let ptr = value.as_primop_ptr().map_err(EvalHeapError::Value)?;
        self.get_primop_ptr(ptr)
    }

    /// Returns the builtin record referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-builtin record.
    pub fn get_primop_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&EvalPrimOp, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Primop, ptr)?;
        match &record.object {
            HeapObjectValue::Primop(primop) => Ok(primop.as_ref()),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Primop,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the suspended thunk object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a thunk value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the thunk handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-thunk record.
    pub fn get_thunk(&self, value: Value) -> Result<&EvalThunk, EvalHeapError> {
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        self.get_thunk_ptr(ptr)
    }

    /// Returns the suspended thunk object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-thunk record.
    pub fn get_thunk_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&EvalThunk, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Thunk, ptr)?;
        match &record.object {
            HeapObjectValue::Thunk(thunk) => Ok(thunk.as_ref()),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Clones the thunk handle so forcing can release the heap borrow before
    /// re-entering evaluation.
    pub(crate) fn clone_thunk(&self, value: Value) -> Result<Rc<EvalThunk>, EvalHeapError> {
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        let record = self.record_or_unknown(ValueTag::Thunk, ptr)?;
        match &record.object {
            HeapObjectValue::Thunk(thunk) => Ok(Rc::clone(thunk)),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Clones the lambda handle so application can release the heap borrow
    /// before evaluating the body.
    pub(crate) fn clone_lambda(&self, value: Value) -> Result<Rc<EvalLambda>, EvalHeapError> {
        let ptr = value.as_lambda_ptr().map_err(EvalHeapError::Value)?;
        let record = self.record_or_unknown(ValueTag::Lambda, ptr)?;
        match &record.object {
            HeapObjectValue::Lambda(lambda) => Ok(Rc::clone(lambda)),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Lambda,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Clones the builtin handle so application can release the heap borrow
    /// before forcing captured arguments.
    pub(crate) fn clone_primop(&self, value: Value) -> Result<Rc<EvalPrimOp>, EvalHeapError> {
        let ptr = value.as_primop_ptr().map_err(EvalHeapError::Value)?;
        let record = self.record_or_unknown(ValueTag::Primop, ptr)?;
        match &record.object {
            HeapObjectValue::Primop(primop) => Ok(Rc::clone(primop)),
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Primop,
                object.tag(),
                ptr,
            )),
        }
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

    fn admit_string_cons(
        &mut self,
        hash: HotXxh3Hash,
        string: &NixString,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let records = &self.records;
            self.string_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
                    let record = Self::record_or_unknown_in(records, ValueTag::String, ptr)?;
                    let same_hash = record.structural_hash == Some(hash);
                    let same_string = matches!(
                        &record.object,
                        HeapObjectValue::String(candidate) if candidate == string
                    );
                    Ok::<bool, EvalHeapError>(same_hash && same_string)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        self.reserve_record_slot()?;
        Ok(HashConsReservation::Vacant(
            self.string_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    fn admit_path_cons(
        &mut self,
        hash: HotXxh3Hash,
        path: &NixString,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let records = &self.records;
            self.path_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
                    let record = Self::record_or_unknown_in(records, ValueTag::Path, ptr)?;
                    let same_hash = record.structural_hash == Some(hash);
                    let same_path = matches!(
                        &record.object,
                        HeapObjectValue::Path(candidate) if candidate == path
                    );
                    Ok::<bool, EvalHeapError>(same_hash && same_path)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        self.reserve_record_slot()?;
        Ok(HashConsReservation::Vacant(
            self.path_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    fn admit_list_cons(
        &mut self,
        hash: HotXxh3Hash,
        list: &NixList,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let records = &self.records;
            self.list_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
                    let record = Self::record_or_unknown_in(records, ValueTag::List, ptr)?;
                    let same_hash = record.structural_hash == Some(hash);
                    let same_list = matches!(
                        &record.object,
                        HeapObjectValue::List(candidate) if candidate.raw_eq(list)
                    );
                    Ok::<bool, EvalHeapError>(same_hash && same_list)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        self.reserve_record_slot()?;
        Ok(HashConsReservation::Vacant(
            self.list_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    fn admit_attrs_cons(
        &mut self,
        hash: HotXxh3Hash,
        shape: u32,
        attrs: &FlatAttrs,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let records = &self.records;
            self.attrs_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
                    let record = Self::record_or_unknown_in(records, ValueTag::Attrs, ptr)?;
                    let same_hash = record.structural_hash == Some(hash);
                    let same_attrs = matches!(
                        &record.object,
                        HeapObjectValue::Attrs {
                            shape: candidate_shape,
                            attrs: candidate_attrs,
                        } if *candidate_shape == shape && candidate_attrs.raw_eq(attrs)
                    );
                    Ok::<bool, EvalHeapError>(same_hash && same_attrs)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        self.reserve_record_slot()?;
        Ok(HashConsReservation::Vacant(
            self.attrs_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    fn push_string_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.string_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    fn push_path_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.path_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    fn push_attrs_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.attrs_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    fn push_list_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.list_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    fn cancel_string_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.string_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    fn cancel_path_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.path_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    fn cancel_attrs_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.attrs_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    fn cancel_list_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.list_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

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
            Ok(record)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    pub(super) fn record_or_unknown(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<&HeapRecord, EvalHeapError> {
        Self::record_or_unknown_in(&self.records, tag, ptr)
    }

    fn record_or_unknown_in(
        records: &[HeapRecord],
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<&HeapRecord, EvalHeapError> {
        Self::record_in(records, ptr).ok_or_else(|| EvalHeapError::unknown(tag, ptr))
    }
}

fn value_heap_ptr(value: Value) -> Result<(ValueTag, NonNull<HeapObject>), EvalHeapError> {
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

fn any_value_heap_ptr(value: Value) -> Result<(ValueTag, NonNull<HeapObject>), EvalHeapError> {
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

fn list_structural_hash(list: &NixList) -> HotXxh3Hash {
    let mut hasher = Xxh3::new();
    ValueTag::List.hash(&mut hasher);
    list.len().hash(&mut hasher);
    for value in list {
        value.tag().hash(&mut hasher);
        value.payload_bits().hash(&mut hasher);
    }
    HotXxh3Hash::from_xxh3(hasher.finish())
}

fn attrs_structural_hash(shape: u32, attrs: &FlatAttrs) -> HotXxh3Hash {
    let mut hasher = Xxh3::new();
    ValueTag::Attrs.hash(&mut hasher);
    shape.hash(&mut hasher);
    attrs.len().hash(&mut hasher);
    attrs.source_order().hash(&mut hasher);
    attrs.iteration_order().hash(&mut hasher);
    for entry in attrs.entries_by_symbol() {
        entry.key.hash(&mut hasher);
        entry.value.tag().hash(&mut hasher);
        entry.value.payload_bits().hash(&mut hasher);
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
