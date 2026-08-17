//! Value allocation and typed accessor methods: `alloc_*` doors for strings,
//! paths, lists, attrsets, lambdas, primops, and thunks, plus the `get_*`
//! resolution family. Moved verbatim from `heap/arena.rs`'s `impl EvalHeap`
//! under the RFC-0007 §2 file-size cap (impl reopened; method bodies
//! unchanged).

use super::*;

impl EvalHeap {
    /// Resolves one heap value through this heap's cached serial reservation.
    ///
    /// Returns `None` when the value is not an expected-tagged value in this
    /// heap's production Candidate-C reservation, allowing callers to retain
    /// the checked context-free fallback for shared, compatibility, malformed,
    /// and foreign values.
    #[cfg(feature = "candidate_c_value")]
    #[inline]
    pub(in crate::eval::heap) fn serial_heap_location(
        &self,
        value: Value,
        expected: ValueTag,
    ) -> Option<SerialHeapLocation> {
        if self.shared.is_some() || value.tag() != expected {
            return None;
        }
        let word = value.word();
        let domain = word.arena_domain()?;
        let (generation, resolver) = if self
            .serial_reservation
            .is_some_and(|resolver| resolver.domain == domain)
        {
            (SerialHeapGeneration::Nursery, self.serial_reservation?)
        } else if self
            .evacuated_serial_reservation
            .is_some_and(|resolver| resolver.domain == domain)
        {
            (
                SerialHeapGeneration::Evacuated,
                self.evacuated_serial_reservation?,
            )
        } else {
            return None;
        };
        let offset = word.arena_index()?.raw() as usize;
        if offset > resolver.capacity.saturating_sub(std::mem::size_of::<u64>()) {
            return None;
        }
        let address = resolver.base.checked_add(offset)?;
        if address % std::mem::align_of::<u64>() != 0 {
            return None;
        }
        Some(SerialHeapLocation {
            ptr: NonNull::new(address as *mut HeapObject)?,
            generation,
        })
    }

    /// Resolves one heap value through either hot serial reservation.
    #[cfg(feature = "candidate_c_value")]
    #[inline]
    fn serial_heap_ptr(&self, value: Value, expected: ValueTag) -> Option<NonNull<HeapObject>> {
        self.serial_heap_location(value, expected)
            .map(|location| location.ptr)
    }

    /// Canonicalizes a temporarily retained nursery closure word.
    ///
    /// This is intentionally limited to the safe evaluator access paths wired
    /// below. GC, JIT, FFI, and context-free `Value` pointer reconstruction
    /// still observe source coordinates and therefore remain blockers to
    /// production alias publication.
    #[cfg(feature = "candidate_c_value")]
    #[inline]
    fn canonicalize_evacuated_closure_value(&self, value: Value, expected: ValueTag) -> Value {
        self.evacuated_closure_forwarding
            .as_ref()
            .and_then(|forwarding| forwarding.translate(value, expected))
            .unwrap_or(value)
    }

    /// Canonicalizes a raw nursery pointer when its offset was evacuated.
    #[cfg(feature = "candidate_c_value")]
    #[inline]
    fn canonicalize_evacuated_closure_ptr(
        &self,
        ptr: NonNull<HeapObject>,
        expected: ValueTag,
    ) -> NonNull<HeapObject> {
        let Some(source) = self.serial_reservation else {
            return ptr;
        };
        let address = ptr.as_ptr() as usize;
        let Some(offset) = address.checked_sub(source.base) else {
            return ptr;
        };
        if offset >= source.capacity {
            return ptr;
        }
        let Ok(offset) = u32::try_from(offset) else {
            return ptr;
        };
        let Some(source_value) = Value::from_domain_index(
            expected,
            source.domain,
            crate::heap::ArenaIndex::new(offset),
        )
        .ok() else {
            return ptr;
        };
        let canonical = self.canonicalize_evacuated_closure_value(source_value, expected);
        self.serial_heap_location(canonical, expected)
            .filter(|location| location.generation == SerialHeapGeneration::Evacuated)
            .map_or(ptr, |location| location.ptr)
    }

    /// Returns whether `ptr` lies inside the installed evacuated reservation.
    #[cfg(feature = "candidate_c_value")]
    #[inline]
    pub(in crate::eval::heap) fn is_evacuated_ptr(&self, ptr: NonNull<HeapObject>) -> bool {
        self.evacuated_serial_reservation.is_some_and(|resolver| {
            let address = ptr.as_ptr() as usize;
            address
                .checked_sub(resolver.base)
                .is_some_and(|offset| offset < resolver.capacity)
        })
    }

    /// Resolves a thunk pointer, preferring the heap-owned serial reservation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] when `value` is not a valid thunk
    /// handle.
    #[inline]
    pub(crate) fn thunk_ptr(&self, value: Value) -> Result<NonNull<HeapObject>, EvalHeapError> {
        #[cfg(feature = "candidate_c_value")]
        if let Some(ptr) = self.serial_heap_ptr(value, ValueTag::Thunk) {
            return Ok(ptr);
        }
        value.as_thunk_ptr().map_err(EvalHeapError::Value)
    }

    /// Resolves a lambda pointer, preferring the heap-owned serial reservation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] when `value` is not a valid lambda
    /// handle.
    #[inline]
    fn lambda_ptr(&self, value: Value) -> Result<NonNull<HeapObject>, EvalHeapError> {
        #[cfg(feature = "candidate_c_value")]
        if let Some(ptr) = self.serial_heap_ptr(value, ValueTag::Lambda) {
            return Ok(ptr);
        }
        value.as_lambda_ptr().map_err(EvalHeapError::Value)
    }

    /// Resolves a primop pointer through this heap's cached serial reservation.
    #[inline]
    fn primop_ptr(&self, value: Value) -> Result<NonNull<HeapObject>, EvalHeapError> {
        #[cfg(feature = "candidate_c_value")]
        if let Some(ptr) = self.serial_heap_ptr(value, ValueTag::Primop) {
            return Ok(ptr);
        }
        value.as_primop_ptr().map_err(EvalHeapError::Value)
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
        if self.shared.is_some() {
            return self.shared_alloc_string(string);
        }
        self.flat_alloc_string(string)
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
        if self.shared.is_some() {
            return self.shared_alloc_path(path);
        }
        self.flat_alloc_path(path)
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
        if self.shared.is_some() {
            return self.shared_alloc_list(list);
        }
        self.flat_alloc_list(list)
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
        self.alloc_attrs_with_repr_metadata(shape, AttrSetReprKind::Flat, attrs)
    }

    /// Allocates an attribute-set object with explicit representation metadata.
    ///
    /// The active object payload remains [`FlatAttrs`]. The `repr` argument is
    /// persisted with the heap record so policy-aware attrset operations can
    /// observe the representation selected for this value while existing flat
    /// consumers keep using [`EvalHeap::get_attrs`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the attrset length cannot fit the runtime slot count, if
    /// the runtime allocator cannot reserve an attrset handle, or if the
    /// resulting handle violates the runtime value alignment contract.
    pub fn alloc_attrs_with_repr_metadata(
        &mut self,
        shape: u32,
        repr: AttrSetReprKind,
        attrs: FlatAttrs,
    ) -> Result<Value, EvalHeapError> {
        self.alloc_attrs_with_projected_shape_metadata(shape, repr, None, attrs)
    }

    /// Allocates an attribute-set value with representation and shape metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the attrset length cannot fit the runtime slot count, if
    /// the runtime allocator cannot reserve an attrset handle, or if the
    /// resulting handle violates the runtime value alignment contract.
    pub fn alloc_attrs_with_projected_shape_metadata(
        &mut self,
        shape: u32,
        repr: AttrSetReprKind,
        projected_shape: Option<ShapeId>,
        attrs: FlatAttrs,
    ) -> Result<Value, EvalHeapError> {
        if self.shared.is_some() {
            return self.shared_alloc_attrs_with_projected_shape_metadata(
                shape,
                repr,
                projected_shape,
                attrs,
            );
        }
        self.alloc_counters.note_attrs_built(attrs.len());
        let metadata = match projected_shape {
            Some(projected_shape) => {
                EvalHeapAttrsMetadata::with_projected_shape(shape, repr, projected_shape)
            }
            None => EvalHeapAttrsMetadata::new(shape, repr),
        };
        self.flat_alloc_attrs(metadata, attrs)
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
        self.alloc_lambda_with_flat_capture(lambda, None)
            .map(|(value, _)| value)
    }

    /// Allocates a lambda, optionally inlines its capture tail, and returns its handle.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::InlineCapturePlacementUnsupported`] if capture
    /// values are supplied outside the serial flat-closure placement, plus
    /// the allocation errors documented by [`Self::alloc_lambda`].
    pub(crate) fn alloc_lambda_with_flat_capture(
        &mut self,
        lambda: EvalLambda,
        capture: Option<EvalFlatCaptureBuffer>,
    ) -> Result<(Value, Option<crate::heap::flat::FlatValueTailHandle>), EvalHeapError> {
        if capture.is_some()
            && (self.shared.is_some()
                || self.worker_closure_placement != WorkerClosurePlacement::Flat)
        {
            return Err(EvalHeapError::InlineCapturePlacementUnsupported);
        }
        if self.shared.is_some() {
            return self.shared_alloc_lambda(lambda).map(|value| (value, None));
        }
        if self.worker_closure_placement == WorkerClosurePlacement::Flat {
            return self.flat_alloc_lambda(lambda, capture);
        }
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_lambda()
            .map_err(EvalHeapError::Arena)?;
        let value = Value::lambda(allocation.ptr).map_err(EvalHeapError::Value)?;
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: initial_generation_for_allocation_domain(HeapAllocationDomain::Worker),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::Lambda(lambda),
        });
        self.alloc_counters.note_value_allocated();
        #[cfg(feature = "peak_ordinal_probe")]
        self.note_peak_ordinal_publication(ValueTag::Lambda);
        self.poll_memory_budget_after_allocation();
        Ok((value, None))
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
        if self.shared.is_some() {
            return self.shared_alloc_primop(primop);
        }
        if self.worker_closure_placement == WorkerClosurePlacement::Flat {
            return self.flat_alloc_primop(primop);
        }
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_raw(PRIMOP_HANDLE_BYTES, PRIMOP_HANDLE_ALIGN, PRIMOP_TYPE_TAG)
            .map_err(EvalHeapError::Arena)?;
        let value = Value::primop(allocation.ptr).map_err(EvalHeapError::Value)?;
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: initial_generation_for_allocation_domain(HeapAllocationDomain::Worker),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::Primop(primop),
        });
        self.alloc_counters.note_value_allocated();
        #[cfg(feature = "peak_ordinal_probe")]
        self.note_peak_ordinal_publication(ValueTag::Primop);
        self.poll_memory_budget_after_allocation();
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
        self.alloc_thunk_with_flat_capture(thunk, None)
            .map(|(value, _)| value)
    }

    /// Allocates a thunk, optionally inlines its capture tail, and returns its handle.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::InlineCapturePlacementUnsupported`] if capture
    /// values are supplied outside the serial flat-closure placement, plus
    /// the allocation errors documented by [`Self::alloc_thunk`].
    pub(crate) fn alloc_thunk_with_flat_capture(
        &mut self,
        thunk: EvalThunk,
        capture: Option<EvalFlatCaptureBuffer>,
    ) -> Result<(Value, Option<crate::heap::flat::FlatValueTailHandle>), EvalHeapError> {
        if capture.is_some()
            && (self.shared.is_some()
                || self.worker_closure_placement != WorkerClosurePlacement::Flat)
        {
            return Err(EvalHeapError::InlineCapturePlacementUnsupported);
        }
        if self.shared.is_some() {
            return self.shared_alloc_thunk(thunk).map(|value| (value, None));
        }
        if self.worker_closure_placement == WorkerClosurePlacement::Flat {
            let mut thunk = thunk;
            if let Some(capture) = capture {
                return self.flat_alloc_thunk(thunk, Some(capture));
            }
            #[cfg(feature = "active_packed_thunk_probe")]
            if let Some(value) = self.try_active_packed_alloc_thunk(&thunk)? {
                self.alloc_counters.note_value_allocated();
                return Ok((value, None));
            }
            match self.try_typed_alloc_thunk(thunk)? {
                Ok(value) => return Ok((value, None)),
                Err(fallback) => {
                    thunk = fallback;
                }
            }
            return self.flat_alloc_thunk(thunk, None);
        }
        // Record-table placement (the GC-stress proving ground) detaches force
        // handles by deep-cloning the whole record on every share/clone, so the
        // serial cell must be `Arc`-shared for those clones to observe one
        // another's force state. Flat placement (the early return above) keeps
        // the cell inline and shares it through the record `Arc` instead.
        let mut thunk = thunk;
        thunk.share_cell();
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_thunk()
            .map_err(EvalHeapError::Arena)?;
        let value = Value::thunk(allocation.ptr).map_err(EvalHeapError::Value)?;
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: initial_generation_for_allocation_domain(HeapAllocationDomain::Worker),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::Thunk(thunk),
        });
        self.alloc_counters.note_value_allocated();
        #[cfg(feature = "peak_ordinal_probe")]
        self.note_peak_ordinal_publication(ValueTag::Thunk);
        self.poll_memory_budget_after_allocation();
        Ok((value, None))
    }

    /// Allocates a worker-domain placeholder record for a reserved minor-GC destination.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `tag` is not a worker-domain record type that
    /// can be copied by the current reservation bridge, if record storage cannot
    /// be reserved, if the runtime allocator fails, or if the allocated handle
    /// cannot be represented as a typed evaluator value.
    // Visibility widened from the pre-split `pub(super)` (then = the heap
    // module) to keep the same audience after the §2 relocation.
    pub(in crate::eval::heap) fn alloc_minor_gc_destination_worker_record(
        &mut self,
        source: GcHeapAddress,
        tag: ValueTag,
    ) -> Result<Value, EvalHeapError> {
        if !matches!(tag, ValueTag::Lambda | ValueTag::Primop | ValueTag::Thunk) {
            return Err(
                EvalHeapError::CollectorPollMinorGcDestinationReservationUnsupported {
                    source_address: source,
                    tag,
                },
            );
        }

        self.reserve_record_slot()?;
        let allocation = match tag {
            ValueTag::Lambda => self
                .allocator
                .aos_alloc_lambda()
                .map_err(EvalHeapError::Arena)?,
            ValueTag::Primop => self
                .allocator
                .aos_alloc_raw(PRIMOP_HANDLE_BYTES, PRIMOP_HANDLE_ALIGN, PRIMOP_TYPE_TAG)
                .map_err(EvalHeapError::Arena)?,
            ValueTag::Thunk => self
                .allocator
                .aos_alloc_thunk()
                .map_err(EvalHeapError::Arena)?,
            tag => {
                return Err(
                    EvalHeapError::CollectorPollMinorGcDestinationReservationUnsupported {
                        source_address: source,
                        tag,
                    },
                );
            }
        };
        let (value, object) = match tag {
            ValueTag::Lambda => (
                Value::lambda(allocation.ptr),
                HeapObjectValue::Lambda(EvalLambda::new(
                    IrId::new(0),
                    IrId::new(0),
                    FrameId::new(0),
                    EvalEnv::default(),
                )),
            ),
            ValueTag::Primop => (
                Value::primop(allocation.ptr),
                HeapObjectValue::Primop(EvalPrimOp::new(Symbol::new(0))),
            ),
            ValueTag::Thunk => (
                Value::thunk(allocation.ptr),
                HeapObjectValue::Thunk(EvalThunk::new(IrId::new(0))),
            ),
            tag => {
                return Err(
                    EvalHeapError::CollectorPollMinorGcDestinationReservationUnsupported {
                        source_address: source,
                        tag,
                    },
                );
            }
        };
        let value = value.map_err(EvalHeapError::Value)?;
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: initial_generation_for_allocation_domain(HeapAllocationDomain::Worker),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object,
        });
        self.poll_memory_budget_after_allocation();
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
        if let Some(shared) = &self.shared {
            return shared.cached_value_hash(value);
        }
        let (tag, ptr) = value_heap_ptr(value)?;
        if matches!(
            tag,
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
        ) {
            let address = self.flat_canonical_address(tag, ptr)?;
            return Ok(self.flat_cold_value_hash(address));
        }
        let address = self.record_for_value(value)?.ptr.as_ptr() as usize;
        Ok(self.records.cold_value_hash(address))
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
        if let Some(shared) = &self.shared {
            return shared.cache_value_hash(value, hash);
        }
        let (tag, ptr) = value_heap_ptr(value)?;
        if matches!(
            tag,
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
        ) {
            let address = self.flat_canonical_address(tag, ptr)?;
            return match self.flat_cold_value_hash(address) {
                Some(existing) if existing == hash => Ok(HeapValueHashCacheUpdate::AlreadyPresent),
                Some(existing) => Err(EvalHeapError::ValueHashMismatch {
                    existing,
                    attempted: hash,
                }),
                None => {
                    self.set_flat_cold_value_hash(address, Some(hash));
                    Ok(HeapValueHashCacheUpdate::Inserted)
                }
            };
        }
        let address = self.record_for_value(value)?.ptr.as_ptr() as usize;
        match self.records.cold_value_hash(address) {
            Some(existing) if existing == hash => Ok(HeapValueHashCacheUpdate::AlreadyPresent),
            Some(existing) => Err(EvalHeapError::ValueHashMismatch {
                existing,
                attempted: hash,
            }),
            None => {
                self.records.set_cold_value_hash(address, Some(hash));
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
        if let Some(shared) = &self.shared {
            return shared.cached_captured_value_hash(value);
        }
        let (tag, ptr) = value_heap_ptr(value)?;
        if matches!(
            tag,
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
        ) {
            let address = self.flat_canonical_address(tag, ptr)?;
            return Ok(self.flat_cold_captured_value_hash(address));
        }
        let address = self.record_for_value(value)?.ptr.as_ptr() as usize;
        Ok(self.records.cold_captured_value_hash(address))
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
        if let Some(shared) = &self.shared {
            return shared.cache_captured_value_hash(value, hash);
        }
        let (tag, ptr) = value_heap_ptr(value)?;
        if matches!(
            tag,
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
        ) {
            let address = self.flat_canonical_address(tag, ptr)?;
            self.set_flat_cold_captured_value_hash(address, Some(hash));
            return Ok(());
        }
        let address = self.record_for_value(value)?.ptr.as_ptr() as usize;
        self.records
            .set_cold_captured_value_hash(address, Some(hash));
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
        #[cfg(feature = "candidate_c_value")]
        if let Some(ptr) = self.serial_heap_ptr(value, ValueTag::String) {
            return self.get_string_ptr(ptr);
        }
        let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.get_string_ptr(ptr)
    }

    /// Returns an allocation-free flat or packed string view.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when an ordinary string cannot be resolved or
    /// a packed coordinate is stale or structurally malformed.
    pub(crate) fn get_string_view(
        &self,
        value: Value,
    ) -> Result<EvalStringView<'_>, EvalHeapError> {
        #[cfg(any(
            feature = "compact_destination_probe",
            feature = "evacuation_plan_probe"
        ))]
        if let Some(generation) = self.packed_generation()
            && let Some(view) = generation.string_view(value)
        {
            return Ok(EvalStringView::packed(view?));
        }
        self.get_string(value).map(EvalStringView::flat)
    }

    /// Returns the string object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-string record.
    pub fn get_string_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        if let Some(shared) = &self.shared {
            return shared.get_string_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            return self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated resolver has no aggregate generation owner",
                })?
                .get_string_ptr(ptr);
        }
        self.flat_get(FlatObjectKind::String, ptr)
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
        #[cfg(feature = "candidate_c_value")]
        if let Some(ptr) = self.serial_heap_ptr(value, ValueTag::Path) {
            return self.get_path_ptr(ptr);
        }
        let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
        self.get_path_ptr(ptr)
    }

    /// Returns an allocation-free flat or packed path view.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when an ordinary path cannot be resolved or a
    /// packed coordinate is stale or structurally malformed.
    pub(crate) fn get_path_view(&self, value: Value) -> Result<EvalStringView<'_>, EvalHeapError> {
        #[cfg(any(
            feature = "compact_destination_probe",
            feature = "evacuation_plan_probe"
        ))]
        if let Some(generation) = self.packed_generation()
            && let Some(view) = generation.path_view(value)
        {
            return Ok(EvalStringView::packed(view?));
        }
        self.get_path(value).map(EvalStringView::flat)
    }

    /// Returns the path object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-path record.
    pub fn get_path_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        if let Some(shared) = &self.shared {
            return shared.get_path_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            return self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated resolver has no aggregate generation owner",
                })?
                .get_path_ptr(ptr);
        }
        self.flat_get(FlatObjectKind::Path, ptr)
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
        #[cfg(feature = "candidate_c_value")]
        if let Some(ptr) = self.serial_heap_ptr(value, ValueTag::List) {
            return self.get_list_ptr(ptr);
        }
        let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
        self.get_list_ptr(ptr)
    }

    /// Returns an allocation-free flat or packed list view.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when an ordinary list cannot be resolved or a
    /// packed coordinate is stale or structurally malformed.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    pub(crate) fn get_list_view(&self, value: Value) -> Result<EvalListView<'_>, EvalHeapError> {
        if let Some(generation) = self.packed_generation()
            && let Some(reference) = generation.list_reference(value)
        {
            return Ok(EvalListView::packed(generation.collections(), reference)?);
        }
        self.get_list(value).map(EvalListView::flat)
    }

    #[cfg(all(
        feature = "candidate_c_value",
        not(any(
            feature = "compact_destination_probe",
            feature = "evacuation_plan_probe"
        ))
    ))]
    pub(crate) fn get_list_view(&self, value: Value) -> Result<EvalListView<'_>, EvalHeapError> {
        self.get_list(value).map(EvalListView::flat)
    }

    /// Returns the list object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-list record.
    pub fn get_list_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixList, EvalHeapError> {
        if let Some(shared) = &self.shared {
            return shared.get_list_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            return self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated resolver has no aggregate generation owner",
                })?
                .get_list_ptr(ptr);
        }
        self.flat_get_list(ptr)
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
        #[cfg(feature = "candidate_c_value")]
        if let Some(ptr) = self.serial_heap_ptr(value, ValueTag::Attrs) {
            return self.get_attrs_ptr(ptr);
        }
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        self.get_attrs_ptr(ptr)
    }

    /// Returns an allocation-free flat or packed attrset view.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when an ordinary attrset cannot be resolved or
    /// a packed coordinate is stale or structurally malformed.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    pub(crate) fn get_attrs_view(&self, value: Value) -> Result<EvalAttrsView<'_>, EvalHeapError> {
        if let Some(generation) = self.packed_generation()
            && let Some(reference) = generation.attrs_reference(value)
        {
            return Ok(EvalAttrsView::packed(generation.collections(), reference)?);
        }
        self.get_attrs(value).map(EvalAttrsView::flat)
    }

    #[cfg(all(
        feature = "candidate_c_value",
        not(any(
            feature = "compact_destination_probe",
            feature = "evacuation_plan_probe"
        ))
    ))]
    pub(crate) fn get_attrs_view(&self, value: Value) -> Result<EvalAttrsView<'_>, EvalHeapError> {
        self.get_attrs(value).map(EvalAttrsView::flat)
    }

    /// Returns the attribute-set object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-attrset record.
    pub fn get_attrs_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&FlatAttrs, EvalHeapError> {
        if let Some(shared) = &self.shared {
            return shared.get_attrs_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            return self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated resolver has no aggregate generation owner",
                })?
                .get_attrs_ptr(ptr);
        }
        self.flat_get_attrs(ptr)
    }

    /// Returns metadata for the attribute-set object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an attrset value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the attrset handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-attrset record.
    pub fn get_attrs_metadata(&self, value: Value) -> Result<EvalHeapAttrsMetadata, EvalHeapError> {
        #[cfg(any(
            feature = "compact_destination_probe",
            feature = "evacuation_plan_probe"
        ))]
        if let Some(generation) = self.packed_generation()
            && let Some(reference) = generation.attrs_reference(value)
        {
            return Ok(generation.collections().attrs_metadata(reference)?);
        }
        #[cfg(feature = "candidate_c_value")]
        if let Some(ptr) = self.serial_heap_ptr(value, ValueTag::Attrs) {
            return self.get_attrs_metadata_ptr(ptr);
        }
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        self.get_attrs_metadata_ptr(ptr)
    }

    /// Returns metadata for the attrset referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-attrset record.
    pub fn get_attrs_metadata_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<EvalHeapAttrsMetadata, EvalHeapError> {
        if let Some(shared) = &self.shared {
            return shared.get_attrs_metadata_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            return self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated resolver has no aggregate generation owner",
                })?
                .get_attrs_metadata_ptr(ptr);
        }
        self.flat_get_attrs_metadata(ptr)
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
        let ptr = self.lambda_ptr(value)?;
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
        if let Some(shared) = &self.shared {
            return shared.get_lambda_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            return self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated closure resolver has no generation owner",
                })?
                .closures()
                .get_lambda_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        let mut ptr = ptr;
        match self.flat_closure_probe(ValueTag::Lambda, FlatObjectKind::Lambda, ptr) {
            Ok(Some(payload)) => {
                #[cfg(feature = "lifetime_cohort_probe")]
                self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::GetLambda);
                return match payload {
                    FlatClosurePayload::Lambda(lambda) => Ok(lambda),
                    payload => Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Lambda,
                        payload.tag(),
                        ptr,
                    )),
                };
            }
            Ok(None) => {}
            Err(error) => {
                #[cfg(feature = "candidate_c_value")]
                {
                    let canonical = self.canonicalize_evacuated_closure_ptr(ptr, ValueTag::Lambda);
                    if canonical == ptr {
                        return Err(error);
                    }
                    // The source tombstone is an expected alias miss.
                    ptr = canonical;
                }
                #[cfg(not(feature = "candidate_c_value"))]
                return Err(error);
            }
        }
        #[cfg(feature = "candidate_c_value")]
        let ptr = self.canonicalize_evacuated_closure_ptr(ptr, ValueTag::Lambda);
        #[cfg(feature = "candidate_c_value")]
        if let Some(generation) = &self.evacuated_generation
            && let Some(result) = generation.closures().lambda_probe(ptr)
        {
            return result;
        }
        let record = self.record_or_unknown(ValueTag::Lambda, ptr)?;
        match &record.object {
            HeapObjectValue::Lambda(lambda) => {
                self.touch_record(record);
                Ok(lambda)
            }
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
        let ptr = self.primop_ptr(value)?;
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
        if let Some(shared) = &self.shared {
            return shared.get_primop_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            return self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated closure resolver has no generation owner",
                })?
                .closures()
                .get_primop_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        let mut ptr = ptr;
        match self.flat_closure_probe(ValueTag::Primop, FlatObjectKind::Primop, ptr) {
            Ok(Some(payload)) => {
                #[cfg(feature = "lifetime_cohort_probe")]
                self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::GetPrimop);
                return match payload {
                    FlatClosurePayload::Primop(inner) => Ok(inner),
                    payload => Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Primop,
                        payload.tag(),
                        ptr,
                    )),
                };
            }
            Ok(None) => {}
            Err(error) => {
                #[cfg(feature = "candidate_c_value")]
                {
                    let canonical = self.canonicalize_evacuated_closure_ptr(ptr, ValueTag::Primop);
                    if canonical == ptr {
                        return Err(error);
                    }
                    // The source tombstone is an expected alias miss.
                    ptr = canonical;
                }
                #[cfg(not(feature = "candidate_c_value"))]
                return Err(error);
            }
        }
        #[cfg(feature = "candidate_c_value")]
        let ptr = self.canonicalize_evacuated_closure_ptr(ptr, ValueTag::Primop);
        #[cfg(feature = "candidate_c_value")]
        if let Some(generation) = &self.evacuated_generation
            && let Some(result) = generation.closures().primop_probe(ptr)
        {
            return result;
        }
        let record = self.record_or_unknown(ValueTag::Primop, ptr)?;
        match &record.object {
            HeapObjectValue::Primop(primop) => {
                self.touch_record(record);
                Ok(primop)
            }
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
        let ptr = self.thunk_ptr(value)?;
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
        if let Some(shared) = &self.shared {
            return shared.get_thunk_ptr(ptr);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            return self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated closure resolver has no generation owner",
                })?
                .closures()
                .get_thunk_ptr(ptr);
        }
        if let Some(work) = self.typed_thunk_work_ref(ptr)? {
            return Ok(work);
        }
        #[cfg(feature = "candidate_c_value")]
        let mut ptr = ptr;
        match self.flat_closure_probe(ValueTag::Thunk, FlatObjectKind::Thunk, ptr) {
            Ok(Some(payload)) => {
                #[cfg(feature = "lifetime_cohort_probe")]
                self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::GetThunk);
                return match payload.as_thunk() {
                    Some(inner) => Ok(inner),
                    None => Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Thunk,
                        payload.tag(),
                        ptr,
                    )),
                };
            }
            Ok(None) => {}
            Err(error) => {
                #[cfg(feature = "candidate_c_value")]
                {
                    let canonical = self.canonicalize_evacuated_closure_ptr(ptr, ValueTag::Thunk);
                    if canonical == ptr {
                        return Err(error);
                    }
                    // The source tombstone is an expected alias miss.
                    ptr = canonical;
                }
                #[cfg(not(feature = "candidate_c_value"))]
                return Err(error);
            }
        }
        #[cfg(feature = "candidate_c_value")]
        let ptr = self.canonicalize_evacuated_closure_ptr(ptr, ValueTag::Thunk);
        #[cfg(feature = "candidate_c_value")]
        if let Some(generation) = &self.evacuated_generation
            && let Some(result) = generation.closures().thunk_probe(ptr)
        {
            return result;
        }
        let record = self.record_or_unknown(ValueTag::Thunk, ptr)?;
        match &record.object {
            HeapObjectValue::Thunk(thunk) => {
                self.touch_record(record);
                Ok(thunk)
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns a stable pointer to an inline serial flat-thunk payload.
    ///
    /// The returned pointer is detached from this method's heap borrow so the
    /// serial evaluator can re-enter evaluation without first moving the thunk
    /// into an `Arc`. Callers must uphold the flat arena's lifetime and
    /// non-reclamation invariants before dereferencing it.
    ///
    /// # Errors
    ///
    /// Returns the same typed-resolution errors as [`Self::get_thunk_ptr`].
    pub(crate) fn serial_flat_thunk_payload_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<Option<NonNull<EvalThunk>>, EvalHeapError> {
        if self.shared.is_some() {
            return Ok(None);
        }
        let Some(payload) = self.flat_closure_probe(ValueTag::Thunk, FlatObjectKind::Thunk, ptr)?
        else {
            return Ok(None);
        };
        #[cfg(feature = "lifetime_cohort_probe")]
        self.observe_lifetime_quarantine_ptr(
            ptr,
            LifetimeQuarantineOrigin::SerialFlatThunkPayloadPtr,
        );
        match payload.as_thunk() {
            Some(thunk) => Ok(Some(NonNull::from(thunk))),
            None => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                payload.tag(),
                ptr,
            )),
        }
    }

    /// Clones thunk metadata and its side-owned force-state handles so forcing
    /// can release the heap borrow before re-entering evaluation.
    pub(crate) fn clone_thunk(&self, value: Value) -> Result<EvalThunk, EvalHeapError> {
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        if let Some(shared) = &self.shared {
            let thunk = shared.clone_thunk_ptr(ptr)?;
            self.deref_counters
                .note_thunk_state_arc_clones(thunk.state_arc_clone_count());
            return Ok(thunk);
        }
        #[cfg(feature = "candidate_c_value")]
        if self.is_evacuated_ptr(ptr) {
            let thunk = self
                .evacuated_generation
                .as_ref()
                .ok_or(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "evacuated closure resolver has no generation owner",
                })?
                .closures()
                .get_thunk_ptr(ptr)?
                .clone();
            self.deref_counters
                .note_thunk_state_arc_clones(thunk.state_arc_clone_count());
            return Ok(thunk);
        }
        if let Some(work) = self.typed_thunk_work_ref(ptr)? {
            return Ok(work.clone());
        }
        #[cfg(feature = "candidate_c_value")]
        let mut ptr = ptr;
        match self.flat_closure_probe(ValueTag::Thunk, FlatObjectKind::Thunk, ptr) {
            Ok(Some(payload)) => {
                #[cfg(feature = "lifetime_cohort_probe")]
                self.observe_lifetime_quarantine_ptr(ptr, LifetimeQuarantineOrigin::CloneThunk);
                return match payload.as_thunk() {
                    Some(inner) => {
                        self.deref_counters
                            .note_thunk_state_arc_clones(inner.state_arc_clone_count());
                        Ok(inner.clone())
                    }
                    None => Err(EvalHeapError::record_type_mismatch(
                        ValueTag::Thunk,
                        payload.tag(),
                        ptr,
                    )),
                };
            }
            Ok(None) => {}
            Err(error) => {
                #[cfg(feature = "candidate_c_value")]
                {
                    let canonical = self.canonicalize_evacuated_closure_ptr(ptr, ValueTag::Thunk);
                    if canonical == ptr {
                        return Err(error);
                    }
                    // The source tombstone is an expected alias miss.
                    ptr = canonical;
                }
                #[cfg(not(feature = "candidate_c_value"))]
                return Err(error);
            }
        }
        #[cfg(feature = "candidate_c_value")]
        let ptr = self.canonicalize_evacuated_closure_ptr(ptr, ValueTag::Thunk);
        #[cfg(feature = "candidate_c_value")]
        if let Some(generation) = &self.evacuated_generation
            && let Some(result) = generation.closures().thunk_probe(ptr)
        {
            let thunk = result?.clone();
            self.deref_counters
                .note_thunk_state_arc_clones(thunk.state_arc_clone_count());
            return Ok(thunk);
        }
        let record = self.record_or_unknown(ValueTag::Thunk, ptr)?;
        match &record.object {
            HeapObjectValue::Thunk(thunk) => {
                self.touch_record(record);
                self.deref_counters
                    .note_thunk_state_arc_clones(thunk.state_arc_clone_count());
                Ok(thunk.clone())
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns a force-path handle to the thunk at an already-decoded heap
    /// pointer.
    ///
    /// This is the force path's cheap replacement for [`clone_thunk`]
    /// (doc 15 §5.5 cheap-thunk-clone I1). For a serial flat thunk it mints an
    /// `Arc<EvalThunk>` on first force ([`flat_share_thunk`]) and caches it in
    /// the flat slot, returning [`ClonedThunk::Shared`], so every force after the
    /// first pays a single `Arc::clone` (one refcount increment) instead of
    /// copying the whole ~128-byte record and re-incrementing its ~5 inner
    /// `Arc`s. Forcing reads the thunk's handles *through* the shared `Arc`,
    /// releasing the heap borrow before re-entering evaluation exactly as the
    /// owned clone did.
    ///
    /// Shared-backend (parallel) and record-table thunks are not yet minted; I2
    /// extends the shared handle to them. Until then they return
    /// [`ClonedThunk::Owned`] — the previous owned clone, unchanged and with no
    /// extra allocation — so I1 stays strictly a flat-hot-path change with zero
    /// regression on those (cold) paths.
    ///
    /// The caller passes the pointer already decoded from the thunk value: the
    /// force entry decodes it once and threads it to both the re-force cache
    /// peek ([`get_thunk_ptr`](Self::get_thunk_ptr)) and this mint, so the second
    /// resolve does not re-walk the carrier word and the reservation-base
    /// registry (RFC-0007 instruction-tax lever 2). `value` is used only by the
    /// cold `GcStressPolicy` record-table arm, which re-clones from the handle.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to this
    /// heap, and [`EvalHeapError::RecordTypeMismatch`] if it references a
    /// non-thunk record.
    ///
    /// [`clone_thunk`]: Self::clone_thunk
    /// [`flat_share_thunk`]: Self::flat_share_thunk
    pub(crate) fn share_thunk_from_ptr(
        &mut self,
        ptr: NonNull<HeapObject>,
        value: Value,
    ) -> Result<ClonedThunk, EvalHeapError> {
        if let Some(shared) = self.shared.as_ref() {
            // Parallel path (I2): the shared arena forbids in-slot mints
            // (publish-once), so each worker caches its own `Arc` in a
            // worker-private side map. Account the mint's one-time clone exactly
            // as `clone_thunk`'s shared arm did.
            let (arc, state_arc_clones) = shared.share_thunk_ptr(ptr)?;
            self.deref_counters
                .note_thunk_state_arc_clones(state_arc_clones);
            return Ok(ClonedThunk::Shared(arc));
        }
        if let Some(shared) = self.flat_share_thunk(ptr)? {
            return Ok(ClonedThunk::Shared(shared));
        }
        // Record-table path: reachable only under `GcStressPolicy` (never a
        // production config, where placement is always `Flat`), so it is left
        // as an owned clone rather than growing `HeapObjectValue` a shared
        // variant across its many exhaustive match sites (doc 15 §5.5 I2 scope).
        Ok(ClonedThunk::Owned(self.clone_thunk(value)?))
    }

    /// Clones lambda metadata so application can release the heap borrow before evaluating the body.
    pub(crate) fn clone_lambda(&self, value: Value) -> Result<EvalLambda, EvalHeapError> {
        let ptr = self.lambda_ptr(value)?;
        if let Some(shared) = &self.shared {
            return shared.clone_lambda_ptr(ptr);
        }
        self.get_lambda_ptr(ptr).cloned()
    }

    /// Clones builtin metadata so application can release the heap borrow
    /// before forcing captured arguments.
    pub(crate) fn clone_primop(&self, value: Value) -> Result<EvalPrimOp, EvalHeapError> {
        let ptr = self.primop_ptr(value)?;
        if let Some(shared) = &self.shared {
            return shared.clone_primop_ptr(ptr);
        }
        self.get_primop_ptr(ptr).cloned()
    }
}

#[cfg(all(test, feature = "candidate_c_value"))]
mod serial_reservation_tests {
    use super::*;
    use crate::heap::ArenaIndex;

    #[test]
    fn two_hot_serial_domains_resolve_without_the_global_fallback() {
        let mut nursery = EvalHeap::new();
        let mut evacuated = EvalHeap::new();
        let nursery_value = nursery
            .alloc_string(NixString::from_bytes(b"nursery".to_vec()))
            .expect("nursery string allocates");
        let evacuated_value = evacuated
            .alloc_string(NixString::from_bytes(b"evacuated".to_vec()))
            .expect("evacuated string allocates");

        nursery.evacuated_serial_reservation = evacuated.serial_reservation;

        let nursery_location = nursery
            .serial_heap_location(nursery_value, ValueTag::String)
            .expect("nursery domain resolves");
        assert_eq!(nursery_location.generation, SerialHeapGeneration::Nursery);
        assert_eq!(
            nursery_location.ptr,
            nursery_value
                .as_string_ptr()
                .expect("nursery value has pointer")
        );

        let evacuated_location = nursery
            .serial_heap_location(evacuated_value, ValueTag::String)
            .expect("evacuated domain resolves");
        assert_eq!(
            evacuated_location.generation,
            SerialHeapGeneration::Evacuated
        );
        assert_eq!(
            evacuated_location.ptr,
            evacuated_value
                .as_string_ptr()
                .expect("evacuated value has pointer")
        );
    }

    #[test]
    fn two_hot_serial_domain_router_rejects_wrong_foreign_and_malformed_words() {
        let mut nursery = EvalHeap::new();
        let evacuated = EvalHeap::new();
        let mut foreign = EvalHeap::new();
        let foreign_value = foreign
            .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
            .expect("foreign string allocates");
        nursery.evacuated_serial_reservation = evacuated.serial_reservation;

        assert!(
            nursery
                .serial_heap_location(foreign_value, ValueTag::String)
                .is_none()
        );
        assert!(
            nursery
                .serial_heap_location(foreign_value, ValueTag::Path)
                .is_none()
        );

        let resolver = nursery
            .serial_reservation
            .expect("production heap has a reservation");
        let unaligned =
            Value::from_domain_index(ValueTag::String, resolver.domain, ArenaIndex::new(1))
                .expect("indexed string word encodes");
        assert!(
            nursery
                .serial_heap_location(unaligned, ValueTag::String)
                .is_none()
        );

        let final_byte = u32::try_from(resolver.capacity - 1)
            .expect("Candidate-C reservation capacity fits its index width");
        let truncated = Value::from_domain_index(
            ValueTag::String,
            resolver.domain,
            ArenaIndex::new(final_byte),
        )
        .expect("final-byte string word encodes");
        assert!(
            nursery
                .serial_heap_location(truncated, ValueTag::String)
                .is_none()
        );
    }
}
