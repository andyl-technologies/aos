//! Allocation, lookup, and cons-table machinery for the [`EvalHeap`] arena.

use super::*;

impl EvalHeap {
    /// Creates an empty evaluator heap.
    pub fn new() -> Self {
        Self {
            arena: BumpArena::new(),
            records: Vec::new(),
            string_cons: HashMap::new(),
            path_cons: HashMap::new(),
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
            arena: BumpArena::with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            records: Vec::new(),
            string_cons: HashMap::new(),
            path_cons: HashMap::new(),
        })
    }

    /// Returns current bump-arena accounting.
    pub fn arena_stats(&self) -> ArenaStats {
        self.arena.stats()
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
    /// reserved, if the bump arena cannot reserve a string handle, or if the
    /// resulting handle violates the runtime value alignment contract.
    pub fn alloc_string(&mut self, string: NixString) -> Result<Value, EvalHeapError> {
        let hash = string.structural_hash_xxh3();
        if let Some(value) = self.lookup_string_cons(hash, &string)? {
            return Ok(value);
        }
        self.reserve_record_slot()?;
        self.reserve_cons_slot(ValueTag::String, hash)?;
        let allocation = self
            .arena
            .aos_alloc_string(string.len())
            .map_err(EvalHeapError::Arena)?;
        let value = Value::string(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            structural_hash: Some(hash),
            object: HeapObjectValue::String(string),
        });
        self.push_cons_value(ValueTag::String, hash, value);
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
    /// reserved, if the bump arena cannot reserve a path handle, or if the
    /// resulting handle violates the runtime value alignment contract.
    pub fn alloc_path(&mut self, path: NixString) -> Result<Value, EvalHeapError> {
        let hash = path.structural_hash_xxh3();
        if let Some(value) = self.lookup_path_cons(hash, &path)? {
            return Ok(value);
        }
        self.reserve_record_slot()?;
        self.reserve_cons_slot(ValueTag::Path, hash)?;
        let allocation = self
            .arena
            .aos_alloc_string(path.len())
            .map_err(EvalHeapError::Arena)?;
        let value = Value::path(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            structural_hash: Some(hash),
            object: HeapObjectValue::Path(path),
        });
        self.push_cons_value(ValueTag::Path, hash, value);
        Ok(value)
    }

    /// Allocates a Nix list object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_list`] to recover the typed list.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// bump arena cannot reserve a list handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_list(&mut self, list: NixList) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .arena
            .aos_alloc_list(list.len())
            .map_err(EvalHeapError::Arena)?;
        let value = Value::list(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            structural_hash: None,
            object: HeapObjectValue::List(list),
        });
        Ok(value)
    }

    /// Allocates an attribute-set object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_attrs`] to recover the typed attrset.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// attrset length cannot fit the runtime slot count, if the bump arena
    /// cannot reserve an attrset handle, or if the resulting handle violates
    /// the runtime value alignment contract.
    pub fn alloc_attrs(&mut self, shape: u32, attrs: FlatAttrs) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let slots = u32::try_from(attrs.len())
            .map_err(|_| EvalHeapError::Arena(ArenaError::SizeOverflow))?;
        let allocation = self
            .arena
            .aos_alloc_attrs(shape, slots)
            .map_err(EvalHeapError::Arena)?;
        let value = Value::attrs(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            structural_hash: None,
            object: HeapObjectValue::Attrs(attrs),
        });
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
    /// bump arena cannot reserve a lambda handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_lambda(&mut self, lambda: EvalLambda) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .arena
            .aos_alloc_lambda()
            .map_err(EvalHeapError::Arena)?;
        let value = Value::lambda(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            structural_hash: None,
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
    /// bump arena cannot reserve a builtin handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_primop(&mut self, primop: EvalPrimOp) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .arena
            .aos_alloc_raw(PRIMOP_HANDLE_BYTES, PRIMOP_HANDLE_ALIGN, PRIMOP_TYPE_TAG)
            .map_err(EvalHeapError::Arena)?;
        let value = Value::primop(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            structural_hash: None,
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
    /// bump arena cannot reserve a thunk handle, or if the resulting handle
    /// violates the runtime value alignment contract.
    pub fn alloc_thunk(&mut self, thunk: EvalThunk) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self.arena.aos_alloc_thunk().map_err(EvalHeapError::Arena)?;
        let value = Value::thunk(allocation.ptr).map_err(EvalHeapError::Value)?;
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            structural_hash: None,
            object: HeapObjectValue::Thunk(Rc::new(thunk)),
        });
        Ok(value)
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
            HeapObjectValue::Attrs(attrs) => Ok(attrs),
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

    fn lookup_string_cons(
        &self,
        hash: u64,
        string: &NixString,
    ) -> Result<Option<Value>, EvalHeapError> {
        let Some(bucket) = self.string_cons.get(&hash) else {
            return Ok(None);
        };
        for value in bucket.iter().copied() {
            let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
            let record = self.record_or_unknown(ValueTag::String, ptr)?;
            if record.structural_hash == Some(hash)
                && matches!(&record.object, HeapObjectValue::String(candidate) if candidate == string)
            {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn lookup_path_cons(
        &self,
        hash: u64,
        path: &NixString,
    ) -> Result<Option<Value>, EvalHeapError> {
        let Some(bucket) = self.path_cons.get(&hash) else {
            return Ok(None);
        };
        for value in bucket.iter().copied() {
            let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
            let record = self.record_or_unknown(ValueTag::Path, ptr)?;
            if record.structural_hash == Some(hash)
                && matches!(&record.object, HeapObjectValue::Path(candidate) if candidate == path)
            {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn reserve_cons_slot(&mut self, tag: ValueTag, hash: u64) -> Result<(), EvalHeapError> {
        let table = match tag {
            ValueTag::String => &mut self.string_cons,
            ValueTag::Path => &mut self.path_cons,
            _ => return Ok(()),
        };

        if let Some(bucket) = table.get_mut(&hash) {
            let entries = bucket
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::ConsTableLengthOverflow)?;
            bucket
                .try_reserve_exact(1)
                .map_err(|_| EvalHeapError::ConsTableAllocationFailed { entries })?;
            return Ok(());
        }

        table
            .try_reserve(1)
            .map_err(|_| EvalHeapError::ConsTableAllocationFailed {
                entries: table.len().saturating_add(1),
            })?;
        let mut bucket = Vec::new();
        bucket
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::ConsTableAllocationFailed { entries: 1 })?;
        table.insert(hash, bucket);
        Ok(())
    }

    fn push_cons_value(&mut self, tag: ValueTag, hash: u64, value: Value) {
        let table = match tag {
            ValueTag::String => &mut self.string_cons,
            ValueTag::Path => &mut self.path_cons,
            _ => return,
        };
        if let Some(bucket) = table.get_mut(&hash) {
            bucket.push(value);
        } else {
            debug_assert!(
                false,
                "cons-table slot should be reserved before allocation"
            );
        }
    }

    fn record(&self, ptr: NonNull<HeapObject>) -> Option<&HeapRecord> {
        let address = ptr.as_ptr() as usize;
        self.records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == address)
    }

    fn record_or_unknown(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<&HeapRecord, EvalHeapError> {
        self.record(ptr)
            .ok_or_else(|| EvalHeapError::unknown(tag, ptr))
    }
}
