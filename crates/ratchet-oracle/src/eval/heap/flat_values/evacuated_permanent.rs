//! Permanent stores owned by a compact Candidate-C generation.
//!
//! This owner is deliberately not installed in [`EvalHeap`]. It supplies the
//! physical cross-domain movement seam for permanent strings, paths, lists,
//! and attribute sets while allocation policy, hash-cons publication, and
//! resolver routing remain unchanged. Plain objects transfer ownership;
//! inline strings/paths and attrsets are reconstructed through the sealed
//! trailing-allocation doors without rebasing their self-relative witnesses.

use super::*;

/// Owns permanent flat values within an [`EvacuatedGeneration`].
#[derive(Debug)]
pub(in crate::eval::heap) struct EvacuatedPermanentGeneration {
    arena: SharedFlatStoreArena,
    values: FlatObjectStore<NixString>,
    lists: FlatObjectStore<NixList>,
    attrs: FlatObjectStore<FlatAttrsPayload>,
}

impl EvacuatedPermanentGeneration {
    /// Creates empty permanent stores over the aggregate generation arena.
    pub(super) fn with_shared_arena(arena: SharedFlatStoreArena) -> Self {
        let values = FlatObjectStore::with_shared_arena(
            arena.clone(),
            FlatKindSet::of(&[FlatObjectKind::String, FlatObjectKind::Path]),
        );
        let lists = FlatObjectStore::with_shared_arena(
            arena.clone(),
            FlatKindSet::of(&[FlatObjectKind::List]),
        );
        let attrs = FlatObjectStore::with_shared_arena(
            arena.clone(),
            FlatKindSet::of(&[FlatObjectKind::Attrs]),
        );
        Self {
            arena,
            values,
            lists,
            attrs,
        }
    }

    /// Returns this generation's Candidate-C domain.
    pub(in crate::eval::heap) fn domain(&self) -> Option<crate::heap::ArenaDomainId> {
        self.arena.arena_domain_id()
    }

    /// Resolves a string directly through this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a live string in this
    /// generation.
    pub(in crate::eval::heap) fn get_string(
        &self,
        value: Value,
    ) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.resolve(ptr, ValueTag::String, FlatObjectKind::String)
    }

    /// Resolves a path directly through this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a live path in this
    /// generation.
    pub(in crate::eval::heap) fn get_path(
        &self,
        value: Value,
    ) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
        self.resolve(ptr, ValueTag::Path, FlatObjectKind::Path)
    }

    /// Resolves a list directly through this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a live list in this
    /// generation.
    pub(in crate::eval::heap) fn get_list(&self, value: Value) -> Result<&NixList, EvalHeapError> {
        let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
        self.lists
            .resolve(ptr, FlatObjectKind::List)
            .map(|object| object.payload())
            .map_err(|error| permanent_relocation_error(ValueTag::List, ptr, error))
    }

    /// Resolves an attribute set directly through this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a live attribute set in
    /// this generation.
    pub(in crate::eval::heap) fn get_attrs(
        &self,
        value: Value,
    ) -> Result<&FlatAttrs, EvalHeapError> {
        self.get_attrs_payload(value).map(|payload| &payload.attrs)
    }

    /// Resolves a complete attribute-set payload directly through this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a live attribute set in
    /// this generation.
    pub(in crate::eval::heap) fn get_attrs_payload(
        &self,
        value: Value,
    ) -> Result<&FlatAttrsPayload, EvalHeapError> {
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        self.attrs
            .resolve(ptr, FlatObjectKind::Attrs)
            .map(|object| object.payload())
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))
    }

    /// Returns the metadata of an attribute set in this generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `value` is not a live attribute set in
    /// this generation.
    pub(in crate::eval::heap) fn get_attrs_metadata(
        &self,
        value: Value,
    ) -> Result<EvalHeapAttrsMetadata, EvalHeapError> {
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        self.attrs
            .resolve(ptr, FlatObjectKind::Attrs)
            .map(|object| object.payload().metadata)
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))
    }

    /// Copies one inline string into this unpublished generation.
    ///
    /// The destination receives a fresh inline byte run and a semantically
    /// reconstructed [`NixString`]. The immutable string context is shared
    /// through its existing copy-on-write identity; the source object and its
    /// registry entry remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not an inline string in
    /// `source_store`, source and destination use the same Candidate-C domain,
    /// or destination allocation/publication metadata cannot be prepared.
    pub(in crate::eval::heap) fn copy_inline_string_from(
        &mut self,
        source_store: &FlatObjectStore<NixString>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.copy_inline_string_like_from(
            source_store,
            source,
            ptr,
            ValueTag::String,
            FlatObjectKind::String,
        )
    }

    /// Copies one inline path into this unpublished generation.
    ///
    /// The destination receives a fresh inline byte run and a semantically
    /// reconstructed [`NixString`]. The immutable string context is shared
    /// through its existing copy-on-write identity; the source object and its
    /// registry entry remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not an inline path in
    /// `source_store`, source and destination use the same Candidate-C domain,
    /// or destination allocation/publication metadata cannot be prepared.
    pub(in crate::eval::heap) fn copy_inline_path_from(
        &mut self,
        source_store: &FlatObjectStore<NixString>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_path_ptr().map_err(EvalHeapError::Value)?;
        self.copy_inline_string_like_from(
            source_store,
            source,
            ptr,
            ValueTag::Path,
            FlatObjectKind::Path,
        )
    }

    /// Copies one owned string into this unpublished generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not an owned string in
    /// `source_store`, source and destination use the same Candidate-C domain,
    /// or byte/store allocation fails.
    pub(in crate::eval::heap) fn copy_owned_string_from(
        &mut self,
        source_store: &FlatObjectStore<NixString>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.copy_owned_string_like_from(
            source_store,
            source,
            ptr,
            ValueTag::String,
            FlatObjectKind::String,
        )
    }

    /// Copies one owned path into this unpublished generation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not an owned path in
    /// `source_store`, source and destination use the same Candidate-C domain,
    /// or byte/store allocation fails.
    pub(in crate::eval::heap) fn copy_owned_path_from(
        &mut self,
        source_store: &FlatObjectStore<NixString>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_path_ptr().map_err(EvalHeapError::Value)?;
        self.copy_owned_string_like_from(
            source_store,
            source,
            ptr,
            ValueTag::Path,
            FlatObjectKind::Path,
        )
    }

    /// Semantically copies one list into this unpublished generation.
    ///
    /// The destination receives a fresh exactly-sized element vector whose
    /// edges remain source words until complete forwarding is available.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not a list in `source_store`,
    /// source and destination use the same Candidate-C domain, or
    /// element/store allocation fails.
    pub(in crate::eval::heap) fn copy_list_from(
        &mut self,
        source_store: &FlatObjectStore<NixList>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_list_ptr().map_err(EvalHeapError::Value)?;
        let domain = self.copy_domain(source, ptr)?;
        let object = source_store
            .resolve(ptr, FlatObjectKind::List)
            .map_err(|error| permanent_relocation_error(ValueTag::List, ptr, error))?;
        if object.aux() != flat_aux_for_len(object.payload().len()) {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "list copy found inconsistent header length metadata",
            });
        }
        let elements = try_copy_slice(object.payload().as_slice())?;
        let allocation = self
            .lists
            .alloc_with_aux(
                FlatObjectKind::List,
                object.aux(),
                object.structural_hash(),
                object.last_touch_epoch(),
                NixList::new(elements),
            )
            .map_err(|error| permanent_relocation_error(ValueTag::List, ptr, error))?;
        self.value_for_destination(ValueTag::List, domain, allocation.ptr)
    }

    /// Copies one inline attribute set into this unpublished generation.
    ///
    /// All three self-relative arrays are copied through
    /// [`FlatObjectStore::alloc_with_trailing`] and receive fresh
    /// [`crate::heap::flat::FlatSlice`] witnesses. Entry values are copied
    /// verbatim; callers must wait for the complete forwarding relation, then
    /// call [`Self::rewrite_inline_attrs_edges_and_repair_hash`] before
    /// publishing the destination.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not an inline attribute set
    /// in `source_store`, its header length disagrees with its arrays, source
    /// and destination use the same Candidate-C domain, or tail planning,
    /// destination allocation, or value construction fails.
    pub(in crate::eval::heap) fn copy_inline_attrs_from(
        &mut self,
        source_store: &FlatObjectStore<FlatAttrsPayload>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        use crate::attrs::AttrEntry;
        use crate::attrs::AttrsStorageKind;

        let ptr = source.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        let domain = self.copy_domain(source, ptr)?;
        let object = source_store
            .resolve(ptr, FlatObjectKind::Attrs)
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
        let payload = object.payload();
        if payload.attrs.storage_kind() != AttrsStorageKind::FlatWitness {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "inline attrs copy requires self-relative FlatSlice storage",
            });
        }
        let len = payload.attrs.len();
        if object.aux() != flat_aux_for_len(len) {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "inline attrs copy found inconsistent header length metadata",
            });
        }

        let mut tail = FlatTailLayout::new();
        tail.add_slice::<AttrEntry>(len)
            .and_then(|()| tail.add_slice::<u32>(len))
            .and_then(|()| tail.add_slice::<u32>(len))
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
        let allocation = self
            .attrs
            .alloc_with_trailing(
                FlatObjectKind::Attrs,
                object.aux(),
                object.structural_hash(),
                object.last_touch_epoch(),
                tail,
                |writer| {
                    let entries = writer.write_slice(payload.attrs.entries_by_symbol())?;
                    let source_order = writer.write_slice(payload.attrs.source_order())?;
                    let iteration_order = writer.write_slice(payload.attrs.iteration_order())?;
                    Ok(FlatAttrsPayload {
                        metadata: payload.metadata,
                        attrs: FlatAttrs::from_flat_parts(entries, source_order, iteration_order),
                    })
                },
            )
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
        self.value_for_destination(ValueTag::Attrs, domain, allocation.ptr)
    }

    /// Copies one owned attribute set into this unpublished generation.
    ///
    /// The destination receives fresh exactly-sized entry and permutation
    /// vectors. Entry values remain source words until complete forwarding is
    /// available.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `source` is not an owned attrset in
    /// `source_store`, its header length disagrees with its arrays, source and
    /// destination use the same Candidate-C domain, or vector/store allocation
    /// fails.
    pub(in crate::eval::heap) fn copy_owned_attrs_from(
        &mut self,
        source_store: &FlatObjectStore<FlatAttrsPayload>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        use crate::attrs::AttrsStorageKind;

        let ptr = source.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        let domain = self.copy_domain(source, ptr)?;
        let object = source_store
            .resolve(ptr, FlatObjectKind::Attrs)
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
        let payload = object.payload();
        if payload.attrs.storage_kind() != AttrsStorageKind::Owned {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "owned attrs copy requires process-owned vector storage",
            });
        }
        let len = payload.attrs.len();
        if object.aux() != flat_aux_for_len(len) {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "owned attrs copy found inconsistent header length metadata",
            });
        }
        let attrs = FlatAttrs::from_restored_parts(
            try_copy_slice(payload.attrs.entries_by_symbol())?,
            try_copy_slice(payload.attrs.source_order())?,
            try_copy_slice(payload.attrs.iteration_order())?,
        );
        let allocation = self
            .attrs
            .alloc_with_aux(
                FlatObjectKind::Attrs,
                object.aux(),
                object.structural_hash(),
                object.last_touch_epoch(),
                FlatAttrsPayload {
                    metadata: payload.metadata,
                    attrs,
                },
            )
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
        self.value_for_destination(ValueTag::Attrs, domain, allocation.ptr)
    }

    /// Rewrites copied list edges and repairs their structural hash.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `destination` is not a list owned by this
    /// generation or structural-hash repair fails.
    pub(in crate::eval::heap) fn rewrite_list_edges_and_repair_hash(
        &mut self,
        destination: Value,
        mut rewrite: impl FnMut(Value) -> Value,
    ) -> Result<(), EvalHeapError> {
        let ptr = destination.as_list_ptr().map_err(EvalHeapError::Value)?;
        {
            let list = self
                .lists
                .resolve_mut(ptr, FlatObjectKind::List)
                .map_err(|error| permanent_relocation_error(ValueTag::List, ptr, error))?;
            list.rewrite_elements(&mut rewrite);
        }
        let hash = {
            let object = self
                .lists
                .resolve(ptr, FlatObjectKind::List)
                .map_err(|error| permanent_relocation_error(ValueTag::List, ptr, error))?;
            crate::eval::heap::arena::list_structural_hash(object.payload())
        };
        self.lists
            .update_structural_hash(ptr, FlatObjectKind::List, hash.raw())
            .map_err(|error| permanent_relocation_error(ValueTag::List, ptr, error))
    }

    /// Rewrites copied inline attr edges and repairs their structural hash.
    ///
    /// This is the post-complete-forwarding phase of destination-first copy:
    /// `rewrite` must translate each old edge to its final value without
    /// allocation or failure. Metadata, keys, positions, permutations, and
    /// the preserved last-touch epoch remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `destination` is not an inline attrset
    /// owned by this generation or structural-hash repair fails.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `rewrite`. Prior entry rewrites are not rolled
    /// back; callers invoke this only after all fallible transaction staging.
    pub(in crate::eval::heap) fn rewrite_inline_attrs_edges_and_repair_hash(
        &mut self,
        destination: Value,
        rewrite: impl FnMut(Value) -> Value,
    ) -> Result<(), EvalHeapError> {
        use crate::attrs::AttrsStorageKind;

        let ptr = destination.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        {
            let payload = self
                .attrs
                .resolve_mut(ptr, FlatObjectKind::Attrs)
                .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
            if payload.attrs.storage_kind() != AttrsStorageKind::FlatWitness {
                return Err(EvalHeapError::ShedRejected {
                    address: ptr.as_ptr() as usize,
                    reason: "inline attrs edge rewrite requires self-relative FlatSlice storage",
                });
            }
        }
        self.rewrite_attrs_edges_and_repair_hash(destination, rewrite)
    }

    /// Rewrites copied attrset edges and repairs their structural hash.
    ///
    /// Both owned and inline destination storage are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when `destination` is not an attrset owned by
    /// this generation or structural-hash repair fails.
    pub(in crate::eval::heap) fn rewrite_attrs_edges_and_repair_hash(
        &mut self,
        destination: Value,
        mut rewrite: impl FnMut(Value) -> Value,
    ) -> Result<(), EvalHeapError> {
        let ptr = destination.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        {
            let payload = self
                .attrs
                .resolve_mut(ptr, FlatObjectKind::Attrs)
                .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
            payload
                .attrs
                .rewrite_entry_values(&mut |value| Some(rewrite(value)));
        }
        let hash = {
            let object = self
                .attrs
                .resolve(ptr, FlatObjectKind::Attrs)
                .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
            crate::eval::heap::arena::attrs_structural_hash(
                object.payload().metadata,
                &object.payload().attrs,
            )
        };
        self.attrs
            .update_structural_hash(ptr, FlatObjectKind::Attrs, hash.raw())
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))
    }

    /// Moves one plain string from `source_store` into this generation.
    ///
    /// The payload and complete flat header move without cloning, preserving
    /// owned byte-buffer identity, structural hash, and last-touch epoch. The
    /// returned value uses this generation's Candidate-C domain.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] before changing the source when `source` has
    /// the wrong tag, does not belong to `source_store`, names another flat
    /// kind, carries inline tail storage, or shares backing with this
    /// generation. Reservation and registry allocation failures also leave
    /// the source unchanged.
    pub(in crate::eval::heap) fn relocate_string_from(
        &mut self,
        source_store: &mut FlatObjectStore<NixString>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.relocate_from(source_store, ptr, ValueTag::String, FlatObjectKind::String)
    }

    /// Moves one plain path from `source_store` into this generation.
    ///
    /// The payload and complete flat header move without cloning, preserving
    /// owned byte-buffer identity, structural hash, and last-touch epoch. The
    /// returned value uses this generation's Candidate-C domain.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] before changing the source when `source` has
    /// the wrong tag, does not belong to `source_store`, names another flat
    /// kind, carries inline tail storage, or shares backing with this
    /// generation. Reservation and registry allocation failures also leave
    /// the source unchanged.
    pub(in crate::eval::heap) fn relocate_path_from(
        &mut self,
        source_store: &mut FlatObjectStore<NixString>,
        source: Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_path_ptr().map_err(EvalHeapError::Value)?;
        self.relocate_from(source_store, ptr, ValueTag::Path, FlatObjectKind::Path)
    }

    /// Moves one plain list into this generation and rewrites its edges.
    ///
    /// The owned element vector and complete flat header move without
    /// cloning. `rewrite` is called once for every element during the
    /// allocation-free commit. The cached structural-hash word is copied
    /// unchanged; callers whose rewrite changes structural identity must
    /// repair it before publishing the destination.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] before changing the source when `source` has
    /// the wrong tag, store, kind, layout, or backing, or when destination
    /// reservation fails.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `rewrite`; see
    /// [`FlatObjectStore::relocate_plain_to_with`] for its unwind contract.
    pub(in crate::eval::heap) fn relocate_list_from(
        &mut self,
        source_store: &mut FlatObjectStore<NixList>,
        source: Value,
        mut rewrite: impl FnMut(Value) -> Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_list_ptr().map_err(EvalHeapError::Value)?;
        let domain = self.relocation_domain(ptr)?;
        source_store
            .resolve(ptr, FlatObjectKind::List)
            .map_err(|error| permanent_relocation_error(ValueTag::List, ptr, error))?;
        let relocation = source_store
            .relocate_plain_to_with(&mut self.lists, ptr, FlatObjectKind::List, |payload| {
                payload.rewrite_elements(&mut rewrite)
            })
            .map_err(|error| permanent_relocation_error(ValueTag::List, ptr, error))?;
        self.value_for_destination(ValueTag::List, domain, relocation.destination.ptr)
    }

    /// Moves one plain attribute set into this generation and rewrites its edges.
    ///
    /// Owned entry/permutation vectors, metadata, and the complete flat header
    /// move without cloning. `rewrite` is called once for every entry value
    /// during the allocation-free commit. Inline attrsets are fail-closed:
    /// their payload contains self-relative slice witnesses and cannot use the
    /// plain relocation contract. The cached structural-hash word is copied
    /// unchanged; callers whose rewrite changes structural identity must
    /// repair it before publishing the destination.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] before changing the source when `source` has
    /// the wrong tag, store, kind, layout, or backing, including an attrset
    /// with inline tail arrays, or when destination reservation fails.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `rewrite`; see
    /// [`FlatObjectStore::relocate_plain_to_with`] for its unwind contract.
    pub(in crate::eval::heap) fn relocate_attrs_from(
        &mut self,
        source_store: &mut FlatObjectStore<FlatAttrsPayload>,
        source: Value,
        mut rewrite: impl FnMut(Value) -> Value,
    ) -> Result<Value, EvalHeapError> {
        let ptr = source.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        let domain = self.relocation_domain(ptr)?;
        source_store
            .resolve(ptr, FlatObjectKind::Attrs)
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
        let relocation = source_store
            .relocate_plain_to_with(&mut self.attrs, ptr, FlatObjectKind::Attrs, |payload| {
                payload
                    .attrs
                    .rewrite_entry_values(&mut |value| Some(rewrite(value)));
            })
            .map_err(|error| permanent_relocation_error(ValueTag::Attrs, ptr, error))?;
        self.value_for_destination(ValueTag::Attrs, domain, relocation.destination.ptr)
    }

    fn resolve(
        &self,
        ptr: NonNull<HeapObject>,
        tag: ValueTag,
        kind: FlatObjectKind,
    ) -> Result<&NixString, EvalHeapError> {
        self.values
            .resolve(ptr, kind)
            .map(|object| object.payload())
            .map_err(|error| permanent_relocation_error(tag, ptr, error))
    }

    fn copy_inline_string_like_from(
        &mut self,
        source_store: &FlatObjectStore<NixString>,
        source: Value,
        ptr: NonNull<HeapObject>,
        tag: ValueTag,
        kind: FlatObjectKind,
    ) -> Result<Value, EvalHeapError> {
        use crate::string::StringBytesStorageKind;

        let domain = self.copy_domain(source, ptr)?;
        let object = source_store
            .resolve(ptr, kind)
            .map_err(|error| permanent_relocation_error(tag, ptr, error))?;
        let payload = object.payload();
        if payload.bytes_storage_kind() != StringBytesStorageKind::FlatWitness {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "inline string/path copy requires self-relative FlatBytes storage",
            });
        }
        if object.aux() != flat_aux_for_len(payload.len()) {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "inline string/path copy found inconsistent header length metadata",
            });
        }
        let context = payload.context().clone();
        let allocation = self
            .values
            .alloc_with_trailing_bytes(
                kind,
                object.structural_hash(),
                object.last_touch_epoch(),
                payload.bytes(),
                |bytes| NixString::from_flat_bytes(bytes, context),
            )
            .map_err(|error| permanent_relocation_error(tag, ptr, error))?;
        self.value_for_destination(tag, domain, allocation.ptr)
    }

    fn copy_owned_string_like_from(
        &mut self,
        source_store: &FlatObjectStore<NixString>,
        source: Value,
        ptr: NonNull<HeapObject>,
        tag: ValueTag,
        kind: FlatObjectKind,
    ) -> Result<Value, EvalHeapError> {
        use crate::string::StringBytesStorageKind;

        let domain = self.copy_domain(source, ptr)?;
        let object = source_store
            .resolve(ptr, kind)
            .map_err(|error| permanent_relocation_error(tag, ptr, error))?;
        let payload = object.payload();
        if payload.bytes_storage_kind() != StringBytesStorageKind::Owned {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "owned string/path copy requires process-owned byte storage",
            });
        }
        let bytes = try_copy_slice(payload.bytes())?;
        let allocation = self
            .values
            .alloc_with_aux(
                kind,
                object.aux(),
                object.structural_hash(),
                object.last_touch_epoch(),
                NixString::new(bytes, payload.context().clone()),
            )
            .map_err(|error| permanent_relocation_error(tag, ptr, error))?;
        self.value_for_destination(tag, domain, allocation.ptr)
    }

    fn copy_domain(
        &self,
        source: Value,
        ptr: NonNull<HeapObject>,
    ) -> Result<crate::heap::ArenaDomainId, EvalHeapError> {
        let destination = self.relocation_domain(ptr)?;
        if source.word().arena_domain() == Some(destination) {
            return Err(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "inline permanent copy requires a distinct destination domain",
            });
        }
        Ok(destination)
    }

    fn relocate_from(
        &mut self,
        source_store: &mut FlatObjectStore<NixString>,
        ptr: NonNull<HeapObject>,
        tag: ValueTag,
        kind: FlatObjectKind,
    ) -> Result<Value, EvalHeapError> {
        let domain = self.relocation_domain(ptr)?;

        source_store
            .resolve(ptr, kind)
            .map_err(|error| permanent_relocation_error(tag, ptr, error))?;
        let relocation = source_store
            .relocate_plain_to(&mut self.values, ptr, kind)
            .map_err(|error| permanent_relocation_error(tag, ptr, error))?;
        self.value_for_destination(tag, domain, relocation.destination.ptr)
    }

    fn relocation_domain(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<crate::heap::ArenaDomainId, EvalHeapError> {
        self.arena
            .arena_domain_id()
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated permanent generation lost Candidate-C domain",
            })
    }

    fn value_for_destination(
        &self,
        tag: ValueTag,
        domain: crate::heap::ArenaDomainId,
        ptr: NonNull<HeapObject>,
    ) -> Result<Value, EvalHeapError> {
        let index = self
            .arena
            .index_for_pointer(ptr)
            .ok_or(EvalHeapError::ShedRejected {
                address: ptr.as_ptr() as usize,
                reason: "evacuated permanent destination is outside its reservation",
            })?;
        Value::from_domain_index(tag, domain, index).map_err(EvalHeapError::Value)
    }
}

fn try_copy_slice<T: Copy>(source: &[T]) -> Result<Vec<T>, EvalHeapError> {
    let mut destination = Vec::new();
    destination.try_reserve_exact(source.len()).map_err(|_| {
        EvalHeapError::RecordAllocationFailed {
            records: source.len(),
        }
    })?;
    destination.extend_from_slice(source);
    Ok(destination)
}

fn permanent_relocation_error(
    tag: ValueTag,
    ptr: NonNull<HeapObject>,
    error: FlatObjectError,
) -> EvalHeapError {
    match error {
        FlatObjectError::Arena(source) => EvalHeapError::Arena(source),
        FlatObjectError::RegistryAllocationFailed { entries } => {
            EvalHeapError::RecordAllocationFailed { records: entries }
        }
        FlatObjectError::UnknownAddress { .. } => EvalHeapError::unknown(tag, ptr),
        FlatObjectError::KindMismatch { actual, .. } => {
            EvalHeapError::record_type_mismatch(tag, value_tag_for_flat_kind(actual), ptr)
        }
        FlatObjectError::RelocationRequiresPlainObject { .. } => EvalHeapError::ShedRejected {
            address: ptr.as_ptr() as usize,
            reason: "permanent evacuation requires a plain object without self-relative tails",
        },
        FlatObjectError::RelocationRequiresDistinctBacking { .. } => EvalHeapError::ShedRejected {
            address: ptr.as_ptr() as usize,
            reason: "permanent evacuation requires distinct source and destination backing",
        },
        FlatObjectError::KindNotAllowed { .. } => EvalHeapError::ShedRejected {
            address: ptr.as_ptr() as usize,
            reason: "permanent evacuation destination rejects the source kind",
        },
        FlatObjectError::InvalidRegionMark { .. }
        | FlatObjectError::SharedArenaRegionUnsupported => EvalHeapError::ShedRejected {
            address: ptr.as_ptr() as usize,
            reason: "permanent evacuation encountered invalid store state",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attrs::AttrEntry;
    use crate::attrs::repr::AttrSetReprKind;
    use crate::string::{ContextElement, StringContext};
    use crate::syntax::SymbolTable;

    fn owned_payload(byte: u8) -> NixString {
        NixString::from_bytes(vec![byte; FLAT_INLINE_BYTES_MAX + 1])
    }

    #[test]
    fn inline_string_and_path_copy_semantics_without_mutating_sources() {
        let context = StringContext::singleton(
            ContextElement::opaque_path(b"/nix/store/source".to_vec())
                .expect("opaque context builds"),
        )
        .expect("singleton context builds");
        let mut source_heap = EvalHeap::new();
        let source_string = source_heap
            .alloc_string(NixString::new(b"inline string".to_vec(), context.clone()))
            .expect("inline source string allocates");
        let source_path = source_heap
            .alloc_path(NixString::new(b"/inline/path".to_vec(), context.clone()))
            .expect("inline source path allocates");
        let string_ptr = source_string
            .as_string_ptr()
            .expect("source string has a pointer");
        let path_ptr = source_path
            .as_path_ptr()
            .expect("source path has a pointer");
        let source_string_object = source_heap
            .flat
            .resolve(string_ptr, FlatObjectKind::String)
            .expect("source string resolves");
        let source_string_bytes = source_string_object.payload().bytes().as_ptr();
        let string_hash = source_string_object.structural_hash();
        let string_epoch = source_string_object.last_touch_epoch();
        let source_path_object = source_heap
            .flat
            .resolve(path_ptr, FlatObjectKind::Path)
            .expect("source path resolves");
        let source_path_bytes = source_path_object.payload().bytes().as_ptr();
        let path_hash = source_path_object.structural_hash();
        let path_epoch = source_path_object.last_touch_epoch();
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };

        let copied_string = destination
            .copy_inline_string_from(&source_heap.flat, source_string)
            .expect("inline string copies");
        let copied_path = destination
            .copy_inline_path_from(&source_heap.flat, source_path)
            .expect("inline path copies");
        let copied_string_ptr = copied_string
            .as_string_ptr()
            .expect("copied string has a pointer");
        let copied_path_ptr = copied_path
            .as_path_ptr()
            .expect("copied path has a pointer");
        let copied_string_object = destination
            .values
            .resolve(copied_string_ptr, FlatObjectKind::String)
            .expect("copied string resolves");
        let copied_path_object = destination
            .values
            .resolve(copied_path_ptr, FlatObjectKind::Path)
            .expect("copied path resolves");

        assert_ne!(
            source_string.word().arena_domain(),
            copied_string.word().arena_domain()
        );
        assert_ne!(
            copied_string_object.payload().bytes().as_ptr(),
            source_string_bytes,
            "destination owns a fresh inline byte run"
        );
        assert_ne!(
            copied_path_object.payload().bytes().as_ptr(),
            source_path_bytes,
            "destination owns a fresh inline byte run"
        );
        assert_eq!(copied_string_object.structural_hash(), string_hash);
        assert_eq!(copied_string_object.last_touch_epoch(), string_epoch);
        assert_eq!(copied_path_object.structural_hash(), path_hash);
        assert_eq!(copied_path_object.last_touch_epoch(), path_epoch);
        assert_eq!(
            copied_string_object.payload(),
            source_heap
                .get_string(source_string)
                .expect("source string remains live")
        );
        assert_eq!(
            copied_path_object.payload(),
            source_heap
                .get_path(source_path)
                .expect("source path remains live")
        );
        assert_eq!(copied_string_object.payload().context(), &context);
        assert_eq!(copied_path_object.payload().context(), &context);
    }

    #[test]
    fn inline_attrs_copy_then_rewrite_edges_and_repair_hash() {
        let mut symbols = SymbolTable::new();
        let key = symbols.intern(b"child").expect("symbol interns");
        let mut source_heap = EvalHeap::new();
        let source_child = source_heap
            .alloc_string(NixString::from_bytes(b"child value".to_vec()))
            .expect("inline child allocates");
        let attrs = FlatAttrs::new(vec![AttrEntry::new(key, source_child)], &symbols)
            .expect("inline attrs build");
        let source = source_heap
            .alloc_attrs(29, attrs)
            .expect("inline attrs allocate");
        let source_ptr = source.as_attrs_ptr().expect("source attrs has a pointer");
        let source_object = source_heap
            .flat_attrs
            .resolve(source_ptr, FlatObjectKind::Attrs)
            .expect("source attrs resolves");
        let source_entries = source_object.payload().attrs.entries_by_symbol().as_ptr();
        let source_source_order = source_object.payload().attrs.source_order().to_vec();
        let source_iteration_order = source_object.payload().attrs.iteration_order().to_vec();
        let source_metadata = source_object.payload().metadata;
        let source_hash = source_object.structural_hash();
        let source_epoch = source_object.last_touch_epoch();
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };
        let copied_child = destination
            .copy_inline_string_from(&source_heap.flat, source_child)
            .expect("inline child copies");

        let copied = destination
            .copy_inline_attrs_from(&source_heap.flat_attrs, source)
            .expect("inline attrs copy");
        let copied_ptr = copied.as_attrs_ptr().expect("copied attrs has a pointer");
        {
            let copied_object = destination
                .attrs
                .resolve(copied_ptr, FlatObjectKind::Attrs)
                .expect("copied attrs resolves before rewrite");
            assert_ne!(
                copied_object.payload().attrs.entries_by_symbol().as_ptr(),
                source_entries,
                "destination owns fresh inline attr arrays"
            );
            assert_eq!(
                copied_object.payload().attrs.source_order(),
                source_source_order
            );
            assert_eq!(
                copied_object.payload().attrs.iteration_order(),
                source_iteration_order
            );
            assert_eq!(copied_object.payload().metadata, source_metadata);
            assert_eq!(copied_object.structural_hash(), source_hash);
            assert_eq!(copied_object.last_touch_epoch(), source_epoch);
            assert!(
                copied_object
                    .payload()
                    .attrs
                    .get(key)
                    .expect("copied edge exists")
                    .raw_eq(source_child),
                "copy phase preserves old edges until forwarding is complete"
            );
        }

        destination
            .rewrite_inline_attrs_edges_and_repair_hash(copied, |value| {
                if value.raw_eq(source_child) {
                    copied_child
                } else {
                    value
                }
            })
            .expect("copied attrs edges rewrite and hash repairs");
        let copied_object = destination
            .attrs
            .resolve(copied_ptr, FlatObjectKind::Attrs)
            .expect("copied attrs resolves after rewrite");
        assert!(
            copied_object
                .payload()
                .attrs
                .get(key)
                .expect("rewritten edge exists")
                .raw_eq(copied_child)
        );
        assert_eq!(copied_object.last_touch_epoch(), source_epoch);
        assert_eq!(
            copied_object.structural_hash(),
            crate::eval::heap::arena::attrs_structural_hash(
                copied_object.payload().metadata,
                &copied_object.payload().attrs,
            )
            .raw()
        );
        assert!(
            source_heap
                .get_attrs(source)
                .expect("source attrs remains live")
                .get(key)
                .expect("source edge remains")
                .raw_eq(source_child),
            "destination edge rewrite does not mutate the source"
        );
    }

    #[test]
    fn inline_copy_rejects_owned_storage_and_same_domain_before_allocating() {
        let mut source_heap = EvalHeap::new();
        let owned = source_heap
            .alloc_string(owned_payload(b'o'))
            .expect("owned source string allocates");
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };

        assert!(
            destination
                .copy_inline_string_from(&source_heap.flat, owned)
                .is_err()
        );
        assert_eq!(destination.values.live_len(), 0);
        assert_eq!(
            source_heap
                .get_string(owned)
                .expect("owned rejection keeps source live")
                .len(),
            FLAT_INLINE_BYTES_MAX + 1
        );

        let inline = source_heap
            .alloc_string(NixString::from_bytes(b"inline".to_vec()))
            .expect("inline source string allocates");
        let mut same_domain =
            EvacuatedPermanentGeneration::with_shared_arena(source_heap.flat_arena.clone());
        assert!(
            same_domain
                .copy_inline_string_from(&source_heap.flat, inline)
                .is_err()
        );
        assert_eq!(same_domain.values.live_len(), 0);
        assert_eq!(
            source_heap
                .get_string(inline)
                .expect("same-domain rejection keeps source live")
                .bytes(),
            b"inline"
        );
    }

    #[test]
    fn owned_string_moves_across_domains_without_cloning_and_keeps_header() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };
        let source = source_heap
            .alloc_string(owned_payload(b's'))
            .expect("source string allocates");
        let source_ptr = source.as_string_ptr().expect("source is a string");
        let source_object = source_heap
            .flat
            .resolve(source_ptr, FlatObjectKind::String)
            .expect("source string resolves");
        let bytes_ptr = source_object.payload().bytes().as_ptr();
        let hash = source_object.structural_hash();
        let epoch = source_object.last_touch_epoch();

        let moved = destination
            .relocate_string_from(&mut source_heap.flat, source)
            .expect("owned string relocates");
        let moved_ptr = moved.as_string_ptr().expect("destination is a string");
        let moved_object = destination
            .values
            .resolve(moved_ptr, FlatObjectKind::String)
            .expect("destination string resolves");

        assert_ne!(source.word().arena_domain(), moved.word().arena_domain());
        assert_eq!(destination.domain(), moved.word().arena_domain());
        assert_eq!(moved_object.payload().bytes().as_ptr(), bytes_ptr);
        assert_eq!(moved_object.structural_hash(), hash);
        assert_eq!(moved_object.last_touch_epoch(), epoch);
        assert!(
            source_heap
                .flat
                .resolve(source_ptr, FlatObjectKind::String)
                .is_err(),
            "the source registry entry is retired"
        );

        drop(source_heap);
        assert_eq!(
            destination
                .get_string(moved)
                .expect("moved string lives")
                .len(),
            FLAT_INLINE_BYTES_MAX + 1
        );
    }

    #[test]
    fn owned_path_moves_across_domains_and_publishes_a_path_value() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };
        let source = source_heap
            .alloc_path(owned_payload(b'p'))
            .expect("source path allocates");

        let moved = destination
            .relocate_path_from(&mut source_heap.flat, source)
            .expect("owned path relocates");

        assert_ne!(source.word().arena_domain(), moved.word().arena_domain());
        assert_eq!(
            destination
                .get_path(moved)
                .expect("moved path resolves")
                .bytes(),
            vec![b'p'; FLAT_INLINE_BYTES_MAX + 1]
        );
    }

    #[test]
    fn owned_list_moves_rewrites_edges_and_preserves_payload_and_header() {
        let mut source_heap = EvalHeap::new();
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };
        let list = NixList::new(vec![Value::int(3), Value::int(5)]);
        let elements_ptr = list.as_slice().as_ptr();
        let allocation = source_heap
            .flat_lists
            .alloc_with_aux(FlatObjectKind::List, flat_aux_for_len(2), 0x51_57, 73, list)
            .expect("plain source list allocates");
        let source = source_heap
            .value_for_flat_allocation(ValueTag::List, allocation.ptr)
            .expect("source list value publishes");

        let moved = destination
            .relocate_list_from(&mut source_heap.flat_lists, source, |value| {
                if value.raw_eq(Value::int(5)) {
                    Value::int(8)
                } else {
                    value
                }
            })
            .expect("plain list relocates");
        let moved_ptr = moved.as_list_ptr().expect("destination is a list");
        let moved_object = destination
            .lists
            .resolve(moved_ptr, FlatObjectKind::List)
            .expect("destination list resolves");

        assert_ne!(source.word().arena_domain(), moved.word().arena_domain());
        assert_eq!(moved_object.payload().as_slice().as_ptr(), elements_ptr);
        assert_eq!(moved_object.structural_hash(), 0x51_57);
        assert_eq!(moved_object.last_touch_epoch(), 73);
        let moved_list = destination.get_list(moved).expect("moved list resolves");
        assert!(moved_list.get(0).expect("first edge").raw_eq(Value::int(3)));
        assert!(
            moved_list
                .get(1)
                .expect("second edge")
                .raw_eq(Value::int(8))
        );
        assert!(
            source_heap
                .flat_lists
                .resolve(allocation.ptr, FlatObjectKind::List)
                .is_err()
        );
    }

    #[test]
    fn owned_attrs_move_rewrites_edges_and_preserves_payload_metadata_and_header() {
        let mut symbols = SymbolTable::new();
        let first = symbols.intern(b"first").expect("first symbol interns");
        let second = symbols.intern(b"second").expect("second symbol interns");
        let attrs = FlatAttrs::new(
            vec![
                AttrEntry::new(first, Value::int(13)),
                AttrEntry::new(second, Value::int(21)),
            ],
            &symbols,
        )
        .expect("owned attrs build");
        let entries_ptr = attrs.entries_by_symbol().as_ptr();
        let metadata = EvalHeapAttrsMetadata::new(41, AttrSetReprKind::Flat);
        let mut source_heap = EvalHeap::new();
        let allocation = source_heap
            .flat_attrs
            .alloc_with_aux(
                FlatObjectKind::Attrs,
                flat_aux_for_len(2),
                0xa7_75,
                89,
                FlatAttrsPayload { metadata, attrs },
            )
            .expect("plain source attrs allocate");
        let source = source_heap
            .value_for_flat_allocation(ValueTag::Attrs, allocation.ptr)
            .expect("source attrs value publishes");
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };

        let moved = destination
            .relocate_attrs_from(&mut source_heap.flat_attrs, source, |value| {
                if value.raw_eq(Value::int(21)) {
                    Value::int(34)
                } else {
                    value
                }
            })
            .expect("plain attrs relocate");
        let moved_ptr = moved.as_attrs_ptr().expect("destination is attrs");
        let moved_object = destination
            .attrs
            .resolve(moved_ptr, FlatObjectKind::Attrs)
            .expect("destination attrs resolve");

        assert_ne!(source.word().arena_domain(), moved.word().arena_domain());
        assert_eq!(
            moved_object.payload().attrs.entries_by_symbol().as_ptr(),
            entries_ptr
        );
        assert_eq!(moved_object.structural_hash(), 0xa7_75);
        assert_eq!(moved_object.last_touch_epoch(), 89);
        assert_eq!(
            destination
                .get_attrs_metadata(moved)
                .expect("attrs metadata resolves"),
            metadata
        );
        let moved_attrs = destination.get_attrs(moved).expect("moved attrs resolve");
        assert!(
            moved_attrs
                .get(first)
                .expect("first value")
                .raw_eq(Value::int(13))
        );
        assert!(
            moved_attrs
                .get(second)
                .expect("second value")
                .raw_eq(Value::int(34))
        );
        assert!(
            source_heap
                .flat_attrs
                .resolve(allocation.ptr, FlatObjectKind::Attrs)
                .is_err()
        );
    }

    #[test]
    fn inline_attrs_fail_closed_before_edge_rewrite_or_source_mutation() {
        let mut symbols = SymbolTable::new();
        let key = symbols.intern(b"inline").expect("symbol interns");
        let attrs = FlatAttrs::new(vec![AttrEntry::new(key, Value::int(55))], &symbols)
            .expect("attrs build");
        let mut source_heap = EvalHeap::new();
        let source = source_heap
            .alloc_attrs(7, attrs)
            .expect("inline attrs allocate");
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };
        let mut rewrite_called = false;

        assert!(
            destination
                .relocate_attrs_from(&mut source_heap.flat_attrs, source, |value| {
                    rewrite_called = true;
                    value
                })
                .is_err()
        );
        assert!(!rewrite_called);
        assert!(
            source_heap
                .get_attrs(source)
                .expect("inline source remains live")
                .get(key)
                .expect("source edge remains")
                .raw_eq(Value::int(55))
        );
    }

    #[test]
    fn foreign_list_store_fails_before_edge_rewrite_or_source_mutation() {
        let mut source_heap = EvalHeap::new();
        let mut foreign_heap = EvalHeap::new();
        let list = NixList::new(vec![Value::int(144)]);
        let elements_ptr = list.as_slice().as_ptr();
        let allocation = source_heap
            .flat_lists
            .alloc_with_aux(FlatObjectKind::List, flat_aux_for_len(1), 0x90, 34, list)
            .expect("plain source list allocates");
        let source = source_heap
            .value_for_flat_allocation(ValueTag::List, allocation.ptr)
            .expect("source list value publishes");
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };
        let mut rewrite_called = false;

        assert!(
            destination
                .relocate_list_from(&mut foreign_heap.flat_lists, source, |value| {
                    rewrite_called = true;
                    value
                })
                .is_err()
        );
        assert!(!rewrite_called);
        let retained = source_heap
            .flat_lists
            .resolve(allocation.ptr, FlatObjectKind::List)
            .expect("foreign-store rejection keeps source live");
        assert_eq!(retained.payload().as_slice().as_ptr(), elements_ptr);
        assert!(
            retained
                .payload()
                .get(0)
                .expect("source edge remains")
                .raw_eq(Value::int(144))
        );
    }

    #[test]
    fn wrong_kind_and_foreign_domain_fail_without_mutating_sources() {
        let mut source_heap = EvalHeap::new();
        let mut foreign_heap = EvalHeap::new();
        let Some(mut destination) =
            EvacuatedGeneration::new().map(EvacuatedGeneration::into_permanent_generation)
        else {
            return;
        };
        let path = source_heap
            .alloc_path(owned_payload(b'k'))
            .expect("source path allocates");
        let path_word = path.word();
        let forged_string = Value::from_domain_index(
            ValueTag::String,
            path_word
                .arena_domain()
                .expect("path carries a Candidate-C domain"),
            path_word
                .arena_index()
                .expect("path carries a Candidate-C index"),
        )
        .expect("the test can forge a mismatched tag");
        let string = source_heap
            .alloc_string(owned_payload(b'd'))
            .expect("source string allocates");

        assert!(
            destination
                .relocate_string_from(&mut source_heap.flat, forged_string)
                .is_err()
        );
        assert_eq!(
            source_heap
                .get_path(path)
                .expect("path remains live")
                .bytes()[0],
            b'k'
        );

        assert!(
            destination
                .relocate_string_from(&mut foreign_heap.flat, string)
                .is_err()
        );
        assert_eq!(
            source_heap
                .get_string(string)
                .expect("foreign-domain rejection keeps source live")
                .bytes()[0],
            b'd'
        );
    }

    #[test]
    fn shared_backing_fails_without_mutating_source() {
        let mut source_heap = EvalHeap::new();
        let arena = source_heap.flat_arena.clone();
        let mut destination = EvacuatedPermanentGeneration::with_shared_arena(arena);
        let source = source_heap
            .alloc_string(owned_payload(b'b'))
            .expect("source string allocates");

        assert!(
            destination
                .relocate_string_from(&mut source_heap.flat, source)
                .is_err()
        );
        assert_eq!(
            source_heap
                .get_string(source)
                .expect("same-backing rejection keeps source live")
                .bytes()[0],
            b'b'
        );
    }
}
