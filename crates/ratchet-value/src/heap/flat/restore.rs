//! Heap-image restore doors for the flat object store (RFC-0007 doc 31 §1).
//!
//! A restored reservation holds every object's dumped bytes verbatim, but the
//! store built over it starts with an empty registry and region index. These
//! doors rebuild the store-side metadata: region adoption, payload
//! reinstallation over the stale dumped bytes (the one sealed unsafe write),
//! value-tail extent registration, and the registry re-sort that handle-based
//! tail resolution depends on. Everything here is snapshot-restore-only and
//! lives off the allocation and resolution hot paths.

use super::*;

impl<T> FlatObjectStore<T> {
    /// Primes the shared-arena membership index for a store constructed over an
    /// already-populated reloaded reservation (RFC-0007 doc 31 §1 heap-image
    /// restore).
    ///
    /// A freshly built store has an empty region index and only refreshes it on
    /// allocation, so a store that never allocated cannot resolve objects the
    /// arena already holds from a restored image. This adopts the backing arena's
    /// current regions once, after which [`FlatObjectStore::resolve`] resolves
    /// restored objects by header witness exactly as for freshly allocated ones.
    #[cfg(feature = "candidate_c_value")]
    pub fn adopt_shared_regions(&mut self) {
        self.refresh_regions();
    }

    /// Registers a restored flat object at `ptr` so the store's [`Drop`] runs its
    /// payload drop glue (RFC-0007 doc 31 §1 list increment).
    ///
    /// Heap-image restore rebuilds out-of-arena payloads — a list's element
    /// `Vec`, whose backing buffer the dumped arena bytes do not carry — and
    /// writes them into objects the reloaded arena already holds.
    /// [`FlatObjectStore::adopt_shared_regions`] primes only the membership
    /// index, so those objects are absent from the registry that drives `Drop`;
    /// without this call their rebuilt buffers would leak. The recorded size is
    /// the payload-inclusive object size and feeds only store accounting, never
    /// drop correctness (which needs the pointer alone).
    ///
    /// The caller must first have installed a valid payload at `ptr` (see
    /// [`FlatObjectStore::restore_payload`]); registering an object whose payload
    /// is still the stale dumped bytes would drop a dangling handle.
    #[cfg(feature = "candidate_c_value")]
    pub fn adopt_restored_object(&mut self, ptr: NonNull<HeapObject>) {
        self.entries.push(FlatStoreEntry::plain(
            ptr,
            core::mem::size_of::<FlatObject<T>>(),
        ));
    }

    /// Installs `payload` into the restored flat object at `ptr`, overwriting the
    /// stale dumped bytes without dropping them, and registers the object so its
    /// [`Drop`] runs (RFC-0007 doc 31 §1 list increment).
    ///
    /// Heap-image restore reloads an object's arena bytes verbatim, so its
    /// payload is the source process's stale value — for a list, a `Vec` header
    /// pointing at a freed buffer that must never be read or dropped. This
    /// resolves the object, overwrites that payload in place with the
    /// freshly-owned `payload` without running the stale value's drop glue, then
    /// records the object in the registry so the store's `Drop` frees the new
    /// payload exactly once. It exists in this crate because
    /// [`crate::heap::snapshot`]'s consumer forbids `unsafe`.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when `ptr` is not a `kind` object of this
    /// store (an unknown address or a kind mismatch).
    #[cfg(feature = "candidate_c_value")]
    pub fn restore_payload(
        &mut self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
        payload: T,
    ) -> Result<(), FlatObjectError> {
        self.write_restored_payload(ptr, kind, payload)?;
        self.adopt_restored_object(ptr);
        Ok(())
    }

    /// Installs `payload` into a restored flat object that owns an inline
    /// `Value` tail, and registers the object with its tail extent (RFC-0007
    /// doc 31 §1 step-3 closure restore).
    ///
    /// The tail values themselves ride the dumped arena lanes (they are
    /// address-free words trailing the object), so only the registry metadata
    /// must be rebuilt: the payload-inclusive entry size and the private
    /// `Value`-tail flag that admits handle-based tail resolution. `tail_len`
    /// is untrusted image input; the computed extent is validated against the
    /// backing arena's live regions before anything is recorded, so a forged
    /// length can never mint a handle to out-of-mapping bytes.
    ///
    /// After every restored object is registered, call
    /// [`FlatObjectStore::finalize_restored_registry`] to re-establish the
    /// registry address order that handle signing relies on.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when `ptr` is not a `kind` object of this
    /// store, or when the declared tail extent overflows or leaves the live
    /// arena region containing the object.
    #[cfg(feature = "candidate_c_value")]
    pub fn restore_payload_with_value_tail(
        &mut self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
        payload: T,
        tail_len: usize,
    ) -> Result<(), FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let object_size = core::mem::size_of::<FlatObject<T>>();
        let size_bytes = core::mem::size_of::<crate::value::Value>()
            .checked_mul(tail_len)
            .and_then(|tail_bytes| object_size.checked_add(tail_bytes))
            .ok_or(FlatObjectError::UnknownAddress { address })?;
        if size_bytes > super::value_tail::VALUE_TAIL_PACKED_SIZE_MASK {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let end = address
            .checked_add(size_bytes)
            .ok_or(FlatObjectError::UnknownAddress { address })?;
        if !self.range_in_live_region(address, end) {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        self.write_restored_payload(ptr, kind, payload)?;
        let generation = self.issue_value_tail_generation().ok_or(
            FlatObjectError::RegistryAllocationFailed {
                entries: self.entries.len(),
            },
        )?;
        let mut entry = FlatStoreEntry::plain(ptr, size_bytes);
        if !entry.mark_value_tail(generation) {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Overwrites a restored object's stale dumped payload without dropping it.
    ///
    /// Registration is the caller's responsibility (see the two `restore_payload`
    /// doors), so the freshly-installed payload is dropped exactly once.
    #[cfg(feature = "candidate_c_value")]
    fn write_restored_payload(
        &mut self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
        payload: T,
    ) -> Result<(), FlatObjectError> {
        let slot = self.resolve_mut(ptr, kind)?;
        // SAFETY: `resolve_mut` proved `slot` names a live `FlatObject<T>`
        // payload in this store's arena. Its current bytes are the dumped
        // payload — for a restored object, a stale owning value (e.g. a `Vec`
        // header pointing at a freed buffer) that must not be read or dropped.
        // `ptr::write` overwrites all payload bytes with `payload` without
        // running the stale value's drop glue, so no dangling resource is freed;
        // `slot` is a unique `&mut` derived from `ptr`, so the write cannot race
        // or alias. The caller's registration then makes the store own the
        // freshly-installed payload for `Drop`.
        unsafe { std::ptr::write(slot as *mut T, payload) };
        Ok(())
    }

    /// Re-establishes registry address order after heap-image restore.
    ///
    /// Restored objects are registered in image segment order, which need not
    /// match allocation order when multiple segments feed one store (primops
    /// and closures share the flat-closure store). Handle-based tail
    /// resolution binary-searches the registry by address, so restore must
    /// sort it back into the backing lane's canonical order: descending for
    /// the rewindable (downward-growing) lane, ascending otherwise.
    #[cfg(feature = "candidate_c_value")]
    pub fn finalize_restored_registry(&mut self) {
        match &self.backing {
            FlatStoreBacking::Rewindable { .. } => self
                .entries
                .sort_unstable_by_key(|entry| core::cmp::Reverse(entry.ptr.as_ptr() as usize)),
            _ => self
                .entries
                .sort_unstable_by_key(|entry| entry.ptr.as_ptr() as usize),
        }
    }

    /// Returns whether `[start, end)` lies inside one live arena chunk region.
    #[cfg(feature = "candidate_c_value")]
    fn range_in_live_region(&self, start: usize, end: usize) -> bool {
        let position = self
            .regions
            .partition_point(|&(region_start, _end)| region_start <= start);
        position
            .checked_sub(1)
            .and_then(|index| self.regions.get(index))
            .is_some_and(|&(_start, region_end)| start < region_end && end <= region_end)
    }
}
