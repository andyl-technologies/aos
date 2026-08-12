//! Allocation-first relocation for plain flat objects.
//!
//! This module supplies the smallest physical-movement primitive needed by
//! the selective evacuation writer. It deliberately rejects objects with
//! inline byte, typed, or `Value` tails: those payloads contain self-relative
//! witnesses or registry-coordinate handles and require a kind-specific
//! relocation contract.

use super::alloc::FlatLayoutCheck;
use super::*;

/// The old and new coordinates produced by one flat-object relocation.
#[derive(Clone, Copy, Debug)]
pub struct FlatRelocation {
    /// The source address, whose registry entry is now a tombstone.
    pub source: NonNull<HeapObject>,
    /// The unpublished destination allocation.
    pub destination: FlatAllocation,
}

impl<T> FlatObjectStore<T> {
    /// Returns whether `source` has the plain layout accepted by relocation.
    ///
    /// A plain object has no typed tail and its registered extent is exactly
    /// one [`FlatObject<T>`]. The check is read-only and applies the same
    /// source-address, liveness, and kind validation as
    /// [`Self::relocate_plain_to_with`].
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::UnknownAddress`] when `source` is not an
    /// exact live allocation and [`FlatObjectError::KindMismatch`] when its
    /// header has another kind.
    pub fn is_plain_relocation_source(
        &self,
        source: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<bool, FlatObjectError> {
        self.check_kind_allowed(kind)?;
        let address = source.as_ptr() as usize;
        let Some(source_index) = self.entry_index_for_address(address) else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        let Some(source_entry) = self.entries.get(source_index).copied() else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        if !source_entry.is_live() {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let actual = self.kind_at(source)?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address,
            });
        }
        Ok(!source_entry.has_value_tail()
            && source_entry.size_bytes() == mem::size_of::<FlatObject<T>>())
    }

    /// Moves one plain object into an independently backed destination store.
    ///
    /// This is the cross-store form of [`Self::relocate_plain`]. The source
    /// and destination must have the same payload type but distinct physical
    /// backings. A destination allocation is registered only after the source
    /// payload ownership has moved successfully.
    ///
    /// # Errors
    ///
    /// Returns the validation and allocation errors documented by
    /// [`Self::relocate_plain_with`], plus
    /// [`FlatObjectError::RelocationRequiresDistinctBacking`] when both stores
    /// allocate from the same shared backing.
    pub fn relocate_plain_to(
        &mut self,
        destination_store: &mut Self,
        source: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<FlatRelocation, FlatObjectError> {
        self.relocate_plain_to_with(destination_store, source, kind, |_| {})
    }

    /// Rewrites and moves one plain object into an independent store.
    ///
    /// All validation, registry reservation, backing allocation, and
    /// destination membership refresh complete before `rewrite` is called.
    /// Once it returns, the commit performs no allocation: it transfers the
    /// object, tombstones the source registry slot, registers the destination,
    /// and updates both reservations' page-liveness ledgers.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::UnknownAddress`] when `source` is not an
    /// exact live source allocation, [`FlatObjectError::KindMismatch`] when
    /// its header has another kind,
    /// [`FlatObjectError::RelocationRequiresPlainObject`] for inline tails,
    /// [`FlatObjectError::KindNotAllowed`] when the destination rejects
    /// `kind`, or [`FlatObjectError::RelocationRequiresDistinctBacking`] when
    /// both stores share physical backing. Registry and destination backing
    /// allocation failures leave the source unchanged.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `rewrite`. The source remains registered and
    /// owns its payload during unwinding, but callback mutations are not
    /// rolled back.
    pub fn relocate_plain_to_with(
        &mut self,
        destination_store: &mut Self,
        source: NonNull<HeapObject>,
        kind: FlatObjectKind,
        rewrite: impl FnOnce(&mut T),
    ) -> Result<FlatRelocation, FlatObjectError> {
        let () = FlatLayoutCheck::<T>::PAYLOAD_FITS_ARENA_ALIGNMENT;
        self.check_kind_allowed(kind)?;
        destination_store.check_kind_allowed(kind)?;
        let address = source.as_ptr() as usize;
        if self
            .backing
            .shares_allocation_backing(&destination_store.backing)
        {
            return Err(FlatObjectError::RelocationRequiresDistinctBacking { address });
        }

        let Some(source_index) = self.entry_index_for_address(address) else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        let Some(source_entry) = self.entries.get(source_index).copied() else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        if !source_entry.is_live() {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let actual = self.kind_at(source)?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address,
            });
        }
        let plain_bytes = mem::size_of::<FlatObject<T>>();
        let registered_bytes = source_entry.size_bytes();
        if source_entry.has_value_tail() || registered_bytes != plain_bytes {
            return Err(FlatObjectError::RelocationRequiresPlainObject {
                address,
                registered_bytes,
                plain_bytes,
            });
        }

        let destination_index = destination_store.entries.len();
        let entries =
            destination_index
                .checked_add(1)
                .ok_or(FlatObjectError::RegistryAllocationFailed {
                    entries: usize::MAX,
                })?;
        destination_store
            .entries
            .try_reserve(1)
            .map_err(|_| FlatObjectError::RegistryAllocationFailed { entries })?;
        let allocation = destination_store
            .backing
            .alloc_raw(plain_bytes, kind)
            .map_err(FlatObjectError::Arena)?;
        #[cfg(feature = "hole_reuse_shadow_probe")]
        destination_store.note_hole_reuse_shadow_allocation(allocation);
        destination_store.refresh_regions();

        let destination = allocation.ptr;
        // SAFETY: source validation and destination allocation establish the
        // same typed, exclusive ownership proof as `relocate_plain_with`.
        // Distinct backing makes the placements disjoint. After the callback
        // returns, raw movement, registry pushes with reserved capacity, and
        // liveness updates are allocation-free.
        unsafe {
            rewrite(&mut (*source.as_ptr().cast::<FlatObject<T>>()).payload);
            let object = source.as_ptr().cast::<FlatObject<T>>().read();
            destination.as_ptr().cast::<FlatObject<T>>().write(object);
            source.as_ptr().cast::<u64>().write(0);
        }
        self.entries[source_index].tombstone();
        destination_store
            .entries
            .push(FlatStoreEntry::plain(destination, allocation.reserved_size));
        self.backing.retire_raw(source, registered_bytes);

        Ok(FlatRelocation {
            source,
            destination: FlatAllocation {
                ptr: destination,
                store_index: destination_index,
                allocation,
            },
        })
    }

    /// Moves one plain flat object to fresh backing storage.
    ///
    /// All fallible work happens before the source is changed: the method
    /// validates the exact registry entry, reserves a destination registry
    /// slot, allocates the destination, and refreshes membership metadata.
    /// The commit then moves the initialized header and payload, tombstones
    /// and wipes the source, appends the destination registry entry, and
    /// updates reservation page liveness without allocating.
    ///
    /// The returned destination is intentionally unpublished. Heap owners
    /// must rewrite every reference from `source` to the destination before
    /// allowing evaluation to resume.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::UnknownAddress`] when `source` is not an
    /// exact live allocation, [`FlatObjectError::KindMismatch`] when its
    /// header has another kind, or
    /// [`FlatObjectError::RelocationRequiresPlainObject`] when the allocation
    /// has an inline tail. Registry reservation and backing allocation
    /// failures are reported without changing the source object.
    pub fn relocate_plain(
        &mut self,
        source: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<FlatRelocation, FlatObjectError> {
        self.relocate_plain_with(source, kind, |_| {})
    }

    /// Rewrites and moves one plain flat object to fresh backing storage.
    ///
    /// This is [`Self::relocate_plain`] with an infallible payload-rewrite
    /// callback inserted at the start of the commit. A collector uses that
    /// callback to rewrite outgoing edges through its prevalidated forwarding
    /// table without resolving the unpublished destination in a second,
    /// fallible operation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::relocate_plain`]. The callback is
    /// not invoked unless validation, registry reservation, backing
    /// allocation, and membership-index refresh have all completed.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `rewrite`. The source remains registered and
    /// owns its payload during unwinding, but mutations already performed by
    /// the callback are not rolled back.
    pub fn relocate_plain_with(
        &mut self,
        source: NonNull<HeapObject>,
        kind: FlatObjectKind,
        rewrite: impl FnOnce(&mut T),
    ) -> Result<FlatRelocation, FlatObjectError> {
        let () = FlatLayoutCheck::<T>::PAYLOAD_FITS_ARENA_ALIGNMENT;
        self.check_kind_allowed(kind)?;
        let address = source.as_ptr() as usize;
        let Some(source_index) = self.entry_index_for_address(address) else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        let Some(source_entry) = self.entries.get(source_index).copied() else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        if !source_entry.is_live() {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let actual = self.kind_at(source)?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address,
            });
        }

        let plain_bytes = mem::size_of::<FlatObject<T>>();
        let registered_bytes = source_entry.size_bytes();
        if source_entry.has_value_tail() || registered_bytes != plain_bytes {
            return Err(FlatObjectError::RelocationRequiresPlainObject {
                address,
                registered_bytes,
                plain_bytes,
            });
        }

        let destination_index = self.entries.len();
        let entries =
            destination_index
                .checked_add(1)
                .ok_or(FlatObjectError::RegistryAllocationFailed {
                    entries: usize::MAX,
                })?;
        self.entries
            .try_reserve(1)
            .map_err(|_| FlatObjectError::RegistryAllocationFailed { entries })?;
        let allocation = self
            .backing
            .alloc_raw(plain_bytes, kind)
            .map_err(FlatObjectError::Arena)?;
        #[cfg(feature = "hole_reuse_shadow_probe")]
        self.note_hole_reuse_shadow_allocation(allocation);
        self.refresh_regions();

        let destination = allocation.ptr;
        // SAFETY: validation proved `source` is this store's exact live,
        // plain `FlatObject<T>` allocation, and `&mut self` excludes other
        // typed resolutions. The callback receives the only payload
        // reference before ownership moves. `allocation` is a fresh,
        // disjoint reservation with sufficient size and alignment. After the
        // callback returns, no fallible operation remains: moving the object
        // transfers its single payload ownership to `destination`; wiping and
        // tombstoning source prevent any later resolution or drop there.
        unsafe {
            rewrite(&mut (*source.as_ptr().cast::<FlatObject<T>>()).payload);
            let object = source.as_ptr().cast::<FlatObject<T>>().read();
            destination.as_ptr().cast::<FlatObject<T>>().write(object);
            source.as_ptr().cast::<u64>().write(0);
        }
        self.entries[source_index].tombstone();
        self.entries
            .push(FlatStoreEntry::plain(destination, allocation.reserved_size));
        self.backing.retire_raw(source, registered_bytes);

        Ok(FlatRelocation {
            source,
            destination: FlatAllocation {
                ptr: destination,
                store_index: destination_index,
                allocation,
            },
        })
    }
}
