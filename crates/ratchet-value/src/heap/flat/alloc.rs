//! Allocation doors of the flat object store (RFC-0007 doc 30 FV-1/FV-4).
//!
//! Split from `flat.rs` for the RFC-0007 section 2 module-size cap; this file
//! carries the `impl` block with every [`FlatObjectStore`] allocation method
//! (plain, aux-carrying, trailing-bytes, and trailing-array) plus the
//! post-monomorphization payload layout check they share. Resolution,
//! iteration, region pops, and the membership index stay in the parent
//! module; see the [parent module docs](super) for the object layout and the
//! fail-loud contract.

use super::*;
use crate::value::Value;

/// Post-monomorphization payload layout checks for [`FlatObject<T>`].
struct FlatLayoutCheck<T>(PhantomData<T>);

impl<T> FlatLayoutCheck<T> {
    /// Fails compilation (post-mono) for payloads the arena cannot host.
    const PAYLOAD_FITS_ARENA_ALIGNMENT: () =
        assert!(mem::align_of::<FlatObject<T>>() <= MAX_ALIGN);
}

impl<T> FlatObjectStore<T> {
    /// Allocates a flat object and returns its stable address.
    ///
    /// The object header stores `kind`, `hash`, and `epoch` (with an `aux`
    /// size class of zero); `payload` is moved into the object in place. The
    /// returned address is valid for the store's lifetime and is never
    /// reissued.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::Arena`] if arena storage cannot be
    /// reserved, [`FlatObjectError::KindNotAllowed`] if `kind` is outside the
    /// store's allowed set, or [`FlatObjectError::RegistryAllocationFailed`]
    /// if the registry cannot grow (the arena reservation is then left as
    /// dead padding and the payload is dropped normally).
    pub fn alloc(
        &mut self,
        kind: FlatObjectKind,
        hash: u64,
        epoch: u64,
        payload: T,
    ) -> Result<FlatAllocation, FlatObjectError> {
        self.alloc_with_aux(kind, 0, hash, epoch, payload)
    }

    /// Allocates a flat object with an explicit header `aux` size class.
    ///
    /// Identical to [`FlatObjectStore::alloc`] except the kind word carries
    /// the saturating 24-bit `aux` field (see the [parent module
    /// documentation](super)).
    ///
    /// # Errors
    ///
    /// As for [`FlatObjectStore::alloc`].
    pub fn alloc_with_aux(
        &mut self,
        kind: FlatObjectKind,
        aux: u32,
        hash: u64,
        epoch: u64,
        payload: T,
    ) -> Result<FlatAllocation, FlatObjectError> {
        let () = FlatLayoutCheck::<T>::PAYLOAD_FITS_ARENA_ALIGNMENT;
        self.check_kind_allowed(kind)?;
        let size = mem::size_of::<FlatObject<T>>();
        let store_index = self.entries.len();
        let entries = store_index
            .checked_add(1)
            .ok_or(FlatObjectError::RegistryAllocationFailed { entries: usize::MAX })?;
        self.entries
            .try_reserve(1)
            .map_err(|_| FlatObjectError::RegistryAllocationFailed { entries })?;
        let allocation = self
            .backing
            .alloc_raw(size, kind)
            .map_err(FlatObjectError::Arena)?;
        debug_assert!(allocation.reserved_size >= size);
        debug_assert_eq!(allocation.ptr.as_ptr() as usize % MAX_ALIGN, 0);
        let object = FlatObject {
            header: FlatHeader {
                kind_word: kind.kind_word(aux),
                hash,
                epoch: AtomicU64::new(epoch),
            },
            payload,
        };
        let ptr = allocation.ptr;
        // SAFETY: `ptr` is a fresh, exclusively owned arena reservation of at
        // least `size_of::<FlatObject<T>>()` bytes at arena word alignment,
        // which satisfies `FlatObject<T>`'s alignment per the post-mono layout
        // check above. The bump arena never reissues this address, so no other
        // object aliases it.
        unsafe { ptr.as_ptr().cast::<FlatObject<T>>().write(object) };
        self.entries
            .push(FlatStoreEntry::plain(ptr, allocation.reserved_size));
        self.refresh_regions();
        Ok(FlatAllocation {
            ptr,
            store_index,
            allocation,
        })
    }

    /// Allocates a flat object whose payload references `bytes` written
    /// inline directly after the payload struct (doc 30 stage FV-1b).
    ///
    /// The bytes are copied into the same arena reservation as the header and
    /// payload; `make_payload` receives the [`FlatBytes`] witness over the
    /// inline copy and must store it inside the returned payload, which is
    /// then written in place exactly like [`FlatObjectStore::alloc`].
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::Arena`] if arena storage cannot be
    /// reserved (including when the combined payload-plus-bytes size
    /// overflows), or [`FlatObjectError::RegistryAllocationFailed`] if the
    /// registry cannot grow.
    pub fn alloc_with_trailing_bytes(
        &mut self,
        kind: FlatObjectKind,
        hash: u64,
        epoch: u64,
        bytes: &[u8],
        make_payload: impl FnOnce(FlatBytes) -> T,
    ) -> Result<FlatAllocation, FlatObjectError> {
        let () = FlatLayoutCheck::<T>::PAYLOAD_FITS_ARENA_ALIGNMENT;
        self.check_kind_allowed(kind)?;
        let object_size = mem::size_of::<FlatObject<T>>();
        let size = object_size
            .checked_add(bytes.len())
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        let store_index = self.entries.len();
        let entries = store_index
            .checked_add(1)
            .ok_or(FlatObjectError::RegistryAllocationFailed { entries: usize::MAX })?;
        self.entries
            .try_reserve(1)
            .map_err(|_| FlatObjectError::RegistryAllocationFailed { entries })?;
        let allocation = self
            .backing
            .alloc_raw(size, kind)
            .map_err(FlatObjectError::Arena)?;
        debug_assert!(allocation.reserved_size >= size);
        debug_assert_eq!(allocation.ptr.as_ptr() as usize % MAX_ALIGN, 0);
        let ptr = allocation.ptr;
        let tail = ptr.as_ptr().cast::<u8>();
        // SAFETY: the reservation covers `object_size + bytes.len()` bytes at
        // `ptr`, so the tail range starting at `object_size` holds exactly
        // `bytes.len()` writable, exclusively owned bytes; the source slice
        // cannot overlap a reservation the arena just created.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), tail.add(object_size), bytes.len())
        };
        let Some(tail_ptr) = NonNull::new(tail.wrapping_add(object_size)) else {
            return Err(FlatObjectError::UnknownAddress {
                address: ptr.as_ptr() as usize,
            });
        };
        // FlatBytes contract (see `FlatBytes::new`): the tail bytes were
        // fully written above, are never written again (payloads are
        // immutable after construction; `resolve_mut` rewrites list spines,
        // never byte-carrying payloads' tails), and stay mapped until the
        // store drops; the witness lives in the payload, which drops in the
        // store's `Drop` strictly before the owned arena unmaps.
        let payload = make_payload(FlatBytes::new(tail_ptr, bytes.len()));
        let object = FlatObject {
            header: FlatHeader {
                kind_word: kind.kind_word(flat_aux_for_len(bytes.len())),
                hash,
                epoch: AtomicU64::new(epoch),
            },
            payload,
        };
        // SAFETY: `ptr` is a fresh, exclusively owned arena reservation of at
        // least `size_of::<FlatObject<T>>()` bytes at arena word alignment
        // (the post-mono layout check above), never reissued by the bump
        // arena; the struct write covers only the object head and leaves the
        // already-written tail bytes untouched.
        unsafe { ptr.as_ptr().cast::<FlatObject<T>>().write(object) };
        self.entries
            .push(FlatStoreEntry::plain(ptr, allocation.reserved_size));
        self.refresh_regions();
        Ok(FlatAllocation {
            ptr,
            store_index,
            allocation,
        })
    }

    /// Allocates a flat object whose payload references typed element runs
    /// written inline directly after the payload struct (doc 30 stage FV-4).
    ///
    /// `tail` plans the trailing region ([`FlatTailLayout`]); `make_payload`
    /// receives a [`FlatTailWriter`] over the reservation's tail, copies each
    /// run through [`FlatTailWriter::write_slice`], and must store the
    /// returned [`FlatSlice`] witnesses inside the returned payload (except
    /// for [`Self::alloc_with_value_tail`]'s registry-owned witness), which is
    /// then written in place exactly like [`FlatObjectStore::alloc`]. The
    /// header kind word carries the caller's saturating `aux` size class.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::Arena`] if arena storage cannot be reserved
    /// (including when the combined payload-plus-tail size overflows or the
    /// callback's writes exceed the planned layout),
    /// [`FlatObjectError::KindNotAllowed`] if `kind` is outside the store's
    /// allowed set, or [`FlatObjectError::RegistryAllocationFailed`] if the
    /// registry cannot grow. On a callback error the arena reservation is
    /// left as dead padding and no object is registered.
    pub fn alloc_with_trailing(
        &mut self,
        kind: FlatObjectKind,
        aux: u32,
        hash: u64,
        epoch: u64,
        tail: FlatTailLayout,
        make_payload: impl FnOnce(&mut FlatTailWriter<'_>) -> Result<T, FlatObjectError>,
    ) -> Result<FlatAllocation, FlatObjectError> {
        let () = FlatLayoutCheck::<T>::PAYLOAD_FITS_ARENA_ALIGNMENT;
        self.check_kind_allowed(kind)?;
        let object_size = mem::size_of::<FlatObject<T>>();
        let size = object_size
            .checked_add(tail.bytes())
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        let store_index = self.entries.len();
        let entries = store_index
            .checked_add(1)
            .ok_or(FlatObjectError::RegistryAllocationFailed { entries: usize::MAX })?;
        self.entries
            .try_reserve(1)
            .map_err(|_| FlatObjectError::RegistryAllocationFailed { entries })?;
        let allocation = self
            .backing
            .alloc_raw(size, kind)
            .map_err(FlatObjectError::Arena)?;
        debug_assert!(allocation.reserved_size >= size);
        debug_assert_eq!(allocation.ptr.as_ptr() as usize % MAX_ALIGN, 0);
        let ptr = allocation.ptr;
        let Some(tail_ptr) = NonNull::new(
            ptr.as_ptr().cast::<u8>().wrapping_add(object_size),
        ) else {
            return Err(FlatObjectError::UnknownAddress {
                address: ptr.as_ptr() as usize,
            });
        };
        // FlatTailWriter contract (see `FlatTailWriter::new`): the tail range
        // `object_size..object_size + tail.bytes()` of this fresh reservation
        // is exclusively owned, writable, 8-byte aligned (`object_size` is a
        // multiple of the arena word: `FlatObject<T>` has word alignment per
        // the post-mono check), disjoint from the object head, and never
        // otherwise written. The writer copies each run exactly once; the
        // resulting witnesses live in the payload, which drops in the store's
        // `Drop` (or a region pop) strictly before the arena unmaps.
        let mut writer = FlatTailWriter::new(tail_ptr, tail.bytes());
        let payload = make_payload(&mut writer)?;
        let object = FlatObject {
            header: FlatHeader {
                kind_word: kind.kind_word(aux),
                hash,
                epoch: AtomicU64::new(epoch),
            },
            payload,
        };
        // SAFETY: `ptr` is a fresh, exclusively owned arena reservation of at
        // least `size_of::<FlatObject<T>>()` bytes at arena word alignment
        // (the post-mono layout check above), never reissued by the bump
        // arena; the struct write covers only the object head and leaves the
        // already-written tail runs untouched.
        unsafe { ptr.as_ptr().cast::<FlatObject<T>>().write(object) };
        self.entries
            .push(FlatStoreEntry::plain(ptr, allocation.reserved_size));
        self.refresh_regions();
        Ok(FlatAllocation {
            ptr,
            store_index,
            allocation,
        })
    }

    /// Allocates one object followed by an initialized inline `Value` run.
    ///
    /// Unlike [`Self::alloc_with_trailing`], the payload stores no pointer
    /// witness. The exact registry entry carries a compact private flag, and
    /// [`Self::value_tail`] reconstructs a borrow only after validating that
    /// flag, the header length, and the reservation extent. This keeps a
    /// closure payload enum at its plain pointer-sized layout.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::alloc_with_trailing`], plus an
    /// unknown-address error if the just-created registry entry is not the
    /// returned allocation (an internal consistency failure).
    pub fn alloc_with_value_tail(
        &mut self,
        kind: FlatObjectKind,
        hash: u64,
        epoch: u64,
        values: &[Value],
        payload: T,
    ) -> Result<FlatValueTailAllocation, FlatObjectError> {
        let () = FlatLayoutCheck::<T>::PAYLOAD_FITS_ARENA_ALIGNMENT;
        self.check_kind_allowed(kind)?;
        let object_size = mem::size_of::<FlatObject<T>>();
        let tail_size = mem::size_of::<Value>()
            .checked_mul(values.len())
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        let size = object_size
            .checked_add(tail_size)
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        let store_index = self.entries.len();
        let entries = store_index
            .checked_add(1)
            .ok_or(FlatObjectError::RegistryAllocationFailed { entries: usize::MAX })?;
        self.entries
            .try_reserve(1)
            .map_err(|_| FlatObjectError::RegistryAllocationFailed { entries })?;
        let allocation = self
            .backing
            .alloc_raw(size, kind)
            .map_err(FlatObjectError::Arena)?;
        debug_assert!(allocation.reserved_size >= size);
        debug_assert_eq!(allocation.ptr.as_ptr() as usize % MAX_ALIGN, 0);
        debug_assert_eq!(object_size % mem::align_of::<Value>(), 0);
        let ptr = allocation.ptr;
        // SAFETY: `ptr` is a fresh, exclusively owned arena reservation
        // covering the object head followed by `values.len()` `Value` slots.
        // `FlatObject<T>`'s size preserves its alignment, which is at least
        // `Value`'s alignment under the post-mono arena check. `Value` is
        // `Copy`, the source cannot overlap this newly reserved range, and the
        // tail is immutable after this initialization.
        unsafe {
            std::ptr::copy_nonoverlapping(
                values.as_ptr(),
                ptr.as_ptr().cast::<u8>().add(object_size).cast::<Value>(),
                values.len(),
            );
            ptr.as_ptr().cast::<FlatObject<T>>().write(FlatObject {
                header: FlatHeader {
                    kind_word: kind.kind_word(flat_aux_for_len(values.len())),
                    hash,
                    epoch: AtomicU64::new(epoch),
                },
                payload,
            });
        }
        let mut entry = FlatStoreEntry::plain(ptr, allocation.reserved_size);
        entry.mark_value_tail();
        self.entries.push(entry);
        self.refresh_regions();
        let allocation = FlatAllocation {
            ptr,
            store_index,
            allocation,
        };
        let handle = FlatValueTailHandle::new(store_index, values.len());
        Ok(FlatValueTailAllocation { allocation, handle })
    }
}
