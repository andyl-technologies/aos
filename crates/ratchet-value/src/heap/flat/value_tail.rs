//! Registry-backed inline [`Value`] tails for compact closure payloads.
//!
//! Closure captures trail the owning flat object, but the closure payload enum
//! must stay pointer-sized: storing a [`FlatSlice`](super::FlatSlice) witness
//! in one variant widens every closure object. The allocation registry already
//! owns the exact reservation extent, so its otherwise-zero low bit records
//! that a closure allocation initialized one canonical `Value` run.

use std::mem;
use std::ptr::NonNull;

use crate::value::{HeapObject, Value};

use super::{
    FLAT_AUX_SATURATED, FlatAllocation, FlatObject, FlatObjectError, FlatObjectKind, FlatObjectRef,
    FlatObjectStore, FlatStoreEntry, aux_of_kind_word,
};

const VALUE_TAIL_FLAG: usize = 1;
const VALUE_TAIL_HANDLE_LEN_BITS: u32 = 4;
const VALUE_TAIL_HANDLE_LEN_MASK: u32 = (1 << VALUE_TAIL_HANDLE_LEN_BITS) - 1;
pub(super) const VALUE_TAIL_PACKED_SIZE_MASK: usize = u32::MAX as usize & !VALUE_TAIL_FLAG;

/// A compact prevalidated registry coordinate for one inline `Value` tail.
///
/// Resolution-based construction checks the exact registry entry, header
/// length, and reserved extent once; the allocation door signs the coordinate
/// while those facts are already exclusively known. The generation is never
/// rewound with a lexical region, so an old coordinate cannot alias a later
/// object that reuses the same registry index and arena address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlatValueTailHandle {
    index_and_len: u32,
    generation: u32,
}

/// The object allocation and compact handle produced by a `Value`-tail door.
#[derive(Clone, Copy, Debug)]
pub struct FlatValueTailAllocation {
    /// The stable flat-object allocation.
    pub allocation: FlatAllocation,
    /// The handle signed directly from that allocation's registry coordinate,
    /// or `None` if its index or tail length exceeds the compact encoding.
    pub handle: Option<FlatValueTailHandle>,
}

impl FlatValueTailHandle {
    pub(super) fn new(store_index: usize, len: usize, generation: u32) -> Option<Self> {
        if generation == 0 {
            return None;
        }
        let len = u32::try_from(len).ok()?;
        if len > VALUE_TAIL_HANDLE_LEN_MASK {
            return None;
        }
        let index = u32::try_from(store_index)
            .ok()?
            .checked_shl(VALUE_TAIL_HANDLE_LEN_BITS)?;
        Some(Self {
            index_and_len: index | len,
            generation,
        })
    }

    const fn store_index(self) -> usize {
        (self.index_and_len >> VALUE_TAIL_HANDLE_LEN_BITS) as usize
    }

    /// Returns the number of values in the tail.
    pub const fn len(self) -> usize {
        (self.index_and_len & VALUE_TAIL_HANDLE_LEN_MASK) as usize
    }

    /// Returns whether the tail is empty.
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
}

impl FlatStoreEntry {
    pub(super) fn plain(ptr: NonNull<HeapObject>, size_bytes: usize) -> Self {
        debug_assert_eq!(size_bytes & VALUE_TAIL_FLAG, 0);
        Self {
            ptr,
            size_and_flags: size_bytes,
            #[cfg(target_pointer_width = "32")]
            value_tail_generation: 0,
        }
    }

    pub(super) fn mark_value_tail(&mut self, generation: u32) -> bool {
        debug_assert_eq!(self.size_and_flags & VALUE_TAIL_FLAG, 0);
        #[cfg(target_pointer_width = "64")]
        {
            if self.size_and_flags > VALUE_TAIL_PACKED_SIZE_MASK {
                return false;
            }
            self.size_and_flags |= (generation as usize) << u32::BITS;
        }
        #[cfg(target_pointer_width = "32")]
        {
            self.value_tail_generation = generation;
        }
        self.size_and_flags |= VALUE_TAIL_FLAG;
        true
    }

    /// Returns whether this registry slot still owns an initialized object.
    pub(super) const fn is_live(self) -> bool {
        self.size_and_flags != 0
    }

    /// Invalidates this registry slot without changing its stable index.
    pub(super) fn tombstone(&mut self) {
        self.clear_value_tail();
        self.size_and_flags = 0;
    }

    fn clear_value_tail(&mut self) {
        #[cfg(target_pointer_width = "64")]
        {
            self.size_and_flags &= VALUE_TAIL_PACKED_SIZE_MASK;
        }
        #[cfg(target_pointer_width = "32")]
        {
            self.value_tail_generation = 0;
        }
        self.size_and_flags &= !VALUE_TAIL_FLAG;
    }

    pub(super) const fn size_bytes(self) -> usize {
        #[cfg(target_pointer_width = "64")]
        if self.has_value_tail() {
            return self.size_and_flags & VALUE_TAIL_PACKED_SIZE_MASK;
        }
        self.size_and_flags & !VALUE_TAIL_FLAG
    }

    pub(super) const fn has_value_tail(self) -> bool {
        self.size_and_flags & VALUE_TAIL_FLAG != 0
    }

    const fn value_tail_generation(self) -> u32 {
        if !self.has_value_tail() {
            return 0;
        }
        #[cfg(target_pointer_width = "64")]
        {
            (self.size_and_flags >> u32::BITS) as u32
        }
        #[cfg(target_pointer_width = "32")]
        {
            self.value_tail_generation
        }
    }
}

impl<T> FlatObjectStore<T> {
    /// Issues a tail identity that is never rewound with the registry.
    pub(super) fn issue_value_tail_generation(&mut self) -> Option<u32> {
        let generation = u32::try_from(self.next_value_tail_generation).ok()?;
        self.next_value_tail_generation = self.next_value_tail_generation.saturating_add(1);
        Some(generation)
    }

    /// Returns the registered owner address signed into `handle`.
    ///
    /// This is an error-reporting and rooting companion to
    /// [`Self::resolve_value_tail_handle_owner`]. It does not expose payload
    /// bytes and returns `None` for a stale or retired tail handle.
    pub fn value_tail_handle_owner(
        &self,
        handle: FlatValueTailHandle,
    ) -> Option<NonNull<HeapObject>> {
        self.entries
            .get(handle.store_index())
            .copied()
            .filter(|entry| {
                entry.has_value_tail() && entry.value_tail_generation() == handle.generation
            })
            .map(|entry| entry.ptr)
    }

    /// Resolves the initialized inline `Value` run trailing one flat object.
    ///
    /// Returns `Ok(None)` when the exact registry entry was not allocated by
    /// the dedicated `Value`-tail door.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when the object does not resolve with
    /// `kind`, or when its registry/header tail metadata is inconsistent.
    pub fn value_tail(
        &self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<Option<&[Value]>, FlatObjectError> {
        self.resolve_with_value_tail(ptr, kind)
            .map(|(_object, values)| values)
    }

    /// Resolves a flat object and its optional inline `Value` run together.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] under the same conditions as
    /// [`Self::value_tail`].
    pub fn resolve_with_value_tail(
        &self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<(FlatObjectRef<'_, T>, Option<&[Value]>), FlatObjectError> {
        let object = self.resolve(ptr, kind)?;
        let len = object.aux() as usize;
        let Some(entry) = self.value_tail_entry(ptr) else {
            return Ok((object, None));
        };
        if !entry.has_value_tail() {
            return Ok((object, None));
        }
        let values = self.value_tail_slice(ptr, entry, len)?;
        Ok((object, Some(values)))
    }

    /// Resolves an object and `Value` tail by its stable registry index.
    ///
    /// This is the closure-read fast path: the exact entry check replaces the
    /// arena-region and registry searches while still validating pointer and
    /// kind identity before exposing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when `store_index` is stale, belongs to a
    /// different pointer, carries a different kind, or has inconsistent tail
    /// metadata.
    pub fn resolve_with_value_tail_at(
        &self,
        store_index: usize,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<(FlatObjectRef<'_, T>, Option<&[Value]>), FlatObjectError> {
        self.check_kind_allowed(kind)?;
        let address = ptr.as_ptr() as usize;
        let (object, entry) = self.object_and_entry_at(store_index, ptr)?;
        let actual = FlatObjectKind::from_kind_word(object.object.header.kind_word)
            .ok_or(FlatObjectError::UnknownAddress { address })?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address,
            });
        }
        if !entry.has_value_tail() {
            return Ok((object, None));
        }
        let len = object.aux() as usize;
        let values = self.value_tail_slice(ptr, entry, len)?;
        Ok((object, Some(values)))
    }

    /// Resolves a known `Value` tail by stable registry index and exact length.
    ///
    /// This closure hot path avoids repeating kind-set and header-kind checks:
    /// the typed store plus exact live registry entry already prove the object
    /// layout, while the private tail flag, header length, and reservation
    /// extent still validate the inline run before it is exposed.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when the registry index or pointer is stale,
    /// the entry has no `Value` tail, or its length/extent disagrees with
    /// `expected_len`.
    #[inline]
    pub fn resolve_value_tail_at(
        &self,
        store_index: usize,
        ptr: NonNull<HeapObject>,
        expected_len: usize,
    ) -> Result<(FlatObjectRef<'_, T>, &[Value]), FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let (object, entry) = self.object_and_entry_at(store_index, ptr)?;
        if !entry.has_value_tail() {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        if object.aux() as usize != expected_len {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let values = self.value_tail_slice(ptr, entry, expected_len)?;
        Ok((object, values))
    }

    /// Resolves the owning object and copies one element from its known
    /// `Value` tail.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::resolve_value_tail_at`]. An index at
    /// or beyond `expected_len` returns `Ok(None)`.
    #[inline]
    pub fn value_tail_get_at(
        &self,
        store_index: usize,
        ptr: NonNull<HeapObject>,
        expected_len: usize,
        index: usize,
    ) -> Result<(FlatObjectRef<'_, T>, Option<Value>), FlatObjectError> {
        let (object, values) = self.resolve_value_tail_at(store_index, ptr, expected_len)?;
        Ok((object, values.get(index).copied()))
    }

    /// Creates a compact handle for an initialized `Value` tail.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when the registry index or pointer is stale,
    /// the entry has no `Value` tail, or its header length/reserved extent does
    /// not agree with `expected_len`.
    pub fn value_tail_handle_at(
        &self,
        store_index: usize,
        ptr: NonNull<HeapObject>,
        expected_len: usize,
    ) -> Result<FlatValueTailHandle, FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let (object, entry) = self.object_and_entry_at(store_index, ptr)?;
        if !entry.has_value_tail() || object.aux() as usize != expected_len {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let _ = checked_value_tail::<T>(ptr, entry, expected_len)?;
        FlatValueTailHandle::new(store_index, expected_len, entry.value_tail_generation())
            .ok_or(FlatObjectError::UnknownAddress { address })
    }

    /// Resolves a prevalidated inline `Value` tail.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when the handle's registry entry or pointer
    /// is stale, its private tail flag is absent, or its signed header length
    /// changed.
    #[inline]
    pub fn resolve_value_tail_handle(
        &self,
        ptr: NonNull<HeapObject>,
        handle: FlatValueTailHandle,
    ) -> Result<(FlatObjectRef<'_, T>, &[Value]), FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let (object, entry) = self.object_and_entry_at(handle.store_index(), ptr)?;
        if !entry.has_value_tail()
            || entry.value_tail_generation() != handle.generation
            || object.aux() as usize != handle.len()
        {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let values = self.value_tail_slice_prevalidated(ptr, handle.len())?;
        Ok((object, values))
    }

    /// Resolves a prevalidated inline `Value` tail and its owning address.
    ///
    /// The handle's signed registry index identifies the owner directly, so
    /// closure metadata does not need to retain a duplicate heap [`Value`].
    /// The private tail flag and signed header length are still validated
    /// before any bytes are exposed.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when the handle's registry entry is stale,
    /// its private tail flag is absent, or its signed header length changed.
    #[inline]
    pub fn resolve_value_tail_handle_owner(
        &self,
        handle: FlatValueTailHandle,
    ) -> Result<(NonNull<HeapObject>, FlatObjectRef<'_, T>, &[Value]), FlatObjectError> {
        let Some(entry) = self.entries.get(handle.store_index()).copied() else {
            return Err(FlatObjectError::UnknownAddress { address: 0 });
        };
        let ptr = entry.ptr;
        let address = ptr.as_ptr() as usize;
        let (object, checked_entry) = self.object_and_entry_at(handle.store_index(), ptr)?;
        if !checked_entry.has_value_tail()
            || checked_entry.value_tail_generation() != handle.generation
            || object.aux() as usize != handle.len()
        {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let values = self.value_tail_slice_prevalidated(ptr, handle.len())?;
        Ok((ptr, object, values))
    }

    /// Copies one value through a prevalidated inline-tail handle.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::resolve_value_tail_handle`]. An
    /// out-of-range element index returns `Ok(None)`.
    #[inline]
    pub fn value_tail_get_handle(
        &self,
        ptr: NonNull<HeapObject>,
        handle: FlatValueTailHandle,
        index: usize,
    ) -> Result<Option<Value>, FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let Some(entry) = self.entries.get(handle.store_index()).copied() else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        if entry.ptr != ptr
            || !entry.has_value_tail()
            || entry.value_tail_generation() != handle.generation
        {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        if index >= handle.len() {
            return Ok(None);
        }
        let values = self.value_tail_slice_prevalidated(ptr, handle.len())?;
        Ok(values.get(index).copied())
    }

    /// Copies one value through a handle that identifies its owner by registry
    /// index.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`Self::resolve_value_tail_handle_owner`]. An out-of-range element index
    /// returns `Ok(None)`.
    #[inline]
    pub fn value_tail_get_handle_owner(
        &self,
        handle: FlatValueTailHandle,
        index: usize,
    ) -> Result<Option<Value>, FlatObjectError> {
        let (_, _, values) = self.resolve_value_tail_handle_owner(handle)?;
        Ok(values.get(index).copied())
    }

    /// Invalidates prevalidated handles when an owning object is retired.
    ///
    /// Returns `false` when `ptr` is not an initialized `Value`-tail entry.
    pub fn retire_value_tail(&mut self, ptr: NonNull<HeapObject>) -> bool {
        let address = ptr.as_ptr() as usize;
        let Some(index) = self.entry_index_for_address(address) else {
            return false;
        };
        let Some(entry) = self.entries.get_mut(index) else {
            return false;
        };
        if !entry.has_value_tail() {
            return false;
        }
        entry.clear_value_tail();
        true
    }

    /// Resolves the initialized inline `Value` run with exclusive access.
    ///
    /// Returns `Ok(None)` when the exact registry entry has no `Value` tail.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when the object does not resolve with
    /// `kind`, or when its registry/header tail metadata is inconsistent.
    pub fn value_tail_mut(
        &mut self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<Option<&mut [Value]>, FlatObjectError> {
        self.resolve_mut_with_value_tail(ptr, kind)
            .map(|(_payload, values)| values)
    }

    /// Resolves a mutable payload and its optional inline `Value` run together.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] under the same conditions as
    /// [`Self::value_tail_mut`].
    pub fn resolve_mut_with_value_tail(
        &mut self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<(&mut T, Option<&mut [Value]>), FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let Some(store_index) = self.entry_index_for_address(address) else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        self.resolve_mut_with_value_tail_at(store_index, ptr, kind)
    }

    /// Resolves a mutable payload and its inline `Value` tail by compact handle.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when the handle is stale, belongs to a
    /// different pointer or object kind, or its signed tail length no longer
    /// agrees with the registry and object header.
    #[inline]
    pub fn resolve_mut_with_value_tail_handle(
        &mut self,
        ptr: NonNull<HeapObject>,
        handle: FlatValueTailHandle,
        kind: FlatObjectKind,
    ) -> Result<(&mut T, &mut [Value]), FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let Some(entry) = self.entries.get(handle.store_index()).copied() else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        if entry.ptr != ptr
            || !entry.has_value_tail()
            || entry.value_tail_generation() != handle.generation
        {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        let (payload, values) =
            self.resolve_mut_with_value_tail_at(handle.store_index(), ptr, kind)?;
        let Some(values) = values else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        if values.len() != handle.len() {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        Ok((payload, values))
    }

    /// Resolves a mutable payload and optional `Value` tail by registry index.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError`] when `store_index` is stale, belongs to a
    /// different pointer, carries a different kind, or has inconsistent tail
    /// metadata.
    pub fn resolve_mut_with_value_tail_at(
        &mut self,
        store_index: usize,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<(&mut T, Option<&mut [Value]>), FlatObjectError> {
        self.check_kind_allowed(kind)?;
        let address = ptr.as_ptr() as usize;
        let Some(entry) = self.entries.get(store_index).copied() else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        if entry.ptr != ptr || !entry.is_live() {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        // SAFETY: the exact live registry entry proves `ptr` starts this
        // store's initialized `FlatObject<T>` and `&mut self` excludes every
        // aliasing resolution. When the private flag is present, the checked
        // extent and dedicated allocation door additionally prove the tail is
        // an initialized, disjoint `Value` run.
        unsafe {
            let object = &mut *(ptr.as_ptr() as *mut FlatObject<T>);
            let actual = FlatObjectKind::from_kind_word(object.header.kind_word)
                .ok_or(FlatObjectError::UnknownAddress { address })?;
            if actual != kind {
                return Err(FlatObjectError::KindMismatch {
                    expected: kind,
                    actual,
                    address,
                });
            }
            let values = if entry.has_value_tail() {
                let len = aux_of_kind_word(object.header.kind_word) as usize;
                let (tail, len) = checked_value_tail::<T>(ptr, entry, len)?;
                Some(std::slice::from_raw_parts_mut(tail.as_ptr(), len))
            } else {
                None
            };
            Ok((&mut object.payload, values))
        }
    }

    fn object_and_entry_at(
        &self,
        store_index: usize,
        ptr: NonNull<HeapObject>,
    ) -> Result<(FlatObjectRef<'_, T>, FlatStoreEntry), FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let Some(entry) = self.entries.get(store_index).copied() else {
            return Err(FlatObjectError::UnknownAddress { address });
        };
        if entry.ptr != ptr || !entry.is_live() {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        // SAFETY: the exact live registry entry proves `ptr` starts this typed
        // store's initialized `FlatObject<T>` and keeps its mapping owned; the
        // shared store borrow excludes mutable resolution.
        let object = unsafe { &*(ptr.as_ptr() as *const FlatObject<T>) };
        Ok((FlatObjectRef { object }, entry))
    }

    fn value_tail_slice(
        &self,
        ptr: NonNull<HeapObject>,
        entry: FlatStoreEntry,
        len: usize,
    ) -> Result<&[Value], FlatObjectError> {
        let (tail, len) = checked_value_tail::<T>(ptr, entry, len)?;
        Ok(self.value_tail_slice_from_ptr(tail, len))
    }

    #[inline]
    fn value_tail_slice_prevalidated(
        &self,
        ptr: NonNull<HeapObject>,
        len: usize,
    ) -> Result<&[Value], FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        let object_size = mem::size_of::<FlatObject<T>>();
        let tail = NonNull::new(
            ptr.as_ptr()
                .cast::<u8>()
                .wrapping_add(object_size)
                .cast::<Value>(),
        )
        .ok_or(FlatObjectError::UnknownAddress { address })?;
        Ok(self.value_tail_slice_from_ptr(tail, len))
    }

    #[inline]
    fn value_tail_slice_from_ptr(&self, tail: NonNull<Value>, len: usize) -> &[Value] {
        // SAFETY: the private registry flag is installed only after the
        // dedicated allocation door writes exactly `len` valid `Value`s; the
        // handle-construction or checked-extent path proves the run is in
        // bounds, and `&self` keeps it immutable.
        unsafe { std::slice::from_raw_parts(tail.as_ptr(), len) }
    }

    fn value_tail_entry(&self, ptr: NonNull<HeapObject>) -> Option<FlatStoreEntry> {
        let address = ptr.as_ptr() as usize;
        self.entry_index_for_address(address)
            .and_then(|index| self.entries.get(index))
            .copied()
    }

    /// Returns the stable registry index of an initialized `Value` tail.
    pub fn value_tail_store_index(&self, ptr: NonNull<HeapObject>) -> Option<usize> {
        let address = ptr.as_ptr() as usize;
        let index = self.entry_index_for_address(address)?;
        self.entries
            .get(index)
            .copied()
            .is_some_and(FlatStoreEntry::has_value_tail)
            .then_some(index)
    }

    pub(super) fn entry_index_for_address(&self, address: usize) -> Option<usize> {
        let ordering = |entry: &FlatStoreEntry| (entry.ptr.as_ptr() as usize).cmp(&address);
        match &self.backing {
            super::FlatStoreBacking::Rewindable { .. } => self
                .entries
                .binary_search_by(|entry| ordering(entry).reverse()),
            _ => self.entries.binary_search_by(ordering),
        }
        .ok()
    }
}

fn checked_value_tail<T>(
    ptr: NonNull<HeapObject>,
    entry: FlatStoreEntry,
    len: usize,
) -> Result<(NonNull<Value>, usize), FlatObjectError> {
    let address = ptr.as_ptr() as usize;
    if len == FLAT_AUX_SATURATED as usize {
        return Err(FlatObjectError::UnknownAddress { address });
    }
    let object_size = mem::size_of::<FlatObject<T>>();
    let tail_bytes = mem::size_of::<Value>()
        .checked_mul(len)
        .ok_or(FlatObjectError::UnknownAddress { address })?;
    let required = object_size
        .checked_add(tail_bytes)
        .ok_or(FlatObjectError::UnknownAddress { address })?;
    if required > entry.size_bytes() {
        return Err(FlatObjectError::UnknownAddress { address });
    }
    let tail = NonNull::new(
        ptr.as_ptr()
            .cast::<u8>()
            .wrapping_add(object_size)
            .cast::<Value>(),
    )
    .ok_or(FlatObjectError::UnknownAddress { address })?;
    Ok((tail, len))
}
