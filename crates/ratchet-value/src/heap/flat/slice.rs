//! Inline flat-object array payloads (RFC-0007 doc 30 stage FV-4).
//!
//! A [`FlatSlice<T>`] is the typed generalization of [`FlatBytes`]: a witness
//! to a `Copy` element run written *inline* into a flat-object allocation,
//! directly after the typed payload struct. FV-4 uses it to move attribute-set
//! entry/permutation arrays out of per-object process-allocator `Vec`s and
//! into the same arena reservation as the flat header (list spines measured
//! as a net loss and stay owned; see the evaluator's flat-values seam):
//!
//! ```text
//! flat heap object with trailing inline arrays:
//!
//!   ┌──────────────────────────────────────────────────────────┐
//!   │ header words (kind/aux/hash/epoch)                        │
//!   ├──────────────────────────────────────────────────────────┤
//!   │ payload struct `T` (holds the `FlatSlice` witnesses)      │
//!   ├──────────────────────────────────────────────────────────┤
//!   │ inline array 0 ...  (8-byte aligned)                      │
//!   │ inline array 1 ...  (8-byte aligned)                      │
//!   │ ...                                                       │
//!   └──────────────────────────────────────────────────────────┘
//! ```
//!
//! The trailing region is sized up front by a [`FlatTailLayout`] and written
//! exactly once through a [`FlatTailWriter`] inside the store's
//! `alloc_with_trailing` callback; each written run yields one witness that
//! must be stored in the returned payload.
//!
//! # Sealing discipline
//!
//! Like [`FlatBytes`], a `FlatSlice` is deliberately **not** `Clone`/`Copy`:
//! exactly one witness exists per inline run, and it lives inside the payload
//! struct written into the flat object. The witnessed elements are immutable
//! for the witness's whole lifetime — the flat store's exclusive writeback
//! door replaces whole payloads (dropping the witness) rather than mutating
//! witnessed elements — and stay mapped until the owning store drops, which
//! runs payload drop glue strictly before its arena unmaps. Consumers that
//! need an owning copy must copy out through [`FlatSlice::as_slice`].
//!
//! [`FlatBytes`]: super::FlatBytes

use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::ptr::NonNull;

use super::{FlatObjectError, MAX_ALIGN};
use crate::heap::arena::ArenaError;

/// Post-monomorphization element-type checks for inline flat arrays.
struct FlatSliceLayoutCheck<T>(PhantomData<T>);

impl<T> FlatSliceLayoutCheck<T> {
    /// Fails compilation (post-mono) for element types the 8-byte-aligned
    /// arena tail cannot host.
    const ELEMENT_FITS_ARENA_ALIGNMENT: () = assert!(mem::align_of::<T>() <= MAX_ALIGN);
}

/// A non-owning witness to immutable `Copy` elements inlined in a flat-object
/// allocation.
///
/// Created only by [`FlatTailWriter::write_slice`]; see this module's
/// documentation (`slice`) for the layout and the sealing discipline.
pub struct FlatSlice<T> {
    ptr: NonNull<T>,
    len: usize,
}

impl<T> FlatSlice<T> {
    /// Creates a witness over `len` immutable elements at `ptr`.
    ///
    /// Sealed to the flat store module: every constructed witness carries the
    /// obligation that `ptr..ptr + len` is an initialized, aligned, readable
    /// element run that is never written again and stays mapped for the whole
    /// lifetime of the witness — [`FlatSlice::as_slice`]'s `unsafe` block
    /// discharges against exactly this contract. [`FlatTailWriter`] is the
    /// only construction site and satisfies it by copying the elements into
    /// the object's own arena reservation immediately before construction,
    /// never mutating them afterwards, and living in a payload that drops
    /// before the arena unmaps.
    pub(super) const fn new(ptr: NonNull<T>, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Returns the inline elements.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: the sealed construction site (`FlatTailWriter::write_slice`,
        // the only `FlatSlice::new` caller) guarantees an initialized,
        // aligned, immutable, mapped run of `self.len` elements at `self.ptr`
        // for the witness's whole lifetime; the returned borrow cannot outlive
        // the witness.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Returns the number of inline elements.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the inline run is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// SAFETY: the witnessed elements are immutable after construction (the `new`
// contract), so cross-thread shared reads through `as_slice` cannot race;
// moving the witness moves only the pointer/length words. `T: Send + Sync`
// keeps element reads sound wherever the witness travels.
unsafe impl<T: Send + Sync> Send for FlatSlice<T> {}

// SAFETY: `FlatSlice` exposes only immutable reads of elements that are never
// written after construction (the `new` contract), so `&FlatSlice<T>` is safe
// to share across threads when `&T` is.
unsafe impl<T: Send + Sync> Sync for FlatSlice<T> {}

impl<T> fmt::Debug for FlatSlice<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlatSlice")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// A trailing-region size plan for one flat allocation with inline arrays.
///
/// Accumulates the byte extent of a sequence of [`FlatTailWriter::write_slice`]
/// calls, including the 8-byte alignment rounding the writer applies before
/// each run. The layout handed to `alloc_with_trailing` must plan exactly the
/// runs the callback writes, in the same order.
#[derive(Clone, Copy, Debug, Default)]
pub struct FlatTailLayout {
    bytes: usize,
}

impl FlatTailLayout {
    /// Creates an empty layout.
    pub const fn new() -> Self {
        Self { bytes: 0 }
    }

    /// Plans one inline run of `len` elements of `T`.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::Arena`] with [`ArenaError::SizeOverflow`]
    /// when the run size or the accumulated tail extent overflows.
    pub fn add_slice<T>(&mut self, len: usize) -> Result<(), FlatObjectError> {
        let () = FlatSliceLayoutCheck::<T>::ELEMENT_FITS_ARENA_ALIGNMENT;
        let run = mem::size_of::<T>()
            .checked_mul(len)
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        // The writer starts every run at 8-byte alignment; plan the padding.
        let padded = run
            .checked_add(MAX_ALIGN - 1)
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?
            & !(MAX_ALIGN - 1);
        self.bytes = self
            .bytes
            .checked_add(padded)
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        Ok(())
    }

    /// Returns the planned trailing-region extent in bytes.
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

/// A one-shot writer over the trailing inline-array region of one flat
/// allocation.
///
/// Constructed only by the flat store's `alloc_with_trailing`, which hands it
/// to the payload callback; each [`FlatTailWriter::write_slice`] call copies
/// one element run into the reservation and returns its witness. Runs are laid
/// out in call order at 8-byte alignment.
#[derive(Debug)]
pub struct FlatTailWriter<'a> {
    cursor: NonNull<u8>,
    remaining: usize,
    _region: PhantomData<&'a mut [u8]>,
}

impl FlatTailWriter<'_> {
    /// Creates a writer over `remaining` writable bytes at `cursor`.
    ///
    /// Sealed to the flat store module: the caller (`alloc_with_trailing`)
    /// guarantees `cursor..cursor + remaining` is an exclusively owned,
    /// writable, 8-byte-aligned arena region inside the object's reservation,
    /// disjoint from the object head, and never otherwise written.
    pub(super) const fn new(cursor: NonNull<u8>, remaining: usize) -> Self {
        Self {
            cursor,
            remaining,
            _region: PhantomData,
        }
    }

    /// Copies `src` into the trailing region and returns its witness.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::Arena`] with [`ArenaError::SizeOverflow`]
    /// when the run does not fit the remaining planned region (the layout
    /// under-planned the writes).
    pub fn write_slice<T: Copy>(&mut self, src: &[T]) -> Result<FlatSlice<T>, FlatObjectError> {
        let () = FlatSliceLayoutCheck::<T>::ELEMENT_FITS_ARENA_ALIGNMENT;
        let run = mem::size_of::<T>()
            .checked_mul(src.len())
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        let padded = run
            .checked_add(MAX_ALIGN - 1)
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?
            & !(MAX_ALIGN - 1);
        if padded > self.remaining {
            return Err(FlatObjectError::Arena(ArenaError::SizeOverflow));
        }
        debug_assert_eq!(self.cursor.as_ptr() as usize % MAX_ALIGN, 0);
        let run_ptr = self.cursor.cast::<T>();
        // SAFETY: the construction contract gives this writer exclusive
        // ownership of `remaining` writable bytes at `cursor`; the bound check
        // above proves the run fits, the cursor is 8-byte aligned (it starts
        // aligned and advances by padded multiples of 8, asserted above) which
        // satisfies `T`'s alignment per the post-mono check, and `src` cannot
        // overlap a reservation the arena just created.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), run_ptr.as_ptr(), src.len());
        }
        // SAFETY: `padded <= remaining` keeps the advanced cursor inside (or
        // one past the end of) the writer's owned region, so the pointer
        // arithmetic cannot leave the allocation.
        self.cursor = unsafe { NonNull::new_unchecked(self.cursor.as_ptr().add(padded)) };
        self.remaining -= padded;
        Ok(FlatSlice::new(run_ptr, src.len()))
    }
}
