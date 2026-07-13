//! Inline flat-object byte payloads (RFC-0007 doc 30 stage FV-1b).
//!
//! A [`FlatBytes`] is a witness to bytes written *inline* into a flat-object
//! allocation, directly after the typed payload struct:
//!
//! ```text
//! flat heap object with trailing inline bytes:
//!
//!   ┌──────────────────────────────────────────────────────────┐
//!   │ header words (kind/hash/epoch)                            │
//!   ├──────────────────────────────────────────────────────────┤
//!   │ payload struct `T` (holds the `FlatBytes` witness)        │
//!   ├──────────────────────────────────────────────────────────┤
//!   │ inline bytes ... (the `FlatBytes` target)                 │
//!   └──────────────────────────────────────────────────────────┘
//! ```
//!
//! Before this stage a flat string's byte buffer stayed behind the payload's
//! `Vec<u8>` — one process-allocator allocation per interned string. The
//! trailing-bytes allocation writes the bytes into the same store-owned arena
//! reservation as the header, and the payload keeps only this witness.
//!
//! # Sealing discipline
//!
//! `FlatBytes` is deliberately **not** `Clone`/`Copy`: exactly one witness
//! exists per inline byte run, and it lives inside the payload struct written
//! into the flat object. Consumers that need an owning copy (for example a
//! value that escapes the store) must copy through [`FlatBytes::as_slice`]
//! into their own storage. This is what makes the safety contract local: the
//! single witness drops inside the store's [`Drop`][std::ops::Drop] strictly
//! before the owning arena unmaps, so no reachable witness can outlive its
//! bytes.

use std::fmt;
use std::ptr::NonNull;

/// A non-owning witness to immutable bytes inlined in a flat-object
/// allocation.
///
/// Created only by the flat store's trailing-bytes allocation (see
/// [`super::FlatObjectStore::alloc_with_trailing_bytes`]); see the [module
/// documentation](self) for the layout and the sealing discipline.
pub struct FlatBytes {
    ptr: NonNull<u8>,
    len: usize,
}

impl FlatBytes {
    /// Creates a witness over `len` immutable bytes at `ptr`.
    ///
    /// Sealed to the flat store module: the constructor itself performs no
    /// memory access, but every constructed witness carries the obligation
    /// that `ptr..ptr + len` is an initialized, readable byte run that is
    /// never written again and stays mapped for the whole lifetime of the
    /// witness — [`FlatBytes::as_slice`]'s `unsafe` block discharges against
    /// exactly this contract. The flat store's trailing-bytes allocation is
    /// the only construction site and satisfies it by writing the bytes into
    /// its own arena reservation immediately before construction, never
    /// mutating them afterwards, and dropping the payload holding the
    /// witness before the arena unmaps.
    pub(super) const fn new(ptr: NonNull<u8>, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Returns the inline bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the sealed construction site (`FlatObjectStore::
        // alloc_with_trailing_bytes`, the only `FlatBytes::new` caller)
        // guarantees an initialized, immutable, mapped byte run of
        // `self.len` bytes at `self.ptr` for the witness's whole lifetime;
        // the returned borrow cannot outlive the witness.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Returns the byte length of the inline run.
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

// SAFETY: the witnessed bytes are immutable after construction (the `new`
// contract), so cross-thread shared reads through `as_slice` cannot race;
// moving the witness moves only the pointer/length words.
unsafe impl Send for FlatBytes {}

// SAFETY: `FlatBytes` exposes only immutable reads of bytes that are never
// written after construction (the `new` contract), so `&FlatBytes` is safe to
// share across threads.
unsafe impl Sync for FlatBytes {}

impl fmt::Debug for FlatBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlatBytes")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}
