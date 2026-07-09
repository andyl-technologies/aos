//! Flat heap objects: header plus typed payload at the pointed-to address.
//!
//! This is RFC-0007 doc 30 stage FV-1's sealed unsafe module family. Until
//! this stage, a heap [`Value`]'s address pointed at reserved-but-never-written
//! arena bytes and the typed payload lived in an evaluator side table, so every
//! dereference paid an address-hash probe plus a record load. A *flat* object
//! finally writes real bytes behind the arena address:
//!
//! ```text
//! flat heap object (Tier-A bump arena, 8-byte aligned):
//!
//!   ┌──────────────────────────────────────────────────────────┐
//!   │ word 0: kind word   = FLAT_OBJECT_MAGIC << 32 | kind      │
//!   │ word 1: structural hash (the hash-cons key)               │
//!   │ word 2: last-touch epoch (cold-value advice input)        │
//!   ├──────────────────────────────────────────────────────────┤
//!   │ payload: the typed payload struct `T`, written in place   │
//!   └──────────────────────────────────────────────────────────┘
//! ```
//!
//! Resolution is pointer arithmetic: a membership check against the store's
//! own arena chunks, one header load validating the magic/kind word, and a
//! reference into the payload — no side-table probe, no record `Vec`, no
//! payload `Arc` chase.
//!
//! # Ownership and drop discipline
//!
//! [`FlatObjectStore`] owns its own [`BumpArena`], so the safe API cannot
//! outlive the memory it hands out: payload drop glue runs in the store's
//! [`Drop`] (in registry order) strictly before the owned arena unmaps its
//! chunks (struct fields drop after `Drop::drop` returns). Objects are never
//! individually freed: flat objects model the evaluator's hash-consed
//! permanent domain, which is immortal for the store's lifetime, so no mark
//! bits or free lists exist here (thunks arrive in stage FV-3 with their own
//! state machinery).
//!
//! # Lists (edge-carrying payloads) and the writeback door
//!
//! Strings and paths are edge-free leaves; lists carry heap **edges** in
//! their element spine, and the evaluator's minor-GC machinery must be able
//! to rewrite one element in place when a young target relocates. The store
//! therefore offers [`FlatObjectStore::resolve_mut`], an exclusive (`&mut
//! self`) payload resolution used only by the collector's staged-commit
//! writeback path; all read paths keep the shared, immutable contract.
//!
//! *Boundary note (doc 30 §11.7):* the `value/small.rs` 0/1/2-element
//! inline-constructor contract remains dormant — no allocation path consults
//! it — so every list, small or not, is one flat object here. When the small
//! constructors activate, their pointer tags must be reconciled with this
//! header's kind word so the same information is not encoded twice.
//!
//! # Fail-loud contract (weaker than the record table's)
//!
//! The record side table failed unknown pointers loudly by a map miss. A flat
//! store substitutes (doc 30 §2.5/§11.6): an address outside the store's
//! mapped chunk regions fails as [`FlatObjectError::UnknownAddress`] without
//! any memory access; an in-region address is read (always memory-safe: the
//! region is this store's live mapping) and fails loudly unless its first
//! word carries the flat magic and a known kind. An in-region *interior*
//! pointer whose bytes coincidentally spell the magic word would resolve
//! wrongly; such a pointer cannot be produced by the evaluator's value
//! discipline (values only carry addresses returned by allocation).

use std::marker::PhantomData;
use std::mem;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use super::arena::{ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaStats, BumpArena};
use super::advice::MemoryAdviceKind;
use crate::value::HeapObject;

mod bytes;
pub mod shared;

pub use bytes::FlatBytes;

/// The magic tag stored in the upper 32 bits of every flat object's word 0.
pub const FLAT_OBJECT_MAGIC: u64 = 0x464c_5431; // ASCII "FLT1"

/// Maximum alignment a flat payload type may require (the arena word size).
const MAX_ALIGN: usize = mem::align_of::<u64>();

/// Ceiling on the owned arena's geometric chunk growth.
///
/// Flat stores carry real payload bytes (FV-1b inlines string byte runs), so
/// an unbounded doubling policy would let the *mapped* peak run a whole
/// doubling step ahead of the byte mass on byte-heavy workloads (the
/// `string-builder` arena-watch case). Capping the chunk size keeps the
/// mapped peak within one cap-sized chunk of the used bytes while chunk
/// counts stay small enough for the sorted region index.
const MAX_CHUNK_BYTES: usize = 32 << 20;

/// First chunk size for a flat store's owned arena.
///
/// Small enough that a second per-heap arena (the flat list store beside the
/// string/path store) does not show up as a whole default-sized chunk in the
/// mapped-peak column of small evaluations; growth doubles from here up to
/// [`MAX_CHUNK_BYTES`].
const INITIAL_CHUNK_BYTES: usize = 256 << 10;

/// The kind byte stored in the low bits of a flat object's word 0.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlatObjectKind {
    /// A Nix string payload.
    String = 0x01,
    /// A Nix path payload.
    Path = 0x02,
    /// A Nix list payload (the element spine carries heap edges).
    List = 0x03,
}

impl FlatObjectKind {
    /// Decodes a kind from a raw header word, validating the magic tag.
    const fn from_kind_word(word: u64) -> Option<Self> {
        if word >> 32 != FLAT_OBJECT_MAGIC {
            return None;
        }
        match word & 0xffff_ffff {
            0x01 => Some(Self::String),
            0x02 => Some(Self::Path),
            0x03 => Some(Self::List),
            _ => None,
        }
    }

    /// Encodes this kind into the header word 0 representation.
    const fn kind_word(self) -> u64 {
        (FLAT_OBJECT_MAGIC << 32) | self as u64
    }
}

/// The fixed header at the start of every flat object.
#[repr(C)]
#[derive(Debug)]
struct FlatHeader {
    /// `FLAT_OBJECT_MAGIC << 32 | kind` — the resolution validity check.
    kind_word: u64,
    /// The structural hash the object was hash-consed under.
    hash: u64,
    /// Last-touch access epoch, input to the cold-value advice policy.
    ///
    /// Atomic (relaxed) rather than `Cell` so a flat object type is `Sync`
    /// when its payload is; the serial store never shares objects across
    /// threads, and the epoch word carries no ordering obligations.
    epoch: AtomicU64,
}

/// A flat object: header followed by the payload, in place.
#[repr(C)]
#[derive(Debug)]
struct FlatObject<T> {
    header: FlatHeader,
    payload: T,
}

/// Post-monomorphization payload layout checks for [`FlatObject<T>`].
struct FlatLayoutCheck<T>(PhantomData<T>);

impl<T> FlatLayoutCheck<T> {
    /// Fails compilation (post-mono) for payloads the arena cannot host.
    const PAYLOAD_FITS_ARENA_ALIGNMENT: () =
        assert!(mem::align_of::<FlatObject<T>>() <= MAX_ALIGN);
}

/// One registered flat allocation.
#[derive(Clone, Copy, Debug)]
struct FlatStoreEntry {
    /// The stable object address (also the runtime value handle).
    ptr: NonNull<HeapObject>,
    /// The reserved allocation size, for memory-advice ranges.
    size_bytes: usize,
}

/// A shared view of one resolved flat object.
#[derive(Debug)]
pub struct FlatObjectRef<'a, T> {
    object: &'a FlatObject<T>,
}

impl<T> Clone for FlatObjectRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for FlatObjectRef<'_, T> {}

impl<'a, T> FlatObjectRef<'a, T> {
    /// Returns the typed payload stored in the object.
    pub fn payload(self) -> &'a T {
        &self.object.payload
    }

    /// Returns the structural hash the object was interned under.
    pub fn structural_hash(self) -> u64 {
        self.object.header.hash
    }

    /// Returns the object's kind.
    ///
    /// # Panics
    ///
    /// Panics if the header kind word is corrupt, which resolution has
    /// already excluded for every reachable `FlatObjectRef`.
    pub fn kind(self) -> FlatObjectKind {
        match FlatObjectKind::from_kind_word(self.object.header.kind_word) {
            Some(kind) => kind,
            None => unreachable!("resolved flat object lost its kind word"),
        }
    }

    /// Returns the object's last-touch access epoch.
    pub fn last_touch_epoch(self) -> u64 {
        self.object.header.epoch.load(Ordering::Relaxed)
    }

    /// Stamps the object's last-touch access epoch.
    pub fn touch(self, epoch: u64) {
        self.object.header.epoch.store(epoch, Ordering::Relaxed);
    }
}

/// One entry yielded by [`FlatObjectStore::iter`].
#[derive(Debug)]
pub struct FlatStoredObject<'a, T> {
    ptr: NonNull<HeapObject>,
    size_bytes: usize,
    object: FlatObjectRef<'a, T>,
}

impl<T> Clone for FlatStoredObject<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for FlatStoredObject<'_, T> {}

impl<'a, T> FlatStoredObject<'a, T> {
    /// Returns the object's stable heap address.
    pub fn ptr(self) -> NonNull<HeapObject> {
        self.ptr
    }

    /// Returns the reserved allocation size in bytes.
    pub fn size_bytes(self) -> usize {
        self.size_bytes
    }

    /// Returns the resolved object view.
    pub fn object(self) -> FlatObjectRef<'a, T> {
        self.object
    }
}

/// The result of one flat allocation.
#[derive(Clone, Copy, Debug)]
pub struct FlatAllocation {
    /// The stable object address; becomes the runtime value handle.
    pub ptr: NonNull<HeapObject>,
    /// The underlying arena allocation, for allocator accounting parity.
    pub allocation: ArenaAllocation,
}

/// An arena-backed store of flat (header + inline payload) heap objects.
///
/// The store owns a dedicated Tier-A [`BumpArena`]; every allocation writes a
/// [`FlatObject<T>`] in place and registers it for enumeration and drop. See
/// the [module documentation](self) for the layout and the fail-loud
/// contract.
#[derive(Debug)]
pub struct FlatObjectStore<T> {
    arena: BumpArena,
    entries: Vec<FlatStoreEntry>,
    /// Sorted `(start, end)` byte regions of the arena's chunks, refreshed on
    /// allocation. Membership in one of these regions makes a resolution read
    /// memory-safe; the header magic check then decides validity.
    regions: Vec<(usize, usize)>,
    _payload: PhantomData<T>,
}

impl<T> Default for FlatObjectStore<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FlatObjectStore<T> {
    /// Creates an empty store with a default-sized arena.
    pub fn new() -> Self {
        match Self::with_initial_chunk_bytes(INITIAL_CHUNK_BYTES) {
            Ok(store) => store,
            // Unreachable: the constant is non-zero and word-alignable.
            Err(_) => {
                let mut arena = BumpArena::new();
                arena.limit_chunk_growth(MAX_CHUNK_BYTES);
                Self {
                    arena,
                    entries: Vec::new(),
                    regions: Vec::new(),
                    _payload: PhantomData,
                }
            }
        }
    }

    /// Creates an empty store whose arena uses an explicit first chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        let mut arena = BumpArena::with_initial_chunk_bytes(chunk_bytes)?;
        arena.limit_chunk_growth(MAX_CHUNK_BYTES.max(chunk_bytes));
        Ok(Self {
            arena,
            entries: Vec::new(),
            regions: Vec::new(),
            _payload: PhantomData,
        })
    }

    /// Returns the number of flat objects in the store.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the store holds no objects.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the owned arena's accounting.
    pub fn arena_stats(&self) -> ArenaStats {
        self.arena.stats()
    }

    /// Advises unused bytes at the end of the owned arena's chunks.
    pub fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        self.arena.advise_unused_tail(kind)
    }

    /// Returns unused-tail bytes this platform can lower to page advice.
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        self.arena.supported_unused_tail_advice_bytes()
    }

    /// Allocates a flat object and returns its stable address.
    ///
    /// The object header stores `kind`, `hash`, and `epoch`; `payload` is
    /// moved into the object in place. The returned address is valid for the
    /// store's lifetime and is never reissued.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::Arena`] if arena storage cannot be
    /// reserved, or [`FlatObjectError::RegistryAllocationFailed`] if the
    /// registry cannot grow (the arena reservation is then left as dead
    /// padding and the payload is dropped normally).
    pub fn alloc(
        &mut self,
        kind: FlatObjectKind,
        hash: u64,
        epoch: u64,
        payload: T,
    ) -> Result<FlatAllocation, FlatObjectError> {
        let () = FlatLayoutCheck::<T>::PAYLOAD_FITS_ARENA_ALIGNMENT;
        let size = mem::size_of::<FlatObject<T>>();
        let entries = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(FlatObjectError::RegistryAllocationFailed { entries: usize::MAX })?;
        self.entries
            .try_reserve(1)
            .map_err(|_| FlatObjectError::RegistryAllocationFailed { entries })?;
        let allocation = self
            .arena
            .aos_alloc_raw(size, MAX_ALIGN, kind as u32)
            .map_err(FlatObjectError::Arena)?;
        debug_assert!(allocation.reserved_size >= size);
        debug_assert_eq!(allocation.ptr.as_ptr() as usize % MAX_ALIGN, 0);
        let object = FlatObject {
            header: FlatHeader {
                kind_word: kind.kind_word(),
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
        self.entries.push(FlatStoreEntry {
            ptr,
            size_bytes: allocation.reserved_size,
        });
        self.refresh_regions();
        Ok(FlatAllocation { ptr, allocation })
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
        let object_size = mem::size_of::<FlatObject<T>>();
        let size = object_size
            .checked_add(bytes.len())
            .ok_or(FlatObjectError::Arena(ArenaError::SizeOverflow))?;
        let entries = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(FlatObjectError::RegistryAllocationFailed { entries: usize::MAX })?;
        self.entries
            .try_reserve(1)
            .map_err(|_| FlatObjectError::RegistryAllocationFailed { entries })?;
        let allocation = self
            .arena
            .aos_alloc_raw(size, MAX_ALIGN, kind as u32)
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
                kind_word: kind.kind_word(),
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
        self.entries.push(FlatStoreEntry {
            ptr,
            size_bytes: allocation.reserved_size,
        });
        self.refresh_regions();
        Ok(FlatAllocation { ptr, allocation })
    }

    /// Resolves `ptr` as a flat object of `kind`.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::UnknownAddress`] if `ptr` is not a flat
    /// object of this store, and [`FlatObjectError::KindMismatch`] if it is a
    /// flat object of another kind.
    #[inline]
    pub fn resolve(
        &self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<FlatObjectRef<'_, T>, FlatObjectError> {
        let actual = self.kind_at(ptr)?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address: ptr.as_ptr() as usize,
            });
        }
        // SAFETY: `kind_at` proved the address lies in this store's live arena
        // regions at word alignment and starts with a valid flat header for
        // `T`'s kind, so it is one of this store's placement-written
        // `FlatObject<T>` allocations; shared access is sound because objects
        // are immutable after construction except the atomic epoch word.
        let object = unsafe { &*(ptr.as_ptr() as *const FlatObject<T>) };
        Ok(FlatObjectRef { object })
    }

    /// Resolves `ptr` as a flat object of `kind` with mutable payload access.
    ///
    /// This is the collector writeback door (doc 30 FV-1, GC coupling (c)):
    /// minor-GC heap-field writebacks rewrite list elements in place, and the
    /// flat store must offer the same staged-commit mutability the record
    /// table's `DerefMut` provided. Exclusivity comes from the borrow: every
    /// shared resolution borrows `&self`, so an outstanding `&mut self`
    /// guarantees no [`FlatObjectRef`] or payload borrow is alive.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::UnknownAddress`] if `ptr` is not a flat
    /// object of this store, and [`FlatObjectError::KindMismatch`] if it is a
    /// flat object of another kind.
    pub fn resolve_mut(
        &mut self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
    ) -> Result<&mut T, FlatObjectError> {
        let actual = self.kind_at(ptr)?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address: ptr.as_ptr() as usize,
            });
        }
        // SAFETY: `kind_at` proved the address is one of this store's
        // placement-written `FlatObject<T>` allocations (see `resolve`);
        // mutable access is exclusive because every other resolution path
        // borrows the store shared while this method holds `&mut self`, so
        // the borrow checker rules out any live aliasing reference.
        let object = unsafe { &mut *(ptr.as_ptr() as *mut FlatObject<T>) };
        Ok(&mut object.payload)
    }

    /// Returns the flat kind stored at `ptr`, if it is one of this store's
    /// objects.
    pub fn kind_of(&self, ptr: NonNull<HeapObject>) -> Option<FlatObjectKind> {
        self.kind_at(ptr).ok()
    }

    /// Iterates every stored object in allocation order.
    pub fn iter(&self) -> impl Iterator<Item = FlatStoredObject<'_, T>> {
        self.entries.iter().map(|entry| {
            // SAFETY: every registry entry was placement-written by `alloc`
            // into this store's owned arena, is never moved or freed before
            // the store drops, and is immutable after construction except the
            // atomic epoch word.
            let object = unsafe { &*(entry.ptr.as_ptr() as *const FlatObject<T>) };
            FlatStoredObject {
                ptr: entry.ptr,
                size_bytes: entry.size_bytes,
                object: FlatObjectRef { object },
            }
        })
    }

    /// Validates that `ptr` names one of this store's objects and reads its
    /// kind.
    #[inline]
    fn kind_at(&self, ptr: NonNull<HeapObject>) -> Result<FlatObjectKind, FlatObjectError> {
        let address = ptr.as_ptr() as usize;
        if address % MAX_ALIGN != 0 || !self.contains_address(address) {
            return Err(FlatObjectError::UnknownAddress { address });
        }
        // SAFETY: `address` is word-aligned inside one of this store's live
        // arena chunk regions, so an 8-byte read is in-bounds of a mapping
        // this store owns; anonymous-mmap bytes are readable and act as
        // initialized (zero-filled) from the abstract machine's view.
        let kind_word = unsafe { (ptr.as_ptr() as *const u64).read() };
        FlatObjectKind::from_kind_word(kind_word)
            .ok_or(FlatObjectError::UnknownAddress { address })
    }

    /// Returns whether `address` lies inside one of the arena's chunk regions.
    #[inline]
    fn contains_address(&self, address: usize) -> bool {
        let position = self
            .regions
            .partition_point(|&(start, _end)| start <= address);
        position
            .checked_sub(1)
            .and_then(|index| self.regions.get(index))
            .is_some_and(|&(_start, end)| address < end)
    }

    /// Rebuilds the sorted chunk-region membership index when chunks change.
    fn refresh_regions(&mut self) {
        if self.regions.len() == self.arena.stats().chunks {
            return;
        }
        self.regions.clear();
        self.regions.extend(self.arena.chunk_regions());
        self.regions.sort_unstable();
    }
}

impl<T> Drop for FlatObjectStore<T> {
    fn drop(&mut self) {
        for entry in &self.entries {
            // SAFETY: `entry.ptr` was placement-written by an allocation
            // method (`alloc` / `alloc_with_trailing_bytes`) as a
            // `FlatObject<T>` in the store-owned arena, is dropped exactly
            // once (entries are never removed), and the arena's mappings are
            // still live: the arena is a field of `self`, and fields drop
            // after this `Drop::drop` body returns.
            unsafe { std::ptr::drop_in_place(entry.ptr.as_ptr() as *mut FlatObject<T>) };
        }
    }
}

/// A failed flat-object operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FlatObjectError {
    /// The owned arena could not reserve object storage.
    #[error("flat object allocation error: {0}")]
    Arena(#[from] ArenaError),
    /// The object registry could not grow.
    #[error("flat object store failed to reserve {entries} registry entries")]
    RegistryAllocationFailed {
        /// The requested registry capacity.
        entries: usize,
    },
    /// The address is not a flat object of this store.
    #[error("flat object address is unknown: 0x{address:x}")]
    UnknownAddress {
        /// The rejected address.
        address: usize,
    },
    /// The address names a flat object of a different kind.
    #[error("flat object kind mismatch at 0x{address:x}: expected {expected:?}, got {actual:?}")]
    KindMismatch {
        /// The kind the caller expected.
        expected: FlatObjectKind,
        /// The kind stored in the object header.
        actual: FlatObjectKind,
        /// The object address.
        address: usize,
    },
}

#[cfg(test)]
mod tests;
