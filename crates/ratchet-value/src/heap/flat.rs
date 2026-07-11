//! Flat heap objects: header plus typed payload at the pointed-to address.
//!
//! This is RFC-0007 doc 30 stage FV-1's sealed unsafe module family. Until
//! this stage, a heap [`Value`]'s address pointed at reserved-but-never-written
//! arena bytes and the typed payload lived in an evaluator side table, so every
//! dereference paid an address-hash probe plus a record load. A *flat* object
//! finally writes real bytes behind the arena address:
//!
//! ```text
//! flat heap object (Tier-A allocation backing, 8-byte aligned):
//!
//!   ┌──────────────────────────────────────────────────────────┐
//!   │ word 0: kind word = FLAT_OBJECT_MAGIC << 32               │
//!   │                     | aux << 8 | kind                     │
//!   │ word 1: structural hash (the hash-cons key)               │
//!   │ word 2: last-touch epoch (cold-value advice input)        │
//!   ├──────────────────────────────────────────────────────────┤
//!   │ payload: the typed payload struct `T`, written in place   │
//!   │ inline arrays ... (FV-1b bytes / FV-4 element runs)       │
//!   └──────────────────────────────────────────────────────────┘
//! ```
//!
//! The kind word's middle 24 bits (`aux`) are the FV-4 size-class field: a
//! saturating payload cardinality (list length, attrset entry count; byte
//! length for strings/paths) pinned here so the compressed-value layout doc
//! 30 §3.5 plans against can classify an object from its first header load.
//! [`FLAT_AUX_SATURATED`] means "consult the payload"; no hot path consumes
//! the field yet — resolution validates only the magic and kind bits.
//!
//! Resolution is pointer arithmetic: a membership check against the store's
//! own arena chunks, one header load validating the magic/kind word, and a
//! reference into the payload — no side-table probe, no record `Vec`, no
//! payload `Arc` chase.
//!
//! # Ownership and drop discipline
//!
//! A [`FlatObjectStore`] owns its backing or holds a strong shared-backing
//! handle, so the safe API cannot outlive the memory it hands out: payload drop
//! glue runs in the store's [`Drop`] before the last backing owner can unmap.
//! Permanent-domain stores (strings/paths/lists/attrsets) share one Candidate-C
//! reservation in production and never free objects individually: they model
//! the evaluator's hash-consed immortal domain. Worker-domain
//! stores (doc 30 stage FV-3: thunks, lambdas, primops) reclaim through
//! exactly two doors, mirroring the record table's two mutually-exclusive
//! reclaimers: [`FlatObjectStore::pop_region`] (LIFO lexical-region pops,
//! addresses may be reused afterwards) and payload retirement in place
//! through [`FlatObjectStore::resolve_mut`] (the B1 sweep swaps the payload
//! for a retired tombstone; the entry, header, and address remain, and the
//! address is never reissued).
//!
//! # Lists and attrsets (edge-carrying payloads) and the writeback door
//!
//! Strings and paths are edge-free leaves; lists carry heap **edges** in
//! their element spine and attrsets in their entry values, and the
//! evaluator's minor-GC machinery must be able to rewrite one field in place
//! when a young target relocates. The store therefore offers
//! [`FlatObjectStore::resolve_mut`], an exclusive (`&mut self`) payload
//! resolution used only by the collector's staged-commit writeback path; all
//! read paths keep the shared, immutable contract.
//!
//! # Attrs metadata placement (doc 30 FV-2 decision)
//!
//! An attrset carries shape metadata (the lowered shape id, the projected
//! hidden-class [`ShapeId`], and the representation kind) alongside its entry
//! slots. That metadata rides **in the payload**, not in the header: header
//! word 1 carries the full 64-bit hash-cons key for every kind, and
//! splitting it into a 32-bit hash plus a shape id would weaken collision
//! confirmation for all kinds while still not fitting the three-field
//! metadata. The payload struct leads with the metadata words, so a
//! PIC/select-cache guard load is header-adjacent — one flat resolution, no
//! record probe — which is the layout doc 30 §2.3 stage 2 asks for. FV-4
//! gave the kind word its 24-bit `aux` size-class field (the entry count for
//! attrsets); the projected `ShapeId` stays in the payload because the aux
//! field is too narrow for the three-field metadata and the guard load is
//! already header-adjacent.
//!
//! *Boundary note (doc 30 §11.7, resolved in FV-2):* the former
//! `value/small.rs` 0/1/2-element inline-constructor contract was dormant —
//! no allocation, resolution, or dispatch path ever consulted it, and no
//! pointer tag bits were ever assigned — so FV-2 retired the module instead
//! of folding a size class into this header. Every list and attrset, small
//! or not, is one flat object here; if a measured small-constructor variant
//! returns, it must be reconciled with the kind word at that point.
//!
//! [`ShapeId`]: crate::attrs::shape::ShapeId
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

use super::arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaRegionMark, ArenaRegionPopReport,
    ArenaStats, BumpArena,
};
use super::advice::MemoryAdviceKind;
use crate::value::HeapObject;

mod alloc;
mod backing;
mod bytes;
pub mod shared;
mod slice;
mod value_tail;

pub use backing::{FlatKindSet, SharedFlatStoreArena};
pub use bytes::FlatBytes;
pub use slice::{FlatSlice, FlatTailLayout, FlatTailWriter};
pub use value_tail::{FlatValueTailAllocation, FlatValueTailHandle};

/// The magic tag stored in the upper 32 bits of every flat object's word 0.
pub const FLAT_OBJECT_MAGIC: u64 = 0x464c_5431; // ASCII "FLT1"

/// The saturation value of the kind word's 24-bit `aux` size-class field.
///
/// An object whose payload cardinality is at least this value stores exactly
/// this value; readers must consult the payload for the true cardinality.
pub const FLAT_AUX_SATURATED: u32 = 0x00ff_ffff;

/// Maximum alignment a flat payload type may require (the arena word size).
const MAX_ALIGN: usize = mem::align_of::<u64>();

/// Ceiling on the owned arena's geometric chunk growth.
///
/// Flat stores carry real payload bytes (FV-1b inlines string byte runs), so
/// an unbounded doubling policy would let the *mapped* peak run a whole
/// doubling step ahead of the byte mass on byte-heavy workloads (the
/// `string-builder` arena-watch case). Capping the chunk size keeps the
/// mapped peak within one cap-sized chunk of the used bytes while chunk
/// counts stay small enough for the sorted region index. FV-5's wide-eval
/// profile used 16.1--16.4 MiB in each flat domain: the former doubling step
/// mapped 16 MiB for only 0.3--0.6 MiB of overflow. A 4 MiB ceiling keeps the
/// sorted region index to eight chunks at that workload while removing 24
/// MiB of unused mappings across the two domains.
const MAX_CHUNK_BYTES: usize = 4 << 20;

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
    /// A Nix attribute-set payload (entry values carry heap edges).
    Attrs = 0x04,
    /// A suspended-thunk payload (doc 30 stage FV-3; worker domain).
    Thunk = 0x05,
    /// A lambda-closure payload (doc 30 stage FV-3; worker domain).
    Lambda = 0x06,
    /// A builtin / partially-applied-builtin payload (doc 30 stage FV-3).
    Primop = 0x07,
}

impl FlatObjectKind {
    /// Decodes a kind from a raw header word, validating the magic tag.
    ///
    /// The middle 24 bits are the `aux` size-class field and do not
    /// participate in validity; see the [module documentation](self).
    const fn from_kind_word(word: u64) -> Option<Self> {
        if word >> 32 != FLAT_OBJECT_MAGIC {
            return None;
        }
        match word & 0xff {
            0x01 => Some(Self::String),
            0x02 => Some(Self::Path),
            0x03 => Some(Self::List),
            0x04 => Some(Self::Attrs),
            0x05 => Some(Self::Thunk),
            0x06 => Some(Self::Lambda),
            0x07 => Some(Self::Primop),
            _ => None,
        }
    }

    /// Encodes this kind and a saturated `aux` size class into word 0.
    const fn kind_word(self, aux: u32) -> u64 {
        let aux = if aux > FLAT_AUX_SATURATED {
            FLAT_AUX_SATURATED
        } else {
            aux
        };
        (FLAT_OBJECT_MAGIC << 32) | ((aux as u64) << 8) | self as u64
    }
}

/// Extracts the 24-bit `aux` size-class field from a raw header word.
const fn aux_of_kind_word(word: u64) -> u32 {
    ((word >> 8) & FLAT_AUX_SATURATED as u64) as u32
}

/// Saturates a payload cardinality into the header `aux` field encoding.
pub const fn flat_aux_for_len(len: usize) -> u32 {
    if len >= FLAT_AUX_SATURATED as usize {
        FLAT_AUX_SATURATED
    } else {
        len as u32
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

/// One registered flat allocation.
#[derive(Clone, Copy, Debug)]
struct FlatStoreEntry {
    /// The stable object address (also the runtime value handle).
    ptr: NonNull<HeapObject>,
    /// The reserved size plus registry-only low-bit tail metadata.
    size_and_flags: usize,
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

    /// Returns the object's saturated 24-bit `aux` size class.
    ///
    /// [`FLAT_AUX_SATURATED`] means the true cardinality did not fit and the
    /// payload must be consulted; see the [module documentation](self).
    pub fn aux(self) -> u32 {
        aux_of_kind_word(self.object.header.kind_word)
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

/// A LIFO marker over a flat store's registry and owned arena.
///
/// Produced by [`FlatObjectStore::region_mark`] and consumed by
/// [`FlatObjectStore::pop_region`] once the caller has proven every object
/// above the marker unreferenced. Worker-domain stores (doc 30 stage FV-3)
/// use this to reclaim flat closures on lexical-region pops exactly where the
/// record table used index truncation; permanent-domain stores never pop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlatStoreRegionMark {
    entries: usize,
    arena: ArenaRegionMark,
}

impl FlatStoreRegionMark {
    /// Returns the registry length captured by the marker.
    pub const fn entries(self) -> usize {
        self.entries
    }
}

/// Accounting returned after popping a flat store's lexical subregion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlatStorePopReport {
    popped_entries: usize,
    arena: ArenaRegionPopReport,
}

impl FlatStorePopReport {
    /// Returns the number of flat objects dropped by the pop.
    pub const fn popped_entries(self) -> usize {
        self.popped_entries
    }

    /// Returns the owned arena's reclamation accounting.
    pub const fn arena_report(self) -> ArenaRegionPopReport {
        self.arena
    }
}

/// The result of one flat allocation.
#[derive(Clone, Copy, Debug)]
pub struct FlatAllocation {
    /// The stable object address; becomes the runtime value handle.
    pub ptr: NonNull<HeapObject>,
    /// The stable allocation-registry index while this object remains live.
    pub store_index: usize,
    /// The underlying arena allocation, for allocator accounting parity.
    pub allocation: ArenaAllocation,
}

/// The arena a flat store reserves object storage from.
///
/// `Owned` is the pre-FV-4 shape: a dedicated per-store arena, required by
/// stores that pop lexical regions (rewinding a bump cursor is only sound
/// over one store's allocations). `Shared` places this store's objects in a
/// [`SharedFlatStoreArena`] beside other stores' objects, collapsing the
/// per-type chunk slack; see the `backing` module for the soundness argument.
#[derive(Debug)]
enum FlatStoreBacking {
    Owned(BumpArena),
    Shared(SharedFlatStoreArena),
}

impl FlatStoreBacking {
    /// Reserves `size` bytes for a flat object of `kind`.
    fn alloc_raw(
        &mut self,
        size: usize,
        kind: FlatObjectKind,
    ) -> Result<ArenaAllocation, ArenaError> {
        match self {
            Self::Owned(arena) => arena.aos_alloc_raw(size, MAX_ALIGN, kind as u32),
            Self::Shared(shared) => shared.alloc_raw(size, MAX_ALIGN, kind),
        }
    }
}

/// An arena-backed store of flat (header + inline payload) heap objects.
///
/// The store reserves storage from its backing — a dedicated Tier-A
/// [`BumpArena`] or an FV-4 shared multi-store arena; every allocation
/// writes a [`FlatObject<T>`] in place and registers it for enumeration and
/// drop. See the [module documentation](self) for the layout and the
/// fail-loud contract.
#[derive(Debug)]
pub struct FlatObjectStore<T> {
    backing: FlatStoreBacking,
    /// Kinds this store may allocate and type as `FlatObject<T>`.
    ///
    /// On a shared arena the header kind word is the payload-type witness, so
    /// typed resolution must reject kinds this store did not allocate even
    /// when the header is valid; sharing stores carry disjoint sets.
    allowed: FlatKindSet,
    entries: Vec<FlatStoreEntry>,
    /// Sorted `(start, end)` byte regions of the backing arena's chunks,
    /// refreshed on allocation. Membership in one of these regions makes a
    /// resolution read memory-safe; the header magic check then decides
    /// validity.
    regions: Vec<(usize, usize)>,
    _payload: PhantomData<T>,
}

impl<T> Default for FlatObjectStore<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FlatObjectStore<T> {
    /// Creates an empty store with a default-sized owned arena.
    pub fn new() -> Self {
        match Self::with_initial_chunk_bytes(INITIAL_CHUNK_BYTES) {
            Ok(store) => store,
            // Unreachable: the constant is non-zero and word-alignable.
            Err(_) => {
                let mut arena = BumpArena::new();
                arena.limit_chunk_growth(MAX_CHUNK_BYTES);
                Self {
                    backing: FlatStoreBacking::Owned(arena),
                    allowed: FlatKindSet::ALL,
                    entries: Vec::new(),
                    regions: Vec::new(),
                    _payload: PhantomData,
                }
            }
        }
    }

    /// Creates an empty store whose owned arena uses an explicit first chunk
    /// size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        let mut arena = BumpArena::with_initial_chunk_bytes(chunk_bytes)?;
        arena.limit_chunk_growth(MAX_CHUNK_BYTES.max(chunk_bytes));
        Ok(Self {
            backing: FlatStoreBacking::Owned(arena),
            allowed: FlatKindSet::ALL,
            entries: Vec::new(),
            regions: Vec::new(),
            _payload: PhantomData,
        })
    }

    /// Creates an empty store over a shared multi-store arena, allowed to
    /// allocate exactly the given kinds (doc 30 FV-4).
    ///
    /// Stores sharing one arena must be given mutually disjoint kind sets:
    /// the header kind word is the payload-type witness across the shared
    /// chunks (see the `backing` module). Shared-backed stores cannot pop
    /// lexical regions.
    pub fn with_shared_arena(arena: SharedFlatStoreArena, allowed: FlatKindSet) -> Self {
        Self {
            backing: FlatStoreBacking::Shared(arena),
            allowed,
            entries: Vec::new(),
            regions: Vec::new(),
            _payload: PhantomData,
        }
    }

    /// Returns the number of flat objects in the store.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the store holds no objects.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the backing arena's accounting.
    ///
    /// For a shared-arena store this reports the whole shared arena; callers
    /// merging per-store statistics must read the shared arena exactly once
    /// (through its [`SharedFlatStoreArena`] handle) rather than per store.
    pub fn arena_stats(&self) -> ArenaStats {
        match &self.backing {
            FlatStoreBacking::Owned(arena) => arena.stats(),
            FlatStoreBacking::Shared(shared) => shared.stats(),
        }
    }

    /// Advises unused bytes at the end of an owned arena's chunks.
    ///
    /// Shared-arena stores report nothing here: unused-tail advice for a
    /// shared arena is issued once through its handle, not once per store.
    pub fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        match &self.backing {
            FlatStoreBacking::Owned(arena) => arena.advise_unused_tail(kind),
            FlatStoreBacking::Shared(_) => ArenaMemoryAdviceReport::empty(kind),
        }
    }

    /// Returns unused-tail bytes this platform can lower to page advice.
    ///
    /// Shared-arena stores report zero here for the same single-reader
    /// discipline as [`FlatObjectStore::advise_unused_tail`].
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        match &self.backing {
            FlatStoreBacking::Owned(arena) => arena.supported_unused_tail_advice_bytes(),
            FlatStoreBacking::Shared(_) => 0,
        }
    }

    /// Rejects kinds outside the store's allowed set.
    #[inline]
    fn check_kind_allowed(&self, kind: FlatObjectKind) -> Result<(), FlatObjectError> {
        if self.allowed.contains(kind) {
            Ok(())
        } else {
            Err(FlatObjectError::KindNotAllowed { kind })
        }
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
        self.check_kind_allowed(kind)?;
        let actual = self.kind_at(ptr)?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address: ptr.as_ptr() as usize,
            });
        }
        // SAFETY: `kind_at` proved the address lies in the backing arena's
        // live chunk regions at word alignment and starts with a valid flat
        // header whose kind is in this store's allowed set; sharing stores
        // carry disjoint kind sets, so the object was placement-written by
        // *this* store as a `FlatObject<T>`. Shared access is sound because
        // objects are immutable after construction except the atomic epoch
        // word.
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
        self.check_kind_allowed(kind)?;
        let actual = self.kind_at(ptr)?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address: ptr.as_ptr() as usize,
            });
        }
        // SAFETY: `kind_at` plus the allowed-kind guard proved the address is
        // one of this store's placement-written `FlatObject<T>` allocations
        // (see `resolve`); mutable access is exclusive because every other
        // resolution path borrows the store shared while this method holds
        // `&mut self`, so the borrow checker rules out any live aliasing
        // reference.
        let object = unsafe { &mut *(ptr.as_ptr() as *mut FlatObject<T>) };
        Ok(&mut object.payload)
    }

    /// Replaces the structural-hash header word of one resolved object.
    ///
    /// Collector writeback uses this after staging a rebuilt hash-cons table:
    /// the object payload and table bucket then publish the same repaired key.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::UnknownAddress`] if `ptr` is not a flat
    /// object of this store, and [`FlatObjectError::KindMismatch`] if it is a
    /// flat object of another kind.
    pub fn update_structural_hash(
        &mut self,
        ptr: NonNull<HeapObject>,
        kind: FlatObjectKind,
        structural_hash: u64,
    ) -> Result<(), FlatObjectError> {
        self.check_kind_allowed(kind)?;
        let actual = self.kind_at(ptr)?;
        if actual != kind {
            return Err(FlatObjectError::KindMismatch {
                expected: kind,
                actual,
                address: ptr.as_ptr() as usize,
            });
        }
        // SAFETY: the same proof as `resolve_mut` applies; `&mut self` excludes
        // every shared resolution while the header word is replaced.
        let object = unsafe { &mut *(ptr.as_ptr() as *mut FlatObject<T>) };
        object.header.hash = structural_hash;
        Ok(())
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
                size_bytes: entry.size_bytes(),
                object: FlatObjectRef { object },
            }
        })
    }

    /// Captures the current registry and arena position for a future
    /// lexical-region pop.
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::SharedArenaRegionUnsupported`] for a store
    /// on a shared arena: rewinding a shared bump cursor would reclaim other
    /// stores' objects, so region marks exist only over owned arenas (the
    /// worker-domain closure store).
    pub fn region_mark(&self) -> Result<FlatStoreRegionMark, FlatObjectError> {
        let FlatStoreBacking::Owned(arena) = &self.backing else {
            return Err(FlatObjectError::SharedArenaRegionUnsupported);
        };
        Ok(FlatStoreRegionMark {
            entries: self.entries.len(),
            arena: arena.region_mark(),
        })
    }

    /// Pops every object allocated after `mark`, dropping payloads and
    /// rewinding the owned arena (doc 30 stage FV-3, worker-domain stores).
    ///
    /// This is the flat analog of the record table's region truncation: the
    /// popped objects' payloads are dropped exactly once, their header kind
    /// words are wiped so a stale resolution of a popped address in a
    /// retained chunk fails the magic check loudly (dropped whole chunks
    /// leave the membership regions entirely), and the arena cursor rewinds
    /// so later allocations may reuse the addresses — the same reuse contract
    /// the record-table pop documents. The caller owns the reachability
    /// proof: no retained object or live root may still reference the popped
    /// suffix (the evaluator's region-pop validation establishes this before
    /// calling), and marker freshness/ownership is the caller's region-mark
    /// discipline (the evaluator wraps flat markers in its owner/epoch
    /// checked region marks).
    ///
    /// # Errors
    ///
    /// Returns [`FlatObjectError::SharedArenaRegionUnsupported`] for a store
    /// on a shared arena (marks are unobtainable there, so this is
    /// defense-in-depth), [`FlatObjectError::InvalidRegionMark`] if `mark`'s
    /// registry length exceeds the store's, or [`FlatObjectError::Arena`] if
    /// the arena marker cannot describe the arena's current prefix. All are
    /// rejected before any payload is dropped.
    pub fn pop_region(
        &mut self,
        mark: FlatStoreRegionMark,
    ) -> Result<FlatStorePopReport, FlatObjectError> {
        let FlatStoreBacking::Owned(arena) = &mut self.backing else {
            return Err(FlatObjectError::SharedArenaRegionUnsupported);
        };
        if mark.entries > self.entries.len() {
            return Err(FlatObjectError::InvalidRegionMark {
                marked_entries: mark.entries,
                current_entries: self.entries.len(),
            });
        }
        arena
            .validate_region_mark(mark.arena)
            .map_err(FlatObjectError::Arena)?;
        for entry in &self.entries[mark.entries..] {
            // SAFETY: `entry.ptr` was placement-written by an allocation
            // method as a `FlatObject<T>` in the store-owned arena and is
            // dropped exactly once: the registry entry is truncated below, so
            // neither a later pop nor the store's `Drop` revisits it. The
            // arena mapping is still live because the rewind happens after
            // this loop.
            unsafe { std::ptr::drop_in_place(entry.ptr.as_ptr() as *mut FlatObject<T>) };
            // SAFETY: same in-bounds, exclusively owned allocation; wiping
            // the kind word makes a stale resolution of this address fail the
            // header magic check loudly instead of reading a dropped payload.
            unsafe { (entry.ptr.as_ptr() as *mut u64).write(0) };
        }
        let popped_entries = self.entries.len() - mark.entries;
        self.entries.truncate(mark.entries);
        // SAFETY: the marker was structurally validated above and every
        // object above it was just dropped and unregistered, so no registry
        // entry or payload borrow refers to the rewound range; the caller's
        // region discipline proves no live runtime value still names those
        // addresses (stale handles fail loudly per the wipe above).
        let arena_report = unsafe { arena.pop_region_to_mark(mark.arena) }
            .map_err(FlatObjectError::Arena)?;
        self.regions.clear();
        self.regions.extend(arena.chunk_regions());
        self.regions.sort_unstable();
        Ok(FlatStorePopReport {
            popped_entries,
            arena: arena_report,
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
        // SAFETY: `address` is word-aligned inside one of the backing arena's
        // live chunk regions (kept mapped by this store's owned arena or its
        // strong shared-arena handle), so an 8-byte read is in-bounds of a
        // live mapping; anonymous-mmap bytes are readable and act as
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
    ///
    /// On a shared arena the index covers every sharing store's chunks; the
    /// header kind word (plus the allowed-kind guard) restores per-store type
    /// fidelity above the shared membership check.
    fn refresh_regions(&mut self) {
        // Constant-time staleness check: this runs after *every* allocation,
        // and a chunk-walking `stats()` here is O(chunks) per alloc — a
        // measured 15%+ wall regression on attrset-churn workloads once the
        // shared arena carries tens of chunks.
        match &self.backing {
            FlatStoreBacking::Owned(arena) => {
                if self.regions.len() == arena.chunk_count() {
                    return;
                }
                self.regions.clear();
                self.regions.extend(arena.chunk_regions());
                self.regions.sort_unstable();
            }
            FlatStoreBacking::Shared(shared) => {
                if self.regions.len() == shared.chunk_count() {
                    return;
                }
                shared.snapshot_chunk_regions(&mut self.regions);
            }
        }
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
    /// A region marker did not describe the store's current prefix.
    #[error(
        "flat store region mark is invalid: marked {marked_entries} entries, store has {current_entries}"
    )]
    InvalidRegionMark {
        /// The registry length captured by the marker.
        marked_entries: usize,
        /// The store's current registry length.
        current_entries: usize,
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
    /// The kind is outside this store's allowed set (doc 30 FV-4: sharing
    /// stores carry disjoint kind sets and may only type their own kinds).
    #[error("flat object kind {kind:?} is not allowed for this store")]
    KindNotAllowed {
        /// The rejected kind.
        kind: FlatObjectKind,
    },
    /// Region marks and pops are unsupported over a shared arena (rewinding
    /// a shared bump cursor would reclaim other stores' objects).
    #[error("flat store region operations are unsupported on a shared arena")]
    SharedArenaRegionUnsupported,
}

#[cfg(test)]
mod tests;
