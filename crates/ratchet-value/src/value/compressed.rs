//! Candidate-C compressed runtime value words.
//!
//! RFC-0007 doc 30 section 3 assigns Candidate C one 64-bit word split into a
//! 32-bit kind/metadata half and a 32-bit payload half. Heap payloads are
//! offsets in one [`ReservedArena`](crate::heap::ReservedArena), not pointer
//! bits. Signed 32-bit integers remain immediate; wider integers and every
//! float use typed boxed-scalar indices. Bit 31 of the kind half is the thunk
//! `FORCED` shortcut.
//!
//! [`CandidateCScalarStore`] supplies the serial hash-consed cells for wide
//! integers and floats; [`SharedCandidateCScalarStore`] supplies one
//! synchronized population across parallel workers. Candidate C addresses
//! those cells by reservation index, while Candidate B can address the same
//! typed populations by validated native pointer on compatibility backends.
//! The active evaluator still uses [`Value`](super::Value); switching the
//! runtime and JIT ABI is a later, separately gated step.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::heap::flat::shared::{SharedFlatObjectError, SharedFlatObjectStore};
use crate::heap::flat::{
    FlatKindSet, FlatObjectError, FlatObjectKind, FlatObjectStore, SharedFlatStoreArena,
};
use crate::heap::{ArenaDomainId, ArenaIndex, ReservedArena};

use super::ValueTag;

mod bridge;

pub use bridge::CandidateCValueError;

/// Metadata bit marking an already-forced thunk index.
pub const COMPRESSED_FORCED_BIT: u32 = 1 << 31;
const KIND_MASK: u32 = 0xff;
const ARENA_DOMAIN_SHIFT: u32 = 8;
const ARENA_DOMAIN_MASK: u32 = 0x7fff_ff00;

/// The representation kind stored in the high half of a compressed word.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompressedValueKind {
    /// An inline signed 32-bit integer.
    InlineInt = 0x00,
    /// A boxed IEEE-754 double in the reservation arena.
    BoxedFloat = 0x01,
    /// An inline boolean encoded as zero or one.
    Bool = 0x02,
    /// The null singleton, whose payload must be zero.
    Null = 0x03,
    /// A string heap index.
    String = 0x10,
    /// A path heap index.
    Path = 0x11,
    /// A list heap index.
    List = 0x12,
    /// An attribute-set heap index.
    Attrs = 0x13,
    /// A lambda heap index.
    Lambda = 0x14,
    /// A builtin or partially-applied-builtin heap index.
    Primop = 0x15,
    /// An opaque external-value heap index.
    External = 0x16,
    /// A thunk heap index.
    Thunk = 0x20,
    /// A boxed signed 64-bit integer in the reservation arena.
    BoxedInt = 0x30,
}

impl CompressedValueKind {
    #[inline]
    fn from_bits(bits: u32) -> Result<Self, CompressedValueError> {
        match bits {
            0x00 => Ok(Self::InlineInt),
            0x01 => Ok(Self::BoxedFloat),
            0x02 => Ok(Self::Bool),
            0x03 => Ok(Self::Null),
            0x10 => Ok(Self::String),
            0x11 => Ok(Self::Path),
            0x12 => Ok(Self::List),
            0x13 => Ok(Self::Attrs),
            0x14 => Ok(Self::Lambda),
            0x15 => Ok(Self::Primop),
            0x16 => Ok(Self::External),
            0x20 => Ok(Self::Thunk),
            0x30 => Ok(Self::BoxedInt),
            kind => Err(CompressedValueError::UnknownKind { kind }),
        }
    }

    /// Returns the semantic runtime tag represented by this encoding kind.
    #[inline]
    pub const fn semantic_tag(self) -> ValueTag {
        match self {
            Self::InlineInt | Self::BoxedInt => ValueTag::Int,
            Self::BoxedFloat => ValueTag::Float,
            Self::Bool => ValueTag::Bool,
            Self::Null => ValueTag::Null,
            Self::String => ValueTag::String,
            Self::Path => ValueTag::Path,
            Self::List => ValueTag::List,
            Self::Attrs => ValueTag::Attrs,
            Self::Lambda => ValueTag::Lambda,
            Self::Primop => ValueTag::Primop,
            Self::External => ValueTag::External,
            Self::Thunk => ValueTag::Thunk,
        }
    }

    #[inline]
    const fn carries_arena_index(self) -> bool {
        !matches!(self, Self::InlineInt | Self::Bool | Self::Null)
    }
}

/// One checked Candidate-C value word.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CompressedValueWord {
    raw: u64,
}

const _: () = assert!(std::mem::size_of::<CompressedValueWord>() == 8);
const _: () = assert!(std::mem::align_of::<CompressedValueWord>() == 8);

impl CompressedValueWord {
    /// Encodes an integer inline when it fits the Candidate-C immediate range.
    ///
    /// # Errors
    ///
    /// Returns [`CompressedValueError::IntegerRequiresBox`] when `value` does
    /// not fit in a signed 32-bit payload. The caller must allocate an `i64`
    /// cell and use [`Self::boxed_int`] in that case.
    pub fn inline_int(value: i64) -> Result<Self, CompressedValueError> {
        let value =
            i32::try_from(value).map_err(|_| CompressedValueError::IntegerRequiresBox { value })?;
        Ok(Self::compose(CompressedValueKind::InlineInt, value as u32))
    }

    /// Encodes an arena index for a boxed signed 64-bit integer.
    pub const fn boxed_int(domain: ArenaDomainId, index: ArenaIndex) -> Self {
        Self::compose_indexed(CompressedValueKind::BoxedInt, domain, index)
    }

    /// Encodes an arena index for a boxed IEEE-754 double.
    pub const fn boxed_float(domain: ArenaDomainId, index: ArenaIndex) -> Self {
        Self::compose_indexed(CompressedValueKind::BoxedFloat, domain, index)
    }

    /// Encodes an inline boolean.
    pub const fn boolean(value: bool) -> Self {
        Self::compose(CompressedValueKind::Bool, value as u32)
    }

    /// Encodes the null singleton.
    pub const fn null() -> Self {
        Self::compose(CompressedValueKind::Null, 0)
    }

    /// Encodes a typed heap index.
    ///
    /// # Errors
    ///
    /// Returns [`CompressedValueError::NonHeapTag`] when `tag` is an inline
    /// scalar tag. Boxed scalars use [`Self::boxed_int`] or
    /// [`Self::boxed_float`].
    pub fn heap(
        domain: ArenaDomainId,
        tag: ValueTag,
        index: ArenaIndex,
    ) -> Result<Self, CompressedValueError> {
        let kind = match tag {
            ValueTag::String => CompressedValueKind::String,
            ValueTag::Path => CompressedValueKind::Path,
            ValueTag::List => CompressedValueKind::List,
            ValueTag::Attrs => CompressedValueKind::Attrs,
            ValueTag::Lambda => CompressedValueKind::Lambda,
            ValueTag::Primop => CompressedValueKind::Primop,
            ValueTag::External => CompressedValueKind::External,
            ValueTag::Thunk => CompressedValueKind::Thunk,
            tag => return Err(CompressedValueError::NonHeapTag { tag }),
        };
        Ok(Self::compose_indexed(kind, domain, index))
    }

    /// Decodes and validates a raw Candidate-C word.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown kinds, a forced bit on a non-thunk, an
    /// invalid boolean payload, or a nonzero null payload.
    pub fn from_raw(raw: u64) -> Result<Self, CompressedValueError> {
        let kind_and_flags = (raw >> 32) as u32;
        let kind = CompressedValueKind::from_bits(kind_and_flags & KIND_MASK)?;
        let domain = (kind_and_flags & ARENA_DOMAIN_MASK) >> ARENA_DOMAIN_SHIFT;
        let forced = kind_and_flags & COMPRESSED_FORCED_BIT != 0;
        if forced && kind != CompressedValueKind::Thunk {
            return Err(CompressedValueError::ForcedBitOnNonThunk { kind });
        }
        if kind.carries_arena_index() && ArenaDomainId::from_raw(domain).is_none() {
            return Err(CompressedValueError::MissingArenaDomain { kind });
        }
        if !kind.carries_arena_index() && domain != 0 {
            return Err(CompressedValueError::ArenaDomainOnInline { kind, domain });
        }
        let payload = raw as u32;
        match kind {
            CompressedValueKind::Bool if payload > 1 => {
                Err(CompressedValueError::InvalidBoolPayload { payload })
            }
            CompressedValueKind::Null if payload != 0 => {
                Err(CompressedValueError::InvalidNullPayload { payload })
            }
            _ => Ok(Self { raw }),
        }
    }

    /// Rebuilds a word whose Candidate-C invariants were already validated.
    ///
    /// # Safety
    ///
    /// `raw` must have been produced by a [`CompressedValueWord`] constructor
    /// or copied intact from one. In particular, its kind, forced bit, arena
    /// domain, and inline payload must satisfy the checks in [`Self::from_raw`].
    /// Violating this contract can reach otherwise-unreachable branches in
    /// later kind-specific accessors.
    #[inline]
    pub const unsafe fn from_raw_unchecked(raw: u64) -> Self {
        Self { raw }
    }

    /// Returns the complete encoded word.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.raw
    }

    /// Returns the representation kind with metadata flags removed.
    ///
    /// Inlined so that the common `kind() == Variant` comparison folds to a
    /// direct bit compare instead of materializing the full decode match: the
    /// word is validated at construction and by `from_raw`, so the `from_bits`
    /// branch is dead at every call site the optimizer can prove.
    #[inline]
    pub fn kind(self) -> CompressedValueKind {
        // Construction and `from_raw` validate this field.
        match CompressedValueKind::from_bits((self.raw >> 32) as u32 & KIND_MASK) {
            Ok(kind) => kind,
            Err(_) => unreachable!("validated compressed value kind"),
        }
    }

    /// Returns the semantic runtime tag.
    #[inline]
    pub fn semantic_tag(self) -> ValueTag {
        self.kind().semantic_tag()
    }

    /// Returns the low 32-bit payload.
    #[inline]
    pub const fn payload(self) -> u32 {
        self.raw as u32
    }

    /// Returns the inline signed integer, if present.
    #[inline]
    pub fn as_inline_int(self) -> Option<i64> {
        (self.kind() == CompressedValueKind::InlineInt).then(|| self.payload() as i32 as i64)
    }

    /// Returns the inline boolean, if present.
    #[inline]
    pub fn as_bool(self) -> Option<bool> {
        (self.kind() == CompressedValueKind::Bool).then(|| self.payload() != 0)
    }

    /// Returns the arena index carried by a heap or boxed-scalar word.
    #[inline]
    pub fn arena_index(self) -> Option<ArenaIndex> {
        self.kind()
            .carries_arena_index()
            .then(|| ArenaIndex::new(self.payload()))
    }

    /// Returns the reservation identity carried by an indexed word.
    pub fn arena_domain(self) -> Option<ArenaDomainId> {
        if !self.kind().carries_arena_index() {
            return None;
        }
        let high = (self.raw >> 32) as u32;
        ArenaDomainId::from_raw((high & ARENA_DOMAIN_MASK) >> ARENA_DOMAIN_SHIFT)
    }

    /// Returns whether this is a thunk word with the `FORCED` shortcut set.
    pub const fn is_forced_thunk(self) -> bool {
        let high = (self.raw >> 32) as u32;
        high & KIND_MASK == CompressedValueKind::Thunk as u32 && high & COMPRESSED_FORCED_BIT != 0
    }

    /// Returns the same thunk index with the `FORCED` shortcut set.
    ///
    /// # Errors
    ///
    /// Returns [`CompressedValueError::ForcedBitOnNonThunk`] for any other
    /// representation kind.
    pub fn with_forced_bit(self) -> Result<Self, CompressedValueError> {
        let kind = self.kind();
        if kind != CompressedValueKind::Thunk {
            return Err(CompressedValueError::ForcedBitOnNonThunk { kind });
        }
        Ok(Self {
            raw: self.raw | (u64::from(COMPRESSED_FORCED_BIT) << 32),
        })
    }

    const fn compose(kind: CompressedValueKind, payload: u32) -> Self {
        Self {
            raw: ((kind as u64) << 32) | payload as u64,
        }
    }

    const fn compose_indexed(
        kind: CompressedValueKind,
        domain: ArenaDomainId,
        index: ArenaIndex,
    ) -> Self {
        Self {
            raw: ((kind as u64 | ((domain.raw() as u64) << ARENA_DOMAIN_SHIFT)) << 32)
                | index.raw() as u64,
        }
    }
}

/// Hash-consed boxed scalar cells in one evaluator flat arena.
///
/// Candidate-C indexed words additionally carry the reservation's non-reusing
/// domain identity. Candidate B uses the same cells through checked native
/// addresses and therefore remains available on the chunked fallback.
#[derive(Debug)]
pub struct CandidateCScalarStore {
    arena: SharedFlatStoreArena,
    domain: Option<ArenaDomainId>,
    ints: FlatObjectStore<i64>,
    floats: FlatObjectStore<u64>,
    int_addresses: HashMap<i64, usize>,
    float_addresses: HashMap<u64, usize>,
}

impl CandidateCScalarStore {
    /// Creates a scalar store in `arena`.
    ///
    /// Candidate C requires a reservation domain, while Candidate B can use
    /// the same typed cells through their validated native addresses on either
    /// arena backend.
    pub fn new(arena: SharedFlatStoreArena) -> Self {
        let domain = arena.arena_domain_id();
        Self {
            ints: FlatObjectStore::with_shared_arena(
                arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::BoxedInt]),
            ),
            floats: FlatObjectStore::with_shared_arena(
                arena.clone(),
                FlatKindSet::of(&[FlatObjectKind::BoxedFloat]),
            ),
            arena,
            domain,
            int_addresses: HashMap::new(),
            float_addresses: HashMap::new(),
        }
    }

    /// Encodes an integer inline or returns its hash-consed boxed word.
    ///
    /// # Errors
    ///
    /// Returns an error if the flat allocation fails or its address cannot be
    /// represented by the store's reservation.
    pub fn encode_int(&mut self, value: i64) -> Result<CompressedValueWord, CandidateCScalarError> {
        let domain = self
            .domain
            .ok_or(CandidateCScalarError::ReservationUnavailable)?;
        match CompressedValueWord::inline_int(value) {
            Ok(word) => return Ok(word),
            Err(CompressedValueError::IntegerRequiresBox { .. }) => {}
            Err(source) => return Err(CandidateCScalarError::Codec(source)),
        }
        let ptr = self.box_int_pointer(value)?;
        let index = self.index_for_allocation(ptr)?;
        Ok(CompressedValueWord::boxed_int(domain, index))
    }

    /// Encodes a float as a hash-consed boxed word, preserving its raw bits.
    ///
    /// # Errors
    ///
    /// Returns an error if the flat allocation fails or its address cannot be
    /// represented by the store's reservation.
    pub fn encode_float(
        &mut self,
        value: f64,
    ) -> Result<CompressedValueWord, CandidateCScalarError> {
        let domain = self
            .domain
            .ok_or(CandidateCScalarError::ReservationUnavailable)?;
        let ptr = self.box_float_pointer(value)?;
        let index = self.index_for_allocation(ptr)?;
        Ok(CompressedValueWord::boxed_float(domain, index))
    }

    /// Decodes an inline or boxed integer word.
    ///
    /// # Errors
    ///
    /// Returns an error when `word` is not an integer, its index is not live,
    /// or the indexed object is not a boxed integer in this store.
    pub fn decode_int(&self, word: CompressedValueWord) -> Result<i64, CandidateCScalarError> {
        match word.kind() {
            CompressedValueKind::InlineInt => Ok(word.payload() as i32 as i64),
            CompressedValueKind::BoxedInt => {
                let ptr = self.pointer_for_word(word)?;
                self.decode_int_pointer(ptr)
                    .map_err(|error| candidate_c_pointer_error(error, "integer", word.payload()))
            }
            actual => Err(CandidateCScalarError::KindMismatch {
                expected: "integer",
                actual,
            }),
        }
    }

    /// Decodes a boxed float word without normalizing its bit pattern.
    ///
    /// # Errors
    ///
    /// Returns an error when `word` is not a float, its index is not live, or
    /// the indexed object is not a boxed float in this store.
    pub fn decode_float(&self, word: CompressedValueWord) -> Result<f64, CandidateCScalarError> {
        if word.kind() != CompressedValueKind::BoxedFloat {
            return Err(CandidateCScalarError::KindMismatch {
                expected: "float",
                actual: word.kind(),
            });
        }
        let ptr = self.pointer_for_word(word)?;
        self.decode_float_pointer(ptr)
            .map_err(|error| candidate_c_pointer_error(error, "float", word.payload()))
    }

    /// Returns the hash-consed boxed integer cell for `value`.
    pub fn box_int_pointer(
        &mut self,
        value: i64,
    ) -> Result<std::ptr::NonNull<crate::value::HeapObject>, CandidateCScalarError> {
        if let Some(address) = self.int_addresses.get(&value) {
            return pointer_from_exposed_address(*address, "integer");
        }
        let ptr = self
            .ints
            .alloc(FlatObjectKind::BoxedInt, value as u64, 0, value)?
            .ptr;
        self.int_addresses
            .insert(value, ptr.as_ptr().expose_provenance());
        Ok(ptr)
    }

    /// Returns the hash-consed boxed float cell for the exact bits of `value`.
    pub fn box_float_pointer(
        &mut self,
        value: f64,
    ) -> Result<std::ptr::NonNull<crate::value::HeapObject>, CandidateCScalarError> {
        let bits = value.to_bits();
        if let Some(address) = self.float_addresses.get(&bits) {
            return pointer_from_exposed_address(*address, "float");
        }
        let ptr = self
            .floats
            .alloc(FlatObjectKind::BoxedFloat, bits, 0, bits)?
            .ptr;
        self.float_addresses
            .insert(bits, ptr.as_ptr().expose_provenance());
        Ok(ptr)
    }

    /// Decodes a pointer owned by this store as a boxed integer.
    pub fn decode_int_pointer(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Result<i64, CandidateCScalarError> {
        self.ints
            .resolve(ptr, FlatObjectKind::BoxedInt)
            .map(|object| *object.payload())
            .map_err(CandidateCScalarError::Flat)
    }

    /// Decodes a pointer owned by this store as a boxed float.
    pub fn decode_float_pointer(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Result<f64, CandidateCScalarError> {
        self.floats
            .resolve(ptr, FlatObjectKind::BoxedFloat)
            .map(|object| f64::from_bits(*object.payload()))
            .map_err(CandidateCScalarError::Flat)
    }

    /// Returns the boxed scalar kind published at `ptr`, if any.
    pub fn kind_of_pointer(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Option<FlatObjectKind> {
        self.ints.kind_of(ptr).or_else(|| self.floats.kind_of(ptr))
    }

    /// Returns the number of distinct boxed integer cells.
    pub fn boxed_int_count(&self) -> usize {
        self.ints.len()
    }

    /// Returns the number of distinct boxed float bit patterns.
    pub fn boxed_float_count(&self) -> usize {
        self.floats.len()
    }

    /// Primes the typed cell stores' membership indexes for a scalar store
    /// constructed over a reloaded reservation (RFC-0007 doc 31 §1 heap-image
    /// restore).
    ///
    /// After this call [`CandidateCScalarStore::decode_int`] and
    /// [`CandidateCScalarStore::decode_float`] resolve boxed cells the restored
    /// image already holds; the hash-cons address maps stay empty because a
    /// restored store re-boxes fresh values rather than deduplicating against the
    /// image.
    #[cfg(feature = "candidate_c_value")]
    pub fn adopt_reloaded_regions(&mut self) {
        self.ints.adopt_shared_regions();
        self.floats.adopt_shared_regions();
    }

    /// Appends each boxed-scalar cell's `(base-relative offset, byte size)` to
    /// `regions`, relative to `base`.
    ///
    /// The heap-image capture completeness audit (RFC-0007 doc 31 §1 decision 6)
    /// marks these as known non-pointer data: a boxed `i64`/`f64` cell holds a
    /// scalar payload, not an arena interior pointer, so a dump word inside one
    /// that coincidentally falls in the reservation's address range must not be
    /// flagged as an uncovered witness.
    #[cfg(feature = "candidate_c_value")]
    pub fn append_cell_regions(&self, base: usize, regions: &mut Vec<(usize, usize)>) {
        for object in self.ints.iter() {
            regions.push((object.ptr().as_ptr() as usize - base, object.size_bytes()));
        }
        for object in self.floats.iter() {
            regions.push((object.ptr().as_ptr() as usize - base, object.size_bytes()));
        }
    }

    fn index_for_allocation(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Result<ArenaIndex, CandidateCScalarError> {
        self.arena
            .index_for_pointer(ptr)
            .ok_or(CandidateCScalarError::AddressOutsideReservation {
                address: ptr.as_ptr().expose_provenance(),
            })
    }

    fn pointer_for_word(
        &self,
        word: CompressedValueWord,
    ) -> Result<std::ptr::NonNull<crate::value::HeapObject>, CandidateCScalarError> {
        let actual_domain = word
            .arena_domain()
            .ok_or(CandidateCScalarError::KindMismatch {
                expected: "boxed scalar",
                actual: word.kind(),
            })?;
        let domain = self
            .domain
            .ok_or(CandidateCScalarError::ReservationUnavailable)?;
        if actual_domain != domain {
            return Err(CandidateCScalarError::ArenaDomainMismatch {
                expected: domain.raw(),
                actual: actual_domain.raw(),
            });
        }
        let index = word
            .arena_index()
            .ok_or(CandidateCScalarError::KindMismatch {
                expected: "boxed scalar",
                actual: word.kind(),
            })?;
        self.arena
            .pointer_for_index(index)
            .ok_or(CandidateCScalarError::IndexOutsideReservation { index: index.raw() })
    }
}

/// Thread-safe hash-consed boxed scalars in one shared evaluator arena.
///
/// Parallel evaluator workers share this store, so a scalar word published by
/// one worker resolves from every other worker. Candidate C uses the common
/// reservation domain when present; Candidate B also supports boxed-level
/// compatibility storage. Wide integers and exact float bit patterns serialize
/// only their first publication; inline integers never acquire a lock.
#[derive(Debug)]
pub struct SharedCandidateCScalarStore {
    arena: Option<Arc<ReservedArena>>,
    domain: Option<ArenaDomainId>,
    ints: SharedFlatObjectStore<i64>,
    floats: SharedFlatObjectStore<u64>,
    int_addresses: Mutex<HashMap<i64, usize>>,
    float_addresses: Mutex<HashMap<u64, usize>>,
}

impl SharedCandidateCScalarStore {
    /// Creates a shared scalar store in `arena`.
    ///
    /// `capacity` is rounded up independently for the integer and float typed
    /// stores. Both stores allocate from the same reservation and carry its
    /// domain in every published word.
    pub fn new(arena: Arc<ReservedArena>, capacity: usize) -> Self {
        let domain = arena.domain_id();
        Self {
            ints: SharedFlatObjectStore::with_reservation(
                Arc::clone(&arena),
                capacity,
                FlatKindSet::of(&[FlatObjectKind::BoxedInt]),
            ),
            floats: SharedFlatObjectStore::with_reservation(
                Arc::clone(&arena),
                capacity,
                FlatKindSet::of(&[FlatObjectKind::BoxedFloat]),
            ),
            arena: Some(arena),
            domain: Some(domain),
            int_addresses: Mutex::new(HashMap::new()),
            float_addresses: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a compatibility store backed by boxed geometric levels.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            arena: None,
            domain: None,
            ints: SharedFlatObjectStore::with_capacity(capacity),
            floats: SharedFlatObjectStore::with_capacity(capacity),
            int_addresses: Mutex::new(HashMap::new()),
            float_addresses: Mutex::new(HashMap::new()),
        }
    }

    /// Encodes an integer inline or returns its shared hash-consed boxed word.
    ///
    /// # Errors
    ///
    /// Returns an error if the hash-cons lock was poisoned, shared publication
    /// fails, or the allocation cannot be represented by the reservation.
    pub fn encode_int(&self, value: i64) -> Result<CompressedValueWord, CandidateCScalarError> {
        let domain = self
            .domain
            .ok_or(CandidateCScalarError::ReservationUnavailable)?;
        match CompressedValueWord::inline_int(value) {
            Ok(word) => return Ok(word),
            Err(CompressedValueError::IntegerRequiresBox { .. }) => {}
            Err(source) => return Err(CandidateCScalarError::Codec(source)),
        }
        let ptr = self.box_int_pointer(value)?;
        let index = self.index_for_allocation(ptr)?;
        Ok(CompressedValueWord::boxed_int(domain, index))
    }

    /// Encodes a float as a shared hash-consed boxed word with exact bits.
    ///
    /// # Errors
    ///
    /// Returns an error if the hash-cons lock was poisoned, shared publication
    /// fails, or the allocation cannot be represented by the reservation.
    pub fn encode_float(&self, value: f64) -> Result<CompressedValueWord, CandidateCScalarError> {
        let domain = self
            .domain
            .ok_or(CandidateCScalarError::ReservationUnavailable)?;
        let ptr = self.box_float_pointer(value)?;
        let index = self.index_for_allocation(ptr)?;
        Ok(CompressedValueWord::boxed_float(domain, index))
    }

    /// Decodes an inline or shared boxed integer word.
    ///
    /// # Errors
    ///
    /// Returns an error when `word` has the wrong kind or domain, its index is
    /// not live, or it does not name this store's boxed-integer population.
    pub fn decode_int(&self, word: CompressedValueWord) -> Result<i64, CandidateCScalarError> {
        match word.kind() {
            CompressedValueKind::InlineInt => Ok(word.payload() as i32 as i64),
            CompressedValueKind::BoxedInt => {
                let ptr = self.pointer_for_word(word)?;
                self.decode_int_pointer(ptr)
                    .map_err(|error| candidate_c_pointer_error(error, "integer", word.payload()))
            }
            actual => Err(CandidateCScalarError::KindMismatch {
                expected: "integer",
                actual,
            }),
        }
    }

    /// Decodes a shared boxed float word without normalizing its bits.
    ///
    /// # Errors
    ///
    /// Returns an error when `word` has the wrong kind or domain, its index is
    /// not live, or it does not name this store's boxed-float population.
    pub fn decode_float(&self, word: CompressedValueWord) -> Result<f64, CandidateCScalarError> {
        if word.kind() != CompressedValueKind::BoxedFloat {
            return Err(CandidateCScalarError::KindMismatch {
                expected: "float",
                actual: word.kind(),
            });
        }
        let ptr = self.pointer_for_word(word)?;
        self.decode_float_pointer(ptr)
            .map_err(|error| candidate_c_pointer_error(error, "float", word.payload()))
    }

    /// Returns the shared hash-consed boxed integer cell for `value`.
    pub fn box_int_pointer(
        &self,
        value: i64,
    ) -> Result<std::ptr::NonNull<crate::value::HeapObject>, CandidateCScalarError> {
        let mut addresses = self
            .int_addresses
            .lock()
            .map_err(|_| CandidateCScalarError::HashConsLockPoisoned { kind: "integer" })?;
        if let Some(address) = addresses.get(&value) {
            return pointer_from_exposed_address(*address, "integer");
        }
        let ptr = self.ints.publish(
            FlatObjectKind::BoxedInt,
            value as u64,
            std::mem::size_of::<i64>(),
            value,
        )?;
        addresses.insert(value, ptr.as_ptr().expose_provenance());
        Ok(ptr)
    }

    /// Returns the shared hash-consed boxed float cell for `value`'s raw bits.
    pub fn box_float_pointer(
        &self,
        value: f64,
    ) -> Result<std::ptr::NonNull<crate::value::HeapObject>, CandidateCScalarError> {
        let bits = value.to_bits();
        let mut addresses = self
            .float_addresses
            .lock()
            .map_err(|_| CandidateCScalarError::HashConsLockPoisoned { kind: "float" })?;
        if let Some(address) = addresses.get(&bits) {
            return pointer_from_exposed_address(*address, "float");
        }
        let ptr = self.floats.publish(
            FlatObjectKind::BoxedFloat,
            bits,
            std::mem::size_of::<u64>(),
            bits,
        )?;
        addresses.insert(bits, ptr.as_ptr().expose_provenance());
        Ok(ptr)
    }

    /// Decodes a pointer owned by this shared store as a boxed integer.
    pub fn decode_int_pointer(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Result<i64, CandidateCScalarError> {
        self.ints
            .resolve(ptr, FlatObjectKind::BoxedInt)
            .map(|object| *object.payload())
            .ok_or(CandidateCScalarError::PointerCellNotFound {
                kind: "integer",
                address: ptr.as_ptr().expose_provenance(),
            })
    }

    /// Decodes a pointer owned by this shared store as a boxed float.
    pub fn decode_float_pointer(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Result<f64, CandidateCScalarError> {
        self.floats
            .resolve(ptr, FlatObjectKind::BoxedFloat)
            .map(|object| f64::from_bits(*object.payload()))
            .ok_or(CandidateCScalarError::PointerCellNotFound {
                kind: "float",
                address: ptr.as_ptr().expose_provenance(),
            })
    }

    /// Returns the boxed scalar kind published at `ptr`, if any.
    pub fn kind_of_pointer(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Option<FlatObjectKind> {
        self.ints
            .resolve_any(ptr)
            .and_then(|object| object.kind())
            .or_else(|| {
                self.floats
                    .resolve_any(ptr)
                    .and_then(|object| object.kind())
            })
    }

    /// Returns the total number of distinct boxed scalar cells.
    pub fn len(&self) -> usize {
        self.ints.len().saturating_add(self.floats.len())
    }

    /// Returns whether no boxed scalar cell has been published.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the approximate published scalar payload bytes.
    pub fn payload_bytes(&self) -> usize {
        self.ints
            .payload_bytes()
            .saturating_add(self.floats.payload_bytes())
    }

    fn index_for_allocation(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Result<ArenaIndex, CandidateCScalarError> {
        self.arena
            .as_ref()
            .ok_or(CandidateCScalarError::ReservationUnavailable)?
            .index_for_pointer(ptr)
            .map_err(|_| CandidateCScalarError::AddressOutsideReservation {
                address: ptr.as_ptr().expose_provenance(),
            })
    }

    fn pointer_for_word(
        &self,
        word: CompressedValueWord,
    ) -> Result<std::ptr::NonNull<crate::value::HeapObject>, CandidateCScalarError> {
        let actual_domain = word
            .arena_domain()
            .ok_or(CandidateCScalarError::KindMismatch {
                expected: "boxed scalar",
                actual: word.kind(),
            })?;
        let domain = self
            .domain
            .ok_or(CandidateCScalarError::ReservationUnavailable)?;
        if actual_domain != domain {
            return Err(CandidateCScalarError::ArenaDomainMismatch {
                expected: domain.raw(),
                actual: actual_domain.raw(),
            });
        }
        let index = word
            .arena_index()
            .ok_or(CandidateCScalarError::KindMismatch {
                expected: "boxed scalar",
                actual: word.kind(),
            })?;
        self.arena
            .as_ref()
            .ok_or(CandidateCScalarError::ReservationUnavailable)?
            .pointer_for_index(index)
            .map_err(|_| CandidateCScalarError::IndexOutsideReservation { index: index.raw() })
    }
}

#[path = "compressed/errors.rs"]
mod errors;
pub use errors::*;

#[cfg(test)]
#[path = "compressed/shared_tests.rs"]
mod shared_tests;

#[cfg(test)]
#[path = "compressed/tests.rs"]
mod tests;
