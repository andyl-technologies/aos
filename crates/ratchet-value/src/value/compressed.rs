//! Candidate-C compressed runtime value words.
//!
//! RFC-0007 doc 30 section 3 assigns Candidate C one 64-bit word split into a
//! 32-bit kind/metadata half and a 32-bit payload half. Heap payloads are
//! offsets in one [`ReservedArena`](crate::heap::ReservedArena), not pointer
//! bits. Signed 32-bit integers remain immediate; wider integers and every
//! float use typed boxed-scalar indices. Bit 31 of the kind half is the thunk
//! `FORCED` shortcut.
//!
//! [`CandidateCScalarStore`] supplies the matching hash-consed reservation
//! cells for wide integers and floats. The active evaluator still uses
//! [`Value`](super::Value); switching the runtime and JIT ABI is a later,
//! separately gated step.

use std::collections::HashMap;

use thiserror::Error;

use crate::heap::flat::{
    FlatKindSet, FlatObjectError, FlatObjectKind, FlatObjectStore, SharedFlatStoreArena,
};
use crate::heap::{ArenaDomainId, ArenaIndex};

use super::ValueTag;

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

    /// Returns the complete encoded word.
    pub const fn raw(self) -> u64 {
        self.raw
    }

    /// Returns the representation kind with metadata flags removed.
    pub fn kind(self) -> CompressedValueKind {
        // Construction and `from_raw` validate this field.
        match CompressedValueKind::from_bits((self.raw >> 32) as u32 & KIND_MASK) {
            Ok(kind) => kind,
            Err(_) => unreachable!("validated compressed value kind"),
        }
    }

    /// Returns the semantic runtime tag.
    pub fn semantic_tag(self) -> ValueTag {
        self.kind().semantic_tag()
    }

    /// Returns the low 32-bit payload.
    pub const fn payload(self) -> u32 {
        self.raw as u32
    }

    /// Returns the inline signed integer, if present.
    pub fn as_inline_int(self) -> Option<i64> {
        (self.kind() == CompressedValueKind::InlineInt).then(|| self.payload() as i32 as i64)
    }

    /// Returns the inline boolean, if present.
    pub fn as_bool(self) -> Option<bool> {
        (self.kind() == CompressedValueKind::Bool).then(|| self.payload() != 0)
    }

    /// Returns the arena index carried by a heap or boxed-scalar word.
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

/// Hash-consed boxed scalar cells in one Candidate-C reservation.
///
/// Every indexed word carries the reservation's non-reusing domain identity;
/// decoding rejects a word from another simultaneously live heap before
/// reconstructing its pointer.
#[derive(Debug)]
pub struct CandidateCScalarStore {
    arena: SharedFlatStoreArena,
    domain: ArenaDomainId,
    ints: FlatObjectStore<i64>,
    floats: FlatObjectStore<u64>,
    int_words: HashMap<i64, CompressedValueWord>,
    float_words: HashMap<u64, CompressedValueWord>,
}

impl CandidateCScalarStore {
    /// Creates a scalar store in `arena` when its reservation backend is active.
    pub fn new(arena: SharedFlatStoreArena) -> Option<Self> {
        let domain = arena.arena_domain_id()?;
        Some(Self {
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
            int_words: HashMap::new(),
            float_words: HashMap::new(),
        })
    }

    /// Encodes an integer inline or returns its hash-consed boxed word.
    ///
    /// # Errors
    ///
    /// Returns an error if the flat allocation fails or its address cannot be
    /// represented by the store's reservation.
    pub fn encode_int(&mut self, value: i64) -> Result<CompressedValueWord, CandidateCScalarError> {
        match CompressedValueWord::inline_int(value) {
            Ok(word) => return Ok(word),
            Err(CompressedValueError::IntegerRequiresBox { .. }) => {}
            Err(source) => return Err(CandidateCScalarError::Codec(source)),
        }
        if let Some(word) = self.int_words.get(&value) {
            return Ok(*word);
        }
        let allocation = self
            .ints
            .alloc(FlatObjectKind::BoxedInt, value as u64, 0, value)?;
        let index = self.index_for_allocation(allocation.ptr)?;
        let word = CompressedValueWord::boxed_int(self.domain, index);
        self.int_words.insert(value, word);
        Ok(word)
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
        let bits = value.to_bits();
        if let Some(word) = self.float_words.get(&bits) {
            return Ok(*word);
        }
        let allocation = self
            .floats
            .alloc(FlatObjectKind::BoxedFloat, bits, 0, bits)?;
        let index = self.index_for_allocation(allocation.ptr)?;
        let word = CompressedValueWord::boxed_float(self.domain, index);
        self.float_words.insert(bits, word);
        Ok(word)
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
                Ok(*self.ints.resolve(ptr, FlatObjectKind::BoxedInt)?.payload())
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
        let bits = *self
            .floats
            .resolve(ptr, FlatObjectKind::BoxedFloat)?
            .payload();
        Ok(f64::from_bits(bits))
    }

    /// Returns the number of distinct boxed integer cells.
    pub fn boxed_int_count(&self) -> usize {
        self.ints.len()
    }

    /// Returns the number of distinct boxed float bit patterns.
    pub fn boxed_float_count(&self) -> usize {
        self.floats.len()
    }

    fn index_for_allocation(
        &self,
        ptr: std::ptr::NonNull<crate::value::HeapObject>,
    ) -> Result<ArenaIndex, CandidateCScalarError> {
        self.arena
            .index_for_pointer(ptr)
            .ok_or(CandidateCScalarError::AddressOutsideReservation {
                address: ptr.as_ptr() as usize,
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
        if actual_domain != self.domain {
            return Err(CandidateCScalarError::ArenaDomainMismatch {
                expected: self.domain.raw(),
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

/// A Candidate-C boxed scalar could not be stored or decoded.
#[derive(Debug, Error)]
pub enum CandidateCScalarError {
    /// The codec rejected a requested scalar encoding.
    #[error(transparent)]
    Codec(#[from] CompressedValueError),
    /// The flat store could not allocate or resolve the scalar cell.
    #[error(transparent)]
    Flat(#[from] FlatObjectError),
    /// Candidate C was requested without a reservation backend.
    #[error("Candidate-C scalar storage requires a reservation-backed arena")]
    ReservationUnavailable,
    /// A fresh scalar allocation did not belong to the expected reservation.
    #[error("scalar allocation 0x{address:x} is outside the Candidate-C reservation")]
    AddressOutsideReservation {
        /// The rejected native address.
        address: usize,
    },
    /// A scalar word named an index outside the reservation's live lanes.
    #[error("scalar index {index} is outside the Candidate-C reservation's live lanes")]
    IndexOutsideReservation {
        /// The rejected compressed offset.
        index: u32,
    },
    /// A scalar decoder received the wrong representation kind.
    #[error("expected a compressed {expected}, found {actual:?}")]
    KindMismatch {
        /// The requested semantic scalar type.
        expected: &'static str,
        /// The observed representation kind.
        actual: CompressedValueKind,
    },
    /// A scalar word belonged to another live reservation.
    #[error("compressed scalar arena domain {actual} does not match expected domain {expected}")]
    ArenaDomainMismatch {
        /// The receiving scalar store's domain.
        expected: u32,
        /// The word's encoded domain.
        actual: u32,
    },
}

/// A Candidate-C value could not be encoded or decoded.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CompressedValueError {
    /// A raw kind value has no assigned representation.
    #[error("unknown compressed value kind 0x{kind:08x}")]
    UnknownKind {
        /// The rejected kind bits, without the forced flag.
        kind: u32,
    },
    /// A 64-bit integer needs a boxed arena cell.
    #[error("integer {value} does not fit the Candidate-C 32-bit immediate range")]
    IntegerRequiresBox {
        /// The integer that requires boxing.
        value: i64,
    },
    /// A scalar tag was passed to the typed heap-index constructor.
    #[error("runtime tag {tag:?} is not a heap-index kind")]
    NonHeapTag {
        /// The rejected runtime tag.
        tag: ValueTag,
    },
    /// An indexed word omitted its nonzero reservation domain.
    #[error("compressed indexed kind {kind:?} has no arena domain")]
    MissingArenaDomain {
        /// The indexed representation kind.
        kind: CompressedValueKind,
    },
    /// An inline word carried reservation-domain metadata.
    #[error("compressed inline kind {kind:?} carries arena domain {domain}")]
    ArenaDomainOnInline {
        /// The inline representation kind.
        kind: CompressedValueKind,
        /// The rejected metadata.
        domain: u32,
    },
    /// The forced shortcut appeared on a value other than a thunk.
    #[error("compressed forced bit is invalid on {kind:?}")]
    ForcedBitOnNonThunk {
        /// The decoded non-thunk kind.
        kind: CompressedValueKind,
    },
    /// A boolean payload was not zero or one.
    #[error("compressed boolean payload is {payload}, expected zero or one")]
    InvalidBoolPayload {
        /// The rejected payload.
        payload: u32,
    },
    /// A null payload was not zero.
    #[error("compressed null payload is {payload}, expected zero")]
    InvalidNullPayload {
        /// The rejected payload.
        payload: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_word_is_exactly_one_machine_word() {
        assert_eq!(std::mem::size_of::<CompressedValueWord>(), 8);
        assert_eq!(std::mem::align_of::<CompressedValueWord>(), 8);
    }

    #[test]
    fn scalar_encodings_roundtrip_and_large_integers_require_boxes() {
        let negative =
            CompressedValueWord::inline_int(i64::from(i32::MIN)).expect("i32 minimum is inline");
        assert_eq!(negative.as_inline_int(), Some(i64::from(i32::MIN)));
        assert_eq!(CompressedValueWord::boolean(true).as_bool(), Some(true));
        assert_eq!(CompressedValueWord::null().semantic_tag(), ValueTag::Null);
        assert_eq!(
            CompressedValueWord::inline_int(i64::from(i32::MAX) + 1),
            Err(CompressedValueError::IntegerRequiresBox {
                value: i64::from(i32::MAX) + 1
            })
        );
    }

    #[test]
    fn typed_indices_and_forced_thunk_bits_roundtrip() {
        let arena = SharedFlatStoreArena::new();
        let domain = arena.arena_domain_id().expect("reservation has a domain");
        let index = ArenaIndex::new(0xfeed_beef);
        let list =
            CompressedValueWord::heap(domain, ValueTag::List, index).expect("list is heap-backed");
        assert_eq!(list.arena_index(), Some(index));
        assert_eq!(list.arena_domain(), Some(domain));
        assert_eq!(list.semantic_tag(), ValueTag::List);

        let thunk = CompressedValueWord::heap(domain, ValueTag::Thunk, index)
            .expect("thunk is heap-backed")
            .with_forced_bit()
            .expect("thunk accepts forced bit");
        assert!(thunk.is_forced_thunk());
        assert_eq!(CompressedValueWord::from_raw(thunk.raw()), Ok(thunk));
        assert_eq!(thunk.arena_index(), Some(index));
    }

    #[test]
    fn scalar_store_rejects_an_equal_offset_from_another_arena_domain() {
        let mut left = CandidateCScalarStore::new(SharedFlatStoreArena::new())
            .expect("left reservation is available");
        let right = CandidateCScalarStore::new(SharedFlatStoreArena::new())
            .expect("right reservation is available");
        let word = left.encode_int(i64::MAX).expect("wide integer boxes");

        assert!(matches!(
            right.decode_int(word),
            Err(CandidateCScalarError::ArenaDomainMismatch { .. })
        ));
    }

    #[test]
    fn scalar_store_inlines_i32_and_hash_conses_boxed_values() {
        let arena = SharedFlatStoreArena::new();
        let mut store =
            CandidateCScalarStore::new(arena.clone()).expect("production arena uses a reservation");

        let inline = store.encode_int(-7).expect("small integer encodes");
        assert_eq!(store.decode_int(inline).expect("small integer decodes"), -7);
        assert_eq!(store.boxed_int_count(), 0);

        let wide_value = i64::from(i32::MAX) + 1;
        let wide = store.encode_int(wide_value).expect("wide integer boxes");
        assert_eq!(
            store.encode_int(wide_value).expect("wide integer reuses"),
            wide
        );
        assert_eq!(
            store.decode_int(wide).expect("wide integer decodes"),
            wide_value
        );
        assert_eq!(store.boxed_int_count(), 1);

        let nan_bits = 0x7ff8_0000_0000_0042;
        let float = store
            .encode_float(f64::from_bits(nan_bits))
            .expect("float boxes");
        assert_eq!(
            store
                .encode_float(f64::from_bits(nan_bits))
                .expect("float reuses"),
            float
        );
        assert_eq!(
            store.decode_float(float).expect("float decodes").to_bits(),
            nan_bits
        );
        assert_eq!(store.boxed_float_count(), 1);
        assert_eq!(
            arena.permanent_stats().used_bytes,
            arena
                .reservation_stats()
                .expect("reservation stats")
                .low_used_bytes
        );
    }

    #[test]
    fn raw_decoder_rejects_invalid_metadata() {
        let forced_bool = (u64::from(COMPRESSED_FORCED_BIT | 0x02) << 32) | 1;
        assert_eq!(
            CompressedValueWord::from_raw(forced_bool),
            Err(CompressedValueError::ForcedBitOnNonThunk {
                kind: CompressedValueKind::Bool
            })
        );
        assert_eq!(
            CompressedValueWord::from_raw((0x02_u64 << 32) | 7),
            Err(CompressedValueError::InvalidBoolPayload { payload: 7 })
        );
        assert_eq!(
            CompressedValueWord::from_raw((0x03_u64 << 32) | 1),
            Err(CompressedValueError::InvalidNullPayload { payload: 1 })
        );
        assert_eq!(
            CompressedValueWord::from_raw((0x12_u64 << 32) | 8),
            Err(CompressedValueError::MissingArenaDomain {
                kind: CompressedValueKind::List
            })
        );
        assert_eq!(
            CompressedValueWord::from_raw(((0x102_u64) << 32) | 1),
            Err(CompressedValueError::ArenaDomainOnInline {
                kind: CompressedValueKind::Bool,
                domain: 1
            })
        );
    }
}
