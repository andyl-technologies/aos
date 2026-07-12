//! Safe pointer-tagging layout helpers for future heap fast paths.
//!
//! The active [`super::Value`] representation still stores heap pointers in the
//! payload word and keeps the value form in a separate tag word. This module
//! captures the low-bit contract needed by the later pointer-tagged variant:
//! heap objects are 8-byte aligned, so the low three pointer bits are available
//! for evaluator metadata. Bit 0 is reserved as the thunk `FORCED` shortcut.
//!
//! These helpers do not dereference pointers, do not prove pointer liveness, and
//! do not change runtime value semantics. Raw tagged words preserve address bits
//! only; callers that need provenance-bearing pointers must keep the original
//! pointer through a separate typed handle.

use std::ptr::NonNull;

use thiserror::Error;

use super::HeapObject;

mod bridge;

pub use bridge::CandidateBValueError;

/// Required heap-object pointer alignment in bytes.
pub const HEAP_POINTER_ALIGNMENT: usize = 8;
/// Number of low pointer bits reserved for pointer tags.
pub const POINTER_TAG_BITS: u32 = 3;
/// Mask selecting the low pointer tag bits.
pub const POINTER_TAG_MASK: usize = HEAP_POINTER_ALIGNMENT - 1;
/// Mask selecting the aligned heap address bits.
pub const POINTER_ADDRESS_MASK: usize = !POINTER_TAG_MASK;
/// The low-bit shortcut marking a thunk pointer whose cell is already forced.
pub const FORCED_BIT: usize = 0b001;
/// Smallest signed integer representable by the Candidate-B immediate payload.
pub const TAGGED_IMMEDIATE_INT_MIN: i64 = -(1_i64 << 60);
/// Largest signed integer representable by the Candidate-B immediate payload.
pub const TAGGED_IMMEDIATE_INT_MAX: i64 = (1_i64 << 60) - 1;

const TAGGED_VALUE_TAG_MASK: u64 = POINTER_TAG_MASK as u64;
const TAGGED_VALUE_HEAP: u64 = 0b000;
const TAGGED_VALUE_FORCED_THUNK: u64 = 0b001;
const TAGGED_VALUE_INT: u64 = 0b010;
const TAGGED_VALUE_FALSE: u64 = 0b011;
const TAGGED_VALUE_TRUE: u64 = 0b100;
const TAGGED_VALUE_NULL: u64 = 0b101;

const _: () = assert!(HEAP_POINTER_ALIGNMENT == 1 << POINTER_TAG_BITS);
const _: () = assert!(POINTER_TAG_MASK == 0b111);

/// A checked low-bit tag that can be packed into a heap pointer address word.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PointerTag {
    bits: u8,
}

impl PointerTag {
    /// An empty pointer tag.
    pub const EMPTY: Self = Self { bits: 0 };
    /// The thunk `FORCED` shortcut tag.
    pub const FORCED: Self = Self {
        bits: FORCED_BIT as u8,
    };

    /// Creates a pointer tag from raw low-bit metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PointerTagError::TagOutOfRange`] when `bits` uses any bit
    /// outside the reserved low three pointer bits.
    pub const fn new(bits: u8) -> Result<Self, PointerTagError> {
        if (bits as usize) & !POINTER_TAG_MASK == 0 {
            Ok(Self { bits })
        } else {
            Err(PointerTagError::TagOutOfRange { bits })
        }
    }

    /// Returns the raw low-bit tag payload.
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// Returns whether this tag has no metadata bits set.
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Returns whether this tag carries bit 0, reserved for thunk `FORCED`.
    ///
    /// This is a mechanical bit test. It is semantically meaningful only after
    /// the enclosing value has been proven to be a thunk pointer.
    pub const fn has_forced_bit(self) -> bool {
        self.bits as usize & FORCED_BIT != 0
    }

    /// Returns this tag with bit 0, reserved for thunk `FORCED`, set.
    pub const fn with_forced_bit(self) -> Self {
        Self {
            bits: self.bits | FORCED_BIT as u8,
        }
    }
}

/// A heap address word packed with low-bit evaluator metadata.
///
/// This type intentionally stores address bits rather than a
/// provenance-bearing pointer. Decoding a raw word proves only that the aligned
/// address portion is non-null; it does not prove that the address belongs to a
/// live heap allocation or can be dereferenced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TaggedHeapAddress {
    raw: usize,
}

impl TaggedHeapAddress {
    /// Packs an aligned heap pointer's address and a checked low-bit tag.
    ///
    /// # Errors
    ///
    /// Returns [`PointerTagError::UnalignedHeapPointer`] when `ptr` does not
    /// satisfy the heap-object alignment contract.
    pub fn from_pointer(
        ptr: NonNull<HeapObject>,
        tag: PointerTag,
    ) -> Result<Self, PointerTagError> {
        let address = ptr.as_ptr().expose_provenance();
        validate_aligned_address(address)?;
        Ok(Self {
            raw: address | tag.bits as usize,
        })
    }

    /// Decodes a raw tagged address word.
    ///
    /// # Errors
    ///
    /// Returns [`PointerTagError::NullHeapPointer`] when the decoded address is
    /// null.
    pub fn from_raw_address(raw: usize) -> Result<Self, PointerTagError> {
        let address = raw & POINTER_ADDRESS_MASK;
        if address == 0 {
            return Err(PointerTagError::NullHeapPointer);
        }
        Ok(Self { raw })
    }

    /// Returns the raw tagged address word.
    pub const fn raw_bits(self) -> usize {
        self.raw
    }

    /// Returns the aligned heap address bits with metadata removed.
    pub const fn address_bits(self) -> usize {
        self.raw & POINTER_ADDRESS_MASK
    }

    /// Returns the low-bit pointer tag.
    pub const fn tag(self) -> PointerTag {
        PointerTag {
            bits: (self.raw & POINTER_TAG_MASK) as u8,
        }
    }

    /// Returns whether this word carries bit 0, reserved for thunk `FORCED`.
    ///
    /// This is a mechanical bit test. It is semantically meaningful only after
    /// the enclosing value has been proven to be a thunk pointer.
    pub const fn has_forced_bit(self) -> bool {
        self.tag().has_forced_bit()
    }

    /// Returns a copy of this address word with a different low-bit tag.
    pub const fn with_tag(self, tag: PointerTag) -> Self {
        Self {
            raw: self.address_bits() | tag.bits as usize,
        }
    }

    /// Returns a copy of this address word with bit 0, reserved for thunk
    /// `FORCED`, set.
    pub const fn with_forced_bit(self) -> Self {
        self.with_tag(self.tag().with_forced_bit())
    }

    /// Returns whether `ptr` has the same address bits as this tagged word.
    pub fn address_matches(self, ptr: NonNull<HeapObject>) -> bool {
        self.address_bits() == ptr.as_ptr().expose_provenance()
    }
}

/// The representation class carried by a validated Candidate-B value word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaggedValueKind {
    /// An aligned heap pointer whose semantic kind lives in the object header.
    Heap,
    /// A heap thunk pointer carrying the low-bit forced shortcut.
    ForcedThunk,
    /// A signed 61-bit immediate integer.
    InlineInt,
    /// An immediate boolean singleton.
    Bool,
    /// The immediate null singleton.
    Null,
}

/// A checked Candidate-B one-word value.
///
/// The low three bits select immediate integers and singleton values or mark a
/// heap pointer. Heap semantic kinds remain in the flat-object header, so
/// decoding a heap word proves address shape only; the evaluator must still
/// validate ownership, liveness, and the expected object kind before use.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TaggedValueWord {
    raw: u64,
}

impl TaggedValueWord {
    /// Encodes a signed 61-bit immediate integer.
    ///
    /// # Errors
    ///
    /// Returns [`TaggedValueWordError::IntegerOutOfRange`] when `value` needs
    /// the Candidate-B boxed-`i64` fallback.
    pub const fn inline_int(value: i64) -> Result<Self, TaggedValueWordError> {
        if value < TAGGED_IMMEDIATE_INT_MIN || value > TAGGED_IMMEDIATE_INT_MAX {
            return Err(TaggedValueWordError::IntegerOutOfRange { value });
        }
        Ok(Self {
            raw: ((value as u64) << POINTER_TAG_BITS) | TAGGED_VALUE_INT,
        })
    }

    /// Encodes an immediate boolean singleton.
    pub const fn boolean(value: bool) -> Self {
        Self {
            raw: if value {
                TAGGED_VALUE_TRUE
            } else {
                TAGGED_VALUE_FALSE
            },
        }
    }

    /// Encodes the immediate null singleton.
    pub const fn null() -> Self {
        Self {
            raw: TAGGED_VALUE_NULL,
        }
    }

    /// Encodes an aligned heap pointer without the forced-thunk shortcut.
    ///
    /// # Errors
    ///
    /// Returns [`TaggedValueWordError::Pointer`] for an unaligned pointer, or
    /// [`TaggedValueWordError::AddressOutOfRange`] when its address does not fit
    /// this 64-bit word.
    pub fn heap(ptr: NonNull<HeapObject>) -> Result<Self, TaggedValueWordError> {
        let address = TaggedHeapAddress::from_pointer(ptr, PointerTag::EMPTY)?;
        Self::from_tagged_heap_address(address)
    }

    /// Encodes an aligned thunk pointer with the forced shortcut set.
    ///
    /// The caller must establish that `ptr` names a thunk. The word layout does
    /// not dereference the pointer or inspect its flat-object header.
    ///
    /// # Errors
    ///
    /// Returns [`TaggedValueWordError::Pointer`] for an unaligned pointer, or
    /// [`TaggedValueWordError::AddressOutOfRange`] when its address does not fit
    /// this 64-bit word.
    pub fn forced_thunk(ptr: NonNull<HeapObject>) -> Result<Self, TaggedValueWordError> {
        let address = TaggedHeapAddress::from_pointer(ptr, PointerTag::FORCED)?;
        Self::from_tagged_heap_address(address)
    }

    /// Validates a raw Candidate-B word.
    ///
    /// Heap words are checked only for a non-null address of the required
    /// alignment. Ownership, liveness, and semantic object kind remain
    /// evaluator responsibilities.
    ///
    /// # Errors
    ///
    /// Returns an error for null heap addresses, reserved low tags, singleton
    /// tags carrying payload bits, or addresses wider than the host pointer.
    pub fn from_raw(raw: u64) -> Result<Self, TaggedValueWordError> {
        tagged_value_kind(raw)?;
        Ok(Self { raw })
    }

    /// Returns the validated representation class.
    ///
    /// # Errors
    ///
    /// Returns an error only if the private word invariant was violated by
    /// memory corruption.
    pub fn kind(self) -> Result<TaggedValueKind, TaggedValueWordError> {
        tagged_value_kind(self.raw)
    }

    /// Returns the decoded immediate integer, if this is an integer word.
    pub const fn as_inline_int(self) -> Option<i64> {
        if self.raw & TAGGED_VALUE_TAG_MASK == TAGGED_VALUE_INT {
            Some((self.raw as i64) >> POINTER_TAG_BITS)
        } else {
            None
        }
    }

    /// Returns the decoded boolean, if this is a boolean singleton.
    pub const fn as_bool(self) -> Option<bool> {
        match self.raw {
            TAGGED_VALUE_FALSE => Some(false),
            TAGGED_VALUE_TRUE => Some(true),
            _ => None,
        }
    }

    /// Returns whether this is the null singleton.
    pub const fn is_null(self) -> bool {
        self.raw == TAGGED_VALUE_NULL
    }

    /// Returns the checked tagged heap address, if this is a heap word.
    ///
    /// # Errors
    ///
    /// Returns an address validation error only if the private word invariant
    /// was violated by memory corruption.
    pub fn heap_address(self) -> Result<Option<TaggedHeapAddress>, TaggedValueWordError> {
        match self.raw & TAGGED_VALUE_TAG_MASK {
            TAGGED_VALUE_HEAP | TAGGED_VALUE_FORCED_THUNK => {
                let raw = usize::try_from(self.raw)
                    .map_err(|_| TaggedValueWordError::AddressTooWide { raw: self.raw })?;
                Ok(Some(TaggedHeapAddress::from_raw_address(raw)?))
            }
            _ => Ok(None),
        }
    }

    /// Returns whether this word is a heap pointer with the forced shortcut.
    pub const fn is_forced_thunk(self) -> bool {
        self.raw & TAGGED_VALUE_TAG_MASK == TAGGED_VALUE_FORCED_THUNK
    }

    /// Returns the raw 64-bit word.
    pub const fn raw_bits(self) -> u64 {
        self.raw
    }

    fn from_tagged_heap_address(address: TaggedHeapAddress) -> Result<Self, TaggedValueWordError> {
        let raw = u64::try_from(address.raw_bits()).map_err(|_| {
            TaggedValueWordError::AddressOutOfRange {
                address: address.raw_bits(),
            }
        })?;
        Ok(Self { raw })
    }
}

const _: () = assert!(std::mem::size_of::<TaggedValueWord>() == 8);

fn tagged_value_kind(raw: u64) -> Result<TaggedValueKind, TaggedValueWordError> {
    match raw & TAGGED_VALUE_TAG_MASK {
        TAGGED_VALUE_HEAP => {
            validate_tagged_value_address(raw)?;
            Ok(TaggedValueKind::Heap)
        }
        TAGGED_VALUE_FORCED_THUNK => {
            validate_tagged_value_address(raw)?;
            Ok(TaggedValueKind::ForcedThunk)
        }
        TAGGED_VALUE_INT => Ok(TaggedValueKind::InlineInt),
        TAGGED_VALUE_FALSE => validate_singleton(raw, TaggedValueKind::Bool),
        TAGGED_VALUE_TRUE => validate_singleton(raw, TaggedValueKind::Bool),
        TAGGED_VALUE_NULL => validate_singleton(raw, TaggedValueKind::Null),
        tag => Err(TaggedValueWordError::ReservedTag { tag: tag as u8 }),
    }
}

fn validate_tagged_value_address(raw: u64) -> Result<(), TaggedValueWordError> {
    let raw = usize::try_from(raw).map_err(|_| TaggedValueWordError::AddressTooWide { raw })?;
    TaggedHeapAddress::from_raw_address(raw)?;
    Ok(())
}

fn validate_singleton(
    raw: u64,
    kind: TaggedValueKind,
) -> Result<TaggedValueKind, TaggedValueWordError> {
    if raw <= TAGGED_VALUE_NULL {
        Ok(kind)
    } else {
        Err(TaggedValueWordError::SingletonPayload { kind, raw })
    }
}

/// A failed Candidate-B value-word encoding or decoding operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TaggedValueWordError {
    /// A signed integer does not fit the 61-bit immediate payload.
    #[error("integer {value} does not fit the signed 61-bit tagged payload")]
    IntegerOutOfRange {
        /// The rejected integer.
        value: i64,
    },
    /// A pointer address cannot be represented by a 64-bit word.
    #[error("heap address 0x{address:x} does not fit a 64-bit tagged word")]
    AddressOutOfRange {
        /// The rejected native address.
        address: usize,
    },
    /// A raw word cannot be represented by the host pointer width.
    #[error("tagged heap word 0x{raw:016x} exceeds the host pointer width")]
    AddressTooWide {
        /// The rejected raw word.
        raw: u64,
    },
    /// A singleton tag carried nonzero payload bits.
    #[error("tagged {kind:?} singleton carries payload bits: 0x{raw:016x}")]
    SingletonPayload {
        /// The singleton representation class.
        kind: TaggedValueKind,
        /// The rejected raw word.
        raw: u64,
    },
    /// The raw low tag is reserved.
    #[error("tagged value uses reserved low tag 0b{tag:03b}")]
    ReservedTag {
        /// The rejected low three bits.
        tag: u8,
    },
    /// The heap-address portion is null or insufficiently aligned.
    #[error(transparent)]
    Pointer(#[from] PointerTagError),
}

/// A failed pointer-tag encoding or decoding operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PointerTagError {
    /// A tag used bits outside the low three pointer bits.
    #[error("pointer tag uses bits outside the low three bits: 0b{bits:08b}")]
    TagOutOfRange {
        /// The rejected raw tag bits.
        bits: u8,
    },
    /// A decoded tagged address word carried a null address.
    #[error("tagged heap address is null")]
    NullHeapPointer,
    /// A heap pointer address was not aligned enough to reserve low tag bits.
    #[error(
        "heap pointer address is not {HEAP_POINTER_ALIGNMENT}-byte aligned for pointer tagging: 0x{address:x}"
    )]
    UnalignedHeapPointer {
        /// The rejected address.
        address: usize,
    },
}

fn validate_aligned_address(address: usize) -> Result<(), PointerTagError> {
    if address & POINTER_TAG_MASK == 0 {
        Ok(())
    } else {
        Err(PointerTagError::UnalignedHeapPointer { address })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_tag_layout_reserves_low_three_bits() {
        assert_eq!(HEAP_POINTER_ALIGNMENT, 8);
        assert_eq!(POINTER_TAG_BITS, 3);
        assert_eq!(POINTER_TAG_MASK, 0b111);
        assert_eq!(POINTER_ADDRESS_MASK & POINTER_TAG_MASK, 0);
        assert_eq!(FORCED_BIT, 0b001);
    }

    #[test]
    fn pointer_tags_reject_out_of_range_bits() {
        assert_eq!(
            PointerTag::new(0b1000),
            Err(PointerTagError::TagOutOfRange { bits: 0b1000 })
        );

        let tag = PointerTag::new(0b101).expect("low three bits are accepted");
        assert_eq!(tag.bits(), 0b101);
        assert!(tag.has_forced_bit());
    }

    #[test]
    fn tagged_heap_addresses_roundtrip_address_and_tag_bits() {
        let ptr = NonNull::<HeapObject>::dangling();
        let tag = PointerTag::new(0b110).expect("low three bits are accepted");

        let tagged =
            TaggedHeapAddress::from_pointer(ptr, tag).expect("aligned pointer is taggable");

        assert!(tagged.address_matches(ptr));
        assert_eq!(tagged.tag(), tag);
        assert_eq!(tagged.raw_bits() & POINTER_TAG_MASK, 0b110);
        assert_eq!(tagged.address_bits(), ptr.as_ptr() as usize);
    }

    #[test]
    fn forced_bit_can_be_added_without_changing_address_bits() {
        let ptr = NonNull::<HeapObject>::dangling();
        let tagged = TaggedHeapAddress::from_pointer(ptr, PointerTag::EMPTY)
            .expect("aligned pointer is taggable");

        let forced = tagged.with_forced_bit();

        assert!(!tagged.has_forced_bit());
        assert!(forced.has_forced_bit());
        assert!(forced.address_matches(ptr));
    }

    #[test]
    fn raw_tagged_words_decode_address_and_low_bits() {
        let ptr = NonNull::<HeapObject>::dangling();
        let raw = ptr.as_ptr() as usize | FORCED_BIT;

        let tagged = TaggedHeapAddress::from_raw_address(raw).expect("raw tagged pointer decodes");

        assert!(tagged.address_matches(ptr));
        assert_eq!(tagged.tag(), PointerTag::FORCED);
    }

    #[test]
    fn tagged_heap_addresses_reject_unaligned_or_null_addresses() {
        let unaligned = NonNull::new(1usize as *mut HeapObject).expect("test pointer is non-null");

        assert_eq!(
            TaggedHeapAddress::from_pointer(unaligned, PointerTag::EMPTY),
            Err(PointerTagError::UnalignedHeapPointer { address: 1 })
        );
        assert_eq!(
            TaggedHeapAddress::from_raw_address(FORCED_BIT),
            Err(PointerTagError::NullHeapPointer)
        );
    }

    #[test]
    fn candidate_b_word_is_one_machine_word() {
        assert_eq!(std::mem::size_of::<TaggedValueWord>(), 8);
        assert_eq!(TAGGED_IMMEDIATE_INT_MIN, -(1_i64 << 60));
        assert_eq!(TAGGED_IMMEDIATE_INT_MAX, (1_i64 << 60) - 1);
    }

    #[test]
    fn candidate_b_inline_ints_roundtrip_full_signed_payload() {
        for value in [TAGGED_IMMEDIATE_INT_MIN, -1, 0, 1, TAGGED_IMMEDIATE_INT_MAX] {
            let word = TaggedValueWord::inline_int(value).expect("integer fits");
            assert_eq!(word.kind(), Ok(TaggedValueKind::InlineInt));
            assert_eq!(word.as_inline_int(), Some(value));
            assert_eq!(TaggedValueWord::from_raw(word.raw_bits()), Ok(word));
        }

        for value in [TAGGED_IMMEDIATE_INT_MIN - 1, TAGGED_IMMEDIATE_INT_MAX + 1] {
            assert_eq!(
                TaggedValueWord::inline_int(value),
                Err(TaggedValueWordError::IntegerOutOfRange { value })
            );
        }
    }

    #[test]
    fn candidate_b_singletons_are_canonical() {
        let false_word = TaggedValueWord::boolean(false);
        let true_word = TaggedValueWord::boolean(true);
        let null_word = TaggedValueWord::null();

        assert_eq!(false_word.kind(), Ok(TaggedValueKind::Bool));
        assert_eq!(true_word.kind(), Ok(TaggedValueKind::Bool));
        assert_eq!(null_word.kind(), Ok(TaggedValueKind::Null));
        assert_eq!(false_word.as_bool(), Some(false));
        assert_eq!(true_word.as_bool(), Some(true));
        assert!(null_word.is_null());
        assert_eq!(
            TaggedValueWord::from_raw(false_word.raw_bits()),
            Ok(false_word)
        );
        assert_eq!(
            TaggedValueWord::from_raw(true_word.raw_bits()),
            Ok(true_word)
        );
        assert_eq!(
            TaggedValueWord::from_raw(null_word.raw_bits()),
            Ok(null_word)
        );

        let noncanonical_false = (1_u64 << POINTER_TAG_BITS) | TAGGED_VALUE_FALSE;
        assert!(matches!(
            TaggedValueWord::from_raw(noncanonical_false),
            Err(TaggedValueWordError::SingletonPayload {
                kind: TaggedValueKind::Bool,
                raw,
            }) if raw == noncanonical_false
        ));
    }

    #[test]
    fn candidate_b_heap_words_preserve_address_and_forced_state() {
        let ptr = NonNull::<HeapObject>::dangling();
        let heap = TaggedValueWord::heap(ptr).expect("aligned pointer encodes");
        let forced = TaggedValueWord::forced_thunk(ptr).expect("aligned pointer encodes");

        assert_eq!(heap.kind(), Ok(TaggedValueKind::Heap));
        assert_eq!(forced.kind(), Ok(TaggedValueKind::ForcedThunk));
        assert!(!heap.is_forced_thunk());
        assert!(forced.is_forced_thunk());
        assert!(
            heap.heap_address()
                .expect("heap address validates")
                .is_some_and(|address| address.address_matches(ptr))
        );
        assert!(
            forced
                .heap_address()
                .expect("heap address validates")
                .is_some_and(|address| address.address_matches(ptr) && address.has_forced_bit())
        );
        assert_eq!(TaggedValueWord::from_raw(heap.raw_bits()), Ok(heap));
        assert_eq!(TaggedValueWord::from_raw(forced.raw_bits()), Ok(forced));
    }

    #[test]
    fn candidate_b_raw_decoder_rejects_null_and_reserved_words() {
        assert_eq!(
            TaggedValueWord::from_raw(TAGGED_VALUE_HEAP),
            Err(TaggedValueWordError::Pointer(
                PointerTagError::NullHeapPointer
            ))
        );
        assert_eq!(
            TaggedValueWord::from_raw(TAGGED_VALUE_FORCED_THUNK),
            Err(TaggedValueWordError::Pointer(
                PointerTagError::NullHeapPointer
            ))
        );
        for tag in [0b110, 0b111] {
            assert_eq!(
                TaggedValueWord::from_raw(tag),
                Err(TaggedValueWordError::ReservedTag { tag: tag as u8 })
            );
        }
    }
}
