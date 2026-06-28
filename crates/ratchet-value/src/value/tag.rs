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
        let address = ptr.as_ptr() as usize;
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
        self.address_bits() == ptr.as_ptr() as usize
    }
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
}
