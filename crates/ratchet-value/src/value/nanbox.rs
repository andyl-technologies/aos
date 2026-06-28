//! Safe NaN-boxing layout helpers for the measured value-size variant.
//!
//! The active [`super::Value`] representation remains the 16-byte tagged word
//! pair. This module only captures the bit-level contract for the later
//! NaN-boxed variant: boxed non-double values use a reserved negative quiet-NaN
//! prefix, a three-bit tag, and a 48-bit payload. Real floating-point values are
//! stored as raw `f64` bits unless their bits collide with the reserved prefix;
//! those NaNs are normalized to a canonical non-boxed quiet NaN.
//!
//! These helpers do not dereference pointers, do not reconstruct provenance, and
//! do not change runtime value semantics. Heap-pointer payloads are address bits
//! only; callers that need live pointers must keep provenance through a separate
//! typed heap handle.

use std::ptr::NonNull;

use thiserror::Error;

use super::{HeapObject, tag::POINTER_TAG_MASK};

/// Mask selecting the reserved boxed-value NaN prefix.
pub const NAN_BOX_PREFIX_MASK: u64 = 0xfff8_0000_0000_0000;
/// The reserved negative quiet-NaN prefix used by boxed non-double values.
pub const NAN_BOX_PREFIX: u64 = 0xfff8_0000_0000_0000;
/// Number of NaN-box tag bits.
pub const NAN_BOX_TAG_BITS: u32 = 3;
/// Shift of the three-bit NaN-box tag field.
pub const NAN_BOX_TAG_SHIFT: u32 = 48;
/// Mask selecting the three-bit NaN-box tag field.
pub const NAN_BOX_TAG_MASK: u64 = 0x0007_0000_0000_0000;
/// Number of payload bits available inside a boxed NaN word.
pub const NAN_BOX_PAYLOAD_BITS: u32 = 48;
/// Mask selecting the boxed NaN payload field.
pub const NAN_BOX_PAYLOAD_MASK: u64 = 0x0000_ffff_ffff_ffff;
/// Canonical quiet NaN used when an incoming float collides with the box prefix.
pub const CANONICAL_FLOAT_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
/// Smallest signed integer that can be carried in a 48-bit NaN-box payload.
pub const SMALL_INT_MIN: i64 = -(1_i64 << 47);
/// Largest signed integer that can be carried in a 48-bit NaN-box payload.
pub const SMALL_INT_MAX: i64 = (1_i64 << 47) - 1;

const SMALL_INT_SIGN_BIT: u64 = 1_u64 << 47;

const _: () = assert!(NAN_BOX_PREFIX & NAN_BOX_PREFIX_MASK == NAN_BOX_PREFIX);
const _: () = assert!(NAN_BOX_TAG_MASK >> NAN_BOX_TAG_SHIFT == 0b111);
const _: () = assert!(NAN_BOX_PAYLOAD_BITS == NAN_BOX_TAG_SHIFT);

/// A boxed NaN payload tag.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NanBoxTag {
    /// A 48-bit aligned heap address payload.
    HeapPointer = 0b001,
    /// Null, booleans, and other fixed immediates.
    Immediate = 0b010,
    /// A signed integer in the inclusive 48-bit range.
    SmallInt = 0b011,
}

impl NanBoxTag {
    /// Creates a NaN-box tag from raw three-bit metadata.
    ///
    /// # Errors
    ///
    /// Returns [`NanBoxError::ReservedTag`] when `bits` is not assigned to a
    /// known NaN-box payload form.
    pub const fn from_bits(bits: u8) -> Result<Self, NanBoxError> {
        match bits {
            0b001 => Ok(Self::HeapPointer),
            0b010 => Ok(Self::Immediate),
            0b011 => Ok(Self::SmallInt),
            tag_bits => Err(NanBoxError::ReservedTag { tag_bits }),
        }
    }

    /// Returns the raw three-bit tag value.
    pub const fn bits(self) -> u8 {
        self as u8
    }
}

/// A fixed immediate carried under [`NanBoxTag::Immediate`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NanBoxImmediate {
    /// The null singleton.
    Null = 0,
    /// The boolean false singleton.
    BoolFalse = 1,
    /// The boolean true singleton.
    BoolTrue = 2,
}

impl NanBoxImmediate {
    /// Returns the immediate representation for `value`.
    pub const fn boolean(value: bool) -> Self {
        if value {
            Self::BoolTrue
        } else {
            Self::BoolFalse
        }
    }

    /// Creates an immediate from a raw boxed payload.
    ///
    /// # Errors
    ///
    /// Returns [`NanBoxError::ReservedImmediate`] when `payload` does not name a
    /// known immediate singleton.
    pub const fn from_payload(payload: u64) -> Result<Self, NanBoxError> {
        match payload {
            0 => Ok(Self::Null),
            1 => Ok(Self::BoolFalse),
            2 => Ok(Self::BoolTrue),
            payload => Err(NanBoxError::ReservedImmediate { payload }),
        }
    }

    /// Returns the immediate's boxed payload bits.
    pub const fn payload(self) -> u64 {
        self as u64
    }
}

/// The decoded tag and payload of a boxed NaN word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NanBoxedPayload {
    /// The decoded payload tag.
    pub tag: NanBoxTag,
    /// The decoded 48-bit payload.
    pub payload: u64,
}

/// A checked NaN-boxed value word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NanBoxWord {
    raw: u64,
}

impl NanBoxWord {
    /// Creates a NaN-box word from a floating-point value.
    ///
    /// Floating-point bit patterns that collide with the reserved boxed-value
    /// prefix are normalized to [`CANONICAL_FLOAT_NAN_BITS`] so the decoder never
    /// mistakes a real float for a heap pointer or immediate.
    pub const fn from_float(value: f64) -> Self {
        let raw = value.to_bits();
        if is_boxed_raw(raw) {
            Self {
                raw: CANONICAL_FLOAT_NAN_BITS,
            }
        } else {
            Self { raw }
        }
    }

    /// Creates a NaN-box word from raw bits.
    ///
    /// # Errors
    ///
    /// Returns an error when `raw` carries the boxed prefix but uses a reserved
    /// tag, reserved immediate payload, null heap pointer payload, or unaligned
    /// heap pointer payload.
    pub const fn from_raw_bits(raw: u64) -> Result<Self, NanBoxError> {
        if !is_boxed_raw(raw) {
            return Ok(Self { raw });
        }

        let tag_bits = ((raw & NAN_BOX_TAG_MASK) >> NAN_BOX_TAG_SHIFT) as u8;
        let payload = raw & NAN_BOX_PAYLOAD_MASK;
        match NanBoxTag::from_bits(tag_bits) {
            Ok(tag) => match validate_boxed_payload(tag, payload) {
                Ok(()) => Ok(Self { raw }),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }

    /// Creates a boxed heap-pointer payload from aligned address bits.
    ///
    /// # Errors
    ///
    /// Returns an error when `address_bits` is null, uses bits outside the
    /// 48-bit payload field, or does not satisfy the heap-pointer alignment
    /// contract.
    pub const fn from_heap_address_bits(address_bits: usize) -> Result<Self, NanBoxError> {
        let payload = address_bits as u64;
        if payload & !NAN_BOX_PAYLOAD_MASK != 0 {
            return Err(NanBoxError::HeapAddressOutOfRange {
                address_bits: payload,
            });
        }
        match validate_heap_payload(payload) {
            Ok(()) => Ok(Self {
                raw: compose_boxed_word(NanBoxTag::HeapPointer, payload),
            }),
            Err(error) => Err(error),
        }
    }

    /// Creates a boxed heap-pointer payload from a typed heap handle.
    ///
    /// The resulting word stores address bits only. It does not retain pointer
    /// provenance or prove that the allocation remains live.
    ///
    /// # Errors
    ///
    /// Returns an error when `ptr` does not fit the 48-bit payload field or does
    /// not satisfy the heap-pointer alignment contract.
    pub fn from_heap_pointer(ptr: NonNull<HeapObject>) -> Result<Self, NanBoxError> {
        Self::from_heap_address_bits(ptr.as_ptr() as usize)
    }

    /// Creates a boxed immediate singleton.
    pub const fn from_immediate(immediate: NanBoxImmediate) -> Self {
        Self {
            raw: compose_boxed_word(NanBoxTag::Immediate, immediate.payload()),
        }
    }

    /// Creates a boxed signed small integer.
    ///
    /// # Errors
    ///
    /// Returns [`NanBoxError::SmallIntOutOfRange`] when `value` does not fit in
    /// the signed 48-bit NaN-box payload range.
    pub const fn from_small_int(value: i64) -> Result<Self, NanBoxError> {
        if value < SMALL_INT_MIN || value > SMALL_INT_MAX {
            return Err(NanBoxError::SmallIntOutOfRange { value });
        }
        Ok(Self {
            raw: compose_boxed_word(NanBoxTag::SmallInt, value as u64 & NAN_BOX_PAYLOAD_MASK),
        })
    }

    /// Returns the raw 64-bit NaN-box word.
    pub const fn raw_bits(self) -> u64 {
        self.raw
    }

    /// Returns whether this word carries the reserved boxed-value prefix.
    pub const fn is_boxed(self) -> bool {
        is_boxed_raw(self.raw)
    }

    /// Returns whether this word should be interpreted as a raw floating-point
    /// value.
    pub const fn is_float(self) -> bool {
        !self.is_boxed()
    }

    /// Returns this word as a floating-point value when it is not boxed.
    pub fn as_float(self) -> Option<f64> {
        if self.is_float() {
            Some(f64::from_bits(self.raw))
        } else {
            None
        }
    }

    /// Returns the decoded boxed payload, if this word is boxed.
    pub const fn boxed_payload(self) -> Option<NanBoxedPayload> {
        if !self.is_boxed() {
            return None;
        }
        let tag_bits = ((self.raw & NAN_BOX_TAG_MASK) >> NAN_BOX_TAG_SHIFT) as u8;
        let payload = self.raw & NAN_BOX_PAYLOAD_MASK;
        match tag_bits {
            0b001 => Some(NanBoxedPayload {
                tag: NanBoxTag::HeapPointer,
                payload,
            }),
            0b010 => Some(NanBoxedPayload {
                tag: NanBoxTag::Immediate,
                payload,
            }),
            0b011 => Some(NanBoxedPayload {
                tag: NanBoxTag::SmallInt,
                payload,
            }),
            _ => None,
        }
    }

    /// Returns the decoded heap address payload for GC scanning, if present.
    pub const fn heap_address_payload(self) -> Option<u64> {
        match self.boxed_payload() {
            Some(boxed) => match boxed.tag {
                NanBoxTag::HeapPointer => Some(boxed.payload),
                NanBoxTag::Immediate | NanBoxTag::SmallInt => None,
            },
            None => None,
        }
    }

    /// Returns the decoded immediate singleton, if present.
    pub const fn immediate(self) -> Option<NanBoxImmediate> {
        match self.boxed_payload() {
            Some(boxed) => match boxed.tag {
                NanBoxTag::Immediate => match NanBoxImmediate::from_payload(boxed.payload) {
                    Ok(immediate) => Some(immediate),
                    Err(_) => None,
                },
                NanBoxTag::HeapPointer | NanBoxTag::SmallInt => None,
            },
            None => None,
        }
    }

    /// Returns the decoded signed small integer, if present.
    pub const fn small_int(self) -> Option<i64> {
        match self.boxed_payload() {
            Some(boxed) => match boxed.tag {
                NanBoxTag::SmallInt => {
                    if boxed.payload & SMALL_INT_SIGN_BIT == 0 {
                        Some(boxed.payload as i64)
                    } else {
                        Some((boxed.payload | !NAN_BOX_PAYLOAD_MASK) as i64)
                    }
                }
                NanBoxTag::HeapPointer | NanBoxTag::Immediate => None,
            },
            None => None,
        }
    }
}

/// A failed NaN-box encoding or decoding operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NanBoxError {
    /// A boxed word used an unassigned tag field.
    #[error("NaN-box tag is reserved: 0b{tag_bits:03b}")]
    ReservedTag {
        /// The rejected raw tag bits.
        tag_bits: u8,
    },
    /// An immediate payload did not name a known singleton.
    #[error("NaN-box immediate payload is reserved: 0x{payload:x}")]
    ReservedImmediate {
        /// The rejected immediate payload.
        payload: u64,
    },
    /// A heap address payload was null.
    #[error("NaN-box heap pointer payload is null")]
    NullHeapPointer,
    /// A heap address used bits outside the 48-bit NaN-box payload.
    #[error("NaN-box heap address does not fit in {NAN_BOX_PAYLOAD_BITS} bits: 0x{address_bits:x}")]
    HeapAddressOutOfRange {
        /// The rejected heap address bits.
        address_bits: u64,
    },
    /// A heap address did not satisfy the heap-pointer alignment contract.
    #[error("NaN-box heap address is not aligned for pointer-tag agreement: 0x{address_bits:x}")]
    UnalignedHeapPointer {
        /// The rejected heap address bits.
        address_bits: u64,
    },
    /// A signed integer did not fit in the 48-bit NaN-box payload range.
    #[error("NaN-box small int is outside the signed 48-bit range: {value}")]
    SmallIntOutOfRange {
        /// The rejected signed integer.
        value: i64,
    },
}

const fn is_boxed_raw(raw: u64) -> bool {
    raw & NAN_BOX_PREFIX_MASK == NAN_BOX_PREFIX
}

const fn compose_boxed_word(tag: NanBoxTag, payload: u64) -> u64 {
    NAN_BOX_PREFIX | ((tag.bits() as u64) << NAN_BOX_TAG_SHIFT) | payload
}

const fn validate_boxed_payload(tag: NanBoxTag, payload: u64) -> Result<(), NanBoxError> {
    match tag {
        NanBoxTag::HeapPointer => validate_heap_payload(payload),
        NanBoxTag::Immediate => match NanBoxImmediate::from_payload(payload) {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        },
        NanBoxTag::SmallInt => Ok(()),
    }
}

const fn validate_heap_payload(payload: u64) -> Result<(), NanBoxError> {
    if payload == 0 {
        Err(NanBoxError::NullHeapPointer)
    } else if payload & POINTER_TAG_MASK as u64 != 0 {
        Err(NanBoxError::UnalignedHeapPointer {
            address_bits: payload,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan_box_layout_uses_negative_quiet_nan_prefix() {
        assert_eq!(NAN_BOX_PREFIX_MASK, 0xfff8_0000_0000_0000);
        assert_eq!(NAN_BOX_PREFIX, 0xfff8_0000_0000_0000);
        assert_eq!(NAN_BOX_TAG_BITS, 3);
        assert_eq!(NAN_BOX_TAG_SHIFT, 48);
        assert_eq!(NAN_BOX_TAG_MASK >> NAN_BOX_TAG_SHIFT, 0b111);
        assert_eq!(NAN_BOX_PAYLOAD_BITS, 48);
        assert_eq!(NAN_BOX_PAYLOAD_MASK, 0x0000_ffff_ffff_ffff);
        assert_eq!(SMALL_INT_MIN, -(1_i64 << 47));
        assert_eq!(SMALL_INT_MAX, (1_i64 << 47) - 1);
    }

    #[test]
    fn floats_roundtrip_except_reserved_prefix_nan_normalization() {
        let finite = NanBoxWord::from_float(1.5);
        assert!(finite.is_float());
        assert_eq!(finite.raw_bits(), 1.5_f64.to_bits());
        assert_eq!(finite.as_float(), Some(1.5));

        let infinity = NanBoxWord::from_float(f64::INFINITY);
        assert!(infinity.is_float());
        assert_eq!(infinity.raw_bits(), f64::INFINITY.to_bits());

        let colliding_nan_bits = compose_boxed_word(NanBoxTag::HeapPointer, 0x1000);
        let colliding_nan = f64::from_bits(colliding_nan_bits);
        let normalized = NanBoxWord::from_float(colliding_nan);

        assert!(normalized.is_float());
        assert_eq!(normalized.raw_bits(), CANONICAL_FLOAT_NAN_BITS);
        assert!(
            normalized
                .as_float()
                .expect("normalized word is a float")
                .is_nan()
        );
    }

    #[test]
    fn boxed_heap_addresses_validate_payload_width_and_alignment() {
        let pointer =
            NanBoxWord::from_heap_address_bits(0x1000).expect("aligned 48-bit address is accepted");

        assert!(pointer.is_boxed());
        assert_eq!(
            pointer.boxed_payload(),
            Some(NanBoxedPayload {
                tag: NanBoxTag::HeapPointer,
                payload: 0x1000,
            })
        );
        assert_eq!(pointer.heap_address_payload(), Some(0x1000));

        assert_eq!(
            NanBoxWord::from_heap_address_bits(0),
            Err(NanBoxError::NullHeapPointer)
        );
        assert_eq!(
            NanBoxWord::from_heap_address_bits(0x1001),
            Err(NanBoxError::UnalignedHeapPointer {
                address_bits: 0x1001,
            })
        );

        if usize::BITS > NAN_BOX_PAYLOAD_BITS {
            assert_eq!(
                NanBoxWord::from_heap_address_bits((NAN_BOX_PAYLOAD_MASK + 1) as usize),
                Err(NanBoxError::HeapAddressOutOfRange {
                    address_bits: NAN_BOX_PAYLOAD_MASK + 1,
                })
            );
        }
    }

    #[test]
    fn typed_heap_handles_encode_address_bits_without_provenance_claims() {
        let ptr = NonNull::<HeapObject>::dangling();
        let word = NanBoxWord::from_heap_pointer(ptr).expect("dangling handle is aligned");

        assert_eq!(word.heap_address_payload(), Some(ptr.as_ptr() as u64));
    }

    #[test]
    fn small_ints_roundtrip_signed_48_bit_range() {
        for value in [SMALL_INT_MIN, -1, 0, 1, SMALL_INT_MAX] {
            let word = NanBoxWord::from_small_int(value).expect("small int fits");

            assert!(word.is_boxed());
            assert_eq!(word.small_int(), Some(value));
            assert_eq!(word.heap_address_payload(), None);
        }

        assert_eq!(
            NanBoxWord::from_small_int(SMALL_INT_MIN - 1),
            Err(NanBoxError::SmallIntOutOfRange {
                value: SMALL_INT_MIN - 1,
            })
        );
        assert_eq!(
            NanBoxWord::from_small_int(SMALL_INT_MAX + 1),
            Err(NanBoxError::SmallIntOutOfRange {
                value: SMALL_INT_MAX + 1,
            })
        );
    }

    #[test]
    fn immediates_roundtrip_and_reject_reserved_payloads() {
        let null = NanBoxWord::from_immediate(NanBoxImmediate::Null);
        let bool_true = NanBoxWord::from_immediate(NanBoxImmediate::boolean(true));

        assert_eq!(null.immediate(), Some(NanBoxImmediate::Null));
        assert_eq!(bool_true.immediate(), Some(NanBoxImmediate::BoolTrue));
        assert_eq!(bool_true.heap_address_payload(), None);

        let raw_reserved_immediate = compose_boxed_word(NanBoxTag::Immediate, 0x7);
        assert_eq!(
            NanBoxWord::from_raw_bits(raw_reserved_immediate),
            Err(NanBoxError::ReservedImmediate { payload: 0x7 })
        );
    }

    #[test]
    fn raw_boxed_words_reject_reserved_tags() {
        let raw_reserved_tag = NAN_BOX_PREFIX | 0x1000;

        assert_eq!(
            NanBoxWord::from_raw_bits(raw_reserved_tag),
            Err(NanBoxError::ReservedTag { tag_bits: 0 })
        );
    }

    #[test]
    fn raw_words_decode_only_valid_boxed_forms() {
        let pointer_raw = compose_boxed_word(NanBoxTag::HeapPointer, 0x2000);
        let small_int_raw =
            compose_boxed_word(NanBoxTag::SmallInt, (-42_i64 as u64) & NAN_BOX_PAYLOAD_MASK);
        let float_raw = 2.0_f64.to_bits();

        assert_eq!(
            NanBoxWord::from_raw_bits(pointer_raw)
                .expect("valid pointer box")
                .heap_address_payload(),
            Some(0x2000)
        );
        assert_eq!(
            NanBoxWord::from_raw_bits(small_int_raw)
                .expect("valid small int box")
                .small_int(),
            Some(-42)
        );
        assert_eq!(
            NanBoxWord::from_raw_bits(float_raw)
                .expect("float bits are accepted")
                .as_float(),
            Some(2.0)
        );
    }
}
