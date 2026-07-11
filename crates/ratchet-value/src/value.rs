//! Runtime value words for the safe tree-walk evaluator.
//!
//! This module owns the Phase-1 value representation from RFC-0007: a 16-byte
//! tagged word pair. The tag word carries the Nix value form and the payload word
//! carries either an inline scalar (`i64`, `f64`, `bool`) or a [`NonNull`]
//! pointer to an evaluator heap object. No alternate representation is active;
//! [`compressed`], [`tag`], and [`nanbox`] capture checked layout contracts for
//! later measured variants. (The former
//! `small` module's 0/1/2-element inline-constructor contract was retired by
//! doc 30 stage FV-2: no allocation, resolution, or dispatch path ever
//! consulted it, and its inline-payload role is subsumed by the flat heap
//! objects in `crate::heap::flat` — see that module's §11.7 boundary note.)

use std::fmt;
use std::mem;
use std::ptr::NonNull;

use thiserror::Error;

pub mod compressed;
pub mod nanbox;
pub mod tag;

use tag::{HEAP_POINTER_ALIGNMENT as HEAP_POINTER_ALIGN, POINTER_TAG_MASK as HEAP_POINTER_MASK};

/// An opaque evaluator heap allocation.
///
/// Concrete heap layouts live in later modules (`heap`, `attrs`, `eval`, and
/// `runtime`). Values store only aligned, non-null handles to those allocations.
#[repr(C, align(8))]
#[derive(Debug)]
pub struct HeapObject {
    _private: [u8; 0],
}

/// The tag word of a [`Value`].
///
/// The discriminants intentionally match the RFC table. The enum uses a full
/// `u64` representation so [`Value`] stays exactly two machine words in the
/// baseline ABI.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueTag {
    /// An inline signed 64-bit integer.
    Int = 0x00,
    /// An inline IEEE-754 double.
    Float = 0x01,
    /// An inline boolean encoded as `0` or `1`.
    Bool = 0x02,
    /// The null singleton.
    Null = 0x03,
    /// A heap string with string context.
    String = 0x10,
    /// A heap path value.
    Path = 0x11,
    /// A heap list spine.
    List = 0x12,
    /// A heap attribute set.
    Attrs = 0x13,
    /// A heap user lambda closure.
    Lambda = 0x14,
    /// A heap builtin or partially-applied builtin.
    Primop = 0x15,
    /// A heap opaque external value.
    External = 0x16,
    /// A heap suspended computation.
    Thunk = 0x20,
}

impl ValueTag {
    /// Returns whether this tag stores a heap pointer payload.
    pub const fn is_heap(self) -> bool {
        matches!(
            self,
            Self::String
                | Self::Path
                | Self::List
                | Self::Attrs
                | Self::Lambda
                | Self::Primop
                | Self::External
                | Self::Thunk
        )
    }

    /// Returns whether this tag is already in weak head normal form.
    pub const fn is_whnf(self) -> bool {
        !matches!(self, Self::Thunk)
    }

    /// Returns the user-visible `builtins.typeOf` name for this tag.
    ///
    /// Thunks are not a Nix value type; callers must force them before
    /// observation, so this returns `None` for [`ValueTag::Thunk`].
    pub const fn nix_type_name(self) -> Option<&'static str> {
        match self {
            Self::Int => Some("int"),
            Self::Float => Some("float"),
            Self::Bool => Some("bool"),
            Self::Null => Some("null"),
            Self::String => Some("string"),
            Self::Path => Some("path"),
            Self::List => Some("list"),
            Self::Attrs => Some("set"),
            Self::Lambda | Self::Primop => Some("lambda"),
            Self::External => Some("external"),
            Self::Thunk => None,
        }
    }
}

/// A Nix runtime value represented as a 16-byte tagged word pair.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Value {
    tag: ValueTag,
    payload: u64,
}

impl Value {
    /// Creates an inline integer value.
    pub const fn int(value: i64) -> Self {
        Self {
            tag: ValueTag::Int,
            payload: value as u64,
        }
    }

    /// Creates an inline floating-point value.
    pub const fn float(value: f64) -> Self {
        Self {
            tag: ValueTag::Float,
            payload: value.to_bits(),
        }
    }

    /// Creates an inline boolean value.
    pub const fn bool(value: bool) -> Self {
        Self {
            tag: ValueTag::Bool,
            payload: value as u64,
        }
    }

    /// Creates the null singleton value.
    pub const fn null() -> Self {
        Self {
            tag: ValueTag::Null,
            payload: 0,
        }
    }

    /// Creates a heap string value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::UnalignedHeapPointer`] when `ptr` is not aligned to
    /// the evaluator heap-object alignment.
    pub fn string(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::String, ptr)
    }

    /// Creates a heap path value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::UnalignedHeapPointer`] when `ptr` is not aligned to
    /// the evaluator heap-object alignment.
    pub fn path(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Path, ptr)
    }

    /// Creates a heap list value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::UnalignedHeapPointer`] when `ptr` is not aligned to
    /// the evaluator heap-object alignment.
    pub fn list(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::List, ptr)
    }

    /// Creates a heap attribute-set value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::UnalignedHeapPointer`] when `ptr` is not aligned to
    /// the evaluator heap-object alignment.
    pub fn attrs(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Attrs, ptr)
    }

    /// Creates a heap lambda value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::UnalignedHeapPointer`] when `ptr` is not aligned to
    /// the evaluator heap-object alignment.
    pub fn lambda(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Lambda, ptr)
    }

    /// Creates a heap primop value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::UnalignedHeapPointer`] when `ptr` is not aligned to
    /// the evaluator heap-object alignment.
    pub fn primop(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Primop, ptr)
    }

    /// Creates a heap external value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::UnalignedHeapPointer`] when `ptr` is not aligned to
    /// the evaluator heap-object alignment.
    pub fn external(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::External, ptr)
    }

    /// Creates a heap thunk value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::UnalignedHeapPointer`] when `ptr` is not aligned to
    /// the evaluator heap-object alignment.
    pub fn thunk(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Thunk, ptr)
    }

    /// Creates a heap-backed value with `tag`.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotHeapTag`] when `tag` is an inline value tag, and
    /// [`ValueError::UnalignedHeapPointer`] when `ptr` does not satisfy the heap
    /// pointer alignment contract.
    pub fn heap(tag: ValueTag, ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        if !tag.is_heap() {
            return Err(ValueError::NotHeapTag { tag });
        }
        let address = ptr.as_ptr() as usize;
        if address & HEAP_POINTER_MASK != 0 {
            return Err(ValueError::UnalignedHeapPointer { tag, address });
        }
        Ok(Self {
            tag,
            payload: address as u64,
        })
    }

    /// Returns this value's tag.
    ///
    /// In debug builds this asserts that the payload is valid for the tag so
    /// raw representation observers catch corrupted values at the boundary.
    pub const fn tag(self) -> ValueTag {
        self.debug_assert_payload_invariant();
        self.tag
    }

    /// Returns raw payload bits for scalar decoding and diagnostics.
    ///
    /// In debug builds this asserts that the payload is valid for the tag so
    /// callers do not accidentally treat malformed values as trusted bits.
    /// Heap-address identities that outlive the immediate expression must use
    /// [`Value::relocation_sensitive_identity_bits`], while collector-free
    /// recursive walks use [`Value::address_identity_bits`].
    ///
    /// # Panics
    ///
    /// Panics in debug builds when the tag and payload violate the value ABI.
    pub const fn payload_bits(self) -> u64 {
        self.debug_assert_payload_invariant();
        self.payload
    }

    /// Returns the representation bits used as identity within a no-relocation interval.
    ///
    /// Heap-backed values use their current address as representation identity. Callers
    /// must not retain this result across a moving-collector safepoint. Data structures
    /// that can survive such a safepoint must use
    /// [`Value::relocation_sensitive_identity_bits`] and participate in the collector's
    /// rekey or writeback protocol instead.
    ///
    /// # Panics
    ///
    /// Panics in debug builds when this is not a valid heap-backed value.
    pub const fn address_identity_bits(self) -> u64 {
        self.debug_assert_payload_invariant();
        debug_assert!(self.tag.is_heap());
        self.payload
    }

    /// Returns representation identity within a no-relocation interval.
    ///
    /// Inline values return their scalar payload, while heap-backed values
    /// return their current address. Callers that mix tags must include the
    /// tag in their key and must not retain this result across a moving-GC
    /// safepoint.
    ///
    /// # Panics
    ///
    /// Panics in debug builds when the tag and payload violate the value ABI.
    pub const fn transient_identity_bits(self) -> u64 {
        self.debug_assert_payload_invariant();
        self.payload
    }

    /// Returns representation-identity bits that require relocation repair.
    ///
    /// This accessor marks a raw address-derived key or reference as live across a
    /// possible moving-collector safepoint. Every caller is part of the checked-in
    /// payload-identity audit and must be handled by B2 through root writeback,
    /// side-table rekeying, or structural-hash rebuilding.
    ///
    /// # Panics
    ///
    /// Panics in debug builds when the tag and payload violate the value ABI.
    pub const fn relocation_sensitive_identity_bits(self) -> u64 {
        self.debug_assert_payload_invariant();
        self.payload
    }

    /// Returns raw tag-and-payload equality.
    ///
    /// This is not Nix semantic equality: semantic equality forces thunks and
    /// recursively compares lists, attrsets, and string contexts. This method is
    /// only for representation-level tests, caches, and runtime invariants.
    pub const fn raw_eq(self, other: Self) -> bool {
        self.debug_assert_payload_invariant();
        other.debug_assert_payload_invariant();
        self.tag as u64 == other.tag as u64 && self.payload == other.payload
    }

    /// Returns whether this value is already in weak head normal form.
    pub const fn is_whnf(self) -> bool {
        self.debug_assert_payload_invariant();
        self.tag.is_whnf()
    }

    /// Returns whether this value is a thunk.
    pub const fn is_thunk(self) -> bool {
        self.debug_assert_payload_invariant();
        matches!(self.tag, ValueTag::Thunk)
    }

    /// Checks that the payload is valid for this value's tag.
    ///
    /// Inline integer and floating-point tags accept every bit pattern. Boolean
    /// values must be encoded as `0` or `1`, null must use a zero payload, and
    /// heap tags must carry a non-null aligned heap pointer.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload does not satisfy the tag's
    /// representation invariant.
    pub fn validate_payload(self) -> Result<(), ValueError> {
        match self.tag {
            ValueTag::Int | ValueTag::Float => Ok(()),
            ValueTag::Bool => match self.payload {
                0 | 1 => Ok(()),
                payload => Err(ValueError::InvalidBoolPayload { payload }),
            },
            ValueTag::Null => {
                if self.payload == 0 {
                    Ok(())
                } else {
                    Err(ValueError::InvalidNullPayload {
                        payload: self.payload,
                    })
                }
            }
            tag @ (ValueTag::String
            | ValueTag::Path
            | ValueTag::List
            | ValueTag::Attrs
            | ValueTag::Lambda
            | ValueTag::Primop
            | ValueTag::External
            | ValueTag::Thunk) => {
                let address = self.payload as usize;
                if address == 0 {
                    Err(ValueError::NullHeapPointer { tag })
                } else if address & HEAP_POINTER_MASK != 0 {
                    Err(ValueError::UnalignedHeapPointer { tag, address })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Returns the inline integer payload.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as an integer.
    pub fn as_int(self) -> Result<i64, ValueError> {
        self.expect_tag(ValueTag::Int, "int")?;
        Ok(self.payload as i64)
    }

    /// Returns the inline floating-point payload.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as a float.
    pub fn as_float(self) -> Result<f64, ValueError> {
        self.expect_tag(ValueTag::Float, "float")?;
        Ok(f64::from_bits(self.payload))
    }

    /// Returns the inline boolean payload.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as a boolean,
    /// or [`ValueError::InvalidBoolPayload`] if the payload is not `0` or `1`.
    pub fn as_bool(self) -> Result<bool, ValueError> {
        self.expect_tag(ValueTag::Bool, "bool")?;
        match self.payload {
            0 => Ok(false),
            1 => Ok(true),
            payload => Err(ValueError::InvalidBoolPayload { payload }),
        }
    }

    /// Returns `Ok(())` when this value is null.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as null, or
    /// [`ValueError::InvalidNullPayload`] when a null value carries non-zero
    /// payload bits.
    pub fn as_null(self) -> Result<(), ValueError> {
        self.expect_tag(ValueTag::Null, "null")?;
        if self.payload == 0 {
            Ok(())
        } else {
            Err(ValueError::InvalidNullPayload {
                payload: self.payload,
            })
        }
    }

    /// Returns the heap pointer payload for any heap-backed value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotHeapTag`] when this value is inline, or
    /// [`ValueError::NullHeapPointer`] if the payload is unexpectedly null, or
    /// [`ValueError::UnalignedHeapPointer`] if the payload does not satisfy the
    /// heap pointer alignment contract.
    pub fn as_heap_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        if !self.tag.is_heap() {
            return Err(ValueError::NotHeapTag { tag: self.tag });
        }
        let address = self.payload as usize;
        let ptr = NonNull::new(address as *mut HeapObject)
            .ok_or(ValueError::NullHeapPointer { tag: self.tag })?;
        if address & HEAP_POINTER_MASK != 0 {
            return Err(ValueError::UnalignedHeapPointer {
                tag: self.tag,
                address,
            });
        }
        Ok(ptr)
    }

    /// Returns the heap string pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as a string.
    pub fn as_string_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::String, "string")
    }

    /// Returns the heap path pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as a path.
    pub fn as_path_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Path, "path")
    }

    /// Returns the heap list pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as a list.
    pub fn as_list_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::List, "list")
    }

    /// Returns the heap attrset pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as an attrset.
    pub fn as_attrs_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Attrs, "attrs")
    }

    /// Returns the heap lambda pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as a lambda.
    pub fn as_lambda_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Lambda, "lambda")
    }

    /// Returns the heap primop pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as a primop.
    pub fn as_primop_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Primop, "primop")
    }

    /// Returns the heap external pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as external.
    pub fn as_external_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::External, "external")
    }

    /// Returns the heap thunk pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not tagged as a thunk.
    pub fn as_thunk_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Thunk, "thunk")
    }

    fn expect_tag(self, expected: ValueTag, expected_name: &'static str) -> Result<(), ValueError> {
        if self.tag == expected {
            Ok(())
        } else {
            Err(ValueError::Type {
                expected: expected_name,
                actual: self.tag,
            })
        }
    }

    fn expect_heap_tag(
        self,
        expected: ValueTag,
        expected_name: &'static str,
    ) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_tag(expected, expected_name)?;
        self.as_heap_ptr()
    }

    const fn debug_assert_payload_invariant(self) {
        if cfg!(debug_assertions) {
            assert!(self.payload_invariant_holds(), "invalid Value payload");
        }
    }

    const fn payload_invariant_holds(self) -> bool {
        match self.tag {
            ValueTag::Int | ValueTag::Float => true,
            ValueTag::Bool => self.payload <= 1,
            ValueTag::Null => self.payload == 0,
            ValueTag::String
            | ValueTag::Path
            | ValueTag::List
            | ValueTag::Attrs
            | ValueTag::Lambda
            | ValueTag::Primop
            | ValueTag::External
            | ValueTag::Thunk => {
                let address = self.payload as usize;
                address != 0 && address & HEAP_POINTER_MASK == 0
            }
        }
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Value")
            .field("tag", &self.tag)
            .field("payload", &format_args!("0x{:016x}", self.payload))
            .finish()
    }
}

/// A failed checked value operation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ValueError {
    /// A value carried an unexpected tag.
    #[error("expected {expected}, got {actual:?}")]
    Type {
        /// The expected value form.
        expected: &'static str,
        /// The actual value tag.
        actual: ValueTag,
    },
    /// A heap constructor received an inline tag.
    #[error("expected heap value tag, got {tag:?}")]
    NotHeapTag {
        /// The rejected tag.
        tag: ValueTag,
    },
    /// A heap pointer payload is not heap-object aligned.
    #[error("heap pointer for {tag:?} is not {HEAP_POINTER_ALIGN}-byte aligned: 0x{address:x}")]
    UnalignedHeapPointer {
        /// The heap tag being constructed.
        tag: ValueTag,
        /// The rejected address.
        address: usize,
    },
    /// A decoded heap value carried a null pointer payload.
    #[error("heap pointer for {tag:?} is null")]
    NullHeapPointer {
        /// The heap tag with the null payload.
        tag: ValueTag,
    },
    /// A boolean payload was neither `0` nor `1`.
    #[error("invalid boolean payload {payload}")]
    InvalidBoolPayload {
        /// The invalid raw payload.
        payload: u64,
    },
    /// A null value carried a non-zero payload.
    #[error("invalid null payload {payload}")]
    InvalidNullPayload {
        /// The invalid raw payload.
        payload: u64,
    },
}

const _: () = {
    assert!(mem::size_of::<usize>() == 8);
    assert!(mem::size_of::<ValueTag>() == 8);
    assert!(mem::size_of::<Value>() == 16);
    assert!(mem::align_of::<Value>() == 8);
    assert!(mem::align_of::<HeapObject>() == HEAP_POINTER_ALIGN);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_layout_is_two_machine_words() {
        assert_eq!(mem::size_of::<usize>(), 8);
        assert_eq!(mem::size_of::<ValueTag>(), 8);
        assert_eq!(mem::size_of::<Value>(), 16);
        assert_eq!(mem::align_of::<Value>(), 8);
        assert_eq!(mem::align_of::<HeapObject>(), HEAP_POINTER_ALIGN);
    }

    #[test]
    fn host_platform_matches_supported_value_abi_contract() {
        assert_eq!(usize::BITS, 64);
        assert!(cfg!(any(target_arch = "x86_64", target_arch = "aarch64")));
        assert!(cfg!(any(target_os = "linux", target_os = "macos")));
    }

    #[test]
    fn value_tag_discriminants_match_the_rfc_layout() {
        assert_eq!(ValueTag::Int as u64, 0x00);
        assert_eq!(ValueTag::Float as u64, 0x01);
        assert_eq!(ValueTag::Bool as u64, 0x02);
        assert_eq!(ValueTag::Null as u64, 0x03);
        assert_eq!(ValueTag::String as u64, 0x10);
        assert_eq!(ValueTag::Path as u64, 0x11);
        assert_eq!(ValueTag::List as u64, 0x12);
        assert_eq!(ValueTag::Attrs as u64, 0x13);
        assert_eq!(ValueTag::Lambda as u64, 0x14);
        assert_eq!(ValueTag::Primop as u64, 0x15);
        assert_eq!(ValueTag::External as u64, 0x16);
        assert_eq!(ValueTag::Thunk as u64, 0x20);
    }

    #[test]
    fn inline_values_roundtrip_through_checked_accessors() {
        assert_eq!(Value::int(i64::MIN).as_int().expect("int value"), i64::MIN);
        assert_eq!(
            Value::float(-13.25).as_float().expect("float value"),
            -13.25
        );
        let nan_bits = 0x7ff8_0000_0000_0001;
        let nan = Value::float(f64::from_bits(nan_bits));
        assert_eq!(nan.payload_bits(), nan_bits);
        assert_eq!(nan.as_float().expect("nan float").to_bits(), nan_bits);
        let negative_zero = Value::float(-0.0);
        assert_eq!(negative_zero.payload_bits(), (-0.0f64).to_bits());
        assert_eq!(
            negative_zero.as_float().expect("negative zero").to_bits(),
            (-0.0f64).to_bits()
        );
        assert!(Value::bool(true).as_bool().expect("bool value"));
        assert!(!Value::bool(false).as_bool().expect("bool value"));
        assert_eq!(Value::null().as_null(), Ok(()));
    }

    #[test]
    fn checked_accessors_reject_wrong_tags_and_invalid_payloads() {
        assert_eq!(
            Value::bool(true).as_int(),
            Err(ValueError::Type {
                expected: "int",
                actual: ValueTag::Bool,
            })
        );
        let invalid_bool = Value {
            tag: ValueTag::Bool,
            payload: 2,
        };
        assert_eq!(
            invalid_bool.as_bool(),
            Err(ValueError::InvalidBoolPayload { payload: 2 })
        );
        let invalid_null = Value {
            tag: ValueTag::Null,
            payload: 1,
        };
        assert_eq!(
            invalid_null.as_null(),
            Err(ValueError::InvalidNullPayload { payload: 1 })
        );
    }

    #[test]
    fn validate_payload_reports_tag_payload_invariants() {
        let ptr = NonNull::<HeapObject>::dangling();
        assert_eq!(Value::int(1).validate_payload(), Ok(()));
        assert_eq!(Value::float(f64::NAN).validate_payload(), Ok(()));
        assert_eq!(Value::bool(false).validate_payload(), Ok(()));
        assert_eq!(Value::null().validate_payload(), Ok(()));
        assert_eq!(
            Value::thunk(ptr)
                .expect("aligned thunk pointer")
                .validate_payload(),
            Ok(())
        );

        assert_eq!(
            (Value {
                tag: ValueTag::Bool,
                payload: 2,
            })
            .validate_payload(),
            Err(ValueError::InvalidBoolPayload { payload: 2 })
        );
        assert_eq!(
            (Value {
                tag: ValueTag::Null,
                payload: 1,
            })
            .validate_payload(),
            Err(ValueError::InvalidNullPayload { payload: 1 })
        );
    }

    #[test]
    fn whnf_fast_path_is_a_tag_predicate() {
        let ptr = NonNull::<HeapObject>::dangling();
        assert!(Value::int(1).is_whnf());
        assert!(Value::float(1.0).is_whnf());
        assert!(Value::bool(false).is_whnf());
        assert!(Value::null().is_whnf());
        assert!(
            Value::string(ptr)
                .expect("aligned string pointer")
                .is_whnf()
        );
        assert!(Value::path(ptr).expect("aligned path pointer").is_whnf());
        assert!(Value::list(ptr).expect("aligned list pointer").is_whnf());
        assert!(Value::attrs(ptr).expect("aligned attrs pointer").is_whnf());
        assert!(
            Value::lambda(ptr)
                .expect("aligned lambda pointer")
                .is_whnf()
        );
        assert!(
            Value::primop(ptr)
                .expect("aligned primop pointer")
                .is_whnf()
        );
        assert!(
            Value::external(ptr)
                .expect("aligned external pointer")
                .is_whnf()
        );
        let thunk = Value::thunk(ptr).expect("aligned thunk pointer");
        assert!(!thunk.is_whnf());
        assert!(thunk.is_thunk());
    }

    #[test]
    fn heap_values_store_aligned_non_null_pointers() {
        let ptr = NonNull::<HeapObject>::dangling();
        let value = Value::attrs(ptr).expect("aligned attrset pointer");
        assert_eq!(value.tag(), ValueTag::Attrs);
        assert_eq!(value.as_attrs_ptr().expect("attrset pointer"), ptr);
        assert_eq!(value.as_heap_ptr().expect("heap pointer"), ptr);
    }

    #[test]
    fn raw_equality_is_explicitly_representation_level() {
        assert!(Value::int(7).raw_eq(Value::int(7)));
        assert!(!Value::int(7).raw_eq(Value::float(7.0)));
    }

    #[test]
    fn payload_identity_accessors_preserve_the_active_value_abi() {
        let ptr = NonNull::<HeapObject>::dangling();
        let thunk = Value::thunk(ptr).expect("aligned thunk pointer");

        assert_eq!(thunk.address_identity_bits(), ptr.as_ptr() as usize as u64);
        assert_eq!(
            thunk.transient_identity_bits(),
            ptr.as_ptr() as usize as u64
        );
        assert_eq!(
            thunk.relocation_sensitive_identity_bits(),
            ptr.as_ptr() as usize as u64
        );
        assert_eq!(
            Value::int(i64::MIN).relocation_sensitive_identity_bits(),
            i64::MIN as u64
        );
        assert_eq!(
            Value::int(i64::MIN).transient_identity_bits(),
            i64::MIN as u64
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn address_identity_rejects_inline_values_in_debug_builds() {
        let _ = Value::int(0).address_identity_bits();
    }

    #[test]
    fn heap_constructors_reject_inline_tags_and_unaligned_pointers() {
        let ptr = NonNull::<HeapObject>::dangling();
        let error =
            Value::heap(ValueTag::Int, ptr).expect_err("inline tag is not a heap value tag");
        assert_eq!(error, ValueError::NotHeapTag { tag: ValueTag::Int });

        let unaligned = NonNull::new(1usize as *mut HeapObject).expect("non-null test pointer");
        let error = Value::string(unaligned).expect_err("unaligned heap pointer is rejected");
        assert_eq!(
            error,
            ValueError::UnalignedHeapPointer {
                tag: ValueTag::String,
                address: 1,
            }
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "invalid Value payload")]
    fn raw_getters_assert_payload_invariants_in_debug_builds() {
        let invalid_bool = Value {
            tag: ValueTag::Bool,
            payload: 2,
        };

        let _ = invalid_bool.tag();
    }

    #[test]
    fn heap_accessors_reject_invalid_raw_pointer_payloads() {
        let null_payload = Value {
            tag: ValueTag::String,
            payload: 0,
        };
        assert_eq!(
            null_payload.as_heap_ptr(),
            Err(ValueError::NullHeapPointer {
                tag: ValueTag::String,
            })
        );

        let unaligned_payload = Value {
            tag: ValueTag::String,
            payload: 1,
        };
        assert_eq!(
            unaligned_payload.as_heap_ptr(),
            Err(ValueError::UnalignedHeapPointer {
                tag: ValueTag::String,
                address: 1,
            })
        );
    }

    #[test]
    fn nix_type_names_match_user_visible_types() {
        assert_eq!(ValueTag::Int.nix_type_name(), Some("int"));
        assert_eq!(ValueTag::Float.nix_type_name(), Some("float"));
        assert_eq!(ValueTag::Bool.nix_type_name(), Some("bool"));
        assert_eq!(ValueTag::Null.nix_type_name(), Some("null"));
        assert_eq!(ValueTag::String.nix_type_name(), Some("string"));
        assert_eq!(ValueTag::Path.nix_type_name(), Some("path"));
        assert_eq!(ValueTag::List.nix_type_name(), Some("list"));
        assert_eq!(ValueTag::Attrs.nix_type_name(), Some("set"));
        assert_eq!(ValueTag::Lambda.nix_type_name(), Some("lambda"));
        assert_eq!(ValueTag::Primop.nix_type_name(), Some("lambda"));
        assert_eq!(ValueTag::External.nix_type_name(), Some("external"));
        assert_eq!(ValueTag::Thunk.nix_type_name(), None);
    }
}
