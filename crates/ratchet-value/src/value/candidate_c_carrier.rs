//! The Candidate-C 8-byte runtime value carrier (RFC-0007 doc 30 §3).
//!
//! Selected by the `candidate_c_value` cargo feature in place of the baseline
//! 16-byte tagged pair in [`super`]. A [`Value`] is one
//! [`CompressedValueWord`](crate::value::compressed::CompressedValueWord): the
//! high 32 bits carry `kind | domain | forced`, the low 32 bits carry an inline
//! `i32` or a `u32` [`ArenaIndex`](crate::heap::ArenaIndex) offset into a
//! reservation. Heap references and boxed scalars name a reservation by its
//! 23-bit domain, so turning a word back into a native pointer needs that
//! reservation's base.
//!
//! # Context-free resolution
//!
//! Heap construction (`ptr → (domain, index)`) and access (`(domain, index) →
//! ptr`) are self-contained here via the process-global reservation base
//! registry ([`crate::heap::reservation_base`] /
//! [`crate::heap::reservation_containing_address`]) — arena-internal hot paths
//! resolve through their own cached base instead. **Scalar boxing has no
//! context-free form**: a 64-bit float and an out-of-`i32`-range integer must
//! allocate a hash-consed cell in a specific reservation, which requires a heap
//! handle. So [`Value::float`] and boxed [`Value::as_float`]/wide
//! [`Value::as_int`] decode do not exist on this carrier; scalar boxing and
//! unboxing funnel through the evaluator heap seam
//! (`EvalHeap::alloc_float_value` / `decode_float_value`). Inline `i32`, `bool`,
//! and `null` stay self-contained.

use std::fmt;
use std::mem;
use std::ptr::NonNull;

use crate::heap::{
    ArenaDomainId, ArenaIndex, GcObjectIdentity, reservation_base, reservation_containing_address,
};
use crate::value::compressed::{CompressedValueKind, CompressedValueWord};

use super::{HeapObject, ValueError, ValueTag};

/// A Nix runtime value represented as one 8-byte Candidate-C compressed word.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Value {
    word: CompressedValueWord,
}

impl Value {
    /// Creates an inline integer value.
    ///
    /// # Panics
    ///
    /// Panics in debug builds when `value` does not fit a signed 32-bit inline
    /// payload. Wider integers must be boxed through the evaluator heap seam
    /// (`EvalHeap::alloc_int_value`), which this carrier cannot do context-free.
    pub fn int(value: i64) -> Self {
        match CompressedValueWord::inline_int(value) {
            Ok(word) => Self { word },
            Err(_) => {
                debug_assert!(
                    false,
                    "Value::int on the Candidate-C carrier requires an i32-range value; \
                     box wider integers through EvalHeap::alloc_int_value"
                );
                // A saturating inline is never reached in a correct build; it
                // keeps the release path total without a silent wrong value in
                // the common (in-range) case.
                Self {
                    word: CompressedValueWord::inline_int(
                        value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)),
                    )
                    .unwrap_or_else(|_| CompressedValueWord::null()),
                }
            }
        }
    }

    /// Creates an inline boolean value.
    pub const fn bool(value: bool) -> Self {
        Self {
            word: CompressedValueWord::boolean(value),
        }
    }

    /// Creates the null singleton value.
    pub const fn null() -> Self {
        Self {
            word: CompressedValueWord::null(),
        }
    }

    /// Creates a heap string value.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotHeapTag`] for an inline tag and
    /// [`ValueError::UnregisteredReservation`] when `ptr` is not inside a live
    /// registered reservation.
    pub fn string(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::String, ptr)
    }

    /// Creates a heap path value.
    ///
    /// # Errors
    ///
    /// See [`Value::heap`].
    pub fn path(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Path, ptr)
    }

    /// Creates a heap list value.
    ///
    /// # Errors
    ///
    /// See [`Value::heap`].
    pub fn list(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::List, ptr)
    }

    /// Creates a heap attribute-set value.
    ///
    /// # Errors
    ///
    /// See [`Value::heap`].
    pub fn attrs(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Attrs, ptr)
    }

    /// Creates a heap lambda value.
    ///
    /// # Errors
    ///
    /// See [`Value::heap`].
    pub fn lambda(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Lambda, ptr)
    }

    /// Creates a heap primop value.
    ///
    /// # Errors
    ///
    /// See [`Value::heap`].
    pub fn primop(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Primop, ptr)
    }

    /// Creates a heap external value.
    ///
    /// # Errors
    ///
    /// See [`Value::heap`].
    pub fn external(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::External, ptr)
    }

    /// Creates a heap thunk value.
    ///
    /// # Errors
    ///
    /// See [`Value::heap`].
    pub fn thunk(ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        Self::heap(ValueTag::Thunk, ptr)
    }

    /// Creates a heap-backed value with `tag` from a raw pointer.
    ///
    /// The pointer is resolved to its `(domain, index)` through the process-wide
    /// reservation base registry, so this is self-contained for context-free
    /// callers. Arena-internal hot paths build the word from their own cached
    /// base via [`Value::from_domain_index`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotHeapTag`] when `tag` is an inline tag, and
    /// [`ValueError::UnregisteredReservation`] when `ptr` is not inside a live
    /// registered reservation.
    pub fn heap(tag: ValueTag, ptr: NonNull<HeapObject>) -> Result<Self, ValueError> {
        if !tag.is_heap() {
            return Err(ValueError::NotHeapTag { tag });
        }
        let address = ptr.as_ptr() as usize;
        let (domain, base) = reservation_containing_address(address)
            .ok_or(ValueError::UnregisteredReservation { address })?;
        let index = ArenaIndex::new((address - base) as u32);
        let word = CompressedValueWord::heap(domain, tag, index)
            .map_err(|_| ValueError::NotHeapTag { tag })?;
        Ok(Self { word })
    }

    /// Builds a heap value directly from a reservation `(domain, index)`.
    ///
    /// This is the arena hot-path constructor: a heap that just allocated an
    /// object holds the domain and index already, so it skips the registry
    /// reverse lookup [`Value::heap`] would perform.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotHeapTag`] when `tag` is an inline tag.
    pub fn from_domain_index(
        tag: ValueTag,
        domain: ArenaDomainId,
        index: ArenaIndex,
    ) -> Result<Self, ValueError> {
        let word = CompressedValueWord::heap(domain, tag, index)
            .map_err(|_| ValueError::NotHeapTag { tag })?;
        Ok(Self { word })
    }

    /// Builds a boxed-scalar value directly from its reservation word.
    ///
    /// The evaluator heap seam constructs boxed `i64`/`f64` words after
    /// allocating a cell; this wraps such a validated word as a [`Value`].
    pub const fn from_word(word: CompressedValueWord) -> Self {
        Self { word }
    }

    /// Rebuilds a value from a raw word already validated by its owning cell.
    ///
    /// # Safety
    ///
    /// `raw` must be the intact encoding of a previously constructed
    /// [`Value`]. See [`CompressedValueWord::from_raw_unchecked`] for the
    /// complete representation invariants.
    #[inline]
    pub const unsafe fn from_validated_raw_unchecked(raw: u64) -> Self {
        // SAFETY: the caller promises the complete Candidate-C word contract.
        let word = unsafe { CompressedValueWord::from_raw_unchecked(raw) };
        Self { word }
    }

    /// Returns the underlying compressed word.
    pub const fn word(self) -> CompressedValueWord {
        self.word
    }

    /// Returns canonical object identity when this value names an indexed cell.
    ///
    /// Boxed integers and floats have identity because they name arena cells.
    /// Inline integers, booleans, and null return `None`. The thunk `FORCED`
    /// shortcut is normalized away, so forcing does not change object identity.
    #[inline]
    pub fn object_identity(self) -> Option<GcObjectIdentity> {
        GcObjectIdentity::from_word(self.word)
    }

    /// Returns the encoding kind byte (the low 8 bits of the high half).
    #[inline]
    const fn kind_byte(self) -> u8 {
        (self.word.raw() >> 32) as u8
    }

    /// Returns this value's semantic runtime tag.
    ///
    /// Const so it stays usable from the `const fn` classifiers that the
    /// baseline carrier's `tag` supported (GC root scanning, WHNF fast path).
    #[inline]
    pub const fn tag(self) -> ValueTag {
        match self.kind_byte() {
            // InlineInt (0x00) and BoxedInt (0x30) are both `int`.
            0x00 | 0x30 => ValueTag::Int,
            0x01 => ValueTag::Float,
            0x02 => ValueTag::Bool,
            0x03 => ValueTag::Null,
            0x10 => ValueTag::String,
            0x11 => ValueTag::Path,
            0x12 => ValueTag::List,
            0x13 => ValueTag::Attrs,
            0x14 => ValueTag::Lambda,
            0x15 => ValueTag::Primop,
            0x16 => ValueTag::External,
            // Thunk (0x20); any other byte is unreachable for a validated word.
            _ => ValueTag::Thunk,
        }
    }

    /// Returns the raw 8-byte word as identity/diagnostic bits.
    #[inline]
    pub const fn payload_bits(self) -> u64 {
        self.word.raw()
    }

    /// Returns the representation-identity bits (the raw word).
    ///
    /// # Panics
    ///
    /// Panics in debug builds when this is not a heap-backed value.
    pub fn address_identity_bits(self) -> u64 {
        debug_assert!(self.word.semantic_tag().is_heap());
        self.word.raw()
    }

    /// Returns the representation-identity bits within a no-relocation interval.
    pub const fn transient_identity_bits(self) -> u64 {
        self.word.raw()
    }

    /// Returns representation-identity bits that require relocation repair.
    ///
    /// On the Candidate-C carrier the whole word is the identity: a moving
    /// collector rewrites the index half, so retained words participate in the
    /// same writeback protocol as the baseline carrier's addresses.
    #[inline]
    pub const fn relocation_sensitive_identity_bits(self) -> u64 {
        self.word.raw()
    }

    /// Returns raw representation equality (not Nix semantic equality).
    #[inline]
    pub const fn raw_eq(self, other: Self) -> bool {
        self.word.raw() == other.word.raw()
    }

    /// Returns whether this value is already in weak head normal form.
    #[inline]
    pub const fn is_whnf(self) -> bool {
        self.kind_byte() != 0x20
    }

    /// Returns whether this value is a thunk.
    #[inline]
    pub const fn is_thunk(self) -> bool {
        self.kind_byte() == 0x20
    }

    /// Returns whether this value is a thunk already marked forced.
    #[inline]
    pub const fn is_forced_thunk(self) -> bool {
        self.word.is_forced_thunk()
    }

    /// Returns this thunk word with the forced shortcut set.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotHeapTag`] with the thunk tag when this is not a
    /// thunk value.
    pub fn with_forced_bit(self) -> Result<Self, ValueError> {
        self.word
            .with_forced_bit()
            .map(|word| Self { word })
            .map_err(|_| ValueError::NotHeapTag {
                tag: ValueTag::Thunk,
            })
    }

    /// Checks that the word is a valid representation for its kind.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the word does not satisfy the Candidate-C
    /// codec invariants.
    pub fn validate_payload(self) -> Result<(), ValueError> {
        CompressedValueWord::from_raw(self.word.raw())
            .map(|_| ())
            .map_err(|_| ValueError::InvalidNullPayload {
                payload: self.word.raw(),
            })
    }

    /// Returns the inline integer payload.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not an inline integer.
    /// Boxed (wide) integers are not decodable context-free and must go through
    /// `EvalHeap::decode_int_value`; this returns
    /// [`ValueError::BoxedScalarRequiresHeap`] for them.
    pub fn as_int(self) -> Result<i64, ValueError> {
        match self.word.kind() {
            CompressedValueKind::InlineInt => self.word.as_inline_int().ok_or(ValueError::Type {
                expected: "int",
                actual: ValueTag::Int,
            }),
            CompressedValueKind::BoxedInt => {
                Err(ValueError::BoxedScalarRequiresHeap { kind: "int" })
            }
            _ => Err(ValueError::Type {
                expected: "int",
                actual: self.word.semantic_tag(),
            }),
        }
    }

    /// Returns the inline boolean payload.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not a boolean.
    pub fn as_bool(self) -> Result<bool, ValueError> {
        self.word.as_bool().ok_or(ValueError::Type {
            expected: "bool",
            actual: self.word.semantic_tag(),
        })
    }

    /// Returns `Ok(())` when this value is null.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not null.
    pub fn as_null(self) -> Result<(), ValueError> {
        if self.word.kind() == CompressedValueKind::Null {
            Ok(())
        } else {
            Err(ValueError::Type {
                expected: "null",
                actual: self.word.semantic_tag(),
            })
        }
    }

    /// Returns the native heap pointer for any heap-backed value.
    ///
    /// Resolves `(domain, index)` to `reservation_base(domain) + index` through
    /// the process-wide registry, so it is self-contained for context-free
    /// callers.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotHeapTag`] when this value is inline, and
    /// [`ValueError::UnregisteredReservation`] when the word's domain is not a
    /// live registered reservation.
    // Inlined across the ratchet-value -> ratchet-oracle boundary: this is the
    // per-touch heap-resolve accessor on the hot force/apply spine and was
    // observed crossing out-of-line at several call sites (RFC-0007 §P1 ledger
    // lever 5); inlining removes the call plus a redundant tag re-decode.
    #[inline]
    pub fn as_heap_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        let tag = self.word.semantic_tag();
        if !tag.is_heap() {
            return Err(ValueError::NotHeapTag { tag });
        }
        let domain = self
            .word
            .arena_domain()
            .ok_or(ValueError::NotHeapTag { tag })?;
        let index = self
            .word
            .arena_index()
            .ok_or(ValueError::NotHeapTag { tag })?;
        let base = reservation_base(domain).ok_or(ValueError::UnregisteredReservation {
            address: index.raw() as usize,
        })?;
        let address = base + index.raw() as usize;
        NonNull::new(address as *mut HeapObject).ok_or(ValueError::NullHeapPointer { tag })
    }

    /// Returns the heap string pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not a string, else as
    /// [`Value::as_heap_ptr`].
    pub fn as_string_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::String, "string")
    }

    /// Returns the heap path pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not a path.
    pub fn as_path_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Path, "path")
    }

    /// Returns the heap list pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not a list.
    pub fn as_list_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::List, "list")
    }

    /// Returns the heap attrset pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not an attrset.
    pub fn as_attrs_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Attrs, "attrs")
    }

    /// Returns the heap lambda pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not a lambda.
    pub fn as_lambda_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Lambda, "lambda")
    }

    /// Returns the heap primop pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not a primop.
    pub fn as_primop_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Primop, "primop")
    }

    /// Returns the heap external pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not external.
    pub fn as_external_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::External, "external")
    }

    /// Returns the heap thunk pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Type`] when this value is not a thunk.
    pub fn as_thunk_ptr(self) -> Result<NonNull<HeapObject>, ValueError> {
        self.expect_heap_tag(ValueTag::Thunk, "thunk")
    }

    #[inline]
    fn expect_heap_tag(
        self,
        expected: ValueTag,
        expected_name: &'static str,
    ) -> Result<NonNull<HeapObject>, ValueError> {
        if self.word.semantic_tag() != expected {
            return Err(ValueError::Type {
                expected: expected_name,
                actual: self.word.semantic_tag(),
            });
        }
        self.as_heap_ptr()
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Value")
            .field("kind", &self.word.kind())
            .field("word", &format_args!("0x{:016x}", self.word.raw()))
            .finish()
    }
}

const _: () = {
    assert!(mem::size_of::<Value>() == 8);
    assert!(mem::align_of::<Value>() == 8);
};
