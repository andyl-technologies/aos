//! Candidate-C compressed runtime value words.
//!
//! RFC-0007 doc 30 section 3 assigns Candidate C one 64-bit word split into a
//! 32-bit kind/metadata half and a 32-bit payload half. Heap payloads are
//! offsets in one [`ReservedArena`](crate::heap::ReservedArena), not pointer
//! bits. Signed 32-bit integers remain immediate; wider integers and every
//! float use typed boxed-scalar indices. Bit 31 of the kind half is the thunk
//! `FORCED` shortcut.
//!
//! This is the sealed codec boundary for the measured variant. The active
//! evaluator still uses [`Value`](super::Value); switching the runtime and JIT
//! ABI is a later, separately gated step.

use thiserror::Error;

use crate::heap::ArenaIndex;

use super::ValueTag;

/// Metadata bit marking an already-forced thunk index.
pub const COMPRESSED_FORCED_BIT: u32 = 1 << 31;
const KIND_MASK: u32 = !COMPRESSED_FORCED_BIT;

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
    pub const fn boxed_int(index: ArenaIndex) -> Self {
        Self::compose(CompressedValueKind::BoxedInt, index.raw())
    }

    /// Encodes an arena index for a boxed IEEE-754 double.
    pub const fn boxed_float(index: ArenaIndex) -> Self {
        Self::compose(CompressedValueKind::BoxedFloat, index.raw())
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
    pub fn heap(tag: ValueTag, index: ArenaIndex) -> Result<Self, CompressedValueError> {
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
        Ok(Self::compose(kind, index.raw()))
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
        let forced = kind_and_flags & COMPRESSED_FORCED_BIT != 0;
        if forced && kind != CompressedValueKind::Thunk {
            return Err(CompressedValueError::ForcedBitOnNonThunk { kind });
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
        let index = ArenaIndex::new(0xfeed_beef);
        let list = CompressedValueWord::heap(ValueTag::List, index).expect("list is heap-backed");
        assert_eq!(list.arena_index(), Some(index));
        assert_eq!(list.semantic_tag(), ValueTag::List);

        let thunk = CompressedValueWord::heap(ValueTag::Thunk, index)
            .expect("thunk is heap-backed")
            .with_forced_bit()
            .expect("thunk accepts forced bit");
        assert!(thunk.is_forced_thunk());
        assert_eq!(CompressedValueWord::from_raw(thunk.raw()), Ok(thunk));
        assert_eq!(thunk.arena_index(), Some(index));
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
    }
}
