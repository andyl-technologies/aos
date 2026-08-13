//! Context-owned conversion between active values and Candidate-B words.
//!
//! Candidate B keeps scalar immediates and aligned heap addresses in one word.
//! The codec checks word shape; [`EvalHeap`] proves that an address names a
//! typed object in the receiving heap and owns the shared boxed-scalar cells.

use std::ptr::NonNull;

use crate::heap::flat::FlatObjectKind;
use crate::value::tag::{
    CandidateBValueError, TaggedValueKind, TaggedValueWord, TaggedValueWordError,
};
use crate::value::{HeapObject, Value, ValueTag};

use super::super::EvalHeap;

impl EvalHeap {
    /// Encodes an integer through Candidate B's immediate or boxed form.
    ///
    /// # Errors
    ///
    /// Returns an error when a wide integer cell cannot be allocated or its
    /// pointer cannot be represented by the tagged word.
    pub fn candidate_b_encode_int(
        &mut self,
        value: i64,
    ) -> Result<TaggedValueWord, CandidateBValueError> {
        match TaggedValueWord::inline_int(value) {
            Ok(word) => return Ok(word),
            Err(TaggedValueWordError::IntegerOutOfRange { .. }) => {}
            Err(source) => return Err(source.into()),
        }
        let ptr = self.candidate_b_box_int_pointer(value)?;
        Ok(TaggedValueWord::heap(ptr)?)
    }

    /// Encodes a float through Candidate B's boxed exact-bit form.
    ///
    /// # Errors
    ///
    /// Returns an error when the float cell cannot be allocated or its pointer
    /// cannot be represented by the tagged word.
    pub fn candidate_b_encode_float(
        &mut self,
        value: f64,
    ) -> Result<TaggedValueWord, CandidateBValueError> {
        let ptr = self.candidate_b_box_float_pointer(value)?;
        Ok(TaggedValueWord::heap(ptr)?)
    }

    /// Decodes a Candidate-B immediate or boxed integer.
    ///
    /// # Errors
    ///
    /// Returns an error when `word` is not an integer or its boxed address is
    /// not a typed integer cell owned by this heap.
    pub fn candidate_b_decode_int(
        &self,
        word: TaggedValueWord,
    ) -> Result<i64, CandidateBValueError> {
        if let Some(value) = word.as_inline_int() {
            return Ok(value);
        }
        let ptr = candidate_b_pointer(word, "integer")?;
        Ok(self.candidate_b_decode_int_pointer(ptr)?)
    }

    /// Decodes a Candidate-B boxed float without normalizing its bit pattern.
    ///
    /// # Errors
    ///
    /// Returns an error when `word` is not a heap word or its address is not a
    /// typed float cell owned by this heap.
    pub fn candidate_b_decode_float(
        &self,
        word: TaggedValueWord,
    ) -> Result<f64, CandidateBValueError> {
        let ptr = candidate_b_pointer(word, "float")?;
        Ok(self.candidate_b_decode_float_pointer(ptr)?)
    }

    /// Encodes one active value as an inactive Candidate-B word.
    ///
    /// Heap values are accepted only when their pointer names a live typed flat
    /// object in this serial heap or its shared arena. Legacy records and
    /// external handles remain unsupported.
    ///
    /// # Errors
    ///
    /// Returns an error when a scalar cannot be boxed or a heap pointer is not
    /// a matching published object in this heap.
    pub fn candidate_b_encode_value(
        &mut self,
        value: Value,
    ) -> Result<TaggedValueWord, CandidateBValueError> {
        let tag = value.tag();
        match tag {
            ValueTag::Int => self.candidate_b_encode_int(value.as_int()?),
            ValueTag::Float => self.candidate_b_encode_float(value.as_float()?),
            ValueTag::Bool => Ok(TaggedValueWord::boolean(value.as_bool()?)),
            ValueTag::Null => {
                value.as_null()?;
                Ok(TaggedValueWord::null())
            }
            tag => {
                let ptr = value.as_heap_ptr()?;
                if self.candidate_b_flat_tag(ptr) != Some(tag) {
                    return Err(CandidateBValueError::HeapPointerNotPublished {
                        tag,
                        address: ptr.as_ptr().expose_provenance(),
                    });
                }
                Ok(TaggedValueWord::heap(ptr)?)
            }
        }
    }

    /// Decodes an inactive Candidate-B word into the active value ABI.
    ///
    /// Boxed scalar addresses are unboxed; other heap addresses must resolve
    /// through a typed flat store. Forced-thunk words are rejected because the
    /// active [`Value`] has no lossless carrier for the shortcut bit.
    ///
    /// # Errors
    ///
    /// Returns an error when a boxed scalar or heap address is not owned by
    /// this heap, or when the word carries the forced-thunk shortcut.
    pub fn candidate_b_decode_value(
        &self,
        word: TaggedValueWord,
    ) -> Result<Value, CandidateBValueError> {
        match word.kind()? {
            TaggedValueKind::InlineInt => Ok(Value::int(word.as_inline_int().ok_or(
                CandidateBValueError::KindMismatch {
                    expected: "integer",
                    actual: TaggedValueKind::InlineInt,
                },
            )?)),
            TaggedValueKind::Bool => Ok(Value::bool(word.as_bool().ok_or(
                CandidateBValueError::KindMismatch {
                    expected: "boolean",
                    actual: TaggedValueKind::Bool,
                },
            )?)),
            TaggedValueKind::Null => Ok(Value::null()),
            TaggedValueKind::ForcedThunk => Err(CandidateBValueError::ForcedThunkUnsupported),
            TaggedValueKind::Heap => {
                let ptr = candidate_b_pointer(word, "heap value")?;
                match self.candidate_b_scalar_kind(ptr) {
                    Some(FlatObjectKind::BoxedInt) => {
                        Ok(Value::int(self.candidate_b_decode_int_pointer(ptr)?))
                    }
                    Some(FlatObjectKind::BoxedFloat) => {
                        Ok(Value::float(self.candidate_b_decode_float_pointer(ptr)?))
                    }
                    _ => {
                        let tag = self.candidate_b_flat_tag(ptr).ok_or(
                            CandidateBValueError::HeapAddressNotPublished {
                                address: ptr.as_ptr().expose_provenance(),
                            },
                        )?;
                        Ok(Value::heap(tag, ptr)?)
                    }
                }
            }
        }
    }

    fn candidate_b_box_int_pointer(
        &mut self,
        value: i64,
    ) -> Result<NonNull<HeapObject>, CandidateBValueError> {
        match &self.shared {
            Some(shared) => Ok(shared.arena().candidate_b_box_int_pointer(value)?),
            None => Ok(self.compressed_scalars.box_int_pointer(value)?),
        }
    }

    fn candidate_b_box_float_pointer(
        &mut self,
        value: f64,
    ) -> Result<NonNull<HeapObject>, CandidateBValueError> {
        match &self.shared {
            Some(shared) => Ok(shared.arena().candidate_b_box_float_pointer(value)?),
            None => Ok(self.compressed_scalars.box_float_pointer(value)?),
        }
    }

    fn candidate_b_decode_int_pointer(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<i64, CandidateBValueError> {
        match &self.shared {
            Some(shared) => Ok(shared.arena().candidate_b_decode_int_pointer(ptr)?),
            None => Ok(self.compressed_scalars.decode_int_pointer(ptr)?),
        }
    }

    fn candidate_b_decode_float_pointer(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<f64, CandidateBValueError> {
        match &self.shared {
            Some(shared) => Ok(shared.arena().candidate_b_decode_float_pointer(ptr)?),
            None => Ok(self.compressed_scalars.decode_float_pointer(ptr)?),
        }
    }

    fn candidate_b_scalar_kind(&self, ptr: NonNull<HeapObject>) -> Option<FlatObjectKind> {
        match &self.shared {
            Some(shared) => shared.arena().candidate_b_scalar_kind(ptr),
            None => self.compressed_scalars.kind_of_pointer(ptr),
        }
    }

    fn candidate_b_flat_tag(&self, ptr: NonNull<HeapObject>) -> Option<ValueTag> {
        match &self.shared {
            Some(shared) => shared.flat_tag_at(ptr),
            None => self.flat_kind_tag(ptr),
        }
    }
}

fn candidate_b_pointer(
    word: TaggedValueWord,
    expected: &'static str,
) -> Result<NonNull<HeapObject>, CandidateBValueError> {
    let actual = word.kind()?;
    let address = word
        .heap_address()?
        .ok_or(CandidateBValueError::KindMismatch { expected, actual })?
        .address_bits();
    NonNull::new(std::ptr::with_exposed_provenance_mut(address))
        .ok_or(CandidateBValueError::HeapAddressNotPublished { address })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::compile::IrId;
    use crate::eval::heap::{EvalThunk, SharedHeapArena};
    use crate::string::NixString;
    use crate::value::compressed::CandidateCScalarError;
    use crate::value::tag::{TAGGED_IMMEDIATE_INT_MAX, TAGGED_IMMEDIATE_INT_MIN};

    #[test]
    fn serial_bridge_roundtrips_immediates_boxed_scalars_and_heap_values() {
        let mut heap = EvalHeap::new();
        let string = heap
            .alloc_string(NixString::from_bytes(b"candidate-b".to_vec()))
            .expect("string allocates");
        let thunk = heap
            .alloc_thunk(EvalThunk::new(IrId::new(11)))
            .expect("thunk allocates");
        let nan = f64::from_bits(0x7ff8_0000_0000_0042);
        let values = [
            Value::int(TAGGED_IMMEDIATE_INT_MIN),
            Value::int(TAGGED_IMMEDIATE_INT_MAX),
            Value::int(i64::MIN),
            Value::int(i64::MAX),
            Value::float(-0.0),
            Value::float(nan),
            Value::bool(true),
            Value::null(),
            string,
            thunk,
        ];

        for value in values {
            let word = heap.candidate_b_encode_value(value).expect("value encodes");
            let decoded = heap.candidate_b_decode_value(word).expect("word decodes");
            assert!(decoded.raw_eq(value));
        }
    }

    #[test]
    fn boxed_scalars_hash_cons_exact_values() {
        let mut heap = EvalHeap::new();
        let int = heap
            .candidate_b_encode_int(i64::MAX)
            .expect("wide integer boxes");
        let same_int = heap
            .candidate_b_encode_int(i64::MAX)
            .expect("wide integer reuses");
        let nan = f64::from_bits(0x7ff8_0000_0000_0042);
        let float = heap.candidate_b_encode_float(nan).expect("float boxes");
        let same_float = heap.candidate_b_encode_float(nan).expect("float reuses");

        assert_eq!(int, same_int);
        assert_eq!(float, same_float);
        assert_eq!(
            heap.candidate_b_decode_int(int).expect("integer decodes"),
            i64::MAX
        );
        assert_eq!(
            heap.candidate_b_decode_float(float)
                .expect("float decodes")
                .to_bits(),
            nan.to_bits()
        );
    }

    #[test]
    fn chunked_compatibility_heap_supports_candidate_b_boxes_and_objects() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(4096).expect("chunked heap builds");
        let wide = heap
            .candidate_b_encode_value(Value::int(i64::MAX))
            .expect("wide integer boxes without a reservation");
        let float = heap
            .candidate_b_encode_value(Value::float(-0.0))
            .expect("float boxes without a reservation");
        let string = heap
            .alloc_string(NixString::from_bytes(b"chunked".to_vec()))
            .expect("string allocates");
        let string_word = heap
            .candidate_b_encode_value(string)
            .expect("chunked flat object encodes");

        assert!(
            heap.candidate_b_decode_value(wide)
                .expect("wide integer decodes")
                .raw_eq(Value::int(i64::MAX))
        );
        assert_eq!(
            heap.candidate_b_decode_value(float)
                .expect("float decodes")
                .as_float()
                .expect("decoded value is a float")
                .to_bits(),
            (-0.0f64).to_bits()
        );
        assert!(
            heap.candidate_b_decode_value(string_word)
                .expect("string decodes")
                .raw_eq(string)
        );
    }

    #[test]
    fn shared_workers_cross_decode_boxed_scalars_and_heap_values() {
        let arena = Arc::new(SharedHeapArena::new(2, 32));
        let mut first = EvalHeap::with_shared_shard(
            Arc::clone(&arena),
            Arc::clone(arena.shard(0).expect("first shard exists")),
        );
        let second = EvalHeap::with_shared_shard(
            Arc::clone(&arena),
            Arc::clone(arena.shard(1).expect("second shard exists")),
        );
        let wide = first
            .candidate_b_encode_value(Value::int(i64::MAX))
            .expect("wide integer encodes");
        let float = first
            .candidate_b_encode_value(Value::float(-0.0))
            .expect("float encodes");
        let string = first
            .alloc_string(NixString::from_bytes(b"shared-b".to_vec()))
            .expect("string allocates");
        let string_word = first
            .candidate_b_encode_value(string)
            .expect("string encodes");

        assert!(
            second
                .candidate_b_decode_value(wide)
                .expect("other worker decodes integer")
                .raw_eq(Value::int(i64::MAX))
        );
        assert_eq!(
            second
                .candidate_b_decode_value(float)
                .expect("other worker decodes float")
                .as_float()
                .expect("decoded value is a float")
                .to_bits(),
            (-0.0f64).to_bits()
        );
        assert!(
            second
                .candidate_b_decode_value(string_word)
                .expect("other worker decodes string")
                .raw_eq(string)
        );
        assert_eq!(arena.published_len(), 3);
        assert_eq!(arena.published_payload_bytes(), 16 + b"shared-b".len());
    }

    #[test]
    fn decoder_rejects_addresses_from_another_live_heap() {
        let mut source = EvalHeap::new();
        let receiver = EvalHeap::new();
        let scalar = source
            .candidate_b_encode_value(Value::int(i64::MAX))
            .expect("source scalar encodes");
        let string = source
            .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
            .expect("source string allocates");
        let heap_word = source
            .candidate_b_encode_value(string)
            .expect("source string encodes");

        assert!(matches!(
            receiver.candidate_b_decode_value(scalar),
            Err(CandidateBValueError::HeapAddressNotPublished { .. })
        ));
        assert!(matches!(
            receiver.candidate_b_decode_value(heap_word),
            Err(CandidateBValueError::HeapAddressNotPublished { .. })
        ));
    }

    #[test]
    fn typed_scalar_decoders_reject_the_other_boxed_population() {
        let mut heap = EvalHeap::new();
        let int = heap
            .candidate_b_encode_int(i64::MAX)
            .expect("integer boxes");
        let float = heap.candidate_b_encode_float(1.5).expect("float boxes");

        assert!(matches!(
            heap.candidate_b_decode_float(int),
            Err(CandidateBValueError::Scalar(CandidateCScalarError::Flat(_)))
        ));
        assert!(matches!(
            heap.candidate_b_decode_int(float),
            Err(CandidateBValueError::Scalar(CandidateCScalarError::Flat(_)))
        ));
    }

    #[test]
    fn bridge_rejects_forced_thunk_until_active_abi_can_preserve_it() {
        let mut heap = EvalHeap::new();
        let thunk = heap
            .alloc_thunk(EvalThunk::new(IrId::new(19)))
            .expect("thunk allocates");
        let ptr = thunk.as_heap_ptr().expect("thunk carries a pointer");
        let forced = TaggedValueWord::forced_thunk(ptr).expect("forced pointer encodes");

        assert!(matches!(
            heap.candidate_b_decode_value(forced),
            Err(CandidateBValueError::ForcedThunkUnsupported)
        ));
    }
}
