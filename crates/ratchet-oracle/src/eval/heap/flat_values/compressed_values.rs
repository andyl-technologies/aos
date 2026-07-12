//! Context-owned conversion between active values and Candidate-C words.
//!
//! The sealed word codec knows representation shape, while [`EvalHeap`] owns
//! the typed-membership proof needed to translate native heap pointers into
//! reservation offsets. These inactive seams exercise the complete serial and
//! parallel conversion boundary without changing the active 16-byte ABI.

use crate::heap::{ArenaDomainId, ArenaIndex};
use crate::value::compressed::{CandidateCValueError, CompressedValueKind, CompressedValueWord};
use crate::value::{HeapObject, Value, ValueTag};

use super::super::EvalHeap;

impl EvalHeap {
    /// Encodes one active value as an inactive Candidate-C word.
    ///
    /// Heap values are accepted only when their pointer names a live typed
    /// flat object in this serial heap or its shared arena. Legacy record
    /// placement and external handles remain unsupported.
    ///
    /// # Errors
    ///
    /// Returns an error when a scalar cannot be boxed, the heap has no
    /// reservation backend, or a heap pointer is not a matching published
    /// object in this heap.
    pub fn candidate_c_encode_value(
        &mut self,
        value: Value,
    ) -> Result<CompressedValueWord, CandidateCValueError> {
        let tag = value.tag();
        match tag {
            ValueTag::Int => Ok(self.candidate_c_encode_int(value.as_int()?)?),
            ValueTag::Float => Ok(self.candidate_c_encode_float(value.as_float()?)?),
            ValueTag::Bool => Ok(CompressedValueWord::boolean(value.as_bool()?)),
            ValueTag::Null => {
                value.as_null()?;
                Ok(CompressedValueWord::null())
            }
            tag => {
                let ptr = value.as_heap_ptr()?;
                let (domain, index) = self.candidate_c_heap_location(tag, ptr)?;
                Ok(CompressedValueWord::heap(domain, tag, index)?)
            }
        }
    }

    /// Decodes an inactive Candidate-C word into the active value ABI.
    ///
    /// The reservation domain is checked before reconstructing a native
    /// pointer, then the pointer must resolve through the expected typed flat
    /// store. Forced-thunk words are rejected because active [`Value`] has no
    /// lossless carrier for the shortcut bit.
    ///
    /// # Errors
    ///
    /// Returns an error when a boxed scalar cannot be resolved, the word names
    /// another reservation domain, its heap index is not a matching published
    /// object, or it carries the forced-thunk shortcut.
    pub fn candidate_c_decode_value(
        &self,
        word: CompressedValueWord,
    ) -> Result<Value, CandidateCValueError> {
        match word.kind() {
            CompressedValueKind::InlineInt | CompressedValueKind::BoxedInt => {
                Ok(Value::int(self.candidate_c_decode_int(word)?))
            }
            CompressedValueKind::BoxedFloat => {
                Ok(Value::float(self.candidate_c_decode_float(word)?))
            }
            CompressedValueKind::Bool => Ok(Value::bool(word.payload() != 0)),
            CompressedValueKind::Null => Ok(Value::null()),
            _ if word.is_forced_thunk() => Err(CandidateCValueError::ForcedThunkUnsupported),
            _ => {
                let tag = word.semantic_tag();
                let index =
                    word.arena_index()
                        .ok_or(CandidateCValueError::HeapIndexNotPublished {
                            tag,
                            index: word.payload(),
                        })?;
                let domain =
                    word.arena_domain()
                        .ok_or(CandidateCValueError::HeapIndexNotPublished {
                            tag,
                            index: index.raw(),
                        })?;
                let ptr = self.candidate_c_heap_pointer(tag, domain, index)?;
                Ok(Value::heap(tag, ptr)?)
            }
        }
    }

    fn candidate_c_heap_location(
        &self,
        tag: ValueTag,
        ptr: std::ptr::NonNull<HeapObject>,
    ) -> Result<(ArenaDomainId, ArenaIndex), CandidateCValueError> {
        if self.candidate_c_flat_tag(ptr) != Some(tag) {
            return Err(CandidateCValueError::HeapPointerNotPublished {
                tag,
                address: ptr.as_ptr() as usize,
            });
        }
        let domain = self.candidate_c_domain_id()?;
        let index = self.candidate_c_index_for_pointer(ptr).ok_or(
            CandidateCValueError::HeapPointerNotPublished {
                tag,
                address: ptr.as_ptr() as usize,
            },
        )?;
        Ok((domain, index))
    }

    fn candidate_c_heap_pointer(
        &self,
        tag: ValueTag,
        actual_domain: ArenaDomainId,
        index: ArenaIndex,
    ) -> Result<std::ptr::NonNull<HeapObject>, CandidateCValueError> {
        let expected_domain = self.candidate_c_domain_id()?;
        if actual_domain != expected_domain {
            return Err(CandidateCValueError::ArenaDomainMismatch {
                expected: expected_domain.raw(),
                actual: actual_domain.raw(),
            });
        }
        let ptr = self.candidate_c_pointer_for_index(index).ok_or(
            CandidateCValueError::HeapIndexNotPublished {
                tag,
                index: index.raw(),
            },
        )?;
        if self.candidate_c_flat_tag(ptr) != Some(tag) {
            return Err(CandidateCValueError::HeapIndexNotPublished {
                tag,
                index: index.raw(),
            });
        }
        Ok(ptr)
    }

    fn candidate_c_domain_id(&self) -> Result<ArenaDomainId, CandidateCValueError> {
        let domain = match &self.shared {
            Some(shared) => shared.arena().candidate_c_domain_id(),
            None => self.flat_arena.arena_domain_id(),
        };
        domain.ok_or(CandidateCValueError::ReservationUnavailable)
    }

    fn candidate_c_index_for_pointer(
        &self,
        ptr: std::ptr::NonNull<HeapObject>,
    ) -> Option<ArenaIndex> {
        match &self.shared {
            Some(shared) => shared.arena().candidate_c_index_for_pointer(ptr),
            None => self.flat_arena.index_for_pointer(ptr),
        }
    }

    fn candidate_c_pointer_for_index(
        &self,
        index: ArenaIndex,
    ) -> Option<std::ptr::NonNull<HeapObject>> {
        match &self.shared {
            Some(shared) => shared.arena().candidate_c_pointer_for_index(index),
            None => self.flat_arena.pointer_for_index(index),
        }
    }

    fn candidate_c_flat_tag(&self, ptr: std::ptr::NonNull<HeapObject>) -> Option<ValueTag> {
        match &self.shared {
            Some(shared) => shared.flat_tag_at(ptr),
            None => self.flat_kind_tag(ptr),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::compile::IrId;
    use crate::eval::heap::{EvalThunk, SharedHeapArena};
    use crate::list::NixList;
    use crate::string::NixString;

    #[test]
    fn serial_bridge_roundtrips_scalars_and_flat_heap_values() {
        let mut heap = EvalHeap::new();
        let string = heap
            .alloc_string(NixString::from_bytes(b"candidate-c".to_vec()))
            .expect("string allocates");
        let thunk = heap
            .alloc_thunk(EvalThunk::new(IrId::new(7)))
            .expect("thunk allocates");
        let values = [
            Value::int(i64::MAX),
            Value::float(-0.0),
            Value::bool(true),
            Value::null(),
            string,
            thunk,
        ];

        for value in values {
            let word = heap.candidate_c_encode_value(value).expect("value encodes");
            let decoded = heap.candidate_c_decode_value(word).expect("word decodes");
            assert!(decoded.raw_eq(value));
        }
    }

    #[test]
    fn shared_workers_cross_decode_heap_values() {
        let arena = Arc::new(SharedHeapArena::new(2, 32));
        let mut first = EvalHeap::with_shared_shard(
            Arc::clone(&arena),
            Arc::clone(arena.shard(0).expect("first shard exists")),
        );
        let second = EvalHeap::with_shared_shard(
            Arc::clone(&arena),
            Arc::clone(arena.shard(1).expect("second shard exists")),
        );
        let value = first
            .alloc_string(NixString::from_bytes(b"shared-word".to_vec()))
            .expect("string allocates");
        let word = first
            .candidate_c_encode_value(value)
            .expect("value encodes");

        assert!(
            second
                .candidate_c_decode_value(word)
                .expect("other worker decodes")
                .raw_eq(value)
        );
    }

    #[test]
    fn bridge_rejects_another_heap_domain_before_pointer_reconstruction() {
        let mut left = EvalHeap::new();
        let right = EvalHeap::new();
        let value = left
            .alloc_string(NixString::from_bytes(b"left".to_vec()))
            .expect("string allocates");
        let word = left.candidate_c_encode_value(value).expect("value encodes");

        assert!(matches!(
            right.candidate_c_decode_value(word),
            Err(CandidateCValueError::ArenaDomainMismatch { .. })
        ));
    }

    #[test]
    fn bridge_rejects_same_domain_index_under_the_wrong_heap_kind() {
        let mut heap = EvalHeap::new();
        let value = heap
            .alloc_string(NixString::from_bytes(b"typed".to_vec()))
            .expect("string allocates");
        let string_word = heap
            .candidate_c_encode_value(value)
            .expect("string encodes");
        let wrong_kind = CompressedValueWord::heap(
            string_word.arena_domain().expect("heap word has domain"),
            ValueTag::Path,
            string_word.arena_index().expect("heap word has index"),
        )
        .expect("path kind encodes");

        assert!(matches!(
            heap.candidate_c_decode_value(wrong_kind),
            Err(CandidateCValueError::HeapIndexNotPublished {
                tag: ValueTag::Path,
                ..
            })
        ));
    }

    #[test]
    fn bridge_rejects_forced_thunk_until_the_active_abi_can_preserve_it() {
        let mut heap = EvalHeap::new();
        let value = heap
            .alloc_thunk(EvalThunk::new(IrId::new(9)))
            .expect("thunk allocates");
        let word = heap
            .candidate_c_encode_value(value)
            .expect("thunk encodes")
            .with_forced_bit()
            .expect("thunk accepts forced bit");

        assert!(matches!(
            heap.candidate_c_decode_value(word),
            Err(CandidateCValueError::ForcedThunkUnsupported)
        ));
    }

    #[test]
    fn bridge_rejects_chunked_fallback_heap_values() {
        let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
        let value = heap
            .alloc_string(NixString::from_bytes(b"fallback".to_vec()))
            .expect("string allocates");

        assert!(matches!(
            heap.candidate_c_encode_value(value),
            Err(CandidateCValueError::ReservationUnavailable)
        ));
    }

    /// Stage S1: broaden the active-value bridge round-trip beyond the single
    /// scalar+string+thunk smoke to a corpus-representative set of heap value
    /// shapes and scalar edge cases, flushing encode/decode + heap-location +
    /// membership bugs across the flat kinds before the carrier flip demands
    /// them at eval scale.
    #[test]
    fn serial_bridge_roundtrips_broad_heap_and_scalar_corpus() {
        let mut heap = EvalHeap::new();

        // Strings: empty, short, and a >4 KiB payload that exceeds the FV-1b
        // inline-bytes cap so the moved owned-buffer path is exercised too.
        let empty = heap
            .alloc_string(NixString::from_bytes(Vec::new()))
            .expect("empty string allocates");
        let short = heap
            .alloc_string(NixString::from_bytes(b"candidate-c".to_vec()))
            .expect("short string allocates");
        let large = heap
            .alloc_string(NixString::from_bytes(vec![b'x'; 5000]))
            .expect("large string allocates");
        let path = heap
            .alloc_path(NixString::from_bytes(b"/nix/store/aaaa-example".to_vec()))
            .expect("path allocates");

        // Lists: empty, flat scalars, and nested (a list holding a list plus a
        // heap string), so the spine's element `Value`s cross the bridge.
        let empty_list = heap.alloc_list(NixList::new(Vec::new())).expect("empty list");
        let flat_list = heap
            .alloc_list(NixList::new(vec![Value::int(1), Value::int(-2), Value::bool(true)]))
            .expect("flat list");
        let nested_list = heap
            .alloc_list(NixList::new(vec![flat_list, short, Value::int(9)]))
            .expect("nested list");

        let scalars = [
            Value::int(0),
            Value::int(1),
            Value::int(-1),
            Value::int(i64::from(i32::MAX)),
            Value::int(i64::from(i32::MIN)),
            Value::int(i64::from(i32::MAX) + 1),
            Value::int(i64::MAX),
            Value::int(i64::MIN),
            Value::float(0.0),
            Value::float(-0.0),
            Value::float(f64::from_bits(0xfff8_0000_0000_0042)),
            Value::float(f64::from_bits(1)),
            Value::bool(false),
            Value::bool(true),
            Value::null(),
        ];

        let heap_values = [
            empty,
            short,
            large,
            path,
            empty_list,
            flat_list,
            nested_list,
        ];

        for value in scalars.into_iter().chain(heap_values) {
            let word = heap
                .candidate_c_encode_value(value)
                .expect("value encodes through the bridge");
            let decoded = heap
                .candidate_c_decode_value(word)
                .expect("word decodes through the bridge");
            assert!(
                decoded.raw_eq(value),
                "bridge round-trip changed value {:?}",
                value.tag()
            );
        }
    }
}
