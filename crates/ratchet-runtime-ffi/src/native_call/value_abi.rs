//! Safe one-word-to-active value adapters for native thunk returns.

use ratchet_jit::{JitCraneliftNativeCallError, JitModuleContextFinalizedBody};
use ratchet_oracle::{
    eval::EvalHeap,
    value::{Value, compressed::CompressedValueWord, tag::TaggedValueWord},
};

/// A value returned through one of the reviewed native thunk ABIs.
pub(super) enum NativeThunkReturn {
    /// The active two-word value ABI.
    Active(Value),
    /// The Candidate-B tagged one-word ABI.
    #[cfg(not(feature = "candidate_c_value"))]
    CandidateB(TaggedValueWord),
    /// The Candidate-C compressed one-word ABI.
    CandidateC(CompressedValueWord),
}

impl NativeThunkReturn {
    /// Converts the native return through the receiving evaluator heap.
    pub(super) fn into_active(
        self,
        heap: &EvalHeap,
        #[cfg_attr(feature = "candidate_c_value", allow(unused_variables))]
        body: &JitModuleContextFinalizedBody,
    ) -> Result<Value, JitCraneliftNativeCallError> {
        match self {
            Self::Active(value) => Ok(value),
            #[cfg(not(feature = "candidate_c_value"))]
            Self::CandidateB(word) => {
                candidate_b_value(heap, body.finalized_function().symbol_name(), word)
            }
            Self::CandidateC(word) => candidate_c_value(heap, word),
        }
    }
}

#[cfg(not(feature = "candidate_c_value"))]
fn candidate_b_value(
    heap: &EvalHeap,
    symbol_name: &str,
    word: TaggedValueWord,
) -> Result<Value, JitCraneliftNativeCallError> {
    let kind = word.kind().map_err(|source| {
        JitCraneliftNativeCallError::InvalidCandidateBReturnValue {
            symbol_name: symbol_name.to_owned(),
            word: word.raw_bits(),
            source,
        }
    })?;
    heap.candidate_b_decode_value(word)
        .map_err(|_| JitCraneliftNativeCallError::UnsupportedCandidateBReturnKind { kind })
}

#[cfg(not(feature = "candidate_c_value"))]
fn candidate_c_value(
    heap: &EvalHeap,
    word: CompressedValueWord,
) -> Result<Value, JitCraneliftNativeCallError> {
    let kind = word.kind();
    heap.candidate_c_decode_value(word)
        .map_err(|_| JitCraneliftNativeCallError::UnsupportedCandidateCReturnKind { kind })
}

/// On the Candidate-C carrier the active runtime value already *is* the
/// compressed word, so the native return adapter is the identity — no heap
/// bridge decode is needed. (The tier-1 JIT is off by construction under this
/// variant, so this path is currently unreachable, but it stays correct.)
#[cfg(feature = "candidate_c_value")]
fn candidate_c_value(
    _heap: &EvalHeap,
    word: CompressedValueWord,
) -> Result<Value, JitCraneliftNativeCallError> {
    Ok(Value::from_word(word))
}

// These adapters bridge the Candidate-B/-C one-word return ABIs back to the
// active two-word `Value`. Under the `candidate_c_value` carrier the value IS
// the word (the `candidate_*_encode_value` heap bridges and `Value::float` /
// `as_float` do not exist) and the tier-1 JIT is off by construction, so the
// adapters are exercised only on the baseline carrier here; the variant's
// identity `candidate_c_value` is covered by the parity battery. See cutover
// plan section 6.1 (S4b re-enables the JIT under the variant).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use super::*;
    use ratchet_oracle::{
        string::NixString,
        value::{ValueTag, tag::TAGGED_IMMEDIATE_INT_MAX},
    };

    #[test]
    fn candidate_b_adapter_decodes_owned_boxed_scalars_and_heap_values() {
        let mut heap = EvalHeap::new();
        let wide = Value::int(TAGGED_IMMEDIATE_INT_MAX + 1);
        let float = Value::float(f64::from_bits(0x7ff8_0000_0000_0042));
        let string = heap
            .alloc_string(NixString::from_bytes(b"candidate-b-return".to_vec()))
            .expect("string allocates");

        for value in [wide, float, string] {
            let word = heap
                .candidate_b_encode_value(value)
                .expect("owned value encodes");
            let decoded = candidate_b_value(&heap, "candidate_b_adapter_test", word)
                .expect("owned return decodes");
            assert_eq!(decoded.tag(), value.tag());
            if value.tag() == ValueTag::Float {
                assert_eq!(
                    decoded.as_float().expect("float decodes").to_bits(),
                    0x7ff8_0000_0000_0042
                );
            }
        }
    }

    #[test]
    fn candidate_c_adapter_decodes_owned_boxed_scalars_and_heap_values() {
        let mut heap = EvalHeap::new();
        let wide = Value::int(i64::MAX);
        let float = Value::float(f64::from_bits(0x8000_0000_0000_0000));
        let string = heap
            .alloc_string(NixString::from_bytes(b"candidate-c-return".to_vec()))
            .expect("string allocates");

        for value in [wide, float, string] {
            let word = heap
                .candidate_c_encode_value(value)
                .expect("owned value encodes");
            let decoded = candidate_c_value(&heap, word).expect("owned return decodes");
            assert_eq!(decoded.tag(), value.tag());
            if value.tag() == ValueTag::Float {
                assert_eq!(
                    decoded.as_float().expect("float decodes").to_bits(),
                    0x8000_0000_0000_0000
                );
            }
        }
    }

    #[test]
    fn candidate_adapters_reject_words_from_another_heap() {
        let mut owner = EvalHeap::new();
        let receiver = EvalHeap::new();
        let candidate_b = owner
            .candidate_b_encode_value(Value::int(i64::MAX))
            .expect("Candidate-B owner encodes");
        let candidate_c = owner
            .candidate_c_encode_value(Value::int(i64::MAX))
            .expect("Candidate-C owner encodes");

        assert!(matches!(
            candidate_b_value(&receiver, "foreign_candidate_b", candidate_b),
            Err(JitCraneliftNativeCallError::UnsupportedCandidateBReturnKind { .. })
        ));
        assert!(matches!(
            candidate_c_value(&receiver, candidate_c),
            Err(JitCraneliftNativeCallError::UnsupportedCandidateCReturnKind { .. })
        ));
    }
}
