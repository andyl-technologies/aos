//! Safe one-word-to-active value adapters for native thunk returns.

use ratchet_jit::{JitCraneliftNativeCallError, JitModuleContextFinalizedBody};
use ratchet_oracle::value::{
    Value,
    compressed::{CompressedValueKind, CompressedValueWord},
    tag::{TaggedValueKind, TaggedValueWord},
};

pub(super) fn candidate_b_inline_value(
    body: &JitModuleContextFinalizedBody,
    word: TaggedValueWord,
) -> Result<Value, JitCraneliftNativeCallError> {
    let kind = word.kind().map_err(|source| {
        JitCraneliftNativeCallError::InvalidCandidateBReturnValue {
            symbol_name: body.finalized_function().symbol_name().to_owned(),
            word: word.raw_bits(),
            source,
        }
    })?;
    match kind {
        TaggedValueKind::InlineInt => word
            .as_inline_int()
            .map(Value::int)
            .ok_or(JitCraneliftNativeCallError::UnsupportedCandidateBReturnKind { kind }),
        TaggedValueKind::Bool => word
            .as_bool()
            .map(Value::bool)
            .ok_or(JitCraneliftNativeCallError::UnsupportedCandidateBReturnKind { kind }),
        TaggedValueKind::Null => Ok(Value::null()),
        TaggedValueKind::Heap | TaggedValueKind::ForcedThunk => {
            Err(JitCraneliftNativeCallError::UnsupportedCandidateBReturnKind { kind })
        }
    }
}

pub(super) fn candidate_c_inline_value(
    word: CompressedValueWord,
) -> Result<Value, JitCraneliftNativeCallError> {
    match word.kind() {
        CompressedValueKind::InlineInt => Ok(Value::int(word.payload() as i32 as i64)),
        CompressedValueKind::Bool => Ok(Value::bool(word.payload() != 0)),
        CompressedValueKind::Null => Ok(Value::null()),
        kind => Err(JitCraneliftNativeCallError::UnsupportedCandidateCReturnKind { kind }),
    }
}
