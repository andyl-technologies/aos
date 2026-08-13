//! Width-generic runtime `Value` word plumbing for tier-1 lowering.
//!
//! The active carrier fixes how many CLIF words one runtime `Value` occupies
//! at native call boundaries: two `i64` words (tag, payload) on the baseline
//! carrier and one compressed `i64` word under the `candidate_c_value`
//! variant. [`VALUE_WORDS`] captures that width as a compile-time constant so
//! the delegating tier-1 shapes can spill, forward, and return value words
//! without hard-coding either representation. Carrier-specific decisions —
//! which constants may be embedded in shared code, and how a helper-returned
//! boolean is tested — live behind the small helpers here so the shape
//! emitters in `lower.rs` stay width-agnostic.

use cranelift_codegen::{
    cursor::FuncCursor,
    ir::{self, InstBuilder, condcodes::IntCC, types},
};
use ratchet_core::runtime_abi_value_layout;
use ratchet_value::value::Value;

use super::{JitLowerError, stack_maps};

/// Number of CLIF `i64` words carrying one runtime `Value` on this carrier.
pub(crate) const VALUE_WORDS: usize = runtime_abi_value_layout().register_words();

/// The CLIF SSA words of one runtime `Value` on the active carrier.
pub(crate) type ValueWords = [ir::Value; VALUE_WORDS];

/// Checks a runtime call's result arity and returns its value words.
///
/// Every delegating shape expects helpers with a `Value` return to produce
/// exactly [`VALUE_WORDS`] CLIF results; anything else is a frozen-ABI drift
/// caught before the malformed function reaches the verifier.
pub(crate) fn expect_value_words(
    symbol_name: &'static str,
    results: &[ir::Value],
) -> Result<ValueWords, JitLowerError> {
    ValueWords::try_from(results).map_err(|_| JitLowerError::InvalidRuntimeCallResultArity {
        symbol_name,
        expected: VALUE_WORDS,
        actual: results.len(),
    })
}

/// Appends one value's words to a runtime-call argument list.
pub(crate) fn push_words(args: &mut Vec<ir::Value>, words: ValueWords) {
    args.extend_from_slice(&words);
}

/// Declines shapes whose emitters still assume the two-word carrier.
///
/// Compound emitters decode or compose value payloads in native code
/// (arithmetic trees, allocating cons cells, tier-2 lambda bodies). Until
/// their compressed-word codegen lands, the one-word carrier declines them at
/// the lowering entry so the def-site stays on the tree walk.
///
/// # Errors
///
/// Returns [`JitLowerError::CarrierUnsupportedShape`] under the
/// `candidate_c_value` variant; always succeeds on the baseline carrier.
pub(crate) fn require_two_word_carrier(shape: &'static str) -> Result<(), JitLowerError> {
    #[cfg(feature = "candidate_c_value")]
    {
        Err(JitLowerError::CarrierUnsupportedShape { shape })
    }
    #[cfg(not(feature = "candidate_c_value"))]
    {
        let _ = shape;
        Ok(())
    }
}

/// Returns the constant words embeddable in shared code for `value`.
///
/// The baseline carrier embeds the (tag, payload) pair of any non-heap value.
/// The one-word carrier can only embed arena-independent compressed words —
/// inline-range integers, booleans, and null; wide integers and floats box
/// through an evaluator-owned arena whose indices must never be baked into
/// reusable native code.
///
/// # Errors
///
/// Returns [`JitLowerError::ArenaBackedConstant`] when the one-word carrier
/// would need evaluator-owned arena storage for `value`.
#[cfg(not(feature = "candidate_c_value"))]
pub(crate) fn embedded_constant_words(value: Value) -> Result<[i64; VALUE_WORDS], JitLowerError> {
    Ok([
        value.tag() as u64 as i64,
        value.relocation_sensitive_identity_bits() as i64,
    ])
}

/// Returns the constant words embeddable in shared code for `value`.
///
/// The one-word carrier can only embed arena-independent compressed words —
/// inline-range integers, booleans, and null; wide integers and floats box
/// through an evaluator-owned arena whose indices must never be baked into
/// reusable native code.
///
/// # Errors
///
/// Returns [`JitLowerError::ArenaBackedConstant`] when `value` requires
/// evaluator-owned arena storage.
#[cfg(feature = "candidate_c_value")]
pub(crate) fn embedded_constant_words(value: Value) -> Result<[i64; VALUE_WORDS], JitLowerError> {
    use ratchet_value::value::{ValueTag, compressed::CompressedValueWord};

    // Decode through the typed accessors, not `payload_bits`: on this carrier
    // the payload bits are the whole compressed word, and inline integers
    // store a sign-extended `i32` that only `as_int` decodes correctly. The
    // accessors also reject boxed scalars, whose words carry arena indices.
    let word = match value.tag() {
        ValueTag::Int => {
            let int = value
                .as_int()
                .map_err(|_| JitLowerError::ArenaBackedConstant { tag: ValueTag::Int })?;
            CompressedValueWord::inline_int(int)
                .map_err(|_| JitLowerError::ArenaBackedConstant { tag: ValueTag::Int })?
        }
        ValueTag::Bool => {
            let boolean = value
                .as_bool()
                .map_err(|_| JitLowerError::ArenaBackedConstant {
                    tag: ValueTag::Bool,
                })?;
            CompressedValueWord::boolean(boolean)
        }
        ValueTag::Null => CompressedValueWord::null(),
        tag => return Err(JitLowerError::ArenaBackedConstant { tag }),
    };
    Ok([word.raw() as i64])
}

/// Materializes constant words as CLIF `iconst`s in emission order.
pub(crate) fn iconst_words(cursor: &mut FuncCursor<'_>, words: [i64; VALUE_WORDS]) -> ValueWords {
    words.map(|word| cursor.ins().iconst(types::I64, word))
}

/// Emits the carrier-specific truth test for a helper-returned boolean value.
///
/// The baseline carrier tests the payload word against zero. The one-word
/// carrier compares the compressed word against the canonical `true` encoding;
/// the helpers behind this test guarantee a boolean, so the two encodings are
/// the only possible words.
pub(crate) fn truthy_test(cursor: &mut FuncCursor<'_>, words: ValueWords) -> ir::Value {
    #[cfg(not(feature = "candidate_c_value"))]
    {
        cursor.ins().icmp_imm(IntCC::NotEqual, words[1], 0)
    }
    #[cfg(feature = "candidate_c_value")]
    {
        use ratchet_value::value::compressed::CompressedValueWord;

        let true_word = CompressedValueWord::boolean(true).raw() as i64;
        cursor.ins().icmp_imm(IntCC::Equal, words[0], true_word)
    }
}

/// Spills value words into a stack-map slot using the carrier's geometry.
pub(crate) fn spill(cursor: &mut FuncCursor<'_>, values: &[ValueWords]) -> stack_maps::Binding {
    #[cfg(not(feature = "candidate_c_value"))]
    {
        stack_maps::spill_values(cursor, values)
    }
    #[cfg(feature = "candidate_c_value")]
    {
        let flat = values.iter().map(|words| words[0]).collect::<Vec<_>>();
        stack_maps::spill_values_one_word(cursor, &flat)
    }
}

/// Attaches the carrier-appropriate user stack map to a safepoint call.
pub(crate) fn attach(cursor: &mut FuncCursor<'_>, call: ir::Inst, binding: stack_maps::Binding) {
    #[cfg(not(feature = "candidate_c_value"))]
    stack_maps::attach(cursor, call, binding);
    #[cfg(feature = "candidate_c_value")]
    stack_maps::attach_one_word(cursor, call, binding);
}

/// Reloads one spilled value's words from a stack-map slot.
pub(crate) fn reload(
    cursor: &mut FuncCursor<'_>,
    binding: stack_maps::Binding,
    index: usize,
) -> ValueWords {
    #[cfg(not(feature = "candidate_c_value"))]
    {
        stack_maps::reload(cursor, binding, index)
    }
    #[cfg(feature = "candidate_c_value")]
    {
        [stack_maps::reload_one_word(cursor, binding, index)]
    }
}
