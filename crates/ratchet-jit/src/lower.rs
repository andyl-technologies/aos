//! Minimal CLIF body lowering for safe JIT smoke tests.
//!
//! This module starts the tier-1 lowering path without executable code. It can
//! build a verified Cranelift [`Function`] for a compiled thunk body that
//! returns a constant runtime [`Value`]. The function body uses the same
//! two-word `Value` ABI as [`crate::abi`], but it is not placed in a
//! `JITModule`, finalized, or called.

use std::{error::Error, fmt};

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, UserFuncName, types},
    settings,
    verifier::{VerifierErrors, verify_function},
};
use ratchet_core::runtime_thunk_call_signature;
use ratchet_value::value::Value;

use crate::abi::{JitClifSignatureError, clif_signature_for_runtime_call};

/// Lowers a constant runtime value into a verified compiled-thunk CLIF body.
///
/// The returned function has the frozen compiled-thunk runtime signature:
/// `rt`, `env`, and a two-word runtime `Value` return. The current body ignores
/// the runtime and environment parameters and emits two `iconst.i64`
/// instructions for the value tag and payload words.
///
/// # Errors
///
/// Returns [`JitLowerError::Abi`] if the runtime thunk signature cannot be
/// lowered to a CLIF signature. Returns [`JitLowerError::Verifier`] if Cranelift
/// rejects the generated single-block function.
pub fn lower_constant_thunk_body(value: Value) -> Result<Function, JitLowerError> {
    let signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(UserFuncName::default(), signature);
    let entry_block = append_entry_block_params(&mut function);
    emit_value_return(&mut function, entry_block, value);
    verify_clif_function(&function)?;
    Ok(function)
}

/// A failure while lowering safe metadata into CLIF.
#[derive(Debug)]
pub enum JitLowerError {
    /// Runtime ABI metadata could not be converted to a CLIF signature.
    Abi(JitClifSignatureError),
    /// Cranelift rejected the generated CLIF function body.
    Verifier(VerifierErrors),
}

impl fmt::Display for JitLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abi(error) => write!(formatter, "{error}"),
            Self::Verifier(error) => {
                write!(formatter, "generated CLIF failed verification: {error}")
            }
        }
    }
}

impl Error for JitLowerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Abi(error) => Some(error),
            Self::Verifier(error) => Some(error),
        }
    }
}

impl From<JitClifSignatureError> for JitLowerError {
    fn from(error: JitClifSignatureError) -> Self {
        Self::Abi(error)
    }
}

fn append_entry_block_params(function: &mut Function) -> cranelift_codegen::ir::Block {
    let entry_block = function.dfg.make_block();
    let parameter_types = function
        .signature
        .params
        .iter()
        .map(|parameter| parameter.value_type)
        .collect::<Vec<_>>();

    for parameter_type in parameter_types {
        function.dfg.append_block_param(entry_block, parameter_type);
    }

    let mut cursor = FuncCursor::new(function);
    cursor.insert_block(entry_block);

    entry_block
}

fn emit_value_return(
    function: &mut Function,
    entry_block: cranelift_codegen::ir::Block,
    value: Value,
) {
    let tag_word = value.tag() as u64;
    let payload_word = value.payload_bits();
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(entry_block);
    let tag = cursor.ins().iconst(types::I64, tag_word as i64);
    let payload = cursor.ins().iconst(types::I64, payload_word as i64);
    cursor.ins().return_(&[tag, payload]);
}

fn verify_clif_function(function: &Function) -> Result<(), JitLowerError> {
    let flags = settings::Flags::new(settings::builder());
    verify_function(function, &flags).map_err(JitLowerError::Verifier)
}

#[cfg(test)]
mod tests {
    use cranelift_codegen::ir::{InstructionData, Opcode, Type};
    use ratchet_value::value::ValueTag;

    use super::*;
    use crate::abi::clif_signature_for_runtime_call;

    #[test]
    fn constant_thunk_body_uses_frozen_thunk_signature() {
        let function =
            lower_constant_thunk_body(Value::null()).expect("constant null thunk body lowers");
        let expected_signature = clif_signature_for_runtime_call(runtime_thunk_call_signature())
            .expect("thunk signature lowers");

        assert_eq!(function.signature, expected_signature);
        assert_eq!(
            entry_block_param_types(&function),
            param_types(&expected_signature)
        );
    }

    #[test]
    fn constant_thunk_body_returns_int_value_words() {
        let function =
            lower_constant_thunk_body(Value::int(-7)).expect("constant int thunk body lowers");

        assert_eq!(
            iconst_words(&function),
            vec![ValueTag::Int as u64, Value::int(-7).payload_bits()]
        );
    }

    #[test]
    fn constant_thunk_body_returns_bool_and_null_value_words() {
        let bool_function =
            lower_constant_thunk_body(Value::bool(true)).expect("constant bool thunk body lowers");
        let null_function =
            lower_constant_thunk_body(Value::null()).expect("constant null thunk body lowers");

        assert_eq!(
            iconst_words(&bool_function),
            vec![ValueTag::Bool as u64, Value::bool(true).payload_bits()]
        );
        assert_eq!(
            iconst_words(&null_function),
            vec![ValueTag::Null as u64, Value::null().payload_bits()]
        );
    }

    #[test]
    fn constant_thunk_body_is_verified_clif_without_jit_module() {
        let function = lower_constant_thunk_body(Value::float(-13.25))
            .expect("constant float thunk body lowers");

        let emitted_constants = iconst_values(&function)
            .into_iter()
            .map(|(value, _word)| value)
            .collect::<Vec<_>>();
        assert_eq!(return_operands(&function), emitted_constants);
        assert_eq!(opcodes(&function).last(), Some(&Opcode::Return));
        verify_clif_function(&function).expect("lowered function verifies independently");
    }

    fn entry_block_param_types(function: &Function) -> Vec<Type> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .dfg
            .block_params(entry_block)
            .iter()
            .map(|value| function.dfg.value_type(*value))
            .collect()
    }

    fn param_types(signature: &cranelift_codegen::ir::Signature) -> Vec<Type> {
        signature
            .params
            .iter()
            .map(|parameter| parameter.value_type)
            .collect()
    }

    fn iconst_words(function: &Function) -> Vec<u64> {
        iconst_values(function)
            .into_iter()
            .map(|(_value, word)| word)
            .collect()
    }

    fn iconst_values(function: &Function) -> Vec<(cranelift_codegen::ir::Value, u64)> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .layout
            .block_insts(entry_block)
            .filter_map(|inst| match function.dfg.insts[inst] {
                InstructionData::UnaryImm {
                    opcode: Opcode::Iconst,
                    imm,
                } => Some((function.dfg.inst_results(inst)[0], imm.bits() as u64)),
                _ => None,
            })
            .collect()
    }

    fn return_operands(function: &Function) -> Vec<cranelift_codegen::ir::Value> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        let return_inst = function
            .layout
            .block_insts(entry_block)
            .find(|inst| function.dfg.insts[*inst].opcode() == Opcode::Return)
            .expect("lowered function has a return instruction");
        function.dfg.inst_args(return_inst).to_vec()
    }

    fn opcodes(function: &Function) -> Vec<Opcode> {
        let entry_block = function
            .layout
            .entry_block()
            .expect("lowered function has an entry block");
        function
            .layout
            .block_insts(entry_block)
            .map(|inst| function.dfg.insts[inst].opcode())
            .collect()
    }
}
