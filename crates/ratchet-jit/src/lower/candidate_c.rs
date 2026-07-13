//! Candidate-C one-word lowering for arena-independent literal thunks.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{Function, InstBuilder, types},
};
use ratchet_core::{IrArena, IrId, runtime_thunk_call_signature};
use ratchet_value::value::{Value, ValueTag, compressed::CompressedValueWord};
use thiserror::Error;

use super::{
    JitLowerError, append_entry_block_params, clif_name_for_ir_root, constant_value_for_root,
    verify_clif_function,
};
use crate::{
    abi::clif_signature_for_candidate_c_runtime_call,
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource, JitValueAbi},
    tier::JitTier,
};

/// A failure while lowering an arena-independent Candidate-C literal body.
#[derive(Debug, Error)]
pub enum JitCandidateCConstantError {
    /// The literal IR was malformed or failed ordinary CLIF lowering checks.
    #[error(transparent)]
    Lower(#[from] JitLowerError),
    /// The scalar needs evaluator-owned Candidate-C arena storage.
    #[error("Candidate-C literal {tag:?} requires evaluator-owned arena storage")]
    RequiresArena {
        /// The runtime tag whose compressed form cannot be embedded in code.
        tag: ValueTag,
    },
}

/// Lowers an inline Candidate-C literal IR root into a one-word thunk artifact.
///
/// Signed integers fitting `i32`, booleans, and null have stable compressed
/// words that reusable code may embed. Wide integers and all floats require an
/// evaluator-owned scalar arena, so this lowerer rejects them rather than
/// baking a context-specific arena index into shared native code.
///
/// # Errors
///
/// Returns [`JitCandidateCConstantError::RequiresArena`] for wide integers,
/// floats, and heap-backed values. Returns
/// [`JitCandidateCConstantError::Lower`] for ordinary literal-shape, ABI, and
/// CLIF verification failures.
pub fn lower_candidate_c_constant_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitCandidateCConstantError> {
    let value = constant_value_for_root(arena, root)?;
    let word = arena_independent_word(value)?;
    let signature = clif_signature_for_candidate_c_runtime_call(runtime_thunk_call_signature())
        .map_err(JitLowerError::from)?;
    let mut function = Function::with_name_signature(clif_name_for_ir_root(root), signature);
    let entry_block = append_entry_block_params(&mut function);
    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let encoded = cursor.ins().iconst(types::I64, word.raw() as i64);
    cursor.ins().return_(&[encoded]);
    verify_clif_function(&function)?;

    Ok(JitClifArtifact::new_with_value_abi(
        JitTier::Tier1Baseline,
        JitClifArtifactKind::ThunkBody,
        JitClifArtifactSource::IrRoot(root),
        JitValueAbi::CandidateC,
        function,
    ))
}

fn arena_independent_word(value: Value) -> Result<CompressedValueWord, JitCandidateCConstantError> {
    // Decode through the typed accessors, not `payload_bits`: on the one-word
    // carrier the payload bits are the whole compressed word, and inline
    // integers store a sign-extended `i32` that only `as_int` decodes
    // correctly. The accessors also reject boxed scalars, whose words carry
    // arena indices.
    match value.tag() {
        ValueTag::Int => value
            .as_int()
            .ok()
            .and_then(|int| CompressedValueWord::inline_int(int).ok())
            .ok_or(JitCandidateCConstantError::RequiresArena { tag: ValueTag::Int }),
        ValueTag::Bool => value
            .as_bool()
            .map(CompressedValueWord::boolean)
            .map_err(|_| JitCandidateCConstantError::RequiresArena { tag: ValueTag::Bool }),
        ValueTag::Null => Ok(CompressedValueWord::null()),
        tag => Err(JitCandidateCConstantError::RequiresArena { tag }),
    }
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use cranelift_codegen::ir::{InstructionData, Opcode, types};
    use ratchet_core::{EffectClass, IrData, IrKind, IrNode, syntax::Span};

    use super::*;

    #[test]
    fn inline_literals_lower_to_tagged_one_word_artifacts() {
        let cases = [
            (
                IrKind::Int,
                IrData::Int(-7),
                CompressedValueWord::inline_int(-7).expect("inline"),
            ),
            (
                IrKind::Bool,
                IrData::Bool(true),
                CompressedValueWord::boolean(true),
            ),
            (IrKind::Null, IrData::None, CompressedValueWord::null()),
        ];

        for (kind, data, expected) in cases {
            let arena = literal_arena(kind, data);
            let artifact = lower_candidate_c_constant_ir_thunk_body_artifact(&arena, IrId::new(0))
                .expect("arena-independent literal lowers");

            assert_eq!(artifact.value_abi(), JitValueAbi::CandidateC);
            assert_eq!(artifact.function().signature.returns.len(), 1);
            assert_eq!(
                artifact.function().signature.returns[0].value_type,
                types::I64
            );
            assert_eq!(iconst_words(artifact.function()), vec![expected.raw()]);
        }
    }

    #[test]
    fn arena_owned_scalars_are_rejected() {
        let cases = [
            (
                IrKind::Int,
                IrData::Int(i64::from(i32::MAX) + 1),
                ValueTag::Int,
            ),
            (IrKind::Float, IrData::Float(1.5), ValueTag::Float),
        ];

        for (kind, data, tag) in cases {
            let Err(error) = lower_candidate_c_constant_ir_thunk_body_artifact(
                &literal_arena(kind, data),
                IrId::new(0),
            ) else {
                panic!("arena-owned scalar is not embedded");
            };
            assert!(matches!(
                error,
                JitCandidateCConstantError::RequiresArena { tag: actual } if actual == tag
            ));
        }
    }

    fn literal_arena(kind: IrKind, data: IrData) -> IrArena {
        IrArena::from_raw_parts(
            vec![IrNode::new(
                kind,
                Span::new(0, 1),
                EffectClass::pure(),
                data,
            )],
            Vec::new(),
        )
    }

    fn iconst_words(function: &Function) -> Vec<u64> {
        function
            .layout
            .blocks()
            .flat_map(|block| function.layout.block_insts(block))
            .filter_map(|inst| match function.dfg.insts[inst] {
                InstructionData::UnaryImm {
                    opcode: Opcode::Iconst,
                    imm,
                } => Some(imm.bits() as u64),
                _ => None,
            })
            .collect()
    }
}
