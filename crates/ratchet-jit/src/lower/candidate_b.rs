//! Candidate-B one-word lowering for allocation-free literal thunks.

use cranelift_codegen::{
    cursor::{Cursor, FuncCursor},
    ir::{ExtFuncData, ExternalName, Function, InstBuilder, types},
};
use ratchet_core::{IrArena, IrId, runtime_helper_call_signature, runtime_thunk_call_signature};
use ratchet_value::value::{
    Value, ValueTag,
    tag::{TaggedValueWord, TaggedValueWordError},
};
use thiserror::Error;

use super::{
    AOS_ENV_GET_SYMBOL, JitLowerError, append_entry_block_params,
    clif_external_name_for_aos_env_get, clif_name_for_ir_root, constant_value_for_root,
    env_slot_for_root, verify_clif_function,
};
use crate::{
    abi::clif_signature_for_candidate_b_runtime_call,
    artifact::{JitClifArtifact, JitClifArtifactKind, JitClifArtifactSource, JitValueAbi},
    tier::JitTier,
};

/// A failure while lowering an allocation-free Candidate-B literal body.
#[derive(Debug, Error)]
pub enum JitCandidateBConstantError {
    /// The literal IR was malformed or failed ordinary CLIF lowering checks.
    #[error(transparent)]
    Lower(#[from] JitLowerError),
    /// The scalar needs an evaluator-owned boxed cell.
    #[error("Candidate-B literal {tag:?} requires evaluator-owned boxed storage")]
    RequiresBoxing {
        /// The runtime tag whose tagged form cannot be embedded in shared code.
        tag: ValueTag,
    },
    /// The checked tagged-word codec rejected an otherwise eligible literal.
    #[error(transparent)]
    TaggedWord(#[from] TaggedValueWordError),
    /// The active literal failed its tag-specific scalar validation.
    #[error(transparent)]
    Value(#[from] ratchet_value::value::ValueError),
}

/// Lowers an allocation-free Candidate-B literal IR root into a one-word thunk.
///
/// Signed integers fitting the 61-bit immediate payload, booleans, and null
/// have process-independent words that reusable code may embed. Wider integers
/// and floats require evaluator-owned boxed cells and are rejected here.
///
/// # Errors
///
/// Returns [`JitCandidateBConstantError::RequiresBoxing`] for wide integers,
/// floats, and heap-backed values. Returns
/// [`JitCandidateBConstantError::Lower`] for ordinary literal-shape, ABI, and
/// CLIF verification failures, and [`JitCandidateBConstantError::TaggedWord`]
/// or [`JitCandidateBConstantError::Value`] if a checked value conversion
/// rejects an eligible literal.
pub fn lower_candidate_b_constant_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitCandidateBConstantError> {
    let value = constant_value_for_root(arena, root)?;
    let word = allocation_free_word(value)?;
    let signature = clif_signature_for_candidate_b_runtime_call(runtime_thunk_call_signature())
        .map_err(JitLowerError::from)?;
    let mut function = Function::with_name_signature(clif_name_for_ir_root(root), signature);
    let entry_block = append_entry_block_params(&mut function);
    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let encoded = cursor.ins().iconst(types::I64, word.raw_bits() as i64);
    cursor.ins().return_(&[encoded]);
    verify_clif_function(&function)?;

    Ok(JitClifArtifact::new_with_value_abi(
        JitTier::Tier1Baseline,
        JitClifArtifactKind::ThunkBody,
        JitClifArtifactSource::IrRoot(root),
        JitValueAbi::CandidateB,
        function,
    ))
}

/// Lowers a local-slot read through Candidate B's one-word helper ABI.
///
/// The artifact imports the stable `aos_env_get` symbol with Candidate B's
/// one-word value result. It intentionally remains a pre-module artifact: the
/// shared module declaration table still pins that symbol to the active
/// two-word wrapper and rejects this signature until ABI-specific helper-symbol
/// coexistence lands.
///
/// # Errors
///
/// Returns the ordinary local-slot shape errors, a missing frozen helper
/// signature, a Candidate-B signature conversion error, an unexpected helper
/// result arity, or a CLIF verification error.
pub fn lower_candidate_b_env_get_ir_thunk_body_artifact(
    arena: &IrArena,
    root: IrId,
) -> Result<JitClifArtifact, JitLowerError> {
    let slot = env_slot_for_root(arena, root)?;
    let signature = clif_signature_for_candidate_b_runtime_call(runtime_thunk_call_signature())?;
    let mut function = Function::with_name_signature(clif_name_for_ir_root(root), signature);
    let entry_block = append_entry_block_params(&mut function);
    let helper_signature = runtime_helper_call_signature(AOS_ENV_GET_SYMBOL).ok_or(
        JitLowerError::MissingRuntimeHelperSignature {
            symbol_name: AOS_ENV_GET_SYMBOL,
        },
    )?;
    let helper_signature = clif_signature_for_candidate_b_runtime_call(helper_signature)?;
    let signature_ref = function.import_signature(helper_signature);
    let user_name = function.declare_imported_user_function(clif_external_name_for_aos_env_get());
    let env_get = function.import_function(ExtFuncData {
        name: ExternalName::user(user_name),
        signature: signature_ref,
        colocated: false,
    });

    let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
    let env = cursor
        .func
        .dfg
        .block_params(entry_block)
        .get(1)
        .copied()
        .ok_or(JitLowerError::MissingEntryBlockParameter { index: 1 })?;
    let slot = cursor.ins().iconst(types::I32, i64::from(slot));
    let call = cursor.ins().call(env_get, &[env, slot]);
    let results = cursor.func.dfg.inst_results(call).to_vec();
    if results.len() != 1 {
        return Err(JitLowerError::InvalidRuntimeCallResultArity {
            symbol_name: AOS_ENV_GET_SYMBOL,
            expected: 1,
            actual: results.len(),
        });
    }
    cursor.ins().return_(&results);
    verify_clif_function(&function)?;

    Ok(JitClifArtifact::new_with_value_abi(
        JitTier::Tier1Baseline,
        JitClifArtifactKind::ThunkBody,
        JitClifArtifactSource::IrRoot(root),
        JitValueAbi::CandidateB,
        function,
    ))
}

fn allocation_free_word(value: Value) -> Result<TaggedValueWord, JitCandidateBConstantError> {
    match value.tag() {
        ValueTag::Int => {
            TaggedValueWord::inline_int(value.as_int()?).map_err(|error| match error {
                TaggedValueWordError::IntegerOutOfRange { .. } => {
                    JitCandidateBConstantError::RequiresBoxing { tag: ValueTag::Int }
                }
                other => JitCandidateBConstantError::TaggedWord(other),
            })
        }
        ValueTag::Bool => Ok(TaggedValueWord::boolean(value.as_bool()?)),
        ValueTag::Null => {
            value.as_null()?;
            Ok(TaggedValueWord::null())
        }
        tag => Err(JitCandidateBConstantError::RequiresBoxing { tag }),
    }
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use cranelift_codegen::ir::{InstructionData, Opcode, types};
    use ratchet_core::{EffectClass, IrData, IrKind, IrNode, syntax::Span};
    use ratchet_value::value::tag::{TAGGED_IMMEDIATE_INT_MAX, TaggedValueKind};

    use super::*;

    #[test]
    fn allocation_free_literals_lower_to_tagged_one_word_artifacts() {
        let cases = [
            (IrKind::Int, IrData::Int(-7), TaggedValueKind::InlineInt),
            (IrKind::Bool, IrData::Bool(true), TaggedValueKind::Bool),
            (IrKind::Null, IrData::None, TaggedValueKind::Null),
        ];

        for (kind, data, expected_kind) in cases {
            let arena = literal_arena(kind, data);
            let artifact = lower_candidate_b_constant_ir_thunk_body_artifact(&arena, IrId::new(0))
                .expect("allocation-free literal lowers");
            let words = iconst_words(artifact.function());

            assert_eq!(artifact.value_abi(), JitValueAbi::CandidateB);
            assert_eq!(artifact.function().signature.returns.len(), 1);
            assert_eq!(
                artifact.function().signature.returns[0].value_type,
                types::I64
            );
            assert_eq!(words.len(), 1);
            assert_eq!(
                TaggedValueWord::from_raw(words[0]).and_then(TaggedValueWord::kind),
                Ok(expected_kind)
            );
        }
    }

    #[test]
    fn boxed_scalars_are_rejected() {
        let cases = [
            (
                IrKind::Int,
                IrData::Int(TAGGED_IMMEDIATE_INT_MAX + 1),
                ValueTag::Int,
            ),
            (IrKind::Float, IrData::Float(1.5), ValueTag::Float),
        ];

        for (kind, data, tag) in cases {
            let Err(error) = lower_candidate_b_constant_ir_thunk_body_artifact(
                &literal_arena(kind, data),
                IrId::new(0),
            ) else {
                panic!("boxed scalar is not embedded");
            };
            assert!(matches!(
                error,
                JitCandidateBConstantError::RequiresBoxing { tag: actual } if actual == tag
            ));
        }
    }

    #[test]
    fn env_get_import_and_return_use_one_word() {
        let arena = IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: 3 },
            )],
            Vec::new(),
        );
        let artifact = lower_candidate_b_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
            .expect("Candidate-B env read lowers");
        let function = artifact.function();
        let import = function
            .dfg
            .ext_funcs
            .values()
            .next()
            .expect("env helper is imported");

        assert_eq!(artifact.value_abi(), JitValueAbi::CandidateB);
        assert_eq!(function.signature.returns.len(), 1);
        assert_eq!(function.signature.returns[0].value_type, types::I64);
        assert_eq!(function.dfg.signatures[import.signature].returns.len(), 1);
        assert_eq!(
            function.dfg.signatures[import.signature].returns[0].value_type,
            types::I64
        );
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
