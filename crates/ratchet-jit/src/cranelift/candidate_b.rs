//! Reviewed native-call boundary for Candidate-B one-word thunk artifacts.

use std::mem;

use ratchet_value::value::tag::TaggedValueWord;

use super::{
    JitCraneliftNativeCallError, JitModuleContextFinalizedBody, require_artifact_value_abi,
};
use crate::{
    abi::{JitCandidateBThunkFn, JitEnvFramePtr, JitRuntimeContextPtr},
    artifact::{JitClifArtifactKind, JitValueAbi},
};

/// Calls a shared-context Candidate-B thunk and validates its one-word result.
///
/// # Safety
///
/// The [`super::JitModuleContext`] that finalized `body`, or a cloned keep-alive
/// handle from it, must remain alive until the call returns. `rt` and `env` must
/// satisfy the compiled body, registered functions must not unwind across the C
/// ABI, and every registered address must match its declared native signature.
///
/// # Errors
///
/// Returns [`JitCraneliftNativeCallError::UnsupportedArtifactKind`] when `body`
/// is not a thunk, [`JitCraneliftNativeCallError::UnsupportedArtifactValueAbi`]
/// when it was not lowered for Candidate B, and
/// [`JitCraneliftNativeCallError::InvalidCandidateBReturnValue`] when native code
/// returns a malformed tagged word.
pub unsafe fn jit_cranelift_call_context_finalized_candidate_b_thunk_entry(
    body: &JitModuleContextFinalizedBody,
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
) -> Result<TaggedValueWord, JitCraneliftNativeCallError> {
    if body.artifact().kind() != JitClifArtifactKind::ThunkBody {
        return Err(JitCraneliftNativeCallError::UnsupportedArtifactKind {
            kind: body.artifact().kind(),
        });
    }
    require_artifact_value_abi(body.artifact(), JitValueAbi::CandidateB)?;

    let code_ptr = body.finalized_function().code_ptr();
    // SAFETY: The checked metadata proves this code was lowered with the
    // Candidate-B thunk signature, and the caller keeps its module and raw
    // runtime inputs valid across this call.
    let entry = unsafe { mem::transmute::<*mut u8, JitCandidateBThunkFn>(code_ptr.as_ptr()) };
    // SAFETY: The typed entry and raw runtime arguments satisfy the invariants
    // documented by this function's caller.
    let word = unsafe { entry(rt, env) };
    TaggedValueWord::from_raw(word).map_err(|source| {
        JitCraneliftNativeCallError::InvalidCandidateBReturnValue {
            symbol_name: body.finalized_function().symbol_name().to_owned(),
            word,
            source,
        }
    })
}

// JIT is off by construction under the Candidate-C variant; these tier-1 lowering/codegen tests re-enable at S4b (cutover plan section 6.1).
#[cfg(all(test, not(feature = "candidate_c_value")))]
mod tests {
    use std::ptr;

    use ratchet_core::{EffectClass, IrArena, IrData, IrId, IrKind, IrNode, syntax::Span};

    use super::*;
    use crate::{
        cranelift::{JitModuleContext, jit_cranelift_call_context_finalized_thunk_entry},
        lower::{
            lower_candidate_b_constant_ir_thunk_body_artifact,
            lower_constant_ir_thunk_body_artifact,
        },
    };

    #[test]
    fn candidate_b_literal_executes_as_one_word() {
        let context = JitModuleContext::with_candidates(&[]).expect("module context builds");
        let body = context
            .define_and_finalize(
                lower_candidate_b_constant_ir_thunk_body_artifact(
                    &literal_int_arena(42),
                    IrId::new(0),
                )
                .expect("Candidate-B literal lowers"),
            )
            .expect("Candidate-B literal finalizes");

        // SAFETY: The no-import literal body ignores both null raw arguments,
        // and `context` keeps the finalized code allocation alive.
        let word = unsafe {
            jit_cranelift_call_context_finalized_candidate_b_thunk_entry(
                &body,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        }
        .expect("Candidate-B literal dispatches");

        assert_eq!(word.as_inline_int(), Some(42));
    }

    #[test]
    fn candidate_b_entry_rejects_active_artifact_before_cast() {
        let context = JitModuleContext::with_candidates(&[]).expect("module context builds");
        let candidate_body = context
            .define_and_finalize(
                lower_candidate_b_constant_ir_thunk_body_artifact(
                    &literal_int_arena(7),
                    IrId::new(0),
                )
                .expect("Candidate-B literal lowers"),
            )
            .expect("Candidate-B literal finalizes");
        let active_body = context
            .define_and_finalize(
                lower_constant_ir_thunk_body_artifact(&literal_int_arena(7), IrId::new(0))
                    .expect("active literal lowers"),
            )
            .expect("active literal finalizes");

        // SAFETY: Both no-import literal bodies ignore the null raw arguments,
        // and `context` keeps both code allocations alive. Metadata rejection
        // happens before either mismatched function-pointer cast.
        let active_error = unsafe {
            jit_cranelift_call_context_finalized_thunk_entry(
                &candidate_body,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        }
        .expect_err("active entry rejects Candidate-B body");
        // SAFETY: Same lifetime and ignored-pointer argument proof as above.
        let candidate_error = unsafe {
            jit_cranelift_call_context_finalized_candidate_b_thunk_entry(
                &active_body,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        }
        .expect_err("Candidate-B entry rejects active body");

        assert!(matches!(
            active_error,
            JitCraneliftNativeCallError::UnsupportedArtifactValueAbi {
                expected: JitValueAbi::Active,
                actual: JitValueAbi::CandidateB,
            }
        ));
        assert!(matches!(
            candidate_error,
            JitCraneliftNativeCallError::UnsupportedArtifactValueAbi {
                expected: JitValueAbi::CandidateB,
                actual: JitValueAbi::Active,
            }
        ));
    }

    fn literal_int_arena(value: i64) -> IrArena {
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Int,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Int(value),
            )],
            Vec::new(),
        )
    }
}
