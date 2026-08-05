//! Candidate-B shared-context thunk dispatch tests.

use aos_nix_dialect::nix_lower;
use ratchet_jit::{JitModuleContext, lower_candidate_b_constant_ir_thunk_body_artifact};
use ratchet_oracle::{
    compile::resolve,
    eval::{EvalEnv, tree_walk::TreeWalk},
    syntax::parse_str,
};

use super::*;

#[test]
fn shared_context_candidate_b_literal_returns_active_value() {
    let ir = nix_lower(resolve(parse_str("42").expect("source parses")).expect("source resolves"))
        .expect("source lowers");
    let artifact = lower_candidate_b_constant_ir_thunk_body_artifact(&ir.arena, ir.root)
        .expect("Candidate-B literal lowers");
    let context = JitModuleContext::with_candidates(&[]).expect("module context builds");
    let body = context
        .define_and_finalize(artifact)
        .expect("Candidate-B literal finalizes");
    let mut eval = TreeWalk::new(&ir);

    let result = run_context_finalized_native_thunk_call(
        &mut eval,
        ir.root,
        ir.arena.node(ir.root).expect("root exists").span,
        &EvalEnv::default(),
        &body,
    );

    // The dispatch selects the value ABI from the artifact. On the baseline
    // carrier the Candidate-B one-word return ABI is live and yields the active
    // value (42). Under the `candidate_c_value` carrier the active ABI is
    // Candidate-C, so a Candidate-B artifact is foreign and rejected with
    // `UnsupportedArtifactValueAbi` (native_call.rs value-ABI dispatch).
    #[cfg(not(feature = "candidate_c_value"))]
    {
        let outcome = result.expect("Candidate-B literal dispatches");
        assert!(!outcome.is_trap());
        assert_eq!(outcome.value().as_int(), Ok(42));
    }
    #[cfg(feature = "candidate_c_value")]
    {
        use ratchet_jit::{JitCraneliftNativeCallError, JitValueAbi};
        assert!(matches!(
            result,
            Err(JitCraneliftNativeCallError::UnsupportedArtifactValueAbi {
                expected: JitValueAbi::CandidateC,
                actual: JitValueAbi::CandidateB,
            })
        ));
    }
}
