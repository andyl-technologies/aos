//! Candidate-C shared-context thunk dispatch tests.

use aos_nix_dialect::nix_lower;
use ratchet_jit::{JitModuleContext, lower_candidate_c_constant_ir_thunk_body_artifact};
use ratchet_oracle::{
    compile::resolve,
    eval::{EvalEnv, tree_walk::TreeWalk},
    syntax::parse_str,
};

use super::*;

#[test]
fn shared_context_candidate_c_literal_returns_active_value() {
    let ir = nix_lower(resolve(parse_str("42").expect("source parses")).expect("source resolves"))
        .expect("source lowers");
    let artifact = lower_candidate_c_constant_ir_thunk_body_artifact(&ir.arena, ir.root)
        .expect("Candidate-C literal lowers");
    let context = JitModuleContext::with_candidates(&[]).expect("module context builds");
    let body = context
        .define_and_finalize(artifact)
        .expect("Candidate-C literal finalizes");
    let mut eval = TreeWalk::new(&ir);

    let outcome = run_context_finalized_native_thunk_call(
        &mut eval,
        ir.root,
        ir.arena.node(ir.root).expect("root exists").span,
        &EvalEnv::default(),
        &body,
    )
    .expect("Candidate-C literal dispatches");

    assert!(!outcome.is_trap());
    assert_eq!(outcome.value().as_int(), Ok(42));
}
