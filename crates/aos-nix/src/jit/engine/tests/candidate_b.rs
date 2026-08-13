//! Production tier-1 dispatch tests for Candidate-B literal artifacts.

use super::*;
use ratchet_jit::JitValueAbi;

#[test]
fn literal_def_site_publishes_candidate_b_artifact() {
    let source = "let g = k: { inherit k; r = 42; }; \
         in builtins.foldl' (acc: item: acc + item.r) 0 \
         (builtins.genList (i: g i) 40)";
    let oracle = eval_oracle(source);
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    eval.set_tier1_engine(Rc::new(
        NixJitTier1Engine::with_threshold(1)
            .expect("engine builds")
            .force_promote()
            .candidate_b_value_abi(),
    ));

    let native = eval.eval_root().expect("Candidate-B evaluation succeeds");
    let stats = eval.stats();
    let candidate_published = ir.arena.nodes().iter().enumerate().any(|(index, _)| {
        eval.tier1_def_site_slot(index as u64)
            .and_then(|slot| slot.owner().downcast_ref::<NixJitTier1DispatchEntry>())
            .is_some_and(|entry| entry.body.artifact().value_abi() == JitValueAbi::CandidateB)
    });

    assert!(oracle.raw_eq(native));
    assert!(
        candidate_published,
        "a Candidate-B literal body must be published"
    );
    assert_eq!(stats.tier1_promoted(), 1);
    assert_eq!(stats.tier1_deopted(), 0);
    assert!(stats.thunk_cache_hits() >= 1);
}

#[test]
fn boxed_scalars_fall_back_to_the_active_abi() {
    for source in ["1152921504606846976", "1.5"] {
        let ir = lower(source);
        let eval = TreeWalk::new(&ir);
        let engine = NixJitTier1Engine::with_threshold(1)
            .expect("engine builds")
            .candidate_b_value_abi();
        let body = EvalNodeRef::new(ratchet_oracle::eval::EvalModuleId::ROOT, ir.root);
        let artifact = engine
            .lower_body_artifact(&eval, body)
            .expect("active literal fallback lowers");

        assert_eq!(artifact.value_abi(), JitValueAbi::Active, "source {source}");
    }
}
