//! Production tier-1 dispatch tests for Candidate-C literal artifacts.

use super::*;
use ratchet_jit::JitValueAbi;

#[test]
fn literal_def_site_publishes_candidate_c_artifact() {
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
            .candidate_c_value_abi(),
    ));

    let native = eval.eval_root().expect("Candidate-C evaluation succeeds");
    let stats = eval.stats();
    let candidate_published = ir.arena.nodes().iter().enumerate().any(|(index, _)| {
        eval.tier1_def_site_slot(index as u64)
            .and_then(|slot| slot.owner().downcast_ref::<NixJitTier1DispatchEntry>())
            .is_some_and(|entry| entry.body.artifact().value_abi() == JitValueAbi::CandidateC)
    });

    assert!(oracle.raw_eq(native));
    assert!(
        candidate_published,
        "a Candidate-C literal body must be published"
    );
    assert_eq!(stats.tier1_promoted(), 1);
    assert_eq!(stats.tier1_deopted(), 0);
    // Every instance is the same closed literal, so thunk hash-consing reuses
    // the first forced thunk rather than dispatching its published body again.
    // The runtime-FFI Candidate-C test exercises the resulting native entry.
    assert!(stats.thunk_cache_hits() >= 1);
}

/// On the baseline carrier an arena-owned scalar (wide int, float) still
/// lowers through the two-word Active-ABI literal path. On the one-word
/// carrier there is no wider fallback — the Active ABI *is* one word and
/// arena-owned scalars cannot be embedded in shared code — so the lowering
/// declines and the def-site stays on the tree walk.
#[test]
fn arena_owned_scalars_fall_back_to_the_active_abi_or_decline() {
    for source in ["2147483648", "1.5"] {
        let ir = lower(source);
        let eval = TreeWalk::new(&ir);
        let engine = NixJitTier1Engine::with_threshold(1)
            .expect("engine builds")
            .candidate_c_value_abi();
        let body = EvalNodeRef::new(ratchet_oracle::eval::EvalModuleId::ROOT, ir.root);
        let lowered = engine.lower_body_artifact(&eval, body);

        #[cfg(not(feature = "candidate_c_value"))]
        assert_eq!(
            lowered.expect("active literal fallback lowers").value_abi(),
            JitValueAbi::Active,
            "source {source}"
        );
        #[cfg(feature = "candidate_c_value")]
        assert!(
            lowered.is_none(),
            "arena-owned scalar {source} must decline on the one-word carrier"
        );
    }
}

#[test]
fn source_backed_ready_call_executes_through_the_mixed_machine() {
    let source = "(f: f 1) (x: 42)";
    let oracle = eval_oracle(source);
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    options.set_mixed_ready_call_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    let engine = Rc::new(NixJitTier1Engine::new().expect("engine builds"));
    eval.set_tier1_engine(engine.clone());

    let native = eval.eval_root().expect("mixed ready-call evaluates");

    assert!(oracle.raw_eq(native));
    assert_eq!(native.as_int(), Ok(42));
    assert_eq!(engine.mixed_ready_run_count(), 1);
}

#[test]
fn source_backed_ready_call_stays_interpreted_by_default() {
    let source = "(f: f 1) (x: 42)";
    let oracle = eval_oracle(source);
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    let engine = Rc::new(NixJitTier1Engine::new().expect("engine builds"));
    eval.set_tier1_engine(engine.clone());

    let native = eval.eval_root().expect("ordinary evaluation succeeds");

    assert!(oracle.raw_eq(native));
    assert_eq!(native.as_int(), Ok(42));
    assert_eq!(engine.mixed_ready_run_count(), 0);
}

#[test]
fn captured_ready_call_target_declines_without_changing_the_result() {
    let source = "(y: (f: f 1) (x: y)) 42";
    let oracle = eval_oracle(source);
    let ir = lower(source);
    let mut options = TreeWalkOptions::default();
    options.set_jit_tier1_publish_enabled(true);
    options.set_mixed_ready_call_enabled(true);
    let mut eval = TreeWalk::with_options(&ir, options);
    let engine = Rc::new(NixJitTier1Engine::new().expect("engine builds"));
    eval.set_tier1_engine(engine.clone());

    let native = eval.eval_root().expect("fallback evaluation succeeds");

    assert!(oracle.raw_eq(native));
    assert_eq!(native.as_int(), Ok(42));
    assert_eq!(engine.mixed_ready_run_count(), 0);
}
