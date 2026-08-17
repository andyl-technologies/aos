//! Force-cache identity tests for source-backed and source-less attr thunks.

use super::*;

mod option_identity;

mod memo_edges;
mod part_1;
mod part_2;

fn synthetic_selected_force_cache_subject(identity: CacheExprIdentity) -> ForceCacheSubject {
    ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::SelectedSubstrate,
    }
}

fn force_cache_identity_for_attr_a(ir: &Ir, source: &str) -> (CacheExprIdentity, IrId) {
    let a = symbol_for(ir, b"a");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        TreeWalkOptions::new(),
        "default.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    let body = thunk.body().expect("a is a node thunk");
    let identity = evaluator
        .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
        .expect("force-cache subject builds")
        .metadata_identity
        .expect("node thunk has metadata identity");
    (identity, body)
}

fn force_cache_identity_for_source_less_attr_a(ir: &Ir) -> (CacheExprIdentity, IrId) {
    let a = symbol_for(ir, b"a");
    let mut evaluator = TreeWalk::with_options_and_eval_cache(
        ir,
        TreeWalkOptions::new(),
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let thunk = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a is a thunk");
    let body = thunk.body().expect("a is a node thunk");
    let identity = evaluator
        .force_cache_subject_for_thunk(EvalNodeRef::new(EvalModuleId::ROOT, ir.root), thunk)
        .expect("force-cache subject builds")
        .metadata_identity
        .expect("node thunk has metadata identity");
    (identity, body)
}
