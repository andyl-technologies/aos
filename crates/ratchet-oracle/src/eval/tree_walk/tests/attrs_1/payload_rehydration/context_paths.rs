//! Context-bearing path payload rehydration coverage.

use super::*;

#[test]
fn context_path_payloads_rehydrate_after_heap_lookup() {
    let ir = lower("1");
    let identity = CacheExprIdentity::new(
        CacheExprSourceHash::from_persisted_hash(DurableBlake3Hash::for_bytes(
            b"force-context-path-result",
        )),
        IrId::new(13),
    );
    let subject = ForceCacheSubject {
        lookup_identity: Some(identity),
        pure_observation_identity: Some(identity),
        impure_observation_identity: Some(identity),
        metadata_identity: Some(identity),
        persistent_clear_identity: Some(identity),
        free_var_value_hashes: Vec::new(),
        replay_position_module: None,
        replay_allocation_node: None,
        memoization_admission: ForceCacheMemoizationAdmission::ConditionalThunk,
    };
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));
    let context = StringContext::singleton(
        ContextElement::opaque_path(b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec())
            .expect("context path is valid"),
    )
    .expect("context allocates");

    let mut first =
        TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache.clone());
    let value = first
        .heap
        .alloc_path(NixString::new(
            b"/nix/store/context-path".to_vec(),
            context.clone(),
        ))
        .expect("context path allocates");
    first.observe_forced_inline_expression_result(
        Some(subject.clone()),
        value,
        ImpureInputTraceSegment {
            trace: Vec::new(),
            complete: true,
        },
    );
    drop(first);

    let mut second = TreeWalk::with_options_and_eval_cache(&ir, TreeWalkOptions::new(), cache);
    let hit = second
        .lookup_forced_inline_expression_result(Some(subject))
        .expect("context path payload hits");
    let path = second
        .heap()
        .get_path(hit)
        .expect("context path rehydrates into this evaluator heap");

    assert_eq!(path.bytes(), b"/nix/store/context-path");
    assert_eq!(path.context(), &context);
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);
}
