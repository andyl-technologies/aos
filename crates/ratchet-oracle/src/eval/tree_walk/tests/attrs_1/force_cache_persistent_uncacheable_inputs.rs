//! Persistent force-cache tests for uncacheable impure inputs.

use super::*;

fn persistent_runtime() -> Arc<Mutex<EvalCacheRuntime>> {
    Arc::new(Mutex::new(EvalCacheRuntime::enabled()))
}

fn current_time_options(time: i64, persist_root: &std::path::Path) -> TreeWalkOptions {
    let mut options = TreeWalkOptions::with_current_time(time).expect("currentTime is valid");
    options.set_eval_cache_enabled(true);
    options.set_persist_cache_root(persist_root);
    options
}

fn force_current_time(ir: &Ir, source: &str, a: Symbol, options: TreeWalkOptions) -> TreeWalk {
    let expected_time = options.current_time().expect("currentTime configured");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        options,
        "current-time.nix",
        source,
        persistent_runtime(),
    );
    let forced = force_attr_a(&mut evaluator, ir, a);
    assert_eq!(
        evaluator.impure_input_trace(),
        [ImpureInputFingerprint::current_time()].as_slice()
    );
    assert_eq!(evaluator.stats().cache_hits(), 0);
    assert_eq!(evaluator.stats().cache_misses(), 0);
    assert_eq!(evaluator.stats().force_cache_hits(), 0);
    assert_eq!(evaluator.stats().force_cache_misses(), 0);
    assert_eq!(
        evaluator.stats().thunks_forced(),
        1,
        "currentTime must force normally instead of replaying persistent values"
    );
    assert_eq!(forced.as_int(), Ok(expected_time));
    evaluator
}

#[test]
fn current_time_forced_expression_never_replays_persistent_cache() {
    let persist_root = unique_temp_dir("force-cache-persistent-current-time-no-replay");
    let source = "{ a = builtins.currentTime; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");

    let first = force_current_time(
        &ir,
        source,
        a,
        current_time_options(1_700_000_000, &persist_root),
    );
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "first currentTime forced-expression run",
    );
    drop(first);

    let same_time = force_current_time(
        &ir,
        source,
        a,
        current_time_options(1_700_000_000, &persist_root),
    );
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "same-time currentTime forced-expression run",
    );
    drop(same_time);

    let changed_time = force_current_time(
        &ir,
        source,
        a,
        current_time_options(1_700_000_123, &persist_root),
    );
    assert_persistent_force_cache_sidecars_empty(
        &persist_root,
        "changed-time currentTime forced-expression run",
    );
    drop(changed_time);

    fs::remove_dir_all(persist_root).expect("persistent temp tree removed");
}
