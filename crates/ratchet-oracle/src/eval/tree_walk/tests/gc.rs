//! Tree-walk GC barrier integration tests.

use super::*;
use crate::eval::heap::HeapAllocationDomain;
use crate::heap::{GcHeapAddress, HeapGeneration, RememberedEdge};

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointer is a valid GC address")
}

fn force_permanent_attr_thunk(options: TreeWalkOptions) -> (TreeWalk, Value, Value) {
    force_attr_thunk(
        "{ a = x: x; }",
        b"a",
        options,
        Some(HeapAllocationDomain::PermanentShared),
    )
}

fn force_attr_thunk(
    source: &str,
    attr_name: &[u8],
    options: TreeWalkOptions,
    source_domain: Option<HeapAllocationDomain>,
) -> (TreeWalk, Value, Value) {
    let ir = lower(source);
    let attr = symbol_for(&ir, attr_name);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("root is an attrset");
        attrs.get(attr).expect("attr exists")
    };
    assert_eq!(thunk_value.tag(), ValueTag::Thunk);
    if let Some(domain) = source_domain {
        evaluator
            .heap
            .set_allocation_domain_for_test(thunk_value, domain)
            .expect("test can mark source thunk domain");
    }
    let forced = evaluator
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("thunk force succeeds");
    (evaluator, thunk_value, forced)
}

#[test]
fn daemon_thunk_forcing_records_remembered_edge() {
    let (evaluator, thunk_value, forced) = force_permanent_attr_thunk(
        TreeWalkOptions::with_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational),
    );
    let edge = RememberedEdge::new(gc_address(thunk_value), gc_address(forced));

    assert_eq!(forced.tag(), ValueTag::Lambda);
    assert_eq!(evaluator.thunk_resolve_remembered_set().edges(), &[edge]);
    assert_eq!(evaluator.thunk_resolve_card_table().len(), 1);
    assert_eq!(
        evaluator.thunk_resolve_card_table().dirty_cards()[0].source(),
        edge.source()
    );
}

#[test]
fn daemon_thunk_forcing_skips_young_source_even_for_young_forced_value() {
    let (evaluator, thunk_value, forced) = force_attr_thunk(
        "{ a = x: x; }",
        b"a",
        TreeWalkOptions::with_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational),
        None,
    );

    assert_eq!(forced.tag(), ValueTag::Lambda);
    assert_eq!(
        evaluator
            .heap()
            .allocation_domain(forced)
            .expect("forced lambda belongs to this heap"),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(thunk_value)
            .expect("source thunk belongs to this heap"),
        HeapGeneration::Young
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(forced)
            .expect("forced lambda belongs to this heap"),
        HeapGeneration::Young
    );
    assert!(evaluator.thunk_resolve_remembered_set().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

#[test]
fn daemon_thunk_forcing_skips_permanent_forced_value_cards() {
    let (evaluator, thunk_value, forced) = force_attr_thunk(
        "{ a = (x: x) \"resident\"; }",
        b"a",
        TreeWalkOptions::with_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational),
        Some(HeapAllocationDomain::PermanentShared),
    );

    assert_eq!(forced.tag(), ValueTag::String);
    assert_eq!(
        evaluator
            .heap()
            .allocation_domain(forced)
            .expect("forced string belongs to this heap"),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(thunk_value)
            .expect("source thunk belongs to this heap"),
        HeapGeneration::Permanent
    );
    assert_eq!(
        evaluator
            .heap()
            .generation(forced)
            .expect("forced string belongs to this heap"),
        HeapGeneration::Permanent
    );
    assert!(evaluator.thunk_resolve_remembered_set().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

#[test]
fn one_shot_thunk_forcing_keeps_remembered_set_empty() {
    let (evaluator, _thunk_value, forced) = force_permanent_attr_thunk(TreeWalkOptions::new());

    assert_eq!(forced.tag(), ValueTag::Lambda);
    assert!(evaluator.thunk_resolve_remembered_set().is_empty());
    assert!(evaluator.thunk_resolve_card_table().is_empty());
}

#[test]
fn daemon_force_cache_replay_runs_barrier_without_remembered_edge_for_permanent_target() {
    let source = "{ a = [ \"cached\" ]; }";
    let ir = lower(source);
    let a = symbol_for(&ir, b"a");
    let cache = Arc::new(Mutex::new(EvalCacheRuntime::enabled()));

    let mut first = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::new(),
        "expr.nix",
        source,
        cache.clone(),
    );
    let root = first.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = first.heap().get_attrs(root).expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    let warmed = first
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("warming force succeeds");
    let warmed_list = first
        .heap()
        .get_list(warmed)
        .expect("warming result is a list");
    let warmed_string = warmed_list.get(0).expect("warming list has an element");
    assert_eq!(
        first
            .heap()
            .get_string(warmed_string)
            .expect("warming element is a string")
            .bytes(),
        b"cached"
    );
    assert_eq!(first.stats().cache_hits(), 0);
    drop(first);

    let mut replay = TreeWalk::with_options_and_source_and_eval_cache(
        &ir,
        TreeWalkOptions::with_thunk_resolve_barrier_tier(GenerationalGcTier::DaemonGenerational),
        "expr.nix",
        source,
        cache,
    );
    let root = replay.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = replay.heap().get_attrs(root).expect("root is an attrset");
        attrs.get(a).expect("a exists")
    };
    replay
        .heap
        .set_allocation_domain_for_test(thunk_value, HeapAllocationDomain::PermanentShared)
        .expect("test can mark replay source thunk permanent");
    let forced = replay
        .force_value(ir.root, Span::new(0, 0), thunk_value)
        .expect("replay force succeeds");

    let replayed_list = replay
        .heap()
        .get_list(forced)
        .expect("replayed result is a list");
    let replayed_string = replayed_list.get(0).expect("replayed list has an element");
    assert_eq!(
        replay
            .heap()
            .get_string(replayed_string)
            .expect("replayed element is a string")
            .bytes(),
        b"cached"
    );
    assert_eq!(replay.stats().cache_hits(), 1);
    assert_eq!(replay.stats().thunks_forced(), 0);
    assert_eq!(
        replay
            .heap()
            .allocation_domain(forced)
            .expect("replayed target belongs to this heap"),
        HeapAllocationDomain::PermanentShared
    );
    assert!(
        replay.thunk_resolve_remembered_set().is_empty(),
        "force-cache replayed composites rehydrate as permanent targets"
    );
    assert!(
        replay.thunk_resolve_card_table().is_empty(),
        "force-cache replayed permanent targets do not dirty cards"
    );
}

/// A program with plenty of thunk garbage: each call allocates a `heavy`
/// thunk that is demanded only on the untaken branch, so its record dies with
/// the call frame once the result is strict. (Bindings must be conditionally
/// used - a never-used binding would be removed by dead-binding elimination,
/// and values stored into attrsets are immortal via permanent hash-consing.)
const SWEEP_FIXTURE: &str =
    "let\n  pick = n: let heavy = (x: x * x) n; in if n > 0 then n + 1 else heavy;\nin pick 1 + pick 2 + pick 3";

#[test]
fn sweep_mode_evaluation_is_byte_identical_and_sheds_captures() {
    let ir = lower(SWEEP_FIXTURE);
    let baseline = eval_raw_bytes_with_options(&ir, TreeWalkOptions::default())
        .expect("baseline evaluates");

    let mut options = TreeWalkOptions::default();
    options.set_gc_mode(EvalGcMode::Sweep);
    options.set_gc_sweep_threshold(0);
    let swept = eval_raw_bytes_with_options(&ir, options.clone()).expect("sweep-mode evaluates");
    assert_eq!(baseline, swept, "AOS_NIX_GC=sweep must be byte-invisible");

    let outcome = eval_whnf_owned_with_options(&ir, options).expect("owned sweep-mode evaluates");
    let stats = outcome.stats();
    assert!(
        stats.thunks_shed() > 0,
        "forced thunks shed their captures under sweep mode"
    );
    assert_eq!(
        stats.gc_sweeps(),
        1,
        "threshold 0 sweeps once at the post-root quiescent point"
    );
    assert!(
        stats.gc_records_swept() > 0,
        "dead worker records are retired by the quiescent sweep"
    );
    assert_eq!(stats.gc_sweeps_skipped_nonquiescent(), 0);
}

#[test]
fn sweep_mode_off_by_default_keeps_counters_zero() {
    let outcome = eval_whnf_owned(&lower(SWEEP_FIXTURE)).expect("expression evaluates");
    let stats = outcome.stats();
    assert_eq!(stats.thunks_shed(), 0);
    assert_eq!(stats.gc_sweeps(), 0);
    assert_eq!(stats.gc_records_swept(), 0);
}

#[test]
fn parallel_mode_pins_sweep_off() {
    let ir = lower(SWEEP_FIXTURE);
    let mut options = TreeWalkOptions::default();
    options.set_gc_mode(EvalGcMode::Sweep);
    options.set_gc_sweep_threshold(0);
    options.set_parallel_thunk_payloads_enabled(true);
    let outcome = eval_whnf_owned_with_options(&ir, options).expect("parallel-mode evaluates");
    let stats = outcome.stats();
    assert_eq!(
        stats.thunks_shed(),
        0,
        "parallel evaluation pins Tier-B reclamation off"
    );
    assert_eq!(stats.gc_sweeps(), 0);
}

#[test]
fn validation_sweep_preserves_later_forcing() {
    // Force one attr, sweep with the root as the only extra root, then force
    // the second attr: the sweep must retire only true garbage, and the still
    // reachable suspended thunk must keep evaluating correctly afterwards.
    let ir = lower("{ a = (x: x + 1) 1; b = (y: y * 3) 2; }");
    let mut options = TreeWalkOptions::default();
    options.set_gc_mode(EvalGcMode::Sweep);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let root = evaluator.eval_root().expect("attrset evaluates");
    let (a_value, b_value) = {
        let attrs = evaluator.heap().get_attrs(root).expect("root is attrs");
        (
            attrs.get(symbol_for(&ir, b"a")).expect("a exists"),
            attrs.get(symbol_for(&ir, b"b")).expect("b exists"),
        )
    };
    let span = Span::new(0, 0);
    let a_forced = evaluator
        .force_value(ir.root, span, a_value)
        .expect("a forces");
    assert!(a_forced.raw_eq(Value::int(2)));

    let report = evaluator
        .sweep_heap_for_validation(&[root])
        .expect("validation sweep succeeds");
    assert!(report.live_worker_records > 0);

    let b_forced = evaluator
        .force_value(ir.root, span, b_value)
        .expect("b still forces after the sweep");
    assert!(b_forced.raw_eq(Value::int(6)));
}
