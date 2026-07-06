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
