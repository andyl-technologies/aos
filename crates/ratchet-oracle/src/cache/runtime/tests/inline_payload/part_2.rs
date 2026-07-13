//! Split-out tests (part_2). See parent module.

use super::*;


#[test]
fn dirty_pure_inline_payload_with_clean_changed_memo_supplier_stays_miss() {
    let mut cache = EvalCache::new();
    let parent_identity = identity(b"parent", 1);
    let child_identity = identity(b"child", 2);
    let parent_observation = cache
        .observe_inline_expression_result(
            parent_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(10),
        )
        .expect("parent result observes");
    let child_observation = cache
        .observe_inline_expression_result(
            child_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("child result observes");
    cache
        .record_memo_read_dependency(parent_observation.node(), child_observation.node())
        .expect("memo-read edge records");

    let child_change = cache
        .graph
        .reconsider_node(
            child_observation.node(),
            ValueHash::from_inline_value(Value::int(4)).expect("inline value hashes"),
        )
        .expect("child recomputation records changed hash");
    assert_eq!(child_change.decision(), CutoffDecision::Propagate);
    assert_eq!(
        child_change.dirtied_dependents(),
        &[parent_observation.node()]
    );
    assert_eq!(
        cache
            .graph()
            .node(child_observation.node())
            .expect("child node exists")
            .freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(
        cache
            .graph()
            .node(parent_observation.node())
            .expect("parent node exists")
            .freshness(),
        NodeFreshness::Dirty
    );

    let plain_hit = cache
        .lookup_inline_expression_payload_hit(parent_identity, std::iter::empty::<ValueHash>())
        .expect("plain lookup succeeds");
    assert!(plain_hit.is_none());
    assert_eq!(
        cache
            .graph()
            .node(parent_observation.node())
            .expect("parent node exists")
            .freshness(),
        NodeFreshness::Dirty
    );

    let mut revalidator = StaticRevalidator::new(Vec::new());
    let impure_aware_hit = cache
        .lookup_inline_expression_payload_hit_with_impure_inputs(
            parent_identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("impure-aware lookup succeeds");
    assert!(impure_aware_hit.is_none());
    assert_eq!(revalidator.calls(), 0);
    assert_eq!(
        cache
            .graph()
            .node(parent_observation.node())
            .expect("parent node exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(cache.inline_payload_record_count(), 2);
}

#[test]
fn eval_cache_lookup_rejects_stale_inline_payload_records() {
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let observation = cache
        .observe_inline_expression_result(identity, std::iter::empty::<ValueHash>(), Value::int(3))
        .expect("result observes");
    cache
        .graph
        .reconsider_node(
            observation.node(),
            ValueHash::from_inline_value(Value::int(4)).expect("inline value hashes"),
        )
        .expect("node can be reconsidered independently");

    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");

    assert!(value.is_none());
}

#[test]
fn pure_inline_observation_clears_prior_impure_edges() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let trace_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("trace-backed result observes");
    let node = trace_observation
        .node()
        .expect("cacheable trace creates node");
    let input_leaf = trace_observation.trace().leaves()[0].node();

    cache
        .observe_inline_expression_result(identity, std::iter::empty::<ValueHash>(), Value::int(3))
        .expect("pure result observes");

    let node_record = cache.graph().node(node).expect("node exists");
    assert!(node_record.dependencies().is_empty());
    assert!(
        node_record
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .is_none()
    );
    assert!(
        !cache
            .graph()
            .node(input_leaf)
            .expect("input leaf exists")
            .dependents()
            .contains(&node)
    );

    cache
        .graph
        .observe_impure_trace(&[read_file_trace(b"/tmp/version", b"2")], true)
        .expect("changed stale input observes");
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Clean
    );
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds")
        .expect("pure payload still hits");
    assert_eq!(value.as_int(), Ok(3));
}

#[test]
fn pure_inline_observation_preserves_memo_read_edges_while_clearing_impure_edges() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let expression_identity = identity(b"source", 7);
    let memo_dependency = cache
        .get_or_insert_expression_node(
            identity(b"memo", 1),
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"memo")),
        )
        .expect("memo dependency inserts");
    let trace_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("trace-backed result observes");
    let node = trace_observation
        .node()
        .expect("cacheable trace creates node");
    let input_leaf = trace_observation.trace().leaves()[0].node();
    cache
        .record_memo_read_dependency(node, memo_dependency)
        .expect("memo-read edge records");

    cache
        .observe_inline_expression_result(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("pure result observes");

    let node_record = cache.graph().node(node).expect("node exists");
    assert!(
        node_record
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .is_none()
    );
    assert!(
        node_record
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .expect("memo-read group remains")
            .contains(&memo_dependency)
    );
    assert!(node_record.dependencies().contains(&memo_dependency));
    assert!(!node_record.dependencies().contains(&input_leaf));
    assert!(
        cache
            .graph()
            .node(memo_dependency)
            .expect("memo dependency exists")
            .dependents()
            .contains(&node)
    );
    assert!(
        !cache
            .graph()
            .node(input_leaf)
            .expect("input leaf exists")
            .dependents()
            .contains(&node)
    );
}

#[test]
fn enabled_eval_cache_runtime_observes_inline_expression_results() {
    let mut runtime = EvalCacheRuntime::enabled();
    let identity = identity(b"source", 7);

    let first = runtime
        .observe_inline_expression_result(identity, std::iter::empty::<ValueHash>(), Value::int(3))
        .expect("first result observes")
        .expect("enabled runtime observes expression results");
    let second = runtime
        .observe_inline_expression_result(identity, std::iter::empty::<ValueHash>(), Value::int(3))
        .expect("second result observes")
        .expect("enabled runtime observes expression results");

    assert_eq!(first.decision(), crate::cache::CutoffDecision::Propagate);
    assert_eq!(second.node(), first.node());
    assert_eq!(second.decision(), crate::cache::CutoffDecision::CutOff);
    assert_eq!(runtime.cache().expect("cache is enabled").len(), 1);
}

#[test]
fn enabled_eval_cache_runtime_looks_up_inline_expression_results() {
    let mut runtime = EvalCacheRuntime::enabled();
    let identity = identity(b"source", 7);

    runtime
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::bool(true),
        )
        .expect("result observes")
        .expect("enabled runtime observes expression results");
    let value = runtime
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds")
        .expect("memoized inline result is present");

    assert_eq!(value.as_bool(), Ok(true));
}

#[test]
fn disabled_eval_cache_runtime_expression_result_observation_is_noop() {
    let mut runtime = EvalCacheRuntime::disabled();

    let observation = runtime
        .observe_inline_expression_result(
            identity(b"source", 7),
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("disabled expression result observation succeeds");

    assert_eq!(observation, None);
    assert!(runtime.cache().is_none());
}

#[test]
fn disabled_eval_cache_runtime_expression_result_lookup_is_noop() {
    let mut runtime = EvalCacheRuntime::disabled();

    let value = runtime
        .lookup_inline_expression_result(identity(b"source", 7), std::iter::empty::<ValueHash>())
        .expect("disabled lookup succeeds");

    assert!(value.is_none());
    assert!(runtime.cache().is_none());
}

#[test]
fn eval_cache_reconsiders_expression_node_from_inline_value() {
    let mut cache = EvalCache::new();
    let node = cache
        .get_or_insert_expression_node(
            identity(b"source", 7),
            [value_hash(b"free-var")],
            Some(ValueHash::from_inline_value(Value::int(1)).expect("inline value hashes")),
        )
        .expect("expression node inserts");

    let reconsideration = cache
        .reconsider_inline_value_node(node, Value::int(2))
        .expect("node reconsiders");

    assert_eq!(
        reconsideration.decision(),
        crate::cache::CutoffDecision::Propagate
    );
    assert_eq!(
        cache.graph().node(node).expect("node exists").value_hash(),
        Some(ValueHash::from_inline_value(Value::int(2)).expect("inline value hashes"))
    );
}
