//! Split-out tests (part_2). See parent module.

use super::*;


#[test]
fn eval_cache_expression_trace_adapter_invalidates_existing_trace_backed_payload() {
    let first_fingerprint = read_file_trace(b"/tmp/first", b"same");
    let first_source = TraceSource {
        trace: vec![first_fingerprint.clone()],
        complete: true,
    };
    let second_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/second", b"same")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let first_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &first_source,
        )
        .expect("first inline result and trace observe");
    let node = first_observation
        .node()
        .expect("cacheable trace creates node");
    let first_dependency = first_observation.trace().leaves()[0].node();

    let mut first_revalidator = StaticRevalidator::new(vec![first_fingerprint.clone()]);
    let value = cache
        .lookup_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            &mut first_revalidator,
        )
        .expect("lookup revalidates");
    assert_eq!(value.expect("cache hit").as_int(), Ok(3));

    let second_observation = cache
        .observe_expression_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"value")),
            &second_source,
        )
        .expect("trace-only observation succeeds");
    assert_eq!(second_observation.node(), Some(node));
    let second_dependency = second_observation.trace().leaves()[0].node();

    assert!(
        !cache
            .graph()
            .node(node)
            .expect("expression node exists")
            .dependencies()
            .contains(&first_dependency)
    );
    assert!(
        cache
            .graph()
            .node(node)
            .expect("expression node exists")
            .dependencies()
            .contains(&second_dependency)
    );
    assert_eq!(
        cache
            .graph()
            .node(node)
            .expect("expression node exists")
            .freshness(),
        NodeFreshness::Dirty
    );

    let mut stale_revalidator = StaticRevalidator::new(vec![first_fingerprint]);
    let value = cache
        .lookup_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            &mut stale_revalidator,
        )
        .expect("lookup succeeds");
    assert!(value.is_none());
    assert_eq!(stale_revalidator.calls(), 0);
}

#[test]
fn eval_cache_revalidates_trace_backed_inline_expression_results() {
    let fingerprint = read_file_trace(b"/tmp/version", b"1");
    let source = TraceSource {
        trace: vec![fingerprint.clone()],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(vec![fingerprint]);
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let value = cache
        .lookup_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("lookup revalidates");

    assert_eq!(value.expect("cache hit").as_int(), Ok(3));
    assert_eq!(revalidator.calls(), 1);
}

#[test]
fn changed_revalidated_input_dirties_trace_backed_inline_expression() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(vec![read_file_trace(b"/tmp/version", b"2")]);
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let node = observation.node().expect("cacheable trace creates node");

    let value = cache
        .lookup_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("lookup revalidates");

    assert!(value.is_none());
    assert_eq!(revalidator.calls(), 1);
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("public lookup succeeds");
    assert!(value.is_none());
}

#[test]
fn unavailable_revalidated_input_invalidates_trace_backed_inline_expression() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(Vec::new());
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let node = observation.node().expect("cacheable trace creates node");

    let value = cache
        .lookup_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("lookup handles unavailable input");

    assert!(value.is_none());
    assert_eq!(revalidator.calls(), 1);
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn changed_impure_edge_dirties_inline_expression_payload_node() {
    let first = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let changed = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"2")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &first,
        )
        .expect("inline result and trace observe");
    let node = observation.node().expect("cacheable trace creates node");

    cache
        .observe_impure_inputs(&changed)
        .expect("changed input observes");

    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
}

#[test]
fn inline_expression_result_with_uncacheable_trace_skips_payload() {
    let source = TraceSource {
        trace: vec![ImpureInputFingerprint::current_time()],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("uncacheable trace classifies");

    assert_eq!(
        observation.cacheability(),
        ExpressionCacheability::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert!(cache.is_empty());
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
}
