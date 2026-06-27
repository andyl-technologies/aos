//! Trace-backed inline expression payload cache tests.

use super::*;

#[test]
fn eval_cache_observes_inline_expression_results_with_impure_edges_without_hits() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");

    assert_eq!(observation.trace().status(), ImpureTraceStatus::Cacheable);
    let node = observation.node().expect("cacheable trace creates node");
    assert_eq!(
        observation.cacheability(),
        ExpressionCacheability::Cacheable(node)
    );
    let dependency = observation.trace().leaves()[0].node();
    assert!(
        cache
            .graph()
            .node(node)
            .expect("expression node exists")
            .dependencies()
            .contains(&dependency)
    );
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");
    assert!(
        value.is_none(),
        "trace-backed payloads require input revalidation before reuse"
    );
    assert_eq!(cache.len(), 2);
}

#[test]
fn eval_cache_recomputed_trace_backed_payload_replaces_prior_input_edges() {
    let first_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/first", b"same")],
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
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &first_source,
        )
        .expect("first inline result and trace observe");
    let node = first_observation
        .node()
        .expect("cacheable trace creates node");
    let first_dependency = first_observation.trace().leaves()[0].node();

    let second_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &second_source,
        )
        .expect("second inline result and trace observe");
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
    assert!(
        !cache
            .graph()
            .node(first_dependency)
            .expect("first dependency exists")
            .dependents()
            .contains(&node)
    );
    assert!(
        cache
            .graph()
            .node(second_dependency)
            .expect("second dependency exists")
            .dependents()
            .contains(&node)
    );

    cache
        .observe_impure_inputs(&TraceSource {
            trace: vec![read_file_trace(b"/tmp/first", b"changed")],
            complete: true,
        })
        .expect("stale input reconsiders");
    assert_eq!(
        cache
            .graph()
            .node(node)
            .expect("expression node exists")
            .freshness(),
        NodeFreshness::Clean
    );

    cache
        .observe_impure_inputs(&TraceSource {
            trace: vec![read_file_trace(b"/tmp/second", b"changed")],
            complete: true,
        })
        .expect("current input reconsiders");
    assert_eq!(
        cache
            .graph()
            .node(node)
            .expect("expression node exists")
            .freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn eval_cache_trace_backed_payload_reports_early_cutoff_reconsideration() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"same")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    let first_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &source,
        )
        .expect("first inline result and trace observe");
    assert_eq!(
        first_observation
            .payload_reconsideration()
            .expect("payload reconsideration is reported")
            .decision(),
        CutoffDecision::Propagate
    );

    let second_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &source,
        )
        .expect("second inline result and trace observes");
    assert_eq!(
        second_observation
            .payload_reconsideration()
            .expect("payload reconsideration is reported")
            .decision(),
        CutoffDecision::CutOff
    );
}

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
            std::iter::empty::<DurableBlake3Hash>(),
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
            std::iter::empty::<DurableBlake3Hash>(),
            &mut first_revalidator,
        )
        .expect("lookup revalidates");
    assert_eq!(value.expect("cache hit").as_int(), Ok(3));

    let second_observation = cache
        .observe_expression_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
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
            std::iter::empty::<DurableBlake3Hash>(),
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
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let value = cache
        .lookup_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
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
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let node = observation.node().expect("cacheable trace creates node");

    let value = cache
        .lookup_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
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
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let node = observation.node().expect("cacheable trace creates node");

    let value = cache
        .lookup_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
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
            std::iter::empty::<DurableBlake3Hash>(),
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
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
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
            std::iter::empty::<DurableBlake3Hash>(),
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
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
}

#[test]
fn uncacheable_trace_invalidates_existing_reusable_inline_payload() {
    let source = TraceSource {
        trace: vec![ImpureInputFingerprint::current_time()],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let previous = cache
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("previous pure result observes");

    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(4),
            &source,
        )
        .expect("uncacheable trace classifies");

    assert_eq!(
        observation.cacheability(),
        ExpressionCacheability::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert_eq!(
        cache
            .graph()
            .node(previous.node())
            .expect("previous node still exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
}

#[test]
fn inline_expression_result_with_incomplete_trace_skips_payload() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: false,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);

    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
            &source,
        )
        .expect("incomplete trace classifies");

    assert_eq!(
        observation.cacheability(),
        ExpressionCacheability::Incomplete
    );
    assert!(cache.is_empty());
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
}

#[test]
fn incomplete_trace_invalidates_existing_reusable_inline_payload() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: false,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let previous = cache
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("previous pure result observes");

    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(4),
            &source,
        )
        .expect("incomplete trace classifies");

    assert_eq!(
        observation.cacheability(),
        ExpressionCacheability::Incomplete
    );
    assert_eq!(
        cache
            .graph()
            .node(previous.node())
            .expect("previous node still exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
}

#[test]
fn unsupported_trace_backed_value_invalidates_existing_reusable_inline_payload() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let previous = cache
        .observe_inline_expression_result(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            Value::int(3),
        )
        .expect("previous pure result observes");
    let heap_value = Value::string(std::ptr::NonNull::<crate::value::HeapObject>::dangling())
        .expect("dangling heap pointer is aligned");

    let error = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<DurableBlake3Hash>(),
            heap_value,
            &source,
        )
        .expect_err("heap-backed values are not inline-cacheable");

    assert!(matches!(
        error,
        DemandGraphError::ValueHash {
            source: ValueHashError::UnsupportedTag {
                tag: crate::value::ValueTag::String
            }
        }
    ));
    assert_eq!(
        cache
            .graph()
            .node(previous.node())
            .expect("previous node still exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<DurableBlake3Hash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
}

#[test]
fn enabled_eval_cache_runtime_observes_inline_expression_trace_results() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut runtime = EvalCacheRuntime::enabled();

    let observation = runtime
        .observe_inline_expression_result_with_impure_inputs(
            identity(b"source", 7),
            std::iter::empty::<DurableBlake3Hash>(),
            Value::bool(true),
            &source,
        )
        .expect("enabled inline trace result observes")
        .expect("enabled runtime observes inline trace results");

    assert_eq!(observation.trace().status(), ImpureTraceStatus::Cacheable);
    assert!(observation.node().is_some());
    assert_eq!(runtime.cache().expect("cache is enabled").len(), 2);
}

#[test]
fn disabled_eval_cache_runtime_inline_expression_trace_result_is_noop() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut runtime = EvalCacheRuntime::disabled();

    let observation = runtime
        .observe_inline_expression_result_with_impure_inputs(
            identity(b"source", 7),
            std::iter::empty::<DurableBlake3Hash>(),
            Value::bool(true),
            &source,
        )
        .expect("disabled inline trace result observation succeeds");

    assert_eq!(observation, None);
    assert!(runtime.cache().is_none());
}

#[test]
fn disabled_eval_cache_runtime_revalidating_lookup_is_noop() {
    let mut runtime = EvalCacheRuntime::disabled();
    let mut revalidator = StaticRevalidator::new(vec![read_file_trace(b"/tmp/version", b"1")]);

    let value = runtime
        .lookup_inline_expression_result_with_impure_inputs(
            identity(b"source", 7),
            std::iter::empty::<DurableBlake3Hash>(),
            &mut revalidator,
        )
        .expect("disabled lookup succeeds");

    assert!(value.is_none());
    assert_eq!(revalidator.calls(), 0);
}
