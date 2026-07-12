//! Trace-backed inline payload invalidation and runtime coverage.

use super::*;

#[test]
fn uncacheable_trace_invalidates_existing_reusable_inline_payload() {
    let source = TraceSource {
        trace: vec![ImpureInputFingerprint::current_time()],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let expression_identity = identity(b"source", 7);
    let previous = cache
        .observe_inline_expression_result(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("previous pure result observes");
    let consumer_identity = identity(b"consumer", 1);
    let consumer = cache
        .observe_inline_expression_result(
            consumer_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(4),
        )
        .expect("consumer pure result observes")
        .node();
    cache
        .graph
        .add_dependency(consumer, previous.node())
        .expect("consumer memo edge records");
    let grandconsumer_identity = identity(b"grandconsumer", 2);
    let grandconsumer = cache
        .observe_inline_expression_result(
            grandconsumer_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(5),
        )
        .expect("grandconsumer pure result observes")
        .node();
    cache
        .graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");
    assert!(cache.inline_values.contains_key(&previous.node()));
    assert!(cache.inline_values.contains_key(&consumer));
    assert!(cache.inline_values.contains_key(&grandconsumer));

    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
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
    assert_eq!(
        cache
            .graph()
            .node(consumer)
            .expect("consumer exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        cache
            .graph()
            .node(grandconsumer)
            .expect("grandconsumer exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert!(!cache.inline_values.contains_key(&previous.node()));
    assert!(!cache.inline_values.contains_key(&consumer));
    assert!(!cache.inline_values.contains_key(&grandconsumer));
    let value = cache
        .lookup_inline_expression_result(expression_identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
    let consumer_value = cache
        .lookup_inline_expression_result(consumer_identity, std::iter::empty::<ValueHash>())
        .expect("consumer lookup succeeds");
    assert!(consumer_value.is_none());
    let grandconsumer_value = cache
        .lookup_inline_expression_result(grandconsumer_identity, std::iter::empty::<ValueHash>())
        .expect("grandconsumer lookup succeeds");
    assert!(grandconsumer_value.is_none());
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
            std::iter::empty::<ValueHash>(),
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
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
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
    let expression_identity = identity(b"source", 7);
    let previous = cache
        .observe_inline_expression_result(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("previous pure result observes");
    let consumer_identity = identity(b"consumer", 1);
    let consumer = cache
        .observe_inline_expression_result(
            consumer_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(4),
        )
        .expect("consumer pure result observes")
        .node();
    cache
        .graph
        .add_dependency(consumer, previous.node())
        .expect("consumer memo edge records");
    let grandconsumer_identity = identity(b"grandconsumer", 2);
    let grandconsumer = cache
        .observe_inline_expression_result(
            grandconsumer_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(5),
        )
        .expect("grandconsumer pure result observes")
        .node();
    cache
        .graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");

    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
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
    assert_eq!(
        cache
            .graph()
            .node(consumer)
            .expect("consumer exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        cache
            .graph()
            .node(grandconsumer)
            .expect("grandconsumer exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert!(!cache.inline_values.contains_key(&previous.node()));
    assert!(!cache.inline_values.contains_key(&consumer));
    assert!(!cache.inline_values.contains_key(&grandconsumer));
    let value = cache
        .lookup_inline_expression_result(expression_identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");
    assert!(value.is_none());
    let consumer_value = cache
        .lookup_inline_expression_result(consumer_identity, std::iter::empty::<ValueHash>())
        .expect("consumer lookup succeeds");
    assert!(consumer_value.is_none());
    let grandconsumer_value = cache
        .lookup_inline_expression_result(grandconsumer_identity, std::iter::empty::<ValueHash>())
        .expect("grandconsumer lookup succeeds");
    assert!(grandconsumer_value.is_none());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn unsupported_trace_backed_value_invalidates_existing_reusable_inline_payload() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let previous = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("previous trace-backed result observes");
    let previous_node = previous.node().expect("cacheable trace creates node");
    let input_dependency = previous.trace().leaves()[0].node();
    assert!(
        cache
            .graph()
            .node(previous_node)
            .expect("previous node exists")
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .expect("previous node has an impure-input edge")
            .contains(&input_dependency)
    );
    let heap_value = Value::string(std::ptr::NonNull::<crate::value::HeapObject>::dangling())
        .expect("dangling heap pointer is aligned");

    let error = cache
        .observe_inline_expression_result_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
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
            .node(previous_node)
            .expect("previous node still exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert!(
        cache
            .graph()
            .node(previous_node)
            .expect("previous node still exists")
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .is_none(),
        "failed trace-backed replacement should clear stale impure-input ownership"
    );
    assert!(
        !cache
            .graph()
            .node(input_dependency)
            .expect("input dependency still exists")
            .dependents()
            .contains(&previous_node),
        "failed trace-backed replacement should remove the stale reverse edge"
    );
    let value = cache
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
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
            std::iter::empty::<ValueHash>(),
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
            std::iter::empty::<ValueHash>(),
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
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("disabled lookup succeeds");

    assert!(value.is_none());
    assert_eq!(revalidator.calls(), 0);
}
