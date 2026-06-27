//! Eval cache expression trace adapter tests.

use super::*;

#[test]
fn eval_cache_expression_node_can_observe_impure_edges() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let dependent = cache
        .get_or_insert_expression_node(
            identity(b"source", 7),
            [durable_hash(b"free-var")],
            Some(value_hash(b"value")),
        )
        .expect("expression node inserts");

    let observation = cache
        .observe_impure_inputs_for_node(dependent, &source)
        .expect("trace observes and wires");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    let dependency = observation.leaves()[0].node();
    assert!(
        cache
            .graph()
            .node(dependent)
            .expect("dependent exists")
            .dependencies()
            .contains(&dependency)
    );
}

#[test]
fn eval_cache_expression_trace_adapter_wires_cacheable_inputs() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut cache = EvalCache::new();

    let observation = cache
        .observe_expression_impure_inputs(
            identity(b"source", 7),
            [durable_hash(b"free-var")],
            Some(value_hash(b"value")),
            &source,
        )
        .expect("expression trace observes");

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
    assert_eq!(cache.len(), 2);
}

#[test]
fn eval_cache_expression_trace_adapter_skips_node_for_uncacheable_trace() {
    let source = TraceSource {
        trace: vec![
            read_file_trace(b"/tmp/version", b"1"),
            ImpureInputFingerprint::current_time(),
        ],
        complete: true,
    };
    let mut cache = EvalCache::new();

    let observation = cache
        .observe_expression_impure_inputs(
            identity(b"source", 7),
            [durable_hash(b"free-var")],
            Some(value_hash(b"value")),
            &source,
        )
        .expect("expression trace observes");

    assert_eq!(
        observation.trace().status(),
        ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert_eq!(observation.node(), None);
    assert_eq!(
        observation.cacheability(),
        ExpressionCacheability::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert!(cache.is_empty());
}

#[test]
fn eval_cache_expression_trace_adapter_uncacheable_trace_clears_prior_edges() {
    let first_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/first", b"same")],
        complete: true,
    };
    let second_source = TraceSource {
        trace: vec![
            read_file_trace(b"/tmp/second", b"same"),
            ImpureInputFingerprint::current_time(),
        ],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let identity = identity(b"source", 7);
    let first_observation = cache
        .observe_expression_impure_inputs(
            identity,
            [durable_hash(b"free-var")],
            Some(value_hash(b"value")),
            &first_source,
        )
        .expect("first expression trace observes");
    let node = first_observation
        .node()
        .expect("cacheable trace creates node");
    let first_dependency = first_observation.trace().leaves()[0].node();

    let second_observation = cache
        .observe_expression_impure_inputs(
            identity,
            [durable_hash(b"free-var")],
            Some(value_hash(b"value")),
            &second_source,
        )
        .expect("uncacheable expression trace observes");

    assert_eq!(
        second_observation.trace().status(),
        ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert_eq!(second_observation.node(), None);
    assert!(
        cache
            .graph()
            .node(node)
            .expect("expression node exists")
            .dependencies()
            .is_empty()
    );
    assert!(
        !cache
            .graph()
            .node(first_dependency)
            .expect("first dependency exists")
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
}

#[test]
fn eval_cache_expression_trace_adapter_marks_incomplete_trace_not_memoizable() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: false,
    };
    let mut cache = EvalCache::new();

    let observation = cache
        .observe_expression_impure_inputs(
            identity(b"source", 7),
            [durable_hash(b"free-var")],
            Some(value_hash(b"value")),
            &source,
        )
        .expect("expression trace observes");

    assert_eq!(observation.trace().status(), ImpureTraceStatus::Incomplete);
    assert_eq!(observation.node(), None);
    assert_eq!(
        observation.cacheability(),
        ExpressionCacheability::Incomplete
    );
    assert!(cache.is_empty());
}

#[test]
fn disabled_eval_cache_runtime_expression_trace_is_noop() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut runtime = EvalCacheRuntime::disabled();

    let observation = runtime
        .observe_expression_impure_inputs(
            identity(b"source", 7),
            [durable_hash(b"free-var")],
            Some(value_hash(b"value")),
            &source,
        )
        .expect("disabled expression observation succeeds");

    assert_eq!(observation, None);
    assert!(runtime.cache().is_none());
}

#[test]
fn enabled_eval_cache_runtime_expression_trace_delegates() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut runtime = EvalCacheRuntime::enabled();

    let observation = runtime
        .observe_expression_impure_inputs(
            identity(b"source", 7),
            [durable_hash(b"free-var")],
            Some(value_hash(b"value")),
            &source,
        )
        .expect("enabled expression observation succeeds")
        .expect("enabled runtime observes expression trace");

    assert_eq!(observation.trace().status(), ImpureTraceStatus::Cacheable);
    assert!(observation.node().is_some());
    assert_eq!(runtime.cache().expect("cache is enabled").len(), 2);
}
