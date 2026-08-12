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
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
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
fn eval_cache_expression_trace_adapter_preserves_memo_read_edges() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut graph = DemandGraph::new();
    let expression_identity = identity(b"source", 7);
    let free_var = value_hash(b"free-var");
    let node = graph
        .get_or_insert_expression_node(expression_identity, [free_var], Some(value_hash(b"value")))
        .expect("expression node inserts");
    let memo_dependency = graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"memo", 1), [value_hash(b"memo")])
                .expect("memo key builds"),
            Some(value_hash(b"memo")),
        )
        .expect("memo dependency inserts");
    graph
        .add_dependency(node, memo_dependency)
        .expect("memo edge records");
    let mut cache = EvalCache::from_graph(graph);

    let observation = cache
        .observe_expression_impure_inputs(
            expression_identity,
            [free_var],
            Some(value_hash(b"value")),
            &source,
        )
        .expect("expression trace observes");

    assert_eq!(observation.node(), Some(node));
    let input_dependency = observation.trace().leaves()[0].node();
    let node = cache.graph().node(node).expect("expression node exists");
    assert!(node.dependencies().contains(&memo_dependency));
    assert!(node.dependencies().contains(&input_dependency));
    assert!(
        node.dependencies_in_group(DemandDependencyGroup::MemoRead)
            .expect("memo group exists")
            .contains(&memo_dependency)
    );
    assert!(
        node.dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .expect("input group exists")
            .contains(&input_dependency)
    );
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
            [value_hash(b"free-var")],
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
fn eval_cache_uncacheable_trace_dirties_existing_node_and_memo_read_dependents() {
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
    let mut graph = DemandGraph::new();
    let expression_identity = identity(b"source", 7);
    let free_var = value_hash(b"free-var");
    let node = graph
        .get_or_insert_expression_node(expression_identity, [free_var], Some(value_hash(b"value")))
        .expect("expression node inserts");
    let memo_dependency = graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"memo", 1), [value_hash(b"memo")])
                .expect("memo key builds"),
            Some(value_hash(b"memo")),
        )
        .expect("memo dependency inserts");
    graph
        .add_dependency(node, memo_dependency)
        .expect("memo edge records");
    let consumer = graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"consumer", 1), [value_hash(b"consumer")])
                .expect("consumer key builds"),
            Some(value_hash(b"consumer")),
        )
        .expect("consumer inserts");
    graph
        .add_dependency(consumer, node)
        .expect("consumer memo edge records");
    let grandconsumer = graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(
                identity(b"grandconsumer", 2),
                [value_hash(b"grandconsumer")],
            )
            .expect("grandconsumer key builds"),
            Some(value_hash(b"grandconsumer")),
        )
        .expect("grandconsumer inserts");
    graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");
    let mut cache = EvalCache::from_graph(graph);
    let first_observation = cache
        .observe_expression_impure_inputs(
            expression_identity,
            [free_var],
            Some(value_hash(b"value")),
            &first_source,
        )
        .expect("first expression trace observes");
    assert_eq!(first_observation.node(), Some(node));
    let first_dependency = first_observation.trace().leaves()[0].node();

    let second_observation = cache
        .observe_expression_impure_inputs(
            expression_identity,
            [free_var],
            Some(value_hash(b"value")),
            &second_source,
        )
        .expect("uncacheable expression trace observes");

    assert_eq!(
        second_observation.trace().status(),
        ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert_eq!(second_observation.node(), None);
    let expression_node = cache.graph().node(node).expect("expression node exists");
    assert_eq!(expression_node.freshness(), NodeFreshness::Dirty);
    assert!(expression_node.dependencies().contains(&memo_dependency));
    assert!(!expression_node.dependencies().contains(&first_dependency));
    assert!(
        expression_node
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .is_none()
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
            .node(memo_dependency)
            .expect("memo dependency exists")
            .dependents()
            .contains(&node)
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
        NodeFreshness::Dirty
    );
}

#[test]
fn eval_cache_incomplete_trace_dirties_existing_node_and_preserves_memo_edges() {
    let first_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/first", b"same")],
        complete: true,
    };
    let second_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/second", b"same")],
        complete: false,
    };
    let mut graph = DemandGraph::new();
    let expression_identity = identity(b"source", 7);
    let free_var = value_hash(b"free-var");
    let node = graph
        .get_or_insert_expression_node(expression_identity, [free_var], Some(value_hash(b"value")))
        .expect("expression node inserts");
    let memo_dependency = graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"memo", 1), [value_hash(b"memo")])
                .expect("memo key builds"),
            Some(value_hash(b"memo")),
        )
        .expect("memo dependency inserts");
    graph
        .add_dependency(node, memo_dependency)
        .expect("memo edge records");
    let consumer = graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"consumer", 1), [value_hash(b"consumer")])
                .expect("consumer key builds"),
            Some(value_hash(b"consumer")),
        )
        .expect("consumer inserts");
    graph
        .add_dependency(consumer, node)
        .expect("consumer memo edge records");
    let grandconsumer = graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(
                identity(b"grandconsumer", 2),
                [value_hash(b"grandconsumer")],
            )
            .expect("grandconsumer key builds"),
            Some(value_hash(b"grandconsumer")),
        )
        .expect("grandconsumer inserts");
    graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");
    let mut cache = EvalCache::from_graph(graph);
    let first_observation = cache
        .observe_expression_impure_inputs(
            expression_identity,
            [free_var],
            Some(value_hash(b"value")),
            &first_source,
        )
        .expect("first expression trace observes");
    assert_eq!(first_observation.node(), Some(node));
    let first_dependency = first_observation.trace().leaves()[0].node();

    let second_observation = cache
        .observe_expression_impure_inputs(
            expression_identity,
            [free_var],
            Some(value_hash(b"value")),
            &second_source,
        )
        .expect("incomplete expression trace observes");

    assert_eq!(
        second_observation.trace().status(),
        ImpureTraceStatus::Incomplete
    );
    assert_eq!(second_observation.node(), None);
    let expression_node = cache.graph().node(node).expect("expression node exists");
    assert_eq!(expression_node.freshness(), NodeFreshness::Dirty);
    assert!(expression_node.dependencies().contains(&memo_dependency));
    assert!(!expression_node.dependencies().contains(&first_dependency));
    assert!(
        expression_node
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .is_none()
    );
    assert!(
        cache
            .graph()
            .node(memo_dependency)
            .expect("memo dependency exists")
            .dependents()
            .contains(&node)
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
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
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
            [value_hash(b"free-var")],
            Some(value_hash(b"value")),
            &source,
        )
        .expect("enabled expression observation succeeds")
        .expect("enabled runtime observes expression trace");

    assert_eq!(observation.trace().status(), ImpureTraceStatus::Cacheable);
    assert!(observation.node().is_some());
    assert_eq!(runtime.cache().expect("cache is enabled").len(), 2);
}
