//! Eval cache trace observation, dirty frontier, and recompute tests.

use super::*;

fn node_with_hash(graph: &mut DemandGraph, node: u32, label: &'static [u8]) -> DemandNodeId {
    graph
        .get_or_insert_node(key(node, label), Some(value_hash(label)))
        .expect("node inserts")
}

#[test]
fn eval_cache_observes_cacheable_trace_source() {
    let source = TraceSource {
        trace: vec![
            read_file_trace(b"/tmp/one", b"same"),
            read_file_trace(b"/tmp/two", b"same"),
        ],
        complete: true,
    };
    let mut cache = EvalCache::new();

    let observation = cache
        .observe_impure_inputs(&source)
        .expect("trace observes");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    assert_eq!(observation.leaves().len(), 2);
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.graph().len(), 2);
    assert_eq!(cache.into_graph().len(), 2);
}

#[test]
fn disabled_eval_cache_runtime_observation_is_noop() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut runtime = EvalCacheRuntime::disabled();

    let observation = runtime
        .observe_impure_inputs(&source)
        .expect("disabled observation succeeds");

    assert_eq!(observation, None);
    assert!(!runtime.is_enabled());
    assert!(runtime.cache().is_none());
}

#[test]
fn disabled_eval_cache_runtime_does_not_classify_uncacheable_traces() {
    let source = TraceSource {
        trace: vec![ImpureInputFingerprint::current_time()],
        complete: true,
    };
    let mut runtime = EvalCacheRuntime::disabled();

    let observation = runtime
        .observe_impure_inputs(&source)
        .expect("disabled observation succeeds");

    assert_eq!(observation, None);
    assert!(runtime.cache().is_none());
}

#[test]
fn enabled_eval_cache_runtime_delegates_trace_observation() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut runtime = EvalCacheRuntime::enabled();

    let observation = runtime
        .observe_impure_inputs(&source)
        .expect("enabled observation succeeds")
        .expect("enabled runtime observes traces");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    assert_eq!(runtime.cache().expect("cache is enabled").len(), 1);
}

#[test]
fn enabled_eval_cache_runtime_delegates_trace_edges() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut runtime = EvalCacheRuntime::Enabled(EvalCache::from_graph(DemandGraph::new()));
    let dependent = runtime
        .cache_mut()
        .expect("cache is enabled")
        .get_or_insert_expression_node(
            identity(b"source", 7),
            [value_hash(b"free-var")],
            Some(value_hash(b"dependent")),
        )
        .expect("dependent inserts");

    let observation = runtime
        .observe_impure_inputs_for_node(dependent, &source)
        .expect("enabled observation succeeds")
        .expect("enabled runtime observes traces");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    let dependency = observation.leaves()[0].node();
    assert!(
        runtime
            .cache()
            .expect("cache is enabled")
            .graph()
            .node(dependent)
            .expect("dependent exists")
            .dependencies()
            .contains(&dependency)
    );
}

#[test]
fn eval_cache_observes_trace_source_for_node_edges() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut graph = DemandGraph::new();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    let mut cache = EvalCache::from_graph(graph);

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
    assert!(
        cache
            .graph()
            .node(dependency)
            .expect("dependency exists")
            .dependents()
            .contains(&dependent)
    );
}

#[test]
fn eval_cache_node_uncacheable_trace_invalidates_side_payload_and_memo_dependents() {
    let source = TraceSource {
        trace: vec![ImpureInputFingerprint::current_time()],
        complete: true,
    };
    let mut cache = EvalCache::new();
    let expression_identity = identity(b"source", 7);
    let observed = cache
        .observe_inline_expression_result(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("inline payload observes");
    let node = observed.node();
    let memo_dependency = cache
        .graph
        .get_or_insert_node(key(8, b"memo"), Some(value_hash(b"memo")))
        .expect("memo dependency inserts");
    cache
        .graph
        .add_dependency(node, memo_dependency)
        .expect("memo edge records");
    let consumer_identity = identity(b"consumer", 9);
    let consumer = cache
        .observe_inline_expression_result(
            consumer_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(4),
        )
        .expect("consumer payload observes")
        .node();
    cache
        .graph
        .add_dependency(consumer, node)
        .expect("consumer memo edge records");
    let grandconsumer_identity = identity(b"grandconsumer", 10);
    let grandconsumer = cache
        .observe_inline_expression_result(
            grandconsumer_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(5),
        )
        .expect("grandconsumer payload observes")
        .node();
    cache
        .graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");
    assert!(cache.inline_values.contains_key(&node));
    assert!(cache.inline_values.contains_key(&consumer));
    assert!(cache.inline_values.contains_key(&grandconsumer));

    let observation = cache
        .observe_impure_inputs_for_node(node, &source)
        .expect("uncacheable node trace observes");

    assert_eq!(
        observation.status(),
        ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert!(!cache.inline_values.contains_key(&node));
    assert!(!cache.inline_values.contains_key(&consumer));
    assert!(!cache.inline_values.contains_key(&grandconsumer));
    let node_state = cache.graph().node(node).expect("node exists");
    assert_eq!(node_state.freshness(), NodeFreshness::Dirty);
    assert!(node_state.dependencies().contains(&memo_dependency));
    assert!(
        node_state
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .is_none()
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
fn replace_memo_read_dependencies_with_dirty_supplier_invalidates_inline_payload() {
    let mut cache = EvalCache::new();
    let supplier = cache
        .get_or_insert_expression_node(
            identity(b"supplier", 7),
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"supplier")),
        )
        .expect("supplier inserts");
    let parent_identity = identity(b"parent", 8);
    let parent = cache
        .observe_inline_expression_result(
            parent_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("parent payload observes")
        .node();
    cache
        .test_mark_dirty_node(supplier)
        .expect("supplier dirties");
    assert!(cache.inline_values.contains_key(&parent));

    cache
        .replace_memo_read_dependencies(parent, [supplier])
        .expect("memo-read dependencies replace");

    assert!(!cache.inline_values.contains_key(&parent));
    let parent_node = cache.graph().node(parent).expect("parent exists");
    assert_eq!(parent_node.freshness(), NodeFreshness::Dirty);
    assert!(
        parent_node
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .expect("parent memo-read edges exist")
            .contains(&supplier)
    );
    assert_eq!(
        cache
            .graph()
            .node(supplier)
            .expect("supplier exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert!(
        cache
            .lookup_inline_expression_result(parent_identity, std::iter::empty::<ValueHash>())
            .expect("parent lookup succeeds")
            .is_none()
    );
}

#[test]
fn eval_cache_changed_input_dirties_dependent_node() {
    let first = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let changed = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"2")],
        complete: true,
    };
    let mut graph = DemandGraph::new();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    let mut cache = EvalCache::from_graph(graph);
    cache
        .observe_impure_inputs_for_node(dependent, &first)
        .expect("trace observes and wires");

    let observation = cache
        .observe_impure_inputs(&changed)
        .expect("changed trace observes");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    assert_eq!(
        cache
            .graph()
            .node(dependent)
            .expect("dependent exists")
            .freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn eval_cache_exposes_dirty_frontier() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b-stable");
    let c = node_with_hash(&mut graph, 3, b"c-stale");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(c).expect("c dirties");
    let cache = EvalCache::from_graph(graph);

    let frontier = cache.dirty_frontier();

    assert_eq!(frontier.ready_nodes(), &[a]);
    let [blocked] = frontier.blocked_nodes() else {
        panic!("c is blocked by dirty upstream a");
    };
    assert_eq!(blocked.node(), c);
    assert_eq!(blocked.blockers(), &[a]);
}

#[test]
fn eval_cache_delegates_ready_dirty_recompute_loop() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b-old");
    let c = node_with_hash(&mut graph, 3, b"c-stable");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");
    graph.mark_dirty(a).expect("a dirties");
    let mut cache = EvalCache::from_graph(graph);

    let result = cache
        .recompute_ready_dirty_nodes::<DemandGraphError, _>(|node| {
            if node == a {
                return Ok(value_hash(b"a-new"));
            }
            if node == b {
                return Ok(value_hash(b"b-new"));
            }
            if node == c {
                return Ok(value_hash(b"c-stable"));
            }
            panic!("unexpected recomputation for {node:?}");
        })
        .expect("runtime cache recomputes");

    let reconsidered: Vec<_> = result
        .reconsiderations()
        .iter()
        .map(Reconsideration::node)
        .collect();
    assert_eq!(reconsidered, vec![a, b, c]);
    assert!(result.remaining_frontier().is_empty());
    assert_eq!(
        cache.graph().dirty_nodes().collect::<Vec<_>>(),
        Vec::<DemandNodeId>::new()
    );
}

#[test]
fn eval_cache_runtime_dirty_frontier_is_disabled_noop() {
    let runtime = EvalCacheRuntime::disabled();

    assert_eq!(runtime.dirty_frontier(), None);
}

#[test]
fn eval_cache_runtime_ready_dirty_recompute_is_disabled_noop() {
    let mut runtime = EvalCacheRuntime::disabled();

    let result = runtime
        .recompute_ready_dirty_nodes::<DemandGraphError, _>(|node| {
            panic!("disabled runtime should not recompute {node:?}");
        })
        .expect("disabled recompute succeeds");

    assert_eq!(result, None);
    assert!(runtime.cache().is_none());
}

#[test]
fn enabled_eval_cache_runtime_delegates_dirty_frontier() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b-stable");
    let c = node_with_hash(&mut graph, 3, b"c-stale");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(c).expect("c dirties");
    let runtime = EvalCacheRuntime::Enabled(EvalCache::from_graph(graph));

    let frontier = runtime
        .dirty_frontier()
        .expect("enabled runtime returns a frontier");

    assert_eq!(frontier.ready_nodes(), &[a]);
    let [blocked] = frontier.blocked_nodes() else {
        panic!("c is blocked by dirty upstream a");
    };
    assert_eq!(blocked.node(), c);
    assert_eq!(blocked.blockers(), &[a]);
}

#[test]
fn enabled_eval_cache_runtime_delegates_ready_dirty_recompute_loop() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b-old");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.mark_dirty(a).expect("a dirties");
    let mut runtime = EvalCacheRuntime::Enabled(EvalCache::from_graph(graph));

    let result = runtime
        .recompute_ready_dirty_nodes::<DemandGraphError, _>(|node| {
            if node == a {
                return Ok(value_hash(b"a-new"));
            }
            if node == b {
                return Ok(value_hash(b"b-stable"));
            }
            panic!("unexpected recomputation for {node:?}");
        })
        .expect("enabled runtime recomputes")
        .expect("enabled runtime returns loop result");

    let reconsidered: Vec<_> = result
        .reconsiderations()
        .iter()
        .map(Reconsideration::node)
        .collect();
    assert_eq!(reconsidered, vec![a, b]);
    assert!(result.remaining_frontier().is_empty());
    assert_eq!(
        runtime
            .cache()
            .expect("cache is enabled")
            .graph()
            .dirty_nodes()
            .collect::<Vec<_>>(),
        Vec::<DemandNodeId>::new()
    );
}

#[test]
fn enabled_eval_cache_runtime_keeps_prior_progress_on_later_recompute_error() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b");
    let c = node_with_hash(&mut graph, 3, b"c");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(c).expect("c dirties");
    let mut runtime = EvalCacheRuntime::Enabled(EvalCache::from_graph(graph));

    let error = runtime
        .recompute_ready_dirty_nodes::<RecomputeTestError, _>(|node| {
            if node == a {
                return Ok(value_hash(b"a-new"));
            }
            Err(RecomputeTestError::Rejected(node))
        })
        .expect_err("later recompute error stops runtime recompute");

    assert_eq!(error, RecomputeTestError::Rejected(c));
    assert_eq!(
        runtime
            .cache()
            .expect("cache is enabled")
            .graph()
            .dirty_nodes()
            .collect::<Vec<_>>(),
        vec![b, c]
    );
}
