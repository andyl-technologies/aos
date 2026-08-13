//! Split-out tests (part_1). See parent module.

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
            std::iter::empty::<ValueHash>(),
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
        .lookup_inline_expression_result(identity, std::iter::empty::<ValueHash>())
        .expect("lookup succeeds");
    assert!(
        value.is_none(),
        "trace-backed payloads require input revalidation before reuse"
    );
    assert_eq!(cache.len(), 2);
}

#[test]
fn eval_cache_inline_trace_payload_preserves_memo_read_edges() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let mut graph = DemandGraph::new();
    let expression_identity = identity(b"source", 7);
    let node = graph
        .get_or_insert_expression_node(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"value")),
        )
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
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");

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
fn eval_cache_inline_trace_payload_uncacheable_trace_preserves_memo_read_edges() {
    let first_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let second_source = TraceSource {
        trace: vec![ImpureInputFingerprint::current_time()],
        complete: true,
    };
    let mut graph = DemandGraph::new();
    let expression_identity = identity(b"source", 7);
    let node = graph
        .get_or_insert_expression_node(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"value")),
        )
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
    let first_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &first_source,
        )
        .expect("first inline result and trace observe");
    assert_eq!(first_observation.node(), Some(node));
    let input_dependency = first_observation.trace().leaves()[0].node();
    let consumer = cache
        .graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"consumer", 1), [value_hash(b"consumer")])
                .expect("consumer key builds"),
            Some(value_hash(b"consumer")),
        )
        .expect("consumer inserts");
    cache
        .graph
        .add_dependency(consumer, node)
        .expect("consumer memo edge records");
    let grandconsumer = cache
        .graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(
                identity(b"grandconsumer", 2),
                [value_hash(b"grandconsumer")],
            )
            .expect("grandconsumer key builds"),
            Some(value_hash(b"grandconsumer")),
        )
        .expect("grandconsumer inserts");
    cache
        .graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");

    let second_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(4),
            &second_source,
        )
        .expect("uncacheable trace observes");

    assert_eq!(
        second_observation.cacheability(),
        ExpressionCacheability::Uncacheable(UncacheableInput::CurrentTime)
    );
    let node = cache.graph().node(node).expect("expression node exists");
    assert_eq!(node.freshness(), NodeFreshness::Dirty);
    assert!(node.dependencies().contains(&memo_dependency));
    assert!(!node.dependencies().contains(&input_dependency));
    assert!(
        node.dependencies_in_group(DemandDependencyGroup::ImpureInput)
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
}

#[test]
fn eval_cache_inline_trace_payload_incomplete_trace_preserves_memo_read_edges() {
    let first_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: true,
    };
    let second_source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"1")],
        complete: false,
    };
    let mut graph = DemandGraph::new();
    let expression_identity = identity(b"source", 7);
    let node = graph
        .get_or_insert_expression_node(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"value")),
        )
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
    let first_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &first_source,
        )
        .expect("first inline result and trace observe");
    assert_eq!(first_observation.node(), Some(node));
    let input_dependency = first_observation.trace().leaves()[0].node();
    let consumer = cache
        .graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"consumer", 1), [value_hash(b"consumer")])
                .expect("consumer key builds"),
            Some(value_hash(b"consumer")),
        )
        .expect("consumer inserts");
    cache
        .graph
        .add_dependency(consumer, node)
        .expect("consumer memo edge records");
    let grandconsumer = cache
        .graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(
                identity(b"grandconsumer", 2),
                [value_hash(b"grandconsumer")],
            )
            .expect("grandconsumer key builds"),
            Some(value_hash(b"grandconsumer")),
        )
        .expect("grandconsumer inserts");
    cache
        .graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");

    let second_observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(4),
            &second_source,
        )
        .expect("incomplete trace observes");

    assert_eq!(
        second_observation.cacheability(),
        ExpressionCacheability::Incomplete
    );
    let node = cache.graph().node(node).expect("expression node exists");
    assert_eq!(node.freshness(), NodeFreshness::Dirty);
    assert!(node.dependencies().contains(&memo_dependency));
    assert!(!node.dependencies().contains(&input_dependency));
    assert!(
        node.dependencies_in_group(DemandDependencyGroup::ImpureInput)
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
            std::iter::empty::<ValueHash>(),
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
            std::iter::empty::<ValueHash>(),
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
            std::iter::empty::<ValueHash>(),
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
            std::iter::empty::<ValueHash>(),
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
fn dirty_trace_backed_inline_payload_revalidates_same_inputs_and_cuts_off() {
    let fingerprint = read_file_trace(b"/tmp/version", b"same");
    let source = TraceSource {
        trace: vec![fingerprint.clone()],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(vec![fingerprint]);
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
    cache.test_mark_dirty_node(node).expect("node marks dirty");

    let hit = cache
        .lookup_inline_expression_payload_hit_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("dirty lookup revalidates")
        .expect("unchanged dirty payload hits");

    assert_eq!(hit.node(), node);
    assert_eq!(
        hit.reconsideration()
            .expect("dirty hit reports reconsideration")
            .decision(),
        CutoffDecision::CutOff
    );
    assert_eq!(
        hit.into_value()
            .immediate_value()
            .expect("hit payload is immediate")
            .as_int(),
        Ok(3)
    );
    assert_eq!(revalidator.calls(), 1);
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(cache.inline_payload_record_count(), 1);
}

#[test]
fn dirty_trace_backed_inline_payload_changed_input_stays_miss() {
    let source = TraceSource {
        trace: vec![read_file_trace(b"/tmp/version", b"same")],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(vec![read_file_trace(b"/tmp/version", b"new")]);
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
    cache.test_mark_dirty_node(node).expect("node marks dirty");

    let hit = cache
        .lookup_inline_expression_payload_hit_with_impure_inputs(
            identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("dirty lookup revalidates");

    assert!(hit.is_none());
    assert_eq!(revalidator.calls(), 1);
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(cache.inline_payload_record_count(), 0);
}

#[test]
fn dirty_trace_backed_inline_payload_with_dirty_memo_supplier_stays_miss() {
    let fingerprint = read_file_trace(b"/tmp/version", b"same");
    let source = TraceSource {
        trace: vec![fingerprint.clone()],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(vec![fingerprint]);
    let mut cache = EvalCache::new();
    let expression_identity = identity(b"source", 7);
    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let node = observation.node().expect("cacheable trace creates node");
    let supplier = cache
        .graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(identity(b"supplier", 1), [value_hash(b"supplier")])
                .expect("supplier key builds"),
            Some(value_hash(b"supplier")),
        )
        .expect("supplier inserts");
    cache
        .graph
        .add_dependency(node, supplier)
        .expect("memo-read edge records");
    cache
        .test_mark_dirty_node(supplier)
        .expect("supplier marks dirty");
    cache.test_mark_dirty_node(node).expect("node marks dirty");

    let hit = cache
        .lookup_inline_expression_payload_hit_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("dirty lookup rejects dirty memo supplier");

    assert!(hit.is_none());
    assert_eq!(revalidator.calls(), 0);
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(cache.inline_payload_record_count(), 0);
}

#[test]
fn dirty_trace_backed_inline_payload_with_clean_changed_memo_supplier_stays_miss() {
    let fingerprint = read_file_trace(b"/tmp/version", b"same");
    let source = TraceSource {
        trace: vec![fingerprint.clone()],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(vec![fingerprint]);
    let mut cache = EvalCache::new();
    let expression_identity = identity(b"trace-parent", 7);
    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(10),
            &source,
        )
        .expect("trace-backed result observes");
    let node = observation.node().expect("cacheable trace creates node");
    let supplier_observation = cache
        .observe_inline_expression_result(
            identity(b"trace-child", 1),
            std::iter::empty::<ValueHash>(),
            Value::int(3),
        )
        .expect("supplier payload observes");
    cache
        .record_memo_read_dependency(node, supplier_observation.node())
        .expect("memo-read edge records");

    let supplier_change = cache
        .graph
        .reconsider_node(
            supplier_observation.node(),
            ValueHash::from_inline_value(Value::int(4)).expect("inline value hashes"),
        )
        .expect("supplier recomputation records changed hash");
    assert_eq!(supplier_change.decision(), CutoffDecision::Propagate);
    assert_eq!(supplier_change.dirtied_dependents(), &[node]);
    assert_eq!(
        cache
            .graph()
            .node(supplier_observation.node())
            .expect("supplier node exists")
            .freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );

    let hit = cache
        .lookup_inline_expression_payload_hit_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("dirty lookup succeeds");

    assert!(hit.is_none());
    assert_eq!(revalidator.calls(), 1);
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(cache.inline_payload_record_count(), 2);
}

#[test]
fn clean_trace_backed_inline_payload_with_dirty_memo_supplier_misses_and_purges_record() {
    let fingerprint = read_file_trace(b"/tmp/version", b"same");
    let source = TraceSource {
        trace: vec![fingerprint.clone()],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(vec![fingerprint]);
    let mut cache = EvalCache::new();
    let expression_identity = identity(b"trace-dependent", 7);
    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let node = observation.node().expect("cacheable trace creates node");
    let supplier = cache
        .graph
        .get_or_insert_node(
            DemandCacheKey::for_free_vars(
                identity(b"trace-supplier", 1),
                [value_hash(b"trace-supplier")],
            )
            .expect("supplier key builds"),
            Some(value_hash(b"trace-supplier")),
        )
        .expect("supplier inserts");
    cache
        .record_memo_read_dependency(node, supplier)
        .expect("memo-read edge records");
    cache
        .test_mark_dirty_node(supplier)
        .expect("supplier marks dirty");
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Clean
    );

    let hit = cache
        .lookup_inline_expression_payload_hit_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("lookup rejects dirty memo supplier chain");

    assert!(hit.is_none());
    assert_eq!(revalidator.calls(), 0);
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(cache.inline_payload_record_count(), 0);
}

#[test]
fn clean_trace_payload_with_transitively_dirty_memo_supplier_misses_and_purges_record() {
    let fingerprint = read_file_trace(b"/tmp/version", b"same");
    let source = TraceSource {
        trace: vec![fingerprint.clone()],
        complete: true,
    };
    let mut revalidator = StaticRevalidator::new(vec![fingerprint]);
    let mut cache = EvalCache::new();
    let expression_identity = identity(b"trace-transitive-dependent", 7);
    let observation = cache
        .observe_inline_expression_result_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            Value::int(3),
            &source,
        )
        .expect("inline result and trace observe");
    let node = observation.node().expect("cacheable trace creates node");
    let root = cache
        .get_or_insert_expression_node(
            identity(b"trace-dirty-root", 1),
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"trace-dirty-root")),
        )
        .expect("root inserts");
    let supplier = cache
        .get_or_insert_expression_node(
            identity(b"trace-clean-supplier", 2),
            std::iter::empty::<ValueHash>(),
            Some(value_hash(b"trace-clean-supplier")),
        )
        .expect("supplier inserts");
    cache
        .record_memo_read_dependency(supplier, root)
        .expect("supplier memo-read edge records");
    cache
        .record_memo_read_dependency(node, supplier)
        .expect("dependent memo-read edge records");
    cache.test_mark_dirty_node(root).expect("root marks dirty");
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(
        cache
            .graph()
            .node(supplier)
            .expect("supplier node exists")
            .freshness(),
        NodeFreshness::Clean
    );

    let hit = cache
        .lookup_inline_expression_payload_hit_with_impure_inputs(
            expression_identity,
            std::iter::empty::<ValueHash>(),
            &mut revalidator,
        )
        .expect("lookup rejects dirty memo supplier chain");

    assert!(hit.is_none());
    assert_eq!(revalidator.calls(), 0);
    assert_eq!(
        cache.graph().node(node).expect("node exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(cache.inline_payload_record_count(), 0);
}
