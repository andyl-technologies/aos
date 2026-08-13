//! Impure trace demand graph tests.

use super::*;

#[test]
fn incomplete_impure_trace_does_not_mutate_graph() {
    let mut graph = DemandGraph::new();
    let existing = node_with_hash(&mut graph, 1, b"existing");
    let trace = [read_file_trace(b"/tmp/version", b"1")];

    let observation = graph
        .observe_impure_trace(&trace, false)
        .expect("trace observes");

    assert_eq!(observation.status(), ImpureTraceStatus::Incomplete);
    assert!(observation.leaves().is_empty());
    assert_eq!(graph.len(), 1);
    assert_eq!(
        graph.node(existing).expect("existing node").freshness(),
        NodeFreshness::Clean
    );
}

#[test]
fn uncacheable_impure_trace_does_not_mutate_graph_in_any_order() {
    let cacheable = read_file_trace(b"/tmp/version", b"1");
    let uncacheable = ImpureInputFingerprint::current_time();

    for trace in [
        vec![cacheable.clone(), uncacheable.clone()],
        vec![uncacheable, cacheable],
    ] {
        let mut graph = DemandGraph::new();
        let existing = node_with_hash(&mut graph, 1, b"existing");

        let observation = graph
            .observe_impure_trace(&trace, true)
            .expect("trace observes");

        assert_eq!(
            observation.status(),
            ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
        );
        assert!(observation.leaves().is_empty());
        assert_eq!(graph.len(), 1);
        assert_eq!(
            graph.node(existing).expect("existing node").freshness(),
            NodeFreshness::Clean
        );
    }
}

#[test]
fn cacheable_impure_trace_inserts_leaves() {
    let mut graph = DemandGraph::new();
    let trace = [
        read_file_trace(b"/tmp/one", b"same"),
        read_file_trace(b"/tmp/two", b"same"),
    ];

    let observation = graph
        .observe_impure_trace(&trace, true)
        .expect("trace observes");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    assert_eq!(observation.leaves().len(), 2);
    assert!(matches!(
        observation.leaves()[0],
        ImpureInputObservation::Inserted { .. }
    ));
    assert!(matches!(
        observation.leaves()[1],
        ImpureInputObservation::Inserted { .. }
    ));
    assert_ne!(
        observation.leaves()[0].node(),
        observation.leaves()[1].node()
    );
    assert_eq!(graph.len(), 2);
}

#[test]
fn unchanged_cacheable_impure_trace_cuts_off() {
    let mut graph = DemandGraph::new();
    let trace = [read_file_trace(b"/tmp/version", b"1")];
    let first = graph
        .observe_impure_trace(&trace, true)
        .expect("first trace observes");
    let leaf = first.leaves()[0].node();

    let second = graph
        .observe_impure_trace(&trace, true)
        .expect("second trace observes");

    assert_eq!(second.status(), ImpureTraceStatus::Cacheable);
    let [ImpureInputObservation::Reconsidered(reconsideration)] = second.leaves() else {
        panic!("same trace reconsiders its existing leaf");
    };
    assert_eq!(reconsideration.node(), leaf);
    assert_eq!(reconsideration.decision(), CutoffDecision::CutOff);
    assert!(reconsideration.dirtied_dependents().is_empty());
    assert_eq!(graph.len(), 1);
}

#[test]
fn changed_cacheable_impure_trace_dirties_dependents() {
    let mut graph = DemandGraph::new();
    let first = [read_file_trace(b"/tmp/version", b"1")];
    let input = graph
        .observe_impure_trace(&first, true)
        .expect("first trace observes")
        .leaves()[0]
        .node();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    graph
        .add_dependency(dependent, input)
        .expect("dependency records");

    let changed = [read_file_trace(b"/tmp/version", b"2")];
    let observation = graph
        .observe_impure_trace(&changed, true)
        .expect("changed trace observes");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    let [ImpureInputObservation::Reconsidered(reconsideration)] = observation.leaves() else {
        panic!("changed trace reconsiders its existing leaf");
    };
    assert_eq!(reconsideration.node(), input);
    assert_eq!(reconsideration.decision(), CutoffDecision::Propagate);
    assert_eq!(reconsideration.dirtied_dependents(), &[dependent]);
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn cacheable_impure_trace_for_node_records_input_edges() {
    let mut graph = DemandGraph::new();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    let trace = [
        read_file_trace(b"/tmp/one", b"same"),
        read_file_trace(b"/tmp/two", b"same"),
    ];

    let observation = graph
        .observe_impure_trace_for_node(dependent, &trace, true)
        .expect("trace observes and wires");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    assert_eq!(observation.leaves().len(), 2);
    for leaf in observation.leaves() {
        let dependency = leaf.node();
        assert!(
            graph
                .node(dependent)
                .expect("dependent exists")
                .dependencies()
                .contains(&dependency)
        );
        assert!(
            graph
                .node(dependency)
                .expect("dependency exists")
                .dependents()
                .contains(&dependent)
        );
    }
    assert_eq!(graph.len(), 3);
}

#[test]
fn cacheable_impure_trace_for_node_replaces_prior_input_edges() {
    let mut graph = DemandGraph::new();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    let first = [read_file_trace(b"/tmp/first", b"same")];
    let first_observation = graph
        .observe_impure_trace_for_node(dependent, &first, true)
        .expect("first trace observes and wires");
    let first_dependency = first_observation.leaves()[0].node();

    let second = [read_file_trace(b"/tmp/second", b"same")];
    let second_observation = graph
        .observe_impure_trace_for_node(dependent, &second, true)
        .expect("second trace replaces edges");
    let second_dependency = second_observation.leaves()[0].node();

    assert!(
        !graph
            .node(dependent)
            .expect("dependent exists")
            .dependencies()
            .contains(&first_dependency)
    );
    assert!(
        graph
            .node(dependent)
            .expect("dependent exists")
            .dependencies()
            .contains(&second_dependency)
    );
    assert!(
        !graph
            .node(first_dependency)
            .expect("first dependency exists")
            .dependents()
            .contains(&dependent)
    );
    assert!(
        graph
            .node(second_dependency)
            .expect("second dependency exists")
            .dependents()
            .contains(&dependent)
    );

    graph
        .observe_impure_trace(&[read_file_trace(b"/tmp/first", b"changed")], true)
        .expect("stale input reconsiders");
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Clean
    );

    graph
        .observe_impure_trace(&[read_file_trace(b"/tmp/second", b"changed")], true)
        .expect("current input reconsiders");
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn impure_trace_for_node_preserves_memo_read_edges() {
    let mut graph = DemandGraph::new();
    let memo_dependency = node_with_hash(&mut graph, 6, b"memo-dependency");
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    graph
        .add_dependency(dependent, memo_dependency)
        .expect("memo edge records");

    let first = [read_file_trace(b"/tmp/first", b"same")];
    let first_observation = graph
        .observe_impure_trace_for_node(dependent, &first, true)
        .expect("first trace observes and wires");
    let first_dependency = first_observation.leaves()[0].node();

    let second = [read_file_trace(b"/tmp/second", b"same")];
    let second_observation = graph
        .observe_impure_trace_for_node(dependent, &second, true)
        .expect("second trace replaces input edges");
    let second_dependency = second_observation.leaves()[0].node();

    let dependent_node = graph.node(dependent).expect("dependent exists");
    assert!(dependent_node.dependencies().contains(&memo_dependency));
    assert!(!dependent_node.dependencies().contains(&first_dependency));
    assert!(dependent_node.dependencies().contains(&second_dependency));
    assert!(
        dependent_node
            .dependencies_in_group(DemandDependencyGroup::MemoRead)
            .expect("memo group exists")
            .contains(&memo_dependency)
    );
    assert!(
        dependent_node
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .expect("input group exists")
            .contains(&second_dependency)
    );
    assert!(
        graph
            .node(memo_dependency)
            .expect("memo dependency exists")
            .dependents()
            .contains(&dependent)
    );

    graph
        .observe_impure_trace(&[read_file_trace(b"/tmp/first", b"changed")], true)
        .expect("stale input reconsiders");
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Clean
    );

    graph
        .reconsider_node(memo_dependency, value_hash(b"changed-memo"))
        .expect("memo dependency reconsiders");
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn uncacheable_impure_trace_for_node_clears_prior_input_edges() {
    let mut graph = DemandGraph::new();
    let memo_dependency = node_with_hash(&mut graph, 6, b"memo-dependency");
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    graph
        .add_dependency(dependent, memo_dependency)
        .expect("memo edge records");
    let first = [read_file_trace(b"/tmp/first", b"same")];
    let first_observation = graph
        .observe_impure_trace_for_node(dependent, &first, true)
        .expect("first trace observes and wires");
    let first_dependency = first_observation.leaves()[0].node();
    let consumer = node_with_hash(&mut graph, 8, b"consumer");
    graph
        .add_dependency(consumer, dependent)
        .expect("consumer memo edge records");
    let grandconsumer = node_with_hash(&mut graph, 9, b"grandconsumer");
    graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");

    let uncacheable = [
        read_file_trace(b"/tmp/second", b"same"),
        ImpureInputFingerprint::current_time(),
    ];
    let second_observation = graph
        .observe_impure_trace_for_node(dependent, &uncacheable, true)
        .expect("uncacheable trace clears edges");

    assert_eq!(
        second_observation.status(),
        ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
    );
    let dependent_node = graph.node(dependent).expect("dependent exists");
    assert_eq!(dependent_node.freshness(), NodeFreshness::Dirty);
    assert!(dependent_node.dependencies().contains(&memo_dependency));
    assert!(!dependent_node.dependencies().contains(&first_dependency));
    assert!(
        dependent_node
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .is_none()
    );
    assert!(
        !graph
            .node(first_dependency)
            .expect("first dependency exists")
            .dependents()
            .contains(&dependent)
    );
    assert!(
        graph
            .node(memo_dependency)
            .expect("memo dependency exists")
            .dependents()
            .contains(&dependent)
    );
    assert_eq!(
        graph.node(consumer).expect("consumer exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph
            .node(grandconsumer)
            .expect("grandconsumer exists")
            .freshness(),
        NodeFreshness::Dirty
    );

    graph
        .observe_impure_trace(&[read_file_trace(b"/tmp/first", b"changed")], true)
        .expect("stale input reconsiders");
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn incomplete_impure_trace_for_node_clears_prior_input_edges() {
    let mut graph = DemandGraph::new();
    let memo_dependency = node_with_hash(&mut graph, 6, b"memo-dependency");
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    graph
        .add_dependency(dependent, memo_dependency)
        .expect("memo edge records");
    let first = [read_file_trace(b"/tmp/first", b"same")];
    let first_observation = graph
        .observe_impure_trace_for_node(dependent, &first, true)
        .expect("first trace observes and wires");
    let first_dependency = first_observation.leaves()[0].node();
    let consumer = node_with_hash(&mut graph, 8, b"consumer");
    graph
        .add_dependency(consumer, dependent)
        .expect("consumer memo edge records");
    let grandconsumer = node_with_hash(&mut graph, 9, b"grandconsumer");
    graph
        .add_dependency(grandconsumer, consumer)
        .expect("grandconsumer memo edge records");

    let incomplete = [read_file_trace(b"/tmp/second", b"same")];
    let second_observation = graph
        .observe_impure_trace_for_node(dependent, &incomplete, false)
        .expect("incomplete trace clears edges");

    assert_eq!(second_observation.status(), ImpureTraceStatus::Incomplete);
    assert!(second_observation.leaves().is_empty());
    let dependent_node = graph.node(dependent).expect("dependent exists");
    assert_eq!(dependent_node.freshness(), NodeFreshness::Dirty);
    assert!(dependent_node.dependencies().contains(&memo_dependency));
    assert!(!dependent_node.dependencies().contains(&first_dependency));
    assert!(
        dependent_node
            .dependencies_in_group(DemandDependencyGroup::ImpureInput)
            .is_none()
    );
    assert!(
        !graph
            .node(first_dependency)
            .expect("first dependency exists")
            .dependents()
            .contains(&dependent)
    );
    assert!(
        graph
            .node(memo_dependency)
            .expect("memo dependency exists")
            .dependents()
            .contains(&dependent)
    );
    assert_eq!(
        graph.node(consumer).expect("consumer exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph
            .node(grandconsumer)
            .expect("grandconsumer exists")
            .freshness(),
        NodeFreshness::Dirty
    );

    graph
        .observe_impure_trace(&[read_file_trace(b"/tmp/first", b"changed")], true)
        .expect("stale input reconsiders");
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn changed_wired_impure_input_dirties_dependent_node() {
    let mut graph = DemandGraph::new();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    let first = [read_file_trace(b"/tmp/version", b"1")];
    graph
        .observe_impure_trace_for_node(dependent, &first, true)
        .expect("trace observes and wires");

    let changed = [read_file_trace(b"/tmp/version", b"2")];
    let observation = graph
        .observe_impure_trace(&changed, true)
        .expect("changed trace observes");

    assert_eq!(observation.status(), ImpureTraceStatus::Cacheable);
    let [ImpureInputObservation::Reconsidered(reconsideration)] = observation.leaves() else {
        panic!("changed trace reconsiders its existing leaf");
    };
    assert_eq!(reconsideration.decision(), CutoffDecision::Propagate);
    assert_eq!(reconsideration.dirtied_dependents(), &[dependent]);
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn incomplete_impure_trace_for_node_does_not_add_edges() {
    let mut graph = DemandGraph::new();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    let trace = [read_file_trace(b"/tmp/version", b"1")];

    let observation = graph
        .observe_impure_trace_for_node(dependent, &trace, false)
        .expect("trace observes");

    assert_eq!(observation.status(), ImpureTraceStatus::Incomplete);
    assert!(observation.leaves().is_empty());
    assert_eq!(graph.len(), 1);
    assert!(
        graph
            .node(dependent)
            .expect("dependent exists")
            .dependencies()
            .is_empty()
    );
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn uncacheable_impure_trace_for_node_does_not_add_edges() {
    let mut graph = DemandGraph::new();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    let trace = [
        read_file_trace(b"/tmp/version", b"1"),
        ImpureInputFingerprint::current_time(),
    ];

    let observation = graph
        .observe_impure_trace_for_node(dependent, &trace, true)
        .expect("trace observes");

    assert_eq!(
        observation.status(),
        ImpureTraceStatus::Uncacheable(UncacheableInput::CurrentTime)
    );
    assert!(observation.leaves().is_empty());
    assert_eq!(graph.len(), 1);
    assert!(
        graph
            .node(dependent)
            .expect("dependent exists")
            .dependencies()
            .is_empty()
    );
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn impure_trace_for_unknown_node_errors_before_leaf_mutation() {
    let mut graph = DemandGraph::new();
    let unknown = DemandNodeId::new(99);
    let trace = [read_file_trace(b"/tmp/version", b"1")];

    let error = graph
        .observe_impure_trace_for_node(unknown, &trace, true)
        .expect_err("unknown dependent is rejected");

    assert!(matches!(error, DemandGraphError::UnknownNode { id } if id == unknown));
    assert!(graph.is_empty());
}

#[test]
fn impure_trace_for_node_rejects_self_dependency_before_edge_mutation() {
    let mut graph = DemandGraph::new();
    let trace = [read_file_trace(b"/tmp/version", b"1")];
    let input = graph
        .observe_impure_trace(&trace, true)
        .expect("input leaf observes")
        .leaves()[0]
        .node();

    let error = graph
        .observe_impure_trace_for_node(input, &trace, true)
        .expect_err("self dependency is rejected");

    assert!(matches!(
        error,
        DemandGraphError::SelfDependency { id } if id == input
    ));
    assert!(
        graph
            .node(input)
            .expect("input exists")
            .dependencies()
            .is_empty()
    );
    assert!(
        graph
            .node(input)
            .expect("input exists")
            .dependents()
            .is_empty()
    );
}
