//! Demand graph key and edge tests.

use super::*;

#[test]
fn node_keys_are_interned() {
    let mut graph = DemandGraph::new();
    let cache_key = key(1, b"same");
    let first = graph
        .get_or_insert_node(cache_key, Some(value_hash(b"first")))
        .expect("first node inserts");
    let second = graph
        .get_or_insert_node(cache_key, Some(value_hash(b"second")))
        .expect("existing node returns");

    assert_eq!(first, second);
    assert_eq!(graph.len(), 1);
    assert_eq!(graph.node_id_for_key(cache_key), Some(first));
    assert_eq!(
        graph.node(first).expect("node exists").value_hash(),
        Some(value_hash(b"first"))
    );
}

#[test]
fn matching_hot_hashes_still_confirm_full_demand_keys() {
    let mut graph = DemandGraph::new();
    let hot = HotXxh3Hash::from_xxh3(7);
    let first_key =
        DemandCacheKey::from_raw_parts_for_test(hot, durable_hash(b"first-confirmation"));
    let second_key =
        DemandCacheKey::from_raw_parts_for_test(hot, durable_hash(b"second-confirmation"));
    let first = graph
        .get_or_insert_node(first_key, Some(value_hash(b"first")))
        .expect("first node inserts");
    let second = graph
        .get_or_insert_node(second_key, Some(value_hash(b"second")))
        .expect("second node inserts despite matching hot hash");

    assert_ne!(first, second);
    assert_eq!(graph.len(), 2);
    assert_eq!(graph.node_id_for_key(first_key), Some(first));
    assert_eq!(graph.node_id_for_key(second_key), Some(second));
}

#[test]
fn expression_nodes_are_interned_by_identity_and_free_vars() {
    let mut graph = DemandGraph::new();
    let identity = identity(b"source", 7);
    let first = graph
        .get_or_insert_expression_node(
            identity,
            [durable_hash(b"left"), durable_hash(b"right")],
            Some(value_hash(b"first")),
        )
        .expect("first expression node inserts");
    let second = graph
        .get_or_insert_expression_node(
            identity,
            [durable_hash(b"left"), durable_hash(b"right")],
            Some(value_hash(b"second")),
        )
        .expect("existing expression node returns");

    assert_eq!(first, second);
    assert_eq!(graph.len(), 1);
    assert_eq!(
        graph.node(first).expect("node exists").value_hash(),
        Some(value_hash(b"first"))
    );
}

#[test]
fn expression_identity_changes_node_key() {
    let mut graph = DemandGraph::new();
    let base = graph
        .get_or_insert_expression_node(
            identity(b"source", 7),
            [durable_hash(b"value")],
            Some(value_hash(b"base")),
        )
        .expect("base expression node inserts");
    let source_changed = graph
        .get_or_insert_expression_node(
            identity(b"other-source", 7),
            [durable_hash(b"value")],
            Some(value_hash(b"source")),
        )
        .expect("source-changed expression node inserts");
    let node_changed = graph
        .get_or_insert_expression_node(
            identity(b"source", 8),
            [durable_hash(b"value")],
            Some(value_hash(b"node")),
        )
        .expect("node-changed expression node inserts");

    assert_ne!(base, source_changed);
    assert_ne!(base, node_changed);
    assert_ne!(source_changed, node_changed);
    assert_eq!(graph.len(), 3);
}

#[test]
fn expression_free_var_order_changes_node_key() {
    let mut graph = DemandGraph::new();
    let identity = identity(b"source", 7);
    let left_then_right = graph
        .get_or_insert_expression_node(
            identity,
            [durable_hash(b"left"), durable_hash(b"right")],
            Some(value_hash(b"left-right")),
        )
        .expect("left-right expression node inserts");
    let right_then_left = graph
        .get_or_insert_expression_node(
            identity,
            [durable_hash(b"right"), durable_hash(b"left")],
            Some(value_hash(b"right-left")),
        )
        .expect("right-left expression node inserts");

    assert_ne!(left_then_right, right_then_left);
    assert_eq!(graph.len(), 2);
}

#[test]
fn dependency_edges_are_symmetric() {
    let mut graph = DemandGraph::new();
    let dependency = node_with_hash(&mut graph, 1, b"dependency");
    let dependent = node_with_hash(&mut graph, 2, b"dependent");

    graph
        .add_dependency(dependent, dependency)
        .expect("edge records");

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

#[test]
fn dependency_edges_iterate_in_node_order() {
    let mut graph = DemandGraph::new();
    let dependency = node_with_hash(&mut graph, 1, b"dependency");
    let earlier_dependent = node_with_hash(&mut graph, 2, b"earlier");
    let later_dependent = node_with_hash(&mut graph, 3, b"later");
    graph
        .add_dependency(later_dependent, dependency)
        .expect("later edge records");
    graph
        .add_dependency(earlier_dependent, dependency)
        .expect("earlier edge records");

    let result = graph
        .reconsider_node(dependency, value_hash(b"changed"))
        .expect("dependency reconsiders");

    assert_eq!(
        result.dirtied_dependents(),
        &[earlier_dependent, later_dependent]
    );
}

#[test]
fn unknown_nodes_and_self_dependencies_are_rejected() {
    let mut graph = DemandGraph::new();
    let known = node_with_hash(&mut graph, 1, b"known");
    let unknown = DemandNodeId::new(99);

    assert!(matches!(
        graph.node(unknown),
        Err(DemandGraphError::UnknownNode { id }) if id == unknown
    ));
    assert!(matches!(
        graph.add_dependency(known, unknown),
        Err(DemandGraphError::UnknownNode { id }) if id == unknown
    ));
    assert!(matches!(
        graph.mark_dirty(unknown),
        Err(DemandGraphError::UnknownNode { id }) if id == unknown
    ));
    assert!(matches!(
        graph.reconsider_node(unknown, value_hash(b"value")),
        Err(DemandGraphError::UnknownNode { id }) if id == unknown
    ));
    assert!(matches!(
        graph.add_dependency(known, known),
        Err(DemandGraphError::SelfDependency { id }) if id == known
    ));
}
