//! Demand graph reconsideration tests.

use super::*;

#[test]
fn reconsidering_missing_prior_hash_propagates() {
    let mut graph = DemandGraph::new();
    let dependency = graph
        .get_or_insert_node(key(1, b"dependency"), None)
        .expect("node inserts");
    let dependent = node_with_hash(&mut graph, 2, b"dependent");
    graph
        .add_dependency(dependent, dependency)
        .expect("edge records");

    let result = graph
        .reconsider_node(dependency, value_hash(b"new"))
        .expect("node reconsiders");

    assert_eq!(result.decision(), CutoffDecision::Propagate);
    assert_eq!(result.dirtied_dependents(), &[dependent]);
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn unchanged_hash_cuts_off_without_dirtying_dependents() {
    let mut graph = DemandGraph::new();
    let dependency = node_with_hash(&mut graph, 1, b"same");
    let dependent = node_with_hash(&mut graph, 2, b"dependent");
    graph
        .add_dependency(dependent, dependency)
        .expect("edge records");

    let result = graph
        .reconsider_node(dependency, value_hash(b"same"))
        .expect("node reconsiders");

    assert_eq!(result.decision(), CutoffDecision::CutOff);
    assert!(result.dirtied_dependents().is_empty());
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Clean
    );
}

#[test]
fn unchanged_inline_value_cuts_off_without_dirtying_dependents() {
    let mut graph = DemandGraph::new();
    let dependency = graph
        .get_or_insert_node(key(1, b"inline"), Some(inline_value_hash(Value::int(7))))
        .expect("dependency inserts");
    let dependent = node_with_hash(&mut graph, 2, b"dependent");
    graph
        .add_dependency(dependent, dependency)
        .expect("edge records");

    let result = graph
        .reconsider_inline_value_node(dependency, Value::int(7))
        .expect("node reconsiders");

    assert_eq!(result.decision(), CutoffDecision::CutOff);
    assert!(result.dirtied_dependents().is_empty());
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Clean
    );
}

#[test]
fn changed_inline_value_dirties_direct_dependents() {
    let mut graph = DemandGraph::new();
    let dependency = graph
        .get_or_insert_node(key(1, b"inline"), Some(inline_value_hash(Value::int(1))))
        .expect("dependency inserts");
    let dependent = node_with_hash(&mut graph, 2, b"dependent");
    graph
        .add_dependency(dependent, dependency)
        .expect("edge records");

    let result = graph
        .reconsider_inline_value_node(dependency, Value::int(2))
        .expect("node reconsiders");

    assert_eq!(result.decision(), CutoffDecision::Propagate);
    assert_eq!(result.dirtied_dependents(), &[dependent]);
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph
            .node(dependency)
            .expect("dependency exists")
            .value_hash(),
        Some(inline_value_hash(Value::int(2)))
    );
}

#[test]
fn unchanged_derivation_aterm_cuts_off_without_dirtying_dependents() {
    let mut graph = DemandGraph::new();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[])";
    let dependency = graph
        .get_or_insert_node(key(1, b"derivation"), Some(derivation_aterm_hash(aterm)))
        .expect("dependency inserts");
    let dependent = node_with_hash(&mut graph, 2, b"dependent");
    graph
        .add_dependency(dependent, dependency)
        .expect("edge records");

    let result = graph
        .reconsider_derivation_aterm_node(dependency, aterm)
        .expect("node reconsiders");

    assert_eq!(result.decision(), CutoffDecision::CutOff);
    assert!(result.dirtied_dependents().is_empty());
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Clean
    );
}

#[test]
fn changed_derivation_aterm_dirties_direct_dependents() {
    let mut graph = DemandGraph::new();
    let prior = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"old\")])";
    let changed = b"Derive([],[],[],\":\",\":\",[],[(\"env\",\"new\")])";
    let dependency = graph
        .get_or_insert_node(key(1, b"derivation"), Some(derivation_aterm_hash(prior)))
        .expect("dependency inserts");
    let dependent = node_with_hash(&mut graph, 2, b"dependent");
    graph
        .add_dependency(dependent, dependency)
        .expect("edge records");

    let result = graph
        .reconsider_derivation_aterm_node(dependency, changed)
        .expect("node reconsiders");

    assert_eq!(result.decision(), CutoffDecision::Propagate);
    assert_eq!(result.dirtied_dependents(), &[dependent]);
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph
            .node(dependency)
            .expect("dependency exists")
            .value_hash(),
        Some(derivation_aterm_hash(changed))
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn unsupported_inline_value_reconsideration_does_not_mutate_node() {
    let mut graph = DemandGraph::new();
    let prior = value_hash(b"prior");
    let node = graph
        .get_or_insert_node(key(1, b"inline"), Some(prior))
        .expect("node inserts");
    graph.mark_dirty(node).expect("node dirties");
    let heap_value =
        Value::string(NonNull::<HeapObject>::dangling()).expect("heap representation builds");

    let error = graph
        .reconsider_inline_value_node(node, heap_value)
        .expect_err("heap values are unsupported");

    assert!(matches!(
        error,
        DemandGraphError::ValueHash {
            source: ValueHashError::UnsupportedTag {
                tag: ValueTag::String
            }
        }
    ));
    let node = graph.node(node).expect("node exists");
    assert_eq!(node.value_hash(), Some(prior));
    assert_eq!(node.freshness(), NodeFreshness::Dirty);
}

#[test]
fn changed_hash_dirties_direct_dependents() {
    let mut graph = DemandGraph::new();
    let dependency = node_with_hash(&mut graph, 1, b"old");
    let dependent = node_with_hash(&mut graph, 2, b"dependent");
    graph
        .add_dependency(dependent, dependency)
        .expect("edge records");

    let result = graph
        .reconsider_node(dependency, value_hash(b"new"))
        .expect("node reconsiders");

    assert_eq!(result.decision(), CutoffDecision::Propagate);
    assert_eq!(result.dirtied_dependents(), &[dependent]);
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn invalidating_node_dirties_transitive_memo_read_dependents_without_value_hash() {
    let mut graph = DemandGraph::new();
    let dependency = graph
        .get_or_insert_node(key(1, b"uncacheable"), None)
        .expect("dependency inserts");
    let memo_dependent = node_with_hash(&mut graph, 2, b"memo-dependent");
    let impure_dependent = node_with_hash(&mut graph, 3, b"impure-dependent");
    let transitive_dependent = node_with_hash(&mut graph, 4, b"transitive-dependent");
    graph
        .add_dependency(memo_dependent, dependency)
        .expect("memo edge records");
    graph
        .add_dependency_to_group(
            impure_dependent,
            DemandDependencyGroup::ImpureInput,
            dependency,
        )
        .expect("impure edge records");
    graph
        .add_dependency(transitive_dependent, memo_dependent)
        .expect("transitive edge records");

    let dirtied = graph
        .invalidate_node(dependency)
        .expect("dependency invalidates");

    assert_eq!(dirtied, vec![memo_dependent, transitive_dependent]);
    assert_eq!(
        graph
            .node(dependency)
            .expect("dependency exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph
            .node(memo_dependent)
            .expect("memo dependent exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph
            .node(impure_dependent)
            .expect("impure dependent exists")
            .freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(
        graph
            .node(transitive_dependent)
            .expect("transitive dependent exists")
            .freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn invalidating_node_returns_affected_memo_read_dependents_once() {
    let mut graph = DemandGraph::new();
    let dependency = node_with_hash(&mut graph, 1, b"dependency");
    let already_dirty = node_with_hash(&mut graph, 2, b"already-dirty");
    let clean = node_with_hash(&mut graph, 3, b"clean");
    let transitive = node_with_hash(&mut graph, 4, b"transitive");
    graph
        .add_dependency(already_dirty, dependency)
        .expect("dirty edge records");
    graph
        .add_dependency(clean, dependency)
        .expect("clean edge records");
    graph
        .add_dependency(transitive, already_dirty)
        .expect("transitive edge records");
    graph
        .add_dependency(transitive, clean)
        .expect("diamond edge records");
    graph.mark_dirty(already_dirty).expect("dependent dirties");

    let dirtied = graph
        .invalidate_node(dependency)
        .expect("dependency invalidates");

    assert_eq!(dirtied, vec![already_dirty, clean, transitive]);
    assert_eq!(
        graph
            .node(already_dirty)
            .expect("already dirty exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph.node(clean).expect("clean exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph
            .node(transitive)
            .expect("transitive exists")
            .freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn invalidating_node_walks_memo_read_cycles_once() {
    let mut graph = DemandGraph::new();
    let root = node_with_hash(&mut graph, 1, b"root");
    let first = node_with_hash(&mut graph, 2, b"first");
    let second = node_with_hash(&mut graph, 3, b"second");
    graph
        .add_dependency(first, root)
        .expect("first memo edge records");
    graph
        .add_dependency(second, first)
        .expect("second memo edge records");
    graph
        .add_dependency(root, second)
        .expect("cycle edge records");

    let dirtied = graph.invalidate_node(root).expect("root invalidates");

    assert_eq!(dirtied, vec![first, second]);
    for node in [root, first, second] {
        assert_eq!(
            graph.node(node).expect("cycle node exists").freshness(),
            NodeFreshness::Dirty
        );
    }
}

#[test]
fn reconsidering_changed_hash_returns_only_newly_dirtied_dependents() {
    let mut graph = DemandGraph::new();
    let dependency = node_with_hash(&mut graph, 1, b"old");
    let already_dirty = node_with_hash(&mut graph, 2, b"already-dirty");
    let clean = node_with_hash(&mut graph, 3, b"clean");
    graph
        .add_dependency(already_dirty, dependency)
        .expect("dirty edge records");
    graph
        .add_dependency(clean, dependency)
        .expect("clean edge records");
    graph.mark_dirty(already_dirty).expect("dependent dirties");

    let result = graph
        .reconsider_node(dependency, value_hash(b"new"))
        .expect("node reconsiders");

    assert_eq!(result.decision(), CutoffDecision::Propagate);
    assert_eq!(result.dirtied_dependents(), &[clean]);
    assert_eq!(
        graph
            .node(already_dirty)
            .expect("already dirty exists")
            .freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph.node(clean).expect("clean exists").freshness(),
        NodeFreshness::Dirty
    );
}
