//! Impure input observation demand graph tests.

use super::*;

#[test]
fn impure_input_observation_inserts_clean_leaf() {
    let mut graph = DemandGraph::new();
    let fingerprint = read_file_input(b"/tmp/version", b"1");
    let observed = graph
        .observe_impure_input(&fingerprint)
        .expect("input observes");
    let ImpureInputObservation::Inserted { node } = observed else {
        panic!("first observation inserts");
    };

    assert_eq!(observed.node(), node);
    assert_eq!(graph.len(), 1);
    assert_eq!(
        graph.node(node).expect("node exists").freshness(),
        NodeFreshness::Clean
    );
    assert_eq!(
        graph.node(node).expect("node exists").value_hash(),
        Some(ValueHash::from_impure_input_observation_hash(
            fingerprint.observation_hash()
        ))
    );
}

#[test]
fn unchanged_impure_input_observation_cuts_off() {
    let mut graph = DemandGraph::new();
    let fingerprint = read_file_input(b"/tmp/version", b"1");
    let first = graph
        .observe_impure_input(&fingerprint)
        .expect("input inserts")
        .node();
    let second = graph
        .observe_impure_input(&fingerprint)
        .expect("input reconsiders");
    let ImpureInputObservation::Reconsidered(reconsideration) = second else {
        panic!("second observation reconsiders");
    };

    assert_eq!(reconsideration.node(), first);
    assert_eq!(reconsideration.decision(), CutoffDecision::CutOff);
    assert!(reconsideration.dirtied_dependents().is_empty());
}

#[test]
fn changed_impure_input_observation_dirties_dependents() {
    let mut graph = DemandGraph::new();
    let first = read_file_input(b"/tmp/version", b"1");
    let input = graph
        .observe_impure_input(&first)
        .expect("input inserts")
        .node();
    let dependent = node_with_hash(&mut graph, 7, b"dependent");
    graph
        .add_dependency(dependent, input)
        .expect("dependency records");

    let changed = read_file_input(b"/tmp/version", b"2");
    let observation = graph
        .observe_impure_input(&changed)
        .expect("input reconsiders");
    let ImpureInputObservation::Reconsidered(reconsideration) = observation else {
        panic!("changed observation reconsiders");
    };

    assert_eq!(reconsideration.node(), input);
    assert_eq!(reconsideration.decision(), CutoffDecision::Propagate);
    assert_eq!(reconsideration.dirtied_dependents(), &[dependent]);
    assert_eq!(
        graph.node(dependent).expect("dependent exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph.node(input).expect("input exists").value_hash(),
        Some(ValueHash::from_impure_input_observation_hash(
            changed.observation_hash()
        ))
    );
}

#[test]
fn impure_input_identity_changes_leaf_key() {
    let mut graph = DemandGraph::new();
    let first = graph
        .observe_impure_input(&read_file_input(b"/tmp/one", b"same"))
        .expect("first input inserts")
        .node();
    let second = graph
        .observe_impure_input(&read_file_input(b"/tmp/two", b"same"))
        .expect("second input inserts")
        .node();

    assert_ne!(first, second);
    assert_eq!(graph.len(), 2);
}
