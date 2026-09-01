//! Tests extracted from the adjacent production module.

use super::*;

fn fragment(request_id: u32, index: u32, start: u64) -> BlockWriteFragmentId {
    BlockWriteFragmentId {
        request_id,
        fragment_index: index,
        start,
        length: 512,
    }
}

#[test]
fn request_and_overlap_dependencies_are_finite_and_release_exactly() {
    let mut graph = BlockPersistenceGraph::new();
    graph
        .admit_request(&[(0, fragment(1, 0, 0)), (1, fragment(1, 1, 512))], 0, &[])
        .unwrap_or_else(|error| panic!("first admission: {error}"));
    graph
        .admit_request(&[(2, fragment(2, 0, 0))], 0, &[])
        .unwrap_or_else(|error| panic!("overlap admission: {error}"));
    assert_eq!(graph.nodes()[&1].dependencies, BTreeSet::from([0]));
    assert_eq!(graph.nodes()[&2].dependencies, BTreeSet::from([0]));
    assert_eq!(graph.next_ready_before(3, 0), Some(0));
    graph
        .commit_persisted(0)
        .unwrap_or_else(|error| panic!("commit ready: {error}"));
    assert!(graph.nodes()[&1].dependencies.is_empty());
    assert!(graph.nodes()[&2].dependencies.is_empty());
    graph
        .validate()
        .unwrap_or_else(|error| panic!("released graph: {error}"));
}

#[test]
fn flush_frontier_excludes_later_writes_and_delay_is_exact() {
    let mut graph = BlockPersistenceGraph::new();
    let transform = ResolvedBlockPersistenceTransform {
        contributor: [1; 32],
        ordering_group: [7; 32],
        ordering: BlockPersistenceOrdering::DescendingRange,
        delay_nanos: 5,
        preserve_barriers: true,
    };
    graph
        .admit_request(&[(0, fragment(1, 0, 1024))], 10, &[transform])
        .unwrap_or_else(|error| panic!("delayed admission: {error}"));
    graph
        .admit_request(&[(1, fragment(2, 0, 0))], 0, &[])
        .unwrap_or_else(|error| panic!("later admission: {error}"));
    assert_eq!(graph.next_ready_before(1, 14), None);
    assert_eq!(graph.next_ready_before(1, 15), Some(0));
    graph
        .commit_persisted(0)
        .unwrap_or_else(|error| panic!("persist captured frontier: {error}"));
    assert!(graph.nodes().contains_key(&1));
}

#[test]
fn explicit_edges_reject_forward_or_absent_nodes_without_mutation() {
    let mut graph = BlockPersistenceGraph::new();
    graph
        .admit_request(&[(0, fragment(1, 0, 0)), (1, fragment(1, 1, 512))], 0, &[])
        .unwrap_or_else(|error| panic!("admission: {error}"));
    let before = graph.clone();
    assert!(graph.add_dependency(0, 1, true).is_err());
    assert_eq!(graph, before);
    assert!(graph.add_dependency(1, 99, true).is_err());
    assert_eq!(graph, before);
}

#[test]
fn reverse_ready_changes_only_mutually_ready_selection() {
    let mut graph = BlockPersistenceGraph::new();
    let transform = ResolvedBlockPersistenceTransform {
        contributor: [2; 32],
        ordering_group: [9; 32],
        ordering: BlockPersistenceOrdering::ReverseReady,
        delay_nanos: 0,
        preserve_barriers: true,
    };
    graph
        .admit_request(&[(0, fragment(1, 0, 0))], 0, &[transform])
        .unwrap_or_else(|error| panic!("first admission: {error}"));
    graph
        .admit_request(&[(1, fragment(2, 0, 1024))], 0, &[transform])
        .unwrap_or_else(|error| panic!("second admission: {error}"));

    assert_eq!(graph.next_ready_before(2, 0), Some(1));
    graph
        .add_dependency(1, 0, true)
        .unwrap_or_else(|error| panic!("barrier dependency: {error}"));
    assert_eq!(graph.next_ready_before(2, 0), Some(0));
}

#[test]
fn ordering_group_does_not_reorder_an_out_of_group_fragment() {
    let mut graph = BlockPersistenceGraph::new();
    let reverse = ResolvedBlockPersistenceTransform {
        contributor: [3; 32],
        ordering_group: [3; 32],
        ordering: BlockPersistenceOrdering::ReverseReady,
        delay_nanos: 0,
        preserve_barriers: true,
    };
    graph
        .admit_request(&[(0, fragment(1, 0, 0))], 0, &[reverse])
        .unwrap_or_else(|error| panic!("group admission: {error}"));
    graph
        .admit_request(&[(1, fragment(2, 0, 1024))], 0, &[])
        .unwrap_or_else(|error| panic!("ungrouped admission: {error}"));

    assert_eq!(graph.next_ready_before(2, 0), Some(0));
}

#[test]
fn loss_unblocks_dependents_without_claiming_durability() {
    let mut graph = BlockPersistenceGraph::new();
    graph
        .admit_request(&[(0, fragment(1, 0, 0)), (1, fragment(1, 1, 512))], 0, &[])
        .unwrap_or_else(|error| panic!("admission: {error}"));

    graph
        .commit_lost(0)
        .unwrap_or_else(|error| panic!("loss: {error}"));
    assert!(graph.is_ready(1));
    assert_eq!(graph.next_ready_before(2, 0), Some(1));
    graph
        .validate()
        .unwrap_or_else(|error| panic!("post-loss graph: {error}"));
}

#[test]
fn configured_edge_bound_and_barrier_policy_fail_closed() {
    let mut bounded = BlockPersistenceGraph::with_edge_limit(1)
        .unwrap_or_else(|error| panic!("edge bound: {error}"));
    bounded
        .admit_request(&[(0, fragment(1, 0, 0))], 0, &[])
        .unwrap_or_else(|error| panic!("first write: {error}"));
    bounded
        .admit_request(&[(1, fragment(2, 0, 0))], 0, &[])
        .unwrap_or_else(|error| panic!("second write: {error}"));
    let before = bounded.clone();
    assert!(
        bounded
            .admit_request(&[(2, fragment(3, 0, 0))], 0, &[])
            .is_err()
    );
    assert_eq!(bounded, before);

    for (preserve_barriers, expected_dependencies) in
        [(true, BTreeSet::from([0])), (false, BTreeSet::new())]
    {
        let mut graph = BlockPersistenceGraph::new();
        graph
            .admit_request(&[(0, fragment(1, 0, 0))], 0, &[])
            .unwrap_or_else(|error| panic!("barrier predecessor: {error}"));
        let transform = ResolvedBlockPersistenceTransform {
            contributor: [8; 32],
            ordering_group: [4; 32],
            ordering: BlockPersistenceOrdering::Preserve,
            delay_nanos: 0,
            preserve_barriers,
        };
        graph
            .admit_request_with_barrier(&[(1, fragment(2, 0, 1024))], 0, &[transform], Some(1))
            .unwrap_or_else(|error| panic!("barrier admission: {error}"));
        assert_eq!(graph.nodes()[&1].dependencies, expected_dependencies);
        assert_eq!(graph.nodes()[&1].barrier_protected, preserve_barriers);
    }
}

#[test]
fn transformation_evidence_retains_every_contributor_until_drained() {
    let mut graph = BlockPersistenceGraph::new();
    for (sequence, contributor) in [(0, [1; 32]), (1, [2; 32])] {
        graph
            .admit_request(
                &[(sequence, fragment(sequence as u32 + 1, 0, sequence * 1024))],
                0,
                &[ResolvedBlockPersistenceTransform {
                    contributor,
                    ordering_group: [5; 32],
                    ordering: BlockPersistenceOrdering::Preserve,
                    delay_nanos: 0,
                    preserve_barriers: true,
                }],
            )
            .unwrap_or_else(|error| panic!("transformed admission: {error}"));
    }
    assert_eq!(graph.transformation_evidence().len(), 2);
    assert_eq!(
        graph.transformation_evidence()[0].contributors,
        vec![[1; 32]]
    );
    assert_eq!(
        graph.transformation_evidence()[1].contributors,
        vec![[2; 32]]
    );
    assert_eq!(graph.drain_transformation_evidence().len(), 2);
    assert!(graph.transformation_evidence().is_empty());
}
