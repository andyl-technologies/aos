//! Dirty frontier recomputation tests.

use super::*;

#[test]
fn dirty_nodes_iterate_in_node_order() {
    let mut graph = DemandGraph::new();
    let first = node_with_hash(&mut graph, 1, b"first");
    let second = node_with_hash(&mut graph, 2, b"second");
    let third = node_with_hash(&mut graph, 3, b"third");
    graph.mark_dirty(third).expect("third dirties");
    graph.mark_dirty(first).expect("first dirties");

    let dirty: Vec<_> = graph.dirty_nodes().collect();

    assert_eq!(dirty, vec![first, third]);
    assert_eq!(
        graph.node(second).expect("second exists").freshness(),
        NodeFreshness::Clean
    );
}

#[test]
fn ready_dirty_nodes_wait_for_dirty_dependencies() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-stable");
    let b = node_with_hash(&mut graph, 2, b"b-old");
    let c = node_with_hash(&mut graph, 3, b"c-stable");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");
    graph.mark_dirty(b).expect("b dirties");
    graph.mark_dirty(c).expect("c dirties");

    let ready: Vec<_> = graph.ready_dirty_nodes().collect();

    assert_eq!(ready, vec![b]);

    graph
        .reconsider_node(b, value_hash(b"b-new"))
        .expect("b reconsiders");

    let ready: Vec<_> = graph.ready_dirty_nodes().collect();

    assert_eq!(ready, vec![c]);
}

#[test]
fn ready_dirty_nodes_wait_for_dirty_transitive_dependencies() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b-stable");
    let c = node_with_hash(&mut graph, 3, b"c-stale");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(c).expect("c dirties");

    let ready: Vec<_> = graph.ready_dirty_nodes().collect();

    assert_eq!(ready, vec![a]);

    graph
        .reconsider_node(a, value_hash(b"a-new"))
        .expect("a reconsiders");

    let ready: Vec<_> = graph.ready_dirty_nodes().collect();

    assert_eq!(ready, vec![b]);
}

#[test]
fn dirty_frontier_reports_ready_and_blocked_nodes() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b-stable");
    let c = node_with_hash(&mut graph, 3, b"c-stale");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(c).expect("c dirties");

    let frontier = graph.dirty_frontier();

    assert_eq!(frontier.ready_nodes(), &[a]);
    let [blocked] = frontier.blocked_nodes() else {
        panic!("c is blocked by dirty upstream a");
    };
    assert_eq!(blocked.node(), c);
    assert_eq!(blocked.blockers(), &[a]);
    assert!(!frontier.is_empty());
}

#[test]
fn ready_dirty_nodes_are_empty_for_dirty_cycle() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a");
    let b = node_with_hash(&mut graph, 2, b"b");
    graph.add_dependency(a, b).expect("a depends on b");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(b).expect("b dirties");

    let ready: Vec<_> = graph.ready_dirty_nodes().collect();

    assert!(ready.is_empty());
    assert_eq!(graph.dirty_nodes().collect::<Vec<_>>(), vec![a, b]);
}

#[test]
fn dirty_frontier_reports_cycle_blockers() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a");
    let b = node_with_hash(&mut graph, 2, b"b");
    graph.add_dependency(a, b).expect("a depends on b");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(b).expect("b dirties");

    let frontier = graph.dirty_frontier();

    assert!(frontier.ready_nodes().is_empty());
    let [a_blocked, b_blocked] = frontier.blocked_nodes() else {
        panic!("cycle keeps both dirty nodes blocked");
    };
    assert_eq!(a_blocked.node(), a);
    assert_eq!(a_blocked.blockers(), &[a, b]);
    assert_eq!(b_blocked.node(), b);
    assert_eq!(b_blocked.blockers(), &[a, b]);
}

#[test]
fn recompute_ready_dirty_nodes_cleans_cutoff_frontier() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-stable");
    let b = node_with_hash(&mut graph, 2, b"b-stable");
    let c = node_with_hash(&mut graph, 3, b"c-stable");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(c).expect("c dirties");

    let result = graph
        .recompute_ready_dirty_nodes::<DemandGraphError, _>(|node| {
            if node == a {
                return Ok(value_hash(b"a-stable"));
            }
            if node == c {
                return Ok(value_hash(b"c-stable"));
            }
            panic!("unexpected recomputation for {node:?}");
        })
        .expect("frontier recomputes");

    let reconsidered: Vec<_> = result
        .reconsiderations()
        .iter()
        .map(Reconsideration::node)
        .collect();
    assert_eq!(reconsidered, vec![a, c]);
    assert!(
        result
            .reconsiderations()
            .iter()
            .all(|reconsideration| reconsideration.decision() == CutoffDecision::CutOff)
    );
    assert!(result.remaining_frontier().is_empty());
    assert_eq!(
        graph.dirty_nodes().collect::<Vec<_>>(),
        Vec::<DemandNodeId>::new()
    );
}

#[test]
fn recompute_ready_dirty_nodes_propagates_until_clean() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b-old");
    let c = node_with_hash(&mut graph, 3, b"c-stable");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");
    graph.mark_dirty(a).expect("a dirties");

    let result = graph
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
        .expect("frontier recomputes");

    let reconsidered: Vec<_> = result
        .reconsiderations()
        .iter()
        .map(Reconsideration::node)
        .collect();
    assert_eq!(reconsidered, vec![a, b, c]);
    assert_eq!(
        result
            .reconsiderations()
            .iter()
            .map(Reconsideration::decision)
            .collect::<Vec<_>>(),
        vec![
            CutoffDecision::Propagate,
            CutoffDecision::Propagate,
            CutoffDecision::CutOff
        ]
    );
    assert!(result.remaining_frontier().is_empty());
    assert_eq!(
        graph.dirty_nodes().collect::<Vec<_>>(),
        Vec::<DemandNodeId>::new()
    );
}

#[test]
fn recompute_ready_dirty_nodes_stops_on_blocked_cycle() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a");
    let b = node_with_hash(&mut graph, 2, b"b");
    graph.add_dependency(a, b).expect("a depends on b");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(b).expect("b dirties");

    let result = graph
        .recompute_ready_dirty_nodes::<DemandGraphError, _>(|node| {
            panic!("dirty cycle should not recompute {node:?}");
        })
        .expect("blocked frontier returns");

    assert!(result.reconsiderations().is_empty());
    assert!(result.remaining_frontier().ready_nodes().is_empty());
    let [a_blocked, b_blocked] = result.remaining_frontier().blocked_nodes() else {
        panic!("cycle keeps both dirty nodes blocked");
    };
    assert_eq!(a_blocked.node(), a);
    assert_eq!(a_blocked.blockers(), &[a, b]);
    assert_eq!(b_blocked.node(), b);
    assert_eq!(b_blocked.blockers(), &[a, b]);
    assert_eq!(graph.dirty_nodes().collect::<Vec<_>>(), vec![a, b]);
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecomputeTestError {
    Graph(DemandGraphError),
    Rejected(DemandNodeId),
}

impl From<DemandGraphError> for RecomputeTestError {
    fn from(error: DemandGraphError) -> Self {
        Self::Graph(error)
    }
}

#[test]
fn recompute_ready_dirty_nodes_stops_on_recompute_error() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a");
    graph.mark_dirty(a).expect("a dirties");

    let error = graph
        .recompute_ready_dirty_nodes::<RecomputeTestError, _>(|node| {
            Err(RecomputeTestError::Rejected(node))
        })
        .expect_err("recompute error stops the loop");

    assert_eq!(error, RecomputeTestError::Rejected(a));
    assert_eq!(graph.dirty_nodes().collect::<Vec<_>>(), vec![a]);
}

#[test]
fn recompute_ready_dirty_nodes_keeps_prior_progress_on_later_recompute_error() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b");
    let c = node_with_hash(&mut graph, 3, b"c");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.mark_dirty(a).expect("a dirties");
    graph.mark_dirty(c).expect("c dirties");

    let error = graph
        .recompute_ready_dirty_nodes::<RecomputeTestError, _>(|node| {
            if node == a {
                return Ok(value_hash(b"a-new"));
            }
            Err(RecomputeTestError::Rejected(node))
        })
        .expect_err("later recompute error stops the loop");

    assert_eq!(error, RecomputeTestError::Rejected(c));
    assert_eq!(graph.dirty_nodes().collect::<Vec<_>>(), vec![b, c]);
}

#[test]
fn cutoff_stops_before_transitive_dependents() {
    let mut graph = DemandGraph::new();
    let a = node_with_hash(&mut graph, 1, b"a-old");
    let b = node_with_hash(&mut graph, 2, b"b-stable");
    let c = node_with_hash(&mut graph, 3, b"c-stable");
    graph.add_dependency(b, a).expect("b depends on a");
    graph.add_dependency(c, b).expect("c depends on b");

    let a_result = graph
        .reconsider_node(a, value_hash(b"a-new"))
        .expect("a reconsiders");
    assert_eq!(a_result.dirtied_dependents(), &[b]);
    assert_eq!(
        graph.node(b).expect("b exists").freshness(),
        NodeFreshness::Dirty
    );
    assert_eq!(
        graph.node(c).expect("c exists").freshness(),
        NodeFreshness::Clean
    );

    let b_cutoff = graph
        .reconsider_node(b, value_hash(b"b-stable"))
        .expect("b reconsiders");
    assert_eq!(b_cutoff.decision(), CutoffDecision::CutOff);
    assert!(b_cutoff.dirtied_dependents().is_empty());
    assert_eq!(
        graph.node(c).expect("c exists").freshness(),
        NodeFreshness::Clean
    );

    graph.mark_dirty(b).expect("b dirties");
    let b_changed = graph
        .reconsider_node(b, value_hash(b"b-new"))
        .expect("b reconsiders");
    assert_eq!(b_changed.decision(), CutoffDecision::Propagate);
    assert_eq!(b_changed.dirtied_dependents(), &[c]);
    assert_eq!(
        graph.node(c).expect("c exists").freshness(),
        NodeFreshness::Dirty
    );
}
