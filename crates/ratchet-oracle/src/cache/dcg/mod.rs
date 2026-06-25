//! In-memory demand graph substrate for incremental evaluation.
//!
//! The full evaluator integration will decide when to create graph nodes and
//! how to recompute them. This module owns the graph-shaped bookkeeping those
//! layers need: key interning, dependency/dependent edges, dirty marking, and
//! the local reconsideration step that applies early cutoff.

use std::collections::{BTreeSet, HashMap};

use thiserror::Error;

use super::{
    CacheExprIdentity, CacheKeyError, CacheableInputFingerprint, CutoffDecision, DemandCacheKey,
    DurableBlake3Hash, EarlyCutoff, ImpureInputFingerprint, UncacheableInput, ValueHash,
    ValueHashError,
};
use crate::value::Value;

mod graph;
mod nodes;
mod observation;

/// A stable id for one node in a [`DemandGraph`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DemandNodeId(u32);

/// Whether a graph node must be reconsidered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeFreshness {
    /// The node has no known upstream change to process.
    Clean,
    /// The node must be recomputed or checked for early cutoff.
    Dirty,
}

/// One demand-graph node.
#[derive(Clone, Debug)]
pub struct DemandNode {
    key: DemandCacheKey,
    value_hash: Option<ValueHash>,
    freshness: NodeFreshness,
    dependencies: BTreeSet<DemandNodeId>,
    dependents: BTreeSet<DemandNodeId>,
}

/// The result of reconsidering one graph node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconsideration {
    node: DemandNodeId,
    decision: CutoffDecision,
    dirtied_dependents: Vec<DemandNodeId>,
}

/// The result of observing one cacheable impure input leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImpureInputObservation {
    /// The input identity had no existing node, so a clean leaf was inserted.
    Inserted {
        /// The inserted leaf node.
        node: DemandNodeId,
    },
    /// An existing leaf was reconsidered against the new observation hash.
    Reconsidered(Reconsideration),
}

/// The cacheability status for an ingested impure input trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImpureTraceStatus {
    /// The trace was complete and contained only cacheable inputs.
    Cacheable,
    /// The evaluator could not produce a complete trace.
    Incomplete,
    /// The trace observed an input that makes the computation uncacheable.
    Uncacheable(UncacheableInput),
}

/// The result of ingesting an evaluator impure-input observation trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpureTraceObservation {
    status: ImpureTraceStatus,
    leaves: Vec<ImpureInputObservation>,
}

/// An in-memory demand graph.
#[derive(Clone, Debug, Default)]
pub struct DemandGraph {
    nodes: Vec<DemandNode>,
    by_key: HashMap<DemandCacheKey, DemandNodeId>,
}

/// Demand-graph bookkeeping failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DemandGraphError {
    /// The graph cannot address another node.
    #[error("demand graph cannot address another node")]
    TooManyNodes,
    /// Node storage could not reserve capacity.
    #[error("demand graph failed to reserve {nodes} nodes")]
    NodeAllocationFailed {
        /// The requested node capacity.
        nodes: usize,
    },
    /// Key-index storage could not reserve capacity.
    #[error("demand graph failed to reserve {keys} keys")]
    KeyAllocationFailed {
        /// The requested key capacity.
        keys: usize,
    },
    /// An expression demand-cache key could not be built.
    #[error("demand graph failed to build cache key: {source}")]
    CacheKey {
        /// The cache-key construction failure.
        source: CacheKeyError,
    },
    /// An inline value could not be hashed.
    #[error("demand graph failed to hash value: {source}")]
    ValueHash {
        /// The value-hash construction failure.
        source: ValueHashError,
    },
    /// Trace observation storage could not reserve capacity.
    #[error("demand graph failed to reserve {observations} trace observations")]
    TraceObservationAllocationFailed {
        /// The requested trace-observation capacity.
        observations: usize,
    },
    /// A node id does not belong to this graph.
    #[error("unknown demand graph node id {id:?}")]
    UnknownNode {
        /// The unknown node id.
        id: DemandNodeId,
    },
    /// A node cannot depend on itself.
    #[error("demand graph node {id:?} cannot depend on itself")]
    SelfDependency {
        /// The node id used on both sides of the edge.
        id: DemandNodeId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{
        CacheExprIdentity, DurableBlake3Hash, HotXxh3Hash, ImpureInputFingerprint, UncacheableInput,
    };
    use crate::compile::IrId;
    use crate::value::{HeapObject, Value, ValueTag};
    use std::ptr::NonNull;

    fn value_hash(bytes: &[u8]) -> ValueHash {
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(bytes))
    }

    fn inline_value_hash(value: Value) -> ValueHash {
        ValueHash::from_inline_value(value).expect("inline value hashes")
    }

    fn durable_hash(bytes: &[u8]) -> DurableBlake3Hash {
        DurableBlake3Hash::for_bytes(bytes)
    }

    fn identity(source: &[u8], node: u32) -> CacheExprIdentity {
        CacheExprIdentity::new(durable_hash(source), IrId::new(node))
    }

    fn key(node: u32, label: &[u8]) -> DemandCacheKey {
        DemandCacheKey::for_free_vars(identity(label, node), [durable_hash(label)])
            .expect("key builds")
    }

    fn read_file_input(path: &[u8], contents: &[u8]) -> CacheableInputFingerprint {
        ImpureInputFingerprint::read_file(path, contents)
            .expect("input fingerprints")
            .as_cacheable()
            .expect("readFile is cacheable")
            .clone()
    }

    fn read_file_trace(path: &[u8], contents: &[u8]) -> ImpureInputFingerprint {
        ImpureInputFingerprint::read_file(path, contents).expect("input fingerprints")
    }

    fn node_with_hash(graph: &mut DemandGraph, node: u32, label: &'static [u8]) -> DemandNodeId {
        graph
            .get_or_insert_node(key(node, label), Some(value_hash(label)))
            .expect("node inserts")
    }

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
}
