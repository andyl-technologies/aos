//! In-memory demand graph substrate for incremental evaluation.
//!
//! The full evaluator integration will decide when to create graph nodes and
//! how to recompute them. This module owns the graph-shaped bookkeeping those
//! layers need: key interning, dependency/dependent edges, dirty marking,
//! dirty-frontier scheduling, and the local reconsideration step that applies
//! early cutoff.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use thiserror::Error;

use super::{
    CacheExprIdentity, CacheKeyError, CacheableInputFingerprint, CutoffDecision, DemandCacheKey,
    EarlyCutoff, ImpureInputFingerprint, UncacheableInput, ValueHash, ValueHashError,
};
use crate::value::Value;

mod frontier;
mod graph;
mod nodes;
mod observation;
mod shared;

pub use shared::{DemandNodeAdmission, SharedDemandGraph, SharedDemandGraphError};

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

/// The owner class for one demand-graph dependency edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DemandDependencyGroup {
    /// A dependency discovered when one memoized demand reads another node.
    MemoRead,
    /// A dependency discovered from one evaluator impure-input trace.
    ImpureInput,
}

/// One demand-graph node.
#[derive(Clone, Debug)]
pub struct DemandNode {
    key: DemandCacheKey,
    value_hash: Option<ValueHash>,
    freshness: NodeFreshness,
    dependency_groups: BTreeMap<DemandDependencyGroup, BTreeSet<DemandNodeId>>,
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

/// The result of running a ready-dirty recomputation loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecomputeReadyDirty {
    reconsiderations: Vec<Reconsideration>,
    remaining: DirtyFrontier,
}

/// One dirty node that cannot be scheduled yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedDirtyNode {
    node: DemandNodeId,
    blockers: Vec<DemandNodeId>,
}

/// A deterministic scheduling snapshot for dirty demand-graph nodes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirtyFrontier {
    ready: Vec<DemandNodeId>,
    blocked: Vec<BlockedDirtyNode>,
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
    /// Recompute loop storage could not reserve capacity.
    #[error("demand graph failed to reserve {entries} recomputation entries")]
    RecomputeLoopAllocationFailed {
        /// The requested recomputation entry capacity.
        entries: usize,
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
mod tests;
