//! Behavior for demand-graph node identifiers, nodes, and reconsideration results.

use super::*;

impl DemandNodeId {
    /// Creates a node id from a raw graph index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw graph index.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the id as a `usize` index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl DemandNode {
    pub(super) fn new(key: DemandCacheKey, value_hash: Option<ValueHash>) -> Self {
        Self {
            key,
            value_hash,
            freshness: NodeFreshness::Clean,
            dependency_groups: BTreeMap::new(),
            dependencies: BTreeSet::new(),
            dependents: BTreeSet::new(),
        }
    }

    /// Returns the key that identifies this node.
    pub const fn key(&self) -> DemandCacheKey {
        self.key
    }

    /// Returns the last known value hash for this node.
    pub const fn value_hash(&self) -> Option<ValueHash> {
        self.value_hash
    }

    /// Returns whether this node is clean or dirty.
    pub const fn freshness(&self) -> NodeFreshness {
        self.freshness
    }

    /// Returns the nodes this node depends on.
    ///
    /// This is the union of all dependency groups. Use
    /// [`Self::dependencies_in_group`] when callers need to inspect ownership
    /// for one group.
    pub fn dependencies(&self) -> &BTreeSet<DemandNodeId> {
        &self.dependencies
    }

    /// Returns the nodes this node depends on through `group`.
    pub fn dependencies_in_group(
        &self,
        group: DemandDependencyGroup,
    ) -> Option<&BTreeSet<DemandNodeId>> {
        self.dependency_groups.get(&group)
    }

    /// Returns the nodes that depend on this node.
    pub fn dependents(&self) -> &BTreeSet<DemandNodeId> {
        &self.dependents
    }
}

impl Reconsideration {
    /// Creates a reconsideration result.
    pub fn new(
        node: DemandNodeId,
        decision: CutoffDecision,
        dirtied_dependents: Vec<DemandNodeId>,
    ) -> Self {
        Self {
            node,
            decision,
            dirtied_dependents,
        }
    }

    /// Returns the reconsidered node.
    pub const fn node(&self) -> DemandNodeId {
        self.node
    }

    /// Returns the early-cutoff decision.
    pub const fn decision(&self) -> CutoffDecision {
        self.decision
    }

    /// Returns dependents dirtied by a propagated change.
    pub fn dirtied_dependents(&self) -> &[DemandNodeId] {
        &self.dirtied_dependents
    }
}

impl RecomputeReadyDirty {
    pub(super) fn new(reconsiderations: Vec<Reconsideration>, remaining: DirtyFrontier) -> Self {
        Self {
            reconsiderations,
            remaining,
        }
    }

    /// Returns reconsiderations in the order the loop recomputed nodes.
    pub fn reconsiderations(&self) -> &[Reconsideration] {
        &self.reconsiderations
    }

    /// Returns the dirty frontier that remained after the loop stopped.
    ///
    /// An empty frontier means the loop cleaned every dirty node it could see.
    /// A non-empty frontier has no ready nodes and contains the dirty nodes still
    /// blocked by dirty upstream dependencies.
    pub fn remaining_frontier(&self) -> &DirtyFrontier {
        &self.remaining
    }
}
