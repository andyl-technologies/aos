//! Behavior for demand-graph dirty-frontier scheduling snapshots.

use super::*;

impl BlockedDirtyNode {
    pub(super) fn new(node: DemandNodeId, blockers: Vec<DemandNodeId>) -> Self {
        Self { node, blockers }
    }

    /// Returns the dirty node that is not ready to recompute.
    pub const fn node(&self) -> DemandNodeId {
        self.node
    }

    /// Returns dirty upstream nodes blocking this node.
    ///
    /// Blockers are returned in deterministic node order. If a dirty node is
    /// reachable from itself through a dependency cycle, that node is included
    /// as a blocker so callers can diagnose a stalled dirty frontier.
    pub fn blockers(&self) -> &[DemandNodeId] {
        &self.blockers
    }
}

impl DirtyFrontier {
    pub(super) fn new(ready: Vec<DemandNodeId>, blocked: Vec<BlockedDirtyNode>) -> Self {
        Self { ready, blocked }
    }

    /// Returns dirty nodes that can be recomputed now.
    pub fn ready_nodes(&self) -> &[DemandNodeId] {
        &self.ready
    }

    /// Returns dirty nodes blocked by dirty upstream dependencies.
    pub fn blocked_nodes(&self) -> &[BlockedDirtyNode] {
        &self.blocked
    }

    /// Returns whether this frontier contains no dirty nodes.
    pub const fn is_empty(&self) -> bool {
        self.ready.is_empty() && self.blocked.is_empty()
    }
}
