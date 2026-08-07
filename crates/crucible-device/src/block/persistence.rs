//! Bounded deterministic persistence dependency graph for block fragments.
//!
//! Every applied write fragment enters this graph before it can reach durable
//! media. The graph owns dependency readiness and persistence ordering; the
//! controller and volatile-cache maps continue to own the fragment bytes.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeviceError;

/// Hard maximum live persistence nodes.
pub const HARD_BLOCK_PERSISTENCE_NODES: usize = 4_194_304;
/// Hard maximum aggregate dependency edges across live persistence nodes.
pub const HARD_BLOCK_PERSISTENCE_EDGES: usize = 16_777_216;

/// Stable identity of one atomic write fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockWriteFragmentId {
    /// Original guest request identity.
    pub request_id: u32,
    /// Zero-based atomic fragment index within the request.
    pub fragment_index: u32,
    /// Physical destination range start.
    pub start: u64,
    /// Positive fragment length.
    pub length: u64,
}

/// Closed persistence-priority transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockPersistenceOrdering {
    /// Uses the normal controller-sequence order.
    Preserve,
    /// Reverses mutually-ready fragments in the selected group.
    ReverseReady,
    /// Prefers the highest addressed mutually-ready fragment.
    DescendingRange,
    /// Uses a deterministic keyed permutation of mutually-ready fragments.
    KeyedPermutation,
}

/// One resolved persistence transformation applied at fragment admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedBlockPersistenceTransform {
    /// Stable ordering-group identity digest.
    pub ordering_group: [u8; 32],
    /// Closed ready-set ordering rule.
    pub ordering: BlockPersistenceOrdering,
    /// Additional virtual delay before persistence service may select the node.
    pub delay_nanos: u64,
    /// Whether barrier dependencies are immutable under this transformation.
    pub preserve_barriers: bool,
}

/// One checkpointed live persistence node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPersistenceNode {
    /// Global controller/write sequence.
    pub sequence: u64,
    /// Stable atomic fragment identity.
    pub fragment: BlockWriteFragmentId,
    /// Live predecessor sequences that must resolve first.
    pub dependencies: BTreeSet<u64>,
    /// Original dependency depth retained after predecessors leave the graph.
    pub dependency_depth: u32,
    /// Independent normal writeback sequence.
    pub writeback_sequence: u64,
    /// Earliest virtual nanosecond at which service may select this node.
    pub persistence_deadline_nanos: Option<u64>,
    /// Whether a flush/FUA/transaction barrier contributed an immutable edge.
    pub barrier_protected: bool,
    ordering_group: Option<[u8; 32]>,
    ordering: BlockPersistenceOrdering,
    keyed_rank: [u8; 32],
}

/// Before/after identity of the most recently admitted graph transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockPersistenceTransformationEvidence {
    /// Graph digest before admitting and transforming the fragments.
    pub before: [u8; 32],
    /// Graph digest after the complete atomic admission.
    pub after: [u8; 32],
}

/// Complete bounded persistence DAG continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPersistenceGraph {
    nodes: BTreeMap<u64, BlockPersistenceNode>,
    edge_count: usize,
    next_writeback_sequence: u64,
    last_transformation: Option<BlockPersistenceTransformationEvidence>,
}

impl Default for BlockPersistenceGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockPersistenceGraph {
    /// Creates an empty persistence graph.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edge_count: 0,
            next_writeback_sequence: 0,
            last_transformation: None,
        }
    }

    /// Returns all live nodes in controller-sequence order.
    #[must_use]
    pub const fn nodes(&self) -> &BTreeMap<u64, BlockPersistenceNode> {
        &self.nodes
    }

    /// Returns the most recent atomic graph-transformation evidence.
    #[must_use]
    pub const fn last_transformation(&self) -> Option<BlockPersistenceTransformationEvidence> {
        self.last_transformation
    }

    /// Returns the canonical digest of the complete live graph continuation.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.block-persistence-graph.v1\0");
        hasher.update(&self.next_writeback_sequence.to_be_bytes());
        for node in self.nodes.values() {
            hasher.update(&node.sequence.to_be_bytes());
            hasher.update(&node.fragment.request_id.to_be_bytes());
            hasher.update(&node.fragment.fragment_index.to_be_bytes());
            hasher.update(&node.fragment.start.to_be_bytes());
            hasher.update(&node.fragment.length.to_be_bytes());
            hasher.update(&node.dependency_depth.to_be_bytes());
            hasher.update(&node.writeback_sequence.to_be_bytes());
            match node.persistence_deadline_nanos {
                Some(deadline) => {
                    hasher.update(&[1]);
                    hasher.update(&deadline.to_be_bytes());
                }
                None => {
                    hasher.update(&[0]);
                }
            };
            hasher.update(&[u8::from(node.barrier_protected)]);
            match node.ordering_group {
                Some(group) => {
                    hasher.update(&[1]);
                    hasher.update(&group);
                }
                None => {
                    hasher.update(&[0]);
                }
            };
            hasher.update(&[ordering_tag(node.ordering)]);
            hasher.update(&node.keyed_rank);
            hasher.update(
                &u64::try_from(node.dependencies.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            for dependency in &node.dependencies {
                hasher.update(&dependency.to_be_bytes());
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// Validates bounds, edge targets, depths, sequence ownership, and acyclicity.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidBlockFaultDirective`] when checkpointed
    /// graph state is malformed or exceeds a compiled hard bound.
    pub fn validate(&self) -> Result<(), DeviceError> {
        if self.nodes.len() > HARD_BLOCK_PERSISTENCE_NODES
            || self.edge_count > HARD_BLOCK_PERSISTENCE_EDGES
            || self.edge_count
                != self
                    .nodes
                    .values()
                    .map(|node| node.dependencies.len())
                    .sum::<usize>()
            || self.nodes.iter().any(|(sequence, node)| {
                *sequence != node.sequence
                    || node.fragment.length == 0
                    || node.writeback_sequence >= self.next_writeback_sequence
                    || node.dependencies.iter().any(|dependency| {
                        *dependency >= node.sequence || !self.nodes.contains_key(dependency)
                    })
            })
        {
            return Err(invalid(
                "restored persistence graph violates bounds or ownership",
            ));
        }
        for node in self.nodes.values() {
            let expected_minimum_depth = node
                .dependencies
                .iter()
                .filter_map(|dependency| self.nodes.get(dependency))
                .map(|dependency| dependency.dependency_depth)
                .max()
                .map_or(0, |depth| depth.saturating_add(1));
            if node.dependency_depth < expected_minimum_depth {
                return Err(invalid(
                    "restored persistence dependency depth is inconsistent",
                ));
            }
        }
        Ok(())
    }

    /// Atomically admits one request's applied atomic fragments.
    ///
    /// Dependencies preserve overlapping earlier writes and fragment order
    /// within the request. Transformations alter only mutually-ready priority;
    /// they never remove normal or barrier edges.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for duplicate identities, sequence/range
    /// overflow, graph bounds, deadline overflow, or a malformed transform.
    pub fn admit_request(
        &mut self,
        fragments: &[(u64, BlockWriteFragmentId)],
        admitted_nanos: u64,
        transforms: &[ResolvedBlockPersistenceTransform],
    ) -> Result<BlockPersistenceTransformationEvidence, DeviceError> {
        let before = self.digest();
        if fragments.is_empty() {
            let evidence = BlockPersistenceTransformationEvidence {
                before,
                after: before,
            };
            self.last_transformation = Some(evidence);
            return Ok(evidence);
        }
        if self
            .nodes
            .len()
            .checked_add(fragments.len())
            .is_none_or(|count| count > HARD_BLOCK_PERSISTENCE_NODES)
            || fragments.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || fragments.iter().any(|(sequence, fragment)| {
                self.nodes.contains_key(sequence)
                    || fragment.length == 0
                    || fragment.start.checked_add(fragment.length).is_none()
            })
        {
            return Err(invalid(
                "persistence fragment admission is noncanonical or unbounded",
            ));
        }
        let mut next = self.clone();
        let transform = compose_transforms(transforms)?;
        let mut prior_fragment = None;
        for (sequence, fragment) in fragments {
            let mut dependencies = next
                .nodes
                .values()
                .filter(|candidate| {
                    candidate.sequence < *sequence
                        && ranges_overlap(
                            candidate.fragment.start,
                            candidate.fragment.length,
                            fragment.start,
                            fragment.length,
                        )
                })
                .map(|candidate| candidate.sequence)
                .collect::<BTreeSet<_>>();
            if let Some(prior) = prior_fragment {
                dependencies.insert(prior);
            }
            let dependency_depth = dependencies
                .iter()
                .filter_map(|dependency| next.nodes.get(dependency))
                .map(|dependency| dependency.dependency_depth)
                .max()
                .map_or(0, |depth| depth.saturating_add(1));
            if dependency_depth == u32::MAX {
                return Err(invalid("persistence dependency depth overflow"));
            }
            let writeback_sequence = next.next_writeback_sequence;
            next.next_writeback_sequence = next
                .next_writeback_sequence
                .checked_add(1)
                .ok_or_else(|| invalid("persistence writeback sequence overflow"))?;
            let persistence_deadline_nanos = transform
                .as_ref()
                .map(|transform| {
                    admitted_nanos
                        .checked_add(transform.delay_nanos)
                        .ok_or_else(|| invalid("persistence deadline overflow"))
                })
                .transpose()?;
            let (ordering_group, ordering) = transform
                .as_ref()
                .map_or((None, BlockPersistenceOrdering::Preserve), |transform| {
                    (Some(transform.ordering_group), transform.ordering)
                });
            let keyed_rank = persistence_rank(ordering_group, *sequence, *fragment);
            next.edge_count = next
                .edge_count
                .checked_add(dependencies.len())
                .ok_or_else(|| invalid("persistence dependency count overflow"))?;
            if next.edge_count > HARD_BLOCK_PERSISTENCE_EDGES {
                return Err(invalid(
                    "persistence dependency graph exceeds its edge bound",
                ));
            }
            next.nodes.insert(
                *sequence,
                BlockPersistenceNode {
                    sequence: *sequence,
                    fragment: *fragment,
                    dependencies,
                    dependency_depth,
                    writeback_sequence,
                    persistence_deadline_nanos,
                    barrier_protected: false,
                    ordering_group,
                    ordering,
                    keyed_rank,
                },
            );
            prior_fragment = Some(*sequence);
        }
        next.validate()?;
        let after = next.digest();
        let evidence = BlockPersistenceTransformationEvidence { before, after };
        next.last_transformation = Some(evidence);
        *self = next;
        Ok(evidence)
    }

    /// Adds one explicit dependency edge transactionally.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when either node is absent, the edge points
    /// forward, a barrier edge would be weakened, bounds are exceeded, or the
    /// edge would make the stored depth unrepresentable.
    pub fn add_dependency(
        &mut self,
        sequence: u64,
        dependency: u64,
        barrier: bool,
    ) -> Result<BlockPersistenceTransformationEvidence, DeviceError> {
        let before = self.digest();
        if dependency >= sequence
            || !self.nodes.contains_key(&dependency)
            || !self.nodes.contains_key(&sequence)
        {
            return Err(invalid("persistence dependency edge has invalid endpoints"));
        }
        let mut next = self.clone();
        let inserted = next
            .nodes
            .get_mut(&sequence)
            .ok_or_else(|| invalid("persistence dependent disappeared"))?
            .dependencies
            .insert(dependency);
        if inserted {
            next.edge_count = next
                .edge_count
                .checked_add(1)
                .ok_or_else(|| invalid("persistence dependency count overflow"))?;
        }
        let dependency_depth = next
            .nodes
            .get(&dependency)
            .ok_or_else(|| invalid("persistence predecessor disappeared"))?
            .dependency_depth
            .checked_add(1)
            .ok_or_else(|| invalid("persistence dependency depth overflow"))?;
        let node = next
            .nodes
            .get_mut(&sequence)
            .ok_or_else(|| invalid("persistence dependent disappeared"))?;
        node.dependency_depth = node.dependency_depth.max(dependency_depth);
        node.barrier_protected |= barrier;
        next.validate()?;
        let after = next.digest();
        let evidence = BlockPersistenceTransformationEvidence { before, after };
        next.last_transformation = Some(evidence);
        *self = next;
        Ok(evidence)
    }

    /// Returns the first ready sequence below an exclusive captured frontier.
    #[must_use]
    pub fn next_ready_before(&self, frontier: u64, now_nanos: u64) -> Option<u64> {
        self.nodes
            .values()
            .filter(|node| {
                node.sequence < frontier
                    && node.dependencies.is_empty()
                    && node
                        .persistence_deadline_nanos
                        .is_none_or(|deadline| deadline <= now_nanos)
            })
            .min_by(|left, right| persistence_order_key(left).cmp(&persistence_order_key(right)))
            .map(|node| node.sequence)
    }

    /// Returns the transformed writeback key used by dirty eviction.
    #[must_use]
    pub fn writeback_key(&self, sequence: u64) -> Option<BlockPersistenceReadyKey> {
        self.nodes.get(&sequence).map(persistence_order_key)
    }

    /// Returns whether one live node currently has no unresolved dependency.
    #[must_use]
    pub fn is_ready(&self, sequence: u64) -> bool {
        self.nodes
            .get(&sequence)
            .is_some_and(|node| node.dependencies.is_empty())
    }

    /// Commits one ready node as durably persisted and unblocks dependents.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the node is absent or still has a live
    /// dependency. Callers perform the durable byte write before committing.
    pub fn commit_persisted(&mut self, sequence: u64) -> Result<(), DeviceError> {
        if self
            .nodes
            .get(&sequence)
            .is_none_or(|node| !node.dependencies.is_empty())
        {
            return Err(invalid("persistence commit selected a non-ready fragment"));
        }
        self.remove_resolved(sequence)
    }

    /// Resolves one lost fragment without marking it durable.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the sequence is not live.
    pub fn commit_lost(&mut self, sequence: u64) -> Result<(), DeviceError> {
        if !self.nodes.contains_key(&sequence) {
            return Err(invalid("persistence loss selected an absent fragment"));
        }
        self.remove_resolved(sequence)
    }

    fn remove_resolved(&mut self, sequence: u64) -> Result<(), DeviceError> {
        let removed = self
            .nodes
            .remove(&sequence)
            .ok_or_else(|| invalid("resolved persistence fragment disappeared"))?;
        self.edge_count = self
            .edge_count
            .checked_sub(removed.dependencies.len())
            .ok_or_else(|| invalid("persistence edge accounting underflow"))?;
        for node in self.nodes.values_mut() {
            if node.dependencies.remove(&sequence) {
                self.edge_count = self
                    .edge_count
                    .checked_sub(1)
                    .ok_or_else(|| invalid("persistence edge accounting underflow"))?;
            }
        }
        Ok(())
    }
}

/// Canonical total-order key for one ready persistence node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockPersistenceReadyKey {
    dependency_depth: u32,
    transformed_primary: [u8; 32],
    controller_sequence: u64,
    range_start: u64,
    fragment: BlockWriteFragmentId,
}

fn persistence_order_key(node: &BlockPersistenceNode) -> BlockPersistenceReadyKey {
    let transformed_primary = match node.ordering {
        BlockPersistenceOrdering::Preserve => expanded_u64(node.writeback_sequence),
        BlockPersistenceOrdering::ReverseReady => expanded_u64(u64::MAX - node.writeback_sequence),
        BlockPersistenceOrdering::DescendingRange => expanded_u64(u64::MAX - node.fragment.start),
        BlockPersistenceOrdering::KeyedPermutation => node.keyed_rank,
    };
    BlockPersistenceReadyKey {
        dependency_depth: node.dependency_depth,
        transformed_primary,
        controller_sequence: node.sequence,
        range_start: node.fragment.start,
        fragment: node.fragment,
    }
}

fn expanded_u64(value: u64) -> [u8; 32] {
    let word = value.to_be_bytes();
    let mut expanded = [0_u8; 32];
    for chunk in expanded.chunks_exact_mut(word.len()) {
        chunk.copy_from_slice(&word);
    }
    expanded
}

fn compose_transforms(
    transforms: &[ResolvedBlockPersistenceTransform],
) -> Result<Option<ResolvedBlockPersistenceTransform>, DeviceError> {
    let Some(first) = transforms.first().copied() else {
        return Ok(None);
    };
    let mut composed = first;
    for transform in &transforms[1..] {
        if transform.ordering_group != composed.ordering_group
            || (transform.ordering != BlockPersistenceOrdering::Preserve
                && composed.ordering != BlockPersistenceOrdering::Preserve
                && transform.ordering != composed.ordering)
        {
            return Err(invalid("conflicting persistence-order transformations"));
        }
        if composed.ordering == BlockPersistenceOrdering::Preserve {
            composed.ordering = transform.ordering;
        }
        composed.delay_nanos = composed
            .delay_nanos
            .checked_add(transform.delay_nanos)
            .ok_or_else(|| invalid("persistence transformation delay overflow"))?;
        composed.preserve_barriers |= transform.preserve_barriers;
    }
    Ok(Some(composed))
}

fn persistence_rank(
    group: Option<[u8; 32]>,
    sequence: u64,
    fragment: BlockWriteFragmentId,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.block-persistence-rank.v1\0");
    hasher.update(&group.unwrap_or([0; 32]));
    hasher.update(&sequence.to_be_bytes());
    hasher.update(&fragment.request_id.to_be_bytes());
    hasher.update(&fragment.fragment_index.to_be_bytes());
    hasher.update(&fragment.start.to_be_bytes());
    hasher.update(&fragment.length.to_be_bytes());
    *hasher.finalize().as_bytes()
}

const fn ordering_tag(ordering: BlockPersistenceOrdering) -> u8 {
    match ordering {
        BlockPersistenceOrdering::Preserve => 0,
        BlockPersistenceOrdering::ReverseReady => 1,
        BlockPersistenceOrdering::DescendingRange => 2,
        BlockPersistenceOrdering::KeyedPermutation => 3,
    }
}

fn ranges_overlap(left_start: u64, left_length: u64, right_start: u64, right_length: u64) -> bool {
    left_start < right_start.saturating_add(right_length)
        && right_start < left_start.saturating_add(left_length)
}

fn invalid(reason: &'static str) -> DeviceError {
    DeviceError::InvalidBlockFaultDirective { reason }
}

#[cfg(test)]
mod tests {
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
}
