//! Persistence graph identities, transformations, and checkpoint state.

use super::*;

/// Stable identity of one atomic write fragment.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBlockPersistenceTransform {
    /// Stable resolved binding-action identity.
    pub contributor: [u8; 32],
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// Group-scoped transformed slot in the global normal writeback order.
    pub transformed_writeback_sequence: u64,
    /// Earliest virtual nanosecond at which service may select this node.
    pub persistence_deadline_nanos: Option<u64>,
    /// Whether a flush/FUA/transaction barrier contributed an immutable edge.
    pub barrier_protected: bool,
    pub(super) ordering_group: Option<[u8; 32]>,
    pub(super) ordering: BlockPersistenceOrdering,
    pub(super) keyed_rank: [u8; 32],
}

/// Before/after identity of the most recently admitted graph transformation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockPersistenceTransformationEvidence {
    /// Original guest request whose fragments were admitted.
    pub request_id: u32,
    /// First admitted global fragment sequence.
    pub first_sequence: u64,
    /// Exclusive admitted global fragment sequence frontier.
    pub sequence_frontier: u64,
    /// Canonically sorted exact binding-action identities that contributed.
    pub contributors: Vec<[u8; 32]>,
    /// Graph digest before admitting and transforming the fragments.
    pub before: [u8; 32],
    /// Graph digest after the complete atomic admission.
    pub after: [u8; 32],
}

/// Complete bounded persistence DAG continuation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockPersistenceGraph {
    pub(super) nodes: BTreeMap<u64, BlockPersistenceNode>,
    pub(super) edge_count: usize,
    pub(super) edge_limit: usize,
    pub(super) next_writeback_sequence: u64,
    pub(super) transformation_evidence: Vec<BlockPersistenceTransformationEvidence>,
}
