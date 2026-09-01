//! Persistence graph admission, ordering, completion, and evidence.

use super::helpers::*;
use super::*;

impl Default for BlockPersistenceGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockPersistenceGraph {
    /// Validates a resolved transformation set without mutating graph state.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for conflicting groups/rules or a persistence
    /// deadline that cannot be represented.
    pub fn validate_transforms(
        transforms: &[ResolvedBlockPersistenceTransform],
        admitted_nanos: u64,
    ) -> Result<(), DeviceError> {
        if let Some(transform) = compose_transforms(transforms)? {
            admitted_nanos
                .checked_add(transform.delay_nanos)
                .ok_or_else(|| invalid("persistence deadline overflow"))?;
        }
        Ok(())
    }

    /// Creates an empty persistence graph.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edge_count: 0,
            edge_limit: HARD_BLOCK_PERSISTENCE_EDGES,
            next_writeback_sequence: 0,
            transformation_evidence: Vec::new(),
        }
    }

    /// Creates an empty graph with an admitted per-device edge ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when `edge_limit` is zero or exceeds the hard
    /// implementation ceiling.
    pub fn with_edge_limit(edge_limit: usize) -> Result<Self, DeviceError> {
        if edge_limit == 0 || edge_limit > HARD_BLOCK_PERSISTENCE_EDGES {
            return Err(invalid("persistence dependency limit is invalid"));
        }
        Ok(Self {
            edge_limit,
            ..Self::new()
        })
    }

    /// Returns all live nodes in controller-sequence order.
    #[must_use]
    pub const fn nodes(&self) -> &BTreeMap<u64, BlockPersistenceNode> {
        &self.nodes
    }

    /// Returns the admitted per-device dependency-edge ceiling.
    #[must_use]
    pub const fn edge_limit(&self) -> usize {
        self.edge_limit
    }

    /// Returns every unconsumed atomic graph-transformation evidence record.
    #[must_use]
    pub fn transformation_evidence(&self) -> &[BlockPersistenceTransformationEvidence] {
        &self.transformation_evidence
    }

    /// Drains transformation evidence after the event log has retained it.
    pub fn drain_transformation_evidence(&mut self) -> Vec<BlockPersistenceTransformationEvidence> {
        std::mem::take(&mut self.transformation_evidence)
    }

    /// Returns the canonical digest of the complete live graph continuation.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.block-persistence-graph.v1\0");
        hasher.update(
            &u64::try_from(self.edge_limit)
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(&self.next_writeback_sequence.to_be_bytes());
        for node in self.nodes.values() {
            hasher.update(&node.sequence.to_be_bytes());
            hasher.update(&node.fragment.request_id.to_be_bytes());
            hasher.update(&node.fragment.fragment_index.to_be_bytes());
            hasher.update(&node.fragment.start.to_be_bytes());
            hasher.update(&node.fragment.length.to_be_bytes());
            hasher.update(&node.dependency_depth.to_be_bytes());
            hasher.update(&node.writeback_sequence.to_be_bytes());
            hasher.update(&node.transformed_writeback_sequence.to_be_bytes());
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
            || self.edge_limit == 0
            || self.edge_limit > HARD_BLOCK_PERSISTENCE_EDGES
            || self.edge_count > self.edge_limit
            || self.transformation_evidence.len() > HARD_BLOCK_PERSISTENCE_EVIDENCE
            || self.transformation_evidence.iter().any(|evidence| {
                evidence.first_sequence >= evidence.sequence_frontier
                    || evidence.contributors.is_empty()
                    || evidence
                        .contributors
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
            })
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
                    || node.transformed_writeback_sequence >= self.next_writeback_sequence
                    || node.dependencies.iter().any(|dependency| {
                        *dependency >= node.sequence || !self.nodes.contains_key(dependency)
                    })
            })
        {
            return Err(invalid(
                "restored persistence graph violates bounds or ownership",
            ));
        }
        let transformed_slots = self
            .nodes
            .values()
            .map(|node| node.transformed_writeback_sequence)
            .collect::<BTreeSet<_>>();
        if transformed_slots.len() != self.nodes.len() {
            return Err(invalid(
                "restored persistence graph repeats a transformed ordering slot",
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
        self.admit_request_with_barrier(fragments, admitted_nanos, transforms, None)
    }

    /// Atomically admits fragments and an optional preceding flush frontier.
    ///
    /// When the composed transformation preserves barriers, the request's
    /// first fragment depends on every still-live node below `barrier_frontier`.
    /// A transformation that explicitly disables barrier preservation omits
    /// those edges while retaining overlap and intra-request dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] under the same conditions as
    /// [`Self::admit_request`], or when the barrier frontier exceeds the first
    /// admitted sequence.
    pub fn admit_request_with_barrier(
        &mut self,
        fragments: &[(u64, BlockWriteFragmentId)],
        admitted_nanos: u64,
        transforms: &[ResolvedBlockPersistenceTransform],
        barrier_frontier: Option<u64>,
    ) -> Result<BlockPersistenceTransformationEvidence, DeviceError> {
        let before = self.digest();
        if fragments.is_empty() {
            let evidence = BlockPersistenceTransformationEvidence {
                request_id: 0,
                first_sequence: 0,
                sequence_frontier: 0,
                contributors: Vec::new(),
                before,
                after: before,
            };
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
        if barrier_frontier.is_some_and(|frontier| frontier > fragments[0].0) {
            return Err(invalid(
                "persistence barrier frontier exceeds the admitted request sequence",
            ));
        }
        if let Some(transform) = transform
            && next.nodes.values().any(|node| {
                node.ordering_group == Some(transform.ordering_group)
                    && node.ordering != transform.ordering
            })
        {
            return Err(invalid(
                "persistence ordering group changes its live ordering rule",
            ));
        }
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
            let barrier_protected = prior_fragment.is_none()
                && barrier_frontier.is_some()
                && transform.is_none_or(|transform| transform.preserve_barriers);
            if barrier_protected && let Some(frontier) = barrier_frontier {
                dependencies.extend(next.nodes.keys().copied().filter(|prior| *prior < frontier));
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
            if next.edge_count > next.edge_limit {
                return Err(invalid(
                    "persistence dependency graph exceeds its configured edge bound",
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
                    transformed_writeback_sequence: writeback_sequence,
                    persistence_deadline_nanos,
                    barrier_protected,
                    ordering_group,
                    ordering,
                    keyed_rank,
                },
            );
            prior_fragment = Some(*sequence);
        }
        if let Some(transform) = transform {
            next.recompute_group_slots(transform.ordering_group)?;
        }
        next.validate()?;
        let after = next.digest();
        let first_sequence = fragments[0].0;
        let sequence_frontier = fragments
            .last()
            .and_then(|(sequence, _fragment)| sequence.checked_add(1))
            .ok_or_else(|| invalid("persistence evidence sequence frontier overflow"))?;
        let mut contributors = transforms
            .iter()
            .map(|transform| transform.contributor)
            .collect::<Vec<_>>();
        contributors.sort_unstable();
        contributors.dedup();
        let evidence = BlockPersistenceTransformationEvidence {
            request_id: fragments[0].1.request_id,
            first_sequence,
            sequence_frontier,
            contributors,
            before,
            after,
        };
        if !transforms.is_empty() {
            if next.transformation_evidence.len() == HARD_BLOCK_PERSISTENCE_EVIDENCE {
                return Err(invalid(
                    "persistence transformation evidence exceeds its hard bound",
                ));
            }
            next.transformation_evidence.push(evidence.clone());
        }
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
        let evidence = BlockPersistenceTransformationEvidence {
            request_id: next.nodes[&sequence].fragment.request_id,
            first_sequence: sequence,
            sequence_frontier: sequence
                .checked_add(1)
                .ok_or_else(|| invalid("persistence evidence sequence frontier overflow"))?,
            contributors: Vec::new(),
            before,
            after,
        };
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

    /// Returns whether one live node is dependency-ready and its delay elapsed.
    #[must_use]
    pub fn is_ready_at(&self, sequence: u64, now_nanos: u64) -> bool {
        self.nodes.get(&sequence).is_some_and(|node| {
            node.dependencies.is_empty()
                && node
                    .persistence_deadline_nanos
                    .is_none_or(|deadline| deadline <= now_nanos)
        })
    }

    /// Returns one node's modeled persistence deadline.
    #[must_use]
    pub fn deadline_nanos(&self, sequence: u64) -> Option<u64> {
        self.nodes
            .get(&sequence)
            .and_then(|node| node.persistence_deadline_nanos)
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

    fn recompute_group_slots(&mut self, group: [u8; 32]) -> Result<(), DeviceError> {
        let members = self
            .nodes
            .values()
            .filter(|node| node.ordering_group == Some(group))
            .map(|node| node.sequence)
            .collect::<Vec<_>>();
        let mut slots = members
            .iter()
            .filter_map(|sequence| self.nodes.get(sequence))
            .map(|node| node.writeback_sequence)
            .collect::<Vec<_>>();
        slots.sort_unstable();
        let mut ranked = members;
        ranked.sort_by(|left, right| {
            let left = &self.nodes[left];
            let right = &self.nodes[right];
            transformation_rank(left).cmp(&transformation_rank(right))
        });
        if ranked.len() != slots.len() {
            return Err(invalid("persistence group slot accounting differs"));
        }
        for (sequence, slot) in ranked.into_iter().zip(slots) {
            self.nodes
                .get_mut(&sequence)
                .ok_or_else(|| invalid("persistence group member disappeared"))?
                .transformed_writeback_sequence = slot;
        }
        Ok(())
    }
}
