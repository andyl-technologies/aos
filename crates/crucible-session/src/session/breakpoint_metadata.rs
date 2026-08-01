//! Deterministic host predicate and symbol metadata for session breakpoints.
//!
//! The session actor evaluates breakpoints only at scheduler-owned virtual-time
//! boundaries. Host integrations therefore supply data-only truth entries and
//! symbol resolutions up front; no wall clock, live process state, or unordered
//! host callback can enter breakpoint evaluation.

use super::*;

/// Canonical key for one named host predicate at a session evaluation point.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BreakpointNamedPredicateKey {
    at: VirtualTime,
    name: String,
    nodes: Vec<NodeId>,
}

impl BreakpointNamedPredicateKey {
    /// Builds one predicate key from virtual time, name, and declared nodes.
    #[must_use]
    pub fn new(at: VirtualTime, name: impl Into<String>, nodes: Vec<NodeId>) -> Self {
        Self {
            at,
            name: name.into(),
            nodes,
        }
    }

    /// Returns the scheduler-owned evaluation time.
    #[must_use]
    pub const fn at(&self) -> VirtualTime {
        self.at
    }

    /// Returns the stable predicate name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared node references in authored order.
    #[must_use]
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }
}

/// Data-only host metadata visible to breakpoint evaluation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BreakpointHostMetadata {
    named_predicates: BTreeMap<BreakpointNamedPredicateKey, bool>,
    resolved_code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    resolved_mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
}

impl BreakpointHostMetadata {
    /// Builds empty breakpoint host metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one named-predicate truth at an exact virtual-time boundary.
    #[must_use]
    pub fn with_named_predicate(mut self, key: BreakpointNamedPredicateKey, value: bool) -> Self {
        self.insert_named_predicate(key, value);
        self
    }

    /// Inserts one named-predicate truth at an exact virtual-time boundary.
    pub fn insert_named_predicate(&mut self, key: BreakpointNamedPredicateKey, value: bool) {
        self.named_predicates.insert(key, value);
    }

    /// Adds one host-resolved executable code point.
    #[must_use]
    pub fn with_resolved_code_point(
        mut self,
        node: NodeId,
        point: CodePoint,
        resolved: ResolvedCodePoint,
    ) -> Self {
        self.insert_resolved_code_point(node, point, resolved);
        self
    }

    /// Inserts one host-resolved executable code point.
    pub fn insert_resolved_code_point(
        &mut self,
        node: NodeId,
        point: CodePoint,
        resolved: ResolvedCodePoint,
    ) {
        self.resolved_code_points.insert((node, point), resolved);
    }

    /// Adds one host-resolved memory or register place.
    #[must_use]
    pub fn with_resolved_mem_place(
        mut self,
        node: NodeId,
        place: MemPlace,
        resolved: ResolvedMemPlace,
    ) -> Self {
        self.insert_resolved_mem_place(node, place, resolved);
        self
    }

    /// Inserts one host-resolved memory or register place.
    pub fn insert_resolved_mem_place(
        &mut self,
        node: NodeId,
        place: MemPlace,
        resolved: ResolvedMemPlace,
    ) {
        self.resolved_mem_places.insert((node, place), resolved);
    }

    /// Returns the declared truth for one exact predicate key.
    #[must_use]
    pub fn named_predicate(&self, key: &BreakpointNamedPredicateKey) -> Option<bool> {
        self.named_predicates.get(key).copied()
    }

    pub(super) fn oracle_at(&self, at: VirtualTime) -> BreakpointHostOracle<'_> {
        BreakpointHostOracle { metadata: self, at }
    }

    pub(super) fn resolved_code_points(
        &self,
    ) -> impl Iterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)> + '_ {
        self.resolved_code_points
            .iter()
            .map(|(key, value)| (key.clone(), *value))
    }

    pub(super) fn resolved_mem_places(
        &self,
    ) -> impl Iterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)> + '_ {
        self.resolved_mem_places
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
    }
}

pub(super) struct BreakpointHostOracle<'metadata> {
    metadata: &'metadata BreakpointHostMetadata,
    at: VirtualTime,
}

impl ConditionLeafOracle for BreakpointHostOracle<'_> {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, nodes } => self
                .metadata
                .named_predicate(&BreakpointNamedPredicateKey::new(
                    self.at,
                    name,
                    nodes.to_vec(),
                ))
                .unwrap_or(false),
            ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

impl<L> Engine<L> {
    /// Adds deterministic host predicate and symbol metadata for breakpoints.
    #[must_use]
    pub fn with_breakpoint_host_metadata(mut self, metadata: BreakpointHostMetadata) -> Self {
        self.breakpoint_host_metadata = metadata;
        self
    }

    /// Returns the deterministic host metadata used by breakpoint evaluation.
    #[must_use]
    pub const fn breakpoint_host_metadata(&self) -> &BreakpointHostMetadata {
        &self.breakpoint_host_metadata
    }

    pub(super) fn breakpoint_condition_prefix(
        &self,
        event_log_entries: &[SchedulerEventLogEntry],
        emitted_event_log_entries: usize,
    ) -> Result<Option<ConditionEventLogPrefix>, SessionError> {
        if emitted_event_log_entries == 0 {
            return ConditionEventLogPrefix::from_scheduler_event_log_entries_with_evaluation_boundary(
                event_log_entries.to_vec(),
                usize_to_u64(self.event_log_len),
                self.frontier,
                SchedulerEvaluationBoundaryKind::Quantum,
            )
            .map(Some)
            .map_err(|error| SessionError::BreakpointConditionPrefix {
                reason: error.to_string(),
            });
        }

        ConditionEventLogPrefix::from_scheduler_event_log_entries(event_log_entries.to_vec())
            .map(Some)
            .map_err(|error| SessionError::BreakpointConditionPrefix {
                reason: error.to_string(),
            })
    }
}
