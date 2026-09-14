//! Hierarchy-aware placement constraints and pure candidate evaluation.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDigest, Revision, SandboxId,
};

use super::graph::SandboxTreeV1;

/// Maximum hard hierarchy constraints in one placement request.
pub const MAXIMUM_HIERARCHY_PLACEMENT_CONSTRAINTS: usize = 4_096;
/// Maximum existing placements supplied to one evaluation.
pub const MAXIMUM_HIERARCHY_PLACEMENTS: usize = 65_536;

/// Binds one placement peer to its complete current assignment fence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PlacementPeerV1 {
    sandbox: SandboxId,
    desired_generation: DesiredGeneration,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
}

impl PlacementPeerV1 {
    /// Constructs one specified live placement peer.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyPlacementError::UnspecifiedIdentity`] for zero input.
    pub fn new(
        sandbox: SandboxId,
        desired_generation: DesiredGeneration,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
    ) -> Result<Self, HierarchyPlacementError> {
        if sandbox.as_bytes() == &[0; 16]
            || desired_generation.get() == 0
            || incarnation.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
        {
            return Err(HierarchyPlacementError::UnspecifiedIdentity);
        }
        Ok(Self {
            sandbox,
            desired_generation,
            incarnation,
            assignment_epoch,
        })
    }

    /// Returns the peer sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the peer desired generation.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the peer runtime incarnation.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the peer assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(self) -> AssignmentEpoch {
        self.assignment_epoch
    }
}

/// Selects one closed hierarchy-aware placement relationship.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HierarchyPlacementConstraintV1 {
    /// Requires the subject and target to share one node.
    CoLocate(PlacementPeerV1),
    /// Requires the subject and target to occupy different nodes.
    Separate(PlacementPeerV1),
    /// Requires the target to be a direct sibling of the subject.
    DirectSibling(PlacementPeerV1),
    /// Requires the target to remain in the subject's project.
    SameProject(PlacementPeerV1),
}

impl HierarchyPlacementConstraintV1 {
    fn target(self) -> PlacementPeerV1 {
        match self {
            Self::CoLocate(target)
            | Self::Separate(target)
            | Self::DirectSibling(target)
            | Self::SameProject(target) => target,
        }
    }
}

/// Stores one bounded canonical constraint set for a sandbox generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HierarchyPlacementPolicyV1 {
    tree_generation: Revision,
    sandbox: SandboxId,
    desired_generation: DesiredGeneration,
    incarnation: IncarnationId,
    current_node: NodeId,
    candidate_node: NodeId,
    current_assignment_epoch: AssignmentEpoch,
    next_assignment_epoch: AssignmentEpoch,
    constraints: Vec<HierarchyPlacementConstraintV1>,
}

impl HierarchyPlacementPolicyV1 {
    /// Constructs one closed placement policy.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyPlacementError`] for zero identities, excessive or
    /// noncanonical constraints, self-reference, or contradictory node rules.
    pub fn new(
        tree_generation: Revision,
        sandbox: SandboxId,
        desired_generation: DesiredGeneration,
        incarnation: IncarnationId,
        current_node: NodeId,
        candidate_node: NodeId,
        current_assignment_epoch: AssignmentEpoch,
        next_assignment_epoch: AssignmentEpoch,
        constraints: Vec<HierarchyPlacementConstraintV1>,
    ) -> Result<Self, HierarchyPlacementError> {
        if tree_generation.get() == 0
            || sandbox.as_bytes() == &[0; 16]
            || desired_generation.get() == 0
            || incarnation.as_bytes() == &[0; 16]
            || current_node.as_bytes() == &[0; 16]
            || candidate_node.as_bytes() == &[0; 16]
            || current_assignment_epoch.get() == 0
            || next_assignment_epoch.get() == 0
        {
            return Err(HierarchyPlacementError::UnspecifiedIdentity);
        }
        if current_assignment_epoch
            .checked_next()
            .map_err(|_| HierarchyPlacementError::AssignmentEpochOverflow)?
            != next_assignment_epoch
        {
            return Err(HierarchyPlacementError::NonSuccessorAssignmentEpoch);
        }
        if constraints.len() > MAXIMUM_HIERARCHY_PLACEMENT_CONSTRAINTS
            || !constraints.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(HierarchyPlacementError::ConstraintsNotCanonical);
        }
        if constraints
            .iter()
            .any(|constraint| constraint.target().sandbox() == sandbox)
        {
            return Err(HierarchyPlacementError::SelfConstraint);
        }

        for constraint in &constraints {
            let target = constraint.target();
            let colocated = constraints.contains(&HierarchyPlacementConstraintV1::CoLocate(target));
            let separated = constraints.contains(&HierarchyPlacementConstraintV1::Separate(target));
            if colocated && separated {
                return Err(HierarchyPlacementError::ContradictoryConstraint);
            }
        }
        Ok(Self {
            tree_generation,
            sandbox,
            desired_generation,
            incarnation,
            current_node,
            candidate_node,
            current_assignment_epoch,
            next_assignment_epoch,
            constraints,
        })
    }

    /// Returns the exact project-tree snapshot evaluated by the policy.
    #[must_use]
    pub const fn tree_generation(&self) -> Revision {
        self.tree_generation
    }

    /// Returns the sandbox being placed.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the exact incarnation being placed.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the subject's currently observed node.
    #[must_use]
    pub const fn current_node(&self) -> NodeId {
        self.current_node
    }

    /// Returns the candidate node being evaluated.
    #[must_use]
    pub const fn candidate_node(&self) -> NodeId {
        self.candidate_node
    }

    /// Returns the subject assignment epoch observed before placement.
    #[must_use]
    pub const fn current_assignment_epoch(&self) -> AssignmentEpoch {
        self.current_assignment_epoch
    }

    /// Returns the mandatory successor assignment epoch.
    #[must_use]
    pub const fn next_assignment_epoch(&self) -> AssignmentEpoch {
        self.next_assignment_epoch
    }

    /// Returns the canonical hard constraints.
    #[must_use]
    pub fn constraints(&self) -> &[HierarchyPlacementConstraintV1] {
        &self.constraints
    }

    fn subject_peer(&self) -> PlacementPeerV1 {
        PlacementPeerV1 {
            sandbox: self.sandbox,
            desired_generation: self.desired_generation,
            incarnation: self.incarnation,
            assignment_epoch: self.current_assignment_epoch,
        }
    }
}

/// Records one existing generation-fenced node placement observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HierarchyPlacementObservationV1 {
    peer: PlacementPeerV1,
    node: NodeId,
    observation_set_commitment: ObjectDigest,
    observation_commitment: ObjectDigest,
}

impl HierarchyPlacementObservationV1 {
    /// Creates an observation only after a trusted assignment adapter verifies it.
    pub(crate) fn from_verified_parts(
        peer: PlacementPeerV1,
        node: NodeId,
        observation_set_commitment: ObjectDigest,
        observation_commitment: ObjectDigest,
    ) -> Self {
        Self {
            peer,
            node,
            observation_set_commitment,
            observation_commitment,
        }
    }

    /// Returns the observed sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.peer.sandbox()
    }

    /// Returns the complete observed assignment fence.
    #[must_use]
    pub const fn peer(self) -> PlacementPeerV1 {
        self.peer
    }

    /// Returns its observed node.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the shared current-observation set commitment.
    #[must_use]
    pub const fn observation_set_commitment(self) -> ObjectDigest {
        self.observation_set_commitment
    }

    /// Returns the opaque commitment to the authenticated current observation.
    #[must_use]
    pub const fn observation_commitment(self) -> ObjectDigest {
        self.observation_commitment
    }
}

/// Records the deterministic result for one candidate node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HierarchyPlacementDecisionV1 {
    /// The candidate satisfies all hard hierarchy constraints.
    Eligible,
    /// The subject generation no longer matches the tree.
    StaleSubject,
    /// Subject or target observations are absent, stale, or from mixed sets.
    IncompleteObservation,
    /// A direct-sibling or project relationship is false.
    RelationshipMismatch,
    /// A co-location constraint selects a different node.
    AffinityMismatch,
    /// An anti-affinity constraint already occupies the candidate node.
    AntiAffinityMismatch,
}

/// Evaluates one candidate against exact tree and placement observations.
///
/// Observations exactly cover the subject and every relevant target under one
/// authenticated observation-set commitment. Duplicate, mixed-snapshot, or
/// stale facts fail closed. The result is scheduling advice and grants no
/// assignment or ownership authority.
///
/// # Errors
///
/// Returns [`HierarchyPlacementError`] for malformed observations, an unknown
/// subject, or a constraint target outside the supplied project tree.
pub fn evaluate_hierarchy_placement(
    tree: &SandboxTreeV1,
    policy: &HierarchyPlacementPolicyV1,
    observations: &[HierarchyPlacementObservationV1],
) -> Result<HierarchyPlacementDecisionV1, HierarchyPlacementError> {
    if observations.len() > MAXIMUM_HIERARCHY_PLACEMENTS
        || !observations
            .windows(2)
            .all(|pair| pair[0].sandbox() < pair[1].sandbox())
    {
        return Err(HierarchyPlacementError::ObservationsNotCanonical);
    }

    if tree.tree_generation() != policy.tree_generation() {
        return Ok(HierarchyPlacementDecisionV1::StaleSubject);
    }
    let subject = tree
        .record(policy.sandbox())
        .ok_or(HierarchyPlacementError::UnknownSandbox)?;
    if subject.desired_generation() != policy.desired_generation()
        || subject.incarnation() != Some(policy.incarnation())
    {
        return Ok(HierarchyPlacementDecisionV1::StaleSubject);
    }
    let observations: BTreeMap<_, _> = observations
        .iter()
        .copied()
        .map(|observation| (observation.sandbox(), observation))
        .collect();
    let observation_set = observations
        .values()
        .next()
        .map(|observation| observation.observation_set_commitment());
    if observations.values().any(|observation| {
        observation.node().as_bytes() == &[0; 16]
            || observation.observation_set_commitment().as_bytes() == &[0; 32]
            || Some(observation.observation_set_commitment()) != observation_set
            || observation.observation_commitment().as_bytes() == &[0; 32]
    }) {
        return Err(HierarchyPlacementError::UnspecifiedIdentity);
    }

    let mut required_targets: BTreeSet<_> = policy
        .constraints()
        .iter()
        .map(|constraint| constraint.target().sandbox())
        .collect();
    required_targets.insert(policy.sandbox());
    let observed_targets: BTreeSet<_> = observations.keys().copied().collect();
    if required_targets != observed_targets {
        return Ok(HierarchyPlacementDecisionV1::IncompleteObservation);
    }
    let subject_observation = observations
        .get(&policy.sandbox())
        .ok_or(HierarchyPlacementError::ObservationsNotCanonical)?;
    if subject_observation.peer() != policy.subject_peer()
        || subject_observation.node() != policy.current_node()
    {
        return Ok(HierarchyPlacementDecisionV1::StaleSubject);
    }

    for constraint in policy.constraints() {
        let target = tree
            .record(constraint.target().sandbox())
            .ok_or(HierarchyPlacementError::UnknownConstraintTarget)?;
        let observation = observations
            .get(&target.sandbox())
            .ok_or(HierarchyPlacementError::ObservationsNotCanonical)?;
        if observation.peer() != constraint.target()
            || target.desired_generation() != constraint.target().desired_generation()
            || target.incarnation() != Some(constraint.target().incarnation())
        {
            return Ok(HierarchyPlacementDecisionV1::IncompleteObservation);
        }
        match constraint {
            HierarchyPlacementConstraintV1::SameProject(_) => {}
            HierarchyPlacementConstraintV1::DirectSibling(_) => {
                if subject.parent() != target.parent() {
                    return Ok(HierarchyPlacementDecisionV1::RelationshipMismatch);
                }
            }
            HierarchyPlacementConstraintV1::CoLocate(_) => {
                if observation.node() != policy.candidate_node() {
                    return Ok(HierarchyPlacementDecisionV1::AffinityMismatch);
                }
            }
            HierarchyPlacementConstraintV1::Separate(_) => {
                if observation.node() == policy.candidate_node() {
                    return Ok(HierarchyPlacementDecisionV1::AntiAffinityMismatch);
                }
            }
        }
    }
    Ok(HierarchyPlacementDecisionV1::Eligible)
}

/// Reports malformed hierarchy-aware placement input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HierarchyPlacementError {
    /// An identity or generation uses its zero sentinel.
    #[error("hierarchy placement contains an unspecified identity")]
    UnspecifiedIdentity,
    /// The current assignment epoch cannot advance without overflow.
    #[error("hierarchy placement assignment epoch is exhausted")]
    AssignmentEpochOverflow,
    /// The proposed assignment epoch is not the exact successor.
    #[error("hierarchy placement assignment epoch is not the exact successor")]
    NonSuccessorAssignmentEpoch,
    /// Constraints are oversized, duplicated, or unordered.
    #[error("hierarchy placement constraints are not canonical")]
    ConstraintsNotCanonical,
    /// Existing placement facts are oversized, duplicated, or unordered.
    #[error("hierarchy placement observations are not canonical")]
    ObservationsNotCanonical,
    /// A policy constrains its own sandbox.
    #[error("hierarchy placement cannot constrain a sandbox against itself")]
    SelfConstraint,
    /// The same target is both co-located and separated.
    #[error("hierarchy placement contains contradictory node constraints")]
    ContradictoryConstraint,
    /// The subject is absent from the validated tree.
    #[error("hierarchy placement subject is absent")]
    UnknownSandbox,
    /// A relationship target is absent from the validated project tree.
    #[error("hierarchy placement target is absent from the project")]
    UnknownConstraintTarget,
}
