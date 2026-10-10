//! Deterministic placement over bounded node capability observations.
//!
//! Placement consumes semantic requirements, complete affinity observations,
//! and authenticated capability snapshots. The result identifies a preferred
//! node and the exact observation used to choose it. It neither reserves
//! capacity nor authorizes that node to realize the sandbox.
//! The assignment-intent adapter keeps the manifest-to-selection checks here;
//! the shared assignment model consumes only its canonical capability binding.

use std::cmp::Ordering;

use aos_sandbox_core::model::PlacementRequest;
use aos_sandbox_core::state::DesiredSandboxState;
use aos_sandbox_core::{
    AssignmentEpoch, CanonicalAssignmentManifestV1, DesiredGeneration, FeatureRef, IncarnationId,
    NodeId, ObservationSequence, ProtocolId, ResourceDimension, ResourceVector, SandboxId,
    supported_protocol_version,
};

use aos_sandbox::local_inventory::assignment::{
    AssignmentIntentV1, InvalidAssignmentModel, SelectedCapabilityBindingV1,
};
pub use aos_sandbox::local_inventory::capability::PlacementCandidateV1;
use aos_sandbox::local_inventory::capability::{
    CarrierValidatedCapabilityObservationV1, NodeAdmissionStateV1, NodeBootId, NodeBootLineageV1,
    NodeCapabilitySnapshotV1, NodeProtocolV1,
};
pub use aos_sandbox::local_inventory::AffinityPlacementV1;
pub use aos_sandbox::local_inventory::InvalidPlacementInput;

/// Maximum candidate nodes considered by one placement decision.
pub const MAX_PLACEMENT_CANDIDATES: usize = 4_096;
/// Maximum complete affinity observations supplied to one placement decision.
pub const MAX_AFFINITY_PLACEMENTS: usize = aos_sandbox::local_inventory::MAX_ASSIGNMENT_AFFINITIES;
/// Maximum required features accepted from one semantic placement request.
pub const MAX_PLACEMENT_REQUIRED_FEATURES: usize =
    aos_sandbox::local_inventory::assignment::MAX_SNAPSHOT_TRANSFER_REQUIRED_FEATURES;

/// Explains why one candidate could not satisfy placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateRejectionReasonV1 {
    /// Node admission is cordoned or draining.
    AdmissionClosed,
    /// Capability observation is from the future or older than policy permits.
    CapabilityNotFresh,
    /// Coordinator-to-node protocol semantics are incompatible.
    ProtocolIncompatible,
    /// Required local-live affinity selects another node.
    AffinityMismatch,
    /// At least one required semantic feature is absent.
    MissingFeature,
    /// Unreserved node capacity cannot cover the request.
    InsufficientCapacity,
}

/// Correlates one rejected node with its stable reason class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateRejectionV1 {
    node: NodeId,
    reason: CandidateRejectionReasonV1,
}

impl CandidateRejectionV1 {
    /// Returns the rejected node.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the first stable rejection reason.
    #[must_use]
    pub const fn reason(self) -> CandidateRejectionReasonV1 {
        self.reason
    }
}

/// Explains why placement could not select a node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementBlockReasonV1 {
    /// No node capability snapshots were supplied.
    NoCandidates,
    /// A requested local-live dependency has no current placement observation.
    AffinityUnknown,
    /// Requested local-live dependencies currently occupy different nodes.
    AffinityConflict,
    /// Every candidate failed at least one hard requirement.
    NoEligibleCandidate,
}

/// Records one deterministic node preference and the evidence it used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementSelectionV1 {
    sandbox: SandboxId,
    node: NodeId,
    capability_observation: CarrierValidatedCapabilityObservationV1,
    required_features: Vec<FeatureRef>,
    requested_resources: ResourceVector,
    projected_headroom: ResourceVector,
}

impl PlacementSelectionV1 {
    /// Constructs one assignment desired-state record.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAssignmentModel::PlacementMismatch`] when the
    /// deterministic selection names another node. The canonical manifest has
    /// already validated every assignment identity and derives its own digest.
    pub fn assignment_intent(
        &self,
        assignment: CanonicalAssignmentManifestV1,
        desired_lifecycle: DesiredSandboxState,
    ) -> Result<AssignmentIntentV1, InvalidAssignmentModel> {
        if assignment.manifest().node() != self.node()
            || assignment.manifest().sandbox() != self.sandbox()
            || assignment.manifest().reservations() != self.requested_resources()
            || assignment.manifest().required_features() != self.required_features()
        {
            return Err(InvalidAssignmentModel::PlacementMismatch);
        }

        let selected_capability =
            SelectedCapabilityBindingV1::from_observation(self.capability_observation())?;

        AssignmentIntentV1::from_canonical_binding(assignment, desired_lifecycle, selected_capability)
    }

    /// Returns the sandbox whose request was evaluated.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the preferred node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the node boot whose capability snapshot was evaluated.
    #[must_use]
    pub const fn capability_boot(&self) -> NodeBootId {
        self.capability_observation.snapshot().boot()
    }

    /// Returns the durable node boot generation evaluated by placement.
    #[must_use]
    pub const fn capability_boot_generation(&self) -> u64 {
        self.capability_observation.snapshot().boot_generation()
    }

    /// Returns the durable boot lineage used by placement.
    #[must_use]
    pub const fn capability_lineage(&self) -> NodeBootLineageV1 {
        self.capability_observation.snapshot().lineage()
    }

    /// Returns the exact capability observation sequence evaluated.
    #[must_use]
    pub const fn capability_sequence(&self) -> ObservationSequence {
        self.capability_observation.snapshot().sequence()
    }

    /// Returns the exact carrier and currentness evidence used for placement.
    #[must_use]
    pub const fn capability_observation(&self) -> &CarrierValidatedCapabilityObservationV1 {
        &self.capability_observation
    }

    /// Returns the resources evaluated by placement.
    #[must_use]
    pub const fn requested_resources(&self) -> ResourceVector {
        self.requested_resources
    }

    /// Returns the semantic features evaluated by placement.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }

    /// Returns capacity remaining if a later controller transaction reserves it.
    #[must_use]
    pub const fn projected_headroom(&self) -> ResourceVector {
        self.projected_headroom
    }
}


/// Reports either a selected node or a complete bounded placement block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlacementDecisionV1 {
    /// A deterministic candidate satisfies every hard requirement.
    Selected(PlacementSelectionV1),
    /// Placement is blocked before any reservation or assignment effect.
    Blocked {
        /// Stable block reason.
        reason: PlacementBlockReasonV1,
        /// Per-node rejections in canonical node order.
        rejections: Vec<CandidateRejectionV1>,
    },
}

/// Selects a node deterministically from complete bounded observations.
///
/// Eligible nodes are ranked by best fit: the scheduler compares post-request
/// headroom only in dimensions requested by the sandbox, in the stable resource
/// registry order, then uses node identity as the final tie-breaker. This keeps
/// placement independent from hash-map iteration and host architecture.
///
/// The selected result is advisory planning evidence. The caller must still
/// reserve capacity durably, publish the assignment, and acquire independently
/// verified ownership authority before any effect.
///
/// # Errors
///
/// Returns [`InvalidPlacementInput`] for noncanonical or oversized input, or
/// for a zero freshness interval.
pub fn place_deterministically(
    request: &PlacementRequest,
    candidates: &[PlacementCandidateV1],
    affinities: &[AffinityPlacementV1],
    coordinator_unix_seconds: u64,
    maximum_capability_age_seconds: u64,
) -> Result<PlacementDecisionV1, InvalidPlacementInput> {
    validate_inputs(
        request,
        candidates,
        affinities,
        maximum_capability_age_seconds,
    )?;

    if candidates.is_empty() {
        return Ok(PlacementDecisionV1::Blocked {
            reason: PlacementBlockReasonV1::NoCandidates,
            rejections: Vec::new(),
        });
    }

    let affinity_node = match resolve_affinity_node(request, affinities, coordinator_unix_seconds) {
        Ok(node) => node,
        Err(reason) => {
            return Ok(PlacementDecisionV1::Blocked {
                reason,
                rejections: Vec::new(),
            });
        }
    };

    let required_protocol = supported_protocol_version(ProtocolId::CoordinatorNode);
    let mut selected: Option<PlacementSelectionV1> = None;
    let mut rejections = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        let snapshot = candidate.snapshot();
        let rejection = if snapshot.admission() != NodeAdmissionStateV1::Accepting {
            Some(CandidateRejectionReasonV1::AdmissionClosed)
        } else if !is_fresh(
            candidate,
            coordinator_unix_seconds,
            maximum_capability_age_seconds,
        ) {
            Some(CandidateRejectionReasonV1::CapabilityNotFresh)
        } else if !snapshot.supports_protocol(NodeProtocolV1::CoordinatorNode, required_protocol) {
            Some(CandidateRejectionReasonV1::ProtocolIncompatible)
        } else if affinity_node.is_some_and(|node| node != snapshot.node()) {
            Some(CandidateRejectionReasonV1::AffinityMismatch)
        } else if request
            .required_features()
            .iter()
            .any(|required| !snapshot.supports_feature(required))
        {
            Some(CandidateRejectionReasonV1::MissingFeature)
        } else if projected_headroom(snapshot, request.reserved_resources()).is_none() {
            Some(CandidateRejectionReasonV1::InsufficientCapacity)
        } else {
            None
        };

        if let Some(reason) = rejection {
            rejections.push(CandidateRejectionV1 {
                node: snapshot.node(),
                reason,
            });
            continue;
        }

        let Some(headroom) = projected_headroom(snapshot, request.reserved_resources()) else {
            continue;
        };
        let proposal = PlacementSelectionV1 {
            sandbox: request.sandbox(),
            node: snapshot.node(),
            capability_observation: candidate.observation().clone(),
            required_features: request.required_features().to_vec(),
            requested_resources: request.reserved_resources(),
            projected_headroom: headroom,
        };
        if selected.as_ref().is_none_or(|current| {
            compare_selection(&proposal, current, request.reserved_resources()) == Ordering::Less
        }) {
            selected = Some(proposal);
        }
    }

    Ok(match selected {
        Some(selection) => PlacementDecisionV1::Selected(selection),
        None => PlacementDecisionV1::Blocked {
            reason: PlacementBlockReasonV1::NoEligibleCandidate,
            rejections,
        },
    })
}

fn validate_inputs(
    request: &PlacementRequest,
    candidates: &[PlacementCandidateV1],
    affinities: &[AffinityPlacementV1],
    maximum_capability_age_seconds: u64,
) -> Result<(), InvalidPlacementInput> {
    if request.sandbox().as_bytes() == &[0; 16] {
        return Err(InvalidPlacementInput::UnspecifiedIdentity);
    }
    if request.required_features().len() > MAX_PLACEMENT_REQUIRED_FEATURES {
        return Err(InvalidPlacementInput::TooManyRequiredFeatures);
    }
    aos_sandbox_core::validate_required_features(request.required_features())
        .map_err(|_| InvalidPlacementInput::UnknownRequiredFeature)?;
    if candidates.len() > MAX_PLACEMENT_CANDIDATES
        || !candidates
            .windows(2)
            .all(|pair| pair[0].snapshot().node() < pair[1].snapshot().node())
    {
        return Err(InvalidPlacementInput::CandidatesNotCanonical);
    }
    if affinities.len() > MAX_AFFINITY_PLACEMENTS
        || affinities
            .iter()
            .any(|placement| ensure_affinity_specified(placement).is_err())
        || !affinities
            .windows(2)
            .all(|pair| affinity_canonical_key(&pair[0]) < affinity_canonical_key(&pair[1]))
        || affinities
            .windows(2)
            .any(|pair| pair[0].sandbox() == pair[1].sandbox())
    {
        return Err(InvalidPlacementInput::AffinitiesNotCanonical);
    }
    if maximum_capability_age_seconds == 0 {
        return Err(InvalidPlacementInput::InvalidFreshnessLimit);
    }
    Ok(())
}

fn affinity_canonical_key(
    placement: &AffinityPlacementV1,
) -> (SandboxId, AssignmentEpoch, IncarnationId, DesiredGeneration) {
    (
        placement.sandbox(),
        placement.epoch(),
        placement.incarnation(),
        placement.desired_generation(),
    )
}

fn ensure_affinity_specified(placement: &AffinityPlacementV1) -> Result<(), InvalidPlacementInput> {
    if placement.sandbox().as_bytes() == &[0; 16]
        || placement.node().as_bytes() == &[0; 16]
        || placement.incarnation().as_bytes() == &[0; 16]
        || placement.desired_generation().get() == 0
        || placement.worker_identity_digest().as_bytes() == &[0; 32]
    {
        return Err(InvalidPlacementInput::UnspecifiedIdentity);
    }
    Ok(())
}

fn resolve_affinity_node(
    request: &PlacementRequest,
    affinities: &[AffinityPlacementV1],
    coordinator_unix_seconds: u64,
) -> Result<Option<NodeId>, PlacementBlockReasonV1> {
    let mut required_node = None;
    for sandbox in request.same_node_sandboxes() {
        let placement = affinities
            .binary_search_by_key(sandbox, |placement| placement.sandbox())
            .ok()
            .map(|index| &affinities[index]);
        let Some(placement) = placement else {
            return Err(PlacementBlockReasonV1::AffinityUnknown);
        };
        if !placement.is_current_at(coordinator_unix_seconds) {
            return Err(PlacementBlockReasonV1::AffinityUnknown);
        }
        if required_node.is_some_and(|node| node != placement.node()) {
            return Err(PlacementBlockReasonV1::AffinityConflict);
        }
        required_node = Some(placement.node());
    }
    Ok(required_node)
}

fn is_fresh(
    candidate: &PlacementCandidateV1,
    coordinator_unix_seconds: u64,
    maximum_age_seconds: u64,
) -> bool {
    coordinator_unix_seconds
        .checked_sub(candidate.received_at_unix_seconds())
        .is_some_and(|age| age <= maximum_age_seconds)
        && candidate
            .observation()
            .is_current_at(coordinator_unix_seconds)
}

fn projected_headroom(
    candidate: &NodeCapabilitySnapshotV1,
    request: ResourceVector,
) -> Option<ResourceVector> {
    candidate.available().checked_sub(request).ok()
}

fn compare_selection(
    left: &PlacementSelectionV1,
    right: &PlacementSelectionV1,
    request: ResourceVector,
) -> Ordering {
    for dimension in ResourceDimension::ALL {
        if request.get(dimension) == 0 {
            continue;
        }
        let ordering = left
            .projected_headroom
            .get(dimension)
            .cmp(&right.projected_headroom.get(dimension));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.node.cmp(&right.node)
}
