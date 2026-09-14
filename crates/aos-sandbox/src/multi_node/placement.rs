//! Deterministic placement over bounded node capability observations.
//!
//! Placement consumes semantic requirements, complete affinity observations,
//! and authenticated capability snapshots. The result identifies a preferred
//! node and the exact observation used to choose it. It neither reserves
//! capacity nor authorizes that node to realize the sandbox.

use std::cmp::Ordering;

use aos_sandbox_core::model::PlacementRequest;
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, NodeId, ObjectDigest,
    ObservationSequence, ProtocolId, ResourceDimension, ResourceVector, SandboxId,
    supported_protocol_version,
};

use super::assignment::{NodeAssignmentObservationV1, VerifiedGuardianStateV1};
use super::capability::{
    CarrierValidatedCapabilityObservationV1, NodeAdmissionStateV1, NodeBootId, NodeBootLineageV1,
    NodeCapabilitySnapshotV1, NodeProtocolV1,
};
use super::evidence_authority::VerifierEvidenceGrantV1;
use super::journal::{JournalEffectStateV1, MultiNodeJournalDomainV1, ProtectedJournalRecordV1};

/// Maximum candidate nodes considered by one placement decision.
pub const MAX_PLACEMENT_CANDIDATES: usize = 4_096;
/// Maximum complete affinity observations supplied to one placement decision.
pub const MAX_AFFINITY_PLACEMENTS: usize = 4_096;
/// Maximum required features accepted from one semantic placement request.
pub const MAX_PLACEMENT_REQUIRED_FEATURES: usize = 64;

/// Couples one node snapshot to its authenticated controller receipt time.
///
/// Receipt time is placement freshness evidence and is deliberately outside
/// the node snapshot's sequence identity. It is not an ownership lease clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementCandidateV1 {
    observation: CarrierValidatedCapabilityObservationV1,
}

impl PlacementCandidateV1 {
    /// Constructs one candidate after authenticated snapshot receipt.
    #[must_use]
    pub(super) fn from_authenticated_observation(
        observation: CarrierValidatedCapabilityObservationV1,
    ) -> Self {
        Self { observation }
    }

    /// Returns the complete node capability snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &NodeCapabilitySnapshotV1 {
        self.observation.snapshot()
    }

    /// Returns the opaque carrier-validated observation.
    #[must_use]
    pub const fn observation(&self) -> &CarrierValidatedCapabilityObservationV1 {
        &self.observation
    }

    /// Returns the controller-recorded authenticated receipt time.
    #[must_use]
    pub const fn received_at_unix_seconds(&self) -> u64 {
        self.observation.authenticated_at_unix_seconds()
    }
}

/// Records the controller-observed node for one affinity dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinityPlacementV1 {
    observation: NodeAssignmentObservationV1,
    worker_identity_digest: ObjectDigest,
    liveness_record: ProtectedJournalRecordV1,
}

impl AffinityPlacementV1 {
    /// Constructs one non-authorizing affinity observation inside the liveness verifier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPlacementInput::AffinityNotLive`] unless the exact
    /// worker, assignment generation, armed Guardian, protected durability,
    /// carrier binding, and currentness all agree.
    pub(super) fn from_liveness_verifier(
        grant: VerifierEvidenceGrantV1<(
            NodeAssignmentObservationV1,
            ObjectDigest,
            ProtectedJournalRecordV1,
            u64,
        )>,
    ) -> Result<Self, InvalidPlacementInput> {
        let (
            (observation, worker_identity_digest, liveness_record, coordinator_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let liveness_digest = affinity_liveness_digest(&observation, worker_identity_digest);
        let durable_affinity = liveness_record
            .record()
            .state_payload()
            .assignment_state()
            .and_then(|state| {
                state
                    .affinities()
                    .iter()
                    .find(|affinity| affinity.sandbox == observation.sandbox())
            });
        if worker_identity_digest.as_bytes() == &[0; 32]
            || verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context.node() != observation.node()
            || verifier_context.lineage() != observation.lineage()
            || !verifier_context.is_current_at(coordinator_unix_seconds)
            || observation.phase() != aos_sandbox_core::state::AssignmentPhase::Active
            || !observation
                .context()
                .is_current_at(coordinator_unix_seconds)
            || observation.observed_at_unix_seconds() > coordinator_unix_seconds
            || !observation.authority().is_some_and(|authority| {
                authority.guardian_state() == VerifiedGuardianStateV1::Armed
                    && authority.is_current_at(coordinator_unix_seconds)
            })
            || liveness_record.record().domain() != MultiNodeJournalDomainV1::Assignment
            || liveness_record.record().payload_digest() != observation.assignment_digest()
            || liveness_record.record().effect_state() != JournalEffectStateV1::Committed
            || liveness_record.record().effect_digest() != liveness_digest
            || durable_affinity.is_none_or(|affinity| {
                affinity.node != observation.node()
                    || affinity.incarnation != observation.incarnation()
                    || affinity.epoch != observation.epoch()
                    || affinity.desired_generation != observation.desired_generation()
                    || affinity.assignment_digest != observation.assignment_digest()
                    || affinity.worker_identity_digest != worker_identity_digest
                    || affinity.liveness_record_digest != liveness_digest
                    || affinity.live_until_unix_seconds < coordinator_unix_seconds
            })
            || liveness_record.context().node() != observation.node()
            || liveness_record.context().lineage() != observation.lineage()
            || liveness_record.context().audience_digest()
                != observation.context().audience_digest()
            || !liveness_record
                .context()
                .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidPlacementInput::AffinityNotLive);
        }
        Ok(Self {
            observation,
            worker_identity_digest,
            liveness_record,
        })
    }

    /// Returns the exact dependent sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.observation.sandbox()
    }

    /// Returns the currently live worker node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.observation.node()
    }

    /// Returns the exact live assignment incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.observation.incarnation()
    }

    /// Returns the exact live desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.observation.desired_generation()
    }

    /// Returns the exact live assignment fencing epoch.
    #[must_use]
    pub const fn epoch(&self) -> AssignmentEpoch {
        self.observation.epoch()
    }

    /// Returns the exact live assignment semantic commitment.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.observation.assignment_digest()
    }

    /// Returns the independently authenticated worker identity commitment.
    #[must_use]
    pub const fn worker_identity_digest(&self) -> ObjectDigest {
        self.worker_identity_digest
    }

    /// Reports whether the exact assignment and protected liveness proof remain current.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        self.observation
            .context()
            .is_current_at(coordinator_unix_seconds)
            && self.observation.observed_at_unix_seconds() <= coordinator_unix_seconds
            && self.observation.authority().is_some_and(|authority| {
                authority.guardian_state() == VerifiedGuardianStateV1::Armed
                    && authority.is_current_at(coordinator_unix_seconds)
            })
            && self
                .liveness_record
                .context()
                .is_current_at(coordinator_unix_seconds)
    }

    /// Returns the exact protected durability capability for this liveness fact.
    #[must_use]
    pub const fn liveness_record(&self) -> &ProtectedJournalRecordV1 {
        &self.liveness_record
    }

    fn canonical_key(&self) -> (SandboxId, AssignmentEpoch, IncarnationId, DesiredGeneration) {
        (
            self.sandbox(),
            self.epoch(),
            self.incarnation(),
            self.desired_generation(),
        )
    }

    fn ensure_specified(&self) -> Result<(), InvalidPlacementInput> {
        if self.sandbox().as_bytes() == &[0; 16]
            || self.node().as_bytes() == &[0; 16]
            || self.incarnation().as_bytes() == &[0; 16]
            || self.desired_generation().get() == 0
            || self.worker_identity_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidPlacementInput::UnspecifiedIdentity);
        }
        Ok(())
    }
}

/// Reports malformed, incomplete, or nondeterministic placement inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidPlacementInput {
    /// An identity uses its all-zero sentinel.
    #[error("placement input contains an unspecified identity")]
    UnspecifiedIdentity,
    /// Candidate snapshots are oversized, duplicated, or not ordered by node.
    #[error("placement candidates must be a canonical set of at most 4096 nodes")]
    CandidatesNotCanonical,
    /// Affinity observations are oversized, duplicated, or not ordered by sandbox.
    #[error("affinity observations must be a canonical set of at most 4096 sandboxes")]
    AffinitiesNotCanonical,
    /// The semantic request exceeds the scheduler's bounded feature profile.
    #[error("placement request exceeds the 64-feature scheduler limit")]
    TooManyRequiredFeatures,
    /// A required feature is outside the local closed semantic registry.
    #[error("placement request contains an unknown required feature")]
    UnknownRequiredFeature,
    /// Freshness evaluation has no positive maximum age.
    #[error("placement capability maximum age must be positive")]
    InvalidFreshnessLimit,
    /// A local-live dependency lacks exact current worker and durability evidence.
    #[error("local-live affinity evidence is absent, stale, or unprotected")]
    AffinityNotLive,
}

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
            .any(|placement| placement.ensure_specified().is_err())
        || !affinities
            .windows(2)
            .all(|pair| pair[0].canonical_key() < pair[1].canonical_key())
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

fn affinity_liveness_digest(
    observation: &NodeAssignmentObservationV1,
    worker_identity_digest: ObjectDigest,
) -> ObjectDigest {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"aos.affinity-live-worker.v1\0");
    hasher.update(observation.node().as_bytes());
    hasher.update(observation.lineage().digest().as_bytes());
    hasher.update(observation.sandbox().as_bytes());
    hasher.update(observation.incarnation().as_bytes());
    hasher.update(observation.epoch().get().to_be_bytes());
    hasher.update(observation.desired_generation().get().to_be_bytes());
    hasher.update(observation.assignment_digest().as_bytes());
    hasher.update(worker_identity_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
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
