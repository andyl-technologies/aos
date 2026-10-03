//! Canonical campaign ref names and domain-separated persistent index-key recipes.
//!
//! General map keys hash the following bytes with the existing v1 domain:
//!
//! ```text
//! hash-key    = u64be(namespace length) || namespace || hash32
//! content-key = u64be(namespace length) || namespace || u64be(encoded ID length) || encoded ID
//! ```

use super::*;

pub(super) fn campaign_ref(name: &str) -> Result<RefName, CampaignRepositoryError> {
    RefName::new(format!("campaigns/{name}")).map_err(CampaignRepositoryError::from)
}

pub(super) fn map_key_hash(namespace: &str, id: CampaignHash) -> CampaignHash {
    let mut bytes = Vec::with_capacity(namespace.len() + 40);
    bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&id.as_bytes());
    CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
}

pub(super) fn map_key_content(namespace: &str, id: ContentId) -> CampaignHash {
    let encoded = id.encode();
    let mut bytes = Vec::with_capacity(namespace.len() + encoded.len() + 16);
    bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(encoded.as_bytes());
    CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
}

pub(super) fn statistical_draw_request_key(coordinate: u64) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign.statistical-draw-request.v1",
        &coordinate.to_be_bytes(),
    )
}

pub(super) fn statistical_draw_proposal_key(coordinate: u64) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign.statistical-draw-proposal.v1",
        &coordinate.to_be_bytes(),
    )
}

pub(super) fn smc_transition_request_key(stage: u32, slot: u32) -> CampaignHash {
    let mut coordinate = [0_u8; 8];
    coordinate[..4].copy_from_slice(&stage.to_be_bytes());
    coordinate[4..].copy_from_slice(&slot.to_be_bytes());
    CampaignHash::derive("crucible.campaign.smc-transition-request.v1", &coordinate)
}

pub(super) fn smc_transition_proposal_key(stage: u32, slot: u32) -> CampaignHash {
    let mut coordinate = [0_u8; 8];
    coordinate[..4].copy_from_slice(&stage.to_be_bytes());
    coordinate[4..].copy_from_slice(&slot.to_be_bytes());
    CampaignHash::derive("crucible.campaign.smc-transition-proposal.v1", &coordinate)
}

pub(super) fn mutation_result_hash_key(namespace: &str, id: CampaignHash) -> CampaignHash {
    map_key_hash(&format!("coordination.result.{namespace}"), id)
}

pub(super) fn mutation_result_content_key(namespace: &str, id: ContentId) -> CampaignHash {
    map_key_content(&format!("coordination.result.{namespace}"), id)
}

pub(super) fn pin_configuration_key(configuration: ConfigurationId) -> CampaignHash {
    map_key_hash("pins.configuration", configuration.as_hash())
}

pub(crate) fn savepoint_capture_request_key(request: CampaignFactId) -> CampaignHash {
    map_key_content("accounting.savepoint-capture.request", request.content_id())
}

pub(crate) fn savepoint_capture_resolution_key(request: CampaignFactId) -> CampaignHash {
    map_key_content(
        "accounting.savepoint-capture.resolution",
        request.content_id(),
    )
}

pub(crate) fn savepoint_continuation_source_key(continuation: AttemptId) -> CampaignHash {
    map_key_content(
        "accounting.savepoint-continuation.source",
        continuation.content_id(),
    )
}

pub(super) fn proposal_ordinal_key(request: BranchRequestId, ordinal: u64) -> CampaignHash {
    let request = request.content_id().encode();
    let mut bytes = Vec::with_capacity(request.len() + 8);
    bytes.extend_from_slice(request.as_bytes());
    bytes.extend_from_slice(&ordinal.to_be_bytes());
    CampaignHash::derive("crucible.campaign-proposal-request-ordinal.v1", &bytes)
}

pub(super) fn proposal_head_key(request: BranchRequestId) -> CampaignHash {
    // Each accepted proposal successor proves its predecessor and advances
    // this exact request-local head in the authenticated exploration root.
    map_key_content("exploration.request-proposal-head.v1", request.content_id())
}

pub(super) fn proposal_value_key(
    request: BranchRequestId,
    value: &crate::ChoiceValue,
) -> CampaignHash {
    let request = request.content_id().encode();
    let value = crate::codec::encode(value);
    let mut bytes = Vec::with_capacity(request.len() + value.len() + 8);
    bytes.extend_from_slice(request.as_bytes());
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&value);
    CampaignHash::derive("crucible.campaign-proposal-request-value.v1", &bytes)
}

pub(crate) fn planner_step_key(step: PlannerStepId) -> CampaignHash {
    map_key_content("coordination.planner-step", step.content_id())
}

pub(crate) fn planner_invocation_result_key(invocation: PlannerInvocationId) -> CampaignHash {
    map_key_content(
        "coordination.planner-invocation-result",
        invocation.content_id(),
    )
}

pub(super) fn planner_head_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-coordination-planner-head.v1", b"")
}

pub(super) fn admission_sequence_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-admission-sequence.v1", b"")
}

pub(super) fn admission_ordinal_key(ordinal: AdmissionOrdinal) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-admission-ordinal.v1",
        &ordinal.value().to_be_bytes(),
    )
}

pub(super) fn observation_sequence_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-observation-sequence.v1", b"")
}

pub(super) fn observation_ordinal_key(ordinal: AdmissionOrdinal) -> CampaignHash {
    let ordinal = CampaignHash::derive(
        "crucible.campaign-observation-ordinal.v1",
        &ordinal.value().to_be_bytes(),
    );
    map_key_hash("accounting.observation-ordinal", ordinal)
}

pub(super) fn non_modeled_ordinal_key(ordinal: AdmissionOrdinal) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-accounting-admission-disposition.v1",
        &ordinal.value().to_be_bytes(),
    )
}

pub(crate) fn attempt_index_key(attempt: AttemptId) -> CampaignHash {
    map_key_content("accounting.attempt", attempt.content_id())
}

pub(crate) fn attempt_execution_basis_key(attempt: AttemptId) -> CampaignHash {
    map_key_content("accounting.attempt-execution-basis", attempt.content_id())
}

pub(crate) fn proposal_index_key(proposal: ProposalId) -> CampaignHash {
    map_key_content("exploration.proposal", proposal.content_id())
}

pub(crate) fn attempt_observation_key(attempt: AttemptId) -> CampaignHash {
    map_key_content("observations.attempt", attempt.content_id())
}

pub(crate) fn objective_evaluation_key(
    policy: CampaignPolicyId,
    observation: ObservationId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(policy.content_id().encode().as_bytes());
    bytes.extend_from_slice(observation.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-objective-evaluation.v1", &bytes)
}

pub(crate) fn authoritative_choice_key(opportunity: ChoiceOpportunityId) -> CampaignHash {
    map_key_content("graph.choice-opportunity", opportunity.content_id())
}

pub(crate) fn choice_index_anchor_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-graph-choice-index.v1", b"")
}

pub(crate) fn choice_index_order_key(opportunity: ChoiceOpportunityId) -> CampaignHash {
    CampaignHash::from_bytes(opportunity.content_id().digest())
}

pub(crate) fn frontier_index_anchor_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b"")
}

pub(crate) fn frontier_index_order_key(request: BranchRequestId) -> CampaignHash {
    CampaignHash::from_bytes(request.content_id().digest())
}

pub(super) fn branch_request_index_anchor_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign-exploration-branch-request-index.v1", b"")
}

/// Derives the nested request-index slot for one semantic branch point.
pub(super) fn branch_request_index_branch_key(branch_point: crate::BranchPointId) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-exploration-branch-request-point.v1",
        &branch_point.as_hash().as_bytes(),
    )
}

pub(super) fn branch_request_index_membership_key(request: BranchRequestId) -> CampaignHash {
    map_key_content("exploration.feedback-branch-request", request.content_id())
}

pub(super) fn choice_discovery_result_key(
    parent: ConfigurationArtifactId,
    opportunity: ChoiceOpportunityId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(parent.content_id().encode().as_bytes());
    bytes.extend_from_slice(opportunity.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-choice-discovery-result.v1", &bytes)
}

pub(super) fn observation_conflict_key(
    attempt: AttemptId,
    observation: ObservationId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(attempt.content_id().encode().as_bytes());
    bytes.extend_from_slice(observation.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-observation-conflict.v1", &bytes)
}

pub(super) fn branch_point_opportunity_key(
    branch_point: crate::BranchPointId,
    opportunity: ChoiceOpportunityId,
) -> CampaignHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&branch_point.as_hash().as_bytes());
    bytes.extend_from_slice(opportunity.content_id().encode().as_bytes());
    CampaignHash::derive("crucible.campaign-branch-point-opportunity.v1", &bytes)
}

pub(super) fn branch_credit_index_key(branch_point: crate::BranchPointId) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign-branch-credit-index.v1",
        &branch_point.as_hash().as_bytes(),
    )
}

pub(super) fn configuration_path_index_key(configuration: ConfigurationArtifactId) -> CampaignHash {
    map_key_content(
        "observations.configuration-path-index",
        configuration.content_id(),
    )
}

pub(super) fn path_index_order_key(path: BranchPathId) -> CampaignHash {
    CampaignHash::from_bytes(path.content_id().digest())
}
