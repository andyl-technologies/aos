//! Unit tests for the authenticated campaign service contracts.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::sync::Arc;

use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

use super::*;
use crate::{
    BranchBudget, BranchPointId, BranchRequestCause, CampaignCommandId, CampaignControlAction,
    CandidateSource, ChoiceDomainId, ChoiceOpportunityId, ChoiceValue, ConfigurationArtifactId,
    ConfigurationId, PinChange, PinRequest, PinRetention, StopCondition,
};

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("campaign-service-test", label.as_bytes())
}

fn snapshot(label: &str) -> CampaignSnapshotId {
    CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        2,
        label.as_bytes(),
    ))
    .expect("snapshot id")
}

fn lineage(label: &str) -> CampaignLineageId {
    CampaignLineageId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignFact,
        1,
        label.as_bytes(),
    ))
    .expect("lineage id")
}

fn policy(label: &str) -> CampaignPolicyId {
    CampaignPolicyId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        1,
        label.as_bytes(),
    ))
    .expect("policy id")
}

fn branch_request(label: &str) -> BranchRequest {
    BranchRequest::new(
        BranchPointId::from_hash(hash(&format!("{label}-branch-point"))),
        ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Configuration,
            1,
            format!("{label}-parent").as_bytes(),
        ))
        .expect("parent id"),
        ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            format!("{label}-opportunity").as_bytes(),
        ))
        .expect("opportunity id"),
        ChoiceDomainId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            format!("{label}-domain").as_bytes(),
        ))
        .expect("domain id"),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash(&format!(
            "{label}-command"
        )))),
        BranchBudget::new(1, 1).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request")
}

fn get_request(name: &str) -> GetCampaignRequest {
    GetCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new(name).expect("campaign name"),
    )
    .expect("get request")
}

#[test]
fn campaign_names_match_the_repository_ref_grammar() {
    for invalid in ["bad:name", "a//b", "a/../b", "."] {
        assert!(CampaignName::new(invalid).is_err(), "accepted {invalid}");
    }
    assert!(CampaignName::new(format!("{}x", "a".repeat(255))).is_err());
    assert_eq!(
        CampaignName::new("team/network-recovery")
            .expect("nested campaign name")
            .as_str(),
        "team/network-recovery"
    );
}

#[test]
fn get_campaign_messages_are_canonical_and_request_bound() {
    let request = get_request("network-recovery");
    assert_eq!(
        GetCampaignRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode request"),
        request
    );
    let response = GetCampaignResponse::new(
        &request,
        snapshot("snapshot"),
        lineage("lineage"),
        policy("policy"),
        CampaignState::Running,
    )
    .expect("response");
    assert_eq!(
        GetCampaignResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode response"),
        response
    );
    response.validate_for(&request).expect("request binding");
    assert!(response.validate_for(&get_request("other")).is_err());

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("e25fd54be8cb0ea10f0dc695d3f7b029883e0f87269c692abe85f5ba9701a61d"),
            String::from("3621345eb7ec6ae17e20f42ced081f182266ce1599d25e21e319a8baf9691a47"),
        ]
    );
}

#[test]
fn apply_command_messages_bind_principal_name_and_payload() {
    let request = ApplyCampaignCommandRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("resume")),
            expected_snapshot: snapshot("prior"),
            action: CampaignControlAction::Resume,
        },
    )
    .expect("apply request");
    assert_eq!(
        ApplyCampaignCommandRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode request"),
        request
    );
    let response = ApplyCampaignCommandResponse::new(
        &request,
        CampaignCommandResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: snapshot("next"),
            replayed: false,
        },
    )
    .expect("apply response");
    response.validate_for(&request).expect("request binding");

    let other_principal = ApplyCampaignCommandRequest::new(
        CampaignPrincipal::new("operator:bob").expect("principal"),
        request.campaign().clone(),
        request.command().clone(),
    )
    .expect("other request");
    assert!(response.validate_for(&other_principal).is_err());

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("854db6d9d21dd722d3c8c754fe83fa55db271325a8c06dbbbd95d63222fbb8c7"),
            String::from("66bf01a14552275865ffd5b6a9a91075387c976244cda5c3efaaee9324f18c18"),
        ]
    );
}

struct WrongGetService {
    response: GetCampaignResponse,
}

impl CampaignService for WrongGetService {
    type Error = Infallible;

    fn create_campaign(
        &self,
        _request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn derive_campaign(
        &self,
        _request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign(
        &self,
        _request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        Ok(self.response.clone())
    }

    fn get_campaign_snapshot(
        &self,
        _request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn watch_campaign(
        &self,
        _request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn query_campaign_graph(
        &self,
        _request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn query_campaign_findings(
        &self,
        _request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_finding_object(
        &self,
        _request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn explain_campaign_attempt(
        &self,
        _request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_planner_rankings(
        &self,
        _request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_graph_object(
        &self,
        _request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn query_campaign_choices(
        &self,
        _request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn query_campaign_frontier(
        &self,
        _request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_frontier_object(
        &self,
        _request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_choice_object(
        &self,
        _request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn apply_campaign_command(
        &self,
        _request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn pin_campaign(
        &self,
        _request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn submit_branch_request(
        &self,
        _request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }
}

#[test]
fn checked_client_rejects_a_cross_request_response() {
    let original = get_request("original");
    let response = GetCampaignResponse::new(
        &original,
        snapshot("snapshot"),
        lineage("lineage"),
        policy("policy"),
        CampaignState::Running,
    )
    .expect("response");
    let client = CampaignClient::new(WrongGetService { response });

    assert!(matches!(
        client.get_campaign(&get_request("other")),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::ProtocolViolation
        ))
    ));
}

struct WrongApplyService {
    response: ApplyCampaignCommandResponse,
}

struct FixedFailureService(CampaignServiceFailure);

impl CampaignService for FixedFailureService {
    type Error = CampaignServiceFailure;

    fn create_campaign(
        &self,
        _request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        Err(self.0)
    }

    fn derive_campaign(
        &self,
        _request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        Err(self.0)
    }

    fn get_campaign(
        &self,
        _request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        Err(self.0)
    }

    fn get_campaign_snapshot(
        &self,
        _request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        Err(self.0)
    }

    fn watch_campaign(
        &self,
        _request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error> {
        Err(self.0)
    }

    fn query_campaign_graph(
        &self,
        _request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        Err(self.0)
    }

    fn query_campaign_findings(
        &self,
        _request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
        Err(self.0)
    }

    fn get_campaign_finding_object(
        &self,
        _request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
        Err(self.0)
    }

    fn explain_campaign_attempt(
        &self,
        _request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
        Err(self.0)
    }

    fn get_campaign_planner_rankings(
        &self,
        _request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        Err(self.0)
    }

    fn get_campaign_graph_object(
        &self,
        _request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        Err(self.0)
    }

    fn query_campaign_choices(
        &self,
        _request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        Err(self.0)
    }

    fn query_campaign_frontier(
        &self,
        _request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        Err(self.0)
    }

    fn get_campaign_frontier_object(
        &self,
        _request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
        Err(self.0)
    }

    fn get_campaign_choice_object(
        &self,
        _request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
        Err(self.0)
    }

    fn apply_campaign_command(
        &self,
        _request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        Err(self.0)
    }

    fn pin_campaign(
        &self,
        _request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error> {
        Err(self.0)
    }

    fn submit_branch_request(
        &self,
        _request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        Err(self.0)
    }
}

impl CampaignService for WrongApplyService {
    type Error = Infallible;

    fn create_campaign(
        &self,
        _request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn derive_campaign(
        &self,
        _request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn get_campaign(
        &self,
        _request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn get_campaign_snapshot(
        &self,
        _request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn watch_campaign(
        &self,
        _request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn query_campaign_graph(
        &self,
        _request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn query_campaign_findings(
        &self,
        _request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn get_campaign_finding_object(
        &self,
        _request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn explain_campaign_attempt(
        &self,
        _request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn get_campaign_planner_rankings(
        &self,
        _request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn get_campaign_graph_object(
        &self,
        _request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn query_campaign_choices(
        &self,
        _request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn query_campaign_frontier(
        &self,
        _request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn get_campaign_frontier_object(
        &self,
        _request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn get_campaign_choice_object(
        &self,
        _request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn apply_campaign_command(
        &self,
        _request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        Ok(self.response.clone())
    }

    fn pin_campaign(
        &self,
        _request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

    fn submit_branch_request(
        &self,
        _request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }
}

#[test]
fn checked_client_rejects_a_command_response_with_the_wrong_prior_snapshot() {
    let request = ApplyCampaignCommandRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("resume")),
            expected_snapshot: snapshot("prior"),
            action: CampaignControlAction::Resume,
        },
    )
    .expect("apply request");
    assert!(
        ApplyCampaignCommandResponse::new(
            &request,
            CampaignCommandResult {
                prior_snapshot: snapshot("wrong"),
                new_snapshot: snapshot("next"),
                replayed: false,
            },
        )
        .is_err()
    );

    let mut response = ApplyCampaignCommandResponse::new(
        &request,
        CampaignCommandResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: snapshot("next"),
            replayed: false,
        },
    )
    .expect("apply response");
    response.prior_snapshot = snapshot("wrong");
    let client = CampaignClient::new(WrongApplyService { response });

    assert!(matches!(
        client.apply_campaign_command(&request),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::ProtocolViolation
        ))
    ));
}

#[test]
fn checked_client_rejects_failures_with_the_wrong_operation_basis() {
    let get = get_request("network-recovery");
    for failure in [
        CampaignServiceFailure::AlreadyExists,
        CampaignServiceFailure::Stale {
            expected: snapshot("irrelevant"),
            current: snapshot("current"),
        },
        CampaignServiceFailure::CommandReuse,
        CampaignServiceFailure::ConcurrentUpdate,
        CampaignServiceFailure::InvalidTransition {
            state: CampaignState::Sealed,
        },
    ] {
        let client = CampaignClient::new(FixedFailureService(failure));
        assert!(matches!(
            client.get_campaign(&get),
            Err(CampaignClientError::Service(
                CampaignServiceFailure::ProtocolViolation
            ))
        ));
    }

    let pin = PinCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        PinRequest {
            command: CampaignCommandId::from_hash(hash("pin")),
            expected_snapshot: snapshot("expected"),
            change: PinChange::new(
                ConfigurationId::from_hash(hash("configuration")),
                Some(PinRetention::Exact),
                "retain reproducer",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request");
    for failure in [
        CampaignServiceFailure::AlreadyExists,
        CampaignServiceFailure::InvalidTransition {
            state: CampaignState::Sealed,
        },
        CampaignServiceFailure::Stale {
            expected: snapshot("wrong"),
            current: snapshot("current"),
        },
        CampaignServiceFailure::Stale {
            expected: snapshot("expected"),
            current: snapshot("expected"),
        },
    ] {
        let client = CampaignClient::new(FixedFailureService(failure));
        assert!(matches!(
            client.pin_campaign(&pin),
            Err(CampaignClientError::Service(
                CampaignServiceFailure::ProtocolViolation
            ))
        ));
    }

    let apply = ApplyCampaignCommandRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("resume")),
            expected_snapshot: snapshot("expected"),
            action: CampaignControlAction::Resume,
        },
    )
    .expect("apply request");
    for failure in [
        CampaignServiceFailure::AlreadyExists,
        CampaignServiceFailure::Stale {
            expected: snapshot("wrong"),
            current: snapshot("current"),
        },
        CampaignServiceFailure::Stale {
            expected: snapshot("expected"),
            current: snapshot("expected"),
        },
    ] {
        let client = CampaignClient::new(FixedFailureService(failure));
        assert!(matches!(
            client.apply_campaign_command(&apply),
            Err(CampaignClientError::Service(
                CampaignServiceFailure::ProtocolViolation
            ))
        ));
    }

    let branch = SubmitCampaignBranchRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        snapshot("expected"),
        branch_request("wrong-failure-basis"),
    )
    .expect("branch request");
    for failure in [
        CampaignServiceFailure::AlreadyExists,
        CampaignServiceFailure::InvalidTransition {
            state: CampaignState::Sealed,
        },
    ] {
        let client = CampaignClient::new(FixedFailureService(failure));
        assert!(matches!(
            client.submit_branch_request(&branch),
            Err(CampaignClientError::Service(
                CampaignServiceFailure::ProtocolViolation
            ))
        ));
    }
}

#[test]
fn branch_messages_are_canonical_and_bind_the_exact_request() {
    let request = SubmitCampaignBranchRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        snapshot("prior"),
        branch_request("first"),
    )
    .expect("branch submission");
    assert_eq!(
        SubmitCampaignBranchRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode request"),
        request
    );
    let response = SubmitCampaignBranchResponse::new(
        &request,
        BranchRequestResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: snapshot("next"),
            request: request.request().id().expect("request id"),
            replayed: false,
        },
    )
    .expect("branch response");
    assert_eq!(
        SubmitCampaignBranchResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode response"),
        response
    );
    response.validate_for(&request).expect("request binding");

    let changed = SubmitCampaignBranchRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        snapshot("other-prior"),
        request.request().clone(),
    )
    .expect("changed submission");
    assert!(response.validate_for(&changed).is_err());

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("486e4c887f7964b881d511ccff736e871bc9ffde2b69d576f9874710f63ee118"),
            String::from("0f327b8933afa03c6f8a172f7db2f8683aba5f0d4a64e910621ca28a0ddcf455"),
        ]
    );
}

#[test]
fn pin_messages_are_canonical_and_bind_the_exact_request() {
    let request = PinCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        PinRequest {
            command: CampaignCommandId::from_hash(hash("pin")),
            expected_snapshot: snapshot("prior"),
            change: PinChange::new(
                ConfigurationId::from_hash(hash("configuration")),
                Some(PinRetention::Thin),
                "retain semantic replay",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request");
    assert_eq!(
        PinCampaignRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode pin request"),
        request
    );

    let response = PinCampaignResponse::new(
        &request,
        CampaignCommandResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: snapshot("next"),
            replayed: false,
        },
    )
    .expect("pin response");
    assert_eq!(
        PinCampaignResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode pin response"),
        response
    );
    response.validate_for(&request).expect("request binding");

    let changed = PinCampaignRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        PinRequest {
            command: request.command().command,
            expected_snapshot: snapshot("other-prior"),
            change: request.command().change.clone(),
        },
    )
    .expect("changed pin request");
    assert!(response.validate_for(&changed).is_err());

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("f660144a465eda8be74584b363ac4c67ee327bd8afdb42704954910ad178431d"),
            String::from("ca85fb59c75c094ed8077a411bc7dac9f5730c08bc858542ec8171d9c127c820"),
        ]
    );
}

#[test]
fn service_error_responses_are_canonical_and_request_bound() {
    let request_digest = hash("error-request");
    let failures = [
        (
            CampaignServiceFailure::Unauthorized,
            CampaignServiceRetryDisposition::Reauthenticate,
        ),
        (
            CampaignServiceFailure::AuthorizationUnavailable,
            CampaignServiceRetryDisposition::RetryAfterBackoff,
        ),
        (
            CampaignServiceFailure::NotFound,
            CampaignServiceRetryDisposition::OperatorAction,
        ),
        (
            CampaignServiceFailure::AlreadyExists,
            CampaignServiceRetryDisposition::OperatorAction,
        ),
        (
            CampaignServiceFailure::Stale {
                expected: snapshot("expected"),
                current: snapshot("current"),
            },
            CampaignServiceRetryDisposition::RefreshCampaign,
        ),
        (
            CampaignServiceFailure::CommandReuse,
            CampaignServiceRetryDisposition::DoNotRetry,
        ),
        (
            CampaignServiceFailure::ConcurrentUpdate,
            CampaignServiceRetryDisposition::RefreshCampaign,
        ),
        (
            CampaignServiceFailure::InvalidTransition {
                state: CampaignState::Sealed,
            },
            CampaignServiceRetryDisposition::OperatorAction,
        ),
        (
            CampaignServiceFailure::InvalidRequest,
            CampaignServiceRetryDisposition::DoNotRetry,
        ),
        (
            CampaignServiceFailure::BackendUnauthorized,
            CampaignServiceRetryDisposition::Reauthenticate,
        ),
        (
            CampaignServiceFailure::ResourceExhausted,
            CampaignServiceRetryDisposition::RetryAfterBackoff,
        ),
        (
            CampaignServiceFailure::Unavailable,
            CampaignServiceRetryDisposition::RetryAfterBackoff,
        ),
        (
            CampaignServiceFailure::IntegrityFailure,
            CampaignServiceRetryDisposition::DoNotRetry,
        ),
        (
            CampaignServiceFailure::ProtocolViolation,
            CampaignServiceRetryDisposition::DoNotRetry,
        ),
    ];
    for (failure, retry_disposition) in failures {
        let response =
            CampaignServiceErrorResponse::new(request_digest, failure).expect("error response");
        assert_eq!(
            CampaignServiceErrorResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode error response"),
            response
        );
        response
            .validate_for_digest(request_digest)
            .expect("request binding");
        assert_eq!(response.failure(), failure);
        assert!(
            response
                .validate_for_digest(hash("other-error-request"))
                .is_err()
        );
        assert_eq!(failure.retry_disposition(), retry_disposition);
    }
    let golden =
        CampaignServiceErrorResponse::new(request_digest, CampaignServiceFailure::Unauthorized)
            .expect("golden error response");
    assert_eq!(
        blake3::hash(&golden.canonical_bytes()).to_hex().to_string(),
        "26766ef9f5cf89d87b0e660c0a498a7dcad09764bd5952d89c82728bd7c34d67"
    );
    assert_eq!(
        repository_service_failure(&CampaignRepositoryError::Poisoned),
        CampaignServiceFailure::IntegrityFailure
    );
    assert_eq!(
        store_service_failure(&StoreError::Poisoned {
            operation: "campaign-service-test",
        }),
        CampaignServiceFailure::IntegrityFailure
    );
}

struct DenyAll;

impl CampaignPrincipalAuthorizer for DenyAll {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Err(CampaignAuthorizationError::Unauthorized)
    }
}

#[test]
fn repository_adapter_authorizes_before_repository_access() {
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("campaign-service-test", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    );
    let service = RepositoryCampaignService::new(&repository, DenyAll);
    assert!(matches!(
        service.get_campaign(&get_request("absent")),
        Err(RepositoryCampaignServiceError::Authorization(
            CampaignAuthorizationError::Unauthorized
        ))
    ));
    let client = CampaignClient::new(RepositoryCampaignService::new(&repository, DenyAll));
    assert!(matches!(
        client.get_campaign(&get_request("absent")),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unauthorized
        ))
    ));

    let pin = PinCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("absent").expect("campaign name"),
        PinRequest {
            command: CampaignCommandId::from_hash(hash("pin")),
            expected_snapshot: snapshot("absent"),
            change: PinChange::new(
                ConfigurationId::from_hash(hash("configuration")),
                None,
                "remove stale pin",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request");
    assert!(matches!(
        client.pin_campaign(&pin),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unauthorized
        ))
    ));
}
