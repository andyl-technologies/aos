//! Unit tests for the authenticated campaign service contracts.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::sync::Arc;

use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

use super::*;
use crate::{
    BranchAcceptanceCount, BranchAcceptanceSummary, BranchBudget, BranchPointId,
    BranchRequestCause, CampaignCommandId, CampaignControlAction, CampaignRoots, CandidateSource,
    ChoiceDomainId, ChoiceOpportunityId, ChoiceValue, ConfigurationArtifactId, ConfigurationId,
    DaemonEpoch, PinChange, PinRequest, PinRetention, StopCondition,
};

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("campaign-service-test", label.as_bytes())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
fn list_campaign_messages_are_canonical_ordered_and_request_bound() {
    let principal = CampaignPrincipal::new("operator:alice").expect("principal");
    let request = ListCampaignsRequest::new(principal.clone(), None, 2).expect("list request");
    assert_eq!(
        ListCampaignsRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode list request"),
        request
    );
    let entries = vec![
        CampaignListEntry::new(
            CampaignName::new("alpha").expect("alpha"),
            snapshot("alpha"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        ),
        CampaignListEntry::new(
            CampaignName::new("middle").expect("middle"),
            snapshot("middle"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Paused,
        ),
    ];
    let response = ListCampaignsResponse::new(
        &request,
        entries.clone(),
        Some(CampaignName::new("middle").expect("cursor")),
        2,
    )
    .expect("list response");
    assert_eq!(
        ListCampaignsResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode list response"),
        response
    );
    response.validate_for(&request).expect("request binding");

    let resumed = ListCampaignsRequest::new(
        principal,
        Some(CampaignName::new("alpha").expect("after")),
        2,
    )
    .expect("resumed request");
    assert!(response.validate_for(&resumed).is_err());
    assert!(
        ListCampaignsResponse::new(&request, entries.into_iter().rev().collect(), None, 2).is_err()
    );
    assert!(
        ListCampaignsRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            None,
            MAX_CAMPAIGN_LIST_PAGE_ITEMS + 1,
        )
        .is_err()
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
fn campaign_status_messages_are_snapshot_bound_and_have_raw_vectors() {
    let head_request = get_request("network-recovery");
    let request = GetCampaignStatusRequest::new(
        head_request.principal().clone(),
        head_request.campaign().clone(),
        snapshot("snapshot"),
    )
    .expect("status request");
    let semantic = CampaignSemanticStatus::new(
        CampaignContinuationStatus::new(1, 2, 3, 4, 5),
        6,
        7,
        15,
        8_192,
    )
    .expect("semantic status");
    let operational = CampaignOperationalStatus::Observed(CampaignOperationalEvidence::new(
        DaemonEpoch::from_bytes([0x42; 16]).expect("daemon epoch"),
        hash("inventory"),
        CampaignWorldStatus::new(8, 9, 10, 11, 12, 13),
        14,
        15,
    ));
    let response =
        GetCampaignStatusResponse::new(&request, CampaignStatusSummary::new(semantic, operational))
            .expect("status response");

    assert_eq!(
        GetCampaignStatusRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode status request"),
        request
    );
    assert_eq!(
        GetCampaignStatusResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode status response"),
        response
    );
    response.validate_for(&request).expect("request binding");

    let other_snapshot = GetCampaignStatusRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        snapshot("other"),
    )
    .expect("other status request");
    assert!(response.validate_for(&other_snapshot).is_err());

    assert_eq!(
        encode_hex(&request.canonical_bytes()),
        "00000001000000000000000e6f70657261746f723a616c69636500000000000000106e6574776f726b2d7265636f76657279000000000000001a6372756369626c652e63616d706169676e2e736e617073686f74000000000000005463616d706169676e2d736e617073686f742e322e65623633643230366361623833326333326338333464303736346132613538646230373335363565623366386431373339316335396366646165663566653961"
    );
    assert_eq!(
        encode_hex(&response.canonical_bytes()),
        "00000001c2645e11c40d98dafd76b6cd55d410ede6c68c1124fa31cf5c2535409a8ccb92000000000000001a6372756369626c652e63616d706169676e2e736e617073686f74000000000000005463616d706169676e2d736e617073686f742e322e656236336432303663616238333263333263383334643037363461326135386462303733353635656233663864313733393163353963666461656635666539610000000000000001000000000000000200000000000000030000000000000004000000000000000500000000000000060000000000000007000000000000000f000000000000200001424242424242424242424242424242428a56cb32569d9a14271f8d8ce49d59c77d6a288e42372209b4234532c01c3f2900000000000000080000000000000009000000000000000a000000000000000b000000000000000c000000000000000d000000000000000e000000000000000f"
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

    fn list_campaigns(
        &self,
        _request: &ListCampaignsRequest,
    ) -> Result<ListCampaignsResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

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

    fn get_campaign_status(
        &self,
        _request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
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

    fn list_campaigns(
        &self,
        _request: &ListCampaignsRequest,
    ) -> Result<ListCampaignsResponse, Self::Error> {
        Err(self.0)
    }

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

    fn get_campaign_status(
        &self,
        _request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
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

    fn list_campaigns(
        &self,
        _request: &ListCampaignsRequest,
    ) -> Result<ListCampaignsResponse, Self::Error> {
        unreachable!("test service only handles ApplyCampaignCommand")
    }

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

    fn get_campaign_status(
        &self,
        _request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
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
    let summary = BranchAcceptanceSummary::new(
        BranchAcceptanceCount::Exact(1),
        BranchAcceptanceCount::Exact(0),
        BranchAcceptanceCount::Exact(1),
        1,
        1,
    )
    .expect("acceptance summary");
    let acceptance_fact = CampaignFact::BranchRequestAccepted {
        request: request.request().id().expect("request id"),
        summary,
    };
    let root = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"branch-response-root");
    let accepted_snapshot = CampaignSnapshot::successor(
        snapshot("prior"),
        lineage("branch-response"),
        policy("branch-response"),
        CampaignRoots {
            graph: root,
            exploration: root,
            observations: root,
            corpus: root,
            coverage: root,
            findings: root,
            pins: root,
            accounting: root,
            coordination: root,
        },
        acceptance_fact.id().expect("acceptance fact id"),
    )
    .expect("accepted snapshot");
    let response = SubmitCampaignBranchResponse::new(
        &request,
        BranchRequestResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: accepted_snapshot.id().expect("accepted snapshot id"),
            request: request.request().id().expect("request id"),
            summary,
            snapshot: accepted_snapshot,
            acceptance_fact,
            summary_recorded: true,
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
    assert_eq!(
        encode_hex(&response.canonical_bytes()),
        include_str!("testdata/submit-branch-response-v2.hex").trim()
    );

    let mut malformed_schema = response.canonical_bytes();
    malformed_schema[..std::mem::size_of::<u32>()].copy_from_slice(&1_u32.to_be_bytes());
    assert!(SubmitCampaignBranchResponse::from_canonical_bytes(&malformed_schema).is_err());
    let mut truncated = response.canonical_bytes();
    truncated.pop();
    assert!(SubmitCampaignBranchResponse::from_canonical_bytes(&truncated).is_err());
    let mut trailing = response.canonical_bytes();
    trailing.push(0);
    assert!(SubmitCampaignBranchResponse::from_canonical_bytes(&trailing).is_err());

    let different_summary = BranchAcceptanceSummary::new(
        BranchAcceptanceCount::Exact(1),
        BranchAcceptanceCount::Exact(1),
        BranchAcceptanceCount::Exact(0),
        1,
        1,
    )
    .expect("different acceptance summary");
    let mut mismatched_fact = response.clone();
    mismatched_fact.summary = different_summary;
    assert!(mismatched_fact.validate_for(&request).is_err());

    let different_budget = BranchAcceptanceSummary::new(
        BranchAcceptanceCount::Exact(2),
        BranchAcceptanceCount::Exact(0),
        BranchAcceptanceCount::Exact(2),
        2,
        1,
    )
    .expect("different acceptance budget");
    let mut mismatched_budget = response.clone();
    mismatched_budget.summary = different_budget;
    mismatched_budget.acceptance_fact = CampaignFact::BranchRequestAccepted {
        request: mismatched_budget.request,
        summary: different_budget,
    };
    assert!(mismatched_budget.validate_for(&request).is_err());

    let mut unrecorded_new_response = response.clone();
    unrecorded_new_response.summary_recorded = false;
    assert!(unrecorded_new_response.validate_for(&request).is_err());

    let legacy_fact = CampaignFact::BranchRequestIssued(response.request());
    let legacy_snapshot = CampaignSnapshot::successor(
        response.prior_snapshot(),
        response.snapshot.lineage(),
        response.snapshot.active_policy(),
        response.snapshot.roots(),
        legacy_fact.id().expect("legacy acceptance fact ID"),
    )
    .expect("legacy acceptance snapshot");
    let legacy_response = SubmitCampaignBranchResponse::new(
        &request,
        BranchRequestResult {
            prior_snapshot: response.prior_snapshot(),
            new_snapshot: legacy_snapshot.id().expect("legacy acceptance snapshot ID"),
            request: response.request(),
            summary,
            snapshot: legacy_snapshot,
            acceptance_fact: legacy_fact,
            summary_recorded: false,
            replayed: true,
        },
    )
    .expect("legacy replay response");
    assert!(legacy_response.replayed());
    assert!(!legacy_response.summary_recorded());
    legacy_response
        .validate_for(&request)
        .expect("legacy replay provenance");

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
            String::from("e697616cbd6b01366d36226fa116bf20daa1199ecbf489a0c5c6f37dcc791ce5"),
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
    let list = ListCampaignsRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        None,
        1,
    )
    .expect("list request");
    assert!(matches!(
        service.list_campaigns(&list),
        Err(RepositoryCampaignServiceError::Authorization(
            CampaignAuthorizationError::Unauthorized
        ))
    ));
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
