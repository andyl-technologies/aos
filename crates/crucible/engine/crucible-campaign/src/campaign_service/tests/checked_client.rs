//! Checked campaign-client rejection of mismatched service responses and failures.

use std::convert::Infallible;

use super::*;

struct WrongGetService {
    response: GetCampaignResponse,
}

impl CampaignService for WrongGetService {
    type Error = Infallible;

    fn campaign_savepoint(
        &self,
        _request: &crate::CampaignSavepointRequest,
    ) -> Result<crate::CampaignSavepointResponse, Self::Error> {
        panic!("savepoint is not used by this fixed test service")
    }

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

    fn query_campaign_report(
        &self,
        _request: &QueryCampaignReportRequest,
    ) -> Result<QueryCampaignReportResponse, Self::Error> {
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

    fn get_campaign_trace_chunk(
        &self,
        _request: &GetCampaignTraceChunkRequest,
    ) -> Result<GetCampaignTraceChunkResponse, Self::Error> {
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

    fn query_campaign_request_attempts(
        &self,
        _request: &QueryCampaignRequestAttemptsRequest,
    ) -> Result<QueryCampaignRequestAttemptsResponse, Self::Error> {
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

    fn submit_discovery_request(
        &self,
        _request: &SubmitCampaignDiscoveryRequest,
    ) -> Result<SubmitCampaignDiscoveryResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }
}

#[test]
fn checked_client_rejects_a_cross_request_response() {
    let original = get_request("original");
    let policy_body = response_policy();
    let response = GetCampaignResponse::new(
        &original,
        snapshot("snapshot"),
        lineage("lineage"),
        policy_body.id().expect("policy ID"),
        policy_body,
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

    fn campaign_savepoint(
        &self,
        _request: &crate::CampaignSavepointRequest,
    ) -> Result<crate::CampaignSavepointResponse, Self::Error> {
        panic!("savepoint is not used by this fixed test service")
    }

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

    fn query_campaign_report(
        &self,
        _request: &QueryCampaignReportRequest,
    ) -> Result<QueryCampaignReportResponse, Self::Error> {
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

    fn get_campaign_trace_chunk(
        &self,
        _request: &GetCampaignTraceChunkRequest,
    ) -> Result<GetCampaignTraceChunkResponse, Self::Error> {
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

    fn query_campaign_request_attempts(
        &self,
        _request: &QueryCampaignRequestAttemptsRequest,
    ) -> Result<QueryCampaignRequestAttemptsResponse, Self::Error> {
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

    fn submit_discovery_request(
        &self,
        _request: &SubmitCampaignDiscoveryRequest,
    ) -> Result<SubmitCampaignDiscoveryResponse, Self::Error> {
        Err(self.0)
    }
}

impl CampaignService for WrongApplyService {
    type Error = Infallible;

    fn campaign_savepoint(
        &self,
        _request: &crate::CampaignSavepointRequest,
    ) -> Result<crate::CampaignSavepointResponse, Self::Error> {
        panic!("savepoint is not used by this fixed test service")
    }

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

    fn query_campaign_report(
        &self,
        _request: &QueryCampaignReportRequest,
    ) -> Result<QueryCampaignReportResponse, Self::Error> {
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

    fn get_campaign_trace_chunk(
        &self,
        _request: &GetCampaignTraceChunkRequest,
    ) -> Result<GetCampaignTraceChunkResponse, Self::Error> {
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

    fn query_campaign_request_attempts(
        &self,
        _request: &QueryCampaignRequestAttemptsRequest,
    ) -> Result<QueryCampaignRequestAttemptsResponse, Self::Error> {
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

    fn submit_discovery_request(
        &self,
        _request: &SubmitCampaignDiscoveryRequest,
    ) -> Result<SubmitCampaignDiscoveryResponse, Self::Error> {
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
