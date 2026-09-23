//! Complete fixed response service shared by loopback protocol tests.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct FixedCampaignService;

impl CampaignService for FixedCampaignService {
    type Error = Infallible;

    fn list_campaigns(
        &self,
        request: &crucible_campaign::ListCampaignsRequest,
    ) -> Result<crucible_campaign::ListCampaignsResponse, Self::Error> {
        Ok(
            crucible_campaign::ListCampaignsResponse::new(request, Vec::new(), None, 0)
                .expect("list response"),
        )
    }

    fn create_campaign(
        &self,
        request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        Ok(
            CreateCampaignResponse::new(request, snapshot("created"), false)
                .expect("create response"),
        )
    }

    fn derive_campaign(
        &self,
        request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        Ok(DeriveCampaignResponse::new(
            request,
            CampaignDerivationResult {
                source_snapshot: request.source_snapshot(),
                new_snapshot: snapshot("derived"),
                active_policy: request
                    .policy()
                    .map(CampaignPolicy::id)
                    .transpose()
                    .expect("derived policy id")
                    .unwrap_or_else(|| policy("source-policy")),
                replayed: false,
            },
        )
        .expect("derive response"))
    }

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        Ok(GetCampaignResponse::new(
            request,
            snapshot("current"),
            lineage("lineage"),
            policy("policy"),
            policy_body("policy"),
            CampaignState::Running,
        )
        .expect("get response"))
    }

    fn get_campaign_status(
        &self,
        request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        let semantic =
            CampaignSemanticStatus::new(CampaignContinuationStatus::default(), 0, 0, 0, 0)
                .expect("empty semantic status");
        Ok(GetCampaignStatusResponse::new(
            request,
            CampaignStatusSummary::new(semantic, CampaignOperationalStatus::Unavailable),
        )
        .expect("status response"))
    }

    fn query_campaign_report(
        &self,
        request: &crucible_campaign::QueryCampaignReportRequest,
    ) -> Result<crucible_campaign::QueryCampaignReportResponse, Self::Error> {
        let semantic =
            CampaignSemanticStatus::new(CampaignContinuationStatus::default(), 0, 0, 0, 0)
                .expect("empty semantic status");
        let summary = crucible_campaign::CampaignReportSummary::new(
            CampaignState::Running,
            CampaignMode::Strict,
            semantic,
            crucible_campaign::CampaignOutcomeCounts::new(0, 0, 0, 0, 0).expect("empty outcomes"),
            crucible_campaign::CampaignExecutionBasisCounts::new(0, 0, 0, 0),
            crucible_campaign::CampaignPlannerEvidence::new(0, None)
                .expect("empty planner evidence"),
            crucible_campaign::CampaignEstimateSummary::new(
                crucible_campaign::CampaignEstimateLabel::Descriptive,
                0,
                None,
            )
            .expect("descriptive estimate"),
        )
        .expect("empty report summary");
        Ok(crucible_campaign::QueryCampaignReportResponse::new(
            request,
            fixed_query_snapshot().0,
            summary,
            Vec::new(),
        )
        .expect("report response"))
    }

    fn get_campaign_snapshot(
        &self,
        request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        Ok(
            GetCampaignSnapshotResponse::new(request, fixed_query_snapshot().0)
                .expect("snapshot response"),
        )
    }

    fn watch_campaign(
        &self,
        request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error> {
        Ok(WatchCampaignResponse::new(
            request,
            snapshot("current"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        )
        .expect("watch response"))
    }

    fn query_campaign_graph(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        let (snapshot, map, root) = fixed_query_snapshot();
        let (page, proof) = map
            .scan_with_proof(root, request.after(), request.limit() as usize)
            .expect("proven graph page");
        Ok(QueryCampaignGraphResponse::new(
            request,
            snapshot,
            page.entries()
                .iter()
                .map(|(key, object)| crucible_campaign::CampaignGraphEntry::new(*key, *object))
                .collect(),
            page.next_after(),
            proof,
        )
        .expect("graph response"))
    }

    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
        let (snapshot, map, _) = fixed_query_snapshot();
        let (page, proof) = map
            .scan_with_proof(
                snapshot.roots().findings,
                request.after(),
                request.limit() as usize,
            )
            .expect("proven finding page");
        Ok(QueryCampaignFindingsResponse::new(
            request,
            snapshot,
            Vec::new(),
            page.next_after(),
            proof,
        )
        .expect("finding response"))
    }

    fn get_campaign_planner_rankings(
        &self,
        _request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        unreachable!("fixed service has no planner-step fixture")
    }

    fn get_campaign_finding_object(
        &self,
        _request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
        unreachable!("fixed service has no finding dependencies")
    }

    fn explain_campaign_attempt(
        &self,
        _request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
        unreachable!("fixed service has no attempt explanations")
    }

    fn get_campaign_graph_object(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        let (snapshot, map, root) = fixed_query_snapshot();
        let (_, proof) = map
            .get_with_proof(root, request.key())
            .expect("graph-object proof");
        Ok(
            GetCampaignGraphObjectResponse::new(request, snapshot, fixed_graph_object().1, proof)
                .expect("graph-object response"),
        )
    }

    fn query_campaign_choices(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        let (snapshot, map, graph) = fixed_query_snapshot();
        let (_, index_proof) = map
            .get_with_proof(graph, CampaignChoiceEntry::index_anchor_key())
            .expect("choice index proof");
        let choice_index = map
            .get(graph, CampaignChoiceEntry::index_anchor_key())
            .expect("choice index lookup")
            .expect("choice index root");
        let (page, page_proof) = map
            .scan_with_proof(
                choice_index,
                request
                    .after()
                    .map(|after| CampaignChoiceEntry::new(after).index_key()),
                request.limit() as usize,
            )
            .expect("choice page proof");
        let entries = page
            .entries()
            .iter()
            .map(|(_, object)| {
                let entry = fixed_choice_entry();
                assert_eq!(*object, entry.opportunity().content_id());
                entry
            })
            .collect::<Vec<_>>();
        let next_after = page
            .next_after()
            .and_then(|_| entries.last().map(|entry| entry.opportunity()));
        Ok(QueryCampaignChoicesResponse::new(
            request,
            snapshot,
            entries,
            next_after,
            index_proof,
            page_proof,
        )
        .expect("choice response"))
    }

    fn query_campaign_frontier(
        &self,
        request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        let (snapshot, map, _) = fixed_query_snapshot();
        let exploration = snapshot.roots().exploration;
        let (_, index_proof) = map
            .get_with_proof(
                exploration,
                CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b""),
            )
            .expect("frontier index proof");
        let frontier_index = map
            .get(
                exploration,
                CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b""),
            )
            .expect("frontier index lookup")
            .expect("frontier index root");
        let (page, page_proof) = map
            .scan_with_proof(
                frontier_index,
                request
                    .after()
                    .map(|after| CampaignHash::from_bytes(after.content_id().digest())),
                request.limit() as usize,
            )
            .expect("frontier page proof");
        let projection = fixed_frontier_projection();
        let entries = page
            .entries()
            .iter()
            .map(|(_, value)| {
                assert_eq!(*value, projection.id().expect("projection id").content_id());
                projection
            })
            .collect::<Vec<_>>();
        let next_after = page
            .next_after()
            .and_then(|_| entries.last().map(|entry| entry.request()));
        Ok(QueryCampaignFrontierResponse::new(
            request,
            snapshot,
            entries,
            next_after,
            index_proof,
            page_proof,
        )
        .expect("frontier response"))
    }

    fn get_campaign_frontier_object(
        &self,
        request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
        let (snapshot, map, _) = fixed_query_snapshot();
        let exploration = snapshot.roots().exploration;
        let anchor = CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b"");
        let (_, index_proof) = map
            .get_with_proof(exploration, anchor)
            .expect("frontier-object index proof");
        let frontier_index = map
            .get(exploration, anchor)
            .expect("frontier-object index lookup")
            .expect("frontier-object index root");
        let (_, object_proof) = map
            .get_with_proof(
                frontier_index,
                CampaignHash::from_bytes(request.request().content_id().digest()),
            )
            .expect("frontier-object membership proof");
        Ok(GetCampaignFrontierObjectResponse::new(
            request,
            snapshot,
            fixed_frontier_projection(),
            branch_submission("network-recovery").request().clone(),
            index_proof,
            object_proof,
        )
        .expect("frontier-object response"))
    }

    fn get_campaign_choice_object(
        &self,
        request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
        let (snapshot, map, graph) = fixed_query_snapshot();
        let (declaration, domain, opportunity) = fixed_choice_objects();
        let (_, proof) = map
            .get_with_proof(
                graph,
                CampaignChoiceEntry::new(request.opportunity()).graph_key(),
            )
            .expect("choice-object opportunity proof");
        let object = match request.kind() {
            CampaignChoiceObjectKind::Declaration => CampaignChoiceObject::Declaration(declaration),
            CampaignChoiceObjectKind::Domain => CampaignChoiceObject::Domain(domain),
        };
        Ok(
            GetCampaignChoiceObjectResponse::new(request, snapshot, opportunity, object, proof)
                .expect("choice-object response"),
        )
    }

    fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        Ok(ApplyCampaignCommandResponse::new(
            request,
            CampaignCommandResult {
                prior_snapshot: request.command().expected_snapshot,
                new_snapshot: snapshot("command-next"),
                replayed: false,
            },
        )
        .expect("command response"))
    }

    fn pin_campaign(
        &self,
        request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error> {
        Ok(PinCampaignResponse::new(
            request,
            CampaignCommandResult {
                prior_snapshot: request.command().expected_snapshot,
                new_snapshot: snapshot("pin-next"),
                replayed: false,
            },
        )
        .expect("pin response"))
    }

    fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        let branch_request = request.request();
        let summary = BranchAcceptanceSummary::new(
            BranchAcceptanceCount::Exact(1),
            BranchAcceptanceCount::Exact(0),
            BranchAcceptanceCount::Exact(1),
            branch_request.budget().maximum_proposals(),
            branch_request.budget().maximum_attempts(),
        )
        .expect("branch acceptance summary");
        let request_id = branch_request.id().expect("branch request ID");
        let acceptance_fact = CampaignFact::BranchRequestAccepted {
            request: request_id,
            summary,
        };
        let root = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"branch-response-root");
        let snapshot = CampaignSnapshot::successor(
            request.expected_snapshot(),
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
            acceptance_fact.id().expect("acceptance fact ID"),
            CampaignBudgetLedger::empty(root)
                .expect("response ledger")
                .id()
                .expect("response ledger ID"),
        )
        .expect("accepted branch snapshot");
        Ok(SubmitCampaignBranchResponse::new(
            request,
            BranchRequestResult {
                prior_snapshot: request.expected_snapshot(),
                new_snapshot: snapshot.id().expect("accepted snapshot ID"),
                request: request_id,
                summary,
                snapshot,
                acceptance_fact,
                replayed: false,
            },
        )
        .expect("branch response"))
    }

    fn submit_discovery_request(
        &self,
        request: &SubmitCampaignDiscoveryRequest,
    ) -> Result<SubmitCampaignDiscoveryResponse, Self::Error> {
        let attempt = crucible_campaign::AttemptId::parse(&format!(
            "crucible.campaign.attempt@{}",
            ContentId::for_bytes(
                ObjectKind::CampaignFact,
                crucible_campaign::CampaignRecordKind::Attempt.schema_version(),
                b"discovery-attempt",
            )
            .encode()
        ))
        .expect("attempt id");
        let admission = crucible_campaign::AttemptAdmissionId::parse(&format!(
            "crucible.campaign.attempt-admission@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 3, b"discovery-admission").encode()
        ))
        .expect("admission id");
        Ok(SubmitCampaignDiscoveryResponse::new(
            request,
            CampaignDiscoveryResult {
                prior_snapshot: request.command().expected_snapshot,
                new_snapshot: snapshot("discovery-next"),
                attempt,
                admission,
                replayed: false,
            },
        )
        .expect("discovery response"))
    }
}

impl CampaignFindingOccurrenceService for FixedCampaignService {
    fn query_campaign_finding_occurrences(
        &self,
        _request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, Self::Error> {
        unreachable!("fixed service has no finding occurrences")
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        _request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, Self::Error> {
        unreachable!("fixed service has no finding occurrence dependencies")
    }

    fn get_campaign_finding_triage_replay_segment(
        &self,
        _request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<GetCampaignFindingTriageReplaySegmentResponse, Self::Error> {
        unreachable!("fixed service has no finding triage replay segments")
    }
}
