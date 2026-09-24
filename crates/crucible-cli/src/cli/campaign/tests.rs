//! Unit tests for campaign CLI command handling.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

#[path = "tests/explain_queries.rs"]
mod explain_queries;
#[path = "tests/render_status.rs"]
mod render_status;

use super::*;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_campaign::*;
use crucible_cas::content_store::{ContentId, MemoryBlobBackend, ObjectKind};

#[derive(Clone, Copy)]
struct FixedHeadService;

struct StatusSequenceService {
    calls: Arc<StatusSequenceCalls>,
    stale_statuses: usize,
    terminal_failure: Option<CampaignServiceFailure>,
}

#[derive(Default)]
struct StatusSequenceCalls {
    get: AtomicUsize,
    status: AtomicUsize,
}

macro_rules! unreachable_status_sequence_operations {
    ($(fn $name:ident($request:ty) -> $response:ty;)*) => {
        $(
            fn $name(&self, _request: &$request) -> Result<$response, Self::Error> {
                unreachable!(concat!(stringify!($name), " is not used by the status retry fixture"))
            }
        )*
    };
}

struct GraphPageService {
    map: MerkleMap,
    root: ContentId,
    snapshot: CampaignSnapshot,
    active_policy_body: CampaignPolicy,
    snapshots: BTreeMap<CampaignSnapshotId, CampaignSnapshot>,
    object_key: CampaignHash,
    object: ObjectEnvelope,
    declaration: SelectableDeclaration,
    domain: ChoiceDomain,
    opportunity: ChoiceOpportunity,
    additional_choices: Vec<(ChoiceOpportunity, SelectableDeclaration, ChoiceDomain)>,
    branch_request: BranchRequest,
    frontier_projection: ContinuationProjection,
    finding: Finding,
    finding_root: ContentId,
    finding_observation: Observation,
    finding_reproduction: ReproductionArtifact,
    attempt: Attempt,
    attempt_admission: AttemptAdmission,
    attempt_path: BranchPath,
    attempt_selection: Selection,
    attempt_proposal: Proposal,
}

fn budget_ledger(label: &str) -> CampaignBudgetLedgerId {
    CampaignBudgetLedgerId::parse(&fixture_record_id(CampaignRecordKind::BudgetLedger, label))
        .expect("current budget-ledger ID")
}

macro_rules! impl_unused_finding_occurrence_service {
    ($service:ty) => {
        impl CampaignFindingOccurrenceService for $service {
            fn query_campaign_finding_occurrences(
                &self,
                _request: &QueryCampaignFindingOccurrencesRequest,
            ) -> Result<QueryCampaignFindingOccurrencesResponse, Self::Error> {
                unreachable!("unused campaign finding occurrence query")
            }

            fn get_campaign_finding_occurrence_object(
                &self,
                _request: &GetCampaignFindingOccurrenceObjectRequest,
            ) -> Result<GetCampaignFindingOccurrenceObjectResponse, Self::Error> {
                unreachable!("unused campaign finding occurrence object query")
            }

            fn get_campaign_finding_triage_replay_segment(
                &self,
                _request: &GetCampaignFindingTriageReplaySegmentRequest,
            ) -> Result<GetCampaignFindingTriageReplaySegmentResponse, Self::Error> {
                unreachable!("unused campaign finding triage replay segment query")
            }
        }
    };
}

impl_unused_finding_occurrence_service!(FixedHeadService);
impl_unused_finding_occurrence_service!(GraphPageService);

fn fixed_branch_response(
    request: &SubmitCampaignBranchRequest,
    label: &str,
) -> SubmitCampaignBranchResponse {
    let budget = request.request().budget();
    let cardinality = request
        .request()
        .source()
        .finite_values()
        .map_or_else(
            || BranchAcceptanceCount::between(0, budget.maximum_proposals()),
            |values| {
                u64::try_from(values.len())
                    .map(BranchAcceptanceCount::Exact)
                    .map_err(|_| CampaignCodecError::LimitExceeded {
                        limit: "test-branch-cardinality",
                    })
            },
        )
        .expect("branch cardinality");
    let remaining = match cardinality.exact() {
        Some(count) => BranchAcceptanceCount::Exact(count.min(budget.maximum_proposals())),
        None => BranchAcceptanceCount::between(0, budget.maximum_proposals())
            .expect("branch remaining bounds"),
    };
    let summary = BranchAcceptanceSummary::new(
        cardinality,
        BranchAcceptanceCount::Exact(0),
        remaining,
        budget.maximum_proposals(),
        budget.maximum_attempts(),
    )
    .expect("branch acceptance summary");
    let acceptance_fact = CampaignFact::BranchRequestAccepted {
        request: request.request().id().expect("branch request ID"),
        summary,
    };
    let root = ContentId::for_bytes(ObjectKind::MerkleNode, 1, label.as_bytes());
    let accepted = CampaignSnapshot::successor(
        request.expected_snapshot(),
        lineage(label),
        policy(label),
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
        budget_ledger(label),
    )
    .expect("accepted snapshot");

    SubmitCampaignBranchResponse::new(
        request,
        BranchRequestResult {
            prior_snapshot: request.expected_snapshot(),
            new_snapshot: accepted.id().expect("accepted snapshot ID"),
            request: request.request().id().expect("branch request ID"),
            summary,
            snapshot: accepted,
            acceptance_fact,
            replayed: false,
        },
    )
    .expect("fixed branch response")
}

impl CampaignService for FixedHeadService {
    type Error = Infallible;

    fn list_campaigns(
        &self,
        request: &crucible_campaign::ListCampaignsRequest,
    ) -> Result<crucible_campaign::ListCampaignsResponse, Self::Error> {
        let (name, next_after) = match request.after().map(CampaignName::as_str) {
            None => ("alpha", Some(CampaignName::new("alpha").expect("cursor"))),
            Some("alpha") => ("middle", None),
            _ => {
                return Ok(crucible_campaign::ListCampaignsResponse::new(
                    request,
                    Vec::new(),
                    None,
                    0,
                )
                .expect("empty list response"));
            }
        };
        Ok(crucible_campaign::ListCampaignsResponse::new(
            request,
            vec![crucible_campaign::CampaignListEntry::new(
                CampaignName::new(name).expect("campaign name"),
                snapshot(name),
                lineage("lineage"),
                policy("policy"),
                CampaignState::Running,
            )],
            next_after,
            1,
        )
        .expect("list response"))
    }

    fn create_campaign(
        &self,
        request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        Ok(
            CreateCampaignResponse::new(request, snapshot("created"), false)
                .expect("fixed create response"),
        )
    }

    fn derive_campaign(
        &self,
        request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        let active_policy = request
            .policy()
            .map(CampaignPolicy::id)
            .transpose()
            .expect("derived policy ID")
            .unwrap_or_else(|| policy("policy"));
        Ok(DeriveCampaignResponse::new(
            request,
            CampaignDerivationResult {
                source_snapshot: request.source_snapshot(),
                new_snapshot: snapshot("derived"),
                active_policy,
                replayed: false,
            },
        )
        .expect("fixed derive response"))
    }

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        let policy_body = campaign_records().1;
        Ok(GetCampaignResponse::new(
            request,
            snapshot("current"),
            lineage("lineage"),
            policy_body.id().expect("fixed policy ID"),
            policy_body,
            CampaignState::Running,
        )
        .expect("fixed get response"))
    }

    fn get_campaign_status(
        &self,
        request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        Ok(render_status::fixed_campaign_status_response(request))
    }

    fn query_campaign_report(
        &self,
        _request: &crucible_campaign::QueryCampaignReportRequest,
    ) -> Result<crucible_campaign::QueryCampaignReportResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign_snapshot(
        &self,
        _request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
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
        .expect("fixed watch response"))
    }

    fn query_campaign_graph(
        &self,
        _request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn query_campaign_findings(
        &self,
        _request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign_finding_object(
        &self,
        _request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn explain_campaign_attempt(
        &self,
        _request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign_trace_chunk(
        &self,
        _request: &GetCampaignTraceChunkRequest,
    ) -> Result<GetCampaignTraceChunkResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn query_campaign_request_attempts(
        &self,
        _request: &QueryCampaignRequestAttemptsRequest,
    ) -> Result<QueryCampaignRequestAttemptsResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign_planner_rankings(
        &self,
        _request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign_graph_object(
        &self,
        _request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn query_campaign_choices(
        &self,
        _request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn query_campaign_frontier(
        &self,
        _request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign_frontier_object(
        &self,
        _request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign_choice_object(
        &self,
        _request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn apply_campaign_command(
        &self,
        request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        assert!(matches!(
            request.command().action,
            CampaignControlAction::Pause(ActiveAttemptPolicy::ExactCheckpoint)
                | CampaignControlAction::Resume
        ));
        let next = match request.command().action {
            CampaignControlAction::Resume => snapshot("started"),
            _ => snapshot("mutated"),
        };
        Ok(ApplyCampaignCommandResponse::new(
            request,
            CampaignCommandResult {
                prior_snapshot: request.command().expected_snapshot,
                new_snapshot: next,
                replayed: false,
            },
        )
        .expect("fixed campaign mutation response"))
    }

    fn pin_campaign(
        &self,
        request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error> {
        Ok(PinCampaignResponse::new(
            request,
            CampaignCommandResult {
                prior_snapshot: request.command().expected_snapshot,
                new_snapshot: snapshot("pinned"),
                replayed: false,
            },
        )
        .expect("fixed campaign pin response"))
    }

    fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        Ok(fixed_branch_response(request, "branched"))
    }

    fn submit_discovery_request(
        &self,
        _request: &SubmitCampaignDiscoveryRequest,
    ) -> Result<SubmitCampaignDiscoveryResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }
}

impl CampaignService for StatusSequenceService {
    type Error = CampaignServiceFailure;

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        let get_index = self.calls.get.fetch_add(1, Ordering::SeqCst);
        let head = render_status::status_sequence_head(get_index);
        let policy_body = campaign_records().1;

        Ok(GetCampaignResponse::new(
            request,
            head,
            lineage("lineage"),
            policy_body.id().expect("scripted policy ID"),
            policy_body,
            CampaignState::Running,
        )
        .expect("scripted get response"))
    }

    fn get_campaign_status(
        &self,
        request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        let status_index = self.calls.status.fetch_add(1, Ordering::SeqCst);
        if let Some(failure) = self.terminal_failure {
            return Err(failure);
        }
        if status_index < self.stale_statuses {
            return Err(CampaignServiceFailure::Stale {
                expected: request.snapshot(),
                current: render_status::status_sequence_head(status_index + 1),
            });
        }

        Ok(render_status::fixed_campaign_status_response(request))
    }

    unreachable_status_sequence_operations! {
        fn list_campaigns(ListCampaignsRequest) -> ListCampaignsResponse;
        fn create_campaign(CreateCampaignRequest) -> CreateCampaignResponse;
        fn derive_campaign(DeriveCampaignRequest) -> DeriveCampaignResponse;
        fn get_campaign_snapshot(GetCampaignSnapshotRequest) -> GetCampaignSnapshotResponse;
        fn query_campaign_report(crucible_campaign::QueryCampaignReportRequest) -> crucible_campaign::QueryCampaignReportResponse;
        fn watch_campaign(WatchCampaignRequest) -> WatchCampaignResponse;
        fn query_campaign_graph(QueryCampaignGraphRequest) -> QueryCampaignGraphResponse;
        fn get_campaign_graph_object(GetCampaignGraphObjectRequest) -> GetCampaignGraphObjectResponse;
        fn query_campaign_choices(QueryCampaignChoicesRequest) -> QueryCampaignChoicesResponse;
        fn query_campaign_frontier(QueryCampaignFrontierRequest) -> QueryCampaignFrontierResponse;
        fn query_campaign_findings(QueryCampaignFindingsRequest) -> QueryCampaignFindingsResponse;
        fn get_campaign_finding_object(GetCampaignFindingObjectRequest) -> GetCampaignFindingObjectResponse;
        fn explain_campaign_attempt(ExplainCampaignAttemptRequest) -> ExplainCampaignAttemptResponse;
        fn get_campaign_trace_chunk(GetCampaignTraceChunkRequest) -> GetCampaignTraceChunkResponse;
        fn query_campaign_request_attempts(QueryCampaignRequestAttemptsRequest) -> QueryCampaignRequestAttemptsResponse;
        fn get_campaign_planner_rankings(GetCampaignPlannerRankingsRequest) -> GetCampaignPlannerRankingsResponse;
        fn get_campaign_frontier_object(GetCampaignFrontierObjectRequest) -> GetCampaignFrontierObjectResponse;
        fn get_campaign_choice_object(GetCampaignChoiceObjectRequest) -> GetCampaignChoiceObjectResponse;
        fn apply_campaign_command(ApplyCampaignCommandRequest) -> ApplyCampaignCommandResponse;
        fn pin_campaign(PinCampaignRequest) -> PinCampaignResponse;
        fn submit_branch_request(SubmitCampaignBranchRequest) -> SubmitCampaignBranchResponse;
        fn submit_discovery_request(SubmitCampaignDiscoveryRequest) -> SubmitCampaignDiscoveryResponse;
    }
}

impl CampaignService for GraphPageService {
    type Error = Infallible;

    fn list_campaigns(
        &self,
        _request: &crucible_campaign::ListCampaignsRequest,
    ) -> Result<crucible_campaign::ListCampaignsResponse, Self::Error> {
        unreachable!("graph-page service does not list campaigns")
    }

    fn create_campaign(
        &self,
        _request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn derive_campaign(
        &self,
        _request: &DeriveCampaignRequest,
    ) -> Result<DeriveCampaignResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        Ok(GetCampaignResponse::new(
            request,
            self.snapshot.id().expect("graph head ID"),
            self.snapshot.lineage(),
            self.snapshot.active_policy(),
            self.active_policy_body.clone(),
            CampaignState::Running,
        )
        .expect("graph head with authenticated policy"))
    }

    fn get_campaign_status(
        &self,
        _request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn query_campaign_report(
        &self,
        request: &crucible_campaign::QueryCampaignReportRequest,
    ) -> Result<crucible_campaign::QueryCampaignReportResponse, Self::Error> {
        Ok(crucible_campaign::QueryCampaignReportResponse::new(
            request,
            self.snapshot.clone(),
            empty_report_summary(),
            Vec::new(),
        )
        .expect("fixed report response"))
    }

    fn get_campaign_snapshot(
        &self,
        request: &GetCampaignSnapshotRequest,
    ) -> Result<GetCampaignSnapshotResponse, Self::Error> {
        let snapshot = self
            .snapshots
            .get(&request.snapshot())
            .expect("requested fixture snapshot")
            .clone();
        Ok(GetCampaignSnapshotResponse::new(request, snapshot)
            .expect("bound campaign snapshot response"))
    }

    fn watch_campaign(
        &self,
        _request: &WatchCampaignRequest,
    ) -> Result<WatchCampaignResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn query_campaign_graph(
        &self,
        request: &QueryCampaignGraphRequest,
    ) -> Result<QueryCampaignGraphResponse, Self::Error> {
        let (page, proof) = self
            .map
            .scan_with_proof(self.root, request.after(), request.limit() as usize)
            .expect("proof-bearing graph page");
        let entries = page
            .entries()
            .iter()
            .map(|(key, object)| CampaignGraphEntry::new(*key, *object))
            .collect();
        Ok(QueryCampaignGraphResponse::new(
            request,
            self.snapshot.clone(),
            entries,
            page.next_after(),
            proof,
        )
        .expect("bound graph response"))
    }

    fn query_campaign_findings(
        &self,
        request: &QueryCampaignFindingsRequest,
    ) -> Result<QueryCampaignFindingsResponse, Self::Error> {
        let (page, proof) = self
            .map
            .scan_with_proof(self.finding_root, request.after(), request.limit() as usize)
            .expect("proof-bearing finding page");
        Ok(QueryCampaignFindingsResponse::new(
            request,
            self.snapshot.clone(),
            vec![self.finding.clone()],
            page.next_after(),
            proof,
        )
        .expect("bound finding response"))
    }

    fn get_campaign_finding_object(
        &self,
        request: &GetCampaignFindingObjectRequest,
    ) -> Result<GetCampaignFindingObjectResponse, Self::Error> {
        assert_eq!(
            request.finding(),
            self.finding.id().expect("explanation finding ID")
        );
        let (_, proof) = self
            .map
            .get_with_proof(
                self.finding_root,
                finding_index_key(self.finding.signature().cluster_key()),
            )
            .expect("finding explanation membership proof");
        let object = match request.kind() {
            CampaignFindingObjectKind::Observation => {
                CampaignFindingObject::Observation(self.finding_observation.clone())
            }
            CampaignFindingObjectKind::LatestOccurrence => {
                CampaignFindingObject::LatestOccurrence(self.finding_observation.clone())
            }
            CampaignFindingObjectKind::Reproduction => {
                CampaignFindingObject::Reproduction(self.finding_reproduction.clone())
            }
            CampaignFindingObjectKind::MinimizedReproduction => {
                unreachable!("fixture finding has no minimized reproduction")
            }
        };
        Ok(GetCampaignFindingObjectResponse::new(
            request,
            self.snapshot.clone(),
            self.finding.clone(),
            object,
            proof,
        )
        .expect("bound finding explanation response"))
    }

    fn explain_campaign_attempt(
        &self,
        request: &ExplainCampaignAttemptRequest,
    ) -> Result<ExplainCampaignAttemptResponse, Self::Error> {
        assert_eq!(
            request.attempt(),
            self.attempt.id().expect("explanation attempt ID")
        );
        let roots = self.snapshot.roots();
        let (_, attempt_proof) = self
            .map
            .get_with_proof(
                roots.accounting,
                content_index_key("accounting.attempt", request.attempt().content_id()),
            )
            .expect("attempt explanation proof");
        let (_, admission_proof) = self
            .map
            .get_with_proof(
                roots.accounting,
                content_index_key(
                    "accounting.attempt-execution-basis",
                    request.attempt().content_id(),
                ),
            )
            .expect("attempt admission explanation proof");
        let branch_provenance = matches!(self.attempt.start(), AttemptStart::Branch { .. });
        let proposal_proof = branch_provenance.then(|| {
            let proposal_id = self
                .attempt_proposal
                .id()
                .expect("attempt explanation proposal ID");
            let (_, proof) = self
                .map
                .get_with_proof(
                    roots.exploration,
                    content_index_key("exploration.proposal", proposal_id.content_id()),
                )
                .expect("attempt proposal explanation proof");
            proof
        });
        let (observation_id, observation_proof) = self
            .map
            .get_with_proof(
                roots.observations,
                content_index_key("observations.attempt", request.attempt().content_id()),
            )
            .expect("attempt observation explanation proof");
        let observation = observation_id.map(|_| self.finding_observation.clone());
        Ok(ExplainCampaignAttemptResponse::new(
            request,
            self.snapshot.clone(),
            self.attempt.clone(),
            self.attempt_admission,
            self.attempt_path.clone(),
            branch_provenance.then(|| self.attempt_selection.clone()),
            branch_provenance.then(|| self.attempt_proposal.clone()),
            None,
            observation,
            attempt_proof,
            admission_proof,
            proposal_proof,
            None,
            observation_proof,
        )
        .expect("bound attempt explanation response"))
    }

    fn get_campaign_trace_chunk(
        &self,
        _request: &GetCampaignTraceChunkRequest,
    ) -> Result<GetCampaignTraceChunkResponse, Self::Error> {
        unreachable!("graph-page fixture does not retain trace leaves")
    }

    fn query_campaign_request_attempts(
        &self,
        _request: &QueryCampaignRequestAttemptsRequest,
    ) -> Result<QueryCampaignRequestAttemptsResponse, Self::Error> {
        unreachable!("graph-page fixture does not retain request attempt links")
    }

    fn get_campaign_planner_rankings(
        &self,
        _request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        unreachable!("graph fixture has no retained planner request")
    }

    fn get_campaign_graph_object(
        &self,
        request: &GetCampaignGraphObjectRequest,
    ) -> Result<GetCampaignGraphObjectResponse, Self::Error> {
        assert_eq!(request.key(), self.object_key);
        let (_, proof) = self
            .map
            .get_with_proof(self.root, request.key())
            .expect("proof-bearing graph object");
        Ok(GetCampaignGraphObjectResponse::new(
            request,
            self.snapshot.clone(),
            self.object.clone(),
            proof,
        )
        .expect("bound graph object response"))
    }

    fn query_campaign_choices(
        &self,
        request: &QueryCampaignChoicesRequest,
    ) -> Result<QueryCampaignChoicesResponse, Self::Error> {
        let graph = self.snapshot.roots().graph;
        let (_, index_proof) = self
            .map
            .get_with_proof(graph, CampaignChoiceEntry::index_anchor_key())
            .expect("selector choice index proof");
        let index = self
            .map
            .get(graph, CampaignChoiceEntry::index_anchor_key())
            .expect("selector choice index lookup")
            .expect("selector choice index root");
        let (page, page_proof) = self
            .map
            .scan_with_proof(
                index,
                request
                    .after()
                    .map(|value| CampaignChoiceEntry::new(value).index_key()),
                usize::try_from(request.limit()).expect("selector page limit"),
            )
            .expect("selector choice page proof");
        let entries = page
            .entries()
            .iter()
            .map(|(_, value)| {
                let selected = std::iter::once(&self.opportunity)
                    .chain(self.additional_choices.iter().map(|(value, _, _)| value))
                    .find_map(|candidate| {
                        let id = candidate.id().expect("selector opportunity ID");
                        (id.content_id() == *value).then_some(id)
                    })
                    .expect("selector indexed opportunity ID");
                CampaignChoiceEntry::new(selected)
            })
            .collect();
        Ok(QueryCampaignChoicesResponse::new(
            request,
            self.snapshot.clone(),
            entries,
            page.next_after().map(|_| {
                page.entries()
                    .last()
                    .and_then(|(_, value)| {
                        std::iter::once(&self.opportunity)
                            .chain(
                                self.additional_choices
                                    .iter()
                                    .map(|(candidate, _, _)| candidate),
                            )
                            .find_map(|candidate| {
                                let id = candidate.id().expect("selector opportunity ID");
                                (id.content_id() == *value).then_some(id)
                            })
                    })
                    .expect("selector page cursor opportunity")
            }),
            index_proof,
            page_proof,
        )
        .expect("bound selector choice page"))
    }

    fn query_campaign_frontier(
        &self,
        request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        let exploration = self.snapshot.roots().exploration;
        let anchor = CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b"");
        let (_, index_proof) = self
            .map
            .get_with_proof(exploration, anchor)
            .expect("frontier query index proof");
        let frontier_index = self
            .map
            .get(exploration, anchor)
            .expect("frontier query index lookup")
            .expect("frontier query index root");
        let (page, page_proof) = self
            .map
            .scan_with_proof(
                frontier_index,
                request
                    .after()
                    .map(|after| CampaignHash::from_bytes(after.content_id().digest())),
                request.limit() as usize,
            )
            .expect("frontier query page proof");
        let entries = page
            .entries()
            .iter()
            .map(|(_, value)| {
                assert_eq!(
                    *value,
                    self.frontier_projection
                        .id()
                        .expect("frontier projection ID")
                        .content_id()
                );
                self.frontier_projection
            })
            .collect::<Vec<_>>();
        let next_after = page
            .next_after()
            .and_then(|_| entries.last().map(|entry| entry.request()));
        Ok(QueryCampaignFrontierResponse::new(
            request,
            self.snapshot.clone(),
            entries,
            next_after,
            index_proof,
            page_proof,
        )
        .expect("bound frontier query response"))
    }

    fn get_campaign_frontier_object(
        &self,
        request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
        assert_eq!(request.request(), self.frontier_projection.request());
        let exploration = self.snapshot.roots().exploration;
        let anchor = CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b"");
        let (_, index_proof) = self
            .map
            .get_with_proof(exploration, anchor)
            .expect("frontier explanation index proof");
        let frontier_index = self
            .map
            .get(exploration, anchor)
            .expect("frontier explanation index lookup")
            .expect("frontier explanation index root");
        let (_, object_proof) = self
            .map
            .get_with_proof(
                frontier_index,
                CampaignHash::from_bytes(request.request().content_id().digest()),
            )
            .expect("frontier explanation membership proof");
        Ok(GetCampaignFrontierObjectResponse::new(
            request,
            self.snapshot.clone(),
            self.frontier_projection,
            self.branch_request.clone(),
            index_proof,
            object_proof,
        )
        .expect("bound frontier explanation response"))
    }

    fn get_campaign_choice_object(
        &self,
        request: &GetCampaignChoiceObjectRequest,
    ) -> Result<GetCampaignChoiceObjectResponse, Self::Error> {
        let (opportunity, declaration, domain) = if request.opportunity()
            == self.opportunity.id().expect("explanation opportunity ID")
        {
            (&self.opportunity, &self.declaration, &self.domain)
        } else {
            let (opportunity, declaration, domain) = self
                .additional_choices
                .iter()
                .find(|(value, _, _)| {
                    value.id().expect("additional opportunity ID") == request.opportunity()
                })
                .expect("requested choice fixture");
            (opportunity, declaration, domain)
        };
        let (_, proof) = self
            .map
            .get_with_proof(
                self.snapshot.roots().graph,
                CampaignChoiceEntry::new(request.opportunity()).graph_key(),
            )
            .expect("choice explanation membership proof");
        let object = match request.kind() {
            CampaignChoiceObjectKind::Declaration => {
                CampaignChoiceObject::Declaration(declaration.clone())
            }
            CampaignChoiceObjectKind::Domain => CampaignChoiceObject::Domain(domain.clone()),
        };
        Ok(GetCampaignChoiceObjectResponse::new(
            request,
            self.snapshot.clone(),
            opportunity.clone(),
            object,
            proof,
        )
        .expect("bound choice explanation response"))
    }

    fn apply_campaign_command(
        &self,
        _request: &ApplyCampaignCommandRequest,
    ) -> Result<ApplyCampaignCommandResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn pin_campaign(
        &self,
        _request: &PinCampaignRequest,
    ) -> Result<PinCampaignResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn submit_branch_request(
        &self,
        request: &SubmitCampaignBranchRequest,
    ) -> Result<SubmitCampaignBranchResponse, Self::Error> {
        Ok(fixed_branch_response(request, "graph-page-branched"))
    }

    fn submit_discovery_request(
        &self,
        _request: &SubmitCampaignDiscoveryRequest,
    ) -> Result<SubmitCampaignDiscoveryResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }
}

#[test]
fn campaign_runtime_attachment_validates_before_connect_and_renders_status() {
    let valid = CampaignCommand::Attach(CampaignAttachArgs {
        name: "example".to_owned(),
        executor_socket: PathBuf::from("/run/crucible/executor.sock"),
    });
    validate_campaign_command(&valid).expect("absolute runtime attachment");

    let relative = CampaignCommand::Attach(CampaignAttachArgs {
        name: "example".to_owned(),
        executor_socket: PathBuf::from("executor.sock"),
    });
    assert!(
        validate_campaign_command(&relative)
            .expect_err("relative executor path")
            .to_string()
            .contains("executor endpoint is invalid")
    );

    let report = CampaignRuntimeAttachmentReport {
        schema: CAMPAIGN_RUNTIME_ATTACHMENT_REPORT_SCHEMA,
        operation: "attach-runtime",
        campaign: "example".to_owned(),
        request_digest: hash("runtime-attachment").to_hex(),
        disposition: "replayed",
        attached_runtime_count: 2,
    };
    let json = render_campaign_runtime_attachment(&report, OutputFormat::Json)
        .expect("runtime attachment JSON");
    let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(decoded["schema"], CAMPAIGN_RUNTIME_ATTACHMENT_REPORT_SCHEMA);
    assert_eq!(decoded["disposition"], "replayed");
    assert_eq!(decoded["attached_runtime_count"], 2);
    let table = render_campaign_runtime_attachment(&report, OutputFormat::Table)
        .expect("runtime attachment table");
    assert!(table.contains("attached_runtimes  2"));
}

#[test]
fn campaign_graph_aggregation_follows_checked_pages_to_authenticated_eof() {
    let (service, snapshot, _) = graph_page_service();
    let client = CampaignClient::new(service);
    let principal = CampaignPrincipal::new("operator").expect("campaign principal");
    let first = CampaignCommand::Graph(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        after: None,
        limit: 1,
        pages: 1,
    });
    let first_report =
        query_campaign_page(&client, principal.clone(), &first).expect("checked first graph page");
    let cursor = first_report
        .next_after
        .clone()
        .expect("first page continuation");
    assert!(!first_report.complete);
    assert_eq!(first_report.pages_scanned, 1);

    let remainder = CampaignCommand::Graph(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        after: Some(cursor.clone()),
        limit: 1,
        pages: MAX_CAMPAIGN_PAGE_FOLLOW_PAGES,
    });
    let remainder_report =
        query_campaign_page(&client, principal, &remainder).expect("checked graph remainder");

    assert_eq!(
        remainder_report.start_after.as_deref(),
        Some(cursor.as_str())
    );
    assert_eq!(remainder_report.page_limit, 1);
    assert_eq!(remainder_report.page_budget, MAX_CAMPAIGN_PAGE_FOLLOW_PAGES);
    assert!(remainder_report.pages_scanned > 1);
    assert!(remainder_report.response_bytes > 0);
    assert!(remainder_report.complete);
    assert!(remainder_report.next_after.is_none());
    assert!(remainder_report.entries.len() > 1);
    assert!(first_report.entries.iter().all(|first_entry| {
        remainder_report.entries.iter().all(|entry| {
            campaign_page_entry_row(first_entry, "\0") != campaign_page_entry_row(entry, "\0")
        })
    }));
}

#[test]
fn campaign_choice_frontier_and_finding_pages_use_checked_query_paths() {
    let (service, snapshot, _) = graph_page_service();
    let expected_opportunity = service
        .opportunity
        .id()
        .expect("choice opportunity identity");
    let expected_request = service
        .branch_request
        .id()
        .expect("frontier request identity");
    let expected_branch_point = service.branch_request.branch_point();
    let expected_finding = service.finding.id().expect("finding identity");
    let expected_cluster = service.finding.signature().cluster_key();
    let expected_observation = service.finding.observation();
    let expected_reproduction = service.finding.reproduction();
    let client = CampaignClient::new(service);
    let principal = CampaignPrincipal::new("operator").expect("campaign principal");

    let choices = query_campaign_page(
        &client,
        principal.clone(),
        &CampaignCommand::Choices(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            after: None,
            limit: 1,
            pages: 1,
        }),
    )
    .expect("checked choice page");
    assert_eq!(choices.schema, CAMPAIGN_PAGE_REPORT_SCHEMA);
    assert!(choices.complete);
    assert!(matches!(
        choices.entries.as_slice(),
        [CampaignPageEntry::Choice { opportunity }]
            if opportunity == &expected_opportunity.to_string()
    ));

    let frontier = query_campaign_page(
        &client,
        principal.clone(),
        &CampaignCommand::Frontier(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            after: None,
            limit: 1,
            pages: 1,
        }),
    )
    .expect("checked frontier page");
    assert!(frontier.complete);
    assert!(matches!(
        frontier.entries.as_slice(),
        [CampaignPageEntry::Frontier {
            request,
            branch_point,
            state: "ready",
            completed_visits: None,
            required_visits: None,
        }] if request == &expected_request.to_string()
            && branch_point == &expected_branch_point.to_string()
    ));

    let findings = query_campaign_page(
        &client,
        principal,
        &CampaignCommand::Findings(CampaignPageArgs {
            name: "example".to_owned(),
            snapshot: snapshot.to_string(),
            after: None,
            limit: 1,
            pages: 1,
        }),
    )
    .expect("checked finding page");
    assert!(findings.complete);
    assert!(matches!(
        findings.entries.as_slice(),
        [CampaignPageEntry::Finding {
            finding,
            cluster,
            observation,
            occurrences: 3,
            reproduction,
            ..
        }] if finding == &expected_finding.to_string()
            && cluster == &expected_cluster.to_hex()
            && observation == &expected_observation.to_string()
            && reproduction == &expected_reproduction.to_string()
    ));
}

#[test]
fn campaign_list_follows_checked_pages_to_authenticated_eof() {
    let client = CampaignClient::new(FixedHeadService);
    let args = CampaignListArgs {
        after: None,
        limit: 1,
        pages: 2,
    };
    let report = query_campaign_list(
        &client,
        CampaignPrincipal::new("operator:alice").expect("principal"),
        &args,
    )
    .expect("campaign list");

    assert!(report.complete);
    assert_eq!(report.pages_scanned, 2);
    assert_eq!(report.next_after, None);
    assert_eq!(
        report
            .entries
            .iter()
            .map(|entry| entry.campaign.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "middle"]
    );
    let rendered = render_campaign_list(&report, OutputFormat::Json).expect("render list");
    assert!(rendered.contains("crucible.cli.campaign-list.v1"));
    assert!(rendered.contains("\"campaign\": \"middle\""));
    assert!(
        render_campaign_list(&report, OutputFormat::Table)
            .expect("render list table")
            .contains("middle")
    );
    assert!(
        render_campaign_list(&report, OutputFormat::Markdown)
            .expect("render list markdown")
            .contains("| middle |")
    );

    let truncated = query_campaign_list(
        &client,
        CampaignPrincipal::new("operator:alice").expect("principal"),
        &CampaignListArgs {
            after: None,
            limit: 1,
            pages: 1,
        },
    )
    .expect("truncated campaign list");
    assert!(!truncated.complete);
    assert_eq!(truncated.next_after.as_deref(), Some("alpha"));
    assert_eq!(truncated.entries.len(), 1);

    assert!(
        validate_campaign_list(&CampaignListArgs {
            after: None,
            limit: 0,
            pages: 1,
        })
        .is_err()
    );
    assert!(
        validate_campaign_list(&CampaignListArgs {
            after: None,
            limit: 1,
            pages: MAX_CAMPAIGN_PAGE_FOLLOW_PAGES + 1,
        })
        .is_err()
    );
}

#[test]
fn campaign_page_aggregation_rejects_byte_overflow_before_an_extra_fetch() {
    let page = CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("page-byte-bound").to_string(),
        after: None,
        limit: 1,
        pages: 3,
    };
    let calls = std::cell::Cell::new(0_u32);
    let result = collect_campaign_pages(
        &page,
        "graph",
        None::<u32>,
        |cursor| cursor.to_string(),
        |cursor| {
            calls.set(calls.get() + 1);
            Ok(CampaignPageBatch {
                entries: Vec::new(),
                next_after: Some(cursor.unwrap_or(0) + 1),
                response_bytes: usize::try_from(MAX_CAMPAIGN_PAGE_AGGREGATE_RESPONSE_BYTES / 2 + 1)
                    .expect("test response byte bound"),
            })
        },
    );

    assert!(matches!(result, Err(CliError::Backend(_))));
    assert_eq!(calls.get(), 2);
}

#[test]
fn campaign_page_aggregation_rejects_a_repeated_cursor() {
    let page = CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("page-cursor-cycle").to_string(),
        after: None,
        limit: 1,
        pages: 2,
    };
    let calls = std::cell::Cell::new(0_u32);
    let result = collect_campaign_pages(
        &page,
        "graph",
        None::<u32>,
        |cursor| cursor.to_string(),
        |_| {
            calls.set(calls.get() + 1);
            Ok(CampaignPageBatch {
                entries: Vec::new(),
                next_after: Some(1),
                response_bytes: 1,
            })
        },
    );

    assert!(matches!(result, Err(CliError::Backend(_))));
    assert_eq!(calls.get(), 2);
}

#[test]
fn campaign_all_branch_derives_authenticated_generator_policy_and_budget() {
    let (service, source_snapshot, _) = graph_page_service();
    let template = service.branch_request.clone();
    let active_policy = service.snapshot.active_policy();
    let all_generator = CandidateGeneratorSpec::new(
        STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("all generator")
    .id()
    .expect("all generator ID");
    let branch = CampaignBranchArgs {
        name: "example".to_owned(),
        expected: source_snapshot.to_string(),
        command: None,
        branch_point: template.branch_point().to_string(),
        parent: template.parent().to_string(),
        opportunity: Some(template.opportunity().to_string()),
        domain: Some(template.domain().to_string()),
        selector: Vec::new(),
        instance: None,
        selector_scan_limit: 256,
        values: Vec::new(),
        generator: None,
        all: true,
        proposals: None,
        attempts: 2,
        stop: "next-choice".to_owned(),
    };
    let expected = BranchRequest::new(
        BranchRequest::identity(
            template.branch_point(),
            template.parent(),
            template.opportunity(),
            template.domain(),
        ),
        CandidateSource::generated(all_generator),
        BranchRequestCause::ExhaustivePolicy(active_policy),
        BranchBudget::new(2, 2).expect("all budget"),
        StopCondition::NextChoice,
    )
    .expect("expected all request")
    .id()
    .expect("expected all request ID");
    let report = apply_campaign_all_branch(
        &CampaignClient::new(service),
        CampaignPrincipal::new("operator").expect("principal"),
        &branch,
    )
    .expect("apply exhaustive branch");
    assert!(matches!(
        report,
        CampaignAcceptanceReport::Branch {
            request,
            prior_snapshot,
            replayed: false,
            ..
        } if request == expected.to_string() && prior_snapshot == source_snapshot.to_string()
    ));
}

#[test]
fn campaign_direct_branch_binds_the_authenticated_attempt_timeout() {
    let (service, bounded_snapshot, old_snapshot) = bounded_graph_page_service();
    let template = service.branch_request.clone();
    let branch = graph_branch_args(&service, bounded_snapshot, "bounded-command");
    let expected = BranchRequest::new(
        BranchRequest::identity(
            template.branch_point(),
            template.parent(),
            template.opportunity(),
            template.domain(),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("finite source"),
        BranchRequestCause::Operator(
            CampaignCommandId::parse(branch.command.as_deref().expect("operator command"))
                .expect("operator command ID"),
        ),
        BranchBudget::new(1, 1).expect("branch budget"),
        StopCondition::bounded(StopCondition::NextChoice, Some(100), Some(10))
            .expect("bounded stop"),
    )
    .expect("expected bounded branch")
    .id()
    .expect("bounded branch ID");
    let client = CampaignClient::new(service);
    let principal = CampaignPrincipal::new("operator").expect("principal");

    let report = apply_campaign_direct_branch(&client, principal.clone(), &branch)
        .expect("apply bounded branch");
    assert!(matches!(
        report,
        CampaignAcceptanceReport::Branch { request, .. } if request == expected.to_string()
    ));

    let stale = CampaignBranchArgs {
        expected: old_snapshot.to_string(),
        ..branch
    };
    assert!(apply_campaign_direct_branch(&client, principal, &stale).is_err());
}

#[test]
fn campaign_selector_and_all_branches_bind_the_authenticated_attempt_timeout() {
    for all in [false, true] {
        let (service, bounded_snapshot, _) = bounded_graph_page_service();
        let template = service.branch_request.clone();
        let active_policy = service.snapshot.active_policy();
        let command = CampaignCommandId::from_hash(hash("bounded-selector-command"));
        let mut branch = graph_branch_args(&service, bounded_snapshot, "bounded-selector-command");
        if all {
            branch.command = None;
            branch.values.clear();
            branch.all = true;
        } else {
            branch.opportunity = None;
            branch.domain = None;
            branch.selector = vec![String::from("product.network.retry")];
        }
        let (source, cause, proposals) = if all {
            let generator = CandidateGeneratorSpec::new(
                STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
                CandidateGeneratorAlgorithm::All,
            )
            .expect("all generator")
            .id()
            .expect("all generator ID");
            (
                CandidateSource::generated(generator),
                BranchRequestCause::ExhaustivePolicy(active_policy),
                2,
            )
        } else {
            (
                CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                    .expect("selector source"),
                BranchRequestCause::Operator(command),
                1,
            )
        };
        let expected = BranchRequest::new(
            BranchRequest::identity(
                template.branch_point(),
                template.parent(),
                template.opportunity(),
                template.domain(),
            ),
            source,
            cause,
            BranchBudget::new(proposals, 1).expect("branch budget"),
            StopCondition::bounded(StopCondition::NextChoice, Some(100), Some(10))
                .expect("bounded stop"),
        )
        .expect("expected bounded request")
        .id()
        .expect("bounded request ID");
        let client = CampaignClient::new(service);
        let principal = CampaignPrincipal::new("operator").expect("principal");

        let report = if all {
            apply_campaign_all_branch(&client, principal, &branch)
        } else {
            apply_campaign_selector_branch(&client, principal, &branch)
        }
        .expect("apply policy-bound branch");
        assert!(matches!(
            report,
            CampaignAcceptanceReport::Branch { request, .. } if request == expected.to_string()
        ));
    }
}

#[test]
fn campaign_branch_selector_resolves_authenticated_name_and_domain() {
    let (service, source_snapshot, _) = graph_page_service();
    let template = service.branch_request.clone();
    let declaration_id = service.declaration.id().expect("selector declaration ID");
    let branch = CampaignBranchArgs {
        name: "example".to_owned(),
        expected: source_snapshot.to_string(),
        command: Some(CampaignCommandId::from_hash(hash("selector-command")).to_string()),
        branch_point: template.branch_point().to_string(),
        parent: template.parent().to_string(),
        opportunity: None,
        domain: None,
        selector: vec![
            "product.network.retry".to_owned(),
            "tag:network".to_owned(),
            format!("id:{declaration_id}"),
        ],
        instance: Some("network-retry".to_owned()),
        selector_scan_limit: 8,
        values: vec!["true".to_owned()],
        generator: None,
        all: false,
        proposals: None,
        attempts: 1,
        stop: "next-choice".to_owned(),
    };
    let expected = BranchRequest::new(
        BranchRequest::identity(
            template.branch_point(),
            template.parent(),
            template.opportunity(),
            template.domain(),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("selector finite source"),
        BranchRequestCause::Operator(
            CampaignCommandId::parse(branch.command.as_deref().expect("selector command"))
                .expect("selector command ID"),
        ),
        BranchBudget::new(1, 1).expect("selector budget"),
        StopCondition::NextChoice,
    )
    .expect("expected selector request")
    .id()
    .expect("expected selector request ID");

    let report = apply_campaign_selector_branch(
        &CampaignClient::new(service),
        CampaignPrincipal::new("operator").expect("principal"),
        &branch,
    )
    .expect("apply selector branch");

    assert!(matches!(
        report,
        CampaignAcceptanceReport::Branch { request, .. }
            if request == expected.to_string()
    ));
    assert!(matches!(
        parse_campaign_choice_selector("tag:network").expect("tag selector"),
        CampaignChoiceSelector::Tag(tag) if tag == "network"
    ));
    assert!(matches!(
        parse_campaign_choice_selector(&format!("id:{declaration_id}"))
            .expect("declaration selector"),
        CampaignChoiceSelector::Declaration(id) if id == declaration_id
    ));
}

#[test]
fn campaign_branch_selector_rejects_ambiguity_and_scan_truncation() {
    let (service, _, _) = graph_page_service();
    let (service, snapshot) = add_ambiguous_selector_choice(service);
    let template = service.branch_request.clone();
    let mut branch = CampaignBranchArgs {
        name: "example".to_owned(),
        expected: snapshot.to_string(),
        command: Some(CampaignCommandId::from_hash(hash("ambiguous-selector-command")).to_string()),
        branch_point: template.branch_point().to_string(),
        parent: template.parent().to_string(),
        opportunity: None,
        domain: None,
        selector: vec!["tag:network".to_owned()],
        instance: None,
        selector_scan_limit: 8,
        values: vec!["true".to_owned()],
        generator: None,
        all: false,
        proposals: None,
        attempts: 1,
        stop: "next-choice".to_owned(),
    };
    let client = CampaignClient::new(service);
    let principal = CampaignPrincipal::new("operator").expect("principal");

    let ambiguity = match apply_campaign_selector_branch(&client, principal.clone(), &branch) {
        Ok(_) => panic!("ambiguous selector must fail"),
        Err(error) => error,
    };
    assert!(
        ambiguity
            .to_string()
            .contains("matches multiple opportunities")
    );

    branch.selector_scan_limit = 1;
    let truncated = match apply_campaign_selector_branch(&client, principal, &branch) {
        Ok(_) => panic!("truncated selector scan must fail"),
        Err(error) => error,
    };
    assert!(truncated.to_string().contains("selector scan exceeded 1"));
    assert!(validate_campaign_selector_scan_limit(0).is_err());
    assert!(validate_campaign_selector_scan_limit(MAX_CAMPAIGN_SELECTOR_SCAN_ITEMS + 1).is_err());
    assert!(
        parse_campaign_choice_selectors(&vec![
            String::from("tag:network");
            MAX_CAMPAIGN_SELECTOR_PREDICATES + 1
        ])
        .is_err()
    );
}

#[test]
fn campaign_create_and_derive_records_are_prepared_before_connection() {
    let temporary = tempfile::tempdir().expect("temporary campaign inputs");
    let lineage_path = temporary.path().join("lineage.bin");
    let policy_path = temporary.path().join("policy.bin");
    let (lineage_record, policy_record) = campaign_records();
    std::fs::write(&lineage_path, lineage_record.canonical_bytes()).expect("write lineage");
    std::fs::write(&policy_path, policy_record.canonical_bytes()).expect("write policy");

    let principal = CampaignPrincipal::new("operator").expect("campaign principal");
    let create = prepare_campaign_command(
        &CampaignCommand::Create(CampaignCreateArgs {
            name: "created".to_owned(),
            lineage: lineage_path.clone(),
            policy: policy_path.clone(),
            start_command: None,
        }),
        &principal,
    )
    .expect("prepare creation")
    .expect("prepared creation request");
    assert!(matches!(create, PreparedCampaignCommand::Create(_)));

    let start_command = CampaignCommandId::from_hash(hash("start-created"));
    let create_and_start = prepare_campaign_command(
        &CampaignCommand::Create(CampaignCreateArgs {
            name: "started".to_owned(),
            lineage: lineage_path,
            policy: policy_path.clone(),
            start_command: Some(start_command.to_string()),
        }),
        &principal,
    )
    .expect("prepare creation with immediate start")
    .expect("prepared create-and-start request");
    assert!(matches!(
        create_and_start,
        PreparedCampaignCommand::CreateAndStart(_, command) if command == start_command
    ));

    let derive = prepare_campaign_command(
        &CampaignCommand::Derive(CampaignDeriveArgs {
            source: "created".to_owned(),
            snapshot: snapshot("created").to_string(),
            target: "derived".to_owned(),
            policy: Some(policy_path),
        }),
        &principal,
    )
    .expect("prepare derivation")
    .expect("prepared derivation request");
    assert!(matches!(derive, PreparedCampaignCommand::Derive(_)));

    let corrupt_path = temporary.path().join("corrupt.bin");
    std::fs::write(&corrupt_path, b"not canonical").expect("write corrupt input");
    assert!(
        prepare_campaign_command(
            &CampaignCommand::Create(CampaignCreateArgs {
                name: "invalid".to_owned(),
                lineage: corrupt_path,
                policy: temporary.path().join("absent-policy.bin"),
                start_command: None,
            }),
            &principal,
        )
        .is_err()
    );
}

#[test]
fn campaign_create_and_start_uses_the_checked_genesis_snapshot() {
    let principal = CampaignPrincipal::new("operator").expect("campaign principal");
    let campaign = CampaignName::new("started").expect("campaign name");
    let (lineage, policy) = campaign_records();
    let request = CreateCampaignRequest::new(principal, campaign, lineage, policy)
        .expect("campaign creation request");
    let command = CampaignCommandId::from_hash(hash("start-created"));
    let client = CampaignClient::new(FixedHeadService);

    let report = apply_campaign_create(&client, request, Some(command))
        .expect("checked campaign creation and start");

    let CampaignAcceptanceReport::Create {
        campaign,
        snapshot: genesis_snapshot,
        replayed,
        start: Some(start),
        ..
    } = report
    else {
        panic!("create-and-start must return both checked results");
    };
    assert_eq!(campaign, "started");
    assert_eq!(genesis_snapshot, snapshot("created").to_string());
    assert!(!replayed);
    assert_eq!(start.command, command.to_string());
    assert_eq!(start.prior_snapshot, genesis_snapshot);
    assert_eq!(start.new_snapshot, snapshot("started").to_string());
    assert!(!start.replayed);
}

#[test]
fn campaign_mutation_actions_preserve_exact_operator_intent() {
    let start = CampaignCommand::Start(mutation_basis("start"));
    let (basis, operation, action) = campaign_mutation_spec(&start).expect("start mutation");
    assert_eq!(basis.command, hash("start").to_hex());
    assert_eq!(operation, "start");
    assert!(matches!(action, CampaignControlAction::Resume));

    let resume = CampaignCommand::Resume(mutation_basis("resume"));
    assert!(matches!(
        campaign_mutation_spec(&resume).expect("resume mutation").2,
        CampaignControlAction::Resume
    ));

    for (active, expected) in [
        (CampaignPausePolicyArg::Drain, ActiveAttemptPolicy::Drain),
        (
            CampaignPausePolicyArg::Checkpoint,
            ActiveAttemptPolicy::ExactCheckpoint,
        ),
        (
            CampaignPausePolicyArg::Retry,
            ActiveAttemptPolicy::CancelAndRetry,
        ),
    ] {
        let pause = CampaignCommand::Pause(CampaignPauseArgs {
            basis: mutation_basis("pause"),
            active,
        });
        assert!(matches!(
            campaign_mutation_spec(&pause).expect("pause mutation").2,
            CampaignControlAction::Pause(policy) if policy == expected
        ));
    }

    let stop = CampaignCommand::Stop(CampaignStopArgs {
        basis: mutation_basis("stop"),
        seal: false,
    });
    assert!(matches!(
        campaign_mutation_spec(&stop).expect("stop mutation").2,
        CampaignControlAction::Complete
    ));
    let seal = CampaignCommand::Stop(CampaignStopArgs {
        basis: mutation_basis("seal"),
        seal: true,
    });
    assert!(matches!(
        campaign_mutation_spec(&seal).expect("seal mutation").2,
        CampaignControlAction::Seal
    ));

    let unseal = CampaignCommand::Unseal(mutation_basis("unseal"));
    assert!(matches!(
        campaign_mutation_spec(&unseal).expect("unseal mutation").2,
        CampaignControlAction::Unseal
    ));

    let budget = CampaignCommand::Budget(CampaignBudgetArgs {
        name: "example".to_owned(),
        expected: snapshot("current").to_string(),
        command: hash("budget").to_hex(),
        operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
            attempts: 11,
            proposals: 13,
        }),
    });
    assert!(matches!(
        campaign_mutation_spec(&budget).expect("budget mutation").2,
        CampaignControlAction::GrantBudget(grant)
            if grant.attempts() == 11 && grant.proposals() == 13
    ));
    let empty_budget = CampaignCommand::Budget(CampaignBudgetArgs {
        name: "example".to_owned(),
        expected: snapshot("current").to_string(),
        command: hash("empty-budget").to_hex(),
        operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
            attempts: 0,
            proposals: 0,
        }),
    });
    assert!(campaign_mutation_spec(&empty_budget).is_err());

    let steer = CampaignCommand::Steer(CampaignSteerArgs {
        basis: mutation_basis("steer"),
        policy: policy("next").to_string(),
    });
    assert!(matches!(
        campaign_mutation_spec(&steer).expect("steer mutation").2,
        CampaignControlAction::ActivatePolicy(next) if next == policy("next")
    ));

    let configuration = ConfigurationId::from_hash(hash("pin-configuration"));
    let pin = CampaignCommand::Pin(CampaignPinArgs {
        basis: mutation_basis("pin"),
        configuration: configuration.to_string(),
        tier: CampaignPinRetentionArg::Exact,
        reason: "retain reproducer".to_owned(),
    });
    let pin_change = campaign_pin_spec(&pin).expect("pin mutation").2;
    assert_eq!(pin_change.configuration(), configuration);
    assert_eq!(pin_change.retention(), Some(PinRetention::Exact));
    assert_eq!(pin_change.reason(), "retain reproducer");

    let unpin = CampaignCommand::Unpin(CampaignUnpinArgs {
        basis: mutation_basis("unpin"),
        configuration: configuration.to_string(),
        reason: "resolved".to_owned(),
    });
    let unpin_change = campaign_pin_spec(&unpin).expect("unpin mutation").2;
    assert_eq!(unpin_change.configuration(), configuration);
    assert_eq!(unpin_change.retention(), None);
    assert_eq!(unpin_change.reason(), "resolved");
}

#[test]
fn campaign_debug_preflight_reaches_the_non_control_owner() {
    let principal = CampaignPrincipal::new("debugger").expect("debugger principal");
    let debug = CampaignDebugArgs {
        name: "midpoint".to_owned(),
        snapshot: snapshot("debug-preflight").to_string(),
        finding: fixture_record_id(CampaignRecordKind::Finding, "debug-preflight"),
        node: "choice-node".to_owned(),
        gdb_listen: "127.0.0.1:0".to_owned(),
        writable: false,
    };

    let mut command = CampaignCommand::Debug(debug);
    assert!(matches!(
        prepare_campaign_command(&command, &principal),
        Ok(None)
    ));
    assert!(campaign_mutation_spec(&command).is_err());

    let CampaignCommand::Debug(debug) = &mut command else {
        unreachable!("the test constructs a debug command")
    };
    debug.writable = true;
    assert!(matches!(
        prepare_campaign_command(&command, &principal),
        Ok(None)
    ));

    let CampaignCommand::Debug(debug) = &mut command else {
        unreachable!("the test constructs a debug command")
    };
    debug.snapshot = "not-a-snapshot".to_owned();
    assert!(validate_campaign_command(&command).is_err());
}

#[test]
fn campaign_inputs_fail_before_transport_setup() {
    assert_eq!(
        parse_campaign_choice_value("i64:-7").expect("signed value"),
        ChoiceValue::Integer(IntegerValue::Signed(-7))
    );
    assert_eq!(
        parse_campaign_choice_value("u64:9").expect("unsigned value"),
        ChoiceValue::Integer(IntegerValue::Unsigned(9))
    );
    let alternative = AlternativeId::from_hash(hash("alternative"));
    assert_eq!(
        parse_campaign_choice_value(&format!("discrete:{alternative}")).expect("discrete value"),
        ChoiceValue::Discrete(alternative)
    );

    for malformed in [
        "group:",
        "group:3",
        "group:GG",
        "group:AB",
        "group:0001",
        "group:0300",
    ] {
        assert!(
            parse_campaign_choice_value(malformed).is_err(),
            "accepted malformed group value: {malformed}"
        );
    }
    assert!(
        parse_campaign_choice_value(&format!(
            "group:{}",
            "00".repeat(MAX_CAMPAIGN_GROUP_VALUE_BYTES + 1)
        ))
        .is_err()
    );

    let bad_watch = CampaignCommand::Watch(CampaignWatchArgs {
        name: "example".to_owned(),
        after: Some("not-a-snapshot".to_owned()),
    });
    assert!(validate_campaign_command(&bad_watch).is_err());
    let bad_snapshot = CampaignCommand::Snapshot(CampaignSnapshotArgs {
        name: "example".to_owned(),
        snapshot: "not-a-snapshot".to_owned(),
    });
    assert!(validate_campaign_command(&bad_snapshot).is_err());
    let bad_compare = CampaignCommand::Compare(CampaignCompareArgs {
        name: "example".to_owned(),
        left: snapshot("left").to_string(),
        right: "not-a-snapshot".to_owned(),
    });
    assert!(validate_campaign_command(&bad_compare).is_err());
    let bad_explain = CampaignCommand::Explain(CampaignExplainArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        opportunity: branch_request("explain-validation")
            .opportunity()
            .to_string(),
        request: "not-a-branch-request".to_owned(),
    });
    assert!(validate_campaign_command(&bad_explain).is_err());

    let bad_graph_cursor = CampaignCommand::Graph(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        after: Some("not-a-hash".to_owned()),
        limit: 8,
        pages: 1,
    });
    assert!(validate_campaign_command(&bad_graph_cursor).is_err());
    let empty_choices_page = CampaignCommand::Choices(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        after: None,
        limit: 0,
        pages: 1,
    });
    assert!(validate_campaign_command(&empty_choices_page).is_err());
    let oversized_graph_page = CampaignCommand::Graph(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        after: None,
        limit: MAX_CAMPAIGN_QUERY_PAGE_ITEMS + 1,
        pages: 1,
    });
    assert!(validate_campaign_command(&oversized_graph_page).is_err());
    let empty_graph_page_budget = CampaignCommand::Graph(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        after: None,
        limit: 1,
        pages: 0,
    });
    assert!(validate_campaign_command(&empty_graph_page_budget).is_err());
    let oversized_graph_page_budget = CampaignCommand::Graph(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        after: None,
        limit: 1,
        pages: MAX_CAMPAIGN_PAGE_FOLLOW_PAGES + 1,
    });
    assert!(validate_campaign_command(&oversized_graph_page_budget).is_err());
    let bad_frontier_cursor = CampaignCommand::Frontier(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        after: Some("not-a-branch-request".to_owned()),
        limit: 8,
        pages: 1,
    });
    assert!(validate_campaign_command(&bad_frontier_cursor).is_err());
    let bad_finding_cursor = CampaignCommand::Findings(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        after: Some("not-a-hash".to_owned()),
        limit: 1,
        pages: 1,
    });
    assert!(validate_campaign_command(&bad_finding_cursor).is_err());
    let bad_graph_object = CampaignCommand::GraphObject(CampaignGraphObjectArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        key: "not-a-hash".to_owned(),
    });
    assert!(validate_campaign_command(&bad_graph_object).is_err());
    let bad_choice_object = CampaignCommand::ChoiceObject(CampaignChoiceObjectArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        opportunity: "not-an-opportunity".to_owned(),
        kind: CampaignChoiceObjectKindArg::Declaration,
    });
    assert!(validate_campaign_command(&bad_choice_object).is_err());
    let bad_frontier_object = CampaignCommand::FrontierObject(CampaignFrontierObjectArgs {
        name: "example".to_owned(),
        snapshot: snapshot("current").to_string(),
        request: "not-a-request".to_owned(),
    });
    assert!(validate_campaign_command(&bad_frontier_object).is_err());

    let mut duplicate_branch = branch_args("duplicate");
    duplicate_branch.values = vec!["true".to_owned(), "true".to_owned()];
    assert!(validate_campaign_command(&CampaignCommand::Branch(duplicate_branch)).is_err());
    let mut invalid_stop = branch_args("invalid-stop");
    invalid_stop.stop = "events:0".to_owned();
    assert!(validate_campaign_command(&CampaignCommand::Branch(invalid_stop)).is_err());
    let mut invalid_budget = branch_args("invalid-budget");
    invalid_budget.proposals = Some(1);
    invalid_budget.attempts = 2;
    assert!(validate_campaign_command(&CampaignCommand::Branch(invalid_budget)).is_err());
    let generator = CandidateGeneratorSpecId::parse(&fixture_record_id(
        CampaignRecordKind::CandidateGeneratorSpec,
        "branch-generator",
    ))
    .expect("candidate generator ID");
    let mut generated_branch = branch_args("generated");
    generated_branch.values.clear();
    generated_branch.generator = Some(generator.to_string());
    generated_branch.proposals = Some(8);
    let PreparedCampaignCommand::Branch(generated) = prepare_campaign_branch(
        &generated_branch,
        &CampaignPrincipal::new("operator").expect("campaign principal"),
    )
    .expect("generated branch request") else {
        unreachable!("generated branch preparation returned another operation")
    };
    assert_eq!(generated.request().source().generator(), Some(generator));
    assert_eq!(generated.request().budget().maximum_proposals(), 8);

    let mut missing_generated_budget = generated_branch.clone();
    missing_generated_budget.proposals = None;
    assert!(validate_campaign_command(&CampaignCommand::Branch(missing_generated_budget)).is_err());
    let mut mixed_source = generated_branch;
    mixed_source.values.push("true".to_owned());
    assert!(validate_campaign_command(&CampaignCommand::Branch(mixed_source)).is_err());

    let mut bad_command_basis = mutation_basis("bad-command");
    bad_command_basis.command = "not-a-command".to_owned();
    assert!(validate_campaign_command(&CampaignCommand::Resume(bad_command_basis)).is_err());

    let empty_budget = CampaignCommand::Budget(CampaignBudgetArgs {
        name: "example".to_owned(),
        expected: snapshot("current").to_string(),
        command: hash("empty-budget-validation").to_hex(),
        operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
            attempts: 0,
            proposals: 0,
        }),
    });
    assert!(validate_campaign_command(&empty_budget).is_err());
}

#[test]
fn campaign_group_value_label_round_trips_through_operator_input() {
    let member_domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "fault.enabled",
        ChoiceSource::Workload {
            producer: "fault-controller".to_owned(),
        },
        member_domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from(["fault".to_owned()])).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("group member declaration");
    let member = declaration.id().expect("member ID");
    let group = ChoiceGroup::new(
        &BTreeMap::from([(member, declaration)]),
        ChoiceGroupDomain::Cartesian {
            members: BTreeMap::from([(member, member_domain)]),
            constraints: BTreeSet::new(),
        },
        ChoiceGroupApplication::new("fault-controller", 1).expect("application"),
    )
    .expect("choice group");
    let value = ChoiceValue::Group(
        group
            .select(ChoiceTuple::new(BTreeMap::from([(
                member,
                ChoiceValue::Boolean(true),
            )])))
            .expect("selected group tuple"),
    );

    let label = object::campaign_choice_value_label(&value);
    assert!(label.starts_with("group:03"));
    assert_eq!(
        parse_campaign_choice_value(&label).expect("canonical group operator value"),
        value
    );
}

#[test]
fn campaign_status_watch_and_list_parse_under_the_nested_cli() {
    let fixture = Cli::try_parse_from([
        "crucible",
        "campaign",
        "fixture",
        "worked-network",
        "--output",
        "/tmp/worked-network",
    ])
    .expect("offline worked-network fixture arguments");
    assert!(matches!(
        fixture.command,
        Commands::Campaign(CampaignArgs {
            socket: None,
            principal: None,
            command: CampaignCommand::Fixture(CampaignFixtureArgs {
                fixture: CampaignFixtureCommand::WorkedNetwork(
                    CampaignWorkedNetworkFixtureArgs { ref output, kernel: None, root_image: None },
                ),
            }),
        }) if output == &PathBuf::from("/tmp/worked-network")
    ));

    let materialized = Cli::try_parse_from([
        "crucible",
        "campaign",
        "fixture",
        "worked-network",
        "--output",
        "/tmp/envoy-network",
        "--kernel",
        "/tmp/vmlinuz",
        "--root-image",
        "/tmp/root.ext4",
    ])
    .expect("materialized worked-network fixture arguments");
    assert!(matches!(
        materialized.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Fixture(CampaignFixtureArgs {
                fixture: CampaignFixtureCommand::WorkedNetwork(CampaignWorkedNetworkFixtureArgs {
                    kernel: Some(ref kernel),
                    root_image: Some(ref root_image),
                    ..
                }),
            }),
            ..
        }) if kernel == &PathBuf::from("/tmp/vmlinuz")
            && root_image == &PathBuf::from("/tmp/root.ext4")
    ));
    assert!(
        Cli::try_parse_from([
            "crucible",
            "campaign",
            "fixture",
            "worked-network",
            "--output",
            "/tmp/envoy-network",
            "--kernel",
            "/tmp/vmlinuz",
        ])
        .is_err()
    );

    let validate = Cli::try_parse_from([
        "crucible",
        "campaign",
        "validate-import",
        "/tmp/campaign-import.toml",
    ])
    .expect("offline campaign import validation arguments");
    assert!(matches!(
        validate.command,
        Commands::Campaign(CampaignArgs {
            socket: None,
            principal: None,
            command: CampaignCommand::ValidateImport(CampaignValidateImportArgs {
                ref manifests,
            }),
        }) if manifests == &[PathBuf::from("/tmp/campaign-import.toml")]
    ));

    let validate_policy = Cli::try_parse_from([
        "crucible",
        "campaign",
        "validate",
        "--policy",
        "/tmp/policy.bin",
    ])
    .expect("offline campaign policy validation arguments");
    assert!(matches!(
        validate_policy.command,
        Commands::Campaign(CampaignArgs {
            socket: None,
            principal: None,
            command: CampaignCommand::Validate(CampaignValidateArgs {
                name: None,
                policy: Some(ref policy),
            }),
        }) if policy == &PathBuf::from("/tmp/policy.bin")
    ));

    let validate_campaign = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "validate",
        "example",
    ])
    .expect("connected campaign validation arguments");
    assert!(matches!(
        validate_campaign.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Validate(CampaignValidateArgs {
                name: Some(ref name),
                policy: None,
            }),
            ..
        }) if name == "example"
    ));
    assert!(
        Cli::try_parse_from([
            "crucible",
            "campaign",
            "validate",
            "example",
            "--policy",
            "/tmp/policy.bin",
        ])
        .is_err()
    );

    let scenario = Cli::try_parse_from([
        "crucible",
        "campaign",
        "scenario",
        "compile",
        "/tmp/scenario.toml",
        "--output",
        "/tmp/scenario-bundle",
    ])
    .expect("offline campaign scenario compilation arguments");
    assert!(matches!(
        scenario.command,
        Commands::Campaign(CampaignArgs {
            socket: None,
            principal: None,
            command: CampaignCommand::Scenario(CampaignScenarioArgs {
                command: CampaignScenarioCommand::Compile(CampaignScenarioCompileArgs {
                    ref input,
                    ref output,
                }),
            }),
        }) if input == &PathBuf::from("/tmp/scenario.toml")
            && output == &PathBuf::from("/tmp/scenario-bundle")
    ));

    let configuration = Cli::try_parse_from([
        "crucible",
        "campaign",
        "configuration",
        "compile",
        "/tmp/scenario.toml",
        "/tmp/schedule.bin",
        "--output",
        "/tmp/configuration-bundle",
    ])
    .expect("offline campaign configuration compilation arguments");
    assert!(matches!(
        configuration.command,
        Commands::Campaign(CampaignArgs {
            socket: None,
            principal: None,
            command: CampaignCommand::Configuration(CampaignConfigurationArgs {
                command: CampaignConfigurationCommand::Compile(
                    CampaignConfigurationCompileArgs {
                        ref scenario,
                        ref schedule,
                        ref output,
                    },
                ),
            }),
        }) if scenario == &PathBuf::from("/tmp/scenario.toml")
            && schedule == &PathBuf::from("/tmp/schedule.bin")
            && output == &PathBuf::from("/tmp/configuration-bundle")
    ));

    let schedule = Cli::try_parse_from([
        "crucible",
        "campaign",
        "schedule",
        "compile",
        "/tmp/decisions.toml",
        "--output",
        "/tmp/schedule.bin",
    ])
    .expect("offline campaign schedule compilation arguments");
    assert!(matches!(
        schedule.command,
        Commands::Campaign(CampaignArgs {
            socket: None,
            principal: None,
            command: CampaignCommand::Schedule(CampaignScheduleArgs {
                command: CampaignScheduleCommand::Compile(CampaignScheduleCompileArgs {
                    ref input,
                    ref output,
                }),
            }),
        }) if input == &PathBuf::from("/tmp/decisions.toml")
            && output == &PathBuf::from("/tmp/schedule.bin")
    ));

    let policy = Cli::try_parse_from([
        "crucible",
        "campaign",
        "policy",
        "compile",
        "/tmp/policy.toml",
        "--scenario",
        "/tmp/scenario.toml",
        "--output",
        "/tmp/policy.bin",
    ])
    .expect("offline campaign policy compilation arguments");
    assert!(matches!(
        policy.command,
        Commands::Campaign(CampaignArgs {
            socket: None,
            principal: None,
            command: CampaignCommand::Policy(CampaignPolicyArgs {
                command: CampaignPolicyCommand::Compile(CampaignPolicyCompileArgs {
                    ref input,
                    scenario: Some(ref scenario),
                    ref output,
                }),
            }),
        }) if input == &PathBuf::from("/tmp/policy.toml")
            && scenario == &PathBuf::from("/tmp/scenario.toml")
            && output == &PathBuf::from("/tmp/policy.bin")
    ));

    let lineage = Cli::try_parse_from([
        "crucible",
        "campaign",
        "lineage",
        "compile",
        "/tmp/lineage.toml",
        "--output",
        "/tmp/lineage.bin",
    ])
    .expect("offline campaign lineage compilation arguments");
    assert!(matches!(
        lineage.command,
        Commands::Campaign(CampaignArgs {
            socket: None,
            principal: None,
            command: CampaignCommand::Lineage(CampaignLineageArgs {
                command: CampaignLineageCommand::Compile(CampaignLineageCompileArgs {
                    ref input,
                    ref output,
                }),
            }),
        }) if input == &PathBuf::from("/tmp/lineage.toml")
            && output == &PathBuf::from("/tmp/lineage.bin")
    ));

    let missing_connection = Cli::try_parse_from(["crucible", "campaign", "status", "example"])
        .expect("connected campaign arguments are checked before dispatch");
    let Commands::Campaign(missing_connection_args) = &missing_connection.command else {
        panic!("campaign command");
    };
    assert!(
        run_campaign_invocation(&missing_connection, missing_connection_args)
            .expect_err("connected command requires a socket")
            .to_string()
            .contains("require --socket")
    );

    let status = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "status",
        "example",
    ])
    .expect("campaign status arguments");
    assert!(matches!(
        status.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Status(CampaignStatusArgs { ref name }),
            ..
        }) if name == "example"
    ));

    let attach = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "attach",
        "example",
        "--executor-socket",
        "/run/crucible/executor.sock",
    ])
    .expect("campaign runtime attachment arguments");
    assert!(matches!(
        attach.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Attach(CampaignAttachArgs {
                ref name,
                ref executor_socket,
            }),
            ..
        }) if name == "example" && executor_socket == &PathBuf::from("/run/crucible/executor.sock")
    ));

    let cursor = snapshot("cursor").to_string();
    let watch = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "watch",
        "example",
        "--after",
        &cursor,
    ])
    .expect("campaign watch arguments");
    assert!(matches!(
        watch.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Watch(CampaignWatchArgs { after: Some(_), .. }),
            ..
        })
    ));

    let list = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "list",
        "--after",
        "alpha",
        "--limit",
        "4",
        "--pages",
        "2",
    ])
    .expect("campaign list arguments");
    assert!(matches!(
        list.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::List(CampaignListArgs {
                after: Some(ref after),
                limit: 4,
                pages: 2,
            }),
            ..
        }) if after == "alpha"
    ));

    let left_snapshot = snapshot("left").to_string();
    let right_snapshot = snapshot("right").to_string();
    let snapshot_command = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "snapshot",
        "example",
        "--snapshot",
        &left_snapshot,
    ])
    .expect("campaign snapshot arguments");
    assert!(matches!(
        snapshot_command.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Snapshot(_),
            ..
        })
    ));
    let compare_command = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "compare",
        "example",
        "--left",
        &left_snapshot,
        "--right",
        &right_snapshot,
    ])
    .expect("campaign compare arguments");
    assert!(matches!(
        compare_command.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Compare(_),
            ..
        })
    ));
    let explanation_request = branch_request("explanation-parser");
    let explanation_request_id = explanation_request
        .id()
        .expect("explanation request ID")
        .to_string();
    let explanation_opportunity = explanation_request.opportunity().to_string();
    let explain_command = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "explain",
        "example",
        "--snapshot",
        &left_snapshot,
        "--opportunity",
        &explanation_opportunity,
        "--request",
        &explanation_request_id,
    ])
    .expect("campaign explanation arguments");
    assert!(matches!(
        explain_command.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Explain(_),
            ..
        })
    ));
    let finding = FindingId::parse(&fixture_record_id(
        CampaignRecordKind::Finding,
        "finding-explanation-parser",
    ))
    .expect("finding explanation ID")
    .to_string();
    let explain_finding = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "explain-finding",
        "example",
        "--snapshot",
        &left_snapshot,
        "--finding",
        &finding,
    ])
    .expect("campaign finding explanation arguments");
    assert!(matches!(
        explain_finding.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::ExplainFinding(_),
            ..
        })
    ));
    let attempt = AttemptId::parse(&fixture_record_id(
        CampaignRecordKind::Attempt,
        "attempt-explanation-parser",
    ))
    .expect("attempt explanation ID")
    .to_string();
    let explain_attempt = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "explain-attempt",
        "example",
        "--snapshot",
        &left_snapshot,
        "--attempt",
        &attempt,
    ])
    .expect("campaign attempt explanation arguments");
    assert!(matches!(
        explain_attempt.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::ExplainAttempt(_),
            ..
        })
    ));

    for operation in ["graph", "choices", "frontier", "findings"] {
        let page = Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            operation,
            "example",
            "--snapshot",
            &snapshot("page").to_string(),
            "--limit",
            "3",
            "--pages",
            "2",
        ])
        .expect("campaign page arguments");
        assert!(matches!(
            page.command,
            Commands::Campaign(CampaignArgs {
                command: CampaignCommand::Graph(CampaignPageArgs {
                    limit: 3,
                    pages: 2,
                    ..
                }) | CampaignCommand::Choices(CampaignPageArgs {
                    limit: 3,
                    pages: 2,
                    ..
                }) | CampaignCommand::Frontier(CampaignPageArgs {
                    limit: 3,
                    pages: 2,
                    ..
                }) | CampaignCommand::Findings(CampaignPageArgs {
                    limit: 3,
                    pages: 2,
                    ..
                }),
                ..
            })
        ));
    }

    let object_snapshot = snapshot("object").to_string();
    let graph_object = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "graph-object",
        "example",
        "--snapshot",
        &object_snapshot,
        "--key",
        &hash("graph-object").to_hex(),
    ])
    .expect("campaign graph-object arguments");
    assert!(matches!(
        graph_object.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::GraphObject(_),
            ..
        })
    ));

    let object_branch = branch_args("objects");
    let choice_object = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "choice-object",
        "example",
        "--snapshot",
        &object_snapshot,
        "--opportunity",
        object_branch
            .opportunity
            .as_deref()
            .expect("object opportunity"),
        "--kind",
        "domain",
    ])
    .expect("campaign choice-object arguments");
    assert!(matches!(
        choice_object.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::ChoiceObject(CampaignChoiceObjectArgs {
                kind: CampaignChoiceObjectKindArg::Domain,
                ..
            }),
            ..
        })
    ));

    let frontier_object = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "frontier-object",
        "example",
        "--snapshot",
        &object_snapshot,
        "--request",
        &branch_request("objects")
            .id()
            .expect("request ID")
            .to_string(),
    ])
    .expect("campaign frontier-object arguments");
    assert!(matches!(
        frontier_object.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::FrontierObject(_),
            ..
        })
    ));

    let create_start = hash("create-start").to_hex();
    let create = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "create",
        "created",
        "--lineage",
        "lineage.bin",
        "--policy",
        "policy.bin",
        "--start-command",
        &create_start,
    ])
    .expect("campaign create arguments");
    assert!(matches!(
        create.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Create(CampaignCreateArgs {
                ref name,
                ref start_command,
                ..
            }),
            ..
        }) if name == "created" && start_command.as_deref() == Some(create_start.as_str())
    ));

    let start = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "start",
        "created",
        "--expected",
        &snapshot("created").to_string(),
        "--command",
        &hash("start").to_hex(),
    ])
    .expect("campaign start arguments");
    assert!(matches!(
        start.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Start(_),
            ..
        })
    ));

    let planner_step = PlannerStepId::parse(&fixture_record_id(
        CampaignRecordKind::PlannerStep,
        "planner ranking step",
    ))
    .expect("planner step ID");
    let branch_point = BranchPointId::from_hash(hash("planner-ranking-branch-point"));
    let source = BranchRequestId::parse(&fixture_record_id(
        CampaignRecordKind::BranchRequest,
        "planner ranking source",
    ))
    .expect("branch request ID");
    let rankings = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "rankings",
        "created",
        "--snapshot",
        &snapshot("created").to_string(),
        "--step",
        &planner_step.to_string(),
        "--pages",
        "4",
        "--policy-groups",
        "--branch-point",
        &branch_point.to_string(),
        "--source",
        &source.to_string(),
        "--top",
        "2",
    ])
    .expect("campaign rankings arguments");
    assert!(matches!(
        rankings.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Rankings(CampaignRankingsArgs {
                pages: 4,
                policy_groups: true,
                branch_point: Some(_),
                source: Some(_),
                top: Some(2),
                ..
            }),
            ..
        })
    ));

    let derive = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "derive",
        "created",
        "--snapshot",
        &snapshot("created").to_string(),
        "derived",
        "--policy",
        "policy.bin",
    ])
    .expect("campaign derive arguments");
    assert!(matches!(
        derive.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Derive(CampaignDeriveArgs {
                ref source,
                ref target,
                ..
            }),
            ..
        }) if source == "created" && target == "derived"
    ));

    let branch = branch_args("parse");
    let branch_cli = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "branch",
        "created",
        "--expected",
        &branch.expected,
        "--command",
        branch.command.as_deref().expect("operator command"),
        "--branch-point",
        &branch.branch_point,
        "--parent",
        &branch.parent,
        "--opportunity",
        branch.opportunity.as_deref().expect("branch opportunity"),
        "--domain",
        branch.domain.as_deref().expect("branch domain"),
        "--value",
        "false",
        "--value",
        "true",
        "--attempts",
        "1",
        "--stop",
        "next-choice",
    ])
    .expect("campaign branch arguments");
    assert!(matches!(
        branch_cli.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Branch(CampaignBranchArgs { ref values, .. }),
            ..
        }) if values == &["false", "true"]
    ));
    let generated_branch = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "branch",
        "created",
        "--expected",
        &branch.expected,
        "--command",
        branch.command.as_deref().expect("operator command"),
        "--branch-point",
        &branch.branch_point,
        "--parent",
        &branch.parent,
        "--opportunity",
        branch.opportunity.as_deref().expect("branch opportunity"),
        "--domain",
        branch.domain.as_deref().expect("branch domain"),
        "--generator",
        &fixture_record_id(
            CampaignRecordKind::CandidateGeneratorSpec,
            "parser-generator",
        ),
        "--proposals",
        "8",
        "--attempts",
        "2",
    ])
    .expect("campaign generated branch arguments");
    assert!(matches!(
        generated_branch.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Branch(CampaignBranchArgs {
                values,
                generator: Some(_),
                proposals: Some(8),
                attempts: 2,
                ..
            }),
            ..
        }) if values.is_empty()
    ));
    let all_branch = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "branch",
        "created",
        "--expected",
        &branch.expected,
        "--branch-point",
        &branch.branch_point,
        "--parent",
        &branch.parent,
        "--opportunity",
        branch.opportunity.as_deref().expect("branch opportunity"),
        "--domain",
        branch.domain.as_deref().expect("branch domain"),
        "--all",
        "--attempts",
        "2",
    ])
    .expect("campaign exhaustive branch arguments");
    assert!(matches!(
        all_branch.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Branch(CampaignBranchArgs {
                all: true,
                values,
                generator: None,
                proposals: None,
                attempts: 2,
                ..
            }),
            ..
        }) if values.is_empty()
    ));
    let selector_branch = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "branch",
        "created",
        "--expected",
        &branch.expected,
        "--command",
        branch.command.as_deref().expect("operator command"),
        "--branch-point",
        &branch.branch_point,
        "--parent",
        &branch.parent,
        "--selector",
        "tag:network",
        "--selector",
        "name:product.network.retry",
        "--instance",
        "network-retry",
        "--selector-scan-limit",
        "32",
        "--value",
        "true",
    ])
    .expect("campaign selector branch arguments");
    assert!(matches!(
        selector_branch.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Branch(CampaignBranchArgs {
                opportunity: None,
                domain: None,
                selector: ref selectors,
                instance: Some(ref instance),
                selector_scan_limit: 32,
                ..
            }),
            ..
        }) if selectors
            == &[
                String::from("tag:network"),
                String::from("name:product.network.retry"),
            ]
            && instance == "network-retry"
    ));
    assert!(
        Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "branch",
            "created",
            "--expected",
            &branch.expected,
            "--command",
            branch.command.as_deref().expect("operator command"),
            "--branch-point",
            &branch.branch_point,
            "--parent",
            &branch.parent,
            "--opportunity",
            branch.opportunity.as_deref().expect("branch opportunity"),
            "--domain",
            branch.domain.as_deref().expect("branch domain"),
            "--all",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "crucible",
            "campaign",
            "--socket",
            "/run/crucible/campaign.sock",
            "--principal",
            "operator",
            "branch",
            "created",
            "--expected",
            &branch.expected,
            "--branch-point",
            &branch.branch_point,
            "--parent",
            &branch.parent,
            "--opportunity",
            branch.opportunity.as_deref().expect("branch opportunity"),
            "--domain",
            branch.domain.as_deref().expect("branch domain"),
            "--value",
            "false",
        ])
        .is_err()
    );

    let expected = snapshot("current").to_string();
    let command = hash("pause").to_hex();
    let pause = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "pause",
        "example",
        "--expected",
        &expected,
        "--command",
        &command,
        "--active",
        "checkpoint",
    ])
    .expect("campaign pause arguments");
    assert!(matches!(
        pause.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Pause(CampaignPauseArgs {
                active: CampaignPausePolicyArg::Checkpoint,
                ..
            }),
            ..
        })
    ));

    let budget = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "budget",
        "example",
        "--expected",
        &expected,
        "--command",
        &hash("budget").to_hex(),
        "add",
        "11",
        "--proposals",
        "13",
    ])
    .expect("campaign budget arguments");
    assert!(matches!(
        budget.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Budget(CampaignBudgetArgs {
                operation: CampaignBudgetCommand::Add(CampaignBudgetAddArgs {
                    attempts: 11,
                    proposals: 13,
                }),
                ..
            }),
            ..
        })
    ));

    let configuration = ConfigurationId::from_hash(hash("pin-configuration")).to_string();
    let pin = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "pin",
        "example",
        "--expected",
        &expected,
        "--command",
        &hash("pin").to_hex(),
        &configuration,
        "--tier",
        "exact",
        "--reason",
        "retain reproducer",
    ])
    .expect("campaign pin arguments");
    assert!(matches!(
        pin.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Pin(CampaignPinArgs {
                tier: CampaignPinRetentionArg::Exact,
                ref reason,
                ..
            }),
            ..
        }) if reason == "retain reproducer"
    ));

    let unpin = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "unpin",
        "example",
        "--expected",
        &expected,
        "--command",
        &hash("unpin").to_hex(),
        &configuration,
        "--reason",
        "resolved",
    ])
    .expect("campaign unpin arguments");
    assert!(matches!(
        unpin.command,
        Commands::Campaign(CampaignArgs {
            command: CampaignCommand::Unpin(CampaignUnpinArgs { ref reason, .. }),
            ..
        }) if reason == "resolved"
    ));
}

fn campaign_records() -> (CampaignLineage, CampaignPolicy) {
    let scenario = ScenarioDefId::from_hash(hash("scenario"));
    let scenario_artifact = ScenarioArtifact::new(scenario, 1, b"scenario-artifact".to_vec())
        .expect("scenario artifact");
    let scenario_artifact_id = scenario_artifact.id().expect("scenario artifact ID");
    let genesis = ConfigurationId::from_hash(hash("genesis"));
    let genesis_artifact = ConfigurationArtifact::new(
        scenario,
        scenario_artifact_id,
        genesis,
        1,
        b"genesis-artifact".to_vec(),
    )
    .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact_id,
        genesis,
        genesis_artifact.id().expect("genesis artifact ID"),
        "crucible-test",
        "qemu-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("campaign lineage");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 64,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("campaign policy");
    (lineage, policy)
}

fn branch_args(label: &str) -> CampaignBranchArgs {
    CampaignBranchArgs {
        name: "created".to_owned(),
        expected: snapshot("created").to_string(),
        command: Some(CampaignCommandId::from_hash(hash(&format!("{label}-command"))).to_string()),
        branch_point: BranchPointId::from_hash(hash(&format!("{label}-point"))).to_string(),
        parent: ConfigurationArtifactId::parse(&fixture_record_id(
            CampaignRecordKind::ConfigurationArtifact,
            &format!("{label}-parent"),
        ))
        .expect("parent ID")
        .to_string(),
        opportunity: Some(
            ChoiceOpportunityId::parse(&fixture_record_id(
                CampaignRecordKind::ChoiceOpportunity,
                &format!("{label}-opportunity"),
            ))
            .expect("opportunity ID")
            .to_string(),
        ),
        domain: Some(
            ChoiceDomainId::parse(&fixture_record_id(
                CampaignRecordKind::ChoiceDomain,
                &format!("{label}-domain"),
            ))
            .expect("domain ID")
            .to_string(),
        ),
        selector: Vec::new(),
        instance: None,
        selector_scan_limit: 256,
        values: vec!["false".to_owned(), "true".to_owned()],
        generator: None,
        all: false,
        proposals: None,
        attempts: 1,
        stop: "next-choice".to_owned(),
    }
}

fn branch_request(label: &str) -> BranchRequest {
    let principal = CampaignPrincipal::new("operator").expect("campaign principal");
    let PreparedCampaignCommand::Branch(request) =
        prepare_campaign_branch(&branch_args(label), &principal).expect("branch request")
    else {
        unreachable!("branch preparation returned another operation")
    };
    request.request().clone()
}

fn graph_page_service() -> (GraphPageService, CampaignSnapshotId, CampaignSnapshotId) {
    let active_policy_body = campaign_records().1;
    let active_policy_id = active_policy_body.id().expect("graph active policy ID");
    let backend = Arc::new(MemoryBlobBackend::new("cli-graph-page", u64::MAX));
    let map = MerkleMap::new(backend);
    let mut root = map.empty().expect("empty graph root");
    let empty = root.content_id();
    let scenario_artifact = ScenarioArtifactId::parse(&fixture_record_id(
        CampaignRecordKind::ScenarioArtifact,
        "cli-graph-scenario",
    ))
    .expect("scenario artifact ID");
    let configuration = ConfigurationArtifact::new(
        ScenarioDefId::from_hash(hash("scenario")),
        scenario_artifact,
        ConfigurationId::from_hash(hash("configuration")),
        1,
        b"configuration".to_vec(),
    )
    .expect("configuration artifact");
    let object =
        ObjectEnvelope::for_configuration_artifact(&configuration).expect("configuration envelope");
    let object_key = hash("first");
    root = map
        .insert(root.content_id(), object_key, object.content_id())
        .expect("configuration graph insertion");
    root = map
        .insert(
            root.content_id(),
            hash("second"),
            fixture_record_content_id(CampaignRecordKind::Fact, "second"),
        )
        .expect("second graph insertion");
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.network.retry",
        ChoiceSource::Workload {
            producer: "network-product".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from(["network-recovery".to_owned()]))
            .expect("choice class"),
        BTreeSet::from(["network".to_owned()]),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        configuration.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("explanation-scheduler"),
            producer: hash("explanation-producer"),
        },
        "network-retry",
        None,
    )
    .expect("choice opportunity");
    let opportunity_id = opportunity.id().expect("choice opportunity ID");
    let domain_id = domain.id().expect("choice domain ID");
    root = map
        .insert(
            root.content_id(),
            CampaignChoiceEntry::new(opportunity_id).graph_key(),
            opportunity_id.content_id(),
        )
        .expect("choice opportunity graph insertion");
    let choice_index = map
        .insert(
            empty,
            CampaignChoiceEntry::new(opportunity_id).index_key(),
            opportunity_id.content_id(),
        )
        .expect("choice opportunity index insertion");
    root = map
        .insert(
            root.content_id(),
            CampaignChoiceEntry::index_anchor_key(),
            choice_index.content_id(),
        )
        .expect("choice opportunity index anchor");
    let branch_request = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(configuration.configuration()),
            configuration.id().expect("configuration artifact ID"),
            opportunity_id,
            domain_id,
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("finite explanation source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("explanation-command"))),
        BranchBudget::new(1, 1).expect("explanation branch budget"),
        StopCondition::NextChoice,
    )
    .expect("explanation branch request");
    let request_id = branch_request.id().expect("explanation request ID");
    let frontier_projection = ContinuationProjection::new(
        request_id,
        branch_request.branch_point(),
        ContinuationState::Ready,
    );
    let frontier_index = map
        .insert(
            empty,
            CampaignHash::from_bytes(request_id.content_id().digest()),
            frontier_projection
                .id()
                .expect("frontier projection ID")
                .content_id(),
        )
        .expect("frontier explanation index");
    let exploration = map
        .insert(
            empty,
            CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b""),
            frontier_index.content_id(),
        )
        .expect("frontier explanation anchor");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        ChoiceValue::Boolean(true),
        branch_request.branch_point(),
    )
    .expect("attempt explanation selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        unreachable!("campaign branch constructor returned another origin")
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(
        branch_request.branch_point(),
        edge,
    )])
    .expect("attempt explanation path");
    let proposal = Proposal::new(
        branch_request.branch_point(),
        request_id,
        domain_id,
        ChoiceValue::Boolean(true),
        active_policy_id,
        None,
        1,
        CampaignViewId::parse(&fixture_record_id(
            CampaignRecordKind::PlanningView,
            "attempt-guidance-view",
        ))
        .expect("attempt guidance view ID"),
    )
    .expect("attempt explanation proposal");
    let proposal_id = proposal.id().expect("attempt explanation proposal ID");
    let exploration = map
        .insert(
            exploration.content_id(),
            content_index_key("exploration.proposal", proposal_id.content_id()),
            proposal_id.content_id(),
        )
        .expect("attempt explanation proposal insertion");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: configuration.id().expect("attempt parent artifact ID"),
            selection: selection.id().expect("attempt selection ID"),
        },
        path.id().expect("attempt path ID"),
        StopCondition::NextChoice,
    )
    .expect("attempt explanation attempt");
    let attempt_id = attempt.id().expect("attempt explanation attempt ID");
    let admission = AttemptAdmission::new(
        attempt_id,
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposal_id),
            cause: branch_request.cause(),
            admission_ordinal: AdmissionOrdinal::new(1),
        },
        policy("policy"),
    );
    let accounting = map
        .insert(
            empty,
            content_index_key("accounting.attempt", attempt_id.content_id()),
            attempt_id.content_id(),
        )
        .expect("attempt explanation accounting insertion");
    let accounting = map
        .insert(
            accounting.content_id(),
            content_index_key(
                "accounting.attempt-execution-basis",
                attempt_id.content_id(),
            ),
            admission
                .id()
                .expect("attempt explanation admission ID")
                .content_id(),
        )
        .expect("attempt explanation admission insertion");
    let finding_observation = Observation::new(
        attempt_id,
        Observation::outcome(
            configuration.configuration(),
            configuration.id().expect("finding child artifact ID"),
            path.id().expect("finding path ID"),
            StopOutcome::ModeledTimeout("execution".to_owned()),
            MeasurementSetId::parse(&fixture_record_id(
                CampaignRecordKind::MeasurementSet,
                "cli-finding-measurements",
            ))
            .expect("finding measurement ID"),
            PropertyVerdictSetId::parse(&fixture_record_id(
                CampaignRecordKind::PropertyVerdictSet,
                "cli-finding-properties",
            ))
            .expect("finding property ID"),
            CoverageProjectionId::parse(&fixture_record_id(
                CampaignRecordKind::CoverageProjection,
                "cli-finding-coverage",
            ))
            .expect("finding coverage ID"),
        ),
        BTreeSet::new(),
    )
    .expect("finding observation");
    let finding_observation_id = finding_observation.id().expect("finding observation ID");
    let observations = map
        .insert(
            empty,
            content_index_key("observations.attempt", attempt_id.content_id()),
            finding_observation_id.content_id(),
        )
        .expect("attempt explanation observation insertion");
    let finding_reproduction = ReproductionArtifact::new(
        crucible_campaign::ReproductionArtifactBasis::new(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration
                .id()
                .expect("finding configuration artifact ID"),
            hash("finding-fingerprint"),
        ),
        1,
        b"reproduce-timeout".to_vec(),
    )
    .expect("finding reproduction");
    let finding_candidate = FindingCandidateBundleId::parse(&fixture_record_id(
        CampaignRecordKind::FindingCandidateBundle,
        "cli-finding-candidate",
    ))
    .expect("finding candidate bundle ID");
    let finding = Finding::new_with_candidate_occurrences(
        Finding::basis(
            FindingSignature::new(
                FindingKind::Timeout,
                hash("finding-fingerprint"),
                None,
                "timeout.execution".to_owned(),
                None,
                BTreeSet::new(),
            )
            .expect("finding signature"),
            finding_observation_id,
            finding_reproduction.id().expect("finding reproduction ID"),
            snapshot("finding-first-seen"),
            FindingOccurrenceSet::new(empty, 3, finding_observation_id)
                .expect("finding occurrences"),
        ),
        None,
        FindingExactPins::default(),
        finding_candidate,
        FindingCandidateOccurrenceSet::new(empty, 1, finding_candidate)
            .expect("finding candidate occurrences"),
    )
    .expect("finding");
    let finding_root = map
        .insert(
            empty,
            finding_index_key(finding.signature().cluster_key()),
            finding.id().expect("finding ID").content_id(),
        )
        .expect("finding index");
    let roots = CampaignRoots {
        graph: root.content_id(),
        exploration: exploration.content_id(),
        observations: observations.content_id(),
        corpus: empty,
        coverage: empty,
        findings: finding_root.content_id(),
        pins: empty,
        accounting: accounting.content_id(),
        coordination: empty,
    };
    let historical = CampaignSnapshot::genesis(
        lineage("lineage"),
        policy("policy"),
        roots,
        budget_ledger("historical-graph"),
    )
    .expect("historical graph snapshot");
    let historical_id = historical.id().expect("historical graph snapshot ID");
    let transition = CampaignFactId::parse(&fixture_record_id(
        CampaignRecordKind::Fact,
        "cli-graph-transition",
    ))
    .expect("transition fact ID");
    let snapshot = CampaignSnapshot::successor(
        historical_id,
        lineage("lineage"),
        active_policy_id,
        roots,
        transition,
        historical.budget_ledger(),
    )
    .expect("current graph snapshot");
    let snapshot_id = snapshot.id().expect("current graph snapshot ID");
    let snapshots = BTreeMap::from([(historical_id, historical), (snapshot_id, snapshot.clone())]);
    (
        GraphPageService {
            map,
            root: root.content_id(),
            snapshot,
            active_policy_body,
            snapshots,
            object_key,
            object,
            declaration,
            domain,
            opportunity,
            additional_choices: Vec::new(),
            branch_request,
            frontier_projection,
            finding,
            finding_root: finding_root.content_id(),
            finding_observation,
            finding_reproduction,
            attempt,
            attempt_admission: admission,
            attempt_path: path,
            attempt_selection: selection,
            attempt_proposal: proposal,
        },
        snapshot_id,
        historical_id,
    )
}

fn bounded_graph_page_service() -> (GraphPageService, CampaignSnapshotId, CampaignSnapshotId) {
    let (mut service, old_snapshot, _) = graph_page_service();
    let timeout = CampaignAttemptTimeoutPolicy::new(Some(100), Some(10), Some(1_000))
        .expect("attempt timeout");
    service.active_policy_body = service
        .active_policy_body
        .clone()
        .with_attempt_timeout_policy(timeout)
        .expect("bounded policy");
    let policy_id = service.active_policy_body.id().expect("bounded policy ID");
    let transition = CampaignFactId::parse(&fixture_record_id(
        CampaignRecordKind::Fact,
        "cli-bounded-branch-transition",
    ))
    .expect("bounded transition");
    service.snapshot = CampaignSnapshot::successor(
        old_snapshot,
        service.snapshot.lineage(),
        policy_id,
        service.snapshot.roots(),
        transition,
        service.snapshot.budget_ledger(),
    )
    .expect("bounded head");
    let bounded_snapshot = service.snapshot.id().expect("bounded head ID");
    service
        .snapshots
        .insert(bounded_snapshot, service.snapshot.clone());
    (service, bounded_snapshot, old_snapshot)
}

fn graph_branch_args(
    service: &GraphPageService,
    snapshot: CampaignSnapshotId,
    command: &str,
) -> CampaignBranchArgs {
    let template = &service.branch_request;
    CampaignBranchArgs {
        name: String::from("example"),
        expected: snapshot.to_string(),
        command: Some(CampaignCommandId::from_hash(hash(command)).to_string()),
        branch_point: template.branch_point().to_string(),
        parent: template.parent().to_string(),
        opportunity: Some(template.opportunity().to_string()),
        domain: Some(template.domain().to_string()),
        selector: Vec::new(),
        instance: None,
        selector_scan_limit: 256,
        values: vec![String::from("true")],
        generator: None,
        all: false,
        proposals: None,
        attempts: 1,
        stop: String::from("next-choice"),
    }
}

fn add_ambiguous_selector_choice(
    mut service: GraphPageService,
) -> (GraphPageService, CampaignSnapshotId) {
    let opportunity = ChoiceOpportunity::new(
        service.opportunity.scenario(),
        &service.declaration,
        &service.domain,
        ChoiceCoordinate {
            scheduler: hash("second-selector-scheduler"),
            producer: hash("second-selector-producer"),
        },
        "network-retry-secondary",
        None,
    )
    .expect("second selector opportunity");
    let opportunity_id = opportunity.id().expect("second selector opportunity ID");
    let old_graph = service.snapshot.roots().graph;
    let choice_index = service
        .map
        .get(old_graph, CampaignChoiceEntry::index_anchor_key())
        .expect("choice index lookup")
        .expect("choice index root");
    let choice_index = service
        .map
        .insert(
            choice_index,
            CampaignChoiceEntry::new(opportunity_id).index_key(),
            opportunity_id.content_id(),
        )
        .expect("second selector index insertion");
    let graph = service
        .map
        .insert(
            old_graph,
            CampaignChoiceEntry::new(opportunity_id).graph_key(),
            opportunity_id.content_id(),
        )
        .expect("second selector graph insertion");
    let graph = service
        .map
        .insert(
            graph.content_id(),
            CampaignChoiceEntry::index_anchor_key(),
            choice_index.content_id(),
        )
        .expect("second selector index anchor");
    let mut roots = service.snapshot.roots();
    roots.graph = graph.content_id();
    let parent = service.snapshot.id().expect("selector parent snapshot ID");
    let transition = CampaignFactId::parse(&fixture_record_id(
        CampaignRecordKind::Fact,
        "cli-selector-ambiguity-transition",
    ))
    .expect("selector transition fact ID");
    let snapshot = CampaignSnapshot::successor(
        parent,
        service.snapshot.lineage(),
        service.snapshot.active_policy(),
        roots,
        transition,
        service.snapshot.budget_ledger(),
    )
    .expect("selector ambiguity snapshot");
    let snapshot_id = snapshot.id().expect("selector ambiguity snapshot ID");
    service.root = graph.content_id();
    service.snapshot = snapshot.clone();
    service.snapshots.insert(snapshot_id, snapshot);
    service.additional_choices.push((
        opportunity,
        service.declaration.clone(),
        service.domain.clone(),
    ));
    (service, snapshot_id)
}

fn finding_index_key(cluster: CampaignHash) -> CampaignHash {
    let namespace = "findings.signature";
    let mut bytes = Vec::with_capacity(namespace.len() + 40);
    bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&cluster.as_bytes());
    CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
}

fn content_index_key(namespace: &str, id: ContentId) -> CampaignHash {
    let encoded = id.encode();
    let mut bytes = Vec::with_capacity(namespace.len() + encoded.len() + 16);
    bytes.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(encoded.as_bytes());
    CampaignHash::derive("crucible.campaign-map-key.v1", &bytes)
}

fn mutation_basis(label: &str) -> CampaignMutationBasisArgs {
    CampaignMutationBasisArgs {
        name: "example".to_owned(),
        expected: snapshot("current").to_string(),
        command: hash(label).to_hex(),
    }
}

fn empty_report_summary() -> crucible_campaign::CampaignReportSummary {
    let semantic = crucible_campaign::CampaignSemanticStatus::new(
        crucible_campaign::CampaignContinuationStatus::default(),
        0,
        0,
        0,
        0,
    )
    .expect("empty report semantic status");
    crucible_campaign::CampaignReportSummary::new(
        CampaignState::Running,
        crucible_campaign::CampaignMode::Strict,
        semantic,
        crucible_campaign::CampaignOutcomeCounts::new(0, 0, 0, 0, 0)
            .expect("empty report outcomes"),
        crucible_campaign::CampaignExecutionBasisCounts::new(0, 0, 0, 0),
        crucible_campaign::CampaignPlannerEvidence::new(0, None)
            .expect("empty report planner evidence"),
        crucible_campaign::CampaignEstimateSummary::new(
            crucible_campaign::CampaignEstimateLabel::Descriptive,
            0,
            None,
        )
        .expect("empty report estimate"),
    )
    .expect("empty report summary")
}

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("crucible-cli-campaign-test", label.as_bytes())
}

fn fixture_record_content_id(kind: CampaignRecordKind, label: &str) -> ContentId {
    ContentId::for_bytes(kind.object_kind(), kind.schema_version(), label.as_bytes())
}

fn fixture_record_id(kind: CampaignRecordKind, label: &str) -> String {
    format!(
        "{}@{}",
        kind.schema_name(),
        fixture_record_content_id(kind, label).encode()
    )
}

fn snapshot(label: &str) -> CampaignSnapshotId {
    CampaignSnapshotId::parse(&fixture_record_id(CampaignRecordKind::Snapshot, label))
        .expect("snapshot id")
}

fn lineage(label: &str) -> CampaignLineageId {
    CampaignLineageId::parse(&fixture_record_id(CampaignRecordKind::Lineage, label))
        .expect("lineage id")
}

fn policy(label: &str) -> CampaignPolicyId {
    CampaignPolicyId::parse(&fixture_record_id(CampaignRecordKind::Policy, label))
        .expect("policy id")
}

#[test]
fn campaign_triage_and_top_level_sugar_parse_the_same_request() {
    let snapshot = snapshot("triage-parser").to_string();
    let nested = Cli::try_parse_from([
        "crucible",
        "campaign",
        "--socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "triage",
        "example",
        "--snapshot",
        &snapshot,
        "--policy",
        "exact",
        "--minimize",
        "all",
        "--recompute-signatures",
    ])
    .expect("campaign triage arguments");
    let top_level = Cli::try_parse_from([
        "crucible",
        "triage",
        "--campaign-socket",
        "/run/crucible/campaign.sock",
        "--principal",
        "operator",
        "example",
        "--snapshot",
        &snapshot,
        "--policy",
        "exact",
        "--minimize",
        "all",
        "--recompute-signatures",
    ])
    .expect("top-level campaign triage arguments");

    let Commands::Campaign(CampaignArgs {
        socket: Some(nested_socket),
        principal: Some(nested_principal),
        command: CampaignCommand::Triage(nested_args),
    }) = nested.command
    else {
        panic!("expected nested campaign triage command");
    };
    let Commands::Triage(top_level_args) = top_level.command else {
        panic!("expected top-level campaign triage sugar");
    };

    assert_eq!(nested_socket, top_level_args.campaign_socket);
    assert_eq!(nested_principal, top_level_args.principal);
    assert_eq!(nested_args, top_level_args.campaign);
}
