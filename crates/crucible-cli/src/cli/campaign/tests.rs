//! Unit tests for campaign CLI command handling.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use super::*;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crucible_campaign::*;
use crucible_cas::content_store::{ContentId, MemoryBlobBackend, ObjectKind};
use crucible_daemon::serve_loopback_campaign_once;

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
            summary_recorded: true,
            replayed: false,
        },
    )
    .expect("fixed branch response")
}

fn fixed_campaign_status_response(request: &GetCampaignStatusRequest) -> GetCampaignStatusResponse {
    let continuations = CampaignContinuationStatus::new(2, 3, 5, 7, 11);
    let semantic = CampaignSemanticStatus::new(continuations, 13, 17, 28, 2_048)
        .expect("fixed semantic status");
    let operational = CampaignOperationalStatus::Observed(CampaignOperationalEvidence::new(
        DaemonEpoch::from_bytes([0x44; 16]).expect("daemon epoch"),
        hash("inventory"),
        CampaignWorldStatus::new(19, 23, 29, 31, 37, 41),
        43,
        47,
    ));
    GetCampaignStatusResponse::new(request, CampaignStatusSummary::new(semantic, operational))
        .expect("fixed status response")
}

fn status_sequence_head(index: usize) -> CampaignSnapshotId {
    match index {
        0 => snapshot("head-a"),
        1 => snapshot("head-b"),
        2 => snapshot("head-c"),
        _ => snapshot("head-d"),
    }
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
        Ok(GetCampaignResponse::new(
            request,
            snapshot("current"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        )
        .expect("fixed get response"))
    }

    fn get_campaign_status(
        &self,
        request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        Ok(fixed_campaign_status_response(request))
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
}

impl CampaignService for StatusSequenceService {
    type Error = CampaignServiceFailure;

    fn get_campaign(
        &self,
        request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        let get_index = self.calls.get.fetch_add(1, Ordering::SeqCst);
        let head = status_sequence_head(get_index);

        Ok(GetCampaignResponse::new(
            request,
            head,
            lineage("lineage"),
            policy("policy"),
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
                current: status_sequence_head(status_index + 1),
            });
        }

        Ok(fixed_campaign_status_response(request))
    }

    unreachable_status_sequence_operations! {
        fn list_campaigns(ListCampaignsRequest) -> ListCampaignsResponse;
        fn create_campaign(CreateCampaignRequest) -> CreateCampaignResponse;
        fn derive_campaign(DeriveCampaignRequest) -> DeriveCampaignResponse;
        fn get_campaign_snapshot(GetCampaignSnapshotRequest) -> GetCampaignSnapshotResponse;
        fn watch_campaign(WatchCampaignRequest) -> WatchCampaignResponse;
        fn query_campaign_graph(QueryCampaignGraphRequest) -> QueryCampaignGraphResponse;
        fn get_campaign_graph_object(GetCampaignGraphObjectRequest) -> GetCampaignGraphObjectResponse;
        fn query_campaign_choices(QueryCampaignChoicesRequest) -> QueryCampaignChoicesResponse;
        fn query_campaign_frontier(QueryCampaignFrontierRequest) -> QueryCampaignFrontierResponse;
        fn query_campaign_findings(QueryCampaignFindingsRequest) -> QueryCampaignFindingsResponse;
        fn get_campaign_finding_object(GetCampaignFindingObjectRequest) -> GetCampaignFindingObjectResponse;
        fn explain_campaign_attempt(ExplainCampaignAttemptRequest) -> ExplainCampaignAttemptResponse;
        fn get_campaign_planner_rankings(GetCampaignPlannerRankingsRequest) -> GetCampaignPlannerRankingsResponse;
        fn get_campaign_frontier_object(GetCampaignFrontierObjectRequest) -> GetCampaignFrontierObjectResponse;
        fn get_campaign_choice_object(GetCampaignChoiceObjectRequest) -> GetCampaignChoiceObjectResponse;
        fn apply_campaign_command(ApplyCampaignCommandRequest) -> ApplyCampaignCommandResponse;
        fn pin_campaign(PinCampaignRequest) -> PinCampaignResponse;
        fn submit_branch_request(SubmitCampaignBranchRequest) -> SubmitCampaignBranchResponse;
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
        _request: &GetCampaignRequest,
    ) -> Result<GetCampaignResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
    }

    fn get_campaign_status(
        &self,
        _request: &GetCampaignStatusRequest,
    ) -> Result<GetCampaignStatusResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
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
        let proposal_id = self
            .attempt_proposal
            .id()
            .expect("attempt explanation proposal ID");
        let (_, proposal_proof) = self
            .map
            .get_with_proof(
                roots.exploration,
                content_index_key("exploration.proposal", proposal_id.content_id()),
            )
            .expect("attempt proposal explanation proof");
        let (_, observation_proof) = self
            .map
            .get_with_proof(
                roots.observations,
                content_index_key("observations.attempt", request.attempt().content_id()),
            )
            .expect("attempt observation explanation proof");
        Ok(ExplainCampaignAttemptResponse::new(
            request,
            self.snapshot.clone(),
            self.attempt.clone(),
            self.attempt_admission,
            self.attempt_path.clone(),
            Some(self.attempt_selection.clone()),
            Some(self.attempt_proposal.clone()),
            None,
            Some(self.finding_observation.clone()),
            attempt_proof,
            admission_proof,
            Some(proposal_proof),
            None,
            observation_proof,
        )
        .expect("bound attempt explanation response"))
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
        _request: &QueryCampaignFrontierRequest,
    ) -> Result<QueryCampaignFrontierResponse, Self::Error> {
        unreachable!("unused campaign-service operation")
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
}

#[test]
fn campaign_head_report_renders_machine_and_human_forms() {
    let report = CampaignHeadReport {
        schema: CAMPAIGN_HEAD_REPORT_SCHEMA,
        operation: "watch",
        campaign: "example".to_owned(),
        snapshot: "snapshot".to_owned(),
        lineage: "lineage".to_owned(),
        policy: "policy".to_owned(),
        state: "running",
        advanced: Some(true),
        semantic: None,
        operational: None,
    };

    let json = render_campaign_head(&report, OutputFormat::Json).expect("JSON report");
    let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(decoded["schema"], CAMPAIGN_HEAD_REPORT_SCHEMA);
    assert_eq!(decoded["advanced"], true);

    let table = render_campaign_head(&report, OutputFormat::Table).expect("table report");
    assert!(table.contains("campaign   example"));
    assert!(table.contains("advanced   true"));

    let markdown = render_campaign_head(&report, OutputFormat::Markdown).expect("Markdown report");
    assert!(markdown.contains("| state | running |"));
}

#[test]
fn campaign_mutation_report_renders_exact_transition_basis() {
    let report = CampaignMutationReport {
        schema: CAMPAIGN_MUTATION_REPORT_SCHEMA,
        operation: "pause",
        campaign: "example".to_owned(),
        command: hash("pause").to_hex(),
        prior_snapshot: snapshot("prior").to_string(),
        new_snapshot: snapshot("next").to_string(),
        replayed: true,
    };

    let json = render_campaign_mutation(&report, OutputFormat::Json).expect("JSON report");
    let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(decoded["schema"], CAMPAIGN_MUTATION_REPORT_SCHEMA);
    assert_eq!(decoded["prior_snapshot"], report.prior_snapshot);
    assert_eq!(decoded["new_snapshot"], report.new_snapshot);
    assert_eq!(decoded["replayed"], true);

    let table = render_campaign_mutation(&report, OutputFormat::Table).expect("table report");
    assert!(table.contains("operation       pause"));
    assert!(table.contains("replayed        true"));

    let markdown =
        render_campaign_mutation(&report, OutputFormat::Markdown).expect("Markdown report");
    assert!(markdown.contains("| prior_snapshot |"));
    assert!(markdown.contains("| new_snapshot |"));
}

#[test]
fn campaign_acceptance_reports_render_exact_idempotent_results() {
    let reports = [
        CampaignAcceptanceReport::Create {
            schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
            campaign: "created".to_owned(),
            snapshot: snapshot("created").to_string(),
            lineage: lineage("lineage").to_string(),
            active_policy: policy("policy").to_string(),
            replayed: false,
            start: Some(CampaignCreateStartReport {
                command: hash("start").to_hex(),
                prior_snapshot: snapshot("created").to_string(),
                new_snapshot: snapshot("started").to_string(),
                replayed: false,
            }),
        },
        CampaignAcceptanceReport::Derive {
            schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
            source_campaign: "source".to_owned(),
            source_snapshot: snapshot("source").to_string(),
            campaign: "derived".to_owned(),
            new_snapshot: snapshot("derived").to_string(),
            active_policy: policy("policy").to_string(),
            replayed: true,
        },
        CampaignAcceptanceReport::Branch {
            schema: CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA,
            campaign: "created".to_owned(),
            request: branch_request("render")
                .id()
                .expect("request ID")
                .to_string(),
            prior_snapshot: snapshot("prior").to_string(),
            new_snapshot: snapshot("next").to_string(),
            summary: CampaignBranchAcceptanceSummaryReport::new(
                BranchAcceptanceSummary::new(
                    BranchAcceptanceCount::Exact(1),
                    BranchAcceptanceCount::Exact(0),
                    BranchAcceptanceCount::Exact(1),
                    1,
                    1,
                )
                .expect("acceptance summary"),
                true,
            ),
            replayed: false,
        },
    ];

    for report in reports {
        let json = render_campaign_acceptance(&report, OutputFormat::Json).expect("JSON report");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_ACCEPTANCE_REPORT_SCHEMA);
        assert!(decoded.get("operation").is_some());
        assert!(decoded.get("replayed").is_some());
        if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
            assert_eq!(decoded["start"]["command"], hash("start").to_hex());
            assert_eq!(
                decoded["start"]["prior_snapshot"],
                snapshot("created").to_string()
            );
            assert_eq!(
                decoded["start"]["new_snapshot"],
                snapshot("started").to_string()
            );
        }
        if matches!(&report, CampaignAcceptanceReport::Branch { .. }) {
            assert_eq!(decoded["validated_cardinality"]["kind"], "exact");
            assert_eq!(decoded["validated_cardinality"]["count"], 1);
            assert_eq!(decoded["deduplicated_existing_edges"]["count"], 0);
            assert_eq!(decoded["remaining_lazy_candidates"]["count"], 1);
            assert_eq!(decoded["budget"]["maximum_proposals"], 1);
            assert_eq!(decoded["budget"]["maximum_attempts"], 1);
            assert_eq!(decoded["summary_provenance"], "recorded");
        }

        let table = render_campaign_acceptance(&report, OutputFormat::Table).expect("table report");
        assert!(table.contains("operation"));
        assert!(table.contains("replayed"));
        if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
            assert!(table.contains("start_command"));
            assert!(table.contains("start_snapshot"));
        }
        if matches!(&report, CampaignAcceptanceReport::Branch { .. }) {
            assert!(table.contains("validated_cardinality 1"));
            assert!(table.contains("deduplicated_edges 0"));
            assert!(table.contains("remaining_candidates 1"));
            assert!(table.contains("summary_provenance recorded"));
        }
        let markdown =
            render_campaign_acceptance(&report, OutputFormat::Markdown).expect("Markdown report");
        assert!(markdown.contains("| replayed |"));
        if matches!(&report, CampaignAcceptanceReport::Create { .. }) {
            assert!(markdown.contains("| start_prior_snapshot |"));
            assert!(markdown.contains("| start_replayed |"));
        }
        if matches!(&report, CampaignAcceptanceReport::Branch { .. }) {
            assert!(markdown.contains("| validated_cardinality | 1 |"));
            assert!(markdown.contains("| summary_provenance | recorded |"));
        }
    }
}

#[test]
fn campaign_branch_acceptance_summary_json_has_exact_and_range_goldens() {
    let exact = CampaignBranchAcceptanceSummaryReport::new(
        BranchAcceptanceSummary::new(
            BranchAcceptanceCount::Exact(3),
            BranchAcceptanceCount::Exact(1),
            BranchAcceptanceCount::Exact(2),
            3,
            2,
        )
        .expect("exact acceptance summary"),
        true,
    );
    assert_eq!(
        serde_json::to_string(&exact).expect("exact summary JSON"),
        r#"{"validated_cardinality":{"kind":"exact","count":3},"deduplicated_existing_edges":{"kind":"exact","count":1},"remaining_lazy_candidates":{"kind":"exact","count":2},"budget":{"maximum_proposals":3,"maximum_attempts":2},"summary_provenance":"recorded"}"#
    );

    let ranged = CampaignBranchAcceptanceSummaryReport::new(
        BranchAcceptanceSummary::new(
            BranchAcceptanceCount::between(4, 8).expect("cardinality range"),
            BranchAcceptanceCount::between(0, 2).expect("deduplication range"),
            BranchAcceptanceCount::between(2, 4).expect("remaining range"),
            4,
            1,
        )
        .expect("ranged acceptance summary"),
        false,
    );
    assert_eq!(
        serde_json::to_string(&ranged).expect("ranged summary JSON"),
        r#"{"validated_cardinality":{"kind":"range","minimum":4,"maximum":8},"deduplicated_existing_edges":{"kind":"range","minimum":0,"maximum":2},"remaining_lazy_candidates":{"kind":"range","minimum":2,"maximum":4},"budget":{"maximum_proposals":4,"maximum_attempts":1},"summary_provenance":"legacy-recomputed"}"#
    );
    assert_eq!(
        ranged.human_fields(),
        vec![
            ("validated_cardinality", "4..=8".to_owned()),
            ("deduplicated_edges", "0..=2".to_owned()),
            ("remaining_candidates", "2..=4".to_owned()),
            ("maximum_proposals", "4".to_owned()),
            ("maximum_attempts", "1".to_owned()),
            ("summary_provenance", "legacy-recomputed".to_owned()),
        ]
    );
}

#[test]
fn campaign_page_reports_render_all_query_shapes() {
    let snapshot = snapshot("page").to_string();
    let reports = [
        CampaignPageReport {
            schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
            operation: "graph",
            campaign: "example".to_owned(),
            snapshot: snapshot.clone(),
            start_after: None,
            page_limit: 1,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 1,
            complete: false,
            next_after: Some(hash("cursor").to_hex()),
            entries: vec![CampaignPageEntry::Graph {
                key: hash("graph-key").to_hex(),
                object: ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"object").to_string(),
            }],
        },
        CampaignPageReport {
            schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
            operation: "choices",
            campaign: "example".to_owned(),
            snapshot: snapshot.clone(),
            start_after: None,
            page_limit: 1,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 1,
            complete: true,
            next_after: None,
            entries: vec![CampaignPageEntry::Choice {
                opportunity: "choice".to_owned(),
            }],
        },
        CampaignPageReport {
            schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
            operation: "frontier",
            campaign: "example".to_owned(),
            snapshot: snapshot.clone(),
            start_after: None,
            page_limit: 1,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 1,
            complete: true,
            next_after: None,
            entries: vec![CampaignPageEntry::Frontier {
                request: "request".to_owned(),
                branch_point: "branch-point".to_owned(),
                state: "waiting-for-feedback",
                completed_visits: Some(3),
                required_visits: Some(5),
            }],
        },
        CampaignPageReport {
            schema: CAMPAIGN_PAGE_REPORT_SCHEMA,
            operation: "findings",
            campaign: "example".to_owned(),
            snapshot,
            start_after: None,
            page_limit: 1,
            page_budget: 1,
            pages_scanned: 1,
            response_bytes: 1,
            complete: false,
            next_after: Some(hash("finding-cursor").to_hex()),
            entries: vec![CampaignPageEntry::Finding {
                finding: "finding".to_owned(),
                cluster: hash("cluster").to_hex(),
                finding_kind: "timeout",
                fingerprint: hash("fingerprint").to_hex(),
                property: None,
                failure_class: "timeout.execution".to_owned(),
                observation: "observation".to_owned(),
                occurrences: 3,
                reproduction: "reproduction".to_owned(),
                minimized: None,
            }],
        },
    ];

    for report in reports {
        let json = render_campaign_page(&report, OutputFormat::Json).expect("JSON page");
        let decoded: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(decoded["schema"], CAMPAIGN_PAGE_REPORT_SCHEMA);
        assert_eq!(decoded["operation"], report.operation);
        assert_eq!(decoded["pages_scanned"], 1);
        assert_eq!(decoded["response_bytes"], 1);
        assert_eq!(decoded["entries"].as_array().map(Vec::len), Some(1));

        let table = render_campaign_page(&report, OutputFormat::Table).expect("table page");
        assert!(table.contains("campaign    example"));
        assert!(table.contains("page_budget 1"));
        let markdown =
            render_campaign_page(&report, OutputFormat::Markdown).expect("Markdown page");
        assert!(markdown.contains("| entries | 1 |"));
        assert!(markdown.contains("| pages | 1 |"));
    }
}

#[test]
fn campaign_status_and_watch_use_the_checked_loopback_transport() {
    let status = CampaignCommand::Status(CampaignStatusArgs {
        name: "example".to_owned(),
    });
    let status_report = query_over_loopback(&status);
    assert_eq!(status_report.operation, "status");
    assert_eq!(status_report.snapshot, snapshot("current").to_string());
    assert_eq!(status_report.advanced, None);
    let status_json =
        render_campaign_head(&status_report, OutputFormat::Json).expect("campaign status JSON");
    let status_value: serde_json::Value =
        serde_json::from_str(&status_json).expect("valid campaign status JSON");
    assert_eq!(status_value["schema"], CAMPAIGN_STATUS_REPORT_SCHEMA);
    assert_eq!(status_value["semantic"]["latent_or_open_continuations"], 10);
    assert_eq!(status_value["semantic"]["admitted_attempts"], 13);
    assert_eq!(status_value["semantic"]["stored_graph_nodes"], 17);
    assert_eq!(status_value["semantic"]["continuation_records_scanned"], 28);
    assert_eq!(status_value["operational"]["availability"], "observed");
    assert_eq!(status_value["operational"]["running_worlds"], 23);
    assert_eq!(status_value["operational"]["retained_checkpoint_roots"], 43);
    assert_eq!(status_value["operational"]["materialized_checkpoints"], 47);
    let status_table =
        render_campaign_head(&status_report, OutputFormat::Table).expect("campaign status table");
    assert!(status_table.contains("latent_or_open_continuations 10"));
    assert!(status_table.contains("operational observed"));
    assert!(status_table.contains("running_worlds 23"));

    let watch = CampaignCommand::Watch(CampaignWatchArgs {
        name: "example".to_owned(),
        after: Some(snapshot("previous").to_string()),
    });
    let watch_report = query_over_loopback(&watch);
    assert_eq!(watch_report.operation, "watch");
    assert_eq!(watch_report.state, "running");
    assert_eq!(watch_report.advanced, Some(true));
    let watch_value = serde_json::to_value(&watch_report).expect("watch JSON");
    assert!(watch_value.get("semantic").is_none());
    assert!(watch_value.get("operational").is_none());
}

#[test]
fn campaign_status_refreshes_the_entire_pair_after_one_stale_snapshot() {
    let calls = Arc::new(StatusSequenceCalls::default());
    let client = CampaignClient::new(StatusSequenceService {
        calls: Arc::clone(&calls),
        stale_statuses: 1,
        terminal_failure: None,
    });
    let command = CampaignCommand::Status(CampaignStatusArgs {
        name: "example".to_string(),
    });

    let report = query_campaign_head(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("the refreshed paired read succeeds");

    assert_eq!(report.snapshot, snapshot("head-b").to_string());
    assert_eq!(calls.get.load(Ordering::SeqCst), 2);
    assert_eq!(calls.status.load(Ordering::SeqCst), 2);
}

#[test]
fn campaign_status_stops_after_bounded_snapshot_churn() {
    let calls = Arc::new(StatusSequenceCalls::default());
    let client = CampaignClient::new(StatusSequenceService {
        calls: Arc::clone(&calls),
        stale_statuses: usize::MAX,
        terminal_failure: None,
    });
    let command = CampaignCommand::Status(CampaignStatusArgs {
        name: "example".to_string(),
    });

    let error = match query_campaign_head(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    ) {
        Ok(_) => panic!("persistent churn must remain a terminal status failure"),
        Err(error) => error,
    };

    let rendered = error.to_string();
    assert!(rendered.contains("stale"), "unexpected error: {rendered}");
    assert_eq!(
        calls.get.load(Ordering::SeqCst),
        MAX_CAMPAIGN_STATUS_PAIR_ATTEMPTS
    );
    assert_eq!(
        calls.status.load(Ordering::SeqCst),
        MAX_CAMPAIGN_STATUS_PAIR_ATTEMPTS
    );
}

#[test]
fn campaign_status_does_not_retry_a_non_stale_failure() {
    let calls = Arc::new(StatusSequenceCalls::default());
    let client = CampaignClient::new(StatusSequenceService {
        calls: Arc::clone(&calls),
        stale_statuses: 0,
        terminal_failure: Some(CampaignServiceFailure::Unauthorized),
    });
    let command = CampaignCommand::Status(CampaignStatusArgs {
        name: "example".to_string(),
    });

    let error = match query_campaign_head(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    ) {
        Ok(_) => panic!("authorization failure must remain terminal"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("not authorized"));
    assert_eq!(calls.get.load(Ordering::SeqCst), 1);
    assert_eq!(calls.status.load(Ordering::SeqCst), 1);
}

#[test]
fn campaign_validation_authenticates_connected_and_offline_targets() {
    let validate = CampaignValidateArgs {
        name: Some("example".to_owned()),
        policy: None,
    };
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
            .expect("serve one campaign validation");
    });
    let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
    let client = CampaignClient::new(service);
    let report = query_campaign_validation(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &validate,
    )
    .expect("checked campaign validation");
    server.join().expect("campaign server thread");
    let validation::CampaignValidationReport::Campaign {
        campaign,
        snapshot: current,
        state,
        ..
    } = &report
    else {
        panic!("connected validation report");
    };
    assert_eq!(campaign, "example");
    assert_eq!(current, &snapshot("current").to_string());
    assert_eq!(*state, "running");
    let rendered =
        render_campaign_validation(&report, OutputFormat::Json).expect("campaign validation JSON");
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(
        value["schema"],
        validation::CAMPAIGN_VALIDATION_REPORT_SCHEMA
    );
    assert_eq!(value["subject"], "campaign");

    let temporary = tempfile::tempdir().expect("temporary policy input");
    let path = temporary.path().join("policy.bin");
    let (_, policy) = campaign_records();
    let canonical = policy.canonical_bytes();
    std::fs::write(&path, &canonical).expect("write canonical policy");
    let report = validate_campaign_policy_file(&path).expect("offline policy validation");
    let validation::CampaignValidationReport::Policy {
        policy: validated,
        encoded_bytes,
        choice_policies,
        ..
    } = &report
    else {
        panic!("offline policy validation report");
    };
    assert_eq!(validated, &policy.id().expect("policy ID").to_string());
    assert_eq!(*encoded_bytes, canonical.len());
    assert_eq!(*choice_policies, 0);
    assert!(
        render_campaign_validation(&report, OutputFormat::Markdown)
            .expect("policy validation Markdown")
            .contains("| subject | policy |")
    );
    let invocation = Cli::try_parse_from([
        std::ffi::OsString::from("crucible"),
        std::ffi::OsString::from("campaign"),
        std::ffi::OsString::from("validate"),
        std::ffi::OsString::from("--policy"),
        path.as_os_str().to_owned(),
    ])
    .expect("offline validation invocation");
    let Commands::Campaign(args) = &invocation.command else {
        panic!("campaign validation command");
    };
    run_campaign_invocation(&invocation, args).expect("offline validation without a socket");

    let mut malformed = canonical;
    malformed.push(0);
    std::fs::write(&path, malformed).expect("write malformed policy");
    assert!(validate_campaign_policy_file(&path).is_err());
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
fn campaign_list_uses_the_checked_loopback_transport_across_pages() {
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        for _page in 0..2 {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve one campaign list page");
        }
    });
    let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
    let client = CampaignClient::new(service);
    let report = query_campaign_list(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &CampaignListArgs {
            after: None,
            limit: 1,
            pages: 2,
        },
    )
    .expect("checked campaign list");
    server.join().expect("campaign server thread");

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
}

#[test]
fn campaign_graph_page_uses_the_checked_proof_bearing_transport() {
    let (service, snapshot, _) = graph_page_service();
    let command = CampaignCommand::Graph(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        after: None,
        limit: 1,
        pages: 1,
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve graph page request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let report = query_campaign_page(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("checked graph query");
    server.join().expect("campaign server thread");

    assert_eq!(report.operation, "graph");
    assert_eq!(report.snapshot, snapshot.to_string());
    assert_eq!(report.entries.len(), 1);
    assert!(report.next_after.is_some());
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
fn campaign_findings_page_uses_the_checked_proof_bearing_transport() {
    let (service, snapshot, _) = graph_page_service();
    let command = CampaignCommand::Findings(CampaignPageArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        after: None,
        limit: 1,
        pages: 1,
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve finding page request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let report = query_campaign_page(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("checked findings query");
    server.join().expect("campaign server thread");

    assert_eq!(report.operation, "findings");
    assert_eq!(report.snapshot, snapshot.to_string());
    assert_eq!(report.entries.len(), 1);
    assert!(report.next_after.is_none());
    assert!(matches!(
        &report.entries[0],
        CampaignPageEntry::Finding {
            finding_kind: "timeout",
            occurrences: 3,
            ..
        }
    ));
}

#[test]
fn campaign_graph_object_uses_the_checked_proof_bearing_transport() {
    let (service, snapshot, _) = graph_page_service();
    let key = service.object_key;
    let command = CampaignCommand::GraphObject(CampaignGraphObjectArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        key: key.to_hex(),
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve graph object request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let report = query_campaign_object(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("checked graph object query");
    server.join().expect("campaign server thread");

    let rendered = render_campaign_object(&report, OutputFormat::Json).expect("object JSON");
    let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(decoded["schema"], "crucible.cli.campaign-object.v1");
    assert_eq!(decoded["operation"], "graph-object");
    assert_eq!(decoded["snapshot"], snapshot.to_string());
    assert_eq!(decoded["object"]["kind"], "configuration");
    assert_eq!(decoded["object"]["key"], key.to_hex());
}

#[test]
fn campaign_compare_uses_two_checked_historical_snapshot_reads() {
    let (service, right, left) = graph_page_service();
    let command = CampaignCommand::Compare(CampaignCompareArgs {
        name: "example".to_owned(),
        left: left.to_string(),
        right: right.to_string(),
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve left snapshot request");
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve right snapshot request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let report = query_campaign_snapshot(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("checked campaign comparison");
    server.join().expect("campaign server thread");

    let rendered = render_campaign_snapshot(&report, OutputFormat::Json).expect("compare JSON");
    let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(decoded["schema"], "crucible.cli.campaign-compare.v1");
    assert_eq!(decoded["direct_relationship"], "left-parent-of-right");
    assert_eq!(decoded["left"]["id"], left.to_string());
    assert_eq!(decoded["right"]["id"], right.to_string());
    assert_eq!(decoded["changed"]["active_policy"], true);
}

#[test]
fn campaign_explain_joins_two_checked_proof_bearing_records() {
    let (service, snapshot, _) = graph_page_service();
    let opportunity = service
        .opportunity
        .id()
        .expect("explanation opportunity ID");
    let request = service.branch_request.id().expect("explanation request ID");
    let command = CampaignCommand::Explain(CampaignExplainArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        opportunity: opportunity.to_string(),
        request: request.to_string(),
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve explanation choice request");
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve explanation frontier request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let report = query_campaign_explanation(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("checked campaign explanation");
    server.join().expect("campaign server thread");

    let rendered =
        render_campaign_explanation(&report, OutputFormat::Json).expect("explanation JSON");
    let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(decoded["schema"], "crucible.cli.campaign-explanation.v1");
    assert_eq!(decoded["opportunity"]["id"], opportunity.to_string());
    assert_eq!(decoded["legality"]["domain_kind"], "boolean");
    assert_eq!(decoded["legality"]["required"], true);
    assert_eq!(decoded["cause"]["request"], request.to_string());
    assert_eq!(decoded["cause"]["continuation_state"], "ready");
    assert_eq!(decoded["cause"]["finite_values"][0], "true");
}

#[test]
fn campaign_finding_explain_joins_observation_and_reproduction_proofs() {
    let (service, snapshot, _) = graph_page_service();
    let finding = service.finding.id().expect("explanation finding ID");
    let command = CampaignCommand::ExplainFinding(CampaignFindingExplainArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        finding: finding.to_string(),
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve finding observation request");
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve finding reproduction request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let report = query_campaign_finding_explanation(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("checked finding explanation");
    server.join().expect("campaign server thread");

    let rendered = render_campaign_finding_explanation(&report, OutputFormat::Json)
        .expect("finding explanation JSON");
    let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(
        decoded["schema"],
        "crucible.cli.campaign-finding-explanation.v1"
    );
    assert_eq!(decoded["finding"]["id"], finding.to_string());
    assert_eq!(decoded["finding"]["kind"], "timeout");
    assert_eq!(decoded["observation"]["stop"], "modeled-timeout:execution");
    assert_eq!(decoded["reproduction"]["payload_schema"], 1);
    assert_eq!(decoded["reproduction"]["payload_bytes"], 17);
}

#[test]
fn campaign_attempt_explain_authenticates_proposal_and_completion() {
    let (service, snapshot, _) = graph_page_service();
    let attempt = service.attempt.id().expect("explanation attempt ID");
    let proposal = service
        .attempt_proposal
        .id()
        .expect("explanation proposal ID");
    let observation = service
        .finding_observation
        .id()
        .expect("explanation observation ID");
    let command = CampaignCommand::ExplainAttempt(CampaignAttemptExplainArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        attempt: attempt.to_string(),
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve attempt explanation request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let report = query_campaign_attempt_explanation(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("checked attempt explanation");
    server.join().expect("campaign server thread");

    let rendered = render_campaign_attempt_explanation(&report, OutputFormat::Json)
        .expect("attempt explanation JSON");
    let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(
        decoded["schema"],
        "crucible.cli.campaign-attempt-explanation.v2"
    );
    assert_eq!(decoded["attempt"]["id"], attempt.to_string());
    assert_eq!(decoded["attempt"]["start"], "branch");
    assert_eq!(decoded["proposal"]["id"], proposal.to_string());
    assert_eq!(decoded["selection"]["value"], "true");
    assert_eq!(decoded["observation"]["id"], observation.to_string());
}

#[test]
fn campaign_explain_rejects_individually_authenticated_unrelated_records() {
    let (service, _, _) = graph_page_service();
    let (service, snapshot) = mismatch_explanation_frontier(service);
    let opportunity = service
        .opportunity
        .id()
        .expect("explanation opportunity ID");
    let request = service
        .branch_request
        .id()
        .expect("mismatched explanation request ID");
    let command = CampaignCommand::Explain(CampaignExplainArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        opportunity: opportunity.to_string(),
        request: request.to_string(),
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve mismatched explanation choice request");
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve mismatched explanation frontier request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let error = query_campaign_explanation(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect_err("unrelated explanation records must fail closed");
    server.join().expect("campaign server thread");
    assert!(
        error
            .to_string()
            .contains("do not share one opportunity and domain")
    );
}

#[test]
fn campaign_create_derive_and_branch_use_checked_loopback_transport() {
    let (lineage_record, policy_record) = campaign_records();
    let principal = CampaignPrincipal::new("operator").expect("campaign principal");
    let create = accept_over_loopback(PreparedCampaignCommand::Create(
        CreateCampaignRequest::new(
            principal.clone(),
            CampaignName::new("created").expect("campaign name"),
            lineage_record,
            policy_record.clone(),
        )
        .expect("create request"),
    ));
    assert!(matches!(
        create,
        CampaignAcceptanceReport::Create { snapshot: value, replayed: false, .. }
            if value == snapshot("created").to_string()
    ));

    let started = accept_start_over_loopback(
        CreateCampaignRequest::new(
            principal.clone(),
            CampaignName::new("started").expect("started campaign name"),
            campaign_records().0,
            policy_record.clone(),
        )
        .expect("create-and-start request"),
        CampaignCommandId::from_hash(hash("start-command")),
    );
    assert!(matches!(
        started,
        CampaignAcceptanceReport::Create {
            snapshot: value,
            replayed: false,
            start: Some(CampaignCreateStartReport {
                prior_snapshot,
                new_snapshot,
                replayed: false,
                ..
            }),
            ..
        } if value == snapshot("created").to_string()
            && prior_snapshot == snapshot("created").to_string()
            && new_snapshot == snapshot("started").to_string()
    ));

    let derive = accept_over_loopback(PreparedCampaignCommand::Derive(
        DeriveCampaignRequest::new(
            principal.clone(),
            CampaignName::new("created").expect("source name"),
            snapshot("created"),
            CampaignName::new("derived").expect("target name"),
            Some(policy_record),
        )
        .expect("derive request"),
    ));
    assert!(matches!(
        derive,
        CampaignAcceptanceReport::Derive { new_snapshot, replayed: false, .. }
            if new_snapshot == snapshot("derived").to_string()
    ));

    let branch = accept_over_loopback(
        prepare_campaign_branch(&branch_args("branch"), &principal)
            .expect("prepared finite branch request"),
    );
    assert!(matches!(
        branch,
        CampaignAcceptanceReport::Branch {
            replayed: false,
            ..
        }
    ));
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
        template.branch_point(),
        template.parent(),
        template.opportunity(),
        template.domain(),
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
        template.branch_point(),
        template.parent(),
        template.opportunity(),
        template.domain(),
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
fn campaign_mutation_uses_the_checked_loopback_transport() {
    let command = CampaignCommand::Pause(CampaignPauseArgs {
        basis: mutation_basis("pause"),
        active: CampaignPausePolicyArg::Checkpoint,
    });
    let report = mutate_over_loopback(&command);

    assert_eq!(report.operation, "pause");
    assert_eq!(report.command, hash("pause").to_hex());
    assert_eq!(report.prior_snapshot, snapshot("current").to_string());
    assert_eq!(report.new_snapshot, snapshot("mutated").to_string());
    assert!(!report.replayed);
}

#[test]
fn campaign_start_uses_the_checked_resume_transition() {
    let command = CampaignCommand::Start(mutation_basis("start"));
    let report = mutate_over_loopback(&command);

    assert_eq!(report.operation, "start");
    assert_eq!(report.command, hash("start").to_hex());
    assert_eq!(report.prior_snapshot, snapshot("current").to_string());
    assert_eq!(report.new_snapshot, snapshot("started").to_string());
    assert!(!report.replayed);
}

#[test]
fn campaign_pin_uses_the_checked_loopback_transport() {
    let configuration = ConfigurationId::from_hash(hash("pin-configuration"));
    let command = CampaignCommand::Pin(CampaignPinArgs {
        basis: mutation_basis("pin"),
        configuration: configuration.to_string(),
        tier: CampaignPinRetentionArg::Exact,
        reason: "retain reproducer".to_owned(),
    });
    let report = pin_over_loopback(&command);

    assert_eq!(report.operation, "pin");
    assert_eq!(report.command, hash("pin").to_hex());
    assert_eq!(report.prior_snapshot, snapshot("current").to_string());
    assert_eq!(report.new_snapshot, snapshot("pinned").to_string());
    assert!(!report.replayed);
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
    let generator = CandidateGeneratorSpecId::parse(&format!(
        "crucible.campaign.candidate-generator-spec@{}",
        ContentId::for_bytes(ObjectKind::Policy, 1, b"branch-generator").encode()
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
                    CampaignWorkedNetworkFixtureArgs { ref output },
                ),
            }),
        }) if output == &PathBuf::from("/tmp/worked-network")
    ));

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
    let finding = FindingId::parse(&format!(
        "crucible.campaign.finding@{}",
        ContentId::for_bytes(ObjectKind::Finding, 1, b"finding-explanation-parser").encode()
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
    let attempt = AttemptId::parse(&format!(
        "crucible.campaign.attempt@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"attempt-explanation-parser").encode()
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

    let planner_step = PlannerStepId::parse(&format!(
        "crucible.campaign.planner-step@{}",
        ContentId::for_bytes(
            CampaignRecordKind::PlannerStep.object_kind(),
            CampaignRecordKind::PlannerStep.schema_version(),
            b"planner ranking step",
        )
    ))
    .expect("planner step ID");
    let branch_point = BranchPointId::from_hash(hash("planner-ranking-branch-point"));
    let source = BranchRequestId::parse(&format!(
        "crucible.campaign.branch-request@{}",
        ContentId::for_bytes(
            CampaignRecordKind::BranchRequest.object_kind(),
            CampaignRecordKind::BranchRequest.schema_version(),
            b"planner ranking source",
        )
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
        &format!(
            "crucible.campaign.candidate-generator-spec@{}",
            ContentId::for_bytes(ObjectKind::Policy, 1, b"parser-generator").encode()
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

fn query_over_loopback(command: &CampaignCommand) -> CampaignHeadReport {
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let serves_status = matches!(command, CampaignCommand::Status(_));
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
            .expect("serve one campaign request");
        if serves_status {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve campaign status request");
        }
    });
    let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
    let client = CampaignClient::new(service);
    let report = query_campaign_head(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        command,
    )
    .expect("checked campaign query");
    server.join().expect("campaign server thread");
    report
}

fn mutate_over_loopback(command: &CampaignCommand) -> CampaignMutationReport {
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
            .expect("serve one campaign mutation");
    });
    let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
    let client = CampaignClient::new(service);
    let report = apply_campaign_mutation(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        command,
    )
    .expect("checked campaign mutation");
    server.join().expect("campaign server thread");
    report
}

fn pin_over_loopback(command: &CampaignCommand) -> CampaignMutationReport {
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
            .expect("serve one campaign pin mutation");
    });
    let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
    let client = CampaignClient::new(service);
    let report = apply_campaign_pin(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        command,
    )
    .expect("checked campaign pin mutation");
    server.join().expect("campaign server thread");
    report
}

fn accept_over_loopback(prepared: PreparedCampaignCommand) -> CampaignAcceptanceReport {
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
            .expect("serve one campaign acceptance");
    });
    let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
    let client = CampaignClient::new(service);
    let report = apply_campaign_acceptance(&client, prepared).expect("checked campaign acceptance");
    server.join().expect("campaign server thread");
    report
}

fn accept_start_over_loopback(
    request: CreateCampaignRequest,
    command: CampaignCommandId,
) -> CampaignAcceptanceReport {
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        for _operation in 0..2 {
            serve_loopback_campaign_once(&mut server_stream, &FixedHeadService)
                .expect("serve create-and-start operation");
        }
    });
    let service = LoopbackCampaignService::new(client_stream).expect("loopback client");
    let client = CampaignClient::new(service);
    let report = apply_campaign_acceptance(
        &client,
        PreparedCampaignCommand::CreateAndStart(request, command),
    )
    .expect("checked create-and-start acceptance");
    server.join().expect("campaign server thread");
    report
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
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 64,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
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
        parent: ConfigurationArtifactId::parse(&format!(
            "crucible.campaign.configuration-artifact@{}",
            ContentId::for_bytes(
                ObjectKind::Configuration,
                1,
                format!("{label}-parent").as_bytes(),
            )
            .encode()
        ))
        .expect("parent ID")
        .to_string(),
        opportunity: Some(
            ChoiceOpportunityId::parse(&format!(
                "crucible.campaign.choice-opportunity@{}",
                ContentId::for_bytes(
                    ObjectKind::CampaignFact,
                    1,
                    format!("{label}-opportunity").as_bytes(),
                )
                .encode()
            ))
            .expect("opportunity ID")
            .to_string(),
        ),
        domain: Some(
            ChoiceDomainId::parse(&format!(
                "crucible.campaign.choice-domain@{}",
                ContentId::for_bytes(
                    ObjectKind::CampaignFact,
                    1,
                    format!("{label}-domain").as_bytes(),
                )
                .encode()
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
    let backend = Arc::new(MemoryBlobBackend::new("cli-graph-page", u64::MAX));
    let map = MerkleMap::new(backend);
    let mut root = map.empty().expect("empty graph root");
    let empty = root.content_id();
    let scenario_artifact = ScenarioArtifactId::parse(&format!(
        "crucible.campaign.scenario-artifact@{}",
        ContentId::for_bytes(ObjectKind::Scenario, 1, b"cli-graph-scenario").encode()
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
            ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"second"),
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
        opportunity.branch_point_id(configuration.configuration()),
        configuration.id().expect("configuration artifact ID"),
        opportunity_id,
        domain_id,
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
        policy("next-policy"),
        None,
        1,
        CampaignViewId::parse(&format!(
            "crucible.campaign.planning-view@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"attempt-guidance-view",).encode()
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
        configuration.configuration(),
        configuration.id().expect("finding child artifact ID"),
        path.id().expect("finding path ID"),
        StopOutcome::ModeledTimeout("execution".to_owned()),
        MeasurementSetId::parse(&format!(
            "crucible.campaign.measurement-set@{}",
            ContentId::for_bytes(ObjectKind::Observation, 1, b"cli-finding-measurements").encode()
        ))
        .expect("finding measurement ID"),
        PropertyVerdictSetId::parse(&format!(
            "crucible.campaign.property-verdict-set@{}",
            ContentId::for_bytes(ObjectKind::Observation, 1, b"cli-finding-properties").encode()
        ))
        .expect("finding property ID"),
        CoverageProjectionId::parse(&format!(
            "crucible.campaign.coverage-projection@{}",
            ContentId::for_bytes(ObjectKind::Projection, 1, b"cli-finding-coverage").encode()
        ))
        .expect("finding coverage ID"),
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
        configuration.scenario(),
        configuration.scenario_artifact(),
        configuration.configuration(),
        configuration
            .id()
            .expect("finding configuration artifact ID"),
        hash("finding-fingerprint"),
        1,
        b"reproduce-timeout".to_vec(),
    )
    .expect("finding reproduction");
    let finding = Finding::new(
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
        FindingOccurrenceSet::new(empty, 3, finding_observation_id).expect("finding occurrences"),
        None,
        BTreeSet::new(),
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
    let historical = CampaignSnapshot::genesis(lineage("lineage"), policy("policy"), roots)
        .expect("historical graph snapshot");
    let historical_id = historical.id().expect("historical graph snapshot ID");
    let transition = CampaignFactId::parse(&format!(
        "crucible.campaign.fact@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 2, b"cli-graph-transition").encode()
    ))
    .expect("transition fact ID");
    let snapshot = CampaignSnapshot::successor(
        historical_id,
        lineage("lineage"),
        policy("next-policy"),
        roots,
        transition,
    )
    .expect("current graph snapshot");
    let snapshot_id = snapshot.id().expect("current graph snapshot ID");
    let snapshots = BTreeMap::from([(historical_id, historical), (snapshot_id, snapshot.clone())]);
    (
        GraphPageService {
            map,
            root: root.content_id(),
            snapshot,
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
    let transition = CampaignFactId::parse(&format!(
        "crucible.campaign.fact@{}",
        ContentId::for_bytes(
            ObjectKind::CampaignFact,
            2,
            b"cli-selector-ambiguity-transition",
        )
        .encode()
    ))
    .expect("selector transition fact ID");
    let snapshot = CampaignSnapshot::successor(
        parent,
        service.snapshot.lineage(),
        service.snapshot.active_policy(),
        roots,
        transition,
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

fn mismatch_explanation_frontier(
    mut service: GraphPageService,
) -> (GraphPageService, CampaignSnapshotId) {
    let foreign_opportunity = ChoiceOpportunityId::parse(&format!(
        "crucible.campaign.choice-opportunity@{}",
        ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"foreign-explanation-opportunity",
        )
        .encode()
    ))
    .expect("foreign explanation opportunity ID");
    let prior = &service.branch_request;
    let branch_request = BranchRequest::new(
        prior.branch_point(),
        prior.parent(),
        foreign_opportunity,
        prior.domain(),
        prior.source().clone(),
        prior.cause(),
        prior.budget(),
        prior.stop().clone(),
    )
    .expect("mismatched explanation branch request");
    let request_id = branch_request.id().expect("mismatched request ID");
    let frontier_projection = ContinuationProjection::new(
        request_id,
        branch_request.branch_point(),
        ContinuationState::Ready,
    );
    let empty = service
        .map
        .empty()
        .expect("empty mismatch root")
        .content_id();
    let frontier_index = service
        .map
        .insert(
            empty,
            CampaignHash::from_bytes(request_id.content_id().digest()),
            frontier_projection
                .id()
                .expect("mismatched projection ID")
                .content_id(),
        )
        .expect("mismatched frontier index");
    let exploration = service
        .map
        .insert(
            empty,
            CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b""),
            frontier_index.content_id(),
        )
        .expect("mismatched frontier anchor");
    let mut roots = service.snapshot.roots();
    roots.exploration = exploration.content_id();
    let snapshot = CampaignSnapshot::genesis(
        service.snapshot.lineage(),
        service.snapshot.active_policy(),
        roots,
    )
    .expect("mismatched explanation snapshot");
    let snapshot_id = snapshot.id().expect("mismatched explanation snapshot ID");
    service.snapshot = snapshot.clone();
    service.snapshots = BTreeMap::from([(snapshot_id, snapshot)]);
    service.branch_request = branch_request;
    service.frontier_projection = frontier_projection;
    (service, snapshot_id)
}

fn mutation_basis(label: &str) -> CampaignMutationBasisArgs {
    CampaignMutationBasisArgs {
        name: "example".to_owned(),
        expected: snapshot("current").to_string(),
        command: hash(label).to_hex(),
    }
}

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("crucible-cli-campaign-test", label.as_bytes())
}

#[test]
fn planner_attempt_explanations_render_guidance_and_accounting() {
    macro_rules! stored_id {
        ($type:ident, $tag:literal, $kind:expr, $version:expr, $label:literal) => {
            $type::parse(&format!(
                concat!($tag, "@{}"),
                ContentId::for_bytes($kind, $version, $label.as_bytes()).encode()
            ))
            .expect(concat!("valid ", $tag))
        };
    }

    let selected = PlanningScanPosition::new(
        BranchPointId::from_hash(hash("planner-explanation-branch-point")),
        stored_id!(
            BranchRequestId,
            "crucible.campaign.branch-request",
            ObjectKind::CampaignFact,
            1,
            "planner-explanation-request"
        ),
    );
    let step = PlannerStep::new(
        None,
        stored_id!(
            PlannerInvocationId,
            "crucible.campaign.planner-invocation",
            ObjectKind::Policy,
            2,
            "planner-explanation-invocation"
        ),
        stored_id!(
            RetainedPlannerRequestId,
            "crucible.campaign.retained-planner-request",
            ObjectKind::Policy,
            1,
            "planner-explanation-retained-request"
        ),
        hash("planner-explanation-request-digest"),
        policy("planner-explanation-policy"),
        stored_id!(
            PlannerEngineId,
            "crucible.campaign.planner-engine",
            ObjectKind::Policy,
            1,
            "planner-explanation-engine"
        ),
        stored_id!(
            PolicyArtifactId,
            "crucible.campaign.policy-artifact",
            ObjectKind::Policy,
            1,
            "planner-explanation-policy-artifact"
        ),
        stored_id!(
            CampaignViewId,
            "crucible.campaign.planning-view",
            ObjectKind::CampaignFact,
            1,
            "planner-explanation-view"
        ),
        PlannerDisposition::Issue {
            selected,
            issued_branch_requests: Vec::new(),
            issued_proposals: vec![stored_id!(
                ProposalId,
                "crucible.campaign.proposal",
                ObjectKind::CampaignFact,
                1,
                "planner-explanation-proposal"
            )],
        },
        stored_id!(
            PlannerStateId,
            "crucible.campaign.planner-state",
            ObjectKind::Policy,
            1,
            "planner-explanation-state"
        ),
        PlanningUsage {
            branch_requests: 0,
            proposals: 1,
            input_objects: 12,
            input_bytes: 34_567,
            fuel: 890,
        },
        PlanningAccounting {
            branch_requests: 0,
            proposals: 1,
            attempts: 1,
            deduplicated: 0,
            input_objects: 12,
            input_bytes: 34_567,
            fuel: 890,
        },
        GuidanceEvidence::new(BTreeMap::from([
            (String::from("exploration"), 125_000),
            (String::from("novelty"), 750_000),
        ]))
        .expect("valid planner guidance evidence"),
    )
    .expect("valid planner explanation step");

    let explained =
        explain::explained_planner_decision(&step).expect("authenticated planner explanation");
    let value = serde_json::to_value(explained).expect("planner explanation JSON");

    assert_eq!(
        value["selected_branch_point"],
        selected.branch_point().to_string()
    );
    assert_eq!(value["selected_source"], selected.source().to_string());
    assert_eq!(value["guidance_terms_micros"]["exploration"], 125_000);
    assert_eq!(value["guidance_terms_micros"]["novelty"], 750_000);
    assert_eq!(value["accounting"]["attempts"], 1);
    assert_eq!(value["accounting"]["input_bytes"], 34_567);
    assert_eq!(value["accounting"]["fuel"], 890);
}

fn snapshot(label: &str) -> CampaignSnapshotId {
    CampaignSnapshotId::parse(&format!(
        "crucible.campaign.snapshot@{}",
        ContentId::for_bytes(ObjectKind::CampaignSnapshot, 2, label.as_bytes()).encode()
    ))
    .expect("snapshot id")
}

fn lineage(label: &str) -> CampaignLineageId {
    CampaignLineageId::parse(&format!(
        "crucible.campaign.lineage@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, label.as_bytes()).encode()
    ))
    .expect("lineage id")
}

fn policy(label: &str) -> CampaignPolicyId {
    CampaignPolicyId::parse(&format!(
        "crucible.campaign.policy@{}",
        ContentId::for_bytes(ObjectKind::Policy, 1, label.as_bytes()).encode()
    ))
    .expect("policy id")
}
