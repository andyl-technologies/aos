//! Campaign loopback framing, poisoning, authorization, and deadline tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

use crucible_campaign::{
    ApplyCampaignCommandRequest, ApplyCampaignCommandResponse, BooleanDomain,
    BranchAcceptanceCount, BranchAcceptanceSummary, BranchBudget, BranchPointId, BranchRequest,
    BranchRequestCause, BranchRequestResult, CampaignChoiceEntry, CampaignChoiceObject,
    CampaignChoiceObjectKind, CampaignClient, CampaignCommandId, CampaignCommandResult,
    CampaignContinuationStatus, CampaignControlAction, CampaignDerivationResult,
    CampaignDiscoveryResult, CampaignFact, CampaignHash, CampaignLineage, CampaignLineageId,
    CampaignMode, CampaignName, CampaignOperationalStatus, CampaignPolicy, CampaignPolicyId,
    CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository, CampaignRoots,
    CampaignSeed, CampaignSemanticStatus, CampaignService, CampaignServiceOperation,
    CampaignSnapshot, CampaignSnapshotId, CampaignState, CampaignStatusSummary, CandidateSource,
    ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceDomainId, ChoiceOpportunity,
    ChoiceOpportunityId, ChoiceSource, ChoiceValue, ConfigurationArtifact, ConfigurationArtifactId,
    ConfigurationId, ContinuationProjection, ContinuationState, ControlRequest,
    CreateCampaignRequest, CreateCampaignResponse, DeriveCampaignRequest, DeriveCampaignResponse,
    DiscoveryRequest, ExactRational, ExplainCampaignAttemptRequest, ExplainCampaignAttemptResponse,
    ExplorerPolicy, FairnessPolicy, GetCampaignChoiceObjectRequest,
    GetCampaignChoiceObjectResponse, GetCampaignFindingObjectRequest,
    GetCampaignFindingObjectResponse, GetCampaignFrontierObjectRequest,
    GetCampaignFrontierObjectResponse, GetCampaignGraphObjectRequest,
    GetCampaignGraphObjectResponse, GetCampaignPlannerRankingsRequest,
    GetCampaignPlannerRankingsResponse, GetCampaignRequest, GetCampaignResponse,
    GetCampaignSnapshotRequest, GetCampaignSnapshotResponse, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES,
    MerkleMap, ObjectEnvelope, PinCampaignRequest, PinCampaignResponse, PinChange, PinRequest,
    PinRetention, ProgressiveWideningPolicy, PuctPolicy, QueryCampaignChoicesRequest,
    QueryCampaignChoicesResponse, QueryCampaignFindingsRequest, QueryCampaignFindingsResponse,
    QueryCampaignFrontierRequest, QueryCampaignFrontierResponse, QueryCampaignGraphRequest,
    QueryCampaignGraphResponse, RepositoryCampaignService, RetentionPolicy, ScenarioArtifactId,
    ScenarioDefId, SelectableDeclaration, StopCondition, SubmitCampaignBranchRequest,
    SubmitCampaignBranchResponse, SubmitCampaignDiscoveryRequest, SubmitCampaignDiscoveryResponse,
    WatchCampaignRequest, WatchCampaignResponse,
};
use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

use super::*;
use crate::{CampaignRuntimeAttachmentDisposition, CrucibleCampaignArtifactStore};

#[derive(Clone, Copy)]
struct FixedCampaignService;

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
                summary_recorded: true,
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
            ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"discovery-attempt").encode()
        ))
        .expect("attempt id");
        let admission = crucible_campaign::AttemptAdmissionId::parse(&format!(
            "crucible.campaign.attempt-admission@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 2, b"discovery-admission").encode()
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

#[test]
fn direct_and_loopback_campaign_services_are_identical() {
    let list = crucible_campaign::ListCampaignsRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        None,
        8,
    )
    .expect("list request");
    let create = create_request("network-recovery-create");
    let derive = derive_request("network-recovery", "network-recovery-derived");
    let get = get_request("network-recovery");
    let get_snapshot = snapshot_request(
        "network-recovery",
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed snapshot identity"),
    );
    let watch = watch_request("network-recovery", Some(snapshot("prior")));
    let query = graph_query_request(
        "network-recovery",
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed query snapshot id"),
        None,
        2,
    );
    let findings = finding_query_request(
        "network-recovery",
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed query snapshot id"),
        None,
        2,
    );
    let graph_object = graph_object_request(
        "network-recovery",
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed query snapshot id"),
        fixed_graph_object().0,
    );
    let choices = choice_query_request(
        "network-recovery",
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed query snapshot id"),
        None,
        2,
    );
    let frontier = frontier_query_request(
        "network-recovery",
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed query snapshot id"),
        None,
        2,
    );
    let frontier_object = frontier_object_request(
        "network-recovery",
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed query snapshot id"),
    );
    let choice_object = choice_object_request(
        "network-recovery",
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed query snapshot id"),
        CampaignChoiceObjectKind::Domain,
    );
    let apply = apply_request("network-recovery");
    let pin = pin_request("network-recovery");
    let branch = branch_submission("network-recovery");
    let discovery = discovery_submission("network-recovery");
    let direct = CampaignClient::new(FixedCampaignService);
    let expected_list = direct.list_campaigns(&list).expect("direct list");
    let expected_create = direct.create_campaign(&create).expect("direct create");
    let expected_derive = direct.derive_campaign(&derive).expect("direct derive");
    let expected_get = direct.get_campaign(&get).expect("direct get");
    let expected_snapshot = direct
        .get_campaign_snapshot(&get_snapshot)
        .expect("direct snapshot");
    let expected_watch = direct.watch_campaign(&watch).expect("direct watch");
    let expected_query = direct
        .query_campaign_graph(&query)
        .expect("direct graph query");
    let expected_findings = direct
        .query_campaign_findings(&findings)
        .expect("direct findings query");
    let expected_graph_object = direct
        .get_campaign_graph_object(&graph_object)
        .expect("direct graph object");
    let expected_choices = direct
        .query_campaign_choices(&choices)
        .expect("direct choice query");
    let expected_frontier = direct
        .query_campaign_frontier(&frontier)
        .expect("direct frontier query");
    let expected_frontier_object = direct
        .get_campaign_frontier_object(&frontier_object)
        .expect("direct frontier object");
    let expected_choice_object = direct
        .get_campaign_choice_object(&choice_object)
        .expect("direct choice object");
    let expected_apply = direct.apply_campaign_command(&apply).expect("direct apply");
    let expected_pin = direct.pin_campaign(&pin).expect("direct pin");
    let expected_branch = direct
        .submit_branch_request(&branch)
        .expect("direct branch");
    let expected_discovery = direct
        .submit_discovery_request(&discovery)
        .expect("direct discovery");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        for _ in 0..17 {
            serve_loopback_campaign_once(&mut server_stream, &FixedCampaignService)
                .expect("serve campaign request");
        }
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert_eq!(
        client.list_campaigns(&list).expect("loopback list"),
        expected_list
    );

    assert_eq!(
        client.create_campaign(&create).expect("loopback create"),
        expected_create
    );
    assert_eq!(
        client.derive_campaign(&derive).expect("loopback derive"),
        expected_derive
    );

    assert_eq!(
        client.get_campaign(&get).expect("loopback get"),
        expected_get
    );
    assert_eq!(
        client
            .get_campaign_snapshot(&get_snapshot)
            .expect("loopback snapshot"),
        expected_snapshot
    );
    assert_eq!(
        client.watch_campaign(&watch).expect("loopback watch"),
        expected_watch
    );
    assert_eq!(
        client
            .query_campaign_graph(&query)
            .expect("loopback graph query"),
        expected_query
    );
    assert_eq!(
        client
            .query_campaign_findings(&findings)
            .expect("loopback findings query"),
        expected_findings
    );
    assert_eq!(
        client
            .get_campaign_graph_object(&graph_object)
            .expect("loopback graph object"),
        expected_graph_object
    );
    assert_eq!(
        client
            .query_campaign_choices(&choices)
            .expect("loopback choices"),
        expected_choices
    );
    assert_eq!(
        client
            .query_campaign_frontier(&frontier)
            .expect("loopback frontier"),
        expected_frontier
    );
    assert_eq!(
        client
            .get_campaign_frontier_object(&frontier_object)
            .expect("loopback frontier object"),
        expected_frontier_object
    );
    assert_eq!(
        client
            .get_campaign_choice_object(&choice_object)
            .expect("loopback choice object"),
        expected_choice_object
    );
    assert_eq!(
        client
            .apply_campaign_command(&apply)
            .expect("loopback apply"),
        expected_apply
    );
    assert_eq!(
        client.pin_campaign(&pin).expect("loopback pin"),
        expected_pin
    );
    assert_eq!(
        client
            .submit_branch_request(&branch)
            .expect("loopback branch"),
        expected_branch
    );
    assert_eq!(
        client
            .submit_discovery_request(&discovery)
            .expect("loopback discovery"),
        expected_discovery
    );
    server.join().expect("server thread");
}

#[test]
fn campaign_loopback_rejects_partial_frames_with_a_finite_deadline() {
    let (mut client, mut server) = UnixStream::pair().expect("stream pair");
    let timeouts = LoopbackCampaignTimeouts::new(
        std::time::Duration::from_millis(20),
        std::time::Duration::from_millis(20),
    )
    .expect("timeouts");
    let server_thread = thread::spawn(move || {
        assert!(matches!(
            serve_loopback_campaign_once_with_timeouts(
                &mut server,
                &FixedCampaignService,
                timeouts,
            ),
            Err(LoopbackCampaignServerError::Protocol(
                LoopbackCampaignProtocolError::Io(_)
            ))
        ));
    });
    client.write_all(b"CRUC").expect("partial frame");
    server_thread.join().expect("server thread");
}

#[test]
fn campaign_loopback_frame_header_is_frozen_and_malformed_headers_close() {
    let (mut writer, mut reader) = UnixStream::pair().expect("stream pair");
    write_frame(
        &mut writer,
        GET_CAMPAIGN_REQUEST_KIND,
        b"abc",
        std::time::Duration::from_secs(1),
    )
    .expect("write frame");
    let mut bytes = [0_u8; 19];
    reader.read_exact(&mut bytes).expect("read frame");
    assert_eq!(&bytes, b"CRUCCS20\x01\0\0\0\0\0\0\x03abc");

    for (kind, reserved, length, reason) in [
        (
            GET_CAMPAIGN_REQUEST_KIND,
            [1, 0, 0],
            0,
            "nonzero-reserved-bits",
        ),
        (0xff, [0, 0, 0], 0, "unknown-campaign-service-request-kind"),
        (
            GET_CAMPAIGN_REQUEST_KIND,
            [0, 0, 0],
            u32::try_from(MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES + 1).expect("oversized length"),
            "component-message-too-large",
        ),
    ] {
        let (mut client, mut server) = UnixStream::pair().expect("stream pair");
        let server_thread = thread::spawn(move || {
            assert!(matches!(
                serve_loopback_campaign_once(&mut server, &FixedCampaignService),
                Err(LoopbackCampaignServerError::Protocol(
                    LoopbackCampaignProtocolError::InvalidFrame { reason: actual }
                )) if actual == reason
            ));
        });
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        header[..FRAME_MAGIC.len()].copy_from_slice(FRAME_MAGIC);
        header[8] = kind;
        header[9..12].copy_from_slice(&reserved);
        header[12..].copy_from_slice(&length.to_be_bytes());
        client.write_all(&header).expect("malformed header");
        server_thread.join().expect("server thread");
    }

    for legacy_magic in [
        b"CRUCCS01",
        b"CRUCCS02",
        b"CRUCCS03",
        b"CRUCCS04",
        b"CRUCCS05",
        b"CRUCCS06",
        b"CRUCCS07",
        b"CRUCCS08",
        b"CRUCCS09",
        b"CRUCCS10",
        b"CRUCCS11",
        b"CRUCCS12",
        b"CRUCCS13",
        b"CRUCCS14",
        b"CRUCCS15",
        b"CRUCCS16",
    ] {
        let (mut legacy_client, mut legacy_server) =
            UnixStream::pair().expect("legacy stream pair");
        let legacy_thread = thread::spawn(move || {
            assert!(matches!(
                serve_loopback_campaign_once(&mut legacy_server, &FixedCampaignService),
                Err(LoopbackCampaignServerError::Protocol(
                    LoopbackCampaignProtocolError::InvalidFrame {
                        reason: "unsupported-frame-version"
                    }
                ))
            ));
        });
        let mut legacy_header = [0_u8; FRAME_HEADER_BYTES];
        legacy_header[..8].copy_from_slice(legacy_magic);
        legacy_header[8] = GET_CAMPAIGN_REQUEST_KIND;
        legacy_client
            .write_all(&legacy_header)
            .expect("legacy frame");
        legacy_thread.join().expect("legacy server thread");
    }
}

#[test]
fn campaign_loopback_rejects_concurrent_exchange_without_waiting() {
    let first_request = get_request("first");
    let first_response = GetCampaignResponse::new(
        &first_request,
        snapshot("current"),
        lineage("lineage"),
        policy("policy"),
        CampaignState::Running,
    )
    .expect("first response");
    let (client_stream, mut peer) = UnixStream::pair().expect("stream pair");
    let service = Arc::new(LoopbackCampaignService::new(client_stream).expect("loopback service"));
    let (request_seen_tx, request_seen_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let peer_thread = thread::spawn(move || {
        read_frame(
            &mut peer,
            GET_CAMPAIGN_REQUEST_KIND,
            std::time::Duration::from_secs(1),
        )
        .expect("first request");
        request_seen_tx.send(()).expect("request seen");
        release_rx.recv().expect("release response");
        write_frame(
            &mut peer,
            GET_CAMPAIGN_RESPONSE_KIND,
            &first_response.canonical_bytes(),
            std::time::Duration::from_secs(1),
        )
        .expect("first response");
    });
    let first_service = Arc::clone(&service);
    let first_thread = thread::spawn(move || first_service.get_campaign(&first_request));
    request_seen_rx.recv().expect("first request observed");

    let second_service = Arc::clone(&service);
    let (second_tx, second_rx) = mpsc::channel();
    let second_thread =
        thread::spawn(move || second_tx.send(second_service.get_campaign(&get_request("second"))));
    assert!(matches!(
        second_rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .expect("bounded busy response"),
        Err(LoopbackCampaignServiceError::Protocol(
            LoopbackCampaignProtocolError::ConnectionBusy
        ))
    ));
    second_thread
        .join()
        .expect("second caller")
        .expect("second result receiver");

    release_tx.send(()).expect("release first response");
    first_thread
        .join()
        .expect("first caller")
        .expect("first response");
    peer_thread.join().expect("peer thread");
}

struct WrongGetService {
    response: GetCampaignResponse,
}

impl CampaignService for WrongGetService {
    type Error = Infallible;

    fn list_campaigns(
        &self,
        _request: &crucible_campaign::ListCampaignsRequest,
    ) -> Result<crucible_campaign::ListCampaignsResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn create_campaign(
        &self,
        _request: &CreateCampaignRequest,
    ) -> Result<CreateCampaignResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_planner_rankings(
        &self,
        _request: &GetCampaignPlannerRankingsRequest,
    ) -> Result<GetCampaignPlannerRankingsResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_frontier_object(
        &self,
        _request: &GetCampaignFrontierObjectRequest,
    ) -> Result<GetCampaignFrontierObjectResponse, Self::Error> {
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
fn campaign_loopback_server_rejects_cross_request_responses() {
    let served = get_request("served");
    let other = get_request("other");
    let service = WrongGetService {
        response: GetCampaignResponse::new(
            &other,
            snapshot("current"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        )
        .expect("wrong response"),
    };
    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        assert!(matches!(
            serve_loopback_campaign_once(&mut server_stream, &service),
            Err(LoopbackCampaignServerError::Protocol(
                LoopbackCampaignProtocolError::Codec(_)
            ))
        ));
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert!(matches!(
        client.get_campaign(&served),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::ProtocolViolation
        ))
    ));
    assert!(matches!(
        client.get_campaign(&served),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::ProtocolViolation
        ))
    ));
    server.join().expect("server thread");
}

#[test]
fn campaign_loopback_client_closes_after_a_cross_request_response() {
    let served = get_request("served");
    let other = get_request("other");
    let wrong_response = GetCampaignResponse::new(
        &other,
        snapshot("current"),
        lineage("lineage"),
        policy("policy"),
        CampaignState::Running,
    )
    .expect("wrong response");
    let (client_stream, mut peer) = UnixStream::pair().expect("stream pair");
    let peer_thread = thread::spawn(move || {
        read_frame(
            &mut peer,
            GET_CAMPAIGN_REQUEST_KIND,
            std::time::Duration::from_secs(1),
        )
        .expect("read request");
        write_frame(
            &mut peer,
            GET_CAMPAIGN_RESPONSE_KIND,
            &wrong_response.canonical_bytes(),
            std::time::Duration::from_secs(1),
        )
        .expect("write response");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("client close"), 0);
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert!(matches!(
        client.get_campaign(&served),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::ProtocolViolation
        ))
    ));
    peer_thread.join().expect("peer thread");
}

#[test]
fn campaign_loopback_client_rejects_and_closes_on_wrong_error_request_digest() {
    let served = get_request("served-error");
    let wrong_error = crucible_campaign::CampaignServiceErrorResponse::new(
        get_request("other-error").request_digest(),
        crucible_campaign::CampaignServiceFailure::Unavailable,
    )
    .expect("wrong error response");
    let (client_stream, mut peer) = UnixStream::pair().expect("stream pair");
    let peer_thread = thread::spawn(move || {
        read_frame(
            &mut peer,
            GET_CAMPAIGN_REQUEST_KIND,
            std::time::Duration::from_secs(1),
        )
        .expect("read request");
        write_frame(
            &mut peer,
            SERVICE_ERROR_RESPONSE_KIND,
            &wrong_error.canonical_bytes(),
            std::time::Duration::from_secs(1),
        )
        .expect("write wrong error");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("client close"), 0);
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");

    assert!(matches!(
        loopback.get_campaign(&served),
        Err(LoopbackCampaignServiceError::Protocol(
            LoopbackCampaignProtocolError::Codec(_)
        ))
    ));
    peer_thread.join().expect("peer thread");
}

#[test]
fn campaign_loopback_client_rejects_same_digest_stale_with_wrong_basis() {
    let request = apply_request("stale-basis");
    let wrong_error = crucible_campaign::CampaignServiceErrorResponse::new(
        request.request_digest(),
        crucible_campaign::CampaignServiceFailure::Stale {
            expected: snapshot("wrong-prior"),
            current: snapshot("current"),
        },
    )
    .expect("wrong stale response");
    let (client_stream, mut peer) = UnixStream::pair().expect("stream pair");
    let peer_thread = thread::spawn(move || {
        read_frame(
            &mut peer,
            APPLY_COMMAND_REQUEST_KIND,
            std::time::Duration::from_secs(1),
        )
        .expect("read request");
        write_frame(
            &mut peer,
            SERVICE_ERROR_RESPONSE_KIND,
            &wrong_error.canonical_bytes(),
            std::time::Duration::from_secs(1),
        )
        .expect("write wrong stale response");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("client close"), 0);
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");

    assert!(matches!(
        loopback.apply_campaign_command(&request),
        Err(LoopbackCampaignServiceError::Protocol(
            LoopbackCampaignProtocolError::Codec(_)
        ))
    ));
    peer_thread.join().expect("peer thread");
}

struct DenyAll;

impl CampaignPrincipalAuthorizer for DenyAll {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crucible_campaign::CampaignAuthorizationError> {
        Err(crucible_campaign::CampaignAuthorizationError::Unauthorized)
    }
}

struct AllowAll;

impl CampaignPrincipalAuthorizer for AllowAll {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crucible_campaign::CampaignAuthorizationError> {
        Ok(())
    }
}

struct RecordingPeerResolver {
    observed: mpsc::Sender<UnixPeerCampaignCredentials>,
}

struct RecordingRuntimeControl {
    calls: Arc<AtomicUsize>,
}

impl CampaignRuntimeControlService for RecordingRuntimeControl {
    fn attach_campaign_runtime(
        &self,
        request: &AttachCampaignRuntimeRequest,
    ) -> Result<AttachCampaignRuntimeResponse, CampaignServiceFailure> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        AttachCampaignRuntimeResponse::new(
            request,
            CampaignRuntimeAttachmentDisposition::Attached,
            1,
        )
        .map_err(|_| CampaignServiceFailure::IntegrityFailure)
    }
}

impl UnixPeerCampaignPrincipalResolver for RecordingPeerResolver {
    fn resolve_campaign_principal(
        &self,
        credentials: UnixPeerCampaignCredentials,
    ) -> Result<CampaignPrincipal, crucible_campaign::CampaignAuthorizationError> {
        self.observed
            .send(credentials)
            .map_err(|_| crucible_campaign::CampaignAuthorizationError::Unavailable)?;
        CampaignPrincipal::new("operator:alice")
            .map_err(|_| crucible_campaign::CampaignAuthorizationError::Unavailable)
    }
}

#[test]
fn authenticated_loopback_binds_kernel_peer_to_the_claimed_principal() {
    let mismatched = GetCampaignRequest::new(
        CampaignPrincipal::new("operator:bob").expect("mismatched principal"),
        CampaignName::new("absent").expect("campaign name"),
    )
    .expect("mismatched request");
    let matched = get_request("absent");
    let (observed_tx, observed_rx) = mpsc::channel();
    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "campaign-loopback-peer-auth",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        );
        let resolver = RecordingPeerResolver {
            observed: observed_tx,
        };
        for _ in 0..2 {
            serve_authenticated_repository_campaign_once(
                &mut server_stream,
                &repository,
                &resolver,
                &AllowAll,
            )
            .expect("serve peer-bound request");
        }
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert!(matches!(
        client.get_campaign(&mismatched),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.get_campaign(&matched),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::NotFound
        ))
    ));

    let first = observed_rx.recv().expect("first peer credential");
    let second = observed_rx.recv().expect("second peer credential");
    assert_eq!(first, second);
    assert_eq!(
        first.process_id(),
        i32::try_from(std::process::id()).expect("process id")
    );
    assert_ne!(first.process_id(), 0);
    assert_eq!(first.user_id(), rustix::process::geteuid().as_raw());
    assert_eq!(first.group_id(), rustix::process::getegid().as_raw());
    server.join().expect("server thread");
}

#[test]
fn authenticated_runtime_control_binds_peer_policy_and_exact_response() {
    let mismatched = AttachCampaignRuntimeRequest::new(
        CampaignPrincipal::new("operator:bob").expect("mismatched principal"),
        CampaignName::new("campaign").expect("campaign"),
        "/run/aos/executor.sock",
    )
    .expect("mismatched request");
    let matched = AttachCampaignRuntimeRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("campaign").expect("campaign"),
        "/run/aos/executor.sock",
    )
    .expect("matched request");
    let calls = Arc::new(AtomicUsize::new(0));
    let control = RecordingRuntimeControl {
        calls: Arc::clone(&calls),
    };
    let (observed_tx, observed_rx) = mpsc::channel();
    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "campaign-loopback-runtime-control",
                u64::MAX,
            )),
            Arc::new(MemoryRefBackend::new()),
        );
        let resolver = RecordingPeerResolver {
            observed: observed_tx,
        };
        serve_authenticated_repository_campaign_connection_with_runtime_control_limits(
            &mut server_stream,
            &repository,
            &resolver,
            &AllowAll,
            Some(&control),
            LoopbackCampaignTimeouts::default(),
            2,
        )
        .expect("serve runtime control");
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");

    assert!(matches!(
        loopback.attach_campaign_runtime(&mismatched),
        Err(LoopbackCampaignServiceError::Remote(
            CampaignServiceFailure::Unauthorized
        ))
    ));
    let response = loopback
        .attach_campaign_runtime(&matched)
        .expect("attached response");
    assert_eq!(
        response.disposition(),
        CampaignRuntimeAttachmentDisposition::Attached
    );
    assert_eq!(response.attached_runtime_count(), 1);
    response.validate_for(&matched).expect("response binding");

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        observed_rx.recv().expect("peer credential").user_id(),
        rustix::process::geteuid().as_raw()
    );
    server.join().expect("server thread");
}

#[test]
fn authenticated_connection_rejects_an_invalid_request_ceiling_before_policy() {
    let (mut client, mut server) = UnixStream::pair().expect("stream pair");
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "campaign-loopback-request-ceiling",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    let error = serve_authenticated_repository_campaign_connection_with_limits(
        &mut server,
        &repository,
        &|_| -> Result<CampaignPrincipal, crucible_campaign::CampaignAuthorizationError> {
            panic!("invalid request limit reached the peer resolver")
        },
        &AllowAll,
        LoopbackCampaignTimeouts::default(),
        0,
    )
    .expect_err("zero request ceiling");
    assert!(matches!(
        error,
        LoopbackCampaignServerError::Protocol(LoopbackCampaignProtocolError::InvalidRequestLimit)
    ));
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .expect("client timeout");
    let mut byte = [0_u8; 1];
    assert_eq!(client.read(&mut byte).expect("server close"), 0);
}

#[test]
fn campaign_loopback_preserves_authorization_before_repository_access() {
    let request = get_request("absent");
    let get_snapshot = snapshot_request("absent", snapshot("absent"));
    let watch = watch_request("absent", None);
    let query = graph_query_request("absent", snapshot("absent"), None, 1);
    let findings = finding_query_request("absent", snapshot("absent"), None, 1);
    let graph_object = graph_object_request("absent", snapshot("absent"), hash("graph-key"));
    let choices = choice_query_request("absent", snapshot("absent"), None, 1);
    let frontier = frontier_query_request("absent", snapshot("absent"), None, 1);
    let frontier_object = frontier_object_request("absent", snapshot("absent"));
    let choice_object = choice_object_request(
        "absent",
        snapshot("absent"),
        CampaignChoiceObjectKind::Domain,
    );
    let rankings = GetCampaignPlannerRankingsRequest::new(
        principal(),
        CampaignName::new("absent").expect("campaign name"),
        snapshot("absent"),
        crucible_campaign::PlannerStepId::parse(&format!(
            "crucible.campaign.planner-step@{}",
            ContentId::for_bytes(
                crucible_campaign::CampaignRecordKind::PlannerStep.object_kind(),
                crucible_campaign::CampaignRecordKind::PlannerStep.schema_version(),
                b"absent planner step",
            )
        ))
        .expect("planner step ID"),
    )
    .expect("planner rankings request");
    let direct_repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "campaign-loopback-direct-auth",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    let direct = CampaignClient::new(RepositoryCampaignService::new(&direct_repository, DenyAll));
    assert!(matches!(
        direct.get_campaign(&request),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.get_campaign_snapshot(&get_snapshot),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.watch_campaign(&watch),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.query_campaign_graph(&query),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.query_campaign_findings(&findings),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.get_campaign_graph_object(&graph_object),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.query_campaign_choices(&choices),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.query_campaign_frontier(&frontier),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.get_campaign_frontier_object(&frontier_object),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.get_campaign_choice_object(&choice_object),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.get_campaign_planner_rankings(&rankings),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));

    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new("campaign-loopback-auth", u64::MAX)),
            Arc::new(MemoryRefBackend::new()),
        );
        let service = RepositoryCampaignService::new(&repository, DenyAll);
        for _ in 0..11 {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve denied request");
        }
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let client = CampaignClient::new(loopback);

    assert!(matches!(
        client.get_campaign(&request),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.get_campaign_snapshot(&get_snapshot),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.watch_campaign(&watch),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.query_campaign_graph(&query),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.query_campaign_findings(&findings),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.get_campaign_graph_object(&graph_object),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.query_campaign_choices(&choices),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.query_campaign_frontier(&frontier),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.get_campaign_frontier_object(&frontier_object),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.get_campaign_choice_object(&choice_object),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.get_campaign_planner_rankings(&rankings),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    server.join().expect("server thread");
}

#[test]
fn verifier_import_then_create_works_on_a_blank_repository() {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("campaign-create-blank", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let schedule = crucible::Schedule::empty();
    let artifacts = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    let scenario_id = artifacts
        .import_scenario(&scenario)
        .expect("import scenario");
    let configuration_id = artifacts
        .import_configuration(&scenario, &schedule)
        .expect("import configuration");
    let stored_scenario = repository
        .load_scenario_artifact(scenario_id)
        .expect("stored scenario");
    let stored_configuration = repository
        .load_configuration_artifact(configuration_id)
        .expect("stored configuration");
    let lineage = CampaignLineage::new(
        stored_scenario.scenario(),
        scenario_id,
        stored_configuration.configuration(),
        configuration_id,
        "crucible-test",
        "qemu-test",
        std::collections::BTreeMap::from([("control".to_owned(), 1)]),
        stored_scenario.payload_schema(),
        stored_configuration.payload_schema(),
    )
    .expect("lineage");
    let request = CreateCampaignRequest::new(
        principal(),
        CampaignName::new("blank-imported").expect("campaign name"),
        lineage.clone(),
        creation_policy(lineage.scenario()),
    )
    .expect("create request");
    let client = CampaignClient::new(RepositoryCampaignService::new(
        repository.as_ref(),
        AllowAll,
    ));

    let created = client.create_campaign(&request).expect("create campaign");
    assert!(!created.replayed());
    assert_eq!(created.lineage(), lineage.id().expect("lineage id"));

    let initial_watch = watch_request("blank-imported", None);
    let initial = client
        .watch_campaign(&initial_watch)
        .expect("initial watch");
    assert_eq!(initial.snapshot(), created.snapshot());
    assert_eq!(initial.state(), CampaignState::Created);
    assert!(initial.advanced());
    let unchanged = client
        .watch_campaign(&watch_request("blank-imported", Some(created.snapshot())))
        .expect("unchanged watch");
    assert_eq!(unchanged.snapshot(), created.snapshot());
    assert!(!unchanged.advanced());

    let resumed = client
        .apply_campaign_command(
            &ApplyCampaignCommandRequest::new(
                principal(),
                CampaignName::new("blank-imported").expect("campaign name"),
                ControlRequest {
                    command: CampaignCommandId::from_hash(hash("blank-imported-resume")),
                    expected_snapshot: created.snapshot(),
                    action: CampaignControlAction::Resume,
                },
            )
            .expect("resume request"),
        )
        .expect("resume campaign");
    let advanced = client
        .watch_campaign(&watch_request("blank-imported", Some(created.snapshot())))
        .expect("advanced watch");
    assert_eq!(advanced.snapshot(), resumed.new_snapshot());
    assert_eq!(advanced.state(), CampaignState::Running);
    assert!(advanced.advanced());
    let unknown_cursor = client
        .watch_campaign(&watch_request(
            "blank-imported",
            Some(snapshot("unknown-watch-cursor")),
        ))
        .expect("unknown cursor watch");
    assert_eq!(unknown_cursor.snapshot(), resumed.new_snapshot());
    assert!(unknown_cursor.advanced());

    let historical = client
        .get_campaign_snapshot(&snapshot_request("blank-imported", created.snapshot()))
        .expect("historical snapshot");
    assert_eq!(historical.snapshot(), created.snapshot());
    assert_eq!(
        historical
            .snapshot_body()
            .id()
            .expect("historical body identity"),
        created.snapshot()
    );
    let current_snapshot = client
        .get_campaign_snapshot(&snapshot_request("blank-imported", resumed.new_snapshot()))
        .expect("current snapshot");
    assert_eq!(current_snapshot.snapshot(), resumed.new_snapshot());
    let choices = client
        .query_campaign_choices(&choice_query_request(
            "blank-imported",
            resumed.new_snapshot(),
            None,
            8,
        ))
        .expect("empty choice page");
    assert!(choices.entries().is_empty());
    assert_eq!(choices.next_after(), None);
    assert!(matches!(
        client.get_campaign_snapshot(&snapshot_request(
            "blank-imported",
            snapshot("not-in-campaign"),
        )),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::InvalidRequest
        ))
    ));

    let graph = client
        .query_campaign_graph(&graph_query_request(
            "blank-imported",
            resumed.new_snapshot(),
            None,
            1,
        ))
        .expect("current graph page");
    assert_eq!(graph.snapshot(), resumed.new_snapshot());
    assert_eq!(
        graph
            .snapshot_body()
            .id()
            .expect("graph snapshot body identity"),
        graph.snapshot()
    );
    assert_eq!(
        graph.snapshot_body().roots().graph.kind(),
        ObjectKind::MerkleNode
    );
    assert_eq!(graph.entries().len(), 1);
    let graph_entry = graph.entries()[0];
    let graph_object = client
        .get_campaign_graph_object(&graph_object_request(
            "blank-imported",
            resumed.new_snapshot(),
            graph_entry.key(),
        ))
        .expect("current graph object");
    assert_eq!(graph_object.snapshot_body(), graph.snapshot_body());
    assert_eq!(graph_object.object().content_id(), graph_entry.object());
    assert_eq!(
        graph_object.object().record_kind(),
        crucible_campaign::CampaignRecordKind::ConfigurationArtifact
    );
    assert!(matches!(
        client.get_campaign_graph_object(&graph_object_request(
            "blank-imported",
            resumed.new_snapshot(),
            hash("unknown-graph-object-key"),
        )),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::InvalidRequest
        ))
    ));
    assert!(matches!(
        client.get_campaign_graph_object(&graph_object_request(
            "blank-imported",
            created.snapshot(),
            graph_entry.key(),
        )),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Stale {
                expected,
                current,
            }
        )) if expected == created.snapshot() && current == resumed.new_snapshot()
    ));
    let invalid_cursor = graph_query_request(
        "blank-imported",
        resumed.new_snapshot(),
        Some(hash("unknown-graph-key")),
        1,
    );
    assert!(matches!(
        client.query_campaign_graph(&invalid_cursor),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::InvalidRequest
        ))
    ));
    let stale_graph = graph_query_request("blank-imported", created.snapshot(), None, 1);
    assert!(matches!(
        client.query_campaign_graph(&stale_graph),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Stale {
                expected,
                current,
            }
        )) if expected == created.snapshot() && current == resumed.new_snapshot()
    ));

    let derive = DeriveCampaignRequest::new(
        principal(),
        CampaignName::new("blank-imported").expect("source campaign"),
        resumed.new_snapshot(),
        CampaignName::new("blank-imported-derived").expect("derived campaign"),
        None,
    )
    .expect("derive request");
    let derived = client.derive_campaign(&derive).expect("derive campaign");
    assert!(!derived.replayed());
    assert_eq!(derived.source_snapshot(), resumed.new_snapshot());
    assert!(matches!(
        client.get_campaign_snapshot(&snapshot_request("blank-imported", derived.new_snapshot(),)),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::InvalidRequest
        ))
    ));
    assert_eq!(
        client
            .get_campaign_snapshot(&snapshot_request(
                "blank-imported-derived",
                derived.new_snapshot(),
            ))
            .expect("derived campaign snapshot")
            .snapshot(),
        derived.new_snapshot()
    );
    assert_eq!(
        client
            .derive_campaign(&derive)
            .expect("replay derivation")
            .new_snapshot(),
        derived.new_snapshot()
    );
}

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("campaign-loopback-test", label.as_bytes())
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

fn fixed_query_snapshot() -> (CampaignSnapshot, MerkleMap, ContentId) {
    let backend = Arc::new(MemoryBlobBackend::new("fixed-query", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty fixed query root").content_id();
    let (key, object) = fixed_graph_object();
    let choice = fixed_choice_entry();
    let choice_index = map
        .insert(empty, choice.index_key(), choice.opportunity().content_id())
        .expect("fixed choice index")
        .content_id();
    let root = map
        .insert(empty, key, object.content_id())
        .expect("fixed graph object")
        .content_id();
    let root = map
        .insert(root, CampaignChoiceEntry::index_anchor_key(), choice_index)
        .expect("fixed choice-index anchor")
        .content_id();
    let root = map
        .insert(root, choice.graph_key(), choice.opportunity().content_id())
        .expect("fixed choice opportunity")
        .content_id();
    let projection = fixed_frontier_projection();
    let frontier_index = map
        .insert(
            empty,
            CampaignHash::from_bytes(projection.request().content_id().digest()),
            projection.id().expect("projection id").content_id(),
        )
        .expect("fixed frontier index")
        .content_id();
    let exploration = map
        .insert(
            empty,
            CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b""),
            frontier_index,
        )
        .expect("fixed frontier-index anchor")
        .content_id();
    let roots = CampaignRoots {
        graph: root,
        exploration,
        observations: empty,
        corpus: empty,
        coverage: empty,
        findings: empty,
        pins: empty,
        accounting: empty,
        coordination: empty,
    };
    let snapshot = CampaignSnapshot::genesis(lineage("lineage"), policy("policy"), roots)
        .expect("fixed query snapshot");
    (snapshot, map, root)
}

fn fixed_frontier_projection() -> ContinuationProjection {
    ContinuationProjection::new(
        branch_submission("network-recovery")
            .request()
            .id()
            .expect("fixed frontier request"),
        BranchPointId::from_hash(hash("branch-point")),
        ContinuationState::Ready,
    )
}

fn fixed_choice_entry() -> CampaignChoiceEntry {
    CampaignChoiceEntry::new(
        fixed_choice_objects()
            .2
            .id()
            .expect("fixed choice opportunity"),
    )
}

fn fixed_choice_objects() -> (SelectableDeclaration, ChoiceDomain, ChoiceOpportunity) {
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
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        ScenarioDefId::from_hash(hash("fixed-choice-scenario")),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("fixed-choice-scheduler"),
            producer: hash("fixed-choice-producer"),
        },
        "fixed-choice",
        None,
    )
    .expect("choice opportunity");
    (declaration, domain, opportunity)
}

fn fixed_graph_object() -> (CampaignHash, ObjectEnvelope) {
    let scenario = ScenarioDefId::from_hash(hash("fixed-query-scenario"));
    let scenario_artifact = ScenarioArtifactId::parse(&format!(
        "crucible.campaign.scenario-artifact@{}",
        ContentId::for_bytes(ObjectKind::Scenario, 1, b"fixed-query-scenario").encode()
    ))
    .expect("fixed scenario artifact id");
    let artifact = ConfigurationArtifact::new(
        scenario,
        scenario_artifact,
        ConfigurationId::from_hash(hash("fixed-query-configuration")),
        1,
        b"fixed-query-configuration".to_vec(),
    )
    .expect("fixed configuration artifact");
    (
        hash("fixed-query-graph-key"),
        ObjectEnvelope::for_configuration_artifact(&artifact)
            .expect("fixed configuration envelope"),
    )
}

fn principal() -> CampaignPrincipal {
    CampaignPrincipal::new("operator:alice").expect("principal")
}

fn get_request(name: &str) -> GetCampaignRequest {
    GetCampaignRequest::new(principal(), CampaignName::new(name).expect("campaign name"))
        .expect("get request")
}

fn snapshot_request(name: &str, snapshot: CampaignSnapshotId) -> GetCampaignSnapshotRequest {
    GetCampaignSnapshotRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
    )
    .expect("snapshot request")
}

fn derive_request(source: &str, target: &str) -> DeriveCampaignRequest {
    DeriveCampaignRequest::new(
        principal(),
        CampaignName::new(source).expect("source campaign name"),
        snapshot("derive-source"),
        CampaignName::new(target).expect("target campaign name"),
        None,
    )
    .expect("derive request")
}

fn create_request(name: &str) -> CreateCampaignRequest {
    let scenario = ScenarioDefId::from_hash(hash("create-scenario"));
    let scenario_artifact = ScenarioArtifactId::parse(&format!(
        "crucible.campaign.scenario-artifact@{}",
        ContentId::for_bytes(ObjectKind::Scenario, 1, b"create-scenario-artifact").encode()
    ))
    .expect("scenario artifact id");
    let genesis = ConfigurationId::from_hash(hash("create-genesis"));
    let genesis_artifact = ConfigurationArtifactId::parse(&format!(
        "crucible.campaign.configuration-artifact@{}",
        ContentId::for_bytes(ObjectKind::Configuration, 1, b"create-genesis-artifact").encode()
    ))
    .expect("genesis artifact id");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact,
        genesis,
        genesis_artifact,
        "crucible-test",
        "qemu-test",
        std::collections::BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("lineage");
    CreateCampaignRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        lineage,
        creation_policy(scenario),
    )
    .expect("create request")
}

fn creation_policy(scenario: ScenarioDefId) -> CampaignPolicy {
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("widening constant"),
        ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening");
    CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy")
}

fn apply_request(name: &str) -> ApplyCampaignCommandRequest {
    ApplyCampaignCommandRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("resume")),
            expected_snapshot: snapshot("command-prior"),
            action: CampaignControlAction::Resume,
        },
    )
    .expect("apply request")
}

fn pin_request(name: &str) -> PinCampaignRequest {
    PinCampaignRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        PinRequest {
            command: CampaignCommandId::from_hash(hash("pin")),
            expected_snapshot: snapshot("pin-prior"),
            change: PinChange::new(
                ConfigurationId::from_hash(hash("pinned-configuration")),
                Some(PinRetention::Exact),
                "retain reproducer",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request")
}

fn discovery_submission(name: &str) -> SubmitCampaignDiscoveryRequest {
    let configuration = ConfigurationArtifactId::parse(&format!(
        "crucible.campaign.configuration-artifact@{}",
        ContentId::for_bytes(ObjectKind::Configuration, 1, b"discovery-genesis").encode()
    ))
    .expect("discovery configuration");
    SubmitCampaignDiscoveryRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        DiscoveryRequest::new(
            CampaignCommandId::from_hash(hash("discovery")),
            snapshot("discovery-prior"),
            configuration,
            StopCondition::Terminal,
        )
        .expect("discovery command"),
    )
    .expect("discovery request")
}

fn watch_request(name: &str, after: Option<CampaignSnapshotId>) -> WatchCampaignRequest {
    WatchCampaignRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        after,
    )
    .expect("watch request")
}

fn graph_query_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    after: Option<CampaignHash>,
    limit: u32,
) -> QueryCampaignGraphRequest {
    QueryCampaignGraphRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        after,
        limit,
    )
    .expect("graph query request")
}

fn finding_query_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    after: Option<CampaignHash>,
    limit: u32,
) -> QueryCampaignFindingsRequest {
    QueryCampaignFindingsRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        after,
        limit,
    )
    .expect("finding query request")
}

fn graph_object_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    key: CampaignHash,
) -> GetCampaignGraphObjectRequest {
    GetCampaignGraphObjectRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        key,
    )
    .expect("graph object request")
}

fn choice_query_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    after: Option<ChoiceOpportunityId>,
    limit: u32,
) -> QueryCampaignChoicesRequest {
    QueryCampaignChoicesRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        after,
        limit,
    )
    .expect("choice query request")
}

fn frontier_query_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    after: Option<crucible_campaign::BranchRequestId>,
    limit: u32,
) -> QueryCampaignFrontierRequest {
    QueryCampaignFrontierRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        after,
        limit,
    )
    .expect("frontier query request")
}

fn frontier_object_request(
    name: &str,
    snapshot: CampaignSnapshotId,
) -> GetCampaignFrontierObjectRequest {
    GetCampaignFrontierObjectRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        fixed_frontier_projection().request(),
    )
    .expect("frontier object request")
}

fn choice_object_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    kind: CampaignChoiceObjectKind,
) -> GetCampaignChoiceObjectRequest {
    GetCampaignChoiceObjectRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        fixed_choice_entry().opportunity(),
        kind,
    )
    .expect("choice object request")
}

fn branch_submission(name: &str) -> SubmitCampaignBranchRequest {
    SubmitCampaignBranchRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot("branch-prior"),
        BranchRequest::new(
            BranchPointId::from_hash(hash("branch-point")),
            ConfigurationArtifactId::parse(&format!(
                "crucible.campaign.configuration-artifact@{}",
                ContentId::for_bytes(ObjectKind::Configuration, 1, b"parent").encode()
            ))
            .expect("parent id"),
            ChoiceOpportunityId::parse(&format!(
                "crucible.campaign.choice-opportunity@{}",
                ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"opportunity").encode()
            ))
            .expect("opportunity id"),
            ChoiceDomainId::parse(&format!(
                "crucible.campaign.choice-domain@{}",
                ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"domain").encode()
            ))
            .expect("domain id"),
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                .expect("finite source"),
            BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("branch-command"))),
            BranchBudget::new(1, 1).expect("branch budget"),
            StopCondition::NextChoice,
        )
        .expect("branch request"),
    )
    .expect("branch submission")
}
