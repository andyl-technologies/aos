//! Authenticated campaign explanation query and rendering tests.

use super::*;

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
    assert!(decoded["attempt"].get("origin").is_none());
    assert!(decoded["attempt"].get("reached").is_none());
    assert_eq!(decoded["proposal"]["id"], proposal.to_string());
    assert_eq!(decoded["selection"]["value"], "true");
    assert_eq!(decoded["observation"]["id"], observation.to_string());
}

#[test]
fn campaign_attempt_explain_renders_continuation_origin_and_boundary() {
    let (service, _, _) = graph_page_service();
    let (service, snapshot, origin, reached) = continuation_attempt_service(service);
    let attempt = service.attempt.id().expect("continuation attempt ID");
    let command = CampaignCommand::ExplainAttempt(CampaignAttemptExplainArgs {
        name: "example".to_owned(),
        snapshot: snapshot.to_string(),
        attempt: attempt.to_string(),
    });
    let (client_stream, mut server_stream) = UnixStream::pair().expect("campaign stream pair");
    let server = thread::spawn(move || {
        serve_loopback_campaign_once(&mut server_stream, &service)
            .expect("serve continuation attempt explanation request");
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback client"));

    let report = query_campaign_attempt_explanation(
        &client,
        CampaignPrincipal::new("operator").expect("campaign principal"),
        &command,
    )
    .expect("checked continuation attempt explanation");
    server.join().expect("campaign server thread");

    let rendered = render_campaign_attempt_explanation(&report, OutputFormat::Json)
        .expect("continuation attempt explanation JSON");
    let decoded: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
    assert_eq!(
        decoded["schema"],
        "crucible.cli.campaign-attempt-explanation.v2"
    );
    assert_eq!(decoded["attempt"]["start"], "after-attempt");
    assert_eq!(decoded["attempt"]["origin"], origin.to_string());
    assert_eq!(decoded["attempt"]["reached"], reached.to_string());
    assert!(decoded["attempt"].get("parent").is_none());
    assert!(decoded["attempt"].get("selection").is_none());

    let markdown = render_campaign_attempt_explanation(&report, OutputFormat::Markdown)
        .expect("continuation attempt explanation markdown");
    assert!(markdown.contains(&format!("| attempt.origin | {origin} |")));
    assert!(markdown.contains(&format!("| attempt.reached | {reached} |")));
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

fn continuation_attempt_service(
    mut service: GraphPageService,
) -> (
    GraphPageService,
    CampaignSnapshotId,
    AttemptId,
    ConfigurationArtifactId,
) {
    let origin = service
        .attempt
        .id()
        .expect("continuation origin attempt ID");
    let reached = service.finding_observation.child_content();
    let attempt = Attempt::new(
        AttemptStart::AfterAttempt { origin, reached },
        service
            .attempt_path
            .id()
            .expect("continuation attempt path ID"),
        StopCondition::NextChoice,
    )
    .expect("continuation attempt");
    let attempt_id = attempt.id().expect("continuation attempt ID");
    let admission = AttemptAdmission::new(
        attempt_id,
        AttemptAdmissionRole::ExecutionBasis {
            proposal: None,
            cause: service.branch_request.cause(),
            admission_ordinal: AdmissionOrdinal::new(2),
        },
    );

    let mut roots = service.snapshot.roots();
    let accounting = service
        .map
        .insert(
            roots.accounting,
            content_index_key("accounting.attempt", attempt_id.content_id()),
            attempt_id.content_id(),
        )
        .expect("continuation attempt accounting insertion");
    let accounting = service
        .map
        .insert(
            accounting.content_id(),
            content_index_key(
                "accounting.attempt-execution-basis",
                attempt_id.content_id(),
            ),
            admission
                .id()
                .expect("continuation admission ID")
                .content_id(),
        )
        .expect("continuation admission accounting insertion");
    roots.accounting = accounting.content_id();

    let parent = service
        .snapshot
        .id()
        .expect("continuation parent snapshot ID");
    let transition = CampaignFactId::parse(&format!(
        "crucible.campaign.fact@{}",
        ContentId::for_bytes(
            ObjectKind::CampaignFact,
            2,
            b"cli-continuation-attempt-transition",
        )
        .encode()
    ))
    .expect("continuation transition fact ID");
    let snapshot = CampaignSnapshot::successor(
        parent,
        service.snapshot.lineage(),
        service.snapshot.active_policy(),
        roots,
        transition,
    )
    .expect("continuation attempt snapshot");
    let snapshot_id = snapshot.id().expect("continuation snapshot ID");

    service.snapshot = snapshot.clone();
    service.snapshots.insert(snapshot_id, snapshot);
    service.attempt = attempt;
    service.attempt_admission = admission;

    (service, snapshot_id, origin, reached)
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
