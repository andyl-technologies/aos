//! Peer authentication and retained-occurrence tests.

use super::*;

#[test]
fn authenticated_loopback_binds_kernel_peer_to_the_claimed_principal() {
    let mismatched = GetCampaignRequest::new(
        CampaignPrincipal::new("operator:bob").expect("mismatched principal"),
        CampaignName::new("absent").expect("campaign name"),
    )
    .expect("mismatched request");
    let matched = get_request("absent");
    let attempts = crucible_campaign::QueryCampaignRequestAttemptsRequest::new(
        CampaignPrincipal::new("operator:bob").expect("mismatched principal"),
        CampaignName::new("absent").expect("campaign name"),
        snapshot("absent"),
        crucible_campaign::BranchRequestId::parse(&format!(
            "crucible.campaign.branch-request@{}",
            ContentId::for_bytes(ObjectKind::CampaignFact, 10, b"request").encode()
        ))
        .expect("request ID"),
        None,
        1,
    )
    .expect("request-attempt query");
    let savepoint = crucible_campaign::CampaignSavepointRequest::new(
        CampaignPrincipal::new("operator:bob").expect("mismatched principal"),
        CampaignName::new("absent").expect("campaign name"),
        snapshot("absent"),
        crucible_campaign::CampaignSavepointAction::Status {
            request: crucible_campaign::CampaignFactId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                b"capture",
            ))
            .expect("capture fact"),
        },
    )
    .expect("savepoint request");
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
        serve_authenticated_repository_campaign_connection_with_controls_limits(
            &mut server_stream,
            &repository,
            &resolver,
            &AllowAll,
            CampaignConnectionControls {
                runtime: None,
                debug: None,
                status: None,
                diagnostics: None,
                timeouts: LoopbackCampaignTimeouts::default(),
                maximum_requests: 4,
            },
        )
        .expect("serve peer-bound requests");
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
        client.query_campaign_request_attempts(&attempts),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.campaign_savepoint(&savepoint),
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

    let first = observed_rx.recv().expect("peer credential");
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
        serve_authenticated_repository_campaign_connection_with_controls_limits(
            &mut server_stream,
            &repository,
            &resolver,
            &AllowAll,
            CampaignConnectionControls {
                runtime: Some(&control),
                debug: None,
                status: None,
                diagnostics: None,
                timeouts: LoopbackCampaignTimeouts::default(),
                maximum_requests: 2,
            },
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
    let error = serve_authenticated_repository_campaign_connection_with_controls_limits(
        &mut server,
        &repository,
        &|_| -> Result<CampaignPrincipal, crucible_campaign::CampaignAuthorizationError> {
            panic!("invalid request limit reached the peer resolver")
        },
        &AllowAll,
        CampaignConnectionControls {
            runtime: None,
            debug: None,
            status: None,
            diagnostics: None,
            timeouts: LoopbackCampaignTimeouts::default(),
            maximum_requests: 0,
        },
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
    let finding_content = ContentId::for_bytes(
        crucible_campaign::CampaignRecordKind::Finding.object_kind(),
        4,
        b"absent finding",
    );
    let finding = FindingId::parse(&format!("crucible.campaign.finding@{finding_content}"))
        .expect("absent finding ID");
    let bundle_content = ContentId::for_bytes(
        crucible_campaign::CampaignRecordKind::FindingCandidateBundle.object_kind(),
        crucible_campaign::CampaignRecordKind::FindingCandidateBundle.schema_version(),
        b"absent finding candidate bundle",
    );
    let bundle = FindingCandidateBundleId::parse(&format!(
        "crucible.campaign.finding-candidate-bundle@{bundle_content}"
    ))
    .expect("absent finding candidate bundle ID");
    let occurrences = QueryCampaignFindingOccurrencesRequest::new(
        principal(),
        CampaignName::new("absent").expect("campaign name"),
        snapshot("absent"),
        finding,
        None,
        1,
    )
    .expect("finding occurrence request");
    let occurrence_object = GetCampaignFindingOccurrenceObjectRequest::new(
        principal(),
        CampaignName::new("absent").expect("campaign name"),
        snapshot("absent"),
        finding,
        bundle,
        CampaignFindingOccurrenceObjectKind::Observation,
    )
    .expect("finding occurrence object request");
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
        direct.query_campaign_finding_occurrences(&occurrences),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        direct.get_campaign_finding_occurrence_object(&occurrence_object),
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
        for _ in 0..13 {
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
        client.query_campaign_finding_occurrences(&occurrences),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert!(matches!(
        client.get_campaign_finding_occurrence_object(&occurrence_object),
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
fn campaign_loopback_round_trips_retained_finding_occurrence_dependencies() {
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "campaign-loopback-finding-occurrence",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    let (campaign, snapshot, _base_finding, base_bundle) =
        crate::campaign_gc::publish_retained_finding_fixture(&repository);
    let retained = repository
        .load_finding_candidate_bundle(base_bundle)
        .expect("load retained finding candidate");
    let original_replay = FindingTriageReplayEvidence::new(
        retained.reproduction(),
        retained.signature().clone(),
        1,
        b"loopback original replay".to_vec(),
    )
    .expect("build original replay evidence");
    let minimized_replay = FindingTriageReplayEvidence::new(
        retained.minimized(),
        retained.signature().clone(),
        1,
        b"loopback minimized replay".to_vec(),
    )
    .expect("build minimized replay evidence");
    let original_replay = repository
        .publish_finding_triage_replay_evidence(&original_replay)
        .expect("publish original replay evidence");
    let minimized_replay = repository
        .publish_finding_triage_replay_evidence(&minimized_replay)
        .expect("publish minimized replay evidence");
    let triage_evidence = FindingTriageEvidenceSet::new(
        original_replay,
        minimized_replay,
        original_replay,
        minimized_replay,
    );
    let with_triage = FindingCandidateBundle::new_with_exact_retention(
        crucible_campaign::FindingCandidateCore::new(
            retained.observation(),
            retained.signature().clone(),
            retained.reproduction(),
            retained.minimized(),
            retained.signature_minimization().clone(),
            retained.exact_pins().clone(),
        ),
        Some(triage_evidence),
        retained.exact_retention(),
    )
    .expect("build retained candidate with triage evidence");
    let bundle = repository
        .publish_finding_candidate_bundle(&with_triage)
        .expect("publish retained candidate with triage evidence");
    let publication = repository
        .incorporate_finding_candidate_bundle(campaign.as_str(), snapshot, bundle)
        .expect("incorporate retained candidate with triage evidence");
    let snapshot = publication.new_snapshot;
    let finding = publication.finding;

    let findings_request =
        QueryCampaignFindingsRequest::new(principal(), campaign.clone(), snapshot, None, 1)
            .expect("retained finding membership request");
    let occurrence_request = QueryCampaignFindingOccurrencesRequest::new(
        principal(),
        campaign.clone(),
        snapshot,
        finding,
        None,
        1,
    )
    .expect("retained finding occurrence request");
    let object_requests = [
        CampaignFindingOccurrenceObjectKind::Observation,
        CampaignFindingOccurrenceObjectKind::Reproduction,
        CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
    ]
    .map(|kind| {
        GetCampaignFindingOccurrenceObjectRequest::new(
            principal(),
            campaign.clone(),
            snapshot,
            finding,
            bundle,
            kind,
        )
        .expect("retained finding occurrence object request")
    });
    let description = repository
        .describe_finding_triage_replay_storage(original_replay)
        .expect("describe retained replay evidence");
    let root = &description.objects()[0];
    let selection = |evidence| {
        crucible_campaign::CampaignFindingTriageReplaySelection::new(
            principal(),
            campaign.clone(),
            snapshot,
            finding,
            bundle,
            CampaignFindingTriageReplayRole::MinimizationOriginal,
            evidence,
        )
    };
    let segment_request = GetCampaignFindingTriageReplaySegmentRequest::new(
        selection(original_replay),
        crucible_campaign::CampaignFindingTriageReplaySegment::new(
            root.ordinal(),
            root.content(),
            0,
        ),
    )
    .expect("retained finding replay segment request");
    let mismatched_role_request = GetCampaignFindingTriageReplaySegmentRequest::new(
        selection(minimized_replay),
        crucible_campaign::CampaignFindingTriageReplaySegment::new(
            0,
            minimized_replay.content_id(),
            0,
        ),
    )
    .expect("mismatched replay role request");
    let out_of_range_request = GetCampaignFindingTriageReplaySegmentRequest::new(
        selection(original_replay),
        crucible_campaign::CampaignFindingTriageReplaySegment::new(
            root.ordinal(),
            root.content(),
            1,
        ),
    )
    .expect("out-of-range replay segment request");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server = thread::spawn(move || {
        let service = RepositoryCampaignService::new(&repository, AllowAll);
        for _ in 0..8 {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve retained finding occurrence request");
        }
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback service"));

    let findings = client
        .query_campaign_findings(&findings_request)
        .expect("query retained finding membership over loopback");
    assert_eq!(findings.entries().len(), 1);
    assert_eq!(findings.entries()[0].id(), Ok(finding));

    let page = client
        .query_campaign_finding_occurrences(&occurrence_request)
        .expect("query retained finding occurrence over loopback");
    assert_eq!(page.entries().len(), 1);
    assert!(page.next_after().is_some());

    let observation = client
        .get_campaign_finding_occurrence_object(&object_requests[0])
        .expect("read retained observation over loopback");
    let reproduction = client
        .get_campaign_finding_occurrence_object(&object_requests[1])
        .expect("read retained reproduction over loopback");
    let minimized = client
        .get_campaign_finding_occurrence_object(&object_requests[2])
        .expect("read retained minimized reproduction over loopback");
    let replay_segment = client
        .get_campaign_finding_triage_replay_segment(&segment_request)
        .expect("read retained replay segment over loopback");
    assert!(matches!(
        client.get_campaign_finding_triage_replay_segment(&mismatched_role_request),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::InvalidRequest
        ))
    ));
    assert!(
        client
            .get_campaign_finding_triage_replay_segment(&out_of_range_request)
            .is_err()
    );
    assert!(matches!(
        observation.object(),
        CampaignFindingOccurrenceObject::Observation(value)
            if value.id().expect("observation identity") == page.entries()[0].bundle().observation()
    ));
    assert!(matches!(
        reproduction.object(),
        CampaignFindingOccurrenceObject::Reproduction(value)
            if value.id().expect("reproduction identity") == page.entries()[0].bundle().reproduction()
    ));
    assert!(matches!(
        minimized.object(),
        CampaignFindingOccurrenceObject::MinimizedReproduction(value)
            if value.id().expect("minimized identity") == retained.minimized()
    ));
    assert_eq!(replay_segment.description(), &description);
    assert_eq!(
        u64::try_from(replay_segment.range_bytes().len()).expect("segment length"),
        root.stored_envelope_bytes()
    );
    assert_eq!(
        ContentId::for_bytes(
            root.content().kind(),
            root.content().schema_version(),
            replay_segment.range_bytes(),
        ),
        root.content()
    );
    server.join().expect("server thread");
}

#[test]
fn campaign_loopback_client_rejects_cross_request_occurrence_object_response() {
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "campaign-loopback-finding-occurrence-mismatch",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    );
    let (campaign, snapshot, finding, bundle) =
        crate::campaign_gc::publish_retained_finding_fixture(&repository);
    let served = GetCampaignFindingOccurrenceObjectRequest::new(
        principal(),
        campaign.clone(),
        snapshot,
        finding,
        bundle,
        CampaignFindingOccurrenceObjectKind::Observation,
    )
    .expect("served occurrence object request");
    let other = GetCampaignFindingOccurrenceObjectRequest::new(
        CampaignPrincipal::new("operator:bob").expect("other principal"),
        campaign,
        snapshot,
        finding,
        bundle,
        CampaignFindingOccurrenceObjectKind::Observation,
    )
    .expect("other occurrence object request");
    let wrong_response = CampaignClient::new(RepositoryCampaignService::new(&repository, AllowAll))
        .get_campaign_finding_occurrence_object(&other)
        .expect("valid response for other request");

    let (client_stream, mut peer) = UnixStream::pair().expect("stream pair");
    let peer_thread = thread::spawn(move || {
        read_frame(
            &mut peer,
            GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_REQUEST_KIND,
            std::time::Duration::from_secs(1),
        )
        .expect("read occurrence object request");
        write_frame(
            &mut peer,
            GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_RESPONSE_KIND,
            &wrong_response.canonical_bytes(),
            std::time::Duration::from_secs(1),
        )
        .expect("write cross-request occurrence object response");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("client close"), 0);
    });
    let client =
        CampaignClient::new(LoopbackCampaignService::new(client_stream).expect("loopback service"));

    assert!(matches!(
        client.get_campaign_finding_occurrence_object(&served),
        Err(crucible_campaign::CampaignClientError::Service(
            crucible_campaign::CampaignServiceFailure::ProtocolViolation
        ))
    ));
    peer_thread.join().expect("peer thread");
}
