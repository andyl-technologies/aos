//! Protocol framing and request-binding tests.

use super::*;

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
    let report = QueryCampaignReportRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        fixed_query_snapshot()
            .0
            .id()
            .expect("fixed query snapshot id"),
        None,
        2,
    )
    .expect("report request");
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
    let expected_report = direct
        .query_campaign_report(&report)
        .expect("direct campaign report");
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
        for _ in 0..18 {
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
            .query_campaign_report(&report)
            .expect("loopback campaign report"),
        expected_report
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
    assert_eq!(&bytes, b"CRUCCS21\x01\0\0\0\0\0\0\x03abc");

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

    let (mut unsupported_client, mut unsupported_server) =
        UnixStream::pair().expect("unsupported-version stream pair");
    let rejection_thread = thread::spawn(move || {
        assert!(matches!(
            serve_loopback_campaign_once(&mut unsupported_server, &FixedCampaignService),
            Err(LoopbackCampaignServerError::Protocol(
                LoopbackCampaignProtocolError::InvalidFrame {
                    reason: "unsupported-frame-version"
                }
            ))
        ));
    });
    let mut unsupported_header = [0_u8; FRAME_HEADER_BYTES];
    unsupported_header[..8].copy_from_slice(b"INVALID!");
    unsupported_header[8] = GET_CAMPAIGN_REQUEST_KIND;
    unsupported_client
        .write_all(&unsupported_header)
        .expect("unsupported-version frame");
    rejection_thread
        .join()
        .expect("unsupported-version server thread");
}

#[test]
fn campaign_loopback_rejects_concurrent_exchange_without_waiting() {
    let first_request = get_request("first");
    let first_response = GetCampaignResponse::new(
        &first_request,
        snapshot("current"),
        lineage("lineage"),
        policy("policy"),
        policy_body("policy"),
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
    let second_thread = thread::spawn(move || {
        second_tx
            .send(second_service.get_campaign(&get_request("second")))
            .map_err(|_| ())
    });
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

    fn query_campaign_report(
        &self,
        _request: &crucible_campaign::QueryCampaignReportRequest,
    ) -> Result<crucible_campaign::QueryCampaignReportResponse, Self::Error> {
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
        _request: &crucible_campaign::QueryCampaignRequestAttemptsRequest,
    ) -> Result<crucible_campaign::QueryCampaignRequestAttemptsResponse, Self::Error> {
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

impl CampaignFindingOccurrenceService for WrongGetService {
    fn query_campaign_finding_occurrences(
        &self,
        _request: &QueryCampaignFindingOccurrencesRequest,
    ) -> Result<QueryCampaignFindingOccurrencesResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_finding_occurrence_object(
        &self,
        _request: &GetCampaignFindingOccurrenceObjectRequest,
    ) -> Result<GetCampaignFindingOccurrenceObjectResponse, Self::Error> {
        unreachable!("test service only handles GetCampaign")
    }

    fn get_campaign_finding_triage_replay_segment(
        &self,
        _request: &GetCampaignFindingTriageReplaySegmentRequest,
    ) -> Result<GetCampaignFindingTriageReplaySegmentResponse, Self::Error> {
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
            policy_body("policy"),
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
        policy_body("policy"),
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

#[test]
fn diagnostic_routing_covers_every_current_request_kind() {
    let operations = [
        (
            GET_CAMPAIGN_REQUEST_KIND,
            CampaignServiceOperation::GetCampaign,
        ),
        (
            APPLY_COMMAND_REQUEST_KIND,
            CampaignServiceOperation::ApplyCampaignCommand,
        ),
        (
            SUBMIT_BRANCH_REQUEST_KIND,
            CampaignServiceOperation::SubmitBranchRequest,
        ),
        (
            CREATE_CAMPAIGN_REQUEST_KIND,
            CampaignServiceOperation::CreateCampaign,
        ),
        (
            DERIVE_CAMPAIGN_REQUEST_KIND,
            CampaignServiceOperation::DeriveCampaign,
        ),
        (
            WATCH_CAMPAIGN_REQUEST_KIND,
            CampaignServiceOperation::WatchCampaign,
        ),
        (
            QUERY_CAMPAIGN_GRAPH_REQUEST_KIND,
            CampaignServiceOperation::QueryCampaignGraph,
        ),
        (
            GET_CAMPAIGN_SNAPSHOT_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignSnapshot,
        ),
        (
            GET_CAMPAIGN_GRAPH_OBJECT_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignGraphObject,
        ),
        (
            QUERY_CAMPAIGN_CHOICES_REQUEST_KIND,
            CampaignServiceOperation::QueryCampaignChoices,
        ),
        (
            GET_CAMPAIGN_CHOICE_OBJECT_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignChoiceObject,
        ),
        (
            QUERY_CAMPAIGN_FRONTIER_REQUEST_KIND,
            CampaignServiceOperation::QueryCampaignFrontier,
        ),
        (
            GET_CAMPAIGN_FRONTIER_OBJECT_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignFrontierObject,
        ),
        (
            PIN_CAMPAIGN_REQUEST_KIND,
            CampaignServiceOperation::PinCampaign,
        ),
        (
            QUERY_CAMPAIGN_FINDINGS_REQUEST_KIND,
            CampaignServiceOperation::QueryCampaignFindings,
        ),
        (
            GET_CAMPAIGN_FINDING_OBJECT_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignFindingObject,
        ),
        (
            EXPLAIN_CAMPAIGN_ATTEMPT_REQUEST_KIND,
            CampaignServiceOperation::ExplainCampaignAttempt,
        ),
        (
            GET_CAMPAIGN_TRACE_CHUNK_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignTraceChunk,
        ),
        (
            GET_CAMPAIGN_PLANNER_RANKINGS_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignPlannerRankings,
        ),
        (
            LIST_CAMPAIGNS_REQUEST_KIND,
            CampaignServiceOperation::ListCampaigns,
        ),
        (
            ATTACH_CAMPAIGN_RUNTIME_REQUEST_KIND,
            CampaignServiceOperation::AttachCampaignRuntime,
        ),
        (
            GET_CAMPAIGN_STATUS_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignStatus,
        ),
        (
            SUBMIT_DISCOVERY_REQUEST_KIND,
            CampaignServiceOperation::SubmitDiscoveryRequest,
        ),
        (
            QUERY_CAMPAIGN_FINDING_OCCURRENCES_REQUEST_KIND,
            CampaignServiceOperation::QueryCampaignFindingOccurrences,
        ),
        (
            GET_CAMPAIGN_FINDING_OCCURRENCE_OBJECT_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignFindingOccurrenceObject,
        ),
        (
            QUERY_CAMPAIGN_REPORT_REQUEST_KIND,
            CampaignServiceOperation::QueryCampaignReport,
        ),
        (
            GET_CAMPAIGN_FINDING_TRIAGE_REPLAY_SEGMENT_REQUEST_KIND,
            CampaignServiceOperation::GetCampaignFindingTriageReplaySegment,
        ),
        (
            OPEN_CAMPAIGN_DEBUG_SESSION_REQUEST_KIND,
            CampaignServiceOperation::DebugCampaign,
        ),
    ];

    for (request_kind, expected) in operations {
        assert_eq!(
            campaign_operation_for_request_kind(request_kind),
            Some(expected)
        );
    }
    assert_eq!(
        campaign_operation_for_request_kind(SERVICE_ERROR_RESPONSE_KIND),
        None
    );
}
