//! Verifier import and campaign creation tests.

use super::*;

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

    let absent_finding_content = ContentId::for_bytes(
        crucible_campaign::CampaignRecordKind::Finding.object_kind(),
        4,
        b"stale absent finding",
    );
    let absent_finding = FindingId::parse(&format!(
        "crucible.campaign.finding@{absent_finding_content}"
    ))
    .expect("stale absent finding ID");
    let absent_bundle_content = ContentId::for_bytes(
        crucible_campaign::CampaignRecordKind::FindingCandidateBundle.object_kind(),
        crucible_campaign::CampaignRecordKind::FindingCandidateBundle.schema_version(),
        b"stale absent candidate bundle",
    );
    let absent_bundle = FindingCandidateBundleId::parse(&format!(
        "crucible.campaign.finding-candidate-bundle@{absent_bundle_content}"
    ))
    .expect("stale absent candidate bundle ID");
    let stale_occurrences = QueryCampaignFindingOccurrencesRequest::new(
        principal(),
        CampaignName::new("blank-imported").expect("campaign name"),
        created.snapshot(),
        absent_finding,
        None,
        1,
    )
    .expect("stale occurrence request");
    let stale_occurrence_object = GetCampaignFindingOccurrenceObjectRequest::new(
        principal(),
        CampaignName::new("blank-imported").expect("campaign name"),
        created.snapshot(),
        absent_finding,
        absent_bundle,
        CampaignFindingOccurrenceObjectKind::Reproduction,
    )
    .expect("stale occurrence object request");
    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server_repository = Arc::clone(&repository);
    let server = thread::spawn(move || {
        let service = RepositoryCampaignService::new(server_repository.as_ref(), AllowAll);
        for _ in 0..2 {
            serve_loopback_campaign_once(&mut server_stream, &service)
                .expect("serve stale finding occurrence request");
        }
    });
    let loopback = LoopbackCampaignService::new(client_stream).expect("loopback service");
    let loopback_client = CampaignClient::new(loopback);
    for result in [
        loopback_client
            .query_campaign_finding_occurrences(&stale_occurrences)
            .map(|_| ()),
        loopback_client
            .get_campaign_finding_occurrence_object(&stale_occurrence_object)
            .map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(crucible_campaign::CampaignClientError::Service(
                crucible_campaign::CampaignServiceFailure::Stale { expected, current }
            )) if expected == created.snapshot() && current == resumed.new_snapshot()
        ));
    }
    server.join().expect("stale occurrence server thread");

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
