//! Crucible scenario and configuration codec tests.

use super::*;

#[test]
fn crucible_payloads_round_trip_and_rederive_semantic_ids() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let schedule = Schedule::empty().appended(Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 1 },
        order: Vec::new(),
    }));
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
            .expect("configuration artifact");
    assert_eq!(
        configuration_artifact.payload_schema(),
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2
    );

    assert_eq!(
        decode_crucible_scenario_artifact(&scenario_artifact).expect("decoded scenario"),
        scenario
    );
    let configuration = decode_crucible_configuration_artifact(
        &scenario,
        &scenario_artifact,
        &configuration_artifact,
    )
    .expect("decoded configuration");
    assert_eq!(configuration.schedule, schedule);
    assert_eq!(
        configuration_artifact.configuration(),
        campaign_configuration_id(configuration.id())
    );
}

#[test]
fn verifier_backed_store_imports_complete_lineage_artifacts() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let schedule = Schedule::empty();
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("crucible-artifact-import", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));

    let scenario_id = store.import_scenario(&scenario).expect("import scenario");
    let configuration_id = store
        .import_configuration(&scenario, &schedule)
        .expect("import configuration");
    let stored_scenario = repository
        .load_scenario_artifact(scenario_id)
        .expect("load scenario");
    let stored_configuration = repository
        .load_configuration_artifact(configuration_id)
        .expect("load configuration");

    assert_eq!(
        decode_crucible_scenario_artifact(&stored_scenario).expect("verify stored scenario"),
        scenario
    );
    assert_eq!(
        decode_crucible_configuration_artifact(&scenario, &stored_scenario, &stored_configuration,)
            .expect("verify stored configuration")
            .schedule,
        schedule
    );
}

#[test]
fn resolved_app_random_model_sample_is_verified_before_execution() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let selectable = crucible::AppRandomSelectable::new(
        &scenario.scenario_def(),
        crucible::NodeId {
            name: String::from("node-a"),
        },
        crucible::RngStreamId::for_node("guest/backoff"),
        11,
        16,
    )
    .expect("app-random selectable");
    let selection = selectable
        .sampled_selection(0x1234_5678_9abc_def0)
        .expect("sampled selection");
    let schedule =
        Schedule::empty().appended(Decision::Selection(SelectionDecision::new(&selection)));
    let artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
        .expect("configuration artifact");

    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "crucible-app-random-selection",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    repository
        .publish_choice_domain(selectable.domain())
        .expect("publish app-random domain");
    repository
        .publish_selectable(selectable.declaration())
        .expect("publish app-random declaration");
    repository
        .publish_choice_opportunity(selectable.opportunity())
        .expect("publish app-random opportunity");
    repository
        .publish_selection(&selection)
        .expect("publish app-random selection");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));

    let decoded = decode_crucible_configuration_artifact_with_selections(
        &scenario,
        &scenario_artifact,
        &artifact,
        &store,
    )
    .expect("standardized model sample should pass executor verification");
    assert_eq!(decoded.schedule, schedule);
}

#[test]
fn selected_decode_refuses_a_large_domain_that_exceeds_its_remaining_budget() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let selected = AlternativeId::from_hash(CampaignHash::derive(
        "crucible.test.large-selected-domain.v1",
        &0_u32.to_be_bytes(),
    ));
    let alternatives = (0_u32..512)
        .map(|index| {
            let id = AlternativeId::from_hash(CampaignHash::derive(
                "crucible.test.large-selected-domain.v1",
                &index.to_be_bytes(),
            ));
            let alternative =
                DiscreteAlternative::new(id, "x".repeat(1024), None).expect("alternative");
            (id, alternative)
        })
        .collect();
    let domain = ChoiceDomain::Discrete(
        DiscreteDomain::new(1, alternatives).expect("large discrete domain"),
    );
    let declaration = SelectableDeclaration::new(
        "product.test.large-selected-domain",
        ChoiceSource::Scheduler {
            producer: String::from("large-domain-test"),
        },
        domain.clone(),
        ChoiceValue::Discrete(selected),
        ChoiceClassContext::new(BTreeSet::new()).expect("class context"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        campaign_scenario_id(scenario.scenario_def().id()),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"large-domain-scheduler"),
            producer: CampaignHash::derive("test", b"large-domain-producer"),
        },
        "large-selected-domain",
        None,
    )
    .expect("choice opportunity");
    let selection = Selection::new(
        &opportunity,
        &domain,
        ChoiceValue::Discrete(selected),
        SelectionOrigin::Default,
    )
    .expect("default selection");
    let schedule =
        Schedule::empty().appended(Decision::Selection(SelectionDecision::new(&selection)));
    let artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
        .expect("configuration artifact");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("large-selected-domain", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    repository
        .publish_selection(&selection)
        .expect("publish selection");
    let store = CampaignExecutorStore::new(repository);
    let mut guard = |_configuration: &Configuration, _branches: usize| Ok(64 * 1024);

    let error = decode_crucible_configuration_artifact_with_signal_fault_replay_guarded(
        &scenario,
        &scenario_artifact,
        &artifact,
        &store,
        Some(&mut guard),
    )
    .expect_err("large resolution closure must fit the selected decode budget");

    assert!(matches!(
        error,
        CrucibleArtifactError::ResourceLimit {
            resource: "selected-origin-decoded-resident-bytes"
        }
    ));
}

#[test]
fn nested_signal_fault_selections_resolve_to_one_exact_ordered_plan() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let parent = Configuration::genesis(scenario.scenario_def());
    let first_selectable = signal_fault_selectable(&parent, b"first-signal-choice", 17);
    let first_selection = first_selectable
        .branch_selection(&parent, 0)
        .expect("first candidate selection");
    let first = first_selectable
        .resolve_branch(&first_selection)
        .expect("first branch");
    let second_selectable = signal_fault_selectable(first.selected(), b"second-signal-choice", 29);
    let second_selection = second_selectable
        .branch_selection(first.selected(), 2)
        .expect("second unmodified selection");
    let second = second_selectable
        .resolve_branch(&second_selection)
        .expect("second branch");
    let artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &second.selected().schedule)
            .expect("nested signal configuration");

    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new(
            "crucible-nested-signal-selections",
            u64::MAX,
        )),
        Arc::new(MemoryRefBackend::new()),
    ));
    publish_signal_selection(&repository, &first_selectable, &first_selection);
    publish_signal_selection(&repository, &second_selectable, &second_selection);
    let store = CampaignExecutorStore::new(Arc::clone(&repository));

    let (decoded, replay) = decode_crucible_configuration_artifact_with_signal_fault_replay(
        &scenario,
        &scenario_artifact,
        &artifact,
        &store,
    )
    .expect("nested signal choices should authenticate");
    assert_eq!(decoded, *second.selected());
    assert_eq!(replay.target(), second.selected());
    assert_eq!(replay.branches(), &[first.clone(), second]);
    let restarted_store = CampaignExecutorStore::new(Arc::clone(&repository));
    let (_, restarted_replay) = decode_crucible_configuration_artifact_with_signal_fault_replay(
        &scenario,
        &scenario_artifact,
        &artifact,
        &restarted_store,
    )
    .expect("restart should reconstruct the same immutable replay plan");
    assert_eq!(restarted_replay, replay);

    let missing_override = Schedule::empty().appended(first.decisions()[0].clone());
    let missing_override =
        encode_crucible_configuration_artifact(&scenario_artifact, &missing_override)
            .expect("missing-override artifact");
    assert!(matches!(
        decode_crucible_configuration_artifact_with_signal_fault_replay(
            &scenario,
            &scenario_artifact,
            &missing_override,
            &store,
        ),
        Err(CrucibleArtifactError::SignalFaultScheduleMismatch)
    ));

    let raw_override = Schedule::empty().appended(first.decisions()[1].clone());
    let raw_override = encode_crucible_configuration_artifact(&scenario_artifact, &raw_override)
        .expect("raw-override artifact");
    assert!(matches!(
        decode_crucible_configuration_artifact_with_signal_fault_replay(
            &scenario,
            &scenario_artifact,
            &raw_override,
            &store,
        ),
        Err(CrucibleArtifactError::UnboundSignalFaultOverride)
    ));
}

#[test]
fn crucible_payloads_reject_schema_and_identity_drift() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let valid = encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let unsupported = ScenarioArtifact::new(
        valid.scenario(),
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3 + 1,
        valid.payload().to_vec(),
    )
    .expect("unsupported artifact remains structurally valid");
    assert!(matches!(
        decode_crucible_scenario_artifact(&unsupported),
        Err(CrucibleArtifactError::UnsupportedPayloadSchema { .. })
    ));
    let mislabeled_legacy = ScenarioArtifact::new(
        valid.scenario(),
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1,
        valid.payload().to_vec(),
    )
    .expect("mislabeled artifact remains structurally valid");
    assert!(matches!(
        decode_crucible_scenario_artifact(&mislabeled_legacy),
        Err(CrucibleArtifactError::UnsupportedPayloadSchema {
            actual: CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V1,
            expected: CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3,
            ..
        })
    ));

    let drifted = ScenarioArtifact::new(
        ScenarioDefId::from_hash(CampaignHash::from_bytes([0x5a; 32])),
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V3,
        valid.payload().to_vec(),
    )
    .expect("drifted identity artifact remains structurally valid");
    assert!(matches!(
        decode_crucible_scenario_artifact(&drifted),
        Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "scenario"
        })
    ));

    let configuration = encode_crucible_configuration_artifact(&valid, &Schedule::empty())
        .expect("configuration artifact");
    let legacy_configuration = ConfigurationArtifact::new(
        configuration.scenario(),
        configuration.scenario_artifact(),
        configuration.configuration(),
        1,
        configuration.payload().to_vec(),
    )
    .expect("legacy configuration remains structurally valid");
    assert!(matches!(
        decode_crucible_configuration_artifact(&scenario, &valid, &legacy_configuration),
        Err(CrucibleArtifactError::UnsupportedPayloadSchema {
            artifact: "configuration",
            actual: 1,
            expected: CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2,
        })
    ));

    let selection_schedule = Schedule::empty().appended(selection_decision(valid.scenario()));
    let unresolved = encode_crucible_configuration_artifact(&valid, &selection_schedule)
        .expect("selection configuration");
    assert!(matches!(
        decode_crucible_configuration_artifact(&scenario, &valid, &unresolved),
        Err(CrucibleArtifactError::UnresolvedSelectionDecision)
    ));

    let mut legacy_payload = configuration.payload().to_vec();
    legacy_payload[..b"crucible.schedule.v2\0".len()].copy_from_slice(b"crucible.schedule.v1\0");
    let legacy_nested_schedule = ConfigurationArtifact::new(
        configuration.scenario(),
        configuration.scenario_artifact(),
        configuration.configuration(),
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V2,
        legacy_payload,
    )
    .expect("legacy nested schedule remains structurally valid");
    assert!(matches!(
        decode_crucible_configuration_artifact(&scenario, &valid, &legacy_nested_schedule),
        Err(CrucibleArtifactError::UnsupportedScheduleEncoding)
    ));
}
