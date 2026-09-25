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
        CRUCIBLE_CONFIGURATION_PAYLOAD_SCHEMA_V4
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
fn configuration_import_rejects_forged_or_stripped_preemption_evidence() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let parent = Configuration::genesis(scenario.scenario_def());
    let producer = crucible::PreemptionBranchConfig {
        node: crucible::NodeId {
            name: String::from("node-a"),
        },
        deadline: crucible::SimInstant { ticks: 2 },
        horizon: crucible::SimInstant { ticks: 2 },
        step: 1,
        switch_from_vcpu: crucible::VcpuId { index: 0 },
        switch_to_vcpu: crucible::VcpuId { index: 0 },
        target_vcpu: crucible::VcpuId { index: 0 },
        irq: crucible::IrqVector { vector: 32 },
    };
    let (_, choices) =
        crucible::preemption_branch_choices(&parent, &producer).expect("preemption choices");
    let decisions = choices.first().expect("preemption branch").decisions();
    let mut forged = serde_json::to_value(&decisions[0]).expect("selection JSON");
    forged["Selection"]["preemption_config"]["node"]["name"] =
        serde_json::Value::String(String::from("forged-node"));
    let forged_selection = serde_json::from_value(forged).expect("structural selection");
    let schedule = Schedule::from_decisions([forged_selection, decisions[1].clone()]);
    let artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
        .expect("configuration artifact");

    let error = decode_crucible_configuration_artifact(&scenario, &scenario_artifact, &artifact)
        .expect_err("forged producer evidence must fail before selection resolution");
    assert!(matches!(
        error,
        CrucibleArtifactError::InvalidPayload {
            artifact: "configuration",
            ..
        }
    ));

    let Decision::Selection(selection) = &decisions[0] else {
        panic!("typed branch must begin with a selection");
    };
    let stripped = Decision::Selection(SelectionDecision::new(
        &selection.selection().expect("canonical selection"),
    ));
    let schedule = Schedule::from_decisions([stripped, decisions[1].clone()]);
    let artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
        .expect("stripped configuration artifact");
    let error = decode_crucible_configuration_artifact(&scenario, &scenario_artifact, &artifact)
        .expect_err("stripped preemption evidence must fail before selection resolution");
    assert!(matches!(
        error,
        CrucibleArtifactError::InvalidPayload {
            artifact: "configuration",
            ..
        }
    ));
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
        .branch_selection(first.selected(), 1)
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
fn network_fault_selections_survive_configuration_artifact_restart() {
    let world = crucible::World::from_nodes_and_links(Vec::new(), Vec::new())
        .expect("network artifact world");
    let selectables = crucible::model::ScenarioSelectables::new(
        &world,
        crucible::model::ScenarioSelectableLimits::default(),
        vec![crucible::NetworkFaultSelectable::declaration().expect("network declaration")],
    )
    .expect("network selectables");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        crucible::Seed::from_u64(20),
    )
    .expect("network artifact scenario")
    .with_selectables(selectables)
    .expect("attach network declarations");
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("network scenario artifact");
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("network-choice-artifact", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let parent = Configuration::genesis(scenario.scenario_def());
    let selectable = crucible::NetworkFaultSelectable::next(
        &scenario,
        &parent,
        crucible::NetworkFaultPhase::First,
        VirtualTime { ticks: 10 },
        &[],
    )
    .expect("next network group")
    .expect("active network group");
    let selection = selectable
        .branch_selection(selectable.declaration_ref().default().clone())
        .expect("network group selection");
    repository
        .publish_choice_domain(selectable.domain())
        .expect("publish network domain");
    repository
        .publish_selectable(selectable.declaration_ref())
        .expect("publish network declaration");
    repository
        .publish_choice_opportunity(selectable.opportunity())
        .expect("publish network opportunity");
    repository
        .publish_selection(&selection)
        .expect("publish network selection");
    let branch = selectable
        .resolve_branch(&selection)
        .expect("network branch");
    let selected = branch.selected().clone();
    let branches = vec![branch];
    let artifact = encode_crucible_configuration_artifact(&scenario_artifact, &selected.schedule)
        .expect("network configuration artifact");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let (decoded, replay) = decode_crucible_configuration_artifact_with_signal_fault_replay(
        &scenario,
        &scenario_artifact,
        &artifact,
        &store,
    )
    .expect("network artifact decode");
    assert_eq!(decoded, selected);
    assert_eq!(replay.network_branches(), branches);

    let restarted_store = CampaignExecutorStore::new(repository);
    let (_, restarted) = decode_crucible_configuration_artifact_with_signal_fault_replay(
        &scenario,
        &scenario_artifact,
        &artifact,
        &restarted_store,
    )
    .expect("network artifact restart");
    assert_eq!(restarted.network_branches(), replay.network_branches());
}

#[test]
fn crucible_payloads_reject_schema_and_identity_drift() {
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let valid = encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let unsupported = ScenarioArtifact::new(
        valid.scenario(),
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V5 + 1,
        valid.payload().to_vec(),
    )
    .expect("unsupported artifact remains structurally valid");
    assert!(matches!(
        decode_crucible_scenario_artifact(&unsupported),
        Err(CrucibleArtifactError::UnsupportedPayloadSchema { .. })
    ));
    let drifted = ScenarioArtifact::new(
        ScenarioDefId::from_hash(CampaignHash::from_bytes([0x5a; 32])),
        CRUCIBLE_SCENARIO_PAYLOAD_SCHEMA_V5,
        valid.payload().to_vec(),
    )
    .expect("drifted identity artifact remains structurally valid");
    assert!(matches!(
        decode_crucible_scenario_artifact(&drifted),
        Err(CrucibleArtifactError::SemanticIdentityMismatch {
            artifact: "scenario"
        })
    ));

    let selection_schedule = Schedule::empty().appended(selection_decision(valid.scenario()));
    let unresolved = encode_crucible_configuration_artifact(&valid, &selection_schedule)
        .expect("selection configuration");
    assert!(matches!(
        decode_crucible_configuration_artifact(&scenario, &valid, &unresolved),
        Err(CrucibleArtifactError::UnresolvedSelectionDecision)
    ));
}
