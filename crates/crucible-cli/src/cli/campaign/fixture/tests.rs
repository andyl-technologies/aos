//! Generated worked-network fixture, catalog, and replay regressions.

use std::fs;
use std::sync::Arc;

use crucible_campaign::{
    CampaignAuthorizationError, CampaignClient, CampaignHash, CampaignName, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignRepository, CampaignServiceOperation,
    CreateCampaignRequest, RepositoryCampaignService,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};
use crucible_core::model::{
    EffectSpecification, FaultCoordinate, FaultObjectId, FaultOperation, FaultOpportunity,
    FaultPhase, NetworkAvailabilityState, NetworkEffectSpecification, OpportunityPayload,
    ResolvedFaultTarget,
};
use crucible_core::{
    Configuration, NetworkFaultCampaignReplayPlan, NetworkFaultPhase, VirtualTime,
};
use crucible_daemon::CrucibleCampaignArtifactStore;

use super::*;

struct PermitFixture;

impl CampaignPrincipalAuthorizer for PermitFixture {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

#[test]
fn worked_network_fixture_validates_imports_and_creates_on_a_blank_repository() {
    let temporary = tempfile::tempdir().expect("fixture temporary directory");
    let output = temporary.path().join("worked-network");
    let report =
        generate_worked_network_fixture(&output, None, None).expect("worked-network fixture");
    let validation = validate_campaign_import_manifests(std::slice::from_ref(&report.manifest))
        .expect("strict generated manifest");
    assert_eq!(validation.configurations().len(), 1);
    assert_eq!(validation.generators().len(), 1);

    let scenario = ScenarioDefForm::from_compact_binary(
        &fs::read(output.join("scenario.bin")).expect("scenario bytes"),
    )
    .expect("canonical scenario");
    let schedule = Schedule::from_compact_binary(
        &fs::read(output.join("schedule.bin")).expect("schedule bytes"),
    )
    .expect("canonical schedule");
    assert_eq!(scenario.world().vm_nodes().len(), 5);
    assert_eq!(scenario.world().links().len(), 5);
    let fault_topology = scenario.world().fault_topology();
    assert_eq!(fault_topology.network_segments.len(), 5);
    assert_eq!(fault_topology.network_paths.len(), 10);
    assert_eq!(fault_topology.fault_domains.len(), 2);
    assert_eq!(
        fault_topology
            .fault_domains
            .iter()
            .find(|domain| domain.id.as_str() == "primary")
            .expect("primary fault domain")
            .targets
            .len(),
        4
    );
    assert_eq!(
        fault_topology
            .fault_domains
            .iter()
            .find(|domain| domain.id.as_str() == "backup")
            .expect("backup fault domain")
            .targets
            .len(),
        2
    );
    assert_eq!(
        fault_topology
            .network_route_fault_targets("router-a", "router-b", 0)
            .expect("direct primary route")
            .len(),
        4
    );
    assert_eq!(
        fault_topology
            .network_route_fault_targets("router-b", "router-a", 0)
            .expect("reverse primary route")
            .len(),
        4
    );
    assert_eq!(
        fault_topology
            .network_route_fault_targets("router-a", "router-c", 0)
            .expect("direct backup route")
            .len(),
        4
    );
    assert_eq!(scenario.measurements().definitions().len(), 3);
    assert_eq!(scenario.plan().event_graph().events().len(), 7);
    assert_eq!(scenario.properties().assertions().len(), 5);
    assert_eq!(scenario.selectables().declarations().len(), 2);
    assert_eq!(
        scenario.selectables().declaration("fault.network"),
        Some(&NetworkFaultSelectable::declaration().expect("canonical fault group")),
    );
    for scalar in [
        "fault.kind",
        "fault.affected_path",
        "fault.duration_us",
        "fault.loss_bps",
        "fault.latency_us",
    ] {
        assert!(scenario.selectables().declaration(scalar).is_none());
    }
    assert!(schedule.is_empty());

    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("worked-network-fixture", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    store
        .import_configuration(&scenario, &schedule)
        .expect("import fixture configuration");
    let generator = CandidateGeneratorSpec::from_canonical_bytes(
        &fs::read(output.join("generator-group-progressive.bin")).expect("generator bytes"),
    )
    .expect("canonical generator");
    store
        .import_generator(&generator)
        .expect("import generator");
    let lineage =
        CampaignLineage::from_canonical_bytes(&fs::read(&report.lineage).expect("lineage bytes"))
            .expect("canonical lineage");
    assert_eq!(
        lineage.exact_closure_schema(),
        crucible_daemon::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
    );
    let policy =
        CampaignPolicy::from_canonical_bytes(&fs::read(&report.policy).expect("policy bytes"))
            .expect("canonical policy");
    assert_eq!(policy.choice_policies().len(), 2);
    assert!(policy.choice_policies().contains_key("fault.network"));
    assert!(policy.choice_policies().contains_key("recovery.response"));
    let request = CreateCampaignRequest::new(
        CampaignPrincipal::new("fixture-operator").expect("principal"),
        CampaignName::new("worked-network").expect("campaign name"),
        lineage,
        policy,
    )
    .expect("creation request");
    let client = CampaignClient::new(RepositoryCampaignService::new(
        repository.as_ref(),
        PermitFixture,
    ));
    let created = client
        .create_campaign(&request)
        .expect("create imported fixture campaign");
    assert!(!created.replayed());
}

#[test]
fn worked_network_guest_catalog_matches_envoy_registration_after_artifact_round_trip() {
    let fixture = worked_network_fixture(None).expect("worked-network fixture");
    let artifact = encode_crucible_scenario_artifact(&fixture.scenario).expect("scenario artifact");
    let scenario = crucible_daemon::decode_crucible_scenario_artifact(&artifact)
        .expect("authenticated scenario round trip");
    let catalog = scenario.selectables();
    assert_eq!(catalog.declarations().len(), 2);
    assert_eq!(catalog.limits().declarations_per_node(), 1);
    assert_eq!(catalog.limits().declarations_per_world(), 2);
    assert_eq!(catalog.limits().requests_per_selectable(), 2);
    assert_eq!(catalog.limits().requests_per_node(), 2);
    assert_eq!(catalog.guest_declarations(&node("router-a")).count(), 1);
    assert_eq!(catalog.guest_declarations(&node("router-b")).count(), 0);
    assert_eq!(
        catalog.declaration("fault.network"),
        Some(&NetworkFaultSelectable::declaration().expect("canonical fault declaration")),
    );

    let response = catalog
        .declaration("recovery.response")
        .expect("group declaration");
    assert_eq!(
        response.source(),
        &ChoiceSource::Guest {
            node: String::from("router-a"),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        }
    );
    assert!(response.required());
    assert!(response.semantic_tags().is_empty());
    let ChoiceDomain::Group(group) = response.domain() else {
        panic!("Envoy recovery response must be atomic");
    };
    assert_eq!(group.members().len(), 4);
    assert_eq!(group.application().adapter(), "envoy.recovery");
    assert_eq!(group.application().version(), 1);
    assert!(response.domain().contains(response.default()));
    let ChoiceValue::Group(default) = response.default() else {
        panic!("Envoy recovery default must be a complete tuple");
    };
    assert_eq!(default.tuple().values().len(), 4);

    let guest_members = group
        .declarations()
        .values()
        .map(|declaration| {
            (
                declaration.name().to_owned(),
                crucible_protocol::ChoiceDomain::from_canonical_bytes(
                    &declaration.domain().canonical_bytes(),
                )
                .expect("portable member domain"),
                crucible_protocol::ChoiceValue::from_canonical_bytes(
                    &declaration.default().canonical_bytes(),
                )
                .expect("portable member default"),
            )
        })
        .collect();
    let guest_group =
        crucible_guest::group::build_guest_group("router-a", "envoy.recovery", 1, guest_members)
            .expect("guest group matches campaign declaration");
    assert_eq!(
        guest_group.domain_bytes(),
        response.domain().canonical_bytes()
    );
    assert_eq!(
        guest_group.default_bytes(),
        response.default().canonical_bytes()
    );

    let registration = crucible_protocol::SelectableRegister::new(
        1,
        response.name(),
        response.domain().canonical_bytes(),
        response.default().canonical_bytes(),
        Vec::new(),
    )
    .expect("one bounded group registration");
    let encoded = registration.encode().expect("group registration bytes");
    assert!(encoded.len() <= crucible_protocol::SELECTABLE_MESSAGE_MAX_BYTES);
    let decoded = crucible_protocol::SelectableRegister::decode(&encoded)
        .expect("group registration round trip");
    assert_eq!(decoded.domain(), response.domain().canonical_bytes());
    assert_eq!(
        decoded.default_value(),
        response.default().canonical_bytes()
    );
}

#[test]
fn generated_network_fault_group_discovers_both_phases_and_projects_typed_paths() {
    let temporary = tempfile::tempdir().expect("fixture temporary directory");
    let output = temporary.path().join("worked-network");
    generate_worked_network_fixture(&output, None, None).expect("generated fixture");
    let source = ScenarioDefForm::from_compact_binary(
        &fs::read(output.join("scenario.bin")).expect("generated scenario bytes"),
    )
    .expect("generated scenario");
    let artifact = encode_crucible_scenario_artifact(&source).expect("scenario artifact");
    let scenario = crucible_daemon::decode_crucible_scenario_artifact(&artifact)
        .expect("authenticated scenario artifact");
    for marker in ["fault.transport.ready", "fault.followup.ready"] {
        assert!(
            scenario
                .plan()
                .event_graph()
                .events()
                .iter()
                .any(|event| event.id.name == marker)
        );
    }

    let parent = Configuration::genesis(scenario.scenario_def());
    let first_at = VirtualTime { ticks: 10_000 };
    let first =
        NetworkFaultSelectable::next(&scenario, &parent, NetworkFaultPhase::First, first_at, &[])
            .expect("first phase admission")
            .expect("first phase discovery");
    assert_eq!(
        NetworkFaultSelectable::from_records(
            &scenario,
            &parent,
            first.declaration_ref(),
            first.opportunity(),
            first.domain(),
        )
        .expect("reconstruct first opportunity from artifact records"),
        first,
    );
    assert_eq!(first.declaration_ref().name(), "fault.network");
    assert_eq!(
        first
            .discovery()
            .expect("public first discovery")
            .declaration()
            .name(),
        "fault.network"
    );
    let first_value =
        NetworkFaultSelectable::selected_value("link_down", "primary", 30_000_000, 0, 0)
            .expect("complete primary outage");
    let first_branch = first
        .resolve_branch(
            &first
                .branch_selection(first_value)
                .expect("first selection"),
        )
        .expect("first exact branch");
    let first_replay = NetworkFaultCampaignReplayPlan::new(
        first_branch.selected().clone(),
        vec![first_branch.clone()],
    )
    .expect("first replay prefix");
    let topology = scenario.world().fault_topology();
    first_replay
        .validate_topology(topology)
        .expect("scenario primary and backup domains");
    let primary = network_fault_frame("segment-router-a-router-b", first_at.ticks + 1_000);
    let backup = network_fault_frame("segment-router-a-router-c", first_at.ticks + 1_000);
    let primary_actions = first_replay
        .actions_for_opportunity(topology, &primary)
        .expect("primary typed action");
    assert_eq!(primary_actions.len(), 1);
    assert!(matches!(
        primary_actions[0].effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            ..
        })
    ));
    assert!(
        first_replay
            .actions_for_opportunity(topology, &backup)
            .expect("backup remains available")
            .is_empty()
    );
    assert!(
        !first_replay
            .active_outages(topology, first_at.ticks)
            .expect("outage activates without traffic")
            .is_empty()
    );

    let followup_at = VirtualTime {
        ticks: 31_000_000_000,
    };
    let followup = NetworkFaultSelectable::next(
        &scenario,
        first_branch.selected(),
        NetworkFaultPhase::Followup,
        followup_at,
        std::slice::from_ref(&first_branch),
    )
    .expect("follow-up phase admission")
    .expect("follow-up phase discovery");
    assert_eq!(
        NetworkFaultSelectable::from_records(
            &scenario,
            first_branch.selected(),
            followup.declaration_ref(),
            followup.opportunity(),
            followup.domain(),
        )
        .expect("reconstruct follow-up opportunity from artifact records"),
        followup,
    );
    assert_ne!(first.opportunity().id(), followup.opportunity().id());
    assert_eq!(followup.declaration_ref().name(), "fault.network");
    let followup_value =
        NetworkFaultSelectable::selected_value("packet_loss", "backup", 10_000_000, 1_000, 0)
            .expect("complete backup loss");
    let followup_branch = followup
        .resolve_branch(
            &followup
                .branch_selection(followup_value)
                .expect("follow-up selection"),
        )
        .expect("follow-up exact branch");
    let replay = NetworkFaultCampaignReplayPlan::new(
        followup_branch.selected().clone(),
        vec![first_branch, followup_branch],
    )
    .expect("both selected phase branches");
    let primary = network_fault_frame("segment-router-a-router-b", followup_at.ticks + 1_000);
    let backup = network_fault_frame("segment-router-a-router-c", followup_at.ticks + 1_000);
    assert!(
        replay
            .active_outages(topology, followup_at.ticks)
            .expect("first outage restored")
            .is_empty()
    );
    assert!(
        replay
            .actions_for_opportunity(topology, &primary)
            .expect("primary after restore")
            .is_empty()
    );
    let backup_actions = replay
        .actions_for_opportunity(topology, &backup)
        .expect("backup packet loss action");
    assert_eq!(backup_actions.len(), 1);
    assert!(matches!(
        backup_actions[0].effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::FrameLoss { .. })
    ));
}

fn network_fault_frame(segment: &str, at: u64) -> FaultOpportunity {
    FaultOpportunity::new(
        ResolvedFaultTarget::NetworkSegment {
            segment: FaultObjectId::parse(segment).expect("declared segment"),
            direction: FaultDirection::AToB,
        },
        FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        FaultCoordinate {
            virtual_nanos: at,
            retired_instructions: None,
        },
        1,
        Some(FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: FaultObjectId::parse("router-a").expect("producer"),
            destination: FaultObjectId::parse("router-c").expect("destination"),
            producer_sequence: 1,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: 64,
            payload_digest: ContentHash::from_bytes(b"worked-network-frame"),
        },
    )
    .expect("modeled network frame")
}

#[test]
fn worked_network_fixture_never_overwrites_an_existing_output() {
    let temporary = tempfile::tempdir().expect("fixture temporary directory");
    let output = temporary.path().join("worked-network");
    fs::create_dir(&output).expect("existing output directory");
    assert!(generate_worked_network_fixture(&output, None, None).is_err());
    assert_eq!(fs::read_dir(&output).expect("empty output").count(), 0);
}

#[test]
fn worked_network_fixture_binds_envoy_boot_artifacts_and_scenario_identity() {
    let temporary = tempfile::tempdir().expect("fixture temporary directory");
    let kernel = temporary.path().join("vmlinuz");
    let root_image = temporary.path().join("root.ext4");
    fs::write(&kernel, b"AOS kernel fixture").expect("kernel fixture");
    fs::write(&root_image, b"Envoy immutable root fixture").expect("root fixture");

    let output = temporary.path().join("envoy-network");
    let report = generate_worked_network_fixture(&output, Some(&kernel), Some(&root_image))
        .expect("materialized worked-network fixture");
    let scenario = ScenarioDefForm::from_compact_binary(
        &fs::read(output.join("scenario.bin")).expect("scenario bytes"),
    )
    .expect("canonical scenario");
    let expected_kernel = reference_for_file("kernel", &kernel).expect("kernel reference");
    let expected_root = reference_for_file("root image", &root_image).expect("root reference");
    for vm in scenario.world().vm_nodes() {
        assert_eq!(vm.kernel, Some(expected_kernel));
        assert_eq!(vm.root_image, Some(expected_root));
        assert_eq!(vm.initrd, None);
        assert_eq!(
            vm.cmdline,
            format!(
                "root=/dev/vda init=/init console=ttyS0 network.role={}",
                vm.id.name
            )
        );
    }
    let lifecycle = crucible_api::ProductionVmLifecycleConfig::new(
        "qemu",
        "plugin",
        &kernel,
        &root_image,
        temporary.path().join("run-state"),
    );
    let resolved = lifecycle
        .portable_replay_asset_paths(&scenario)
        .expect("production lifecycle resolves fixture boot assets");
    assert_eq!(resolved.guest_assets().len(), 1);
    assert_eq!(resolved.guest_assets()[0].kernel(), kernel.as_path());
    assert_eq!(
        resolved.guest_assets()[0].root_image(),
        root_image.as_path()
    );
    let wrong_root = temporary.path().join("wrong-root.ext4");
    fs::write(&wrong_root, b"different root image").expect("wrong root fixture");
    let mismatched_lifecycle = crucible_api::ProductionVmLifecycleConfig::new(
        "qemu",
        "plugin",
        &kernel,
        &wrong_root,
        temporary.path().join("run-state"),
    );
    assert!(
        mismatched_lifecycle
            .portable_replay_asset_paths(&scenario)
            .is_err()
    );

    let offline = temporary.path().join("offline-network");
    let offline_report = generate_worked_network_fixture(&offline, None, None)
        .expect("offline worked-network fixture");
    assert_ne!(report.scenario, offline_report.scenario);
    assert_ne!(report.configuration, offline_report.configuration);
    assert_ne!(
        fs::read(&report.policy).expect("policy"),
        fs::read(&offline_report.policy).expect("offline policy")
    );
    assert_ne!(
        fs::read(&report.lineage).expect("lineage"),
        fs::read(&offline_report.lineage).expect("offline lineage")
    );
    validate_campaign_import_manifests(std::slice::from_ref(&report.manifest))
        .expect("materialized import manifest");

    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("envoy-network-fixture", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let store = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    let schedule = Schedule::from_compact_binary(
        &fs::read(output.join("schedule.bin")).expect("schedule bytes"),
    )
    .expect("canonical schedule");
    store
        .import_configuration(&scenario, &schedule)
        .expect("import materialized configuration");
    let generator = CandidateGeneratorSpec::from_canonical_bytes(
        &fs::read(output.join("generator-group-progressive.bin")).expect("generator bytes"),
    )
    .expect("canonical generator");
    store
        .import_generator(&generator)
        .expect("import generator");
    let lineage =
        CampaignLineage::from_canonical_bytes(&fs::read(&report.lineage).expect("lineage bytes"))
            .expect("canonical lineage");
    let policy =
        CampaignPolicy::from_canonical_bytes(&fs::read(&report.policy).expect("policy bytes"))
            .expect("canonical policy");
    let request = CreateCampaignRequest::new(
        CampaignPrincipal::new("fixture-operator").expect("principal"),
        CampaignName::new("envoy-network").expect("campaign name"),
        lineage,
        policy,
    )
    .expect("creation request");
    let client = CampaignClient::new(RepositoryCampaignService::new(
        repository.as_ref(),
        PermitFixture,
    ));
    assert!(
        !client
            .create_campaign(&request)
            .expect("create materialized campaign")
            .replayed()
    );
}

#[test]
fn worked_network_fixture_rejects_incomplete_boot_assets_before_creating_output() {
    let temporary = tempfile::tempdir().expect("fixture temporary directory");
    let output = temporary.path().join("envoy-network");
    let missing = temporary.path().join("missing-vmlinuz");
    assert!(generate_worked_network_fixture(&output, Some(&missing), None).is_err());
    assert!(generate_worked_network_fixture(&output, Some(&missing), Some(&missing)).is_err());
    assert!(!output.exists());
}
