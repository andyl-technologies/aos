//! Builtin exhaustive-source admission through the actual repository and Unix owner.

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::{
    BooleanDomain, BranchBudget, BranchRequest, BranchRequestCause, CampaignLineage, CampaignMode,
    CampaignPolicy, CampaignRepositoryError, CampaignSeed, CandidateGeneratorAlgorithm,
    CandidateGeneratorSpec, CandidateSource, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoicePolicy, ChoiceSource, ChoiceValue, CreateCampaignRequest,
    ExplorerPolicy, FairnessPolicy, QueryCampaignFrontierRequest, RetentionPolicy,
    STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION, SelectableDeclaration, StopCondition,
    SubmitCampaignBranchRequest,
};
use crucible_cas::content_store::{MutableRefBackend, RefName, StoreError};

use super::*;
use crate::CrucibleCampaignArtifactStore;

#[test]
fn missing_all_and_unselected_policy_refuse_without_publication() {
    let blobs = Arc::new(MemoryBlobBackend::new("all-source-admission", u64::MAX));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let artifacts = CrucibleCampaignArtifactStore::new(repository.clone());
    let scenario = crucible::happy_path_scenario().expect("scenario").scenario;
    let scenario_id = artifacts
        .import_scenario(&scenario)
        .expect("scenario import");
    let configuration_id = artifacts
        .import_configuration(&scenario, &crucible::Schedule::empty())
        .expect("configuration import");
    let stored_scenario = repository
        .load_scenario_artifact(scenario_id)
        .expect("scenario");
    let configuration = repository
        .load_configuration_artifact(configuration_id)
        .expect("configuration");
    let lineage = CampaignLineage::new(
        stored_scenario.scenario(),
        scenario_id,
        configuration.configuration(),
        configuration_id,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        stored_scenario.payload_schema(),
        configuration.payload_schema(),
    )
    .expect("lineage");
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            lineage.scenario(),
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 4,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            false,
        ),
    )
    .expect("policy");
    let created = repository
        .create("all-source", &lineage, &policy, &BTreeMap::new())
        .expect("create without choice-policy generators");
    let unrelated = repository
        .create("unrelated", &lineage, &policy, &BTreeMap::new())
        .expect("unrelated owner");

    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("domain"));
    let declaration = SelectableDeclaration::new(
        "product.all",
        ChoiceSource::Workload {
            producer: "all-producer".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("context"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("all-test", b"scheduler"),
            producer: CampaignHash::derive("all-test", b"producer"),
        },
        "instance-1",
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let discovered = repository
        .discover_operator_choice_opportunity(
            "all-source",
            created.snapshot_id(),
            configuration_id,
            opportunity.id().expect("opportunity ID"),
        )
        .expect("authenticate campaign opportunity");
    let generator = CandidateGeneratorSpec::new(
        STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("canonical All generator");
    let generator_id = generator.id().expect("generator ID");
    let branch = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(configuration.configuration()),
            configuration_id,
            opportunity.id().expect("opportunity ID"),
            domain.id().expect("domain ID"),
        ),
        CandidateSource::generated(generator_id),
        BranchRequestCause::ExhaustivePolicy(policy.id().expect("policy ID")),
        BranchBudget::new(2, 1).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("exhaustive request");
    let campaign_ref = RefName::new("campaigns/all-source").expect("ref");
    let unrelated_ref = RefName::new("campaigns/unrelated").expect("unrelated ref");
    let prior_ref = refs.read_ref(&campaign_ref).expect("prior ref");
    let prior_objects = blobs.object_count().expect("object count");

    let original = repository
        .submit_branch_request("all-source", discovered.new_snapshot, &branch)
        .expect_err("unpublished builtin record");

    assert!(
        matches!(original, CampaignRepositoryError::Store(StoreError::NotFound { id })
        if id == generator_id.content_id())
    );
    assert_eq!(
        refs.read_ref(&campaign_ref)
            .expect("ref after direct refusal"),
        prior_ref
    );
    assert_eq!(
        blobs.object_count().expect("objects after refusal"),
        prior_objects
    );

    let request = SubmitCampaignBranchRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("all-source").expect("campaign name"),
        discovered.new_snapshot,
        branch,
    )
    .expect("request envelope");
    let (_directory, listener, socket) = listener();
    let (observed, _observed_rx) = mpsc::channel();
    let diagnostics = Arc::new(RecordingDiagnostics::default());
    let server = CampaignLoopbackServer::new(
        listener,
        repository.clone(),
        Arc::new(RecordingResolver { observed }),
        Arc::new(AllowAll),
        CampaignLoopbackServerConfig::default(),
    )
    .expect("Unix listener")
    .with_diagnostic_sink(diagnostics.clone());
    let shutdown = server.shutdown_handle();
    let serving = thread::spawn(move || server.serve().expect("serve"));
    let client = CampaignClient::new(
        LoopbackCampaignService::new(UnixStream::connect(&socket).expect("connect"))
            .expect("canonical connection"),
    );

    assert!(matches!(
        client.submit_branch_request(&request),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unavailable
        ))
    ));
    assert_eq!(
        refs.read_ref(&campaign_ref)
            .expect("ref after Unix refusal"),
        prior_ref
    );
    assert_eq!(
        blobs.object_count().expect("objects after Unix refusal"),
        prior_objects
    );

    assert_eq!(
        artifacts
            .import_generator(&generator)
            .expect("authorized immutable import"),
        generator_id
    );
    let imported_objects = blobs.object_count().expect("objects after import");
    let unselected = repository
        .submit_branch_request("all-source", discovered.new_snapshot, request.request())
        .expect_err("import does not grant policy selection");

    assert!(matches!(
        unselected,
        CampaignRepositoryError::Integrity {
            reason: "branch-request-generator-is-not-selected-by-active-policy"
        }
    ));
    assert!(matches!(
        client.submit_branch_request(&request),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::IntegrityFailure
        ))
    ));
    assert_eq!(
        refs.read_ref(&campaign_ref)
            .expect("ref after policy refusal"),
        prior_ref
    );
    assert_eq!(
        blobs.object_count().expect("objects after policy refusal"),
        imported_objects
    );
    assert_eq!(
        refs.read_ref(&unrelated_ref).expect("unrelated ref"),
        Some(unrelated.content_id())
    );
    assert!(
        diagnostics
            .records()
            .contains(&CampaignServiceDiagnostic::RequestFailureSource {
                operation: CampaignServiceOperation::SubmitBranchRequest,
                request_digest: request.request_digest(),
                category: crucible_campaign::CampaignServiceFailureCategory::Missing,
            })
    );

    let selected_policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            lineage.scenario(),
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 4,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::from([(
                declaration.name().to_owned(),
                ChoicePolicy::new(declaration.name(), generator_id, true)
                    .expect("select imported All"),
            )]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            false,
        ),
    )
    .expect("selected policy");
    let selected = client
        .create_campaign(
            &CreateCampaignRequest::new(
                request.principal().clone(),
                CampaignName::new("selected-all").expect("campaign"),
                lineage.clone(),
                selected_policy.clone(),
            )
            .expect("selected-policy creation request"),
        )
        .expect("create through Unix with authenticated imported closure");
    let selected_discovery = repository
        .discover_operator_choice_opportunity(
            "selected-all",
            selected.snapshot(),
            configuration_id,
            opportunity.id().expect("opportunity ID"),
        )
        .expect("discover without publishing a branch request");
    let selected_campaign = CampaignName::new("selected-all").expect("campaign");
    let frontier = client
        .query_campaign_frontier(
            &QueryCampaignFrontierRequest::new(
                request.principal().clone(),
                selected_campaign.clone(),
                selected_discovery.new_snapshot,
                None,
                8,
            )
            .expect("frontier request"),
        )
        .expect("authenticate frontier before explicit All");

    assert!(frontier.entries().is_empty());

    let selected_branch = BranchRequest::new(
        BranchRequest::identity(
            request.request().branch_point(),
            request.request().parent(),
            request.request().opportunity(),
            request.request().domain(),
        ),
        CandidateSource::generated(generator_id),
        BranchRequestCause::ExhaustivePolicy(selected_policy.id().expect("selected policy ID")),
        BranchBudget::new(2, 1).expect("exact proposal cardinality"),
        StopCondition::NextChoice,
    )
    .expect("selected request");
    let selected_request = SubmitCampaignBranchRequest::new(
        request.principal().clone(),
        selected_campaign,
        selected_discovery.new_snapshot,
        selected_branch,
    )
    .expect("selected request envelope");
    let accepted = client
        .submit_branch_request(&selected_request)
        .expect("accept imported and selected source through Unix listener");
    let accepted_objects = blobs.object_count().expect("accepted objects");
    let accepted_head = repository.head("selected-all").expect("accepted head");
    let replay = client
        .submit_branch_request(&selected_request)
        .expect("replay exact accepted request");

    assert!(!accepted.replayed());
    assert!(replay.replayed());
    assert_eq!(accepted.request(), replay.request());
    assert_eq!(accepted.new_snapshot(), replay.new_snapshot());
    assert_eq!(accepted.summary(), replay.summary());
    assert_eq!(
        accepted.summary().validated_cardinality(),
        crucible_campaign::BranchAcceptanceCount::Exact(2)
    );
    assert_eq!(
        accepted.summary().remaining_lazy_candidates(),
        crucible_campaign::BranchAcceptanceCount::Exact(2)
    );
    assert_eq!(
        repository.head("selected-all").expect("replayed head"),
        accepted_head
    );
    assert_eq!(
        blobs.object_count().expect("replayed objects"),
        accepted_objects
    );
    assert_eq!(
        refs.read_ref(&unrelated_ref)
            .expect("unrelated ref after acceptance"),
        Some(unrelated.content_id())
    );

    drop(client);
    shutdown.shutdown();
    serving.join().expect("join listener");
    assert_eq!(shutdown.active_connections(), 0);
}
