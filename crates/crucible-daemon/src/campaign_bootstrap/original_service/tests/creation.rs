//! Exercises inherited identity and head publication through the original service.
//!
//! Actual files, repository, original budget and service methods are exercised.
//! Fixture accounts and imported native-independent models do not qualify an
//! installed Parent workflow, listener, executor or complete mutation purpose.

use super::*;
use crucible_campaign::{
    CampaignLineage, CampaignMode, CampaignName, CampaignPolicy, CampaignPrincipal,
    CampaignRepositoryError, CampaignSeed, CreateCampaignRequest, ExplorerPolicy, FairnessPolicy,
    RetentionPolicy,
};

#[derive(Clone, Copy)]
enum CreationCase {
    Authorized,
    DifferentPrincipal,
    MissingGrant,
    AuthorizedCommand,
    CreateOnlyCommand,
    DifferentCommandPrincipal,
    ReadOnlyCommand,
}

fn exercise_creation(case: CreationCase) {
    let (_root, decoder, catalog, decode_controls) =
        crate::private_measurement_runtime::catalog::tests::campaign_creation_fixture();
    let directory = tempfile::TempDir::new().unwrap();
    let budget = decoder.budget().unwrap();
    let quota = Arc::new(GraphQuotaFixture(budget.clone()));
    let heap = crucible_cas::content_store::fixture_sqlite_heap().unwrap();
    let mut graph = crucible_cas::content_store::OriginalSqliteGraphOwner::open(
        OriginalSqliteGraphConfig {
            name: "campaign-primary",
            root: &directory.path().join("objects"),
            admitted_kinds: &crate::campaign_bootstrap::CAMPAIGN_REPOSITORY_OBJECT_KINDS,
            maximum_sqlite_heap_bytes: heap.maximum_heap_bytes(),
        },
        quota.clone(),
        catalog.supervisor().unwrap(),
        &heap,
    )
    .unwrap();
    let mut refs = crucible_cas::content_store::OriginalDirectoryRefOwner::open(
        &directory.path().join("refs"),
        quota.clone(),
    )
    .unwrap();
    let mut repository = OriginalCampaignRepositoryBootstrap::prepare_with_components(
        &mut graph,
        &refs,
        budget,
        (
            PlannerAuthorityKey::from_bytes([1; 32]).unwrap(),
            DebuggerAuthorityKey::from_bytes([2; 32]).unwrap(),
        ),
    )
    .unwrap();
    let state_path = directory.path().join("state");
    fs::create_dir(&state_path).unwrap();
    fs::set_permissions(&state_path, Permissions::from_mode(0o700)).unwrap();
    let mut state = Some(OriginalCampaignStateBootstrap::fixture_at(&state_path, budget).unwrap());
    let state_handle = state.as_mut().unwrap().share_for_service().unwrap().into();
    let mut retention =
        crate::hot_checkpoint_retention::OriginalHotCheckpointRetentionOwner::fixture_at(
            &directory.path().join("retention"),
            catalog.supervisor().unwrap(),
            quota.clone(),
            budget,
        )
        .unwrap();
    let mut transfers = crate::campaign_transfer::OriginalCampaignTransferJournalOwner::fixture_at(
        &directory.path().join("transfers"),
        catalog.supervisor().unwrap(),
        quota.clone(),
        budget,
    )
    .unwrap();
    let actual_identity = UnixPeerCampaignIdentity::new(
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let policy_bytes = format!(
        "schema = \"crucible.campaign-local-policy\"\nversion = 1\n\
         [[bindings]]\nuser_id = {}\ngroup_id = {}\nprincipal = \"operator\"\n\
         [[grants]]\nprincipal = \"operator\"\noperation = \"{}\"\n\
         campaign = \"creation-control\"\n",
        actual_identity.user_id(),
        actual_identity.group_id(),
        if matches!(case, CreationCase::MissingGrant) {
            "get-campaign-status"
        } else {
            "create-campaign"
        },
    );
    let policy_bytes = if matches!(
        case,
        CreationCase::AuthorizedCommand | CreationCase::ReadOnlyCommand
    ) {
        format!(
            "{policy_bytes}\n[[grants]]\nprincipal = \"operator\"\noperation = \"apply-campaign-command\"\ncampaign = \"creation-control\"\n"
        )
    } else {
        policy_bytes
    };
    let policy =
        Arc::new(UnixPeerCampaignPolicy::from_toml_bytes(policy_bytes.as_bytes()).unwrap());
    let original = ServiceOriginal::Fixture(fixture_original(&catalog));
    let mut prepared = OriginalPreparedCampaignServiceOwner::prepare_configured(
        (
            configuration().0,
            CampaignLocalServiceMode::ReadWrite,
            original,
        ),
        &mut repository,
        state_handle,
        policy,
        retention.share().unwrap(),
        transfers.share().unwrap(),
        budget,
    )
    .unwrap();

    let scenario = crucible::happy_path_scenario().unwrap().scenario;
    let imported = prepared
        .import_configuration(&scenario, &crucible::Schedule::empty())
        .unwrap();
    let service = prepared.service.as_ref().unwrap();
    let stored_configuration = service
        .repository
        .load_configuration_artifact(imported)
        .unwrap();
    let stored_scenario = service
        .repository
        .load_scenario_artifact(stored_configuration.scenario_artifact())
        .unwrap();
    let lineage = CampaignLineage::new(
        stored_scenario.scenario(),
        stored_configuration.scenario_artifact(),
        stored_configuration.configuration(),
        imported,
        env!("CARGO_PKG_VERSION"),
        "creation-fixture",
        crate::packaged_qemu_identity::packaged_qemu_protocol_versions(),
        stored_scenario.payload_schema(),
        crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
    )
    .unwrap();
    let execution_policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            stored_scenario.scenario(),
            CampaignSeed::from_bytes([42; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).unwrap(),
            RetentionPolicy::new(true, 1, true, true),
            false,
        ),
    )
    .unwrap();
    let request = CreateCampaignRequest::new(
        CampaignPrincipal::new(if matches!(case, CreationCase::DifferentPrincipal) {
            "different-principal"
        } else {
            "operator"
        })
        .unwrap(),
        CampaignName::new("creation-control").unwrap(),
        lineage,
        execution_policy,
    )
    .unwrap();
    assert!(matches!(
        service.repository.head("creation-control"),
        Err(CampaignRepositoryError::NotFound)
    ));

    let result = prepared.create_campaign(&request);

    if !matches!(
        case,
        CreationCase::DifferentPrincipal | CreationCase::MissingGrant
    ) {
        let response = result.unwrap();
        response.validate_for(&request).unwrap();
        assert_eq!(
            prepared
                .service
                .as_ref()
                .unwrap()
                .repository
                .head("creation-control")
                .unwrap()
                .snapshot_id(),
            response.snapshot(),
        );
        let repeated = prepared.create_campaign(&request).unwrap();
        assert_eq!(response.snapshot(), repeated.snapshot());
        if matches!(
            case,
            CreationCase::AuthorizedCommand
                | CreationCase::CreateOnlyCommand
                | CreationCase::DifferentCommandPrincipal
                | CreationCase::ReadOnlyCommand
        ) {
            exercise_commands(&mut prepared, &request, case);
        }
    } else {
        let refusal = result.err().unwrap();
        assert!(matches!(
            &refusal.failure,
            PreparedFailure::Retained(purpose)
                if matches!(purpose.data.source,
                    Some(PreparedCause::Authorization(CampaignAuthorizationError::Unauthorized))
                    | Some(PreparedCause::Creation(crucible_campaign::RepositoryCampaignServiceError::Authorization(CampaignAuthorizationError::Unauthorized))))
        ));
        assert!(matches!(
            prepared
                .service
                .as_ref()
                .unwrap()
                .repository
                .head("creation-control"),
            Err(CampaignRepositoryError::NotFound)
        ));
        drop(refusal);
    }
    // The actual canonical request/artifact bodies close before parent credit.
    drop(request);
    drop(stored_configuration);
    drop(stored_scenario);
    drop(scenario);
    prepared.try_close().unwrap();
    repository.try_close().unwrap();
    retention.try_close().unwrap();
    transfers.try_close().unwrap();
    assert!(state.take().unwrap().try_close().is_ok());
    refs.try_close().unwrap();
    graph.try_close().unwrap();
    drop(prepared);
    drop(repository);
    drop(retention);
    drop(transfers);
    drop(refs);
    drop(graph);
    drop(quota);
    assert!(catalog.try_close().is_ok());
    assert!(decoder.try_close().is_ok());
    drop(decode_controls);
}

#[test]
fn readwrite_actual_identity_and_grant_publish_the_validated_head_once() {
    exercise_creation(CreationCase::Authorized);
}

#[test]
fn request_principal_differing_from_inherited_identity_creates_no_head() {
    exercise_creation(CreationCase::DifferentPrincipal);
}

#[test]
fn actual_identity_without_create_grant_creates_no_head() {
    exercise_creation(CreationCase::MissingGrant);
}

fn exercise_commands(
    prepared: &mut OriginalPreparedCampaignServiceOwner,
    creation: &CreateCampaignRequest,
    case: CreationCase,
) {
    use crucible_campaign::{
        ApplyCampaignCommandRequest, BudgetGrant, CampaignCommandId, CampaignControlAction,
        CampaignHash, ControlRequest,
    };
    if matches!(case, CreationCase::ReadOnlyCommand) {
        prepared.service.as_mut().unwrap().mode = CampaignLocalServiceMode::ReadOnly;
    }
    let actions = [
        CampaignControlAction::GrantBudget(BudgetGrant::new(1, 1).unwrap()),
        CampaignControlAction::Resume,
        CampaignControlAction::Complete,
    ];
    for (ordinal, action) in actions.into_iter().enumerate() {
        let before = prepared
            .service
            .as_ref()
            .unwrap()
            .repository
            .head(creation.campaign().as_str())
            .unwrap()
            .snapshot_id();
        let principal = if matches!(case, CreationCase::DifferentCommandPrincipal) {
            CampaignPrincipal::new("different-principal").unwrap()
        } else {
            creation.principal().clone()
        };
        let request = ApplyCampaignCommandRequest::new(
            principal,
            creation.campaign().clone(),
            ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.original-campaign-command-fixture.v1",
                    &(ordinal as u64).to_be_bytes(),
                )),
                expected_snapshot: before,
                action,
            },
        )
        .unwrap();

        let result = prepared
            .artifact_operation(|service| artifacts::apply_authorized_command(service, &request));

        if matches!(case, CreationCase::AuthorizedCommand) {
            let response = result.unwrap();
            response.validate_for(&request).unwrap();
            assert_eq!(
                prepared
                    .service
                    .as_ref()
                    .unwrap()
                    .repository
                    .head(creation.campaign().as_str())
                    .unwrap()
                    .snapshot_id(),
                response.new_snapshot()
            );
        } else {
            let refusal = result.err().unwrap();
            assert!(matches!(
                &refusal.failure,
                PreparedFailure::Retained(purpose)
                    if matches!(purpose.data.source,
                        Some(PreparedCause::Authorization(CampaignAuthorizationError::Unauthorized))
                        | Some(PreparedCause::Creation(crucible_campaign::RepositoryCampaignServiceError::Authorization(CampaignAuthorizationError::Unauthorized))))
            ));
            assert_eq!(
                prepared
                    .service
                    .as_ref()
                    .unwrap()
                    .repository
                    .head(creation.campaign().as_str())
                    .unwrap()
                    .snapshot_id(),
                before
            );
            drop(refusal);
        }
    }
}

#[test]
fn actual_control_grant_resume_complete_validate_the_same_published_heads() {
    exercise_creation(CreationCase::AuthorizedCommand);
}

#[test]
fn create_only_policy_cannot_grant_resume_or_complete_existing_heads() {
    exercise_creation(CreationCase::CreateOnlyCommand);
}

#[test]
fn foreign_control_principal_cannot_select_another_inherited_identity() {
    exercise_creation(CreationCase::DifferentCommandPrincipal);
}

#[test]
fn readonly_actual_service_refuses_control_publication() {
    exercise_creation(CreationCase::ReadOnlyCommand);
}
