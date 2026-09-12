//! Terminal lifecycle and provider adoption settlement tests.

use super::*;

#[test]
fn mixed_terminal_lifecycle_success_supersedes_only_the_prior_consumer() {
    let mut fixture = adoption_inventory_fixture();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes("lifecycle revision"));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    let owner = fixture.candidate_owner(fixture.resource.clone(), Some(fixture.receipt()));
    let current = fixture.candidate_consumer(revision);
    let mut prior = current.clone();
    prior.generation = "gen-1".to_string();
    prior.transaction = TransactionId(key("source"));
    prior.owner = Some(fixture.source.clone());
    fixture
        .save_full_ledger(vec![owner], vec![prior, current.clone()])
        .expect("mixed lifecycle ledger");

    fixture
        .state
        .finalize_terminal_ownership_with_consumer_status(
            Some(aos_ability_model::document::TerminalResult::SettledFailure),
            &fixture.successful_operations(),
            |_, _| Ok(true),
        )
        .expect("successful lifecycle branch finalization");

    let ledger = load_native_resource_ledger(&fixture.state.ledger_path)
        .expect("finalized lifecycle ledger");
    assert_eq!(ledger.consumers, vec![current]);
    assert!(ledger.owners[0].adoption.is_some());
}

#[test]
fn mixed_terminal_failed_lifecycle_keeps_the_prior_consumer() {
    let mut fixture = adoption_inventory_fixture();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes("failed lifecycle"));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    let owner = fixture.candidate_owner(fixture.resource.clone(), Some(fixture.receipt()));
    let current_claim = fixture.candidate_consumer(revision);
    let mut prior = current_claim.clone();
    prior.generation = "gen-1".to_string();
    prior.transaction = TransactionId(key("source"));
    prior.owner = Some(fixture.source.clone());
    fixture
        .save_full_ledger(vec![owner], vec![prior.clone(), current_claim])
        .expect("failed lifecycle ledger");

    fixture
        .state
        .finalize_terminal_ownership_with_evidence(
            Some(aos_ability_model::document::TerminalResult::SettledFailure),
            &BTreeMap::new(),
        )
        .expect("failed lifecycle branch finalization");

    let ledger =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("retained lifecycle ledger");
    assert_eq!(ledger.consumers, vec![prior]);
    assert!(ledger.owners[0].adoption.is_some());
}

#[test]
fn mixed_terminal_successful_stop_detaches_the_prior_consumer() {
    let mut fixture = adoption_inventory_fixture();
    let stop_operation_key = fixture
        .state
        .operations
        .iter()
        .find_map(|(key, operation)| {
            matches!(
                operation.operation.family,
                aos_ability_model::OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop
                }
            )
            .then(|| key.clone())
        })
        .expect("stop operation");
    let reservation_operation_key = fixture
        .state
        .operations
        .iter()
        .find_map(|(key, operation)| {
            matches!(
                operation.operation.family,
                aos_ability_model::OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Start
                }
            )
            .then(|| key.clone())
        })
        .expect("candidate Start operation");
    fixture
        .state
        .operations
        .get_mut(&reservation_operation_key)
        .expect("reservation operation claim")
        .resources
        .insert(fixture.resource.clone());
    let successful_operations = BTreeMap::from([(stop_operation_key, 1)]);
    let owner = fixture.candidate_owner(fixture.resource.clone(), Some(fixture.receipt()));
    let mut prior = fixture.candidate_consumer(RevisionId(aos_contract::Sha256Digest::of_bytes(
        "stopped lifecycle",
    )));
    prior.generation = "gen-1".to_string();
    prior.transaction = TransactionId(key("prior-stop"));
    prior.owner = Some(fixture.source.clone());
    fixture
        .save_full_ledger(vec![owner], vec![prior])
        .expect("stop lifecycle ledger");

    fixture
        .state
        .finalize_terminal_ownership_with_consumer_status(
            Some(aos_ability_model::document::TerminalResult::SettledFailure),
            &successful_operations,
            |_, _| Ok(true),
        )
        .expect("successful stop branch finalization");
    fixture
        .state
        .finalize_terminal_ownership_with_consumer_status(
            Some(aos_ability_model::document::TerminalResult::SettledFailure),
            &successful_operations,
            |_, _| Ok(true),
        )
        .expect("idempotent successful stop marker replay");

    let ledger =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("stopped lifecycle ledger");
    assert!(ledger.consumers.is_empty());
    assert!(ledger.owners[0].adoption.is_some());

    let mut requalified = fixture.qualified_resource();
    requalified.physical.object =
        "/org/freedesktop/systemd1/unit/stopped_2drequalified_2eservice".to_string();
    let operation = fixture.state.operations[&reservation_operation_key]
        .operation
        .clone();
    let operation_id = OperationId {
        plan: fixture.state.plan,
        operation: operation.key.clone(),
    };
    let transaction = fixture.state.transaction.clone();
    let candidate_assignment = fixture.candidate_assignment.clone();
    let state = Arc::new(fixture.state);
    let error = state
        .reserve(
            &requalified,
            aos_ability_runtime::adapter::ReservationContext {
                transaction: &transaction,
                operation: &operation_id,
                attempt: std::num::NonZeroU32::new(2).expect("positive reservation attempt"),
                expected_provider: Some(&candidate_assignment),
                recovery_remaining_millis: 1_000,
            },
            &operation,
            &operation.accesses[0],
        )
        .expect_err("post-Stop zero-consumer owner must retain its physical fence");
    assert!(
        error.to_string().contains("another physical identity"),
        "{error}"
    );
}

#[test]
fn linked_settlement_preserves_the_verified_original_consumer() {
    let mut fixture = adoption_inventory_fixture();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes("linked lifecycle"));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    let operation_key = fixture.operation_key();
    fixture
        .state
        .operations
        .get_mut(&operation_key)
        .expect("candidate operation")
        .retains_consumer = false;
    let successful_operations = BTreeMap::from([(operation_key.clone(), 1)]);
    fixture.write_terminal_marker(aos_ability_model::document::TerminalResult::Succeeded);
    fixture
        .state
        .replayed_current_successes
        .lock()
        .expect("current success replay set")
        .insert((
            OperationId {
                plan: fixture.state.plan,
                operation: operation_key,
            },
            1,
        ));
    *fixture
        .state
        .replayed_current_terminal
        .lock()
        .expect("current terminal replay state") =
        Some(aos_ability_model::document::TerminalResult::Succeeded);
    fixture.state.linked_recovery_observations.insert(
        fixture.resource.clone(),
        RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Healthy,
        },
    );
    let owner = fixture.candidate_owner(fixture.resource.clone(), Some(fixture.receipt()));
    let mut original = fixture.candidate_consumer(revision);
    original.generation = "gen-1".to_string();
    original.transaction = TransactionId(key("original-candidate"));
    let (reconciliation, observation) =
        fixture.linked_evidence(revision, NativeConsumerRequirement::Required);
    fixture
        .save_full_ledger(vec![owner], vec![original.clone()])
        .expect("linked settlement ledger");

    fixture
        .state
        .verify_linked_adoption_no_op_with_consumer_status(
            &reconciliation,
            &[observation],
            &BTreeSet::new(),
            true,
            |_, _| Ok(true),
        )
        .expect("linked receipt verification");
    let verified =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("verified linked ledger");

    fixture
        .save_full_ledger(verified.owners.clone(), Vec::new())
        .expect("missing linked consumer ledger");
    assert!(
        fixture
            .state
            .finalize_terminal_ownership_with_consumer_status(
                Some(aos_ability_model::document::TerminalResult::Succeeded),
                &successful_operations,
                |_, _| Ok(true),
            )
            .is_err()
    );

    let mut duplicate = original.clone();
    duplicate.attempt = 2;
    fixture
        .save_full_ledger(verified.owners.clone(), vec![original.clone(), duplicate])
        .expect("duplicate linked consumer ledger");
    assert!(
        fixture
            .state
            .finalize_terminal_ownership_with_consumer_status(
                Some(aos_ability_model::document::TerminalResult::Succeeded),
                &successful_operations,
                |_, _| Ok(true),
            )
            .is_err()
    );

    let mut repointed = original.clone();
    repointed.owner = Some(fixture.source.clone());
    fixture
        .save_full_ledger(verified.owners.clone(), vec![repointed])
        .expect("repointed linked consumer ledger");
    assert!(
        fixture
            .state
            .finalize_terminal_ownership_with_consumer_status(
                Some(aos_ability_model::document::TerminalResult::Succeeded),
                &successful_operations,
                |_, _| Ok(true),
            )
            .is_err()
    );

    save_native_resource_ledger(&fixture.state.ledger_path, &verified)
        .expect("restore exact linked ledger");
    fixture
        .state
        .finalize_terminal_ownership_with_consumer_status(
            Some(aos_ability_model::document::TerminalResult::Succeeded),
            &successful_operations,
            |_, _| Ok(true),
        )
        .expect("linked receipt settlement");

    let ledger =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("settled linked ledger");
    assert_eq!(ledger.consumers, vec![original]);
    assert!(ledger.owners[0].adoption.is_none());
}

#[test]
fn adoption_settlement_rejects_success_from_an_alternate_handler() {
    let mut fixture = adoption_inventory_fixture();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes("handler fence"));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    fixture.state.linked_recovery_observations.insert(
        fixture.resource.clone(),
        RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Healthy,
        },
    );
    let operation_key = fixture.operation_key();
    let operation = fixture
        .state
        .operations
        .get_mut(&operation_key)
        .expect("fixture operation");
    operation
        .owner_handler
        .as_mut()
        .expect("owner handler")
        .package = aos_contract::Sha256Digest::of_bytes("alternate handler");
    let owner = fixture.candidate_owner(fixture.resource.clone(), Some(fixture.receipt()));
    let consumer = fixture.candidate_consumer(revision);
    fixture
        .save_full_ledger(vec![owner], vec![consumer])
        .expect("alternate-handler ledger");
    let before = std::fs::read(&fixture.state.ledger_path).expect("ledger before rejection");

    let error = fixture
        .state
        .finalize_terminal_ownership_with_evidence(
            Some(aos_ability_model::document::TerminalResult::Succeeded),
            &fixture.successful_operations(),
        )
        .expect_err("alternate handler success must not settle adoption");

    assert!(
        error
            .to_string()
            .contains("durable completed recovery evidence")
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("ledger after rejection"),
        before
    );
}

#[test]
fn existing_owner_requires_the_fresh_handler_assignment_before_mutation() {
    let mut fixture = adoption_inventory_fixture();
    let checked_handler = handler_from_endpoint(&fixture.state.adoptions[0].candidate);
    let owner = fixture.candidate_owner(fixture.resource.clone(), None);
    fixture.state.adoptions.clear();
    let mut ledger = NativeResourceLedger {
        schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
        owners: vec![owner],
        consumers: Vec::new(),
    };
    let before = ledger.clone();
    let changed_implementation = ProviderAssignment {
        implementation: ProviderImplementationReference {
            descriptor: aos_contract::Sha256Digest::of_bytes("revoked descriptor"),
            artifact: fixture.candidate_assignment.implementation.artifact.clone(),
            handler: fixture.candidate_assignment.implementation.handler.clone(),
        },
        ..fixture.candidate_assignment.clone()
    };
    let changed_error = fixture
        .state
        .authorize_provider_owner(
            &mut ledger,
            &fixture.candidate,
            &fixture.qualified_resource(),
            Some(&checked_handler),
            Some(&changed_implementation),
            false,
            &fixture.operation_id(),
            1,
        )
        .expect_err("changed handler authority requires adoption");
    assert!(
        changed_error
            .to_string()
            .contains("freshly admitted implementation")
    );
    assert_eq!(ledger, before);

    fixture
        .state
        .replayed_current_effect_intents
        .lock()
        .expect("effect-intent replay set")
        .insert((fixture.operation_id(), 1));
    let stale_execution = ProviderAssignment {
        incarnation: IncarnationId::new("stale-incarnation").expect("valid stale incarnation"),
        ..fixture.candidate_assignment.clone()
    };
    assert!(
        !fixture
            .state
            .authorize_provider_owner(
                &mut ledger,
                &fixture.candidate,
                &fixture.qualified_resource(),
                Some(&checked_handler),
                Some(&stale_execution),
                false,
                &fixture.operation_id(),
                1,
            )
            .expect("runtime incarnation may rotate without changing durable ownership")
    );
    assert_eq!(ledger, before);

    let rotated_execution = ProviderAssignment {
        incarnation: IncarnationId::new("new-transaction-incarnation")
            .expect("valid execution incarnation"),
        ..fixture.candidate_assignment.clone()
    };
    assert!(
        !fixture
            .state
            .authorize_provider_owner(
                &mut ledger,
                &fixture.candidate,
                &fixture.qualified_resource(),
                Some(&checked_handler),
                Some(&rotated_execution),
                false,
                &fixture.operation_id(),
                1,
            )
            .expect("exact fresh assignment")
    );
    assert_eq!(ledger, before);
}

#[test]
fn reserve_time_cannot_initiate_provider_adoption() {
    let root = tempfile::tempdir().expect("temporary profile");
    let plan = checked_systemd_manager_effect_plan();
    let provider = plan.operations()[0].target.resource.provider.clone();
    let interface = plan.operations()[0].target.interface.clone();
    let format = aos_contract::Sha256Digest::of_bytes("shared state format");
    let source = provider_identity(&provider, &interface, "source", format);
    let candidate = provider_identity(&provider, &interface, "candidate", format);
    let source_assignment = assignment(&plan, "source-incarnation");
    let candidate_assignment = assignment(&plan, "candidate-incarnation");
    let resource = ResourceId {
        provider,
        key: key("adopted"),
    };
    let candidate_binding = BindingId(key("candidate-binding"));
    let adoption = ProviderAdoptionAuthorization {
        resource: resource.clone(),
        resource_interface: interface,
        source: endpoint(
            &source,
            BindingId(key("source-binding")),
            &source_assignment,
        ),
        candidate: endpoint(&candidate, candidate_binding.clone(), &candidate_assignment),
    };
    let mut operations = BTreeMap::new();
    operations.extend([operation_claim(
        &plan,
        resource.clone(),
        candidate_binding,
        candidate.clone(),
        "adopt",
    )]);
    let state = inventory_state(root.path(), &plan, adoption, operations);
    let mut ledger = NativeResourceLedger {
        schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
        owners: vec![owner(
            resource.clone(),
            source,
            handler_identity("source-binding", source_assignment),
            &plan,
        )],
        consumers: Vec::new(),
    };
    let before = ledger.clone();
    let qualified = NativeQualifiedResource {
        logical: resource,
        physical: NativePhysicalResource {
            class: "systemd-unit".to_string(),
            authority: "system-manager".to_string(),
            object: "/org/freedesktop/systemd1/unit/adopted_2eservice".to_string(),
        },
    };

    let error = state
        .authorize_provider_owner(
            &mut ledger,
            &candidate,
            &qualified,
            Some(&handler_from_endpoint(&state.adoptions[0].candidate)),
            Some(&candidate_assignment),
            false,
            &OperationId {
                plan: state.plan,
                operation: state
                    .operations
                    .keys()
                    .next()
                    .cloned()
                    .expect("fixture operation"),
            },
            1,
        )
        .expect_err("reservation cannot perform the ownership transfer");

    assert!(
        error
            .to_string()
            .contains("after atomic adoption preflight")
    );
    assert_eq!(ledger, before);
}
