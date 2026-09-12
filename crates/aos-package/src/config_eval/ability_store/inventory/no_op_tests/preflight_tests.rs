//! Journal replay and fail-closed ownership preflight tests.

use super::*;

#[test]
fn adoption_requires_a_sealed_authority_digest() {
    let mut fixture = adoption_inventory_fixture();
    fixture
        .save_ledger(vec![fixture.source_owner()])
        .expect("fixture ledger");
    fixture.state.transition_authority = None;
    let before = std::fs::read(&fixture.state.ledger_path).expect("fixture ledger bytes");

    let error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("missing authority digest must fail");

    assert!(error.to_string().contains("sealed transition authority"));
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged ledger bytes"),
        before
    );
}

#[test]
fn missing_or_invalid_adoption_receipt_fails_closed() {
    let fixture = adoption_inventory_fixture();
    fixture
        .state
        .replayed_current_effect_intents
        .lock()
        .expect("effect-intent replay set")
        .insert((fixture.operation_id(), 1));
    let missing_receipt = fixture.candidate_owner(fixture.resource.clone(), None);
    fixture
        .save_ledger(vec![missing_receipt])
        .expect("missing-receipt ledger");
    let before = std::fs::read(&fixture.state.ledger_path).expect("fixture ledger bytes");

    let missing_error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("missing adoption receipt must fail without a terminal marker");
    assert!(
        missing_error
            .to_string()
            .contains("stale or mismatched receipt evidence")
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged ledger bytes"),
        before
    );

    let mut invalid_receipt = fixture.receipt();
    invalid_receipt.authority = aos_contract::Sha256Digest::of_bytes("wrong authority");
    let invalid_owner = fixture.candidate_owner(fixture.resource.clone(), Some(invalid_receipt));
    fixture
        .save_ledger(vec![invalid_owner])
        .expect("invalid-receipt ledger");
    let invalid_before = std::fs::read(&fixture.state.ledger_path).expect("invalid ledger bytes");

    let invalid_error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("invalid adoption receipt must fail");
    assert!(
        invalid_error
            .to_string()
            .contains("stale or mismatched receipt evidence")
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged invalid ledger bytes"),
        invalid_before
    );
}

#[test]
fn receipt_free_current_owner_requires_an_exact_success_marker() {
    let mut fixture = adoption_inventory_fixture();
    fixture.disable_adoption();
    let owner = fixture.candidate_owner(fixture.resource.clone(), None);
    let claim = owner.claim_by[0].clone();
    fixture
        .save_ledger(vec![owner.clone()])
        .expect("receipt-free current owner ledger");
    fixture
        .state
        .replayed_current_effect_intents
        .lock()
        .expect("effect-intent replay set")
        .insert((claim.operation, claim.attempt));

    fixture.write_terminal_marker(aos_ability_model::document::TerminalResult::SettledFailure);
    *fixture
        .state
        .replayed_current_terminal
        .lock()
        .expect("terminal replay state") =
        Some(aos_ability_model::document::TerminalResult::SettledFailure);
    let before = std::fs::read(&fixture.state.ledger_path).expect("ledger bytes");
    fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect("a settled failure leaves the receipt-free current claim recoverable");
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged ledger bytes"),
        before
    );

    fixture.write_terminal_marker(aos_ability_model::document::TerminalResult::Succeeded);
    *fixture
        .state
        .replayed_current_terminal
        .lock()
        .expect("terminal replay state") =
        Some(aos_ability_model::document::TerminalResult::Succeeded);
    fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect("the exact successful marker replays finalized ownership");
    assert_eq!(
        load_native_resource_ledger(&fixture.state.ledger_path)
            .expect("finalized owner ledger")
            .owners,
        vec![owner]
    );
}

#[test]
fn current_journal_provenance_uses_seeded_replay_without_diagnostic_reopen() {
    let fixture = adoption_inventory_fixture();
    let terminal = aos_ability_model::document::TerminalResult::Succeeded;
    let operation = fixture.operation_id();
    fixture.write_terminal_marker(terminal);
    fixture
        .state
        .replayed_current_effect_intents
        .lock()
        .expect("effect-intent replay set")
        .insert((operation.clone(), 1));
    fixture
        .state
        .replayed_current_successes
        .lock()
        .expect("success replay set")
        .insert((operation.clone(), 1));
    *fixture
        .state
        .replayed_current_terminal
        .lock()
        .expect("terminal replay state") = Some(terminal);

    let claimed_owner = fixture.candidate_owner(fixture.resource.clone(), None);
    let claim = claimed_owner.claim_by[0].clone();
    assert!(
        fixture
            .state
            .authenticate_candidate_claim(&claimed_owner, &claim)
            .expect("current claim uses replayed effect intent")
    );

    let establishment = ownership::NativeProviderEstablishment {
        generation: fixture.state.generation.clone(),
        transaction: fixture.state.transaction.clone(),
        plan: fixture.state.plan,
        operation: operation.clone(),
        attempt: 1,
        artifacts: fixture.state.artifacts.clone(),
    };
    let mut established_owner = claimed_owner.clone();
    established_owner.claim_by.clear();
    established_owner.established_by = Some(establishment.clone());
    fixture
        .state
        .authenticate_source_establishment(&established_owner, &establishment)
        .expect("current establishment uses replayed terminal success");

    let mut consumer = fixture.candidate_consumer(RevisionId(
        aos_contract::Sha256Digest::of_bytes("current replay revision"),
    ));
    consumer.desired_revision = None;
    assert!(
        fixture
            .state
            .consumer_operation_succeeded(&consumer, Some(&established_owner.handler))
            .expect("current consumer uses replayed terminal success")
    );
}

#[test]
fn foreign_plan_on_current_journal_identity_fails_before_diagnostic_reopen() {
    let fixture = adoption_inventory_fixture();
    let terminal = aos_ability_model::document::TerminalResult::Succeeded;
    fixture.write_terminal_marker(terminal);
    *fixture
        .state
        .replayed_current_terminal
        .lock()
        .expect("terminal replay state") = Some(terminal);
    let foreign_plan = PlanId(aos_contract::Sha256Digest::of_bytes("foreign current plan"));

    let mut owner = fixture.candidate_owner(fixture.resource.clone(), None);
    let mut claim = owner.claim_by[0].clone();
    claim.plan = foreign_plan;
    claim.operation.plan = foreign_plan;
    owner.generation = claim.generation.clone();
    owner.transaction = claim.transaction.clone();
    owner.plan = foreign_plan;
    owner.artifacts = claim.artifacts.clone();
    owner.claim_by = vec![claim.clone()];
    let claim_error = fixture
        .state
        .authenticate_candidate_claim(&owner, &claim)
        .expect_err("foreign-plan current claim must fail");
    assert!(claim_error.to_string().contains("different checked plan"));

    let mut establishment = ownership::NativeProviderEstablishment {
        generation: fixture.state.generation.clone(),
        transaction: fixture.state.transaction.clone(),
        plan: foreign_plan,
        operation: fixture.operation_id(),
        attempt: 1,
        artifacts: fixture.state.artifacts.clone(),
    };
    establishment.operation.plan = foreign_plan;
    owner.claim_by.clear();
    owner.established_by = Some(establishment.clone());
    let establishment_error = fixture
        .state
        .authenticate_source_establishment(&owner, &establishment)
        .expect_err("foreign-plan current establishment must fail");
    assert!(
        establishment_error
            .to_string()
            .contains("different checked plan")
    );

    let mut consumer = fixture.candidate_consumer(RevisionId(
        aos_contract::Sha256Digest::of_bytes("foreign plan revision"),
    ));
    consumer.plan = foreign_plan;
    consumer.operation.plan = foreign_plan;
    let consumer_error = fixture
        .state
        .consumer_operation_succeeded(&consumer, Some(&owner.handler))
        .expect_err("foreign-plan current consumer must fail");
    assert!(
        consumer_error
            .to_string()
            .contains("different checked plan")
    );
    assert!(!consumer_error.to_string().contains("acquire shared lock"));

    let terminal_error = fixture
        .state
        .authenticated_retained_terminal_result(
            &fixture.state.generation,
            &fixture.state.transaction,
            foreign_plan,
        )
        .expect_err("foreign-plan current terminal evidence must fail");
    assert!(
        terminal_error
            .to_string()
            .contains("different checked plan")
    );

    let mut receipt = fixture.receipt();
    receipt.source_generation = fixture.state.generation.clone();
    receipt.source_transaction = fixture.state.transaction.clone();
    receipt.source_plan = foreign_plan;
    receipt.source_establishment.generation = fixture.state.generation.clone();
    receipt.source_establishment.transaction = fixture.state.transaction.clone();
    receipt.source_establishment.plan = foreign_plan;
    receipt.source_establishment.operation.plan = foreign_plan;
    let receipt_owner = fixture.candidate_owner(fixture.resource.clone(), Some(receipt));
    fixture
        .save_ledger(vec![receipt_owner])
        .expect("foreign-plan receipt ledger");
    let receipt_error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("foreign-plan current receipt must fail");
    assert!(receipt_error.to_string().contains("different checked plan"));

    let current_owner = fixture.candidate_owner(fixture.resource.clone(), None);
    fixture
        .save_full_ledger(vec![current_owner], vec![consumer])
        .expect("foreign-plan current consumer ledger");
    let finalization_error = fixture
        .state
        .finalize_terminal_ownership_with_evidence(
            Some(aos_ability_model::document::TerminalResult::Succeeded),
            &fixture.successful_operations(),
        )
        .expect_err("terminal finalization must reject a foreign-plan current consumer");
    assert!(
        finalization_error
            .to_string()
            .contains("different checked plan")
    );
}

#[test]
fn historical_consumer_still_requires_the_retained_diagnostic_source() {
    let fixture = adoption_inventory_fixture();
    let historical_generation = "gen-3";
    let historical_transaction = TransactionId(key("historical"));
    fixture.write_terminal_marker_for(
        historical_generation,
        &historical_transaction,
        fixture.state.plan,
        aos_ability_model::document::TerminalResult::Succeeded,
    );
    let mut consumer = fixture.candidate_consumer(RevisionId(
        aos_contract::Sha256Digest::of_bytes("historical revision"),
    ));
    consumer.generation = historical_generation.to_string();
    consumer.transaction = historical_transaction;

    let error = fixture
        .state
        .consumer_operation_succeeded(
            &consumer,
            Some(&handler_from_endpoint(
                &fixture.state.adoptions[0].candidate,
            )),
        )
        .expect_err("historical consumer must load retained diagnostics");

    assert!(
        error.to_string().contains("retained plan bundle")
            || error.to_string().contains("protected ability"),
        "{error}"
    );
    assert!(!error.to_string().contains("different checked plan"));
}

#[test]
fn terminal_marker_replay_finalizes_current_consumer_from_supplied_evidence() {
    let mut fixture = adoption_inventory_fixture();
    fixture.disable_adoption();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes(
        "terminal replay revision",
    ));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    fixture
        .state
        .dispatch_positions
        .insert(fixture.operation_key(), 0);
    let owner = fixture.candidate_owner(fixture.resource.clone(), None);
    let consumer = fixture.candidate_consumer(revision);
    fixture
        .save_full_ledger(vec![owner], vec![consumer.clone()])
        .expect("current terminal replay ledger");
    fixture.write_terminal_marker(aos_ability_model::document::TerminalResult::Succeeded);

    fixture
        .state
        .finalize_existing_terminal_marker_with_evidence(
            Some(aos_ability_model::document::TerminalResult::Succeeded),
            &fixture.successful_operations(),
        )
        .expect("current finalization uses supplied replay evidence");

    let ledger =
        load_native_resource_ledger(&fixture.state.ledger_path).expect("current finalized ledger");
    assert_eq!(ledger.consumers, vec![consumer]);
    assert!(ledger.owners[0].claim_by.is_empty());
    assert!(ledger.owners[0].established_by.is_some());
}

#[test]
fn missing_or_ambiguous_source_owner_fails_closed() {
    let fixture = adoption_inventory_fixture();
    fixture
        .save_ledger(Vec::new())
        .expect("empty fixture ledger");
    let empty_before = std::fs::read(&fixture.state.ledger_path).expect("empty ledger bytes");

    let missing_error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("missing source owner must fail");
    assert!(
        missing_error
            .to_string()
            .contains("exactly one durable source owner")
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged empty ledger bytes"),
        empty_before
    );

    let duplicate = fixture.source_owner();
    let ambiguous = NativeResourceLedger {
        schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
        owners: vec![duplicate.clone(), duplicate],
        consumers: Vec::new(),
    };
    std::fs::write(
        &fixture.state.ledger_path,
        aos_contract::canonical::to_vec(&ambiguous).expect("ambiguous ledger encoding"),
    )
    .expect("ambiguous fixture ledger");
    let ambiguous_before =
        std::fs::read(&fixture.state.ledger_path).expect("ambiguous ledger bytes");

    let ambiguous_error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("ambiguous source owner must fail");
    assert!(
        ambiguous_error
            .to_string()
            .contains("ambiguous provider ownership")
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged ambiguous ledger bytes"),
        ambiguous_before
    );
}

#[test]
fn mixed_source_and_candidate_receipts_fail_atomically() {
    let mut fixture = adoption_inventory_fixture();
    let second_resource = ResourceId {
        provider: fixture.resource.provider.clone(),
        key: key("adopted-second"),
    };
    let mut second_adoption = fixture.state.adoptions[0].clone();
    second_adoption.resource = second_resource.clone();
    fixture.state.adoptions.push(second_adoption);
    let (candidate_key, mut candidate_operation) = operation_claim(
        &fixture.plan,
        second_resource.clone(),
        BindingId(key("candidate-binding")),
        fixture.candidate.clone(),
        "adopt-second",
    );
    candidate_operation.operation.family = aos_ability_model::OperationFamily::ServiceLifecycle {
        action: ServiceAction::Start,
    };
    let (stop_key, mut stop_operation) = operation_claim(
        &fixture.plan,
        second_resource.clone(),
        BindingId(key("candidate-binding")),
        fixture.source.clone(),
        "stop-second",
    );
    stop_operation.operation.family = aos_ability_model::OperationFamily::ServiceLifecycle {
        action: ServiceAction::Stop,
    };
    stop_operation.owner_handler = Some(fixture.source_owner.handler.clone());
    stop_operation.retains_consumer = false;
    fixture
        .state
        .operations
        .insert(candidate_key.clone(), candidate_operation);
    fixture
        .state
        .operations
        .insert(stop_key.clone(), stop_operation);
    fixture
        .state
        .desired_owner_selections
        .push(NativeProviderSelection {
            resource: second_resource.clone(),
            identity: fixture.candidate.clone(),
            handler: handler_from_endpoint(&fixture.state.adoptions[0].candidate),
        });
    fixture.state.required_success_edges.push((
        aos_ability_model::PlanNodeKey::Operation {
            key: stop_key.clone(),
        },
        aos_ability_model::PlanNodeKey::Operation {
            key: candidate_key.clone(),
        },
    ));
    fixture.state.dispatch_positions.insert(stop_key, 2);
    fixture
        .state
        .dispatch_positions
        .insert(candidate_key.clone(), 3);
    fixture
        .state
        .replayed_current_effect_intents
        .lock()
        .expect("effect-intent replay set")
        .insert((
            OperationId {
                plan: fixture.state.plan,
                operation: candidate_key.clone(),
            },
            1,
        ));
    let mut completed_candidate = fixture.candidate_owner(second_resource, Some(fixture.receipt()));
    completed_candidate.claim_by[0].operation.operation = candidate_key;
    fixture
        .save_ledger(vec![fixture.source_owner(), completed_candidate])
        .expect("mixed fixture ledger");
    let before = std::fs::read(&fixture.state.ledger_path).expect("mixed ledger bytes");

    let error = fixture
        .state
        .preflight_provider_owners_for_current(|_| true)
        .expect_err("mixed partial transfer must fail");

    assert!(
        error
            .to_string()
            .contains("typed deletion and tombstone evidence"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&fixture.state.ledger_path).expect("unchanged mixed ledger bytes"),
        before
    );
}
