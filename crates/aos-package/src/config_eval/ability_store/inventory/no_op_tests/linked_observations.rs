//! Linked adoption observation and consumer-accounting tests.

use super::*;

#[test]
fn linked_settlement_requires_one_exact_globally_accounted_consumer() {
    let mut fixture = adoption_inventory_fixture();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes("linked revision"));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    let owner = fixture.candidate_owner(fixture.resource.clone(), Some(fixture.receipt()));
    let consumer = fixture.candidate_consumer(revision);
    let (reconciliation, observation) =
        fixture.linked_evidence(revision, NativeConsumerRequirement::Required);

    fixture
        .save_full_ledger(vec![owner.clone()], vec![consumer.clone()])
        .expect("exact linked ledger");
    fixture
        .state
        .verify_linked_adoption_no_op_with_consumer_status(
            &reconciliation,
            std::slice::from_ref(&observation),
            &BTreeSet::new(),
            true,
            |_, _| Ok(true),
        )
        .expect("exact linked consumer");

    fixture
        .save_full_ledger(vec![owner.clone()], Vec::new())
        .expect("missing-consumer ledger");
    assert!(
        fixture
            .state
            .verify_linked_adoption_no_op_with_consumer_status(
                &reconciliation,
                std::slice::from_ref(&observation),
                &BTreeSet::new(),
                true,
                |_, _| Ok(true),
            )
            .is_err()
    );

    let mut wrong_owner = consumer.clone();
    wrong_owner.owner = Some(fixture.source.clone());
    fixture
        .save_full_ledger(vec![owner.clone()], vec![wrong_owner])
        .expect("wrong-owner ledger");
    assert!(
        fixture
            .state
            .verify_linked_adoption_no_op_with_consumer_status(
                &reconciliation,
                std::slice::from_ref(&observation),
                &BTreeSet::new(),
                true,
                |_, _| Ok(true),
            )
            .is_err()
    );

    let mut wrong_revision = consumer.clone();
    wrong_revision.desired_revision = Some(RevisionId(aos_contract::Sha256Digest::of_bytes(
        "wrong revision",
    )));
    fixture
        .save_full_ledger(vec![owner.clone()], vec![wrong_revision])
        .expect("wrong-revision ledger");
    assert!(
        fixture
            .state
            .verify_linked_adoption_no_op_with_consumer_status(
                &reconciliation,
                std::slice::from_ref(&observation),
                &BTreeSet::new(),
                true,
                |_, _| Ok(true),
            )
            .is_err()
    );

    let mut wrong_physical = consumer.clone();
    wrong_physical.physical.object = "/org/freedesktop/systemd1/unit/wrong_2eservice".to_string();
    assert!(
        fixture
            .save_full_ledger(vec![owner.clone()], vec![wrong_physical])
            .is_err()
    );

    let mut stale = consumer.clone();
    stale.attempt = 2;
    fixture
        .save_full_ledger(vec![owner.clone()], vec![consumer.clone(), stale])
        .expect("extra-stale-consumer ledger");
    assert!(
        fixture
            .state
            .verify_linked_adoption_no_op_with_consumer_status(
                &reconciliation,
                std::slice::from_ref(&observation),
                &BTreeSet::new(),
                true,
                |_, _| Ok(true),
            )
            .is_err()
    );

    let orphan_resource = ResourceId {
        provider: fixture.resource.provider.clone(),
        key: key("orphan"),
    };
    let mut orphan_reconciliation = reconciliation.clone();
    orphan_reconciliation
        .observations
        .push(RuntimeResourceObservation {
            resource: orphan_resource.clone(),
            state: RuntimeResourceState::Present {
                revision,
                health: RuntimeResourceHealth::Healthy,
            },
        });
    let mut orphan_owner = owner.clone();
    orphan_owner.resource = orphan_resource.clone();
    orphan_owner.physical = fixture_physical_resource(&orphan_resource);
    fixture
        .save_full_ledger(vec![owner.clone(), orphan_owner], vec![consumer.clone()])
        .expect("orphan-owner ledger");
    assert!(
        fixture
            .state
            .verify_linked_adoption_no_op_with_consumer_status(
                &orphan_reconciliation,
                std::slice::from_ref(&observation),
                &BTreeSet::new(),
                true,
                |_, _| Ok(true),
            )
            .is_err()
    );

    let mut orphan_consumer = consumer.clone();
    orphan_consumer.logical = orphan_resource;
    orphan_consumer.physical.object = "/org/freedesktop/systemd1/unit/orphan_2eservice".to_string();
    orphan_consumer.owner = None;
    fixture
        .save_full_ledger(vec![owner], vec![consumer, orphan_consumer])
        .expect("orphan-consumer ledger");
    assert!(
        fixture
            .state
            .verify_linked_adoption_no_op_with_consumer_status(
                &orphan_reconciliation,
                &[observation],
                &BTreeSet::new(),
                true,
                |_, _| Ok(true),
            )
            .is_err()
    );
}

#[test]
fn fresh_consumer_backed_observation_rejects_deletion_of_its_sole_consumer() {
    let mut fixture = adoption_inventory_fixture();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes(
        "ordinary drift revision",
    ));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    let owner = fixture.candidate_owner(fixture.resource.clone(), None);
    let mut consumer = fixture.candidate_consumer(revision);
    consumer.generation = "gen-1".to_string();
    consumer.transaction = TransactionId(key("ordinary-drift-source"));
    let (_, observation) = fixture.linked_evidence(revision, NativeConsumerRequirement::Required);
    let consumer_backed = BTreeSet::from([fixture.resource.clone()]);

    fixture
        .save_full_ledger(vec![owner.clone()], vec![consumer])
        .expect("ordinary drift ledger");
    fixture
        .state
        .verify_observed_current_consumers_with_status(
            std::slice::from_ref(&observation),
            &consumer_backed,
            |_, _| Ok(true),
        )
        .expect("one exact ordinary drift consumer");

    fixture
        .save_full_ledger(vec![owner], Vec::new())
        .expect("consumer-deleted ordinary drift ledger");
    let error = fixture
        .state
        .verify_observed_current_consumers_with_status(&[observation], &consumer_backed, |_, _| {
            Ok(true)
        })
        .expect_err("deleting the sole ordinary drift consumer must fail closed");
    assert!(error.to_string().contains("lacks one exact authenticated"));
}

#[test]
fn linked_fresh_observation_allows_only_exact_source_and_candidate_ambiguity() {
    let mut fixture = adoption_inventory_fixture();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes(
        "linked candidate intent revision",
    ));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    let owner = fixture.candidate_owner(fixture.resource.clone(), Some(fixture.receipt()));
    let candidate = fixture.candidate_consumer(revision);
    let mut source = candidate.clone();
    source.generation = "gen-1".to_string();
    source.transaction = TransactionId(key("linked-source"));
    source.owner = Some(fixture.source.clone());
    let (_, observation) = fixture.linked_evidence(revision, NativeConsumerRequirement::Required);
    let consumer_backed = BTreeSet::from([fixture.resource.clone()]);

    fixture
        .save_full_ledger(vec![owner.clone()], vec![source.clone(), candidate.clone()])
        .expect("linked source and candidate ledger");
    fixture
        .state
        .verify_observed_current_consumers_with_status(
            std::slice::from_ref(&observation),
            &consumer_backed,
            |consumer, _| Ok(consumer.generation == "gen-1"),
        )
        .expect("exact linked source and candidate ambiguity");

    fixture
        .save_full_ledger(vec![owner.clone()], vec![candidate])
        .expect("source-deleted linked ledger");
    assert!(
        fixture
            .state
            .verify_observed_current_consumers_with_status(
                std::slice::from_ref(&observation),
                &consumer_backed,
                |_, _| Ok(false),
            )
            .is_err(),
        "the candidate intent cannot replace the sole authenticated source consumer"
    );

    let mut duplicate_source = source.clone();
    duplicate_source.attempt = 2;
    fixture
        .save_full_ledger(vec![owner.clone()], vec![source.clone(), duplicate_source])
        .expect("duplicate linked source ledger");
    assert!(
        fixture
            .state
            .verify_observed_current_consumers_with_status(
                std::slice::from_ref(&observation),
                &consumer_backed,
                |_, _| Ok(true),
            )
            .is_err(),
        "duplicate successful source consumers must fail closed"
    );

    let mut foreign = source;
    let mut foreign_owner = fixture.source.clone();
    foreign_owner.package = aos_contract::Sha256Digest::of_bytes("foreign owner package");
    foreign.owner = Some(foreign_owner);
    fixture
        .save_full_ledger(vec![owner], vec![foreign])
        .expect("foreign linked source ledger");
    assert!(
        fixture
            .state
            .verify_observed_current_consumers_with_status(
                &[observation],
                &consumer_backed,
                |_, _| Ok(true),
            )
            .is_err(),
        "a foreign source consumer must fail closed"
    );
}

#[test]
fn linked_resource_only_settlement_requires_zero_consumers() {
    let mut fixture = adoption_inventory_fixture();
    let revision = RevisionId(aos_contract::Sha256Digest::of_bytes(
        "resource-only revision",
    ));
    fixture
        .state
        .desired_revisions
        .insert(fixture.resource.clone(), revision);
    let owner = fixture.candidate_owner(fixture.resource.clone(), Some(fixture.receipt()));
    let (reconciliation, observation) =
        fixture.linked_evidence(revision, NativeConsumerRequirement::Forbidden);
    fixture
        .save_full_ledger(vec![owner.clone()], Vec::new())
        .expect("resource-only ledger");

    fixture
        .state
        .verify_linked_adoption_no_op_with_consumer_status(
            &reconciliation,
            std::slice::from_ref(&observation),
            &BTreeSet::new(),
            true,
            |_, _| Ok(true),
        )
        .expect("resource-only linked settlement");
    let operation_key = fixture.operation_key();
    fixture
        .state
        .operations
        .get_mut(&operation_key)
        .expect("resource-only operation")
        .retains_consumer = false;
    let successful_operations = fixture.successful_operations();
    fixture.write_terminal_marker(aos_ability_model::document::TerminalResult::Succeeded);
    *fixture
        .state
        .replayed_current_successes
        .lock()
        .expect("current success replay set") = successful_operations
        .iter()
        .map(|(operation, attempt)| {
            (
                OperationId {
                    plan: fixture.state.plan,
                    operation: operation.clone(),
                },
                *attempt,
            )
        })
        .collect();
    *fixture
        .state
        .replayed_current_terminal
        .lock()
        .expect("current terminal replay state") =
        Some(aos_ability_model::document::TerminalResult::Succeeded);
    fixture
        .state
        .finalize_terminal_ownership_with_consumer_status(
            Some(aos_ability_model::document::TerminalResult::Succeeded),
            &successful_operations,
            |_, _| Ok(true),
        )
        .expect("resource-only finalization accepts zero consumers");
    assert!(
        load_native_resource_ledger(&fixture.state.ledger_path)
            .expect("resource-only finalized ledger")
            .owners[0]
            .adoption
            .is_none()
    );

    fixture
        .save_full_ledger(vec![owner], vec![fixture.candidate_consumer(revision)])
        .expect("unexpected resource-only consumer");
    assert!(
        fixture
            .state
            .verify_linked_adoption_no_op_with_consumer_status(
                &reconciliation,
                &[observation],
                &BTreeSet::new(),
                true,
                |_, _| Ok(true),
            )
            .is_err()
    );
}
