//! Crash-point and cross-plan durable ownership recovery tests.

use super::*;

#[test]
fn real_journal_compacts_reserve_before_admitted_and_admitted_before_intent_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let reserve_only = IntegratedRecoveryFixture::new("reserve-only")?;
    let transaction = reserve_only.open()?;
    reserve_only.preflight(&transaction, false)?;
    drop(reserve_only.reserve(1)?);
    drop(transaction);
    let transaction = reserve_only.open()?;
    reserve_only.preflight_after_restart(&transaction, false)?;
    assert!(reserve_only.ledger()?.owners.is_empty());

    let admitted_only = IntegratedRecoveryFixture::new("admitted-only")?;
    let mut transaction = admitted_only.open()?;
    admitted_only.preflight(&transaction, false)?;
    let reservation = admitted_only.reserve(1)?;
    let mut catalog = JournalCatalog;
    let mut policy = AllowAllPolicy;
    let adapter = IndeterminateThenRetryAdapter;
    let admitted = transaction
        .admit(
            &admitted_only.operation().key,
            &adapter,
            &mut catalog,
            &mut policy,
            &RecoveryClock,
        )
        .map_err(admission_error)?;
    drop(admitted);
    drop(reservation);
    drop(transaction);

    let transaction = admitted_only.open()?;
    admitted_only.preflight_after_restart(&transaction, false)?;
    assert!(admitted_only.ledger()?.owners.is_empty());
    Ok(())
}

#[test]
fn real_journal_retains_the_exact_claim_that_reached_effect_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = IntegratedRecoveryFixture::new("intent")?;
    let mut transaction = fixture.open()?;
    fixture.preflight(&transaction, false)?;
    halt_at_effect_intent(&fixture, &mut transaction, 1)?;
    drop(transaction);

    let transaction = fixture.open()?;
    fixture.preflight_after_restart(&transaction, false)?;
    let ledger = fixture.ledger()?;
    assert_eq!(ledger.owners.len(), 1);
    assert_eq!(ledger.owners[0].claim_by.len(), 1);
    assert_eq!(ledger.owners[0].claim_by[0].attempt, 1);
    Ok(())
}

#[test]
fn retry_replay_retains_intent_attempts_and_compacts_only_the_clean_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let both_intents = IntegratedRecoveryFixture::retrying_new("two-intents")?;
    let mut transaction = progress_to_retry_attempt_two(&both_intents)?;
    halt_at_effect_intent(&both_intents, &mut transaction, 2)?;
    drop(transaction);

    let transaction = both_intents.open()?;
    both_intents.preflight_after_restart(&transaction, false)?;
    let ledger = both_intents.ledger()?;
    assert_eq!(
        ledger.owners[0]
            .claim_by
            .iter()
            .map(|claim| claim.attempt)
            .collect::<Vec<_>>(),
        [1, 2]
    );

    let clean_retry = IntegratedRecoveryFixture::retrying_new("clean-second-attempt")?;
    let mut transaction = progress_to_retry_attempt_two(&clean_retry)?;
    let reservation = clean_retry.reserve(2)?;
    let mut catalog = JournalCatalog;
    let mut policy = AllowAllPolicy;
    let adapter = IndeterminateThenRetryAdapter;
    let admitted = transaction
        .admit(
            &clean_retry.operation().key,
            &adapter,
            &mut catalog,
            &mut policy,
            &RecoveryClock,
        )
        .map_err(admission_error)?;
    assert_eq!(admitted.attempt().get(), 2);
    drop(admitted);
    drop(reservation);
    drop(transaction);

    let transaction = clean_retry.open()?;
    clean_retry.preflight_after_restart(&transaction, false)?;
    let ledger = clean_retry.ledger()?;
    assert_eq!(ledger.owners[0].claim_by.len(), 1);
    assert_eq!(ledger.owners[0].claim_by[0].attempt, 1);
    Ok(())
}

#[test]
fn replay_rejects_a_deleted_or_repointed_actual_intent_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let deleted = IntegratedRecoveryFixture::new("deleted-intent")?;
    let mut transaction = deleted.open()?;
    deleted.preflight(&transaction, false)?;
    halt_at_effect_intent(&deleted, &mut transaction, 1)?;
    drop(transaction);
    save_native_resource_ledger(
        &deleted.state.ledger_path,
        &NativeResourceLedger {
            schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
            owners: Vec::new(),
            consumers: Vec::new(),
        },
    )?;
    let transaction = deleted.open()?;
    let error = deleted
        .preflight_after_restart(&transaction, false)
        .expect_err("effect intent without its durable owner must fail");
    assert!(error.to_string().contains("EffectIntent"));

    let repointed = IntegratedRecoveryFixture::new("repointed-intent")?;
    let mut transaction = repointed.open()?;
    repointed.preflight(&transaction, false)?;
    halt_at_effect_intent(&repointed, &mut transaction, 1)?;
    drop(transaction);
    let mut ledger = repointed.ledger()?;
    ledger.owners[0].claim_by[0].operation.operation.key = key("repointed");
    save_native_resource_ledger(&repointed.state.ledger_path, &ledger)?;
    let transaction = repointed.open()?;
    let error = repointed
        .preflight_after_restart(&transaction, false)
        .expect_err("repointed intent claim must fail");
    assert!(
        error.to_string().contains("operation is absent")
            || error.to_string().contains("EffectIntent")
    );
    Ok(())
}

#[test]
fn clean_claim_compaction_removes_its_exact_paired_consumer_and_true_create_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = IntegratedRecoveryFixture::new("paired-cleanup")?;
    Arc::get_mut(&mut fixture.state)
        .ok_or("fixture state unexpectedly shared")?
        .operations
        .values_mut()
        .next()
        .ok_or("fixture operation claim is absent")?
        .retains_consumer = true;
    let transaction = fixture.open()?;
    fixture.preflight(&transaction, false)?;
    drop(fixture.reserve(1)?);
    let claimed = fixture.ledger()?;
    assert_eq!(claimed.owners.len(), 1);
    assert_eq!(claimed.consumers.len(), 1);
    drop(transaction);

    let transaction = fixture.open()?;
    fixture.preflight_after_restart(&transaction, false)?;
    let compacted = fixture.ledger()?;
    assert!(compacted.owners.is_empty());
    assert!(compacted.consumers.is_empty());
    Ok(())
}

#[test]
fn earlier_successful_owner_write_survives_a_later_intent_and_terminal_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = Arc::new(tempfile::tempdir()?);
    let first = IntegratedRecoveryFixture::in_profile(
        Arc::clone(&profile),
        "gen-1",
        "source",
        "first-incarnation",
    )?;
    complete_and_finalize(&first)?;
    let established = first.ledger()?;
    assert_eq!(established.owners.len(), 1);
    assert!(established.owners[0].claim_by.is_empty());
    assert!(established.owners[0].established_by.is_some());
    let first_plan = first.plan.id();
    drop(first);

    let second =
        IntegratedRecoveryFixture::in_profile(profile, "gen-2", "candidate", "second-incarnation")?;
    assert_ne!(first_plan, second.plan.id());
    let mut transaction = second.open()?;
    second.preflight(&transaction, true)?;
    halt_at_effect_intent(&second, &mut transaction, 1)?;
    drop(transaction);

    let transaction = second.open()?;
    second.preflight_after_restart(&transaction, true)?;
    let retained = second.ledger()?;
    assert_eq!(retained.owners.len(), 1);
    assert_eq!(
        retained.owners[0].established_by,
        established.owners[0].established_by
    );
    assert_eq!(retained.owners[0].claim_by.len(), 1);
    assert_eq!(retained.owners[0].claim_by[0].plan, second.plan.id());
    Ok(())
}

#[test]
fn clean_unestablished_adoption_restores_its_authenticated_source_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = Arc::new(tempfile::tempdir()?);
    let source = IntegratedRecoveryFixture::in_profile(
        Arc::clone(&profile),
        "gen-1",
        "source",
        "source-incarnation",
    )?;
    complete_and_finalize(&source)?;
    let source_owner = source.ledger()?.owners.remove(0);
    drop(source);

    let candidate = IntegratedRecoveryFixture::in_profile(
        profile,
        "gen-2",
        "candidate",
        "candidate-incarnation",
    )?;
    let selection = candidate.state.desired_owner_selections[0].clone();
    let claim = ownership::NativeProviderClaim {
        generation: candidate.state.generation.clone(),
        transaction: candidate.transaction.clone(),
        plan: candidate.plan.id(),
        operation: candidate.operation_id(),
        attempt: 1,
        artifacts: candidate.state.artifacts.clone(),
    };
    let establishment = source_owner
        .established_by
        .clone()
        .ok_or("source owner establishment is absent")?;
    let adopted = NativeProviderOwner {
        resource: source_owner.resource.clone(),
        physical: source_owner.physical.clone(),
        identity: selection.identity,
        handler: selection.handler,
        generation: candidate.state.generation.clone(),
        transaction: candidate.transaction.clone(),
        plan: candidate.plan.id(),
        artifacts: candidate.state.artifacts.clone(),
        claim_by: vec![claim],
        established_by: None,
        adoption: Some(NativeProviderAdoptionReceipt {
            authority: aos_contract::Sha256Digest::of_bytes("restoration authority"),
            source: source_owner.identity.clone(),
            source_handler: source_owner.handler.clone(),
            source_generation: establishment.generation.clone(),
            source_transaction: establishment.transaction.clone(),
            source_plan: establishment.plan,
            source_artifacts: source_owner.artifacts.clone(),
            source_establishment: establishment,
            consumer_requirement: None,
            linked_verification: None,
        }),
    };
    save_native_resource_ledger(
        &candidate.state.ledger_path,
        &NativeResourceLedger {
            schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
            owners: vec![adopted],
            consumers: Vec::new(),
        },
    )?;

    let transaction = candidate.open()?;
    candidate.preflight(&transaction, true)?;
    let restored = candidate.ledger()?;
    assert_eq!(restored.owners, vec![source_owner]);
    Ok(())
}

#[derive(Clone, Copy)]
enum HandlerCoreMutation {
    Package,
    Provider,
    Interface,
    Implementation,
}

fn mutate_handler_core(
    fixture: &mut IntegratedRecoveryFixture,
    mutation: HandlerCoreMutation,
) -> Result<(), &'static str> {
    let state = Arc::get_mut(&mut fixture.state).ok_or("fixture state unexpectedly shared")?;
    let handler = &mut state
        .desired_owner_selections
        .first_mut()
        .ok_or("fixture owner selection is absent")?
        .handler;
    match mutation {
        HandlerCoreMutation::Package => {
            handler.package = aos_contract::Sha256Digest::of_bytes("changed handler package");
        }
        HandlerCoreMutation::Provider => {
            handler.provider.key = key("changed-handler-provider");
        }
        HandlerCoreMutation::Interface => {
            handler.interface.descriptor =
                aos_contract::Sha256Digest::of_bytes("changed handler interface");
        }
        HandlerCoreMutation::Implementation => {
            handler.implementation.descriptor =
                aos_contract::Sha256Digest::of_bytes("changed handler implementation");
        }
    }
    Ok(())
}

#[test]
fn distinct_checked_plan_accepts_new_incarnation_and_rejects_every_handler_core_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = Arc::new(tempfile::tempdir()?);
    let first = IntegratedRecoveryFixture::in_profile(
        Arc::clone(&profile),
        "gen-1",
        "source",
        "first-incarnation",
    )?;
    complete_and_finalize(&first)?;
    let first_plan = first.plan.id();
    let first_handler = first.ledger()?.owners[0].handler.clone();
    drop(first);

    let second = IntegratedRecoveryFixture::in_profile(
        Arc::clone(&profile),
        "gen-2",
        "candidate",
        "rotated-incarnation",
    )?;
    assert_ne!(first_plan, second.plan.id());
    assert_eq!(
        first_handler,
        second.state.desired_owner_selections[0].handler
    );
    let transaction = second.open()?;
    second.preflight(&transaction, true)?;
    drop(transaction);
    drop(second);

    for (index, mutation) in [
        HandlerCoreMutation::Package,
        HandlerCoreMutation::Provider,
        HandlerCoreMutation::Interface,
        HandlerCoreMutation::Implementation,
    ]
    .into_iter()
    .enumerate()
    {
        let generation = format!("gen-{}", index + 3);
        let transaction_name = format!("mutated-{}", index + 1);
        let incarnation = format!("mutation-incarnation-{}", index + 1);
        let mut mutated = IntegratedRecoveryFixture::in_profile(
            Arc::clone(&profile),
            &generation,
            &transaction_name,
            &incarnation,
        )?;
        mutate_handler_core(&mut mutated, mutation)?;
        let transaction = mutated.open()?;
        let error = mutated
            .preflight(&transaction, true)
            .expect_err("mutated durable handler core must fail closed");
        assert!(
            error.to_string().contains("exact selected owner"),
            "{error}"
        );
        drop(transaction);
        drop(mutated);
    }
    Ok(())
}
