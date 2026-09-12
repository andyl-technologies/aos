//! Retained consumer and resource-only observation tests.

use super::*;

#[test]
fn retained_consumer_must_match_the_directly_loaded_revision() {
    let root = tempfile::tempdir().expect("temporary profile");
    let generation = root.path().join("gen-1");
    std::fs::create_dir(&generation).expect("generation directory");
    let plan = checked_systemd_manager_effect_plan();
    let operation = &plan.operations()[0];
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .expect("fixture binding");
    let revision = plan.document().desired_revisions[0].revision;
    let qualified = NativeQualifiedResource::systemd(
        operation.target.resource.clone(),
        "/org/freedesktop/systemd1/unit/fixture_2eservice",
    )
    .expect("qualified fixture resource");
    let consumer = ActiveNativeConsumer {
        physical: qualified.physical.clone(),
        logical: qualified.logical.clone(),
        generation: "gen-1".to_string(),
        transaction: TransactionId(LocalKey::new("activate").expect("transaction")),
        plan: plan.id(),
        binding: binding.id.clone(),
        consumer: binding.request.consumer.clone(),
        provider: binding.provider.clone(),
        owner: None,
        desired_revision: Some(revision),
        artifacts: plan.required_runtime_artifacts().to_vec(),
        operation: OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        },
        attempt: 1,
    };
    save_native_resource_ledger(
        &root.path().join(NATIVE_RESOURCE_LEDGER_FILE),
        &NativeResourceLedger {
            schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
            owners: Vec::new(),
            consumers: vec![consumer],
        },
    )
    .expect("fixture ledger");
    let exact = NativeNoOpResourceObservation {
        qualified: qualified.clone(),
        state: RuntimeResourceState::Present {
            revision,
            health: RuntimeResourceHealth::Healthy,
        },
        consumer_requirement: NativeConsumerRequirement::Required,
    };
    let ledger = load_native_resource_ledger(&root.path().join(NATIVE_RESOURCE_LEDGER_FILE))
        .expect("fixture ledger");
    verify_retained_native_consumers_with_status(&ledger, std::slice::from_ref(&exact), |_, _| {
        Ok(true)
    })
    .expect("exact retained consumer");

    let mut conflicting_physical_consumers = ledger.consumers.clone();
    let mut conflicting = conflicting_physical_consumers[0].clone();
    conflicting.physical.object = "/org/freedesktop/systemd1/unit/different_2eservice".to_string();
    conflicting_physical_consumers.push(conflicting);
    assert!(
        canonicalize_native_consumers(&mut conflicting_physical_consumers)
            .expect_err("one logical resource cannot identify two physical subjects")
            .to_string()
            .contains("conflicting physical subjects")
    );

    let loaded_new_revision = NativeNoOpResourceObservation {
        qualified,
        state: RuntimeResourceState::Present {
            revision: RevisionId(aos_contract::Sha256Digest::of_bytes("new loaded revision")),
            health: RuntimeResourceHealth::Healthy,
        },
        consumer_requirement: NativeConsumerRequirement::Required,
    };
    let error =
        verify_retained_native_consumers_with_status(&ledger, &[loaded_new_revision], |_, _| {
            Ok(true)
        })
        .expect_err("an old consumer cannot stand in for a newly loaded revision");
    assert!(error.to_string().contains("directly observed resource"));
}

#[test]
fn retained_consumer_claim_is_bound_to_its_exact_checked_operation() {
    let plan = checked_systemd_manager_effect_plan();
    let operation = &plan.operations()[0];
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .expect("fixture binding");
    let revision = plan.document().desired_revisions[0].revision;
    let qualified = NativeQualifiedResource::systemd(
        operation.target.resource.clone(),
        "/org/freedesktop/systemd1/unit/fixture_2eservice",
    )
    .expect("qualified fixture resource");
    let consumer = ActiveNativeConsumer {
        physical: qualified.physical,
        logical: qualified.logical,
        generation: "gen-1".to_string(),
        transaction: TransactionId(key("activate")),
        plan: plan.id(),
        binding: binding.id.clone(),
        consumer: binding.request.consumer.clone(),
        provider: binding.provider.clone(),
        owner: None,
        desired_revision: Some(revision),
        artifacts: plan.required_runtime_artifacts().to_vec(),
        operation: OperationId {
            plan: plan.id(),
            operation: operation.key.clone(),
        },
        attempt: 1,
    };
    assert_eq!(consumer.consumer, consumer.logical.provider);
    let mut canonical_consumer = vec![consumer.clone()];
    canonicalize_native_consumers(&mut canonical_consumer)
        .expect("non-stateful terminal provider owns the logical resource");
    validate_retained_native_consumer_claim(&consumer, &plan, &[], None)
        .expect("exact checked consumer claim");

    let mut repointed = consumer.clone();
    repointed.operation.operation = ScopedOperationKey {
        scope: ScopePath::root(),
        key: key("another-successful-operation"),
    };
    assert!(validate_retained_native_consumer_claim(&repointed, &plan, &[], None).is_err());

    let mut wrong_binding = consumer.clone();
    wrong_binding.binding = BindingId(key("wrong-binding"));
    assert!(validate_retained_native_consumer_claim(&wrong_binding, &plan, &[], None).is_err());

    let mut wrong_artifacts = consumer;
    wrong_artifacts.artifacts.clear();
    assert!(validate_retained_native_consumer_claim(&wrong_artifacts, &plan, &[], None).is_err());
}

#[test]
fn retained_resource_without_consumer_proof_does_not_claim_a_consumer_revision() {
    let root = tempfile::tempdir().expect("temporary profile");
    let generation = root.path().join("gen-1");
    std::fs::create_dir(&generation).expect("generation directory");
    let plan = checked_systemd_manager_effect_plan();
    let operation = &plan.operations()[0];
    let observation = NativeNoOpResourceObservation {
        qualified: NativeQualifiedResource::systemd(
            operation.target.resource.clone(),
            "/org/freedesktop/systemd1/unit/k3s_2eservice",
        )
        .expect("qualified K3s resource"),
        state: RuntimeResourceState::Present {
            revision: plan.document().desired_revisions[0].revision,
            health: RuntimeResourceHealth::Healthy,
        },
        consumer_requirement: NativeConsumerRequirement::Forbidden,
    };

    verify_retained_native_consumers_with_status(
        &NativeResourceLedger {
            schema: NATIVE_RESOURCE_LEDGER_SCHEMA.to_string(),
            owners: Vec::new(),
            consumers: Vec::new(),
        },
        &[observation],
        |_, _| Ok(true),
    )
    .expect("resource-only no-op evidence does not invent a consumer");
}
