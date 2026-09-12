//! Live multi-operation ownership replay tests.

use super::*;

fn checked_materialize_lifecycle_plan(
    action: aos_ability_model::ServiceAction,
) -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = stateful_owner_plan_fixture();
    let operation_template = fixture.effect_plan.operations[0].clone();
    let terminal_binding_index = fixture
        .binding_plan
        .bindings
        .iter()
        .position(|binding| binding.id == operation_template.binding)
        .expect("stateful fixture terminal binding");
    let terminal_request = fixture.binding_plan.bindings[terminal_binding_index]
        .request
        .clone();
    let old_interface = fixture.binding_plan.bindings[terminal_binding_index]
        .interface
        .clone();
    let old_implementation = fixture.binding_plan.bindings[terminal_binding_index]
        .implementation
        .clone();
    let lifecycle_method = match action {
        aos_ability_model::ServiceAction::Start => key("start"),
        aos_ability_model::ServiceAction::Restart => key("restart"),
        _ => panic!("lifecycle recovery fixture requires Start or Restart"),
    };
    let materialize_method = key("materialize");
    let observe_method = key("observe");

    let interface = fixture
        .interfaces
        .iter_mut()
        .find(|document| document.interface_key().ok().as_ref() == Some(&old_interface))
        .expect("stateful fixture terminal interface");
    let method_template = interface
        .interface
        .methods
        .get(&observe_method)
        .cloned()
        .expect("stateful fixture observation method");
    let mut materialize_descriptor = method_template.clone();
    materialize_descriptor.operation_family =
        aos_ability_model::OperationFamily::PrepareManagedConfiguration;
    materialize_descriptor.permitted_operations = vec![materialize_method.clone()];
    materialize_descriptor.outcome.indeterminate =
        aos_ability_model::IndeterminateSemantics::Reconcile;
    let mut lifecycle_descriptor = method_template;
    lifecycle_descriptor.operation_family =
        aos_ability_model::OperationFamily::ServiceLifecycle { action };
    lifecycle_descriptor.permitted_operations = vec![lifecycle_method.clone()];
    lifecycle_descriptor.outcome.indeterminate =
        aos_ability_model::IndeterminateSemantics::Reconcile;
    interface
        .interface
        .methods
        .insert(materialize_method.clone(), materialize_descriptor);
    interface
        .interface
        .methods
        .insert(lifecycle_method.clone(), lifecycle_descriptor);
    let terminal_interface = interface
        .interface_key()
        .expect("materialize lifecycle interface key");

    let package = fixture
        .binding_inputs
        .packages
        .first_mut()
        .expect("stateful fixture package");
    let terminal_implementation = package
        .implementation
        .providers
        .iter_mut()
        .find(|implementation| {
            implementation.interface == old_interface
                && matches!(
                    implementation.implementation,
                    aos_ability_model::ImplementationKind::TerminalHandler { .. }
                )
        })
        .expect("stateful fixture terminal implementation");
    terminal_implementation.interface = terminal_interface.clone();
    let terminal_descriptor = terminal_implementation
        .descriptor_digest()
        .expect("materialize lifecycle implementation digest");
    let terminal_reference = aos_ability_model::ProviderImplementationReference {
        descriptor: terminal_descriptor,
        artifact: old_implementation.artifact.clone(),
        handler: old_implementation.handler.clone(),
    };
    let terminal_export = package
        .exports
        .iter_mut()
        .find(|export| export.implementation == old_implementation.descriptor)
        .expect("stateful fixture terminal export");
    terminal_export.interface = terminal_interface.clone();
    terminal_export.implementation = terminal_descriptor;
    let package_digest = package
        .content_digest()
        .expect("materialize lifecycle package digest");

    for instance in &mut fixture.binding_inputs.desired_state.instances {
        instance.package = package_digest;
    }
    for binding in &mut fixture.binding_plan.bindings {
        binding.provider_package = Some(package_digest);
    }
    for inventory in &mut fixture.binding_inputs.environment.providers {
        if inventory.provider == fixture.binding_plan.bindings[terminal_binding_index].provider
            && inventory.interface == old_interface
            && inventory.implementation == old_implementation
        {
            inventory.interface = terminal_interface.clone();
            inventory.implementation = terminal_reference.clone();
        }
    }
    for request in &mut fixture.binding_inputs.desired_state.child_requests {
        if request.id == terminal_request {
            request.accepted_interfaces = vec![terminal_interface.clone()];
            request.methods = vec![
                materialize_method.clone(),
                observe_method.clone(),
                lifecycle_method.clone(),
            ];
            request.methods.sort();
        }
    }
    for request in &mut fixture.binding_plan.requests {
        if request.id == terminal_request {
            request.accepted_interfaces = vec![terminal_interface.clone()];
            request.methods = vec![
                materialize_method.clone(),
                observe_method.clone(),
                lifecycle_method.clone(),
            ];
            request.methods.sort();
        }
    }
    let binding = &mut fixture.binding_plan.bindings[terminal_binding_index];
    binding.interface = terminal_interface.clone();
    binding.implementation = terminal_reference;
    binding.caller_grant.methods = vec![
        materialize_method.clone(),
        observe_method.clone(),
        lifecycle_method.clone(),
    ];
    binding.caller_grant.methods.sort();
    for permission in &mut binding.caller_grant.resources {
        permission.operations = binding.caller_grant.methods.clone();
    }

    let mut materialize = operation_template.clone();
    materialize.key.key = materialize_method.clone();
    materialize.interface = terminal_interface.clone();
    materialize.method = materialize_method.clone();
    materialize.family = aos_ability_model::OperationFamily::PrepareManagedConfiguration;
    materialize.phase = aos_ability_model::OperationPhase::Preparing;
    materialize.input_phase = aos_ability_model::ValuePhase::Planning;
    materialize.target.interface = terminal_interface.clone();
    materialize.target.operations = vec![materialize_method];
    materialize.recovery.retry = RetryPolicy::Disabled;
    materialize.recovery.reconcile = Some(aos_ability_model::MethodReference {
        interface: terminal_interface.clone(),
        method: observe_method.clone(),
    });

    let mut lifecycle = operation_template;
    lifecycle.key.key = lifecycle_method.clone();
    lifecycle.interface = terminal_interface.clone();
    lifecycle.method = lifecycle_method.clone();
    lifecycle.family = aos_ability_model::OperationFamily::ServiceLifecycle { action };
    lifecycle.phase = aos_ability_model::OperationPhase::Converging;
    lifecycle.input_phase = aos_ability_model::ValuePhase::Planning;
    lifecycle.target.interface = terminal_interface.clone();
    lifecycle.target.operations = vec![lifecycle_method];
    lifecycle.recovery.retry = RetryPolicy::Disabled;
    lifecycle.recovery.reconcile = Some(aos_ability_model::MethodReference {
        interface: terminal_interface,
        method: observe_method,
    });
    fixture.effect_plan.operations = vec![materialize.clone(), lifecycle.clone()];
    fixture.effect_plan.edges = vec![aos_ability_model::DependencyEdge {
        from: aos_ability_model::PlanNodeKey::Operation {
            key: materialize.key,
        },
        to: aos_ability_model::PlanNodeKey::Operation { key: lifecycle.key },
        kind: aos_ability_model::DependencyKind::RequiredSuccess,
    }];
    fixture.context = aos_ability_validate::ValidationContext::new(
        BTreeSet::from([
            aos_ability_model::RequiredFeature::new("abilities-v1").expect("valid base feature"),
            aos_ability_model::RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)
                .expect("valid state format feature"),
        ]),
        fixture.interfaces.clone(),
    )
    .expect("materialize lifecycle validation context");
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("materialize lifecycle fixture must validate")
}

fn checked_assignment_for_operation(
    plan: &aos_ability_validate::CheckedEffectPlan,
    operation: &aos_ability_model::Operation,
) -> Result<aos_ability_model::ProviderAssignment, &'static str> {
    let binding = plan
        .binding_plan()
        .binding(&operation.binding)
        .ok_or("lifecycle operation binding is absent")?;
    let provider = plan
        .binding_plan()
        .environment()
        .providers
        .iter()
        .find(|provider| {
            provider.provider == binding.provider
                && provider.interface == binding.interface
                && provider.implementation == binding.implementation
        })
        .ok_or("lifecycle handler inventory is absent")?;

    Ok(aos_ability_model::ProviderAssignment {
        provider: provider.provider.clone(),
        interface: provider.interface.clone(),
        implementation: provider.implementation.clone(),
        incarnation: provider
            .incarnation
            .clone()
            .ok_or("lifecycle handler incarnation is absent")?,
    })
}

fn exercise_live_materialize_lifecycle_transaction(
    action: aos_ability_model::ServiceAction,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let generation = root.path().join("gen-1");
    std::fs::create_dir(&generation)?;
    let transaction_id = aos_ability_model::TransactionId(key("lifecycle"));
    let plan = checked_materialize_lifecycle_plan(action);
    let switch_lock = Arc::new(acquire_switch_lock_pub(&root.path().join("switch.lock"))?);
    let state = NativeInventoryState::for_generation(
        &generation,
        &transaction_id,
        &plan,
        None,
        BTreeSet::new(),
        switch_lock,
    )?;
    let journal_path = generation
        .join(TRANSACTION_ROOT)
        .join(transaction_id.0.as_str())
        .join(EXECUTION_JOURNAL_FILE);
    std::fs::create_dir_all(
        journal_path
            .parent()
            .ok_or("lifecycle journal has no transaction directory")?,
    )?;
    let mut store = ReopenStore {
        bundle: aos_contract::Sha256Digest::of_bytes("lifecycle recovery bundle"),
    };
    let mut transaction = ExecutionTransaction::open(
        &plan,
        transaction_id.clone(),
        journal_path,
        JournalLimits::default(),
        &mut store,
    )?;
    state.preflight_provider_owners_for_recovery_test(&transaction, |_| false)?;

    let qualified = NativeQualifiedResource::systemd(
        plan.operations()[0].target.resource.clone(),
        "/org/freedesktop/systemd1/unit/lifecycle_2eservice",
    )?;
    let mut catalog = JournalCatalog;
    let mut policy = AllowAllPolicy;
    let clock = RecoveryClock;

    let materialize = &plan.operations()[0];
    assert_eq!(
        materialize.family,
        aos_ability_model::OperationFamily::PrepareManagedConfiguration
    );
    let materialize_id = aos_ability_model::OperationId {
        plan: plan.id(),
        operation: materialize.key.clone(),
    };
    let materialize_assignment = checked_assignment_for_operation(&plan, materialize)?;
    let materialize_reservation = state.reserve(
        &qualified,
        ReservationContext {
            transaction: &transaction_id,
            operation: &materialize_id,
            attempt: NonZeroU32::new(1).ok_or("materialize attempt must be positive")?,
            expected_provider: Some(&materialize_assignment),
            recovery_remaining_millis: 1_000,
        },
        materialize,
        &materialize.accesses[0],
    )?;
    let mut materialize_adapter = CompletedAdapter::for_operation(&plan, materialize);
    let admitted = transaction
        .admit(
            &materialize.key,
            &materialize_adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    assert_eq!(
        transaction.drive_admitted(
            &admitted,
            &mut materialize_adapter,
            &mut policy,
            &clock,
            &CancellationToken::default(),
        )?,
        ExecutionStep::Completed
    );
    transaction
        .release_admitted::<CompletedAdapter, _, _>(admitted, &mut catalog, &clock)
        .map_err(|failure| io::Error::other(failure.error().to_string()))?;
    drop(materialize_reservation);

    // This refresh must consume the already-open transaction's replay summary.
    // Reopening its journal here would try to acquire the live exclusive lock.
    state.preflight_provider_owners_for_recovery_test(&transaction, |_| false)?;

    let lifecycle = &plan.operations()[1];
    assert_eq!(
        lifecycle.family,
        aos_ability_model::OperationFamily::ServiceLifecycle { action }
    );
    let lifecycle_id = aos_ability_model::OperationId {
        plan: plan.id(),
        operation: lifecycle.key.clone(),
    };
    let lifecycle_assignment = checked_assignment_for_operation(&plan, lifecycle)?;
    let lifecycle_reservation = state.reserve(
        &qualified,
        ReservationContext {
            transaction: &transaction_id,
            operation: &lifecycle_id,
            attempt: NonZeroU32::new(1).ok_or("lifecycle attempt must be positive")?,
            expected_provider: Some(&lifecycle_assignment),
            recovery_remaining_millis: 1_000,
        },
        lifecycle,
        &lifecycle.accesses[0],
    )?;
    let mut lifecycle_adapter = IndeterminateThenRetryAdapter;
    let admitted = transaction
        .admit(
            &lifecycle.key,
            &lifecycle_adapter,
            &mut catalog,
            &mut policy,
            &clock,
        )
        .map_err(admission_error)?;
    let error = transaction
        .drive_admitted_with_observer(
            &admitted,
            &mut lifecycle_adapter,
            &mut policy,
            &clock,
            &CancellationToken::default(),
            &mut HaltAtIntent,
        )
        .expect_err("lifecycle operation must halt at durable effect intent");
    assert!(matches!(
        error,
        ExecutionError::BoundaryHalt(Boundary::EffectIntentDurable)
    ));
    drop(admitted);
    drop(lifecycle_reservation);

    state.preflight_provider_owners_for_recovery_test(&transaction, |_| false)?;
    let ledger = load_native_resource_ledger(&state.ledger_path)?;
    assert_eq!(ledger.owners.len(), 1);
    assert_eq!(ledger.owners[0].claim_by.len(), 2);
    assert!(
        ledger.owners[0]
            .claim_by
            .iter()
            .any(|claim| claim.operation == materialize_id)
    );
    assert!(
        ledger.owners[0]
            .claim_by
            .iter()
            .any(|claim| claim.operation == lifecycle_id)
    );
    Ok(())
}

#[test]
fn materialize_then_start_or_restart_replays_through_the_same_live_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_live_materialize_lifecycle_transaction(aos_ability_model::ServiceAction::Start)?;
    exercise_live_materialize_lifecycle_transaction(aos_ability_model::ServiceAction::Restart)?;
    Ok(())
}
