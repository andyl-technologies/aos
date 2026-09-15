//! Regression tests for aggregate and nested output projections.

use super::*;

#[test]
fn aggregate_output_projection_cycle_is_rejected() {
    let mut fixture = plan_fixture();
    install_projection_ports(
        &mut fixture,
        ValueSchema::Boolean,
        ResourceLifetime::Instance,
    );
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let aggregate = AggregateId {
        provider: provider.clone(),
        group: key("projection"),
    };
    let first = aggregate_projection(&aggregate, &fixture, "first", "second");
    let second = aggregate_projection(&aggregate, &fixture, "second", "first");
    let outputs = vec![first.clone(), second];

    assert!(
        fixture
            .context
            .validate_composed_output(
                &provider,
                &first,
                &outputs,
                &fixture.binding_plan.bindings,
                &fixture.binding_plan.resources,
                &fixture.effect_plan.artifacts,
                None,
            )
            .is_err()
    );
}

#[test]
fn transitive_aggregate_projection_rechecks_resource_authority() {
    let mut fixture = plan_fixture();
    let ungranted = add_ungranted_resource(&mut fixture);
    install_projection_ports(
        &mut fixture,
        ValueSchema::ResourceReference,
        ResourceLifetime::Attempt,
    );
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let aggregate = AggregateId {
        provider: provider.clone(),
        group: key("projection"),
    };
    let first = aggregate_projection(&aggregate, &fixture, "first", "second");
    let second = aggregate_projection(&aggregate, &fixture, "second", "third");
    let third = AggregateOutput {
        aggregate: aggregate.clone(),
        interface: fixture.binding_plan.bindings[0].interface.clone(),
        port: key("third"),
        value: ValueExpression::ResourceReference {
            reference: ResourceReference {
                interface: fixture.binding_plan.bindings[0].interface.clone(),
                resource: ungranted,
                operations: vec![key("observe")],
                lifetime: ResourceLifetime::Instance,
            },
        },
    };
    let outputs = vec![first.clone(), second, third];

    assert!(
        fixture
            .context
            .validate_composed_output(
                &provider,
                &first,
                &outputs,
                &fixture.binding_plan.bindings,
                &fixture.binding_plan.resources,
                &fixture.effect_plan.artifacts,
                None,
            )
            .is_err()
    );
}

#[test]
fn aggregate_projection_rejects_unretained_artifact() {
    let mut fixture = plan_fixture();
    install_projection_ports(
        &mut fixture,
        ValueSchema::ArtifactReference,
        ResourceLifetime::Instance,
    );
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let aggregate = AggregateId {
        provider: provider.clone(),
        group: key("projection"),
    };
    let mut artifact = fixture.effect_plan.artifacts[0].clone();
    artifact.content = digest('e');
    let output = AggregateOutput {
        aggregate,
        interface: fixture.binding_plan.bindings[0].interface.clone(),
        port: key("first"),
        value: ValueExpression::ArtifactReference {
            reference: artifact,
        },
    };

    assert!(
        fixture
            .context
            .validate_composed_output(
                &provider,
                &output,
                std::slice::from_ref(&output),
                &fixture.binding_plan.bindings,
                &fixture.binding_plan.resources,
                &fixture.effect_plan.artifacts,
                None,
            )
            .is_err()
    );
}

#[test]
fn aggregate_projection_allows_lifetime_attenuation() {
    let mut fixture = plan_fixture();
    install_projection_ports(
        &mut fixture,
        ValueSchema::Boolean,
        ResourceLifetime::Attempt,
    );
    fixture.interfaces[0]
        .interface
        .outputs
        .get_mut(&key("second"))
        .expect("projection port exists")
        .lifetime = ResourceLifetime::Instance;
    fixture.refresh_interface();
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let aggregate = AggregateId {
        provider: provider.clone(),
        group: key("projection"),
    };
    let first = aggregate_projection(&aggregate, &fixture, "first", "second");
    let second = AggregateOutput {
        aggregate,
        interface: fixture.binding_plan.bindings[0].interface.clone(),
        port: key("second"),
        value: ValueExpression::Literal {
            value: AbilityValue::new(serde_json::Value::Bool(true))
                .expect("boolean is a bounded value"),
        },
    };
    let outputs = vec![first.clone(), second];

    fixture
        .context
        .validate_composed_output(
            &provider,
            &first,
            &outputs,
            &fixture.binding_plan.bindings,
            &fixture.binding_plan.resources,
            &fixture.effect_plan.artifacts,
            None,
        )
        .expect("longer-lived source may be exposed through a shorter-lived output");
}

#[test]
fn aggregate_projection_requires_the_exact_root_value() {
    let mut fixture = plan_fixture();
    install_projection_ports(
        &mut fixture,
        ValueSchema::Boolean,
        ResourceLifetime::Instance,
    );
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let aggregate = AggregateId {
        provider: provider.clone(),
        group: key("projection"),
    };
    let retained = AggregateOutput {
        aggregate: aggregate.clone(),
        interface: fixture.binding_plan.bindings[0].interface.clone(),
        port: key("first"),
        value: ValueExpression::Literal {
            value: AbilityValue::new(serde_json::Value::Bool(true))
                .expect("boolean is a bounded value"),
        },
    };
    let forged = AggregateOutput {
        value: ValueExpression::Literal {
            value: AbilityValue::new(serde_json::Value::Bool(false))
                .expect("boolean is a bounded value"),
        },
        ..retained.clone()
    };

    assert!(
        fixture
            .context
            .validate_composed_output(
                &provider,
                &forged,
                &[retained],
                &fixture.binding_plan.bindings,
                &fixture.binding_plan.resources,
                &fixture.effect_plan.artifacts,
                None,
            )
            .is_err()
    );
}

#[test]
fn aggregate_projection_rejects_deep_programmatic_input_before_recursive_equality() {
    let mut fixture = plan_fixture();
    install_projection_ports(
        &mut fixture,
        ValueSchema::Boolean,
        ResourceLifetime::Instance,
    );
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let mut value = ValueExpression::Literal {
        value: AbilityValue::new(serde_json::Value::Bool(true))
            .expect("boolean is a bounded value"),
    };
    for _ in 0..aos_ability_model::ABILITY_LIMITS_V1.max_structural_depth {
        value = ValueExpression::List { items: vec![value] };
    }
    let output = AggregateOutput {
        aggregate: AggregateId {
            provider: provider.clone(),
            group: key("projection"),
        },
        interface: fixture.binding_plan.bindings[0].interface.clone(),
        port: key("first"),
        value,
    };
    let outputs = vec![output.clone()];
    let errors = fixture
        .context
        .validate_composed_output(
            &provider,
            &output,
            &outputs,
            &fixture.binding_plan.bindings,
            &fixture.binding_plan.resources,
            &fixture.effect_plan.artifacts,
            None,
        )
        .expect_err("deep programmatic projection must fail bounded preflight");

    assert!(
        errors
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::LimitExceeded)
    );
}

#[test]
fn aggregate_resource_reference_cannot_exceed_binding_lifetime() {
    let mut fixture = plan_fixture();
    install_projection_ports(
        &mut fixture,
        ValueSchema::ResourceReference,
        ResourceLifetime::Attempt,
    );
    fixture.binding_plan.bindings[0].lifetime = ResourceLifetime::Attempt;
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let output = AggregateOutput {
        aggregate: AggregateId {
            provider: provider.clone(),
            group: key("projection"),
        },
        interface: fixture.binding_plan.bindings[0].interface.clone(),
        port: key("first"),
        value: ValueExpression::ResourceReference {
            reference: ResourceReference {
                interface: fixture.binding_plan.bindings[0].interface.clone(),
                resource: fixture.binding_plan.resources[0].resource.clone(),
                operations: vec![key("observe")],
                lifetime: ResourceLifetime::Persistent,
            },
        },
    };

    assert!(
        fixture
            .context
            .validate_composed_output(
                &provider,
                &output,
                std::slice::from_ref(&output),
                &fixture.binding_plan.bindings,
                &fixture.binding_plan.resources,
                &fixture.effect_plan.artifacts,
                None,
            )
            .is_err()
    );
}

#[test]
fn contribution_rejects_forged_provider_assignment() {
    let mut fixture = contribution_fixture(ValueSchema::ProviderAssignment);
    let inventory = &fixture.binding_inputs.environment.providers[0];
    let assignment = ProviderAssignment {
        provider: inventory.provider.clone(),
        interface: inventory.interface.clone(),
        implementation: inventory.implementation.clone(),
        incarnation: inventory
            .incarnation
            .clone()
            .expect("fixture provider is available"),
    };
    install_contribution_value(
        &mut fixture,
        AbilityValue::new(
            serde_json::to_value(assignment).expect("provider assignment must serialize"),
        )
        .expect("provider assignment is bounded"),
    );

    assert_diagnostic(fixture, DiagnosticCode::MissingReference);
}

#[test]
fn contribution_rechecks_nested_resource_authority() {
    let mut fixture = contribution_fixture(ValueSchema::ResourceReference);
    let resource = add_ungranted_resource(&mut fixture);
    let reference = ResourceReference {
        interface: fixture.binding_plan.bindings[0].interface.clone(),
        resource,
        operations: vec![key("observe")],
        lifetime: ResourceLifetime::Instance,
    };
    install_contribution_value(
        &mut fixture,
        AbilityValue::new(
            serde_json::to_value(reference).expect("resource reference must serialize"),
        )
        .expect("resource reference is bounded"),
    );

    assert_diagnostic(fixture, DiagnosticCode::ResourceScopeEscape);
}

#[test]
fn contribution_rejects_foreign_artifact() {
    let mut fixture = contribution_fixture(ValueSchema::ArtifactReference);
    let mut artifact = fixture.effect_plan.artifacts[0].clone();
    artifact.content = digest('e');
    install_contribution_value(
        &mut fixture,
        AbilityValue::new(
            serde_json::to_value(artifact).expect("artifact reference must serialize"),
        )
        .expect("artifact reference is bounded"),
    );

    assert_diagnostic(fixture, DiagnosticCode::ResourceScopeEscape);
}

#[test]
fn path_through_an_unselected_branch_does_not_order_writes() {
    let fixture = conditional_ordering_fixture(false);

    assert_diagnostic(fixture, DiagnosticCode::ConflictingController);
}

#[test]
fn extra_branch_merge_edge_is_rejected() {
    let mut fixture = conditional_ordering_fixture(true);
    fixture
        .clone()
        .validate()
        .expect("direct ordering makes the conditional fixture valid");
    fixture.effect_plan.edges.push(DependencyEdge {
        from: operation_node("selector"),
        to: PlanNodeKey::Merge {
            key: scoped("merge"),
        },
        kind: DependencyKind::BranchMerge,
    });
    fixture.effect_plan.edges.sort_by(compare_edges);

    assert_diagnostic(fixture, DiagnosticCode::MissingDataDependency);
}

#[test]
fn boolean_decision_rejects_duplicate_predicates() {
    let mut fixture = conditional_ordering_fixture(true);
    fixture.effect_plan.decisions[0].alternatives[1].predicate =
        DecisionPredicate::Boolean { value: false };

    assert_diagnostic(fixture, DiagnosticCode::ValueTypeMismatch);
}

#[test]
fn two_stage_planned_provider_chain_is_grounded_in_available_inventory() {
    planned_provider_chain_fixture()
        .validate()
        .expect("available A may establish planned B, which may establish planned C");
}

#[test]
fn unrelated_assignment_evidence_cannot_satisfy_planned_readiness() {
    let fixture = planned_provider_chain_fixture();
    let available_provider = fixture
        .binding_inputs
        .environment
        .providers
        .iter()
        .find(|provider| provider.state == ProviderState::Available)
        .expect("fixture has an available root provider")
        .provider
        .clone();
    let plan = fixture
        .validate()
        .expect("planned provider chain fixture must validate");
    let readiness = plan
        .provider_readiness(&BindingId(key("b")))
        .expect("planned B readiness must be retained");
    let planned_binding = plan
        .binding_plan()
        .binding(&readiness.binding)
        .expect("planned B binding must be retained");
    let unrelated = ProviderAssignment {
        provider: available_provider,
        interface: planned_binding.interface.clone(),
        implementation: planned_binding.implementation.clone(),
        incarnation: IncarnationId::new("unrelated-incarnation").expect("valid test incarnation"),
    };
    let value = AbilityValue::new(
        serde_json::to_value(unrelated).expect("provider assignment must serialize"),
    )
    .expect("provider assignment must be a bounded canonical value");

    assert!(matches!(
        plan.validate_provider_assignment(readiness, &value),
        Err(crate::ProviderReadinessError::SubjectMismatch)
    ));
}

#[test]
fn materialized_input_rechecks_empty_resource_projection_baseline() {
    let mut fixture = plan_fixture();
    fixture.interfaces[0]
        .interface
        .methods
        .get_mut(&key("observe"))
        .expect("fixture observe method")
        .parameters = ValueSchema::ResourceReference;
    fixture.refresh_interface();
    fixture.effect_plan.operations[0].inputs = ValueExpression::ResourceReference {
        reference: fixture.effect_plan.operations[0].target.clone(),
    };
    let ungranted = add_ungranted_resource(&mut fixture);
    fixture.refresh_commitments();
    let plan = fixture
        .validate()
        .expect("static fixture input remains authorized");
    let operation = &plan.operations()[0];
    let malicious = ResourceReference {
        interface: operation.interface.clone(),
        resource: ungranted,
        operations: Vec::new(),
        lifetime: ResourceLifetime::Attempt,
    };
    let value = AbilityValue::new(
        serde_json::to_value(malicious).expect("resource reference must serialize"),
    )
    .expect("resource reference must be a bounded canonical value");

    assert!(matches!(
        plan.validate_operation_inputs(operation, &value),
        Err(crate::InputValidationError::UnauthorizedReference(
            crate::ValueAuthorizationError::ResourceNotGranted
        ))
    ));
}

#[test]
fn nested_operation_result_accepts_the_exact_producer_output_schema() {
    let fixture = nested_operation_result_fixture(ValueSchema::Boolean);

    fixture
        .validate()
        .expect("nested result reference must match the exact producer output schema");
}

#[test]
fn nested_operation_result_rejects_a_different_producer_output_schema() {
    let fixture = nested_operation_result_fixture(ValueSchema::String {
        max_length: 32,
        syntax: None,
    });

    assert_diagnostic(fixture, DiagnosticCode::ValueTypeMismatch);
}

fn assert_retained_reference_mismatch(mutate: impl FnOnce(&mut ResourceReference)) {
    let plan = checked_lifecycle_effect_plan();
    let operation = &plan.operations()[0];
    let mut reference = operation.target.clone();
    mutate(&mut reference);
    let outputs = BTreeMap::from([
        (
            key("active"),
            AbilityValue::new(serde_json::Value::Bool(true)).expect("boolean output"),
        ),
        (
            key("retained-resource"),
            AbilityValue::new(
                serde_json::to_value(reference).expect("resource reference must serialize"),
            )
            .expect("resource reference must be a bounded canonical value"),
        ),
    ]);

    assert_eq!(
        plan.validate_operation_outputs(operation, &outputs),
        Err(crate::OutputValidationError::OutputSetMismatch)
    );
}

#[test]
fn retained_output_rejects_a_different_interface() {
    assert_retained_reference_mismatch(|reference| {
        reference.interface.name =
            aos_ability_model::InterfaceName::new("test.other").expect("interface name");
    });
}

#[test]
fn retained_output_rejects_a_different_resource() {
    assert_retained_reference_mismatch(|reference| {
        reference.resource.key = key("other-resource");
    });
}

#[test]
fn retained_output_rejects_different_operations() {
    assert_retained_reference_mismatch(|reference| {
        reference.operations = vec![key("observe")];
    });
}

#[test]
fn retained_output_rejects_a_different_lifetime() {
    assert_retained_reference_mismatch(|reference| {
        reference.lifetime = ResourceLifetime::Persistent;
    });
}

#[test]
fn runtime_output_rejects_reference_shorter_than_declared_output() {
    let mut fixture = plan_fixture();
    let ready = fixture.interfaces[0]
        .interface
        .methods
        .get_mut(&key("observe"))
        .expect("fixture observe method")
        .outputs
        .get_mut(&key("ready"))
        .expect("fixture ready output");
    ready.schema = ValueSchema::ResourceReference;
    ready.phase = ValuePhase::Planning;
    ready.lifetime = ResourceLifetime::Instance;
    fixture.refresh_interface();
    let plan = fixture
        .validate()
        .expect("resource-output fixture must validate");
    let operation = &plan.operations()[0];
    let short_lived = ResourceReference {
        interface: operation.interface.clone(),
        resource: operation.target.resource.clone(),
        operations: vec![key("observe")],
        lifetime: ResourceLifetime::Attempt,
    };
    let value = AbilityValue::new(
        serde_json::to_value(short_lived).expect("resource reference must serialize"),
    )
    .expect("resource reference must be a bounded canonical value");

    assert!(matches!(
        plan.validate_operation_output(operation, &key("ready"), &value),
        Err(crate::OutputValidationError::UnauthorizedReference(
            crate::ValueAuthorizationError::ResourceScopeEscape
        ))
    ));
}

#[test]
fn runtime_output_allows_lifetime_attenuation() {
    let mut fixture = plan_fixture();
    let ready = fixture.interfaces[0]
        .interface
        .methods
        .get_mut(&key("observe"))
        .expect("fixture observe method")
        .outputs
        .get_mut(&key("ready"))
        .expect("fixture ready output");
    ready.schema = ValueSchema::ResourceReference;
    ready.lifetime = ResourceLifetime::Attempt;
    fixture.refresh_interface();
    let plan = fixture
        .validate()
        .expect("resource-output fixture must validate");
    let operation = &plan.operations()[0];
    let longer_lived = ResourceReference {
        interface: operation.interface.clone(),
        resource: operation.target.resource.clone(),
        operations: vec![key("observe")],
        lifetime: ResourceLifetime::Instance,
    };
    let value = AbilityValue::new(
        serde_json::to_value(longer_lived).expect("resource reference must serialize"),
    )
    .expect("resource reference must be a bounded canonical value");

    assert!(
        plan.validate_operation_output(operation, &key("ready"), &value)
            .is_ok()
    );
}

#[test]
fn runtime_output_rechecks_nested_resource_authority() {
    let mut fixture = plan_fixture();
    let ready = fixture.interfaces[0]
        .interface
        .methods
        .get_mut(&key("observe"))
        .expect("fixture observe method")
        .outputs
        .get_mut(&key("ready"))
        .expect("fixture ready output");
    ready.schema = ValueSchema::ResourceReference;
    ready.phase = ValuePhase::Planning;
    ready.lifetime = ResourceLifetime::Instance;
    fixture.refresh_interface();
    let ungranted = add_ungranted_resource(&mut fixture);
    fixture.refresh_commitments();
    let plan = fixture
        .validate()
        .expect("resource-output fixture must validate");
    let operation = &plan.operations()[0];
    let malicious = ResourceReference {
        interface: operation.interface.clone(),
        resource: ungranted,
        operations: Vec::new(),
        lifetime: ResourceLifetime::Instance,
    };
    let value = AbilityValue::new(
        serde_json::to_value(malicious).expect("resource reference must serialize"),
    )
    .expect("resource reference must be a bounded canonical value");

    assert!(matches!(
        plan.validate_operation_output(operation, &key("ready"), &value),
        Err(crate::OutputValidationError::UnauthorizedReference(
            crate::ValueAuthorizationError::ResourceNotGranted
        ))
    ));
}

#[test]
fn runtime_method_validation_rejects_an_authorized_but_undeclared_method() {
    let mut fixture = plan_fixture();
    let foreign_method = key("foreign-observe");
    let descriptor = fixture.interfaces[0].interface.methods[&key("observe")].clone();
    fixture.interfaces[0]
        .interface
        .methods
        .insert(foreign_method.clone(), descriptor);
    fixture.binding_plan.bindings[0]
        .caller_grant
        .methods
        .push(foreign_method.clone());
    fixture.binding_plan.bindings[0].caller_grant.methods.sort();
    fixture.binding_plan.bindings[0].caller_grant.resources[0]
        .operations
        .push(foreign_method.clone());
    fixture.binding_plan.bindings[0].caller_grant.resources[0]
        .operations
        .sort();
    fixture.refresh_interface();
    fixture.refresh_commitments();
    let plan = fixture
        .validate()
        .expect("an unused authorized interface method does not alter the operation");
    let operation = &plan.operations()[0];
    let foreign = MethodReference {
        interface: operation.interface.clone(),
        method: foreign_method,
    };

    assert!(matches!(
        plan.method_outcome_semantics(operation, &foreign),
        Err(crate::OutputValidationError::UndeclaredMethod)
    ));
}
