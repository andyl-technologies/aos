//! Cross-stage semantic regression tests built from the shared checked-plan fixture.

use std::collections::BTreeMap;

use aos_ability_model::document::{Contribution, PackageSubject, ProviderState};
use aos_ability_model::{
    AbilityActivationMode, AbilityValue, AccessMode, AggregateId, AggregateOutput,
    AggregateOutputReference, AggregationContract, AggregationScope, BindingId, BranchMembership,
    ContributionPermission, ControllerAssignment, DecisionAlternative, DecisionNode,
    DecisionPredicate, DecisionSelector, DependencyEdge, DependencyKind, DiagnosticCode,
    ExportDeclaration, HandlerDescriptor, ImplementationKind, IncarnationId, LocalKey, MergeNode,
    MergedOutput, MethodReference, OperationFamily, OperationResultReference, OutputDescriptor,
    PackageDocument, PackageImplementation, PlanNodeKey, ProviderAssignment,
    ProviderImplementation, RequirementDeclaration, RequirementFallback, RequirementStrength,
    ResourceId, ResourceLifetime, ResourcePermission, ResourceReference, ResourceRevision,
    ResultProducerKey, RevisionId, ScopePath, ScopedOperationKey, ServiceAction, ValueExpression,
    ValuePhase, ValueSchema, ValueVisibility, VersionedDocument, compare_edges,
    compare_operation_keys, compare_resource_ids,
};
use aos_contract::Sha256Digest;

use crate::test_support::{PlanFixture, plan_fixture, planned_provider_chain_fixture};

#[test]
fn retained_resource_cannot_silently_change_controller() {
    let mut fixture = plan_fixture();
    let resource = fixture.effect_plan.current_revisions[0].resource.clone();
    let current = controller(&fixture, "current");
    let desired = controller(&fixture, "desired");
    fixture.binding_inputs.environment.controllers = vec![ControllerAssignment {
        resource: resource.clone(),
        controller: current,
    }];
    fixture.binding_inputs.desired_state.controllers = vec![ControllerAssignment {
        resource,
        controller: desired,
    }];
    fixture.refresh_commitments();

    assert_diagnostic(fixture, DiagnosticCode::ConflictingController);
}

#[test]
fn effect_cannot_omit_authenticated_current_state() {
    let mut fixture = plan_fixture();
    fixture.effect_plan.current_revisions.clear();

    assert_diagnostic(fixture, DiagnosticCode::BindingInterfaceMismatch);
}

#[test]
fn effect_cannot_invent_a_desired_revision() {
    let mut fixture = plan_fixture();
    fixture.effect_plan.desired_revisions[0].revision = RevisionId(digest('b'));

    assert_diagnostic(fixture, DiagnosticCode::BindingInterfaceMismatch);
}

#[test]
fn unchanged_write_still_requires_a_controller() {
    let mut fixture = plan_fixture();
    grant_exclusive_access(&mut fixture);
    fixture.effect_plan.operations[0].accesses[0].mode = AccessMode::ExclusiveWrite;
    fixture.refresh_commitments();

    assert_diagnostic(fixture, DiagnosticCode::MissingController);
}

#[test]
fn unordered_read_and_exclusive_write_conflict() {
    let mut fixture = plan_fixture();
    let assigned = install_controller(&mut fixture);
    grant_exclusive_access(&mut fixture);

    let mut writer = fixture.effect_plan.operations[0].clone();
    writer.key.key = key("write");
    writer.accesses[0].mode = AccessMode::ExclusiveWrite;
    writer.controller = Some(assigned);
    fixture.effect_plan.operations.push(writer);
    fixture.refresh_commitments();

    assert_diagnostic(fixture, DiagnosticCode::ConflictingController);
}

#[test]
fn bounded_ordering_accepts_a_conflicting_access_chain() {
    let mut fixture = plan_fixture();
    let assigned = install_controller(&mut fixture);
    grant_exclusive_access(&mut fixture);

    let mut first = fixture.effect_plan.operations[0].clone();
    first.key.key = key("first");
    first.accesses[0].mode = AccessMode::ExclusiveWrite;
    first.controller = Some(assigned.clone());
    let mut second = first.clone();
    second.key.key = key("second");
    let mut third = first.clone();
    third.key.key = key("third");
    fixture.effect_plan.operations = vec![first, second, third];
    fixture.effect_plan.edges = vec![dependency("first", "second"), dependency("second", "third")];
    fixture.refresh_commitments();

    fixture
        .validate()
        .expect("a finite explicit chain orders every conflicting access");
}

#[test]
fn read_only_primary_cannot_authorize_write_recovery() {
    let mut fixture = plan_fixture();
    let primary = fixture.interfaces[0].interface.methods[&key("observe")].clone();
    fixture.interfaces[0].interface.methods.insert(
        key("stop"),
        aos_ability_model::MethodDescriptor {
            operation_family: OperationFamily::ServiceLifecycle {
                action: ServiceAction::Stop,
            },
            ..primary
        },
    );
    fixture.binding_plan.bindings[0]
        .caller_grant
        .methods
        .push(key("stop"));
    fixture.binding_plan.bindings[0].caller_grant.resources[0]
        .operations
        .push(key("stop"));
    fixture.effect_plan.operations[0].recovery.cancel = Some(MethodReference {
        interface: fixture.effect_plan.operations[0].interface.clone(),
        method: key("stop"),
    });
    fixture.refresh_interface();

    assert_diagnostic(fixture, DiagnosticCode::MethodContractMismatch);
}

#[test]
fn final_effect_leaf_requires_a_terminal_handler() {
    let mut fixture = plan_fixture();
    pin_primary_binding_to_pure_package(&mut fixture);

    assert_diagnostic(fixture, DiagnosticCode::UnresolvedObligation);
}

#[test]
fn exact_pure_provider_package_is_required() {
    let mut fixture = plan_fixture();
    pin_primary_binding_to_pure_package(&mut fixture);
    fixture.binding_plan.bindings[0].provider_package = Some(digest('f'));

    assert_diagnostic(fixture, DiagnosticCode::MissingReference);
}

#[test]
fn contracts_only_package_cannot_claim_resource_ownership() {
    let mut fixture = plan_fixture();
    pin_primary_binding_to_pure_package(&mut fixture);
    fixture.binding_inputs.packages[0]
        .ownership
        .push(ScopePath::root());

    assert_diagnostic(fixture, DiagnosticCode::ResourceScopeEscape);
}

#[test]
fn contracts_only_package_cannot_catalog_a_terminal_handler() {
    let mut fixture = plan_fixture();
    pin_primary_binding_to_pure_package(&mut fixture);
    let package = &mut fixture.binding_inputs.packages[0];
    let artifact = package.implementation.providers[0].artifact.clone();
    let handler = key("terminal");
    package.implementation.providers[0].implementation = ImplementationKind::TerminalHandler {
        handler: handler.clone(),
    };
    package.implementation.handlers.insert(
        handler,
        HandlerDescriptor {
            artifact,
            entry_point: "bin/terminal".to_string(),
            arguments: ValueSchema::Boolean,
            result: ValueSchema::Boolean,
        },
    );

    assert_diagnostic(fixture, DiagnosticCode::ResourceScopeEscape);
}

#[test]
fn advisory_null_fallback_does_not_synthesize_authority() {
    let mut fixture = plan_fixture();
    install_optional_resource_output(&mut fixture);
    fixture.refresh_interface();
    pin_primary_binding_to_pure_package(&mut fixture);
    fixture.binding_inputs.packages[0].requirements = vec![advisory_requirement(
        &fixture.binding_plan.bindings[0].interface,
        AbilityValue::new(serde_json::Value::Null).expect("null is a bounded value"),
    )];

    fixture
        .context
        .prepare_binding_candidates(
            &fixture.binding_inputs.environment,
            &fixture.binding_inputs.desired_state,
            &fixture.binding_inputs.packages,
        )
        .expect("an absent optional resource carries no authority");
}

#[test]
fn advisory_resource_fallback_cannot_synthesize_authority() {
    let mut fixture = plan_fixture();
    install_optional_resource_output(&mut fixture);
    fixture.refresh_interface();
    pin_primary_binding_to_pure_package(&mut fixture);
    let reference = fixture.effect_plan.operations[0].target.clone();
    fixture.binding_inputs.packages[0].requirements = vec![advisory_requirement(
        &fixture.binding_plan.bindings[0].interface,
        AbilityValue::new(
            serde_json::to_value(reference).expect("resource reference must serialize"),
        )
        .expect("resource reference is a bounded value"),
    )];

    let errors = fixture
        .context
        .prepare_binding_candidates(
            &fixture.binding_inputs.environment,
            &fixture.binding_inputs.desired_state,
            &fixture.binding_inputs.packages,
        )
        .expect_err("literal fallback must not create resource authority");
    assert!(
        errors
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ResourceScopeEscape)
    );
}

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

fn install_controller(fixture: &mut PlanFixture) -> AggregateId {
    let resource = fixture.effect_plan.current_revisions[0].resource.clone();
    let assigned = controller(fixture, "service");
    let assignment = ControllerAssignment {
        resource,
        controller: assigned.clone(),
    };
    fixture.binding_inputs.environment.controllers = vec![assignment.clone()];
    fixture.binding_inputs.desired_state.controllers = vec![assignment.clone()];
    fixture.effect_plan.controllers = vec![assignment];
    assigned
}

fn conditional_ordering_fixture(direct_order: bool) -> PlanFixture {
    let mut fixture = plan_fixture();
    let original_resource = fixture.effect_plan.current_revisions[0].resource.clone();
    let shared_resource = ResourceId {
        provider: original_resource.provider.clone(),
        key: key("shared"),
    };
    let shared_revision = ResourceRevision {
        resource: shared_resource.clone(),
        revision: RevisionId(digest('8')),
    };
    fixture
        .binding_inputs
        .environment
        .resources
        .push(shared_revision.clone());
    fixture
        .binding_inputs
        .desired_state
        .resources
        .push(shared_revision.clone());
    fixture.binding_plan.resources.push(shared_revision.clone());
    fixture
        .effect_plan
        .current_revisions
        .push(shared_revision.clone());
    fixture.effect_plan.desired_revisions.push(shared_revision);

    let assigned = AggregateId {
        provider: shared_resource.provider.clone(),
        group: key("shared"),
    };
    let assignment = ControllerAssignment {
        resource: shared_resource.clone(),
        controller: assigned.clone(),
    };
    fixture.binding_inputs.environment.controllers = vec![assignment.clone()];
    fixture.binding_inputs.desired_state.controllers = vec![assignment.clone()];
    fixture.effect_plan.controllers = vec![assignment];
    fixture.binding_plan.bindings[0]
        .caller_grant
        .resources
        .push(ResourcePermission {
            resource: shared_resource.clone(),
            access: AccessMode::ExclusiveWrite,
            operations: vec![key("observe")],
        });

    let template = fixture.effect_plan.operations[0].clone();
    let decision_key = scoped("decision");
    let mut selector = template.clone();
    selector.key = scoped("selector");
    let mut false_branch = template.clone();
    false_branch.key = scoped("false-branch");
    false_branch.branch_context = vec![BranchMembership {
        decision: decision_key.clone(),
        alternative: key("false"),
    }];
    let mut true_branch = template.clone();
    true_branch.key = scoped("true-branch");
    true_branch.branch_context = vec![BranchMembership {
        decision: decision_key.clone(),
        alternative: key("true"),
    }];
    let mut left = template.clone();
    left.key = scoped("left");
    left.target.resource = shared_resource.clone();
    left.accesses = vec![aos_ability_model::ResourceAccess {
        resource: shared_resource.clone(),
        mode: AccessMode::ExclusiveWrite,
    }];
    left.controller = Some(assigned.clone());
    let mut right = left.clone();
    right.key = scoped("right");
    right.controller = Some(assigned);
    fixture.effect_plan.operations = vec![false_branch, left, right, selector, true_branch];
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));

    let output = key("ready");
    let decision = DecisionNode {
        key: decision_key.clone(),
        branch_context: Vec::new(),
        selector: DecisionSelector {
            result: operation_result("selector", "ready"),
            tag_field: None,
        },
        alternatives: vec![
            DecisionAlternative {
                key: key("false"),
                predicate: DecisionPredicate::Boolean { value: false },
            },
            DecisionAlternative {
                key: key("true"),
                predicate: DecisionPredicate::Boolean { value: true },
            },
        ],
    };
    let merge = MergeNode {
        key: scoped("merge"),
        decision: decision_key.clone(),
        branch_context: Vec::new(),
        outputs: [(
            output.clone(),
            MergedOutput {
                descriptor: OutputDescriptor {
                    schema: aos_ability_model::ValueSchema::Boolean,
                    phase: ValuePhase::Observation,
                    visibility: ValueVisibility::Protected,
                    lifetime: ResourceLifetime::Attempt,
                },
                alternatives: [
                    (key("false"), operation_result("false-branch", "ready")),
                    (key("true"), operation_result("true-branch", "ready")),
                ]
                .into_iter()
                .collect(),
            },
        )]
        .into_iter()
        .collect(),
    };
    fixture.effect_plan.decisions = vec![decision];
    fixture.effect_plan.merges = vec![merge];
    fixture.effect_plan.edges = vec![
        DependencyEdge {
            from: operation_node("selector"),
            to: PlanNodeKey::Decision {
                key: decision_key.clone(),
            },
            kind: DependencyKind::Data,
        },
        DependencyEdge {
            from: PlanNodeKey::Decision {
                key: decision_key.clone(),
            },
            to: operation_node("false-branch"),
            kind: DependencyKind::BranchGuard,
        },
        DependencyEdge {
            from: PlanNodeKey::Decision { key: decision_key },
            to: operation_node("true-branch"),
            kind: DependencyKind::BranchGuard,
        },
        DependencyEdge {
            from: operation_node("false-branch"),
            to: PlanNodeKey::Merge {
                key: scoped("merge"),
            },
            kind: DependencyKind::BranchMerge,
        },
        DependencyEdge {
            from: operation_node("true-branch"),
            to: PlanNodeKey::Merge {
                key: scoped("merge"),
            },
            kind: DependencyKind::BranchMerge,
        },
        dependency("left", "true-branch"),
        DependencyEdge {
            from: PlanNodeKey::Merge {
                key: scoped("merge"),
            },
            to: operation_node("right"),
            kind: DependencyKind::RequiredSuccess,
        },
    ];
    if direct_order {
        fixture.effect_plan.edges.push(dependency("left", "right"));
    }
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
}

fn add_ungranted_resource(fixture: &mut PlanFixture) -> ResourceId {
    let resource = ResourceId {
        provider: fixture.effect_plan.current_revisions[0]
            .resource
            .provider
            .clone(),
        key: key("ungranted"),
    };
    let revision = ResourceRevision {
        resource: resource.clone(),
        revision: RevisionId(digest('a')),
    };
    fixture
        .binding_inputs
        .environment
        .resources
        .push(revision.clone());
    fixture
        .binding_inputs
        .desired_state
        .resources
        .push(revision.clone());
    fixture.binding_plan.resources.push(revision.clone());
    fixture.effect_plan.current_revisions.push(revision.clone());
    fixture.effect_plan.desired_revisions.push(revision);
    fixture
        .binding_inputs
        .environment
        .resources
        .sort_by(|left, right| compare_resource_ids(&left.resource, &right.resource));
    fixture
        .binding_inputs
        .desired_state
        .resources
        .sort_by(|left, right| compare_resource_ids(&left.resource, &right.resource));
    fixture
        .binding_plan
        .resources
        .sort_by(|left, right| compare_resource_ids(&left.resource, &right.resource));
    fixture
        .effect_plan
        .current_revisions
        .sort_by(|left, right| compare_resource_ids(&left.resource, &right.resource));
    fixture
        .effect_plan
        .desired_revisions
        .sort_by(|left, right| compare_resource_ids(&left.resource, &right.resource));
    resource
}

fn pin_primary_binding_to_pure_package(fixture: &mut PlanFixture) {
    let binding = &mut fixture.binding_plan.bindings[0];
    let artifact = binding.implementation.artifact.clone();
    let compose_entry = key("compose");
    let transition_entry = key("transition");
    let implementation = ProviderImplementation {
        interface: binding.interface.clone(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        implementation: ImplementationKind::PureComposition {
            compose_entry: compose_entry.clone(),
            transition_entry: transition_entry.clone(),
        },
        owns_resource_kinds: Vec::new(),
    };
    let descriptor = implementation
        .descriptor_digest()
        .expect("static pure implementation must have a descriptor");
    binding.implementation.descriptor = descriptor;
    binding.implementation.handler = None;
    fixture.binding_inputs.environment.providers[0].implementation = binding.implementation.clone();

    let package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::ContractsOnly,
        package: PackageSubject {
            name: key("pure-provider"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact.clone()],
        exports: vec![ExportDeclaration {
            name: key("provider"),
            interface: binding.interface.clone(),
            aggregation: None,
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::from([
            (compose_entry, artifact.clone()),
            (transition_entry, artifact),
        ]),
        implementation: PackageImplementation {
            providers: vec![implementation],
            handlers: BTreeMap::new(),
        },
        ownership: Vec::new(),
    };
    binding.provider_package = Some(
        package
            .content_digest()
            .expect("static pure package must have a content digest"),
    );
    fixture.binding_inputs.packages = vec![package];
    fixture.refresh_commitments();
}

fn contribution_fixture(schema: ValueSchema) -> PlanFixture {
    let mut fixture = plan_fixture();
    fixture.interfaces[0].interface.request = schema;
    fixture.refresh_interface();
    pin_primary_binding_to_pure_package(&mut fixture);

    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let aggregate = AggregateId {
        provider,
        group: key("aggregate"),
    };
    fixture.binding_inputs.packages[0].exports[0].aggregation = Some(AggregationContract {
        scope: AggregationScope::ProviderInstance,
        key: key("slot"),
        controller_group: aggregate.group.clone(),
        reject_slot_collisions: true,
        merge_contract: None,
    });
    fixture.binding_plan.bindings[0].caller_grant.contributions = vec![ContributionPermission {
        aggregate,
        slot: key("primary"),
    }];
    refresh_provider_package_pin(&mut fixture);
    fixture
}

fn install_contribution_value(fixture: &mut PlanFixture, value: AbilityValue) {
    let binding = &fixture.binding_plan.bindings[0];
    let permission = &binding.caller_grant.contributions[0];
    fixture.binding_inputs.desired_state.contributions = vec![Contribution {
        request: binding.request.clone(),
        aggregate: permission.aggregate.clone(),
        slot: permission.slot.clone(),
        grant: binding.id.clone(),
        value,
    }];
    fixture.refresh_commitments();
}

fn refresh_provider_package_pin(fixture: &mut PlanFixture) {
    fixture.binding_plan.bindings[0].provider_package = Some(
        fixture.binding_inputs.packages[0]
            .content_digest()
            .expect("static provider package must have a content digest"),
    );
    fixture.refresh_commitments();
}

fn advisory_requirement(
    interface: &aos_ability_model::InterfaceKey,
    fallback: AbilityValue,
) -> RequirementDeclaration {
    RequirementDeclaration {
        alias: key("advisory"),
        accepted_interfaces: vec![interface.clone()],
        methods: vec![key("observe")],
        guarantees: Vec::new(),
        strength: RequirementStrength::Advisory,
        fallback: Some(RequirementFallback {
            outputs: BTreeMap::from([(key("ready"), fallback)]),
        }),
    }
}

fn install_optional_resource_output(fixture: &mut PlanFixture) {
    fixture.interfaces[0].interface.outputs.insert(
        key("ready"),
        OutputDescriptor {
            schema: ValueSchema::Optional {
                value: Box::new(ValueSchema::ResourceReference),
            },
            phase: ValuePhase::Planning,
            visibility: ValueVisibility::Public,
            lifetime: ResourceLifetime::Instance,
        },
    );
}

fn install_projection_ports(
    fixture: &mut PlanFixture,
    schema: ValueSchema,
    lifetime: ResourceLifetime,
) {
    let descriptor = OutputDescriptor {
        schema,
        phase: ValuePhase::Planning,
        visibility: ValueVisibility::Public,
        lifetime,
    };
    fixture.interfaces[0].interface.outputs = BTreeMap::from([
        (key("first"), descriptor.clone()),
        (key("second"), descriptor.clone()),
        (key("third"), descriptor),
    ]);
    fixture.refresh_interface();
}

fn aggregate_projection(
    aggregate: &AggregateId,
    fixture: &PlanFixture,
    port: &str,
    target: &str,
) -> AggregateOutput {
    let interface = fixture.binding_plan.bindings[0].interface.clone();
    AggregateOutput {
        aggregate: aggregate.clone(),
        interface: interface.clone(),
        port: key(port),
        value: ValueExpression::AggregateOutput {
            reference: AggregateOutputReference {
                aggregate: aggregate.clone(),
                interface,
                port: key(target),
            },
        },
    }
}

fn operation_result(producer: &str, output: &str) -> OperationResultReference {
    OperationResultReference {
        producer: ResultProducerKey::Operation {
            key: scoped(producer),
        },
        output: key(output),
    }
}

fn grant_exclusive_access(fixture: &mut PlanFixture) {
    fixture.binding_plan.bindings[0].caller_grant.resources[0].access = AccessMode::ExclusiveWrite;
}

fn dependency(from: &str, to: &str) -> DependencyEdge {
    DependencyEdge {
        from: operation_node(from),
        to: operation_node(to),
        kind: DependencyKind::RequiredSuccess,
    }
}

fn operation_node(name: &str) -> PlanNodeKey {
    PlanNodeKey::Operation { key: scoped(name) }
}

fn scoped(name: &str) -> ScopedOperationKey {
    ScopedOperationKey {
        scope: ScopePath::root(),
        key: key(name),
    }
}

fn controller(fixture: &PlanFixture, group: &str) -> AggregateId {
    AggregateId {
        provider: fixture.effect_plan.current_revisions[0]
            .resource
            .provider
            .clone(),
        group: key(group),
    }
}

fn assert_diagnostic(fixture: PlanFixture, expected: DiagnosticCode) {
    let errors = fixture
        .validate()
        .expect_err("mutated fixture must fail closed");

    assert!(
        errors
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == expected),
        "expected {expected:?}, got {:?}",
        errors.diagnostics()
    );
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid static regression-test key")
}

fn digest(digit: char) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{}", digit.to_string().repeat(64)))
        .expect("valid static regression-test digest")
}
