//! Cross-stage semantic regression tests built from the shared checked-plan fixture.

use aos_ability_model::document::ProviderState;
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, BindingId, BranchMembership, ControllerAssignment,
    DecisionAlternative, DecisionNode, DecisionPredicate, DecisionSelector, DependencyEdge,
    DependencyKind, DiagnosticCode, IncarnationId, LocalKey, MergeNode, MergedOutput,
    MethodReference, OperationFamily, OperationResultReference, OutputDescriptor, PlanNodeKey,
    ProviderAssignment, ResourceId, ResourceLifetime, ResourcePermission, ResourceReference,
    ResourceRevision, ResultProducerKey, RevisionId, ScopePath, ScopedOperationKey, ServiceAction,
    ValueExpression, ValuePhase, ValueSchema, ValueVisibility, compare_edges,
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
    fixture.binding_inputs.environment.providers[0]
        .implementation
        .handler = None;
    fixture.binding_plan.bindings[0].implementation.handler = None;
    fixture.refresh_commitments();

    assert_diagnostic(fixture, DiagnosticCode::UnresolvedObligation);
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
        lifetime: ResourceLifetime::Attempt,
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
