//! Cross-stage semantic regression tests built from the shared checked-plan fixture.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::{AggregateInput, DesiredInstance, PackageSubject, ProviderState};
use aos_ability_model::identity::compare_instance_ids;
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, AggregateOutput, AggregateOutputReference,
    AggregateSlotPermission, AggregationContract, AggregationScope, ArtifactReference, BindingId,
    BranchMembership, ControllerAssignment, DecisionAlternative, DecisionNode, DecisionPredicate,
    DecisionSelector, DeclarationAuthority, DependencyEdge, DependencyKind, DiagnosticCode,
    ExportDeclaration, HandlerDescriptor, IncarnationId, InstanceId, LocalKey, MergeNode,
    MergedOutput, MethodReference, MethodSemantics, ModuleLocator, OperationResultReference,
    OutputDescriptor, PROVIDER_STATE_FORMAT_V1, PackageDocument, PackageImplementation,
    PlanNodeKey, ProviderAssignment, ProviderImplementation, ProviderStateFormat, RelativePath,
    RequiredFeature, RequirementDeclaration, RequirementFallback, RequirementStrength, ResourceId,
    ResourceLifetime, ResourcePermission, ResourceReference, ResourceRevision, ResultProducerKey,
    RevisionId, StringConstraint, ValueExpression, ValuePhase, ValueSchema, ValueVisibility,
    VersionedDocument, compare_edges, compare_operation_keys, compare_resource_ids,
};
use aos_contract::Sha256Digest;

use crate::test_support::{
    PlanFixture, checked_lifecycle_effect_plan, digest, key, operation_node, plan_fixture,
    planned_provider_chain_fixture, scoped, stateful_owner_plan_fixture,
};

#[test]
fn system_authored_consumer_requires_no_package_artifact() {
    let mut fixture = plan_fixture();
    let consumer = fixture.binding_plan.requests[0].id.consumer.clone();
    fixture.binding_inputs.desired_state.instances = vec![DesiredInstance {
        instance: consumer,
        authority: DeclarationAuthority::System,
        package: None,
        enabled: true,
        configuration: None,
    }];
    fixture.binding_inputs.desired_state.child_requests[0].authority = DeclarationAuthority::System;
    fixture.binding_plan.requests[0].authority = DeclarationAuthority::System;
    fixture.refresh_commitments();

    fixture
        .validate()
        .expect("system authority does not require a fabricated package artifact");
}

#[test]
fn request_authority_must_match_its_consumer_declaration() {
    let mut fixture = plan_fixture();
    let consumer = fixture.binding_plan.requests[0].id.consumer.clone();
    fixture.binding_inputs.desired_state.instances = vec![DesiredInstance {
        instance: consumer,
        authority: DeclarationAuthority::System,
        package: None,
        enabled: true,
        configuration: None,
    }];
    fixture.binding_inputs.desired_state.child_requests[0].authority =
        DeclarationAuthority::Operator;
    fixture.binding_plan.requests[0].authority = DeclarationAuthority::Operator;
    fixture.refresh_commitments();

    assert_diagnostic(fixture, DiagnosticCode::BindingPrincipalMismatch);
}

#[test]
fn pure_provider_package_authenticates_children_without_runtime_inventory() {
    let mut fixture = stateful_owner_plan_fixture();
    fixture.binding_inputs.environment.providers.clear();
    fixture.binding_inputs.desired_state.instances[0].authority = DeclarationAuthority::System;
    for request in &mut fixture.binding_inputs.desired_state.child_requests {
        if request.id.scope.as_slice().is_empty() {
            request.authority = DeclarationAuthority::System;
        }
    }
    fixture.binding_plan.requests = fixture.binding_inputs.desired_state.child_requests.clone();
    fixture.refresh_commitments();

    let mut unpinned = fixture.clone();
    unpinned.binding_inputs.desired_state.instances[0].package = None;
    unpinned.refresh_commitments();
    let unpinned_errors = unpinned
        .context
        .validate_binding_plan(unpinned.binding_plan, unpinned.binding_inputs)
        .expect_err("a package-authored child needs an exact provider package pin");
    assert!(
        unpinned_errors
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::BindingPrincipalMismatch)
    );

    let errors = fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect_err("terminal handler has no runtime inventory");
    assert!(
        errors
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code != DiagnosticCode::BindingPrincipalMismatch),
        "pure provider child lost its authenticated package author: {:?}",
        errors.diagnostics()
    );
}

#[test]
fn operation_rejects_caller_authored_method_semantics() {
    let checked = checked_lifecycle_effect_plan();
    let mut document = serde_json::to_value(checked.document()).unwrap();
    document["operations"][0]["semantics"] = serde_json::json!({
        "required_target_access": "read",
        "stops_provider": false,
    });

    assert!(
        serde_json::from_value::<aos_ability_model::EffectPlanDocument>(document).is_err(),
        "portable operations must derive semantics from their authenticated method"
    );
}

#[test]
fn desired_realization_must_match_the_selected_controller_schema() {
    let mut fixture = stateful_owner_plan_fixture();
    let resource = fixture.binding_inputs.desired_state.controllers[0]
        .resource
        .clone();
    let invalid = AbilityValue::new(serde_json::json!("not-a-boolean"))
        .expect("bounded invalid realization fixture");

    for revisions in [
        &mut fixture.binding_inputs.desired_state.resources,
        &mut fixture.binding_plan.resources,
    ] {
        for revision in revisions
            .iter_mut()
            .filter(|revision| revision.resource == resource)
        {
            revision.realization = invalid.clone();
        }
    }
    fixture.refresh_commitments();

    let errors = fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect_err("a realization outside the selected provider schema must fail closed");

    assert!(
        errors.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == DiagnosticCode::ValueTypeMismatch
                && diagnostic
                    .path
                    .first()
                    .is_some_and(|field| field == "desired_state")
                && diagnostic
                    .path
                    .last()
                    .is_some_and(|field| field == "realization")
                && diagnostic.resource.as_ref() == Some(&resource)
        }),
        "unexpected diagnostics: {:?}",
        errors.diagnostics()
    );
}

#[test]
fn published_read_only_resource_must_retain_its_exact_reference() {
    let mut fixture = stateful_owner_plan_fixture();
    let controlled = fixture.binding_inputs.desired_state.controllers[0]
        .resource
        .clone();
    let published = fixture
        .binding_inputs
        .desired_state
        .resources
        .iter_mut()
        .find(|resource| resource.resource != controlled)
        .expect("stateful fixture publishes one read-only resource");
    let mut value = published.value.as_json().clone();
    value["resource"]["key"] = serde_json::json!("substituted-resource");
    published.value = AbilityValue::new(value).expect("bounded mismatched reference");
    let published_resource = published.resource.clone();
    fixture.binding_plan.resources = fixture.binding_inputs.desired_state.resources.clone();
    fixture.refresh_commitments();

    let errors = fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect_err("a published reference for another resource must fail closed");

    assert!(errors.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::BindingInterfaceMismatch
            && diagnostic.resource.as_ref() == Some(&published_resource)
    }));
}

#[test]
fn published_read_only_resource_requires_its_exact_read_grant() {
    let mut fixture = stateful_owner_plan_fixture();
    let controlled = fixture.binding_inputs.desired_state.controllers[0]
        .resource
        .clone();
    let published = fixture
        .binding_inputs
        .desired_state
        .resources
        .iter()
        .find(|resource| resource.resource != controlled)
        .expect("stateful fixture publishes one read-only resource")
        .resource
        .clone();
    let binding = fixture
        .binding_plan
        .bindings
        .iter_mut()
        .find(|binding| {
            binding
                .caller_grant
                .resources
                .iter()
                .any(|permission| permission.resource == published)
        })
        .expect("published resource binding");
    binding
        .caller_grant
        .resources
        .retain(|permission| permission.resource != published);
    fixture.refresh_commitments();

    let errors = fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect_err("a publication without its exact read grant must fail closed");

    assert!(errors.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::ResourceScopeEscape
            && diagnostic.resource.as_ref() == Some(&published)
            && diagnostic
                .message
                .contains("exact request, method, and read resource grant")
    }));
}

#[test]
fn published_read_only_resource_rejects_ambiguous_provider_bindings() {
    let mut fixture = stateful_owner_plan_fixture();
    let controlled = fixture.binding_inputs.desired_state.controllers[0]
        .resource
        .clone();
    let published = fixture
        .binding_inputs
        .desired_state
        .resources
        .iter()
        .find(|resource| resource.resource != controlled)
        .expect("stateful fixture publishes one read-only resource")
        .resource
        .clone();
    let original_binding = fixture
        .binding_plan
        .bindings
        .iter()
        .find(|binding| {
            binding
                .caller_grant
                .resources
                .iter()
                .any(|permission| permission.resource == published)
        })
        .expect("published resource binding")
        .clone();
    let mut duplicate_request = fixture
        .binding_plan
        .requests
        .iter()
        .find(|request| request.id == original_binding.request)
        .expect("published resource request")
        .clone();
    duplicate_request.id.key = key("duplicate-publication");
    let mut duplicate_binding = original_binding;
    duplicate_binding.id = BindingId(key("duplicate-publication"));
    duplicate_binding.request = duplicate_request.id.clone();

    fixture
        .binding_inputs
        .desired_state
        .child_requests
        .push(duplicate_request.clone());
    fixture.binding_plan.requests.push(duplicate_request);
    fixture.binding_plan.bindings.push(duplicate_binding);
    fixture
        .binding_inputs
        .desired_state
        .child_requests
        .sort_by(|left, right| left.id.cmp(&right.id));
    fixture
        .binding_plan
        .requests
        .sort_by(|left, right| left.id.cmp(&right.id));
    fixture.binding_plan.bindings.sort_by(|left, right| {
        left.request
            .cmp(&right.request)
            .then_with(|| left.id.cmp(&right.id))
    });
    fixture.refresh_commitments();

    let errors = fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect_err("multiple candidate publication bindings must fail closed");

    assert!(errors.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::DuplicateIdentity
            && diagnostic.resource.as_ref() == Some(&published)
            && diagnostic
                .message
                .contains("multiple candidate provider bindings")
    }));
}

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
fn missing_edge_endpoint_does_not_create_a_spurious_cycle() {
    let mut fixture = plan_fixture();
    let destination = fixture.effect_plan.operations[0].key.clone();
    fixture.effect_plan.edges.push(DependencyEdge {
        from: operation_node("missing"),
        to: PlanNodeKey::Operation { key: destination },
        kind: DependencyKind::OrderingOnly,
    });

    let errors = fixture
        .validate()
        .expect_err("a missing edge endpoint must fail closed");
    let codes = errors
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect::<Vec<_>>();

    assert_eq!(codes, vec![DiagnosticCode::MissingReference]);
}

#[test]
fn read_only_primary_cannot_authorize_write_recovery() {
    let mut fixture = plan_fixture();
    let primary = fixture.interfaces[0].interface.methods[&key("observe")].clone();
    fixture.interfaces[0].interface.methods.insert(
        key("stop"),
        aos_ability_model::MethodDescriptor {
            description: "Describes this declaration.".to_string(),
            semantics: MethodSemantics::provider_stop(),
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
fn offline_effect_template_keeps_planned_provider_readiness_unresolved() {
    let mut fixture = plan_fixture();
    fixture.binding_inputs.environment.providers[0].state = ProviderState::Planned;
    fixture.binding_inputs.environment.providers[0].incarnation = None;
    fixture.refresh_commitments();

    let binding = fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect("planned provider binding remains structurally valid");
    let operation_binding = fixture.effect_plan.operations[0].binding.clone();
    let complete = fixture
        .context
        .validate_effect_plan(fixture.effect_plan.clone(), binding.clone())
        .expect_err("an executable plan needs provider readiness");
    assert!(
        complete
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::UnresolvedObligation)
    );

    let template = fixture
        .context
        .validate_effect_template(fixture.effect_plan.clone(), binding.clone())
        .expect("the offline graph is otherwise valid");
    assert_eq!(
        template.unresolved_provider_bindings(),
        &BTreeSet::from([operation_binding])
    );

    let mut invalid_graph = fixture.effect_plan;
    invalid_graph.operations[0].binding = BindingId(key("foreign"));
    let invalid = fixture
        .context
        .validate_effect_template(invalid_graph, binding)
        .expect_err("template validation must still reject foreign bindings");
    assert!(
        invalid
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::MissingReference)
    );
}

#[test]
fn exact_pure_provider_package_is_required() {
    let mut fixture = plan_fixture();
    pin_primary_binding_to_pure_package(&mut fixture);
    fixture.binding_plan.bindings[0].provider_package = Some(digest('f'));

    assert_diagnostic(fixture, DiagnosticCode::MissingReference);
}

#[test]
fn contracts_only_package_requires_the_effect_feature_for_a_terminal_handler() {
    let mut fixture = plan_fixture();
    pin_primary_binding_to_pure_package(&mut fixture);
    let package = &mut fixture.binding_inputs.packages[0];
    let artifact = package.implementation.providers[0].artifact.clone();
    let handler = key("terminal");
    package.implementation.providers[0].provider_module = None;
    package.implementation.providers[0].handler = Some(handler.clone());
    package.implementation.handlers.insert(
        handler.clone(),
        HandlerDescriptor {
            artifact,
            entry_point: "bin/terminal".to_string(),
            arguments: ValueSchema::Boolean,
            result: ValueSchema::Boolean,
        },
    );
    let descriptor = package.implementation.providers[0]
        .descriptor_digest()
        .expect("terminal implementation must digest");
    package.exports[0].implementation = descriptor;
    fixture.binding_plan.bindings[0].implementation.descriptor = descriptor;
    fixture.binding_plan.bindings[0].implementation.handler = Some(handler.clone());
    fixture.binding_inputs.environment.providers[0]
        .implementation
        .descriptor = descriptor;
    fixture.binding_inputs.environment.providers[0]
        .implementation
        .handler = Some(handler);
    fixture.binding_plan.bindings[0].provider_package = Some(
        package
            .content_digest()
            .expect("terminal package must digest"),
    );
    fixture.binding_inputs.packages[0]
        .required_features
        .retain(|feature| feature.as_str() != aos_ability_model::FEATURE_ABILITY_EFFECTS_V1);
    fixture.binding_plan.bindings[0].provider_package = Some(
        fixture.binding_inputs.packages[0]
            .content_digest()
            .expect("contracts-only package must digest"),
    );
    fixture.refresh_commitments();

    assert_diagnostic(fixture, DiagnosticCode::UnsupportedRequiredFeature);
}

#[test]
fn state_format_declaration_requires_its_package_feature() {
    let mut fixture = plan_fixture();
    configure_primary_state_format(&mut fixture, StateFormatFixture::MissingFeature);

    assert_diagnostic(fixture, DiagnosticCode::UnsupportedRequiredFeature);
}

#[test]
fn state_format_feature_requires_a_declaration() {
    let mut fixture = plan_fixture();
    configure_primary_state_format(&mut fixture, StateFormatFixture::MissingDeclaration);

    assert_diagnostic(fixture, DiagnosticCode::UnsupportedRequiredFeature);
}

#[test]
fn old_client_rejects_state_format_semantics_as_unknown() {
    let mut fixture = plan_fixture();
    configure_primary_state_format(&mut fixture, StateFormatFixture::Valid);
    fixture.context = crate::ValidationContext::new(BTreeSet::new(), fixture.interfaces.clone())
        .expect("fixture catalog accepts an empty feature set");

    assert_diagnostic(fixture, DiagnosticCode::UnsupportedRequiredFeature);
}

#[test]
fn package_feature_authenticates_state_format_semantics() {
    let mut fixture = plan_fixture();
    configure_primary_state_format(&mut fixture, StateFormatFixture::Valid);

    fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect("feature-aware validation accepts the exact state-format declaration");
}

#[test]
fn terminal_provider_cannot_declare_persistent_state_format() {
    let mut fixture = plan_fixture();
    configure_primary_state_format(&mut fixture, StateFormatFixture::TerminalProvider);

    assert_diagnostic(fixture, DiagnosticCode::UnsupportedRequiredFeature);
}

#[test]
fn state_format_requires_an_owned_resource_kind() {
    let mut fixture = plan_fixture();
    configure_primary_state_format(&mut fixture, StateFormatFixture::MissingOwnedResource);

    assert_diagnostic(fixture, DiagnosticCode::UnsupportedRequiredFeature);
}

#[test]
fn state_format_artifact_must_equal_the_provider_artifact() {
    let mut fixture = plan_fixture();
    configure_primary_state_format(&mut fixture, StateFormatFixture::DivergentArtifact);

    assert_diagnostic(fixture, DiagnosticCode::UnsupportedRequiredFeature);
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
fn package_requirement_does_not_activate_without_a_concrete_request() {
    let mut fixture = plan_fixture();
    pin_primary_binding_to_pure_package(&mut fixture);

    let mut external = fixture.binding_plan.bindings[0].interface.clone();
    external.name = aos_ability_model::InterfaceName::new("aos.test.external")
        .expect("external interface name");
    fixture.binding_inputs.packages[0].requirements = vec![RequirementDeclaration {
        description: "Available in another configuration.".to_string(),
        alias: key("external"),
        accepted_interfaces: vec![external.into()],
        methods: Vec::new(),
        guarantees: Vec::new(),
        strength: RequirementStrength::Required,
        fallback: None,
    }];
    refresh_provider_package_pin(&mut fixture);

    let provider = fixture.binding_plan.bindings[0].provider.clone();
    fixture
        .binding_inputs
        .desired_state
        .instances
        .push(DesiredInstance {
            instance: provider,
            authority: fixture.binding_plan.requests[0].authority.clone(),
            package: fixture.binding_plan.bindings[0].provider_package,
            enabled: true,
            configuration: None,
        });
    fixture.refresh_commitments();

    fixture
        .context
        .prepare_binding_candidates(
            &fixture.binding_inputs.environment,
            &fixture.binding_inputs.desired_state,
            &fixture.binding_inputs.packages,
        )
        .expect("unused package declarations do not become instance requests");
}

#[test]
fn environment_artifact_authorizes_an_exact_aggregate_input_reference() {
    let mut fixture = aggregate_input_fixture(ValueSchema::ArtifactReference);
    let artifact = ArtifactReference {
        content: digest('a'),
        store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-stage-tool".to_string(),
        nar_hash: digest('b'),
        closure: digest('c'),
    };
    let value = AbilityValue::new(serde_json::to_value(&artifact).expect("artifact reference"))
        .expect("bounded artifact reference");
    fixture.binding_inputs.desired_state.child_requests[0].parameters = value.clone();
    fixture.binding_plan.requests[0].parameters = value.clone();
    install_aggregate_input_value(&mut fixture, value);

    let error = fixture
        .context
        .validate_binding_plan(fixture.binding_plan.clone(), fixture.binding_inputs.clone())
        .expect_err("unretained artifact cannot be contributed");
    assert!(error.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::ResourceScopeEscape
            && diagnostic.message.contains("artifact reference is absent")
    }));

    fixture.binding_inputs.environment.artifacts.push(artifact);
    fixture.refresh_commitments();
    fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect("the committed environment inventory retains the exact artifact");
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
fn advisory_empty_resource_map_fallback_does_not_synthesize_authority() {
    let mut fixture = plan_fixture();
    install_resource_map_output(&mut fixture);
    fixture.refresh_interface();
    pin_primary_binding_to_pure_package(&mut fixture);
    fixture.binding_inputs.packages[0].requirements = vec![advisory_requirement(
        &fixture.binding_plan.bindings[0].interface,
        AbilityValue::new(serde_json::json!({})).expect("empty map is a bounded value"),
    )];

    fixture
        .context
        .prepare_binding_candidates(
            &fixture.binding_inputs.environment,
            &fixture.binding_inputs.desired_state,
            &fixture.binding_inputs.packages,
        )
        .expect("an empty resource-reference map carries no authority");
}

#[test]
fn advisory_populated_resource_map_fallback_cannot_synthesize_authority() {
    let mut fixture = plan_fixture();
    install_resource_map_output(&mut fixture);
    fixture.refresh_interface();
    pin_primary_binding_to_pure_package(&mut fixture);
    let reference = fixture.effect_plan.operations[0].target.clone();
    fixture.binding_inputs.packages[0].requirements = vec![advisory_requirement(
        &fixture.binding_plan.bindings[0].interface,
        AbilityValue::new(serde_json::json!({"resource": reference}))
            .expect("resource map is a bounded value"),
    )];

    let errors = fixture
        .context
        .prepare_binding_candidates(
            &fixture.binding_inputs.environment,
            &fixture.binding_inputs.desired_state,
            &fixture.binding_inputs.packages,
        )
        .expect_err("a populated resource-reference map creates authority");
    assert!(
        errors
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::ResourceScopeEscape)
    );
}

#[path = "regression_tests/projection.rs"]
mod projection;

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
        kind: fixture.binding_plan.bindings[0].interface.name.clone(),
        lifetime: aos_ability_model::ResourceLifetime::Instance,
        value: aos_ability_model::AbilityValue::new(serde_json::json!(true)).unwrap(),
        realization: AbilityValue::new(serde_json::Value::Null).unwrap(),
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
                    description: "Describes this declaration.".to_string(),
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
        kind: fixture.binding_plan.bindings[0].interface.name.clone(),
        lifetime: aos_ability_model::ResourceLifetime::Instance,
        value: aos_ability_model::AbilityValue::new(serde_json::json!(true)).unwrap(),
        realization: AbilityValue::new(serde_json::Value::Null).unwrap(),
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
    let effect_features = BTreeSet::from([
        RequiredFeature::new("abilities-v1").expect("abilities feature"),
        RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
            .expect("effect feature"),
    ]);
    fixture.context =
        crate::ValidationContext::new(effect_features.clone(), fixture.interfaces.clone())
            .expect("fixture catalog accepts effect semantics");

    let binding = &mut fixture.binding_plan.bindings[0];
    let artifact = binding.implementation.artifact.clone();
    let implementation = ProviderImplementation {
        name: LocalKey::new("pure").expect("valid implementation name"),
        description: "Pure test implementation.".to_string(),
        interface: binding.interface.clone(),
        methods: Vec::new(),
        guarantees: Vec::new(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        desired_schema: None,
        composition_schema: None,
        provider_module: Some(ModuleLocator {
            artifact: artifact.clone(),
            path: RelativePath::new("default.nix").expect("valid module path"),
        }),
        handler: None,
        owns_resource_kinds: Vec::new(),
        state_format: None,
    };
    let descriptor = implementation
        .descriptor_digest()
        .expect("static pure implementation must have a descriptor");
    binding.implementation.descriptor = descriptor;
    binding.implementation.handler = None;
    fixture.binding_inputs.environment.providers[0].implementation = binding.implementation.clone();

    let package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: effect_features.into_iter().collect(),
        package: PackageSubject {
            name: key("pure-provider"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.identity(),
        },
        artifacts: vec![artifact.clone()],
        interfaces: Default::default(),
        guarantees: Default::default(),
        package_module: Some(aos_ability_model::ModuleLocator {
            artifact: artifact.clone(),
            path: aos_ability_model::RelativePath::new("module.nix")
                .expect("fixture package module path is valid"),
        }),
        option_declarations: Vec::new(),
        exports: vec![ExportDeclaration {
            name: key("provider"),
            interface: binding.interface.clone(),
            implementation_name: key("provider"),
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        implementation: PackageImplementation {
            providers: vec![implementation],
            handlers: BTreeMap::new(),
        },
        qualification: aos_ability_model::PackageQualification::default(),
    };
    binding.provider_package = Some(
        package
            .content_digest()
            .expect("static pure package must have a content digest"),
    );
    fixture.binding_inputs.packages = vec![package];
    fixture.refresh_commitments();
}

#[derive(Clone, Copy)]
enum StateFormatFixture {
    DivergentArtifact,
    MissingDeclaration,
    MissingFeature,
    MissingOwnedResource,
    TerminalProvider,
    Valid,
}

fn configure_primary_state_format(fixture: &mut PlanFixture, mode: StateFormatFixture) {
    pin_primary_binding_to_pure_package(fixture);

    let feature = RequiredFeature::new(PROVIDER_STATE_FORMAT_V1)
        .expect("static provider state-format feature");
    if !matches!(mode, StateFormatFixture::MissingFeature) {
        fixture.binding_inputs.packages[0]
            .required_features
            .push(feature.clone());
    }
    let supported_features = BTreeSet::from([
        RequiredFeature::new("abilities-v1").expect("abilities feature"),
        RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
            .expect("effect feature"),
        feature,
    ]);
    fixture.context = crate::ValidationContext::new(supported_features, fixture.interfaces.clone())
        .expect("fixture catalog accepts the state-format feature");

    let package = &mut fixture.binding_inputs.packages[0];
    if !matches!(mode, StateFormatFixture::MissingDeclaration) {
        let implementation = &mut package.implementation.providers[0];
        implementation.owns_resource_kinds =
            if matches!(mode, StateFormatFixture::MissingOwnedResource) {
                Vec::new()
            } else {
                vec![implementation.interface.name.clone()]
            };
        implementation.state_format = Some(ProviderStateFormat {
            descriptor: Sha256Digest::of_bytes("state-format-v1"),
            artifact: if matches!(mode, StateFormatFixture::DivergentArtifact) {
                ArtifactReference {
                    content: Sha256Digest::of_bytes("divergent state-format content"),
                    store_path:
                        "/nix/store/00000000000000000000000000000000-divergent-state-format"
                            .to_string(),
                    nar_hash: Sha256Digest::of_bytes("divergent state-format nar"),
                    closure: Sha256Digest::of_bytes("divergent state-format closure"),
                }
            } else {
                implementation.artifact.clone()
            },
        });
        if matches!(mode, StateFormatFixture::TerminalProvider) {
            let handler = key("stateful-terminal");
            implementation.provider_module = None;
            implementation.handler = Some(handler.clone());
            implementation
                .state_format
                .as_mut()
                .expect("state format")
                .artifact = implementation.artifact.clone();
            package.implementation.handlers.insert(
                handler,
                HandlerDescriptor {
                    artifact: implementation.artifact.clone(),
                    entry_point: "bin/stateful-terminal".to_string(),
                    arguments: ValueSchema::Boolean,
                    result: ValueSchema::Boolean,
                },
            );
        }
        let implementation_descriptor = implementation
            .descriptor_digest()
            .expect("stateful fixture implementation must digest");
        package.exports[0].implementation = implementation_descriptor;
        fixture.binding_plan.bindings[0].implementation.descriptor = implementation_descriptor;
        fixture.binding_inputs.environment.providers[0]
            .implementation
            .descriptor = implementation_descriptor;
    }

    let package_digest = package
        .content_digest()
        .expect("stateful fixture package must digest");
    fixture.binding_plan.bindings[0].provider_package = Some(package_digest);
    fixture.refresh_commitments();
}

fn aggregate_input_fixture(schema: ValueSchema) -> PlanFixture {
    let mut fixture = plan_fixture();
    fixture.interfaces[0].interface.request = schema;
    fixture.interfaces[0].interface.aggregation = AggregationContract {
        scope: AggregationScope::ProviderInstance,
        key: key("slot"),
        controller_group: key("aggregate"),
        reject_slot_collisions: true,
        merge_contract: None,
    };
    fixture.refresh_interface();
    pin_primary_binding_to_pure_package(&mut fixture);

    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let aggregate = AggregateId {
        provider,
        group: key("aggregate"),
    };
    fixture.binding_plan.bindings[0]
        .caller_grant
        .aggregate_slots = vec![AggregateSlotPermission {
        aggregate,
        slot: key("primary"),
    }];
    refresh_provider_package_pin(&mut fixture);
    fixture
}

fn install_aggregate_input_value(fixture: &mut PlanFixture, value: AbilityValue) {
    let binding = &fixture.binding_plan.bindings[0];
    let permission = &binding.caller_grant.aggregate_slots[0];
    fixture.binding_inputs.desired_state.aggregate_inputs = vec![AggregateInput {
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
        description: "Describes this declaration.".to_string(),
        alias: key("advisory"),
        accepted_interfaces: vec![interface.clone().into()],
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
            description: "Describes this declaration.".to_string(),
            schema: ValueSchema::Optional {
                value: Box::new(ValueSchema::ResourceReference),
            },
            phase: ValuePhase::Planning,
            visibility: ValueVisibility::Protected,
            lifetime: ResourceLifetime::Instance,
        },
    );
}

fn install_resource_map_output(fixture: &mut PlanFixture) {
    fixture.interfaces[0].interface.outputs.insert(
        key("ready"),
        OutputDescriptor {
            description: "Describes this declaration.".to_string(),
            schema: ValueSchema::Map {
                key: StringConstraint {
                    max_length: 128,
                    syntax: None,
                },
                value: Box::new(ValueSchema::ResourceReference),
                max_entries: 8,
            },
            phase: ValuePhase::Planning,
            visibility: ValueVisibility::Protected,
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
        description: "Describes this declaration.".to_string(),
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

fn nested_operation_result_fixture(producer_schema: ValueSchema) -> PlanFixture {
    let mut fixture = plan_fixture();
    let parameters = ValueSchema::Record {
        fields: BTreeMap::from([(key("nested"), ValueSchema::Boolean)]),
        optional_fields: Vec::new(),
    };
    let method = fixture.interfaces[0]
        .interface
        .methods
        .get_mut(&key("observe"))
        .expect("fixture observe method");
    method.parameters = parameters;
    method
        .outputs
        .get_mut(&key("ready"))
        .expect("fixture ready output")
        .schema = producer_schema;
    fixture.refresh_interface();

    let producer = &mut fixture.effect_plan.operations[0];
    producer.inputs = ValueExpression::Literal {
        value: AbilityValue::new(serde_json::json!({"nested": true}))
            .expect("fixture producer input is bounded"),
    };
    let mut consumer = producer.clone();
    consumer.key = scoped("consume");
    consumer.inputs = ValueExpression::Object {
        fields: BTreeMap::from([(
            "nested".to_string(),
            ValueExpression::OperationResult {
                reference: operation_result("observe", "ready"),
            },
        )]),
    };
    fixture.effect_plan.operations.push(consumer);
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.edges.push(DependencyEdge {
        from: operation_node("observe"),
        to: operation_node("consume"),
        kind: DependencyKind::Data,
    });
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();

    fixture
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
