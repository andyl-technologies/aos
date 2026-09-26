//! Tests for transition authority validation.

use aos_ability_model::document::{DesiredInstance, PackageSubject};
use aos_ability_model::identity::compare_request_ids;
use aos_ability_model::{
    AbilityValue, AccessMode, AggregateId, AggregateSlotPermission, BindingRequest,
    DeclarationAuthority, ExportDeclaration, HandlerDescriptor, InterfaceName, LocalKey,
    ModuleLocator, PackageImplementation, ProviderAdoptionAuthorization, ProviderImplementation,
    ProviderImplementationReference, ProviderStateFormat, RelativePath, RequiredFeature,
    ResourcePermission, ScopePath, TeardownBindingAuthorization, ValueSchema,
};

use super::*;

#[derive(Clone)]
struct AuthorityFixture {
    context: ValidationContext,
    desired: CheckedBindingPlan,
    current: CheckedBindingPlan,
    document: TransitionAuthorizationDocument,
}

impl AuthorityFixture {
    fn validate(&self) -> Result<CheckedTransitionAuthority, TransitionAuthorityError> {
        let expected_digest = self
            .document
            .content_digest()
            .expect("test authorization must digest");
        self.context.validate_transition_authority(
            self.document.clone(),
            TransitionAuthorityInputs {
                expected_digest,
                desired_planning: self.document.desired_planning,
                current_planning: self.document.current_planning,
                authorization_policy_revision: self.document.authorization_policy_revision,
                desired: &self.desired,
                current: &self.current,
            },
        )
    }
}

#[test]
fn current_policy_can_newly_grant_stop_for_exact_prior_selection() {
    let fixture = authority_fixture();
    let checked = fixture
        .validate()
        .expect("fresh Stop authority need not be a subset of historical Start authority");
    let teardown = &checked.document().teardown_bindings[0].binding;

    assert_eq!(teardown.caller_grant.methods, vec![key("stop")]);
    assert_eq!(checked.bindings().last(), Some(teardown));
}

#[test]
fn superseded_policy_revision_fails_closed() {
    let mut fixture = authority_fixture();
    fixture.document.authorization_policy_revision =
        RevisionId(Sha256Digest::of_bytes("superseded transition policy"));

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Commitment(_))
    ));
}

#[test]
fn changed_prior_selection_fails_closed() {
    let mut fixture = authority_fixture();
    fixture.document.teardown_bindings[0]
        .binding
        .implementation
        .descriptor = Sha256Digest::of_bytes("different implementation");

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Binding { .. })
    ));
}

#[test]
fn every_prior_binding_identity_is_reserved() {
    let mut fixture = authority_fixture();
    fixture.document.teardown_bindings[0].binding.id = fixture.current.bindings()[0].id.clone();

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Binding { .. })
    ));
}

#[test]
fn one_prior_source_cannot_be_reauthorized_twice() {
    let mut fixture = authority_fixture();
    let mut duplicate = fixture.document.teardown_bindings[0].clone();
    duplicate.binding.id = BindingId(key("zz-second-teardown"));
    duplicate.request.id.key = key("zz-second-request");
    duplicate.binding.request = duplicate.request.id.clone();
    fixture.document.teardown_bindings.push(duplicate);

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Binding { .. })
    ));
}

#[test]
fn teardown_cannot_adopt_aggregate_ownership() {
    let mut fixture = authority_fixture();
    let provider = fixture.document.teardown_bindings[0]
        .binding
        .provider
        .clone();
    fixture.document.teardown_bindings[0]
        .binding
        .caller_grant
        .aggregate_slots
        .push(AggregateSlotPermission {
            aggregate: AggregateId {
                provider,
                group: key("adopted"),
            },
            slot: key("owner"),
        });

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Binding { .. })
    ));
}

#[test]
fn teardown_resource_must_have_belonged_to_exact_source_grant() {
    let mut fixture = authority_fixture();
    let mut resource = fixture.current.document.resources[0].resource.clone();
    resource.key = key("newly-desired");
    fixture.document.teardown_bindings[0]
        .binding
        .caller_grant
        .resources = vec![ResourcePermission {
        resource,
        access: AccessMode::ExclusiveWrite,
        operations: vec![key("stop")],
    }];

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Binding { .. })
    ));
}

#[test]
fn stale_teardown_terminal_fails_closed() {
    let mut fixture = authority_fixture();
    fixture.desired.inputs.environment.providers[0].state = ProviderState::Stale;

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Binding { .. })
    ));
}

#[test]
fn absent_teardown_terminal_fails_closed() {
    let mut fixture = authority_fixture();
    fixture.desired.inputs.environment.providers.clear();

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Binding { .. })
    ));
}

#[test]
fn planned_teardown_terminal_requires_later_readiness_qualification() {
    let mut fixture = authority_fixture();
    fixture.desired.inputs.environment.providers[0].state = ProviderState::Planned;
    fixture.desired.inputs.environment.providers[0].incarnation = None;
    let checked = fixture
        .validate()
        .expect("consistent planned inventory may be sealed for readiness planning");

    assert!(!checked.binding_plan().is_executable());
    assert!(
        checked
            .binding_plan()
            .planned_providers()
            .contains(&fixture.document.teardown_bindings[0].binding.provider)
    );
}

#[test]
fn different_prior_platform_fails_closed() {
    let mut fixture = authority_fixture();
    fixture.current.inputs.environment.platform.architecture = key("aarch64");

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Commitment(_))
    ));
}

#[test]
fn persistent_delete_method_requires_separate_authorization_type() {
    let mut fixture = authority_fixture();
    let selected_interface = fixture.document.teardown_bindings[0]
        .binding
        .interface
        .clone();
    let mut interface = fixture
        .context
        .interfaces()
        .get(&selected_interface)
        .expect("fixture interface")
        .clone();
    let delete_method = interface
        .interface
        .methods
        .keys()
        .next()
        .expect("fixture interface method")
        .clone();
    interface
        .interface
        .methods
        .get_mut(&delete_method)
        .expect("fixture delete method")
        .semantics = aos_ability_model::MethodSemantics::provider_stop();
    interface.interface.lifecycle.persistent_delete_method = Some(delete_method.clone());
    let interface_key = interface
        .interface_key()
        .expect("mutated interface must digest");
    fixture.context = ValidationContext::new(BTreeSet::new(), [interface])
        .expect("mutated interface must validate");
    for plan in [&mut fixture.desired, &mut fixture.current] {
        plan.document.bindings[0].interface = interface_key.clone();
        plan.inputs.environment.providers[0].interface = interface_key.clone();
    }
    fixture.document.teardown_bindings[0].binding.interface = interface_key;
    fixture.document.teardown_bindings[0]
        .binding
        .caller_grant
        .methods = vec![delete_method.clone()];
    fixture.document.teardown_bindings[0]
        .binding
        .caller_grant
        .resources[0]
        .operations = vec![delete_method];

    assert!(matches!(
        fixture.validate(),
        Err(TransitionAuthorityError::Binding { .. })
    ));
}

#[test]
fn typed_persistent_deletion_requires_exact_exclusive_grant() {
    let mut fixture = authority_fixture();
    let selected_interface = fixture.document.teardown_bindings[0]
        .binding
        .interface
        .clone();
    let mut interface = fixture
        .context
        .interfaces()
        .get(&selected_interface)
        .expect("fixture interface")
        .clone();
    let delete_method = interface
        .interface
        .methods
        .keys()
        .next()
        .expect("fixture interface method")
        .clone();
    interface
        .interface
        .methods
        .get_mut(&delete_method)
        .expect("fixture delete method")
        .semantics = aos_ability_model::MethodSemantics::provider_stop();
    interface.interface.lifecycle.persistent_delete_method = Some(delete_method.clone());
    let interface_key = interface
        .interface_key()
        .expect("mutated interface must digest");
    fixture.context = ValidationContext::new(BTreeSet::new(), [interface])
        .expect("mutated interface must validate");

    let source_binding = fixture.document.teardown_bindings[0].source_binding.clone();
    let transition_binding = fixture.document.teardown_bindings[0].binding.id.clone();
    let resource = fixture.current.document.resources[0].resource.clone();
    fixture.current.document.bindings[0].lifetime = ResourceLifetime::Persistent;
    fixture.current.inputs.desired_state.resources[0].lifetime = ResourceLifetime::Persistent;
    fixture.document.teardown_bindings[0].binding.interface = interface_key;
    fixture.document.teardown_bindings[0].binding.lifetime = ResourceLifetime::Persistent;
    fixture.document.teardown_bindings[0]
        .binding
        .caller_grant
        .methods = vec![delete_method.clone()];
    fixture.document.teardown_bindings[0]
        .binding
        .caller_grant
        .resources[0]
        .operations = vec![delete_method.clone()];
    let deletion = aos_ability_model::PersistentResourceDeletionAuthorization {
        source_binding,
        binding: transition_binding,
        resource,
        method: delete_method,
    };
    fixture.document.persistent_deletions = vec![deletion.clone()];
    let inputs = TransitionAuthorityInputs {
        expected_digest: Sha256Digest::of_bytes("unused test digest"),
        desired_planning: fixture.document.desired_planning,
        current_planning: fixture.document.current_planning,
        authorization_policy_revision: fixture.document.authorization_policy_revision,
        desired: &fixture.desired,
        current: &fixture.current,
    };

    validate_persistent_deletion(&fixture.context, &fixture.document, &inputs, &deletion)
        .expect("exact typed persistent deletion must validate");
    drop(inputs);

    fixture.document.teardown_bindings[0]
        .binding
        .caller_grant
        .resources[0]
        .access = AccessMode::SharedWrite;
    let inputs = TransitionAuthorityInputs {
        expected_digest: Sha256Digest::of_bytes("unused test digest"),
        desired_planning: fixture.document.desired_planning,
        current_planning: fixture.document.current_planning,
        authorization_policy_revision: fixture.document.authorization_policy_revision,
        desired: &fixture.desired,
        current: &fixture.current,
    };
    let error =
        validate_persistent_deletion(&fixture.context, &fixture.document, &inputs, &deletion)
            .expect_err("persistent deletion without exclusive authority must fail");
    assert!(matches!(error, TransitionAuthorityError::Binding { .. }));
}

#[test]
fn combined_transition_projection_enforces_the_v1_request_limit() {
    let fixture = authority_fixture();
    let mut projection = fixture.desired.document().clone();
    let request = projection.requests[0].clone();
    projection.requests =
        vec![request; aos_ability_model::ABILITY_LIMITS_V1.max_graph_nodes as usize];
    projection
        .requests
        .push(fixture.document.teardown_bindings[0].request.clone());

    assert!(matches!(
        validate_projection_bounds(&projection, fixture.desired.packages()),
        Err(TransitionAuthorityError::InvalidDocument(_))
    ));
}

#[test]
fn nested_adoption_request_scope_belongs_to_its_owner() {
    let fixture = authority_fixture();
    let owner = fixture.current.document.requests[0].id.consumer.clone();
    let nested_scope = ScopePath::new(vec![owner.key.clone(), key("nested")])
        .expect("nested owner scope must be valid");

    assert!(scope_belongs_to_owner(&nested_scope, &owner));
}

#[test]
fn adoption_request_scope_rejects_a_foreign_first_component() {
    let fixture = authority_fixture();
    let owner = fixture.current.document.requests[0].id.consumer.clone();
    let foreign_scope = ScopePath::new(vec![key("foreign"), owner.key.clone()])
        .expect("foreign test scope must be valid");

    assert!(!scope_belongs_to_owner(&foreign_scope, &owner));
}

#[test]
fn enabled_multi_export_package_cannot_substitute_an_unselected_owner() {
    let (_, plan, endpoint) = multi_export_owner_fixture(false);

    assert!(plan.desired_state().instances.iter().any(|instance| {
        instance.enabled
            && instance.instance == endpoint.provider
            && instance.package == Some(endpoint.package)
    }));
    assert!(!owner_implementation_is_selected(&plan, &endpoint));
}

#[test]
fn stateful_owner_fixture_selects_the_exact_export() {
    let (_, plan, endpoint) = multi_export_owner_fixture(true);

    assert!(owner_implementation_is_selected(&plan, &endpoint));
}

#[test]
fn exact_compatible_provider_adoption_is_valid() {
    adoption_authority_fixture()
        .validate()
        .expect("exact compatible adoption authority");
}

#[test]
fn byte_identical_provider_adoption_endpoints_are_rejected() {
    let mut fixture = adoption_authority_fixture();
    fixture.document.provider_adoptions[0].candidate =
        fixture.document.provider_adoptions[0].source.clone();

    assert_invalid_adoption(fixture, "byte-identical endpoints");
}

#[test]
fn binding_and_method_only_provider_adoption_is_rejected() {
    let mut fixture = adoption_authority_fixture();
    let candidate = fixture.document.provider_adoptions[0].candidate.clone();
    let source = &mut fixture.document.provider_adoptions[0].source;
    *source = candidate;
    source.handler_binding = BindingId(key("plan-local-source-binding"));
    source.handler_method = key("plan-local-source-method");

    let error = fixture
        .validate()
        .expect_err("plan-local endpoint fields cannot create durable adoption authority");
    assert!(
        error
            .to_string()
            .contains("does not change durable owner or handler authority"),
        "{error}"
    );
}

#[test]
fn provider_adoption_entries_and_feature_are_coupled() {
    let mut missing_feature = adoption_authority_fixture();
    missing_feature.document.required_features.clear();
    assert_invalid_adoption(missing_feature, "missing adoption feature");

    let mut missing_entry = adoption_authority_fixture();
    missing_entry.document.provider_adoptions.clear();
    assert_invalid_adoption(missing_entry, "adoption feature without entries");
}

#[test]
fn provider_adoptions_require_unique_canonical_resource_order() {
    let mut duplicate = adoption_authority_fixture();
    duplicate
        .document
        .provider_adoptions
        .push(duplicate.document.provider_adoptions[0].clone());
    assert_invalid_adoption(duplicate, "duplicate adoption resource");

    let mut noncanonical = adoption_authority_fixture();
    let mut earlier = noncanonical.document.provider_adoptions[0].clone();
    earlier.resource.key = key("aaa-adoption-resource");
    let mut later = noncanonical.document.provider_adoptions[0].clone();
    later.resource.key = key("zzz-adoption-resource");
    noncanonical.document.provider_adoptions = vec![later, earlier];
    assert_invalid_adoption(noncanonical, "noncanonical adoption resource order");
}

#[test]
fn checked_handler_incarnation_only_adoption_is_not_a_durable_change() {
    let mut fixture = adoption_authority_fixture();
    fixture.current = fixture.desired.clone();
    let candidate = fixture.document.provider_adoptions[0].candidate.clone();
    let source_incarnation = aos_ability_model::IncarnationId::new("prior-checked-handler")
        .expect("valid prior incarnation");
    let source_inventory = fixture
        .current
        .inputs
        .environment
        .providers
        .iter_mut()
        .find(|provider| {
            provider.provider == candidate.handler_provider
                && provider.interface == candidate.handler_interface
                && provider.implementation == candidate.handler_implementation
        })
        .expect("source handler inventory");
    source_inventory.incarnation = Some(source_incarnation.clone());

    let source = &mut fixture.document.provider_adoptions[0].source;
    *source = candidate.clone();
    source.handler_incarnation = source_incarnation;
    assert_ne!(*source, candidate);

    assert_invalid_adoption(
        fixture,
        "does not change durable owner or handler authority",
    );
}

#[test]
fn adoption_authority_requires_its_exact_authenticated_digest() {
    let fixture = adoption_authority_fixture();
    let error = fixture
        .context
        .validate_transition_authority(
            fixture.document.clone(),
            TransitionAuthorityInputs {
                expected_digest: Sha256Digest::of_bytes("wrong adoption authority digest"),
                desired_planning: fixture.document.desired_planning,
                current_planning: fixture.document.current_planning,
                authorization_policy_revision: fixture.document.authorization_policy_revision,
                desired: &fixture.desired,
                current: &fixture.current,
            },
        )
        .expect_err("a mismatched authenticated digest must fail");

    assert!(matches!(error, TransitionAuthorityError::Commitment(_)));
}

#[test]
fn stale_source_adoption_endpoint_fields_fail_closed() {
    assert_endpoint_mutations_fail(AdoptionSide::Source);
}

#[test]
fn stale_candidate_adoption_endpoint_fields_fail_closed() {
    assert_endpoint_mutations_fail(AdoptionSide::Candidate);
}

#[test]
fn stale_adoption_resource_and_kind_fail_closed() {
    let mut stale_resource = adoption_authority_fixture();
    stale_resource.document.provider_adoptions[0].resource.key = key("stale-resource");
    assert_invalid_adoption(stale_resource, "stale resource");

    let mut stale_kind = adoption_authority_fixture();
    stale_kind.document.provider_adoptions[0]
        .resource_interface
        .descriptor = Sha256Digest::of_bytes("stale resource kind");
    assert_invalid_adoption(stale_kind, "stale resource kind");
}

#[test]
fn stale_source_and_candidate_grants_fail_closed() {
    let mut stale_source = adoption_authority_fixture();
    let source_binding = stale_source.document.provider_adoptions[0]
        .source
        .handler_binding
        .clone();
    let source_index = stale_source.current.binding_indices[&source_binding];
    stale_source.current.document.bindings[source_index]
        .caller_grant
        .resources
        .clear();
    assert_invalid_adoption(stale_source, "stale source grant");

    let mut stale_candidate = adoption_authority_fixture();
    let candidate_binding = stale_candidate.document.provider_adoptions[0]
        .candidate
        .handler_binding
        .clone();
    let candidate_index = stale_candidate.desired.binding_indices[&candidate_binding];
    stale_candidate.desired.document.bindings[candidate_index]
        .caller_grant
        .resources
        .clear();
    assert_invalid_adoption(stale_candidate, "stale candidate grant");
}

#[test]
fn revoked_or_unavailable_adoption_assignment_fails_closed() {
    for side in [AdoptionSide::Source, AdoptionSide::Candidate] {
        let mut revoked = adoption_authority_fixture();
        adoption_plan_mut(&mut revoked, side)
            .inputs
            .environment
            .providers
            .clear();
        assert_invalid_adoption(revoked, "revoked assignment");

        let mut unavailable = adoption_authority_fixture();
        adoption_plan_mut(&mut unavailable, side)
            .inputs
            .environment
            .providers[0]
            .state = ProviderState::Unavailable;
        assert_invalid_adoption(unavailable, "unavailable assignment");
    }
}

#[derive(Clone, Copy)]
enum AdoptionSide {
    Source,
    Candidate,
}

fn assert_endpoint_mutations_fail(side: AdoptionSide) {
    type Mutator = fn(&mut ProviderAdoptionEndpoint);

    let mutations: [(&str, Mutator); 13] = [
        ("owner provider", |endpoint| {
            endpoint.provider.key = key("stale-owner-provider");
        }),
        ("package", |endpoint| {
            endpoint.package = Sha256Digest::of_bytes("stale owner package");
        }),
        ("owner interface", |endpoint| {
            endpoint.interface.descriptor = Sha256Digest::of_bytes("stale owner interface");
        }),
        ("owner implementation", |endpoint| {
            endpoint.implementation.descriptor =
                Sha256Digest::of_bytes("stale owner implementation");
        }),
        ("state-format artifact", |endpoint| {
            endpoint.state_format.artifact.content =
                Sha256Digest::of_bytes("unauthenticated state-format artifact");
        }),
        ("state-format descriptor", |endpoint| {
            endpoint.state_format.descriptor =
                Sha256Digest::of_bytes("stale state-format descriptor");
        }),
        ("handler binding", |endpoint| {
            endpoint.handler_binding = BindingId(key("stale-handler-binding"));
        }),
        ("handler method", |endpoint| {
            endpoint.handler_method = key("stale-handler-method");
        }),
        ("handler provider", |endpoint| {
            endpoint.handler_provider.key = key("stale-handler-provider");
        }),
        ("handler incarnation", |endpoint| {
            endpoint.handler_incarnation =
                aos_ability_model::IncarnationId::new("stale-handler-incarnation")
                    .expect("valid incarnation");
        }),
        ("handler interface", |endpoint| {
            endpoint.handler_interface.descriptor =
                Sha256Digest::of_bytes("stale handler interface");
        }),
        ("handler implementation", |endpoint| {
            endpoint.handler_implementation.descriptor =
                Sha256Digest::of_bytes("stale handler implementation");
        }),
        ("handler package", |endpoint| {
            endpoint.handler_package = Sha256Digest::of_bytes("stale handler package");
        }),
    ];

    for (label, mutate) in mutations {
        let mut fixture = adoption_authority_fixture();
        mutate(adoption_endpoint_mut(&mut fixture, side));
        assert_invalid_adoption(fixture, label);
    }
}

fn adoption_endpoint_mut(
    fixture: &mut AuthorityFixture,
    side: AdoptionSide,
) -> &mut ProviderAdoptionEndpoint {
    let adoption = &mut fixture.document.provider_adoptions[0];

    match side {
        AdoptionSide::Source => &mut adoption.source,
        AdoptionSide::Candidate => &mut adoption.candidate,
    }
}

fn adoption_plan_mut(
    fixture: &mut AuthorityFixture,
    side: AdoptionSide,
) -> &mut CheckedBindingPlan {
    match side {
        AdoptionSide::Source => &mut fixture.current,
        AdoptionSide::Candidate => &mut fixture.desired,
    }
}

fn assert_invalid_adoption(fixture: AuthorityFixture, label: &str) {
    assert!(
        matches!(
            fixture.validate(),
            Err(TransitionAuthorityError::InvalidDocument(_))
        ),
        "{label} unexpectedly passed adoption authority validation"
    );
}

fn adoption_authority_fixture() -> AuthorityFixture {
    let (context, desired, candidate) = multi_export_owner_fixture(true);
    let mut current = desired.clone();
    current.inputs.packages[0].package.version = "0.9.0".to_string();
    let source_package = current.inputs.packages[0]
        .content_digest()
        .expect("source package digest");
    for binding in &mut current.document.bindings {
        binding.provider_package = Some(source_package);
    }
    current.inputs.desired_state.instances[0].package = Some(source_package);
    current.document.desired_state = current
        .inputs
        .desired_state
        .content_digest()
        .expect("source desired-state digest");
    current.id = PlanId(
        current
            .document
            .content_digest()
            .expect("source binding-plan digest"),
    );

    let mut source = candidate.clone();
    source.package = source_package;
    source.handler_package = source_package;
    let handler_binding = desired
        .binding(&candidate.handler_binding)
        .expect("candidate handler binding");
    let resource = handler_binding.caller_grant.resources[0].resource.clone();
    let resource_interface = candidate.handler_interface.clone();
    let desired_planning = Sha256Digest::of_bytes("adoption desired planning");
    let current_planning = Sha256Digest::of_bytes("adoption current planning");
    let policy_revision = desired.document.policy_revision;
    let document = TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: vec![
            RequiredFeature::new(PROVIDER_STATE_ADOPTION_FEATURE).expect("adoption feature"),
        ],
        desired_planning,
        current_planning,
        desired_policy_revision: policy_revision,
        prior_policy_revision: current.document.policy_revision,
        authorization_policy_revision: policy_revision,
        teardown_bindings: Vec::new(),
        teardown_providers: Vec::new(),
        persistent_deletions: Vec::new(),
        provider_adoptions: vec![ProviderAdoptionAuthorization {
            resource,
            resource_interface,
            source,
            candidate,
        }],
    };

    AuthorityFixture {
        context,
        desired,
        current,
        document,
    }
}

fn multi_export_owner_fixture(
    select_owner: bool,
) -> (
    ValidationContext,
    CheckedBindingPlan,
    ProviderAdoptionEndpoint,
) {
    let mut fixture = crate::test_support::plan_fixture();
    let selected_interface = fixture.binding_plan.bindings[0].interface.clone();
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let artifact = fixture.binding_plan.bindings[0]
        .implementation
        .artifact
        .clone();
    let handler_key = key("observe-handler");
    let selected_implementation = ProviderImplementation {
        name: key("selected"),
        description: "Selected test implementation.".to_string(),
        interface: selected_interface.clone(),
        methods: Vec::new(),
        guarantees: Vec::new(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        desired_schema: None,
        composition_schema: None,
        provider_module: None,
        handler: Some(handler_key.clone()),
        owns_resource_kinds: Vec::new(),
        state_format: None,
    };
    let selected_reference = ProviderImplementationReference {
        descriptor: selected_implementation
            .descriptor_digest()
            .expect("selected implementation digest"),
        artifact: artifact.clone(),
        handler: Some(handler_key.clone()),
    };

    let mut owner_interface = fixture.interfaces[0].clone();
    owner_interface.interface.name =
        InterfaceName::new("test.state-owner").expect("owner interface name");
    for method in owner_interface.interface.methods.values_mut() {
        method.target_resource = owner_interface.interface.name.clone();
    }
    let owner_interface_key = owner_interface
        .interface_key()
        .expect("owner interface digest");
    let state_format = ProviderStateFormat {
        descriptor: Sha256Digest::of_bytes("state-format-v1"),
        artifact: artifact.clone(),
    };
    let owner_implementation = ProviderImplementation {
        name: key("owner"),
        description: "State-owning test implementation.".to_string(),
        interface: owner_interface_key.clone(),
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
        owns_resource_kinds: vec![selected_interface.name.clone()],
        state_format: Some(state_format.clone()),
    };
    let owner_reference = ProviderImplementationReference {
        descriptor: owner_implementation
            .descriptor_digest()
            .expect("owner implementation digest"),
        artifact: artifact.clone(),
        handler: None,
    };
    let package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: vec![
            RequiredFeature::new("abilities-v1").expect("abilities feature"),
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
                .expect("effect feature"),
            RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)
                .expect("state-format feature"),
        ],
        package: PackageSubject {
            name: key("multi-export-provider"),
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
        exports: vec![
            ExportDeclaration {
                name: key("handler"),
                interface: selected_interface.clone(),
                implementation_name: key("handler"),
                implementation: selected_reference.descriptor,
            },
            ExportDeclaration {
                name: key("owner"),
                interface: owner_interface_key.clone(),
                implementation_name: key("owner"),
                implementation: owner_reference.descriptor,
            },
        ],
        requirements: Vec::new(),
        implementation: PackageImplementation {
            providers: vec![selected_implementation, owner_implementation],
            handlers: BTreeMap::from([(
                handler_key,
                HandlerDescriptor {
                    artifact: artifact.clone(),
                    entry_point: "bin/observe".to_string(),
                    arguments: ValueSchema::Boolean,
                    result: ValueSchema::Boolean,
                },
            )]),
        },
        qualification: aos_ability_model::PackageQualification::default(),
    };
    let package_digest = package.content_digest().expect("package digest");
    fixture.binding_plan.bindings[0].provider_package = Some(package_digest);
    fixture.binding_plan.bindings[0].implementation = selected_reference.clone();
    fixture.binding_inputs.environment.providers[0].implementation = selected_reference.clone();
    fixture.binding_inputs.desired_state.instances = vec![DesiredInstance {
        instance: provider.clone(),
        authority: DeclarationAuthority::Package {
            package: key("multi-export-provider"),
        },
        package: Some(package_digest),
        enabled: true,
        configuration: None,
    }];
    fixture.binding_inputs.packages = vec![package];
    fixture.binding_inputs.desired_state.child_requests[0].authority =
        DeclarationAuthority::Package {
            package: key("multi-export-provider"),
        };
    fixture.binding_plan.requests[0].authority = DeclarationAuthority::Package {
        package: key("multi-export-provider"),
    };
    if select_owner {
        let handler_scope =
            ScopePath::new(vec![provider.key.clone(), key("nested")]).expect("nested owner scope");
        fixture.binding_inputs.desired_state.child_requests[0]
            .id
            .scope = handler_scope.clone();
        fixture.binding_plan.requests[0].id.scope = handler_scope;
        fixture.binding_plan.bindings[0].request = fixture.binding_plan.requests[0].id.clone();
        fixture.binding_inputs.desired_state.child_requests[0].lifetime =
            aos_ability_model::ResourceLifetime::Persistent;
        fixture.binding_plan.requests[0].lifetime = aos_ability_model::ResourceLifetime::Persistent;
        fixture.binding_plan.bindings[0].lifetime = aos_ability_model::ResourceLifetime::Persistent;
        fixture.binding_plan.bindings[0].caller_grant.resources[0].access =
            AccessMode::ExclusiveWrite;
        let owner_resource = aos_ability_model::ResourceId {
            provider: provider.clone(),
            key: key("owner-service"),
        };
        let owner_revision = aos_ability_model::ResourceRevision {
            resource: owner_resource.clone(),
            kind: fixture.binding_plan.bindings[0].interface.name.clone(),
            lifetime: aos_ability_model::ResourceLifetime::Instance,
            value: aos_ability_model::AbilityValue::new(serde_json::json!(true)).unwrap(),
            realization: AbilityValue::new(serde_json::Value::Null).unwrap(),
            revision: RevisionId(Sha256Digest::of_bytes("owner revision")),
        };
        let owner_request = BindingRequest {
            authority: DeclarationAuthority::Package {
                package: key("multi-export-provider"),
            },
            id: aos_ability_model::RequestId {
                consumer: provider.clone(),
                scope: ScopePath::root(),
                key: key("owner-service"),
            },
            accepted_interfaces: vec![owner_interface_key.clone()],
            methods: vec![key("observe")],
            guarantees: Vec::new(),
            lifetime: aos_ability_model::ResourceLifetime::Persistent,
            parameters: AbilityValue::new(serde_json::json!(true))
                .expect("owner request parameters must be bounded"),
        };
        let policy_revision = fixture.binding_plan.policy_revision;
        let owner_binding = Binding {
            id: BindingId(key("owner-service")),
            request: owner_request.id.clone(),
            interface: owner_interface_key.clone(),
            provider: provider.clone(),
            provider_package: Some(package_digest),
            implementation: owner_reference.clone(),
            source: aos_ability_model::BindingSource::Explicit,
            caller_grant: aos_ability_model::AuthorityGrant {
                principal: provider.clone(),
                methods: vec![key("observe")],
                aggregate_slots: Vec::new(),
                resources: vec![ResourcePermission {
                    resource: owner_resource.clone(),
                    access: AccessMode::Read,
                    operations: vec![key("observe")],
                }],
            },
            provider_grant: aos_ability_model::AuthorityGrant {
                principal: provider.clone(),
                methods: Vec::new(),
                aggregate_slots: Vec::new(),
                resources: Vec::new(),
            },
            guarantees: Vec::new(),
            policy_revision,
            lifetime: aos_ability_model::ResourceLifetime::Persistent,
            mediation_allowed: false,
        };
        fixture
            .binding_inputs
            .desired_state
            .child_requests
            .push(owner_request.clone());
        fixture.binding_plan.requests.push(owner_request);
        fixture.binding_plan.bindings.push(owner_binding);
        for revisions in [
            &mut fixture.binding_inputs.environment.resources,
            &mut fixture.binding_inputs.desired_state.resources,
            &mut fixture.binding_plan.resources,
            &mut fixture.effect_plan.current_revisions,
            &mut fixture.effect_plan.desired_revisions,
        ] {
            revisions.push(owner_revision.clone());
            revisions.sort_by(|left, right| {
                aos_ability_model::compare_resource_ids(&left.resource, &right.resource)
            });
        }
        fixture
            .binding_plan
            .requests
            .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
        fixture
            .binding_inputs
            .desired_state
            .child_requests
            .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
        fixture.binding_plan.bindings.sort_by(|left, right| {
            compare_request_ids(&left.request, &right.request).then_with(|| left.id.cmp(&right.id))
        });
    }
    fixture.interfaces.push(owner_interface);
    fixture.context = ValidationContext::new(
        BTreeSet::from([
            RequiredFeature::new("abilities-v1").expect("abilities feature"),
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
                .expect("effect feature"),
            RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)
                .expect("state-format feature"),
        ]),
        fixture.interfaces.clone(),
    )
    .expect("multi-export context");
    fixture.refresh_commitments();
    let checked = fixture
        .context
        .validate_binding_plan(fixture.binding_plan, fixture.binding_inputs)
        .expect("multi-export binding plan");
    let binding = checked
        .bindings()
        .iter()
        .find(|binding| binding.implementation == selected_reference)
        .expect("selected handler binding")
        .clone();
    let incarnation = checked
        .environment()
        .providers
        .iter()
        .find(|inventory| inventory.implementation == selected_reference)
        .expect("selected handler inventory")
        .incarnation
        .clone()
        .expect("available handler incarnation");
    let endpoint = ProviderAdoptionEndpoint {
        provider,
        package: package_digest,
        interface: owner_interface_key,
        implementation: owner_reference,
        state_format,
        handler_binding: binding.id,
        handler_method: key("observe"),
        handler_provider: binding.provider,
        handler_incarnation: incarnation,
        handler_interface: binding.interface,
        handler_implementation: binding.implementation,
        handler_package: package_digest,
    };

    let context = ValidationContext::new(
        BTreeSet::from([
            RequiredFeature::new("abilities-v1").expect("abilities feature"),
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
                .expect("effect feature"),
            RequiredFeature::new(aos_ability_model::PROVIDER_STATE_FORMAT_V1)
                .expect("state-format feature"),
            RequiredFeature::new(PROVIDER_STATE_ADOPTION_FEATURE).expect("adoption feature"),
        ]),
        fixture.interfaces,
    )
    .expect("stateful owner context");

    (context, checked, endpoint)
}

fn authority_fixture() -> AuthorityFixture {
    let mut source = crate::test_support::lifecycle_plan_fixture();
    let mut stop = crate::test_support::test_lifecycle_interface()
        .interface
        .methods
        .remove(&key("stop"))
        .expect("neutral lifecycle interface must declare Stop");
    stop.target_resource = source.interfaces[0].interface.name.clone();
    stop.parameters = source.interfaces[0].interface.request.clone();
    stop.outcome.indeterminate = aos_ability_model::IndeterminateSemantics::Reconcile;
    source.interfaces[0]
        .interface
        .methods
        .insert(key("stop"), stop);
    source.refresh_interface_with_features(BTreeSet::from([RequiredFeature::new(
        aos_ability_model::FEATURE_ABILITY_EFFECTS_V1,
    )
    .expect("effect feature")]));
    let checked = source
        .validate()
        .expect("lifecycle teardown fixture must validate");
    let context = ValidationContext::new(
        BTreeSet::from([
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
                .expect("effect feature"),
        ]),
        checked.interfaces().values().cloned(),
    )
    .expect("systemd interface catalog must validate");
    let current = checked.binding_plan().clone();
    let desired = current.clone();
    let source = current.bindings()[0].clone();
    let mut request = current.document.requests[0].clone();
    request.id.key = key("transition-stop-old-request");
    let mut binding = source.clone();
    binding.id = BindingId(key("transition-stop-old"));
    binding.request = request.id.clone();
    binding.caller_grant.methods = vec![key("stop")];
    binding.caller_grant.resources[0].access = AccessMode::ExclusiveWrite;
    binding.caller_grant.resources[0].operations = vec![key("stop")];
    binding.provider_grant.methods.clear();
    binding.provider_grant.resources.clear();
    let desired_planning = Sha256Digest::of_bytes("desired planning");
    let current_planning = Sha256Digest::of_bytes("current planning");
    let policy_revision = desired.document.policy_revision;
    let document = TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_planning,
        current_planning,
        desired_policy_revision: policy_revision,
        prior_policy_revision: current.document.policy_revision,
        authorization_policy_revision: policy_revision,
        teardown_bindings: vec![TeardownBindingAuthorization {
            source_binding: source.id,
            request,
            binding,
        }],
        teardown_providers: Vec::new(),
        persistent_deletions: Vec::new(),
        provider_adoptions: Vec::new(),
    };

    AuthorityFixture {
        context,
        desired,
        current,
        document,
    }
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid test key")
}
