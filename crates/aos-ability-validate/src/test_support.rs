//! Reusable semantically validated ability-plan fixtures for downstream tests.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU32, NonZeroU64};

use aos_ability_model::document::{
    DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory, ProviderState,
};
use aos_ability_model::identity::{compare_instance_ids, compare_request_ids};
use aos_ability_model::*;
use aos_contract::Sha256Digest;

use crate::{BindingValidationInputs, CheckedEffectPlan, ValidationContext, ValidationErrors};

/// Holds mutable unchecked documents that form one internally consistent plan fixture.
#[derive(Clone, Debug)]
pub struct PlanFixture {
    /// Retains mutable source interface documents for fixture extensions.
    pub interfaces: Vec<InterfaceDocument>,
    /// Supplies the validated interface catalog used by both plan stages.
    pub context: ValidationContext,
    /// Supplies the unchecked binding-plan document.
    pub binding_plan: BindingPlanDocument,
    /// Supplies the exact environment, desired-state, and package inputs.
    pub binding_inputs: BindingValidationInputs,
    /// Supplies the unchecked effect-plan document.
    pub effect_plan: EffectPlanDocument,
}

impl PlanFixture {
    /// Rebuilds the single-interface catalog and rewrites its exact references.
    ///
    /// # Panics
    ///
    /// Panics when the fixture does not contain exactly one valid interface.
    pub fn refresh_interface(&mut self) {
        self.refresh_interface_with_features(BTreeSet::new());
    }

    /// Rebuilds the interface catalog with an explicit format-feature set.
    ///
    /// This variant supports fixtures that replace the baseline interface with
    /// a versioned fixture contract while retaining the same cross-document
    /// identity rewrite as [`Self::refresh_interface`].
    ///
    /// # Panics
    ///
    /// Panics when the fixture does not contain exactly one interface valid
    /// under `supported_features`.
    pub fn refresh_interface_with_features(
        &mut self,
        supported_features: BTreeSet<RequiredFeature>,
    ) {
        let [interface] = self.interfaces.as_slice() else {
            panic!("the minimal test fixture must contain exactly one interface");
        };
        let interface_key = interface
            .interface_key()
            .expect("test interface must have a canonical key");
        self.context = ValidationContext::new(supported_features, self.interfaces.clone())
            .expect("mutated test interface must validate");
        for provider in &mut self.binding_inputs.environment.providers {
            provider.interface = interface_key.clone();
        }
        for request in &mut self.binding_inputs.desired_state.child_requests {
            request.accepted_interfaces = vec![interface_key.clone()];
        }
        for request in &mut self.binding_plan.requests {
            request.accepted_interfaces = vec![interface_key.clone()];
        }
        for binding in &mut self.binding_plan.bindings {
            binding.interface = interface_key.clone();
        }
        for operation in &mut self.effect_plan.operations {
            operation.interface = interface_key.clone();
            operation.target.interface = interface_key.clone();
            for recovery in [
                operation.recovery.reconcile.as_mut(),
                operation.recovery.cancel.as_mut(),
                operation.recovery.compensate.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                recovery.interface = interface_key.clone();
            }
        }
        self.refresh_commitments();
    }

    /// Recomputes cross-document digests after mutating fixture inputs.
    ///
    /// # Panics
    ///
    /// Panics only when a mutated test document cannot be canonically encoded.
    pub fn refresh_commitments(&mut self) {
        self.binding_inputs.desired_state.environment = self
            .binding_inputs
            .environment
            .content_digest()
            .expect("test environment must have a canonical digest");
        self.binding_plan.environment = self.binding_inputs.desired_state.environment;
        self.binding_plan.desired_state = self
            .binding_inputs
            .desired_state
            .content_digest()
            .expect("test desired state must have a canonical digest");
        self.effect_plan.binding_plan = self
            .binding_plan
            .content_digest()
            .expect("test binding plan must have a canonical digest");
    }

    /// Runs the production binding and effect validators over this fixture.
    ///
    /// # Errors
    ///
    /// Returns structured diagnostics when a fixture mutation violates either
    /// production validation stage.
    pub fn validate(self) -> Result<CheckedEffectPlan, ValidationErrors> {
        let checked_binding = self
            .context
            .validate_binding_plan(self.binding_plan, self.binding_inputs)?;
        self.context
            .validate_effect_plan(self.effect_plan, checked_binding)
    }
}

/// Builds a minimal real checked plan with one available provider observation.
///
/// The fixture passes the public interface, binding, and effect validators. It
/// contains one `observe` operation targeting one unchanged instance-lifetime
/// resource under caller authority.
///
/// # Panics
///
/// Panics only when the statically constructed fixture violates the production
/// validator contract.
#[must_use]
pub fn checked_effect_plan() -> CheckedEffectPlan {
    plan_fixture()
        .validate()
        .expect("static test plan must pass production validation")
}

/// Builds a checked start operation against a test-only lifecycle contract.
///
/// The fixture includes observation-based reconciliation and a terminal
/// implementation without introducing a production interface catalog.
///
/// # Panics
///
/// Panics only when the test contract and this static effect fixture stop
/// satisfying the production validator.
#[must_use]
pub fn checked_lifecycle_effect_plan() -> CheckedEffectPlan {
    lifecycle_plan_fixture()
        .validate()
        .expect("lifecycle fixture must pass production validation")
}

/// Builds mutable inputs for an exact host-local lifecycle-manager plan.
///
/// # Panics
///
/// Panics only when a fixture identity or static value cannot be constructed.
#[must_use]
pub fn lifecycle_plan_fixture() -> PlanFixture {
    let mut fixture = plan_fixture();
    let artifact = fixture.binding_plan.bindings[0]
        .implementation
        .artifact
        .clone();
    fixture.interfaces = vec![test_manager_interface()];
    fixture.refresh_interface();

    let provider = test_manager_provider(artifact.clone());
    let implementation = ProviderImplementationReference {
        descriptor: provider
            .descriptor_digest()
            .expect("lifecycle provider must have a digest"),
        artifact,
        handler: Some(test_manager_handler_key()),
    };
    fixture.binding_inputs.environment.providers[0].implementation = implementation.clone();
    fixture.binding_plan.bindings[0].implementation = implementation;

    let guarantees = vec![test_manager_guarantee()];
    fixture.binding_inputs.environment.providers[0].guarantees = guarantees.clone();
    fixture.binding_inputs.desired_state.child_requests[0].guarantees = guarantees.clone();
    fixture.binding_plan.requests[0].guarantees = guarantees.clone();
    fixture.binding_plan.bindings[0].guarantees = guarantees;

    let methods = vec![key("observe"), key("start")];
    fixture.binding_inputs.desired_state.child_requests[0].methods = methods.clone();
    fixture.binding_inputs.desired_state.child_requests[0].parameters =
        AbilityValue::new(serde_json::json!({"subject": "fixture"}))
            .expect("lifecycle request parameters must be bounded");
    fixture.binding_plan.requests[0].methods = methods.clone();
    fixture.binding_plan.requests[0].parameters =
        fixture.binding_inputs.desired_state.child_requests[0]
            .parameters
            .clone();
    fixture.binding_plan.bindings[0].caller_grant.methods = methods;
    fixture.binding_plan.bindings[0].caller_grant.resources[0].access = AccessMode::ExclusiveWrite;
    fixture.binding_plan.bindings[0].caller_grant.resources[0].operations =
        vec![key("observe"), key("start")];

    let resource = fixture.effect_plan.current_revisions[0].resource.clone();
    let controller = AggregateId {
        provider: resource.provider.clone(),
        group: fixture.interfaces[0]
            .interface
            .aggregation
            .controller_group
            .clone(),
    };
    let controller_assignment = ControllerAssignment {
        resource,
        controller: controller.clone(),
    };
    fixture.binding_inputs.environment.controllers = vec![controller_assignment.clone()];
    fixture.binding_inputs.desired_state.controllers = vec![controller_assignment.clone()];
    fixture.effect_plan.controllers = vec![controller_assignment];

    let operation = &mut fixture.effect_plan.operations[0];
    operation.method = key("start");
    operation.input_phase = ValuePhase::Planning;
    operation.target.operations = vec![key("start")];
    operation.inputs = ValueExpression::Literal {
        value: AbilityValue::new(serde_json::json!({"subject": "fixture"}))
            .expect("lifecycle fixture input must be bounded"),
    };
    operation.accesses[0].mode = AccessMode::ExclusiveWrite;
    operation.controller = Some(controller);
    operation.recovery.reconcile = Some(MethodReference {
        interface: operation.interface.clone(),
        method: key("observe"),
    });
    fixture.refresh_commitments();

    fixture
}

/// Builds a checked persistent write owned by a stateful pure provider.
///
/// One package exports the pure owner and the terminal handler. The terminal
/// request is nested beneath the owner instance, so native inventory tests can
/// exercise durable owner admission through the same checked binding evidence
/// used by production dispatch.
///
/// # Panics
///
/// Panics only when the statically constructed package, binding, or effect
/// fixture stops satisfying a production validator invariant.
#[must_use]
pub fn checked_stateful_owner_effect_plan() -> CheckedEffectPlan {
    stateful_owner_plan_fixture()
        .validate()
        .expect("stateful owner fixture must pass production validation")
}

/// Builds mutable checked-plan inputs for a stateful provider-owned write.
///
/// This is the mutable counterpart to [`checked_stateful_owner_effect_plan`].
/// Downstream recovery tests can vary execution incarnation or operation shape,
/// refresh the commitments, and still pass through the production validators.
///
/// # Panics
///
/// Panics only when the statically constructed package or model identities
/// cannot be represented.
#[must_use]
pub fn stateful_owner_plan_fixture() -> PlanFixture {
    let mut fixture = plan_fixture();
    let terminal_interface = fixture.binding_plan.bindings[0].interface.clone();
    let provider = fixture.binding_plan.bindings[0].provider.clone();
    let artifact = fixture.binding_plan.bindings[0]
        .implementation
        .artifact
        .clone();
    let handler = key("observe-handler");
    let terminal_implementation = ProviderImplementation {
        name: key("terminal"),
        description: "Terminal test implementation.".to_string(),
        interface: terminal_interface.clone(),
        methods: Vec::new(),
        guarantees: Vec::new(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        desired_schema: None,
        composition_schema: None,
        provider_module: None,
        handler: Some(handler.clone()),
        owns_resource_kinds: Vec::new(),
        state_format: None,
    };
    let terminal_reference = ProviderImplementationReference {
        descriptor: terminal_implementation
            .descriptor_digest()
            .expect("terminal implementation digest"),
        artifact: artifact.clone(),
        handler: Some(handler.clone()),
    };

    let mut owner_interface = fixture.interfaces[0].clone();
    owner_interface.interface.name =
        InterfaceName::new("test.state-owner").expect("owner interface name");
    owner_interface.interface.aggregation.controller_group = key("stateful-owner");
    let owner_resource_kind = owner_interface.interface.name.clone();
    for method in owner_interface.interface.methods.values_mut() {
        method.target_resource = owner_resource_kind.clone();
    }
    let mut control_method = owner_interface.interface.methods[&key("observe")].clone();
    control_method.semantics = MethodSemantics::ordinary(AccessMode::ExclusiveWrite);
    control_method.target_resource = terminal_interface.name.clone();
    control_method.permitted_operations = vec![key("control")];
    owner_interface
        .interface
        .methods
        .insert(key("control"), control_method);
    let owner_interface_key = owner_interface
        .interface_key()
        .expect("owner interface digest");
    let owner_implementation = ProviderImplementation {
        name: key("owner"),
        description: "State-owning test implementation.".to_string(),
        interface: owner_interface_key.clone(),
        methods: Vec::new(),
        guarantees: Vec::new(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        provider_module: Some(ModuleLocator {
            artifact: artifact.clone(),
            path: RelativePath::new("default.nix").expect("valid module path"),
        }),
        handler: None,
        owns_resource_kinds: vec![terminal_interface.name.clone()],
        desired_schema: Some(aos_ability_model::ValueSchema::Optional {
            value: Box::new(aos_ability_model::ValueSchema::Boolean),
        }),
        composition_schema: None,
        state_format: Some(ProviderStateFormat {
            descriptor: Sha256Digest::of_bytes("stateful owner test format"),
            artifact: artifact.clone(),
        }),
    };
    let owner_reference = ProviderImplementationReference {
        descriptor: owner_implementation
            .descriptor_digest()
            .expect("owner implementation digest"),
        artifact: artifact.clone(),
        handler: None,
    };
    let mut providers = vec![terminal_implementation, owner_implementation];
    providers.sort_by(|left, right| left.interface.cmp(&right.interface));
    let package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: vec![
            RequiredFeature::new("abilities-v1").expect("base abilities feature"),
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
                .expect("effect semantics feature"),
            RequiredFeature::new(PROVIDER_STATE_FORMAT_V1).expect("state-format feature"),
        ],
        package: aos_ability_model::document::PackageSubject {
            name: key("stateful-owner-provider"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact.clone()],
        interfaces: BTreeMap::from([
            (key("handler"), terminal_interface.clone()),
            (key("owner"), owner_interface_key.clone()),
        ]),
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
                interface: terminal_interface.clone(),
                implementation_name: key("terminal"),
                implementation: terminal_reference.descriptor,
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
            providers,
            handlers: BTreeMap::from([(
                handler,
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
    let package_digest = package.content_digest().expect("stateful package digest");

    fixture.binding_inputs.environment.providers[0].implementation = terminal_reference.clone();
    fixture.binding_inputs.desired_state.instances = vec![DesiredInstance {
        instance: provider.clone(),
        authority: DeclarationAuthority::Package {
            package: key("stateful-owner-provider"),
        },
        package: Some(package_digest),
        enabled: true,
        configuration: None,
    }];
    fixture.binding_inputs.packages = vec![package];
    fixture.binding_inputs.desired_state.child_requests[0].authority =
        DeclarationAuthority::Package {
            package: key("stateful-owner-provider"),
        };
    fixture.binding_plan.requests[0].authority = DeclarationAuthority::Package {
        package: key("stateful-owner-provider"),
    };

    let owner_resource = ResourceId {
        provider: provider.clone(),
        key: key("owner-metadata"),
    };
    let owner_revision = ResourceRevision {
        resource: owner_resource.clone(),
        kind: owner_resource_kind,
        lifetime: aos_ability_model::ResourceLifetime::Instance,
        value: AbilityValue::new(serde_json::json!({
            "_type": "aos-resource-reference",
            "interface": owner_interface_key.clone(),
            "resource": owner_resource.clone(),
            "operations": ["observe"],
            "lifetime": "instance",
        }))
        .unwrap(),
        realization: AbilityValue::new(serde_json::Value::Null).unwrap(),
        revision: RevisionId(Sha256Digest::of_bytes("stateful owner metadata revision")),
    };
    for revisions in [
        &mut fixture.binding_inputs.environment.resources,
        &mut fixture.binding_inputs.desired_state.resources,
        &mut fixture.binding_plan.resources,
        &mut fixture.effect_plan.current_revisions,
        &mut fixture.effect_plan.desired_revisions,
    ] {
        revisions.push(owner_revision.clone());
        revisions.sort_by(|left, right| compare_resource_ids(&left.resource, &right.resource));
    }

    let handler_scope =
        ScopePath::new(vec![provider.key.clone(), key("nested")]).expect("nested handler scope");
    fixture.binding_inputs.desired_state.child_requests[0]
        .id
        .scope = handler_scope.clone();
    fixture.binding_inputs.desired_state.child_requests[0].lifetime = ResourceLifetime::Persistent;
    fixture.binding_plan.requests[0] =
        fixture.binding_inputs.desired_state.child_requests[0].clone();
    fixture.binding_plan.bindings[0].request = fixture.binding_plan.requests[0].id.clone();
    fixture.binding_plan.bindings[0].provider_package = Some(package_digest);
    fixture.binding_plan.bindings[0].implementation = terminal_reference;
    fixture.binding_plan.bindings[0].caller_grant.resources[0].access = AccessMode::ExclusiveWrite;
    fixture.binding_plan.bindings[0].lifetime = ResourceLifetime::Persistent;

    let owner_request = BindingRequest {
        authority: DeclarationAuthority::Package {
            package: key("stateful-owner-provider"),
        },
        id: RequestId {
            consumer: provider.clone(),
            scope: ScopePath::root(),
            key: key("owner"),
        },
        accepted_interfaces: vec![owner_interface_key.clone()],
        methods: vec![key("control"), key("observe")],
        guarantees: Vec::new(),
        lifetime: ResourceLifetime::Persistent,
        parameters: AbilityValue::new(serde_json::json!(true))
            .expect("owner request parameters must be bounded"),
    };
    let terminal_resource = fixture.effect_plan.operations[0].target.resource.clone();
    let owner_binding = Binding {
        id: BindingId(key("owner")),
        request: owner_request.id.clone(),
        interface: owner_interface_key,
        provider: provider.clone(),
        provider_package: Some(package_digest),
        implementation: owner_reference,
        source: BindingSource::Explicit,
        caller_grant: AuthorityGrant {
            principal: provider.clone(),
            methods: vec![key("control"), key("observe")],
            contributions: Vec::new(),
            resources: vec![
                ResourcePermission {
                    resource: owner_resource,
                    access: AccessMode::Read,
                    operations: vec![key("observe")],
                },
                ResourcePermission {
                    resource: terminal_resource.clone(),
                    access: AccessMode::ExclusiveWrite,
                    operations: vec![key("control")],
                },
            ],
        },
        provider_grant: AuthorityGrant {
            principal: provider,
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        guarantees: Vec::new(),
        policy_revision: fixture.binding_plan.policy_revision,
        lifetime: ResourceLifetime::Persistent,
        mediation_allowed: false,
    };
    fixture
        .binding_inputs
        .desired_state
        .child_requests
        .push(owner_request.clone());
    fixture.binding_plan.requests.push(owner_request);
    fixture.binding_plan.bindings.push(owner_binding);
    fixture
        .binding_inputs
        .desired_state
        .child_requests
        .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
    fixture
        .binding_plan
        .requests
        .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
    fixture.binding_plan.bindings.sort_by(|left, right| {
        compare_request_ids(&left.request, &right.request).then_with(|| left.id.cmp(&right.id))
    });

    let controller = AggregateId {
        provider: terminal_resource.provider.clone(),
        group: key("stateful-owner"),
    };
    let controller_assignment = ControllerAssignment {
        resource: terminal_resource,
        controller: controller.clone(),
    };
    fixture.binding_inputs.environment.controllers = vec![controller_assignment.clone()];
    fixture.binding_inputs.desired_state.controllers = vec![controller_assignment.clone()];
    fixture.effect_plan.controllers = vec![controller_assignment];
    fixture.effect_plan.operations[0].target.lifetime = ResourceLifetime::Persistent;
    fixture.effect_plan.operations[0].accesses[0].mode = AccessMode::ExclusiveWrite;
    fixture.effect_plan.operations[0].controller = Some(controller);
    fixture.interfaces.push(owner_interface);
    fixture.interfaces.sort_by(|left, right| {
        left.interface
            .name
            .cmp(&right.interface.name)
            .then_with(|| left.interface.abi.cmp(&right.interface.abi))
    });
    fixture.context = ValidationContext::new(
        BTreeSet::from([
            RequiredFeature::new("abilities-v1").expect("base abilities feature"),
            RequiredFeature::new(aos_ability_model::FEATURE_ABILITY_EFFECTS_V1)
                .expect("effect semantics feature"),
            RequiredFeature::new(PROVIDER_STATE_FORMAT_V1).expect("state-format feature"),
        ]),
        fixture.interfaces.clone(),
    )
    .expect("stateful owner context");
    fixture.refresh_commitments();

    fixture
}

/// Builds mutable unchecked documents for focused validator regression tests.
///
/// # Panics
///
/// Panics only if a statically constructed identity or intermediate document
/// cannot be represented by the portable model.
#[must_use]
pub fn plan_fixture() -> PlanFixture {
    let environment_id = EnvironmentId {
        authority: key("test"),
        key: key("host"),
        stage: ExecutionStage::Host,
    };
    let provider = InstanceId {
        environment: environment_id.clone(),
        key: key("provider"),
    };
    let resource = ResourceId {
        provider: provider.clone(),
        key: key("service"),
    };
    let artifact = ArtifactReference {
        content: digest('1'),
        store_path: "/nix/store/00000000000000000000000000000000-test-provider".to_string(),
        nar_hash: digest('2'),
        closure: digest('3'),
    };
    let implementation = ProviderImplementationReference {
        descriptor: digest('4'),
        artifact: artifact.clone(),
        handler: Some(key("observe-handler")),
    };

    let interface = interface_document();
    let interface_key = interface
        .interface_key()
        .expect("test interface must have a canonical key");
    let context = ValidationContext::new(BTreeSet::new(), [interface.clone()])
        .expect("test interface must validate");
    let policy_revision = RevisionId(digest('5'));
    let resource_revision = ResourceRevision {
        resource: resource.clone(),
        kind: interface_key.name.clone(),
        lifetime: aos_ability_model::ResourceLifetime::Instance,
        value: AbilityValue::new(serde_json::json!(true)).unwrap(),
        realization: AbilityValue::new(serde_json::Value::Null).unwrap(),
        revision: RevisionId(digest('6')),
    };
    let environment = EnvironmentDocument {
        schema: EnvironmentDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        environment: environment_id,
        platform: PlatformIdentity {
            system: key("linux"),
            architecture: key("x86_64"),
        },
        policy_revision,
        providers: vec![ProviderInventory {
            provider: provider.clone(),
            interface: interface_key.clone(),
            implementation: implementation.clone(),
            state: ProviderState::Available,
            incarnation: Some(
                IncarnationId::new("test-incarnation").expect("valid test incarnation"),
            ),
            guarantees: Vec::new(),
        }],
        resources: vec![resource_revision.clone()],
        controllers: Vec::new(),
        guarantees: Vec::new(),
        freshness: FreshnessCondition {
            generation: RevisionId(digest('7')),
            max_age_millis: 1_000,
        },
    };
    let request = BindingRequest {
        authority: DeclarationAuthority::Package {
            package: aos_ability_model::LocalKey::new("test-package")
                .expect("valid test package provenance"),
        },
        id: RequestId {
            consumer: provider.clone(),
            scope: ScopePath::root(),
            key: key("service"),
        },
        accepted_interfaces: vec![interface_key.clone()],
        methods: vec![key("observe")],
        guarantees: Vec::new(),
        lifetime: ResourceLifetime::Instance,
        parameters: AbilityValue::new(serde_json::json!(true))
            .expect("test request parameters must be bounded"),
    };
    let desired_state = DesiredStateDocument {
        schema: DesiredStateDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        environment: environment
            .content_digest()
            .expect("test environment must have a canonical digest"),
        instances: Vec::new(),
        contributions: Vec::new(),
        child_requests: vec![request.clone()],
        resources: vec![resource_revision.clone()],
        outputs: Vec::new(),
        controllers: Vec::new(),
    };
    let permission = ResourcePermission {
        resource: resource.clone(),
        access: AccessMode::Read,
        operations: vec![key("observe")],
    };
    let binding = Binding {
        id: BindingId(key("service")),
        request: request.id.clone(),
        interface: interface_key.clone(),
        provider: provider.clone(),
        provider_package: None,
        implementation,
        source: BindingSource::ExistingPin,
        caller_grant: AuthorityGrant {
            principal: provider.clone(),
            methods: vec![key("observe")],
            contributions: Vec::new(),
            resources: vec![permission],
        },
        provider_grant: AuthorityGrant {
            principal: provider,
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        guarantees: Vec::new(),
        policy_revision,
        lifetime: ResourceLifetime::Instance,
        mediation_allowed: false,
    };
    let binding_plan = BindingPlanDocument {
        schema: BindingPlanDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state: desired_state
            .content_digest()
            .expect("test desired state must have a canonical digest"),
        environment: environment
            .content_digest()
            .expect("test environment must have a canonical digest"),
        policy_revision,
        requests: vec![request],
        bindings: vec![binding.clone()],
        resources: vec![resource_revision.clone()],
        obligations: Vec::new(),
    };
    let binding_plan_digest = binding_plan
        .content_digest()
        .expect("test binding plan must have a canonical digest");
    let operation = Operation {
        key: ScopedOperationKey {
            scope: ScopePath::root(),
            key: key("observe"),
        },
        branch_context: Vec::new(),
        binding: binding.id,
        authority: AuthorityRole::Caller,
        interface: interface_key.clone(),
        method: key("observe"),
        phase: OperationPhase::Converging,
        input_phase: ValuePhase::Observation,
        target: ResourceReference {
            interface: interface_key,
            resource: resource.clone(),
            operations: vec![key("observe")],
            lifetime: ResourceLifetime::Instance,
        },
        inputs: ValueExpression::Literal {
            value: AbilityValue::new(serde_json::Value::Bool(true))
                .expect("valid test input value"),
        },
        preconditions: Vec::new(),
        accesses: vec![ResourceAccess {
            resource,
            mode: AccessMode::Read,
        }],
        controller: None,
        deadline: DeadlinePolicy {
            attempt_timeout_millis: NonZeroU64::new(100).expect("positive test timeout"),
            total_recovery_millis: NonZeroU64::new(1_000).expect("positive test deadline"),
        },
        recovery: RecoveryContract {
            retry: RetryPolicy::Disabled,
            reconcile: None,
            cancel: None,
            compensate: None,
        },
    };
    let effect_plan = EffectPlanDocument {
        schema: EffectPlanDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        limits: ABILITY_LIMITS_V1,
        binding_plan: binding_plan_digest,
        artifacts: vec![artifact],
        current_revisions: vec![resource_revision.clone()],
        desired_revisions: vec![resource_revision],
        operations: vec![operation],
        decisions: Vec::new(),
        merges: Vec::new(),
        edges: Vec::new(),
        provider_readiness: Vec::new(),
        controllers: Vec::new(),
        obligations: Vec::new(),
    };

    PlanFixture {
        interfaces: vec![interface],
        context,
        binding_plan,
        binding_inputs: BindingValidationInputs {
            environment,
            desired_state,
            packages: Vec::new(),
        },
        effect_plan,
    }
}

/// Builds a valid two-stage chain from one available provider through two planned providers.
///
/// The returned mutable documents are useful for validator regressions that need to alter
/// readiness declarations. Call [`PlanFixture::validate`] to obtain a checked effect plan.
///
/// # Panics
///
/// Panics only if the statically constructed fixture violates an intermediate model contract.
#[must_use]
pub fn planned_provider_chain_fixture() -> PlanFixture {
    let mut fixture = plan_fixture();
    let ready_output = &mut fixture.interfaces[0]
        .interface
        .methods
        .get_mut(&key("observe"))
        .expect("fixture observe method")
        .outputs
        .get_mut(&key("ready"))
        .expect("fixture ready output");
    ready_output.schema = ValueSchema::ProviderAssignment;
    ready_output.lifetime = ResourceLifetime::Instance;

    let available_provider = fixture.binding_inputs.environment.providers[0]
        .provider
        .clone();
    let environment = available_provider.environment.clone();
    let provider_b = InstanceId {
        environment: environment.clone(),
        key: key("planned-b"),
    };
    let provider_c = InstanceId {
        environment,
        key: key("planned-c"),
    };
    let implementation = fixture.binding_plan.bindings[0].implementation.clone();
    for provider in [&provider_b, &provider_c] {
        fixture
            .binding_inputs
            .environment
            .providers
            .push(ProviderInventory {
                provider: provider.clone(),
                interface: fixture.binding_plan.bindings[0].interface.clone(),
                implementation: implementation.clone(),
                state: ProviderState::Planned,
                incarnation: None,
                guarantees: Vec::new(),
            });
    }
    fixture
        .binding_inputs
        .environment
        .providers
        .sort_by(|left, right| {
            compare_instance_ids(&left.provider, &right.provider)
                .then_with(|| left.interface.cmp(&right.interface))
        });

    let resource_b = ResourceId {
        provider: provider_b.clone(),
        key: key("service"),
    };
    let resource_c = ResourceId {
        provider: provider_c.clone(),
        key: key("service"),
    };
    for (resource, digit) in [(&resource_b, '8'), (&resource_c, '9')] {
        let revision = ResourceRevision {
            resource: resource.clone(),
            kind: fixture.binding_plan.bindings[0].interface.name.clone(),
            lifetime: aos_ability_model::ResourceLifetime::Instance,
            value: AbilityValue::new(serde_json::json!(true)).unwrap(),
            realization: AbilityValue::new(serde_json::Value::Null).unwrap(),
            revision: RevisionId(digest(digit)),
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
    }
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

    let request_template = fixture.binding_plan.requests[0].clone();
    let binding_template = fixture.binding_plan.bindings[0].clone();
    for (name, provider, resource) in [
        ("b", &provider_b, &resource_b),
        ("c", &provider_c, &resource_c),
    ] {
        let mut request = request_template.clone();
        request.id.key = key(name);
        fixture
            .binding_inputs
            .desired_state
            .child_requests
            .push(request.clone());
        fixture.binding_plan.requests.push(request.clone());

        let mut binding = binding_template.clone();
        binding.id = BindingId(key(name));
        binding.request = request.id;
        binding.provider = provider.clone();
        binding.caller_grant.resources = vec![ResourcePermission {
            resource: resource.clone(),
            access: AccessMode::Read,
            operations: vec![key("observe")],
        }];
        binding.provider_grant.principal = provider.clone();
        fixture.binding_plan.bindings.push(binding);
    }
    fixture
        .binding_inputs
        .desired_state
        .child_requests
        .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
    fixture
        .binding_plan
        .requests
        .sort_by(|left, right| compare_request_ids(&left.id, &right.id));
    fixture
        .binding_plan
        .bindings
        .sort_by(|left, right| left.id.cmp(&right.id));

    let template = fixture.effect_plan.operations[0].clone();
    let mut ready_b = template.clone();
    ready_b.key = scoped("ready-b");
    let mut ready_c = template.clone();
    ready_c.key = scoped("ready-c");
    ready_c.binding = BindingId(key("b"));
    ready_c.target.resource = resource_b.clone();
    ready_c.accesses[0].resource = resource_b;
    let mut use_c = template;
    use_c.key = scoped("use-c");
    use_c.binding = BindingId(key("c"));
    use_c.target.resource = resource_c.clone();
    use_c.accesses[0].resource = resource_c;
    fixture.effect_plan.operations = vec![ready_b, ready_c, use_c];
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.provider_readiness = vec![
        ProviderReadiness {
            binding: BindingId(key("b")),
            producer: scoped("ready-b"),
            output: key("ready"),
        },
        ProviderReadiness {
            binding: BindingId(key("c")),
            producer: scoped("ready-c"),
            output: key("ready"),
        },
    ];
    fixture.effect_plan.edges = vec![
        DependencyEdge {
            from: operation_node("ready-b"),
            to: operation_node("ready-c"),
            kind: DependencyKind::Readiness,
        },
        DependencyEdge {
            from: operation_node("ready-c"),
            to: operation_node("use-c"),
            kind: DependencyKind::Readiness,
        },
    ];
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_interface();
    fixture
}

/// Builds a checked two-stage provider-readiness chain rooted in available inventory.
///
/// # Panics
///
/// Panics only if the shared static fixture fails production validation.
#[must_use]
pub fn checked_planned_provider_chain() -> CheckedEffectPlan {
    planned_provider_chain_fixture()
        .validate()
        .expect("static planned-provider chain must pass production validation")
}

pub(crate) fn operation_node(name: &str) -> PlanNodeKey {
    PlanNodeKey::Operation { key: scoped(name) }
}

pub(crate) fn scoped(name: &str) -> ScopedOperationKey {
    ScopedOperationKey {
        scope: ScopePath::root(),
        key: key(name),
    }
}

fn interface_document() -> InterfaceDocument {
    InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            description: "Describes this declaration.".to_string(),
            name: InterfaceName::new("test.service").expect("valid test interface name"),
            abi: NonZeroU32::new(1).expect("positive test ABI"),
            request: ValueSchema::Boolean,
            configuration: None,
            outputs: BTreeMap::new(),
            methods: BTreeMap::from([(
                key("observe"),
                MethodDescriptor {
                    description: "Describes this declaration.".to_string(),
                    semantics: MethodSemantics::ordinary(AccessMode::Read),
                    parameters: ValueSchema::Boolean,
                    target_resource: InterfaceName::new("test.service")
                        .expect("valid test resource interface"),
                    outputs: BTreeMap::from([(
                        key("ready"),
                        OutputDescriptor {
                            description: "Describes this declaration.".to_string(),
                            schema: ValueSchema::Boolean,
                            phase: ValuePhase::Observation,
                            visibility: ValueVisibility::Protected,
                            lifetime: ResourceLifetime::Attempt,
                        },
                    )]),
                    permitted_operations: vec![key("observe")],
                    guarantees: Vec::new(),
                    outcome: OutcomeSemantics {
                        completion_evidence: ValueSchema::Boolean,
                        observation_evidence: ValueSchema::Boolean,
                        supports_rejected_before_effect: true,
                        indeterminate: IndeterminateSemantics::InterventionRequired,
                    },
                },
            )]),
            lifecycle: LifecycleSemantics {
                persistent_delete_method: None,
            },
            aggregation: AggregationContract {
                scope: AggregationScope::ProviderInstance,
                key: key("slot"),
                controller_group: key("test-service"),
                reject_slot_collisions: true,
                merge_contract: None,
            },
            guarantees: Vec::new(),
        },
    }
}

/// Builds a neutral lifecycle interface for validator tests.
#[must_use]
pub fn test_lifecycle_interface() -> InterfaceDocument {
    let mut document = interface_document();
    let interface_name = InterfaceName::new("test.lifecycle").expect("valid test interface");
    let mut observe = document
        .interface
        .methods
        .remove(&key("observe"))
        .expect("observe method");
    observe.target_resource = interface_name.clone();

    let mut start = observe.clone();
    start.semantics = MethodSemantics::ordinary(AccessMode::ExclusiveWrite);
    start.permitted_operations = vec![key("start")];

    let mut stop = start.clone();
    stop.semantics = MethodSemantics::provider_stop();
    stop.permitted_operations = vec![key("stop")];

    document.interface.name = interface_name;
    document.interface.methods = BTreeMap::from([
        (key("observe"), observe),
        (key("start"), start),
        (key("stop"), stop),
    ]);
    document
}

/// Builds the exact guarantee used by neutral manager fixtures.
#[must_use]
pub fn test_manager_guarantee() -> GuaranteeKey {
    GuaranteeDeclaration {
        name: InterfaceName::new("test.manager-guarantee").expect("valid guarantee name"),
        version: NonZeroU32::new(1).expect("positive guarantee version"),
        semantics: "the selected fixture provider controls the target lifecycle".to_string(),
        description: "Supplies lifecycle control in tests.".to_string(),
    }
    .key()
    .expect("test guarantee must have a canonical key")
}

/// Builds a lifecycle-manager interface used only by checked-plan fixtures.
#[must_use]
pub fn test_manager_interface() -> InterfaceDocument {
    let mut document = test_lifecycle_interface();
    let interface_name = InterfaceName::new("test.manager").expect("valid test interface");
    let request = ValueSchema::Record {
        fields: BTreeMap::from([(
            key("subject"),
            ValueSchema::String {
                max_length: 256,
                syntax: None,
            },
        )]),
        optional_fields: Vec::new(),
    };

    document.interface.name = interface_name.clone();
    document.interface.request = request.clone();
    document.interface.guarantees = vec![test_manager_guarantee()];
    document.interface.aggregation.controller_group = key("manager");
    document.interface.methods.remove(&key("stop"));
    for method in document.interface.methods.values_mut() {
        method.target_resource = interface_name.clone();
        method.parameters = request.clone();
        method.outcome.indeterminate = IndeterminateSemantics::Reconcile;
    }
    document
}

/// Returns the test-only terminal handler key.
#[must_use]
pub fn test_manager_handler_key() -> LocalKey {
    key("test-manager-handler")
}

/// Builds a test-only terminal handler descriptor.
#[must_use]
pub fn test_manager_handler(artifact: ArtifactReference) -> HandlerDescriptor {
    HandlerDescriptor {
        artifact,
        entry_point: "libexec/test-manager-handler".to_string(),
        arguments: test_manager_interface().interface.request,
        result: ValueSchema::Boolean,
    }
}

/// Builds a test-only terminal provider descriptor.
#[must_use]
pub fn test_manager_provider(artifact: ArtifactReference) -> ProviderImplementation {
    let interface = test_manager_interface()
        .interface_key()
        .expect("test manager interface must digest");
    let handler = test_manager_handler_key();

    ProviderImplementation {
        name: handler.clone(),
        description: "Controls the neutral test lifecycle resource.".to_string(),
        interface: interface.clone(),
        methods: Vec::new(),
        guarantees: Vec::new(),
        artifact,
        requirements: Vec::new(),
        desired_schema: None,
        composition_schema: None,
        provider_module: None,
        handler: Some(handler),
        owns_resource_kinds: vec![interface.name],
        state_format: None,
    }
}

pub(crate) fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid static test key")
}

pub(crate) fn digest(digit: char) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{}", digit.to_string().repeat(64)))
        .expect("valid static test digest")
}

#[cfg(test)]
mod tests {
    use super::{
        checked_effect_plan, checked_lifecycle_effect_plan, checked_stateful_owner_effect_plan,
    };

    #[test]
    fn fixture_passes_production_validators() {
        let plan = checked_effect_plan();

        assert!(plan.is_executable());
        assert_eq!(plan.operations().len(), 1);
    }

    #[test]
    fn lifecycle_fixture_passes_production_validators() {
        let plan = checked_lifecycle_effect_plan();

        assert!(plan.is_executable());
        assert_eq!(plan.operations()[0].method.as_str(), "start");
    }

    #[test]
    fn stateful_owner_fixture_passes_production_validators() {
        let plan = checked_stateful_owner_effect_plan();

        assert!(plan.is_executable());
        assert_eq!(plan.operations().len(), 1);
    }
}
