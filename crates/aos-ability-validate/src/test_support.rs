//! Reusable semantically validated ability-plan fixtures for downstream tests.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU32, NonZeroU64};

use aos_ability_model::document::{
    FreshnessCondition, PlatformIdentity, ProviderInventory, ProviderState,
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
        let [interface] = self.interfaces.as_slice() else {
            panic!("the minimal test fixture must contain exactly one interface");
        };
        let interface_key = interface
            .interface_key()
            .expect("test interface must have a canonical key");
        self.context = ValidationContext::new(BTreeSet::new(), self.interfaces.clone())
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
        id: RequestId {
            consumer: provider.clone(),
            scope: ScopePath::root(),
            key: key("service"),
        },
        accepted_interfaces: vec![interface_key.clone()],
        methods: vec![key("observe")],
        guarantees: Vec::new(),
        lifetime: ResourceLifetime::Instance,
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
        outputs: BTreeMap::new(),
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
        implementation,
        source: BindingSource::ExistingPin,
        caller_grant: AuthorityGrant {
            principal: provider.clone(),
            methods: vec![key("observe")],
            resources: vec![permission],
        },
        provider_grant: AuthorityGrant {
            principal: provider,
            methods: Vec::new(),
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
        family: OperationFamily::ObserveReadiness,
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

fn operation_node(name: &str) -> PlanNodeKey {
    PlanNodeKey::Operation { key: scoped(name) }
}

fn scoped(name: &str) -> ScopedOperationKey {
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
            name: InterfaceName::new("test.service").expect("valid test interface name"),
            abi: NonZeroU32::new(1).expect("positive test ABI"),
            request: ValueSchema::Boolean,
            outputs: BTreeMap::new(),
            methods: BTreeMap::from([(
                key("observe"),
                MethodDescriptor {
                    operation_family: OperationFamily::ObserveReadiness,
                    parameters: ValueSchema::Boolean,
                    target_resource: InterfaceName::new("test.service")
                        .expect("valid test resource interface"),
                    outputs: BTreeMap::from([(
                        key("ready"),
                        OutputDescriptor {
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
                stable_resource_identity: true,
                releases_ephemeral_on_disable: true,
                retains_persistent_by_default: true,
                persistent_delete_method: None,
            },
            guarantees: Vec::new(),
        },
    }
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid static test key")
}

fn digest(digit: char) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{}", digit.to_string().repeat(64)))
        .expect("valid static test digest")
}

#[cfg(test)]
mod tests {
    use super::checked_effect_plan;

    #[test]
    fn fixture_passes_production_validators() {
        let plan = checked_effect_plan();

        assert!(plan.is_executable());
        assert_eq!(plan.operations().len(), 1);
    }
}
