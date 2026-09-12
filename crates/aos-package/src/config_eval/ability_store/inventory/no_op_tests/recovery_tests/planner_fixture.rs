//! Production-planner fixtures for integrated recovery tests.

use super::*;

pub(super) struct RealRecoveryPlan {
    pub(super) context: aos_ability_validate::ValidationContext,
    pub(super) planning: VerifiedPlanningSnapshot,
    pub(super) transition: VerifiedTransitionPlan,
    pub(super) supported_features: BTreeSet<aos_ability_model::RequiredFeature>,
}

impl RealRecoveryPlan {
    pub(super) fn bundle(&self) -> ReloadablePlanBundle {
        ReloadablePlanBundle::from_verified(&self.planning, None, None, &self.transition)
            .expect("real recovery fixture bundle")
    }
}

struct EmptyCompositionEvaluator;

impl CompositionEvaluator for EmptyCompositionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &aos_ability_model::ProviderImplementationReference,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let _: CompositionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        fragment_value(CompositionFragment {
            schema: "aos.ability.composition-fragment/v1".to_string(),
            requests: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
            outputs: Vec::new(),
            controllers: Vec::new(),
        })
    }
}

struct RecoveryTransitionEvaluator {
    operations: Vec<aos_ability_model::Operation>,
    edges: Vec<aos_ability_model::DependencyEdge>,
}

pub(super) struct EmptyRecoveryTransitionEvaluator;

impl CompositionEvaluator for EmptyRecoveryTransitionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &aos_ability_model::ProviderImplementationReference,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let _: TransitionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        transition_fragment_value(TransitionFragment {
            schema: "aos.ability.transition-fragment/v1".to_string(),
            operations: Vec::new(),
            decisions: Vec::new(),
            merges: Vec::new(),
            edges: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            links: Vec::new(),
            handoffs: Vec::new(),
            provider_readiness: Vec::new(),
            obligations: Vec::new(),
        })
    }
}

impl CompositionEvaluator for RecoveryTransitionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &aos_ability_model::ProviderImplementationReference,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context: TransitionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        let binding = context
            .authorized_bindings
            .iter()
            .find(|authorized| authorized.binding.implementation.handler.is_some())
            .ok_or_else(|| EvaluationError::new("stateful fixture lost its terminal binding"))?;
        let operations = self
            .operations
            .iter()
            .cloned()
            .map(|mut operation| {
                operation.key.scope = context.operation_scope.clone();
                operation.binding = binding.binding.id.clone();
                operation
            })
            .collect();

        transition_fragment_value(TransitionFragment {
            schema: "aos.ability.transition-fragment/v1".to_string(),
            operations,
            decisions: Vec::new(),
            merges: Vec::new(),
            edges: self.edges.clone(),
            exports: Vec::new(),
            imports: Vec::new(),
            links: Vec::new(),
            handoffs: Vec::new(),
            provider_readiness: Vec::new(),
            obligations: Vec::new(),
        })
    }
}

pub(super) fn real_recovery_plan(incarnation: &str) -> RealRecoveryPlan {
    real_recovery_plan_with_package(incarnation, "1.0.0")
}

pub(super) fn real_recovery_plan_with_package(
    incarnation: &str,
    package_version: &str,
) -> RealRecoveryPlan {
    real_recovery_plan_with_options(incarnation, package_version, false)
}

pub(super) fn real_retry_recovery_plan(incarnation: &str) -> RealRecoveryPlan {
    real_recovery_plan_with_options(incarnation, "1.0.0", true)
}

fn real_recovery_plan_with_options(
    incarnation: &str,
    package_version: &str,
    retry_after_reconciliation: bool,
) -> RealRecoveryPlan {
    let mut source = stateful_owner_plan_fixture();
    let terminal_binding_index = source
        .binding_plan
        .bindings
        .iter()
        .position(|binding| binding.id == source.effect_plan.operations[0].binding)
        .expect("stateful recovery terminal binding");
    let old_interface = source.binding_plan.bindings[terminal_binding_index]
        .interface
        .clone();
    let old_implementation = source.binding_plan.bindings[terminal_binding_index]
        .implementation
        .clone();
    source.binding_inputs.packages[0].package.version = package_version.to_string();
    if retry_after_reconciliation {
        let interface = source
            .interfaces
            .iter_mut()
            .find(|document| document.interface_key().ok().as_ref() == Some(&old_interface))
            .expect("stateful recovery terminal interface");
        interface
            .interface
            .methods
            .get_mut(&key("observe"))
            .expect("stateful recovery observation method")
            .outcome
            .indeterminate = aos_ability_model::IndeterminateSemantics::Reconcile;
        let terminal_interface = interface
            .interface_key()
            .expect("stateful recovery interface key");
        let terminal_implementation = source.binding_inputs.packages[0]
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
            .expect("stateful recovery terminal implementation");
        terminal_implementation.interface = terminal_interface.clone();
        let terminal_descriptor = terminal_implementation
            .descriptor_digest()
            .expect("stateful recovery terminal implementation digest");
        let terminal_reference = aos_ability_model::ProviderImplementationReference {
            descriptor: terminal_descriptor,
            artifact: old_implementation.artifact.clone(),
            handler: old_implementation.handler.clone(),
        };
        let terminal_export = source.binding_inputs.packages[0]
            .exports
            .iter_mut()
            .find(|export| export.implementation == old_implementation.descriptor)
            .expect("stateful recovery terminal export");
        terminal_export.interface = terminal_interface.clone();
        terminal_export.implementation = terminal_descriptor;
        for inventory in &mut source.binding_inputs.environment.providers {
            if inventory.interface == old_interface
                && inventory.implementation == old_implementation
            {
                inventory.interface = terminal_interface.clone();
                inventory.implementation = terminal_reference.clone();
            }
        }
        for request in &mut source.binding_inputs.desired_state.child_requests {
            if request.id == source.binding_plan.bindings[terminal_binding_index].request {
                request.accepted_interfaces = vec![terminal_interface.clone()];
            }
        }
        for request in &mut source.binding_plan.requests {
            if request.id == source.binding_plan.bindings[terminal_binding_index].request {
                request.accepted_interfaces = vec![terminal_interface.clone()];
            }
        }
        source.binding_plan.bindings[terminal_binding_index].interface = terminal_interface.clone();
        source.binding_plan.bindings[terminal_binding_index].implementation = terminal_reference;
        source.effect_plan.operations[0].interface = terminal_interface.clone();
        source.effect_plan.operations[0].target.interface = terminal_interface;
        source.effect_plan.operations[0].recovery.retry = RetryPolicy::Bounded {
            max_attempts: std::num::NonZeroU32::new(2).expect("positive retry count"),
            backoff_millis: 0,
        };
        source.effect_plan.operations[0].recovery.reconcile =
            Some(aos_ability_model::MethodReference {
                interface: source.effect_plan.operations[0].interface.clone(),
                method: source.effect_plan.operations[0].method.clone(),
            });
    }
    let package_digest = source.binding_inputs.packages[0]
        .content_digest()
        .expect("stateful recovery package digest");
    for instance in &mut source.binding_inputs.desired_state.instances {
        instance.package = package_digest;
    }
    for binding in &mut source.binding_plan.bindings {
        binding.provider_package = Some(package_digest);
    }
    let mut supported_features = source.context.supported_features().clone();
    supported_features.insert(
        aos_ability_model::RequiredFeature::new(aos_ability_model::PROVIDER_STATE_ADOPTION_V1)
            .expect("valid provider adoption feature"),
    );
    source.context = aos_ability_validate::ValidationContext::new(
        supported_features.clone(),
        source.interfaces.clone(),
    )
    .expect("stateful recovery validation context");
    let owner_consumer = aos_ability_model::InstanceId {
        environment: source.binding_inputs.environment.environment.clone(),
        key: LocalKey::new("owner-client").expect("valid owner consumer key"),
    };
    let mut owner_consumer_inventory = source.binding_inputs.environment.providers[0].clone();
    owner_consumer_inventory.provider = owner_consumer.clone();
    owner_consumer_inventory.state = aos_ability_model::document::ProviderState::Declared;
    owner_consumer_inventory.incarnation = None;
    source
        .binding_inputs
        .environment
        .providers
        .push(owner_consumer_inventory);
    source
        .binding_inputs
        .environment
        .providers
        .sort_by(|left, right| left.provider.cmp(&right.provider));
    let owner_request = source
        .binding_inputs
        .desired_state
        .child_requests
        .iter_mut()
        .find(|request| request.id.key.as_str() == "owner")
        .expect("stateful fixture owner request");
    owner_request.id.consumer = owner_consumer.clone();
    let owner_request = source
        .binding_plan
        .requests
        .iter_mut()
        .find(|request| request.id.key.as_str() == "owner")
        .expect("stateful fixture checked owner request");
    owner_request.id.consumer = owner_consumer.clone();
    let owner_binding = source
        .binding_plan
        .bindings
        .iter_mut()
        .find(|binding| binding.id.0.as_str() == "owner")
        .expect("stateful fixture owner binding");
    owner_binding.request.consumer = owner_consumer.clone();
    owner_binding.caller_grant.principal = owner_consumer;
    let terminal = source
        .binding_inputs
        .environment
        .providers
        .iter_mut()
        .find(|provider| {
            provider.implementation.handler.is_some()
                && provider.state == aos_ability_model::document::ProviderState::Available
        })
        .expect("stateful fixture terminal inventory");
    terminal.incarnation = Some(
        aos_ability_model::IncarnationId::new(incarnation).expect("valid recovery incarnation"),
    );
    source.refresh_commitments();

    let environment = source.binding_inputs.environment.clone();
    let desired = source.binding_inputs.desired_state.clone();
    let packages = source.binding_inputs.packages.clone();
    let mut candidates = source
        .binding_plan
        .bindings
        .iter()
        .map(|binding| BindingCandidate {
            key: binding.id.0.clone(),
            request: binding.request.clone(),
            interface: binding.interface.clone(),
            provider: binding.provider.clone(),
            provider_package: binding
                .provider_package
                .expect("stateful fixture binding package"),
            implementation: binding.implementation.clone(),
            caller_grant: binding.caller_grant.clone(),
            provider_grant: binding.provider_grant.clone(),
            guarantees: binding.guarantees.clone(),
            policy_revision: binding.policy_revision,
            lifetime: binding.lifetime,
            mediation_allowed: binding.mediation_allowed,
            exclusive_resources: Vec::new(),
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.key.cmp(&right.key));
    let mut explicit_bindings = candidates
        .iter()
        .map(|candidate| CandidateSelection {
            request: candidate.request.clone(),
            candidate: candidate.key.clone(),
        })
        .collect::<Vec<_>>();
    explicit_bindings.sort_by(|left, right| left.request.cmp(&right.request));
    let policy = ResolutionPolicyDocument {
        schema: ResolutionPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state: desired.content_digest().expect("desired-state digest"),
        environment: environment.content_digest().expect("environment digest"),
        policy_revision: environment.policy_revision,
        candidates,
        explicit_bindings,
        existing_pins: Vec::new(),
        operator_orders: Vec::new(),
        enabled_providers: Vec::new(),
        obligations: Vec::new(),
    };
    let policies = vec![policy];
    let mut composer = EmptyCompositionEvaluator;
    let outcome = RecursiveComposer::new(&source.context)
        .compose(
            &policies,
            desired.clone(),
            environment.clone(),
            packages.clone(),
            &mut composer,
        )
        .expect("stateful recovery composition");
    let snapshot = PlanningSnapshot::from_outcome(&outcome).expect("recovery planning snapshot");
    let snapshot_digest = snapshot.digest().expect("recovery planning digest");
    let planning = snapshot
        .verify_structure(
            &RecursiveComposer::new(&source.context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &policies,
                seed: desired,
                environment,
                packages,
            },
        )
        .expect("recovery planning replay");
    let mut evaluator = RecoveryTransitionEvaluator {
        operations: vec![source.effect_plan.operations[0].clone()],
        edges: Vec::new(),
    };
    let transition = TransitionPlanner::new(&source.context)
        .plan(
            &planning,
            TransitionInputs {
                current: None,
                authority: None,
                reconciliation: None,
            },
            &mut evaluator,
        )
        .expect("stateful recovery transition");

    RealRecoveryPlan {
        context: source.context,
        planning,
        transition,
        supported_features,
    }
}

pub(super) fn real_recovery_plan_with_later_failure(
    incarnation: &str,
    package_version: &str,
) -> RealRecoveryPlan {
    let mut real = real_recovery_plan_with_package(incarnation, package_version);
    let mut acquisition = real.transition.checked_effect().operations()[0].clone();
    acquisition.key.key = key("acquire");
    let mut later_failure = acquisition.clone();
    later_failure.key.key = key("later-failure");
    later_failure.recovery.retry = RetryPolicy::Disabled;
    let edge = aos_ability_model::DependencyEdge {
        from: aos_ability_model::PlanNodeKey::Operation {
            key: acquisition.key.clone(),
        },
        to: aos_ability_model::PlanNodeKey::Operation {
            key: later_failure.key.clone(),
        },
        kind: aos_ability_model::DependencyKind::RequiredSuccess,
    };
    let mut evaluator = RecoveryTransitionEvaluator {
        operations: vec![acquisition, later_failure],
        edges: vec![edge],
    };
    real.transition = TransitionPlanner::new(&real.context)
        .plan(
            &real.planning,
            TransitionInputs {
                current: None,
                authority: None,
                reconciliation: None,
            },
            &mut evaluator,
        )
        .expect("stateful recovery transition with later failure");
    real
}

fn fragment_value(fragment: CompositionFragment) -> Result<AbilityValue, EvaluationError> {
    AbilityValue::new(
        serde_json::to_value(fragment).map_err(|error| EvaluationError::new(error.to_string()))?,
    )
    .map_err(|error| EvaluationError::new(error.to_string()))
}

fn transition_fragment_value(
    fragment: TransitionFragment,
) -> Result<AbilityValue, EvaluationError> {
    AbilityValue::new(
        serde_json::to_value(fragment).map_err(|error| EvaluationError::new(error.to_string()))?,
    )
    .map_err(|error| EvaluationError::new(error.to_string()))
}
