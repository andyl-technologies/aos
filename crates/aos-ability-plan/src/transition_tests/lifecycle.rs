//! Transition tests for lifecycle upgrades and provider retirement.

use super::*;

#[test]
fn package_upgrade_stops_old_provider_and_starts_new_provider_through_exact_roles() {
    let fixture = lifecycle_upgrade_fixture(false);
    let mut evaluator = LifecycleUpgradeEvaluator::new(&fixture);
    let transition = TransitionPlanner::new(&fixture.context)
        .plan(
            &fixture.desired,
            TransitionInputs {
                current: Some(&fixture.current),
                authority: Some(&fixture.authority),
                reconciliation: None,
            },
            &mut evaluator,
        )
        .expect("package replacement must construct checked Stop-old/Start-new effects");
    let operations = &transition.checked_effect().document().operations;

    assert_eq!(operations.len(), 2);
    assert!(operations.iter().any(|operation| {
        operation.binding == fixture.old_manager_binding && operation.method == key("stop")
    }));
    assert!(operations.iter().any(|operation| {
        operation.binding == fixture.new_manager_binding && operation.method == key("start")
    }));
    assert_eq!(evaluator.old_teardown_bindings, 1);
    assert_eq!(evaluator.new_desired_bindings, 1);
    assert_eq!(fixture.old_manager, fixture.new_manager);
    let stop = operations
        .iter()
        .find(|operation| operation.method == key("stop"))
        .expect("Stop operation");
    let start = operations
        .iter()
        .find(|operation| operation.method == key("start"))
        .expect("Start operation");
    assert!(
        transition
            .checked_effect()
            .document()
            .edges
            .contains(&DependencyEdge {
                from: PlanNodeKey::Operation {
                    key: stop.key.clone(),
                },
                to: PlanNodeKey::Operation {
                    key: start.key.clone(),
                },
                kind: DependencyKind::RequiredSuccess,
            })
    );
}

#[test]
fn payload_only_upgrade_evaluates_unchanged_implementation_once_and_retains_both_packages() {
    let fixture = lifecycle_upgrade_fixture(true);
    let mut evaluator = LifecycleUpgradeEvaluator::new(&fixture);
    let transition = TransitionPlanner::new(&fixture.context)
        .plan(
            &fixture.desired,
            TransitionInputs {
                current: Some(&fixture.current),
                authority: Some(&fixture.authority),
                reconciliation: None,
            },
            &mut evaluator,
        )
        .expect("payload-only package replacement must use one exact constructor scope");
    let artifacts = &transition.checked_effect().document().artifacts;

    assert_eq!(transition.snapshot().evaluations().len(), 1);
    assert_eq!(transition.checked_effect().document().operations.len(), 2);
    assert!(artifacts.contains(&fixture.old_payload));
    assert!(artifacts.contains(&fixture.new_payload));
    assert_ne!(fixture.old_package, fixture.new_package);
}

#[test]
fn retained_parent_receives_only_fresh_outgoing_teardown_authority() {
    let fixture = lifecycle_upgrade_fixture(true);
    let outgoing_source = fixture
        .current
        .checked_binding()
        .bindings()
        .iter()
        .find(|binding| binding.request.consumer == fixture.service)
        .expect("retained parent must have an outgoing source binding");
    let outgoing_authority =
        focused_lifecycle_authority(&fixture, &fixture.current, &outgoing_source.id);

    let mut authorized = EmptyTransitionEvaluator::new();
    TransitionPlanner::new(&fixture.context)
        .plan(
            &fixture.current,
            TransitionInputs {
                current: Some(&fixture.current),
                authority: Some(&outgoing_authority),
                reconciliation: None,
            },
            &mut authorized,
        )
        .expect("retained parent must receive fresh outgoing teardown authority");
    let parent = authorized
        .contexts
        .iter()
        .find(|context| context.provider == fixture.service)
        .expect("retained parent transition context");
    assert!(parent.authorized_bindings.iter().any(|binding| {
        matches!(
            binding.authority,
            TransitionBindingAuthority::Teardown { .. }
        )
    }));

    let mut missing = EmptyTransitionEvaluator::new();
    TransitionPlanner::new(&fixture.context)
        .plan(
            &fixture.current,
            TransitionInputs {
                current: Some(&fixture.current),
                authority: None,
                reconciliation: None,
            },
            &mut missing,
        )
        .expect("an unchanged retained plan must remain valid without teardown authority");
    let parent = missing
        .contexts
        .iter()
        .find(|context| context.provider == fixture.service)
        .expect("retained parent transition context");
    assert!(parent.authorized_bindings.iter().all(|binding| {
        !matches!(
            binding.authority,
            TransitionBindingAuthority::Teardown { .. }
        )
    }));

    let foreign_source = fixture
        .current
        .checked_binding()
        .bindings()
        .iter()
        .find(|binding| {
            binding.provider == fixture.service && binding.request.consumer != fixture.service
        })
        .expect("retained parent must have a foreign-consumer source binding");
    let foreign_authority =
        focused_lifecycle_authority(&fixture, &fixture.current, &foreign_source.id);
    let mut foreign = EmptyTransitionEvaluator::new();
    TransitionPlanner::new(&fixture.context)
        .plan(
            &fixture.current,
            TransitionInputs {
                current: Some(&fixture.current),
                authority: Some(&foreign_authority),
                reconciliation: None,
            },
            &mut foreign,
        )
        .expect("foreign-consumer teardown authority may select the retained group");
    let parent = foreign
        .contexts
        .iter()
        .find(|context| context.provider == fixture.service)
        .expect("retained parent transition context");
    assert!(parent.authorized_bindings.iter().all(|binding| {
        !matches!(
            binding.authority,
            TransitionBindingAuthority::Teardown { .. }
        )
    }));

    let replacement_authority =
        focused_lifecycle_authority(&fixture, &fixture.desired, &outgoing_source.id);
    let error = TransitionPlanner::new(&fixture.context)
        .plan(
            &fixture.desired,
            TransitionInputs {
                current: Some(&fixture.current),
                authority: Some(&replacement_authority),
                reconciliation: None,
            },
            &mut EmptyTransitionEvaluator::new(),
        )
        .expect_err("outgoing-only authority must not authorize a package replacement");
    assert!(matches!(
        error,
        TransitionError::MissingTeardownAuthority { provider }
            if provider == fixture.service
    ));
}

fn focused_lifecycle_authority(
    fixture: &LifecycleUpgradeFixture,
    desired: &VerifiedPlanningSnapshot,
    source_binding: &BindingId,
) -> aos_ability_validate::CheckedTransitionAuthority {
    let authorization = fixture
        .authority
        .document()
        .teardown_bindings
        .iter()
        .find(|entry| entry.source_binding == *source_binding)
        .expect("fixture authority must remap the selected source binding")
        .clone();
    let desired_policy_revision = desired.checked_binding().document().policy_revision;
    let prior_policy_revision = fixture.current.checked_binding().document().policy_revision;
    let mut document = fixture.authority.document().clone();
    document.desired_planning = desired.snapshot_digest();
    document.current_planning = fixture.current.snapshot_digest();
    document.desired_policy_revision = desired_policy_revision;
    document.prior_policy_revision = prior_policy_revision;
    document.authorization_policy_revision = desired_policy_revision;
    document.teardown_bindings = vec![authorization];
    document.teardown_providers.clear();
    let digest = document
        .content_digest()
        .expect("focused teardown authority must digest");

    fixture
        .context
        .validate_transition_authority(
            document,
            TransitionAuthorityInputs {
                expected_digest: digest,
                desired_planning: desired.snapshot_digest(),
                current_planning: fixture.current.snapshot_digest(),
                authorization_policy_revision: desired_policy_revision,
                desired: desired.checked_binding(),
                current: fixture.current.checked_binding(),
            },
        )
        .expect("focused teardown authority must validate")
}

#[test]
fn disabled_operator_enabled_root_stops_through_fresh_lower_binding_and_retains_state() {
    let fixture = enabled_root_retirement_fixture();
    let mut evaluator = RootRetirementEvaluator {
        service: fixture.service.clone(),
        manager: fixture.manager.clone(),
        resource: fixture.resource.clone(),
        controller: fixture.controller.clone(),
        operation_template: fixture.operation_template.clone(),
        saw_root_authority: false,
    };
    let transition = TransitionPlanner::new(&fixture.context)
        .plan(
            &fixture.desired,
            TransitionInputs {
                current: Some(&fixture.current),
                authority: Some(&fixture.authority),
                reconciliation: None,
            },
            &mut evaluator,
        )
        .expect("disabled operator-enabled root must construct a checked Stop");
    let [operation] = transition.checked_effect().document().operations.as_slice() else {
        panic!("root retirement must emit exactly one Stop operation");
    };

    assert_eq!(operation.method, key("stop"));
    assert!(evaluator.saw_root_authority);
    assert!(
        fixture
            .desired
            .checked_binding()
            .desired_state()
            .resources
            .iter()
            .any(|revision| revision.resource == fixture.resource)
    );
}

#[test]
fn operator_root_authority_rejects_a_non_constructor_entry_reference() {
    let fixture = enabled_root_retirement_fixture();
    let mut document = fixture.authority.document().clone();
    document.teardown_providers[0].implementation.handler = Some(key("unexpected-handler"));
    let expected_digest = document
        .content_digest()
        .expect("mutated root authority must digest");
    let error = fixture
        .context
        .validate_transition_authority(
            document,
            TransitionAuthorityInputs {
                expected_digest,
                desired_planning: fixture.desired.snapshot_digest(),
                current_planning: fixture.current.snapshot_digest(),
                authorization_policy_revision: fixture
                    .desired
                    .checked_binding()
                    .document()
                    .policy_revision,
                desired: fixture.desired.checked_binding(),
                current: fixture.current.checked_binding(),
            },
        )
        .expect_err("a handler entry cannot stand in for the exact pure root constructor");

    assert!(matches!(
        error,
        TransitionAuthorityError::InvalidDocument(_)
    ));
}

struct EnabledRootRetirementFixture {
    context: ValidationContext,
    desired: VerifiedPlanningSnapshot,
    current: VerifiedPlanningSnapshot,
    authority: aos_ability_validate::CheckedTransitionAuthority,
    service: InstanceId,
    manager: InstanceId,
    resource: ResourceId,
    controller: AggregateId,
    operation_template: Operation,
}

struct RootRetirementEvaluator {
    service: InstanceId,
    manager: InstanceId,
    resource: ResourceId,
    controller: AggregateId,
    operation_template: Operation,
    saw_root_authority: bool,
}

impl CompositionEvaluator for RootRetirementEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _module: &aos_ability_model::ModuleLocator,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context: TransitionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        if context.provider != self.service {
            return empty_fragment_value();
        }
        self.saw_root_authority = context.teardown_provider_authority.is_some();
        let manager_binding = context
            .authorized_bindings
            .iter()
            .find(|authorized| {
                matches!(
                    authorized.authority,
                    TransitionBindingAuthority::Teardown { .. }
                ) && authorized.binding.provider == self.manager
            })
            .ok_or_else(|| EvaluationError::new("missing exact teardown manager binding"))?;
        let operation = lifecycle_operation(
            &self.operation_template,
            &context.operation_scope,
            manager_binding.binding.id.clone(),
            "stop-disabled-root",
            "stop",
            self.resource.clone(),
            self.controller.clone(),
        );
        let fragment = TransitionFragment {
            schema: TRANSITION_FRAGMENT_SCHEMA.to_string(),
            operations: vec![operation],
            decisions: Vec::new(),
            merges: Vec::new(),
            edges: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            links: Vec::new(),
            handoffs: Vec::new(),
            provider_readiness: Vec::new(),
            obligations: Vec::new(),
        };
        AbilityValue::new(
            serde_json::to_value(fragment)
                .map_err(|error| EvaluationError::new(error.to_string()))?,
        )
        .map_err(|error| EvaluationError::new(error.to_string()))
    }
}

fn enabled_root_retirement_fixture() -> EnabledRootRetirementFixture {
    let baseline = lifecycle_upgrade_fixture(true);
    let environment = baseline.current.checked_binding().environment().clone();
    let application = instance(&environment.environment, "upgrade-application");
    let pure_package = baseline
        .current
        .checked_binding()
        .packages()
        .iter()
        .find(|package| {
            package
                .content_digest()
                .is_ok_and(|digest| digest == baseline.old_package)
        })
        .expect("old pure package")
        .clone();
    let terminal_package = baseline
        .current
        .checked_binding()
        .packages()
        .iter()
        .find(|package| {
            package
                .content_digest()
                .is_ok_and(|digest| digest != baseline.old_package)
        })
        .expect("terminal package")
        .clone();
    let terminal_package_digest = terminal_package
        .content_digest()
        .expect("terminal package must digest");
    let current = lifecycle_planning_snapshot(
        &baseline.context,
        environment.clone(),
        pure_package,
        terminal_package,
        &application,
        &baseline.service,
        &baseline.old_manager,
        &baseline.old_resource,
        terminal_package_digest,
        true,
    );
    let desired = removed_lifecycle_snapshot(&baseline.context, environment, &current);

    let source_binding = current.checked_binding().bindings()[0].clone();
    let source_request = current.checked_binding().document().requests[0].clone();
    let mut request = source_request;
    request.id.key = key("teardown-root-manager-request");
    let mut binding = source_binding.clone();
    binding.id = BindingId(key("teardown-root-manager-binding"));
    binding.request = request.id.clone();
    binding.policy_revision = desired.checked_binding().document().policy_revision;
    binding.caller_grant.methods = vec![key("observe"), key("stop")];
    binding.caller_grant.resources[0].operations = vec![key("observe"), key("stop")];
    let enabled = &current.outcome().resolution.policy.enabled_providers[0];
    let enabled_package = current
        .outcome()
        .desired_state
        .instances
        .iter()
        .find(|instance| instance.instance == enabled.instance && instance.enabled)
        .expect("enabled root package selection");
    let authorization_document = TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_planning: desired.snapshot_digest(),
        current_planning: current.snapshot_digest(),
        desired_policy_revision: desired.checked_binding().document().policy_revision,
        prior_policy_revision: current.checked_binding().document().policy_revision,
        authorization_policy_revision: desired.checked_binding().document().policy_revision,
        teardown_bindings: vec![TeardownBindingAuthorization {
            source_binding: source_binding.id,
            request,
            binding,
        }],
        teardown_providers: vec![TeardownProviderAuthorization {
            provider: enabled.instance.clone(),
            implementation: enabled.implementation.clone(),
            package: enabled_package.package,
            policy_revision: desired.checked_binding().document().policy_revision,
        }],
        persistent_deletions: Vec::new(),
        provider_adoptions: Vec::new(),
    };
    let authorization_digest = authorization_document
        .content_digest()
        .expect("root retirement authority must digest");
    let authority = baseline
        .context
        .validate_transition_authority(
            authorization_document,
            TransitionAuthorityInputs {
                expected_digest: authorization_digest,
                desired_planning: desired.snapshot_digest(),
                current_planning: current.snapshot_digest(),
                authorization_policy_revision: desired.checked_binding().document().policy_revision,
                desired: desired.checked_binding(),
                current: current.checked_binding(),
            },
        )
        .expect("root retirement authority must validate");

    EnabledRootRetirementFixture {
        context: baseline.context,
        desired,
        current,
        authority,
        service: baseline.service,
        manager: baseline.old_manager,
        resource: baseline.old_resource,
        controller: baseline.old_controller,
        operation_template: baseline.operation_template,
    }
}

fn removed_lifecycle_snapshot(
    context: &ValidationContext,
    environment: EnvironmentDocument,
    current: &VerifiedPlanningSnapshot,
) -> VerifiedPlanningSnapshot {
    let mut desired = current.outcome().seed.clone();
    desired.instances.clear();
    desired.contributions.clear();
    desired.child_requests.clear();
    desired.outputs.clear();
    let environment_digest = environment
        .content_digest()
        .expect("removal environment must digest");
    desired.environment = environment_digest;
    let desired_digest = desired
        .content_digest()
        .expect("removal desired state must digest");
    let policy = ResolutionPolicyDocument {
        schema: ResolutionPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state: desired_digest,
        environment: environment_digest,
        policy_revision: environment.policy_revision,
        candidates: Vec::new(),
        explicit_bindings: Vec::new(),
        existing_pins: Vec::new(),
        operator_orders: Vec::new(),
        enabled_providers: Vec::new(),
        obligations: Vec::new(),
    };
    let policies = vec![policy];
    let packages = Vec::new();
    let outcome = RecursiveComposer::new(context)
        .compose(
            &policies,
            desired.clone(),
            environment.clone(),
            packages.clone(),
            &mut EmptyCompositionEvaluator,
        )
        .expect("removed root desired state must compose");
    let snapshot = PlanningSnapshot::from_outcome(&outcome)
        .expect("removed root planning snapshot must encode");
    let snapshot_digest = snapshot
        .digest()
        .expect("removed root planning snapshot must digest");
    snapshot
        .verify_structure(
            &RecursiveComposer::new(context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &policies,
                seed: desired,
                environment,
                packages,
            },
        )
        .expect("removed root planning snapshot must replay")
}

struct LifecycleUpgradeFixture {
    context: ValidationContext,
    desired: VerifiedPlanningSnapshot,
    current: VerifiedPlanningSnapshot,
    authority: aos_ability_validate::CheckedTransitionAuthority,
    service: InstanceId,
    old_manager: InstanceId,
    new_manager: InstanceId,
    old_manager_binding: BindingId,
    new_manager_binding: BindingId,
    old_resource: ResourceId,
    new_resource: ResourceId,
    old_controller: AggregateId,
    new_controller: AggregateId,
    old_descriptor: aos_contract::Sha256Digest,
    new_descriptor: aos_contract::Sha256Digest,
    operation_template: Operation,
    old_payload: ArtifactReference,
    new_payload: ArtifactReference,
    old_package: aos_contract::Sha256Digest,
    new_package: aos_contract::Sha256Digest,
}

struct LifecycleUpgradeEvaluator {
    service: InstanceId,
    old_manager: InstanceId,
    new_manager: InstanceId,
    old_resource: ResourceId,
    new_resource: ResourceId,
    old_controller: AggregateId,
    new_controller: AggregateId,
    old_descriptor: aos_contract::Sha256Digest,
    new_descriptor: aos_contract::Sha256Digest,
    operation_template: Operation,
    old_teardown_bindings: usize,
    new_desired_bindings: usize,
}

impl LifecycleUpgradeEvaluator {
    fn new(fixture: &LifecycleUpgradeFixture) -> Self {
        Self {
            service: fixture.service.clone(),
            old_manager: fixture.old_manager.clone(),
            new_manager: fixture.new_manager.clone(),
            old_resource: fixture.old_resource.clone(),
            new_resource: fixture.new_resource.clone(),
            old_controller: fixture.old_controller.clone(),
            new_controller: fixture.new_controller.clone(),
            old_descriptor: fixture.old_descriptor,
            new_descriptor: fixture.new_descriptor,
            operation_template: fixture.operation_template.clone(),
            old_teardown_bindings: 0,
            new_desired_bindings: 0,
        }
    }
}

impl CompositionEvaluator for LifecycleUpgradeEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _module: &aos_ability_model::ModuleLocator,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context: TransitionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        if context.provider != self.service {
            return empty_fragment_value();
        }

        let mut operations = Vec::new();
        for authorized in &context.authorized_bindings {
            let binding = &authorized.binding;
            match (&authorized.authority, &binding.provider) {
                (TransitionBindingAuthority::Teardown { .. }, provider)
                    if provider == &self.old_manager =>
                {
                    self.old_teardown_bindings = self.old_teardown_bindings.saturating_add(1);
                    operations.push(lifecycle_operation(
                        &self.operation_template,
                        &context.operation_scope,
                        binding.id.clone(),
                        "a-stop-old",
                        "stop",
                        self.old_resource.clone(),
                        self.old_controller.clone(),
                    ));
                }
                (TransitionBindingAuthority::Desired, provider)
                    if provider == &self.new_manager =>
                {
                    self.new_desired_bindings = self.new_desired_bindings.saturating_add(1);
                    operations.push(lifecycle_operation(
                        &self.operation_template,
                        &context.operation_scope,
                        binding.id.clone(),
                        "b-start-new",
                        "start",
                        self.new_resource.clone(),
                        self.new_controller.clone(),
                    ));
                }
                _ => {}
            }
        }
        operations.sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
        let edges = if let [stop, start] = operations.as_slice() {
            vec![DependencyEdge {
                from: PlanNodeKey::Operation {
                    key: stop.key.clone(),
                },
                to: PlanNodeKey::Operation {
                    key: start.key.clone(),
                },
                kind: DependencyKind::OrderingOnly,
            }]
        } else {
            Vec::new()
        };
        let mut exports = Vec::new();
        let mut handoffs = Vec::new();
        if self.old_descriptor != self.new_descriptor {
            if let Some(operation) = operations
                .iter()
                .find(|operation| operation.method == key("stop"))
            {
                exports.push(TransitionExport {
                    key: key("stopped"),
                    kind: TransitionExportKind::Completion,
                    node: PlanNodeKey::Operation {
                        key: operation.key.clone(),
                    },
                    outputs: BTreeMap::new(),
                });
            }
            if let Some(operation) = operations
                .iter()
                .find(|operation| operation.method == key("start"))
            {
                exports.push(TransitionExport {
                    key: key("starting"),
                    kind: TransitionExportKind::Entry,
                    node: PlanNodeKey::Operation {
                        key: operation.key.clone(),
                    },
                    outputs: BTreeMap::new(),
                });
                handoffs.push(TransitionHandoff {
                    from_implementation: self.old_descriptor,
                    from_export: key("stopped"),
                    to_implementation: self.new_descriptor,
                    to_export: key("starting"),
                    kind: DependencyKind::RequiredSuccess,
                });
            }
        }
        let fragment = TransitionFragment {
            schema: TRANSITION_FRAGMENT_SCHEMA.to_string(),
            operations,
            decisions: Vec::new(),
            merges: Vec::new(),
            edges,
            exports,
            imports: Vec::new(),
            links: Vec::new(),
            handoffs,
            provider_readiness: Vec::new(),
            obligations: Vec::new(),
        };
        AbilityValue::new(
            serde_json::to_value(fragment)
                .map_err(|error| EvaluationError::new(error.to_string()))?,
        )
        .map_err(|error| EvaluationError::new(error.to_string()))
    }
}

fn lifecycle_operation(
    template: &Operation,
    scope: &ScopePath,
    binding: BindingId,
    key_name: &str,
    method: &str,
    resource: ResourceId,
    controller: AggregateId,
) -> Operation {
    let mut operation = template.clone();
    operation.key = ScopedOperationKey {
        scope: scope.clone(),
        key: key(key_name),
    };
    operation.binding = binding;
    operation.method = key(method);
    operation.target.resource = resource.clone();
    operation.target.operations = vec![operation.method.clone()];
    operation.accesses = vec![ResourceAccess {
        resource,
        mode: AccessMode::ExclusiveWrite,
    }];
    operation.controller = Some(controller);
    operation
}

fn transition_manager_interface() -> InterfaceDocument {
    let mut document = aos_ability_validate::test_support::test_manager_interface();
    let mut stop = aos_ability_validate::test_support::test_lifecycle_interface()
        .interface
        .methods
        .remove(&key("stop"))
        .expect("neutral lifecycle interface must declare Stop");
    stop.target_resource = document.interface.name.clone();
    stop.parameters = document.interface.request.clone();
    stop.outcome.indeterminate = IndeterminateSemantics::Reconcile;
    document.interface.methods.insert(key("stop"), stop);
    document
}

fn lifecycle_upgrade_fixture(payload_only: bool) -> LifecycleUpgradeFixture {
    let source = aos_ability_validate::test_support::checked_lifecycle_effect_plan();
    let interface_document = transition_manager_interface();
    let interface = interface_document
        .interface_key()
        .expect("systemd interface must digest");
    let controller_group = interface_document
        .interface
        .aggregation
        .controller_group
        .clone();
    let context = ValidationContext::new(
        effect_features().into_iter().collect(),
        [interface_document],
    )
    .expect("systemd interface catalog must validate");
    let source_binding = &source.binding_plan().bindings()[0];
    let terminal_artifact = source_binding.implementation.artifact.clone();
    let mut terminal_provider =
        aos_ability_validate::test_support::test_manager_provider(terminal_artifact.clone());
    terminal_provider.interface = interface.clone();
    terminal_provider.desired_schema = Some(ValueSchema::Optional {
        value: Box::new(ValueSchema::Boolean),
    });
    let terminal_reference = ProviderImplementationReference {
        descriptor: terminal_provider
            .descriptor_digest()
            .expect("systemd provider descriptor must digest"),
        artifact: terminal_artifact.clone(),
        handler: Some(aos_ability_validate::test_support::test_manager_handler_key()),
    };
    let terminal_package =
        terminal_package(&interface, terminal_provider, terminal_artifact.clone());
    let terminal_package_digest = terminal_package
        .content_digest()
        .expect("terminal package must digest");

    let environment_id = source.binding_plan().environment().environment.clone();
    let application = instance(&environment_id, "upgrade-application");
    let service = instance(&environment_id, "upgrade-service");
    let old_manager = instance(&environment_id, "old-manager");
    let new_manager = old_manager.clone();
    let old_resource = ResourceId {
        provider: old_manager.clone(),
        key: key("unit"),
    };
    let new_resource = ResourceId {
        provider: new_manager.clone(),
        key: key("unit"),
    };
    let old_controller = AggregateId {
        provider: old_manager.clone(),
        group: controller_group.clone(),
    };
    let new_controller = AggregateId {
        provider: new_manager.clone(),
        group: controller_group,
    };

    let module_template = distinct_artifact(&terminal_artifact, 0x91, "service-module");
    let old_module = module_template.clone();
    let new_module = if payload_only {
        old_module.clone()
    } else {
        distinct_artifact(&terminal_artifact, 0x92, "service-module-updated")
    };
    let old_payload = distinct_artifact(&terminal_artifact, 0x93, "service-payload-original");
    let new_payload = distinct_artifact(&terminal_artifact, 0x94, "service-payload-updated");
    let old_pure_package =
        pure_service_package(&interface, "1.0.0", old_module, old_payload.clone());
    let new_pure_package =
        pure_service_package(&interface, "2.0.0", new_module, new_payload.clone());
    let old_package = old_pure_package
        .content_digest()
        .expect("old pure package must digest");
    let new_package = new_pure_package
        .content_digest()
        .expect("new pure package must digest");

    let environment = lifecycle_environment(
        source.binding_plan().environment(),
        &application,
        &old_manager,
        &new_manager,
        &interface,
        &terminal_reference,
        &old_resource,
        &new_resource,
        &old_controller,
        &new_controller,
    );
    let current = lifecycle_planning_snapshot(
        &context,
        environment.clone(),
        old_pure_package,
        terminal_package.clone(),
        &application,
        &service,
        &old_manager,
        &old_resource,
        terminal_package_digest,
        false,
    );
    let desired = lifecycle_planning_snapshot(
        &context,
        environment,
        new_pure_package,
        terminal_package,
        &application,
        &service,
        &new_manager,
        &new_resource,
        terminal_package_digest,
        false,
    );
    let old_descriptor = current
        .checked_binding()
        .bindings()
        .iter()
        .find(|binding| binding.provider == service)
        .expect("old service binding")
        .implementation
        .descriptor;
    let new_descriptor = desired
        .checked_binding()
        .bindings()
        .iter()
        .find(|binding| binding.provider == service)
        .expect("new service binding")
        .implementation
        .descriptor;

    let mut teardown_bindings = Vec::new();
    for source in current.checked_binding().bindings() {
        let source_request = current
            .checked_binding()
            .document()
            .requests
            .iter()
            .find(|request| request.id == source.request)
            .expect("source request must exist");
        let mut request = source_request.clone();
        request.id.key = key(&format!("teardown-request-{}", source.id.0));
        let mut binding = source.clone();
        binding.id = BindingId(key(&format!("teardown-binding-{}", source.id.0)));
        binding.request = request.id.clone();
        binding.policy_revision = desired.checked_binding().document().policy_revision;
        if source.request.consumer == service {
            binding.caller_grant.methods = vec![key("observe"), key("stop")];
            binding.caller_grant.resources[0].operations = vec![key("observe"), key("stop")];
        }
        binding.caller_grant.methods.sort();
        binding.caller_grant.methods.dedup();
        binding.provider_grant.methods.sort();
        binding.provider_grant.methods.dedup();
        for permission in binding
            .caller_grant
            .resources
            .iter_mut()
            .chain(binding.provider_grant.resources.iter_mut())
        {
            permission.operations.sort();
            permission.operations.dedup();
        }
        teardown_bindings.push(TeardownBindingAuthorization {
            source_binding: source.id.clone(),
            request,
            binding,
        });
    }
    teardown_bindings.sort_by(|left, right| {
        (&left.source_binding, &left.request.id, &left.binding.id).cmp(&(
            &right.source_binding,
            &right.request.id,
            &right.binding.id,
        ))
    });
    let authorization_document = TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_planning: desired.snapshot_digest(),
        current_planning: current.snapshot_digest(),
        desired_policy_revision: desired.checked_binding().document().policy_revision,
        prior_policy_revision: current.checked_binding().document().policy_revision,
        authorization_policy_revision: desired.checked_binding().document().policy_revision,
        teardown_bindings,
        teardown_providers: Vec::new(),
        persistent_deletions: Vec::new(),
        provider_adoptions: Vec::new(),
    };
    let authorization_digest = authorization_document
        .content_digest()
        .expect("upgrade authorization must digest");
    let authority = context
        .validate_transition_authority(
            authorization_document,
            TransitionAuthorityInputs {
                expected_digest: authorization_digest,
                desired_planning: desired.snapshot_digest(),
                current_planning: current.snapshot_digest(),
                authorization_policy_revision: desired.checked_binding().document().policy_revision,
                desired: desired.checked_binding(),
                current: current.checked_binding(),
            },
        )
        .expect("upgrade transition authority must validate");
    let old_manager_binding = authority
        .document()
        .teardown_bindings
        .iter()
        .find(|entry| entry.binding.provider == old_manager)
        .expect("old manager teardown binding")
        .binding
        .id
        .clone();
    let new_manager_binding = desired
        .checked_binding()
        .bindings()
        .iter()
        .find(|binding| binding.provider == new_manager)
        .expect("new manager desired binding")
        .id
        .clone();

    let mut operation_template = source.operations()[0].clone();
    operation_template.interface = interface.clone();
    operation_template.target.interface = interface;
    for recovery in [
        operation_template.recovery.reconcile.as_mut(),
        operation_template.recovery.cancel.as_mut(),
        operation_template.recovery.compensate.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        recovery.interface = operation_template.interface.clone();
    }

    LifecycleUpgradeFixture {
        context,
        desired,
        current,
        authority,
        service,
        old_manager,
        new_manager,
        old_manager_binding,
        new_manager_binding,
        old_resource,
        new_resource,
        old_controller,
        new_controller,
        old_descriptor,
        new_descriptor,
        operation_template,
        old_payload,
        new_payload,
        old_package,
        new_package,
    }
}
