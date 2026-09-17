//! Transition tests for the checked provider pipeline.

use super::*;

#[test]
fn checked_boundaries_construct_prepare_validate_publish_start_pipeline() {
    let fixture = pipeline_planning_fixture();
    let mut evaluator = PipelineTransitionEvaluator {
        root: fixture.root.clone(),
        configuration: fixture.configuration.clone(),
        service: fixture.service.clone(),
        configuration_binding: BindingId(key("b-configuration")),
        service_binding: BindingId(key("c-service")),
        validation_binding: BindingId(key("d-validation-terminal")),
        configuration_terminal_binding: BindingId(key("e-configuration-terminal")),
        service_terminal_binding: BindingId(key("f-service-terminal")),
        operation_template: fixture.operation_template,
    };
    let transition = TransitionPlanner::new(&fixture.context)
        .plan(
            &fixture.planning,
            TransitionInputs {
                current: None,
                authority: None,
                reconciliation: None,
            },
            &mut evaluator,
        )
        .expect("checked entry and completion boundaries must lower into one valid graph");
    let document = transition.checked_effect().document();
    let config_scope = operation_scope_for(&fixture.configuration, fixture.pure_descriptor);
    let root_scope = operation_scope_for(&fixture.root, fixture.pure_descriptor);
    let service_scope = operation_scope_for(&fixture.service, fixture.pure_descriptor);
    let prepare = operation_node(&config_scope, "prepare");
    let validate = operation_node(&root_scope, "validate");
    let publish = operation_node(&config_scope, "publish");
    let start = operation_node(&service_scope, "start");

    assert_eq!(document.operations.len(), 4);
    assert!(document.edges.contains(&edge(&prepare, &validate)));
    assert!(document.edges.contains(&edge(&validate, &publish)));
    assert!(document.edges.contains(&edge(&publish, &start)));
    assert_eq!(transition.snapshot().evaluations().len(), 3);
    assert!(
        document
            .artifacts
            .iter()
            .any(|artifact| artifact == &fixture.terminal_payload)
    );
    assert!(
        document
            .artifacts
            .iter()
            .any(|artifact| artifact == &fixture.terminal_source)
    );
}

struct PipelinePlanningFixture {
    context: ValidationContext,
    planning: VerifiedPlanningSnapshot,
    root: InstanceId,
    configuration: InstanceId,
    service: InstanceId,
    pure_descriptor: aos_contract::Sha256Digest,
    operation_template: Operation,
    terminal_payload: ArtifactReference,
    terminal_source: ArtifactReference,
}

struct PipelineTransitionEvaluator {
    root: InstanceId,
    configuration: InstanceId,
    service: InstanceId,
    configuration_binding: BindingId,
    service_binding: BindingId,
    validation_binding: BindingId,
    configuration_terminal_binding: BindingId,
    service_terminal_binding: BindingId,
    operation_template: Operation,
}

impl CompositionEvaluator for PipelineTransitionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _module: &aos_ability_model::ModuleLocator,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context: TransitionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        let fragment = if context.provider == self.configuration {
            self.configuration_fragment(&context.operation_scope)
        } else if context.provider == self.root {
            self.root_fragment(&context.operation_scope)
        } else if context.provider == self.service {
            self.service_fragment(&context.operation_scope)
        } else {
            return Err(EvaluationError::new("unexpected pipeline provider"));
        };
        transition_fragment_value(fragment)
    }
}

impl PipelineTransitionEvaluator {
    fn configuration_fragment(&self, scope: &ScopePath) -> TransitionFragment {
        let prepare = self.operation(
            scope,
            "prepare",
            self.configuration_terminal_binding.clone(),
        );
        let publish = self.operation(
            scope,
            "publish",
            self.configuration_terminal_binding.clone(),
        );
        let prepare_node = operation_node(scope, "prepare");
        let publish_node = operation_node(scope, "publish");

        TransitionFragment {
            schema: TRANSITION_FRAGMENT_SCHEMA.to_string(),
            operations: vec![prepare, publish],
            decisions: Vec::new(),
            merges: Vec::new(),
            edges: vec![edge(&prepare_node, &publish_node)],
            exports: vec![
                TransitionExport {
                    key: key("prepared"),
                    kind: TransitionExportKind::Completion,
                    node: prepare_node,
                    outputs: BTreeMap::new(),
                },
                TransitionExport {
                    key: key("publish-entry"),
                    kind: TransitionExportKind::Entry,
                    node: publish_node.clone(),
                    outputs: BTreeMap::new(),
                },
                TransitionExport {
                    key: key("published"),
                    kind: TransitionExportKind::Completion,
                    node: publish_node,
                    outputs: BTreeMap::new(),
                },
            ],
            imports: Vec::new(),
            links: Vec::new(),
            handoffs: Vec::new(),
            provider_readiness: Vec::new(),
            obligations: Vec::new(),
        }
    }

    fn root_fragment(&self, scope: &ScopePath) -> TransitionFragment {
        let validate = self.operation(scope, "validate", self.validation_binding.clone());
        let validate_node = operation_node(scope, "validate");

        TransitionFragment {
            schema: TRANSITION_FRAGMENT_SCHEMA.to_string(),
            operations: vec![validate],
            decisions: Vec::new(),
            merges: Vec::new(),
            edges: Vec::new(),
            exports: Vec::new(),
            imports: vec![
                TransitionImport {
                    binding: self.configuration_binding.clone(),
                    export: key("prepared"),
                    direction: TransitionImportDirection::AfterExport,
                    outputs: Vec::new(),
                    consumer: validate_node.clone(),
                    kind: DependencyKind::RequiredSuccess,
                },
                TransitionImport {
                    binding: self.configuration_binding.clone(),
                    export: key("publish-entry"),
                    direction: TransitionImportDirection::BeforeExport,
                    outputs: Vec::new(),
                    consumer: validate_node,
                    kind: DependencyKind::RequiredSuccess,
                },
            ],
            links: vec![TransitionLink {
                from_binding: self.configuration_binding.clone(),
                from_export: key("published"),
                to_binding: self.service_binding.clone(),
                to_export: key("start-entry"),
                kind: DependencyKind::RequiredSuccess,
            }],
            handoffs: Vec::new(),
            provider_readiness: Vec::new(),
            obligations: Vec::new(),
        }
    }

    fn service_fragment(&self, scope: &ScopePath) -> TransitionFragment {
        let start = self.operation(scope, "start", self.service_terminal_binding.clone());
        let start_node = operation_node(scope, "start");

        TransitionFragment {
            schema: TRANSITION_FRAGMENT_SCHEMA.to_string(),
            operations: vec![start],
            decisions: Vec::new(),
            merges: Vec::new(),
            edges: Vec::new(),
            exports: vec![TransitionExport {
                key: key("start-entry"),
                kind: TransitionExportKind::Entry,
                node: start_node,
                outputs: BTreeMap::new(),
            }],
            imports: Vec::new(),
            links: Vec::new(),
            handoffs: Vec::new(),
            provider_readiness: Vec::new(),
            obligations: Vec::new(),
        }
    }

    fn operation(&self, scope: &ScopePath, name: &str, binding: BindingId) -> Operation {
        let mut operation = self.operation_template.clone();
        operation.key = scoped_key(scope, name);
        operation.binding = binding;
        operation
    }
}

fn pipeline_planning_fixture() -> PipelinePlanningFixture {
    let source = aos_ability_validate::test_support::plan_fixture();
    let context = ValidationContext::new(
        effect_features().into_iter().collect(),
        source.interfaces.clone(),
    )
    .expect("pipeline interface catalog must validate");
    let interface = source.binding_plan.bindings[0].interface.clone();
    let terminal = source.binding_plan.bindings[0].provider.clone();
    let environment_id = terminal.environment.clone();
    let root = instance(&environment_id, "pipeline-root");
    let configuration = instance(&environment_id, "pipeline-configuration");
    let service = instance(&environment_id, "pipeline-service");
    let application = instance(&environment_id, "pipeline-application");
    let artifact = source.binding_plan.bindings[0]
        .implementation
        .artifact
        .clone();
    let pure_implementation = ProviderImplementation {
        name: key("pure"),
        description: "Pure pipeline test implementation.".to_string(),
        interface: interface.clone(),
        methods: Vec::new(),
        guarantees: Vec::new(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        desired_schema: None,
        composition_schema: None,
        provider_module: Some(module_locator(artifact.clone())),
        handler: None,
        owns_resource_kinds: Vec::new(),
        state_format: None,
    };
    let pure_descriptor = pure_implementation
        .descriptor_digest()
        .expect("pure pipeline implementation must have a digest");
    let pure_reference = ProviderImplementationReference {
        descriptor: pure_descriptor,
        artifact: artifact.clone(),
        handler: None,
    };
    let pure_package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: effect_features(),
        package: PackageSubject {
            name: key("pipeline-pure"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
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
            interface: interface.clone(),
            implementation_name: key("provider"),
            implementation: pure_descriptor,
        }],
        requirements: Vec::new(),
        implementation: PackageImplementation {
            providers: vec![pure_implementation],
            handlers: BTreeMap::new(),
        },
        qualification: aos_ability_model::PackageQualification::default(),
    };
    let pure_package_digest = pure_package
        .content_digest()
        .expect("pure pipeline package must have a digest");
    let handler_key = key("observe-handler");
    let terminal_implementation = ProviderImplementation {
        name: key("terminal"),
        description: "Terminal pipeline test implementation.".to_string(),
        interface: interface.clone(),
        methods: Vec::new(),
        guarantees: Vec::new(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        desired_schema: None,
        composition_schema: None,
        provider_module: None,
        handler: Some(handler_key.clone()),
        owns_resource_kinds: vec![interface.name.clone()],
        state_format: None,
    };
    let terminal_reference = ProviderImplementationReference {
        descriptor: terminal_implementation
            .descriptor_digest()
            .expect("terminal pipeline implementation must have a digest"),
        artifact: artifact.clone(),
        handler: Some(handler_key.clone()),
    };
    let terminal_payload = distinct_artifact(&artifact, 0x91, "pipeline-terminal-payload");
    let terminal_source = distinct_artifact(&artifact, 0x92, "pipeline-terminal-source");
    let terminal_package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: effect_features(),
        package: PackageSubject {
            name: key("pipeline-terminal"),
            version: "1.0.0".to_string(),
            payload: terminal_payload.clone(),
            source: terminal_source.clone(),
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
            interface: interface.clone(),
            implementation_name: key("terminal"),
            implementation: terminal_reference.descriptor,
        }],
        requirements: Vec::new(),
        implementation: PackageImplementation {
            providers: vec![terminal_implementation],
            handlers: BTreeMap::from([(
                handler_key,
                HandlerDescriptor {
                    artifact: artifact.clone(),
                    entry_point: "libexec/pipeline-observe".to_string(),
                    arguments: ValueSchema::Boolean,
                    result: ValueSchema::Boolean,
                },
            )]),
        },
        qualification: aos_ability_model::PackageQualification::default(),
    };
    let terminal_package_digest = terminal_package
        .content_digest()
        .expect("terminal pipeline package must have a digest");

    let mut environment = source.binding_inputs.environment;
    environment.providers[0].implementation = terminal_reference.clone();
    for provider in [&configuration, &root, &service] {
        let mut inventory = environment.providers[0].clone();
        inventory.provider = provider.clone();
        inventory.implementation = pure_reference.clone();
        inventory.state = ProviderState::Declared;
        inventory.incarnation = None;
        environment.providers.push(inventory);
    }
    let mut application_inventory = environment.providers[0].clone();
    application_inventory.provider = application.clone();
    application_inventory.state = ProviderState::Declared;
    application_inventory.incarnation = None;
    environment.providers.push(application_inventory);
    environment.providers.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.interface.cmp(&right.interface))
    });
    let environment_digest = environment
        .content_digest()
        .expect("pipeline environment must have a digest");
    let request_specs = [
        ("a-root", application.clone(), root.clone(), true),
        ("b-configuration", root.clone(), configuration.clone(), true),
        ("c-service", root.clone(), service.clone(), true),
        (
            "d-validation-terminal",
            root.clone(),
            terminal.clone(),
            false,
        ),
        (
            "e-configuration-terminal",
            configuration.clone(),
            terminal.clone(),
            false,
        ),
        (
            "f-service-terminal",
            service.clone(),
            terminal.clone(),
            false,
        ),
    ];
    let resource = environment.resources[0].resource.clone();
    let mut requests = Vec::new();
    let mut candidates = Vec::new();
    for (name, consumer, provider, pure) in request_specs {
        let request = BindingRequest {
            package: if consumer == application {
                key("test-package")
            } else {
                pure_package.package.name.clone()
            },
            id: RequestId {
                consumer: consumer.clone(),
                scope: ScopePath::root(),
                key: key(name),
            },
            accepted_interfaces: vec![interface.clone()],
            methods: vec![key("observe")],
            guarantees: Vec::new(),
            lifetime: ResourceLifetime::Instance,
            parameters: ability_value(serde_json::json!(true)),
        };
        let permission = ResourcePermission {
            resource: resource.clone(),
            access: AccessMode::Read,
            operations: vec![key("observe")],
        };
        candidates.push(BindingCandidate {
            key: key(name),
            request: request.id.clone(),
            interface: interface.clone(),
            provider: provider.clone(),
            provider_package: if pure {
                pure_package_digest
            } else {
                terminal_package_digest
            },
            implementation: if pure {
                pure_reference.clone()
            } else {
                terminal_reference.clone()
            },
            caller_grant: AuthorityGrant {
                principal: consumer,
                methods: vec![key("observe")],
                contributions: Vec::new(),
                resources: if pure { Vec::new() } else { vec![permission] },
            },
            provider_grant: AuthorityGrant {
                principal: provider,
                methods: Vec::new(),
                contributions: Vec::new(),
                resources: Vec::new(),
            },
            guarantees: Vec::new(),
            policy_revision: environment.policy_revision,
            lifetime: ResourceLifetime::Instance,
            mediation_allowed: false,
            exclusive_resources: Vec::new(),
        });
        requests.push(request);
    }
    requests.sort_by(|left, right| left.id.cmp(&right.id));
    candidates.sort_by(|left, right| left.key.cmp(&right.key));
    let mut desired = DesiredStateDocument {
        schema: DesiredStateDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        environment: environment_digest,
        instances: vec![
            DesiredInstance {
                instance: configuration.clone(),
                package: pure_package_digest,
                enabled: true,
                configuration: None,
            },
            DesiredInstance {
                instance: root.clone(),
                package: pure_package_digest,
                enabled: true,
                configuration: None,
            },
            DesiredInstance {
                instance: service.clone(),
                package: pure_package_digest,
                enabled: true,
                configuration: None,
            },
            DesiredInstance {
                instance: terminal.clone(),
                package: terminal_package_digest,
                enabled: true,
                configuration: None,
            },
        ],
        contributions: Vec::new(),
        child_requests: requests,
        resources: environment.resources.clone(),
        outputs: Vec::new(),
        controllers: Vec::new(),
    };
    desired
        .instances
        .sort_by(|left, right| left.instance.cmp(&right.instance));
    let desired_digest = desired
        .content_digest()
        .expect("pipeline desired state must have a digest");
    let mut explicit_bindings: Vec<_> = candidates
        .iter()
        .map(|candidate| CandidateSelection {
            request: candidate.request.clone(),
            candidate: candidate.key.clone(),
        })
        .collect();
    explicit_bindings.sort_by(|left, right| left.request.cmp(&right.request));
    let policy = ResolutionPolicyDocument {
        schema: ResolutionPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state: desired_digest,
        environment: environment_digest,
        policy_revision: environment.policy_revision,
        candidates,
        explicit_bindings,
        existing_pins: Vec::new(),
        operator_orders: Vec::new(),
        enabled_providers: Vec::new(),
        obligations: Vec::new(),
    };
    let mut packages = vec![pure_package, terminal_package];
    packages.sort_by_key(|package| {
        package
            .content_digest()
            .expect("pipeline package must digest")
    });
    let policies = vec![policy];
    let mut composition_evaluator = EmptyCompositionEvaluator;
    let outcome = RecursiveComposer::new(&context)
        .compose(
            &policies,
            desired.clone(),
            environment.clone(),
            packages.clone(),
            &mut composition_evaluator,
        )
        .expect("pipeline composition must reach a fixed point");
    let snapshot = PlanningSnapshot::from_outcome(&outcome)
        .expect("pipeline composition must produce a snapshot");
    let snapshot_digest = snapshot.digest().expect("pipeline snapshot must digest");
    let planning = snapshot
        .verify_structure(
            &RecursiveComposer::new(&context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &policies,
                seed: desired,
                environment,
                packages,
            },
        )
        .expect("pipeline planning snapshot must replay");
    let mut operation_template = source.effect_plan.operations[0].clone();
    operation_template.interface = interface.clone();
    operation_template.target.interface = interface;

    PipelinePlanningFixture {
        context,
        planning,
        root,
        configuration,
        service,
        pure_descriptor,
        operation_template,
        terminal_payload,
        terminal_source,
    }
}
