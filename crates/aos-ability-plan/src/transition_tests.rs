//! Transition-construction and replay regressions.

use std::collections::BTreeMap;

use aos_ability_model::document::{DesiredInstance, PackageSubject, ProviderState};
use aos_ability_model::*;
use aos_ability_validate::ValidationContext;

use crate::test_support::verified_planning_transition_fixture;
use crate::{
    BindingCandidate, CandidateSelection, CompositionContext, CompositionEvaluator,
    CompositionFragment, EvaluationError, PlanningReplayInputs, PlanningSnapshot,
    RecursiveComposer, ResolutionPolicyDocument, TRANSITION_FRAGMENT_SCHEMA, TransitionContext,
    TransitionError, TransitionEvaluationResult, TransitionExport, TransitionExportKind,
    TransitionFragment, TransitionImport, TransitionImportDirection, TransitionInputs,
    TransitionLimits, TransitionLink, TransitionPlanner, TransitionReplayInputs,
    TransitionSnapshot, TransitionSnapshotError, VerifiedPlanningSnapshot,
};

struct EmptyTransitionEvaluator {
    contexts: Vec<TransitionContext>,
}

impl EmptyTransitionEvaluator {
    const fn new() -> Self {
        Self {
            contexts: Vec::new(),
        }
    }
}

impl CompositionEvaluator for EmptyTransitionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        self.contexts.push(context);

        empty_fragment_value()
    }
}

struct FailingTransitionEvaluator;

impl CompositionEvaluator for FailingTransitionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _entry: &LocalKey,
        _input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        Err(EvaluationError::new("deterministic transition failure"))
    }
}

#[test]
fn transition_snapshot_round_trips_and_replays_without_provider_execution() {
    let (context, planning, transition) = verified_planning_transition_fixture();
    let bytes = transition
        .snapshot()
        .canonical_bytes()
        .expect("fixture transition snapshot must encode");
    let snapshot = TransitionSnapshot::decode(&bytes)
        .expect("canonical fixture transition snapshot must decode");
    let replayed = snapshot
        .verify_structure(
            &TransitionPlanner::new(&context),
            TransitionReplayInputs {
                expected_digest: transition.snapshot_digest(),
                desired: &planning,
                current: None,
            },
        )
        .expect("retained transition transcript must reconstruct the graph");

    assert_eq!(replayed.effect_plan(), transition.effect_plan());
    assert_eq!(replayed.snapshot_digest(), transition.snapshot_digest());
}

#[test]
fn transition_snapshot_requires_its_independent_planning_commitments() {
    let (context, planning, transition) = verified_planning_transition_fixture();
    let error = transition
        .snapshot()
        .verify_structure(
            &TransitionPlanner::new(&context),
            TransitionReplayInputs {
                expected_digest: transition.snapshot_digest(),
                desired: &planning,
                current: Some(&planning),
            },
        )
        .expect_err("adding an uncommitted prior plan must fail closed");

    assert!(matches!(
        error,
        TransitionSnapshotError::PlanningCommitmentMismatch
    ));
}

#[test]
fn provider_receives_scoped_state_observations_and_snapshot_commitments() {
    let (context, planning, _) = verified_planning_transition_fixture();
    let mut evaluator = EmptyTransitionEvaluator::new();
    let transition = TransitionPlanner::new(&context)
        .plan(
            &planning,
            TransitionInputs { current: None },
            &mut evaluator,
        )
        .expect("empty transition fragment must validate");
    let [provider_context] = evaluator.contexts.as_slice() else {
        panic!("fixture must evaluate exactly one pure transition provider");
    };

    assert_eq!(
        provider_context.desired_planning,
        planning.snapshot_digest()
    );
    assert_eq!(provider_context.current_planning, None);
    assert_eq!(provider_context.before, None);
    assert_eq!(provider_context.after.instances.len(), 0);
    assert_eq!(provider_context.after.bindings.len(), 1);
    assert_eq!(provider_context.observations.providers.len(), 1);
    assert_eq!(
        transition.snapshot().evaluations()[0].input.as_json(),
        &serde_json::to_value(provider_context).expect("context must serialize")
    );
}

#[test]
fn evaluator_failure_retains_the_exact_failed_exchange() {
    let (context, planning, _) = verified_planning_transition_fixture();
    let error = TransitionPlanner::new(&context)
        .plan(
            &planning,
            TransitionInputs { current: None },
            &mut FailingTransitionEvaluator,
        )
        .expect_err("provider evaluator failure must abort transition planning");

    let TransitionError::Evaluation {
        provider,
        message,
        evaluation,
    } = error
    else {
        panic!("failure must retain the exact evaluator exchange");
    };
    assert_eq!(provider, evaluation.provider);
    assert_eq!(message, "deterministic transition failure");
    assert!(matches!(
        evaluation.result,
        TransitionEvaluationResult::Failed { message }
            if message == "deterministic transition failure"
    ));
}

#[test]
fn configured_evaluation_byte_limit_cannot_exceed_the_v1_ceiling() {
    let limits = TransitionLimits {
        max_evaluation_bytes: ABILITY_LIMITS_V1.max_document_bytes + 1,
        ..TransitionLimits::default()
    };
    let context = aos_ability_validate::test_support::plan_fixture().context;

    assert!(matches!(
        TransitionPlanner::new(&context).with_limits(limits),
        Err(TransitionError::Limit {
            limit: "configured transition"
        })
    ));
}

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
            TransitionInputs { current: None },
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

struct EmptyCompositionEvaluator;

impl CompositionEvaluator for EmptyCompositionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let _: CompositionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        let fragment = CompositionFragment {
            schema: "aos.ability.composition-fragment/v1".to_string(),
            requests: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
            outputs: Vec::new(),
            controllers: Vec::new(),
        };
        AbilityValue::new(
            serde_json::to_value(fragment)
                .map_err(|error| EvaluationError::new(error.to_string()))?,
        )
        .map_err(|error| EvaluationError::new(error.to_string()))
    }
}

fn pipeline_planning_fixture() -> PipelinePlanningFixture {
    let source = aos_ability_validate::test_support::plan_fixture();
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
    let compose_entry = key("compose");
    let transition_entry = key("transition");
    let pure_implementation = ProviderImplementation {
        interface: interface.clone(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        implementation: ImplementationKind::PureComposition {
            compose_entry: compose_entry.clone(),
            transition_entry: transition_entry.clone(),
        },
        owns_resource_kinds: Vec::new(),
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
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::StructuredEffects,
        package: PackageSubject {
            name: key("pipeline-pure"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact.clone()],
        exports: vec![ExportDeclaration {
            name: key("provider"),
            interface: interface.clone(),
            aggregation: None,
            implementation: pure_descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::from([
            (compose_entry, artifact.clone()),
            (transition_entry, artifact.clone()),
        ]),
        implementation: PackageImplementation {
            providers: vec![pure_implementation],
            handlers: BTreeMap::new(),
        },
        ownership: Vec::new(),
    };
    let pure_package_digest = pure_package
        .content_digest()
        .expect("pure pipeline package must have a digest");
    let handler_key = key("observe-handler");
    let terminal_implementation = ProviderImplementation {
        interface: interface.clone(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        implementation: ImplementationKind::TerminalHandler {
            handler: handler_key.clone(),
        },
        owns_resource_kinds: vec![interface.name.clone()],
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
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::StructuredEffects,
        package: PackageSubject {
            name: key("pipeline-terminal"),
            version: "1.0.0".to_string(),
            payload: terminal_payload.clone(),
            source: terminal_source.clone(),
        },
        artifacts: vec![artifact.clone()],
        exports: vec![ExportDeclaration {
            name: key("provider"),
            interface: interface.clone(),
            aggregation: None,
            implementation: terminal_reference.descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::new(),
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
        ownership: Vec::new(),
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
        ("a-root", application, root.clone(), true),
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
            id: RequestId {
                consumer: consumer.clone(),
                scope: ScopePath::root(),
                key: key(name),
            },
            accepted_interfaces: vec![interface.clone()],
            methods: vec![key("observe")],
            guarantees: Vec::new(),
            lifetime: ResourceLifetime::Instance,
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
            },
            DesiredInstance {
                instance: root.clone(),
                package: pure_package_digest,
                enabled: true,
            },
            DesiredInstance {
                instance: service.clone(),
                package: pure_package_digest,
                enabled: true,
            },
            DesiredInstance {
                instance: terminal.clone(),
                package: terminal_package_digest,
                enabled: true,
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
    let packages = vec![pure_package, terminal_package];
    let policies = vec![policy];
    let mut composition_evaluator = EmptyCompositionEvaluator;
    let outcome = RecursiveComposer::new(&source.context)
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
            &RecursiveComposer::new(&source.context),
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
        context: source.context,
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

fn instance(environment: &EnvironmentId, name: &str) -> InstanceId {
    InstanceId {
        environment: environment.clone(),
        key: key(name),
    }
}

fn distinct_artifact(template: &ArtifactReference, byte: u8, name: &str) -> ArtifactReference {
    ArtifactReference {
        content: aos_contract::Sha256Digest::from_bytes([byte; 32]),
        store_path: format!("/nix/store/00000000000000000000000000000000-{name}"),
        nar_hash: template.nar_hash,
        closure: template.closure,
    }
}

fn operation_scope_for(provider: &InstanceId, descriptor: aos_contract::Sha256Digest) -> ScopePath {
    ScopePath::new(vec![provider.key.clone(), key(&descriptor.hex())])
        .expect("pipeline operation scope must be valid")
}

fn scoped_key(scope: &ScopePath, name: &str) -> ScopedOperationKey {
    ScopedOperationKey {
        scope: scope.clone(),
        key: key(name),
    }
}

fn operation_node(scope: &ScopePath, name: &str) -> PlanNodeKey {
    PlanNodeKey::Operation {
        key: scoped_key(scope, name),
    }
}

fn edge(from: &PlanNodeKey, to: &PlanNodeKey) -> DependencyEdge {
    DependencyEdge {
        from: from.clone(),
        to: to.clone(),
        kind: DependencyKind::RequiredSuccess,
    }
}

fn transition_fragment_value(
    fragment: TransitionFragment,
) -> Result<AbilityValue, EvaluationError> {
    AbilityValue::new(
        serde_json::to_value(fragment).map_err(|error| EvaluationError::new(error.to_string()))?,
    )
    .map_err(|error| EvaluationError::new(error.to_string()))
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("static transition test key must be valid")
}

fn empty_fragment_value() -> Result<AbilityValue, EvaluationError> {
    let fragment = TransitionFragment {
        schema: TRANSITION_FRAGMENT_SCHEMA.to_string(),
        operations: Vec::new(),
        decisions: Vec::new(),
        merges: Vec::new(),
        edges: Vec::new(),
        exports: Vec::new(),
        imports: Vec::new(),
        links: Vec::new(),
        provider_readiness: Vec::new(),
        obligations: Vec::new(),
    };
    AbilityValue::new(
        serde_json::to_value(fragment).map_err(|error| EvaluationError::new(error.to_string()))?,
    )
    .map_err(|error| EvaluationError::new(error.to_string()))
}
