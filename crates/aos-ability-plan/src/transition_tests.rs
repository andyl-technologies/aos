//! Transition-construction and replay regressions.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::{DesiredInstance, PackageSubject, ProviderState};
use aos_ability_model::*;
use aos_ability_validate::{
    TransitionAuthorityError, TransitionAuthorityInputs, ValidationContext,
};

use crate::test_support::{
    verified_planning_authorized_removal_fixture, verified_planning_transition_fixture,
};
use crate::{
    BindingCandidate, CandidateSelection, CompositionContext, CompositionEvaluator,
    CompositionFragment, EvaluationError, PlanningReplayInputs, PlanningSnapshot,
    RecursiveComposer, ResolutionPolicyDocument, TRANSITION_FRAGMENT_SCHEMA,
    TransitionBindingAuthority, TransitionContext, TransitionError, TransitionEvaluationResult,
    TransitionExport, TransitionExportKind, TransitionFragment, TransitionHandoff,
    TransitionImport, TransitionImportDirection, TransitionInputs, TransitionLimits,
    TransitionLink, TransitionPlanner, TransitionReplayInputs, TransitionSnapshot,
    TransitionSnapshotError, VerifiedPlanningSnapshot,
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
                authority: None,
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
                authority: None,
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
            TransitionInputs {
                current: None,
                authority: None,
            },
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
            TransitionInputs {
                current: None,
                authority: None,
            },
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
fn removed_provider_uses_sealed_current_policy_authority_and_retains_old_package() {
    let (desired, current, authority, fixture_transition) =
        verified_planning_authorized_removal_fixture();
    let context = transition_context(&fixture_transition);
    let old_package = current.checked_binding().packages()[0]
        .content_digest()
        .expect("old package must digest");
    let old_interface = current.checked_binding().bindings()[0].interface.clone();
    let old_payload = current.checked_binding().packages()[0]
        .package
        .payload
        .clone();
    let mut evaluator = EmptyTransitionEvaluator::new();
    let transition = TransitionPlanner::new(&context)
        .plan(
            &desired,
            TransitionInputs {
                current: Some(&current),
                authority: Some(&authority),
            },
            &mut evaluator,
        )
        .expect("removed provider must transition under fresh sealed authority");
    let [provider_context] = evaluator.contexts.as_slice() else {
        panic!("removed pure provider must be evaluated exactly once");
    };

    assert!(provider_context.before.is_some());
    assert!(provider_context.after.bindings.is_empty());
    assert!(
        desired
            .checked_binding()
            .bindings()
            .iter()
            .all(|binding| binding.interface != old_interface)
    );
    assert!(
        fixture_transition
            .checked_effect()
            .interfaces()
            .contains_key(&old_interface)
    );
    assert_eq!(
        transition.transition_authority_digest(),
        Some(authority.digest())
    );
    assert!(
        transition
            .checked_effect()
            .document()
            .artifacts
            .contains(&old_payload)
    );
    assert!(authority.packages().iter().any(|package| {
        package
            .content_digest()
            .is_ok_and(|digest| digest == old_package)
    }));

    let replayed = transition
        .snapshot()
        .verify_structure(
            &TransitionPlanner::new(&context),
            TransitionReplayInputs {
                expected_digest: transition.snapshot_digest(),
                desired: &desired,
                current: Some(&current),
                authority: Some(&authority),
            },
        )
        .expect("teardown authority commitment must replay with the transition");
    assert_eq!(replayed.snapshot_digest(), transition.snapshot_digest());
}

#[test]
fn removed_provider_without_current_authority_fails_closed() {
    let (desired, current, _, transition) = verified_planning_authorized_removal_fixture();
    let context = transition_context(&transition);
    let error = TransitionPlanner::new(&context)
        .plan(
            &desired,
            TransitionInputs {
                current: Some(&current),
                authority: None,
            },
            &mut EmptyTransitionEvaluator::new(),
        )
        .expect_err("historical planning state must not remain live authority");

    assert!(matches!(
        error,
        TransitionError::MissingTeardownAuthority { .. }
    ));
}

#[test]
fn transition_replay_rejects_missing_authority_commitment() {
    let (desired, current, authority, fixture_transition) =
        verified_planning_authorized_removal_fixture();
    let context = transition_context(&fixture_transition);
    let transition = TransitionPlanner::new(&context)
        .plan(
            &desired,
            TransitionInputs {
                current: Some(&current),
                authority: Some(&authority),
            },
            &mut EmptyTransitionEvaluator::new(),
        )
        .expect("authorized removal must plan");
    let error = transition
        .snapshot()
        .verify_structure(
            &TransitionPlanner::new(&context),
            TransitionReplayInputs {
                expected_digest: transition.snapshot_digest(),
                desired: &desired,
                current: Some(&current),
                authority: None,
            },
        )
        .expect_err("dropping committed authority during replay must fail closed");

    assert!(matches!(
        error,
        TransitionSnapshotError::PlanningCommitmentMismatch
    ));
}

fn transition_context(transition: &crate::VerifiedTransitionPlan) -> ValidationContext {
    ValidationContext::new(
        BTreeSet::new(),
        transition.checked_effect().interfaces().values().cloned(),
    )
    .expect("fixture transition interface catalog must validate")
}

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
            },
            &mut evaluator,
        )
        .expect("package replacement must construct checked Stop-old/Start-new effects");
    let operations = &transition.checked_effect().document().operations;

    assert_eq!(operations.len(), 2);
    assert!(operations.iter().any(|operation| {
        operation.binding == fixture.old_manager_binding
            && operation.family
                == OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Stop,
                }
    }));
    assert!(operations.iter().any(|operation| {
        operation.binding == fixture.new_manager_binding
            && operation.family
                == OperationFamily::ServiceLifecycle {
                    action: ServiceAction::Start,
                }
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
            ServiceAction::Stop,
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
                        ServiceAction::Stop,
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
                        ServiceAction::Start,
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
    action: ServiceAction,
    resource: ResourceId,
    controller: AggregateId,
) -> Operation {
    let mut operation = template.clone();
    operation.key = ScopedOperationKey {
        scope: scope.clone(),
        key: key(key_name),
    };
    operation.binding = binding;
    operation.method = match action {
        ServiceAction::Stop => key("stop"),
        ServiceAction::Start => key("start"),
        ServiceAction::Reload | ServiceAction::Restart => unreachable!("static test action"),
    };
    operation.family = OperationFamily::ServiceLifecycle { action };
    operation.target.resource = resource.clone();
    operation.target.operations = vec![operation.method.clone()];
    operation.accesses = vec![ResourceAccess {
        resource,
        mode: AccessMode::ExclusiveWrite,
    }];
    operation.controller = Some(controller);
    operation
}

fn lifecycle_upgrade_fixture(payload_only: bool) -> LifecycleUpgradeFixture {
    let source = aos_ability_validate::test_support::checked_systemd_manager_effect_plan();
    let interface_document = source
        .interfaces()
        .values()
        .next()
        .expect("systemd interface")
        .clone();
    let interface = interface_document
        .interface_key()
        .expect("systemd interface must digest");
    let context = ValidationContext::new(BTreeSet::new(), [interface_document])
        .expect("systemd interface catalog must validate");
    let source_binding = &source.binding_plan().bindings()[0];
    let terminal_artifact = source_binding.implementation.artifact.clone();
    let terminal_provider = builtin::systemd_manager_provider(terminal_artifact.clone())
        .expect("systemd provider contract must construct");
    let terminal_reference = ProviderImplementationReference {
        descriptor: terminal_provider
            .descriptor_digest()
            .expect("systemd provider descriptor must digest"),
        artifact: terminal_artifact.clone(),
        handler: Some(
            builtin::systemd_manager_handler_key()
                .expect("systemd handler identity must construct"),
        ),
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
        group: key("systemd"),
    };
    let new_controller = AggregateId {
        provider: new_manager.clone(),
        group: key("systemd"),
    };

    let module_template = distinct_artifact(&terminal_artifact, 0x91, "service-module");
    let old_module = module_template.clone();
    let new_module = if payload_only {
        old_module.clone()
    } else {
        distinct_artifact(&terminal_artifact, 0x92, "service-module-v2")
    };
    let old_payload = distinct_artifact(&terminal_artifact, 0x93, "service-payload-v1");
    let new_payload = distinct_artifact(&terminal_artifact, 0x94, "service-payload-v2");
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
        operation_template: source.operations()[0].clone(),
        old_payload,
        new_payload,
        old_package,
        new_package,
    }
}

fn pure_service_package(
    interface: &InterfaceKey,
    version: &str,
    module: ArtifactReference,
    payload: ArtifactReference,
) -> PackageDocument {
    let compose_entry = key("compose");
    let transition_entry = key("transition");
    let implementation = ProviderImplementation {
        interface: interface.clone(),
        artifact: module.clone(),
        requirements: Vec::new(),
        implementation: ImplementationKind::PureComposition {
            compose_entry: compose_entry.clone(),
            transition_entry: transition_entry.clone(),
        },
        owns_resource_kinds: Vec::new(),
    };
    let descriptor = implementation
        .descriptor_digest()
        .expect("pure service implementation must digest");
    let mut artifacts = vec![module.clone(), payload.clone()];
    artifacts.sort_by(|left, right| left.content.cmp(&right.content));
    artifacts.dedup();
    PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::StructuredEffects,
        package: PackageSubject {
            name: key("upgrade-service"),
            version: version.to_string(),
            payload: payload.clone(),
            source: payload,
        },
        artifacts,
        exports: vec![ExportDeclaration {
            name: key("service"),
            interface: interface.clone(),
            aggregation: None,
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::from([
            (compose_entry, module.clone()),
            (transition_entry, module),
        ]),
        implementation: PackageImplementation {
            providers: vec![implementation],
            handlers: BTreeMap::new(),
        },
        ownership: Vec::new(),
    }
}

fn terminal_package(
    interface: &InterfaceKey,
    provider: ProviderImplementation,
    artifact: ArtifactReference,
) -> PackageDocument {
    let descriptor = provider
        .descriptor_digest()
        .expect("terminal provider must digest");
    let handler_key =
        builtin::systemd_manager_handler_key().expect("systemd handler identity must construct");
    let handler = builtin::systemd_manager_handler(artifact.clone())
        .expect("systemd handler contract must construct");
    PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::StructuredEffects,
        package: PackageSubject {
            name: key("systemd-terminal"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact],
        exports: vec![ExportDeclaration {
            name: key("manager"),
            interface: interface.clone(),
            aggregation: None,
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::new(),
        implementation: PackageImplementation {
            providers: vec![provider],
            handlers: BTreeMap::from([(handler_key, handler)]),
        },
        ownership: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn lifecycle_environment(
    template: &EnvironmentDocument,
    application: &InstanceId,
    old_manager: &InstanceId,
    new_manager: &InstanceId,
    interface: &InterfaceKey,
    implementation: &ProviderImplementationReference,
    old_resource: &ResourceId,
    new_resource: &ResourceId,
    old_controller: &AggregateId,
    new_controller: &AggregateId,
) -> EnvironmentDocument {
    let mut environment = template.clone();
    let mut inventory = template.providers[0].clone();
    inventory.provider = old_manager.clone();
    inventory.interface = interface.clone();
    inventory.implementation = implementation.clone();
    inventory.state = ProviderState::Available;
    let old_inventory = inventory.clone();
    inventory.provider = new_manager.clone();
    let new_inventory = inventory.clone();
    inventory.provider = application.clone();
    inventory.state = ProviderState::Declared;
    inventory.incarnation = None;
    environment.providers = vec![old_inventory, new_inventory, inventory];
    environment.providers.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.interface.cmp(&right.interface))
    });
    environment.providers.dedup_by(|left, right| {
        left.provider == right.provider && left.interface == right.interface
    });

    environment.resources = vec![
        ResourceRevision {
            resource: old_resource.clone(),
            revision: RevisionId(aos_contract::Sha256Digest::of_bytes("old unit revision")),
        },
        ResourceRevision {
            resource: new_resource.clone(),
            revision: RevisionId(aos_contract::Sha256Digest::of_bytes("new unit revision")),
        },
    ];
    environment
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    environment
        .resources
        .dedup_by(|left, right| left.resource == right.resource);
    environment.controllers = vec![
        ControllerAssignment {
            resource: old_resource.clone(),
            controller: old_controller.clone(),
        },
        ControllerAssignment {
            resource: new_resource.clone(),
            controller: new_controller.clone(),
        },
    ];
    environment
        .controllers
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    environment
        .controllers
        .dedup_by(|left, right| left.resource == right.resource);
    environment
}

#[allow(clippy::too_many_arguments)]
fn lifecycle_planning_snapshot(
    context: &ValidationContext,
    environment: EnvironmentDocument,
    mut pure_package: PackageDocument,
    terminal_package: PackageDocument,
    application: &InstanceId,
    service: &InstanceId,
    manager: &InstanceId,
    resource: &ResourceId,
    terminal_package_digest: aos_contract::Sha256Digest,
    operator_enabled: bool,
) -> VerifiedPlanningSnapshot {
    let interface = pure_package.implementation.providers[0].interface.clone();
    let manager_alias = key("b-manager");
    if operator_enabled {
        let implementation = &mut pure_package.implementation.providers[0];
        implementation.requirements = vec![RequirementDeclaration {
            alias: manager_alias.clone(),
            accepted_interfaces: vec![interface.clone()],
            methods: vec![key("observe"), key("start")],
            guarantees: Vec::new(),
            strength: RequirementStrength::Required,
            fallback: None,
        }];
        let descriptor = implementation
            .descriptor_digest()
            .expect("enabled root implementation must digest");
        pure_package.exports[0].implementation = descriptor;
        pure_package.exports[0].aggregation = Some(AggregationContract {
            scope: AggregationScope::ProviderInstance,
            key: key("service"),
            controller_group: key("service"),
            reject_slot_collisions: true,
            merge_contract: None,
        });
    }

    let pure_package_digest = pure_package
        .content_digest()
        .expect("pure package must digest");
    let pure_implementation = &pure_package.implementation.providers[0];
    let pure_reference = ProviderImplementationReference {
        descriptor: pure_implementation
            .descriptor_digest()
            .expect("pure implementation must digest"),
        artifact: pure_implementation.artifact.clone(),
        handler: None,
    };
    let terminal_implementation = &terminal_package.implementation.providers[0];
    let terminal_reference = ProviderImplementationReference {
        descriptor: terminal_implementation
            .descriptor_digest()
            .expect("terminal implementation must digest"),
        artifact: terminal_implementation.artifact.clone(),
        handler: Some(
            builtin::systemd_manager_handler_key()
                .expect("systemd handler identity must construct"),
        ),
    };
    let service_request = BindingRequest {
        id: RequestId {
            consumer: application.clone(),
            scope: ScopePath::root(),
            key: key("a-service"),
        },
        accepted_interfaces: vec![interface.clone()],
        methods: vec![key("start")],
        guarantees: Vec::new(),
        lifetime: ResourceLifetime::Instance,
    };
    let manager_request = BindingRequest {
        id: if operator_enabled {
            crate::child_request_id(service, manager_alias)
                .expect("enabled root child request must be in scope")
        } else {
            RequestId {
                consumer: service.clone(),
                scope: ScopePath::root(),
                key: manager_alias,
            }
        },
        accepted_interfaces: vec![interface.clone()],
        methods: vec![key("observe"), key("start")],
        guarantees: Vec::new(),
        lifetime: ResourceLifetime::Instance,
    };
    let environment_digest = environment
        .content_digest()
        .expect("lifecycle environment must digest");
    let child_requests = if operator_enabled {
        Vec::new()
    } else {
        vec![service_request.clone(), manager_request.clone()]
    };
    let desired = DesiredStateDocument {
        schema: DesiredStateDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        environment: environment_digest,
        instances: vec![DesiredInstance {
            instance: service.clone(),
            package: pure_package_digest,
            enabled: true,
        }],
        contributions: Vec::new(),
        child_requests,
        resources: environment.resources.clone(),
        outputs: Vec::new(),
        controllers: environment.controllers.clone(),
    };
    let desired_digest = desired
        .content_digest()
        .expect("lifecycle desired state must digest");
    let permission = ResourcePermission {
        resource: resource.clone(),
        access: AccessMode::ExclusiveWrite,
        operations: vec![key("observe"), key("start")],
    };
    let service_candidate = BindingCandidate {
        key: key("a-service"),
        request: service_request.id.clone(),
        interface: interface.clone(),
        provider: service.clone(),
        provider_package: pure_package_digest,
        implementation: pure_reference,
        caller_grant: AuthorityGrant {
            principal: application.clone(),
            methods: vec![key("start")],
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        provider_grant: AuthorityGrant {
            principal: service.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        guarantees: Vec::new(),
        policy_revision: environment.policy_revision,
        lifetime: ResourceLifetime::Instance,
        mediation_allowed: false,
        exclusive_resources: Vec::new(),
    };
    let manager_candidate = BindingCandidate {
        key: key("b-manager"),
        request: manager_request.id.clone(),
        interface,
        provider: manager.clone(),
        provider_package: terminal_package_digest,
        implementation: terminal_reference,
        caller_grant: AuthorityGrant {
            principal: service.clone(),
            methods: vec![key("observe"), key("start")],
            contributions: Vec::new(),
            resources: vec![permission],
        },
        provider_grant: AuthorityGrant {
            principal: manager.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
        },
        guarantees: Vec::new(),
        policy_revision: environment.policy_revision,
        lifetime: ResourceLifetime::Instance,
        mediation_allowed: false,
        exclusive_resources: Vec::new(),
    };
    let enabled_providers = if operator_enabled {
        vec![crate::EnabledProviderSelection {
            instance: service.clone(),
            interface: pure_implementation.interface.clone(),
            implementation: service_candidate.implementation.clone(),
            provider_grant: service_candidate.provider_grant.clone(),
            policy_revision: environment.policy_revision,
            lifetime: ResourceLifetime::Instance,
        }]
    } else {
        Vec::new()
    };
    let policies = if operator_enabled {
        let initial_policy = ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: desired_digest,
            environment: environment_digest,
            policy_revision: environment.policy_revision,
            candidates: Vec::new(),
            explicit_bindings: Vec::new(),
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers: enabled_providers.clone(),
            obligations: Vec::new(),
        };
        let mut expanded = desired.clone();
        expanded.child_requests = vec![manager_request.clone()];
        let expanded_digest = expanded
            .content_digest()
            .expect("enabled root expansion must digest");
        let expanded_policy = ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: expanded_digest,
            environment: environment_digest,
            policy_revision: environment.policy_revision,
            candidates: vec![manager_candidate],
            explicit_bindings: vec![CandidateSelection {
                request: manager_request.id.clone(),
                candidate: key("b-manager"),
            }],
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers,
            obligations: Vec::new(),
        };
        vec![initial_policy, expanded_policy]
    } else {
        let mut candidates = vec![service_candidate, manager_candidate];
        candidates.sort_by(|left, right| left.key.cmp(&right.key));
        let mut explicit_bindings = vec![
            CandidateSelection {
                request: service_request.id,
                candidate: key("a-service"),
            },
            CandidateSelection {
                request: manager_request.id.clone(),
                candidate: key("b-manager"),
            },
        ];
        explicit_bindings.sort_by(|left, right| left.request.cmp(&right.request));
        vec![ResolutionPolicyDocument {
            schema: ResolutionPolicyDocument::SCHEMA.to_string(),
            required_features: Vec::new(),
            desired_state: desired_digest,
            environment: environment_digest,
            policy_revision: environment.policy_revision,
            candidates,
            explicit_bindings,
            existing_pins: Vec::new(),
            operator_orders: Vec::new(),
            enabled_providers,
            obligations: Vec::new(),
        }]
    };
    let mut packages = vec![pure_package, terminal_package];
    packages.sort_by_key(|package| {
        package
            .content_digest()
            .expect("lifecycle package must digest")
    });
    if operator_enabled {
        let selection = &policies[0].enabled_providers[0];
        let package = packages
            .iter()
            .find(|package| {
                package
                    .content_digest()
                    .is_ok_and(|digest| digest == pure_package_digest)
            })
            .expect("enabled pure package");
        let implementation = &package.implementation.providers[0];
        assert_eq!(implementation.interface, selection.interface);
        assert_eq!(implementation.artifact, selection.implementation.artifact);
        assert_eq!(
            implementation
                .descriptor_digest()
                .expect("enabled implementation digest"),
            selection.implementation.descriptor
        );
        assert!(package.exports[0].aggregation.is_some());
        let ImplementationKind::PureComposition {
            compose_entry,
            transition_entry,
        } = &implementation.implementation
        else {
            panic!("enabled root must be a pure implementation");
        };
        assert!(selection.implementation.handler.is_none());
        assert_eq!(
            package.module_entry_points.get(compose_entry),
            Some(&selection.implementation.artifact)
        );
        assert_eq!(
            package.module_entry_points.get(transition_entry),
            Some(&selection.implementation.artifact)
        );
        assert!(selection.provider_grant.methods.iter().all(|method| {
            context
                .interface(&selection.interface)
                .is_some_and(|interface| interface.interface.methods.contains_key(method))
        }));
    }
    let mut composition_evaluator = LifecycleCompositionEvaluator {
        expanding_provider: operator_enabled.then(|| service.clone()),
        manager_request,
    };
    let outcome = RecursiveComposer::new(context)
        .compose(
            &policies,
            desired.clone(),
            environment.clone(),
            packages.clone(),
            &mut composition_evaluator,
        )
        .expect("lifecycle composition must reach a fixed point");
    let snapshot =
        PlanningSnapshot::from_outcome(&outcome).expect("lifecycle planning snapshot must encode");
    let snapshot_digest = snapshot
        .digest()
        .expect("lifecycle planning snapshot must digest");
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
        .expect("lifecycle planning snapshot must replay")
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
            TransitionInputs {
                current: None,
                authority: None,
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

struct EmptyCompositionEvaluator;

struct LifecycleCompositionEvaluator {
    expanding_provider: Option<InstanceId>,
    manager_request: BindingRequest,
}

impl CompositionEvaluator for LifecycleCompositionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context: CompositionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        let requests = if self.expanding_provider.as_ref() == Some(&context.provider) {
            vec![self.manager_request.clone()]
        } else {
            Vec::new()
        };
        let fragment = CompositionFragment {
            schema: "aos.ability.composition-fragment/v1".to_string(),
            requests,
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
        handoffs: Vec::new(),
        provider_readiness: Vec::new(),
        obligations: Vec::new(),
    };
    AbilityValue::new(
        serde_json::to_value(fragment).map_err(|error| EvaluationError::new(error.to_string()))?,
    )
    .map_err(|error| EvaluationError::new(error.to_string()))
}
