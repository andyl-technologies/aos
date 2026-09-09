//! Executable resolver and fixed-point composition regressions.

use std::collections::BTreeMap;

use aos_ability_model::document::{DesiredInstance, PackageSubject};
use aos_ability_model::{
    AbilityActivationMode, AbilityValue, AccessMode, AggregationContract, AggregationScope,
    AuthorityGrant, BindingRequest, DeploymentObligation, DesiredStateDocument, ExportDeclaration,
    ImplementationKind, InstanceId, LocalKey, ObligationKind, PackageDocument,
    PackageImplementation, ProviderImplementation, ProviderImplementationReference, RequestId,
    RequirementDeclaration, RequirementStrength, ResourceLifetime, ResourcePermission, ScopePath,
    VersionedDocument,
};
use aos_ability_validate::ValidationContext;
use aos_contract::Sha256Digest;

use crate::{
    BindingCandidate, CandidateOrder, CompositionContext, CompositionError, CompositionEvaluator,
    CompositionFragment, CompositionLimits, EnabledProviderSelection, EvaluationError,
    ExistingProviderPin, PlanningReplayInputs, PlanningSnapshot, PlanningSnapshotError,
    RecursiveComposer, ResolutionError, ResolutionLimits, ResolutionPolicyDocument, Resolver,
};

struct PlannerFixture {
    context: ValidationContext,
    desired: DesiredStateDocument,
    environment: aos_ability_model::EnvironmentDocument,
    packages: Vec<PackageDocument>,
    policy: ResolutionPolicyDocument,
    provider: InstanceId,
    implementation: ProviderImplementationReference,
    package: Sha256Digest,
}

impl PlannerFixture {
    fn refresh_policy(&mut self) {
        self.desired.environment = self
            .environment
            .content_digest()
            .expect("test environment must have a digest");
        self.policy.desired_state = self
            .desired
            .content_digest()
            .expect("test desired state must have a digest");
        self.policy.environment = self.desired.environment;
    }

    fn enable_provider(&mut self, enabled: bool) {
        self.desired.instances = vec![DesiredInstance {
            instance: self.provider.clone(),
            package: self.package,
            enabled,
        }];
        self.policy.enabled_providers = if enabled {
            vec![EnabledProviderSelection {
                instance: self.provider.clone(),
                interface: self.implementation_interface(),
                implementation: self.implementation.clone(),
                provider_grant: empty_grant(self.provider.clone()),
                policy_revision: self.environment.policy_revision,
                lifetime: ResourceLifetime::Instance,
            }]
        } else {
            Vec::new()
        };
        self.refresh_policy();
    }

    fn implementation_interface(&self) -> aos_ability_model::InterfaceKey {
        self.packages[0].implementation.providers[0]
            .interface
            .clone()
    }
}

#[derive(Default)]
struct EmptyEvaluator {
    calls: usize,
    contexts: Vec<CompositionContext>,
}

struct LowerRequirementEvaluator {
    expanding_provider: InstanceId,
    lower_request: BindingRequest,
    providers: Vec<InstanceId>,
}

impl CompositionEvaluator for LowerRequirementEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context: CompositionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        self.providers.push(context.provider.clone());

        let fragment = CompositionFragment {
            schema: "aos.ability.composition-fragment/v1".to_string(),
            requests: if context.provider == self.expanding_provider {
                vec![self.lower_request.clone()]
            } else {
                Vec::new()
            },
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

impl CompositionEvaluator for EmptyEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        self.calls += 1;
        self.contexts.push(context);

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

#[test]
fn unresolved_request_retains_every_canonical_policy_obligation() {
    let mut fixture = planner_fixture(1);
    let request = fixture.desired.child_requests[0].id.clone();
    fixture.policy.candidates.clear();
    fixture.policy.obligations = two_obligations(&request);

    let outcome = Resolver::new(&fixture.context)
        .resolve(
            &fixture.policy,
            fixture.desired,
            fixture.environment,
            fixture.packages,
        )
        .expect("one unresolved request may retain multiple obligations");

    assert!(outcome.decisions.is_empty());
    assert!(outcome.checked.bindings().is_empty());
    assert_eq!(
        outcome.checked.document().obligations,
        fixture.policy.obligations
    );
}

#[test]
fn obligation_groups_require_canonical_unique_request_and_key_pairs() {
    let mutations: [fn(&mut Vec<DeploymentObligation>); 2] = [
        |obligations: &mut Vec<DeploymentObligation>| obligations.reverse(),
        |obligations: &mut Vec<DeploymentObligation>| {
            obligations[1].key = obligations[0].key.clone();
        },
    ];
    for mutate in mutations {
        let mut fixture = planner_fixture(1);
        let request = fixture.desired.child_requests[0].id.clone();
        fixture.policy.candidates.clear();
        fixture.policy.obligations = two_obligations(&request);
        mutate(&mut fixture.policy.obligations);

        assert!(matches!(
            Resolver::new(&fixture.context).resolve(
                &fixture.policy,
                fixture.desired,
                fixture.environment,
                fixture.packages,
            ),
            Err(ResolutionError::InvalidPolicy(_))
        ));
    }
}

#[test]
fn authenticated_existing_pin_survives_tentative_parent_fallback() {
    let mut fixture = planner_fixture(2);
    let parent_request = fixture.desired.child_requests[0].id.clone();
    let pinned_request = fixture.desired.child_requests[1].id.clone();
    let exclusive = fixture.environment.resources[0].resource.clone();

    let mut parent_first = fixture.policy.candidates[0].clone();
    parent_first.key = key("a-parent-first");
    parent_first.request = parent_request.clone();
    parent_first.exclusive_resources = vec![exclusive.clone()];
    let mut parent_fallback = parent_first.clone();
    parent_fallback.key = key("b-parent-fallback");
    parent_fallback.exclusive_resources.clear();
    let mut pinned = fixture.policy.candidates[1].clone();
    pinned.key = key("c-child-pin");
    pinned.request = pinned_request.clone();
    pinned.exclusive_resources = vec![exclusive];
    fixture.policy.candidates = vec![parent_first, parent_fallback, pinned.clone()];
    fixture.policy.operator_orders = vec![CandidateOrder {
        request: parent_request.clone(),
        candidates: vec![key("a-parent-first"), key("b-parent-fallback")],
    }];
    fixture.policy.existing_pins = vec![ExistingProviderPin {
        request: pinned_request.clone(),
        candidate: pinned.key.clone(),
        provider: pinned.provider.clone(),
        provider_package: pinned.provider_package,
        interface: pinned.interface.clone(),
        implementation: pinned.implementation.clone(),
    }];

    let outcome = Resolver::new(&fixture.context)
        .resolve(
            &fixture.policy,
            fixture.desired,
            fixture.environment,
            fixture.packages,
        )
        .expect("parent may fall back without replacing the authenticated child pin");

    assert_eq!(outcome.decisions[0].candidate, key("b-parent-fallback"));
    assert_eq!(outcome.decisions[1].candidate, key("c-child-pin"));
    assert_eq!(
        outcome.decisions[1].source,
        aos_ability_model::BindingSource::ExistingPin
    );
}

#[test]
fn recursive_parent_fallback_does_not_turn_tentative_choice_into_a_pin() {
    let mut fixture = planner_fixture(2);
    let setup = configure_recursive_fallback(&mut fixture);
    let expanded_policy = policy_for_unresolvable_expansion(&fixture, &setup);
    let policies = vec![fixture.policy.clone(), expanded_policy];
    let mut evaluator = setup.evaluator();

    let outcome = RecursiveComposer::new(&fixture.context)
        .compose(
            &policies,
            fixture.desired.clone(),
            fixture.environment.clone(),
            fixture.packages.clone(),
            &mut evaluator,
        )
        .expect("recursive failure may replace only the tentative parent choice");

    assert_eq!(outcome.resolution.decisions.len(), 2);
    assert_eq!(
        outcome.resolution.decisions[0].candidate,
        key("b-parent-fallback")
    );
    assert_eq!(
        outcome.resolution.decisions[1].candidate,
        key("c-independent-pin")
    );
    assert_eq!(
        outcome.resolution.decisions[1].source,
        aos_ability_model::BindingSource::ExistingPin
    );
    assert!(evaluator.providers.contains(&setup.first_parent));
    assert!(evaluator.providers.contains(&setup.fallback_parent));
    assert!(evaluator.providers.contains(&setup.pinned_provider));

    let snapshot = PlanningSnapshot::from_outcome(&outcome)
        .expect("recursive provenance must fit the snapshot bounds");
    assert_eq!(snapshot.policies().len(), 2);
    assert!(
        snapshot
            .evaluations()
            .iter()
            .any(|evaluation| evaluation.provider == setup.first_parent)
    );
    let bytes = snapshot
        .canonical_bytes()
        .expect("recursive provenance must encode canonically");
    let snapshot_digest = snapshot.digest().expect("snapshot must have a commitment");
    let authenticated_policies = snapshot.policies().to_vec();
    let decoded = PlanningSnapshot::decode(&bytes).expect("snapshot must round trip");
    let verified = decoded
        .verify_structure(
            &RecursiveComposer::new(&fixture.context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &authenticated_policies,
                seed: fixture.desired.clone(),
                environment: fixture.environment.clone(),
                packages: fixture.packages.clone(),
            },
        )
        .expect("retained discarded-branch evidence must reproduce composition");
    assert_eq!(
        verified.checked_binding().id(),
        outcome.resolution.checked.id()
    );
    let mut live_evaluator = setup.evaluator();
    decoded
        .replay_with(
            &RecursiveComposer::new(&fixture.context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &authenticated_policies,
                seed: fixture.desired.clone(),
                environment: fixture.environment.clone(),
                packages: fixture.packages.clone(),
            },
            &mut live_evaluator,
        )
        .expect("live provider replay must reproduce the retained result");

    let tampered = tamper_discarded_policy_revision(&decoded);
    assert!(matches!(
        tampered.verify_structure(
            &RecursiveComposer::new(&fixture.context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &authenticated_policies,
                seed: fixture.desired.clone(),
                environment: fixture.environment.clone(),
                packages: fixture.packages.clone(),
            },
        ),
        Err(PlanningSnapshotError::CommitmentMismatch)
    ));
    let tampered_digest = tampered
        .digest()
        .expect("tampered policy snapshot remains bounded");
    assert!(matches!(
        tampered.verify_structure(
            &RecursiveComposer::new(&fixture.context),
            PlanningReplayInputs {
                expected_digest: tampered_digest,
                authenticated_policies: &authenticated_policies,
                seed: fixture.desired.clone(),
                environment: fixture.environment.clone(),
                packages: fixture.packages.clone(),
            },
        ),
        Err(PlanningSnapshotError::PolicySetMismatch)
    ));

    let transcript_tampered = tamper_first_evaluation_entry(&decoded);
    let transcript_tampered_digest = transcript_tampered
        .digest()
        .expect("tampered transcript remains bounded");
    assert!(matches!(
        transcript_tampered.verify_structure(
            &RecursiveComposer::new(&fixture.context),
            PlanningReplayInputs {
                expected_digest: transcript_tampered_digest,
                authenticated_policies: &authenticated_policies,
                seed: fixture.desired,
                environment: fixture.environment,
                packages: fixture.packages,
            },
        ),
        Err(PlanningSnapshotError::Replay(_))
            | Err(PlanningSnapshotError::ReplayMismatch)
            | Err(PlanningSnapshotError::InvalidTranscript(_))
    ));
}

#[test]
fn invalid_grant_is_rejected_before_pure_evaluation() {
    let mut fixture = planner_fixture(1);
    fixture.policy.candidates[0].caller_grant.principal = fixture.provider.clone();
    let mut evaluator = EmptyEvaluator::default();

    let result = RecursiveComposer::new(&fixture.context).compose(
        std::slice::from_ref(&fixture.policy),
        fixture.desired,
        fixture.environment,
        fixture.packages,
        &mut evaluator,
    );

    assert!(matches!(
        result,
        Err(CompositionError::Resolution(ResolutionError::NoCandidate))
    ));
    assert_eq!(evaluator.calls, 0);
}

#[test]
fn enabled_zero_contributor_provider_is_evaluated_but_disabled_provider_is_not() {
    let mut enabled = planner_fixture(0);
    enabled.enable_provider(true);
    let mut enabled_evaluator = EmptyEvaluator::default();
    RecursiveComposer::new(&enabled.context)
        .compose(
            std::slice::from_ref(&enabled.policy),
            enabled.desired,
            enabled.environment,
            enabled.packages,
            &mut enabled_evaluator,
        )
        .expect("explicitly enabled aggregate remains a composition root");
    assert_eq!(enabled_evaluator.calls, 1);

    let mut disabled = planner_fixture(0);
    disabled.enable_provider(false);
    let mut disabled_evaluator = EmptyEvaluator::default();
    RecursiveComposer::new(&disabled.context)
        .compose(
            std::slice::from_ref(&disabled.policy),
            disabled.desired,
            disabled.environment,
            disabled.packages,
            &mut disabled_evaluator,
        )
        .expect("disabled aggregate has no implicit composition root");
    assert_eq!(disabled_evaluator.calls, 0);
}

#[test]
fn two_parents_share_one_lower_provider_evaluation() {
    let fixture = planner_fixture(2);
    let mut evaluator = EmptyEvaluator::default();
    RecursiveComposer::new(&fixture.context)
        .compose(
            std::slice::from_ref(&fixture.policy),
            fixture.desired,
            fixture.environment,
            fixture.packages,
            &mut evaluator,
        )
        .expect("two consumers may bind one shared provider aggregate");

    assert_eq!(evaluator.calls, 1);
    assert_eq!(evaluator.contexts[0].requests.len(), 2);
}

#[test]
fn failed_candidate_work_stops_at_the_search_bound() {
    let mut fixture = planner_fixture(2);
    let exclusive = fixture.environment.resources[0].resource.clone();
    let mut candidates = Vec::new();
    let mut orders = Vec::new();
    for (request_index, request) in fixture.desired.child_requests.iter().enumerate() {
        let mut keys = Vec::new();
        for candidate_index in 0..2 {
            let mut candidate = fixture.policy.candidates[request_index].clone();
            candidate.key = key(&format!("candidate-{request_index}-{candidate_index}"));
            candidate.exclusive_resources = vec![exclusive.clone()];
            keys.push(candidate.key.clone());
            candidates.push(candidate);
        }
        orders.push(CandidateOrder {
            request: request.id.clone(),
            candidates: keys,
        });
    }
    candidates.sort_by(|left, right| left.key.cmp(&right.key));
    fixture.policy.candidates = candidates;
    fixture.policy.operator_orders = orders;
    let resolver = Resolver::new(&fixture.context)
        .with_limits(ResolutionLimits {
            max_backtracks: 2,
            ..ResolutionLimits::default()
        })
        .expect("small search bound is valid");

    assert!(matches!(
        resolver.resolve(
            &fixture.policy,
            fixture.desired,
            fixture.environment,
            fixture.packages,
        ),
        Err(ResolutionError::SearchExhausted { attempts: 2 })
    ));
}

#[test]
fn recursive_failed_attempts_share_one_composer_search_bound() {
    let mut fixture = planner_fixture(2);
    let setup = configure_recursive_fallback(&mut fixture);
    let expanded_policy = policy_for_unresolvable_expansion(&fixture, &setup);
    let limits = CompositionLimits {
        max_search_attempts: 2,
        ..CompositionLimits::default()
    };
    let composer = RecursiveComposer::new(&fixture.context)
        .with_limits(limits)
        .expect("small aggregate search bound is valid");
    let mut evaluator = setup.evaluator();

    assert!(matches!(
        composer.compose(
            &[fixture.policy.clone(), expanded_policy],
            fixture.desired,
            fixture.environment,
            fixture.packages,
            &mut evaluator,
        ),
        Err(CompositionError::Limit {
            limit: "aggregate candidate search attempt"
        })
    ));
    assert_eq!(
        evaluator
            .providers
            .iter()
            .filter(|provider| **provider == setup.first_parent)
            .count(),
        1
    );
}

struct RecursiveFallbackSetup {
    first_parent: InstanceId,
    fallback_parent: InstanceId,
    pinned_provider: InstanceId,
    lower_request: BindingRequest,
}

impl RecursiveFallbackSetup {
    fn evaluator(&self) -> LowerRequirementEvaluator {
        LowerRequirementEvaluator {
            expanding_provider: self.first_parent.clone(),
            lower_request: self.lower_request.clone(),
            providers: Vec::new(),
        }
    }
}

fn configure_recursive_fallback(fixture: &mut PlannerFixture) -> RecursiveFallbackSetup {
    let parent_request = fixture.desired.child_requests[0].id.clone();
    let pinned_request = fixture.desired.child_requests[1].id.clone();
    let first_parent = fixture.provider.clone();
    let fallback_parent = sibling_instance(&first_parent, "fallback-parent");
    let pinned_provider = sibling_instance(&first_parent, "pinned-provider");
    add_provider_inventory(fixture, &fallback_parent);
    add_provider_inventory(fixture, &pinned_provider);
    let fallback_resource = add_provider_resource(fixture, &fallback_parent);
    let pinned_resource = add_provider_resource(fixture, &pinned_provider);

    let lower_alias = key("lower-service");
    let lower_request = BindingRequest {
        id: crate::child_request_id(&first_parent, lower_alias.clone())
            .expect("test child request is in scope"),
        accepted_interfaces: vec![fixture.implementation_interface()],
        methods: fixture.desired.child_requests[0].methods.clone(),
        guarantees: Vec::new(),
        lifetime: ResourceLifetime::Instance,
    };
    let base_implementation = fixture.implementation.clone();
    let mut recursive_package = fixture.packages[0].clone();
    recursive_package.package.name = key("recursive-provider");
    let recursive_implementation = &mut recursive_package.implementation.providers[0];
    recursive_implementation.requirements = vec![RequirementDeclaration {
        alias: lower_alias,
        accepted_interfaces: lower_request.accepted_interfaces.clone(),
        methods: lower_request.methods.clone(),
        guarantees: Vec::new(),
        strength: RequirementStrength::Required,
        fallback: None,
    }];
    let recursive_entry = key("compose-recursive");
    let ImplementationKind::PureComposition {
        transition_entry, ..
    } = &recursive_implementation.implementation
    else {
        panic!("planner fixture must use pure composition");
    };
    recursive_implementation.implementation = ImplementationKind::PureComposition {
        compose_entry: recursive_entry.clone(),
        transition_entry: transition_entry.clone(),
    };
    let recursive_descriptor = recursive_implementation
        .descriptor_digest()
        .expect("recursive test implementation must have a digest");
    let recursive_reference = ProviderImplementationReference {
        descriptor: recursive_descriptor,
        artifact: base_implementation.artifact.clone(),
        handler: None,
    };
    recursive_package
        .module_entry_points
        .insert(recursive_entry, base_implementation.artifact.clone());
    recursive_package.exports[0].implementation = recursive_descriptor;
    let recursive_package_digest = recursive_package
        .content_digest()
        .expect("recursive test package must have a digest");
    fixture.packages.push(recursive_package);
    fixture.packages.sort_by_key(|package| {
        package
            .content_digest()
            .expect("test package must have a digest")
    });

    for inventory in &mut fixture.environment.providers {
        inventory.implementation = if inventory.provider == first_parent {
            recursive_reference.clone()
        } else {
            base_implementation.clone()
        };
    }

    let mut first_candidate = fixture.policy.candidates[0].clone();
    first_candidate.key = key("a-parent-first");
    first_candidate.request = parent_request.clone();
    first_candidate.provider = first_parent.clone();
    first_candidate.provider_package = recursive_package_digest;
    first_candidate.implementation = recursive_reference;
    first_candidate.provider_grant = empty_grant(first_parent.clone());
    let mut fallback_candidate = first_candidate.clone();
    fallback_candidate.key = key("b-parent-fallback");
    fallback_candidate.provider = fallback_parent.clone();
    fallback_candidate.provider_package = fixture.package;
    fallback_candidate.implementation = base_implementation.clone();
    fallback_candidate.provider_grant = empty_grant(fallback_parent.clone());
    fallback_candidate.caller_grant.resources[0].resource = fallback_resource;
    let mut pinned_candidate = fixture.policy.candidates[1].clone();
    pinned_candidate.key = key("c-independent-pin");
    pinned_candidate.request = pinned_request.clone();
    pinned_candidate.provider = pinned_provider.clone();
    pinned_candidate.provider_package = fixture.package;
    pinned_candidate.implementation = base_implementation;
    pinned_candidate.provider_grant = empty_grant(pinned_provider.clone());
    pinned_candidate.caller_grant.resources[0].resource = pinned_resource;
    fixture.policy.candidates = vec![
        first_candidate,
        fallback_candidate,
        pinned_candidate.clone(),
    ];
    fixture.policy.operator_orders = vec![CandidateOrder {
        request: parent_request,
        candidates: vec![key("a-parent-first"), key("b-parent-fallback")],
    }];
    fixture.policy.existing_pins = vec![ExistingProviderPin {
        request: pinned_request,
        candidate: pinned_candidate.key,
        provider: pinned_candidate.provider,
        provider_package: pinned_candidate.provider_package,
        interface: pinned_candidate.interface,
        implementation: pinned_candidate.implementation,
    }];
    fixture.refresh_policy();

    RecursiveFallbackSetup {
        first_parent,
        fallback_parent,
        pinned_provider,
        lower_request,
    }
}

fn policy_for_unresolvable_expansion(
    fixture: &PlannerFixture,
    setup: &RecursiveFallbackSetup,
) -> ResolutionPolicyDocument {
    let draft = Resolver::new(&fixture.context)
        .resolve_draft_at(
            &fixture.policy,
            &fixture.desired,
            &fixture.environment,
            &fixture.packages,
            0,
        )
        .expect("first recursive resolution must succeed");
    assert_eq!(
        draft.next_combination,
        Some(1),
        "unexpected candidate rejections: {:?}",
        draft.rejections
    );

    let mut evaluator = setup.evaluator();
    let result = RecursiveComposer::new(&fixture.context).compose(
        std::slice::from_ref(&fixture.policy),
        fixture.desired.clone(),
        fixture.environment.clone(),
        fixture.packages.clone(),
        &mut evaluator,
    );
    let desired_state_digest = match result {
        Err(CompositionError::PolicyRequired {
            desired_state_digest,
            ..
        }) => desired_state_digest,
        other => panic!("first recursive expansion must request authenticated policy: {other:?}"),
    };

    let mut expanded_policy = fixture.policy.clone();
    expanded_policy.desired_state = desired_state_digest;
    expanded_policy
}

fn tamper_discarded_policy_revision(snapshot: &PlanningSnapshot) -> PlanningSnapshot {
    let bytes = snapshot
        .canonical_bytes()
        .expect("snapshot must encode canonically");
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("snapshot must be JSON");
    let seed = serde_json::to_value(
        snapshot
            .seed()
            .content_digest()
            .expect("seed must have a digest"),
    )
    .expect("digest must serialize");
    let policies = value["policies"]
        .as_array_mut()
        .expect("snapshot policies must be an array");
    let discarded = policies
        .iter_mut()
        .find(|policy| policy["desired_state"] != seed)
        .expect("recursive snapshot must retain a discarded-branch policy");
    discarded["policy_revision"] = serde_json::to_value(aos_ability_model::RevisionId(
        Sha256Digest::from_bytes([0x9a; 32]),
    ))
    .expect("revision must serialize");
    let tampered_bytes = aos_contract::canonical::canonical_json(&value)
        .expect("tampered snapshot must have a canonical encoding");
    PlanningSnapshot::decode(&tampered_bytes)
        .expect("structurally self-consistent tampering reaches authenticated replay")
}

fn tamper_first_evaluation_entry(snapshot: &PlanningSnapshot) -> PlanningSnapshot {
    let bytes = snapshot
        .canonical_bytes()
        .expect("snapshot must encode canonically");
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("snapshot must be JSON");
    value["evaluations"][0]["entry"] = serde_json::json!("tampered-entry");
    let tampered_bytes = aos_contract::canonical::canonical_json(&value)
        .expect("tampered snapshot must have a canonical encoding");
    PlanningSnapshot::decode(&tampered_bytes)
        .expect("bounded transcript tampering reaches structural replay")
}

fn sibling_instance(instance: &InstanceId, name: &str) -> InstanceId {
    InstanceId {
        environment: instance.environment.clone(),
        key: key(name),
    }
}

fn add_provider_inventory(fixture: &mut PlannerFixture, provider: &InstanceId) {
    let mut inventory = fixture.environment.providers[0].clone();
    inventory.provider = provider.clone();
    fixture.environment.providers.push(inventory);
    fixture.environment.providers.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.interface.cmp(&right.interface))
    });
}

fn add_provider_resource(
    fixture: &mut PlannerFixture,
    provider: &InstanceId,
) -> aos_ability_model::ResourceId {
    let mut revision = fixture.environment.resources[0].clone();
    revision.resource.provider = provider.clone();
    let resource = revision.resource.clone();
    fixture.environment.resources.push(revision);
    fixture.environment.resources.sort_by(|left, right| {
        aos_ability_model::compare_resource_ids(&left.resource, &right.resource)
    });
    resource
}

fn planner_fixture(request_count: usize) -> PlannerFixture {
    let source = aos_ability_validate::test_support::plan_fixture();
    let context = source.context;
    let interface = source.binding_plan.bindings[0].interface.clone();
    let provider = source.binding_plan.bindings[0].provider.clone();
    let artifact = source.binding_plan.bindings[0]
        .implementation
        .artifact
        .clone();
    let compose_entry = key("compose");
    let transition_entry = key("transition");
    let provider_implementation = ProviderImplementation {
        interface: interface.clone(),
        artifact: artifact.clone(),
        requirements: Vec::new(),
        implementation: ImplementationKind::PureComposition {
            compose_entry: compose_entry.clone(),
            transition_entry: transition_entry.clone(),
        },
        owns_resource_kinds: Vec::new(),
    };
    let descriptor = provider_implementation
        .descriptor_digest()
        .expect("test implementation must have a digest");
    let implementation = ProviderImplementationReference {
        descriptor,
        artifact: artifact.clone(),
        handler: None,
    };
    let package = PackageDocument {
        schema: PackageDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        activation_mode: AbilityActivationMode::StructuredEffects,
        package: PackageSubject {
            name: key("shared-provider"),
            version: "1.0.0".to_string(),
            payload: artifact.clone(),
            source: artifact.clone(),
        },
        artifacts: vec![artifact.clone()],
        exports: vec![ExportDeclaration {
            name: key("provider"),
            interface: interface.clone(),
            aggregation: Some(AggregationContract {
                scope: AggregationScope::ProviderInstance,
                key: key("slot"),
                controller_group: key("aggregate"),
                reject_slot_collisions: true,
                merge_contract: None,
            }),
            implementation: descriptor,
        }],
        requirements: Vec::new(),
        module_entry_points: BTreeMap::from([
            (compose_entry, artifact.clone()),
            (transition_entry, artifact),
        ]),
        implementation: PackageImplementation {
            providers: vec![provider_implementation],
            handlers: BTreeMap::new(),
        },
        ownership: Vec::new(),
    };
    let package_digest = package
        .content_digest()
        .expect("test package must have a digest");

    let mut environment = source.binding_inputs.environment;
    environment.providers[0].interface = interface.clone();
    environment.providers[0].implementation = implementation.clone();
    let request_template = source.binding_plan.requests[0].clone();
    let mut requests = Vec::new();
    let mut candidates = Vec::new();
    for index in 0..request_count {
        let consumer = InstanceId {
            environment: provider.environment.clone(),
            key: key(&format!("consumer-{index}")),
        };
        let mut consumer_inventory = environment.providers[0].clone();
        consumer_inventory.provider = consumer.clone();
        consumer_inventory.state = aos_ability_model::document::ProviderState::Declared;
        consumer_inventory.incarnation = None;
        environment.providers.push(consumer_inventory);
        let request = BindingRequest {
            id: RequestId {
                consumer: consumer.clone(),
                scope: ScopePath::root(),
                key: key("service"),
            },
            accepted_interfaces: vec![interface.clone()],
            methods: request_template.methods.clone(),
            guarantees: Vec::new(),
            lifetime: ResourceLifetime::Instance,
        };
        let candidate = BindingCandidate {
            key: key(&format!("provider-{index}")),
            request: request.id.clone(),
            interface: interface.clone(),
            provider: provider.clone(),
            provider_package: package_digest,
            implementation: implementation.clone(),
            caller_grant: AuthorityGrant {
                principal: consumer,
                methods: request.methods.clone(),
                contributions: Vec::new(),
                resources: vec![ResourcePermission {
                    resource: environment.resources[0].resource.clone(),
                    access: AccessMode::Read,
                    operations: vec![key("observe")],
                }],
            },
            provider_grant: empty_grant(provider.clone()),
            guarantees: Vec::new(),
            policy_revision: environment.policy_revision,
            lifetime: ResourceLifetime::Instance,
            mediation_allowed: false,
            exclusive_resources: Vec::new(),
        };
        requests.push(request);
        candidates.push(candidate);
    }
    requests.sort_by(|left, right| left.id.cmp(&right.id));
    candidates.sort_by(|left, right| left.key.cmp(&right.key));
    environment.providers.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.interface.cmp(&right.interface))
    });
    let environment_digest = environment
        .content_digest()
        .expect("test environment must have a digest");

    let mut desired = source.binding_inputs.desired_state;
    desired.environment = environment_digest;
    desired.instances.clear();
    desired.contributions.clear();
    desired.child_requests = requests;
    desired.outputs.clear();
    desired.controllers.clear();
    let desired_digest = desired
        .content_digest()
        .expect("test desired state must have a digest");
    let policy = ResolutionPolicyDocument {
        schema: ResolutionPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state: desired_digest,
        environment: environment_digest,
        policy_revision: environment.policy_revision,
        candidates,
        explicit_bindings: Vec::new(),
        existing_pins: Vec::new(),
        operator_orders: Vec::new(),
        enabled_providers: Vec::new(),
        obligations: Vec::new(),
    };
    PlannerFixture {
        context,
        desired,
        environment,
        packages: vec![package],
        policy,
        provider,
        implementation,
        package: package_digest,
    }
}

fn empty_grant(principal: InstanceId) -> AuthorityGrant {
    AuthorityGrant {
        principal,
        methods: Vec::new(),
        contributions: Vec::new(),
        resources: Vec::new(),
    }
}

fn two_obligations(request: &RequestId) -> Vec<DeploymentObligation> {
    vec![
        DeploymentObligation {
            key: key("authorization"),
            kind: ObligationKind::Authorization,
            request: request.clone(),
            resource: None,
            description: "operator authorization is unavailable".to_string(),
        },
        DeploymentObligation {
            key: key("provider"),
            kind: ObligationKind::ExternalProvider,
            request: request.clone(),
            resource: None,
            description: "external provider is unavailable".to_string(),
        },
    ]
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid static planner-test key")
}
