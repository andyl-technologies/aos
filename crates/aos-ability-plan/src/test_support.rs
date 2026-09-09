//! Real planning fixtures for downstream crate tests.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use aos_ability_model::document::PackageSubject;
use aos_ability_model::{
    AbilityActivationMode, AbilityValue, AggregationContract, AggregationScope, BindingId,
    DeploymentObligation, ExportDeclaration, ImplementationKind, InstanceId, LocalKey,
    ObligationKind, PackageDocument, PackageImplementation, ProviderImplementation,
    ProviderImplementationReference, ResourceLifetime, TeardownBindingAuthorization,
    TransitionAuthorizationDocument, VersionedDocument,
};
use aos_ability_validate::{
    CheckedEffectPlan, CheckedTransitionAuthority, TransitionAuthorityInputs, ValidationContext,
};

use crate::{
    BindingCandidate, CompositionContext, CompositionEvaluator, CompositionFragment,
    EvaluationError, PlanningReplayInputs, PlanningSnapshot, RecursiveComposer,
    ResolutionPolicyDocument, TransitionFragment, TransitionInputs, TransitionPlanner,
    VerifiedPlanningSnapshot, VerifiedTransitionPlan,
};

/// Builds planning provenance and an effect plan checked from its final binding.
///
/// The fixture runs the production resolver, recursive composer, snapshot
/// encoder, structural replay, binding validator, and effect validator. It is
/// intended for downstream recovery tests that must not construct an opaque
/// [`VerifiedPlanningSnapshot`] directly.
///
/// # Panics
///
/// Panics only when the statically constructed fixture stops satisfying a
/// production planning or validation invariant.
#[must_use]
pub fn verified_planning_effect_plan() -> (VerifiedPlanningSnapshot, CheckedEffectPlan) {
    let (planning, transition) = verified_planning_transition_plan();
    let effect = transition.into_checked_effect();
    (planning, effect)
}

/// Builds verified planning provenance with two obligations for one request.
///
/// The fixture exercises the binding contract that an unresolved request may
/// retain one or more independently classified missing inputs.
///
/// # Panics
///
/// Panics only when the statically constructed fixture stops satisfying a
/// production planning, snapshot, or validation invariant.
#[must_use]
pub fn verified_planning_multiple_obligations() -> VerifiedPlanningSnapshot {
    build_verified_planning_fixture(false, PlanningFixtureKind::MultipleObligations).1
}

/// Builds verified planning provenance with one retained candidate rejection.
///
/// # Panics
///
/// Panics only when the statically constructed fixture stops satisfying a
/// production planning, snapshot, or validation invariant.
#[must_use]
pub fn verified_planning_with_rejection() -> VerifiedPlanningSnapshot {
    build_verified_planning_fixture(false, PlanningFixtureKind::SelectedWithRejection).1
}

/// Builds sealed planning and transition provenance through production planners.
///
/// # Panics
///
/// Panics only when the statically constructed fixture stops satisfying a
/// production planning or transition invariant.
#[must_use]
pub fn verified_planning_transition_plan() -> (VerifiedPlanningSnapshot, VerifiedTransitionPlan) {
    let (_, planning, transition) = build_verified_planning_transition_fixture(false);
    (planning, transition)
}

/// Builds a transition whose desired and retained prior states are identical.
///
/// This fixture exercises prior-snapshot linkage without introducing resource
/// changes into the generated effect graph.
///
/// # Panics
///
/// Panics only when the statically constructed fixture stops satisfying a
/// production planning or transition invariant.
#[must_use]
pub fn verified_planning_transition_with_current()
-> (VerifiedPlanningSnapshot, VerifiedTransitionPlan) {
    let (_, planning, transition) = build_verified_planning_transition_fixture(true);
    (planning, transition)
}

/// Builds a transition linked to a distinct prior planning snapshot.
///
/// # Panics
///
/// Panics only when the statically constructed fixture stops satisfying a
/// production planning or transition invariant.
#[must_use]
pub fn verified_planning_transition_with_distinct_current() -> (
    VerifiedPlanningSnapshot,
    VerifiedPlanningSnapshot,
    VerifiedTransitionPlan,
) {
    let (_, current) = build_verified_planning_fixture(true, PlanningFixtureKind::Selected);
    let (context, desired) = build_verified_planning_fixture(false, PlanningFixtureKind::Selected);
    let transition = TransitionPlanner::new(&context)
        .plan(
            &desired,
            TransitionInputs {
                current: Some(&current),
                authority: None,
            },
            &mut EmptyTransitionEvaluator,
        )
        .expect("test transition from a distinct prior plan must validate");

    (desired, current, transition)
}

/// Builds a removed-provider transition with nonempty sealed teardown authority.
///
/// The desired plan contains no binding or package for the prior pure provider.
/// The independently checked authorization remaps its exact prior binding to a
/// transition-local identity and the resulting effect snapshot commits that
/// authorization.
///
/// # Panics
///
/// Panics only when the statically constructed fixture stops satisfying a
/// production planning, authorization, or transition invariant.
#[must_use]
pub fn verified_planning_authorized_removal_fixture() -> (
    VerifiedPlanningSnapshot,
    VerifiedPlanningSnapshot,
    CheckedTransitionAuthority,
    VerifiedTransitionPlan,
) {
    let (context, current) = build_verified_planning_fixture(false, PlanningFixtureKind::Selected);
    let environment = current.checked_binding().environment().clone();
    let environment_digest = environment
        .content_digest()
        .expect("test environment must have a digest");
    let mut seed = current.outcome().seed.clone();
    seed.environment = environment_digest;
    seed.instances.clear();
    seed.contributions.clear();
    seed.child_requests.clear();
    seed.outputs.clear();
    seed.controllers.clear();
    let desired_state_digest = seed
        .content_digest()
        .expect("removed-provider desired state must digest");
    let policy = ResolutionPolicyDocument {
        schema: ResolutionPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state: desired_state_digest,
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
    let outcome = RecursiveComposer::new(&context)
        .compose(
            &policies,
            seed.clone(),
            environment.clone(),
            packages.clone(),
            &mut EmptyEvaluator,
        )
        .expect("removed-provider desired state must compose");
    let snapshot = PlanningSnapshot::from_outcome(&outcome)
        .expect("removed-provider planning snapshot must encode");
    let snapshot_digest = snapshot
        .digest()
        .expect("removed-provider planning snapshot must digest");
    let desired = snapshot
        .verify_structure(
            &RecursiveComposer::new(&context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &policies,
                seed,
                environment,
                packages,
            },
        )
        .expect("removed-provider planning snapshot must replay");

    let source = current.checked_binding().bindings()[0].clone();
    let mut request = current.checked_binding().document().requests[0].clone();
    request.id.key = key("transition-prior-request");
    let mut binding = source.clone();
    binding.id = BindingId(key("transition-prior-binding"));
    binding.request = request.id.clone();
    binding.policy_revision = desired.checked_binding().document().policy_revision;
    let authorization_document = TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_planning: desired.snapshot_digest(),
        current_planning: current.snapshot_digest(),
        desired_policy_revision: desired.checked_binding().document().policy_revision,
        prior_policy_revision: current.checked_binding().document().policy_revision,
        authorization_policy_revision: desired.checked_binding().document().policy_revision,
        teardown_bindings: vec![TeardownBindingAuthorization {
            source_binding: source.id,
            request,
            binding,
        }],
        teardown_providers: Vec::new(),
    };
    let authorization_digest = authorization_document
        .content_digest()
        .expect("test transition authorization must digest");
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
        .expect("test transition authority must validate");
    let transition = TransitionPlanner::new(&context)
        .plan(
            &desired,
            TransitionInputs {
                current: Some(&current),
                authority: Some(&authority),
            },
            &mut EmptyTransitionEvaluator,
        )
        .expect("authorized removed-provider transition must validate");

    (desired, current, authority, transition)
}

/// Builds a validation context with sealed planning and transition provenance.
///
/// # Panics
///
/// Panics only when the statically constructed fixture stops satisfying a
/// production planning or transition invariant.
#[must_use]
pub fn verified_planning_transition_fixture() -> (
    ValidationContext,
    VerifiedPlanningSnapshot,
    VerifiedTransitionPlan,
) {
    build_verified_planning_transition_fixture(false)
}

fn build_verified_planning_transition_fixture(
    include_current: bool,
) -> (
    ValidationContext,
    VerifiedPlanningSnapshot,
    VerifiedTransitionPlan,
) {
    let (context, verified) = build_verified_planning_fixture(false, PlanningFixtureKind::Selected);
    let transition = TransitionPlanner::new(&context)
        .plan(
            &verified,
            TransitionInputs {
                current: include_current.then_some(&verified),
                authority: None,
            },
            &mut EmptyTransitionEvaluator,
        )
        .expect("test transition must produce a checked effect graph");

    (context, verified, transition)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PlanningFixtureKind {
    Selected,
    SelectedWithRejection,
    MultipleObligations,
}

fn build_verified_planning_fixture(
    include_discarded_policy: bool,
    kind: PlanningFixtureKind,
) -> (ValidationContext, VerifiedPlanningSnapshot) {
    let source = aos_ability_validate::test_support::plan_fixture();
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
        .expect("test provider implementation must have a digest");
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
            name: key("planning-provider"),
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
            (transition_entry, artifact.clone()),
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
    environment.providers[0].implementation = implementation.clone();
    let consumer = InstanceId {
        environment: provider.environment.clone(),
        key: key("consumer"),
    };
    let mut consumer_inventory = environment.providers[0].clone();
    consumer_inventory.provider = consumer.clone();
    consumer_inventory.state = aos_ability_model::document::ProviderState::Declared;
    consumer_inventory.incarnation = None;
    environment.providers.push(consumer_inventory);
    environment
        .providers
        .sort_by(|left, right| left.provider.cmp(&right.provider));
    let environment_digest = environment
        .content_digest()
        .expect("test environment must have a digest");
    let mut desired_state = source.binding_inputs.desired_state;
    desired_state.environment = environment_digest;
    desired_state.child_requests[0].id.consumer = consumer.clone();
    let desired_state_digest = desired_state
        .content_digest()
        .expect("test desired state must have a digest");

    let request = desired_state.child_requests[0].clone();
    let source_binding = &source.binding_plan.bindings[0];
    let mut caller_grant = source_binding.caller_grant.clone();
    caller_grant.principal = consumer;
    let obligations = if kind == PlanningFixtureKind::MultipleObligations {
        vec![
            DeploymentObligation {
                key: key("authorization"),
                kind: ObligationKind::Authorization,
                request: request.id.clone(),
                resource: None,
                description: "operator authorization is unavailable".to_string(),
            },
            DeploymentObligation {
                key: key("provider"),
                kind: ObligationKind::ExternalProvider,
                request: request.id.clone(),
                resource: None,
                description: "external provider is unavailable".to_string(),
            },
        ]
    } else {
        Vec::new()
    };
    let mut candidates = if kind == PlanningFixtureKind::MultipleObligations {
        Vec::new()
    } else {
        let selected = BindingCandidate {
            key: source_binding.id.0.clone(),
            request: request.id.clone(),
            interface,
            provider,
            provider_package: package_digest,
            implementation,
            caller_grant,
            provider_grant: source_binding.provider_grant.clone(),
            guarantees: Vec::new(),
            policy_revision: environment.policy_revision,
            lifetime: ResourceLifetime::Instance,
            mediation_allowed: false,
            exclusive_resources: Vec::new(),
        };
        if kind == PlanningFixtureKind::SelectedWithRejection {
            let mut rejected = selected.clone();
            rejected.key = key("a-rejected-short-lifetime");
            rejected.lifetime = ResourceLifetime::Attempt;
            vec![rejected, selected]
        } else {
            vec![selected]
        }
    };
    candidates.sort_by(|left, right| left.key.cmp(&right.key));
    let policy = ResolutionPolicyDocument {
        schema: ResolutionPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state: desired_state_digest,
        environment: environment_digest,
        policy_revision: environment.policy_revision,
        candidates,
        explicit_bindings: Vec::new(),
        existing_pins: Vec::new(),
        operator_orders: Vec::new(),
        enabled_providers: Vec::new(),
        obligations,
    };
    let mut policies = vec![policy];
    if include_discarded_policy {
        let mut discarded = policies[0].clone();
        discarded.desired_state = aos_contract::Sha256Digest::of_bytes("discarded desired state");
        policies.push(discarded);
        policies.sort_by_key(|policy| policy.desired_state);
    }
    let packages = vec![package];
    let mut evaluator = EmptyEvaluator;
    let outcome = RecursiveComposer::new(&source.context)
        .compose(
            &policies,
            desired_state.clone(),
            environment.clone(),
            packages.clone(),
            &mut evaluator,
        )
        .expect("test composition must reach a fixed point");
    let snapshot = PlanningSnapshot::from_outcome(&outcome)
        .expect("test planning outcome must produce a bounded snapshot");
    let snapshot_digest = snapshot
        .digest()
        .expect("test planning snapshot must have a digest");
    let verified = snapshot
        .verify_structure(
            &RecursiveComposer::new(&source.context),
            PlanningReplayInputs {
                expected_digest: snapshot_digest,
                authenticated_policies: &policies,
                seed: desired_state,
                environment,
                packages,
            },
        )
        .expect("test planning snapshot must pass structural replay");

    (source.context, verified)
}

struct EmptyEvaluator;

impl CompositionEvaluator for EmptyEvaluator {
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

struct EmptyTransitionEvaluator;

impl CompositionEvaluator for EmptyTransitionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _entry: &LocalKey,
        _input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let fragment = TransitionFragment {
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
        };
        AbilityValue::new(
            serde_json::to_value(fragment)
                .map_err(|error| EvaluationError::new(error.to_string()))?,
        )
        .map_err(|error| EvaluationError::new(error.to_string()))
    }
}

fn key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("valid static planning fixture key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_fixture_passes_real_planning_and_effect_validation() {
        let (verified, checked) = verified_planning_effect_plan();

        assert_eq!(verified.checked_binding().id(), checked.binding_plan().id());
    }

    #[test]
    fn shared_fixture_carries_sealed_transition_provenance() {
        let (planning, transition) = verified_planning_transition_plan();

        assert_eq!(
            transition.desired_planning_digest(),
            planning.snapshot_digest()
        );
        assert_eq!(transition.effect_plan(), transition.checked_effect().id());
    }
}
