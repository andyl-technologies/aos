//! Real planning fixtures for downstream crate tests.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use aos_ability_model::document::PackageSubject;
use aos_ability_model::{
    AbilityActivationMode, AbilityValue, AggregationContract, AggregationScope, ExportDeclaration,
    ImplementationKind, InstanceId, LocalKey, PackageDocument, PackageImplementation,
    ProviderImplementation, ProviderImplementationReference, ResourceLifetime, VersionedDocument,
};
use aos_ability_validate::{CheckedEffectPlan, ValidationContext};

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
    let (_, current) = build_verified_planning_fixture(true);
    let (context, desired) = build_verified_planning_fixture(false);
    let transition = TransitionPlanner::new(&context)
        .plan(
            &desired,
            TransitionInputs {
                current: Some(&current),
            },
            &mut EmptyTransitionEvaluator,
        )
        .expect("test transition from a distinct prior plan must validate");

    (desired, current, transition)
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
    let (context, verified) = build_verified_planning_fixture(false);
    let transition = TransitionPlanner::new(&context)
        .plan(
            &verified,
            TransitionInputs {
                current: include_current.then_some(&verified),
            },
            &mut EmptyTransitionEvaluator,
        )
        .expect("test transition must produce a checked effect graph");

    (context, verified, transition)
}

fn build_verified_planning_fixture(
    include_discarded_policy: bool,
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
    let policy = ResolutionPolicyDocument {
        schema: ResolutionPolicyDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_state: desired_state_digest,
        environment: environment_digest,
        policy_revision: environment.policy_revision,
        candidates: vec![BindingCandidate {
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
        }],
        explicit_bindings: Vec::new(),
        existing_pins: Vec::new(),
        operator_orders: Vec::new(),
        enabled_providers: Vec::new(),
        obligations: Vec::new(),
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
