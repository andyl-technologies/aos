//! Transition-construction and replay regressions.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::{DesiredInstance, PackageSubject, ProviderState};
use aos_ability_model::*;
use aos_ability_validate::{
    TransitionAuthorityError, TransitionAuthorityInputs, ValidationContext,
};

use crate::test_support::{
    ability_value, key, module_locator, verified_planning_authorized_removal_fixture,
    verified_planning_resource_removal_fixture, verified_planning_transition_fixture,
};
use crate::{
    BindingCandidate, CandidateSelection, CompositionContext, CompositionEvaluator,
    CompositionFragment, EvaluationError, PlanningReplayInputs, PlanningSnapshot,
    RUNTIME_OBSERVATIONS_SCHEMA, RecursiveComposer, ResolutionPolicyDocument,
    RuntimeResourceHealth, RuntimeResourceObservation, RuntimeResourceState,
    TRANSITION_FRAGMENT_SCHEMA, TRANSITION_SNAPSHOT_SCHEMA, TransitionBindingAuthority,
    TransitionContext, TransitionError, TransitionEvaluationResult, TransitionExport,
    TransitionExportKind, TransitionFragment, TransitionHandoff, TransitionImport,
    TransitionImportDirection, TransitionInputs, TransitionLimits, TransitionLink,
    TransitionPlanner, TransitionReconciliation, TransitionReplayInputs, TransitionSnapshot,
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
        _module: &aos_ability_model::ModuleLocator,
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
        _module: &aos_ability_model::ModuleLocator,
        _entry: &LocalKey,
        _input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        Err(EvaluationError::new("deterministic transition failure"))
    }
}

fn reconciliation_fixture(
    observations: Vec<RuntimeResourceObservation>,
    unsettled_provider_adoptions: Vec<ResourceId>,
) -> TransitionReconciliation {
    let source_plan = PlanId(aos_contract::Sha256Digest::of_bytes(
        "reconciliation-source",
    ));
    let transaction = TransactionId(key("reconciliation-attempt"));
    let policy_fence = RevisionId(aos_contract::Sha256Digest::of_bytes("policy-fence"));
    let authority_json = serde_json::json!({
        "schema": "aos.ability.current-authority/v1",
        "policy_fence": policy_fence,
        "transaction": transaction,
        "authority_epoch": 7,
        "sequence": 11,
        "observed_at_restart_millis": 23,
        "max_age_millis": 5_000,
        "plan": source_plan,
        "resource_observations": observations.iter().map(|observation| {
            let state = match observation.state {
                RuntimeResourceState::Absent => serde_json::json!({"state": "absent"}),
                RuntimeResourceState::Present { revision, health } => {
                    let state = match health {
                        RuntimeResourceHealth::Healthy => "present",
                        RuntimeResourceHealth::Stopped => "stopped",
                        RuntimeResourceHealth::Divergent => "divergent",
                    };
                    serde_json::json!({"state": state, "revision": revision})
                }
            };
            serde_json::json!({"resource": observation.resource, "state": state})
        }).collect::<Vec<_>>(),
    });
    let authority_bytes = aos_contract::canonical::to_vec(&authority_json)
        .expect("reconciliation authority must encode");
    TransitionReconciliation {
        schema: RUNTIME_OBSERVATIONS_SCHEMA.to_string(),
        source_plan,
        transaction,
        policy_fence,
        authority_epoch: 7,
        sequence: 11,
        observed_at_restart_millis: 23,
        max_age_millis: 5_000,
        authority_publication: aos_contract::Sha256Digest::separated(
            "aos.ability.current-authority/v1",
            authority_bytes,
        ),
        authority_document: AbilityValue::new(authority_json)
            .expect("bounded reconciliation authority"),
        unsettled_provider_adoptions,
        observations,
    }
}

fn empty_transition_authority(
    context: &ValidationContext,
    planning: &VerifiedPlanningSnapshot,
) -> aos_ability_validate::CheckedTransitionAuthority {
    let policy_revision = planning.checked_binding().document().policy_revision;
    let document = TransitionAuthorizationDocument {
        schema: TransitionAuthorizationDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        desired_planning: planning.snapshot_digest(),
        current_planning: planning.snapshot_digest(),
        desired_policy_revision: policy_revision,
        prior_policy_revision: policy_revision,
        authorization_policy_revision: policy_revision,
        teardown_bindings: Vec::new(),
        teardown_providers: Vec::new(),
        persistent_deletions: Vec::new(),
        provider_adoptions: Vec::new(),
    };
    let expected_digest = document
        .content_digest()
        .expect("empty transition authority must digest");
    context
        .validate_transition_authority(
            document,
            TransitionAuthorityInputs {
                expected_digest,
                desired_planning: planning.snapshot_digest(),
                current_planning: planning.snapshot_digest(),
                authorization_policy_revision: policy_revision,
                desired: planning.checked_binding(),
                current: planning.checked_binding(),
            },
        )
        .expect("empty transition authority must validate")
}

#[test]
fn reconciliation_requires_the_exact_desired_current_observation_union() {
    let (context, planning, _) = verified_planning_transition_fixture();
    let reconciliation = reconciliation_fixture(Vec::new(), Vec::new());
    let inputs = TransitionInputs {
        current: Some(&planning),
        authority: None,
        reconciliation: Some(&reconciliation),
    };

    let error = TransitionPlanner::new(&context)
        .validate_reconciliation_inputs(&planning, &inputs)
        .expect_err("omitting a retained resource observation must fail closed");
    assert!(
        error
            .to_string()
            .contains("exact desired/current resource union")
    );
}

#[test]
fn unsettled_provider_adoption_requires_exact_sealed_authority() {
    let (context, planning, _) = verified_planning_transition_fixture();
    let resource = planning.outcome().desired_state.resources[0].clone();
    let reconciliation = reconciliation_fixture(
        vec![RuntimeResourceObservation {
            resource: resource.resource.clone(),
            state: RuntimeResourceState::Present {
                revision: resource.revision,
                health: RuntimeResourceHealth::Stopped,
            },
        }],
        vec![resource.resource],
    );
    let no_authority = TransitionInputs {
        current: Some(&planning),
        authority: None,
        reconciliation: Some(&reconciliation),
    };
    let error = TransitionPlanner::new(&context)
        .validate_reconciliation_inputs(&planning, &no_authority)
        .expect_err("an unauthenticated unsettled adoption must fail closed");
    assert!(
        error
            .to_string()
            .contains("one exact sealed authority entry")
    );

    let authority = empty_transition_authority(&context, &planning);
    let unmatched_authority = TransitionInputs {
        current: Some(&planning),
        authority: Some(&authority),
        reconciliation: Some(&reconciliation),
    };
    let error = TransitionPlanner::new(&context)
        .validate_reconciliation_inputs(&planning, &unmatched_authority)
        .expect_err("an unmatched unsettled adoption must fail closed");
    assert!(
        error
            .to_string()
            .contains("one exact sealed authority entry")
    );
}

#[test]
fn only_exact_healthy_linked_provider_adoptions_allow_effect_free_settlement() {
    let (_, planning, _) = verified_planning_transition_fixture();
    let resource = planning.outcome().desired_state.resources[0].clone();
    let exact_observation = RuntimeResourceObservation {
        resource: resource.resource.clone(),
        state: RuntimeResourceState::Present {
            revision: resource.revision,
            health: RuntimeResourceHealth::Healthy,
        },
    };
    let reconciliation = reconciliation_fixture(
        vec![exact_observation.clone()],
        vec![resource.resource.clone()],
    );

    assert_eq!(
        crate::transition::linked_healthy_provider_adoptions(&planning, Some(&reconciliation)),
        BTreeSet::from([resource.resource.clone()])
    );

    let stopped = reconciliation_fixture(
        vec![RuntimeResourceObservation {
            state: RuntimeResourceState::Present {
                revision: resource.revision,
                health: RuntimeResourceHealth::Stopped,
            },
            ..exact_observation.clone()
        }],
        vec![resource.resource.clone()],
    );
    let stale = reconciliation_fixture(
        vec![RuntimeResourceObservation {
            state: RuntimeResourceState::Present {
                revision: RevisionId(aos_contract::Sha256Digest::of_bytes("stale revision")),
                health: RuntimeResourceHealth::Healthy,
            },
            ..exact_observation
        }],
        vec![resource.resource],
    );

    for reconciliation in [&stopped, &stale] {
        assert!(
            crate::transition::linked_healthy_provider_adoptions(&planning, Some(reconciliation))
                .is_empty()
        );
    }
}

#[test]
fn unsettled_provider_adoption_must_remain_in_current_and_desired_state() {
    let (context, desired, current) = verified_planning_resource_removal_fixture();
    let resource = current.outcome().desired_state.resources[0].clone();
    let observations = current
        .outcome()
        .desired_state
        .resources
        .iter()
        .map(|revision| RuntimeResourceObservation {
            resource: revision.resource.clone(),
            state: RuntimeResourceState::Present {
                revision: revision.revision,
                health: if revision.resource == resource.resource {
                    RuntimeResourceHealth::Stopped
                } else {
                    RuntimeResourceHealth::Healthy
                },
            },
        })
        .collect();
    let reconciliation = reconciliation_fixture(observations, vec![resource.resource.clone()]);
    let current_only = TransitionInputs {
        current: Some(&current),
        authority: None,
        reconciliation: Some(&reconciliation),
    };
    let error = TransitionPlanner::new(&context)
        .validate_reconciliation_inputs(&desired, &current_only)
        .expect_err("a current-only adoption receipt must fail closed");
    assert!(
        matches!(
            &error,
            TransitionError::Encoding(reason)
                if reason == "runtime reconciliation provider adoption is not retained by both desired and current state"
        ),
        "{error}"
    );

    let desired_only = TransitionInputs {
        current: Some(&desired),
        authority: None,
        reconciliation: Some(&reconciliation),
    };
    let error = TransitionPlanner::new(&context)
        .validate_reconciliation_inputs(&current, &desired_only)
        .expect_err("a desired-only adoption receipt must fail closed");
    assert!(
        matches!(
            &error,
            TransitionError::Encoding(reason)
                if reason == "runtime reconciliation provider adoption is not retained by both desired and current state"
        ),
        "{error}"
    );
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
    let encoded: serde_json::Value =
        serde_json::from_slice(&bytes).expect("transition snapshot is JSON");
    assert_eq!(encoded["schema"], TRANSITION_SNAPSHOT_SCHEMA);
    assert!(
        encoded.get("reconciliation").is_none(),
        "snapshots without reconciliation must omit the optional field"
    );
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
fn reconciliation_snapshot_round_trips_and_replays_exact_live_input() {
    let (context, planning, _) = verified_planning_transition_fixture();
    let desired_resource = planning
        .outcome()
        .desired_state
        .resources
        .first()
        .expect("fixture must expose one desired resource")
        .clone();
    let source_plan = PlanId(aos_contract::Sha256Digest::of_bytes("source-noop-plan"));
    let transaction = TransactionId(LocalKey::new("repair-attempt").unwrap());
    let policy_fence = RevisionId(aos_contract::Sha256Digest::of_bytes("policy-fence"));
    let authority_json = serde_json::json!({
        "schema": "aos.ability.current-authority/v1",
        "policy_fence": policy_fence,
        "transaction": transaction,
        "authority_epoch": 7,
        "sequence": 11,
        "observed_at_restart_millis": 23,
        "max_age_millis": 5_000,
        "plan": source_plan,
        "resource_observations": [{
            "resource": desired_resource.resource,
            "state": {
                "state": "stopped",
                "revision": desired_resource.revision,
            },
        }],
    });
    let authority_bytes = aos_contract::canonical::to_vec(&authority_json).unwrap();
    let authority_publication =
        aos_contract::Sha256Digest::separated("aos.ability.current-authority/v1", authority_bytes);
    let reconciliation = TransitionReconciliation {
        schema: RUNTIME_OBSERVATIONS_SCHEMA.to_string(),
        source_plan,
        transaction,
        policy_fence,
        authority_epoch: 7,
        sequence: 11,
        observed_at_restart_millis: 23,
        max_age_millis: 5_000,
        authority_publication,
        authority_document: AbilityValue::new(authority_json).unwrap(),
        unsettled_provider_adoptions: Vec::new(),
        observations: vec![crate::RuntimeResourceObservation {
            resource: desired_resource.resource,
            state: crate::RuntimeResourceState::Present {
                revision: desired_resource.revision,
                health: crate::RuntimeResourceHealth::Stopped,
            },
        }],
    };
    let mut evaluator = EmptyTransitionEvaluator::new();
    let transition = TransitionPlanner::new(&context)
        .plan(
            &planning,
            TransitionInputs {
                current: Some(&planning),
                authority: None,
                reconciliation: Some(&reconciliation),
            },
            &mut evaluator,
        )
        .expect("bounded live input must produce a linked repair snapshot");

    let bytes = transition.snapshot().canonical_bytes().unwrap();
    let encoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(encoded["schema"], TRANSITION_SNAPSHOT_SCHEMA);
    assert_eq!(
        transition.snapshot().reconciliation(),
        Some(&reconciliation)
    );

    let snapshot = TransitionSnapshot::decode(&bytes).unwrap();
    let replayed = snapshot
        .verify_structure(
            &TransitionPlanner::new(&context),
            TransitionReplayInputs {
                expected_digest: transition.snapshot_digest(),
                desired: &planning,
                current: Some(&planning),
                authority: None,
            },
        )
        .expect("repair snapshot must reconstruct from its retained live input");

    assert_eq!(replayed.snapshot_digest(), transition.snapshot_digest());
    assert_eq!(replayed.snapshot().reconciliation(), Some(&reconciliation));

    let mut tampered = reconciliation;
    tampered.sequence += 1;
    let error = TransitionPlanner::new(&context)
        .plan(
            &planning,
            TransitionInputs {
                current: Some(&planning),
                authority: None,
                reconciliation: Some(&tampered),
            },
            &mut EmptyTransitionEvaluator::new(),
        )
        .expect_err("a changed reconciliation stamp must break its authority link");
    assert!(error.to_string().contains("authority publication differs"));
}

#[test]
fn absent_reconciliation_is_transaction_linked_and_replayable() {
    let (context, planning, _) = verified_planning_transition_fixture();
    let desired_resource = planning
        .outcome()
        .desired_state
        .resources
        .first()
        .expect("fixture must expose one desired resource")
        .clone();
    let source_plan = PlanId(aos_contract::Sha256Digest::of_bytes("absent-source-plan"));
    let transaction = TransactionId(LocalKey::new("absent-repair").unwrap());
    let policy_fence = RevisionId(aos_contract::Sha256Digest::of_bytes("policy-fence"));
    let authority_json = serde_json::json!({
        "schema": "aos.ability.current-authority/v1",
        "policy_fence": policy_fence,
        "transaction": transaction,
        "authority_epoch": 7,
        "sequence": 11,
        "observed_at_restart_millis": 23,
        "max_age_millis": 5_000,
        "plan": source_plan,
        "resource_observations": [{
            "resource": desired_resource.resource,
            "state": {"state": "absent"},
        }],
    });
    let authority_bytes = aos_contract::canonical::to_vec(&authority_json).unwrap();
    let reconciliation = TransitionReconciliation {
        schema: RUNTIME_OBSERVATIONS_SCHEMA.to_string(),
        source_plan,
        transaction,
        policy_fence,
        authority_epoch: 7,
        sequence: 11,
        observed_at_restart_millis: 23,
        max_age_millis: 5_000,
        authority_publication: aos_contract::Sha256Digest::separated(
            "aos.ability.current-authority/v1",
            authority_bytes,
        ),
        authority_document: AbilityValue::new(authority_json).unwrap(),
        unsettled_provider_adoptions: Vec::new(),
        observations: vec![crate::RuntimeResourceObservation {
            resource: desired_resource.resource,
            state: crate::RuntimeResourceState::Absent,
        }],
    };
    let transition = TransitionPlanner::new(&context)
        .plan(
            &planning,
            TransitionInputs {
                current: Some(&planning),
                authority: None,
                reconciliation: Some(&reconciliation),
            },
            &mut EmptyTransitionEvaluator::new(),
        )
        .expect("absent live state must produce a linked repair snapshot");
    let bytes = transition.snapshot().canonical_bytes().unwrap();
    let snapshot = TransitionSnapshot::decode(&bytes).unwrap();
    let replayed = snapshot
        .verify_structure(
            &TransitionPlanner::new(&context),
            TransitionReplayInputs {
                expected_digest: transition.snapshot_digest(),
                desired: &planning,
                current: Some(&planning),
                authority: None,
            },
        )
        .expect("absent repair snapshot must replay from retained authority");

    assert_eq!(snapshot.reconciliation(), Some(&reconciliation));
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
                reconciliation: None,
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
                reconciliation: None,
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
                reconciliation: None,
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
                reconciliation: None,
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
                reconciliation: None,
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

#[path = "transition_tests/composition_evaluators.rs"]
mod composition_evaluators;
#[path = "transition_tests/lifecycle.rs"]
mod lifecycle;
#[path = "transition_tests/lifecycle_support.rs"]
mod lifecycle_support;
#[path = "transition_tests/pipeline.rs"]
mod pipeline;

use composition_evaluators::*;
use lifecycle_support::*;

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

fn effect_features() -> Vec<RequiredFeature> {
    vec![
        RequiredFeature::new("abilities-v1").expect("base abilities feature"),
        RequiredFeature::new(FEATURE_ABILITY_EFFECTS_V1).expect("effect semantics feature"),
    ]
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
