//! Pure admission and lifecycle planning for single-host A/B image rollouts.
//!
//! The built-in strategy prepares one candidate beside one retained
//! predecessor and admits exactly one boot image. The ordinary transition
//! planner lowers these semantic steps into its checked effect graph.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{
    AccessMode, BranchMembership, DecisionAlternative, DecisionNode, DecisionPredicate,
    DecisionSelector, DependencyEdge, DependencyKind, ImageRolloutAction, IncarnationId, LocalKey,
    MergeNode, MergedOutput, MethodReference, Operation, OperationFamily, OperationPhase,
    OperationResultReference, PlanNodeKey, ResultProducerKey, RevisionId, ScopedOperationKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum retention interval admitted by the version-1 strategy.
pub const MAX_RETENTION_MILLIS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// Pins every immutable component used to authenticate one boot image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RolloutImageIdentity {
    /// Pins the immutable system toplevel.
    pub toplevel: String,
    /// Pins the signed UKI source identity.
    pub uki: String,
    /// Pins the exact native ability executor carried by the image.
    pub executor: String,
    /// Pins the compatible nonempty persistent state format.
    pub state_format: String,
}

/// Supplies one exact desired single-host rollout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AbRolloutRequest {
    /// Names the only strategy implemented by this provider version.
    pub strategy: String,
    /// Limits preparation to one candidate beside one retained predecessor.
    pub concurrency: u32,
    /// Identifies the currently admitted image.
    pub predecessor: RolloutImageIdentity,
    /// Identifies the candidate to prepare and select.
    pub candidate: RolloutImageIdentity,
    /// Gives the restart-stable deadline through which both images remain retained.
    pub retention_expires_at_millis: u64,
}

/// Captures fresh authority facts checked before constructing a rollout graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolloutAuthority {
    /// Pins the current policy revision.
    pub policy_revision: RevisionId,
    /// Pins the current provider assignment incarnation.
    pub provider_incarnation: IncarnationId,
    /// Pins the active image authenticated from the physical backend.
    pub active_image: RolloutImageIdentity,
    /// Reports whether current policy revoked the provider or either artifact.
    pub revoked: bool,
}

/// Identifies one semantic node in the version-1 strategy graph.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RolloutStep {
    /// Retains both exact image identities before any mutable effect.
    Retain,
    /// Prepares the candidate in the inactive slot.
    Prepare,
    /// Drains host workloads before changing boot selection.
    Drain,
    /// Selects the candidate as the host's one next boot image.
    Select,
    /// Reconciles which authenticated image actually booted.
    ObserveBoot,
    /// Observes the bounded health decision for that boot.
    ObserveHealth,
    /// Withdraws a failed or partially completed candidate.
    Withdraw,
    /// Installs the terminal retention lease.
    Hold,
}

/// Selects the conditional health outcome that admits one graph edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RolloutBranch {
    /// The authenticated candidate completed strict boot health.
    Healthy,
    /// The candidate failed or the retained predecessor actually booted.
    Fallback,
}

/// Connects two semantic rollout steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RolloutDependency {
    /// Names the prerequisite step.
    pub from: RolloutStep,
    /// Names the dependent step.
    pub to: RolloutStep,
    /// Guards an edge on the durable health decision, when conditional.
    pub branch: Option<RolloutBranch>,
}

/// Retains an admitted strategy graph and its exact current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedAbRollout {
    /// Carries the exact request used by every effect.
    pub request: AbRolloutRequest,
    /// Pins the current policy used for admission.
    pub policy_revision: RevisionId,
    /// Pins the selected provider incarnation.
    pub provider_incarnation: IncarnationId,
    /// Lists all possible branch steps in stable order.
    pub steps: Vec<RolloutStep>,
    /// Lists prerequisite edges for the healthy and fallback branches.
    pub dependencies: Vec<RolloutDependency>,
}

/// Retains an admitted later retirement transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedRetirement {
    /// Carries the completed rollout whose lease is being retired.
    pub request: AbRolloutRequest,
    /// Pins the current policy used by this later transition.
    pub policy_revision: RevisionId,
    /// Pins the current provider incarnation used by this later transition.
    pub provider_incarnation: IncarnationId,
}

/// Reports a rejection before any rollout effect is constructed.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RolloutAdmissionError {
    /// The request selected unsupported strategy semantics.
    #[error("rollout strategy or concurrency is unsupported")]
    UnsupportedStrategy,
    /// Candidate and predecessor were the same immutable identity.
    #[error("rollout candidate must differ from its predecessor")]
    VacuousCandidate,
    /// The predecessor no longer matches the authenticated active image.
    #[error("rollout predecessor is stale")]
    StalePredecessor,
    /// Current policy revoked the provider or an image artifact.
    #[error("rollout provider or artifact is revoked")]
    Revoked,
    /// The images do not declare one compatible state format.
    #[error("rollout requires identical nonempty image state formats")]
    IncompatibleState,
    /// The retention deadline is expired, unbounded, or too distant.
    #[error("rollout retention window is invalid")]
    InvalidRetention,
    /// A later retirement transition is not yet eligible.
    #[error("rollout retention lease has not expired")]
    RetentionActive,
    /// The request did not pin every immutable identity component.
    #[error("rollout image identity is incomplete")]
    IncompleteIdentity,
}

/// Admits the version-1 single-host A/B strategy without performing effects.
///
/// The returned graph contains both healthy and fallback branches. `hold`
/// finishes either branch after installing a durable retention lease.
///
/// # Errors
///
/// Returns [`RolloutAdmissionError`] for stale, revoked, incompatible,
/// incomplete, unsupported, or unbounded requests.
pub fn admit_ab_rollout(
    request: AbRolloutRequest,
    authority: &RolloutAuthority,
    now_millis: u64,
) -> Result<AdmittedAbRollout, RolloutAdmissionError> {
    validate_request(&request, now_millis)?;
    if authority.revoked {
        return Err(RolloutAdmissionError::Revoked);
    }
    if request.predecessor != authority.active_image {
        return Err(RolloutAdmissionError::StalePredecessor);
    }

    let steps = vec![
        RolloutStep::Retain,
        RolloutStep::Prepare,
        RolloutStep::Drain,
        RolloutStep::Select,
        RolloutStep::ObserveBoot,
        RolloutStep::ObserveHealth,
        RolloutStep::Withdraw,
        RolloutStep::Hold,
    ];
    let dependencies = [
        (RolloutStep::Retain, RolloutStep::Prepare),
        (RolloutStep::Retain, RolloutStep::Drain),
        (RolloutStep::Prepare, RolloutStep::Drain),
        (RolloutStep::Drain, RolloutStep::Select),
        (RolloutStep::Select, RolloutStep::ObserveBoot),
        (RolloutStep::ObserveBoot, RolloutStep::ObserveHealth),
        (RolloutStep::ObserveHealth, RolloutStep::Withdraw),
        (RolloutStep::ObserveHealth, RolloutStep::Hold),
        (RolloutStep::Withdraw, RolloutStep::Hold),
    ]
    .into_iter()
    .map(|(from, to)| RolloutDependency {
        from,
        to,
        branch: match (from, to) {
            (RolloutStep::ObserveHealth, RolloutStep::Withdraw) => Some(RolloutBranch::Fallback),
            (RolloutStep::ObserveHealth, RolloutStep::Hold) => Some(RolloutBranch::Healthy),
            (RolloutStep::Withdraw, RolloutStep::Hold) => Some(RolloutBranch::Fallback),
            _ => None,
        },
    })
    .collect();

    Ok(AdmittedAbRollout {
        request,
        policy_revision: authority.policy_revision,
        provider_incarnation: authority.provider_incarnation.clone(),
        steps,
        dependencies,
    })
}

/// Admits retirement as a later transition under fresh current authority.
///
/// # Errors
///
/// Returns [`RolloutAdmissionError`] until expiry, or when current authority is
/// stale, revoked, incompatible, or incomplete.
pub fn admit_retirement(
    request: AbRolloutRequest,
    authority: &RolloutAuthority,
    now_millis: u64,
) -> Result<AdmittedRetirement, RolloutAdmissionError> {
    validate_request_shape(&request)?;
    if request.retention_expires_at_millis == 0 {
        return Err(RolloutAdmissionError::InvalidRetention);
    }
    if now_millis < request.retention_expires_at_millis {
        return Err(RolloutAdmissionError::RetentionActive);
    }
    if authority.revoked {
        return Err(RolloutAdmissionError::Revoked);
    }
    if authority.active_image != request.candidate && authority.active_image != request.predecessor
    {
        return Err(RolloutAdmissionError::StalePredecessor);
    }

    Ok(AdmittedRetirement {
        request,
        policy_revision: authority.policy_revision,
        provider_incarnation: authority.provider_incarnation.clone(),
    })
}

fn validate_request(
    request: &AbRolloutRequest,
    now_millis: u64,
) -> Result<(), RolloutAdmissionError> {
    validate_request_shape(request)?;
    if !matches!(
        request.retention_expires_at_millis.checked_sub(now_millis),
        Some(1..=MAX_RETENTION_MILLIS)
    ) {
        return Err(RolloutAdmissionError::InvalidRetention);
    }
    Ok(())
}

fn validate_request_shape(request: &AbRolloutRequest) -> Result<(), RolloutAdmissionError> {
    if request.strategy != "single-host-ab-v1" || request.concurrency != 1 {
        return Err(RolloutAdmissionError::UnsupportedStrategy);
    }
    validate_identity(&request.predecessor)?;
    validate_identity(&request.candidate)?;
    if request.predecessor == request.candidate {
        return Err(RolloutAdmissionError::VacuousCandidate);
    }
    if request.predecessor.state_format.is_empty()
        || request.predecessor.state_format != request.candidate.state_format
    {
        return Err(RolloutAdmissionError::IncompatibleState);
    }
    Ok(())
}

fn validate_identity(identity: &RolloutImageIdentity) -> Result<(), RolloutAdmissionError> {
    let components = [
        identity.toplevel.as_str(),
        identity.uki.as_str(),
        identity.executor.as_str(),
        identity.state_format.as_str(),
    ];
    if components.iter().any(|value| value.is_empty()) {
        return Err(RolloutAdmissionError::IncompleteIdentity);
    }
    Ok(())
}

/// Reports whether every strategy effect is dominated by retention.
///
/// Malformed graphs with duplicate steps, unknown edge endpoints, or nodes
/// unreachable from any root fail closed.
#[must_use]
pub fn retention_dominates_effects(plan: &AdmittedAbRollout) -> bool {
    let steps = plan.steps.iter().copied().collect::<BTreeSet<_>>();
    if steps.len() != plan.steps.len() || !steps.contains(&RolloutStep::Retain) {
        return false;
    }

    let mut predecessors = steps
        .iter()
        .copied()
        .map(|step| (step, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for dependency in &plan.dependencies {
        if !steps.contains(&dependency.from) || !steps.contains(&dependency.to) {
            return false;
        }
        let Some(incoming) = predecessors.get_mut(&dependency.to) else {
            return false;
        };
        incoming.insert(dependency.from);
    }

    let roots = predecessors
        .iter()
        .filter_map(|(step, incoming)| incoming.is_empty().then_some(*step))
        .collect::<BTreeSet<_>>();
    if roots.is_empty() {
        return false;
    }

    let mut reachable = roots.clone();
    loop {
        let before = reachable.len();
        for dependency in &plan.dependencies {
            if reachable.contains(&dependency.from) {
                reachable.insert(dependency.to);
            }
        }
        if reachable.len() == before {
            break;
        }
    }
    if reachable != steps {
        return false;
    }

    let mut dominators = steps
        .iter()
        .copied()
        .map(|step| {
            let initial = if roots.contains(&step) {
                BTreeSet::from([step])
            } else {
                steps.clone()
            };
            (step, initial)
        })
        .collect::<BTreeMap<_, _>>();
    loop {
        let mut changed = false;
        for step in steps.difference(&roots) {
            let Some(incoming) = predecessors.get(step) else {
                return false;
            };
            let mut incoming = incoming.iter();
            let Some(first) = incoming.next() else {
                return false;
            };
            let Some(first_dominators) = dominators.get(first) else {
                return false;
            };
            let mut updated = first_dominators.clone();
            for predecessor in incoming {
                updated.retain(|dominator| {
                    dominators
                        .get(predecessor)
                        .is_some_and(|values| values.contains(dominator))
                });
            }
            updated.insert(*step);

            if dominators.get(step) != Some(&updated) {
                dominators.insert(*step, updated);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    steps.iter().all(|step| {
        *step == RolloutStep::Retain
            || dominators
                .get(step)
                .is_some_and(|values| values.contains(&RolloutStep::Retain))
    })
}

/// Lowers the rollout lifecycle into an ordinary provider transition fragment.
///
/// `template` carries a binding, interface, resource, grants, inputs, deadline,
/// and recovery contract that have already been derived from the selected
/// provider. This function replaces only the semantic operation identity and
/// graph structure. The transition planner still validates every invocation
/// against the current checked binding and retained artifacts.
///
/// # Errors
///
/// Returns an error if a stable built-in node or method key cannot be built.
pub fn lower_ab_rollout_fragment(
    template: &Operation,
) -> anyhow::Result<crate::TransitionFragment> {
    let operation = |key: &str,
                     method: &str,
                     action: ImageRolloutAction,
                     phase: OperationPhase,
                     branch_context: Vec<BranchMembership>|
     -> anyhow::Result<Operation> {
        let mut operation = template.clone();
        operation.key = scoped_key(template, key)?;
        operation.method = LocalKey::new(method)?;
        operation.family = OperationFamily::ImageRollout { action };
        operation.phase = phase;
        operation.branch_context = branch_context;
        operation.target.operations = vec![operation.method.clone()];
        let access = if matches!(
            action,
            ImageRolloutAction::ObserveBoot | ImageRolloutAction::ObserveHealth
        ) {
            AccessMode::Read
        } else {
            AccessMode::ExclusiveWrite
        };
        for resource in &mut operation.accesses {
            resource.mode = access;
        }
        let observation_method = MethodReference {
            interface: operation.interface.clone(),
            method: operation.method.clone(),
        };
        operation.recovery.reconcile = Some(observation_method.clone());
        operation.recovery.cancel = Some(observation_method);
        operation.recovery.compensate = None;
        Ok(operation)
    };
    let decision_key = scoped_key(template, "health-decision")?;
    let fallback = LocalKey::new("fallback")?;
    let healthy = LocalKey::new("healthy")?;
    let fallback_context = vec![BranchMembership {
        decision: decision_key.clone(),
        alternative: fallback.clone(),
    }];
    let healthy_context = vec![BranchMembership {
        decision: decision_key.clone(),
        alternative: healthy.clone(),
    }];
    let operations = vec![
        operation(
            "drain",
            "drain",
            ImageRolloutAction::Drain,
            OperationPhase::Converging,
            Vec::new(),
        )?,
        operation(
            "hold-fallback",
            "hold",
            ImageRolloutAction::Hold,
            OperationPhase::Recovering,
            fallback_context.clone(),
        )?,
        operation(
            "hold-healthy",
            "hold",
            ImageRolloutAction::Hold,
            OperationPhase::Recovering,
            healthy_context.clone(),
        )?,
        operation(
            "observe-boot",
            "observe-boot",
            ImageRolloutAction::ObserveBoot,
            OperationPhase::Converging,
            Vec::new(),
        )?,
        operation(
            "observe-health",
            "observe-health",
            ImageRolloutAction::ObserveHealth,
            OperationPhase::Converging,
            Vec::new(),
        )?,
        operation(
            "prepare",
            "prepare",
            ImageRolloutAction::Prepare,
            OperationPhase::Preparing,
            Vec::new(),
        )?,
        operation(
            "retain",
            "retain",
            ImageRolloutAction::Retain,
            OperationPhase::Preparing,
            Vec::new(),
        )?,
        operation(
            "select",
            "select",
            ImageRolloutAction::Select,
            OperationPhase::Publishing,
            Vec::new(),
        )?,
        operation(
            "settle-hold-fallback",
            "hold",
            ImageRolloutAction::Hold,
            OperationPhase::Recovering,
            fallback_context.clone(),
        )?,
        operation(
            "settle-hold-healthy",
            "hold",
            ImageRolloutAction::Hold,
            OperationPhase::Recovering,
            healthy_context.clone(),
        )?,
        operation(
            "settle-observe-health",
            "observe-health",
            ImageRolloutAction::ObserveHealth,
            OperationPhase::Converging,
            Vec::new(),
        )?,
        operation(
            "withdraw",
            "withdraw",
            ImageRolloutAction::Withdraw,
            OperationPhase::Recovering,
            fallback_context.clone(),
        )?,
    ];
    let key = |name: &str| scoped_key(template, name);
    let decision = DecisionNode {
        key: decision_key.clone(),
        branch_context: Vec::new(),
        selector: DecisionSelector {
            result: OperationResultReference {
                producer: ResultProducerKey::Operation {
                    key: key("settle-observe-health")?,
                },
                output: LocalKey::new("healthy")?,
            },
            tag_field: None,
        },
        alternatives: vec![
            DecisionAlternative {
                key: fallback,
                predicate: DecisionPredicate::Boolean { value: false },
            },
            DecisionAlternative {
                key: healthy,
                predicate: DecisionPredicate::Boolean { value: true },
            },
        ],
    };
    let merge_key = key("terminal")?;
    let state_output = LocalKey::new("rollout-state")?;
    let merge = MergeNode {
        key: merge_key.clone(),
        decision: decision_key.clone(),
        branch_context: Vec::new(),
        outputs: std::collections::BTreeMap::from([(
            state_output.clone(),
            MergedOutput {
                descriptor: aos_ability_model::OutputDescriptor {
                    schema: aos_ability_model::builtin::ab_image_rollout_observation_schema()?,
                    phase: aos_ability_model::ValuePhase::Observation,
                    visibility: aos_ability_model::ValueVisibility::Protected,
                    lifetime: aos_ability_model::ResourceLifetime::Persistent,
                },
                alternatives: std::collections::BTreeMap::from([
                    (
                        LocalKey::new("fallback")?,
                        OperationResultReference {
                            producer: ResultProducerKey::Operation {
                                key: key("settle-hold-fallback")?,
                            },
                            output: state_output.clone(),
                        },
                    ),
                    (
                        LocalKey::new("healthy")?,
                        OperationResultReference {
                            producer: ResultProducerKey::Operation {
                                key: key("settle-hold-healthy")?,
                            },
                            output: state_output.clone(),
                        },
                    ),
                ]),
            },
        )]),
    };
    let edge = |from: PlanNodeKey, to: PlanNodeKey, kind| DependencyEdge { from, to, kind };
    let op = |name: &str| -> anyhow::Result<PlanNodeKey> {
        Ok(PlanNodeKey::Operation { key: key(name)? })
    };
    let decision_node = PlanNodeKey::Decision { key: decision_key };
    let merge_node = PlanNodeKey::Merge { key: merge_key };
    let mut edges = vec![
        edge(
            op("retain")?,
            op("prepare")?,
            DependencyKind::RequiredSuccess,
        ),
        edge(op("retain")?, op("drain")?, DependencyKind::Retention),
        edge(
            op("prepare")?,
            op("drain")?,
            DependencyKind::RequiredSuccess,
        ),
        edge(op("drain")?, op("select")?, DependencyKind::RequiredSuccess),
        edge(
            op("select")?,
            op("observe-boot")?,
            DependencyKind::RequiredSuccess,
        ),
        edge(
            op("observe-boot")?,
            op("observe-health")?,
            DependencyKind::RequiredSuccess,
        ),
        edge(
            op("observe-health")?,
            op("settle-observe-health")?,
            DependencyKind::RequiredSuccess,
        ),
        edge(
            op("settle-observe-health")?,
            decision_node.clone(),
            DependencyKind::Data,
        ),
        edge(
            decision_node.clone(),
            op("hold-fallback")?,
            DependencyKind::BranchGuard,
        ),
        edge(
            decision_node.clone(),
            op("settle-hold-fallback")?,
            DependencyKind::BranchGuard,
        ),
        edge(
            decision_node.clone(),
            op("hold-healthy")?,
            DependencyKind::BranchGuard,
        ),
        edge(
            decision_node.clone(),
            op("settle-hold-healthy")?,
            DependencyKind::BranchGuard,
        ),
        edge(decision_node, op("withdraw")?, DependencyKind::BranchGuard),
        edge(
            op("withdraw")?,
            op("hold-fallback")?,
            DependencyKind::RequiredSuccess,
        ),
        edge(
            op("hold-fallback")?,
            op("settle-hold-fallback")?,
            DependencyKind::RequiredSuccess,
        ),
        edge(
            op("settle-hold-fallback")?,
            merge_node.clone(),
            DependencyKind::BranchMerge,
        ),
        edge(
            op("hold-healthy")?,
            op("settle-hold-healthy")?,
            DependencyKind::RequiredSuccess,
        ),
        edge(
            op("settle-hold-healthy")?,
            merge_node,
            DependencyKind::BranchMerge,
        ),
    ];
    edges.sort_by(aos_ability_model::compare_edges);

    Ok(crate::TransitionFragment {
        schema: crate::TRANSITION_FRAGMENT_SCHEMA.to_string(),
        operations,
        decisions: vec![decision],
        merges: vec![merge],
        edges,
        exports: Vec::new(),
        imports: Vec::new(),
        links: Vec::new(),
        handoffs: Vec::new(),
        provider_readiness: Vec::new(),
        obligations: Vec::new(),
    })
}

fn scoped_key(template: &Operation, key: &str) -> anyhow::Result<ScopedOperationKey> {
    Ok(ScopedOperationKey {
        scope: template.key.scope.clone(),
        key: LocalKey::new(key)?,
    })
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{AbilityValue, AccessMode, ValueExpression, VersionedDocument};
    use aos_contract::Sha256Digest;

    use super::*;

    fn image(seed: u8, state_format: &str) -> RolloutImageIdentity {
        RolloutImageIdentity {
            toplevel: format!(
                "/nix/store/{}-toplevel",
                char::from(b'a' + seed).to_string().repeat(32)
            ),
            uki: format!("EFI/Linux/aos-{seed}+3.efi"),
            executor: format!(
                "/nix/store/{}-executor",
                char::from(b'k' + seed).to_string().repeat(32)
            ),
            state_format: state_format.into(),
        }
    }

    fn request() -> AbRolloutRequest {
        AbRolloutRequest {
            strategy: "single-host-ab-v1".into(),
            concurrency: 1,
            predecessor: image(0, "7"),
            candidate: image(1, "7"),
            retention_expires_at_millis: 2_000,
        }
    }

    fn authority(active_image: RolloutImageIdentity) -> RolloutAuthority {
        RolloutAuthority {
            policy_revision: RevisionId(Sha256Digest::of_bytes(b"policy")),
            provider_incarnation: IncarnationId::new("incarnation-1").unwrap(),
            active_image,
            revoked: false,
        }
    }

    #[test]
    fn happy_path_retains_both_images_before_rollout_effects() {
        let request = request();
        let plan = admit_ab_rollout(
            request.clone(),
            &authority(request.predecessor.clone()),
            1_000,
        )
        .unwrap();

        assert!(retention_dominates_effects(&plan));
        assert_eq!(plan.steps[0], RolloutStep::Retain);
        assert!(plan.dependencies.contains(&RolloutDependency {
            from: RolloutStep::ObserveHealth,
            to: RolloutStep::Withdraw,
            branch: Some(RolloutBranch::Fallback),
        }));
        assert!(plan.dependencies.contains(&RolloutDependency {
            from: RolloutStep::ObserveHealth,
            to: RolloutStep::Hold,
            branch: Some(RolloutBranch::Healthy),
        }));
    }

    #[test]
    fn retention_dominance_rejects_a_second_root_that_bypasses_retention() {
        let request = request();
        let mut plan = admit_ab_rollout(
            request.clone(),
            &authority(request.predecessor.clone()),
            1_000,
        )
        .unwrap();
        plan.dependencies.retain(|dependency| {
            !(dependency.from == RolloutStep::Retain && dependency.to == RolloutStep::Prepare)
        });

        assert!(!retention_dominates_effects(&plan));
    }

    #[test]
    fn retention_dominance_rejects_duplicate_and_unreachable_steps() {
        let request = request();
        let plan = admit_ab_rollout(
            request.clone(),
            &authority(request.predecessor.clone()),
            1_000,
        )
        .unwrap();

        let mut duplicate = plan.clone();
        duplicate.steps.push(RolloutStep::Hold);
        assert!(!retention_dominates_effects(&duplicate));

        let mut unreachable = plan;
        unreachable.dependencies.retain(|dependency| {
            dependency.from != RolloutStep::ObserveBoot && dependency.to != RolloutStep::ObserveBoot
        });
        unreachable.dependencies.push(RolloutDependency {
            from: RolloutStep::ObserveBoot,
            to: RolloutStep::ObserveBoot,
            branch: None,
        });
        assert!(!retention_dominates_effects(&unreachable));
    }

    #[test]
    fn admission_rejects_stale_revoked_and_incompatible_requests() {
        let base = request();
        assert_eq!(
            admit_ab_rollout(base.clone(), &authority(image(2, "7")), 1_000).unwrap_err(),
            RolloutAdmissionError::StalePredecessor
        );

        let mut revoked = authority(base.predecessor.clone());
        revoked.revoked = true;
        assert_eq!(
            admit_ab_rollout(base.clone(), &revoked, 1_000).unwrap_err(),
            RolloutAdmissionError::Revoked
        );

        let mut incompatible = base.clone();
        incompatible.candidate.state_format = "8".into();
        assert_eq!(
            admit_ab_rollout(incompatible, &authority(base.predecessor.clone()), 1_000,)
                .unwrap_err(),
            RolloutAdmissionError::IncompatibleState
        );
    }

    #[test]
    fn retention_is_bounded_and_retirement_needs_fresh_authority() {
        let rollout_request = request();
        assert_eq!(
            admit_retirement(
                rollout_request.clone(),
                &authority(rollout_request.predecessor.clone()),
                1_999,
            )
            .unwrap_err(),
            RolloutAdmissionError::RetentionActive
        );

        let mut current = authority(rollout_request.candidate.clone());
        current.policy_revision = RevisionId(Sha256Digest::of_bytes(b"new-policy"));
        current.provider_incarnation = IncarnationId::new("incarnation-2").unwrap();
        let retirement = admit_retirement(rollout_request, &current, 2_000).unwrap();
        assert_eq!(retirement.policy_revision, current.policy_revision);
        assert_eq!(
            retirement.provider_incarnation,
            current.provider_incarnation
        );

        let mut revoked = current;
        revoked.revoked = true;
        assert_eq!(
            admit_retirement(request(), &revoked, 2_000).unwrap_err(),
            RolloutAdmissionError::Revoked
        );

        let mut incompatible = request();
        incompatible.candidate.state_format = "8".into();
        assert_eq!(
            admit_retirement(incompatible, &revoked, 2_000).unwrap_err(),
            RolloutAdmissionError::IncompatibleState
        );
    }

    #[test]
    fn rollback_is_a_new_current_authority_plan() {
        let forward = request();
        let mut rollback = forward.clone();
        rollback.predecessor = forward.candidate;
        rollback.candidate = forward.predecessor;
        rollback.retention_expires_at_millis = 3_000;
        let current = authority(rollback.predecessor.clone());

        let plan = admit_ab_rollout(rollback, &current, 2_000).unwrap();
        assert_eq!(plan.policy_revision, current.policy_revision);
        assert_eq!(plan.provider_incarnation, current.provider_incarnation);
    }

    #[test]
    fn lowered_effect_plan_has_durable_exclusive_health_branches() {
        let mut fixture = aos_ability_validate::test_support::plan_fixture();
        let artifact = fixture.binding_plan.bindings[0]
            .implementation
            .artifact
            .clone();
        fixture.interfaces =
            vec![aos_ability_model::builtin::ab_image_rollout_interface().unwrap()];
        fixture.refresh_interface_with_features(BTreeSet::from([
            aos_ability_model::RequiredFeature::new(
                aos_ability_model::builtin::AB_IMAGE_ROLLOUT_FEATURE,
            )
            .unwrap(),
        ]));
        let provider =
            aos_ability_model::builtin::ab_image_rollout_provider(artifact.clone()).unwrap();
        let implementation = aos_ability_model::ProviderImplementationReference {
            descriptor: provider.descriptor_digest().unwrap(),
            artifact,
            handler: Some(aos_ability_model::builtin::ab_image_rollout_handler_key().unwrap()),
        };
        fixture.binding_inputs.environment.providers[0].implementation = implementation.clone();
        fixture.binding_plan.bindings[0].implementation = implementation;
        let methods = fixture.interfaces[0]
            .interface
            .methods
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        fixture.binding_inputs.desired_state.child_requests[0].methods = methods.clone();
        fixture.binding_plan.requests[0].methods = methods.clone();
        fixture.binding_plan.bindings[0].caller_grant.methods = methods.clone();
        fixture.binding_plan.bindings[0].caller_grant.resources[0].access =
            AccessMode::ExclusiveWrite;
        fixture.binding_plan.bindings[0].caller_grant.resources[0].operations = methods.clone();
        let resource = fixture.effect_plan.current_revisions[0].resource.clone();
        let controller = aos_ability_model::AggregateId {
            provider: resource.provider.clone(),
            group: LocalKey::new("rollout").unwrap(),
        };
        let controller_assignment = aos_ability_model::ControllerAssignment {
            resource,
            controller: controller.clone(),
        };
        fixture.binding_inputs.environment.controllers = vec![controller_assignment.clone()];
        fixture.binding_inputs.desired_state.controllers = vec![controller_assignment.clone()];
        fixture.effect_plan.controllers = vec![controller_assignment];
        fixture.effect_plan.operations[0].target.operations = methods;
        fixture.effect_plan.operations[0].input_phase = aos_ability_model::ValuePhase::Planning;
        fixture.effect_plan.operations[0].controller = Some(controller);
        fixture.effect_plan.operations[0].inputs = ValueExpression::Literal {
            value: AbilityValue::new(serde_json::to_value(request()).unwrap()).unwrap(),
        };
        let fragment = lower_ab_rollout_fragment(&fixture.effect_plan.operations[0]).unwrap();
        fixture.effect_plan.operations = fragment.operations;
        fixture.effect_plan.decisions = fragment.decisions;
        fixture.effect_plan.merges = fragment.merges;
        fixture.effect_plan.edges = fragment.edges;
        fixture.refresh_commitments();
        let binding_plan = fixture.binding_plan.content_digest().unwrap();

        let checked = fixture.validate().unwrap();
        assert!(
            checked
                .operations()
                .iter()
                .find(|operation| operation.key.key.as_str() == "withdraw")
                .unwrap()
                .branch_context
                .iter()
                .any(|branch| branch.alternative.as_str() == "fallback")
        );
        assert_eq!(checked.document().decisions.len(), 1);
        assert_eq!(checked.document().merges.len(), 1);
        assert_eq!(checked.document().binding_plan, binding_plan);
        assert!(checked.operations().iter().all(|operation| {
            let expected = MethodReference {
                interface: operation.interface.clone(),
                method: operation.method.clone(),
            };
            operation.recovery.reconcile.as_ref() == Some(&expected)
                && operation.recovery.cancel.as_ref() == Some(&expected)
                && operation.recovery.compensate.is_none()
        }));
    }
}
