//! Scoped transition inputs and authenticated state projection.
//!
//! Each pure transition entry receives one closed context shaped as follows:
//!
//! ```text
//! {"schema":"aos.ability.transition-context/v1",
//!  "desired_planning":"sha256:...","current_planning":null,
//!  "provider":{...},"authorized_bindings":[...],"before":null,
//!  "after":{...},"observations":{...}}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::{
    Contribution, DesiredInstance, FreshnessCondition, PlatformIdentity, ProviderInventory,
};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, AggregateOutput, Binding, BindingId, BindingRequest,
    ControllerAssignment, EnvironmentId, InstanceId, PlanId, ProviderImplementationReference,
    RequestId, ResourceRevision, RevisionId, ScopePath, TeardownProviderAuthorization,
    TransactionId,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{CompositionOutcome, EvaluationError, VerifiedPlanningSnapshot};

use super::TransitionError;

/// Exact schema discriminator passed to pure transition constructors.
pub const TRANSITION_CONTEXT_SCHEMA: &str = "aos.ability.transition-context/v1";

/// Schema discriminator for transition contexts carrying live reconciliation input.
pub const TRANSITION_CONTEXT_SCHEMA_V2: &str = "aos.ability.transition-context/v2";

/// Exact schema discriminator for one trusted runtime observation publication.
pub const RUNTIME_OBSERVATIONS_SCHEMA: &str = "aos.ability.runtime-observations/v1";

/// Classifies one provider-owned logical resource change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceChangeKind {
    /// Adds a resource absent from the authenticated current snapshot.
    Create,
    /// Changes the desired semantic revision of an existing resource.
    Update,
    /// Removes a resource present in the authenticated current snapshot.
    Remove,
    /// Preserves the same logical resource and semantic revision.
    Unchanged,
    /// Repairs a desired resource that was observed at its exact revision but stopped.
    ReconcileStopped,
    /// Repairs a desired resource whose live behavior contradicted its exact revision.
    ReconcileDivergent,
}

/// Classifies the live health of one present native resource.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeResourceHealth {
    /// The resource is available and its behavior matches the desired contract.
    Healthy,
    /// The resource exists at the expected revision but is not running.
    Stopped,
    /// The resource exists, but direct behavior evidence contradicts its contract.
    Divergent,
}

/// Carries one authoritative live resource classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeResourceState {
    /// An authoritative probe established that the resource is absent.
    Absent,
    /// An authoritative probe established a present semantic revision and health.
    Present {
        /// Identifies the semantic revision established by the probe.
        revision: RevisionId,
        /// Classifies direct live behavior at that revision.
        health: RuntimeResourceHealth,
    },
}

/// Records one exact resource observation used to construct a repair graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResourceObservation {
    /// Identifies the logical resource that was probed.
    pub resource: aos_ability_model::ResourceId,
    /// Carries the authoritative presence, revision, and health result.
    pub state: RuntimeResourceState,
}

/// Links one live classification publication to the repair graph it produced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionReconciliation {
    /// Carries [`RUNTIME_OBSERVATIONS_SCHEMA`].
    pub schema: String,
    /// Identifies the initially checked graph whose no-op assumption was disproved.
    pub source_plan: PlanId,
    /// Separates this protected classification from other attempts for that graph.
    pub transaction: TransactionId,
    /// Identifies the revocation-sensitive operator policy publication.
    pub policy_fence: RevisionId,
    /// Binds the observation to the protected current-authority epoch.
    pub authority_epoch: u64,
    /// Identifies the exact current-authority publication in that epoch.
    pub sequence: u64,
    /// Records the trusted restart-stable time at which resources were classified.
    pub observed_at_restart_millis: u64,
    /// Bounds how long the classification may be used to construct a repair graph.
    pub max_age_millis: u64,
    /// Commits to the protected current-authority document used for classification.
    pub authority_publication: Sha256Digest,
    /// Retains the exact protected current-authority publication as bounded JSON.
    pub authority_document: AbilityValue,
    /// Names settled provider handoffs that still require linked ownership settlement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsettled_provider_adoptions: Vec<aos_ability_model::ResourceId>,
    /// Lists exact classified resources in canonical logical-resource order.
    pub observations: Vec<RuntimeResourceObservation>,
}

#[derive(Deserialize)]
pub(super) struct LinkedCurrentAuthorityDocument {
    pub(super) schema: String,
    pub(super) policy_fence: RevisionId,
    pub(super) transaction: TransactionId,
    pub(super) authority_epoch: u64,
    pub(super) sequence: u64,
    pub(super) observed_at_restart_millis: u64,
    pub(super) max_age_millis: u64,
    pub(super) plan: PlanId,
    pub(super) resource_observations: Vec<LinkedCurrentResourceObservation>,
}

#[derive(Deserialize)]
pub(super) struct LinkedCurrentResourceObservation {
    pub(super) resource: aos_ability_model::ResourceId,
    pub(super) state: LinkedCurrentResourceState,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub(super) enum LinkedCurrentResourceState {
    Absent,
    Present { revision: RevisionId },
    Stopped { revision: RevisionId },
    Divergent { revision: RevisionId },
}

/// Supplies one exact before-and-after resource comparison to a constructor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceChange {
    /// Identifies the logical provider-owned resource.
    pub resource: aos_ability_model::ResourceId,
    /// Carries the authenticated current revision when the resource exists.
    pub current: Option<RevisionId>,
    /// Carries the normalized desired revision when the resource remains desired.
    pub desired: Option<RevisionId>,
    /// Classifies the exact current and desired revision relationship.
    pub kind: ResourceChangeKind,
}

/// Carries the desired-state records visible to one provider implementation.
///
/// The planner includes records owned by the provider and records that identify
/// it as consumer, provider, or controller. This preserves the complete local
/// before-and-after contract without exposing unrelated deployment state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedDesiredState {
    /// Lists deployment instances for this exact provider.
    pub instances: Vec<DesiredInstance>,
    /// Lists contributions admitted to provider-owned aggregates.
    pub contributions: Vec<Contribution>,
    /// Lists lower-interface requests authored by this provider.
    pub child_requests: Vec<BindingRequest>,
    /// Lists desired revisions of provider-owned resources.
    pub resources: Vec<ResourceRevision>,
    /// Lists outputs published by provider-owned aggregates.
    pub outputs: Vec<AggregateOutput>,
    /// Lists lifecycle assignments controlled by this provider.
    pub controllers: Vec<ControllerAssignment>,
    /// Lists checked bindings in which this provider is caller or provider.
    pub bindings: Vec<Binding>,
}

/// Carries authenticated environment observations visible to one provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedObservations {
    /// Identifies the observed environment and execution stage.
    pub environment: EnvironmentId,
    /// Identifies the observed target platform.
    pub platform: PlatformIdentity,
    /// Identifies the policy revision authenticating the observations.
    pub policy_revision: RevisionId,
    /// Bounds the observation generation and accepted age.
    pub freshness: FreshnessCondition,
    /// Lists exact provider inventory entries for this provider.
    pub providers: Vec<ProviderInventory>,
    /// Lists authenticated revisions of provider-owned resources.
    pub resources: Vec<ResourceRevision>,
    /// Lists authenticated controller assignments owned by this provider.
    pub controllers: Vec<ControllerAssignment>,
}

/// Identifies the sealed authority role of one constructor-visible binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "role", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TransitionBindingAuthority {
    /// Uses a binding from the checked desired-state plan.
    Desired,
    /// Uses a prior binding remapped by fresh current policy.
    Teardown {
        /// Identifies the exact prior binding that supplied selection evidence.
        source_binding: BindingId,
        /// Identifies the exact prior request that supplied contract evidence.
        source_request: RequestId,
    },
}

/// Supplies an exact outgoing binding and its sealed transition authority role.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedTransitionBinding {
    /// Carries the desired or transition-local checked binding.
    pub binding: Binding,
    /// Distinguishes desired authority from fresh teardown authority.
    pub authority: TransitionBindingAuthority,
}

/// Carries one exact pure provider's scoped transition-construction input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionContext {
    /// Carries [`TRANSITION_CONTEXT_SCHEMA`].
    pub schema: String,
    /// Commits to the verified desired planning snapshot.
    pub desired_planning: Sha256Digest,
    /// Commits to the verified prior planning snapshot, when one existed.
    pub current_planning: Option<Sha256Digest>,
    /// Identifies the provider authoring this fragment.
    pub provider: InstanceId,
    /// Identifies the exact public interface implementation being evaluated.
    pub interface: aos_ability_model::InterfaceKey,
    /// Pins the exact implementation descriptor and artifact.
    pub implementation: ProviderImplementationReference,
    /// Identifies the exact retained package document.
    pub package: Sha256Digest,
    /// Assigns the exclusive graph-key scope for this implementation.
    pub operation_scope: ScopePath,
    /// Lists exact outgoing bindings authorized for this constructor call.
    pub authorized_bindings: Vec<AuthorizedTransitionBinding>,
    /// Carries fresh root authority when retiring an operator-enabled provider.
    pub teardown_provider_authority: Option<TeardownProviderAuthorization>,
    /// Carries scoped prior desired state, absent for first activation.
    pub before: Option<ScopedDesiredState>,
    /// Carries scoped desired state after this transition.
    pub after: ScopedDesiredState,
    /// Carries current authenticated observations from the desired plan input.
    pub observations: ScopedObservations,
    /// Lists exact changes owned by this provider or exposed through binding grants.
    ///
    /// Outgoing caller grants and incoming provider grants expose lower-resource
    /// changes so a recursive provider can coordinate lifecycle boundaries.
    pub changes: Vec<ResourceChange>,
    /// Lists current and desired lifecycle controller assignments in scope.
    pub controllers: Vec<ControllerAssignment>,
}

pub(super) fn scoped_desired_state(
    snapshot: &VerifiedPlanningSnapshot,
    provider: &InstanceId,
) -> ScopedDesiredState {
    let desired = snapshot.checked_binding().desired_state();
    ScopedDesiredState {
        instances: desired
            .instances
            .iter()
            .filter(|instance| instance.instance == *provider)
            .cloned()
            .collect(),
        contributions: desired
            .contributions
            .iter()
            .filter(|contribution| contribution.aggregate.provider == *provider)
            .cloned()
            .collect(),
        child_requests: desired
            .child_requests
            .iter()
            .filter(|request| request.id.consumer == *provider)
            .cloned()
            .collect(),
        resources: desired
            .resources
            .iter()
            .filter(|revision| revision.resource.provider == *provider)
            .cloned()
            .collect(),
        outputs: desired
            .outputs
            .iter()
            .filter(|output| output.aggregate.provider == *provider)
            .cloned()
            .collect(),
        controllers: desired
            .controllers
            .iter()
            .filter(|assignment| {
                assignment.resource.provider == *provider
                    || assignment.controller.provider == *provider
            })
            .cloned()
            .collect(),
        bindings: snapshot
            .checked_binding()
            .bindings()
            .iter()
            .filter(|binding| {
                binding.provider == *provider || binding.request.consumer == *provider
            })
            .cloned()
            .collect(),
    }
}

pub(super) fn scoped_observations(
    desired: &VerifiedPlanningSnapshot,
    provider: &InstanceId,
) -> ScopedObservations {
    let environment = desired.checked_binding().environment();
    ScopedObservations {
        environment: environment.environment.clone(),
        platform: environment.platform.clone(),
        policy_revision: environment.policy_revision,
        freshness: environment.freshness.clone(),
        providers: environment
            .providers
            .iter()
            .filter(|inventory| inventory.provider == *provider)
            .cloned()
            .collect(),
        resources: environment
            .resources
            .iter()
            .filter(|revision| revision.resource.provider == *provider)
            .cloned()
            .collect(),
        controllers: environment
            .controllers
            .iter()
            .filter(|assignment| {
                assignment.resource.provider == *provider
                    || assignment.controller.provider == *provider
            })
            .cloned()
            .collect(),
    }
}

pub(super) fn encode_ability_value(
    value: &impl Serialize,
) -> Result<AbilityValue, TransitionError> {
    let json = serde_json::to_value(value)
        .map_err(|error| TransitionError::Encoding(error.to_string()))?;
    AbilityValue::new(json).map_err(|error| TransitionError::Encoding(error.to_string()))
}

pub(super) fn bounded_evaluation_message(error: &EvaluationError) -> String {
    let message = error.to_string();
    if message.len() <= ABILITY_LIMITS_V1.max_string_bytes as usize {
        message
    } else {
        "transition evaluator returned an oversized failure message".to_string()
    }
}

pub(super) fn resource_changes(
    current: &[ResourceRevision],
    desired: &[ResourceRevision],
    observations: Option<&[RuntimeResourceObservation]>,
) -> Vec<ResourceChange> {
    let mut current: BTreeMap<_, _> = current
        .iter()
        .map(|revision| (revision.resource.clone(), revision.revision))
        .collect();
    let desired: BTreeMap<_, _> = desired
        .iter()
        .map(|revision| (revision.resource.clone(), revision.revision))
        .collect();
    let observations: BTreeMap<_, _> = observations
        .unwrap_or_default()
        .iter()
        .map(|observation| (observation.resource.clone(), observation.state))
        .collect();
    for (resource, state) in &observations {
        match state {
            RuntimeResourceState::Absent => {
                current.remove(resource);
            }
            RuntimeResourceState::Present { revision, .. } => {
                current.insert(resource.clone(), *revision);
            }
        }
    }
    current
        .keys()
        .chain(desired.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|resource| {
            let current = current.get(&resource).copied();
            let desired = desired.get(&resource).copied();
            let kind = match observations.get(&resource) {
                Some(RuntimeResourceState::Present {
                    revision,
                    health: RuntimeResourceHealth::Stopped,
                }) if desired == Some(*revision) => ResourceChangeKind::ReconcileStopped,
                Some(RuntimeResourceState::Present {
                    revision,
                    health: RuntimeResourceHealth::Divergent,
                }) if desired == Some(*revision) => ResourceChangeKind::ReconcileDivergent,
                _ => match (current, desired) {
                    (None, Some(_)) => ResourceChangeKind::Create,
                    (Some(_), None) => ResourceChangeKind::Remove,
                    (Some(left), Some(right)) if left != right => ResourceChangeKind::Update,
                    (Some(_), Some(_)) => ResourceChangeKind::Unchanged,
                    (None, None) => return None,
                },
            };
            Some(ResourceChange {
                resource,
                current,
                desired,
                kind,
            })
        })
        .collect()
}

pub(super) fn controller_union(outcome: &CompositionOutcome) -> Vec<ControllerAssignment> {
    let mut controllers: BTreeMap<_, _> = outcome
        .resolution
        .checked
        .environment()
        .controllers
        .iter()
        .map(|assignment| (assignment.resource.clone(), assignment.clone()))
        .collect();
    controllers.extend(
        outcome
            .resolution
            .checked
            .desired_state()
            .controllers
            .iter()
            .map(|assignment| (assignment.resource.clone(), assignment.clone())),
    );
    controllers.into_values().collect()
}

pub(super) fn scoped_changes_and_controllers(
    provider: &InstanceId,
    changes: &[ResourceChange],
    controllers: &[ControllerAssignment],
    authorized_outgoing: &[AuthorizedTransitionBinding],
    binding_plan: &[Binding],
) -> (Vec<ResourceChange>, Vec<ControllerAssignment>) {
    let outgoing_resources = authorized_outgoing.iter().filter(|authorized| {
        authorized.binding.request.consumer == *provider
            && authorized.binding.caller_grant.principal == *provider
    });
    let incoming_resources = binding_plan.iter().filter(|binding| {
        binding.provider == *provider && binding.provider_grant.principal == *provider
    });
    let granted_resources = outgoing_resources
        .flat_map(|authorized| &authorized.binding.caller_grant.resources)
        .chain(incoming_resources.flat_map(|binding| &binding.provider_grant.resources))
        .map(|permission| permission.resource.clone())
        .collect::<BTreeSet<_>>();

    let visible_changes = changes
        .iter()
        .filter(|change| {
            change.resource.provider == *provider || granted_resources.contains(&change.resource)
        })
        .cloned()
        .collect();
    let visible_controllers = controllers
        .iter()
        .filter(|assignment| {
            assignment.controller.provider == *provider
                || granted_resources.contains(&assignment.resource)
        })
        .cloned()
        .collect();

    (visible_changes, visible_controllers)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::{
        AccessMode, AggregateId, ArtifactReference, AuthorityGrant, BindingSource, ExecutionStage,
        InterfaceKey, InterfaceName, LocalKey, ResourceId, ResourceLifetime, ResourcePermission,
    };

    use super::*;

    #[test]
    fn change_projection_includes_only_owned_and_exactly_granted_resources() {
        let provider = instance("provider");
        let lower = instance("lower");
        let caller = instance("caller");
        let unrelated = instance("unrelated");
        let own = resource(&provider, "own");
        let outgoing = resource(&lower, "outgoing");
        let incoming = resource(&lower, "incoming");
        let unrelated_binding = resource(&lower, "unrelated-binding");
        let unrelated_principal = resource(&lower, "unrelated-principal");
        let foreign = resource(&lower, "foreign");

        let outgoing_binding = binding(
            "outgoing",
            &provider,
            &lower,
            grant(&provider, &[outgoing.clone()]),
            grant(&lower, &[]),
        );
        let incoming_binding = binding(
            "incoming",
            &caller,
            &provider,
            grant(&caller, &[]),
            grant(&provider, &[incoming.clone()]),
        );
        let foreign_binding = binding(
            "foreign",
            &unrelated,
            &lower,
            grant(&unrelated, &[unrelated_binding.clone()]),
            grant(&lower, &[]),
        );
        let wrong_principal_binding = binding(
            "wrong-principal",
            &provider,
            &lower,
            grant(&unrelated, &[unrelated_principal.clone()]),
            grant(&lower, &[]),
        );
        let authorized_outgoing = vec![
            authorized(outgoing_binding.clone()),
            authorized(foreign_binding.clone()),
            authorized(wrong_principal_binding.clone()),
        ];
        let binding_plan = vec![
            outgoing_binding,
            incoming_binding,
            foreign_binding,
            wrong_principal_binding,
        ];
        let changes = [
            own.clone(),
            outgoing.clone(),
            incoming.clone(),
            unrelated_binding,
            unrelated_principal,
            foreign,
        ]
        .into_iter()
        .map(change)
        .collect::<Vec<_>>();
        let controllers = changes
            .iter()
            .map(|change| {
                let controller_provider = if change.resource == own {
                    provider.clone()
                } else {
                    lower.clone()
                };
                controller(change.resource.clone(), controller_provider)
            })
            .collect::<Vec<_>>();

        let (visible_changes, visible_controllers) = scoped_changes_and_controllers(
            &provider,
            &changes,
            &controllers,
            &authorized_outgoing,
            &binding_plan,
        );
        let visible_resources = visible_changes
            .iter()
            .map(|change| change.resource.clone())
            .collect::<BTreeSet<_>>();
        let visible_controller_resources = visible_controllers
            .iter()
            .map(|assignment| assignment.resource.clone())
            .collect::<BTreeSet<_>>();
        let expected = BTreeSet::from([own, outgoing, incoming]);

        assert_eq!(visible_resources, expected);
        assert_eq!(visible_controller_resources, expected);
    }

    #[test]
    fn teardown_projection_uses_only_fresh_remapped_outgoing_grants() {
        let provider = instance("provider");
        let lower = instance("lower");
        let stale = resource(&lower, "stale");
        let remapped = resource(&lower, "remapped");
        let stale_binding = binding(
            "stale",
            &provider,
            &lower,
            grant(&provider, &[stale.clone()]),
            grant(&lower, &[]),
        );
        let remapped_binding = binding(
            "remapped",
            &provider,
            &lower,
            grant(&provider, &[remapped.clone()]),
            grant(&lower, &[]),
        );
        let authorized_outgoing = vec![AuthorizedTransitionBinding {
            binding: remapped_binding.clone(),
            authority: TransitionBindingAuthority::Teardown {
                source_binding: stale_binding.id.clone(),
                source_request: stale_binding.request.clone(),
            },
        }];
        let binding_plan = vec![stale_binding, remapped_binding];
        let changes = vec![change(stale), change(remapped.clone())];

        let (visible_changes, _) = scoped_changes_and_controllers(
            &provider,
            &changes,
            &[],
            &authorized_outgoing,
            &binding_plan,
        );
        let [visible] = visible_changes.as_slice() else {
            panic!("only the freshly authorized remapped resource must be visible");
        };

        assert_eq!(visible.resource, remapped);
    }

    #[test]
    fn runtime_observations_select_bounded_repair_change_kinds() {
        let provider = instance("provider");
        let stopped = resource(&provider, "stopped");
        let divergent = resource(&provider, "divergent");
        let absent = resource(&provider, "absent");
        let stale = resource(&provider, "stale");
        let desired_revision = RevisionId(Sha256Digest::separated(
            "aos.test.transition-context/v1",
            b"desired",
        ));
        let stale_revision = RevisionId(Sha256Digest::separated(
            "aos.test.transition-context/v1",
            b"stale",
        ));
        let desired = [&stopped, &divergent, &absent, &stale]
            .into_iter()
            .map(|resource| ResourceRevision {
                resource: resource.clone(),
                revision: desired_revision,
            })
            .collect::<Vec<_>>();
        let current = desired.clone();
        let observations = vec![
            RuntimeResourceObservation {
                resource: absent.clone(),
                state: RuntimeResourceState::Absent,
            },
            RuntimeResourceObservation {
                resource: divergent.clone(),
                state: RuntimeResourceState::Present {
                    revision: desired_revision,
                    health: RuntimeResourceHealth::Divergent,
                },
            },
            RuntimeResourceObservation {
                resource: stale.clone(),
                state: RuntimeResourceState::Present {
                    revision: stale_revision,
                    health: RuntimeResourceHealth::Healthy,
                },
            },
            RuntimeResourceObservation {
                resource: stopped.clone(),
                state: RuntimeResourceState::Present {
                    revision: desired_revision,
                    health: RuntimeResourceHealth::Stopped,
                },
            },
        ];

        let changes = resource_changes(&current, &desired, Some(&observations));
        let kinds = changes
            .into_iter()
            .map(|change| (change.resource, (change.kind, change.current)))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            kinds[&stopped],
            (ResourceChangeKind::ReconcileStopped, Some(desired_revision))
        );
        assert_eq!(
            kinds[&divergent],
            (
                ResourceChangeKind::ReconcileDivergent,
                Some(desired_revision)
            )
        );
        assert_eq!(kinds[&absent], (ResourceChangeKind::Create, None));
        assert_eq!(
            kinds[&stale],
            (ResourceChangeKind::Update, Some(stale_revision))
        );
    }

    #[test]
    fn mismatched_runtime_revision_selects_update_before_health_repair() {
        let provider = instance("provider");
        let stopped = resource(&provider, "stopped-old");
        let divergent = resource(&provider, "divergent-old");
        let desired_revision = RevisionId(Sha256Digest::separated(
            "aos.test.transition-context/v1",
            b"desired",
        ));
        let old_revision = RevisionId(Sha256Digest::separated(
            "aos.test.transition-context/v1",
            b"old",
        ));
        let desired = [&stopped, &divergent]
            .into_iter()
            .map(|resource| ResourceRevision {
                resource: resource.clone(),
                revision: desired_revision,
            })
            .collect::<Vec<_>>();
        let observations = vec![
            RuntimeResourceObservation {
                resource: divergent.clone(),
                state: RuntimeResourceState::Present {
                    revision: old_revision,
                    health: RuntimeResourceHealth::Divergent,
                },
            },
            RuntimeResourceObservation {
                resource: stopped.clone(),
                state: RuntimeResourceState::Present {
                    revision: old_revision,
                    health: RuntimeResourceHealth::Stopped,
                },
            },
        ];

        let changes = resource_changes(&desired, &desired, Some(&observations));

        assert!(changes.iter().all(|change| {
            change.kind == ResourceChangeKind::Update && change.current == Some(old_revision)
        }));
    }

    fn authorized(binding: Binding) -> AuthorizedTransitionBinding {
        AuthorizedTransitionBinding {
            binding,
            authority: TransitionBindingAuthority::Desired,
        }
    }

    fn binding(
        name: &str,
        consumer: &InstanceId,
        provider: &InstanceId,
        caller_grant: AuthorityGrant,
        provider_grant: AuthorityGrant,
    ) -> Binding {
        let digest = Sha256Digest::separated("aos.test.transition-context/v1", name.as_bytes());
        Binding {
            id: BindingId(key(name)),
            request: RequestId {
                consumer: consumer.clone(),
                scope: ScopePath::root(),
                key: key(name),
            },
            interface: InterfaceKey {
                name: InterfaceName::new("aos.test-transition-context")
                    .expect("test interface name must be valid"),
                abi: NonZeroU32::new(1).expect("test ABI must be nonzero"),
                descriptor: digest,
            },
            provider: provider.clone(),
            provider_package: None,
            implementation: ProviderImplementationReference {
                descriptor: digest,
                artifact: ArtifactReference {
                    content: digest,
                    store_path: "/nix/store/00000000000000000000000000000000-transition-context"
                        .to_string(),
                    nar_hash: digest,
                    closure: digest,
                },
                handler: None,
            },
            source: BindingSource::Explicit,
            caller_grant,
            provider_grant,
            guarantees: Vec::new(),
            policy_revision: RevisionId(digest),
            lifetime: ResourceLifetime::Instance,
            mediation_allowed: true,
        }
    }

    fn grant(principal: &InstanceId, resources: &[ResourceId]) -> AuthorityGrant {
        AuthorityGrant {
            principal: principal.clone(),
            methods: Vec::new(),
            contributions: Vec::new(),
            resources: resources
                .iter()
                .cloned()
                .map(|resource| ResourcePermission {
                    resource,
                    access: AccessMode::Read,
                    operations: vec![key("observe")],
                })
                .collect(),
        }
    }

    fn change(resource: ResourceId) -> ResourceChange {
        ResourceChange {
            resource,
            current: None,
            desired: Some(RevisionId(Sha256Digest::separated(
                "aos.test.transition-context/v1",
                b"desired",
            ))),
            kind: ResourceChangeKind::Create,
        }
    }

    fn controller(resource: ResourceId, provider: InstanceId) -> ControllerAssignment {
        ControllerAssignment {
            resource,
            controller: AggregateId {
                provider,
                group: key("controller"),
            },
        }
    }

    fn resource(provider: &InstanceId, name: &str) -> ResourceId {
        ResourceId {
            provider: provider.clone(),
            key: key(name),
        }
    }

    fn instance(name: &str) -> InstanceId {
        InstanceId {
            environment: EnvironmentId {
                authority: key("test"),
                key: key("host"),
                stage: ExecutionStage::Host,
            },
            key: key(name),
        }
    }

    fn key(value: &str) -> LocalKey {
        LocalKey::new(value).expect("test key must be valid")
    }
}
