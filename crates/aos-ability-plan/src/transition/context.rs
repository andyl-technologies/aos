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
    ControllerAssignment, EnvironmentId, InstanceId, ProviderImplementationReference, RequestId,
    ResourceRevision, RevisionId, ScopePath, TeardownProviderAuthorization,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{CompositionOutcome, EvaluationError, VerifiedPlanningSnapshot};

use super::TransitionError;

/// Exact schema discriminator passed to pure transition constructors.
pub const TRANSITION_CONTEXT_SCHEMA: &str = "aos.ability.transition-context/v1";

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
    /// Lists exact current-to-desired resource changes owned by this provider.
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
) -> Vec<ResourceChange> {
    let current: BTreeMap<_, _> = current
        .iter()
        .map(|revision| (revision.resource.clone(), revision.revision))
        .collect();
    let desired: BTreeMap<_, _> = desired
        .iter()
        .map(|revision| (revision.resource.clone(), revision.revision))
        .collect();
    current
        .keys()
        .chain(desired.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|resource| {
            let current = current.get(&resource).copied();
            let desired = desired.get(&resource).copied();
            let kind = match (current, desired) {
                (None, Some(_)) => ResourceChangeKind::Create,
                (Some(_), None) => ResourceChangeKind::Remove,
                (Some(left), Some(right)) if left != right => ResourceChangeKind::Update,
                (Some(_), Some(_)) => ResourceChangeKind::Unchanged,
                (None, None) => return None,
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
