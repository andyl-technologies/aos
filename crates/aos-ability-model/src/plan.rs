//! Binding records, resource authority, and finite effect-plan graphs.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroU64};

use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::identity::{
    AggregateId, IncarnationId, InstanceId, InterfaceKey, LocalKey, RequestId, ResourceId,
    RevisionId, ScopePath, ScopedOperationKey,
};
use crate::interface::{
    GuaranteeKey, OutputDescriptor, ProviderImplementationReference, ValuePhase,
};
use crate::value::{
    OperationResultReference, ResourceLifetime, ResourceReference, ValueExpression,
};

/// Identifies one binding within a canonical binding plan.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BindingId(pub LocalKey);

/// Classifies one provider decision for a required request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingSource {
    /// Comes from an explicit deployment-owned selection.
    Explicit,
    /// Preserves an existing exact provider pin.
    ExistingPin,
    /// Selects the only eligible provider when no preference policy exists.
    SoleEligible,
    /// Comes from an operator-authored ordered candidate policy.
    OperatorPolicy,
}

/// Defines the maximum resource access granted to an invocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessMode {
    /// Permits observation without mutation.
    Read,
    /// Permits a provider-defined shared mutation mode.
    SharedWrite,
    /// Permits exclusive mutation while ownership is held.
    ExclusiveWrite,
}

impl AccessMode {
    /// Reports whether this permission covers `requested` access.
    #[must_use]
    pub fn permits(self, requested: Self) -> bool {
        matches!(
            (self, requested),
            (Self::ExclusiveWrite, _)
                | (Self::SharedWrite, Self::SharedWrite | Self::Read)
                | (Self::Read, Self::Read)
        )
    }

    /// Reports whether the mode may mutate a resource.
    #[must_use]
    pub fn is_write(self) -> bool {
        matches!(self, Self::SharedWrite | Self::ExclusiveWrite)
    }
}

/// Grants bounded operations and access to one exact resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePermission {
    /// Identifies the logical resource covered by the grant.
    pub resource: ResourceId,
    /// Sets the maximum access mode.
    pub access: AccessMode,
    /// Names permitted resource operations in canonical order.
    pub operations: Vec<LocalKey>,
}

/// Defines one side of an authorized provider binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrant {
    /// Identifies the principal receiving this grant.
    pub principal: InstanceId,
    /// Names callable interface methods in canonical order.
    pub methods: Vec<LocalKey>,
    /// Lists exact resource permissions in canonical resource order.
    pub resources: Vec<ResourcePermission>,
}

/// Describes one consumer request before a provider is selected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRequest {
    /// Identifies the consuming instance and local request.
    pub id: RequestId,
    /// Lists exact accepted public descriptors in policy order.
    pub accepted_interfaces: Vec<InterfaceKey>,
    /// Names required methods in canonical order.
    pub methods: Vec<LocalKey>,
    /// Names exact required guarantees in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
    /// Defines the longest resource lifetime the consumer requests.
    pub lifetime: ResourceLifetime,
}

/// Binds one request to an exact provider under separate caller/provider grants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// Names the binding inside the plan.
    pub id: BindingId,
    /// Identifies the request satisfied by this binding.
    pub request: RequestId,
    /// Identifies the exact provider implementation interface.
    pub interface: InterfaceKey,
    /// Identifies the selected provider instance.
    pub provider: InstanceId,
    /// Pins the selected provider implementation and executable artifact.
    pub implementation: ProviderImplementationReference,
    /// Records the deterministic selection source.
    pub source: BindingSource,
    /// Defines authority retained by the caller.
    pub caller_grant: AuthorityGrant,
    /// Defines separate implementation authority used by the provider.
    pub provider_grant: AuthorityGrant,
    /// Names guarantees actually supplied in canonical order.
    pub guarantees: Vec<GuaranteeKey>,
    /// Identifies the policy revision that authorized both grants.
    pub policy_revision: RevisionId,
    /// Bounds the binding's resource lifetime.
    pub lifetime: ResourceLifetime,
    /// States whether the provider may mediate using its implementation grant.
    pub mediation_allowed: bool,
}

/// Classifies an external input that prevents runtime admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObligationKind {
    /// Requires an environment facility that is not yet supplied.
    EnvironmentFacility,
    /// Requires an operator policy grant.
    Authorization,
    /// Requires a provider selected outside the current deployment.
    ExternalProvider,
    /// Requires an exact artifact not currently available.
    Artifact,
}

/// Records one unresolved deployment input without treating it as success.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentObligation {
    /// Gives the obligation a stable local identity.
    pub key: LocalKey,
    /// Classifies the missing input.
    pub kind: ObligationKind,
    /// Identifies the request that introduced the obligation.
    pub request: RequestId,
    /// Identifies a related resource, when one is already known.
    pub resource: Option<ResourceId>,
    /// Supplies a bounded human-facing explanation.
    pub description: String,
}

/// Records the current or desired revision of one logical resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRevision {
    /// Identifies the logical provider-owned resource.
    pub resource: ResourceId,
    /// Identifies its semantic desired or observed content.
    pub revision: RevisionId,
}

/// Selects whether an operation uses caller or provider implementation authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityRole {
    /// Executes only with authority granted directly to the caller.
    Caller,
    /// Executes as provider mediation under the separate implementation grant.
    Provider,
}

/// Records one exact resource access performed by an operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAccess {
    /// Identifies the accessed resource.
    pub resource: ResourceId,
    /// Selects read or mutation semantics.
    pub mode: AccessMode,
}

/// Selects a service lifecycle operation without collapsing their semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceAction {
    /// Starts an absent service instance.
    Start,
    /// Reloads a provider-declared compatible configuration change.
    Reload,
    /// Restarts an instance when reload is insufficient.
    Restart,
    /// Stops an instance before resource release.
    Stop,
}

/// Selects credential acquisition or delivery while keeping both typed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAction {
    /// Acquires an opaque credential version from its source provider.
    Acquire,
    /// Delivers an acquired credential into an authorized workload view.
    Deliver,
}

/// Identifies the initial semantic operation families.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OperationFamily {
    /// Verifies an exact artifact and its required provenance.
    VerifyArtifact,
    /// Prepares a managed configuration candidate without publishing it.
    PrepareManagedConfiguration,
    /// Acquires or delivers a credential without exposing secret bytes.
    Credential {
        /// Selects acquisition or workload delivery.
        action: CredentialAction,
    },
    /// Validates a candidate in its intended identity and resource views.
    ValidateCandidate,
    /// Publishes a validated configuration under an expected revision.
    PublishConfiguration,
    /// Prepares exact unit definitions in a selected manager scope.
    PrepareManagerConfiguration,
    /// Performs one explicit service lifecycle operation.
    ServiceLifecycle {
        /// Selects start, reload, restart, or stop.
        action: ServiceAction,
    },
    /// Establishes declared readiness for an expected revision.
    ObserveReadiness,
    /// Releases or fences an exact resource after required users detach.
    ReleaseResource,
    /// Records exact generation and observed-consumer associations.
    RecordGenerationAssociation,
}

/// Selects the durable transaction phase containing an operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationPhase {
    /// Performs non-live candidate and resource preparation.
    Preparing,
    /// Crosses a declared live visibility boundary.
    Publishing,
    /// Applies lifecycle effects and observes the selected target.
    Converging,
    /// Reconciles or compensates an interrupted operation.
    Recovering,
}

/// Defines a finite operation and total recovery deadline.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlinePolicy {
    /// Bounds one live attempt.
    pub attempt_timeout_millis: NonZeroU64,
    /// Bounds all retries and recovery across restarts.
    pub total_recovery_millis: NonZeroU64,
}

/// Defines bounded automatic retry semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RetryPolicy {
    /// Performs no automatic retry.
    Disabled,
    /// Permits a finite number of attempts under provider reconciliation.
    Bounded {
        /// Bounds the total attempt count, including the first attempt.
        max_attempts: NonZeroU32,
        /// Defines the finite delay between attempts.
        backoff_millis: u64,
    },
}

/// References one exact interface method used for recovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MethodReference {
    /// Identifies the exact public interface contract.
    pub interface: InterfaceKey,
    /// Names the declared method.
    pub method: LocalKey,
}

/// Defines reconciliation, retry, cancellation, and compensation behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContract {
    /// Defines bounded automatic retry.
    pub retry: RetryPolicy,
    /// Names the observation/reconciliation method for indeterminate effects.
    pub reconcile: Option<MethodReference>,
    /// Names an explicit cancellation method, when supported.
    pub cancel: Option<MethodReference>,
    /// Names an explicit compensation method, when supported.
    pub compensate: Option<MethodReference>,
}

/// Defines expected resource state checked immediately before an effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPrecondition {
    /// Identifies the resource whose state is constrained.
    pub resource: ResourceId,
    /// Requires an exact current content revision, when known.
    pub expected_revision: Option<RevisionId>,
    /// Requires an exact provider assignment incarnation, when known.
    pub expected_incarnation: Option<IncarnationId>,
}

/// Names any schedulable node in an effect plan.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PlanNodeKey {
    /// Names an invoked provider operation.
    Operation {
        /// Carries the operation's scoped key.
        key: ScopedOperationKey,
    },
    /// Names a selector decision that durably chooses one alternative.
    Decision {
        /// Carries the decision node's scoped key.
        key: ScopedOperationKey,
    },
    /// Names a merge that exposes the selected alternative's typed outputs.
    Merge {
        /// Carries the merge node's scoped key.
        key: ScopedOperationKey,
    },
}

impl PlanNodeKey {
    /// Returns the underlying scoped node key.
    #[must_use]
    pub const fn key(&self) -> &ScopedOperationKey {
        match self {
            Self::Operation { key } | Self::Decision { key } | Self::Merge { key } => key,
        }
    }

    /// Returns the stable version-1 node-kind ordering rank.
    #[must_use]
    pub const fn canonical_rank(&self) -> u8 {
        match self {
            Self::Operation { .. } => 0,
            Self::Decision { .. } => 1,
            Self::Merge { .. } => 2,
        }
    }
}

/// Records one enclosing conditional alternative for a plan node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BranchMembership {
    /// Names the enclosing selector decision.
    pub decision: ScopedOperationKey,
    /// Names the alternative containing the node.
    pub alternative: LocalKey,
}

/// Selects the typed result inspected by a decision node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionSelector {
    /// Names the result whose value determines the selected alternative.
    pub result: OperationResultReference,
    /// Names a tagged-union discriminator, or is absent for a Boolean result.
    pub tag_field: Option<LocalKey>,
}

/// Defines one exact alternative predicate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DecisionPredicate {
    /// Matches one of the two Boolean selector values.
    Boolean {
        /// Gives the exact Boolean value selected by this alternative.
        value: bool,
    },
    /// Matches one tagged-union variant.
    Tag {
        /// Gives the exact variant tag selected by this alternative.
        value: LocalKey,
    },
}

/// Associates an alternative name with its exact selector predicate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionAlternative {
    /// Names the alternative within its decision.
    pub key: LocalKey,
    /// Defines the selector value that activates it.
    pub predicate: DecisionPredicate,
}

/// Durably selects exactly one exhaustive conditional alternative.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionNode {
    /// Names the decision within the plan's recursive scope.
    pub key: ScopedOperationKey,
    /// Lists enclosing alternatives from outermost to innermost.
    pub branch_context: Vec<BranchMembership>,
    /// Identifies the typed result used for selection.
    pub selector: DecisionSelector,
    /// Lists exhaustive alternatives in canonical key order.
    pub alternatives: Vec<DecisionAlternative>,
}

/// Defines one typed output selected from all conditional alternatives.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergedOutput {
    /// Defines the common schema, phase, visibility, and lifetime.
    pub descriptor: OutputDescriptor,
    /// Maps every alternative to its producing result in canonical key order.
    pub alternatives: BTreeMap<LocalKey, OperationResultReference>,
}

/// Joins selected branch results without executing an effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergeNode {
    /// Names the merge within the plan's recursive scope.
    pub key: ScopedOperationKey,
    /// Names the decision whose alternatives this node joins.
    pub decision: ScopedOperationKey,
    /// Lists enclosing alternatives from outermost to innermost.
    pub branch_context: Vec<BranchMembership>,
    /// Maps output ports to all-branch typed producers.
    pub outputs: BTreeMap<LocalKey, MergedOutput>,
}

/// Describes one invocation in a finite effect graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    /// Names the operation within the plan's recursive scope.
    pub key: ScopedOperationKey,
    /// Lists enclosing alternatives from outermost to innermost.
    pub branch_context: Vec<BranchMembership>,
    /// Identifies the binding authorizing this invocation.
    pub binding: BindingId,
    /// Selects caller or provider implementation authority.
    pub authority: AuthorityRole,
    /// Identifies the exact called interface descriptor.
    pub interface: InterfaceKey,
    /// Names the called method.
    pub method: LocalKey,
    /// Retains the operation's high-level semantic family.
    pub family: OperationFamily,
    /// Places the operation in the durable transition state machine.
    pub phase: OperationPhase,
    /// States the latest value phase this invocation can consume.
    pub input_phase: ValuePhase,
    /// Identifies the primary resource reference targeted by the invocation.
    pub target: ResourceReference,
    /// Supplies closed literal and symbolic method parameters.
    pub inputs: ValueExpression,
    /// Lists required fresh precondition checks in canonical resource order.
    pub preconditions: Vec<OperationPrecondition>,
    /// Lists all declared resource accesses in canonical resource order.
    pub accesses: Vec<ResourceAccess>,
    /// Names the lifecycle controller for mutating accesses.
    pub controller: Option<AggregateId>,
    /// Defines finite attempt and recovery time bounds.
    pub deadline: DeadlinePolicy,
    /// Defines retry, reconciliation, cancellation, and compensation behavior.
    pub recovery: RecoveryContract,
}

/// Distinguishes graph relationships with different scheduling semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyKind {
    /// Requires successful production of a typed result.
    Data,
    /// Requires predecessor success before the consumer starts.
    RequiredSuccess,
    /// Waits for any settled predecessor outcome.
    OrderingOnly,
    /// Requires declared readiness evidence for the expected condition.
    Readiness,
    /// Makes a branch node eligible only after its decision selects that branch.
    BranchGuard,
    /// Makes a merge wait for the selected alternative's producer.
    BranchMerge,
    /// Retains an artifact or resource without adding startup order.
    Retention,
    /// Records permitted runtime communication without adding startup order.
    Communication,
}

impl DependencyKind {
    /// Returns the stable version-1 canonical sort rank.
    #[must_use]
    pub const fn canonical_rank(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::RequiredSuccess => 1,
            Self::OrderingOnly => 2,
            Self::Readiness => 3,
            Self::BranchGuard => 4,
            Self::BranchMerge => 5,
            Self::Retention => 6,
            Self::Communication => 7,
        }
    }

    /// Reports whether this edge participates in execution-cycle checks.
    #[must_use]
    pub fn is_scheduling(self) -> bool {
        matches!(
            self,
            Self::Data
                | Self::RequiredSuccess
                | Self::OrderingOnly
                | Self::Readiness
                | Self::BranchGuard
                | Self::BranchMerge
        )
    }
}

/// Connects two exact operations under one typed graph relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyEdge {
    /// Names the predecessor or producer.
    pub from: PlanNodeKey,
    /// Names the dependent or consumer.
    pub to: PlanNodeKey,
    /// Defines scheduling, retention, or communication semantics.
    pub kind: DependencyKind,
}

/// Assigns exactly one lifecycle controller to a mutable resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerAssignment {
    /// Identifies the controlled logical resource.
    pub resource: ResourceId,
    /// Identifies the owning provider aggregate.
    pub controller: AggregateId,
}

/// Returns the explicit canonical ordering for operation keys.
#[must_use]
pub fn compare_operation_keys(left: &ScopedOperationKey, right: &ScopedOperationKey) -> Ordering {
    left.scope
        .as_slice()
        .cmp(right.scope.as_slice())
        .then_with(|| left.key.cmp(&right.key))
}

/// Returns the explicit canonical ordering for all plan node identities.
#[must_use]
pub fn compare_plan_node_keys(left: &PlanNodeKey, right: &PlanNodeKey) -> Ordering {
    compare_operation_keys(left.key(), right.key())
        .then_with(|| left.canonical_rank().cmp(&right.canonical_rank()))
}

/// Returns the explicit canonical ordering for dependency edges.
#[must_use]
pub fn compare_edges(left: &DependencyEdge, right: &DependencyEdge) -> Ordering {
    compare_plan_node_keys(&left.from, &right.from)
        .then_with(|| compare_plan_node_keys(&left.to, &right.to))
        .then_with(|| left.kind.canonical_rank().cmp(&right.kind.canonical_rank()))
}

/// Returns the explicit canonical ordering for logical resources.
#[must_use]
pub fn compare_resource_ids(left: &ResourceId, right: &ResourceId) -> Ordering {
    compare_instances(&left.provider, &right.provider).then_with(|| left.key.cmp(&right.key))
}

fn compare_instances(left: &InstanceId, right: &InstanceId) -> Ordering {
    left.environment
        .authority
        .cmp(&right.environment.authority)
        .then_with(|| left.environment.key.cmp(&right.environment.key))
        .then_with(|| {
            left.environment
                .stage
                .canonical_rank()
                .cmp(&right.environment.stage.canonical_rank())
        })
        .then_with(|| left.key.cmp(&right.key))
}

/// Returns the content digest domain for a terminal handler result.
#[must_use]
pub fn handler_result_domain(interface: &InterfaceKey, method: &LocalKey) -> String {
    format!(
        "aos.ability.handler-result/v1\0{}\0{}\0{}\0{}",
        interface.name, interface.abi, interface.descriptor, method
    )
}

/// Identifies one exact handler implementation version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct HandlerId(pub Sha256Digest);

/// Retains an explicitly bounded composition scope for graph diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionFrame {
    /// Identifies the nested provider scope.
    pub scope: ScopePath,
    /// Identifies the request expanded in this frame.
    pub request: RequestId,
}
