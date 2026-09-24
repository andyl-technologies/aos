//! Inert advanced Network policy and atomic-replacement model.
//!
//! These modules describe assignment-bound identity, immutable project service
//! discovery, mediated egress, explicitly allocated ingress, checked quotas,
//! deterministic lowering, a pure replacement reducer, and a dormant canonical
//! worker handoff. They deliberately expose no socket, live worker, kernel, or
//! service integration. A protected owner must persist each accepted reducer
//! transition atomically and revalidate currentness before releasing an effect.

pub mod compiler;
pub mod egress;
pub mod handoff;
pub mod identity;
pub mod ingress;
mod protected_owner;
pub mod quota;
mod recovery_reader;
pub mod replacement;
pub mod service_discovery;
mod source_authority;

pub use compiler::{
    AdvancedNetworkPolicyV1, CompiledAdvancedNetworkPolicyV1, NetworkEnforcementArtifactsV1,
    compile_advanced_network_policy_v1,
};
pub use egress::{MediatedEgressDestinationV1, MediatedEgressPolicyV1};
pub use handoff::{
    AdvancedNetworkKernelEffectHandoffV1, AdvancedNetworkPolicyWorkerHandoffV1,
    AdvancedNetworkPolicyWorkerOperationV1,
};
pub use identity::{
    AdvancedNetworkIdentityV1, NetworkAllocationIdentityV1, NetworkPolicyRevisionV1,
    ProtectedCurrentnessWitnessV1, ProtectedRecoveryAuthoritiesV1,
};
pub use ingress::{
    ExternalIngressKeyV1, ExternalIngressRegistryV1, IngressAllocationSetV1,
    IngressPoolAuthorityV1, IngressPoolPortRangeV1, IngressRegistryCasV1,
    IngressRegistryRowStateV1, IngressRegistryRowV1, IngressTranslationPlanV1,
    IngressTranslationV1, PublishedIngressAllocationV1,
};
pub use protected_owner::{
    AdvancedNetworkPolicyOwnerCommitV1, AdvancedNetworkPolicyOwnerSnapshotV1,
    AdvancedNetworkPolicyProtectedAuthoritiesV1, AdvancedNetworkPolicyProtectedOwnerV1,
    AdvancedNetworkPolicyProtectedSourceOwnerV1, ProtectedAssignmentSourceInputV1,
    ProtectedCapabilitiesSourceInputV1, ProtectedCombinedNetworkOutcomeV1,
    ProtectedCombinedNetworkSourceInputV1, ProtectedCombinedNetworkStateV1,
    ProtectedDiscoverySourceInputV1, ProtectedIngressPoolSourceInputV1,
    ProtectedIngressRegistrySnapshotV1,
};
pub use quota::{
    AdvancedNetworkQuotaV1, NetworkPolicyUsageV1, NetworkQuotaAccountV1, ProjectNetworkUsageV1,
    ProtectedNetworkQuotaV1, ProtectedNetworkTransactionV1,
};
pub use replacement::{
    AdvancedNetworkRecoveryCompanionsV1, AdvancedNetworkRecoveryRecordV1, AmbiguousStateV1,
    NetworkPolicyReplacementEventV1, NetworkPolicyReplacementPhaseV1,
    NetworkPolicyReplacementStateV1, NetworkReplacementObservationV1, ObservedNetworkPolicyV1,
    ProtectedNetworkObservationInputV1, ReplacementCapabilitiesV1, ReservedStateV1, StableStateV1,
    TerminalStateV1, reduce_network_policy_replacement_v1,
};
pub use service_discovery::{
    DiscoveredProjectServiceV1, ProjectServiceAddressV1, ProjectServiceDiscoverySnapshotV1,
    ServiceDiscoveryExpectationV1, ServicePublicationAuthorityV1,
};
pub use source_authority::{
    AdvancedNetworkPolicyAuthorityCompositionV1, AdvancedNetworkPolicyUpstreamAuthorityOwnerV1,
    BrokerAssignmentLeaseProofV1, DiscoveryPublisherProofV1, IngressPoolAuthorityProofV1,
    KernelCapabilityProbeProofV1, QuotaAuthorityProofV1,
};

/// Maximum number of logical endpoints in one advanced policy.
pub const MAXIMUM_ADVANCED_NETWORK_ENDPOINTS: usize = 256;

/// Maximum number of packet flows lowered under one logical endpoint.
pub const MAXIMUM_ADVANCED_NETWORK_FLOWS_PER_ENDPOINT: usize = 64;

/// Maximum number of packet flows in one complete advanced policy.
pub const MAXIMUM_ADVANCED_NETWORK_FLOWS: usize =
    MAXIMUM_ADVANCED_NETWORK_ENDPOINTS * MAXIMUM_ADVANCED_NETWORK_FLOWS_PER_ENDPOINT;

/// Reports invalid, stale, conflicting, or unrepresentable advanced policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdvancedNetworkPolicyError {
    /// A required identity, generation, or digest is the zero sentinel.
    #[error("advanced Network policy contains an unspecified identity")]
    Unspecified,
    /// A bounded set is empty when required, oversized, duplicated, or unordered.
    #[error("advanced Network policy collection is not canonical")]
    NonCanonical,
    /// Project service discovery does not match the immutable expected snapshot.
    #[error("advanced Network policy service-discovery snapshot is stale")]
    StaleServiceDiscovery,
    /// An external ingress key, allocation identity, or compare-and-swap conflicts.
    #[error("advanced Network policy ingress allocation conflicts")]
    IngressConflict,
    /// Checked accounting overflowed or exceeded an explicit quota.
    #[error("advanced Network policy exceeds its explicit quota")]
    QuotaExceeded,
    /// A hard feature required by a candidate is unavailable.
    #[error("advanced Network policy requires an unsupported hard feature")]
    UnsupportedHardFeature,
    /// A policy cannot be represented by the existing closed packet-program profile.
    #[error("advanced Network policy cannot be lowered to the packet program")]
    Unrepresentable,
    /// A replacement event is stale or illegal for the current reducer phase.
    #[error("advanced Network policy replacement transition is invalid")]
    InvalidTransition,
    /// A protected currentness witness no longer matches its owner record.
    #[error("advanced Network policy authority is stale")]
    StaleAuthority,
    /// A project service was not disclosed to the consuming sibling sandbox.
    #[error("advanced Network service disclosure is denied")]
    DisclosureDenied,
    /// The node-global external ingress pool has no admissible listener.
    #[error("advanced Network ingress pool is exhausted")]
    PoolExhausted,
    /// Typed physical or policy observation evidence is incomplete or mixed.
    #[error("advanced Network replacement observation is invalid")]
    InvalidObservation,
    /// Immutable physical namespace identity or artifact commitments disagree.
    #[error("advanced Network physical namespace identity does not match")]
    PhysicalIdentityMismatch,
    /// Fixed protected journal replay, mutation, or exact readback failed.
    #[error("advanced Network policy protected storage is unavailable or ambiguous")]
    ProtectedStorage,
    /// A durable append may have completed and must be resolved by cold replay.
    #[error("advanced Network policy protected commit outcome is indeterminate")]
    CommitIndeterminate,
}

pub(crate) fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

pub(crate) fn nonzero_digest(digest: aos_sandbox_core::ObjectDigest) -> bool {
    digest.as_bytes() != &[0; 32]
}
