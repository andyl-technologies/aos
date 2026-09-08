//! Root network-broker preparation and recovery foundation.
//!
//! [`policy`] closes node-local endpoint policy into bounded typed packet flows,
//! while [`allocation`] resolves durable address, route, link, and generation
//! plans.
//! [`catalog`] models protected preparation-profile, endpoint-policy, and
//! reserved-handle allocation. [`preparation_catalog`] binds those inputs to an
//! exact portable assignment, mints the opaque handle, and retains reservations
//! in a protected append-only catalog. [`kernel_plan`] compiles one exact
//! assignment, namespace allocation, and packet policy into a canonical
//! architecture-neutral pre-effect artifact. [`namespace_store`] validates
//! restart-retained namespace descriptors and admits systemd FD-store mutations
//! only after complete manager readback. [`authorization`] adapts the shared
//! signed authority verifier. [`state`] atomically journals
//! authenticated authorization links, a durable pre-effect crash boundary, and
//! typed committed namespace observations. [`namespace_catalog`] retains
//! verified namespace identity and lease lifecycle, then emits authoritative
//! current-boot inventory. [`service`] exposes that catalog through an
//! authenticated Network 1.2 one-shot session, while [`activation`] validates
//! its systemd record-subject listener. [`broker`] composes effect state without
//! exposing Apply or performing netlink, nftables, or BPF work. The privileged
//! kernel helper, postcondition observer, and authenticated mutation dispatch
//! remain explicit Apply-readiness prerequisites.

pub mod activation;
pub mod allocation;
pub mod authorization;
pub mod broker;
pub mod catalog;
pub mod kernel_observation;
pub mod kernel_plan;
pub mod kernel_reader;
pub mod namespace_catalog;
pub mod namespace_store;
pub mod policy;
pub mod preparation_catalog;
pub mod service;
pub mod state;

pub use allocation::{
    NetworkAddressPairV1, NetworkAddressPoolV1, NetworkAllocationError, NetworkAllocationPolicyV1,
    NetworkInterfaceNameV1, NetworkIpAddressV1, NetworkMacAddressV1, NetworkNamespacePlanV1,
    NetworkRouteV1,
};
pub use authorization::{NetworkAdmissionError, NetworkAuthorityV1};
pub use broker::{
    NetworkAdmissionCoordinator, NetworkAdmissionOutcome, NetworkBrokerError,
    advertised_network_methods,
};
pub use catalog::{
    AuthenticatedNetworkPreparationV1, NetworkCatalogBindingV1, ResolvedEndpointV1,
    ResolvedNetworkPreparationV1,
};
pub use kernel_observation::{
    ExpectedAddressPairV1, ExpectedRouteV1, ExpectedVethV1, NetworkKernelExpectationV1,
    NetworkKernelObservationError, NetworkKernelObservationV1, ObservedAddressV1,
    ObservedBpfArtifactV1, ObservedBpfAttachmentV1, ObservedBpfBindingV1, ObservedBpfMapV1,
    ObservedFlowV1, ObservedInterfaceV1, ObservedIpAddressV1, ObservedIpPrefixV1,
    ObservedLeaseDirectionV1, ObservedLeaseGateV1, ObservedLeaseStateV1, ObservedLinkV1,
    ObservedNetworkNamespaceV1, ObservedNftAntiSpoofRuleV1, ObservedNftBaseChainV1,
    ObservedNftVerdictV1, ObservedNftablesPolicyV1, ObservedRouteProtocolV1, ObservedRouteScopeV1,
    ObservedRouteTypeV1, ObservedRouteV1,
};
pub use kernel_plan::{
    NetworkKernelActionV1, NetworkKernelPlanError, NetworkKernelPlanV1,
    NetworkNamespacePublicationRequirementV1,
};
pub use kernel_reader::{
    FixedBpfObservationReader, NetworkKernelReaderError, decode_bpf_observation,
};
pub use namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceCatalogOutcomeV1, NetworkNamespaceCatalogV1,
    NetworkNamespaceIdentityV1, NetworkNamespaceLifecycleActionV1,
    NetworkNamespaceLifecycleObservationV1, NetworkNamespaceLifecycleOutcomeV1,
    NetworkNamespaceLifecycleTransitionV1, NetworkNamespaceObservedStateKindV1,
    NetworkNamespaceObservedStateV1, NetworkNamespacePublicationV1,
};
pub use namespace_store::{
    ActivatedNetworkDescriptors, MAXIMUM_RETAINED_NETWORK_NAMESPACES,
    NetworkNamespaceCustodyRequirementV1, NetworkNamespaceStoreError, NetworkNamespaceStoreName,
    NetworkNamespaceStoreOutcome, RetainedNetworkNamespace, SystemdNetworkNamespaceStore,
    adopt_systemd_activation, validate_activation_replay,
};
pub use policy::{
    NetworkEndpointPolicyV1, NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1,
    NetworkPolicyProgramError, NetworkPolicyProgramV1, NetworkPortRangeV1,
    NetworkTransportProtocolV1,
};
pub use preparation_catalog::{
    NetworkPolicyCatalogV1, NetworkPolicyProfileV1, NetworkPreparationCatalogError,
    NetworkPreparationCatalogOutcomeV1, NetworkPreparationCatalogV1,
    NetworkPreparationReservationV1,
};
pub use service::{NetworkConnectionOutcome, NetworkInventoryService, NetworkServiceError};
pub use state::{
    CommittedNetworkResultV1, DurableNetworkPhase, NetworkRecoveryEntry, NetworkRecoverySnapshotV1,
    NetworkStateError, NetworkStateStore, VerifiedNetworkResultV1,
};
