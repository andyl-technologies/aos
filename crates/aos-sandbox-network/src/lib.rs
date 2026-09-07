//! Root network-broker preparation and recovery foundation.
//!
//! [`policy`] closes node-local endpoint policy into bounded typed packet flows.
//! [`catalog`] models protected preparation-profile, endpoint-policy, and
//! reserved-handle allocation. [`preparation_catalog`] binds those inputs to an
//! exact portable assignment, mints the opaque handle, and retains reservations
//! in a protected append-only catalog. [`authorization`] adapts the shared
//! signed authority verifier. [`state`] atomically journals authenticated
//! authorization links, a durable pre-effect crash boundary, and typed
//! committed namespace observations. [`namespace_catalog`] retains verified
//! namespace identity and lease lifecycle, then emits authoritative current-boot
//! inventory. [`service`] exposes that catalog through an authenticated Network
//! 1.2 one-shot session, while [`activation`] validates its systemd
//! record-subject listener. [`broker`] composes effect state without exposing
//! Apply or performing netlink, nftables, or BPF work. The privileged kernel
//! helper, postcondition observer, and authenticated mutation dispatch remain
//! explicit Apply-readiness prerequisites.

pub mod activation;
pub mod authorization;
pub mod broker;
pub mod catalog;
pub mod namespace_catalog;
pub mod policy;
pub mod preparation_catalog;
pub mod service;
pub mod state;

pub use authorization::{NetworkAdmissionError, NetworkAuthorityV1};
pub use broker::{
    NetworkAdmissionCoordinator, NetworkAdmissionOutcome, NetworkBrokerError,
    advertised_network_methods,
};
pub use catalog::{
    AuthenticatedNetworkPreparationV1, NetworkCatalogBindingV1, ResolvedEndpointV1,
    ResolvedNetworkPreparationV1,
};
pub use namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceCatalogOutcomeV1, NetworkNamespaceCatalogV1,
    NetworkNamespaceIdentityV1, NetworkNamespaceLifecycleActionV1,
    NetworkNamespaceLifecycleObservationV1, NetworkNamespaceLifecycleOutcomeV1,
    NetworkNamespaceLifecycleTransitionV1, NetworkNamespaceObservedStateKindV1,
    NetworkNamespaceObservedStateV1, NetworkNamespacePublicationV1,
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
