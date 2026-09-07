//! Non-executing root network-broker admission and recovery foundation.
//!
//! [`catalog`] models protected preparation-profile, endpoint-policy, and
//! reserved-handle allocation. [`preparation_catalog`] binds those inputs to an
//! exact portable assignment, mints the opaque handle, and retains reservations
//! in a protected append-only catalog. [`authorization`] adapts the shared
//! signed authority verifier. [`state`] atomically journals authenticated
//! authorization links and network-specific phases. [`broker`] composes those
//! pieces without exposing Apply or performing netlink, nftables, or BPF work.
//! The current-resource lifecycle index and kernel helper remain explicit
//! readiness prerequisites, so no network method is advertised.

pub mod authorization;
pub mod broker;
pub mod catalog;
pub mod preparation_catalog;
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
pub use preparation_catalog::{
    NetworkPolicyCatalogV1, NetworkPolicyProfileV1, NetworkPreparationCatalogError,
    NetworkPreparationCatalogOutcomeV1, NetworkPreparationCatalogV1,
    NetworkPreparationReservationV1,
};
pub use state::{
    DurableNetworkPhase, NetworkRecoveryEntry, NetworkRecoverySnapshotV1, NetworkStateError,
    NetworkStateStore,
};
