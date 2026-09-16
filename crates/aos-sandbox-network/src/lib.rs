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
//! authenticated Network 1.0 one-shot session, while [`activation`] validates
//! its systemd record-subject listener. [`broker`] composes effect state without
//! exposing Apply or directly performing netlink, nftables, or BPF work.
//! [`worker_runtime`] and [`kernel_mutator`] provide the fixed one-shot
//! preparation effect path; [`namespace_observer`] and [`preparation_runtime`]
//! provide observation, durable commit, and publication. [`advanced_policy`]
//! adds source-only compilation, replacement recovery, and a durable worker
//! handoff without activating a worker. Public Apply remains unadvertised
//! pending production service/controller composition, protected retention
//! authorization, effect activation, and P0-06/MAC/VM qualification. The
//! dormant fixed owner can now release move-only Arm, Renew, Disarm, and
//! Destroy effect handoffs after exact protected checkpoint readback.

pub mod activation;
#[allow(
    dead_code,
    reason = "advanced policy remains a dormant source-only integration seam"
)]
pub mod advanced_policy;
pub mod allocation;
pub mod authorization;
pub mod broker;
pub mod catalog;
mod dormant_broker_session;
pub mod kernel_mutator;
pub mod kernel_observation;
pub mod kernel_plan;
pub mod kernel_reader;
pub mod lifecycle_state;
mod lifecycle_worker_process;
pub mod lifecycle_worker_protocol;
pub mod lifecycle_worker_runtime;
pub mod namespace_catalog;
#[allow(
    dead_code,
    reason = "broker-side namespace-inspector completion remains staged before Apply integration"
)]
mod namespace_inspector;
pub use namespace_inspector::{
    NamespaceInspectorProductionError, run_inherited_network_namespace_inspector,
};
#[cfg(any(feature = "kernel-tests", feature = "protected-store-fixture"))]
#[doc(hidden)]
pub use namespace_inspector::{
    PROTECTED_STORE_EXT4_CASES, run_namespace_inspector_protected_store_ext4_fixture,
};
pub mod namespace_observer;
pub mod namespace_store;
pub mod nftables_reader;
pub mod policy;
pub mod preparation_catalog;
pub mod preparation_runtime;
mod protected_policy;
pub mod rtnetlink_reader;
pub mod service;
mod session_runtime;
pub mod state;
mod systemd_socket_instance;
#[allow(
    dead_code,
    reason = "private wire helpers support the fixed one-shot worker runtime"
)]
mod worker_process;
pub mod worker_protocol;
pub mod worker_replay;
pub mod worker_runtime;

pub use allocation::{
    NetworkAddressPairV1, NetworkAddressPoolV1, NetworkAllocationError, NetworkAllocationPolicyV1,
    NetworkInterfaceNameV1, NetworkIpAddressV1, NetworkMacAddressV1, NetworkNamespacePlanV1,
    NetworkRouteV1,
};
pub use authorization::NetworkAuthorityConfigError;
pub use authorization::{NetworkAdmissionError, NetworkAuthorityV1};
pub use broker::{
    NetworkAdmissionOutcome, NetworkBrokerError, NetworkLifecycleAdmissionCoordinator,
    NetworkLifecycleAdmissionOutcome, NetworkLifecycleEffectDispatchPermitV1,
    NetworkPrepareExecutionOutcomeV1, advertised_network_methods,
};
pub use catalog::{
    AuthenticatedNetworkPreparationV1, NetworkCatalogBindingV1, ResolvedEndpointV1,
    ResolvedNetworkPreparationV1,
};
pub use dormant_broker_session::{
    DormantNetworkBrokerAdmissionV1, DormantNetworkBrokerCallErrorV1,
    DormantNetworkBrokerCallsiteV1, DormantNetworkBrokerCompositionV1,
    DormantNetworkBrokerObservationV1, DormantResolvedNetworkBrokerCompositionV1,
};
pub use kernel_observation::{
    ExpectedAddressPairV1, ExpectedRouteV1, ExpectedVethV1, NetworkKernelExpectationV1,
    NetworkKernelObservationError, NetworkKernelObservationV1, ObservedAddressV1,
    ObservedBpfArtifactV1, ObservedBpfAttachmentV1, ObservedBpfBindingV1, ObservedBpfMapV1,
    ObservedFlowV1, ObservedInterfaceV1, ObservedIpAddressV1, ObservedIpFamilyV1,
    ObservedIpPrefixV1, ObservedIpv6AddressGenerationV1, ObservedIpv6NeighborV1,
    ObservedLeaseDirectionV1, ObservedLeaseGateV1, ObservedLeaseStateV1, ObservedLinkV1,
    ObservedNetworkNamespaceV1, ObservedNftAntiSpoofRuleV1, ObservedNftBaseChainV1,
    ObservedNftVerdictV1, ObservedNftablesPolicyV1, ObservedPolicyRuleV1, ObservedRouteProtocolV1,
    ObservedRouteScopeV1, ObservedRouteTypeV1, ObservedRouteV1,
};
pub use kernel_plan::{
    NetworkKernelActionV1, NetworkKernelPlanError, NetworkKernelPlanV1,
    NetworkNamespacePublicationRequirementV1,
};
pub use kernel_reader::{
    FixedBpfObservationReader, NetworkKernelReaderError, decode_bpf_observation,
};
pub use lifecycle_state::{
    CommittedNetworkLifecycleResultV1, DurableNetworkLifecyclePhase,
    NetworkLifecycleRecoveryEntryV1, NetworkLifecycleStateError, NetworkLifecycleStateStore,
};
pub use lifecycle_worker_protocol::{
    AuthenticatedNetworkLifecycleWorkerDispatchV1, DormantNetworkLifecycleEffectHandoffV1,
    DormantNetworkLifecycleEffectStepV1, DormantNetworkLifecycleOwnerErrorV1,
    DormantNetworkLifecycleProtectedCommitV1, DormantNetworkLifecycleProtectedOwnerV1,
    MAXIMUM_NETWORK_LIFECYCLE_WORKER_REQUEST_BYTES, NetworkLifecycleAuthorizedStepV1,
    NetworkLifecycleDescriptorRoleV1, NetworkLifecycleExecutionAuthorizationV1,
    NetworkLifecycleExecutionStepV1, NetworkLifecycleWorkerDispatchV1,
    NetworkLifecycleWorkerRoleV1,
};
pub use lifecycle_worker_runtime::{
    AdmittedNetworkLifecycleWorkerV1, NetworkLifecycleWorkerRuntimeError,
    SystemdNetworkLifecycleAdmissionExecutor, run_inherited_network_lifecycle_admission_worker,
};
pub use namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceCatalogOutcomeV1, NetworkNamespaceCatalogV1,
    NetworkNamespaceIdentityV1, NetworkNamespaceLifecycleActionV1,
    NetworkNamespaceLifecycleObservationV1, NetworkNamespaceLifecycleOutcomeV1,
    NetworkNamespaceLifecycleTransitionV1, NetworkNamespaceObservedStateKindV1,
    NetworkNamespaceObservedStateV1, NetworkNamespacePublicationV1,
};
pub use namespace_observer::{
    NetworkKernelObservationReaders, NetworkNamespaceObserverError, NetworkNamespacePeerProofV1,
    RtnetlinkIsolatedNamespaceInventoryV1, RtnetlinkNamespacePairInventoryV1,
    StableNetworkKernelObservationV1, StableRtnetlinkNamespaceInventoryV1,
    observe_stable_network_kernel, observe_stable_prepared_network_kernel,
    observe_stable_recovered_network_kernel, observe_stable_rtnetlink_namespace,
    observe_stable_rtnetlink_pair,
};
pub use namespace_store::{
    ActivatedNetworkDescriptors, MAXIMUM_RETAINED_NETWORK_NAMESPACES,
    NetworkNamespaceCustodyRequirementV1, NetworkNamespaceStoreError, NetworkNamespaceStoreName,
    NetworkNamespaceStoreOutcome, PendingNetworkSystemdActivationV1, RetainedNetworkNamespace,
    SystemdNetworkNamespaceStore, adopt_systemd_activation, claim_network_activation,
    validate_activation_replay,
};
pub use nftables_reader::{FixedNftablesObservationReader, decode_nftables_observation};
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
pub use preparation_runtime::{
    FinalizedNetworkPreparationV1, NetworkPreparationFinalizationInput,
    NetworkPreparationRecoveryInput, NetworkPreparationRuntimeError,
    begin_network_preparation_once, finalize_executed_network_preparation,
    finalize_recovered_ambiguous_network_preparation, publish_committed_network_preparation,
};
pub use protected_policy::{NETWORK_POLICY_CATALOG_FILE_NAME, ProtectedNetworkPolicyErrorV1};
pub use rtnetlink_reader::{
    FixedRtnetlinkObservationReader, RtnetlinkLinkInventoryV1, RtnetlinkNamespaceInventoryV1,
};
pub use service::{NetworkConnectionOutcome, NetworkInventoryService, NetworkServiceError};
pub use session_runtime::{NetworkBrokerSessionRuntimeErrorV1, NetworkBrokerSessionRuntimeV1};
pub use state::{
    CommittedNetworkResultV1, DurableNetworkPhase, NetworkNamespaceCustodyV1, NetworkRecoveryEntry,
    NetworkRecoverySnapshotV1, NetworkStateError, NetworkStateStore, VerifiedNetworkResultV1,
};
pub use worker_protocol::{
    AuthenticatedNetworkPrepareWorkerDispatchV1, MAXIMUM_NETWORK_WORKER_REQUEST_BYTES,
    NetworkActivationAuthorizationV1, NetworkMutationAuthorizationV1,
    NetworkPrepareWorkerDispatchV1, NetworkWorkerProtocolError,
};
pub use worker_replay::NetworkWorkerReplayLedger;
pub use worker_runtime::{
    NetworkWorkerConfiguration, NetworkWorkerRuntimeError, PreparedNetworkWorkerOutput,
    RecoveredNetworkPreparationObservation, SystemdNetworkPrepareExecutor,
    run_inherited_network_prepare_worker,
};
