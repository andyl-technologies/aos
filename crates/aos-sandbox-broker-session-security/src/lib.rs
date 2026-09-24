//! Protected local foundation for Broker Session Authentication 1.0.
//!
//! This crate decodes one fixed protected manifest, retains
//! role-local signing seeds behind protected file descriptors, detects local
//! configuration replacement, pins the custody process through a retained
//! self pidfd, and obtains process identifiers, hello nonces, and time directly
//! from the Linux kernel. Its fixed activation owner adopts only the exact
//! systemd listener table for a selected broker service. The protected
//! composition accepts one connected sequenced-packet socket, completes the
//! authenticated hello flights, opens
//! the matching protected journal, and exposes the complete post-handshake
//! request, response, replay, and recovery state machine. Transcript, peer,
//! protected time, descriptor custody, and journal ownership remain inseparable;
//! no detached signer, caller-built authenticated request, or raw channel
//! authority is exposed.
//!
//! [`controller_service`] owns the unprivileged node-controller process above
//! the controller core and this crate's protected transports. Sharing a crate
//! does not combine processes: each broker and controller retains its separate
//! executable, service identity, protected state, and systemd confinement.
//!
//! Broker-side execution reserves the authenticated request durably before
//! issuing a move-only domain handoff. Concrete Host, Storage, Mount, and
//! Network adapters cover the closed method profile, including observation and
//! inventory, and bind the signed terminal outcome to the protected domain
//! observation. Ambiguous effects and commits retain exact recovery custody.
//! The crate creates no listener and registers no service by itself. Production
//! daemons must explicitly own its activation object, dispatch the closed
//! method profile, and retain recovery custody before advertising readiness.
//!
//! [`manifest`] owns the fixed `AOSBSC01` format.
//! `cache_source_membership` binds public Cache consumers to the independently
//! authenticated View source projection; `cache_directory_source` streams
//! staged objects beneath a caller-pinned source root. The private
//! protected-files module pins the endpoint directory and its three role-local
//! files. The private self-execution module pins and revalidates the loading
//! process. The private entropy module implements bounded kernel acquisition;
//! the endpoint module owns narrow client and broker custody APIs; and the
//! handshake module owns the dormant same-channel hello and general protected
//! traffic typestates. The private
//! recovery module owns the fixed-root `AOSBSJ01` namespace-47 journal, stable
//! endpoint identity and authenticated process rollover, protected full-history
//! currentness sandwiches, and the only paths able to mint recovered resend or
//! outstanding-outcome state.

#![cfg(target_os = "linux")]

mod cache_directory_source;
mod cache_index_buffer;
mod cache_public_pin;
mod cache_source_membership;
mod controller_authority_effect;
mod controller_attach_credentials;
mod controller_guest_root_credentials;
mod controller_attach_exchange;
mod controller_ownership;
mod controller_plan_signer;
mod controller_publication;
mod controller_retained_exchange;
pub mod controller_service;
mod dormant_handshake;
mod endpoint;
mod entropy;
mod error;
mod handoff;
mod handshake;
mod host_consumer_cgroup_transfer;
mod host_execution_handoff;
mod lifecycle_domain_effect;
mod lifecycle_host_inventory;
pub mod policy_authority_client;
pub mod policy_binding_barrier;
pub mod manifest;
pub mod ownership_authority_client;
pub mod ownership_authority_runtime;
pub mod ownership_authority_server;
pub mod policy_signer_credential;
mod production_activation;
mod production_dispatch;
mod production_receive;
mod production_response;
mod production_root_mount_source_provider;
mod production_service;
mod production_source_provider_catalog;
mod production_source_provider;
mod production_source_provider_storage;
#[allow(
    dead_code,
    reason = "sealed handshake context access stays unreachable until P0-10"
)]
mod protected_files;
mod recovery;
#[allow(
    dead_code,
    reason = "sealed handshake boot access stays unreachable until P0-10"
)]
mod self_execution;
mod storage_create_preparation;

pub use cache_directory_source::{
    DirectoryPortableObjectSource, PortableObjectReader, ProjectSealedViewObjectSourceV1,
    ProjectSealedViewSourceErrorV1,
};
pub use cache_public_pin::{
    ConfirmedPublicCachePinV1, PublicCachePinExecutionErrorV1, PublicCachePinExecutionV1,
    PublicCachePinRecoveryErrorV1, PublicCachePinRecoveryV1, PublicCacheUnpinExecutionV1,
    PublicCacheUnpinObservationErrorV1, PublicCacheUnpinProgressErrorV1,
    PublicCacheUnpinProgressV1, PublicCacheUnpinRecoveryErrorV1, PublicCacheUnpinRecoveryV1,
    execute_public_cache_pin_from_project_revision_v1,
    execute_public_cache_pin_from_project_source_v1, execute_public_cache_pin_v1,
    execute_public_cache_unpin_consumer_v1, execute_public_cache_unpin_v1,
    observe_public_cache_unpin_completion_v1, public_cache_pin_transaction_id_v1,
    public_cache_unpin_transaction_id_v1, recover_public_cache_pin_v1,
    recover_public_cache_unpin_v1,
};
pub use cache_source_membership::{
    CacheCompiledSourceLimitsV1, CacheSourceMembershipErrorV1, CacheSourceMembershipLimitsV1,
    CompiledCacheSourceMembershipErrorV1, join_cache_source_membership_v1,
    with_cache_source_membership_v1, with_compiled_cache_source_membership_from_revision_v1,
    with_compiled_cache_source_membership_v1,
};
pub use dormant_handshake::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorCommitRecoveryV1,
    DormantBrokerDescriptorCommitResultV1, DormantBrokerDescriptorExecutionFailureV1,
    DormantBrokerDescriptorInFlightReplayV1, DormantBrokerDescriptorOutcomeUnknownV1,
    DormantBrokerDescriptorRequestPreparationV1, DormantBrokerDescriptorRequestReceiveProgressV1,
    DormantBrokerDescriptorRequestSendProgressV1, DormantBrokerDescriptorRequestSendRecoveryV1,
    DormantBrokerDescriptorResponseProgressV1, DormantBrokerDescriptorSendProgressV1,
    DormantBrokerDescriptorSendRecoveryV1, DormantBrokerDescriptorTerminalReplayRecoveryProgressV1,
    DormantBrokerDescriptorTerminalReplaySendProgressV1, DormantBrokerDescriptorTerminalReplayV1,
    DormantBrokerEndpointHandshakeProgressV1, DormantBrokerEndpointHandshakeV1,
    DormantBrokerExecutionErrorV1, DormantBrokerExecutionFailureV1, DormantBrokerFailureV1,
    DormantBrokerOutcomeUnknownV1, DormantBrokerOutcomeVerificationV1,
    DormantBrokerPublicationExecutionFailureV1, DormantBrokerRequestCoordinatesV1,
    DormantBrokerRequestPreparationV1, DormantBrokerRequestReceiveProgressV1,
    DormantBrokerRequestSendProgressV1, DormantBrokerResponseProgressV1,
    DormantBrokerResponseSendProgressV1, DormantBrokerSessionHandshakeErrorV1,
    DormantBrokerTerminalReplaySendProgressV1, DormantBrokerTerminalReplayV1,
    DormantCommittedBrokerDescriptorResponseV1, DormantControllerClientHandshakeProgressV1,
    DormantControllerClientHandshakeV1, DormantHostCatalogPublicationRecoveryProgressV1,
    DormantHostCatalogPublicationRetryV1, DormantHostCatalogPublicationUnknownV1,
    DormantHostConsumerCgroupResponseProgressV1, DormantHostScopeTerminalFinalizationV1,
    DormantMountSourceBrokerRecoveryProgressV1, DormantMountSourceBrokerRecoveryV1,
    DormantOutstandingBrokerRequestV1, DormantPreparedBrokerDescriptorRequestV1,
    DormantPreparedBrokerRequestV1, DormantReadyBrokerDescriptorTerminalReplayV1,
    DormantReceivedBrokerDescriptorRequestV1, DormantReceivedBrokerRequestV1,
    DormantUnconfirmedBrokerDescriptorRequestV1, DormantUnconfirmedBrokerRequestV1,
    DormantUnconfirmedReceivedBrokerRequestV1,
};
pub use endpoint::{
    BrokerSessionProcessExecutionIdV1, FreshBrokerHelloNonceV1, FreshClientHelloNonceV1,
};
pub(crate) use endpoint::{ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1};
pub use error::BrokerSessionSecurityError;
pub use handoff::{
    DormantBrokerEffectHandoffErrorV1, DormantHostBrokerEffectAdapterV1,
    DormantHostBrokerObservationAdapterV1, DormantMountBrokerEffectAdapterV1,
    DormantMountBrokerInventoryAdapterV1, DormantMountCatalogPreparationAdapterV1,
    DormantNetworkBrokerEffectAdapterV1, DormantStorageBrokerEffectAdapterV1,
    ProtectedBrokerEffectEvidenceV1, ProtectedBrokerEffectHandoffV1,
    ProtectedBrokerEffectObservationOutcomeV1, ProtectedBrokerEffectObservationRetryV1,
    ProtectedBrokerEffectObservationV1, ProtectedHostEffectHandoffV1,
    ProtectedMountEffectHandoffV1, ProtectedNetworkEffectHandoffV1,
    ProtectedStorageEffectHandoffV1,
};
pub use host_consumer_cgroup_transfer::{
    ProtectedHostConsumerCgroupIdentityV1, ProtectedHostConsumerCgroupTransferV1,
    ProtectedHostStorageConsumerJoinErrorV1, ProtectedHostStorageConsumerJoinV1,
};
pub use host_execution_handoff::HostExecutionHandoffErrorV1;
pub use lifecycle_domain_effect::{
    DormantLifecycleDomainEffectOwnerV1, DormantLifecycleDomainEffectProgressV1,
    DormantLifecycleDomainEffectRecoveryV1,
};
pub use lifecycle_host_inventory::{
    DormantAtomicStorageInventoryCompletionV1, DormantAtomicStorageInventoryFinishProgressV1,
    DormantAtomicStorageInventoryFinishRecoveryV1, DormantAtomicStorageInventoryPredecessorV1,
    DormantHostRuntimeInventoryOwnerV1, DormantLifecycleInventoryQueryProgressV1,
    DormantLifecycleInventoryQueryRecoveryV1, DormantMountLifecycleInventoryOwnerV1,
    DormantNetworkLifecycleInventoryOwnerV1, DormantStorageLifecycleInventoryOwnerV1,
};
pub use manifest::{
    BROKER_SESSION_SECURITY_MANIFEST_BYTES, BrokerSessionManifestBindingV1,
    BrokerSessionSecurityAudienceV1, BrokerSessionSecurityKeyPinV1,
    BrokerSessionSecurityManifestV1,
};
pub use production_activation::{
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    ProductionHostBrokerServiceErrorV1, ProductionHostBrokerServiceV1,
};
pub use production_dispatch::{
    ProductionHostBrokerDispatchCommitV1, ProductionHostBrokerDispatchFailureV1,
    ProductionMountBrokerDispatchErrorV1, ProductionNetworkBrokerDispatchErrorV1,
    ProductionStorageBrokerDispatchErrorV1,
};
pub use production_receive::{
    ProductionBrokerReceiveErrorV1, ProductionBrokerRequestEventV1,
    ProductionHostBrokerRequestEventV1,
};
pub use production_response::ProductionBrokerResponseErrorV1;
pub use production_root_mount_source_provider::{
    ProductionRootMountSourceProviderErrorV1, advance_authenticated_pending_acquire_recovery,
    connect_authenticated_fixed_source_provider, observe_original_pending_acquires,
};
pub use production_service::{
    ProductionBrokerDeadlineErrorV1, ProductionBrokerServiceErrorV1, ProductionMountBrokerOwnersV1,
    production_deadline_after,
};
pub use production_source_provider::{
    ProductionSourceProviderIngressErrorV1, ProductionSourceProviderIngressV1,
};
pub use production_source_provider_catalog::{
    ProductionSourceProviderCatalogInstallErrorV1, install_fixed_source_provider_catalog_credential,
};
pub use production_source_provider_storage::{
    ProductionSourceProviderStorageErrorV1, ProductionSourceProviderStorageOutcomeV1,
    ProductionSourceProviderStorageReadbackV1, inspect_signed_storage_export_plan,
};
pub use recovery::{
    ProtectedBrokerOutcomeAdmissionGateV1, ProtectedBrokerOutcomeAdmissionV1,
    ProtectedBrokerOutcomeCommitReadbackV1, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
    ProtectedBrokerOutcomeCurrentV1, ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ProtectedBrokerOutcomeDurableCasV1, ProtectedBrokerOutcomePendingAdvancementV1,
    ProtectedBrokerOutcomeReplayV1, ProtectedBrokerRequestCommitRecoveryV1,
    ProtectedBrokerRequestCommitResultV1, ProtectedBrokerSessionFixedCustodyV1,
    ProtectedBrokerSessionFixedEndpointV1, ProtectedBrokerSessionInitializationRecoveryV1,
    ProtectedBrokerSessionInitializationResultV1,
};
pub use storage_create_preparation::AuthenticatedStorageCreatePreparationV1;
