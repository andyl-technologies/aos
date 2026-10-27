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
//! Protected Controller integration and reconciliation live above this crate
//! in `aos-sandbox-controller-runtime`. Executable entry points, HTTP listeners,
//! and service registration live in `aos-sandbox-services`; its assembly port
//! receives opaque handlers and negative-only terminal loans.
//! Brokers and Controller retain separate identities, state, and confinement.
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
//! The canonical protocol manifest owns the fixed `AOSBSC01` format and
//! shape-only pins; this crate owns their protected provenance and currentness.
//! The private protected-files module pins
//! the endpoint directory and its three role-local files. The private
//! self-execution module pins and revalidates the loading
//! process. The private entropy module implements bounded kernel acquisition;
//! the endpoint module owns narrow client and broker custody APIs; and the
//! handshake module owns the dormant same-channel hello and general protected
//! traffic typestates. The private
//! recovery module owns the fixed-root `AOSBSJ01` namespace-47 journal, stable
//! endpoint identity and authenticated process rollover, protected full-history
//! currentness sandwiches, and the only paths able to mint recovered resend or
//! outstanding-outcome state.

#![cfg(target_os = "linux")]

pub mod controller_composition;
mod dormant_handshake;
mod host_stop;
mod host_stop_inventory;
pub use host_stop_inventory::HostStopInventoryAttestationOriginalV5;

pub use host_stop::HostStopRequestPreparationOriginalV5;
mod endpoint;
mod controller_session_receiving;
mod entropy;
pub mod nix_floor_provisioning;
pub mod method46_initial_provisioning;
#[cfg(feature = "online-nix")]
pub mod nix_service;
mod error;
mod tpm_nv_custody;
pub use tpm_nv_custody::{RuntimeDeploymentCanaryRunErrorV2, run_runtime_deployment_canary_once_v2, run_runtime_boot_preparation_once_v1};
mod handoff;
mod handshake;

pub use handshake::output_registration_continuation::{
    ExecutionAvailabilitySessionIoOriginalV2, ExecutionAvailabilityClientSessionBorrowV2,
    HostExecutionNoApplySessionIoOriginalV2, HostExecutionNoApplyClientSessionBorrowV2,
};
mod host_consumer_cgroup_transfer;
mod host_execution_handoff;
mod host_mount_scope_identity_transfer;
mod immutable_image;
pub mod ownership_authority_client;
pub mod ownership_authority_server;
mod production_activation;
mod production_dispatch;
mod production_receive;
mod production_response;
mod production_root_mount_source_provider;
mod production_service;
mod production_source_provider_catalog;
mod production_source_provider_storage;
mod production_startup;
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
mod storage_host_consumer_client;
mod storage_host_output_readback;

#[cfg(test)]
mod test_signed_endpoint;

pub use recovery::{HostExecutionSessionReceivingOriginalV1, ExecutionClientPostOriginalV1};
pub use dormant_handshake::{
    DormantControllerInitialSessionOpenV1,
    OperatorRecoverStorageSessionOpenV1,
    OperatorStopCleanupSessionOpenV1,
    OperatorStopCleanupSourceSessionOpenV1,
    OperatorStopCleanupSourceInventoryOriginalV1,
    OperatorStopCleanupInventoryOriginalV1,
    ExecutionNoApplySessionOpenV2,
    DormantControllerInitialSessionCompletedBorrowV1,
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
    DormantHostConsumerCgroupResponseProgressV1, DormantHostMountScopeIdentityResponseProgressV1,
    DormantHostScopeTerminalFinalizationV1, DormantMountSourceBrokerRecoveryProgressV1,
    DormantMountSourceBrokerRecoveryV1, DormantOutstandingBrokerRequestV1,
    DormantPreparedBrokerDescriptorRequestV1, DormantPreparedBrokerRequestV1,
    DormantReadyBrokerDescriptorTerminalReplayV1, DormantReceivedBrokerDescriptorRequestV1,
    DormantReceivedBrokerRequestV1, DormantUnconfirmedBrokerDescriptorRequestV1,
    DormantUnconfirmedBrokerRequestV1, DormantUnconfirmedReceivedBrokerRequestV1,
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
    DormantStorageBrokerEffectAdapterV1,
    ProtectedBrokerEffectEvidenceV1, ProtectedBrokerEffectHandoffV1,
    ProtectedBrokerEffectObservationOutcomeV1, ProtectedBrokerEffectObservationRetryV1,
    ProtectedBrokerEffectObservationV1, ProtectedHostEffectHandoffV1,
    ProtectedMountEffectHandoffV1,
    ProtectedStorageEffectHandoffV1,
};
pub use host_consumer_cgroup_transfer::{
    ProtectedHostConsumerCgroupIdentityV1, ProtectedHostConsumerCgroupTransferV1,
    ProtectedHostStorageConsumerJoinErrorV1, ProtectedHostStorageConsumerJoinV1,
};
pub use host_execution_handoff::HostExecutionHandoffErrorV1;
pub use host_mount_scope_identity_transfer::{
    ProtectedHostMountScopeCurrentV1, ProtectedHostMountScopeIdentityTransferV1,
    ProtectedHostMountScopeIdentityV1,
};
pub use production_activation::{
    ProductionBrokerSessionActivationErrorV1, ProductionBrokerSessionActivationV1,
    ProductionHostActivationV1, ProductionHostReadinessV1, ProductionHostRoleV1,
};
pub use production_dispatch::{
    ProductionHostBrokerDispatchCommitV1, ProductionHostBrokerDispatchFailureV1,
    ProductionMountBrokerDispatchErrorV1,
    ProductionStorageBrokerDispatchErrorV1,
};
pub use production_receive::{
    ProductionBrokerReceiveErrorV1, ProductionBrokerRequestEventV1,
    ProductionHostBrokerRequestEventV1,
    ProductionOriginalMountReceiptV1, ProductionOriginalMountReceiptFailureV1,
};
pub use production_response::ProductionBrokerResponseErrorV1;
pub use production_root_mount_source_provider::{
    ProductionSelectedRootMountSourceProviderV1,
    ProductionSelectedRootMountSourceProviderFailureV1,
    ProductionRootMountSourceProviderErrorV1, advance_authenticated_pending_acquire_recovery,
    connect_authenticated_fixed_source_provider, observe_original_pending_acquires,
    observe_remote_cold_source_inventory, observe_remote_source_inventory,
    recover_reserved_remote_inventories,
};
pub use production_service::{
    ProductionBrokerDeadlineErrorV1, ProductionBrokerServiceErrorV1, ProductionMountBrokerOwnersV1,
    ProductionOriginalMountCycleV1, ProductionOriginalMountCycleFailureV1,
    ProductionOriginalNixGenerationCycleV1,
    ProductionOriginalStoragePrepareCycleV1, ProductionStorageSessionContinuationV1, StoragePrepareCycleClosedV1,
    ProductionOriginalStorageConnectionV1, ProductionOriginalStorageLifecycleSessionV1, StorageSessionContinuationClosedV1,
    production_deadline_after,
};
pub use source_catalog_readback::ProductionSourceProviderIngressErrorV1;
pub use production_source_provider_catalog::{
    ProductionSourceProviderCatalogInstallErrorV1, install_fixed_source_provider_catalog_credential,
    SelectedSourceProviderCatalogFailureRefV1, SelectedSourceProviderCatalogInstallFailureV1,
    install_fixed_selected_source_provider_catalog_credential,
};
pub use production_source_provider_storage::{
    ProductionSourceProviderStorageErrorV1, ProductionSourceProviderStorageOutcomeV1,
    ProductionSourceProviderStorageReadbackV1, inspect_signed_storage_export_plan,
};
pub use production_startup::{
    ProductionStorageResourceRecipientStartupErrorV1, ProductionStorageStartupPartsV1,
    ProductionStorageStartupV1,
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
pub use storage_host_consumer_client::{
    StorageHostConsumerClientErrorV1, StorageHostConsumerClientV1,
};
pub use storage_host_output_readback::{
    ProtectedHostStorageOutputCurrentV1, ProtectedHostStorageOutputReadbackV1,
};

/// Shares fixed catalog bytes and retained native failures without role authority.
#[doc(hidden)]
pub mod source_catalog_readback;

/// Shares nonauthorizing native activation and deadline observations.
#[doc(hidden)]
pub mod activation_envelope;

pub use production_source_provider_catalog::{
    SelectedFixedEndpointInstallClosedV4, SelectedMountEndpointInstallOriginalV4,
    SelectedNetworkEndpointInstallOriginalV4,
};

pub use handshake::output_registration_continuation::{FixedServiceRequestOriginalV4, FixedServiceRequestClosedV4};

pub use handshake::output_registration_continuation::{FixedServiceResponseOriginalV4, FixedServiceResponseClosedV4, FixedServiceResponseProgressV4};

pub use handshake::{FixedServiceSessionOpenOriginalV4, FixedServiceSessionBorrowV4, FixedServiceSessionClosedV4};

#[doc(hidden)]
pub use handshake::{StartResourceSessionOpenOriginalV4, StartResourceSessionClosedV4, StartResourceSessionBorrowV4};
