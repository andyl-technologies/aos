//! Owns protected Controller integration above the sandbox domain and sessions.
//!
//! The Controller retains reconciliation, concrete effect exchanges, inventory
//! custody, Cache/View integration, and its private role credentials together.
//! `controller_service` exposes the existing application assembly and inventory
//! owners; private `retained_exchange` and `inventory_transport` modules own their
//! finite in-process transitions. Broker Session Security remains below this
//! crate and owns protected transport, authentication, clocks, and native history.
//! Executable registration stays in `aos-sandbox-services`.

#![cfg(target_os = "linux")]

pub mod controller_service;
mod inventory_transport;
mod retained_exchange;
mod storage_create_preparation;

use aos_sandbox_broker_session_security::{
    BrokerSessionSecurityError,
    DormantAuthenticatedBrokerSessionV1,
    DormantBrokerDescriptorRequestPreparationV1,
    DormantBrokerDescriptorRequestSendProgressV1,
    DormantBrokerDescriptorRequestSendRecoveryV1,
    DormantBrokerRequestCoordinatesV1,
    DormantBrokerRequestPreparationV1,
    DormantBrokerRequestSendProgressV1,
    DormantBrokerResponseProgressV1,
    DormantBrokerSessionHandshakeErrorV1,
    DormantOutstandingBrokerRequestV1,
    DormantPreparedBrokerDescriptorRequestV1,
    DormantPreparedBrokerRequestV1,
    DormantUnconfirmedBrokerDescriptorRequestV1,
    DormantUnconfirmedBrokerRequestV1,
    ProtectedBrokerOutcomeAdmissionV1,
    ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1,
    ProtectedBrokerOutcomeCommittedAdvancementV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ProtectedBrokerRequestCommitRecoveryV1,
    ProtectedBrokerSessionFixedCustodyV1,
    ProtectedBrokerSessionFixedEndpointV1,
    ProtectedBrokerSessionInitializationRecoveryV1,
    production_deadline_after,
};

#[cfg(all(test, feature = "kernel-tests"))]
use aos_sandbox_broker_session_security::{
    ProductionBrokerSessionActivationV1, ProductionMountBrokerOwnersV1,
};

pub use controller_service::inventory::{
    DormantAtomicStorageInventoryCompletionV1, DormantAtomicStorageInventoryFinishProgressV1,
    DormantAtomicStorageInventoryFinishRecoveryV1, DormantAtomicStorageInventoryPredecessorV1,
    DormantHostRuntimeInventoryOwnerV1, DormantLifecycleInventoryQueryProgressV1,
    DormantLifecycleInventoryQueryRecoveryV1, DormantMountLifecycleInventoryOwnerV1,
    DormantNetworkLifecycleInventoryOwnerV1, DormantStorageLifecycleInventoryOwnerV1,
};

pub use storage_create_preparation::AuthenticatedStorageCreatePreparationV1;
