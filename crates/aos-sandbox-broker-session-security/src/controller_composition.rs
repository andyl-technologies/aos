//! Provides the closed sealed compositions used by the concrete Controller owner.
//!
//! Broker Session Security retains protected files, fixed credentials, native
//! history, and all authentication. These named ports let Controller retain the
//! original opaque custody and inspect inert DATA; they expose no scalar signer,
//! caller-selected root or replacement authority. Borrowed historical negotiated
//! contexts remain comparison DATA tied to their actual completed answer. Fixed
//! lifecycle completions and online Nix recipes preserve their existing lower
//! authentication and native commit engines.

mod history;
mod lifecycle;
#[cfg(feature = "online-nix")]
mod online;

pub use history::{
    ArchivedStorageInventoryHeadDataV1, HistoricalAtomicStorageHistoryDataV1,
    HistoricalAtomicStorageHistoryV1,
};
#[cfg(feature = "online-nix")]
pub use online::{
    ControllerOnlineNixEndpointCustodyV1, ControllerOnlineNixHandshakeErrorV1,
    ControllerOnlineNixHandshakeProgressV1, ControllerOnlineNixHandshakeV1,
    ControllerOnlineNixHelloV1, ControllerOnlineNixNativeRequestCustodyV1,
    ControllerOnlineNixOutcomeOpeningV1,
    ControllerOnlineNixPreparedRequestV1, ControllerOnlineNixProvisionV1,
    ControllerOnlineNixSessionV1, ControllerOnlineNixVerifiedHandshakeV1,
    OnlineTransportFailureV1,
};

pub use crate::dormant_handshake::{
    ExecutionPublicationReceiveCustodyV1, ProtectedStorageSessionBindingV1,
    OriginalStorageClientSessionTransitionV1, OriginalStorageClientTransitionClosedV1,
    OriginalDeleteInventoryClientV1,
    OperatorRecoverStorageInventoryOriginalV1, OperatorReconciliationSessionOpenV2,
    OperatorReconciliationInventoryOriginalV2,
    ControllerCatalogMaintenanceInventoryOriginalV2,
    ControllerCatalogMaintenanceCycleOriginalV2, ControllerCatalogMaintenanceColdCompletedV2, ControllerCatalogMaintenanceColdReceiptV2,
    ControllerCatalogMaintenanceRefreshCompletedV2, ControllerCatalogMaintenanceRefreshReceiptV2,
    check_production_deadline, wait_for_handshake_readiness,
};
pub use crate::handshake::{
    OriginalBrokerColdDeadlineV1, OutputCurrentnessBoundaryV1,
    RetainedStorageColdOpenV1, RetainedStorageHandshakeSendFailureV1,
    protected_boottime_nanoseconds,
};
pub use crate::handshake::output_registration_continuation::{
    HeldOutputPreparationV1, OriginalOutputClientFlightV1, OriginalStorageInventoryClientFlightV1,
    DeleteInventoryModelV1, DeleteInventoryAnswerOriginalsV1, DeleteInventoryNegotiatedPreimagesV2,
    OriginalStorageCreatePreparationFlightV1, CreateStorageCompletedPreparationDataV1, original_create_storage_use_security_shape_v1,
    CreateStorageReadyBundleClosedV1, OriginalStorageReadyBundleFlightV1,
    OriginalStoragePreparationClientFlightV1, OutputPreparationClosedV1,
    DeleteNetworkApplySessionIoOriginalV4, delete_network_apply_security_shape_v4, delete_network_apply_response_maximum_v4, DeleteMountReapSessionIoOriginalV4, delete_mount_reap_security_shape_v4, delete_mount_reap_response_maximum_v4, DeleteStorageApplySessionIoOriginalV3, delete_storage_apply_security_shape_v3, delete_storage_apply_response_maximum_v3,
    DeleteStoragePreparationSessionIoOriginalV3, delete_storage_preparation_security_shape_v3, delete_storage_preparation_response_maximum_v3,
    OutputPreparationCustodyV1, StoragePreparationClientProgressV1,
    ControllerCatalogMaintenanceSessionIoOriginalV2, StorageProvisioningSessionIoOriginalV1, StartHostCatalogSessionIoOriginalV2, StartHostCatalogQualifiedSessionBorrowV2, StartResourceProvisioningSessionIoOriginalV4, StartResourceCompletedModelsOriginalV2, StartResourceSessionCompletionDataV2,
};
pub use aos_sandbox_broker::ownership_clock::{CLOCK_PROVENANCE, sample_ownership_clock};
pub use crate::production_startup::{
    ControllerLaunchImageCaptureV1, ControllerLaunchImageBindingErrorV1,
    ControllerLaunchImageCaptureFailureV1, Pid1LaunchImageV1,
};
pub use crate::recovery::{
    ArchivedStorageInventoryHeadV1, AuthenticatedOriginalHostArgumentArchiveV1,
    AuthenticatedOriginalHostNoApplyJoinV1, RetainedFailedCreateOriginalsDataV3,
};
#[cfg(feature = "online-nix")]
pub use crate::tpm_nv_custody::FloorErrorV1;

/// Borrows only a matching actual Session's retained native mutation cause.
///
/// Returned wrappers keep their original cause order. This helper follows the
/// existing source chain and resolves only the exact captured transaction
/// marker emitted by that same owner's native return; it performs no IO,
/// revalidation, allocation, retry, funding or authority construction.
#[must_use]
pub fn execution_native_failure_for_v1<'cause>(
    session: &'cause crate::DormantAuthenticatedBrokerSessionV1,
    returned: &'cause (dyn std::error::Error + 'static),
) -> Option<&'cause (dyn std::error::Error + 'static)> {
    let mut current = Some(returned);
    // All actual wrappers are finite. Bound hostile diagnostic implementations
    // too; failure to resolve never changes the returned classification.
    for _ in 0..16 {
        let cause = current?;
        if let Some(marker @ crate::BrokerSessionSecurityError::CapturedJournalMutation { .. }) =
            cause.downcast_ref::<crate::BrokerSessionSecurityError>()
        {
            return session.captured_journal_failure_for_v1(marker);
        }
        current = cause.source();
    }
    None
}
