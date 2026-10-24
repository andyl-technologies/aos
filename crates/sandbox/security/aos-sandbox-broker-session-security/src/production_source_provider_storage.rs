//! Fixed SourceProvider adapters for the protected Storage client.
//!
//! Kernel peer and cgroup checks remain owned by the shared security boundary.

use aos_sandbox_source_provider::{
    AcquirePlanV1, ActiveAcquisitionSnapshotV1, BackendObservationChallengeV1,
    RawAcquireObservationV1, RawBackendAcquisitionV1, RawBackendReleaseV1, RawReleaseObservationV1,
    RawReopenObservationV1, ReleasePlanV1, SourceProviderBackendTransportErrorV1,
    SourceProviderBackendTransportV1,
};
use aos_sandbox_source_provider_protocol::{
    SignedStorageLiveExportRequestV1, SignedStorageNativeAcquireRequestV2,
};

pub use aos_sandbox_source_provider_security::{
    ProductionSourceProviderStorageErrorV1, ProductionSourceProviderStorageOutcomeV1,
    inspect_signed_storage_export_plan,
};

/// Adapts the fixed authenticated Storage clients to the dormant Provider backend.
///
/// LocalLive remains descriptor-free and unavailable-only. The native client
/// returns received original-FD custody, which the private Provider owner must
/// independently authenticate and durably complete before any RootMount reply.
#[derive(Debug, Default)]
pub struct ProductionSourceProviderStorageReadbackV1;

impl SourceProviderBackendTransportV1 for ProductionSourceProviderStorageReadbackV1 {
    fn exchange_storage_native_acquire_v2(
        &mut self,
        request: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<
        Option<aos_sandbox_source_provider_security::ReceivedStorageNativeAcquireV3>,
        SourceProviderBackendTransportErrorV1,
    > {
        aos_sandbox_source_provider_security::exchange_signed_storage_native_acquire_v2(request)
            .map_err(|_| SourceProviderBackendTransportErrorV1::Unavailable)
    }

    fn inspect_storage_live_export_request(
        &mut self,
        signed_plan: &SignedStorageLiveExportRequestV1,
    ) -> Result<(), SourceProviderBackendTransportErrorV1> {
        inspect_signed_storage_export_plan(signed_plan.clone())
            .map(|ProductionSourceProviderStorageOutcomeV1::Unavailable| ())
            .map_err(|_| SourceProviderBackendTransportErrorV1::Unavailable)
    }

    fn observe_acquire(
        &mut self,
        _plan: &AcquirePlanV1,
        _challenge: &BackendObservationChallengeV1,
    ) -> Result<RawAcquireObservationV1, SourceProviderBackendTransportErrorV1> {
        Err(SourceProviderBackendTransportErrorV1::Unavailable)
    }

    fn execute_acquire(
        &mut self,
        _plan: &AcquirePlanV1,
    ) -> Result<RawBackendAcquisitionV1, SourceProviderBackendTransportErrorV1> {
        Err(SourceProviderBackendTransportErrorV1::Unavailable)
    }

    fn reopen_active(
        &mut self,
        _acquisition: &ActiveAcquisitionSnapshotV1,
    ) -> Result<RawReopenObservationV1, SourceProviderBackendTransportErrorV1> {
        Err(SourceProviderBackendTransportErrorV1::Unavailable)
    }

    fn observe_release(
        &mut self,
        _plan: &ReleasePlanV1,
        _challenge: &BackendObservationChallengeV1,
    ) -> Result<RawReleaseObservationV1, SourceProviderBackendTransportErrorV1> {
        Err(SourceProviderBackendTransportErrorV1::Unavailable)
    }

    fn execute_release(
        &mut self,
        _plan: &ReleasePlanV1,
    ) -> Result<RawBackendReleaseV1, SourceProviderBackendTransportErrorV1> {
        Err(SourceProviderBackendTransportErrorV1::Unavailable)
    }
}
