//! Joins the actual signed Capture60 to the same State and physical catalog.
//!
//! Only this coordinator owns the configured verifier and protected writers.
//! Fresh cuts remain alongside the actual request; they cannot be reconstructed
//! from historical receipts or parsed Source data. Worker entry remains on the
//! same genuine State/F loan after the authenticated Host45 continuation.

use super::*;
use crate::authorization::VerifiedCaptureReserveOngoingAdmissionV3;
use crate::runtime::original_capture::CaptureReserveErrorV3;

pub(crate) struct CaptureReserveCutV3 {
    admitted: Option<VerifiedCaptureReserveOngoingAdmissionV3>,
    source: aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2,
    authority_head: u64,
    fence_digest: ObjectDigest,
    catalog: crate::catalog_transition::VerifiedPhysicalCatalogSnapshotV1,
}

impl CaptureReserveCutV3 {
    pub(crate) fn source_v3(&self)
        -> &aos_sandbox_protocol::storage_capture_grant::StorageCaptureGrantSourceV2
    { &self.source }

    pub(crate) fn catalog_v3(&self) -> &crate::catalog_transition::VerifiedPhysicalCatalogSnapshotV1 {
        &self.catalog
    }

    pub(crate) fn matches_v3(&self, other: &Self) -> bool {
        match (&self.admitted, &other.admitted) {
            (Some(before), Some(after)) => before.matches_v3(after)
                && self.source == other.source && self.authority_head == other.authority_head
                && self.fence_digest == other.fence_digest && self.catalog.binding() == other.catalog.binding(),
            _ => false,
        }
    }

    pub(crate) fn require_acquisition_clock_v3(&self, clock: &RawPairedClockSample)
        -> Result<(), CaptureReserveErrorV3>
    {
        let admitted = self.admitted.as_ref().ok_or(CaptureReserveErrorV3::Closed)?;
        admitted.lifetime_v3().require_ongoing_clock_v3(clock)?;
        if clock.boottime_nanoseconds() >= admitted.lifetime_v3().acquisition_deadline_v3() {
            return Err(CaptureReserveErrorV3::Closed);
        }
        Ok(())
    }

    pub(crate) fn take_admitted_once_v3(&mut self) -> Option<VerifiedCaptureReserveOngoingAdmissionV3> {
        self.admitted.take()
    }
}

impl StorageAdmissionCoordinator {
    pub(crate) fn authenticate_capture_reserve_ongoing_v3(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        clock: &RawPairedClockSample,
    ) -> Result<CaptureReserveCutV3, CaptureReserveErrorV3> {
        let source = request.storage_execution_capture_source_ongoing_v2()
            .ok_or(CaptureReserveErrorV3::Closed)?;
        let prior = self.transactions.authority_record(RecordNamespace::DesiredState,
            source.original_source_v1().assignment().sandbox().as_bytes())?
            .ok_or(CaptureReserveErrorV3::Closed)?;
        let admitted = self.authority.admit_capture_reserve_ongoing_v3(request, clock, prior)?;
        let physical = self.transactions.verified_resolver_journal()?;
        let catalog = physical.physical().clone();
        Ok(CaptureReserveCutV3 {
            admitted: Some(admitted), source: *source,
            authority_head: self.transactions.authority_head_sequence()?,
            fence_digest: ObjectDigest::from_bytes(Sha256::digest(prior).into()), catalog,
        })
    }

    pub(crate) fn prepare_capture_native_pending_v3(
        &mut self,
        native: &mut crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), crate::StorageStateError> {
        native.prepare_state_pending_once_v3(&mut self.transactions, &self.authority, receiving)
    }

    pub(crate) fn complete_capture_created_catalog_v3(
        &mut self,
        physical: &mut crate::process::CapturePhysicalPreparationOriginalV3,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), crate::StorageStateError> {
        physical.commit_catalog_once_v3(&mut self.transactions, output, receiving)
    }
}


impl StorageAdmissionCoordinator {
    pub(crate) fn serve_capture_held_native_v3(&self,
        physical: &mut crate::process::CapturePhysicalPreparationOriginalV3,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener,
        output: &mut crate::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>) -> Result<(), crate::ZfsWorkerError> {
        physical.serve_host_held_once_v3(listener, &self.transactions,
            self.transactions.recovery_encoding_journal_v1(), output, receiving)
    }
}
