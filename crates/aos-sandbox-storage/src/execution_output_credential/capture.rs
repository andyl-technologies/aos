//! Lends only the protected Output writer to its genuine Native Capture owner.
//!
//! Source/name/currentness bookends are independently driven by the enclosing
//! paid Session action. This adapter does not open a second Output source,
//! create a financial owner or accept parsed physical data as authority.

use super::StorageExecutionOutputCustodyV1;

impl StorageExecutionOutputCustodyV1 {
    pub(crate) fn capture_issuance_receiving_demand_v3(&self)
        -> Result<aos_sandbox_core::ResourceVector, aos_sandbox::journal::JournalAppendReceivingDemandErrorV1>
    {
        crate::execution_output::CaptureCreateIssuanceOriginalV3::receiving_demand_v3(&self.ledger)
    }

    pub(crate) fn issue_native_capture_ongoing_v3(
        &mut self,
        admitted: crate::authorization::VerifiedCaptureReserveOngoingAdmissionV3,
        host: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        requirement: crate::catalog_transition::execution_capture::CaptureDatasetRequirementV1,
        policy: crate::execution_capture_policy::CaptureAllocationV1,
        original: &mut crate::execution_output::CaptureCreateIssuanceOriginalV3,
    ) -> Result<(), crate::execution_output::ExecutionOutputLedgerErrorV1> {
        self.ledger.issue_capture_create_ongoing_v3(admitted, host, requirement, policy, original)
    }

    pub(crate) fn bind_native_capture_dataset_v3(
        &mut self,
        original: &mut crate::execution_output::CapturePhysicalBindingOriginalV3,
        native: &crate::execution_capture_zfs_worker::NativeCaptureCreateOriginalV3,
        catalog: &crate::state::CaptureStateCatalogOriginalV3,
        state: &aos_sandbox::Journal,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), crate::execution_output::ExecutionOutputLedgerErrorV1> {
        self.ledger.bind_native_capture_dataset_v3(original, native, catalog, state, receiving)
    }
}


impl StorageExecutionOutputCustodyV1 {
    pub(crate) fn capture_complete_receiving_demand_v3(&self)
        -> Result<aos_sandbox_core::ResourceVector, aos_sandbox::journal::JournalAppendReceivingDemandErrorV1> {
        crate::execution_output::CaptureCompletePersistenceOriginalV2::receiving_demand_data_v2(&self.ledger)
    }

    pub(crate) fn commit_native_capture_complete_v3(&mut self,
        original: &mut crate::execution_output::CaptureCompletePersistenceOriginalV2,
        record: &aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2)
        -> Result<(), crate::execution_output::ExecutionOutputLedgerErrorV1> {
        self.ledger.commit_complete_record_data_v2(original, record)
    }
}
