//! Runs fresh Query61 through the same paid request/outcome Session engine.
//!
//! The installed method selector remains closed until the complete Capture
//! dispatch cohort is joined. This concrete domain adapter produces only a
//! canonical historical response and cannot issue a worker or reserve permit.

use super::*;

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn execute_storage_capture_query_lifecycle_and_commit_v3(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox_controller_domain::StorageReceivingClosedV1>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>
    {
        let selected = request.0.method() == BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1
            && request.0.authorization().is_some()
            && request.0.storage_execution_capture_source_ongoing_v2().is_some();
        let (request, _) = if selected {
            self.begin_storage_lifecycle_execution_v1(request, selected, receiving, native_admission)?
        } else {
            self.begin_execution(request, selected)?
        };
        let response = match self.0.consume_storage_capture_query_lifecycle_v3(&request.0, storage, output, receiving) {
            Ok(response) => response,
            Err(cause) => return Err(Self::unknown_domain(request, cause)),
        };
        self.finish_observed_success_with_storage_payer_v1(request, response,
            Some(StorageOutcomeReceivingV1::Lifecycle(receiving)))
    }
}

impl DormantReceivedBrokerRequestV1 {
    pub(crate) fn retire_original_storage_capture_query_v3(
        &self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
    ) -> Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        storage.retire_original_capture_query_v3(&self.0)
    }
}
