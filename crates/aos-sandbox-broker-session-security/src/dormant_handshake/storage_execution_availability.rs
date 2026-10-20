//! Executes method65 through the same original receipt, floor and outcome CAS.

use super::*;

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn execute_storage_execution_availability_receiving_and_commit_v2(
        &mut self, request: DormantReceivedBrokerRequestV1,
        original: &mut crate::production_service::ProductionStorageExecutionAvailabilityOriginalV2,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox::StorageReceivingClosedV1>,
    ) -> Result<ProtectedBrokerOutcomeCommitResultV1, DormantBrokerExecutionFailureV1<BrokerSessionSecurityError>> {
        let method_matches = request.method() == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2
            && request.0.authorization().is_none();
        let (request, context) = self.begin_storage_lifecycle_execution_v1(
            request, method_matches, receiving, native_admission)?;
        let response = match original.observe_phase_v2(
            &mut self.0, receiving, &request.0, context.boot_id(), context.node_id()) {
            Ok(response) => response,
            Err(cause) => return Err(Self::unknown_domain(request, cause)),
        };
        self.finish_observed_success_with_storage_payer_v1(
            request, response, Some(StorageOutcomeReceivingV1::Lifecycle(receiving)))
    }
}
