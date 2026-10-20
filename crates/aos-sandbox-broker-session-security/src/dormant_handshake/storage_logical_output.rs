//! Runs the shared logical46/47 driver on the real paid Session Domain.

use super::*;
use crate::production_service::StorageOutputLifecycleOriginalV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn reserve_storage_output_front_v1(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        demand: aos_sandbox_core::ResourceVector,
    ) -> Result<(), BrokerSessionSecurityError> {
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || !matches!(
                request.method(),
                BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
            )
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.0.reserve_storage_output_domain_additional_v1(receiving, demand)
    }

    pub(crate) fn execute_storage_logical_output_lifecycle_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        original: &mut StorageOutputLifecycleOriginalV1,
        receiving: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox::StorageReceivingClosedV1>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        let selected = matches!(
            request.0.method(),
            BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
                | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1
        ) && request.0.authorization().is_some();
        let (request, _) = if selected {
            self.begin_storage_lifecycle_execution_v1(
                request,
                selected,
                receiving,
                native_admission,
            )?
        } else {
            self.begin_execution(request, selected)?
        };
        original.advance(self, &request.0, storage, output, receiving);
        let Some(response) = original.response() else {
            return Err(Self::unknown_domain(
                request,
                aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel,
            ));
        };
        self.finish_observed_success_with_storage_payer_v1(
            request,
            response.to_vec(),
            Some(StorageOutcomeReceivingV1::Lifecycle(receiving)),
        )
    }
}
