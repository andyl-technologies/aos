//! Lends only the actual Server Session and same F to historical Query61.

use super::*;

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn consume_storage_capture_query_lifecycle_v3(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<Vec<u8>, aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        let journal = self.owner.retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        receiving.receiving_domain_v1(journal, &self.socket)
            .map_err(|_| aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        storage.query_original_capture_ongoing_v3(request, output, receiving, journal, &self.socket);
        storage.original_capture_query_response_v3().map(<[u8]>::to_vec)
            .ok_or(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)
    }
}
