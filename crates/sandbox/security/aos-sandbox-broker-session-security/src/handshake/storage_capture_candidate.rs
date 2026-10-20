//! Binds actual Candidate source operations to the same paid Server Session.

use super::*;

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn consume_storage_capture_candidate_receiving_v1(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        version: aos_sandbox_model::ProtocolVersion,
        boot: aos_sandbox_linux::boot::KernelBootId,
    ) -> Result<Vec<u8>, aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        let journal = self
            .owner
            .retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        receiving
            .receiving_domain_v1(journal, &self.socket)
            .map_err(|_| aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        storage.observe_original_capture_candidate_receiving_v1(
            output,
            request,
            version,
            boot,
            receiving,
            journal,
            &self.socket,
        );
        storage
            .take_original_capture_candidate_response_receiving_v1()
            .ok_or(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)
    }

    pub(crate) fn recheck_storage_capture_candidate_receiving_v1(
        &self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        before_signing: bool,
    ) -> Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        let journal = self
            .owner
            .retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        storage.recheck_original_capture_candidate_receiving_v1(
            output,
            before_signing,
            receiving,
            journal,
            &self.socket,
        )
    }

    pub(crate) fn prepare_storage_capture_candidate_delivery_v1(
        &self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        let journal = self
            .owner
            .retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        storage.prepare_original_capture_candidate_delivery_v1(
            output,
            receiving,
            journal,
            &self.socket,
        )
    }

    pub(crate) fn finish_storage_capture_candidate_delivery_v1(
        &self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        let journal = self
            .owner
            .retained_storage_journal_v1()
            .map_err(|_| aos_sandbox_storage::DormantStorageBrokerCallErrorV1::StaleKernel)?;
        storage.finish_original_capture_candidate_delivery_v1(
            output,
            receiving,
            journal,
            &self.socket,
        )
    }
}
