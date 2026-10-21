//! Shares ordinary and actual same-F candidate dispatch through one terminal path.
//!
//! Only genuine authenticated requests enter the existing admission/sign/CAS
//! engines. The funded branch holds its actual lifecycle and retained Output
//! source through signing and every independently owed delivery observation.

use super::*;

impl DormantAuthenticatedBrokerSessionV1 {
    /// Observes the original Storage candidate before the same BSA terminal.
    pub(crate) fn execute_storage_capture_candidate_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        self.execute_storage_capture_candidate_shared_v1(
            request,
            CandidateDispatchV1::Ordinary { storage, output },
        )
    }

    pub(crate) fn execute_storage_capture_candidate_lifecycle_and_commit_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        native_admission: &mut Option<aos_sandbox_controller_domain::StorageReceivingClosedV1>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        self.execute_storage_capture_candidate_shared_v1(
            request,
            CandidateDispatchV1::Lifecycle {
                storage,
                output,
                receiving,
                native_admission,
            },
        )
    }

    fn execute_storage_capture_candidate_shared_v1(
        &mut self,
        request: DormantReceivedBrokerRequestV1,
        mut domain: CandidateDispatchV1<'_, '_, '_, '_>,
    ) -> Result<
        ProtectedBrokerOutcomeCommitResultV1,
        DormantBrokerExecutionFailureV1<aos_sandbox_storage::DormantStorageBrokerCallErrorV1>,
    > {
        let method_matches = request.method()
            == BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
            && request.authorization_artifacts().is_some();
        let (request, context) = match &mut domain {
            CandidateDispatchV1::Ordinary { .. } => {
                self.begin_execution(request, method_matches)?
            }
            CandidateDispatchV1::Lifecycle {
                receiving,
                native_admission,
                ..
            } => self.begin_storage_lifecycle_execution_v1(
                request,
                method_matches,
                receiving,
                native_admission,
            )?,
        };
        let version = ProtocolVersion::new(context.protocol_major(), context.protocol_minor());
        let boot = match aos_linux_descriptors::boot::KernelBootId::from_bytes(context.boot_id()) {
            Ok(boot) => boot,
            Err(error) => {
                let error = aos_sandbox_storage::StorageRuntimeError::from(
                    aos_sandbox_storage::ZfsWorkerError::Linux(error),
                );
                return Err(Self::unknown_domain(request, error.into()));
            }
        };
        let (response, receiving) = match domain {
            CandidateDispatchV1::Ordinary { storage, output } => {
                let response = match storage
                    .observe_original_capture_candidate_v1(output, &request.0, version, boot)
                {
                    Ok(response) => response,
                    Err(error) => return Err(Self::unknown_domain(request, error)),
                };
                if let Err(error) = storage.recheck_original_capture_candidate_v1(output, true) {
                    return Err(Self::unknown_domain(request, error));
                }
                (response, None)
            }
            CandidateDispatchV1::Lifecycle {
                storage,
                output,
                receiving,
                ..
            } => {
                let response = match self.0.consume_storage_capture_candidate_receiving_v1(
                    &request.0, storage, output, receiving, version, boot,
                ) {
                    Ok(response) => response,
                    Err(error) => return Err(Self::unknown_domain(request, error)),
                };
                if let Err(error) = self.0.recheck_storage_capture_candidate_receiving_v1(
                    storage, output, receiving, true,
                ) {
                    return Err(Self::unknown_domain(request, error));
                }
                (
                    response,
                    Some(StorageOutcomeReceivingV1::Lifecycle(receiving)),
                )
            }
        };
        self.finish_observed_success_with_storage_payer_v1(request, response, receiving)
    }
}

// Closed adapters preserve the actual ordinary or same-F domain ownership.
enum CandidateDispatchV1<'owner, 'loan, 'cut, 'original> {
    Ordinary {
        storage: &'owner mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &'owner aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    },
    Lifecycle {
        storage: &'owner mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &'owner mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &'loan mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>,
        native_admission: &'owner mut Option<aos_sandbox_controller_domain::StorageReceivingClosedV1>,
    },
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(crate) fn prepare_storage_capture_candidate_delivery_v1(
        &self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        self.0
            .prepare_storage_capture_candidate_delivery_v1(storage, output, receiving)
    }

    pub(crate) fn finish_storage_capture_candidate_delivery_v1(
        &self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        receiving: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
    ) -> Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1> {
        self.0
            .finish_storage_capture_candidate_delivery_v1(storage, output, receiving)
    }
}
