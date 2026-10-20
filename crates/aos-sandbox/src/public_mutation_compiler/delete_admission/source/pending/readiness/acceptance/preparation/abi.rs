//! Adapts both closed public SDK ABIs to one actual upper loan driver.

use super::*;

macro_rules! common_abi {
    ($loan:ident, $native:ty, $completed_preparation_native_v3:ident, $complete_preparation_once_v3:ident, $prepay_preparation_entry_once_v3:ident, $preparation_request_bound_v3:ident, $require_preparation_contract_v3:ident, $preparation_header_data_v3:ident, $preparation_request_envelope_v3:ident, $require_preparation_request_v3:ident, $close_preparation_append_window_v3:ident, $retire_completed_preparation_append_once_v3:ident) => {
        impl $loan<'_> {
            /// Borrows the completed terminal after actual receipt and native posts.
            ///
            /// # Errors
            /// Retains changed custody, original horizons, funding or native failures.
            pub fn $completed_preparation_native_v3(&self) -> Result<&[u8; 64], Closed> {
                self.inner.completed_preparation_native_v3()
            }

            /// Completes the same C17 interval after actual Session-window retirement.
            ///
            /// # Errors
            /// Retains changed custody, original horizons, funding or native failures.
            pub fn $complete_preparation_once_v3(&mut self) -> Result<(), Closed> {
                self.inner.complete_preparation_once_v3()
            }

            /// Prepays the negotiated SDK representation before endpoint or native entry.
            ///
            /// # Errors
            /// Retains changed custody, original horizons, funding or native failures.
            pub fn $prepay_preparation_entry_once_v3(
                &mut self,
                shape: crate::StorageProvisioningSessionIoShapeDataV1,
            ) -> Result<(), Closed> {
                self.inner.prepay_preparation_entry_once_v3(shape)
            }

            pub(crate) fn io_original_v3(&mut self) -> &mut $native {
                &mut self.inner.state.io
            }

            pub(crate) fn native_turn_data_v3(&self) -> u64 {
                self.inner.native_turn_data_v3()
            }

            pub(crate) fn cutoff_data_v3(&self) -> u64 {
                self.inner.cutoff_data_v3()
            }

            /// Returns the held canonical request ceiling as passive sizing DATA.
            pub fn $preparation_request_bound_v3(&self) -> Option<usize> {
                self.inner.preparation_request_bound_v3()
            }

            pub(crate) fn require_current_v3(&mut self) -> Result<(), Closed> {
                self.inner.require_current_v3()
            }

            pub(crate) fn $require_preparation_contract_v3(&mut self) -> Result<(), Closed> {
                self.inner.require_preparation_contract_v3()
            }

            pub(crate) fn complete_base_native_v3(
                &mut self,
                incoming: ResourceVector,
            ) -> Result<ResourceVector, Closed> {
                self.inner.complete_base_native_v3(incoming)
            }

            pub(crate) fn require_prepared_complete_native_v3(
                &mut self,
                complete: ResourceVector,
            ) -> Result<(), Closed> {
                self.inner.require_prepared_complete_native_v3(complete)
            }

            pub(crate) fn require_session_association_v3(
                &self,
                journal: &Journal,
                socket: &SeqpacketSocket,
                transcript: &VerifiedBrokerSessionTranscriptV1,
            ) -> Result<(), Closed> {
                self.inner
                    .require_session_association_v3(journal, socket, transcript)
            }

            pub(crate) fn require_session_journal_v3(
                &self,
                journal: &Journal,
            ) -> Result<(), Closed> {
                self.inner.require_session_journal_v3(journal)
            }

            /// Copies the common header from the actual Root-signed request.
            ///
            /// # Errors
            /// Retains changed custody, original horizons, funding or native failures.
            pub fn $preparation_header_data_v3(&self) -> Result<RequestHeader, Closed> {
                self.inner.preparation_header_data_v3()
            }

            /// Copies the approved body and its four exact authorization artifacts.
            ///
            /// # Errors
            /// Retains changed custody, original horizons, funding or native failures.
            pub fn $preparation_request_envelope_v3(
                &self,
            ) -> Result<BrokerRequestEnvelope, Closed> {
                self.inner.preparation_request_envelope_v3()
            }

            pub(crate) fn $require_preparation_request_v3(
                &self,
                request: &AuthenticatedBrokerMethodRequestV1,
            ) -> Result<(), Closed> {
                self.inner.require_preparation_request_v3(request)
            }

            /// Closes the same primary without dropping an entered native append window.
            pub fn $close_preparation_append_window_v3(&self) {
                self.inner.close_preparation_append_window_v3()
            }

            /// Records the actual SDK refusal before independently owed posts.
            pub fn refuse_sdk_primary_v3(&mut self) {
                self.inner.refuse_sdk_primary_v3()
            }

            /// Runs the independently prepaid C17, Root and clock posts.
            ///
            /// # Errors
            /// Retains changed custody, original horizons, funding or native failures.
            pub fn finish_after_sdk_once_v3(&mut self) -> Result<(), Closed> {
                self.inner.finish_after_sdk_once_v3()
            }

            /// Retires the same finite native Session append window after upper posts.
            ///
            /// # Errors
            /// Retains changed custody, original horizons, funding or native failures.
            pub fn $retire_completed_preparation_append_once_v3(
                &mut self,
                journal: &mut Journal,
            ) -> Result<(), Closed> {
                self.inner
                    .retire_completed_preparation_append_once_v3(journal)
            }
        }
    };
}

common_abi!(
    OriginalDeleteStoragePreparationLoanV3,
    DeleteStoragePreparationIoOriginalV3,
    completed_preparation_native_v3,
    complete_preparation_once_v3,
    prepay_preparation_entry_once_v3,
    preparation_request_bound_v3,
    require_preparation_contract_v3,
    preparation_header_data_v3,
    preparation_request_envelope_v3,
    require_preparation_request_v3,
    close_preparation_append_window_v3,
    retire_completed_preparation_append_once_v3
);

common_abi!(
    OriginalDeleteStorageApplyLoanV3,
    DeleteStorageApplyIoOriginalV3,
    completed_apply_native_v3,
    complete_apply_once_v3,
    prepay_apply_entry_once_v3,
    apply_request_bound_v3,
    require_apply_contract_v3,
    apply_header_data_v3,
    apply_request_envelope_v3,
    require_apply_request_v3,
    close_apply_append_window_v3,
    retire_completed_apply_append_once_v3
);

common_abi!(
    OriginalDeleteNetworkApplyLoanV4,
    DeleteNetworkApplyIoOriginalV4,
    completed_network_native_v4,
    complete_network_once_v4,
    prepay_network_entry_once_v4,
    network_request_bound_v4,
    require_network_contract_v4,
    network_header_data_v4,
    network_request_envelope_v4,
    require_network_request_v4,
    close_network_append_window_v4,
    retire_completed_network_append_once_v4
);

common_abi!(
    OriginalDeleteMountReapLoanV4,
    DeleteMountReapIoOriginalV4,
    completed_mount_native_v4,
    complete_mount_once_v4,
    prepay_mount_entry_once_v4,
    mount_request_bound_v4,
    require_mount_contract_v4,
    mount_header_data_v4,
    mount_request_envelope_v4,
    require_mount_request_v4,
    close_mount_append_window_v4,
    retire_completed_mount_append_once_v4
);

impl OriginalDeleteMountReapLoanV4<'_> {
    /// Captures the actual retained signed/native Mount16 predecessor.
    ///
    /// # Errors
    /// Refuses a changed Session, complete owner cut or authenticated inventory.
    pub fn capture_mount_session_once_v4(
        &mut self, journal: &mut Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
        native: (u64, u64, u64, u64), protected: (u64, [u8; 32]),
    ) -> Result<(), Closed> {
        self.inner.capture_session_once_v3(journal, socket, transcript,
            inventory, CaptureData::Inventory { native, protected })
    }
}

impl OriginalDeleteNetworkApplyLoanV4<'_> {
    /// Captures the actual fresh signed/native Network Inventory predecessor.
    ///
    /// # Errors
    /// Refuses a changed Session, complete owner cut or authenticated Inventory.
    pub fn capture_network_session_once_v4(
        &mut self, journal: &mut Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
        native: (u64, u64, u64, u64), protected: (u64, [u8; 32]),
    ) -> Result<(), Closed> {
        self.inner.capture_session_once_v3(journal, socket, transcript,
            inventory, CaptureData::Inventory { native, protected })
    }
}

impl OriginalDeleteStoragePreparationLoanV3<'_> {
    /// Captures the actual fresh signed/native Storage Inventory predecessor.
    ///
    /// # Errors
    /// Retains any changed Session, native boundary or authenticated Inventory.
    pub fn capture_preparation_session_once_v3(
        &mut self,
        journal: &mut Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
        native: (u64, u64, u64, u64),
        protected: (u64, [u8; 32]),
    ) -> Result<(), Closed> {
        self.inner.capture_session_once_v3(
            journal,
            socket,
            transcript,
            inventory,
            CaptureData::Inventory { native, protected },
        )
    }
}

impl OriginalDeleteStorageApplyLoanV3<'_> {
    /// Joins SDK26 to the actual completed native26 owner retained in this loan.
    ///
    /// # Errors
    /// Retains changed exact request/outcome/native64, Session or live file custody.
    pub fn capture_apply_session_once_v3(
        &mut self,
        journal: &mut Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        native: [u8; 64],
    ) -> Result<(), Closed> {
        self.inner.capture_session_once_v3(
            journal,
            socket,
            transcript,
            outcome,
            CaptureData::Preparation(native),
        )
    }
}
