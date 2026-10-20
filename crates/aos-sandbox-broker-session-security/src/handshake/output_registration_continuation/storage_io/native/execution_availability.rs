//! Delegates shared IO only to genuine retained execution client borrowers.

use super::*;
use aos_sandbox::controller_execution_operation::ControllerExecutionAvailabilityClientLoanV2;

macro_rules! execution_client_native_member_v2 {
    ($loan:ty, $journal:ident, $stored:ident) => {
        impl NativeStorageIoV1 for $loan {
            type Failure = aos_sandbox::ResourceReservationErrorV1;
            type Disposal<'positive>
                = aos_sandbox::StorageProvisioningIoDisposalV1<'positive>
            where
                Self: 'positive;

            fn closed() -> Self::Failure {
                aos_sandbox::ResourceReservationErrorV1::Conflict
            }

            fn session_journal_v1<'session>(
                &self,
                owner: &'session ProtectedBrokerSessionOwnerV1,
            ) -> Result<&'session Journal, BrokerSessionSecurityError> {
                owner.$journal()
            }

            fn session_stored_v1<'session>(
                &self,
                owner: &'session ProtectedBrokerSessionOwnerV1,
            ) -> Result<&'session [u8], BrokerSessionSecurityError> {
                owner.$stored()
            }

            fn begin_send_once(
                &mut self,
                journal: &Journal,
                socket: &SeqpacketSocket,
                transcript: &VerifiedBrokerSessionTranscriptV1,
            ) -> Result<(), Self::Failure> {
                self.begin_send_once(journal, socket, transcript)
            }

            fn begin_wait_once(
                &mut self,
                journal: &Journal,
                socket: &SeqpacketSocket,
                transcript: &VerifiedBrokerSessionTranscriptV1,
                wants_write: bool,
            ) -> Result<(), Self::Failure> {
                self.begin_wait_once(journal, socket, transcript, wants_write)
            }

            fn observe_io_post_once(
                &mut self,
                journal: &Journal,
                socket: &SeqpacketSocket,
                transcript: &VerifiedBrokerSessionTranscriptV1,
            ) -> Result<(), Self::Failure> {
                self.observe_io_post_once(journal, socket, transcript)
            }

            fn original_cutoff_data_v1(&mut self) -> Result<u64, Self::Failure> {
                self.original_cutoff_data_v1()
            }

            fn finish_positive_io_once(&mut self) -> Result<(), Self::Failure> {
                self.finish_positive_io_once()
            }

            fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), Self::Failure> {
                self.admit_response_decode_once(packet)
            }

            fn admit_outcome_once(
                &mut self,
                stored: &[u8],
                request: &[u8],
                body: &[u8],
            ) -> Result<(), Self::Failure> {
                self.admit_outcome_once(stored, request, body)
            }

            fn prepare_pending_send_disposal_once<'positive>(
                &'positive mut self,
                receipt: &StorageSeqpacketSendAttemptV1,
                socket: &SeqpacketSocket,
            ) -> Result<Self::Disposal<'positive>, Self::Failure> {
                self.prepare_pending_send_disposal_once(receipt, socket)
            }

            fn prepare_positive_wait_disposal_once(
                &mut self,
            ) -> Result<Self::Disposal<'_>, Self::Failure> {
                self.prepare_positive_wait_disposal_once()
            }
        }
    };
}

pub(super) use execution_client_native_member_v2;

execution_client_native_member_v2!(
    ControllerExecutionAvailabilityClientLoanV2<'_>,
    execution_availability_client_journal_v2,
    execution_availability_client_stored_v2
);
