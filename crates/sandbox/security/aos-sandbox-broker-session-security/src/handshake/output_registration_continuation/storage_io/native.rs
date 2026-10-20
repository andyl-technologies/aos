//! Seals shared IO dispatch to its actual closed native borrower types.
//!
//! The implementations only forward to existing closed methods. Neither a
//! decoded method nor a supplied resource vector can implement this private
//! interface or choose a different financial original.

use super::*;
use std::error::Error;
use std::os::fd::{AsFd, BorrowedFd};
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use crate::recovery::ProtectedBrokerSessionOwnerV1;
use aos_sandbox_controller_domain::{DeleteInventorySessionAppendOriginalV1, DeleteInventoryIoDisposalV1, Journal};
use aos_sandbox_linux::seqpacket::{RetainedSeqpacketReceiveErrorV1, StorageSeqpacketSendAttemptV1};

mod execution_availability;
mod execution_no_apply;

#[derive(Debug, thiserror::Error)]
pub(in crate::handshake::output_registration_continuation) enum StorageIoNativeFailureV1 {
    #[error(transparent)]
    Create(#[from] CreateStorageInventoryClosedV1),
    #[error(transparent)]
    Provisioning(#[from] aos_sandbox_controller_domain::ResourceReservationErrorV1),
    #[error(transparent)]
    Delete(#[from] aos_sandbox_controller_domain::JournalError),
}

pub(in crate::handshake::output_registration_continuation) trait NativeStorageIoDisposalV1 {
    fn complete_after_receipt_disposal(self);
    fn complete_after_wait_disposal(self);
}

impl NativeStorageIoDisposalV1 for aos_sandbox_controller_domain::CreateStorageInventoryPendingDisposalV1<'_, '_, '_, '_> {
    fn complete_after_receipt_disposal(self) {
        self.complete_after_receipt_disposal();
    }

    fn complete_after_wait_disposal(self) {
        self.complete_after_wait_disposal();
    }
}

impl NativeStorageIoDisposalV1 for DeleteInventoryIoDisposalV1<'_> {
    fn complete_after_receipt_disposal(self) {
        self.complete_after_receipt_disposal();
    }

    fn complete_after_wait_disposal(self) {
        self.complete_after_wait_disposal();
    }
}

pub(in crate::handshake::output_registration_continuation) trait NativeStorageIoV1 {
    type Failure: Error + Into<StorageIoNativeFailureV1> + 'static;
    type Disposal<'positive>: NativeStorageIoDisposalV1 where Self: 'positive;

    fn closed() -> Self::Failure;
    // Only Recover adds an external negative diagnostic marker. Existing
    // J/U/C17/C23 owners retain their unchanged chronological engines.
    fn mark_sdk_primary_before_post_v1(&mut self) {}

    // Existing zero-descriptor members keep their literal sender path. Only
    // the genuine Start loan can lend its same already-sealed preparation FD.
    fn preparation_descriptor_v4(&self)
        -> Result<Option<BorrowedFd<'_>>, Self::Failure>
    {
        Ok(None)
    }

    fn session_journal_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session Journal, BrokerSessionSecurityError>;
    fn session_stored_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session [u8], BrokerSessionSecurityError>;
    fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure>;
    fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool) -> Result<(), Self::Failure>;
    fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure>;
    fn original_cutoff_data_v1(&mut self) -> Result<u64, Self::Failure>;
    fn finish_positive_io_once(&mut self) -> Result<(), Self::Failure>;
    fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), Self::Failure>;
    fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8]) -> Result<(), Self::Failure>;
    fn prepare_pending_send_disposal_once<'positive>(&'positive mut self,
        receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket,
    ) -> Result<Self::Disposal<'positive>, Self::Failure>;
    fn prepare_positive_wait_disposal_once(&mut self)
        -> Result<Self::Disposal<'_>, Self::Failure>;
}

impl<'turn, 'original, 'cache> NativeStorageIoV1 for OriginalCreateStorageInventoryV1<'turn, 'original, 'cache> {
    type Failure = CreateStorageInventoryClosedV1;
    type Disposal<'positive> = aos_sandbox_controller_domain::CreateStorageInventoryPendingDisposalV1<'positive, 'turn, 'original, 'cache> where Self: 'positive;

    fn closed() -> Self::Failure { CreateStorageInventoryClosedV1 }

    fn session_journal_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session Journal, BrokerSessionSecurityError>
    {
        owner.retained_storage_client_journal_v1()
    }

    fn session_stored_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session [u8], BrokerSessionSecurityError>
    {
        owner.retained_storage_client_stored_v1()
    }

    fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure> {
        self.begin_send_once(journal, socket, transcript)
    }

    fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool) -> Result<(), Self::Failure> {
        self.begin_wait_once(journal, socket, transcript, wants_write)
    }

    fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure> {
        self.observe_io_post_once(journal, socket, transcript)
    }

    fn original_cutoff_data_v1(&mut self) -> Result<u64, Self::Failure> {
        OriginalCreateStorageInventoryV1::original_cutoff_data_v1(self)
    }

    fn finish_positive_io_once(&mut self) -> Result<(), Self::Failure> {
        self.finish_positive_io_once()
    }

    fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), Self::Failure> {
        self.admit_response_decode_once(packet)
    }

    fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8]) -> Result<(), Self::Failure> {
        self.admit_outcome_once(stored, request, body)
    }

    fn prepare_pending_send_disposal_once<'positive>(&'positive mut self,
        receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket,
    ) -> Result<Self::Disposal<'positive>, Self::Failure> {
        self.prepare_pending_send_disposal_once(receipt, socket)
    }

    fn prepare_positive_wait_disposal_once(&mut self)
        -> Result<Self::Disposal<'_>, Self::Failure>
    {
        self.prepare_positive_wait_disposal_once()
    }
}

impl<'turn, 'fence, 'journal, 'original, 'authorization, 'profile> NativeStorageIoV1 for DeleteInventorySessionAppendOriginalV1<'turn, 'fence, 'journal, 'original, 'authorization, 'profile> {
    type Failure = aos_sandbox_controller_domain::JournalError;
    type Disposal<'positive> = DeleteInventoryIoDisposalV1<'positive> where Self: 'positive;

    fn closed() -> Self::Failure { aos_sandbox_controller_domain::JournalError::ProtectedBoundary }

    fn session_journal_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session Journal, BrokerSessionSecurityError>
    {
        owner.delete_inventory_client_journal_v1()
    }

    fn session_stored_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session [u8], BrokerSessionSecurityError>
    {
        owner.delete_inventory_client_stored_v1()
    }

    fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure> {
        self.begin_send_once(journal, socket, transcript)
    }

    fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool) -> Result<(), Self::Failure> {
        self.begin_wait_once(journal, socket, transcript, wants_write)
    }

    fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure> {
        self.observe_io_post_once(journal, socket, transcript)
    }

    fn original_cutoff_data_v1(&mut self) -> Result<u64, Self::Failure> {
        DeleteInventorySessionAppendOriginalV1::original_cutoff_data_v1(self)
    }

    fn finish_positive_io_once(&mut self) -> Result<(), Self::Failure> {
        self.finish_positive_io_once()
    }

    fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), Self::Failure> {
        self.reserve_response_decode_once_v1(packet)
    }

    fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8]) -> Result<(), Self::Failure> {
        self.admit_outcome_once(stored, request, body)
    }

    fn prepare_pending_send_disposal_once<'positive>(&'positive mut self,
        receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket,
    ) -> Result<Self::Disposal<'positive>, Self::Failure> {
        self.prepare_pending_send_disposal_once(receipt, socket)
    }

    fn prepare_positive_wait_disposal_once(&mut self)
        -> Result<Self::Disposal<'_>, Self::Failure>
    {
        self.prepare_positive_wait_disposal_once()
    }
}


impl NativeStorageIoDisposalV1 for aos_sandbox_controller_domain::StorageProvisioningIoDisposalV1<'_> {
    fn complete_after_receipt_disposal(self) { self.complete_after_receipt_disposal(); }
    fn complete_after_wait_disposal(self) { self.complete_after_wait_disposal(); }
}

impl NativeStorageIoV1 for aos_sandbox_controller_domain::CreateProvisioningStorageIoLoanV1<'_> {
    type Failure = aos_sandbox_controller_domain::ResourceReservationErrorV1;
    type Disposal<'positive> = aos_sandbox_controller_domain::StorageProvisioningIoDisposalV1<'positive> where Self: 'positive;
    fn closed() -> Self::Failure { aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict }
    fn session_journal_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session Journal, BrokerSessionSecurityError> { owner.retained_storage_client_journal_v1() }
    fn session_stored_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session [u8], BrokerSessionSecurityError> { owner.retained_storage_client_stored_v1() }
    fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1)
        -> Result<(), Self::Failure> { self.begin_send_once(journal, socket, transcript) }
    fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool)
        -> Result<(), Self::Failure> { self.begin_wait_once(journal, socket, transcript, wants_write) }
    fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1)
        -> Result<(), Self::Failure> { self.observe_io_post_once(journal, socket, transcript) }
    fn original_cutoff_data_v1(&mut self) -> Result<u64, Self::Failure> { self.original_cutoff_data_v1() }
    fn finish_positive_io_once(&mut self) -> Result<(), Self::Failure> { self.finish_positive_io_once() }
    fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), Self::Failure> { self.admit_response_decode_once(packet) }
    fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8]) -> Result<(), Self::Failure> {
        self.admit_outcome_once(stored, request, body)
    }
    fn prepare_pending_send_disposal_once<'positive>(&'positive mut self, receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket)
        -> Result<Self::Disposal<'positive>, Self::Failure> { self.prepare_pending_send_disposal_once(receipt, socket) }
    fn prepare_positive_wait_disposal_once(&mut self) -> Result<Self::Disposal<'_>, Self::Failure> {
        self.prepare_positive_wait_disposal_once()
    }
}

impl<'query, 'owner, 'controller, 'seed, 'completed> NativeStorageIoV1 for aos_sandbox_controller_domain::ControllerRecoveryInventoryLoanV2<'query, 'owner, 'controller, 'seed, 'completed> {
    type Failure = aos_sandbox_controller_domain::JournalError;
    type Disposal<'positive> = aos_sandbox_controller_domain::DeleteInventoryIoDisposalV1<'positive> where Self: 'positive;

    fn closed() -> Self::Failure { aos_sandbox_controller_domain::JournalError::ProtectedBoundary }
    fn mark_sdk_primary_before_post_v1(&mut self) { self.mark_primary_refused_v1(); }
    fn session_journal_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1) -> Result<&'session Journal, BrokerSessionSecurityError> {
        if self.is_operator_recover_storage_data_v2() { owner.operator_recover_inventory_journal_v1() }
        else { owner.reconciliation_inventory_client_journal_v2(self.method_data_v2()) }
    }
    fn session_stored_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1) -> Result<&'session [u8], BrokerSessionSecurityError> {
        if self.is_operator_recover_storage_data_v2() { owner.operator_recover_inventory_stored_v1() }
        else { owner.reconciliation_inventory_client_stored_v2(self.method_data_v2()) }
    }
    fn begin_send_once(&mut self, j: &Journal, s: &SeqpacketSocket, t: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure> { self.begin_send_once(j, s, t) }
    fn begin_wait_once(&mut self, j: &Journal, s: &SeqpacketSocket, t: &VerifiedBrokerSessionTranscriptV1, w: bool) -> Result<(), Self::Failure> { self.begin_wait_once(j, s, t, w) }
    fn observe_io_post_once(&mut self, j: &Journal, s: &SeqpacketSocket, t: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure> { self.observe_io_post_once(j, s, t) }
    fn original_cutoff_data_v1(&mut self) -> Result<u64, Self::Failure> { aos_sandbox_controller_domain::ControllerRecoveryInventoryLoanV2::original_cutoff_data_v1(self) }
    fn finish_positive_io_once(&mut self) -> Result<(), Self::Failure> { self.finish_positive_io_once() }
    fn admit_response_decode_once(&mut self, packet: &[u8]) -> Result<(), Self::Failure> { self.admit_response_decode_once(packet) }
    fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8]) -> Result<(), Self::Failure> { self.admit_outcome_once(stored, request, body) }
    fn prepare_pending_send_disposal_once<'positive>(&'positive mut self, receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket) -> Result<Self::Disposal<'positive>, Self::Failure> { self.prepare_pending_send_disposal_once(receipt, socket) }
    fn prepare_positive_wait_disposal_once(&mut self) -> Result<Self::Disposal<'_>, Self::Failure> { self.prepare_positive_wait_disposal_once() }
}

impl NativeStorageIoV1 for aos_sandbox_controller_domain::StartResourceProvisioningIoLoanV2<'_> {
    type Failure = aos_sandbox_controller_domain::ResourceReservationErrorV1;
    type Disposal<'positive> = aos_sandbox_controller_domain::StorageProvisioningIoDisposalV1<'positive>
    where
        Self: 'positive;

    fn closed() -> Self::Failure {
        aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict
    }

    fn preparation_descriptor_v4(&self)
        -> Result<Option<BorrowedFd<'_>>, Self::Failure>
    {
        self.borrow_preparation_content_descriptor_v2()
            .map(|content| content.map(|credential| credential.as_fd()))
    }

    fn session_journal_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session Journal, BrokerSessionSecurityError>
    {
        owner.start_resource_journal_v4()
    }

    fn session_stored_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session [u8], BrokerSessionSecurityError>
    {
        owner.start_resource_stored_v4()
    }

    fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure>
    {
        self.begin_send_once(journal, socket, transcript)
    }

    fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool,
    ) -> Result<(), Self::Failure> {
        self.begin_wait_once(journal, socket, transcript, wants_write)
    }

    fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure>
    {
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

    fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8])
        -> Result<(), Self::Failure>
    {
        self.admit_outcome_once(stored, request, body)
    }

    fn prepare_pending_send_disposal_once<'positive>(&'positive mut self,
        receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket,
    ) -> Result<Self::Disposal<'positive>, Self::Failure> {
        self.prepare_pending_send_disposal_once(receipt, socket)
    }

    fn prepare_positive_wait_disposal_once(&mut self)
        -> Result<Self::Disposal<'_>, Self::Failure>
    {
        self.prepare_positive_wait_disposal_once()
    }
}

impl NativeStorageIoV1 for aos_sandbox_controller_domain::StartHostCatalogIoLoanV2<'_> {
    type Failure = aos_sandbox_controller_domain::ResourceReservationErrorV1;
    type Disposal<'positive> = aos_sandbox_controller_domain::StorageProvisioningIoDisposalV1<'positive>
    where
        Self: 'positive;

    fn closed() -> Self::Failure {
        aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict
    }

    fn preparation_descriptor_v4(&self)
        -> Result<Option<BorrowedFd<'_>>, Self::Failure>
    {
        self.borrow_catalog_descriptor_v2().map(|credential| Some(credential.as_fd()))
    }

    fn session_journal_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session Journal, BrokerSessionSecurityError>
    {
        owner.start_resource_journal_v4()
    }

    fn session_stored_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session [u8], BrokerSessionSecurityError>
    {
        owner.start_resource_stored_v4()
    }

    fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure>
    {
        self.begin_send_once(journal, socket, transcript)
    }

    fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool,
    ) -> Result<(), Self::Failure> {
        self.begin_wait_once(journal, socket, transcript, wants_write)
    }

    fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure>
    {
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

    fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8])
        -> Result<(), Self::Failure>
    {
        self.admit_outcome_once(stored, request, body)
    }

    fn prepare_pending_send_disposal_once<'positive>(&'positive mut self,
        receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket,
    ) -> Result<Self::Disposal<'positive>, Self::Failure> {
        self.prepare_pending_send_disposal_once(receipt, socket)
    }

    fn prepare_positive_wait_disposal_once(&mut self)
        -> Result<Self::Disposal<'_>, Self::Failure>
    {
        self.prepare_positive_wait_disposal_once()
    }
}

macro_rules! delete_storage_native_member {
    ($loan:ident, $journal:ident, $stored:ident $(, $refusal:ident)?) => {
        impl NativeStorageIoV1 for aos_sandbox_controller_domain::$loan<'_> {
            type Failure = aos_sandbox_controller_domain::ResourceReservationErrorV1;
            type Disposal<'positive>
                = aos_sandbox_controller_domain::StorageProvisioningIoDisposalV1<'positive>
            where
                Self: 'positive;
            fn closed() -> Self::Failure {
                aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict
            }
            fn mark_sdk_primary_before_post_v1(&mut self) {
                $(self.$refusal();)?
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
            fn prepare_positive_wait_disposal_once(&mut self) -> Result<Self::Disposal<'_>, Self::Failure> {
                self.prepare_positive_wait_disposal_once()
            }
        }

    };
}

delete_storage_native_member!(OriginalDeleteStoragePreparationLoanV3, retained_storage_client_journal_v1, retained_storage_client_stored_v1);
delete_storage_native_member!(OriginalDeleteStorageApplyLoanV3, retained_storage_client_journal_v1, retained_storage_client_stored_v1);
delete_storage_native_member!(OriginalDeleteNetworkApplyLoanV4, delete_inventory_client_journal_v1, delete_inventory_client_stored_v1);
delete_storage_native_member!(OriginalDeleteMountReapLoanV4, delete_inventory_client_journal_v1, delete_inventory_client_stored_v1);
delete_storage_native_member!(ControllerMaintenanceStorageIoLoanV3, retained_storage_client_journal_v1, retained_storage_client_stored_v1, retain_storage_sdk_refusal_once_v3);

impl NativeStorageIoV1 for aos_sandbox_controller_domain::ControllerCatalogMaintenanceIoLoanV2<'_> {
    type Failure = aos_sandbox_controller_domain::ResourceReservationErrorV1;
    type Disposal<'positive> = aos_sandbox_controller_domain::StorageProvisioningIoDisposalV1<'positive>
    where
        Self: 'positive;

    fn closed() -> Self::Failure {
        aos_sandbox_controller_domain::ResourceReservationErrorV1::Conflict
    }

    fn mark_sdk_primary_before_post_v1(&mut self) {
        self.retain_catalog_sdk_refusal_once_v2();
    }

    fn preparation_descriptor_v4(&self)
        -> Result<Option<BorrowedFd<'_>>, Self::Failure>
    {
        self.borrow_catalog_descriptor_v2().map(|credential| Some(credential.as_fd()))
    }

    fn session_journal_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session Journal, BrokerSessionSecurityError>
    {
        owner.catalog_maintenance_client_journal_v2()
    }

    fn session_stored_v1<'session>(&self, owner: &'session ProtectedBrokerSessionOwnerV1)
        -> Result<&'session [u8], BrokerSessionSecurityError>
    {
        owner.catalog_maintenance_client_stored_v2()
    }

    fn begin_send_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure>
    {
        self.begin_send_once(journal, socket, transcript)
    }

    fn begin_wait_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1, wants_write: bool,
    ) -> Result<(), Self::Failure> {
        self.begin_wait_once(journal, socket, transcript, wants_write)
    }

    fn observe_io_post_once(&mut self, journal: &Journal, socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), Self::Failure>
    {
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

    fn admit_outcome_once(&mut self, stored: &[u8], request: &[u8], body: &[u8])
        -> Result<(), Self::Failure>
    {
        self.admit_outcome_once(stored, request, body)
    }

    fn prepare_pending_send_disposal_once<'positive>(&'positive mut self,
        receipt: &StorageSeqpacketSendAttemptV1, socket: &SeqpacketSocket,
    ) -> Result<Self::Disposal<'positive>, Self::Failure> {
        self.prepare_pending_send_disposal_once(receipt, socket)
    }

    fn prepare_positive_wait_disposal_once(&mut self)
        -> Result<Self::Disposal<'_>, Self::Failure>
    {
        self.prepare_positive_wait_disposal_once()
    }
}
