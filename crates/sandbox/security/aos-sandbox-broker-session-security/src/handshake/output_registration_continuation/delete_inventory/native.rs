//! Seals the common Inventory query to its genuine Delete or Recover original.
//!
//! These forwards mint nothing. Each closed native constructor has already
//! joined its actual source/C loan, Session opening, profile and original cutoff.

use super::*;
use aos_sandbox_controller_domain::{Journal, OperatorRecoverInventoryLoanV1};
use aos_sandbox_linux::seqpacket::{SeqpacketSocket, RetainedSeqpacketReceiveErrorV1};
use crate::recovery::{ProtectedBrokerSessionOwnerV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1, OutcomeCurrentOriginalsV1};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_linux::seqpacket::ConnectionPeerIdentity;

type FinancialView<'cause> = aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>;

pub(super) trait ControllerInventoryCompletionV1 {
    fn completed_boundary_data_v2(&self) -> (u64, u64, u64, u64);

    fn completed_native_position_data_v4(&self) -> Option<[u8; 64]> { None }

    fn complete_after_upper_disposal_v1(self);
}

impl ControllerInventoryCompletionV1 for aos_sandbox_controller_domain::DeleteInventorySessionAppendDisposalV1<'_> {
    fn completed_native_position_data_v4(&self) -> Option<[u8; 64]> {
        Some(*self.completed_native_position_data_v4())
    }

    fn completed_boundary_data_v2(&self) -> (u64, u64, u64, u64) { self.completed_boundary_data_v2() }

    fn complete_after_upper_disposal_v1(self) { self.complete_after_upper_disposal_v1(); }
}

impl ControllerInventoryCompletionV1 for aos_sandbox_controller_domain::OperatorRecoverInventoryDisposalV1<'_> {
    fn completed_boundary_data_v2(&self) -> (u64, u64, u64, u64) { self.completed_boundary_data_v2() }

    fn complete_after_upper_disposal_v1(self) { self.complete_after_upper_disposal_v1(); }
}

pub(super) trait ControllerInventoryNativeV1: NativeStorageIoV1<Failure = JournalError> {
    fn inventory_method_data_v2(&self) -> Option<BrokerMethod> { None }

    type Completion<'positive>: ControllerInventoryCompletionV1 where Self: 'positive;

    fn outer_construction_bytes_v1() -> Result<usize, JournalError>;

    fn require_security_construction_once_v1(&mut self, shape: DeleteInventorySecurityShapeDataV1) -> Result<(), JournalError>;

    fn session_journal_mut_v1<'session>(&self, owner: &'session mut ProtectedBrokerSessionOwnerV1) -> Result<&'session mut Journal, BrokerSessionSecurityError>;

    fn capture_session_once_v1(&mut self, journal: &mut Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError>;

    fn begin_request_preparation_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError>;

    fn begin_receive_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError>;

    fn coordinates_v1(&self, session: &DormantAuthenticatedBrokerSessionV1) -> Result<crate::dormant_handshake::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError>;

    fn prepare_pending_receive_disposal_once(&mut self, receipt: &RetainedSeqpacketReceiveErrorV1) -> Result<Self::Disposal<'_>, JournalError>;

    fn admit_retained_predecessor_once(&mut self, journal: &Journal) -> Result<(), JournalError>;

    fn committed_originals_v1<'terminal>(&self, terminal: &'terminal ProtectedBrokerOutcomeCommittedAdvancementV1, owner: &ProtectedBrokerSessionOwnerV1) -> Result<(&'terminal AuthenticatedBrokerMethodOutcomeV1, &'terminal ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError>;

    fn compare_predecessor_v1(&mut self, owner: &mut ProtectedBrokerSessionOwnerV1, currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity, originals: &mut OutcomeCurrentOriginalsV1) -> Result<(), BrokerSessionSecurityError>;

    fn finish_native_once_v1(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError>;

    fn mark_primary_refused_v1(&mut self);

    fn prepare_positive_disposal_v1<'positive>(&'positive mut self, journal: &'positive mut Journal) -> Result<Self::Completion<'positive>, JournalError>;

    fn local_failure_v1(&self) -> Option<&(dyn Error + 'static)>;

    fn controller_failure_view_v1(&self) -> Option<FinancialView<'_>>;

    fn finish_outer_source_failure_once_v1(&mut self) -> Result<(), JournalError>;
}

impl<'turn, 'fence, 'journal, 'original, 'authorization, 'profile> ControllerInventoryNativeV1 for DeleteInventorySessionAppendOriginalV1<'turn, 'fence, 'journal, 'original, 'authorization, 'profile> {
    type Completion<'positive> = aos_sandbox_controller_domain::DeleteInventorySessionAppendDisposalV1<'positive> where Self: 'positive;

    fn outer_construction_bytes_v1() -> Result<usize, JournalError> {
        size_of::<crate::dormant_handshake::OriginalDeleteInventoryClientV1<'_, '_, '_, '_, '_, '_>>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(3 * size_of::<DeleteInventoryAnswerOriginalsV1>()))
            .and_then(|bytes| bytes.checked_add(3 * size_of::<DeleteInventoryNegotiatedPreimagesV2<'_>>()))
            .ok_or(JournalError::LimitExceeded("Delete Inventory upper owner"))
    }

    fn require_security_construction_once_v1(&mut self, shape: DeleteInventorySecurityShapeDataV1) -> Result<(), JournalError> { self.require_security_construction_once_v1(shape) }

    fn session_journal_mut_v1<'session>(&self, owner: &'session mut ProtectedBrokerSessionOwnerV1) -> Result<&'session mut Journal, BrokerSessionSecurityError> { owner.delete_inventory_client_journal_mut_v1() }

    fn capture_session_once_v1(&mut self, journal: &mut Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.capture_session_once_v1(journal, socket, transcript) }

    fn begin_request_preparation_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.begin_request_preparation_once(journal, socket, transcript) }

    fn begin_receive_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.begin_receive_once(journal, socket, transcript) }

    fn coordinates_v1(&self, session: &DormantAuthenticatedBrokerSessionV1) -> Result<crate::dormant_handshake::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> { crate::dormant_handshake::delete_inventory_coordinates_v1(session, self) }

    fn prepare_pending_receive_disposal_once(&mut self, receipt: &RetainedSeqpacketReceiveErrorV1) -> Result<Self::Disposal<'_>, JournalError> { self.prepare_pending_receive_disposal_once(receipt) }

    fn admit_retained_predecessor_once(&mut self, journal: &Journal) -> Result<(), JournalError> { self.admit_retained_predecessor_once(journal) }

    fn committed_originals_v1<'terminal>(&self, terminal: &'terminal ProtectedBrokerOutcomeCommittedAdvancementV1, owner: &ProtectedBrokerSessionOwnerV1) -> Result<(&'terminal AuthenticatedBrokerMethodOutcomeV1, &'terminal ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> { terminal.delete_inventory_client_originals_v1(owner) }

    fn compare_predecessor_v1(&mut self, owner: &mut ProtectedBrokerSessionOwnerV1, currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity, originals: &mut OutcomeCurrentOriginalsV1) -> Result<(), BrokerSessionSecurityError> { owner.compare_delete_inventory_predecessor_retaining_v1(currentness, peer, originals) }

    fn finish_native_once_v1(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.finish_native_once_v1(journal, socket, transcript) }

    fn mark_primary_refused_v1(&mut self) { self.mark_primary_refused_v1(); }

    fn prepare_positive_disposal_v1<'positive>(&'positive mut self, journal: &'positive mut Journal) -> Result<Self::Completion<'positive>, JournalError> { self.prepare_positive_disposal_v1(journal) }

    fn local_failure_v1(&self) -> Option<&(dyn Error + 'static)> { self.local_failure_v1() }

    fn controller_failure_view_v1(&self) -> Option<FinancialView<'_>> { self.controller_failure_view_v1() }

    fn finish_outer_source_failure_once_v1(&mut self) -> Result<(), JournalError> { self.finish_outer_source_failure_once_v1() }
}

impl<'query, 'owner, 'controller, 'seed, 'completed> ControllerInventoryNativeV1 for aos_sandbox_controller_domain::ControllerRecoveryInventoryLoanV2<'query, 'owner, 'controller, 'seed, 'completed> {
    fn inventory_method_data_v2(&self) -> Option<BrokerMethod> { Some(self.method_data_v2()) }

    type Completion<'positive> = aos_sandbox_controller_domain::OperatorRecoverInventoryDisposalV1<'positive> where Self: 'positive;

    fn outer_construction_bytes_v1() -> Result<usize, JournalError> {
        size_of::<crate::dormant_handshake::OperatorRecoverStorageInventoryOriginalV1>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(3 * size_of::<DeleteInventoryAnswerOriginalsV1>()))
            .and_then(|bytes| bytes.checked_add(3 * size_of::<DeleteInventoryNegotiatedPreimagesV2<'_>>()))
            .ok_or(JournalError::LimitExceeded("Controller Inventory upper owner"))
    }

    fn require_security_construction_once_v1(&mut self, shape: DeleteInventorySecurityShapeDataV1) -> Result<(), JournalError> { self.require_security_construction_once_v1(shape) }

    fn session_journal_mut_v1<'session>(&self, owner: &'session mut ProtectedBrokerSessionOwnerV1) -> Result<&'session mut Journal, BrokerSessionSecurityError> { if self.is_operator_recover_storage_data_v2() { owner.operator_recover_inventory_journal_mut_v1() }
        else { owner.reconciliation_inventory_client_journal_mut_v2(self.method_data_v2()) } }

    fn capture_session_once_v1(&mut self, journal: &mut Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.capture_session_once_v1(journal, socket, transcript) }

    fn begin_request_preparation_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.begin_request_preparation_once(journal, socket, transcript) }

    fn begin_receive_once(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.begin_receive_once(journal, socket, transcript) }

    fn coordinates_v1(&self, session: &DormantAuthenticatedBrokerSessionV1) -> Result<crate::dormant_handshake::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> { crate::dormant_handshake::operator_recover_inventory_coordinates_v1(session, self) }

    fn prepare_pending_receive_disposal_once(&mut self, receipt: &RetainedSeqpacketReceiveErrorV1) -> Result<Self::Disposal<'_>, JournalError> { self.prepare_pending_receive_disposal_once(receipt) }

    fn admit_retained_predecessor_once(&mut self, journal: &Journal) -> Result<(), JournalError> { self.admit_retained_predecessor_once(journal) }

    fn committed_originals_v1<'terminal>(&self, terminal: &'terminal ProtectedBrokerOutcomeCommittedAdvancementV1, owner: &ProtectedBrokerSessionOwnerV1) -> Result<(&'terminal AuthenticatedBrokerMethodOutcomeV1, &'terminal ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> { if self.is_operator_recover_storage_data_v2() { terminal.operator_recover_inventory_originals_v1(owner) }
        else { terminal.reconciliation_inventory_client_originals_v2(owner, self.method_data_v2()) } }

    fn compare_predecessor_v1(&mut self, owner: &mut ProtectedBrokerSessionOwnerV1, currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity, originals: &mut OutcomeCurrentOriginalsV1) -> Result<(), BrokerSessionSecurityError> { if self.is_operator_recover_storage_data_v2() { owner.compare_operator_recover_inventory_retaining_v1(currentness, peer, originals) }
        else { owner.compare_reconciliation_inventory_predecessor_retaining_v2(currentness, peer, originals, self.method_data_v2()) } }

    fn finish_native_once_v1(&mut self, journal: &Journal, socket: &SeqpacketSocket, transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), JournalError> { self.finish_native_once_v1(journal, socket, transcript) }

    fn mark_primary_refused_v1(&mut self) { self.mark_primary_refused_v1(); }

    fn prepare_positive_disposal_v1<'positive>(&'positive mut self, journal: &'positive mut Journal) -> Result<Self::Completion<'positive>, JournalError> { self.prepare_positive_disposal_v1(journal) }

    fn local_failure_v1(&self) -> Option<&(dyn Error + 'static)> { self.failure_v1() }

    fn controller_failure_view_v1(&self) -> Option<FinancialView<'_>> { None }

    fn finish_outer_source_failure_once_v1(&mut self) -> Result<(), JournalError> {
        // The enclosing Recover original owns the independent Source/C posts.
        // This failure-only path cannot finish or substitute those outer posts.
        self.mark_primary_refused_v1();
        Err(JournalError::ProtectedBoundary)
    }
}
