//! Adapts actual C8 Prepare turns to the existing retained Session IO engines.
//!
//! The distinct Native purpose owns U admission and original currentness. This
//! child retains concrete results, delegates the sole sender/receiver/wait and
//! always finishes the independent Root post after failure or real completion.

use super::*;
use aos_sandbox::{CreateStorageInventoryClosedV1, OriginalCreateStorageInventoryV1};
use super::super::storage_inventory::wait::InventoryWaitOriginalsV1;
use aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogResponse;
use buffa::Message as _;
use std::error::Error;

#[derive(Debug, thiserror::Error)]
#[error("Storage Prepare returned its authenticated terminal error {code:?}")]
pub(super) struct PrepareRejectedV1 {
    code: aos_proto::aos::sandbox::local::v1::BrokerErrorCode,
}

#[derive(Default)]
pub(super) struct CreatePrepareIoOriginalsV1 {
    pub(super) wait: InventoryWaitOriginalsV1,
    borrow: Option<Result<(), CreateStorageInventoryClosedV1>>,
    before: Option<Result<(), CreateStorageInventoryClosedV1>>,
    after: Option<Result<(), CreateStorageInventoryClosedV1>>,
    parked: Option<Result<(), CreateStorageInventoryClosedV1>>,
    predecessor_funding: Option<Result<(), CreateStorageInventoryClosedV1>>,
    pub(super) projection: Option<Result<(), BrokerSessionSecurityError>>,
    pub(super) rejected: Option<PrepareRejectedV1>,
    pub(super) response: Option<Result<PrepareStorageCatalogResponse, buffa::DecodeError>>,
    pub(super) predecessor_originals: Option<Box<crate::recovery::OutcomeCurrentOriginalsV1>>,
    pub(super) predecessor: Option<Result<(), BrokerSessionSecurityError>>,
    completion: Option<Result<(), CreateStorageInventoryClosedV1>>,
    root_after: Option<Result<(), CreateStorageInventoryClosedV1>>,
}

impl CreatePrepareIoOriginalsV1 {
    pub(super) fn native_failure(&self) -> Option<&(dyn Error + 'static)> {
        [&self.borrow, &self.before, &self.after, &self.parked, &self.predecessor_funding,
            &self.completion, &self.root_after].into_iter().find_map(|result|
                result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

// Selects only which existing private engine this fixed Session wrapper runs.
// It is not retained phase state or a public method/purpose/funding factory.
#[derive(Clone, Copy)]
enum PrepareIoTurnV1 { Send, Wait, Receive }

impl OriginalStorageCreatePreparationFlightV1 {
    fn require_io_entry(&mut self) -> bool {
        if self.use_first.is_some() || self.shared.inner.closed || self.complete
            || self.request_prepared != Some(true) || !matches!(self.request_finish, Some(Ok(()))) {
            self.close_use(UsePreparationFailureV1::Closed)
        } else { true }
    }

    pub(crate) fn send_request_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> StoragePreparationClientProgressV1 {
        self.advance_io_once(session, ready, PrepareIoTurnV1::Send)
    }

    pub(crate) fn wait_request_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        matches!(self.advance_io_once(session, ready, PrepareIoTurnV1::Wait),
            StoragePreparationClientProgressV1::Pending)
    }

    pub(crate) fn receive_request_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> StoragePreparationClientProgressV1 {
        self.advance_io_once(session, ready, PrepareIoTurnV1::Receive)
    }

    fn advance_io_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>, turn: PrepareIoTurnV1,
    ) -> StoragePreparationClientProgressV1 {
        if !self.require_io_entry() { return StoragePreparationClientProgressV1::Closed; }
        let progress = {
            let journal = match session.owner.retained_storage_client_journal_v1() {
                Ok(journal) => Some(journal),
                Err(cause) => {
                    self.shared.inner.protected_failure.get_or_insert(cause);
                    self.use_first.get_or_insert(UsePreparationFailureV1::IoShared);
                    None
                }
            };
            let original = journal.map(|journal| ready.borrow_original_storage_prepare_io_once(
                journal, &session.socket, &session.transcript));
            match original {
                Some(Ok(mut original)) => {
                    self.io.borrow = Some(Ok(()));
                    let primary = self.run_native_io_turn_once(session, &mut original, turn);
                    match primary {
                        Ok(progress) => {
                            if matches!(progress, StoragePreparationClientProgressV1::Pending | StoragePreparationClientProgressV1::Sent) {
                                self.io.parked = Some(original.park_original_storage_prepare_turn_once());
                                if !matches!(self.io.parked, Some(Ok(()))) {
                                    self.use_first.get_or_insert(UsePreparationFailureV1::IoNative);
                                }
                            }
                            if self.use_first.is_none() { progress }
                            else { StoragePreparationClientProgressV1::Closed }
                        }
                        Err(first) => {
                            self.use_first.get_or_insert(first);
                            StoragePreparationClientProgressV1::Closed
                        }
                    }
                }
                Some(Err(cause)) => {
                    self.io.borrow = Some(Err(cause));
                    self.use_first.get_or_insert(UsePreparationFailureV1::IoNative);
                    StoragePreparationClientProgressV1::Closed
                }
                None => StoragePreparationClientProgressV1::Closed,
            }
        };
        // The short native borrower ends before borrowing Ready for the one
        // independently owed Root completion. Pending keeps that whole scope.
        if matches!(progress, StoragePreparationClientProgressV1::Closed | StoragePreparationClientProgressV1::Committed) {
            if !self.finish_io_once(ready) { return StoragePreparationClientProgressV1::Closed; }
            self.complete = true;
        }
        progress
    }

    fn run_native_io_turn_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageInventoryV1<'_, '_, '_>, turn: PrepareIoTurnV1,
    ) -> Result<StoragePreparationClientProgressV1, UsePreparationFailureV1> {
        match turn {
            PrepareIoTurnV1::Send => super::super::storage_io::send_once(&mut self.shared, &mut self.io.wait,
                &mut self.io.before, &mut self.io.after, session, original).map_err(|cause| match cause {
                    super::super::storage_io::StorageIoFailureV1::Native => UsePreparationFailureV1::IoNative,
                    super::super::storage_io::StorageIoFailureV1::Wait => UsePreparationFailureV1::IoWait,
                    super::super::storage_io::StorageIoFailureV1::Shared => UsePreparationFailureV1::IoShared,
                }),
            PrepareIoTurnV1::Wait => {
                if self.io.wait.wait_original_once(session, &mut self.shared.inner, original) {
                    Ok(StoragePreparationClientProgressV1::Pending)
                } else { Err(UsePreparationFailureV1::IoWait) }
            }
            PrepareIoTurnV1::Receive => {
                let primary = self.receive_request_body_once(session, original);
                if matches!(primary, Ok(StoragePreparationClientProgressV1::Pending)) { return primary; }
                if let Err(first) = primary.as_ref() { self.use_first.get_or_insert(*first); }
                // Every entered receive/decode/CAS outcome owes the same native
                // post, including an earlier upper semantic/native failure.
                self.io.completion = Some(match session.owner.retained_storage_client_journal_v1() {
                    Ok(journal) => original.observe_terminal_post_once(journal, &session.socket, &session.transcript),
                    Err(cause) => {
                        self.shared.inner.protected_failure.get_or_insert(cause);
                        Err(CreateStorageInventoryClosedV1)
                    }
                });
                if !matches!(self.io.completion, Some(Ok(()))) {
                    self.use_first.get_or_insert(UsePreparationFailureV1::IoNative);
                }
                if primary.is_ok() && self.use_first.is_none() {
                    self.io.completion = Some(match session.owner.retained_storage_client_journal_v1() {
                        Ok(journal) => original.finish_after_authenticated_inventory_once(
                            journal, &session.socket, &session.transcript),
                        Err(cause) => {
                            self.shared.inner.protected_failure.get_or_insert(cause);
                            Err(CreateStorageInventoryClosedV1)
                        }
                    });
                    if !matches!(self.io.completion, Some(Ok(()))) {
                        self.use_first.get_or_insert(UsePreparationFailureV1::IoNative);
                    }
                }
                self.use_first.map_or(primary, Err)
            }
        }
    }

    fn receive_request_body_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        original: &mut OriginalCreateStorageInventoryV1<'_, '_, '_>,
    ) -> Result<StoragePreparationClientProgressV1, UsePreparationFailureV1> {
        if self.shared.pending.is_some() || self.io.wait.is_pending()
            || !matches!(self.shared.inner.sent, Some(Ok(()))) {
            return Err(UsePreparationFailureV1::IoShared);
        }
        self.io.before = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.begin_receive_once(journal, &session.socket, &session.transcript),
            Err(cause) => {
                self.shared.inner.protected_failure.get_or_insert(cause);
                return Err(UsePreparationFailureV1::IoShared);
            }
        });
        if !matches!(self.io.before, Some(Ok(()))) { return Err(UsePreparationFailureV1::IoNative); }
        let committed = self.shared.inner.receive_terminal_with_storage_io_v1(session, Some(original));
        if !committed && !self.shared.inner.closed && self.shared.inner.terminal_packet.is_nonconsuming_v1() {
            let receipt = match self.shared.inner.terminal_packet.received.as_ref() {
                Some(Err(receipt)) => receipt,
                _ => return Err(UsePreparationFailureV1::IoShared),
            };
            let disposal = original.prepare_pending_receive_disposal_once(receipt)
                .map_err(|_| UsePreparationFailureV1::IoNative)?;
            let old = std::mem::replace(&mut self.shared.inner.terminal_packet, OriginalOutputPacketV1::empty());
            drop(old);
            disposal.complete_after_receipt_disposal();
            self.shared.inner.inventory_io_post = None;
            self.io.before = None;
            if !self.io.wait.arm_receive() { return Err(UsePreparationFailureV1::IoWait); }
            return Ok(StoragePreparationClientProgressV1::Pending);
        }
        if !committed {
            return Err(if self.shared.inner.inventory_decode.as_ref().is_some_and(Result::is_err)
                || self.shared.inner.inventory_outcome.as_ref().is_some_and(Result::is_err) {
                UsePreparationFailureV1::IoNative
            } else { UsePreparationFailureV1::IoShared });
        }
        self.io.predecessor_funding = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => original.admit_retained_predecessor_once(journal),
            Err(cause) => {
                self.shared.inner.protected_failure.get_or_insert(cause);
                return Err(UsePreparationFailureV1::IoShared);
            }
        });
        if !matches!(self.io.predecessor_funding, Some(Ok(()))) { return Err(UsePreparationFailureV1::IoNative); }
        let terminal = match self.shared.inner.committed.as_ref() {
            Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal)) => terminal,
            _ => return Err(UsePreparationFailureV1::IoShared),
        };
        self.io.projection = Some(terminal.storage_prepare_client_originals_v1().map(|_| ()));
        let (outcome, currentness) = terminal.storage_prepare_client_originals_v1()
            .map_err(|_| UsePreparationFailureV1::IoProjection)?;
        let exact_body = match outcome.result() {
            aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
            aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Error(error) => {
                self.io.rejected = Some(PrepareRejectedV1 { code: error.code() });
                return Err(UsePreparationFailureV1::IoRejected);
            }
        };
        // The existing authenticated method validator already checked canonical
        // response meaning against the actual protected Prepare request. This
        // same paid body projection is retained for the later C9 original loan.
        self.io.response = Some(PrepareStorageCatalogResponse::decode(&mut exact_body.as_slice()));
        self.io.response.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(UsePreparationFailureV1::IoResponse)?;
        self.io.predecessor = Some(
            self.io.predecessor_originals
                .as_deref_mut()
                .ok_or(BrokerSessionSecurityError::Currentness)
                .and_then(|originals| session.owner
                    .compare_atomic_snapshot_predecessor_retaining_v1(
                        currentness, session.socket.peer(), originals,
                    )),
        );
        if !matches!(self.io.predecessor, Some(Ok(()))) { return Err(UsePreparationFailureV1::IoPredecessor); }
        Ok(StoragePreparationClientProgressV1::Committed)
    }

    fn finish_io_once(&mut self, ready: &mut aos_sandbox::OriginalCreateStorageReadyV1<'_, '_>) -> bool {
        self.io.root_after = Some(ready.finish_original_storage_prepare_io_once());
        if !matches!(self.io.root_after, Some(Ok(()))) {
            self.use_first.get_or_insert(UsePreparationFailureV1::IoNative);
        }
        if self.use_first.is_some() { self.shared.inner.closed = true; false } else { true }
    }
}
