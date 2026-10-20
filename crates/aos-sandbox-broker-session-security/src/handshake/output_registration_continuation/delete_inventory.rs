//! Runs the sole Delete query kernel on each borrowed outer-owned Session.
//!
//! Planning and preaccept reach this same engine through distinct native
//! constructors. The request ID and cutoff come from that native association;
//! the fixed endpoint chooses the method. No answer escapes before the final
//! independent C/profile/Session posts and actual positive native disposition.

use super::*;
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointV1;
use std::error::Error;
use std::mem::size_of;
use aos_sandbox::{DeleteInventorySecurityShapeDataV1, DeleteInventorySessionAppendOriginalV1, JournalError};
use aos_proto::aos::sandbox::local::v1::{
    InventoryDestinationSlotsRequest, InventoryNetworksRequest, InventoryRuntimeRequest,
    InventoryRuntimeResponse, InventoryStorageRequest, InventoryStorageResourcesResponse,
};
use aos_sandbox_protocol::{ValidatedDestinationSlotInventory, ValidatedNetworkInventory, ValidatedStorageInventory};
use buffa::Message as _;

pub use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::
    ControllerInventoryModelDataV2 as DeleteInventoryModelV1;
use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2;

#[derive(Clone, Copy)]
enum First {
    Capture,
    Preparation,
    Shared,
    Send,
    Receive,
    Wait,
    PredecessorAdmission,
    Projection,
    Model,
    Predecessor,
    WitnessPost,
    Final,
    Disposal,
    Reentry,
}

/// Retains all entered query originals beside the genuine C17 native guard.
///
/// The purpose-closed outer owner retains the whole Session and lends its inner
/// only for these named turns. This kernel's first native field refuses negative
/// abandonment before the outer Session or any request/raw owner can drop.
#[doc(hidden)]
#[must_use = "retain the whole negative query and same Session through all owed posts"]
pub(crate) type DeleteInventoryClientKernelV1<
    'turn, 'fence, 'journal, 'original, 'authorization, 'profile,
> = ControllerInventoryClientKernelV1<DeleteInventorySessionAppendOriginalV1<
    'turn, 'fence, 'journal, 'original, 'authorization, 'profile>>;

/// Holds the same byte/native query algorithm behind two sealed genuine lenders.
/// The retained SDK state can move back beside Recover's inline native original
/// before the short loan ends; no entered request or native result is discarded.
pub(crate) struct ControllerInventoryClientKernelV1<N: native::ControllerInventoryNativeV1> {
    native: N,
    original: ControllerInventoryQueryOriginalsV1,
}

pub(crate) struct ControllerInventoryQueryOriginalsV1 {
    shared: OriginalStoragePreparationClientFlightV1,
    wait: storage_inventory::wait::InventoryWaitOriginalsV1<JournalError>,
    capture: Option<Result<(), JournalError>>,
    preparation: Option<Result<(), JournalError>>,
    preparation_post: Option<Result<(), JournalError>>,
    unsigned: Option<BrokerRequestEnvelope>,
    send_before: Option<Result<(), JournalError>>,
    send_after: Option<Result<(), JournalError>>,
    receive_before: Option<Result<(), JournalError>>,
    predecessor_admission: Option<Result<(), JournalError>>,
    projection: Option<Result<(), BrokerSessionSecurityError>>,
    model: Option<Result<ControllerInventoryDecodedOriginalV2, ProtocolValidationError>>,
    predecessor_originals: crate::recovery::OutcomeCurrentOriginalsV1,
    predecessor: Option<Result<(), BrokerSessionSecurityError>>,
    witness_post: Option<Result<(), super::super::HandshakeError>>,
    final_post: Option<Result<(), JournalError>>,
    disposal: Option<Result<(), JournalError>>,
    first: Option<First>,
    reentry: Option<OutputPreparationClosedV1>,
    prepared: bool,
    received: bool,
}

mod native;
use native::{ControllerInventoryNativeV1, ControllerInventoryCompletionV1};
use super::storage_io::{NativeStorageIoV1, NativeStorageIoDisposalV1};

impl<N: ControllerInventoryNativeV1> ControllerInventoryClientKernelV1<N> {
    /// Describes this exact concrete owner before native construction or IO.
    ///
    /// The genuine native planning/preaccept constructor must admit this DATA;
    /// it independently adds the fixed raw receiver and native name frontier.
    ///
    /// # Errors
    /// Refuses compiled size arithmetic overflow.
    pub(crate) fn security_shape_v1() -> Result<DeleteInventorySecurityShapeDataV1, JournalError> {
        let (currentness, _) = crate::recovery::OutcomeCurrentOriginalsV1::receiving_footprint_v1()
            .ok_or(JournalError::LimitExceeded("Delete Inventory predecessor originals"))?;
        let process = super::super::storage_process_evidence_footprint_v1()
            .ok_or(JournalError::LimitExceeded("Delete Inventory process witnesses"))?;
        let wait = storage_inventory::wait::InventoryWaitOriginalsV1::<JournalError>::
            receiving_construction_bytes_v1().ok_or(JournalError::LimitExceeded("Delete Inventory readiness"))?;
        Ok(DeleteInventorySecurityShapeDataV1 {
            construction_bytes: N::outer_construction_bytes_v1()?,
            backing_bytes: currentness.checked_add(wait)
                .ok_or(JournalError::LimitExceeded("Delete Inventory backing"))?,
            retained_endpoint_files: crate::recovery::OutcomeCurrentOriginalsV1::retained_endpoint_open_files_v1()
                .ok_or(JournalError::LimitExceeded("Delete Inventory endpoint originals"))?,
            process_evidence: process,
        })
    }

    /// Retains the already-paid native borrower inside the whole outer owner.
    ///
    /// A mismatched actual outer shape terminates while its same Session and
    /// native original remain resident. No method, nonce, cutoff or payer input
    /// constructs a different purpose here.
    pub(crate) fn retain_prepaid(
        mut native: N,
    ) -> Self {
        let shape = match Self::security_shape_v1() {
            Ok(shape) => shape,
            Err(_) => std::process::abort(),
        };
        if native.require_security_construction_once_v1(shape).is_err() {
            std::process::abort();
        }
        let mut shared = OriginalStoragePreparationClientFlightV1::empty();
        shared.inner.purpose = match native.inventory_method_data_v2() {
            Some(method) if method != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES =>
                OriginalClientFlightPurposeV1::ReconciliationInventory(method),
            _ => OriginalClientFlightPurposeV1::ControllerInventory,
        };
        Self {
            native,
            original: ControllerInventoryQueryOriginalsV1 {
                shared,
                wait: storage_inventory::wait::InventoryWaitOriginalsV1::default(),
                capture: None, preparation: None, preparation_post: None, unsigned: None,
                send_before: None, send_after: None, receive_before: None,
                predecessor_admission: None, projection: None, model: None,
                predecessor_originals: crate::recovery::OutcomeCurrentOriginalsV1::default(),
                predecessor: None, witness_post: None, final_post: None, disposal: None,
                first: None, reentry: None, prepared: false, received: false,
            },
        }
    }

    /// Captures the same Session and commits its fixed signed Inventory request.
    ///
    /// # Errors
    /// Keeps every entered native/security/request original on refusal. The
    /// caller must still run finish_native_once, including after this error.
    pub(crate) fn prepare_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> Result<(), OutputPreparationClosedV1> {
        if self.original.capture.is_some() || self.original.first.is_some() {
            return self.refuse();
        }
        self.original.capture = Some(match self.native.session_journal_mut_v1(&mut (*session).owner) {
            Ok(journal) => self.native.capture_session_once_v1(journal, &(*session).socket, &(*session).transcript),
            Err(cause) => {
                self.original.shared.inner.protected_failure = Some(cause);
                Err(JournalError::ProtectedBoundary)
            }
        });
        if !matches!(self.original.capture, Some(Ok(()))) {
            self.original.first.get_or_insert(First::Capture);
            return Err(OutputPreparationClosedV1);
        }
        self.original.preparation = Some(match self.native.session_journal_v1(&(*session).owner) {
            Ok(journal) => self.native.begin_request_preparation_once(journal, &(*session).socket, &(*session).transcript),
            Err(cause) => {
                self.original.shared.inner.protected_failure = Some(cause);
                Err(JournalError::ProtectedBoundary)
            }
        });
        let constructed = if matches!(self.original.preparation, Some(Ok(()))) {
            self.original.shared.inner.coordinates = Some(self.native.coordinates_v1(&(*session)));
            match self.original.shared.inner.coordinates.as_ref() {
                Some(Ok(coordinates)) => {
                    self.original.unsigned = Some(fixed_inventory_envelope(&(*session), *coordinates, self.native.inventory_method_data_v2()));
                    match self.original.unsigned.as_ref() {
                        Some(unsigned) => self.original.shared.inner.prepare_engine(
                            &mut (*session), unsigned.clone(), Some(
                                aos_sandbox_protocol::fixed_controller_inventory_request_packet_bound_v1(),
                            ),
                        ),
                        None => false,
                    }
                }
                _ => false,
            }
        } else {
            self.original.first.get_or_insert(First::Preparation);
            false
        };
        if !constructed && self.original.shared.inner.failure_with_session(&(*session)).is_some() {
            self.native.mark_sdk_primary_before_post_v1();
        }
        self.original.preparation_post = Some(self.observe_post(session));
        if !constructed {
            self.original.first.get_or_insert(First::Shared);
            self.native.mark_primary_refused_v1();
            return Err(OutputPreparationClosedV1);
        }
        if !matches!(self.original.preparation_post, Some(Ok(()))) || self.native.finish_positive_io_once().is_err() {
            self.original.first.get_or_insert(First::Preparation);
            return Err(OutputPreparationClosedV1);
        }
        self.original.prepared = true;
        Ok(())
    }

    /// Advances the existing shared atomic sender, receiver or readiness waiter.
    ///
    /// Pending no-consumption receipts retire only after their real independent
    /// posts. The original immutable cutoff governs every reached native turn.
    pub(crate) fn advance_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> StoragePreparationClientProgressV1 {
        if !self.original.prepared || self.original.received || self.original.first.is_some() || self.original.final_post.is_some() {
            let _ = self.refuse();
            return StoragePreparationClientProgressV1::Closed;
        }
        if self.original.wait.is_pending() {
            if !self.original.wait.wait_original_once(&mut (*session), &mut self.original.shared.inner, &mut self.native) {
                self.original.first.get_or_insert(First::Wait);
                return StoragePreparationClientProgressV1::Closed;
            }
            return StoragePreparationClientProgressV1::Pending;
        }
        if !matches!(self.original.shared.inner.sent, Some(Ok(()))) {
            return match storage_io::send_once(&mut self.original.shared, &mut self.original.wait,
                &mut self.original.send_before, &mut self.original.send_after, &mut (*session), &mut self.native)
            {
                Ok(progress) => progress,
                Err(storage_io::StorageIoFailureV1::Native) => {
                    self.original.first.get_or_insert(First::Send);
                    StoragePreparationClientProgressV1::Closed
                }
                Err(storage_io::StorageIoFailureV1::Wait) => {
                    self.original.first.get_or_insert(First::Wait);
                    StoragePreparationClientProgressV1::Closed
                }
                Err(storage_io::StorageIoFailureV1::Shared) => {
                    self.original.first.get_or_insert(First::Shared);
                    StoragePreparationClientProgressV1::Closed
                }
            };
        }
        self.receive_once(session)
    }

    fn receive_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> StoragePreparationClientProgressV1 {
        self.original.receive_before = Some(match self.native.session_journal_v1(&(*session).owner) {
            Ok(journal) => self.native.begin_receive_once(journal, &(*session).socket, &(*session).transcript),
            Err(cause) => {
                self.original.shared.inner.protected_failure = Some(cause);
                Err(JournalError::ProtectedBoundary)
            }
        });
        if !matches!(self.original.receive_before, Some(Ok(()))) {
            self.original.first.get_or_insert(First::Receive);
            let _ = self.observe_post(session);
            return StoragePreparationClientProgressV1::Closed;
        }
        let committed = self.original.shared.inner.receive_terminal_with_storage_io_v1(
            &mut (*session), Some(&mut self.native),
        );
        if !committed && !self.original.shared.inner.closed && self.original.shared.inner.terminal_packet.is_nonconsuming_v1() {
            let Some(Err(receipt)) = self.original.shared.inner.terminal_packet.received.as_ref() else {
                self.original.first.get_or_insert(First::Shared);
                return StoragePreparationClientProgressV1::Closed;
            };
            let disposal = match self.native.prepare_pending_receive_disposal_once(receipt) {
                Ok(disposal) => disposal,
                Err(_) => {
                    self.original.first.get_or_insert(First::Receive);
                    return StoragePreparationClientProgressV1::Closed;
                }
            };
            let old = std::mem::replace(&mut self.original.shared.inner.terminal_packet, OriginalOutputPacketV1::empty());
            drop(old);
            disposal.complete_after_receipt_disposal();
            self.original.shared.inner.inventory_io_post = None;
            self.original.receive_before = None;
            if !self.original.wait.arm_receive() {
                self.original.first.get_or_insert(First::Wait);
                return StoragePreparationClientProgressV1::Closed;
            }
            return StoragePreparationClientProgressV1::Pending;
        }
        if !committed {
            // Shared concrete IO/verification errors precede the later native
            // post. Native decode/outcome marker sites have no earlier shared
            // failure, and resolve only through this exact actual borrower.
            if self.original.shared.inner.failure_with_session(&(*session)).is_some() {
                self.original.first.get_or_insert(First::Shared);
            } else {
                self.original.first.get_or_insert(First::Receive);
            }
            return StoragePreparationClientProgressV1::Closed;
        }
        self.original.predecessor_admission = Some(match self.native.session_journal_v1(&(*session).owner) {
            Ok(journal) => self.native.admit_retained_predecessor_once(journal),
            Err(cause) => {
                self.original.shared.inner.protected_failure = Some(cause);
                Err(JournalError::ProtectedBoundary)
            }
        });
        if !matches!(self.original.predecessor_admission, Some(Ok(()))) {
            self.original.first.get_or_insert(First::PredecessorAdmission);
            return StoragePreparationClientProgressV1::Closed;
        }
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal)) = self.original.shared.inner.committed.as_ref() else {
            self.original.first.get_or_insert(First::Shared);
            return StoragePreparationClientProgressV1::Closed;
        };
        self.original.projection = Some(self.native.committed_originals_v1(terminal, &(*session).owner).map(|_| ()));
        match self.native.committed_originals_v1(terminal, &(*session).owner) {
            Ok((outcome, currentness)) => {
                self.original.model = Some(decode_model(outcome));
                if !matches!(self.original.model, Some(Ok(_))) {
                    self.original.first.get_or_insert(First::Model);
                    return StoragePreparationClientProgressV1::Closed;
                }
                self.original.predecessor = Some(self.native.compare_predecessor_v1(&mut (*session).owner,
                    currentness, (*session).socket.peer(), &mut self.original.predecessor_originals,
                ));
                if !matches!(self.original.predecessor, Some(Ok(()))) {
                    self.original.first.get_or_insert(First::Predecessor);
                    return StoragePreparationClientProgressV1::Closed;
                }
            }
            Err(_) => {
                self.original.first.get_or_insert(First::Projection);
                return StoragePreparationClientProgressV1::Closed;
            }
        }
        self.original.received = true;
        StoragePreparationClientProgressV1::Committed
    }

    fn observe_post(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> Result<(), JournalError> {
        match self.native.session_journal_v1(&(*session).owner) {
            Ok(journal) => self.native.observe_io_post_once(journal, &(*session).socket, &(*session).transcript),
            Err(cause) => {
                self.original.shared.inner.protected_failure.get_or_insert(cause);
                Err(JournalError::ProtectedBoundary)
            }
        }
    }

    /// Runs independent final posts after either entered whole-query outcome.
    ///
    /// # Errors
    /// Retains reentry, earlier primary or final native/currentness refusal.
    pub(crate) fn finish_native_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> Result<(), OutputPreparationClosedV1> {
        if self.original.final_post.is_some() {
            return self.refuse();
        }
        self.original.witness_post = Some((*session).observe_delete_inventory_witness_post_v1());
        if self.original.witness_post.as_ref().is_some_and(Result::is_err) {
            self.original.first.get_or_insert(First::WitnessPost);
        }
        if self.original.first.is_some() || !self.original.received {
            self.native.mark_primary_refused_v1();
        }
        self.original.final_post = Some(match self.native.session_journal_v1(&(*session).owner) {
            Ok(journal) => self.native.finish_native_once_v1(journal, &(*session).socket, &(*session).transcript),
            Err(cause) => {
                self.original.shared.inner.protected_failure.get_or_insert(cause);
                Err(JournalError::ProtectedBoundary)
            }
        });
        if !matches!(self.original.final_post, Some(Ok(()))) {
            self.original.first.get_or_insert(First::Final);
        }
        if self.original.first.is_none() { Ok(()) } else { Err(OutputPreparationClosedV1) }
    }

    pub(crate) fn finish_outer_source_failure_once_v1(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if self.original.first.is_some() || !matches!(self.original.final_post, Some(Ok(()))) {
            self.native.mark_primary_refused_v1();
        }
        self.native.finish_outer_source_failure_once_v1().map_err(|_| OutputPreparationClosedV1)
    }

    /// Moves the successful Session and historical answer after real disposal.
    ///
    /// Invalid/incomplete entry terminates while the whole owner remains
    /// resident. A rejected native positive gate likewise cannot release any
    /// uncertain request, file or Session. This completion grants no Root floor
    /// or dependency-plan acceptance.
    pub(crate) fn try_finish_positive_once(mut self, session: &mut DormantAuthenticatedBrokerSessionV1)
        -> Result<DeleteInventoryAnswerOriginalsV1, Self>
    {
        if self.original.first.is_some() || !self.original.received
            || !matches!(self.original.final_post, Some(Ok(())))
            || !matches!(self.original.model, Some(Ok(_)))
            || !matches!(self.original.predecessor, Some(Ok(())))
            || self.original.shared.inner.failure_with_session(&(*session)).is_some()
            || !matches!(self.original.shared.inner.committed,
                Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(_)))
        {
            self.native.mark_primary_refused_v1();
            return Err(self);
        }
        let journal = match self.native.session_journal_mut_v1(&mut (*session).owner) {
            Ok(journal) => journal,
            Err(cause) => {
                self.original.shared.inner.protected_failure.get_or_insert(cause);
                self.native.mark_primary_refused_v1();
                return Err(self);
            }
        };
        // The native Result and every possible borrowed completion token end
        // inside this finite block before a failed whole kernel can move back.
        let completed = {
            let disposition = self.native.prepare_positive_disposal_v1(journal);
            match disposition {
                Ok(disposition) => {
                    let native_boundary = disposition.completed_boundary_data_v2();
                    let native_position = disposition.completed_native_position_data_v4();
                    let committed = match self.original.shared.inner.committed.take() {
                        Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) => committed,
                        _ => std::process::abort(),
                    };
                    let model = match self.original.model.take() {
                        Some(Ok(model)) => model,
                        _ => std::process::abort(),
                    };
                    // Actual terminal/model/currentness persist. Only proved
                    // positive IO/request scratch drops before Native releases.
                    drop(std::mem::replace(&mut self.original.shared,
                        OriginalStoragePreparationClientFlightV1::empty()));
                    drop(std::mem::take(&mut self.original.wait));
                    drop(self.original.unsigned.take());
                    disposition.complete_after_upper_disposal_v1();
                    Some((committed, model, native_boundary, native_position))
                }
                Err(cause) => {
                    self.original.disposal = Some(Err(cause));
                    self.original.first.get_or_insert(First::Disposal);
                    None
                }
            }
        };
        let Some((committed, model, native_boundary, native_position)) = completed else {
            return Err(self);
        };
        let Self { native, original: ControllerInventoryQueryOriginalsV1 {
            predecessor_originals, ..
        } } = self;
        drop(native);
        Ok(DeleteInventoryAnswerOriginalsV1 { committed, model,
            predecessor: predecessor_originals, native_boundary, native_position })
    }

    pub(crate) fn into_retained_query_v1(self) -> ControllerInventoryQueryOriginalsV1 {
        let Self { native, original } = self;
        drop(native);
        original
    }

    fn refuse(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.original.reentry.get_or_insert(OutputPreparationClosedV1);
        self.original.first.get_or_insert(First::Reentry);
        self.native.mark_primary_refused_v1();
        Err(OutputPreparationClosedV1)
    }

    /// Borrows the original local/security primary without replacing its cause.
    #[must_use]
    pub(crate) fn failure<'cause>(&'cause self, session: &'cause DormantAuthenticatedBrokerSessionV1)
        -> Option<&'cause (dyn Error + 'static)>
    {
        self.original.failure_with_session_v1(session, self.native.local_failure_v1())
    }

    /// Borrows the exact same-C17 financial/profile cause only at its marker site.
    #[must_use]
    pub(crate) fn controller_failure_view_v1(&self)
        -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'_>>
    {
        match self.original.first? {
            First::Capture | First::Preparation | First::Send | First::Receive
                | First::PredecessorAdmission | First::Final | First::Disposal | First::Wait =>
                self.native.controller_failure_view_v1(),
            _ => None,
        }
    }
}

impl<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>
    DeleteInventoryClientKernelV1<'turn, 'fence, 'journal, 'original, 'authorization, 'profile>
{
    pub(crate) fn finish_positive_once(self, session: &mut DormantAuthenticatedBrokerSessionV1)
        -> DeleteInventoryAnswerOriginalsV1
    {
        match self.try_finish_positive_once(session) {
            Ok(answer) => answer,
            Err(mut original) => {
                original.native.mark_primary_refused_v1();
                let _ = original.native.finish_outer_source_failure_once_v1();
                std::process::abort();
            }
        }
    }

    /// Borrows a paid planning query from the actual authorized Source pair.
    ///
    /// The Session stays on its original Runtime owner while fixed and outer
    /// construction debt is admitted. Its private transcript selects the role;
    /// no transcript getter, caller nonce, capacity or alternate payer escapes.
    ///
    /// # Errors
    /// Refuses the original same-C17/Source/currentness or representation gate
    /// before the Session is moved or any new query IO is entered.
    #[doc(hidden)]
    pub(crate) fn borrow_planning_native_once_v1(
        bank: &'turn aos_sandbox::ControllerResourceBankOpeningV1,
        authorized: &'turn mut aos_sandbox::ControllerDeleteSourceAuthorizedScopeV1<'journal, 'original>,
        controller: &'turn mut aos_sandbox::Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        session: &DormantAuthenticatedBrokerSessionV1,
        upper_construction_bytes: usize,
    ) -> Result<DeleteInventorySessionAppendOriginalV1<'turn, 'turn, 'journal, 'original, 'journal, 'profile>, aos_sandbox::ResourceReservationErrorV1> {
        let shape = Self::security_shape_v1()?;
        bank.borrow_delete_planning_inventory_once_v1(
            authorized, controller, profile, &session.transcript, shape, upper_construction_bytes,
        )
    }

}

impl ControllerInventoryQueryOriginalsV1 {
    pub(crate) fn failure_with_session_v1<'cause>(&'cause self,
        session: &'cause DormantAuthenticatedBrokerSessionV1,
        native_failure: Option<&'cause (dyn Error + 'static)>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.first? {
            First::Shared => self.shared.inner.failure_with_session(&(*session)),
            First::Model => self.model.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _),
            First::Projection => self.projection.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _),
            First::Predecessor => self.predecessor_originals.failure()
                .or_else(|| self.predecessor.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _)),
            First::WitnessPost => self.witness_post.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _),
            First::Wait => self.wait.failure_with_native(native_failure),
            First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
            _ => native_failure
                .or_else(|| self.shared.inner.failure_with_session(&(*session))),
        }
    }
}

fn fixed_inventory_envelope(session: &DormantAuthenticatedBrokerSessionV1,
    coordinates: crate::dormant_handshake::DormantBrokerRequestCoordinatesV1,
    selected: Option<BrokerMethod>,
) -> BrokerRequestEnvelope {
    let header = InventoryRuntimeRequest { header: Some(coordinates.request_header()).into(), ..Default::default() }.header;
    let default = match session.transcript.protocol() {
        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Mount => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Network => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        _ => std::process::abort(),
    };
    // A selected method comes only from the private genuine native borrower.
    // The same receiver validates its protocol, original and finite roster.
    let method = selected.unwrap_or(default);
    let body = match method {
        BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME =>
            InventoryRuntimeRequest { header, ..Default::default() }.encode_to_vec(),
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS =>
            InventoryDestinationSlotsRequest { header, ..Default::default() }.encode_to_vec(),
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES =>
            InventoryStorageRequest { header, ..Default::default() }.encode_to_vec(),
        BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES =>
            InventoryNetworksRequest { header, ..Default::default() }.encode_to_vec(),
        _ => std::process::abort(),
    };
    BrokerRequestEnvelope { method: method.into(), body, ..Default::default() }
}

pub(super) fn decode_model(outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1)
    -> Result<ControllerInventoryDecodedOriginalV2, ProtocolValidationError> {
    aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::decode_controller_inventory_model_v2(outcome)
}

/// Keeps complete successful query originals beside the returned Session.
///
/// This owner is historical DATA until the actual upper preaccept consumer
/// rechecks its same Session under the fresh genuine Root/C17 association.
#[doc(hidden)]
pub struct DeleteInventoryAnswerOriginalsV1 {
    committed: crate::recovery::ProtectedBrokerOutcomeCommittedAdvancementV1,
    model: ControllerInventoryDecodedOriginalV2,
    predecessor: crate::recovery::OutcomeCurrentOriginalsV1,
    native_boundary: (u64, u64, u64, u64),
    native_position: Option<[u8; 64]>,
}

impl DeleteInventoryAnswerOriginalsV1 {
    pub(crate) fn recover_transcript_data_v1(&self) -> Option<&VerifiedBrokerSessionTranscriptV1> {
        self.committed.operator_recover_inventory_transcript_data_v1()
    }

    /// Borrows the actual fully checked negotiated history and fixed location.
    ///
    /// This historical comparison view is available only from the completed D
    /// predecessor. It creates no Session, verifier, native reader or live cut.
    #[must_use]
    pub fn negotiated_preimages_v2(&self) -> Option<DeleteInventoryNegotiatedPreimagesV2<'_>> {
        let (encoded_history, checkpoint, history) = self.predecessor.negotiated_delete_preimages_v2()?;
        let (context, transcript, directory, basename) = self.committed.delete_inventory_negotiated_context_data_v2()?;
        Some(DeleteInventoryNegotiatedPreimagesV2 {
            encoded_history, checkpoint, history, context, transcript, directory, basename,
        })
    }

    /// Returns the original completed native NEXT/device/inode/byte boundary.
    ///
    /// This is historical DATA copied before actual positive native disposal.
    /// The whole terminal/model/predecessor originals remain on this answer;
    /// a later preaccept must still join the same Session and fresh Root/C17.
    #[must_use]
    pub const fn native_boundary_data_v2(&self) -> (u64, u64, u64, u64) {
        self.native_boundary
    }

    /// Borrows the actual completed Delete query's final native position DATA.
    ///
    /// The format is names48, snapshot sequence8 and held length8. Recovery
    /// queries without that native supplier return `None`. No caller installs
    /// this field or constructs an answer from a supplied position.
    #[must_use]
    pub fn native_position_data_v4(&self) -> Option<&[u8; 64]> {
        self.native_position.as_ref()
    }

    /// Returns the original kernel boot retained by this exact Session context.
    ///
    /// This is historical comparison DATA from the confirmed advancement, not
    /// a caller boot, new clock sample or authority to borrow another Session.
    #[must_use]
    pub fn kernel_boot_data_v2(&self) -> [u8; 16] {
        self.committed.delete_inventory_kernel_boot_data_v2()
    }

    /// Returns the actual confirmed protected generation and complete head.
    ///
    /// No supplied digest, generation or decoded packet can construct this
    /// answer. This projection does not replace fresh native currentness.
    #[must_use]
    pub fn protected_cut_data_v2(&self) -> (u64, [u8; 32]) {
        self.committed.delete_inventory_protected_cut_data_v2()
    }

    /// Borrows the complete historical authenticated model without a grant.
    #[must_use]
    pub fn model_v1(&self) -> &DeleteInventoryModelV1 { self.model.model_v2() }

    pub(crate) fn decoded_model_original_v2(&self) -> &ControllerInventoryDecodedOriginalV2 { &self.model }

    /// Borrows the exact completed authenticated outcome as historical DATA.
    ///
    /// Its original terminal/native/currentness owners stay on this answer.
    /// This borrow is not a live six-cut or permission to mutate any resource.
    #[must_use]
    pub fn outcome_v1(&self)
        -> &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1
    {
        self.committed.delete_inventory_completed_outcome_data_v1()
    }
}

/// Borrows actual negotiated preimages from one completed Delete answer.
///
/// Every reference points into the same retained answer. There is no public
/// constructor, supplied verifier or decoded-DATA adoption path. Independent
/// Root verification must still use its own fixed manifests and native files.
#[doc(hidden)]
pub struct DeleteInventoryNegotiatedPreimagesV2<'answer> {
    encoded_history: &'answer [u8],
    checkpoint: &'answer HistoricalSessionCheckpointV1,
    history: &'answer aos_sandbox_broker_session_protocol::BrokerSessionDurableHistoryV1,
    context: &'answer aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1,
    transcript: &'answer VerifiedBrokerSessionTranscriptV1,
    directory: &'static str,
    basename: &'static str,
}

impl DeleteInventoryNegotiatedPreimagesV2<'_> {
    /// Borrows the complete canonical history bytes actually decoded and checked.
    #[must_use]
    pub fn encoded_history_v2(&self) -> &[u8] { self.encoded_history }

    /// Borrows the actual checkpoint, including both exact Hello packets.
    #[must_use]
    pub fn checkpoint_v2(&self) -> &HistoricalSessionCheckpointV1 { self.checkpoint }

    /// Borrows the same fully replayed durable history.
    #[must_use]
    pub fn history_v2(&self) -> &aos_sandbox_broker_session_protocol::BrokerSessionDurableHistoryV1 { self.history }

    /// Borrows the same protected verification context, without adoption rights.
    #[must_use]
    pub fn context_v2(&self) -> &aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1 { self.context }

    /// Borrows the actual verified negotiation retained by the advancement.
    #[must_use]
    pub fn transcript_v2(&self) -> &VerifiedBrokerSessionTranscriptV1 { self.transcript }

    /// Returns the fixed original Controller Session directory and basename.
    #[must_use]
    pub const fn fixed_location_v2(&self) -> (&'static str, &'static str) { (self.directory, self.basename) }
}
