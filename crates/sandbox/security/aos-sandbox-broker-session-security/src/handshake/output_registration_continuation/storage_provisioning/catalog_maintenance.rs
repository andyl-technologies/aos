//! Publishes one canonical maintenance catalog on its same completed Host Session.
//!
//! This is a finite member of the existing retained provisioning flight. The
//! opaque completed borrower continuously holds receiver and mutable Session;
//! native completion independently retains actual sent/received originals.

use super::*;
use crate::recovery::{ProtectedBrokerSessionOwnerV1, RetainedStorageClientOwnerPostV1};
use aos_sandbox_controller_domain::Journal;
use aos_sandbox_controller_domain::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2;
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, RetainedSeqpacketReceiveErrorV1, SeqpacketSocket,
};

/// Retains the actual canonical Catalog17 flight through confirmation and all posts.
#[doc(hidden)]
#[must_use = "retain failed prefixes; dispose only after canonical confirmation and all posts"]
pub struct ControllerCatalogMaintenanceSessionIoOriginalV2 {
    flight: Option<ProvisioningFlightV1>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    protected: Option<BrokerSessionSecurityError>,
    sent: Option<aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1>,
    received: Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
    completion: Option<Result<(), aos_sandbox_controller_domain::ControllerCatalogMaintenanceCompletionRefusalV2>>,
    completion_entered: bool,
    original_selected: bool,
    disposal: Option<Result<(), ResourceReservationErrorV1>>,
    disposed_session: Option<([u8; 32], [u8; 32])>,
}

impl ControllerCatalogMaintenanceSessionIoOriginalV2 {
    /// Constructs empty inline destinations without allocation or native IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flight: Some(ProvisioningFlightV1::new(
                ProvisioningKindV4::MaintenanceCatalog,
            )),
            admission: None,
            protected: None,
            sent: None,
            received: None,
            completion: None,
            completion_entered: false,
            original_selected: false,
            disposal: None,
            disposed_session: None,
        }
    }

    /// Runs the sole Catalog17 flight under the actual paid maintenance and Host borrower.
    ///
    /// # Errors
    /// Retains reentry, changed receiver/source, financial, native, transport,
    /// canonical model, signed history or independently owed post failure.
    pub fn publish_once_v2(
        &mut self,
        loan: &mut aos_sandbox_controller_domain::ControllerCatalogMaintenanceLoanV2<'_, '_>,
        completed: &mut crate::dormant_handshake::DormantControllerInitialSessionCompletedBorrowV1<
            '_,
        >,
        source: &StartHostCatalogPublicationOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.admission.is_some() {
            loan.retain_sdk_refusal_once_v2();
            return Err(OutputPreparationClosedV1);
        }
        let (receiving, session) = completed.reborrow_v1();
        let journal = match session.owner.catalog_maintenance_client_journal_v2() {
            Ok(journal) => journal,
            Err(cause) => {
                self.protected = Some(cause);
                self.admission = Some(Err(ResourceReservationErrorV1::Conflict));
                loan.retain_sdk_refusal_once_v2();
                return Err(OutputPreparationClosedV1);
            }
        };
        let mut native =
            match loan.borrow_catalog_io_once_v2(receiving, source, journal, &session.transcript) {
                Ok(native) => {
                    self.admission = Some(Ok(()));
                    native
                }
                Err(cause) => {
                    self.admission = Some(Err(cause));
                    return Err(OutputPreparationClosedV1);
                }
            };
        let flight = self.flight.as_mut().ok_or(OutputPreparationClosedV1)?;
        let body = StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
            flight,
            session,
            &mut native,
            source,
            false,
        );
        if body.is_err() {
            self.original_selected = flight.selected_original_failure();
            if self.original_selected {
                native.retain_catalog_io_refusal_once_v2();
            } else {
                native.retain_catalog_sdk_refusal_once_v2();
            }
            return body;
        }
        self.completion_entered = true;
        self.sent = flight
            .shared
            .inner
            .storage_sent
            .as_mut()
            .and_then(|sent| sent.take_native_sent_v1());
        let received = flight.shared.inner.terminal_packet.received.take();
        match received {
            Some(Ok(OriginalReceivedPacketV4::Plain(record))) => self.received = Some(record),
            other => flight.shared.inner.terminal_packet.received = other,
        }
        let outcome = flight
            .authenticated(false)
            .ok_or(OutputPreparationClosedV1)?;
        let journal = native
            .session_journal_v1(&session.owner)
            .map_err(|_| OutputPreparationClosedV1)?;
        match (self.sent.take(), self.received.take()) {
            (Some(sent), Some(received)) => {
                self.completion = Some(native.complete_catalog_native_once_v2(
                    source,
                    journal,
                    &session.socket,
                    &session.transcript,
                    outcome,
                    sent,
                    received,
                ));
            }
            (sent, received) => {
                self.sent = sent;
                self.received = received;
            }
        }
        self.original_selected = native.catalog_original_failure_selected_v2();
        if matches!(self.completion, Some(Ok(()))) {
            Ok(())
        } else {
            native.retain_catalog_io_refusal_once_v2();
            Err(OutputPreparationClosedV1)
        }
    }

    /// Borrows only the actual authenticated outcome after the shared flight completes.
    #[must_use]
    pub fn completed_outcome_v2(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        if !matches!(self.completion, Some(Ok(()))) {
            return None;
        }
        self.flight.as_ref()?.authenticated(false)
    }

    /// Identifies the exact earlier lower-original boundary for diagnostic routing.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        self.original_selected
    }

    /// Borrows the whole retained SDK cause when the lower original was not selected.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.flight
            .as_ref()
            .and_then(ProvisioningFlightV1::failure)
            .or_else(|| self.protected.as_ref().map(|cause| cause as _))
            .or_else(|| {
                self.admission
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.completion
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.disposal
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                (self.completion_entered && !matches!(self.completion, Some(Ok(()))))
                    .then_some(&OutputPreparationClosedV1 as &(dyn Error + 'static))
            })
    }

    /// Physically retires this positive flight after confirmation and every outer post.
    ///
    /// The same held Session remains live. The lower token completes only after
    /// the actual request/response/replay/transport flight has been dropped.
    ///
    /// # Errors
    /// Refuses missing completion, changed Session, confirmation, native posts,
    /// or repeated disposal. Negative prefixes are never replaced.
    pub fn dispose_positive_once_v2(
        &mut self,
        owner: &mut aos_sandbox_controller_domain::CatalogMaintenanceOriginalV2,
        controller: &Journal,
        source: &StartHostCatalogPublicationOriginalV2,
        completed: &mut crate::dormant_handshake::DormantControllerInitialSessionCompletedBorrowV1<
            '_,
        >,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.disposal.is_some()
            || self.disposed_session.is_some()
            || self.sent.is_some()
            || self.received.is_some()
        {
            return Err(OutputPreparationClosedV1);
        }
        let (_, session) = completed.reborrow_v1();
        let outcome = self
            .completed_outcome_v2()
            .ok_or(OutputPreparationClosedV1)?;
        if outcome.request().session_binding() != session.transcript.session_binding()
            || session
                .owner
                .catalog_maintenance_client_journal_v2()
                .is_err()
        {
            return Err(OutputPreparationClosedV1);
        }
        let binding = (
            session.transcript.session_binding(),
            session.transcript.protected_context_digest(),
        );
        let token = match owner.prepare_catalog_sdk_disposal_once_v2(controller, source, outcome) {
            Ok(token) => token,
            Err(cause) => {
                self.disposal = Some(Err(cause));
                return Err(OutputPreparationClosedV1);
            }
        };
        self.complete_physical_disposal_v2(token, binding);
        Ok(())
    }
    fn complete_physical_disposal_v2(
        &mut self,
        token: aos_sandbox_controller_domain::ControllerCatalogMaintenanceCatalogDisposalV2<'_>,
        binding: ([u8; 32], [u8; 32]),
    ) {
        drop(self.flight.take());
        token.complete_after_disposal_v2();
        self.disposal = Some(Ok(()));
        self.disposed_session = Some(binding);
    }

    /// Disposes the same positive flight using the Node's closed private-C port.
    ///
    /// # Errors
    /// Refuses an earlier failure, changed Session, unfinished confirmation/posts
    /// or repeated disposition. No raw C or Source writer is exposed.
    #[doc(hidden)]
    pub fn dispose_positive_with_node_once_v2<C, E>(
        &mut self,
        node: &aos_sandbox_controller_domain::NodeController<C, E>,
        owner: &mut aos_sandbox_controller_domain::CatalogMaintenanceOriginalV2,
        source: &StartHostCatalogPublicationOriginalV2,
        completed: &mut crate::dormant_handshake::DormantControllerInitialSessionCompletedBorrowV1<
            '_,
        >,
    ) -> Result<(), OutputPreparationClosedV1>
    where
        C: aos_sandbox_controller_domain::ActivatedOperationCompiler,
        E: aos_sandbox_controller_domain::SingleNodeEffectExecutor,
    {
        if self.disposal.is_some()
            || self.disposed_session.is_some()
            || self.sent.is_some()
            || self.received.is_some()
        {
            return Err(OutputPreparationClosedV1);
        }
        let (_, session) = completed.reborrow_v1();
        let outcome = self
            .completed_outcome_v2()
            .ok_or(OutputPreparationClosedV1)?;
        if outcome.request().session_binding() != session.transcript.session_binding()
            || session
                .owner
                .catalog_maintenance_client_journal_v2()
                .is_err()
        {
            return Err(OutputPreparationClosedV1);
        }
        let binding = (
            session.transcript.session_binding(),
            session.transcript.protected_context_digest(),
        );
        let token = match node.prepare_catalog_maintenance_sdk_disposal_v2(owner, source, outcome) {
            Ok(token) => token,
            Err(cause) => {
                self.disposal = Some(Err(cause));
                return Err(OutputPreparationClosedV1);
            }
        };
        self.complete_physical_disposal_v2(token, binding);
        Ok(())
    }
}

impl Default for ControllerCatalogMaintenanceSessionIoOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisioningMemberV4 for aos_sandbox_controller_domain::ControllerCatalogMaintenanceIoLoanV2<'_> {
    fn retain_primary_refusal_v4(&mut self, original_selected: bool) {
        if original_selected {
            self.retain_catalog_io_refusal_once_v2();
        } else {
            self.retain_catalog_sdk_refusal_once_v2();
        }
    }

    type Prepared = StartHostCatalogPublicationOriginalV2;

    fn flight_owner_inline_bytes_v4() -> Option<usize> {
        size_of::<ControllerCatalogMaintenanceSessionIoOriginalV2>().checked_mul(2)?
            .checked_add(ProvisioningFlightV1::body_slots_receiving_bytes_v5(1)?)
    }

    fn matches_kind_v2(&self, kind: ProvisioningKindV4, _: &Self::Prepared) -> bool {
        matches!(kind, ProvisioningKindV4::MaintenanceCatalog)
    }

    fn extra_inline_bytes_v4(&self) -> Option<usize> {
        aos_sandbox_linux::seqpacket::SeqpacketSocket::network_preparation_send_receiving_bytes_v4(
        )?
        .checked_add(crate::handshake::start_host_coordinates_receiving_bytes_v2()?)
    }

    fn request_packet_bound_v4(&self, _: &Self::Prepared, inventory: bool) -> Option<usize> {
        if inventory {
            None
        } else {
            Some(aos_sandbox_protocol::host_catalog::MAXIMUM_HOST_CATALOG_PUBLICATION_PACKET_BYTES)
        }
    }

    fn admit_v4(
        &mut self,
        source: &Self::Prepared,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: aos_sandbox_controller_domain::StorageProvisioningSessionIoShapeDataV1,
        inventory: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if inventory {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.admit_catalog_io_once_v2(source, journal, socket, transcript, shape)
    }

    fn prepare_request_v4(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        source: &Self::Prepared,
        inventory: bool,
        maximum_request: usize,
    ) -> bool {
        let inputs = (|| {
            if inventory {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let journal = self.session_journal_v1(&session.owner)?;
            let header = self
                .catalog_request_header_data_v2(journal, &session.socket, &session.transcript)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let coordinates = session.maintenance_catalog_coordinates_v2(&header)?;
            let draft = source
                .draft_v2()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            Ok((
                coordinates,
                draft.request_envelope_data_v2(coordinates.request_header()),
            ))
        })();
        match inputs {
            Ok((coordinates, envelope)) => {
                flight.shared.inner.coordinates = Some(Ok(coordinates));
                flight.unsigned = Some(envelope);
                match flight.unsigned.as_ref() {
                    Some(envelope) => flight.shared.inner.prepare_captured_engine_v1(
                        session,
                        envelope.clone(),
                        Some(maximum_request),
                        match flight.request_originals.as_mut() {
                            Some(capture) => Some(capture.as_mut()),
                            None => return false,
                        },
                    ),
                    None => false,
                }
            }
            Err(cause) => {
                flight.shared.inner.coordinates = Some(Err(cause));
                flight.mark(First::Coordinates);
                false
            }
        }
    }

    fn begin_request_preparation_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_request_preparation_once(journal, socket, transcript)
    }

    fn begin_receive_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_receive_once(journal, socket, transcript)
    }

    fn bind_request_v4(
        &mut self,
        source: &Self::Prepared,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.bind_catalog_request_once_v2(source, request)
    }

    fn admit_predecessor_v4(
        &mut self,
        journal: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.admit_retained_predecessor_once(journal)
    }

    fn prepare_pending_receive_v4<'held>(
        &'held mut self,
        receipt: &RetainedSeqpacketReceiveErrorV1,
    ) -> Result<Self::Disposal<'held>, ResourceReservationErrorV1> {
        self.prepare_pending_receive_disposal_once(receipt)
    }

    fn observe_owner_v4(
        owner: &mut ProtectedBrokerSessionOwnerV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        owner.observe_catalog_maintenance_client_owner_v2(transcript, peer)
    }

    fn finish_terminal_v4(
        &mut self,
        source: &Self::Prepared,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_catalog_terminal_once_v2(source, journal, outcome)
    }

    fn observe_terminal_post_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.observe_catalog_terminal_post_once_v2(journal, socket, transcript)
    }
}
