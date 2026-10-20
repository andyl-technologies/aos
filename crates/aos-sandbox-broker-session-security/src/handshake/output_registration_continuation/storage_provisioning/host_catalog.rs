//! Runs Catalog17 on the genuine pending-child Host Session through the shared flight.
//!
//! This owner retains one complete request/response/native flight. It never
//! borrows the later HostLaunch stages or constructs a Session, source, payer
//! or activation proof from the returned outcome.

use super::*;
use crate::recovery::{ProtectedBrokerSessionOwnerV1, RetainedStorageClientOwnerPostV1};
use aos_sandbox::{Journal, StartHostCatalogIoLoanV2};
use aos_sandbox::host_catalog_reconciliation::StartHostCatalogPublicationOriginalV2;
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, RetainedSeqpacketReceiveErrorV1, SeqpacketSocket,
};

/// Retains the sole pending-child Catalog17 flight beside its original Host Session.
///
/// Construction is inert. Only the real Catalog6 loan and privately qualified
/// Host Session borrower can enter this owner. A completed outcome is historical
/// DATA; canonical confirmation and native disposal are separate obligations.
#[doc(hidden)]
#[must_use = "retain the complete flight through confirmation and native disposal"]
pub struct StartHostCatalogSessionIoOriginalV2 {
    flight: Option<ProvisioningFlightV1>,
    native_sent: Option<aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1>,
    native_received: Option<aos_sandbox_linux::seqpacket::ReceivedRecord>,
    completion: Option<Result<(), aos_sandbox::StartHostCatalogCompletionRefusalV2>>,
    completion_entered: bool,
    completion_original_selected: bool,
    qualification: Option<QualifiedCatalogDataV2>,
    disposal_entry: Option<Result<(), ResourceReservationErrorV1>>,
}

impl StartHostCatalogSessionIoOriginalV2 {
    /// Constructs empty inline destinations without allocation or native IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flight: Some(ProvisioningFlightV1::new(ProvisioningKindV4::HostCatalog)),
            native_sent: None,
            native_received: None,
            completion: None,
            completion_entered: false,
            completion_original_selected: false,
            qualification: None,
            disposal_entry: None,
        }
    }

    /// Publishes the same source's sealed catalog through its protected Host Session.
    ///
    /// # Errors
    /// Refuses a changed source, Session, pending child, reentry or any actual
    /// funding, request, transport, schema, journal or independently owed post.
    pub fn publish_once_v2(
        &mut self,
        session: &mut super::super::super::StartResourceSessionBorrowV4<'_>,
        original: &mut StartHostCatalogIoLoanV2<'_>,
        source: &StartHostCatalogPublicationOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
            self.flight.as_mut().ok_or(OutputPreparationClosedV1)?,
            session.inner,
            original,
            source,
            false,
        )
    }

    /// Moves the actual sent/received receipts into the genuine native completion owner.
    ///
    /// The private qualified Session and completed shared flight are checked
    /// before either owning receipt is moved. Rejected or failed native prefixes
    /// remain on this owner or the same NativeState through all outer posts.
    ///
    /// # Errors
    /// Refuses missing flight completion, reentry, native receipt substitution,
    /// protected terminal-row mismatch or any independent native post refusal.
    pub fn complete_native_once_v2(
        &mut self,
        session: &mut super::super::super::StartResourceSessionBorrowV4<'_>,
        original: &mut StartHostCatalogIoLoanV2<'_>,
        source: &StartHostCatalogPublicationOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        let flight = self.flight.as_mut().ok_or(OutputPreparationClosedV1)?;
        if self.completion_entered || flight.authenticated(false).is_none() {
            return Err(OutputPreparationClosedV1);
        }
        self.completion_entered = true;
        self.native_sent = flight
            .shared
            .inner
            .storage_sent
            .as_mut()
            .and_then(|sent| sent.take_native_sent_v1());
        let received = flight.shared.inner.terminal_packet.received.take();
        match received {
            Some(Ok(OriginalReceivedPacketV4::Plain(record))) => {
                self.native_received = Some(record)
            }
            other => flight.shared.inner.terminal_packet.received = other,
        }
        if self.native_sent.is_none() || self.native_received.is_none() {
            return Err(OutputPreparationClosedV1);
        }
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal)) =
            flight.shared.inner.committed.as_ref()
        else {
            return Err(OutputPreparationClosedV1);
        };
        let (outcome, _) = flight
            .originals(terminal, false)
            .map_err(|_| OutputPreparationClosedV1)?;
        let journal = original
            .session_journal_v1(&session.inner.owner)
            .map_err(|_| OutputPreparationClosedV1)?;
        if let (Some(sent), Some(received)) = (self.native_sent.take(), self.native_received.take())
        {
            self.completion = Some(original.prepare_native_completion_once_v2(
                source,
                journal,
                &session.inner.socket,
                &session.inner.transcript,
                outcome,
                sent,
                received,
            ));
        }
        self.completion_original_selected = self.completion.as_ref().is_some_and(Result::is_err)
            && original.completion_original_failure_selected_v2();
        if matches!(self.completion, Some(Ok(()))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Borrows the actual authenticated receipt only after all flight posts succeed.
    ///
    /// This DATA view does not authorize confirmation or private child activation.
    #[must_use]
    pub fn completed_outcome_v2(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.flight.as_ref()?.authenticated(false)
    }

    /// Borrows this flight's earliest retained native, protocol or model cause.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.flight
            .as_ref()
            .and_then(ProvisioningFlightV1::failure)
            .or_else(|| {
                self.disposal_entry
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| {
                self.completion
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| {
                (self.completion_entered && !matches!(self.completion, Some(Ok(()))))
                    .then_some(&OutputPreparationClosedV1 as &(dyn Error + 'static))
            })
    }

    /// Identifies only an actual selected lower-original failure at its first boundary.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        self.flight
            .as_ref()
            .is_some_and(ProvisioningFlightV1::selected_original_failure)
            || (self
                .flight
                .as_ref()
                .is_none_or(|flight| flight.failure().is_none())
                && self.completion_original_selected)
    }

    /// Disposes this actual successful catalog flight after confirmation and C/Root6 posts.
    ///
    /// The same privately qualified Host Session remains live. All operation
    /// request/replay/native prefixes are physically dropped before completing
    /// the genuine lower disposal token. Negative owners are never replaced.
    ///
    /// # Errors
    /// Refuses missing completion, changed source/Session, unconfirmed history,
    /// unfinished outer posts or repeated/abandoned native disposal.
    pub fn dispose_positive_once_v2(
        &mut self,
        session: &mut super::super::super::StartResourceSessionBorrowV4<'_>,
        entry: &mut aos_sandbox::AcceptedStartEntryOriginalV1,
        root: &aos_sandbox::normal_root::RootHostLaunchClientOriginalV1,
        controller: &Journal,
        source: &StartHostCatalogPublicationOriginalV2,
    ) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.completion, Some(Ok(())))
            || self.qualification.is_some()
            || self.disposal_entry.is_some()
            || self.native_sent.is_some()
            || self.native_received.is_some()
        {
            return Err(OutputPreparationClosedV1);
        }
        let outcome = self
            .completed_outcome_v2()
            .ok_or(OutputPreparationClosedV1)?;
        if outcome.request().session_binding() != session.inner.transcript.session_binding() {
            return Err(OutputPreparationClosedV1);
        }
        let context = outcome
            .request()
            .host_catalog_publication_data_v2()
            .ok_or(OutputPreparationClosedV1)?;
        let qualified = QualifiedCatalogDataV2 {
            session: session.inner.transcript.session_binding(),
            context: session.inner.transcript.protected_context_digest(),
            generation: context.catalog_generation(),
            digest: *context.catalog_digest().as_bytes(),
            request: outcome.request().signed_request_digest(),
            outcome: aos_sandbox::StartHostCatalogNativeCompletionV2::canonical_outcome_digest_data_v2(outcome),
        };
        let disposal =
            match entry.prepare_host_catalog_disposal_once_v2(root, controller, source, outcome) {
                Ok(disposal) => disposal,
                Err(cause) => {
                    self.disposal_entry = Some(Err(cause));
                    return Err(OutputPreparationClosedV1);
                }
            };
        drop(self.flight.take());
        disposal.complete_after_disposal_v2();
        self.disposal_entry =
            Some(entry.finish_host_catalog_resident_disposal_v2(root, controller));
        if !matches!(self.disposal_entry, Some(Ok(()))) {
            return Err(OutputPreparationClosedV1);
        }
        self.qualification = Some(qualified);
        Ok(())
    }

    /// Borrows only the same authenticated Host Session after actual catalog disposal.
    ///
    /// # Errors
    /// Refuses another Session/context, missing whole native completion or
    /// operation prefixes that have not physically retired after outer posts.
    pub fn qualified_session_v2<'held, 'session>(
        &'held self,
        session: &'held mut super::super::super::StartResourceSessionBorrowV4<'session>,
    ) -> Result<StartHostCatalogQualifiedSessionBorrowV2<'held, 'session>, OutputPreparationClosedV1>
    {
        let qualified = self
            .qualification
            .as_ref()
            .ok_or(OutputPreparationClosedV1)?;
        if self.flight.is_some()
            || self.failure_v2().is_some()
            || qualified.session != session.inner.transcript.session_binding()
            || qualified.context != session.inner.transcript.protected_context_digest()
        {
            return Err(OutputPreparationClosedV1);
        }
        Ok(StartHostCatalogQualifiedSessionBorrowV2 { session, qualified })
    }

    /// Returns the concrete post destinations required before Catalog6 completion.
    #[must_use]
    pub fn retained_post_receiving_demand_v2() -> Option<aos_sandbox_core::ResourceVector> {
        StorageProvisioningSessionIoOriginalV1::retained_post_receiving_demand_v1()
    }
}

impl Default for StartHostCatalogSessionIoOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisioningMemberV4 for StartHostCatalogIoLoanV2<'_> {
    type Prepared = StartHostCatalogPublicationOriginalV2;

    fn flight_owner_inline_bytes_v4() -> Option<usize> {
        size_of::<StartHostCatalogSessionIoOriginalV2>().checked_mul(2)?
            .checked_add(ProvisioningFlightV1::body_slots_receiving_bytes_v5(1)?)
    }

    fn matches_kind_v2(&self, kind: ProvisioningKindV4, _: &Self::Prepared) -> bool {
        matches!(kind, ProvisioningKindV4::HostCatalog)
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
        shape: aos_sandbox::StorageProvisioningSessionIoShapeDataV1,
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
            let coordinates = session.start_host_catalog_coordinates_v2(&header)?;
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
        owner.observe_retained_resource_client_owner_v2(transcript, peer)
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

// Fixed comparison DATA is captured only from the actual protected outcome
// immediately before this same owner's positive native/SDK disposal.
struct QualifiedCatalogDataV2 {
    session: [u8; 32],
    context: [u8; 32],
    generation: u64,
    digest: [u8; 32],
    request: [u8; 32],
    outcome: [u8; 32],
}

/// Borrows the same SDK-qualified Host Session beside its exact disposed receipt.
///
/// There is no public constructor or raw Session getter. The lower native proof
/// remains independent; this borrower supplies captured-key/context qualification
/// to the actual activation caller without claiming that native DATA grants it.
#[doc(hidden)]
pub struct StartHostCatalogQualifiedSessionBorrowV2<'held, 'session> {
    session: &'held mut super::super::super::StartResourceSessionBorrowV4<'session>,
    qualified: &'held QualifiedCatalogDataV2,
}

impl StartHostCatalogQualifiedSessionBorrowV2<'_, '_> {
    /// Rejoins the genuine disposed native owner to this exact protected receipt.
    ///
    /// # Errors
    /// Refuses incomplete native disposal or changed catalog/receipt coordinates.
    pub fn require_native_completion_v2(
        &self,
        native: &aos_sandbox::StartHostCatalogNativeCompletionV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.qualified.session != self.session.inner.transcript.session_binding()
            || self.qualified.context != self.session.inner.transcript.protected_context_digest()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        native.require_disposed_receipt_data_v2(
            self.qualified.generation,
            &self.qualified.digest,
            &self.qualified.request,
            &self.qualified.outcome,
        )
    }
}
