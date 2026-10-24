//! Publishes only the genuine C9 terminal owner and its original returned U.

use super::*;
use super::super::super::history::{CreateStorageWriterPositionV1, outcome::OutcomeOriginalsV1};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::ControllerOutcomeBodyDataV1,
};
use sha2::{Digest as _, Sha256};

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Records C9 only from this actual C8 operation's complete prepared terminal.
    ///
    /// Native independently captures the same Session row and names and checks
    /// the exact retained C8 history/request against its actual terminal append.
    /// No scalar snapshot or parsed receipt supplies completion authority.
    ///
    /// # Errors
    /// Retains absent actual IO/C8/Root/U, changed Session/original history,
    /// resource, packet/model/readback/crossing or independently owed post error.
    #[doc(hidden)]
    pub fn produce_original_storage_outcome_once(&mut self, journal: Option<&Journal>,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() || self.original.owner.storage_use.outcome.started() {
            return Err(CreateStorageReadyClosedV1);
        }
        self.original.owner.storage_use.outcome.enter_once().map_err(|_| CreateStorageReadyClosedV1)?;
        let primary = (|| {
            let entry = (|| {
                self.original.require_operation_currentness_peak_v1(&self.cache)?;
                self.original.owner.root_exchange.require_preparation_terminal_after_v1()?;
                self.original.owner.storage_use.io.completed_extent_v1()?;
                journal.ok_or(ResourceReservationErrorV1::Conflict)?;
                Ok(())
            })();
            let owner = &mut *self.original.owner;
            owner.storage_use.outcome.retain_entry_once(entry).map_err(|_| CreateStorageReadyClosedV1)?;
            let journal = journal.ok_or(CreateStorageReadyClosedV1)?;
            let actual = &mut owner.storage_use;
            let extent = actual.io.completed_extent_v1().map_err(|_| CreateStorageReadyClosedV1)?;
            actual.outcome.produce_once(&owner.parent, &mut owner.intake, &owner.histories, &owner.assignment,
                &actual.validated, &actual.reserved, &actual.signed, &actual.dispatch, &actual.session,
                &mut actual.reservation, &actual.preparation, &owner.root_exchange, journal, extent, outcome,
                self.original.controller, self.original.source, self.original.profile,
                &owner.client_session, socket, transcript).map_err(|_| CreateStorageReadyClosedV1)
        })();
        if primary.is_err() {
            let owner = &mut *self.original.owner;
            let actual = &mut owner.storage_use;
            // This retained original is available after debt solely for the
            // prepaid negative post. It cannot restore U or C9 health.
            if let Ok((_, receiving)) = actual.reservation.split_retained_root_receiving_after_debt_v1() {
                let _ = owner.root_exchange.observe_outcome_entry_refusal_once(&owner.parent, &mut owner.intake,
                    self.original.controller, self.original.source, self.original.profile, &mut self.cache,
                    &actual.outcome, receiving);
            }
        }
        primary
    }
}

pub(in crate::controller_resource_reservation::create_intake)
struct OriginalCreateStorageOutcomeV1<'held> {
    reserved: OriginalCreateStorageUseReservedV1<'held>,
    outcome: &'held OutcomeOriginalsV1,
}

pub(super) fn completed_outcome_view_v1<'held>(reserved: OriginalCreateStorageUseReservedV1<'held>,
    outcome: &'held OutcomeOriginalsV1,
) -> Result<OriginalCreateStorageOutcomeV1<'held>, ResourceReservationErrorV1> {
    reserved.claim_v1()?;
    outcome.position()?;
    Ok(OriginalCreateStorageOutcomeV1 { reserved, outcome })
}

impl CreateStorageUseOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn split_outcome_receiving_v1(&mut self)
        -> Result<(OriginalCreateStorageOutcomeV1<'_>, &mut UseReceivingOriginalsV1), ResourceReservationErrorV1> {
        if self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.outcome.position()?;
        let width = self.reservation.request_shape_bytes_v1()?;
        let (append, receiving) = self.reservation.split_retained_root_receiving_after_debt_v1()?;
        receiving.require_reserved_v1()?;
        let reserved = OriginalCreateStorageUseReservedV1 { append, request_shape_bytes: width, record: &self.reserved };
        Ok((completed_outcome_view_v1(reserved, &self.outcome)?, receiving))
    }
}

impl<'held> OriginalCreateStorageOutcomeV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake)
    fn position_v1(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        self.reserved.claim_v1()?;
        self.outcome.position()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn body_v1(&self) -> Result<ControllerOutcomeBodyDataV1, ResourceReservationErrorV1> { self.outcome.body_v1() }

    pub(in crate::controller_resource_reservation::create_intake)
    fn reserved_v1(&self) -> &OriginalCreateStorageUseReservedV1<'held> { &self.reserved }

    pub(in crate::controller_resource_reservation::create_intake)
    fn request_shape_bytes_v1(&self) -> Result<usize, ResourceReservationErrorV1> { self.reserved.request_shape_bytes_v1() }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> { self.outcome.cutoff_v1() }

    pub(in crate::controller_resource_reservation::create_intake)
    fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'held>, ResourceReservationErrorV1> {
        let position = self.position_v1()?;
        let actual: &'held OutcomeOriginalsV1 = self.outcome;
        Ok(ContinuationNativeReceiptDataV1 { record: actual.record_v1()?, latest_head: *actual.head_v1()?,
            names: position.names, after_next: position.next, after_end: position.end })
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn require_outcome_v1(&self, actual: &AuthenticatedBrokerMethodOutcomeV1) -> Result<(), ResourceReservationErrorV1> {
        self.position_v1()?;
        let body = self.body_v1()?;
        let request = actual.request();
        if body.request_packet != <[u8; 32]>::from(Sha256::digest(request.canonical_packet()))
            || body.outcome_packet != <[u8; 32]>::from(Sha256::digest(actual.canonical_packet()))
            || body.signed_request != request.signed_request_digest() || body.request_id != request.request_id()
            || body.use_claim != self.reserved.claim_v1()?.native_fields().id
            || request.canonical_packet().len() > self.request_shape_bytes_v1()? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}
