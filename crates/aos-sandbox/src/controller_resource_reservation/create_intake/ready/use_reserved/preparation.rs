//! Retains same-U Prepare admission and actual fixed Session request readback.
//!
//! The native caller gates C7/Root4 first. Dominant existing request/replay
//! suppliers are admitted before the shared Session signer/CAS or these bounded
//! decoders. Names and snapshot fields come from the same real held Journal.

use super::*;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1,
    BrokerSessionDurableHistoryV1, BrokerSessionDurablePhaseV1};
use aos_sandbox_protocol::authenticated_session::{
    all_methods::AuthenticatedBrokerMethodRequestV1,
    stored_history::{StoredBrokerSessionHistoryV1, StoredBrokerSessionHistoryErrorV1, canonical_protocol_key_v1},
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::controller_use::ControllerSessionReservedBodyDataV1;
use crate::journal::{CreateStorageWriterPositionOriginalV1, JournalError};
use super::super::client_session::{ClientSessionOriginalsV1, ClientSessionAssociationErrorV1};
use super::super::outcome_receiving::{OutcomeReplayReceivingOriginalsV1, OutcomeReplayRosterV1};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake)
struct PreparationOriginalsV1 {
    entered: bool,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    association: Option<Result<(), ClientSessionAssociationErrorV1>>,
    sampler: OutcomeReplayReceivingOriginalsV1,
    request_demand: Option<Result<ResourceVector, crate::journal::broker_session_receiving::StorageSessionGeometryRefusalV1>>,
    request_funding: Option<Result<(), ResourceReservationErrorV1>>,
    admitted: bool,
    finished: bool,
    request_shape_bytes: Option<usize>,
    before: CreateStorageWriterPositionOriginalV1,
    stored: Option<Result<StoredBrokerSessionHistoryV1, StoredBrokerSessionHistoryErrorV1>>,
    durable: Option<Result<BrokerSessionDurableHistoryV1, aos_sandbox_broker_session_protocol::BrokerSessionDurableError>>,
    commitment: Option<Result<[u8; 32], aos_sandbox_broker_session_protocol::BrokerSessionDurableError>>,
    readback: Option<Result<ControllerSessionReservedBodyDataV1, JournalError>>,
    after: CreateStorageWriterPositionOriginalV1,
    after_result: Option<Result<(), JournalError>>,
    closed: Option<ResourceReservationErrorV1>,
}

pub(in crate::controller_resource_reservation)
fn preparation_originals_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::Conflict;
    let bytes = std::mem::size_of::<PreparationOriginalsV1>().checked_mul(2).ok_or_else(invalid)?;
    let names = crate::journal::create_storage_name_peak_demand_v1()?;
    // Two distinct retained Session name observations coexist with the actual
    // C8 pair's independently funded original name/post engine.
    let mut demand = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?);
    for _ in 0..2 {
        demand = demand.checked_add(names)?;
    }
    demand.checked_add(OutcomeReplayReceivingOriginalsV1::fixed_receiving_demand_v1()?)
        .map_err(ResourceReservationErrorV1::Accounting)
}

impl PreparationOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake)
    fn admit_fixed_once(&mut self, reservation: &mut reservation::UseReservationOriginalsV1)
        -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.request_shape_bytes = Some(reservation.request_shape_bytes_v1()?);
        self.fixed = Some(preparation_originals_receiving_demand_v1()
            .and_then(|demand| reservation.receiving_mut_v1()?.reserve_once(demand)));
        self.require_fixed()
    }

    fn require_fixed(&self) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.fixed, Some(Ok(()))) || self.failure().is_some() {
            Err(ResourceReservationErrorV1::Conflict)
        } else { Ok(()) }
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn admit_session_once(&mut self, client: &ClientSessionOriginalsV1,
        receiving: &mut receiving::UseReceivingOriginalsV1, request_shape_bytes: usize, journal: &Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_fixed()?;
        if self.association.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.association = Some(client.require_completed_association_v1(journal, socket, transcript));
        if !matches!(self.association, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.sampler.capture_once(journal, OutcomeReplayRosterV1::CreateSigning)?;
        let replay = self.sampler.demand_v1()?;
        let paid = receiving.reserve_once(replay);
        self.sampler.retain_admission_once(paid)?;
        self.request_shape_bytes = Some(request_shape_bytes);
        self.request_demand = Some(crate::journal::broker_session_receiving::
            storage_create_prepare_client_request_demand_v1(self.sampler.captured_extent_v1()?,
                request_shape_bytes));
        self.request_funding = Some((|| {
            let demand = self.request_demand.as_ref().and_then(|r| r.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            receiving.reserve_once(demand)
        })());
        self.admitted = matches!(self.request_funding, Some(Ok(()))) && self.failure().is_none();
        self.require_admitted()
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn require_admitted(&self) -> Result<(), ResourceReservationErrorV1> {
        if !self.admitted || self.failure().is_some() { Err(ResourceReservationErrorV1::Conflict) } else { Ok(()) }
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn read_request_once(&mut self, journal: &Journal, controller: &Journal,
        request: &AuthenticatedBrokerMethodRequestV1, signed: &OriginalCreateStorageSignedV1<'_>,
        dispatch: &super::super::super::history::dispatch::DispatchOriginalsV1,
        lane: [u8; 16], cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_admitted()?;
        if self.readback.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.before.capture_controller_storage_client_once(journal, controller);
        self.readback = Some((|| {
            journal.ensure_healthy()?;
            let position = self.before.position()?;
            let maximum = signed.request_shape_bytes_v1().map_err(native)?;
            let bound = signed.body_v1(lane).map_err(native)?.bundle_data_v1(lane, maximum)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if request.canonical_packet().len() > maximum || request.exact_body() != bound.request_body
                || request.request_id() != signed.request_id_v1().map_err(native)?
                || request.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1::ClientSend
                || request.method() != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                || request.deadline_boottime_nanoseconds() != cutoff {
                return Err(JournalError::ProtectedBoundary);
            }
            let key = canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage);
            let stored = journal.get(crate::RecordNamespace::BrokerSessionTraffic, &key)
                .ok_or(JournalError::ProtectedBoundary)?;
            self.stored = Some(StoredBrokerSessionHistoryV1::decode(&key, stored));
            let stored = self.stored.as_ref().and_then(|r| r.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            if stored.endpoint != aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Client {
                return Err(JournalError::ProtectedBoundary);
            }
            self.durable = Some(BrokerSessionDurableHistoryV1::decode(&stored.history));
            let history = self.durable.as_ref().and_then(|r| r.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            let head = history.head().map_err(|_| JournalError::ProtectedBoundary)?;
            if history.head_commitment() != stored.current_head
                || head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
                || head.request_packet() != request.canonical_packet()
                || head.session_binding() != request.session_binding()
                || head.client_sequence() != request.client_sequence() {
                return Err(JournalError::ProtectedBoundary);
            }
            self.commitment = Some(head.commitment());
            let commitment = self.commitment.as_ref().and_then(|r| r.as_ref().ok()).copied()
                .ok_or(JournalError::ProtectedBoundary)?;
            let row = aos_sandbox_protocol::domain_ledger::create_storage_history::RecordEnvelopeV1::decode(
                dispatch.record_v1().map_err(native)?,
                aos_sandbox_protocol::domain_ledger::create_storage_history::KeyV1::new(lane,
                    aos_sandbox_protocol::domain_ledger::create_storage_history::OwnerV1::Controller, 7)
                    .map_err(|_| JournalError::ProtectedBoundary)?,
                aos_sandbox_protocol::domain_ledger::create_storage_history::PhaseV1::new(
                    aos_sandbox_protocol::domain_ledger::create_storage_history::OwnerV1::Controller, 6)
                    .map_err(|_| JournalError::ProtectedBoundary)?).map_err(|_| JournalError::ProtectedBoundary)?;
            Ok(ControllerSessionReservedBodyDataV1 { dispatch_bound: row.checksum(),
                session_binding: request.session_binding(), request_id: request.request_id(),
                signed_request: request.signed_request_digest(), client_sequence: request.client_sequence(),
                generation: stored.generation, head: stored.current_head, revision: head.revision(), commitment,
                names: position.names, after_next: position.next, after_end: position.end })
        })());
        if matches!(self.readback, Some(Ok(_))) { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn body_v1(&self) -> Result<ControllerSessionReservedBodyDataV1, ResourceReservationErrorV1> {
        self.readback.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn prepared_snapshot_v1(&self)
        -> Result<(&StoredBrokerSessionHistoryV1, &BrokerSessionDurableHistoryV1), ResourceReservationErrorV1> {
        self.body_v1()?;
        if !matches!(self.after_result, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        Ok((self.stored.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?,
            self.durable.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?))
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn finish_request_once(&mut self, journal: &Journal, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.after.capture_controller_storage_client_once(journal, controller);
        self.after_result = Some((|| {
            let expected = self.before.position()?;
            let actual = self.after.position()?;
            if expected != actual { return Err(JournalError::ProtectedBoundary); }
            Ok(())
        })());
        if matches!(self.after_result, Some(Ok(()))) && self.failure().is_none() { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        cause(&self.fixed).or_else(|| cause(&self.association)).or_else(|| self.sampler.failure())
            .or_else(|| cause(&self.request_demand)).or_else(|| cause(&self.request_funding))
            .or_else(|| self.before.failure()).or_else(|| cause(&self.stored))
            .or_else(|| cause(&self.durable)).or_else(|| cause(&self.commitment))
            .or_else(|| cause(&self.readback)).or_else(|| self.after.failure())
            .or_else(|| cause(&self.after_result)).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn cause<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref().and_then(|r| r.as_ref().err()).map(|cause| cause as _)
}

fn native(error: ResourceReservationErrorV1) -> JournalError {
    crate::controller_resource_reservation::create_intake_append::native_error(error)
}

/// Borrows the exact already-signed C6 request proposal as comparison DATA.
#[doc(hidden)]
pub struct CreateStoragePrepareInputsDataV1<'held> {
    /// The actual signed canonical plan retained by C6.
    pub plan: &'held [u8],
    /// The actual detached canonical plan signature retained by C6.
    pub signature: &'held [u8],
    /// The exact Root-bound Prepare body, including its unchanged header.
    pub request_body: &'held [u8],
    /// The stable ID derived by the sole protected request builder.
    pub request_id: [u8; 16],
    /// The exact normalized full authenticated request width already used by U.
    pub request_shape_bytes: usize,
    /// The original accepted/RootHello minimum, without renewal.
    pub cutoff: u64,
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Admits actual same-Session Prepare work beside this completed C7 and U.
    ///
    /// The fixed owner and reached Session request/replay work are paid before
    /// the shared Security signer or CAS can be entered. A failed admission
    /// leaves its already-prepaid Root after-check to the mandatory finish.
    ///
    /// # Errors
    /// Retains reentry, incomplete C7/Root4/U, foreign Session, resource refusal,
    /// changed native/currentness or an independently owed Root post failure.
    #[doc(hidden)]
    pub fn admit_original_storage_preparation_once(&mut self, journal: Option<&Journal>,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), CreateStorageReadyClosedV1> {
        if self.failure().is_some() { return Err(CreateStorageReadyClosedV1); }
        self.original.require_operation_currentness_peak_v1(&self.cache).map_err(|_| CreateStorageReadyClosedV1)?;
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        actual.dispatch.position().map_err(|_| CreateStorageReadyClosedV1)?;
        let fixed = actual.preparation.admit_fixed_once(&mut actual.reservation);
        let width = actual.preparation.request_shape_bytes.ok_or(CreateStorageReadyClosedV1)?;
        let (append, receiving) = actual.reservation.split_retained_root_receiving_after_debt_v1()
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let reserved = OriginalCreateStorageUseReservedV1 { append, request_shape_bytes: width, record: &actual.reserved };
        let signed = OriginalCreateStorageSignedV1::from_original_reserved_v1(reserved, &actual.signed)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        fixed.map_err(|_| CreateStorageReadyClosedV1)?;
        let before = owner.root_exchange.observe_preparation_root_once(&owner.parent, &mut owner.intake,
            self.original.controller, self.original.source, self.original.profile, &mut self.cache,
            &signed, &actual.dispatch, &actual.session, receiving);
        let admitted = match (before, journal) {
            (Ok(()), Some(journal)) => actual.preparation.admit_session_once(
                &owner.client_session, receiving, width, journal, socket, transcript),
            _ => Err(ResourceReservationErrorV1::Conflict),
        };
        admitted.map_err(|_| CreateStorageReadyClosedV1)
    }

    /// Borrows the exact original signed proposal only after actual U admission.
    ///
    /// # Errors
    /// Refuses incomplete/failed preparation, changed signed owner or Root post.
    #[doc(hidden)]
    pub fn original_storage_prepare_inputs_v1(&self) -> Result<CreateStoragePrepareInputsDataV1<'_>, CreateStorageReadyClosedV1> {
        let owner = &*self.original.owner;
        owner.storage_use.preparation.require_admitted().map_err(|_| CreateStorageReadyClosedV1)?;
        let signed = owner.storage_use.borrow_completed_signed_v1().map_err(|_| CreateStorageReadyClosedV1)?;
        let lane = owner.intake.create_lane().map_err(|_| CreateStorageReadyClosedV1)?;
        let width = signed.request_shape_bytes_v1().map_err(|_| CreateStorageReadyClosedV1)?;
        let body = signed.body_v1(lane).map_err(|_| CreateStorageReadyClosedV1)?;
        let bundle = body.bundle_data_v1(lane, width).map_err(|_| CreateStorageReadyClosedV1)?;
        Ok(CreateStoragePrepareInputsDataV1 { plan: bundle.plan, signature: bundle.signature,
            request_body: bundle.request_body, request_id: signed.request_id_v1().map_err(|_| CreateStorageReadyClosedV1)?,
            request_shape_bytes: width, cutoff: owner.root_exchange.preparation_cutoff_v1().map_err(|_| CreateStorageReadyClosedV1)? })
    }

    /// Records C8 from actual same-Session reservation and always owes Root's post.
    ///
    /// Security supplies its actual authenticated request after the sole request
    /// signer/CAS/readback engine. Native independently captures the fixed
    /// Session row, validates its packet, and samples actual names/NEXT/end.
    /// An absent request is a refusal, never a synthetic positive reservation.
    ///
    /// # Errors
    /// Retains request/CAS absence, changed native or stored bytes, resource,
    /// Controller append/readback, cutoff or independent Root post failure.
    #[doc(hidden)]
    pub fn finish_original_storage_request_once(&mut self, journal: Option<&Journal>,
        request: Option<&AuthenticatedBrokerMethodRequestV1>,
    ) -> Result<(), CreateStorageReadyClosedV1> {
        let owner = &mut *self.original.owner;
        let actual = &mut owner.storage_use;
        if !actual.preparation.entered || actual.preparation.finished {
            return Err(CreateStorageReadyClosedV1);
        }
        actual.preparation.finished = true;
        let primary = (|| {
            let cutoff = owner.root_exchange.preparation_cutoff_v1()?;
            match (journal, request) {
            (Some(journal), Some(request)) => {
                let inputs = owner.root_exchange.inputs_ready_receipt_v1()?;
                actual.session.produce_once(&owner.parent, &mut owner.intake, &owner.histories,
                    &owner.assignment, &actual.validated, &actual.reserved, &actual.signed,
                    &actual.dispatch, &mut actual.reservation, &mut actual.preparation,
                    journal, request, cutoff, inputs,
                    self.original.controller, self.original.source, self.original.profile)
            }
            _ => Err(ResourceReservationErrorV1::Conflict),
            }
        })();
        // The original reserve, P and raw receiving ledger remain lendable for
        // this owed post after a later U debit error. No new primary uses it.
        let width = actual.preparation.request_shape_bytes.ok_or(CreateStorageReadyClosedV1)?;
        let (append, receiving) = actual.reservation.split_retained_root_receiving_after_debt_v1()
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let reserved = OriginalCreateStorageUseReservedV1 { append, request_shape_bytes: width, record: &actual.reserved };
        let signed = OriginalCreateStorageSignedV1::from_original_reserved_v1(reserved, &actual.signed)
            .map_err(|_| CreateStorageReadyClosedV1)?;
        let after = if owner.root_exchange.preparation_before_entered_v1() {
            owner.root_exchange.observe_preparation_root_once(&owner.parent, &mut owner.intake,
                self.original.controller, self.original.source, self.original.profile, &mut self.cache,
                &signed, &actual.dispatch, &actual.session, receiving)
        } else {
            owner.root_exchange.observe_preparation_refusal_once(&owner.parent, &mut owner.intake,
                self.original.controller, self.original.source, self.original.profile, &mut self.cache,
                &signed, &actual.dispatch, &actual.session, receiving)
        };
        if primary.is_err() || after.is_err() {
            actual.preparation.closed.get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(CreateStorageReadyClosedV1);
        }
        owner.root_exchange.require_preparation_after_v1().map_err(|_| CreateStorageReadyClosedV1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_request_error_precedes_later_native_session_post_failure() {
        let mut original = PreparationOriginalsV1::default();
        original.stored = Some(Err(StoredBrokerSessionHistoryErrorV1::Invalid));
        original.after_result = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(5))));

        let first = original.failure().unwrap();

        assert!(first.downcast_ref::<StoredBrokerSessionHistoryErrorV1>().is_some());
        assert!(original.body_v1().is_err());
        assert!(original.require_admitted().is_err());
    }
}

impl OriginalCreateStorageReadyV1<'_, '_> {
    /// Borrows the actual completed Root preparation bookend's paired clock.
    ///
    /// # Errors
    /// Refuses an unpaid/incomplete or failed original preparation bookend.
    #[doc(hidden)]
    pub fn original_storage_preparation_clock_v1(&self)
        -> Result<aos_sandbox_core::RawPairedClockSample, CreateStorageReadyClosedV1> {
        self.original.owner.root_exchange.preparation_clock_v1().map_err(|_| CreateStorageReadyClosedV1)
    }
}
