//! Records C9 from the real prepared Session terminal and native readback.
//!
//! This retains the independent Session before/after originals and canonical
//! terminal model. The one existing atomic pair owns Controller/source/profile
//! posts; parsed packets or scalar snapshots cannot construct this owner.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::{AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodResultV1, AuthenticatedBrokerOutcomeDirectionV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::ContinuationKindV1,
    outcome::{ControllerOutcomeBodyDataV1, CONTROLLER_OUTCOME_BODY_BYTES_V1},
};
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1, BrokerSessionDurableHistoryV1,
    BrokerSessionDurablePhaseV1};
use aos_sandbox_protocol::authenticated_session::stored_history::{StoredBrokerSessionHistoryV1,
    StoredBrokerSessionHistoryErrorV1, canonical_protocol_key_v1};
use aos_proto::aos::sandbox::local::v1::{BrokerMethod, PrepareStorageCatalogResponse};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};
use crate::journal::{CreateStorageWriterPositionOriginalV1, ProtectedJournalPreopenReplayExtentV1,
    broker_session_receiving::{StorageSessionGeometryRefusalV1, schema_demand}};
use super::super::ready::{root_exchange::RootExchangeOriginalsV1,
    use_reserved::{completed_signed_view_v1, OriginalCreateStorageSignedV1,
        reservation::UseReservationOriginalsV1, preparation::PreparationOriginalsV1}};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake)
struct OutcomeOriginalsV1 {
    entered: bool,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    association: Option<Result<(), super::super::ready::client_session::ClientSessionAssociationErrorV1>>,
    demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    before: CreateStorageWriterPositionOriginalV1,
    resident_width: Option<Result<u64, JournalError>>,
    extent: Option<Result<ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    schema: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    schema_funding: Option<Result<(), ResourceReservationErrorV1>>,
    stored: Option<Result<StoredBrokerSessionHistoryV1, StoredBrokerSessionHistoryErrorV1>>,
    history: Option<Result<BrokerSessionDurableHistoryV1, aos_sandbox_broker_session_protocol::BrokerSessionDurableError>>,
    response: Option<Result<PrepareStorageCatalogResponse, buffa::DecodeError>>,
    body_data: Option<Result<ControllerOutcomeBodyDataV1, JournalError>>,
    body: Option<Result<[u8; CONTROLLER_OUTCOME_BODY_BYTES_V1], HistoryErrorV1>>,
    cutoff: Option<u64>,
    pair: OriginalHistoryPairV1,
    pair_production_entered: bool,
    primary: Option<ResultV1<()>>,
    after: CreateStorageWriterPositionOriginalV1,
    session_post: Option<Result<(), JournalError>>,
    complete: bool,
}

impl OutcomeOriginalsV1 {
    pub(super) fn fixed_inline_receiving_bytes_v1() -> Result<usize, ResourceReservationErrorV1> {
        std::mem::size_of::<Self>().checked_mul(2).and_then(|bytes| bytes.checked_add(
            std::mem::size_of::<OutcomeAppendBindingV1<'static>>().checked_mul(2)?))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake)
    fn enter_once(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn retain_entry_once(&mut self, result: Result<(), ResourceReservationErrorV1>)
        -> Result<(), ResourceReservationErrorV1> {
        if !self.entered || self.entry.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.entry = Some(result);
        retained(&self.entry).map(|_| ()).map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn produce_once(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1, validated: &root_validated::RootValidatedOriginalsV1,
        reserved: &use_reserved::UseReservedOriginalsV1, signed: &signed::SignedOriginalsV1,
        dispatch: &dispatch::DispatchOriginalsV1, session: &session::SessionOriginalsV1,
        reservation: &mut UseReservationOriginalsV1, preparation: &PreparationOriginalsV1,
        root: &RootExchangeOriginalsV1, terminal_journal: &Journal,
        terminal_extent: &ProtectedJournalPreopenReplayExtentV1, outcome: &AuthenticatedBrokerMethodOutcomeV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        client: &super::super::ready::client_session::ClientSessionOriginalsV1,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.entered || !matches!(self.entry, Some(Ok(()))) || self.primary.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.association = Some(client.require_completed_association_v1(terminal_journal, socket, transcript));
        self.primary = Some((|| {
            self.association.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.produce_inner(parent, intake, histories, assignment, validated, reserved,
            signed, dispatch, session, reservation, preparation, root, terminal_journal, terminal_extent,
            outcome, controller, source, profile)
        })());
        if matches!(self.funding, Some(Ok(()))) && !self.pair.posts_attempted {
            if let (Ok(clock), Some(cutoff)) = (intake.create_storage_j_data_v1().map(|j| j.clock), self.cutoff) {
                self.pair.finish_posts_once(intake, controller, source.journal_ref_v1(), profile,
                    clock, cutoff, HistoryRoleV1::Controller);
            }
        }
        if self.before_entered() {
            self.after.capture_controller_storage_client_once(terminal_journal, controller);
            self.session_post = Some((|| {
                if self.before.position()? != self.after.position()? { return Err(JournalError::ProtectedBoundary); }
                Ok(())
            })());
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && self.pair.complete
            && matches!(self.session_post, Some(Ok(()))) && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn before_entered(&self) -> bool { self.extent.is_some() || self.before.failure().is_some() }

    fn produce_inner(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1, validated: &root_validated::RootValidatedOriginalsV1,
        reserved: &use_reserved::UseReservedOriginalsV1, signed: &signed::SignedOriginalsV1,
        dispatch: &dispatch::DispatchOriginalsV1, session: &session::SessionOriginalsV1,
        reservation: &mut UseReservationOriginalsV1, preparation: &PreparationOriginalsV1,
        root: &RootExchangeOriginalsV1, terminal_journal: &Journal,
        terminal_extent: &ProtectedJournalPreopenReplayExtentV1, outcome: &AuthenticatedBrokerMethodOutcomeV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> ResultV1<()> {
        root.require_preparation_terminal_after_v1()?;
        self.cutoff = Some(root.preparation_cutoff_v1()?);
        self.demand = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            intake.require_create_history_names_peak_v1()?;
            let pair = use_history_pair_receiving_demand_v1(CONTROLLER_OUTCOME_BODY_BYTES_V1 + RECORD_OVERHEAD_BYTES,
                &controller.create_storage_semantic_append_demand_v1()?)?;
            let names = crate::journal::create_storage_name_peak_demand_v1()?;
            pair.checked_add(names)?.checked_add(names).map_err(ResourceReservationErrorV1::Accounting)
        })());
        self.funding = Some((|| {
            let demand = *self.demand.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            reservation.reserve_pair_receiving_once_v1(demand)?;
            intake.extend_create_storage_use_observers_once(profile, reservation.receiving_mut_v1()?, 6)
        })());
        retained(&self.funding)?;
        self.pair.enter_once(parent, intake, controller, source.journal_ref_v1(), profile, HistoryRoleV1::Controller)?;
        self.before.capture_controller_storage_client_once(terminal_journal, controller);
        self.resident_width = Some(terminal_journal.held_materialized_encoding_bytes_v1());
        self.extent = Some((|| {
            let physical = self.before.position()?.end;
            let resident = self.resident_width.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                terminal_extent.limits, physical.max(resident))
        })());
        if let Some(Ok(extent)) = self.extent.as_ref() { self.schema = Some(schema_demand(extent)); }
        self.schema_funding = Some((|| {
            let demand = self.schema.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            reservation.receiving_mut_v1()?.reserve_once(demand)
        })());
        retained(&self.schema_funding)?;
        let signed = completed_signed_view_v1(reservation, reserved, signed)?;
        let lane = intake.create_lane()?;
        self.body_data = Some(self.read_terminal_once(terminal_journal, preparation, &signed, root, outcome, lane));
        let body = *retained(&self.body_data)?;
        self.cutoff = Some(self.cutoff.ok_or(ResourceReservationErrorV1::Conflict)?
            .min(self.response.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?.preparation_expires_boottime_nanoseconds));
        self.body = Some(body.encode());
        let bytes = retained(&self.body)?;
        let previous = RecordEnvelopeV1::decode(session.record_v1()?, KeyV1::new(lane, OwnerV1::Controller, 8)?,
            PhaseV1::new(OwnerV1::Controller, 7)?)?;
        let seed = previous.coordinates().correlation;
        let binding = OutcomeAppendBindingV1 { lane, seed, histories, assignment, validated, reserved,
            signed: &signed, dispatch, session, reservation, body: bytes, actual: body,
            inputs: root.inputs_ready_receipt_v1()?, funded: &self.funding,
            demand: *self.demand.as_ref().and_then(|result| result.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)? };
        let clock = intake.create_storage_j_data_v1()?.clock;
        let before = session.position()?;
        self.pair_production_entered = true;
        self.pair.produce_once(parent, intake, controller, source.journal_ref_v1(), profile,
            HistoryRoleV1::Controller, lane, seed, clock, self.cutoff.ok_or(ResourceReservationErrorV1::Conflict)?,
            Some((before.next, before.end)), bytes, Some(HistorySuccessorBindingV1::Outcome(&binding)))
    }

    fn read_terminal_once(&mut self, journal: &Journal, preparation: &PreparationOriginalsV1,
        signed: &OriginalCreateStorageSignedV1<'_>, root: &RootExchangeOriginalsV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1, lane: [u8; 16],
    ) -> Result<ControllerOutcomeBodyDataV1, JournalError> {
        let closed = || JournalError::ProtectedBoundary;
        journal.ensure_healthy()?;
        let position = self.before.position()?;
        let request = outcome.request();
        let (reserved_stored, reserved_history) = preparation.prepared_snapshot_v1().map_err(native_error)?;
        let reserved_head = reserved_history.head().map_err(|_| closed())?;
        if outcome.method() != BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || request.canonical_packet() != reserved_head.request_packet()
            || request.request_id() != signed.request_id_v1().map_err(native_error)?
            || request.canonical_packet().len() > signed.request_shape_bytes_v1().map_err(native_error)?
            || outcome.canonical_packet().len() > usize::try_from(request.maximum_response_bytes()).map_err(|_| closed())? {
            return Err(closed());
        }
        let key = canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage);
        let stored = journal.get(crate::RecordNamespace::BrokerSessionTraffic, &key).ok_or_else(closed)?;
        self.stored = Some(StoredBrokerSessionHistoryV1::decode(&key, stored));
        let stored = self.stored.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        self.history = Some(BrokerSessionDurableHistoryV1::decode(&stored.history));
        let history = self.history.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        let head = history.head().map_err(|_| closed())?;
        let prefix = reserved_history.records();
        if stored.endpoint != reserved_stored.endpoint || stored.endpoint != aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1::Client
            || stored.stable_endpoint_identity != reserved_stored.stable_endpoint_identity
            || stored.endpoint_publication != reserved_stored.endpoint_publication || stored.checkpoint != reserved_stored.checkpoint
            || stored.current_catalog != head.protected_bindings().current_catalog()
            || stored.generation <= reserved_stored.generation || history.head_commitment() != stored.current_head
            || history.records().len() != prefix.len().checked_add(1).ok_or_else(closed)?
            || history.records().get(..prefix.len()) != Some(prefix)
            || head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.request_packet() != request.canonical_packet() || head.outcome_packet() != Some(outcome.canonical_packet())
            || head.session_binding() != request.session_binding() || head.client_sequence() != request.client_sequence()
            || head.broker_sequence() != outcome.broker_sequence()
            || head.request_semantic_binding() != request.semantic_commitment()
            || head.outcome_semantic_binding() != outcome.semantic_commitment() {
            return Err(closed());
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else { return Err(closed()); };
        self.response = Some(PrepareStorageCatalogResponse::decode(&mut exact_body.as_slice()));
        let response = self.response.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(closed)?;
        let bound = root.borrow_signed_bound_v1(signed).map_err(native_error)?;
        let admitted = signed.body_v1(lane).map_err(native_error)?.admitted
            .record_data(lane, ContinuationKindV1::UseAdmitted).map_err(|_| closed())?;
        Ok(ControllerOutcomeBodyDataV1 {
            signed_bound: bound.receipt_v1().map_err(native_error)?.record_data(lane, ContinuationKindV1::SignedBound)
                .map_err(|_| closed())?.checksum(), use_admitted: admitted.checksum(),
            use_claim: signed.reserved_v1().claim_v1().map_err(native_error)?.native_fields().id,
            request_packet: Sha256::digest(request.canonical_packet()).into(),
            outcome_packet: Sha256::digest(outcome.canonical_packet()).into(),
            signed_request: request.signed_request_digest(),
            prepared_receipt: aos_sandbox_protocol::semantics::storage_prepare::
                storage_prepared_receipt_digest_v1(&response.non_authorizing_receipt),
            session_names: position.names, session_after_next: position.next, session_after_end: position.end,
            session_head: stored.current_head, session_generation: stored.generation,
            session_revision: head.revision(), session_commitment: head.commitment().map_err(|_| closed())?,
            request_id: request.request_id(),
        })
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn position(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.pair.after.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn record_v1(&self) -> Result<&[u8], ResourceReservationErrorV1> { self.position()?; Ok(&self.pair.record) }

    pub(in crate::controller_resource_reservation::create_intake)
    fn head_v1(&self) -> Result<&[u8; HEAD_BYTES], ResourceReservationErrorV1> { self.position()?; Ok(&self.pair.head) }

    pub(in crate::controller_resource_reservation::create_intake)
    fn body_v1(&self) -> Result<ControllerOutcomeBodyDataV1, ResourceReservationErrorV1> {
        self.position()?;
        self.body_data.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> { self.position()?; self.cutoff.ok_or(ResourceReservationErrorV1::Conflict) }

    pub(in crate::controller_resource_reservation::create_intake)
    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.entry).or_else(|| cause(&self.association)).or_else(|| cause(&self.demand)).or_else(|| cause(&self.funding)).or_else(|| self.pair.primary_failure())
            .or_else(|| self.before.failure()).or_else(|| cause(&self.resident_width)).or_else(|| cause(&self.extent)).or_else(|| cause(&self.schema))
            .or_else(|| cause(&self.schema_funding)).or_else(|| cause(&self.stored)).or_else(|| cause(&self.history))
            .or_else(|| cause(&self.response)).or_else(|| cause(&self.body_data)).or_else(|| cause(&self.body))
            // Only the final pair invocation can project its actual post cause
            // into a coarse outer primary marker. Earlier semantic failures
            // retain priority over independently owed later pair posts.
            .or_else(|| self.pair_production_entered.then(|| self.pair.failure()).flatten())
            .or_else(|| cause(&self.primary)).or_else(|| self.pair.post_failure()).or_else(|| self.after.failure())
            .or_else(|| cause(&self.session_post))
    }
}

pub(super) struct OutcomeAppendBindingV1<'held> {
    lane: [u8; 16], seed: [u8; 32], histories: &'held CreateStorageOriginalHistoriesV1,
    assignment: &'held assignment::AssignmentPlannedOriginalV1,
    validated: &'held root_validated::RootValidatedOriginalsV1, reserved: &'held use_reserved::UseReservedOriginalsV1,
    signed: &'held OriginalCreateStorageSignedV1<'held>, dispatch: &'held dispatch::DispatchOriginalsV1,
    session: &'held session::SessionOriginalsV1, reservation: &'held UseReservationOriginalsV1,
    body: &'held [u8], actual: ControllerOutcomeBodyDataV1,
    inputs: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'held>,
    funded: &'held Option<Result<(), ResourceReservationErrorV1>>, demand: ResourceVector,
}

impl OutcomeAppendBindingV1<'_> {
    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        RecordEnvelopeV1::decode(self.session.record_v1().map_err(|_| HistoryErrorV1::Correlation)?,
            KeyV1::new(self.lane, OwnerV1::Controller, 8)?, PhaseV1::new(OwnerV1::Controller, 7)?)
            .map(|record| record.checksum())
    }

    pub(super) fn require_prepaid_v1(&self, demand: ResourceVector) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.funded, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.demand.checked_sub(demand)?;
        self.reservation.require_pair_receiving_v1(self.demand)
    }

    pub(super) fn require_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        journal: &Journal, transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        journal.ensure_healthy()?;
        self.require_state_successor(parent, intake, state, transaction)
    }

    pub(super) fn require_state_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State, transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        let closed = || JournalError::ProtectedBoundary;
        self.reservation.require_current_state_v1(parent, state).map_err(native_error)?;
        require_j_readback_members_v1(intake, state)?;
        let reserved = self.reserved.native_receipt_v1().map_err(native_error)?;
        require_exact_controller_prefix_v1(state, self.lane,
            &[(1, &self.histories.intent.record), (2, self.assignment.bundle_record_v1().map_err(native_error)?),
                (3, self.inputs.record), (4, self.validated.retained_record_v1().map_err(native_error)?),
                (5, reserved.record), (6, self.signed.record_v1().map_err(native_error)?),
                (7, self.dispatch.record_v1().map_err(native_error)?), (8, self.session.record_v1().map_err(native_error)?)],
            self.session.head_v1().map_err(native_error)?)?;
        if intake.create_lane().map_err(native_error)? != self.lane { return Err(closed()); }
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Controller, 9).map_err(|_| closed())?;
        let latest = KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory
            || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != latest.encode() { return Err(closed()); }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key,
            PhaseV1::new(OwnerV1::Controller, 8).map_err(|_| closed())?).map_err(|_| closed())?;
        if envelope.body() != self.body || envelope.coordinates().correlation != self.seed
            || envelope.coordinates().predecessor != self.predecessor().map_err(|_| closed())?
            || ControllerOutcomeBodyDataV1::decode(envelope.body()).map_err(|_| closed())? != self.actual { return Err(closed()); }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, latest)
            .and_then(|value| value.check_record(latest, envelope)).map_err(|_| closed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_pair_post_cause_precedes_its_outer_projection() {
        let mut actual = OutcomeOriginalsV1::default();
        actual.pair_production_entered = true;
        actual.pair.after = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(5))));
        actual.primary = Some(Err(JournalError::ProtectedBoundary.into()));
        let original = actual.pair.post_failure().unwrap();

        let returned = actual.failure().unwrap();

        assert!(std::ptr::eq(returned, original));
        assert!(matches!(returned.downcast_ref::<JournalError>(),
            Some(JournalError::Io(error)) if error.raw_os_error() == Some(5)));
    }

    #[test]
    fn earlier_terminal_failure_precedes_independently_owed_pair_post() {
        let mut actual = OutcomeOriginalsV1::default();
        actual.primary = Some(Err(JournalError::ProtectedBoundary.into()));
        actual.pair.after = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(5))));
        let original = actual.primary.as_ref().unwrap().as_ref().unwrap_err();

        let returned = actual.failure().unwrap();

        // Compare the retained concrete error, not duplicated trait vtables.
        let returned = returned.downcast_ref::<super::super::HistoryProductionErrorV1>().unwrap();
        assert!(std::ptr::eq(returned, original));
        assert!(actual.pair.post_failure().is_some());
    }
}
