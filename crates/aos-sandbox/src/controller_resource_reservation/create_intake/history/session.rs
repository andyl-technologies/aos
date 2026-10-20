//! Appends C8 only from the actual same-Session prepared request readback.

use super::*;
use aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::controller_use::{
    ControllerSessionReservedBodyDataV1, SESSION_RESERVED_BODY_BYTES_V1,
};
use super::super::ready::use_reserved::{completed_signed_view_v1,
    OriginalCreateStorageSignedV1, reservation::UseReservationOriginalsV1,
    preparation::PreparationOriginalsV1};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake)
struct SessionOriginalsV1 {
    entered: bool,
    demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    body: Option<Result<[u8; SESSION_RESERVED_BODY_BYTES_V1], HistoryErrorV1>>,
    pair: OriginalHistoryPairV1,
    primary: Option<ResultV1<()>>,
    session_post: Option<Result<(), ResourceReservationErrorV1>>,
    complete: bool,
}

impl SessionOriginalsV1 {
    pub(super) fn fixed_inline_receiving_bytes_v1() -> Result<usize, ResourceReservationErrorV1> {
        std::mem::size_of::<Self>().checked_mul(2).and_then(|bytes| bytes.checked_add(
            std::mem::size_of::<SessionAppendBindingV1<'static>>().checked_mul(2)?))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake)
    fn produce_once(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1,
        validated: &root_validated::RootValidatedOriginalsV1,
        reserved: &use_reserved::UseReservedOriginalsV1, signed: &signed::SignedOriginalsV1,
        dispatch: &dispatch::DispatchOriginalsV1, reservation: &mut UseReservationOriginalsV1,
        preparation: &mut PreparationOriginalsV1, session: &Journal,
        request: &AuthenticatedBrokerMethodRequestV1, cutoff: u64, inputs: InputsReadyNativeReceiptDataV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.primary = Some(self.produce_inner(parent, intake, histories, assignment, validated,
            reserved, signed, dispatch, reservation, preparation, session, request, cutoff, inputs,
            controller, source, profile));
        if matches!(self.funding, Some(Ok(()))) && !self.pair.posts_attempted {
            if let Ok(clock) = intake.create_storage_j_data_v1().map(|j| j.clock) {
                self.pair.finish_posts_once(intake, controller, source.journal_ref_v1(), profile,
                    clock, cutoff, HistoryRoleV1::Controller);
            }
        }
        // Even a failed Controller crossing cannot suppress the actual
        // independent Session names/NEXT/end comparison after its readback.
        self.session_post = Some(preparation.finish_request_once(session, controller));
        self.complete = matches!(self.primary, Some(Ok(()))) && self.pair.complete
            && matches!(self.session_post, Some(Ok(()))) && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn produce_inner(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1,
        validated: &root_validated::RootValidatedOriginalsV1,
        reserved: &use_reserved::UseReservedOriginalsV1, signed: &signed::SignedOriginalsV1,
        dispatch: &dispatch::DispatchOriginalsV1, reservation: &mut UseReservationOriginalsV1,
        preparation: &mut PreparationOriginalsV1, session: &Journal,
        request: &AuthenticatedBrokerMethodRequestV1, cutoff: u64, inputs: InputsReadyNativeReceiptDataV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> ResultV1<()> {
        preparation.require_admitted()?;
        self.demand = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            intake.require_create_history_names_peak_v1()?;
            use_history_pair_receiving_demand_v1(SESSION_RESERVED_BODY_BYTES_V1 + RECORD_OVERHEAD_BYTES,
                &controller.create_storage_semantic_append_demand_v1()?)
        })());
        self.funding = Some((|| {
            let demand = *self.demand.as_ref().and_then(|r| r.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            reservation.reserve_pair_receiving_once_v1(demand)?;
            intake.extend_create_storage_use_observers_once(profile, reservation.receiving_mut_v1()?, 6)
        })());
        retained(&self.funding)?;
        self.pair.enter_once(parent, intake, controller, source.journal_ref_v1(), profile, HistoryRoleV1::Controller)?;
        let signed = completed_signed_view_v1(reservation, reserved, signed)?;
        let lane = intake.create_lane()?;
        preparation.read_request_once(session, controller, request, &signed, dispatch, lane, cutoff)?;
        self.body = Some(preparation.body_v1()?.encode());
        let bytes = retained(&self.body)?;
        let row = RecordEnvelopeV1::decode(dispatch.record_v1()?, KeyV1::new(lane, OwnerV1::Controller, 7)?,
            PhaseV1::new(OwnerV1::Controller, 6)?)?;
        let seed = row.coordinates().correlation;
        let binding = SessionAppendBindingV1 { lane, seed, histories, assignment, validated,
            reserved, signed: &signed, dispatch, reservation, body: bytes, preparation, inputs,
            funded: &self.funding,
            demand: *self.demand.as_ref().and_then(|r| r.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)? };
        let clock = intake.create_storage_j_data_v1()?.clock;
        let before = dispatch.position()?;
        self.pair.produce_once(parent, intake, controller, source.journal_ref_v1(), profile,
            HistoryRoleV1::Controller, lane, seed, clock, cutoff, Some((before.next, before.end)),
            bytes, Some(HistorySuccessorBindingV1::Session(&binding)))
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn position(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.pair.after.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn record_v1(&self) -> Result<&[u8], ResourceReservationErrorV1> { self.position()?; Ok(&self.pair.record) }

    pub(in crate::controller_resource_reservation::create_intake)
    fn head_v1(&self) -> Result<&[u8; HEAD_BYTES], ResourceReservationErrorV1> { self.position()?; Ok(&self.pair.head) }

    pub(in crate::controller_resource_reservation::create_intake)
    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.demand).or_else(|| cause(&self.funding)).or_else(|| self.pair.primary_failure())
            .or_else(|| cause(&self.body)).or_else(|| cause(&self.primary)).or_else(|| self.pair.post_failure())
            .or_else(|| cause(&self.session_post))
    }
}

pub(super) struct SessionAppendBindingV1<'held> {
    lane: [u8; 16], seed: [u8; 32],
    histories: &'held CreateStorageOriginalHistoriesV1,
    assignment: &'held assignment::AssignmentPlannedOriginalV1,
    validated: &'held root_validated::RootValidatedOriginalsV1,
    reserved: &'held use_reserved::UseReservedOriginalsV1,
    signed: &'held OriginalCreateStorageSignedV1<'held>,
    dispatch: &'held dispatch::DispatchOriginalsV1,
    reservation: &'held UseReservationOriginalsV1,
    preparation: &'held PreparationOriginalsV1,
    inputs: InputsReadyNativeReceiptDataV1<'held>,
    body: &'held [u8],
    funded: &'held Option<Result<(), ResourceReservationErrorV1>>,
    demand: ResourceVector,
}

impl SessionAppendBindingV1<'_> {
    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        RecordEnvelopeV1::decode(self.dispatch.record_v1().map_err(|_| HistoryErrorV1::Correlation)?,
            KeyV1::new(self.lane, OwnerV1::Controller, 7)?, PhaseV1::new(OwnerV1::Controller, 6)?)
            .map(|row| row.checksum())
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
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        let closed = || JournalError::ProtectedBoundary;
        self.reservation.require_current_state_v1(parent, state).map_err(native_error)?;
        require_j_readback_members_v1(intake, state)?;
        let reserved = self.reserved.native_receipt_v1().map_err(native_error)?;
        require_exact_controller_prefix_v1(state, self.lane,
            &[(1, &self.histories.intent.record), (2, self.assignment.bundle_record_v1().map_err(native_error)?),
                (3, self.inputs.record), (4, self.validated.retained_record_v1().map_err(native_error)?),
                (5, reserved.record), (6, self.signed.record_v1().map_err(native_error)?),
                (7, self.dispatch.record_v1().map_err(native_error)?)],
            self.dispatch.head_v1().map_err(native_error)?)?;
        if intake.create_lane().map_err(native_error)? != self.lane { return Err(closed()); }
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Controller, 8).map_err(|_| closed())?;
        let latest = KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory
            || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != latest.encode() { return Err(closed()); }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key,
            PhaseV1::new(OwnerV1::Controller, 7).map_err(|_| closed())?).map_err(|_| closed())?;
        if envelope.body() != self.body || envelope.coordinates().correlation != self.seed
            || envelope.coordinates().predecessor != self.predecessor().map_err(|_| closed())? { return Err(closed()); }
        let body = ControllerSessionReservedBodyDataV1::decode(envelope.body()).map_err(|_| closed())?;
        if body != self.preparation.body_v1().map_err(native_error)? { return Err(closed()); }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, latest)
            .and_then(|value| value.check_record(latest, envelope)).map_err(|_| closed())
    }
}
