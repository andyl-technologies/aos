//! Appends UseReserved through the original pair engine under the actual U.
//!
//! A complete typed bank reserve/readback owns the only receiving ledger. The
//! original Root authorization and exact prefix remain borrowed through this
//! append and every independently owed native/profile/clock post.

use super::*;
use super::super::ready::root_exchange::OriginalCreateStorageRootUseAuthorizationV1;
use super::super::ready::use_reserved::reservation::UseReservationOriginalsV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    use_authorized::UseAuthorizedNativeReceiptDataV1, transport::FRAME_HEADER_BYTES,
    use_reserved::{UseReservedBodyDataV1, UseReservedNativeReceiptDataV1,
        USE_RESERVED_BODY_BYTES_V1, USE_RESERVED_RECORD_BYTES_V1}};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct UseReservedOriginalsV1 {
    entered: bool,
    demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    encoded: Option<Result<[u8; USE_RESERVED_BODY_BYTES_V1], HistoryProductionErrorV1>>,
    pair: OriginalHistoryPairV1,
    primary: Option<ResultV1<()>>,
    complete: bool,
}

impl UseReservedOriginalsV1 {
    // One common concrete inline recipe also bounds later same-engine pairs.
    pub(super) fn fixed_inline_receiving_bytes_v1() -> Result<usize, ResourceReservationErrorV1> {
        std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<UseReservedAppendBindingV1<'static>>().checked_mul(2)?))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake) fn produce_once(
        &mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1,
        validated: &root_validated::RootValidatedOriginalsV1,
        reserve: &mut UseReservationOriginalsV1,
        authorization: &OriginalCreateStorageRootUseAuthorizationV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.primary = Some(self.produce_inner(parent, intake, histories, assignment,
            validated, reserve, authorization, controller, source, profile));
        if matches!(self.funding, Some(Ok(()))) && !self.pair.posts_attempted {
            if let (Ok(j), Ok(cutoff)) = (intake.create_storage_j_data_v1(), authorization.cutoff_v1()) {
                self.pair.finish_posts_once(intake, controller, source.journal_ref_v1(), profile,
                    j.clock, cutoff, HistoryRoleV1::Controller);
            }
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && self.pair.complete
            && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn produce_inner(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1,
        validated: &root_validated::RootValidatedOriginalsV1,
        reserve: &mut UseReservationOriginalsV1,
        authorization: &OriginalCreateStorageRootUseAuthorizationV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> ResultV1<()> {
        let lane = intake.create_lane()?;
        let original = intake.create_storage_j_data_v1()?.clock;
        let cutoff = authorization.cutoff_v1()?;
        let before = reserve.position()?;
        self.demand = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            intake.require_create_history_names_peak_v1()?;
            let semantic = controller.create_storage_semantic_append_demand_v1()?;
            use_history_pair_receiving_demand_v1(USE_RESERVED_RECORD_BYTES_V1, &semantic)
        })());
        self.funding = Some((|| {
            let demand = self.demand.as_ref().and_then(|r| r.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            reserve.reserve_pair_receiving_once_v1(demand)?;
            intake.extend_create_storage_use_observers_once(profile, reserve.receiving_mut_v1()?, 6)
        })());
        retained(&self.funding)?;
        self.pair.enter_once(parent, intake, controller, source.journal_ref_v1(), profile, HistoryRoleV1::Controller)?;
        self.encoded = Some((|| {
            let actual = reserve.returned_transition_v1()?;
            let (head, claim, binding) = reserve.bank_members_v1()?;
            Ok(UseReservedBodyDataV1 { root_validated: validated.checksum_v1(lane)?,
                head, claim, binding,
                transaction: actual.transaction_id, names: before.names,
                after_next: before.next, after_end: before.end }.encode()?)
        })());
        let body = retained(&self.encoded)?;
        let inputs = authorization.inputs_ready_v1()?;
        let binding = UseReservedAppendBindingV1 { lane, intent: &histories.intent.record,
            planned: assignment.bundle_record_v1()?, inputs, validated, reserve, authorization,
            body, funded: &self.funding,
            demand: *self.demand.as_ref().and_then(|r| r.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)? };
        self.pair.produce_once(parent, intake, controller, source.journal_ref_v1(), profile,
            HistoryRoleV1::Controller, lane, authorization.association_v1()?.association.seed,
            original, cutoff, Some((before.next, before.end)), body,
            Some(HistorySuccessorBindingV1::UseReserved(&binding)))
    }

    pub(in crate::controller_resource_reservation::create_intake) fn position(&self)
        -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.pair.after.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    // The actual C5 trailing clock is later than the returned U reserve.
    // Its bytes are comparison DATA, never a reconstructed/current clock.
    pub(in crate::controller_resource_reservation::create_intake) fn completed_clock_v1(&self)
        -> Result<RawPairedClockSample, ResourceReservationErrorV1>
    {
        self.position()?;
        self.pair.clock.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn native_receipt_v1(&self)
        -> Result<UseReservedNativeReceiptDataV1<'_>, ResourceReservationErrorV1> {
        let after = self.position()?;
        Ok(UseReservedNativeReceiptDataV1 { record: self.pair.record.as_slice().try_into()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?, latest_head: self.pair.head,
            names: after.names, after_next: after.next, after_end: after.end })
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn StdError + 'static)> {
        cause(&self.demand).or_else(|| cause(&self.funding)).or_else(|| self.pair.primary_failure())
            .or_else(|| cause(&self.encoded)).or_else(|| cause(&self.primary)).or_else(|| self.pair.post_failure())
    }
}

pub(super) struct UseReservedAppendBindingV1<'held> {
    lane: [u8; 16],
    intent: &'held [u8],
    planned: &'held [u8],
    inputs: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'held>,
    validated: &'held root_validated::RootValidatedOriginalsV1,
    reserve: &'held UseReservationOriginalsV1,
    authorization: &'held OriginalCreateStorageRootUseAuthorizationV1<'held>,
    body: &'held [u8],
    funded: &'held Option<Result<(), ResourceReservationErrorV1>>,
    demand: ResourceVector,
}

impl UseReservedAppendBindingV1<'_> {
    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        self.validated.checksum_v1(self.lane).map_err(|_| HistoryErrorV1::Correlation)
    }

    pub(super) fn require_prepaid_v1(&self, demand: ResourceVector) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.funded, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.demand.checked_sub(demand)?;
        self.reserve.require_pair_receiving_v1(self.demand)
    }

    pub(super) fn require_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        journal: &Journal, transaction: &JournalTransaction) -> Result<(), JournalError> {
        journal.ensure_healthy()?;
        self.require_state_successor(parent, intake, state, transaction)
    }

    pub(super) fn require_state_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        transaction: &JournalTransaction) -> Result<(), JournalError> {
        let closed = || JournalError::ProtectedBoundary;
        self.reserve.require_current_state_v1(parent, state).map_err(native_error)?;
        require_j_readback_members_v1(intake, state)?;
        if intake.create_lane().map_err(native_error)? != self.lane { return Err(closed()); }
        require_exact_controller_prefix_v1(state, self.lane,
            &[(1, self.intent), (2, self.planned), (3, self.inputs.record),
                (4, self.validated.retained_record_v1().map_err(native_error)?)],
            self.validated.retained_head_v1().map_err(native_error)?)?;
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Controller, 5).map_err(|_| closed())?;
        let head_key = KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory
            || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != head_key.encode() { return Err(closed()); }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key,
            PhaseV1::new(OwnerV1::Controller, 4).map_err(|_| closed())?).map_err(|_| closed())?;
        let body = UseReservedBodyDataV1::decode(envelope.body()).map_err(|_| closed())?;
        let authorization = UseAuthorizedNativeReceiptDataV1::decode(
            &self.authorization.frame_v1()[FRAME_HEADER_BYTES..], self.lane).map_err(|_| closed())?;
        body.require_authorization_v1(self.lane, authorization).map_err(|_| closed())?;
        let actual = self.reserve.returned_transition_v1().map_err(native_error)?;
        let before = self.reserve.position().map_err(native_error)?;
        let members = self.reserve.bank_members_v1().map_err(native_error)?;
        if envelope.body() != self.body || body.head != members.0
            || body.claim != members.1 || body.binding != members.2
            || body.transaction != actual.transaction_id
            || (body.names, body.after_next, body.after_end) != (before.names, before.next, before.end)
            || envelope.coordinates().predecessor != self.predecessor().map_err(|_| closed())?
            || envelope.coordinates().correlation != self.authorization.association_v1().map_err(native_error)?.association.seed {
            return Err(closed());
        }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, head_key)
            .and_then(|latest| latest.check_record(head_key, envelope)).map_err(|_| closed())
    }
}
