//! Retains C10 only from actual committed U and both original held releases.
//!
//! One existing atomic pair owns publication, readback and all native posts.
//! Its heavy backing is allocated only after the same real U admits this stage.

use super::*;
use super::super::ready::use_reserved::{
    release::OriginalCreateStorageReleasedV1, UseReceivingOriginalsV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{HandoffRetainedBodyDataV1, ReleasedBodyDataV1, HANDOFF_RETAINED_BODY_BYTES_V1},
};
use sha2::{Digest as _, Sha256};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake)
struct HandoffOriginalsV1 {
    entered: bool,
    closed: bool,
    pub(in crate::controller_resource_reservation::create_intake)
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    pub(in crate::controller_resource_reservation::create_intake)
    primary: Option<Result<(), ResourceReservationErrorV1>>,
    demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    native: Option<Box<HandoffNativeOriginalsV1>>,
}

#[derive(Default)]
struct HandoffNativeOriginalsV1 {
    body: Option<Result<[u8; HANDOFF_RETAINED_BODY_BYTES_V1], HistoryProductionErrorV1>>,
    pair: OriginalHistoryPairV1,
    pair_invoked: bool,
    primary: Option<ResultV1<()>>,
    complete: bool,
}

impl HandoffOriginalsV1 {
    pub(super) fn fixed_inline_receiving_bytes_v1() -> Result<usize, ResourceReservationErrorV1> {
        std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HandoffNativeOriginalsV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HandoffAppendBindingV1<'static>>().checked_mul(2)?))
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake)
    fn enter_once(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if self.entered {
            self.closed = true;
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.entered = true;
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn produce_once(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1, validated: &root_validated::RootValidatedOriginalsV1,
        reserved: &use_reserved::UseReservedOriginalsV1, signed: &signed::SignedOriginalsV1,
        dispatch: &dispatch::DispatchOriginalsV1, session: &session::SessionOriginalsV1,
        released: &OriginalCreateStorageReleasedV1<'_>, receiving: &mut UseReceivingOriginalsV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        inputs: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.entered || !matches!(self.entry, Some(Ok(()))) || self.demand.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.demand = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            intake.require_create_history_names_peak_v1()?;
            released.committed_v1().require_current_state_v1(controller.controller_resource_state_v1()?)?;
            use_history_pair_receiving_demand_v1(HANDOFF_RETAINED_BODY_BYTES_V1 + RECORD_OVERHEAD_BYTES,
                &controller.create_storage_semantic_append_demand_v1()?)
        })());
        self.funding = Some((|| {
            let demand = *self.demand.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            receiving.reserve_once(demand)?;
            intake.extend_create_storage_use_observers_once(profile, receiving, 6)
        })());
        if !matches!(self.funding, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.native = Some(Box::new(HandoffNativeOriginalsV1::default()));
        let native = self.native.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        native.primary = Some((|| {
            native.pair.enter_once(parent, intake, controller, source.journal_ref_v1(), profile, HistoryRoleV1::Controller)?;
            let lane = intake.create_lane()?;
            native.body = Some(body_v1(released, lane, controller.controller_resource_state_v1()?));
            let body = retained(&native.body)?;
            let previous = released.committed_v1().recorded_v1().receipt_v1()?
                .record_data(lane, ContinuationKindV1::ControllerOutcomeRecorded)?;
            let seed = previous.coordinates().correlation;
            let demand = *self.demand.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let binding = HandoffAppendBindingV1 { lane, seed, histories, assignment, validated, reserved,
                signed, dispatch, session, released, receiving, inputs, body, demand };
            let before = released.committed_v1().position_v1()?;
            native.pair_invoked = true;
            native.pair.produce_once(parent, intake, controller, source.journal_ref_v1(), profile,
                HistoryRoleV1::Controller, lane, seed, released.clock_v1()?, released.cutoff_v1()?,
                Some((before.next, before.end)), body, Some(HistorySuccessorBindingV1::Handoff(&binding)))
        })());
        if !native.pair.posts_attempted {
            if let (Ok(clock), Ok(cutoff)) = (released.clock_v1(), released.cutoff_v1()) {
                native.pair.finish_posts_once(intake, controller, source.journal_ref_v1(), profile,
                    clock, cutoff, HistoryRoleV1::Controller);
            }
        }
        native.complete = matches!(native.primary, Some(Ok(()))) && native.pair.complete;
        if native.complete && self.failure().is_none() { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn position(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        let native = self.native.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !native.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        native.pair.after.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, ResourceReservationErrorV1> {
        let position = self.position()?;
        let pair = &self.native.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?.pair;
        Ok(ContinuationNativeReceiptDataV1 { record: &pair.record, latest_head: pair.head,
            names: position.names, after_next: position.next, after_end: position.end })
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.entry).or_else(|| cause(&self.demand)).or_else(|| cause(&self.funding)).or_else(|| {
            let native = self.native.as_ref()?;
            cause(&native.body).or_else(|| native.pair.primary_failure())
                .or_else(|| native.pair_invoked.then(|| native.pair.post_failure()).flatten())
                .or_else(|| cause(&native.primary)).or_else(|| native.pair.post_failure())
        }).or_else(|| cause(&self.primary))
            .or_else(|| self.closed.then_some(&ResourceReservationErrorV1::Conflict as &(dyn StdError + 'static)))
    }
}

fn body_v1(released: &OriginalCreateStorageReleasedV1<'_>, lane: [u8; 16],
    state: &super::super::super::State,
) -> Result<[u8; HANDOFF_RETAINED_BODY_BYTES_V1], HistoryProductionErrorV1> {
    let committed = released.committed_v1();
    committed.require_current_state_v1(state)?;
    let source = released.source_receipt_v1()?.record_data(lane, ContinuationKindV1::SourceReleased)?;
    let cache = released.cache_receipt_v1()?.record_data(lane, ContinuationKindV1::CacheReleased)?;
    let source_body = ReleasedBodyDataV1::decode(source.body(), OwnerV1::Source)?;
    let cache_body = ReleasedBodyDataV1::decode(cache.body(), OwnerV1::Cache)?;
    let recorded = committed.recorded_v1().receipt_v1()?.record_data(lane, ContinuationKindV1::ControllerOutcomeRecorded)?;
    if source_body.root_outcome != cache_body.root_outcome
        || source_body.controller_outcome != recorded.checksum() || cache_body.controller_outcome != recorded.checksum() {
        return Err(HistoryErrorV1::Correlation.into());
    }
    let transition = committed.transition_v1()?;
    let binding = transition.create_storage_use.ok_or(ResourceReservationErrorV1::Conflict)?;
    let claim = super::super::super::bank::claim_bytes(state, transition.claim.native_fields().id)
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let position = committed.position_v1()?;
    HandoffRetainedBodyDataV1 { root_outcome: source_body.root_outcome,
        source_released: source.checksum(), cache_released: cache.checksum(),
        committed_use_claim: Sha256::digest(claim).into(), use_binding: Sha256::digest(binding.encode().map_err(ResourceReservationErrorV1::from)?).into(),
        bank_commit: transition.transaction_id, bank_names: position.names,
        bank_after_next: position.next, bank_after_end: position.end }.encode().map_err(Into::into)
}

pub(super) struct HandoffAppendBindingV1<'held> {
    lane: [u8; 16], seed: [u8; 32], histories: &'held CreateStorageOriginalHistoriesV1,
    assignment: &'held assignment::AssignmentPlannedOriginalV1,
    validated: &'held root_validated::RootValidatedOriginalsV1, reserved: &'held use_reserved::UseReservedOriginalsV1,
    signed: &'held signed::SignedOriginalsV1, dispatch: &'held dispatch::DispatchOriginalsV1,
    session: &'held session::SessionOriginalsV1,
    released: &'held OriginalCreateStorageReleasedV1<'held>, receiving: &'held UseReceivingOriginalsV1,
    inputs: aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'held>,
    body: &'held [u8], demand: ResourceVector,
}

impl HandoffAppendBindingV1<'_> {
    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        self.released.committed_v1().recorded_v1().receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?
            .record_data(self.lane, ContinuationKindV1::ControllerOutcomeRecorded).map(|record| record.checksum())
    }

    pub(super) fn require_prepaid_v1(&self, demand: ResourceVector) -> Result<(), ResourceReservationErrorV1> {
        self.receiving.require_reserved_v1()?;
        self.demand.checked_sub(demand)?;
        self.receiving.charged_v1().checked_sub(self.demand)?;
        Ok(())
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
        parent.require_create_continuation_state(state).map_err(native_error)?;
        self.released.committed_v1().require_current_state_v1(state).map_err(native_error)?;
        require_j_readback_members_v1(intake, state)?;
        let recorded = self.released.committed_v1().recorded_v1().receipt_v1().map_err(native_error)?;
        require_exact_controller_prefix_v1(state, self.lane,
            &[(1, &self.histories.intent.record), (2, self.assignment.bundle_record_v1().map_err(native_error)?),
                (3, self.inputs.record), (4, self.validated.retained_record_v1().map_err(native_error)?),
                (5, self.reserved.native_receipt_v1().map_err(native_error)?.record),
                (6, self.signed.record_v1().map_err(native_error)?), (7, self.dispatch.record_v1().map_err(native_error)?),
                (8, self.session.record_v1().map_err(native_error)?), (9, recorded.record)], &recorded.latest_head)?;
        if intake.create_lane().map_err(native_error)? != self.lane { return Err(closed()); }
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Controller, 10).map_err(|_| closed())?;
        let latest = KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != latest.encode() { return Err(closed()); }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key,
            PhaseV1::new(OwnerV1::Controller, 9).map_err(|_| closed())?).map_err(|_| closed())?;
        if envelope.body() != self.body || envelope.coordinates().correlation != self.seed
            || envelope.coordinates().predecessor != self.predecessor().map_err(|_| closed())?
            || body_v1(self.released, self.lane, state).map_err(|_| closed())?.as_slice() != self.body { return Err(closed()); }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, latest)
            .and_then(|value| value.check_record(latest, envelope)).map_err(|_| closed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_handoff_pair_post_cause_precedes_its_outer_projection() {
        let mut native = HandoffNativeOriginalsV1::default();
        native.pair_invoked = true;
        native.pair.after = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(5))));
        native.primary = Some(Err(JournalError::ProtectedBoundary.into()));
        let actual = HandoffOriginalsV1 { native: Some(Box::new(native)), ..Default::default() };
        let original = actual.native.as_ref().unwrap().pair.after.as_ref().unwrap().as_ref().err().unwrap();

        let returned = actual.failure().unwrap().downcast_ref::<JournalError>().unwrap();

        assert!(std::ptr::eq(returned, original));
        assert!(matches!(returned, JournalError::Io(error) if error.raw_os_error() == Some(5)));
    }

    #[test]
    fn earlier_handoff_failure_precedes_independently_owed_pair_post() {
        let mut native = HandoffNativeOriginalsV1::default();
        native.primary = Some(Err(JournalError::ProtectedBoundary.into()));
        native.pair.after = Some(Err(JournalError::Io(std::io::Error::from_raw_os_error(5))));
        let actual = HandoffOriginalsV1 { native: Some(Box::new(native)), ..Default::default() };
        let original = actual.native.as_ref().unwrap().primary.as_ref().unwrap().as_ref().unwrap_err();

        let returned = actual.failure().unwrap().downcast_ref::<HistoryProductionErrorV1>().unwrap();

        assert!(std::ptr::eq(returned, original));
        assert!(actual.native.as_ref().unwrap().pair.post_failure().is_some());
    }

    #[test]
    fn repeated_handoff_entry_closes_the_completed_position_without_replacing_native_custody() {
        let position = CreateStorageWriterPositionV1 {
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4)),
            next: 40, end: 4096,
        };
        let mut native = HandoffNativeOriginalsV1::default();
        native.complete = true;
        native.pair.after = Some(Ok(position));
        let mut actual = HandoffOriginalsV1 { native: Some(Box::new(native)), ..Default::default() };
        actual.enter_once().unwrap();
        let original = std::ptr::from_ref(actual.native.as_deref().unwrap());
        assert!(actual.position().ok() == Some(position));

        assert!(actual.enter_once().is_err());

        assert!(actual.failure().is_some());
        assert!(actual.position().is_err());
        assert!(std::ptr::from_ref(actual.native.as_deref().unwrap()) == original);
        assert!(actual.native.as_ref().unwrap().pair.after.as_ref().unwrap().as_ref().ok() == Some(&position));
    }
}
