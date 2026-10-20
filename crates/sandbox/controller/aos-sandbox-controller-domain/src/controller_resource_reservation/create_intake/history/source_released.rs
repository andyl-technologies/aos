//! Releases the original Source Held pair after the same U's positive commit.
//!
//! This purpose uses the sole original atomic pair engine. Its private binding
//! keeps the actual committed bank owner, Root5 acknowledgment and original
//! Source Held record borrowed through native crossing and all pair posts.

use super::*;
use super::super::ready::{
    root_exchange::OriginalCreateStorageRootOutcomeV1,
    use_reserved::{OriginalCreateStorageUseCommittedV1, UseReceivingOriginalsV1},
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{ReleasedBodyDataV1, RELEASED_BODY_BYTES_V1, RELEASED_RECORD_BYTES_V1},
};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake)
struct SourceReleasedOriginalsV1 {
    entered: bool,
    demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    body: Option<Result<[u8; RELEASED_BODY_BYTES_V1], HistoryProductionErrorV1>>,
    pair: OriginalHistoryPairV1,
    primary: Option<ResultV1<()>>,
    pair_invoked: bool,
    complete: bool,
}

impl SourceReleasedOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake)
    fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake)
    fn funding_failure_is_selected_v1(&self) -> bool {
        matches!(self.demand, Some(Ok(_))) && matches!(self.funding, Some(Err(_)))
    }


    pub(in crate::controller_resource_reservation)
    fn inline_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<SourceReleasedAppendBindingV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(std::mem::align_of::<Self>()))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?)
            .checked_add(super::super::ready::cache_receiving::CacheCaptureOriginalV1::
                source_release_association_receiving_demand_v1()?)
            .map_err(ResourceReservationErrorV1::from)
    }

    pub(in crate::controller_resource_reservation)
    fn fixed_receiving_demand_v1(semantic: &ResourceVector)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        Self::inline_receiving_demand_v1()?.checked_add(Self::pair_receiving_demand_v1(semantic)?)?
            .checked_add(crate::controller_resource_reservation::create_storage_use_profile_rows_receiving_demand_v1(6)?)
            .map_err(ResourceReservationErrorV1::from)
    }

    fn pair_receiving_demand_v1(semantic: &ResourceVector)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        let pair = pair_use_complete_demand_v1(RELEASED_RECORD_BYTES_V1, semantic)?;
        let append = pair.get(D::StorageBytes);
        pair.checked_add(crate::journal::create_storage_name_peak_demand_v1()?)?
            .checked_add(ResourceVector::ZERO.with(D::OutputBytes, append)
                .with(D::PublicationStagingBytes, append)).map_err(ResourceReservationErrorV1::from)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn produce_once(&mut self,
        parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1,
        histories: &CreateStorageOriginalHistoriesV1,
        controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        committed: &OriginalCreateStorageUseCommittedV1<'_>,
        root: &OriginalCreateStorageRootOutcomeV1<'_>,
        receiving: &mut UseReceivingOriginalsV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.primary = Some(self.produce_inner(parent, intake, histories, controller,
            source, profile, committed, root, receiving));
        if matches!(self.funding, Some(Ok(()))) && !self.pair.posts_attempted {
            if let (Ok(clock), Ok(cutoff)) = (root.clock_v1(), root.cutoff_v1()) {
                self.pair.finish_posts_once(intake, source.journal_ref_v1(), controller,
                    profile, clock, cutoff, HistoryRoleV1::Source);
            }
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && self.pair.complete
            && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn produce_inner(&mut self,
        parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1,
        histories: &CreateStorageOriginalHistoriesV1,
        controller: &Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
        committed: &OriginalCreateStorageUseCommittedV1<'_>,
        root: &OriginalCreateStorageRootOutcomeV1<'_>,
        receiving: &mut UseReceivingOriginalsV1,
    ) -> ResultV1<()> {
        let lane = intake.create_lane()?;
        committed.require_current_state_v1(controller.controller_resource_state_v1()?)?;
        receiving.require_reserved_v1()?;
        parent.require_create_storage_association(controller, source, profile)?;
        let held = histories.source_held_data_v1(lane)?;
        let before = CreateStorageWriterPositionV1 { names: held.source_names,
            next: held.source_after_next, end: held.source_after_end };
        self.demand = Some(Self::pair_receiving_demand_v1(
            &source.journal_ref_v1().create_storage_semantic_append_demand_v1()?));
        self.funding = Some((|| {
            let demand = self.demand.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            receiving.reserve_once(demand)?;
            intake.extend_create_storage_use_observers_once(profile, receiving, 6)
        })());
        retained(&self.funding)?;
        self.pair.enter_once(parent, intake, source.journal_ref_v1(), controller,
            profile, HistoryRoleV1::Source)?;
        self.body = Some((|| {
            let held = RecordEnvelopeV1::decode(held.record, KeyV1::new(lane, OwnerV1::Source, 1)?,
                PhaseV1::new(OwnerV1::Source, 1)?)?;
            let recorded = committed.recorded_v1().receipt_v1()?
                .record_data(lane, ContinuationKindV1::ControllerOutcomeRecorded)?;
            let root = root.receipt_v1()?.record_data(lane, ContinuationKindV1::OutcomeRecorded)?;
            Ok(ReleasedBodyDataV1 { root_outcome: root.checksum(), held: held.checksum(),
                controller_outcome: recorded.checksum() }.encode(OwnerV1::Source)?)
        })());
        let body = retained(&self.body)?;
        let binding = SourceReleasedAppendBindingV1 { lane, histories, committed, root,
            controller, receiving, body, funded: &self.funding,
            demand: *retained(&self.demand)? };
        let seed = binding.held_envelope()?.coordinates().correlation;
        self.pair_invoked = true;
        self.pair.produce_once(parent, intake, source.journal(), controller, profile,
            HistoryRoleV1::Source, lane, seed, root.clock_v1()?, root.cutoff_v1()?,
            Some((before.next, before.end)), body,
            Some(HistorySuccessorBindingV1::SourceReleased(&binding)))
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn position_v1(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.pair.after.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn require_held_source_v1(&self, held: &[u8; 508], lane: [u8; 16])
        -> Result<(), ResourceReservationErrorV1> {
        self.position_v1()?;
        let receipt = SourceHeldReceiptDataV1::decode(held, lane)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let before = self.pair.before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let held_envelope = RecordEnvelopeV1::decode(receipt.record,
            KeyV1::new(lane, OwnerV1::Source, 1).map_err(|_| ResourceReservationErrorV1::Conflict)?,
            PhaseV1::new(OwnerV1::Source, 1).map_err(|_| ResourceReservationErrorV1::Conflict)?)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let released = RecordEnvelopeV1::decode(&self.pair.record,
            KeyV1::new(lane, OwnerV1::Source, 2).map_err(|_| ResourceReservationErrorV1::Conflict)?,
            PhaseV1::new(OwnerV1::Source, 2).map_err(|_| ResourceReservationErrorV1::Conflict)?)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let body = ReleasedBodyDataV1::decode(released.body(), OwnerV1::Source)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if before.names != receipt.source_names || before.next != receipt.source_after_next
            || before.end != receipt.source_after_end || body.held != held_envelope.checksum()
            || released.coordinates().predecessor != held_envelope.checksum()
            || released.coordinates().correlation != held_envelope.coordinates().correlation {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, ResourceReservationErrorV1> {
        let position = self.position_v1()?;
        Ok(ContinuationNativeReceiptDataV1 { record: &self.pair.record,
            latest_head: self.pair.head, names: position.names,
            after_next: position.next, after_end: position.end })
    }

    pub(in crate::controller_resource_reservation::create_intake)
    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.demand).or_else(|| cause(&self.funding))
            .or_else(|| self.pair.primary_failure()).or_else(|| cause(&self.body))
            .or_else(|| (!self.pair_invoked).then(|| cause(&self.primary)).flatten())
            .or_else(|| self.pair.post_failure()).or_else(|| cause(&self.primary))
    }
}

pub(super) struct SourceReleasedAppendBindingV1<'held> {
    lane: [u8; 16],
    histories: &'held CreateStorageOriginalHistoriesV1,
    committed: &'held OriginalCreateStorageUseCommittedV1<'held>,
    root: &'held OriginalCreateStorageRootOutcomeV1<'held>,
    controller: &'held Journal,
    receiving: &'held UseReceivingOriginalsV1,
    body: &'held [u8; RELEASED_BODY_BYTES_V1],
    funded: &'held Option<Result<(), ResourceReservationErrorV1>>,
    demand: ResourceVector,
}

impl SourceReleasedAppendBindingV1<'_> {
    fn held_envelope(&self) -> Result<RecordEnvelopeV1<'_>, HistoryErrorV1> {
        RecordEnvelopeV1::decode(&self.histories.source.record,
            KeyV1::new(self.lane, OwnerV1::Source, 1)?, PhaseV1::new(OwnerV1::Source, 1)?)
    }

    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        self.held_envelope().map(|held| held.checksum())
    }

    pub(super) fn require_prepaid_v1(&self, demand: ResourceVector)
        -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.funded, Some(Ok(()))) { return Err(ResourceReservationErrorV1::Conflict); }
        self.demand.checked_sub(demand)?;
        self.receiving.require_reserved_v1()
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
        self.committed.require_current_state_v1(self.controller.controller_resource_state_v1()?)
            .map_err(native_error)?;
        self.receiving.require_reserved_v1().map_err(native_error)?;
        let held = self.histories.source_held_data_v1(self.lane).map_err(native_error)?;
        parent.require_terminal_retention().map_err(native_error)?;
        if intake.create_lane().map_err(native_error)? != self.lane { return Err(closed()); }
        let expected_member = KeyV1::new(self.lane, OwnerV1::Source, 1).map_err(|_| closed())?.encode();
        let expected_head = KeyV1::new(self.lane, OwnerV1::Source, 0).map_err(|_| closed())?.encode();
        let mut count = 0_usize;
        for ((namespace, key), value) in state {
            if *namespace != crate::RecordNamespace::CreateStorageHistory { continue; }
            count += 1;
            if key.as_slice() == expected_member && value.as_slice() == held.record { continue; }
            if key.as_slice() == expected_head && value.as_slice() == held.latest_head { continue; }
            return Err(closed());
        }
        if count != 2 { return Err(closed()); }
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Source, 2).map_err(|_| closed())?;
        let latest = KeyV1::new(self.lane, OwnerV1::Source, 0).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory
            || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != latest.encode() { return Err(closed()); }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key,
            PhaseV1::new(OwnerV1::Source, 2).map_err(|_| closed())?).map_err(|_| closed())?;
        let held_envelope = self.held_envelope().map_err(|_| closed())?;
        let root = self.root.receipt_v1().map_err(native_error)?
            .record_data(self.lane, ContinuationKindV1::OutcomeRecorded).map_err(|_| closed())?;
        let recorded = self.committed.recorded_v1().receipt_v1().map_err(native_error)?
            .record_data(self.lane, ContinuationKindV1::ControllerOutcomeRecorded).map_err(|_| closed())?;
        let expected = ReleasedBodyDataV1 { root_outcome: root.checksum(), held: held_envelope.checksum(),
            controller_outcome: recorded.checksum() };
        if envelope.body() != self.body || envelope.coordinates().predecessor != held_envelope.checksum()
            || envelope.coordinates().correlation != held_envelope.coordinates().correlation
            || ReleasedBodyDataV1::decode(envelope.body(), OwnerV1::Source).map_err(|_| closed())? != expected {
            return Err(closed());
        }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, latest)
            .and_then(|latest_head| latest_head.check_record(latest, envelope)).map_err(|_| closed())
    }
}
