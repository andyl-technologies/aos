//! Appends InputsReady only from the same completed original B and planned row.
//!
//! The exact bundle remains in its Security flight. This producer retains only
//! its canonical fixed commitment and actual append/readback; a parsed bundle
//! or InputsReady row cannot construct another genuine continuation.

use super::*;
use aos_sandbox_protocol::domain_ledger::create_storage_history::ready::{
    InputsReadyBodyDataV1, INPUTS_READY_BODY_BYTES_V1,
};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct InputsReadyOriginalsV1 {
    entered: bool,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    bundle: Option<Result<(), ResourceReservationErrorV1>>,
    body: Option<Result<InputsReadyBodyDataV1, HistoryErrorV1>>,
    encoded: Option<Result<[u8; INPUTS_READY_BODY_BYTES_V1], HistoryErrorV1>>,
    pair: OriginalHistoryPairV1,
    primary: Option<ResultV1<()>>,
    complete: bool,
}

impl InputsReadyOriginalsV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn receiving_demand_v1(
        controller: &Journal, source: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let receipt = std::mem::size_of::<aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>>()
            .checked_mul(2).ok_or(ResourceReservationErrorV1::Conflict)?;
        let binding = std::mem::size_of::<InputsReadyAppendBindingV1<'_>>().checked_mul(2)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|value| value.checked_add(receipt))
            .and_then(|value| value.checked_add(binding))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let fixed = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?).with(D::MetadataEntries, 8 + 6 + 6);
        let controller_cells = CreateStorageWriterPositionOriginalV1::receiving_metadata_cells_v1(HistoryRoleV1::Controller)?;
        let source_cells = CreateStorageWriterPositionOriginalV1::receiving_metadata_cells_v1(HistoryRoleV1::Source)?;
        // Actual before/readback/after/final-crossing Controller slots and
        // before/after/final-crossing Source slots coexist. Their fresh Files
        // reuse the genuine shared HistoryNames peak after positive cleanup;
        // their reached native Results and Source Vec backings stay paid here.
        let position_cells = controller_cells.checked_mul(4)
            .and_then(|value| value.checked_add(source_cells.checked_mul(3)?))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let names = crate::journal::create_storage_name_peak_demand_v1()?;
        let positions = ResourceVector::ZERO.with(D::MemoryBytes, names.get(D::MemoryBytes))
            .with(D::MetadataEntries, u64::try_from(position_cells).map_err(|_| ResourceReservationErrorV1::Conflict)?);
        let framing = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::ReadyBundleDataV1::fixed_framing_receiving_demand_v1()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut demand = pair_fixed_demand(RECORD_OVERHEAD_BYTES + INPUTS_READY_BODY_BYTES_V1)?
            .checked_add(fixed)?.checked_add(positions)?.checked_add(framing)?;
        demand = demand.checked_add(controller.create_storage_semantic_append_demand_v1()?)?;
        demand.checked_add(source.create_storage_semantic_append_demand_v1()?).map_err(ResourceReservationErrorV1::from)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn started(&self) -> bool { self.entered }

    pub(in crate::controller_resource_reservation::create_intake) fn produce_once(
        &mut self, parent: &ProjectPreparationReservationAttemptV1, intake: &mut Q04OriginalIntakeAttemptV1,
        histories: &CreateStorageOriginalHistoriesV1, assignment: &assignment::AssignmentPlannedOriginalV1,
        bundle: &super::super::ready::bundle::BundleEncodingOriginalsV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1, bytes: &[u8],
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.primary = Some(self.produce_inner(parent, intake, histories, assignment, bundle, controller, source, profile, bytes));
        // Once fixed work was paid, all owed posts run even on body or append
        // refusal; their later causes never displace the original primary.
        if matches!(self.funding, Some(Ok(()))) && !self.pair.posts_attempted {
            if let (Ok(j), Ok(accepted)) = (intake.create_storage_j_data_v1(), parent.create_storage_original_identity_v1()) {
                self.pair.finish_posts_once(intake, controller, source.journal_ref_v1(), profile,
                    j.clock, accepted.original_cutoff, HistoryRoleV1::Controller);
            }
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && self.pair.complete && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn produce_inner(&mut self, parent: &ProjectPreparationReservationAttemptV1, intake: &mut Q04OriginalIntakeAttemptV1,
        histories: &CreateStorageOriginalHistoriesV1, assignment: &assignment::AssignmentPlannedOriginalV1,
        bundle: &super::super::ready::bundle::BundleEncodingOriginalsV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1, bytes: &[u8],
    ) -> ResultV1<()> {
        self.bundle = Some(bundle.require_completed_bytes_v1(bytes));
        retained(&self.bundle)?;
        let before = assignment.position()?;
        let accepted = parent.create_storage_original_identity_v1()?;
        let original = intake.create_storage_j_data_v1()?.clock;
        let lane = intake.create_lane()?;
        let planned = assignment.bundle_record_v1()?;
        self.funding = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            let demand = Self::receiving_demand_v1(controller, source.journal_ref_v1())?;
            intake.reserve_create_capture_complete(Owner::RootExchange, demand)?;
            // Entry, Native crossing and trailing profile each require their
            // own two properties, under this same already-entered J.
            intake.extend_create_capture_observers_once(profile, 6)
        })());
        retained(&self.funding)?;
        self.pair.enter_once(parent, intake, controller, source.journal_ref_v1(), profile, HistoryRoleV1::Controller)?;
        self.body = Some(InputsReadyBodyDataV1::from_bundle(bytes));
        self.encoded = Some(retained(&self.body)?.encode());
        let body = retained(&self.encoded)?;
        let binding = InputsReadyAppendBindingV1 { lane, intent: &histories.intent.record,
            planned, planned_head: assignment.bundle_head_v1()?, body, bundle: bytes };
        self.pair.produce_once(parent, intake, controller, source.journal_ref_v1(), profile,
            HistoryRoleV1::Controller, lane, histories.source_held_data_v1(lane)?.body(lane)?.seed,
            original, accepted.original_cutoff, Some((before.next, before.end)), body,
            Some(HistorySuccessorBindingV1::InputsReady(&binding)))?;
        Ok(())
    }

    pub(in crate::controller_resource_reservation::create_intake) fn native_receipt_v1(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1<'_>, ResourceReservationErrorV1>
    {
        let position = self.position()?;
        Ok(aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyNativeReceiptDataV1 {
            record: self.pair.record.as_slice().try_into().map_err(|_| ResourceReservationErrorV1::Conflict)?,
            latest_head: self.pair.head,
            names: position.names,
            after_next: position.next,
            after_end: position.end,
        })
    }

    pub(in crate::controller_resource_reservation::create_intake) fn body_data_v1(&self) -> Result<InputsReadyBodyDataV1, ResourceReservationErrorV1> {
        self.position()?;
        self.body.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn position(&self) -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1> {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.pair.after.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.bundle).or_else(|| cause(&self.funding)).or_else(|| self.pair.primary_failure())
            .or_else(|| cause(&self.body)).or_else(|| cause(&self.encoded))
            .or_else(|| cause(&self.primary)).or_else(|| self.pair.post_failure())
    }
}

// The enclosing genuine producer holds both the original planned row and the
// completed B. Neither can be supplied by an arbitrary Journal caller.
pub(super) struct InputsReadyAppendBindingV1<'held> {
    lane: [u8; 16], intent: &'held [u8], planned: &'held [u8],
    planned_head: [u8; HEAD_BYTES], body: &'held [u8], bundle: &'held [u8],
}

impl InputsReadyAppendBindingV1<'_> {
    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        Ok(RecordEnvelopeV1::decode(self.planned, KeyV1::new(self.lane, OwnerV1::Controller, 2)?,
            PhaseV1::new(OwnerV1::Controller, 12)?)?.checksum())
    }

    pub(super) fn require_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        journal: &Journal, transaction: &JournalTransaction) -> Result<(), JournalError>
    {
        journal.ensure_healthy()?;
        self.require_state_successor(parent, intake, state, transaction)
    }

    pub(super) fn require_state_successor(&self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &Q04OriginalIntakeAttemptV1, state: &super::super::super::State,
        transaction: &JournalTransaction) -> Result<(), JournalError>
    {
        let closed = || JournalError::ProtectedBoundary;
        parent.require_create_continuation_state(state).map_err(native_error)?;
        require_j_readback_members_v1(intake, state)?;
        if intake.create_lane().map_err(native_error)? != self.lane { return Err(closed()); }
        let expected = [(KeyV1::new(self.lane, OwnerV1::Controller, 1).map_err(|_| closed())?.encode(), self.intent),
            (KeyV1::new(self.lane, OwnerV1::Controller, 2).map_err(|_| closed())?.encode(), self.planned),
            (KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?.encode(), self.planned_head.as_slice())];
        let mut count = 0;
        for ((namespace, key), value) in state {
            if *namespace != crate::RecordNamespace::CreateStorageHistory { continue; }
            count += 1;
            if !expected.iter().any(|(expected_key, expected_value)| key.as_slice() == expected_key && value.as_slice() == *expected_value) {
                return Err(closed());
            }
        }
        if count != expected.len() { return Err(closed()); }
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Controller, 3).map_err(|_| closed())?;
        let head_key = KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?;
        let phase = PhaseV1::new(OwnerV1::Controller, 2).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != head_key.encode() { return Err(closed()); }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key, phase).map_err(|_| closed())?;
        let body = InputsReadyBodyDataV1::decode(envelope.body()).map_err(|_| closed())?;
        body.require_bundle(self.bundle).map_err(|_| closed())?;
        let accepted = parent.create_storage_original_identity_v1().map_err(native_error)?;
        if envelope.body() != self.body || envelope.coordinates().predecessor != self.predecessor().map_err(|_| closed())?
            || envelope.coordinates().correlation != body.association.seed || body.association.operation != accepted.operation
            || body.association.project != accepted.project || body.association.sandbox != accepted.sandbox
            || body.association.accepted_request != accepted.accepted_request
            || body.association.coissuance_binding != accepted.coissuance_binding
            || body.association.cutoff != accepted.original_cutoff { return Err(closed()); }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, head_key)
            .and_then(|latest| latest.check_record(head_key, envelope)).map_err(|_| closed())
    }
}
