//! Commits RootValidated from the same completed authenticated Root turn.
//!
//! The original private lender remains borrowed through the shared native
//! append, readback and independent posts. No decoded authorization, receiving
//! vector or checksum can construct this producer's append binding.

use super::*;
use super::super::ready::root_exchange::OriginalCreateStorageRootUseAuthorizationV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    ready::InputsReadyNativeReceiptDataV1,
    transport::FRAME_HEADER_BYTES,
    use_authorized::UseAuthorizedNativeReceiptDataV1,
    use_reserved::{RootValidatedBodyDataV1, ROOT_VALIDATED_BODY_BYTES_V1,
        ROOT_VALIDATED_RECORD_BYTES_V1},
};

#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct RootValidatedOriginalsV1 {
    entered: bool,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    encoded: Option<Result<[u8; ROOT_VALIDATED_BODY_BYTES_V1], HistoryErrorV1>>,
    pair: OriginalHistoryPairV1,
    primary: Option<ResultV1<()>>,
    complete: bool,
}

impl RootValidatedOriginalsV1 {
    fn receiving_demand_v1(controller: &Journal, source: &Journal)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        type FixedModels = (RootValidatedAppendBindingV1<'static>,
            RootValidatedBodyDataV1<'static>, UseAuthorizedNativeReceiptDataV1<'static>,
            InputsReadyNativeReceiptDataV1<'static>);
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<FixedModels>().checked_mul(4)?))
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        // Fixed models and Results are compiled bytes, not namespace entries.
        // The same positively disposed HistoryNames peak covers fresh probes;
        // each new retained Source ancestor backing is paid cumulatively here.
        let names = crate::journal::create_storage_name_peak_demand_v1()?;
        let backing = ResourceVector::ZERO.with(D::MemoryBytes, names.get(D::MemoryBytes));
        let fixed = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::Conflict)?);
        let demand = pair_fixed_demand(ROOT_VALIDATED_RECORD_BYTES_V1)?
            .checked_add(fixed)?.checked_add(backing)?
            .checked_add(controller.create_storage_semantic_append_demand_v1()?)?;
        demand.checked_add(source.create_storage_semantic_append_demand_v1()?)
            .map_err(ResourceReservationErrorV1::from)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn started(&self) -> bool {
        self.entered
    }

    pub(in crate::controller_resource_reservation::create_intake) fn produce_once(
        &mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1,
        authorization: &OriginalCreateStorageRootUseAuthorizationV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered { return Err(ResourceReservationErrorV1::Conflict); }
        self.entered = true;
        self.primary = Some(self.produce_inner(parent, intake, histories, assignment,
            authorization, controller, source, profile));
        // A failed primary never cancels the separately prepaid trailing posts.
        if matches!(self.funding, Some(Ok(()))) && !self.pair.posts_attempted {
            if let (Ok(original), Ok(cutoff)) = (intake.create_storage_j_data_v1(), authorization.cutoff_v1()) {
                self.pair.finish_posts_once(intake, controller, source.journal_ref_v1(), profile,
                    original.clock, cutoff, HistoryRoleV1::Controller);
            }
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && self.pair.complete
            && self.failure().is_none();
        if self.complete { Ok(()) } else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn produce_inner(&mut self, parent: &ProjectPreparationReservationAttemptV1,
        intake: &mut Q04OriginalIntakeAttemptV1, histories: &CreateStorageOriginalHistoriesV1,
        assignment: &assignment::AssignmentPlannedOriginalV1,
        authorization: &OriginalCreateStorageRootUseAuthorizationV1<'_>,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> ResultV1<()> {
        let original = intake.create_storage_j_data_v1()?.clock;
        let cutoff = authorization.cutoff_v1()?;
        let lane = intake.create_lane()?;
        let inputs = authorization.inputs_ready_v1()?;
        self.funding = Some((|| {
            parent.require_create_storage_association(controller, source, profile)?;
            intake.require_create_history_names_peak_v1()?;
            let demand = Self::receiving_demand_v1(controller, source.journal_ref_v1())?;
            intake.reserve_root_validated_capture_once(demand)?;
            intake.extend_create_capture_observers_once(profile, 6)
        })());
        retained(&self.funding)?;
        self.pair.enter_once(parent, intake, controller, source.journal_ref_v1(), profile,
            HistoryRoleV1::Controller)?;
        self.encoded = Some(UseAuthorizedNativeReceiptDataV1::decode(
            &authorization.frame_v1()[FRAME_HEADER_BYTES..], lane)
            .and_then(|authorization| RootValidatedBodyDataV1 { authorization }.encode(lane)));
        let body = retained(&self.encoded)?;
        let binding = RootValidatedAppendBindingV1 {
            lane, intent: &histories.intent.record, planned: assignment.bundle_record_v1()?,
            authorization, inputs, body,
        };
        self.pair.produce_once(parent, intake, controller, source.journal_ref_v1(), profile,
            HistoryRoleV1::Controller, lane, authorization.association_v1()?.association.seed,
            original, cutoff, Some((inputs.after_next, inputs.after_end)), body,
            Some(HistorySuccessorBindingV1::RootValidated(&binding)))
    }

    pub(in crate::controller_resource_reservation::create_intake) fn position(&self)
        -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>
    {
        if !self.complete || self.failure().is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.pair.after.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn retained_record_v1(&self)
        -> Result<&[u8], ResourceReservationErrorV1>
    {
        self.position()?;
        Ok(&self.pair.record)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn retained_head_v1(&self)
        -> Result<&[u8; HEAD_BYTES], ResourceReservationErrorV1>
    {
        self.position()?;
        Ok(&self.pair.head)
    }

    // Both peers size U from the SAME actual InputsReady prefix. The later
    // returned RootValidated position is a separate exact successor, not the
    // independent Root reader's original extent.
    pub(in crate::controller_resource_reservation::create_intake) fn predecessor_position_v1(&self)
        -> Result<CreateStorageWriterPositionV1, ResourceReservationErrorV1>
    {
        self.position()?;
        self.pair.before.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn checksum_v1(&self, lane: [u8; 16])
        -> Result<[u8; 32], ResourceReservationErrorV1>
    {
        self.position()?;
        RecordEnvelopeV1::decode(&self.pair.record,
            KeyV1::new(lane, OwnerV1::Controller, 4).map_err(|_| ResourceReservationErrorV1::Conflict)?,
            PhaseV1::new(OwnerV1::Controller, 3).map_err(|_| ResourceReservationErrorV1::Conflict)?)
            .map(|record| record.checksum())
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn StdError + 'static)>
    {
        cause(&self.funding).or_else(|| self.pair.primary_failure())
            .or_else(|| cause(&self.encoded)).or_else(|| cause(&self.primary))
            .or_else(|| self.pair.post_failure())
    }
}

pub(super) struct RootValidatedAppendBindingV1<'held> {
    lane: [u8; 16],
    intent: &'held [u8],
    planned: &'held [u8],
    authorization: &'held OriginalCreateStorageRootUseAuthorizationV1<'held>,
    inputs: InputsReadyNativeReceiptDataV1<'held>,
    body: &'held [u8],
}

impl RootValidatedAppendBindingV1<'_> {
    pub(super) fn predecessor(&self) -> Result<[u8; 32], HistoryErrorV1> {
        Ok(RecordEnvelopeV1::decode(self.inputs.record, KeyV1::new(self.lane, OwnerV1::Controller, 3)?,
            PhaseV1::new(OwnerV1::Controller, 2)?)?.checksum())
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
        require_exact_controller_prefix_v1(state, self.lane,
            &[(1, self.intent), (2, self.planned), (3, self.inputs.record)], &self.inputs.latest_head)?;
        let [member, head] = transaction.records() else { return Err(closed()); };
        let key = KeyV1::new(self.lane, OwnerV1::Controller, 4).map_err(|_| closed())?;
        let head_key = KeyV1::new(self.lane, OwnerV1::Controller, 0).map_err(|_| closed())?;
        let phase = PhaseV1::new(OwnerV1::Controller, 3).map_err(|_| closed())?;
        if member.namespace() != crate::RecordNamespace::CreateStorageHistory
            || head.namespace() != crate::RecordNamespace::CreateStorageHistory
            || member.key() != key.encode() || head.key() != head_key.encode() { return Err(closed()); }
        let envelope = RecordEnvelopeV1::decode(member.value().ok_or_else(closed)?, key, phase)
            .map_err(|_| closed())?;
        let body = RootValidatedBodyDataV1::decode(envelope.body(), self.lane).map_err(|_| closed())?;
        let accepted = parent.create_storage_original_identity_v1().map_err(native_error)?;
        let association = self.authorization.association_v1().map_err(native_error)?.association;
        if envelope.body() != self.body
            || &envelope.body()[8..] != &self.authorization.frame_v1()[FRAME_HEADER_BYTES..]
            || envelope.coordinates().predecessor != self.predecessor().map_err(|_| closed())?
            || envelope.coordinates().correlation != association.seed
            || body.authorization.body(self.lane).map_err(|_| closed())?.association != association
            || association.operation != accepted.operation || association.project != accepted.project
            || association.sandbox != accepted.sandbox || association.accepted_request != accepted.accepted_request
            || association.coissuance_binding != accepted.coissuance_binding
            || association.cutoff != accepted.original_cutoff { return Err(closed()); }
        LatestHeadV1::decode(head.value().ok_or_else(closed)?, head_key)
            .and_then(|latest| latest.check_record(head_key, envelope)).map_err(|_| closed())
    }
}
