//! Retains independent settled-Capture preparation and all spent owner phases.
//!
//! Pending input ownership precedes every allocation. A complete whole-world
//! census admits passive prequote work, then the real Source/native rows, then
//! the append. No later row or successful write refunds an earlier commitment.

use super::*;
use crate::node_adapters::cnp::{CnpSemanticSource, OriginalSourceRestoredCaptureConstructionData};
use crate::node_contract::{
    OriginalLineageOwnerCaptureTicket, OriginalLineageRuntimeRecord,
    OriginalRestoredCaptureRuntimeConstructionData, OriginalRestoredCoordinatorBoundary17,
    OriginalRestoredCoordinatorCheckpointOwner17, WorldActivation,
};
use crate::node_scheduling::InputPayload;
use crucible_node_provider::{
    client::CnpController, reference_packet::service::PacketNative5SourceLaunch,
};

#[path = "restored_capture/attempt_guard.rs"]
mod attempt_guard;
#[path = "restored_capture/banks.rs"]
mod banks;
#[path = "restored_capture/checkpoint.rs"]
mod checkpoint;
#[path = "restored_capture/checkpoint_inputs.rs"]
mod checkpoint_inputs;
#[path = "restored_capture/claims.rs"]
mod claims;
#[path = "restored_capture/member.rs"]
mod member;

#[path = "restored_capture/inputs.rs"]
mod inputs;
pub(crate) use inputs::{
    OriginalRestoredCaptureImportedOwnerInputs, OriginalRestoredCaptureSigningInputs,
};

pub use claims::{OriginalRestoredCaptureClaim, OriginalRestoredCaptureRequestData};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Preparing,
    Quoted,
    Admitted,
    Verified,
    Failed,
}

struct Attempt {
    capture_id: Id,
    cut: crucible_node_contract::Position,
    ordinal: crucible_node_contract::U64,
    runtime: *const NodeRuntime,
    runtime_row: OriginalRestoredCaptureRuntimeConstructionData,
    boundary: OriginalRestoredCoordinatorBoundary17,
    checkpoint: OriginalRestoredCoordinatorCheckpointOwner17,
    checkpoint_inputs: checkpoint_inputs::OriginalRestoredCaptureCheckpointInputs17,
    counting_banks: [banks::CountingBanks; 3],
    writer_join: Cell<checkpoint::WriterJoinStage>,
    window_work: (usize, usize, usize),
    prequote: [Option<(usize, usize, usize)>; 3],
    rows: [Option<OriginalSourceRestoredCaptureConstructionData>; 3],
    members: [Cell<u8>; 3],
    stage: Cell<Stage>,
}

impl Attempt {
    fn request_data(&self) -> OriginalRestoredCaptureRequestData<'_> {
        OriginalRestoredCaptureRequestData {
            capture_id: &self.capture_id,
            cut: self.cut,
            ordinal: self.ordinal,
            maximum_runtime_record_encoded_bytes: self
                .runtime_row
                .maximum_runtime_record_encoded_bytes_data(),
            maximum_coordinator_checkpoint_encoded_bytes: self
                .boundary
                .maximum_checkpoint_encoded_bytes_data(),
        }
    }

    fn future_requested_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let mut requested = checked_sum(
            &[
                self.runtime_row.requested_bytes_data()?,
                self.boundary.construction_requested_bytes_data(),
                self.window_work.0,
                self.window_work.1,
                self.window_work.2,
            ],
            maximum,
        )?;
        for work in self.prequote.iter().flatten() {
            requested = checked_sum(&[requested, work.0, work.1, work.2], maximum)?;
        }
        for row in self.rows.iter().flatten() {
            requested = checked_sum(&[requested, row.requested_bytes_data()?], maximum)?;
        }
        Ok(requested)
    }
}

pub(super) struct Ledger {
    pending: Option<Attempt>,
    attempts: Vec<Attempt>,
}

impl Ledger {
    pub(super) fn new() -> Self {
        Self {
            pending: None,
            attempts: Vec::new(),
        }
    }

    fn active(&self, slot: usize) -> Result<&Attempt, RuntimeError> {
        self.attempts
            .get(slot)
            .filter(|_| slot.checked_add(1) == Some(self.attempts.len()))
            .ok_or(RuntimeError::ForeignAuthority)
    }

    pub(super) fn future_requested_bytes_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut requested = 0;
        for attempt in self.pending.iter().chain(self.attempts.iter()) {
            requested = checked_sum(
                &[requested, attempt.future_requested_data(maximum)?],
                maximum,
            )?;
        }
        Ok(requested)
    }

    pub(super) fn retained_requested_bytes_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut requested = self
            .attempts
            .capacity()
            .checked_mul(size_of::<Attempt>())
            .ok_or(RuntimeError::ResourceLimit)?;
        for attempt in self.pending.iter().chain(self.attempts.iter()) {
            requested = checked_sum(
                &[
                    requested,
                    attempt.capture_id.allocated_capacity(),
                    attempt.checkpoint.retained_requested_storage_data()?,
                    attempt
                        .checkpoint_inputs
                        .retained_requested_storage_data()?,
                    attempt
                        .counting_banks
                        .iter()
                        .try_fold(0usize, |total, bank| {
                            total
                                .checked_add(bank.retained_requested_storage_data()?)
                                .ok_or(RuntimeError::ResourceLimit)
                        })?,
                ],
                maximum,
            )?;
        }
        Ok(requested)
    }
}

impl CompleteOriginalRestorationWindow {
    /// Moves the caller's actual capture identity into the inline pending owner.
    /// No new string, history bank, ticket or model state is constructed here.
    pub(crate) fn retain_restored_capture_preparation_data(
        &self,
        runtime: &ConformanceRuntime,
        node_runtime: &NodeRuntime,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        capture_id: Id,
        cut: crucible_node_contract::Position,
        ordinal: crucible_node_contract::U64,
        runtime_row: OriginalRestoredCaptureRuntimeConstructionData,
        boundary: OriginalRestoredCoordinatorBoundary17,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current_observation_runtime_data(runtime, plan, world)?;
        self.require_original_current_inspections_settled_data()?;
        for producer in &self.producer_executions {
            producer
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .require_available_data()?;
        }
        for seed in &self.suffix_seeds {
            seed.authenticate(super::continuation_suffix::SeedStage::Verified)?;
        }
        runtime_row.authenticate_original_data(node_runtime, world, cut, ordinal)?;
        if boundary.cut_data() != cut || boundary.ordinal_data() != ordinal {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut ledger = self
            .restored_captures
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger.pending.is_some()
            || ledger.attempts.len() >= 64
            || ledger
                .attempts
                .last()
                .is_some_and(|attempt| attempt.stage.get() != Stage::Verified)
            || ledger
                .attempts
                .iter()
                .any(|attempt| attempt.capture_id == capture_id)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let bank = ledger
            .attempts
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(size_of::<Attempt>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let strings = capture_id
            .allocated_capacity()
            .checked_mul(2)
            .ok_or(RuntimeError::ResourceLimit)?;
        let window_work = (
            checked_sum(&[bank, strings], self.policy.maximum_requested_bytes)?,
            bank,
            counter_scratch_data(),
        );
        checked_sum(
            &[window_work.0, window_work.1, window_work.2],
            self.policy.maximum_requested_bytes,
        )?;
        ledger.pending = Some(Attempt {
            capture_id,
            cut,
            ordinal,
            runtime: node_runtime,
            runtime_row,
            boundary,
            checkpoint: OriginalRestoredCoordinatorCheckpointOwner17::empty(),
            checkpoint_inputs:
                checkpoint_inputs::OriginalRestoredCaptureCheckpointInputs17::default(),
            counting_banks: std::array::from_fn(|_| banks::CountingBanks::default()),
            writer_join: Cell::new(checkpoint::WriterJoinStage::Waiting),
            window_work,
            prequote: [None; 3],
            rows: [None; 3],
            members: std::array::from_fn(|_| Cell::new(0)),
            stage: Cell::new(Stage::Preparing),
        });
        self.restored_capture_in_flight.set(true);
        self.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn with_pending_restored_capture_request_data<R>(
        &self,
        inspect: impl FnOnce(&OriginalRestoredCaptureRequestData<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.origin()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger
            .pending
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if attempt.stage.get() != Stage::Preparing {
            return Err(RuntimeError::OutstandingObligations);
        }
        inspect(&attempt.request_data())
    }

    pub(crate) fn retain_restored_capture_prequote_data(
        &self,
        selected: usize,
        work: (usize, usize, usize),
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        checked_sum(
            &[work.0, work.1, work.2],
            self.policy.maximum_requested_bytes,
        )?;
        if work.2 > self.policy.declared_observer_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut ledger = self
            .restored_captures
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger
            .pending
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let slot = attempt
            .prequote
            .get_mut(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if attempt.stage.get() != Stage::Preparing || slot.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *slot = Some(work);
        self.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn retain_restored_capture_quote_data(
        &self,
        selected: usize,
        row: OriginalSourceRestoredCaptureConstructionData,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let mut ledger = self
            .restored_captures
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger
            .pending
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let slot = attempt
            .rows
            .get_mut(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if attempt.stage.get() != Stage::Preparing
            || slot.is_some()
            || attempt.prequote.iter().any(Option::is_none)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        attempt
            .counting_banks
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .require_quoted_data()?;
        *slot = Some(row);
        // Retain even a refused row before validation; no earlier whole
        // observation remains current after this new future commitment.
        self.whole_observation.require_observation();
        row.requested_bytes_data()?;
        if attempt.rows.iter().all(Option::is_some) {
            attempt.stage.set(Stage::Quoted);
        }
        self.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn append_restored_capture_after_census_data(&self) -> Result<usize, RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let mut ledger = self
            .restored_captures
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger
            .pending
            .as_ref()
            .is_none_or(|attempt| attempt.stage.get() != Stage::Quoted)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // The Runtime row separately reserves the full next history backing.
        // Pending ownership remains inline if reserve_exact fails.
        ledger
            .attempts
            .try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let attempt = ledger
            .pending
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        attempt.stage.set(Stage::Admitted);
        let slot = ledger.attempts.len();
        ledger.attempts.push(attempt);
        self.whole_observation.require_observation();
        Ok(slot)
    }

    pub(crate) fn authenticate_restored_capture_claim_data(
        &self,
        claim: &OriginalRestoredCaptureClaim<'_>,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !std::ptr::eq(self, claim.window)
            || !self.restored_capture_in_flight.get()
            || self.original_installed_source_index_data(source)? != claim.selected
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(claim.slot)?;
        if attempt.stage.get() != Stage::Admitted
            || attempt.writer_join.get() != checkpoint::WriterJoinStage::Verified
            || attempt.members[claim.selected].get() != 1
            || claim.ticket.capture_id() != &attempt.capture_id
            || claim.ticket.cut() != attempt.cut
            || claim.ticket.ordinal() != attempt.ordinal
            || claim.runtime_object.bytes.len()
                > attempt
                    .runtime_row
                    .maximum_runtime_record_encoded_bytes_data()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        claim.row.authenticate_owner_data(
            source,
            controller,
            claim.read_owner,
            &attempt.request_data(),
        )?;
        self.authenticate_suffix_identity_data(
            claim.selected,
            source,
            claim.read_owner,
            claim.world,
            self.original_complete_scope_proof_identity_data()?,
        )
    }

    pub(crate) fn complete_restored_capture_member_data(
        &self,
        claim: &OriginalRestoredCaptureClaim<'_>,
    ) -> Result<(), RuntimeError> {
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(claim.slot)?;
        if attempt.stage.get() != Stage::Admitted || attempt.members[claim.selected].replace(2) != 1
        {
            attempt.stage.set(Stage::Failed);
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn fail_restored_capture_member_data(&self, slot: usize, selected: usize) {
        if let Ok(ledger) = self.restored_captures.try_borrow()
            && let Ok(attempt) = ledger.active(slot)
            && let Some(member) = attempt.members.get(selected)
        {
            member.set(3);
            attempt.stage.set(Stage::Failed);
        }
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn begin_restored_capture_owner_claim_data<'a>(
        &'a self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
        read_owner: *const (),
        world: &'a WorldActivation,
        ticket: &'a OriginalLineageOwnerCaptureTicket<'a>,
        record: &'a OriginalLineageRuntimeRecord,
        runtime_object: &'a InputPayload,
    ) -> Result<OriginalRestoredCaptureClaim<'a>, RuntimeError> {
        self.origin()?;
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        ticket.authenticate_original_restored_identity_data(
            world,
            record,
            runtime_object,
            ticket.owner(),
            ticket.participants(),
        )?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let slot = ledger
            .attempts
            .len()
            .checked_sub(1)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = ledger.active(slot)?;
        if attempt.stage.get() != Stage::Admitted
            || attempt.writer_join.get() != checkpoint::WriterJoinStage::Verified
            || attempt.capture_id != *ticket.capture_id()
            || attempt.cut != ticket.cut()
            || attempt.ordinal != ticket.ordinal()
            || attempt
                .members
                .get(selected)
                .is_none_or(|member| member.get() != 0)
            || !self
                .activation_world
                .get()
                .is_some_and(|actual| actual.same_authority(world))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let row = attempt.rows[selected].ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_owner_data(source, controller, read_owner, &attempt.request_data())?;
        attempt.members[selected].set(1);
        let maximum_runtime_record_encoded_bytes = attempt
            .runtime_row
            .maximum_runtime_record_encoded_bytes_data();
        let maximum_coordinator_checkpoint_encoded_bytes =
            attempt.boundary.maximum_checkpoint_encoded_bytes_data();
        attempt
            .checkpoint
            .object_data()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let checkpoint = std::cell::Ref::filter_map(ledger, |ledger| {
            ledger.attempts.get(slot).map(|attempt| &attempt.checkpoint)
        })
        .map_err(|_| RuntimeError::ForeignAuthority)?;
        let claim = OriginalRestoredCaptureClaim {
            window: self,
            selected,
            slot,
            ticket,
            record,
            runtime_object,
            world,
            row,
            controller,
            read_owner,
            maximum_runtime_record_encoded_bytes,
            maximum_coordinator_checkpoint_encoded_bytes,
            checkpoint,
            completed: Cell::new(false),
            source_verified: Cell::new(false),
        };
        claim.authenticate_current_data(source, controller)?;
        Ok(claim)
    }

    pub(crate) fn admitted_restored_capture_id_data(
        &self,
        slot: usize,
    ) -> Result<Id, RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        if attempt.stage.get() != Stage::Admitted
            || attempt.members.iter().any(|member| member.get() != 0)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(attempt.capture_id.clone())
    }

    pub(crate) fn complete_restored_capture_archive_data(
        &self,
        slot: usize,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        if attempt.stage.get() != Stage::Admitted
            || attempt.members.iter().any(|member| member.get() != 2)
        {
            attempt.stage.set(Stage::Failed);
            return Err(RuntimeError::OutstandingObligations);
        }
        self.whole_observation.authenticate_dispatch_data()?;
        attempt.stage.set(Stage::Verified);
        self.restored_capture_in_flight.set(false);
        self.whole_observation.require_observation();
        Ok(())
    }
}

impl CompleteOriginalRestorationWindow {
    fn authenticate_restored_capture_quote_inputs_data(
        &self,
        selected: usize,
        erased: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        read_owner: *const (),
        request: &OriginalRestoredCaptureRequestData<'_>,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if maximum != self.policy.maximum_requested_bytes
            || self.original_installed_source_index_data(erased)? != selected
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let node = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        node.authenticate_original_owner_data(&self.sources[selected], read_owner)?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger
            .pending
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if attempt.stage.get() != Stage::Preparing
            || attempt.capture_id != *request.capture_id
            || attempt.cut != request.cut
            || attempt.ordinal != request.ordinal
            || attempt
                .runtime_row
                .maximum_runtime_record_encoded_bytes_data()
                != request.maximum_runtime_record_encoded_bytes
            || attempt.boundary.maximum_checkpoint_encoded_bytes_data()
                != request.maximum_coordinator_checkpoint_encoded_bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn quote_original_restored_capture_prequote_data(
        &self,
        selected: usize,
        erased: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &OriginalRestoredCaptureRequestData<'_>,
        node_history: &crate::node_adapters::cnp::OriginalRestoredSettledNodeHistoryView<'_>,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.authenticate_restored_capture_quote_inputs_data(
            selected, erased, read_owner, request, maximum,
        )?;
        let source = &self.sources[selected];
        let mut work = None;
        self.with_original_restored_capture_signing_inputs_data(
            selected,
            source,
            self.original_complete_scope_proof_identity_data()?,
            |inputs| {
                work = Some(source.original_restored_capture_prequote_storage_data(
                    controller,
                    read_owner,
                    launch,
                    raw5,
                    inputs,
                    request,
                    node_history,
                    maximum,
                )?);
                Ok(())
            },
        )?;
        work.ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(crate) fn quote_original_restored_capture_construction_data(
        &self,
        selected: usize,
        erased: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        request: &OriginalRestoredCaptureRequestData<'_>,
        node_history: &crate::node_adapters::cnp::OriginalRestoredSettledNodeHistoryView<'_>,
        maximum: usize,
    ) -> Result<OriginalSourceRestoredCaptureConstructionData, RuntimeError> {
        self.authenticate_restored_capture_quote_inputs_data(
            selected, erased, read_owner, request, maximum,
        )?;
        self.whole_observation.authenticate_dispatch_data()?;
        {
            let ledger = self
                .restored_captures
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let attempt = ledger
                .pending
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            if attempt.prequote.iter().any(Option::is_none) || attempt.rows[selected].is_some() {
                return Err(RuntimeError::OutstandingObligations);
            }
        }
        let source = &self.sources[selected];
        let mut row = None;
        self.with_original_restored_capture_signing_inputs_data(
            selected,
            source,
            self.original_complete_scope_proof_identity_data()?,
            |inputs| {
                row = Some(self.with_restored_capture_quote_banks_data(
                    selected,
                    source,
                    controller,
                    inputs,
                    node_history,
                    maximum,
                    |quote| {
                        source.original_restored_capture_construction_data(
                            controller,
                            read_owner,
                            launch,
                            raw5,
                            inputs,
                            request,
                            node_history,
                            quote,
                            maximum,
                        )
                    },
                )?);
                Ok(())
            },
        )?;
        row.ok_or(RuntimeError::OwnerUnavailable)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn restored_capture_node_data(&self, selected: usize) -> Result<&Id, RuntimeError> {
        self.origin()?;
        self.sources
            .get(selected)
            .map(|source| &source.installation().binding.compatibility.node_id)
            .ok_or(RuntimeError::UnknownNode)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::{
        cell::{Ref, RefMut},
        iter::Chain,
        option, slice,
    };
    type Attempts = Chain<option::Iter<'static, Attempt>, slice::Iter<'static, Attempt>>;
    size_of::<Ledger>()
        + size_of::<Attempt>()
        + size_of::<Stage>()
        + size_of::<Option<Attempt>>()
        + size_of::<Vec<Attempt>>()
        + size_of::<Attempts>()
        + size_of::<Ref<'static, Ledger>>()
        + size_of::<RefMut<'static, Ledger>>()
        + size_of::<Result<Ref<'static, Ledger>, std::cell::BorrowError>>()
        + size_of::<Result<RefMut<'static, Ledger>, std::cell::BorrowMutError>>()
        + size_of::<OriginalRestoredCaptureRequestData<'static>>()
        + size_of::<OriginalRestoredCaptureClaim<'static>>()
        + size_of::<[Option<(usize, usize, usize)>; 3]>()
        + size_of::<[Option<OriginalSourceRestoredCaptureConstructionData>; 3]>()
        + size_of::<[Cell<u8>; 3]>()
        + size_of::<slice::Iter<'static, Option<(usize, usize, usize)>>>()
        + size_of::<slice::Iter<'static, Option<OriginalSourceRestoredCaptureConstructionData>>>()
        + size_of::<slice::Iter<'static, Cell<u8>>>()
        + size_of::<Result<OriginalRestoredCaptureClaim<'static>, RuntimeError>>()
        + size_of::<Result<OriginalSourceRestoredCaptureConstructionData, RuntimeError>>()
        + size_of::<Result<(usize, usize, usize), RuntimeError>>()
        + size_of::<Result<Id, RuntimeError>>()
        + size_of::<Option<OriginalSourceRestoredCaptureConstructionData>>()
        + size_of::<Option<(usize, usize, usize)>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<&PacketCompleteSemanticSource, RuntimeError>>()
        + checkpoint_inputs::counter_scratch_data()
        + size_of::<attempt_guard::OriginalRestoredCaptureAttemptGuard<'static>>()
        + crate::node_contract::coordinator_commitment::counter_scratch_data()
        + NodeRuntime::original_restored_capture_runtime_counter_scratch_data()
        + OriginalLineageOwnerCaptureTicket::original_restored_identity_counter_scratch_data()
        + crate::node_adapters::cnp::original_restored_settled_semantic_history_counter_scratch_data(
        )
        + PacketCompleteSemanticSource::original_restored_capture_counter_scratch_data()
        + banks::counter_scratch_data()
}
