//! Binds a separately admitted settled codec to the genuine administrative ticket.
//!
//! Neither a portable checkpoint nor the Window's resource row issues Capture.
//! The callback must also carry the original Runtime-created owner reservation.

use super::*;
use crate::node_contract::{OriginalLineageOwnerCaptureTicket, OriginalLineageRuntimeRecord};
use crate::node_scheduling::InputPayload;
use crucible_node_transport::client::CnpController;
use std::cell::Ref;

/// Borrows future request coordinates before Runtime7 or Capture arguments exist.
///
/// This view contains no admission or executable permission. The actual full
/// runtime reference is verified against the genuine owner ticket at dispatch.
#[derive(Clone, Copy)]
pub struct OriginalRestoredCaptureRequestData<'a> {
    pub(crate) capture_id: &'a Id,
    pub(crate) cut: crucible_node_format::Position,
    pub(crate) ordinal: crucible_node_format::U64,
    pub(crate) maximum_runtime_record_encoded_bytes: usize,
    pub(crate) maximum_coordinator_checkpoint_encoded_bytes: usize,
}

/// Borrows a real administrative reservation under its fully admitted Window.
///
/// There is no constructor, clone, decoder or conversion from stored history.
/// All three Sources retain independent rows and spent originals. The ticket
/// remains the sole administrative permission; this claim binds its selected
/// settled codec, current World and resource commitment.
pub struct OriginalRestoredCaptureClaim<'a> {
    pub(super) window: &'a CompleteOriginalRestorationWindow,
    pub(super) selected: usize,
    pub(super) slot: usize,
    pub(super) ticket: &'a OriginalLineageOwnerCaptureTicket<'a>,
    pub(super) record: &'a OriginalLineageRuntimeRecord,
    pub(super) runtime_object: &'a InputPayload,
    pub(super) world: &'a WorldActivation,
    pub(super) controller: *const CnpController,
    pub(super) read_owner: *const (),
    pub(super) row: OriginalSourceRestoredCaptureConstructionData,
    pub(super) maximum_runtime_record_encoded_bytes: usize,
    pub(super) maximum_coordinator_checkpoint_encoded_bytes: usize,
    pub(super) checkpoint:
        Ref<'a, crate::node_contract::OriginalRestoredCoordinatorCheckpointOwner17>,
    pub(super) completed: Cell<bool>,
    pub(super) source_verified: Cell<bool>,
}

impl OriginalRestoredCaptureClaim<'_> {
    pub(crate) fn row_data(&self) -> &OriginalSourceRestoredCaptureConstructionData {
        &self.row
    }

    pub(crate) fn world_data(&self) -> &WorldActivation {
        self.world
    }

    pub(crate) fn ticket_data(&self) -> &OriginalLineageOwnerCaptureTicket<'_> {
        self.ticket
    }

    pub(crate) fn capture_operation_data(&self) -> &Id {
        self.ticket.operation_id()
    }

    pub(crate) fn runtime_record_data(&self) -> &OriginalLineageRuntimeRecord {
        self.record
    }

    pub(crate) fn runtime_object_data(&self) -> &InputPayload {
        self.runtime_object
    }

    pub(crate) fn request_data(&self) -> OriginalRestoredCaptureRequestData<'_> {
        OriginalRestoredCaptureRequestData {
            capture_id: self.ticket.capture_id(),
            cut: self.ticket.cut(),
            ordinal: self.ticket.ordinal(),
            maximum_runtime_record_encoded_bytes: self.maximum_runtime_record_encoded_bytes,
            maximum_coordinator_checkpoint_encoded_bytes: self
                .maximum_coordinator_checkpoint_encoded_bytes,
        }
    }

    /// Lends the verified checkpoint retained by this same admitted attempt.
    ///
    /// The mapped ledger loan keeps the actual owner alive for the callback;
    /// no portable reference or caller-created checkpoint can replace it.
    ///
    /// # Errors
    /// Refuses an incomplete checkpoint or an object exceeding its defining row.
    pub(crate) fn coordinator_checkpoint_data(
        &self,
    ) -> Result<(&crucible_node_format::ContentRef, &[u8]), RuntimeError> {
        let object = self
            .checkpoint
            .object_for_runtime_data(self.runtime_object)?;
        if object.bytes.len() > self.maximum_coordinator_checkpoint_encoded_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok((&object.reference, &object.bytes))
    }

    pub(crate) fn authenticate_current_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
    ) -> Result<(), RuntimeError> {
        if self.completed.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.window
            .authenticate_restored_capture_claim_data(self, source, controller)
    }

    pub(crate) fn authenticate_inputs_data(
        &self,
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(inputs.window, self.window)
            || inputs.selected != self.selected
            || !inputs.world.same_authority(self.world)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Repeats real ticket validation under its independent constructor credit.
    ///
    /// This operation allocates complete Runtime7 Value and canonical banks.
    /// Its defining prequote funds both before/after Source uses separately.
    pub(crate) fn authenticate_ticket_data(
        &self,
        owner: &crate::node_contract::OwnerIdentity,
        participants: &[Id],
    ) -> Result<(), RuntimeError> {
        self.ticket.authenticate_scope(
            self.world,
            self.record,
            self.runtime_object,
            owner,
            participants,
        )
    }

    pub(crate) fn with_original_inputs_data<R>(
        &self,
        source: &PacketCompleteSemanticSource,
        inspect: impl FnOnce(&OriginalRestoredCaptureSigningInputs<'_>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        let mut result = None;
        self.window
            .with_original_restored_capture_signing_inputs_data(
                self.selected,
                source,
                self.window.original_complete_scope_proof_identity_data()?,
                |inputs| {
                    self.authenticate_inputs_data(inputs)?;
                    result = Some(inspect(inputs)?);
                    Ok(())
                },
            )?;
        result.ok_or(RuntimeError::OwnerUnavailable)
    }

    pub(crate) fn authenticate_terminal_member_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current_data(source, controller)?;
        let plan = self
            .window
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .window
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.window
            .authenticate_original_complete_member_data(&plan, scope)?;
        self.authenticate_current_data(source, controller)
    }

    pub(crate) fn authenticate_node_data(
        &self,
        route: &crate::node_contract::NodeRoute,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        if !world.same_authority(self.world)
            || route.owners.as_slice() != std::slice::from_ref(self.ticket.owner())
            || !self.ticket.participants().contains(&route.node)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(crate) fn retain_source_completion_data(
        &self,
        evidence: &crate::node_adapters::cnp::OriginalSourceRestoredCaptureCompletion<'_>,
    ) -> Result<(), RuntimeError> {
        evidence.authenticate_claim_data(
            &self.row,
            self.world,
            self.ticket,
            self.record,
            self.runtime_object,
        )?;
        if self.source_verified.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn complete_source_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        self.authenticate_terminal_member_data(source, controller)?;
        if !self.source_verified.get() {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.window.complete_restored_capture_member_data(self)?;
        self.completed.set(true);
        Ok(())
    }
}

impl Drop for OriginalRestoredCaptureClaim<'_> {
    fn drop(&mut self) {
        if !self.completed.get() {
            self.window
                .fail_restored_capture_member_data(self.slot, self.selected);
        }
        self.window.whole_observation.require_observation();
    }
}
