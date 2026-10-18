//! Retains the once-only selected settled Capture and final confirmation custody.
//!
//! The genuine Source/Window ticket and complete all-owner row precede these
//! transport markers. They authenticate neither a portable DTO nor allocation
//! authority. Every initialized owner remains in the Controller through refusal.
//! Old original Capture and confirmation5 routing/guards remain unchanged.

use super::*;
use crate::operational_time::OperationalDeadline;
use crate::reference_packet::service::restored_settled_capture::*;
use crate::reference_packet::service::restored_settled_confirmation::*;
use std::mem::size_of;

#[path = "settled_capture/confirmation.rs"]
mod confirmation;
#[path = "settled_capture/prepare.rs"]
mod prepare;
#[path = "settled_capture/upload.rs"]
mod upload;
pub use upload::{
    PreparedRestoredSettledCaptureAuxiliaryOriginal, RestoredSettledCaptureAuxiliaryBody,
};
#[path = "settled_capture/history.rs"]
mod history;
#[path = "settled_capture/storage.rs"]
mod storage;

pub use history::OriginalRestoredSettledCaptureData;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Reserving,
    Reserved,
    Assigning,
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    Captured,
    Confirming,
    Complete,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ConfirmationStage {
    Preparing,
    Assigned,
    Publishing,
    Complete,
}

pub(super) struct AssignedRestoredSettledCapture {
    request_id: Id,
    operation_id: Id,
    body: BeginRequest,
    request: PacketRestoredSettledCaptureRequest,
    prefix_frontier: Option<U64>,
    auxiliary_uploads: [Option<upload::AssignedAuxiliaryUpload>; 2],
    maximum_auxiliary_originals: [usize; 2],
    arguments: Option<CaptureArguments>,
    unsigned_request: Option<Value>,
    original: Option<Envelope>,
    context: Option<PacketRestoredSettledCaptureContext>,
    artifact: Option<PacketRestoredSettledCaptureArtifact>,
    canonical: Vec<u8>,
    cut: Option<OperationalDeadline>,
    terminal: Option<Envelope>,
    decoded: Option<Box<ResponseBody>>,
    roots: Vec<ContentRef>,
    capture_frontier: Option<U64>,
    confirmation: Option<AssignedConfirmation>,
    stage: Stage,
}

struct AssignedConfirmation {
    request_id: Id,
    request: PacketRestoredSettledAfterConfirmationRequest,
    extension: Option<Value>,
    original: Option<Envelope>,
    cut: Option<OperationalDeadline>,
    terminal: Option<Envelope>,
    decoded: Option<Box<ResponseBody>>,
    receipt: Option<PacketRestoredSettledAfterConfirmationReceipt>,
    roots: Vec<ContentRef>,
    frontier: Option<U64>,
    stage: ConfirmationStage,
}

/// Borrows the same once-assigned Capture without moving any retained partial.
#[must_use = "retain the same Controller through Capture and fourth-object confirmation"]
pub struct PreparedOriginalRestoredSettledCapture<'a> {
    controller: &'a mut CnpController,
}

impl CnpController {
    pub(super) fn ensure_no_pending_original_restored_settled_capture(
        &self,
    ) -> Result<(), ProviderError> {
        if self
            .original_restored_settled_capture
            .as_ref()
            .is_some_and(|s| s.stage != Stage::Complete)
        {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_restored_settled_capture_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_installed_restored_suffix_data(emitter)?;
        crate::reference_packet::service::complete_restore::settled_recapture::authenticate_restored_settled_capture_selection_data(
            self.session.fresh_restore_query_selection()?, self.authority(),
        )
    }

    /// Reborrows the same retained marker without a new ID, cut or assignment.
    ///
    /// # Errors
    /// Refuses another emitter, revoked selection or a missing once-only owner.
    /// An earlier failure's sticky phase is preserved and cannot be restarted.
    pub fn original_restored_settled_capture_marker_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<PreparedOriginalRestoredSettledCapture<'_>, ProviderError> {
        self.authenticate_restored_settled_capture_data(emitter)?;
        if self.original_restored_settled_capture.is_none() {
            return Err(refused());
        }
        Ok(PreparedOriginalRestoredSettledCapture { controller: self })
    }
}

impl PreparedOriginalRestoredSettledCapture<'_> {
    /// Borrows the actual assigned Capture under its immutable unfinished cut.
    ///
    /// # Errors
    /// Refuses missing assignment, a revoked actor or an expired unfinished cut.
    pub fn original_data(&self) -> Result<&Envelope, ProviderError> {
        self.controller.protocol_owner.ensure_current()?;
        let state = self
            .controller
            .original_restored_settled_capture
            .as_ref()
            .ok_or_else(refused)?;
        let original = state.original.as_ref().ok_or_else(refused)?;
        if matches!(
            state.stage,
            Stage::Assigning | Stage::Unsigned | Stage::Sealing | Stage::Sealed | Stage::Publishing
        ) {
            self.controller
                .session
                .authenticate_original_ack_admit_cut(
                    original.sequence,
                    state.cut.ok_or_else(refused)?,
                )?;
        }
        Ok(original)
    }

    /// Publishes only the same proof-filled original and retains all raw replies.
    ///
    /// # Errors
    /// Refuses another emitter/selection, a nonsealed phase, expired original
    /// cut, uncertain IO or incomplete typed Capture. Failed owners stay retained.
    pub fn publish_data(
        &mut self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<(), ProviderError> {
        self.controller
            .authenticate_restored_settled_capture_data(emitter)?;
        self.original_data()?;
        let state = self
            .controller
            .original_restored_settled_capture
            .as_mut()
            .ok_or_else(refused)?;
        if state.stage != Stage::Sealed {
            return Err(refused());
        }
        state.stage = Stage::Publishing;
        self.controller
            .session
            .publish_original_restored_suffix_into(
                &mut self.controller.custody,
                state.original.as_ref().ok_or_else(refused)?,
                state.cut.ok_or_else(refused)?,
                &mut state.terminal,
                &mut state.decoded,
            )?;
        let terminal = state.terminal.as_ref().ok_or_else(refused)?;
        for value in terminal.body.values() {
            references(value, &mut state.roots)?;
        }
        for reference in &state.roots {
            self.controller.custody.content().get(reference)?;
        }
        let body = state.decoded.as_deref().ok_or_else(refused)?;
        if !matches!(&body.result, Some(MethodResult::Capture(_)))
            || !matches!(
                &body.shape,
                crate::bodies::ResponseShape::Completed {
                    operation_state: crate::bodies::OperationState::Completed,
                    ..
                }
            )
        {
            return Err(refused());
        }
        state.capture_frontier = Some(self.controller.session.fresh_restore_query_sequence()?);
        state.stage = Stage::Captured;
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("settled Capture original, phase or confirmation changed")
}

fn request_id_reserved(state: &AssignedRestoredSettledCapture, request_id: &Id) -> bool {
    state.request_id == *request_id
        || state
            .confirmation
            .as_ref()
            .is_some_and(|value| value.request_id == *request_id)
        || state.auxiliary_uploads.iter().flatten().any(|upload| {
            upload
                .pending
                .as_ref()
                .is_some_and(|value| value.request_id == *request_id)
                || upload
                    .completed
                    .iter()
                    .any(|value| value.request_id == *request_id)
        })
}

#[path = "settled_capture/current.rs"]
mod current;
pub use current::OriginalCompletedRestoredSettledCaptureData;

#[path = "settled_capture/construction.rs"]
mod construction;
pub use construction::{
    OriginalRestoredSettledCaptureConstructionData, OriginalRestoredSettledCaptureProspectiveData,
};
#[path = "settled_capture/typed_owner.rs"]
mod typed_owner;
pub use typed_owner::RestoredSettledCaptureTypedOwnerData;
