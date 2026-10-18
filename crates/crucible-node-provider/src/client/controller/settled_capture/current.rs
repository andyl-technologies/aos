//! Lends completed Capture17 and its fourth Poll at the actual current SDK frontier.
//!
//! The private completed owners already passed full assigned-envelope and
//! terminal digest checks. This read-only lender repeats actual journal/typed
//! correspondence without allocating a DOM, canonical copy or new operation.
//! Source/Core still authenticate the native proof and real Capture claim.

use super::*;

/// Borrows actual completed Capture and confirmation owners on the same Controller.
///
/// This loan has no public constructor, Clone, decoder or mutable escape. It
/// supplies correspondence DATA, never a Source/native Capture permission.
pub struct OriginalCompletedRestoredSettledCaptureData<'a> {
    controller: &'a CnpController,
    capture: &'a AssignedRestoredSettledCapture,
    confirmation: &'a AssignedConfirmation,
    frontier: U64,
    capture_original: &'a Envelope,
    capture_terminal: &'a Envelope,
    capture_body: &'a ResponseBody,
    confirmation_original: &'a Envelope,
    confirmation_terminal: &'a Envelope,
    confirmation_body: &'a ResponseBody,
    receipt: &'a PacketRestoredSettledAfterConfirmationReceipt,
}

impl CnpController {
    /// Borrows the actual completed pair and fourth receipt at the unchanged frontier.
    ///
    /// Earlier Observe evidence remains historical; this method does not pretend
    /// it is current after Capture-owned uploads or confirmation traffic.
    ///
    /// # Errors
    /// Refuses another emitter/selection, incomplete or failed Capture, a changed
    /// actual journal pair, missing typed receipt/content or an advanced frontier.
    pub fn original_completed_restored_settled_capture_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
    ) -> Result<OriginalCompletedRestoredSettledCaptureData<'_>, ProviderError> {
        self.authenticate_restored_settled_capture_data(emitter)?;
        let capture = self
            .original_restored_settled_capture
            .as_ref()
            .ok_or_else(refused)?;
        let confirmation = capture.confirmation.as_ref().ok_or_else(refused)?;
        if capture.stage != Stage::Complete || confirmation.stage != ConfirmationStage::Complete {
            return Err(refused());
        }
        let frontier = confirmation.frontier.ok_or_else(refused)?;
        if frontier != self.session.fresh_restore_query_sequence()? {
            return Err(refused());
        }
        let capture_original = capture.original.as_ref().ok_or_else(refused)?;
        let capture_terminal = capture.terminal.as_ref().ok_or_else(refused)?;
        let confirmation_original = confirmation.original.as_ref().ok_or_else(refused)?;
        let confirmation_terminal = confirmation.terminal.as_ref().ok_or_else(refused)?;
        authenticate_pair(
            self,
            &capture.request_id,
            capture_original,
            capture_terminal,
        )?;
        authenticate_pair(
            self,
            &confirmation.request_id,
            confirmation_original,
            confirmation_terminal,
        )?;

        let capture_body = capture.decoded.as_deref().ok_or_else(refused)?;
        let confirmation_body = confirmation.decoded.as_deref().ok_or_else(refused)?;
        let Some(MethodResult::Capture(result)) = &capture_body.result else {
            return Err(refused());
        };
        let Some(MethodResult::Poll(poll)) = &confirmation_body.result else {
            return Err(refused());
        };
        let receipt = confirmation.receipt.as_ref().ok_or_else(refused)?;
        if !matches!(
            &capture_body.shape,
            crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                ..
            }
        ) || !matches!(
            &confirmation_body.shape,
            crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                ..
            }
        ) || result.owner_state_refs.len() != 1
            || receipt.capture != confirmation.request
            || receipt.capture.capture_request_id != capture.request_id
            || receipt.capture.capture_operation_id != capture.operation_id
            || receipt.capture.native_snapshot_ref != result.capture_manifest
            || receipt.capture.native_control_ref != result.owner_state_refs[0]
            || receipt.capture.native_anchor_ref != result.unchanged_cut_receipt
            || poll.operation_id != capture.operation_id
            || !poll.observations.is_empty()
            || poll.next_observation_sequence != U64::new(0)
            || poll.outcome.0.as_ref() != Some(&capture_terminal.body)
        {
            return Err(refused());
        }
        self.custody.content().get(&receipt.native_after_ref)?;
        Ok(OriginalCompletedRestoredSettledCaptureData {
            controller: self,
            capture,
            confirmation,
            frontier,
            capture_original,
            capture_terminal,
            capture_body,
            confirmation_original,
            confirmation_terminal,
            confirmation_body,
            receipt,
        })
    }
}

fn authenticate_pair(
    controller: &CnpController,
    id: &Id,
    original: &Envelope,
    terminal: &Envelope,
) -> Result<(), ProviderError> {
    let actual = controller.original(id).ok_or_else(refused)?;
    if &actual.request != original || actual.response.as_ref() != Some(terminal) {
        return Err(refused());
    }
    original.matches_response(terminal)
}

impl OriginalCompletedRestoredSettledCaptureData<'_> {
    /// Borrows the actual complete proof-filled Capture request and both replies.
    pub fn capture_pair_data(&self) -> (&Envelope, &Envelope, &ResponseBody) {
        (
            self.capture_original,
            self.capture_terminal,
            self.capture_body,
        )
    }

    /// Borrows the actual fourth Poll original, terminal and independent typed reply.
    pub fn confirmation_pair_data(&self) -> (&Envelope, &Envelope, &ResponseBody) {
        (
            self.confirmation_original,
            self.confirmation_terminal,
            self.confirmation_body,
        )
    }

    /// Borrows the actual Source-signed Capture request retained before publication.
    pub fn request_data(&self) -> &PacketRestoredSettledCaptureRequest {
        &self.capture.request
    }

    /// Borrows the complete confirmation request already joined to this Capture.
    pub fn confirmation_request_data(&self) -> &PacketRestoredSettledAfterConfirmationRequest {
        &self.confirmation.request
    }

    /// Borrows the actual typed fourth receipt, without creating a native proof.
    pub fn receipt_data(&self) -> &PacketRestoredSettledAfterConfirmationReceipt {
        self.receipt
    }

    /// Returns the actual post-confirmation SDK frontier checked by construction.
    pub fn frontier_data(&self) -> U64 {
        self.frontier
    }

    /// Returns the pre-auxiliary-upload prefix cut retained by this same once owner.
    ///
    /// # Errors
    /// Refuses a missing private cut without inferring one from request DATA.
    pub fn prefix_frontier_data(&self) -> Result<U64, ProviderError> {
        self.capture.prefix_frontier.ok_or_else(refused)
    }

    /// Borrows the same proof-filled canonical Capture bytes retained by the SDK.
    pub fn canonical_original_data(&self) -> &[u8] {
        &self.capture.canonical
    }

    /// Borrows only a hash-verified content object named by these actual replies.
    ///
    /// # Errors
    /// Refuses foreign or missing content; this read runs no Blob fetch or IO.
    pub fn transferred_object_data(&self, reference: &ContentRef) -> Result<&[u8], ProviderError> {
        let Some(MethodResult::Capture(result)) = &self.capture_body.result else {
            return Err(refused());
        };
        if reference != &result.capture_manifest
            && reference != &result.unchanged_cut_receipt
            && !result.owner_state_refs.contains(reference)
            && reference != &self.receipt.native_after_ref
        {
            return Err(refused());
        }
        self.controller.custody.content().get(reference)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<OriginalCompletedRestoredSettledCaptureData<'static>>()
        + size_of::<Result<OriginalCompletedRestoredSettledCaptureData<'static>, ProviderError>>()
        + size_of::<&CnpController>()
        + size_of::<&AssignedRestoredSettledCapture>()
        + size_of::<&AssignedConfirmation>()
        + size_of::<Result<&AssignedRestoredSettledCapture, ProviderError>>()
        + size_of::<Result<&AssignedConfirmation, ProviderError>>()
        + size_of::<&Envelope>() * 4
        + size_of::<Result<&Envelope, ProviderError>>()
        + size_of::<&ResponseBody>() * 2
        + size_of::<Result<&ResponseBody, ProviderError>>()
        + size_of::<Option<&Envelope>>()
        + size_of::<Option<&ResponseBody>>()
        + size_of::<&PacketRestoredSettledAfterConfirmationReceipt>()
        + size_of::<Result<&PacketRestoredSettledAfterConfirmationReceipt, ProviderError>>()
        + size_of::<&crate::client::ClientOriginal>()
        + size_of::<Option<&crate::client::ClientOriginal>>()
        + size_of::<Result<&crate::client::ClientOriginal, ProviderError>>()
        + size_of::<&crate::bodies::CaptureResult>()
        + size_of::<&crate::bodies::PollResult>()
        + size_of::<(&Envelope, &Envelope, &ResponseBody)>() * 2
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<&[u8]>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<U64>()
        + size_of::<bool>()
        + size_of::<Result<(), ProviderError>>()
}

impl PreparedOriginalRestoredSettledCapture<'_> {
    /// Borrows the retained proof-filled original after actual Capture completion.
    ///
    /// Successful sealing established canonical correspondence before publication;
    /// this lender repeats the real retained journal pair without reserializing.
    /// The caller independently admits any new full reference or confirmation.
    ///
    /// # Errors
    /// Refuses an earlier/failed phase, missing original/terminal/canonical bank,
    /// or a changed actual Controller journal. It grants no archive permission.
    pub fn canonical_original_data(&self) -> Result<&[u8], ProviderError> {
        let state = self
            .controller
            .original_restored_settled_capture
            .as_ref()
            .ok_or_else(refused)?;
        if !matches!(
            state.stage,
            Stage::Captured | Stage::Confirming | Stage::Complete
        ) || state.canonical.is_empty()
        {
            return Err(refused());
        }
        authenticate_pair(
            self.controller,
            &state.request_id,
            state.original.as_ref().ok_or_else(refused)?,
            state.terminal.as_ref().ok_or_else(refused)?,
        )?;
        Ok(&state.canonical)
    }
}
