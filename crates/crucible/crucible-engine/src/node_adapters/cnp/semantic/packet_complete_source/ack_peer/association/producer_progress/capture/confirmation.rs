//! Retains the separate fourth-object request before SDK assignment or IO.
//!
//! The parent first verifies the genuine native17 Capture output under its same
//! ticket/claim and SourceRead. The actual SDK canonical original and correlated
//! terminal supply this request; neither a reference nor a completed DTO grants
//! a Capture or renews the earlier Observe proof.

use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_contract::RuntimeError;
use crucible_node_format::{ContentRef, Id, canonical};
use crucible_node_transport::{
    bodies::MethodResult,
    client::{
        OriginalCanonicalBlobAckEmitter, OriginalRestoredSettledCaptureConstructionData,
        PreparedOriginalRestoredSettledCapture, RestoredSettledCaptureTypedOwnerData,
    },
    envelope::RequestOrigin,
    reference_packet::service::restored_settled_confirmation::{
        PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA,
        PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
        PacketRestoredSettledAfterConfirmationRequest,
    },
};
use std::mem::size_of;

pub(super) struct CaptureConfirmationOwners {
    attempted: bool,
    request_id: Option<Id>,
    terminal_value: Option<serde_json::Value>,
    terminal_bytes: Vec<u8>,
    request: Option<PacketRestoredSettledAfterConfirmationRequest>,
}

impl CaptureConfirmationOwners {
    pub(super) fn new_data() -> Self {
        Self {
            attempted: false,
            request_id: None,
            terminal_value: None,
            terminal_bytes: Vec::new(),
            request: None,
        }
    }

    pub(super) fn publish_data(
        &mut self,
        prepared: &mut PreparedOriginalRestoredSettledCapture<'_>,
        emitter: &OriginalCanonicalBlobAckEmitter,
        request_id: Id,
        sdk: &OriginalRestoredSettledCaptureConstructionData,
        recheck_read: &mut dyn FnMut() -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if self.attempted {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.attempted = true;
        self.request_id = Some(request_id);
        recheck_read()?;

        {
            let partial = prepared
                .partial_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let original = partial
                .original_data()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let terminal = partial
                .terminal_data()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            let response = partial
                .response_body_data()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            original
                .matches_response(terminal)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let Some(MethodResult::Capture(capture)) = response.result.as_ref() else {
                return Err(RuntimeError::InvalidReceipt);
            };
            if !matches!(
                &response.shape,
                crucible_node_transport::bodies::ResponseShape::Completed {
                    operation_state: crucible_node_transport::bodies::OperationState::Completed,
                    ..
                }
            ) || capture.owner_state_refs.len() != 1
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            self.terminal_value =
                Some(serde_json::to_value(terminal).map_err(|_| RuntimeError::InvalidReceipt)?);
            self.terminal_bytes = canonical::canonical_json(
                self.terminal_value
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
            if self.terminal_bytes.len() > sdk.maximum_frame_bytes_data() {
                return Err(RuntimeError::ResourceLimit);
            }
            let canonical_original = prepared
                .canonical_original_data()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            self.request = Some(PacketRestoredSettledAfterConfirmationRequest {
                schema: PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA.into(),
                capture_request_id: original
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(RuntimeError::InvalidReceipt)?
                    .clone(),
                capture_request_hash: original
                    .request_hash(RequestOrigin::Controller)
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
                capture_operation_id: original
                    .operation_id
                    .0
                    .as_ref()
                    .ok_or(RuntimeError::InvalidReceipt)?
                    .clone(),
                capture_terminal_hash: canonical::hash(
                    PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
                    &self.terminal_bytes,
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?,
                capture_terminal_sequence: terminal.sequence,
                settled_capture_request: canonical::content_ref(
                    canonical_original,
                    "application/json",
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?,
                native_snapshot_ref: capture.capture_manifest.clone(),
                native_control_ref: capture.owner_state_refs[0].clone(),
                native_anchor_ref: capture.unchanged_cut_receipt.clone(),
            });
        }
        let request = self
            .request
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        request
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        sdk.authenticate_typed_owner_data(
            &RestoredSettledCaptureTypedOwnerData::ConfirmationRequest(request),
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        recheck_read()?;
        // Retain our independent request before the SDK's live guard. The SDK
        // owns the complete incoming copy even if later assignment/IO fails.
        prepared
            .prepare_confirmation_data(
                emitter,
                self.request_id
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .clone(),
                copy_request_data(request),
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        recheck_read()?;
        prepared
            .publish_confirmation_data(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        recheck_read()
    }

    pub(super) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            attempted: _,
            request_id,
            terminal_value,
            terminal_bytes,
            request,
        } = self;
        let mut total = terminal_bytes.capacity();
        if let Some(id) = request_id {
            total = add(total, id.allocated_capacity(), maximum)?;
        }
        if let Some(value) = terminal_value {
            total = add(total, crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::value_storage_with_error::<RuntimeError>(value, 0, maximum)?, maximum)?;
        }
        if let Some(request) = request {
            let facts = RestoredSettledCaptureTypedOwnerData::ConfirmationRequest(request)
                .retained_metadata_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            total = add(
                total,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &facts, maximum,
                )?,
                maximum,
            )?;
        }
        Ok(total)
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<&mut Self>()
            + size_of::<&mut PreparedOriginalRestoredSettledCapture<'static>>()
            + size_of::<&OriginalCanonicalBlobAckEmitter>()
            + size_of::<Id>()
            + size_of::<Option<&Id>>()
            + size_of::<&PacketRestoredSettledAfterConfirmationRequest>()
            + size_of::<PacketRestoredSettledAfterConfirmationRequest>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<&serde_json::Value>>()
            + size_of::<&ContentRef>()
            + RestoredSettledCaptureTypedOwnerData::counter_scratch_data()
    }
}

// This is deliberately an exhaustive field copy instead of widening the public
// DTO with a new authority-adjacent constructor or relying on a generic Value.
fn copy_request_data(
    request: &PacketRestoredSettledAfterConfirmationRequest,
) -> PacketRestoredSettledAfterConfirmationRequest {
    let PacketRestoredSettledAfterConfirmationRequest {
        schema,
        capture_request_id,
        capture_request_hash,
        capture_operation_id,
        capture_terminal_hash,
        capture_terminal_sequence,
        settled_capture_request,
        native_snapshot_ref,
        native_control_ref,
        native_anchor_ref,
    } = request;
    PacketRestoredSettledAfterConfirmationRequest {
        schema: schema.clone(),
        capture_request_id: capture_request_id.clone(),
        capture_request_hash: capture_request_hash.clone(),
        capture_operation_id: capture_operation_id.clone(),
        capture_terminal_hash: capture_terminal_hash.clone(),
        capture_terminal_sequence: *capture_terminal_sequence,
        settled_capture_request: settled_capture_request.clone(),
        native_snapshot_ref: native_snapshot_ref.clone(),
        native_control_ref: native_control_ref.clone(),
        native_anchor_ref: native_anchor_ref.clone(),
    }
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}
