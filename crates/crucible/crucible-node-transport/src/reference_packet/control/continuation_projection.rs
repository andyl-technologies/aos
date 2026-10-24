//! Projects the real Capture and confirmation response grammars before owners exist.
//!
//! Current binding/session strings are borrowed from stopped Control. Future
//! request identifiers, reference digests and decimal lengths use their closed
//! contract extents. No Envelope, ContentRef or result DTO is manufactured. The
//! SDK must reconcile the actual originals and terminal bodies before copying.

use super::*;
use crate::reference_packet::serialization_storage::NativeSerializationStorageData;
use crate::reference_packet::service::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection;

type Projection = OriginalSerializationStorageProjection;

pub(crate) struct NativeContinuationTerminalProjectionData {
    pub(crate) capture_terminal: NativeSerializationStorageData,
    pub(crate) capture_anchor: NativeSerializationStorageData,
    pub(crate) confirmation_original: NativeSerializationStorageData,
    pub(crate) confirmation_terminal: NativeSerializationStorageData,
}

fn hash(projection: &mut Projection, domain: &str) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["algorithm", "domain", "digest"] {
        projection.add_field(key)?;
    }
    projection.add_string("blake3-256")?;
    projection.add_string(domain)?;
    projection.add_unescaped_ascii_extent(2 * blake3::OUT_LEN)
}

fn reference(projection: &mut Projection) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["hash", "length", "media_type"] {
        projection.add_field(key)?;
    }
    hash(projection, "cnp.blob.v1")?;
    projection.add_unescaped_ascii_extent(20)?;
    // All four actual native Capture/after encoders create this media type.
    projection.add_string("application/json")
}

fn capture_result(projection: &mut Projection) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in [
        "capture_manifest",
        "owner_state_refs",
        "unchanged_cut_receipt",
    ] {
        projection.add_field(key)?;
    }
    reference(projection)?;
    projection.add_array_extent(1)?;
    reference(projection)?;
    reference(projection)
}

fn completed(
    projection: &mut Projection,
    result: impl FnOnce(&mut Projection) -> Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in ["status", "operation_state", "result", "extensions"] {
        projection.add_field(key)?;
    }
    projection.add_string("completed")?;
    projection.add_value(&OperationState::Completed)?;
    result(projection)?;
    projection.add_object()
}

fn confirmation_request(projection: &mut Projection) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in [
        "schema",
        "capture_request_id",
        "capture_request_hash",
        "capture_operation_id",
        "capture_terminal_hash",
        "capture_terminal_sequence",
        "native_snapshot_ref",
        "native_control_ref",
        "native_anchor_ref",
    ] {
        projection.add_field(key)?;
    }
    projection.add_string("source-owned.packet-native-after-confirmation-request/5")?;
    projection.add_unescaped_ascii_extent(128)?;
    hash(projection, "cnp.request.v1")?;
    projection.add_unescaped_ascii_extent(128)?;
    hash(projection, "source-owned.packet-native-capture-terminal/5")?;
    projection.add_unescaped_ascii_extent(20)?;
    for _ in 0..3 {
        reference(projection)?;
    }
    Ok(())
}

fn confirmation_receipt(projection: &mut Projection) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in [
        "schema",
        "capture",
        "native_after_ref",
        "native_after_capacity",
    ] {
        projection.add_field(key)?;
    }
    projection.add_string("source-owned.packet-native-after-confirmation-receipt/5")?;
    confirmation_request(projection)?;
    reference(projection)?;
    projection.add_unescaped_ascii_extent(20)
}

fn confirmation_result(projection: &mut Projection) -> Result<(), ProviderError> {
    projection.add_object()?;
    for key in [
        "operation_id",
        "operation_state",
        "outcome",
        "observations",
        "next_observation_sequence",
    ] {
        projection.add_field(key)?;
    }
    projection.add_unescaped_ascii_extent(128)?;
    projection.add_value(&OperationState::Completed)?;
    // PollResult retains the full original Completed Capture response body.
    completed(projection, capture_result)?;
    projection.add_array_extent(0)?;
    projection.add_value(&U64::new(0))
}

impl PacketControl {
    pub(crate) fn quote_original_continuation_terminal_shapes(
        &self,
        observed: &Envelope,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
        capture_request: &NativeProjectedCaptureRequestData,
        maximum: usize,
    ) -> Result<NativeContinuationTerminalProjectionData, ProviderError> {
        currency.authenticate_before_observe(self)?;
        let result = self.quote_continuation_terminal_shapes_data(
            observed,
            currency,
            capture_request,
            maximum,
        )?;
        currency.authenticate_before_observe(self)?;
        Ok(result)
    }

    pub(crate) fn quote_startup_capture_terminal_shapes(
        &self,
        observed: &Envelope,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
        capture_request: &NativeProjectedCaptureRequestData,
        maximum: usize,
    ) -> Result<NativeContinuationTerminalProjectionData, ProviderError> {
        currency.authenticate_capture_boundary(self, None)?;
        let result = self.quote_continuation_terminal_shapes_data(
            observed,
            currency,
            capture_request,
            maximum,
        )?;
        currency.authenticate_capture_boundary(self, None)?;
        Ok(result)
    }

    pub(crate) fn quote_startup_confirmation_terminal_shapes(
        &self,
        observed: &Envelope,
        capture: &Envelope,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
        capture_request: &NativeProjectedCaptureRequestData,
        maximum: usize,
    ) -> Result<NativeContinuationTerminalProjectionData, ProviderError> {
        currency.authenticate_capture_boundary(self, Some(capture))?;
        let result = self.quote_continuation_terminal_shapes_data(
            observed,
            currency,
            capture_request,
            maximum,
        )?;
        currency.authenticate_capture_boundary(self, Some(capture))?;
        Ok(result)
    }

    fn quote_continuation_terminal_shapes_data(
        &self,
        observed: &Envelope,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
        capture_request: &NativeProjectedCaptureRequestData,
        maximum: usize,
    ) -> Result<NativeContinuationTerminalProjectionData, ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(ProviderError::Correlation(
                "native continuation projection binding roster",
            ));
        };
        if observed.message != crate::envelope::MessageKind::Request
            || observed.method != Method::Observe
            || observed.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || observed.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || self.complete_capture_allocation_selection.is_none()
        {
            return Err(ProviderError::Correlation(
                "native continuation projection original differs",
            ));
        }

        // The real anchor embeds both the full incoming Envelope and its
        // independently decoded CaptureArguments. Their closed counters are
        // composed separately; no placeholder request/reference is created.
        let mut anchor = Projection::new(maximum)?;
        anchor.add_object()?;
        for key in [
            "schema",
            "native_pid",
            "request",
            "request_hash",
            "capture",
            "world",
            "binding",
            "local_cursor",
            "control_snapshot",
            "inventory_hash",
        ] {
            anchor.add_field(key)?;
        }
        anchor.add_string("source-owned.packet-native-unchanged-cut/5")?;
        anchor.add_value(&U64::new(u64::from(self.capture_creator)))?;
        hash(&mut anchor, "cnp.request.v1")?;
        anchor.add_value(&self.selection.world)?;
        hash(&mut anchor, "cnp.owner-binding.v1")?;
        anchor.add_value(&currency.cursor())?;
        reference(&mut anchor)?;
        hash(
            &mut anchor,
            match &self.program {
                NativeProgram::OutputOnly(_) => "source-owned.packet-inventory.v1",
                NativeProgram::Connected(_) => "source-owned.packet-connected-inventory/4",
                NativeProgram::RestorationInProgress => {
                    return Err(ProviderError::Conflict(
                        "native Capture anchor model incomplete",
                    ));
                }
            },
        )?;
        let anchor = anchor.finish(maximum)?;
        let capture_anchor =
            crate::reference_packet::serialization_storage::sum_serialization_storage_data(
                &[
                    &anchor,
                    &capture_request.envelope,
                    &capture_request.arguments,
                ],
                maximum,
            )?;
        if capture_anchor.maximum_encoded_bytes > 8192 {
            return Err(ProviderError::ResourceExhausted(
                "native Capture closed anchor extent",
            ));
        }

        let mut capture = Projection::new(maximum)?;
        self.project_continuation_envelope(&mut capture, observed, Method::Begin, true)?;
        completed(&mut capture, capture_result)?;
        capture.add_object()?;
        let capture_terminal = capture.finish(maximum)?;

        let mut poll = Projection::new(maximum)?;
        self.project_continuation_envelope(&mut poll, observed, Method::Poll, false)?;
        poll.add_object()?;
        for key in ["after_observation_sequence", "extensions"] {
            poll.add_field(key)?;
        }
        poll.add_value(&U64::new(0))?;
        poll.add_object()?;
        poll.add_object()?;
        poll.add_field(PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)?;
        confirmation_request(&mut poll)?;
        let confirmation_original = poll.finish(maximum)?;

        let mut response = Projection::new(maximum)?;
        self.project_continuation_envelope(&mut response, observed, Method::Poll, true)?;
        completed(&mut response, confirmation_result)?;
        response.add_object()?;
        response.add_field(PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)?;
        confirmation_receipt(&mut response)?;
        let confirmation_terminal = response.finish(maximum)?;
        let requested = [
            capture_terminal.requested_total()?,
            capture_anchor.requested_total()?,
            confirmation_original.requested_total()?,
            confirmation_terminal.requested_total()?,
        ]
        .into_iter()
        .try_fold(0usize, |sum, next| {
            sum.checked_add(next)
                .ok_or(ProviderError::ResourceExhausted(
                    "native continuation projection sum",
                ))
        })?;
        if requested > maximum {
            return Err(ProviderError::ResourceExhausted(
                "native continuation projection sum",
            ));
        }
        Ok(NativeContinuationTerminalProjectionData {
            capture_terminal,
            capture_anchor,
            confirmation_original,
            confirmation_terminal,
        })
    }

    fn project_continuation_envelope(
        &self,
        projection: &mut Projection,
        observed: &Envelope,
        method: Method,
        response: bool,
    ) -> Result<(), ProviderError> {
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(ProviderError::Correlation(
                "native continuation projection binding roster",
            ));
        };
        projection.add_object()?;
        for key in [
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ] {
            projection.add_field(key)?;
        }
        projection.add_value(&observed.protocol)?;
        projection.add_value(&if response {
            crate::envelope::MessageKind::Response
        } else {
            crate::envelope::MessageKind::Request
        })?;
        projection.add_value(&observed.session_id)?;
        projection.add_value(&observed.incarnation_id)?;
        projection.add_value(&binding.compatibility.node_id)?;
        projection.add_value(&())?;
        projection.add_value(&binding.compatibility.capture_owner.id)?;
        projection.add_unescaped_ascii_extent(128)?;
        projection.add_unescaped_ascii_extent(128)?;
        projection.add_unescaped_ascii_extent(20)?;
        projection.add_value(&method)
    }
}
