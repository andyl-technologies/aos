//! Lends every actual Capture field separately from its mutable recorder banks.

use super::*;

#[derive(Clone, Copy)]
pub(crate) struct NativeCaptureAttemptCurrent17<'a> {
    ordinal: &'a u64,
    original: &'a Option<Envelope>,
    body: &'a Option<Body>,
    arguments: &'a Option<CaptureArguments>,
    capture: &'a Option<PacketRestoredSettledCaptureArtifact>,
    capture_context: &'a Option<PacketRestoredSettledCaptureContext>,
    upload: &'a Option<PacketRestoredSettledCaptureUploadArtifact>,
    upload_context: &'a Option<PacketRestoredSettledCaptureUploadContext>,
    continuation: &'a Option<PacketRestoredSettledCaptureUploadContinuation>,
    confirmation: &'a Option<PacketRestoredSettledAfterConfirmationRequest>,
    registration: &'a Option<crate::reference_packet::control::PacketOriginalCaptureReservation>,
    checkpoint:
        &'a Option<crate::reference_packet::control::NativeRestoredSettledCheckpointAttempt>,
    terminal: &'a Option<Envelope>,
    prepared_reply: &'a Option<Map<String, Value>>,
    confirmation_receipt: &'a Option<Value>,
    stage: &'a Stage,
}

pub(super) trait CaptureOutputMetadata17 {
    fn observe_output_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError>;
}
impl CaptureOutputMetadata17
    for Option<super::super::restored_settled_capture_output::NativeRestoredSettledCaptureOutputs>
{
    fn observe_output_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(outputs) = self {
            outputs.observe_current17_metadata_data(observer)?;
        }
        Ok(())
    }
}
impl CaptureOutputMetadata17
    for super::super::restored_settled_capture_output::NativeCaptureOutputCut17<'_>
{
    fn observe_output_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.observe_current17_metadata_data(observer)
    }
}

impl NativeRestoredSettledCaptureAttempt {
    /// Checks both passive writers against an actual reservation in component tests.
    ///
    /// This test-only fixture supplies no Source proof or native action grant.
    ///
    /// # Errors
    /// Refuses serialization or metadata recording failure.
    #[cfg(test)]
    pub(crate) fn check_registration_writer_fixture_data(
        registration: crate::reference_packet::control::PacketOriginalCaptureReservation,
    ) -> Result<(), ProviderError> {
        use crate::retained_metadata::records::MetadataRecordBank;

        let expected = serde_json::to_value(registration.borrowed_capture17_data())
            .map_err(crucible_node_format::ContractError::from)?;
        let mut attempt = Self::new_data(1);
        attempt.registration = Some(registration);

        let owned =
            serde_json::to_vec(&attempt).map_err(crucible_node_format::ContractError::from)?;
        let source = attempt.current_readonly_data();
        let borrowed = serde_json::to_vec(&CaptureAttemptWithOutput17 {
            source: &source,
            output: &attempt.outputs,
        })
        .map_err(crucible_node_format::ContractError::from)?;
        assert_eq!(owned, borrowed);
        let value: Value =
            serde_json::from_slice(&owned).map_err(crucible_node_format::ContractError::from)?;
        assert_eq!(value["registration"], expected);

        // Every other slot is scalar or absent. Recording the complete writer
        // must therefore match the real reservation's defining metadata order.
        let mut actual_rows = MetadataRecordBank::reserve(4096)?;
        let mut observer = MetadataObserver::recording(&mut actual_rows);
        attempt.observe_settled_history_metadata_data(&mut observer)?;
        observer.finish();

        let mut expected_rows = MetadataRecordBank::reserve(4096)?;
        let mut observer = MetadataObserver::recording(&mut expected_rows);
        attempt
            .registration
            .as_ref()
            .ok_or_else(invalid)?
            .observe_capture17_metadata_data(&mut observer)?;
        observer.finish();
        assert_eq!(
            serde_json::to_vec(&actual_rows).map_err(crucible_node_format::ContractError::from)?,
            serde_json::to_vec(&expected_rows)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        Ok(())
    }

    pub(super) fn current_readonly_data(&self) -> NativeCaptureAttemptCurrent17<'_> {
        let Self {
            ordinal,
            original,
            body,
            arguments,
            capture,
            capture_context,
            upload,
            upload_context,
            continuation,
            confirmation,
            registration,
            checkpoint,
            outputs: _,
            terminal,
            prepared_reply,
            confirmation_receipt,
            stage,
        } = self;
        NativeCaptureAttemptCurrent17 {
            ordinal,
            original,
            body,
            arguments,
            capture,
            capture_context,
            upload,
            upload_context,
            continuation,
            confirmation,
            registration,
            checkpoint,
            terminal,
            prepared_reply,
            confirmation_receipt,
            stage,
        }
    }

    /// Lends the actual current fields separately from their mutable output bank.
    ///
    /// # Errors
    /// Refuses absent output custody; this DATA split grants no dispatch right.
    pub(crate) fn split_outputs_current17_data(
        &mut self,
    ) -> Result<
        (
            NativeCaptureAttemptCurrent17<'_>,
            &mut super::super::restored_settled_capture_output::NativeRestoredSettledCaptureOutputs,
        ),
        ProviderError,
    > {
        let Self {
            ordinal,
            original,
            body,
            arguments,
            capture,
            capture_context,
            upload,
            upload_context,
            continuation,
            confirmation,
            registration,
            checkpoint,
            outputs,
            terminal,
            prepared_reply,
            confirmation_receipt,
            stage,
        } = self;
        Ok((
            NativeCaptureAttemptCurrent17 {
                ordinal,
                original,
                body,
                arguments,
                capture,
                capture_context,
                upload,
                upload_context,
                continuation,
                confirmation,
                registration,
                checkpoint,
                terminal,
                prepared_reply,
                confirmation_receipt,
                stage,
            },
            outputs.as_mut().ok_or_else(invalid)?,
        ))
    }
}

impl NativeCaptureAttemptCurrent17<'_> {
    pub(super) fn observe_with_outputs_data<O: CaptureOutputMetadata17>(
        &self,
        output: &O,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let NativeCaptureAttemptCurrent17 {
            ordinal,
            original,
            body,
            arguments,
            capture,
            capture_context,
            upload,
            upload_context,
            continuation,
            confirmation,
            registration,
            checkpoint,
            terminal,
            prepared_reply,
            confirmation_receipt,
            stage,
        } = *self;
        observer.observe(ordinal)?;
        observer.observe(original)?;
        if let Some(body) = body {
            match body {
                Body::Capture(value) => observer.observe(value)?,
                Body::BlobBegin(value) => {
                    let BlobBeginRequest {
                        transfer_id,
                        content,
                        extensions,
                    } = value;
                    observer.observe(transfer_id)?;
                    observer.observe(content)?;
                    observer.observe(extensions)?;
                }
                Body::BlobChunk(value) => {
                    let BlobChunkRequest {
                        transfer_id,
                        offset,
                        bytes,
                        extensions,
                    } = value;
                    observer.observe(transfer_id)?;
                    observer.observe(offset)?;
                    observer.observe(bytes)?;
                    observer.observe(extensions)?;
                }
                Body::BlobFinish(value) => {
                    let BlobFinishRequest {
                        transfer_id,
                        extensions,
                    } = value;
                    observer.observe(transfer_id)?;
                    observer.observe(extensions)?;
                }
                Body::Confirmation(value) => {
                    let PollRequest {
                        after_observation_sequence,
                        extensions,
                    } = value;
                    observer.observe(after_observation_sequence)?;
                    observer.observe(extensions)?;
                }
            }
        }
        if let Some(arguments) = arguments {
            let CaptureArguments {
                capture_id,
                participant_ids,
                cut_id,
                cut,
                event_ordinal,
                ordering_profile,
                preservation_contract,
            } = arguments;
            observer.observe(capture_id)?;
            observer.observe(participant_ids)?;
            observer.observe(cut_id)?;
            observer.observe(cut)?;
            observer.observe(event_ordinal)?;
            observer.observe(ordering_profile)?;
            observer.observe(preservation_contract)?;
        }
        observer.observe(capture)?;
        observer.observe(capture_context)?;
        observer.observe(upload)?;
        observer.observe(upload_context)?;
        observer.observe(continuation)?;
        if let Some(value) = confirmation {
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
            } = value;
            observer.observe(schema)?;
            observer.observe(capture_request_id)?;
            observer.observe(capture_request_hash)?;
            observer.observe(capture_operation_id)?;
            observer.observe(capture_terminal_hash)?;
            observer.observe(capture_terminal_sequence)?;
            observer.observe(settled_capture_request)?;
            observer.observe(native_snapshot_ref)?;
            observer.observe(native_control_ref)?;
            observer.observe(native_anchor_ref)?;
        }
        if let Some(registration) = registration {
            registration.observe_capture17_metadata_data(observer)?;
        }
        if let Some(checkpoint) = checkpoint {
            checkpoint.observe_settled_history_metadata_data(observer)?;
        }
        output.observe_output_metadata_data(observer)?;
        observer.observe(terminal)?;
        observer.observe(prepared_reply)?;
        observer.observe(confirmation_receipt)?;
        let stage = match stage {
            Stage::Receiving => 0usize,
            Stage::Raw => 1,
            Stage::Typed => 2,
            Stage::Failed => 3,
        };
        observer.observe(&stage)
    }

    /// Observes the exact source fields using their active output-recorder cut.
    ///
    /// # Errors
    /// Refuses metadata capacity or checked layout overflow.
    pub(crate) fn observe_with_output_cut_metadata_data(
        &self,
        output: &super::super::restored_settled_capture_output::NativeCaptureOutputCut17<'_>,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.observe_with_outputs_data(output, observer)
    }

    pub(crate) fn borrowed_with_output_cut_data<'a>(
        &'a self,
        output: &'a super::super::restored_settled_capture_output::NativeCaptureOutputCut17<'a>,
    ) -> impl serde::Serialize + 'a {
        CaptureAttemptWithOutput17 {
            source: self,
            output,
        }
    }
}

struct CaptureAttemptWithOutput17<'a, O> {
    source: &'a NativeCaptureAttemptCurrent17<'a>,
    output: &'a O,
}
impl<O: serde::Serialize> serde::Serialize for CaptureAttemptWithOutput17<'_, O> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut fields = serializer.serialize_struct("NativeCaptureAttemptCurrent17", 17)?;
        fields.serialize_field("ordinal", self.source.ordinal)?;
        fields.serialize_field("original", self.source.original)?;
        fields.serialize_field("body", self.source.body)?;
        fields.serialize_field("arguments", self.source.arguments)?;
        fields.serialize_field("capture", self.source.capture)?;
        fields.serialize_field("capture_context", self.source.capture_context)?;
        fields.serialize_field("upload", self.source.upload)?;
        fields.serialize_field("upload_context", self.source.upload_context)?;
        fields.serialize_field("continuation", self.source.continuation)?;
        fields.serialize_field("confirmation", self.source.confirmation)?;
        fields.serialize_field("registration", &Registration17(self.source.registration))?;
        fields.serialize_field("checkpoint", self.source.checkpoint)?;
        fields.serialize_field("outputs", self.output)?;
        fields.serialize_field("terminal", self.source.terminal)?;
        fields.serialize_field("prepared_reply", self.source.prepared_reply)?;
        fields.serialize_field("confirmation_receipt", self.source.confirmation_receipt)?;
        fields.serialize_field("stage", self.source.stage)?;
        fields.end()
    }
}

/// Serializes the actual retained reservation through its passive field view.
pub(super) fn serialize_registration<S: serde::Serializer>(
    registration: &Option<crate::reference_packet::control::PacketOriginalCaptureReservation>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(
        &registration
            .as_ref()
            .map(|value| value.borrowed_capture17_data()),
        serializer,
    )
}

struct Registration17<'a>(
    &'a Option<crate::reference_packet::control::PacketOriginalCaptureReservation>,
);

impl serde::Serialize for Registration17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_registration(self.0, serializer)
    }
}

pub(super) const fn counter_scratch_data() -> usize {
    std::mem::size_of::<Registration17<'static>>()
        + std::mem::size_of::<NativeCaptureAttemptCurrent17<'static>>()
        + std::mem::size_of::<CaptureAttemptWithOutput17<'static, super::super::restored_settled_capture_output::NativeCaptureOutputCut17<'static>>>()
        + std::mem::size_of::<CaptureAttemptWithOutput17<'static, Option<super::super::restored_settled_capture_output::NativeRestoredSettledCaptureOutputs>>>()
}

/// Borrows only the typed Capture or confirmation owned by this active cut.
impl NativeCaptureAttemptCurrent17<'_> {
    /// Refuses raw, failed or auxiliary requests without constructing a grant.
    pub(crate) fn current_capture_cut_original17_data(&self) -> Result<&Envelope, ProviderError> {
        if *self.stage != Stage::Typed {
            return Err(invalid());
        }
        let original = self.original.as_ref().ok_or_else(invalid)?;
        match self.body.as_ref().ok_or_else(invalid)? {
            Body::Capture(body) => {
                if original.method != Method::Begin || body.kind != BeginKind::Capture {
                    return Err(invalid());
                }
                self.capture.as_ref().ok_or_else(invalid)?.validate_data()?;
                self.capture_context
                    .as_ref()
                    .ok_or_else(invalid)?
                    .validate_data()?;
            }
            Body::Confirmation(body) => {
                let confirmation = self.confirmation.as_ref().ok_or_else(invalid)?;
                confirmation.validate_data()?;
                if original.method != Method::Poll
                    || original.operation_id.0.as_ref() != Some(&confirmation.capture_operation_id)
                    || body.after_observation_sequence.get() != 0
                    || !body.extensions.is_empty()
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        Ok(original)
    }
}
