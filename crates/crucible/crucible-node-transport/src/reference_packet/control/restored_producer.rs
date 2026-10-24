//! Dispatches actual current Producer work under a separately spent private scope.

use super::*;
use crate::reference_packet::service::ack_emitter::OriginalRestoredProducerRead;
use crate::reference_packet::service::native_startup::{
    PacketNativeStartupAllocationRow, native_closed_producer_action_row_data,
};
use crate::reference_packet::service::{PacketConnectedSourceProgram, PacketNative5SourceLaunch};

impl PacketControl {
    pub(crate) fn original_restored_producer_selected_data(&self) -> bool {
        self.restoration_activation_required && matches!(self.program, NativeProgram::OutputOnly(_))
    }

    pub(crate) fn authenticate_original_restored_producer_model_data(
        &self,
    ) -> Result<(), ProviderError> {
        let NativeProgram::OutputOnly(program) = &self.program else {
            return Err(refused());
        };
        let [private, output] = program.events.as_slice() else {
            return Err(refused());
        };
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || !self.restoration_activation_required
            || self.original_physical_gate_held()?
            || program.failed
            || program.gate_closed
            || program.next_event > program.events.len()
            || private.payload.is_some()
            || output
                .payload
                .as_ref()
                .is_none_or(|bytes| bytes.as_slice().len() > 32)
            || program.outputs.len() > 1
            || program.grants.len() > 64
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn original_restored_producer_action_row_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        original: &Envelope,
        finish_extent: usize,
        maximum: usize,
    ) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
        self.authenticate_original_restored_producer_model_data()?;
        let NativeProgram::OutputOnly(program) = &self.program else {
            return Err(refused());
        };
        let PacketConnectedSourceProgram::Producer { program: selected } = &launch.program else {
            return Err(refused());
        };
        if program.events != selected.events {
            return Err(refused());
        }
        let upload = match original.method {
            Method::BlobBegin => original
                .body
                .get("content")
                .and_then(Value::as_object)
                .and_then(|reference| reference.get("length"))
                .and_then(Value::as_str)
                .and_then(|text| text.parse::<usize>().ok())
                .ok_or_else(refused)?,
            Method::BlobChunk => original
                .body
                .get("bytes")
                .and_then(Value::as_str)
                .map(str::len)
                .and_then(|n| n.checked_mul(3))
                .map(|n| n / 4)
                .ok_or_else(refused)?,
            Method::BlobFinish => finish_extent,
            Method::Begin | Method::Poll | Method::Retire | Method::Observe => 0,
            _ => return Err(refused()),
        };
        if upload > 8192 && original.method == Method::BlobBegin {
            return Err(refused());
        }
        native_closed_producer_action_row_data(launch, upload, maximum)
    }

    pub(crate) fn authenticate_original_restored_producer_upload_data(
        &self,
        original: &Envelope,
        scope: &OriginalRestoredProducerRead<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_restored_producer_model_data()?;
        if !matches!(
            original.method,
            Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
        ) {
            return Err(refused());
        }
        scope.authenticate_control_request_data(original, &self.selection, self)
    }

    pub(crate) fn dispatch_original_restored_producer_with_preflight(
        &mut self,
        request: &Envelope,
        scope: &OriginalRestoredProducerRead<'_>,
        prepare: &mut dyn FnMut(&PacketControlReply) -> Result<(), ProviderError>,
    ) -> Result<&PacketControlReply, ProviderError> {
        self.authenticate_original_restored_producer_model_data()?;
        if !matches!(
            request.method,
            Method::Begin | Method::Poll | Method::Retire | Method::Observe
        ) || request
            .request_id
            .0
            .as_ref()
            .is_none_or(|id| self.originals.contains_key(id))
        {
            return Err(refused());
        }
        scope.authenticate_control_request_data(request, &self.selection, self)?;
        self.dispatch_prepared_with_restoration_permissions(
            request,
            &mut ReplyPreparation {
                callback: Some(prepare),
                attempted: false,
            },
            OriginalControlPermissionsData {
                canonical_ack_admit: None,
                selected_observe: None,
                restoration_activation: None,
                restoration_observation: None,
                suffix_observation: None,
                producer_action: Some(scope),
            },
        )
    }

    pub(crate) fn authenticate_original_restored_producer_terminal_data(
        &self,
        original: &Envelope,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_restored_producer_model_data()?;
        original.matches_response(terminal)?;
        let (_, cached) = self
            .originals
            .get(original.request_id.0.as_ref().ok_or_else(refused)?)
            .ok_or_else(refused)?;
        if cached.body != terminal.body
            || terminal.body.get("status").and_then(Value::as_str) != Some("completed")
            || terminal.body.get("operation_state").and_then(Value::as_str) != Some("completed")
        {
            return Err(refused());
        }
        for (reference, bytes) in &cached.evidence {
            reference.verify(bytes)?;
            if self.content.get(reference) != Some(bytes) {
                return Err(refused());
            }
        }
        Ok(())
    }
}

pub(crate) fn original_restored_producer_control_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<crate::reference_packet::common::LiveNative5Grant<'static>>()
        + size_of::<Result<crate::reference_packet::common::PacketNative5CommonGrant, ProviderError>>(
        )
        + size_of::<Vec<crate::reference_packet::common::PacketCommonOwner>>()
        + size_of::<
            Result<Vec<crate::reference_packet::common::PacketCommonOwner>, serde_json::Error>,
        >()
        + size_of::<Result<Position, ProviderError>>()
        + size_of::<&OriginalRestoredProducerRead<'static>>()
        + size_of::<Option<&OriginalRestoredProducerRead<'static>>>()
        + size_of::<ReplyPreparation<'static>>()
        + size_of::<&PacketControlReply>()
        + size_of::<Result<&PacketControlReply, ProviderError>>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<Result<usize, std::num::ParseIntError>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<&Map<String, Value>>>()
        + size_of::<&mut dyn FnMut(&PacketControlReply) -> Result<(), ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}
fn refused() -> ProviderError {
    ProviderError::Correlation("spent current Producer native scope differs")
}
