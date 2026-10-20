//! Retains a once restored observation before typed-body or artifact decoding.
//!
//! The actual boot consumes this read before invoking the transport. Generic
//! framing, negotiated limits, incidents, request IDs and sequence transitions
//! remain unchanged. Failed and malformed raw bytes stay in the same bank.

use super::*;
use crate::reference_packet::service::ack_emitter::OriginalRestorationObservationRead;
use crate::reference_packet::service::complete_restore::restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE;
use serde_json::Value;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn receive_original_restoration_observation_data(
        &mut self,
        scope: &OriginalRestorationObservationRead,
    ) -> Result<bool, ProviderError> {
        scope.begin_receive_data(self)?;
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(refused());
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let result = self.receive_original_restoration_observation_inner(scope);
        match &result {
            Ok(false) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_restoration_observation_inner(
        &mut self,
        scope: &OriginalRestorationObservationRead,
    ) -> Result<bool, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(false);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        scope.retain_original_data(envelope)?;
        let original = scope.original_data()?;
        if original.message != MessageKind::Request
            || original.method != Method::Observe
            || original.operation_id.0.is_some()
            || original.capture_owner_id.0.is_some()
            || original.extensions.len() != 1
            || !original
                .extensions
                .contains_key(PACKET_RESTORATION_OBSERVE_FEATURE)
            || original.body.len() != 5
            || original
                .body
                .get("extensions")
                .and_then(Value::as_object)
                .is_none_or(|extensions| !extensions.is_empty())
        {
            return Err(refused());
        }
        let body = self.validate_body(&original, true)?;
        drop(original);
        scope.retain_body_data(body)?;
        let original = scope.original_data()?;
        self.retain_original_request_id(&original, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&original))?;
        scope.authenticate_receive_data(self)?;
        drop(original);
        scope.complete_receive_data()?;
        Ok(true)
    }
}

pub(crate) fn original_native_restoration_observation_receive_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&OriginalRestorationObservationRead>()
        + size_of::<Envelope>()
        + size_of::<Result<Envelope, serde_json::Error>>()
        + size_of::<Option<Value>>()
        + size_of::<Result<Option<Value>, ProviderError>>()
        + size_of::<std::cell::Ref<'static, Envelope>>()
        + size_of::<Result<std::cell::Ref<'static, Envelope>, ProviderError>>()
        + size_of::<ReceivedBody>()
        + size_of::<Result<ReceivedBody, ProviderError>>()
        + size_of::<Result<bool, ProviderError>>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("restored observation requires its once original receive")
}
