//! Receives signed Observe17 raw-first in its actual prepaid native slot.
//!
//! The ordinary selected codec/guard still validates independent transport DATA.
//! No generic dispatch path, old observation permit or caller row grants action.

use super::*;
use crate::reference_packet::service::ack_emitter::OriginalNativeObservation17Read;

impl<S: ProviderStream> Connection<S> {
    /// Receives one Source-signed Observe beneath its irreversible native slot.
    ///
    /// # Errors
    /// Refuses changed admission, malformed/unsupported input, revoked policy,
    /// sequence disagreement or conflicting custody. Literal/typed partials and
    /// ordinary transport incidents remain in their actual retained owners.
    pub(crate) fn receive_original_observation17_data(
        &mut self,
        scope: &OriginalNativeObservation17Read,
    ) -> Result<bool, ProviderError> {
        scope.begin_receive_data(self)?;
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(refused());
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let result = self.receive_original_observation17_inner(scope);
        match &result {
            Ok(false) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_observation17_inner(
        &mut self,
        scope: &OriginalNativeObservation17Read,
    ) -> Result<bool, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(false);
        };
        let original: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        scope.retain_original_data(self, original)?;
        let original = scope.original_data()?;
        let ReceivedBody::Request(body) = self.validate_body(&original, true)? else {
            return Err(refused());
        };
        if !matches!(body.as_ref(), RequestBody::Observe(_)) {
            return Err(refused());
        }
        self.retain_original_request_id(&original, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&original))?;
        drop(original);
        scope.complete_receive_data(self)?;
        Ok(true)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("signed Observe17 requires its retained native receive")
}

/// Names the independently returning selected body decoder and raw receive views.
pub(crate) fn native_observation17_receive_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&OriginalNativeObservation17Read>()
        + size_of::<Option<serde_json::Value>>()
        + size_of::<Result<Option<serde_json::Value>, ProviderError>>()
        + size_of::<Envelope>()
        + size_of::<Result<Envelope, serde_json::Error>>()
        + size_of::<ReceivedBody>()
        + size_of::<Result<ReceivedBody, ProviderError>>()
        + size_of::<Box<RequestBody>>()
        + size_of::<std::cell::Ref<'static, Envelope>>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}
